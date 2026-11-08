#include "ReferenceVssSelectivePointEnvelope.hpp"

#include <cstring>
#include <limits>
#include <utility>

namespace pvia {
namespace {
constexpr u64 MAGIC = 0x50565653504e5431ULL; // PVVSPNT1
constexpr u64 DIGEST_DOMAIN = 0x5056505444494731ULL; // PVPTDIG1
constexpr size_t HEADER_WORDS = 26;
constexpr size_t TRANSCRIPT_OFFSET = 9;
constexpr size_t ROW_OFFSET = 13;
constexpr size_t CONTEXT_OFFSET = 17;
constexpr size_t PAYLOAD_DIGEST_OFFSET = 21;

void append_digest_words(const Digest& digest, std::vector<u64>* output) {
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        output->push_back(word);
    }
}

Digest read_digest_words(const std::vector<u64>& words, size_t offset) {
    Digest digest{};
    if (offset > words.size() || words.size() - offset < 4) return digest;
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(digest.bytes.data() + 8 * i, &words[offset + i], 8);
    return digest;
}

Digest packet_digest(const std::vector<u64>& words) {
    if (words.size() < HEADER_WORDS) return Digest{};
    std::vector<u64> preimage;
    preimage.reserve(words.size() - 3);
    preimage.push_back(DIGEST_DOMAIN);
    preimage.insert(preimage.end(), words.begin(),
                    words.begin() + PAYLOAD_DIGEST_OFFSET);
    preimage.insert(preimage.end(),
                    words.begin() + PAYLOAD_DIGEST_OFFSET + 4, words.end());
    return hash_words(preimage);
}

bool valid_context(const AuthenticatedMpcMessageContext& context) {
    return context.protocol_domain == PVIA_VSS_SELECTIVE_POINT_DOMAIN &&
        context.message_kind == PVIA_VSS_SELECTIVE_POINT_KIND &&
        validate_authenticated_mpc_message_context(context);
}
} // namespace

bool encode_reference_vss_selective_point_envelope(
    const ReferenceVssSelectivePoint& point,
    const ReferenceVssReceipt& receipt,
    const AuthenticatedMpcMessageContext& context,
    std::vector<u64>* output) {
    if (!output) return false;
    output->clear();
    if (!valid_context(context) || !receipt.available ||
        !receipt.consistent || receipt.transcript_binding == Digest{} ||
        point.helper < 0 || point.helper >= receipt.world_size ||
        point.target < 0 || point.target >= receipt.world_size ||
        point.helper == point.target ||
        point.transcript_binding != receipt.transcript_binding ||
        point.helper_row_commitment == Digest{} ||
        point.values.size() != receipt.element_count ||
        receipt.element_count >
            (std::numeric_limits<size_t>::max() - HEADER_WORDS) / 2)
        return false;
    std::vector<u64> words = {
        MAGIC, PVIA_VSS_SELECTIVE_POINT_VERSION,
        static_cast<u64>(point.helper), static_cast<u64>(point.target),
        context.sid, context.checkpoint, context.round,
        context.sequence, context.message_kind};
    append_digest_words(point.transcript_binding, &words);
    append_digest_words(point.helper_row_commitment, &words);
    append_digest_words(compute_authenticated_mpc_context_binding(context),
                        &words);
    words.insert(words.end(), 4, 0);
    words.push_back(static_cast<u64>(point.values.size()));
    for (const F& value : point.values) {
        if (value.real >= F::mod || value.img >= F::mod) return false;
        words.push_back(value.real);
        words.push_back(value.img);
    }
    const Digest digest = packet_digest(words);
    if (digest == Digest{}) return false;
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(&words[PAYLOAD_DIGEST_OFFSET + i],
                    digest.bytes.data() + 8 * i, 8);
    *output = std::move(words);
    return true;
}

bool decode_reference_vss_selective_point_envelope(
    const std::vector<u64>& words,
    int sender, int target,
    const ReferenceVssReceipt& receipt,
    const ReferenceVssTranscriptContext& transcript,
    const AuthenticatedMpcMessageContext& context,
    ReferenceVssSelectivePoint* output) {
    if (!output) return false;
    *output = ReferenceVssSelectivePoint{};
    if (!valid_context(context) || !receipt.available ||
        !receipt.consistent || receipt.world_size < 4 ||
        sender < 0 || sender >= receipt.world_size ||
        target < 0 || target >= receipt.world_size || sender == target ||
        receipt.element_count == 0 ||
        receipt.element_count >
            (std::numeric_limits<size_t>::max() - HEADER_WORDS) / 2 ||
        words.size() != HEADER_WORDS + 2 * receipt.element_count ||
        words[0] != MAGIC ||
        words[1] != PVIA_VSS_SELECTIVE_POINT_VERSION ||
        words[2] != static_cast<u64>(sender) ||
        words[3] != static_cast<u64>(target) ||
        words[4] != context.sid ||
        words[5] != context.checkpoint ||
        words[6] != context.round ||
        words[7] != context.sequence ||
        words[8] != context.message_kind ||
        words[25] != receipt.element_count ||
        transcript.world_size != receipt.world_size ||
        transcript.row_commitments.size() !=
            static_cast<size_t>(receipt.world_size) ||
        compute_reference_vss_transcript_binding(
            receipt.dealer, receipt.threshold, receipt.element_count,
            transcript) != receipt.transcript_binding ||
        read_digest_words(words, TRANSCRIPT_OFFSET) !=
            receipt.transcript_binding ||
        read_digest_words(words, ROW_OFFSET) !=
            transcript.row_commitments[static_cast<size_t>(sender)] ||
        read_digest_words(words, CONTEXT_OFFSET) !=
            compute_authenticated_mpc_context_binding(context) ||
        read_digest_words(words, PAYLOAD_DIGEST_OFFSET) !=
            packet_digest(words))
        return false;
    ReferenceVssSelectivePoint point;
    point.helper = sender;
    point.target = target;
    point.transcript_binding = receipt.transcript_binding;
    point.helper_row_commitment =
        transcript.row_commitments[static_cast<size_t>(sender)];
    point.values.reserve(receipt.element_count);
    for (size_t i = HEADER_WORDS; i < words.size(); i += 2) {
        if (words[i] >= F::mod || words[i + 1] >= F::mod) return false;
        point.values.emplace_back(
            static_cast<long long>(words[i]),
            static_cast<long long>(words[i + 1]));
    }
    *output = std::move(point);
    return true;
}

bool ReferenceVssSelectivePointReplayGuard::Observe(
    const AuthenticatedMpcMessageContext& context,
    int sender, int target) {
    if (!valid_context(context) || sender < 0 || target < 0 ||
        sender == target) return false;
    const Key key(context.sid, context.checkpoint, sender, target);
    auto found = highest_sequence_.find(key);
    if (found != highest_sequence_.end() &&
        context.sequence <= found->second) return false;
    highest_sequence_[key] = context.sequence;
    return true;
}

} // namespace pvia
