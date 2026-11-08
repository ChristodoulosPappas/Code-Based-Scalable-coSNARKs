#include "ReferenceVssSelectivePointCommitment.hpp"
#include "ReferenceVssSelectivePointEnvelope.hpp"

#include <cstring>
#include <limits>
#include <utility>

namespace pvia {
namespace {
constexpr u64 MATRIX_MAGIC = 0x505653504d415431ULL; // PVSPMAT1
constexpr u64 ACK_MAGIC = 0x5056535041434b32ULL; // PVSPACK2
constexpr u64 POINT_DOMAIN = 0x50565350564c4431ULL; // PVSPVLD1
constexpr u64 REGISTRY_DOMAIN = 0x5056535052475331ULL; // PVSP RGS1
constexpr size_t HEADER_WORDS = 9;

void append_digest(const Digest& digest, std::vector<u64>* output) {
    for (size_t k = 0; k < 4; ++k) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * k, 8);
        output->push_back(word);
    }
}

Digest read_digest(const std::vector<u64>& input, size_t offset) {
    Digest result{};
    if (offset > input.size() || input.size() - offset < 4) return result;
    for (size_t k = 0; k < 4; ++k)
        std::memcpy(result.bytes.data() + 8 * k, &input[offset + k], 8);
    return result;
}

bool valid_setup_context(const AuthenticatedMpcMessageContext& context) {
    return context.protocol_domain == PVIA_VSS_SELECTIVE_POINT_DOMAIN &&
           context.message_kind == PVIA_VSS_POINT_SETUP_KIND &&
           validate_authenticated_mpc_message_context(context);
}

AuthenticatedMpcMessageContext acknowledgement_context(
    const AuthenticatedMpcMessageContext& context) {
    auto ack = context;
    ack.message_kind = PVIA_VSS_POINT_ACK_KIND;
    // Different kind/domain are disjoint replay namespaces.
    return ack;
}

F evaluate_private_row(const ReferenceVssLocalWitness& witness,
                       size_t element, int target) {
    const size_t dim = static_cast<size_t>(witness.threshold + 1);
    F value(0);
    const F point(target + 1);
    for (int d = witness.threshold; d >= 0; --d) {
        const size_t index = 2 * (element * dim + static_cast<size_t>(d));
        value = value * point + F(
            static_cast<long long>(witness.local_row_words[index]),
            static_cast<long long>(witness.local_row_words[index + 1]));
    }
    return value;
}

std::vector<F> evaluate_row_at(const ReferenceVssLocalWitness& witness,
                               int target) {
    std::vector<F> result;
    result.reserve(witness.element_count);
    for (size_t k = 0; k < witness.element_count; ++k)
        result.push_back(evaluate_private_row(witness, k, target));
    return result;
}

Digest point_commitment(const Digest& vss_transcript,
                        const Digest& setup_binding,
                        int helper, int target,
                        const std::vector<F>& values) {
    if (vss_transcript == Digest{} || setup_binding == Digest{} ||
        helper < 0 || target < 0 || values.empty() ||
        values.size() > (std::numeric_limits<size_t>::max() - 12) / 2)
        return {};
    std::vector<u64> preimage = {
        POINT_DOMAIN, static_cast<u64>(helper),
        static_cast<u64>(target), static_cast<u64>(values.size())};
    append_digest(vss_transcript, &preimage);
    append_digest(setup_binding, &preimage);
    for (const F& value : values) {
        if (value.real >= F::mod || value.img >= F::mod) return {};
        preimage.push_back(value.real);
        preimage.push_back(value.img);
    }
    return hash_words(preimage);
}

Digest registry_binding(const ReferenceVssSelectivePointCommitmentRegistry& r) {
    if (r.world_size < 4 || r.element_count == 0 ||
        r.sid == 0 || r.checkpoint == 0 ||
        r.setup_round == 0 || r.setup_sequence == 0 ||
        r.vss_transcript == Digest{} || r.setup_context_binding == Digest{} ||
        r.signed_commit_transport == Digest{} ||
        r.commitments.size() != static_cast<size_t>(r.world_size) *
                                 static_cast<size_t>(r.world_size))
        return {};
    std::vector<u64> words = {
        REGISTRY_DOMAIN, static_cast<u64>(r.world_size),
        static_cast<u64>(r.element_count), r.sid, r.checkpoint,
        r.setup_round, r.setup_sequence};
    append_digest(r.vss_transcript, &words);
    append_digest(r.setup_context_binding, &words);
    append_digest(r.signed_commit_transport, &words);
    for (const auto& digest : r.commitments) {
        if (digest == Digest{}) return {};
        append_digest(digest, &words);
    }
    return hash_words(words);
}
} // namespace

bool validate_reference_vss_point_commitment_registry(
    const ReferenceVssSelectivePointCommitmentRegistry& registry) {
    return registry.available && registry.world_size <= 1024 &&
           registry.signed_ack_transport != Digest{} &&
           registry.registry_binding != Digest{} &&
           registry.registry_binding == registry_binding(registry);
}

bool establish_reference_vss_point_commitment_registry(
    const ReferenceVssLocalWitness& local,
    const ReferenceVssReceipt& receipt,
    const AuthenticatedMpcExchange& exchange,
    const AuthenticatedMpcMessageContext& setup_context,
    ReferenceVssSelectivePointCommitmentRegistry* output) {
    if (!output) return false;
    *output = {};
    if (!valid_setup_context(setup_context) || !exchange.ready() ||
        !validate_reference_vss_local_witness(local) ||
        !receipt.available || !receipt.consistent ||
        receipt.world_size < 4 || receipt.threshold != local.threshold ||
        receipt.world_size != local.transcript_context.world_size ||
        receipt.dealer != local.dealer ||
        receipt.element_count != local.element_count ||
        receipt.transcript_binding != local.transcript_binding ||
        receipt.local_row_commitment != local.local_row_commitment ||
        receipt.world_size > 1024)
        return false;
    const size_t n = static_cast<size_t>(receipt.world_size);
    const Digest setup_binding =
        compute_authenticated_mpc_context_binding(setup_context);
    if (setup_binding == Digest{}) return false;
    std::vector<u64> local_words = {
        MATRIX_MAGIC, 1, static_cast<u64>(local.participant),
        static_cast<u64>(n), static_cast<u64>(receipt.element_count)};
    append_digest(receipt.transcript_binding, &local_words);
    for (size_t target = 0; target < n; ++target) {
        const auto values = evaluate_row_at(local, static_cast<int>(target));
        const Digest d = point_commitment(receipt.transcript_binding,
            setup_binding, local.participant, static_cast<int>(target), values);
        if (d == Digest{}) return false;
        append_digest(d, &local_words);
    }
    const size_t stride = HEADER_WORDS + 4 * n;
    if (local_words.size() != stride) return false;
    std::vector<u64> gathered;
    Digest signed_commit_transport{};
    if (!exchange.AllGatherWords(setup_context, local_words, &gathered,
                                  &signed_commit_transport) ||
        signed_commit_transport == Digest{} ||
        gathered.size() != n * stride)
        return false;

    ReferenceVssSelectivePointCommitmentRegistry candidate;
    candidate.world_size = receipt.world_size;
    candidate.element_count = receipt.element_count;
    candidate.vss_transcript = receipt.transcript_binding;
    candidate.sid = setup_context.sid;
    candidate.checkpoint = setup_context.checkpoint;
    candidate.setup_round = setup_context.round;
    candidate.setup_sequence = setup_context.sequence;
    candidate.setup_context_binding = setup_binding;
    candidate.signed_commit_transport = signed_commit_transport;
    candidate.commitments.resize(n * n);
    bool local_consistent = true;
    for (size_t helper = 0; helper < n; ++helper) {
        const size_t offset = helper * stride;
        if (gathered[offset] != MATRIX_MAGIC || gathered[offset + 1] != 1 ||
            gathered[offset + 2] != helper || gathered[offset + 3] != n ||
            gathered[offset + 4] != receipt.element_count ||
            read_digest(gathered, offset + 5) != receipt.transcript_binding)
            local_consistent = false;
        for (size_t target = 0; target < n; ++target) {
            const auto digest = read_digest(
                gathered, offset + HEADER_WORDS + 4 * target);
            candidate.commitments[helper * n + target] = digest;
            if (digest == Digest{}) local_consistent = false;
        }
        // f(helper, local.participant) = f(local.participant, helper)
        // for an accepted symmetric bivariate VSS transcript.
        const auto expectation = point_commitment(
            receipt.transcript_binding, setup_binding,
            static_cast<int>(helper), local.participant,
            evaluate_row_at(local, static_cast<int>(helper)));
        if (candidate.commitments[
                helper * n + static_cast<size_t>(local.participant)] !=
            expectation)
            local_consistent = false;
    }
    candidate.registry_binding = registry_binding(candidate);
    if (candidate.registry_binding == Digest{}) local_consistent = false;

    std::vector<u64> ack = {
        ACK_MAGIC, static_cast<u64>(local.participant),
        local_consistent ? 1ULL : 0ULL};
    append_digest(candidate.registry_binding, &ack);
    std::vector<u64> all_acks;
    Digest ack_binding{};
    if (!exchange.AllGatherWords(acknowledgement_context(setup_context),
                                  ack, &all_acks, &ack_binding) ||
        all_acks.size() != n * ack.size() ||
        ack_binding == Digest{})
        return false;
    if (!local_consistent) return false;
    for (size_t rank = 0; rank < n; ++rank) {
        const size_t offset = rank * ack.size();
        if (all_acks[offset] != ACK_MAGIC ||
            all_acks[offset + 1] != rank || all_acks[offset + 2] != 1 ||
            read_digest(all_acks, offset + 3) != candidate.registry_binding)
            return false;
    }
    candidate.signed_ack_transport = ack_binding;
    candidate.available = true;
    *output = std::move(candidate);
    return true;
}

bool verify_reference_vss_point_commitment(
    const ReferenceVssSelectivePointCommitmentRegistry& registry,
    const ReferenceVssSelectivePoint& opening,
    const ReferenceVssReceipt& receipt,
    const AuthenticatedMpcMessageContext& release_context) {
    if (!registry.available || !receipt.available || !receipt.consistent ||
        !validate_authenticated_mpc_message_context(release_context) ||
        release_context.protocol_domain != PVIA_VSS_SELECTIVE_POINT_DOMAIN ||
        release_context.message_kind != PVIA_VSS_SELECTIVE_POINT_KIND ||
        registry.world_size != receipt.world_size ||
        registry.element_count != receipt.element_count ||
        registry.vss_transcript != receipt.transcript_binding ||
        release_context.sid != registry.sid ||
        release_context.checkpoint != registry.checkpoint ||
        registry.signed_ack_transport == Digest{} ||
        registry.registry_binding != registry_binding(registry) ||
        opening.helper < 0 || opening.helper >= registry.world_size ||
        opening.target < 0 || opening.target >= registry.world_size ||
        opening.helper == opening.target ||
        opening.helper_row_commitment == Digest{} ||
        opening.transcript_binding != registry.vss_transcript ||
        opening.values.size() != registry.element_count ||
        registry.commitments.size() != static_cast<size_t>(registry.world_size) *
                                      static_cast<size_t>(registry.world_size))
        return false;
    // A release packet is accepted only within the same SID/checkpoint
    // in which all parties jointly established the commitment matrix.
    auto setup_context = release_context;
    setup_context.message_kind = PVIA_VSS_POINT_SETUP_KIND;
    // Setup round and sequence are saved from the authenticated setup;
    // release cannot select or rewrite them.
    setup_context.round = registry.setup_round;
    setup_context.sequence = registry.setup_sequence;
    if (compute_authenticated_mpc_context_binding(setup_context) !=
        registry.setup_context_binding) return false;
    const auto derived = point_commitment(
        registry.vss_transcript, registry.setup_context_binding,
        opening.helper, opening.target, opening.values);
    return derived != Digest{} &&
        derived == registry.commitments[
            static_cast<size_t>(opening.helper) *
                static_cast<size_t>(registry.world_size) +
            static_cast<size_t>(opening.target)];
}

bool recover_reference_vss_share_from_committed_points(
    int target,
    const ReferenceVssReceipt& receipt,
    const ReferenceVssTranscriptContext& transcript,
    const ReferenceVssSelectivePointCommitmentRegistry& registry,
    const AuthenticatedMpcMessageContext& context,
    const std::vector<ReferenceVssSelectivePoint>& openings,
    std::vector<F>* recovered) {
    if (!recovered) return false;
    recovered->clear();
    for (const auto& opening : openings) {
        if (opening.target != target ||
            !verify_reference_vss_point_commitment(
                registry, opening, receipt, context))
            return false;
    }
    return recover_reference_vss_share_from_points(
        target, receipt, transcript, openings, recovered);
}

} // namespace pvia
