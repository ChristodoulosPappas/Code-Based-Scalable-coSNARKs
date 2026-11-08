#include "PublicTransferObservation.hpp"
#include "TransferAuthentication.hpp"

#include <algorithm>
#include <cstring>

namespace pvia {
namespace {

Digest digest_from_words(const u64* words) {
    Digest digest;
    std::memcpy(digest.bytes.data(), words, digest.bytes.size());
    return digest;
}

void append_digest_words(const Digest& digest, std::vector<u64>& words) {
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words.push_back(word);
    }
}

bool same_ref(const OperationRef& lhs, const OperationRef& rhs) {
    return lhs.owner == rhs.owner && lhs.object_id == rhs.object_id;
}

bool contains_ref(const std::vector<OperationRef>& refs,
                  const OperationRef& ref) {
    return refs.empty() ||
        std::find(refs.begin(), refs.end(), ref) != refs.end();
}

} // namespace

std::vector<u64> encode_public_transfer_observation(
    const PublicTransferObservation& observation) {
    std::vector<u64> words = {
        observation.valid ? 1ULL : 0ULL,
        observation.ref.owner,
        observation.ref.object_id,
        observation.source_label.sid,
        static_cast<u64>(observation.source_label.phase),
        observation.source_label.round,
        observation.source_label.owner,
        static_cast<u64>(observation.source_label.obligation),
        observation.source_label.object_id,
        observation.transfer_label.sid,
        static_cast<u64>(observation.transfer_label.phase),
        observation.transfer_label.round,
        observation.transfer_label.owner,
        static_cast<u64>(observation.transfer_label.obligation),
        observation.transfer_label.object_id,
        observation.checkpoint,
        observation.observer_rank,
        observation.remote_observation ? 1ULL : 0ULL
    };
    words.push_back(observation.predecessor_count);
    append_digest_words(observation.predecessor_root, words);
    words.push_back(observation.state_dependency_count);
    append_digest_words(observation.state_dependency_root, words);
    words.push_back(observation.public_aux_count);
    append_digest_words(observation.public_aux_root, words);
    append_digest_words(observation.registered_digest, words);
    append_digest_words(observation.payload_digest, words);
    append_digest_words(observation.operation_statement_binding, words);
    append_digest_words(observation.metadata_binding, words);
    words.insert(words.end(), observation.authenticated_metadata.begin(),
                 observation.authenticated_metadata.end());
    return words;
}

bool decode_public_transfer_observation_unchecked(
    const std::vector<u64>& words,
    PublicTransferObservation* observation) {
    if (!observation || words.size() != PUBLIC_TRANSFER_OBSERVATION_WORDS)
        return false;
    PublicTransferObservation out;
    out.valid = words[0] != 0;
    out.ref.owner = static_cast<uint32_t>(words[1]);
    out.ref.object_id = words[2];
    out.source_label.sid = words[3];
    out.source_label.phase = static_cast<Phase>(static_cast<uint32_t>(words[4]));
    out.source_label.round = static_cast<uint32_t>(words[5]);
    out.source_label.owner = static_cast<uint32_t>(words[6]);
    out.source_label.obligation = static_cast<Obligation>(static_cast<uint32_t>(words[7]));
    out.source_label.object_id = words[8];
    out.transfer_label.sid = words[9];
    out.transfer_label.phase = static_cast<Phase>(static_cast<uint32_t>(words[10]));
    out.transfer_label.round = static_cast<uint32_t>(words[11]);
    out.transfer_label.owner = static_cast<uint32_t>(words[12]);
    out.transfer_label.obligation = static_cast<Obligation>(static_cast<uint32_t>(words[13]));
    out.transfer_label.object_id = words[14];
    out.checkpoint = words[15];
    out.observer_rank = static_cast<uint32_t>(words[16]);
    out.remote_observation = words[17] != 0;
    out.predecessor_count = static_cast<uint32_t>(words[18]);
    out.state_dependency_count = static_cast<uint32_t>(words[23]);
    out.public_aux_count = static_cast<uint32_t>(words[28]);
    auto load_digest = [&](size_t offset, Digest* digest) {
        for (size_t i = 0; i < 4; ++i)
            std::memcpy(digest->bytes.data() + 8 * i, &words[offset + i], 8);
    };
    load_digest(19, &out.predecessor_root);
    load_digest(24, &out.state_dependency_root);
    load_digest(29, &out.public_aux_root);
    load_digest(33, &out.registered_digest);
    load_digest(37, &out.payload_digest);
    load_digest(41, &out.operation_statement_binding);
    load_digest(45, &out.metadata_binding);
    std::copy(words.begin() + PUBLIC_TRANSFER_OBSERVATION_BASE_WORDS,
              words.end(), out.authenticated_metadata.begin());
    *observation = out;
    return true;
}

namespace {
bool validate_public_transfer_observation_structure(
    const PublicTransferObservation& observation) {
    if (!observation.valid) return false;
    if (observation.ref.owner != observation.source_label.owner ||
        observation.ref.object_id != observation.source_label.object_id)
        return false;
    if (observation.source_label.sid == 0) return false;
    if (observation.transfer_label.sid != observation.source_label.sid ||
        observation.transfer_label.phase != observation.source_label.phase ||
        observation.transfer_label.round != observation.source_label.round ||
        observation.transfer_label.owner != observation.source_label.owner ||
        observation.transfer_label.object_id != observation.source_label.object_id ||
        observation.transfer_label.obligation != Obligation::SEND)
        return false;
    const auto& meta = observation.authenticated_metadata;
    if (meta[1] != observation.source_label.sid ||
        meta[2] != static_cast<u64>(observation.source_label.phase) ||
        meta[3] != observation.source_label.round ||
        meta[4] != observation.source_label.owner ||
        meta[5] != static_cast<u64>(observation.source_label.obligation) ||
        meta[6] != observation.source_label.object_id)
        return false;
    if (observation.checkpoint == 0 ||
        meta[META_CHECKPOINT_INDEX] != observation.checkpoint ||
        observation.predecessor_root == Digest{} ||
        observation.state_dependency_root == Digest{} ||
        observation.public_aux_root == Digest{} ||
        observation.operation_statement_binding == Digest{} ||
        observation.metadata_binding == Digest{})
        return false;
    if (digest_from_words(&meta[8]) != observation.registered_digest ||
        digest_from_words(&meta[META_AUTH_WIRE_DIGEST_OFFSET]) !=
            observation.payload_digest ||
        digest_from_words(&meta[META_PREDECESSOR_ROOT_OFFSET]) !=
            observation.predecessor_root ||
        static_cast<uint32_t>(meta[META_PREDECESSOR_COUNT_INDEX]) !=
            observation.predecessor_count ||
        digest_from_words(&meta[META_STATE_DEP_ROOT_OFFSET]) !=
            observation.state_dependency_root ||
        static_cast<uint32_t>(meta[META_STATE_DEP_COUNT_INDEX]) !=
            observation.state_dependency_count ||
        digest_from_words(&meta[META_PUBLIC_AUX_ROOT_OFFSET]) !=
            observation.public_aux_root ||
        static_cast<uint32_t>(meta[META_PUBLIC_AUX_COUNT_INDEX]) !=
            observation.public_aux_count)
        return false;
    const Digest expected_metadata_binding = hash_words(
        std::vector<u64>(meta.begin(), meta.end()));
    if (observation.metadata_binding != expected_metadata_binding) return false;
    const Digest expected_statement = compute_relation_statement(
        observation.transfer_label, RelationKind::MESSAGE_BINDING,
        AuditRelationKernel::UNKNOWN, observation.registered_digest,
        observation.predecessor_root, observation.predecessor_count,
        observation.state_dependency_root, observation.state_dependency_count,
        observation.public_aux_root, observation.public_aux_count);
    if (observation.operation_statement_binding != expected_statement)
        return false;
    return compute_public_transfer_observation_binding(observation) != Digest{};
}
} // namespace

bool validate_public_transfer_observation(
    const PublicTransferObservation& observation) {
    if (!validate_public_transfer_observation_structure(observation))
        return false;
    const auto& auth = Ed25519TransferAuthenticator::instance();
    return auth.ready() && auth.Verify(
        observation.authenticated_metadata,
        static_cast<int>(observation.source_label.owner));
}

bool validate_public_transfer_observation_with_public_key(
    const PublicTransferObservation& observation,
    const std::array<uint8_t, 32>& public_key) {
    return validate_public_transfer_observation_structure(observation) &&
        verify_ed25519_transfer_meta_with_public_key(
            observation.authenticated_metadata, public_key,
            static_cast<int>(observation.source_label.owner));
}

bool decode_public_transfer_observation(
    const std::vector<u64>& words,
    PublicTransferObservation* observation) {
    PublicTransferObservation out;
    if (!decode_public_transfer_observation_unchecked(words, &out) ||
        !validate_public_transfer_observation(out))
        return false;
    *observation = out;
    return true;
}

Digest compute_public_transfer_observation_binding(
    const PublicTransferObservation& observation) {
    return hash_words(encode_public_transfer_observation(observation));
}

void PublicTransferObservationStore::Put(
    const PublicTransferObservation& observation) {
    if (!validate_public_transfer_observation(observation)) return;
    const size_t index = observations_.size();
    observations_.push_back(observation);
    checkpoint_index_[observation.checkpoint].push_back(index);
    ref_index_[observation.ref].push_back(index);
}

bool PublicTransferObservationStore::Has(const OperationRef& ref) const {
    const auto it = ref_index_.find(ref);
    return it != ref_index_.end() && !it->second.empty();
}

std::vector<PublicTransferObservation>
PublicTransferObservationStore::Select(const ObligationSet& scope) const {
    std::vector<PublicTransferObservation> out;

    // Exact failure/release scopes are checkpoint-bound in normal operation.
    // Use that index first.  For broader scopes with explicit operation refs,
    // union the per-ref indices and restore insertion order.
    const std::vector<size_t>* candidate_indices = nullptr;
    std::vector<size_t> merged_indices;

    if (scope.checkpoint != 0) {
        const auto checkpoint_it = checkpoint_index_.find(scope.checkpoint);
        if (checkpoint_it == checkpoint_index_.end()) return out;
        candidate_indices = &checkpoint_it->second;
    } else if (!scope.operations.empty()) {
        for (const OperationRef& ref : scope.operations) {
            const auto ref_it = ref_index_.find(ref);
            if (ref_it == ref_index_.end()) continue;
            merged_indices.insert(
                merged_indices.end(),
                ref_it->second.begin(), ref_it->second.end());
        }
        if (merged_indices.empty()) return out;
        std::sort(merged_indices.begin(), merged_indices.end());
        merged_indices.erase(
            std::unique(merged_indices.begin(), merged_indices.end()),
            merged_indices.end());
        candidate_indices = &merged_indices;
    }

    auto consider = [&](const PublicTransferObservation& observation) {
        if (!observation.valid) return;
        if (scope.session_id != 0 &&
            observation.transfer_label.sid != scope.session_id)
            return;
        if (scope.phase != Phase::UNKNOWN &&
            observation.transfer_label.phase != scope.phase)
            return;
        if (scope.exact_round &&
            observation.transfer_label.round != scope.round)
            return;
        if (scope.checkpoint != 0 &&
            observation.checkpoint != scope.checkpoint)
            return;
        const Obligation transfer_obligation =
            observation.transfer_label.obligation;
        if (transfer_obligation != Obligation::SEND &&
            transfer_obligation != Obligation::RECEIVE &&
            transfer_obligation != Obligation::CONSUME)
            return;
        if (!scope.obligations.empty() &&
            std::find(scope.obligations.begin(), scope.obligations.end(),
                      transfer_obligation) == scope.obligations.end())
            return;
        if (!contains_ref(scope.operations, observation.ref)) return;
        out.push_back(observation);
    };

    if (candidate_indices) {
        out.reserve(candidate_indices->size());
        for (size_t index : *candidate_indices) {
            if (index >= observations_.size()) continue;
            consider(observations_[index]);
        }
    } else {
        out.reserve(observations_.size());
        for (const auto& observation : observations_)
            consider(observation);
    }
    return out;
}

} // namespace pvia
