#include "PublicTransferCheckEngine.hpp"

#include <algorithm>
#include <cstring>
#include <vector>

namespace pvia {
namespace {

void append_digest_words(const Digest& digest, std::vector<u64>& words) {
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words.push_back(word);
    }
}

bool transfer_relation(RelationKind relation) {
    return relation == RelationKind::MESSAGE_BINDING ||
           relation == RelationKind::RECEIVE_CONSUME;
}

} // namespace

Digest compute_public_transfer_check_binding(
    const PublicTransferCheckResult& result) {
    std::vector<u64> words = {
        result.available ? 1ULL : 0ULL,
        result.cryptographically_authenticated ? 1ULL : 0ULL,
        result.ok ? 1ULL : 0ULL,
        result.checkpoint,
        static_cast<u64>(result.checked_operations),
        static_cast<u64>(result.mismatches)
    };
    append_digest_words(result.scope_binding, words);
    append_digest_words(result.transcript_binding, words);
    append_digest_words(result.authentication_commitment, words);
    return hash_words(words);
}

bool validate_public_transfer_check_result(
    const ObligationSet& scope,
    const PublicTransferCheckResult& result) {
    if (!result.available || !result.cryptographically_authenticated)
        return false;
    if (result.checkpoint != scope.checkpoint) return false;
    if (result.scope_binding != compute_collective_scope_binding(scope))
        return false;
    if (!scope.operations.empty() &&
        result.checked_operations != scope.operations.size())
        return false;
    if (result.transcript_binding == Digest{} ||
        result.authentication_commitment == Digest{})
        return false;
    if (result.ok && result.mismatches != 0) return false;
    if (!result.ok && result.mismatches == 0) return false;
    return true;
}

BatchCheckResult make_public_transfer_batch_envelope(
    const ObligationSet& scope,
    const PublicTransferCheckResult& result,
    int world_size) {
    BatchCheckResult envelope;
    envelope.available = result.available;
    envelope.cryptographically_authenticated =
        result.cryptographically_authenticated;
    envelope.ok = result.ok;
    envelope.checkpoint = result.checkpoint;
    envelope.checked_operations = result.checked_operations;
    envelope.mismatches = result.mismatches;
    envelope.participant_count = world_size > 0
        ? static_cast<size_t>(world_size) : 0;
    envelope.scope_binding = result.scope_binding;
    envelope.participant_commitment_root = result.transcript_binding;
    envelope.challenge_transcript_binding = result.authentication_commitment;
    const Digest binding = compute_public_transfer_check_binding(result);
    envelope.challenge = binding;
    envelope.aggregate_residual_commitment = binding;
    return envelope;
}

bool validate_public_transfer_dispute_result(
    const ObligationSet& scope,
    const PublicTransferCheckResult& check,
    const CollectiveDisputeResult& result) {
    if (!validate_public_transfer_check_result(scope, check) || check.ok)
        return false;
    if (!result.available || !result.cryptographically_authenticated ||
        !result.found)
        return false;
    if (result.checkpoint != scope.checkpoint ||
        result.label.sid != scope.session_id ||
        result.label.owner != result.accused.owner ||
        result.label.object_id != result.accused.object_id ||
        result.label.phase != scope.phase)
        return false;
    if (scope.exact_round && result.label.round != scope.round) return false;
    if (!scope.operations.empty() &&
        std::find(scope.operations.begin(), scope.operations.end(),
                  result.accused) == scope.operations.end())
        return false;
    if (!transfer_relation(result.relation) ||
        relation_for_obligation(result.label.obligation) != result.relation)
        return false;
    if (result.kernel != AuditRelationKernel::UNKNOWN) return false;
    if (result.expected == result.actual ||
        result.operation_statement_binding == Digest{})
        return false;
    if (result.residual_commitment != compute_residual_commitment(
            result.label, result.relation, AuditRelationKernel::UNKNOWN,
            result.expected, result.actual))
        return false;
    if (result.batch_result_binding !=
        compute_public_transfer_check_binding(check))
        return false;
    if (result.public_evidence_binding == Digest{}) return false;
    if (result.recursive_transcript_binding == Digest{} ||
        result.localization_commitment == Digest{})
        return false;
    return true;
}

bool public_transfer_observation_supports_dispute(
    const PublicTransferObservation& observation,
    const CollectiveDisputeResult& result) {
    if (!validate_public_transfer_observation(observation)) return false;
    if (result.relation != RelationKind::MESSAGE_BINDING ||
        result.kernel != AuditRelationKernel::UNKNOWN ||
        result.label.obligation != Obligation::SEND)
        return false;
    if (result.accused != observation.ref ||
        result.label.sid != observation.transfer_label.sid ||
        result.label.phase != observation.transfer_label.phase ||
        result.label.round != observation.transfer_label.round ||
        result.label.owner != observation.transfer_label.owner ||
        result.label.object_id != observation.transfer_label.object_id ||
        result.checkpoint != observation.checkpoint)
        return false;
    if (result.expected != observation.registered_digest ||
        result.actual != observation.payload_digest ||
        result.operation_statement_binding !=
            observation.operation_statement_binding)
        return false;
    return result.public_evidence_binding ==
        compute_public_transfer_observation_binding(observation);
}

bool find_public_transfer_observation_for_dispute(
    const PublicTransferObservationStore& observations,
    const ObligationSet& scope,
    const CollectiveDisputeResult& result,
    PublicTransferObservation* matched) {
    bool found = false;
    PublicTransferObservation candidate;
    for (const auto& observation : observations.Select(scope)) {
        if (!public_transfer_observation_supports_dispute(observation, result))
            continue;
        if (!found) {
            candidate = observation;
            found = true;
            continue;
        }
        if (encode_public_transfer_observation(candidate) !=
            encode_public_transfer_observation(observation))
            return false;
    }
    if (!found) return false;
    if (matched) *matched = candidate;
    return true;
}

PublicTransferCheckResult BackendPublicTransferCheckEngine::Check(
    const ObligationSet& scope,
    const PublicTransferObservationStore& observations,
    int rank,
    int world_size) const {
    PublicTransferCheckResult unavailable;
    unavailable.checkpoint = scope.checkpoint;
    const std::vector<PublicTransferObservation> selected =
        observations.Select(scope);
    const PublicTransferCheckResult result = backend_.Check(
        scope, selected, rank, world_size);
    if (!validate_public_transfer_check_result(scope, result))
        return unavailable;
    return result;
}

CollectiveDisputeResult BackendPublicTransferCheckEngine::Dispute(
    const ObligationSet& scope,
    const PublicTransferCheckResult& check,
    const PublicTransferObservationStore& observations,
    int rank,
    int world_size) const {
    CollectiveDisputeResult unavailable;
    unavailable.checkpoint = scope.checkpoint;
    if (!validate_public_transfer_check_result(scope, check) || check.ok)
        return unavailable;
    const std::vector<PublicTransferObservation> selected =
        observations.Select(scope);
    const CollectiveDisputeResult result = backend_.Dispute(
        scope, check, selected, rank, world_size);
    if (!validate_public_transfer_dispute_result(scope, check, result))
        return unavailable;
    return result;
}

PublicTransferCheckResult FailClosedPublicTransferCheckEngine::Check(
    const ObligationSet& scope,
    const PublicTransferObservationStore&, int, int) const {
    PublicTransferCheckResult result;
    result.checkpoint = scope.checkpoint;
    return result;
}
CollectiveDisputeResult FailClosedPublicTransferCheckEngine::Dispute(
    const ObligationSet& scope,
    const PublicTransferCheckResult&,
    const PublicTransferObservationStore&,
    int,
    int) const {
    CollectiveDisputeResult result;
    result.checkpoint = scope.checkpoint;
    return result;
}

} // namespace pvia
