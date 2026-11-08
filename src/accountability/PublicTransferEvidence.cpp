#include "PublicTransferEvidence.hpp"

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

CollectiveDisputeResult reconstruct_transfer_dispute(
    const PublicTransferEvidence& evidence) {
    CollectiveDisputeResult result;
    result.available = true;
    result.cryptographically_authenticated = true;
    result.found = true;
    result.accused = evidence.accused;
    result.checkpoint = evidence.checkpoint;
    result.relation = evidence.relation;
    result.kernel = AuditRelationKernel::UNKNOWN;
    result.label = evidence.label;
    result.expected = evidence.expected;
    result.actual = evidence.actual;
    result.residual_commitment = evidence.residual_commitment;
    result.operation_statement_binding = evidence.operation_statement_binding;
    result.batch_result_binding = evidence.batch_check_binding;
    result.public_evidence_binding = evidence.observation_binding;
    result.recursive_transcript_binding = evidence.recursive_transcript_binding;
    result.localization_commitment = evidence.localization_commitment;
    return result;
}

bool same_violation(const Violation& violation,
                    const CollectiveDisputeResult& dispute) {
    return violation.valid && dispute.available && dispute.found &&
           dispute.cryptographically_authenticated &&
           violation.label.sid == dispute.label.sid &&
           violation.label.phase == dispute.label.phase &&
           violation.label.round == dispute.label.round &&
           violation.label.owner == dispute.label.owner &&
           violation.label.obligation == dispute.label.obligation &&
           violation.label.object_id == dispute.label.object_id &&
           violation.checkpoint == dispute.checkpoint &&
           violation.relation == dispute.relation &&
           violation.kernel == dispute.kernel &&
           violation.expected == dispute.expected &&
           violation.actual == dispute.actual &&
           violation.residual_commitment == dispute.residual_commitment &&
           violation.operation_statement_binding ==
               dispute.operation_statement_binding &&
           violation.dispute_binding ==
               compute_collective_dispute_binding(dispute);
}

} // namespace

std::vector<u64> encode_public_transfer_evidence(
    const PublicTransferEvidence& evidence) {
    std::vector<u64> words = {
        evidence.available ? 1ULL : 0ULL,
        evidence.cryptographically_authenticated ? 1ULL : 0ULL,
        evidence.accused.owner,
        evidence.accused.object_id,
        evidence.label.sid,
        static_cast<u64>(evidence.label.phase),
        evidence.label.round,
        evidence.label.owner,
        static_cast<u64>(evidence.label.obligation),
        evidence.label.object_id,
        evidence.checkpoint,
        static_cast<u64>(evidence.relation)
    };
    append_digest_words(evidence.expected, words);
    append_digest_words(evidence.actual, words);
    append_digest_words(evidence.residual_commitment, words);
    append_digest_words(evidence.operation_statement_binding, words);
    append_digest_words(evidence.dispute_binding, words);
    append_digest_words(evidence.checkpoint_root, words);
    append_digest_words(evidence.scope_binding, words);
    append_digest_words(evidence.batch_check_binding, words);
    append_digest_words(evidence.transfer_transcript_binding, words);
    append_digest_words(evidence.authentication_commitment, words);
    append_digest_words(evidence.recursive_transcript_binding, words);
    append_digest_words(evidence.localization_commitment, words);
    append_digest_words(evidence.observation_binding, words);
    const std::vector<u64> observation_words =
        encode_public_transfer_observation(evidence.observation);
    words.push_back(static_cast<u64>(observation_words.size()));
    words.insert(words.end(), observation_words.begin(), observation_words.end());
    return words;
}

Digest compute_public_transfer_evidence_binding(
    const PublicTransferEvidence& evidence) {
    return hash_words(encode_public_transfer_evidence(evidence));
}
PublicTransferEvidence make_public_transfer_evidence(
    const Violation& violation,
    const ObligationSet& transfer_scope,
    const PublicTransferCheckResult& check,
    const CollectiveDisputeResult& dispute,
    const PublicTransferObservation& observation) {
    PublicTransferEvidence evidence;
    if (!validate_public_transfer_check_result(transfer_scope, check) ||
        check.ok ||
        !validate_public_transfer_dispute_result(
            transfer_scope, check, dispute) ||
        !same_violation(violation, dispute) ||
        !public_transfer_observation_supports_dispute(observation, dispute) ||
        !transfer_relation(violation.relation) ||
        violation.relation != RelationKind::MESSAGE_BINDING ||
        violation.kernel != AuditRelationKernel::UNKNOWN ||
        transfer_scope.checkpoint_root == Digest{})
        return evidence;

    evidence.available = true;
    evidence.cryptographically_authenticated = true;
    evidence.accused = dispute.accused;
    evidence.label = violation.label;
    evidence.checkpoint = violation.checkpoint;
    evidence.relation = violation.relation;
    evidence.expected = violation.expected;
    evidence.actual = violation.actual;
    evidence.residual_commitment = violation.residual_commitment;
    evidence.operation_statement_binding =
        violation.operation_statement_binding;
    evidence.dispute_binding = violation.dispute_binding;
    evidence.checkpoint_root = transfer_scope.checkpoint_root;
    evidence.scope_binding = check.scope_binding;
    evidence.batch_check_binding =
        compute_public_transfer_check_binding(check);
    evidence.transfer_transcript_binding = check.transcript_binding;
    evidence.authentication_commitment = check.authentication_commitment;
    evidence.recursive_transcript_binding =
        dispute.recursive_transcript_binding;
    evidence.localization_commitment = dispute.localization_commitment;
    evidence.observation = observation;
    evidence.observation_binding =
        compute_public_transfer_observation_binding(observation);
    evidence.evidence_binding =
        compute_public_transfer_evidence_binding(evidence);
    return evidence;
}

namespace {
bool validate_public_transfer_evidence_claim_after_observation(
    const PublicTransferEvidence& evidence) {
    if (!evidence.available || !evidence.cryptographically_authenticated ||
        evidence.evidence_binding == Digest{})
        return false;
    if (evidence.observation_binding == Digest{} ||
        evidence.observation_binding !=
            compute_public_transfer_observation_binding(evidence.observation))
        return false;
    if (evidence.checkpoint_root == Digest{} ||
        evidence.scope_binding == Digest{} ||
        evidence.batch_check_binding == Digest{} ||
        evidence.transfer_transcript_binding == Digest{} ||
        evidence.authentication_commitment == Digest{} ||
        evidence.recursive_transcript_binding == Digest{} ||
        evidence.localization_commitment == Digest{})
        return false;
    if (evidence.relation != RelationKind::MESSAGE_BINDING ||
        evidence.label.obligation != Obligation::SEND ||
        evidence.accused != evidence.observation.ref ||
        evidence.label.sid != evidence.observation.transfer_label.sid ||
        evidence.label.phase != evidence.observation.transfer_label.phase ||
        evidence.label.round != evidence.observation.transfer_label.round ||
        evidence.label.owner != evidence.observation.transfer_label.owner ||
        evidence.label.object_id != evidence.observation.transfer_label.object_id ||
        evidence.checkpoint != evidence.observation.checkpoint)
        return false;
    if (evidence.expected != evidence.observation.registered_digest ||
        evidence.actual != evidence.observation.payload_digest ||
        evidence.expected == evidence.actual ||
        evidence.operation_statement_binding !=
            evidence.observation.operation_statement_binding)
        return false;
    if (evidence.residual_commitment != compute_residual_commitment(
            evidence.label, evidence.relation, AuditRelationKernel::UNKNOWN,
            evidence.expected, evidence.actual))
        return false;
    const CollectiveDisputeResult dispute =
        reconstruct_transfer_dispute(evidence);
    if (evidence.dispute_binding !=
        compute_collective_dispute_binding(dispute))
        return false;
    return evidence.evidence_binding ==
        compute_public_transfer_evidence_binding(evidence);

}
} // namespace

bool validate_public_transfer_evidence_claim(
    const PublicTransferEvidence& evidence) {
    return validate_public_transfer_observation(evidence.observation) &&
        validate_public_transfer_evidence_claim_after_observation(evidence);
}

bool validate_public_transfer_evidence_claim_with_public_key(
    const PublicTransferEvidence& evidence,
    const std::array<uint8_t, 32>& public_key) {
    return validate_public_transfer_observation_with_public_key(
               evidence.observation, public_key) &&
        validate_public_transfer_evidence_claim_after_observation(evidence);
}

bool validate_public_transfer_evidence(
    const Violation& violation,
    const ObligationSet& transfer_scope,
    const PublicTransferCheckResult& check,
    const CollectiveDisputeResult& dispute,
    const PublicTransferObservation& observation,
    const PublicTransferEvidence& evidence) {
    if (!validate_public_transfer_evidence_claim(evidence)) return false;
    const PublicTransferEvidence expected = make_public_transfer_evidence(
        violation, transfer_scope, check, dispute, observation);
    if (!expected.available ||
        expected.evidence_binding != evidence.evidence_binding)
        return false;
    if (encode_public_transfer_evidence(expected) !=
        encode_public_transfer_evidence(evidence))
        return false;
    return evidence.evidence_binding ==
        compute_public_transfer_evidence_binding(evidence);
}

} // namespace pvia
