#include "PublicTransferBlameProof.hpp"

namespace pvia {
namespace {

bool statement_matches_evidence(
    const PublicBlameStatement& statement,
    const PublicTransferEvidence& evidence) {
    if (statement.evidence_kind != AuditEvidenceKind::PUBLIC_TRANSFER ||
        !evidence.available || !evidence.cryptographically_authenticated)
        return false;
    if (!validate_public_transfer_evidence_claim(evidence))
        return false;
    return statement.audit_evidence_binding == evidence.evidence_binding &&
           statement.accused == evidence.accused &&
           statement.label.sid == evidence.label.sid &&
           statement.label.phase == evidence.label.phase &&
           statement.label.round == evidence.label.round &&
           statement.label.owner == evidence.label.owner &&
           statement.label.obligation == evidence.label.obligation &&
           statement.label.object_id == evidence.label.object_id &&
           statement.checkpoint == evidence.checkpoint &&
           statement.relation == evidence.relation &&
           statement.expected == evidence.expected &&
           statement.actual == evidence.actual &&
           statement.residual_commitment == evidence.residual_commitment &&
           statement.operation_statement_binding ==
               evidence.operation_statement_binding &&
           statement.dispute_binding == evidence.dispute_binding &&
           statement.checkpoint_root == evidence.checkpoint_root;
}

} // namespace

PublicBlameProofArtifact BackendPublicTransferBlameProofEngine::Prove(
    const PublicBlameStatement& statement,
    const PublicTransferEvidence& evidence) const {
    PublicBlameProofArtifact artifact;
    if (statement.statement_binding == Digest{} ||
        statement.statement_binding !=
            compute_public_blame_statement_binding(statement) ||
        !statement_matches_evidence(statement, evidence))
        return artifact;

    const std::vector<u64> public_inputs =
        encode_public_blame_statement(statement);
    const std::vector<u64> public_evidence =
        encode_public_transfer_evidence(evidence);
    const ExternalPublicBlameProof external =
        backend_.Prove(public_inputs, public_evidence);
    if (!external.available || !external.cryptographically_authenticated ||
        external.proof_system_id == 0 ||
        external.transcript_binding == Digest{} ||
        external.proof_words.empty() ||
        !backend_.Verify(public_inputs, external))
        return artifact;

    artifact.available = true;
    artifact.cryptographically_authenticated = true;
    artifact.proof_system_id = external.proof_system_id;
    artifact.statement_binding = statement.statement_binding;
    artifact.transcript_binding = external.transcript_binding;
    artifact.proof_words = external.proof_words;
    artifact.proof_commitment =
        compute_public_blame_proof_commitment(artifact);
    return artifact;
}

bool BackendPublicTransferBlameProofEngine::Verify(
    const PublicBlameStatement& statement,
    const PublicBlameProofArtifact& artifact) const {
    if (statement.evidence_kind != AuditEvidenceKind::PUBLIC_TRANSFER ||
        !validate_public_blame_proof_artifact(statement, artifact))
        return false;
    ExternalPublicBlameProof external;
    external.available = artifact.available;
    external.cryptographically_authenticated =
        artifact.cryptographically_authenticated;
    external.proof_system_id = artifact.proof_system_id;
    external.transcript_binding = artifact.transcript_binding;
    external.proof_words = artifact.proof_words;
    return backend_.Verify(
        encode_public_blame_statement(statement), external);
}

PublicBlameProofArtifact FailClosedPublicTransferBlameProofEngine::Prove(
    const PublicBlameStatement& statement,
    const PublicTransferEvidence&) const {
    PublicBlameProofArtifact artifact;
    artifact.available = false;
    artifact.cryptographically_authenticated = false;
    artifact.statement_binding = statement.statement_binding;
    return artifact;
}

bool FailClosedPublicTransferBlameProofEngine::Verify(
    const PublicBlameStatement&,
    const PublicBlameProofArtifact&) const {
    return false;
}

} // namespace pvia
