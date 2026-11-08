#include "Ed25519PublicTransferJudge.hpp"
#include "PublicTransferCertificateCodec.hpp"

namespace pvia {
namespace {

bool prepare_statement_and_proof(
    const BlameCertificate& certificate,
    uint64_t expected_session_id,
    PublicBlameStatement* statement,
    PublicBlameProofArtifact* proof) {
    if (!statement || !proof || !certificate.valid || certificate.debug_only ||
        certificate.evidence_kind != AuditEvidenceKind::PUBLIC_TRANSFER)
        return false;
    if (certificate.sid == 0 || certificate.sid != expected_session_id ||
        certificate.label.sid != certificate.sid ||
        certificate.accused != certificate.label.owner)
        return false;
    if (certificate.relation != RelationKind::MESSAGE_BINDING ||
        certificate.kernel != AuditRelationKernel::UNKNOWN ||
        certificate.label.obligation != Obligation::SEND ||
        certificate.predecessor_root != Digest{})
        return false;
    if (certificate.expected == certificate.actual ||
        certificate.checkpoint == 0 ||
        certificate.checkpoint_root == Digest{} ||
        certificate.audit_witness_digest == Digest{})
        return false;
    if (certificate.residual_commitment != compute_residual_commitment(
            certificate.label, certificate.relation, certificate.kernel,
            certificate.expected, certificate.actual))
        return false;
    if (certificate.operation_statement_binding == Digest{} ||
        certificate.dispute_binding == Digest{} ||
        certificate.blame_statement_binding == Digest{} ||
        certificate.public_proof_system_id == 0 ||
        certificate.public_proof_commitment == Digest{} ||
        certificate.public_proof_transcript_binding == Digest{} ||
        certificate.public_proof_words.empty())
        return false;

    *statement = make_public_blame_statement(certificate);
    if (statement->statement_binding == Digest{} ||
        statement->statement_binding != certificate.blame_statement_binding)
        return false;
    proof->available = true;
    proof->cryptographically_authenticated = true;
    proof->proof_system_id = certificate.public_proof_system_id;
    proof->statement_binding = certificate.blame_statement_binding;
    proof->proof_commitment = certificate.public_proof_commitment;
    proof->transcript_binding = certificate.public_proof_transcript_binding;
    proof->proof_words = certificate.public_proof_words;
    if (!validate_public_blame_proof_artifact(*statement, *proof)) return false;
    return certificate.transcript_digest == proof->transcript_binding &&
           certificate.proof_digest == proof->proof_commitment;
}

} // namespace

bool Ed25519PublicTransferJudge::Verify(
    const BlameCertificate& certificate,
    uint64_t expected_session_id) {
    PublicBlameStatement statement;
    PublicBlameProofArtifact proof;
    if (!prepare_statement_and_proof(
            certificate, expected_session_id, &statement, &proof))
        return false;
    Ed25519PublicTransferBlameProofBackend backend;
    BackendPublicTransferBlameProofEngine engine(backend);
    return engine.Verify(statement, proof);
}

bool Ed25519PublicTransferJudge::VerifyAnchored(
    const BlameCertificate& certificate,
    uint64_t expected_session_id,
    const Digest& expected_registry_anchor) {
    if (expected_registry_anchor == Digest{}) return false;
    PublicBlameStatement statement;
    PublicBlameProofArtifact proof;
    if (!prepare_statement_and_proof(
            certificate, expected_session_id, &statement, &proof))
        return false;
    Ed25519PublicTransferBlameProofBackend backend;
    ExternalPublicBlameProof external;
    external.available = proof.available;
    external.cryptographically_authenticated = proof.cryptographically_authenticated;
    external.proof_system_id = proof.proof_system_id;
    external.transcript_binding = proof.transcript_binding;
    external.proof_words = proof.proof_words;
    return backend.VerifyAnchored(
        encode_public_blame_statement(statement), external,
        expected_registry_anchor);
}

bool Ed25519PublicTransferJudge::VerifyEncoded(
    const std::vector<u64>& encoded_certificate,
    uint64_t expected_session_id,
    const Digest& expected_registry_anchor) {
    BlameCertificate certificate;
    if (!decode_public_transfer_blame_certificate(
            encoded_certificate, &certificate))
        return false;
    return VerifyAnchored(
        certificate, expected_session_id, expected_registry_anchor);
}

} // namespace pvia
