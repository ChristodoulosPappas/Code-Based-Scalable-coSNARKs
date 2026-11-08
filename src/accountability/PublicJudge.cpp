#include "PublicJudge.hpp"
#include "Sp1VssRecoveryProofProvider.hpp"
#include "MultiplicationConsistencyProof.hpp"

#include <algorithm>
#include <cstring>
#include <vector>

namespace pvia {
namespace {

void append_digest_words(const Digest& digest, std::vector<u64>& words) {
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + i * 8, 8);
        words.push_back(word);
    }
}

bool evidence_ref_less(const OperationEvidence& lhs,
                       const OperationEvidence& rhs) {
    if (lhs.ref.owner != rhs.ref.owner) return lhs.ref.owner < rhs.ref.owner;
    return lhs.ref.object_id < rhs.ref.object_id;
}

Digest predecessor_root_from_evidence(
    const std::vector<OperationEvidence>& evidence) {
    std::vector<u64> words;
    for (const auto& item : evidence) {
        words.push_back(item.ref.owner);
        words.push_back(item.ref.object_id);
        append_digest_words(item.actual, words);
        append_digest_words(item.predecessor_root, words);
    }
    return hash_words(words);
}

Digest checkpoint_root_from_evidence(const BlameCertificate& cert) {
    std::vector<OperationEvidence> evidence = cert.checkpoint_evidence;
    std::sort(evidence.begin(), evidence.end(), evidence_ref_less);
    std::vector<u64> words = {
        cert.checkpoint, static_cast<u64>(cert.label.phase), cert.label.round };
    for (const auto& item : evidence) {
        words.push_back(item.ref.owner);
        words.push_back(item.ref.object_id);
        words.push_back(static_cast<u64>(item.obligation));
        words.push_back(static_cast<u64>(item.relation));
        words.push_back(static_cast<u64>(item.kernel));
        words.push_back(item.source_checkpoint_hint);
        words.push_back(item.predecessor_count);
        words.push_back(item.state_dependency_count);
        words.push_back(item.public_aux_count);
        append_digest_words(item.expected, words);
        append_digest_words(item.actual, words);
        append_digest_words(item.predecessor_root, words);
        append_digest_words(item.state_dependency_root, words);
        append_digest_words(item.public_aux_root, words);
        append_digest_words(item.relation_statement, words);
    }
    return hash_words(words);
}

bool valid_checkpoint_relation_evidence(
    const BlameCertificate& cert, const OperationEvidence& item) {
    const RelationKind expected_relation = relation_for_obligation(item.obligation);
    if (item.relation != expected_relation) return false;
    if (item.relation == RelationKind::PRIVATE_DERIVATION &&
        item.kernel == AuditRelationKernel::UNKNOWN) return false;
    if (item.kernel != AuditRelationKernel::UNKNOWN &&
        relation_for_kernel(item.kernel) != item.relation) return false;
    if (!item.public_aux_evidence_complete) return false;
    if (item.public_aux_count != item.public_aux_evidence.size()) return false;
    if (item.public_aux_root != compute_public_aux_root(item.public_aux_evidence))
        return false;
    if (!item.state_dependency_evidence_complete) return false;
    if (item.state_dependency_count != item.state_dependency_evidence.size())
        return false;
    if (item.state_dependency_root !=
        compute_state_dependency_root(item.state_dependency_evidence))
        return false;

    Label label;
    label.sid = cert.sid;
    label.phase = cert.label.phase;
    label.round = cert.label.round;
    label.owner = item.ref.owner;
    label.obligation = item.obligation;
    label.object_id = item.ref.object_id;
    return item.relation_statement == compute_relation_statement(
        label, item.relation, item.kernel, item.expected, item.predecessor_root,
        item.predecessor_count, item.state_dependency_root,
        item.state_dependency_count, item.public_aux_root, item.public_aux_count);
}

const OperationEvidence* accused_operation(const BlameCertificate& cert) {
    for (const auto& item : cert.checkpoint_evidence) {
        if (item.ref.owner == cert.label.owner &&
            item.ref.object_id == cert.label.object_id)
            return &item;
    }
    return nullptr;
}

} // namespace

Digest PublicJudge::compute_debug_proof_digest(
    const BlameCertificate& cert) {
    std::vector<u64> words = {
        cert.sid,
        cert.accused,
        static_cast<u64>(cert.label.phase),
        cert.label.round,
        cert.label.owner,
        static_cast<u64>(cert.label.obligation),
        cert.label.object_id,
        cert.checkpoint,
        static_cast<u64>(cert.relation),
        static_cast<u64>(cert.kernel),
        cert.predecessor_evidence_complete ? 1ULL : 0ULL,
        static_cast<u64>(cert.predecessor_evidence.size()),
        static_cast<u64>(cert.checkpoint_evidence.size())
    };
    append_digest_words(cert.expected, words);
    append_digest_words(cert.actual, words);
    append_digest_words(cert.residual_commitment, words);
    append_digest_words(cert.operation_statement_binding, words);
    append_digest_words(cert.dispute_binding, words);
    append_digest_words(cert.predecessor_root, words);
    append_digest_words(cert.checkpoint_root, words);
    append_digest_words(cert.audit_witness_digest, words);
    append_digest_words(cert.transcript_digest, words);
    append_digest_words(cert.blame_statement_binding, words);
    words.push_back(cert.public_proof_system_id);
    append_digest_words(cert.public_proof_commitment, words);
    append_digest_words(cert.public_proof_transcript_binding, words);
    words.push_back(static_cast<u64>(cert.public_proof_words.size()));
    words.insert(words.end(), cert.public_proof_words.begin(),
                 cert.public_proof_words.end());
    return hash_words(words);
}

bool PublicJudge::VerifyDebug(const BlameCertificate& cert,
                              uint64_t expected_session_id) {
    if (!cert.valid || !cert.debug_only) return false;
    if (cert.blame_statement_binding != Digest{} ||
        cert.public_proof_system_id != 0 ||
        cert.public_proof_commitment != Digest{} ||
        cert.public_proof_transcript_binding != Digest{} ||
        !cert.public_proof_words.empty() ||
        !cert.recovery_artifact_words.empty())
        return false;
    if (cert.sid != expected_session_id) return false;
    if (cert.label.sid != cert.sid) return false;
    if (cert.accused != cert.label.owner) return false;
    if (cert.expected == cert.actual) return false;
    if (cert.relation == RelationKind::UNKNOWN) return false;
    if (cert.kernel == AuditRelationKernel::UNKNOWN &&
        cert.relation == RelationKind::PRIVATE_DERIVATION) return false;
    if (cert.kernel != AuditRelationKernel::UNKNOWN &&
        relation_for_kernel(cert.kernel) != cert.relation) return false;
    if (cert.checkpoint_root == Digest{} ||
        cert.operation_statement_binding == Digest{}) return false;
    if (cert.residual_commitment != compute_residual_commitment(
            cert.label, cert.relation, cert.kernel, cert.expected, cert.actual))
        return false;

    if (!cert.predecessor_evidence_complete) return false;
    if (cert.predecessor_root !=
        predecessor_root_from_evidence(cert.predecessor_evidence))
        return false;
    if (cert.checkpoint_evidence.empty()) return false;
    for (const auto& evidence : cert.checkpoint_evidence) {
        if (!valid_checkpoint_relation_evidence(cert, evidence)) return false;
    }
    if (cert.checkpoint_root != checkpoint_root_from_evidence(cert))
        return false;

    const OperationEvidence* accused = accused_operation(cert);
    if (!accused) return false;
    if (accused->predecessor_root != cert.predecessor_root) return false;
    if (accused->predecessor_count != cert.predecessor_evidence.size())
        return false;
    if (accused->relation_statement != cert.operation_statement_binding)
        return false;
    if (cert.relation == RelationKind::MESSAGE_BINDING) {
        if (cert.kernel != AuditRelationKernel::UNKNOWN) return false;
        if (accused->actual != cert.expected) return false;
    } else {
        if (accused->kernel != cert.kernel) return false;
        if (accused->obligation != cert.label.obligation) return false;
        if (accused->relation != cert.relation) return false;
        if (accused->expected != cert.expected || accused->actual != cert.actual)
            return false;
    }

    if (cert.checkpoint == 0) return false;
    const uint32_t checkpoint_phase =
        static_cast<uint32_t>((cert.checkpoint >> 56) & 0xffULL);
    const uint32_t checkpoint_round =
        static_cast<uint32_t>((cert.checkpoint >> 24) & 0xffffffffULL);
    if (checkpoint_phase != static_cast<uint32_t>(cert.label.phase)) return false;
    if (checkpoint_round != cert.label.round) return false;

    return cert.proof_digest == compute_debug_proof_digest(cert);
}

bool PublicJudge::VerifyRecoveryReceipt(
    const BlameCertificate& certificate,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& externally_pinned_registry_commitment) {
    if (!certificate.valid || certificate.debug_only ||
        certificate.evidence_kind != AuditEvidenceKind::PRIVATE_RECOVERY ||
        certificate.recovery_artifact_words.empty() ||
        certificate.accused != certificate.label.owner ||
        externally_pinned_registry_commitment == Digest{})
        return false;

    const PublicBlameStatement statement =
        make_public_blame_statement(certificate);
    if (statement.statement_binding == Digest{} ||
        statement.statement_binding != certificate.blame_statement_binding)
        return false;
    PublicBlameProofArtifact proof;
    proof.available = true;
    proof.cryptographically_authenticated = true;
    proof.proof_system_id = certificate.public_proof_system_id;
    proof.statement_binding = certificate.blame_statement_binding;
    proof.proof_commitment = certificate.public_proof_commitment;
    proof.transcript_binding = certificate.public_proof_transcript_binding;
    proof.proof_words = certificate.public_proof_words;
    proof.recovery_proof_system_id = certificate.recovery_proof_system_id;
    proof.recovery_proof_statement_binding =
        certificate.recovery_proof_statement_binding;
    proof.recovery_proof_artifact_commitment =
        certificate.recovery_proof_artifact_commitment;
    proof.recovery_proof_statement_words =
        certificate.recovery_proof_statement_words;
    proof.recovery_proof_artifact_bytes =
        certificate.recovery_proof_artifact_bytes;
    if (!validate_public_blame_proof_artifact(statement, proof) ||
        certificate.proof_digest != certificate.public_proof_commitment ||
        certificate.transcript_digest !=
            certificate.public_proof_transcript_binding)
        return false;

    const AuthenticatedRecoveryRequest request =
        make_recovery_request(certificate);
    AuthenticatedRecoveryArtifact recovery;
    if (request.request_binding == Digest{} ||
        !decode_authenticated_recovery_artifact(
            certificate.recovery_artifact_words, &recovery) ||
        !validate_recovery_artifact(request, recovery) ||
        compute_recovery_artifact_binding(recovery) !=
            certificate.audit_witness_digest ||
        recovery.accused != OperationRef{
            certificate.label.owner, certificate.label.object_id} ||
        recovery.recovery_auth_signer != certificate.label.owner ||
        recovery.predecessor_root != certificate.predecessor_root ||
        recovery.checkpoint_root != certificate.checkpoint_root)
        return false;

    return verify_authenticated_recovery_receipt(
        request, recovery, public_keys,
        externally_pinned_registry_commitment);
}


bool PublicJudge::ValidateRecoveryRelationStatement(
    const BlameCertificate& certificate,
    const std::vector<u64>& expected_statement_words) {
    constexpr uint64_t kStatementDomain = 0x5056524350525331ULL;
    constexpr uint64_t kProofSystemId = 68103ULL;
    if (!certificate.valid || certificate.debug_only ||
        certificate.evidence_kind != AuditEvidenceKind::PRIVATE_RECOVERY ||
        certificate.accused != certificate.label.owner ||
        certificate.sid == 0 || certificate.label.sid != certificate.sid ||
        certificate.checkpoint == 0 ||
        certificate.recovery_proof_system_id != kProofSystemId ||
        certificate.recovery_proof_statement_binding == Digest{} ||
        certificate.recovery_proof_artifact_commitment == Digest{} ||
        certificate.recovery_proof_statement_words.size() != 85 ||
        expected_statement_words.size() != 85 ||
        certificate.recovery_proof_statement_words != expected_statement_words ||
        certificate.recovery_proof_artifact_bytes.empty() ||
        certificate.recovery_artifact_words.empty())
        return false;

    const AuthenticatedRecoveryRequest request = make_recovery_request(certificate);
    AuthenticatedRecoveryArtifact recovery;
    if (request.request_binding == Digest{} ||
        !decode_authenticated_recovery_artifact(
            certificate.recovery_artifact_words, &recovery) ||
        !validate_recovery_artifact(request, recovery) ||
        compute_recovery_artifact_binding(recovery) !=
            certificate.audit_witness_digest ||
        recovery.accused != OperationRef{
            certificate.label.owner, certificate.label.object_id} ||
        recovery.recovery_auth_signer != certificate.label.owner ||
        recovery.predecessor_root != certificate.predecessor_root ||
        recovery.checkpoint_root != certificate.checkpoint_root)
        return false;

    const auto& words = expected_statement_words;
    if (words[0] != kStatementDomain || words[1] != 1 ||
        words[2] < 4 || words[2] > 128 ||
        words[3] >= words[2] || words[3] * 3 >= words[2] ||
        words[4] >= words[2] || words[4] != certificate.accused ||
        words[5] == 0 || words[5] > (1ULL << 16) ||
        words[6] != certificate.sid || words[7] != certificate.checkpoint ||
        words[8] == 0 || words[9] == 0 ||
        words[10] != static_cast<u64>(certificate.relation) ||
        words[11] != static_cast<u64>(certificate.kernel) ||
        words[12] != recovery.recovery_auth_signer ||
        words[12] != words[4])
        return false;

    auto digest_at = [&words](size_t digest_index) {
        Digest digest{};
        const size_t offset = 13 + digest_index * 4;
        if (offset + 4 > words.size()) return digest;
        for (size_t i = 0; i < 4; ++i) {
            const uint64_t word = static_cast<uint64_t>(words[offset + i]);
            for (size_t j = 0; j < 8; ++j)
                digest.bytes[i * 8 + j] =
                    static_cast<uint8_t>(word >> (8 * j));
        }
        return digest;
    };
    std::vector<u64> request_context_words = {
        request.label.sid,
        static_cast<u64>(request.label.phase),
        request.label.round,
        request.label.owner,
        static_cast<u64>(request.label.obligation),
        request.label.object_id,
        request.checkpoint,
        static_cast<u64>(request.relation),
        static_cast<u64>(request.kernel)
    };
    append_digest_words(request.expected, request_context_words);
    append_digest_words(request.actual, request_context_words);
    append_digest_words(request.residual_commitment, request_context_words);
    append_digest_words(request.operation_statement_binding, request_context_words);
    append_digest_words(request.dispute_binding, request_context_words);
    append_digest_words(request.checkpoint_root, request_context_words);
    const Digest request_context_binding = hash_words(request_context_words);

    if (digest_at(4) != recovery.recovery_registry_binding ||
        digest_at(5) != recovery.request_binding ||
        digest_at(6) != recovery.operation_statement_binding ||
        digest_at(7) != recovery.dispute_binding ||
        digest_at(8) != recovery.predecessor_root ||
        digest_at(9) != recovery.checkpoint_root ||
        digest_at(10) != recovery.recovery_share_commitment ||
        digest_at(11) != recovery.recovered_audit_commitment ||
        digest_at(12) != recovery.recovery_agreement_binding ||
        digest_at(13) != recovery.recovery_replay_head ||
        digest_at(14) != recovery.recovery_auth_registry_binding ||
        digest_at(15) != recovery.authentication_proof_commitment ||
        digest_at(16) != recovery.recovery_transcript_binding ||
        digest_at(17) != request_context_binding)
        return false;

    return true;
}



bool PublicJudge::VerifyRecoveryRelationProof(
    const BlameCertificate& certificate,
    const std::vector<u64>& expected_statement_words) {
    if (!ValidateRecoveryRelationStatement(
            certificate, expected_statement_words))
        return false;
    Sp1VssRecoveryProofProvider provider;
    Sp1VssRecoveryProofReceipt receipt;
    if (!provider.VerifyArtifactBytes(
            certificate.recovery_proof_artifact_bytes,
            expected_statement_words, &receipt))
        return false;
    return receipt.available && receipt.proof_verified &&
        receipt.proof_system_id == certificate.recovery_proof_system_id &&
        receipt.statement_binding ==
            certificate.recovery_proof_statement_binding &&
        receipt.artifact_commitment ==
            certificate.recovery_proof_artifact_commitment;
}

bool PublicJudge::VerifyRecoveryProof(
    const BlameCertificate& certificate,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& externally_pinned_registry_commitment,
    const std::vector<u64>& expected_statement_words) {
    return VerifyRecoveryReceipt(
               certificate, public_keys, externally_pinned_registry_commitment) &&
           VerifyRecoveryRelationProof(certificate, expected_statement_words);
}


// Verifies a collectively signed RS-event summary and a participant's own
// signed report that its multiplication proof preflight failed. A signer can
// only self-report: changing the accused identity or the report invalidates
// the Ed25519 envelope. This is protocol-abort attribution, not a ZK proof of
// the hidden multiplication inequality.
bool PublicJudge::VerifyMultiplicationFailureCertificate(
    const ReferenceMultiplicationFailureCertificate& certificate,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& externally_pinned_registry_commitment) {
    if (externally_pinned_registry_commitment == Digest{} ||
        public_keys.size() != certificate.event.world_size ||
        compute_ed25519_registry_commitment(public_keys) !=
            externally_pinned_registry_commitment ||
        certificate.registry_commitment !=
            externally_pinned_registry_commitment ||
        !validate_reference_multiplication_failure_certificate(certificate))
        return false;
    for (const auto& observation : certificate.status_observations) {
        if (observation.registry_commitment !=
                externally_pinned_registry_commitment ||
            !verify_authenticated_mpc_signed_envelope_observation(
                observation, public_keys,
                externally_pinned_registry_commitment))
            return false;
    }
    return true;
}


// The serialized overload intentionally has no alternate verification path:
// strict decoding is followed by the same certificate validator and Ed25519
// verification used for the in-memory artifact.
bool PublicJudge::VerifyMultiplicationFailureCertificate(
    const std::vector<u64>& encoded_certificate,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& externally_pinned_registry_commitment) {
    ReferenceMultiplicationFailureCertificate certificate;
    return decode_reference_multiplication_failure_certificate(
               encoded_certificate, &certificate) &&
        VerifyMultiplicationFailureCertificate(
            certificate, public_keys, externally_pinned_registry_commitment);
}

} // namespace pvia
