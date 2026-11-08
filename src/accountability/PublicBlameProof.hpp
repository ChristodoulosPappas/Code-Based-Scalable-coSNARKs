#pragma once

#include "AuthenticatedAuditRecovery.hpp"

namespace pvia {

struct PublicTransferEvidence;

struct PublicBlameStatement {
    uint64_t sid = 0;
    OperationRef accused{};
    Label label{};
    CheckpointId checkpoint = 0;
    RelationKind relation = RelationKind::UNKNOWN;
    AuditRelationKernel kernel = AuditRelationKernel::UNKNOWN;
    AuditEvidenceKind evidence_kind = AuditEvidenceKind::UNKNOWN;
    Digest expected{};
    Digest actual{};
    Digest residual_commitment{};
    Digest operation_statement_binding{};
    Digest dispute_binding{};
    Digest audit_evidence_binding{};
    Digest predecessor_root{};
    Digest checkpoint_root{};
    Digest statement_binding{};
};

std::vector<u64> encode_public_blame_statement(
    const PublicBlameStatement& statement);
Digest compute_public_blame_statement_binding(
    const PublicBlameStatement& statement);
PublicBlameStatement make_public_blame_statement(
    const Violation& violation,
    const RecoverableAuditShare& audit,
    const AuthenticatedRecoveryArtifact& recovery);
PublicBlameStatement make_public_blame_statement(
    const Violation& violation,
    const RecoverableAuditShare& audit,
    const PublicTransferEvidence& evidence);
PublicBlameStatement make_public_blame_statement(
    const BlameCertificate& certificate);

// Portable codec for proof-carrying PRIVATE_RECOVERY blame certificates.
// The recovery receipt is embedded verbatim; decoding performs structural
// and binding checks, while signature verification needs a pinned key registry.
std::vector<u64> encode_private_recovery_blame_certificate(
    const BlameCertificate& certificate);
bool decode_private_recovery_blame_certificate(
    const std::vector<u64>& words,
    BlameCertificate* certificate);

struct PublicBlameProofArtifact {
    bool available = false;
    bool cryptographically_authenticated = false;
    uint32_t proof_system_id = 0;
    Digest statement_binding{};
    Digest proof_commitment{};
    Digest transcript_binding{};
    std::vector<u64> proof_words;
    // Carries the independently verifiable VSS-recovery relation proof for
    // PRIVATE_RECOVERY statements. Empty for PUBLIC_TRANSFER statements.
    uint32_t recovery_proof_system_id = 0;
    Digest recovery_proof_statement_binding{};
    Digest recovery_proof_artifact_commitment{};
    std::vector<u64> recovery_proof_statement_words;
    std::vector<uint8_t> recovery_proof_artifact_bytes;
};

Digest compute_public_blame_proof_commitment(
    const PublicBlameProofArtifact& artifact);
bool validate_public_blame_proof_artifact(
    const PublicBlameStatement& statement,
    const PublicBlameProofArtifact& artifact);
class PublicBlameProofEngine {
public:
    virtual ~PublicBlameProofEngine() = default;
    virtual Digest ProductionCapabilityBinding() const { return {}; }
    virtual PublicBlameProofArtifact Prove(
        const PublicBlameStatement& statement,
        const AuthenticatedRecoveryArtifact& recovery) const = 0;
    virtual bool Verify(
        const PublicBlameStatement& statement,
        const PublicBlameProofArtifact& proof) const = 0;
};

struct ExternalPublicBlameProof {
    bool available = false;
    bool cryptographically_authenticated = false;
    uint32_t proof_system_id = 0;
    Digest transcript_binding{};
    std::vector<u64> proof_words;
};

class PublicBlameProofBackend {
public:
    virtual ~PublicBlameProofBackend() = default;
    virtual Digest ProductionCapabilityBinding() const { return {}; }
    virtual ExternalPublicBlameProof Prove(
        const std::vector<u64>& public_inputs,
        const AuthenticatedRecoveryArtifact& recovery) const = 0;
    virtual bool Verify(
        const std::vector<u64>& public_inputs,
        const ExternalPublicBlameProof& proof) const = 0;
};

class BackendPublicBlameProofEngine final : public PublicBlameProofEngine {
public:
    explicit BackendPublicBlameProofEngine(
        const PublicBlameProofBackend& backend) : backend_(backend) {}
    PublicBlameProofArtifact Prove(
        const PublicBlameStatement& statement,
        const AuthenticatedRecoveryArtifact& recovery) const override;
    bool Verify(
        const PublicBlameStatement& statement,
        const PublicBlameProofArtifact& proof) const override;
    Digest ProductionCapabilityBinding() const override {
        return backend_.ProductionCapabilityBinding();
    }
private:
    const PublicBlameProofBackend& backend_;
};

class FailClosedPublicBlameProofEngine final
    : public PublicBlameProofEngine {
public:
    PublicBlameProofArtifact Prove(
        const PublicBlameStatement& statement,
        const AuthenticatedRecoveryArtifact& recovery) const override;
    bool Verify(
        const PublicBlameStatement& statement,
        const PublicBlameProofArtifact& proof) const override;
};

} // namespace pvia
