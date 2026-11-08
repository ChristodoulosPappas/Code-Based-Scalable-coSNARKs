#pragma once

#include "PVIA.hpp"

#include <array>
#include <cstdint>

namespace pvia {

struct AuthenticatedRecoveryRequest {
    Label label{};
    CheckpointId checkpoint = 0;
    RelationKind relation = RelationKind::UNKNOWN;
    AuditRelationKernel kernel = AuditRelationKernel::UNKNOWN;
    Digest expected{};
    Digest actual{};
    Digest residual_commitment{};
    Digest operation_statement_binding{};
    Digest dispute_binding{};
    Digest checkpoint_root{};
    Digest request_binding{};
};

struct AuthenticatedRecoveryArtifact {
    bool available = false;
    bool cryptographically_authenticated = false;
    OperationRef accused{};
    CheckpointId checkpoint = 0;
    RelationKind relation = RelationKind::UNKNOWN;
    AuditRelationKernel kernel = AuditRelationKernel::UNKNOWN;
    Digest request_binding{};
    Digest operation_statement_binding{};
    Digest dispute_binding{};
    Digest predecessor_root{};
    Digest checkpoint_root{};
    Digest recovered_audit_commitment{};
    Digest recovery_transcript_binding{};
    Digest authentication_proof_commitment{};

    // Optional portable Ed25519 recovery receipt. This authenticates the
    // target's statement about the recovery transcript; it is NOT a proof
    // that interpolation or the native relation was computed correctly.
    Digest recovery_share_commitment{};
    Digest recovery_registry_binding{};
    Digest recovery_agreement_binding{};
    Digest recovery_replay_head{};
    uint32_t recovery_auth_signer = 0xffffffffU;
    Digest recovery_auth_registry_binding{};
    std::array<uint8_t, 64> recovery_auth_signature{};

    // Optional SP1/Groth16 proof of the committed VSS interpolation relation.
    // Kept outside the signed 70-word receipt to avoid a circular binding:
    // the proof statement is derived from the receipt, not vice versa.
    uint32_t recovery_proof_system_id = 0;
    Digest recovery_proof_statement_binding{};
    Digest recovery_proof_artifact_commitment{};
    std::vector<u64> recovery_proof_statement_words;
    std::vector<uint8_t> recovery_proof_artifact_bytes;
};

Digest compute_recovery_request_binding(
    const AuthenticatedRecoveryRequest& request);
AuthenticatedRecoveryRequest make_recovery_request(
    const Violation& violation,
    const AuditCheckpointView& checkpoint);
AuthenticatedRecoveryRequest make_recovery_request(
    const BlameCertificate& certificate);
Digest compute_recovered_audit_commitment(
    const Digest& request_binding,
    const Digest& share_commitment,
    const Digest& registry_binding);
Digest compute_recovery_artifact_binding(
    const AuthenticatedRecoveryArtifact& artifact);
// Canonical fixed-width codec for portable Ed25519-authenticated recovery
// artifacts. Decoding is syntactic; callers must still validate against the
// independently pinned request and verify the receipt signature.
std::vector<u64> encode_authenticated_recovery_artifact(
    const AuthenticatedRecoveryArtifact& artifact);
bool decode_authenticated_recovery_artifact(
    const std::vector<u64>& words,
    AuthenticatedRecoveryArtifact* artifact);
bool validate_recovery_artifact(
    const AuthenticatedRecoveryRequest& request,
    const AuthenticatedRecoveryArtifact& artifact);
// Verifies a portable target receipt against an explicitly supplied,
// externally pinned Ed25519 public-key registry. No MPI or local session
// authenticator state is required by this verifier.
bool verify_authenticated_recovery_receipt(
    const AuthenticatedRecoveryRequest& request,
    const AuthenticatedRecoveryArtifact& artifact,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& expected_registry_commitment);

class AuthenticatedAuditRecoveryEngine {
public:
    virtual ~AuthenticatedAuditRecoveryEngine() = default;
    virtual Digest ProductionCapabilityBinding() const { return {}; }
    virtual AuthenticatedRecoveryArtifact Recover(
        const AuthenticatedRecoveryRequest& request,
        int rank,
        int world_size) const = 0;
    // Detached certificate verification must be performed by the configured
    // backend, including its independently pinned recovery-registry binding.
    // The default is fail-closed for legacy/custom engines.
    virtual bool Verify(
        const AuthenticatedRecoveryRequest& request,
        const AuthenticatedRecoveryArtifact& artifact) const {
        (void)request;
        (void)artifact;
        return false;
    }
};

class AuthenticatedAuditRecoveryBackend {
public:
    virtual ~AuthenticatedAuditRecoveryBackend() = default;
    virtual Digest ProductionCapabilityBinding() const { return {}; }
    virtual AuthenticatedRecoveryArtifact Recover(
        const AuthenticatedRecoveryRequest& request,
        int rank,
        int world_size) const = 0;
    // Independent verification is mandatory. The engine never treats the
    // backend's available/authenticated flags as a cryptographic check.
    virtual bool Verify(
        const AuthenticatedRecoveryRequest& request,
        const AuthenticatedRecoveryArtifact& artifact) const = 0;
};

class BackendAuthenticatedAuditRecoveryEngine final
    : public AuthenticatedAuditRecoveryEngine {
public:
    explicit BackendAuthenticatedAuditRecoveryEngine(
        const AuthenticatedAuditRecoveryBackend& backend)
        : backend_(backend) {}
    AuthenticatedRecoveryArtifact Recover(
        const AuthenticatedRecoveryRequest& request,
        int rank,
        int world_size) const override;
    Digest ProductionCapabilityBinding() const override {
        return backend_.ProductionCapabilityBinding();
    }
    bool Verify(
        const AuthenticatedRecoveryRequest& request,
        const AuthenticatedRecoveryArtifact& artifact) const override;
private:
    const AuthenticatedAuditRecoveryBackend& backend_;
};

// Regression: a backend that returns a well-formed artifact and sets its
// authentication flags, but cannot independently verify it, must be rejected.
bool run_authenticated_audit_recovery_verifier_selftest();

class FailClosedAuthenticatedAuditRecoveryEngine final
    : public AuthenticatedAuditRecoveryEngine {
public:
    AuthenticatedRecoveryArtifact Recover(
        const AuthenticatedRecoveryRequest& request,
        int rank,
        int world_size) const override;
};

} // namespace pvia
