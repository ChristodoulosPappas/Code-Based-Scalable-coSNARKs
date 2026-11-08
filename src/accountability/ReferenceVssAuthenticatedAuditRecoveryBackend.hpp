#pragma once

#include "AuthenticatedAuditRecovery.hpp"
#include "ReferenceVssSelectiveReleaseCoordinator.hpp"

namespace pvia {

struct ReferenceShamirSelectedAuditWitness;
struct ReferenceVssAuthenticatedRecoveryConfig;

// Bind a sealed Shamir-session selection directly to the existing VSS
// recovery adapter. The selected witness must outlive the backend/config.
bool bind_reference_shamir_selected_audit_witness(
    const ReferenceShamirSelectedAuditWitness& selected,
    ReferenceVssAuthenticatedRecoveryConfig* config);

// Reference adapter joining the existing VSS selective-point release path to
// PVIA's authenticated recovery interface. Its portable Ed25519 receipt can
// be checked by a separate verifier using the session public-key registry.
// It is deliberately NOT a production/GOD backend: the target's signature
// authenticates its recovery statement but does not prove correct
// interpolation or native-relation evaluation. ProductionCapabilityBinding
// therefore stays empty and this adapter cannot satisfy production readiness.
//
// All ranks must invoke Recover in the same order. The target rank supplies
// the independently pinned registry/replay paths and durable-head callback;
// other ranks supply the same public bindings but no target-local paths.
struct ReferenceVssAuthenticatedRecoveryConfig {
    const AuthenticatedMpcExchange* exchange = nullptr;
    const ReferenceVssLocalWitness* local_witness = nullptr;
    const ReferenceVssReceipt* receipt = nullptr;
    const ReferenceVssTranscriptContext* trusted_transcript = nullptr;
    AuthenticatedMpcMessageContext release_context{};
    ReferenceVssSelectiveReleasePins target_pins{};
    OperationRef expected_operation{};
    Digest independently_pinned_operation_statement_binding{};
    Digest independently_pinned_predecessor_root{};
    Digest independently_pinned_checkpoint_root{};
    Digest independently_pinned_registry_binding{};
};

class ReferenceVssAuthenticatedAuditRecoveryBackend final
    : public AuthenticatedAuditRecoveryBackend {
public:
    explicit ReferenceVssAuthenticatedAuditRecoveryBackend(
        ReferenceVssAuthenticatedRecoveryConfig config);

    Digest ProductionCapabilityBinding() const override { return {}; }

    AuthenticatedRecoveryArtifact Recover(
        const AuthenticatedRecoveryRequest& request,
        int rank,
        int world_size) const override;

    bool Verify(
        const AuthenticatedRecoveryRequest& request,
        const AuthenticatedRecoveryArtifact& artifact) const override;

private:
    ReferenceVssAuthenticatedRecoveryConfig config_;
    mutable u64 next_sequence_ = 0;
    mutable Digest current_replay_head_{};

};

} // namespace pvia
