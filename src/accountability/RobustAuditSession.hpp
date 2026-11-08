#pragma once

#include "CollectiveResidualEngine.hpp"
#include "AuthenticatedAuditRecovery.hpp"
#include "PublicBlameProof.hpp"
#include "RegistrationConsistencyProof.hpp"
#include "MultiplicationConsistencyProof.hpp"
#include "AuthenticatedMpcAbortEvidence.hpp"

#include <vector>

namespace pvia {

class PrivateAuditMaterialStore;
class PrivateStateMaterialStore;

enum class RobustAuditSecurityLevel : uint32_t {
    UNKNOWN = 0,
    REFERENCE_PASSIVE = 1,
    MALICIOUS_ABORT = 2,
    MALICIOUS_GOD = 3
};

struct RobustAuditCapabilities {
    bool available = false;
    uint64_t protocol_id = 0;
    RobustAuditSecurityLevel security_level = RobustAuditSecurityLevel::UNKNOWN;
    bool malicious_secure = false;
    bool authenticated_channels = false;
    bool publicly_identifiable_abort = false;
    bool guaranteed_output_delivery = false;
    bool activation_before_failure = false;
    bool private_witness_retention = false;
    bool detectable_input_sharing = false;
    bool public_registration_consistency = false;
    bool robust_opening = false;
    bool commit_reveal_public_coin = false;
    bool detectable_degree_reduction = false;
    bool detectable_random_sharing = false;
    bool malicious_multiplication_consistency = false;
    bool packed_sharing = false;
    uint32_t corruption_threshold = 0;
    std::vector<AuditRelationKernel> supported_kernels;
    Digest authenticated_channel_capability_binding{};
    Digest identifiable_abort_capability_binding{};
    Digest delivery_capability_binding{};
    Digest registration_consistency_capability_binding{};
    Digest multiplication_consistency_capability_binding{};
    Digest implementation_binding{};
    Digest capability_binding{};
};

Digest compute_robust_audit_capability_binding(
    const RobustAuditCapabilities& capabilities);
bool validate_robust_audit_capabilities(
    const RobustAuditCapabilities& capabilities);
bool production_ready_robust_audit_capabilities(
    const RobustAuditCapabilities& capabilities);
bool production_ready_identifiable_abort_capabilities(
    const RobustAuditCapabilities& capabilities);
bool robust_audit_supports_kernel(
    const RobustAuditCapabilities& capabilities,
    AuditRelationKernel kernel);

struct RobustAuditActivation {
    bool available = false;
    uint64_t sid = 0;
    CheckpointId checkpoint = 0;
    Digest checkpoint_root{};
    Digest checkpoint_binding{};
    size_t registered_operations = 0;
    Digest capability_binding{};
    Digest authenticated_channel_activation_binding{};
    Digest delivery_activation_binding{};
    Digest registration_consistency_binding{};
    Digest activation_transcript_binding{};
    Digest activation_binding{};
};

Digest compute_robust_checkpoint_binding(
    const AuditCheckpointView& checkpoint);
uint64_t compute_robust_bootstrap_transport_sid(
    const AuditCheckpointView& checkpoint);
Digest compute_robust_audit_activation_binding(
    const RobustAuditActivation& activation);
bool validate_robust_audit_activation(
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation& activation);

struct RobustAuditSessionOutput {
    bool available = false;
    bool cryptographically_authenticated = false;
    bool completed = false;
    bool clean = false;
    RobustAuditSecurityLevel security_level = RobustAuditSecurityLevel::UNKNOWN;
    uint64_t sid = 0;
    CheckpointId checkpoint = 0;
    Digest scope_binding{};
    Digest activation_binding{};
    Digest capability_binding{};
    Digest authenticated_channel_transcript_binding{};
    Digest delivery_transcript_binding{};
    Digest multiplication_consistency_binding{};
    BatchCheckResult batch{};
    Violation violation{};
    AuthenticatedRecoveryArtifact recovery{};
    PublicBlameStatement statement{};
    PublicBlameProofArtifact proof{};
    Digest execution_transcript_binding{};
    Digest output_binding{};
};

Digest compute_robust_audit_output_binding(
    const RobustAuditSessionOutput& output);
bool validate_robust_audit_session_output(
    const ObligationSet& scope,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation& activation,
    const RobustAuditSessionOutput& output,
    int world_size);

enum class RobustAuditAbortStage : uint32_t {
    UNKNOWN = 0,
    ACTIVATION = 1,
    EXECUTION = 2
};

struct RobustAuditAbortOutput {
    bool available = false;
    bool publicly_verifiable = false;
    RobustAuditAbortStage stage = RobustAuditAbortStage::UNKNOWN;
    uint64_t sid = 0;
    CheckpointId checkpoint = 0;
    Digest checkpoint_root{};
    Digest checkpoint_binding{};
    uint32_t accused = 0;
    Digest capability_binding{};
    Digest authenticated_channel_capability_binding{};
    Digest activation_binding{};
    Digest external_registry_anchor{};
    AuthenticatedMpcEquivocationEvidence equivocation{};
    Digest abort_transcript_binding{};
    Digest abort_binding{};
};

enum class RobustAuditTerminationKind : uint32_t {
    UNKNOWN = 0,
    COMPLETED = 1,
    DETECTABLE_UNATTRIBUTABLE_ABORT = 2,
    PUBLICLY_ATTRIBUTABLE_ABORT = 3
};

enum class RobustAuditUnattributableAbortReason : uint32_t {
    UNKNOWN = 0,
    ACTIVATION_UNAVAILABLE = 1,
    EXECUTION_UNAVAILABLE = 2,
    AUTHENTICATED_TRANSPORT_FAILURE = 3
};

// Runtime classification only. An unattributable abort records authenticated-
// route non-completion; it is NOT public blame evidence and names no party.
struct RobustAuditTerminationOutput {
    bool available = false;
    RobustAuditTerminationKind kind = RobustAuditTerminationKind::UNKNOWN;
    RobustAuditAbortStage stage = RobustAuditAbortStage::UNKNOWN;
    RobustAuditUnattributableAbortReason unattributable_reason =
        RobustAuditUnattributableAbortReason::UNKNOWN;
    uint64_t sid = 0;
    CheckpointId checkpoint = 0;
    Digest checkpoint_root{};
    Digest checkpoint_binding{};
    Digest capability_binding{};
    Digest activation_binding{};
    bool authenticated_route = false;
    bool completed = false;
    bool detectable_abort = false;
    bool publicly_attributable = false;
    Digest completed_output_binding{};
    Digest public_abort_binding{};
    // Hash-bound local diagnostic only; never identifies an accused party.
    Digest local_failure_binding{};
    Digest termination_binding{};
};

Digest compute_robust_audit_termination_binding(
    const RobustAuditTerminationOutput& output);
bool validate_robust_audit_termination_output(
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation* activation,
    const RobustAuditTerminationOutput& output);
// These builders assume the source object has already passed its full
// source-specific verifier at the caller boundary.
bool build_robust_audit_termination_from_validated_session_output(
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation& activation,
    const RobustAuditSessionOutput& session_output,
    RobustAuditTerminationOutput* output);
bool build_robust_audit_unattributable_abort_termination(
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation* activation,
    RobustAuditAbortStage stage,
    RobustAuditUnattributableAbortReason reason,
    RobustAuditTerminationOutput* output);
bool build_robust_audit_transport_failure_termination(
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation* activation,
    RobustAuditAbortStage stage,
    const Digest& local_failure_binding,
    RobustAuditTerminationOutput* output);
bool build_robust_audit_termination_from_verified_public_abort(
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation* activation,
    const RobustAuditAbortOutput& verified_abort,
    RobustAuditTerminationOutput* output);

Digest compute_robust_audit_abort_transcript_binding(
    const RobustAuditAbortOutput& output);
Digest compute_robust_audit_abort_binding(
    const RobustAuditAbortOutput& output);
bool build_robust_audit_abort_output_from_equivocation(
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation* activation,
    const AuthenticatedMpcEquivocationEvidence& evidence,
    const Digest& expected_registry_anchor,
    int world_size, RobustAuditAbortOutput* output);

// Pure reconciliation boundary for observations collected by any higher-level
// dissemination mechanism. This validates the transport capability and public
// key registry, but does not itself provide reliable dissemination or GOD.
bool build_robust_audit_abort_output_from_observations(
    const std::vector<AuthenticatedMpcSignedEnvelopeObservation>& observations,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const AuthenticatedMpcTransportCapabilities& transport,
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation* activation,
    int world_size, RobustAuditAbortOutput* output,
    Digest* observation_set_binding = nullptr);

// Bridge from the authenticated transport's verified-envelope cache into the
// canonical robust identifiable-abort output. This rejects unanchored or
// capability-mismatched transports before exposing any accused party.
bool build_robust_audit_abort_output_from_exchange(
    const AuthenticatedMpcExchange& exchange,
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation* activation,
    int world_size, RobustAuditAbortOutput* output);

// Explicit best-effort collective evidence reconciliation. Unlike LastAbort(),
// this function intentionally enters authenticated collectives and therefore
// must only be called from a protocol phase where all honest ranks participate.
// It does not provide reliable broadcast, liveness, or guaranteed delivery.
bool build_robust_audit_abort_output_from_reconciled_exchange(
    const AuthenticatedMpcExchange& exchange,
    const AuthenticatedMpcMessageContext& reconciliation_context,
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation* activation,
    int world_size, RobustAuditAbortOutput* output,
    Digest* observation_set_binding = nullptr,
    Digest* reconciliation_transcript_binding = nullptr);
bool run_robust_audit_abort_output_selftest(int rank, int world_size);

bool validate_robust_audit_abort_output(
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation* activation,
    const RobustAuditAbortOutput& output,
    const Digest& expected_registry_anchor,
    int world_size);

// Production route-A boundary: one checkpoint-scoped robust execution owns
// registration, batch checking, private localization, witness selection and
// blame lifting. A backend must not re-contact the accused after activation.
class RobustAuditSessionBackend {
public:
    virtual ~RobustAuditSessionBackend() = default;
    virtual RobustAuditCapabilities Capabilities() const = 0;

    virtual RobustAuditActivation Activate(
        const AuditCheckpointView& checkpoint,
        const PrivateStateMaterialStore& states,
        const PrivateAuditMaterialStore& materials) = 0;

    virtual RobustAuditSessionOutput Execute(
        const ObligationSet& scope,
        int rank,
        int world_size) = 0;

    // Explicit synchronized failure-phase hook. Implementations may enter
    // authenticated collectives here; callers must invoke it on all honest
    // ranks in the same failure phase. Ordinary LastAbort() remains local-only.
    virtual RobustAuditAbortOutput ReconcileAbortCollectively(
        const AuditCheckpointView&,
        const RobustAuditActivation*,
        int, int) { return {}; }
    virtual RobustAuditAbortOutput LastAbort() const { return {}; }
    // Local authenticated-transport diagnostics are non-public and carry no
    // accused party. Callers may only use this to classify detectable abort.
    virtual bool LastAuthenticatedTransportFailure(
        const AuditCheckpointView&, const RobustAuditActivation*,
        Digest*) const { return false; }
    virtual bool VerifyPublicAbort(
        const AuditCheckpointView&, const RobustAuditActivation*,
        const RobustAuditAbortOutput&) const { return false; }

    virtual bool VerifyPublicBlame(
        const PublicBlameStatement& statement,
        const PublicBlameProofArtifact& proof) const = 0;
};

} // namespace pvia
