#pragma once

#include "AuthenticatedResidualProtocol.hpp"
#include "RobustAuditSession.hpp"

namespace pvia {

// Security capabilities of the concrete MPC used to keep residuals private.
// This is deliberately separate from RobustAuditCapabilities: it describes
// only the collective residual-audit primitive consumed by
// AuthenticatedResidualProtocol.
struct ResidualMpcCapabilities {
    bool available = false;
    uint64_t protocol_id = 0;
    RobustAuditSecurityLevel security_level =
        RobustAuditSecurityLevel::UNKNOWN;
    bool malicious_secure = false;
    bool activation_before_failure = false;
    bool authenticated_channels = false;
    bool private_residual_sharing = false;
    bool commit_before_challenge = false;
    bool joint_unpredictable_challenge = false;
    bool random_linear_batch_check = false;
    bool masked_zero_test = false;
    bool recursive_subset_localization = false;
    bool publicly_identifiable_abort = false;
    bool guaranteed_output_delivery = false;
    Digest authenticated_channel_capability_binding{};
    Digest identifiable_abort_capability_binding{};
    Digest delivery_capability_binding{};
    Digest implementation_binding{};
    Digest capability_binding{};
};

Digest compute_residual_mpc_capability_binding(
    const ResidualMpcCapabilities& capabilities);
bool validate_residual_mpc_capabilities(
    const ResidualMpcCapabilities& capabilities);
bool residual_mpc_satisfies(
    const ResidualMpcCapabilities& capabilities,
    RobustAuditSecurityLevel required_security);

struct ResidualMpcPrecommitSecurityContext {
    bool available = false;
    Digest activation_binding{};
    Digest strong_consistency_capability_binding{};
};

// Concrete MPC implementations live behind this boundary. The existing
// ReferenceShamirMpc is allowed only as REFERENCE_PASSIVE. Failure-before
// activation is necessary for stronger security but is not sufficient by
// itself: malicious/GOD backends must also carry independent security and
// abort/delivery capability bindings.
class ResidualMpcBackend {
public:
    virtual ~ResidualMpcBackend() = default;
    virtual ResidualMpcCapabilities Capabilities() const = 0;
    // Empty by default. A structurally valid capability record is not proof
    // that the implementation is a production MPC backend. Only an audited
    // backend may override this with a stable implementation identity.
    virtual Digest ProductionCapabilityBinding() const { return {}; }
    virtual ResidualMpcPrecommitSecurityContext PrecommitSecurityContext(
        const ObligationSet&) const { return {}; }
    virtual bool ReadyForScope(
        const ObligationSet&,
        RobustAuditSecurityLevel required_security) const {
        return required_security == RobustAuditSecurityLevel::REFERENCE_PASSIVE &&
               residual_mpc_satisfies(Capabilities(), required_security);
    }
    virtual bool SupportsObliviousAudit(const ObligationSet&) const {
        return false;
    }
    virtual ObliviousLocalizationPublicResult AuditObliviously(
        const ObligationSet&, const LocalResidualBatchView&, int, int) const {
        return {};
    }

    virtual CollectiveResidualCommitmentSet CommitResidualBatch(
        const ObligationSet& scope,
        const CollectiveBatchDescriptor& local_descriptor,
        const LocalResidualBatchView& local_view,
        int rank, int world_size) const = 0;

    virtual AuthenticatedChallengeTranscript DeriveJointChallenge(
        const ObligationSet& scope,
        const CollectiveBatchDescriptor& local_descriptor,
        const CollectiveResidualCommitmentSet& commitments,
        int rank, int world_size) const = 0;

    virtual BatchCheckResult RandomLinearBatchCheck(
        const ObligationSet& scope,
        const CollectiveBatchDescriptor& local_descriptor,
        const LocalResidualBatchView& local_view,
        const CollectiveResidualCommitmentSet& commitments,
        const AuthenticatedChallengeTranscript& challenge_transcript,
        int rank, int world_size) const = 0;

    virtual ResidualSubsetCheckResult CheckResidualSubset(
        const ObligationSet& scope,
        const BatchCheckResult& batch,
        const ResidualSubsetDescriptor& subset,
        const LocalResidualBatchView& local_view,
        int rank, int world_size) const = 0;

    virtual CollectiveDisputeResult FinalizeLocalization(
        const ObligationSet& scope,
        const BatchCheckResult& batch,
        const OperationRef& accused,
        const Digest& recursive_transcript_binding,
        const LocalResidualBatchView& local_view,
        int rank, int world_size) const = 0;
};

// Security-gated AuthenticatedResidualProtocol adapter. Under-strength
// capabilities fail closed. REFERENCE_PASSIVE is supported only for explicit
// development/selftest callers; production SecureAuditRequirements continue to
// require MALICIOUS_ABORT or MALICIOUS_GOD.
class MpcBackedAuthenticatedResidualProtocol final
    : public AuthenticatedResidualProtocol {
public:
    MpcBackedAuthenticatedResidualProtocol(
        const ResidualMpcBackend& backend,
        RobustAuditSecurityLevel required_security =
            RobustAuditSecurityLevel::MALICIOUS_ABORT);

    bool ready() const;
    bool ready_for_scope(const ObligationSet& scope) const;
    ResidualMpcCapabilities capabilities() const;
    Digest ProductionCapabilityBinding() const override;
    bool SupportsObliviousAudit(const ObligationSet& scope) const override;
    ObliviousLocalizationPublicResult AuditObliviously(
        const ObligationSet& scope, const LocalResidualBatchView& local_view,
        int rank, int world_size) const override;

    CollectiveResidualCommitmentSet CommitResidualBatch(
        const ObligationSet& scope,
        const CollectiveBatchDescriptor& local_descriptor,
        const LocalResidualBatchView& local_view,
        int rank, int world_size) const override;

    AuthenticatedChallengeTranscript DeriveJointChallenge(
        const ObligationSet& scope,
        const CollectiveBatchDescriptor& local_descriptor,
        const CollectiveResidualCommitmentSet& commitments,
        int rank, int world_size) const override;

    BatchCheckResult RandomLinearBatchCheck(
        const ObligationSet& scope,
        const CollectiveBatchDescriptor& local_descriptor,
        const LocalResidualBatchView& local_view,
        const CollectiveResidualCommitmentSet& commitments,
        const AuthenticatedChallengeTranscript& challenge_transcript,
        int rank, int world_size) const override;

    ResidualSubsetCheckResult CheckResidualSubset(
        const ObligationSet& scope,
        const BatchCheckResult& batch,
        const ResidualSubsetDescriptor& subset,
        const LocalResidualBatchView& local_view,
        int rank, int world_size) const override;

    CollectiveDisputeResult FinalizeLocalization(
        const ObligationSet& scope,
        const BatchCheckResult& batch,
        const OperationRef& accused,
        const Digest& recursive_transcript_binding,
        const LocalResidualBatchView& local_view,
        int rank, int world_size) const override;

private:
    const ResidualMpcBackend& backend_;
    RobustAuditSecurityLevel required_security_;
};

} // namespace pvia
