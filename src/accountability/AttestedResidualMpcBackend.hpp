#pragma once

#include "ResidualMpcMaliciousSecurity.hpp"

namespace pvia {

// Security-upgrading adapter for a residual data plane. The wrapped backend
// remains responsible for private residual computation; the independent
// security provider must attest the exact pre-failure activated state.
class AttestedResidualMpcBackend final : public ResidualMpcBackend {
public:
    AttestedResidualMpcBackend(
        const ResidualMpcBackend& data_plane,
        const ResidualMpcMaliciousSecurityProvider& security_provider,
        RobustAuditSecurityLevel required_security =
            RobustAuditSecurityLevel::MALICIOUS_ABORT);

    ResidualMpcCapabilities Capabilities() const override;
    Digest ProductionCapabilityBinding() const override;
    ResidualMpcPrecommitSecurityContext PrecommitSecurityContext(
        const ObligationSet& scope) const override;
    bool ReadyForScope(
        const ObligationSet& scope,
        RobustAuditSecurityLevel required_security) const override;

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
    bool PrepareAttestation(
        const ObligationSet& scope,
        ResidualMpcSecurityAttestation* attestation) const;
    bool ValidateActiveAttestation(
        const ObligationSet& scope,
        const Digest& expected_binding) const;
    void ClearActiveAttestation() const;

    const ResidualMpcBackend& data_plane_;
    const ResidualMpcMaliciousSecurityProvider& security_provider_;
    RobustAuditSecurityLevel required_security_;
    mutable ResidualMpcSecurityAttestation active_attestation_{};
    mutable Digest active_scope_binding_{};
};

} // namespace pvia
