#pragma once

#include "SecureAuditBackend.hpp"

namespace pvia {

// Deliberately non-functional secure provider used as a safe integration
// placeholder. It never claims that secure audit evidence is available and
// never accepts a public blame certificate. Replace this class with a concrete
// malicious/IA-MPC + ZK blame implementation before using SecureAuditBackend
// for security claims.
class FailClosedSecureAuditProvider final : public SecureAuditProvider {
public:
    void RegisterStateMetadata(const AuditStateView& state) override;
    void BindPrivateState(
        const AuditStateView& state,
        const std::vector<F>& local_share) override;
    bool BindPrivateStateAuthentication(
        const AuditStateView& state, uint64_t scheme_id,
        const Digest& authentication_binding) override;
    void BindPrivateFieldOperation(
        const AuditOperationView& operation, AuditPrivatePayloadKind kind,
        AuditPayloadStage stage, const std::vector<F>& values) override;
    void BindPrivateWordOperation(
        const AuditOperationView& operation, AuditPayloadStage stage,
        const std::vector<u64>& values) override;
    void BindOperationStateDependencies(
        const AuditOperationView& operation,
        const std::vector<StateId>& state_ids) override;
    void BindPublicFieldAux(
        const AuditOperationView& operation, AuditPublicAuxKind kind,
        const std::vector<F>& values) override;
    void BindPublicWordAux(
        const AuditOperationView& operation, AuditPublicAuxKind kind,
        const std::vector<u64>& values) override;
    void FinalizePrivateRelation(
        const AuditOperationView& operation) override;
    void RegisterOperation(const AuditOperationView& operation) override;
    void ActivateOperation(const AuditOperationView& operation) override;
    void SealCheckpoint(const AuditCheckpointView& checkpoint) override;
    void ObservePublicTransfer(
        const PublicTransferObservation& observation) override;
    bool RequiresCollectiveFailureHandling() const override;
    ObligationSet SynchronizeFailureScope(
        const ObligationSet& local_scope, int rank, int world_size) const override;

    BatchCheckResult PrivateBatchCheck(
        const ObligationSet& scope) const override;
    Violation PrivateDispute(
        const ObligationSet& scope,
        const BatchCheckResult& batch) const override;
    RecoverableAuditShare RecoverAuthenticatedAudit(
        const Violation& violation) const override;
    BlameCertificate ProvePublicBlame(
        const Violation& violation,
        const RecoverableAuditShare& audit) const override;
    bool VerifyPublicBlame(
        const BlameCertificate& certificate,
        uint64_t expected_session_id) const override;
};

} // namespace pvia
