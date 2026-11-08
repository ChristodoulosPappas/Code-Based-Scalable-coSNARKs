#pragma once

#include "AuditBackend.hpp"
#include "PublicTransferObservation.hpp"

namespace pvia {

// Adapter boundary for the eventual paper-level audit implementation.
// A provider must keep residual evaluation/localization private and return
// only authenticated audit handles / publicly verifiable blame material.
class SecureAuditProvider {
public:
    virtual ~SecureAuditProvider() = default;

    virtual void RegisterStateMetadata(const AuditStateView& state) = 0;
    virtual void BindPrivateState(
        const AuditStateView& state,
        const std::vector<F>& local_share) = 0;
    virtual void BindPrivateStateSegments(
        const AuditStateView& state, const std::vector<F>& local_share,
        const std::vector<size_t>&) {
        BindPrivateState(state, local_share);
    }
    virtual bool BindPrivateStateAuthentication(
        const AuditStateView& state, uint64_t scheme_id,
        const Digest& authentication_binding) = 0;
    virtual void BindPrivateFieldOperation(
        const AuditOperationView& operation, AuditPrivatePayloadKind kind,
        AuditPayloadStage stage, const std::vector<F>& values) = 0;
    virtual void BindPrivateWordOperation(
        const AuditOperationView& operation, AuditPayloadStage stage,
        const std::vector<u64>& values) = 0;
    virtual void BindOperationStateDependencies(
        const AuditOperationView& operation,
        const std::vector<StateId>& state_ids) = 0;
    virtual void BindPublicFieldAux(
        const AuditOperationView& operation, AuditPublicAuxKind kind,
        const std::vector<F>& values) = 0;
    virtual void BindPublicWordAux(
        const AuditOperationView& operation, AuditPublicAuxKind kind,
        const std::vector<u64>& values) = 0;
    // Compute/store the operation residual privately. Implementations may
    // authenticate/share it internally, but must not expose the clear residual.
    virtual void FinalizePrivateRelation(
        const AuditOperationView& operation) = 0;
    virtual void RegisterOperation(const AuditOperationView& operation) = 0;
    virtual void ActivateOperation(const AuditOperationView& operation) = 0;
    virtual void SealCheckpoint(const AuditCheckpointView& checkpoint) = 0;
    virtual void ObservePublicTransfer(
        const PublicTransferObservation& observation) = 0;
    // Collective providers must make all parties enter the same failure
    // instance and return a canonical public scope/result. In particular,
    // PrivateDispute/Recover/ProvePublicBlame must not leave non-coordinator
    // parties before any collective subprotocol they participate in completes.
    virtual bool RequiresCollectiveFailureHandling() const = 0;
    virtual ObligationSet SynchronizeFailureScope(
        const ObligationSet& local_scope, int rank, int world_size) const = 0;
    // Runtime-only robust termination status. This is diagnostic state and
    // must never be treated as public blame evidence.
    virtual bool GetLastRobustTermination(
        RobustAuditTerminationOutput*) const { return false; }
    virtual bool GetLastRobustAbortCertificate(
        RobustAuditAbortCertificate*) const { return false; }

    virtual BatchCheckResult PrivateBatchCheck(
        const ObligationSet& scope) const = 0;
    virtual Violation PrivateDispute(
        const ObligationSet& scope,
        const BatchCheckResult& batch) const = 0;
    virtual RecoverableAuditShare RecoverAuthenticatedAudit(
        const Violation& violation) const = 0;
    virtual BlameCertificate ProvePublicBlame(
        const Violation& violation,
        const RecoverableAuditShare& audit) const = 0;
    virtual bool VerifyPublicBlame(
        const BlameCertificate& certificate,
        uint64_t expected_session_id) const = 0;
    virtual bool ReadRelationProofReceipt(
        AuditRelationKernel, AuditRelationProofReceipt*) const {
        return false;
    }
};

class SecureAuditBackend final : public AuditBackend {
public:
    explicit SecureAuditBackend(SecureAuditProvider& provider)
        : provider_(provider) {}

    void OnImportStateMetadata(
        const AuditStateView& state) override;
    void OnBindPrivateState(
        const AuditStateView& state,
        const std::vector<F>& local_share) override;
    void OnBindPrivateStateSegments(
        const AuditStateView& state, const std::vector<F>& local_share,
        const std::vector<size_t>& segment_lengths) override;
    bool OnBindPrivateStateAuthentication(
        const AuditStateView& state, uint64_t scheme_id,
        const Digest& authentication_binding) override;
    void OnBindPrivateFieldOperation(
        const AuditOperationView& operation, AuditPrivatePayloadKind kind,
        AuditPayloadStage stage, const std::vector<F>& values) override;
    void OnBindPrivateWordOperation(
        const AuditOperationView& operation, AuditPayloadStage stage,
        const std::vector<u64>& values) override;
    void OnBindOperationStateDependencies(
        const AuditOperationView& operation,
        const std::vector<StateId>& state_ids) override;
    void OnBindPublicFieldAux(
        const AuditOperationView& operation, AuditPublicAuxKind kind,
        const std::vector<F>& values) override;
    void OnBindPublicWordAux(
        const AuditOperationView& operation, AuditPublicAuxKind kind,
        const std::vector<u64>& values) override;
    void OnFinalizePrivateRelation(
        const AuditOperationView& operation) override;
    void OnRegisterOperation(
        const AuditOperationView& operation) override;
    void OnActivateOperation(
        const AuditOperationView& operation) override;
    void OnSealCheckpoint(
        const AuditCheckpointView& checkpoint) override;
    void OnObservePublicTransfer(
        const PublicTransferObservation& observation) override;
    bool RequiresCollectiveFailureHandling() const override;
    ObligationSet SynchronizeFailureScope(
        const ObligationSet& local_scope, int rank, int world_size) const override;
    bool GetLastRobustTermination(
        RobustAuditTerminationOutput* output) const override;
    bool GetLastRobustAbortCertificate(
        RobustAuditAbortCertificate* certificate) const override;

    BatchCheckResult BatchCheck(
        const ObligationSet& scope) const override;
    Violation Dispute(
        const ObligationSet& scope,
        const BatchCheckResult& batch) const override;
    RecoverableAuditShare RecoverAudit(
        const Violation& violation) const override;
    BlameCertificate LiftBlame(
        const Violation& violation,
        const RecoverableAuditShare& audit) const override;
    bool Judge(
        const BlameCertificate& certificate,
        uint64_t expected_session_id) const override;
    bool ReadRelationProofReceipt(
        AuditRelationKernel kernel,
        AuditRelationProofReceipt* receipt) const override;

private:
    SecureAuditProvider& provider_;
};

} // namespace pvia
