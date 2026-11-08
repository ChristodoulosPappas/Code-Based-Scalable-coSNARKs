#pragma once

#include "PVIA.hpp"

namespace pvia {

struct PublicTransferObservation;
struct RobustAuditTerminationOutput;
struct RobustAuditAbortCertificate;

// Verified evidence for one exact private relation. This receipt is not
// authenticated MPC provenance and never authorizes release on its own.
struct AuditRelationProofReceipt {
    bool available = false;
    bool proof_verified = false;
    bool production_privacy_confirmed = false;
    AuditRelationKernel kernel = AuditRelationKernel::UNKNOWN;
    OperationRef operation_ref{};
    uint64_t checkpoint = 0;
    Digest relation_statement{};
    uint32_t proof_system_id = 0;
    size_t proof_word_count = 0;
    Digest statement_binding{};
    Digest artifact_commitment{};
};

// Backend boundary used by the application-layer accountability hooks.
// A secure instantiation can replace DebugAuditBackend without changing
// coSumcheck/PCS/encoding responsibility instrumentation.
class AuditBackend {
public:
    virtual ~AuditBackend() = default;

    // Lifecycle notifications are no-ops by default. Secure backends can use
    // them to mirror the public operation DAG and maintain private audit state.
    virtual void OnImportStateMetadata(const AuditStateView&) {}
    virtual void OnBindPrivateState(
        const AuditStateView&, const std::vector<F>&) {}
    virtual void OnBindPrivateStateSegments(
        const AuditStateView& state, const std::vector<F>& local_share,
        const std::vector<size_t>&) {
        OnBindPrivateState(state, local_share);
    }
    virtual bool OnBindPrivateStateAuthentication(
        const AuditStateView&, uint64_t, const Digest&) { return false; }
    virtual void OnBindPrivateFieldOperation(
        const AuditOperationView&, AuditPrivatePayloadKind, AuditPayloadStage,
        const std::vector<F>&) {}
    virtual void OnBindPrivateWordOperation(
        const AuditOperationView&, AuditPayloadStage,
        const std::vector<u64>&) {}
    virtual void OnBindOperationStateDependencies(
        const AuditOperationView&, const std::vector<StateId>&) {}
    virtual void OnBindPublicFieldAux(
        const AuditOperationView&, AuditPublicAuxKind,
        const std::vector<F>&) {}
    virtual void OnBindPublicWordAux(
        const AuditOperationView&, AuditPublicAuxKind,
        const std::vector<u64>&) {}
    // Called exactly when a local private relation has all material needed
    // for residual evaluation. The backend keeps the residual private.
    virtual void OnFinalizePrivateRelation(const AuditOperationView&) {}
    virtual void OnRegisterOperation(const AuditOperationView&) {}
    virtual void OnActivateOperation(const AuditOperationView&) {}
    virtual void OnSealCheckpoint(const AuditCheckpointView&) {}
    virtual void OnObservePublicTransfer(const PublicTransferObservation&) {}

    // Debug backends can remain coordinator-only. A secure distributed backend
    // can require every prover to enter the failure pipeline with its local
    // private residual state.
    virtual bool RequiresCollectiveFailureHandling() const { return false; }
    virtual ObligationSet SynchronizeFailureScope(
        const ObligationSet& local_scope, int, int) const {
        return local_scope;
    }
    // Optional diagnostic surface for robust secure backends. The returned
    // termination state is runtime status only; it is not a blame certificate.
    virtual bool GetLastRobustTermination(
        RobustAuditTerminationOutput*) const { return false; }
    // Optional public artifact surface. Implementations may return a robust
    // abort certificate only after public-abort verification has succeeded.
    virtual bool GetLastRobustAbortCertificate(
        RobustAuditAbortCertificate*) const { return false; }
    // Optional read-only evidence for one exact private relation. This receipt
    // is diagnostic proof evidence only; it is not authenticated MPC
    // provenance and must never authorize release by itself.
    virtual bool ReadRelationProofReceipt(
        AuditRelationKernel, AuditRelationProofReceipt* receipt) const {
        if (receipt) *receipt = AuditRelationProofReceipt{};
        return false;
    }

    virtual BatchCheckResult BatchCheck(const ObligationSet& scope) const = 0;
    virtual Violation Dispute(const ObligationSet& scope,
                              const BatchCheckResult& batch) const = 0;
    virtual RecoverableAuditShare RecoverAudit(
        const Violation& violation) const = 0;
    virtual BlameCertificate LiftBlame(
        const Violation& violation,
        const RecoverableAuditShare& audit) const = 0;
    virtual bool Judge(
        const BlameCertificate& certificate,
        uint64_t expected_session_id) const = 0;
};

class DebugAuditBackend final : public AuditBackend {
public:
    explicit DebugAuditBackend(Runtime& runtime) : runtime_(runtime) {}

    BatchCheckResult BatchCheck(const ObligationSet& scope) const override;
    Violation Dispute(const ObligationSet& scope,
                      const BatchCheckResult& batch) const override;
    RecoverableAuditShare RecoverAudit(
        const Violation& violation) const override;
    BlameCertificate LiftBlame(
        const Violation& violation,
        const RecoverableAuditShare& audit) const override;
    bool Judge(
        const BlameCertificate& certificate,
        uint64_t expected_session_id) const override;

private:
    Runtime& runtime_;
};

// Intentionally left as an interface boundary.  The final paper-level backend
// must provide private batched residual evaluation, robust localization,
// recoverable authenticated audit sharing, and ZK blame lifting.
class SecureAuditBackend;

} // namespace pvia
