#pragma once

#include "AuditBackend.hpp"
#include "FoldResidualComputationBackend.hpp"
#include "NativeSumcheckResidualComputationBackend.hpp"
#include "Sp1SumcheckProofProvider.hpp"
#include "PrivateAuditMaterialStore.hpp"
#include "PrivateStateMaterialStore.hpp"
#include "ReferenceShamirAuditSession.hpp"
#include "RegistrationNativeConsumedSnapshot.hpp"

#include <array>
#include <memory>
#include <string>
#include <vector>

namespace pvia {

struct NativeFoldSourceCapture {
    RegistrationConsistencyStatement statement{};
    RegistrationNativeConsumedSnapshot snapshot{};
};

// Development-only harness for checking that real protocol instrumentation
// supplies the material required by FOLD_RS residual recomputation. It never
// participates in blame attribution. Residuals stay unauthenticated unless an
// explicit second-stage externally pinned provenance receipt is accepted;
// that step alone does not authorize proof release or establish full MPC security.
class FoldResidualRuntimeHarness final : public AuditBackend,
                                      public RegistrationNativeSourceProvider {
public:
    explicit FoldResidualRuntimeHarness(
        bool enable_reference_mpc_activation = false,
        bool delegate_runtime_debug_checks = false);

    void OnImportStateMetadata(const AuditStateView& state) override;
    void OnBindPrivateState(const AuditStateView& state,
                            const std::vector<F>& local_share) override;
    void OnBindPrivateStateSegments(
        const AuditStateView& state, const std::vector<F>& local_share,
        const std::vector<size_t>& segment_lengths) override;
    void OnRegisterOperation(const AuditOperationView& operation) override;
    void OnActivateOperation(const AuditOperationView& operation) override;
    void OnBindPrivateFieldOperation(
        const AuditOperationView& operation, AuditPrivatePayloadKind kind,
        AuditPayloadStage stage, const std::vector<F>& values) override;
    void OnBindOperationStateDependencies(
        const AuditOperationView& operation,
        const std::vector<StateId>& state_ids) override;
    void OnBindPublicFieldAux(
        const AuditOperationView& operation, AuditPublicAuxKind kind,
        const std::vector<F>& values) override;
    void OnFinalizePrivateRelation(
        const AuditOperationView& operation) override;
    void OnSealCheckpoint(const AuditCheckpointView& checkpoint) override;

    bool RunSelfCheck(int rank, int world_size) const;
    bool RunNativeSumcheckSelfCheck(int rank, int world_size) const;
    bool RunReferenceMpcSelfCheck(int rank, int world_size) const;

    // Build a pre-VSS source statement from the most recent FOLD_RS operation
    // observed by the real coSNARK runtime callbacks.
    bool CaptureLatestNativeFoldStatement(
        RegistrationConsistencyStatement* statement) const;
    // Capture every finalized FOLD_RS source attached to one sealed checkpoint.
    // The returned list is canonicalized by (owner, object_id).
    bool CaptureNativeFoldCapturesForCheckpoint(
        CheckpointId checkpoint_id,
        std::vector<NativeFoldSourceCapture>* output) const;
    // Returns only the public checkpoint view; private source bytes remain
    // held by this observer and are rechecked before any export.
    bool ReadNativeFoldCheckpoint(
        CheckpointId checkpoint_id,
        AuditCheckpointView* output) const;
    // Recomputes the native local FOLD_RS residual and binds it to the
    // exact captured source/operation. No residual authentication is claimed.
    bool VerifyCapturedNativeFoldResidual(
        const RegistrationConsistencyStatement& statement,
        const RegistrationNativeConsumedSnapshot& snapshot) const;
    // Exposes only digest commitments for the locally verified residual.
    // Never treats this reference residual as an authenticated MPC share.
    bool ReadVerifiedNativeResidualBindings(
        const RegistrationConsistencyStatement& statement,
        const RegistrationNativeConsumedSnapshot& snapshot,
        Digest* computation_binding,
        Digest* residual_commitment) const;
    // After the exact residual provenance receipt is accepted, derive the
    // owner-local one-operation source-pin root from the authenticated handle.
    // This is still a reference harness and not a production MPC guarantee.
    bool ReadAuthenticatedNativeResidualRoot(
        const RegistrationConsistencyStatement& statement,
        const RegistrationNativeConsumedSnapshot& snapshot,
        Digest* local_residual_root) const;
    bool ReadAuthenticatedNativeResidualRoot(
        const RegistrationConsistencyStatement& statement,
        const RegistrationNativeConsumedSnapshot& snapshot,
        Digest* local_residual_root,
        Digest* residual_commitment) const;
    // Internal fail-closed release verdict for an already authenticated real
    // native FOLD_RS residual.  Returns false on any binding/authentication
    // failure; on success writes whether every residual coordinate is zero.
    // No residual coordinate leaves this process.
    bool AuthenticatedNativeFoldResidualExactZero(
        const RegistrationConsistencyStatement& statement,
        const RegistrationNativeConsumedSnapshot& snapshot,
        bool* exact_zero) const;
    // Require the checkpoint-scoped joint-randomness fingerprint and masked
    // zero-test before a strict native release can be authorized. This is the
    // reference MPC gate; it does not claim malicious-secure/GOD guarantees.
    bool AuthenticatedNativeFoldResidualMpcZero(
        const RegistrationConsistencyStatement& statement,
        const RegistrationNativeConsumedSnapshot& snapshot,
        bool* mpc_zero, Digest* mpc_transcript_binding) const;
    // Test-only strict-gate bridge: export one authenticated native FOLD_RS
    // residual as a private scalar fingerprint. The caller must keep the file
    // mode 0600, consume it after WITHHOLD, and delete it immediately.
    bool ExportAuthenticatedNativeFoldResidualRlcSingle(
        const RegistrationConsistencyStatement& statement,
        const RegistrationNativeConsumedSnapshot& snapshot,
        const std::string& private_output_path) const;
    // Verify a PVNPIN02 receipt against all authenticated FOLD_RS captures in
    // the sealed checkpoint, then consume its issuer sequence exactly once.
    // When requested, replay_rejected reports the expected second-consume denial.
    bool VerifyCapturedNativeFoldBatchPinReceipt(
        CheckpointId checkpoint_id,
        uint32_t local_owner,
        const std::string& receipt_file,
        const std::array<uint8_t, 32>& independently_pinned_issuer_key,
        uint64_t expected_issuer_id,
        uint64_t minimum_accepted_sequence,
        const std::string& replay_ledger_directory,
        size_t* verified_operation_count = nullptr,
        bool* replay_rejected = nullptr) const;
    // Reference N=4 audit-only bridge. AFTER successful two-operation
    // PVNPIN02 verification, export a bounded private scalar fingerprint of
    // each real residual vector for test-only post-seal recovery. The file
    // contains private derived values: caller MUST keep it 0600 and delete
    // it after checking; this is neither an MPC share conversion nor an
    // independent native-state equality proof.
    bool ExportAuthenticatedNativeFoldResidualRlc(
        CheckpointId checkpoint_id, uint32_t local_owner,
        const std::string& private_output_path) const;

    // Optional second-stage activation: consume an externally issued receipt
    // after its issuer key, rank-specific identity, sequence and exact local
    // residual computation are independently pinned by the caller.
    bool VerifyCapturedNativeFoldResidualReceipt(
        const RegistrationConsistencyStatement& statement,
        const RegistrationNativeConsumedSnapshot& snapshot,
        const std::string& receipt_file,
        const std::string& issuer_public_key_file,
        const std::string& replay_ledger_file,
        uint64_t expected_issuer_id,
        uint64_t minimum_accepted_sequence,
        uint64_t receipt_wait_ms = 0) const;
    bool AuthenticateCapturedNativeFoldResidual(
        const RegistrationConsistencyStatement& statement,
        const RegistrationNativeConsumedSnapshot& snapshot,
        const std::string& receipt_file,
        const std::string& issuer_public_key_file,
        const std::string& replay_ledger_file,
        uint64_t expected_issuer_id,
        uint64_t minimum_accepted_sequence,
        uint64_t receipt_wait_ms = 0);
    bool capture(
        const RegistrationConsistencyStatement& pre_vss_statement,
        RegistrationNativeConsumedSnapshot* output) const override;
    bool still_matches(
        const RegistrationConsistencyStatement& pre_vss_statement,
        const RegistrationNativeConsumedSnapshot& captured) const override;

    BatchCheckResult BatchCheck(const ObligationSet& scope) const override;
    Violation Dispute(const ObligationSet& scope,
                      const BatchCheckResult& batch) const override;
    RecoverableAuditShare RecoverAudit(
        const Violation& violation) const override;
    BlameCertificate LiftBlame(
        const Violation& violation,
        const RecoverableAuditShare& audit) const override;
    bool Judge(const BlameCertificate& certificate,
               uint64_t expected_session_id) const override;

private:
    bool CaptureNativeFoldStatementForRef(
        const OperationRef& ref,
        RegistrationConsistencyStatement* statement) const;
    bool ActivateReferenceMpcCheckpoint(
        const AuditCheckpointView& checkpoint, int rank, int world_size);
    const AuditCheckpointView* FindSealedCheckpoint(
        CheckpointId checkpoint_id) const;

    PrivateStateMaterialStore states_;
    PrivateAuditMaterialStore materials_;
    PrivateResidualShareStore shares_;
    FoldResidualComputationBackend backend_;
    Sp1SumcheckProofProvider sp1_sumcheck_proof_provider_;
    NativeSumcheckResidualComputationBackend sumcheck_backend_;
    NativeSumcheckKernelResidualEvaluator sumcheck_evaluator_;
    size_t fold_operations_ = 0;
    size_t native_sumcheck_operations_ = 0;
    size_t native_sumcheck_zero_residuals_ = 0;
    size_t native_sumcheck_nonzero_residuals_ = 0;
    size_t native_sumcheck_invalid_material_ = 0;
    size_t native_sumcheck_not_ready_ = 0;
    size_t native_sumcheck_state_invalid_ = 0;
    size_t native_sumcheck_relation_invalid_ = 0;
    size_t native_sumcheck_reconstruction_invalid_ = 0;
    size_t native_sumcheck_input_mismatch_ = 0;
    size_t native_sumcheck_other_invalid_ = 0;
    std::array<size_t, 5> native_sumcheck_kernel_counts_{};
    std::array<size_t, 5> native_sumcheck_proof_input_counts_{};
    std::array<bool, 5> native_sumcheck_proof_input_written_{};
    size_t native_sumcheck_proof_input_failures_ = 0;
    size_t zero_residuals_ = 0;
    size_t nonzero_residuals_ = 0;
    size_t invalid_material_ = 0;
    std::vector<OperationRef> fold_refs_;
    std::vector<AuditCheckpointView> sealed_checkpoints_;
    bool reference_mpc_activation_enabled_ = false;
    bool delegate_runtime_debug_checks_ = false;
    size_t reference_mpc_activation_failures_ = 0;
    std::vector<ReferenceShamirBatchResult> reference_mpc_batches_;
    std::vector<std::unique_ptr<ReferenceShamirAuditSession>>
        reference_mpc_sessions_;
};

} // namespace pvia
