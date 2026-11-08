#pragma once

#include "MpcBackedAuthenticatedResidualProtocol.hpp"
#include "PrivateResidualShareStore.hpp"
#include "ReferenceShamirMpc.hpp"
#include "ReferenceBivariateVss.hpp"
#include "AuthenticatedMpcExchange.hpp"
#include "ReferencePrivateOwnerSelection.hpp"
#include "ResidualNativeSourcePinReceipt.hpp"
#include "RegistrationReceiptReplayLedger.hpp"
#include "RegistrationNativeConsumedSnapshot.hpp"

namespace pvia {

// Development/reference implementation of the residual MPC boundary.
//
// Residual values originate in backend-owned PrivateResidualShareStore, but
// ActivateResiduals moves them into authenticated bivariate-VSS state before
// any failure-phase audit. Activated checks never re-contact the owner/store.
// This demonstrates the paper-level random-linear batch check and recursive
// localization flow, but it is intentionally REFERENCE_PASSIVE: the optional
// consistency path is still a reference/test primitive and this backend has no
// production public-abort or guaranteed-delivery construction. Stronger backends
// must carry independent malicious/abort/delivery capability bindings.
class ReferenceShamirResidualMpcBackend final : public ResidualMpcBackend {
public:
    ReferenceShamirResidualMpcBackend(
        const PrivateResidualShareStore& store,
        ReferenceShamirMpc& mpc,
        const AuthenticatedMpcExchange& exchange);

    ResidualMpcCapabilities Capabilities() const override;
    ResidualMpcPrecommitSecurityContext PrecommitSecurityContext(
        const ObligationSet& scope) const override;
    bool SupportsObliviousAudit(const ObligationSet& scope) const override;
    ObliviousLocalizationPublicResult AuditObliviously(
        const ObligationSet& scope, const LocalResidualBatchView& local_view,
        int rank, int world_size) const override;

    // Pre-share and snapshot all residuals before a failure is handled.
    // Once active, batch/localization never reads residual values from store_.
    bool ActivateResiduals(
        const ObligationSet& scope,
        const LocalResidualBatchView& local_view,
        int rank, int world_size,
        bool private_owner_mode = false,
        const Digest* independently_pinned_local_source_root = nullptr);
    // Stronger reference preflight: checks an issuer-signed local residual
    // root against an independently pinned native-consumed record digest,
    // registration pre-VSS claim, issuer key and sequence policy before
    // the same collective VSS activation. Only the validated root is used.
    // This is local Ed25519 source binding, NOT proof that issuer is honest.
    bool ActivateResidualsWithNativeIssuerPin(
        const ObligationSet& scope,
        const LocalResidualBatchView& local_view,
        int rank, int world_size,
        const ResidualNativeSourcePinReceipt& receipt,
        const Digest& independently_expected_native_consumed_binding,
        const Digest& independently_expected_pre_vss_claim_binding,
        const std::array<uint8_t,32>& pinned_issuer_public_key,
        u64 expected_issuer_id, u64 minimum_accepted_sequence);

    // Paired native+residual signatures from the same externally pinned
    // issuer. Fail-closed via the same group preflight on any local error.
    // Strict callers can require the local private residual artifact to also
    // verify under this issuer key and match the pin's exact issuer/sequence.
    // Keep false only for legacy reference fixtures without that artifact.
    bool ActivateResidualsWithPairedNativeIssuerReceipts(
        const ObligationSet& scope,
        const LocalResidualBatchView& local_view,
        int rank,int world_size,
        const ResidualNativeSourcePinReceipt& residual_pin,
        const RegistrationConsistencyStatement& registration_pre_vss,
        const RegistrationNativeExecutionReceipt& native_receipt,
        const Digest& independently_expected_native_consumed_binding,
        const std::array<uint8_t,32>& pinned_issuer_public_key,
        u64 expected_issuer_id,u64 minimum_accepted_sequence,
        const RegistrationReceiptReplayLedger* native_replay_ledger=nullptr,
        bool require_private_residual_provenance=false);

    // Uses the exact registered native-consumed snapshot as local expected
    // input, rather than a caller-synthesized binding. Validation is
    // collective, even on a single-owner mismatch. The optional strict
    // provenance check is propagated to the paired-receipt activation gate.
    bool ActivateResidualsWithCapturedNativeSnapshot(
        const ObligationSet& scope,
        const LocalResidualBatchView& local_view,
        int rank, int world_size,
        const ResidualNativeSourcePinReceipt& residual_pin,
        const RegistrationConsistencyStatement& registration_pre_vss,
        const RegistrationNativeExecutionReceipt& native_receipt,
        const RegistrationNativeConsumedSnapshot& captured,
        const std::array<uint8_t,32>& pinned_issuer_public_key,
        u64 expected_issuer_id, u64 minimum_accepted_sequence,
        const RegistrationReceiptReplayLedger* native_replay_ledger=nullptr,
        bool require_private_residual_provenance=false);

    // Stronger native-store adapter; re-reads finalized local state,
    // operation and checkpoint, rejecting drift after capture.
    bool ActivateResidualsWithLiveNativeSnapshot(
        const ObligationSet& scope,
        const LocalResidualBatchView& local_view,
        int rank, int world_size,
        const ResidualNativeSourcePinReceipt& residual_pin,
        const RegistrationConsistencyStatement& registration_pre_vss,
        const RegistrationNativeExecutionReceipt& native_receipt,
        const RegistrationNativeConsumedSnapshot& captured,
        const PrivateStateMaterialStore& states,
        const PrivateAuditMaterialStore& operations,
        const AuditCheckpointView& checkpoint,
        const std::array<uint8_t,32>& pinned_issuer_public_key,
        u64 expected_issuer_id, u64 minimum_accepted_sequence,
        bool require_native_fold_residual = false,
        bool require_all_native_fold_residuals = false,
        const RegistrationReceiptReplayLedger* native_replay_ledger=nullptr,
        bool require_private_residual_provenance=false);

    // Provider-based overload: native execution owners can supply their own
    // capture/re-read adapter while the reference fold relation checks remain
    // attached to the operation store.
    bool ActivateResidualsWithLiveNativeSnapshot(
        const ObligationSet& scope,
        const LocalResidualBatchView& local_view,
        int rank, int world_size,
        const ResidualNativeSourcePinReceipt& residual_pin,
        const RegistrationConsistencyStatement& registration_pre_vss,
        const RegistrationNativeExecutionReceipt& native_receipt,
        const RegistrationNativeConsumedSnapshot& captured,
        const RegistrationNativeSourceProvider& source_provider,
        const PrivateStateMaterialStore& states,
        const PrivateAuditMaterialStore& operations,
        const AuditCheckpointView& checkpoint,
        const std::array<uint8_t,32>& pinned_issuer_public_key,
        u64 expected_issuer_id, u64 minimum_accepted_sequence,
        bool require_native_fold_residual = false,
        bool require_all_native_fold_residuals = false,
        const RegistrationReceiptReplayLedger* native_replay_ledger=nullptr,
        bool require_private_residual_provenance=false);

    bool HasActivatedResiduals(const ObligationSet& scope) const;
    bool HasActivatedVssProvenance(const ObligationSet& scope) const;
    Digest activation_binding() const { return activation_binding_; }
    bool private_owner_activation_mode() const {
        return private_owner_activation_mode_;
    }
    bool PrivateOwnerActivationMetadataRedacted(
        const ObligationSet& scope) const;
    // Layout-only batch descriptor: no original local residual commitment
    // is inserted into the public commitment set or joint challenge.
    CollectiveBatchDescriptor PrivateOwnerPublicBatchDescriptor(
        const ObligationSet& scope,
        const LocalResidualBatchView& local_view,
        int rank, int world_size) const;
    void ClearActivatedResiduals();

    // P1-05 REFERENCE integration: no public subset tests and no operation
    // indexed blame output. Requires a previously VSS-activated scope,
    // signed batch commitments and the challenge derived AFTER commitment.
    // The native R_q authentication relation and production multiplicative
    // consistency remain separate formal gates.
    bool LocalizeActivatedPrivateOwner(
        const ObligationSet& scope,
        const LocalResidualBatchView& local_view,
        const CollectiveResidualCommitmentSet& commitments,
        const AuthenticatedChallengeTranscript& challenge,
        int rank, int world_size,
        ReferencePrivateOwnerSelectionResult* result,
        Digest* activated_input_binding) const;

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
    struct PassiveResidualSharingCacheEntry {
        OperationRef ref{};
        std::vector<F> local_shares;
    };

    struct ActivatedResidualOperation {
        OperationRef ref{};
        Label label{};
        RelationKind relation = RelationKind::UNKNOWN;
        AuditRelationKernel kernel = AuditRelationKernel::UNKNOWN;
        CheckpointId checkpoint = 0;
        std::vector<F> local_shares;
        Digest sharing_binding{};
        ReferenceVssLocalWitness local_witness{};
        Digest expected{};
        Digest actual{};
        Digest operation_statement_binding{};
        Digest source_commitment{};
        Digest descriptor_binding{};
    };

    bool EnsureTransport(
        const ObligationSet& scope, int rank, int world_size) const;
    bool ValidateLocalView(
        const LocalResidualBatchView& local_view, int rank) const;
    bool ValidateActivatedLocalView(
        const LocalResidualBatchView& local_view, int rank) const;
    const ActivatedResidualOperation* FindActivated(
        const OperationRef& ref) const;
    AuthenticatedMpcMessageContext NextContext(
        const ObligationSet& scope, u64 message_kind,
        uint64_t round = 0) const;
    F DeriveCoefficient(
        const Digest& challenge, const OperationRef& ref,
        size_t coordinate, const Digest& domain_binding) const;
    bool BuildFingerprint(
        const ObligationSet& scope,
        const std::vector<OperationRef>& operations,
        const Digest& challenge,
        const Digest& domain_binding,
        F* fingerprint_share,
        Digest* sharing_binding,
        ReferenceLinearSharingProvenance* provenance = nullptr) const;
    void ClearPassiveSharingCache() const;
    void BeginPassiveSharingCacheCapture(const ObligationSet& scope) const;
    bool PreparePassiveSharingCache(const ObligationSet& scope) const;
    const std::vector<F>* FindPassiveSharingCache(
        const ObligationSet& scope, const OperationRef& ref) const;
    bool PassiveSharingCacheMatches(
        const ObligationSet& scope, const BatchCheckResult& batch) const;

    const PrivateResidualShareStore& store_;
    ReferenceShamirMpc& mpc_;
    const AuthenticatedMpcExchange& exchange_;
    mutable uint64_t active_sid_ = 0;
    mutable CheckpointId active_checkpoint_ = 0;
    mutable uint64_t exchange_sequence_ = 1;

    uint64_t activated_sid_ = 0;
    CheckpointId activated_checkpoint_ = 0;
    Digest activated_scope_binding_{};
    Digest activation_binding_{};
    bool private_owner_activation_mode_ = false;
    std::vector<std::pair<OperationRef, Digest>>
        owner_original_source_commitments_;
    std::vector<ActivatedResidualOperation> activated_operations_;

    mutable bool passive_cache_capture_ = false;
    mutable uint64_t passive_cache_sid_ = 0;
    mutable CheckpointId passive_cache_checkpoint_ = 0;
    mutable Digest passive_cache_scope_binding_{};
    mutable Digest passive_cache_batch_binding_{};
    mutable std::vector<PassiveResidualSharingCacheEntry>
        passive_sharing_cache_;
};

} // namespace pvia
