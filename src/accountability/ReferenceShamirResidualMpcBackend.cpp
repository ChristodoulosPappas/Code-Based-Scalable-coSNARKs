#include "ReferenceShamirResidualMpcBackend.hpp"
#include "Ed25519PrivateResidualShareAuthenticator.hpp"
#include "ResidualFingerprintLinearity.hpp"
#include "ReferencePrivateResidualFlag.hpp"
#include "PrivateResidualRegistry.hpp"
#include "FoldResidualComputationBackend.hpp"
#include "ReferenceVssResidualSourceLink.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace pvia {
namespace {

constexpr u64 REFERENCE_RESIDUAL_MPC_PROTOCOL_ID = 0x50565253484d5031ULL; // PVRSHMP1
constexpr u64 REFERENCE_RESIDUAL_MPC_IMPL_DOMAIN = 0x50565253484d494dULL; // PVRSHMIM
constexpr u64 REFERENCE_RESIDUAL_COMMIT_DOMAIN = 0x5056525348434f4dULL; // PVRSHCOM
constexpr u64 REFERENCE_RESIDUAL_CHALLENGE_DOMAIN = 0x505652534843484cULL; // PVRSHCHL
constexpr u64 REFERENCE_RESIDUAL_BATCH_DOMAIN = 0x5056525348424154ULL; // PVRSHBAT
constexpr u64 REFERENCE_RESIDUAL_SUBSET_DOMAIN = 0x5056525348535542ULL; // PVRSHSUB
constexpr u64 REFERENCE_RESIDUAL_LOCALIZE_DOMAIN = 0x50565253484c4f43ULL; // PVRSHLOC
constexpr u64 AUTH_KIND_COMMITMENTS = 0x5253434f4d4d4954ULL; // RSCOMMIT
constexpr u64 AUTH_KIND_LOCALIZATION = 0x52534c4f43414c31ULL; // RSLOCAL1
constexpr u64 AUTH_KIND_COMMIT_READY = 0x5253434d52445931ULL; // RSCMRDY1
constexpr u64 AUTH_KIND_CHALLENGE_READY = 0x5253434852445931ULL; // RSCHRDY1
constexpr u64 AUTH_KIND_BATCH_READY = 0x5253425452445931ULL; // RSBTRDY1
constexpr u64 AUTH_KIND_SUBSET_READY = 0x5253534252445931ULL; // RSSBRDY1
constexpr u64 AUTH_KIND_LOCALIZE_READY = 0x52534c4352445931ULL; // RSLCRDY1
constexpr u64 AUTH_KIND_PASSIVE_BATCH_LAYOUT =
    0x525350424c415931ULL; // RSPBLAY1
constexpr u64 REFERENCE_RESIDUAL_ACTIVATION_DOMAIN = 0x5056525348414354ULL; // PVRSH ACT
constexpr u64 AUTH_KIND_ACTIVATE_READY = 0x5253414354524459ULL; // RSACTRDY
constexpr u64 AUTH_KIND_ACTIVATE_OPERATION_READY = 0x5253414f50524459ULL; // RSAOPRDY
constexpr u64 AUTH_KIND_ACTIVATE_DESCRIPTOR = 0x5253414354444553ULL; // RSACTDES
constexpr u64 AUTH_KIND_ACTIVATE_FINAL = 0x525341435446494eULL; // RSACTFIN
constexpr u64 AUTH_KIND_ACTIVATE_VSS = 0x5253414354565353ULL; // RSACTVSS
constexpr u64 AUTH_KIND_ACTIVATE_VSS_DEALER_LINK =
    0x52535653534c4b31ULL; // RSVSSLK1
constexpr u64 REFERENCE_RESIDUAL_STRONG_ZERO_DOMAIN = 0x5056525354525a52ULL; // PVRSTRZR

void append_digest(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

uint64_t nonzero_digest_word(const Digest& digest) {
    uint64_t word = 0;
    std::memcpy(&word, digest.bytes.data(), sizeof(word));
    return word == 0 ? 1ULL : word;
}

Digest digest_from_words(const std::vector<u64>& words, size_t offset) {
    Digest digest{};
    if (offset > words.size() || words.size() - offset < 4) return digest;
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(digest.bytes.data() + 8 * i, &words[offset + i], 8);
    return digest;
}


bool same_ref(const OperationRef& lhs, const OperationRef& rhs) {
    return lhs.owner == rhs.owner && lhs.object_id == rhs.object_id;
}

bool operation_less(const OperationRef& lhs, const OperationRef& rhs) {
    if (lhs.owner != rhs.owner) return lhs.owner < rhs.owner;
    return lhs.object_id < rhs.object_id;
}

const PrivateResidualHandle* find_handle(
    const LocalResidualBatchView& view, const OperationRef& ref) {
    for (const auto& handle : view.handles)
        if (same_ref(handle.ref, ref)) return &handle;
    return nullptr;
}

Digest bind_words(u64 domain, const std::vector<Digest>& digests,
                  const std::vector<u64>& suffix = {}) {
    std::vector<u64> words = {domain, static_cast<u64>(digests.size())};
    for (const Digest& digest : digests) append_digest(digest, &words);
    words.insert(words.end(), suffix.begin(), suffix.end());
    return hash_words(words);
}

} // namespace

ReferenceShamirResidualMpcBackend::ReferenceShamirResidualMpcBackend(
    const PrivateResidualShareStore& store,
    ReferenceShamirMpc& mpc,
    const AuthenticatedMpcExchange& exchange)
    : store_(store), mpc_(mpc), exchange_(exchange) {}

ResidualMpcCapabilities
ReferenceShamirResidualMpcBackend::Capabilities() const {
    ResidualMpcCapabilities c;
    if (!mpc_.valid() || !exchange_.production_authenticated_ready()) {
        return c;
    }
    c.available = true;
    c.protocol_id = REFERENCE_RESIDUAL_MPC_PROTOCOL_ID;
    c.security_level = RobustAuditSecurityLevel::REFERENCE_PASSIVE;
    c.malicious_secure = false;
    c.activation_before_failure = true;
    c.authenticated_channels = true;
    c.private_residual_sharing = true;
    c.commit_before_challenge = true;
    c.joint_unpredictable_challenge = true;
    c.random_linear_batch_check = true;
    c.masked_zero_test = true;
    c.recursive_subset_localization = true;
    c.publicly_identifiable_abort = false;
    c.guaranteed_output_delivery = false;
    c.authenticated_channel_capability_binding =
        exchange_.ProductionCapabilityBinding();
    c.identifiable_abort_capability_binding = Digest{};
    c.delivery_capability_binding = Digest{};
    c.implementation_binding = bind_words(
        REFERENCE_RESIDUAL_MPC_IMPL_DOMAIN,
        {c.authenticated_channel_capability_binding},
        {static_cast<u64>(mpc_.world_size()),
         static_cast<u64>(mpc_.threshold()),
         4ULL}); // v4: owner batching reuses authenticated shape metadata
    c.capability_binding = compute_residual_mpc_capability_binding(c);
    return c;
}

ResidualMpcPrecommitSecurityContext
ReferenceShamirResidualMpcBackend::PrecommitSecurityContext(
    const ObligationSet& scope) const {
    ResidualMpcPrecommitSecurityContext context;
    if (!HasActivatedVssProvenance(scope)) return context;
    const Digest strong_binding =
        mpc_.multiplication_consistency_capability_binding();
    if (activation_binding_ == Digest{} || strong_binding == Digest{})
        return context;
    context.available = true;
    context.activation_binding = activation_binding_;
    context.strong_consistency_capability_binding = strong_binding;
    return context;
}

bool ReferenceShamirResidualMpcBackend::EnsureTransport(
    const ObligationSet& scope, int rank, int world_size) const {
    if (scope.session_id == 0 || scope.checkpoint == 0 ||
        rank != mpc_.rank() || world_size != mpc_.world_size() ||
        rank < 0 || rank >= world_size ||
        !exchange_.production_authenticated_ready())
        return false;
    if (active_sid_ == scope.session_id &&
        active_checkpoint_ == scope.checkpoint &&
        mpc_.authenticated_transport_available())
        return true;
    if (!mpc_.SetAuthenticatedTransport(
            &exchange_, scope.session_id, scope.checkpoint))
        return false;
    active_sid_ = scope.session_id;
    active_checkpoint_ = scope.checkpoint;
    exchange_sequence_ = 1;
    return true;
}

bool ReferenceShamirResidualMpcBackend::ValidateLocalView(
    const LocalResidualBatchView& local_view, int rank) const {
    if (!local_view.complete_for_owner || !local_view.all_authenticated ||
        local_view.local_owner != static_cast<uint32_t>(rank) ||
        local_view.commitment_root==Digest{} ||
        compute_private_residual_local_handle_root(local_view.handles)!=
            local_view.commitment_root)
        return false;
    for (const auto& handle : local_view.handles) {
        const PrivateResidualShare* share = store_.Find(handle.ref);
        if (!share || !validate_private_residual_share(*share) ||
            share->ref.owner != static_cast<uint32_t>(rank) ||
            share->commitment != handle.commitment ||
            share->checkpoint != handle.checkpoint ||
            share->relation != handle.relation ||
            share->kernel != handle.kernel ||
            share->label.sid != handle.label.sid ||
            share->label.phase != handle.label.phase ||
            share->label.round != handle.label.round ||
            share->label.owner != handle.label.owner ||
            share->label.obligation != handle.label.obligation ||
            share->label.object_id != handle.label.object_id ||
            !share->authenticated)
            return false;
    }
    return true;
}

void ReferenceShamirResidualMpcBackend::ClearActivatedResiduals() {
    activated_sid_ = 0;
    activated_checkpoint_ = 0;
    activated_scope_binding_ = Digest{};
    activation_binding_ = Digest{};
    private_owner_activation_mode_ = false;
    owner_original_source_commitments_.clear();
    activated_operations_.clear();
}

const ReferenceShamirResidualMpcBackend::ActivatedResidualOperation*
ReferenceShamirResidualMpcBackend::FindActivated(
    const OperationRef& ref) const {
    for (const auto& operation : activated_operations_)
        if (same_ref(operation.ref, ref)) return &operation;
    return nullptr;
}

bool ReferenceShamirResidualMpcBackend::HasActivatedResiduals(
    const ObligationSet& scope) const {
    if (activated_sid_ == 0 || activated_checkpoint_ == 0 ||
        activation_binding_ == Digest{} || activated_operations_.empty() ||
        activated_sid_ != scope.session_id ||
        activated_checkpoint_ != scope.checkpoint ||
        activated_scope_binding_ != compute_collective_scope_binding(scope) ||
        activated_operations_.size() != scope.operations.size())
        return false;
    for (const OperationRef& ref : scope.operations)
        if (!FindActivated(ref)) return false;
    return true;
}

bool ReferenceShamirResidualMpcBackend::HasActivatedVssProvenance(
    const ObligationSet& scope) const {
    if (!HasActivatedResiduals(scope)) return false;
    for (const auto& operation : activated_operations_) {
        if (operation.sharing_binding == Digest{} ||
            operation.local_shares.empty() ||
            !validate_reference_vss_local_witness(operation.local_witness) ||
            operation.local_witness.dealer !=
                static_cast<int>(operation.ref.owner) ||
            operation.local_witness.participant != mpc_.rank() ||
            operation.local_witness.element_count !=
                operation.local_shares.size() ||
            operation.local_witness.transcript_binding !=
                operation.sharing_binding)
            return false;
    }
    return true;
}

bool ReferenceShamirResidualMpcBackend::ValidateActivatedLocalView(
    const LocalResidualBatchView& local_view, int rank) const {
    if (!local_view.complete_for_owner || !local_view.all_authenticated ||
        local_view.local_owner != static_cast<uint32_t>(rank) ||
        activated_scope_binding_ !=
            compute_collective_scope_binding(local_view.scope))
        return false;
    size_t expected = 0;
    for (const auto& operation : activated_operations_)
        if (operation.ref.owner == static_cast<uint32_t>(rank)) ++expected;
    if (local_view.handles.size() != expected) return false;
    for (const auto& handle : local_view.handles) {
        const ActivatedResidualOperation* operation = FindActivated(handle.ref);
        if (!operation || operation->ref.owner != static_cast<uint32_t>(rank) ||
            (private_owner_activation_mode_
                ? !std::any_of(
                    owner_original_source_commitments_.begin(),
                    owner_original_source_commitments_.end(),
                    [&](const std::pair<OperationRef,Digest>& entry) {
                        return same_ref(entry.first,handle.ref) &&
                               entry.second == handle.commitment;
                    })
                : operation->source_commitment != handle.commitment) ||
            operation->checkpoint != handle.checkpoint ||
            operation->relation != handle.relation ||
            operation->kernel != handle.kernel ||
            operation->label.sid != handle.label.sid ||
            operation->label.phase != handle.label.phase ||
            operation->label.round != handle.label.round ||
            operation->label.owner != handle.label.owner ||
            operation->label.obligation != handle.label.obligation ||
            operation->label.object_id != handle.label.object_id)
            return false;
    }
    return true;
}

bool ReferenceShamirResidualMpcBackend::
ActivateResidualsWithCapturedNativeSnapshot(
    const ObligationSet& scope,
    const LocalResidualBatchView& local_view,
    int rank,int world_size,
    const ResidualNativeSourcePinReceipt& residual_pin,
    const RegistrationConsistencyStatement& registration_pre_vss,
    const RegistrationNativeExecutionReceipt& native_receipt,
    const RegistrationNativeConsumedSnapshot& captured,
    const std::array<uint8_t,32>& pinned_issuer_public_key,
    u64 expected_issuer_id,u64 minimum_accepted_sequence,
    const RegistrationReceiptReplayLedger* native_replay_ledger,
    bool require_private_residual_provenance) {
    // Snapshot contents are checked LOCALLY without broadcasting their
    // sensitive source digest or values. A bad local snapshot joins the
    // same all-rank rejection as a bad signature.
    const bool matches=captured.consumed_record_binding!=Digest{} &&
        captured.pre_vss_claim_binding!=Digest{} &&
        captured.pre_vss_claim_binding==
            native_receipt.pre_vss_claim_binding &&
        captured.consumed_record_binding==
            native_receipt.consumed_record_binding &&
        !captured.state_values.empty() &&
        !captured.actual_output.empty() &&
        captured.state_values.size()==
            registration_pre_vss.state_element_count &&
        captured.actual_output.size()==
            registration_pre_vss.output_element_count &&
        hash_field_vector(captured.state_values)==
            registration_pre_vss.public_state_digest &&
        hash_field_vector(captured.actual_output)==
            registration_pre_vss.public_actual_digest &&
        hash_field_vector({captured.public_challenge})==
            registration_pre_vss.public_challenge_binding;
    const Digest expected=matches
        ? captured.consumed_record_binding : Digest{};
    return ActivateResidualsWithPairedNativeIssuerReceipts(
        scope,local_view,rank,world_size,
        residual_pin,registration_pre_vss,native_receipt,
        expected,pinned_issuer_public_key,
        expected_issuer_id,minimum_accepted_sequence,
        native_replay_ledger,require_private_residual_provenance);
}

bool ReferenceShamirResidualMpcBackend::
ActivateResidualsWithLiveNativeSnapshot(
    const ObligationSet& scope,
    const LocalResidualBatchView& local_view,
    int rank,int world_size,
    const ResidualNativeSourcePinReceipt& residual_pin,
    const RegistrationConsistencyStatement& registration_pre_vss,
    const RegistrationNativeExecutionReceipt& native_receipt,
    const RegistrationNativeConsumedSnapshot& captured,
    const PrivateStateMaterialStore& states,
    const PrivateAuditMaterialStore& operations,
    const AuditCheckpointView& checkpoint,
    const std::array<uint8_t,32>& pinned_issuer_public_key,
    u64 expected_issuer_id,u64 minimum_accepted_sequence,
    bool require_native_fold_residual,
    bool require_all_native_fold_residuals,
    const RegistrationReceiptReplayLedger* native_replay_ledger,
    bool require_private_residual_provenance) {
    RegistrationNativeStoreSourceProvider source_provider(
        states,operations,checkpoint);
    return ActivateResidualsWithLiveNativeSnapshot(
        scope,local_view,rank,world_size,residual_pin,registration_pre_vss,
        native_receipt,captured,source_provider,states,operations,checkpoint,
        pinned_issuer_public_key,expected_issuer_id,
        minimum_accepted_sequence,require_native_fold_residual,
        require_all_native_fold_residuals,native_replay_ledger,
        require_private_residual_provenance);
}

bool ReferenceShamirResidualMpcBackend::
ActivateResidualsWithLiveNativeSnapshot(
    const ObligationSet& scope,
    const LocalResidualBatchView& local_view,
    int rank,int world_size,
    const ResidualNativeSourcePinReceipt& residual_pin,
    const RegistrationConsistencyStatement& registration_pre_vss,
    const RegistrationNativeExecutionReceipt& native_receipt,
    const RegistrationNativeConsumedSnapshot& captured,
    const RegistrationNativeSourceProvider& source_provider,
    const PrivateStateMaterialStore& states,
    const PrivateAuditMaterialStore& operations,
    const AuditCheckpointView& checkpoint,
    const std::array<uint8_t,32>& pinned_issuer_public_key,
    u64 expected_issuer_id,u64 minimum_accepted_sequence,
    bool require_native_fold_residual,
    bool require_all_native_fold_residuals,
    const RegistrationReceiptReplayLedger* native_replay_ledger,
    bool require_private_residual_provenance) {
    // Re-check through the source provider BEFORE sharing. This keeps the
    // backend independent of a particular native store implementation.
    const bool current=source_provider.still_matches(
        registration_pre_vss,captured);
    bool fold_relation_ok=!(require_native_fold_residual ||
                             require_all_native_fold_residuals);
    if(current && (require_native_fold_residual ||
                   require_all_native_fold_residuals)) {
        const auto* operation=operations.Find(registration_pre_vss.ref);
        const auto* share=store_.Find(registration_pre_vss.ref);
        std::vector<F> expected;
        const bool fold_computed=recompute_fold_rs_output(
            captured.state_values,captured.public_challenge,&expected);
        fold_relation_ok = fold_computed &&
            registration_pre_vss.ref.owner==static_cast<uint32_t>(rank) &&
            operation && share &&
            registration_pre_vss.kernel==AuditRelationKernel::FOLD_RS &&
            share->kernel==AuditRelationKernel::FOLD_RS &&
            share->relation==RelationKind::FOLDING &&
            share->checkpoint==scope.checkpoint &&
            share->ref==registration_pre_vss.ref &&
            share->source_state_id==
                registration_pre_vss.native_context.native_state_id &&
            share->source_state_digest==
                registration_pre_vss.public_state_digest &&
            share->source_state_authentication_scheme_id==
                registration_pre_vss.native_context.authentication_scheme_id &&
            share->source_state_authentication_binding==
                registration_pre_vss.native_context.authentication_binding &&
            share->public_aux_root==operation->operation.public_aux_root &&
            share->operation_statement_binding==
                registration_pre_vss.operation_statement_binding &&
            share->expected==hash_field_vector(expected) &&
            share->actual==registration_pre_vss.public_actual_digest &&
            share->values.size()==expected.size() &&
            captured.actual_output.size()==expected.size();
        if(fold_relation_ok)
            for(size_t i=0;i<expected.size();++i)
                if(share->values[i]!=captured.actual_output[i]-expected[i]){
                    fold_relation_ok=false;
                    break;
                }
    }
    // Optional complete local native layout validation. The source-root
    // issuer receipt covers every local residual HANDLE; this checks
    // corresponding finalized native relations for EVERY such handle.
    // The public protocol still emits just the owner, never private q*.
    if(current && fold_relation_ok && require_all_native_fold_residuals) {
        size_t expected_local=0;
        for(const auto& ref:scope.operations) {
            if(ref.owner!=static_cast<uint32_t>(rank))continue;
            ++expected_local;
            const auto* share=store_.Find(ref);
            const auto* material=operations.Find(ref);
            const auto handle=std::find_if(
                local_view.handles.begin(),local_view.handles.end(),
                [&](const PrivateResidualHandle& h){
                    return h.ref==ref;
                });
            // All local native candidates have exactly one input state,
            // one FOLD challenge, and a finalized private output vector.
            if(!share || !material ||
               handle==local_view.handles.end() ||
               !handle->available || !handle->authenticated ||
               handle->commitment!=share->commitment ||
               !validate_private_residual_share(*share) ||
               !material->finalized ||
               material->operation.ref!=ref ||
               material->operation.checkpoint!=scope.checkpoint ||
               material->operation.kernel!=AuditRelationKernel::FOLD_RS ||
               material->operation.relation!=RelationKind::FOLDING ||
               material->operation.relation_statement!=
                   share->operation_statement_binding ||
               material->operation.public_aux_root!=share->public_aux_root ||
               !material->has_field_output ||
               material->state_dependencies.size()!=1 ||
               material->field_aux.size()!=1 ||
               material->field_aux.front().first!=
                   AuditPublicAuxKind::FOLD_CHALLENGE ||
               material->field_aux.front().second.size()!=1 ||
               std::find(checkpoint.operations.begin(),
                   checkpoint.operations.end(),ref)==
                   checkpoint.operations.end()) {
                fold_relation_ok=false;break;
            }
            const StateId state_id=material->state_dependencies.front();
            const auto* state=states.Find(state_id);
            std::vector<F> expected;
            if(!state || !state->has_private_share ||
               !state->has_authentication || state->invalidated ||
               !states.VerifyDigest(state_id) ||
               !states.VerifyAuthentication(state_id) ||
               state->state.label.sid!=scope.session_id ||
               state->state.label.owner!=static_cast<uint32_t>(rank) ||
               share->source_state_id!=state_id ||
               share->source_state_owner!=static_cast<uint32_t>(rank) ||
               share->source_state_digest!=state->state.digest ||
               share->source_state_authentication_scheme_id!=
                   state->authentication_scheme_id ||
               share->source_state_authentication_binding!=
                   state->authentication_binding ||
               !recompute_fold_rs_output(
                   state->local_share,
                   material->field_aux.front().second.front(),&expected) ||
               expected.size()!=material->field_output.size() ||
               expected.size()!=share->values.size() ||
               share->expected!=hash_field_vector(expected) ||
               share->actual!=hash_field_vector(material->field_output)) {
                fold_relation_ok=false;break;
            }
            for(size_t i=0;i<expected.size();++i)
                if(share->values[i]!=material->field_output[i]-expected[i]) {
                    fold_relation_ok=false;break;
                }
            if(!fold_relation_ok)break;
        }
        if(expected_local==0 ||
           expected_local!=local_view.handles.size())
            fold_relation_ok=false;
    }
    const RegistrationNativeConsumedSnapshot usable=
        (current && fold_relation_ok)
            ? captured : RegistrationNativeConsumedSnapshot{};
    return ActivateResidualsWithCapturedNativeSnapshot(
        scope,local_view,rank,world_size,
        residual_pin,registration_pre_vss,native_receipt,
        usable,pinned_issuer_public_key,
        expected_issuer_id,minimum_accepted_sequence,
        native_replay_ledger,require_private_residual_provenance);
}

bool ReferenceShamirResidualMpcBackend::
ActivateResidualsWithPairedNativeIssuerReceipts(
    const ObligationSet& scope,
    const LocalResidualBatchView& local_view,
    int rank,int world_size,
    const ResidualNativeSourcePinReceipt& residual_pin,
    const RegistrationConsistencyStatement& registration_pre_vss,
    const RegistrationNativeExecutionReceipt& native_receipt,
    const Digest& independently_expected_native_consumed_binding,
    const std::array<uint8_t,32>& pinned_issuer_public_key,
    u64 expected_issuer_id,u64 minimum_accepted_sequence,
    const RegistrationReceiptReplayLedger* native_replay_ledger,
    bool require_private_residual_provenance) {
    // As in the single-receipt API, local signature failure must join
    // the common authenticated preflight instead of returning early.
    bool private_provenance_verified=true;
    if(require_private_residual_provenance) {
        const PrivateResidualShare* share=
            store_.Find(registration_pre_vss.ref);
        private_provenance_verified =
            registration_pre_vss.ref.owner==static_cast<uint32_t>(rank) &&
            share && share->ref==registration_pre_vss.ref &&
            share->source_state_id==
                registration_pre_vss.native_context.native_state_id &&
            share->source_state_digest==
                registration_pre_vss.public_state_digest &&
            share->source_state_authentication_scheme_id==
                registration_pre_vss.native_context.authentication_scheme_id &&
            share->source_state_authentication_binding==
                registration_pre_vss.native_context.authentication_binding &&
            share->operation_statement_binding==
                registration_pre_vss.operation_statement_binding &&
            share->actual==registration_pre_vss.public_actual_digest &&
            share->computation_binding==
                compute_private_residual_computation_binding(*share) &&
            verify_private_residual_provenance_matches_source_pin(
                *share,residual_pin,pinned_issuer_public_key,
                expected_issuer_id,minimum_accepted_sequence);
    }
    const bool verified=
        verify_residual_source_pin_and_native_execution_pair(
            scope,static_cast<uint32_t>(rank),
            residual_pin,registration_pre_vss,native_receipt,
            independently_expected_native_consumed_binding,
            pinned_issuer_public_key,expected_issuer_id,
            minimum_accepted_sequence) &&
        private_provenance_verified;
    // A verified signed issuer sequence is consumed at most once on
    // persistent owner-private storage. Local replay/IO failure feeds
    // the same authenticated all-rank readiness rejection. The marker
    // is deliberately irreversible even if a later peer refuses.
    const bool usable=verified &&
        (!native_replay_ledger ||
         native_replay_ledger->ConsumeNativeSourcePinOnce(residual_pin));
    const Digest pinned=usable?residual_pin.local_residual_root:Digest{};
    return ActivateResiduals(scope,local_view,rank,world_size,true,&pinned);
}

bool ReferenceShamirResidualMpcBackend::ActivateResidualsWithNativeIssuerPin(
    const ObligationSet& scope,
    const LocalResidualBatchView& local_view,
    int rank,int world_size,
    const ResidualNativeSourcePinReceipt& receipt,
    const Digest& independently_expected_native_consumed_binding,
    const Digest& independently_expected_pre_vss_claim_binding,
    const std::array<uint8_t,32>& pinned_issuer_public_key,
    u64 expected_issuer_id,u64 minimum_accepted_sequence) {
    // Deliberately enter the same collective preflight on EVERY rank,
    // even if the local signature/issuer policy fails: a local
    // return-false here would deadlock peers beginning ActivateResiduals.
    const bool permitted=verify_residual_native_source_pin_receipt(
        scope,static_cast<uint32_t>(rank),receipt,
        independently_expected_native_consumed_binding,
        independently_expected_pre_vss_claim_binding,
        pinned_issuer_public_key,expected_issuer_id,
        minimum_accepted_sequence);
    const Digest pin=permitted?receipt.local_residual_root:Digest{};
    return ActivateResiduals(
        scope,local_view,rank,world_size,true,&pin);
}

bool ReferenceShamirResidualMpcBackend::ActivateResiduals(
    const ObligationSet& scope,
    const LocalResidualBatchView& local_view,
    int rank, int world_size, bool private_owner_mode,
    const Digest* independently_pinned_local_source_root) {
    ClearActivatedResiduals();
    if (!EnsureTransport(scope, rank, world_size) || scope.operations.empty())
        return false;
    // This pin must be supplied by an INDEPENDENT trust boundary before
    // activation; never derive it from owner data after entering this call.
    // It is deliberately never included in the broadcast public descriptor.
    const bool pin_ready=!private_owner_mode ||
        (independently_pinned_local_source_root &&
         *independently_pinned_local_source_root!=Digest{} &&
         *independently_pinned_local_source_root==
             local_view.commitment_root);
    const bool local_ready = pin_ready && ValidateLocalView(local_view, rank);
    bool all_ready = false;
    Digest ready_binding{};
    if (!exchange_.AllTrue(
            NextContext(scope, AUTH_KIND_ACTIVATE_READY),
            local_ready, &all_ready, &ready_binding) ||
        !all_ready || ready_binding == Digest{})
        return false;

    ReferenceBivariateVss vss(
        rank, world_size, mpc_.threshold(), MPI_COMM_WORLD);
    if (!vss.valid()) return false;

    std::vector<OperationRef> refs = scope.operations;
    std::sort(refs.begin(), refs.end(), operation_less);
    if (std::adjacent_find(refs.begin(), refs.end()) != refs.end())
        return false;
    std::vector<ActivatedResidualOperation> activated;
    std::vector<std::pair<OperationRef,Digest>> private_owner_originals;
    std::vector<Digest> descriptor_bindings;
    activated.reserve(refs.size());
    descriptor_bindings.reserve(refs.size());

    for (const OperationRef& ref : refs) {
        std::vector<u64> payload;
        std::vector<F> plaintext;
        bool owner_ready = true;
        if (rank == static_cast<int>(ref.owner)) {
            const PrivateResidualShare* share = store_.Find(ref);
            const PrivateResidualHandle* handle = find_handle(local_view, ref);
            owner_ready = share && handle &&
                validate_private_residual_share(*share) && share->authenticated &&
                share->commitment == handle->commitment &&
                share->checkpoint == scope.checkpoint && share->ref == ref &&
                share->label.sid == scope.session_id &&
                share->expected != Digest{} && share->actual != Digest{} &&
                share->operation_statement_binding != Digest{} &&
                !share->values.empty();
            if (owner_ready) {
                plaintext = share->values;
                payload = {
                    ref.owner, ref.object_id, share->label.sid,
                    static_cast<u64>(share->label.phase), share->label.round,
                    static_cast<u64>(share->label.obligation),
                    static_cast<u64>(share->relation),
                    static_cast<u64>(share->kernel), share->checkpoint,
                    static_cast<u64>(share->values.size())};
                if(private_owner_mode) {
                    // These slot-bound opaque *markers* are PUBLIC constants,
                    // NOT cryptographic commitments to the hidden values.
                    // Their only purpose is avoiding the direct equality leak
                    // (expected==actual) and not releasing source commitments.
                    constexpr u64 REDACTION_DOMAIN=0x5056313035524544ULL;
                    auto public_slot=[&](u64 field) {
                        return hash_words({REDACTION_DOMAIN,
                            scope.session_id,scope.checkpoint,
                            ref.owner,ref.object_id,field});
                    };
                    const Digest expectation=public_slot(1);
                    append_digest(expectation,&payload);
                    append_digest(expectation,&payload);
                    append_digest(public_slot(2),&payload);
                    append_digest(public_slot(3),&payload);
                    private_owner_originals.push_back(
                        {ref,share->commitment});
                }else {
                    append_digest(share->expected, &payload);
                    append_digest(share->actual, &payload);
                    append_digest(share->operation_statement_binding, &payload);
                    append_digest(share->commitment, &payload);
                }
            }
        }
        bool operation_ready = false;
        Digest operation_ready_binding{};
        if (!exchange_.AllTrue(
                NextContext(scope, AUTH_KIND_ACTIVATE_OPERATION_READY,
                            ref.object_id),
                owner_ready, &operation_ready, &operation_ready_binding) ||
            !operation_ready || operation_ready_binding == Digest{})
            return false;

        std::vector<u64> descriptor;
        Digest descriptor_transport{};
        if (!exchange_.BroadcastWords(
                NextContext(scope, AUTH_KIND_ACTIVATE_DESCRIPTOR,
                            ref.object_id),
                static_cast<int>(ref.owner), payload, &descriptor,
                &descriptor_transport) ||
            descriptor.size() != 26 || descriptor_transport == Digest{})
            return false;
        if (descriptor[0] != ref.owner || descriptor[1] != ref.object_id ||
            descriptor[2] != scope.session_id || descriptor[8] != scope.checkpoint ||
            descriptor[9] == 0)
            return false;

        ActivatedResidualOperation operation;
        operation.ref = ref;
        operation.label.sid = descriptor[2];
        operation.label.phase = static_cast<Phase>(descriptor[3]);
        operation.label.round = static_cast<uint32_t>(descriptor[4]);
        operation.label.owner = static_cast<uint32_t>(descriptor[0]);
        operation.label.obligation = static_cast<Obligation>(descriptor[5]);
        operation.label.object_id = descriptor[1];
        operation.relation = static_cast<RelationKind>(descriptor[6]);
        operation.kernel = static_cast<AuditRelationKernel>(descriptor[7]);
        operation.checkpoint = descriptor[8];
        operation.expected = digest_from_words(descriptor, 10);
        operation.actual = digest_from_words(descriptor, 14);
        operation.operation_statement_binding = digest_from_words(descriptor, 18);
        operation.source_commitment = digest_from_words(descriptor, 22);
        if (operation.expected == Digest{} || operation.actual == Digest{} ||
            operation.operation_statement_binding == Digest{} ||
            operation.source_commitment == Digest{})
            return false;

        ReferenceVssReceipt vss_receipt;
        ReferenceVssDealerWitness dealer_witness;
        if (!vss.ShareVectorFromDealerAuthenticated(
                static_cast<int>(ref.owner), plaintext,
                &operation.local_shares, &vss_receipt,
                exchange_,
                NextContext(scope, AUTH_KIND_ACTIVATE_VSS, ref.object_id),
                &dealer_witness, &operation.local_witness) ||
            operation.local_shares.size() !=
                static_cast<size_t>(descriptor[9]) ||
            !vss_receipt.available || !vss_receipt.consistent ||
            vss_receipt.element_count != operation.local_shares.size() ||
            vss_receipt.transcript_binding == Digest{} ||
            !validate_reference_vss_local_witness(operation.local_witness) ||
            operation.local_witness.transcript_binding !=
                vss_receipt.transcript_binding)
            return false;
        // Independently recheck the dealer's original private residual
        // against the constant coefficient of the authenticated VSS
        // sharing polynomial. Bind to the signed transport capability and
        // the VSS receipt transcript from this collective.
        //
        // This is a POST-ACTIVATION consistency check; it does not turn an
        // unauthenticated source into an authenticated PrivateResidualShare.
        // Only available in the isolated activated-private integration
        // selftest: deliberately challenge the dealer witness with a
        // different locally expected secret. The checked VSS transcript
        // remains genuine, and AllTrue must reject on every participant.
        const char* link_fault = std::getenv(
            "PVIA_P105_VSS_DEALER_LINK_FAULT_SELFTEST");
        const char* activated_selftest = std::getenv(
            "PVIA_P105_ACTIVATED_PRIVATE_SELFTEST");
        const bool inject_link_fault = link_fault && link_fault[0]=='1' &&
            link_fault[1]=='\0' && activated_selftest &&
            activated_selftest[0]=='1' && activated_selftest[1]=='\0';
        bool dealer_link_ok = true;
        if (rank == static_cast<int>(ref.owner)) {
            std::vector<F> expected_private_residual = plaintext;
            if (inject_link_fault && !expected_private_residual.empty())
                expected_private_residual[0] += F(1);
            dealer_link_ok =
                verify_reference_vss_dealer_authenticated_source_link(
                    dealer_witness, expected_private_residual,
                    vss_receipt.transcript_binding,
                    exchange_.ProductionCapabilityBinding());
        }
        // Verify that every recipient's actual private VSS share matches
        // the constant coefficient of its committed local row. No share
        // value is transmitted to another rank during this check.
        std::vector<F> expected_local_shares=operation.local_shares;
        const char* recipient_fault = std::getenv(
            "PVIA_P105_VSS_RECIPIENT_LINK_FAULT_SELFTEST");
        const bool inject_recipient_fault = recipient_fault &&
            recipient_fault[0]=='1' && recipient_fault[1]=='\0' &&
            activated_selftest && activated_selftest[0]=='1' &&
            activated_selftest[1]=='\0' && rank==1;
        if (inject_recipient_fault && !expected_local_shares.empty())
            expected_local_shares[0] += F(1);
        const bool recipient_link_ok =
            verify_reference_vss_recipient_authenticated_share_link(
                operation.local_witness,expected_local_shares,
                vss_receipt.transcript_binding,
                exchange_.ProductionCapabilityBinding());
        const bool local_link_ok=dealer_link_ok && recipient_link_ok;
        bool all_dealer_links_ok = false;
        Digest dealer_link_agreement{};
        const bool link_transport_ok = exchange_.AllTrue(
            NextContext(scope, AUTH_KIND_ACTIVATE_VSS_DEALER_LINK,
                        ref.object_id),
            local_link_ok, &all_dealer_links_ok,
            &dealer_link_agreement);
        if ((inject_link_fault || recipient_fault) && rank == 0)
            std::cout << "[PVIA][vss-dealer-source-link-selftest] "
                      << ((link_transport_ok && !all_dealer_links_ok)
                              ? "REJECTED_ALL_RANKS"
                              : "UNEXPECTED_RESULT")
                      << " private_values_revealed=false\n";
        if (!link_transport_ok || !all_dealer_links_ok ||
            dealer_link_agreement == Digest{})
            return false;
        operation.sharing_binding = vss_receipt.transcript_binding;
        operation.descriptor_binding = bind_words(
            REFERENCE_RESIDUAL_ACTIVATION_DOMAIN,
            {operation.expected, operation.actual,
             operation.operation_statement_binding,
             operation.source_commitment, operation.sharing_binding,
             descriptor_transport, operation_ready_binding},
            {ref.owner, ref.object_id, descriptor[9]});
        if (operation.descriptor_binding == Digest{}) return false;
        descriptor_bindings.push_back(operation.descriptor_binding);
        activated.push_back(std::move(operation));
    }

    const Digest scope_binding = compute_collective_scope_binding(scope);
    const Digest candidate = bind_words(
        REFERENCE_RESIDUAL_ACTIVATION_DOMAIN,
        descriptor_bindings,
        {scope.session_id, scope.checkpoint,
         static_cast<u64>(activated.size())});
    std::vector<u64> local_candidate;
    append_digest(candidate, &local_candidate);
    std::vector<u64> gathered;
    Digest final_transport{};
    if (candidate == Digest{} ||
        !exchange_.AllGatherWords(
            NextContext(scope, AUTH_KIND_ACTIVATE_FINAL),
            local_candidate, &gathered, &final_transport) ||
        gathered.size() != static_cast<size_t>(world_size) * 4 ||
        final_transport == Digest{})
        return false;
    for (int peer = 0; peer < world_size; ++peer)
        if (digest_from_words(gathered, static_cast<size_t>(peer) * 4) != candidate)
            return false;

    activated_sid_ = scope.session_id;
    activated_checkpoint_ = scope.checkpoint;
    activated_scope_binding_ = scope_binding;
    activation_binding_ = bind_words(
        REFERENCE_RESIDUAL_ACTIVATION_DOMAIN,
        {candidate, scope_binding, final_transport,
         exchange_.ProductionCapabilityBinding(), ready_binding},
        {static_cast<u64>(activated.size())});
    if (activation_binding_ == Digest{}) {
        ClearActivatedResiduals();
        return false;
    }
    private_owner_activation_mode_ = private_owner_mode;
    owner_original_source_commitments_ =
        std::move(private_owner_originals);
    activated_operations_ = std::move(activated);
    return HasActivatedVssProvenance(scope);
}

bool ReferenceShamirResidualMpcBackend::
PrivateOwnerActivationMetadataRedacted(
    const ObligationSet& scope) const {
    if(!private_owner_activation_mode_ ||
       !HasActivatedVssProvenance(scope))return false;
    constexpr u64 REDACTION_DOMAIN=0x5056313035524544ULL;
    for(const auto& op:activated_operations_) {
        auto marker=[&](u64 field) {
            return hash_words({REDACTION_DOMAIN,
                scope.session_id,scope.checkpoint,
                op.ref.owner,op.ref.object_id,field});
        };
        if(op.expected!=marker(1) ||
           op.actual!=marker(1) ||
           op.operation_statement_binding!=marker(2) ||
           op.source_commitment!=marker(3))
            return false;
    }
    return true;
}

CollectiveBatchDescriptor
ReferenceShamirResidualMpcBackend::
PrivateOwnerPublicBatchDescriptor(
    const ObligationSet& scope,
    const LocalResidualBatchView& local_view,
    int rank,int world_size) const {
    if(!PrivateOwnerActivationMetadataRedacted(scope) ||
       !ValidateActivatedLocalView(local_view,rank) ||
       rank!=mpc_.rank() || world_size!=mpc_.world_size())
        return {};
    // Public shape/root intentionally excludes all local handle commitments.
    constexpr u64 PUBLIC_ROOT_DOMAIN=0x505631303550524fULL;
    std::vector<u64> words={
        PUBLIC_ROOT_DOMAIN,scope.session_id,scope.checkpoint,
        static_cast<u64>(rank),static_cast<u64>(world_size)};
    for(const auto& ref:scope.operations)
        if(ref.owner==static_cast<uint32_t>(rank)) {
            const auto* op=FindActivated(ref);
            if(!op)return {};
            words.push_back(ref.owner);
            words.push_back(ref.object_id);
            words.push_back(static_cast<u64>(op->relation));
            words.push_back(static_cast<u64>(op->kernel));
            words.push_back(op->local_shares.size());
        }
    CollectiveBatchDescriptor desc;
    desc.scope=scope;
    desc.local_owner=static_cast<uint32_t>(rank);
    desc.world_size=world_size;
    desc.local_handle_count=local_view.handles.size();
    desc.local_commitment_root=hash_words(words);
    if(desc.local_commitment_root==Digest{})return {};
    desc.descriptor_digest=compute_collective_descriptor_digest(
        scope,desc.local_owner,world_size,
        desc.local_handle_count,desc.local_commitment_root);
    return desc;
}

AuthenticatedMpcMessageContext
ReferenceShamirResidualMpcBackend::NextContext(
    const ObligationSet& scope, u64 message_kind, uint64_t round) const {
    AuthenticatedMpcMessageContext context;
    context.protocol_domain = REFERENCE_RESIDUAL_MPC_PROTOCOL_ID;
    context.sid = scope.session_id;
    context.checkpoint = scope.checkpoint;
    context.round = round;
    context.sequence = exchange_sequence_++;
    context.message_kind = message_kind;
    return context;
}

F ReferenceShamirResidualMpcBackend::DeriveCoefficient(
    const Digest& challenge, const OperationRef& ref,
    size_t coordinate, const Digest& domain_binding) const {
    return derive_residual_batch_global_coefficient(
        active_sid_, active_checkpoint_, challenge,
        domain_binding, ref, coordinate);
}

void ReferenceShamirResidualMpcBackend::ClearPassiveSharingCache() const {
    passive_cache_capture_ = false;
    passive_cache_sid_ = 0;
    passive_cache_checkpoint_ = 0;
    passive_cache_scope_binding_ = Digest{};
    passive_cache_batch_binding_ = Digest{};
    passive_sharing_cache_.clear();
}

void ReferenceShamirResidualMpcBackend::BeginPassiveSharingCacheCapture(
    const ObligationSet& scope) const {
    ClearPassiveSharingCache();
    passive_cache_capture_ = true;
    passive_cache_sid_ = scope.session_id;
    passive_cache_checkpoint_ = scope.checkpoint;
    passive_cache_scope_binding_ = compute_collective_scope_binding(scope);
    passive_sharing_cache_.reserve(scope.operations.size());
}

bool ReferenceShamirResidualMpcBackend::PreparePassiveSharingCache(
    const ObligationSet& scope) const {
    BeginPassiveSharingCacheCapture(scope);
    if (scope.operations.empty() ||
        passive_cache_scope_binding_ == Digest{})
        return false;

    std::vector<OperationRef> ordered = scope.operations;
    std::sort(ordered.begin(), ordered.end(), operation_less);
    if (std::adjacent_find(ordered.begin(), ordered.end()) != ordered.end())
        return false;

    for (int owner = 0; owner < mpc_.world_size(); ++owner) {
        std::vector<OperationRef> owner_refs;
        for (const OperationRef& ref : ordered) {
            if (ref.owner >= static_cast<uint32_t>(mpc_.world_size()))
                return false;
            if (ref.owner == static_cast<uint32_t>(owner))
                owner_refs.push_back(ref);
        }
        if (owner_refs.empty()) continue;

        // Layout is public/authenticated metadata: operation id and residual
        // coordinate count. The old per-operation ShareVectorFromDealer path
        // already revealed each vector length separately; batching only moves
        // those shapes into one owner-scoped descriptor.
        std::vector<u64> layout;
        std::vector<F> plaintext;
        if (mpc_.rank() == owner) {
            bool owner_ready = true;
            uint64_t total_coordinates = 0;
            layout = {
                1ULL, static_cast<u64>(owner),
                static_cast<u64>(owner_refs.size()), 0ULL};
            layout.reserve(4 + 2 * owner_refs.size());
            for (const OperationRef& ref : owner_refs) {
                const PrivateResidualShare* share = store_.Find(ref);
                const bool share_ok =
                    share && validate_private_residual_share(*share) &&
                    share->authenticated &&
                    share->checkpoint == scope.checkpoint &&
                    share->label.sid == scope.session_id &&
                    share->ref == ref && !share->values.empty() &&
                    share->values.size() <=
                        static_cast<size_t>(
                            std::numeric_limits<uint64_t>::max());
                const uint64_t count = share_ok
                    ? static_cast<uint64_t>(share->values.size()) : 0ULL;
                if (!share_ok ||
                    total_coordinates >
                        std::numeric_limits<uint64_t>::max() - count) {
                    owner_ready = false;
                } else {
                    total_coordinates += count;
                }
                layout.push_back(ref.object_id);
                layout.push_back(count);
                if (share_ok)
                    plaintext.insert(
                        plaintext.end(),
                        share->values.begin(), share->values.end());
            }
            layout[0] = owner_ready ? 1ULL : 0ULL;
            layout[3] = owner_ready ? total_coordinates : 0ULL;
            if (!owner_ready) plaintext.clear();
        }

        std::vector<u64> received_layout;
        Digest layout_transport_binding{};
        if (!exchange_.BroadcastWords(
                NextContext(
                    scope, AUTH_KIND_PASSIVE_BATCH_LAYOUT,
                    static_cast<uint64_t>(owner)),
                owner, layout, &received_layout,
                &layout_transport_binding) ||
            layout_transport_binding == Digest{})
            return false;

        const size_t expected_words = 4 + 2 * owner_refs.size();
        if (received_layout.size() != expected_words ||
            received_layout[0] != 1ULL ||
            received_layout[1] != static_cast<u64>(owner) ||
            received_layout[2] !=
                static_cast<u64>(owner_refs.size()) ||
            received_layout[3] == 0)
            return false;

        uint64_t total_coordinates = 0;
        std::vector<size_t> lengths;
        lengths.reserve(owner_refs.size());
        for (size_t i = 0; i < owner_refs.size(); ++i) {
            const size_t offset = 4 + 2 * i;
            const uint64_t object_id = received_layout[offset];
            const uint64_t count = received_layout[offset + 1];
            if (object_id != owner_refs[i].object_id ||
                count == 0 ||
                count > static_cast<uint64_t>(
                    std::numeric_limits<size_t>::max()) ||
                total_coordinates >
                    std::numeric_limits<uint64_t>::max() - count)
                return false;
            total_coordinates += count;
            lengths.push_back(static_cast<size_t>(count));
        }
        if (total_coordinates != received_layout[3] ||
            total_coordinates >
                static_cast<uint64_t>(
                    std::numeric_limits<size_t>::max()))
            return false;
        if (mpc_.rank() == owner &&
            plaintext.size() !=
                static_cast<size_t>(total_coordinates))
            return false;

        std::vector<F> owner_local_shares;
        if (!mpc_.ShareVectorFromDealerKnownSize(
                owner, plaintext,
                static_cast<size_t>(total_coordinates),
                &owner_local_shares) ||
            owner_local_shares.size() !=
                static_cast<size_t>(total_coordinates))
            return false;

        size_t cursor = 0;
        for (size_t i = 0; i < owner_refs.size(); ++i) {
            const size_t count = lengths[i];
            if (cursor > owner_local_shares.size() ||
                owner_local_shares.size() - cursor < count)
                return false;
            PassiveResidualSharingCacheEntry entry;
            entry.ref = owner_refs[i];
            entry.local_shares.assign(
                owner_local_shares.begin() +
                    static_cast<std::ptrdiff_t>(cursor),
                owner_local_shares.begin() +
                    static_cast<std::ptrdiff_t>(cursor + count));
            passive_sharing_cache_.push_back(std::move(entry));
            cursor += count;
        }
        if (cursor != owner_local_shares.size())
            return false;
    }

    if (passive_sharing_cache_.size() != ordered.size())
        return false;
    std::sort(
        passive_sharing_cache_.begin(),
        passive_sharing_cache_.end(),
        [](const PassiveResidualSharingCacheEntry& lhs,
           const PassiveResidualSharingCacheEntry& rhs) {
            return operation_less(lhs.ref, rhs.ref);
        });
    return true;
}

const std::vector<F>*
ReferenceShamirResidualMpcBackend::FindPassiveSharingCache(
    const ObligationSet& scope, const OperationRef& ref) const {
    if ((!passive_cache_capture_ &&
         passive_cache_batch_binding_ == Digest{}) ||
        passive_cache_sid_ != scope.session_id ||
        passive_cache_checkpoint_ != scope.checkpoint ||
        passive_cache_scope_binding_ != compute_collective_scope_binding(scope))
        return nullptr;
    const auto it = std::lower_bound(
        passive_sharing_cache_.begin(),
        passive_sharing_cache_.end(), ref,
        [](const PassiveResidualSharingCacheEntry& entry,
           const OperationRef& target) {
            return operation_less(entry.ref, target);
        });
    if (it == passive_sharing_cache_.end() || it->ref != ref)
        return nullptr;
    return &it->local_shares;
}

bool ReferenceShamirResidualMpcBackend::PassiveSharingCacheMatches(
    const ObligationSet& scope, const BatchCheckResult& batch) const {
    return passive_cache_batch_binding_ != Digest{} &&
        passive_cache_sid_ == scope.session_id &&
        passive_cache_checkpoint_ == scope.checkpoint &&
        passive_cache_scope_binding_ == compute_collective_scope_binding(scope) &&
        passive_cache_batch_binding_ ==
            compute_collective_batch_result_binding(batch) &&
        passive_sharing_cache_.size() == scope.operations.size();
}

bool ReferenceShamirResidualMpcBackend::BuildFingerprint(
    const ObligationSet& scope,
    const std::vector<OperationRef>& operations,
    const Digest& challenge,
    const Digest& domain_binding,
    F* fingerprint_share,
    Digest* sharing_binding,
    ReferenceLinearSharingProvenance* provenance) const {
    if (!fingerprint_share || !sharing_binding || operations.empty() ||
        challenge == Digest{} || domain_binding == Digest{})
        return false;
    const bool activated = HasActivatedVssProvenance(scope);
    if (provenance) *provenance = ReferenceLinearSharingProvenance{};
    if (provenance && !activated) return false;

    *fingerprint_share = F(0);
    std::vector<Digest> operation_bindings;
    std::vector<ReferenceLinearSharingSource> provenance_sources;
    std::vector<OperationRef> ordered = operations;
    std::sort(ordered.begin(), ordered.end(), operation_less);
    if (provenance) provenance_sources.reserve(ordered.size());
    for (const OperationRef& ref : ordered) {
        if (ref.owner >= static_cast<uint32_t>(mpc_.world_size())) return false;
        std::vector<F> local_shares;
        const ActivatedResidualOperation* activated_operation = nullptr;
        if (activated) {
            activated_operation = FindActivated(ref);
            if (!activated_operation || activated_operation->local_shares.empty() ||
                activated_operation->descriptor_binding == Digest{} ||
                activated_operation->sharing_binding == Digest{})
                return false;
            local_shares = activated_operation->local_shares;
        } else {
            const std::vector<F>* cached =
                FindPassiveSharingCache(scope, ref);
            if (cached) {
                local_shares = *cached;
            } else {
                std::vector<F> plaintext;
                if (mpc_.rank() == static_cast<int>(ref.owner)) {
                    const PrivateResidualShare* share = store_.Find(ref);
                    if (share && validate_private_residual_share(*share) &&
                        share->authenticated &&
                        share->checkpoint == scope.checkpoint &&
                        share->ref == ref)
                        plaintext = share->values;
                }
                if (!mpc_.ShareVectorFromDealer(
                        static_cast<int>(ref.owner), plaintext,
                        &local_shares) ||
                    local_shares.empty())
                    return false;
                if (passive_cache_capture_ &&
                    passive_cache_sid_ == scope.session_id &&
                    passive_cache_checkpoint_ == scope.checkpoint &&
                    passive_cache_scope_binding_ ==
                        compute_collective_scope_binding(scope)) {
                    PassiveResidualSharingCacheEntry entry;
                    entry.ref = ref;
                    entry.local_shares = local_shares;
                    passive_sharing_cache_.push_back(std::move(entry));
                }
            }
        }
        F local_operation_fingerprint(0);
        std::vector<F> coefficients;
        if (provenance) coefficients.reserve(local_shares.size());
        for (size_t coordinate = 0; coordinate < local_shares.size(); ++coordinate) {
            const F coefficient = DeriveCoefficient(
                challenge, ref, coordinate, domain_binding);
            local_operation_fingerprint += coefficient * local_shares[coordinate];
            if (provenance) coefficients.push_back(coefficient);
        }
        *fingerprint_share += local_operation_fingerprint;
        std::vector<u64> bind = {
            ref.owner, ref.object_id, static_cast<u64>(local_shares.size())};
        append_digest(challenge, &bind);
        append_digest(domain_binding, &bind);
        if (activated) {
            bind.push_back(1ULL);
            append_digest(activated_operation->descriptor_binding, &bind);
            append_digest(activated_operation->sharing_binding, &bind);
            append_digest(activation_binding_, &bind);
        }
        operation_bindings.push_back(hash_words(bind));
        if (provenance) {
            ReferenceLinearSharingSource source;
            source.sharing_binding = activated_operation->sharing_binding;
            source.element_coefficients = std::move(coefficients);
            source.local_witness = activated_operation->local_witness;
            provenance_sources.push_back(std::move(source));
        }
    }

    if (activated) operation_bindings.push_back(activation_binding_);
    *sharing_binding = bind_words(
        REFERENCE_RESIDUAL_BATCH_DOMAIN, operation_bindings,
        {static_cast<u64>(ordered.size()), activated ? 1ULL : 0ULL});
    if (*sharing_binding == Digest{}) return false;
    if (provenance &&
        (!build_reference_linear_sharing_provenance(
             std::move(provenance_sources), provenance) ||
         provenance->local_share != *fingerprint_share ||
         provenance->binding == Digest{}))
        return false;
    return true;
}

CollectiveResidualCommitmentSet
ReferenceShamirResidualMpcBackend::CommitResidualBatch(
    const ObligationSet& scope,
    const CollectiveBatchDescriptor& local_descriptor,
    const LocalResidualBatchView& local_view,
    int rank, int world_size) const {
    CollectiveResidualCommitmentSet out;
    out.checkpoint = scope.checkpoint;
    if (!EnsureTransport(scope, rank, world_size))
        return out;
    const CollectiveBatchDescriptor public_desc =
        private_owner_activation_mode_
        ? PrivateOwnerPublicBatchDescriptor(
            scope,local_view,rank,world_size)
        : CollectiveBatchDescriptor{};
    const bool public_desc_valid =
        !private_owner_activation_mode_ ||
        (public_desc.descriptor_digest!=Digest{} &&
         local_descriptor.descriptor_digest==
             public_desc.descriptor_digest &&
         local_descriptor.local_commitment_root==
             public_desc.local_commitment_root);
    const bool local_ready =
        public_desc_valid &&
        (HasActivatedResiduals(scope)
            ? ValidateActivatedLocalView(local_view, rank)
            : ValidateLocalView(local_view, rank)) &&
        local_descriptor.local_owner == static_cast<uint32_t>(rank) &&
        local_descriptor.world_size == world_size &&
        local_descriptor.descriptor_digest != Digest{} &&
        local_descriptor.local_commitment_root != Digest{};
    bool all_ready = false;
    Digest ready_binding{};
    if (!exchange_.AllTrue(
            NextContext(scope, AUTH_KIND_COMMIT_READY),
            local_ready, &all_ready, &ready_binding) ||
        !all_ready || ready_binding == Digest{})
        return out;

    std::vector<u64> local_payload = {
        static_cast<u64>(rank),
        static_cast<u64>(local_descriptor.local_handle_count)
    };
    append_digest(local_descriptor.descriptor_digest, &local_payload);
    append_digest(local_descriptor.local_commitment_root, &local_payload);
    std::vector<u64> gathered;
    Digest gather_binding{};
    if (!exchange_.AllGatherWords(
            NextContext(scope, AUTH_KIND_COMMITMENTS),
            local_payload, &gathered, &gather_binding) ||
        gather_binding == Digest{} ||
        gathered.size() != static_cast<size_t>(world_size) * local_payload.size())
        return out;

    const size_t stride = local_payload.size();
    out.participants.reserve(static_cast<size_t>(world_size));
    const Digest transport_capability = exchange_.ProductionCapabilityBinding();
    for (int i = 0; i < world_size; ++i) {
        const size_t offset = static_cast<size_t>(i) * stride;
        if (gathered[offset] != static_cast<u64>(i))
            return CollectiveResidualCommitmentSet{};
        ParticipantResidualCommitment participant;
        participant.owner = static_cast<uint32_t>(i);
        participant.handle_count = static_cast<size_t>(gathered[offset + 1]);
        participant.descriptor_digest = digest_from_words(gathered, offset + 2);
        participant.local_commitment_root = digest_from_words(gathered, offset + 6);
        participant.authentication_commitment = bind_words(
            REFERENCE_RESIDUAL_COMMIT_DOMAIN,
            {participant.descriptor_digest, participant.local_commitment_root,
             gather_binding, transport_capability},
            {participant.owner, static_cast<u64>(participant.handle_count)});
        if (participant.descriptor_digest == Digest{} ||
            participant.local_commitment_root == Digest{} ||
            participant.authentication_commitment == Digest{})
            return CollectiveResidualCommitmentSet{};
        out.participants.push_back(participant);
    }
    out.available = true;
    out.cryptographically_authenticated = true;
    out.root = compute_collective_residual_commitment_root(
        out.participants, out.security_attestation_binding);
    if (!validate_participant_commitment_set(
            scope, local_descriptor, out, world_size))
        return CollectiveResidualCommitmentSet{};
    return out;
}

AuthenticatedChallengeTranscript
ReferenceShamirResidualMpcBackend::DeriveJointChallenge(
    const ObligationSet& scope,
    const CollectiveBatchDescriptor& local_descriptor,
    const CollectiveResidualCommitmentSet& commitments,
    int rank, int world_size) const {
    AuthenticatedChallengeTranscript out;
    out.checkpoint = scope.checkpoint;
    if (!EnsureTransport(scope, rank, world_size))
        return out;
    const bool local_ready = validate_participant_commitment_set(
        scope, local_descriptor, commitments, world_size);
    bool all_ready = false;
    Digest ready_binding{};
    if (!exchange_.AllTrue(
            NextContext(scope, AUTH_KIND_CHALLENGE_READY),
            local_ready, &all_ready, &ready_binding) ||
        !all_ready || ready_binding == Digest{})
        return out;

    Digest seed{};
    Digest coin_transcript{};
    if (!mpc_.JointPublicSeed(&seed, &coin_transcript) ||
        seed == Digest{} || coin_transcript == Digest{})
        return out;
    out.available = true;
    out.cryptographically_authenticated = true;
    out.participant_count = commitments.participants.size();
    out.scope_binding = compute_collective_scope_binding(scope);
    out.participant_commitment_root = commitments.root;
    out.randomness_commitment = bind_words(
        REFERENCE_RESIDUAL_CHALLENGE_DOMAIN,
        {coin_transcript, commitments.root, out.scope_binding});
    out.challenge = bind_words(
        REFERENCE_RESIDUAL_CHALLENGE_DOMAIN,
        {seed, coin_transcript, commitments.root, out.scope_binding});
    out.security_attestation_binding =
        commitments.security_attestation_binding;
    out.proof_commitment = bind_words(
        REFERENCE_RESIDUAL_CHALLENGE_DOMAIN,
        {coin_transcript, exchange_.ProductionCapabilityBinding(),
         Capabilities().capability_binding});
    out.transcript_digest = compute_challenge_transcript_digest(out);
    if (!validate_challenge_transcript(
            scope, commitments, out, world_size))
        return AuthenticatedChallengeTranscript{};
    return out;
}

bool ReferenceShamirResidualMpcBackend::LocalizeActivatedPrivateOwner(
    const ObligationSet& scope,
    const LocalResidualBatchView& local_view,
    const CollectiveResidualCommitmentSet& commitments,
    const AuthenticatedChallengeTranscript& challenge,
    int rank, int world_size,
    ReferencePrivateOwnerSelectionResult* result,
    Digest* activated_input_binding) const {
    if(!result || !activated_input_binding)return false;
    *result={};
    *activated_input_binding={};
    // Strictly activated-only: never re-contact store_ or passively reshare
    // a fresh witness from the owner during the failure-time computation.
    if(!EnsureTransport(scope,rank,world_size) ||
       !HasActivatedVssProvenance(scope) ||
       !PrivateOwnerActivationMetadataRedacted(scope) ||
       !ValidateActivatedLocalView(local_view,rank) ||
       !validate_challenge_transcript(
           scope,commitments,challenge,world_size) ||
       scope.operations.empty() || scope.operations.size()>64 ||
       challenge.challenge==Digest{} ||
       challenge.transcript_digest==Digest{} ||
       activation_binding_==Digest{})
        return false;

    std::vector<OperationRef> ordered=scope.operations;
    std::sort(ordered.begin(),ordered.end(),operation_less);
    if(std::adjacent_find(ordered.begin(),ordered.end())!=ordered.end())
        return false;
    std::vector<F> fingerprints;
    std::vector<uint32_t> owners;
    std::vector<Digest> sources;
    fingerprints.reserve(ordered.size());
    owners.reserve(ordered.size());
    sources.reserve(ordered.size());
    for(const OperationRef& ref:ordered) {
        const ActivatedResidualOperation* active=FindActivated(ref);
        if(!active || active->local_shares.empty() ||
           active->descriptor_binding==Digest{} ||
           active->sharing_binding==Digest{} ||
           active->source_commitment==Digest{})
            return false;
        F share(0);
        Digest fingerprint_binding{};
        // The exact SAME coefficients and challenge transcript used for
        // full-batch reference fingerprints. No per-subset coins or tags.
        if(!BuildFingerprint(
                scope,{ref},challenge.challenge,
                challenge.transcript_digest,
                &share,&fingerprint_binding,nullptr) ||
           fingerprint_binding==Digest{})
            return false;
        fingerprints.push_back(share);
        owners.push_back(ref.owner);
        sources.push_back(active->descriptor_binding);
        sources.push_back(active->sharing_binding);
        sources.push_back(active->source_commitment);
        sources.push_back(fingerprint_binding);
    }
    constexpr u64 INPUT_DOMAIN=0x5056313035415653ULL; // PV105AVS
    const Digest input_binding=bind_words(
        INPUT_DOMAIN,
        [&] {
            std::vector<Digest> anchored={
                activation_binding_,activated_scope_binding_,
                commitments.root,challenge.challenge,
                challenge.transcript_digest};
            anchored.insert(anchored.end(),sources.begin(),sources.end());
            return anchored;
        }(),
        {scope.session_id,scope.checkpoint,
         static_cast<u64>(ordered.size()),
         static_cast<u64>(world_size)});
    if(input_binding==Digest{})return false;

    std::vector<F> flags;
    uint64_t flag_multiplications=0;
    if(!derive_reference_private_nonzero_flags(
           mpc_,fingerprints,&flags,&flag_multiplications) ||
       flags.size()!=ordered.size() || flag_multiplications==0)
        return false;
    ReferencePrivateOwnerSelectionResult candidate;
    if(!select_reference_private_fault_owner(
           mpc_,flags,owners,scope.session_id,scope.checkpoint,
           &candidate) ||
       !candidate.available || candidate.circuit_binding==Digest{})
        return false;
    *result=candidate;
    *activated_input_binding=input_binding;
    return true;
}

BatchCheckResult
ReferenceShamirResidualMpcBackend::RandomLinearBatchCheck(
    const ObligationSet& scope,
    const CollectiveBatchDescriptor& local_descriptor,
    const LocalResidualBatchView& local_view,
    const CollectiveResidualCommitmentSet& commitments,
    const AuthenticatedChallengeTranscript& challenge_transcript,
    int rank, int world_size) const {
    BatchCheckResult out;
    out.available = false;
    out.cryptographically_authenticated = false;
    out.ok = false;
    out.checkpoint = scope.checkpoint;
    if (!EnsureTransport(scope, rank, world_size) ||
        private_owner_activation_mode_) return out;
    const bool activated = HasActivatedVssProvenance(scope);
    const bool local_ready =
        (activated ? ValidateActivatedLocalView(local_view, rank)
                   : ValidateLocalView(local_view, rank)) &&
        validate_participant_commitment_set(
            scope, local_descriptor, commitments, world_size) &&
        validate_challenge_transcript(
            scope, commitments, challenge_transcript, world_size);
    bool all_ready = false;
    Digest ready_binding{};
    if (!exchange_.AllTrue(
            NextContext(scope, AUTH_KIND_BATCH_READY), local_ready,
            &all_ready, &ready_binding) || !all_ready || ready_binding == Digest{})
        return out;

    const bool strong_zero = activated &&
        mpc_.multiplication_consistency_available();
    F fingerprint(0);
    Digest sharing_binding{};
    ReferenceLinearSharingProvenance provenance;
    if (!activated && !PreparePassiveSharingCache(scope)) {
        ClearPassiveSharingCache();
        return out;
    }
    if (!BuildFingerprint(
            scope, scope.operations, challenge_transcript.challenge,
            challenge_transcript.transcript_digest,
            &fingerprint, &sharing_binding,
            strong_zero ? &provenance : nullptr)) {
        if (!activated) ClearPassiveSharingCache();
        return out;
    }
    if (!activated)
        passive_cache_capture_ = false;
    bool is_zero = false;
    Digest zero_binding{};
    Digest multiplication_binding{};
    if (strong_zero) {
        ReferenceMaskedZeroConsistencyContext context;
        context.sid = scope.session_id;
        context.checkpoint = scope.checkpoint;
        context.context_binding = bind_words(
            REFERENCE_RESIDUAL_STRONG_ZERO_DOMAIN,
            {sharing_binding, challenge_transcript.transcript_digest,
             activation_binding_},
            {0ULL, static_cast<u64>(scope.operations.size())});
        context.multiplication_id = nonzero_digest_word(context.context_binding);
        if (context.context_binding == Digest{} ||
            !mpc_.MaskedZeroTestWithConsistency(
                provenance, context, &is_zero, &zero_binding,
                &multiplication_binding) ||
            zero_binding == Digest{} || multiplication_binding == Digest{})
            return out;
    } else if (!mpc_.MaskedZeroTest(
                   fingerprint, &is_zero, &zero_binding) ||
               zero_binding == Digest{}) {
        return out;
    }

    if (!strong_zero && !is_zero) {
        size_t localization_depth = 0;
        size_t remaining = scope.operations.size();
        while (remaining > 1) {
            remaining = (remaining + 1) / 2;
            ++localization_depth;
        }
        if (localization_depth > 0 &&
            !mpc_.PreparePassiveRandomMasks(
                localization_depth))
            return BatchCheckResult{};
    }

    out.available = true;
    out.cryptographically_authenticated = true;
    out.ok = is_zero;
    out.checked_operations = scope.operations.size();
    out.mismatches = is_zero ? 0 : 1;
    out.participant_count = commitments.participants.size();
    out.scope_binding = compute_collective_scope_binding(scope);
    out.participant_commitment_root = commitments.root;
    out.challenge_transcript_binding = challenge_transcript.transcript_digest;
    out.challenge = challenge_transcript.challenge;
    out.security_attestation_binding =
        challenge_transcript.security_attestation_binding;
    std::vector<Digest> audit_bindings = {
        sharing_binding, zero_binding, commitments.root,
        challenge_transcript.transcript_digest};
    if (strong_zero) audit_bindings.push_back(multiplication_binding);
    out.aggregate_residual_commitment = bind_words(
        REFERENCE_RESIDUAL_BATCH_DOMAIN, audit_bindings,
        {is_zero ? 1ULL : 0ULL,
         static_cast<u64>(scope.operations.size()),
         strong_zero ? 1ULL : 0ULL});
    if (!validate_collective_batch_result(scope, out, world_size)) {
        if (!activated) ClearPassiveSharingCache();
        return BatchCheckResult{};
    }
    if (!activated) {
        passive_cache_batch_binding_ =
            compute_collective_batch_result_binding(out);
        if (passive_cache_batch_binding_ == Digest{} ||
            passive_sharing_cache_.size() != scope.operations.size()) {
            ClearPassiveSharingCache();
        }
    }
    return out;
}

ResidualSubsetCheckResult
ReferenceShamirResidualMpcBackend::CheckResidualSubset(
    const ObligationSet& scope,
    const BatchCheckResult& batch,
    const ResidualSubsetDescriptor& subset,
    const LocalResidualBatchView& local_view,
    int rank, int world_size) const {
    ResidualSubsetCheckResult out;
    out.checkpoint = scope.checkpoint;
    if (private_owner_activation_mode_ ||
        !EnsureTransport(scope, rank, world_size)) return out;
    const bool activated = HasActivatedVssProvenance(scope);
    if (!activated && !PassiveSharingCacheMatches(scope, batch))
        ClearPassiveSharingCache();
    const bool local_ready =
        (activated ? ValidateActivatedLocalView(local_view, rank)
                   : ValidateLocalView(local_view, rank)) &&
        validate_collective_batch_result(scope, batch, world_size) &&
        !batch.ok && !subset.operations.empty() &&
        subset.checkpoint == batch.checkpoint &&
        subset.batch_result_binding == compute_collective_batch_result_binding(batch) &&
        subset.challenge_transcript_binding == batch.challenge_transcript_binding &&
        subset.binding != Digest{};
    bool all_ready = false;
    Digest ready_binding{};
    if (!exchange_.AllTrue(
            NextContext(scope, AUTH_KIND_SUBSET_READY, subset.depth), local_ready,
            &all_ready, &ready_binding) || !all_ready || ready_binding == Digest{})
        return out;
    const bool strong_zero = activated &&
        mpc_.multiplication_consistency_available();
    F fingerprint(0);
    Digest sharing_binding{};
    ReferenceLinearSharingProvenance provenance;
    // Reuse the batch-global coefficient domain for every recursive subset.
    // Then the fingerprint of a parent set is exactly the sum of the
    // fingerprints of its disjoint children.  This lets localization infer
    // the right child is failing whenever the parent is known failing and the
    // left child checks clean, without a second private MPC check.
    if (!BuildFingerprint(
            scope, subset.operations, batch.challenge,
            batch.challenge_transcript_binding,
            &fingerprint, &sharing_binding,
            strong_zero ? &provenance : nullptr))
        return out;
    bool is_zero = false;
    Digest zero_binding{};
    Digest multiplication_binding{};
    if (strong_zero) {
        ReferenceMaskedZeroConsistencyContext context;
        context.sid = scope.session_id;
        context.checkpoint = scope.checkpoint;
        context.context_binding = bind_words(
            REFERENCE_RESIDUAL_STRONG_ZERO_DOMAIN,
            {sharing_binding, subset.binding, activation_binding_},
            {1ULL, subset.depth, static_cast<u64>(subset.operations.size())});
        context.multiplication_id = nonzero_digest_word(context.context_binding);
        if (context.context_binding == Digest{} ||
            !mpc_.MaskedZeroTestWithConsistency(
                provenance, context, &is_zero, &zero_binding,
                &multiplication_binding) ||
            zero_binding == Digest{} || multiplication_binding == Digest{})
            return out;
    } else if (!mpc_.MaskedZeroTest(
                   fingerprint, &is_zero, &zero_binding) ||
               zero_binding == Digest{}) {
        return out;
    }

    out.available = true;
    out.cryptographically_authenticated = true;
    out.failed = !is_zero;
    out.batch_result_binding = subset.batch_result_binding;
    out.challenge_transcript_binding = subset.challenge_transcript_binding;
    out.security_attestation_binding = subset.security_attestation_binding;
    out.subset_binding = subset.binding;
    std::vector<Digest> proof_bindings = {
        subset.binding, sharing_binding, zero_binding,
        batch.challenge_transcript_binding};
    if (strong_zero) proof_bindings.push_back(multiplication_binding);
    out.proof_commitment = bind_words(
        REFERENCE_RESIDUAL_SUBSET_DOMAIN, proof_bindings,
        {subset.depth, is_zero ? 1ULL : 0ULL,
         static_cast<u64>(subset.operations.size()),
         strong_zero ? 1ULL : 0ULL});
    if (!validate_residual_subset_check(batch, subset, out))
        return ResidualSubsetCheckResult{};
    return out;
}

CollectiveDisputeResult
ReferenceShamirResidualMpcBackend::FinalizeLocalization(
    const ObligationSet& scope,
    const BatchCheckResult& batch,
    const OperationRef& accused,
    const Digest& recursive_transcript_binding,
    const LocalResidualBatchView& local_view,
    int rank, int world_size) const {
    CollectiveDisputeResult out;
    out.checkpoint = scope.checkpoint;
    if (private_owner_activation_mode_ ||
        !EnsureTransport(scope, rank, world_size))
        return out;
    const bool activated = HasActivatedResiduals(scope);
    const bool local_ready =
        (activated
            ? ValidateActivatedLocalView(local_view, rank)
            : ValidateLocalView(local_view, rank)) &&
        validate_collective_batch_result(scope, batch, world_size) &&
        !batch.ok && recursive_transcript_binding != Digest{} &&
        accused.owner < static_cast<uint32_t>(world_size);
    bool all_ready = false;
    Digest ready_binding{};
    if (!exchange_.AllTrue(
            NextContext(scope, AUTH_KIND_LOCALIZE_READY, accused.object_id),
            local_ready, &all_ready, &ready_binding) ||
        !all_ready || ready_binding == Digest{})
        return out;

    Digest localization_source_binding{};
    Digest private_share_commitment{};
    if (activated) {
        const ActivatedResidualOperation* operation = FindActivated(accused);
        if (!operation || operation->expected == Digest{} ||
            operation->actual == Digest{} ||
            operation->expected == operation->actual ||
            operation->operation_statement_binding == Digest{} ||
            operation->source_commitment == Digest{} ||
            operation->descriptor_binding == Digest{})
            return out;

        out.available = true;
        out.cryptographically_authenticated = true;
        out.found = true;
        out.accused = accused;
        out.relation = operation->relation;
        out.kernel = operation->kernel;
        out.label = operation->label;
        out.expected = operation->expected;
        out.actual = operation->actual;
        out.operation_statement_binding =
            operation->operation_statement_binding;
        private_share_commitment = operation->source_commitment;
        localization_source_binding = bind_words(
            REFERENCE_RESIDUAL_LOCALIZE_DOMAIN,
            {activation_binding_, operation->descriptor_binding,
             operation->source_commitment, ready_binding},
            {accused.owner, accused.object_id, 1ULL});
        if (localization_source_binding == Digest{}) return out;
    } else {
        std::vector<u64> payload;
        if (rank == static_cast<int>(accused.owner)) {
            payload.assign(25, 0ULL);
            const PrivateResidualShare* share = store_.Find(accused);
            const PrivateResidualHandle* handle = find_handle(local_view, accused);
            const bool descriptor_ready =
                share && handle && validate_private_residual_share(*share) &&
                share->authenticated && share->commitment == handle->commitment &&
                share->expected != Digest{} && share->actual != Digest{} &&
                share->expected != share->actual &&
                share->operation_statement_binding != Digest{};
            if (descriptor_ready) {
                payload[0] = 1ULL;
                payload[1] = static_cast<u64>(share->relation);
                payload[2] = static_cast<u64>(share->kernel);
                payload[3] = share->label.sid;
                payload[4] = static_cast<u64>(share->label.phase);
                payload[5] = share->label.round;
                payload[6] = share->label.owner;
                payload[7] = static_cast<u64>(share->label.obligation);
                payload[8] = share->label.object_id;
                auto put_digest = [&](size_t offset, const Digest& digest) {
                    for (size_t i = 0; i < 4; ++i)
                        std::memcpy(&payload[offset + i],
                                    digest.bytes.data() + 8 * i, 8);
                };
                put_digest(9, share->expected);
                put_digest(13, share->actual);
                put_digest(17, share->operation_statement_binding);
                put_digest(21, share->commitment);
            }
        }

        std::vector<u64> received;
        if (!exchange_.BroadcastWords(
                NextContext(scope, AUTH_KIND_LOCALIZATION, accused.object_id),
                static_cast<int>(accused.owner), payload, &received,
                &localization_source_binding) ||
            received.size() != 25 || received[0] != 1ULL ||
            localization_source_binding == Digest{})
            return out;

        out.available = true;
        out.cryptographically_authenticated = true;
        out.found = true;
        out.accused = accused;
        out.relation = static_cast<RelationKind>(received[1]);
        out.kernel = static_cast<AuditRelationKernel>(received[2]);
        out.label.sid = received[3];
        out.label.phase = static_cast<Phase>(received[4]);
        out.label.round = static_cast<uint32_t>(received[5]);
        out.label.owner = static_cast<uint32_t>(received[6]);
        out.label.obligation = static_cast<Obligation>(received[7]);
        out.label.object_id = received[8];
        out.expected = digest_from_words(received, 9);
        out.actual = digest_from_words(received, 13);
        out.operation_statement_binding = digest_from_words(received, 17);
        private_share_commitment = digest_from_words(received, 21);
    }

    if (out.label.owner != accused.owner ||
        out.label.object_id != accused.object_id ||
        out.label.sid != scope.session_id ||
        out.label.phase != scope.phase ||
        (scope.exact_round && out.label.round != scope.round) ||
        out.expected == Digest{} || out.actual == Digest{} ||
        out.expected == out.actual ||
        out.operation_statement_binding == Digest{} ||
        private_share_commitment == Digest{})
        return CollectiveDisputeResult{};

    out.residual_commitment = compute_residual_commitment(
        out.label, out.relation, out.kernel, out.expected, out.actual);
    out.batch_result_binding = compute_collective_batch_result_binding(batch);
    out.public_evidence_binding = Digest{};
    out.security_attestation_binding = batch.security_attestation_binding;
    out.recursive_transcript_binding = recursive_transcript_binding;
    if (activated) {
        out.localization_commitment = bind_words(
            REFERENCE_RESIDUAL_LOCALIZE_DOMAIN,
            {out.batch_result_binding, recursive_transcript_binding,
             ready_binding, localization_source_binding,
             private_share_commitment, out.residual_commitment,
             out.operation_statement_binding, activation_binding_},
            {1ULL});
    } else {
        out.localization_commitment = bind_words(
            REFERENCE_RESIDUAL_LOCALIZE_DOMAIN,
            {out.batch_result_binding, recursive_transcript_binding,
             ready_binding, localization_source_binding,
             private_share_commitment, out.residual_commitment,
             out.operation_statement_binding});
    }
    if (!validate_collective_dispute_result(scope, batch, out))
        return CollectiveDisputeResult{};
    return out;
}


bool ReferenceShamirResidualMpcBackend::SupportsObliviousAudit(
    const ObligationSet& scope) const {
    return private_owner_activation_mode_ &&
        HasActivatedVssProvenance(scope) &&
        PrivateOwnerActivationMetadataRedacted(scope);
}

ObliviousLocalizationPublicResult
ReferenceShamirResidualMpcBackend::AuditObliviously(
    const ObligationSet& scope, const LocalResidualBatchView& local_view,
    int rank, int world_size) const {
    ObliviousLocalizationPublicResult out;
    out.checkpoint = scope.checkpoint;
    // This is a reference-only protected-selection route. It never calls the
    // legacy public subset test or exposes an OperationRef/q* to the caller.
    if (rank < 0 || world_size < 4 || rank >= world_size ||
        scope.operations.empty() || scope.operations.size() > 64 ||
        !SupportsObliviousAudit(scope) ||
        !ValidateActivatedLocalView(local_view, rank) ||
        !EnsureTransport(scope, rank, world_size))
        return out;

    const CollectiveBatchDescriptor descriptor =
        PrivateOwnerPublicBatchDescriptor(scope, local_view, rank, world_size);
    const CollectiveResidualCommitmentSet commitments =
        CommitResidualBatch(scope, descriptor, local_view, rank, world_size);
    if (!validate_participant_commitment_set(
            scope, descriptor, commitments, world_size))
        return out;

    const AuthenticatedChallengeTranscript challenge =
        DeriveJointChallenge(scope, descriptor, commitments, rank, world_size);
    if (!validate_challenge_transcript(
            scope, commitments, challenge, world_size))
        return out;

    ReferencePrivateOwnerSelectionResult selection;
    Digest activated_input_binding{};
    if (!LocalizeActivatedPrivateOwner(
            scope, local_view, commitments, challenge, rank, world_size,
            &selection, &activated_input_binding) ||
        !selection.available || selection.circuit_binding == Digest{} ||
        activated_input_binding == Digest{} ||
        selection.multiplication_count != 3 * scope.operations.size() - 2 ||
        (selection.found &&
         selection.attributed_party >= static_cast<uint32_t>(world_size)))
        return out;

    const ResidualMpcCapabilities capabilities = Capabilities();
    if (!validate_residual_mpc_capabilities(capabilities) ||
        capabilities.security_level != RobustAuditSecurityLevel::REFERENCE_PASSIVE ||
        capabilities.capability_binding == Digest{})
        return out;

    constexpr u64 OBLIVIOUS_AUDIT_BATCH_DOMAIN = 0x50563130354f4155ULL;
    constexpr u64 OBLIVIOUS_AUDIT_EVIDENCE_DOMAIN = 0x50563130354f4156ULL;
    const Digest batch_binding = bind_words(
        OBLIVIOUS_AUDIT_BATCH_DOMAIN,
        {commitments.root, challenge.transcript_digest,
         challenge.security_attestation_binding, activation_binding_,
         compute_collective_scope_binding(scope),
         capabilities.capability_binding},
        {scope.session_id, scope.checkpoint,
         static_cast<u64>(scope.operations.size())});
    const Digest evidence_binding = bind_words(
        OBLIVIOUS_AUDIT_EVIDENCE_DOMAIN,
        {batch_binding, activated_input_binding, selection.circuit_binding,
         capabilities.capability_binding},
        {selection.found ? 1ULL : 0ULL,
         selection.found ? static_cast<u64>(selection.attributed_party) : 0ULL,
         static_cast<u64>(selection.multiplication_count)});
    if (batch_binding == Digest{} || evidence_binding == Digest{})
        return out;

    out.available = true;
    out.cryptographically_authenticated = true;
    out.reference_only = true;
    out.found = selection.found;
    out.attributed_party = selection.found ? selection.attributed_party : 0;
    out.checkpoint = scope.checkpoint;
    out.batch_result_binding = batch_binding;
    out.public_evidence_binding = evidence_binding;
    return out;
}

} // namespace pvia
