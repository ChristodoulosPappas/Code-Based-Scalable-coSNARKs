#include "FoldResidualRuntimeHarness.hpp"
#include "Ed25519PrivateResidualShareAuthenticator.hpp"
#include "LiveNativeSourceRequest.hpp"
#include "RegistrationReceiptReplayLedger.hpp"

#include <mpi.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <cerrno>
#include <chrono>
#include <thread>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sstream>

namespace pvia {
namespace {

constexpr int LIVE_FOLD_DESCRIPTOR_WORDS = 21;
constexpr uint64_t RUNTIME_CAPTURE_AUTH_SCHEME_ID =
    0x5056525443415031ULL;  // PVRTCAP1
constexpr uint64_t RUNTIME_CAPTURE_AUTH_DOMAIN =
    0x5056525441555431ULL;  // PVRTAUT1
constexpr uint64_t RUNTIME_SOURCE_BINDING_DOMAIN =
    0x5056525453524331ULL;  // PVRTSRC1

struct LiveFoldDescriptor {
    u64 sid = 0;
    u64 checkpoint = 0;
    u64 owner = 0;
    u64 object_id = 0;
    u64 state_id = 0;
    u64 challenge_real = 0;
    u64 challenge_img = 0;
    u64 state_size = 0;
    u64 output_size = 0;
    Digest state_digest{};
    Digest actual_digest{};
    Digest statement_binding{};
};

void append_live_digest(const Digest& digest, std::vector<u64>* words) {
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

Digest read_live_digest(const std::vector<u64>& words, size_t offset) {
    Digest digest{};
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(digest.bytes.data() + 8 * i, &words[offset + i], 8);
    return digest;
}

// Development capture identity only. This deterministic binding helps the
// source adapter detect local record substitution; it is not an external
// signature, MAC, or proof of execution truth.
bool wait_for_regular_receipt_file(
    const std::string& path, uint64_t wait_ms) {
    if(path.empty() || wait_ms>120000) return false;
    const auto deadline=std::chrono::steady_clock::now()+
        std::chrono::milliseconds(wait_ms);
    for(;;) {
        struct stat st{};
        if(::lstat(path.c_str(),&st)==0)
            return S_ISREG(st.st_mode);
        if(errno!=ENOENT) return false;
        if(std::chrono::steady_clock::now()>=deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

Digest runtime_capture_auth_binding(const AuditStateView& state) {
    std::vector<u64> words = {
        RUNTIME_CAPTURE_AUTH_DOMAIN, state.id, state.label.sid,
        static_cast<u64>(state.label.phase), state.label.round,
        state.label.owner, state.label.object_id};
    append_live_digest(state.digest, &words);
    return hash_words(words);
}

} // namespace


FoldResidualRuntimeHarness::FoldResidualRuntimeHarness(
    bool enable_reference_mpc_activation,
    bool delegate_runtime_debug_checks)
    : backend_(shares_),
      sp1_sumcheck_proof_provider_(),
      sumcheck_backend_(shares_, nullptr, &sp1_sumcheck_proof_provider_),
      sumcheck_evaluator_(sumcheck_backend_),
      reference_mpc_activation_enabled_(enable_reference_mpc_activation),
      delegate_runtime_debug_checks_(delegate_runtime_debug_checks) {}

void FoldResidualRuntimeHarness::OnImportStateMetadata(
    const AuditStateView& state) {
    states_.RegisterMetadata(state);
}

void FoldResidualRuntimeHarness::OnBindPrivateState(
    const AuditStateView& state, const std::vector<F>& local_share) {
    if (!states_.BindPrivateState(state, local_share)) return;
    // The real runtime has supplied the local state bytes. Attach a stable
    // local capture identity so the existing registration-source reader can
    // re-check the exact state. This is intentionally not called production
    // authentication.
    const Digest binding = runtime_capture_auth_binding(state);
    if (binding != Digest{})
        states_.BindAuthentication(
            state, RUNTIME_CAPTURE_AUTH_SCHEME_ID, binding);
}

void FoldResidualRuntimeHarness::OnBindPrivateStateSegments(
    const AuditStateView& state, const std::vector<F>& local_share,
    const std::vector<size_t>& segment_lengths) {
    if (!states_.BindPrivateStateSegments(state, local_share, segment_lengths))
        return;
    const Digest binding = runtime_capture_auth_binding(state);
    if (binding != Digest{})
        states_.BindAuthentication(state, RUNTIME_CAPTURE_AUTH_SCHEME_ID, binding);
}

void FoldResidualRuntimeHarness::OnRegisterOperation(
    const AuditOperationView& operation) {
    materials_.RegisterOperation(operation);
}

void FoldResidualRuntimeHarness::OnActivateOperation(
    const AuditOperationView& operation) {
    materials_.ActivateOperation(operation);
}
void FoldResidualRuntimeHarness::OnBindPrivateFieldOperation(
    const AuditOperationView& operation, AuditPrivatePayloadKind kind,
    AuditPayloadStage stage, const std::vector<F>& values) {
    materials_.BindPrivateField(operation, kind, stage, values);
}

void FoldResidualRuntimeHarness::OnBindOperationStateDependencies(
    const AuditOperationView& operation,
    const std::vector<StateId>& state_ids) {
    materials_.BindStateDependencies(operation, state_ids);
}

void FoldResidualRuntimeHarness::OnBindPublicFieldAux(
    const AuditOperationView& operation, AuditPublicAuxKind kind,
    const std::vector<F>& values) {
    materials_.BindPublicFieldAux(operation, kind, values);
}

void FoldResidualRuntimeHarness::OnFinalizePrivateRelation(
    const AuditOperationView& operation) {
    if (operation.kernel == AuditRelationKernel::FOLD_RS) {
        ++fold_operations_;
        const PrivateOperationMaterial* material =
            materials_.Find(operation.ref);
        if (!material || !materials_.ReadyForResidual(operation.ref)) {
            ++invalid_material_;
            return;
        }
        for (StateId state_id : material->state_dependencies) {
            if (!states_.VerifyDigest(state_id)) {
                ++invalid_material_;
                return;
            }
        }
        KernelResidualContext context{operation, *material, states_};
        const PrivateResidualHandle handle = backend_.EvaluateKernel(context);
        const PrivateResidualShare* share = shares_.Find(operation.ref);
        if (!handle.available || handle.authenticated || !share ||
            !validate_private_residual_share(*share) || share->authenticated) {
            ++invalid_material_;
            return;
        }
        bool zero = true;
        for (const F& value : share->values) {
            if (value != F(0)) {
                zero = false;
                break;
            }
        }
        if (zero) ++zero_residuals_;
        else ++nonzero_residuals_;
        materials_.MarkFinalized(operation.ref);
        if (std::find(fold_refs_.begin(), fold_refs_.end(), operation.ref) ==
            fold_refs_.end())
            fold_refs_.push_back(operation.ref);
        return;
    }

    if (!sumcheck_evaluator_.Supports(operation.kernel)) return;
    ++native_sumcheck_operations_;
    switch (operation.kernel) {
        case AuditRelationKernel::COSUMCHECK_ZERO:
            ++native_sumcheck_kernel_counts_[0]; break;
        case AuditRelationKernel::COSUMCHECK_QUADRATIC:
            ++native_sumcheck_kernel_counts_[1]; break;
        case AuditRelationKernel::COSUMCHECK_BATCH:
            ++native_sumcheck_kernel_counts_[2]; break;
        case AuditRelationKernel::DSC_QUADRATIC:
            ++native_sumcheck_kernel_counts_[3]; break;
        case AuditRelationKernel::DSC_CUBIC:
            ++native_sumcheck_kernel_counts_[4]; break;
        default: break;
    }
    const PrivateOperationMaterial* material = materials_.Find(operation.ref);
    if (!material || !materials_.ReadyForResidual(operation.ref)) {
        ++native_sumcheck_invalid_material_;
        ++native_sumcheck_not_ready_;
        return;
    }
    for (StateId state_id : material->state_dependencies) {
        if (!states_.VerifyDigest(state_id)) {
            ++native_sumcheck_invalid_material_;
            ++native_sumcheck_state_invalid_;
            return;
        }
    }
    KernelResidualContext context{operation, *material, states_};
    if (!validate_kernel_residual_material(context)) {
        ++native_sumcheck_invalid_material_;
        ++native_sumcheck_relation_invalid_;
        return;
    }
    std::vector<F> recomputed;
    if (!recompute_native_sumcheck_polynomial(context, &recomputed)) {
        ++native_sumcheck_invalid_material_;
        ++native_sumcheck_reconstruction_invalid_;
        return;
    }
    if (recomputed != material->field_input) {
        ++native_sumcheck_invalid_material_;
        ++native_sumcheck_input_mismatch_;
        return;
    }
    const PrivateResidualHandle handle = sumcheck_evaluator_.Evaluate(context);
    const PrivateResidualShare* share = shares_.Find(operation.ref);
    if (!handle.available || handle.authenticated || !share ||
        !validate_private_residual_share(*share) || share->authenticated) {
        ++native_sumcheck_invalid_material_;
        ++native_sumcheck_other_invalid_;
        return;
    }
    bool zero = true;
    for (const F& value : share->values) {
        if (value != F(0)) {
            zero = false;
            break;
        }
    }
    if (zero) ++native_sumcheck_zero_residuals_;
    else ++native_sumcheck_nonzero_residuals_;
    materials_.MarkFinalized(operation.ref);
}

void FoldResidualRuntimeHarness::OnSealCheckpoint(
    const AuditCheckpointView& checkpoint) {
    if (!checkpoint.sealed || checkpoint.phase != Phase::FOLD)
        return;
    auto existing = std::find_if(
        sealed_checkpoints_.begin(), sealed_checkpoints_.end(),
        [&checkpoint](const AuditCheckpointView& value) {
            return value.id == checkpoint.id;
        });
    if (existing == sealed_checkpoints_.end())
        sealed_checkpoints_.push_back(checkpoint);
    else
        *existing = checkpoint;

    if (!reference_mpc_activation_enabled_) return;
    int rank = -1;
    int world_size = 0;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);
    if (!ActivateReferenceMpcCheckpoint(checkpoint, rank, world_size))
        ++reference_mpc_activation_failures_;
}

const AuditCheckpointView* FoldResidualRuntimeHarness::FindSealedCheckpoint(
    CheckpointId checkpoint_id) const {
    const auto found = std::find_if(
        sealed_checkpoints_.begin(), sealed_checkpoints_.end(),
        [checkpoint_id](const AuditCheckpointView& checkpoint) {
            return checkpoint.id == checkpoint_id && checkpoint.sealed;
        });
    return found == sealed_checkpoints_.end() ? nullptr : &*found;
}

bool FoldResidualRuntimeHarness::CaptureNativeFoldStatementForRef(
    const OperationRef& ref,
    RegistrationConsistencyStatement* output) const {
    if (!output) return false;
    const PrivateOperationMaterial* material = materials_.Find(ref);
    if (!material || !material->finalized ||
        !material->has_field_output ||
        material->state_dependencies.size() != 1)
        return false;
    const AuditOperationView& native = material->operation;
    if (native.kernel != AuditRelationKernel::FOLD_RS ||
        native.label.phase != Phase::FOLD ||
        native.label.obligation != Obligation::FOLD ||
        native.relation != RelationKind::FOLDING ||
        !native.active || native.observed_remote ||
        native.checkpoint == 0)
        return false;
    const StateId state_id = material->state_dependencies.front();
    const PrivateStateMaterial* state = states_.Find(state_id);
    const AuditCheckpointView* checkpoint =
        FindSealedCheckpoint(native.checkpoint);
    if (!state || !state->has_private_share ||
        !state->has_authentication ||
        !states_.VerifyDigest(state_id) ||
        !states_.VerifyAuthentication(state_id) ||
        state->state.label.sid != native.label.sid ||
        state->state.label.owner != native.ref.owner ||
        !checkpoint ||
        std::count(checkpoint->operations.begin(),
                   checkpoint->operations.end(), native.ref) != 1)
        return false;

    const std::vector<F>* challenge = nullptr;
    size_t challenge_count = 0;
    for (const auto& aux : material->field_aux) {
        if (aux.first != AuditPublicAuxKind::FOLD_CHALLENGE) continue;
        if (aux.second.size() != 1) {
            challenge_count = 2;
            break;
        }
        challenge = &aux.second;
        ++challenge_count;
    }
    if (challenge_count != 1 || !challenge) return false;

    RegistrationConsistencyStatement statement{};
    statement.sid = native.label.sid;
    statement.checkpoint = native.checkpoint;
    statement.ref = native.ref;
    statement.kernel = native.kernel;
    statement.state_element_count = state->local_share.size();
    statement.output_element_count = material->field_output.size();
    statement.public_state_digest = state->state.digest;
    statement.public_actual_digest = native.actual;
    statement.public_challenge_binding = hash_field_vector(*challenge);
    statement.native_context.native_state_id = state_id;
    statement.native_context.authentication_scheme_id =
        state->authentication_scheme_id;
    statement.native_context.authentication_binding =
        state->authentication_binding;
    statement.native_context.predecessor_root = native.predecessor_root;
    statement.native_context.checkpoint_root = checkpoint->root;
    statement.operation_statement_binding = native.relation_statement;

    // This is a domain-separated pre-VSS source binding, not a claim that a
    // zero-knowledge sharing transcript has already been produced.
    std::vector<u64> source_words = {
        RUNTIME_SOURCE_BINDING_DOMAIN, statement.sid,
        statement.checkpoint, statement.ref.owner,
        statement.ref.object_id, state_id,
        statement.native_context.authentication_scheme_id,
        static_cast<u64>(statement.state_element_count),
        static_cast<u64>(statement.output_element_count)};
    append_live_digest(statement.public_state_digest, &source_words);
    append_live_digest(statement.public_actual_digest, &source_words);
    append_live_digest(statement.public_challenge_binding, &source_words);
    append_live_digest(statement.operation_statement_binding, &source_words);
    append_live_digest(statement.native_context.predecessor_root,
                       &source_words);
    append_live_digest(statement.native_context.checkpoint_root,
                       &source_words);
    append_live_digest(statement.native_context.authentication_binding,
                       &source_words);
    statement.sharing_transcript_binding = hash_words(source_words);
    statement.statement_binding =
        compute_registration_consistency_statement_binding(statement);
    if (!validate_registration_consistency_statement(statement)) return false;
    *output = statement;
    return true;
}

bool FoldResidualRuntimeHarness::CaptureLatestNativeFoldStatement(
    RegistrationConsistencyStatement* output) const {
    if (!output) return false;
    for (auto ref = fold_refs_.rbegin(); ref != fold_refs_.rend(); ++ref) {
        if (CaptureNativeFoldStatementForRef(*ref, output)) return true;
    }
    return false;
}

bool FoldResidualRuntimeHarness::CaptureNativeFoldCapturesForCheckpoint(
    CheckpointId checkpoint_id,
    std::vector<NativeFoldSourceCapture>* output) const {
    if (!output) return false;
    output->clear();
    const AuditCheckpointView* checkpoint = FindSealedCheckpoint(checkpoint_id);
    if (!checkpoint || checkpoint->root == Digest{}) return false;

    std::vector<OperationRef> refs;
    for (const auto& ref : fold_refs_) {
        const PrivateOperationMaterial* material = materials_.Find(ref);
        if (material && material->operation.checkpoint == checkpoint_id &&
            std::count(checkpoint->operations.begin(),
                       checkpoint->operations.end(), ref) == 1)
            refs.push_back(ref);
    }
    std::sort(refs.begin(), refs.end(),
        [](const OperationRef& a, const OperationRef& b) {
            if (a.owner != b.owner) return a.owner < b.owner;
            return a.object_id < b.object_id;
        });
    refs.erase(std::unique(refs.begin(), refs.end(),
        [](const OperationRef& a, const OperationRef& b) {
            return a.owner == b.owner && a.object_id == b.object_id;
        }), refs.end());

    std::vector<NativeFoldSourceCapture> captures;
    for (const auto& ref : refs) {
        NativeFoldSourceCapture item{};
        if (!CaptureNativeFoldStatementForRef(ref, &item.statement) ||
            !this->capture(item.statement, &item.snapshot) ||
            !still_matches(item.statement, item.snapshot))
            return false;
        captures.push_back(std::move(item));
    }
    if (captures.empty()) return false;
    *output = std::move(captures);
    return true;
}

bool FoldResidualRuntimeHarness::ReadNativeFoldCheckpoint(
    CheckpointId checkpoint_id,
    AuditCheckpointView* output) const {
    const AuditCheckpointView* checkpoint =
        FindSealedCheckpoint(checkpoint_id);
    if (!checkpoint || !output || checkpoint->root == Digest{}) return false;
    *output = *checkpoint;
    return true;
}

bool FoldResidualRuntimeHarness::VerifyCapturedNativeFoldResidual(
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeConsumedSnapshot& snapshot) const {
    if (statement.kernel != AuditRelationKernel::FOLD_RS ||
        !still_matches(statement, snapshot) ||
        snapshot.state_values.empty() || snapshot.actual_output.empty())
        return false;
    const PrivateResidualShare* share = shares_.Find(statement.ref);
    const PrivateOperationMaterial* operation = materials_.Find(statement.ref);
    const PrivateStateMaterial* state =
        states_.Find(statement.native_context.native_state_id);
    if (!share || !operation || !state ||
        !operation->finalized || !operation->has_field_output ||
        !share->computation_valid ||
        !validate_private_residual_share(*share) ||
        share->ref != statement.ref ||
        share->checkpoint != statement.checkpoint ||
        share->kernel != AuditRelationKernel::FOLD_RS ||
        share->relation != RelationKind::FOLDING ||
        share->source_state_id != statement.native_context.native_state_id ||
        share->source_state_owner != statement.ref.owner ||
        share->source_state_digest != statement.public_state_digest ||
        share->source_state_authentication_scheme_id !=
            statement.native_context.authentication_scheme_id ||
        share->source_state_authentication_binding !=
            statement.native_context.authentication_binding ||
        share->operation_statement_binding !=
            statement.operation_statement_binding ||
        share->public_aux_root != operation->operation.public_aux_root ||
        share->actual != statement.public_actual_digest ||
        operation->operation.ref != statement.ref ||
        operation->operation.checkpoint != statement.checkpoint ||
        operation->field_output != snapshot.actual_output ||
        state->local_share != snapshot.state_values ||
        operation->field_aux.size() != 1 ||
        operation->field_aux.front().first !=
            AuditPublicAuxKind::FOLD_CHALLENGE ||
        operation->field_aux.front().second.size() != 1 ||
        operation->field_aux.front().second[0] != snapshot.public_challenge)
        return false;

    std::vector<F> expected;
    if (!recompute_fold_rs_output(
            snapshot.state_values, snapshot.public_challenge, &expected) ||
        expected.size() != snapshot.actual_output.size() ||
        expected.size() != share->values.size() ||
        share->expected != hash_field_vector(expected))
        return false;
    for (size_t i = 0; i < expected.size(); ++i)
        if (share->values[i] != snapshot.actual_output[i] - expected[i])
            return false;
    // The residual vector is still unauthenticated unless a separate MPC
    // residual authenticator proves its origin; never upgrade that status.
    return true;
}

bool FoldResidualRuntimeHarness::ReadVerifiedNativeResidualBindings(
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeConsumedSnapshot& snapshot,
    Digest* computation_binding,
    Digest* residual_commitment) const {
    if (!computation_binding || !residual_commitment ||
        !VerifyCapturedNativeFoldResidual(statement,snapshot))
        return false;
    const PrivateResidualShare* share=shares_.Find(statement.ref);
    if (!share || share->authenticated ||
        share->computation_binding==Digest{} ||
        share->commitment==Digest{})
        return false;
    *computation_binding=share->computation_binding;
    *residual_commitment=share->commitment;
    return true;
}

bool FoldResidualRuntimeHarness::ReadAuthenticatedNativeResidualRoot(
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeConsumedSnapshot& snapshot,
    Digest* local_residual_root) const {
    return ReadAuthenticatedNativeResidualRoot(
        statement, snapshot, local_residual_root, nullptr);
}

bool FoldResidualRuntimeHarness::ReadAuthenticatedNativeResidualRoot(
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeConsumedSnapshot& snapshot,
    Digest* local_residual_root,
    Digest* residual_commitment) const {
    if (!local_residual_root ||
        !VerifyCapturedNativeFoldResidual(statement, snapshot))
        return false;
    const PrivateResidualShare* share = shares_.Find(statement.ref);
    if (!share || !share->authenticated ||
        !validate_private_residual_share(*share) ||
        share->ref != statement.ref ||
        share->checkpoint != statement.checkpoint ||
        share->source_state_id != statement.native_context.native_state_id ||
        share->source_state_owner != statement.ref.owner ||
        share->source_state_digest != statement.public_state_digest ||
        share->source_state_authentication_scheme_id !=
            statement.native_context.authentication_scheme_id ||
        share->source_state_authentication_binding !=
            statement.native_context.authentication_binding ||
        share->operation_statement_binding !=
            statement.operation_statement_binding ||
        share->computation_binding !=
            compute_private_residual_computation_binding(*share) ||
        share->commitment == Digest{})
        return false;

    PrivateResidualHandle handle{};
    handle.ref = share->ref;
    handle.label = share->label;
    handle.relation = share->relation;
    handle.kernel = share->kernel;
    handle.checkpoint = share->checkpoint;
    handle.commitment = share->commitment;
    handle.available = true;
    handle.authenticated = true;
    const Digest root = compute_private_residual_local_handle_root({handle});
    if (root == Digest{}) return false;
    *local_residual_root = root;
    if (residual_commitment) *residual_commitment = share->commitment;
    return true;
}

bool FoldResidualRuntimeHarness::VerifyCapturedNativeFoldResidualReceipt(
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeConsumedSnapshot& snapshot,
    const std::string& receipt_file,
    const std::string& issuer_public_key_file,
    const std::string& replay_ledger_file,
    uint64_t expected_issuer_id,
    uint64_t minimum_accepted_sequence,
    uint64_t receipt_wait_ms) const {
    if(!VerifyCapturedNativeFoldResidual(statement,snapshot) ||
       receipt_file.empty() || issuer_public_key_file.empty() ||
       replay_ledger_file.empty() || !expected_issuer_id ||
       !minimum_accepted_sequence || receipt_wait_ms>120000 ||
       statement.native_context.authentication_scheme_id!=
           RUNTIME_CAPTURE_AUTH_SCHEME_ID)
        return false;
    const PrivateResidualShare* share=shares_.Find(statement.ref);
    if(!share || share->authenticated ||
       share->source_state_authentication_scheme_id!=
           RUNTIME_CAPTURE_AUTH_SCHEME_ID)
        return false;
    PrivateResidualProvenanceReceipt receipt{};
    std::array<uint8_t,32> pinned_key{};
    if(!wait_for_regular_receipt_file(receipt_file,receipt_wait_ms) ||
       !read_private_residual_provenance_receipt_file(
            receipt_file,&receipt) ||
       !read_private_residual_provenance_public_key_file(
            issuer_public_key_file,&pinned_key) ||
       receipt.issuer_id!=expected_issuer_id ||
       receipt.sequence<minimum_accepted_sequence ||
       receipt.scheme_id!=RUNTIME_CAPTURE_AUTH_SCHEME_ID ||
       receipt.computation_binding!=share->computation_binding ||
       !private_residual_provenance_sequence_available(
            replay_ledger_file,receipt.issuer_id,receipt.sequence))
        return false;
    // This ephemeral verifier checks signature and all local bindings without
    // consuming the durable sequence or mutating the stored residual. The
    // MPI caller performs a collective preflight before any rank commits.
    Ed25519PrivateResidualShareAuthenticator verifier(
        RUNTIME_CAPTURE_AUTH_SCHEME_ID,expected_issuer_id,
        minimum_accepted_sequence,pinned_key,{receipt});
    PrivateResidualAuthenticationArtifact artifact{};
    return verifier.Authenticate(*share,&artifact) &&
        validate_private_residual_authentication_artifact(*share,artifact) &&
        verify_private_residual_authentication_artifact_signature(
            *share,artifact,pinned_key,expected_issuer_id,
            minimum_accepted_sequence);
}

bool FoldResidualRuntimeHarness::AuthenticateCapturedNativeFoldResidual(
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeConsumedSnapshot& snapshot,
    const std::string& receipt_file,
    const std::string& issuer_public_key_file,
    const std::string& replay_ledger_file,
    uint64_t expected_issuer_id,
    uint64_t minimum_accepted_sequence,
    uint64_t receipt_wait_ms) {
    if(!VerifyCapturedNativeFoldResidual(statement,snapshot) ||
       receipt_file.empty() || issuer_public_key_file.empty() ||
       receipt_wait_ms>120000 ||
       replay_ledger_file.empty() || !expected_issuer_id ||
       !minimum_accepted_sequence ||
       statement.native_context.authentication_scheme_id!=
           RUNTIME_CAPTURE_AUTH_SCHEME_ID)
        return false;
    const PrivateResidualShare* current=shares_.Find(statement.ref);
    if(!current || current->authenticated ||
       current->source_state_authentication_scheme_id!=
           RUNTIME_CAPTURE_AUTH_SCHEME_ID)
        return false;
    PrivateResidualProvenanceReceipt receipt{};
    std::array<uint8_t,32> pinned_key{};
    if(!wait_for_regular_receipt_file(receipt_file,receipt_wait_ms) ||
       !read_private_residual_provenance_receipt_file(
            receipt_file,&receipt) ||
       !read_private_residual_provenance_public_key_file(
            issuer_public_key_file,&pinned_key))
        return false;
    Ed25519PrivateResidualShareAuthenticator authenticator(
        RUNTIME_CAPTURE_AUTH_SCHEME_ID,expected_issuer_id,
        minimum_accepted_sequence,pinned_key,{receipt},replay_ledger_file);
    if(!backend_.AuthenticateStoredShare(statement.ref,authenticator))
        return false;
    const PrivateResidualShare* authenticated=shares_.Find(statement.ref);
    return authenticated && authenticated->authenticated &&
        validate_private_residual_share(*authenticated) &&
        verify_private_residual_authentication_artifact_signature(
            *authenticated,authenticated->authentication,pinned_key,
            expected_issuer_id,minimum_accepted_sequence);
}

bool FoldResidualRuntimeHarness::VerifyCapturedNativeFoldBatchPinReceipt(
    CheckpointId checkpoint_id,
    uint32_t local_owner,
    const std::string& receipt_file,
    const std::array<uint8_t, 32>& independently_pinned_issuer_key,
    uint64_t expected_issuer_id,
    uint64_t minimum_accepted_sequence,
    const std::string& replay_ledger_directory,
    size_t* verified_operation_count,
    bool* replay_rejected) const {
    if (verified_operation_count) *verified_operation_count = 0;
    if (replay_rejected) *replay_rejected = false;
    if (local_owner >= 64 || receipt_file.empty() ||
        replay_ledger_directory.empty() || !expected_issuer_id ||
        !minimum_accepted_sequence)
        return false;

    std::vector<NativeFoldSourceCapture> captures;
    if (!CaptureNativeFoldCapturesForCheckpoint(checkpoint_id, &captures) ||
        captures.empty())
        return false;
    AuditCheckpointView checkpoint{};
    if (!ReadNativeFoldCheckpoint(checkpoint_id, &checkpoint)) return false;

    std::vector<RegistrationConsistencyStatement> statements;
    statements.reserve(captures.size());
    for (const auto& item : captures) {
        if (item.statement.ref.owner != local_owner ||
            item.statement.checkpoint != checkpoint_id ||
            !VerifyCapturedNativeFoldResidual(item.statement, item.snapshot))
            return false;
        statements.push_back(item.statement);
    }
    const ObligationSet scope =
        BuildLiveNativeSourcePinScope(statements, checkpoint);
    if (scope.operations.size() != captures.size() ||
        scope.operations.empty())
        return false;

    LocalResidualBatchView local_view{};
    local_view.scope = scope;
    local_view.local_owner = local_owner;
    std::vector<LiveNativeSourceOperationBinding> bindings;
    bindings.reserve(captures.size());
    for (const auto& item : captures) {
        const PrivateResidualShare* share = shares_.Find(item.statement.ref);
        if (!share || !share->authenticated ||
            !validate_private_residual_share(*share) ||
            share->commitment == Digest{} ||
            share->checkpoint != checkpoint_id ||
            share->ref != item.statement.ref ||
            share->source_state_id !=
                item.statement.native_context.native_state_id ||
            share->source_state_digest != item.statement.public_state_digest ||
            share->source_state_authentication_scheme_id !=
                item.statement.native_context.authentication_scheme_id ||
            share->source_state_authentication_binding !=
                item.statement.native_context.authentication_binding ||
            share->operation_statement_binding !=
                item.statement.operation_statement_binding ||
            share->computation_binding !=
                compute_private_residual_computation_binding(*share))
            return false;

        PrivateResidualHandle handle{};
        handle.ref = share->ref;
        handle.label = share->label;
        handle.relation = share->relation;
        handle.kernel = share->kernel;
        handle.checkpoint = share->checkpoint;
        handle.commitment = share->commitment;
        handle.available = true;
        handle.authenticated = true;
        local_view.handles.push_back(handle);

        LiveNativeSourceOperationBinding binding{};
        if (!BuildLiveNativeSourceOperationBinding(
                item.statement, item.snapshot, checkpoint, &binding))
            return false;
        bindings.push_back(binding);
    }
    std::sort(local_view.handles.begin(), local_view.handles.end(),
        [](const PrivateResidualHandle& a, const PrivateResidualHandle& b) {
            if (a.ref.owner != b.ref.owner) return a.ref.owner < b.ref.owner;
            return a.ref.object_id < b.ref.object_id;
        });
    std::sort(bindings.begin(), bindings.end(),
        [](const LiveNativeSourceOperationBinding& a,
           const LiveNativeSourceOperationBinding& b) {
            if (a.ref.owner != b.ref.owner) return a.ref.owner < b.ref.owner;
            return a.ref.object_id < b.ref.object_id;
        });
    local_view.complete_for_owner =
        local_view.handles.size() == scope.operations.size();
    local_view.all_authenticated = local_view.complete_for_owner &&
        std::all_of(local_view.handles.begin(), local_view.handles.end(),
            [](const PrivateResidualHandle& handle) {
                return handle.available && handle.authenticated;
            });
    local_view.commitment_root =
        compute_private_residual_local_handle_root(local_view.handles);
    if (!local_view.complete_for_owner || !local_view.all_authenticated ||
        local_view.commitment_root == Digest{})
        return false;

    LiveNativeSourceBatchPinReceipt receipt{};
    if (!read_live_native_source_batch_pin_receipt_file(
            receipt_file, &receipt) ||
        !verify_live_native_source_batch_pin_receipt(
            scope, local_owner, local_view, bindings, receipt,
            independently_pinned_issuer_key, expected_issuer_id,
            minimum_accepted_sequence))
        return false;

    RegistrationReceiptReplayLedger ledger(replay_ledger_directory);
    if (!ledger.ConsumeNativeSourceBatchPinOnce(receipt)) return false;
    if (verified_operation_count)
        *verified_operation_count = local_view.handles.size();
    if (replay_rejected)
        *replay_rejected = !ledger.ConsumeNativeSourceBatchPinOnce(receipt);
    return !replay_rejected || *replay_rejected;
}

bool FoldResidualRuntimeHarness::AuthenticatedNativeFoldResidualExactZero(
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeConsumedSnapshot& snapshot,
    bool* exact_zero) const {
    if (!exact_zero) return false;
    *exact_zero = false;
    if (!VerifyCapturedNativeFoldResidual(statement, snapshot))
        return false;
    const PrivateResidualShare* share = shares_.Find(statement.ref);
    if (!share || !share->authenticated || share->values.empty() ||
        !validate_private_residual_share(*share) ||
        share->kernel != AuditRelationKernel::FOLD_RS ||
        share->commitment == Digest{})
        return false;
    bool zero = true;
    for (const F& value : share->values) {
        if (value != F(0)) {
            zero = false;
            break;
        }
    }
    *exact_zero = zero;
    return true;
}

bool FoldResidualRuntimeHarness::AuthenticatedNativeFoldResidualMpcZero(
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeConsumedSnapshot& snapshot,
    bool* mpc_zero, Digest* mpc_transcript_binding) const {
    if (!mpc_zero || !mpc_transcript_binding) return false;
    *mpc_zero = false;
    *mpc_transcript_binding = Digest{};
    if (!VerifyCapturedNativeFoldResidual(statement, snapshot) ||
        statement.checkpoint == 0)
        return false;

    const ReferenceShamirBatchResult* matched_batch = nullptr;
    const ReferenceShamirAuditSession* matched_session = nullptr;
    size_t matches = 0;
    for (size_t i = 0; i < reference_mpc_batches_.size(); ++i) {
        if (reference_mpc_batches_[i].checkpoint != statement.checkpoint)
            continue;
        ++matches;
        matched_batch = &reference_mpc_batches_[i];
        if (i < reference_mpc_sessions_.size())
            matched_session = reference_mpc_sessions_[i].get();
    }
    if (matches != 1 || !matched_batch || !matched_session ||
        !matched_session->sealed() || !matched_batch->available ||
        matched_batch->checkpoint != statement.checkpoint ||
        matched_batch->registration_binding == Digest{} ||
        matched_batch->registration_binding !=
            matched_session->registration_binding() ||
        !matched_session->ContainsOperationBinding(
            statement.ref, statement.operation_statement_binding,
            statement.public_state_digest, statement.public_actual_digest) ||
        matched_batch->operation_count == 0 ||
        matched_batch->operation_count != matched_session->operation_count() ||
        matched_batch->public_coin_transcript_binding == Digest{} ||
        matched_batch->challenge_binding == Digest{} ||
        matched_batch->opening_transcript_binding == Digest{})
        return false;

    // Bind the MPC verdict to the complete native FOLD_RS capture set for
    // this checkpoint, not merely to a caller-supplied operation identifier.
    std::vector<NativeFoldSourceCapture> captures;
    // Captures are owner-local, whereas the MPC batch count is global.
    // Require this local source to be represented and reject impossible
    // local/global count relationships without assuming equal work per owner.
    if (!CaptureNativeFoldCapturesForCheckpoint(
            statement.checkpoint, &captures) ||
        captures.empty() ||
        captures.size() > matched_batch->operation_count)
        return false;
    const auto captured_statement = std::find_if(
        captures.begin(), captures.end(),
        [&](const NativeFoldSourceCapture& capture) {
            return capture.statement.ref == statement.ref &&
                capture.statement.operation_statement_binding ==
                    statement.operation_statement_binding &&
                capture.statement.statement_binding ==
                    statement.statement_binding;
        });
    if (captured_statement == captures.end()) return false;

    constexpr u64 NATIVE_FOLD_MPC_GATE_DOMAIN =
        0x50564e464d504731ULL; // PVNFMPG1
    std::vector<u64> words = {
        NATIVE_FOLD_MPC_GATE_DOMAIN,
        statement.checkpoint,
        statement.ref.owner,
        statement.ref.object_id,
        static_cast<u64>(matched_batch->operation_count),
        matched_batch->clean ? 1ULL : 0ULL};
    append_live_digest(matched_batch->registration_binding, &words);
    append_live_digest(
        matched_batch->public_coin_transcript_binding, &words);
    append_live_digest(matched_batch->challenge_binding, &words);
    append_live_digest(matched_batch->opening_transcript_binding, &words);
    append_live_digest(statement.statement_binding, &words);
    const Digest binding = hash_words(words);
    if (binding == Digest{}) return false;

    *mpc_zero = matched_batch->clean;
    *mpc_transcript_binding = binding;
    return true;
}

bool FoldResidualRuntimeHarness::ExportAuthenticatedNativeFoldResidualRlcSingle(
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeConsumedSnapshot& snapshot,
    const std::string& private_output_path) const {
    if (private_output_path.empty() ||
        !VerifyCapturedNativeFoldResidual(statement, snapshot))
        return false;
    const PrivateResidualShare* share = shares_.Find(statement.ref);
    if (!share || !share->authenticated || share->values.empty() ||
        !validate_private_residual_share(*share) ||
        share->kernel != AuditRelationKernel::FOLD_RS ||
        share->commitment == Digest{})
        return false;
    F total(0);
    F weight(1);
    bool exact_zero = true;
    for (const F& value : share->values) {
        total += value * weight;
        weight = weight * F(65537) + F(17);
        if (value != F(0)) exact_zero = false;
    }
    const char digits[] = "0123456789abcdef";
    std::string commitment_hex;
    for (uint8_t b : share->commitment.bytes) {
        commitment_hex.push_back(digits[b >> 4]);
        commitment_hex.push_back(digits[b & 15]);
    }
    std::ostringstream content;
    content << "PVIA_REAL_NATIVE_RESIDUAL_RLC_SINGLE_V1\n";
    content << "checkpoint " << statement.checkpoint << "\n";
    content << "owner " << statement.ref.owner << "\n";
    content << "object_id " << statement.ref.object_id << "\n";
    content << "commitment " << commitment_hex << "\n";
    std::string computation_hex;
    for (uint8_t b : share->computation_binding.bytes) {
        computation_hex.push_back(digits[b >> 4]);
        computation_hex.push_back(digits[b & 15]);
    }
    content << "computation_binding " << computation_hex << "\n";
    content << "output_count " << share->values.size() << "\n";
    content << "rlc " << total.real << " " << total.img << "\n";
    content << "exact_zero " << (exact_zero ? 1 : 0) << "\n";
    const std::string payload = content.str();
    const int fd = ::open(private_output_path.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    bool ok = true;
    size_t pos = 0;
    while (pos < payload.size()) {
        const ssize_t count = ::write(
            fd, payload.data() + pos, payload.size() - pos);
        if (count <= 0) { ok = false; break; }
        pos += static_cast<size_t>(count);
    }
    if (ok) ok = ::fsync(fd) == 0;
    if (::close(fd) != 0) ok = false;
    if (!ok) ::unlink(private_output_path.c_str());
    return ok;
}

bool FoldResidualRuntimeHarness::ExportAuthenticatedNativeFoldResidualRlc(
    CheckpointId checkpoint_id, uint32_t local_owner,
    const std::string& private_output_path) const {
    // This primitive is only called from the non-strict signed dual-FOLD
    // observer after ALL four owner-local PVNPIN02 checks have succeeded.
    // Export refusal is fail-closed. Never emit these private values in logs.
    if (private_output_path.empty() || local_owner >= 4 ||
        checkpoint_id == 0) return false;
    std::vector<NativeFoldSourceCapture> captures;
    if (!CaptureNativeFoldCapturesForCheckpoint(
            checkpoint_id, &captures) || captures.size() != 2)
        return false;
    std::ostringstream content;
    content << "PVIA_REAL_NATIVE_RESIDUAL_RLC_V1\n";
    content << "checkpoint " << checkpoint_id << "\n";
    content << "owner " << local_owner << "\n";
    content << "operation_count 2\n";
    for (const auto& capture : captures) {
        const auto& ref = capture.statement.ref;
        const PrivateResidualShare* share = shares_.Find(ref);
        if (ref.owner != local_owner || !share ||
            !share->authenticated || share->values.empty() ||
            !validate_private_residual_share(*share) ||
            !VerifyCapturedNativeFoldResidual(
                capture.statement, capture.snapshot) ||
            share->commitment == Digest{} ||
            share->kernel != AuditRelationKernel::FOLD_RS)
            return false;
        // Fixed public reference weights, not a maliciously secure private
        // zero proof. The exact_zero bit scans the entire real native vector.
        F total(0);
        F weight(1);
        bool exact_zero = true;
        for (const F& value : share->values) {
            total += value * weight;
            weight = weight * F(65537) + F(17);
            if (value != F(0)) exact_zero = false;
        }
        const char digits[] = "0123456789abcdef";
        std::string commitment_hex;
        for (uint8_t b : share->commitment.bytes) {
            commitment_hex.push_back(digits[b >> 4]);
            commitment_hex.push_back(digits[b & 15]);
        }
        content << "operation " << ref.object_id << " "
                << commitment_hex << " " << share->values.size()
                << " " << total.real << " " << total.img
                << " " << (exact_zero ? 1 : 0) << "\n";
    }
    const std::string payload = content.str();
    const int fd = ::open(private_output_path.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    bool ok = true;
    size_t pos = 0;
    while (pos < payload.size()) {
        const ssize_t count = ::write(
            fd, payload.data() + pos, payload.size() - pos);
        if (count <= 0) { ok = false; break; }
        pos += static_cast<size_t>(count);
    }
    if (ok) ok = ::fsync(fd) == 0;
    if (::close(fd) != 0) ok = false;
    if (!ok) ::unlink(private_output_path.c_str());
    return ok;
}

bool FoldResidualRuntimeHarness::capture(
    const RegistrationConsistencyStatement& pre_vss_statement,
    RegistrationNativeConsumedSnapshot* output) const {
    const AuditCheckpointView* checkpoint =
        FindSealedCheckpoint(pre_vss_statement.checkpoint);
    return checkpoint && read_registration_native_consumed_snapshot(
        pre_vss_statement, states_, materials_, *checkpoint, output);
}

bool FoldResidualRuntimeHarness::still_matches(
    const RegistrationConsistencyStatement& pre_vss_statement,
    const RegistrationNativeConsumedSnapshot& captured) const {
    const AuditCheckpointView* checkpoint =
        FindSealedCheckpoint(pre_vss_statement.checkpoint);
    return checkpoint && registration_native_consumed_snapshot_still_matches(
        pre_vss_statement, states_, materials_, *checkpoint, captured);
}

bool FoldResidualRuntimeHarness::ActivateReferenceMpcCheckpoint(
    const AuditCheckpointView& checkpoint, int rank, int world_size) {
    if (world_size < 3 || rank < 0 || rank >= world_size ||
        checkpoint.id == 0 || !checkpoint.sealed ||
        checkpoint.phase != Phase::FOLD)
        return false;
    const int threshold = (world_size - 1) / 2;
    if (2 * threshold >= world_size) return false;

    u64 local_header[4] = {
        checkpoint.id,
        static_cast<u64>(checkpoint.phase),
        checkpoint.round,
        checkpoint.sealed ? 1ULL : 0ULL};
    std::vector<u64> all_headers(static_cast<size_t>(world_size) * 4);
    MPI_Allgather(local_header, 4, MPI_UINT64_T,
                  all_headers.data(), 4, MPI_UINT64_T, MPI_COMM_WORLD);
    for (int participant = 0; participant < world_size; ++participant) {
        const size_t off = static_cast<size_t>(participant) * 4;
        if (all_headers[off] != local_header[0] ||
            all_headers[off + 1] != local_header[1] ||
            all_headers[off + 2] != local_header[2] ||
            all_headers[off + 3] != 1ULL)
            return false;
    }

    std::vector<LiveFoldDescriptor> local_descriptors;
    int local_invalid = 0;
    for (const OperationRef& ref : checkpoint.operations) {
        const PrivateOperationMaterial* material = materials_.Find(ref);
        if (!material || material->operation.kernel != AuditRelationKernel::FOLD_RS)
            continue;
        if (material->operation.ref.owner != static_cast<uint32_t>(rank))
            continue;
        if (!material->finalized || material->state_dependencies.size() != 1 ||
            !material->has_field_output ||
            !materials_.ReadyForResidual(ref)) {
            ++local_invalid;
            continue;
        }
        const StateId state_id = material->state_dependencies.front();
        const PrivateStateMaterial* state = states_.Find(state_id);
        KernelResidualContext context{material->operation, *material, states_};
        const std::vector<F>* challenge =
            context.field_aux(AuditPublicAuxKind::FOLD_CHALLENGE);
        if (!state || !state->has_private_share ||
            !states_.VerifyDigest(state_id) || !challenge ||
            challenge->size() != 1 ||
            !validate_kernel_residual_material(context) ||
            material->operation.actual == Digest{} ||
            material->operation.relation_statement == Digest{}) {
            ++local_invalid;
            continue;
        }
        LiveFoldDescriptor descriptor;
        descriptor.sid = material->operation.label.sid;
        descriptor.checkpoint = material->operation.checkpoint;
        descriptor.owner = material->operation.ref.owner;
        descriptor.object_id = material->operation.ref.object_id;
        descriptor.state_id = state_id;
        descriptor.challenge_real = challenge->front().real;
        descriptor.challenge_img = challenge->front().img;
        descriptor.state_size = state->local_share.size();
        descriptor.output_size = material->field_output.size();
        descriptor.state_digest = state->state.digest;
        descriptor.actual_digest = material->operation.actual;
        descriptor.statement_binding = material->operation.relation_statement;
        local_descriptors.push_back(descriptor);
    }
    int global_invalid = 0;
    MPI_Allreduce(&local_invalid, &global_invalid, 1, MPI_INT, MPI_SUM,
                  MPI_COMM_WORLD);
    if (global_invalid != 0) return false;

    std::vector<u64> local_words;
    local_words.reserve(local_descriptors.size() * LIVE_FOLD_DESCRIPTOR_WORDS);
    for (const LiveFoldDescriptor& d : local_descriptors) {
        local_words.insert(local_words.end(), {
            d.sid, d.checkpoint, d.owner, d.object_id, d.state_id,
            d.challenge_real, d.challenge_img, d.state_size, d.output_size});
        append_live_digest(d.state_digest, &local_words);
        append_live_digest(d.actual_digest, &local_words);
        append_live_digest(d.statement_binding, &local_words);
    }
    const int local_word_count = static_cast<int>(local_words.size());
    std::vector<int> word_counts(static_cast<size_t>(world_size), 0);
    MPI_Allgather(&local_word_count, 1, MPI_INT,
                  word_counts.data(), 1, MPI_INT, MPI_COMM_WORLD);
    std::vector<int> displacements(static_cast<size_t>(world_size), 0);
    int total_words = 0;
    for (int i = 0; i < world_size; ++i) {
        if (word_counts[static_cast<size_t>(i)] < 0 ||
            word_counts[static_cast<size_t>(i)] % LIVE_FOLD_DESCRIPTOR_WORDS != 0)
            return false;
        displacements[static_cast<size_t>(i)] = total_words;
        total_words += word_counts[static_cast<size_t>(i)];
    }
    std::vector<u64> all_words(static_cast<size_t>(total_words));
    MPI_Allgatherv(local_words.empty() ? nullptr : local_words.data(),
                   local_word_count, MPI_UINT64_T,
                   all_words.empty() ? nullptr : all_words.data(),
                   word_counts.data(), displacements.data(), MPI_UINT64_T,
                   MPI_COMM_WORLD);
    if (all_words.empty()) return true;

    std::vector<LiveFoldDescriptor> descriptors;
    descriptors.reserve(all_words.size() / LIVE_FOLD_DESCRIPTOR_WORDS);
    for (size_t off = 0; off < all_words.size();
         off += LIVE_FOLD_DESCRIPTOR_WORDS) {
        LiveFoldDescriptor d;
        d.sid = all_words[off + 0];
        d.checkpoint = all_words[off + 1];
        d.owner = all_words[off + 2];
        d.object_id = all_words[off + 3];
        d.state_id = all_words[off + 4];
        d.challenge_real = all_words[off + 5];
        d.challenge_img = all_words[off + 6];
        d.state_size = all_words[off + 7];
        d.output_size = all_words[off + 8];
        d.state_digest = read_live_digest(all_words, off + 9);
        d.actual_digest = read_live_digest(all_words, off + 13);
        d.statement_binding = read_live_digest(all_words, off + 17);
        descriptors.push_back(d);
    }
    std::sort(descriptors.begin(), descriptors.end(),
        [](const LiveFoldDescriptor& lhs, const LiveFoldDescriptor& rhs) {
            if (lhs.owner != rhs.owner) return lhs.owner < rhs.owner;
            return lhs.object_id < rhs.object_id;
        });
    const u64 sid = descriptors.front().sid;
    if (sid == 0) return false;
    for (size_t i = 0; i < descriptors.size(); ++i) {
        const LiveFoldDescriptor& d = descriptors[i];
        if (d.sid != sid || d.checkpoint != checkpoint.id ||
            d.owner >= static_cast<u64>(world_size) ||
            d.state_size == 0 || d.output_size == 0 ||
            d.state_digest == Digest{} || d.actual_digest == Digest{} ||
            d.statement_binding == Digest{})
            return false;
        if (i > 0 && descriptors[i - 1].owner == d.owner &&
            descriptors[i - 1].object_id == d.object_id)
            return false;
    }

    auto session = std::make_unique<ReferenceShamirAuditSession>(
        sid, checkpoint.id, rank, world_size, threshold);
    for (const LiveFoldDescriptor& d : descriptors) {
        const OperationRef ref{static_cast<uint32_t>(d.owner), d.object_id};
        const F challenge(static_cast<long long>(d.challenge_real),
                          static_cast<long long>(d.challenge_img));
        std::vector<F> owner_state;
        std::vector<F> owner_output;
        int local_ready = 1;
        if (rank == static_cast<int>(d.owner)) {
            const PrivateOperationMaterial* material = materials_.Find(ref);
            const PrivateStateMaterial* state = states_.Find(d.state_id);
            if (!material || !state || !state->has_private_share ||
                material->state_dependencies.size() != 1 ||
                material->state_dependencies.front() != d.state_id ||
                state->local_share.size() != d.state_size ||
                material->field_output.size() != d.output_size ||
                state->state.digest != d.state_digest ||
                material->operation.actual != d.actual_digest ||
                material->operation.relation_statement != d.statement_binding) {
                local_ready = 0;
            } else {
                KernelResidualContext context{
                    material->operation, *material, states_};
                const std::vector<F>* local_challenge =
                    context.field_aux(AuditPublicAuxKind::FOLD_CHALLENGE);
                if (!local_challenge || local_challenge->size() != 1 ||
                    local_challenge->front() != challenge) {
                    local_ready = 0;
                } else {
                    owner_state = state->local_share;
                    owner_output = material->field_output;
                }
            }
        }
        int global_ready = 0;
        MPI_Allreduce(&local_ready, &global_ready, 1, MPI_INT, MPI_MIN,
                      MPI_COMM_WORLD);
        if (!global_ready) return false;
        if (!session->RegisterFoldOperation(
                static_cast<uint32_t>(d.owner), ref, challenge,
                d.state_digest, d.actual_digest, d.statement_binding,
                owner_state, owner_output))
            return false;
    }
    if (!session->SealRegistration()) return false;
    const ReferenceShamirBatchResult batch = session->BatchCheck();
    if (!batch.available || batch.checkpoint != checkpoint.id ||
        batch.operation_count != descriptors.size())
        return false;
    reference_mpc_batches_.push_back(batch);
    reference_mpc_sessions_.push_back(std::move(session));
    return true;
}

bool FoldResidualRuntimeHarness::RunSelfCheck(
    int rank, int world_size) const {
    if (world_size <= 0 || rank < 0 || rank >= world_size) return false;
    unsigned long long local[4] = {
        static_cast<unsigned long long>(fold_operations_),
        static_cast<unsigned long long>(zero_residuals_),
        static_cast<unsigned long long>(nonzero_residuals_),
        static_cast<unsigned long long>(invalid_material_)};
    unsigned long long global[4] = {0, 0, 0, 0};
    MPI_Allreduce(local, global, 4, MPI_UNSIGNED_LONG_LONG, MPI_SUM,
                  MPI_COMM_WORLD);
    const bool ok = global[0] > 0 && global[0] == global[1] &&
        global[2] == 0 && global[3] == 0;
    if (rank == 0) {
        std::cout << "[PVIA][fold-runtime-selftest] operations=" << global[0]
                  << " zero=" << global[1]
                  << " nonzero=" << global[2]
                  << " invalid=" << global[3]
                  << " result=" << (ok ? "PASS" : "FAIL") << "\n";
    }
    return ok;
}

bool FoldResidualRuntimeHarness::RunNativeSumcheckSelfCheck(
    int rank, int world_size) const {
    if (world_size <= 0 || rank < 0 || rank >= world_size) return false;
    unsigned long long local[10] = {
        static_cast<unsigned long long>(native_sumcheck_operations_),
        static_cast<unsigned long long>(native_sumcheck_zero_residuals_),
        static_cast<unsigned long long>(native_sumcheck_nonzero_residuals_),
        static_cast<unsigned long long>(native_sumcheck_invalid_material_),
        static_cast<unsigned long long>(native_sumcheck_not_ready_),
        static_cast<unsigned long long>(native_sumcheck_state_invalid_),
        static_cast<unsigned long long>(native_sumcheck_relation_invalid_),
        static_cast<unsigned long long>(native_sumcheck_reconstruction_invalid_),
        static_cast<unsigned long long>(native_sumcheck_input_mismatch_),
        static_cast<unsigned long long>(native_sumcheck_other_invalid_)};
    unsigned long long global[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    MPI_Allreduce(local, global, 10, MPI_UNSIGNED_LONG_LONG, MPI_SUM,
                  MPI_COMM_WORLD);
    unsigned long long local_kernels[5] = {};
    unsigned long long global_kernels[5] = {};
    for (size_t i = 0; i < native_sumcheck_kernel_counts_.size(); ++i)
        local_kernels[i] =
            static_cast<unsigned long long>(native_sumcheck_kernel_counts_[i]);
    MPI_Allreduce(local_kernels, global_kernels, 5,
                  MPI_UNSIGNED_LONG_LONG, MPI_SUM, MPI_COMM_WORLD);
    const bool ok = global[0] > 0 && global[0] == global[1] &&
        global[2] == 0 && global[3] == 0;
    if (rank == 0) {
        std::cout << "[PVIA][native-sumcheck-runtime-selftest] operations="
                  << global[0] << " zero=" << global[1]
                  << " nonzero=" << global[2]
                  << " invalid=" << global[3]
                  << " not-ready=" << global[4]
                  << " state-invalid=" << global[5]
                  << " relation-invalid=" << global[6]
                  << " reconstruction-invalid=" << global[7]
                  << " input-mismatch=" << global[8]
                  << " other-invalid=" << global[9]
                  << " kernels={cosumcheck-zero:" << global_kernels[0]
                  << ",cosumcheck-quadratic:" << global_kernels[1]
                  << ",cosumcheck-batch:" << global_kernels[2]
                  << ",dsc-quadratic:" << global_kernels[3]
                  << ",dsc-cubic:" << global_kernels[4]
                  << "} result=" << (ok ? "PASS" : "FAIL") << "\n";
    }
    return ok;
}

bool FoldResidualRuntimeHarness::RunReferenceMpcSelfCheck(
    int rank, int world_size) const {
    if (!reference_mpc_activation_enabled_ || world_size < 3 ||
        rank < 0 || rank >= world_size)
        return false;

    size_t operations = 0;
    size_t failed_sessions = 0;
    bool local_valid = reference_mpc_activation_failures_ == 0 &&
        !reference_mpc_sessions_.empty() &&
        reference_mpc_sessions_.size() == reference_mpc_batches_.size();
    for (size_t i = 0; i < reference_mpc_batches_.size(); ++i) {
        const ReferenceShamirBatchResult& batch = reference_mpc_batches_[i];
        const auto& session = reference_mpc_sessions_[i];
        if (!session || !session->sealed() || !batch.available ||
            batch.registration_binding != session->registration_binding() ||
            batch.operation_count != session->operation_count()) {
            local_valid = false;
            continue;
        }
        operations += batch.operation_count;
        if (!batch.clean) ++failed_sessions;
    }
    local_valid = local_valid && operations > 0 && failed_sessions == 0;
    int local_ok = local_valid ? 1 : 0;
    int global_ok = 0;
    MPI_Allreduce(&local_ok, &global_ok, 1, MPI_INT, MPI_MIN,
                  MPI_COMM_WORLD);
    if (rank == 0) {
        std::cout << "[PVIA][shamir-fold-runtime-selftest] sessions="
                  << reference_mpc_sessions_.size()
                  << " operations=" << operations
                  << " clean=" << (reference_mpc_batches_.size() - failed_sessions)
                  << " failed=" << failed_sessions
                  << " activation-errors=" << reference_mpc_activation_failures_
                  << " result=" << (global_ok ? "PASS" : "FAIL")
                  << "\n";
    }
    return global_ok != 0;
}

BatchCheckResult FoldResidualRuntimeHarness::BatchCheck(
    const ObligationSet& scope) const {
    if (delegate_runtime_debug_checks_)
        return Runtime::instance().debug_batch_check(scope);
    BatchCheckResult out;
    out.checkpoint = scope.checkpoint;
    return out;
}

Violation FoldResidualRuntimeHarness::Dispute(
    const ObligationSet& scope, const BatchCheckResult& batch) const {
    if (delegate_runtime_debug_checks_)
        return Runtime::instance().debug_dispute(scope, batch);
    return Violation{};
}

RecoverableAuditShare FoldResidualRuntimeHarness::RecoverAudit(
    const Violation& violation) const {
    if (delegate_runtime_debug_checks_)
        return Runtime::instance().recover_debug_audit(violation);
    return RecoverableAuditShare{};
}
BlameCertificate FoldResidualRuntimeHarness::LiftBlame(
    const Violation& violation, const RecoverableAuditShare& audit) const {
    if (delegate_runtime_debug_checks_)
        return Runtime::instance().lift_debug_blame(violation, audit);
    return BlameCertificate{};
}

bool FoldResidualRuntimeHarness::Judge(
    const BlameCertificate& certificate, uint64_t expected_session_id) const {
    if (delegate_runtime_debug_checks_)
        return expected_session_id == Runtime::instance().session_id() &&
            Runtime::instance().debug_judge(certificate);
    return false;
}

} // namespace pvia
