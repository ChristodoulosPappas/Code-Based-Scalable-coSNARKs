#include "ReferenceShamirRobustAuditBackend.hpp"

#include "PrivateAuditMaterialStore.hpp"
#include "PrivateStateMaterialStore.hpp"

#include <mpi.h>

#include <algorithm>
#include <cstring>
#include <limits>

namespace pvia {
namespace {

constexpr u64 REF_ROBUST_PROTOCOL_ID = 0x5245465348524f42ULL;
constexpr u64 REF_IMPL_DOMAIN = 0x524546524f42494dULL;
constexpr u64 REF_ACT_DOMAIN = 0x524546524f424143ULL;
constexpr u64 REF_AUTH_PROTOCOL_DOMAIN = 0x5246524f42415554ULL; // RFROBAUT
constexpr u64 REF_AUTH_ROLL_DOMAIN = 0x5246524f4254524eULL; // RFROBTRN
constexpr u64 REF_AUTH_ACT_DOMAIN = 0x5246415554414354ULL; // RFAUTACT
constexpr u64 REF_AUTH_OUT_DOMAIN = 0x52464155544f5554ULL; // RFAUTOUT
constexpr u64 REF_AUTH_KIND_CAP = 0x5246434150303031ULL; // RFCAP001
constexpr u64 REF_AUTH_KIND_HEADER = 0x5246484452303031ULL; // RFHDR001
constexpr u64 REF_AUTH_KIND_VALID = 0x524656414c303031ULL; // RFVAL001
constexpr u64 REF_AUTH_KIND_COUNTS = 0x5246434e54303031ULL; // RFCNT001
constexpr u64 REF_AUTH_KIND_DESCRIPTORS = 0x5246444553303031ULL; // RFDES001
constexpr u64 REF_AUTH_KIND_OWNER_READY = 0x52464f574e523031ULL; // RFOWNR01
constexpr u64 REF_AUTH_KIND_SID_TRANSITION = 0x5246534944545231ULL; // RFSIDTR1
constexpr u64 REF_ABORT_RECON_PROTOCOL_DOMAIN = 0x5246414254524543ULL; // RFABTREC
constexpr u64 REF_ABORT_RECON_ACT_KIND = 0x5246414254414354ULL; // RFABTACT
constexpr u64 REF_ABORT_RECON_EXEC_KIND = 0x5246414254455845ULL; // RFABTEXE
constexpr int DESC_WORDS = 35;

struct FoldDescriptor {
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
    RegistrationNativeContext native_context{};
};

void append_digest(const Digest& d, std::vector<u64>* words) {
    for (size_t i = 0; i < 4; ++i) {
        u64 w = 0;
        std::memcpy(&w, d.bytes.data() + 8 * i, 8);
        words->push_back(w);
    }
}

Digest read_digest(const std::vector<u64>& words, size_t offset) {
    Digest d{};
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(d.bytes.data() + 8 * i, &words[offset + i], 8);
    return d;
}

bool all_ranks_true(int local, MPI_Comm comm = MPI_COMM_WORLD) {
    int global = 0;
    MPI_Allreduce(&local, &global, 1, MPI_INT, MPI_MIN, comm);
    return global != 0;
}

bool same_refs(const std::vector<OperationRef>& lhs,
               const std::vector<OperationRef>& rhs) {
    if (lhs.size() != rhs.size()) return false;
    for (size_t i = 0; i < lhs.size(); ++i)
        if (!(lhs[i] == rhs[i])) return false;
    return true;
}

} // namespace

ReferenceShamirRobustAuditBackend::ReferenceShamirRobustAuditBackend(
    int rank, int world_size, int threshold,
    const RegistrationConsistencyProofBackend*
        registration_consistency_backend,
    const MultiplicationConsistencyProofBackend*
        multiplication_consistency_backend,
    const AuthenticatedMpcExchange* authenticated_exchange)
    : rank_(rank), world_size_(world_size), threshold_(threshold) {
    capabilities_.available = world_size_ > 0 && rank_ >= 0 &&
        rank_ < world_size_ && threshold_ >= 0 &&
        2 * threshold_ < world_size_;
    capabilities_.protocol_id = REF_ROBUST_PROTOCOL_ID;
    capabilities_.security_level = RobustAuditSecurityLevel::REFERENCE_PASSIVE;
    capabilities_.malicious_secure = false;
    const bool authenticated_transport_ready =
        authenticated_exchange &&
        authenticated_exchange->production_authenticated_ready() &&
        authenticated_exchange->ProductionCapabilityBinding() != Digest{};
    if (authenticated_transport_ready)
        authenticated_exchange_ = authenticated_exchange;
    capabilities_.authenticated_channels = authenticated_transport_ready;
    capabilities_.authenticated_channel_capability_binding =
        authenticated_transport_ready
            ? authenticated_exchange->ProductionCapabilityBinding()
            : Digest{};
    capabilities_.publicly_identifiable_abort = false;
    capabilities_.identifiable_abort_capability_binding = Digest{};
    capabilities_.guaranteed_output_delivery = false;
    capabilities_.delivery_capability_binding = Digest{};
    capabilities_.activation_before_failure = true;
    capabilities_.private_witness_retention = true;
    capabilities_.detectable_input_sharing =
        threshold_ >= 0 && 3 * threshold_ < world_size_;
    RegistrationConsistencyCapabilities registration_capabilities;
    if (registration_consistency_backend)
        registration_capabilities = registration_consistency_backend->Capabilities();
    const bool registration_ready =
        registration_consistency_backend &&
        production_ready_registration_consistency_capabilities(
            registration_capabilities);
    if (registration_ready)
        registration_consistency_backend_ = registration_consistency_backend;
    capabilities_.public_registration_consistency = registration_ready;
    capabilities_.registration_consistency_capability_binding =
        registration_ready ? registration_capabilities.capability_binding : Digest{};
    capabilities_.robust_opening =
        threshold_ >= 0 && 3 * threshold_ < world_size_;
    capabilities_.commit_reveal_public_coin = capabilities_.available;
    capabilities_.detectable_degree_reduction =
        threshold_ >= 0 && 3 * threshold_ < world_size_;
    capabilities_.detectable_random_sharing =
        threshold_ >= 0 && 3 * threshold_ < world_size_;
    MultiplicationConsistencyCapabilities multiplication_capabilities;
    if (multiplication_consistency_backend)
        multiplication_capabilities =
            multiplication_consistency_backend->Capabilities();
    const bool multiplication_ready =
        capabilities_.detectable_degree_reduction &&
        multiplication_consistency_backend &&
        production_ready_multiplication_consistency_capabilities(
            multiplication_capabilities);
    if (multiplication_ready)
        multiplication_consistency_backend_ =
            multiplication_consistency_backend;
    capabilities_.malicious_multiplication_consistency =
        multiplication_ready;
    capabilities_.multiplication_consistency_capability_binding =
        multiplication_ready
            ? multiplication_capabilities.capability_binding
            : Digest{};
    capabilities_.packed_sharing = false;
    capabilities_.corruption_threshold = static_cast<uint32_t>(
        threshold_ < 0 ? 0 : threshold_);
    capabilities_.supported_kernels = {AuditRelationKernel::FOLD_RS};
    capabilities_.implementation_binding = hash_words({
        REF_IMPL_DOMAIN, static_cast<u64>(world_size_),
        static_cast<u64>(threshold_ < 0 ? 0 : threshold_)});
    capabilities_.capability_binding =
        compute_robust_audit_capability_binding(capabilities_);
}

AuthenticatedMpcMessageContext
ReferenceShamirRobustAuditBackend::NextTransportContext(
    uint64_t namespace_sid, CheckpointId checkpoint,
    u64 message_kind, uint64_t round) const {
    AuthenticatedMpcMessageContext context;
    if (!authenticated_exchange_ || namespace_sid == 0 ||
        checkpoint == 0 || message_kind == 0)
        return context;
    context.protocol_domain = REF_AUTH_PROTOCOL_DOMAIN;
    // Bootstrap traffic precedes recovery of the protocol SID. Its namespace
    // is derived from the sealed checkpoint binding/root, so a repeated
    // phase/round/generation checkpoint id in another session cannot reuse the
    // same authenticated context. After descriptor agreement the audit session
    // switches to the recovered real protocol SID.
    context.sid = namespace_sid;
    context.checkpoint = checkpoint;
    context.round = round;
    context.sequence = transport_sequence_++;
    context.message_kind = message_kind;
    return context;
}

RobustAuditCapabilities ReferenceShamirRobustAuditBackend::Capabilities() const {
    return capabilities_;
}

RobustAuditAbortOutput
ReferenceShamirRobustAuditBackend::ReconcileAbortCollectively(
    const AuditCheckpointView& checkpoint,
    const RobustAuditActivation* activation,
    int rank, int world_size) {
    RobustAuditAbortOutput unavailable;
    if (rank != rank_ || world_size != world_size_ ||
        !authenticated_exchange_ ||
        !production_ready_identifiable_abort_capabilities(capabilities_) ||
        !checkpoint.sealed || checkpoint.id == 0 || checkpoint.root == Digest{})
        return unavailable;
    if (activation && !validate_robust_audit_activation(
            checkpoint, capabilities_, *activation))
        return unavailable;

    const uint64_t evidence_sid = activation
        ? activation->sid
        : compute_robust_bootstrap_transport_sid(checkpoint);
    const Digest checkpoint_binding = compute_robust_checkpoint_binding(checkpoint);
    if (evidence_sid == 0 || checkpoint_binding == Digest{}) return unavailable;
    u64 reconciliation_sequence = 0;
    std::memcpy(&reconciliation_sequence,
                checkpoint_binding.bytes.data(), sizeof(reconciliation_sequence));
    if (reconciliation_sequence == 0) reconciliation_sequence = 1;

    AuthenticatedMpcMessageContext context;
    context.protocol_domain = REF_ABORT_RECON_PROTOCOL_DOMAIN;
    context.sid = evidence_sid;
    context.checkpoint = checkpoint.id;
    context.round = checkpoint.round;
    context.sequence = reconciliation_sequence;
    context.message_kind = activation
        ? REF_ABORT_RECON_EXEC_KIND : REF_ABORT_RECON_ACT_KIND;

    RobustAuditAbortOutput output;
    Digest observation_binding{};
    Digest reconciliation_binding{};
    if (!build_robust_audit_abort_output_from_reconciled_exchange(
            *authenticated_exchange_, context, checkpoint, capabilities_,
            activation, world_size_, &output,
            &observation_binding, &reconciliation_binding) ||
        observation_binding == Digest{} || reconciliation_binding == Digest{} ||
        !VerifyPublicAbort(checkpoint, activation, output))
        return unavailable;
    last_abort_ = output;
    return output;
}

RobustAuditAbortOutput
ReferenceShamirRobustAuditBackend::LastAbort() const {
    if (last_abort_.available) return last_abort_;
    RobustAuditAbortOutput unavailable;
    if (!authenticated_exchange_ ||
        !production_ready_identifiable_abort_capabilities(capabilities_))
        return unavailable;
    // Query evidence by namespace so an unrelated newer equivocation cannot
    // hide an older unconsumed abort certificate.
    for (auto it = entries_.rbegin(); it != entries_.rend(); ++it) {
        AuthenticatedMpcEquivocationEvidence evidence;
        if (!authenticated_exchange_->LastEquivocationEvidence(
                it->sid, it->checkpoint, &evidence))
            continue;
        RobustAuditAbortOutput output;
        if (build_robust_audit_abort_output_from_exchange(
                *authenticated_exchange_, it->checkpoint_view,
                capabilities_, &it->activation, world_size_, &output))
            return output;
    }
    if (last_checkpoint_view_.id != 0) {
        const uint64_t bootstrap_sid =
            compute_robust_bootstrap_transport_sid(last_checkpoint_view_);
        AuthenticatedMpcEquivocationEvidence evidence;
        if (bootstrap_sid != 0 &&
            authenticated_exchange_->LastEquivocationEvidence(
                bootstrap_sid, last_checkpoint_view_.id, &evidence)) {
            RobustAuditAbortOutput output;
            if (build_robust_audit_abort_output_from_exchange(
                    *authenticated_exchange_, last_checkpoint_view_,
                    capabilities_, nullptr, world_size_, &output))
                return output;
        }
    }
    return unavailable;
}
bool ReferenceShamirRobustAuditBackend::LastAuthenticatedTransportFailure(
    const AuditCheckpointView& checkpoint,
    const RobustAuditActivation* activation,
    Digest* failure_binding) const {
    if (!failure_binding) return false;
    *failure_binding = Digest{};
    if (!authenticated_exchange_ || !capabilities_.authenticated_channels ||
        !checkpoint.sealed || checkpoint.id == 0 || checkpoint.root == Digest{})
        return false;
    if (activation && !validate_robust_audit_activation(
            checkpoint, capabilities_, *activation))
        return false;
    const uint64_t failure_sid = activation
        ? activation->sid
        : compute_robust_bootstrap_transport_sid(checkpoint);
    if (failure_sid == 0) return false;
    AuthenticatedMpcLocalFailureObservation failure;
    if (!authenticated_exchange_->LastLocalFailure(
            failure_sid, checkpoint.id, &failure) ||
        failure.kind == AuthenticatedMpcLocalFailureKind::UNKNOWN ||
        failure.context.sid != failure_sid ||
        failure.context.checkpoint != checkpoint.id ||
        failure.failure_binding == Digest{} ||
        failure.failure_binding !=
            compute_authenticated_mpc_local_failure_binding(failure))
        return false;
    *failure_binding = failure.failure_binding;
    return true;
}

ReferenceShamirRobustAuditBackend::Entry*
ReferenceShamirRobustAuditBackend::FindEntry(
    CheckpointId checkpoint, uint64_t sid) {
    for (auto& entry : entries_)
        if (entry.checkpoint == checkpoint && entry.sid == sid) return &entry;
    return nullptr;
}

const ReferenceShamirRobustAuditBackend::Entry*
ReferenceShamirRobustAuditBackend::FindEntry(
    CheckpointId checkpoint, uint64_t sid) const {
    for (const auto& entry : entries_)
        if (entry.checkpoint == checkpoint && entry.sid == sid) return &entry;
    return nullptr;
}

ReferenceShamirRobustAuditBackend::Entry*
ReferenceShamirRobustAuditBackend::FindEntryForCheckpoint(
    const AuditCheckpointView& checkpoint) {
    const Digest binding = compute_robust_checkpoint_binding(checkpoint);
    if (binding == Digest{}) return nullptr;
    for (auto& entry : entries_)
        if (entry.checkpoint == checkpoint.id &&
            compute_robust_checkpoint_binding(entry.checkpoint_view) == binding)
            return &entry;
    return nullptr;
}

const ReferenceShamirRobustAuditBackend::Entry*
ReferenceShamirRobustAuditBackend::FindEntryForCheckpoint(
    const AuditCheckpointView& checkpoint) const {
    const Digest binding = compute_robust_checkpoint_binding(checkpoint);
    if (binding == Digest{}) return nullptr;
    for (const auto& entry : entries_)
        if (entry.checkpoint == checkpoint.id &&
            compute_robust_checkpoint_binding(entry.checkpoint_view) == binding)
            return &entry;
    return nullptr;
}

RobustAuditActivation ReferenceShamirRobustAuditBackend::Activate(
    const AuditCheckpointView& checkpoint,
    const PrivateStateMaterialStore& states,
    const PrivateAuditMaterialStore& materials) {
    RobustAuditActivation unavailable;
    last_abort_ = RobustAuditAbortOutput{};
    last_checkpoint_view_ = AuditCheckpointView{};
    if (!validate_robust_audit_capabilities(capabilities_) ||
        !checkpoint.sealed || checkpoint.id == 0 || checkpoint.root == Digest{})
        return unavailable;
    if (Entry* existing = FindEntryForCheckpoint(checkpoint))
        return existing->activation;
    const uint64_t bootstrap_sid =
        compute_robust_bootstrap_transport_sid(checkpoint);
    if (capabilities_.authenticated_channels && bootstrap_sid == 0)
        return unavailable;
    last_checkpoint_view_ = checkpoint;

    Digest activation_transport_binding{};
    auto bind_transport = [&](const Digest& binding) -> bool {
        if (!capabilities_.authenticated_channels) return true;
        if (binding == Digest{}) return false;
        std::vector<u64> binding_words = {
            REF_AUTH_ROLL_DOMAIN, bootstrap_sid,
            checkpoint.id, checkpoint.round};
        append_digest(capabilities_.authenticated_channel_capability_binding,
                      &binding_words);
        append_digest(activation_transport_binding, &binding_words);
        append_digest(binding, &binding_words);
        activation_transport_binding = hash_words(binding_words);
        return activation_transport_binding != Digest{};
    };
    if (capabilities_.authenticated_channels) {
        std::vector<u64> local_capability;
        append_digest(capabilities_.authenticated_channel_capability_binding,
                      &local_capability);
        std::vector<u64> gathered_capabilities;
        Digest capability_exchange_binding{};
        if (!authenticated_exchange_->AllGatherWords(
                NextTransportContext(bootstrap_sid, checkpoint.id, REF_AUTH_KIND_CAP,
                                     checkpoint.round),
                local_capability, &gathered_capabilities,
                &capability_exchange_binding) ||
            gathered_capabilities.size() !=
                static_cast<size_t>(world_size_) * 4)
            return unavailable;
        for (int i = 0; i < world_size_; ++i)
            if (read_digest(gathered_capabilities,
                    static_cast<size_t>(i) * 4) !=
                capabilities_.authenticated_channel_capability_binding)
                return unavailable;
        if (!bind_transport(capability_exchange_binding)) return unavailable;
    }
    u64 local_header[3] = {
        checkpoint.id, static_cast<u64>(checkpoint.phase), checkpoint.round};
    std::vector<u64> headers;
    if (capabilities_.authenticated_channels) {
        Digest header_binding{};
        if (!authenticated_exchange_->AllGatherWords(
                NextTransportContext(bootstrap_sid, checkpoint.id, REF_AUTH_KIND_HEADER,
                                     checkpoint.round),
                {local_header[0], local_header[1], local_header[2]},
                &headers, &header_binding) ||
            headers.size() != static_cast<size_t>(world_size_) * 3 ||
            !bind_transport(header_binding))
            return unavailable;
    } else {
        headers.resize(static_cast<size_t>(world_size_) * 3);
        MPI_Allgather(local_header, 3, MPI_UINT64_T,
                     headers.data(), 3, MPI_UINT64_T, MPI_COMM_WORLD);
    }
    for (int i = 0; i < world_size_; ++i) {
        const size_t off = static_cast<size_t>(i) * 3;
        if (headers[off] != local_header[0] ||
            headers[off + 1] != local_header[1] ||
            headers[off + 2] != local_header[2])
            return unavailable;
    }

    std::vector<FoldDescriptor> local;
    int local_invalid = 0;
    for (const OperationRef& ref : checkpoint.operations) {
        const PrivateOperationMaterial* material = materials.Find(ref);
        if (!material || material->operation.kernel != AuditRelationKernel::FOLD_RS ||
            material->operation.ref.owner != static_cast<uint32_t>(rank_))
            continue;
        if (!material->finalized || material->state_dependencies.size() != 1 ||
            !material->has_field_output || !materials.ReadyForResidual(ref)) {
            ++local_invalid;
            continue;
        }
        const StateId state_id = material->state_dependencies.front();
        const PrivateStateMaterial* state = states.Find(state_id);
        KernelResidualContext context{material->operation, *material, states};
        const std::vector<F>* challenge =
            context.field_aux(AuditPublicAuxKind::FOLD_CHALLENGE);
        if (!state || !state->has_private_share ||
            !states.VerifyDigest(state_id) || !challenge ||
            challenge->size() != 1 ||
            !validate_kernel_residual_material(context) ||
            material->operation.actual == Digest{} ||
            material->operation.relation_statement == Digest{} ||
            (registration_consistency_backend_ &&
                (!states.VerifyAuthentication(state_id) ||
                 material->operation.predecessor_root == Digest{} ||
                 checkpoint.root == Digest{}))) {
            ++local_invalid;
            continue;
        }
        FoldDescriptor d;
        d.sid = material->operation.label.sid;
        d.checkpoint = material->operation.checkpoint;
        d.owner = material->operation.ref.owner;
        d.object_id = material->operation.ref.object_id;
        d.state_id = state_id;
        d.challenge_real = challenge->front().real;
        d.challenge_img = challenge->front().img;
        d.state_size = state->local_share.size();
        d.output_size = material->field_output.size();
        d.state_digest = state->state.digest;
        d.actual_digest = material->operation.actual;
        d.statement_binding = material->operation.relation_statement;
        if (registration_consistency_backend_) {
            // These metadata bytes are collected from the native execution
            // record; they are statement bindings, NOT a proof of equality.
            d.native_context.native_state_id = state_id;
            d.native_context.authentication_scheme_id =
                state->authentication_scheme_id;
            d.native_context.authentication_binding =
                state->authentication_binding;
            d.native_context.predecessor_root =
                material->operation.predecessor_root;
            d.native_context.checkpoint_root = checkpoint.root;
        }
        local.push_back(d);
    }
    if (capabilities_.authenticated_channels) {
        bool globally_valid = false;
        Digest validity_binding{};
        if (!authenticated_exchange_->AllTrue(
                NextTransportContext(bootstrap_sid, checkpoint.id, REF_AUTH_KIND_VALID,
                                     checkpoint.round),
                local_invalid == 0, &globally_valid, &validity_binding) ||
            !globally_valid || !bind_transport(validity_binding))
            return unavailable;
    } else if (!all_ranks_true(local_invalid == 0 ? 1 : 0)) {
        return unavailable;
    }

    std::vector<u64> local_words;
    for (const FoldDescriptor& d : local) {
        local_words.insert(local_words.end(), {
            d.sid, d.checkpoint, d.owner, d.object_id, d.state_id,
            d.challenge_real, d.challenge_img, d.state_size, d.output_size});
        append_digest(d.state_digest, &local_words);
        append_digest(d.actual_digest, &local_words);
        append_digest(d.statement_binding, &local_words);
        local_words.push_back(d.native_context.native_state_id);
        local_words.push_back(d.native_context.authentication_scheme_id);
        append_digest(d.native_context.authentication_binding, &local_words);
        append_digest(d.native_context.predecessor_root, &local_words);
        append_digest(d.native_context.checkpoint_root, &local_words);
    }
    if (local_words.size() >
        static_cast<size_t>(std::numeric_limits<int>::max()))
        return unavailable;
    const int local_count = static_cast<int>(local_words.size());
    std::vector<int> counts(static_cast<size_t>(world_size_), 0);
    if (capabilities_.authenticated_channels) {
        std::vector<u64> gathered_counts;
        Digest counts_binding{};
        if (!authenticated_exchange_->AllGatherWords(
                NextTransportContext(bootstrap_sid, checkpoint.id, REF_AUTH_KIND_COUNTS,
                                     checkpoint.round),
                {static_cast<u64>(local_words.size())},
                &gathered_counts, &counts_binding) ||
            gathered_counts.size() != static_cast<size_t>(world_size_) ||
            !bind_transport(counts_binding))
            return unavailable;
        for (int i = 0; i < world_size_; ++i) {
            const u64 count = gathered_counts[static_cast<size_t>(i)];
            if (count > static_cast<u64>(std::numeric_limits<int>::max()))
                return unavailable;
            counts[static_cast<size_t>(i)] = static_cast<int>(count);
        }
    } else {
        MPI_Allgather(&local_count, 1, MPI_INT,
                      counts.data(), 1, MPI_INT, MPI_COMM_WORLD);
    }
    std::vector<int> displacements(static_cast<size_t>(world_size_), 0);
    int total = 0;
    int max_count = 0;
    for (int i = 0; i < world_size_; ++i) {
        const int count = counts[static_cast<size_t>(i)];
        if (count < 0 || count % DESC_WORDS != 0 ||
            count > std::numeric_limits<int>::max() - total)
            return unavailable;
        displacements[static_cast<size_t>(i)] = total;
        total += count;
        max_count = std::max(max_count, count);
    }
    if (total == 0 || max_count <= 0) return unavailable;
    std::vector<u64> words;
    if (capabilities_.authenticated_channels) {
        std::vector<u64> padded(static_cast<size_t>(max_count), 0);
        std::copy(local_words.begin(), local_words.end(), padded.begin());
        std::vector<u64> gathered_padded;
        Digest descriptors_binding{};
        if (!authenticated_exchange_->AllGatherWords(
                NextTransportContext(bootstrap_sid, checkpoint.id, REF_AUTH_KIND_DESCRIPTORS,
                                     checkpoint.round),
                padded, &gathered_padded, &descriptors_binding) ||
            gathered_padded.size() !=
                static_cast<size_t>(world_size_) *
                    static_cast<size_t>(max_count) ||
            !bind_transport(descriptors_binding))
            return unavailable;
        words.reserve(static_cast<size_t>(total));
        for (int i = 0; i < world_size_; ++i) {
            const size_t base = static_cast<size_t>(i) *
                static_cast<size_t>(max_count);
            const size_t count =
                static_cast<size_t>(counts[static_cast<size_t>(i)]);
            words.insert(words.end(), gathered_padded.begin() + base,
                         gathered_padded.begin() + base + count);
        }
    } else {
        words.resize(static_cast<size_t>(total));
        MPI_Allgatherv(local_words.empty() ? nullptr : local_words.data(),
                       local_count, MPI_UINT64_T,
                       words.data(), counts.data(), displacements.data(),
                       MPI_UINT64_T, MPI_COMM_WORLD);
    }

    std::vector<FoldDescriptor> descriptors;
    for (size_t off = 0; off < words.size(); off += DESC_WORDS) {
        FoldDescriptor d;
        d.sid = words[off + 0];
        d.checkpoint = words[off + 1];
        d.owner = words[off + 2];
        d.object_id = words[off + 3];
        d.state_id = words[off + 4];
        d.challenge_real = words[off + 5];
        d.challenge_img = words[off + 6];
        d.state_size = words[off + 7];
        d.output_size = words[off + 8];
        d.state_digest = read_digest(words, off + 9);
        d.actual_digest = read_digest(words, off + 13);
        d.statement_binding = read_digest(words, off + 17);
        d.native_context.native_state_id = words[off + 21];
        d.native_context.authentication_scheme_id = words[off + 22];
        d.native_context.authentication_binding = read_digest(words, off + 23);
        d.native_context.predecessor_root = read_digest(words, off + 27);
        d.native_context.checkpoint_root = read_digest(words, off + 31);
        descriptors.push_back(d);
    }
    std::sort(descriptors.begin(), descriptors.end(),
        [](const FoldDescriptor& a, const FoldDescriptor& b) {
            if (a.owner != b.owner) return a.owner < b.owner;
            return a.object_id < b.object_id;
        });
    const uint64_t sid = descriptors.front().sid;
    if (sid == 0) return unavailable;
    for (size_t i = 0; i < descriptors.size(); ++i) {
        const auto& d = descriptors[i];
        if (d.sid != sid || d.checkpoint != checkpoint.id ||
            d.owner >= static_cast<u64>(world_size_) ||
            d.state_size == 0 || d.output_size == 0 ||
            d.state_digest == Digest{} || d.actual_digest == Digest{} ||
            d.statement_binding == Digest{} ||
            (registration_consistency_backend_ &&
                (!validate_registration_native_context(d.native_context) ||
                 d.native_context.checkpoint_root != checkpoint.root)))
            return unavailable;
        if (i > 0 && descriptors[i - 1].owner == d.owner &&
            descriptors[i - 1].object_id == d.object_id)
            return unavailable;
    }

    if (capabilities_.authenticated_channels) {
        std::vector<u64> gathered_transition;
        Digest transition_binding{};
        if (!authenticated_exchange_->AllGatherWords(
                NextTransportContext(bootstrap_sid, checkpoint.id,
                    REF_AUTH_KIND_SID_TRANSITION, checkpoint.round),
                {bootstrap_sid, checkpoint.id, sid}, &gathered_transition,
                &transition_binding) ||
            gathered_transition.size() !=
                static_cast<size_t>(world_size_) * 3)
            return unavailable;
        for (int i = 0; i < world_size_; ++i) {
            const size_t off = static_cast<size_t>(i) * 3;
            if (gathered_transition[off] != bootstrap_sid ||
                gathered_transition[off + 1] != checkpoint.id ||
                gathered_transition[off + 2] != sid)
                return unavailable;
        }
        if (!bind_transport(transition_binding)) return unavailable;
    }

    Entry entry;
    entry.checkpoint = checkpoint.id;
    entry.sid = sid;
    entry.checkpoint_view = checkpoint;
    entry.session = std::make_unique<ReferenceShamirAuditSession>(
        sid, checkpoint.id, rank_, world_size_, threshold_,
        registration_consistency_backend_,
        multiplication_consistency_backend_, authenticated_exchange_);
    for (const auto& d : descriptors) {
        const OperationRef ref{static_cast<uint32_t>(d.owner), d.object_id};
        const F challenge(static_cast<long long>(d.challenge_real),
                          static_cast<long long>(d.challenge_img));
        std::vector<F> owner_state;
        std::vector<F> owner_output;
        int local_ready = 1;
        if (rank_ == static_cast<int>(d.owner)) {
            const PrivateOperationMaterial* material = materials.Find(ref);
            const PrivateStateMaterial* state = states.Find(d.state_id);
            if (!material || !state || !state->has_private_share ||
                material->state_dependencies.size() != 1 ||
                material->state_dependencies.front() != d.state_id ||
                state->local_share.size() != d.state_size ||
                material->field_output.size() != d.output_size ||
                state->state.digest != d.state_digest ||
                material->operation.actual != d.actual_digest ||
                material->operation.relation_statement != d.statement_binding ||
                (registration_consistency_backend_ &&
                    (!states.VerifyAuthentication(d.state_id) ||
                     state->authentication_scheme_id !=
                         d.native_context.authentication_scheme_id ||
                     state->authentication_binding !=
                         d.native_context.authentication_binding ||
                     material->operation.predecessor_root !=
                         d.native_context.predecessor_root ||
                     state->state.id != d.native_context.native_state_id))) {
                local_ready = 0;
            } else {
                KernelResidualContext context{
                    material->operation, *material, states};
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
        if (capabilities_.authenticated_channels) {
            bool globally_ready = false;
            Digest owner_ready_binding{};
            if (!authenticated_exchange_->AllTrue(
                    NextTransportContext(bootstrap_sid, checkpoint.id,
                        REF_AUTH_KIND_OWNER_READY, d.object_id),
                    local_ready != 0, &globally_ready,
                    &owner_ready_binding) ||
                !globally_ready || !bind_transport(owner_ready_binding))
                return unavailable;
        } else if (!all_ranks_true(local_ready)) {
            return unavailable;
        }
        if (!entry.session->RegisterFoldOperation(
                static_cast<uint32_t>(d.owner), ref, challenge,
                d.state_digest, d.actual_digest, d.statement_binding,
                owner_state, owner_output, d.native_context))
            return unavailable;
        entry.operations.push_back(ref);
    }
    if (!entry.session->SealRegistration()) return unavailable;
    if (capabilities_.authenticated_channels &&
        (!entry.session->authenticated_transport_enabled() ||
         entry.session->authenticated_transport_capability_binding() !=
             capabilities_.authenticated_channel_capability_binding ||
         entry.session->authenticated_transport_transcript_binding() == Digest{} ||
         activation_transport_binding == Digest{}))
        return unavailable;

    RobustAuditActivation activation;
    activation.available = true;
    activation.sid = sid;
    activation.checkpoint = checkpoint.id;
    activation.checkpoint_root = checkpoint.root;
    activation.checkpoint_binding = compute_robust_checkpoint_binding(checkpoint);
    activation.registered_operations = entry.operations.size();
    activation.capability_binding = capabilities_.capability_binding;
    if (capabilities_.authenticated_channels) {
        std::vector<u64> channel_words = {
            REF_AUTH_ACT_DOMAIN, bootstrap_sid, sid, checkpoint.id,
            static_cast<u64>(entry.operations.size())};
        append_digest(capabilities_.authenticated_channel_capability_binding,
                      &channel_words);
        append_digest(activation_transport_binding, &channel_words);
        append_digest(
            entry.session->authenticated_transport_transcript_binding(),
            &channel_words);
        activation.authenticated_channel_activation_binding =
            hash_words(channel_words);
        if (activation.authenticated_channel_activation_binding == Digest{})
            return unavailable;
    } else {
        activation.authenticated_channel_activation_binding = Digest{};
    }
    activation.delivery_activation_binding = Digest{};
    activation.registration_consistency_binding =
        entry.session->registration_consistency_binding();
    std::vector<u64> activation_words = {
        REF_ACT_DOMAIN, sid, checkpoint.id,
        static_cast<u64>(entry.operations.size())};
    append_digest(entry.session->registration_binding(), &activation_words);
    append_digest(activation.authenticated_channel_activation_binding,
                  &activation_words);
    append_digest(activation.registration_consistency_binding,
                  &activation_words);
    activation.activation_transcript_binding = hash_words(activation_words);
    activation.activation_binding =
        compute_robust_audit_activation_binding(activation);
    if (!validate_robust_audit_activation(
            checkpoint, capabilities_, activation))
        return unavailable;
    entry.activation = activation;
    entries_.push_back(std::move(entry));
    return activation;
}
RobustAuditSessionOutput ReferenceShamirRobustAuditBackend::Execute(
    const ObligationSet& scope, int rank, int world_size) {
    RobustAuditSessionOutput unavailable;
    last_abort_ = RobustAuditAbortOutput{};
    if (rank != rank_ || world_size != world_size_ ||
        scope.session_id == 0 || scope.checkpoint == 0)
        return unavailable;
    Entry* entry = FindEntry(scope.checkpoint, scope.session_id);
    if (!entry || !entry->session || !entry->session->sealed())
        return unavailable;

    auto ref_less = [](const OperationRef& a, const OperationRef& b) {
        if (a.owner != b.owner) return a.owner < b.owner;
        return a.object_id < b.object_id;
    };
    std::vector<OperationRef> requested = scope.operations;
    std::sort(requested.begin(), requested.end(), ref_less);
    std::vector<OperationRef> registered = entry->operations;
    std::sort(registered.begin(), registered.end(), ref_less);
    if (!same_refs(requested, registered)) return unavailable;

    const ReferenceShamirBatchResult reference = entry->session->BatchCheck();
    if (!reference.available || reference.checkpoint != scope.checkpoint ||
        reference.operation_count != registered.size())
        return unavailable;
    if (capabilities_.authenticated_channels &&
        (!entry->session->authenticated_transport_enabled() ||
         entry->session->authenticated_transport_capability_binding() !=
             capabilities_.authenticated_channel_capability_binding ||
         entry->session->authenticated_transport_transcript_binding() == Digest{}))
        return unavailable;

    if (capabilities_.malicious_multiplication_consistency !=
        (reference.multiplication_consistency_binding != Digest{}))
        return unavailable;

    BatchCheckResult batch;
    batch.available = true;
    batch.cryptographically_authenticated = false;
    batch.ok = reference.clean;
    batch.checkpoint = scope.checkpoint;
    batch.checked_operations = registered.size();
    batch.mismatches = reference.clean ? 0 : 1;
    batch.participant_count = static_cast<size_t>(world_size_);
    batch.scope_binding = compute_collective_scope_binding(scope);
    batch.challenge_transcript_binding = reference.challenge_binding;
    batch.aggregate_residual_commitment = reference.registration_binding;

    RobustAuditSessionOutput output;
    output.available = true;
    output.cryptographically_authenticated = false;
    output.completed = true;
    output.clean = reference.clean;
    output.security_level = RobustAuditSecurityLevel::REFERENCE_PASSIVE;
    output.sid = scope.session_id;
    output.checkpoint = scope.checkpoint;
    output.scope_binding = batch.scope_binding;
    output.activation_binding = entry->activation.activation_binding;
    output.capability_binding = capabilities_.capability_binding;
    if (capabilities_.authenticated_channels) {
        std::vector<u64> channel_words = {
            REF_AUTH_OUT_DOMAIN, scope.session_id, scope.checkpoint,
            reference.clean ? 1ULL : 0ULL,
            static_cast<u64>(registered.size())};
        append_digest(capabilities_.authenticated_channel_capability_binding,
                      &channel_words);
        append_digest(entry->activation.authenticated_channel_activation_binding,
                      &channel_words);
        append_digest(
            entry->session->authenticated_transport_transcript_binding(),
            &channel_words);
        append_digest(reference.registration_binding, &channel_words);
        append_digest(reference.public_coin_transcript_binding, &channel_words);
        append_digest(reference.opening_transcript_binding, &channel_words);
        output.authenticated_channel_transcript_binding = hash_words(channel_words);
        if (output.authenticated_channel_transcript_binding == Digest{})
            return unavailable;
    } else {
        output.authenticated_channel_transcript_binding = Digest{};
    }
    output.delivery_transcript_binding = Digest{};
    output.multiplication_consistency_binding =
        reference.multiplication_consistency_binding;
    output.batch = batch;
    std::vector<u64> transcript_words = {
        REF_ACT_DOMAIN, scope.session_id, scope.checkpoint,
        reference.clean ? 1ULL : 0ULL,
        static_cast<u64>(registered.size())};
    append_digest(reference.registration_binding, &transcript_words);
    append_digest(output.authenticated_channel_transcript_binding,
                  &transcript_words);
    append_digest(reference.public_coin_transcript_binding, &transcript_words);
    append_digest(reference.challenge_binding, &transcript_words);
    append_digest(reference.multiplication_consistency_binding,
                  &transcript_words);
    append_digest(reference.opening_transcript_binding, &transcript_words);
    output.execution_transcript_binding = hash_words(transcript_words);
    output.output_binding = compute_robust_audit_output_binding(output);
    return output;
}

bool ReferenceShamirRobustAuditBackend::VerifyPublicAbort(
    const AuditCheckpointView& checkpoint,
    const RobustAuditActivation* activation,
    const RobustAuditAbortOutput& output) const {
    if (!authenticated_exchange_ ||
        !production_ready_identifiable_abort_capabilities(capabilities_))
        return false;
    const auto transport = authenticated_exchange_->Capabilities();
    if (!production_ready_authenticated_mpc_transport_capabilities(transport) ||
        transport.capability_binding !=
            capabilities_.authenticated_channel_capability_binding ||
        transport.external_registry_anchor == Digest{})
        return false;
    return validate_robust_audit_abort_output(
        checkpoint, capabilities_, activation, output,
        transport.external_registry_anchor, world_size_);
}

bool ReferenceShamirRobustAuditBackend::VerifyPublicBlame(
    const PublicBlameStatement&,
    const PublicBlameProofArtifact&) const {
    return false;
}

} // namespace pvia
