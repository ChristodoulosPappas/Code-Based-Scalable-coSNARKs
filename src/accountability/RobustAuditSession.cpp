#include "RobustAuditSession.hpp"
#include "RobustAuditAbortCertificateCodec.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <utility>

namespace pvia {
namespace {
constexpr u64 CAP_DOMAIN = 0x5056524f42434150ULL;
constexpr u64 CKPT_DOMAIN = 0x5056524f42434b50ULL;
constexpr u64 BOOTSTRAP_SID_DOMAIN = 0x5056524253545349ULL; // PVRBSTSI
constexpr u64 ACT_DOMAIN = 0x5056524f42414354ULL;
constexpr u64 OUT_DOMAIN = 0x5056524f424f5554ULL;
constexpr u64 ABORT_DOMAIN = 0x5056524f42414254ULL; // PVROBABT
constexpr u64 ABORT_TRANSCRIPT_DOMAIN = 0x5056524142545452ULL; // PVRABTTR
constexpr u64 TERMINATION_DOMAIN = 0x5056525445524d31ULL; // PVRTERM1

void append_digest(const Digest& d, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 w = 0;
        std::memcpy(&w, d.bytes.data() + 8 * i, 8);
        words->push_back(w);
    }
}

void append_ref(const OperationRef& ref, std::vector<u64>* words) {
    words->push_back(ref.owner);
    words->push_back(ref.object_id);
}
} // namespace
Digest compute_robust_audit_capability_binding(
    const RobustAuditCapabilities& c) {
    std::vector<u64> words = {
        CAP_DOMAIN, c.available ? 1ULL : 0ULL, c.protocol_id,
        static_cast<u64>(c.security_level), c.malicious_secure ? 1ULL : 0ULL,
        c.authenticated_channels ? 1ULL : 0ULL,
        c.publicly_identifiable_abort ? 1ULL : 0ULL,
        c.guaranteed_output_delivery ? 1ULL : 0ULL,
        c.activation_before_failure ? 1ULL : 0ULL,
        c.private_witness_retention ? 1ULL : 0ULL,
        c.detectable_input_sharing ? 1ULL : 0ULL,
        c.public_registration_consistency ? 1ULL : 0ULL,
        c.robust_opening ? 1ULL : 0ULL,
        c.commit_reveal_public_coin ? 1ULL : 0ULL,
        c.detectable_degree_reduction ? 1ULL : 0ULL,
        c.detectable_random_sharing ? 1ULL : 0ULL,
        c.malicious_multiplication_consistency ? 1ULL : 0ULL,
        c.packed_sharing ? 1ULL : 0ULL, c.corruption_threshold,
        static_cast<u64>(c.supported_kernels.size())};
    for (AuditRelationKernel kernel : c.supported_kernels)
        words.push_back(static_cast<u64>(kernel));
    append_digest(c.authenticated_channel_capability_binding, &words);
    append_digest(c.identifiable_abort_capability_binding, &words);
    append_digest(c.delivery_capability_binding, &words);
    append_digest(c.registration_consistency_capability_binding, &words);
    append_digest(c.multiplication_consistency_capability_binding, &words);
    append_digest(c.implementation_binding, &words);
    return hash_words(words);
}

bool validate_robust_audit_capabilities(
    const RobustAuditCapabilities& c) {
    if (!c.available || c.protocol_id == 0 ||
        c.security_level == RobustAuditSecurityLevel::UNKNOWN ||
        c.implementation_binding == Digest{} || c.capability_binding == Digest{} ||
        c.supported_kernels.empty())
        return false;
    if (c.capability_binding != compute_robust_audit_capability_binding(c))
        return false;
    if (c.authenticated_channels !=
        (c.authenticated_channel_capability_binding != Digest{}))
        return false;
    if (c.publicly_identifiable_abort !=
        (c.identifiable_abort_capability_binding != Digest{}))
        return false;
    if (c.publicly_identifiable_abort && !c.authenticated_channels)
        return false;
    if (c.publicly_identifiable_abort) {
        const auto abort_capabilities =
            make_signed_equivocation_abort_evidence_capabilities(
                c.authenticated_channel_capability_binding);
        if (!production_ready_authenticated_mpc_abort_evidence_capabilities(
                abort_capabilities) ||
            c.identifiable_abort_capability_binding !=
                abort_capabilities.capability_binding)
            return false;
    }
    if (c.guaranteed_output_delivery !=
        (c.delivery_capability_binding != Digest{}))
        return false;
    if (c.public_registration_consistency !=
        (c.registration_consistency_capability_binding != Digest{}))
        return false;
    if (c.malicious_multiplication_consistency !=
        (c.multiplication_consistency_capability_binding != Digest{}))
        return false;
    if (c.malicious_secure &&
        c.security_level == RobustAuditSecurityLevel::REFERENCE_PASSIVE)
        return false;
    if (c.guaranteed_output_delivery &&
        c.security_level != RobustAuditSecurityLevel::MALICIOUS_GOD)
        return false;
    return true;
}
bool production_ready_robust_audit_capabilities(
    const RobustAuditCapabilities& c) {
    return validate_robust_audit_capabilities(c) && c.malicious_secure &&
        c.authenticated_channels && c.guaranteed_output_delivery &&
        c.activation_before_failure &&
        c.private_witness_retention && c.detectable_input_sharing &&
        c.public_registration_consistency && c.robust_opening &&
        c.commit_reveal_public_coin && c.detectable_degree_reduction &&
        c.detectable_random_sharing &&
        c.malicious_multiplication_consistency &&
        c.security_level == RobustAuditSecurityLevel::MALICIOUS_GOD;
}

bool production_ready_identifiable_abort_capabilities(
    const RobustAuditCapabilities& c) {
    return validate_robust_audit_capabilities(c) &&
        c.malicious_secure && c.authenticated_channels &&
        c.publicly_identifiable_abort && c.activation_before_failure &&
        c.private_witness_retention && c.detectable_input_sharing &&
        c.public_registration_consistency && c.robust_opening &&
        c.commit_reveal_public_coin && c.detectable_degree_reduction &&
        c.detectable_random_sharing && c.malicious_multiplication_consistency &&
        (c.security_level == RobustAuditSecurityLevel::MALICIOUS_ABORT ||
         c.security_level == RobustAuditSecurityLevel::MALICIOUS_GOD);
}

bool robust_audit_supports_kernel(
    const RobustAuditCapabilities& c, AuditRelationKernel kernel) {
    return validate_robust_audit_capabilities(c) &&
        std::find(c.supported_kernels.begin(), c.supported_kernels.end(), kernel) !=
            c.supported_kernels.end();
}

Digest compute_robust_checkpoint_binding(
    const AuditCheckpointView& checkpoint) {
    std::vector<u64> words = {
        CKPT_DOMAIN, checkpoint.id, static_cast<u64>(checkpoint.phase),
        checkpoint.round, checkpoint.generation,
        checkpoint.sealed ? 1ULL : 0ULL,
        static_cast<u64>(checkpoint.operations.size())};
    for (const OperationRef& ref : checkpoint.operations)
        append_ref(ref, &words);
    append_digest(checkpoint.root, &words);
    return hash_words(words);
}

uint64_t compute_robust_bootstrap_transport_sid(
    const AuditCheckpointView& checkpoint) {
    if (!checkpoint.sealed || checkpoint.id == 0 ||
        checkpoint.root == Digest{})
        return 0;
    const Digest checkpoint_binding = compute_robust_checkpoint_binding(checkpoint);
    if (checkpoint_binding == Digest{}) return 0;
    std::vector<u64> words = {
        BOOTSTRAP_SID_DOMAIN, checkpoint.id,
        static_cast<u64>(checkpoint.phase), checkpoint.round,
        checkpoint.generation};
    append_digest(checkpoint_binding, &words);
    const Digest namespace_binding = hash_words(words);
    if (namespace_binding == Digest{}) return 0;
    u64 sid = 0;
    std::memcpy(&sid, namespace_binding.bytes.data(), sizeof(sid));
    return sid == 0 ? 1ULL : sid;
}

Digest compute_robust_audit_activation_binding(
    const RobustAuditActivation& a) {
    std::vector<u64> words = {
        ACT_DOMAIN, a.available ? 1ULL : 0ULL, a.sid, a.checkpoint,
        static_cast<u64>(a.registered_operations)};
    append_digest(a.checkpoint_root, &words);
    append_digest(a.checkpoint_binding, &words);
    append_digest(a.capability_binding, &words);
    append_digest(a.authenticated_channel_activation_binding, &words);
    append_digest(a.delivery_activation_binding, &words);
    append_digest(a.registration_consistency_binding, &words);
    append_digest(a.activation_transcript_binding, &words);
    return hash_words(words);
}
bool validate_robust_audit_activation(
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation& activation) {
    if (!validate_robust_audit_capabilities(capabilities) ||
        !activation.available || activation.sid == 0 ||
        activation.checkpoint == 0 || activation.checkpoint != checkpoint.id ||
        !checkpoint.sealed || checkpoint.root == Digest{} ||
        activation.checkpoint_root != checkpoint.root ||
        activation.registered_operations == 0 ||
        activation.registered_operations > checkpoint.operations.size() ||
        activation.capability_binding != capabilities.capability_binding ||
        activation.activation_transcript_binding == Digest{})
        return false;
    if (activation.checkpoint_binding != compute_robust_checkpoint_binding(checkpoint))
        return false;
    if (capabilities.authenticated_channels !=
        (activation.authenticated_channel_activation_binding != Digest{}))
        return false;
    if (capabilities.guaranteed_output_delivery !=
        (activation.delivery_activation_binding != Digest{}))
        return false;
    if (capabilities.public_registration_consistency !=
        (activation.registration_consistency_binding != Digest{}))
        return false;
    return activation.activation_binding ==
        compute_robust_audit_activation_binding(activation);
}

Digest compute_robust_audit_output_binding(
    const RobustAuditSessionOutput& output) {
    std::vector<u64> words = {
        OUT_DOMAIN, output.available ? 1ULL : 0ULL,
        output.cryptographically_authenticated ? 1ULL : 0ULL,
        output.completed ? 1ULL : 0ULL, output.clean ? 1ULL : 0ULL,
        static_cast<u64>(output.security_level), output.sid,
        output.checkpoint};
    append_digest(output.scope_binding, &words);
    append_digest(output.activation_binding, &words);
    append_digest(output.capability_binding, &words);
    append_digest(output.authenticated_channel_transcript_binding, &words);
    append_digest(output.delivery_transcript_binding, &words);
    append_digest(output.multiplication_consistency_binding, &words);
    append_digest(output.batch.scope_binding, &words);
    append_digest(output.batch.aggregate_residual_commitment, &words);
    append_digest(output.violation.dispute_binding, &words);
    append_digest(output.recovery.recovered_audit_commitment, &words);
    append_digest(output.statement.statement_binding, &words);
    append_digest(output.proof.proof_commitment, &words);
    append_digest(output.execution_transcript_binding, &words);
    return hash_words(words);
}
Digest compute_robust_audit_abort_transcript_binding(
    const RobustAuditAbortOutput& output) {
    if (!output.available || !output.publicly_verifiable ||
        output.stage == RobustAuditAbortStage::UNKNOWN ||
        output.checkpoint == 0 || output.capability_binding == Digest{} ||
        output.authenticated_channel_capability_binding == Digest{} ||
        output.external_registry_anchor == Digest{} ||
        output.equivocation.evidence_binding == Digest{})
        return Digest{};
    std::vector<u64> words = {
        ABORT_TRANSCRIPT_DOMAIN, static_cast<u64>(output.stage),
        output.sid, output.checkpoint, static_cast<u64>(output.accused)};
    append_digest(output.capability_binding, &words);
    append_digest(output.authenticated_channel_capability_binding, &words);
    append_digest(output.activation_binding, &words);
    append_digest(output.external_registry_anchor, &words);
    append_digest(output.equivocation.evidence_binding, &words);
    return hash_words(words);
}

Digest compute_robust_audit_abort_binding(
    const RobustAuditAbortOutput& output) {
    std::vector<u64> words = {
        ABORT_DOMAIN, output.available ? 1ULL : 0ULL,
        output.publicly_verifiable ? 1ULL : 0ULL,
        static_cast<u64>(output.stage), output.sid, output.checkpoint,
        static_cast<u64>(output.accused)};
    append_digest(output.checkpoint_root, &words);
    append_digest(output.checkpoint_binding, &words);
    append_digest(output.capability_binding, &words);
    append_digest(output.authenticated_channel_capability_binding, &words);
    append_digest(output.activation_binding, &words);
    append_digest(output.external_registry_anchor, &words);
    append_digest(output.equivocation.evidence_binding, &words);
    append_digest(output.abort_transcript_binding, &words);
    return hash_words(words);
}

Digest compute_robust_audit_termination_binding(
    const RobustAuditTerminationOutput& output) {
    std::vector<u64> words = {
        TERMINATION_DOMAIN, output.available ? 1ULL : 0ULL,
        static_cast<u64>(output.kind), static_cast<u64>(output.stage),
        static_cast<u64>(output.unattributable_reason),
        output.sid, output.checkpoint,
        output.authenticated_route ? 1ULL : 0ULL,
        output.completed ? 1ULL : 0ULL,
        output.detectable_abort ? 1ULL : 0ULL,
        output.publicly_attributable ? 1ULL : 0ULL};
    append_digest(output.checkpoint_root, &words);
    append_digest(output.checkpoint_binding, &words);
    append_digest(output.capability_binding, &words);
    append_digest(output.activation_binding, &words);
    append_digest(output.completed_output_binding, &words);
    append_digest(output.public_abort_binding, &words);
    append_digest(output.local_failure_binding, &words);
    return hash_words(words);
}

bool validate_robust_audit_termination_output(
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation* activation,
    const RobustAuditTerminationOutput& output) {
    if (!validate_robust_audit_capabilities(capabilities) ||
        !output.available || output.kind == RobustAuditTerminationKind::UNKNOWN ||
        output.stage == RobustAuditAbortStage::UNKNOWN ||
        output.checkpoint == 0 || output.checkpoint != checkpoint.id ||
        !checkpoint.sealed || checkpoint.root == Digest{} ||
        output.checkpoint_root != checkpoint.root ||
        output.checkpoint_binding != compute_robust_checkpoint_binding(checkpoint) ||
        output.capability_binding != capabilities.capability_binding ||
        output.authenticated_route != capabilities.authenticated_channels ||
        output.termination_binding == Digest{})
        return false;
    if (output.stage == RobustAuditAbortStage::ACTIVATION) {
        if (activation != nullptr || output.sid != 0 ||
            output.activation_binding != Digest{}) return false;
    } else if (output.stage == RobustAuditAbortStage::EXECUTION) {
        if (!activation ||
            !validate_robust_audit_activation(checkpoint, capabilities, *activation) ||
            output.sid != activation->sid ||
            output.activation_binding != activation->activation_binding)
            return false;
    } else return false;
    if (output.kind == RobustAuditTerminationKind::COMPLETED) {
        if (output.stage != RobustAuditAbortStage::EXECUTION ||
            output.unattributable_reason !=
                RobustAuditUnattributableAbortReason::UNKNOWN ||
            !output.completed || output.detectable_abort ||
            output.publicly_attributable ||
            output.completed_output_binding == Digest{} ||
            output.public_abort_binding != Digest{} ||
            output.local_failure_binding != Digest{})
            return false;
    } else if (output.kind ==
               RobustAuditTerminationKind::DETECTABLE_UNATTRIBUTABLE_ABORT) {
        const bool transport_failure =
            output.unattributable_reason ==
                RobustAuditUnattributableAbortReason::AUTHENTICATED_TRANSPORT_FAILURE;
        const bool reason_matches_stage = transport_failure ||
            (output.stage == RobustAuditAbortStage::ACTIVATION &&
             output.unattributable_reason ==
                 RobustAuditUnattributableAbortReason::ACTIVATION_UNAVAILABLE) ||
            (output.stage == RobustAuditAbortStage::EXECUTION &&
             output.unattributable_reason ==
                 RobustAuditUnattributableAbortReason::EXECUTION_UNAVAILABLE);
        const bool failure_binding_matches_reason = transport_failure
            ? output.local_failure_binding != Digest{}
            : output.local_failure_binding == Digest{};
        if (!output.authenticated_route || !reason_matches_stage ||
            !failure_binding_matches_reason || output.completed ||
            !output.detectable_abort || output.publicly_attributable ||
            output.completed_output_binding != Digest{} ||
            output.public_abort_binding != Digest{})
            return false;
    } else if (output.kind ==
               RobustAuditTerminationKind::PUBLICLY_ATTRIBUTABLE_ABORT) {
        if (output.unattributable_reason !=
                RobustAuditUnattributableAbortReason::UNKNOWN ||
            output.completed || !output.detectable_abort ||
            !output.publicly_attributable ||
            output.completed_output_binding != Digest{} ||
            output.public_abort_binding == Digest{} ||
            output.local_failure_binding != Digest{})
            return false;
    } else {
        return false;
    }
    return output.termination_binding ==
        compute_robust_audit_termination_binding(output);
}

bool build_robust_audit_termination_from_validated_session_output(
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation& activation,
    const RobustAuditSessionOutput& session_output,
    RobustAuditTerminationOutput* output) {
    if (!output || !session_output.available || !session_output.completed ||
        session_output.output_binding == Digest{} ||
        session_output.sid != activation.sid ||
        session_output.checkpoint != checkpoint.id ||
        session_output.activation_binding != activation.activation_binding ||
        session_output.capability_binding != capabilities.capability_binding)
        return false;
    RobustAuditTerminationOutput candidate;
    candidate.available = true;
    candidate.kind = RobustAuditTerminationKind::COMPLETED;
    candidate.stage = RobustAuditAbortStage::EXECUTION;
    candidate.sid = activation.sid;
    candidate.checkpoint = checkpoint.id;
    candidate.checkpoint_root = checkpoint.root;
    candidate.checkpoint_binding = compute_robust_checkpoint_binding(checkpoint);
    candidate.capability_binding = capabilities.capability_binding;
    candidate.activation_binding = activation.activation_binding;
    candidate.authenticated_route = capabilities.authenticated_channels;
    candidate.completed = true;
    candidate.completed_output_binding = session_output.output_binding;
    candidate.termination_binding =
        compute_robust_audit_termination_binding(candidate);
    if (!validate_robust_audit_termination_output(
            checkpoint, capabilities, &activation, candidate)) return false;
    *output = candidate;
    return true;
}

bool build_robust_audit_unattributable_abort_termination(
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation* activation,
    RobustAuditAbortStage stage,
    RobustAuditUnattributableAbortReason reason,
    RobustAuditTerminationOutput* output) {
    if (!output || !capabilities.authenticated_channels ||
        stage == RobustAuditAbortStage::UNKNOWN ||
        reason == RobustAuditUnattributableAbortReason::UNKNOWN ||
        reason == RobustAuditUnattributableAbortReason::AUTHENTICATED_TRANSPORT_FAILURE)
        return false;
    RobustAuditTerminationOutput candidate;
    candidate.available = true;
    candidate.kind = RobustAuditTerminationKind::DETECTABLE_UNATTRIBUTABLE_ABORT;
    candidate.stage = stage;
    candidate.unattributable_reason = reason;
    candidate.sid = activation ? activation->sid : 0;
    candidate.checkpoint = checkpoint.id;
    candidate.checkpoint_root = checkpoint.root;
    candidate.checkpoint_binding = compute_robust_checkpoint_binding(checkpoint);
    candidate.capability_binding = capabilities.capability_binding;
    candidate.activation_binding = activation ? activation->activation_binding : Digest{};
    candidate.authenticated_route = true;
    candidate.detectable_abort = true;
    candidate.termination_binding =
        compute_robust_audit_termination_binding(candidate);
    if (!validate_robust_audit_termination_output(
            checkpoint, capabilities, activation, candidate)) return false;
    *output = candidate;
    return true;
}

bool build_robust_audit_transport_failure_termination(
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation* activation,
    RobustAuditAbortStage stage,
    const Digest& local_failure_binding,
    RobustAuditTerminationOutput* output) {
    if (!output || !capabilities.authenticated_channels ||
        stage == RobustAuditAbortStage::UNKNOWN ||
        local_failure_binding == Digest{})
        return false;
    RobustAuditTerminationOutput candidate;
    candidate.available = true;
    candidate.kind = RobustAuditTerminationKind::DETECTABLE_UNATTRIBUTABLE_ABORT;
    candidate.stage = stage;
    candidate.unattributable_reason =
        RobustAuditUnattributableAbortReason::AUTHENTICATED_TRANSPORT_FAILURE;
    candidate.sid = activation ? activation->sid : 0;
    candidate.checkpoint = checkpoint.id;
    candidate.checkpoint_root = checkpoint.root;
    candidate.checkpoint_binding = compute_robust_checkpoint_binding(checkpoint);
    candidate.capability_binding = capabilities.capability_binding;
    candidate.activation_binding = activation ? activation->activation_binding : Digest{};
    candidate.authenticated_route = true;
    candidate.detectable_abort = true;
    candidate.local_failure_binding = local_failure_binding;
    candidate.termination_binding =
        compute_robust_audit_termination_binding(candidate);
    if (!validate_robust_audit_termination_output(
            checkpoint, capabilities, activation, candidate)) return false;
    *output = candidate;
    return true;
}

bool build_robust_audit_termination_from_verified_public_abort(
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation* activation,
    const RobustAuditAbortOutput& verified_abort,
    RobustAuditTerminationOutput* output) {
    if (!output || !verified_abort.available ||
        !verified_abort.publicly_verifiable ||
        verified_abort.abort_binding == Digest{} ||
        verified_abort.checkpoint != checkpoint.id ||
        verified_abort.capability_binding != capabilities.capability_binding)
        return false;
    RobustAuditTerminationOutput candidate;
    candidate.available = true;
    candidate.kind = RobustAuditTerminationKind::PUBLICLY_ATTRIBUTABLE_ABORT;
    candidate.stage = verified_abort.stage;
    candidate.sid = verified_abort.sid;
    candidate.checkpoint = checkpoint.id;
    candidate.checkpoint_root = checkpoint.root;
    candidate.checkpoint_binding = compute_robust_checkpoint_binding(checkpoint);
    candidate.capability_binding = capabilities.capability_binding;
    candidate.activation_binding = activation ? activation->activation_binding : Digest{};
    candidate.authenticated_route = capabilities.authenticated_channels;
    candidate.detectable_abort = true;
    candidate.publicly_attributable = true;
    candidate.public_abort_binding = verified_abort.abort_binding;
    candidate.termination_binding =
        compute_robust_audit_termination_binding(candidate);
    if (!validate_robust_audit_termination_output(
            checkpoint, capabilities, activation, candidate)) return false;
    *output = candidate;
    return true;
}

namespace {
bool validate_robust_audit_abort_output_impl(
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation* activation,
    const RobustAuditAbortOutput& output,
    const Digest& expected_registry_anchor,
    int world_size,
    bool verify_equivocation);
} // namespace

bool build_robust_audit_abort_output_from_equivocation(
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation* activation,
    const AuthenticatedMpcEquivocationEvidence& evidence,
    const Digest& expected_registry_anchor,
    int world_size, RobustAuditAbortOutput* output) {
    if (!output || !production_ready_identifiable_abort_capabilities(capabilities) ||
        expected_registry_anchor == Digest{} || world_size <= 0 ||
        !verify_authenticated_mpc_equivocation_evidence(
            evidence, expected_registry_anchor) ||
        evidence.public_keys.size() != static_cast<size_t>(world_size) ||
        evidence.context.checkpoint != checkpoint.id)
        return false;
    RobustAuditAbortOutput candidate;
    candidate.available = true;
    candidate.publicly_verifiable = true;
    candidate.stage = activation ? RobustAuditAbortStage::EXECUTION
                                 : RobustAuditAbortStage::ACTIVATION;
    candidate.sid = activation ? activation->sid : 0;
    candidate.checkpoint = checkpoint.id;
    candidate.checkpoint_root = checkpoint.root;
    candidate.checkpoint_binding = compute_robust_checkpoint_binding(checkpoint);
    candidate.accused = evidence.sender;
    candidate.capability_binding = capabilities.capability_binding;
    candidate.authenticated_channel_capability_binding =
        capabilities.authenticated_channel_capability_binding;
    candidate.activation_binding = activation ? activation->activation_binding : Digest{};
    candidate.external_registry_anchor = expected_registry_anchor;
    candidate.equivocation = evidence;
    candidate.abort_transcript_binding =
        compute_robust_audit_abort_transcript_binding(candidate);
    candidate.abort_binding = compute_robust_audit_abort_binding(candidate);
    // The equivocation evidence was fully verified at function entry.
    // Re-run all structural/transcript/binding checks on the assembled abort
    // output, but do not repeat the same signature verification in this
    // trusted builder call stack. Public/Judge validation still uses the
    // full validator below.
    if (!validate_robust_audit_abort_output_impl(
            checkpoint, capabilities, activation, candidate,
            expected_registry_anchor, world_size, false))
        return false;
    *output = candidate;
    return true;
}

bool build_robust_audit_abort_output_from_observations(
    const std::vector<AuthenticatedMpcSignedEnvelopeObservation>& observations,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const AuthenticatedMpcTransportCapabilities& transport,
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation* activation,
    int world_size, RobustAuditAbortOutput* output,
    Digest* observation_set_binding) {
    if (observation_set_binding) *observation_set_binding = Digest{};
    if (!output || observations.empty() || world_size <= 0 ||
        public_keys.size() != static_cast<size_t>(world_size) ||
        !production_ready_identifiable_abort_capabilities(capabilities) ||
        !production_ready_authenticated_mpc_transport_capabilities(transport) ||
        transport.capability_binding !=
            capabilities.authenticated_channel_capability_binding ||
        transport.external_registry_anchor == Digest{} ||
        transport.external_registry_anchor != transport.registry_commitment ||
        compute_ed25519_registry_commitment(public_keys) !=
            transport.registry_commitment)
        return false;
    const auto reconciled = reconcile_authenticated_mpc_observations(
        observations, public_keys, transport.external_registry_anchor);
    if (!reconciled.valid || !reconciled.equivocation_found ||
        reconciled.observation_set_binding == Digest{})
        return false;
    RobustAuditAbortOutput candidate;
    if (!build_robust_audit_abort_output_from_equivocation(
            checkpoint, capabilities, activation, reconciled.evidence,
            transport.external_registry_anchor, world_size, &candidate))
        return false;
    *output = std::move(candidate);
    if (observation_set_binding)
        *observation_set_binding = reconciled.observation_set_binding;
    return true;
}

bool build_robust_audit_abort_output_from_exchange(
    const AuthenticatedMpcExchange& exchange,
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation* activation,
    int world_size, RobustAuditAbortOutput* output) {
    if (!output ||
        !production_ready_identifiable_abort_capabilities(capabilities))
        return false;
    const auto transport = exchange.Capabilities();
    if (!production_ready_authenticated_mpc_transport_capabilities(transport))
        return false;
    const uint64_t evidence_sid = activation
        ? activation->sid
        : compute_robust_bootstrap_transport_sid(checkpoint);
    const auto& auth = Ed25519TransferAuthenticator::instance();
    std::vector<AuthenticatedMpcSignedEnvelopeObservation> observations;
    if (evidence_sid == 0 || !auth.ready() ||
        !exchange.ExportVerifiedEnvelopeObservations(
            evidence_sid, checkpoint.id, &observations))
        return false;
    return build_robust_audit_abort_output_from_observations(
        observations, auth.PublicKeys(), transport,
        checkpoint, capabilities, activation, world_size, output, nullptr);
}

bool build_robust_audit_abort_output_from_reconciled_exchange(
    const AuthenticatedMpcExchange& exchange,
    const AuthenticatedMpcMessageContext& reconciliation_context,
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation* activation,
    int world_size, RobustAuditAbortOutput* output,
    Digest* observation_set_binding,
    Digest* reconciliation_transcript_binding) {
    if (observation_set_binding) *observation_set_binding = Digest{};
    if (reconciliation_transcript_binding)
        *reconciliation_transcript_binding = Digest{};
    if (!output ||
        !production_ready_identifiable_abort_capabilities(capabilities) ||
        world_size <= 0)
        return false;
    const auto transport = exchange.Capabilities();
    if (!production_ready_authenticated_mpc_transport_capabilities(transport) ||
        transport.capability_binding !=
            capabilities.authenticated_channel_capability_binding ||
        transport.external_registry_anchor == Digest{} ||
        transport.external_registry_anchor != transport.registry_commitment)
        return false;
    const uint64_t evidence_sid = activation
        ? activation->sid
        : compute_robust_bootstrap_transport_sid(checkpoint);
    if (evidence_sid == 0 ||
        reconciliation_context.sid != evidence_sid ||
        reconciliation_context.checkpoint != checkpoint.id)
        return false;

    AuthenticatedMpcObservationReconciliation reconciled;
    Digest reconciliation_binding{};
    if (!exchange.ReconcileCheckpointObservations(
            reconciliation_context, evidence_sid, checkpoint.id,
            &reconciled, &reconciliation_binding) ||
        !reconciled.valid || !reconciled.equivocation_found ||
        reconciled.observation_set_binding == Digest{} ||
        reconciliation_binding == Digest{})
        return false;

    RobustAuditAbortOutput candidate;
    if (!build_robust_audit_abort_output_from_equivocation(
            checkpoint, capabilities, activation, reconciled.evidence,
            transport.external_registry_anchor, world_size, &candidate))
        return false;
    *output = std::move(candidate);
    if (observation_set_binding)
        *observation_set_binding = reconciled.observation_set_binding;
    if (reconciliation_transcript_binding)
        *reconciliation_transcript_binding = reconciliation_binding;
    return true;
}

namespace {
bool validate_robust_audit_abort_output_impl(
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation* activation,
    const RobustAuditAbortOutput& output,
    const Digest& expected_registry_anchor,
    int world_size,
    bool verify_equivocation) {
    if (!production_ready_identifiable_abort_capabilities(capabilities) ||
        !output.available || !output.publicly_verifiable ||
        output.stage == RobustAuditAbortStage::UNKNOWN ||
        world_size <= 0 || output.checkpoint == 0 ||
        output.checkpoint != checkpoint.id || !checkpoint.sealed ||
        checkpoint.root == Digest{} || output.checkpoint_root != checkpoint.root ||
        output.checkpoint_binding != compute_robust_checkpoint_binding(checkpoint) ||
        output.accused >= static_cast<uint32_t>(world_size) ||
        output.capability_binding != capabilities.capability_binding ||
        output.authenticated_channel_capability_binding !=
            capabilities.authenticated_channel_capability_binding ||
        expected_registry_anchor == Digest{} ||
        output.external_registry_anchor != expected_registry_anchor ||
        output.equivocation.sender != output.accused ||
        output.equivocation.public_keys.size() !=
            static_cast<size_t>(world_size) ||
        output.equivocation.context.checkpoint != output.checkpoint ||
        output.abort_transcript_binding == Digest{} ||
        output.abort_binding == Digest{})
        return false;
    if (verify_equivocation &&
        !verify_authenticated_mpc_equivocation_evidence(
            output.equivocation, expected_registry_anchor))
        return false;
    if (output.stage == RobustAuditAbortStage::ACTIVATION) {
        if (activation != nullptr || output.activation_binding != Digest{})
            return false;
        const uint64_t bootstrap_sid =
            compute_robust_bootstrap_transport_sid(checkpoint);
        if (bootstrap_sid == 0 || output.sid != 0 ||
            output.equivocation.context.sid != bootstrap_sid)
            return false;
    } else if (output.stage == RobustAuditAbortStage::EXECUTION) {
        if (!activation || !activation->available || activation->sid == 0 ||
            activation->checkpoint != output.checkpoint ||
            output.sid != activation->sid ||
            output.activation_binding != activation->activation_binding ||
            output.equivocation.context.sid != output.sid)
            return false;
    } else {
        return false;
    }
    if (output.abort_transcript_binding !=
        compute_robust_audit_abort_transcript_binding(output))
        return false;
    return output.abort_binding == compute_robust_audit_abort_binding(output);
}
} // namespace

bool validate_robust_audit_abort_output(
    const AuditCheckpointView& checkpoint,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation* activation,
    const RobustAuditAbortOutput& output,
    const Digest& expected_registry_anchor,
    int world_size) {
    return validate_robust_audit_abort_output_impl(
        checkpoint, capabilities, activation, output,
        expected_registry_anchor, world_size, true);
}

bool validate_robust_audit_session_output(
    const ObligationSet& scope,
    const RobustAuditCapabilities& capabilities,
    const RobustAuditActivation& activation,
    const RobustAuditSessionOutput& output,
    int world_size) {
    if (!validate_robust_audit_capabilities(capabilities) ||
        !activation.available || !output.available || !output.completed ||
        world_size <= 0 || output.sid != scope.session_id ||
        output.checkpoint != scope.checkpoint ||
        output.checkpoint != activation.checkpoint ||
        output.security_level != capabilities.security_level ||
        output.scope_binding != compute_collective_scope_binding(scope) ||
        output.activation_binding != activation.activation_binding ||
        output.capability_binding != capabilities.capability_binding ||
        output.execution_transcript_binding == Digest{} ||
        output.output_binding == Digest{})
        return false;
    if (output.output_binding != compute_robust_audit_output_binding(output))
        return false;
    if (capabilities.authenticated_channels !=
        (output.authenticated_channel_transcript_binding != Digest{}))
        return false;
    if (capabilities.guaranteed_output_delivery !=
        (output.delivery_transcript_binding != Digest{}))
        return false;
    if (output.cryptographically_authenticated != capabilities.malicious_secure)
        return false;
    if (!output.batch.available ||
        output.batch.checkpoint != scope.checkpoint ||
        output.batch.scope_binding != output.scope_binding ||
        output.batch.participant_count != static_cast<size_t>(world_size) ||
        output.batch.cryptographically_authenticated !=
            capabilities.malicious_secure)
        return false;

    if (capabilities.malicious_multiplication_consistency !=
        (output.multiplication_consistency_binding != Digest{}))
        return false;

    if (output.clean) {
        if (!output.batch.ok || output.violation.valid ||
            output.recovery.available ||
            output.statement.statement_binding != Digest{} ||
            output.proof.available)
            return false;
        return true;
    }

    if (!production_ready_robust_audit_capabilities(capabilities) ||
        !output.cryptographically_authenticated || output.batch.ok ||
        output.batch.mismatches == 0 || !output.violation.valid ||
        !output.recovery.available ||
        !output.recovery.cryptographically_authenticated ||
        output.statement.statement_binding == Digest{} ||
        !output.proof.available || !output.proof.cryptographically_authenticated)
        return false;
    if (output.violation.checkpoint != scope.checkpoint ||
        output.recovery.checkpoint != scope.checkpoint ||
        output.proof.statement_binding != output.statement.statement_binding)
        return false;

    AuditCheckpointView checkpoint;
    checkpoint.id = scope.checkpoint;
    checkpoint.phase = scope.phase;
    checkpoint.round = scope.round;
    checkpoint.generation = scope.generation;
    checkpoint.operations = scope.operations;
    checkpoint.root = scope.checkpoint_root;
    checkpoint.sealed = true;
    const AuthenticatedRecoveryRequest recovery_request =
        make_recovery_request(output.violation, checkpoint);
    if (recovery_request.request_binding == Digest{} ||
        !validate_recovery_artifact(recovery_request, output.recovery))
        return false;

    RecoverableAuditShare recovered_audit;
    recovered_audit.valid = true;
    recovered_audit.debug_only = false;
    recovered_audit.evidence_kind = AuditEvidenceKind::PRIVATE_RECOVERY;
    recovered_audit.label = output.violation.label;
    recovered_audit.relation = output.violation.relation;
    recovered_audit.kernel = output.violation.kernel;
    recovered_audit.expected = output.violation.expected;
    recovered_audit.actual = output.violation.actual;
    recovered_audit.residual_commitment =
        output.violation.residual_commitment;
    recovered_audit.operation_statement_binding =
        output.violation.operation_statement_binding;
    recovered_audit.dispute_binding = output.violation.dispute_binding;
    recovered_audit.predecessor_root = output.recovery.predecessor_root;
    recovered_audit.checkpoint_root = output.recovery.checkpoint_root;
    recovered_audit.witness_digest =
        compute_recovery_artifact_binding(output.recovery);
    const PublicBlameStatement expected_statement =
        make_public_blame_statement(
            output.violation, recovered_audit, output.recovery);
    if (expected_statement.statement_binding == Digest{} ||
        output.statement.statement_binding !=
            expected_statement.statement_binding ||
        output.statement.evidence_kind != AuditEvidenceKind::PRIVATE_RECOVERY ||
        !validate_public_blame_proof_artifact(output.statement, output.proof))
        return false;
    return true;
}

bool run_robust_audit_abort_output_selftest(int rank, int world_size) {
    if (world_size < 2 || rank < 0 || rank >= world_size) return false;
    auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.ready() || !auth.ExternalRegistryAnchorVerified() ||
        auth.ExternalRegistryAnchor() != auth.RegistryCommitment())
        return false;
    AuthenticatedMpcExchange exchange(rank, world_size);
    const Digest transport_binding = exchange.ProductionCapabilityBinding();
    const auto abort_caps =
        make_signed_equivocation_abort_evidence_capabilities(transport_binding);
    if (!production_ready_authenticated_mpc_abort_evidence_capabilities(
            abort_caps))
        return false;

    RobustAuditCapabilities capabilities;
    capabilities.available = true;
    capabilities.protocol_id = 0x4142525453454c46ULL; // ABRTSELF
    capabilities.security_level = RobustAuditSecurityLevel::MALICIOUS_ABORT;
    capabilities.malicious_secure = true;
    capabilities.authenticated_channels = true;
    capabilities.publicly_identifiable_abort = true;
    capabilities.guaranteed_output_delivery = false;
    capabilities.activation_before_failure = true;
    capabilities.private_witness_retention = true;
    capabilities.detectable_input_sharing = true;
    capabilities.public_registration_consistency = true;
    capabilities.robust_opening = true;
    capabilities.commit_reveal_public_coin = true;
    capabilities.detectable_degree_reduction = true;
    capabilities.detectable_random_sharing = true;
    capabilities.malicious_multiplication_consistency = true;
    capabilities.supported_kernels = {AuditRelationKernel::FOLD_RS};
    capabilities.authenticated_channel_capability_binding = transport_binding;
    capabilities.identifiable_abort_capability_binding = abort_caps.capability_binding;
    capabilities.registration_consistency_capability_binding =
        hash_words({0x4142525452454743ULL, 1ULL});
    capabilities.multiplication_consistency_capability_binding =
        hash_words({0x414252544d554c43ULL, 1ULL});
    capabilities.implementation_binding =
        hash_words({0x41425254494d5031ULL, 1ULL});
    capabilities.capability_binding =
        compute_robust_audit_capability_binding(capabilities);
    if (!production_ready_identifiable_abort_capabilities(capabilities) ||
        production_ready_robust_audit_capabilities(capabilities))
        return false;

    AuditCheckpointView checkpoint;
    checkpoint.id = 0x41425254434b5031ULL; // ABRTCKP1
    checkpoint.phase = Phase::FOLD;
    checkpoint.round = 7;
    checkpoint.generation = 3;
    checkpoint.operations = {OperationRef{0, 1}};
    checkpoint.root = hash_words({0x41425254434b5054ULL, checkpoint.id});
    checkpoint.sealed = true;
    const uint64_t bootstrap_sid =
        compute_robust_bootstrap_transport_sid(checkpoint);
    if (bootstrap_sid == 0) return false;
    AuditCheckpointView next_generation = checkpoint;
    ++next_generation.generation;
    if (compute_robust_checkpoint_binding(next_generation) ==
            compute_robust_checkpoint_binding(checkpoint) ||
        compute_robust_bootstrap_transport_sid(next_generation) ==
            bootstrap_sid)
        return false;

    AuthenticatedMpcMessageContext bridge_context;
    bridge_context.protocol_domain = 0x4142525442524447ULL; // ABRTBRDG
    bridge_context.sid = bootstrap_sid;
    bridge_context.checkpoint = checkpoint.id;
    bridge_context.round = checkpoint.round;
    bridge_context.sequence = 1;
    bridge_context.message_kind = 0x4142525445515631ULL; // ABRTEQV1
    std::vector<u64> bridge_gathered;
    Digest bridge_transcript{};
    if (!exchange.AllGatherWords(
            bridge_context, {static_cast<u64>(rank), 41ULL},
            &bridge_gathered, &bridge_transcript) ||
        bridge_transcript == Digest{})
        return false;
    if (exchange.AllGatherWords(
            bridge_context, {static_cast<u64>(rank), 41ULL},
            &bridge_gathered, &bridge_transcript))
        return false;
    AuthenticatedMpcLocalFailureObservation replay_failure;
    if (!exchange.LastLocalFailure(
            bootstrap_sid, checkpoint.id, &replay_failure) ||
        replay_failure.kind != AuthenticatedMpcLocalFailureKind::EXACT_REPLAY ||
        replay_failure.failure_binding == Digest{})
        return false;
    RobustAuditTerminationOutput transport_failure_termination;
    if (!build_robust_audit_transport_failure_termination(
            checkpoint, capabilities, nullptr,
            RobustAuditAbortStage::ACTIVATION,
            replay_failure.failure_binding, &transport_failure_termination) ||
        transport_failure_termination.kind !=
            RobustAuditTerminationKind::DETECTABLE_UNATTRIBUTABLE_ABORT ||
        transport_failure_termination.unattributable_reason !=
            RobustAuditUnattributableAbortReason::AUTHENTICATED_TRANSPORT_FAILURE ||
        transport_failure_termination.publicly_attributable ||
        transport_failure_termination.public_abort_binding != Digest{} ||
        transport_failure_termination.local_failure_binding !=
            replay_failure.failure_binding)
        return false;
    if (exchange.AllGatherWords(
            bridge_context, {static_cast<u64>(rank), 42ULL},
            &bridge_gathered, &bridge_transcript))
        return false;
    AuthenticatedMpcEquivocationEvidence evidence;
    if (!exchange.LastEquivocationEvidence(
            bootstrap_sid, checkpoint.id, &evidence) ||
        evidence.context.sid != bootstrap_sid ||
        evidence.context.checkpoint != checkpoint.id)
        return false;

    RobustAuditAbortOutput output;
    if (!build_robust_audit_abort_output_from_equivocation(
            checkpoint, capabilities, nullptr, evidence,
            auth.ExternalRegistryAnchor(), world_size, &output) ||
        output.stage != RobustAuditAbortStage::ACTIVATION ||
        output.activation_binding != Digest{} || output.sid != 0 ||
        output.accused != 0)
        return false;

    RobustAuditTerminationOutput unattributable_termination;
    if (!build_robust_audit_unattributable_abort_termination(
            checkpoint, capabilities, nullptr,
            RobustAuditAbortStage::ACTIVATION,
            RobustAuditUnattributableAbortReason::ACTIVATION_UNAVAILABLE,
            &unattributable_termination) ||
        unattributable_termination.kind !=
            RobustAuditTerminationKind::DETECTABLE_UNATTRIBUTABLE_ABORT ||
        !unattributable_termination.detectable_abort ||
        unattributable_termination.publicly_attributable ||
        unattributable_termination.public_abort_binding != Digest{} ||
        !validate_robust_audit_termination_output(
            checkpoint, capabilities, nullptr, unattributable_termination))
        return false;
    RobustAuditTerminationOutput falsely_attributed = unattributable_termination;
    falsely_attributed.publicly_attributable = true;
    falsely_attributed.termination_binding =
        compute_robust_audit_termination_binding(falsely_attributed);
    if (validate_robust_audit_termination_output(
            checkpoint, capabilities, nullptr, falsely_attributed))
        return false;

    RobustAuditTerminationOutput attributable_termination;
    if (!build_robust_audit_termination_from_verified_public_abort(
            checkpoint, capabilities, nullptr, output,
            &attributable_termination) ||
        attributable_termination.kind !=
            RobustAuditTerminationKind::PUBLICLY_ATTRIBUTABLE_ABORT ||
        !attributable_termination.publicly_attributable ||
        attributable_termination.public_abort_binding != output.abort_binding ||
        !validate_robust_audit_termination_output(
            checkpoint, capabilities, nullptr, attributable_termination))
        return false;

    RobustAuditAbortOutput tampered = output;
    tampered.accused = static_cast<uint32_t>(
        (static_cast<uint64_t>(output.accused) + 1ULL) %
        static_cast<uint64_t>(world_size));
    tampered.abort_transcript_binding =
        compute_robust_audit_abort_transcript_binding(tampered);
    tampered.abort_binding = compute_robust_audit_abort_binding(tampered);
    if (validate_robust_audit_abort_output(
            checkpoint, capabilities, nullptr, tampered,
            auth.ExternalRegistryAnchor(), world_size))
        return false;
    tampered = output;
    tampered.abort_binding.bytes[0] ^= 1U;
    if (validate_robust_audit_abort_output(
            checkpoint, capabilities, nullptr, tampered,
            auth.ExternalRegistryAnchor(), world_size))
        return false;

    RobustAuditAbortOutput bridged_output;
    if (!build_robust_audit_abort_output_from_exchange(
            exchange, checkpoint, capabilities, nullptr,
            world_size, &bridged_output) ||
        bridged_output.accused != 0 ||
        bridged_output.stage != RobustAuditAbortStage::ACTIVATION ||
        !validate_robust_audit_abort_output(
            checkpoint, capabilities, nullptr, bridged_output,
            auth.ExternalRegistryAnchor(), world_size))
        return false;
    std::vector<AuthenticatedMpcSignedEnvelopeObservation> bridge_observations;
    RobustAuditAbortOutput observation_output;
    Digest observation_set_binding{};
    if (!exchange.ExportVerifiedEnvelopeObservations(
            bootstrap_sid, checkpoint.id, &bridge_observations) ||
        !build_robust_audit_abort_output_from_observations(
            bridge_observations, auth.PublicKeys(), exchange.Capabilities(),
            checkpoint, capabilities, nullptr, world_size,
            &observation_output, &observation_set_binding) ||
        observation_set_binding == Digest{} ||
        observation_output.abort_binding != bridged_output.abort_binding)
        return false;

    AuthenticatedMpcMessageContext collective_context = bridge_context;
    collective_context.sequence = 2;
    collective_context.message_kind = 0x4142525452454331ULL; // ABRTREC1
    RobustAuditAbortOutput collective_output;
    Digest collective_observation_binding{};
    Digest collective_reconciliation_binding{};
    if (!build_robust_audit_abort_output_from_reconciled_exchange(
            exchange, collective_context, checkpoint, capabilities,
            nullptr, world_size, &collective_output,
            &collective_observation_binding,
            &collective_reconciliation_binding) ||
        collective_observation_binding == Digest{} ||
        collective_reconciliation_binding == Digest{} ||
        collective_output.abort_binding != bridged_output.abort_binding ||
        !validate_robust_audit_abort_output(
            checkpoint, capabilities, nullptr, collective_output,
            auth.ExternalRegistryAnchor(), world_size))
        return false;

    RobustAuditAbortCertificate certificate;
    certificate.checkpoint = checkpoint;
    certificate.capabilities = capabilities;
    certificate.output = collective_output;
    const std::vector<u64> encoded_certificate =
        encode_robust_audit_abort_certificate(certificate);
    RobustAuditAbortCertificate decoded_certificate;
    if (encoded_certificate.empty() ||
        !decode_robust_audit_abort_certificate(
            encoded_certificate, &decoded_certificate) ||
        !verify_robust_audit_abort_certificate(
            decoded_certificate, auth.ExternalRegistryAnchor()))
        return false;
    std::vector<u64> tampered_certificate = encoded_certificate;
    if (tampered_certificate.size() <= 5) return false;
    ++tampered_certificate[5]; // checkpoint generation
    if (decode_robust_audit_abort_certificate(
            tampered_certificate, &decoded_certificate))
        return false;
    Digest wrong_certificate_anchor = auth.ExternalRegistryAnchor();
    wrong_certificate_anchor.bytes[0] ^= 1U;
    if (verify_robust_audit_abort_certificate(
            certificate, wrong_certificate_anchor))
        return false;

    RobustAuditActivation execution_activation;
    execution_activation.available = true;
    execution_activation.sid = 0x4142525445584543ULL; // ABRTEXEC
    execution_activation.checkpoint = checkpoint.id;
    execution_activation.checkpoint_root = checkpoint.root;
    execution_activation.checkpoint_binding =
        compute_robust_checkpoint_binding(checkpoint);
    execution_activation.registered_operations = checkpoint.operations.size();
    execution_activation.capability_binding = capabilities.capability_binding;
    execution_activation.authenticated_channel_activation_binding =
        hash_words({0x4142525441555448ULL, execution_activation.sid});
    execution_activation.registration_consistency_binding =
        hash_words({0x4142525452454742ULL, execution_activation.sid});
    execution_activation.activation_transcript_binding =
        hash_words({0x4142525441435452ULL, execution_activation.sid});
    execution_activation.activation_binding =
        compute_robust_audit_activation_binding(execution_activation);
    if (!validate_robust_audit_activation(
            checkpoint, capabilities, execution_activation))
        return false;

    RobustAuditSessionOutput completed_source;
    completed_source.available = true;
    completed_source.completed = true;
    completed_source.sid = execution_activation.sid;
    completed_source.checkpoint = checkpoint.id;
    completed_source.activation_binding = execution_activation.activation_binding;
    completed_source.capability_binding = capabilities.capability_binding;
    completed_source.output_binding = hash_words({
        0x5445524d434f4d50ULL, execution_activation.sid}); // TERMCOMP
    RobustAuditTerminationOutput completed_termination;
    if (!build_robust_audit_termination_from_validated_session_output(
            checkpoint, capabilities, execution_activation,
            completed_source, &completed_termination) ||
        completed_termination.kind != RobustAuditTerminationKind::COMPLETED ||
        !completed_termination.completed || completed_termination.detectable_abort ||
        completed_termination.publicly_attributable ||
        !validate_robust_audit_termination_output(
            checkpoint, capabilities, &execution_activation,
            completed_termination))
        return false;
    RobustAuditTerminationOutput execution_unattributable;
    if (!build_robust_audit_unattributable_abort_termination(
            checkpoint, capabilities, &execution_activation,
            RobustAuditAbortStage::EXECUTION,
            RobustAuditUnattributableAbortReason::EXECUTION_UNAVAILABLE,
            &execution_unattributable) ||
        execution_unattributable.sid != execution_activation.sid ||
        execution_unattributable.activation_binding !=
            execution_activation.activation_binding ||
        execution_unattributable.publicly_attributable ||
        execution_unattributable.public_abort_binding != Digest{} ||
        !validate_robust_audit_termination_output(
            checkpoint, capabilities, &execution_activation,
            execution_unattributable))
        return false;

    AuthenticatedMpcMessageContext execution_context = bridge_context;
    execution_context.sid = execution_activation.sid;
    execution_context.sequence = 1;
    execution_context.message_kind = 0x4142525445584d53ULL; // ABRTEXMS
    std::vector<u64> execution_gathered;
    Digest execution_transport{};
    if (!exchange.AllGatherWords(
            execution_context, {static_cast<u64>(rank), 51ULL},
            &execution_gathered, &execution_transport) ||
        execution_transport == Digest{})
        return false;
    if (exchange.AllGatherWords(
            execution_context, {static_cast<u64>(rank), 52ULL},
            &execution_gathered, &execution_transport))
        return false;
    AuthenticatedMpcEquivocationEvidence execution_evidence;
    if (!exchange.LastEquivocationEvidence(
            execution_activation.sid, checkpoint.id, &execution_evidence))
        return false;
    RobustAuditAbortOutput execution_output;
    if (!build_robust_audit_abort_output_from_equivocation(
            checkpoint, capabilities, &execution_activation,
            execution_evidence, auth.ExternalRegistryAnchor(),
            world_size, &execution_output) ||
        execution_output.stage != RobustAuditAbortStage::EXECUTION ||
        execution_output.sid != execution_activation.sid ||
        execution_output.activation_binding !=
            execution_activation.activation_binding)
        return false;

    RobustAuditTerminationOutput execution_attributable;
    if (!build_robust_audit_termination_from_verified_public_abort(
            checkpoint, capabilities, &execution_activation,
            execution_output, &execution_attributable) ||
        execution_attributable.kind !=
            RobustAuditTerminationKind::PUBLICLY_ATTRIBUTABLE_ABORT ||
        execution_attributable.public_abort_binding !=
            execution_output.abort_binding ||
        !validate_robust_audit_termination_output(
            checkpoint, capabilities, &execution_activation,
            execution_attributable))
        return false;

    int export_requested = 0;
    const char* export_path = nullptr;
    if (rank == 0) {
        export_path = std::getenv("PVIA_ROBUST_ABORT_CERT_OUT");
        export_requested = export_path && *export_path ? 1 : 0;
    }
    MPI_Bcast(&export_requested, 1, MPI_INT, 0, MPI_COMM_WORLD);
    if (export_requested) {
        int export_ok = 1;
        if (rank == 0)
            export_ok = write_robust_audit_abort_certificate_file(
                export_path, certificate) ? 1 : 0;
        MPI_Bcast(&export_ok, 1, MPI_INT, 0, MPI_COMM_WORLD);
        if (!export_ok) return false;
    }
    exchange.ClearEquivocationEvidence();
    return true;
}

} // namespace pvia
