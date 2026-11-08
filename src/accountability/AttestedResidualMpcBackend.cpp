#include "AttestedResidualMpcBackend.hpp"

#include <cstring>
#include <vector>

namespace pvia {
namespace {

constexpr u64 ATTESTED_RESIDUAL_PROTOCOL_ID =
    0x5056524154544d50ULL; // PVRATTMP
constexpr u64 ATTESTED_RESIDUAL_IMPL_DOMAIN =
    0x505652415454494dULL; // PVRATTIM

void append_digest(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

CollectiveResidualCommitmentSet unavailable_commitments(
    const ObligationSet& scope) {
    CollectiveResidualCommitmentSet out;
    out.checkpoint = scope.checkpoint;
    return out;
}

AuthenticatedChallengeTranscript unavailable_challenge(
    const ObligationSet& scope) {
    AuthenticatedChallengeTranscript out;
    out.checkpoint = scope.checkpoint;
    return out;
}

BatchCheckResult unavailable_batch(const ObligationSet& scope) {
    BatchCheckResult out;
    out.available = false;
    out.cryptographically_authenticated = false;
    out.ok = false;
    out.checkpoint = scope.checkpoint;
    return out;
}

ResidualSubsetCheckResult unavailable_subset(
    const ObligationSet& scope) {
    ResidualSubsetCheckResult out;
    out.checkpoint = scope.checkpoint;
    return out;
}

CollectiveDisputeResult unavailable_dispute(
    const ObligationSet& scope) {
    CollectiveDisputeResult out;
    out.checkpoint = scope.checkpoint;
    return out;
}

} // namespace

AttestedResidualMpcBackend::AttestedResidualMpcBackend(
    const ResidualMpcBackend& data_plane,
    const ResidualMpcMaliciousSecurityProvider& security_provider,
    RobustAuditSecurityLevel required_security)
    : data_plane_(data_plane),
      security_provider_(security_provider),
      required_security_(required_security) {}

ResidualMpcCapabilities AttestedResidualMpcBackend::Capabilities() const {
    ResidualMpcCapabilities out;
    if (required_security_ != RobustAuditSecurityLevel::MALICIOUS_ABORT &&
        required_security_ != RobustAuditSecurityLevel::MALICIOUS_GOD)
        return out;
    const ResidualMpcCapabilities data = data_plane_.Capabilities();
    const ResidualMpcMaliciousSecurityCapabilities security =
        security_provider_.Capabilities();
    if (!validate_residual_mpc_capabilities(data) ||
        !residual_mpc_malicious_security_satisfies(
            security, required_security_) ||
        !data.activation_before_failure ||
        security.residual_implementation_binding != data.implementation_binding)
        return out;

    out = data;
    out.protocol_id = ATTESTED_RESIDUAL_PROTOCOL_ID;
    out.security_level = security.security_level;
    out.malicious_secure = true;
    out.publicly_identifiable_abort = security.publicly_identifiable_abort;
    out.guaranteed_output_delivery = security.guaranteed_output_delivery;
    out.identifiable_abort_capability_binding =
        security.identifiable_abort_capability_binding;
    out.delivery_capability_binding = security.delivery_capability_binding;

    std::vector<u64> implementation_words = {
        ATTESTED_RESIDUAL_IMPL_DOMAIN,
        ATTESTED_RESIDUAL_PROTOCOL_ID,
        static_cast<u64>(required_security_)};
    append_digest(data.implementation_binding, &implementation_words);
    append_digest(data.capability_binding, &implementation_words);
    append_digest(security.implementation_binding, &implementation_words);
    append_digest(security.capability_binding, &implementation_words);
    out.implementation_binding = hash_words(implementation_words);
    out.capability_binding = compute_residual_mpc_capability_binding(out);
    if (!residual_mpc_satisfies(out, required_security_))
        return ResidualMpcCapabilities{};
    return out;
}

Digest AttestedResidualMpcBackend::ProductionCapabilityBinding() const {
    const Digest data_plane_binding =
        data_plane_.ProductionCapabilityBinding();
    if (data_plane_binding == Digest{}) return {};
    const ResidualMpcCapabilities residual = Capabilities();
    const ResidualMpcMaliciousSecurityCapabilities security =
        security_provider_.Capabilities();
    if (!residual_mpc_satisfies(residual, required_security_) ||
        !residual_mpc_malicious_security_satisfies(
            security, required_security_))
        return {};
    std::vector<u64> words = {
        0x5056414154545052ULL, // PVAATTPR
        static_cast<u64>(required_security_)};
    append_digest(data_plane_binding, &words);
    append_digest(residual.capability_binding, &words);
    append_digest(security.capability_binding, &words);
    return hash_words(words);
}

ResidualMpcPrecommitSecurityContext
AttestedResidualMpcBackend::PrecommitSecurityContext(
    const ObligationSet& scope) const {
    return data_plane_.PrecommitSecurityContext(scope);
}

bool AttestedResidualMpcBackend::ReadyForScope(
    const ObligationSet& scope,
    RobustAuditSecurityLevel required_security) const {
    if (required_security != required_security_ ||
        !residual_mpc_satisfies(Capabilities(), required_security_))
        return false;
    const Digest scope_binding = compute_collective_scope_binding(scope);
    if (active_attestation_.available &&
        active_scope_binding_ == scope_binding &&
        ValidateActiveAttestation(
            scope, active_attestation_.attestation_binding))
        return true;
    ClearActiveAttestation();
    ResidualMpcSecurityAttestation attestation;
    if (!PrepareAttestation(scope, &attestation)) return false;
    active_attestation_ = attestation;
    active_scope_binding_ = scope_binding;
    return true;
}

bool AttestedResidualMpcBackend::PrepareAttestation(
    const ObligationSet& scope,
    ResidualMpcSecurityAttestation* attestation) const {
    if (!attestation ||
        !residual_mpc_satisfies(Capabilities(), required_security_))
        return false;
    const ResidualMpcCapabilities data = data_plane_.Capabilities();
    const ResidualMpcMaliciousSecurityCapabilities security =
        security_provider_.Capabilities();
    const ResidualMpcPrecommitSecurityContext context =
        data_plane_.PrecommitSecurityContext(scope);
    if (!context.available || context.activation_binding == Digest{} ||
        context.strong_consistency_capability_binding == Digest{} ||
        context.strong_consistency_capability_binding !=
            security.strong_consistency_capability_binding)
        return false;

    ResidualMpcSecurityAttestation candidate =
        security_provider_.AttestActivatedState(
            scope, data, context.activation_binding,
            context.strong_consistency_capability_binding);
    if (!validate_residual_mpc_security_attestation(
            scope, data, security, candidate, required_security_) ||
        !security_provider_.VerifyAttestation(
            scope, data, candidate, required_security_))
        return false;
    *attestation = candidate;
    return true;
}

bool AttestedResidualMpcBackend::ValidateActiveAttestation(
    const ObligationSet& scope,
    const Digest& expected_binding) const {
    if (expected_binding == Digest{} || !active_attestation_.available ||
        active_attestation_.attestation_binding != expected_binding ||
        active_scope_binding_ != compute_collective_scope_binding(scope))
        return false;
    const ResidualMpcCapabilities data = data_plane_.Capabilities();
    const ResidualMpcMaliciousSecurityCapabilities security =
        security_provider_.Capabilities();
    const ResidualMpcPrecommitSecurityContext context =
        data_plane_.PrecommitSecurityContext(scope);
    if (!context.available ||
        context.activation_binding != active_attestation_.activation_binding ||
        context.strong_consistency_capability_binding !=
            active_attestation_.strong_consistency_capability_binding)
        return false;
    return validate_residual_mpc_security_attestation(
               scope, data, security, active_attestation_, required_security_) &&
           security_provider_.VerifyAttestation(
               scope, data, active_attestation_, required_security_);
}

void AttestedResidualMpcBackend::ClearActiveAttestation() const {
    active_attestation_ = ResidualMpcSecurityAttestation{};
    active_scope_binding_ = Digest{};
}

CollectiveResidualCommitmentSet
AttestedResidualMpcBackend::CommitResidualBatch(
    const ObligationSet& scope,
    const CollectiveBatchDescriptor& local_descriptor,
    const LocalResidualBatchView& local_view,
    int rank, int world_size) const {
    ResidualMpcSecurityAttestation attestation;
    const Digest scope_binding = compute_collective_scope_binding(scope);
    if (active_attestation_.available &&
        active_scope_binding_ == scope_binding &&
        ValidateActiveAttestation(
            scope, active_attestation_.attestation_binding)) {
        attestation = active_attestation_;
    } else {
        ClearActiveAttestation();
        if (!PrepareAttestation(scope, &attestation))
            return unavailable_commitments(scope);
    }
    CollectiveResidualCommitmentSet out = data_plane_.CommitResidualBatch(
        scope, local_descriptor, local_view, rank, world_size);
    if (!out.available || !out.cryptographically_authenticated ||
        out.security_attestation_binding != Digest{})
        return unavailable_commitments(scope);
    out.security_attestation_binding = attestation.attestation_binding;
    out.root = compute_collective_residual_commitment_root(
        out.participants, out.security_attestation_binding);
    if (!validate_participant_commitment_set(
            scope, local_descriptor, out, world_size))
        return unavailable_commitments(scope);
    active_attestation_ = attestation;
    active_scope_binding_ = compute_collective_scope_binding(scope);
    return out;
}

AuthenticatedChallengeTranscript
AttestedResidualMpcBackend::DeriveJointChallenge(
    const ObligationSet& scope,
    const CollectiveBatchDescriptor& local_descriptor,
    const CollectiveResidualCommitmentSet& commitments,
    int rank, int world_size) const {
    if (!ValidateActiveAttestation(
            scope, commitments.security_attestation_binding))
        return unavailable_challenge(scope);
    AuthenticatedChallengeTranscript out = data_plane_.DeriveJointChallenge(
        scope, local_descriptor, commitments, rank, world_size);
    if (out.security_attestation_binding !=
            commitments.security_attestation_binding ||
        !validate_challenge_transcript(
            scope, commitments, out, world_size))
        return unavailable_challenge(scope);
    return out;
}

BatchCheckResult
AttestedResidualMpcBackend::RandomLinearBatchCheck(
    const ObligationSet& scope,
    const CollectiveBatchDescriptor& local_descriptor,
    const LocalResidualBatchView& local_view,
    const CollectiveResidualCommitmentSet& commitments,
    const AuthenticatedChallengeTranscript& challenge_transcript,
    int rank, int world_size) const {
    const Digest security_binding = commitments.security_attestation_binding;
    if (!ValidateActiveAttestation(scope, security_binding) ||
        challenge_transcript.security_attestation_binding != security_binding)
        return unavailable_batch(scope);
    BatchCheckResult out = data_plane_.RandomLinearBatchCheck(
        scope, local_descriptor, local_view, commitments,
        challenge_transcript, rank, world_size);
    if (out.security_attestation_binding != security_binding ||
        !validate_collective_batch_result(scope, out, world_size))
        return unavailable_batch(scope);
    return out;
}

ResidualSubsetCheckResult
AttestedResidualMpcBackend::CheckResidualSubset(
    const ObligationSet& scope,
    const BatchCheckResult& batch,
    const ResidualSubsetDescriptor& subset,
    const LocalResidualBatchView& local_view,
    int rank, int world_size) const {
    const Digest security_binding = batch.security_attestation_binding;
    if (!ValidateActiveAttestation(scope, security_binding) ||
        subset.security_attestation_binding != security_binding)
        return unavailable_subset(scope);
    ResidualSubsetCheckResult out = data_plane_.CheckResidualSubset(
        scope, batch, subset, local_view, rank, world_size);
    if (out.security_attestation_binding != security_binding ||
        !validate_residual_subset_check(batch, subset, out))
        return unavailable_subset(scope);
    return out;
}

CollectiveDisputeResult
AttestedResidualMpcBackend::FinalizeLocalization(
    const ObligationSet& scope,
    const BatchCheckResult& batch,
    const OperationRef& accused,
    const Digest& recursive_transcript_binding,
    const LocalResidualBatchView& local_view,
    int rank, int world_size) const {
    const Digest security_binding = batch.security_attestation_binding;
    if (!ValidateActiveAttestation(scope, security_binding))
        return unavailable_dispute(scope);
    CollectiveDisputeResult out = data_plane_.FinalizeLocalization(
        scope, batch, accused, recursive_transcript_binding,
        local_view, rank, world_size);
    if (out.security_attestation_binding != security_binding ||
        !validate_collective_dispute_result(scope, batch, out))
        return unavailable_dispute(scope);
    return out;
}

} // namespace pvia
