#include "MpcBackedAuthenticatedResidualProtocol.hpp"

#include <cstring>
#include <vector>

namespace pvia {
namespace {

constexpr u64 RESIDUAL_MPC_CAP_DOMAIN = 0x5056524d50434341ULL; // PVRMPCCA

void append_digest_words(const Digest& digest, std::vector<u64>* words) {
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

Digest compute_residual_mpc_capability_binding(
    const ResidualMpcCapabilities& c) {
    std::vector<u64> words = {
        RESIDUAL_MPC_CAP_DOMAIN,
        c.available ? 1ULL : 0ULL,
        c.protocol_id,
        static_cast<u64>(c.security_level),
        c.malicious_secure ? 1ULL : 0ULL,
        c.activation_before_failure ? 1ULL : 0ULL,
        c.authenticated_channels ? 1ULL : 0ULL,
        c.private_residual_sharing ? 1ULL : 0ULL,
        c.commit_before_challenge ? 1ULL : 0ULL,
        c.joint_unpredictable_challenge ? 1ULL : 0ULL,
        c.random_linear_batch_check ? 1ULL : 0ULL,
        c.masked_zero_test ? 1ULL : 0ULL,
        c.recursive_subset_localization ? 1ULL : 0ULL,
        c.publicly_identifiable_abort ? 1ULL : 0ULL,
        c.guaranteed_output_delivery ? 1ULL : 0ULL
    };
    append_digest_words(c.authenticated_channel_capability_binding, &words);
    append_digest_words(c.identifiable_abort_capability_binding, &words);
    append_digest_words(c.delivery_capability_binding, &words);
    append_digest_words(c.implementation_binding, &words);
    return hash_words(words);
}

bool validate_residual_mpc_capabilities(
    const ResidualMpcCapabilities& c) {
    if (!c.available || c.protocol_id == 0 ||
        c.security_level == RobustAuditSecurityLevel::UNKNOWN ||
        c.implementation_binding == Digest{} ||
        !c.authenticated_channels || !c.private_residual_sharing ||
        !c.commit_before_challenge || !c.joint_unpredictable_challenge ||
        !c.random_linear_batch_check || !c.masked_zero_test ||
        !c.recursive_subset_localization)
        return false;
    if (c.authenticated_channels !=
        (c.authenticated_channel_capability_binding != Digest{}))
        return false;
    if (c.publicly_identifiable_abort !=
        (c.identifiable_abort_capability_binding != Digest{}))
        return false;
    if (c.guaranteed_output_delivery !=
        (c.delivery_capability_binding != Digest{}))
        return false;
    if (c.publicly_identifiable_abort && !c.authenticated_channels)
        return false;
    if (c.guaranteed_output_delivery && !c.publicly_identifiable_abort)
        return false;
    if (c.security_level == RobustAuditSecurityLevel::REFERENCE_PASSIVE) {
        if (c.malicious_secure || c.publicly_identifiable_abort ||
            c.guaranteed_output_delivery)
            return false;
    } else if (c.security_level == RobustAuditSecurityLevel::MALICIOUS_ABORT) {
        if (!c.malicious_secure || !c.activation_before_failure ||
            !c.publicly_identifiable_abort || c.guaranteed_output_delivery)
            return false;
    } else if (c.security_level == RobustAuditSecurityLevel::MALICIOUS_GOD) {
        if (!c.malicious_secure || !c.activation_before_failure ||
            !c.publicly_identifiable_abort || !c.guaranteed_output_delivery)
            return false;
    } else {
        return false;
    }
    return c.capability_binding != Digest{} &&
        c.capability_binding == compute_residual_mpc_capability_binding(c);
}

bool residual_mpc_satisfies(
    const ResidualMpcCapabilities& c,
    RobustAuditSecurityLevel required_security) {
    if (!validate_residual_mpc_capabilities(c)) return false;
    switch (required_security) {
        case RobustAuditSecurityLevel::REFERENCE_PASSIVE:
            return c.security_level == RobustAuditSecurityLevel::REFERENCE_PASSIVE ||
                   c.security_level == RobustAuditSecurityLevel::MALICIOUS_ABORT ||
                   c.security_level == RobustAuditSecurityLevel::MALICIOUS_GOD;
        case RobustAuditSecurityLevel::MALICIOUS_ABORT:
            return (c.security_level == RobustAuditSecurityLevel::MALICIOUS_ABORT ||
                    c.security_level == RobustAuditSecurityLevel::MALICIOUS_GOD) &&
                   c.publicly_identifiable_abort;
        case RobustAuditSecurityLevel::MALICIOUS_GOD:
            return c.security_level == RobustAuditSecurityLevel::MALICIOUS_GOD &&
                   c.publicly_identifiable_abort &&
                   c.guaranteed_output_delivery;
        default:
            return false;
    }
}

MpcBackedAuthenticatedResidualProtocol::
MpcBackedAuthenticatedResidualProtocol(
    const ResidualMpcBackend& backend,
    RobustAuditSecurityLevel required_security)
    : backend_(backend), required_security_(required_security) {}

bool MpcBackedAuthenticatedResidualProtocol::ready() const {
    return residual_mpc_satisfies(backend_.Capabilities(), required_security_);
}

bool MpcBackedAuthenticatedResidualProtocol::ready_for_scope(
    const ObligationSet& scope) const {
    return ready() && backend_.ReadyForScope(scope, required_security_);
}

ResidualMpcCapabilities
MpcBackedAuthenticatedResidualProtocol::capabilities() const {
    return backend_.Capabilities();
}

Digest MpcBackedAuthenticatedResidualProtocol::ProductionCapabilityBinding() const {
    if (!ready() ||
        (required_security_ != RobustAuditSecurityLevel::MALICIOUS_ABORT &&
         required_security_ != RobustAuditSecurityLevel::MALICIOUS_GOD))
        return {};
    const Digest backend_binding = backend_.ProductionCapabilityBinding();
    const ResidualMpcCapabilities current = capabilities();
    if (backend_binding == Digest{} ||
        !validate_residual_mpc_capabilities(current) ||
        !residual_mpc_satisfies(current, required_security_))
        return {};
    std::vector<u64> words = {
        RESIDUAL_MPC_CAP_DOMAIN, 0x50524f4443415031ULL,
        static_cast<u64>(required_security_)};
    append_digest_words(backend_binding, &words);
    append_digest_words(current.capability_binding, &words);
    return hash_words(words);
}

bool MpcBackedAuthenticatedResidualProtocol::SupportsObliviousAudit(
    const ObligationSet& scope) const {
    return ready_for_scope(scope) && backend_.SupportsObliviousAudit(scope);
}

ObliviousLocalizationPublicResult
MpcBackedAuthenticatedResidualProtocol::AuditObliviously(
    const ObligationSet& scope, const LocalResidualBatchView& local_view,
    int rank, int world_size) const {
    if (!ready_for_scope(scope) || !backend_.SupportsObliviousAudit(scope))
        return {};
    return backend_.AuditObliviously(scope, local_view, rank, world_size);
}

CollectiveResidualCommitmentSet
MpcBackedAuthenticatedResidualProtocol::CommitResidualBatch(
    const ObligationSet& scope,
    const CollectiveBatchDescriptor& local_descriptor,
    const LocalResidualBatchView& local_view,
    int rank, int world_size) const {
    if (!ready_for_scope(scope)) return unavailable_commitments(scope);
    return backend_.CommitResidualBatch(
        scope, local_descriptor, local_view, rank, world_size);
}

AuthenticatedChallengeTranscript
MpcBackedAuthenticatedResidualProtocol::DeriveJointChallenge(
    const ObligationSet& scope,
    const CollectiveBatchDescriptor& local_descriptor,
    const CollectiveResidualCommitmentSet& commitments,
    int rank, int world_size) const {
    if (!ready_for_scope(scope)) return unavailable_challenge(scope);
    return backend_.DeriveJointChallenge(
        scope, local_descriptor, commitments, rank, world_size);
}

BatchCheckResult
MpcBackedAuthenticatedResidualProtocol::RandomLinearBatchCheck(
    const ObligationSet& scope,
    const CollectiveBatchDescriptor& local_descriptor,
    const LocalResidualBatchView& local_view,
    const CollectiveResidualCommitmentSet& commitments,
    const AuthenticatedChallengeTranscript& challenge_transcript,
    int rank, int world_size) const {
    if (!ready_for_scope(scope)) return unavailable_batch(scope);
    return backend_.RandomLinearBatchCheck(
        scope, local_descriptor, local_view, commitments,
        challenge_transcript, rank, world_size);
}

ResidualSubsetCheckResult
MpcBackedAuthenticatedResidualProtocol::CheckResidualSubset(
    const ObligationSet& scope,
    const BatchCheckResult& batch,
    const ResidualSubsetDescriptor& subset,
    const LocalResidualBatchView& local_view,
    int rank, int world_size) const {
    if (!ready_for_scope(scope)) return unavailable_subset(scope);
    return backend_.CheckResidualSubset(
        scope, batch, subset, local_view, rank, world_size);
}

CollectiveDisputeResult
MpcBackedAuthenticatedResidualProtocol::FinalizeLocalization(
    const ObligationSet& scope,
    const BatchCheckResult& batch,
    const OperationRef& accused,
    const Digest& recursive_transcript_binding,
    const LocalResidualBatchView& local_view,
    int rank, int world_size) const {
    if (!ready_for_scope(scope)) return unavailable_dispute(scope);
    return backend_.FinalizeLocalization(
        scope, batch, accused, recursive_transcript_binding,
        local_view, rank, world_size);
}

} // namespace pvia
