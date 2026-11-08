#include "AuthenticatedResidualProtocol.hpp"

#include <algorithm>
#include <cstring>

namespace pvia {
namespace {

constexpr u64 RESIDUAL_SECURITY_ROOT_DOMAIN = 0x5056525345435254ULL; // PVRSECRT
constexpr u64 RESIDUAL_SECURITY_LINK_MARKER = 0x5056525345434c4bULL; // PVRSECLK

void append_digest_words(const Digest& digest, std::vector<u64>& words) {
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words.push_back(word);
    }
}

bool participant_less(const ParticipantResidualCommitment& lhs,
                      const ParticipantResidualCommitment& rhs) {
    return lhs.owner < rhs.owner;
}

bool operation_less(const OperationRef& lhs, const OperationRef& rhs) {
    if (lhs.owner != rhs.owner) return lhs.owner < rhs.owner;
    return lhs.object_id < rhs.object_id;
}

BatchCheckResult unavailable_batch(const ObligationSet& scope) {
    BatchCheckResult result;
    result.available = false;
    result.cryptographically_authenticated = false;
    result.ok = false;
    result.checkpoint = scope.checkpoint;
    return result;
}

CollectiveDisputeResult unavailable_dispute(const ObligationSet& scope) {
    CollectiveDisputeResult result;
    result.available = false;
    result.cryptographically_authenticated = false;
    result.found = false;
    result.checkpoint = scope.checkpoint;
    return result;
}

} // namespace

Digest compute_participant_commitment_root(
    const std::vector<ParticipantResidualCommitment>& participants) {
    std::vector<ParticipantResidualCommitment> ordered = participants;
    std::sort(ordered.begin(), ordered.end(), participant_less);
    std::vector<u64> words;
    words.push_back(static_cast<u64>(ordered.size()));
    for (const auto& participant : ordered) {
        words.push_back(participant.owner);
        words.push_back(static_cast<u64>(participant.handle_count));
        append_digest_words(participant.descriptor_digest, words);
        append_digest_words(participant.local_commitment_root, words);
        append_digest_words(participant.authentication_commitment, words);
    }
    return hash_words(words);
}

Digest compute_collective_residual_commitment_root(
    const std::vector<ParticipantResidualCommitment>& participants,
    const Digest& security_attestation_binding) {
    const Digest participant_root =
        compute_participant_commitment_root(participants);
    if (security_attestation_binding == Digest{}) return participant_root;
    std::vector<u64> words = {RESIDUAL_SECURITY_ROOT_DOMAIN};
    append_digest_words(participant_root, words);
    append_digest_words(security_attestation_binding, words);
    return hash_words(words);
}

bool validate_participant_commitment_set(
    const ObligationSet& scope,
    const CollectiveBatchDescriptor& local_descriptor,
    const CollectiveResidualCommitmentSet& commitments,
    int world_size) {
    if (world_size <= 0 || scope.operations.empty()) return false;
    if (!commitments.available ||
        !commitments.cryptographically_authenticated)
        return false;
    if (commitments.checkpoint != scope.checkpoint) return false;
    if (commitments.participants.size() != static_cast<size_t>(world_size))
        return false;
    if (local_descriptor.world_size != world_size ||
        local_descriptor.local_owner >= static_cast<uint32_t>(world_size))
        return false;
    const Digest local_descriptor_digest = compute_collective_descriptor_digest(
        scope, local_descriptor.local_owner, world_size,
        local_descriptor.local_handle_count,
        local_descriptor.local_commitment_root);
    if (local_descriptor.descriptor_digest != local_descriptor_digest)
        return false;

    std::vector<ParticipantResidualCommitment> ordered = commitments.participants;
    std::sort(ordered.begin(), ordered.end(), participant_less);
    bool found_local = false;
    size_t total_handles = 0;
    for (int i = 0; i < world_size; ++i) {
        const auto& participant = ordered[static_cast<size_t>(i)];
        if (participant.owner != static_cast<uint32_t>(i)) return false;
        if (participant.local_commitment_root == Digest{} ||
            participant.authentication_commitment == Digest{})
            return false;
        total_handles += participant.handle_count;
        const Digest expected_descriptor = compute_collective_descriptor_digest(
            scope, participant.owner, world_size,
            participant.handle_count, participant.local_commitment_root);
        if (participant.descriptor_digest != expected_descriptor) return false;
        if (participant.owner == local_descriptor.local_owner) {
            found_local = true;
            if (participant.handle_count != local_descriptor.local_handle_count ||
                participant.descriptor_digest != local_descriptor.descriptor_digest ||
                participant.local_commitment_root !=
                    local_descriptor.local_commitment_root)
                return false;
        }
    }
    if (!found_local || total_handles != scope.operations.size()) return false;
    if (commitments.root == Digest{}) return false;
    return commitments.root ==
           compute_collective_residual_commitment_root(
               commitments.participants,
               commitments.security_attestation_binding);
}

ResidualSubsetDescriptor make_residual_subset_descriptor(
    const BatchCheckResult& batch,
    const std::vector<OperationRef>& operations,
    uint32_t depth) {
    ResidualSubsetDescriptor subset;
    subset.checkpoint = batch.checkpoint;
    subset.depth = depth;
    subset.operations = operations;
    std::sort(subset.operations.begin(), subset.operations.end(), operation_less);
    subset.batch_result_binding = compute_collective_batch_result_binding(batch);
    subset.challenge_transcript_binding = batch.challenge_transcript_binding;
    subset.security_attestation_binding = batch.security_attestation_binding;
    std::vector<u64> words = {subset.checkpoint, subset.depth,
        static_cast<u64>(subset.operations.size())};
    append_digest_words(subset.batch_result_binding, words);
    append_digest_words(subset.challenge_transcript_binding, words);
    if (subset.security_attestation_binding != Digest{}) {
        words.push_back(RESIDUAL_SECURITY_LINK_MARKER);
        append_digest_words(subset.security_attestation_binding, words);
    }
    for (const auto& ref : subset.operations) {
        words.push_back(ref.owner);
        words.push_back(ref.object_id);
    }
    subset.binding = hash_words(words);
    return subset;
}

bool validate_residual_subset_check(
    const BatchCheckResult& batch,
    const ResidualSubsetDescriptor& subset,
    const ResidualSubsetCheckResult& result) {
    if (!batch.available || !batch.cryptographically_authenticated || batch.ok)
        return false;
    if (subset.operations.empty() || subset.binding == Digest{}) return false;
    if (subset.checkpoint != batch.checkpoint) return false;
    if (subset.batch_result_binding !=
        compute_collective_batch_result_binding(batch))
        return false;
    if (subset.challenge_transcript_binding != batch.challenge_transcript_binding ||
        subset.challenge_transcript_binding == Digest{})
        return false;
    if (subset.security_attestation_binding !=
        batch.security_attestation_binding)
        return false;
    if (!result.available || !result.cryptographically_authenticated)
        return false;
    if (result.checkpoint != subset.checkpoint) return false;
    if (result.batch_result_binding != subset.batch_result_binding) return false;
    if (result.challenge_transcript_binding !=
        subset.challenge_transcript_binding) return false;
    if (result.security_attestation_binding !=
        subset.security_attestation_binding) return false;
    if (result.subset_binding != subset.binding) return false;
    if (result.proof_commitment == Digest{}) return false;
    return true;
}

BatchCheckResult ProtocolBackedCollectiveResidualEngine::BatchCheck(
    const ObligationSet& scope,
    const LocalResidualBatchView& local_view,
    int rank,
    int world_size) const {
    if (world_size <= 0 || rank < 0 || rank >= world_size ||
        scope.operations.empty())
        return unavailable_batch(scope);
    if (!local_view.complete_for_owner || !local_view.all_authenticated)
        return unavailable_batch(scope);

    const CollectiveBatchDescriptor descriptor =
        make_collective_batch_descriptor(scope, local_view, rank, world_size);
    const CollectiveResidualCommitmentSet commitments =
        protocol_.CommitResidualBatch(
            scope, descriptor, local_view, rank, world_size);
    if (!validate_participant_commitment_set(
            scope, descriptor, commitments, world_size))
        return unavailable_batch(scope);

    const AuthenticatedChallengeTranscript challenge_transcript =
        protocol_.DeriveJointChallenge(
            scope, descriptor, commitments, rank, world_size);
    if (!validate_challenge_transcript(
            scope, commitments, challenge_transcript, world_size))
        return unavailable_batch(scope);

    BatchCheckResult result = protocol_.RandomLinearBatchCheck(
        scope, descriptor, local_view, commitments, challenge_transcript,
        rank, world_size);
    if (result.participant_commitment_root != commitments.root ||
        result.participant_count != commitments.participants.size() ||
        result.scope_binding != compute_collective_scope_binding(scope) ||
        result.challenge != challenge_transcript.challenge ||
        result.challenge_transcript_binding !=
            challenge_transcript.transcript_digest ||
        result.security_attestation_binding !=
            challenge_transcript.security_attestation_binding)
        return unavailable_batch(scope);
    if (!validate_collective_batch_result(scope, result, world_size))
        return unavailable_batch(scope);
    return result;
}

ObliviousLocalizationPublicResult
ProtocolBackedCollectiveResidualEngine::DisputeObliviously(
    const ObligationSet& scope, const BatchCheckResult& batch,
    const LocalResidualBatchView& local_view,
    int rank, int world_size) const {
    // The only acceptable provider opens a canonical public j*, and never
    // reveals q*, the protected branch or an operation-indexed proof tag.
    // An ordinary recursive subset backend cannot be silently upgraded.
    if(rank<0 || world_size<4 || rank>=world_size ||
       scope.operations.empty() ||
       !validate_collective_batch_result(scope,batch,world_size) ||
       batch.ok || !local_view.complete_for_owner ||
       !local_view.all_authenticated ||
       !protocol_.SupportsObliviousLocalization())
        return {};
    const auto result=protocol_.LocalizeObliviously(
        scope,batch,local_view,rank,world_size);
    if(!result.available || !result.cryptographically_authenticated ||
       !result.found || result.attributed_party>=static_cast<uint32_t>(world_size) ||
       result.checkpoint!=scope.checkpoint ||
       result.batch_result_binding!=compute_collective_batch_result_binding(batch) ||
       result.public_evidence_binding==Digest{})
        return {};
    return result;
}

ObliviousLocalizationPublicResult
ProtocolBackedCollectiveResidualEngine::AuditObliviously(
    const ObligationSet& scope, const LocalResidualBatchView& local_view,
    int rank, int world_size) const {
    // This path deliberately has no public BatchCheckResult parameter. The
    // private-mode backend computes the batch verdict and owner selection
    // internally, and may return only clean/fault plus the owner identifier.
    if (rank < 0 || world_size < 4 || rank >= world_size ||
        scope.operations.empty() || scope.operations.size() > 64 ||
        !local_view.complete_for_owner || !local_view.all_authenticated ||
        !protocol_.SupportsObliviousAudit(scope))
        return {};
    const auto result = protocol_.AuditObliviously(
        scope, local_view, rank, world_size);
    if (!result.available || !result.cryptographically_authenticated ||
        result.checkpoint != scope.checkpoint ||
        result.batch_result_binding == Digest{} ||
        result.public_evidence_binding == Digest{} ||
        (result.found && result.attributed_party >=
            static_cast<uint32_t>(world_size)) ||
        (!result.found && result.attributed_party != 0))
        return {};
    return result;
}

// LEGACY REFERENCE MODE ONLY. The public subset test returns a clear bool,
// the selected subset changes with that bool, and both the branch and
// operation identifier are committed to the recursive transcript. This path
// is not oblivious and MUST NOT be used to claim hidden internal q*.
CollectiveDisputeResult ProtocolBackedCollectiveResidualEngine::Dispute(
    const ObligationSet& scope,
    const BatchCheckResult& batch,
    const LocalResidualBatchView& local_view,
    int rank,
    int world_size) const {
    if (world_size <= 0 || rank < 0 || rank >= world_size ||
        scope.operations.empty())
        return unavailable_dispute(scope);
    if (!validate_collective_batch_result(scope, batch, world_size) || batch.ok)
        return unavailable_dispute(scope);
    if (!local_view.complete_for_owner || !local_view.all_authenticated)
        return unavailable_dispute(scope);

    std::vector<OperationRef> candidates = scope.operations;
    std::sort(candidates.begin(), candidates.end(), operation_less);
    if (std::adjacent_find(candidates.begin(), candidates.end()) != candidates.end())
        return unavailable_dispute(scope);

    std::vector<u64> transcript_words;
    const Digest batch_binding = compute_collective_batch_result_binding(batch);
    append_digest_words(batch_binding, transcript_words);
    append_digest_words(batch.participant_commitment_root, transcript_words);
    transcript_words.push_back(static_cast<u64>(candidates.size()));
    uint32_t depth = 0;

    while (candidates.size() > 1) {
        const size_t mid = candidates.size() / 2;
        std::vector<OperationRef> left(candidates.begin(), candidates.begin() + mid);
        const ResidualSubsetDescriptor left_subset =
            make_residual_subset_descriptor(batch, left, depth);
        const ResidualSubsetCheckResult left_result = protocol_.CheckResidualSubset(
            scope, batch, left_subset, local_view, rank, world_size);
        if (!validate_residual_subset_check(batch, left_subset, left_result))
            return unavailable_dispute(scope);

        transcript_words.push_back(depth);
        transcript_words.push_back(0);
        append_digest_words(left_subset.binding, transcript_words);
        append_digest_words(left_result.proof_commitment, transcript_words);
        transcript_words.push_back(left_result.failed ? 1ULL : 0ULL);

        if (left_result.failed) {
            candidates = std::move(left);
        } else {
            std::vector<OperationRef> right(
                candidates.begin() + mid, candidates.end());
            const ResidualSubsetDescriptor right_subset =
                make_residual_subset_descriptor(batch, right, depth);
            if (right_subset.operations.empty() ||
                right_subset.binding == Digest{})
                return unavailable_dispute(scope);

            // All subset fingerprints use the same batch-global random
            // coefficients.  The current parent is known to have a nonzero
            // fingerprint; if the checked left child is zero, additivity
            // implies the complementary right child is nonzero.  Bind that
            // inference to the clean-left proof rather than running a second
            // MPC zero test.
            transcript_words.push_back(depth);
            transcript_words.push_back(1);
            append_digest_words(right_subset.binding, transcript_words);
            append_digest_words(left_result.proof_commitment, transcript_words);
            transcript_words.push_back(2); // inferred-failing complement
            candidates = std::move(right);
        }
        ++depth;
    }

    const OperationRef accused = candidates.front();
    transcript_words.push_back(accused.owner);
    transcript_words.push_back(accused.object_id);
    const Digest recursive_binding = hash_words(transcript_words);
    CollectiveDisputeResult result = protocol_.FinalizeLocalization(
        scope, batch, accused, recursive_binding,
        local_view, rank, world_size);
    if (result.accused != accused ||
        result.recursive_transcript_binding != recursive_binding)
        return unavailable_dispute(scope);
    if (!validate_collective_dispute_result(scope, batch, result))
        return unavailable_dispute(scope);
    return result;
}

} // namespace pvia
