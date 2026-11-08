#include "HybridAuditCheck.hpp"

#include <cstring>
#include <vector>

namespace pvia {
namespace {

void append_digest_words(const Digest& digest, std::vector<u64>& words) {
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words.push_back(word);
    }
}

Digest combine_lane_bindings(u64 domain, const Digest& lhs,
                             const Digest& rhs) {
    std::vector<u64> words = {domain};
    append_digest_words(lhs, words);
    append_digest_words(rhs, words);
    return hash_words(words);
}

bool same_batch(const BatchCheckResult& lhs, const BatchCheckResult& rhs) {
    return lhs.available == rhs.available &&
           lhs.cryptographically_authenticated == rhs.cryptographically_authenticated &&
           lhs.ok == rhs.ok && lhs.checkpoint == rhs.checkpoint &&
           lhs.checked_operations == rhs.checked_operations &&
           lhs.mismatches == rhs.mismatches &&
           lhs.participant_count == rhs.participant_count &&
           lhs.scope_binding == rhs.scope_binding &&
           lhs.participant_commitment_root == rhs.participant_commitment_root &&
           lhs.challenge_transcript_binding == rhs.challenge_transcript_binding &&
           lhs.challenge == rhs.challenge &&
           lhs.aggregate_residual_commitment == rhs.aggregate_residual_commitment;
}

Digest absent_lane_binding(u64 tag) {
    return hash_words(std::vector<u64>{tag, 0ULL});
}

} // namespace

BatchCheckResult make_hybrid_audit_batch_envelope(
    const ObligationSet& full_scope,
    const AuditScopePartition& partition,
    const HybridAuditBatchComponents& components,
    int world_size) {
    BatchCheckResult out;
    out.available = false;
    out.cryptographically_authenticated = false;
    out.ok = false;
    out.checkpoint = full_scope.checkpoint;
    if (!partition.complete || world_size <= 0 ||
        (!components.private_present && !components.transfer_present))
        return out;

    Digest private_binding = absent_lane_binding(0x50524956415445ULL);
    Digest transfer_binding = absent_lane_binding(0x5452414e53464552ULL);
    bool ok = true;
    size_t checked = 0;
    size_t mismatches = 0;
    Digest private_participants{};
    Digest private_challenge_transcript{};
    Digest private_challenge{};
    Digest private_residual{};
    Digest transfer_transcript{};
    Digest transfer_auth{};

    if (components.private_present) {
        if (!validate_collective_batch_result(
                partition.private_scope, components.private_result, world_size))
            return out;
        private_binding = compute_collective_batch_result_binding(
            components.private_result);
        ok = ok && components.private_result.ok;
        checked += components.private_result.checked_operations;
        mismatches += components.private_result.mismatches;
        private_participants = components.private_result.participant_commitment_root;
        private_challenge_transcript = components.private_result.challenge_transcript_binding;
        private_challenge = components.private_result.challenge;
        private_residual = components.private_result.aggregate_residual_commitment;
    }
    if (components.transfer_present) {
        if (!validate_public_transfer_check_result(
                partition.transfer_scope, components.transfer_result))
            return out;
        transfer_binding = compute_public_transfer_check_binding(
            components.transfer_result);
        ok = ok && components.transfer_result.ok;
        checked += components.transfer_result.checked_operations;
        mismatches += components.transfer_result.mismatches;
        transfer_transcript = components.transfer_result.transcript_binding;
        transfer_auth = components.transfer_result.authentication_commitment;
    }
    out.available = true;
    out.cryptographically_authenticated = true;
    out.ok = ok;
    out.checked_operations = checked;
    out.mismatches = mismatches;
    out.participant_count = static_cast<size_t>(world_size);
    out.scope_binding = compute_collective_scope_binding(full_scope);
    out.participant_commitment_root = combine_lane_bindings(
        0x4859425249445001ULL, private_participants, transfer_transcript);
    out.challenge_transcript_binding = combine_lane_bindings(
        0x4859425249445002ULL, private_challenge_transcript, transfer_auth);
    out.challenge = combine_lane_bindings(
        0x4859425249445003ULL, private_challenge, transfer_binding);
    out.aggregate_residual_commitment = combine_lane_bindings(
        0x4859425249445004ULL, private_residual, transfer_binding);
    return out;
}

bool validate_hybrid_audit_batch_envelope(
    const ObligationSet& full_scope,
    const AuditScopePartition& partition,
    const HybridAuditBatchComponents& components,
    const BatchCheckResult& envelope,
    int world_size) {
    const BatchCheckResult expected = make_hybrid_audit_batch_envelope(
        full_scope, partition, components, world_size);
    return expected.available && same_batch(expected, envelope);
}

} // namespace pvia
