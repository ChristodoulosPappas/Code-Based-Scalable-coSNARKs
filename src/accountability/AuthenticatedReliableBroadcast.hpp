#pragma once
#include "AuthenticatedMpcExchange.hpp"
#include <cstddef>
#include <cstdint>
#include <vector>

namespace pvia {

// Synchronous-round Bracha-style reliable broadcast for the reference N=4,t=1
// configuration. It uses authenticated per-recipient AllToAllWords messages.
// All MPI ranks must remain alive; this is not process-crash tolerant.
struct AuthenticatedReliableBroadcastResult {
    bool available = false;
    bool delivered = false;
    std::vector<u64> payload;
    Digest value_binding{};
    Digest transcript_binding{};
    uint32_t echo_support = 0;
    uint32_t ready_support = 0;
    bool authenticated_point_to_point = false;
    bool synchronous_round_model = true;
    bool process_crash_tolerant = false;
};

bool authenticated_reliable_broadcast_n4(
    int rank, int world_size, int broadcaster,
    const std::vector<u64>& local_payload,
    size_t expected_payload_words,
    const AuthenticatedMpcMessageContext& base_context,
    const AuthenticatedMpcExchange& exchange,
    AuthenticatedReliableBroadcastResult* result);

// Exercises honest delivery, per-recipient INIT/READY equivocation, and
// collective rejection of rank-local invalid context/output arguments.
// Intended for the existing N=4 authenticated selftest.
bool run_authenticated_reliable_broadcast_n4_selftest(
    int rank, int world_size,
    const AuthenticatedMpcExchange& exchange);

} // namespace pvia
