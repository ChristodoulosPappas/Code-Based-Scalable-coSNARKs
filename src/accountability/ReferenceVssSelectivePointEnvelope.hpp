#pragma once

#include "ReferenceVssSelectivePointRecovery.hpp"
#include "AuthenticatedMpcExchange.hpp"

#include <map>
#include <tuple>
#include <vector>

namespace pvia {

// P1-03 selective-point transport v1.  The signed AuthenticatedMpcExchange
// AllToAllWords frame authenticates the physical sender/receiver; this nested
// envelope binds the semantic sender, intended target, externally supplied
// session and checkpoint, sequence, VSS receipt and exact point values.
constexpr u64 PVIA_VSS_SELECTIVE_POINT_DOMAIN = 0x50565653504f494eULL;
constexpr u64 PVIA_VSS_SELECTIVE_POINT_KIND = 0x5056504f494e5431ULL;
constexpr u64 PVIA_VSS_SELECTIVE_POINT_VERSION = 1;

// Caller must select an independently meaningful SID/checkpoint.  Reusing a
// VSS transcript digest alone is NOT a session-uniqueness guarantee.
bool encode_reference_vss_selective_point_envelope(
    const ReferenceVssSelectivePoint& point,
    const ReferenceVssReceipt& receipt,
    const AuthenticatedMpcMessageContext& message_context,
    std::vector<u64>* words);

// Only call on packets obtained from a SUCCESSFUL authenticated exchange.
// expected_sender must be the verified MPI sender slot, not a claimed ID.
bool decode_reference_vss_selective_point_envelope(
    const std::vector<u64>& words,
    int expected_sender, int expected_target,
    const ReferenceVssReceipt& receipt,
    const ReferenceVssTranscriptContext& trusted_transcript,
    const AuthenticatedMpcMessageContext& expected_context,
    ReferenceVssSelectivePoint* point);

// Receiver-local anti-replay state for already validated, authenticated packets.
// Scope it to the lifetime of the protocol session; do not reset on retries.
class ReferenceVssSelectivePointReplayGuard {
public:
    bool Observe(const AuthenticatedMpcMessageContext& context,
                 int sender, int target);
private:
    using Key = std::tuple<u64, CheckpointId, int, int>;
    std::map<Key, uint64_t> highest_sequence_;
};

} // namespace pvia
