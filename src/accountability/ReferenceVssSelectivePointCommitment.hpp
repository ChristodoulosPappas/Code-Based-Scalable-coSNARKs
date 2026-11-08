#pragma once

#include "ReferenceVssSelectivePointRecovery.hpp"
#include "AuthenticatedMpcExchange.hpp"

#include <vector>

namespace pvia {

// Reference pre-commitment phase.  Each source authenticates one digest per
// target; each target checks that source's digest against its own symmetric
// VSS row while it is still available.  The confirmed matrix is subsequently
// retained by the receiver when only targeted point openings are released.
// Not a generic polynomial commitment or a zero-knowledge opening proof.
constexpr u64 PVIA_VSS_POINT_SETUP_KIND = 0x5056535053455431ULL; // PVSPSET1
constexpr u64 PVIA_VSS_POINT_ACK_KIND   = 0x5056535041434b31ULL; // PVSPACK1

struct ReferenceVssSelectivePointCommitmentRegistry {
    bool available = false;
    int world_size = 0;
    size_t element_count = 0;
    Digest vss_transcript{};
    u64 sid = 0;
    CheckpointId checkpoint = 0;
    u64 setup_round = 0;
    u64 setup_sequence = 0;
    Digest setup_context_binding{};
    Digest signed_commit_transport{};
    Digest signed_ack_transport{};
    Digest registry_binding{};
    // Indexed by [helper * world_size + target].  Commitments are domain-
    // separated, salted by session context and bound to the VSS transcript.
    std::vector<Digest> commitments;
};

// Validates the complete in-memory registry state, including the transport
// receipts and recomputed matrix binding. A hash in an untrusted disk record
// is not an independent authenticity anchor.
bool validate_reference_vss_point_commitment_registry(
    const ReferenceVssSelectivePointCommitmentRegistry& registry);

// Must be called collectively before a target discards its VSS local row.
// Requires the same valid external SID/checkpoint on every rank.  On failure
// no usable registry is returned; malicious early setup failures can abort.
bool establish_reference_vss_point_commitment_registry(
    const ReferenceVssLocalWitness& local,
    const ReferenceVssReceipt& receipt,
    const AuthenticatedMpcExchange& exchange,
    const AuthenticatedMpcMessageContext& setup_context,
    ReferenceVssSelectivePointCommitmentRegistry* registry);

// Validate a target-only opening against a previously finalized registry.
// The registry must have been saved from the independently authenticated setup
// and not accepted from an untrusted release message.
bool verify_reference_vss_point_commitment(
    const ReferenceVssSelectivePointCommitmentRegistry& registry,
    const ReferenceVssSelectivePoint& opening,
    const ReferenceVssReceipt& receipt,
    const AuthenticatedMpcMessageContext& release_context);

// Recommended release gate: validate every selective opening against the
// authenticated setup registry BEFORE allowing t+1-point interpolation.
// This prevents callers from accidentally treating a bare row digest or
// a minimally interpolated polynomial as point-opening evidence.
bool recover_reference_vss_share_from_committed_points(
    int target,
    const ReferenceVssReceipt& receipt,
    const ReferenceVssTranscriptContext& trusted_transcript,
    const ReferenceVssSelectivePointCommitmentRegistry& registry,
    const AuthenticatedMpcMessageContext& release_context,
    const std::vector<ReferenceVssSelectivePoint>& openings,
    std::vector<F>* recovered);

} // namespace pvia
