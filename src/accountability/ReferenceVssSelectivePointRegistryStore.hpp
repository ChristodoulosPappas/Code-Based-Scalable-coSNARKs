#pragma once

#include "ReferenceVssSelectivePointCommitment.hpp"

#include <string>

namespace pvia {

// The caller MUST retain the record binding separately from the disk file.
// native_execution_binding is an independently established binding to the
// native execution/consumed input record, NOT a value learned from the file.
// No private VSS rows, field values, or secret keys are stored here.
struct ReferenceVssPointRegistryExecutionRecord {
    ReferenceVssSelectivePointCommitmentRegistry registry;
    Digest native_execution_binding{};
    Digest record_binding{};
};

// Produces the independent journal anchor to pin after authenticated setup.
Digest compute_reference_vss_point_registry_execution_binding(
    const ReferenceVssSelectivePointCommitmentRegistry& registry,
    const Digest& native_execution_binding);

// Store only the authenticated registry and public digests, atomically.
// The returned binding MUST be retained outside this file (e.g. in the
// externally authenticated native execution journal).
bool save_reference_vss_point_registry_execution_record(
    const std::string& path,
    const ReferenceVssSelectivePointCommitmentRegistry& registry,
    const Digest& native_execution_binding,
    Digest* independent_record_binding);

// Reload refuses a self-anchored file: the independent expected record hash
// and expected native execution binding must both be provided by caller.
bool load_reference_vss_point_registry_execution_record(
    const std::string& path,
    const Digest& expected_record_binding,
    const Digest& expected_native_execution_binding,
    u64 expected_sid,
    CheckpointId expected_checkpoint,
    const Digest& expected_vss_transcript,
    ReferenceVssPointRegistryExecutionRecord* record);

// Combined durable-load and checked interpolation path; never interpolates
// an unanchored or invalidly opened share.
bool recover_reference_vss_share_from_persisted_points(
    const std::string& path,
    const Digest& expected_record_binding,
    const Digest& expected_native_execution_binding,
    int target,
    const ReferenceVssReceipt& receipt,
    const ReferenceVssTranscriptContext& transcript,
    const AuthenticatedMpcMessageContext& release_context,
    const std::vector<ReferenceVssSelectivePoint>& openings,
    std::vector<F>* recovered);

} // namespace pvia
