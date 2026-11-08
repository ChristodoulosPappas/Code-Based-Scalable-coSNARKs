#pragma once

#include "PVIA.hpp"

#include <vector>

namespace pvia {

// One batch-global coefficient domain: deliberately excludes subset, depth
// and selected branch. Reused verbatim by the batch and every localization
// subset. This is algebraic compatibility, NOT location privacy.
F derive_residual_batch_global_coefficient(
    u64 sid, CheckpointId checkpoint,
    const Digest& batch_challenge,
    const Digest& batch_challenge_transcript,
    const OperationRef& operation, size_t coordinate);

// Deterministic algebraic selftest over 8/32/64 operations. It checks
// parent = left + right for the same transcript and catches accidentally
// using a depth/subset-specific transcript for the child.
bool run_residual_batch_global_additivity_selftest();

} // namespace pvia
