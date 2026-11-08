#pragma once
#include "ReferenceBivariateVss.hpp"
#include <vector>

namespace pvia {
// One target-specific field-vector opening computed from one PRIVATE VSS
// row. Unlike dealer-polynomial aggregation this transports no row
// coefficient arrays. The receiving party still needs authenticated
// origin/validity evidence in a production protocol.
struct ReferenceVssSelectivePoint {
    int helper = -1;
    int target = -1;
    Digest transcript_binding{};
    Digest helper_row_commitment{};
    std::vector<F> values;
};

// Source-side locally validate the original row before computing f(i,j).
bool make_reference_vss_selective_point(
    const ReferenceVssLocalWitness& helper,
    int target, ReferenceVssSelectivePoint* opening);

// Receiver-side reference interpolation. The locally trusted complete
// transcript context and receipt are supplied outside point messages.
// Does NOT prove the values match committed rows and does NOT provide
// sender authentication; extra helper points give detection, not correction.
bool recover_reference_vss_share_from_points(
    int target,
    const ReferenceVssReceipt& receipt,
    const ReferenceVssTranscriptContext& trusted_context,
    const std::vector<ReferenceVssSelectivePoint>& openings,
    std::vector<F>* recovered);
} // namespace pvia
