#pragma once
#include "ReferenceBivariateVss.hpp"
#include <vector>

namespace pvia {
// Reference/offline reconstruction of participant j's missing degree-t
// share f(j,0) from t+1 distinct committed bivariate helper rows f(i,Y).
// The caller must independently trust receipt.transcript_binding; row
// commitments are hashes, NOT a privacy-preserving polynomial opening proof.
// This interface consumes PRIVATE helper rows and must not be called to
// populate a public PVIA attribution artifact.
bool recover_reference_vss_share_from_rows(
    int missing_participant,
    const ReferenceVssReceipt& trusted_receipt,
    const std::vector<ReferenceVssLocalWitness>& helper_rows,
    std::vector<F>* recovered_share);
} // namespace pvia
