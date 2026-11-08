#pragma once
#include "ReferenceBivariateVss.hpp"

namespace pvia {
// Reference-only witness aggregation. Recover full VSS dealer polynomial
// from t+1 separately held private row witnesses, without reading the
// original dealer polynomial. The aggregator learns all secret values.
// Never expose this API/its output in the public verifier or call it
// a fully distributed privacy-preserving proof.
bool reconstruct_reference_vss_dealer_from_rows(
    const ReferenceVssReceipt& trusted_receipt,
    const std::vector<ReferenceVssLocalWitness>& helper_rows,
    ReferenceVssDealerWitness* reconstructed);
} // namespace pvia
