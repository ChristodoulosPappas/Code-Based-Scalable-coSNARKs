#pragma once
#include "ReferenceShamirMpc.hpp"
#include <vector>

namespace pvia {

// Field-specific reference-MPC nonzero relation. Input is a degree-t
// authenticated Shamir sharing of native residual(s). Produces degree-t
// Shamir shares of [x != 0]; never opens per-candidate zero results.
//
// Requires F = GF(p)[i]/(i^2+1), p=2^61-1 (p=3 mod 4). This is passive
// BGW and does not prove native-state provenance or malicious resilience.
bool derive_reference_private_nonzero_flags(
    const ReferenceShamirMpc& mpc,
    const std::vector<F>& local_residual_shares,
    std::vector<F>* local_nonzero_indicator_shares,
    uint64_t* multiplication_count);

} // namespace pvia
