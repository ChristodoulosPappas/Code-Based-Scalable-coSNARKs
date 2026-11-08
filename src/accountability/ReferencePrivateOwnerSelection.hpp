#pragma once

#include "ReferenceShamirMpc.hpp"
#include <cstdint>
#include <vector>

namespace pvia {

// P1-05 reference building block: caller supplies degree-t secret-shared,
// authenticated, semantically correct Boolean fault indicators. No branch,
// subset, index or operation label is opened. The output is ONLY j*.
// This is a passive BGW reference component and is NOT a malicious-secure
// implementation of the entire R_q / causal admissibility relation.
struct ReferencePrivateOwnerSelectionResult {
    bool available=false;
    bool found=false;
    uint32_t attributed_party=0;
    Digest circuit_binding{};
    uint64_t multiplication_count=0;
};

bool select_reference_private_fault_owner(
    const ReferenceShamirMpc& mpc,
    const std::vector<F>& local_boolean_indicator_shares,
    const std::vector<uint32_t>& public_owner_layout,
    u64 sid, CheckpointId checkpoint,
    ReferencePrivateOwnerSelectionResult* result);

} // namespace pvia
