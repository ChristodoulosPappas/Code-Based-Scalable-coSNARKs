#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace pvia {

// Reference-only public signature checks. This does NOT authenticate an MPC
// residual share, a VSS witness, or any proof-release decision.
struct ReferenceResidualPairExpected {
    uint64_t issuer_id = 0;
    uint64_t sequence = 0;
    std::array<uint8_t,32> issuer_public_key{};
    std::array<uint8_t,32> pre_vss_claim_binding{};
    std::array<uint8_t,32> consumed_source_binding{};
    std::array<uint8_t,32> residual_computation_binding{};
    std::array<uint8_t,32> residual_commitment{};
    std::vector<uint8_t> canonical_native_message;
};

// The expected fields and pinned key must come from independent policy and
// already-verified source material, NOT directly from the receipts below.
bool VerifyReferenceResidualPairPublic(
    const ReferenceResidualPairExpected& expected,
    const std::vector<uint8_t>& native_receipt,
    const std::vector<uint8_t>& reference_link_receipt);

// Prevent symlink / special file reads, require exact known wire lengths.
bool ReadReferenceResidualPairWire(
    const std::string& native_path, const std::string& link_path,
    std::vector<uint8_t>* native_receipt,
    std::vector<uint8_t>* reference_link_receipt);
}
