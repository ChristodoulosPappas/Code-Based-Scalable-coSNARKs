#pragma once
#include "RegistrationConsistencyProof.hpp"
#include <array>
#include <cstdint>
#include <vector>

namespace pvia {

// Separate domain from the signed final 46-word registration statement.
// This is a signer-asserted pre-sharing snapshot, not an independent
// attestation that an honest native executor consumed those secret shares.
constexpr u64 REGISTRATION_PRE_VSS_RECEIPT_DOMAIN =
    0x5056524558454352ULL; // PVREXECR

struct RegistrationPreVssReceipt {
    uint32_t signer = 0;
    std::array<uint8_t, 64> signature{};
};

// Canonical 38-word prefix through operation_statement_binding, excluding
// the post-VSS transcript digest and final statement-binding digest.
// Input may be a pre-VSS statement with unset sharing fields.
std::vector<u64> registration_pre_vss_claim_words(
    const RegistrationConsistencyStatement& statement);

// The expected key registry commitment must be pinned by the caller.
// Neither receipt nor session-supplied key bytes are a trust anchor.
bool verify_registration_pre_vss_receipt(
    const RegistrationConsistencyStatement& statement,
    const RegistrationPreVssReceipt& receipt,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& independently_trusted_registry_commitment,
    uint32_t expected_signer);

} // namespace pvia
