#pragma once

#include "PrivateResidualRegistry.hpp"
#include "RegistrationNativeExecutionReceipt.hpp"
#include "PrivateResidualShareStore.hpp"
#include <array>
#include <cstdint>
#include <vector>
#include <string>

namespace pvia {

// Local-only, issuer-signed bridge between an independently known native
// consumed-source record and the pre-activation private residual handles.
// The public operation layout/scope is bound, but the private source root
// and this receipt are NOT to be included in the public localization trace.
struct ResidualNativeSourcePinReceipt {
    u64 issuer_id = 0;
    u64 sequence = 0;
    u64 sid = 0;
    CheckpointId checkpoint = 0;
    uint32_t owner = 0;
    Digest scope_binding{};
    Digest local_residual_root{};
    Digest native_consumed_record_binding{};
    Digest registration_pre_vss_claim_binding{};
    std::array<uint8_t, 64> signature{};
};

// Stable message for EXTERNALLY authorized Ed25519 issuer to sign.
// No state, residual coordinates or other plaintext are serialized.
std::vector<uint8_t> residual_native_source_pin_signing_message(
    const ResidualNativeSourcePinReceipt& receipt);

// Publicly specified binary file for an externally signed source pin.
// PVNPIN01, fixed-width little-endian metadata, four digests and signature.
// Read/write helpers refuse symlinks; new files are created owner-only.
bool write_residual_native_source_pin_receipt_file(
    const std::string& new_file,
    const ResidualNativeSourcePinReceipt& receipt);
bool read_residual_native_source_pin_receipt_file(
    const std::string& file,
    ResidualNativeSourcePinReceipt* receipt);

// Only the relying party can supply the pinned issuer key, accepted
// issuer identity, monotonic sequence policy and expected native-source
// bindings; receipt fields cannot choose their own trust policy.
// Require TWO signed statements by the same independently trusted issuer:
// native-consumed execution first, then the residual root linked to that
// EXACT claim, consumed source and issuance sequence.
bool verify_residual_source_pin_and_native_execution_pair(
    const ObligationSet& scope, uint32_t local_owner,
    const ResidualNativeSourcePinReceipt& residual_pin,
    const RegistrationConsistencyStatement& registration_pre_vss,
    const RegistrationNativeExecutionReceipt& native_receipt,
    const Digest& independently_expected_native_consumed_binding,
    const std::array<uint8_t,32>& independently_pinned_issuer_key,
    u64 expected_issuer_id, u64 minimum_accepted_sequence);

// Optional stronger activation link: require the per-operation private
// residual provenance artifact to be signed by the same issuer at the exact
// sequence used for the local residual source-pin receipt.
bool verify_private_residual_provenance_matches_source_pin(
    const PrivateResidualShare& share,
    const ResidualNativeSourcePinReceipt& residual_pin,
    const std::array<uint8_t,32>& independently_pinned_issuer_key,
    u64 expected_issuer_id,
    u64 minimum_accepted_sequence);

bool verify_residual_native_source_pin_receipt(
    const ObligationSet& scope,
    uint32_t local_owner,
    const ResidualNativeSourcePinReceipt& receipt,
    const Digest& independently_expected_native_consumed_binding,
    const Digest& independently_expected_pre_vss_claim_binding,
    const std::array<uint8_t,32>& independently_pinned_issuer_key,
    u64 expected_issuer_id,
    u64 minimum_accepted_sequence);

} // namespace pvia
