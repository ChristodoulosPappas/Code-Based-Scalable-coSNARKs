#pragma once

#include "RegistrationNativeConsumedSnapshot.hpp"
#include <array>
#include <cstdint>
#include <vector>

namespace pvia {

// A native-execution issuer's assertion about a consumed local record.
// Issuer identity and freshness policy MUST come from the calling
// application, never from key/counter fields supplied with the receipt.
struct RegistrationNativeExecutionReceipt {
    u64 issuer_id = 0;
    u64 sequence = 0;
    Digest pre_vss_claim_binding{};
    Digest consumed_record_binding{};
    std::array<uint8_t, 64> signature{};
};

// Stable, domain-separated Ed25519 message over the exact 38-word
// pre-VSS claim + source record binding + issuer and issuance sequence.
// No state values, shares or other private payloads are serialized.
std::vector<uint8_t> registration_native_execution_receipt_message(
    const RegistrationConsistencyStatement& proposed_pre_vss,
    u64 issuer_id, u64 sequence,
    const Digest& pre_vss_claim_binding,
    const Digest& consumed_record_binding);

// Canonical executor-role attestation over public metadata and digests,
// including scope_binding and local_residual_root used by the source-pin
// receipt. It authenticates the producer's statement, not execution truth
// unless the producer is itself a trusted native execution service.
std::vector<uint8_t> registration_native_execution_attestation_message(
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeConsumedSnapshot& snapshot,
    const AuditCheckpointView& checkpoint,
    const Digest& scope_binding,
    const Digest& local_residual_root);

// Public-only verification of a signed source record. The expected source
// digest and issuer public key must be pinned OUTSIDE the receipt by the
// relying party. This proves signature validity for those public bytes,
// not the private record contents or issuance service behavior.
bool verify_registration_native_execution_receipt_public(
    const RegistrationConsistencyStatement& proposed_pre_vss,
    const RegistrationNativeExecutionReceipt& receipt,
    const Digest& independently_expected_consumed_record_binding,
    const std::array<uint8_t, 32>& independently_pinned_issuer_public_key,
    u64 expected_issuer_id,
    u64 minimum_accepted_sequence);

// Version 2 binds both the source declaration and the actual FINAL
// 46-word registration/VSS transcript. The final release signature is
// domain-separated from the pre-VSS issuer signature.
struct RegistrationNativeIssuerReleaseEvidence {
    RegistrationNativeExecutionReceipt source_receipt{};
    Digest final_statement_binding{};
    std::array<uint8_t, 64> final_signature{};
};

std::vector<uint8_t> registration_native_issuer_release_message(
    const RegistrationConsistencyStatement& final_statement,
    const RegistrationNativeExecutionReceipt& source_receipt);

bool verify_registration_native_issuer_release_evidence(
    const RegistrationConsistencyStatement& final_statement,
    const RegistrationNativeIssuerReleaseEvidence& evidence,
    const Digest& independently_expected_consumed_record_binding,
    const std::array<uint8_t, 32>& independently_pinned_issuer_public_key,
    u64 expected_issuer_id,
    u64 minimum_accepted_sequence);

// Use an externally provisioned 32-byte Ed25519 public key and explicit
// per-execution issuer/sequence policy. Does not establish that the
// external execution provider itself is trustworthy; key governance,
// timing and issuance-counter monotonicity are caller responsibilities.
bool verify_registration_native_execution_receipt(
    const RegistrationConsistencyStatement& proposed_pre_vss,
    const RegistrationNativeConsumedSnapshot& actual_source,
    const RegistrationNativeExecutionReceipt& receipt,
    const std::array<uint8_t, 32>& expected_issuer_public_key,
    u64 expected_issuer_id,
    u64 minimum_accepted_sequence);
} // namespace pvia
