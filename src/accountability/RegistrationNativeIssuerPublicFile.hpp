#pragma once

#include "RegistrationNativeExecutionReceipt.hpp"
#include <string>

namespace pvia {

// V1 public-only binary: 8-byte PVNISS01, 2xLE64 metadata,
// two 32-byte commitments, 64-byte Ed25519 signature (152 bytes).
// Caller-provided issuer trust policy NEVER travels with the file.
bool write_registration_native_issuer_public_file(
    const std::string& new_file,
    const RegistrationNativeExecutionReceipt& receipt);

bool read_registration_native_issuer_public_file(
    const std::string& file,
    RegistrationNativeExecutionReceipt* receipt);

bool verify_registration_native_issuer_public_file(
    const std::string& file,
    const RegistrationConsistencyStatement& expected_statement,
    const Digest& independently_expected_consumed_binding,
    const std::array<uint8_t, 32>& independently_pinned_issuer_key,
    u64 expected_issuer_id,
    u64 minimum_accepted_sequence);

// V2 wire (PVNISS02): signed 152-byte source declaration, then
// final 46-word statement binding (32 bytes), final signature (64 bytes).
// Total is exactly 248 bytes; V1 remains read-only via explicit CLI.
bool write_registration_native_issuer_release_file(
    const std::string& new_file,
    const RegistrationNativeIssuerReleaseEvidence& evidence);
bool read_registration_native_issuer_release_file(
    const std::string& file,
    RegistrationNativeIssuerReleaseEvidence* evidence);
bool verify_registration_native_issuer_release_file(
    const std::string& file,
    const RegistrationConsistencyStatement& final_statement,
    const Digest& independently_expected_consumed_binding,
    const std::array<uint8_t, 32>& independently_pinned_issuer_key,
    u64 expected_issuer_id, u64 minimum_accepted_sequence);

bool parse_native_issuer_public_key_hex(
    const std::string& hex, std::array<uint8_t, 32>* output);

} // namespace pvia
