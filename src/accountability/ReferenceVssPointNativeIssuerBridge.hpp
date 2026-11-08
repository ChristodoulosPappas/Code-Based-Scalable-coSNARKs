#pragma once
#include "ReferenceVssSelectivePointRegistryStore.hpp"
#include "RegistrationNativeExecutionReceipt.hpp"

#include <array>
#include <string>

namespace pvia {

// Derive a native-execution binding ONLY from the independently pinned,
// successfully verified native issuer's paired source + final release
// Ed25519 evidence. The final statement must name this exact VSS transcript
// and SID/checkpoint. This does not validate a ZK proof or issuer governance.
bool derive_verified_reference_vss_native_execution_binding(
    const ReferenceVssSelectivePointCommitmentRegistry& registry,
    const RegistrationConsistencyStatement& final_statement,
    const RegistrationNativeIssuerReleaseEvidence& signed_evidence,
    const Digest& independently_expected_consumed_record,
    const std::array<uint8_t, 32>& independently_pinned_issuer_key,
    u64 expected_issuer_id, u64 minimum_issuer_sequence,
    Digest* native_execution_binding);

// Fail-closed bridge into the existing disk registry API: callers store the
// independently returned record anchor in an authenticated execution journal,
// not inside the same registry file.
bool save_reference_vss_registry_from_verified_native_issuer(
    const std::string& path,
    const ReferenceVssSelectivePointCommitmentRegistry& registry,
    const RegistrationConsistencyStatement& final_statement,
    const RegistrationNativeIssuerReleaseEvidence& signed_evidence,
    const Digest& independently_expected_consumed_record,
    const std::array<uint8_t, 32>& independently_pinned_issuer_key,
    u64 expected_issuer_id, u64 minimum_issuer_sequence,
    Digest* native_execution_binding,
    Digest* independent_record_binding);

} // namespace pvia
