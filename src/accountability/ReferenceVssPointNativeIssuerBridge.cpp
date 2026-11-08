#include "ReferenceVssPointNativeIssuerBridge.hpp"

#include <cstring>
#include <vector>

namespace pvia {
namespace {
constexpr u64 NATIVE_EXECUTION_DOMAIN = 0x5056534e49534231ULL; // PVSNISB1
void append_digest(std::vector<u64>* words, const Digest& digest) {
    for (size_t i = 0; i < 32; i += 8) {
        u64 word = 0;
        for (size_t j = 0; j < 8; ++j)
            word |= static_cast<u64>(digest.bytes[i + j]) << (8 * j);
        words->push_back(word);
    }
}
void append_bytes(std::vector<u64>* words, const uint8_t* bytes, size_t count) {
    for (size_t i = 0; i < count; i += 8) {
        u64 word = 0;
        for (size_t j = 0; j < 8 && i + j < count; ++j)
            word |= static_cast<u64>(bytes[i + j]) << (8 * j);
        words->push_back(word);
    }
}
} // namespace

bool derive_verified_reference_vss_native_execution_binding(
    const ReferenceVssSelectivePointCommitmentRegistry& registry,
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeIssuerReleaseEvidence& evidence,
    const Digest& expected_consumed,
    const std::array<uint8_t, 32>& expected_key,
    u64 expected_issuer, u64 minimum_sequence,
    Digest* output) {
    if (!output) return false;
    *output = {};
    if (!validate_reference_vss_point_commitment_registry(registry) ||
        !validate_registration_consistency_statement(statement) ||
        statement.kernel != AuditRelationKernel::FOLD_RS ||
        statement.sid != registry.sid ||
        statement.checkpoint != registry.checkpoint ||
        statement.sharing_transcript_binding != registry.vss_transcript ||
        expected_consumed == Digest{} || !expected_issuer ||
        !minimum_sequence ||
        !verify_registration_native_issuer_release_evidence(
            statement, evidence, expected_consumed, expected_key,
            expected_issuer, minimum_sequence))
        return false;
    std::vector<u64> words = {
        NATIVE_EXECUTION_DOMAIN, registry.sid, registry.checkpoint,
        evidence.source_receipt.issuer_id, evidence.source_receipt.sequence
    };
    append_digest(&words, registry.vss_transcript);
    append_digest(&words, statement.statement_binding);
    append_digest(&words, evidence.source_receipt.pre_vss_claim_binding);
    append_digest(&words, evidence.source_receipt.consumed_record_binding);
    append_digest(&words, evidence.final_statement_binding);
    append_bytes(&words, expected_key.data(), expected_key.size());
    append_bytes(&words, evidence.source_receipt.signature.data(),
                 evidence.source_receipt.signature.size());
    append_bytes(&words, evidence.final_signature.data(),
                 evidence.final_signature.size());
    const Digest result = hash_words(words);
    if (result == Digest{}) return false;
    *output = result;
    return true;
}

bool save_reference_vss_registry_from_verified_native_issuer(
    const std::string& path,
    const ReferenceVssSelectivePointCommitmentRegistry& registry,
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeIssuerReleaseEvidence& evidence,
    const Digest& expected_consumed,
    const std::array<uint8_t, 32>& expected_key,
    u64 expected_issuer, u64 minimum_sequence,
    Digest* native_binding, Digest* record_binding) {
    if (!native_binding || !record_binding) return false;
    *native_binding = {};
    *record_binding = {};
    Digest verified{};
    if (!derive_verified_reference_vss_native_execution_binding(
            registry, statement, evidence, expected_consumed,
            expected_key, expected_issuer, minimum_sequence, &verified))
        return false;
    Digest saved{};
    if (!save_reference_vss_point_registry_execution_record(
            path, registry, verified, &saved))
        return false;
    *native_binding = verified;
    *record_binding = saved;
    return true;
}
} // namespace pvia
