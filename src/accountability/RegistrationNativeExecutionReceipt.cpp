#include "RegistrationNativeExecutionReceipt.hpp"
#include "RegistrationPreVssReceipt.hpp"

#include <algorithm>
#include <openssl/evp.h>

namespace pvia {
namespace {
constexpr u64 NATIVE_ISSUER_RECEIPT_DOMAIN = 0x5056524e49535331ULL; // PVRNISS1
constexpr u64 NATIVE_ISSUER_RECEIPT_VERSION = 1;
constexpr u64 NATIVE_EXECUTION_ATTESTATION_DOMAIN = 0x5056524e45584531ULL; // PVRNEXE1
constexpr u64 NATIVE_EXECUTION_ATTESTATION_VERSION = 1;

void append_word_le(std::vector<uint8_t>* bytes, u64 value) {
    for (size_t i = 0; i < 8; ++i)
        bytes->push_back(static_cast<uint8_t>(value >> (8 * i)));
}
void append_digest(std::vector<uint8_t>* bytes, const Digest& d) {
    bytes->insert(bytes->end(), d.bytes.begin(), d.bytes.end());
}
bool nonzero_key(const std::array<uint8_t, 32>& key) {
    return std::any_of(key.begin(), key.end(),
                       [](uint8_t byte) { return byte != 0; });
}
} // namespace

std::vector<uint8_t> registration_native_execution_receipt_message(
    const RegistrationConsistencyStatement& proposed_pre_vss,
    u64 issuer_id, u64 sequence,
    const Digest& pre_vss_claim_binding,
    const Digest& consumed_record_binding) {
    if (!issuer_id || !sequence || pre_vss_claim_binding == Digest{} ||
        consumed_record_binding == Digest{})
        return {};
    const auto claim = registration_pre_vss_claim_words(proposed_pre_vss);
    if (claim.size() != 38 ||
        hash_words(claim) != pre_vss_claim_binding)
        return {};
    std::vector<uint8_t> bytes;
    bytes.reserve((4 + 38) * 8 + 64);
    append_word_le(&bytes, NATIVE_ISSUER_RECEIPT_DOMAIN);
    append_word_le(&bytes, NATIVE_ISSUER_RECEIPT_VERSION);
    append_word_le(&bytes, issuer_id);
    append_word_le(&bytes, sequence);
    for (const u64 word : claim) append_word_le(&bytes, word);
    append_digest(&bytes, pre_vss_claim_binding);
    append_digest(&bytes, consumed_record_binding);
    return bytes;
}

std::vector<uint8_t> registration_native_execution_attestation_message(
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeConsumedSnapshot& snapshot,
    const AuditCheckpointView& checkpoint,
    const Digest& scope_binding,
    const Digest& local_residual_root) {
    const Digest source_binding =
        compute_registration_native_consumed_record_binding(
            statement, snapshot, checkpoint);
    const auto claim = registration_pre_vss_claim_words(statement);
    if (source_binding == Digest{} ||
        source_binding != snapshot.consumed_record_binding ||
        claim.size() != 38 ||
        hash_words(claim) != snapshot.pre_vss_claim_binding ||
        scope_binding == Digest{} || local_residual_root == Digest{})
        return {};

    const Digest state_digest = hash_field_vector(snapshot.state_values);
    const Digest output_digest = hash_field_vector(snapshot.actual_output);
    const Digest challenge_digest =
        hash_field_vector({snapshot.public_challenge});
    std::vector<uint8_t> message;
    message.reserve(10 * 8 + 9 * 32);
    append_word_le(&message, NATIVE_EXECUTION_ATTESTATION_DOMAIN);
    append_word_le(&message, NATIVE_EXECUTION_ATTESTATION_VERSION);
    append_word_le(&message, statement.sid);
    append_word_le(&message, statement.checkpoint);
    append_word_le(&message, static_cast<u64>(statement.ref.owner));
    append_word_le(&message, statement.ref.object_id);
    append_word_le(&message, statement.native_context.native_state_id);
    append_word_le(&message,
                   statement.native_context.authentication_scheme_id);
    append_word_le(&message, snapshot.state_values.size());
    append_word_le(&message, snapshot.actual_output.size());
    append_digest(&message, snapshot.pre_vss_claim_binding);
    append_digest(&message, state_digest);
    append_digest(&message, output_digest);
    append_digest(&message, challenge_digest);
    append_digest(&message, checkpoint.root);
    append_digest(&message, scope_binding);
    append_digest(&message, local_residual_root);
    append_digest(&message, statement.native_context.authentication_binding);
    append_digest(&message, source_binding);
    return message;
}

bool verify_registration_native_execution_receipt_public(
    const RegistrationConsistencyStatement& proposed_pre_vss,
    const RegistrationNativeExecutionReceipt& receipt,
    const Digest& independently_expected_consumed_record_binding,
    const std::array<uint8_t, 32>& expected_issuer_public_key,
    u64 expected_issuer_id,
    u64 minimum_accepted_sequence) {
    if (!expected_issuer_id || !minimum_accepted_sequence ||
        !nonzero_key(expected_issuer_public_key) ||
        independently_expected_consumed_record_binding == Digest{} ||
        receipt.issuer_id != expected_issuer_id ||
        receipt.sequence < minimum_accepted_sequence ||
        receipt.sequence == 0 ||
        receipt.consumed_record_binding !=
            independently_expected_consumed_record_binding)
        return false;
    const auto bytes = registration_native_execution_receipt_message(
        proposed_pre_vss, receipt.issuer_id, receipt.sequence,
        receipt.pre_vss_claim_binding, receipt.consumed_record_binding);
    if (bytes.empty()) return false;
    EVP_PKEY* public_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, expected_issuer_public_key.data(),
        expected_issuer_public_key.size());
    if (!public_key) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const bool valid = ctx &&
        EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, public_key) == 1 &&
        EVP_DigestVerify(ctx, receipt.signature.data(),
                         receipt.signature.size(),
                         bytes.data(), bytes.size()) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(public_key);
    return valid;
}

std::vector<uint8_t> registration_native_issuer_release_message(
    const RegistrationConsistencyStatement& final_statement,
    const RegistrationNativeExecutionReceipt& source_receipt) {
    constexpr u64 RELEASE_DOMAIN = 0x5056524e49535232ULL; // PVRNISR2
    constexpr u64 RELEASE_VERSION = 2;
    const auto words =
        encode_registration_consistency_statement_words(final_statement);
    if (words.size() != 46 ||
        source_receipt.issuer_id == 0 || source_receipt.sequence == 0 ||
        source_receipt.pre_vss_claim_binding == Digest{} ||
        source_receipt.consumed_record_binding == Digest{})
        return {};
    const auto prefix = registration_pre_vss_claim_words(final_statement);
    if (prefix.size() != 38 ||
        hash_words(prefix) != source_receipt.pre_vss_claim_binding)
        return {};
    std::vector<uint8_t> message;
    append_word_le(&message, RELEASE_DOMAIN);
    append_word_le(&message, RELEASE_VERSION);
    append_word_le(&message, source_receipt.issuer_id);
    append_word_le(&message, source_receipt.sequence);
    for (u64 word : words) append_word_le(&message, word);
    append_digest(&message,source_receipt.consumed_record_binding);
    message.insert(message.end(),source_receipt.signature.begin(),
                   source_receipt.signature.end());
    return message;
}

bool verify_registration_native_issuer_release_evidence(
    const RegistrationConsistencyStatement& final_statement,
    const RegistrationNativeIssuerReleaseEvidence& evidence,
    const Digest& independently_expected_consumed_record_binding,
    const std::array<uint8_t, 32>& public_key,
    u64 expected_issuer_id, u64 minimum_accepted_sequence) {
    if (evidence.final_statement_binding == Digest{} ||
        evidence.final_statement_binding != final_statement.statement_binding ||
        !verify_registration_native_execution_receipt_public(
            final_statement, evidence.source_receipt,
            independently_expected_consumed_record_binding, public_key,
            expected_issuer_id, minimum_accepted_sequence))
        return false;
    const auto message=registration_native_issuer_release_message(
        final_statement,evidence.source_receipt);
    if (message.empty()) return false;
    EVP_PKEY* key=EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519,nullptr,public_key.data(),public_key.size());
    if (!key) return false;
    EVP_MD_CTX* ctx=EVP_MD_CTX_new();
    const bool valid=ctx &&
        EVP_DigestVerifyInit(ctx,nullptr,nullptr,nullptr,key)==1 &&
        EVP_DigestVerify(ctx,evidence.final_signature.data(),
                         evidence.final_signature.size(),
                         message.data(),message.size())==1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return valid;
}

bool verify_registration_native_execution_receipt(
    const RegistrationConsistencyStatement& proposed_pre_vss,
    const RegistrationNativeConsumedSnapshot& actual_source,
    const RegistrationNativeExecutionReceipt& receipt,
    const std::array<uint8_t, 32>& expected_issuer_public_key,
    u64 expected_issuer_id,
    u64 minimum_accepted_sequence) {
    return actual_source.pre_vss_claim_binding != Digest{} &&
        receipt.pre_vss_claim_binding ==
            actual_source.pre_vss_claim_binding &&
        verify_registration_native_execution_receipt_public(
            proposed_pre_vss, receipt,
            actual_source.consumed_record_binding,
            expected_issuer_public_key,
            expected_issuer_id, minimum_accepted_sequence);
}
} // namespace pvia
