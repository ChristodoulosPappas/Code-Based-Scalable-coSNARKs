#include "RegistrationPreVssReceipt.hpp"
#include "TransferAuthentication.hpp"

namespace pvia {

std::vector<u64> registration_pre_vss_claim_words(
    const RegistrationConsistencyStatement& statement) {
    // Canonical validation here is performed with a constant dummy
    // post-sharing digest. That dummy MUST NOT be part of this message.
    RegistrationConsistencyStatement public_prefix = statement;
    public_prefix.sharing_transcript_binding =
        hash_words({0x5056524558505258ULL}); // PVREXPRX
    public_prefix.statement_binding =
        compute_registration_consistency_statement_binding(public_prefix);
    auto full = encode_registration_consistency_statement_words(public_prefix);
    if (full.size() != 46) return {};
    // 42 statement payload words - 4 sharing transcript words = 38.
    full.resize(38);
    return full;
}

bool verify_registration_pre_vss_receipt(
    const RegistrationConsistencyStatement& statement,
    const RegistrationPreVssReceipt& receipt,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& independently_trusted_registry_commitment,
    uint32_t expected_signer) {
    const auto words = registration_pre_vss_claim_words(statement);
    return words.size() == 38 && receipt.signer == expected_signer &&
        expected_signer < public_keys.size() &&
        public_keys.size() >= 4 &&
        independently_trusted_registry_commitment != Digest{} &&
        verify_ed25519_words_with_public_registry(
            REGISTRATION_PRE_VSS_RECEIPT_DOMAIN, words,
            receipt.signature, receipt.signer, public_keys,
            independently_trusted_registry_commitment);
}

} // namespace pvia
