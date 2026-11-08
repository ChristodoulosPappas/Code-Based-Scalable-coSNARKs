#include "RegistrationOriginEvidencePair.hpp"
#include "TransferAuthentication.hpp"

#include <algorithm>

namespace pvia {

bool verify_registration_origin_evidence_pair(
    const RegistrationConsistencyStatement& statement,
    const RegistrationOriginEvidencePair& evidence,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& independently_trusted_registry_commitment,
    size_t minimum_distinct_signers,
    bool require_owner_signature) {
    if (public_keys.size() < 4 ||
        independently_trusted_registry_commitment == Digest{} ||
        evidence.pre_vss_receipts.size() != evidence.final_endorsements.size() ||
        evidence.pre_vss_receipts.empty() ||
        evidence.pre_vss_receipts.size() > public_keys.size() ||
        !validate_registration_consistency_statement(statement))
        return false;

    // A rank-indexed roster must identify distinct actual keys; otherwise
    // one signer can authenticate two nominal participant slots.
    for (size_t i = 0; i < public_keys.size(); ++i) {
        for (size_t j = i + 1; j < public_keys.size(); ++j) {
            if (public_keys[i] == public_keys[j]) return false;
        }
    }

    // Reuse the original complete-statement quorum/owner/ordering checks.
    // This validates every post-VSS signature against the caller's pin.
    if (!verify_registration_origin_endorsements(
            statement, evidence.final_endorsements, public_keys,
            independently_trusted_registry_commitment,
            minimum_distinct_signers, require_owner_signature))
        return false;

    // The two signatures must be from precisely the SAME identity set.
    // Neither a missing pre-VSS receipt nor a different signer's valid
    // receipt may be counted toward the final endorsement quorum.
    const auto& receipts = evidence.pre_vss_receipts;
    const auto& endorsements = evidence.final_endorsements;
    for (size_t i = 0; i < receipts.size(); ++i) {
        if (receipts[i].signer != endorsements[i].signer ||
            !verify_registration_pre_vss_receipt(
                statement, receipts[i], public_keys,
                independently_trusted_registry_commitment,
                endorsements[i].signer))
            return false;
    }
    return true;
}

} // namespace pvia
