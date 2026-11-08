#pragma once

#include "RegistrationOriginEndorsements.hpp"
#include "RegistrationPreVssReceipt.hpp"

namespace pvia {

// PUBLIC-only joint evidence: same signer set authenticates the pre-VSS
// native-state prefix and the finalized post-VSS 46-word statement.
// The public key registry hash is a CALLER-SUPPLIED trust anchor;
// computing it from evidence supplied by an untrusted prover is unsafe.
//
// Cryptographic scope: authenticity of signer assertions only.
// Does not prove source-native equality, local-state consumption,
// non-equivocation by dishonest signers, or full distributed ZK.
struct RegistrationOriginEvidencePair {
    std::vector<RegistrationPreVssReceipt> pre_vss_receipts;
    std::vector<RegistrationOriginEndorsement> final_endorsements;
};

bool verify_registration_origin_evidence_pair(
    const RegistrationConsistencyStatement& statement,
    const RegistrationOriginEvidencePair& evidence,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& independently_trusted_registry_commitment,
    size_t minimum_distinct_signers,
    bool require_owner_signature);

} // namespace pvia
