#pragma once

#include "PublicBlameProof.hpp"

#include <array>
#include <vector>

namespace pvia {

struct ReferenceMultiplicationFailureCertificate;

// Public verification helpers. VerifyDebug is development-only. The
// detached recovery-receipt verifier accepts only a self-contained certificate
// and an explicitly supplied, externally pinned Ed25519 key registry; it
// requires no witness, secret share, MPI state, or Runtime internals.
class PublicJudge {
public:
    static Digest compute_debug_proof_digest(const BlameCertificate& cert);
    static bool VerifyDebug(const BlameCertificate& cert,
                            uint64_t expected_session_id);
    static bool VerifyRecoveryReceipt(
        const BlameCertificate& certificate,
        const std::vector<std::array<uint8_t, 32>>& public_keys,
        const Digest& externally_pinned_registry_commitment);
    // Check certificate-to-statement consistency without invoking the
    // expensive Groth16 verifier. When expected words are copied from the
    // certificate this establishes internal consistency, not independent
    // pinning of the VSS registry.
    static bool ValidateRecoveryRelationStatement(
        const BlameCertificate& certificate,
        const std::vector<u64>& expected_statement_words);
    // Verify the SP1/Groth16 interpolation proof against caller-supplied
    // public statement words. Strong external attribution requires those
    // words (or the VSS registry root they encode) to be independently pinned.
    static bool VerifyRecoveryRelationProof(
        const BlameCertificate& certificate,
        const std::vector<u64>& expected_statement_words);
    static bool VerifyRecoveryProof(
        const BlameCertificate& certificate,
        const std::vector<std::array<uint8_t, 32>>& public_keys,
        const Digest& externally_pinned_registry_commitment,
        const std::vector<u64>& expected_statement_words);
    // Verifies every participant's signed acknowledgement of the same
    // nonzero RS event and the accused sender's signed preflight-failure
    // report. It does not prove the hidden multiplication relation false.
    static bool VerifyMultiplicationFailureCertificate(
        const ReferenceMultiplicationFailureCertificate& certificate,
        const std::vector<std::array<uint8_t, 32>>& public_keys,
        const Digest& externally_pinned_registry_commitment);
    // Portable artifact overload: decodes a canonical u64 certificate before
    // applying the same signature, roster and external-anchor checks.
    static bool VerifyMultiplicationFailureCertificate(
        const std::vector<u64>& encoded_certificate,
        const std::vector<std::array<uint8_t, 32>>& public_keys,
        const Digest& externally_pinned_registry_commitment);
};

} // namespace pvia
