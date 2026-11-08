#pragma once

#include "RegistrationConsistencyProof.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace pvia {

// A distinct domain for endorsements of the COMPLETE public 46-word
// registration statement. Signatures are public execution declarations,
// NOT a proof of native shares or equality with state consumed by MPI.
constexpr u64 REGISTRATION_ORIGIN_ENDORSEMENT_DOMAIN =
    0x50565245474f5247ULL; // "PVREGORG"

struct RegistrationOriginEndorsement {
    uint32_t signer = 0;
    std::array<uint8_t, 64> signature{};
};

// Rejects malformed statements, missing/duplicate/unordered signer sets,
// altered signatures, substitutions across sessions/checkpoints/operations
// and mismatched *externally pinned* Ed25519 key registries.
//
// The caller must independently select BOTH the intended statement and the
// trusted registry commitment, and define its own quorum policy.
// Having quorum signatures means the signers endorsed these public bytes;
// it does NOT establish that their native shares had these values.
std::vector<u64> registration_origin_endorsement_message(
    const RegistrationConsistencyStatement& statement);

bool verify_registration_origin_endorsements(
    const RegistrationConsistencyStatement& statement,
    const std::vector<RegistrationOriginEndorsement>& endorsements,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& independently_trusted_registry_commitment,
    size_t minimum_distinct_signers,
    bool require_owner_signature);

// Explicit injection point for the *public* endorsement release precondition.
// Implementations must verify signature quorum against a trusted registry
// and ensure each signer checks its own execution record before signing.
// This interface is not by itself proof of equality of native secret shares.
class RegistrationOriginApprovalBackend {
public:
    virtual ~RegistrationOriginApprovalBackend() = default;
    // Called on the owner BEFORE sharing native state into the VSS layer.
    // An approval provider must check the actual owner input bytes against
    // the finalized native record it retains, not just a caller's hash.
    // On other ranks, the session checks only the collective result here.
    virtual bool CheckOwnerNativeInputBeforeVss(
        const RegistrationConsistencyStatement& proposed_statement,
        const std::vector<F>& owner_private_state,
        const std::vector<F>& owner_actual_output,
        const F& public_challenge) const = 0;
    // Called on every rank before the collective pre-sign approval barrier.
    // Implementations must check their independently retained local record.
    virtual bool CheckLocalNativeOrigin(
        const RegistrationConsistencyStatement& statement) const = 0;
    virtual bool ApprovePublicOrigin(
        const RegistrationConsistencyStatement& statement) const = 0;
    // Irreversible, fail-closed replay reservation after public
    // endorsements but BEFORE registration proving. All ranks call it.
    virtual bool ConsumeApprovedOrigin(
        const RegistrationConsistencyStatement& statement) const = 0;
};

// Synthetic MPI cryptographic regression only: ephemeral keys, test-only
// registry pin, no production certificate or actual native-state attestation.
bool run_registration_origin_endorsement_selftest(int rank, int world_size);

} // namespace pvia
