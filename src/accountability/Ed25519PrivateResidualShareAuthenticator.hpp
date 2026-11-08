#pragma once

#include "PrivateResidualShareStore.hpp"

#include <array>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace pvia {

// Issued by a separately trusted native execution/provenance service only
// after it has independently checked the exact residual computation and
// its source-state provenance. The signature binds a single computation.
struct PrivateResidualProvenanceReceipt {
    u64 issuer_id = 0;
    u64 sequence = 0;
    u64 scheme_id = 0;
    Digest computation_binding{};
    std::array<uint8_t,64> signature{};
};

std::vector<uint8_t> private_residual_provenance_signing_message(
    const PrivateResidualProvenanceReceipt& receipt);

bool verify_private_residual_provenance_receipt(
    const PrivateResidualProvenanceReceipt& receipt,
    const std::array<uint8_t,32>& independently_pinned_issuer_key,
    u64 expected_issuer_id, u64 expected_scheme_id,
    u64 minimum_accepted_sequence,
    const Digest& independently_expected_computation_binding);

bool write_private_residual_provenance_receipt_file(
    const std::string& new_file,
    const PrivateResidualProvenanceReceipt& receipt);
bool read_private_residual_provenance_receipt_file(
    const std::string& file,
    PrivateResidualProvenanceReceipt* receipt);
bool read_private_residual_provenance_public_key_file(
    const std::string& file,
    std::array<uint8_t,32>* public_key);
bool private_residual_provenance_sequence_available(
    const std::string& replay_ledger_file,
    u64 issuer_id, u64 sequence);

// A concrete Ed25519 verifier for an independently provisioned receipt set.
// The public key, issuer identity, scheme and sequence floor are caller-pinned;
// no trust field is learned from a receipt. Valid receipt sequences are
// consumed once per authenticator instance and, when configured, in a
// durable owner-only replay ledger shared across process restarts.
class Ed25519PrivateResidualShareAuthenticator final
    : public PrivateResidualShareAuthenticator {
public:
    Ed25519PrivateResidualShareAuthenticator(
        u64 scheme_id, u64 expected_issuer_id,
        u64 minimum_accepted_sequence,
        const std::array<uint8_t,32>& independently_pinned_issuer_key,
        std::vector<PrivateResidualProvenanceReceipt> receipts,
        std::string persistent_replay_ledger_path = {});

    uint64_t SchemeId() const override;
    bool Authenticate(
        const PrivateResidualShare& share,
        PrivateResidualAuthenticationArtifact* artifact) const override;

private:
    u64 scheme_id_ = 0;
    u64 expected_issuer_id_ = 0;
    u64 minimum_accepted_sequence_ = 0;
    std::array<uint8_t,32> issuer_key_{};
    std::vector<PrivateResidualProvenanceReceipt> receipts_;
    std::string persistent_replay_ledger_path_;
    mutable std::mutex mutex_;
    mutable std::set<std::pair<u64,u64>> consumed_sequences_;
};

bool verify_private_residual_authentication_artifact_signature(
    const PrivateResidualShare& share,
    const PrivateResidualAuthenticationArtifact& artifact,
    const std::array<uint8_t,32>& independently_pinned_issuer_key,
    u64 expected_issuer_id, u64 minimum_accepted_sequence);

} // namespace pvia
