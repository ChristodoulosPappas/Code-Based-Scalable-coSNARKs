#pragma once

#include "PVIA.hpp"
#include "AccountabilitySignature.hpp"

#include <array>
#include <cstdint>
#include <vector>
#include <openssl/evp.h>

namespace pvia {

Digest compute_ed25519_registry_commitment(
    const std::vector<std::array<uint8_t, 32>>& public_keys);
bool verify_ed25519_transfer_meta_with_public_key(
    const std::array<u64, META_WORDS>& meta,
    const std::array<uint8_t, 32>& public_key,
    int expected_transport_sender = -1);
bool verify_ed25519_words_with_public_registry(
    u64 domain, const std::vector<u64>& message,
    const std::array<uint8_t, 64>& signature, uint32_t signer,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& expected_registry_commitment);

// Session-scoped Ed25519 authentication for public transfer metadata.
// MPI is used only to distribute public keys; authenticity comes from
// Ed25519 signatures verified against the registered session keys.
class Ed25519TransferAuthenticator {
public:
    static Ed25519TransferAuthenticator& instance();

    bool Initialize(int rank, int world_size);
    void Reset();
    bool ready() const { return ready_; }
    AccountabilitySignatureCapabilities SignatureCapabilities() const;

    bool Seal(std::array<u64, META_WORDS>* meta,
              const std::vector<u64>& wire_payload) const;
    bool SealDigest(std::array<u64, META_WORDS>* meta,
                    const Digest& wire_digest) const;
    bool Verify(const std::array<u64, META_WORDS>& meta,
                int expected_transport_sender = -1) const;

    // Generic domain-separated authentication for protocol control messages.
    // The signed preimage also binds signer rank, session key registry, key id,
    // message length and payload; callers cannot omit those identity fields.
    bool SignWords(
        u64 domain, const std::vector<u64>& message,
        std::array<uint8_t, 64>* signature) const;
    bool VerifyWords(
        u64 domain, const std::vector<u64>& message,
        const std::array<uint8_t, 64>& signature,
        uint32_t signer) const;

    Digest PublicKeyId(uint32_t rank) const;
    Digest RegistryCommitment() const { return registry_commitment_; }
    bool ExternalRegistryAnchorVerified() const {
        return external_registry_anchor_verified_;
    }
    Digest ExternalRegistryAnchor() const { return external_registry_anchor_; }
    const std::vector<std::array<uint8_t, 32>>& PublicKeys() const {
        return public_keys_;
    }
    int rank() const { return rank_; }
    int world_size() const { return world_size_; }

private:
    Ed25519TransferAuthenticator() = default;
    ~Ed25519TransferAuthenticator();

    bool BuildSessionKeyObjects();

    bool ready_ = false;
    int rank_ = -1;
    int world_size_ = 0;
    std::array<uint8_t, 32> private_key_{};
    std::array<uint8_t, 32> public_key_{};
    std::vector<std::array<uint8_t, 32>> public_keys_;
    std::vector<Digest> public_key_ids_;
    EVP_PKEY* private_pkey_ = nullptr;
    std::vector<EVP_PKEY*> public_pkeys_;
    Digest registry_commitment_{};
    Digest external_registry_anchor_{};
    bool external_registry_anchor_verified_ = false;
};

} // namespace pvia
