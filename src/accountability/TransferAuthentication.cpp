#include "TransferAuthentication.hpp"
#include "Ed25519AccountabilitySignatureBackend.hpp"

#include <mpi.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <dlfcn.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace pvia {
namespace {

bool generate_ed25519_keypair(std::array<uint8_t, 32>* private_key,
                              std::array<uint8_t, 32>* public_key) {
    if (!private_key || !public_key) return false;
    std::vector<uint8_t> private_bytes;
    std::vector<uint8_t> public_bytes;
    const auto& backend = ed25519_accountability_signature_backend();
    if (!backend.GenerateKeypair(&private_bytes, &public_bytes) ||
        private_bytes.size() != private_key->size() ||
        public_bytes.size() != public_key->size())
        return false;
    std::copy(private_bytes.begin(), private_bytes.end(), private_key->begin());
    std::copy(public_bytes.begin(), public_bytes.end(), public_key->begin());
    return true;
}

bool derive_ed25519_public_key(
    const std::array<uint8_t, 32>& private_key,
    std::array<uint8_t, 32>* public_key) {
    if (!public_key) return false;
    const auto& backend = ed25519_accountability_signature_backend();
    const std::vector<uint8_t> private_bytes(
        private_key.begin(), private_key.end());
    std::vector<uint8_t> public_bytes;
    if (!backend.DerivePublicKey(private_bytes, &public_bytes) ||
        public_bytes.size() != public_key->size())
        return false;
    std::copy(public_bytes.begin(), public_bytes.end(), public_key->begin());
    return true;
}

int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool parse_hex_32(std::string text, std::array<uint8_t, 32>* out) {
    if (!out) return false;
    text.erase(std::remove_if(text.begin(), text.end(),
        [](unsigned char c) { return std::isspace(c) != 0; }), text.end());
    if (text.size() != 64) return false;
    for (size_t i = 0; i < out->size(); ++i) {
        const int hi = hex_value(text[2 * i]);
        const int lo = hex_value(text[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        (*out)[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

bool sign_ed25519_with_pkey(
    EVP_PKEY* pkey, const uint8_t* message, size_t message_size,
    std::array<uint8_t, 64>* signature) {
    if (!pkey || !signature) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = ctx != nullptr &&
              EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) == 1;
    size_t signature_len = signature->size();
    if (ok) ok = EVP_DigestSign(ctx, signature->data(), &signature_len,
                                message, message_size) == 1;
    ok = ok && signature_len == signature->size();
    EVP_MD_CTX_free(ctx);
    return ok;
}

bool sign_ed25519(const std::array<uint8_t, 32>& private_key,
                  const uint8_t* message, size_t message_size,
                  std::array<uint8_t, 64>* signature) {
    if (!signature) return false;
    const auto& backend = ed25519_accountability_signature_backend();
    const std::vector<uint8_t> private_bytes(
        private_key.begin(), private_key.end());
    std::vector<uint8_t> signature_bytes;
    if (!backend.Sign(
            private_bytes, message, message_size, &signature_bytes) ||
        signature_bytes.size() != signature->size())
        return false;
    std::copy(signature_bytes.begin(), signature_bytes.end(),
              signature->begin());
    return true;
}

bool verify_ed25519_with_pkey(
    EVP_PKEY* pkey, const uint8_t* message, size_t message_size,
    const std::array<uint8_t, 64>& signature) {
    if (!pkey) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = ctx != nullptr &&
              EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1;
    if (ok) ok = EVP_DigestVerify(ctx, signature.data(), signature.size(),
                                  message, message_size) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}
struct SodiumEd25519VerifyApi {
    using InitFn = int (*)();
    using VerifyFn = int (*)(
        const unsigned char*, const unsigned char*,
        unsigned long long, const unsigned char*);

    void* handle = nullptr;
    InitFn init = nullptr;
    VerifyFn verify = nullptr;
    bool ready = false;

    SodiumEd25519VerifyApi() {
        if (std::getenv("PVIA_DISABLE_LIBSODIUM_VERIFY"))
            return;
        const char* candidates[] = {
            "libsodium.so.23", "libsodium.so"};
        for (const char* name : candidates) {
            handle = dlopen(name, RTLD_NOW | RTLD_LOCAL);
            if (handle) break;
        }
        if (!handle) return;
        init = reinterpret_cast<InitFn>(
            dlsym(handle, "sodium_init"));
        verify = reinterpret_cast<VerifyFn>(
            dlsym(handle, "crypto_sign_verify_detached"));
        if (!init || !verify || init() < 0) {
            dlclose(handle);
            handle = nullptr;
            init = nullptr;
            verify = nullptr;
            return;
        }
        ready = true;
    }

    ~SodiumEd25519VerifyApi() {
        if (handle) dlclose(handle);
    }
};

const SodiumEd25519VerifyApi& sodium_ed25519_verify_api() {
    static const SodiumEd25519VerifyApi api;
    return api;
}

bool verify_ed25519_fast(
    const std::array<uint8_t, 32>& public_key,
    EVP_PKEY* fallback_pkey,
    const uint8_t* message, size_t message_size,
    const std::array<uint8_t, 64>& signature) {
    const auto& sodium = sodium_ed25519_verify_api();
    if (sodium.ready) {
        return sodium.verify(
                   signature.data(), message,
                   static_cast<unsigned long long>(message_size),
                   public_key.data()) == 0;
    }
    return verify_ed25519_with_pkey(
        fallback_pkey, message, message_size, signature);
}


bool verify_ed25519(const std::array<uint8_t, 32>& public_key,
                    const uint8_t* message, size_t message_size,
                    const std::array<uint8_t, 64>& signature) {
    const auto& backend = ed25519_accountability_signature_backend();
    const std::vector<uint8_t> public_bytes(
        public_key.begin(), public_key.end());
    const std::vector<uint8_t> signature_bytes(
        signature.begin(), signature.end());
    return backend.Verify(
        public_bytes, message, message_size, signature_bytes);
}

void digest_to_words_local(const Digest& digest, u64* out) {
    std::memcpy(out, digest.bytes.data(), digest.bytes.size());
}

Digest words_to_digest_local(const u64* words) {
    Digest digest;
    std::memcpy(digest.bytes.data(), words, digest.bytes.size());
    return digest;
}

std::string resolve_rank_key_path(std::string pattern, int rank) {
    const std::string marker = "{rank}";
    const std::string value = std::to_string(rank);
    size_t pos = 0;
    while ((pos = pattern.find(marker, pos)) != std::string::npos) {
        pattern.replace(pos, marker.size(), value);
        pos += value.size();
    }
    return pattern;
}

bool load_private_key_file(
    const std::string& path, std::array<uint8_t, 32>* private_key) {
    if (!private_key || path.empty()) return false;
    std::ifstream input(path, std::ios::in | std::ios::binary);
    if (!input) return false;
    const std::string text((std::istreambuf_iterator<char>(input)),
                           std::istreambuf_iterator<char>());
    return parse_hex_32(text, private_key);
}

bool parse_digest_hex(const char* text, Digest* digest) {
    if (!text || !*text || !digest) return false;
    std::array<uint8_t, 32> bytes{};
    if (!parse_hex_32(std::string(text), &bytes)) return false;
    digest->bytes = bytes;
    return true;
}

bool env_flag_enabled(const char* name) {
    if (!name || !*name) return false;
    const char* value = std::getenv(name);
    return value && *value && std::string(value) != "0";
}

bool all_zero(const std::array<uint8_t, 32>& bytes) {
    return std::all_of(bytes.begin(), bytes.end(),
        [](uint8_t value) { return value == 0; });
}

constexpr u64 GENERIC_WORD_AUTH_DOMAIN =
    0x5056494157415554ULL; // PVIAWAUT

std::vector<u64> canonical_word_auth_message(
    u64 domain, uint32_t signer, const Digest& registry_commitment,
    const Digest& key_id, const std::vector<u64>& message) {
    if (domain == 0 || registry_commitment == Digest{} ||
        key_id == Digest{} || message.empty())
        return {};
    std::vector<u64> words = {
        GENERIC_WORD_AUTH_DOMAIN, domain, static_cast<u64>(signer),
        static_cast<u64>(message.size())};
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, registry_commitment.bytes.data() + 8 * i, 8);
        words.push_back(word);
    }
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, key_id.bytes.data() + 8 * i, 8);
        words.push_back(word);
    }
    words.insert(words.end(), message.begin(), message.end());
    return words;
}

} // namespace

Digest compute_ed25519_registry_commitment(
    const std::vector<std::array<uint8_t, 32>>& public_keys) {
    if (public_keys.empty()) return Digest{};
    std::vector<u64> words = {
        0x505649415f4b4559ULL,
        static_cast<u64>(public_keys.size())
    };
    for (size_t i = 0; i < public_keys.size(); ++i) {
        if (all_zero(public_keys[i])) return Digest{};
        words.push_back(static_cast<u64>(i));
        const Digest id = hash_bytes(public_keys[i].data(), public_keys[i].size());
        for (size_t j = 0; j < 4; ++j) {
            u64 word = 0;
            std::memcpy(&word, id.bytes.data() + 8 * j, 8);
            words.push_back(word);
        }
    }
    return hash_words(words);
}

bool verify_ed25519_words_with_public_registry(
    u64 domain, const std::vector<u64>& message,
    const std::array<uint8_t, 64>& signature, uint32_t signer,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& expected_registry_commitment) {
    if (domain == 0 || message.empty() || public_keys.empty() ||
        signer >= public_keys.size() || expected_registry_commitment == Digest{})
        return false;
    for (size_t i = 0; i < public_keys.size(); ++i) {
        if (all_zero(public_keys[i])) return false;
        for (size_t j = i + 1; j < public_keys.size(); ++j)
            if (public_keys[i] == public_keys[j]) return false;
    }
    const Digest registry_commitment =
        compute_ed25519_registry_commitment(public_keys);
    if (registry_commitment == Digest{} ||
        registry_commitment != expected_registry_commitment)
        return false;
    const Digest key_id = hash_bytes(
        public_keys[signer].data(), public_keys[signer].size());
    if (key_id == Digest{}) return false;
    const std::vector<u64> preimage = canonical_word_auth_message(
        domain, signer, registry_commitment, key_id, message);
    if (preimage.empty()) return false;
    const uint8_t* bytes =
        reinterpret_cast<const uint8_t*>(preimage.data());
    return verify_ed25519(public_keys[signer], bytes,
                          preimage.size() * sizeof(u64), signature);
}

bool verify_ed25519_transfer_meta_with_public_key(
    const std::array<u64, META_WORDS>& meta,
    const std::array<uint8_t, 32>& public_key,
    int expected_transport_sender) {
    if (meta[0] != META_MAGIC || meta[META_SCHEMA_INDEX] < 6 ||
        all_zero(public_key)) return false;
    const uint32_t signer = static_cast<uint32_t>(meta[META_AUTH_SIGNER_INDEX]);
    if (expected_transport_sender >= 0 &&
        signer != static_cast<uint32_t>(expected_transport_sender))
        return false;
    if (meta[4] != static_cast<u64>(signer)) return false;
    const Digest expected_key_id = hash_bytes(public_key.data(), public_key.size());
    if (words_to_digest_local(&meta[META_AUTH_KEY_ID_OFFSET]) != expected_key_id)
        return false;
    if (words_to_digest_local(&meta[META_AUTH_WIRE_DIGEST_OFFSET]) == Digest{})
        return false;
    std::array<uint8_t, 64> signature{};
    std::memcpy(signature.data(), &meta[META_AUTH_SIGNATURE_OFFSET],
                signature.size());
    const uint8_t* message = reinterpret_cast<const uint8_t*>(meta.data());
    const size_t message_size =
        static_cast<size_t>(META_AUTH_SIGNATURE_OFFSET) * sizeof(u64);
    return verify_ed25519(public_key, message, message_size, signature);
}

Ed25519TransferAuthenticator& Ed25519TransferAuthenticator::instance() {
    static Ed25519TransferAuthenticator authenticator;
    return authenticator;
}

Ed25519TransferAuthenticator::~Ed25519TransferAuthenticator() {
    Reset();
}

bool Ed25519TransferAuthenticator::BuildSessionKeyObjects() {
    if (private_pkey_) {
        EVP_PKEY_free(private_pkey_);
        private_pkey_ = nullptr;
    }
    for (EVP_PKEY* pkey : public_pkeys_) EVP_PKEY_free(pkey);
    public_pkeys_.clear();

    private_pkey_ = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, private_key_.data(), private_key_.size());
    if (!private_pkey_) return false;
    public_pkeys_.reserve(public_keys_.size());
    for (const auto& public_key : public_keys_) {
        EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
            EVP_PKEY_ED25519, nullptr, public_key.data(), public_key.size());
        if (!pkey) {
            EVP_PKEY_free(private_pkey_);
            private_pkey_ = nullptr;
            for (EVP_PKEY* existing : public_pkeys_) EVP_PKEY_free(existing);
            public_pkeys_.clear();
            return false;
        }
        public_pkeys_.push_back(pkey);
    }
    return public_pkeys_.size() == public_keys_.size();
}

void Ed25519TransferAuthenticator::Reset() {
    if (private_pkey_) {
        EVP_PKEY_free(private_pkey_);
        private_pkey_ = nullptr;
    }
    for (EVP_PKEY* pkey : public_pkeys_) EVP_PKEY_free(pkey);
    public_pkeys_.clear();
    OPENSSL_cleanse(private_key_.data(), private_key_.size());
    public_key_.fill(0);
    public_keys_.clear();
    public_key_ids_.clear();
    registry_commitment_ = Digest{};
    external_registry_anchor_ = Digest{};
    external_registry_anchor_verified_ = false;
    ready_ = false;
    rank_ = -1;
    world_size_ = 0;
}

bool Ed25519TransferAuthenticator::Initialize(int rank, int world_size) {
    Reset();
    if (world_size <= 0 || rank < 0 || rank >= world_size) return false;
    int comm_rank = -1;
    int comm_size = 0;
    MPI_Comm_rank(MPI_COMM_WORLD, &comm_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &comm_size);
    if (rank != comm_rank || world_size != comm_size) return false;
    const AccountabilitySignatureCapabilities signature_capabilities =
        ed25519_accountability_signature_backend().Capabilities();
    AccountabilitySignatureRequirements signature_requirements;
    signature_requirements.require_post_quantum =
        env_flag_enabled("PVIA_REQUIRE_POST_QUANTUM_SIGNATURE");
    signature_requirements.require_hash_based =
        env_flag_enabled("PVIA_REQUIRE_HASH_BASED_SIGNATURE");
    // Metadata schema v6 and authenticated-MPC envelopes still encode a
    // fixed-size 64-byte signature. A future PQ schema must relax this gate.
    signature_requirements.allow_variable_length_signature = false;
    if (!validate_accountability_signature_capabilities(
            signature_capabilities) ||
        !accountability_signature_satisfies(
            signature_capabilities, signature_requirements) ||
        signature_capabilities.private_key_bytes != private_key_.size() ||
        signature_capabilities.public_key_bytes != public_key_.size() ||
        signature_capabilities.signature_bytes != 64)
        return false;
    const char* key_file_pattern =
        std::getenv("PVIA_TRANSFER_PRIVATE_KEY_FILE");
    bool key_ok = false;
    if (key_file_pattern && *key_file_pattern) {
        const std::string key_path = resolve_rank_key_path(
            std::string(key_file_pattern), rank);
        key_ok = load_private_key_file(key_path, &private_key_) &&
            derive_ed25519_public_key(private_key_, &public_key_);
    } else {
        key_ok = generate_ed25519_keypair(&private_key_, &public_key_);
    }
    if (!key_ok || all_zero(public_key_)) {
        Reset();
        return false;
    }

    std::vector<uint8_t> gathered(static_cast<size_t>(world_size) * 32, 0);
    MPI_Allgather(public_key_.data(), 32, MPI_UNSIGNED_CHAR,
                  gathered.data(), 32, MPI_UNSIGNED_CHAR, MPI_COMM_WORLD);
    public_keys_.resize(static_cast<size_t>(world_size));
    public_key_ids_.resize(static_cast<size_t>(world_size));
    for (int i = 0; i < world_size; ++i) {
        std::memcpy(public_keys_[static_cast<size_t>(i)].data(),
                    gathered.data() + static_cast<size_t>(i) * 32, 32);
        if (all_zero(public_keys_[static_cast<size_t>(i)])) {
            Reset();
            return false;
        }
        public_key_ids_[static_cast<size_t>(i)] = hash_bytes(
            public_keys_[static_cast<size_t>(i)].data(), 32);
    }

    for (int i = 0; i < world_size; ++i) {
        for (int j = i + 1; j < world_size; ++j) {
            if (public_keys_[static_cast<size_t>(i)] ==
                public_keys_[static_cast<size_t>(j)]) {
                Reset();
                return false;
            }
        }
    }
    std::vector<u64> registry_words = {
        0x505649415f4b4559ULL,
        static_cast<u64>(world_size)
    };
    for (int i = 0; i < world_size; ++i) {
        registry_words.push_back(static_cast<u64>(i));
        for (size_t j = 0; j < 4; ++j) {
            u64 word = 0;
            std::memcpy(&word,
                public_key_ids_[static_cast<size_t>(i)].bytes.data() + 8 * j, 8);
            registry_words.push_back(word);
        }
    }
    registry_commitment_ = compute_ed25519_registry_commitment(public_keys_);
    if (registry_commitment_ == Digest{}) {
        Reset();
        return false;
    }
    const char* anchor_text =
        std::getenv("PVIA_TRANSFER_REGISTRY_ANCHOR");
    if (anchor_text && *anchor_text) {
        Digest expected_anchor{};
        if (!parse_digest_hex(anchor_text, &expected_anchor) ||
            expected_anchor != registry_commitment_) {
            Reset();
            return false;
        }
        external_registry_anchor_ = expected_anchor;
        external_registry_anchor_verified_ = true;
    }
    if (!BuildSessionKeyObjects()) {
        Reset();
        return false;
    }
    rank_ = rank;
    world_size_ = world_size;
    ready_ = true;
    return true;
}

AccountabilitySignatureCapabilities
Ed25519TransferAuthenticator::SignatureCapabilities() const {
    return ed25519_accountability_signature_backend().Capabilities();
}

Digest Ed25519TransferAuthenticator::PublicKeyId(uint32_t rank) const {
    if (!ready_ || rank >= public_key_ids_.size()) return Digest{};
    return public_key_ids_[rank];
}

bool Ed25519TransferAuthenticator::Seal(
    std::array<u64, META_WORDS>* meta,
    const std::vector<u64>& wire_payload) const {
    return SealDigest(meta, hash_words(wire_payload));
}

bool Ed25519TransferAuthenticator::SealDigest(
    std::array<u64, META_WORDS>* meta,
    const Digest& wire_digest) const {
    if (!ready_ || !meta || (*meta)[0] != META_MAGIC ||
        rank_ < 0 || static_cast<size_t>(rank_) >= public_key_ids_.size() ||
        wire_digest == Digest{})
        return false;
    (*meta)[META_SCHEMA_INDEX] = META_SCHEMA_VERSION;
    (*meta)[META_AUTH_SIGNER_INDEX] = static_cast<u64>(rank_);
    digest_to_words_local(public_key_ids_[static_cast<size_t>(rank_)],
                          &(*meta)[META_AUTH_KEY_ID_OFFSET]);

    digest_to_words_local(wire_digest, &(*meta)[META_AUTH_WIRE_DIGEST_OFFSET]);
    std::fill(meta->begin() + META_AUTH_SIGNATURE_OFFSET, meta->end(), 0ULL);

    std::array<uint8_t, 64> signature{};
    const uint8_t* message = reinterpret_cast<const uint8_t*>(meta->data());
    const size_t message_size =
        static_cast<size_t>(META_AUTH_SIGNATURE_OFFSET) * sizeof(u64);
    if (!sign_ed25519_with_pkey(
            private_pkey_, message, message_size, &signature))
        return false;
    std::memcpy(&(*meta)[META_AUTH_SIGNATURE_OFFSET],
                signature.data(), signature.size());
    return true;
}

bool Ed25519TransferAuthenticator::Verify(
    const std::array<u64, META_WORDS>& meta,
    int expected_transport_sender) const {
    if (!ready_ || meta[0] != META_MAGIC ||
        meta[META_SCHEMA_INDEX] < 6)
        return false;
    const uint32_t signer = static_cast<uint32_t>(meta[META_AUTH_SIGNER_INDEX]);
    if (signer >= public_keys_.size() || signer >= public_pkeys_.size() ||
        !public_pkeys_[signer]) return false;
    if (expected_transport_sender >= 0 &&
        signer != static_cast<uint32_t>(expected_transport_sender))
        return false;
    if (meta[4] != static_cast<u64>(signer)) return false;

    const Digest key_id = words_to_digest_local(&meta[META_AUTH_KEY_ID_OFFSET]);
    if (key_id != public_key_ids_[signer]) return false;
    const Digest wire_digest =
        words_to_digest_local(&meta[META_AUTH_WIRE_DIGEST_OFFSET]);
    if (wire_digest == Digest{}) return false;

    std::array<uint8_t, 64> signature{};
    std::memcpy(signature.data(), &meta[META_AUTH_SIGNATURE_OFFSET],
                signature.size());
    const uint8_t* message = reinterpret_cast<const uint8_t*>(meta.data());
    const size_t message_size =
        static_cast<size_t>(META_AUTH_SIGNATURE_OFFSET) * sizeof(u64);
    return verify_ed25519_fast(
        public_keys_[signer], public_pkeys_[signer],
        message, message_size, signature);
}
bool Ed25519TransferAuthenticator::SignWords(
    u64 domain, const std::vector<u64>& message,
    std::array<uint8_t, 64>* signature) const {
    if (!ready_ || !signature || domain == 0 || message.empty() || rank_ < 0 ||
        static_cast<size_t>(rank_) >= public_key_ids_.size() ||
        registry_commitment_ == Digest{})
        return false;
    const std::vector<u64> preimage = canonical_word_auth_message(
        domain, static_cast<uint32_t>(rank_), registry_commitment_,
        public_key_ids_[static_cast<size_t>(rank_)], message);
    if (preimage.empty()) return false;
    const uint8_t* bytes =
        reinterpret_cast<const uint8_t*>(preimage.data());
    const size_t byte_count = preimage.size() * sizeof(u64);
    return sign_ed25519_with_pkey(
        private_pkey_, bytes, byte_count, signature);
}

bool Ed25519TransferAuthenticator::VerifyWords(
    u64 domain, const std::vector<u64>& message,
    const std::array<uint8_t, 64>& signature, uint32_t signer) const {
    if (!ready_ || domain == 0 || message.empty() ||
        signer >= public_keys_.size() || signer >= public_key_ids_.size() ||
        signer >= public_pkeys_.size() || !public_pkeys_[signer] ||
        registry_commitment_ == Digest{})
        return false;
    const std::vector<u64> preimage = canonical_word_auth_message(
        domain, signer, registry_commitment_, public_key_ids_[signer], message);
    if (preimage.empty()) return false;
    const uint8_t* bytes =
        reinterpret_cast<const uint8_t*>(preimage.data());
    const size_t byte_count = preimage.size() * sizeof(u64);
    return verify_ed25519_fast(
        public_keys_[signer], public_pkeys_[signer],
        bytes, byte_count, signature);
}


} // namespace pvia
