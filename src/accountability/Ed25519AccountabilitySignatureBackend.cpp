#include "Ed25519AccountabilitySignatureBackend.hpp"

#include <openssl/evp.h>
#include <dlfcn.h>
#include <cstdlib>

namespace pvia {
namespace {

constexpr u64 ED25519_SCHEME_ID =
    0x4544323535313931ULL; // ED255191
constexpr u64 ED25519_IMPL_DOMAIN =
    0x5056454432353549ULL; // PVED255I

AccountabilitySignatureCapabilities make_capabilities() {
    AccountabilitySignatureCapabilities c;
    c.available = true;
    c.scheme_id = ED25519_SCHEME_ID;
    c.post_quantum = false;
    c.hash_based = false;
    c.deterministic = true;
    c.variable_length_signature = false;
    c.private_key_bytes = 32;
    c.public_key_bytes = 32;
    c.signature_bytes = 64;
    c.implementation_binding = hash_words({
        ED25519_IMPL_DOMAIN, ED25519_SCHEME_ID,
        32ULL, 32ULL, 64ULL});
    c.capability_binding =
        compute_accountability_signature_capability_binding(c);
    return c;
}

bool make_private_pkey(
    const std::vector<uint8_t>& private_key,
    EVP_PKEY** pkey) {
    if (!pkey || private_key.size() != 32) return false;
    *pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr,
        private_key.data(), private_key.size());
    return *pkey != nullptr;
}

bool make_public_pkey(
    const std::vector<uint8_t>& public_key,
    EVP_PKEY** pkey) {
    if (!pkey || public_key.size() != 32) return false;
    *pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr,
        public_key.data(), public_key.size());
    return *pkey != nullptr;
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

const SodiumEd25519VerifyApi& sodium_verify_api() {
    static const SodiumEd25519VerifyApi api;
    return api;
}


} // namespace
AccountabilitySignatureCapabilities
Ed25519AccountabilitySignatureBackend::Capabilities() const {
    return make_capabilities();
}

bool Ed25519AccountabilitySignatureBackend::GenerateKeypair(
    std::vector<uint8_t>* private_key,
    std::vector<uint8_t>* public_key) const {
    if (!private_key || !public_key) return false;
    EVP_PKEY_CTX* ctx =
        EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx) return false;
    EVP_PKEY* pkey = nullptr;
    bool ok = EVP_PKEY_keygen_init(ctx) == 1 &&
        EVP_PKEY_keygen(ctx, &pkey) == 1 && pkey != nullptr;
    private_key->assign(32, 0);
    public_key->assign(32, 0);
    size_t private_len = private_key->size();
    size_t public_len = public_key->size();
    if (ok) ok = EVP_PKEY_get_raw_private_key(
        pkey, private_key->data(), &private_len) == 1;
    if (ok) ok = EVP_PKEY_get_raw_public_key(
        pkey, public_key->data(), &public_len) == 1;
    ok = ok && private_len == 32 && public_len == 32;
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    if (!ok) {
        private_key->clear();
        public_key->clear();
    }
    return ok;
}

bool Ed25519AccountabilitySignatureBackend::DerivePublicKey(
    const std::vector<uint8_t>& private_key,
    std::vector<uint8_t>* public_key) const {
    if (!public_key) return false;
    EVP_PKEY* pkey = nullptr;
    if (!make_private_pkey(private_key, &pkey)) return false;
    public_key->assign(32, 0);
    size_t public_len = public_key->size();
    const bool ok = EVP_PKEY_get_raw_public_key(
        pkey, public_key->data(), &public_len) == 1 &&
        public_len == public_key->size();
    EVP_PKEY_free(pkey);
    if (!ok) public_key->clear();
    return ok;
}
bool Ed25519AccountabilitySignatureBackend::Sign(
    const std::vector<uint8_t>& private_key,
    const uint8_t* message, size_t message_size,
    std::vector<uint8_t>* signature) const {
    if (!message || message_size == 0 || !signature)
        return false;
    EVP_PKEY* pkey = nullptr;
    if (!make_private_pkey(private_key, &pkey)) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = ctx != nullptr &&
        EVP_DigestSignInit(
            ctx, nullptr, nullptr, nullptr, pkey) == 1;
    signature->assign(64, 0);
    size_t signature_len = signature->size();
    if (ok) ok = EVP_DigestSign(
        ctx, signature->data(), &signature_len,
        message, message_size) == 1;
    ok = ok && signature_len == 64;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    if (!ok) signature->clear();
    return ok;
}
bool Ed25519AccountabilitySignatureBackend::Verify(
    const std::vector<uint8_t>& public_key,
    const uint8_t* message, size_t message_size,
    const std::vector<uint8_t>& signature) const {
    if (!message || message_size == 0 ||
        public_key.size() != 32 || signature.size() != 64)
        return false;

    const auto& sodium = sodium_verify_api();
    if (sodium.ready) {
        return sodium.verify(
                   signature.data(), message,
                   static_cast<unsigned long long>(message_size),
                   public_key.data()) == 0;
    }

    EVP_PKEY* pkey = nullptr;
    if (!make_public_pkey(public_key, &pkey)) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = ctx != nullptr &&
        EVP_DigestVerifyInit(
            ctx, nullptr, nullptr, nullptr, pkey) == 1;
    if (ok) ok = EVP_DigestVerify(
        ctx, signature.data(), signature.size(),
        message, message_size) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

const Ed25519AccountabilitySignatureBackend&
ed25519_accountability_signature_backend() {
    static const Ed25519AccountabilitySignatureBackend backend;
    return backend;
}

} // namespace pvia
