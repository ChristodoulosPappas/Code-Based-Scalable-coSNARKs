#include "ReferenceResidualPairPublicVerifier.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace pvia {
namespace {
constexpr uint64_t NATIVE_DOMAIN=0x5056524e49535331ULL; // PVRNISS1
constexpr uint64_t LINK_WIRE_DOMAIN=0x31534b4e524c5650ULL; // PVLRNKS1 unused
constexpr size_t NATIVE_SIZE=152;
constexpr size_t LINK_SIZE=184;
constexpr size_t NATIVE_MESSAGE_SIZE=400;

uint64_t word_le(const uint8_t* p) {
    uint64_t v=0;
    for (unsigned i=0;i<8;++i)
        v|=static_cast<uint64_t>(p[i])<<(8*i);
    return v;
}
void append_word(std::vector<uint8_t>* result,uint64_t v) {
    for (unsigned i=0;i<8;++i)
        result->push_back(static_cast<uint8_t>(v>>(8*i)));
}
bool check_digest(const std::vector<uint8_t>& input,size_t at,
                  const std::array<uint8_t,32>& digest) {
    return input.size()>=at+digest.size() &&
        std::equal(digest.begin(),digest.end(),input.begin()+at);
}
bool read_exact_regular(const std::string& filename,size_t n,
                        std::vector<uint8_t>* output) {
    if (!output || filename.empty()) return false;
    const int fd=::open(filename.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return false;
    struct stat st{};
    bool ok=::fstat(fd,&st)==0 && S_ISREG(st.st_mode) &&
        st.st_size==static_cast<off_t>(n);
    std::vector<uint8_t> value(n);
    size_t read_count=0;
    while (ok && read_count<n) {
        const ssize_t k=::read(fd,value.data()+read_count,n-read_count);
        if (k<0 && errno==EINTR)continue;
        if (k<=0){ok=false;break;}
        read_count+=static_cast<size_t>(k);
    }
    if (::close(fd)!=0) ok=false;
    if (!ok) return false;
    *output=std::move(value);
    return true;
}
bool verify_ed25519(const std::array<uint8_t,32>& public_key,
                    const uint8_t* message,size_t message_size,
                    const uint8_t* signature,size_t signature_size) {
    EVP_PKEY* key=EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519,nullptr,public_key.data(),public_key.size());
    if (!key)return false;
    EVP_MD_CTX* ctx=EVP_MD_CTX_new();
    const bool ok=ctx &&
        EVP_DigestVerifyInit(ctx,nullptr,nullptr,nullptr,key)==1 &&
        EVP_DigestVerify(ctx,signature,signature_size,
                         message,message_size)==1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}
} // namespace

bool VerifyReferenceResidualPairPublic(
    const ReferenceResidualPairExpected& e,
    const std::vector<uint8_t>& native,
    const std::vector<uint8_t>& link) {
    if (!e.issuer_id || !e.sequence ||
        e.canonical_native_message.size()!=NATIVE_MESSAGE_SIZE ||
        native.size()!=NATIVE_SIZE || link.size()!=LINK_SIZE ||
        std::all_of(e.issuer_public_key.begin(),e.issuer_public_key.end(),
                    [](uint8_t b){return b==0;}) ||
        !std::equal(native.begin(),native.begin()+8,
                    "PVNISS01") ||
        !std::equal(link.begin(),link.begin()+8,
                    "PVLRNK01"))
        return false;

    // Source-only native issuer receipt: PVNISS01 | issuer | sequence |
    // pre-VSS binding | native-consumed source | Ed25519 signature.
    if (word_le(native.data()+8)!=e.issuer_id ||
        word_le(native.data()+16)!=e.sequence ||
        !check_digest(native,24,e.pre_vss_claim_binding) ||
        !check_digest(native,56,e.consumed_source_binding))
        return false;

    const auto& message=e.canonical_native_message;
    if (word_le(message.data())!=NATIVE_DOMAIN ||
        word_le(message.data()+8)!=1 ||
        word_le(message.data()+16)!=e.issuer_id ||
        word_le(message.data()+24)!=e.sequence ||
        !check_digest(message,336,e.pre_vss_claim_binding) ||
        !check_digest(message,368,e.consumed_source_binding) ||
        !verify_ed25519(e.issuer_public_key,message.data(),message.size(),
                        native.data()+88,64))
        return false;

    // Reference-only signed computation association: PVLRNK01 | issuer |
    // sequence | native-consumed source | computation | commitment | sig.
    if (word_le(link.data()+8)!=e.issuer_id ||
        word_le(link.data()+16)!=e.sequence ||
        !check_digest(link,24,e.consumed_source_binding) ||
        !check_digest(link,56,e.residual_computation_binding) ||
        !check_digest(link,88,e.residual_commitment))
        return false;
    std::vector<uint8_t> signed_link;
    signed_link.insert(signed_link.end(),link.begin(),link.begin()+8);
    append_word(&signed_link,e.issuer_id);
    append_word(&signed_link,e.sequence);
    signed_link.insert(signed_link.end(),e.consumed_source_binding.begin(),
                       e.consumed_source_binding.end());
    signed_link.insert(signed_link.end(),e.residual_computation_binding.begin(),
                       e.residual_computation_binding.end());
    signed_link.insert(signed_link.end(),e.residual_commitment.begin(),
                       e.residual_commitment.end());
    return signed_link.size()==120 &&
        verify_ed25519(e.issuer_public_key,signed_link.data(),
                       signed_link.size(),link.data()+120,64);
}

bool ReadReferenceResidualPairWire(
    const std::string& native_path, const std::string& link_path,
    std::vector<uint8_t>* native, std::vector<uint8_t>* link) {
    return read_exact_regular(native_path,NATIVE_SIZE,native) &&
        read_exact_regular(link_path,LINK_SIZE,link);
}
} // namespace pvia
