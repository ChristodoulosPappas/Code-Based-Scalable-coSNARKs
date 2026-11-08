#include "ResidualNativeSourcePinReceipt.hpp"
#include "Ed25519PrivateResidualShareAuthenticator.hpp"
#include "CollectiveResidualEngine.hpp"

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>

namespace pvia {
namespace {
constexpr u64 ROOT_RECEIPT_DOMAIN=0x5056313035525049ULL; // PV105RPI
constexpr u64 ROOT_RECEIPT_VERSION=1;
constexpr uint8_t PIN_FILE_MAGIC[]={'P','V','N','P','I','N','0','1'};
constexpr size_t PIN_FILE_BYTES=240;
void append_u64(std::vector<uint8_t>* out,u64 word) {
    for(unsigned i=0;i<8;++i)
        out->push_back(static_cast<uint8_t>(word>>(8*i)));
}
void append_digest(std::vector<uint8_t>* out,const Digest& digest) {
    out->insert(out->end(),digest.bytes.begin(),digest.bytes.end());
}
u64 read_u64_le(const uint8_t* at) {
    u64 value=0;
    for(unsigned i=0;i<8;++i)
        value |= static_cast<u64>(at[i]) << (8*i);
    return value;
}
bool write_exclusive_private(const std::string& path,
                             const std::vector<uint8_t>& bytes) {
    if(path.empty())return false;
    const int fd=::open(path.c_str(),
        O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)return false;
    size_t offset=0;
    bool ok=true;
    while(offset<bytes.size()) {
        const ssize_t n=::write(fd,bytes.data()+offset,bytes.size()-offset);
        if(n<0 && errno==EINTR)continue;
        if(n<=0){ok=false;break;}
        offset+=static_cast<size_t>(n);
    }
    if(ok)ok=::fsync(fd)==0;
    if(::close(fd)!=0)ok=false;
    return ok;
}
bool nonzero_key(const std::array<uint8_t,32>& key) {
    return std::any_of(key.begin(),key.end(),[](uint8_t b){return b!=0;});
}
} // namespace

std::vector<uint8_t> residual_native_source_pin_signing_message(
    const ResidualNativeSourcePinReceipt& receipt) {
    if(!receipt.issuer_id || !receipt.sequence || !receipt.sid ||
       !receipt.checkpoint ||
       receipt.scope_binding==Digest{} ||
       receipt.local_residual_root==Digest{} ||
       receipt.native_consumed_record_binding==Digest{} ||
       receipt.registration_pre_vss_claim_binding==Digest{})return {};
    std::vector<uint8_t> bytes;
    bytes.reserve(8*8+4*32);
    append_u64(&bytes,ROOT_RECEIPT_DOMAIN);
    append_u64(&bytes,ROOT_RECEIPT_VERSION);
    append_u64(&bytes,receipt.issuer_id);
    append_u64(&bytes,receipt.sequence);
    append_u64(&bytes,receipt.sid);
    append_u64(&bytes,receipt.checkpoint);
    append_u64(&bytes,receipt.owner);
    append_u64(&bytes,4);
    append_digest(&bytes,receipt.scope_binding);
    append_digest(&bytes,receipt.local_residual_root);
    append_digest(&bytes,receipt.native_consumed_record_binding);
    append_digest(&bytes,receipt.registration_pre_vss_claim_binding);
    return bytes;
}

bool write_residual_native_source_pin_receipt_file(
    const std::string& path,
    const ResidualNativeSourcePinReceipt& receipt) {
    if(path.empty() || residual_native_source_pin_signing_message(receipt).empty())
        return false;
    std::vector<uint8_t> wire(std::begin(PIN_FILE_MAGIC),
                              std::end(PIN_FILE_MAGIC));
    append_u64(&wire,receipt.issuer_id);
    append_u64(&wire,receipt.sequence);
    append_u64(&wire,receipt.sid);
    append_u64(&wire,receipt.checkpoint);
    append_u64(&wire,receipt.owner);
    append_digest(&wire,receipt.scope_binding);
    append_digest(&wire,receipt.local_residual_root);
    append_digest(&wire,receipt.native_consumed_record_binding);
    append_digest(&wire,receipt.registration_pre_vss_claim_binding);
    wire.insert(wire.end(),receipt.signature.begin(),receipt.signature.end());
    return wire.size()==PIN_FILE_BYTES &&
           write_exclusive_private(path,wire);
}

bool read_residual_native_source_pin_receipt_file(
    const std::string& path,
    ResidualNativeSourcePinReceipt* receipt) {
    if(path.empty() || !receipt)return false;
    const int fd=::open(path.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return false;
    struct stat st{};
    bool ok=::fstat(fd,&st)==0 && S_ISREG(st.st_mode) &&
        st.st_uid==::geteuid() && (st.st_mode&0077)==0 &&
        st.st_size==static_cast<off_t>(PIN_FILE_BYTES);
    std::array<uint8_t,PIN_FILE_BYTES> wire{};
    size_t offset=0;
    while(ok && offset<wire.size()) {
        const ssize_t n=::read(fd,wire.data()+offset,wire.size()-offset);
        if(n<0 && errno==EINTR)continue;
        if(n<=0){ok=false;break;}
        offset+=static_cast<size_t>(n);
    }
    uint8_t trailing=0;
    if(ok)ok=::read(fd,&trailing,1)==0;
    ::close(fd);
    if(!ok)return false;
    for(size_t i=0;i<sizeof(PIN_FILE_MAGIC);++i)
        if(wire[i]!=PIN_FILE_MAGIC[i])return false;
    ResidualNativeSourcePinReceipt parsed{};
    parsed.issuer_id=read_u64_le(wire.data()+8);
    parsed.sequence=read_u64_le(wire.data()+16);
    parsed.sid=read_u64_le(wire.data()+24);
    parsed.checkpoint=read_u64_le(wire.data()+32);
    const u64 owner=read_u64_le(wire.data()+40);
    if(owner>UINT32_MAX)return false;
    parsed.owner=static_cast<uint32_t>(owner);
    for(size_t i=0;i<32;++i) {
        parsed.scope_binding.bytes[i]=wire[48+i];
        parsed.local_residual_root.bytes[i]=wire[80+i];
        parsed.native_consumed_record_binding.bytes[i]=wire[112+i];
        parsed.registration_pre_vss_claim_binding.bytes[i]=wire[144+i];
    }
    for(size_t i=0;i<64;++i)parsed.signature[i]=wire[176+i];
    if(residual_native_source_pin_signing_message(parsed).empty())return false;
    *receipt=parsed;
    return true;
}

bool verify_residual_source_pin_and_native_execution_pair(
    const ObligationSet& scope,uint32_t local_owner,
    const ResidualNativeSourcePinReceipt& residual_pin,
    const RegistrationConsistencyStatement& registration_pre_vss,
    const RegistrationNativeExecutionReceipt& native_receipt,
    const Digest& independently_expected_native_consumed_binding,
    const std::array<uint8_t,32>& independently_pinned_issuer_key,
    u64 expected_issuer_id,u64 minimum_sequence) {
    if(registration_pre_vss.sid!=scope.session_id ||
       registration_pre_vss.checkpoint!=scope.checkpoint ||
       registration_pre_vss.ref.owner!=local_owner ||
       registration_pre_vss.kernel!=AuditRelationKernel::FOLD_RS ||
       native_receipt.issuer_id!=residual_pin.issuer_id ||
       native_receipt.sequence!=residual_pin.sequence ||
       native_receipt.pre_vss_claim_binding!=
           residual_pin.registration_pre_vss_claim_binding ||
       native_receipt.consumed_record_binding!=
           residual_pin.native_consumed_record_binding)
        return false;
    // Explicitly reject a statement for an operation outside the
    // currently fixed public activation layout.
    const auto match=std::find_if(
        scope.operations.begin(),scope.operations.end(),
        [&](const OperationRef& ref) {
            return ref==registration_pre_vss.ref;
        });
    if(match==scope.operations.end())return false;
    if(!verify_registration_native_execution_receipt_public(
           registration_pre_vss,native_receipt,
           independently_expected_native_consumed_binding,
           independently_pinned_issuer_key,expected_issuer_id,
           minimum_sequence))
        return false;
    return verify_residual_native_source_pin_receipt(
        scope,local_owner,residual_pin,
        independently_expected_native_consumed_binding,
        native_receipt.pre_vss_claim_binding,
        independently_pinned_issuer_key,expected_issuer_id,
        minimum_sequence);
}

bool verify_private_residual_provenance_matches_source_pin(
    const PrivateResidualShare& share,
    const ResidualNativeSourcePinReceipt& residual_pin,
    const std::array<uint8_t,32>& pinned_key,
    u64 expected_issuer_id,
    u64 minimum_accepted_sequence) {
    if(!share.authenticated ||
       !validate_private_residual_share(share) ||
       !expected_issuer_id || !minimum_accepted_sequence ||
       residual_pin.issuer_id!=expected_issuer_id ||
       residual_pin.sequence<minimum_accepted_sequence ||
       share.authentication.issuer_id!=residual_pin.issuer_id ||
       share.authentication.issuer_sequence!=residual_pin.sequence ||
       share.authentication.computation_binding!=share.computation_binding)
        return false;
    return verify_private_residual_authentication_artifact_signature(
        share,share.authentication,pinned_key,expected_issuer_id,
        minimum_accepted_sequence);
}

bool verify_residual_native_source_pin_receipt(
    const ObligationSet& scope,
    uint32_t local_owner,
    const ResidualNativeSourcePinReceipt& receipt,
    const Digest& expected_native,
    const Digest& expected_claim,
    const std::array<uint8_t,32>& pinned_key,
    u64 expected_issuer_id,
    u64 minimum_sequence) {
    if(!scope.session_id || !scope.checkpoint || scope.operations.empty() ||
       !expected_issuer_id || !minimum_sequence ||
       !nonzero_key(pinned_key) ||
       expected_native==Digest{} || expected_claim==Digest{} ||
       receipt.issuer_id!=expected_issuer_id ||
       receipt.sequence<minimum_sequence ||
       receipt.sid!=scope.session_id ||
       receipt.checkpoint!=scope.checkpoint ||
       receipt.owner!=local_owner ||
       receipt.scope_binding!=compute_collective_scope_binding(scope) ||
       receipt.native_consumed_record_binding!=expected_native ||
       receipt.registration_pre_vss_claim_binding!=expected_claim)
        return false;
    const auto message=residual_native_source_pin_signing_message(receipt);
    if(message.empty())return false;
    EVP_PKEY* key=EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519,nullptr,pinned_key.data(),pinned_key.size());
    if(!key)return false;
    EVP_MD_CTX* ctx=EVP_MD_CTX_new();
    const bool verified=ctx &&
        EVP_DigestVerifyInit(ctx,nullptr,nullptr,nullptr,key)==1 &&
        EVP_DigestVerify(ctx,receipt.signature.data(),
                         receipt.signature.size(),
                         message.data(),message.size())==1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return verified;
}
} // namespace pvia
