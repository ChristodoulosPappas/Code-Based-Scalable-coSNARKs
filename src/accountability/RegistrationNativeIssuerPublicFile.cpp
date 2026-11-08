#include "RegistrationNativeIssuerPublicFile.hpp"

#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace pvia {
namespace {
constexpr uint8_t MAGIC[] = {'P','V','N','I','S','S','0','1'};
constexpr size_t WIRE_BYTES = 8 + 8 + 8 + 32 + 32 + 64;
void append_u64(std::vector<uint8_t>* out, u64 v) {
    for (size_t i = 0; i < 8; ++i)
        out->push_back(static_cast<uint8_t>(v >> (8*i)));
}
u64 read_u64(const uint8_t* at) {
    u64 value = 0;
    for (size_t i = 0; i < 8; ++i)
        value |= static_cast<u64>(at[i]) << (8*i);
    return value;
}
int nibble(char x) {
    if (x >= '0' && x <= '9') return x-'0';
    if (x >= 'a' && x <= 'f') return x-'a'+10;
    return -1;
}
} // namespace

bool parse_native_issuer_public_key_hex(
    const std::string& hex, std::array<uint8_t, 32>* output) {
    if (!output || hex.size() != 64) return false;
    std::array<uint8_t, 32> key{};
    for (size_t i=0;i<key.size();++i) {
        int a=nibble(hex[2*i]), b=nibble(hex[2*i+1]);
        if (a<0 || b<0) return false;
        key[i]=static_cast<uint8_t>(a*16+b);
    }
    if (key == std::array<uint8_t,32>{}) return false;
    *output=key;
    return true;
}

bool write_registration_native_issuer_public_file(
    const std::string& new_file,
    const RegistrationNativeExecutionReceipt& receipt) {
    if (new_file.empty() || !receipt.issuer_id || !receipt.sequence ||
        receipt.pre_vss_claim_binding == Digest{} ||
        receipt.consumed_record_binding == Digest{})
        return false;
    std::vector<uint8_t> wire(std::begin(MAGIC),std::end(MAGIC));
    append_u64(&wire,receipt.issuer_id);
    append_u64(&wire,receipt.sequence);
    wire.insert(wire.end(),receipt.pre_vss_claim_binding.bytes.begin(),
                receipt.pre_vss_claim_binding.bytes.end());
    wire.insert(wire.end(),receipt.consumed_record_binding.bytes.begin(),
                receipt.consumed_record_binding.bytes.end());
    wire.insert(wire.end(),receipt.signature.begin(),receipt.signature.end());
    if (wire.size()!=WIRE_BYTES) return false;
    int fd=::open(new_file.c_str(), O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if (fd<0) return false;
    size_t offset=0;
    bool ok=true;
    while (offset<wire.size()) {
        ssize_t count=::write(fd,wire.data()+offset,wire.size()-offset);
        if (count<0 && errno==EINTR) continue;
        if (count<=0) {ok=false;break;}
        offset+=static_cast<size_t>(count);
    }
    if (ok) ok=::fsync(fd)==0;
    if (::close(fd)!=0) ok=false;
    return ok;
}

bool read_registration_native_issuer_public_file(
    const std::string& file,
    RegistrationNativeExecutionReceipt* receipt) {
    if (!receipt) return false;
    int fd=::open(file.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return false;
    struct stat st{};
    bool ok=::fstat(fd,&st)==0 && S_ISREG(st.st_mode) &&
            st.st_size==static_cast<off_t>(WIRE_BYTES);
    std::array<uint8_t,WIRE_BYTES> wire{};
    size_t offset=0;
    while (ok && offset<wire.size()) {
        ssize_t count=::read(fd,wire.data()+offset,wire.size()-offset);
        if (count<0 && errno==EINTR) continue;
        if (count<=0) {ok=false;break;}
        offset+=static_cast<size_t>(count);
    }
    uint8_t trailing=0;
    if (ok) ok=::read(fd,&trailing,1)==0;
    ::close(fd);
    if (!ok) return false;
    for (size_t i=0;i<sizeof(MAGIC);++i)
        if (wire[i]!=MAGIC[i]) return false;
    RegistrationNativeExecutionReceipt parsed{};
    parsed.issuer_id=read_u64(wire.data()+8);
    parsed.sequence=read_u64(wire.data()+16);
    for(size_t i=0;i<32;++i) {
        parsed.pre_vss_claim_binding.bytes[i]=wire[24+i];
        parsed.consumed_record_binding.bytes[i]=wire[56+i];
    }
    for(size_t i=0;i<64;++i) parsed.signature[i]=wire[88+i];
    if (!parsed.issuer_id || !parsed.sequence ||
        parsed.pre_vss_claim_binding==Digest{} ||
        parsed.consumed_record_binding==Digest{}) return false;
    *receipt=parsed;
    return true;
}

bool verify_registration_native_issuer_public_file(
    const std::string& file,
    const RegistrationConsistencyStatement& expected_statement,
    const Digest& independently_expected_consumed_binding,
    const std::array<uint8_t, 32>& independently_pinned_issuer_key,
    u64 expected_issuer_id, u64 minimum_accepted_sequence) {
    RegistrationNativeExecutionReceipt receipt;
    return read_registration_native_issuer_public_file(file,&receipt) &&
        verify_registration_native_execution_receipt_public(
            expected_statement,receipt,
            independently_expected_consumed_binding,
            independently_pinned_issuer_key,
            expected_issuer_id,minimum_accepted_sequence);
}
// V2 carries the existing source signature plus the final statement
// commitment and a DIFFERENT-domain Ed25519 signature over all 46 words.
bool write_registration_native_issuer_release_file(
    const std::string& path,
    const RegistrationNativeIssuerReleaseEvidence& evidence) {
    constexpr uint8_t MAGIC2[]={'P','V','N','I','S','S','0','2'};
    constexpr size_t V2_BYTES=248;
    const auto& r=evidence.source_receipt;
    if (path.empty() || !r.issuer_id || !r.sequence ||
        r.pre_vss_claim_binding==Digest{} ||
        r.consumed_record_binding==Digest{} ||
        evidence.final_statement_binding==Digest{})
        return false;
    std::vector<uint8_t> wire(std::begin(MAGIC2),std::end(MAGIC2));
    append_u64(&wire,r.issuer_id);
    append_u64(&wire,r.sequence);
    wire.insert(wire.end(),r.pre_vss_claim_binding.bytes.begin(),
                r.pre_vss_claim_binding.bytes.end());
    wire.insert(wire.end(),r.consumed_record_binding.bytes.begin(),
                r.consumed_record_binding.bytes.end());
    wire.insert(wire.end(),r.signature.begin(),r.signature.end());
    wire.insert(wire.end(),evidence.final_statement_binding.bytes.begin(),
                evidence.final_statement_binding.bytes.end());
    wire.insert(wire.end(),evidence.final_signature.begin(),
                evidence.final_signature.end());
    if (wire.size()!=V2_BYTES) return false;
    int fd=::open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if (fd<0) return false;
    size_t off=0;
    bool ok=true;
    while (off<wire.size()) {
        const ssize_t n=::write(fd,wire.data()+off,wire.size()-off);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) {ok=false;break;}
        off+=static_cast<size_t>(n);
    }
    if(ok) ok=::fsync(fd)==0;
    if(::close(fd)!=0) ok=false;
    return ok;
}

bool read_registration_native_issuer_release_file(
    const std::string& path,
    RegistrationNativeIssuerReleaseEvidence* evidence) {
    if (!evidence) return false;
    constexpr uint8_t MAGIC2[]={'P','V','N','I','S','S','0','2'};
    constexpr size_t V2_BYTES=248;
    int fd=::open(path.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return false;
    struct stat st{};
    bool ok=::fstat(fd,&st)==0 && S_ISREG(st.st_mode) &&
            st.st_size==static_cast<off_t>(V2_BYTES);
    std::array<uint8_t,V2_BYTES> wire{};
    size_t off=0;
    while(ok && off<wire.size()){
        const ssize_t n=::read(fd,wire.data()+off,wire.size()-off);
        if(n<0 && errno==EINTR) continue;
        if(n<=0){ok=false;break;}
        off+=static_cast<size_t>(n);
    }
    uint8_t trailing=0;
    if(ok) ok=::read(fd,&trailing,1)==0;
    ::close(fd);
    if(!ok) return false;
    for(size_t i=0;i<sizeof(MAGIC2);++i)
        if(wire[i]!=MAGIC2[i]) return false;
    RegistrationNativeIssuerReleaseEvidence parsed{};
    auto& r=parsed.source_receipt;
    r.issuer_id=read_u64(wire.data()+8);
    r.sequence=read_u64(wire.data()+16);
    for(size_t i=0;i<32;++i){
        r.pre_vss_claim_binding.bytes[i]=wire[24+i];
        r.consumed_record_binding.bytes[i]=wire[56+i];
        parsed.final_statement_binding.bytes[i]=wire[152+i];
    }
    for(size_t i=0;i<64;++i){
        r.signature[i]=wire[88+i];
        parsed.final_signature[i]=wire[184+i];
    }
    if(!r.issuer_id || !r.sequence ||
       r.pre_vss_claim_binding==Digest{} ||
       r.consumed_record_binding==Digest{} ||
       parsed.final_statement_binding==Digest{})
        return false;
    *evidence=parsed;
    return true;
}

bool verify_registration_native_issuer_release_file(
    const std::string& path,
    const RegistrationConsistencyStatement& statement,
    const Digest& expected_consumed,
    const std::array<uint8_t,32>& expected_issuer_key,
    u64 expected_issuer_id, u64 minimum_accepted_sequence) {
    RegistrationNativeIssuerReleaseEvidence evidence;
    return read_registration_native_issuer_release_file(path,&evidence) &&
        verify_registration_native_issuer_release_evidence(
            statement,evidence,expected_consumed,expected_issuer_key,
            expected_issuer_id,minimum_accepted_sequence);
}

} // namespace pvia
