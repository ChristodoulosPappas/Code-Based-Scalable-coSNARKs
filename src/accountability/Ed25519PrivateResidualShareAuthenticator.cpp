#include "Ed25519PrivateResidualShareAuthenticator.hpp"

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <unistd.h>
#include <set>
#include <string>
#include <openssl/evp.h>

namespace pvia {
namespace {
constexpr u64 PROVENANCE_DOMAIN = 0x50565250524f5631ULL; // PVRPROV1
constexpr u64 PROVENANCE_VERSION = 1;
constexpr uint8_t RECEIPT_MAGIC[] = {'P','V','R','P','R','V','0','1'};
constexpr size_t RECEIPT_BYTES = 128;

void append_u64(std::vector<uint8_t>* out, u64 value) {
    for (unsigned i=0;i<8;++i)
        out->push_back(static_cast<uint8_t>(value>>(8*i)));
}
u64 read_u64_le(const uint8_t* at) {
    u64 value=0;
    for (unsigned i=0;i<8;++i)
        value |= static_cast<u64>(at[i]) << (8*i);
    return value;
}
void append_digest(std::vector<uint8_t>* out, const Digest& digest) {
    out->insert(out->end(),digest.bytes.begin(),digest.bytes.end());
}
bool nonzero_key(const std::array<uint8_t,32>& key) {
    return std::any_of(key.begin(),key.end(),
        [](uint8_t b){return b!=0;});
}
bool nonzero_signature(const std::array<uint8_t,64>& signature) {
    return std::any_of(signature.begin(),signature.end(),
        [](uint8_t b){return b!=0;});
}
bool check_or_consume_persistent_sequence(const std::string& path,
                                          u64 issuer_id, u64 sequence,
                                          bool consume) {
    if(path.empty()) return consume;
    if(!issuer_id || !sequence) return false;
    const int fd=::open(path.c_str(),
        O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0) return false;
    bool ok=::flock(fd,LOCK_EX)==0;
    struct stat st{};
    if(ok) ok=::fstat(fd,&st)==0 && S_ISREG(st.st_mode) &&
        st.st_uid==::geteuid() && st.st_nlink==1 &&
        (st.st_mode&0077)==0 && st.st_size>=0 &&
        st.st_size<=1024*1024 && st.st_size%16==0;
    std::vector<uint8_t> existing;
    if(ok) {
        existing.resize(static_cast<size_t>(st.st_size));
        if(::lseek(fd,0,SEEK_SET)<0) ok=false;
        size_t offset=0;
        while(ok && offset<existing.size()) {
            const ssize_t n=::read(
                fd,existing.data()+offset,existing.size()-offset);
            if(n<0 && errno==EINTR) continue;
            if(n<=0) {ok=false;break;}
            offset+=static_cast<size_t>(n);
        }
        uint8_t trailing=0;
        if(ok) ok=::read(fd,&trailing,1)==0;
    }
    std::set<std::pair<u64,u64>> seen;
    if(ok) {
        for(size_t offset=0;offset<existing.size();offset+=16) {
            const u64 issuer=read_u64_le(existing.data()+offset);
            const u64 seq=read_u64_le(existing.data()+offset+8);
            if(!issuer || !seq || !seen.insert({issuer,seq}).second) {
                ok=false;
                break;
            }
            if(issuer==issuer_id && seq==sequence) {
                ok=false;
                break;
            }
        }
    }
    if(ok && consume) {
        std::vector<uint8_t> record;
        record.reserve(16);
        append_u64(&record,issuer_id);
        append_u64(&record,sequence);
        if(::lseek(fd,0,SEEK_END)<0) ok=false;
        size_t offset=0;
        while(ok && offset<record.size()) {
            const ssize_t n=::write(
                fd,record.data()+offset,record.size()-offset);
            if(n<0 && errno==EINTR) continue;
            if(n<=0) {ok=false;break;}
            offset+=static_cast<size_t>(n);
        }
        if(ok) ok=::fsync(fd)==0;
    }
    if(::flock(fd,LOCK_UN)!=0) ok=false;
    if(::close(fd)!=0) ok=false;
    return ok;
}

bool write_private_exclusive(const std::string& path,
                             const std::vector<uint8_t>& bytes) {
    if(path.empty()) return false;
    const int fd=::open(path.c_str(),
        O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0) return false;
    size_t offset=0;
    bool ok=true;
    while(offset<bytes.size()) {
        const ssize_t n=::write(fd,bytes.data()+offset,bytes.size()-offset);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) {ok=false;break;}
        offset+=static_cast<size_t>(n);
    }
    if(ok) ok=::fsync(fd)==0;
    if(::close(fd)!=0) ok=false;
    if(!ok) ::unlink(path.c_str());
    return ok;
}
} // namespace

bool private_residual_provenance_sequence_available(
    const std::string& replay_ledger_file,u64 issuer_id,u64 sequence) {
    return !replay_ledger_file.empty() &&
        check_or_consume_persistent_sequence(
            replay_ledger_file,issuer_id,sequence,false);
}

std::vector<uint8_t> private_residual_provenance_signing_message(
    const PrivateResidualProvenanceReceipt& receipt) {
    if(!receipt.issuer_id || !receipt.sequence || !receipt.scheme_id ||
       receipt.computation_binding==Digest{}) return {};
    std::vector<uint8_t> message;
    message.reserve(5*8+32);
    append_u64(&message,PROVENANCE_DOMAIN);
    append_u64(&message,PROVENANCE_VERSION);
    append_u64(&message,receipt.issuer_id);
    append_u64(&message,receipt.sequence);
    append_u64(&message,receipt.scheme_id);
    append_digest(&message,receipt.computation_binding);
    return message;
}

bool read_private_residual_provenance_public_key_file(
    const std::string& path, std::array<uint8_t,32>* public_key) {
    if(path.empty() || !public_key) return false;
    const int fd=::open(path.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0) return false;
    struct stat st{};
    bool ok=::fstat(fd,&st)==0 && S_ISREG(st.st_mode) &&
        st.st_uid==::geteuid() && st.st_nlink==1 &&
        (st.st_mode&0077)==0 &&
        (st.st_size==64 || st.st_size==65);
    std::array<char,65> wire{};
    size_t offset=0;
    while(ok && offset<static_cast<size_t>(st.st_size)) {
        const ssize_t n=::read(fd,wire.data()+offset,
            static_cast<size_t>(st.st_size)-offset);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) {ok=false;break;}
        offset+=static_cast<size_t>(n);
    }
    char trailing=0;
    if(ok) ok=::read(fd,&trailing,1)==0;
    ::close(fd);
    if(!ok) return false;
    const size_t hex_size=wire[64]=='\n' ? 64 : static_cast<size_t>(st.st_size);
    if(hex_size!=64) return false;
    const auto nibble=[](char c)->int {
        if(c>='0' && c<='9') return c-'0';
        if(c>='a' && c<='f') return c-'a'+10;
        return -1;
    };
    std::array<uint8_t,32> parsed{};
    for(size_t i=0;i<parsed.size();++i) {
        const int hi=nibble(wire[2*i]);
        const int lo=nibble(wire[2*i+1]);
        if(hi<0 || lo<0) return false;
        parsed[i]=static_cast<uint8_t>((hi<<4)|lo);
    }
    if(!nonzero_key(parsed)) return false;
    *public_key=parsed;
    return true;
}

bool verify_private_residual_provenance_receipt(
    const PrivateResidualProvenanceReceipt& receipt,
    const std::array<uint8_t,32>& pinned_key,
    u64 expected_issuer_id, u64 expected_scheme_id,
    u64 minimum_sequence, const Digest& expected_binding) {
    if(!expected_issuer_id || !expected_scheme_id || !minimum_sequence ||
       !nonzero_key(pinned_key) || !nonzero_signature(receipt.signature) ||
       expected_binding==Digest{} || receipt.issuer_id!=expected_issuer_id ||
       receipt.scheme_id!=expected_scheme_id ||
       receipt.sequence<minimum_sequence ||
       receipt.computation_binding!=expected_binding)
        return false;
    const auto message=private_residual_provenance_signing_message(receipt);
    if(message.empty()) return false;
    EVP_PKEY* key=EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519,nullptr,pinned_key.data(),pinned_key.size());
    if(!key) return false;
    EVP_MD_CTX* ctx=EVP_MD_CTX_new();
    const bool verified=ctx &&
        EVP_DigestVerifyInit(ctx,nullptr,nullptr,nullptr,key)==1 &&
        EVP_DigestVerify(ctx,receipt.signature.data(),receipt.signature.size(),
                         message.data(),message.size())==1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return verified;
}

bool write_private_residual_provenance_receipt_file(
    const std::string& path,
    const PrivateResidualProvenanceReceipt& receipt) {
    if(path.empty() ||
       private_residual_provenance_signing_message(receipt).empty() ||
       !nonzero_signature(receipt.signature)) return false;
    std::vector<uint8_t> wire(std::begin(RECEIPT_MAGIC),
                              std::end(RECEIPT_MAGIC));
    append_u64(&wire,receipt.issuer_id);
    append_u64(&wire,receipt.sequence);
    append_u64(&wire,receipt.scheme_id);
    append_digest(&wire,receipt.computation_binding);
    wire.insert(wire.end(),receipt.signature.begin(),receipt.signature.end());
    return wire.size()==RECEIPT_BYTES && write_private_exclusive(path,wire);
}

bool read_private_residual_provenance_receipt_file(
    const std::string& path, PrivateResidualProvenanceReceipt* receipt) {
    if(path.empty() || !receipt) return false;
    const int fd=::open(path.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0) return false;
    struct stat st{};
    bool ok=::fstat(fd,&st)==0 && S_ISREG(st.st_mode) &&
        st.st_uid==::geteuid() && (st.st_mode&0077)==0 &&
        st.st_size==static_cast<off_t>(RECEIPT_BYTES);
    std::array<uint8_t,RECEIPT_BYTES> wire{};
    size_t offset=0;
    while(ok && offset<wire.size()) {
        const ssize_t n=::read(fd,wire.data()+offset,wire.size()-offset);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) {ok=false;break;}
        offset+=static_cast<size_t>(n);
    }
    uint8_t trailing=0;
    if(ok) ok=::read(fd,&trailing,1)==0;
    ::close(fd);
    if(!ok) return false;
    for(size_t i=0;i<sizeof(RECEIPT_MAGIC);++i)
        if(wire[i]!=RECEIPT_MAGIC[i]) return false;
    PrivateResidualProvenanceReceipt parsed{};
    parsed.issuer_id=read_u64_le(wire.data()+8);
    parsed.sequence=read_u64_le(wire.data()+16);
    parsed.scheme_id=read_u64_le(wire.data()+24);
    for(size_t i=0;i<32;++i)
        parsed.computation_binding.bytes[i]=wire[32+i];
    for(size_t i=0;i<64;++i)
        parsed.signature[i]=wire[64+i];
    if(private_residual_provenance_signing_message(parsed).empty() ||
       !nonzero_signature(parsed.signature)) return false;
    *receipt=parsed;
    return true;
}

Ed25519PrivateResidualShareAuthenticator::
Ed25519PrivateResidualShareAuthenticator(
    u64 scheme_id, u64 issuer_id, u64 minimum_sequence,
    const std::array<uint8_t,32>& pinned_key,
    std::vector<PrivateResidualProvenanceReceipt> receipts,
    std::string persistent_replay_ledger_path)
    : scheme_id_(scheme_id), expected_issuer_id_(issuer_id),
      minimum_accepted_sequence_(minimum_sequence), issuer_key_(pinned_key),
      receipts_(std::move(receipts)),
      persistent_replay_ledger_path_(
          std::move(persistent_replay_ledger_path)) {}

uint64_t Ed25519PrivateResidualShareAuthenticator::SchemeId() const {
    return scheme_id_;
}

bool Ed25519PrivateResidualShareAuthenticator::Authenticate(
    const PrivateResidualShare& share,
    PrivateResidualAuthenticationArtifact* artifact) const {
    if(!artifact || !scheme_id_ || !expected_issuer_id_ ||
       !minimum_accepted_sequence_ || !share.computation_valid ||
       share.computation_binding==Digest{} ||
       share.computation_binding!=compute_private_residual_computation_binding(share) ||
       share.source_state_authentication_scheme_id!=scheme_id_ ||
       share.source_state_authentication_binding==Digest{} ||
       share.source_state_digest==Digest{} ||
       share.operation_statement_binding==Digest{} ||
       !nonzero_key(issuer_key_))
        return false;

    std::lock_guard<std::mutex> lock(mutex_);
    const PrivateResidualProvenanceReceipt* match=nullptr;
    for(const auto& receipt:receipts_) {
        if(receipt.issuer_id!=expected_issuer_id_ ||
           receipt.scheme_id!=scheme_id_ ||
           receipt.sequence<minimum_accepted_sequence_ ||
           receipt.computation_binding!=share.computation_binding)
            continue;
        if(match) return false; // ambiguous provisioned evidence fails closed
        match=&receipt;
    }
    if(!match || consumed_sequences_.count(
            {match->issuer_id,match->sequence}) ||
       !verify_private_residual_provenance_receipt(
            *match,issuer_key_,expected_issuer_id_,scheme_id_,
            minimum_accepted_sequence_,share.computation_binding))
        return false;

    const auto message=private_residual_provenance_signing_message(*match);
    PrivateResidualAuthenticationArtifact candidate{};
    candidate.available=true;
    candidate.cryptographically_authenticated=true;
    candidate.scheme_id=scheme_id_;
    candidate.computation_binding=share.computation_binding;
    candidate.source_state_id=share.source_state_id;
    candidate.source_state_owner=share.source_state_owner;
    candidate.source_state_digest=share.source_state_digest;
    candidate.source_state_authentication_scheme_id=
        share.source_state_authentication_scheme_id;
    candidate.source_state_authentication_binding=
        share.source_state_authentication_binding;
    candidate.public_aux_root=share.public_aux_root;
    candidate.operation_statement_binding=share.operation_statement_binding;
    candidate.proof_commitment=hash_bytes(
        match->signature.data(),match->signature.size());
    candidate.transcript_binding=hash_bytes(message.data(),message.size());
    candidate.issuer_id=match->issuer_id;
    candidate.issuer_sequence=match->sequence;
    candidate.proof_signature=match->signature;
    candidate.binding=compute_private_residual_authentication_artifact_binding(
        candidate);
    if(!validate_private_residual_authentication_artifact(share,candidate))
        return false;
    if(!check_or_consume_persistent_sequence(
            persistent_replay_ledger_path_,
            match->issuer_id,match->sequence,true))
        return false;
    consumed_sequences_.insert({match->issuer_id,match->sequence});
    *artifact=candidate;
    return true;
}

bool verify_private_residual_authentication_artifact_signature(
    const PrivateResidualShare& share,
    const PrivateResidualAuthenticationArtifact& artifact,
    const std::array<uint8_t,32>& pinned_key,
    u64 expected_issuer_id, u64 minimum_sequence) {
    if(!validate_private_residual_authentication_artifact(share,artifact) ||
       artifact.issuer_id!=expected_issuer_id ||
       artifact.computation_binding!=share.computation_binding ||
       artifact.scheme_id!=share.source_state_authentication_scheme_id)
        return false;
    PrivateResidualProvenanceReceipt receipt;
    receipt.issuer_id=artifact.issuer_id;
    receipt.sequence=artifact.issuer_sequence;
    receipt.scheme_id=artifact.scheme_id;
    receipt.computation_binding=artifact.computation_binding;
    receipt.signature=artifact.proof_signature;
    const auto message=private_residual_provenance_signing_message(receipt);
    return !message.empty() &&
        artifact.transcript_binding==hash_bytes(message.data(),message.size()) &&
        artifact.proof_commitment==hash_bytes(
            receipt.signature.data(),receipt.signature.size()) &&
        verify_private_residual_provenance_receipt(
            receipt,pinned_key,expected_issuer_id,artifact.scheme_id,
            minimum_sequence,share.computation_binding);
}

} // namespace pvia
