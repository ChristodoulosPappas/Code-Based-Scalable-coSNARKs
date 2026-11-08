#include "ReferenceNativeIssuerKeyAdapter.hpp"
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#include <string>

namespace pvia {
namespace {
template <size_t N>
bool ReadFile(const std::string& path,
              std::array<uint8_t,N>* value, bool is_secret) {
    int fd=::open(path.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0) return false;
    struct stat st{};
    bool ok=::fstat(fd,&st)==0 && S_ISREG(st.st_mode) &&
            st.st_size==static_cast<off_t>(N) &&
            (!is_secret || (st.st_uid==::geteuid() &&
                            (st.st_mode & 0077)==0));
    size_t off=0;
    while(ok && off<N) {
        const ssize_t n=::read(fd,value->data()+off,N-off);
        if(n<0 && errno==EINTR) continue;
        if(n<=0){ok=false;break;}
        off+=static_cast<size_t>(n);
    }
    ::close(fd);
    return ok;
}
int hex_nibble(uint8_t c){
    if(c>='0' && c<='9') return c-'0';
    if(c>='a' && c<='f') return c-'a'+10;
    return -1;
}
} // namespace
bool LoadReferenceNativeIssuerSigningKey(
    const std::string& directory, int mpi_rank,
    EVP_PKEY** private_key, std::array<uint8_t,32>* expected_public_key) {
    if(!private_key || !expected_public_key || mpi_rank<0 ||
       mpi_rank>=64 || directory.empty()) return false;
    *private_key=nullptr;
    struct stat st{};
    if(::lstat(directory.c_str(),&st)!=0 || !S_ISDIR(st.st_mode) ||
       st.st_uid!=::geteuid() || (st.st_mode & 0077)!=0) return false;
    const std::string prefix=directory+"/issuer-rank-"+
                             std::to_string(mpi_rank);
    std::array<uint8_t,32> seed{};
    std::array<uint8_t,64> pin_hex{};
    if(!ReadFile(prefix+".seed",&seed,true) ||
       !ReadFile(prefix+".pub",&pin_hex,false)) return false;
    std::array<uint8_t,32> expected{};
    for(size_t i=0;i<32;++i){
        const int hi=hex_nibble(pin_hex[2*i]);
        const int lo=hex_nibble(pin_hex[2*i+1]);
        if(hi<0 || lo<0) return false;
        expected[i]=static_cast<uint8_t>(hi*16+lo);
    }
    EVP_PKEY* pkey=EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519,nullptr,seed.data(),seed.size());
    seed.fill(0);
    if(!pkey)return false;
    std::array<uint8_t,32> actual{};
    size_t size=actual.size();
    const bool valid=
        EVP_PKEY_get_raw_public_key(pkey,actual.data(),&size)==1 &&
        size==actual.size() && actual==expected;
    if(!valid){EVP_PKEY_free(pkey);return false;}
    *private_key=pkey;
    *expected_public_key=expected;
    return true;
}
bool LoadReferenceNativeIssuerPublicKey(
    const std::string& directory, int mpi_rank,
    std::array<uint8_t,32>* expected_public_key) {
    if (!expected_public_key || mpi_rank < 0 || mpi_rank >= 64 ||
        directory.empty())
        return false;
    struct stat st{};
    if (::lstat(directory.c_str(), &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != ::geteuid() || (st.st_mode & 0077) != 0)
        return false;
    const std::string path = directory + "/issuer-rank-" +
        std::to_string(mpi_rank) + ".pub";
    std::array<uint8_t,64> encoded{};
    if (!ReadFile(path, &encoded, true))
        return false;
    std::array<uint8_t,32> decoded{};
    for (size_t i=0;i<decoded.size();++i) {
        const int hi=hex_nibble(encoded[2*i]);
        const int lo=hex_nibble(encoded[2*i+1]);
        if (hi<0 || lo<0)
            return false;
        decoded[i]=static_cast<uint8_t>(hi*16+lo);
    }
    if (decoded == std::array<uint8_t,32>{})
        return false;
    *expected_public_key=decoded;
    return true;
}


bool LoadReferenceNativeExecutorSigningKey(
    const std::string& directory, int mpi_rank,
    EVP_PKEY** private_key, std::array<uint8_t,32>* expected_public_key) {
    if(!private_key || !expected_public_key || mpi_rank<0 ||
       mpi_rank>=64 || directory.empty()) return false;
    *private_key=nullptr;
    struct stat st{};
    if(::lstat(directory.c_str(),&st)!=0 || !S_ISDIR(st.st_mode) ||
       st.st_uid!=::geteuid() || (st.st_mode & 0077)!=0) return false;
    const std::string prefix=directory+"/executor-rank-"+
                             std::to_string(mpi_rank);
    std::array<uint8_t,32> seed{};
    std::array<uint8_t,64> pin_hex{};
    if(!ReadFile(prefix+".seed",&seed,true) ||
       !ReadFile(prefix+".pub",&pin_hex,false)) return false;
    std::array<uint8_t,32> expected{};
    for(size_t i=0;i<32;++i) {
        const int hi=hex_nibble(pin_hex[2*i]);
        const int lo=hex_nibble(pin_hex[2*i+1]);
        if(hi<0 || lo<0) return false;
        expected[i]=static_cast<uint8_t>(hi*16+lo);
    }
    EVP_PKEY* pkey=EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519,nullptr,seed.data(),seed.size());
    seed.fill(0);
    if(!pkey)return false;
    std::array<uint8_t,32> actual{};
    size_t size=actual.size();
    const bool valid=
        EVP_PKEY_get_raw_public_key(pkey,actual.data(),&size)==1 &&
        size==actual.size() && actual==expected;
    if(!valid){EVP_PKEY_free(pkey);return false;}
    *private_key=pkey;
    *expected_public_key=expected;
    return true;
}

} // namespace pvia
