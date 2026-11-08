#include "accountability/ReferenceResidualPairPublicVerifier.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <map>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
int hex_digit(char c) {
    if(c>='0' && c<='9') return c-'0';
    if(c>='a' && c<='f') return c-'a'+10;
    return -1;
}
bool hex_bytes(const std::string& hex,std::vector<uint8_t>* result) {
    if(!result || hex.size()%2) return false;
    result->clear();
    for(size_t i=0;i<hex.size();i+=2) {
        int lo=hex_digit(hex[i]),hi=hex_digit(hex[i+1]);
        if(lo<0||hi<0)return false;
        result->push_back(static_cast<uint8_t>((lo<<4)|hi));
    }
    return true;
}
bool hex_digest(const std::string& hex,std::array<uint8_t,32>* output) {
    std::vector<uint8_t> value;
    if(!hex_bytes(hex,&value) || value.size()!=32 || !output)return false;
    std::copy(value.begin(),value.end(),output->begin());
    return true;
}
bool read_pin(const std::string& filename,std::array<uint8_t,32>* result) {
    const int fd=::open(filename.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return false;
    struct stat st{};
    bool ok=::fstat(fd,&st)==0&&S_ISREG(st.st_mode)&&st.st_size==64;
    char raw[64]{};
    size_t offset=0;
    while(ok&&offset<sizeof(raw)) {
        ssize_t n=::read(fd,raw+offset,sizeof(raw)-offset);
        if(n<=0){ok=false;break;}
        offset+=static_cast<size_t>(n);
    }
    ::close(fd);
    return ok&&hex_digest(std::string(raw,sizeof(raw)),result);
}
bool decimal(const std::string& s,uint64_t* value) {
    if(!value||s.empty()|| (s.size()>1&&s[0]=='0'))return false;
    uint64_t v=0;
    for(char c:s) {
        if(c<'0'||c>'9'||
           v>(std::numeric_limits<uint64_t>::max()-uint64_t(c-'0'))/10)
            return false;
        v=v*10+uint64_t(c-'0');
    }
    *value=v;
    return v!=0;
}
}
int main(int argc,char** argv) {
    if(argc!=21) {
        std::cerr<<"usage: pvia_reference_pair_verify "
                 <<"--native PATH --link PATH --issuer-public PATH "
                 <<"--native-message HEX --issuer-id DEC --sequence DEC "
                 <<"--claim HEX --source HEX --computation HEX --commitment HEX\n";
        return 2;
    }
    std::map<std::string,std::string> args;
    for(int i=1;i<argc;i+=2) {
        if(i+1>=argc || !args.emplace(argv[i],argv[i+1]).second)
            return 2;
    }
    if(args.size()!=10) return 2;
    const char* required[]={"--native","--link","--issuer-public",
        "--native-message","--issuer-id","--sequence","--claim",
        "--source","--computation","--commitment"};
    for(const char* key:required)if(!args.count(key))return 2;

    pvia::ReferenceResidualPairExpected e;
    if(!decimal(args["--issuer-id"],&e.issuer_id) ||
       !decimal(args["--sequence"],&e.sequence) ||
       !read_pin(args["--issuer-public"],&e.issuer_public_key) ||
       !hex_bytes(args["--native-message"],&e.canonical_native_message) ||
       !hex_digest(args["--claim"],&e.pre_vss_claim_binding) ||
       !hex_digest(args["--source"],&e.consumed_source_binding) ||
       !hex_digest(args["--computation"],&e.residual_computation_binding) ||
       !hex_digest(args["--commitment"],&e.residual_commitment))
        return 2;

    std::vector<uint8_t> native,link;
    const bool valid=pvia::ReadReferenceResidualPairWire(
        args["--native"],args["--link"],&native,&link) &&
        pvia::VerifyReferenceResidualPairPublic(e,native,link);
    std::cout<<"PVIA_REFERENCE_PAIR_PUBLIC_VERIFY "
             <<(valid?"PASS":"FAIL")
             <<" source_only=true residual_authenticated=false\n";
    return valid?0:1;
}
