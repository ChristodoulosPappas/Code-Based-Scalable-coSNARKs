#include "ResidualFingerprintLinearity.hpp"

#include <cstring>

namespace pvia {
namespace {
constexpr u64 COEFFICIENT_DOMAIN = 0x5056525348424154ULL; // PVRSHBAT

void append_digest_words(const Digest& digest, std::vector<u64>* words) {
    for(size_t i=0;i<4;++i) {
        u64 word=0;
        std::memcpy(&word,digest.bytes.data()+8*i,8);
        words->push_back(word);
    }
}

F fingerprint(u64 sid,CheckpointId checkpoint,
              const Digest& challenge,const Digest& transcript,
              size_t start,size_t end) {
    F accumulator(0);
    for(size_t k=start;k<end;++k) {
        const OperationRef op{
            static_cast<uint32_t>(k%4),static_cast<u64>(900000+k)};
        for(size_t coordinate=0;coordinate<3;++coordinate) {
            const F share(static_cast<long long>(k+7+coordinate*3),
                          static_cast<long long>(k*2+11+coordinate));
            accumulator += derive_residual_batch_global_coefficient(
                sid,checkpoint,challenge,transcript,op,coordinate)*share;
        }
    }
    return accumulator;
}
} // namespace

F derive_residual_batch_global_coefficient(
    u64 sid, CheckpointId checkpoint,
    const Digest& challenge, const Digest& transcript,
    const OperationRef& ref, size_t coordinate) {
    if(!sid || !checkpoint || challenge==Digest{} ||
       transcript==Digest{})return F(0);
    std::vector<u64> words={
        COEFFICIENT_DOMAIN,sid,checkpoint,ref.owner,
        ref.object_id,static_cast<u64>(coordinate)};
    append_digest_words(challenge,&words);
    append_digest_words(transcript,&words);
    const Digest hashed=hash_words(words);
    u64 real=0;
    u64 imag=0;
    std::memcpy(&real,hashed.bytes.data(),8);
    std::memcpy(&imag,hashed.bytes.data()+8,8);
    return F(static_cast<long long>(real%F::mod),
             static_cast<long long>(imag%F::mod));
}

bool run_residual_batch_global_additivity_selftest() {
    constexpr u64 SID=0x543201ULL;
    constexpr CheckpointId CHECKPOINT=0x563122ULL;
    const Digest challenge=hash_words({0x7011, SID,CHECKPOINT});
    const Digest transcript=hash_words({0x7012,SID,CHECKPOINT});
    const Digest other=hash_words({0x7013,SID,CHECKPOINT});
    if(challenge==Digest{} || transcript==Digest{} ||
       other==Digest{} || other==transcript)return false;
    bool different_domains_are_detectable=false;
    for(size_t n:{8ULL,32ULL,64ULL}) {
        const auto whole=fingerprint(SID,CHECKPOINT,challenge,transcript,0,n);
        for(size_t cut=1;cut<n;++cut) {
            const auto left=fingerprint(
                SID,CHECKPOINT,challenge,transcript,0,cut);
            const auto right=fingerprint(
                SID,CHECKPOINT,challenge,transcript,cut,n);
            if(whole != left+right)return false;
            const auto altered_right=fingerprint(
                SID,CHECKPOINT,challenge,other,cut,n);
            if(whole != left+altered_right)
                different_domains_are_detectable=true;
        }
    }
    return different_domains_are_detectable;
}

} // namespace pvia
