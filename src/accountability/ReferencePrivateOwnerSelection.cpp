#include "ReferencePrivateOwnerSelection.hpp"

#include <cstring>

namespace pvia {
namespace {
constexpr u64 SELECTOR_DOMAIN = 0x50563130354f534cULL; // PV105OSL
constexpr u64 BOOLEAN_DOMAIN = 0x5056313035424f4fULL; // PV105BOO
void append_digest_words(const Digest& digest,std::vector<u64>* words) {
    for(size_t i=0;i<4;++i) {
        u64 word=0;
        std::memcpy(&word,digest.bytes.data()+i*8,8);
        words->push_back(word);
    }
}
F digest_field(const Digest& digest) {
    u64 value=0;
    std::memcpy(&value,digest.bytes.data(),8);
    return F(static_cast<long long>(value%(F::mod-1)+1));
}
} // namespace

bool select_reference_private_fault_owner(
    const ReferenceShamirMpc& mpc,
    const std::vector<F>& indicators,
    const std::vector<uint32_t>& owners,
    u64 sid, CheckpointId checkpoint,
    ReferencePrivateOwnerSelectionResult* result) {
    if(!result)return false;
    *result={};
    const size_t count=indicators.size();
    if(!mpc.valid() || !mpc.authenticated_transport_available() ||
       !mpc.robust_opening_available() ||
       !sid || !checkpoint || count==0 || count>64 ||
       count!=owners.size() || mpc.world_size()<4 ||
       mpc.world_size()>32)return false;
    for(uint32_t owner:owners)
        if(owner>=static_cast<uint32_t>(mpc.world_size()))return false;

    // Public circuit structure is independent of the selected operation.
    // Version 2 binds the fixed balanced-merge topology, not the
    // prior serial-prefix selector using the same owner layout.
    std::vector<u64> domain={SELECTOR_DOMAIN,2,sid,checkpoint,
        static_cast<u64>(count),
        static_cast<u64>(mpc.world_size()),
        static_cast<u64>(mpc.threshold())};
    for(uint32_t owner:owners)domain.push_back(owner);
    const Digest circuit=hash_words(domain);
    if(circuit==Digest{})return false;

    // Input shares have already been distributed before this public
    // commit/reveal challenge. A random linear check enforces b*(b-1)=0
    // without opening any individual b. Independent coefficients give an
    // algebraic soundness bound for invalid non-Boolean inputs.
    Digest challenge{};
    Digest transcript{};
    if(!mpc.JointPublicSeed(&challenge,&transcript) ||
       challenge==Digest{} || transcript==Digest{})return false;
    // All Boolean checks are independent. One vector-VSS
    // multiplication shares all b_i*(b_i-1), rather than Q successive
    // authenticated VSS rounds. The random-linear relation check
    // and its challenge remain exactly as before.
    std::vector<F> bool_rhs;
    bool_rhs.reserve(count);
    for(const F& bit:indicators)bool_rhs.push_back(bit-F(1));
    std::vector<F> boolean_residuals;
    if(!mpc.MultiplyVector(indicators,bool_rhs,&boolean_residuals) ||
       boolean_residuals.size()!=count)return false;
    F invalid_share(0);
    uint64_t multiply_count=static_cast<uint64_t>(count);
    for(size_t i=0;i<count;++i) {
        auto coeff_words=std::vector<u64>{
            BOOLEAN_DOMAIN,sid,checkpoint,static_cast<u64>(i)};
        append_digest_words(challenge,&coeff_words);
        append_digest_words(transcript,&coeff_words);
        append_digest_words(circuit,&coeff_words);
        invalid_share+=digest_field(hash_words(coeff_words))*
                       boolean_residuals[i];
    }

    // Each ordered subtree carries secret shares:
    //  no_fault = product of (1-b_i), winner = encoded owner of first
    //  nonzero b_i, or 0. To combine adjacent ordered subtrees L,R:
    //  no_fault = L.no_fault * R.no_fault
    //  winner = L.winner + L.no_fault * R.winner
    // The two independent multiplications per pair are batched into
    // ONE authenticated vector-VSS exchange for that tree layer.
    // Tree topology, pairing and all communication are fully public
    // and independent of the private indicators.
    struct TreeNode { F no_fault; F winner; };
    std::vector<TreeNode> nodes;
    nodes.reserve(count);
    for(size_t i=0;i<count;++i)
        nodes.push_back({
            F(1)-indicators[i],
            F(static_cast<long long>(owners[i])+1)*indicators[i]});
    while(nodes.size()>1) {
        const size_t pairs=nodes.size()/2;
        std::vector<F> lhs,rhs;
        lhs.reserve(pairs*2);rhs.reserve(pairs*2);
        for(size_t pair=0;pair<pairs;++pair) {
            const auto& left=nodes[2*pair];
            const auto& right=nodes[2*pair+1];
            lhs.push_back(left.no_fault);
            rhs.push_back(right.no_fault);
            lhs.push_back(left.no_fault);
            rhs.push_back(right.winner);
        }
        std::vector<F> combined;
        if(!mpc.MultiplyVector(lhs,rhs,&combined) ||
           combined.size()!=pairs*2)return false;
        multiply_count+=static_cast<uint64_t>(pairs*2);
        std::vector<TreeNode> next;
        next.reserve((nodes.size()+1)/2);
        for(size_t pair=0;pair<pairs;++pair)
            next.push_back({
                combined[2*pair],
                nodes[2*pair].winner+combined[2*pair+1]});
        if(nodes.size()%2)next.push_back(nodes.back());
        nodes=std::move(next);
    }
    const F selected_owner_share=nodes.front().winner;
    bool all_boolean=false;
    if(!mpc.MaskedZeroTest(invalid_share,&all_boolean) ||
       !all_boolean)return false;

    // Exactly one value is opened. It is encoded as j+1 so zero means
    // "no selected owner" and no second secret bit must be opened.
    F opened(0);
    if(!mpc.Open(selected_owner_share,&opened))return false;
    if(opened.img!=0 ||
       opened.real>static_cast<u64>(mpc.world_size()))return false;
    result->available=true;
    result->found=opened.real!=0;
    if(result->found)
        result->attributed_party=static_cast<uint32_t>(opened.real-1);
    result->circuit_binding=circuit;
    result->multiplication_count=multiply_count;
    return true;
}
} // namespace pvia
