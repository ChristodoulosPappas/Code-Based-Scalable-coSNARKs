#include "ReferencePrivateResidualFlag.hpp"
#include <utility>

namespace pvia {
namespace {
// Given x, compute x^(2^k-1) in O(k) secret multiplications with
// a short addition chain. Both branch directions depend ONLY on public k.
// For k even: (2^k-1)=(2^(k/2)-1)*(2^(k/2)+1).
// For k odd:  (2^k-1)=2*(2^(k-1)-1)+1.
bool power_mersenne_share(
    const ReferenceShamirMpc& mpc, const F& base,
    unsigned bits, F* output, uint64_t* multiplications) {
    if(!output || !multiplications || bits==0 || bits>60)return false;
    if(bits==1){*output=base;return true;}
    F result(0);
    if(bits%2==0){
        F lower(0);
        if(!power_mersenne_share(mpc,base,bits/2,&lower,
                                 multiplications))return false;
        F squared=lower;
        for(unsigned i=0;i<bits/2;++i){
            F next(0);
            if(!mpc.Multiply(squared,squared,&next))return false;
            ++*multiplications;
            squared=next;
        }
        if(!mpc.Multiply(squared,lower,&result))return false;
        ++*multiplications;
    }else{
        F previous(0);
        if(!power_mersenne_share(mpc,base,bits-1,&previous,
                                 multiplications))return false;
        F squared(0);
        if(!mpc.Multiply(previous,previous,&squared) ||
           !mpc.Multiply(squared,base,&result))return false;
        *multiplications+=2;
    }
    *output=result;
    return true;
}

F conjugate_share(const F& share) {
    return F(static_cast<long long>(share.real),
        static_cast<long long>(share.img==0 ? 0 : F::mod-share.img));
}

// Batched equivalent of the same Mersenne exponent addition chain.
// The local lanes never contain a public zero-test/selected index, and
// every lane runs the same circuit irrespective of its private value.
bool power_mersenne_shares_vector(
    const ReferenceShamirMpc& mpc,const std::vector<F>& bases,
    unsigned bits,std::vector<F>* outputs,uint64_t* count) {
    if(!outputs || !count || bases.empty() || bases.size()>64 ||
       bits==0 || bits>60)return false;
    if(bits==1){*outputs=bases;return true;}
    if(bits%2==0) {
        std::vector<F> lower;
        if(!power_mersenne_shares_vector(
               mpc,bases,bits/2,&lower,count))return false;
        auto squared=lower;
        for(unsigned i=0;i<bits/2;++i){
            std::vector<F> next;
            if(!mpc.MultiplyVector(squared,squared,&next) ||
               next.size()!=bases.size())return false;
            *count+=bases.size();
            squared=std::move(next);
        }
        if(!mpc.MultiplyVector(squared,lower,outputs) ||
           outputs->size()!=bases.size())return false;
        *count+=bases.size();
    }else{
        std::vector<F> previous,squared;
        if(!power_mersenne_shares_vector(
               mpc,bases,bits-1,&previous,count) ||
           !mpc.MultiplyVector(previous,previous,&squared) ||
           !mpc.MultiplyVector(squared,bases,outputs) ||
           outputs->size()!=bases.size())return false;
        *count+=2*bases.size();
    }
    return true;
}
} // namespace

bool derive_reference_private_nonzero_flags(
    const ReferenceShamirMpc& mpc,
    const std::vector<F>& residual_shares,
    std::vector<F>* flags,
    uint64_t* multiplication_count) {
    if(!flags || !multiplication_count)return false;
    flags->clear();
    *multiplication_count=0;
    // F is a quadratic extension over GF(p) with i^2=-1.
    // p=2^61-1 is 3 mod 4, hence x^p=conjugate(x), and
    // norm(x)=x*conjugate(x) is in GF(p).
    if(!mpc.valid() || !mpc.authenticated_transport_available() ||
       !mpc.robust_opening_available() ||
       F::mod!=((1ULL<<61)-1) ||
       F(0,1)*F(0,1)!=F(-1) ||
       residual_shares.empty() || residual_shares.size()>64)
        return false;
    // Width-1 retains the original passive scalar path. For Q>1 the
    // exact same norm and exponent circuit is evaluated with vector-VSS
    // degree reduction: one authenticated VSS batch per circuit layer
    // instead of one batch per candidate and layer.
    if(residual_shares.size()>1) {
        std::vector<F> conjugates;
        conjugates.reserve(residual_shares.size());
        for(const F& residual:residual_shares)
            conjugates.push_back(conjugate_share(residual));
        std::vector<F> norms,powers,derived;
        if(!mpc.MultiplyVector(residual_shares,conjugates,&norms) ||
           norms.size()!=residual_shares.size())return false;
        *multiplication_count+=residual_shares.size();
        if(!power_mersenne_shares_vector(
               mpc,norms,60,&powers,multiplication_count) ||
           !mpc.MultiplyVector(powers,powers,&derived) ||
           derived.size()!=residual_shares.size())return false;
        *multiplication_count+=residual_shares.size();
        *flags=std::move(derived);
        return true;
    }
    std::vector<F> derived;
    derived.reserve(residual_shares.size());
    for(const F& residual:residual_shares) {
        F norm(0);
        const F conjugate=conjugate_share(residual);
        if(!mpc.Multiply(residual,conjugate,&norm))return false;
        ++*multiplication_count;
        // norm^(p-1) = norm^(2^61-2) is 1 iff norm is nonzero.
        // For GF(p^2), norm=0 iff the original residual=0.
        F power(0);
        if(!power_mersenne_share(mpc,norm,60,&power,
                                  multiplication_count))return false;
        F nonzero(0);
        if(!mpc.Multiply(power,power,&nonzero))return false;
        ++*multiplication_count;
        derived.push_back(nonzero);
    }
    *flags=std::move(derived);
    return true;
}
} // namespace pvia
