#include "ReferenceVssDealerFromRows.hpp"
#include <algorithm>
#include <limits>

namespace pvia {
namespace {
F decode_field(u64 real,u64 imag) {
    return F(static_cast<long long>(real),static_cast<long long>(imag));
}
void append_field(const F& x,std::vector<u64>* words) {
    words->push_back(x.real);
    words->push_back(x.img);
}
} // namespace
bool reconstruct_reference_vss_dealer_from_rows(
    const ReferenceVssReceipt& receipt,
    const std::vector<ReferenceVssLocalWitness>& helpers,
    ReferenceVssDealerWitness* result) {
    if(!result)return false;
    *result=ReferenceVssDealerWitness{};
    if(!receipt.available || !receipt.consistent ||
       receipt.world_size<4 || receipt.threshold<0 ||
       3*receipt.threshold>=receipt.world_size ||
       receipt.dealer<0 || receipt.dealer>=receipt.world_size ||
       receipt.element_count==0 || receipt.transcript_binding==Digest{} ||
       helpers.size()<static_cast<size_t>(receipt.threshold+1) ||
       helpers.size()>static_cast<size_t>(receipt.world_size))
        return false;
    const size_t n=static_cast<size_t>(receipt.world_size);
    const size_t d=static_cast<size_t>(receipt.threshold+1);
    if(receipt.element_count>std::numeric_limits<size_t>::max()/d/d/2)
        return false;
    const auto& common=helpers.front().transcript_context;
    if(common.world_size!=receipt.world_size ||
       common.row_commitments.size()!=n ||
       compute_reference_vss_transcript_binding(
           receipt.dealer,receipt.threshold,receipt.element_count,
           common)!=receipt.transcript_binding)
        return false;
    std::vector<bool> seen(n,false);
    for(const auto& row:helpers) {
        if(!validate_reference_vss_local_witness(row) ||
           row.dealer!=receipt.dealer ||
           row.threshold!=receipt.threshold ||
           row.element_count!=receipt.element_count ||
           row.transcript_binding!=receipt.transcript_binding ||
           row.participant<0 || row.participant>=receipt.world_size ||
           seen[static_cast<size_t>(row.participant)] ||
           row.transcript_context.world_size!=common.world_size ||
           row.transcript_context.authenticated!=common.authenticated ||
           row.transcript_context.capability_binding!=common.capability_binding ||
           row.transcript_context.transport_bindings!=common.transport_bindings ||
           row.transcript_context.row_commitments!=common.row_commitments)
            return false;
        seen[static_cast<size_t>(row.participant)]=true;
    }
    // L_i(X)=prod_{j!=i}(X-x_j)/(x_i-x_j), using the first
    // t+1 distinct helpers. Lagrange coefficient lists allow
    // reconstruction of every coefficient of f(X,Y).
    std::vector<std::vector<F>> basis(d,std::vector<F>(d,F(0)));
    for(size_t i=0;i<d;++i) {
        std::vector<F> polynomial{F(1)};
        F denominator(1);
        const F xi(helpers[i].participant+1);
        for(size_t j=0;j<d;++j) {
            if(i==j)continue;
            const F xj(helpers[j].participant+1);
            std::vector<F> next(polynomial.size()+1,F(0));
            for(size_t k=0;k<polynomial.size();++k) {
                next[k]-=polynomial[k]*xj;
                next[k+1]+=polynomial[k];
            }
            polynomial=std::move(next);
            denominator*=xi-xj;
        }
        const F inv=denominator.inv();
        for(size_t k=0;k<d;++k)
            basis[i][k]=polynomial[k]*inv;
    }
    ReferenceVssDealerWitness derived{};
    derived.available=true;
    derived.dealer=receipt.dealer;
    derived.threshold=receipt.threshold;
    derived.element_count=receipt.element_count;
    derived.transcript_binding=receipt.transcript_binding;
    derived.transcript_context=common;
    derived.coefficient_words.reserve(receipt.element_count*d*d*2);
    for(size_t element=0;element<receipt.element_count;++element) {
        for(size_t x_degree=0;x_degree<d;++x_degree) {
            for(size_t y_degree=0;y_degree<d;++y_degree) {
                F coefficient(0);
                for(size_t i=0;i<d;++i){
                    const size_t offset=2*(element*d+y_degree);
                    const F row=decode_field(
                        helpers[i].local_row_words[offset],
                        helpers[i].local_row_words[offset+1]);
                    coefficient+=basis[i][x_degree]*row;
                }
                append_field(coefficient,&derived.coefficient_words);
            }
        }
    }
    // Strong check: symmetry and commitments of ALL participants.
    // This also checks additional helper rows through their
    // pre-committed row hashes without disclosing them publicly.
    if(!validate_reference_vss_dealer_witness(derived)) return false;
    *result=std::move(derived);
    return true;
}
} // namespace pvia
