#include "ReferenceVssShareRecovery.hpp"
#include <algorithm>
#include <limits>

namespace pvia {
namespace {
F decode_field(u64 re, u64 im) {
    return F(static_cast<long long>(re),static_cast<long long>(im));
}
F evaluate_row(const ReferenceVssLocalWitness& row,
               size_t element,int degree,const F& x) {
    const size_t start=element*static_cast<size_t>(degree+1)*2;
    F result(0);
    for(int d=degree;d>=0;--d) {
        const size_t index=start+2*static_cast<size_t>(d);
        result=result*x+decode_field(
            row.local_row_words[index],row.local_row_words[index+1]);
    }
    return result;
}
F interpolate_at(const std::vector<int>& participants,
                 const std::vector<F>& evaluations,
                 const F& target) {
    F sum(0);
    for(size_t i=0;i<participants.size();++i){
        const F xi(participants[i]+1);
        F numerator(1),denominator(1);
        for(size_t j=0;j<participants.size();++j){
            if(i==j)continue;
            const F xj(participants[j]+1);
            numerator*=target-xj;
            denominator*=xi-xj;
        }
        sum+=evaluations[i]*numerator*denominator.inv();
    }
    return sum;
}
} // namespace

bool recover_reference_vss_share_from_rows(
    int missing_participant,
    const ReferenceVssReceipt& receipt,
    const std::vector<ReferenceVssLocalWitness>& helpers,
    std::vector<F>* output) {
    if(!output) return false;
    output->clear();
    if(!receipt.available || !receipt.consistent ||
       receipt.transcript_binding==Digest{} ||
       receipt.world_size<4 || receipt.threshold<0 ||
       3*receipt.threshold>=receipt.world_size ||
       receipt.dealer<0 || receipt.dealer>=receipt.world_size ||
       receipt.element_count==0 ||
       missing_participant<0 ||
       missing_participant>=receipt.world_size ||
       helpers.size()<static_cast<size_t>(receipt.threshold+1) ||
       helpers.size()>static_cast<size_t>(receipt.world_size-1))
        return false;
    const size_t n=static_cast<size_t>(receipt.world_size);
    std::vector<bool> seen(n,false);
    const auto& reference=helpers.front().transcript_context;
    if(reference.row_commitments.size()!=n ||
       compute_reference_vss_transcript_binding(
           receipt.dealer,receipt.threshold,receipt.element_count,
           reference)!=receipt.transcript_binding)
        return false;
    std::vector<int> participants;
    participants.reserve(helpers.size());
    for(const auto& row:helpers) {
        if(!validate_reference_vss_local_witness(row) ||
           row.dealer!=receipt.dealer ||
           row.threshold!=receipt.threshold ||
           row.element_count!=receipt.element_count ||
           row.transcript_binding!=receipt.transcript_binding ||
           row.transcript_context.world_size!=receipt.world_size ||
           row.transcript_context.authenticated!=reference.authenticated ||
           row.transcript_context.capability_binding!=
               reference.capability_binding ||
           row.transcript_context.transport_bindings!=
               reference.transport_bindings ||
           row.transcript_context.row_commitments!=
               reference.row_commitments ||
           row.participant==missing_participant ||
           row.participant<0 || row.participant>=receipt.world_size ||
           seen[static_cast<size_t>(row.participant)])
            return false;
        seen[static_cast<size_t>(row.participant)]=true;
        participants.push_back(row.participant);
    }
    const size_t t=static_cast<size_t>(receipt.threshold+1);
    // Deterministic interpolation basis; every additional helper must
    // agree with the SAME degree-t row polynomial.
    const std::vector<int> basis(participants.begin(),participants.begin()+t);
    std::vector<F> recovered(receipt.element_count);
    const F missing_x(missing_participant+1);
    for(size_t element=0;element<receipt.element_count;++element){
        std::vector<F> evaluation;
        evaluation.reserve(t);
        for(size_t i=0;i<t;++i)
            evaluation.push_back(evaluate_row(
                helpers[i],element,receipt.threshold,missing_x));
        recovered[element]=interpolate_at(basis,evaluation,F(0));
        for(size_t i=t;i<helpers.size();++i) {
            const F got=evaluate_row(
                helpers[i],element,receipt.threshold,missing_x);
            if(interpolate_at(basis,evaluation,
                              F(participants[i]+1))!=got)
                return false;
        }
    }
    *output=std::move(recovered);
    return true;
}
} // namespace pvia
