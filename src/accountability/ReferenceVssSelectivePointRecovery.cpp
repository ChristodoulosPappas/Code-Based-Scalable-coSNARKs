#include "ReferenceVssSelectivePointRecovery.hpp"

namespace pvia {
namespace {
F read_field(u64 r,u64 i) {
    return F(static_cast<long long>(r),static_cast<long long>(i));
}
F evaluate_private_row(const ReferenceVssLocalWitness& witness,
                       size_t element, const F& point) {
    const size_t dim=static_cast<size_t>(witness.threshold+1);
    F result(0);
    const size_t start=element*dim*2;
    for(int j=witness.threshold;j>=0;--j){
        const size_t index=start+static_cast<size_t>(j)*2;
        result=result*point+read_field(
            witness.local_row_words[index],
            witness.local_row_words[index+1]);
    }
    return result;
}
F interpolation(const std::vector<ReferenceVssSelectivePoint>& samples,
                size_t degree, size_t element, const F& point) {
    F sum(0);
    for(size_t i=0;i<degree;++i){
        F num(1),den(1);
        const F xi(samples[i].helper+1);
        for(size_t j=0;j<degree;++j){
            if(i==j)continue;
            const F xj(samples[j].helper+1);
            num*=point-xj;
            den*=xi-xj;
        }
        sum+=samples[i].values[element]*num*den.inv();
    }
    return sum;
}
} // namespace

bool make_reference_vss_selective_point(
    const ReferenceVssLocalWitness& helper,
    int target,ReferenceVssSelectivePoint* result) {
    if(!result) return false;
    *result=ReferenceVssSelectivePoint{};
    if(!validate_reference_vss_local_witness(helper) ||
       target<0 || target>=helper.transcript_context.world_size ||
       target==helper.participant)return false;
    ReferenceVssSelectivePoint point;
    point.helper=helper.participant;
    point.target=target;
    point.transcript_binding=helper.transcript_binding;
    point.helper_row_commitment=helper.local_row_commitment;
    const F x(target+1);
    point.values.reserve(helper.element_count);
    for(size_t i=0;i<helper.element_count;++i)
        point.values.push_back(evaluate_private_row(helper,i,x));
    *result=std::move(point);
    return true;
}

bool recover_reference_vss_share_from_points(
    int target,const ReferenceVssReceipt& receipt,
    const ReferenceVssTranscriptContext& context,
    const std::vector<ReferenceVssSelectivePoint>& points,
    std::vector<F>* result) {
    if(!result)return false;
    result->clear();
    if(!receipt.available || !receipt.consistent ||
       receipt.world_size<4 || receipt.threshold<0 ||
       3*receipt.threshold>=receipt.world_size ||
       receipt.dealer<0 || receipt.dealer>=receipt.world_size ||
       receipt.element_count==0 ||
       target<0 || target>=receipt.world_size ||
       receipt.transcript_binding==Digest{} ||
       context.world_size!=receipt.world_size ||
       context.row_commitments.size()!=static_cast<size_t>(receipt.world_size) ||
       compute_reference_vss_transcript_binding(
           receipt.dealer,receipt.threshold,
           receipt.element_count,context)!=receipt.transcript_binding ||
       points.size()<static_cast<size_t>(receipt.threshold+1) ||
       points.size()>static_cast<size_t>(receipt.world_size-1))
        return false;
    std::vector<bool> seen(static_cast<size_t>(receipt.world_size),false);
    for(const auto& p:points){
        if(p.helper<0 || p.helper>=receipt.world_size ||
           p.helper==target || p.target!=target ||
           seen[static_cast<size_t>(p.helper)] ||
           p.transcript_binding!=receipt.transcript_binding ||
           p.helper_row_commitment!=
               context.row_commitments[static_cast<size_t>(p.helper)] ||
           p.values.size()!=receipt.element_count)return false;
        seen[static_cast<size_t>(p.helper)]=true;
    }
    const size_t threshold_plus_one=
        static_cast<size_t>(receipt.threshold+1);
    std::vector<F> output;
    output.reserve(receipt.element_count);
    for(size_t element=0;element<receipt.element_count;++element){
        const F restored=interpolation(
            points,threshold_plus_one,element,F(0));
        // Additional rows check consistent evaluations at their
        // original helper coordinates; this detects deviations but
        // does not assign blame or correct arbitrary helper values.
        for(size_t i=threshold_plus_one;i<points.size();++i){
            if(interpolation(points,threshold_plus_one,element,
                             F(points[i].helper+1))!=points[i].values[element])
                return false;
        }
        output.push_back(restored);
    }
    *result=std::move(output);
    return true;
}
} // namespace pvia
