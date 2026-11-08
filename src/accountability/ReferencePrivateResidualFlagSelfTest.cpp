#include "ReferencePrivateResidualFlagSelfTest.hpp"
#include "ReferencePrivateResidualFlag.hpp"
#include "ReferencePrivateOwnerSelection.hpp"
#include "AuthenticatedMpcExchange.hpp"
#include "ExperimentMetrics.hpp"
#include "PVIA.hpp"

#include <mpi.h>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace pvia {
bool run_reference_private_residual_flag_selftest(
    int rank,int world_size) {
    if(rank<0 || rank>=world_size ||
       world_size<4 || world_size>16)return false;
    const char* fixture=std::getenv("PVIA_P105_TEST_RESIDUAL_POSITION");
    const std::string mode=rank==0 && fixture
        ? std::string(fixture) : "other-party";
    if(rank==0 && mode!="first" && mode!="middle" &&
       mode!="last" && mode!="none")return false;
    const u64 sid=Runtime::instance().session_id();
    constexpr CheckpointId checkpoint=0x5056313035524553ULL;
    AuthenticatedMpcExchange exchange(rank,world_size);
    if(!exchange.production_authenticated_ready() || !sid)return false;
    ReferenceShamirMpc mpc(rank,world_size,(world_size-1)/3);
    if(!mpc.SetAuthenticatedTransport(&exchange,sid,checkpoint))
        return false;
    const ExperimentMetricsSnapshot before=experiment_metrics_snapshot();
    // Only the owner sees its test residuals before sharing. The field
    // element in each position deliberately exercises real, imaginary
    // and mixed coordinates in the quadratic extension.
    std::vector<F> native_dealer_values;
    if(rank==0) {
        native_dealer_values.assign(3,F(0));
        if(mode=="first") native_dealer_values[0]=F(7,4);
        if(mode=="middle") native_dealer_values[1]=F(0,9);
        if(mode=="last") native_dealer_values[2]=F(11,0);
    }
    std::vector<F> residual_shares;
    if(!mpc.ShareVectorFromDealerKnownSize(
           0,native_dealer_values,3,&residual_shares) ||
       residual_shares.size()!=3)return false;

    std::vector<F> private_nonzero_flags;
    uint64_t flag_multiplications=0;
    if(!derive_reference_private_nonzero_flags(
        mpc,residual_shares,&private_nonzero_flags,
        &flag_multiplications) ||
       private_nonzero_flags.size()!=3 ||
       flag_multiplications==0)return false;
    const std::vector<uint32_t> owners={0,0,0};
    ReferencePrivateOwnerSelectionResult selection;
    const bool accepted=select_reference_private_fault_owner(
        mpc,private_nonzero_flags,owners,sid,checkpoint,&selection);
    const bool with_fault=accepted && selection.available &&
        selection.found && selection.attributed_party==0 &&
        selection.circuit_binding!=Digest{} &&
        selection.multiplication_count==7;
    const bool no_fault=accepted && selection.available &&
        !selection.found && selection.circuit_binding!=Digest{} &&
        selection.multiplication_count==7;
    const bool expected=rank==0
        ? (mode=="none" ? no_fault : with_fault)
        : (with_fault || no_fault);
    const ExperimentMetricsSnapshot after=experiment_metrics_snapshot();
    const uint64_t local_traffic[4]={
        after.authenticated_envelope_sent_bytes-
            before.authenticated_envelope_sent_bytes,
        after.authenticated_envelope_sent_messages-
            before.authenticated_envelope_sent_messages,
        after.protocol_control_sent_bytes-
            before.protocol_control_sent_bytes,
        after.protocol_control_sent_messages-
            before.protocol_control_sent_messages};
    uint64_t traffic[4]={};
    MPI_Reduce(local_traffic,traffic,4,MPI_UINT64_T,
               MPI_SUM,0,MPI_COMM_WORLD);
    int local_ok=expected?1:0;
    int all_ok=0;
    MPI_Allreduce(&local_ok,&all_ok,1,MPI_INT,
                  MPI_MIN,MPI_COMM_WORLD);
    if(rank==0) {
        std::cout<<"PVIA_PRIVATE_RESIDUAL_FLAG"
                 <<" result="<<(all_ok?"PASS":"FAIL")
                 <<" public_owner="<<(mode=="none"?"NONE":"0")
                 <<" candidates=3"
                 <<" flag_multiplications="<<flag_multiplications
                 <<" selector_multiplications=7"
                 <<" auth_bytes="<<traffic[0]
                 <<" auth_messages="<<traffic[1]
                 <<" control_bytes="<<traffic[2]
                 <<" control_messages="<<traffic[3]
                 <<" backend=REFERENCE_PASSIVE_SHAMIR"
                 <<" residual_provenance=TEST_DEALER_INPUT"
                 <<" native_Rq_binding=NOT_INTEGRATED"
                 <<" private_location_claim=NOT_ESTABLISHED"
                 <<std::endl;
    }
    return all_ok!=0;
}
} // namespace pvia
