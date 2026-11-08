#include "ReferencePrivateOwnerSelectionSelfTest.hpp"
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
bool run_reference_private_owner_selection_selftest(int rank,int world_size) {
    if(rank<0 || rank>=world_size || world_size<4 || world_size>16)
        return false;
    const size_t per_owner=3;
    const size_t count=static_cast<size_t>(world_size)*per_owner;
    const char* fixture=std::getenv("PVIA_P105_TEST_PRIVATE_POSITION");
    const std::string mode=rank==0 && fixture
        ? std::string(fixture) : "not-selected";
    const bool malformed=mode=="malformed";
    const size_t local_index=mode=="middle" ? 1 :
        mode=="last" ? 2 : 0;
    if(rank==0 && mode!="first" && mode!="middle" &&
       mode!="last" && mode!="malformed" &&
       mode!="owner1" && mode!="two_owners")return false;
    // Test-only public fixture: rank 1 is fed an independently shared
    // nonzero flag, permitting cross-owner ordering to be checked.
    // This variable is not a branch in the MPC selection circuit.
    const char* second_flag_env=
        std::getenv("PVIA_P105_TEST_FIXED_RANK1_BIT");
    const bool rank1_test_bit=second_flag_env &&
        std::string(second_flag_env)=="1";
    const u64 sid=Runtime::instance().session_id();
    const CheckpointId checkpoint=0x50563130354f534cULL;
    AuthenticatedMpcExchange exchange(rank,world_size);
    if(!exchange.production_authenticated_ready() || !sid)return false;
    ReferenceShamirMpc mpc(rank,world_size,(world_size-1)/3);
    if(!mpc.SetAuthenticatedTransport(&exchange,sid,checkpoint))
        return false;
    const ExperimentMetricsSnapshot before=experiment_metrics_snapshot();
    std::vector<F> indicators;
    indicators.reserve(count);
    std::vector<uint32_t> owners;
    owners.reserve(count);
    for(int dealer=0;dealer<world_size;++dealer) {
        std::vector<F> dealer_plaintext;
        if(dealer==rank) {
            dealer_plaintext.assign(per_owner,F(0));
            if(rank==0 && mode!="owner1")
                dealer_plaintext[local_index]=malformed?F(2):F(1);
            if(rank==1 && rank1_test_bit)
                dealer_plaintext[0]=F(1);
        }
        std::vector<F> shares;
        if(!mpc.ShareVectorFromDealerKnownSize(
             dealer,dealer_plaintext,per_owner,&shares) ||
           shares.size()!=per_owner)
            return false;
        indicators.insert(indicators.end(),shares.begin(),shares.end());
        for(size_t i=0;i<per_owner;++i)
            owners.push_back(static_cast<uint32_t>(dealer));
    }
    ReferencePrivateOwnerSelectionResult selection;
    const bool accepted=select_reference_private_fault_owner(
        mpc,indicators,owners,sid,checkpoint,&selection);
    const bool owner_ok=selection.attributed_party==0 ||
        (rank1_test_bit && selection.attributed_party==1);
    const bool positive=accepted && selection.available &&
        selection.found &&
        (rank==0
            ? selection.attributed_party==
                static_cast<uint32_t>(mode=="owner1"?1:0)
            : owner_ok) &&
        selection.multiplication_count==3*count-2 &&
        selection.circuit_binding!=Digest{};
    const bool properly_refused=!accepted && !selection.available;
    // The private fixture position and its malformed flag are supplied
    // ONLY to rank zero. Other parties cannot condition on that secret.
    // Rank zero checks the expected case, all others check either coherent
    // success or coherent rejection, then every rank agrees via Allreduce.
    const bool expected=rank==0
        ? (malformed ? properly_refused : positive)
        : (positive || properly_refused);
    const ExperimentMetricsSnapshot after=experiment_metrics_snapshot();
    const uint64_t local_metrics[4]={
        after.authenticated_envelope_sent_bytes-
            before.authenticated_envelope_sent_bytes,
        after.authenticated_envelope_sent_messages-
            before.authenticated_envelope_sent_messages,
        after.protocol_control_sent_bytes-
            before.protocol_control_sent_bytes,
        after.protocol_control_sent_messages-
            before.protocol_control_sent_messages};
    uint64_t all_metrics[4]={};
    MPI_Reduce(local_metrics,all_metrics,4,MPI_UINT64_T,
               MPI_SUM,0,MPI_COMM_WORLD);
    int local_ok=expected?1:0;
    int global_ok=0;
    MPI_Allreduce(&local_ok,&global_ok,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
    if(rank==0)
        std::cout << "PVIA_PRIVATE_OWNER_SELECTOR"
                  << " result=" << (global_ok?"PASS":"FAIL")
                  << " public_owner=" << (malformed?"REJECTED":
                                         mode=="owner1"?"1":"0")
                  << " operations=" << count
                  << " multiplications=" << 3*count-2
                  << " output_fields=" << (malformed?0:1)
                  << " auth_bytes=" << all_metrics[0]
                  << " auth_messages=" << all_metrics[1]
                  << " control_bytes=" << all_metrics[2]
                  << " control_messages=" << all_metrics[3]
                  << " backend=REFERENCE_PASSIVE_SHAMIR"
                  << " hidden_q_proof=NOT_ESTABLISHED"
                  << std::endl;
    return global_ok!=0;
}
} // namespace pvia
