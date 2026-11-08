#include "ReferenceDistributedRowRegistrationSelfTest.hpp"
#include "ReferenceBivariateVss.hpp"
#include "ReferenceVssDealerFromRows.hpp"
#include "RegistrationConsistencyProof.hpp"
#include "RegistrationPrivateTestVectorExport.hpp"
#include "FoldResidualComputationBackend.hpp"

#include <mpi.h>
#include <cstdlib>
#include <iostream>
#include <vector>

namespace pvia {
bool run_reference_distributed_row_registration_selftest(
    int rank,int world_size) {
    if(world_size<4 || rank<0 || rank>=world_size)return false;
    const int threshold=(world_size-1)/3;
    ReferenceBivariateVss vss(rank,world_size,threshold);
    if(!vss.valid())return false;
    constexpr int dealer=0;
    constexpr size_t state_size=8;
    const F challenge(7,3);
    std::vector<F> native_state;
    std::vector<F> actual_output;
    std::vector<F> plaintext;
    int shape_ok=1;
    if(rank==dealer) {
        for(size_t i=0;i<state_size;++i)
            native_state.emplace_back(
                static_cast<long long>(300+i),
                static_cast<long long>(900+2*i));
        if(!recompute_fold_rs_output(
                native_state,challenge,&actual_output))shape_ok=0;
        if(shape_ok) {
            plaintext=native_state;
            plaintext.insert(plaintext.end(),
                             actual_output.begin(),actual_output.end());
        }
    }
    int output_size=rank==dealer ?
        static_cast<int>(actual_output.size()):0;
    MPI_Bcast(&shape_ok,1,MPI_INT,dealer,MPI_COMM_WORLD);
    MPI_Bcast(&output_size,1,MPI_INT,dealer,MPI_COMM_WORLD);
    if(!shape_ok || output_size<=0)return false;

    // Request ONLY a local witness per rank: there is no dealer
    // polynomial witness object on the prover-side aggregation path.
    std::vector<F> shares;
    ReferenceVssReceipt receipt;
    ReferenceVssLocalWitness local;
    const bool shared=vss.ShareVectorFromDealerWithLocalWitness(
        dealer,plaintext,&shares,&receipt,&local);
    const size_t elements=state_size+static_cast<size_t>(output_size);
    const size_t words_per_row=elements*static_cast<size_t>(threshold+1)*2;
    int good=shared && receipt.available && receipt.consistent &&
        receipt.element_count==elements &&
        shares.size()==elements &&
        validate_reference_vss_local_witness(local) &&
        local.local_row_words.size()==words_per_row ? 1:0;
    int ready=0;
    MPI_Allreduce(&good,&ready,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
    if(!ready)return false;

    // In THIS EXPLICIT PRIVATE SELFTEST only: collect private row
    // coefficients. This is not private communication or public data.
    std::vector<u64> rows(static_cast<size_t>(world_size)*words_per_row);
    MPI_Allgather(local.local_row_words.data(),
                  static_cast<int>(words_per_row),MPI_UINT64_T,
                  rows.data(),static_cast<int>(words_per_row),
                  MPI_UINT64_T,MPI_COMM_WORLD);

    int result_ok=1;
    if(rank==dealer) {
        std::vector<ReferenceVssLocalWitness> helpers;
        // Exclude the dealer: the witness reconstructed below
        // derives solely from the other participant-held rows.
        for(int participant=1;participant<world_size;++participant) {
            ReferenceVssLocalWitness helper=local;
            helper.participant=participant;
            helper.local_row_commitment=
                local.transcript_context.row_commitments[
                    static_cast<size_t>(participant)];
            auto begin=rows.begin()+
                static_cast<size_t>(participant)*words_per_row;
            helper.local_row_words.assign(
                begin,begin+words_per_row);
            helpers.push_back(std::move(helper));
        }
        ReferenceVssDealerWitness reconstructed;
        const bool assembled=reconstruct_reference_vss_dealer_from_rows(
            receipt,helpers,&reconstructed);
        result_ok=assembled ? 1:0;
        if(result_ok) {
            std::vector<ReferenceVssLocalWitness> minimal(
                helpers.begin(),helpers.begin()+threshold+1);
            ReferenceVssDealerWitness exact;
            result_ok=
                reconstruct_reference_vss_dealer_from_rows(
                    receipt,minimal,&exact) &&
                exact.coefficient_words==reconstructed.coefficient_words;
        }
        if(result_ok) {
            RegistrationConsistencyWitness witness;
            // Do not feed the original dealer plaintext into the
            // proving witness. Derive native input from recovered
            // bivariate polynomial constants C[0,0].
            const size_t stride=
                static_cast<size_t>(threshold+1)*
                static_cast<size_t>(threshold+1)*2;
            for(size_t element=0;element<elements;++element) {
                const size_t offset=element*stride;
                F field(
                    static_cast<long long>(
                        reconstructed.coefficient_words[offset]),
                    static_cast<long long>(
                        reconstructed.coefficient_words[offset+1]));
                if(element<state_size)
                    witness.state_values.push_back(field);
                else
                    witness.actual_output.push_back(field);
            }
            witness.public_challenge=challenge;
            witness.sharing_witness_words=
                encode_reference_vss_dealer_witness(reconstructed);
            RegistrationConsistencyStatement statement;
            statement.sid=0x50564452574e5354ULL; // PVDRWNST
            statement.checkpoint=0x505644525743484bULL;
            statement.ref=OperationRef{0,0x50564452574f5052ULL};
            statement.kernel=AuditRelationKernel::FOLD_RS;
            statement.state_element_count=witness.state_values.size();
            statement.output_element_count=witness.actual_output.size();
            statement.public_state_digest=
                hash_field_vector(witness.state_values);
            statement.public_actual_digest=
                hash_field_vector(witness.actual_output);
            statement.public_challenge_binding=
                hash_field_vector({challenge});
            statement.native_context.native_state_id=
                0x5056445257535441ULL;
            statement.native_context.authentication_scheme_id=
                0x5056445257415554ULL;
            statement.native_context.authentication_binding=
                hash_words({statement.sid,0x5056445241555448ULL});
            statement.native_context.predecessor_root=
                hash_words({statement.sid,0x5056445250524544ULL});
            statement.native_context.checkpoint_root=
                hash_words({statement.checkpoint,0x5056445243484b52ULL});
            statement.operation_statement_binding=hash_words({
                statement.sid,statement.checkpoint,
                statement.ref.owner,statement.ref.object_id});
            statement.sharing_transcript_binding=receipt.transcript_binding;
            statement.statement_binding=
                compute_registration_consistency_statement_binding(statement);
            result_ok=validate_registration_consistency_statement(statement) &&
                evaluate_reference_registration_consistency_relation(
                    statement,witness) &&
                witness.state_values==native_state &&
                witness.actual_output==actual_output ? 1:0;
            if(result_ok) {
                auto bad=witness;
                bad.sharing_witness_words.back()^=1;
                result_ok=
                    !evaluate_reference_registration_consistency_relation(
                        statement,bad);
            }
            if(result_ok) {
                ReferenceVssDealerWitness bad;
                auto changed=helpers;
                changed[0].local_row_words[0]^=1;
                result_ok=!reconstruct_reference_vss_dealer_from_rows(
                    receipt,changed,&bad);
                changed=helpers;
                changed[1]=changed[0];
                result_ok=result_ok &&
                    !reconstruct_reference_vss_dealer_from_rows(
                        receipt,changed,&bad);
                changed=helpers;
                changed.resize(static_cast<size_t>(threshold));
                result_ok=result_ok &&
                    !reconstruct_reference_vss_dealer_from_rows(
                        receipt,changed,&bad);
                auto wrong=receipt;
                wrong.transcript_binding.bytes[0]^=1;
                result_ok=result_ok &&
                    !reconstruct_reference_vss_dealer_from_rows(
                        wrong,helpers,&bad);
            }
            const char* path=
                std::getenv("PVIA_DISTRIBUTED_ROW_PRIVATE_EXPORT");
            if(result_ok && path && *path)
                result_ok=write_registration_private_test_vector_once(
                    path,statement,witness);
        }
    }
    MPI_Bcast(&result_ok,1,MPI_INT,dealer,MPI_COMM_WORLD);
    if(rank==dealer) {
        std::cout << "PVIA_DISTRIBUTED_ROW_SP1: "
                  << (result_ok ? "PASS" : "FAIL")
                  << " helper_only=TRUE"
                  << " source=PRIVATE_MPI_LOCAL_ROWS"
                  << " relation=VSS_NATIVE"
                  << " privacy=NOT_ATTESTED" << std::endl;
    }
    return result_ok!=0;
}
} // namespace pvia
