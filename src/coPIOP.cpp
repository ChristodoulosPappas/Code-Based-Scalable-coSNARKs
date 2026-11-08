#pragma once
#include "coPIOP.h"
#include "coSumcheck.h"
#include "sparse_eval.hpp"
#include "coPCS_utils.h"
#include "MPI_utils.hpp"
#include "Fiat_Shamir.h"
#include "coSumcheck_MPI.h"
#include "coPCS.h"
#include "Distributed_Sumcheck.h"
#include "timer.hpp"
#include "accountability/PVIA.hpp"
#include "accountability/InitialValidityGate.hpp"
#include "accountability/PublicDirectValidation.hpp"
#include "accountability/AccountableAggregation.hpp"
#include <cstdlib>
#include <cstring>
int com_rounds = 0;
// R1CS matrixes
vector<vector<pair<int, int>>> A,B,C;
// Transposed R1CS matrixes
vector<vector<pair<int,int>>> tA,tB,tC;
extern vector<vector<pair<int,int>>> pA,pB,pC;
int logm,logn;
bool bit_method = false;
int index_rate = 4;
bool data_parallel = false;
extern bool isLAN;
extern double ps_plain; 
double cm = 0.0;
int gate_ctr = 0;
timer pt,pt_cp,temp_pc;
timer_cpu pt_cpu;
extern timer sch_com;

timer vt;


void transpose_R1CS_matrixes(){
    tA.resize(1<<logn);tB.resize(1<<logn);tC.resize(1<<logn);


    for(int i = 0; i < A.size(); i++){
        for(int j = 0; j < A[i].size(); j++){
            if(tA.size() <= A[i][j].first){
                printf("Error %d,%d\n",tA.size(),A[i][j].first);
                exit(-1);
            }
            tA[A[i][j].first].push_back(make_pair(A[i][j].first,A[i][j].second));
        } 
    }
    for(int i = 0; i < B.size(); i++){
        for(int j = 0; j < B[i].size(); j++) tB[B[i][j].first].push_back(make_pair(B[i][j].first,B[i][j].second));
    }

    for(int i = 0; i < C.size(); i++){
        for(int j = 0; j < C[i].size(); j++) tC[C[i][j].first].push_back(make_pair(C[i][j].first,C[i][j].second));
    }

    /*
    for(int i = 0; i < tA.size(); i++){
        if(tA[i].size() > 1 || tB[i].size() > 1 || tC[i].size() > 1){
            printf("> Error\n");
            exit(-1);
        }
    }
    */
    
}

gate add_input(){
    gate gt;
    gt.id = gate_ctr++;
    gt.id_left.push_back(-1);
    gt.id_right = -1;
    gt.type = 0;
    return gt;
}


gate add_mul(int size, int add_ctr){
    gate gt;
    vector<int> wires;
    wires.push_back((unsigned int)rand()%size);
    for(int i = 0; i < add_ctr-1; i++){
        while(true){
            bool is_dublicate = false;
            unsigned int num = (unsigned int)rand()%size;
            for(int j = 0; j < wires.size(); j++){
                if(num == wires[j]){
                    is_dublicate = true;
                    break;
                }
            }
            if(!is_dublicate){
                wires.push_back(num);
                break;
            }
        }
    }
    
    gt.id = gate_ctr++;
    gt.id_left = wires;
    gt.id_right = (unsigned int)rand()%size;
    gt.type = 2;
    return gt;
}

// Dummy computation represeting multiplication tree
// 0: Default, multree
// 1: Random circuit
void generate_R1CS_matrixes(size_t size, int type){
    int n = size;
    int m = 0;
    int counter = 0;
    if(type == 0){
        A.resize(size); B.resize(size); C.resize(size);
        for(int j = 0; j < (int)log2(size); j++){
            for(int i = 0; i < size/(1<<(j+1)); i++){
                A[counter].resize(1);B[counter].resize(1);C[counter].resize(1);
                A[counter][0] = {2*i + m,i+m/2};
                B[counter][0] = {2*i+1+m,i+m/2};
                C[counter][0] = {n+i,i+m/2};
                counter++;
            }
            m+=size/(1<<(j));
            n+=size/(1<<(j+1));
        }
        logm = (int)log2(size);
        logn = (int)log2(size)+1;    
    }else{
        vector<gate> gates;
        for(int i = 0; i < size/16; i++) gates.push_back(add_input());
        int add_ctr = 0;
        int additions = 0;
        srand(42);
        for(int i = size/16; i < size; i++){
            if(rand()%2 == 0){
                add_ctr++;
                additions++;
            }else{
                gates.push_back(add_mul(gates.size(),add_ctr));
                add_ctr = 0;
            }
        }
        if(add_ctr != 0) gates.push_back(add_mul(gates.size(), add_ctr));
        
        A.resize(gates.size());B.resize(gates.size());C.resize(gates.size());
        for(int i = size/16; i  < A.size(); i++){
            A[i].resize(gates[i].id_left.size());B[i].resize(1);C[i].resize(1);
            for(int j = 0; j < A[i].size(); j++){
                A[i][j] = {gates[i].id_left[j],gates[i].id-size/16};
            }
            B[i][0] = {gates[i].id_right,gates[i].id-size/16};
            C[i][0] = {gates[i].id,gates[i].id-size/16};
        }
        logm = (int)log2(next_pow2(gates.size()-size/16));
        logn = (int)log2(next_pow2(gates.size()));    
    
    }
    transpose_R1CS_matrixes();
}




void reduce_R1CS_matrixes(size_t size, vector<F> r, vector<F> &RA, vector<F> &RB, vector<F> &RC){
    vector<F> beta;
    precompute_beta(r,beta);
    RA.resize(1<<logn,F(0));RB.resize(1<<logn,F(0));RC.resize(1<<logn,F(0));
    for(int i = 0; i < A.size(); i++){
        for(int j = 0; j < A[i].size(); j++){
            RA[A[i][j].first] += beta[A[i][j].second];
        }
        for(int j = 0; j < B[i].size(); j++){
            RB[B[i][j].first] += beta[B[i][j].second];
        }
        for(int j = 0; j < C[i].size(); j++){
            RC[C[i][j].first] += beta[C[i][j].second];
        }
    }
}

void secret_share_proving_data(vector<F> &witness, 
                               vector<vector<F>> &tr, 
                               vector<vector<F>> &W, 
                               vector<vector<vector<F>>> &Tr, int k, int _k, int N){
    W.resize(witness.size()/k);
    Tr.resize(3);
    int ctr = 0;
    for(int i = 0; i < W.size(); i++){
        W[i].resize(_k);
        for(int j = 0; j < k; j++){
            W[i][j] = witness[ctr++];
        }
        for(int j = k; j < _k; j++){
            W[i][j] = random();
        }
        fft(W[i],(int)log2(_k),true);
        W[i].resize(N,0);
        fft(W[i],(int)log2(N),false);
    } 
    for(int i = 0; i < Tr.size(); i++){
        Tr[i].resize(tr[i].size()/k);
        ctr = 0;
        for(int j = 0; j < Tr[i].size(); j++){
            Tr[i][j].resize(_k);
            for(int l = 0; l < k; l++){
                Tr[i][j][l] = tr[i][ctr++];
            }
            for(int l = 0; l < _k; l++){
                Tr[i][j][l] = random();
            }
            fft(Tr[i][j],(int)log2(_k),true);
            Tr[i][j].resize(N,0);
            fft(Tr[i][j],(int)log2(N),false);
        }
    }
}



vector<pair<F,vector<F>>> prove_phase1( vector<F> vL, 
                                        vector<F> vR, 
                                        vector<F> vO, 
                                        vector<F> rL,
                                        vector<F> rR,
                                        vector<F> rO,
                                        vector<F> R1,
                                        vector<F> R2, 
                                        int N, int _k, int k,  double &ps){

    
    pt_cp.start();
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    

    vector<F> _r1,_r2;
    
    for(int i = 0; i < (int)log2(vL.size()); i++)_r1.push_back(hash_to_field({0}));
    for(int i = 0; i < (int)log2(k); i++)_r2.push_back(hash_to_field({0}));
    
    
    vector<F> beta1,beta2;
    //precompute_beta(_r1,beta1);
    precompute_beta(_r2,beta2);
    
    F y = 0;
    for(int i = 0; i < rL.size(); i++){
        y += _beta(i,_r1)*(rL[i]*rR[i] - rO[i]);
    }
    vector<u64> buff_u64(2);
    std::array<u64, pvia::META_WORDS> phase1_publish_meta{};
    pvia::RecordId phase1_send_record = 0;
    if (pvia::Runtime::instance().enabled()) {
        auto& rt = pvia::Runtime::instance();
        std::vector<pvia::OperationRef> predecessors;
        const auto predecessor = rt.latest_operation_ref(pvia::Phase::INIT);
        if (predecessor.object_id != 0)
            predecessors.push_back(predecessor);

        const pvia::StateId source_state = rt.import_state_slices(
            "phase1_initial_relation_claim_input",
            pvia::Phase::INIT,
            std::vector<pvia::FieldStateSegment>{
                {&rL, 0, rL.size()},
                {&rR, 0, rR.size()},
                {&rO, 0, rO.size()}});

        const pvia::RecordId derive_record = rt.register_vector_operation(
            pvia::Phase::INIT, 2, pvia::Obligation::DERIVE,
            vector<F>{y}, predecessors);
        if (derive_record == 0 || source_state == 0) {
            if (rank == 0)
                printf("[PVIA][phase1-claim] unable to bind local derivation\n");
            std::exit(15);
        }
        rt.bind_state_dependencies(
            derive_record, std::vector<pvia::StateId>{source_state});
        vector<F> public_aux = _r1;
        public_aux.insert(public_aux.end(), _r2.begin(), _r2.end());
        rt.bind_public_field_aux(
            derive_record, pvia::AuditPublicAuxKind::GENERIC_FIELDS,
            public_aux);
        rt.activate_vector(derive_record, vector<F>{y});

        phase1_send_record = rt.prepare_followup_vector(
            pvia::Obligation::SEND, vector<F>{y});
        if (phase1_send_record == 0) {
            if (rank == 0)
                printf("[PVIA][phase1-claim] unable to bind local transfer\n");
            std::exit(15);
        }
        rt.activate_vector(phase1_send_record, vector<F>{y});
    }

    buff_u64 = {y.real, y.img};
    pt_cp.end();
    com_rounds++;
    if(rank == 0){
        vector<F> Y(N);
        Y[0] = y;
        if (pvia::Runtime::instance().enabled())
            pvia::Runtime::instance().consume_pending();
        for(int i = 1; i < N; i++){
            std::array<u64, pvia::META_WORDS> remote_meta{};
            if (pvia::Runtime::instance().enabled()) {
                MPI_Recv(
                    remote_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                    i, pvia::META_TAG, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            }
            MPI_Recv(buff_u64.data(),2,MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            if (pvia::Runtime::instance().enabled()) {
                pvia::Runtime::instance().observe_remote_meta(
                    i, remote_meta, buff_u64);
            }
            Y[i].real = buff_u64[0];
            Y[i].img = buff_u64[1];
        }
        pt_cp.start();
        fft(Y,(int)log2(N),true);
        F mul = F(1);
        F omega = getRootOfUnity(1+(int)log2(N)).inv();
        for(int i = 0; i < Y.size(); i++){
            Y[i] = mul*Y[i];
            mul = omega*mul;
        }
        fft(Y,(int)log2(N),false);
        y = 0;
        for(int i = 0; i < k; i++){
            y += beta2[i]*Y[i*N/_k];
        }
        buff_u64 = {y.real,y.img};
        if (pvia::Runtime::instance().enabled()) {
            auto& rt = pvia::Runtime::instance();
            const auto contributors = rt.checkpoint_operations(
                pvia::Phase::INIT, 2, pvia::Obligation::SEND);
            const pvia::RecordId aggregate_record =
                rt.register_vector_operation(
                    pvia::Phase::INIT, 2, pvia::Obligation::AGGREGATE,
                    vector<F>{y}, contributors);
            if (aggregate_record == 0) {
                printf("[PVIA][phase1-claim] unable to bind aggregate\n");
                std::exit(15);
            }
            vector<F> aggregation_aux = beta2;
            aggregation_aux.push_back(F(N));
            aggregation_aux.push_back(F(k));
            aggregation_aux.push_back(F(_k));
            rt.bind_public_field_aux(
                aggregate_record,
                pvia::AuditPublicAuxKind::AGGREGATION_WEIGHTS,
                aggregation_aux);
            rt.bind_relation_kernel(
                aggregate_record,
                pvia::AuditRelationKernel::AGGREGATE_WEIGHTED);
            rt.activate_vector(aggregate_record, vector<F>{y});
            const pvia::RecordId publish_record =
                rt.prepare_followup_vector(
                    pvia::Obligation::PUBLISH, vector<F>{y});
            if (publish_record == 0) {
                printf("[PVIA][phase1-claim] unable to bind publication\n");
                std::exit(15);
            }
            rt.bind_relation_kernel(
                publish_record,
                pvia::AuditRelationKernel::PUBLISH_AGGREGATE);
            rt.activate_vector(publish_record, vector<F>{y});
            phase1_publish_meta = rt.make_pending_meta(buff_u64, false);
        }
        pt_cp.end();
    
    }else{
        buff_u64 = {y.real,y.img};
        cm += 8*buff_u64.size()/1024.0;
        if (pvia::Runtime::instance().enabled()) {
            auto& rt = pvia::Runtime::instance();
            auto transfer_meta = rt.make_pending_meta(buff_u64, false);
            if (!rt.seal_transfer_meta(transfer_meta, buff_u64)) {
                std::exit(15);
            }
            rt.observe_outgoing_transfer(transfer_meta, buff_u64);
            rt.observe_local_payload(buff_u64);
            MPI_Send(
                transfer_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                0, pvia::META_TAG, MPI_COMM_WORLD);
        }
        MPI_Send(buff_u64.data(),2,MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        if (pvia::Runtime::instance().enabled())
            pvia::Runtime::instance().consume_pending();
    }
    if(rank == 0) cm += (N-1)*8*buff_u64.size()/1024.0;
    if (pvia::Runtime::instance().enabled()) {
        auto& rt = pvia::Runtime::instance();
        if (!rt.pre_release_gate(
                "phase1_relation_claim", pvia::Phase::INIT, 2)) {
            rt.handle_global_failure(
                "phase1_relation_claim", pvia::Phase::INIT, 2);
            std::exit(15);
        }
    }
    com_rounds++;
    MPI_Bcast(buff_u64.data(),2,MPI_UINT64_T,0,MPI_COMM_WORLD);
    if (pvia::Runtime::instance().enabled()) {
        pvia::publish_rank0_aggregate_meta(
            phase1_publish_meta, buff_u64, rank);
        pvia::Runtime::instance().consume_pending();
    }
    
    pt_cp.start();
    
    y.real = buff_u64[0];y.img = buff_u64[1];
    vector<F> r1 = _r1,r2 = _r2;
    r1.push_back(hash_to_field({0}));
    vL.resize(2*vL.size(),F(0));
    vR.resize(2*vL.size(),F(0));
    vO.resize(2*vL.size(),F(0));
    for(int i = vL.size()/2; i < vL.size()/2+rL.size(); i++){
        vL[i] = rL[i-vL.size()/2];
        vR[i] = rR[i-vL.size()/2];
        vO[i] = rO[i-vL.size()/2];
    }
    
    y = r1[r1.size()-1]*y;
    
    vector<F> r = r1;r.insert(r.begin(),r2.begin(),r2.end());
    pt_cp.end();
    
    return _zero_check_sumcheck(y,vL,vR,vO,R1,R2,r,N,_k,k,ps);    
}

void compute_beta_shares(vector<F> &shares, vector<F> r, int k, int N, int _k){
    shares.clear();
    vector<F> r1,r2,b1;
    for(int i = 0; i < (int)log2(k); i++) r1.push_back(r[i]);
    for(int i = (int)log2(k); i < r.size(); i++) r2.push_back(r[i]);
    
    precompute_beta(r1,b1);precompute_beta(r2,shares);
    vector<F> buff(_k,0);
    
    for(int i = 0; i < k; i++) buff[i] = b1[i];
    fft(buff,(int)log2(buff.size()),true);
    buff.resize(2*N,F(0));
    fft(buff,(int)log2(buff.size()),false);
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    for(int i = 0; i < shares.size(); i++){
        shares[i] = buff[2*rank+1]*shares[i];
    }

}


static bool pvia_public_all_true(bool local_ok) {
    int local = local_ok ? 1 : 0;
    int global = 0;
    MPI_Allreduce(&local, &global, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    return global == 1;
}

static bool pvia_same_field_vector(const vector<F>& lhs, const vector<F>& rhs) {
    if (lhs.size() != rhs.size()) return false;
    for (size_t i = 0; i < lhs.size(); ++i)
        if (lhs[i] != rhs[i]) return false;
    return true;
}

static void pvia_append_digest_words(
    const pvia::Digest& digest,
    vector<u64>& words) {
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words.push_back(word);
    }
}

static bool pvia_validate_public_vector(
    pvia::PublicDirectValidationKind kind,
    const vector<F>& expected,
    const vector<F>& actual,
    const vector<F>& context_fields,
    const vector<u64>& context_words) {
    if (!pvia::Runtime::instance().enabled())
        return true;
    pvia::PublicDirectValidationResult result;
    const bool executed = pvia::validate_public_direct_vector(
        pvia::Runtime::instance(), kind, expected, actual,
        context_fields, context_words, &result);
    return executed && result.collective_valid;
}

static bool pvia_check_public_r1cs_reduction(
    size_t size, const vector<F>& r,
    const vector<F>& RA, const vector<F>& RB, const vector<F>& RC, int N,
    const pvia::Digest& relation_binding) {
    (void)size;
    vector<F> r1, r2, beta1, beta2;
    const int split = static_cast<int>(r.size()) - static_cast<int>(log2(N));
    if (split < 0) return pvia_public_all_true(false);
    for (int i = 0; i < split; ++i) r1.push_back(r[i]);
    for (int i = split; i < static_cast<int>(r.size()); ++i) r2.push_back(r[i]);
    precompute_beta(r1, beta1);
    precompute_beta(r2, beta2);

    const int local_columns = (1 << logn) / N;
    const int local_rows = (1 << logm) / N;
    bool local_ok = local_columns > 0 && local_rows > 0;
    local_ok = local_ok && RA.size() == static_cast<size_t>(local_columns);
    local_ok = local_ok && RB.size() == RA.size() && RC.size() == RA.size();
    vector<F> expected_RA(local_columns, F(0));
    vector<F> expected_RB(local_columns, F(0));
    vector<F> expected_RC(local_columns, F(0));

    auto accumulate = [&](const vector<vector<pair<int,int>>>& matrix, vector<F>& out) {
        for (const auto& row : matrix) {
            for (const auto& entry : row) {
                const int col = entry.first % local_columns;
                const int row_local = entry.second % local_rows;
                const int row_party = entry.second / local_rows;
                if (col < 0 || col >= local_columns ||
                    row_local < 0 || row_local >= static_cast<int>(beta1.size()) ||
                    row_party < 0 || row_party >= static_cast<int>(beta2.size())) {
                    local_ok = false;
                    continue;
                }
                out[col] += beta1[row_local] * beta2[row_party];
            }
        }
    };
    if (local_ok) {
        accumulate(pA, expected_RA);
        accumulate(pB, expected_RB);
        accumulate(pC, expected_RC);
    }
    local_ok = local_ok && pvia_same_field_vector(expected_RA, RA);
    local_ok = local_ok && pvia_same_field_vector(expected_RB, RB);
    local_ok = local_ok && pvia_same_field_vector(expected_RC, RC);
    if (!local_ok)
        return pvia_public_all_true(false);

    vector<F> expected;
    vector<F> actual;
    expected.reserve(expected_RA.size() + expected_RB.size() + expected_RC.size());
    actual.reserve(RA.size() + RB.size() + RC.size());
    expected.insert(expected.end(), expected_RA.begin(), expected_RA.end());
    expected.insert(expected.end(), expected_RB.begin(), expected_RB.end());
    expected.insert(expected.end(), expected_RC.begin(), expected_RC.end());
    actual.insert(actual.end(), RA.begin(), RA.end());
    actual.insert(actual.end(), RB.begin(), RB.end());
    actual.insert(actual.end(), RC.begin(), RC.end());

    if (relation_binding == pvia::Digest{})
        return pvia_public_all_true(false);
    vector<u64> context_words = {
        static_cast<u64>(size), static_cast<u64>(N),
        static_cast<u64>(logm), static_cast<u64>(logn),
        static_cast<u64>(local_columns), static_cast<u64>(local_rows)};
    // Initial validity already constructed a collective commitment to the
    // complete public R1CS relation.  Reuse that binding instead of
    // serializing and hashing pA/pB/pC again on the success path.
    pvia_append_digest_words(relation_binding, context_words);
    return pvia_validate_public_vector(
        pvia::PublicDirectValidationKind::R1CS_REDUCTION,
        expected, actual, r, context_words);
}

static bool pvia_check_public_raggr(
    const vector<F>& R_aggr,
    const vector<F>& RA, const vector<F>& RB, const vector<F>& RC,
    F a, F b, F c, F scale) {
    vector<F> expected(RA.size(), F(0));
    if (RA.size() != RB.size() || RA.size() != RC.size()) return false;
    for (size_t i = 0; i < RA.size(); ++i)
        expected[i] = scale * (a * RA[i] + b * RB[i] + c * RC[i]);
    vector<F> context_fields = {a, b, c, scale};
    context_fields.insert(context_fields.end(), RA.begin(), RA.end());
    context_fields.insert(context_fields.end(), RB.begin(), RB.end());
    context_fields.insert(context_fields.end(), RC.begin(), RC.end());
    const vector<u64> context_words = {
        static_cast<u64>(RA.size())};
    return pvia_validate_public_vector(
        pvia::PublicDirectValidationKind::R_AGGREGATION,
        expected, R_aggr, context_fields, context_words);
}

static bool pvia_check_public_beta_shares(
    const vector<F>& actual, const vector<F>& r,
    int k, int N, int _k, F scale) {
    vector<F> expected;
    compute_beta_shares(expected, r, k, N, _k);
    for (auto& value : expected) value = scale * value;
    expected.resize(4 * expected.size(), F(0));
    vector<F> context_fields = r;
    context_fields.push_back(scale);
    const vector<u64> context_words = {
        static_cast<u64>(k), static_cast<u64>(N),
        static_cast<u64>(_k), static_cast<u64>(expected.size())};
    return pvia_validate_public_vector(
        pvia::PublicDirectValidationKind::BETA_SHARES,
        expected, actual, context_fields, context_words);
}

static void pvia_fail_public_prescription(const char* name) {
    int rank = 0;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    if (rank == 0)
        printf("[PVIA][PublicDirect] WITHHOLD %s before coPIOP phase-2 Sumcheck\n", name);
    std::exit(15);
}

vector<pair<F,vector<F>>> prove_phase2(
                  vector<F> &w, 
                  vector<F> &r_w, 
                  vector<F> rL,
                  vector<F> rR,
                  vector<F> rO,
                  vector<F> &RA, 
                  vector<F> &RB, 
                  vector<F> &RC,
                  vector<F> &R1,
                  vector<F> &R2, 
                  vector<F> r,
                  F yL,F yR, F yO,
                  int N, int size,
                  int _k, int k, F &a, F &b, F &c,
                  const pvia::Digest& relation_binding, double &ps){

    
    RA.clear();RB.clear();RC.clear();
    
    vector<F> _r = r;_r.pop_back();

    pt_cp.start();
    _reduce_R1CS_matrixes(size, _r, RA, RB, RC, N);
    if (pvia::Runtime::instance().enabled() &&
        !pvia_check_public_r1cs_reduction(
            size, _r, RA, RB, RC, N, relation_binding))
        pvia_fail_public_prescription("copiop_public_r1cs_reduction");

    a = hash_to_field({0});
    b = hash_to_field({0}); c = hash_to_field({0});  
    
    // Initialize main inputs
    w.insert(w.end(),r_w.begin(),r_w.end());
    w.resize(next_pow2(w.size()),F(0));
    rL.resize(w.size(),F(0));
    for(int i = 0; i < rR.size(); i++) rL[i] = a*rL[i] + b*rR[i] + c*rO[i];    
    
    // Initialize secondary inputs
    vector<F> R_aggr(RA.size(),F(0));
    
    for(int i = 0; i < RA.size(); i++){
        R_aggr[i] = (F(1)- r[r.size()-1])*(a*RA[i] + b*RB[i] + c*RC[i]);
    }
    if (pvia::Runtime::instance().enabled() &&
        !pvia_check_public_raggr(
            R_aggr, RA, RB, RC, a, b, c, F(1)-r[r.size()-1]))
        pvia_fail_public_prescription("copiop_public_r_aggr");

    F i = (F(1)- r[r.size()-1]).inv();
    
    pt_cp.end();
    secret_share_vector(R_aggr, _k, k, N, "COPIOP_PUBLIC_SHARE_SEND");
    pt_cp.start();
    R_aggr.resize(2*R_aggr.size(),F(0));

    vector<F> beta_shares;
    
    compute_beta_shares(beta_shares, _r, k, N, _k);
    for(int i = 0; i < beta_shares.size(); i++){
        beta_shares[i] = r[r.size()-1]*beta_shares[i];
    }
    beta_shares.resize(4*beta_shares.size(),F(0));
    if (pvia::Runtime::instance().enabled() &&
        !pvia_check_public_beta_shares(
            beta_shares, _r, k, N, _k, r[r.size()-1]))
        pvia_fail_public_prescription("copiop_public_beta");
    pt_cp.end();

    vector<pair<F,vector<F>>> claim = _quadratic_batch_sumcheck(a*yL + b*yR + c*yO, w, R_aggr, rL, beta_shares, R1,R2,N, _k, k, ps);
    claim[1].first = (F(1)-claim[1].second[claim[1].second.size()-1]).inv()*i*claim[1].first;
    return claim;
}


void get_bits(vector<short> &buff, int idx1, int idx2){
    for(int i = 0; i < logm; i++){
        buff[i] = 0;
        if(idx1&1){
            buff[i] = 1;
        }
        idx1 = idx1>>1;
    }
    for(int i = logm; i < logm+logn; i++){
        buff[i] = 0;
        if(idx2&1){
            buff[i] = 1;
        }
        idx2 = idx2>>1;
    }

}

void prepare_matrix_data(vector<vector<pair<int, int>>> &M, vector<vector<int>> &idx, vector<vector<short>> &bits){
    int mask1 = 0;
    int mask2 = 0;
    for(int i = 0; i < logm/2; i++){
        mask1 = mask1<<1;
        mask1 += 1;
    }
    for(int i = 0; i < logn/2; i++){
        mask2 = mask2<<1;
        mask2 += 1;
    }
    int idx_size = 0;
    for(int i = 0; i < M.size(); i++){
        idx_size+= M[i].size();
    }
    
    idx.resize(idx_size);
    bits.resize(idx_size);
    int ctr = 0;
    vector<short> buff(logm+logn,0);
    for(int i = 0; i < M.size(); i++){
        for(int j = 0; j < M[i].size(); j++){
            idx[ctr].resize(4);
            idx[ctr][0] = i&mask1;
            idx[ctr][1] = i>>(logm/2);
            if(idx[ctr][0] + (idx[ctr][1]<<(logm/2)) != i){
                printf("Error in matrix preperation 1,%d,%d,%d\n",i,mask1,idx[ctr][1]);
                exit(-1);
            }
            idx[ctr][2] = M[i][j].first&mask2; 
            idx[ctr][3] = M[i][j].first>>(logn/2); 
            if(idx[ctr][2] + (idx[ctr][3]<<(logn/2)) != M[i][j].first){
                printf("Error in matrix preperation 2,%d\n",M[i][j].first);
                exit(-1);
            }
            get_bits(buff,i,M[i][j].first);
            bits[ctr] = buff;
            ctr++;

        }
    }
}


void compute_witness_vector(vector<F> r1, vector<F> r2, vector<sparse_eval_data> &data, vector<F> &witness, int N, double &pt){
    vector<F> r11,r12,r21,r22;
    for(int i = 0 ; i < r1.size()/2; i++){
        r11.push_back(r1[i]);
    }
    for(int i = r1.size()/2; i < r1.size(); i++){
        r12.push_back(r1[i]);
    }
    for(int i = 0; i < r2.size()/2; i++){
        r21.push_back(r2[i]);
    }
    for(int i = r2.size()/2; i < r2.size(); i++){
        r22.push_back(r2[i]);
    }
    int mask1 = 0;
    int mask2 = 0;
    for(int i = 0; i < logm/2; i++){
        mask1 = mask1<<1;
        mask1 += 1;
    }
    for(int i = 0; i < logn/2; i++){
        mask2 = mask2<<1;
        mask2 += 1;
    }

    vector<F> beta11,beta12,beta21,beta22;
    
    clock_t t1 = clock();
    precompute_beta(r11,beta11);
    precompute_beta(r12,beta12);
    precompute_beta(r21,beta21);
    precompute_beta(r22,beta22);
    clock_t t2 = clock();
    pt += (double)(t2-t1)*N/(double)CLOCKS_PER_SEC;
    witness.resize(8*next_pow2(data[0].IDX1.size()),F(0));
    int ctr = 0;
    t1 = clock();
    for(int i = 0; i < data.size(); i++){
        for(int j = 0; j < data[i].IDX1.size(); j++){
            int idx1 = data[i].IDX1[j];
            int idx11 = idx1&mask1;
            int idx12 = idx1>>(logm/2);
            witness[ctr] = beta11[idx11]*beta12[idx12];
            ctr++;
        }
        ctr+= next_pow2(data[i].IDX1.size())-data[i].IDX1.size();
        for(int j = 0; j < data[i].IDX2.size(); j++){
            int idx2 = data[i].IDX2[j];
            int idx21 = idx2&mask2;
            int idx22 = idx2>>(logn/2);
            witness[ctr] = beta21[idx21]*beta22[idx22];
            ctr++;

        }
        ctr+= next_pow2(data[i].IDX1.size())-data[i].IDX1.size();

    }
    t2 = clock();
    pt += (double)(t2-t1)/(double)CLOCKS_PER_SEC;

}

void evaluate_sparse_matrix(size_t size, int N, vector<F> r1, vector<F> r2, F y, F a, F b, F c, double &pt, double &ps, double &vt){
    vector<F> witness;
    vector<vector<F>> R;
    vector<vector<F>> Code;
    vector<vector<vector<_hash>>> MT;     
    vector<sparse_eval_data> data;
    
    prepare_R1CS_data(A, B, C, logm, logn, data);
    vector<F> beta1,beta2;precompute_beta(r1,beta1);precompute_beta(r2,beta2);
    
    compute_witness_vector(r1,r2,data,witness,N,pt);
    
    //COMMIT
    //plain_commit(witness,N/2,N,N,R,Code,MT,pt,vt,ps,cm);
    prove_sparse_eval(y,a,b,c, beta1, beta2, data,pt, ps, vt);
    
    vector<F> r,_r1,_r2;
    for(int i = 0; i < (int)log2(witness.size()); i++){
        r.push_back(F::_random());
        if(i < (int)log2(N/2)){
            _r1.push_back(r[i]);
        }else{
            _r2.push_back(r[i]);
        }
    }
    clock_t t1 = clock();
    precompute_beta(_r1,beta1);
    precompute_beta(_r2,beta2);
    clock_t t2 = clock();
    pt += N*(double)(t2-t1)/(double)CLOCKS_PER_SEC;
    y = evaluate_vector(witness,r);
    // OPEN
    //plain_open(y,Code,R,MT,beta1,beta2,N/2,pt,vt,ps,500,false);

    
    //r1.insert(r1.end(),r2.begin(),r2.end());
    //prepare_matrix_data(A,idx,bits);
    //prove_sparse_eval_bit(r1, evaluate_vector(RA,r2), bits, idx, logm, logn, N, pt, vt, ps);
    //printf("%lf\n",pt/N);
    
}

void commit_sparse_eval_witness(vector<vector<F>> &beta1, vector<vector<F>> &beta2,vector<F> &codeword ,vector<F> &row_data, MT &Com, int k, int N){
    vector<F> data;
    vector<vector<F>> buff;
    buff = beta1;
    
    vector<int> order;

    sort_transcript(buff, order);
    
    data = convert2vector(buff);
    buff.clear();
    data.resize(next_pow2(data.size()),F(0));
    
    //for(int i = 0; i < beta1.size(); i++) data.insert(data.end(),beta1[i].begin(),beta1[i].end());
    for(int i = 0; i < beta2.size(); i++) data.insert(data.end(),beta2[order[i]].begin(),beta2[order[i]].end());
    data.resize(next_pow2(data.size()),F(0));
    plaintext_commit(data, codeword,row_data,Com,k,N);
}

void open_sparse_eval(vector<F> &codeword, vector<F> &row_data, vector<F> r, MT &Com, F y,int l, int k, int N, double &ps){
    vector<F> r1,r2,v1,v2;

    for(int i = 0; i < (int)log2(k); i++) r2.push_back(r[i]);
    for(int i = r2.size(); i < r.size() ; i++) r1.push_back(r[i]);
    
    precompute_beta(r1,v1);precompute_beta(r2,v2);
    
    open_plaintext(codeword, row_data, v1, v2, Com, y, l, k, N, ps,false);
}

void sparse_matrix_evaluation(F y, F a, F b, F c, vector<F> r1,vector<F> r2, vector<sparse_eval_data> &index, int N, double &ps){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id

    vector<vector<F>> beta1(3),beta2(3);
    r1.pop_back();r2.pop_back();
    if(r1.size() != logm){
        printf("Wrong dimensions 1\n");
        exit(-1);
    }
    if(r2.size() != logn){
        printf("Wrong dimensions 2\n");
        exit(-1);
    }
    pt_cp.start();

    timer sparse_eval_timer;
    sparse_eval_timer.start();
    compute_R1CS_betas(r1,  r2, index, beta1, beta2, logm, logn, N);
    vector<F> codeword,row_data;
    MT Com;
    pt_cp.end();
    commit_sparse_eval_witness(beta1, beta2, codeword , row_data, Com, N/2,  N);
    sparse_eval_timer.end();
    if(rank == 0) printf("      Phase 5.0 (Commit): %lf\n",sparse_eval_timer.get_time());

    //pair<F,vector<F>> claim = _prove_sparse_eval(y, a, b, c, beta1, beta2, index,r1,r2, N);
    sparse_eval_timer.reset();
    sparse_eval_timer.start();
    int gkr_rounds = com_rounds;
    // The optimized evaluator contains the native DSC_QUADRATIC probe.
    // Keep this probe independent from the legacy evaluator selection.
    pair<F,vector<F>> claim =
        _prove_sparse_eval_opt(y, a, b, c, beta1, beta2, index, r1, r2, N);
    sparse_eval_timer.end();
    
    if(rank == 0) printf("      Phase 5.1 (Sumcheck): %lf, Rounds: %d\n",sparse_eval_timer.get_time(),com_rounds-gkr_rounds);

    sparse_eval_timer.reset();
    sparse_eval_timer.start();
    open_sparse_eval(codeword,row_data,claim.second,Com,claim.first,796,N/2,N,ps);
    sparse_eval_timer.end();
    if(rank == 0) printf("      Phase 5.2 (Open): %lf\n",sparse_eval_timer.get_time());
    
}

pair<F,vector<F>> sparse_matrix_evaluation_batch(F y, F a, F b, F c, vector<F> r1,vector<F> r2, vector<sparse_eval_data> &index,
                                    vector<F> &row_data,vector<F> &codeword, MT &Com, int N, double &ps){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id

    vector<vector<F>> beta1(3),beta2(3);
    r1.pop_back();r2.pop_back();
    if(r1.size() != logm){
        printf("Wrong dimensions 1\n");
        exit(-1);
    }
    if(r2.size() != logn){
        printf("Wrong dimensions 2\n");
        exit(-1);
    }
    double temp = pt_cp.get_time();
    pt_cp.start();
    
    timer sparse_eval_timer;
    sparse_eval_timer.start();
    compute_R1CS_betas(r1,  r2, index, beta1, beta2, logm, logn, N);
    pt_cp.end();
    commit_sparse_eval_witness(beta1, beta2, codeword , row_data, Com, N/2,  N);
    sparse_eval_timer.end();
    if(rank == 0) printf("      Phase 5.0 (Commit): %lf, Pt : %lf\n",sparse_eval_timer.get_time(),pt_cp.get_time()-temp);

    //pair<F,vector<F>> claim = _prove_sparse_eval(y, a, b, c, beta1, beta2, index,r1,r2, N);
    sparse_eval_timer.reset();
    temp = pt_cp.get_time();
    sparse_eval_timer.start();
    int gkr_rounds = com_rounds;
    // The optimized evaluator contains the native DSC_QUADRATIC probe.
    // Keep this probe independent from the legacy evaluator selection.
    pair<F,vector<F>> claim =
        _prove_sparse_eval_opt(y, a, b, c, beta1, beta2, index, r1, r2, N);
    sparse_eval_timer.end();
    
    if(rank == 0) printf("      Phase 5.1 (Sumcheck): %lf, Local time: %lf, Rounds: %d\n",sparse_eval_timer.get_time(),pt_cp.get_time()-temp,com_rounds-gkr_rounds);

    sparse_eval_timer.reset();
    return claim;
    //sparse_eval_timer.start();
    //open_sparse_eval(codeword,row_data,claim.second,Com,claim.first,500,N/2,N,ps);
    //sparse_eval_timer.end();
    //if(rank == 0) printf("      Phase 5.2 (Open): %lf\n",sparse_eval_timer.get_time());   
}



vector<pair<F,vector<F>>> aggregate_random_evaluations_phase1(vector<pair<F,vector<F>>> claims1, vector<pair<F,vector<F>>> claims2,
                                 vector<F> &R, vector<F> &_R,vector<F> &codeword, vector<F> &_codeword, MT &CR, F a, F b, F c, int N, int k, int _k, double &ps){
    
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    pt_cp.start();
    
    int logk = (int)log2(k);
    vector<vector<F>> vectors(10);
    vectors[0].resize(4);vectors[1].resize(4);vectors[2].resize(4);
    vectors[3].resize(logn-logk+2);vectors[4].resize(logn-logk+2);
    vectors[5].resize(logm-logk+2);vectors[6].resize(logm-logk+2);
    vectors[7].resize(4);vectors[8].resize(4);vectors[9].resize(4);
    for(int i = 0; i < 4; i++){
        vectors[0][i] = _R[i];
        vectors[1][i] = _R[i+4];
        vectors[2][i] = _R[i+8];
        vectors[7][i] = R[i];
        vectors[8][i] = R[i+4];
        vectors[9][i] = R[i+8];
    }
    for(int i = 0; i < logn+2-logk; i++){
        vectors[3][i] = _R[i+12];
        vectors[4][i] = _R[i+12+logn-logk+2];
    }
    for(int i = 0; i < logm+2-logk; i++){
        vectors[5][i] = _R[i+12+2*(logn -logk + 2)];
        vectors[6][i] = _R[i+12+2*(logn -logk + 2) + logm-logk+2];
    }
    vector<vector<vector<F>>> betas(10);
    for(int i = 0; i < 7; i++) betas[i].resize(2);
    vector<F> r1,r2;
    
    for(int i = 0; i < (int)log2(k); i++) r2.push_back(claims1[0].second[i]);
    for(int i = (int)log2(k); i < claims1[0].second.size(); i++) r1.push_back(claims1[0].second[i]);
    
    for(int i = 0; i < logm-logk; i++) betas[5][0].push_back(_beta(1<<i,r1));
    
    betas[5][0].push_back(_beta((1<<(logm-logk))-2,r1));
    betas[5][0].push_back(_beta((1<<(logm-logk))-1,r1));
    precompute_beta(r2,betas[5][1]);
    betas[6] = betas[5];

    r1.clear();r2.clear();
    for(int i = 0; i <  (int)log2(k); i++) r2.push_back(claims2[0].second[i]);
    for(int i = (int)log2(k); i < claims2[0].second.size(); i++) r1.push_back(claims2[0].second[i]);
    for(int i = 0; i < (logn-logk); i++) betas[3][0].push_back(_beta(1<<i,r1));
    
    betas[3][0].push_back(_beta((1<<(logn-logk))-2,r1));
    betas[3][0].push_back(_beta((1<<(logn-logk))-1,r1));
    precompute_beta(r2,betas[3][1]);
    betas[4] = betas[3];
    for(int i = 0; i < 4; i++){
        betas[0][0].push_back(_beta(i,r1));
    }
    betas[0][1] = betas[3][1];
    betas[1] = betas[0];betas[2] = betas[0];
    betas[7] = betas[0];betas[8] = betas[0];
    betas[9] = betas[0];
    pt_cp.end();
    
    vector<F> evals = batch_ip(vectors, betas, N, k,_k,
        PVIA_SCALAR_CTX_RANDOM_EVAL_BATCH);    
    pt_cp.start();
    vector<F> _c(7);
    for(int i = 0; i < 7; i++) _c[i] = hash_to_field({});
    F _b = hash_to_field({});
    for(int i = 0; i < R.size(); i++){
        R[i] += _b*_R[i];
    }
    for(int i = 0; i < codeword.size(); i++){
        codeword[i] += _b*_codeword[i];
    }
   if(rank == 0){
        if(claims2[2].first != a*evals[7]+b*evals[8] + c*evals[9]){
            printf("ERROR\n");
        }
   }
   
    
    F sum = _c[0]*evals[7]+_c[1]*evals[8]+_c[2]*evals[9] + _c[3]*claims2[4].first +_c[4]*claims2[5].first  + _c[5]*claims1[4].first + _c[6]*claims1[5].first;
    for(int i = 0; i < 7; i++) sum += _b*_c[i]*evals[i];

    vector<F> v1 = R,v2;
    for(int i = 0; i < vectors.size()-3; i++){
        vector<F> buff = betas[i][1];
        buff.resize(_k,F(0));
        fft(buff,(int)log2(buff.size()),true);
        buff.resize(2*N,0);
        fft(buff,(int)log2(buff.size()),false);
        for(int j = 0; j < betas[i][0].size(); j++){
            betas[i][0][j] = _c[i]*buff[2*rank+1]*betas[i][0][j];
        }
        v2.insert(v2.end(),betas[i][0].begin(),betas[i][0].end());
    }
    v1.resize(next_pow2(v1.size()),F(0));
    v2.resize(next_pow2(v1.size()),F(0));
        
    pt_cp.end();
    // The opening below targets the aggregated oracle. Refresh CR only after
    // leaving the local timing region, since distributed_MT manages pt_cp itself.
    distributed_MT(codeword, CR, N);
    vector<pair<F,vector<F>>> claims = _quadratic_cosumcheck(sum,v1,v2,N,_k,k,ps);
    return claims;

}

void aggregate_random_evaluations(vector<pair<F,vector<F>>> claims1, vector<pair<F,vector<F>>> claims2,
                                 vector<F> &R, vector<F> &_R,vector<F> &codeword, vector<F> &_codeword, MT &CR, F a, F b, F c, int N, int k, int _k, double &ps){
    
    
    int logk = (int)log2(k);
    
    timer aggr_timer;
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    // Evaluate claims of _R, then apply the sumcheck to aggregate partial claims into one
    aggr_timer.start();
    vector<pair<F,vector<F>>> claims = aggregate_random_evaluations_phase1(claims1, claims2, R, _R,codeword, _codeword, CR, a, b, c, N, k, _k, ps);
    aggr_timer.end();
    pt_cp.start();
    if(rank == 0) printf("      Phase 4.0 (sumcheck): %lf\n",aggr_timer.get_time());
    vector<F> r1,r2,v1,v2;
    for(int i = 0; i < logk; i++) r2.push_back(claims[0].second[i]);
    for(int i = logk; i < claims[0].second.size(); i++) r1.push_back(claims[0].second[i]);
    aggr_timer.reset();
    aggr_timer.start();
    precompute_beta(r1,v1);precompute_beta(r2,v2);
    
    R.resize(next_pow2(R.size()),0);
    
    pt_cp.end();
    open_plaintext(codeword,R,v1,v2,CR,claims[0].first,500,k,N,ps,true);
    aggr_timer.end();
    if(rank == 0) printf("      Phase 4.1 (open): %lf\n",aggr_timer.get_time());
    
}


pair<F,vector<F>> aggregate_random_evaluations_batch(vector<pair<F,vector<F>>> claims1, vector<pair<F,vector<F>>> claims2,
                                 vector<F> &R, vector<F> &_R,vector<F> &codeword, vector<F> &_codeword, MT &CR, F a, F b, F c, int N, int k, int _k, double &ps){
    
    
    int logk = (int)log2(k);
    
    timer aggr_timer;
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    // Evaluate claims of _R, then apply the sumcheck to aggregate partial claims into one
    aggr_timer.start();
    vector<pair<F,vector<F>>> claims = aggregate_random_evaluations_phase1(claims1, claims2, R, _R,codeword, _codeword, CR, a, b, c, N, k, _k, ps);
    aggr_timer.end();
    if(rank == 0) printf("      Phase 4.0 (sumcheck): %lf\n",aggr_timer.get_time());
    R.resize(next_pow2(R.size()),0);
    return make_pair(claims[0].first,claims[0].second);
}


void init_dummy_index_commitment(vector<sparse_eval_data> &data, vector<F> &row_data, vector<F> &codeword, MT &index_Com, int rate, int N){
    int size = 0;
    for(int i = 0; i < data.size(); i++){
        size += data[i].FINAL_FR1.size();
        size += data[i].FINAL_FR2.size();
        size += data[i].IDX1.size();
        size += data[i].IDX2.size();
        size += data[i].RD1.size();
        size += data[i].RD2.size();
    }
    size = next_pow2(size);
    row_data = generate_randomness(size);
    codeword = generate_randomness(rate*size);
    distributed_MT(codeword, index_Com, N);
    
}


void open_index(vector<F> &index_data,vector<F> &codeword, MT &index_Com, int N,double &ps){
    pt_cp.start();
    vector<F> r1,r2,beta1,beta2;
    for(int i = 0; i < (int)log2(index_data.size()); i++) r1.push_back(hash_to_field({}));
    for(int i = 0; i < (int)log2(N); i++) r2.push_back(hash_to_field({}));
    precompute_beta(r1,beta1);precompute_beta(r2,beta2);
    pt_cp.end();
    open_plaintext(codeword,index_data,beta1,beta2,index_Com,F(0),100,N,N,ps,false,false);
}

void batch_open_PIOP(vector<pair<F,vector<F>>> claims, vector<vector<F>> &row_data,vector<vector<F>> &codeword, vector<MT> &Com, int k, int N,double &ps){
    vector<vector<F>> v1(3),v2(3);
    int logk = (int)log2(k);
    pt_cp.start();
    vector<F> r1,r2;
    for(int i = 0; i < logk; i++) r2.push_back(claims[0].second[i]);
    for(int i = logk; i < claims[0].second.size(); i++) r1.push_back(claims[0].second[i]);
    precompute_beta(r1,v1[0]);precompute_beta(r2,v2[0]);r1.clear();r2.clear();
    

    for(int i = 0; i < (int)log2(N/2); i++) r2.push_back(claims[1].second[i]);
    for(int i = r2.size(); i < claims[1].second.size() ; i++) r1.push_back(claims[1].second[i]);    
    precompute_beta(r1,v1[1]);precompute_beta(r2,v2[1]);r1.clear();r2.clear();

    for(int i = 0; i < (int)log2(row_data[2].size()); i++) r1.push_back(hash_to_field({}));
    for(int i = 0; i < (int)log2(N); i++) r2.push_back(hash_to_field({}));
    precompute_beta(r1,v1[2]);precompute_beta(r2,v2[2]);

    pt_cp.end();
    
    //open_plaintext(codeword[1],row_data[1],v1[1],v2[1],Com[1],claims[1].first,500,N/2,N,ps,false);
    

    
    batch_open(codeword,row_data,v1,v2,Com,{claims[0].first,claims[1].first,F(1)},{500,796,100},{k,N/2,N},N,ps,{true,false,false},{true,true,false});
}


void coPIOP_prove(size_t size, int N, int _k, int k, int cir_type){
    double ps = 0.0;
    int logk = (int)log2(k);
    
    vector<F> witness,vL,vO,vR,R,_R;
    vector<F> r_witness;
    vector<vector<F>> mask_shares,mask_data,C_mask;
    vector<F> RA,RB,RC;
    vector<sparse_eval_data> index;
    MT CR,_CR,index_Com,Com;
    vector<MT> Com_mask;
    vector<F> codeword,row_data,codeword_R,_codeword_R,index_codeword,index_data;
    distribute_index(N, size, index,cir_type);
    distribute_proving_data(vL, vR, vO, witness, N, size, _k, k,cir_type);
    pvia::InitialValidityGateResult initial_validity;
    if (pvia::Runtime::instance().enabled()) {
        auto& rt = pvia::Runtime::instance();
        // Bind the packed input state before deriving the public coin used by
        // the private initial validity gate.
        const pvia::StateId vL_state =
            rt.import_state("vL", pvia::Phase::INIT, vL);
        const pvia::StateId vR_state =
            rt.import_state("vR", pvia::Phase::INIT, vR);
        const pvia::StateId vO_state =
            rt.import_state("vO", pvia::Phase::INIT, vO);
        const pvia::StateId witness_state =
            rt.import_state("witness", pvia::Phase::INIT, witness);
        const std::vector<pvia::StateId> initial_states = {
            witness_state, vL_state, vR_state, vO_state};
        const bool gate_ok = pvia::run_initial_packed_validity_gate(
            rt, witness, vL, vR, vO, pA, pB, pC, initial_states,
            k, _k, &initial_validity);
        if (!gate_ok || !initial_validity.valid) {
            int rank = 0;
            MPI_Comm_rank(MPI_COMM_WORLD, &rank);
            if (rank == 0)
                printf("[PVIA][validity] WITHHOLD before first proof-dependent release\n");
            std::exit(15);
        }
    }
    setup_randomness_pair(
        R, _R, N, _k, k,
        500 + 2*(logm + logn - 2*logk + 4) + 12+1,
        0x5056505245523031ULL, 0x5056505245523032ULL);
    if (pvia::Runtime::instance().enabled()) {
        pvia::Runtime::instance().import_state("R", pvia::Phase::INIT, R);
        pvia::Runtime::instance().import_state("R_mask", pvia::Phase::INIT, _R);
    }
    dummy_setup(r_witness, mask_shares, N, 1<<logn, k, _k, 500);
    prepare_mask_shares(mask_shares, mask_data, C_mask, Com_mask, N, 1<<logn, k, _k, 500);
    //setup_randomness(r_witness, N, _k, k,500);
    commit_randomness(R, _R, codeword_R, _codeword_R, CR, _CR, N);
    // To ease development, we initialize a dummy index commitment. In practice, we could let the indexer 
    // generate such a commitment in a preprocessing phase.
    if(witness.size() < r_witness.size()){
        printf("Circuit too small. Select fewer parties\n");
        return;
    }
    init_dummy_index_commitment(index,index_data,index_codeword,index_Com,index_rate,N);
    

    MPI_Barrier(MPI_COMM_WORLD);
    com_rounds = 0;
    cm = 0.0;
    
    pt_cp.reset();
    pt.start();
    pt_cpu.start();
    temp_pc.start();
    if (pvia::Runtime::instance().enabled()) {
        pvia::Runtime::instance().set_next_commit_predecessor(
            initial_validity.validation_operation);
        pvia::Runtime::instance().set_next_commit_state_dependency(
            initial_validity.validated_state);
    }
    commit(codeword, row_data, witness, r_witness, Com, 500, k, _k, N);
    vector<F> rL(4),rR(4),rO(4),R1(logn-logk +2),R2(logn+2-logk ),R3(logm-logk +2),R4(logm+2-logk );
    for(int i = 0; i < 4; i++){
        rL[i] = R[i];
        rR[i] = R[i+4];
        rO[i] = R[i+8];
    }
    for(int i = 0; i < logn -logk +2; i++){
        R1[i] = R[i+12];
        R2[i] = R[i+12 + logn-logk +2];
    }
    for(int i = 0; i < logm-logk+2; i++){
        R3[i] = R[i+12+2*(logn -logk + 2)];
        R4[i] = R[i+12+2*(logn -logk + 2)+logm-logk+2];
    }
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    temp_pc.end();
    if(rank == 0)printf("1 >>>>>>>> %lf\n",cm/1024.0);
    
    if(rank == 0)printf("Phase 1: %lf, rounds: %d\n",temp_pc.get_time(),com_rounds);temp_pc.reset();
    temp_pc.start();
    vector<pair<F,vector<F>>> claims1 = prove_phase1(vL, vR, vO, rL, rR, rO,R3,R4, N,_k, k, ps);
    temp_pc.end();
    if(rank == 0)printf("Phase 2: %lf, rounds: %d\n",temp_pc.get_time(),com_rounds);temp_pc.reset();
    F a,b,c;
    if(rank == 0)printf("1 >>>>>>>> %lf\n",cm/1024.0);
    temp_pc.start();
    vector<pair<F,vector<F>>> claims2 = prove_phase2(witness, r_witness, rL, rR, rO, RA, RB, RC,R1,R2, claims1[0].second, claims1[0].first,claims1[1].first,claims1[2].first,N, size, _k, k, a,b,c,
        initial_validity.relation_definition_binding, ps);
    temp_pc.end();
    if(rank == 0)printf("Phase 3: %lf, rounds: %d\n",temp_pc.get_time(),com_rounds);temp_pc.reset();
    
    if(rank == 0)printf("1 >>>>>>>> %lf\n",cm/1024.0);
    temp_pc.start();
    aggregate_random_evaluations(claims1,  claims2, R,  _R,codeword_R,_codeword_R,CR ,a,b,c, N, k,  _k,ps);
    temp_pc.end();
    if(rank == 0)printf("Phase 4: %lf, rounds: %d\n",temp_pc.get_time(),com_rounds);temp_pc.reset();
    if(rank == 0)printf("2 >>>>>>>> %lf\n",cm/1024.0);
    
    //return;
    if(!data_parallel){
        temp_pc.start();
        sparse_matrix_evaluation(claims2[1].first,a,b,c,
                             claims1[0].second,claims2[0].second,index,N,ps);
        temp_pc.end();
        if(rank == 0)printf("Phase 5: %lf\n",temp_pc.get_time());temp_pc.reset();
    
        
        
        temp_pc.start();
        open_index(index_data,index_codeword, index_Com, N,ps);
        temp_pc.end();
        if(rank == 0)printf("Phase 6 (Open): %lf\n",temp_pc.get_time());temp_pc.reset();
    
    }
    temp_pc.start();
    open_zk(codeword,C_mask,row_data,mask_data,Com,Com_mask, claims2[0].second,claims2[0].first,500,k,_k,(1<<logm),N,ps);
    if(rank == 0)printf("3 >>>>>>>> %lf\n",(double)cm/1024.0);
    temp_pc.end();
    if(rank == 0)printf("Phase 7: %lf, rounds: %d\n",temp_pc.get_time(),com_rounds);temp_pc.reset();
    pt.end();
    pt_cpu.end();
    MPI_Barrier(MPI_COMM_WORLD);
    if(rank == 0){
        vector<double> buff(3);
        printf("Id : %d, Pt: %lf, CPU Only Pt: %lf, Computation only: %lf, Vt: %lf\n", rank, pt.get_time(),pt_cpu.get_time(),pt_cp.get_time(),vt.get_time());
        for(int i = 1; i < N; i++){
            MPI_Recv(buff.data(), 3,MPI_DOUBLE,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            printf("Id : %d, Pt: %lf, CPU Only Pt: %lf, Computation only: %lf\n", i, buff[0],buff[1],buff[2]);
        }    
    }else{
        vector<double> buff = {pt.get_time(),pt_cpu.get_time(),pt_cp.get_time()};
        MPI_Send(buff.data(), 3,MPI_DOUBLE,0,0,MPI_COMM_WORLD);   
    }
    MPI_Barrier(MPI_COMM_WORLD);
    vector<double> buff = {vt.get_time(),ps,cm};
    if(rank != 0){
        MPI_Send(buff.data(),3,MPI_DOUBLE,0,0,MPI_COMM_WORLD);
    }else{
        double total_vt = vt.get_time();
        for(int i = 1; i < N; i++){
            MPI_Recv(buff.data(),3,MPI_DOUBLE,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            total_vt += buff[0];
            ps += buff[1];
            cm += buff[2];
        }
        printf("Vt : %lf sec, Ps: %lf KB, Com: %lf MB\n",total_vt,ps+ps_plain,cm/1024.0);
        printf("Interaction Rounds: %d\n",com_rounds);
    }
}

void coPIOP_prove_batch(size_t size, int N, int _k, int k, int cir_type){
    double ps = 0.0;
    int logk = (int)log2(k);
    
    vector<F> witness,vL,vO,vR,R,_R;
    vector<F> r_witness;
    vector<vector<F>> mask_shares,mask_data,C_mask;
    vector<F> RA,RB,RC;
    vector<sparse_eval_data> index;
    MT CR,_CR,index_Com,Com;
    vector<MT> Com_mask;
    vector<vector<F>> batch_row_data(3),batch_codewords(3);
    vector<MT> batch_MT(3);
    vector<pair<F,vector<F>>> claims(3);
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    
    vector<F> codeword,row_data,codeword_R,_codeword_R,index_codeword,index_data;
    timer setup_time;setup_time.start();
    distribute_index(N, size, index,cir_type);
    distribute_proving_data(vL, vR, vO, witness, N, size, _k, k,cir_type);
    pvia::InitialValidityGateResult initial_validity;
    if (pvia::Runtime::instance().enabled()) {
        auto& rt = pvia::Runtime::instance();
        // Bind the packed input state before deriving the public coin used by
        // the private initial validity gate.
        const pvia::StateId vL_state =
            rt.import_state("vL", pvia::Phase::INIT, vL);
        const pvia::StateId vR_state =
            rt.import_state("vR", pvia::Phase::INIT, vR);
        const pvia::StateId vO_state =
            rt.import_state("vO", pvia::Phase::INIT, vO);
        const pvia::StateId witness_state =
            rt.import_state("witness", pvia::Phase::INIT, witness);
        const std::vector<pvia::StateId> initial_states = {
            witness_state, vL_state, vR_state, vO_state};
        const bool gate_ok = pvia::run_initial_packed_validity_gate(
            rt, witness, vL, vR, vO, pA, pB, pC, initial_states,
            k, _k, &initial_validity);
        if (!gate_ok || !initial_validity.valid) {
            int rank = 0;
            MPI_Comm_rank(MPI_COMM_WORLD, &rank);
            if (rank == 0)
                printf("[PVIA][validity] WITHHOLD before first proof-dependent release\n");
            std::exit(15);
        }
    }
    setup_randomness_pair(
        R, _R, N, _k, k,
        500 + 2*(logm + logn - 2*logk + 4) + 12+1,
        0x5056505245523031ULL, 0x5056505245523032ULL);
    if (pvia::Runtime::instance().enabled()) {
        pvia::Runtime::instance().import_state("R", pvia::Phase::INIT, R);
        pvia::Runtime::instance().import_state("R_mask", pvia::Phase::INIT, _R);
    }
    dummy_setup(r_witness, mask_shares, N, 1<<logn, k, _k, 500);
    prepare_mask_shares(mask_shares, mask_data, C_mask, Com_mask, N, 1<<logn, k, _k, 500);
    //setup_randomness(r_witness, N, _k, k,500);
    commit_randomness(R, _R, codeword_R, _codeword_R, CR, _CR, N);
    // To ease development, we initialize a dummy index commitment. In practice, we could let the indexer 
    // generate such a commitment in a preprocessing phase.
    if(witness.size() < r_witness.size()){
        printf("Circuit too small. Select fewer parties\n");
        return;
    }
    init_dummy_index_commitment(index,batch_row_data[2],batch_codewords[2],batch_MT[2],index_rate,N);
    setup_time.end();
    if(rank == 0) printf("Setup time: %lf\n",setup_time.get_time()); 
    
    MPI_Barrier(MPI_COMM_WORLD);
    cm = 0.0;
    com_rounds = 0;
    pt_cp.reset();
    pt.start();
    pt_cpu.start();
    temp_pc.start();
    int temp_rounds;
    double temp_comp_time;
    temp_comp_time = pt_cp.get_time();
    if (pvia::Runtime::instance().enabled()) {
        pvia::Runtime::instance().set_next_commit_predecessor(
            initial_validity.validation_operation);
        pvia::Runtime::instance().set_next_commit_state_dependency(
            initial_validity.validated_state);
    }
    commit(codeword, row_data, witness, r_witness, Com, 500, k, _k, N);
    vector<F> rL(4),rR(4),rO(4),R1(logn-logk +2),R2(logn+2-logk ),R3(logm-logk +2),R4(logm+2-logk );
    for(int i = 0; i < 4; i++){
        rL[i] = R[i];
        rR[i] = R[i+4];
        rO[i] = R[i+8];
    }
    for(int i = 0; i < logn -logk +2; i++){
        R1[i] = R[i+12];
        R2[i] = R[i+12 + logn-logk +2];
    }
    for(int i = 0; i < logm-logk+2; i++){
        R3[i] = R[i+12+2*(logn -logk + 2)];
        R4[i] = R[i+12+2*(logn -logk + 2)+logm-logk+2];
    }
    temp_pc.end();
    temp_rounds = com_rounds;
    if(rank == 0)printf("Phase 1: %lf, rounds: %d, comp_time: %lf\n",temp_pc.get_time(),com_rounds,pt_cp.get_time()-temp_comp_time);temp_pc.reset();
    temp_rounds = com_rounds;
    temp_pc.start();
    temp_comp_time = pt_cp.get_time();
    
    vector<pair<F,vector<F>>> claims1 = prove_phase1(vL, vR, vO, rL, rR, rO,R3,R4, N,_k, k, ps);
    temp_pc.end();
    if(rank == 0)printf("Phase 2: %lf, rounds: %d, comp_time: %lf\n",temp_pc.get_time(),com_rounds-temp_rounds,pt_cp.get_time()-temp_comp_time);temp_pc.reset();
    F a,b,c;
    temp_rounds = com_rounds;
    temp_pc.start();
    temp_comp_time = pt_cp.get_time();
    vector<pair<F,vector<F>>> claims2 = prove_phase2(witness, r_witness, rL, rR, rO, RA, RB, RC,R1,R2, claims1[0].second, claims1[0].first,claims1[1].first,claims1[2].first,N, size, _k, k, a,b,c,
        initial_validity.relation_definition_binding, ps);
    temp_pc.end();
    if(rank == 0)printf("Phase 3: %lf, rounds: %d, comp_time: %lf\n",temp_pc.get_time(),com_rounds-temp_rounds,pt_cp.get_time()-temp_comp_time);temp_pc.reset();
    
    temp_rounds = com_rounds;
    temp_pc.start();
    temp_comp_time = pt_cp.get_time();
    
    claims[0] = aggregate_random_evaluations_batch(claims1,  claims2, R,  _R,codeword_R,_codeword_R,CR ,a,b,c, N, k,  _k,ps);
    temp_pc.end();
    batch_row_data[0] = R;batch_codewords[0] = codeword_R;batch_MT[0] = CR;
        
    
    if(rank == 0)printf("Phase 4: %lf, rounds: %d, comp_time: %lf\n",temp_pc.get_time(),com_rounds-temp_rounds,pt_cp.get_time()-temp_comp_time);temp_pc.reset();
    
    //return;
    if(!data_parallel){
        temp_comp_time = pt_cp.get_time();
        temp_pc.start();
        claims[1] = sparse_matrix_evaluation_batch(claims2[1].first,a,b,c,
                             claims1[0].second,claims2[0].second,index,batch_row_data[1],batch_codewords[1],batch_MT[1],N,ps);
        temp_pc.end();
        if(rank == 0)printf("Phase 5 (Sparse Matrix Eval): %lf, Comp_time: %lf, Comm time: %lf\n",temp_pc.get_time(),pt_cp.get_time()-temp_comp_time,sch_com.get_time());temp_pc.reset();
    
        temp_pc.start();
        int temp_rounds = com_rounds;
        temp_comp_time = pt_cp.get_time();
        batch_open_PIOP(claims, batch_row_data,batch_codewords, batch_MT, k, N,ps);
        
        //open_index(index_data,index_codeword, index_Com, N,ps);
        temp_pc.end();
        
        if(rank == 0)printf("Phase 6 (Open Plaintex): %lf, Rounds : %d, Comp time: %lf\n",temp_pc.get_time(),com_rounds-temp_rounds,pt_cp.get_time()-temp_comp_time);temp_pc.reset();
    
    }
    temp_pc.start();
    temp_rounds = com_rounds;
    open_zk(codeword,C_mask,row_data,mask_data,Com,Com_mask, claims2[0].second,claims2[0].first,500,k,_k,(1<<logm),N,ps);
    temp_pc.end();
    if(rank == 0)printf("Phase 7 (Open Witness): %lf, rounds: %d\n",temp_pc.get_time(),com_rounds-temp_rounds);temp_pc.reset();
    pt.end();
    pt_cpu.end();
    MPI_Barrier(MPI_COMM_WORLD);
    if(rank == 0){
        vector<double> buff(3);
        printf("Id : %d, Pt: %lf, CPU Only Pt: %lf, Computation only: %lf, Vt: %lf\n", rank, pt.get_time(),pt_cpu.get_time(),pt_cp.get_time(),vt.get_time());
        for(int i = 1; i < N; i++){
            MPI_Recv(buff.data(), 3,MPI_DOUBLE,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            printf("Id : %d, Pt: %lf, CPU Only Pt: %lf, Computation only: %lf\n", i, buff[0],buff[1],buff[2]);
        }    
    }else{
        vector<double> buff = {pt.get_time(),pt_cpu.get_time(),pt_cp.get_time()};
        MPI_Send(buff.data(), 3,MPI_DOUBLE,0,0,MPI_COMM_WORLD);   
    }
    MPI_Barrier(MPI_COMM_WORLD);
    vector<double> buff = {vt.get_time(),ps,cm};
    if(rank != 0){
        MPI_Send(buff.data(),3,MPI_DOUBLE,0,0,MPI_COMM_WORLD);
    }else{
        double total_vt = vt.get_time();
        for(int i = 1; i < N; i++){
            MPI_Recv(buff.data(),3,MPI_DOUBLE,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            total_vt += buff[0];
            ps += buff[1];
            cm += buff[2];
        }
        printf("Vt : %lf sec, Ps: %lf KB, Com: %lf MB\n",total_vt,ps+ps_plain,cm/1024.0);
        printf("Interaction Rounds: %d\n",com_rounds);
    }
}


void prove_R1CS_standard(size_t size, int cir){
    double pt = 0.0,vt = 0.0,ps = 0.0;
    double cm = 0.0;

    vector<F> witness,vL,vO,vR;
    vector<F> RA,RB,RC;
    
    generate_R1CS_matrixes(size,cir);
    
    vector<vector<int>> idx;
    vector<vector<short>> bits;
    
    
    
    prepare_witness_data(size, witness, vL, vR, vO,cir);
    vector<F> rand_vL = vL,rand_vR = vR,rand_vO = vO;

    printf("Witness size 1 : %d\n",witness.size());
    vector<F> r1;
    for(int i = 0; i < (int)log2(vL.size()); i++)r1.push_back(F::_random());
    
    
    //_r1 = generate_randomness((int)log2(vL[0].size()));
    //_r2 = generate_randomness((int)log2(k));
    vector<F> beta1,beta2;
    clock_t t1 = clock();
    precompute_beta(r1,beta1);
    
    vector<pair<F,vector<F>>> claims = zerocheck_sumcheck(F(0), beta1, vL, vR,vO,F(0), vt, ps);
    r1 = claims[0].second;
    //vector<F> buff = vL; buff.insert(buff.end(),rL.begin(),rL.end());buff.resize(next_pow2(buff.size()),F(0));
    F a = F::_random(),b= F::_random(),c= F::_random();
    
    
    RA.clear();RB.clear();RC.clear();
    
    reduce_R1CS_matrixes(size,claims[0].second,RA,RB,RC);

    vector<F> R_aggr(RA.size(),F(0));
    
    for(int i = 0; i < RA.size(); i++){
        R_aggr[i] = (a*RA[i] + b*RB[i] + c*RC[i]);
    }
    claims = quadratic_sumcheck(a*claims[1].first+b*claims[2].first+c*claims[3].first, witness, R_aggr,F(0));
    vector<F> r2 = claims[0].second;
    
    
    
    
    vector<sparse_eval_data> data;
    prepare_R1CS_data(A, B, C, logm, logn, data);
    
    //compute_witness_vector(r1,r2,data,witness,1,pt);
    beta1.clear();beta2.clear();
    vector<vector<F>> _beta1(3),_beta2(3);
    
    compute_R1CS_betas(r1,  r2, data, _beta1, _beta2, logm, logn,1);
    int wit_size = 0;
    for(int i = 0; i <  _beta1.size(); i++){
        wit_size += next_pow2(_beta1[i].size());
        wit_size += next_pow2(_beta2[i].size());
    }
    printf("Witness 2 size: %d\n", next_pow2(wit_size));
    
    
    witness.clear();
    prove_sparse_eval_opt_local(claims[1].first, a, b, c, _beta1, _beta2, data ,r1, r2, pt, ps, vt);
    //prove_sparse_eval(claims[1].first,a,b,c, beta1, beta2, data,pt, ps, vt);
    int idx_size = 0;
    for(int i = 0; i < data.size(); i++){
        idx_size += next_pow2(data[0].IDX1.size());
        idx_size += next_pow2(data[0].RD1.size());
        idx_size += next_pow2(data[0].FINAL_FR1.size());
        idx_size += next_pow2(data[0].FINAL_FR2.size());
    }
    idx_size = next_pow2(idx_size);
    clock_t t2 = clock();
    pt += (double)((t2-t1))/(double)CLOCKS_PER_SEC;
    
    //evaluate_sparse_matrix(size, N, r1, r2, claims[1].first, a, b, c, pt, ps, vt,cm);
    printf("PIOP Perf---- Pt : %lf, Vt: %lf, Ps: %lf KB, Data to commit: (Online): %d, (Offline): %d\n",pt, vt,ps,witness.size(),next_pow2(12*next_pow2(data[0].IDX1.size())));
}







