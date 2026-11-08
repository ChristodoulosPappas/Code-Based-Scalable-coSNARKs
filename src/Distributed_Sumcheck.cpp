#include "MPI_utils.hpp"
#include "Distributed_Sumcheck.h"
#include "timer.hpp"
#include "accountability/PVIA.hpp"
#include "accountability/AccountableAggregation.hpp"
#include "../Blake/blake3.h"
#include <array>
#include <unordered_map>
#include <algorithm>
#include <cstdlib>
extern timer pt_cp,vt;
double ps_plain = 0.0; 
extern double cm; 
vector<vector<pair<int, int>>> pA,pB,pC;
extern vector<int> real_idx_dim;
extern int logm,logn;
extern int com_rounds;
extern int sumcheck_offset;
extern int multree_offset;
extern bool isLAN;
timer sch_com;
timer com_timer;
extern bool data_parallel;

namespace {

class CanonicalSparseStateHasher {
public:
    CanonicalSparseStateHasher() {
        blake3_hasher_init(&hasher_);
    }

    void append_field(const F& value) {
        words_[2 * used_] = value.real;
        words_[2 * used_ + 1] = value.img;
        ++used_;
        if (used_ == FIELDS_PER_CHUNK) flush();
    }

    void append_fields(const std::vector<F>& values) {
        for (const F& value : values) append_field(value);
    }

    void append_nested_fields(const std::vector<std::vector<F>>& values) {
        for (const auto& row : values) append_fields(row);
    }

    void append_ints(const std::vector<int>& values) {
        for (int value : values)
            append_field(F(static_cast<long long>(value)));
    }

    pvia::Digest finalize() {
        flush();
        pvia::Digest out{};
        blake3_hasher_finalize(
            &hasher_, out.bytes.data(), out.bytes.size());
        return out;
    }

private:
    static constexpr size_t FIELDS_PER_CHUNK = 1024;

    void flush() {
        if (used_ == 0) return;
        blake3_hasher_update(
            &hasher_,
            reinterpret_cast<const uint8_t*>(words_.data()),
            2 * used_ * sizeof(u64));
        used_ = 0;
    }

    blake3_hasher hasher_{};
    std::array<u64, 2 * FIELDS_PER_CHUNK> words_{};
    size_t used_ = 0;
};

pvia::Digest hash_sparse_eval_source_stream(
    const std::vector<std::vector<F>>& beta1,
    const std::vector<std::vector<F>>& beta2,
    const std::vector<sparse_eval_data>& data) {
    CanonicalSparseStateHasher hasher;
    hasher.append_nested_fields(beta1);
    hasher.append_nested_fields(beta2);
    for (const auto& item : data) {
        hasher.append_ints(item.IDX1);
        hasher.append_ints(item.RD1);
        hasher.append_ints(item.WR1);
        hasher.append_ints(item.IDX2);
        hasher.append_ints(item.RD2);
        hasher.append_ints(item.WR2);
        hasher.append_ints(item.FINAL_FR1);
        hasher.append_ints(item.FINAL_FR2);
    }
    return hasher.finalize();
}

void enforce_named_aggregate_release_gate(
    const char* release_name, pvia::Phase phase, uint32_t round) {
    auto& rt = pvia::Runtime::instance();
    if (!rt.enabled()) return;
    if (rt.pre_release_gate(release_name, phase, round))
        return;
    rt.handle_global_failure(release_name, phase, round);
    std::exit(15);
}

bool pvia_linear_pair_check_value(
    const std::vector<F>& values, size_t pair, const F& x, F* out) {
    if (!out || 2 * pair + 1 >= values.size()) return false;
    *out = values[2 * pair] + x * (values[2 * pair + 1] - values[2 * pair]);
    return true;
}

bool pvia_verify_distributed_quadratic(
    const quadratic_poly& poly, const std::vector<F>& v1,
    const std::vector<F>& v2, size_t pair_count) {
    if (2 * pair_count > v1.size() || 2 * pair_count > v2.size()) return false;
    const F points[] = {F(0), F(1), F(2)};
    for (const F& x : points) {
        F expected(0);
        for (size_t j = 0; j < pair_count; ++j) {
            F a(0), b(0);
            if (!pvia_linear_pair_check_value(v1, j, x, &a) ||
                !pvia_linear_pair_check_value(v2, j, x, &b)) return false;
            expected += a * b;
        }
        if (poly.eval(x) != expected) return false;
    }
    return true;
}

bool pvia_verify_distributed_cubic(
    const cubic_poly& poly, const std::vector<F>& v1,
    const std::vector<F>& v2, const std::vector<F>& v3,
    size_t pair_count) {
    if (2 * pair_count > v1.size() || 2 * pair_count > v2.size() ||
        2 * pair_count > v3.size()) return false;
    const F points[] = {F(0), F(1), F(2), F(3)};
    for (const F& x : points) {
        F expected(0);
        for (size_t j = 0; j < pair_count; ++j) {
            F a(0), b(0), c(0);
            if (!pvia_linear_pair_check_value(v1, j, x, &a) ||
                !pvia_linear_pair_check_value(v2, j, x, &b) ||
                !pvia_linear_pair_check_value(v3, j, x, &c)) return false;
            expected += a * b * c;
        }
        if (poly.eval(x) != expected) return false;
    }
    return true;
}

} // namespace
vector<F> aggregate_quadratic_poly_sparrow(
    vector<F> H, int N, const char* release_name,
    pvia::Phase gate_phase, uint32_t gate_round){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    vector<F> buff;
    vector<u64> buff_u64(2*H.size()),send_buff(2*H.size());
    const bool pvia_on = pvia::Runtime::instance().enabled();
    std::array<u64, pvia::META_WORDS> pvia_meta{};
    std::array<u64, pvia::META_WORDS> pvia_aggregate_meta{};

    field_vector_serialize(H,send_buff);
    if (pvia_on) {
        pvia_meta = pvia::Runtime::instance().make_pending_meta(send_buff, false);
        pvia::Runtime::instance().observe_local_meta(pvia_meta, send_buff);
    }
    com_rounds+=2;
    if(rank == 0){
        vector<vector<u64>> recv_data(N);
        vector<MPI_Request> req(N-1);
        for(int i = 1; i < N; i++){
            recv_data[i].resize(2*H.size());
            MPI_Irecv(recv_data[i].data(),recv_data[i].size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i-1]);
        }
        for(int i = 1; i < N; i++){
            std::array<u64, pvia::META_WORDS> remote_meta{};
            if (pvia_on) MPI_Recv(remote_meta.data(),pvia::META_WORDS,MPI_UINT64_T,i,pvia::META_TAG,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            MPI_Wait(&req[i-1],MPI_STATUS_IGNORE);
            if (pvia_on) pvia::Runtime::instance().observe_remote_meta(i,remote_meta,recv_data[i]);
            field_vector_deserialize(recv_data[i],buff);
            for(int j = 0; j < H.size(); j++) H[j] += buff[j];
        }
        buff = H;
        if (pvia_on) pvia_aggregate_meta = pvia::bind_rank0_aggregate(
            buff, "DSC_SPARROW_AGGREGATE", rank,
            pvia::make_aggregation_aux({}, N));
        field_vector_serialize(buff,buff_u64);
    }else{
        buff = H;
        field_vector_serialize(buff,send_buff);
        cm += 8*send_buff.size()/1024.0;
        if (pvia_on) {
            pvia::Runtime::instance().seal_transfer_meta(pvia_meta, send_buff);
            pvia::Runtime::instance().observe_outgoing_transfer(pvia_meta, send_buff);
            MPI_Send(pvia_meta.data(),pvia::META_WORDS,MPI_UINT64_T,0,pvia::META_TAG,MPI_COMM_WORLD);
        }
        MPI_Request req;
        MPI_Isend(send_buff.data(),send_buff.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
    }
    if(rank == 0) cm += (N-1)*8*buff_u64.size()/1024.0;
    if (release_name) enforce_named_aggregate_release_gate(
        release_name, gate_phase, gate_round);
    myBcast(buff_u64,N);
    if (pvia_on) pvia::publish_rank0_aggregate_meta(pvia_aggregate_meta,buff_u64,rank);
    field_vector_deserialize(buff_u64,buff);
    if (pvia_on) pvia::Runtime::instance().consume_pending();
    return buff;
}

vector<F> aggregate_quadratic_poly_sparrow(
    vector<F> H, int N, const char* release_name) {
    return aggregate_quadratic_poly_sparrow(
        H, N, release_name, pvia::Phase::DISTRIBUTED_SUMCHECK,
        pvia::Runtime::instance().pending_round());
}

quadratic_poly aggregate_poly(quadratic_poly H, int N, const char* release_name, pvia::Phase gate_phase, uint32_t gate_round){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<F> buff; 
    vector<u64> buff_u64(6);

    // PVIA sidecar for the actual local polynomial sent into the
    // Distributed-Sumcheck aggregation step.
    vector<F> pvia_local_poly = {H.a,H.b,H.c};
    vector<u64> pvia_local_payload;
    field_vector_serialize(pvia_local_poly,pvia_local_payload);
    std::array<u64, pvia::META_WORDS> pvia_meta{};
    const bool pvia_on = pvia::Runtime::instance().enabled();
    if (pvia_on) {
        pvia_meta = pvia::Runtime::instance().make_pending_meta(pvia_local_payload, false);
        pvia::Runtime::instance().observe_local_meta(pvia_meta, pvia_local_payload);
    }

    com_rounds+=2;
    std::array<u64, pvia::META_WORDS> pvia_aggregate_meta{};
    
    if(rank == 0){
        vector<vector<u64>> recv_data(N);
        vector<MPI_Request> req(N);
        for(int i = 1; i < N; i++){
            recv_data[i].resize(buff_u64.size());
            MPI_Irecv(recv_data[i].data(),recv_data[i].size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i]);
            //MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        }
        for(int i = 1; i < N; i++){
            std::array<u64, pvia::META_WORDS> remote_meta{};
            if (pvia_on) {
                MPI_Recv(remote_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                         i, pvia::META_TAG, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            }
            MPI_Wait(&req[i],MPI_STATUS_IGNORE);
            if (pvia_on)
                pvia::Runtime::instance().observe_remote_meta(i, remote_meta, recv_data[i]);
            field_vector_deserialize(recv_data[i],buff);
            H = H + quadratic_poly(buff[0],buff[1],buff[2]);
        }
        buff = {H.a,H.b,H.c};
        if (pvia_on) pvia_aggregate_meta = pvia::bind_rank0_aggregate(
            buff, "DSC_AGGREGATE_QUADRATIC", rank,
            pvia::make_aggregation_aux({}, N));
        field_vector_serialize(buff,buff_u64);
    }else{
        buff = {H.a,H.b,H.c};
        field_vector_serialize(buff,buff_u64);
        cm += 8*buff_u64.size()/1024.0;
        //MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        if (pvia_on) {
            pvia::Runtime::instance().seal_transfer_meta(pvia_meta, buff_u64);
            pvia::Runtime::instance().observe_outgoing_transfer(pvia_meta, buff_u64);
            MPI_Send(pvia_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                     0, pvia::META_TAG, MPI_COMM_WORLD);
        }
        MPI_Request req;
        MPI_Isend(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
    }   
    if(rank == 0)cm += (N-1)*8*buff_u64.size()/1024.0;
    if (release_name) enforce_named_aggregate_release_gate(
        release_name, gate_phase, gate_round);
    myBcast(buff_u64, N);
    if (pvia_on) pvia::publish_rank0_aggregate_meta(
        pvia_aggregate_meta, buff_u64, rank);
    
    //MPI_Bcast(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,MPI_COMM_WORLD);
    field_vector_deserialize(buff_u64,buff);
    H = quadratic_poly(buff[0],buff[1],buff[2]);
    if (pvia_on) pvia::Runtime::instance().consume_pending();
    return H;
}


quadratic_poly aggregate_poly(
    quadratic_poly H, int N, const char* release_name) {
    return aggregate_poly(
        H, N, release_name, pvia::Phase::DISTRIBUTED_SUMCHECK,
        pvia::Runtime::instance().pending_round());
}

cubic_poly aggregate_poly(
    cubic_poly H, int N, vector<F> &v, const char* release_name,
    pvia::Phase gate_phase, uint32_t gate_round){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<F> buff; 
    vector<u64> buff_u64(8);

    // PVIA sidecar for the prover-local cubic polynomial before rank-0 weighting.
    vector<F> pvia_local_poly = {H.a,H.b,H.c,H.d};
    vector<u64> pvia_local_payload;
    field_vector_serialize(pvia_local_poly,pvia_local_payload);
    std::array<u64, pvia::META_WORDS> pvia_meta{};
    const bool pvia_on = pvia::Runtime::instance().enabled();
    if (pvia_on) {
        pvia_meta = pvia::Runtime::instance().make_pending_meta(pvia_local_payload, false);
        pvia::Runtime::instance().observe_local_meta(pvia_meta, pvia_local_payload);
    }

    com_rounds+=2;
    std::array<u64, pvia::META_WORDS> pvia_aggregate_meta{};
    if(rank == 0){
        H.a  = v[0]*H.a;
        H.b  = v[0]*H.b;
        H.c  = v[0]*H.c;
        H.d  = v[0]*H.d;
        
        for(int i = 1; i < N; i++){
            std::array<u64, pvia::META_WORDS> remote_meta{};
            if (pvia_on) {
                MPI_Recv(remote_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                         i, pvia::META_TAG, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            }
            MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            if (pvia_on)
                pvia::Runtime::instance().observe_remote_meta(i, remote_meta, buff_u64);
            field_vector_deserialize(buff_u64,buff);
            H = H + cubic_poly(v[i]*buff[0],v[i]*buff[1],v[i]*buff[2],v[i]*buff[3]);
        }
        buff = {H.a,H.b,H.c,H.d};
        if (pvia_on) pvia_aggregate_meta = pvia::bind_rank0_aggregate(
            buff, "DSC_AGGREGATE_CUBIC", rank,
            pvia::make_aggregation_aux(v, N),
            pvia::AuditRelationKernel::AGGREGATE_WEIGHTED);
        field_vector_serialize(buff,buff_u64);
    }else{
        buff = {H.a,H.b,H.c,H.d};
        field_vector_serialize(buff,buff_u64);
        cm += 8*buff_u64.size()/1024.0;
        if (pvia_on) {
            pvia::Runtime::instance().seal_transfer_meta(pvia_meta, buff_u64);
            pvia::Runtime::instance().observe_outgoing_transfer(pvia_meta, buff_u64);
            MPI_Send(pvia_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                     0, pvia::META_TAG, MPI_COMM_WORLD);
        }
        MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD);
    }
    if(rank == 0) cm += (N-1)*8*buff_u64.size()/1024.0;
    if (release_name) enforce_named_aggregate_release_gate(
        release_name, gate_phase, gate_round);
    myBcast(buff_u64, N);
    if (pvia_on) pvia::publish_rank0_aggregate_meta(
        pvia_aggregate_meta, buff_u64, rank);
    //MPI_Bcast(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,MPI_COMM_WORLD);
    field_vector_deserialize(buff_u64,buff);
    H = cubic_poly(buff[0],buff[1],buff[2],buff[3]);
    if (pvia_on) pvia::Runtime::instance().consume_pending();
    return H;
}


cubic_poly aggregate_poly(
    cubic_poly H, int N, vector<F> &v, const char* release_name) {
    return aggregate_poly(
        H, N, v, release_name, pvia::Phase::DISTRIBUTED_SUMCHECK,
        pvia::Runtime::instance().pending_round());
}

vector<pair<F,vector<F>>> _quadratic_sumcheck(F y, vector<F> &v1, vector<F> &v2, int N){
	//int offset = 4;
    //vector<F> r = generate_randomness(int(log2(v1.size())));
	int offset = sumcheck_offset;
    
    int rounds = int(log2(v1.size()))-offset;
	int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    com_rounds+=2;
    
    F rand;
	vector<F> r;
    if(rounds > 0){
        for(int i = 0; i < rounds; i++){
            
            pt_cp.start();
    
            quadratic_poly poly = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
            linear_poly l1,l2;
                
            int L = 1 << ((int)log2(v1.size()) -1- i);
            for(int j = 0; j < L; j++){
                l1 = linear_poly(v1[2*j+1] - v1[2*j],v1[2*j]);
                l2 = linear_poly(v2[2*j+1] - v2[2*j],v2[2*j]);
                poly = poly + (l1*l2);
            }

            vector<F> input;
            pt_cp.end();
            if (pvia::Runtime::instance().enabled() &&
                !pvia_verify_distributed_quadratic(poly, v1, v2, static_cast<size_t>(L))) {
                pvia::Runtime::instance().handle_global_failure(
                    "distributed_quadratic_local_arithmetic",
                    pvia::Phase::DISTRIBUTED_SUMCHECK, i);
                return {};
            }

            // PVIA: bind the prover-local distributed-Sumcheck polynomial
            // before aggregation, then optionally inject a real coefficient fault.
            pvia::RecordId pvia_record = 0;
            if (pvia::Runtime::instance().enabled()) {
                auto& rt = pvia::Runtime::instance();
                const size_t active_count = static_cast<size_t>(2 * L);
                const std::vector<pvia::FieldStateSegment> pvia_source_segments = {
                    {&v1, 0, active_count}, {&v2, 0, active_count}};
                const pvia::StateId source_state = rt.import_state_slices(
                    "distributed_quadratic_round_input",
                    pvia::Phase::DISTRIBUTED_SUMCHECK, pvia_source_segments);
                std::vector<pvia::OperationRef> predecessors;
                const auto predecessor = rt.previous_round_operation_ref(
                    pvia::Phase::DISTRIBUTED_SUMCHECK,
                    static_cast<uint32_t>(i), pvia::Obligation::PUBLISH);
                if (predecessor.object_id != 0) predecessors.push_back(predecessor);
                pvia_record = rt.register_quadratic_operation(
                    pvia::Phase::DISTRIBUTED_SUMCHECK, i,
                    pvia::Obligation::DERIVE, poly, predecessors);
                rt.bind_state_dependencies(
                    pvia_record, std::vector<pvia::StateId>{source_state});
                rt.bind_relation_kernel(
                    pvia_record, pvia::AuditRelationKernel::DSC_QUADRATIC);
                vector<F> pvia_round_aux = {y};
                if (!r.empty()) pvia_round_aux.push_back(r.back());
                rt.bind_public_field_aux(
                    pvia_record, pvia::AuditPublicAuxKind::SUMCHECK_CHALLENGE,
                    pvia_round_aux);
                pvia::Runtime::instance().activate_quadratic(pvia_record, poly);
            }

            poly = aggregate_poly(
                poly, N, "distributed_quadratic_round_release",
                pvia::Phase::DISTRIBUTED_SUMCHECK, static_cast<uint32_t>(i));
            pt_cp.start();
            if(rank == 0)vt.start();
            
            if(poly.eval(0)+ poly.eval(1) != y){
                printf("Error in distributed sumcheck round %d\n",i);
                if (pvia::Runtime::instance().enabled()) {
                    pvia::Runtime::instance().handle_global_failure(
                        "distributed_quadratic_sumcheck",
                        pvia::Phase::DISTRIBUTED_SUMCHECK, i);
                } else {
                    exit(-1);
                }
            }
            rand = hash_to_field({poly.a,poly.b,poly.c});
            if(rank == 0)ps_plain += 16*(3)/1024.0;
        
            y = poly.eval(rand);
            if(rank == 0)vt.end();
        
            r.push_back(rand);        
            for(int j = 0; j < L; j++){
                v1[j] = rand*(v1[2*j+1]-v1[2*j]) + v1[2*j];
                v2[j] = rand*(v2[2*j+1]-v2[2*j]) + v2[2*j];
            }
            pt_cp.end();
    
        }
    }else{
        offset = int(log2(v1.size()));
    }
	
    vector<F> final_v1(1<<(offset)),final_v2(1<<(offset)),buff;
    vector<u64> buff_u64;
    for(int i = 0; i  <final_v1.size(); i++){
        final_v1[i] = v1[i];
        final_v2[i] = v2[i];
    }

    vector<F> reply;
    if(rank == 0){
        int idx = final_v1.size(); 
        buff_u64.resize(4*final_v1.size());    
        final_v1.resize(final_v1.size()*N,F(0));
        final_v2.resize(final_v2.size()*N,F(0));
        vector<vector<u64>> recv_buff(N);
        vector<MPI_Request> req(N);
        for(int i = 1; i < N; i++){
            recv_buff[i].resize(4*final_v1.size());
            //MPI_Recv(recv_buff[i].data(),recv_buff[i].size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);   
            MPI_Irecv(recv_buff[i].data(),recv_buff[i].size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i]);   
        }
        for(int i = 1; i < N; i++){
            std::array<u64, pvia::META_WORDS> remote_meta{};
            if (pvia::Runtime::instance().enabled()) {
                MPI_Recv(remote_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                         i, pvia::META_TAG, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            }
            MPI_Wait(&req[i],MPI_STATUS_IGNORE);
            if (pvia::Runtime::instance().enabled()) {
                pvia::Runtime::instance().observe_remote_meta(
                    i, remote_meta, recv_buff[i]);
            }
            field_vector_deserialize(recv_buff[i],buff);
            for(int j = 0; j < (1<<offset); j++){
                final_v1[idx] = buff[j];
                final_v2[idx] = buff[j+ (buff.size()/2)];
                idx++;
            }
        }
        if (pvia::Runtime::instance().enabled()) {
            pvia::Runtime::instance().import_state(
                "distributed_reduced_v1", pvia::Phase::DISTRIBUTED_SUMCHECK,
                final_v1);
            pvia::Runtime::instance().import_state(
                "distributed_reduced_v2", pvia::Phase::DISTRIBUTED_SUMCHECK,
                final_v2);
        }
        pt_cp.start();
        
        vector<pair<F,vector<F>>> res = quadratic_sumcheck(y,final_v1,final_v2,F(0));
        if(rank == 0)ps_plain += 16*(2+3*(int)log2(N))/1024.0;
        
        reply.push_back(res[0].first);
        reply.push_back(res[1].first);
        reply.insert(reply.end(),res[0].second.begin(),res[0].second.end());
        field_vector_serialize(reply,buff_u64);
        pt_cp.end();
    
    }else{
        buff = final_v1; buff.insert(buff.end(),final_v2.begin(),final_v2.end());

        // PVIA: the reduced state handed to rank 0 is a separate SEND
        // obligation. Register the expected transfer value before deriving
        // the execution-bound transfer metadata.
        pvia::RecordId transfer_record = 0;
        if (pvia::Runtime::instance().enabled()) {
            auto& rt = pvia::Runtime::instance();
            std::vector<pvia::OperationRef> predecessors;
            const auto predecessor = rt.previous_round_operation_ref(
                pvia::Phase::DISTRIBUTED_SUMCHECK,
                static_cast<uint32_t>(rounds), pvia::Obligation::PUBLISH);
            if (predecessor.object_id != 0) predecessors.push_back(predecessor);
            transfer_record = rt.register_vector_operation(
                pvia::Phase::DISTRIBUTED_SUMCHECK,
                static_cast<uint32_t>(rounds),
                pvia::Obligation::SEND, buff, predecessors);
            pvia::Runtime::instance().activate_vector(transfer_record, buff);
        }

        field_vector_serialize(buff,buff_u64);
        cm += 8*buff_u64.size()/1024.0;

        if (pvia::Runtime::instance().enabled()) {
            auto transfer_meta =
                pvia::Runtime::instance().make_pending_meta(buff_u64, false);
            pvia::Runtime::instance().seal_transfer_meta(transfer_meta, buff_u64);
            pvia::Runtime::instance().observe_outgoing_transfer(transfer_meta, buff_u64);
            pvia::Runtime::instance().observe_local_payload(buff_u64);
            MPI_Send(transfer_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                     0, pvia::META_TAG, MPI_COMM_WORLD);
        }

        MPI_Request req;
        MPI_Isend(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
        if (pvia::Runtime::instance().enabled()) {
            pvia::Runtime::instance().consume_pending();
        }
        
        //MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        buff_u64.clear();buff_u64.resize(2*(2+offset+(int)log2(N))); 
    }
    if(rank == 0) cm += (N-1)*8*buff_u64.size()/1024.0;
    myBcast(buff_u64, N);
    //MPI_Bcast(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,MPI_COMM_WORLD);
	if(rank != 0){
        field_vector_deserialize(buff_u64,reply);
    }
    for(int i = 2; i < reply.size(); i++){
        r.push_back(reply[i]);
    }
  
    return {make_pair(reply[0] ,r),make_pair(reply[1] ,r)};
}

F compute_ip(vector<F> &v1, vector<F> &v2, int poly_degree, int size, vector<F> beta, vector<F> beta2){
    vector<F> poly(poly_degree*(poly_degree+1)/2,F(0));
    int ctr = 0;
	F sum = F(0);
    F sum2 = 0;
    int rank;
    
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    for(int i = 0; i < v1.size()/size; i++){
        //for(int l = 0; l < poly_degree; l++){
        if(size != poly_degree){
            printf("Abort %d,%d\n",size,poly_degree);
            exit(-1);
        }
        vector<F> temp_v1(poly_degree),temp_v2(poly_degree);
        for(int l = 0; l < poly_degree; l++){
			temp_v1[l] = v1[poly_degree*i + l];
			temp_v2[l] = v2[poly_degree*i + l];
            sum += beta[ctr]*temp_v2[l]*temp_v1[l];
            
        }

        
         //}
        
        if(((i != 0 || v1.size()/(size*beta.size()) == 1)) && beta.size() && !(i%(v1.size()/(size*beta.size())))){
            ctr++;
        }
         
    }
    
    
    //printf("Size: %d,%d, (%lld,%lld)\n",beta.size(),poly_degree*v1.size()/size,sum2.real,sum2.img);
    return sum;
}

vector<F> _sparrow_quadratic_sumcheck_step1(vector<F> &v1, vector<F> &v2, int poly_degree, int size, vector<F> beta = {}){
    vector<F> poly;
    if(poly_degree <= 16) poly.resize(poly_degree*(poly_degree+1)/2,F(0));
    else poly.resize(2*poly_degree,F(0));

    int ctr = 0;
	int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    F sum = 0;
    for(int i = 0; i < v1.size()/size; i++){
        if((i != 0 ) && beta.size() && !(i%(v1.size()/(size*beta.size())))) {
            ctr++;
        }
        vector<F> temp_v1(poly_degree),temp_v2(poly_degree);
        for(int l = 0; l < poly_degree; l++){
            temp_v1[l] = v1[poly_degree*i + l];
            temp_v2[l] = v2[poly_degree*i + l];
            sum += beta[ctr]*temp_v2[l]*temp_v1[l];
        }
            
        if(poly_degree <= 16){
            int idx = 0;
            for(int l = 0; l < poly_degree; l++){
                for(int h = l+1; h < poly_degree; h++){
                    if(beta.size()) poly[idx] += beta[ctr]*(temp_v1[l]*temp_v2[h] + temp_v1[h]*temp_v2[l]);
                    else poly[idx] += temp_v1[l]*temp_v2[h] + temp_v1[h]*temp_v2[l];
                    idx++;
                }
            }
                        
            for(int l = 0; l < poly_degree; l++){
                if(beta.size()) poly[idx] += beta[ctr]*temp_v1[l]*temp_v2[l];
                else poly[idx] += temp_v1[l]*temp_v2[l];
                idx++;
            }
        }else{
            fft(temp_v1,(int)log2(temp_v1.size()),true);
            fft(temp_v2,(int)log2(temp_v2.size()),true);
            temp_v1.resize(2*temp_v1.size(),F(0));
            temp_v2.resize(2*temp_v2.size(),F(0));
            fft(temp_v1,(int)log2(temp_v2.size()),false);
            fft(temp_v2,(int)log2(temp_v2.size()),false);
            for(int l = 0; l < poly.size(); l++){
                if(beta.size()) poly[l] += beta[ctr]*temp_v1[l]*temp_v2[l];
                else poly[l] += temp_v1[l]*temp_v2[l];
            }
        }
        
        
    }
    return poly;
}

F _sparrow_quadratic_sumcheck_step2(vector<F> &v1, vector<F> &v2, F rand, int poly_degree, int size){
    vector<F> L = compute_lagrange_coeff(getRootOfUnity((int)log2(poly_degree)),rand,poly_degree);
    int i = 0;
    F sum = F(0);
    for(i = 0; i < v1.size()/((size)); i++){
        F sum1 = F(0),sum2 = F(0);
        for(int l = 0; l < poly_degree; l++){
            sum1 += L[l]*v1[poly_degree*i + l];
			sum2 += L[l]*v2[poly_degree*i + l];
		}
        v1[i] = sum1;
        v2[i] = sum2;
        sum += v1[i]*v2[i];
    }
    return sum;

}

vector<pair<F,vector<F>>> _cubic_sumcheck_sparrow(F y, vector<F> &v1, vector<F> &v2, vector<F> &beta1, vector<F> &beta2, vector<F> &beta3, int N){
	int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    com_rounds+=4;
    int offset = sumcheck_offset;
    vector<int> degrees;
    
    vector<F> original_v1 = v1,original_v2 = v2;   
        
    int rounds = int(log2(v1.size()))-offset;
    if(rounds <= 8){
        if(rounds%4 != 0) degrees.push_back(rounds - 4*((int)rounds/4));
        
        for(int i = 0; i < rounds/4; i++){
            degrees.push_back(4);
        }
    }else{
        degrees.push_back(4);
        degrees.push_back(rounds - 4);
    }
    //if(!rank) printf("%d\n",degrees.size());    
    
    F rand;
	vector<F> r;
    vector<F> Lambdas(1,1);    
    
    for(int i = 0; i < v1.size(); i++) v1[i] = beta1[i%beta1.size()]*v1[i];
    
   
	if(rounds > 0){
        int _s = 1;
        vector<F> challenges;
        for(int i = 0; i < degrees.size(); i++){
            _s *= (1<<degrees[i]);
            /*
            if(i == 0){
                F ip = compute_ip(v1, v2, 1<<degrees[0], 1<<degrees[0], beta2,beta1);
                vector<F> ip_v = {beta3[rank]*ip};
                
                ip_v = aggregate_quadratic_poly_sparrow(ip_v,N);
                if(ip_v[0] != y){
                    if(!rank) printf("EERROR (%lld,%lld)\n",ip_v[0].real,ip_v[0].img);
                }
                
            }
            */
            
            pt_cp.start();
            vector<F> poly = _sparrow_quadratic_sumcheck_step1(v1, v2, 1<<degrees[i], _s, beta2);
            for(int j = 0; j < poly.size(); j++){
                poly[j] = beta3[rank]*poly[j];
            }
            pt_cp.end();

            pvia::RecordId pvia_record = 0;
            if (pvia::Runtime::instance().enabled()) {
                auto& rt = pvia::Runtime::instance();
                const vector<F> beta3_local = {beta3[rank]};
                const pvia::StateId source_state = rt.import_state_slices(
                    "sparrow_cubic_round_input",
                    pvia::Phase::DISTRIBUTED_SUMCHECK,
                    std::vector<pvia::FieldStateSegment>{
                        {&v1, 0, v1.size()},
                        {&v2, 0, v2.size()},
                        {&beta2, 0, beta2.size()},
                        {&beta3_local, 0, beta3_local.size()}});
                std::vector<pvia::OperationRef> predecessors;
                const auto predecessor = rt.previous_round_operation_ref(
                    pvia::Phase::DISTRIBUTED_SUMCHECK,
                    static_cast<uint32_t>(i), pvia::Obligation::PUBLISH);
                if (predecessor.object_id != 0) predecessors.push_back(predecessor);
                pvia_record = rt.register_vector_operation(
                    pvia::Phase::DISTRIBUTED_SUMCHECK, i,
                    pvia::Obligation::DERIVE, poly, predecessors);
                rt.bind_state_dependencies(
                    pvia_record, std::vector<pvia::StateId>{source_state});
                rt.bind_relation_kernel(
                    pvia_record, pvia::AuditRelationKernel::DSC_SPARROW_CUBIC);
                vector<F> pvia_round_aux = {
                    y, beta3[rank], F(degrees[i])};
                if (!challenges.empty())
                    pvia_round_aux.push_back(challenges.back());
                rt.bind_public_field_aux(
                    pvia_record, pvia::AuditPublicAuxKind::SUMCHECK_CHALLENGE,
                    pvia_round_aux);
                pvia::Runtime::instance().activate_vector(pvia_record, poly);
            }

            sch_com.start();
            poly = aggregate_quadratic_poly_sparrow(
                poly, N, "distributed_sparrow_cubic_round_release",
                pvia::Phase::DISTRIBUTED_SUMCHECK, static_cast<uint32_t>(i));
            sch_com.end();
            
            pt_cp.start();

            if(rank == 0)vt.start();
            
            if(sparrow_V_check(poly,1<<degrees[i]) != y){
                printf("Error in distributed sumcheck round %d, %d, (%lld,%lld),(%lld,%lld)\n",i,poly.size(),poly[0].real,poly[0].img,y.real,y.img);
                if (pvia::Runtime::instance().enabled())
                    pvia::Runtime::instance().handle_global_failure(
                        "sparrow_cubic_sumcheck",
                        pvia::Phase::DISTRIBUTED_SUMCHECK, i);
                else exit(-1);
            }
            rand = hash_to_field({});
            challenges.push_back(rand);
            if(rank == 0)ps_plain += 16*4/1024.0;
            
            y = evaluate_poly_extended(poly, {}, rand, degrees[i]);
            if(rank == 0)vt.end();
            //r.push_back(rand);        
            F sum = _sparrow_quadratic_sumcheck_step2(v1,v2,rand,1<<degrees[i],_s);
            pt_cp.end();
            
    
        } 
        if(rank == 0){
            pt_cp.start();
            for(int i = 0; i < challenges.size(); i++){
                vector<F> L = compute_lagrange_coeff(getRootOfUnity(degrees[i]),challenges[i],1<<degrees[i]);
                vector<F> buff = Lambdas;
                Lambdas.resize(Lambdas.size()*L.size());
                for(int j = 0; j < L.size(); j++){
                    for(int k = 0; k < buff.size(); k++){
                        Lambdas[j*buff.size() + k] = buff[k]*L[j];
                    }
                }
            }
            if(Lambdas.size() != _s){
                printf("Error\n");
            }
            pt_cp.end();


        }
    }else{
        offset = int(log2(v1.size()));
    }
    pt_cp.start();
        
    vector<F> final_v1(1<<(offset)),final_v2(1<<(offset)),buff;
    vector<u64> buff_u64;
    for(int i = 0; i  <final_v1.size(); i++){
        final_v1[i] = v1[i];
        final_v2[i] = v2[i];
    }
    pt_cp.end();
        
    vector<F> reply;
    if(rank == 0){
        int idx = final_v1.size(); 
        pt_cp.start();
        
        vector<vector<u64>> recv_buff(N-1);
        for(int i = 0; i < N-1; i++)recv_buff[i].resize(4*final_v1.size());
        //buff_u64.resize(6*final_v1.size());    
        final_v1.resize(final_v1.size()*N,F(0));
        final_v2.resize(final_v2.size()*N,F(0));
        vector<MPI_Request> req(N-1);
        pt_cp.end();
        
        sch_com.start();
        
        for(int i = 1; i < N; i++){
            MPI_Irecv(recv_buff[i-1].data(),recv_buff[i-1].size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i-1]);
            
        }
        for(int i = 1; i < N; i++){
            std::array<u64, pvia::META_WORDS> remote_meta{};
            if (pvia::Runtime::instance().enabled()) {
                MPI_Recv(remote_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                         i, pvia::META_TAG, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            }
            //MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            MPI_Wait(&req[i-1],MPI_STATUS_IGNORE);
            if (pvia::Runtime::instance().enabled()) {
                pvia::Runtime::instance().observe_remote_meta(
                    i, remote_meta, recv_buff[i-1]);
            }
            field_vector_deserialize(recv_buff[i-1],buff);
            for(int j = 0; j < (1<<offset); j++){
                final_v1[idx] = buff[j];
                final_v2[idx] = buff[j+ (buff.size()/2)];
                idx++;
            }   
        }
        if (pvia::Runtime::instance().enabled()) {
            pvia::Runtime::instance().import_state(
                "sparrow_cubic_reduced_v1",
                pvia::Phase::DISTRIBUTED_SUMCHECK, final_v1);
            pvia::Runtime::instance().import_state(
                "sparrow_cubic_reduced_v2",
                pvia::Phase::DISTRIBUTED_SUMCHECK, final_v2);
        }
        sch_com.end();
        pt_cp.start();
        
        vector<F> B(beta2.size()*beta3.size());
        for(int i = 0; i < beta3.size(); i++){
            for(int j = 0; j < beta2.size(); j++){
                B[i*beta2.size() + j] = beta3[i]*beta2[j];
            }
        }
        vector<pair<F,vector<F>>> res = cubic_sumcheck(y,final_v1,final_v2,B,F(0));
        ps_plain += 16*(2+4*(int)log2(N))/1024.0;
        
        reply.push_back(res[0].first);
        reply.push_back(res[1].first);
        reply.insert(reply.end(),res[0].second.begin(),res[0].second.end());
        field_vector_serialize(reply,buff_u64);
        pt_cp.end();

    }else{
        buff = final_v1; 
        buff.insert(buff.end(),final_v2.begin(),final_v2.end());

        pvia::RecordId transfer_record = 0;
        if (pvia::Runtime::instance().enabled()) {
            auto& rt = pvia::Runtime::instance();
            std::vector<pvia::OperationRef> predecessors;
            const auto predecessor =
                rt.latest_operation_ref(pvia::Phase::DISTRIBUTED_SUMCHECK);
            if (predecessor.object_id != 0)
                predecessors.push_back(predecessor);
            transfer_record = rt.register_vector_operation(
                pvia::Phase::DISTRIBUTED_SUMCHECK,
                static_cast<uint32_t>(rounds),
                pvia::Obligation::SEND, buff, predecessors);
            rt.bind_relation_kernel(
                transfer_record,
                pvia::AuditRelationKernel::DSC_SPARROW_CUBIC);
            rt.activate_vector(transfer_record, buff);
        }

        field_vector_serialize(buff,buff_u64);
        cm += 8*buff_u64.size()/1024.0;
        if (pvia::Runtime::instance().enabled()) {
            auto transfer_meta =
                pvia::Runtime::instance().make_pending_meta(buff_u64, false);
            pvia::Runtime::instance().seal_transfer_meta(
                transfer_meta, buff_u64);
            pvia::Runtime::instance().observe_outgoing_transfer(
                transfer_meta, buff_u64);
            pvia::Runtime::instance().observe_local_payload(buff_u64);
            MPI_Send(
                transfer_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                0, pvia::META_TAG, MPI_COMM_WORLD);
        }
        MPI_Request req;
        MPI_Isend(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
        if (pvia::Runtime::instance().enabled()) {
            pvia::Runtime::instance().consume_pending();
        }
        buff_u64.clear();buff_u64.resize(2*(2+offset+(int)log2(N))); 
    }
    if(rank == 0) cm += (N-1)*8*buff_u64.size()/1024.0;
    sch_com.start();

    myBcast(buff_u64, N);
    sch_com.end();
    //MPI_Bcast(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,MPI_COMM_WORLD);
	pt_cp.start();
    if(rank != 0){
        field_vector_deserialize(buff_u64,reply);
    }
    F y1_claim = reply[0];
    F y2_claim = reply[1];
    
    for(int i = 2; i < reply.size(); i++){
        r.push_back(reply[i]);
    }
    vector<F> r_last = r;
    vector<F> r1,r2;
    for(int i = 0; i < offset; i++) r1.push_back(r[i]);
    for(int i = (offset); i < r.size(); i++) r2.push_back(r[i]);
    vector<F> beta; precompute_beta(r1,beta);
    
    //for(int i = 0; i < beta.size(); i++){
    //    beta[i] = _beta(rank,r2)*beta[i];
   // }
    vector<F> aggr_v1(v1.size()/(1<<offset),F(0)),aggr_v2(v1.size()/(1<<offset),F(0));
    for(int j = 0; j < beta.size(); j++){
        for(int i = 0; i < aggr_v1.size(); i++){
            aggr_v1[i] += original_v1[aggr_v1.size()*j + i]*beta[j];
            aggr_v2[i] += original_v2[aggr_v2.size()*j + i]*beta[j];
        } 
    }
    pt_cp.end();

    if(rank == 0){
        int idx = aggr_v1.size(); 
        
        sch_com.start();

        
        vector<vector<u64>> recv_buff(N-1);
        for(int i = 0; i < N-1; i++)recv_buff[i].resize(4*aggr_v1.size());
        //buff_u64.resize(6*final_v1.size());    
        aggr_v1.resize(aggr_v1.size()*N,F(0));
        aggr_v2.resize(aggr_v2.size()*N,F(0));
        vector<MPI_Request> req(N-1);
        for(int i = 1; i < N; i++){
            MPI_Irecv(recv_buff[i-1].data(),recv_buff[i-1].size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i-1]);
            
        }
        for(int i = 1; i < N; i++){
            //MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            MPI_Wait(&req[i-1],MPI_STATUS_IGNORE);
            field_vector_deserialize(recv_buff[i-1],buff);
            for(int j = 0; j < aggr_v1.size()/N; j++){
                aggr_v1[idx] = buff[j];
                aggr_v2[idx] = buff[j+ (buff.size()/2)];
                idx++;
            }   
        }
        sch_com.end();

        pt_cp.start();
        vector<F> extended_lambdas,extended_beta;
        for(int i =0 ; i < N; i++){
            extended_lambdas.insert(extended_lambdas.end(),Lambdas.begin(),Lambdas.end());
            extended_beta.insert(extended_beta.end(),beta1.begin(),beta1.end());
        }
        for(int j = 0; j < N; j++){
            for(int i = 0; i < Lambdas.size(); i++){
                extended_lambdas[Lambdas.size()*j+i] = _beta(j,r2)*extended_lambdas[Lambdas.size()*j+i];
            }
        }
        
        F a = F::_random();

        vector<pair<F,vector<F>>> res = batch_cubic_sumcheck(aggr_v1,extended_beta,aggr_v2,extended_lambdas,y1_claim+a*y2_claim,a);
        
        ps_plain += 16*(3+4*(int)log2(N))/1024.0;
        reply.clear();
        reply.push_back(res[0].first);

        reply.push_back(res[2].first);
        reply.insert(reply.end(),res[0].second.begin(),res[0].second.end());
        field_vector_serialize(reply,buff_u64);
        pt_cp.end();
    
    }else{
        buff = aggr_v1; 
        buff.insert(buff.end(),aggr_v2.begin(),aggr_v2.end());
        field_vector_serialize(buff,buff_u64);
        cm += 8*buff_u64.size()/1024.0;
        MPI_Request req;
        
        MPI_Isend(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
        buff_u64.clear();buff_u64.resize(2*(2+(int)log2(N*aggr_v1.size()))); 
        //printf(">> %d\n",buff_u64.size());
    }
    if(rank == 0) cm += (N-1)*8*buff_u64.size()/1024.0;
    sch_com.start();

    myBcast(buff_u64, N);
    sch_com.end();

    if(rank != 0){
        field_vector_deserialize(buff_u64,reply);
    }
    
    r.clear();
    for(int i = 2; i < reply.size()-(int)log2(N); i++) r.push_back(reply[i]);
    
    r.insert(r.end(),r1.begin(),r1.end());
    for(int i = reply.size()-(int)log2(N); i < reply.size(); i++) r.push_back(reply[i]);
    
    return {make_pair(reply[0] ,r),make_pair(reply[1] ,r) };
}

vector<pair<F,vector<F>>> _quadratic_sumcheck_sparrow(F y, vector<F> &v1, vector<F> &v2, int N){
	int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    com_rounds+=2;
    int offset = sumcheck_offset;
    vector<int> degrees;
    //int offset = 4;
    //vector<F> r = generate_randomness(int(log2(v1.size())));
    int rounds = int(log2(v1.size()))-offset;
    if(rounds%4 != 0) degrees.push_back(rounds - 4*((int)rounds/4));
    vector<F> original_v1 = v1,original_v2 = v2;   
    for(int i = 0; i < rounds/4; i++){
        degrees.push_back(4);
    }
    
    F rand;
	vector<F> r;
    vector<F> Lambdas(1,1);    
    
        
	if(rounds > 0){
        int s = 1;
        vector<F> challenges;
        for(int i = 0; i < degrees.size(); i++){
            s *= (1<<degrees[i]);
        
            pt_cp.start();

            vector<F> poly = _sparrow_quadratic_sumcheck_step1(v1, v2, 1<<degrees[i], s);
            
            pt_cp.end();

            pvia::RecordId pvia_record = 0;
            if (pvia::Runtime::instance().enabled()) {
                auto& rt = pvia::Runtime::instance();
                const std::vector<pvia::FieldStateSegment> pvia_source_segments = {
                    {&v1, 0, v1.size()}, {&v2, 0, v2.size()}};
                const pvia::StateId source_state = rt.import_state_slices(
                    "sparrow_quadratic_round_input",
                    pvia::Phase::DISTRIBUTED_SUMCHECK, pvia_source_segments);
                std::vector<pvia::OperationRef> predecessors;
                const auto predecessor = rt.previous_round_operation_ref(
                    pvia::Phase::DISTRIBUTED_SUMCHECK,
                    static_cast<uint32_t>(i), pvia::Obligation::PUBLISH);
                if (predecessor.object_id != 0) predecessors.push_back(predecessor);
                pvia_record = rt.register_vector_operation(
                    pvia::Phase::DISTRIBUTED_SUMCHECK, i,
                    pvia::Obligation::DERIVE, poly, predecessors);
                rt.bind_state_dependencies(
                    pvia_record, std::vector<pvia::StateId>{source_state});
                rt.bind_relation_kernel(
                    pvia_record, pvia::AuditRelationKernel::DSC_SPARROW_QUADRATIC);
                vector<F> pvia_round_aux = {y, F(degrees[i])};
                if (!challenges.empty())
                    pvia_round_aux.push_back(challenges.back());
                rt.bind_public_field_aux(
                    pvia_record, pvia::AuditPublicAuxKind::SUMCHECK_CHALLENGE,
                    pvia_round_aux);
                pvia::Runtime::instance().activate_vector(pvia_record, poly);
            }

            poly = aggregate_quadratic_poly_sparrow(
                poly, N, "distributed_sparrow_quadratic_round_release",
                pvia::Phase::DISTRIBUTED_SUMCHECK, static_cast<uint32_t>(i));
            pt_cp.start();
        
            if(rank == 0)vt.start();
        
            if(sparrow_V_check(poly,1<<degrees[i]) != y){
                printf("Error in distributed sumcheck round %d\n",i);
                if (pvia::Runtime::instance().enabled())
                    pvia::Runtime::instance().handle_global_failure(
                        "sparrow_quadratic_sumcheck",
                        pvia::Phase::DISTRIBUTED_SUMCHECK, i);
                else exit(-1);
            }
            rand = hash_to_field(poly);
            challenges.push_back(rand);
            if(rank == 0)ps_plain += 16*4/1024.0;
            
            y = evaluate_poly_extended(poly, {}, rand, degrees[i]);
            if(rank == 0)vt.end();
            //r.push_back(rand);        
            F sum = _sparrow_quadratic_sumcheck_step2(v1,v2,rand,1<<degrees[i],s);
            pt_cp.end();
    
        } 
        if(rank == 0){
            pt_cp.start();

            for(int i = 0; i < challenges.size(); i++){
                vector<F> L = compute_lagrange_coeff(getRootOfUnity(degrees[i]),challenges[i],1<<degrees[i]);
                vector<F> buff = Lambdas;
                Lambdas.resize(Lambdas.size()*L.size());
                for(int j = 0; j < L.size(); j++){
                    for(int k = 0; k < buff.size(); k++){
                        Lambdas[j*buff.size() + k] = buff[k]*L[j];
                    }
                }
            }
            if(Lambdas.size() != s){
                printf("Error\n");
            }
            pt_cp.end();

        }
    }else{
        offset = int(log2(v1.size()));
    }
    pt_cp.start();

    vector<F> final_v1(1<<(offset)),final_v2(1<<(offset)),buff;
    vector<u64> buff_u64;
    for(int i = 0; i  <final_v1.size(); i++){
        final_v1[i] = v1[i];
        final_v2[i] = v2[i];
    }
    pt_cp.end();

    vector<F> reply;
    if(rank == 0){
        int idx = final_v1.size(); 
        
        vector<vector<u64>> recv_buff(N-1);
        for(int i = 0; i < N-1; i++)recv_buff[i].resize(4*final_v1.size());
        //buff_u64.resize(6*final_v1.size());    
        final_v1.resize(final_v1.size()*N,F(0));
        final_v2.resize(final_v2.size()*N,F(0));
        vector<MPI_Request> req(N-1);
        for(int i = 1; i < N; i++){
            MPI_Irecv(recv_buff[i-1].data(),recv_buff[i-1].size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i-1]);
            
        }
        for(int i = 1; i < N; i++){
            //MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            MPI_Wait(&req[i-1],MPI_STATUS_IGNORE);
            field_vector_deserialize(recv_buff[i-1],buff);
            for(int j = 0; j < (1<<offset); j++){
                final_v1[idx] = buff[j];
                final_v2[idx] = buff[j+ (buff.size()/2)];
                idx++;
            }   
        }
        pt_cp.start();
    
        vector<pair<F,vector<F>>> res = quadratic_sumcheck(y,final_v1,final_v2,F(0));
        ps_plain += 16*(2+4*(int)log2(N))/1024.0;
        
        reply.push_back(res[0].first);
        reply.push_back(res[1].first);
        reply.insert(reply.end(),res[0].second.begin(),res[0].second.end());
        field_vector_serialize(reply,buff_u64);
        pt_cp.end();

    }else{
        buff = final_v1; 
        buff.insert(buff.end(),final_v2.begin(),final_v2.end());
        field_vector_serialize(buff,buff_u64);
        cm += 8*buff_u64.size()/1024.0;
        MPI_Request req;
        MPI_Isend(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
        buff_u64.clear();buff_u64.resize(2*(2+offset+(int)log2(N))); 
    }
    if(rank == 0) cm += (N-1)*8*buff_u64.size()/1024.0;
    myBcast(buff_u64, N);
    
    //MPI_Bcast(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,MPI_COMM_WORLD);
	if(rank != 0){
        field_vector_deserialize(buff_u64,reply);
    }
    
    pt_cp.start();
    F y1_claim = reply[0];
    F y2_claim = reply[1];
    
    for(int i = 2; i < reply.size(); i++){
        r.push_back(reply[i]);
    }
    vector<F> r_last = r;
    vector<F> r1,r2;
    for(int i = 0; i < offset; i++) r1.push_back(r[i]);
    for(int i = (offset); i < r.size(); i++) r2.push_back(r[i]);
    vector<F> beta; precompute_beta(r1,beta);
    
    //for(int i = 0; i < beta.size(); i++){
    //    beta[i] = _beta(rank,r2)*beta[i];
   // }
    vector<F> aggr_v1(v1.size()/(1<<offset),F(0)),aggr_v2(v1.size()/(1<<offset),F(0));
    for(int j = 0; j < beta.size(); j++){
        for(int i = 0; i < aggr_v1.size(); i++){
            aggr_v1[i] += original_v1[aggr_v1.size()*j + i]*beta[j];
            aggr_v2[i] += original_v2[aggr_v2.size()*j + i]*beta[j];
        } 
    }
    pt_cp.end();

    if(rank == 0){
        int idx = aggr_v1.size(); 
        
        vector<vector<u64>> recv_buff(N-1);
        for(int i = 0; i < N-1; i++)recv_buff[i].resize(4*aggr_v1.size());
        //buff_u64.resize(6*final_v1.size());    
        aggr_v1.resize(aggr_v1.size()*N,F(0));
        aggr_v2.resize(aggr_v2.size()*N,F(0));
        vector<MPI_Request> req(N-1);
        for(int i = 1; i < N; i++){
            MPI_Irecv(recv_buff[i-1].data(),recv_buff[i-1].size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i-1]);
            
        }
        for(int i = 1; i < N; i++){
            //MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            MPI_Wait(&req[i-1],MPI_STATUS_IGNORE);
            field_vector_deserialize(recv_buff[i-1],buff);
            for(int j = 0; j < aggr_v1.size()/N; j++){
                aggr_v1[idx] = buff[j];
                aggr_v2[idx] = buff[j+ (buff.size()/2)];
                idx++;
            }   
        }
        pt_cp.start();
        vector<F> extended_lambdas;
        for(int i =0 ; i < N; i++){
            extended_lambdas.insert(extended_lambdas.end(),Lambdas.begin(),Lambdas.end());
        }
        for(int j = 0; j < N; j++){
            for(int i = 0; i < Lambdas.size(); i++){
                extended_lambdas[Lambdas.size()*j+i] = _beta(j,r2)*extended_lambdas[Lambdas.size()*j+i];
            }
        }
        
        F a = F::_random();
        vector<F> aggr_v(aggr_v1.size());
        for(int i = 0; i < aggr_v.size(); i++){
            aggr_v[i] = aggr_v1[i] + a*aggr_v2[i]; 
        }
        vector<pair<F,vector<F>>> res = quadratic_sumcheck(y1_claim+a*y2_claim,extended_lambdas,aggr_v,F(0));
        
        ps_plain += 16*(3+4*(int)log2(N))/1024.0;
        reply.clear();
        reply.push_back(evaluate_vector(aggr_v1,res[0].second));

        reply.push_back(evaluate_vector(aggr_v2,res[0].second));
        reply.insert(reply.end(),res[0].second.begin(),res[0].second.end());
        field_vector_serialize(reply,buff_u64);
        pt_cp.end();
    
    }else{
        buff = aggr_v1; 
        buff.insert(buff.end(),aggr_v2.begin(),aggr_v2.end());
        field_vector_serialize(buff,buff_u64);
        cm += 8*buff_u64.size()/1024.0;
        MPI_Request req;
        MPI_Isend(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
        buff_u64.clear();buff_u64.resize(2*(2+(int)log2(N*aggr_v1.size()))); 
        //printf(">> %d\n",buff_u64.size());
    }
    if(rank == 0) cm += (N-1)*8*buff_u64.size()/1024.0;
    myBcast(buff_u64, N);
    if(rank != 0){
        field_vector_deserialize(buff_u64,reply);
    }
    
    r.clear();
    for(int i = 2; i < reply.size()-(int)log2(N); i++) r.push_back(reply[i]);
    
    r.insert(r.end(),r1.begin(),r1.end());
    for(int i = reply.size()-(int)log2(N); i < reply.size(); i++) r.push_back(reply[i]);
    
    return {make_pair(reply[0] ,r),make_pair(reply[1] ,r) };
}



vector<pair<F,vector<F>>> _cubic_sumcheck(F y, vector<F> &v1, vector<F> &v2, vector<F> &v3, vector<F> &v, int N){
	int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    com_rounds+=2;
    int offset = sumcheck_offset;
    //int offset = 4;
    //vector<F> r = generate_randomness(int(log2(v1.size())));
    int rounds = int(log2(v1.size()))-offset;
	F rand;
	vector<F> r;
	if(rounds > 0){
        for(int i = 0; i < rounds; i++){
            pt_cp.start();
    
            cubic_poly poly = cubic_poly(F_ZERO,F_ZERO,F_ZERO,F_ZERO);
            linear_poly l1,l2,l3;
                
            int L = 1 << ((int)log2(v1.size()) -1- i);
            for(int j = 0; j < L; j++){
                l1 = linear_poly(v1[2*j+1] - v1[2*j],v1[2*j]);
                l2 = linear_poly(v2[2*j+1] - v2[2*j],v2[2*j]);
                l3 = linear_poly(v3[2*j+1] - v3[2*j],v3[2*j]);
                poly = poly + (l1*l2*l3);
            }

            vector<F> input;
            pt_cp.end();

            if (pvia::Runtime::instance().enabled() &&
                !pvia_verify_distributed_cubic(
                    poly, v1, v2, v3, static_cast<size_t>(L))) {
                pvia::Runtime::instance().handle_global_failure(
                    "distributed_cubic_local_arithmetic",
                    pvia::Phase::DISTRIBUTED_SUMCHECK, i);
                return {};
            }
            // PVIA: bind the prover-local cubic relation before the
            // weighted distributed aggregation performed by rank 0.
            pvia::RecordId pvia_record = 0;
            if (pvia::Runtime::instance().enabled()) {
                auto& rt = pvia::Runtime::instance();
                const size_t active_count = static_cast<size_t>(2 * L);
                const std::vector<pvia::FieldStateSegment> pvia_source_segments = {
                    {&v1, 0, active_count}, {&v2, 0, active_count},
                    {&v3, 0, active_count}};
                const pvia::StateId source_state = rt.import_state_slices(
                    "distributed_cubic_round_input",
                    pvia::Phase::DISTRIBUTED_SUMCHECK, pvia_source_segments);
                std::vector<pvia::OperationRef> predecessors;
                const auto predecessor = rt.previous_round_operation_ref(
                    pvia::Phase::DISTRIBUTED_SUMCHECK,
                    static_cast<uint32_t>(i), pvia::Obligation::PUBLISH);
                if (predecessor.object_id != 0) predecessors.push_back(predecessor);
                pvia_record = rt.register_cubic_operation(
                    pvia::Phase::DISTRIBUTED_SUMCHECK, i,
                    pvia::Obligation::DERIVE, poly, predecessors);
                rt.bind_state_dependencies(
                    pvia_record, std::vector<pvia::StateId>{source_state});
                rt.bind_relation_kernel(
                    pvia_record, pvia::AuditRelationKernel::DSC_CUBIC);
                vector<F> pvia_round_aux = {y};
                if (!r.empty()) pvia_round_aux.push_back(r.back());
                rt.bind_public_field_aux(
                    pvia_record, pvia::AuditPublicAuxKind::SUMCHECK_CHALLENGE,
                    pvia_round_aux);
                pvia::Runtime::instance().activate_cubic(pvia_record, poly);
            }
    
            poly = aggregate_poly(
                poly, N, v, "distributed_cubic_round_release",
                pvia::Phase::DISTRIBUTED_SUMCHECK, static_cast<uint32_t>(i));
            pt_cp.start();
        
            if(rank == 0)vt.start();
        
            if(poly.eval(0)+ poly.eval(1) != y){
                printf("Error in distributed sumcheck round %d\n",i);
                if (pvia::Runtime::instance().enabled()) {
                    pvia::Runtime::instance().handle_global_failure(
                        "distributed_cubic_sumcheck",
                        pvia::Phase::DISTRIBUTED_SUMCHECK, i);
                } else {
                    exit(-1);
                }
            }
            rand = hash_to_field({poly.a,poly.b,poly.c,poly.d});
            if(rank == 0)ps_plain += 16*4/1024.0;
            y = poly.eval(rand);
            if(rank == 0)vt.end();
            r.push_back(rand);        
            for(int j = 0; j < L; j++){
                v1[j] = rand*(v1[2*j+1]-v1[2*j]) + v1[2*j];
                v2[j] = rand*(v2[2*j+1]-v2[2*j]) + v2[2*j];
                v3[j] = rand*(v3[2*j+1]-v3[2*j]) + v3[2*j];
            }
            pt_cp.end();
    
        }    
    }else{
        offset = int(log2(v1.size()));
    }
    
    vector<F> final_v1(1<<(offset)),final_v2(1<<(offset)),final_v3(1<<(offset)),buff;
    vector<u64> buff_u64;
    for(int i = 0; i  <final_v1.size(); i++){
        final_v1[i] = v1[i];
        final_v2[i] = v2[i];
        final_v3[i] = v[rank]*v3[i];
    }
    
    vector<F> reply;
    if(rank == 0){
        int idx = final_v1.size(); 
        
        vector<vector<u64>> recv_buff(N-1);
        for(int i = 0; i < N-1; i++)recv_buff[i].resize(6*final_v1.size());
        //buff_u64.resize(6*final_v1.size());    
        final_v1.resize(final_v1.size()*N,F(0));
        final_v2.resize(final_v2.size()*N,F(0));
        final_v3.resize(final_v3.size()*N,F(0));
        vector<MPI_Request> req(N-1);
        for(int i = 1; i < N; i++){
            MPI_Irecv(recv_buff[i-1].data(),recv_buff[i-1].size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i-1]);
            
        }
        for(int i = 1; i < N; i++){
            std::array<u64, pvia::META_WORDS> remote_meta{};
            if (pvia::Runtime::instance().enabled()) {
                MPI_Recv(remote_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                         i, pvia::META_TAG, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            }
            //MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            MPI_Wait(&req[i-1],MPI_STATUS_IGNORE);
            if (pvia::Runtime::instance().enabled()) {
                pvia::Runtime::instance().observe_remote_meta(
                    i, remote_meta, recv_buff[i-1]);
            }
            field_vector_deserialize(recv_buff[i-1],buff);
            for(int j = 0; j < (1<<offset); j++){
                final_v1[idx] = buff[j];
                final_v2[idx] = buff[j+ (buff.size()/3)];
                final_v3[idx] = buff[j+ 2*(buff.size()/3)];
                idx++;
            }   
        }
        if (pvia::Runtime::instance().enabled()) {
            pvia::Runtime::instance().import_state(
                "distributed_cubic_reduced_v1",
                pvia::Phase::DISTRIBUTED_SUMCHECK, final_v1);
            pvia::Runtime::instance().import_state(
                "distributed_cubic_reduced_v2",
                pvia::Phase::DISTRIBUTED_SUMCHECK, final_v2);
            pvia::Runtime::instance().import_state(
                "distributed_cubic_reduced_v3",
                pvia::Phase::DISTRIBUTED_SUMCHECK, final_v3);
        }
        pt_cp.start();
    
        vector<pair<F,vector<F>>> res = cubic_sumcheck(y,final_v1,final_v2,final_v3,F(0));
        ps_plain += 16*(3+4*(int)log2(N))/1024.0;
            
        reply.push_back(res[0].first);
        reply.push_back(res[1].first);
        reply.push_back(res[2].first);
        reply.insert(reply.end(),res[0].second.begin(),res[0].second.end());
        field_vector_serialize(reply,buff_u64);
        pt_cp.end();
    
    }else{
        buff = final_v1; 
        buff.insert(buff.end(),final_v2.begin(),final_v2.end());
        buff.insert(buff.end(),final_v3.begin(),final_v3.end());

        pvia::RecordId transfer_record = 0;
        if (pvia::Runtime::instance().enabled()) {
            auto& rt = pvia::Runtime::instance();
            std::vector<pvia::OperationRef> predecessors;
            const auto predecessor = rt.previous_round_operation_ref(
                pvia::Phase::DISTRIBUTED_SUMCHECK,
                static_cast<uint32_t>(rounds), pvia::Obligation::PUBLISH);
            if (predecessor.object_id != 0) predecessors.push_back(predecessor);
            transfer_record = rt.register_vector_operation(
                pvia::Phase::DISTRIBUTED_SUMCHECK,
                static_cast<uint32_t>(rounds),
                pvia::Obligation::SEND, buff, predecessors);
            pvia::Runtime::instance().activate_vector(transfer_record, buff);
        }

        field_vector_serialize(buff,buff_u64);
        cm += 8*buff_u64.size()/1024.0;
        if (pvia::Runtime::instance().enabled()) {
            auto transfer_meta =
                pvia::Runtime::instance().make_pending_meta(buff_u64, false);
            pvia::Runtime::instance().seal_transfer_meta(transfer_meta, buff_u64);
            pvia::Runtime::instance().observe_outgoing_transfer(transfer_meta, buff_u64);
            pvia::Runtime::instance().observe_local_payload(buff_u64);
            MPI_Send(transfer_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                     0, pvia::META_TAG, MPI_COMM_WORLD);
        }
        MPI_Request req;
        MPI_Isend(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
        if (pvia::Runtime::instance().enabled()) {
            pvia::Runtime::instance().consume_pending();
        }
        buff_u64.clear();buff_u64.resize(2*(3+offset+(int)log2(N))); 
    }
    if(rank == 0) cm += (N-1)*8*buff_u64.size()/1024.0;
    myBcast(buff_u64, N);
    
    //MPI_Bcast(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,MPI_COMM_WORLD);
	if(rank != 0){
        field_vector_deserialize(buff_u64,reply);
    }
    for(int i = 3; i < reply.size(); i++){
        r.push_back(reply[i]);
    }
    return {make_pair(reply[0] ,r),make_pair(reply[1] ,r),make_pair(reply[2] ,r)};
}



pair<F,vector<vector<F>>> prove_product(vector<vector<F>> &input, vector<F> &output, F y, vector<F> r, int N){

    double temp_time = pt_cp.get_time();
	pt_cp.start();
    timer smch_timer;
    smch_timer.start();
    int vectors = input.size();
	int depth = (int)log2(next_pow2(input[0].size()))-multree_offset;
	int size = input[0].size();
    for(int i = 0; i < input.size(); i++){
		if(input[i].size() != size){
			printf("Error in mul tree sumcheck, no equal size vectors %d,%d\n",input[i].size(),size);
			exit(-1);
		}
        input[i].resize(1<<depth,F(1));
	}

	if(vectors != 1<<((int)log2(vectors))){
		vectors = 1<<((int)log2(vectors)+1);
		int old_vector_size = input.size();
		vector<F> temp_vector(1<<depth,F(0));
		for(int i = 0; i < vectors-old_vector_size; i++){
			input.push_back(temp_vector);
		}
	}
	// Initialize total input
	int total_input_size = vectors*size;
	
	//printf("total input %d\n",total_input_size );
	vector<F> total_input(total_input_size);
	int counter = 0;
	for(int j = 0; j < input.size(); j++){
		for(int i = 0; i < input[0].size(); i++){
			total_input[counter] = input[j][i];
			counter++;
		}
	}	
	
    vector<vector<F>> transcript(depth);
	vector<vector<F>> in1(depth),in2(depth);
	for(int i = 0; i < depth; i++){
		transcript[i].resize(total_input_size/(1<<(i+1)));
		in1[i].resize(total_input_size/(1<<(i+1)));
		in2[i].resize(total_input_size/(1<<(i+1)));
	}
	
	counter = 0;
	for(int i = 0; i < total_input_size/2; i++){
		transcript[0][counter] = total_input[2*i]*total_input[2*i+1];
		in1[0][counter] = total_input[2*i];
		in2[0][counter] = total_input[2*i+1];
		counter++;
	}
    
	int len = total_input_size/2;
	for(int i = 1; i < transcript.size(); i++){
		counter = 0;
		for(int j = 0; j < len/2; j++){
			transcript[i][counter] = transcript[i-1][2*j]*transcript[i-1][2*j + 1];
			in1[i][counter] = transcript[i-1][2*j];
			in2[i][counter] = transcript[i-1][2*j + 1];
			counter++;
		}
		len = len/2;
	}

    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id

    // PVIA: the final local multiplication-tree frontier is a
    // secret-dependent DERIVE obligation, distinct from the later SEND.
    pvia::RecordId product_derive_record = 0;
    if (pvia::Runtime::instance().enabled()) {
        auto& rt = pvia::Runtime::instance();
        std::vector<pvia::OperationRef> predecessors;
        const auto predecessor = rt.latest_operation_ref(
            pvia::Phase::DISTRIBUTED_SUMCHECK);
        if (predecessor.object_id != 0) predecessors.push_back(predecessor);
        const pvia::StateId product_source_state =
            depth > 0
                ? rt.import_state_slices(
                    "product_frontier_input",
                    pvia::Phase::DISTRIBUTED_SUMCHECK,
                    std::vector<pvia::FieldStateSegment>{
                        {&in1[depth-1], 0, in1[depth-1].size()},
                        {&in2[depth-1], 0, in2[depth-1].size()}})
                : 0;
        const pvia::Digest product_frontier_digest =
            pvia::hash_field_vector(transcript[depth-1]);
        product_derive_record = rt.register_vector_operation_prehashed(
            pvia::Phase::DISTRIBUTED_SUMCHECK,
            static_cast<uint32_t>(depth),
            pvia::Obligation::DERIVE, transcript[depth-1],
            product_frontier_digest, predecessors);
        rt.bind_state_dependencies(
            product_derive_record, std::vector<pvia::StateId>{product_source_state});
        rt.bind_relation_kernel(
            product_derive_record, pvia::AuditRelationKernel::PRODUCT_FRONTIER);
        rt.bind_public_word_aux(
            product_derive_record, pvia::AuditPublicAuxKind::GENERIC_WORDS,
            vector<u64>{static_cast<u64>(depth),
                        static_cast<u64>(transcript[depth-1].size())});
        rt.activate_vector_prehashed(
            product_derive_record, transcript[depth-1],
            product_frontier_digest);
        rt.observe_local_payload_digest(product_frontier_digest);
        rt.consume_pending();
    }

    // Send outputs to the leader
    vector<u64> buff;
    pair<F,vector<F>> eval_claim;
    vector<F> buff_reply;
    pt_cp.end();
    com_rounds+=2;
    
    if(rank == 0){
        int ctr = 0;
        sch_com.start();
        vector<vector<F>> local_input(vectors);
        for(int i = 0; i < local_input.size(); i++){
            local_input[i].resize(N*(transcript[depth-1].size())/vectors);
            for(int j = 0; j  < transcript[depth-1].size()/vectors; j++) local_input[i][j] = transcript[depth-1][ctr++];
            
            //local_input[i][0] = transcript[depth-1][i];
        }
        //buff.resize(2*transcript[depth-1].size());
        vector<vector<u64>> recv_data(N-1);
        vector<MPI_Request> req(N-1);
        for(int i = 0; i < N-1; i++){
            recv_data[i].resize(2*transcript[depth-1].size());
            MPI_Irecv(recv_data[i].data(),recv_data[i].size(),MPI_UINT64_T,i+1,0,MPI_COMM_WORLD,&req[i]);
        }

        vector<F> _buff;
        for(int i = 0; i < N-1; i++){
            ctr = 0;
            std::array<u64, pvia::META_WORDS> remote_meta{};
            if (pvia::Runtime::instance().enabled()) {
                MPI_Recv(remote_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                         i+1, pvia::META_TAG, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            }
            MPI_Wait(&req[i],MPI_STATUS_IGNORE);
            if (pvia::Runtime::instance().enabled()) {
                pvia::Runtime::instance().observe_remote_meta(
                    i+1, remote_meta, recv_data[i]);
            }
            //MPI_Recv(buff.data(),buff.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            field_vector_deserialize(recv_data[i],_buff);
            for(int j = 0; j < vectors; j++){
                for(int k = 0; k < _buff.size()/vectors; k++){
                    //if(j == 0) printf("%d,%d\n",i*_buff.size()/vectors + k,vectors);
                    local_input[j][(i+1)*_buff.size()/vectors + k] = _buff[ctr++];
                }
            }
            //for(int j = 0; j < buff.size()/2; j++){
            //    local_input[j][i].real = buff[2*j];
            //    local_input[j][i].img = buff[2*j+1];
            //}
        }
        if (pvia::Runtime::instance().enabled()) {
            vector<F> merged_frontier = convert2vector(local_input);
            pvia::Runtime::instance().import_state(
                "product_tree_merged_frontier",
                pvia::Phase::DISTRIBUTED_SUMCHECK,
                merged_frontier);
        }
        sch_com.end();

        pt_cp.start();
        printf("Size : %d\n",local_input.size()*local_input[0].size());
        eval_claim = prove_multiplication_tree_new(local_input, output, F(0),y, {});
        buff_reply.push_back(eval_claim.first);
        
        buff_reply.insert(buff_reply.end(),eval_claim.second.begin(),eval_claim.second.end());
        
        field_vector_serialize(buff_reply,buff);   

        pt_cp.end();
          
    }else{
        // PVIA: transfer of the already-derived product frontier is a
        // separate SEND obligation, so a receiver cannot frame the sender.
        vector<F> transfer_frontier = transcript[depth-1];
        pvia::RecordId transfer_record = 0;
        if (pvia::Runtime::instance().enabled()) {
            std::vector<pvia::OperationRef> predecessors;
            if (product_derive_record != 0) {
                pvia::OperationRef ref;
                ref.owner = static_cast<uint32_t>(rank);
                ref.object_id = product_derive_record;
                predecessors.push_back(ref);
            }
            transfer_record = pvia::Runtime::instance().register_vector_operation(
                pvia::Phase::DISTRIBUTED_SUMCHECK,
                static_cast<uint32_t>(depth),
                pvia::Obligation::SEND, transfer_frontier, predecessors);
            pvia::Runtime::instance().activate_vector(
                transfer_record, transfer_frontier);
        }

        field_vector_serialize(transfer_frontier,buff);
        cm += 8*buff.size()/1024.0;
        if (pvia::Runtime::instance().enabled()) {
            auto transfer_meta =
                pvia::Runtime::instance().make_pending_meta(buff, false);
            pvia::Runtime::instance().seal_transfer_meta(transfer_meta, buff);
            pvia::Runtime::instance().observe_outgoing_transfer(transfer_meta, buff);
            pvia::Runtime::instance().observe_local_payload(buff);
            MPI_Send(transfer_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                     0, pvia::META_TAG, MPI_COMM_WORLD);
        }
        MPI_Request req;
        MPI_Isend(buff.data(),buff.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
        if (pvia::Runtime::instance().enabled()) {
            pvia::Runtime::instance().consume_pending();
        }
        buff.clear();buff.resize(2*(1 + log2(N*transcript[depth-1].size())));
        
    }
    if(rank == 0) cm += (N-1)*8*buff.size()/1024.0;
    //printf("%d ?? %d\n",rank,buff.size());
    myBcast(buff, N);
    smch_timer.end();
    if(rank == 0) printf("          Step 1: %lf, %lf,%lf\n",smch_timer.get_time(),pt_cp.get_time()-temp_time,sch_com.get_time());
    temp_time = pt_cp.get_time();
    //MPI_Bcast(buff.data(),buff.size(),MPI_UINT64_T,0,MPI_COMM_WORLD);
    if(rank != 0){
        field_vector_deserialize(buff,buff_reply);
        eval_claim.first = buff_reply[0];
        for(int i = 1; i < buff_reply.size(); i++){
            eval_claim.second.push_back(buff_reply[i]);
        }
    }
    
    //printf("Final prod len : %d\n",transcript[depth-1].size());
		
	F sum = eval_claim.first;//evaluate_vector(transcript[depth-1],r);
    r = eval_claim.second;
    vector<F> r1,r2;
    for(int i = 0; i < multree_offset; i++){
        r2.push_back(r[i]);
    }
    for(int i = multree_offset; i < (int)log2(N)+multree_offset; i++){
        r1.push_back(r[i]);
    }
    for(int  i = multree_offset+ r1.size(); i < r.size(); i++){
        r2.push_back(r[i]);
    }
    double smc_time = smch_timer.get_time();
    for(int i = depth-1; i >= 0; i--){
        pt_cp.start();
        smch_timer.start();
        
        pt_cp.end();
        vector<pair<F,vector<F>>> claims;
        
        if((r2.size() < sumcheck_offset+1) || isLAN ){
            vector<F>  beta1,beta2;
        	pt_cp.start();
            precompute_beta(r2,beta2);
            precompute_beta(r1,beta1);
            pt_cp.end();
            claims = _cubic_sumcheck(sum,in1[i], in2[i],beta2, beta1, N );
        }else{
            vector<F> beta1,beta2,beta3,r21,r22;
        	for(int j = 0; j < r2.size()-sumcheck_offset; j++) r21.push_back(r2[j]);
        	for(int j = r2.size()-sumcheck_offset; j < r2.size(); j++) r22.push_back(r2[j]);
            pt_cp.start();
            precompute_beta(r21,beta2);
            precompute_beta(r22,beta3);
            precompute_beta(r1,beta1);
            pt_cp.end();
            claims = _cubic_sumcheck_sparrow(sum,in1[i], in2[i],beta2,beta3, beta1, N );
        
        }
        smch_timer.end();
        if(rank == 0) printf("          Round %d: %lf, %lf\n",i,smch_timer.get_time(),sch_com.get_time());
    
        pt_cp.start();
    
        F new_rand = hash_to_field(claims[0].second);
        r = claims[0].second;
        r.insert(r.begin(),new_rand);
        sum = (F(1)-new_rand)*claims[0].first + new_rand*claims[1].first;
        r1.clear();r2.clear();
        for(int j = 0; j < r.size()-(int)log2(N); j++){
            r2.push_back(r[j]);
        }
        for(int j = r2.size(); j  < r.size(); j++){
            r1.push_back(r[j]);
        }
        pt_cp.end();
	}
    if(rank == 0) printf("          Step 2: %lf, %lf,%lf\n",smch_timer.get_time() - smc_time,pt_cp.get_time()-temp_time,sch_com.get_time());
    pt_cp.start();
    
    vector<vector<F>> eval_points(3);
    
    for(int i = 0; i < r.size()-(int)log2(N)-(int)log2(vectors); i++){
        eval_points[0].push_back(r[i]);
    }
    for(int i = eval_points[0].size(); i < r.size()-(int)log2(N); i++){
        eval_points[1].push_back(r[i]);
    }
    for(int i = r.size()-(int)log2(N); i < r.size(); i++){
        eval_points[2].push_back(r[i]);
    }
    pt_cp.end();
    
    return make_pair(sum,eval_points);
}

// New version of multiplication tree prover that takes as input vectors of different size
pair<F,vector<vector<F>>> prove_product_opt(vector<vector<F>> &input, vector<F> &output, int N, vector<F> &evals){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    int total_size = 0;
    int size = 0;
    pt_cp.start();
    
    for(int i = 0; i < input.size(); i++) {
        if(i > 0 && input[i].size() > input[i-1].size()){
            printf("Input is not sorted, exiting \n");
            if(rank == 0) for(int j = 0; j < input.size(); j++) printf("%d\n",input[j].size());
            exit(-1);
        }
        input[i].resize(next_pow2(input[i].size()),F(1));
        total_size += input[i].size();
        size = input[i].size();
    }
    
    vector<vector<F>> new_input;
    vector<F> buff(size);
    for(int i = 0; i < input.size(); i++){
        int ctr = 0;
        for(int j = 0; j < input[i].size()/size; j++){
            for(int k = 0; k < size; k++) buff[k] = input[i][ctr++];
            new_input.push_back(buff);
        }
    }
    pt_cp.end();
    vector<F> temp_out;
    pair<F,vector<vector<F>>> claim = prove_product(new_input,temp_out,F(0),{},N);
    int ctr = 0;
    if(rank == 0){
        output.resize(input.size(),F(1));
        for(int i = 0; i < input.size(); i++){
            for(int j = 0; j < input[i].size()/size; j++)output[i] *= temp_out[ctr++];
        }
    }
    vector<F> r = claim.second[0];
    r.insert(r.end(),claim.second[1].begin(),claim.second[1].end());
    //evals = batch_distributed_eval_opt(input, r, claim.second[2], N);
    
    return claim;

}


void _reduce_R1CS_matrixes(size_t size, vector<F> r, vector<F> &RA, vector<F> &RB, vector<F> &RC, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    
    vector<F> r1,r2,beta1,beta2;
    for(int i = 0; i < r.size() - (int)log2(N); i++){
        r1.push_back(r[i]);
    }
    for(int i = r.size() - (int)log2(N); i < r.size(); i++){
        r2.push_back(r[i]);
    }
    
    precompute_beta(r1,beta1);precompute_beta(r2,beta2);
    
    int M = (1<<logn)/N;
    RA.resize(M,F(0));RB.resize(M,F(0));RC.resize(M,F(0));
    
    for(int i = 0; i < pA.size(); i++){
        if(pA[i].size()){
            //if(rank == 1) printf("%d,(%d,%d),(%d,%d,%d)\n",rank,pA[i][0].first,pA[i][0].first%RA.size(),pA[i][0].second,pA[i][0].second/(pA.size()/2),pA[i][0].second%(pA.size()/2));
            for(int j = 0; j < pA[i].size(); j++){
                RA[pA[i][j].first%RA.size()] += beta1[pA[i][j].second%((1<<logm)/N)]*beta2[pA[i][j].second/((1<<logm)/N)];
            }
        }
        if(pB[i].size()){
            //printf("> %d, %d\n",rank,pB[i][0].second);
            for(int j = 0; j < pB[i].size(); j++){
                RB[pB[i][j].first%RB.size()] += beta1[pB[i][j].second%((1<<logm)/N)]*beta2[pB[i][j].second/((1<<logm)/N)];
            }
        } 
        if(pC[i].size()){
            for(int j = 0; j < pC[i].size(); j++){
                RC[pC[i][j].first%RC.size()] += beta1[pC[i][j].second%((1<<logm)/N)]*beta2[pC[i][j].second/((1<<logm)/N)];
            }
        }
    }
}



void secret_share_vector(
    vector<F> &v, int _k, int k, int N,
    const char* transfer_label){
    int rank = 0;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    int ctr = 0;
    pt_cp.start();

    vector<vector<F>> data(N);
    for(int i = 0; i < data.size(); i++) data[i].resize(v.size()/k);
    for(int i = 0; i < v.size()/k; i++){
        vector<F> tmp(_k);
        for(int j = 0; j < k; j++) tmp[j] = v[ctr++];
        for(int j = k; j < _k; j++) tmp[j] = 0;
        fft(tmp,(int)log2(tmp.size()),true);
        tmp.resize(2*N,F(0));
        fft(tmp,(int)log2(tmp.size()),false);
        for(int j = 0; j < N; j++) data[j][i] = tmp[2*j + 1];
    }

    vector<u64> buff_u64, buff_recv_u64;
    vector<F> flat = convert2vector(data);
    field_vector_serialize(flat,buff_u64);
    buff_recv_u64.resize(buff_u64.size(),0);
    pt_cp.end();
    if(!data_parallel) cm += 8*buff_u64.size()/1024.0;
    com_rounds++;

    const bool pvia_bound = pvia::Runtime::instance().enabled() &&
                            transfer_label != nullptr;
    const size_t chunk_words = N > 0 ? buff_u64.size()/N : 0;
    vector<u64> meta_send, meta_recv;
    if (pvia_bound) {
        bool shape_ok = N > 0 && buff_u64.size() % N == 0;
        int local = shape_ok ? 1 : 0, global = 0;
        MPI_Allreduce(&local, &global, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
        if (!global) std::exit(15);
        meta_send.resize(N*pvia::META_WORDS);
        meta_recv.resize(N*pvia::META_WORDS);
        for (int dst = 0; dst < N; ++dst) {
            const u64* segment =
                buff_u64.data() + static_cast<size_t>(dst) * chunk_words;
            const pvia::Digest segment_digest =
                pvia::hash_word_span(segment, chunk_words);
            const uint64_t object_id =
                pvia::Runtime::instance().allocate_object_id();
            auto meta = pvia::Runtime::instance().make_direct_meta_digest(
                pvia::Phase::DISTRIBUTED_SUMCHECK, 0,
                pvia::Obligation::SEND, object_id,
                segment_digest, false);
            pvia::Runtime::instance().seal_transfer_meta_digest(
                meta, segment_digest);
            pvia::Runtime::instance().observe_outgoing_transfer_digest(
                meta, segment_digest);
            std::copy(meta.begin(), meta.end(),
                      meta_send.begin()+dst*pvia::META_WORDS);
        }
    }

    MPI_Request req[2];
    int req_count = 0;
    if (pvia_bound) {
        MPI_Ialltoall(meta_send.data(), pvia::META_WORDS, MPI_UINT64_T,
                      meta_recv.data(), pvia::META_WORDS, MPI_UINT64_T,
                      MPI_COMM_WORLD, &req[req_count++]);
    }
    MPI_Ialltoall(buff_u64.data(), chunk_words, MPI_UINT64_T,
                  buff_recv_u64.data(), chunk_words, MPI_UINT64_T,
                  MPI_COMM_WORLD, &req[req_count++]);
    MPI_Waitall(req_count, req, MPI_STATUSES_IGNORE);

    if (pvia_bound) {
        bool local_ok = true;
        for (int sender = 0; sender < N; ++sender) {
            const u64* segment =
                buff_recv_u64.data() +
                static_cast<size_t>(sender) * chunk_words;
            const pvia::Digest segment_digest =
                pvia::hash_word_span(segment, chunk_words);
            std::array<u64, pvia::META_WORDS> meta{};
            std::copy(meta_recv.begin()+sender*pvia::META_WORDS,
                      meta_recv.begin()+(sender+1)*pvia::META_WORDS,
                      meta.begin());
            if (!pvia::Runtime::instance().strict_remote_transfer_valid_digest(
                    sender, meta, segment_digest))
                local_ok = false;
            pvia::Runtime::instance().observe_remote_meta_digest(
                sender, meta, segment_digest);
        }
        int local = local_ok ? 1 : 0, global = 0;
        MPI_Allreduce(&local, &global, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
        if (!global) {
            if (rank == 0)
                printf("[PVIA][PublicDirect] WITHHOLD copiop_public_share_transfer before coPIOP phase-2 Sumcheck\n");
            std::exit(15);
        }
    }

    pt_cp.start();
    field_vector_deserialize(buff_recv_u64,v);
    pt_cp.end();
    if (pvia::Runtime::instance().enabled()) {
        pvia::Runtime::instance().import_state(
            "distributed_secret_share_vector",
            pvia::Phase::DISTRIBUTED_SUMCHECK, v);
    }
}



void compute_R1CS_betas(vector<F> r1, vector<F> r2, vector<sparse_eval_data> &data, vector<vector<F>> &beta1, vector<vector<F>> &beta2, int logm, int logn, int N){
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
    
    precompute_beta(r11,beta11);
    precompute_beta(r12,beta12);
    precompute_beta(r21,beta21);
    precompute_beta(r22,beta22);
    
    int ctr = 0;

    vector<F> b; precompute_beta(r2,b);
    for(int i = 0; i < data.size(); i++){
        
        beta1[i].resize(data[i].IDX1.size(),F(0));
        for(int j = 0; j < data[i].IDX1.size(); j++){
            int idx1 = data[i].IDX1[j];
            int idx11 = idx1&mask1;
            int idx12 = idx1>>(logm/2);
            beta1[i][j] = beta11[idx11]*beta12[idx12];
            //ctr++;
            
        }
        beta2[i].resize(data[i].IDX2.size(),F(0));        
        for(int j = 0; j < data[i].IDX2.size(); j++){
            int idx2 = data[i].IDX2[j];
            int idx21 = idx2&mask2;
            int idx22 = idx2>>(logn/2);
            beta2[i][j] = beta21[idx21]*beta22[idx22];
            //ctr++;
        }
    }
}

void  compute_base_betas(vector<F> r1,vector<F> r2, vector<F> &base_beta1, vector<F> &base_beta2, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<F> r11,r12,r21,r22;
    
    for(int i  = 0; i < r1.size()-(int)log2(N); i++){
        r12.push_back(r1[i]);
    }
    for(int i = r12.size(); i < r1.size(); i++){
        r11.push_back(r1[i]);
    }
    
    for(int i  = 0; i < r2.size()-(int)log2(N); i++){
        r22.push_back(r2[i]);
    }
    for(int i = r22.size(); i < r2.size(); i++){
        r21.push_back(r2[i]);
    }
    
    precompute_beta(r12,base_beta1);
    precompute_beta(r22,base_beta2);
    F b1 = _beta(rank,  r11);
    F b2 = _beta(rank,  r21);
    
    for(int i = 0; i < base_beta1.size(); i++){
        base_beta1[i] = b1*base_beta1[i];
    }
    for(int i = 0; i < base_beta2.size(); i++){
        base_beta2[i] = b2*base_beta2[i];
    }
}


vector<pair<F,vector<F>>> distributed_accumulation(vector<vector<F>> &polys, vector<vector<vector<F>>> eval_points, vector<F> evals, int N){
    int rank,ctr = 0;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    pt_cp.start();
    vector<F> v1,v2,b;
    vector<F> r;
    F y;
    r.push_back(hash_to_field(evals));
    y = r[0]*evals[0];
    for(int i = 1; i < polys.size(); i++){
        r.push_back(hash_to_field({r[i-1]}));
        y += r[i]*evals[i];
    }
    
    for(int i = 0; i < polys.size(); i++){
        v1.insert(v1.end(),polys[i].begin(),polys[i].end());
    }
    v2.resize(v1.size());
    precompute_beta(eval_points[0][0],b);
    F _b = _beta(rank,eval_points[0][2]);
    for(int i = 0; i < b.size(); i++){
        b[i] = _b*b[i];
    }
    for(int i = 0; i < 3; i++){
        for(int j = 0; j < polys[i].size(); j++){
            v2[ctr] = r[i]*b[j];
            ctr++;
        }
    }
    b.clear();
    precompute_beta(eval_points[1][0],b);
    _b = _beta(rank,eval_points[1][2]);
    for(int i = 0; i < b.size(); i++){
        b[i] = _b*b[i];
    }
    for(int i = 3; i < 15; i++){
        for(int j = 0; j < polys[i].size(); j++){
            v2[ctr] = r[i]*b[j];
            ctr++;
        }
    }
    b.clear();
    precompute_beta(eval_points[2][0],b);
    _b = _beta(rank,eval_points[2][2]);
    for(int i = 0; i < b.size(); i++){
        b[i] = _b*b[i];
    }
    for(int i = 15; i < 18; i++){
        for(int j = 0; j < polys[i].size(); j++){
            v2[ctr] = r[i]*b[j];
            ctr++;
        }
    }
    v1.resize(next_pow2(v1.size()),F(0));
    v2.resize(next_pow2(v2.size()),F(0));
    pt_cp.end();
    
    vector<pair<F,vector<F>>> claim = _quadratic_sumcheck(y,v1,v2,N);
    pt_cp.start();
    
    if(rank == 0){
        vector<F> claimed_r1,claimed_r2;
        for(int i = 0; i < (int)log2(polys[0].size()); i++){
            claimed_r1.push_back(claim[0].second[i]);
        }
        for(int i = 0; i < (int)log2(N); i++){
            claimed_r1.push_back(claim[0].second[claim[0].second.size()-(int)log2(N)+i]);
        }
        for(int i = (int)log2(polys[0].size()); i < claim[0].second.size()-(int)log2(N); i++){
            claimed_r1.push_back(claim[0].second[i]);
        }

        for(int i = 0; i < (int)log2(polys[3].size()); i++){
            claimed_r2.push_back(claim[0].second[i]);
        }
        for(int i = 0; i < (int)log2(N); i++){
            claimed_r2.push_back(claim[0].second[claim[0].second.size()-(int)log2(N)+i]);
        }
        for(int i = (int)log2(polys[3].size()); i < claim[0].second.size()-(int)log2(N); i++){
            claimed_r2.push_back(claim[0].second[i]);
        }

        vector<F> partial_poly(32,F(0));
        
        vector<F> _r = eval_points[0][0];_r.insert(_r.end(),eval_points[0][2].begin(),eval_points[0][2].end());
        _b = beta_identity(_r,claimed_r1);
        for(int i = 0; i < 3; i++){
            partial_poly[i] = r[i]*_b;
        }
        _r = eval_points[1][0];_r.insert(_r.end(),eval_points[1][2].begin(),eval_points[1][2].end());
        _b = beta_identity(_r,claimed_r2);
        for(int i = 3; i < 15; i++){
            partial_poly[i] = r[i]*_b;
        }
        _r = eval_points[2][0];_r.insert(_r.end(),eval_points[2][2].begin(),eval_points[2][2].end());
        _b = beta_identity(_r,claimed_r2);
        for(int i = 15; i < 18; i++){
            partial_poly[i] = r[i]*_b;
        }

        int pos = 0;
        for(int i = 0; i < 3; i++){
            F prod = get_offset_product(N*polys[i].size(),pos,claimed_r1);
            pos += N*polys[i].size();
            partial_poly[i] *= prod;
        }
        for(int i = 3; i < 18; i++){
            F prod = get_offset_product(N*polys[i].size(),pos,claimed_r2);
            pos += N*polys[i].size();
            partial_poly[i] *= prod;
        }
        for(int i = 0; i < partial_poly.size(); i++){
            claim[1].first -= partial_poly[i];
        }
        printf("%lld,%lld\n",claim[1].first.real,claim[1].first.img);
        if(F(0) != claim[1].first){
            printf("Error in final eval\n");
            if (pvia::Runtime::instance().enabled()) {
                pvia::Runtime::instance().handle_global_failure(
                    "distributed_accumulation_final_eval",
                    pvia::Phase::DISTRIBUTED_SUMCHECK, 0);
            }
        }

    }
    pt_cp.end();
    
    return claim;
}


void compute_transcript(vector<vector<F>> &Tr, vector<sparse_eval_data> &data, vector<F> challenges, vector<vector<F>> &beta1, vector<vector<F>> &beta2,
                    vector<F> r1, vector<F> r2, int N){
    int rank;
    vector<F> base_beta1,base_beta2;
    compute_base_betas(r1,r2,base_beta1,base_beta2,N);
    
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    for(int j = 0; j < data.size(); j++){
        Tr[2*j].resize(next_pow2(data[j].IDX1.size()),F(1));
        Tr[2*j+1].resize(next_pow2(data[j].IDX1.size()),F(1));
        for(int i = 0; i < data[j].IDX1.size(); i++){
            Tr[2*j][i] = challenges[0]*beta1[j][i] +  challenges[1]*F(data[j].RD1[i]) + challenges[2]*F(data[j].IDX1[i]) + F(1);
            Tr[2*j+1][i] = challenges[0]*beta1[j][i] +  challenges[1]*F(data[j].WR1[i]) + challenges[2]*F(data[j].IDX1[i]) + F(1);
        }
    }
    for(int j = 0; j < data.size(); j++){
        Tr[2*j+6].resize(next_pow2(data[j].IDX2.size()),F(1));
        Tr[2*j+1+6].resize(next_pow2(data[j].IDX2.size()),F(1));
        for(int i = 0; i < data[j].IDX2.size(); i++){
            Tr[2*j+6][i] = challenges[0]*beta2[j][i] +  challenges[1]*F(data[j].RD2[i]) + challenges[2]*F(data[j].IDX2[i]) + F(1);
            Tr[2*j+1+6][i] = challenges[0]*beta2[j][i] +  challenges[1]*F(data[j].WR2[i]) + challenges[2]*F(data[j].IDX2[i]) + F(1);
        }
    }
    for(int j = 0; j < data.size(); j++){
        Tr[2*j+12].resize(next_pow2(data[j].FINAL_FR1.size()),F(1));
        Tr[2*j+1+12].resize(next_pow2(data[j].FINAL_FR1.size()),F(1));
    
        for(int i = 0; i < data[j].FINAL_FR1.size(); i++){
            Tr[2*j+0+12][i] =   challenges[0]*base_beta1[i]+F(1)  +  challenges[2]*F(rank*data[j].FINAL_FR1.size() + i);
            Tr[2*j+1+12][i] = challenges[0]*base_beta1[i] +  challenges[1]*F(data[j].FINAL_FR1[i]) + challenges[2]*F(rank*data[j].FINAL_FR1.size() + i) + F(1);
        }
    }
    for(int j = 0; j < data.size(); j++){
        Tr[2*j+18].resize(next_pow2(data[j].FINAL_FR2.size()),F(1));
        Tr[2*j+1+18].resize(next_pow2(data[j].FINAL_FR2.size()),F(1));
        for(int i = 0; i < data[j].FINAL_FR2.size(); i++){
            Tr[2*j+18][i] =   challenges[2]*F(rank*data[j].FINAL_FR2.size() + i) + F(1) + challenges[0]*base_beta2[i]; 
            Tr[2*j+1+18][i] = challenges[0]*base_beta2[i] +  challenges[1]*F(data[j].FINAL_FR2[i]) + challenges[2]*F(rank*data[j].FINAL_FR2.size() + i) + F(1);
        }
    }

    if (pvia::Runtime::instance().enabled()) {
        auto& rt = pvia::Runtime::instance();
        vector<F> sparse_source;
        pvia::Digest sparse_source_digest{};
        if (rt.audit_backend()) {
            sparse_source = convert2vector(beta1);
            vector<F> beta2_flat = convert2vector(beta2);
            sparse_source.insert(
                sparse_source.end(), beta2_flat.begin(), beta2_flat.end());
            for (const auto& item : data) {
                for (auto x : item.IDX1) sparse_source.push_back(F(x));
                for (auto x : item.RD1) sparse_source.push_back(F(x));
                for (auto x : item.WR1) sparse_source.push_back(F(x));
                for (auto x : item.IDX2) sparse_source.push_back(F(x));
                for (auto x : item.RD2) sparse_source.push_back(F(x));
                for (auto x : item.WR2) sparse_source.push_back(F(x));
                for (auto x : item.FINAL_FR1) sparse_source.push_back(F(x));
                for (auto x : item.FINAL_FR2) sparse_source.push_back(F(x));
            }
            sparse_source_digest = pvia::hash_field_vector(sparse_source);
        } else {
            sparse_source_digest =
                hash_sparse_eval_source_stream(beta1, beta2, data);
        }
        const pvia::StateId source_state = rt.import_state_prehashed(
            "sparse_eval_source", pvia::Phase::DISTRIBUTED_SUMCHECK,
            sparse_source, sparse_source_digest);

        vector<const vector<F>*> transcript_segments;
        transcript_segments.reserve(Tr.size());
        for (const auto& row : Tr)
            transcript_segments.push_back(&row);
        const pvia::Digest transcript_block_digest =
            pvia::hash_field_segments(transcript_segments);
        vector<F> transcript_block;
        if (rt.audit_backend())
            transcript_block = convert2vector(Tr);
        const pvia::RecordId sparse_record =
            rt.register_vector_operation_prehashed(
                pvia::Phase::DISTRIBUTED_SUMCHECK, 0,
                pvia::Obligation::DERIVE, transcript_block,
                transcript_block_digest, {});
        rt.bind_state_dependencies(
            sparse_record, std::vector<pvia::StateId>{source_state});
        rt.bind_relation_kernel(
            sparse_record, pvia::AuditRelationKernel::SPARSE_TRANSCRIPT);
        vector<F> sparse_aux = challenges;
        sparse_aux.insert(sparse_aux.end(), r1.begin(), r1.end());
        sparse_aux.insert(sparse_aux.end(), r2.begin(), r2.end());
        sparse_aux.push_back(F(N));
        rt.bind_public_field_aux(
            sparse_record, pvia::AuditPublicAuxKind::GENERIC_FIELDS, sparse_aux);
        rt.activate_vector_prehashed(
            sparse_record, transcript_block, transcript_block_digest);
        rt.import_state_prehashed(
            "sparse_eval_transcript_block",
            pvia::Phase::DISTRIBUTED_SUMCHECK,
            transcript_block, transcript_block_digest);
    }
}

void sort_transcript(vector<vector<F>> &Tr, vector<int> &order){
    // Create a vector of pairs to store (value, original_index)
    std::vector<std::pair<int, int>> sizes;
    for(int i = 0; i < Tr.size(); i++){
        sizes.push_back(make_pair(Tr[i].size(),i));
    }
    

    // Sort the indexed_vector based on the values (first element of the pair)
    // By default, std::sort sorts pairs based on the first element, then the second if first elements are equal.
    std::sort(sizes.begin(), sizes.end(),[](const std::pair<int, int>& a, const std::pair<int, int>& b) {
        return a.first > b.first; // For descending order
    });

    
    
    //reverse(sizes.begin(),sizes.end());
    order.resize(sizes.size());
    
    for(int i = 0; i < sizes.size(); i++) order[sizes[i].second] = i;
    
    
    
    vector<vector<F>> temp;
    for(int i = 0; i < sizes.size(); i++) temp.push_back(Tr[sizes[i].second]);
    Tr = temp;
}


pair<F,vector<F>> _prove_sparse_eval_opt(F y, F a, F b, F c, vector<vector<F>> &beta1, vector<vector<F>> &beta2, vector<sparse_eval_data> &data, 
                        vector<F> r1, vector<F> r2, int N){
    
    
    double temp = pt_cp.get_time();
    timer t;t.start();
    pt_cp.start();
    vector<vector<F>> Tr(24);
    vector<F> output;
    vector<int> order;
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    //pt_cp.start();
    vector<F> challenges(3);
    clock_t t1 = clock();
    for(int i = 0; i < 3; i++) challenges[i] = hash_to_field({0}); 
    
    compute_transcript(Tr, data, challenges, beta1, beta2, r1, r2, N);
    
    //vector<F> test_v = Tr[13];
    
    sort_transcript(Tr, order);
    vector<F> debug_evals;
    pt_cp.end();
    
    pair<F,vector<vector<F>>> claim = prove_product_opt(Tr, output, N, debug_evals);
    t.end();
    if(rank == 0) printf("> %lf,%lf\n",t.get_time(),pt_cp.get_time()-temp);
    if(rank == 0){
        vector<F> organized_output(output.size());
        for(int i = 0; i < output.size(); i++){
            organized_output[i] = output[order[i]];
        }
        for(int i = 0; i < 6; i++){
            if(organized_output[2*i]*organized_output[2*i+1+12] != organized_output[2*i+1]*organized_output[2*i+12]){
                printf("Error phase 2 %d\n",i);
                if (pvia::Runtime::instance().enabled()) {
                    pvia::Runtime::instance().handle_global_failure(
                        "sparse_product_consistency",
                        pvia::Phase::DISTRIBUTED_SUMCHECK,
                        static_cast<uint32_t>(i));
                }
            }
        }
    }
    vector<F> r = claim.second[0];
    r.insert(r.end(),claim.second[1].begin(),claim.second[1].end());
    vector<vector<F>> polys;
    for(int i = 0; i < data.size(); i++){
        polys.push_back(beta1[i]);
        polys.push_back(convert_to_field(data[i].RD1));
        polys.push_back(convert_to_field(data[i].IDX1));
    }
    for(int i = 0; i < data.size(); i++){
        polys.push_back(beta2[i]);
        polys.push_back(convert_to_field(data[i].RD2));
        polys.push_back(convert_to_field(data[i].IDX2));        
    }
    for(int i = 0; i < data.size(); i++) polys.push_back(convert_to_field(data[i].FINAL_FR1));
    for(int i = 0; i < data.size(); i++) polys.push_back(convert_to_field(data[i].FINAL_FR2));
    
    vector<F> evals = batch_distributed_eval_opt(polys, r, claim.second[2], N,
        PVIA_SCALAR_CTX_SPARSE_OPT);
    pt_cp.start();
    
    vector<F> beta_evals;
    
    for(int i = 0; i < data.size(); i++){
        beta_evals.push_back(evals[3*i]);
        beta_evals.push_back(evals[3*i + 9]);
    }

    if(rank == 0){
        vector<F> Tr_evals(24,F(0));
        vector<F> r11,r12,r21,r22,_r;
        
        for(int i  = 0; i < r1.size()-(int)log2(N); i++){
            r11.push_back(r1[i]);
        }
        for(int i = r11.size(); i < r1.size(); i++){
            r12.push_back(r1[i]);
        }
        
        for(int i  = 0; i < r2.size()-(int)log2(N); i++){
            r21.push_back(r2[i]);
        }
        for(int i = r21.size(); i < r2.size(); i++){
            r22.push_back(r2[i]);
        }
        

        for(int i = 0; i < data.size();i++){
            Tr_evals[2*i] = challenges[0]*evals[3*i] +  challenges[1]*evals[3*i+1] + challenges[2]*evals[3*i+2] + F(1);
            Tr_evals[2*i+1] = Tr_evals[2*i] +  challenges[1];
        }
        for(int i = 0; i < data.size();i++){
            Tr_evals[2*i+6] = challenges[0]*evals[3*i+9] +  challenges[1]*evals[3*i+1+9] + challenges[2]*evals[3*i+2+9] + F(1);
            Tr_evals[2*i+1+6] = Tr_evals[2*i+6] +  challenges[1];
        }
        for(int i = 0; i < data.size(); i++){
            Tr_evals[2*i + 12] =  challenges[0]*betas_eval(data[i].FINAL_FR1.size(),r11,r12,r,claim.second[2]) + F(1) + challenges[2]*sequence_eval(N*next_pow2(data[i].FINAL_FR1.size()),r,claim.second[2]);
            Tr_evals[2*i + 13] = Tr_evals[2*i + 12] + challenges[1]*evals[i+18];
        }
        for(int i = 0; i < data.size(); i++){
            Tr_evals[2*i + 18] =  challenges[2]*sequence_eval(N*next_pow2(data[i].FINAL_FR2.size()),r,claim.second[2]) + F(1) + challenges[0]*betas_eval(data[i].FINAL_FR2.size(),r21,r22,r,claim.second[2]);
            Tr_evals[2*i + 19] = Tr_evals[2*i + 18] + challenges[1]*evals[i+3+18];
        }

        /*
        printf("%d,%d\n",_r.size(),beta.size());
        if(evaluate_vector(beta,_r) != betas_eval(data[0].FINAL_FR1.size(),r11,r12,r,claim.second[2])){
            printf("ERROR\n");
        }*/
        for(int i = 0; i < Tr_evals.size(); i++){
            //if(Tr_evals[i] != debug_evals[order[i]]){
            //    printf("error %d ,%d, %d\n",i,order[i],Tr[order[i]].size());
            //}
        }
        
        //if(evaluate_vector(Tr_evals,claims.second[1]) != claims.first){
        //    printf("Sparse Eval Error 1\n");
        //}
    }
    order.clear();
    vector<F> v1,v2,v3,ones(N,1);
    vector<vector<F>> _beta2_sorted,_beta1_sorted = beta1;
    vector<F> aggr_challenges = {a,b,c};
    sort_transcript(_beta1_sorted,order);    
    for(int i = 0; i < beta2.size(); i++) _beta2_sorted.push_back(beta2[order[i]]);
    
    for(int i = 0; i < beta1.size(); i++){
        v1.insert(v1.end(),_beta1_sorted[i].begin(),_beta1_sorted[i].end());
        v2.insert(v2.end(),_beta2_sorted[i].begin(),_beta2_sorted[i].end());
        //vector<F> c_buff(_beta1_sorted[i].size(),aggr_challenges[order[i]]);
        //v3.insert(v3.end(),c_buff.begin(),c_buff.end());
    }
    v1.resize(next_pow2(v1.size()),F(0));v2.resize(next_pow2(v2.size()),F(0));
    //v3.resize(next_pow2(v3.size()),F(0));
    
    
    int ctr = 0;
    v3.resize(next_pow2(real_idx_dim[0]+real_idx_dim[1]+real_idx_dim[2])/N,F(0));
    
    for(int j = 0; j < 3; j++){
        if((rank+1)*next_pow2(real_idx_dim[order[j]])/N <= real_idx_dim[order[j]]){
            for(int i = 0 ; i < next_pow2(real_idx_dim[order[j]])/N; i++){
                v3[ctr] = aggr_challenges[order[j]];
                ctr++;
            }
        }else if(rank*next_pow2(real_idx_dim[order[j]])/N < real_idx_dim[order[j]]){
            
            int offset = real_idx_dim[order[j]] - (rank)*next_pow2(real_idx_dim[order[j]])/N;
            for(int i = 0 ; i < real_idx_dim[order[j]] - (rank)*next_pow2(real_idx_dim[order[j]])/N; i++){
                v3[ctr] = aggr_challenges[order[j]];
                ctr++;
            }
            for(int i = 0; i < (next_pow2(real_idx_dim[order[j]])/N) -offset; i++) ctr++;
            //ctr = (j+1)*next_pow2(real_idx_dim[order[j]])/N;
            
        }else{
            for(int i = 0 ; i < next_pow2(real_idx_dim[order[j]])/N; i++){
                v3[ctr] = 0;
                ctr++;
            }
        }
    }
    /*
    if(rank != N-1){

        int ctr = 0;
        
        for(int i = 0 ; i < next_pow2(real_idx_dim[order[1]])/N; i++){
            v3[ctr] = aggr_challenges[order[1]];
            ctr++;
        }
        for(int i = 0 ; i < next_pow2(real_idx_dim[order[2]])/N; i++){
            v3[ctr] = aggr_challenges[order[2]];
            ctr++;
        }
    }else{
        int ctr = 0;
        
        for(int i = 0 ; i < real_idx_dim[order[0]] - (N-1)*next_pow2(real_idx_dim[order[0]])/N; i++){
            v3[ctr] = aggr_challenges[order[0]];
            ctr++;
        }
        
        ctr = next_pow2(real_idx_dim[order[0]])/N;
        for(int i = 0 ; i < real_idx_dim[order[1]] - (N-1)*next_pow2(real_idx_dim[order[1]])/N; i++){
            v3[ctr] = aggr_challenges[order[1]];
            ctr++;
        }
        ctr = 2*next_pow2(real_idx_dim[order[1]])/N;
        
        for(int i = 0 ; i < real_idx_dim[order[2]] - (N-1)*next_pow2(real_idx_dim[order[2]])/N; i++){
            v3[ctr] = aggr_challenges[order[2]];
            ctr++;
        }
    }    
    */
    
    // Optional conformance probe: capture one real quadratic local polynomial
    // from the optimized sparse-evaluation vectors. It does not consume or
    // mutate the protocol's Fiat-Shamir transcript.
    const char* dsc_probe_env =
        std::getenv("PVIA_NATIVE_SUMCHECK_DSC_QUADRATIC_PROBE");
    if (dsc_probe_env && std::string(dsc_probe_env) != "0" &&
        pvia::Runtime::instance().enabled()) {
        int world_size = 0;
        MPI_Comm_size(MPI_COMM_WORLD, &world_size);
        if (world_size == N && N > 0 && v1.size() == v2.size() &&
            v1.size() >= 2 && (v1.size() % 2) == 0) {
            const size_t active_count = v1.size();
            const size_t pairs = active_count / 2;
            quadratic_poly probe_poly =
                quadratic_poly(F_ZERO, F_ZERO, F_ZERO);
            for (size_t j = 0; j < pairs; ++j) {
                const linear_poly l1(
                    v1[2 * j + 1] - v1[2 * j], v1[2 * j]);
                const linear_poly l2(
                    v2[2 * j + 1] - v2[2 * j], v2[2 * j]);
                probe_poly = probe_poly + (l1 * l2);
            }
            if (pvia_verify_distributed_quadratic(
                    probe_poly, v1, v2, pairs)) {
                F local_claim = F_ZERO;
                for (size_t j = 0; j < active_count; ++j)
                    local_claim += v1[j] * v2[j];
                const u64 local_words[2] = {
                    static_cast<u64>(local_claim.real),
                    static_cast<u64>(local_claim.img)};
                std::vector<u64> all_words(
                    static_cast<size_t>(2 * world_size), 0);
                MPI_Allgather(local_words, 2, MPI_UNSIGNED_LONG_LONG,
                    all_words.data(), 2, MPI_UNSIGNED_LONG_LONG,
                    MPI_COMM_WORLD);
                F global_claim = F_ZERO;
                for (int party = 0; party < world_size; ++party)
                    global_claim += F(
                        static_cast<long long>(all_words[2 * party]),
                        static_cast<long long>(all_words[2 * party + 1]));

                auto& rt = pvia::Runtime::instance();
                const std::vector<pvia::FieldStateSegment> source_segments = {
                    {&v1, 0, active_count}, {&v2, 0, active_count}};
                const pvia::StateId source_state = rt.import_state_slices(
                    "dsc_quadratic_native_probe_input",
                    pvia::Phase::DISTRIBUTED_SUMCHECK, source_segments);
                if (source_state != 0) {
                    const pvia::RecordId record = rt.register_quadratic_operation(
                        pvia::Phase::DISTRIBUTED_SUMCHECK, 0xFFFFFFFEu,
                        pvia::Obligation::DERIVE, probe_poly, {});
                    rt.bind_state_dependencies(
                        record, std::vector<pvia::StateId>{source_state});
                    rt.bind_relation_kernel(
                        record, pvia::AuditRelationKernel::DSC_QUADRATIC);
                    rt.bind_public_field_aux(
                        record, pvia::AuditPublicAuxKind::SUMCHECK_CHALLENGE,
                        std::vector<F>{global_claim});
                    rt.activate_quadratic(record, probe_poly);
                    if (rank == 0)
                        std::cout << "[PVIA][dsc-quadratic-probe] REGISTERED "
                                  << "source_fields=" << active_count
                                  << " local_pairs=" << pairs << "\n";
                } else if (rank == 0) {
                    std::cerr << "[PVIA][dsc-quadratic-probe] FAILED state_capture\n";
                }
            } else if (rank == 0) {
                std::cerr << "[PVIA][dsc-quadratic-probe] FAILED local_arithmetic\n";
            }
        } else if (rank == 0) {
            std::cerr << "[PVIA][dsc-quadratic-probe] FAILED input_shape "
                      << "world_size=" << world_size << " N=" << N
                      << " v1=" << v1.size() << " v2=" << v2.size() << "\n";
        }
    }

    pt_cp.end();
    timer eval;
    eval.reset();
        
    eval.start();
    vector<pair<F,vector<F>>>  beta_evals2 =  _cubic_sumcheck(y,v1,v2,v3,ones,N);
    eval.end();
    if(rank == 0) printf("          Final Sumcheck: %lf\n",eval.get_time());
    //for(int i = 0; i < )
    F __r = hash_to_field({});
    
    r1.clear();r2.clear();
    
    for(int i = 0; i < beta_evals2[0].second.size() - (int)log2(N); i++){
        r1.push_back(beta_evals2[0].second[i]);
    }
    for(int i = r1.size(); i< beta_evals2[0].second.size(); i++){
        r2.push_back(beta_evals2[0].second[i]);
    }
    r1.push_back(__r);

    r2.insert(r2.begin(),r1.begin(),r1.end());
    
    return make_pair((F(1)-__r)*beta_evals2[0].first + __r*beta_evals2[1].first,r2);
    //return make_pair(evaluate_vector(beta_evals,temp_r),betas_r);

       
}



pair<F,vector<F>> _prove_sparse_eval(F y, F a, F b, F c, vector<vector<F>> &beta1, vector<vector<F>> &beta2, vector<sparse_eval_data> &data, 
                        vector<F> r1, vector<F> r2, 
                        int N){
    
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    pt_cp.start();
    vector<F> challenges(3);
    clock_t t1 = clock();
    for(int i = 0; i < 3; i++) challenges[i] = hash_to_field({0}); 
    
    
    vector<vector<F>> Tr(12);
    vector<vector<F>> polys,acc_polys(18);
    vector<vector<vector<F>>> acc_eval_points;
    vector<F> acc_evals;
    for(int j = 0; j < data.size(); j++){
        Tr[2*j].resize(next_pow2(data[j].IDX1.size()),F(1));
        Tr[2*j+1].resize(next_pow2(data[j].IDX1.size()),F(1));
        for(int i = 0; i < data[j].IDX1.size(); i++){
            Tr[2*j][i] = challenges[0]*beta1[j][i] +  challenges[1]*F(data[j].RD1[i]) + challenges[2]*F(data[j].IDX1[i]) + F(1);
            Tr[2*j+1][i] = challenges[0]*beta1[j][i] +  challenges[1]*F(data[j].WR1[i]) + challenges[2]*F(data[j].IDX1[i]) + F(1);
        }
    }
    for(int j = 0; j < data.size(); j++){
        Tr[2*j+6].resize(next_pow2(data[0].IDX2.size()),F(1));
        Tr[2*j+1+6].resize(next_pow2(data[0].IDX2.size()),F(1));
        for(int i = 0; i < data[j].IDX2.size(); i++){
            Tr[2*j+6][i] = challenges[0]*beta2[j][i] +  challenges[1]*F(data[j].RD2[i]) + challenges[2]*F(data[j].IDX2[i]) + F(1);
            Tr[2*j+1+6][i] = challenges[0]*beta2[j][i] +  challenges[1]*F(data[j].WR2[i]) + challenges[2]*F(data[j].IDX2[i]) + F(1);
        }
    }
    vector<F> output1,output2,output3;
    pt_cp.end();
    
    pair<F,vector<vector<F>>> claims = prove_product(Tr, output1, F(0), {}, N);
    vector<F> v1,v2;
    pt_cp.start();
    
    precompute_beta(claims.second[0],v1);
    precompute_beta(claims.second[2],v2);
    vector<vector<F>> eval_points1 = claims.second;
    for(int i = 0; i < data.size(); i++){
        polys.push_back(beta1[i]);
        polys.push_back(convert_to_field(data[i].RD1));
        polys.push_back(convert_to_field(data[i].IDX1));
        acc_polys[2*i+3] = polys[3*i+1];
        acc_polys[2*i+1+3] = polys[3*i+2];
    }
    for(int i = 0; i < data.size(); i++){
        polys.push_back(beta2[i]);
        polys.push_back(convert_to_field(data[i].RD2));
        polys.push_back(convert_to_field(data[i].IDX2));        
        acc_polys[2*i+6+3] = polys[3*i+1+9];
        acc_polys[2*i+1+6+3] = polys[3*i+2+9];
    }
    pt_cp.end();
    
    vector<F> evals = batch_distributed_eval(polys,v1,v2,N,
        PVIA_SCALAR_CTX_SPARSE_BATCH_1);
    pt_cp.start();
    
    vector<F> beta_evals,evals1;
    vector<F> betas_r = claims.second[0];
    vector<F> temp_r;
    
    for(int i = 0; i < (int)log2(next_pow2(2*beta1.size())); i++){
        betas_r.push_back(hash_to_field({0}));
        temp_r.push_back(betas_r[betas_r.size()-1]); 
    }
    betas_r.insert(betas_r.end(),claims.second[2].begin(),claims.second[2].end());
    
    //vector<F> evals2 = batch_distributed_eval(Tr,v1,v2,N);
    for(int i = 0; i < data.size();i++){
        beta_evals.push_back(evals[3*i]);
        evals1.push_back(evals[3*i+1]);
        evals1.push_back(evals[3*i+2]);
    }
    for(int i = 0; i < data.size();i++){
        beta_evals.push_back(evals[3*i+9]);
        evals1.push_back(evals[3*i+1+9]);
        evals1.push_back(evals[3*i+2+9]);
    }
    
    
    
    if(rank == 0){
        vector<F> Tr_evals(12,F(0));
        for(int i = 0; i < data.size();i++){
            Tr_evals[2*i] = challenges[0]*evals[3*i] +  challenges[1]*evals[3*i+1] + challenges[2]*evals[3*i+2] + F(1);
            Tr_evals[2*i+1] = Tr_evals[2*i] +  challenges[1];
        }
        for(int i = 0; i < data.size();i++){
            Tr_evals[2*i+6] = challenges[0]*evals[3*i+9] +  challenges[1]*evals[3*i+1+9] + challenges[2]*evals[3*i+2+9] + F(1);
            Tr_evals[2*i+1+6] = Tr_evals[2*i+6] +  challenges[1];
        }
        
        Tr_evals.resize(16,F(0));
        if(evaluate_vector(Tr_evals,claims.second[1]) != claims.first){
            printf("Sparse Eval Error 1\n");
        }
    }

    vector<F> base_beta1,base_beta2;
    compute_base_betas(r1,r2,base_beta1,base_beta2,N);

    Tr.clear();Tr.resize(6);
    for(int j = 0; j < data.size(); j++){
        Tr[2*j].clear();Tr[2*j+1].clear();
        Tr[2*j].resize(next_pow2(data[0].FINAL_FR1.size()),F(1));
        Tr[2*j+1].resize(next_pow2(data[0].FINAL_FR1.size()),F(1));
    
        for(int i = 0; i < data[j].FINAL_FR1.size(); i++){
            Tr[2*j+0][i] = challenges[0]*base_beta1[i] +  challenges[2]*F(rank*data[j].FINAL_FR1.size() + i) + F(1);
            Tr[2*j+1][i] = challenges[0]*base_beta1[i] +  challenges[1]*F(data[j].FINAL_FR1[i]) + challenges[2]*F(rank*data[j].FINAL_FR1.size() + i) + F(1);
        }
    }
    pt_cp.end();
    
    claims = prove_product(Tr, output2, F(0), {}, N);
    pt_cp.start();
    
    polys.clear();
    for(int i = 0; i < data.size(); i++){
        polys.push_back(convert_to_field(data[i].FINAL_FR1));
        acc_polys[i+15] = polys[i];    
    }
    v1.clear();v2.clear();
    precompute_beta(claims.second[0],v1);
    precompute_beta(claims.second[2],v2);
    pt_cp.end();
    vector<F> evals2 = batch_distributed_eval(polys,v1,v2,N,
        PVIA_SCALAR_CTX_SPARSE_BATCH_2);
    vector<vector<F>> eval_points2 = claims.second;


    pt_cp.start();
    
    Tr.clear();Tr.resize(6);
    for(int j = 0; j < data.size(); j++){
        Tr[2*j].clear();Tr[2*j+1].clear();
        Tr[2*j].resize(next_pow2(data[0].FINAL_FR2.size()),F(1));
        Tr[2*j+1].resize(next_pow2(data[0].FINAL_FR2.size()),F(1));
        for(int i = 0; i < data[j].FINAL_FR2.size(); i++){
            Tr[2*j][i] = challenges[0]*base_beta2[i] +  challenges[2]*F(rank*data[j].FINAL_FR2.size() + i) + F(1);
            Tr[2*j+1][i] = challenges[0]*base_beta2[i] +  challenges[1]*F(data[j].FINAL_FR2[i]) + challenges[2]*F(rank*data[j].FINAL_FR2.size() + i) + F(1);
        }
    }
    pt_cp.end();
    
    claims = prove_product(Tr, output3, F(0), {}, N);
    pt_cp.start();
    
    polys.clear();
    for(int i = 0; i < data.size(); i++){
        polys.push_back(convert_to_field(data[i].FINAL_FR2));
        acc_polys[i] = polys[i];    
    }
    v1.clear();v2.clear();
    timer eval;
    eval.start();
    precompute_beta(claims.second[0],v1);
    precompute_beta(claims.second[2],v2);
    pt_cp.end();
    vector<F> evals3 = batch_distributed_eval(polys,v1,v2,N,
        PVIA_SCALAR_CTX_SPARSE_BATCH_3);
    eval.end();
    vector<vector<F>> eval_points3 = claims.second;
    pt_cp.start();
    if(rank == 0) printf("          Distributed Eval: %lf\n",eval.get_time());
    
    if(rank == 0){
        //printf("%d\n",output1.size());
        for(int i = 0; i < 3; i++){
            if(output1[2*i]*output2[2*i+1] != output1[2*i+1]*output2[2*i+0]){
                printf("Error phase 2 %d\n",i);
            }
        }
        for(int i = 0; i < 3; i++){
            if(output1[2*i+6]*output3[2*i+1] != output1[2*i+1+6]*output3[2*i+0]){
                printf("Error phase 2 %d\n",i);
            }
        }
    }
    acc_eval_points.push_back(eval_points3);
    acc_eval_points.push_back(eval_points1);
    acc_eval_points.push_back(eval_points2);
    acc_evals = evals3;
    acc_evals.insert(acc_evals.end(),evals1.begin(),evals1.end());
    acc_evals.insert(acc_evals.end(),evals2.begin(),evals2.end());
    pt_cp.end();
    
    distributed_accumulation(acc_polys, acc_eval_points, acc_evals, N);
    
    pt_cp.start();
    /// Need to do the final sumcheck 
    vector<F> v3,ones(N,1);
    
    v1.clear();v2.clear();
    for(int i = 0; i < beta1.size(); i++){
        v1.insert(v1.end(),beta1[i].begin(),beta1[i].end());
        v2.insert(v2.end(),beta2[i].begin(),beta2[i].end());
    }
    v1.resize(next_pow2(v1.size()),F(0));v2.resize(next_pow2(v2.size()),F(0));
    
    
    int ca = 0,cb = 0,cc = 0;
    v3.resize(4*next_pow2(real_idx_dim[0])/N,F(0));
    if(rank != N-1){
        int ctr = 0;
        for(int i = 0 ; i < next_pow2(real_idx_dim[0])/N; i++){
            v3[ctr] = a;
            ctr++;
        }
        for(int i = 0 ; i < next_pow2(real_idx_dim[1])/N; i++){
            v3[ctr] = b;
            ctr++;
        }
        for(int i = 0 ; i < next_pow2(real_idx_dim[2])/N; i++){
            v3[ctr] = c;
            ctr++;
        }
    }else{
        int ctr = 0;
        for(int i = 0 ; i < real_idx_dim[0] - (N-1)*next_pow2(real_idx_dim[0])/N; i++){
            v3[ctr] = a;
            ctr++;
        }
        ctr = next_pow2(real_idx_dim[0])/N;
        for(int i = 0 ; i < real_idx_dim[1] - (N-1)*next_pow2(real_idx_dim[1])/N; i++){
            v3[ctr] = b;
            ctr++;
        }
        ctr = 2*next_pow2(real_idx_dim[1])/N;
        
        for(int i = 0 ; i < real_idx_dim[2] - (N-1)*next_pow2(real_idx_dim[2])/N; i++){
            v3[ctr] = c;
            ctr++;
        }
    }    
    pt_cp.end();
    eval.reset();
    eval.start();
    vector<pair<F,vector<F>>>  beta_evals2 =  _cubic_sumcheck(y,v1,v2,v3,ones,N);
    eval.end();
    if(rank == 0) printf("          Final Sumcheck: %lf\n",eval.get_time());
    
    beta_evals.resize(next_pow2(beta_evals.size()),F(0));
    return make_pair(evaluate_vector(beta_evals,temp_r),betas_r);
}
