#pragma once
#include "MPI_utils.hpp"
#include "timer.hpp"
#include "accountability/PVIA.hpp"
#include "accountability/AccountableAggregation.hpp"
#include "accountability/JointPackedPreprocessing.hpp"
#include "accountability/AuthenticatedMpcExchange.hpp"
#include "accountability/ExperimentMetrics.hpp"
#include <cstdlib>
#include <cstring>
extern vector<vector<pair<int,int>>> A,B,C;
// Transposed R1CS matrixes
extern vector<vector<pair<int,int>>> tA,tB,tC;
extern vector<vector<pair<int,int>>> pA,pB,pC;
extern int logm,logn;
extern vector<int> real_idx_dim;
extern double cm;
extern timer pt_cp,vt;
extern int com_rounds;

namespace {
void enforce_pvia_prebroadcast_release_gate(
    const char* release_name,
    pvia::Phase phase_override = pvia::Phase::UNKNOWN,
    uint32_t round_override = 0) {
    if (!release_name) return;
    auto& rt = pvia::Runtime::instance();
    if (!rt.enabled()) return;
    const bool explicit_scope = phase_override != pvia::Phase::UNKNOWN;
    const pvia::Phase phase = explicit_scope ? phase_override : rt.pending_phase();
    const uint32_t round = explicit_scope ? round_override : rt.pending_round();
    if (phase != pvia::Phase::UNKNOWN &&
        rt.pre_release_gate(release_name, phase, round))
        return;
    if (phase != pvia::Phase::UNKNOWN)
        rt.handle_global_failure(release_name, phase, round);
    std::exit(15);
}

std::array<u64, pvia::META_WORDS> prepare_cosumcheck_tail_send(
    pvia::Phase phase, uint32_t tail_round,
    const vector<F>& local_fields, const vector<F>& public_aux) {
    std::array<u64, pvia::META_WORDS> meta{};
    auto& rt = pvia::Runtime::instance();
    if (!rt.enabled()) return meta;

    std::vector<pvia::OperationRef> predecessors;
    const auto predecessor = rt.previous_round_operation_ref(
        phase, tail_round, pvia::Obligation::PUBLISH);
    if (predecessor.object_id != 0)
        predecessors.push_back(predecessor);

    const pvia::RecordId send_record = rt.register_vector_operation(
        phase, tail_round, pvia::Obligation::SEND,
        local_fields, predecessors);
    if (send_record == 0) std::exit(15);
    if (!public_aux.empty()) {
        rt.bind_public_field_aux(
            send_record, pvia::AuditPublicAuxKind::GENERIC_FIELDS,
            public_aux);
    }
    rt.activate_vector(send_record, local_fields);
    const auto payload = pvia::serialize_field_vector_for_meta(local_fields);
    meta = rt.make_pending_meta(payload, false);
    return meta;
}

std::array<u64, pvia::META_WORDS> prepare_scalar_aggregation_send(
    uint32_t context_id, const vector<F>& local_fields,
    const vector<F>& public_aux) {
    std::array<u64, pvia::META_WORDS> meta{};
    auto& rt = pvia::Runtime::instance();
    if (!rt.enabled()) return meta;

    const pvia::RecordId send_record = rt.register_vector_operation(
        pvia::Phase::SCALAR_AGGREGATION, context_id,
        pvia::Obligation::SEND, local_fields, {});
    if (send_record == 0) std::exit(15);
    if (!public_aux.empty()) {
        rt.bind_public_field_aux(
            send_record, pvia::AuditPublicAuxKind::GENERIC_FIELDS,
            public_aux);
    }
    rt.activate_vector(send_record, local_fields);
    const auto payload = pvia::serialize_field_vector_for_meta(local_fields);
    meta = rt.make_pending_meta(payload, false);
    return meta;
}

std::array<u64, pvia::META_WORDS> prepare_scalar_aggregation_publication(
    uint32_t context_id, const vector<F>& result_fields,
    const vector<F>& public_aux) {
    std::array<u64, pvia::META_WORDS> meta{};
    auto& rt = pvia::Runtime::instance();
    if (!rt.enabled()) return meta;

    const auto contributors = rt.checkpoint_operations(
        pvia::Phase::SCALAR_AGGREGATION, context_id,
        pvia::Obligation::SEND);
    const pvia::RecordId aggregate_record = rt.register_vector_operation(
        pvia::Phase::SCALAR_AGGREGATION, context_id,
        pvia::Obligation::AGGREGATE, result_fields, contributors);
    if (aggregate_record == 0) std::exit(15);
    if (!public_aux.empty()) {
        rt.bind_public_field_aux(
            aggregate_record,
            pvia::AuditPublicAuxKind::AGGREGATION_WEIGHTS,
            public_aux);
    }
    rt.activate_vector(aggregate_record, result_fields);

    const pvia::RecordId publish_record = rt.prepare_followup_vector(
        pvia::Obligation::PUBLISH, result_fields);
    if (publish_record == 0) std::exit(15);
    rt.activate_vector(publish_record, result_fields);
    const auto payload = pvia::serialize_field_vector_for_meta(result_fields);
    meta = rt.make_pending_meta(payload, false);
    return meta;
}

std::array<u64, pvia::META_WORDS> prepare_cosumcheck_tail_publication(
    pvia::Phase phase, uint32_t tail_round,
    const vector<F>& result_fields, const vector<F>& public_aux) {
    std::array<u64, pvia::META_WORDS> meta{};
    auto& rt = pvia::Runtime::instance();
    if (!rt.enabled()) return meta;

    const auto contributors = rt.checkpoint_operations(
        phase, tail_round, pvia::Obligation::SEND);
    const pvia::RecordId aggregate_record = rt.register_vector_operation(
        phase, tail_round, pvia::Obligation::AGGREGATE,
        result_fields, contributors);
    if (aggregate_record == 0) std::exit(15);
    if (!public_aux.empty()) {
        rt.bind_public_field_aux(
            aggregate_record,
            pvia::AuditPublicAuxKind::AGGREGATION_WEIGHTS,
            public_aux);
    }
    rt.activate_vector(aggregate_record, result_fields);

    const pvia::RecordId publish_record = rt.prepare_followup_vector(
        pvia::Obligation::PUBLISH, result_fields);
    if (publish_record == 0) std::exit(15);
    rt.activate_vector(publish_record, result_fields);
    const auto payload = pvia::serialize_field_vector_for_meta(result_fields);
    meta = rt.make_pending_meta(payload, false);
    return meta;
}

void send_bound_payload(
    const std::array<u64, pvia::META_WORDS>& meta,
    const vector<u64>& payload, int receiver) {
    auto& rt = pvia::Runtime::instance();
    if (rt.enabled()) {
        auto sealed = meta;
        if (!rt.seal_transfer_meta(sealed, payload))
            std::exit(15);
        rt.observe_outgoing_transfer(sealed, payload);
        rt.observe_local_payload(payload);
        MPI_Send(
            sealed.data(), pvia::META_WORDS, MPI_UINT64_T,
            receiver, pvia::META_TAG, MPI_COMM_WORLD);
    }
}
} // namespace


void myAlltoAll(vector<u64> &in, vector<u64> &out, int N, int total_size){
    int rank;
    
    vector<vector<u64>> recv_data(N);
    vector<vector<u64>> send_data(N);
    MPI_Request req1,req2;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    for(int i = 0; i < N; i++){
        if(i == rank)continue;
        send_data[i].resize(total_size/N);
        recv_data[i].resize(total_size/N);
        for(int j = 0; j < total_size/N; j++){
            send_data[i][j] = in[i*total_size/N+j];
        }
        MPI_Isend(send_data[i].data(),send_data[i].size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req1);
        MPI_Irecv(recv_data[i].data(),send_data[i].size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req2);
    }
    for(int i = 0; i < N; i++){
        if(i == rank){
            for(int j = 0; j < total_size/N; j++){
                out[i*total_size/N + j] = in[i*total_size/N + j];
            }
            continue;
        }
        MPI_Wait(&req2,MPI_STATUS_IGNORE);
        for(int j = 0; j < total_size/N; j++){
            out[i*total_size/N + j] = recv_data[i][j];
        }
    }
    for(int i = 0; i < N; i++){
        if(i == rank) continue;
        MPI_Wait(&req1,MPI_STATUS_IGNORE);
    }

}

void myBcast(vector<u64> &data, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    if(rank == 0){
        vector<MPI_Request> req(N-1);
        for(int i = 1; i < N; i++){
            MPI_Isend(data.data(),data.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i-1]);
        }
        for(int i = 0; i < N-1; i++){
            MPI_Wait(&req[i],MPI_STATUS_IGNORE);
        }
    }else{
        MPI_Request req;
        MPI_Irecv(data.data(),data.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
    }
}


F F_ip(vector<F> &data, vector<F> &v1, vector<F> &v2, int k, int _k, int N,
       uint32_t scalar_context){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    F y = F(0),sum = F(0);
    //printf("%d,%d\n",data.size(),v1.size());
    pt_cp.start();
    for(int i = 0; i < data.size(); i++){
        y += data[i]*v1[i];
    }
    pt_cp.end();

    vector<F> scalar_public_aux = v1;
    scalar_public_aux.insert(
        scalar_public_aux.end(), v2.begin(), v2.end());
    scalar_public_aux.push_back(F(k));
    scalar_public_aux.push_back(F(_k));
    scalar_public_aux.push_back(F(N));
    const vector<F> local_scalar_fields = {y};
    const auto scalar_meta = prepare_scalar_aggregation_send(
        scalar_context, local_scalar_fields, scalar_public_aux);
    std::array<u64, pvia::META_WORDS> scalar_publish_meta{};

    vector<u64> f_element(2);
    com_rounds+=2;
    if(rank == 0){
        if (pvia::Runtime::instance().enabled())
            pvia::Runtime::instance().consume_pending();
        vector<F> Y(N);Y[0] = y;
        vector<MPI_Request> req(N);
        vector<vector<u64>> recv_data(N);

        for(int i = 1; i < N; i++){
            recv_data[i].resize(2);
            MPI_Irecv(recv_data[i].data(),2,MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i]);
            //MPI_Recv(f_element.data(),2,MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
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
                    i, remote_meta, recv_data[i]);
            }
            Y[i].real = recv_data[i][0];
            Y[i].img = recv_data[i][1];

        }
        pt_cp.start();
    
        fft(Y,(int)log2(Y.size()),true);
        
        F omega = getRootOfUnity(1+(int)log2(N)).inv();
        F mul = F(1); 
        for(int i = 0; i < Y.size(); i++){
            Y[i] = mul*Y[i];
            mul = mul*omega;
        }
        
        fft(Y,(int)log2(Y.size()),false);
        
        for(int i = 0; i < v2.size(); i++){
            sum += v2[i]*Y[N*i/_k];
        }
        f_element[0] = sum.real;
        f_element[1] = sum.img;
        if (pvia::Runtime::instance().enabled()) {
            scalar_publish_meta = prepare_scalar_aggregation_publication(
                scalar_context, vector<F>{sum}, scalar_public_aux);
        }
        pt_cp.end();
    
        //for(int i = 1; i < N; i++){
        //    cm += 8*f_element.size()/1024.0;
        //    MPI_Send(f_element.data(), 2,MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        //}

    }else{
        f_element[0] = y.real;
        f_element[1] = y.img;
        cm += 8*f_element.size()/1024.0;
        send_bound_payload(scalar_meta, f_element, 0);
        MPI_Request req;
        MPI_Isend(f_element.data(),2,MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
        if (pvia::Runtime::instance().enabled())
            pvia::Runtime::instance().consume_pending();
        //MPI_Recv(f_element.data(),2,MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
    }
    myBcast(f_element,N);
    if (pvia::Runtime::instance().enabled()) {
        pvia::publish_rank0_aggregate_meta(
            scalar_publish_meta, f_element, rank);
        pvia::Runtime::instance().consume_pending();
    }
    if(rank != 0){
        sum.real = f_element[0];
        sum.img = f_element[1];
    }
    return sum;
}

F F_ip_prod(vector<F> &data1, vector<F> &data2, vector<F> &v1, vector<F> &v2, int k, int _k, int N,
            uint32_t scalar_context){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    F y = F(0),sum = F(0);
    pt_cp.start();
     
    for(int i = 0; i < data1.size(); i++){
        y += data1[i]*data2[i]*v1[i];
    }
    pt_cp.end();

    vector<F> scalar_public_aux = v1;
    scalar_public_aux.insert(
        scalar_public_aux.end(), v2.begin(), v2.end());
    scalar_public_aux.push_back(F(k));
    scalar_public_aux.push_back(F(_k));
    scalar_public_aux.push_back(F(N));
    const vector<F> local_scalar_fields = {y};
    const auto scalar_meta = prepare_scalar_aggregation_send(
        scalar_context, local_scalar_fields, scalar_public_aux);
    std::array<u64, pvia::META_WORDS> scalar_publish_meta{};

    vector<u64> f_element(2);
    com_rounds+=2;
    
    if(rank == 0){
        if (pvia::Runtime::instance().enabled())
            pvia::Runtime::instance().consume_pending();
        
        vector<F> Y(N);Y[0] = y;
        vector<MPI_Request> req(N);
        vector<vector<u64>> recv_data(N);

        for(int i = 1; i < N; i++){
            recv_data[i].resize(2);
            //MPI_Recv(f_element.data(),2,MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            MPI_Irecv(recv_data[i].data(),2,MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i]);
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
                    i, remote_meta, recv_data[i]);
            }
            Y[i].real = recv_data[i][0];
            Y[i].img = recv_data[i][1];
        }
        pt_cp.start();
    
        fft(Y,(int)log2(Y.size()),true);
        F omega = getRootOfUnity(1+(int)log2(N)).inv();
        F mul = F(1);
        for(int i = 0; i < Y.size(); i++){
            Y[i] = mul*Y[i];
            mul = mul*omega;
        }
        fft(Y,(int)log2(Y.size()),false);
        
        for(int i = 0; i < v2.size(); i++){
            sum += v2[i]*Y[N*i/_k];
        }
        f_element[0] = sum.real;
        f_element[1] = sum.img;
        if (pvia::Runtime::instance().enabled()) {
            scalar_publish_meta = prepare_scalar_aggregation_publication(
                scalar_context, vector<F>{sum}, scalar_public_aux);
        }
        pt_cp.end();
    
        //for(int i = 1; i < N; i++){
        //    cm += 8*f_element.size()/1024.0;
        //    MPI_Send(f_element.data(), 2,MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        //}

    }else{
        f_element[0] = y.real;
        f_element[1] = y.img;
        cm += 8*f_element.size()/1024.0;
        send_bound_payload(scalar_meta, f_element, 0);
        MPI_Request req;
        MPI_Isend(f_element.data(),f_element.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
        if (pvia::Runtime::instance().enabled())
            pvia::Runtime::instance().consume_pending();
    
        //MPI_Send(f_element.data(),2,MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        //MPI_Recv(f_element.data(),2,MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
    }
    myBcast(f_element,N);
    if (pvia::Runtime::instance().enabled()) {
        pvia::publish_rank0_aggregate_meta(
            scalar_publish_meta, f_element, rank);
        pvia::Runtime::instance().consume_pending();
    }
    if(rank != 0){
        sum.real = f_element[0];
        sum.img = f_element[1];
    }
    return sum;
}

quadratic_poly _batch_aggregate(vector<quadratic_poly> polys,vector<F> v2, int k, bool secret_shared){
    quadratic_poly H;
    F a= F(0),b= F(0),c = F(0);
    if(!secret_shared){
        for(int i = 0; i < polys.size(); i++){
            a += v2[i]*polys[i].a;
            b += v2[i]*polys[i].b;
            c += v2[i]*polys[i].c;
        }
        H = quadratic_poly(a,b,c);
    }else{
        int N = polys.size();
        vector<F> _a(N),_b(N),_c(N);
        for(int i = 0; i < N; i++){
            _a[i] = polys[i].a;_b[i] = polys[i].b;_c[i] = polys[i].c; 
        }
        pt_cp.start();
    
        fft(_a,(int)log2(_a.size()),true);
        fft(_b,(int)log2(_a.size()),true);
        fft(_c,(int)log2(_a.size()),true);
        F omega = getRootOfUnity(1+(int)log2(N)).inv();
        F mul = F(1);
        for(int i = 0; i < _a.size(); i++){
            _a[i] = mul*_a[i];
            _b[i] = mul*_b[i];
            _c[i] = mul*_c[i];
            mul = mul*omega;
        }
        
        fft(_a,(int)log2(_a.size()),false);
        fft(_b,(int)log2(_a.size()),false);
        fft(_c,(int)log2(_a.size()),false);
        
        for(int j = 0; j < v2.size(); j++){
            a += v2[j]*_a[N*j/k];
            b += v2[j]*_b[N*j/k];
            c += v2[j]*_c[N*j/k];
        }
        H = quadratic_poly(a,b,c);
        pt_cp.end();
            

    }
    return H;
}   

vector<quadratic_poly> batch_aggregate(vector<quadratic_poly> H, vector<vector<F>> v2, vector<bool> secret_shared, vector<int> rounds,vector<int> k, int round, int N, const char* release_name){
    vector<F> poly;
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    
    for(int i = 0; i < H.size(); i++){
        if(rounds[i] > round){
            poly.push_back(H[i].a);
            poly.push_back(H[i].b);
            poly.push_back(H[i].c);
        } 
    }
    vector<u64> coef_u;
    field_vector_serialize(poly,coef_u);

    std::array<u64, pvia::META_WORDS> pvia_meta{};
    const bool pvia_on = pvia::Runtime::instance().enabled();
    if (pvia_on) {
        pvia_meta = pvia::Runtime::instance().make_pending_meta(coef_u, false);
        pvia::Runtime::instance().observe_local_payload(coef_u);
    }

    com_rounds +=2;
    vector<quadratic_poly> final_P(rounds.size());
    std::array<u64, pvia::META_WORDS> pvia_aggregate_meta{};
        
    if(rank == 0){
        vector<MPI_Request> req(N-1);
        vector<vector<u64>> recv_data(N-1); 
        vector<vector<F>> polys(N);
        polys[0] = poly; 
        for(int i = 0; i < N-1; i++){
            recv_data[i].resize(coef_u.size());
            MPI_Irecv(recv_data[i].data(),recv_data[i].size(),MPI_UINT64_T,i+1,0,MPI_COMM_WORLD,&req[i]);
        }
        for(int i = 0; i < N-1; i++){
            std::array<u64, pvia::META_WORDS> remote_meta{};
            if (pvia_on) {
                MPI_Recv(remote_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                         i+1, pvia::META_TAG, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            }
            MPI_Wait(&req[i],MPI_STATUS_IGNORE);
            if (pvia_on)
                pvia::Runtime::instance().observe_remote_meta(i+1, remote_meta, recv_data[i]);
            field_vector_deserialize(recv_data[i],polys[i+1]); 
        }
        vector<vector<quadratic_poly>> P(rounds.size());
        int ctr = 0;
        for(int i = 0; i < rounds.size(); i++){
            if(rounds[i] > round){
                P[i].resize(N);
                for(int j = 0; j < N; j++) {
                    P[i][j] = quadratic_poly(polys[j][3*ctr],polys[j][3*ctr+1],polys[j][3*ctr+2]);
                }
                ctr++;
            }
            if(P[i].size() != 0){
                final_P[i] = (_batch_aggregate(P[i],v2[i],2*k[i],secret_shared[i]));
            }
        }
        poly.clear();
        for(int i = 0; i < final_P.size(); i++){
            if(P[i].size() != 0){
                poly.push_back(final_P[i].a);
                poly.push_back(final_P[i].b);
                poly.push_back(final_P[i].c);

            }
        }
        //printf("%d, (%lld),%lld\n",round,final_P[1].a.real,poly[0].real);
        if (pvia_on) {
            vector<F> pvia_batch_aux = {
                F(N), F(round), F(static_cast<int>(rounds.size()))};
            for (int idx = 0; idx < rounds.size(); ++idx) {
                pvia_batch_aux.push_back(F(rounds[idx]));
                pvia_batch_aux.push_back(F(k[idx]));
                pvia_batch_aux.push_back(F(secret_shared[idx] ? 1 : 0));
                pvia_batch_aux.push_back(F(static_cast<int>(v2[idx].size())));
                pvia_batch_aux.insert(
                    pvia_batch_aux.end(), v2[idx].begin(), v2[idx].end());
            }
            pvia_aggregate_meta = pvia::bind_rank0_aggregate(
                poly, "AGGREGATE_BATCH", rank, pvia_batch_aux,
                pvia::AuditRelationKernel::AGGREGATE_BATCH);
        }
        field_vector_serialize(poly,coef_u);
        
    }else{
        if (pvia_on) {
            pvia::Runtime::instance().seal_transfer_meta(pvia_meta, coef_u);
            pvia::Runtime::instance().observe_outgoing_transfer(pvia_meta, coef_u);
            MPI_Send(pvia_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                     0, pvia::META_TAG, MPI_COMM_WORLD);
        }
        MPI_Request req;
        MPI_Isend(coef_u.data(),coef_u.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
    }
    enforce_pvia_prebroadcast_release_gate(
        release_name, pvia::Phase::PCS, static_cast<uint32_t>(round));
    myBcast(coef_u,N);
    if (pvia_on)
        pvia::publish_rank0_aggregate_meta(pvia_aggregate_meta, coef_u, rank);
    {
        field_vector_deserialize(coef_u,poly);
        int ctr = 0;
        for(int i = 0; i < rounds.size(); i++){
            if(rounds[i] > round){
                final_P[i] = quadratic_poly(poly[3*ctr],poly[3*ctr+1],poly[3*ctr+2]);
                ctr++;
            }
        }
        //printf("%d, (%lld)\n",round,final_P[1].a.real);
        
    }
    if (pvia_on) pvia::Runtime::instance().consume_pending();
    return final_P;

}

quadratic_poly aggregate_quadratic_poly(quadratic_poly H, int k, int _k, int N, const char* release_name, pvia::Phase gate_phase, uint32_t gate_round){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    F a = F(0),b = F(0),c = F(0);
    pt_cp.start();
      
    vector<F> coef; coef.push_back(H.a);coef.push_back(H.b);coef.push_back(H.c);
    vector<u64> coef_u;
    
    field_vector_serialize(coef,coef_u);
    pt_cp.end();

    // PVIA sidecar metadata is transmitted only when the development path is enabled.
    std::array<u64, pvia::META_WORDS> pvia_meta{};
    const bool pvia_on = pvia::Runtime::instance().enabled();
    if (pvia_on) {
        pvia_meta = pvia::Runtime::instance().make_pending_meta(coef_u, false);
        pvia::Runtime::instance().observe_local_payload(coef_u);
    }

    com_rounds+=2;
    std::array<u64, pvia::META_WORDS> pvia_aggregate_meta{};
    if(rank == 0){
        vector<F> _a(N),_b(N),_c(N);
        _a[0] = coef[0];_b[0] = coef[1];_c[0] = coef[2]; 
        vector<MPI_Request> req(N);
        vector<vector<u64>> recv_data(N);

        for(int i = 1; i < N; i++){
            recv_data[i].resize(6);
            //MPI_Recv(coef_u.data(),6,MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            MPI_Irecv(recv_data[i].data(),6,MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i]);
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
            field_vector_deserialize(recv_data[i],coef);
            _a[i] = coef[0];_b[i] = coef[1];_c[i] = coef[2]; 
        
        }
        pt_cp.start();
    
        fft(_a,(int)log2(_a.size()),true);
        fft(_b,(int)log2(_a.size()),true);
        fft(_c,(int)log2(_a.size()),true);
        F omega = getRootOfUnity(1+(int)log2(N)).inv();
        F mul = F(1);
        for(int i = 0; i < _a.size(); i++){
            _a[i] = mul*_a[i];
            _b[i] = mul*_b[i];
            _c[i] = mul*_c[i];
            mul = mul*omega;
        }
        fft(_a,(int)log2(_a.size()),false);
        fft(_b,(int)log2(_a.size()),false);
        fft(_c,(int)log2(_a.size()),false);
        
        for(int j = 0; j < k; j++){
            a += _a[N*j/_k];
            b += _b[N*j/_k];
            c += _c[N*j/_k];
        }
        coef[0] = a;coef[1] = b;coef[2] = c;
        if (pvia_on) pvia_aggregate_meta = pvia::bind_rank0_aggregate(
            coef, "AGGREGATE_QUADRATIC", rank,
            pvia::make_aggregation_aux({}, N, k, _k));
        field_vector_serialize(coef,coef_u);
        pt_cp.end();
    
        //for(int i = 1; i < N; i++){
        //    cm += 8*coef_u.size()/1024.0;
        //    MPI_Send(coef_u.data(),6,MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        //}        
    }else{
        cm += 8*coef_u.size()/1024.0;
        if (pvia_on) {
            pvia::Runtime::instance().seal_transfer_meta(pvia_meta, coef_u);
            pvia::Runtime::instance().observe_outgoing_transfer(pvia_meta, coef_u);
            MPI_Send(pvia_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                     0, pvia::META_TAG, MPI_COMM_WORLD);
        }
        MPI_Request req;
        MPI_Isend(coef_u.data(),coef_u.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);

        //MPI_Send(coef_u.data(),6,MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        //MPI_Recv(coef_u.data(),6,MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        //a = coef[0];b = coef[1];c = coef[2]; 
    }
    enforce_pvia_prebroadcast_release_gate(release_name, gate_phase, gate_round);
    myBcast(coef_u,N);
    if (pvia_on) pvia::publish_rank0_aggregate_meta(
        pvia_aggregate_meta, coef_u, rank);
    field_vector_deserialize(coef_u,coef);
    a = coef[0];b = coef[1];c = coef[2];
    H = quadratic_poly(a,b,c);
    if (pvia_on) pvia::Runtime::instance().consume_pending();
    return H;
}

quadratic_poly aggregate_quadratic_poly(
    quadratic_poly H, int k, int _k, int N, const char* release_name) {
    return aggregate_quadratic_poly(
        H, k, _k, N, release_name, pvia::Phase::UNKNOWN, 0);
}

quadratic_poly aggregate_quadratic_poly(quadratic_poly H, vector<F> &v, int k, int _k, int N, const char* release_name, pvia::Phase gate_phase, uint32_t gate_round){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    F a = F(0),b = F(0),c = F(0);
    pt_cp.start();
        
    vector<F> coef; coef.push_back(H.a);coef.push_back(H.b);coef.push_back(H.c);
    vector<u64> coef_u;
    
    field_vector_serialize(coef,coef_u);
    pt_cp.end();

    // PVIA sidecar metadata is transmitted only when the development path is enabled.
    std::array<u64, pvia::META_WORDS> pvia_meta{};
    const bool pvia_on = pvia::Runtime::instance().enabled();
    if (pvia_on) {
        pvia_meta = pvia::Runtime::instance().make_pending_meta(coef_u, false);
        pvia::Runtime::instance().observe_local_payload(coef_u);
    }

    com_rounds+=2;
    std::array<u64, pvia::META_WORDS> pvia_aggregate_meta{};
    if(rank == 0){
        vector<F> _a(N),_b(N),_c(N);
        _a[0] = coef[0];_b[0] = coef[1];_c[0] = coef[2]; 
        vector<MPI_Request> req(N);
        vector<vector<u64>> recv_data(N);
        for(int i = 1; i < N; i++){
            recv_data[i].resize(6);
            MPI_Irecv(recv_data[i].data(),6,MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i]);
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
            //MPI_Recv(coef_u.data(),6,MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            field_vector_deserialize(recv_data[i],coef);
            _a[i] = coef[0];_b[i] = coef[1];_c[i] = coef[2]; 
        }
        pt_cp.start();
    
        fft(_a,(int)log2(_a.size()),true);
        fft(_b,(int)log2(_a.size()),true);
        fft(_c,(int)log2(_a.size()),true);
        F omega = getRootOfUnity(1+(int)log2(N)).inv();
        F mul = F(1);
        for(int i = 0; i < _a.size(); i++){
            _a[i] = mul*_a[i];
            _b[i] = mul*_b[i];
            _c[i] = mul*_c[i];
            mul = mul*omega;
        }
        
        fft(_a,(int)log2(_a.size()),false);
        fft(_b,(int)log2(_a.size()),false);
        fft(_c,(int)log2(_a.size()),false);
        
        for(int j = 0; j < v.size(); j++){
            a += v[j]*_a[N*j/_k];
            b += v[j]*_b[N*j/_k];
            c += v[j]*_c[N*j/_k];
        }
        coef[0] = a;coef[1] = b;coef[2] = c;
        if (pvia_on) pvia_aggregate_meta = pvia::bind_rank0_aggregate(
            coef, "AGGREGATE_QUADRATIC_WEIGHTED", rank,
            pvia::make_aggregation_aux(v, N, k, _k),
            pvia::AuditRelationKernel::AGGREGATE_WEIGHTED);
        field_vector_serialize(coef,coef_u);
        pt_cp.end();
        //for(int i = 1; i < N; i++){
            //cm += 8*coef_u.size()/1024.0;
            //MPI_Send(coef_u.data(),6,MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        //}        
    }else{
        cm += 8*coef_u.size()/1024.0;
        if (pvia_on) {
            pvia::Runtime::instance().seal_transfer_meta(pvia_meta, coef_u);
            pvia::Runtime::instance().observe_outgoing_transfer(pvia_meta, coef_u);
            MPI_Send(pvia_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                     0, pvia::META_TAG, MPI_COMM_WORLD);
        }
        MPI_Request req;
        MPI_Isend(coef_u.data(),coef_u.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);

        //MPI_Send(coef_u.data(),6,MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        //MPI_Recv(coef_u.data(),6,MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
    }
    enforce_pvia_prebroadcast_release_gate(release_name, gate_phase, gate_round);
    myBcast(coef_u,N);
    if (pvia_on) pvia::publish_rank0_aggregate_meta(
        pvia_aggregate_meta, coef_u, rank);
    field_vector_deserialize(coef_u,coef);
    a = coef[0];b = coef[1];c = coef[2];

    H = quadratic_poly(a,b,c);
    if (pvia_on) pvia::Runtime::instance().consume_pending();
    return H;
}


quadratic_poly aggregate_quadratic_poly(
    quadratic_poly H, vector<F> &v, int k, int _k, int N,
    const char* release_name) {
    return aggregate_quadratic_poly(
        H, v, k, _k, N, release_name, pvia::Phase::UNKNOWN, 0);
}

vector<F> zero_check_sumcheck_local(vector<F> final_v1, vector<F> final_v2, 
                                    vector<F> final_v3, vector<F> h1, 
                                    vector<F> h2, vector<F> &beta1, vector<F> &beta2,
                                    F b, F y, int k, int _k, int N){
    
    pt_cp.start();
    vector<F> omegas;
    F omega = getRootOfUnity(1+(int)log2(N));
    omega = omega.inv();
    F mul = F(1);
    for(int i = 0; i  < N; i++){
        omegas.push_back(mul);
        mul = mul*omega;
    }
    
    //for(int i = 0; i < final_v1.size(); i++){
        fft(final_v1,(int)log2(final_v1.size()),true);
        fft(final_v2,(int)log2(final_v2.size()),true);
        fft(final_v3,(int)log2(final_v3.size()),true);
        fft(h1,(int)log2(h1.size()),true);
        fft(h2,(int)log2(h2.size()),true);
        
        for(int j = 0; j < final_v1.size(); j++){
            final_v1[j] = omegas[j]*final_v1[j];
            final_v2[j] = omegas[j]*final_v2[j];
            final_v3[j] = omegas[j]*final_v3[j];
            h1[j] = omegas[j]*h1[j];
            h2[j] = omegas[j]*h2[j];
        }

        fft(final_v1,(int)log2(final_v1.size()),false);
        fft(final_v2,(int)log2(final_v2.size()),false);
        fft(final_v3,(int)log2(final_v3.size()),false);
        fft(h1,(int)log2(h1.size()),false);
        fft(h2,(int)log2(h2.size()),false);
    //}
    

    vector<F> v1(k),v2(k),v3(k);
    vector<F> r1(k),r2(k);
    int ctr = 0;
    //for(int j = 0; j < final_v1.size(); j++){
        for(int i = 0; i < k; i++){
            v1[ctr] = final_v1[N*i/_k];
            v2[ctr] = final_v2[N*i/_k];
            v3[ctr] = final_v3[N*i/_k];
            r1[ctr] = h1[N*i/_k];
            r2[ctr++] = h2[N*i/_k];
        }
    //}
    
    beta2.resize(v1.size());
    //for(int j = 0; j < final_v1.size(); j++){
        for(int i = 0; i < k; i++) beta2[i] = beta2[i]*beta1[0];
        
    //}
    
    int rounds = (int)log2(k);
    vector<F> challenges(rounds);
    for(int i = 0; i < rounds; i++){
        quadratic_poly p = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
        quadratic_poly p_r = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
        linear_poly _p = linear_poly(F_ZERO,F_ZERO);
        cubic_poly poly = cubic_poly(F_ZERO,F_ZERO,F_ZERO,F_ZERO);
        linear_poly l1,l2;
        for(int j = 0; j < v1.size()/(1<<(i+1)); j++){
            l1 = linear_poly(v1[2*j+1]-v1[2*j],v1[2*j]);
            l2 = linear_poly(v2[2*j+1]-v2[2*j],v2[2*j]);
            p = l1*l2;
            l1 = linear_poly(r1[2*j+1]-r1[2*j],r1[2*j]);
            l2 = linear_poly(r2[2*j+1]-r2[2*j],r2[2*j]);
            p_r = l1*l2;
            _p = linear_poly(v3[2*j+1]-v3[2*j],v3[2*j]);
            p.a = p.a + b*p_r.a;p.b = p.b + b*p_r.b - _p.a;p.c = p.c + b*p_r.c-_p.b;
            poly = poly + p* linear_poly(beta2[2*j+1]-beta2[2*j],beta2[2*j]);
        }
        vt.start();
        if(poly.eval(0) + poly.eval(1) != y){
            printf("Error in sumcheck functionality %d\n",i);
            exit(-1);
        }
        
        challenges[i] = F::_random();
        y = poly.eval(challenges[i]);
        vt.end();
        for(int j = 0; j < v1.size()/(1<<(i+1)); j++){
            v1[j] = challenges[i]*(v1[2*j+1]-v1[2*j]) + v1[2*j];
            v2[j] = challenges[i]*(v2[2*j+1]-v2[2*j]) + v2[2*j];
            v3[j] = challenges[i]*(v3[2*j+1]-v3[2*j]) + v3[2*j];
            r1[j] = challenges[i]*(r1[2*j+1]-r1[2*j]) + r1[2*j];
            r2[j] = challenges[i]*(r2[2*j+1]-r2[2*j]) + r2[2*j];
            beta2[j] = challenges[i]*(beta2[2*j+1]-beta2[2*j]) + beta2[2*j];
        }        
    }
    vector<F> ret;
    ret.push_back(v1[0]);ret.push_back(v2[0]);ret.push_back(v3[0]);
    ret.push_back(beta2[0]);ret.push_back(r1[0]);ret.push_back(r2[0]);
    ret.insert(ret.end(),challenges.begin(),challenges.end());
    pt_cp.end();

    vt.start();
    if((v1[0]*v2[0]-v3[0] + b*r1[0]*r2[0])*beta2[0] != y){
        printf("Error in final sumcheck step\n");
        exit(-1);
    }
    vt.end();
    
    return ret;

}

vector<F> quadratic_sumcheck_local(vector<F> final_v1, vector<F> final_v2, F y, int k, int _k, int N){
    
    pt_cp.start();
    
    fft(final_v1,(int)log2(final_v1.size()),true);
    fft(final_v2,(int)log2(final_v2.size()),true);
    
    F omega = getRootOfUnity(1+(int)log2(N));
    omega = omega.inv();
    F mul = F(1);
    for(int i = 0; i < final_v1.size(); i++){
        final_v1[i] = mul*final_v1[i];
        final_v2[i] = mul*final_v2[i];
        mul = mul*omega;
    }

    fft(final_v1,(int)log2(final_v1.size()),false);
    fft(final_v2,(int)log2(final_v2.size()),false);
    
    vector<F> v1(k),v2(k);    
    for(int i = 0; i < k; i++){
        v1[i] = final_v1[N*i/_k];
        v2[i] = final_v2[N*i/_k];
    }
    
    int rounds = (int)log2(k);
    vector<F> challenges(rounds);
    for(int i = 0; i < rounds; i++){
        quadratic_poly p = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
        linear_poly l1,l2;
        for(int j = 0; j < v1.size()/(1<<(i+1)); j++){
            l1 = linear_poly(v1[2*j+1]-v1[2*j],v1[2*j]);
            l2 = linear_poly(v2[2*j+1]-v2[2*j],v2[2*j]);
            p = p + l1*l2;
        }
        vt.start();
        
        if(p.eval(0) + p.eval(1) != y){
            printf("Error in sumcheck functionality %d\n",i);
            exit(-1);
        }
        
        challenges[i] = F::_random();
        y = p.eval(challenges[i]);
        vt.end();
        for(int j = 0; j < v1.size()/(1<<(i+1)); j++){
            v1[j] = challenges[i]*(v1[2*j+1]-v1[2*j]) + v1[2*j];
            v2[j] = challenges[i]*(v2[2*j+1]-v2[2*j]) + v2[2*j];
        }
                
    }
    vector<F> ret;
    ret.push_back(v1[0]);ret.push_back(v2[0]);
    ret.insert(ret.end(),challenges.begin(),challenges.end());
    pt_cp.end();
    
    return ret;

}

vector<F> batch_sumcheck_local(vector<F> final_v1, vector<F> final_v2, 
                                    vector<F> final_v3, vector<F> final_v4, 
                                    vector<F> h1, vector<F> h2,
                                    F b, F y, int k, int _k, int N){
    
    pt_cp.start();
    
    fft(final_v1,(int)log2(final_v1.size()),true);
    fft(final_v2,(int)log2(final_v2.size()),true);
    fft(final_v3,(int)log2(final_v3.size()),true);
    fft(final_v4,(int)log2(final_v4.size()),true);
    fft(h1,(int)log2(h1.size()),true);
    fft(h2,(int)log2(h2.size()),true);
    


    F omega = getRootOfUnity(1+(int)log2(N));
    omega = omega.inv();
    F mul = F(1);
    for(int i = 0; i < final_v1.size(); i++){
        final_v1[i] = mul*final_v1[i];
        final_v2[i] = mul*final_v2[i];
        final_v3[i] = mul*final_v3[i];
        final_v4[i] = mul*final_v4[i];
        h1[i] = mul*h1[i];
        h2[i] = mul*h2[i];
        mul = mul*omega;
    }

    fft(final_v1,(int)log2(final_v1.size()),false);
    fft(final_v2,(int)log2(final_v2.size()),false);
    fft(final_v3,(int)log2(final_v3.size()),false);
    fft(final_v4,(int)log2(final_v4.size()),false);
    fft(h1,(int)log2(h1.size()),false);
    fft(h2,(int)log2(h2.size()),false);
    /*
    for(int i = 0; i < N; i++){
        printf("(%lld,%lld)\n",final_v1[i].real,final_v1[i].img);    
    }
    printf("=======\n");
    
    for(int i = 0; i < N; i++){
        printf("(%lld,%lld)\n",final_v2[i].real,final_v2[i].img);    
    }
    printf("=======\n");

    for(int i = 0; i < N; i++){
        printf("(%lld,%lld)\n",final_v3[i].real,final_v3[i].img);    
    }
    printf("=======\n");
    for(int i = 0; i < N; i++){
        printf("(%lld,%lld)\n",final_v4[i].real,final_v4[i].img);    
    }
    printf("=======\n");
    for(int i = 0; i < N; i++){
        printf("(%lld,%lld)\n",h1[i].real,h1[i].img);    
    }
    printf("=======\n");

    for(int i = 0; i < N; i++){
        printf("(%lld,%lld)\n",h2[i].real,h2[i].img);    
    }
    printf("=======\n");

    printf(">> %d,%d\n",k,_k);
    */
    
    vector<F> v1(k),v2(k),v3(k),v4(k);
    vector<F> r1(k),r2(k);
    
    for(int i = 0; i < k; i++){
        v1[i] = final_v1[N*i/_k];
        v2[i] = final_v2[N*i/_k];
        v3[i] = final_v3[N*i/_k];
        v4[i] = final_v4[N*i/_k];
        r1[i] = h1[N*i/_k];
        r2[i] = h2[N*i/_k];
    }
    
    int rounds = (int)log2(k);
    vector<F> challenges(rounds);
    for(int i = 0; i < rounds; i++){
        quadratic_poly p = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
        quadratic_poly p_r = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
        linear_poly l1,l2;
    
        for(int j = 0; j < v1.size()/(1<<(i+1)); j++){

            l1 = linear_poly(v1[2*j+1]-v1[2*j],v1[2*j]);
            l2 = linear_poly(v2[2*j+1]-v2[2*j],v2[2*j]);
            p = p + l1*l2;
            l1 = linear_poly(v3[2*j+1]-v3[2*j],v3[2*j]);
            l2 = linear_poly(v4[2*j+1]-v4[2*j],v4[2*j]);
            p = p + l1*l2;
            
            l1 = linear_poly(r1[2*j+1]-r1[2*j],r1[2*j]);
            l2 = linear_poly(r2[2*j+1]-r2[2*j],r2[2*j]);
            p_r = p_r + l1*l2;
        }
        p.a = p.a + b*p_r.a;
        p.b = p.b + b*p_r.b;
        p.c = p.c + b*p_r.c;
        vt.start();
        
        if(p.eval(0) + p.eval(1) != y){
            printf("Error in sumcheck functionality %d\n",i);
            exit(-1);
        }
        
        challenges[i] = F::_random();
        y = p.eval(challenges[i]);
        vt.end();
        for(int j = 0; j < v1.size()/(1<<(i+1)); j++){
            v1[j] = challenges[i]*(v1[2*j+1]-v1[2*j]) + v1[2*j];
            v2[j] = challenges[i]*(v2[2*j+1]-v2[2*j]) + v2[2*j];
            v3[j] = challenges[i]*(v3[2*j+1]-v3[2*j]) + v3[2*j];
            v4[j] = challenges[i]*(v4[2*j+1]-v4[2*j]) + v4[2*j];
            r1[j] = challenges[i]*(r1[2*j+1]-r1[2*j]) + r1[2*j];
            r2[j] = challenges[i]*(r2[2*j+1]-r2[2*j]) + r2[2*j];
        }        
    }
    vector<F> ret;
    ret.push_back(v1[0]);ret.push_back(v2[0]);ret.push_back(v3[0]);
    ret.push_back(v4[0]);ret.push_back(r1[0]);ret.push_back(r2[0]);
    ret.insert(ret.end(),challenges.begin(),challenges.end());
    pt_cp.end();
    vt.start();
    if((v1[0]*v2[0]+v3[0]*v4[0] + b*r1[0]*r2[0]) != y){
        printf("Error in final sumcheck step\n");
        exit(-1);
    }
    vt.end();
    
    return ret;

}


vector<pair<F,vector<F>>> F_zero_check_rest(vector<F> &v1, vector<F> &v2, vector<F> &v3,vector<F> &h1, vector<F> &h2, 
                                            vector<F> &beta1, vector<F> &beta2, 
                                            F b, F y, int k, int _k, int N,
                                            uint32_t tail_round){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<u64> buff_u64(10*v1.size());
    vector<F> buff,ret;
    vector<F> local_fields = v1;
    local_fields.insert(local_fields.end(),v2.begin(),v2.end());
    local_fields.insert(local_fields.end(),v3.begin(),v3.end());
    local_fields.insert(local_fields.end(),h1.begin(),h1.end());
    local_fields.insert(local_fields.end(),h2.begin(),h2.end());
    vector<F> public_aux = beta1;
    public_aux.insert(public_aux.end(), beta2.begin(), beta2.end());
    public_aux.push_back(b);
    public_aux.push_back(y);
    public_aux.push_back(F(k));
    public_aux.push_back(F(_k));
    public_aux.push_back(F(N));
    const auto local_meta = prepare_cosumcheck_tail_send(
        pvia::Phase::COSUMCHECK_ZERO, tail_round, local_fields, public_aux);
    std::array<u64, pvia::META_WORDS> publish_meta{};
    com_rounds+=2;
    
    if(rank == 0){
        if (pvia::Runtime::instance().enabled())
            pvia::Runtime::instance().consume_pending();
        vector<vector<F>> final_v1(v1.size()),final_v2(v2.size()),final_v3(v3.size()),final_h1(h1.size()),final_h2(h2.size());
        for(int i = 0; i < final_v1.size(); i++){
            final_v1[i].resize(N);
            final_v2[i].resize(N);
            final_v3[i].resize(N);
            final_h1[i].resize(N);
            final_h2[i].resize(N);            
            final_v1[i][0] = v1[i];final_v2[i][0] = v2[i];final_v3[i][0] = v3[i];final_h1[i][0] = h1[i];final_h2[i][0] = h2[i];
        }
        vector<vector<u64>> recv_data(N);
        vector<MPI_Request> req(N);
        for(int i = 1; i < N; i++){
            recv_data[i].resize(10*v1.size());
            MPI_Irecv(recv_data[i].data(),recv_data[i].size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i]);
            //MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            
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
                    i, remote_meta, recv_data[i]);
            }
            field_vector_deserialize(recv_data[i],buff);
            for(int j = 0; j < v1.size(); j++){
                final_v1[j][i] = buff[j];
                final_v2[j][i] = buff[j + v1.size()];
                final_v3[j][i] = buff[j + 2*v1.size()];
                final_h1[j][i] = buff[j + 3*v1.size()];
                final_h2[j][i] = buff[j + 4*v1.size()];
            }
        }
        ret = zero_check_sumcheck_local(convert2vector(final_v1), convert2vector(final_v2), convert2vector(final_v3), convert2vector(final_h1), convert2vector(final_h2), beta1, beta2, b, y, k, _k, N);
        //for(int i = 1; i < N; i++){
        field_vector_serialize(ret,buff_u64);
        if (pvia::Runtime::instance().enabled()) {
            publish_meta = prepare_cosumcheck_tail_publication(
                pvia::Phase::COSUMCHECK_ZERO, tail_round, ret, public_aux);
        }
            //cm += 8*buff_u64.size()/1024.0;
            //MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        //}
    }else{
        buff = local_fields;
        field_vector_serialize(buff,buff_u64);
        cm += 8*buff_u64.size()/1024.0;
        send_bound_payload(local_meta, buff_u64, 0);
        MPI_Request req;
        MPI_Isend(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
        if (pvia::Runtime::instance().enabled())
            pvia::Runtime::instance().consume_pending();

        buff_u64.clear();buff_u64.resize(2*(6+(int)log2(k)));
    }
    myBcast(buff_u64,N);
    if (pvia::Runtime::instance().enabled()) {
        pvia::publish_rank0_aggregate_meta(publish_meta, buff_u64, rank);
        pvia::Runtime::instance().consume_pending();
    }
    if(rank != 0){
        field_vector_deserialize(buff_u64,ret);        
    }
    vector<F> r;
    for(int i = 6; i < ret.size(); i++) r.push_back(ret[i]); 
    return {make_pair(ret[0],r),make_pair(ret[1],r),make_pair(ret[2],r),make_pair(ret[3],r),make_pair(ret[4],r),make_pair(ret[5],r)};
}

vector<pair<F,vector<F>>> F_batch_sumcheck_rest(F v1, F v2, F v3, F v4, F h1, F h2, 
                                            F b, F y, int k, int _k, int N,
                                            uint32_t tail_round){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<u64> buff_u64(12);
    vector<F> buff,ret;
    const vector<F> local_fields = {v1,v2,v3,v4,h1,h2};
    const vector<F> public_aux = {b,y,F(k),F(_k),F(N)};
    const auto local_meta = prepare_cosumcheck_tail_send(
        pvia::Phase::COSUMCHECK_BATCH, tail_round, local_fields, public_aux);
    std::array<u64, pvia::META_WORDS> publish_meta{};
    com_rounds+=2;
    
    if(rank == 0){
        if (pvia::Runtime::instance().enabled())
            pvia::Runtime::instance().consume_pending();
        vector<F> final_v1(N),final_v2(N),final_v3(N),final_v4(N),final_h1(N),final_h2(N);
        final_v1[0] = v1;final_v2[0] = v2;final_v3[0] = v3;final_v4[0] = v4;final_h1[0] = h1;final_h2[0] = h2;
        vector<vector<u64>> recv_data(N);
        vector<MPI_Request> req(N);
        for(int i = 1; i < N; i++){
            recv_data[i].resize(12);
            MPI_Irecv(recv_data[i].data(),12,MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i]);
            //MPI_Recv(buff_u64.data(),12,MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
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
                    i, remote_meta, recv_data[i]);
            }
            field_vector_deserialize(recv_data[i],buff);
            final_v1[i] = buff[0];final_v2[i] = buff[1];final_v3[i] = buff[2];final_v4[i] = buff[3];final_h1[i] = buff[4];final_h2[i] = buff[5];

        }
        ret = batch_sumcheck_local(final_v1, final_v2, final_v3, final_v4, final_h1, final_h2, b, y, k, _k, N);
        field_vector_serialize(ret,buff_u64);
        if (pvia::Runtime::instance().enabled()) {
            publish_meta = prepare_cosumcheck_tail_publication(
                pvia::Phase::COSUMCHECK_BATCH, tail_round, ret, public_aux);
        }
            
        //for(int i = 1; i < N; i++){
        //    cm += 8*buff_u64.size()/1024.0;
        //    MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        //}
    }else{
        buff = local_fields;
        field_vector_serialize(buff,buff_u64);
        cm += 8*buff_u64.size()/1024.0;
        send_bound_payload(local_meta, buff_u64, 0);
        MPI_Request req;
        MPI_Isend(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
        if (pvia::Runtime::instance().enabled())
            pvia::Runtime::instance().consume_pending();

        buff_u64.clear();buff_u64.resize(2*(6+(int)log2(k)));
    }
    myBcast(buff_u64,N);
    if (pvia::Runtime::instance().enabled()) {
        pvia::publish_rank0_aggregate_meta(publish_meta, buff_u64, rank);
        pvia::Runtime::instance().consume_pending();
    }
    if(rank != 0){
        field_vector_deserialize(buff_u64,ret);        
    }
    vector<F> r;
    for(int i = 6; i < ret.size(); i++) r.push_back(ret[i]); 
    return {make_pair(ret[0],r),make_pair(ret[1],r),make_pair(ret[2],r),make_pair(ret[3],r),make_pair(ret[4],r),make_pair(ret[5],r)};
}


vector<pair<F,vector<F>>> F_quadratic_sumcheck_rest(F v1, F v2, F y, int k, int _k, int N,
                                            uint32_t tail_round){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<u64> buff_u64(4);
    vector<F> buff,ret;
    const vector<F> local_fields = {v1,v2};
    const vector<F> public_aux = {y,F(k),F(_k),F(N)};
    const auto local_meta = prepare_cosumcheck_tail_send(
        pvia::Phase::COSUMCHECK_QUADRATIC, tail_round,
        local_fields, public_aux);
    std::array<u64, pvia::META_WORDS> publish_meta{};
    com_rounds+=2;
    
    if(rank == 0){
        if (pvia::Runtime::instance().enabled())
            pvia::Runtime::instance().consume_pending();
        vector<F> final_v1(N),final_v2(N);
        final_v1[0] = v1;final_v2[0] = v2;
        vector<vector<u64>> recv_data(N);
        vector<MPI_Request> req(N);
        for(int i = 1; i < N; i++){
            recv_data[i].resize(4);
            MPI_Irecv(recv_data[i].data(),4,MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i]);
            //MPI_Recv(buff_u64.data(),4,MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        }
        for(int i = 1; i  < N; i++){
            std::array<u64, pvia::META_WORDS> remote_meta{};
            if (pvia::Runtime::instance().enabled()) {
                MPI_Recv(remote_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                         i, pvia::META_TAG, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            }
            MPI_Wait(&req[i],MPI_STATUS_IGNORE);
            if (pvia::Runtime::instance().enabled()) {
                pvia::Runtime::instance().observe_remote_meta(
                    i, remote_meta, recv_data[i]);
            }
            field_vector_deserialize(recv_data[i],buff);
            final_v1[i] = buff[0];final_v2[i] = buff[1];
        }
        ret = quadratic_sumcheck_local(final_v1, final_v2, y, k, _k, N);
        //for(int i = 1; i < N; i++){
        field_vector_serialize(ret,buff_u64);
        if (pvia::Runtime::instance().enabled()) {
            publish_meta = prepare_cosumcheck_tail_publication(
                pvia::Phase::COSUMCHECK_QUADRATIC, tail_round,
                ret, public_aux);
        }
            //cm += 8*buff_u64.size()/1024.0;
            //MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        //}
    }else{
        buff = local_fields;
        field_vector_serialize(buff,buff_u64);
        cm += 8*buff_u64.size()/1024.0;
        send_bound_payload(local_meta, buff_u64, 0);
        MPI_Request req;
        MPI_Isend(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
        if (pvia::Runtime::instance().enabled())
            pvia::Runtime::instance().consume_pending();

        buff_u64.clear();buff_u64.resize(2*(2+(int)log2(k)));
    }
    myBcast(buff_u64,N);
    if (pvia::Runtime::instance().enabled()) {
        pvia::publish_rank0_aggregate_meta(publish_meta, buff_u64, rank);
        pvia::Runtime::instance().consume_pending();
    }
    if(rank != 0){
        field_vector_deserialize(buff_u64,ret);                
    }
    vector<F> r;
    for(int i = 2; i < ret.size(); i++) r.push_back(ret[i]); 
    return {make_pair(ret[0],r),make_pair(ret[1],r)};
}


cubic_poly aggregate_cubic_poly(
    cubic_poly H, vector<F> &v, int k, int _k, int N,
    const char* release_name, pvia::Phase gate_phase, uint32_t gate_round){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    F a = F(0),b = F(0),c = F(0),d = F(0);
    pt_cp.start();
        
    vector<F> coef; coef.push_back(H.a);coef.push_back(H.b);coef.push_back(H.c),coef.push_back(H.d);
    vector<u64> coef_u;
    
    field_vector_serialize(coef,coef_u);
    pt_cp.end();

    // PVIA sidecar metadata is transmitted only when the development path is enabled.
    std::array<u64, pvia::META_WORDS> pvia_meta{};
    const bool pvia_on = pvia::Runtime::instance().enabled();
    if (pvia_on) {
        pvia_meta = pvia::Runtime::instance().make_pending_meta(coef_u, false);
        pvia::Runtime::instance().observe_local_payload(coef_u);
    }

    com_rounds+=2;
    std::array<u64, pvia::META_WORDS> pvia_aggregate_meta{};
    
    if(rank == 0){
        vector<F> _a(N),_b(N),_c(N),_d(N);
        _a[0] = coef[0];_b[0] = coef[1];_c[0] = coef[2],_d[0] = coef[3]; 
        vector<vector<u64>> recv_data(N);
        vector<MPI_Request> req(N);
        for(int i = 1; i < N; i++){
            recv_data[i].resize(8);
            MPI_Irecv(recv_data[i].data(),8,MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i]);
            //MPI_Recv(coef_u.data(),8,MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
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
            field_vector_deserialize(recv_data[i],coef);
            _a[i] = coef[0];_b[i] = coef[1];_c[i] = coef[2];_d[i] = coef[3];
        }
        pt_cp.start();
    
        vector<F> test_a;
        
        fft(_a,(int)log2(_a.size()),true);
        fft(_b,(int)log2(_a.size()),true);
        fft(_c,(int)log2(_a.size()),true);
        fft(_d,(int)log2(_a.size()),true);
        F omega = getRootOfUnity(1+(int)log2(N));
        omega = omega.inv();
        F mul = F(1);
        for(int i = 0; i < _a.size(); i++){
            _a[i] = mul*_a[i];
            _b[i] = mul*_b[i];
            _c[i] = mul*_c[i];
            _d[i] = mul*_d[i];
            mul = omega*mul;
        }
        //_a.resize(_k);
        fft(_a,(int)log2(_a.size()),false);
        //_b.resize(_k);
        fft(_b,(int)log2(_a.size()),false);
        //_c.resize(_k);
        fft(_c,(int)log2(_a.size()),false);
        //_d.resize(_k);
        fft(_d,(int)log2(_a.size()),false);
        
        /*
        for(int i = 0; i < _a.size(); i++){
            if(_a[i] + _b[i]+_c[i]+F(2)*_d[i] == 0){
                printf("OK %d\n",i);
            }
        }
        */
        
        for(int j = 0; j < v.size(); j++){
            
            a += v[j]*_a[N*j/_k];
            b += v[j]*_b[N*j/_k];
            c += v[j]*_c[N*j/_k];
            d += v[j]*_d[N*j/_k];
        }
        coef[0] = a;coef[1] = b;coef[2] = c;coef[3] = d;
        if (pvia_on) pvia_aggregate_meta = pvia::bind_rank0_aggregate(
            coef, "AGGREGATE_CUBIC", rank,
            pvia::make_aggregation_aux(v, N, k, _k),
            pvia::AuditRelationKernel::AGGREGATE_WEIGHTED);
        field_vector_serialize(coef,coef_u);
        pt_cp.end();
    
        //for(int i = 1; i < N; i++){
            //cm += 8*coef_u.size()/1024.0;
            //MPI_Send(coef_u.data(),8,MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        //}       
         
    }else{
        cm += 8*coef_u.size()/1024.0;
        if (pvia_on) {
            pvia::Runtime::instance().seal_transfer_meta(pvia_meta, coef_u);
            pvia::Runtime::instance().observe_outgoing_transfer(pvia_meta, coef_u);
            MPI_Send(pvia_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                     0, pvia::META_TAG, MPI_COMM_WORLD);
        }
        MPI_Request req;
        MPI_Isend(coef_u.data(),coef_u.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);

        //MPI_Send(coef_u.data(),8,MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        //MPI_Recv(coef_u.data(),8,MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        //field_vector_deserialize(coef_u,coef);
        //a = coef[0];b = coef[1];c = coef[2];d = coef[3]; 
    }
    enforce_pvia_prebroadcast_release_gate(
        release_name, gate_phase, gate_round);
    myBcast(coef_u,N);
    if (pvia_on) pvia::publish_rank0_aggregate_meta(
        pvia_aggregate_meta, coef_u, rank);
    field_vector_deserialize(coef_u,coef);
    a = coef[0];b = coef[1];c = coef[2];d = coef[3];
    if (pvia_on) pvia::Runtime::instance().consume_pending();
    return cubic_poly(a,b,c,d);
}




cubic_poly aggregate_cubic_poly(
    cubic_poly H, vector<F> &v, int k, int _k, int N,
    const char* release_name) {
    return aggregate_cubic_poly(
        H, v, k, _k, N, release_name,
        pvia::Phase::UNKNOWN, pvia::Runtime::instance().pending_round());
}
F distributed_eval(vector<F> &poly, vector<F> &beta1, vector<F> &beta2, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<u64> buff(2); 
    pt_cp.start();
    
    F y = F(0);
    for(int i = 0; i < poly.size(); i++){
        y += poly[i]*beta1[i];
    }
    pt_cp.end();
    com_rounds+=2;
        
    if(rank == 0){
        vector<F> Y(N);Y[0] = y; 
        vector<vector<u32>> recv_data(N);
        vector<MPI_Request> req(N);
        for(int i = 1; i < N; i++){
            //MPI_Recv(buff.data(),2,MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            recv_data[i].resize(2);
            MPI_Irecv(recv_data[i].data(),2,MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i]);

        }
        for(int i =  1; i < N; i++){
            MPI_Wait(&req[i],MPI_STATUS_IGNORE);
            Y[i].real = recv_data[i][0];
            Y[i].img = recv_data[i][1];
        }
        pt_cp.start();
    
        y = 0;
        for(int i = 0; i < beta2.size(); i++){
            y += Y[i]*beta2[i];
        }
        buff = {y.real,y.img};
        pt_cp.end();
    
    }else{
        buff = {y.real,y.img};
        cm += 8*buff.size()/1024.0;
        //MPI_Send(buff.data(),2,MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        MPI_Request req;
        MPI_Isend(buff.data(),buff.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
    }
    if(rank == 0) cm += (N-1)*8*buff.size()/1024.0;
    myBcast(buff, N);
    //MPI_Bcast(buff.data(),2,MPI_UINT64_T,0,MPI_COMM_WORLD);
    y.real = buff[0];
    y.img = buff[1];
    return y;
}

vector<F> batch_ip(vector<vector<F>> &arr, vector<vector<vector<F>>> &v, int N, int k, int _k,
                   uint32_t scalar_context){
    
    pt_cp.start();
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<F> Y(arr.size(),F(0));
    for(int i = 0; i < Y.size(); i++){
        for(int j = 0; j < arr[i].size(); j++){
            Y[i] += arr[i][j]*v[i][0][j];
        }
    }
    vector<u64> Y_int;
    pt_cp.end();

    const vector<F> scalar_public_aux = {
        F(N), F(k), F(_k), F(static_cast<long long>(arr.size()))};
    const auto scalar_meta = prepare_scalar_aggregation_send(
        scalar_context, Y, scalar_public_aux);
    std::array<u64, pvia::META_WORDS> scalar_publish_meta{};
    com_rounds+=2;
    
    if(rank == 0){
        if (pvia::Runtime::instance().enabled())
            pvia::Runtime::instance().consume_pending();
        vector<vector<F>> partial_Y(arr.size());
        for(int i = 0; i < partial_Y.size(); i++){
            partial_Y[i].resize(N);
            partial_Y[i][0] = Y[i];
        }
        Y_int.resize(Y.size()*2);
        vector<vector<u64>> recv_data(N);
        vector<MPI_Request> req(N);
        for(int i = 1; i < N; i++){
            recv_data[i].resize(Y.size()*2);
            MPI_Irecv(recv_data[i].data(),recv_data[i].size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i]);
        
            //MPI_Recv(recv_data[i].data(),recv_data[i].size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i]);
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
                    i, remote_meta, recv_data[i]);
            }
            field_vector_deserialize(recv_data[i],Y);
            for(int j = 0; j < Y.size(); j++) partial_Y[j][i] = Y[j];

        }

        pt_cp.start();
    
        Y.clear();Y.resize(arr.size(),F(0));
        for(int i = 0; i < partial_Y.size(); i++){
            fft(partial_Y[i],(int)log2(partial_Y[i].size()),true);
            F omega = getRootOfUnity(1+(int)log2(N)).inv();
            F mul = F(1);
            for(int j = 0; j < partial_Y[i].size(); j++){
                partial_Y[i][j] = mul*partial_Y[i][j];
                mul = mul*omega;
            }
            fft(partial_Y[i],(int)log2(partial_Y[i].size()),false);
            for(int j = 0; j < k; j++){
                Y[i] += v[i][1][j]*partial_Y[i][N*j/_k];
            }
        }
        field_vector_serialize(Y,Y_int);
        if (pvia::Runtime::instance().enabled()) {
            scalar_publish_meta = prepare_scalar_aggregation_publication(
                scalar_context, Y, scalar_public_aux);
        }
        pt_cp.end();
    
        
    }else{
        field_vector_serialize(Y,Y_int);
        cm += 8*Y_int.size()/1024.0;
        send_bound_payload(scalar_meta, Y_int, 0);
        //MPI_Send(Y_int.data(),Y_int.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        MPI_Request req;
        MPI_Isend(Y_int.data(),Y_int.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
        if (pvia::Runtime::instance().enabled())
            pvia::Runtime::instance().consume_pending();

    }
    if(rank == 0) cm += (N-1)*8*Y_int.size()/1024.0;
    myBcast(Y_int, N);
    if (pvia::Runtime::instance().enabled()) {
        pvia::publish_rank0_aggregate_meta(
            scalar_publish_meta, Y_int, rank);
        pvia::Runtime::instance().consume_pending();
    }
    //MPI_Bcast(Y_int.data(),Y_int.size(),MPI_UINT64_T,0,MPI_COMM_WORLD);
    if(rank != 0){
        field_vector_deserialize(Y_int,Y);
    }
    return Y;
}

vector<F> batch_distributed_eval_opt(vector<vector<F>> &poly, vector<F> r1, vector<F> r2, int N,
                                     uint32_t scalar_context){
    int rank;
    pt_cp.start();
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<u64> buff(poly.size()*2); 
    
    int max_size = 0;
    for(int i = 0; i < poly.size(); i++){
        if(poly[i].size() > max_size) max_size = poly[i].size();
    }
    vector<F> r,y(poly.size(),F(0)); 
    for(int i = 0; i < (int)log2(max_size); i++) r.push_back(r1[i]);

    vector<F> beta1; precompute_beta(r,beta1);

    for(int i = 0; i < poly.size(); i++){
        for(int j  = 0; j < poly[i].size(); j++) y[i] += poly[i][j]*beta1[j];
        
        for(int j = (int)log2(poly[i].size()); j < r.size(); j++) y[i] *= (F(1)-r[j]).inv();
    }
    pt_cp.end();

    vector<F> scalar_public_aux = r1;
    scalar_public_aux.insert(
        scalar_public_aux.end(), r2.begin(), r2.end());
    scalar_public_aux.push_back(F(N));
    const auto scalar_meta = prepare_scalar_aggregation_send(
        scalar_context, y, scalar_public_aux);
    std::array<u64, pvia::META_WORDS> scalar_publish_meta{};
    com_rounds+=2;
    
    if(rank == 0){
        if (pvia::Runtime::instance().enabled())
            pvia::Runtime::instance().consume_pending();
        
        pt_cp.start();
        vector<F> beta2;precompute_beta(r2,beta2);
        vector<F> Y(poly.size(),F(0));
        for(int i = 0; i < poly.size(); i++){
            Y[i] += beta2[0]*y[i];
        }
        pt_cp.end();
        vector<vector<u64>> recv_data(N);
        vector<MPI_Request> req(N);

        for(int i = 1; i < N; i++){
            recv_data[i].resize(2*poly.size());
            MPI_Irecv(recv_data[i].data(),2*poly.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i]);
            //MPI_Recv(buff.data(),2*poly.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            
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
                    i, remote_meta, recv_data[i]);
            }
            for(int j = 0; j < poly.size(); j++){
                F v; v.real = recv_data[i][2*j];v.img = recv_data[i][2*j+1];
                Y[j] += beta2[i]*v;
            }
        }

        field_vector_serialize(Y,buff);
        if (pvia::Runtime::instance().enabled()) {
            scalar_publish_meta = prepare_scalar_aggregation_publication(
                scalar_context, Y, scalar_public_aux);
        }
    }else{
        field_vector_serialize(y,buff);
        cm += 8*buff.size()/1024.0;
        send_bound_payload(scalar_meta, buff, 0);
        MPI_Request req;
        MPI_Isend(buff.data(),buff.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
        if (pvia::Runtime::instance().enabled())
            pvia::Runtime::instance().consume_pending();

    }
    if(rank == 0) cm += (N-1)*8*buff.size()/1024.0;
    myBcast(buff, N);
    if (pvia::Runtime::instance().enabled()) {
        pvia::publish_rank0_aggregate_meta(
            scalar_publish_meta, buff, rank);
        pvia::Runtime::instance().consume_pending();
    }
    //MPI_Bcast(buff.data(),2*poly.size(),MPI_UINT64_T,0,MPI_COMM_WORLD);
    field_vector_deserialize(buff,y);
    return y;
}



vector<F> batch_distributed_eval(vector<vector<F>> &poly, vector<F> &beta1, vector<F> &beta2, int N,
                                 uint32_t scalar_context){
    int rank;
    pt_cp.start();
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<u64> buff(poly.size()*2); 
    
    vector<F> y(poly.size(),F(0));
    for(int i = 0; i < poly.size(); i++){
        for(int j  = 0; j < poly[i].size(); j++){
            y[i] += poly[i][j]*beta1[j];
        }
    }
    pt_cp.end();

    vector<F> scalar_public_aux = beta1;
    scalar_public_aux.insert(
        scalar_public_aux.end(), beta2.begin(), beta2.end());
    scalar_public_aux.push_back(F(N));
    const auto scalar_meta = prepare_scalar_aggregation_send(
        scalar_context, y, scalar_public_aux);
    std::array<u64, pvia::META_WORDS> scalar_publish_meta{};
    com_rounds+=2;
    
    if(rank == 0){
        if (pvia::Runtime::instance().enabled())
            pvia::Runtime::instance().consume_pending();
        
        pt_cp.start();
        vector<F> Y(poly.size(),F(0));
        for(int i = 0; i < poly.size(); i++){
            Y[i] += beta2[0]*y[i];
        }
        pt_cp.end();

        vector<vector<u64>> recv_data(N);
        vector<MPI_Request> req(N);
        for(int i = 1; i  < N; i++){
            recv_data[i].resize(2*poly.size());
            MPI_Irecv(recv_data[i].data(),2*poly.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i]);
            //MPI_Recv(recv_data[i].data(),2*poly.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i]);
            
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
                    i, remote_meta, recv_data[i]);
            }
            for(int j = 0; j < poly.size(); j++){
                F v;
                v.real = recv_data[i][2*j];
                v.img = recv_data[i][2*j+1];
                Y[j] += beta2[i]*v;
            }
        }

        field_vector_serialize(Y,buff);
        if (pvia::Runtime::instance().enabled()) {
            scalar_publish_meta = prepare_scalar_aggregation_publication(
                scalar_context, Y, scalar_public_aux);
        }
    }else{
        field_vector_serialize(y,buff);
        cm += 8*buff.size()/1024.0;
        send_bound_payload(scalar_meta, buff, 0);
        MPI_Request req;
        MPI_Isend(buff.data(),buff.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
        if (pvia::Runtime::instance().enabled())
            pvia::Runtime::instance().consume_pending();

    }
    if(rank == 0) cm += (N-1)*8*buff.size()/1024.0;
    myBcast(buff, N);
    if (pvia::Runtime::instance().enabled()) {
        pvia::publish_rank0_aggregate_meta(
            scalar_publish_meta, buff, rank);
        pvia::Runtime::instance().consume_pending();
    }
    //MPI_Bcast(buff.data(),2*poly.size(),MPI_UINT64_T,0,MPI_COMM_WORLD);
    field_vector_deserialize(buff,y);
    return y;
}

void send_index(vector<vector<int>> &Data,vector<int> dim , int N){
    vector<int> buff;
    vector<int> dim_buff = dim;
    dim_buff.insert(dim_buff.end(),real_idx_dim.begin(),real_idx_dim.end());
    vector<MPI_Request> req1(N-1),req2(N-1);
    for(int i = 1; i < N; i++){
        MPI_Isend(dim_buff.data(),dim_buff.size(),MPI_INT,i,0,MPI_COMM_WORLD,&req1[i-1]);
        MPI_Isend(Data[i].data(),Data[i].size(),MPI_INT,i,1,MPI_COMM_WORLD,&req2[i-1]);
    }
    for(int i = 1; i < N; i++){
        MPI_Wait(&req1[i-1],MPI_STATUS_IGNORE);
        MPI_Wait(&req2[i-1],MPI_STATUS_IGNORE);
    }
}

void send_matrix_dims(vector<int> dim1, vector<int> dim2, vector<int> dim3, int idx, vector<MPI_Request> &req){
    vector<int> buff = {(int)dim1.size(),(int)dim2.size(),(int)dim3.size()};
    MPI_Isend(buff.data(),3,MPI_INT,idx,0,MPI_COMM_WORLD,&req[0]);
    vector<int> buff2 = dim1;buff2.insert(buff2.end(),dim2.begin(),dim2.end());
    buff2.insert(buff2.end(),dim3.begin(),dim3.end());
    MPI_Isend(buff2.data(),buff2.size(),MPI_INT,idx,0,MPI_COMM_WORLD,&req[1]);
}

void receive_matrix_dims(vector<int> &dim1, vector<int> &dim2, vector<int> &dim3){
    MPI_Request req1,req2;
    vector<int> buff(3);
    MPI_Irecv(buff.data(),3,MPI_INT,0,0,MPI_COMM_WORLD,&req1);
    MPI_Wait(&req1,MPI_STATUS_IGNORE);
    vector<int> sizes = buff;
    buff.resize(sizes[0]+sizes[1]+sizes[2]);
    MPI_Irecv(buff.data(),buff.size(),MPI_INT,0,1,MPI_COMM_WORLD,&req2);
    MPI_Wait(&req2,MPI_STATUS_IGNORE);
    dim1.resize(sizes[0]);dim2.resize(sizes[1]);dim3.resize(sizes[2]);
    int ctr = 0;
    for(int i = 0; i < sizes[0]; i++)dim1[i] = buff[ctr++];
    for(int i = 0; i < sizes[1]; i++)dim2[i] = buff[ctr++];
    for(int i = 0; i < sizes[2]; i++)dim3[i] = buff[ctr++];
}

void send_R1CS_matrixes(vector<vector<int>> &Data,vector<vector<int>> tA_dim,vector<vector<int>> tB_dim,vector<vector<int>> tC_dim, int N){
    vector<vector<MPI_Request>> req(N-1);
    vector<vector<int>> buff(N),buff2(N);
    for(int i = 0; i < N-1; i++) req[i].resize(3);
    for(int i = 1; i < N; i++){
        //send_matrix_dims(tA_dim[i],tB_dim[i],tC_dim[i],i,req[i-1]);

        buff[i] = {(int)tA_dim[i].size(),(int)tB_dim[i].size(),(int)tC_dim[i].size()};
        MPI_Isend(buff[i].data(),3,MPI_INT,i,0,MPI_COMM_WORLD,&req[i-1][0]);
        buff2[i] = tA_dim[i];buff2[i].insert(buff2[i].end(),tB_dim[i].begin(),tB_dim[i].end());
        buff2[i].insert(buff2[i].end(),tC_dim[i].begin(),tC_dim[i].end());
        MPI_Isend(buff2[i].data(),buff2[i].size(),MPI_INT,i,1,MPI_COMM_WORLD,&req[i-1][1]);
        MPI_Isend(Data[i].data(),Data[i].size(),MPI_INT,i,2,MPI_COMM_WORLD,&req[i-1][2]);
    }
    for(int i = 0; i < req.size(); i++){
        MPI_Wait(&req[i][0],MPI_STATUS_IGNORE);
        MPI_Wait(&req[i][1],MPI_STATUS_IGNORE);
        MPI_Wait(&req[i][2],MPI_STATUS_IGNORE);
    }
}

void parse_R1CS_matrixes(vector<int> &data, vector<int> &dimsA, vector<int> &dimsB, vector<int> &dimsC, int N, int M){
    int ctr = 0; 
    //pA.resize(2*M/N); pB.resize(2*M/N); pC.resize(2*M/N);
    for(int i = 0; i < dimsA.size(); i++){
        
        if(data[2*ctr] == -1){
            pA.push_back({});
            ctr++;
            continue;
        }else{
            vector<pair<int,int>> buff;
            for(int j = 0; j < dimsA[i]; j++){
                buff.push_back(make_pair(data[2*ctr],data[2*ctr+1]));
                ctr++;
            }        
            pA.push_back(buff);    
        
        } 
        //pA[i].resize(1);
        //pA[i][0].first = data[2*i];
        //pA[i][0].second = data[2*i+1];
    }
    for(int i = 0; i < dimsB.size(); i++){
        if(data[2*ctr] == -1){
            pB.push_back({});
            ctr++;
            continue;
        }else{
            vector<pair<int,int>> buff;
            for(int j = 0; j < dimsB[i]; j++){
                buff.push_back(make_pair(data[2*ctr],data[2*ctr+1]));
                ctr++;
            }        
            pB.push_back(buff);    
        } 

        /*
        if(data[2*ctr] == -1){
            continue;
        }
        pB[i].resize(1);
        pB[i][0].first = data[2*i + 4*M/N];
        pB[i][0].second = data[2*i + 1 + 4*M/N];
        */
    }
    for(int i = 0; i < dimsC.size(); i++){
          if(data[2*ctr] == -1){
            pC.push_back({});
            ctr++;
            continue;
        }else{
            vector<pair<int,int>> buff;
            for(int j = 0; j < dimsC[i]; j++){
                buff.push_back(make_pair(data[2*ctr],data[2*ctr+1]));
                ctr++;
            }        
            pC.push_back(buff);    
        } 
        /*
        if(data[2*i + 8*M/N] == -1){
            continue;
        }
        pC[i].resize(1);
        pC[i][0].first = data[2*i + 8*M/N];
        pC[i][0].second = data[2*i + 1 + 8*M/N];*/
        
    }
}

void receive_R1CS_matrixes(int N, int M){
    vector<int> dim1,dim2,dim3;
    
    receive_matrix_dims(dim1, dim2, dim3);
    int total_size = 0;
    for(int i = 0; i < dim1.size(); i++) total_size += dim1[i];
    for(int i = 0; i < dim2.size(); i++) total_size += dim2[i];
    for(int i = 0; i < dim3.size(); i++) total_size += dim3[i];
    vector<int> data(2*total_size);
    MPI_Request req;
    MPI_Irecv(data.data(),data.size(),MPI_INT,0,2,MPI_COMM_WORLD,&req);
    MPI_Wait(&req,MPI_STATUS_IGNORE);
    
    parse_R1CS_matrixes(data,dim1,dim2,dim3,N,M);
}

void parse_index(vector<sparse_eval_data> &index,vector<int> &dim, vector<int> &data){
    int ctr = 0;
    for(int i = 0; i < index.size(); i++){
        index[i].FINAL_FR1.resize(dim[4*i]);
        index[i].FINAL_FR2.resize(dim[4*i+1]);
        index[i].RD1.resize(dim[4*i+2]);
        index[i].WR1.resize(dim[4*i+2]);
        index[i].IDX1.resize(dim[4*i+2]);
        index[i].RD2.resize(dim[4*i+3]);
        index[i].WR2.resize(dim[4*i+3]);
        index[i].IDX2.resize(dim[4*i+3]);
        for(int j = 0; j < index[i].FINAL_FR1.size(); j++){
            index[i].FINAL_FR1[j] = data[ctr++];
        }
        for(int j = 0; j < index[i].FINAL_FR2.size(); j++){
            index[i].FINAL_FR2[j] = data[ctr++];
        }
        for(int j = 0; j < index[i].RD1.size(); j++){
            index[i].RD1[j] = data[ctr++];
            index[i].RD2[j] = data[ctr++];
            index[i].WR1[j] = data[ctr++];
            index[i].WR2[j] = data[ctr++];
            index[i].IDX1[j] = data[ctr++];
            index[i].IDX2[j] = data[ctr++];
        }
    }

}

void receive_index(vector<sparse_eval_data> &index,vector<int> &dim){
    
    vector<int> buff(15);
    dim.clear();dim.resize(12);
    MPI_Request req1,req2;
    MPI_Irecv(buff.data(),buff.size(),MPI_INT,0,0,MPI_COMM_WORLD,&req1);
    MPI_Wait(&req1,MPI_STATUS_IGNORE);
    for(int i = 0; i < 12; i++){
        dim[i] =  buff[i];
    }
    for(int i = 12; i < 15; i++){
        real_idx_dim.push_back(buff[i]);
    }
    int size = 0;
    for(int i = 0; i < dim.size()/4; i++){
        size += dim[4*i];
        size += dim[4*i+1];
        size += 3*dim[4*i+2];
        size += 3*dim[4*i+3];
    }  
    vector<int> data(size);
    MPI_Irecv(data.data(),data.size(),MPI_INT,0,1,MPI_COMM_WORLD,&req2);
    MPI_Wait(&req2,MPI_STATUS_IGNORE);
    parse_index(index,dim, data);
}

void distribute_index(int N, int M,vector<sparse_eval_data> &index, int type){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    index.resize(3);
    vector<int> dims;
    vector<int> buff(2);
        
    if(rank == 0){
        generate_R1CS_matrixes(M,type);
        buff[0] = logm;
        buff[1]= logn;
    }
    
    MPI_Bcast(buff.data(),2,MPI_INT,0,MPI_COMM_WORLD);
    
    if(rank == 0){
        vector<sparse_eval_data> data;
        vector<vector<int>> parsed_data(N);
        prepare_R1CS_data(A, B, C, logm, logn, data);
        for(int i = 0; i < data.size(); i++){
            dims.push_back(data[i].FINAL_FR1.size()/N);
            dims.push_back(data[i].FINAL_FR2.size()/N);
            dims.push_back(data[i].RD1.size()/N);
            dims.push_back(data[i].RD2.size()/N);
        }
        
        for(int k = 0; k < N; k++){
            for(int i = 0; i < data.size(); i++){
                for(int j = 0; j < data[i].FINAL_FR1.size()/N; j++){
                    parsed_data[k].push_back(data[i].FINAL_FR1[k*data[i].FINAL_FR1.size()/N+ j]);
                }
                for(int j = 0; j < data[i].FINAL_FR2.size()/N; j++){
                    parsed_data[k].push_back(data[i].FINAL_FR2[k*data[i].FINAL_FR2.size()/N+j]);
                }
                for(int j = 0; j < data[i].RD1.size()/N; j++){
                    parsed_data[k].push_back(data[i].RD1[k*data[i].RD1.size()/N + j]);
                    parsed_data[k].push_back(data[i].RD2[k*data[i].RD1.size()/N +j]);            
                    parsed_data[k].push_back(data[i].WR1[k*data[i].RD1.size()/N +j]);
                    parsed_data[k].push_back(data[i].WR2[k*data[i].RD1.size()/N +j]);            
                    parsed_data[k].push_back(data[i].IDX1[k*data[i].RD1.size()/N +j]);
                    parsed_data[k].push_back(data[i].IDX2[k*data[i].RD1.size()/N +j]);     
                }
            }    
        }

        //for(int i = 0; i < parsed_data[0].size(); i++){
        //    printf("%d\n",parsed_data[0][i]);
        //}
        send_index(parsed_data,dims , N);
        parse_index(index,dims,parsed_data[0]);
        vector<vector<int>> parsed_R1CS_matrixes(N);
        vector<vector<int>> tA_dim(N),tB_dim(N),tC_dim(N);
        for(int i = 0; i < N; i++){
            //parsed_R1CS_matrixes[i].resize(12*M/N,0);
            for(int j = 0; j < tA.size()/N; j++){
                if(tA[i*tA.size()/N + j].size()){
                    for(int k = 0; k < tA[i*tA.size()/N + j].size(); k++){
                        parsed_R1CS_matrixes[i].push_back(tA[i*tA.size()/N + j][k].first);
                        parsed_R1CS_matrixes[i].push_back(tA[i*tA.size()/N + j][k].second);
                    }
                    tA_dim[i].push_back(tA[i*tA.size()/N + j].size());
                }else{
                    parsed_R1CS_matrixes[i].push_back(-1);
                    parsed_R1CS_matrixes[i].push_back(-1);
                    tA_dim[i].push_back(1);
                }
            }
            for(int j = 0;  j < tB.size()/N; j++){
                if(tB[i*tB.size()/N + j].size()){
                    for(int k = 0; k < tB[i*tB.size()/N + j].size(); k++){
                        parsed_R1CS_matrixes[i].push_back(tB[i*tB.size()/N + j][k].first);
                        parsed_R1CS_matrixes[i].push_back(tB[i*tB.size()/N + j][k].second);
                    }
                    tB_dim[i].push_back(tB[i*tB.size()/N + j].size());

                    //parsed_R1CS_matrixes[i][2*j + 4*M/N] = tB[i*2*M/N + j][0].first;
                    //parsed_R1CS_matrixes[i][2*j+1 + 4*M/N] = tB[i*2*M/N + j][0].second;
                }else{
                    parsed_R1CS_matrixes[i].push_back(-1);
                    parsed_R1CS_matrixes[i].push_back(-1);
                    tB_dim[i].push_back(1);
                }
            }
            for(int j = 0; j < tC.size()/N; j++){
                if(tC[i*tC.size()/N + j].size()){
                    for(int k = 0; k < tC[i*tC.size()/N + j].size(); k++){
                        parsed_R1CS_matrixes[i].push_back(tC[i*tC.size()/N + j][k].first);
                        parsed_R1CS_matrixes[i].push_back(tC[i*tC.size()/N + j][k].second);
                    }
                    tC_dim[i].push_back(tC[i*tC.size()/N + j].size());
                
                    //parsed_R1CS_matrixes[i][2*j + 8*M/N] = tC[i*2*M/N + j][0].first;
                    //parsed_R1CS_matrixes[i][2*j+1 + 8*M/N] = tC[i*2*M/N + j][0].second;
                }else{
                    parsed_R1CS_matrixes[i].push_back(-1);
                    parsed_R1CS_matrixes[i].push_back(-1);
                    tC_dim[i].push_back(1);
                }
            }
        }
        send_R1CS_matrixes(parsed_R1CS_matrixes,tA_dim,tB_dim,tC_dim,N);        
        parse_R1CS_matrixes(parsed_R1CS_matrixes[0],tA_dim[0],tB_dim[0],tC_dim[0],N,M);
    }else{
        logm = buff[0];
        logn = buff[1];
        receive_index(index,dims);
        receive_R1CS_matrixes(N,M);
        
    }
}


void compute_secret_shares(vector<F> &v, vector<vector<F>> &v_shares, int N, int k, int _k, bool privacy_preserving){
    v_shares.resize(N);
    F y = F(0);
    int counter = 0;
    for(int i = 0; i < N; i++){
        v_shares[i].resize(v.size()/k);
    }
    
    for(int i = 0; i < v.size()/k; i++){
        vector<F> buff(_k,F(0));
        for(int j = 0; j < k; j++){
            buff[j] = v[counter++];
        }
        for(int  j = k; j < _k; j++){
            if(privacy_preserving) buff[j] = random();
        }

        fft(buff,(int)log2(buff.size()),true);
        buff.resize(2*N,F(0));
        fft(buff,(int)log2(buff.size()),false);
        for(int  j = 0; j < N; j++){
            v_shares[j][i] = buff[2*j + 1];
        }
    }
}

#include "Fiat_Shamir.h"
#include "Distributed_Sumcheck.h"

void secret_share_coefficients(vector<F> &w, int M, int N, int _k, int k){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<u64> buff_u64;
    vector<F> buff;
    

    if(rank == 0){
        vector<F> poly = generate_randomness(M);
        vector<vector<F>> poly_shares;
        compute_secret_shares(poly,poly_shares,N,k,_k,true);
        
        w = poly_shares[0];
        
        for(int i = 1; i < N; i++){
            field_vector_serialize(poly_shares[i],buff_u64);
            MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        }
    }else{
        buff_u64.resize(2*(M)/k);
        MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        field_vector_deserialize(buff_u64,w);           
    }
    if (pvia::Runtime::instance().enabled()) {
        pvia::Runtime::instance().import_state(
            "pcs_secret_shared_coefficients", pvia::Phase::PCS, w);
    }
}


void distribute_proving_data(vector<F> &vL, vector<F> &vR, vector<F> &vO, vector<F> &w, int N, int M, int _k, int k, int cir_type){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<F> buff;

    auto& rt = pvia::Runtime::instance();
    pvia::CheckpointId bootstrap_checkpoint = 0;
    if (rt.enabled()) {
        // A session-scoped private-epoch bootstrap boundary.  It contains no
        // witness material; the receive record created below is placed in the
        // next generation of INIT/0 and becomes the predecessor of validity.
        rt.seal_checkpoint_instance(pvia::Phase::INIT, 0);
        bootstrap_checkpoint = rt.checkpoint_id(pvia::Phase::INIT, 0);
        if (bootstrap_checkpoint == 0) {
            if (rank == 0)
                printf("[PVIA][input] bootstrap checkpoint unavailable\n");
            std::exit(15);
        }
    }

    pvia::AuthenticatedMpcExchange exchange(rank, N, MPI_COMM_WORLD);
    const bool use_bound_transport =
        rt.enabled() && bootstrap_checkpoint != 0 &&
        exchange.production_authenticated_ready();
    pvia::Digest distribution_binding{};

    const size_t local_l_count = static_cast<size_t>((1 << logm) / k);
    const size_t local_w_count = static_cast<size_t>((1 << logn) / k);
    const size_t fields_per_receiver = 3 * local_l_count + local_w_count;
    const size_t words_per_receiver = 2 * fields_per_receiver;

    if (use_bound_transport) {
        vector<u64> dealer_payloads;
        if(rank == 0){
            vector<F> L,R,O,W;
            vector<vector<F>> L_shares,R_shares,O_shares,W_shares;
            prepare_witness_data(M,W,L,R,O,cir_type);
            compute_secret_shares(W,W_shares,N,k,_k,true);
            compute_secret_shares(L,L_shares,N,k,_k,true);
            compute_secret_shares(R,R_shares,N,k,_k,true);
            compute_secret_shares(O,O_shares,N,k,_k,true);

            dealer_payloads.reserve(static_cast<size_t>(N) * words_per_receiver);
            for(int i = 0; i < N; i++){
                vector<F> packed = L_shares[i];
                packed.insert(packed.end(),R_shares[i].begin(),R_shares[i].end());
                packed.insert(packed.end(),O_shares[i].begin(),O_shares[i].end());
                packed.insert(packed.end(),W_shares[i].begin(),W_shares[i].end());
                vector<u64> serialized;
                field_vector_serialize(packed,serialized);
                if (serialized.size() != words_per_receiver) {
                    printf("[PVIA][input] serialized share shape mismatch\n");
                    std::exit(15);
                }
                dealer_payloads.insert(
                    dealer_payloads.end(), serialized.begin(), serialized.end());
            }
        }

        pvia::AuthenticatedMpcMessageContext context;
        context.protocol_domain =
            pvia::AUTHENTICATED_MPC_BASELINE_INPUT_DOMAIN;
        context.sid = rt.session_id();
        context.checkpoint = bootstrap_checkpoint;
        context.round = 0;
        context.sequence = 1;
        context.message_kind = 0x494e505554534852ULL; // INPUTSHR
        vector<u64> received_words;
        if (!exchange.ScatterWords(
                context, 0, dealer_payloads, words_per_receiver,
                &received_words, &distribution_binding) ||
            received_words.size() != words_per_receiver ||
            distribution_binding == pvia::Digest{}) {
            if (rank == 0)
                printf("[PVIA][input] common transport unavailable\n");
            std::exit(15);
        }
        field_vector_deserialize(received_words,buff);
        if (buff.size() != fields_per_receiver) {
            if (rank == 0)
                printf("[PVIA][input] received share shape mismatch\n");
            std::exit(15);
        }
        vL.assign(buff.begin(), buff.begin() + static_cast<std::ptrdiff_t>(local_l_count));
        vR.assign(
            buff.begin() + static_cast<std::ptrdiff_t>(local_l_count),
            buff.begin() + static_cast<std::ptrdiff_t>(2 * local_l_count));
        vO.assign(
            buff.begin() + static_cast<std::ptrdiff_t>(2 * local_l_count),
            buff.begin() + static_cast<std::ptrdiff_t>(3 * local_l_count));
        w.assign(
            buff.begin() + static_cast<std::ptrdiff_t>(3 * local_l_count),
            buff.end());
    } else if(rank == 0){
        vector<F> L,R,O,W;
        vector<vector<F>> L_shares,R_shares,O_shares,W_shares;
        prepare_witness_data(M,W,L,R,O,cir_type);

        compute_secret_shares(W,W_shares,N,k,_k,true);
        compute_secret_shares(L,L_shares,N,k,_k,true);
        compute_secret_shares(R,R_shares,N,k,_k,true);
        compute_secret_shares(O,O_shares,N,k,_k,true);

        vL = L_shares[0];
        vR = R_shares[0];
        vO = O_shares[0];
        w = W_shares[0];
        vector<MPI_Request> req(N-1);
        vector<vector<u64>> buff_u64(N);
        for(int i = 1; i < N; i++){
            L_shares[i].insert(L_shares[i].end(),R_shares[i].begin(),R_shares[i].end());
            L_shares[i].insert(L_shares[i].end(),O_shares[i].begin(),O_shares[i].end());
            L_shares[i].insert(L_shares[i].end(),W_shares[i].begin(),W_shares[i].end());
            field_vector_serialize(L_shares[i],buff_u64[i]);
            MPI_Isend(buff_u64[i].data(),buff_u64[i].size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i-1]);
            L_shares[i].clear();
        }
        for(int i = 0; i < N-1; i++){
            MPI_Wait(&req[i],MPI_STATUS_IGNORE);
        }
    }else{
        vector<u64> buff_u64;
        MPI_Request req;
        buff_u64.resize(words_per_receiver);
        MPI_Irecv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
        field_vector_deserialize(buff_u64,buff);
        vL.resize(local_l_count);vR.resize(local_l_count);vO.resize(local_l_count);
        w.resize(local_w_count);

        for(size_t i = 0; i < vL.size(); i++) vL[i] = buff[i];
        for(size_t i = 0; i < vR.size(); i++) vR[i] = buff[i + vL.size()];
        for(size_t i = 0; i < vO.size(); i++) vO[i] = buff[i + 2*vL.size()];
        for(size_t i = 0; i < w.size(); i++) w[i] = buff[i + 3*vL.size()];
    }

    // The native prover sends exactly this input-share payload regardless of
    // whether PVIA authenticates the transport. Record it in both scenarios so
    // communication comparisons use an identical end-to-end boundary.
    const uint64_t baseline_input_bytes =
        static_cast<uint64_t>(words_per_receiver * sizeof(u64));
    if (rank == 0) {
        pvia::experiment_add_baseline_input_payload_traffic(
            baseline_input_bytes * static_cast<uint64_t>(N - 1), 0);
    } else {
        pvia::experiment_add_baseline_input_payload_traffic(
            0, baseline_input_bytes);
    }

    if (rt.enabled()) {
        vector<F> received_state = vL;
        received_state.insert(received_state.end(), vR.begin(), vR.end());
        received_state.insert(received_state.end(), vO.begin(), vO.end());
        received_state.insert(received_state.end(), w.begin(), w.end());
        const pvia::RecordId receive_record = rt.register_vector_operation(
            pvia::Phase::INIT, 0, pvia::Obligation::RECEIVE,
            received_state, {});
        if (receive_record == 0) {
            if (rank == 0)
                printf("[PVIA][input] receive binding unavailable\n");
            std::exit(15);
        }
        vector<u64> aux = {
            bootstrap_checkpoint,
            use_bound_transport ? 1ULL : 0ULL,
            static_cast<u64>(N),
            static_cast<u64>(k),
            static_cast<u64>(_k),
            static_cast<u64>(fields_per_receiver)};
        if (distribution_binding != pvia::Digest{}) {
            for (size_t i = 0; i < 4; ++i) {
                u64 word = 0;
                std::memcpy(
                    &word, distribution_binding.bytes.data() + 8 * i, 8);
                aux.push_back(word);
            }
        }
        rt.bind_public_word_aux(
            receive_record, pvia::AuditPublicAuxKind::GENERIC_WORDS, aux);
        rt.activate_vector(receive_record, received_state);
        rt.consume_pending();
        rt.seal_checkpoint_instance(pvia::Phase::INIT, 0);
    }
} 

void setup_randomness(vector<F> &R, int N, int _k, int k, int size, uint64_t joint_domain){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id

    if (pvia::Runtime::instance().enabled()) {
        if (joint_domain == 0) {
            if (rank == 0)
                printf("[PVIA][preprocessing] missing joint randomness domain\n");
            std::exit(15);
        }
        pvia::JointPackedPreprocessingResult joint_result;
        if (!pvia::generate_joint_packed_random_share(
                static_cast<size_t>(size), N, k, _k, joint_domain,
                &R, &joint_result, MPI_COMM_WORLD) ||
            !joint_result.ok) {
            if (rank == 0)
                printf("[PVIA][preprocessing] joint randomness unavailable\n");
            std::exit(15);
        }
        return;
    }

    int logk = (int)log2(k);
    if(rank == 0){
        vector<F> random_values(k*(size));
        vector<vector<F>> R_shares;
        for(int i = 0; i < random_values.size(); i++) random_values[i] = random();
        compute_secret_shares(random_values,R_shares,N,k,_k,true);
        R = R_shares[0];
        vector<MPI_Request> req(N-1); 
        vector<vector<u64>> buff_u64(N);
        for(int i = 1; i < N; i++){
   
            field_vector_serialize(R_shares[i],buff_u64[i]);
            F s = F(0);
            MPI_Isend(buff_u64[i].data(),buff_u64[i].size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i-1]);
            R_shares[i].clear();
            //MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        }
        for(int i = 0; i < N-1; i++){
            MPI_Wait(&req[i],MPI_STATUS_IGNORE);
        }
    }else{
        vector<u64> buff_u64;
   
        buff_u64.resize(2*(size));
        MPI_Request req;
        //MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        MPI_Irecv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
        field_vector_deserialize(buff_u64,R);         
          
    }
}

void setup_randomness_pair(
    vector<F> &R, vector<F> &R2, int N, int _k, int k, int size,
    uint64_t joint_domain, uint64_t joint_domain2) {
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);

    if (!pvia::Runtime::instance().enabled()) {
        setup_randomness(R, N, _k, k, size, joint_domain);
        setup_randomness(R2, N, _k, k, size, joint_domain2);
        return;
    }
    if (size <= 0 || joint_domain == 0 || joint_domain2 == 0 ||
        joint_domain == joint_domain2) {
        if (rank == 0)
            printf("[PVIA][preprocessing] invalid paired randomness request\n");
        std::exit(15);
    }

    const size_t count = static_cast<size_t>(size);
    if (count > std::numeric_limits<size_t>::max() / 2) {
        if (rank == 0)
            printf("[PVIA][preprocessing] paired randomness size overflow\n");
        std::exit(15);
    }
    std::vector<F> combined;
    pvia::JointPackedPreprocessingResult joint_result;
    // R and R2 are two disjoint slices of one vector of independently sampled
    // random field elements.  This preserves their independence while sharing
    // a single preprocessing collective.
    if (!pvia::generate_joint_packed_random_share(
            2 * count, N, k, _k,
            0x5056505242504149ULL, // PVP RBPAI: paired randomness batch
            &combined, &joint_result, MPI_COMM_WORLD) ||
        !joint_result.ok || combined.size() != 2 * count) {
        if (rank == 0)
            printf("[PVIA][preprocessing] paired randomness unavailable\n");
        std::exit(15);
    }
    R.assign(
        combined.begin(),
        combined.begin() + static_cast<std::ptrdiff_t>(count));
    R2.assign(
        combined.begin() + static_cast<std::ptrdiff_t>(count),
        combined.end());
}
