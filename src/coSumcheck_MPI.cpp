#pragma once
#include "coSumcheck_MPI.h"
#include "MPI_utils.hpp"
#include "Fiat_Shamir.h"
#include "timer.hpp"
#include "accountability/PVIA.hpp"
#include <cstdlib>
extern int queries;
extern timer pt,pt_cp,vt;
extern timer_cpu pt_cpu;
extern int cosumcheck_offset;

namespace {

F pvia_linear_pair_value(const vector<F>& values, size_t pair, const F& x) {
    const size_t offset = 2 * pair;
    return values[offset] + x * (values[offset + 1] - values[offset]);
}

bool pvia_verify_zero_round_polynomial(
    const cubic_poly& H, int iter, const F& b,
    const vector<F>& v1, const vector<F>& v2, const vector<F>& v3,
    const vector<F>& beta1, const vector<F>& r1, const vector<F>& r2) {
    if (iter < 0) return false;
    const size_t count = v1.size() / (1ULL << (iter + 1));
    if (2 * count > v2.size() || 2 * count > v3.size() ||
        2 * count > beta1.size() || 2 * count > r1.size() ||
        2 * count > r2.size()) return false;
    const F points[] = {F(0), F(1), F(2), F(3)};
    for (const F& x : points) {
        F expected(0);
        for (size_t j = 0; j < count; ++j) {
            const F left = pvia_linear_pair_value(v1, j, x);
            const F right = pvia_linear_pair_value(v2, j, x);
            const F output = pvia_linear_pair_value(v3, j, x);
            const F mask_left = pvia_linear_pair_value(r1, j, x);
            const F mask_right = pvia_linear_pair_value(r2, j, x);
            const F beta = pvia_linear_pair_value(beta1, j, x);
            expected += (left * right + b * mask_left * mask_right - output) * beta;
        }
        if (H.eval(x) != expected) return false;
    }
    return true;
}

bool pvia_verify_quadratic_round_polynomial(
    const quadratic_poly& H, int iter,
    const vector<F>& v1, const vector<F>& v2) {
    if (iter < 0) return false;
    const size_t count = v1.size() / (1ULL << (iter + 1));
    if (2 * count > v2.size()) return false;
    const F points[] = {F(0), F(1), F(2)};
    for (const F& x : points) {
        F expected(0);
        for (size_t j = 0; j < count; ++j)
            expected += pvia_linear_pair_value(v1, j, x) *
                        pvia_linear_pair_value(v2, j, x);
        if (H.eval(x) != expected) return false;
    }
    return true;
}

bool pvia_verify_batch_round_polynomial(
    const quadratic_poly& H, int iter, const F& b,
    const vector<F>& v1, const vector<F>& v2,
    const vector<F>& v3, const vector<F>& v4,
    const vector<F>& r1, const vector<F>& r2) {
    if (iter < 0) return false;
    const size_t count = v1.size() / (1ULL << (iter + 1));
    if (2 * count > v2.size() || 2 * count > v3.size() ||
        2 * count > v4.size() || 2 * count > r1.size() ||
        2 * count > r2.size()) return false;
    const F points[] = {F(0), F(1), F(2)};
    for (const F& x : points) {
        F expected(0);
        for (size_t j = 0; j < count; ++j) {
            expected += pvia_linear_pair_value(v1, j, x) *
                        pvia_linear_pair_value(v2, j, x);
            expected += pvia_linear_pair_value(v3, j, x) *
                        pvia_linear_pair_value(v4, j, x);
            expected += b * pvia_linear_pair_value(r1, j, x) *
                        pvia_linear_pair_value(r2, j, x);
        }
        if (H.eval(x) != expected) return false;
    }
    return true;
}

} // namespace

cubic_poly _zero_check_sumcheck_phase1(int iter, F b,vector<F> &v1,vector<F> &v2, vector<F> &v3, vector<F> &beta1, vector<F> &r1, vector<F> &r2){
    quadratic_poly p = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
    quadratic_poly p_r = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
    //quadratic_poly _p = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
    linear_poly _p = linear_poly(F_ZERO,F_ZERO);
    cubic_poly res = cubic_poly(F_ZERO,F_ZERO,F_ZERO,F_ZERO);
    linear_poly l1,l2;
    for(int i = 0; i < v1.size()/(1<<(iter+1)); i++){
        l1 = linear_poly(v1[2*i+1]-v1[2*i],v1[2*i]);
        l2 = linear_poly(v2[2*i+1]-v2[2*i],v2[2*i]);
        p = l1*l2;
        l1 = linear_poly(r1[2*i+1]-r1[2*i],r1[2*i]);
        l2 = linear_poly(r2[2*i+1]-r2[2*i],r2[2*i]);
        p_r = l1*l2;
        _p = linear_poly(v3[2*i+1]-v3[2*i],v3[2*i]);
        p.a = p.a + b*p_r.a ;
        p.b = p.b + b*p_r.b - _p.a;
        p.c = p.c + b*p_r.c - _p.b; 
        res = res + p*linear_poly(beta1[2*i+1]-beta1[2*i],beta1[2*i]);
    }
    return res;
}

void _zero_check_sumcheck_phase2(int iter, F r,vector<F> &v1,vector<F> &v2, vector<F> &v3, vector<F> &beta1, vector<F> &r1, vector<F> &r2){
    for(int i = 0; i < v1.size()/(1<<(iter+1)); i++){
        v1[i] = v1[2*i] + r*(v1[2*i+1]-v1[2*i]);
        v2[i] = v2[2*i] + r*(v2[2*i+1]-v2[2*i]);
        v3[i] = v3[2*i] + r*(v3[2*i+1]-v3[2*i]);
        r1[i] = r1[2*i] + r*(r1[2*i+1]-r1[2*i]);
        r2[i] = r2[2*i] + r*(r2[2*i+1]-r2[2*i]);
        beta1[i] = beta1[2*i] + r*(beta1[2*i+1]-beta1[2*i]);
    }
}

vector<std::pair<F,vector<F>>> _zero_check_sumcheck(F y, vector<F> &v1, 
                                vector<F> &v2, vector<F> &v3, vector<F> &R1, vector<F> &R2, 
                                vector<F> r, int N, int _k, int k, double &ps){  
    int M = v1.size();
    pt_cp.start();
    vector<F> h1(M,F(0)),h2(M,F(0));
    int j;
    
    for(j = 0; j < R1.size()-2; j++){
        
        h1[1<<j] = R1[j];
        h2[1<<j] = R2[j];
    }
    h1[(1<<j)-2] = R1[j];
    h2[(1<<j)-2] = R2[j];
    h1[(1<<j)-1] = R1[j+1];
    h2[(1<<j)-1] = R2[j+1];
    
    
    vector<F> _r1,_r2,beta1,beta2;
    

    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    
    for(int i = 0; i < (int)log2(k); i++) _r2.push_back(r[i]);
    for(int i = (int)log2(k); i < r.size(); i++) _r1.push_back(r[i]);

    
    precompute_beta(_r1,beta1);precompute_beta(_r2,beta2);
    
    pt_cp.end();


    F y_r = F_ip_prod(h1,h2,beta1,beta2,k,_k,N,
        PVIA_SCALAR_CTX_COSUMCHECK_ZERO_AUX);
    
    if(rank == 0)vt.start();
    
    
    F b = hash_to_field({y_r});
    
    y += b*y_r;
    
    if(rank == 0)vt.end();
    
    
    int rounds = (int)log2(M)-cosumcheck_offset;
    vector<F> final_v1,final_v2,final_v3,final_h1,final_h2;
    vector<F> challenges;

    if(rounds>0){

        challenges.resize(rounds);        
        for(int i = 0; i < rounds; i++){
            cubic_poly H;
            pt_cp.start();
            H = _zero_check_sumcheck_phase1(i, b,v1,v2, v3, beta1, h1, h2);
            pt_cp.end();
            if (pvia::Runtime::instance().enabled() &&
                !pvia_verify_zero_round_polynomial(
                    H, i, b, v1, v2, v3, beta1, h1, h2)) {
                pvia::Runtime::instance().handle_global_failure(
                    "cosumcheck_zero_local_arithmetic",
                    pvia::Phase::COSUMCHECK_ZERO, i);
                return {};
            }

            // PVIA: bind the honest local derivation before any injected deviation.
            pvia::RecordId pvia_record = 0;
            if (pvia::Runtime::instance().enabled()) {
                auto& rt = pvia::Runtime::instance();
                const size_t active_count =
                    2 * (v1.size() / (1ULL << (i + 1)));
                const std::vector<pvia::FieldStateSegment> pvia_source_segments = {
                    {&v1, 0, active_count}, {&v2, 0, active_count},
                    {&v3, 0, active_count}, {&beta1, 0, active_count},
                    {&h1, 0, active_count}, {&h2, 0, active_count}};
                const pvia::StateId source_state = rt.import_state_slices(
                    "cosumcheck_zero_round_input", pvia::Phase::COSUMCHECK_ZERO,
                    pvia_source_segments);
                std::vector<pvia::OperationRef> predecessors;
                const auto predecessor = rt.previous_round_operation_ref(
                    pvia::Phase::COSUMCHECK_ZERO, static_cast<uint32_t>(i),
                    pvia::Obligation::PUBLISH);
                if (predecessor.object_id != 0) predecessors.push_back(predecessor);
                pvia_record = rt.register_cubic_operation(
                    pvia::Phase::COSUMCHECK_ZERO, i, pvia::Obligation::DERIVE, H, predecessors);
                rt.bind_state_dependencies(
                    pvia_record, std::vector<pvia::StateId>{source_state});
                rt.bind_relation_kernel(
                    pvia_record, pvia::AuditRelationKernel::COSUMCHECK_ZERO);
                vector<F> pvia_round_aux = {y, b};
                if (i > 0) pvia_round_aux.push_back(challenges[i-1]);
                rt.bind_public_field_aux(
                    pvia_record, pvia::AuditPublicAuxKind::SUMCHECK_CHALLENGE,
                    pvia_round_aux);
                pvia::Runtime::instance().activate_cubic(pvia_record, H);
            }

            H = aggregate_cubic_poly(
                H, beta2, k, _k, N, "cosumcheck_zero_round_release",
                pvia::Phase::COSUMCHECK_ZERO, static_cast<uint32_t>(i));
            
            if(rank == 0)vt.start();
        
            if(H.eval(0) + H.eval(1) != y){
                printf("Error cubic sumcheck %d,(%lld,%lld),(%lld,%lld)\n",i,y.real,y.img,(H.eval(0) + H.eval(1)).real,(H.eval(0) + H.eval(1)).img);
                pvia::Runtime::instance().handle_global_failure(
                    "zero-check sumcheck", pvia::Phase::COSUMCHECK_ZERO, i);
                // Original code continued here; PVIA keeps that behavior in debug mode.
            }
            pt_cp.start();
            challenges[i] = hash_to_field({H.a,H.b,H.c,H.d}); 
            if(rank == 0) ps += 4*16/1024.0;
            y = H.eval(challenges[i]);
            if(rank == 0)vt.end();
            _zero_check_sumcheck_phase2(i, challenges[i],v1,v2, v3, beta1, h1, h2);
            pt_cp.end();
            
        }
        final_v1.resize(1<<cosumcheck_offset);
        final_v2.resize(1<<cosumcheck_offset);
        final_v3.resize(1<<cosumcheck_offset);
        final_h1.resize(1<<cosumcheck_offset);
        final_h2.resize(1<<cosumcheck_offset);
        for(int i = 0; i < 1<<cosumcheck_offset; i++){
            final_v1[i] = v1[i];
            final_v2[i] = v2[i];
            final_v3[i] = v3[i];
            final_h1[i] = h1[i];
            final_h2[i] = h2[i];
        }

    }else{
        final_v1 = v1;
        final_v2 = v2;
        final_v3 = v3;
        final_h1 = h1;
        final_h2 = h2;        
    }
    
    vector<pair<F,vector<F>>> reply = F_zero_check_rest(final_v1, final_v2, final_v3, final_h1, final_h2, beta1, beta2, b, y, k, _k, N,
        static_cast<uint32_t>(rounds));
    if(rank == 0) ps += 16*(4*(int)log2(N)+5)/1024.0;
        
    for(int i = 0; i < 4; i++){
        reply[i].second.insert(reply[i].second.end(),challenges.begin(),challenges.end());
    }
    return reply;
}


quadratic_poly _quadratic_batch_sumcheck_phase1(int iter, F b,vector<F> &v1,vector<F> &v2, vector<F> &v3,vector<F> &v4, vector<F> &r1, vector<F> &r2){
    quadratic_poly p = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
    quadratic_poly p_r = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
    linear_poly l1,l2;
    for(int i = 0; i < v1.size()/(1<<(iter+1)); i++){
        l1 = linear_poly(v1[2*i+1]-v1[2*i],v1[2*i]);
        l2 = linear_poly(v2[2*i+1]-v2[2*i],v2[2*i]);
        p = p + l1*l2;
        l1 = linear_poly(v3[2*i+1]-v3[2*i],v3[2*i]);
        l2 = linear_poly(v4[2*i+1]-v4[2*i],v4[2*i]);
        p = p + l1*l2;
        
        l1 = linear_poly(r1[2*i+1]-r1[2*i],r1[2*i]);
        l2 = linear_poly(r2[2*i+1]-r2[2*i],r2[2*i]);
        p_r = p_r + l1*l2;
    }
    p.a = p.a + b*p_r.a;
    p.b = p.b + b*p_r.b;
    p.c = p.c + b*p_r.c;
    return p;
}

void _quadratic_batch_sumcheck_phase2(int iter, F r,vector<F> &v1,vector<F> &v2, vector<F> &v3, vector<F> &v4, vector<F> &r1, vector<F> &r2){
    for(int i = 0; i < v1.size()/(1<<(iter+1)); i++){
        v1[i] = v1[2*i] + r*(v1[2*i+1]-v1[2*i]);
        v2[i] = v2[2*i] + r*(v2[2*i+1]-v2[2*i]);
        v3[i] = v3[2*i] + r*(v3[2*i+1]-v3[2*i]);
        v4[i] = v4[2*i] + r*(v4[2*i+1]-v4[2*i]);
        r1[i] = r1[2*i] + r*(r1[2*i+1]-r1[2*i]);
        r2[i] = r2[2*i] + r*(r2[2*i+1]-r2[2*i]);
    }
}

vector<std::pair<F,vector<F>>> _quadratic_cosumcheck(F y, vector<F> &v1, vector<F> &v2, int N, int _k, int k, double &ps){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    int M = v1.size();
    int rounds = (int)log2(M);
    vector<F> challenges(rounds);
    for(int i = 0; i < rounds; i++){
        pt_cp.start();
        
        quadratic_poly H = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
        for(int j = 0; j < v1.size()/(1<<(i+1)); j++) H = H + linear_poly(v1[2*j+1]-v1[2*j],v1[2*j])*linear_poly(v2[2*j+1]-v2[2*j],v2[2*j]);
        
        pt_cp.end();
        if (pvia::Runtime::instance().enabled() &&
            !pvia_verify_quadratic_round_polynomial(H, i, v1, v2)) {
            pvia::Runtime::instance().handle_global_failure(
                "cosumcheck_quadratic_local_arithmetic",
                pvia::Phase::COSUMCHECK_QUADRATIC, i);
            return {};
        }
        // PVIA: one responsibility block per prover and coSumcheck round.
        pvia::RecordId pvia_record = 0;
        if (pvia::Runtime::instance().enabled()) {
            auto& rt = pvia::Runtime::instance();
            const size_t active_count =
                2 * (v1.size() / (1ULL << (i + 1)));
            const std::vector<pvia::FieldStateSegment> pvia_source_segments = {
                {&v1, 0, active_count}, {&v2, 0, active_count}};
            const pvia::StateId source_state = rt.import_state_slices(
                "cosumcheck_quadratic_round_input",
                pvia::Phase::COSUMCHECK_QUADRATIC, pvia_source_segments);
            std::vector<pvia::OperationRef> predecessors;
            const auto predecessor = rt.previous_round_operation_ref(
                pvia::Phase::COSUMCHECK_QUADRATIC, static_cast<uint32_t>(i),
                pvia::Obligation::PUBLISH);
            if (predecessor.object_id != 0) predecessors.push_back(predecessor);
            pvia_record = rt.register_quadratic_operation(
                pvia::Phase::COSUMCHECK_QUADRATIC, i, pvia::Obligation::DERIVE, H, predecessors);
            rt.bind_state_dependencies(
                pvia_record, std::vector<pvia::StateId>{source_state});
            rt.bind_relation_kernel(
                pvia_record, pvia::AuditRelationKernel::COSUMCHECK_QUADRATIC);
            vector<F> pvia_round_aux = {y};
            if (i > 0) pvia_round_aux.push_back(challenges[i-1]);
            rt.bind_public_field_aux(
                pvia_record, pvia::AuditPublicAuxKind::SUMCHECK_CHALLENGE,
                pvia_round_aux);
            pvia::Runtime::instance().activate_quadratic(pvia_record, H);
        }
        H = aggregate_quadratic_poly(
            H, k, _k, N, "cosumcheck_quadratic_round_release",
            pvia::Phase::COSUMCHECK_QUADRATIC, static_cast<uint32_t>(i));
        if(rank == 0)vt.start();
        if(H.eval(0) + H.eval(1) != y){
            printf("Error cubic sumcheck %d,(%lld,%lld),(%lld,%lld)\n",i,y.real,y.img,(H.eval(0) + H.eval(1)).real,(H.eval(0) + H.eval(1)).img);
            pvia::Runtime::instance().handle_global_failure(
                "quadratic coSumcheck", pvia::Phase::COSUMCHECK_QUADRATIC, i);
            if (!pvia::Runtime::instance().enabled()) exit(-1);
        }
        pt_cp.start();
        challenges[i] = hash_to_field({H.a,H.b,H.c}); 
        if(rank == 0)vt.end();
        if(rank == 0) ps += 3*16/1024.0;

        y = H.eval(challenges[i]);
        for(int j = 0; j < v1.size()/(1<<(i+1)); j++){
            v1[j] = challenges[i]*(v1[2*j+1]-v1[2*j]) + v1[2*j];
            v2[j] = challenges[i]*(v2[2*j+1]-v2[2*j]) + v2[2*j];
        }
        pt_cp.end();
         
    }
    vector<pair<F,vector<F>>> reply = F_quadratic_sumcheck_rest(v1[0], v2[0], y, k, _k, N,
        static_cast<uint32_t>(rounds));
    if(rank == 0) ps += 16*(3*(int)log2(N)+2)/1024.0;
    
    for(int i = 0; i < 2; i++){
        reply[i].second.insert(reply[i].second.end(),challenges.begin(),challenges.end());
    }
    return reply; 
}


vector<std::pair<F,vector<F>>> _quadratic_batch_sumcheck(F y, vector<F> &v1, 
                                vector<F> &v2, vector<F> &v3, vector<F> &v4, vector<F> &R1, vector<F> &R2, 
                                int N, int _k, int k, double &ps){  
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    int M = v1.size();
    pt_cp.start();
        
    vector<F> h1(M,F(0)),h2(M,F(0));
    int j;
    
    for(j = 0; j < R1.size()-2; j++){
        
        h1[1<<j] = R1[j];
        h2[1<<j] = R2[j];
    }
    h1[(1<<j)-2] = R1[j];
    h2[(1<<j)-2] = R2[j];
    h1[(1<<j)-1] = R1[j+1];
    h2[(1<<j)-1] = R2[j+1];
    
    int rounds = (int)log2(M);
    vector<F> challenges(rounds);

    vector<F> _r1,_r2,ones1(M,F(1)),ones2(k,F(1));
    pt_cp.end();
    
    F y_r = F_ip_prod(h1,h2,ones1,ones2,k,_k,N,
        PVIA_SCALAR_CTX_COSUMCHECK_BATCH_AUX);
    if(rank == 0)vt.start();
    
    F b = hash_to_field({y_r});
    
    y += b*y_r;
    if(rank == 0)vt.end();
    
    //printf("%d,%d,%d,%d\n",v1.size(),v2.size(),v3.size(),v4.size());
    for(int i = 0; i < rounds; i++){
        pt_cp.start();
        quadratic_poly H;
        H = _quadratic_batch_sumcheck_phase1(i, b,v1,v2, v3,v4, h1, h2);
        pt_cp.end();
        if (pvia::Runtime::instance().enabled() &&
            !pvia_verify_batch_round_polynomial(
                H, i, b, v1, v2, v3, v4, h1, h2)) {
            pvia::Runtime::instance().handle_global_failure(
                "cosumcheck_batch_local_arithmetic",
                pvia::Phase::COSUMCHECK_BATCH, i);
            return {};
        }
        // PVIA: bind batch-Sumcheck local polynomial before aggregation.
        pvia::RecordId pvia_record = 0;
        if (pvia::Runtime::instance().enabled()) {
            auto& rt = pvia::Runtime::instance();
            const size_t active_count =
                2 * (v1.size() / (1ULL << (i + 1)));
            const std::vector<pvia::FieldStateSegment> pvia_source_segments = {
                {&v1, 0, active_count}, {&v2, 0, active_count},
                {&v3, 0, active_count}, {&v4, 0, active_count},
                {&h1, 0, active_count}, {&h2, 0, active_count}};
            const pvia::StateId source_state = rt.import_state_slices(
                "cosumcheck_batch_round_input",
                pvia::Phase::COSUMCHECK_BATCH, pvia_source_segments);
            std::vector<pvia::OperationRef> predecessors;
            const auto predecessor = rt.previous_round_operation_ref(
                pvia::Phase::COSUMCHECK_BATCH, static_cast<uint32_t>(i),
                pvia::Obligation::PUBLISH);
            if (predecessor.object_id != 0) predecessors.push_back(predecessor);
            pvia_record = rt.register_quadratic_operation(
                pvia::Phase::COSUMCHECK_BATCH, i, pvia::Obligation::DERIVE, H, predecessors);
            rt.bind_state_dependencies(
                pvia_record, std::vector<pvia::StateId>{source_state});
            rt.bind_relation_kernel(
                pvia_record, pvia::AuditRelationKernel::COSUMCHECK_BATCH);
            vector<F> pvia_round_aux = {y, b};
            if (i > 0) pvia_round_aux.push_back(challenges[i-1]);
            rt.bind_public_field_aux(
                pvia_record, pvia::AuditPublicAuxKind::SUMCHECK_CHALLENGE,
                pvia_round_aux);
            pvia::Runtime::instance().activate_quadratic(pvia_record, H);
        }
        H = aggregate_quadratic_poly(
            H, k, _k, N, "cosumcheck_batch_round_release",
            pvia::Phase::COSUMCHECK_BATCH, static_cast<uint32_t>(i));
        pt_cp.start();
        if(rank == 0)vt.start();
    
        if(H.eval(0) + H.eval(1) != y){
            printf("Error cubic sumcheck %d,(%lld,%lld),(%lld,%lld)\n",i,y.real,y.img,(H.eval(0) + H.eval(1)).real,(H.eval(0) + H.eval(1)).img);
            pvia::Runtime::instance().handle_global_failure(
                "quadratic batch sumcheck", pvia::Phase::COSUMCHECK_BATCH, i);
            // Original code continued here; PVIA keeps that behavior in debug mode.
        }
        challenges[i] = hash_to_field({H.a,H.b,H.c}); 
        
        y = H.eval(challenges[i]);
        if(rank == 0)vt.end();
        if(rank == 0) ps += 16*(3)/1024.0;
    
        _quadratic_batch_sumcheck_phase2(i, challenges[i],v1,v2, v3, v4, h1, h2);
        pt_cp.end();
        
    }
    
    vector<pair<F,vector<F>>> reply = F_batch_sumcheck_rest(v1[0], v2[0], v3[0], v4[0], h1[0], h2[0], b, y, k, _k, N,
        static_cast<uint32_t>(rounds));
    if(rank == 0) ps += 16*(3*(int)log2(N)+6)/1024.0;
    
    for(int i = 0; i < 4; i++){
        reply[i].second.insert(reply[i].second.end(),challenges.begin(),challenges.end());
    }
    return reply;
}