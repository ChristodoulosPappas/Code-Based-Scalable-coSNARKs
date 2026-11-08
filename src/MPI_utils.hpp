#pragma once
#include "coPIOP.h"
#include "sparse_eval.hpp"
#include "config_pc.hpp"
#include "utils.hpp"
#include "math.h"
#include "coPCS_utils.h"
#include <mpi.h>
#include <cstdint>

namespace pvia { enum class Phase : uint32_t; }

constexpr uint32_t PVIA_SCALAR_CTX_COSUMCHECK_ZERO_AUX = 0x1001U;
constexpr uint32_t PVIA_SCALAR_CTX_COSUMCHECK_BATCH_AUX = 0x1002U;
constexpr uint32_t PVIA_SCALAR_CTX_RANDOM_EVAL_BATCH = 0x2001U;
constexpr uint32_t PVIA_SCALAR_CTX_PCS_MASK_BASE = 0x3000U;
constexpr uint32_t PVIA_SCALAR_CTX_SPARSE_OPT = 0x4001U;
constexpr uint32_t PVIA_SCALAR_CTX_SPARSE_BATCH_1 = 0x4002U;
constexpr uint32_t PVIA_SCALAR_CTX_SPARSE_BATCH_2 = 0x4003U;
constexpr uint32_t PVIA_SCALAR_CTX_SPARSE_BATCH_3 = 0x4004U;
constexpr uint32_t PVIA_SCALAR_CTX_TEST_BASE = 0x9000U;

F F_ip(vector<F> &data, vector<F> &v1, vector<F> &v2, int k, int _k, int N,
       uint32_t scalar_context);
F F_ip_prod(vector<F> &data1, vector<F> &data2, vector<F> &v1, vector<F> &v2, int k, int _k, int N,
            uint32_t scalar_context);
quadratic_poly aggregate_quadratic_poly(quadratic_poly H, vector<F> &v, int k, int _k, int N, const char* release_name=nullptr);
quadratic_poly aggregate_quadratic_poly(quadratic_poly H, vector<F> &v, int k, int _k, int N, const char* release_name, pvia::Phase gate_phase, uint32_t gate_round);
cubic_poly aggregate_cubic_poly(cubic_poly H, vector<F> &v, int k, int _k, int N, const char* release_name = nullptr);
cubic_poly aggregate_cubic_poly(cubic_poly H, vector<F> &v, int k, int _k, int N, const char* release_name, pvia::Phase gate_phase, uint32_t gate_round);

vector<pair<F,vector<F>>> F_zero_check_rest(vector<F> &v1, vector<F> &v2, vector<F> &v3,vector<F> &h1, vector<F> &h2, 
                                            vector<F> &beta1, vector<F> &beta2, 
                                            F b, F y, int k, int _k, int N,
                                            uint32_t tail_round);
quadratic_poly aggregate_quadratic_poly(quadratic_poly H, int k, int _k, int N, const char* release_name = nullptr);
quadratic_poly aggregate_quadratic_poly(quadratic_poly H, int k, int _k, int N, const char* release_name, pvia::Phase gate_phase, uint32_t gate_round);

vector<pair<F,vector<F>>> F_batch_sumcheck_rest(F v1, F v2, F v3, F v4, F h1, F h2, 
                                            F b, F y, int k, int _k, int N,
                                            uint32_t tail_round);

F distributed_eval(vector<F> &poly, vector<F> &beta1, vector<F> &beta2, int N);
vector<F> batch_distributed_eval(vector<vector<F>> &poly, vector<F> &beta1, vector<F> &beta2, int N,
                                 uint32_t scalar_context);
void distribute_index(int N, int M,vector<sparse_eval_data> &index, int type=0);
void distribute_proving_data(vector<F> &vL, vector<F> &vR, vector<F> &vO, vector<F> &w, int N, int M, int _k, int k, int cir_type=0);
void setup_randomness(vector<F> &R, int N, int _k, int k, int size, uint64_t joint_domain = 0);
void setup_randomness_pair(
    vector<F> &R, vector<F> &R2, int N, int _k, int k, int size,
    uint64_t joint_domain, uint64_t joint_domain2);
void compute_secret_shares(vector<F> &v, vector<vector<F>> &v_shares, int N, int k, int _k, bool privacy_preserving);
vector<F> batch_ip(vector<vector<F>> &arr, vector<vector<vector<F>>> &v, int N, int k,int _k,
                   uint32_t scalar_context);
vector<pair<F,vector<F>>> F_quadratic_sumcheck_rest(F v1, F v2, F y, int k, int _k, int N,
                                            uint32_t tail_round);
vector<F> batch_distributed_eval_opt(vector<vector<F>> &poly, vector<F> r1, vector<F> r2, int N,
                                     uint32_t scalar_context);
void secret_share_coefficients(vector<F> &w, int M, int N, int _k, int k);
void myBcast(vector<u64> &data, int N);
vector<quadratic_poly> batch_aggregate(vector<quadratic_poly> H, vector<vector<F>> v2, vector<bool> secret_shared, vector<int> rounds,vector<int> k, int round, int N, const char* release_name=nullptr);
void myAlltoAll(vector<u64> &in, vector<u64> &out, int N, int total_size);