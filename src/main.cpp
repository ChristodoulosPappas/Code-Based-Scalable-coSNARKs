#include "config_pc.hpp"
#include "constants.h"
#include <vector>
#include <math.h>
#include "utils.hpp"
#include "mimc.h"
#include <chrono>
#include <fcntl.h>
#include <omp.h>
#include <unistd.h>
#include <mutex>
#include "polynomial.h"
#include "coPIOP.h"
#include "coSumcheck_MPI.h"
#include "coPCS_utils.h"
#include <mpi.h>
#include <mpi-ext.h>
#include "coPCS.h"
#include "Fiat_Shamir.h"
#include "Distributed_Sumcheck.h"
#include "MPI_utils.hpp"
#include "timer.hpp"
#include "accountability/PVIA.hpp"
#include "accountability/TransferAuthentication.hpp"
#include "accountability/Ed25519TransferAuditHarness.hpp"
#include "accountability/Ed25519TransferSecureRuntime.hpp"
#include "accountability/FoldResidualComputationSelfTest.hpp"
#include "accountability/FoldResidualRuntimeHarness.hpp"
#include "accountability/SecureAuditComposition.hpp"
#include "accountability/NativeSumcheckResidualComputationBackend.hpp"
#include "accountability/RegistrationNativeConsumedSnapshot.hpp"
#include "accountability/LiveNativeSourceRequest.hpp"
#include "accountability/ReferenceShamirAuditSession.hpp"
#include "accountability/ReferenceGodOutputDelivery.hpp"
#include "accountability/ReferenceDistributedRowRegistrationSelfTest.hpp"
#include "accountability/ReferenceVssSelectivePointSelfTest.hpp"
#include "accountability/ReferenceVssSelectivePointDurableReplay.hpp"
#include "accountability/ReferenceVssExternalAnchor.hpp"
#include "accountability/Sp1VssRecoveryProofProvider.hpp"
#include "accountability/ReferenceResidualMpcSelfTest.hpp"
#include "accountability/ReferencePrivateOwnerSelectionSelfTest.hpp"
#include "accountability/ReferencePrivateResidualFlagSelfTest.hpp"
#include "accountability/RegistrationOriginEndorsements.hpp"
#include "accountability/RegistrationReceiptReplayLedger.hpp"
#include "accountability/RegistrationPublicOriginBundle.hpp"
#include "accountability/RegistrationNativeIssuerPublicFile.hpp"
#include "accountability/ReleaseGateMatrixSelfTest.hpp"
#include "accountability/RobustTerminationRuntimeSelfTest.hpp"
#include "accountability/ReferenceBivariateVss.hpp"
#include "accountability/PublicTransferCertificateCodec.hpp"
#include "accountability/Ed25519PublicTransferJudge.hpp"
#include "accountability/RobustAuditAbortCertificateCodec.hpp"
#include "accountability/SharedLibraryMultiplicationConsistencyProviderSession.hpp"
#include "accountability/SharedLibraryReferenceGodOutputConsistencyProvider.hpp"
#include "accountability/ExperimentMetrics.hpp"
#include "accountability/CheckpointBatchAuthentication.hpp"
#include "accountability/JointPackedPreprocessing.hpp"
#include "accountability/InitialValidityRelationCache.hpp"
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <limits>
#include <string>
#include <memory>


int tensor_row_size;
int mul_counter= 0;
extern timer pt,pt_cp,vt,sch_com;
extern timer_cpu pt_cpu;
extern vector<vector<pair<int, int>>> A,B,C;
extern vector<vector<pair<int, int>>> pA,pB,pC;
extern vector<vector<pair<int,int>>> tA,tB,tC;
extern int logm,logn;
extern int rate;
extern bool data_parallel;
extern int cosumcheck_offset = 0;
extern int sumcheck_offset = 4;
extern int PC_offset = 10;
extern int multree_offset = 4;
extern int com_rounds;
bool isLAN = false;
extern double cm;


void encode_locally(vector<vector<F>> &C, vector<vector<F>> &R_shares, int l, int N, int M, int k, int _k){
    vector<vector<F>> data(M/k);
    C.resize(N);
    int ctr = 0;
    for(int i = 0; i < data.size(); i++){
        data[i].resize(_k);
        for(int j = 0; j < _k; j++){
            data[i][j] = ctr++;
        }
        fft(data[i],(int)log2(_k),true);
        data[i].resize(N,0);
        fft(data[i],(int)log2(N),false);
    }
    for(int i = 0; i < C.size(); i++){
        C[i].resize(next_pow2(M/k+l),F(0));
        for(int j = 0; j < M/k; j++){
            C[i][j] = data[j][i];
        }
        for(int j = 0; j < l; j++){
            C[i][j+(M/k)] = R_shares[i][j];
        }
        fft(C[i], (int)log2(C[i].size()),true);
        C[i].resize(C[i].size()*4,F(0));
        fft(C[i], (int)log2(C[i].size()),false);
        
    }
}   

F evaluate_locally(vector<F> r, int k, int _k){
    vector<F> b;precompute_beta(r,b);
    F y = F(0);
    int ctr = 0;
    int idx = 0;
    for(int i = 0; i < b.size()/k; i++){
        for(int j = 0; j < k; j++){
            y += b[idx]*F(ctr);
            ctr++;
            idx++;
        }
        ctr += (_k-k);    
    }
    return y;
}


void test_batch_check(int M,int N, int k, int _k, int l){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<vector<F>> V1(N),V2(N),V3(N),V4(N); 
    vector<vector<F>> R1(N),R2(N); 
    vector<F> r;
    for(int i = 0; i < (int)log2(M); i++){
        r.push_back(hash_to_field({0}));
    }   
    vector<F> fl,fr,fo;
    F y = F(0);
    if(rank == 0){
       //vector<F> beta; precompute_beta(r,beta);
        int idx = 0;
        for(int i = 0; i < N; i++){
            V1[i].resize(M/k);V2[i].resize(M/k);V3[i].resize(M/k);V4[i].resize(M/k);
            R1[i].resize((int)log2(M/k) + 2 );
            R2[i].resize((int)log2(M/k) + 2 );
        }
        int ctr = 0;
        
        for(int i = 0; i < M/k; i++){
            vector<F> buff1(_k),buff2(_k),buff3(_k),buff4(_k);
            for(int j = 0; j < k; j++){
                buff1[j] = ctr++;
                buff2[j] = ctr++;
                buff3[j] = ctr++;                
                buff4[j] = ctr++;                
                y += buff1[j]*buff2[j] + buff3[j]*buff4[j];
                fl.push_back(buff1[j]);
                fr.push_back(buff2[j]);
                fo.push_back(buff3[j]);
            }
            for(int j = k; j < _k; j++){
                buff1[j] = ctr++;
                buff2[j] = ctr++;
                buff3[j] = ctr++;                
                buff4[j] = ctr++;                
            }
            fft(buff1,(int)log2(buff1.size()),true);fft(buff2,(int)log2(buff2.size()),true);fft(buff3,(int)log2(buff3.size()),true);fft(buff4,(int)log2(buff4.size()),true);
            buff1.resize(2*N,0);buff2.resize(2*N,0);buff3.resize(2*N,0);buff4.resize(2*N,0);
            fft(buff1,(int)log2(buff1.size()),false);fft(buff2,(int)log2(buff2.size()),false);fft(buff3,(int)log2(buff3.size()),false);
            fft(buff4,(int)log2(buff4.size()),false);
            for(int j = 0; j < N; j++){
                V1[j][i] = buff1[2*j+1];
                V2[j][i] = buff2[2*j+1];
                V3[j][i] = buff3[2*j+1];
                V4[j][i] = buff4[2*j+1];
            }
        }
        
        for(int i = 0; i < R1[0].size(); i++){
            vector<F> buff1(_k),buff2(_k);
            for(int j = 0; j < k; j++){
                buff1[j] = ctr++;
                buff2[j] = ctr++;
            }
            for(int j = k; j < _k; j++){
                buff1[j] = ctr++;
                buff2[j] = ctr++;
            }
            fft(buff1,(int)log2(buff1.size()),true);fft(buff2,(int)log2(buff2.size()),true);
            buff1.resize(2*N,0);buff2.resize(2*N,0);
            fft(buff1,(int)log2(buff1.size()),false);fft(buff2,(int)log2(buff2.size()),false);
            for(int j = 0; j < N; j++){
                R1[j][i] = buff1[2*j+1];
                R2[j][i] = buff2[2*j+1];
            }
        }
        
    }
    vector<F> v1,v2,v3,v4,h1,h2;
    vector<F> buff;
    vector<u64> buff_u64;
    
    if(rank == 0){
        v1 = V1[0];v2 = V2[0]; v3 = V3[0]; v4 = V4[0];
        h1 = R1[0]; h2 = R2[0];
        for(int i = 1; i < N; i++){
            buff = V1[i];
            buff.insert(buff.end(),V2[i].begin(),V2[i].end());
            buff.insert(buff.end(),V3[i].begin(),V3[i].end());
            buff.insert(buff.end(),V4[i].begin(),V4[i].end());
            buff.insert(buff.end(),R1[i].begin(),R1[i].end());
            buff.insert(buff.end(),R2[i].begin(),R2[i].end());
            buff.push_back(y);
            field_vector_serialize(buff,buff_u64);
            MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        }
    }else{
        buff_u64.resize(2+2*(4*M/k + 2*(log2(M/k) + 2)));
        MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        field_vector_deserialize(buff_u64,buff);
        v1.resize(M/k);v2.resize(M/k);v3.resize(M/k);v4.resize(M/k);
        h1.resize(log2(M/k) + 2);h2.resize(log2(M/k) + 2);
        int ctr = 0;
        for(int i = 0; i < M/k; i++){
            v1[i] = buff[ctr++];
        }
        for(int i = 0; i < M/k; i++){
            v2[i] = buff[ctr++];
        }
        for(int i = 0; i < M/k; i++){
            v3[i] = buff[ctr++];
        }
        for(int i = 0; i < M/k; i++){
            v4[i] = buff[ctr++];
        }
        for(int i = 0; i < h1.size(); i++){
            h1[i] = buff[ctr++];
        }
        for(int i = 0; i < h1.size(); i++){
            h2[i] = buff[ctr++];
        }
        y = buff[ctr];
    }
    MPI_Barrier(MPI_COMM_WORLD);

    double pt = 0.0,vt = 0,ps = 0,cm = 0;
    vector<pair<F,vector<F>>> reply = _quadratic_batch_sumcheck(y, v1, v2, v3,v4, h1, h2, N, _k, k,ps);
    if(rank == (0)){
        if(evaluate_vector(fl,reply[0].second) != reply[0].first){
            printf("ERROR L\n");
        }
        if(evaluate_vector(fr,reply[1].second) != reply[1].first){
            printf("ERROR R\n");
        }
        if(evaluate_vector(fo,reply[2].second) != reply[2].first){
            printf("ERROR O\n");
        }
        printf("OK\n");
    }

}

void test_zero_check(int M,int N, int k, int _k, int l){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<vector<F>> L(N),R(N),O(N); 
    vector<vector<F>> R1(N),R2(N); 
    vector<F> r;
    for(int i = 0; i < (int)log2(M); i++){
        r.push_back(hash_to_field({0}));
    }   
    vector<F> fl,fr,fo;
        
    if(rank == 0){
       //vector<F> beta; precompute_beta(r,beta);
        int idx = 0;
        for(int i = 0; i < N; i++){
            L[i].resize(M/k);R[i].resize(M/k);O[i].resize(M/k);
            R1[i].resize((int)log2(M/k) + 2 + l);
            R2[i].resize((int)log2(M/k) + 2 + l);
        }
        int ctr = 0;

        for(int i = 0; i < M/k; i++){
            vector<F> buffL(_k),buffR(_k),buffO(_k);
            for(int j = 0; j < k; j++){
                buffL[j] = ctr++;
                buffR[j] = ctr++;
                buffO[j] = buffL[j]*buffR[j];                
                fl.push_back(buffL[j]);
                fr.push_back(buffR[j]);
                fo.push_back(buffO[j]);
            }
            for(int j = k; j < _k; j++){
                buffL[j] = ctr++;
                buffR[j] = ctr++;
                buffO[j] = ctr++;                
            }
            fft(buffL,(int)log2(buffL.size()),true);fft(buffR,(int)log2(buffL.size()),true);fft(buffO,(int)log2(buffL.size()),true);
            buffL.resize(2*N,0);buffR.resize(2*N,0);buffO.resize(2*N,0);
            fft(buffL,(int)log2(buffL.size()),false);fft(buffR,(int)log2(buffL.size()),false);fft(buffO,(int)log2(buffL.size()),false);
            for(int j = 0; j < N; j++){
                L[j][i] = buffL[2*j+1];
                R[j][i] = buffR[2*j+1];
                O[j][i] = buffO[2*j+1];
            }
        }
        
        for(int i = 0; i < R1[0].size(); i++){
            vector<F> buff1(_k),buff2(_k);
            for(int j = 0; j < k; j++){
                buff1[j] = ctr++;
                buff2[j] = ctr++;
            }
            for(int j = k; j < _k; j++){
                buff1[j] = ctr++;
                buff2[j] = ctr++;
            }
            fft(buff1,(int)log2(buff1.size()),true);fft(buff2,(int)log2(buff2.size()),true);
            buff1.resize(2*N,0);buff2.resize(2*N,0);
            fft(buff1,(int)log2(buff1.size()),false);fft(buff2,(int)log2(buff2.size()),false);
            for(int j = 0; j < N; j++){
                R1[j][i] = buff1[2*j+1];
                R2[j][i] = buff2[2*j+1];
            }
        }
        
    }
    vector<F> v1,v2,v3,h1,h2;
    vector<F> buff;
    vector<u64> buff_u64;
    
    if(rank == 0){
        v1 = L[0];v2 = R[0]; v3 = O[0];
        h1 = R1[0]; h2 = R2[0];
        for(int i = 1; i < N; i++){
            buff = L[i];
            buff.insert(buff.end(),R[i].begin(),R[i].end());
            buff.insert(buff.end(),O[i].begin(),O[i].end());
            buff.insert(buff.end(),R1[i].begin(),R1[i].end());
            buff.insert(buff.end(),R2[i].begin(),R2[i].end());
            field_vector_serialize(buff,buff_u64);
            MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        }
    }else{
        buff_u64.resize(2*(3*M/k + 2*(log2(M/k) + 2+l)));
        MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        field_vector_deserialize(buff_u64,buff);
        v1.resize(M/k);v2.resize(M/k);v3.resize(M/k);
        h1.resize(log2(M/k) + 2+l);h2.resize(log2(M/k) + 2+l);
        int ctr = 0;
        for(int i = 0; i < M/k; i++){
            v1[i] = buff[ctr++];
        }
        for(int i = 0; i < M/k; i++){
            v2[i] = buff[ctr++];
        }
        for(int i = 0; i < M/k; i++){
            v3[i] = buff[ctr++];
        }
        for(int i = 0; i < h1.size(); i++){
            h1[i] = buff[ctr++];
        }
        for(int i = 0; i < h1.size(); i++){
            h2[i] = buff[ctr++];
        }
    }
    MPI_Barrier(MPI_COMM_WORLD);

    double pt = 0.0,vt = 0,ps = 0,cm = 0;
    vector<pair<F,vector<F>>> reply = _zero_check_sumcheck(F(0), v1, v2, v3, h1, h2, r, N, _k, k,ps);
    if(rank == (0)){
        if(evaluate_vector(fl,reply[0].second) != reply[0].first){
            printf("ERROR L\n");
        }
        if(evaluate_vector(fr,reply[1].second) != reply[1].first){
            printf("ERROR R\n");
        }
        if(evaluate_vector(fo,reply[2].second) != reply[2].first){
            printf("ERROR O\n");
        }
        printf("OK\n");
    }

}

void distribute_data(vector<vector<F>> &Data){
    vector<u64> buff;
    for(int i = 1; i < Data.size(); i++){
        field_vector_serialize(Data[i],buff);
        MPI_Send(buff.data(),buff.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
    }
}

void distribute_data_tensor(vector<vector<vector<F>>> &Data){
    vector<u64> buff;
    vector<F> arr;
    for(int i = 1; i < Data.size(); i++){
        arr = convert2vector(Data[i]);
        field_vector_serialize(arr,buff);
        MPI_Send(buff.data(),buff.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
    }
}

void get_data(vector<F> &v, int N){
    vector<u64> buff(N*2);
    MPI_Recv(buff.data(),buff.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
    field_vector_deserialize(buff,v);
}

void test_quadratic_sumheck(int N, int M){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    F sum = 0;
    vector<F> arr1,arr2;
    vector<F> f1,f2;
    if(rank == 0){
        vector<vector<F>> V(N);
        vector<vector<F>> v1(N),v2(N);
        for(int i = 0; i < N; i++){
            v1[i].resize(M/N);
            v2[i].resize(M/N);
            for(int j = 0; j < v1[i].size(); j++){
                v1[i][j] = random();
                v2[i][j] = random();
                f1.push_back(v1[i][j]);
                f2.push_back(v2[i][j]);
                
                sum += v1[i][j]*v2[i][j];
            }
            V[i] = v1[i];
            V[i].insert(V[i].end(),v2[i].begin(),v2[i].end());
        }
        for(int i = 0; i < N; i++){
            V[i].push_back(sum);
        }
        arr1 = v1[0];
        arr2 = v2[0];
        distribute_data(V);
    }else{
        vector<F> buff;
        get_data(buff,2*M/N+1);
        arr1.resize(M/N);
        arr2.resize(M/N);
        for(int i = 0; i < M/N; i++){
            arr1[i] = buff[i];
            arr2[i] = buff[i+M/N];
        }
        sum = buff[buff.size()-1];
    }
    double vt = 0.0,ps = 0.0;
    vector<pair<F,vector<F>>> claims = _quadratic_sumcheck_sparrow(sum, arr1, arr2, N);
    //vector<pair<F,vector<F>>> claims = _quadratic_sumcheck(sum, arr1, arr2, N);
    if(rank == 0){
        if(evaluate_vector(f1,claims[0].second) != claims[0].first){
            printf("ERROR1\n");
        }
        if(evaluate_vector(f1,claims[0].second) != claims[0].first){
            printf("ERROR1\n");
        }
    }
    
}

void test_cubic_sumheck(int N, int M){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    
    vector<F> r1,r2,r3;
    for(int i = 0; i < (int)log2(M/N)-sumcheck_offset; i++) r1.push_back(hash_to_field({}));
    for(int i = (int)log2(M/N)-sumcheck_offset; i < (int)log2(M/N); i++) r2.push_back(hash_to_field({}));
    for(int i = (int)log2(M/N); i < (int)log2(M); i++) r3.push_back(hash_to_field({}));
    vector<F> beta1,beta2,beta3;
    precompute_beta(r1,beta1);precompute_beta(r2,beta2);precompute_beta(r3,beta3);
    vector<F> f1,f2;
        
    F sum = 0;
    vector<F> arr1,arr2,arr3;
    if(rank == 0){
        vector<vector<F>> V(N);
        vector<vector<F>> v1(N),v2(N);
        vector<F> r = r1;r.insert(r.end(),r2.begin(),r2.end());r.insert(r.end(),r3.begin(),r3.end());
        vector<F> beta;precompute_beta(r,beta);
        int ctr = 0;
        for(int i = 0; i < N; i++){
            v1[i].resize(M/N);
            v2[i].resize(M/N);
            for(int j = 0; j < v1[i].size(); j++){
                v1[i][j] = rand();
                v2[i][j] = rand();
                f1.push_back(v1[i][j]);
                f2.push_back(v2[i][j]);
                sum += v1[i][j]*v2[i][j]*beta[ctr++];
            }
            V[i] = v1[i];
            V[i].insert(V[i].end(),v2[i].begin(),v2[i].end());
        }
        for(int i = 0; i < N; i++){
            V[i].push_back(sum);
        }
        arr1 = v1[0];
        arr2 = v2[0];
        distribute_data(V);
    }else{
        vector<F> buff;
        get_data(buff,2*M/N+1);
        arr1.resize(M/N);
        arr2.resize(M/N);
        for(int i = 0; i < M/N; i++){
            arr1[i] = buff[i];
            arr2[i] = buff[i+M/N];
        }
        sum = buff[buff.size()-1];
    }
    double vt = 0.0,ps = 0.0;

     pt.start();
       
    vector<pair<F,vector<F>>> claims = _cubic_sumcheck_sparrow(sum, arr1, arr2, beta1,beta2,beta3, N);
     pt.end();
    /*
    if(rank == 0){
        if(evaluate_vector(f1,claims[0].second) != claims[0].first){
            printf("ERROR1\n");
        }
        if(evaluate_vector(f2,claims[0].second) != claims[1].first){
            printf("ERROR1\n");
        }
    }*/
    
}

void test_product(int N, int M, int K){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<vector<F>> input(K);
    vector<F> prod(K,F(1));
    vector<vector<vector<F>>> data(N);
    vector<vector<F>> poly_matrix(K);
    if(rank == 0){
        int ctr = 1;
        for(int i = 0; i < N; i++){
            data[i].resize(K);
            for(int j = 0; j < K; j++){
                data[i][j].resize(M/N);
                for(int k = 0; k < M/N; k++){
                    data[i][j][k] = ctr++;
                    prod[j] *= data[i][j][k];
                    poly_matrix[j].push_back(data[i][j][k]);
                } 
            }
        }
        input = data[0];
        distribute_data_tensor(data);
    }else{
        vector<F> buff;
        int ctr = 0;
        get_data(buff,K*M/N);
        for(int i = 0; i < input.size(); i++){
            input[i].resize(M/N);
            for(int j = 0; j < M/N; j++){
                input[i][j] = buff[ctr++];
            }
        }
    }

    vector<F> output,r;
    double vt,ps;
    
    pair<F,vector<vector<F>>> claim =  prove_product(input, output, F(0), r, N);
    
    vector<F> b1,b2;
    precompute_beta(claim.second[0],b1);
    precompute_beta(claim.second[2],b2);
    vector<F> Y = batch_distributed_eval(input,b1,b2,N, PVIA_SCALAR_CTX_TEST_BASE + 1U);
    
    if(rank == 0){
        F sum  =F(0);
        for(int i = 0; i < data.size(); i++){
            F y = F(0);
            for(int j = 0; j < data[i][0].size(); j++){
                if(i == 0 && data[i][0][j] != input[i][j]){
                    printf("Error\n");
                }
                y += data[i][0][j]*b1[j];
            }
            printf("> %lld,%lld\n",y.real,y.img);
            sum += b2[i]*y;
        }

        printf("%d\n",output.size());
        for(int i = 0; i < output.size(); i++){
            if(output[i] != prod[i]){
                printf("Error %d\n",i);
            }
        }
        for(int i = 0; i < input.size(); i++){
            for(int j = 0; j < input[i].size(); j++){
                if(input[i][j] != poly_matrix[i][j]){
                    printf("Error\n");
                }
            }
        }
        vector<F> r = claim.second[0];
        r.insert(r.end(),claim.second[2].begin(),claim.second[2].end());
        r.insert(r.end(),claim.second[1].begin(),claim.second[1].end());
        vector<F> poly = convert2vector(poly_matrix);
        if(evaluate_vector(poly,r) != claim.first){
            printf(">>>EEROR\n");
        }
        if(sum != claim.first){
            printf("EEER\n");
        }
        if(evaluate_vector(Y,claim.second[1])!= sum){
            printf("EERROR 2\n");
        }
    }
}





void test_sparse_eval(int N, int M, int type){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<sparse_eval_data> index;
        
    distribute_index(N, M, index,type);
    vector<F> r1,r2;
    vector<vector<F>> beta1(3),beta2(3);
    F a = hash_to_field({0}), b = hash_to_field({0}), c = hash_to_field({0});
    //double pt = 0.0;

    for(int i = 0; i < logm; i++){
        r1.push_back(hash_to_field({0}));
    }
    for(int i = 0; i < logn; i++){
        r2.push_back(hash_to_field({0}));
    }
    compute_R1CS_betas(r1,  r2, index, beta1, beta2, logm, logn, N);
    vector<F> RA,RB,RC;
    _reduce_R1CS_matrixes(M, r1, RA, RB, RC, N);
    
    
    vector<vector<F>> polys = {RA,RB,RC};
    vector<F> r21,r22;
    for(int i = 0; i < logn - (int)log2(N); i++) r21.push_back(r2[i]);
    for(int i = r21.size(); i < r2.size(); i++) r22.push_back(r2[i]);
    vector<F> b1,b2;
    precompute_beta(r21,b1);precompute_beta(r22,b2);
    

    vector<F> Y = batch_distributed_eval(polys,b1,b2,N, PVIA_SCALAR_CTX_TEST_BASE + 2U);
    vector<F> _RA,_RB,_RC;
    if(rank!= 0){
        generate_R1CS_matrixes(M,type);
    }
    
    reduce_R1CS_matrixes(M,r1,_RA,_RB,_RC);
    
    //if(rank == 4){
       /*
        for(int i = 0; i < pA.size(); i++){
            if(pA[i].size()){
                for(int j = 0; j < pA[i].size(); j++){
                    printf(" %d, %d |",pA[i][j].first,pA[i][j].second);
                }
                printf("\n");
            }
        }
        printf("=====================\n");
        for(int i = 0; i < pA.size(); i++){
            if(tA[i+pC.size()*rank].size()){
                for(int j = 0; j < tA[i+pC.size()*rank].size(); j++){
                    printf(" %d, %d |",tA[i+pC.size()*rank][j].first,tA[i+pC.size()*rank][j].second);
                }
                printf("\n");
            }
        }
        printf("===== %d,%d ======\n",pA.size()*N,tA.size());
       */
        for(int i = 0; i < pA.size(); i++){
            if(pA[i].size() != tA[i+pA.size()*rank].size()){
                printf("> Error pA %d\n",i);
                return;
            }
            if(pA[i].size()){
                for(int j = 0; j < pA[i].size(); j++){
                    if(pA[i][j].first != tA[i+pA.size()*rank][j].first || pA[i][j].second != tA[i+pA.size()*rank][j].second){
                        printf("> Error pA %d,%d\n",i,j);        
                    }
                }
            }
        }
        for(int i = 0; i < pB.size(); i++){
            if(pB[i].size() != tB[i+pB.size()*rank].size()){
                printf("> Error pB %d\n",i);
                return;
            }
            if(pB[i].size()){
                for(int j = 0; j < pB[i].size(); j++){
                    if(pB[i][j].first != tB[i+pB.size()*rank][j].first || pB[i][j].second != tB[i+pB.size()*rank][j].second){
                        printf("> Error pB %d,%d\n",i,j);        
                    }
                }
            }
        }

        for(int i = 0; i < pC.size(); i++){
            if(pC[i].size() != tC[i+pC.size()*rank].size()){
                printf("> Error pC %d\n",i);
                return;
            }
            if(pC[i].size()){
                for(int j = 0; j < pC[i].size(); j++){
                    if(pC[i][j].first != tC[i+pC.size()*rank][j].first || pC[i][j].second != tC[i+pC.size()*rank][j].second){
                        printf("> Error pC %d,%d\n",i,j);        
                    }
                }
            }
        }
        
        
        
   // }
    
        for(int i = 0; i < RA.size(); i++){
            if(RA[i] != _RA[i + rank*pA.size()]){
               printf("Error %d,%d,%d, (%lld,%lld),(%lld,%lld)\n",rank,i,RA.size(),RA[i].real,RA[i].img,_RA[i + rank*pA.size()].real,_RA[i + rank*pA.size()].img);
            }
        }
        
        for(int i = 0; i < RB.size(); i++){
            if(RB[i] != _RB[i + rank*pB.size()]){
               printf("Error %d,%d,%d, (%lld,%lld),(%lld,%lld)\n",rank,i,RB.size(),RA[i].real,RA[i].img,_RA[i + rank*pB.size()].real,_RA[i + rank*pB.size()].img);
            }
        }
        
        for(int i = 0; i < RC.size(); i++){
            if(RC[i] != _RC[i + rank*pC.size()]){
               printf("Error %d,%d,%d, (%lld,%lld),(%lld,%lld)\n",rank,i,RC.size(),RA[i].real,RA[i].img,_RA[i + rank*pB.size()].real,_RA[i + rank*pB.size()].img);
            }
        }
        if(evaluate_vector(_RA,r2) != Y[0]){
            printf("Error 1\n");
        }
        if(evaluate_vector(_RB,r2) != Y[1]){
            printf("Error 2\n");
        }
        if(evaluate_vector(_RC,r2) != Y[2]){
            printf("Error 3\n");
        }
      
    MPI_Barrier(MPI_COMM_WORLD);
    pt.start();
    //_prove_sparse_eval(a*Y[0]+b*Y[1]+c*Y[2], a, b, c, beta1, beta2, index,r1,r2, N);
    _prove_sparse_eval_opt(a*Y[0]+b*Y[1]+c*Y[2], a, b, c, beta1, beta2, index, r1, r2, N);
    pt.end();
    printf("%lf\n",pt.get_time());
}

void test_mult_tree(vector<int> dims, int N){
    int rank,size = 0;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<F> output;
    for(int i = 0; i < dims.size(); i++) size += dims[i];
    vector<vector<F>> input;
    vector<F> prod(dims.size(),F(1));
    if(rank == 0){
        vector<vector<vector<F>>> data(N);
        for(int i = 0; i < N; i++){
            data[i].resize(dims.size());
            for(int j = 0; j < dims.size(); j++){
                data[i][j] = generate_randomness(dims[j]/N);
                for(int k = 0; k < data[i][j].size(); k++) prod[j] *= data[i][j][k];
            }
        }
        input = data[0];
        distribute_data_tensor(data);
    }else{
        vector<F> v;
        get_data(v,size/N);
        input.resize(dims.size());
        int ctr = 0;
        for(int i = 0; i < dims.size(); i++){
            input[i].resize(dims[i]/N);
            for(int j = 0; j < input[i].size(); j++) input[i][j] = v[ctr++];
        }
    }
    //prove_product_opt(input, output, N);
    if(rank == 0){
        for(int i = 0; i < output.size(); i++){
            if(output[i] != prod[i]){
                printf("Error %d\n",i);
            }
        }
    }
}



int main(int argc, char *argv[]){
    
    /*
    vector<F> w,vl,vr,vo,ra,rb,rc;
    generate_R1CS_matrixes(1<<atoi(argv[1]), 1);
    prepare_witness_data(1<<atoi(argv[1]),w,vl,vr,vo,1);
    vector<F> r = generate_randomness(logm);
    reduce_R1CS_matrixes(1<<atoi(argv[1]),r,ra,rb,rc);
    printf("%d, %d,%d\n",vl.size(),ra.size(),w.size());
    F a = random();
    F b = random();
    F c = random();
    
    F y = a*evaluate_vector(vl,r)+b*evaluate_vector(vr,r)+c*evaluate_vector(vo,r);
    for(int i = 0; i < rc.size(); i++){
        y -= (a*ra[i]+b*rb[i]+c*rc[i])*w[i];
    }
    
    if(y != F(0)) printf("Error\n");
    exit(-1);
    */
    
    const bool standalone_transfer_judge = argc > 1 &&
        std::string(argv[1]) == "--pvia-transfer-judge";
    const bool standalone_robust_abort_judge = argc > 1 &&
        std::string(argv[1]) == "--pvia-robust-abort-judge";
    const bool standalone_preprocess_fill = argc > 1 &&
        std::string(argv[1]) == "--pvia-preprocess-fill";
    const bool standalone_preprocess_consume = argc > 1 &&
        std::string(argv[1]) == "--pvia-preprocess-consume";
    const bool standalone_relation_cache_fill = argc > 1 &&
        std::string(argv[1]) == "--pvia-relation-cache-fill";
    const bool standalone_sp1_recovery_envelope = argc > 1 &&
        std::string(argv[1]) == "--pvia-sp1-vss-recovery-proof-envelope-selftest";
    const bool standalone_sp1_recovery_verifier = argc > 1 &&
        std::string(argv[1]) == "--pvia-sp1-vss-recovery-proof-verifier-selftest";
    const char* composition_readiness_selftest_env =
        std::getenv("PVIA_SECURE_AUDIT_COMPOSITION_READINESS_SELFTEST");
    const bool run_composition_readiness_selftest =
        composition_readiness_selftest_env &&
        std::string(composition_readiness_selftest_env) != "0";
    const bool standalone_judge =
        standalone_transfer_judge || standalone_robust_abort_judge;
    const bool standalone_utility =
        standalone_judge || standalone_preprocess_fill ||
        standalone_preprocess_consume ||
        standalone_relation_cache_fill || standalone_sp1_recovery_envelope ||
        standalone_sp1_recovery_verifier || run_composition_readiness_selftest;
    int benchmark = standalone_utility ? 0 : (argc > 1 ? atoi(argv[1]) : 0);
    // The native DSC quadratic probe is captured inside the optimized
    // sparse-evaluation path; it must not force the legacy coPIOP path.
    int size;
    int rank;
    


    //encode_locally(C,R_shares,500,N,M,k,_k);
    const char* ulfm_crash_recovery_env =
        std::getenv("PVIA_GOD_OUTPUT_CRASH_RECOVERY_N4_SELFTEST");
    const bool run_ulfm_crash_recovery_selftest =
        ulfm_crash_recovery_env && std::string(ulfm_crash_recovery_env) != "0";
    const char* god_bundle_crash_env =
        std::getenv("PVIA_GOD_OUTPUT_BUNDLE_N4_CRASH_RECOVERY_SELFTEST");
    const char* god_bundle_test_env =
        std::getenv("PVIA_GOD_OUTPUT_BUNDLE_N4_SELFTEST");
    const bool run_ulfm_bundle_crash_selftest =
        god_bundle_crash_env && std::string(god_bundle_crash_env)!="0" &&
        god_bundle_test_env && std::string(god_bundle_test_env)!="0";
    if (run_ulfm_crash_recovery_selftest ||
        run_ulfm_bundle_crash_selftest) {
        int thread_provided = MPI_THREAD_SINGLE;
        MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &thread_provided);
        if (thread_provided < MPI_THREAD_MULTIPLE) {
            std::cerr << "PVIA ULFM selftest requires MPI_THREAD_MULTIPLE" << std::endl;
            _exit(6);
        }
    } else {
        MPI_Init (&argc, &argv);
    }

    MPI_Comm_size(MPI_COMM_WORLD, &size); //get number of processes
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id

    if (run_composition_readiness_selftest) {
        const int local_ok =
            pvia::run_secure_audit_composition_readiness_selftest() ? 1 : 0;
        int global_ok = 0;
        MPI_Allreduce(&local_ok, &global_ok, 1, MPI_INT, MPI_MIN,
                      MPI_COMM_WORLD);
        if (rank == 0) {
            std::cout << "[PVIA][secure-audit-composition-readiness-selftest] "
                      << (global_ok ? "PASS" : "FAIL")
                      << " ranks=" << size
                      << " private_fail_closed=1 transfer_fail_closed=1"
                      << " recovery_verifier_checked=1"
                      << std::endl;
        }
        MPI_Finalize();
        return global_ok ? 0 : 7;
    }

    if (run_ulfm_crash_recovery_selftest) {
        const bool recovered =
            pvia::run_reference_god_output_crash_recovery_n4_selftest(rank, size);
        const char* finalize_probe =
            std::getenv("PVIA_GOD_OUTPUT_CRASH_RECOVERY_TRY_FINALIZE");
        if (finalize_probe && std::string(finalize_probe) != "0") {
            // The PRTE launcher can lose one rank's final stderr line after
            // an injected crash. Persist two fsync'ed markers to distinguish
            // a real MPI_Finalize hang from late log transport loss.
            const char* evidence_dir=std::getenv("PVIA_GOD_FINALIZE_EVIDENCE_DIR");
            auto write_finalize_marker=[&](const char* phase, int rc)->bool {
                if(!evidence_dir || !*evidence_dir)return true;
                const std::string filename=std::string(evidence_dir)+
                    "/mpi_finalize_rank"+std::to_string(rank)+
                    "_"+phase+".txt";
                const int fd=::open(filename.c_str(),O_WRONLY|O_CREAT|O_TRUNC,0600);
                if(fd<0)return false;
                const std::string data="original_rank="+std::to_string(rank)+
                    " phase="+phase+" rc="+std::to_string(rc)+
                    " recovery="+(recovered?"PASS":"FAIL")+"\n";
                size_t offset=0;
                bool ok=true;
                while(offset<data.size()) {
                    const ssize_t n=::write(fd,data.data()+offset,data.size()-offset);
                    if(n<=0){ok=false;break;}
                    offset+=static_cast<size_t>(n);
                }
                if(::fsync(fd)!=0)ok=false;
                if(::close(fd)!=0)ok=false;
                return ok;
            };
            const bool before_recorded=write_finalize_marker("enter",-1);
            const int finalize_rc=MPI_Finalize();
            const bool after_recorded=write_finalize_marker("return",finalize_rc);
            std::cerr << "[PVIA][god-output-crash-recovery-n4] "
                      << "MPI_FINALIZE_AFTER_FAILURE rank=" << rank
                      << " status=" << (finalize_rc == MPI_SUCCESS ? "PASS" : "FAIL")
                      << " rc=" << finalize_rc
                      << " durable_trace="<<((before_recorded&&after_recorded)?"PASS":"FAIL")
                      << std::endl;
            return recovered && finalize_rc == MPI_SUCCESS &&
                before_recorded && after_recorded ? 0 : 5;
        }
        _exit(recovered ? 0 : 5);
    }

    // Public-only independent verifier: requires BOTH caller-provided
    // expected statement and public-key registry pins. MPI is initialized
    // for the existing binary but no collective/witness input is used.
    if (argc > 1 && std::string(argv[1]) == "--pvia-reg-pair-verify") {
        pvia::Digest statement_pin{};
        pvia::Digest registry_pin{};
        const bool accepted =
            argc == 5 &&
            pvia::parse_registration_public_digest_hex(
                argv[3], &statement_pin) &&
            pvia::parse_registration_public_digest_hex(
                argv[4], &registry_pin) &&
            pvia::verify_registration_public_origin_bundle_file(
                argv[2], statement_pin, registry_pin, 0, true);
        if (rank == 0)
            std::cout << "PVIA_REG_PUBLIC_PAIR_VERIFY: "
                      << (accepted ? "PASS" : "REJECT")
                      << " scope=PUBLIC_ONLY_EXPECTED_PINS_EXTERNAL"
                      << " native_share_equality=NOT_ATTESTED"
                      << std::endl;
        MPI_Finalize();
        return accepted ? 0 : 43;
    }

    // Public issuer declaration: statement and roster must first be
    // verified with external pins. No private witness or issuer secret.
    if (argc > 1 &&
        (std::string(argv[1])=="--pvia-reg-issuer-verify" ||
         std::string(argv[1])=="--pvia-reg-issuer-source-verify")) {
        const bool source_only =
            std::string(argv[1])=="--pvia-reg-issuer-source-verify";
        pvia::Digest expected_statement{}, expected_registry{};
        pvia::Digest expected_consumed{};
        std::array<uint8_t, 32> issuer_key{};
        pvia::RegistrationConsistencyStatement statement{};
        auto parse_positive_decimal = [](const char* text, u64* out) {
            if (!text || !*text || !out || *text=='0') return false;
            u64 value=0;
            for (const char* it=text; *it; ++it) {
                if (*it<'0' || *it>'9') return false;
                const u64 digit=static_cast<u64>(*it-'0');
                if (value>(UINT64_MAX-digit)/10) return false;
                value=value*10+digit;
            }
            if (!value) return false;
            *out=value;
            return true;
        };
        u64 expected_id=0, minimum_sequence=0;
        const bool accepted = argc==10 &&
            pvia::parse_registration_public_digest_hex(
                argv[4],&expected_statement) &&
            pvia::parse_registration_public_digest_hex(
                argv[5],&expected_registry) &&
            pvia::parse_native_issuer_public_key_hex(
                argv[6],&issuer_key) &&
            pvia::parse_registration_public_digest_hex(
                argv[7],&expected_consumed) &&
            parse_positive_decimal(argv[8],&expected_id) &&
            parse_positive_decimal(argv[9],&minimum_sequence) &&
            pvia::read_registration_public_origin_statement_file(
                argv[2],&statement) &&
            statement.statement_binding==expected_statement &&
            pvia::verify_registration_public_origin_bundle_file(
                argv[2],expected_statement,expected_registry,0,true) &&
            (source_only ?
                pvia::verify_registration_native_issuer_public_file(
                    argv[3],statement,expected_consumed,issuer_key,
                    expected_id,minimum_sequence) :
                pvia::verify_registration_native_issuer_release_file(
                    argv[3],statement,expected_consumed,issuer_key,
                    expected_id,minimum_sequence));
        if (rank==0)
            std::cout << (source_only ?
                "PVIA_REG_PUBLIC_ISSUER_SOURCE_VERIFY: " :
                "PVIA_REG_PUBLIC_ISSUER_VERIFY: ")
                      << (accepted ? "PASS" : "REJECT")
                      << " scope=PUBLIC_ISSUER_ASSERTION_ONLY"
                      << " native_share_equality=NOT_ATTESTED"
                      << std::endl;
        MPI_Finalize();
        return accepted ? 0 : 46;
    }

    if (argc == 3 &&
        std::string(argv[1]) ==
            "--pvia-live-native-real-batch-public-verify") {
        const bool passed =
            pvia::verify_live_native_real_batch_public_fixture(argv[2]);
        if (rank == 0)
            std::cout << "PVIA_REAL_NATIVE_BATCH_PUBLIC_VERIFY: "
                      << (passed ? "PASS" : "REJECT")
                      << " scope=DECLARED_PUBLIC_MATERIAL_ONLY"
                      << " authenticated_private_share=NOT_ATTESTED"
                      << " signature_and_binding=CHECKED" << std::endl;
        MPI_Finalize();
        return passed ? 0 : 52;
    }
    if (argc == 2 &&
        std::string(argv[1]) == "--pvia-live-native-batch-binding-selftest") {
        const bool passed =
            pvia::run_live_native_source_batch_binding_selftest();
        if (rank == 0)
            std::cout << "PVIA_LIVE_NATIVE_BATCH_BINDING_SELFTEST: "
                      << (passed ? "PASS" : "FAIL")
                      << " operations=2 canonical_order=CHECKED"
                      << " incomplete_duplicate_foreign=REJECTED"
                      << " binding_change=DETECTED PVNPIN02=SIGNED_ROUNDTRIP"
                      << " malformed_files=REJECTED"
                      << " identity_scope_partition_key=REJECTED"
                      << std::endl;
        MPI_Finalize();
        return passed ? 0 : 51;
    }

    // Isolated MPI crypto regression only: ephemeral Ed25519 test keys.
    if (argc == 2 && std::string(argv[1]) == "--pvia-reg-origin-selftest") {
        const bool passed = pvia::run_registration_origin_endorsement_selftest(
            rank, size);
        MPI_Finalize();
        return passed ? 0 : 39;
    }

    if (argc == 3 &&
        (std::string(argv[1]) == "--pvia-replay-ledger-probe" ||
         std::string(argv[1]) == "--pvia-replay-ledger-probe-alt")) {
        const bool changed_claim =
            std::string(argv[1]) == "--pvia-replay-ledger-probe-alt";
        const bool reserved =
            pvia::run_registration_replay_ledger_persistence_probe(
                argv[2], changed_claim);
        if (rank == 0)
            std::cout << "PVIA_REPLAY_PROBE: "
                      << (reserved ? "CONSUMED" : "REJECTED")
                      << " mode=PUBLIC_TEST_LEDGER_ONLY" << std::endl;
        MPI_Finalize();
        return reserved ? 0 : 42;
    }

    if (standalone_sp1_recovery_envelope) {
        const bool local_passed = rank == 0
            ? pvia::run_sp1_vss_recovery_proof_envelope_selftest()
            : true;
        const int local_value = local_passed ? 1 : 0;
        int global_value = 0;
        MPI_Allreduce(&local_value, &global_value, 1, MPI_INT, MPI_MIN,
                      MPI_COMM_WORLD);
        MPI_Finalize();
        return global_value == 1 ? 0 : 50;
    }

    if (standalone_sp1_recovery_verifier) {
        const bool local_passed = rank == 0
            ? pvia::run_sp1_vss_recovery_proof_verifier_selftest()
            : true;
        const int local_value = local_passed ? 1 : 0;
        int global_value = 0;
        MPI_Allreduce(&local_value, &global_value, 1, MPI_INT, MPI_MIN,
                      MPI_COMM_WORLD);
        MPI_Finalize();
        return global_value == 1 ? 0 : 49;
    }

    if (argc == 4 &&
        std::string(argv[1]) == "--pvia-vss-cross-process-recovery-selftest") {
        const bool local_passed =
            pvia::run_reference_vss_cross_process_recovery_selftest(
                rank, size, argv[2], argv[3]);
        const int local_value = local_passed ? 1 : 0;
        int global_value = 0;
        MPI_Allreduce(&local_value, &global_value, 1, MPI_INT, MPI_MIN,
                      MPI_COMM_WORLD);
        MPI_Finalize();
        return global_value == 1 ? 0 : 54;
    }

    if (argc == 2 &&
        std::string(argv[1]) == "--pvia-vss-replay-head-anchor-selftest") {
        const bool local_passed = rank == 0
            ? pvia::run_reference_vss_replay_head_anchor_selftest()
            : true;
        const int local_value = local_passed ? 1 : 0;
        int global_value = 0;
        MPI_Allreduce(&local_value, &global_value, 1, MPI_INT, MPI_MIN,
                      MPI_COMM_WORLD);
        MPI_Finalize();
        return global_value == 1 ? 0 : 53;
    }

    if (argc == 3 &&
        std::string(argv[1]) == "--pvia-vss-external-anchor-selftest") {
        const bool passed =
            pvia::run_reference_vss_external_anchor_selftest(
                rank, size, argv[2]);
        const int local_value = passed ? 1 : 0;
        int global_value = 0;
        MPI_Allreduce(&local_value, &global_value, 1, MPI_INT, MPI_MIN,
                      MPI_COMM_WORLD);
        MPI_Finalize();
        return global_value == 1 ? 0 : 56;
    }

    if (argc == 4 && std::string(argv[1]) == "--pvia-vss-selective-process-restart-selftest") {
        const bool passed = pvia::run_reference_vss_selective_point_process_restart_selftest(rank,size,argv[2],argv[3]);
        MPI_Finalize();
        return passed ? 0 : 55;
    }

    if (argc == 2 &&
        std::string(argv[1]) == "--pvia-vss-selective-point-selftest") {
        const bool passed=
            pvia::run_reference_vss_selective_point_selftest(rank,size);
        MPI_Finalize();
        return passed ? 0 : 48;
    }

    if (argc == 2 &&
        std::string(argv[1]) == "--pvia-reg-distributed-row-selftest") {
        const bool passed=
            pvia::run_reference_distributed_row_registration_selftest(
                rank,size);
        MPI_Finalize();
        return passed ? 0 : 47;
    }

    if (argc == 2 && std::string(argv[1]) == "--pvia-reg-preprove-selftest") {
        const bool passed = pvia::run_registration_origin_preprove_gate_selftest(
            rank, size);
        MPI_Finalize();
        return passed ? 0 : 40;
    }

    if (standalone_relation_cache_fill) {
        bool prepared = false;
        size_t circuit_size = 0;
        int circuit_type = 0;
        int target_world = 0;
        std::string cache_path;
        if (size == 1 && argc == 6) {
            try {
                const unsigned long long parsed_size =
                    std::stoull(argv[2], nullptr, 0);
                const long long parsed_type =
                    std::stoll(argv[3], nullptr, 0);
                const long long parsed_world =
                    std::stoll(argv[4], nullptr, 0);
                if (parsed_size > 0 &&
                    parsed_size <=
                        std::numeric_limits<size_t>::max() &&
                    parsed_type >= 0 &&
                    parsed_type <=
                        std::numeric_limits<int>::max() &&
                    parsed_world >= 4 &&
                    parsed_world <=
                        std::numeric_limits<int>::max()) {
                    circuit_size =
                        static_cast<size_t>(parsed_size);
                    circuit_type =
                        static_cast<int>(parsed_type);
                    target_world =
                        static_cast<int>(parsed_world);
                    cache_path = argv[5];
                }
            } catch (...) {
                circuit_size = 0;
            }
        }

        const bool world_shape_ok =
            target_world >= 4 &&
            (target_world & (target_world - 1)) == 0 &&
            target_world % 4 == 0;
        if (size == 1 && circuit_size != 0 &&
            world_shape_ok && !cache_path.empty()) {
            generate_R1CS_matrixes(
                circuit_size, circuit_type);
            if (logm >= 0 && logm < 63 &&
                logn >= 0 && logn < 63) {
                const size_t witness_slots =
                    static_cast<size_t>(1ULL << logn);
                const size_t constraint_slots =
                    static_cast<size_t>(1ULL << logm);
                const int target_k = target_world / 4;
                const int target_packed = target_world / 2;
                pvia::Digest relation_binding{};
                prepared =
                    pvia::write_initial_validity_relation_cache(
                        cache_path, tA, tB, tC,
                        target_world, target_k,
                        target_packed, witness_slots,
                        constraint_slots,
                        &relation_binding);
            }
        }

        if (rank == 0) {
            if (argc != 6 || size != 1) {
                std::cerr
                    << "usage: pigeon --pvia-relation-cache-fill "
                    << "<circuit-size> <circuit-type> "
                    << "<target-world-size> <cache-file>\n"
                    << "run this public setup utility with one MPI rank\n";
            }
            std::cout << "[PVIA][relation-cache-fill] "
                      << (prepared ? "PASS" : "FAIL")
                      << " circuit_size=" << circuit_size
                      << " circuit_type=" << circuit_type
                      << " target_world=" << target_world
                      << " file=" << cache_path << "\n";
        }
        MPI_Finalize();
        return prepared ? 0 : 11;
    }

    if (standalone_preprocess_fill) {
        bool prepared = false;
        size_t share_count = 0;
        int packed_k = 0;
        int packed_width = 0;
        uint64_t domain = 0;
        uint64_t slot = 0;
        std::string directory;
        if (argc == 8) {
            try {
                const unsigned long long count =
                    std::stoull(argv[2], nullptr, 0);
                const long long parsed_k =
                    std::stoll(argv[3], nullptr, 0);
                const long long parsed_packed =
                    std::stoll(argv[4], nullptr, 0);
                domain = std::stoull(argv[5], nullptr, 0);
                slot = std::stoull(argv[6], nullptr, 0);
                if (count > 0 &&
                    count <= std::numeric_limits<size_t>::max() &&
                    parsed_k > 0 &&
                    parsed_k <= std::numeric_limits<int>::max() &&
                    parsed_packed > 0 &&
                    parsed_packed <= std::numeric_limits<int>::max()) {
                    share_count = static_cast<size_t>(count);
                    packed_k = static_cast<int>(parsed_k);
                    packed_width = static_cast<int>(parsed_packed);
                    directory = argv[7];
                }
            } catch (...) {
                share_count = 0;
            }
        }

        if (share_count != 0 && domain != 0 && !directory.empty()) {
            // The fill utility must always create fresh randomness.  Ignore a
            // surrounding shell's consume setting rather than accidentally
            // copying an already-consumed pool slot.
            ::unsetenv("PVIA_PREPROCESS_POOL_CONSUME");
            std::vector<F> local_share;
            pvia::JointPackedPreprocessingResult prep;
            const bool generated =
                pvia::generate_joint_packed_random_share(
                    share_count, size, packed_k, packed_width,
                    domain, &local_share, &prep, MPI_COMM_WORLD);
            const bool stored = generated && prep.ok &&
                pvia::write_joint_packed_preprocessing_slot(
                    directory, slot, share_count, size,
                    packed_k, packed_width, domain, local_share,
                    MPI_COMM_WORLD);
            int local_ok = stored ? 1 : 0;
            int global_ok = 0;
            MPI_Allreduce(
                &local_ok, &global_ok, 1, MPI_INT, MPI_MIN,
                MPI_COMM_WORLD);
            prepared = global_ok == 1;
        }

        if (rank == 0) {
            if (argc != 8) {
                std::cerr
                    << "usage: pigeon --pvia-preprocess-fill "
                    << "<share-count> <k> <packed-width> <domain> "
                    << "<slot> <directory>\n";
            }
            std::cout << "[PVIA][preprocess-fill] "
                      << (prepared ? "PASS" : "FAIL")
                      << " count=" << share_count
                      << " world=" << size
                      << " k=" << packed_k
                      << " packed=" << packed_width
                      << " domain=" << domain
                      << " slot=" << slot << "\n";
        }
        MPI_Finalize();
        return prepared ? 0 : 9;
    }

    if (standalone_preprocess_consume) {
        bool consumed = false;
        size_t share_count = 0;
        int packed_k = 0;
        int packed_width = 0;
        uint64_t domain = 0;
        uint64_t slot = 0;
        std::string directory;
        if (argc == 8) {
            try {
                const unsigned long long count =
                    std::stoull(argv[2], nullptr, 0);
                const long long parsed_k =
                    std::stoll(argv[3], nullptr, 0);
                const long long parsed_packed =
                    std::stoll(argv[4], nullptr, 0);
                domain = std::stoull(argv[5], nullptr, 0);
                slot = std::stoull(argv[6], nullptr, 0);
                if (count > 0 &&
                    count <= std::numeric_limits<size_t>::max() &&
                    parsed_k > 0 &&
                    parsed_k <= std::numeric_limits<int>::max() &&
                    parsed_packed > 0 &&
                    parsed_packed <= std::numeric_limits<int>::max()) {
                    share_count = static_cast<size_t>(count);
                    packed_k = static_cast<int>(parsed_k);
                    packed_width = static_cast<int>(parsed_packed);
                    directory = argv[7];
                }
            } catch (...) {
                share_count = 0;
            }
        }

        if (share_count != 0 && domain != 0 && !directory.empty()) {
            const std::string slot_text = std::to_string(slot);
            ::setenv("PVIA_PREPROCESS_POOL_CONSUME", "1", 1);
            ::setenv(
                "PVIA_PREPROCESS_POOL_DIR", directory.c_str(), 1);
            ::setenv(
                "PVIA_PREPROCESS_POOL_SLOT", slot_text.c_str(), 1);
            std::vector<F> local_share;
            pvia::JointPackedPreprocessingResult prep;
            const bool loaded =
                pvia::generate_joint_packed_random_share(
                    share_count, size, packed_k, packed_width,
                    domain, &local_share, &prep, MPI_COMM_WORLD);
            int local_ok =
                loaded && prep.ok &&
                local_share.size() == share_count ? 1 : 0;
            int global_ok = 0;
            MPI_Allreduce(
                &local_ok, &global_ok, 1, MPI_INT, MPI_MIN,
                MPI_COMM_WORLD);
            consumed = global_ok == 1;
        }

        if (rank == 0) {
            if (argc != 8) {
                std::cerr
                    << "usage: pigeon --pvia-preprocess-consume "
                    << "<share-count> <k> <packed-width> <domain> "
                    << "<slot> <directory>\n";
            }
            std::cout << "[PVIA][preprocess-consume] "
                      << (consumed ? "PASS" : "FAIL")
                      << " count=" << share_count
                      << " world=" << size
                      << " k=" << packed_k
                      << " packed=" << packed_width
                      << " domain=" << domain
                      << " slot=" << slot << "\n";
        }
        MPI_Finalize();
        return consumed ? 0 : 10;
    }

    if (standalone_transfer_judge) {
        bool accepted = false;
        if (size == 1 && argc == 5) {
            std::vector<u64> encoded;
            pvia::Digest anchor_digest{};
            uint64_t sid = 0;
            try { sid = std::stoull(argv[3]); } catch (...) { sid = 0; }
            if (sid != 0 &&
                pvia::read_public_transfer_blame_certificate_file(
                    argv[2], &encoded) &&
                pvia::parse_public_transfer_registry_anchor_hex(
                    argv[4], &anchor_digest)) {
                accepted = pvia::Ed25519PublicTransferJudge::VerifyEncoded(
                    encoded, sid, anchor_digest);
            }
        }
        if (rank == 0) {
            if (argc != 5)
                std::cerr << "usage: pigeon --pvia-transfer-judge "
                          << "<certificate-file> <session-id> "
                          << "<registry-anchor-hex>\n";
            else if (size != 1)
                std::cerr << "[PVIA][standalone-judge] requires exactly one MPI rank\n";
            std::cout << "[PVIA][standalone-judge] "
                      << (accepted ? "ACCEPT" : "REJECT") << "\n";
        }
        MPI_Finalize();
        return accepted ? 0 : 7;
    }

    if (standalone_robust_abort_judge) {
        bool accepted = false;
        bool benchmark_requested = false;
        uint64_t benchmark_repeats = 1;
        uint64_t benchmark_completed = 0;
        uint64_t benchmark_total_ns = 0;
        size_t benchmark_certificate_bytes = 0;
        const char* benchmark_env =
            std::getenv("PVIA_ROBUST_ABORT_JUDGE_BENCHMARK_REPEATS");
        if (benchmark_env && *benchmark_env) {
            benchmark_requested = true;
            try { benchmark_repeats = std::stoull(benchmark_env); }
            catch (...) { benchmark_repeats = 1; }
            if (benchmark_repeats == 0) benchmark_repeats = 1;
            if (benchmark_repeats > 1000000ULL) benchmark_repeats = 1000000ULL;
        }
        if (size == 1 && argc == 4) {
            std::vector<u64> encoded;
            pvia::Digest anchor_digest{};
            if (pvia::read_robust_audit_abort_certificate_file(
                    argv[2], &encoded) &&
                pvia::parse_robust_audit_registry_anchor_hex(
                    argv[3], &anchor_digest)) {
                benchmark_certificate_bytes = encoded.size() * sizeof(u64);
                if (!benchmark_requested) {
                    accepted =
                        pvia::verify_encoded_robust_audit_abort_certificate(
                            encoded, anchor_digest);
                } else {
                    accepted = true;
                    const auto start = std::chrono::steady_clock::now();
                    for (uint64_t i = 0; i < benchmark_repeats; ++i) {
                        const bool verified =
                            pvia::verify_encoded_robust_audit_abort_certificate(
                                encoded, anchor_digest);
                        ++benchmark_completed;
                        if (!verified) { accepted = false; break; }
                    }
                    const auto end = std::chrono::steady_clock::now();
                    benchmark_total_ns = static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::nanoseconds>(
                            end - start).count());
                }
            }
        }
        if (rank == 0) {
            if (argc != 4)
                std::cerr << "usage: pigeon --pvia-robust-abort-judge "
                          << "<certificate-file> <registry-anchor-hex>\n";
            else if (size != 1)
                std::cerr << "[PVIA][robust-abort-judge] requires exactly one MPI rank\n";
            if (benchmark_requested && benchmark_completed > 0) {
                std::cout << "[PVIA][robust-abort-judge-benchmark] repeats="
                          << benchmark_repeats
                          << " completed=" << benchmark_completed
                          << " total_ns=" << benchmark_total_ns
                          << " mean_ns="
                          << (benchmark_total_ns / benchmark_completed)
                          << " canonical_bytes="
                          << benchmark_certificate_bytes << "\n";
            }
            std::cout << "[PVIA][robust-abort-judge] "
                      << (accepted ? "ACCEPT" : "REJECT") << "\n";
        }
        MPI_Finalize();
        return accepted ? 0 : 8;
    }

    const char* transfer_selftest_env = std::getenv("PVIA_TRANSFER_SELFTEST");
    const bool transfer_selftest = transfer_selftest_env &&
        std::string(transfer_selftest_env) != "0";
    const char* transfer_no_framing_selftest_env =
        std::getenv("PVIA_TRANSFER_NO_FRAMING_SELFTEST");
    const bool transfer_no_framing_selftest =
        transfer_no_framing_selftest_env &&
        std::string(transfer_no_framing_selftest_env) != "0";
    bool transfer_no_framing_selftest_ok = true;
    const char* fold_runtime_selftest_env =
        std::getenv("PVIA_FOLD_RUNTIME_SELFTEST");
    const bool fold_runtime_selftest = fold_runtime_selftest_env &&
        std::string(fold_runtime_selftest_env) != "0";
    const char* native_sumcheck_runtime_selftest_env =
        std::getenv("PVIA_NATIVE_SUMCHECK_RUNTIME_SELFTEST");
    const bool native_sumcheck_runtime_selftest =
        native_sumcheck_runtime_selftest_env &&
        std::string(native_sumcheck_runtime_selftest_env) != "0";
    const char* sp1_secure_backend_bridge_env =
        std::getenv("PVIA_SP1_SUMCHECK_SECURE_BACKEND_BRIDGE");
    const bool sp1_secure_backend_bridge =
        sp1_secure_backend_bridge_env &&
        std::string(sp1_secure_backend_bridge_env) != "0";
    const char* shamir_fold_runtime_selftest_env =
        std::getenv("PVIA_SHAMIR_FOLD_RUNTIME_SELFTEST");
    const bool shamir_fold_runtime_selftest =
        shamir_fold_runtime_selftest_env &&
        std::string(shamir_fold_runtime_selftest_env) != "0";
    const char* native_runtime_source_capture_env =
        std::getenv("PVIA_P105_NATIVE_SOURCE_CAPTURE");
    const bool native_runtime_source_capture =
        native_runtime_source_capture_env &&
        std::string(native_runtime_source_capture_env) != "0";
    const char* native_runtime_source_capture_stop_env =
        std::getenv("PVIA_P105_NATIVE_SOURCE_CAPTURE_STOP_AFTER_FIRST");
    const bool native_runtime_source_capture_stop =
        native_runtime_source_capture_stop_env &&
        std::string(native_runtime_source_capture_stop_env) != "0";
    const char* passive_observer_env =
        std::getenv("PVIA_P105_NATIVE_SOURCE_OBSERVER");
    const bool passive_observer = passive_observer_env &&
        std::string(passive_observer_env) != "0";
    const char* passive_stop_env =
        std::getenv("PVIA_P105_NATIVE_SOURCE_OBSERVER_STOP_AFTER_FIRST");
    const bool passive_stop = passive_stop_env &&
        std::string(passive_stop_env) != "0";
    const char* strict_residual_provenance_env =
        std::getenv("PVIA_P105_REQUIRE_PRIVATE_RESIDUAL_PROVENANCE");
    const bool strict_residual_provenance =
        strict_residual_provenance_env &&
        std::string(strict_residual_provenance_env) != "0";
    const char* strict_gate_matrix_selftest_env =
        std::getenv("PVIA_RELEASE_GATE_MATRIX_SELFTEST");
    const bool strict_gate_matrix_selftest =
        strict_gate_matrix_selftest_env &&
        std::string(strict_gate_matrix_selftest_env) != "0";
    const char* strict_gate_disabled_selftest_env =
        std::getenv("PVIA_STRICT_GATE_DISABLED_SELFTEST");
    const bool strict_gate_disabled_selftest =
        strict_gate_disabled_selftest_env &&
        std::string(strict_gate_disabled_selftest_env) != "0";
    bool native_runtime_source_capture_ok = true;
    if (strict_residual_provenance && !strict_gate_matrix_selftest &&
        !strict_gate_disabled_selftest &&
        (!passive_observer || native_runtime_source_capture)) {
        if (rank == 0)
            std::cerr
                << "[PVIA][strict-residual-provenance] WITHHOLD: "
                << "strict issuer mode requires the passive observer and "
                << "capture mode disabled" << std::endl;
        MPI_Finalize();
        return 46;
    }
    if (passive_observer &&
        ((!passive_stop && !strict_residual_provenance) ||
         native_runtime_source_capture || transfer_selftest ||
         fold_runtime_selftest || shamir_fold_runtime_selftest ||
         native_sumcheck_runtime_selftest)) {
        if (rank == 0)
            std::cerr << "[PVIA][native-source-observer] "
                      << "requires dedicated observer and STOP_AFTER_FIRST=1"
                      << std::endl;
        MPI_Finalize();
        return 45;
    }
    if (native_runtime_source_capture &&
        !native_runtime_source_capture_stop) {
        if (rank == 0)
            std::cerr << "[PVIA][native-source-runtime-capture] "
                      << "requires PVIA_P105_NATIVE_SOURCE_CAPTURE_STOP_AFTER_FIRST=1; "
                      << "this mode does not certify a proof result" << std::endl;
        MPI_Finalize();
        return 44;
    }
    bool fold_runtime_selftest_ok = true;
    bool native_sumcheck_runtime_selftest_ok = true;
    bool shamir_fold_runtime_selftest_ok = true;
    bool sp1_secure_backend_bridge_ok = true;
    const char* secure_transfer_env = std::getenv("PVIA_SECURE_TRANSFER");
    const bool secure_transfer = secure_transfer_env &&
        std::string(secure_transfer_env) != "0";
    if (passive_observer && secure_transfer) {
        if (rank == 0)
            std::cerr << "[PVIA][native-source-observer] "
                      << "cannot share the development probe with secure transfer"
                      << std::endl;
        MPI_Finalize();
        return 45;
    }
    const char* secure_transfer_anchor_env =
        std::getenv("PVIA_SECURE_TRANSFER_REQUIRE_ANCHOR");
    const bool secure_transfer_require_anchor = secure_transfer_anchor_env &&
        std::string(secure_transfer_anchor_env) != "0";
    const char* secure_transfer_selftest_env = std::getenv("PVIA_SECURE_TRANSFER_SELFTEST");
    const bool secure_transfer_selftest = secure_transfer_selftest_env &&
        std::string(secure_transfer_selftest_env) != "0";
    bool secure_transfer_selftest_ok = true;
    if (secure_transfer_selftest && !secure_transfer) {
        if (rank == 0) std::cerr << "[PVIA] PVIA_SECURE_TRANSFER_SELFTEST requires PVIA_SECURE_TRANSFER=1\n";
        MPI_Finalize();
        return 4;
    }
    if ((transfer_selftest && secure_transfer) ||
        ((fold_runtime_selftest || shamir_fold_runtime_selftest) &&
         (transfer_selftest || secure_transfer)) ||
        (native_runtime_source_capture &&
         (transfer_selftest || secure_transfer ||
          fold_runtime_selftest || shamir_fold_runtime_selftest ||
          native_sumcheck_runtime_selftest)) ||
        (sp1_secure_backend_bridge &&
         (transfer_selftest || secure_transfer || fold_runtime_selftest ||
          shamir_fold_runtime_selftest || native_runtime_source_capture ||
          passive_observer || native_sumcheck_runtime_selftest))) {
        if (rank == 0)
            std::cerr << "[PVIA] audit runtime selftests/backends are mutually exclusive\n";
        MPI_Finalize();
        return 2;
    }
    pvia::Ed25519TransferAuditHarness transfer_harness;
    // Strict native release-gate runs also activate the existing reference
    // Shamir checkpoint check, so its joint-randomness fingerprint and masked
    // zero-test are a prerequisite for release rather than a detached selftest.
    const bool native_strict_mpc_gate =
        (passive_observer || native_runtime_source_capture) &&
        strict_residual_provenance;
    pvia::FoldResidualRuntimeHarness fold_runtime_harness(
        shamir_fold_runtime_selftest || native_strict_mpc_gate,
        native_runtime_source_capture);

    // Development bridge: the real SecureAuditBackend receives the native
    // relation callbacks and invokes the ordinary KernelResidualEvaluator
    // chain. No authenticated batch/recovery/blame engines are installed, so
    // Ready() remains false and the post-run release-gate probe must WITHHOLD.
    pvia::Sp1SumcheckProofProvider sp1_secure_backend_proof_provider;
    pvia::PrivateResidualShareStore sp1_secure_backend_residual_shares;
    pvia::NativeSumcheckResidualComputationBackend
        sp1_secure_backend_sumcheck_backend(
            sp1_secure_backend_residual_shares, nullptr,
            &sp1_secure_backend_proof_provider);
    pvia::NativeSumcheckKernelResidualEvaluator
        sp1_secure_backend_sumcheck_evaluator(
            sp1_secure_backend_sumcheck_backend);
    pvia::SecureAuditComponents sp1_secure_backend_components;
    sp1_secure_backend_components.kernel_evaluators.push_back(
        &sp1_secure_backend_sumcheck_evaluator);
    sp1_secure_backend_components.native_sumcheck_proof_provider =
        &sp1_secure_backend_proof_provider;
    pvia::ComposedSecureAuditProvider sp1_secure_backend_provider(
        sp1_secure_backend_components, true,
        pvia::RobustAuditSecurityLevel::MALICIOUS_GOD);
    pvia::SecureAuditBackend sp1_secure_backend(
        sp1_secure_backend_provider);
    pvia::SecureAuditRequirements sp1_secure_backend_requirements;
    sp1_secure_backend_requirements.private_lane = true;
    sp1_secure_backend_requirements.transfer_lane = false;
    sp1_secure_backend_requirements.private_security_level =
        pvia::RobustAuditSecurityLevel::MALICIOUS_GOD;
    sp1_secure_backend_requirements.required_kernels = {
        pvia::AuditRelationKernel::COSUMCHECK_ZERO,
        pvia::AuditRelationKernel::COSUMCHECK_QUADRATIC,
        pvia::AuditRelationKernel::COSUMCHECK_BATCH,
        pvia::AuditRelationKernel::DSC_QUADRATIC,
        pvia::AuditRelationKernel::DSC_CUBIC};

    pvia::Ed25519TransferSecureRuntime secure_transfer_runtime;
    if (transfer_selftest)
        pvia::Runtime::instance().set_audit_backend(&transfer_harness);
    if (fold_runtime_selftest || shamir_fold_runtime_selftest ||
        native_runtime_source_capture)
        pvia::Runtime::instance().set_audit_backend(&fold_runtime_harness);
    if (passive_observer &&
        !pvia::Runtime::instance().set_source_observer(
            &fold_runtime_harness)) {
        if (rank == 0)
            std::cerr << "[PVIA][native-source-observer] attach refused"
                      << std::endl;
        MPI_Finalize();
        return 45;
    }
    if (native_sumcheck_runtime_selftest &&
        !pvia::Runtime::instance().set_source_observer(
            &fold_runtime_harness)) {
        if (rank == 0)
            std::cerr << "[PVIA][native-sumcheck-runtime-selftest] "
                      << "source observer attach refused" << std::endl;
        MPI_Finalize();
        return 45;
    }
    if (sp1_secure_backend_bridge &&
        !pvia::Runtime::instance().set_source_observer(
            &sp1_secure_backend)) {
        if (rank == 0)
            std::cerr << "[PVIA][sp1-secure-backend-bridge] "
                      << "source callback attach refused" << std::endl;
        MPI_Finalize();
        return 47;
    }
    if (secure_transfer &&
        !secure_transfer_runtime.Attach(pvia::Runtime::instance())) {
        if (rank == 0)
            std::cerr << "[PVIA] failed to attach Ed25519 transfer-only secure composition\n";
        MPI_Finalize();
        return 3;
    }

    // Optional PVIA/PAAPS development runtime. Disabled unless PVIA_ENABLE=1.
    pvia::Runtime::instance().initialize_from_environment(rank, size);
    pvia::ReferenceVssExternalReleaseGate runtime_external_release_anchor;
    auto& pvia_runtime = pvia::Runtime::instance();
    if (pvia_runtime.external_release_anchor_required()) {
        bool local_anchor_config_ok = pvia_runtime.enabled();
        auto& transfer_auth =
            pvia::Ed25519TransferAuthenticator::instance();
        const pvia::Digest registry_binding =
            transfer_auth.RegistryCommitment();
        const char* transfer_key_pattern =
            std::getenv("PVIA_TRANSFER_PRIVATE_KEY_FILE");
        const bool stable_transfer_identity =
            transfer_key_pattern && *transfer_key_pattern &&
            std::string(transfer_key_pattern).find("{rank}") !=
                std::string::npos;
        local_anchor_config_ok = local_anchor_config_ok &&
            transfer_auth.ready() && registry_binding != pvia::Digest{} &&
            stable_transfer_identity;
        int local_anchor_config_word = local_anchor_config_ok ? 1 : 0;
        int global_anchor_config_word = 0;
        if (MPI_Allreduce(&local_anchor_config_word,
                          &global_anchor_config_word, 1, MPI_INT, MPI_MIN,
                          MPI_COMM_WORLD) != MPI_SUCCESS ||
            !global_anchor_config_word) {
            if (rank == 0)
                std::cerr << "[PVIA][external-release-anchor] WITHHOLD: "
                          << "PVIA runtime, authenticated registry, or persistent "
                          << "rank-specific transfer keys are unavailable"
                          << std::endl;
            pvia_runtime.shutdown();
            MPI_Finalize();
            return 48;
        }
        const bool anchor_initialized = runtime_external_release_anchor.Initialize(
            rank, size, pvia_runtime.session_id(), registry_binding);
        const bool anchor_attached =
            anchor_initialized && runtime_external_release_anchor.Attach(
                pvia_runtime);
        int local_anchor_attached = anchor_attached ? 1 : 0;
        int global_anchor_attached = 0;
        if (MPI_Allreduce(&local_anchor_attached, &global_anchor_attached, 1,
                          MPI_INT, MPI_MIN, MPI_COMM_WORLD) != MPI_SUCCESS ||
            !global_anchor_attached) {
            if (rank == 0)
                std::cerr << "[PVIA][external-release-anchor] WITHHOLD: "
                          << "remote Anchor initialization or attachment failed"
                          << std::endl;
            pvia_runtime.shutdown();
            MPI_Finalize();
            return 48;
        }
        if (rank == 0)
            std::cout << "[PVIA][external-release-anchor] READY"
                      << " generation=" << runtime_external_release_anchor.generation()
                      << " registry_bound=1"
                      << " resumed=" << (runtime_external_release_anchor.resumed() ? 1 : 0)
                      << std::endl;

        const char* anchor_gate_selftest_env =
            std::getenv("PVIA_EXTERNAL_RELEASE_ANCHOR_GATE_SELFTEST");
        const bool anchor_gate_selftest = anchor_gate_selftest_env &&
            std::string(anchor_gate_selftest_env) != "0";
        if (anchor_gate_selftest &&
            !runtime_external_release_anchor.RunGateSelfTest(
                pvia_runtime, rank, size)) {
            if (rank == 0)
                std::cerr << "[PVIA][external-release-anchor-gate-selftest] FAIL"
                          << std::endl;
            pvia_runtime.shutdown();
            MPI_Finalize();
            return 49;
        }
    }
    if (sp1_secure_backend_bridge &&
        !pvia::Runtime::instance().enabled()) {
        if (rank == 0)
            std::cerr << "[PVIA][sp1-secure-backend-bridge] "
                      << "requires PVIA_ENABLE=1" << std::endl;
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return 47;
    }
    if ((native_runtime_source_capture || passive_observer) &&
        !pvia::Runtime::instance().enabled()) {
        if (rank == 0)
            std::cerr << "[PVIA][native-source-runtime-capture] "
                      << "requires PVIA_ENABLE=1\\n";
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return 44;
    }
    const char* pq_signature_env =
        std::getenv("PVIA_REQUIRE_POST_QUANTUM_SIGNATURE");
    const char* hash_signature_env =
        std::getenv("PVIA_REQUIRE_HASH_BASED_SIGNATURE");
    const bool require_pq_signature = pq_signature_env &&
        std::string(pq_signature_env) != "0";
    const bool require_hash_signature = hash_signature_env &&
        std::string(hash_signature_env) != "0";
    if (pvia::Runtime::instance().enabled() &&
        (require_pq_signature || require_hash_signature)) {
        pvia::AccountabilitySignatureRequirements requirements;
        requirements.require_post_quantum = require_pq_signature;
        requirements.require_hash_based = require_hash_signature;
        requirements.allow_variable_length_signature = false;
        auto& auth = pvia::Ed25519TransferAuthenticator::instance();
        const auto capabilities = auth.SignatureCapabilities();
        if (!auth.ready() ||
            !pvia::accountability_signature_satisfies(capabilities, requirements)) {
            if (rank == 0)
                std::cerr << "[PVIA] requested accountability signature requirements are unavailable: "
                          << "post-quantum=" << (require_pq_signature ? "required" : "optional")
                          << " hash-based=" << (require_hash_signature ? "required" : "optional")
                          << "; current Ed25519 backend is development-only and not post-quantum.\n";
            if (secure_transfer) secure_transfer_runtime.Detach();
            pvia::Runtime::instance().shutdown();
            MPI_Finalize();
            return 16;
        }
    }
    const char* checkpoint_batch_selftest_env =
        std::getenv("PVIA_CHECKPOINT_BATCH_SELFTEST");
    const bool checkpoint_batch_selftest =
        checkpoint_batch_selftest_env &&
        std::string(checkpoint_batch_selftest_env) != "0";
    if (checkpoint_batch_selftest) {
        const bool checkpoint_batch_ok =
            pvia::run_checkpoint_batch_authentication_selftest(
                rank, size);
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return checkpoint_batch_ok ? 0 : 24;
    }

    if (strict_gate_disabled_selftest) {
        auto& strict_gate_runtime = pvia::Runtime::instance();
        strict_gate_runtime.begin_private_residual_provenance_gate(799);
        const bool denied = !strict_gate_runtime.pre_release_gate(
            "strict_provenance_with_pvia_disabled",
            pvia::Phase::FOLD, 799);
        int local = denied ? 1 : 0;
        int global = 0;
        MPI_Allreduce(&local, &global, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
        if (rank == 0)
            std::cout << "[PVIA][strict-gate-disabled-selftest] "
                      << "PVIA_ENABLE=0 pending-provenance="
                      << (denied ? "WITHHOLD" : "FAIL")
                      << " result=" << (global ? "PASS" : "FAIL") << "\n";
        strict_gate_runtime.shutdown();
        MPI_Finalize();
        return global ? 0 : 25;
    }

    const char* release_gate_matrix_env =
        std::getenv("PVIA_RELEASE_GATE_MATRIX_SELFTEST");
    const bool release_gate_matrix_selftest =
        release_gate_matrix_env &&
        std::string(release_gate_matrix_env) != "0";
    if (release_gate_matrix_selftest) {
        const bool gate_matrix_ok =
            pvia::run_release_gate_matrix_selftest(
                pvia::Runtime::instance(), rank, size);
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return gate_matrix_ok ? 0 : 23;
    }
    const char* activated_private_env =
        std::getenv("PVIA_P105_ACTIVATED_PRIVATE_SELFTEST");
    if(activated_private_env &&
       std::string(activated_private_env)!="0") {
        const bool ok=pvia::run_reference_activated_private_owner_selftest(
            rank,size);
        if(secure_transfer)secure_transfer_runtime.Detach();
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return ok?0:37;
    }
    const char* private_residual_env =
        std::getenv("PVIA_P105_PRIVATE_RESIDUAL_SELFTEST");
    if(private_residual_env &&
       std::string(private_residual_env)!="0") {
        const bool passed=pvia::run_reference_private_residual_flag_selftest(
            rank,size);
        if(secure_transfer)secure_transfer_runtime.Detach();
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return passed?0:36;
    }
    const char* private_owner_select_env =
        std::getenv("PVIA_P105_PRIVATE_OWNER_SELECTOR_SELFTEST");
    if(private_owner_select_env &&
       std::string(private_owner_select_env) != "0") {
        const bool passed=pvia::run_reference_private_owner_selection_selftest(
            rank,size);
        if (secure_transfer) secure_transfer_runtime.Detach();
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return passed ? 0 : 35;
    }
    const char* rs_e2e_selftest_env =
        std::getenv("PVIA_REFERENCE_RS_E2E_SELFTEST");
    if (rs_e2e_selftest_env &&
        std::string(rs_e2e_selftest_env) == "1") {
        const bool passed =
            pvia::run_reference_rs_e2e_selftest(
                pvia::Runtime::instance(), rank, size);
        if (secure_transfer) secure_transfer_runtime.Detach();
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return passed ? 0 : 48;
    }
    const char* rs_mul_selftest_env =
        std::getenv("PVIA_REFERENCE_RS_MUL_SELFTEST");
    if (rs_mul_selftest_env &&
        std::string(rs_mul_selftest_env) == "1") {
        const bool passed =
            pvia::run_reference_rs_multiplication_selftest(rank, size);
        if (secure_transfer) secure_transfer_runtime.Detach();
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return passed ? 0 : 47;
    }
    const char* reference_residual_mpc_selftest_env =
        std::getenv("PVIA_REFERENCE_RESIDUAL_MPC_SELFTEST");
    const bool reference_residual_mpc_selftest =
        reference_residual_mpc_selftest_env &&
        std::string(reference_residual_mpc_selftest_env) != "0";
    if (reference_residual_mpc_selftest &&
        !pvia::run_reference_residual_mpc_selftest(rank, size)) {
        if (secure_transfer) secure_transfer_runtime.Detach();
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return 15;
    }
    const char* reference_residual_exit_env =
        std::getenv("PVIA_REFERENCE_RESIDUAL_MPC_EXIT_AFTER_SELFTEST");
    if (reference_residual_mpc_selftest && reference_residual_exit_env &&
        std::string(reference_residual_exit_env) != "0") {
        if (secure_transfer) secure_transfer_runtime.Detach();
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return 0;
    }
    const char* localization_scaling_env =
        std::getenv("PVIA_LOCALIZATION_SCALING_Q");
    if (localization_scaling_env &&
        std::string(localization_scaling_env) != "0") {
        const long long q_value =
            std::strtoll(localization_scaling_env, nullptr, 10);
        const char* position_env =
            std::getenv("PVIA_LOCALIZATION_SCALING_FAULT");
        const std::string position =
            position_env ? std::string(position_env) : "first";
        const bool fault_last = position == "last";
        const int owner0_position = position == "owner0_first" ? 0 :
            position == "owner0_middle" ? 1 :
            position == "owner0_last" ? 2 : -1;
        const bool valid_position =
            position == "first" || fault_last || owner0_position >= 0;
        const bool scaling_ok =
            valid_position && q_value > 0 &&
            pvia::run_reference_residual_localization_benchmark(
                rank, size, static_cast<size_t>(q_value),
                fault_last, owner0_position);
        if (rank == 0 && !scaling_ok)
            std::cerr << "[PVIA][localization-scaling] FAILED\n";
        if (secure_transfer) secure_transfer_runtime.Detach();
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return scaling_ok ? 0 : 22;
    }
    // Authenticated N=4 output agreement test. PVIA_ENABLE=1 is required
    // to initialize the Ed25519 transport before this branch.
    const char* god_auth_env = std::getenv("PVIA_GOD_OUTPUT_N4_AUTH_SELFTEST");
    if (god_auth_env && std::string(god_auth_env) != "0") {
        const bool god_auth_ok =
            pvia::run_reference_god_authenticated_output_n4_selftest(rank,size);
        if (secure_transfer) secure_transfer_runtime.Detach();
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return god_auth_ok ? 0 : 27;
    }
    const char* god_provider_abi_env =
        std::getenv("PVIA_GOD_OUTPUT_PROVIDER_ABI_SELFTEST");
    if (god_provider_abi_env && std::string(god_provider_abi_env) != "0") {
        const char* library_path = std::getenv("PVIA_GOD_OUTPUT_PROVIDER_LIBRARY");
        std::string detail;
        const bool abi_ok = library_path &&
            pvia::run_reference_god_output_provider_abi_selftest(library_path,&detail);
        if (rank == 0)
            std::cout << "[PVIA][god-output-provider-abi] "
                      << (abi_ok ? "PASS" : "FAIL")
                      << " external_anchor=REQUIRED detail=" << detail << std::endl;
        if (secure_transfer) secure_transfer_runtime.Detach();
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return abi_ok ? 0 : 29;
    }
    const char* god_offline_cert_env =
        std::getenv("PVIA_GOD_SURVIVOR_CERTIFICATE_VERIFY_SELFTEST");
    if (god_offline_cert_env && std::string(god_offline_cert_env)!="0") {
        const char* certificate_words = std::getenv("PVIA_GOD_SURVIVOR_CERT_FILE");
        const char* public_registry = std::getenv("PVIA_GOD_SURVIVOR_REGISTRY_FILE");
        const char* trusted_anchor = std::getenv("PVIA_TRANSFER_REGISTRY_ANCHOR");
        std::string verification_detail;
        const bool local_verified =
            certificate_words && public_registry && trusted_anchor &&
            pvia::verify_reference_god_survivor_certificate_files(
                certificate_words,public_registry,trusted_anchor,
                &verification_detail);
        int local_flag = local_verified?1:0;
        int all_verified = 0;
        MPI_Allreduce(&local_flag,&all_verified,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
        if(rank==0)
            std::cout << "[PVIA][god-survivor-certificate-offline] "
                      << (all_verified?"PASS":"FAIL")
                      << " public_signature=" << (all_verified?"VERIFIED":"REJECTED")
                      << " production_authorization=NO"
                      << " detail="<<verification_detail << std::endl;
        if(secure_transfer)secure_transfer_runtime.Detach();
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return all_verified?0:32;
    }
    const char* god_bundle_env = std::getenv("PVIA_GOD_OUTPUT_BUNDLE_N4_SELFTEST");
    if (god_bundle_env && std::string(god_bundle_env) != "0") {
        const char* multiplication_library = std::getenv("PVIA_MC_PROVIDER_LIBRARY");
        const char* output_library = std::getenv("PVIA_GOD_OUTPUT_PROVIDER_LIBRARY");
        const char* relation_vector = std::getenv("PVIA_MC_RELATION_VECTOR");
        const bool bundle_ok = multiplication_library && output_library && relation_vector &&
            pvia::run_reference_god_output_bundle_n4_selftest(
                rank,size,multiplication_library,output_library,relation_vector);
        if (run_ulfm_bundle_crash_selftest) {
            // The proof bundle was verified before an actual process crash.
            // Do not enter the normal shutdown path, which may issue
            // collectives on the revoked original communicator.
            const char* final_dir=std::getenv("PVIA_GOD_FINALIZE_EVIDENCE_DIR");
            auto durable_finalize_marker=[&](const char* phase,int rc)->bool {
                if(!final_dir||!*final_dir)return false;
                const std::string filename=std::string(final_dir)+
                    "/mpi_bundle_finalize_rank"+std::to_string(rank)+
                    "_"+phase+".txt";
                const int fd=::open(filename.c_str(),O_WRONLY|O_CREAT|O_TRUNC,0600);
                if(fd<0)return false;
                const std::string payload=
                    "original_rank="+std::to_string(rank)+
                    " phase="+phase+" rc="+std::to_string(rc)+
                    " verified_bundle="+(bundle_ok?"PASS":"FAIL")+"\n";
                bool written=true;
                size_t offset=0;
                while(offset<payload.size()) {
                    const ssize_t n=::write(fd,payload.data()+offset,payload.size()-offset);
                    if(n<=0){written=false;break;}
                    offset+=static_cast<size_t>(n);
                }
                if(::fsync(fd)!=0)written=false;
                if(::close(fd)!=0)written=false;
                return written;
            };
            const char* precreated=
                std::getenv("PVIA_GOD_PRECREATED_SURVIVOR_COMM");
            const char* postfault=
                std::getenv("PVIA_GOD_POSTFAULT_SURVIVOR_GROUP_CREATE");
            const bool precreated_test=precreated && std::string(precreated)=="1";
            const bool postfault_test=postfault && std::string(postfault)=="1";
            const char* strict_identity_env=
                std::getenv("PVIA_GOD_POSTFAULT_REQUIRE_ULFM_IDENTITY");
            const bool strict_ulfm_shrink=strict_identity_env &&
                std::string(strict_identity_env)=="1";
            if((precreated_test || postfault_test) && !strict_ulfm_shrink) {
                // TEST ONLY: legacy fixture modes use an injected rank pin
                // and deliberately exit without MPI_Finalize. They are not
                // evidence for strict runtime-detected recovery.
                const bool persisted=durable_finalize_marker(
                    "direct_exit_testonly",bundle_ok?0:31);
                std::cerr<<"[PVIA][god-output-bundle-crash-n4] "
                         <<"TEST_ONLY_EXIT_NO_MPI_FINALIZE rank="<<rank
                         <<" verified_bundle="<<(bundle_ok?"PASS":"FAIL")
                         <<" persisted="<<(persisted?"YES":"NO")
                         <<" survivor_comm_strategy="
                         <<(strict_ulfm_shrink?"STRICT_ULFM_SHRINK":
                            (postfault_test?"POSTFAILURE_CREATE_GROUP":"PRECREATED"))
                         <<" dynamic_ulfm_shrink="
                         <<(strict_ulfm_shrink?"YES":"NO")<<std::endl;
                std::cout.flush(); std::cerr.flush();
                _exit(bundle_ok&&persisted?0:31);
            }
            if(strict_ulfm_shrink) {
                // Mark the original failed WORLD revoked only AFTER survivor
                // recovery completed and its active communicator was freed.
                // All protocol traffic has already moved to the shrunk group.
                if(!bundle_ok) {
                    std::cerr<<"[PVIA][god-output-bundle-crash-n4] "
                             <<"MPI_FINALIZE_WITHHELD recovery=FAIL rank="
                             <<rank<<std::endl;
                    std::cerr.flush();
                    _exit(31);
                }
                int revoke_rc=MPI_ERR_OTHER;
                bool revoke_status_ok=false;
#if defined(OMPI_HAVE_MPI_EXT_FTMPI)
                revoke_rc=MPIX_Comm_revoke(MPI_COMM_WORLD);
                revoke_status_ok=
                    revoke_rc==MPI_SUCCESS || revoke_rc==MPIX_ERR_REVOKED;
#endif
                const bool revoke_persisted=
                    durable_finalize_marker("world_revoke",revoke_rc);
                const bool revoke_ok=revoke_status_ok && revoke_persisted;
                std::cerr<<"[PVIA][god-output-bundle-crash-n4] "
                         <<"WORLD_REVOKE_AFTER_SHRINK rank="<<rank
                         <<" rc="<<revoke_rc
                         <<" durable_trace="<<(revoke_persisted?"PASS":"FAIL")
                         <<std::endl;
                if(!revoke_ok) {
                    std::cerr.flush();
                    _exit(31);
                }
            }
            const bool entered=durable_finalize_marker("enter",-1);
            const int finalize_rc=MPI_Finalize();
            const bool returned=durable_finalize_marker("return",finalize_rc);
            const bool verified_finalized=
                bundle_ok && finalize_rc==MPI_SUCCESS && entered && returned;
            std::cerr << "[PVIA][god-output-bundle-crash-n4] "
                      << (verified_finalized?"MPI_FINALIZE_AFTER_FAILURE rank=":
                          "MPI_FINALIZE_UNVERIFIED_PATH rank=") << rank
                      << " status=" << (finalize_rc==MPI_SUCCESS?"PASS":"FAIL")
                      << " rc=" << finalize_rc
                      << " durable_trace="<<((entered&&returned)?"PASS":"FAIL")
                      << std::endl;
            return verified_finalized ? 0 : 31;
        }
        if (secure_transfer) secure_transfer_runtime.Detach();
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return bundle_ok ? 0 : 31;
    }
    const char* god_provider_artifact_env =
        std::getenv("PVIA_GOD_OUTPUT_PROVIDER_ARTIFACT_SELFTEST");
    if (god_provider_artifact_env && std::string(god_provider_artifact_env) != "0") {
        const char* statement_path = std::getenv("PVIA_GOD_OUTPUT_STATEMENT_WORDS");
        const char* witness_path = std::getenv("PVIA_GOD_OUTPUT_WITNESS_WORDS");
        const char* proof_path = std::getenv("PVIA_GOD_OUTPUT_PROOF_ARTIFACT_WORDS");
        std::string detail;
        const bool local_ok = statement_path && witness_path && proof_path &&
            pvia::run_reference_god_output_provider_artifact_selftest(
                statement_path,witness_path,proof_path,&detail);
        int score=local_ok?1:0,all_scores=0;
        MPI_Allreduce(&score,&all_scores,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
        if (rank == 0)
            std::cout << "[PVIA][god-output-provider-artifact] "
                      << (all_scores ? "PASS" : "FAIL")
                      << " cryptographic_verification=separately_checked detail="
                      << detail << std::endl;
        if (secure_transfer) secure_transfer_runtime.Detach();
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return all_scores ? 0 : 30;
    }
    // Reference N=4, t=1 output recovery, isolated from production GOD claims.
    const char* god_output_demo = std::getenv("PVIA_GOD_OUTPUT_N4_SELFTEST");
    if (god_output_demo && std::string(god_output_demo) != "0") {
        const bool recovered = pvia::run_reference_god_output_n4_selftest(rank,size);
        if (secure_transfer) secure_transfer_runtime.Detach();
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return recovered ? 0 : 26;
    }
    if (argc == 2 &&
        std::string(argv[1]) == "--pvia-shamir-mpc-selftest") {
        const bool passed =
            pvia::run_reference_shamir_mpc_selftest(rank, size);
        if (rank == 0)
            std::cout << "[PVIA][shamir-mpc-selftest-standalone] "
                      << (passed ? "PASS" : "FAIL") << std::endl;
        if (secure_transfer) secure_transfer_runtime.Detach();
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return passed ? 0 : 10;
    }

    const char* shamir_mpc_selftest_env = std::getenv("PVIA_SHAMIR_MPC_SELFTEST");
    const bool shamir_mpc_selftest = shamir_mpc_selftest_env &&
        std::string(shamir_mpc_selftest_env) != "0";
    if (shamir_mpc_selftest &&
        !pvia::run_reference_shamir_mpc_selftest(rank, size)) {
        if (secure_transfer) secure_transfer_runtime.Detach();
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return 10;
    }
    const char* robust_termination_runtime_selftest_env =
        std::getenv("PVIA_ROBUST_TERMINATION_RUNTIME_SELFTEST");
    const bool robust_termination_runtime_selftest =
        robust_termination_runtime_selftest_env &&
        std::string(robust_termination_runtime_selftest_env) != "0";
    if (robust_termination_runtime_selftest) {
        const bool robust_termination_runtime_ok =
            pvia::run_robust_termination_runtime_selftest(
                pvia::Runtime::instance(), rank, size);
        if (rank == 0)
            std::cout << "[PVIA][robust-termination-runtime-selftest] "
                      << (robust_termination_runtime_ok ? "PASS" : "FAIL")
                      << "\n";
        if (!robust_termination_runtime_ok) {
            if (secure_transfer) secure_transfer_runtime.Detach();
            pvia::Runtime::instance().shutdown();
            MPI_Finalize();
            return 13;
        }
    }
    const char* bivariate_vss_selftest_env =
        std::getenv("PVIA_BIVARIATE_VSS_SELFTEST");
    const bool bivariate_vss_selftest = bivariate_vss_selftest_env &&
        std::string(bivariate_vss_selftest_env) != "0";
    if (bivariate_vss_selftest &&
        !pvia::ReferenceBivariateVss::SelfTest(rank, size)) {
        if (secure_transfer) secure_transfer_runtime.Detach();
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return 12;
    }
    // Fast isolated regression mode: execute the VSS recovery tests
    // without starting the unrelated default native proving workload.
    if (bivariate_vss_selftest &&
        std::getenv("PVIA_BIVARIATE_VSS_EXIT_AFTER_SELFTEST")) {
        if (secure_transfer) secure_transfer_runtime.Detach();
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return 0;
    }
    const char* fold_residual_selftest_env = std::getenv("PVIA_FOLD_RESIDUAL_SELFTEST");
    const bool fold_residual_selftest = fold_residual_selftest_env &&
        std::string(fold_residual_selftest_env) != "0";
    if (fold_residual_selftest) {
        int local_fold_ok = pvia::run_fold_residual_computation_selftest() ? 1 : 0;
        int global_fold_ok = 0;
        MPI_Allreduce(&local_fold_ok, &global_fold_ok, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
        if (rank == 0)
            std::cout << "[PVIA][fold-residual-selftest] "
                      << (global_fold_ok ? "PASS" : "FAIL") << "\n";
        if (!global_fold_ok) {
            if (secure_transfer) secure_transfer_runtime.Detach();
            pvia::Runtime::instance().shutdown();
            MPI_Finalize();
            return 8;
        }
        const char* fold_exit_env =
            std::getenv("PVIA_FOLD_RESIDUAL_EXIT_AFTER_SELFTEST");
        if (fold_exit_env && std::string(fold_exit_env)!="0") {
            if (secure_transfer) secure_transfer_runtime.Detach();
            pvia::Runtime::instance().shutdown();
            MPI_Finalize();
            return 0;
        }
    }
    if (secure_transfer &&
        !secure_transfer_runtime.SessionAuthenticationReady(
            secure_transfer_require_anchor)) {
        if (rank == 0) {
            std::cerr << "[PVIA] secure transfer authentication unavailable";
            if (secure_transfer_require_anchor)
                std::cerr << " or external registry anchor not verified";
            std::cerr << "\n";
        }
        secure_transfer_runtime.Detach();
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return 6;
    }
    
    
    
    

    std::unique_ptr<
        pvia::SharedLibraryMultiplicationConsistencyProviderSession>
        consistency_provider_session;
    const char* consistency_provider_library_env =
        std::getenv("PVIA_MC_PROVIDER_LIBRARY");
    const char* consistency_provider_id_env =
        std::getenv("PVIA_MC_PROVIDER_PROOF_SYSTEM_ID");
    const bool local_provider_library =
        consistency_provider_library_env &&
        consistency_provider_library_env[0] != '\0';
    const bool local_provider_id =
        consistency_provider_id_env &&
        consistency_provider_id_env[0] != '\0';
    // Explicit opt-out of optional SP1 while retaining legacy explicit
    // library-based opt-in for independent provider verification.
    const char* sp1_enabled_env = std::getenv("PVIA_SP1_ENABLED");
    const bool sp1_force_off =
        sp1_enabled_env && std::string(sp1_enabled_env) == "0";
    const bool sp1_force_on =
        sp1_enabled_env && std::string(sp1_enabled_env) == "1";
    const int local_provider_requested =
        !sp1_force_off &&
        (sp1_force_on || local_provider_library || local_provider_id) ? 1 : 0;
    int any_provider_requested = 0;
    MPI_Allreduce(
        &local_provider_requested, &any_provider_requested,
        1, MPI_INT, MPI_MAX, MPI_COMM_WORLD);
    if (rank == 0 && sp1_force_off)
        std::cout << "[PVIA][consistency-provider] sp1_online=off\n";

    uint32_t local_provider_proof_system_id = 0;
    bool local_provider_config_valid = !local_provider_requested;
    if (local_provider_library && local_provider_id) {
        errno = 0;
        char* end = nullptr;
        const unsigned long long parsed =
            std::strtoull(consistency_provider_id_env, &end, 0);
        local_provider_config_valid =
            errno == 0 && end &&
            end != consistency_provider_id_env && *end == '\0' &&
            parsed > 0 &&
            parsed <= static_cast<unsigned long long>(
                std::numeric_limits<uint32_t>::max());
        if (local_provider_config_valid)
            local_provider_proof_system_id =
                static_cast<uint32_t>(parsed);
    }

    if (any_provider_requested) {
        const int local_ready =
            local_provider_library && local_provider_id &&
            local_provider_config_valid &&
            pvia::Runtime::instance().enabled() ? 1 : 0;
        int all_ready = 0;
        MPI_Allreduce(
            &local_ready, &all_ready, 1, MPI_INT, MPI_MIN,
            MPI_COMM_WORLD);
        if (!all_ready) {
            if (rank == 0)
                std::cerr
                    << "[PVIA][consistency-provider] incomplete provider "
                    << "configuration across participants\n";
            if (secure_transfer) secure_transfer_runtime.Detach();
            pvia::Runtime::instance().shutdown();
            MPI_Finalize();
            return 17;
        }

        consistency_provider_session =
            std::make_unique<
                pvia::SharedLibraryMultiplicationConsistencyProviderSession>(
                std::string(consistency_provider_library_env),
                local_provider_proof_system_id);
        bool provider_activated = false;
        {
            pvia::ExperimentDurationScope provider_duration_scope(
                pvia::ExperimentDurationKind::CONSISTENCY_PROVIDER);
            pvia::ExperimentControlTrafficScope provider_traffic_scope(
                pvia::ExperimentControlTrafficKind::CONSISTENCY_PROVIDER);
            provider_activated = consistency_provider_session->Activate(
                rank, size, MPI_COMM_WORLD);
        }
        if (!provider_activated) {
            if (rank == 0) {
                std::cerr
                    << "[PVIA][consistency-provider] provider activation "
                    << "did not complete";
                if (!consistency_provider_session->error().empty())
                    std::cerr << ": "
                              << consistency_provider_session->error();
                std::cerr << "\n";
            }
            consistency_provider_session->Reset();
            if (secure_transfer) secure_transfer_runtime.Detach();
            pvia::Runtime::instance().shutdown();
            MPI_Finalize();
            return 18;
        }
        if (rank == 0) {
            const auto* provider_acceptance =
                consistency_provider_session->acceptance();
            std::cout
                << "[PVIA][consistency-provider] active protocol_id="
                << consistency_provider_session->capabilities().protocol_id
                << " authenticated_transport="
                << (provider_acceptance &&
                    provider_acceptance->authenticated_transport_used ? 1 : 0)
                << "\n";
        }
    }

    if (benchmark == 7) {
        if (!any_provider_requested) {
            if (rank == 0)
                std::cout
                    << "[PVIA][consistency-provider-probe] NOT_CONFIGURED\n";
            if (secure_transfer) secure_transfer_runtime.Detach();
            pvia::Runtime::instance().shutdown();
            MPI_Finalize();
            return 19;
        }

        const auto* acceptance = consistency_provider_session
            ? consistency_provider_session->acceptance() : nullptr;
        const bool local_probe_ready =
            consistency_provider_session &&
            consistency_provider_session->active() &&
            acceptance && acceptance->available &&
            acceptance->acceptance_binding != pvia::Digest{} &&
            acceptance->capability_binding != pvia::Digest{} &&
            consistency_provider_session->capabilities().protocol_id != 0;
        int local_probe_ready_int = local_probe_ready ? 1 : 0;
        int all_probe_ready = 0;
        MPI_Allreduce(
            &local_probe_ready_int, &all_probe_ready,
            1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);

        if (rank == 0) {
            if (all_probe_ready) {
                std::cout
                    << "[PVIA][consistency-provider-probe] PASS protocol_id="
                    << consistency_provider_session->capabilities().protocol_id
                    << " relation_binding="
                    << consistency_provider_session
                           ->capabilities().relation_binding.hex()
                    << " capability_binding="
                    << consistency_provider_session
                           ->capabilities().capability_binding.hex()
                    << " acceptance_binding="
                    << acceptance->acceptance_binding.hex()
                    << "\n";
            } else {
                std::cout
                    << "[PVIA][consistency-provider-probe] INCOMPLETE\n";
            }
        }

        if (consistency_provider_session)
            consistency_provider_session->Reset();
        if (secure_transfer) secure_transfer_runtime.Detach();
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return all_probe_ready ? 0 : 20;
    }

    int N = size;
    if(rank == 0) printf("Workers: %d\n",size);
    const bool packed_party_count_valid =
        N >= 4 && (N % 4) == 0 && (N & (N - 1)) == 0;
    if ((benchmark == 0 || benchmark == 1) && !packed_party_count_valid) {
        if (rank == 0)
            std::cerr << "coPIOP/PCS requires a power-of-two worker count "
                      << "N>=4 (packed-sharing uses k=N/4, _k=N/2)\n";
        if (consistency_provider_session)
            consistency_provider_session->Reset();
        if (secure_transfer) secure_transfer_runtime.Detach();
        pvia::Runtime::instance().shutdown();
        MPI_Finalize();
        return 14;
    }
    int k = N/4;
    int _k = N/2;
    int M = 1ULL<<(atoi(argv[2]));
    
    double ps = 0.0;
    vector<F> codeword,row_data;
    vector<vector<F>> data;
    
    
    //vector<int> dims = {1<<16,1<<14,1<<14};
    //test_mult_tree(dims, N);
    //generate_R1CS_matrixes(N, 1);
    //test_sparse_eval(N, M,1);
    
    if(benchmark == 0){
        int cir = atoi(argv[3]);
        if(cir <= 1){
            if(argc > 4){
                sumcheck_offset = atoi(argv[4]) - (int)log2(N);
                PC_offset = atoi(argv[5])- (int)log2(N);
                // Calculate x64
                multree_offset = atoi(argv[6]) - (int)log2(N);
            }
            if(isLAN) coPIOP_prove(M, N, _k, k,cir);
            else coPIOP_prove_batch(M, N, _k, k,cir);
        }else{
            data_parallel = true;
            coPIOP_prove(M, N, _k, k,1);
        }
    }else if(benchmark == 1){
        // test PCS
        rate = atoi(argv[3]);
        

        vector<F> codeword,row_data,R_shares,coefficients;
        MT C;
        vector<vector<F>> mask_shares,mask_data,C_mask;
        vector<MT> Com_mask;
        
        int l = (int)(-100.0/(log2(1-0.34*(1-(1.0/(double)rate))*(1.0-(double)_k/(double)N))));
        double cm = 0;
        dummy_setup(R_shares, mask_shares, N, M, k, _k, l);
        prepare_mask_shares(mask_shares, mask_data, C_mask, Com_mask, N, M, k, _k, l);
        secret_share_coefficients(coefficients, M, N, _k, k);
        
        MPI_Barrier(MPI_COMM_WORLD);
        pt_cp.reset();
        
        pt.start();
        commit(codeword, row_data,coefficients, R_shares, C, l, k, _k, N);
        pt.end();
        double commit_time = pt.get_time();
        vector<F> r;
        for(int i = 0; i < (int)log2(2*M); i++) r.push_back(hash_to_field({}));

        pt.start();
        open_zk(codeword,C_mask,row_data,mask_data,C,Com_mask,r,F(0),l,k,_k,M,N,ps,false);
        pt.end();
        double open_time = pt.get_time()-commit_time;
        
        if(rank == 0){
            vector<double> buff(4);
            printf("Id : %d, Pt: %lf, CPU Only Pt: %lf, Computation only: %lf, Vt: %lf\n", rank, pt.get_time(),pt_cpu.get_time(),pt_cp.get_time(),vt.get_time());
            for(int i = 1; i < N; i++){
                MPI_Recv(buff.data(), 4,MPI_DOUBLE,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
                printf("Id : %d, Commit time: %lf, Open time, %lf, Total: %lf, CPU Only Pt: %lf, Computation only: %lf\n", i, buff[0],buff[1],buff[0]+buff[1],buff[2],buff[3]);
            }    
        }else{
            vector<double> buff = {commit_time,open_time,pt_cpu.get_time(),pt_cp.get_time()};
            MPI_Send(buff.data(), 4,MPI_DOUBLE,0,0,MPI_COMM_WORLD);   
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
            printf("Vt : %lf sec, Ps: %lf KB, Com: %lf MB, Queries: %d\n",total_vt,ps,cm/1024.0,l);
        }
        
    }else if(benchmark == 2){
        vector<u64> buff64(2048);
        vector<F> buff;
        if(rank == 0){
            buff = generate_randomness(1024);
            field_vector_serialize(buff,buff64);
        }
        if(M == 1){
            pt.start();
            MPI_Bcast(buff64.data(),buff64.size(),MPI_UINT64_T,0,MPI_COMM_WORLD);
            pt.end();
            printf("%lf\n",pt.get_time());
        }else{
            pt.start();
            MPI_Request req;
            if(rank == 0){
                for(int i = 1; i < N; i++){
                    MPI_Isend(buff64.data(),buff64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req);
                }
            }else{
                MPI_Irecv(buff64.data(),buff64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
                MPI_Wait(&req,MPI_STATUS_IGNORE);
            }
            pt.end();
            printf("%lf\n",pt.get_time());

        }
        //printf("Incorrect Benchmark\n");
    }else if(benchmark == 3){
        vector<u64> buff64(2048),recv_buff(N*2048);
        
        vector<F> buff;
        buff = generate_randomness(1024);
        field_vector_serialize(buff,buff64);
        if(M == 1){
            pt.start();
            
            MPI_Gather(buff64.data(), buff64.size(), MPI_UINT64_T,
               recv_buff.data(), buff64.size(), MPI_UINT64_T, 0,
               MPI_COMM_WORLD);

            pt.end();
             if(rank == 0) printf("%lf\n",pt.get_time());
        }else if(M == 2){
            pt.start();
            if(rank == 0){
                vector<MPI_Request> req(N-1);
                for(int i = 1; i < N; i++){
                    MPI_Recv(buff64.data(),buff64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
                }
            
            }else{
                MPI_Request req;
                MPI_Send(buff64.data(),buff64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD);
            }
            pt.end();
            if(rank == 0) printf("%lf\n",pt.get_time());
        }
        else{
            pt.start();
            if(rank == 0){
                vector<vector<u64>> _buff(N-1);
                for(int i = 1; i < N; i++){_buff[i-1].resize(buff64.size());}
                
                vector<MPI_Request> req(N-1);
                for(int i = 1; i < N; i++){
                    MPI_Irecv(_buff[i-1].data(),_buff[i-1].size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i-1]);
                }
                for(int i = 1; i < N; i++){
                    MPI_Wait(&req[i-1],MPI_STATUS_IGNORE);
                }
            
            }else{
                MPI_Request req;
                MPI_Isend(buff64.data(),buff64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
                MPI_Wait(&req,MPI_STATUS_IGNORE);
            }
            pt.end();
            if(rank == 0)printf("%lf\n",pt.get_time());

        }
    }else if(benchmark == 4){
        PC_offset = 0;
        vector<F> poly(M);
        for(int i = 0; i < poly.size(); i++){
            poly[i] = F(i);
        }
        vector<F> r = generate_randomness((int)log2(M));
        F y  = evaluate_vector(poly,r);
        vector<F> arr(M/N);
        for(int i = 0; i < M/N; i++){
            arr[i] = rank*M/N + i;
        }
        MT Com; 
        plaintext_commit(arr,codeword,row_data,Com,N/2,N);
        vector<F> r1,r2,b1,b2;
        for(int i = 0; i < (int)log2(N/2); i++) r2.push_back(r[i]);
        for(int i = (int)log2(N/2); i < r.size(); i++) r1.push_back(r[i]);
        precompute_beta(r1,b1);
        precompute_beta(r2,b2);
        
        open_plaintext(codeword,row_data,b1,b2,Com,y,500,N/2,N,ps,false);
        
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
            printf("Vt : %lf sec, Ps: %lf KB, Com: %lf MB\n",total_vt,ps,cm/1024.0);
            printf("Interaction Rounds: %d\n",com_rounds);
        }
        printf(">>> Rounds: %d\n",com_rounds);
    }else if(benchmark == 5){
        vector<vector<F>> r1(3),r2(3);
        vector<F> arr1(M/N,1);
        vector<F> arr2(M/(N),2);
        vector<F> arr3(M/(N),3);
        vector<vector<F>> codeword(3);
        vector<vector<F>> row_data(3);
        vector<MT> Com(3);
        
        
        plaintext_commit(arr1,codeword[0],row_data[0],Com[0],N/2,N);
        plaintext_commit(arr2,codeword[1],row_data[1],Com[1],N/2,N);
        plaintext_commit(arr3,codeword[2],row_data[2],Com[2],N/2,N);
        r1[0] = generate_randomness((int)log2(M) - (int)log2(N/2));
        r2[0] = generate_randomness((int)log2(N/2));
        r1[1] = generate_randomness((int)log2(M) - (int)log2(N/2));
        r2[1] = generate_randomness((int)log2(N/2));
        r1[2] = generate_randomness((int)log2(M) - (int)log2(N/2));
        r2[2] = generate_randomness((int)log2(N/2));
        vector<vector<F>> v1(3),v2(3);
        for(int i = 0; i < v1.size(); i++) precompute_beta(r1[i],v1[i]);
        for(int i = 0; i < v2.size(); i++) precompute_beta(r2[i],v2[i]);
        //r11 = generate_randomness();
        batch_open(codeword, row_data, v1, v2, Com, {1,2,3}, {500,500,500}, {N/2,N/2,N/2},  N, ps, {false,false,false}, {true,true,true});
        double cm = 0.0;
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
            printf("Vt : %lf sec, Ps: %lf KB, Com: %lf MB\n",total_vt,ps,cm/1024.0);
            printf("Interaction Rounds: %d\n",com_rounds);
        }
        //test_quadratic_sumheck(N,  M);
    }else if(benchmark == 6){
        prove_R1CS_standard(1<<atoi(argv[2]), atoi(argv[3]));
    }else{
        sumcheck_offset = atoi(argv[4]) - (int)log2(N);
        printf("OK\n");   
        test_cubic_sumheck(N,M);
        if(rank == 0)printf("%lf,%lf,%lf\n",pt_cp.get_time(),pt.get_time(),sch_com.get_time());
    }
    
    if (native_runtime_source_capture) {
        pvia::RegistrationConsistencyStatement native_statement{};
        pvia::RegistrationNativeConsumedSnapshot native_snapshot{};
        const bool local_capture_ok =
            fold_runtime_harness.CaptureLatestNativeFoldStatement(
                &native_statement) &&
            fold_runtime_harness.capture(native_statement, &native_snapshot) &&
            fold_runtime_harness.still_matches(
                native_statement, native_snapshot);
        int local_capture = local_capture_ok ? 1 : 0;
        int global_capture = 0;
        MPI_Allreduce(&local_capture, &global_capture, 1, MPI_INT, MPI_MIN,
                      MPI_COMM_WORLD);
        native_runtime_source_capture_ok = global_capture == 1;
        if (rank == 0) {
            std::cout << "[PVIA][native-source-runtime-capture] "
                      << (native_runtime_source_capture_ok ? "PASS" : "FAIL");
            if (native_runtime_source_capture_ok) {
                std::cout << " checkpoint=" << native_statement.checkpoint
                          << " owner=" << native_statement.ref.owner
                          << " operation=" << native_statement.ref.object_id
                          << " state_elements="
                          << native_snapshot.state_values.size()
                          << " output_elements="
                          << native_snapshot.actual_output.size()
                          << " consumed_binding="
                          << native_snapshot.consumed_record_binding.hex();
            }
            std::cout << std::endl;
        }
    }

    // ==================================================== //
    /*
    dummy_setup(R_shares, mask_shares, N, M, k, _k, 500);

    prepare_mask_shares(mask_shares, mask_data, C_mask, Com_mask, N, M, k, _k, 500);
    commit(codeword,row_data,R_shares,Com,500,k,_k,M,N);
    open_zk(codeword, C_mask, row_data, mask_data, Com, Com_mask, r, y, 500, k, _k, M, N,ps,vt);
    */
    
    
    if (rank == 0) printf("MPI World size = %d processes\n", size);
    //else printf("Worker Finalizing ... \n");
    if (transfer_selftest && pvia::Runtime::instance().enabled()) {
        const bool transfer_ok = transfer_harness.RunSelfCheck(rank, size);
        if (rank == 0 && !transfer_ok)
            std::cout << "[PVIA][transfer-selftest] FAILED\n";
    }
    if (transfer_selftest)
        pvia::Runtime::instance().set_audit_backend(nullptr);
    if (transfer_no_framing_selftest &&
        pvia::Runtime::instance().enabled()) {
        transfer_no_framing_selftest_ok =
            pvia::run_ed25519_transfer_no_framing_selftest(
                rank, size);
        if (rank == 0 && !transfer_no_framing_selftest_ok)
            std::cout
                << "[PVIA][transfer-no-framing-entry] FAILED\n";
    }
    if (fold_runtime_selftest) {
        fold_runtime_selftest_ok = pvia::Runtime::instance().enabled() &&
            fold_runtime_harness.RunSelfCheck(rank, size);
        if (rank == 0 && !fold_runtime_selftest_ok)
            std::cout << "[PVIA][fold-runtime-selftest] FAILED\n";
    }
    if (shamir_fold_runtime_selftest) {
        shamir_fold_runtime_selftest_ok =
            pvia::Runtime::instance().enabled() &&
            fold_runtime_harness.RunReferenceMpcSelfCheck(rank, size);
        if (rank == 0 && !shamir_fold_runtime_selftest_ok)
            std::cout << "[PVIA][shamir-fold-runtime-selftest] FAILED\n";
    }
    if (native_sumcheck_runtime_selftest) {
        native_sumcheck_runtime_selftest_ok =
            pvia::Runtime::instance().enabled() &&
            fold_runtime_harness.RunNativeSumcheckSelfCheck(rank, size);
        if (rank == 0 && !native_sumcheck_runtime_selftest_ok)
            std::cout << "[PVIA][native-sumcheck-runtime-selftest] FAILED\n";
    }
    if (sp1_secure_backend_bridge &&
        pvia::Runtime::instance().enabled()) {
        auto& runtime = pvia::Runtime::instance();
        // The same SecureAuditBackend instance captured the live callbacks.
        // Promote it only after protocol execution, then exercise the actual
        // Runtime release gate. With no authenticated batch engine installed,
        // the gate must reject rather than treating a Groth16 receipt as a
        // release authorization.
        runtime.set_source_observer(nullptr);
        runtime.set_audit_backend(&sp1_secure_backend);

        const pvia::AuditRelationKernel required_kernels[] = {
            pvia::AuditRelationKernel::COSUMCHECK_ZERO,
            pvia::AuditRelationKernel::COSUMCHECK_QUADRATIC,
            pvia::AuditRelationKernel::COSUMCHECK_BATCH,
            pvia::AuditRelationKernel::DSC_CUBIC};
        constexpr int required_kernel_count =
            static_cast<int>(sizeof(required_kernels) /
                             sizeof(required_kernels[0]));
        pvia::AuditRelationProofReceipt receipts[required_kernel_count];
        bool receipt_valid[required_kernel_count] = {};
        pvia::AuditBackend* promoted_backend = runtime.audit_backend();
        int local_receipt_count = 0;

        // The normal optimized path has four native relation classes. Read
        // each proof receipt through the generic backend boundary rather
        // than accepting one successful proof as coverage for every class.
        if (rank == 0) {
            for (int i = 0; i < required_kernel_count; ++i) {
                const bool receipt_found = promoted_backend &&
                    promoted_backend->ReadRelationProofReceipt(
                        required_kernels[i], &receipts[i]);
                const auto& current = receipts[i];
                receipt_valid[i] = receipt_found && current.available &&
                    current.proof_verified &&
                    !current.production_privacy_confirmed &&
                    current.kernel == required_kernels[i] &&
                    current.operation_ref.object_id != 0 &&
                    current.checkpoint != 0 &&
                    current.relation_statement != pvia::Digest{} &&
                    current.proof_system_id == 68102 &&
                    current.proof_word_count > 17 &&
                    current.statement_binding != pvia::Digest{} &&
                    current.artifact_commitment != pvia::Digest{};
                if (receipt_valid[i]) ++local_receipt_count;
            }
        }

        int global_receipt_count = 0;
        MPI_Allreduce(&local_receipt_count, &global_receipt_count, 1,
                      MPI_INT, MPI_SUM, MPI_COMM_WORLD);

        const bool production_composition_ready =
            sp1_secure_backend_provider.Ready(
                sp1_secure_backend_requirements);
        int local_composition_ready =
            production_composition_ready ? 1 : 0;
        int global_composition_ready = 0;
        // A local readiness result is insufficient in MPI: fail closed
        // if any rank reports a partially installed secure composition.
        MPI_Allreduce(&local_composition_ready, &global_composition_ready,
                      1, MPI_INT, MPI_MAX, MPI_COMM_WORLD);
        const int local_composition_readiness_guard =
            pvia::run_secure_audit_composition_readiness_selftest() ? 1 : 0;
        int global_composition_readiness_guard = 0;
        MPI_Allreduce(&local_composition_readiness_guard,
                      &global_composition_readiness_guard, 1,
                      MPI_INT, MPI_MIN, MPI_COMM_WORLD);
        if (rank == 0) {
            std::cout << "[PVIA][secure-audit-composition-readiness-selftest] "
                      << (global_composition_readiness_guard ? "PASS" : "FAIL")
                      << " private_fail_closed=1 transfer_fail_closed=1"
                      << std::endl;
        }
        const bool gate_allowed = runtime.pre_release_gate(
            "sp1_secure_backend_bridge_fail_closed",
            pvia::Phase::INIT, 2);
        int local_gate_withheld = gate_allowed ? 0 : 1;
        int global_gate_withheld = 0;
        MPI_Allreduce(&local_gate_withheld, &global_gate_withheld, 1,
                      MPI_INT, MPI_MIN, MPI_COMM_WORLD);

        const auto& counts =
            sp1_secure_backend_provider.native_sumcheck_finalized_counts();
        // The provider counters are rank-local. Aggregate them before
        // reporting N=4 coverage; otherwise the acceptance summary sees only
        // rank 0's 32 callbacks instead of the global 128 callbacks.
        const uint64_t local_bridge_counts[7] = {
            static_cast<uint64_t>(counts[0]),
            static_cast<uint64_t>(counts[1]),
            static_cast<uint64_t>(counts[2]),
            static_cast<uint64_t>(counts[3]),
            static_cast<uint64_t>(counts[4]),
            static_cast<uint64_t>(
                sp1_secure_backend_provider.native_sumcheck_invalid_count()),
            static_cast<uint64_t>(
                sp1_secure_backend_provider.native_sumcheck_unavailable_count())};
        uint64_t global_bridge_counts[7] = {};
        MPI_Allreduce(local_bridge_counts, global_bridge_counts, 7,
                      MPI_UINT64_T, MPI_SUM, MPI_COMM_WORLD);
        uint64_t local_finalized_total = 0;
        for (size_t i = 0; i < 5; ++i)
            local_finalized_total += local_bridge_counts[i];
        uint64_t global_finalized_total_min = 0;
        uint64_t global_finalized_total_max = 0;
        MPI_Allreduce(&local_finalized_total,
                      &global_finalized_total_min, 1, MPI_UINT64_T,
                      MPI_MIN, MPI_COMM_WORLD);
        MPI_Allreduce(&local_finalized_total,
                      &global_finalized_total_max, 1, MPI_UINT64_T,
                      MPI_MAX, MPI_COMM_WORLD);
        uint64_t global_finalized_total = 0;
        for (size_t i = 0; i < 5; ++i)
            global_finalized_total += global_bridge_counts[i];
        sp1_secure_backend_bridge_ok =
            global_receipt_count == required_kernel_count &&
            global_gate_withheld == 1 &&
            global_composition_ready == 0 &&
            global_composition_readiness_guard == 1 &&
            size == 4 &&
            global_finalized_total_min > 0 &&
            global_finalized_total_min == global_finalized_total_max &&
            global_finalized_total_min * static_cast<uint64_t>(size) ==
                global_finalized_total &&
            global_bridge_counts[5] == 0 &&
            global_bridge_counts[6] == 0;
        if (rank == 0) {
            std::cout << "[PVIA][sp1-secure-backend-bridge] "
                      << (sp1_secure_backend_bridge_ok ? "PASS" : "FAIL")
                      << " receipt="
                      << (global_receipt_count == required_kernel_count
                              ? "PASS" : "INCOMPLETE")
                      << " receipts=" << global_receipt_count << "/"
                      << required_kernel_count
                      << " required_kernels={1,2,3,5}"
                      << " backend_promoted=1"
                      << " composition_ready="
                      << global_composition_ready
                      << " release_gate="
                      << (global_gate_withheld ? "WITHHOLD" : "ALLOW")
                      << " finalized_kernels={"
                      << global_bridge_counts[0] << ","
                      << global_bridge_counts[1] << ","
                      << global_bridge_counts[2] << ","
                      << global_bridge_counts[3] << ","
                      << global_bridge_counts[4] << "}"
                      << " invalid=" << global_bridge_counts[5]
                      << " unavailable=" << global_bridge_counts[6]
                      << " rank_callbacks_min="
                      << global_finalized_total_min
                      << " rank_callbacks_max="
                      << global_finalized_total_max
                      << std::endl;
            for (int i = 0; i < required_kernel_count; ++i) {
                if (!receipt_valid[i]) continue;
                const auto& current = receipts[i];
                std::cout << "[PVIA][sp1-secure-backend-receipt] "
                          << "kernel="
                          << static_cast<uint64_t>(current.kernel)
                          << " operation=" << current.operation_ref.object_id
                          << " checkpoint=" << current.checkpoint
                          << " proof_system=" << current.proof_system_id
                          << " proof_words=" << current.proof_word_count
                          << " statement_binding="
                          << current.statement_binding.hex()
                          << " artifact_commitment="
                          << current.artifact_commitment.hex()
                          << " relation_statement="
                          << current.relation_statement.hex()
                          << std::endl;
            }
        }
        runtime.set_audit_backend(nullptr);
    }

    if (fold_runtime_selftest || shamir_fold_runtime_selftest ||
        native_runtime_source_capture)
        pvia::Runtime::instance().set_audit_backend(nullptr);
    if (secure_transfer_selftest && pvia::Runtime::instance().enabled()) {
        secure_transfer_selftest_ok = secure_transfer_runtime.RunFailureHandlerSelfTest(
            pvia::Runtime::instance(), rank, size);
        if (rank == 0 && !secure_transfer_selftest_ok)
            std::cout << "[PVIA][secure-transfer-selftest] FAILED\n";
    }
    if (consistency_provider_session)
        consistency_provider_session->Reset();
    if (secure_transfer)
        secure_transfer_runtime.Detach();
    if (passive_observer || native_sumcheck_runtime_selftest ||
        sp1_secure_backend_bridge)
        pvia::Runtime::instance().set_source_observer(nullptr);
    pvia::Runtime::instance().shutdown();
    MPI_Finalize();
    if (!secure_transfer_selftest_ok) return 5;
    if (!fold_runtime_selftest_ok) return 9;
    if (!shamir_fold_runtime_selftest_ok) return 11;
    if (!native_sumcheck_runtime_selftest_ok) return 12;
    if (!transfer_no_framing_selftest_ok) return 21;
    if (!native_runtime_source_capture_ok) return 44;
    if (!sp1_secure_backend_bridge_ok) return 54;
    
    /*
    if(op == 1){
        prove_R1CS(size,N,_k,k);
    }else if(op == 2){
        prove_R1CS_standard(size);    
    }else if(op == 3){
        emulate_PCS(size,N,k,_k,ps);
    }
    exit(-1);
    */
    
    return 0;
}
