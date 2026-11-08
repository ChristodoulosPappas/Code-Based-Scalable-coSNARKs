#pragma once

#include "MultiplicationConsistencyProof.hpp"
#include "PVIA.hpp"

#include <mpi.h>

namespace pvia {

struct MultiplicationConsistencyProviderAcceptanceResult {
    bool available = false;
    bool capabilities_ready = false;
    bool multiplication_verified = false;
    bool zero_case_verified = false;
    bool nonzero_case_verified = false;
    bool authenticated_transport_used = false;
    uint32_t completed_stage = 0;
    Digest authenticated_transport_capability_binding{};
    Digest capability_binding{};
    Digest multiplication_binding{};
    Digest zero_case_binding{};
    Digest nonzero_case_binding{};
    Digest acceptance_binding{};
};

bool run_multiplication_consistency_provider_acceptance(
    int rank, int world_size,
    const MultiplicationConsistencyProofBackend& backend,
    MultiplicationConsistencyProviderAcceptanceResult* result,
    MPI_Comm comm = MPI_COMM_WORLD);

} // namespace pvia
