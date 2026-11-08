#pragma once

#include "PVIA.hpp"

#include <mpi.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pvia {

struct JointPackedPreprocessingResult {
    bool ok = false;
    size_t share_count = 0;
    int contributors = 0;
    Digest local_binding{};
};

bool generate_joint_packed_random_share(
    size_t share_count, int world_size, int k, int packed_width,
    uint64_t domain, std::vector<F>* local_share,
    JointPackedPreprocessingResult* result = nullptr,
    MPI_Comm comm = MPI_COMM_WORLD);

// Persist one rank-local preprocessing share as a one-time offline artifact.
// The artifact is parameter-bound and contains only this rank's private share.
// It must be stored on rank-private storage in a real multi-party deployment.
bool write_joint_packed_preprocessing_slot(
    const std::string& directory, uint64_t slot,
    size_t share_count, int world_size, int k, int packed_width,
    uint64_t domain, const std::vector<F>& local_share,
    MPI_Comm comm = MPI_COMM_WORLD);

} // namespace pvia
