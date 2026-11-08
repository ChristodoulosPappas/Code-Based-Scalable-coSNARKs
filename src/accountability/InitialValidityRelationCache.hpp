#pragma once

#include "PVIA.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace pvia {

struct InitialValidityRelationCache {
    int world_size = 0;
    int k = 0;
    int packed_width = 0;
    size_t witness_slots = 0;
    size_t constraint_slots = 0;
    Digest relation_binding{};
    bool validated = false;
    // Derived from the public relation after validation.  This is intentionally
    // not serialized: it is a local acceleration index and is not part of the
    // canonical relation binding.
    std::vector<uint32_t> active_blocks;
    std::array<std::vector<uint32_t>, 3> row_offsets;
    std::array<std::vector<uint32_t>, 3> constraint_indices;
};

// Builds a reusable cache from the complete public transposed R1CS relation.
// The cache contains no witness data and no proof-time randomness.
bool write_initial_validity_relation_cache(
    const std::string& path,
    const std::vector<std::vector<std::pair<int,int>>>& full_a,
    const std::vector<std::vector<std::pair<int,int>>>& full_b,
    const std::vector<std::vector<std::pair<int,int>>>& full_c,
    int world_size,
    int k,
    int packed_width,
    size_t witness_slots,
    size_t constraint_slots,
    Digest* relation_binding = nullptr);

// Loads and validates a public cache.  Validation recomputes the exact
// canonical relation binding used by the online gate and compares it with the
// binding reconstructed from the live distributed relation shards.
bool load_initial_validity_relation_cache(
    const std::string& path,
    int world_size,
    int k,
    int packed_width,
    size_t witness_slots,
    size_t constraint_slots,
    const Digest& expected_relation_binding,
    InitialValidityRelationCache* cache);

// Computes only this rank's challenge-dependent packed block coefficients.
// All inputs are public; no witness material is read by this routine.
bool compute_initial_validity_block_coefficients_from_cache(
    const InitialValidityRelationCache& cache,
    const std::vector<F>& linkage_coefficients,
    int rank,
    const std::vector<F>& local_lagrange_weights,
    std::vector<F>* block_coefficients);

} // namespace pvia
