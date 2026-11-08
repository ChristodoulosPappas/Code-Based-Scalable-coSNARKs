#include "MpiPublicTransferObservationExchange.hpp"

#include <cstring>
#include <mpi.h>
#include <vector>

namespace pvia {
namespace {

void digest_to_words(const Digest& digest, uint64_t* out) {
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(&out[i], digest.bytes.data() + 8 * i, 8);
}

bool all_ranks_same_digest(const Digest& digest, int world_size) {
    uint64_t local[4]{};
    digest_to_words(digest, local);
    std::vector<uint64_t> all(static_cast<size_t>(world_size) * 4, 0);
    MPI_Allgather(local, 4, MPI_UINT64_T,
                  all.data(), 4, MPI_UINT64_T, MPI_COMM_WORLD);
    for (int r = 1; r < world_size; ++r) {
        for (size_t i = 0; i < 4; ++i) {
            if (all[static_cast<size_t>(r) * 4 + i] != all[i])
                return false;
        }
    }
    return true;
}

bool all_ranks_true(int local) {
    int global = 0;
    MPI_Allreduce(&local, &global, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    return global != 0;
}

} // namespace

bool MpiPublicTransferObservationExchange::Resolve(
    const PublicTransferObservationStore& observations,
    const ObligationSet& scope,
    const CollectiveDisputeResult& dispute,
    int rank,
    int world_size,
    PublicTransferObservation* resolved) {
    int comm_rank = -1;
    int comm_size = 0;
    MPI_Comm_rank(MPI_COMM_WORLD, &comm_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &comm_size);

    const int local_input_ok =
        resolved != nullptr && world_size > 0 && rank >= 0 &&
        rank < world_size && rank == comm_rank && world_size == comm_size &&
        dispute.public_evidence_binding != Digest{} ? 1 : 0;
    if (!all_ranks_true(local_input_ok)) return false;
    *resolved = PublicTransferObservation{};

    const Digest scope_binding = compute_collective_scope_binding(scope);
    const Digest dispute_binding = compute_collective_dispute_binding(dispute);
    const bool same_scope = all_ranks_same_digest(scope_binding, world_size);
    const bool same_dispute = all_ranks_same_digest(dispute_binding, world_size);
    if (!same_scope || !same_dispute) return false;

    PublicTransferObservation local_observation;
    const bool local_match = find_public_transfer_observation_for_dispute(
        observations, scope, dispute, &local_observation);
    const bool local_has = local_match &&
        local_observation.observer_rank == static_cast<uint32_t>(rank);
    const int local_has_int = local_has ? 1 : 0;
    std::vector<int> holders(static_cast<size_t>(world_size), 0);
    MPI_Allgather(&local_has_int, 1, MPI_INT,
                  holders.data(), 1, MPI_INT, MPI_COMM_WORLD);

    int source_rank = -1;
    for (int r = 0; r < world_size; ++r) {
        if (holders[static_cast<size_t>(r)] != 0) {
            source_rank = r;
            break;
        }
    }
    if (source_rank < 0) return false;

    std::vector<u64> words(PUBLIC_TRANSFER_OBSERVATION_WORDS, 0);

    int source_ready = 1;
    if (rank == source_rank) {
        const std::vector<u64> encoded =
            encode_public_transfer_observation(local_observation);
        if (encoded.size() != PUBLIC_TRANSFER_OBSERVATION_WORDS) {
            source_ready = 0;
        } else {
            words = encoded;
        }
    }
    if (!all_ranks_true(source_ready)) return false;

    MPI_Bcast(words.data(), static_cast<int>(words.size()), MPI_UINT64_T,
              source_rank, MPI_COMM_WORLD);

    PublicTransferObservation decoded;
    int local_resolved_ok =
        decode_public_transfer_observation(words, &decoded) &&
        decoded.observer_rank == static_cast<uint32_t>(source_rank) &&
        public_transfer_observation_supports_dispute(decoded, dispute) &&
        compute_public_transfer_observation_binding(decoded) ==
            dispute.public_evidence_binding
            ? 1 : 0;

    if (local_has &&
        encode_public_transfer_observation(local_observation) != words)
        local_resolved_ok = 0;
    if (!all_ranks_true(local_resolved_ok)) return false;

    *resolved = decoded;
    return true;
}

} // namespace pvia
