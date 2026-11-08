#include "InitialValidityGate.hpp"
#include "InitialValidityRelationCache.hpp"

#include "AuthenticatedMpcExchange.hpp"
#include "ReferenceShamirMpc.hpp"
#include "ProtocolTrafficMetrics.hpp"
#include "MultiplicationConsistencyBackendRegistry.hpp"
#include "../utils.hpp"
#include "../../Blake/blake3.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <thread>
#include <vector>

namespace pvia {
namespace {

constexpr u64 INITIAL_VALIDITY_COEFF_STREAM_DOMAIN =
    0x5056495643465332ULL; // PVIVCFS2
constexpr u64 INITIAL_VALIDITY_LINK_STREAM_DOMAIN =
    0x505649564c4b5332ULL; // PVIVLKS2
constexpr u64 INITIAL_VALIDITY_RELATION_PART_DOMAIN = 0x5056495652504152ULL; // PVIVRPAR
constexpr u64 INITIAL_VALIDITY_RELATION_BIND_DOMAIN = 0x505649565242494eULL; // PVIVRBIN
constexpr u64 INITIAL_VALIDITY_BIND_DOMAIN  = 0x50564956414c424eULL; // PVIVALBN
constexpr u64 INITIAL_VALIDITY_CONTRIBUTION_DOMAIN = 0x50564956434f4e54ULL; // PVIVCONT

void append_digest_words(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

F digest_to_field(const Digest& digest) {
    u64 real = 0;
    u64 imag = 0;
    std::memcpy(&real, digest.bytes.data(), 8);
    std::memcpy(&imag, digest.bytes.data() + 8, 8);
    return F(static_cast<long long>(real % F::mod),
             static_cast<long long>(imag % F::mod));
}

bool exact_log2(int value, int* log_value) {
    if (!log_value || value <= 0 || (value & (value - 1)) != 0)
        return false;
    int out = 0;
    while ((1 << out) < value) ++out;
    *log_value = out;
    return true;
}

bool expand_field_coefficients(
    u64 domain,
    const std::vector<u64>& context_words,
    const std::vector<Digest>& context_digests,
    size_t count,
    std::vector<F>* coefficients) {
    if (!coefficients || domain == 0 || count == 0 ||
        count > std::numeric_limits<size_t>::max() / 16)
        return false;

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(
        &hasher, reinterpret_cast<const uint8_t*>(&domain),
        sizeof(domain));
    if (!context_words.empty()) {
        blake3_hasher_update(
            &hasher,
            reinterpret_cast<const uint8_t*>(context_words.data()),
            context_words.size() * sizeof(u64));
    }
    for (const Digest& digest : context_digests) {
        if (digest == Digest{}) return false;
        blake3_hasher_update(
            &hasher, digest.bytes.data(), digest.bytes.size());
    }

    std::vector<uint8_t> stream(count * 16);
    blake3_hasher_finalize(
        &hasher, stream.data(), stream.size());
    coefficients->resize(count);
    for (size_t i = 0; i < count; ++i) {
        u64 real = 0;
        u64 imag = 0;
        std::memcpy(&real, stream.data() + 16 * i, 8);
        std::memcpy(&imag, stream.data() + 16 * i + 8, 8);
        (*coefficients)[i] = F(
            static_cast<long long>(real % F::mod),
            static_cast<long long>(imag % F::mod));
    }
    return true;
}

bool expand_linkage_coefficients(
    const Digest& seed,
    const Digest& relation_binding,
    uint64_t sid,
    int world_size,
    int k,
    int packed_width,
    size_t constraint_slots,
    std::vector<F>* coefficients) {
    if (world_size <= 0 || k <= 0 || packed_width <= 0 ||
        constraint_slots == 0 ||
        constraint_slots >
            std::numeric_limits<size_t>::max() / 3)
        return false;
    const std::vector<u64> context = {
        sid,
        static_cast<u64>(world_size),
        static_cast<u64>(k),
        static_cast<u64>(packed_width),
        static_cast<u64>(constraint_slots),
        3ULL};
    return expand_field_coefficients(
        INITIAL_VALIDITY_LINK_STREAM_DOMAIN,
        context, {seed, relation_binding},
        3 * constraint_slots, coefficients);
}

bool expand_multiplicative_coefficients(
    const Digest& seed,
    uint64_t sid,
    int world_size,
    int k,
    int packed_width,
    size_t block_count,
    std::vector<F>* coefficients) {
    if (world_size <= 0 || k <= 0 || packed_width <= 0 ||
        block_count == 0 ||
        block_count >
            std::numeric_limits<size_t>::max() /
                static_cast<size_t>(k))
        return false;
    const size_t count =
        block_count * static_cast<size_t>(k);
    const std::vector<u64> context = {
        sid,
        static_cast<u64>(world_size),
        static_cast<u64>(k),
        static_cast<u64>(packed_width),
        static_cast<u64>(block_count),
        static_cast<u64>(count)};
    return expand_field_coefficients(
        INITIAL_VALIDITY_COEFF_STREAM_DOMAIN,
        context, {seed}, count, coefficients);
}

Digest local_relation_partition_binding(
    const std::vector<std::vector<std::pair<int,int>>>& pA,
    const std::vector<std::vector<std::pair<int,int>>>& pB,
    const std::vector<std::vector<std::pair<int,int>>>& pC,
    int rank,
    int world_size,
    size_t witness_slots,
    size_t constraint_slots) {
    if (rank < 0 || world_size <= 0 ||
        witness_slots == 0 || witness_slots % static_cast<size_t>(world_size) != 0)
        return {};
    const size_t slice = witness_slots / static_cast<size_t>(world_size);
    if (pA.size() != slice || pB.size() != slice || pC.size() != slice)
        return {};
    const std::vector<const std::vector<std::vector<std::pair<int,int>>>*> lanes = {
        &pA, &pB, &pC};

    // Preserve the exact canonical u64 sequence previously materialized in a
    // single vector, but stream it through BLAKE3 in bounded chunks.  The
    // relation partition can contain hundreds of thousands of sparse entries,
    // so avoiding the full temporary buffer removes one large allocation and
    // memory copy from every initial-validity check.
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    constexpr size_t RELATION_HASH_CHUNK_WORDS = 1024;
    std::array<u64, RELATION_HASH_CHUNK_WORDS> chunk{};
    size_t chunk_size = 0;
    auto flush = [&]() {
        if (chunk_size == 0) return;
        blake3_hasher_update(
            &hasher,
            reinterpret_cast<const uint8_t*>(chunk.data()),
            chunk_size * sizeof(u64));
        chunk_size = 0;
    };
    auto append_word = [&](u64 word) {
        chunk[chunk_size++] = word;
        if (chunk_size == chunk.size()) flush();
    };

    append_word(INITIAL_VALIDITY_RELATION_PART_DOMAIN);
    append_word(static_cast<u64>(rank));
    append_word(static_cast<u64>(world_size));
    append_word(static_cast<u64>(witness_slots));
    append_word(static_cast<u64>(constraint_slots));
    append_word(static_cast<u64>(slice));
    for (size_t lane = 0; lane < lanes.size(); ++lane) {
        append_word(static_cast<u64>(lane));
        const auto& rows = *lanes[lane];
        for (size_t local_wire = 0; local_wire < rows.size(); ++local_wire) {
            const size_t expected_wire =
                static_cast<size_t>(rank) * slice + local_wire;
            append_word(static_cast<u64>(expected_wire));
            append_word(static_cast<u64>(rows[local_wire].size()));
            for (const auto& entry : rows[local_wire]) {
                if (entry.first < 0 || entry.second < 0 ||
                    static_cast<size_t>(entry.first) != expected_wire ||
                    static_cast<size_t>(entry.second) >= constraint_slots)
                    return {};
                append_word(static_cast<u64>(entry.first));
                append_word(static_cast<u64>(entry.second));
            }
        }
    }
    flush();
    Digest out{};
    blake3_hasher_finalize(
        &hasher, out.bytes.data(), out.bytes.size());
    return out;
}

Digest collective_relation_binding(
    const Digest& local_binding,
    int world_size,
    MPI_Comm comm) {
    if (local_binding == Digest{} || world_size <= 0) return {};
    const size_t digest_bytes = local_binding.bytes.size();
    std::vector<uint8_t> gathered(
        static_cast<size_t>(world_size) * digest_bytes);
    MPI_Allgather(
        local_binding.bytes.data(), static_cast<int>(digest_bytes), MPI_BYTE,
        gathered.data(), static_cast<int>(digest_bytes), MPI_BYTE, comm);
    record_control_allgather(
        static_cast<uint64_t>(digest_bytes), world_size);
    std::vector<u64> words = {
        INITIAL_VALIDITY_RELATION_BIND_DOMAIN,
        static_cast<u64>(world_size)};
    for (int participant = 0; participant < world_size; ++participant) {
        Digest part{};
        std::memcpy(
            part.bytes.data(),
            gathered.data() + static_cast<size_t>(participant) * digest_bytes,
            digest_bytes);
        append_digest_words(part, &words);
    }
    return hash_words(words);
}

Digest collective_contribution_binding(
    const Digest& local_binding, int world_size, MPI_Comm comm) {
    if (local_binding == Digest{} || world_size <= 0) return {};
    const size_t digest_bytes = local_binding.bytes.size();
    std::vector<uint8_t> gathered(
        static_cast<size_t>(world_size) * digest_bytes);
    MPI_Allgather(
        local_binding.bytes.data(), static_cast<int>(digest_bytes), MPI_BYTE,
        gathered.data(), static_cast<int>(digest_bytes), MPI_BYTE, comm);
    record_control_allgather(
        static_cast<uint64_t>(digest_bytes), world_size);
    std::vector<u64> words = {
        INITIAL_VALIDITY_CONTRIBUTION_DOMAIN, static_cast<u64>(world_size)};
    for (int participant = 0; participant < world_size; ++participant) {
        Digest part{};
        std::memcpy(part.bytes.data(),
            gathered.data() + static_cast<size_t>(participant) * digest_bytes,
            digest_bytes);
        append_digest_words(part, &words);
    }
    return hash_words(words);
}

bool build_packed_lagrange_matrix(
    const F& root,
    int source_stride,
    const std::vector<F>& participant_points,
    int k,
    std::vector<std::vector<F>>* lagrange_by_rank) {
    if (!lagrange_by_rank || source_stride <= 0 || k <= 0 ||
        participant_points.empty())
        return false;
    const int world_size =
        static_cast<int>(participant_points.size());

    // For participant point x_i and packed slot point z, the coefficient is
    // L_i(z) = prod_{j != i}(z-x_j) / prod_{j != i}(x_i-x_j).
    // Compute each denominator inverse once, then all slot numerators with
    // prefix/suffix products.  This is algebraically identical to the former
    // nested formula but replaces O(k*n^2) inversions by only n inversions.
    std::vector<F> denominator_inverse(
        static_cast<size_t>(world_size), F(0));
    for (int i = 0; i < world_size; ++i) {
        F denominator(1);
        const F xi = participant_points[static_cast<size_t>(i)];
        for (int j = 0; j < world_size; ++j) {
            if (j == i) continue;
            denominator *=
                xi - participant_points[static_cast<size_t>(j)];
        }
        if (denominator == F(0)) return false;
        denominator_inverse[static_cast<size_t>(i)] =
            denominator.inv();
    }

    lagrange_by_rank->assign(
        static_cast<size_t>(world_size),
        std::vector<F>(static_cast<size_t>(k), F(0)));
    std::vector<F> prefix(
        static_cast<size_t>(world_size + 1), F(1));
    std::vector<F> suffix(
        static_cast<size_t>(world_size + 1), F(1));

    for (int slot = 0; slot < k; ++slot) {
        const F z = F::fastPow(
            root, static_cast<__uint128_t>(source_stride * slot));
        prefix[0] = F(1);
        for (int i = 0; i < world_size; ++i) {
            prefix[static_cast<size_t>(i + 1)] =
                prefix[static_cast<size_t>(i)] *
                (z - participant_points[static_cast<size_t>(i)]);
        }
        suffix[static_cast<size_t>(world_size)] = F(1);
        for (int i = world_size; i-- > 0;) {
            suffix[static_cast<size_t>(i)] =
                suffix[static_cast<size_t>(i + 1)] *
                (z - participant_points[static_cast<size_t>(i)]);
        }
        for (int i = 0; i < world_size; ++i) {
            const F numerator =
                prefix[static_cast<size_t>(i)] *
                suffix[static_cast<size_t>(i + 1)];
            (*lagrange_by_rank)[static_cast<size_t>(i)]
                               [static_cast<size_t>(slot)] =
                numerator *
                denominator_inverse[static_cast<size_t>(i)];
        }
    }
    return true;
}

bool build_local_witness_block_coefficients(
    const std::vector<F>& linkage_coefficients,
    int rank,
    int world_size,
    int k,
    int packed_width,
    size_t witness_slots,
    size_t constraint_slots,
    const std::vector<std::vector<std::pair<int,int>>>& pA,
    const std::vector<std::vector<std::pair<int,int>>>& pB,
    const std::vector<std::vector<std::pair<int,int>>>& pC,
    const std::vector<std::vector<F>>& lagrange_by_rank,
    std::vector<F>* block_coefficients,
    MPI_Comm comm) {
    if (!block_coefficients || rank < 0 || rank >= world_size ||
        world_size <= 0 || k <= 0 ||
        witness_slots == 0 ||
        witness_slots % static_cast<size_t>(world_size) != 0 ||
        witness_slots % static_cast<size_t>(k) != 0 ||
        lagrange_by_rank.size() != static_cast<size_t>(world_size) ||
        constraint_slots >
            std::numeric_limits<size_t>::max() / 3 ||
        linkage_coefficients.size() != 3 * constraint_slots)
        return false;

    (void)packed_width;
    const size_t slice =
        witness_slots / static_cast<size_t>(world_size);
    const size_t block_count =
        witness_slots / static_cast<size_t>(k);
    if (slice % static_cast<size_t>(k) != 0 ||
        block_count % static_cast<size_t>(world_size) != 0)
        return false;
    const size_t blocks_per_owner =
        slice / static_cast<size_t>(k);
    if (blocks_per_owner == 0 ||
        pA.size() != slice || pB.size() != slice || pC.size() != slice)
        return false;
    for (const auto& row : lagrange_by_rank)
        if (row.size() != static_cast<size_t>(k))
            return false;

    // Whether a packed witness block contributes to the public R1CS relation
    // depends only on the public relation partition, not on witness data or
    // Fiat--Shamir coins.  Nearly half of the blocks in the benchmark circuit
    // are structurally empty.  Exchange this public activity bitmap once and
    // omit coefficients that are identically zero for every receiver.
    const size_t mask_words =
        (blocks_per_owner + 63) / 64;
    if (mask_words == 0 ||
        mask_words >
            static_cast<size_t>(std::numeric_limits<int>::max()))
        return false;
    std::vector<u64> local_mask(mask_words, 0);
    std::vector<size_t> active_blocks;
    active_blocks.reserve(blocks_per_owner);
    for (size_t local_block = 0;
         local_block < blocks_per_owner; ++local_block) {
        bool active = false;
        const size_t base =
            local_block * static_cast<size_t>(k);
        for (int slot = 0; slot < k && !active; ++slot) {
            const size_t row =
                base + static_cast<size_t>(slot);
            active = !pA[row].empty() ||
                     !pB[row].empty() ||
                     !pC[row].empty();
        }
        if (!active) continue;
        local_mask[local_block / 64] |=
            (1ULL << (local_block % 64));
        active_blocks.push_back(local_block);
    }

    std::vector<u64> all_masks(
        static_cast<size_t>(world_size) * mask_words, 0);
    MPI_Allgather(
        local_mask.data(), static_cast<int>(mask_words), MPI_UINT64_T,
        all_masks.data(), static_cast<int>(mask_words), MPI_UINT64_T,
        comm);
    record_control_allgather(
        static_cast<uint64_t>(mask_words * sizeof(u64)),
        world_size);

    std::vector<size_t> active_counts(
        static_cast<size_t>(world_size), 0);
    for (int owner = 0; owner < world_size; ++owner) {
        const size_t mask_base =
            static_cast<size_t>(owner) * mask_words;
        size_t count = 0;
        for (size_t word = 0; word < mask_words; ++word) {
            u64 bits = all_masks[mask_base + word];
            if (word + 1 == mask_words &&
                blocks_per_owner % 64 != 0) {
                const unsigned valid_bits =
                    static_cast<unsigned>(blocks_per_owner % 64);
                bits &= (1ULL << valid_bits) - 1ULL;
            }
#if defined(__GNUC__) || defined(__clang__)
            count += static_cast<size_t>(__builtin_popcountll(bits));
#else
            while (bits) {
                bits &= bits - 1;
                ++count;
            }
#endif
        }
        active_counts[static_cast<size_t>(owner)] = count;
    }
    if (active_counts[static_cast<size_t>(rank)] != active_blocks.size())
        return false;

    std::vector<int> compact_index(
        blocks_per_owner, -1);
    for (size_t i = 0; i < active_blocks.size(); ++i)
        compact_index[active_blocks[i]] =
            static_cast<int>(i);

    // send_fields[target_rank][active_local_block] contains the final
    // coefficient reconstructed by target_rank.  Structurally empty blocks
    // are omitted from both computation and transport.
    const size_t local_active = active_blocks.size();
    if (local_active >
        static_cast<size_t>(std::numeric_limits<int>::max() / 2))
        return false;
    std::vector<F> send_fields(
        static_cast<size_t>(world_size) * local_active, F(0));
    const size_t owner_block_base =
        static_cast<size_t>(rank) * blocks_per_owner;
    const std::vector<
        const std::vector<std::vector<std::pair<int,int>>>*> lanes = {
            &pA, &pB, &pC};

    for (size_t local_wire = 0; local_wire < slice; ++local_wire) {
        const size_t global_wire =
            static_cast<size_t>(rank) * slice + local_wire;
        const size_t global_block =
            global_wire / static_cast<size_t>(k);
        const size_t local_block =
            global_block - owner_block_base;
        const int compact =
            compact_index[local_block];
        if (compact < 0) continue;
        const size_t slot =
            global_wire % static_cast<size_t>(k);

        F coefficient(0);
        for (size_t lane = 0; lane < lanes.size(); ++lane) {
            const auto& row = (*lanes[lane])[local_wire];
            for (const auto& entry : row) {
                if (entry.first < 0 || entry.second < 0 ||
                    static_cast<size_t>(entry.first) != global_wire ||
                    static_cast<size_t>(entry.second) >= constraint_slots)
                    return false;
                coefficient += linkage_coefficients[
                    lane * constraint_slots +
                    static_cast<size_t>(entry.second)];
            }
        }
        for (int target_rank = 0;
             target_rank < world_size; ++target_rank) {
            send_fields[
                static_cast<size_t>(target_rank) * local_active +
                static_cast<size_t>(compact)] +=
                coefficient *
                lagrange_by_rank[
                    static_cast<size_t>(target_rank)][slot];
        }
    }

    std::vector<int> send_counts(
        static_cast<size_t>(world_size), 0);
    std::vector<int> send_displacements(
        static_cast<size_t>(world_size), 0);
    const int local_words =
        static_cast<int>(2 * local_active);
    for (int target = 0; target < world_size; ++target) {
        send_counts[static_cast<size_t>(target)] =
            local_words;
        if (target > 0) {
            const long long displacement =
                static_cast<long long>(target) *
                static_cast<long long>(local_words);
            if (displacement >
                std::numeric_limits<int>::max())
                return false;
            send_displacements[
                static_cast<size_t>(target)] =
                static_cast<int>(displacement);
        }
    }

    std::vector<int> recv_counts(
        static_cast<size_t>(world_size), 0);
    std::vector<int> recv_displacements(
        static_cast<size_t>(world_size), 0);
    size_t total_recv_words = 0;
    for (int owner = 0; owner < world_size; ++owner) {
        const size_t owner_words =
            2 * active_counts[static_cast<size_t>(owner)];
        if (owner_words >
            static_cast<size_t>(std::numeric_limits<int>::max()) ||
            total_recv_words >
            static_cast<size_t>(std::numeric_limits<int>::max()) -
                owner_words)
            return false;
        recv_counts[static_cast<size_t>(owner)] =
            static_cast<int>(owner_words);
        recv_displacements[static_cast<size_t>(owner)] =
            static_cast<int>(total_recv_words);
        total_recv_words += owner_words;
    }

    std::vector<u64> send_words(
        static_cast<size_t>(world_size) *
            static_cast<size_t>(local_words), 0);
    for (size_t i = 0; i < send_fields.size(); ++i) {
        send_words[2 * i] = send_fields[i].real;
        send_words[2 * i + 1] = send_fields[i].img;
    }
    std::vector<u64> recv_words(total_recv_words, 0);
    MPI_Alltoallv(
        send_words.data(), send_counts.data(),
        send_displacements.data(), MPI_UINT64_T,
        recv_words.data(), recv_counts.data(),
        recv_displacements.data(), MPI_UINT64_T,
        comm);

    uint64_t sent_words_to_peers = 0;
    uint64_t recv_words_from_peers = 0;
    uint64_t sent_messages = 0;
    uint64_t recv_messages = 0;
    for (int peer = 0; peer < world_size; ++peer) {
        if (peer == rank) continue;
        const uint64_t sent =
            static_cast<uint64_t>(
                send_counts[static_cast<size_t>(peer)]);
        const uint64_t recv =
            static_cast<uint64_t>(
                recv_counts[static_cast<size_t>(peer)]);
        sent_words_to_peers += sent;
        recv_words_from_peers += recv;
        sent_messages += sent ? 1ULL : 0ULL;
        recv_messages += recv ? 1ULL : 0ULL;
    }
    experiment_add_protocol_control_traffic(
        sent_words_to_peers * sizeof(u64),
        recv_words_from_peers * sizeof(u64),
        sent_messages, recv_messages, 1);

    block_coefficients->assign(block_count, F(0));
    for (int owner = 0; owner < world_size; ++owner) {
        const size_t mask_base =
            static_cast<size_t>(owner) * mask_words;
        size_t compact = 0;
        const size_t recv_base =
            static_cast<size_t>(
                recv_displacements[
                    static_cast<size_t>(owner)]);
        const size_t block_base =
            static_cast<size_t>(owner) * blocks_per_owner;
        for (size_t local_block = 0;
             local_block < blocks_per_owner; ++local_block) {
            const bool active =
                (all_masks[
                    mask_base + local_block / 64] >>
                    (local_block % 64)) & 1ULL;
            if (!active) continue;
            if (compact >=
                active_counts[static_cast<size_t>(owner)])
                return false;
            const size_t word_offset =
                recv_base + 2 * compact;
            if (word_offset + 1 >= recv_words.size())
                return false;
            (*block_coefficients)[
                block_base + local_block] = F(
                    static_cast<long long>(
                        recv_words[word_offset] % F::mod),
                    static_cast<long long>(
                        recv_words[word_offset + 1] % F::mod));
            ++compact;
        }
        if (compact !=
            active_counts[static_cast<size_t>(owner)])
            return false;
    }
    return true;
}

size_t validity_thread_count(size_t work_items, int world_size) {
    if (work_items < 4096 ||
        std::getenv("PVIA_DISABLE_VALIDITY_PARALLEL"))
        return 1;
    const char* explicit_value =
        std::getenv("PVIA_VALIDITY_THREADS");
    if (explicit_value && *explicit_value) {
        char* end = nullptr;
        const unsigned long parsed =
            std::strtoul(explicit_value, &end, 10);
        if (end != explicit_value && *end == '\0' && parsed > 0)
            return std::max<size_t>(
                1, std::min<size_t>(
                    static_cast<size_t>(parsed), work_items));
    }
    size_t local_ranks =
        world_size > 0 ? static_cast<size_t>(world_size) : 1;
    const char* local_size =
        std::getenv("OMPI_COMM_WORLD_LOCAL_SIZE");
    if (local_size && *local_size) {
        char* end = nullptr;
        const unsigned long parsed =
            std::strtoul(local_size, &end, 10);
        if (end != local_size && *end == '\0' && parsed > 0)
            local_ranks = static_cast<size_t>(parsed);
    }
    const unsigned hw = std::thread::hardware_concurrency();
    size_t per_rank = 1;
    if (hw != 0)
        per_rank = std::max<size_t>(
            1, static_cast<size_t>(hw) /
                   std::max<size_t>(1, local_ranks));
    constexpr size_t AUTO_THREAD_CAP = 4;
    return std::max<size_t>(
        1, std::min({AUTO_THREAD_CAP, per_rank, work_items}));
}

template <typename Fn>
F parallel_field_sum(
    size_t work_items, int world_size, Fn&& fn) {
    if (work_items == 0) return F(0);
    const size_t threads =
        validity_thread_count(work_items, world_size);
    if (threads == 1)
        return fn(0, work_items);

    const size_t chunk =
        (work_items + threads - 1) / threads;
    std::vector<F> partials(threads, F(0));
    std::vector<std::thread> workers;
    workers.reserve(threads);
    for (size_t worker = 0; worker < threads; ++worker) {
        const size_t begin = worker * chunk;
        const size_t end =
            std::min(work_items, begin + chunk);
        if (begin >= end) break;
        workers.emplace_back(
            [&, worker, begin, end]() {
                partials[worker] = fn(begin, end);
            });
    }
    for (auto& worker : workers) worker.join();
    F total(0);
    for (const F& partial : partials)
        total += partial;
    return total;
}

bool collective_shape_ok(bool local_ok, MPI_Comm comm) {
    int local = local_ok ? 1 : 0;
    int global = 0;
    int world_size = 0;
    MPI_Comm_size(comm, &world_size);
    MPI_Allreduce(&local, &global, 1, MPI_INT, MPI_MIN, comm);
    record_control_allreduce(sizeof(int), world_size);
    return global == 1;
}

} // namespace

bool run_initial_packed_validity_gate(
    Runtime& runtime,
    const std::vector<F>& witness_share,
    const std::vector<F>& vL_share,
    const std::vector<F>& vR_share,
    const std::vector<F>& vO_share,
    const std::vector<std::vector<std::pair<int,int>>>& pA,
    const std::vector<std::vector<std::pair<int,int>>>& pB,
    const std::vector<std::vector<std::pair<int,int>>>& pC,
    const std::vector<StateId>& input_states,
    int k,
    int packed_width,
    InitialValidityGateResult* result,
    MPI_Comm comm) {
    if (!result) return false;
    *result = InitialValidityGateResult{};
    if (!runtime.enabled()) {
        result->valid = true;
        return true;
    }
    ExperimentDurationScope duration_scope(
        ExperimentDurationKind::INITIAL_VALIDITY);
    ExperimentControlTrafficScope traffic_scope(
        ExperimentControlTrafficKind::INITIAL_VALIDITY);

    int rank = -1;
    int world_size = 0;
    MPI_Comm_rank(comm, &rank);
    MPI_Comm_size(comm, &world_size);

    const char* relation_cache_path =
        std::getenv("PVIA_VALIDITY_RELATION_CACHE_FILE");
    const bool local_cache_requested =
        relation_cache_path && *relation_cache_path;

    const bool local_shape_ok =
        rank >= 0 &&
        world_size == runtime.world_size() &&
        world_size >= 4 &&
        k > 0 &&
        packed_width > k &&
        packed_width * 2 == world_size &&
        k * 4 == world_size &&
        !witness_share.empty() &&
        !vL_share.empty() &&
        vL_share.size() == vR_share.size() &&
        vL_share.size() == vO_share.size();
    const int local_shape_cache[2] = {
        local_shape_ok ? 1 : 0,
        local_cache_requested ? 1 : 0};
    int global_shape_cache[2] = {0, 0};
    MPI_Allreduce(
        local_shape_cache, global_shape_cache,
        2, MPI_INT, MPI_SUM, comm);
    record_control_allreduce(
        2 * sizeof(int), world_size);
    if (global_shape_cache[0] != world_size ||
        (global_shape_cache[1] != 0 &&
         global_shape_cache[1] != world_size))
        return false;
    const bool use_relation_cache =
        global_shape_cache[1] == world_size;

    int domain_log = 0;
    if (!exact_log2(2 * world_size, &domain_log))
        return false;

    const int threshold = (world_size - 1) / 3;
    if (threshold <= 0 || 3 * threshold >= world_size)
        return false;

    const std::vector<F> expected_marker = {F(1)};
    std::vector<OperationRef> validation_predecessors;
    const OperationRef init_predecessor =
        runtime.latest_operation_ref(Phase::INIT);
    if (init_predecessor.object_id != 0)
        validation_predecessors.push_back(init_predecessor);
    const RecordId validation_record = runtime.register_vector_operation(
        Phase::INIT, 1, Obligation::DERIVE,
        expected_marker, validation_predecessors);
    if (validation_record == 0)
        return false;
    runtime.bind_state_dependencies(validation_record, input_states);
    const CheckpointId validation_checkpoint =
        runtime.checkpoint_id(Phase::INIT, 1);
    if (validation_checkpoint == 0)
        return false;

    AuthenticatedMpcExchange exchange(rank, world_size, comm);
    ReferenceShamirMpc mpc(rank, world_size, threshold, comm);
    if (!mpc.valid())
        return false;
    bool authenticated_transport_used = false;
    Digest transport_capability_binding{};
    if (exchange.production_authenticated_ready()) {
        if (!mpc.SetAuthenticatedTransport(
                &exchange, runtime.session_id(), validation_checkpoint))
            return false;
        authenticated_transport_used = true;
        transport_capability_binding = exchange.ProductionCapabilityBinding();
        if (transport_capability_binding == Digest{})
            return false;
    }

    bool strong_consistency_used = false;
    Digest consistency_capability_binding{};
    const MultiplicationConsistencyProofBackend* consistency_backend =
        MultiplicationConsistencyBackendRegistry::Current();
    const Digest consistency_acceptance_binding =
        MultiplicationConsistencyBackendRegistry::CurrentAcceptanceBinding();
    if (consistency_backend) {
        const auto capabilities = consistency_backend->Capabilities();
        if (!production_ready_multiplication_consistency_capabilities(
                capabilities) ||
            consistency_acceptance_binding == Digest{} ||
            !mpc.SetMultiplicationConsistencyProofBackend(
                consistency_backend) ||
            !mpc.multiplication_consistency_available())
            return false;
        consistency_capability_binding =
            mpc.multiplication_consistency_capability_binding();
        if (consistency_capability_binding == Digest{})
            return false;
        experiment_record_consistency_provider_status(
            true, true, true, capabilities.protocol_id);
        strong_consistency_used = true;
    } else {
        experiment_record_consistency_provider_status(
            false, false, false, 0);
    }

    Digest joint_seed{};
    Digest public_coin_binding{};
    if (!mpc.JointPublicSeed(&joint_seed, &public_coin_binding) ||
        joint_seed == Digest{} || public_coin_binding == Digest{})
        return false;

    const F root = getRootOfUnity(domain_log);
    std::vector<F> participant_points(static_cast<size_t>(world_size), F(0));
    for (int participant = 0; participant < world_size; ++participant) {
        participant_points[static_cast<size_t>(participant)] =
            F::fastPow(root, static_cast<__uint128_t>(2 * participant + 1));
    }

    const int source_stride = (2 * world_size) / packed_width;
    std::vector<std::vector<F>> lagrange_by_rank;
    if (!build_packed_lagrange_matrix(
            root, source_stride, participant_points, k,
            &lagrange_by_rank) ||
        lagrange_by_rank.size() != static_cast<size_t>(world_size))
        return false;
    const std::vector<F>& local_lagrange =
        lagrange_by_rank[static_cast<size_t>(rank)];

    const size_t witness_slots =
        witness_share.size() * static_cast<size_t>(k);
    const size_t constraint_slots =
        vL_share.size() * static_cast<size_t>(k);
    const Digest local_relation_binding = local_relation_partition_binding(
        pA, pB, pC, rank, world_size, witness_slots, constraint_slots);
    const Digest relation_binding = collective_relation_binding(
        local_relation_binding, world_size, comm);
    if (local_relation_binding == Digest{} || relation_binding == Digest{})
        return false;

    std::vector<F> linkage_coefficients;
    if (!expand_linkage_coefficients(
            joint_seed, relation_binding, runtime.session_id(),
            world_size, k, packed_width, constraint_slots,
            &linkage_coefficients))
        return false;

    std::vector<F> local_witness_block_coefficients;
    std::vector<uint32_t> active_witness_blocks;
    if (use_relation_cache) {
        InitialValidityRelationCache relation_cache;
        bool local_cache_ok =
            load_initial_validity_relation_cache(
                relation_cache_path,
                world_size, k, packed_width,
                witness_slots, constraint_slots,
                relation_binding, &relation_cache);
        if (local_cache_ok) {
            active_witness_blocks =
                relation_cache.active_blocks;
            local_cache_ok =
                compute_initial_validity_block_coefficients_from_cache(
                    relation_cache, linkage_coefficients, rank,
                    local_lagrange,
                    &local_witness_block_coefficients);
        }
        if (!collective_shape_ok(local_cache_ok, comm))
            return false;

        const char* crosscheck =
            std::getenv("PVIA_VALIDITY_RELATION_CACHE_CROSSCHECK");
        const bool local_crosscheck =
            crosscheck && *crosscheck &&
            std::string(crosscheck) != "0";
        int crosscheck_count = 0;
        const int local_crosscheck_word =
            local_crosscheck ? 1 : 0;
        MPI_Allreduce(
            &local_crosscheck_word, &crosscheck_count,
            1, MPI_INT, MPI_SUM, comm);
        record_control_allreduce(sizeof(int), world_size);
        if (crosscheck_count != 0 &&
            crosscheck_count != world_size)
            return false;

        if (crosscheck_count == world_size) {
            std::vector<F> network_coefficients;
            const bool network_ok =
                build_local_witness_block_coefficients(
                    linkage_coefficients,
                    rank, world_size, k, packed_width,
                    witness_slots, constraint_slots,
                    pA, pB, pC, lagrange_by_rank,
                    &network_coefficients, comm);
            const bool same =
                network_ok &&
                network_coefficients ==
                    local_witness_block_coefficients;
            if (!collective_shape_ok(same, comm))
                return false;
            if (rank == 0)
                std::cout
                    << "[PVIA][validity-relation-cache] crosscheck=PASS"
                    << " blocks="
                    << local_witness_block_coefficients.size()
                    << "\n";
        }
    } else {
        if (!build_local_witness_block_coefficients(
                linkage_coefficients,
                rank, world_size, k, packed_width,
                witness_slots, constraint_slots,
                pA, pB, pC, lagrange_by_rank,
                &local_witness_block_coefficients, comm))
            return false;
    }
    if (local_witness_block_coefficients.size() !=
        witness_share.size())
        return false;

    // Multiplicative R1CS residuals share the same final zero test, but use
    // a separate coefficient domain from the linear linkage relation.
    std::vector<F> multiplicative_coefficients;
    if (!expand_multiplicative_coefficients(
            joint_seed, runtime.session_id(), world_size,
            k, packed_width, vL_share.size(),
            &multiplicative_coefficients) ||
        multiplicative_coefficients.size() != constraint_slots)
        return false;

    // All terms below are finite-field sums.  Compute independent block
    // ranges in parallel and combine the thread-local sums afterwards.  This
    // is algebraically identical to the serial loop (no floating-point
    // rounding) and does not change any challenge or transcript input.
    const F lane_and_multiplicative =
        parallel_field_sum(
            vL_share.size(), world_size,
            [&](size_t begin, size_t end) {
                F subtotal(0);
                for (size_t block = begin; block < end; ++block) {
                    const size_t base =
                        block * static_cast<size_t>(k);

                    F left_weight(0);
                    F right_weight(0);
                    F output_weight(0);
                    F mul_weight(0);
                    for (int slot = 0; slot < k; ++slot) {
                        const size_t offset =
                            base + static_cast<size_t>(slot);
                        const F& lagrange =
                            local_lagrange[
                                static_cast<size_t>(slot)];
                        left_weight +=
                            linkage_coefficients[offset] *
                            lagrange;
                        right_weight +=
                            linkage_coefficients[
                                constraint_slots + offset] *
                            lagrange;
                        output_weight +=
                            linkage_coefficients[
                                2 * constraint_slots + offset] *
                            lagrange;
                        mul_weight +=
                            multiplicative_coefficients[offset] *
                            lagrange;
                    }

                    subtotal += left_weight * vL_share[block];
                    subtotal += right_weight * vR_share[block];
                    subtotal += output_weight * vO_share[block];

                    const F local_residual =
                        vL_share[block] * vR_share[block] -
                        vO_share[block];
                    subtotal += local_residual * mul_weight;
                }
                return subtotal;
            });

    F witness_linkage(0);
    if (use_relation_cache && !active_witness_blocks.empty()) {
        witness_linkage = parallel_field_sum(
            active_witness_blocks.size(), world_size,
            [&](size_t begin, size_t end) {
                F subtotal(0);
                for (size_t i = begin; i < end; ++i) {
                    const size_t block =
                        static_cast<size_t>(
                            active_witness_blocks[i]);
                    if (block >= witness_share.size())
                        continue;
                    subtotal +=
                        local_witness_block_coefficients[block] *
                        witness_share[block];
                }
                return subtotal;
            });
    } else {
        witness_linkage = parallel_field_sum(
            witness_share.size(), world_size,
            [&](size_t begin, size_t end) {
                F subtotal(0);
                for (size_t block = begin; block < end; ++block) {
                    const F& coefficient =
                        local_witness_block_coefficients[block];
                    if (coefficient == F(0)) continue;
                    subtotal +=
                        coefficient * witness_share[block];
                }
                return subtotal;
            });
    }

    // Independent serial cross-check of the parallel local residual sums.
    // This is an execution-consistency guard, not a malicious-secure proof.
    F serial_lane(0);
    for (size_t block = 0; block < vL_share.size(); ++block) {
        const size_t base = block * static_cast<size_t>(k);
        F lw(0), rw(0), ow(0), mw(0);
        for (int slot = 0; slot < k; ++slot) {
            const size_t offset = base + static_cast<size_t>(slot);
            const F& lagrange = local_lagrange[static_cast<size_t>(slot)];
            lw += linkage_coefficients[offset] * lagrange;
            rw += linkage_coefficients[constraint_slots + offset] * lagrange;
            ow += linkage_coefficients[2 * constraint_slots + offset] * lagrange;
            mw += multiplicative_coefficients[offset] * lagrange;
        }
        serial_lane += lw * vL_share[block];
        serial_lane += rw * vR_share[block];
        serial_lane += ow * vO_share[block];
        serial_lane += (vL_share[block] * vR_share[block] -
                        vO_share[block]) * mw;
    }
    F serial_witness(0);
    if (use_relation_cache && !active_witness_blocks.empty()) {
        for (uint32_t block : active_witness_blocks) {
            if (block >= witness_share.size()) return false;
            serial_witness += local_witness_block_coefficients[block] *
                              witness_share[block];
        }
    } else {
        for (size_t block = 0; block < witness_share.size(); ++block) {
            const F& coefficient = local_witness_block_coefficients[block];
            if (coefficient != F(0))
                serial_witness += coefficient * witness_share[block];
        }
    }
    const bool local_recomputed =
        serial_lane == lane_and_multiplicative &&
        serial_witness == witness_linkage &&
        serial_lane - serial_witness ==
            lane_and_multiplicative - witness_linkage;
    if (!collective_shape_ok(local_recomputed, comm)) return false;

    const F local_additive_contribution =
        lane_and_multiplicative - witness_linkage;

    // Commit to exact operands, coefficient streams, intermediates and output.
    // This digest binds the future ZK statement; it does not prove the relation.
    const std::vector<const std::vector<F>*> segments = {
        &witness_share, &vL_share, &vR_share, &vO_share, &local_lagrange,
        &linkage_coefficients, &multiplicative_coefficients,
        &local_witness_block_coefficients};
    const Digest material_digest = hash_field_segments(segments);
    if (material_digest == Digest{}) return false;
    std::vector<u64> words = {
        INITIAL_VALIDITY_CONTRIBUTION_DOMAIN, runtime.session_id(),
        validation_checkpoint, validation_record, static_cast<u64>(rank),
        static_cast<u64>(world_size), static_cast<u64>(k),
        static_cast<u64>(packed_width), static_cast<u64>(witness_share.size()),
        static_cast<u64>(vL_share.size()), static_cast<u64>(local_lagrange.size()),
        static_cast<u64>(linkage_coefficients.size()),
        static_cast<u64>(multiplicative_coefficients.size()),
        static_cast<u64>(local_witness_block_coefficients.size()),
        static_cast<u64>(active_witness_blocks.size()),
        use_relation_cache ? 1ULL : 0ULL};
    append_digest_words(joint_seed, &words);
    append_digest_words(public_coin_binding, &words);
    append_digest_words(relation_binding, &words);
    append_digest_words(material_digest, &words);
    for (uint32_t block : active_witness_blocks)
        words.push_back(static_cast<u64>(block));
    const F scalars[] = {lane_and_multiplicative, witness_linkage,
                         local_additive_contribution};
    for (const F& value : scalars) {
        words.push_back(value.real);
        words.push_back(value.img);
    }
    const Digest local_digest = hash_words(words);
    const Digest local_contribution_binding =
        collective_contribution_binding(local_digest, world_size, comm);
    if (local_contribution_binding == Digest{}) return false;

    F compressed_share(0);
    ReferenceLinearSharingProvenance compressed_provenance;
    Digest compressed_value_binding{};
    Digest compressed_sharing_binding{};
    const bool passive_local_sum_fast =
        !strong_consistency_used &&
        std::getenv("PVIA_DISABLE_PASSIVE_LOCAL_SUM_FAST") == nullptr;
    if (passive_local_sum_fast) {
        if (!mpc.ShareLocalSum(
                local_additive_contribution, &compressed_share,
                &compressed_value_binding,
                &compressed_sharing_binding) ||
            compressed_value_binding == Digest{} ||
            compressed_sharing_binding == Digest{})
            return false;
    } else {
        if (!mpc.ShareLocalSumWithProvenance(
                local_additive_contribution, &compressed_share,
                &compressed_provenance,
                &compressed_sharing_binding) ||
            compressed_sharing_binding == Digest{} ||
            !validate_reference_linear_sharing_provenance(
                compressed_provenance) ||
            compressed_provenance.local_share != compressed_share ||
            compressed_provenance.binding == Digest{})
            return false;
        compressed_value_binding =
            compressed_provenance.binding;
    }
    bool is_zero = false;
    Digest zero_test_binding{};
    Digest multiplication_consistency_binding{};
    if (strong_consistency_used) {
        std::vector<u64> zero_context_words = {
            INITIAL_VALIDITY_BIND_DOMAIN,
            runtime.session_id(),
            validation_checkpoint,
            validation_record,
            static_cast<u64>(world_size),
            static_cast<u64>(k),
            static_cast<u64>(packed_width),
            static_cast<u64>(vL_share.size())};
        append_digest_words(joint_seed, &zero_context_words);
        append_digest_words(relation_binding, &zero_context_words);
        append_digest_words(
            consistency_acceptance_binding, &zero_context_words);
        append_digest_words(
            compressed_provenance.binding, &zero_context_words);
        append_digest_words(local_contribution_binding, &zero_context_words);
        const Digest zero_context_binding = hash_words(zero_context_words);
        if (zero_context_binding == Digest{})
            return false;

        ReferenceMaskedZeroConsistencyContext zero_context;
        zero_context.sid = runtime.session_id();
        zero_context.checkpoint = validation_checkpoint;
        zero_context.multiplication_id = validation_record;
        zero_context.context_binding = zero_context_binding;
        if (!mpc.MaskedZeroTestWithConsistency(
                compressed_provenance, zero_context,
                &is_zero, &zero_test_binding,
                &multiplication_consistency_binding) ||
            zero_test_binding == Digest{} ||
            multiplication_consistency_binding == Digest{})
            return false;
    } else {
        if (!mpc.MaskedZeroTest(
                compressed_share, &is_zero, &zero_test_binding) ||
            zero_test_binding == Digest{})
            return false;
    }

    std::vector<u64> binding_words = {
        INITIAL_VALIDITY_BIND_DOMAIN,
        runtime.session_id(),
        static_cast<u64>(world_size),
        static_cast<u64>(k),
        static_cast<u64>(packed_width),
        static_cast<u64>(vL_share.size()),
        static_cast<u64>(threshold),
        is_zero ? 1ULL : 0ULL,
        authenticated_transport_used ? 1ULL : 0ULL,
        strong_consistency_used ? 1ULL : 0ULL};
    append_digest_words(joint_seed, &binding_words);
    append_digest_words(public_coin_binding, &binding_words);
    append_digest_words(relation_binding, &binding_words);
    append_digest_words(compressed_value_binding, &binding_words);
    append_digest_words(compressed_sharing_binding, &binding_words);
    append_digest_words(local_contribution_binding, &binding_words);
    if (authenticated_transport_used)
        append_digest_words(transport_capability_binding, &binding_words);
    if (strong_consistency_used) {
        append_digest_words(
            consistency_capability_binding, &binding_words);
        append_digest_words(
            consistency_acceptance_binding, &binding_words);
        append_digest_words(
            multiplication_consistency_binding, &binding_words);
    }
    append_digest_words(zero_test_binding, &binding_words);
    const Digest validation_binding = hash_words(binding_words);
    if (validation_binding == Digest{})
        return false;

    experiment_record_initial_validity(strong_consistency_used);

    result->executed = true;
    result->valid = is_zero;
    result->public_coin_binding = public_coin_binding;
    result->zero_test_binding = zero_test_binding;
    result->validation_binding = validation_binding;
    result->relation_definition_binding = relation_binding;
    result->transport_capability_binding = transport_capability_binding;
    result->compressed_sharing_binding = compressed_value_binding;
    result->consistency_capability_binding =
        consistency_capability_binding;
    result->consistency_acceptance_binding =
        consistency_acceptance_binding;
    result->multiplication_consistency_binding =
        multiplication_consistency_binding;
    result->local_contribution_binding = local_contribution_binding;
    result->authenticated_transport_used = authenticated_transport_used;
    result->strong_consistency_used = strong_consistency_used;
    result->packed_blocks = vL_share.size();
    result->linked_witness_slots = witness_slots;
    result->linked_constraint_slots = constraint_slots;
    result->reference_threshold = threshold;

    std::vector<u64> public_aux = {
        static_cast<u64>(world_size),
        static_cast<u64>(k),
        static_cast<u64>(packed_width),
        static_cast<u64>(vL_share.size()),
        static_cast<u64>(witness_slots),
        static_cast<u64>(constraint_slots),
        static_cast<u64>(threshold),
        authenticated_transport_used ? 1ULL : 0ULL,
        strong_consistency_used ? 1ULL : 0ULL};
    append_digest_words(relation_binding, &public_aux);
    append_digest_words(compressed_value_binding, &public_aux);
    if (authenticated_transport_used)
        append_digest_words(transport_capability_binding, &public_aux);
    if (strong_consistency_used) {
        append_digest_words(
            consistency_capability_binding, &public_aux);
        append_digest_words(
            consistency_acceptance_binding, &public_aux);
        append_digest_words(
            multiplication_consistency_binding, &public_aux);
    }
    append_digest_words(local_contribution_binding, &public_aux);
    append_digest_words(validation_binding, &public_aux);
    runtime.bind_public_word_aux(
        validation_record, AuditPublicAuxKind::GENERIC_WORDS, public_aux);
    const std::vector<F> actual_marker = {is_zero ? F(1) : F(0)};
    runtime.activate_vector(validation_record, actual_marker);
    runtime.record_pending_relation_violation();
    runtime.consume_pending();
    runtime.seal_checkpoint_instance(Phase::INIT, 1);

    result->validation_operation.owner = static_cast<uint32_t>(rank);
    result->validation_operation.object_id = validation_record;

    if (!is_zero)
        return true;

    std::vector<F> validated_material = witness_share;
    validated_material.push_back(digest_to_field(validation_binding));
    const StateId validated_state = runtime.import_state(
        "validated_witness", Phase::INIT, validated_material);
    if (validated_state == 0)
        return false;

    result->validated_state = validated_state;

    if (runtime.verbose() && rank == 0) {
        std::cout << "[PVIA][validity] PASS blocks="
                  << result->packed_blocks
                  << " witness_slots=" << result->linked_witness_slots
                  << " constraint_slots=" << result->linked_constraint_slots
                  << " reference_threshold=" << threshold
                  << " bound_transport="
                  << (authenticated_transport_used ? "yes" : "no") << "\n";
    }
    return true;
}

} // namespace pvia
