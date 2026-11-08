#include "InitialValidityRelationCache.hpp"

#include "../../Blake/blake3.h"

#include <array>
#include <atomic>
#include <thread>
#include <cstdlib>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace pvia {
namespace {

constexpr u64 RELATION_CACHE_MAGIC = 0x5056495652434143ULL; // PVIVRCAC
constexpr u64 RELATION_CACHE_VERSION = 1ULL;
constexpr u64 RELATION_PART_DOMAIN = 0x5056495652504152ULL; // PVIVRPAR
constexpr u64 RELATION_BIND_DOMAIN = 0x505649565242494eULL; // PVIVRBIN

size_t parse_positive_size_env(const char* name, size_t fallback) {
    const char* value = std::getenv(name);
    if (!value || !*value) return fallback;
    char* end = nullptr;
    errno = 0;
    const unsigned long long parsed =
        std::strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed == 0)
        return fallback;
    return static_cast<size_t>(parsed);
}

size_t relation_cache_thread_count(
    size_t work_items, int world_size, size_t witness_slots) {
    if (work_items <= 1 || witness_slots < 8192)
        return 1;
    const size_t explicit_threads =
        parse_positive_size_env("PVIA_RELATION_CACHE_THREADS", 0);
    if (explicit_threads != 0)
        return std::max<size_t>(
            1, std::min(explicit_threads, work_items));

    size_t local_ranks = parse_positive_size_env(
        "OMPI_COMM_WORLD_LOCAL_SIZE",
        world_size > 0 ? static_cast<size_t>(world_size) : 1);
    if (local_ranks == 0) local_ranks = 1;
    const unsigned hw = std::thread::hardware_concurrency();
    size_t per_rank_budget = 1;
    if (hw != 0)
        per_rank_budget = std::max<size_t>(
            1, static_cast<size_t>(hw) / local_ranks);
    constexpr size_t AUTO_THREAD_CAP = 4;
    return std::max<size_t>(
        1, std::min({AUTO_THREAD_CAP, per_rank_budget, work_items}));
}

template <typename Fn>
void parallel_cache_chunks(size_t count, size_t threads, Fn&& fn) {
    if (count == 0) return;
    threads = std::max<size_t>(1, std::min(threads, count));
    if (threads == 1) {
        fn(0, count);
        return;
    }
    const size_t chunk = (count + threads - 1) / threads;
    std::vector<std::thread> workers;
    workers.reserve(threads);
    for (size_t worker = 0; worker < threads; ++worker) {
        const size_t begin = worker * chunk;
        const size_t end = std::min(count, begin + chunk);
        if (begin >= end) break;
        workers.emplace_back([&, begin, end]() { fn(begin, end); });
    }
    for (auto& worker : workers) worker.join();
}

class WordHasher {
public:
    void append(u64 word) {
        buffer_[used_++] = word;
        if (used_ == buffer_.size()) flush();
    }

    Digest finish() {
        flush();
        Digest out{};
        blake3_hasher_finalize(&hasher_, out.bytes.data(), out.bytes.size());
        return out;
    }

    WordHasher() {
        blake3_hasher_init(&hasher_);
    }

private:
    void flush() {
        if (used_ == 0) return;
        blake3_hasher_update(
            &hasher_,
            reinterpret_cast<const uint8_t*>(buffer_.data()),
            used_ * sizeof(u64));
        used_ = 0;
    }

    blake3_hasher hasher_{};
    std::array<u64, 1024> buffer_{};
    size_t used_ = 0;
};

void append_digest_words(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

Digest relation_binding_from_cache(
    const InitialValidityRelationCache& cache,
    std::vector<uint32_t>* active_blocks = nullptr) {
    if (cache.world_size < 4 || cache.k <= 0 ||
        cache.packed_width <= cache.k ||
        cache.packed_width * 2 != cache.world_size ||
        cache.k * 4 != cache.world_size ||
        cache.witness_slots == 0 ||
        cache.witness_slots %
            static_cast<size_t>(cache.world_size) != 0 ||
        cache.witness_slots %
            static_cast<size_t>(cache.k) != 0 ||
        cache.constraint_slots == 0 ||
        cache.witness_slots >
            static_cast<size_t>(
                std::numeric_limits<uint32_t>::max()))
        return {};

    for (size_t lane = 0; lane < 3; ++lane) {
        const auto& offsets = cache.row_offsets[lane];
        const auto& indices = cache.constraint_indices[lane];
        if (offsets.size() != cache.witness_slots + 1 ||
            offsets.empty() || offsets.front() != 0 ||
            offsets.back() != indices.size())
            return {};
    }

    const size_t slice =
        cache.witness_slots / static_cast<size_t>(cache.world_size);
    if (slice % static_cast<size_t>(cache.k) != 0)
        return {};
    const size_t blocks_per_owner =
        slice / static_cast<size_t>(cache.k);
    const size_t block_count =
        cache.witness_slots / static_cast<size_t>(cache.k);
    if (block_count >
        static_cast<size_t>(std::numeric_limits<uint32_t>::max()))
        return {};

    std::vector<Digest> partitions(
        static_cast<size_t>(cache.world_size));
    std::vector<std::vector<uint32_t>> active_by_owner;
    if (active_blocks)
        active_by_owner.resize(static_cast<size_t>(cache.world_size));

    std::atomic<bool> structurally_valid{true};
    const size_t threads = relation_cache_thread_count(
        static_cast<size_t>(cache.world_size),
        cache.world_size, cache.witness_slots);
    parallel_cache_chunks(
        static_cast<size_t>(cache.world_size), threads,
        [&](size_t owner_begin, size_t owner_end) {
            for (size_t owner_index = owner_begin;
                 owner_index < owner_end; ++owner_index) {
                const int owner = static_cast<int>(owner_index);
                WordHasher hasher;
                hasher.append(RELATION_PART_DOMAIN);
                hasher.append(static_cast<u64>(owner));
                hasher.append(static_cast<u64>(cache.world_size));
                hasher.append(static_cast<u64>(cache.witness_slots));
                hasher.append(static_cast<u64>(cache.constraint_slots));
                hasher.append(static_cast<u64>(slice));

                std::vector<uint8_t> active_flags;
                if (active_blocks)
                    active_flags.assign(blocks_per_owner, 0);

                const size_t first_wire = owner_index * slice;
                for (size_t lane = 0; lane < 3; ++lane) {
                    hasher.append(static_cast<u64>(lane));
                    const auto& offsets = cache.row_offsets[lane];
                    const auto& indices = cache.constraint_indices[lane];
                    for (size_t local_wire = 0;
                         local_wire < slice; ++local_wire) {
                        const size_t wire = first_wire + local_wire;
                        const uint32_t begin = offsets[wire];
                        const uint32_t finish = offsets[wire + 1];
                        if (finish < begin ||
                            static_cast<size_t>(finish) >
                                indices.size()) {
                            structurally_valid.store(
                                false, std::memory_order_relaxed);
                            continue;
                        }
                        if (active_blocks && begin != finish)
                            active_flags[
                                local_wire /
                                static_cast<size_t>(cache.k)] = 1;
                        hasher.append(static_cast<u64>(wire));
                        hasher.append(static_cast<u64>(finish - begin));
                        for (uint32_t cursor = begin;
                             cursor < finish; ++cursor) {
                            const uint32_t index = indices[cursor];
                            if (static_cast<size_t>(index) >=
                                cache.constraint_slots) {
                                structurally_valid.store(
                                    false, std::memory_order_relaxed);
                                continue;
                            }
                            hasher.append(static_cast<u64>(wire));
                            hasher.append(static_cast<u64>(index));
                        }
                    }
                }
                partitions[owner_index] = hasher.finish();

                if (active_blocks) {
                    auto& owner_blocks = active_by_owner[owner_index];
                    owner_blocks.reserve(blocks_per_owner);
                    const size_t owner_block_base =
                        owner_index * blocks_per_owner;
                    for (size_t local_block = 0;
                         local_block < blocks_per_owner; ++local_block) {
                        if (!active_flags[local_block]) continue;
                        owner_blocks.push_back(
                            static_cast<uint32_t>(
                                owner_block_base + local_block));
                    }
                }
            }
        });

    if (!structurally_valid.load(std::memory_order_relaxed))
        return {};
    for (const Digest& part : partitions)
        if (part == Digest{}) return {};

    if (active_blocks) {
        active_blocks->clear();
        size_t total_active = 0;
        for (const auto& owner_blocks : active_by_owner)
            total_active += owner_blocks.size();
        active_blocks->reserve(total_active);
        for (const auto& owner_blocks : active_by_owner)
            active_blocks->insert(
                active_blocks->end(),
                owner_blocks.begin(), owner_blocks.end());
    }

    std::vector<u64> words = {
        RELATION_BIND_DOMAIN,
        static_cast<u64>(cache.world_size)};
    words.reserve(2 + 4 * partitions.size());
    for (const Digest& part : partitions)
        append_digest_words(part, &words);
    return hash_words(words);
}

template <typename T>
bool write_vector(std::ofstream* out, const std::vector<T>& values) {
    if (!out) return false;
    if (!values.empty()) {
        out->write(
            reinterpret_cast<const char*>(values.data()),
            static_cast<std::streamsize>(values.size() * sizeof(T)));
    }
    return static_cast<bool>(*out);
}

template <typename T>
bool read_vector(
    std::ifstream* in, size_t count, std::vector<T>* values) {
    if (!in || !values ||
        count > std::numeric_limits<size_t>::max() / sizeof(T))
        return false;
    values->assign(count, T{});
    if (count != 0) {
        in->read(
            reinterpret_cast<char*>(values->data()),
            static_cast<std::streamsize>(count * sizeof(T)));
    }
    return static_cast<bool>(*in);
}

bool cache_from_full_relation(
    const std::vector<std::vector<std::pair<int,int>>>& full_a,
    const std::vector<std::vector<std::pair<int,int>>>& full_b,
    const std::vector<std::vector<std::pair<int,int>>>& full_c,
    int world_size, int k, int packed_width,
    size_t witness_slots, size_t constraint_slots,
    InitialValidityRelationCache* cache) {
    if (!cache || full_a.size() != witness_slots ||
        full_b.size() != witness_slots ||
        full_c.size() != witness_slots ||
        constraint_slots > std::numeric_limits<uint32_t>::max())
        return false;

    InitialValidityRelationCache out;
    out.world_size = world_size;
    out.k = k;
    out.packed_width = packed_width;
    out.witness_slots = witness_slots;
    out.constraint_slots = constraint_slots;

    const std::array<
        const std::vector<std::vector<std::pair<int,int>>>*, 3> lanes = {
            &full_a, &full_b, &full_c};

    for (size_t lane = 0; lane < lanes.size(); ++lane) {
        auto& offsets = out.row_offsets[lane];
        auto& indices = out.constraint_indices[lane];
        offsets.resize(witness_slots + 1, 0);
        size_t total = 0;
        for (const auto& row : *lanes[lane]) {
            if (total >
                static_cast<size_t>(std::numeric_limits<uint32_t>::max()) -
                    row.size())
                return false;
            total += row.size();
        }
        indices.reserve(total);

        for (size_t wire = 0; wire < witness_slots; ++wire) {
            offsets[wire] =
                static_cast<uint32_t>(indices.size());
            for (const auto& entry : (*lanes[lane])[wire]) {
                if (entry.first < 0 || entry.second < 0 ||
                    static_cast<size_t>(entry.first) != wire ||
                    static_cast<size_t>(entry.second) >= constraint_slots)
                    return false;
                indices.push_back(
                    static_cast<uint32_t>(entry.second));
            }
        }
        offsets[witness_slots] =
            static_cast<uint32_t>(indices.size());
    }

    out.relation_binding =
        relation_binding_from_cache(out, &out.active_blocks);
    if (out.relation_binding == Digest{}) return false;
    out.validated = true;
    *cache = std::move(out);
    return true;
}

} // namespace

bool write_initial_validity_relation_cache(
    const std::string& path,
    const std::vector<std::vector<std::pair<int,int>>>& full_a,
    const std::vector<std::vector<std::pair<int,int>>>& full_b,
    const std::vector<std::vector<std::pair<int,int>>>& full_c,
    int world_size, int k, int packed_width,
    size_t witness_slots, size_t constraint_slots,
    Digest* relation_binding) {
    if (path.empty()) return false;

    InitialValidityRelationCache cache;
    if (!cache_from_full_relation(
            full_a, full_b, full_c,
            world_size, k, packed_width,
            witness_slots, constraint_slots, &cache))
        return false;

    const std::array<u64, 10> header = {
        RELATION_CACHE_MAGIC,
        RELATION_CACHE_VERSION,
        static_cast<u64>(world_size),
        static_cast<u64>(k),
        static_cast<u64>(packed_width),
        static_cast<u64>(witness_slots),
        static_cast<u64>(constraint_slots),
        static_cast<u64>(cache.constraint_indices[0].size()),
        static_cast<u64>(cache.constraint_indices[1].size()),
        static_cast<u64>(cache.constraint_indices[2].size())};

    std::ostringstream tmp_name;
    tmp_name << path << ".tmp."
             << static_cast<unsigned long long>(::getpid());
    const std::string tmp = tmp_name.str();
    std::ofstream out(tmp.c_str(), std::ios::binary | std::ios::trunc);
    if (!out) return false;

    out.write(
        reinterpret_cast<const char*>(header.data()),
        static_cast<std::streamsize>(header.size() * sizeof(u64)));
    out.write(
        reinterpret_cast<const char*>(cache.relation_binding.bytes.data()),
        static_cast<std::streamsize>(cache.relation_binding.bytes.size()));
    for (size_t lane = 0; lane < 3; ++lane) {
        if (!write_vector(&out, cache.row_offsets[lane]) ||
            !write_vector(&out, cache.constraint_indices[lane])) {
            out.close();
            ::unlink(tmp.c_str());
            return false;
        }
    }
    out.flush();
    const bool ok = static_cast<bool>(out);
    out.close();
    if (!ok || ::chmod(tmp.c_str(), 0644) != 0 ||
        ::rename(tmp.c_str(), path.c_str()) != 0) {
        ::unlink(tmp.c_str());
        return false;
    }
    if (relation_binding)
        *relation_binding = cache.relation_binding;
    return true;
}

bool load_initial_validity_relation_cache(
    const std::string& path,
    int world_size, int k, int packed_width,
    size_t witness_slots, size_t constraint_slots,
    const Digest& expected_relation_binding,
    InitialValidityRelationCache* cache) {
    if (!cache || path.empty() ||
        expected_relation_binding == Digest{})
        return false;

    std::ifstream in(path.c_str(), std::ios::binary);
    if (!in) return false;

    std::array<u64, 10> header{};
    in.read(
        reinterpret_cast<char*>(header.data()),
        static_cast<std::streamsize>(header.size() * sizeof(u64)));
    if (!in ||
        header[0] != RELATION_CACHE_MAGIC ||
        header[1] != RELATION_CACHE_VERSION ||
        header[2] != static_cast<u64>(world_size) ||
        header[3] != static_cast<u64>(k) ||
        header[4] != static_cast<u64>(packed_width) ||
        header[5] != static_cast<u64>(witness_slots) ||
        header[6] != static_cast<u64>(constraint_slots))
        return false;

    Digest stored_binding{};
    in.read(
        reinterpret_cast<char*>(stored_binding.bytes.data()),
        static_cast<std::streamsize>(stored_binding.bytes.size()));
    if (!in || stored_binding == Digest{})
        return false;

    InitialValidityRelationCache out;
    out.world_size = world_size;
    out.k = k;
    out.packed_width = packed_width;
    out.witness_slots = witness_slots;
    out.constraint_slots = constraint_slots;
    out.relation_binding = stored_binding;

    for (size_t lane = 0; lane < 3; ++lane) {
        const u64 count64 = header[7 + lane];
        if (count64 > std::numeric_limits<uint32_t>::max())
            return false;
        if (!read_vector(
                &in, witness_slots + 1,
                &out.row_offsets[lane]) ||
            !read_vector(
                &in, static_cast<size_t>(count64),
                &out.constraint_indices[lane]))
            return false;
    }

    char trailing = 0;
    if (in.read(&trailing, 1))
        return false;
    const Digest recomputed =
        relation_binding_from_cache(out, &out.active_blocks);
    if (recomputed == Digest{} ||
        recomputed != stored_binding ||
        recomputed != expected_relation_binding)
        return false;

    out.validated = true;
    *cache = std::move(out);
    return true;
}

bool compute_initial_validity_block_coefficients_from_cache(
    const InitialValidityRelationCache& cache,
    const std::vector<F>& linkage_coefficients,
    int rank,
    const std::vector<F>& local_lagrange_weights,
    std::vector<F>* block_coefficients) {
    if (!block_coefficients ||
        !cache.validated ||
        cache.relation_binding == Digest{} ||
        rank < 0 || rank >= cache.world_size ||
        cache.k <= 0 ||
        local_lagrange_weights.size() !=
            static_cast<size_t>(cache.k) ||
        cache.constraint_slots >
            std::numeric_limits<size_t>::max() / 3 ||
        linkage_coefficients.size() !=
            3 * cache.constraint_slots)
        return false;

    const size_t block_count =
        cache.witness_slots / static_cast<size_t>(cache.k);
    block_coefficients->assign(block_count, F(0));

    const size_t active_count = cache.active_blocks.size();
    const size_t threads = relation_cache_thread_count(
        active_count, cache.world_size, cache.witness_slots);
    parallel_cache_chunks(
        active_count, threads,
        [&](size_t active_begin, size_t active_end) {
            for (size_t active_index = active_begin;
                 active_index < active_end; ++active_index) {
                const size_t block =
                    static_cast<size_t>(
                        cache.active_blocks[active_index]);
                if (block >= block_count) continue;
                F block_coefficient(0);
                const size_t first_wire =
                    block * static_cast<size_t>(cache.k);
                for (int slot = 0; slot < cache.k; ++slot) {
                    const size_t wire =
                        first_wire + static_cast<size_t>(slot);
                    // Accumulate the two prime-field limbs without reducing
                    // after every sparse relation entry.  Each lane stores at
                    // most UINT32_MAX indices, so even the sum across all
                    // three lanes stays far below the 128-bit accumulator
                    // limit (3 * 2^32 * (2^61 - 1) < 2^95).
                    __uint128_t real_sum = 0;
                    __uint128_t img_sum = 0;
                    bool active = false;
                    for (size_t lane = 0; lane < 3; ++lane) {
                        const auto& offsets = cache.row_offsets[lane];
                        const auto& indices =
                            cache.constraint_indices[lane];
                        const uint32_t begin = offsets[wire];
                        const uint32_t finish = offsets[wire + 1];
                        active = active || begin != finish;
                        const size_t base =
                            lane * cache.constraint_slots;
                        for (uint32_t cursor = begin;
                             cursor < finish; ++cursor) {
                            const F& term =
                                linkage_coefficients[
                                    base + indices[cursor]];
                            real_sum +=
                                static_cast<__uint128_t>(term.real);
                            img_sum +=
                                static_cast<__uint128_t>(term.img);
                        }
                    }
                    if (active) {
                        const F coefficient(
                            static_cast<long long>(
                                real_sum % F::mod),
                            static_cast<long long>(
                                img_sum % F::mod));
                        block_coefficient +=
                            coefficient *
                            local_lagrange_weights[
                                static_cast<size_t>(slot)];
                    }
                }
                (*block_coefficients)[block] =
                    block_coefficient;
            }
        });
    return true;
}

} // namespace pvia
