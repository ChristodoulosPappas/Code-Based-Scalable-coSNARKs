#include "JointPackedPreprocessing.hpp"
#include "ProtocolTrafficMetrics.hpp"
#include "../utils.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <atomic>
#include <cstdlib>
#include <thread>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <cerrno>
#include <cstdio>
#include <sys/stat.h>
#include <unistd.h>

namespace pvia {
namespace {

constexpr u64 JOINT_PACKED_BIND_DOMAIN = 0x50564a5041434b44ULL;

bool secure_random_fields(size_t count, std::vector<F>* out) {
    if (!out) return false;
    out->clear();
    if (count == 0) return true;
    if (count > std::numeric_limits<size_t>::max() / 2) return false;
    std::vector<u64> words(count * 2);
    unsigned char* bytes = reinterpret_cast<unsigned char*>(words.data());
    const size_t total = words.size() * sizeof(u64);
    size_t offset = 0;
    constexpr size_t chunk_limit = 1u << 20;
    while (offset < total) {
        const size_t chunk = std::min(chunk_limit, total - offset);
        if (RAND_bytes(bytes + offset, static_cast<int>(chunk)) != 1)
            return false;
        offset += chunk;
    }
    out->resize(count);
    for (size_t i = 0; i < count; ++i) {
        (*out)[i] = F(
            static_cast<long long>(words[2*i] % F::mod),
            static_cast<long long>(words[2*i+1] % F::mod));
    }
    return true;
}

void append_digest_words(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8*i, 8);
        words->push_back(word);
    }
}

bool power_of_two(int value) {
    return value > 0 && (value & (value - 1)) == 0;
}

size_t parse_positive_size_env(const char* name, size_t fallback) {
    const char* env = std::getenv(name);
    if (!env || !*env) return fallback;
    char* end = nullptr;
    const unsigned long parsed = std::strtoul(env, &end, 10);
    if (end == env || *end != '\0' || parsed == 0)
        return fallback;
    return static_cast<size_t>(parsed);
}

size_t configured_preprocess_threads(size_t work_items, int world_size) {
    if (work_items < 512) return 1;

    // An explicit setting remains authoritative for reproducibility and
    // machine-specific tuning.
    const size_t explicit_threads =
        parse_positive_size_env("PVIA_PREPROCESS_THREADS", 0);
    if (explicit_threads != 0)
        return std::max<size_t>(
            1, std::min(explicit_threads, work_items));

    // The FFT work is CPU/memory intensive but each MPI rank performs it
    // independently.  Auto-parallelize conservatively: six workers was the
    // saturation point on the paper machine, while the local-rank cap avoids
    // oversubscribing smaller or multi-node hosts.  Open MPI exports the
    // per-node rank count; fall back to the global size on other runtimes.
    size_t local_ranks = parse_positive_size_env(
        "OMPI_COMM_WORLD_LOCAL_SIZE",
        world_size > 0 ? static_cast<size_t>(world_size) : 1);
    if (local_ranks == 0) local_ranks = 1;
    const unsigned hw = std::thread::hardware_concurrency();
    size_t per_rank_budget = 1;
    if (hw != 0)
        per_rank_budget = std::max<size_t>(
            1, static_cast<size_t>(hw) / local_ranks);

    constexpr size_t AUTO_THREAD_CAP = 6;
    return std::max<size_t>(
        1, std::min({
               AUTO_THREAD_CAP, per_rank_budget, work_items}));
}

template <typename Fn>
void parallel_preprocess_chunks(size_t count, size_t threads, Fn&& fn) {
    threads = std::max<size_t>(1, std::min(threads, count));
    if (threads == 1 || count == 0) {
        fn(0, count);
        return;
    }
    std::vector<std::thread> workers;
    workers.reserve(threads);
    const size_t chunk = (count + threads - 1) / threads;
    for (size_t worker = 0; worker < threads; ++worker) {
        const size_t begin = worker * chunk;
        const size_t end = std::min(count, begin + chunk);
        if (begin >= end) break;
        workers.emplace_back([&, begin, end]() { fn(begin, end); });
    }
    for (auto& worker : workers) worker.join();
}

bool build_forward_fft_plan(
    int logn, std::vector<uint32_t>* rev, std::vector<F>* twiddles) {
    if (!rev || !twiddles || logn <= 0 || logn >= 31)
        return false;
    const uint32_t len = 1u << logn;
    rev->resize(len);
    twiddles->resize(len);
    (*rev)[0] = 0;
    for (uint32_t i = 1; i < len; ++i) {
        (*rev)[i] =
            ((*rev)[i >> 1] >> 1) |
            ((i & 1u) << (logn - 1));
    }
    (*twiddles)[0] = F(1);
    if (len > 1) {
        (*twiddles)[1] = getRootOfUnity(logn);
        for (uint32_t i = 2; i < len; ++i)
            (*twiddles)[i] =
                (*twiddles)[i - 1] * (*twiddles)[1];
    }
    return true;
}

bool apply_forward_fft_plan(
    std::vector<F>* values,
    const std::vector<uint32_t>& rev,
    const std::vector<F>& twiddles) {
    if (!values || values->empty() ||
        values->size() != rev.size() ||
        values->size() != twiddles.size())
        return false;
    const uint32_t len =
        static_cast<uint32_t>(values->size());
    for (uint32_t i = 0; i < len; ++i) {
        if (rev[i] < i)
            std::swap((*values)[i], (*values)[rev[i]]);
    }
    for (uint32_t width = 2; width <= len; width <<= 1) {
        for (uint32_t base = 0; base < len; base += width) {
            for (uint32_t k = 0; k < (width >> 1); ++k) {
                const F u = (*values)[base + k];
                const F v =
                    (*values)[base + k + (width >> 1)] *
                    twiddles[len / width * k];
                (*values)[base + k] = u + v;
                (*values)[base + k + (width >> 1)] = u - v;
            }
        }
    }
    return true;
}

constexpr u64 PREPROCESS_POOL_MAGIC = 0x50565052504f4f4cULL; // PVPRPOOL
constexpr u64 PREPROCESS_POOL_VERSION = 1ULL;

struct PreprocessPoolRequest {
    bool requested = false;
    bool valid = false;
    std::string directory;
    uint64_t slot = 0;
};

bool parse_u64_text(const char* text, uint64_t* value) {
    if (!text || !*text || !value) return false;
    char* end = nullptr;
    errno = 0;
    const unsigned long long parsed = std::strtoull(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0') return false;
    *value = static_cast<uint64_t>(parsed);
    return true;
}

PreprocessPoolRequest preprocessing_pool_request() {
    PreprocessPoolRequest request;
    const char* consume = std::getenv("PVIA_PREPROCESS_POOL_CONSUME");
    if (!consume || std::string(consume) == "0") return request;
    request.requested = true;
    const char* directory = std::getenv("PVIA_PREPROCESS_POOL_DIR");
    const char* slot = std::getenv("PVIA_PREPROCESS_POOL_SLOT");
    if (!directory || !*directory || !parse_u64_text(slot, &request.slot))
        return request;
    request.valid = true;
    request.directory = directory;
    return request;
}

std::string preprocessing_pool_path(
    const std::string& directory, uint64_t slot,
    size_t share_count, int world_size, int k, int packed_width,
    uint64_t domain, int rank) {
    std::ostringstream out;
    out << directory;
    if (!directory.empty() && directory.back() != '/') out << '/';
    out << "pvia-preproc-v1"
        << "-n" << world_size
        << "-k" << k
        << "-p" << packed_width
        << "-c" << share_count
        << "-d" << std::hex << std::setw(16) << std::setfill('0') << domain
        << std::dec
        << "-s" << slot
        << "-r" << rank
        << ".bin";
    return out.str();
}

bool ensure_private_directory(const std::string& directory) {
    if (directory.empty()) return false;
    struct stat st{};
    if (::stat(directory.c_str(), &st) == 0)
        return S_ISDIR(st.st_mode);
    if (errno != ENOENT) return false;
    if (::mkdir(directory.c_str(), 0700) == 0) return true;
    if (errno != EEXIST) return false;
    return ::stat(directory.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

std::vector<u64> preprocessing_pool_header_words(
    uint64_t slot, size_t share_count, int world_size,
    int k, int packed_width, uint64_t domain, int rank) {
    return {
        PREPROCESS_POOL_MAGIC,
        PREPROCESS_POOL_VERSION,
        static_cast<u64>(world_size),
        static_cast<u64>(k),
        static_cast<u64>(packed_width),
        static_cast<u64>(rank),
        static_cast<u64>(share_count),
        domain,
        slot,
        static_cast<u64>(F::mod)};
}

bool write_preprocessing_pool_file(
    const std::string& path, uint64_t slot,
    size_t share_count, int world_size, int k, int packed_width,
    uint64_t domain, int rank, const std::vector<F>& local_share) {
    if (local_share.size() != share_count || share_count == 0)
        return false;
    struct stat existing{};
    if (::stat(path.c_str(), &existing) == 0)
        return false;

    const Digest payload_digest = hash_field_vector(local_share);
    if (payload_digest == Digest{}) return false;
    const std::vector<u64> header = preprocessing_pool_header_words(
        slot, share_count, world_size, k, packed_width, domain, rank);

    std::ostringstream tmp_name;
    tmp_name << path << ".tmp." << static_cast<unsigned long long>(::getpid());
    const std::string tmp = tmp_name.str();
    std::ofstream out(tmp.c_str(), std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(
        reinterpret_cast<const char*>(header.data()),
        static_cast<std::streamsize>(header.size() * sizeof(u64)));
    out.write(
        reinterpret_cast<const char*>(payload_digest.bytes.data()),
        static_cast<std::streamsize>(payload_digest.bytes.size()));
    for (const F& value : local_share) {
        const u64 words[2] = {value.real, value.img};
        out.write(
            reinterpret_cast<const char*>(words),
            static_cast<std::streamsize>(sizeof(words)));
    }
    out.flush();
    const bool stream_ok = static_cast<bool>(out);
    out.close();
    if (!stream_ok || ::chmod(tmp.c_str(), 0600) != 0) {
        ::unlink(tmp.c_str());
        return false;
    }
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        ::unlink(tmp.c_str());
        return false;
    }
    return true;
}

bool preprocessing_pool_file_exists(const std::string& path) {
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

bool consume_preprocessing_pool_file(
    const std::string& path, uint64_t slot,
    size_t share_count, int world_size, int k, int packed_width,
    uint64_t domain, int rank, std::vector<F>* local_share) {
    if (!local_share) return false;
    std::ostringstream claim_name;
    claim_name << path << ".claim."
               << static_cast<unsigned long long>(::getpid());
    const std::string claim = claim_name.str();
    if (::rename(path.c_str(), claim.c_str()) != 0)
        return false;

    bool ok = false;
    do {
        std::ifstream in(claim.c_str(), std::ios::binary);
        if (!in) break;
        const std::vector<u64> expected = preprocessing_pool_header_words(
            slot, share_count, world_size, k, packed_width, domain, rank);
        std::vector<u64> header(expected.size(), 0);
        in.read(
            reinterpret_cast<char*>(header.data()),
            static_cast<std::streamsize>(header.size() * sizeof(u64)));
        if (!in || header != expected) break;

        Digest stored_digest{};
        in.read(
            reinterpret_cast<char*>(stored_digest.bytes.data()),
            static_cast<std::streamsize>(stored_digest.bytes.size()));
        if (!in || stored_digest == Digest{}) break;

        std::vector<F> values(share_count, F(0));
        for (size_t i = 0; i < share_count; ++i) {
            u64 words[2] = {};
            in.read(
                reinterpret_cast<char*>(words),
                static_cast<std::streamsize>(sizeof(words)));
            if (!in) break;
            if (words[0] >= F::mod || words[1] >= F::mod) {
                in.setstate(std::ios::failbit);
                break;
            }
            values[i] = F(
                static_cast<long long>(words[0]),
                static_cast<long long>(words[1]));
        }
        if (!in) break;
        char trailing = 0;
        if (in.read(&trailing, 1))
            break;
        const Digest actual_digest = hash_field_vector(values);
        if (actual_digest == Digest{} || actual_digest != stored_digest)
            break;
        *local_share = std::move(values);
        ok = true;
    } while (false);

    // Claiming happens before reading so a crash can waste a slot but can
    // never cause the same preprocessing randomness to be consumed twice.
    ::unlink(claim.c_str());
    return ok;
}

bool all_ranks_have_pool_slot(bool local_has, int world_size, MPI_Comm comm) {
    int local = local_has ? 1 : 0;
    int global = 0;
    MPI_Allreduce(&local, &global, 1, MPI_INT, MPI_MIN, comm);
    record_control_allreduce(sizeof(int), world_size);
    return global == 1;
}

bool all_ranks_loaded_pool_slot(bool local_ok, int world_size, MPI_Comm comm) {
    int local = local_ok ? 1 : 0;
    int global = 0;
    MPI_Allreduce(&local, &global, 1, MPI_INT, MPI_MIN, comm);
    record_control_allreduce(sizeof(int), world_size);
    return global == 1;
}

Digest joint_preprocessing_local_binding(
    const std::vector<F>& local_share,
    size_t share_count, int world_size, int k, int packed_width,
    uint64_t domain, int contributor_count, int rank) {
    const Digest share_digest = hash_field_vector(local_share);
    std::vector<u64> binding_words = {
        JOINT_PACKED_BIND_DOMAIN, domain,
        static_cast<u64>(world_size), static_cast<u64>(k),
        static_cast<u64>(packed_width), static_cast<u64>(share_count),
        static_cast<u64>(contributor_count), static_cast<u64>(rank)};
    append_digest_words(share_digest, &binding_words);
    return hash_words(binding_words);
}

} // namespace

bool generate_joint_packed_random_share(
    size_t share_count, int world_size, int k, int packed_width,
    uint64_t domain, std::vector<F>* local_share,
    JointPackedPreprocessingResult* result, MPI_Comm comm) {
    if (result) *result = JointPackedPreprocessingResult{};
    if (!local_share || share_count == 0 || domain == 0) return false;
    ExperimentDurationScope duration_scope(
        ExperimentDurationKind::PREPROCESSING);
    ExperimentControlTrafficScope traffic_scope(
        ExperimentControlTrafficKind::PREPROCESSING);

    int rank = -1;
    int actual_world = 0;
    MPI_Comm_rank(comm, &rank);
    MPI_Comm_size(comm, &actual_world);
    const bool local_shape_ok =
        actual_world == world_size && world_size >= 4 &&
        rank >= 0 && rank < world_size &&
        k > 0 && packed_width > k &&
        packed_width * 2 == world_size &&
        k * 4 == world_size &&
        power_of_two(packed_width) && power_of_two(2 * world_size) &&
        share_count <= static_cast<size_t>(std::numeric_limits<int>::max() / 2);
    int local_ok = local_shape_ok ? 1 : 0;
    int global_ok = 0;
    MPI_Allreduce(&local_ok, &global_ok, 1, MPI_INT, MPI_MIN, comm);
    record_control_allreduce(sizeof(int), world_size);
    if (!global_ok) return false;

    // The reference robust path uses t=floor((n-1)/3).  For a sum of
    // independently sampled sharings to remain unpredictable, it is enough
    // that at least one contributor is honest.  A fixed set of t+1
    // contributors therefore preserves this property against any static
    // corruption set of size at most t, while avoiding the previous n-way
    // all-to-all of full random-sharing payloads.
    const int threshold = (world_size - 1) / 3;
    const int contributor_count = threshold + 1;
    if (threshold < 0 || 3 * threshold >= world_size ||
        contributor_count <= 0 || contributor_count > world_size)
        return false;
    const bool contributes = rank < contributor_count;

    const PreprocessPoolRequest pool_request =
        preprocessing_pool_request();
    if (pool_request.requested) {
        if (!pool_request.valid) return false;
        const std::string pool_path = preprocessing_pool_path(
            pool_request.directory, pool_request.slot,
            share_count, world_size, k, packed_width,
            domain, rank);
        const bool local_has =
            preprocessing_pool_file_exists(pool_path);
        if (!all_ranks_have_pool_slot(
                local_has, world_size, comm))
            return false;

        std::vector<F> pooled_share;
        const bool local_loaded = consume_preprocessing_pool_file(
            pool_path, pool_request.slot,
            share_count, world_size, k, packed_width,
            domain, rank, &pooled_share);
        if (!all_ranks_loaded_pool_slot(
                local_loaded, world_size, comm))
            return false;
        if (!local_loaded || pooled_share.size() != share_count)
            return false;

        const Digest binding = joint_preprocessing_local_binding(
            pooled_share, share_count, world_size, k, packed_width,
            domain, contributor_count, rank);
        if (binding == Digest{}) return false;
        *local_share = std::move(pooled_share);
        if (result) {
            result->ok = true;
            result->share_count = share_count;
            result->contributors = contributor_count;
            result->local_binding = binding;
        }
        return true;
    }

    if (share_count > std::numeric_limits<size_t>::max() /
                          static_cast<size_t>(packed_width))
        return false;
    std::vector<F> local_material;
    if (contributes &&
        !secure_random_fields(
            share_count * static_cast<size_t>(packed_width),
            &local_material))
        return false;

    if (share_count > std::numeric_limits<size_t>::max() /
                          static_cast<size_t>(world_size))
        return false;
    const size_t words_per_peer = 2 * share_count;
    if (words_per_peer >
        static_cast<size_t>(std::numeric_limits<int>::max()))
        return false;

    // Write FFT evaluations directly in wire format.  The former path first
    // materialized an equally large vector<F> send_fields and then copied the
    // entire array into send_words.  Avoiding that duplicate representation
    // removes one full memory pass and cuts contributor-side peak buffering.
    std::vector<u64> send_words;
    if (contributes) {
        const size_t peer_count = static_cast<size_t>(world_size);
        if (share_count >
            std::numeric_limits<size_t>::max() / peer_count ||
            share_count * peer_count >
            std::numeric_limits<size_t>::max() / 2)
            return false;
        send_words.assign(
            2 * share_count * peer_count, 0);
        const int eval_log =
            static_cast<int>(std::log2(2 * world_size));
        std::vector<uint32_t> fft_rev;
        std::vector<F> fft_twiddles;
        if (!build_forward_fft_plan(
                eval_log, &fft_rev, &fft_twiddles))
            return false;
        std::atomic<bool> fft_ok{true};
        const size_t preprocess_threads =
            configured_preprocess_threads(share_count, world_size);
        parallel_preprocess_chunks(
            share_count, preprocess_threads,
            [&](size_t begin, size_t end) {
                std::vector<F> polynomial(
                    static_cast<size_t>(2 * world_size), F(0));
                for (size_t block = begin; block < end; ++block) {
                    const size_t base =
                        block * static_cast<size_t>(packed_width);
                    std::fill(
                        polynomial.begin(), polynomial.end(), F(0));
                    // The old path sampled packed_width uniform field
                    // elements as evaluations, applied an inverse FFT, and
                    // then evaluated the resulting polynomial.  Sampling
                    // coefficients directly preserves the same uniform
                    // polynomial distribution.
                    for (int j = 0; j < packed_width; ++j)
                        polynomial[static_cast<size_t>(j)] =
                            local_material[
                                base + static_cast<size_t>(j)];
                    if (!apply_forward_fft_plan(
                            &polynomial, fft_rev, fft_twiddles)) {
                        fft_ok.store(false, std::memory_order_relaxed);
                        return;
                    }
                    for (int recipient = 0;
                         recipient < world_size; ++recipient) {
                        const F& value =
                            polynomial[
                                static_cast<size_t>(2 * recipient + 1)];
                        const size_t word_offset =
                            2 * (
                                static_cast<size_t>(recipient) *
                                    share_count +
                                block);
                        send_words[word_offset] = value.real;
                        send_words[word_offset + 1] = value.img;
                    }
                }
            });
        if (!fft_ok.load(std::memory_order_relaxed))
            return false;
    }

    // Execute the sparse contributor exchange in one collective.  Only the
    // first contributor_count ranks have non-zero sendcounts; every rank
    // receives exactly one packed-share slice from each contributor.
    std::vector<int> sendcounts(static_cast<size_t>(world_size), 0);
    std::vector<int> senddispls(static_cast<size_t>(world_size), 0);
    std::vector<int> recvcounts(static_cast<size_t>(world_size), 0);
    std::vector<int> recvdispls(static_cast<size_t>(world_size), 0);
    if (contributes) {
        for (int peer = 0; peer < world_size; ++peer) {
            sendcounts[static_cast<size_t>(peer)] =
                static_cast<int>(words_per_peer);
            const size_t displacement =
                static_cast<size_t>(peer) * words_per_peer;
            if (displacement >
                static_cast<size_t>(std::numeric_limits<int>::max()))
                return false;
            senddispls[static_cast<size_t>(peer)] =
                static_cast<int>(displacement);
        }
    }
    for (int contributor = 0;
         contributor < contributor_count; ++contributor) {
        recvcounts[static_cast<size_t>(contributor)] =
            static_cast<int>(words_per_peer);
        const size_t displacement =
            static_cast<size_t>(contributor) * words_per_peer;
        if (displacement >
            static_cast<size_t>(std::numeric_limits<int>::max()))
            return false;
        recvdispls[static_cast<size_t>(contributor)] =
            static_cast<int>(displacement);
    }

    std::vector<u64> recv_words(
        static_cast<size_t>(contributor_count) * words_per_peer, 0);
    MPI_Alltoallv(
        contributes ? send_words.data() : nullptr,
        sendcounts.data(), senddispls.data(), MPI_UINT64_T,
        recv_words.data(), recvcounts.data(), recvdispls.data(),
        MPI_UINT64_T, comm);

    const uint64_t bytes_per_peer =
        static_cast<uint64_t>(words_per_peer * sizeof(u64));
    const uint64_t sent_peers = contributes
        ? static_cast<uint64_t>(world_size - 1) : 0ULL;
    const uint64_t recv_peers = static_cast<uint64_t>(
        contributor_count - (contributes ? 1 : 0));
    experiment_add_protocol_control_traffic(
        sent_peers * bytes_per_peer,
        recv_peers * bytes_per_peer,
        sent_peers, recv_peers, 1);

    local_share->assign(share_count, F(0));
    for (int contributor = 0;
         contributor < contributor_count; ++contributor) {
        const size_t peer_base =
            static_cast<size_t>(contributor) * words_per_peer;
        for (size_t block = 0; block < share_count; ++block) {
            const u64 real =
                recv_words[peer_base + 2*block] % F::mod;
            const u64 imag =
                recv_words[peer_base + 2*block + 1] % F::mod;
            (*local_share)[block] += F(
                static_cast<long long>(real),
                static_cast<long long>(imag));
        }
    }

    const Digest binding = joint_preprocessing_local_binding(
        *local_share, share_count, world_size, k, packed_width,
        domain, contributor_count, rank);
    if (binding == Digest{}) return false;

    if (result) {
        result->ok = true;
        result->share_count = share_count;
        result->contributors = contributor_count;
        result->local_binding = binding;
    }
    return true;
}

bool write_joint_packed_preprocessing_slot(
    const std::string& directory, uint64_t slot,
    size_t share_count, int world_size, int k, int packed_width,
    uint64_t domain, const std::vector<F>& local_share,
    MPI_Comm comm) {
    int rank = -1;
    int actual_world = 0;
    MPI_Comm_rank(comm, &rank);
    MPI_Comm_size(comm, &actual_world);
    const bool local_shape_ok =
        actual_world == world_size &&
        rank >= 0 && rank < world_size &&
        world_size >= 4 && k > 0 &&
        packed_width * 2 == world_size &&
        k * 4 == world_size &&
        share_count > 0 &&
        local_share.size() == share_count &&
        ensure_private_directory(directory);

    int local = local_shape_ok ? 1 : 0;
    int all_shape_ok = 0;
    MPI_Allreduce(&local, &all_shape_ok, 1, MPI_INT, MPI_MIN, comm);
    if (!all_shape_ok) return false;

    uint64_t min_slot = slot;
    uint64_t max_slot = slot;
    MPI_Allreduce(
        &slot, &min_slot, 1, MPI_UINT64_T, MPI_MIN, comm);
    MPI_Allreduce(
        &slot, &max_slot, 1, MPI_UINT64_T, MPI_MAX, comm);
    if (min_slot != max_slot) return false;

    const std::string path = preprocessing_pool_path(
        directory, slot, share_count, world_size,
        k, packed_width, domain, rank);
    const bool local_written = write_preprocessing_pool_file(
        path, slot, share_count, world_size,
        k, packed_width, domain, rank, local_share);
    local = local_written ? 1 : 0;
    int all_written = 0;
    MPI_Allreduce(&local, &all_written, 1, MPI_INT, MPI_MIN, comm);
    if (!all_written) {
        if (local_written) ::unlink(path.c_str());
        return false;
    }
    return true;
}

} // namespace pvia
