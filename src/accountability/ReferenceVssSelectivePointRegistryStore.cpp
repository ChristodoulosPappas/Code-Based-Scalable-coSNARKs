#include "ReferenceVssSelectivePointRegistryStore.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace pvia {
namespace {
constexpr u64 RECORD_MAGIC = 0x5056535053545231ULL;  // PVSPSTR1
constexpr u64 RECORD_VERSION = 1;
constexpr size_t FIXED_WORDS = 33;
constexpr size_t ANCHOR_WORDS = 4;
constexpr size_t MAX_PARTICIPANTS = 1024;
constexpr size_t MAX_RECORD_BYTES =
    (FIXED_WORDS + MAX_PARTICIPANTS * MAX_PARTICIPANTS * 4 +
     ANCHOR_WORDS) * sizeof(u64);

void append_digest(const Digest& d, std::vector<u64>* out) {
    for (size_t i = 0; i < d.bytes.size(); i += 8) {
        u64 word = 0;
        for (size_t j = 0; j < 8; ++j)
            word |= static_cast<u64>(d.bytes[i + j]) << (8 * j);
        out->push_back(word);
    }
}

Digest read_digest(const std::vector<u64>& words, size_t at) {
    Digest d{};
    if (at > words.size() || words.size() - at < 4) return {};
    for (size_t i = 0; i < 4; ++i) {
        for (size_t j = 0; j < 8; ++j)
            d.bytes[8 * i + j] = static_cast<uint8_t>(
                words[at + i] >> (8 * j));
    }
    return d;
}

bool encode_words(
    const ReferenceVssSelectivePointCommitmentRegistry& r,
    const Digest& native_execution_binding,
    std::vector<u64>* out) {
    if (!out || native_execution_binding == Digest{} ||
        !validate_reference_vss_point_commitment_registry(r))
        return false;
    const size_t n = static_cast<size_t>(r.world_size);
    if (n > MAX_PARTICIPANTS || r.element_count == 0) return false;
    const size_t count = FIXED_WORDS + 4 * n * n + ANCHOR_WORDS;
    std::vector<u64> words = {
        RECORD_MAGIC, RECORD_VERSION, static_cast<u64>(count),
        static_cast<u64>(n), static_cast<u64>(r.element_count),
        r.sid, r.checkpoint, r.setup_round, r.setup_sequence
    };
    append_digest(r.vss_transcript, &words);
    append_digest(r.setup_context_binding, &words);
    append_digest(r.signed_commit_transport, &words);
    append_digest(r.signed_ack_transport, &words);
    append_digest(r.registry_binding, &words);
    append_digest(native_execution_binding, &words);
    for (const auto& d : r.commitments) append_digest(d, &words);
    if (words.size() != count - ANCHOR_WORDS) return false;
    const Digest record_hash = hash_words(words);
    if (record_hash == Digest{}) return false;
    append_digest(record_hash, &words);
    *out = std::move(words);
    return true;
}

bool decode_words(
    const std::vector<u64>& words,
    ReferenceVssPointRegistryExecutionRecord* out) {
    if (!out || words.size() < FIXED_WORDS + ANCHOR_WORDS ||
        words[0] != RECORD_MAGIC || words[1] != RECORD_VERSION ||
        words[2] != words.size() || words[3] < 4 ||
        words[3] > MAX_PARTICIPANTS || words[4] == 0)
        return false;
    const size_t n = static_cast<size_t>(words[3]);
    if (words.size() != FIXED_WORDS + 4 * n * n + ANCHOR_WORDS)
        return false;
    ReferenceVssPointRegistryExecutionRecord r;
    r.registry.available = true;
    r.registry.world_size = static_cast<int>(n);
    if (words[4] > std::numeric_limits<size_t>::max()) return false;
    r.registry.element_count = static_cast<size_t>(words[4]);
    r.registry.sid = words[5];
    r.registry.checkpoint = words[6];
    r.registry.setup_round = words[7];
    r.registry.setup_sequence = words[8];
    r.registry.vss_transcript = read_digest(words, 9);
    r.registry.setup_context_binding = read_digest(words, 13);
    r.registry.signed_commit_transport = read_digest(words, 17);
    r.registry.signed_ack_transport = read_digest(words, 21);
    r.registry.registry_binding = read_digest(words, 25);
    r.native_execution_binding = read_digest(words, 29);
    r.registry.commitments.reserve(n * n);
    for (size_t i = 0; i < n * n; ++i)
        r.registry.commitments.push_back(
            read_digest(words, FIXED_WORDS + 4 * i));
    r.record_binding = read_digest(words, words.size() - ANCHOR_WORDS);
    const Digest computed = hash_words(
        std::vector<u64>(words.begin(), words.end() - ANCHOR_WORDS));
    if (computed == Digest{} || computed != r.record_binding ||
        !validate_reference_vss_point_commitment_registry(r.registry))
        return false;
    *out = std::move(r);
    return true;
}

std::vector<uint8_t> serialize_le(const std::vector<u64>& words) {
    std::vector<uint8_t> bytes;
    bytes.reserve(words.size() * sizeof(u64));
    for (const u64 word : words) {
        for (size_t shift = 0; shift < 64; shift += 8)
            bytes.push_back(static_cast<uint8_t>(word >> shift));
    }
    return bytes;
}

bool write_exact(int fd, const std::vector<uint8_t>& bytes) {
    size_t offset = 0;
    while (offset < bytes.size()) {
        const ssize_t wrote = ::write(fd, bytes.data() + offset,
                                      bytes.size() - offset);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) return false;
        offset += static_cast<size_t>(wrote);
    }
    return true;
}

bool read_record(const std::string& path, std::vector<u64>* output) {
    if (!output || path.empty()) return false;
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat info{};
    bool ok = ::fstat(fd, &info) == 0 &&
        S_ISREG(info.st_mode) && info.st_size > 0 &&
        static_cast<uint64_t>(info.st_size) <= MAX_RECORD_BYTES &&
        (info.st_size % static_cast<off_t>(sizeof(u64))) == 0;
    std::vector<uint8_t> bytes;
    if (ok) {
        bytes.resize(static_cast<size_t>(info.st_size));
        size_t offset = 0;
        while (offset < bytes.size()) {
            const ssize_t got = ::read(fd, bytes.data() + offset,
                                       bytes.size() - offset);
            if (got < 0 && errno == EINTR) continue;
            if (got <= 0) { ok = false; break; }
            offset += static_cast<size_t>(got);
        }
        uint8_t extra = 0;
        if (ok && ::read(fd, &extra, 1) != 0) ok = false;
    }
    if (::close(fd) != 0) ok = false;
    if (!ok) return false;
    std::vector<u64> words(bytes.size() / 8, 0);
    for (size_t i = 0; i < words.size(); ++i) {
        for (size_t j = 0; j < 8; ++j)
            words[i] |= static_cast<u64>(bytes[8 * i + j]) << (8 * j);
    }
    *output = std::move(words);
    return true;
}
} // namespace

Digest compute_reference_vss_point_registry_execution_binding(
    const ReferenceVssSelectivePointCommitmentRegistry& registry,
    const Digest& native_execution_binding) {
    std::vector<u64> words;
    if (!encode_words(registry, native_execution_binding, &words))
        return {};
    return read_digest(words, words.size() - ANCHOR_WORDS);
}

bool save_reference_vss_point_registry_execution_record(
    const std::string& path,
    const ReferenceVssSelectivePointCommitmentRegistry& registry,
    const Digest& native_execution_binding,
    Digest* independent_record_binding) {
    if (!independent_record_binding) return false;
    *independent_record_binding = {};
    if (path.empty() || path.size() > 4000) return false;
    std::vector<u64> words;
    if (!encode_words(registry, native_execution_binding, &words))
        return false;
    const auto bytes = serialize_le(words);
    std::string temp = path + ".tmp.XXXXXX";
    std::vector<char> pattern(temp.begin(), temp.end());
    pattern.push_back('\0');
    const int fd = ::mkstemp(pattern.data());
    if (fd < 0) return false;
    const std::string created(pattern.data());
    const bool wrote = ::fchmod(fd, S_IRUSR | S_IWUSR) == 0 &&
                       write_exact(fd, bytes) && ::fsync(fd) == 0;
    const bool closed = ::close(fd) == 0;
    if (!wrote || !closed || ::rename(created.c_str(), path.c_str()) != 0) {
        ::unlink(created.c_str());
        return false;
    }
    // Persist the rename itself, not merely the temporary file contents.
    // The independent anchor is not returned unless the directory update
    // has reached durable storage.
    const size_t separator = path.find_last_of('/');
    const std::string parent = separator == std::string::npos
        ? "." : (separator == 0 ? "/" : path.substr(0, separator));
    const int dirfd = ::open(parent.c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) return false;
    const bool durable = ::fsync(dirfd) == 0;
    const bool directory_closed = ::close(dirfd) == 0;
    if (!durable || !directory_closed) return false;
    *independent_record_binding =
        read_digest(words, words.size() - ANCHOR_WORDS);
    return true;
}

bool load_reference_vss_point_registry_execution_record(
    const std::string& path,
    const Digest& expected_record_binding,
    const Digest& expected_native_execution_binding,
    u64 expected_sid,
    CheckpointId expected_checkpoint,
    const Digest& expected_vss_transcript,
    ReferenceVssPointRegistryExecutionRecord* record) {
    if (!record) return false;
    *record = {};
    if (expected_record_binding == Digest{} ||
        expected_native_execution_binding == Digest{} ||
        !expected_sid || !expected_checkpoint ||
        expected_vss_transcript == Digest{})
        return false;
    std::vector<u64> words;
    ReferenceVssPointRegistryExecutionRecord loaded;
    if (!read_record(path, &words) || !decode_words(words, &loaded) ||
        loaded.record_binding != expected_record_binding ||
        loaded.native_execution_binding != expected_native_execution_binding ||
        loaded.registry.sid != expected_sid ||
        loaded.registry.checkpoint != expected_checkpoint ||
        loaded.registry.vss_transcript != expected_vss_transcript)
        return false;
    *record = std::move(loaded);
    return true;
}

bool recover_reference_vss_share_from_persisted_points(
    const std::string& path,
    const Digest& expected_record_binding,
    const Digest& expected_native_execution_binding,
    int target,
    const ReferenceVssReceipt& receipt,
    const ReferenceVssTranscriptContext& transcript,
    const AuthenticatedMpcMessageContext& release_context,
    const std::vector<ReferenceVssSelectivePoint>& openings,
    std::vector<F>* recovered) {
    if (!recovered) return false;
    recovered->clear();
    ReferenceVssPointRegistryExecutionRecord record;
    if (!load_reference_vss_point_registry_execution_record(
            path, expected_record_binding, expected_native_execution_binding,
            release_context.sid, release_context.checkpoint,
            receipt.transcript_binding, &record))
        return false;
    return recover_reference_vss_share_from_committed_points(
        target, receipt, transcript, record.registry, release_context,
        openings, recovered);
}

} // namespace pvia
