#include "PublicDirectValidation.hpp"

#include "ExperimentMetrics.hpp"
#include "ProtocolTrafficMetrics.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <vector>

namespace pvia {
namespace {

constexpr u64 PUBLIC_DIRECT_RECORD_DOMAIN = 0x505644495256414cULL; // PVDIRVAL
constexpr u64 PUBLIC_DIRECT_BUNDLE_DOMAIN = 0x5056444952424e44ULL; // PVDIRBND
constexpr u64 PUBLIC_DIRECT_BUNDLE_VERSION = 1;
constexpr size_t DIGEST_WORDS = 4;
constexpr size_t RECORD_HEADER_WORDS = 7;
constexpr size_t RECORD_WORDS =
    RECORD_HEADER_WORDS + 3 * DIGEST_WORDS;
constexpr size_t RECORD_CONTEXT_OFFSET = RECORD_HEADER_WORDS;
constexpr size_t BUNDLE_HEADER_WORDS = 7 + DIGEST_WORDS;

void append_digest_words(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < DIGEST_WORDS; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

Digest digest_from_words(const u64* words) {
    Digest digest{};
    if (!words) return digest;
    for (size_t i = 0; i < DIGEST_WORDS; ++i)
        std::memcpy(digest.bytes.data() + 8 * i, &words[i], 8);
    return digest;
}

Digest compute_context_binding_impl(
    PublicDirectValidationKind kind,
    const std::vector<F>& fields,
    const std::vector<u64>& words) {
    std::vector<u64> input = {
        PUBLIC_DIRECT_RECORD_DOMAIN,
        static_cast<u64>(kind),
        static_cast<u64>(fields.size()),
        static_cast<u64>(words.size())};
    append_digest_words(hash_field_vector(fields), &input);
    input.insert(input.end(), words.begin(), words.end());
    return hash_words(input);
}

bool record_shape_valid(
    const u64* record,
    uint64_t sid,
    int expected_rank,
    PublicDirectValidationKind kind) {
    if (!record || expected_rank < 0) return false;
    if (record[0] != PUBLIC_DIRECT_RECORD_DOMAIN ||
        record[1] != sid ||
        record[2] != static_cast<u64>(expected_rank) ||
        record[3] != static_cast<u64>(kind) ||
        record[4] > 1)
        return false;
    const Digest expected = digest_from_words(record + RECORD_HEADER_WORDS + DIGEST_WORDS);
    const Digest actual = digest_from_words(record + RECORD_HEADER_WORDS + 2 * DIGEST_WORDS);
    const bool digest_equal = expected == actual;
    return (record[4] != 0) == digest_equal;
}

} // namespace

Digest compute_public_direct_context_binding(
    PublicDirectValidationKind kind,
    const std::vector<F>& public_context_fields,
    const std::vector<u64>& public_context_words) {
    return compute_context_binding_impl(
        kind, public_context_fields, public_context_words);
}

bool verify_encoded_public_direct_validation_bundle(
    const std::vector<u64>& encoded_bundle,
    uint64_t expected_session_id,
    PublicDirectValidationKind expected_kind,
    const std::vector<Digest>& expected_context_bindings,
    Digest* collective_binding) {
    if (encoded_bundle.size() < BUNDLE_HEADER_WORDS)
        return false;
    if (encoded_bundle[0] != PUBLIC_DIRECT_BUNDLE_DOMAIN ||
        encoded_bundle[1] != PUBLIC_DIRECT_BUNDLE_VERSION ||
        encoded_bundle[2] != expected_session_id ||
        encoded_bundle[3] != static_cast<u64>(expected_kind) ||
        encoded_bundle[5] != RECORD_WORDS)
        return false;

    const size_t world_size = static_cast<size_t>(encoded_bundle[4]);
    const size_t record_count = static_cast<size_t>(encoded_bundle[6]);
    if (world_size == 0 || record_count != world_size ||
        expected_context_bindings.size() != world_size)
        return false;
    if (record_count >
        (std::numeric_limits<size_t>::max() - BUNDLE_HEADER_WORDS) /
            RECORD_WORDS)
        return false;
    const size_t expected_words =
        BUNDLE_HEADER_WORDS + record_count * RECORD_WORDS;
    if (encoded_bundle.size() != expected_words)
        return false;

    const Digest encoded_collective =
        digest_from_words(encoded_bundle.data() + 7);
    const u64* records = encoded_bundle.data() + BUNDLE_HEADER_WORDS;
    std::vector<u64> record_words(
        records, records + record_count * RECORD_WORDS);
    const Digest recomputed_collective = hash_words(record_words);
    if (encoded_collective == Digest{} ||
        encoded_collective != recomputed_collective)
        return false;

    for (size_t participant = 0; participant < record_count; ++participant) {
        const u64* record = records + participant * RECORD_WORDS;
        if (!record_shape_valid(
                record, expected_session_id,
                static_cast<int>(participant), expected_kind) ||
            record[4] == 0)
            return false;
        const Digest context = digest_from_words(
            record + RECORD_CONTEXT_OFFSET);
        if (context != expected_context_bindings[participant])
            return false;
    }

    if (collective_binding)
        *collective_binding = recomputed_collective;
    return true;
}

bool validate_public_direct_vector(
    Runtime& runtime,
    PublicDirectValidationKind kind,
    const std::vector<F>& expected,
    const std::vector<F>& actual,
    const std::vector<F>& public_context_fields,
    const std::vector<u64>& public_context_words,
    PublicDirectValidationResult* result,
    MPI_Comm comm) {
    if (!result) return false;
    *result = PublicDirectValidationResult{};

    int rank = -1;
    int world_size = 0;
    MPI_Comm_rank(comm, &rank);
    MPI_Comm_size(comm, &world_size);
    if (rank < 0 || world_size <= 0 ||
        expected.empty() || expected.size() != actual.size())
        return false;

    ExperimentDurationScope duration_scope(
        ExperimentDurationKind::PUBLIC_DIRECT_VALIDATION);
    ExperimentControlTrafficScope traffic_scope(
        ExperimentControlTrafficKind::PUBLIC_DIRECT_VALIDATION);

    const Digest context_binding = compute_public_direct_context_binding(
        kind, public_context_fields, public_context_words);

    // On the successful path the two public vectors are byte-for-byte equal.
    // Compare them directly first, hash the actual vector once, and reuse that
    // digest as the expected digest.  If they differ, compute both digests so
    // the rejecting-path record still carries the exact expected/actual pair.
    const bool local_valid =
        std::equal(expected.begin(), expected.end(), actual.begin());
    const Digest actual_digest = hash_field_vector(actual);
    const Digest expected_digest =
        local_valid ? actual_digest : hash_field_vector(expected);
    if (context_binding == Digest{} ||
        expected_digest == Digest{} || actual_digest == Digest{})
        return false;
    std::vector<u64> local_record = {
        PUBLIC_DIRECT_RECORD_DOMAIN,
        runtime.enabled() ? runtime.session_id() : 0ULL,
        static_cast<u64>(rank),
        static_cast<u64>(kind),
        local_valid ? 1ULL : 0ULL,
        static_cast<u64>(expected.size()),
        static_cast<u64>(public_context_words.size())};
    append_digest_words(context_binding, &local_record);
    append_digest_words(expected_digest, &local_record);
    append_digest_words(actual_digest, &local_record);
    if (local_record.size() != RECORD_WORDS ||
        RECORD_WORDS > static_cast<size_t>(std::numeric_limits<int>::max()))
        return false;

    std::vector<u64> gathered(
        static_cast<size_t>(world_size) * RECORD_WORDS, 0);
    MPI_Allgather(
        local_record.data(), static_cast<int>(RECORD_WORDS), MPI_UINT64_T,
        gathered.data(), static_cast<int>(RECORD_WORDS), MPI_UINT64_T, comm);
    record_control_allgather(
        static_cast<uint64_t>(RECORD_WORDS * sizeof(u64)), world_size);

    const uint64_t sid = runtime.enabled() ? runtime.session_id() : 0ULL;
    bool collective_valid = true;
    for (int participant = 0; participant < world_size; ++participant) {
        const u64* record = gathered.data() +
            static_cast<size_t>(participant) * RECORD_WORDS;
        if (!record_shape_valid(record, sid, participant, kind)) {
            collective_valid = false;
            break;
        }
        if (record[4] == 0)
            collective_valid = false;
    }
    const Digest collective_binding = hash_words(gathered);
    if (collective_binding == Digest{})
        return false;

    std::vector<u64> encoded_bundle = {
        PUBLIC_DIRECT_BUNDLE_DOMAIN,
        PUBLIC_DIRECT_BUNDLE_VERSION,
        sid,
        static_cast<u64>(kind),
        static_cast<u64>(world_size),
        static_cast<u64>(RECORD_WORDS),
        static_cast<u64>(world_size)};
    append_digest_words(collective_binding, &encoded_bundle);
    encoded_bundle.insert(
        encoded_bundle.end(), gathered.begin(), gathered.end());

    RecordId record_id = 0;
    if (runtime.enabled()) {
        std::vector<u64> context = {
            PUBLIC_DIRECT_RECORD_DOMAIN,
            static_cast<u64>(kind),
            static_cast<u64>(rank),
            static_cast<u64>(world_size),
            local_valid ? 1ULL : 0ULL,
            collective_valid ? 1ULL : 0ULL,
            static_cast<u64>(expected.size())};
        append_digest_words(context_binding, &context);
        append_digest_words(collective_binding, &context);
        record_id = runtime.register_public_digest_validation(
            Phase::PUBLIC_DIRECT_VALIDATION,
            static_cast<uint32_t>(kind),
            expected_digest, actual_digest, context);
        if (record_id == 0)
            return false;
    }

    result->executed = true;
    result->local_valid = local_valid;
    result->collective_valid = collective_valid;
    result->record_id = record_id;
    result->context_binding = context_binding;
    result->collective_binding = collective_binding;
    result->encoded_bundle = std::move(encoded_bundle);
    return true;
}

} // namespace pvia
