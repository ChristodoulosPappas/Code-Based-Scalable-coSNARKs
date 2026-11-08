#include "SharedLibraryMultiplicationConsistencyProviderSession.hpp"
#include "MultiplicationConsistencyProviderAbiHelpers.h"

#include <dlfcn.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

#include <cstring>
#include <limits>
#include <utility>
#include <vector>

namespace pvia {
namespace {

constexpr size_t MAX_PROVIDER_WORDS = 1ULL << 24;

// Optional host-local semaphore for bounding simultaneous SP1 CPU proofs
// across MPI ranks. It changes scheduling only; proof inputs and relations
// remain unchanged. The lock is held across the ABI size query and proof copy.
class ProofConcurrencyPermit {
public:
    ProofConcurrencyPermit() = default;
    ProofConcurrencyPermit(const ProofConcurrencyPermit&) = delete;
    ProofConcurrencyPermit& operator=(const ProofConcurrencyPermit&) = delete;

    ~ProofConcurrencyPermit() { Release(); }

    bool Acquire(std::string* error) {
        const char* raw_limit = std::getenv("PVIA_SP1_MAX_CONCURRENT_PROOFS");
        if (!raw_limit || raw_limit[0] == '\0') return true;

        char* end = nullptr;
        errno = 0;
        const long limit = std::strtol(raw_limit, &end, 10);
        if (errno != 0 || end == raw_limit || *end != '\0' ||
            limit < 0 || limit > 256) {
            if (error) *error = "invalid PVIA_SP1_MAX_CONCURRENT_PROOFS";
            return false;
        }
        if (limit == 0) return true;

        const char* raw_dir = std::getenv("PVIA_SP1_PROOF_LOCK_DIR");
        const std::string dir =
            (raw_dir && raw_dir[0] != '\0')
                ? std::string(raw_dir)
                : std::string("/tmp/pvia-sp1-proof-slots-") +
                      std::to_string(static_cast<unsigned long>(getuid()));
        if (dir.empty() || dir.size() > 3000) {
            if (error) *error = "invalid PVIA_SP1_PROOF_LOCK_DIR";
            return false;
        }
        if (mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST) {
            if (error) *error = "unable to create SP1 proof lock directory";
            return false;
        }
        struct stat directory_stat {};
        if (lstat(dir.c_str(), &directory_stat) != 0 ||
            !S_ISDIR(directory_stat.st_mode) ||
            directory_stat.st_uid != getuid() ||
            (directory_stat.st_mode & 0077) != 0) {
            if (error) *error = "SP1 proof lock directory is not private and user-owned";
            return false;
        }

        for (;;) {
            for (long slot = 0; slot < limit; ++slot) {
                const std::string path =
                    dir + "/slot_" + std::to_string(slot) + ".lock";
                const int candidate = open(
                    path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW,
                    0600);
                if (candidate < 0) {
                    if (error) *error = "unable to open SP1 proof lock slot";
                    return false;
                }
                struct stat lock_stat {};
                if (fstat(candidate, &lock_stat) != 0 ||
                    !S_ISREG(lock_stat.st_mode) ||
                    lock_stat.st_uid != getuid() ||
                    (lock_stat.st_mode & 0077) != 0) {
                    close(candidate);
                    if (error) *error = "SP1 proof lock slot is not private and user-owned";
                    return false;
                }
                if (flock(candidate, LOCK_EX | LOCK_NB) == 0) {
                    fd_ = candidate;
                    slot_ = slot;
                    limit_ = limit;
                    std::fprintf(
                        stderr,
                        "[PVIA][sp1-proof-slot] acquired slot=%ld limit=%ld pid=%ld\n",
                        slot_, limit_, static_cast<long>(getpid()));
                    return true;
                }
                const int lock_error = errno;
                close(candidate);
                if (lock_error != EWOULDBLOCK &&
                    lock_error != EAGAIN &&
                    lock_error != EINTR) {
                    if (error) *error = "unable to acquire SP1 proof lock slot";
                    return false;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

private:
    void Release() {
        if (fd_ < 0) return;
        std::fprintf(
            stderr,
            "[PVIA][sp1-proof-slot] released slot=%ld pid=%ld\n",
            slot_, static_cast<long>(getpid()));
        flock(fd_, LOCK_UN);
        close(fd_);
        fd_ = -1;
    }

    int fd_ = -1;
    long slot_ = -1;
    long limit_ = 0;
};

template <typename Fn>
Fn load_symbol(void* handle, const char* name) {
    return reinterpret_cast<Fn>(dlsym(handle, name));
}

void append_digest_as_words(
    const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

} // namespace

SharedLibraryMultiplicationConsistencyProviderSession::
SharedLibraryMultiplicationConsistencyProviderSession(
    std::string library_path,
    uint32_t expected_proof_system_id)
    : library_path_(std::move(library_path)),
      expected_proof_system_id_(expected_proof_system_id) {}

SharedLibraryMultiplicationConsistencyProviderSession::
~SharedLibraryMultiplicationConsistencyProviderSession() {
    Close();
}

bool SharedLibraryMultiplicationConsistencyProviderSession::Load() {
    if (loaded()) return true;
    Close();
    if (library_path_.empty() || expected_proof_system_id_ == 0) {
        error_ = "provider path or proof-system id is missing";
        return false;
    }

    handle_ = dlopen(library_path_.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle_) {
        const char* detail = dlerror();
        error_ = detail ? detail : "unable to load provider library";
        Close();
        return false;
    }

    version_fn_ = load_symbol<MultiplicationConsistencyAbiVersionFn>(
        handle_, MULTIPLICATION_CONSISTENCY_ABI_VERSION_SYMBOL);
    capabilities_fn_ =
        load_symbol<MultiplicationConsistencyAbiCapabilitiesFn>(
            handle_, MULTIPLICATION_CONSISTENCY_ABI_CAPABILITIES_SYMBOL);
    prove_fn_ = load_symbol<MultiplicationConsistencyAbiProveFn>(
        handle_, MULTIPLICATION_CONSISTENCY_ABI_PROVE_SYMBOL);
    verify_fn_ = load_symbol<MultiplicationConsistencyAbiVerifyFn>(
        handle_, MULTIPLICATION_CONSISTENCY_ABI_VERIFY_SYMBOL);
    if (!version_fn_ || !capabilities_fn_ || !prove_fn_ || !verify_fn_) {
        error_ = "provider library is missing one or more required ABI symbols";
        Close();
        return false;
    }
    if (version_fn_() != MULTIPLICATION_CONSISTENCY_PROVIDER_ABI_VERSION) {
        error_ = "provider ABI version does not match";
        Close();
        return false;
    }

    size_t count = 0;
    if (capabilities_fn_(nullptr, &count) != 1 ||
        count == 0 || count > MAX_PROVIDER_WORDS) {
        error_ = "provider capabilities size query failed";
        Close();
        return false;
    }
    std::vector<uint64_t> words(count);
    size_t actual = count;
    if (capabilities_fn_(words.data(), &actual) != 1 ||
        actual != count ||
        !decode_multiplication_consistency_capabilities_abi(
            words, &capabilities_) ||
        !production_ready_multiplication_consistency_capabilities(
            capabilities_)) {
        error_ = "provider capabilities are not accepted";
        Close();
        return false;
    }

    MultiplicationConsistencyProviderCallbacks callbacks;
    callbacks.prove =
        [this](
            const MultiplicationConsistencyStatement& statement,
            const MultiplicationConsistencyWitness& witness) {
            return Prove(statement, witness);
        };
    callbacks.verify =
        [this](
            const MultiplicationConsistencyStatement& statement,
            const MultiplicationConsistencyProofArtifact& proof) {
            return Verify(statement, proof);
        };
    callbacks.last_error = [this]() { return provider_operation_error_; };
    session_ =
        std::make_unique<ExternalMultiplicationConsistencyProviderSession>(
            capabilities_, expected_proof_system_id_, std::move(callbacks));
    if (!session_->adapter_ready()) {
        error_ = "provider adapter is not ready";
        Close();
        return false;
    }

    error_.clear();
    return true;
}

bool SharedLibraryMultiplicationConsistencyProviderSession::
CollectiveProviderAgreement(
    int rank, int world_size, MPI_Comm comm) const {
    if (!loaded() || rank < 0 || world_size <= 0 || rank >= world_size)
        return false;

    std::vector<u64> local = {
        static_cast<u64>(MULTIPLICATION_CONSISTENCY_PROVIDER_ABI_VERSION),
        static_cast<u64>(expected_proof_system_id_),
        capabilities_.protocol_id};
    append_digest_as_words(capabilities_.capability_binding, &local);
    append_digest_as_words(capabilities_.relation_binding, &local);
    append_digest_as_words(capabilities_.implementation_binding, &local);

    std::vector<u64> gathered(
        local.size() * static_cast<size_t>(world_size), 0);
    MPI_Allgather(
        local.data(), static_cast<int>(local.size()), MPI_UINT64_T,
        gathered.data(), static_cast<int>(local.size()), MPI_UINT64_T,
        comm);
    for (int participant = 1; participant < world_size; ++participant) {
        const size_t offset =
            static_cast<size_t>(participant) * local.size();
        for (size_t i = 0; i < local.size(); ++i) {
            if (gathered[offset + i] != gathered[i])
                return false;
        }
    }
    return true;
}

bool SharedLibraryMultiplicationConsistencyProviderSession::Activate(
    int rank, int world_size, MPI_Comm comm) {
    provider_operation_error_.clear();
    int local_loaded = Load() ? 1 : 0;
    int all_loaded = 0;
    MPI_Allreduce(
        &local_loaded, &all_loaded, 1, MPI_INT, MPI_MIN, comm);
    if (!all_loaded)
        return false;
    if (!CollectiveProviderAgreement(rank, world_size, comm)) {
        error_ = "provider identity differs across participants";
        return false;
    }
    if (!session_) {
        error_ = "provider adapter session is unavailable";
        return false;
    }
    if (!session_->Activate(rank, world_size, comm)) {
        const auto& attempt = session_->last_attempt();
        const uint64_t local_status[2] = {
            static_cast<uint64_t>(attempt.completed_stage),
            attempt.available ? 1ULL : 0ULL};
        std::vector<uint64_t> rank_status(
            static_cast<size_t>(world_size) * 2, 0);
        MPI_Allgather(
            local_status, 2, MPI_UINT64_T,
            rank_status.data(), 2, MPI_UINT64_T, comm);
        constexpr size_t ERROR_BUFFER_SIZE = 256;
        char local_error_buffer[ERROR_BUFFER_SIZE] = {};
        std::string local_error = session_->last_error();
        if (local_error.empty()) local_error = provider_operation_error_;
        const size_t local_error_size =
            std::min(local_error.size(), ERROR_BUFFER_SIZE - 1);
        if (local_error_size != 0)
            std::memcpy(local_error_buffer, local_error.data(), local_error_size);
        std::vector<char> rank_errors(
            static_cast<size_t>(world_size) * ERROR_BUFFER_SIZE, '\0');
        MPI_Allgather(
            local_error_buffer, static_cast<int>(ERROR_BUFFER_SIZE), MPI_CHAR,
            rank_errors.data(), static_cast<int>(ERROR_BUFFER_SIZE), MPI_CHAR,
            comm);
        bool all_acceptance_checks_completed = true;
        error_ = "provider distributed acceptance did not complete; rank_status=[";
        for (int participant = 0; participant < world_size; ++participant) {
            if (participant != 0) error_ += ";";
            const uint64_t stage =
                rank_status[static_cast<size_t>(participant) * 2];
            const uint64_t available =
                rank_status[static_cast<size_t>(participant) * 2 + 1];
            error_ += "rank" + std::to_string(participant) +
                ":stage=" + std::to_string(stage) +
                ",available=" + std::to_string(available);
            all_acceptance_checks_completed =
                all_acceptance_checks_completed && stage >= 11 && available == 1;
        }
        error_ += "]";
        bool any_provider_error = false;
        for (int participant = 0; participant < world_size; ++participant) {
            const char* detail = rank_errors.data() +
                static_cast<size_t>(participant) * ERROR_BUFFER_SIZE;
            if (detail[0] == '\0') continue;
            if (!any_provider_error) error_ += "; provider_errors=[";
            else error_ += ";";
            error_ += "rank" + std::to_string(participant) + ":" + detail;
            any_provider_error = true;
        }
        if (any_provider_error) error_ += "]";
        if (all_acceptance_checks_completed)
            error_ = "provider acceptance checks completed but backend registration did not complete; " +
                error_;
        return false;
    }
    error_.clear();
    return true;
}

void SharedLibraryMultiplicationConsistencyProviderSession::Reset() {
    if (session_)
        session_->Reset();
}

MultiplicationConsistencyProofArtifact
SharedLibraryMultiplicationConsistencyProviderSession::Prove(
    const MultiplicationConsistencyStatement& statement,
    const MultiplicationConsistencyWitness& witness) const {
    provider_operation_error_.clear();
    MultiplicationConsistencyProofArtifact proof;
    if (!prove_fn_) {
        provider_operation_error_ = "ABI prove function is unavailable";
        return proof;
    }
    if (!validate_multiplication_consistency_statement(statement)) {
        provider_operation_error_ = "statement failed canonical validation";
        return proof;
    }
    const auto statement_words =
        encode_multiplication_consistency_statement_abi(statement);
    const auto witness_words =
        encode_multiplication_consistency_witness_abi(witness);
    pvia_mc_statement_view c_statement{};
    pvia_mc_witness_view c_witness{};
    if (!pvia_mc_parse_statement(
            statement_words.data(), statement_words.size(),
            &c_statement) ||
        !pvia_mc_parse_witness(
            witness_words.data(), witness_words.size(),
            &c_witness) ||
        !pvia_mc_validate_witness_payloads(&c_witness)) {
        provider_operation_error_ = "ABI statement/witness parse or payload validation failed";
        return proof;
    }
    ProofConcurrencyPermit proof_permit;
    if (!proof_permit.Acquire(&provider_operation_error_))
        return proof;
    size_t proof_count = 0;
    if (prove_fn_(
            statement_words.data(), statement_words.size(),
            witness_words.data(), witness_words.size(),
            nullptr, &proof_count) != 1 ||
        proof_count == 0 || proof_count > MAX_PROVIDER_WORDS) {
        provider_operation_error_ = "ABI prove size query failed";
        return proof;
    }
    std::vector<uint64_t> proof_words(proof_count);
    size_t actual = proof_count;
    if (prove_fn_(
            statement_words.data(), statement_words.size(),
            witness_words.data(), witness_words.size(),
            proof_words.data(), &actual) != 1 ||
        actual != proof_count) {
        provider_operation_error_ = "ABI prove operation failed or returned an unexpected proof size";
        return MultiplicationConsistencyProofArtifact{};
    }
    const std::vector<u64> internal_proof_words(
        proof_words.begin(), proof_words.end());
    if (!decode_multiplication_consistency_proof_artifact(
            internal_proof_words, &proof)) {
        provider_operation_error_ = "ABI proof artifact decoding failed";
        return MultiplicationConsistencyProofArtifact{};
    }
    return proof;
}

bool SharedLibraryMultiplicationConsistencyProviderSession::Verify(
    const MultiplicationConsistencyStatement& statement,
    const MultiplicationConsistencyProofArtifact& proof) const {
    provider_operation_error_.clear();
    if (!verify_fn_) {
        provider_operation_error_ = "ABI verify function is unavailable";
        return false;
    }
    if (!validate_multiplication_consistency_statement(statement) ||
        !validate_multiplication_consistency_proof_artifact(
            statement, proof)) {
        provider_operation_error_ = "statement/proof failed canonical validation before ABI verify";
        return false;
    }
    const auto statement_words =
        encode_multiplication_consistency_statement_abi(statement);
    const auto internal_proof_words =
        encode_multiplication_consistency_proof_artifact(proof);
    const std::vector<uint64_t> proof_words(
        internal_proof_words.begin(), internal_proof_words.end());
    if (verify_fn_(
            statement_words.data(), statement_words.size(),
            proof_words.data(), proof_words.size()) != 1) {
        provider_operation_error_ = "ABI verify function rejected proof";
        return false;
    }
    return true;
}

void SharedLibraryMultiplicationConsistencyProviderSession::Close() {
    session_.reset();
    version_fn_ = nullptr;
    capabilities_fn_ = nullptr;
    prove_fn_ = nullptr;
    verify_fn_ = nullptr;
    capabilities_ = MultiplicationConsistencyCapabilities{};
    if (handle_) {
        dlclose(handle_);
        handle_ = nullptr;
    }
}

} // namespace pvia
