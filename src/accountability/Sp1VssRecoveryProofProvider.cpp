#include "Sp1VssRecoveryProofProvider.hpp"

#include "ReferenceVssSelectivePointCommitment.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <fstream>
#include <iterator>
#include <limits>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace pvia {
namespace {

constexpr uint64_t RECOVERY_STATEMENT_DOMAIN = 0x5056524350525331ULL;
constexpr uint64_t RECOVERY_WITNESS_DOMAIN = 0x5056524350574954ULL;
constexpr uint64_t RECOVERY_RELATION_ABI = 1;
constexpr uint64_t RECOVERY_FIELD_MODULUS = 2305843009213693951ULL;
constexpr size_t RECOVERY_STATEMENT_PREFIX_WORDS = 13;
constexpr size_t RECOVERY_STATEMENT_DIGESTS = 18;
constexpr size_t RECOVERY_STATEMENT_WORDS =
    RECOVERY_STATEMENT_PREFIX_WORDS + 4 * RECOVERY_STATEMENT_DIGESTS;
constexpr size_t RECOVERY_MAX_WORLD_SIZE = 128;
constexpr size_t RECOVERY_MAX_ELEMENTS = 1U << 16;
constexpr size_t RECOVERY_MAX_WITNESS_WORDS = 1U << 24;

void append_digest(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        uint64_t word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

bool digest_nonzero(const Digest& digest) {
    return digest != Digest{};
}

bool append_field(const F& value, std::vector<u64>* words) {
    if (!words || value.real >= RECOVERY_FIELD_MODULUS ||
        value.img >= RECOVERY_FIELD_MODULUS)
        return false;
    words->push_back(static_cast<uint64_t>(value.real));
    words->push_back(static_cast<uint64_t>(value.img));
    return true;
}

Digest recovery_request_context_digest(
    const AuthenticatedRecoveryRequest& request) {
    std::vector<u64> words = {
        request.label.sid,
        static_cast<uint64_t>(request.label.phase),
        request.label.round,
        request.label.owner,
        static_cast<uint64_t>(request.label.obligation),
        request.label.object_id,
        request.checkpoint,
        static_cast<uint64_t>(request.relation),
        static_cast<uint64_t>(request.kernel)
    };
    append_digest(request.expected, &words);
    append_digest(request.actual, &words);
    append_digest(request.residual_commitment, &words);
    append_digest(request.operation_statement_binding, &words);
    append_digest(request.dispute_binding, &words);
    append_digest(request.checkpoint_root, &words);
    return hash_words(words);
}

bool write_all(int fd, const void* data, size_t size) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    size_t offset = 0;
    while (offset < size) {
        const ssize_t written = ::write(fd, bytes + offset, size - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return false;
        offset += static_cast<size_t>(written);
    }
    return true;
}

bool write_words(int fd, const std::vector<u64>& words) {
    static const uint16_t endian_probe = 1;
    if (*reinterpret_cast<const uint8_t*>(&endian_probe) != 1) return false;
    return words.empty() ||
        write_all(fd, words.data(), words.size() * sizeof(uint64_t));
}

} // namespace

bool Sp1VssRecoveryProofProvider::BuildRelationInput(
    const ReferenceVssRecoveryProofWitness& witness,
    const AuthenticatedRecoveryRequest& request,
    const AuthenticatedRecoveryArtifact& artifact,
    std::vector<u64>* statement_words,
    std::vector<u64>* witness_words) const {
    if (!statement_words || !witness_words) return false;
    statement_words->clear();
    witness_words->clear();

    if (!witness.available || witness.target < 0 ||
        witness.world_size < 4 ||
        witness.world_size > static_cast<int>(RECOVERY_MAX_WORLD_SIZE) ||
        witness.threshold < 0 ||
        static_cast<size_t>(witness.threshold) * 3 >=
            static_cast<size_t>(witness.world_size) ||
        witness.element_count == 0 ||
        witness.element_count > RECOVERY_MAX_ELEMENTS ||
        witness.target >= witness.world_size ||
        witness.sid == 0 || witness.checkpoint == 0 ||
        witness.setup_round == 0 || witness.setup_sequence == 0 ||
        request.label.sid != witness.sid ||
        request.label.owner != static_cast<uint64_t>(witness.target) ||
        request.checkpoint != witness.checkpoint ||
        request.request_binding == Digest{} ||
        request.request_binding != compute_recovery_request_binding(request) ||
        artifact.accused.owner != static_cast<uint64_t>(witness.target) ||
        artifact.recovery_auth_signer !=
            static_cast<uint32_t>(witness.target) ||
        artifact.request_binding != request.request_binding ||
        artifact.recovery_registry_binding != witness.registry_binding ||
        artifact.recovery_share_commitment == Digest{} ||
        artifact.recovered_audit_commitment == Digest{} ||
        !validate_recovery_artifact(request, artifact))
        return false;

    const size_t n = static_cast<size_t>(witness.world_size);
    const size_t count = witness.element_count;
    if (n > std::numeric_limits<size_t>::max() / n ||
        witness.commitments.size() != n * n ||
        witness.openings.size() != n - 1)
        return false;

    ReferenceVssSelectivePointCommitmentRegistry registry;
    registry.available = true;
    registry.world_size = witness.world_size;
    registry.element_count = witness.element_count;
    registry.vss_transcript = witness.vss_transcript;
    registry.sid = witness.sid;
    registry.checkpoint = witness.checkpoint;
    registry.setup_round = witness.setup_round;
    registry.setup_sequence = witness.setup_sequence;
    registry.setup_context_binding = witness.setup_context_binding;
    registry.signed_commit_transport = witness.signed_commit_transport;
    registry.signed_ack_transport = witness.signed_ack_transport;
    registry.registry_binding = witness.registry_binding;
    registry.commitments = witness.commitments;
    if (!validate_reference_vss_point_commitment_registry(registry))
        return false;

    const std::array<Digest, RECOVERY_STATEMENT_DIGESTS> digests = {{
        witness.vss_transcript,
        witness.setup_context_binding,
        witness.signed_commit_transport,
        witness.signed_ack_transport,
        witness.registry_binding,
        request.request_binding,
        request.operation_statement_binding,
        request.dispute_binding,
        artifact.predecessor_root,
        artifact.checkpoint_root,
        artifact.recovery_share_commitment,
        artifact.recovered_audit_commitment,
        artifact.recovery_agreement_binding,
        artifact.recovery_replay_head,
        artifact.recovery_auth_registry_binding,
        artifact.authentication_proof_commitment,
        artifact.recovery_transcript_binding,
        recovery_request_context_digest(request)
    }};
    for (const auto& digest : digests)
        if (!digest_nonzero(digest)) return false;

    std::vector<u64> statement = {
        RECOVERY_STATEMENT_DOMAIN,
        RECOVERY_RELATION_ABI,
        static_cast<uint64_t>(witness.world_size),
        static_cast<uint64_t>(witness.threshold),
        static_cast<uint64_t>(witness.target),
        static_cast<uint64_t>(witness.element_count),
        witness.sid,
        witness.checkpoint,
        witness.setup_round,
        witness.setup_sequence,
        static_cast<uint64_t>(request.relation),
        static_cast<uint64_t>(request.kernel),
        static_cast<uint64_t>(artifact.recovery_auth_signer)
    };
    for (const auto& digest : digests) append_digest(digest, &statement);
    if (statement.size() != RECOVERY_STATEMENT_WORDS) return false;

    std::vector<u64> proof_witness = {
        RECOVERY_WITNESS_DOMAIN,
        RECOVERY_RELATION_ABI,
        static_cast<uint64_t>(witness.commitments.size())
    };
    for (const auto& commitment : witness.commitments) {
        if (!digest_nonzero(commitment)) return false;
        append_digest(commitment, &proof_witness);
    }
    proof_witness.push_back(static_cast<uint64_t>(witness.openings.size()));

    for (size_t i = 0; i < witness.openings.size(); ++i) {
        const auto& opening = witness.openings[i];
        const size_t expected_helper =
            i < static_cast<size_t>(witness.target) ? i : i + 1;
        if (opening.helper < 0 ||
            static_cast<size_t>(opening.helper) != expected_helper ||
            opening.target != witness.target ||
            opening.transcript_binding != witness.vss_transcript ||
            opening.values.size() != count)
            return false;

        proof_witness.push_back(static_cast<uint64_t>(opening.helper));
        proof_witness.push_back(static_cast<uint64_t>(opening.target));
        proof_witness.push_back(static_cast<uint64_t>(opening.values.size()));
        for (const F& value : opening.values)
            if (!append_field(value, &proof_witness)) return false;
    }

    if (proof_witness.size() > RECOVERY_MAX_WITNESS_WORDS)
        return false;
    *statement_words = std::move(statement);
    *witness_words = std::move(proof_witness);
    return true;
}

bool Sp1VssRecoveryProofProvider::ExportRelationInput(
    const ReferenceVssRecoveryProofWitness& witness,
    const AuthenticatedRecoveryRequest& request,
    const AuthenticatedRecoveryArtifact& artifact,
    const std::string& output_dir,
    Sp1VssRecoveryInputInfo* info) const {
    if (!info) return false;
    *info = Sp1VssRecoveryInputInfo{};
    if (output_dir.empty()) return false;

    struct stat directory_status {};
    if (::stat(output_dir.c_str(), &directory_status) != 0 ||
        !S_ISDIR(directory_status.st_mode) ||
        directory_status.st_uid != ::geteuid() ||
        (directory_status.st_mode & 0077) != 0)
        return false;

    std::vector<u64> statement, proof_witness;
    if (!BuildRelationInput(
            witness, request, artifact, &statement, &proof_witness))
        return false;

    const std::string output_path =
        output_dir + "/vss_recovery_" +
        std::to_string(witness.sid) + "_" +
        std::to_string(witness.checkpoint) + ".input.bin";
    const int fd = ::open(
        output_path.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
        S_IRUSR | S_IWUSR);
    if (fd < 0) return false;

    const uint64_t statement_count =
        static_cast<uint64_t>(statement.size());
    const uint64_t witness_count =
        static_cast<uint64_t>(proof_witness.size());
    bool ok = write_all(fd, &statement_count, sizeof(statement_count)) &&
              write_all(fd, &witness_count, sizeof(witness_count)) &&
              write_words(fd, statement) &&
              write_words(fd, proof_witness) &&
              ::fsync(fd) == 0;
    const int close_result = ::close(fd);
    if (!ok || close_result != 0) {
        ::unlink(output_path.c_str());
        return false;
    }
    if (::chmod(output_path.c_str(), S_IRUSR | S_IWUSR) != 0) {
        ::unlink(output_path.c_str());
        return false;
    }

    info->available = true;
    info->statement_word_count = statement.size();
    info->witness_word_count = proof_witness.size();
    info->statement_binding = hash_words(statement);
    info->path = output_path;
    if (info->statement_binding == Digest{}) {
        ::unlink(output_path.c_str());
        *info = Sp1VssRecoveryInputInfo{};
        return false;
    }

    std::cerr << "[PVIA][sp1-vss-recovery-input-export] PASS"
              << " target=" << witness.target
              << " statement_words=" << statement.size()
              << " witness_words=" << proof_witness.size()
              << " statement_binding=" << info->statement_binding.hex()
              << " path=" << output_path
              << " private_input=1\n";
    return true;
}


bool Sp1VssRecoveryProofProvider::VerifyArtifactBytes(
    const std::vector<uint8_t>& artifact_bytes,
    const std::vector<u64>& expected_statement_words,
    Sp1VssRecoveryProofReceipt* receipt) const {
    if (receipt) *receipt = Sp1VssRecoveryProofReceipt{};
    constexpr size_t kHeaderWords = 18;
    constexpr size_t kStatementWords = 85;
    constexpr size_t kHeaderBytes = kHeaderWords * sizeof(uint64_t);
    constexpr uint64_t kMagic = 0x5056524350524631ULL;
    constexpr uint64_t kProofSystemId = 68103ULL;
    if (artifact_bytes.size() < kHeaderBytes + kStatementWords * 8 ||
        artifact_bytes.size() > (1ULL << 30) + 4096 ||
        expected_statement_words.size() != kStatementWords)
        return false;
    auto read_word = [&artifact_bytes](size_t offset, uint64_t* value) {
        if (!value || offset > artifact_bytes.size() ||
            artifact_bytes.size() - offset < 8) return false;
        uint64_t word = 0;
        for (size_t i = 0; i < 8; ++i)
            word |= static_cast<uint64_t>(artifact_bytes[offset + i]) << (8 * i);
        *value = word;
        return true;
    };
    std::array<uint64_t, kHeaderWords> header{};
    for (size_t i = 0; i < header.size(); ++i)
        if (!read_word(i * 8, &header[i])) return false;
    if (header[0] != kMagic || header[1] != 1 ||
        header[17] != kProofSystemId || header[4] != kStatementWords ||
        header[2] == 0 || header[2] > (1ULL << 30))
        return false;
    const uint64_t statement_bytes = kStatementWords * 8;
    if (artifact_bytes.size() < kHeaderBytes + statement_bytes ||
        header[2] != artifact_bytes.size() - kHeaderBytes - statement_bytes ||
        header[3] != kHeaderWords + kStatementWords + (header[2] + 7) / 8)
        return false;
    std::vector<uint64_t> embedded(kStatementWords, 0);
    for (size_t i = 0; i < embedded.size(); ++i)
        if (!read_word(kHeaderBytes + i * 8, &embedded[i])) return false;
    const std::vector<uint64_t> expected_words(
        expected_statement_words.begin(), expected_statement_words.end());
    if (embedded != expected_words) return false;

    const char* configured_verifier =
        std::getenv("PVIA_SP1_RECOVERY_VERIFIER_EXECUTABLE");
    const std::string verifier_path =
        configured_verifier && *configured_verifier
            ? configured_verifier
            : "experiments/sp1_provider/target/release/examples/verify_recovery_artifact";
    char artifact_template[] = "/tmp/pvia_sp1_recovery_artifact_XXXXXX";
    char statement_template[] = "/tmp/pvia_sp1_recovery_statement_XXXXXX";
    const int artifact_fd = ::mkstemp(artifact_template);
    if (artifact_fd < 0) return false;
    const int statement_fd = ::mkstemp(statement_template);
    if (statement_fd < 0) {
        ::close(artifact_fd);
        ::unlink(artifact_template);
        return false;
    }
    static const uint16_t endian_probe = 1;
    bool files_ok = *reinterpret_cast<const uint8_t*>(&endian_probe) == 1 &&
        write_all(artifact_fd, artifact_bytes.data(), artifact_bytes.size()) &&
        write_all(statement_fd, expected_words.data(),
                  expected_words.size() * sizeof(uint64_t)) &&
        ::fsync(artifact_fd) == 0 && ::fsync(statement_fd) == 0 &&
        ::fchmod(artifact_fd, S_IRUSR | S_IWUSR) == 0 &&
        ::fchmod(statement_fd, S_IRUSR | S_IWUSR) == 0;
    const int artifact_close = ::close(artifact_fd);
    const int statement_close = ::close(statement_fd);
    files_ok = files_ok && artifact_close == 0 && statement_close == 0;

    bool valid = false;
    if (files_ok) {
        const pid_t child = ::fork();
        if (child == 0) {
            char* child_argv[] = {
                const_cast<char*>(verifier_path.c_str()),
                artifact_template, statement_template, nullptr
            };
            const char* verbose =
                std::getenv("PVIA_SP1_RECOVERY_VERIFIER_VERBOSE");
            if (!verbose || std::strcmp(verbose, "1") != 0) {
                const int null_fd = ::open("/dev/null", O_WRONLY);
                if (null_fd >= 0) {
                    ::dup2(null_fd, STDOUT_FILENO);
                    ::dup2(null_fd, STDERR_FILENO);
                    ::close(null_fd);
                }
            }
            // Preserve the caller's complete SP1/Rust environment. execv uses
            // the inherited environment and avoids a fragile hand-built envp.
            ::execv(verifier_path.c_str(), child_argv);
            _exit(errno == ENOENT ? 127 : 126);
        }
        if (child > 0) {
            int status = 0;
            pid_t waited = -1;
            do {
                waited = ::waitpid(child, &status, 0);
            } while (waited < 0 && errno == EINTR);
            valid = waited == child && WIFEXITED(status) &&
                WEXITSTATUS(status) == 0;
            if (!valid) {
                if (waited != child)
                    std::cerr << "[PVIA][sp1-vss-recovery] verifier wait failed"
                              << " errno=" << errno << "\n";
                else if (WIFEXITED(status))
                    std::cerr << "[PVIA][sp1-vss-recovery] verifier exit="
                              << WEXITSTATUS(status) << "\n";
                else if (WIFSIGNALED(status))
                    std::cerr << "[PVIA][sp1-vss-recovery] verifier signal="
                              << WTERMSIG(status) << "\n";
            }
        }
    }
    ::unlink(artifact_template);
    ::unlink(statement_template);
    if (!valid) return false;
    if (receipt) {
        auto load_digest = [&header](size_t offset) {
            Digest digest{};
            for (size_t i = 0; i < 4; ++i)
                for (size_t j = 0; j < 8; ++j)
                    digest.bytes[i * 8 + j] =
                        static_cast<uint8_t>(header[offset + i] >> (8 * j));
            return digest;
        };
        receipt->available = true;
        receipt->proof_verified = true;
        receipt->proof_system_id = static_cast<uint32_t>(header[17]);
        receipt->statement_binding = load_digest(5);
        receipt->artifact_commitment = load_digest(13);
        receipt->statement_words = expected_statement_words;
        receipt->artifact_bytes = artifact_bytes;
        if (receipt->statement_binding == Digest{} ||
            receipt->artifact_commitment == Digest{})
            return false;
    }
    return true;
}



bool Sp1VssRecoveryProofProvider::LoadArtifact(
    const std::string& artifact_path,
    const std::vector<u64>& expected_statement_words,
    Sp1VssRecoveryProofReceipt* receipt) const {
    if (!receipt) return false;
    *receipt = Sp1VssRecoveryProofReceipt{};
    if (artifact_path.empty() || expected_statement_words.size() != 85)
        return false;
    std::ifstream input(artifact_path, std::ios::binary);
    if (!input) return false;
    std::vector<uint8_t> bytes(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>());
    constexpr size_t kHeaderWords = 18;
    constexpr size_t kStatementWords = 85;
    constexpr size_t kHeaderBytes = kHeaderWords * sizeof(uint64_t);
    constexpr uint64_t kMagic = 0x5056524350524631ULL;
    constexpr uint64_t kProofSystemId = 68103ULL;
    if (bytes.size() < kHeaderBytes + kStatementWords * 8 ||
        bytes.size() > (1ULL << 30) + 4096)
        return false;

    auto read_word = [&bytes](size_t offset, uint64_t* value) {
        if (!value || offset > bytes.size() || bytes.size() - offset < 8)
            return false;
        uint64_t word = 0;
        for (size_t i = 0; i < 8; ++i)
            word |= static_cast<uint64_t>(bytes[offset + i]) << (8 * i);
        *value = word;
        return true;
    };
    std::array<uint64_t, kHeaderWords> header{};
    for (size_t i = 0; i < header.size(); ++i)
        if (!read_word(i * 8, &header[i])) return false;
    if (header[0] != kMagic || header[1] != 1 ||
        header[17] != kProofSystemId || header[4] != kStatementWords ||
        header[2] == 0 || header[2] > (1ULL << 30) ||
        header[2] != bytes.size() - kHeaderBytes - kStatementWords * 8)
        return false;
    const uint64_t proof_word_count = (header[2] + 7) / 8;
    if (header[3] != kHeaderWords + kStatementWords + proof_word_count)
        return false;

    std::vector<u64> embedded_statement(kStatementWords, 0);
    for (size_t i = 0; i < embedded_statement.size(); ++i) {
        uint64_t word = 0;
        if (!read_word(kHeaderBytes + i * 8, &word)) return false;
        embedded_statement[i] = static_cast<u64>(word);
    }
    if (embedded_statement != expected_statement_words) return false;

    auto load_digest = [&header](size_t offset) {
        Digest digest{};
        for (size_t i = 0; i < 4; ++i)
            for (size_t j = 0; j < 8; ++j)
                digest.bytes[i * 8 + j] =
                    static_cast<uint8_t>(header[offset + i] >> (8 * j));
        return digest;
    };
    const Digest statement_binding = load_digest(5);
    const Digest transcript_binding = load_digest(9);
    const Digest artifact_commitment = load_digest(13);
    if (statement_binding == Digest{} || transcript_binding == Digest{} ||
        artifact_commitment == Digest{} ||
        hash_words(expected_statement_words) != statement_binding)
        return false;

    std::vector<u64> proof_words;
    proof_words.reserve(static_cast<size_t>(proof_word_count));
    const size_t proof_offset = kHeaderBytes + kStatementWords * 8;
    for (size_t i = 0; i < static_cast<size_t>(proof_word_count); ++i) {
        u64 word = 0;
        for (size_t j = 0; j < 8; ++j) {
            const size_t byte_offset = proof_offset + i * 8 + j;
            if (byte_offset < bytes.size())
                word |= static_cast<u64>(bytes[byte_offset]) << (8 * j);
        }
        proof_words.push_back(word);
    }
    std::vector<u64> commitment_words = {
        kMagic, 1ULL, kProofSystemId,
        static_cast<u64>(kStatementWords),
        static_cast<u64>(proof_words.size())
    };
    append_digest(statement_binding, &commitment_words);
    append_digest(transcript_binding, &commitment_words);
    commitment_words.insert(
        commitment_words.end(), expected_statement_words.begin(),
        expected_statement_words.end());
    commitment_words.insert(
        commitment_words.end(), proof_words.begin(), proof_words.end());
    if (hash_words(commitment_words) != artifact_commitment)
        return false;

    receipt->available = true;
    receipt->proof_verified = false;
    receipt->proof_system_id = static_cast<uint32_t>(header[17]);
    receipt->statement_binding = statement_binding;
    receipt->artifact_commitment = artifact_commitment;
    receipt->statement_words = expected_statement_words;
    receipt->artifact_bytes = std::move(bytes);
    return true;
}

bool Sp1VssRecoveryProofProvider::LoadAndVerifyArtifact(
    const std::string& artifact_path,
    const std::vector<u64>& expected_statement_words,
    Sp1VssRecoveryProofReceipt* receipt) const {
    if (!receipt) return false;
    *receipt = Sp1VssRecoveryProofReceipt{};
    Sp1VssRecoveryProofReceipt loaded;
    if (!LoadArtifact(artifact_path, expected_statement_words, &loaded))
        return false;
    Sp1VssRecoveryProofReceipt verified;
    if (!VerifyArtifactBytes(
            loaded.artifact_bytes, expected_statement_words, &verified))
        return false;
    *receipt = std::move(verified);
    return receipt->available && receipt->proof_verified &&
           receipt->proof_system_id == loaded.proof_system_id &&
           receipt->statement_binding == loaded.statement_binding &&
           receipt->artifact_commitment == loaded.artifact_commitment;
}


bool run_sp1_vss_recovery_proof_envelope_selftest() {
    const char* artifact_path =
        std::getenv("PVIA_SP1_VSS_RECOVERY_PROOF_ARTIFACT");
    const char* statement_path =
        std::getenv("PVIA_SP1_VSS_RECOVERY_STATEMENT");
    if (!artifact_path || !*artifact_path ||
        !statement_path || !*statement_path)
        return false;
    std::ifstream statement_file(statement_path, std::ios::binary);
    if (!statement_file) return false;
    std::vector<uint8_t> statement_bytes(
        (std::istreambuf_iterator<char>(statement_file)),
        std::istreambuf_iterator<char>());
    if (statement_bytes.size() != 85 * sizeof(uint64_t)) return false;
    std::vector<u64> statement(85, 0);
    for (size_t i = 0; i < statement.size(); ++i) {
        uint64_t word = 0;
        for (size_t j = 0; j < 8; ++j)
            word |= static_cast<uint64_t>(statement_bytes[i * 8 + j]) << (8 * j);
        statement[i] = static_cast<u64>(word);
    }
    Sp1VssRecoveryProofProvider provider;
    Sp1VssRecoveryProofReceipt receipt;
    const bool loaded =
        provider.LoadArtifact(artifact_path, statement, &receipt);
    const bool passed = loaded && receipt.available &&
        !receipt.proof_verified && receipt.proof_system_id == 68103 &&
        receipt.statement_words == statement &&
        !receipt.artifact_bytes.empty() &&
        receipt.statement_binding == hash_words(statement);
    std::cout << "[PVIA][sp1-vss-recovery-envelope-selftest] "
              << (passed ? "PASS" : "FAIL")
              << " loaded=" << (loaded ? 1 : 0)
              << " proof_verified=0"
              << " proof_system_id=" << receipt.proof_system_id
              << " statement_words=" << receipt.statement_words.size()
              << " artifact_bytes=" << receipt.artifact_bytes.size() << "\n";
    return passed;
}


bool run_sp1_vss_recovery_proof_verifier_selftest() {
    const char* artifact_path =
        std::getenv("PVIA_SP1_VSS_RECOVERY_PROOF_ARTIFACT");
    const char* statement_path =
        std::getenv("PVIA_SP1_VSS_RECOVERY_STATEMENT");
    const char* tampered_path =
        std::getenv("PVIA_SP1_VSS_RECOVERY_TAMPERED_ARTIFACT");
    if (!artifact_path || !*artifact_path ||
        !statement_path || !*statement_path ||
        !tampered_path || !*tampered_path)
        return false;

    std::ifstream statement_file(statement_path, std::ios::binary);
    if (!statement_file) return false;
    std::vector<uint8_t> statement_bytes(
        (std::istreambuf_iterator<char>(statement_file)),
        std::istreambuf_iterator<char>());
    if (statement_bytes.size() != 85 * sizeof(uint64_t)) return false;
    std::vector<u64> statement(85, 0);
    for (size_t i = 0; i < statement.size(); ++i) {
        uint64_t word = 0;
        for (size_t j = 0; j < 8; ++j)
            word |= static_cast<uint64_t>(statement_bytes[i * 8 + j]) << (8 * j);
        statement[i] = static_cast<u64>(word);
    }

    Sp1VssRecoveryProofProvider provider;
    Sp1VssRecoveryProofReceipt receipt;
    const bool valid = provider.LoadAndVerifyArtifact(
        artifact_path, statement, &receipt);
    std::ifstream tampered_file(tampered_path, std::ios::binary);
    if (!tampered_file) return false;
    std::vector<uint8_t> tampered_bytes(
        (std::istreambuf_iterator<char>(tampered_file)),
        std::istreambuf_iterator<char>());
    const bool tamper_rejected =
        !provider.VerifyArtifactBytes(tampered_bytes, statement);
    std::vector<u64> wrong_statement = statement;
    wrong_statement[0] ^= 1;
    const bool wrong_statement_rejected =
        !provider.VerifyArtifactBytes(receipt.artifact_bytes, wrong_statement);
    const bool passed = valid && receipt.available && receipt.proof_verified &&
        receipt.proof_system_id == 68103 &&
        receipt.statement_words == statement &&
        !receipt.artifact_bytes.empty() &&
        tamper_rejected && wrong_statement_rejected;
    std::cout << "[PVIA][sp1-vss-recovery-verifier-selftest] "
              << (passed ? "PASS" : "FAIL")
              << " valid=" << (valid ? 1 : 0)
              << " tamper_rejected=" << (tamper_rejected ? 1 : 0)
              << " wrong_statement_rejected="
              << (wrong_statement_rejected ? 1 : 0) << "\n";
    return passed;
}

} // namespace pvia
