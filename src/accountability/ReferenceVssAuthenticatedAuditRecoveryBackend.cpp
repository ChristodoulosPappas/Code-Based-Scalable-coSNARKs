#include "ReferenceVssAuthenticatedAuditRecoveryBackend.hpp"
#include "ReferenceShamirAuditSession.hpp"
#include "TransferAuthentication.hpp"
#include "Sp1VssRecoveryProofProvider.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

namespace pvia {
namespace {

constexpr u64 RECOVERY_DOMAIN = 0x5056494152565331ULL; // PVIARVS1
constexpr u64 PREFLIGHT_KIND = 0x5056524350524631ULL; // PVRCPRF1
constexpr u64 REQUEST_KIND = 0x5056524352455131ULL;   // PVRCREQ1
constexpr u64 RELEASE_GATE_KIND = 0x5056524352475431ULL; // PVRCGT1
constexpr u64 RESULT_GATE_KIND = 0x5056524352475432ULL;  // PVRCGT2
constexpr u64 SHARE_GATE_KIND = 0x5056524352475433ULL;  // PVRCGT3
constexpr u64 SIGNATURE_GATE_KIND = 0x5056524352475434ULL; // PVRCGT4
constexpr u64 SIGNATURE_KIND = 0x5056524353494731ULL; // PVRSIG1
constexpr u64 SIGNATURE_VERIFY_GATE_KIND = 0x5056524356475431ULL; // PVRVGT1
constexpr u64 PROOF_EXPORT_GATE_KIND = 0x5056524350475431ULL; // PVRCPGT1
constexpr u64 PROOF_GENERATE_GATE_KIND = 0x5056524350475432ULL; // PVRCPGT2
constexpr u64 PROOF_STATEMENT_KIND = 0x5056524350535431ULL; // PVRCPST1
constexpr u64 PROOF_IMPORT_GATE_KIND = 0x5056524350475433ULL; // PVRCPGT3
constexpr u64 PROOF_ARTIFACT_KIND = 0x5056524350415231ULL; // PVRCPAR1
constexpr u64 SUMMARY_KIND = 0x5056524353554d31ULL;  // PVRSUM1
constexpr u64 AGREEMENT_KIND = 0x5056524341475231ULL; // PVRCAGR1
constexpr u64 SUMMARY_MAGIC = 0x50565243534d5231ULL; // PVRCSMR1
constexpr u64 AGREEMENT_MAGIC = 0x5056524341475232ULL; // PVRCAGR2
constexpr u64 AUTH_RECEIPT_DOMAIN = 0x5056524341555431ULL; // PVRCAUT1
constexpr u64 SIGNATURE_MAGIC = 0x5056524353494732ULL; // PVRSIG2

void append_digest(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        for (size_t j = 0; j < 8; ++j)
            word |= static_cast<u64>(digest.bytes[i * 8 + j]) << (8 * j);
        words->push_back(word);
    }
}

Digest read_digest(const std::vector<u64>& words, size_t offset) {
    Digest digest{};
    if (offset > words.size() || words.size() - offset < 4) return digest;
    for (size_t i = 0; i < 4; ++i)
        for (size_t j = 0; j < 8; ++j)
            digest.bytes[i * 8 + j] =
                static_cast<uint8_t>(words[offset + i] >> (8 * j));
    return digest;
}

AuthenticatedMpcMessageContext derive_context(
    const AuthenticatedMpcMessageContext& base, u64 kind) {
    AuthenticatedMpcMessageContext context = base;
    context.protocol_domain = RECOVERY_DOMAIN;
    context.message_kind = kind;
    return context;
}

OperationRef request_operation(const AuthenticatedRecoveryRequest& request) {
    return OperationRef{request.label.owner, request.label.object_id};
}

std::vector<u64> recovery_receipt_message(
    const AuthenticatedRecoveryRequest& request,
    uint32_t signer,
    const Digest& recovered_commitment,
    const Digest& summary_binding,
    const Digest& agreement_binding,
    const Digest& replay_head,
    const Digest& registry_binding,
    const Digest& predecessor_root,
    const Digest& checkpoint_root) {
    std::vector<u64> words = {
        AUTH_RECEIPT_DOMAIN, signer, request.checkpoint,
        static_cast<u64>(request.relation),
        static_cast<u64>(request.kernel)};
    append_digest(request.request_binding, &words);
    append_digest(request.operation_statement_binding, &words);
    append_digest(request.dispute_binding, &words);
    append_digest(recovered_commitment, &words);
    append_digest(summary_binding, &words);
    append_digest(agreement_binding, &words);
    append_digest(replay_head, &words);
    append_digest(registry_binding, &words);
    append_digest(predecessor_root, &words);
    append_digest(checkpoint_root, &words);
    return words;
}

Digest authentication_receipt_commitment(
    const std::vector<u64>& message,
    uint32_t signer,
    const Digest& authentication_registry_binding,
    const std::array<uint8_t, 64>& signature) {
    if (message.empty() || signer == 0xffffffffU ||
        authentication_registry_binding == Digest{})
        return {};
    std::vector<u64> words = {AUTH_RECEIPT_DOMAIN, signer};
    words.insert(words.end(), message.begin(), message.end());
    append_digest(authentication_registry_binding, &words);
    for (size_t i = 0; i < signature.size(); i += 8) {
        u64 word = 0;
        std::memcpy(&word, signature.data() + i, 8);
        words.push_back(word);
    }
    return hash_words(words);
}

bool env_is_one(const char* name) {
    const char* value = std::getenv(name);
    return value && std::string(value) == "1";
}

bool run_sp1_recovery_prover(
    const std::string& input_path,
    const std::string& proof_path) {
    if (input_path.empty() || proof_path.empty()) return false;
    struct stat existing {};
    if (::lstat(proof_path.c_str(), &existing) == 0 || errno != ENOENT)
        return false;

    const std::string lock_path = proof_path + ".lock";
    const int lock_fd = ::open(
        lock_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
        S_IRUSR | S_IWUSR);
    if (lock_fd < 0) return false;

    const char* configured =
        std::getenv("PVIA_SP1_RECOVERY_PROVER_EXECUTABLE");
    const std::string prover_path =
        configured && *configured
            ? configured
            : "experiments/sp1_provider/target/release/examples/prove_recovery_words";
    const bool verbose =
        std::getenv("PVIA_SP1_RECOVERY_PROVER_VERBOSE") &&
        std::string(std::getenv("PVIA_SP1_RECOVERY_PROVER_VERBOSE")) == "1";
    char* child_argv[] = {
        const_cast<char*>(prover_path.c_str()),
        const_cast<char*>(input_path.c_str()),
        const_cast<char*>(proof_path.c_str()),
        nullptr
    };

    bool generated = false;
    const pid_t child = ::fork();
    if (child == 0) {
        if (!verbose) {
            const int null_fd = ::open("/dev/null", O_WRONLY);
            if (null_fd >= 0) {
                ::dup2(null_fd, STDOUT_FILENO);
                ::dup2(null_fd, STDERR_FILENO);
                ::close(null_fd);
            }
        }
        ::execv(prover_path.c_str(), child_argv);
        _exit(errno == ENOENT ? 127 : 126);
    }
    if (child > 0) {
        int status = 0;
        pid_t waited = -1;
        do {
            waited = ::waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR);
        generated = waited == child && WIFEXITED(status) &&
            WEXITSTATUS(status) == 0;
        if (!generated && waited == child) {
            if (WIFEXITED(status))
                std::cerr << "[PVIA][sp1-vss-recovery-prover] exit="
                          << WEXITSTATUS(status) << "\n";
            else if (WIFSIGNALED(status))
                std::cerr << "[PVIA][sp1-vss-recovery-prover] signal="
                          << WTERMSIG(status) << "\n";
        }
    }
    ::close(lock_fd);
    ::unlink(lock_path.c_str());

    struct stat proof_status {};
    if (!generated ||
        ::stat(proof_path.c_str(), &proof_status) != 0 ||
        !S_ISREG(proof_status.st_mode) ||
        proof_status.st_uid != ::geteuid() ||
        proof_status.st_size <= 0 ||
        static_cast<uint64_t>(proof_status.st_size) > (1ULL << 30) + 4096 ||
        ::chmod(proof_path.c_str(), S_IRUSR | S_IWUSR) != 0) {
        ::unlink(proof_path.c_str());
        return false;
    }
    return true;
}


std::array<uint8_t, 64> read_signature(
    const std::vector<u64>& words, size_t offset) {
    std::array<uint8_t, 64> signature{};
    if (offset > words.size() || words.size() - offset < 8)
        return signature;
    for (size_t i = 0; i < 8; ++i)
        std::memcpy(signature.data() + i * 8, &words[offset + i], 8);
    return signature;
}

bool all_zero(const std::vector<u64>& words, size_t offset, size_t count) {
    if (offset > words.size() || count > words.size() - offset) return false;
    for (size_t i = 0; i < count; ++i)
        if (words[offset + i] != 0) return false;
    return true;
}

} // namespace

bool bind_reference_shamir_selected_audit_witness(
    const ReferenceShamirSelectedAuditWitness& selected,
    ReferenceVssAuthenticatedRecoveryConfig* config) {
    if (!config || !selected.available ||
        !validate_reference_vss_local_witness(
            selected.registration_vss_witness))
        return false;
    const auto& local = selected.registration_vss_witness;
    const auto& receipt = selected.registration_vss_receipt;
    if (!receipt.available || !receipt.consistent ||
        receipt.dealer != local.dealer ||
        receipt.world_size != local.transcript_context.world_size ||
        receipt.element_count != local.element_count ||
        receipt.transcript_binding != local.transcript_binding ||
        receipt.local_row_commitment != local.local_row_commitment)
        return false;
    config->local_witness = &local;
    config->receipt = &receipt;
    config->trusted_transcript = &local.transcript_context;
    return true;
}

ReferenceVssAuthenticatedAuditRecoveryBackend::
ReferenceVssAuthenticatedAuditRecoveryBackend(
    ReferenceVssAuthenticatedRecoveryConfig config)
    : config_(std::move(config)),
      next_sequence_(config_.release_context.sequence),
      current_replay_head_(
          config_.target_pins.independently_pinned_replay_head) {}

AuthenticatedRecoveryArtifact
ReferenceVssAuthenticatedAuditRecoveryBackend::Recover(
    const AuthenticatedRecoveryRequest& request,
    int rank,
    int world_size) const {
    AuthenticatedRecoveryArtifact unavailable;
    unavailable.accused = request_operation(request);
    unavailable.checkpoint = request.checkpoint;
    unavailable.relation = request.relation;
    unavailable.kernel = request.kernel;
    unavailable.request_binding = request.request_binding;
    unavailable.operation_statement_binding =
        request.operation_statement_binding;
    unavailable.dispute_binding = request.dispute_binding;
    unavailable.checkpoint_root = request.checkpoint_root;

    if (!config_.exchange || !config_.exchange->ready() ||
        !config_.local_witness || !config_.receipt ||
        !config_.trusted_transcript ||
        !validate_authenticated_mpc_message_context(
            config_.release_context) ||
        config_.release_context.protocol_domain !=
            PVIA_VSS_SELECTIVE_POINT_DOMAIN ||
        config_.release_context.message_kind !=
            PVIA_VSS_SELECTIVE_POINT_KIND ||
        config_.release_context.sequence == 0 ||
        next_sequence_ == 0 ||
        next_sequence_ == std::numeric_limits<u64>::max() ||
        rank < 0 || world_size < 4 || rank >= world_size ||
        config_.release_context.sequence > next_sequence_)
        return unavailable;

    const u64 sequence = next_sequence_++;
    const u64 sequence_delta =
        sequence - config_.release_context.sequence;
    if (config_.release_context.round >
        std::numeric_limits<u64>::max() - sequence_delta)
        return unavailable;

    const int target = static_cast<int>(request.label.owner);
    const auto& local = *config_.local_witness;
    const auto& receipt = *config_.receipt;
    const bool request_valid =
        request.request_binding != Digest{} &&
        request.request_binding ==
            compute_recovery_request_binding(request) &&
        request.label.sid == config_.release_context.sid &&
        request.checkpoint == config_.release_context.checkpoint &&
        request.checkpoint_root ==
            config_.independently_pinned_checkpoint_root &&
        request.operation_statement_binding ==
            config_.independently_pinned_operation_statement_binding &&
        request.operation_statement_binding != Digest{} &&
        request.dispute_binding != Digest{} &&
        request.residual_commitment != Digest{} &&
        request.relation != RelationKind::UNKNOWN &&
        request.kernel != AuditRelationKernel::UNKNOWN &&
        request_operation(request) == config_.expected_operation &&
        target >= 0 && target < world_size &&
        receipt.available && receipt.consistent &&
        receipt.world_size == world_size && receipt.dealer == target &&
        receipt.transcript_binding == local.transcript_binding &&
        receipt.element_count == local.element_count &&
        receipt.local_row_commitment == local.local_row_commitment &&
        local.participant == rank && local.dealer == target &&
        local.transcript_context.world_size == world_size &&
        config_.trusted_transcript->world_size == world_size &&
        compute_reference_vss_transcript_binding(
            receipt.dealer, receipt.threshold, receipt.element_count,
            *config_.trusted_transcript) == receipt.transcript_binding &&
        validate_reference_vss_local_witness(local) &&
        config_.independently_pinned_predecessor_root != Digest{} &&
        config_.independently_pinned_checkpoint_root != Digest{} &&
        config_.independently_pinned_registry_binding != Digest{};

    bool target_pins_valid = true;
    if (rank == target) {
        const auto& pins = config_.target_pins;
        Digest live_replay_head{};
        target_pins_valid =
            pins.independently_pinned_record != Digest{} &&
            pins.independently_pinned_native_execution != Digest{} &&
            pins.independently_pinned_registry_binding ==
                config_.independently_pinned_registry_binding &&
            static_cast<bool>(pins.load_current_head) &&
            !pins.registry_path.empty() &&
            !pins.replay_journal_path.empty() &&
            static_cast<bool>(pins.verify_independent_pins) &&
            static_cast<bool>(pins.persist_new_head) &&
            pins.load_current_head(&live_replay_head) &&
            live_replay_head != Digest{};
        if (target_pins_valid) current_replay_head_ = live_replay_head;
        target_pins_valid = target_pins_valid &&
            pins.verify_independent_pins(
                pins.independently_pinned_record,
                pins.independently_pinned_native_execution,
                pins.independently_pinned_registry_binding,
                current_replay_head_);
    }

    auto base = config_.release_context;
    base.sequence = sequence;
    base.round += sequence_delta;
    auto preflight_context = derive_context(base, PREFLIGHT_KIND);
    bool all_preflight = false;
    Digest preflight_transport{};
    if (!config_.exchange->AllTrue(
            preflight_context, request_valid && target_pins_valid,
            &all_preflight, &preflight_transport) ||
        !all_preflight || preflight_transport == Digest{})
        return unavailable;

    std::vector<u64> request_words = {
        static_cast<u64>(target),
        config_.expected_operation.owner,
        config_.expected_operation.object_id};
    append_digest(request.request_binding, &request_words);
    append_digest(config_.independently_pinned_operation_statement_binding,
                  &request_words);
    append_digest(config_.independently_pinned_predecessor_root,
                  &request_words);
    append_digest(config_.independently_pinned_checkpoint_root,
                  &request_words);
    append_digest(config_.independently_pinned_registry_binding,
                  &request_words);
    auto request_context = derive_context(base, REQUEST_KIND);
    std::vector<u64> gathered_request;
    Digest request_transport{};
    if (!config_.exchange->AllGatherWords(
            request_context, request_words, &gathered_request,
            &request_transport) ||
        request_transport == Digest{} ||
        gathered_request.size() !=
            static_cast<size_t>(world_size) * request_words.size())
        return unavailable;
    for (int peer = 0; peer < world_size; ++peer) {
        const size_t offset =
            static_cast<size_t>(peer) * request_words.size();
        if (!std::equal(
                request_words.begin(), request_words.end(),
                gathered_request.begin() +
                    static_cast<std::ptrdiff_t>(offset)))
            return unavailable;
    }

    ReferenceVssSelectiveReleasePins pins = config_.target_pins;
    if (rank == target) {
        pins.independently_pinned_replay_head = current_replay_head_;
        const auto persist = config_.target_pins.persist_new_head;
        pins.persist_new_head =
            [this, persist](const Digest& expected, const Digest& next) {
                if (!persist || expected == Digest{} || next == Digest{} ||
                    expected != current_replay_head_ ||
                    !persist(expected, next))
                    return false;
                current_replay_head_ = next;
                return true;
            };
    }

    std::vector<F> recovered;
    Digest next_head{};
    ReferenceVssRecoveryProofWitness recovery_proof_witness;
    const bool local_release_ok =
        release_reference_vss_selective_share_collective(
            *config_.exchange, local, target, receipt,
            *config_.trusted_transcript, base,
            rank == target ? &pins : nullptr,
            &recovered, &next_head, &recovery_proof_witness);

    auto release_gate_context = derive_context(base, RELEASE_GATE_KIND);
    bool all_release_ok = false;
    Digest release_gate_binding{};
    const bool target_result_valid = rank != target ||
        (!recovered.empty() && recovered.size() == receipt.element_count &&
         next_head != Digest{} && next_head == current_replay_head_);
    auto result_gate_context = derive_context(base, RESULT_GATE_KIND);
    bool all_result_ok = false;
    Digest result_gate_binding{};
    if (!config_.exchange->AllTrue(
            release_gate_context, local_release_ok,
            &all_release_ok, &release_gate_binding) ||
        !all_release_ok || release_gate_binding == Digest{} ||
        !config_.exchange->AllTrue(
            result_gate_context, target_result_valid,
            &all_result_ok, &result_gate_binding) ||
        !all_result_ok || result_gate_binding == Digest{})
        return unavailable;

    Digest local_share_commitment{};
    if (rank == target)
        local_share_commitment = hash_field_vector(recovered);
    const bool share_commitment_valid =
        rank != target || local_share_commitment != Digest{};
    auto share_gate_context = derive_context(base, SHARE_GATE_KIND);
    bool all_share_commitments_valid = false;
    Digest share_gate_binding{};
    if (!config_.exchange->AllTrue(
            share_gate_context, share_commitment_valid,
            &all_share_commitments_valid, &share_gate_binding) ||
        !all_share_commitments_valid || share_gate_binding == Digest{})
        return unavailable;

    std::vector<u64> summary_words;
    if (rank == target) {
        summary_words = {SUMMARY_MAGIC, static_cast<u64>(target)};
        append_digest(request.request_binding, &summary_words);
        append_digest(local_share_commitment, &summary_words);
        append_digest(next_head, &summary_words);
        append_digest(config_.independently_pinned_registry_binding,
                      &summary_words);
    } else {
        summary_words.assign(18, 0);
    }
    auto summary_context = derive_context(base, SUMMARY_KIND);
    std::vector<u64> all_summaries;
    Digest summary_binding{};
    if (!config_.exchange->AllGatherWords(
            summary_context, summary_words, &all_summaries,
            &summary_binding) ||
        summary_binding == Digest{} ||
        all_summaries.size() !=
            static_cast<size_t>(world_size) * summary_words.size())
        return unavailable;

    Digest share_commitment{};
    Digest replay_head{};
    Digest registry_binding{};
    for (int peer = 0; peer < world_size; ++peer) {
        const size_t offset =
            static_cast<size_t>(peer) * summary_words.size();
        if (peer == target) {
            if (all_summaries[offset] != SUMMARY_MAGIC ||
                all_summaries[offset + 1] !=
                    static_cast<u64>(target) ||
                read_digest(all_summaries, offset + 2) !=
                    request.request_binding)
                return unavailable;
            share_commitment = read_digest(all_summaries, offset + 6);
            replay_head = read_digest(all_summaries, offset + 10);
            registry_binding = read_digest(all_summaries, offset + 14);
            if (share_commitment == Digest{} ||
                replay_head == Digest{} ||
                registry_binding !=
                    config_.independently_pinned_registry_binding)
                return unavailable;
        } else if (!all_zero(
                       all_summaries, offset, summary_words.size())) {
            return unavailable;
        }
    }

    const Digest recovered_commitment = compute_recovered_audit_commitment(
        request.request_binding, share_commitment, registry_binding);
    if (recovered_commitment == Digest{}) return unavailable;

    std::vector<u64> agreement_words = {
        AGREEMENT_MAGIC, static_cast<u64>(target)};
    append_digest(request.request_binding, &agreement_words);
    append_digest(recovered_commitment, &agreement_words);
    append_digest(summary_binding, &agreement_words);
    append_digest(replay_head, &agreement_words);
    append_digest(registry_binding, &agreement_words);
    append_digest(config_.independently_pinned_predecessor_root,
                  &agreement_words);
    append_digest(config_.independently_pinned_checkpoint_root,
                  &agreement_words);
    auto agreement_context = derive_context(base, AGREEMENT_KIND);
    std::vector<u64> all_agreements;
    Digest agreement_binding{};
    if (!config_.exchange->AllGatherWords(
            agreement_context, agreement_words, &all_agreements,
            &agreement_binding) ||
        agreement_binding == Digest{} ||
        all_agreements.size() !=
            static_cast<size_t>(world_size) * agreement_words.size())
        return unavailable;
    for (int peer = 0; peer < world_size; ++peer) {
        const size_t offset =
            static_cast<size_t>(peer) * agreement_words.size();
        if (!std::equal(
                agreement_words.begin(), agreement_words.end(),
                all_agreements.begin() +
                    static_cast<std::ptrdiff_t>(offset)))
            return unavailable;
    }

    auto& authenticator = Ed25519TransferAuthenticator::instance();
    const Digest authentication_registry_binding =
        authenticator.RegistryCommitment();
    const std::vector<u64> receipt_message = recovery_receipt_message(
        request, static_cast<uint32_t>(target), recovered_commitment,
        summary_binding, agreement_binding, replay_head, registry_binding,
        config_.independently_pinned_predecessor_root,
        config_.independently_pinned_checkpoint_root);
    std::array<uint8_t, 64> target_signature{};
    const bool signature_created = rank != target ||
        (authenticator.ready() && authenticator.rank() == target &&
         authenticator.world_size() == world_size &&
         authentication_registry_binding != Digest{} &&
         authenticator.SignWords(
             AUTH_RECEIPT_DOMAIN, receipt_message, &target_signature));
    auto signature_gate_context = derive_context(base, SIGNATURE_GATE_KIND);
    bool all_signatures_created = false;
    Digest signature_gate_binding{};
    if (!config_.exchange->AllTrue(
            signature_gate_context, signature_created,
            &all_signatures_created, &signature_gate_binding) ||
        !all_signatures_created || signature_gate_binding == Digest{})
        return unavailable;

    std::vector<u64> signature_words(22, 0);
    if (rank == target) {
        signature_words[0] = SIGNATURE_MAGIC;
        signature_words[1] = static_cast<u64>(target);
        std::vector<u64> encoded_registry;
        append_digest(authentication_registry_binding, &encoded_registry);
        std::copy(encoded_registry.begin(), encoded_registry.end(),
                  signature_words.begin() + 2);
        for (size_t i = 0; i < target_signature.size(); i += 8) {
            u64 word = 0;
            std::memcpy(&word, target_signature.data() + i, 8);
            signature_words[6 + i / 8] = word;
        }
    }
    auto signature_context = derive_context(base, SIGNATURE_KIND);
    std::vector<u64> all_signatures;
    Digest signature_transport_binding{};
    if (!config_.exchange->AllGatherWords(
            signature_context, signature_words, &all_signatures,
            &signature_transport_binding) ||
        signature_transport_binding == Digest{} ||
        all_signatures.size() !=
            static_cast<size_t>(world_size) * signature_words.size())
        return unavailable;

    Digest signed_key_registry_binding{};
    std::array<uint8_t, 64> portable_signature{};
    for (int peer = 0; peer < world_size; ++peer) {
        const size_t offset =
            static_cast<size_t>(peer) * signature_words.size();
        if (peer == target) {
            if (all_signatures[offset] != SIGNATURE_MAGIC ||
                all_signatures[offset + 1] !=
                    static_cast<u64>(target))
                return unavailable;
            signed_key_registry_binding =
                read_digest(all_signatures, offset + 2);
            portable_signature = read_signature(
                all_signatures, offset + 6);
            if (!all_zero(all_signatures, offset + 14, 8) ||
                signed_key_registry_binding == Digest{} ||
                std::all_of(portable_signature.begin(),
                            portable_signature.end(),
                            [](uint8_t byte) { return byte == 0; }))
                return unavailable;
        } else if (!all_zero(
                       all_signatures, offset, signature_words.size())) {
            return unavailable;
        }
    }

    const bool portable_signature_valid =
        authenticator.ready() &&
        signed_key_registry_binding == authenticator.RegistryCommitment() &&
        authenticator.VerifyWords(
            AUTH_RECEIPT_DOMAIN, receipt_message,
            portable_signature, static_cast<uint32_t>(target));
    auto signature_verify_context =
        derive_context(base, SIGNATURE_VERIFY_GATE_KIND);
    bool all_signatures_verified = false;
    Digest signature_verify_binding{};
    if (!config_.exchange->AllTrue(
            signature_verify_context, portable_signature_valid,
            &all_signatures_verified, &signature_verify_binding) ||
        !all_signatures_verified || signature_verify_binding == Digest{})
        return unavailable;

    AuthenticatedRecoveryArtifact artifact;
    artifact.available = true;
    artifact.cryptographically_authenticated = true;
    artifact.accused = request_operation(request);
    artifact.checkpoint = request.checkpoint;
    artifact.relation = request.relation;
    artifact.kernel = request.kernel;
    artifact.request_binding = request.request_binding;
    artifact.operation_statement_binding =
        request.operation_statement_binding;
    artifact.dispute_binding = request.dispute_binding;
    artifact.predecessor_root =
        config_.independently_pinned_predecessor_root;
    artifact.checkpoint_root = request.checkpoint_root;
    artifact.recovered_audit_commitment = recovered_commitment;
    artifact.recovery_transcript_binding = summary_binding;
    artifact.recovery_share_commitment = share_commitment;
    artifact.recovery_registry_binding = registry_binding;
    artifact.recovery_agreement_binding = agreement_binding;
    artifact.recovery_replay_head = replay_head;
    artifact.recovery_auth_signer = static_cast<uint32_t>(target);
    artifact.recovery_auth_registry_binding = signed_key_registry_binding;
    artifact.recovery_auth_signature = portable_signature;
    artifact.authentication_proof_commitment =
        authentication_receipt_commitment(
            receipt_message, static_cast<uint32_t>(target),
            signed_key_registry_binding, portable_signature);
    if (artifact.authentication_proof_commitment == Digest{} ||
        !validate_recovery_artifact(request, artifact))
        return unavailable;

    // Optional one-shot bridge. PROVE_ONCE implies export, then the target
    // runs the SP1 prover on the exact witness just accepted by this recovery
    // execution. All ranks import the same portable proof envelope and agree
    // on its statement/artifact commitments before the artifact is returned.
    const bool prove_sp1_once =
        env_is_one("PVIA_SP1_VSS_RECOVERY_PROVE_ONCE");
    if (env_is_one("PVIA_SP1_VSS_RECOVERY_EXPORT_ONCE") || prove_sp1_once) {
        const char* output_dir_env =
            std::getenv("PVIA_SP1_VSS_RECOVERY_EXPORT_DIR");
        const std::string output_dir =
            output_dir_env && *output_dir_env ? output_dir_env : "";
        bool local_export_ok = rank != target;
        Sp1VssRecoveryInputInfo input_info;
        if (rank == target && !output_dir.empty()) {
            Sp1VssRecoveryProofProvider provider;
            local_export_ok = provider.ExportRelationInput(
                recovery_proof_witness, request, artifact,
                output_dir, &input_info);
        }
        auto proof_export_context =
            derive_context(base, PROOF_EXPORT_GATE_KIND);
        bool all_exports_ok = false;
        Digest proof_export_binding{};
        if (!config_.exchange->AllTrue(
                proof_export_context, local_export_ok,
                &all_exports_ok, &proof_export_binding) ||
            !all_exports_ok || proof_export_binding == Digest{})
            return unavailable;
        if (rank == target) {
            std::cerr << "[PVIA][sp1-vss-recovery-input-export] "
                      << "collective_gate=PASS"
                      << " statement_binding="
                      << input_info.statement_binding.hex() << "\n";
        }

        if (prove_sp1_once) {
            const std::string proof_path = output_dir +
                "/vss_recovery_" + std::to_string(request.label.sid) + "_" +
                std::to_string(request.checkpoint) + ".groth16.bin";
            std::vector<u64> local_statement(85, 0);
            std::vector<u64> local_witness;
            bool local_proof_ok = rank != target;
            if (rank == target) {
                Sp1VssRecoveryProofProvider provider;
                local_proof_ok = run_sp1_recovery_prover(
                    input_info.path, proof_path) &&
                    provider.BuildRelationInput(
                        recovery_proof_witness, request, artifact,
                        &local_statement, &local_witness) &&
                    local_statement.size() == 85;
            }
            auto proof_generate_context =
                derive_context(base, PROOF_GENERATE_GATE_KIND);
            bool all_proofs_generated = false;
            Digest proof_generate_binding{};
            if (!config_.exchange->AllTrue(
                    proof_generate_context, local_proof_ok,
                    &all_proofs_generated, &proof_generate_binding) ||
                !all_proofs_generated || proof_generate_binding == Digest{})
                return unavailable;

            auto statement_context =
                derive_context(base, PROOF_STATEMENT_KIND);
            std::vector<u64> gathered_statements;
            Digest statement_transport{};
            if (!config_.exchange->AllGatherWords(
                    statement_context, local_statement,
                    &gathered_statements, &statement_transport) ||
                statement_transport == Digest{} ||
                gathered_statements.size() !=
                    static_cast<size_t>(world_size) * local_statement.size())
                return unavailable;
            const size_t statement_words = local_statement.size();
            const size_t target_offset =
                static_cast<size_t>(target) * statement_words;
            std::vector<u64> expected_statement(
                gathered_statements.begin() +
                    static_cast<std::ptrdiff_t>(target_offset),
                gathered_statements.begin() +
                    static_cast<std::ptrdiff_t>(target_offset + statement_words));
            bool statement_agreement =
                expected_statement.size() == 85 &&
                expected_statement[0] == 0x5056524350525331ULL &&
                expected_statement[1] == 1 &&
                expected_statement[2] == static_cast<u64>(world_size) &&
                expected_statement[4] == static_cast<u64>(target) &&
                expected_statement[6] == request.label.sid &&
                expected_statement[7] == request.checkpoint &&
                expected_statement[10] == static_cast<u64>(request.relation) &&
                expected_statement[11] == static_cast<u64>(request.kernel) &&
                expected_statement[12] == static_cast<u64>(target);
            for (int peer = 0; peer < world_size; ++peer) {
                if (peer == target) continue;
                const size_t offset = static_cast<size_t>(peer) * statement_words;
                if (!std::all_of(
                        gathered_statements.begin() +
                            static_cast<std::ptrdiff_t>(offset),
                        gathered_statements.begin() +
                            static_cast<std::ptrdiff_t>(offset + statement_words),
                        [](u64 word) { return word == 0; }))
                    statement_agreement = false;
            }
            if (!statement_agreement) return unavailable;

            Sp1VssRecoveryProofProvider proof_provider;
            Sp1VssRecoveryProofReceipt proof_receipt;
            const bool verify_sp1_on_import =
                env_is_one("PVIA_SP1_VSS_RECOVERY_VERIFY_ON_IMPORT");
            const bool proof_loaded = !proof_path.empty() &&
                (verify_sp1_on_import
                    ? proof_provider.LoadAndVerifyArtifact(
                        proof_path, expected_statement, &proof_receipt)
                    : proof_provider.LoadArtifact(
                        proof_path, expected_statement, &proof_receipt));
            const bool local_import_ok =
                proof_loaded && proof_receipt.available &&
                proof_receipt.proof_verified == verify_sp1_on_import &&
                proof_receipt.proof_system_id == 68103 &&
                proof_receipt.statement_words == expected_statement &&
                !proof_receipt.artifact_bytes.empty();

            // Include the verification mode in the collective metadata. This
            // prevents ranks with inconsistent environment configuration from
            // silently mixing structural-only and Groth16-verified imports.
            std::vector<u64> proof_metadata(11, 0);
            proof_metadata[2] = verify_sp1_on_import ? 1ULL : 0ULL;
            if (local_import_ok) {
                proof_metadata[0] = proof_receipt.proof_system_id;
                proof_metadata[1] =
                    static_cast<u64>(proof_receipt.artifact_bytes.size());
                append_digest(proof_receipt.statement_binding, &proof_metadata);
                append_digest(proof_receipt.artifact_commitment, &proof_metadata);
            }
            auto proof_artifact_context =
                derive_context(base, PROOF_ARTIFACT_KIND);
            std::vector<u64> gathered_proof_metadata;
            Digest proof_artifact_transport{};
            if (!config_.exchange->AllGatherWords(
                    proof_artifact_context, proof_metadata,
                    &gathered_proof_metadata, &proof_artifact_transport) ||
                proof_artifact_transport == Digest{} ||
                gathered_proof_metadata.size() !=
                    static_cast<size_t>(world_size) * proof_metadata.size())
                return unavailable;
            bool proof_metadata_agreement = local_import_ok;
            for (int peer = 0; peer < world_size; ++peer) {
                const size_t offset =
                    static_cast<size_t>(peer) * proof_metadata.size();
                if (!std::equal(
                        proof_metadata.begin(), proof_metadata.end(),
                        gathered_proof_metadata.begin() +
                            static_cast<std::ptrdiff_t>(offset)))
                    proof_metadata_agreement = false;
            }
            auto proof_import_context =
                derive_context(base, PROOF_IMPORT_GATE_KIND);
            bool all_proofs_imported = false;
            Digest proof_import_binding{};
            if (!config_.exchange->AllTrue(
                    proof_import_context, proof_metadata_agreement,
                    &all_proofs_imported, &proof_import_binding) ||
                !all_proofs_imported || proof_import_binding == Digest{})
                return unavailable;

            artifact.recovery_proof_system_id = proof_receipt.proof_system_id;
            artifact.recovery_proof_statement_binding =
                proof_receipt.statement_binding;
            artifact.recovery_proof_artifact_commitment =
                proof_receipt.artifact_commitment;
            artifact.recovery_proof_statement_words = expected_statement;
            artifact.recovery_proof_artifact_bytes =
                std::move(proof_receipt.artifact_bytes);
            if (rank == target) {
                std::cerr << "[PVIA][sp1-vss-recovery-proof-import] "
                          << "collective_gate=PASS"
                          << " proof_system_id="
                          << artifact.recovery_proof_system_id
                          << " statement_binding="
                          << artifact.recovery_proof_statement_binding.hex()
                          << " artifact_commitment="
                          << artifact.recovery_proof_artifact_commitment.hex()
                          << " artifact_bytes="
                          << artifact.recovery_proof_artifact_bytes.size()
                          << " proof_verified_by_importer="
                          << (proof_receipt.proof_verified ? 1 : 0) << "\n";
            }
        }
    }
    return artifact;
}

bool ReferenceVssAuthenticatedAuditRecoveryBackend::Verify(
    const AuthenticatedRecoveryRequest& request,
    const AuthenticatedRecoveryArtifact& artifact) const {
    if (!validate_recovery_artifact(request, artifact) ||
        request_operation(request) != config_.expected_operation ||
        request.operation_statement_binding !=
            config_.independently_pinned_operation_statement_binding ||
        request.checkpoint_root !=
            config_.independently_pinned_checkpoint_root ||
        artifact.accused != config_.expected_operation ||
        artifact.predecessor_root !=
            config_.independently_pinned_predecessor_root ||
        artifact.checkpoint_root !=
            config_.independently_pinned_checkpoint_root ||
        artifact.recovery_registry_binding !=
            config_.independently_pinned_registry_binding ||
        artifact.recovery_auth_signer !=
            config_.expected_operation.owner)
        return false;

    auto& authenticator = Ed25519TransferAuthenticator::instance();
    if (!authenticator.ready() ||
        artifact.recovery_auth_registry_binding !=
            authenticator.RegistryCommitment())
        return false;
    return verify_authenticated_recovery_receipt(
        request, artifact, authenticator.PublicKeys(),
        authenticator.RegistryCommitment());
}

} // namespace pvia
