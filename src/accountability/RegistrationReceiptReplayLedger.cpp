#include "RegistrationReceiptReplayLedger.hpp"
#include "LiveNativeSourceRequest.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace pvia {
namespace {
std::string digest_hex(const Digest& digest) {
    constexpr char abc[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (uint8_t b : digest.bytes) {
        result.push_back(abc[b >> 4]);
        result.push_back(abc[b & 15]);
    }
    return result;
}
bool write_all(int fd, const uint8_t* bytes, size_t length) {
    while (length != 0) {
        ssize_t n = ::write(fd, bytes, length);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        bytes += n;
        length -= static_cast<size_t>(n);
    }
    return true;
}
} // namespace

std::string RegistrationReceiptReplayLedger::MarkerName(
    const RegistrationConsistencyStatement& statement, uint32_t signer) {
    if (!validate_registration_consistency_statement(statement))
        return {};
    // Deliberately exclude output/VSS contents: the entire execution
    // identity is single-use even if an attacker changes claim bytes.
    const Digest scope = hash_words({
        0x50565245504c4159ULL, // PVREPLAY
        statement.sid, statement.checkpoint,
        statement.ref.owner, statement.ref.object_id,
        static_cast<u64>(signer)});
    if (scope == Digest{}) return {};
    return "receipt-" + digest_hex(scope) + ".used";
}

bool consume_private_marker(const std::string& directory,
                            const std::string& marker,
                            const Digest& binding) {
    if (marker.empty() || directory.empty() || binding == Digest{})
        return false;
    int dirfd = ::open(directory.c_str(),
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dirfd < 0) return false;
    struct stat st {};
    const bool secure = ::fstat(dirfd, &st) == 0 &&
        S_ISDIR(st.st_mode) && st.st_uid == ::geteuid() &&
        (st.st_mode & 0077) == 0;
    if (!secure) { ::close(dirfd); return false; }
    const int fd = ::openat(dirfd, marker.c_str(),
                            O_WRONLY | O_CREAT | O_EXCL |
                            O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) { ::close(dirfd); return false; }
    const bool ok = write_all(fd, binding.bytes.data(),
                              binding.bytes.size()) &&
                    ::fsync(fd) == 0;
    const bool closed = ::close(fd) == 0;
    const bool directory_synced = ::fsync(dirfd) == 0;
    ::close(dirfd);
    // Do not unlink a possibly incomplete marker: failures must remain
    // fail-closed. An administrator must explicitly reconcile/recover.
    return ok && closed && directory_synced;
}

bool RegistrationReceiptReplayLedger::ConsumeOnce(
    const RegistrationConsistencyStatement& statement,
    uint32_t signer) const {
    return consume_private_marker(directory_, MarkerName(statement,signer),
                                  statement.statement_binding);
}

std::string RegistrationReceiptReplayLedger::NativeSourceMarkerName(
    const ResidualNativeSourcePinReceipt& receipt) {
    if(!receipt.issuer_id || !receipt.sequence ||
       !receipt.sid || !receipt.checkpoint ||
       receipt.scope_binding==Digest{} ||
       receipt.local_residual_root==Digest{} ||
       receipt.native_consumed_record_binding==Digest{} ||
       receipt.registration_pre_vss_claim_binding==Digest{})
        return {};
    const Digest identity=hash_words({
        0x50564e4154495645ULL, // PVNATIVE
        receipt.issuer_id,receipt.sequence});
    if(identity==Digest{})return {};
    return "native-issuer-"+digest_hex(identity)+".used";
}

bool RegistrationReceiptReplayLedger::ConsumeNativeSourcePinOnce(
    const ResidualNativeSourcePinReceipt& receipt) const {
    const auto marker=NativeSourceMarkerName(receipt);
    if(marker.empty())return false;
    const Digest record_binding=hash_words({
        0x50564e4953535243ULL, // PVNISSRC
        receipt.issuer_id,receipt.sequence,receipt.sid,
        receipt.checkpoint,receipt.owner,
        // Persist a local commitment to the accepted claim, without
        // publishing the owner-specific residual root.
        static_cast<u64>(receipt.signature[0]),
        static_cast<u64>(receipt.signature[63])});
    return consume_private_marker(directory_,marker,record_binding);
}

std::string RegistrationReceiptReplayLedger::NativeBatchPinMarkerName(
    const LiveNativeSourceBatchPinReceipt& receipt) {
    if (live_native_source_batch_pin_signing_message(receipt).empty() ||
        std::all_of(receipt.signature.begin(), receipt.signature.end(),
            [](uint8_t byte) { return byte == 0; }))
        return {};
    const Digest identity = hash_words({
        0x50564e4241545250ULL, // PVNBATRP
        receipt.issuer_id, receipt.sequence});
    if (identity == Digest{}) return {};
    return "native-batch-pin-" + digest_hex(identity) + ".used";
}

bool RegistrationReceiptReplayLedger::ConsumeNativeSourceBatchPinOnce(
    const LiveNativeSourceBatchPinReceipt& receipt) const {
    const std::string marker = NativeBatchPinMarkerName(receipt);
    if (marker.empty()) return false;
    std::vector<u64> words = {
        0x50564e425052504cULL, // PVNBPRPL
        receipt.issuer_id, receipt.sequence, receipt.session_id,
        receipt.checkpoint, receipt.owner, receipt.operation_count};
    const auto append = [&words](const Digest& digest) {
        for (size_t block = 0; block < 4; ++block) {
            u64 value = 0;
            std::memcpy(&value, digest.bytes.data() + block * 8, 8);
            words.push_back(value);
        }
    };
    append(receipt.scope_binding);
    append(receipt.local_residual_root);
    append(receipt.operation_binding_root);
    append(receipt.batch_binding);
    for (size_t block = 0; block < receipt.signature.size() / 8; ++block) {
        u64 value = 0;
        std::memcpy(&value, receipt.signature.data() + block * 8, 8);
        words.push_back(value);
    }
    const Digest binding = hash_words(words);
    return binding != Digest{} &&
        consume_private_marker(directory_, marker, binding);
}

bool run_registration_replay_ledger_persistence_probe(
    const std::string& owner_only_dir, bool changed_public_claim) {
    RegistrationConsistencyStatement statement;
    statement.sid = 0x50565245504c4141ULL;
    statement.checkpoint = 0x50565245504c4142ULL;
    statement.ref = OperationRef{0, 0x50565245504c4143ULL};
    statement.kernel = AuditRelationKernel::FOLD_RS;
    statement.state_element_count = 8;
    statement.output_element_count = 4;
    statement.public_state_digest = hash_words({101,102});
    statement.public_actual_digest = hash_words({201,202});
    statement.public_challenge_binding = hash_words({301,302});
    statement.native_context.native_state_id = 0x50565245504c4144ULL;
    statement.native_context.authentication_scheme_id = 0x4544323535313921ULL;
    statement.native_context.authentication_binding = hash_words({401,402});
    statement.native_context.predecessor_root = hash_words({501,502});
    statement.native_context.checkpoint_root = hash_words({601,602});
    statement.operation_statement_binding = hash_words({701,702});
    statement.sharing_transcript_binding = hash_words({801,802});
    if (changed_public_claim)
        statement.public_actual_digest = hash_words({203,204});
    statement.statement_binding =
        compute_registration_consistency_statement_binding(statement);
    return RegistrationReceiptReplayLedger(owner_only_dir)
        .ConsumeOnce(statement, 0);
}

} // namespace pvia
