#include "LiveNativeSourceRequest.hpp"
#include <accountability/CollectiveResidualEngine.hpp>

#include <algorithm>
#include <fstream>
#include <limits>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <fcntl.h>
#include <cerrno>

namespace pvia {
namespace {
constexpr u64 LIVE_NATIVE_BATCH_BINDING_DOMAIN = 0x50564e4241543031ULL; // PVNBAT01
constexpr u64 LIVE_NATIVE_BATCH_BINDING_VERSION = 1;
constexpr size_t LIVE_NATIVE_BATCH_PIN_FILE_BYTES = 248;

bool write_test_bytes_exclusive(const std::string& path,
                                const std::vector<uint8_t>& bytes,
                                mode_t mode = 0600);

bool same_ref(const OperationRef& a, const OperationRef& b) {
    return a.owner == b.owner && a.object_id == b.object_id;
}

bool contains_ref(const std::vector<OperationRef>& refs,
                  const OperationRef& wanted) {
    return std::count_if(refs.begin(), refs.end(), [&](const OperationRef& ref) {
        return same_ref(ref, wanted);
    }) == 1;
}

bool contains_obligation(const ObligationSet& scope, Obligation value) {
    return scope.obligations.empty() ||
        std::find(scope.obligations.begin(), scope.obligations.end(), value) !=
            scope.obligations.end();
}

void append_digest_words(std::vector<u64>* words, const Digest& digest) {
    for (size_t block = 0; block < 4; ++block) {
        u64 value = 0;
        for (size_t byte = 0; byte < 8; ++byte)
            value |= static_cast<u64>(digest.bytes[block * 8 + byte])
                     << (8 * byte);
        words->push_back(value);
    }
}

void append_handle_binding(std::vector<u64>* words,
                           const PrivateResidualHandle& handle,
                           const LiveNativeSourceOperationBinding& binding) {
    words->push_back(handle.ref.owner);
    words->push_back(handle.ref.object_id);
    words->push_back(static_cast<u64>(handle.relation));
    words->push_back(static_cast<u64>(handle.kernel));
    words->push_back(handle.checkpoint);
    words->push_back(handle.label.sid);
    words->push_back(static_cast<u64>(handle.label.phase));
    words->push_back(handle.label.round);
    words->push_back(static_cast<u64>(handle.label.obligation));
    words->push_back(handle.label.object_id);
    append_digest_words(words, handle.commitment);
    append_digest_words(words, binding.native_consumed_record_binding);
    append_digest_words(words, binding.registration_pre_vss_claim_binding);
}

bool valid_operation_binding(const LiveNativeSourceOperationBinding& binding,
                             uint32_t owner) {
    return binding.ref.owner == owner && binding.ref.object_id != 0 &&
           binding.native_consumed_record_binding != Digest{} &&
           binding.registration_pre_vss_claim_binding != Digest{};
}
} // namespace

bool compute_live_native_source_pin_batch_binding(
    const ObligationSet& scope, uint32_t local_owner,
    const LocalResidualBatchView& local_view,
    const std::vector<LiveNativeSourceOperationBinding>& operation_bindings,
    LiveNativeSourcePinBatchBinding* output) {
    if (!output || local_owner >= 64 || !scope.session_id || !scope.checkpoint ||
        scope.checkpoint_root == Digest{} || scope.operations.empty() ||
        local_view.local_owner != local_owner ||
        !local_view.complete_for_owner || !local_view.all_authenticated)
        return false;

    const Digest scope_binding = compute_collective_scope_binding(scope);
    if (scope_binding == Digest{} ||
        compute_collective_scope_binding(local_view.scope) != scope_binding)
        return false;

    // Reject malformed/duplicate refs before set-like membership checks.
    for (size_t i = 0; i < scope.operations.size(); ++i) {
        const auto& ref = scope.operations[i];
        if (ref.owner >= 64 || !ref.object_id) return false;
        for (size_t j = i + 1; j < scope.operations.size(); ++j)
            if (same_ref(ref, scope.operations[j])) return false;
    }

    if (scope.private_operations.empty()) return false;
    for (size_t i = 0; i < scope.private_operations.size(); ++i) {
        const auto& ref = scope.private_operations[i];
        if (!contains_ref(scope.operations, ref)) return false;
        for (size_t j = i + 1; j < scope.private_operations.size(); ++j)
            if (same_ref(ref, scope.private_operations[j])) return false;
    }
    for (size_t i = 0; i < scope.transfer_operations.size(); ++i) {
        const auto& ref = scope.transfer_operations[i];
        if (!contains_ref(scope.operations, ref) ||
            contains_ref(scope.private_operations, ref))
            return false;
        for (size_t j = i + 1; j < scope.transfer_operations.size(); ++j)
            if (same_ref(ref, scope.transfer_operations[j])) return false;
    }

    size_t expected_local = 0;
    for (const auto& ref : scope.operations) {
        if (ref.owner != local_owner) continue;
        if (!contains_ref(scope.private_operations, ref) ||
            contains_ref(scope.transfer_operations, ref))
            return false;
        ++expected_local;
    }
    if (expected_local == 0 || local_view.handles.size() != expected_local ||
        operation_bindings.size() != expected_local)
        return false;

    const Digest recomputed_local_root =
        compute_private_residual_local_handle_root(local_view.handles);
    if (recomputed_local_root == Digest{} ||
        local_view.commitment_root != recomputed_local_root)
        return false;

    std::vector<LiveNativeSourceOperationBinding> sorted_bindings =
        operation_bindings;
    std::sort(sorted_bindings.begin(), sorted_bindings.end(),
        [](const auto& a, const auto& b) {
            if (a.ref.owner != b.ref.owner) return a.ref.owner < b.ref.owner;
            return a.ref.object_id < b.ref.object_id;
        });
    for (size_t i = 0; i < sorted_bindings.size(); ++i) {
        const auto& binding = sorted_bindings[i];
        if (!valid_operation_binding(binding, local_owner) ||
            !contains_ref(scope.operations, binding.ref) ||
            (i && same_ref(sorted_bindings[i - 1].ref, binding.ref)))
            return false;
    }

    std::vector<u64> operation_words{
        LIVE_NATIVE_BATCH_BINDING_DOMAIN,
        LIVE_NATIVE_BATCH_BINDING_VERSION,
        local_owner,
        static_cast<u64>(sorted_bindings.size())};
    append_digest_words(&operation_words, scope_binding);
    for (size_t i = 0; i < local_view.handles.size(); ++i) {
        const auto& handle = local_view.handles[i];
        const auto& binding = sorted_bindings[i];
        if (!handle.available || !handle.authenticated ||
            handle.ref.owner != local_owner ||
            handle.checkpoint != scope.checkpoint ||
            handle.label.sid != scope.session_id ||
            handle.label.phase != scope.phase ||
            (scope.exact_round && handle.label.round != scope.round) ||
            handle.label.owner != local_owner ||
            handle.label.object_id != handle.ref.object_id ||
            !contains_obligation(scope, handle.label.obligation) ||
            !same_ref(handle.ref, binding.ref) ||
            handle.commitment == Digest{} ||
            !contains_ref(scope.operations, handle.ref))
            return false;
        append_handle_binding(&operation_words, handle, binding);
    }

    LiveNativeSourcePinBatchBinding result{};
    result.session_id = scope.session_id;
    result.checkpoint = scope.checkpoint;
    result.local_owner = local_owner;
    result.operation_count = expected_local;
    result.scope_binding = scope_binding;
    result.local_residual_root = recomputed_local_root;
    result.operation_binding_root = hash_words(operation_words);
    if (result.operation_binding_root == Digest{}) return false;

    std::vector<u64> batch_words{
        LIVE_NATIVE_BATCH_BINDING_DOMAIN,
        LIVE_NATIVE_BATCH_BINDING_VERSION,
        result.session_id,
        result.checkpoint,
        result.local_owner,
        static_cast<u64>(result.operation_count)};
    append_digest_words(&batch_words, scope.checkpoint_root);
    append_digest_words(&batch_words, result.scope_binding);
    append_digest_words(&batch_words, result.local_residual_root);
    append_digest_words(&batch_words, result.operation_binding_root);
    result.batch_binding = hash_words(batch_words);
    if (result.batch_binding == Digest{}) return false;
    *output = result;
    return true;
}

bool run_live_native_source_batch_binding_selftest() {
    constexpr u64 TEST_DOMAIN = 0x50564e4254535431ULL; // PVNBTST1
    ObligationSet scope{};
    scope.session_id = 77;
    scope.phase = Phase::FOLD;
    scope.round = 3;
    scope.generation = 2;
    scope.exact_round = true;
    scope.checkpoint = 19;
    scope.checkpoint_root = hash_words({TEST_DOMAIN, 1, scope.session_id,
                                        scope.checkpoint});
    scope.operations = {{0, 100}, {0, 101}, {1, 200}};
    scope.private_operations = scope.operations;
    scope.obligations = {Obligation::FOLD};

    LocalResidualBatchView view{};
    view.scope = scope;
    view.local_owner = 0;
    for (uint64_t object_id : {100ULL, 101ULL}) {
        PrivateResidualHandle handle{};
        handle.ref = {0, object_id};
        handle.label.sid = scope.session_id;
        handle.label.phase = scope.phase;
        handle.label.round = scope.round;
        handle.label.owner = 0;
        handle.label.obligation = Obligation::FOLD;
        handle.label.object_id = object_id;
        handle.relation = RelationKind::FOLDING;
        handle.kernel = AuditRelationKernel::FOLD_RS;
        handle.checkpoint = scope.checkpoint;
        handle.commitment = hash_words({TEST_DOMAIN, 2, object_id});
        handle.available = true;
        handle.authenticated = true;
        view.handles.push_back(handle);
    }
    view.complete_for_owner = true;
    view.all_authenticated = true;
    view.commitment_root = compute_private_residual_local_handle_root(view.handles);
    if (view.commitment_root == Digest{}) return false;

    std::vector<LiveNativeSourceOperationBinding> bindings;
    for (uint64_t object_id : {100ULL, 101ULL}) {
        LiveNativeSourceOperationBinding binding{};
        binding.ref = {0, object_id};
        binding.native_consumed_record_binding =
            hash_words({TEST_DOMAIN, 3, object_id});
        binding.registration_pre_vss_claim_binding =
            hash_words({TEST_DOMAIN, 4, object_id});
        bindings.push_back(binding);
    }

    LiveNativeSourcePinBatchBinding baseline{};
    if (!compute_live_native_source_pin_batch_binding(
            scope, 0, view, bindings, &baseline) ||
        baseline.operation_count != 2 || baseline.batch_binding == Digest{})
        return false;

    auto permuted = bindings;
    std::reverse(permuted.begin(), permuted.end());
    LiveNativeSourcePinBatchBinding permutation_result{};
    if (!compute_live_native_source_pin_batch_binding(
            scope, 0, view, permuted, &permutation_result) ||
        permutation_result.batch_binding != baseline.batch_binding ||
        permutation_result.operation_binding_root != baseline.operation_binding_root)
        return false;

    auto missing = bindings;
    missing.pop_back();
    LiveNativeSourcePinBatchBinding rejected{};
    if (compute_live_native_source_pin_batch_binding(
            scope, 0, view, missing, &rejected)) return false;

    auto duplicate = bindings;
    duplicate.push_back(bindings.front());
    if (compute_live_native_source_pin_batch_binding(
            scope, 0, view, duplicate, &rejected)) return false;

    auto foreign = bindings;
    foreign.front().ref.owner = 1;
    if (compute_live_native_source_pin_batch_binding(
            scope, 0, view, foreign, &rejected)) return false;

    auto tampered_view = view;
    tampered_view.commitment_root = hash_words({TEST_DOMAIN, 5});
    if (compute_live_native_source_pin_batch_binding(
            scope, 0, tampered_view, bindings, &rejected)) return false;

    auto changed_source = bindings;
    changed_source.front().native_consumed_record_binding =
        hash_words({TEST_DOMAIN, 6, bindings.front().ref.object_id});
    LiveNativeSourcePinBatchBinding changed_result{};
    if (!compute_live_native_source_pin_batch_binding(
            scope, 0, view, changed_source, &changed_result) ||
        changed_result.batch_binding == baseline.batch_binding ||
        changed_result.operation_binding_root == baseline.operation_binding_root)
        return false;

    auto duplicate_scope = scope;
    duplicate_scope.operations.push_back(scope.operations.front());
    duplicate_scope.private_operations = duplicate_scope.operations;
    auto duplicate_scope_view = view;
    duplicate_scope_view.scope = duplicate_scope;
    if (compute_live_native_source_pin_batch_binding(
            duplicate_scope, 0, duplicate_scope_view, bindings, &rejected))
        return false;


    // Exercise the PVNPIN02 receipt schema with an ephemeral test key. This
    // checks serialization and verification only, not a production issuer.
    EVP_PKEY_CTX* key_context = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY* issuer_key = nullptr;
    const bool key_ready = key_context &&
        EVP_PKEY_keygen_init(key_context) == 1 &&
        EVP_PKEY_keygen(key_context, &issuer_key) == 1;
    EVP_PKEY_CTX_free(key_context);
    if (!key_ready || !issuer_key) {
        EVP_PKEY_free(issuer_key);
        return false;
    }
    std::array<uint8_t, 32> issuer_public{};
    size_t public_size = issuer_public.size();
    const bool public_ready =
        EVP_PKEY_get_raw_public_key(issuer_key, issuer_public.data(),
                                    &public_size) == 1 &&
        public_size == issuer_public.size();

    LiveNativeSourceBatchPinReceipt receipt{};
    receipt.issuer_id = 0x505649410001ULL;
    receipt.sequence = 99;
    receipt.session_id = baseline.session_id;
    receipt.checkpoint = baseline.checkpoint;
    receipt.owner = baseline.local_owner;
    receipt.operation_count = baseline.operation_count;
    receipt.scope_binding = baseline.scope_binding;
    receipt.local_residual_root = baseline.local_residual_root;
    receipt.operation_binding_root = baseline.operation_binding_root;
    receipt.batch_binding = baseline.batch_binding;
    const auto message = live_native_source_batch_pin_signing_message(receipt);
    EVP_MD_CTX* sign_context = EVP_MD_CTX_new();
    size_t signature_size = receipt.signature.size();
    const bool signed_ok = public_ready && !message.empty() && sign_context &&
        EVP_DigestSignInit(sign_context, nullptr, nullptr, nullptr, issuer_key) == 1 &&
        EVP_DigestSign(sign_context, receipt.signature.data(), &signature_size,
                       message.data(), message.size()) == 1 &&
        signature_size == receipt.signature.size();
    EVP_MD_CTX_free(sign_context);
    EVP_PKEY_free(issuer_key);
    if (!signed_ok ||
        !verify_live_native_source_batch_pin_receipt(
            scope, 0, view, bindings, receipt, issuer_public,
            receipt.issuer_id, 99) ||
        verify_live_native_source_batch_pin_receipt(
            scope, 0, view, bindings, receipt, issuer_public,
            receipt.issuer_id, 100))
        return false;

    auto tampered_receipt = receipt;
    tampered_receipt.operation_binding_root = hash_words({TEST_DOMAIN, 7});
    if (verify_live_native_source_batch_pin_receipt(
            scope, 0, view, bindings, tampered_receipt, issuer_public,
            receipt.issuer_id, 99))
        return false;

    const std::string receipt_path =
        "/tmp/pvia-live-native-batch-pin-selftest-" +
        std::to_string(static_cast<long long>(::getpid())) + ".bin";
    ::unlink(receipt_path.c_str());
    if (!write_live_native_source_batch_pin_receipt_file(receipt_path, receipt) ||
        write_live_native_source_batch_pin_receipt_file(receipt_path, receipt)) {
        ::unlink(receipt_path.c_str());
        return false;
    }
    LiveNativeSourceBatchPinReceipt decoded{};
    const bool roundtrip =
        read_live_native_source_batch_pin_receipt_file(receipt_path, &decoded) &&
        decoded.issuer_id == receipt.issuer_id &&
        decoded.sequence == receipt.sequence &&
        decoded.session_id == receipt.session_id &&
        decoded.checkpoint == receipt.checkpoint &&
        decoded.owner == receipt.owner &&
        decoded.operation_count == receipt.operation_count &&
        decoded.scope_binding == receipt.scope_binding &&
        decoded.local_residual_root == receipt.local_residual_root &&
        decoded.operation_binding_root == receipt.operation_binding_root &&
        decoded.batch_binding == receipt.batch_binding &&
        decoded.signature == receipt.signature &&
        verify_live_native_source_batch_pin_receipt(
            scope, 0, view, bindings, decoded, issuer_public,
            receipt.issuer_id, 99);
    if (!roundtrip) {
        ::unlink(receipt_path.c_str());
        return false;
    }

    // File parser rejects truncation, trailing bytes, and group/world access.
    const std::string truncated_path = receipt_path + ".truncated";
    const std::string extended_path = receipt_path + ".extended";
    const std::string public_mode_path = receipt_path + ".public-mode";
    const bool malformed_files_created =
        write_test_bytes_exclusive(truncated_path,
                                   std::vector<uint8_t>{'P','V','N','P','I','N','0','2'}) &&
        write_test_bytes_exclusive(extended_path,
            std::vector<uint8_t>(LIVE_NATIVE_BATCH_PIN_FILE_BYTES + 1, 0));
    bool public_mode_created = false;
    const int source_fd = ::open(receipt_path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (source_fd >= 0) {
        std::vector<uint8_t> source_wire(LIVE_NATIVE_BATCH_PIN_FILE_BYTES);
        size_t offset = 0;
        bool read_ok = true;
        while (offset < source_wire.size()) {
            const ssize_t count = ::read(source_fd, source_wire.data() + offset,
                                         source_wire.size() - offset);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) { read_ok = false; break; }
            offset += static_cast<size_t>(count);
        }
        ::close(source_fd);
        if (read_ok &&
            write_test_bytes_exclusive(public_mode_path, source_wire, 0644))
            public_mode_created = true;
    }
    LiveNativeSourceBatchPinReceipt malformed_decoded{};
    const bool malformed_rejected = malformed_files_created &&
        !read_live_native_source_batch_pin_receipt_file(
            truncated_path, &malformed_decoded) &&
        !read_live_native_source_batch_pin_receipt_file(
            extended_path, &malformed_decoded) &&
        public_mode_created &&
        !read_live_native_source_batch_pin_receipt_file(
            public_mode_path, &malformed_decoded);
    ::unlink(truncated_path.c_str());
    ::unlink(extended_path.c_str());
    ::unlink(public_mode_path.c_str());
    ::unlink(receipt_path.c_str());
    if (!malformed_rejected) return false;

    decoded.signature[0] ^= 1;
    if (verify_live_native_source_batch_pin_receipt(
            scope, 0, view, bindings, decoded, issuer_public,
            receipt.issuer_id, 99))
        return false;

    auto wrong_issuer = receipt;
    if (verify_live_native_source_batch_pin_receipt(
            scope, 0, view, bindings, wrong_issuer, issuer_public,
            receipt.issuer_id + 1, 99))
        return false;
    auto wrong_owner = receipt;
    wrong_owner.owner = 1;
    if (verify_live_native_source_batch_pin_receipt(
            scope, 0, view, bindings, wrong_owner, issuer_public,
            receipt.issuer_id, 99))
        return false;
    auto changed_scope = scope;
    changed_scope.round += 1;
    if (verify_live_native_source_batch_pin_receipt(
            changed_scope, 0, view, bindings, receipt, issuer_public,
            receipt.issuer_id, 99))
        return false;
    auto changed_partition = scope;
    changed_partition.transfer_operations.push_back(scope.operations.front());
    if (compute_live_native_source_pin_batch_binding(
            changed_partition, 0, view, bindings, &rejected))
        return false;
    std::array<uint8_t, 32> zero_key{};
    if (verify_live_native_source_batch_pin_receipt(
            scope, 0, view, bindings, receipt, zero_key,
            receipt.issuer_id, 99))
        return false;

    return true;
}

namespace {
constexpr u64 LIVE_NATIVE_BATCH_PIN_RECEIPT_DOMAIN = 0x50564e4250523032ULL; // PVNBPR02
constexpr u64 LIVE_NATIVE_BATCH_PIN_RECEIPT_VERSION = 1;
constexpr uint8_t LIVE_NATIVE_BATCH_PIN_MAGIC[] =
    {'P', 'V', 'N', 'P', 'I', 'N', '0', '2'};

void append_u64_le(std::vector<uint8_t>* bytes, u64 value) {
    for (unsigned i = 0; i < 8; ++i)
        bytes->push_back(static_cast<uint8_t>(value >> (8 * i)));
}

void append_digest_bytes(std::vector<uint8_t>* bytes, const Digest& digest) {
    bytes->insert(bytes->end(), digest.bytes.begin(), digest.bytes.end());
}

u64 read_u64_le(const uint8_t* at) {
    u64 value = 0;
    for (unsigned i = 0; i < 8; ++i)
        value |= static_cast<u64>(at[i]) << (8 * i);
    return value;
}

bool write_private_file_exclusive(const std::string& path,
                                  const std::vector<uint8_t>& bytes) {
    if (path.empty()) return false;
    const int fd = ::open(path.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    size_t offset = 0;
    bool ok = true;
    while (offset < bytes.size()) {
        const ssize_t count = ::write(fd, bytes.data() + offset,
                                      bytes.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { ok = false; break; }
        offset += static_cast<size_t>(count);
    }
    if (ok) ok = ::fsync(fd) == 0;
    if (::close(fd) != 0) ok = false;
    if (!ok) ::unlink(path.c_str());
    return ok;
}

bool nonzero_issuer_key(const std::array<uint8_t, 32>& key) {
    return std::any_of(key.begin(), key.end(),
                       [](uint8_t byte) { return byte != 0; });
}

bool nonzero_signature(const std::array<uint8_t, 64>& signature) {
    return std::any_of(signature.begin(), signature.end(),
                       [](uint8_t byte) { return byte != 0; });
}

bool write_test_bytes_exclusive(const std::string& path,
                                const std::vector<uint8_t>& bytes,
                                mode_t mode) {
    const int fd = ::open(path.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
    if (fd < 0) return false;
    size_t offset = 0;
    bool ok = true;
    while (offset < bytes.size()) {
        const ssize_t count = ::write(fd, bytes.data() + offset,
                                      bytes.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { ok = false; break; }
        offset += static_cast<size_t>(count);
    }
    if (::close(fd) != 0) ok = false;
    if (!ok) ::unlink(path.c_str());
    return ok;
}
} // namespace

std::vector<uint8_t> live_native_source_batch_pin_signing_message(
    const LiveNativeSourceBatchPinReceipt& receipt) {
    if (!receipt.issuer_id || !receipt.sequence || !receipt.session_id ||
        !receipt.checkpoint || !receipt.operation_count ||
        receipt.owner >= 64 || receipt.scope_binding == Digest{} ||
        receipt.local_residual_root == Digest{} ||
        receipt.operation_binding_root == Digest{} ||
        receipt.batch_binding == Digest{})
        return {};
    std::vector<uint8_t> bytes;
    bytes.reserve(8 * 8 + 4 * 32);
    append_u64_le(&bytes, LIVE_NATIVE_BATCH_PIN_RECEIPT_DOMAIN);
    append_u64_le(&bytes, LIVE_NATIVE_BATCH_PIN_RECEIPT_VERSION);
    append_u64_le(&bytes, receipt.issuer_id);
    append_u64_le(&bytes, receipt.sequence);
    append_u64_le(&bytes, receipt.session_id);
    append_u64_le(&bytes, receipt.checkpoint);
    append_u64_le(&bytes, receipt.owner);
    append_u64_le(&bytes, receipt.operation_count);
    append_digest_bytes(&bytes, receipt.scope_binding);
    append_digest_bytes(&bytes, receipt.local_residual_root);
    append_digest_bytes(&bytes, receipt.operation_binding_root);
    append_digest_bytes(&bytes, receipt.batch_binding);
    return bytes;
}

bool write_live_native_source_batch_pin_receipt_file(
    const std::string& path,
    const LiveNativeSourceBatchPinReceipt& receipt) {
    if (path.empty() || !nonzero_signature(receipt.signature) ||
        live_native_source_batch_pin_signing_message(receipt).empty())
        return false;
    std::vector<uint8_t> wire(std::begin(LIVE_NATIVE_BATCH_PIN_MAGIC),
                              std::end(LIVE_NATIVE_BATCH_PIN_MAGIC));
    append_u64_le(&wire, receipt.issuer_id);
    append_u64_le(&wire, receipt.sequence);
    append_u64_le(&wire, receipt.session_id);
    append_u64_le(&wire, receipt.checkpoint);
    append_u64_le(&wire, receipt.owner);
    append_u64_le(&wire, receipt.operation_count);
    append_digest_bytes(&wire, receipt.scope_binding);
    append_digest_bytes(&wire, receipt.local_residual_root);
    append_digest_bytes(&wire, receipt.operation_binding_root);
    append_digest_bytes(&wire, receipt.batch_binding);
    wire.insert(wire.end(), receipt.signature.begin(), receipt.signature.end());
    return wire.size() == LIVE_NATIVE_BATCH_PIN_FILE_BYTES &&
           write_private_file_exclusive(path, wire);
}

bool read_live_native_source_batch_pin_receipt_file(
    const std::string& path,
    LiveNativeSourceBatchPinReceipt* receipt) {
    if (path.empty() || !receipt) return false;
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat status{};
    bool ok = ::fstat(fd, &status) == 0 && S_ISREG(status.st_mode) &&
        status.st_uid == ::geteuid() && (status.st_mode & 0077) == 0 &&
        status.st_size == static_cast<off_t>(LIVE_NATIVE_BATCH_PIN_FILE_BYTES);
    std::array<uint8_t, LIVE_NATIVE_BATCH_PIN_FILE_BYTES> wire{};
    size_t offset = 0;
    while (ok && offset < wire.size()) {
        const ssize_t count = ::read(fd, wire.data() + offset, wire.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { ok = false; break; }
        offset += static_cast<size_t>(count);
    }
    uint8_t trailing = 0;
    if (ok) {
        for (;;) {
            const ssize_t count = ::read(fd, &trailing, 1);
            if (count < 0 && errno == EINTR) continue;
            ok = count == 0;
            break;
        }
    }
    ::close(fd);
    if (!ok || !std::equal(std::begin(LIVE_NATIVE_BATCH_PIN_MAGIC),
                           std::end(LIVE_NATIVE_BATCH_PIN_MAGIC), wire.begin()))
        return false;

    size_t cursor = sizeof(LIVE_NATIVE_BATCH_PIN_MAGIC);
    const u64 issuer_id = read_u64_le(wire.data() + cursor); cursor += 8;
    const u64 sequence = read_u64_le(wire.data() + cursor); cursor += 8;
    const u64 session_id = read_u64_le(wire.data() + cursor); cursor += 8;
    const u64 checkpoint = read_u64_le(wire.data() + cursor); cursor += 8;
    const u64 owner = read_u64_le(wire.data() + cursor); cursor += 8;
    const u64 operation_count = read_u64_le(wire.data() + cursor); cursor += 8;
    if (owner >= 64 || checkpoint == 0) return false;

    LiveNativeSourceBatchPinReceipt parsed{};
    parsed.issuer_id = issuer_id;
    parsed.sequence = sequence;
    parsed.session_id = session_id;
    parsed.checkpoint = static_cast<CheckpointId>(checkpoint);
    parsed.owner = static_cast<uint32_t>(owner);
    parsed.operation_count = operation_count;
    auto read_digest = [&](Digest* digest) {
        std::copy_n(wire.data() + cursor, digest->bytes.size(), digest->bytes.begin());
        cursor += digest->bytes.size();
    };
    read_digest(&parsed.scope_binding);
    read_digest(&parsed.local_residual_root);
    read_digest(&parsed.operation_binding_root);
    read_digest(&parsed.batch_binding);
    std::copy_n(wire.data() + cursor, parsed.signature.size(), parsed.signature.begin());
    if (live_native_source_batch_pin_signing_message(parsed).empty()) return false;
    *receipt = parsed;
    return true;
}

bool verify_live_native_source_batch_pin_receipt(
    const ObligationSet& scope, uint32_t local_owner,
    const LocalResidualBatchView& local_view,
    const std::vector<LiveNativeSourceOperationBinding>& operation_bindings,
    const LiveNativeSourceBatchPinReceipt& receipt,
    const std::array<uint8_t, 32>& pinned_key,
    u64 expected_issuer_id, u64 minimum_accepted_sequence) {
    if (!expected_issuer_id || !minimum_accepted_sequence ||
        !nonzero_issuer_key(pinned_key) ||
        receipt.issuer_id != expected_issuer_id ||
        receipt.sequence < minimum_accepted_sequence ||
        receipt.session_id != scope.session_id ||
        receipt.checkpoint != scope.checkpoint ||
        receipt.owner != local_owner)
        return false;

    LiveNativeSourcePinBatchBinding expected{};
    if (!compute_live_native_source_pin_batch_binding(
            scope, local_owner, local_view, operation_bindings, &expected) ||
        receipt.operation_count != expected.operation_count ||
        receipt.scope_binding != expected.scope_binding ||
        receipt.local_residual_root != expected.local_residual_root ||
        receipt.operation_binding_root != expected.operation_binding_root ||
        receipt.batch_binding != expected.batch_binding)
        return false;

    const auto message = live_native_source_batch_pin_signing_message(receipt);
    if (message.empty()) return false;
    EVP_PKEY* key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, pinned_key.data(), pinned_key.size());
    if (!key) return false;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    const bool verified = context &&
        EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr, key) == 1 &&
        EVP_DigestVerify(context, receipt.signature.data(), receipt.signature.size(),
                         message.data(), message.size()) == 1;
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    return verified;
}

namespace {
int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

bool decode_hex_digest(const std::string& value, Digest* output) {
    if (!output || value.size() != 64) return false;
    for (size_t i = 0; i < 32; ++i) {
        const int upper = hex_nibble(value[2*i]);
        const int lower = hex_nibble(value[2*i+1]);
        if (upper < 0 || lower < 0) return false;
        output->bytes[i] = static_cast<uint8_t>(16*upper+lower);
    }
    return *output != Digest{};
}

bool decode_hex_public(const std::string& value,
                       std::array<uint8_t, 32>* output) {
    Digest value_digest{};
    if (!output || !decode_hex_digest(value, &value_digest)) return false;
    std::copy(value_digest.bytes.begin(), value_digest.bytes.end(),
              output->begin());
    return true;
}

bool canonical_u64(const std::string& text, u64* output) {
    if (!output || text.empty() ||
        (text.size() > 1 && text.front() == '0'))
        return false;
    u64 value = 0;
    for (char c : text) {
        if (c < '0' || c > '9' ||
            value > (std::numeric_limits<u64>::max() -
                     static_cast<u64>(c-'0')) / 10)
            return false;
        value = value*10 + static_cast<u64>(c-'0');
    }
    *output = value;
    return true;
}
} // namespace

bool verify_live_native_real_batch_public_fixture(
    const std::string& path) {
    std::ifstream file(path);
    if (!file) return false;
    std::string header;
    if (!(file >> header) ||
        header != "PVIA_REAL_NATIVE_BATCH_PUBLIC_FIXTURE_V1")
        return false;
    auto field = [&file](const char* label, std::string* output) {
        std::string actual;
        return bool(file >> actual >> *output) && actual == label;
    };
    auto scalar = [&field](const char* label, u64* value) {
        std::string input;
        return field(label, &input) && canonical_u64(input, value);
    };

    std::string receipt_path, issuer_public_hex, checkpoint_root_hex;
    u64 issuer_id = 0, minimum_sequence = 0, session_id = 0,
        checkpoint_id = 0, owner = 0, phase = 0, round = 0,
        generation = 0, operation_count = 0;
    if (!field("receipt_file", &receipt_path) ||
        !field("issuer_public_hex", &issuer_public_hex) ||
        !scalar("issuer_id", &issuer_id) ||
        !scalar("minimum_sequence", &minimum_sequence) ||
        !scalar("session_id", &session_id) ||
        !scalar("checkpoint", &checkpoint_id) ||
        !scalar("phase", &phase) ||
        !scalar("round", &round) ||
        !scalar("generation", &generation) ||
        !field("checkpoint_root", &checkpoint_root_hex) ||
        !scalar("owner", &owner) ||
        !scalar("operation_count", &operation_count) ||
        !issuer_id || !minimum_sequence || !session_id || !checkpoint_id ||
        owner >= 64 || operation_count != 2 ||
        phase != static_cast<u64>(Phase::FOLD) ||
        round > std::numeric_limits<uint32_t>::max() ||
        generation > std::numeric_limits<uint32_t>::max())
        return false;

    std::array<uint8_t, 32> pinned_key{};
    ObligationSet scope{};
    scope.session_id = session_id;
    scope.checkpoint = checkpoint_id;
    scope.phase = Phase::FOLD;
    scope.round = static_cast<uint32_t>(round);
    scope.generation = static_cast<uint32_t>(generation);
    scope.exact_round = true;
    if (!decode_hex_public(issuer_public_hex, &pinned_key) ||
        !decode_hex_digest(checkpoint_root_hex, &scope.checkpoint_root))
        return false;

    LocalResidualBatchView local_view{};
    local_view.scope = scope;
    local_view.local_owner = static_cast<uint32_t>(owner);
    std::vector<LiveNativeSourceOperationBinding> operation_bindings;
    for (u64 slot = 0; slot < operation_count; ++slot) {
        std::string key, object_text, commitment_hex, source_hex, claim_hex;
        if (!(file >> key >> object_text >> commitment_hex >>
              source_hex >> claim_hex) || key != "operation")
            return false;
        u64 object_id = 0;
        if (!canonical_u64(object_text, &object_id) || !object_id)
            return false;
        PrivateResidualHandle handle{};
        handle.ref = {static_cast<uint32_t>(owner), object_id};
        handle.label.sid = session_id;
        handle.label.phase = Phase::FOLD;
        handle.label.round = static_cast<uint32_t>(round);
        handle.label.owner = static_cast<uint32_t>(owner);
        handle.label.obligation = Obligation::FOLD;
        handle.label.object_id = object_id;
        handle.relation = RelationKind::FOLDING;
        handle.kernel = AuditRelationKernel::FOLD_RS;
        handle.checkpoint = checkpoint_id;
        handle.available = true;
        // Fixture-level declared status only. No private share is accessed
        // here; this must not be described as residual authentication.
        handle.authenticated = true;
        if (!decode_hex_digest(commitment_hex, &handle.commitment))
            return false;
        LiveNativeSourceOperationBinding binding{};
        binding.ref = handle.ref;
        if (!decode_hex_digest(source_hex,
                               &binding.native_consumed_record_binding) ||
            !decode_hex_digest(claim_hex,
                               &binding.registration_pre_vss_claim_binding))
            return false;
        scope.operations.push_back(handle.ref);
        scope.private_operations.push_back(handle.ref);
        local_view.handles.push_back(handle);
        operation_bindings.push_back(binding);
    }
    std::string trailing;
    if (file >> trailing) return false;
    local_view.scope = scope;
    local_view.all_authenticated = true;
    local_view.complete_for_owner = true;
    local_view.commitment_root =
        compute_private_residual_local_handle_root(local_view.handles);

    LiveNativeSourceBatchPinReceipt receipt{};
    return local_view.commitment_root != Digest{} &&
        read_live_native_source_batch_pin_receipt_file(receipt_path,
                                                      &receipt) &&
        verify_live_native_source_batch_pin_receipt(
            scope, static_cast<uint32_t>(owner), local_view,
            operation_bindings, receipt, pinned_key,
            issuer_id, minimum_sequence);
}

} // namespace pvia
