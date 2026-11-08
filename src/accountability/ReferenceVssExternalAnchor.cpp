#include "ReferenceVssExternalAnchor.hpp"
#include "PVIA.hpp"

#include <mpi.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

namespace pvia {
namespace {
constexpr uint64_t EXTERNAL_MAGIC = 0x5056494145585431ULL;
constexpr uint64_t EXTERNAL_VERSION = 1;
constexpr uint64_t OP_INIT = 1;
constexpr uint64_t OP_READ = 2;
constexpr uint64_t OP_CAS = 3;
constexpr uint64_t OP_ATTEST = 4;
constexpr uint64_t STATUS_OK = 0;
constexpr size_t REQUEST_PREFIX_SIZE = 240;
constexpr size_t REQUEST_SIZE = 272;
constexpr size_t RESPONSE_PREFIX_SIZE = 240;
constexpr size_t RESPONSE_SIZE = 304;
constexpr uint64_t AUTH_BINDING_DOMAIN = 0x5056494145584155ULL;

struct ExternalResponse {
    uint64_t status = UINT64_MAX;
    ReferenceVssExternalAnchorSnapshot snapshot{};
    Digest authorized_next{};
    Digest request_binding{};
};

void append_u64(std::vector<uint8_t>* out, uint64_t value) {
    for (size_t i = 0; i < 8; ++i)
        out->push_back(static_cast<uint8_t>(value >> (8 * i)));
}

uint64_t read_u64(const uint8_t* input) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i)
        value |= static_cast<uint64_t>(input[i]) << (8 * i);
    return value;
}

void append_digest(std::vector<uint8_t>* out, const Digest& digest) {
    out->insert(out->end(), digest.bytes.begin(), digest.bytes.end());
}

Digest read_digest(const uint8_t* input) {
    Digest digest{};
    std::copy(input, input + digest.bytes.size(), digest.bytes.begin());
    return digest;
}

bool parse_hex_32(const char* text, std::array<uint8_t, 32>* output) {
    if (!text || !output || std::strlen(text) != 64) return false;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < output->size(); ++i) {
        const int high = nibble(text[2 * i]);
        const int low = nibble(text[2 * i + 1]);
        if (high < 0 || low < 0) return false;
        (*output)[i] = static_cast<uint8_t>((high << 4) | low);
    }
    return true;
}

bool all_zero(const std::array<uint8_t, 32>& value) {
    return std::all_of(value.begin(), value.end(),
                       [](uint8_t byte) { return byte == 0; });
}

bool send_all(int fd, const uint8_t* data, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        const ssize_t sent = ::send(fd, data + offset, length - offset, 0);
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0) return false;
        offset += static_cast<size_t>(sent);
    }
    return true;
}

bool receive_all(int fd, uint8_t* data, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        const ssize_t got = ::recv(fd, data + offset, length - offset, 0);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return false;
        offset += static_cast<size_t>(got);
    }
    return true;
}

bool verify_response_signature(
    const std::array<uint8_t, 32>& public_key,
    const uint8_t* response) {
    EVP_PKEY* key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, public_key.data(), public_key.size());
    if (!key) return false;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    bool ok = context != nullptr &&
        EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr, key) == 1 &&
        EVP_DigestVerify(context,
            response + RESPONSE_PREFIX_SIZE, 64,
            response, RESPONSE_PREFIX_SIZE) == 1;
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    return ok;
}

Digest release_request_binding(
    const AuthenticatedMpcMessageContext& context, int target,
    const std::vector<int>& helpers) {
    if (!validate_authenticated_mpc_message_context(context) ||
        context.protocol_domain != PVIA_VSS_SELECTIVE_POINT_DOMAIN ||
        context.message_kind != PVIA_VSS_SELECTIVE_POINT_KIND ||
        target < 0 || helpers.empty() || helpers.size() > 1024)
        return {};
    std::vector<int> sorted = helpers;
    std::sort(sorted.begin(), sorted.end());
    if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end() ||
        std::find(sorted.begin(), sorted.end(), target) != sorted.end() ||
        std::any_of(sorted.begin(), sorted.end(),
                    [](int rank) { return rank < 0; }))
        return {};
    std::vector<u64> words = {
        AUTH_BINDING_DOMAIN, context.protocol_domain, context.sid,
        context.checkpoint, context.round, context.sequence,
        context.message_kind, static_cast<u64>(target),
        static_cast<u64>(sorted.size())};
    for (int helper : sorted) words.push_back(static_cast<u64>(helper));
    return hash_words(words);
}

bool snapshot_has_identity(
    const ReferenceVssExternalAnchorSnapshot& snapshot) {
    return snapshot.record_binding != Digest{} &&
           snapshot.native_execution_binding != Digest{} &&
           snapshot.registry_binding != Digest{} &&
           snapshot.replay_head != Digest{};
}

bool external_anchor_exchange(
    const std::string& host, uint16_t port,
    const std::array<uint8_t, 32>& auth_token,
    const std::array<uint8_t, 32>& server_public_key,
    uint64_t operation,
    const ReferenceVssExternalAnchorSnapshot* pins,
    uint64_t generation, const Digest& expected_head,
    const Digest& next_head, const Digest& request_binding,
    ExternalResponse* output) {
    if (!output || host.empty() || host.size() > 255 || port == 0 ||
        all_zero(auth_token) || all_zero(server_public_key))
        return false;
    *output = ExternalResponse{};

    std::vector<uint8_t> request;
    request.reserve(REQUEST_SIZE);
    append_u64(&request, EXTERNAL_MAGIC);
    append_u64(&request, EXTERNAL_VERSION);
    append_u64(&request, operation);
    if (pins) {
        append_digest(&request, pins->record_binding);
        append_digest(&request, pins->native_execution_binding);
        append_digest(&request, pins->registry_binding);
    } else {
        const Digest zero{};
        append_digest(&request, zero);
        append_digest(&request, zero);
        append_digest(&request, zero);
    }
    append_u64(&request, generation);
    append_digest(&request, expected_head);
    append_digest(&request, next_head);
    append_digest(&request, request_binding);
    std::array<uint8_t, 16> nonce{};
    if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1)
        return false;
    request.insert(request.end(), nonce.begin(), nonce.end());
    if (request.size() != REQUEST_PREFIX_SIZE) return false;

    std::array<uint8_t, 32> mac{};
    unsigned int mac_length = 0;
    if (!HMAC(EVP_sha256(), auth_token.data(),
              static_cast<int>(auth_token.size()),
              request.data(), request.size(), mac.data(), &mac_length) ||
        mac_length != mac.size())
        return false;
    request.insert(request.end(), mac.begin(), mac.end());
    if (request.size() != REQUEST_SIZE) return false;

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* addresses = nullptr;
    const std::string service = std::to_string(port);
    if (::getaddrinfo(host.c_str(), service.c_str(), &hints, &addresses) != 0)
        return false;

    int fd = -1;
    for (addrinfo* address = addresses; address; address = address->ai_next) {
        fd = ::socket(address->ai_family, address->ai_socktype,
                      address->ai_protocol);
        if (fd < 0) continue;
        timeval timeout{};
        timeout.tv_sec = 5;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        if (::connect(fd, address->ai_addr, address->ai_addrlen) == 0) break;
        ::close(fd);
        fd = -1;
    }
    ::freeaddrinfo(addresses);
    if (fd < 0) return false;

    std::array<uint8_t, RESPONSE_SIZE> response{};
    bool ok = send_all(fd, request.data(), request.size()) &&
              receive_all(fd, response.data(), response.size());
    if (::close(fd) != 0) ok = false;
    if (!ok || !verify_response_signature(server_public_key, response.data()))
        return false;

    const uint8_t* p = response.data();
    if (read_u64(p) != EXTERNAL_MAGIC ||
        read_u64(p + 8) != EXTERNAL_VERSION ||
        !std::equal(nonce.begin(), nonce.end(), p + 224))
        return false;

    output->status = read_u64(p + 16);
    output->snapshot.record_binding = read_digest(p + 24);
    output->snapshot.native_execution_binding = read_digest(p + 56);
    output->snapshot.registry_binding = read_digest(p + 88);
    output->snapshot.generation = read_u64(p + 120);
    output->snapshot.replay_head = read_digest(p + 128);
    output->authorized_next = read_digest(p + 160);
    output->request_binding = read_digest(p + 192);
    return true;
}

} // namespace

bool ReferenceVssExternalAnchorClient::LoadFromEnvironment() {
    const char* token = std::getenv("PVIA_EXTERNAL_ANCHOR_AUTH_TOKEN");
    const char* public_key = std::getenv("PVIA_EXTERNAL_ANCHOR_PUBLIC_KEY_HEX");
    const char* host = std::getenv("PVIA_EXTERNAL_ANCHOR_HOST");
    const char* port = std::getenv("PVIA_EXTERNAL_ANCHOR_PORT");
    if (!parse_hex_32(token, &auth_token_) ||
        !parse_hex_32(public_key, &server_public_key_))
        return false;
    host_ = host && *host ? host : "127.0.0.1";
    if (port && *port) {
        char* end = nullptr;
        const unsigned long parsed = std::strtoul(port, &end, 10);
        if (!end || *end || parsed == 0 || parsed > 65535) return false;
        port_ = static_cast<uint16_t>(parsed);
    } else {
        port_ = 18765;
    }
    return Ready();
}

bool ReferenceVssExternalAnchorClient::Ready() const {
    return !host_.empty() && host_.size() <= 255 && port_ != 0 &&
           !all_zero(auth_token_) && !all_zero(server_public_key_);
}

bool ReferenceVssExternalAnchorClient::InitializeNew(
    const Digest& record, const Digest& native, const Digest& registry,
    const Digest& initial_head) const {
    if (!Ready() || record == Digest{} || native == Digest{} ||
        registry == Digest{} || initial_head == Digest{})
        return false;
    ReferenceVssExternalAnchorSnapshot pins;
    pins.record_binding = record;
    pins.native_execution_binding = native;
    pins.registry_binding = registry;
    ExternalResponse response;
    const Digest zero{};
    return external_anchor_exchange(
               host_, port_, auth_token_, server_public_key_, OP_INIT,
               &pins, 0, zero, initial_head, zero, &response) &&
           response.status == STATUS_OK &&
           response.snapshot.record_binding == record &&
           response.snapshot.native_execution_binding == native &&
           response.snapshot.registry_binding == registry &&
           response.snapshot.generation == 0 &&
           response.snapshot.replay_head == initial_head &&
           response.authorized_next == zero &&
           response.request_binding == zero;
}

bool ReferenceVssExternalAnchorClient::ReadSnapshot(
    ReferenceVssExternalAnchorSnapshot* snapshot) const {
    if (!Ready() || !snapshot) return false;
    *snapshot = ReferenceVssExternalAnchorSnapshot{};
    ExternalResponse response;
    const Digest zero{};
    if (!external_anchor_exchange(
            host_, port_, auth_token_, server_public_key_, OP_READ,
            nullptr, 0, zero, zero, zero, &response) ||
        response.status != STATUS_OK ||
        !snapshot_has_identity(response.snapshot) ||
        response.authorized_next != zero ||
        response.request_binding != zero)
        return false;
    *snapshot = response.snapshot;
    return true;
}

bool ReferenceVssExternalAnchorClient::CompareAndSwap(
    const ReferenceVssExternalAnchorSnapshot& expected,
    const Digest& next_head,
    ReferenceVssExternalAnchorSnapshot* updated) const {
    if (!Ready() || !snapshot_has_identity(expected) ||
        next_head == Digest{} || next_head == expected.replay_head ||
        expected.generation == UINT64_MAX)
        return false;
    ExternalResponse response;
    const Digest zero{};
    if (!external_anchor_exchange(
            host_, port_, auth_token_, server_public_key_, OP_CAS,
            &expected, expected.generation, expected.replay_head,
            next_head, zero, &response) ||
        response.status != STATUS_OK ||
        response.snapshot.record_binding != expected.record_binding ||
        response.snapshot.native_execution_binding !=
            expected.native_execution_binding ||
        response.snapshot.registry_binding != expected.registry_binding ||
        response.snapshot.generation != expected.generation + 1 ||
        response.snapshot.replay_head != next_head ||
        response.authorized_next != zero ||
        response.request_binding != zero)
        return false;
    if (updated) *updated = response.snapshot;
    return true;
}

bool ReferenceVssExternalAnchorClient::AttestTransition(
    const ReferenceVssExternalAnchorSnapshot& expected,
    const AuthenticatedMpcMessageContext& context,
    int target, const std::vector<int>& helpers,
    const Digest& authorized_next_head) const {
    if (!Ready() || !snapshot_has_identity(expected) ||
        authorized_next_head == Digest{})
        return false;
    const Digest binding = release_request_binding(context, target, helpers);
    if (binding == Digest{}) return false;
    ExternalResponse response;
    return external_anchor_exchange(
               host_, port_, auth_token_, server_public_key_, OP_ATTEST,
               &expected, expected.generation, expected.replay_head,
               authorized_next_head, binding, &response) &&
           response.status == STATUS_OK &&
           response.snapshot.record_binding == expected.record_binding &&
           response.snapshot.native_execution_binding ==
               expected.native_execution_binding &&
           response.snapshot.registry_binding == expected.registry_binding &&
           response.snapshot.generation == expected.generation &&
           response.snapshot.replay_head == expected.replay_head &&
           response.authorized_next == authorized_next_head &&
           response.request_binding == binding;
}

bool ReferenceVssExternalAnchorClient::ConfigureReleasePins(
    const std::string& registry_path,
    const std::string& replay_journal_path,
    const ReferenceVssExternalAnchorSnapshot& identity,
    ReferenceVssExternalAnchorResumeMode resume_mode,
    ReferenceVssSelectiveReleasePins* pins) {
    if (!Ready() || !pins || registry_path.empty() ||
        replay_journal_path.empty() || !snapshot_has_identity(identity))
        return false;
    pins->registry_path = registry_path;
    pins->replay_journal_path = replay_journal_path;
    pins->independently_pinned_record = identity.record_binding;
    pins->independently_pinned_native_execution =
        identity.native_execution_binding;
    pins->independently_pinned_registry_binding = identity.registry_binding;
    pins->independently_pinned_replay_head = identity.replay_head;

    const Digest record = identity.record_binding;
    const Digest native = identity.native_execution_binding;
    const Digest registry = identity.registry_binding;
    pins->load_current_head = [this, record, native, registry](Digest* head) {
        if (!head) return false;
        *head = {};
        ReferenceVssExternalAnchorSnapshot current;
        if (!ReadSnapshot(&current) ||
            current.record_binding != record ||
            current.native_execution_binding != native ||
            current.registry_binding != registry)
            return false;
        *head = current.replay_head;
        return true;
    };
    pins->verify_independent_pins =
        [this, record, native, registry](
            const Digest& requested_record, const Digest& requested_native,
            const Digest& requested_registry, const Digest& requested_head) {
            ReferenceVssExternalAnchorSnapshot current;
            return requested_record == record && requested_native == native &&
                requested_registry == registry &&
                ReadSnapshot(&current) &&
                current.record_binding == record &&
                current.native_execution_binding == native &&
                current.registry_binding == registry &&
                current.replay_head == requested_head;
        };
    // The coordinator rejects configurations that enable both modes.
    // Install exactly one mode so the caller cannot accidentally request a
    // pending retry and a committed resume in the same release invocation.
    pins->authorize_committed_resume = {};
    pins->authorize_pending_resume = {};
    if (resume_mode == ReferenceVssExternalAnchorResumeMode::kCommitted) {
        pins->authorize_committed_resume =
            [this, record, native, registry](
                const AuthenticatedMpcMessageContext& context, int target,
                const std::vector<int>& helpers, const Digest& head) {
                ReferenceVssExternalAnchorSnapshot current;
                return ReadSnapshot(&current) &&
                    current.record_binding == record &&
                    current.native_execution_binding == native &&
                    current.registry_binding == registry &&
                    current.replay_head == head &&
                    AttestTransition(current, context, target, helpers, head);
            };
    } else if (resume_mode ==
               ReferenceVssExternalAnchorResumeMode::kPending) {
        pins->authorize_pending_resume =
            [this, record, native, registry](
                const AuthenticatedMpcMessageContext& context, int target,
                const std::vector<int>& helpers, const Digest& old_head,
                const Digest& pending_head) {
                ReferenceVssExternalAnchorSnapshot current;
                return ReadSnapshot(&current) &&
                    current.record_binding == record &&
                    current.native_execution_binding == native &&
                    current.registry_binding == registry &&
                    current.replay_head == old_head &&
                    AttestTransition(
                        current, context, target, helpers, pending_head);
            };
    } else if (resume_mode != ReferenceVssExternalAnchorResumeMode::kFresh) {
        return false;
    }
    pins->persist_new_head =
        [this, record, native, registry](
            const Digest& old_head, const Digest& next_head) {
            ReferenceVssExternalAnchorSnapshot current;
            if (!ReadSnapshot(&current) ||
                current.record_binding != record ||
                current.native_execution_binding != native ||
                current.registry_binding != registry ||
                current.replay_head != old_head)
                return false;
            return CompareAndSwap(current, next_head, nullptr);
        };
    return true;
}

bool ReferenceVssExternalReleaseGate::Initialize(
    int rank, int world_size, uint64_t session_id,
    const Digest& registry_binding) {
    rank_ = rank;
    world_size_ = world_size;
    session_id_ = session_id;
    registry_binding_ = registry_binding;
    initialized_ = false;
    if (rank < 0 || world_size <= 0 || rank >= world_size)
        return false;
    resumed_ = false;
    int local_ok = session_id != 0 && registry_binding != Digest{} ? 1 : 0;

    const auto append_digest_words = [](std::vector<u64>* words,
                                        const Digest& digest) {
        if (!words) return;
        for (size_t offset = 0; offset < digest.bytes.size();
             offset += sizeof(u64)) {
            u64 word = 0;
            for (size_t i = 0; i < sizeof(u64); ++i)
                word |= static_cast<u64>(digest.bytes[offset + i]) << (8 * i);
            words->push_back(word);
        }
    };
    std::vector<u64> record_words = {
        0x5056494152454c52ULL, session_id,
        static_cast<u64>(world_size)};
    append_digest_words(&record_words, registry_binding_);
    record_binding_ = hash_words(record_words);

    std::vector<u64> native_words = {
        0x5056494152454c4eULL, session_id,
        static_cast<u64>(world_size)};
    append_digest_words(&native_words, record_binding_);
    append_digest_words(&native_words, registry_binding_);
    native_execution_binding_ = hash_words(native_words);

    std::vector<u64> initial_words = {
        0x5056494152454c48ULL, session_id,
        static_cast<u64>(world_size)};
    append_digest_words(&initial_words, record_binding_);
    append_digest_words(&initial_words, native_execution_binding_);
    append_digest_words(&initial_words, registry_binding_);
    initial_replay_head_ = hash_words(initial_words);
    if (record_binding_ == Digest{} ||
        native_execution_binding_ == Digest{} ||
        initial_replay_head_ == Digest{})
        local_ok = 0;

    local_ok = local_ok && client_.LoadFromEnvironment() ? 1 : 0;
    if (rank_ == 0 && local_ok) {
        // A verified existing snapshot is the recovery source of truth.
        // Do not require generation zero or reconstruct the initial head:
        // both would reject a legitimate process restart after any release.
        bool snapshot_ok = client_.ReadSnapshot(&snapshot_);
        bool created_new = false;
        if (!snapshot_ok) {
            created_new = client_.InitializeNew(
                record_binding_, native_execution_binding_,
                registry_binding_, initial_replay_head_);
            snapshot_ok = client_.ReadSnapshot(&snapshot_);
        }
        resumed_ = snapshot_ok && !created_new;
        local_ok = snapshot_ok &&
            snapshot_.record_binding == record_binding_ &&
            snapshot_.native_execution_binding == native_execution_binding_ &&
            snapshot_.registry_binding == registry_binding_ &&
            snapshot_.generation < UINT64_MAX &&
            snapshot_.replay_head != Digest{} ? 1 : 0;
    }

    int global_ok = 0;
    if (MPI_Allreduce(&local_ok, &global_ok, 1, MPI_INT, MPI_MIN,
                      MPI_COMM_WORLD) != MPI_SUCCESS)
        return false;
    initialized_ = global_ok == 1;
    return initialized_;
}

bool ReferenceVssExternalReleaseGate::Attach(Runtime& runtime) {
    if (!initialized_ || !runtime.external_release_anchor_required())
        return false;
    runtime.set_external_release_anchor_gate(
        [this](const char* name, Phase phase, uint32_t round,
               const Digest& release_context) {
            return Authorize(name, static_cast<uint32_t>(phase), round,
                             release_context);
        });
    return true;
}

bool ReferenceVssExternalReleaseGate::Authorize(
    const char* release_name, uint32_t phase, uint32_t round,
    const Digest& release_context) {
    if (!initialized_ || rank_ != 0 || !release_name ||
        release_context == Digest{})
        return false;
    ReferenceVssExternalAnchorSnapshot current;
    if (!client_.ReadSnapshot(&current) ||
        current.record_binding != record_binding_ ||
        current.native_execution_binding != native_execution_binding_ ||
        current.registry_binding != registry_binding_ ||
        current.generation != snapshot_.generation ||
        current.replay_head != snapshot_.replay_head ||
        current.generation == UINT64_MAX)
        return false;

    std::vector<u64> transition_words = {
        0x5056494152454c54ULL, session_id_,
        static_cast<u64>(world_size_), current.generation,
        static_cast<u64>(phase), static_cast<u64>(round)};
    const auto append_digest_words = [&transition_words](
        const Digest& digest) {
        for (size_t offset = 0; offset < digest.bytes.size();
             offset += sizeof(u64)) {
            u64 word = 0;
            for (size_t i = 0; i < sizeof(u64); ++i)
                word |= static_cast<u64>(digest.bytes[offset + i]) << (8 * i);
            transition_words.push_back(word);
        }
    };
    append_digest_words(current.record_binding);
    append_digest_words(current.native_execution_binding);
    append_digest_words(current.registry_binding);
    append_digest_words(current.replay_head);
    append_digest_words(release_context);
    const std::string label(release_name);
    transition_words.push_back(static_cast<u64>(label.size()));
    for (size_t offset = 0; offset < label.size(); offset += sizeof(u64)) {
        u64 word = 0;
        const size_t count = std::min(sizeof(u64), label.size() - offset);
        for (size_t i = 0; i < count; ++i)
            word |= static_cast<u64>(
                static_cast<unsigned char>(label[offset + i])) << (8 * i);
        transition_words.push_back(word);
    }
    const Digest next_head = hash_words(transition_words);
    if (next_head == Digest{} || next_head == current.replay_head)
        return false;

    ReferenceVssExternalAnchorSnapshot updated;
    if (!client_.CompareAndSwap(current, next_head, &updated) ||
        updated.record_binding != record_binding_ ||
        updated.native_execution_binding != native_execution_binding_ ||
        updated.registry_binding != registry_binding_ ||
        updated.generation != current.generation + 1 ||
        updated.replay_head != next_head)
        return false;
    snapshot_ = updated;
    return true;
}

bool ReferenceVssExternalReleaseGate::RunGateSelfTest(
    Runtime& runtime, int rank, int world_size) {
    if (!initialized_ || rank != rank_ || world_size != world_size_ ||
        !Attach(runtime))
        return false;

    const bool valid_allowed = runtime.pre_release_gate(
        "external_anchor_gate_valid_probe", Phase::INIT, 9001);

    Digest saved_record = record_binding_;
    record_binding_.bytes[0] ^= 0x01;
    const bool record_mismatch_denied = !runtime.pre_release_gate(
        "external_anchor_gate_record_mismatch_probe", Phase::INIT, 9002);
    record_binding_ = saved_record;

    Digest saved_native = native_execution_binding_;
    native_execution_binding_.bytes[0] ^= 0x01;
    const bool native_mismatch_denied = !runtime.pre_release_gate(
        "external_anchor_gate_native_mismatch_probe", Phase::INIT, 9003);
    native_execution_binding_ = saved_native;

    Digest saved_registry = registry_binding_;
    registry_binding_.bytes[0] ^= 0x01;
    const bool registry_mismatch_denied = !runtime.pre_release_gate(
        "external_anchor_gate_registry_mismatch_probe", Phase::INIT, 9004);
    registry_binding_ = saved_registry;

    Digest saved_head = snapshot_.replay_head;
    snapshot_.replay_head.bytes[0] ^= 0x01;
    const bool replay_head_mismatch_denied = !runtime.pre_release_gate(
        "external_anchor_gate_replay_head_mismatch_probe", Phase::INIT, 9005);
    snapshot_.replay_head = saved_head;

    const uint64_t saved_generation = snapshot_.generation;
    snapshot_.generation = saved_generation + 1;
    const bool generation_mismatch_denied = !runtime.pre_release_gate(
        "external_anchor_gate_generation_mismatch_probe", Phase::INIT, 9006);
    snapshot_.generation = saved_generation;

    const bool mismatched_identity_denied =
        record_mismatch_denied && native_mismatch_denied &&
        registry_mismatch_denied && replay_head_mismatch_denied &&
        generation_mismatch_denied;

    const char* previous_port_value =
        std::getenv("PVIA_EXTERNAL_ANCHOR_PORT");
    const bool had_previous_port = previous_port_value != nullptr;
    const std::string previous_port =
        previous_port_value ? previous_port_value : "";
    const bool port_changed =
        ::setenv("PVIA_EXTERNAL_ANCHOR_PORT", "65534", 1) == 0;
    ReferenceVssExternalAnchorClient unavailable_client;
    const bool unavailable_client_loaded =
        port_changed && unavailable_client.LoadFromEnvironment();
    if (had_previous_port)
        ::setenv("PVIA_EXTERNAL_ANCHOR_PORT", previous_port.c_str(), 1);
    else
        ::unsetenv("PVIA_EXTERNAL_ANCHOR_PORT");
    runtime.set_external_release_anchor_gate(
        [unavailable_client, unavailable_client_loaded, rank](
            const char*, Phase, uint32_t, const Digest&) {
            if (rank != 0) return true;
            ReferenceVssExternalAnchorSnapshot current;
            return unavailable_client_loaded &&
                unavailable_client.ReadSnapshot(&current);
        });
    const bool unavailable_service_denied = !runtime.pre_release_gate(
        "external_anchor_gate_unavailable_probe", Phase::INIT, 9003);

    bool snapshot_unchanged = true;
    if (rank_ == 0) {
        ReferenceVssExternalAnchorSnapshot current;
        snapshot_unchanged = client_.ReadSnapshot(&current) &&
            current.record_binding == record_binding_ &&
            current.native_execution_binding == native_execution_binding_ &&
            current.registry_binding == registry_binding_ &&
            current.generation == snapshot_.generation &&
            current.replay_head == snapshot_.replay_head;
    }
    const bool restored = Attach(runtime);
    int local_ok = valid_allowed && mismatched_identity_denied &&
        unavailable_service_denied && snapshot_unchanged && restored ? 1 : 0;
    int global_ok = 0;
    if (MPI_Allreduce(&local_ok, &global_ok, 1, MPI_INT, MPI_MIN,
                      MPI_COMM_WORLD) != MPI_SUCCESS)
        return false;
    if (rank == 0) {
        std::cout << "[PVIA][external-release-anchor-gate-selftest] "
                  << (global_ok ? "PASS" : "FAIL")
                  << " valid=ALLOW record_mismatch=WITHHOLD"
                  << " native_mismatch=WITHHOLD registry_mismatch=WITHHOLD"
                  << " replay_head_mismatch=WITHHOLD generation_mismatch=WITHHOLD"
                  << " unavailable=WITHHOLD"
                  << " generation=" << snapshot_.generation << std::endl;
    }
    return global_ok == 1;
}

bool run_reference_vss_external_anchor_selftest(
    int rank, int world_size, const std::string& phase) {
    if (world_size != 4 || rank < 0 || rank >= world_size ||
        (phase != "prepare" && phase != "resume" && phase != "final" &&
         phase != "verify"))
        return false;
    if (rank != 0) return true;

    ReferenceVssExternalAnchorClient client;
    if (!client.LoadFromEnvironment()) return false;

    const Digest record = hash_words({0x5056455854524543ULL, 1, 4});
    const Digest native = hash_words({0x50564558544e4154ULL, 1, 4});
    const Digest registry = hash_words({0x5056455854524547ULL, 1, 4});
    const Digest initial = hash_words({0x5056455854484541ULL, 0, 4});
    const Digest first = hash_words({0x5056455854484541ULL, 1, 4});
    const Digest branch_a = hash_words({0x5056455854484541ULL, 2, 4});
    const Digest branch_b = hash_words({0x5056455854484541ULL, 3, 4});
    const Digest final_head = hash_words({0x5056455854484541ULL, 4, 4});
    bool ok = record != Digest{} && native != Digest{} &&
        registry != Digest{} && initial != Digest{} && first != Digest{} &&
        branch_a != Digest{} && branch_b != Digest{} && final_head != Digest{};

    if (phase == "prepare") {
        const bool initialized = ok &&
            client.InitializeNew(record, native, registry, initial);
        ReferenceVssExternalAnchorSnapshot initial_snapshot;
        const bool initial_read = initialized &&
            client.ReadSnapshot(&initial_snapshot) &&
            initial_snapshot.record_binding == record &&
            initial_snapshot.native_execution_binding == native &&
            initial_snapshot.registry_binding == registry &&
            initial_snapshot.generation == 0 &&
            initial_snapshot.replay_head == initial;
        const bool duplicate_init_rejected =
            !client.InitializeNew(record, native, registry, initial);
        ReferenceVssExternalAnchorSnapshot after_first;
        const bool first_cas = initial_read &&
            client.CompareAndSwap(initial_snapshot, first, &after_first) &&
            after_first.generation == 1 &&
            after_first.replay_head == first;
        const bool stale_cas_rejected = first_cas &&
            !client.CompareAndSwap(initial_snapshot, branch_a, nullptr);

        std::atomic<int> winners{0};
        ReferenceVssExternalAnchorClient left = client;
        ReferenceVssExternalAnchorClient right = client;
        std::thread thread_a([&]() {
            if (left.CompareAndSwap(after_first, branch_a, nullptr))
                ++winners;
        });
        std::thread thread_b([&]() {
            if (right.CompareAndSwap(after_first, branch_b, nullptr))
                ++winners;
        });
        thread_a.join();
        thread_b.join();

        ReferenceVssExternalAnchorSnapshot after_race;
        const bool race_single_winner = winners.load() == 1 &&
            client.ReadSnapshot(&after_race) &&
            after_race.generation == 2 &&
            (after_race.replay_head == branch_a ||
             after_race.replay_head == branch_b);
        ok = initialized && initial_read && duplicate_init_rejected &&
             first_cas && stale_cas_rejected && race_single_winner;
        std::cout << "PVIA_VSS_EXTERNAL_ANCHOR_SELFTEST: "
                  << (ok ? "PASS" : "FAIL")
                  << " phase=PREPARE separate_host_rpc=PASS"
                  << " signed_snapshot=" << (initial_read ? "PASS" : "FAIL")
                  << " duplicate_init="
                  << (duplicate_init_rejected ? "REJECTED" : "FAIL")
                  << " stale_generation_cas="
                  << (stale_cas_rejected ? "REJECTED" : "FAIL")
                  << " concurrent_cas_single_winner="
                  << (race_single_winner ? "PASS" : "FAIL")
                  << " generation=" << (race_single_winner ? 2 : 0)
                  << " host_storage_rollback=NOT_CLAIMED" << std::endl;
        return ok;
    }

    ReferenceVssExternalAnchorSnapshot current;
    const bool loaded = client.ReadSnapshot(&current);
    if (!loaded || current.record_binding != record ||
        current.native_execution_binding != native ||
        current.registry_binding != registry)
        return false;

    if (phase == "verify") {
        const bool generation_persisted = current.generation == 4 &&
            current.replay_head != Digest{};
        ReferenceVssSelectiveReleasePins pins;
        ReferenceVssSelectiveReleasePins fresh_pins;
        const bool fresh_mode_configured = generation_persisted &&
            client.ConfigureReleasePins(
                "/external/registry.record", "/external/replay.journal",
                current, ReferenceVssExternalAnchorResumeMode::kFresh,
                &fresh_pins) &&
            !fresh_pins.authorize_committed_resume &&
            !fresh_pins.authorize_pending_resume;
        const bool pins_configured = generation_persisted &&
            client.ConfigureReleasePins(
                "/external/registry.record", "/external/replay.journal",
                current, ReferenceVssExternalAnchorResumeMode::kPending,
                &pins);
        Digest reloaded_head{};
        const bool callback_reload = pins_configured &&
            pins.load_current_head(&reloaded_head) &&
            reloaded_head == current.replay_head;
        const bool independent_pin_check = pins_configured &&
            pins.verify_independent_pins(
                record, native, registry, current.replay_head);
        AuthenticatedMpcMessageContext context;
        context.protocol_domain = PVIA_VSS_SELECTIVE_POINT_DOMAIN;
        context.sid = 0x5056455854564552ULL;
        context.checkpoint = 0x4558545645520001ULL;
        context.round = 31;
        context.sequence = 47;
        context.message_kind = PVIA_VSS_SELECTIVE_POINT_KIND;
        const std::vector<int> helpers{1, 2, 3};
        const bool valid_attestation = generation_persisted &&
            client.AttestTransition(
                current, context, 0, helpers, current.replay_head);
        AuthenticatedMpcMessageContext wrong_domain = context;
        wrong_domain.protocol_domain ^= 1;
        const bool wrong_domain_rejected = generation_persisted &&
            !client.AttestTransition(
                current, wrong_domain, 0, helpers, current.replay_head);
        ok = generation_persisted && fresh_mode_configured &&
             pins_configured && callback_reload && independent_pin_check &&
             valid_attestation && wrong_domain_rejected;
        std::cout << "PVIA_VSS_EXTERNAL_ANCHOR_SELFTEST: "
                  << (ok ? "PASS" : "FAIL")
                  << " phase=VERIFY service_restart=PASS"
                  << " persisted_generation="
                  << (generation_persisted ? "PASS" : "FAIL")
                  << " coordinator_reload="
                  << (callback_reload ? "PASS" : "FAIL")
                  << " fresh_mode="
                  << (fresh_mode_configured ? "PASS" : "FAIL")
                  << " independent_pins="
                  << (independent_pin_check ? "PASS" : "FAIL")
                  << " signed_attestation="
                  << (valid_attestation ? "PASS" : "FAIL")
                  << " wrong_protocol_domain="
                  << (wrong_domain_rejected ? "REJECTED" : "FAIL")
                  << " generation=" << current.generation << std::endl;
        return ok;
    }

    if (phase == "resume") {
        const bool correct_persistent_state =
            current.generation == 2 &&
            (current.replay_head == branch_a ||
             current.replay_head == branch_b);
        const bool duplicate_init_rejected =
            !client.InitializeNew(record, native, registry, initial);

        AuthenticatedMpcMessageContext context;
        context.protocol_domain = PVIA_VSS_SELECTIVE_POINT_DOMAIN;
        context.sid = 0x5056455854414e43ULL;
        context.checkpoint = 0x455854414e430001ULL;
        context.round = 19;
        context.sequence = 37;
        context.message_kind = PVIA_VSS_SELECTIVE_POINT_KIND;
        const std::vector<int> helpers{1, 2, 3};
        ReferenceVssSelectiveReleasePins committed_pins;
        ReferenceVssSelectiveReleasePins pending_pins;
        const bool committed_pins_configured = client.ConfigureReleasePins(
            "/external/registry.record", "/external/replay.journal",
            current, ReferenceVssExternalAnchorResumeMode::kCommitted,
            &committed_pins);
        const bool pending_pins_configured = client.ConfigureReleasePins(
            "/external/registry.record", "/external/replay.journal",
            current, ReferenceVssExternalAnchorResumeMode::kPending,
            &pending_pins);
        const bool pins_configured = committed_pins_configured &&
            pending_pins_configured &&
            static_cast<bool>(committed_pins.authorize_committed_resume) &&
            !committed_pins.authorize_pending_resume &&
            static_cast<bool>(pending_pins.authorize_pending_resume) &&
            !pending_pins.authorize_committed_resume;
        Digest loaded_head{};
        const bool callback_reload = pins_configured &&
            pending_pins.load_current_head(&loaded_head) &&
            loaded_head == current.replay_head;
        const bool callback_pin_check = pins_configured &&
            pending_pins.verify_independent_pins(
                record, native, registry, current.replay_head) &&
            !pending_pins.verify_independent_pins(
                record, native, initial, current.replay_head);
        const bool committed_authorization = pins_configured &&
            committed_pins.authorize_committed_resume(
                context, 0, helpers, current.replay_head);
        const bool pending_authorization = pins_configured &&
            pending_pins.authorize_pending_resume(
                context, 0, helpers, current.replay_head, final_head);
        const bool callback_cas = pins_configured &&
            pending_pins.persist_new_head(current.replay_head, final_head);
        const bool stale_callback_cas = pins_configured &&
            !pending_pins.persist_new_head(current.replay_head, branch_a);
        ReferenceVssExternalAnchorSnapshot advanced;
        const bool advanced_read = client.ReadSnapshot(&advanced) &&
            advanced.generation == 3 && advanced.replay_head == final_head;
        ok = correct_persistent_state && duplicate_init_rejected &&
             pins_configured && callback_reload && callback_pin_check &&
             committed_authorization && pending_authorization &&
             callback_cas && stale_callback_cas && advanced_read;
        std::cout << "PVIA_VSS_EXTERNAL_ANCHOR_SELFTEST: "
                  << (ok ? "PASS" : "FAIL")
                  << " phase=RESUME service_restart=PASS"
                  << " generation_reload="
                  << (correct_persistent_state ? "PASS" : "FAIL")
                  << " coordinator_callbacks="
                  << (pins_configured && callback_reload &&
                      callback_pin_check ? "PASS" : "FAIL")
                  << " coordinator_resume_mode_exclusive="
                  << (pins_configured ? "PASS" : "FAIL")
                  << " signed_committed_attestation="
                  << (committed_authorization ? "PASS" : "FAIL")
                  << " signed_pending_attestation="
                  << (pending_authorization ? "PASS" : "FAIL")
                  << " remote_cas=" << (callback_cas ? "PASS" : "FAIL")
                  << " stale_cas="
                  << (stale_callback_cas ? "REJECTED" : "FAIL")
                  << " generation=" << (advanced_read ? advanced.generation : 0)
                  << std::endl;
        return ok;
    }

    const bool persisted_after_second_restart =
        current.generation == 3 && current.replay_head == final_head;
    const std::string correct_public_key =
        std::getenv("PVIA_EXTERNAL_ANCHOR_PUBLIC_KEY_HEX")
            ? std::getenv("PVIA_EXTERNAL_ANCHOR_PUBLIC_KEY_HEX") : "";
    bool bad_key_rejected = false;
    if (correct_public_key.size() == 64) {
        std::string wrong_key = correct_public_key;
        wrong_key[0] = wrong_key[0] == '0' ? '1' : '0';
        ::setenv("PVIA_EXTERNAL_ANCHOR_PUBLIC_KEY_HEX",
                 wrong_key.c_str(), 1);
        ReferenceVssExternalAnchorClient wrong_key_client;
        const bool loaded_wrong_key = wrong_key_client.LoadFromEnvironment();
        ::setenv("PVIA_EXTERNAL_ANCHOR_PUBLIC_KEY_HEX",
                 correct_public_key.c_str(), 1);
        ReferenceVssExternalAnchorSnapshot ignored;
        bad_key_rejected = loaded_wrong_key &&
            !wrong_key_client.ReadSnapshot(&ignored);
    }
    ReferenceVssExternalAnchorSnapshot stale;
    stale.record_binding = record;
    stale.native_execution_binding = native;
    stale.registry_binding = registry;
    stale.generation = 2;
    stale.replay_head = branch_a;
    const bool rollback_attempt_rejected =
        !client.CompareAndSwap(stale, branch_b, nullptr);

    // Model a prover-disk rollback: the external service advances to a
    // journal tip while a second journal copy remains at its initial head.
    // The coordinator's remote high-water and local journal then disagree,
    // so a restored local journal cannot be mistaken for the current state.
    const std::string suffix = std::to_string(static_cast<unsigned long long>(::getpid()));
    const std::string current_journal_path =
        "/tmp/pvia-external-anchor-current-" + suffix + ".journal";
    const std::string rolled_back_journal_path =
        "/tmp/pvia-external-anchor-rollback-" + suffix + ".journal";
    ReferenceVssSelectivePointDurableReplayGuard current_journal(
        current_journal_path, registry);
    ReferenceVssSelectivePointDurableReplayGuard rolled_back_journal(
        rolled_back_journal_path, registry);
    AuthenticatedMpcMessageContext journal_context;
    journal_context.protocol_domain = PVIA_VSS_SELECTIVE_POINT_DOMAIN;
    journal_context.sid = 0x50564558544a4e4cULL;
    journal_context.checkpoint = 0x4558544a4e4c0001ULL;
    journal_context.round = 29;
    journal_context.sequence = 43;
    journal_context.message_kind = PVIA_VSS_SELECTIVE_POINT_KIND;
    const std::vector<int> journal_helpers{1, 2, 3};
    Digest journal_initial{}, journal_tip{}, rolled_back_head{};
    const bool journal_batch_written =
        current_journal.InitializeNew() &&
        current_journal.ReadCurrentHead(&journal_initial) &&
        current_journal.ObserveBatchWithPinnedHead(
            journal_context, journal_helpers, 0,
            journal_initial, &journal_tip) &&
        journal_tip != Digest{};
    const bool rollback_copy_created =
        rolled_back_journal.InitializeNew() &&
        rolled_back_journal.ReadCurrentHead(&rolled_back_head) &&
        rolled_back_head == journal_initial;
    ReferenceVssExternalAnchorSnapshot before_journal_cas, after_journal_cas;
    const bool remote_journal_cas =
        journal_batch_written && rollback_copy_created &&
        client.ReadSnapshot(&before_journal_cas) &&
        before_journal_cas.generation == 3 &&
        before_journal_cas.replay_head == final_head &&
        client.CompareAndSwap(
            before_journal_cas, journal_tip, &after_journal_cas) &&
        after_journal_cas.generation == 4 &&
        after_journal_cas.replay_head == journal_tip;
    const bool local_journal_rollback_detected =
        remote_journal_cas &&
        rolled_back_head != after_journal_cas.replay_head &&
        !rolled_back_journal.VerifyCommittedBatchWithPinnedHead(
            journal_context, journal_helpers, 0,
            after_journal_cas.replay_head);
    ::unlink(current_journal_path.c_str());
    ::unlink(rolled_back_journal_path.c_str());

    ok = persisted_after_second_restart && bad_key_rejected &&
         rollback_attempt_rejected && local_journal_rollback_detected;
    std::cout << "PVIA_VSS_EXTERNAL_ANCHOR_SELFTEST: "
              << (ok ? "PASS" : "FAIL")
              << " phase=FINAL second_service_restart=PASS"
              << " persisted_generation="
              << (persisted_after_second_restart ? "PASS" : "FAIL")
              << " wrong_signing_key=" << (bad_key_rejected ? "REJECTED" : "FAIL")
              << " stale_rollback_cas="
              << (rollback_attempt_rejected ? "REJECTED" : "FAIL")
              << " local_journal_rollback="
              << (local_journal_rollback_detected ? "DETECTED" : "FAIL")
              << " generation="
              << (remote_journal_cas ? after_journal_cas.generation : current.generation)
              << " host_admin_rollback=NOT_PROTECTED" << std::endl;
    return ok;
}

} // namespace pvia
