#include "AuthenticatedMpcExchange.hpp"
#include "ExperimentMetrics.hpp"
#include "AuthenticatedMpcAbortEvidence.hpp"
#include "../../Blake/blake3.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <limits>
#include <utility>
#include <vector>

namespace pvia {
namespace {

constexpr u64 MPC_SIGNATURE_DOMAIN = AUTHENTICATED_MPC_SIGNATURE_DOMAIN;
constexpr u64 MPC_MESSAGE_DOMAIN = 0x50564d50434d5333ULL; // PVMPCMS3
constexpr u64 MPC_PAYLOAD_DOMAIN = 0x50564d5043504159ULL; // PVMPCPAY
constexpr u64 MPC_CONTEXT_DOMAIN = 0x50564d5043435458ULL; // PVMPCCTX
constexpr u64 MPC_TRANSCRIPT_DOMAIN = 0x50564d5043545232ULL; // PVMPCTR2
constexpr u64 MPC_CAP_DOMAIN = 0x50564d5043434150ULL; // PVMPCCAP
constexpr u64 MPC_IMPL_DOMAIN = 0x50564d5043494d32ULL; // PVMPCIM2
constexpr u64 MPC_PROTOCOL_ID = 0x4d50434155544833ULL; // MPCAUTH3
constexpr u64 MPC_BROADCAST_OP = 0x42524f4144434153ULL; // BROADCAS
constexpr u64 MPC_ALLGATHER_OP = 0x414c4c4741544845ULL; // ALLGATHE
constexpr u64 MPC_SCATTER_OP = 0x5343415454455232ULL; // SCATTER2
constexpr u64 MPC_SCATTER_BATCH_SIGNATURE_DOMAIN =
    0x5056534342545347ULL; // PVSCBTSG
constexpr u64 MPC_SCATTER_BATCH_ROOT_DOMAIN =
    0x5056534342545254ULL; // PVSCBTRT
constexpr u64 MPC_ALLTOALL_OP = 0x414c4c32414c4c32ULL; // ALL2ALL2
constexpr u64 MPC_ALLTOALL_RECEIVER_SUMMARY_DOMAIN =
    0x5056324153554d31ULL; // PV2ASUM1
constexpr u64 MPC_ALLTOALL_SUMMARY_STAGE = 0x41324153554d3031ULL; // A2ASUM01
constexpr u64 MPC_SELFTEST_DOMAIN = 0x50564d5043544553ULL; // PVMPCTES
constexpr u64 MPC_LEGACY_MESSAGE_KIND = 0x4c45474143594d50ULL; // LEGACYMP
constexpr u64 MPC_OBSERVATION_RECONCILE_DOMAIN =
    0x50564f4253524543ULL; // PVOBSREC
constexpr u64 MPC_LOCAL_FAILURE_DOMAIN = 0x50564d5043464149ULL; // PVMPCFAI
constexpr u64 MPC_OBSERVATION_COUNT_STAGE = 0x4f4253434e543031ULL; // OBSCNT01
constexpr u64 MPC_OBSERVATION_DATA_STAGE = 0x4f42534441543031ULL; // OBSDAT01
constexpr u64 MPC_OBSERVATION_WIRE_MAGIC = 0x4f42535749524531ULL; // OBSWIRE1
constexpr u64 MPC_OBSERVATION_WIRE_VERSION = 1ULL;
constexpr size_t MPC_OBSERVATION_WIRE_WORDS = 31;
constexpr size_t MAX_RECONCILED_OBSERVATIONS_PER_RANK = 1024;

void append_digest(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

void append_signature(
    const std::array<uint8_t, 64>& signature,
    std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < signature.size() / sizeof(u64); ++i) {
        u64 word = 0;
        std::memcpy(&word, signature.data() + i * sizeof(u64), sizeof(u64));
        words->push_back(word);
    }
}

Digest digest_from_words(const std::vector<u64>& words, size_t offset) {
    Digest digest{};
    if (offset > words.size() || words.size() - offset < 4) return digest;
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(digest.bytes.data() + 8 * i, &words[offset + i], 8);
    return digest;
}

std::array<uint8_t, 64> signature_from_words(
    const std::vector<u64>& words, size_t offset) {
    std::array<uint8_t, 64> signature{};
    if (offset > words.size() || words.size() - offset < 8) return signature;
    for (size_t i = 0; i < 8; ++i)
        std::memcpy(signature.data() + 8 * i, &words[offset + i], 8);
    return signature;
}

std::vector<u64> encode_observation(
    const AuthenticatedMpcSignedEnvelopeObservation& observation) {
    if (!observation.available || observation.payload_word_count == 0 ||
        observation.payload_binding == Digest{} ||
        observation.registry_commitment == Digest{} ||
        observation.observation_binding == Digest{})
        return {};
    std::vector<u64> words = {
        MPC_OBSERVATION_WIRE_MAGIC, MPC_OBSERVATION_WIRE_VERSION,
        observation.context.protocol_domain, observation.context.sid,
        observation.context.checkpoint, observation.context.round,
        observation.context.sequence, observation.context.message_kind,
        static_cast<u64>(observation.sender),
        static_cast<u64>(observation.receiver),
        observation.payload_word_count};
    append_digest(observation.payload_binding, &words);
    append_signature(observation.signature, &words);
    append_digest(observation.registry_commitment, &words);
    append_digest(observation.observation_binding, &words);
    return words.size() == MPC_OBSERVATION_WIRE_WORDS ? words
                                                      : std::vector<u64>{};
}

bool decode_observation(
    const std::vector<u64>& words, size_t offset,
    AuthenticatedMpcSignedEnvelopeObservation* observation) {
    if (!observation || offset > words.size() ||
        words.size() - offset < MPC_OBSERVATION_WIRE_WORDS ||
        words[offset] != MPC_OBSERVATION_WIRE_MAGIC ||
        words[offset + 1] != MPC_OBSERVATION_WIRE_VERSION ||
        words[offset + 8] > std::numeric_limits<uint32_t>::max() ||
        words[offset + 9] > std::numeric_limits<uint32_t>::max() ||
        words[offset + 10] == 0)
        return false;
    AuthenticatedMpcSignedEnvelopeObservation decoded;
    decoded.available = true;
    decoded.context.protocol_domain = words[offset + 2];
    decoded.context.sid = words[offset + 3];
    decoded.context.checkpoint = words[offset + 4];
    decoded.context.round = words[offset + 5];
    decoded.context.sequence = words[offset + 6];
    decoded.context.message_kind = words[offset + 7];
    decoded.sender = static_cast<uint32_t>(words[offset + 8]);
    decoded.receiver = static_cast<uint32_t>(words[offset + 9]);
    decoded.payload_word_count = words[offset + 10];
    decoded.payload_binding = digest_from_words(words, offset + 11);
    decoded.signature = signature_from_words(words, offset + 15);
    decoded.registry_commitment = digest_from_words(words, offset + 23);
    decoded.observation_binding = digest_from_words(words, offset + 27);
    if (!validate_authenticated_mpc_message_context(decoded.context) ||
        decoded.payload_binding == Digest{} ||
        decoded.registry_commitment == Digest{} ||
        decoded.observation_binding == Digest{})
        return false;
    *observation = std::move(decoded);
    return true;
}

AuthenticatedMpcMessageContext observation_reconciliation_subcontext(
    const AuthenticatedMpcMessageContext& base, u64 stage) {
    AuthenticatedMpcMessageContext context = base;
    context.protocol_domain = MPC_OBSERVATION_RECONCILE_DOMAIN;
    const Digest kind_binding = hash_words({
        MPC_OBSERVATION_RECONCILE_DOMAIN,
        base.protocol_domain, base.message_kind, stage});
    u64 derived_kind = 0;
    std::memcpy(&derived_kind, kind_binding.bytes.data(), sizeof(derived_kind));
    context.message_kind = derived_kind == 0 ? stage : derived_kind;
    return context;
}

AuthenticatedMpcMessageContext alltoall_summary_subcontext(
    const AuthenticatedMpcMessageContext& base) {
    AuthenticatedMpcMessageContext context = base;
    const Digest kind_binding = hash_words({
        MPC_ALLTOALL_RECEIVER_SUMMARY_DOMAIN,
        base.protocol_domain, base.message_kind,
        MPC_ALLTOALL_SUMMARY_STAGE});
    u64 derived_kind = 0;
    std::memcpy(&derived_kind, kind_binding.bytes.data(), sizeof(derived_kind));
    context.message_kind = derived_kind == 0
        ? MPC_ALLTOALL_SUMMARY_STAGE : derived_kind;
    return context;
}

Digest payload_binding_from_words(const u64* payload, size_t count) {
    if (!payload || count == 0) return Digest{};
    const u64 prefix[2] = {
        MPC_PAYLOAD_DOMAIN, static_cast<u64>(count)};
    Digest out{};
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(
        &hasher, reinterpret_cast<const uint8_t*>(prefix), sizeof(prefix));
    blake3_hasher_update(
        &hasher, reinterpret_cast<const uint8_t*>(payload),
        count * sizeof(u64));
    blake3_hasher_finalize(
        &hasher, out.bytes.data(), out.bytes.size());
    return out;
}

std::vector<u64> signed_message(
    const AuthenticatedMpcMessageContext& context,
    uint32_t sender, uint32_t receiver,
    int world_size, const std::vector<u64>& payload) {
    if (world_size <= 0 || payload.empty()) return {};
    const Digest payload_binding =
        compute_authenticated_mpc_payload_binding(payload);
    if (payload_binding == Digest{}) return {};
    return build_authenticated_mpc_signed_message(
        context, sender, receiver, static_cast<size_t>(world_size),
        static_cast<uint64_t>(payload.size()), payload_binding);
}

std::vector<u64> transcript_prefix(
    u64 op_domain,
    const AuthenticatedMpcMessageContext& context,
    int world_size,
    const AuthenticatedMpcTransportCapabilities& capabilities) {
    std::vector<u64> words = {
        MPC_TRANSCRIPT_DOMAIN, op_domain,
        static_cast<u64>(world_size)};
    append_digest(compute_authenticated_mpc_context_binding(context), &words);
    append_digest(capabilities.capability_binding, &words);
    append_digest(capabilities.registry_commitment, &words);
    append_digest(capabilities.external_registry_anchor, &words);
    return words;
}

} // namespace
Digest compute_authenticated_mpc_context_binding(
    const AuthenticatedMpcMessageContext& context) {
    if (context.protocol_domain == 0 || context.sid == 0 ||
        context.checkpoint == 0 || context.sequence == 0 ||
        context.message_kind == 0)
        return Digest{};
    return hash_words({
        MPC_CONTEXT_DOMAIN,
        context.protocol_domain,
        context.sid,
        context.checkpoint,
        context.round,
        context.sequence,
        context.message_kind});
}

bool validate_authenticated_mpc_message_context(
    const AuthenticatedMpcMessageContext& context) {
    return compute_authenticated_mpc_context_binding(context) != Digest{};
}

Digest compute_authenticated_mpc_payload_binding(
    const std::vector<u64>& payload) {
    return payload.empty()
        ? Digest{}
        : payload_binding_from_words(payload.data(), payload.size());
}

Digest compute_authenticated_mpc_local_failure_binding(
    const AuthenticatedMpcLocalFailureObservation& failure) {
    if (!failure.available ||
        failure.kind == AuthenticatedMpcLocalFailureKind::UNKNOWN)
        return Digest{};
    std::vector<u64> words = {
        MPC_LOCAL_FAILURE_DOMAIN, static_cast<u64>(failure.kind),
        failure.context.protocol_domain, failure.context.sid,
        failure.context.checkpoint, failure.context.round,
        failure.context.sequence, failure.context.message_kind,
        failure.has_claimed_sender ? 1ULL : 0ULL,
        static_cast<u64>(failure.claimed_sender),
        static_cast<u64>(failure.claimed_receiver)};
    append_digest(failure.payload_binding, &words);
    return hash_words(words);
}

std::vector<u64> build_authenticated_mpc_signed_message(
    const AuthenticatedMpcMessageContext& context,
    uint32_t sender, uint32_t receiver, size_t world_size,
    uint64_t payload_word_count, const Digest& payload_binding) {
    if (!validate_authenticated_mpc_message_context(context) ||
        world_size == 0 ||
        world_size > static_cast<size_t>(std::numeric_limits<uint32_t>::max()) ||
        sender >= world_size ||
        (receiver != AUTHENTICATED_MPC_BROADCAST_RECEIVER &&
         receiver >= world_size) || payload_word_count == 0 ||
        payload_binding == Digest{})
        return {};
    std::vector<u64> words = {
        MPC_MESSAGE_DOMAIN,
        context.protocol_domain, context.sid, context.checkpoint,
        context.round, context.sequence, context.message_kind,
        static_cast<u64>(sender), static_cast<u64>(receiver),
        static_cast<u64>(world_size), payload_word_count};
    append_digest(payload_binding, &words);
    return words;
}

Digest compute_authenticated_mpc_transport_capability_binding(
    const AuthenticatedMpcTransportCapabilities& c) {
    std::vector<u64> words = {
        MPC_CAP_DOMAIN,
        c.available ? 1ULL : 0ULL,
        c.cryptographic_authentication ? 1ULL : 0ULL,
        c.external_registry_anchor_verified ? 1ULL : 0ULL,
        c.binds_sender ? 1ULL : 0ULL,
        c.binds_receiver ? 1ULL : 0ULL,
        c.binds_checkpoint ? 1ULL : 0ULL,
        c.binds_round_sequence ? 1ULL : 0ULL,
        c.replay_protected ? 1ULL : 0ULL,
        c.payload_binding_signatures ? 1ULL : 0ULL,
        c.binds_message_kind ? 1ULL : 0ULL,
        c.protocol_id};
    append_digest(c.registry_commitment, &words);
    append_digest(c.external_registry_anchor, &words);
    append_digest(c.implementation_binding, &words);
    return hash_words(words);
}

bool validate_authenticated_mpc_transport_capabilities(
    const AuthenticatedMpcTransportCapabilities& c) {
    if (!c.available || !c.cryptographic_authentication ||
        c.protocol_id == 0 || c.registry_commitment == Digest{} ||
        c.implementation_binding == Digest{} || c.capability_binding == Digest{})
        return false;
    if (c.external_registry_anchor_verified !=
        (c.external_registry_anchor != Digest{}))
        return false;
    return c.capability_binding ==
        compute_authenticated_mpc_transport_capability_binding(c);
}

bool production_ready_authenticated_mpc_transport_capabilities(
    const AuthenticatedMpcTransportCapabilities& c) {
    return validate_authenticated_mpc_transport_capabilities(c) &&
        c.external_registry_anchor_verified &&
        c.external_registry_anchor == c.registry_commitment &&
        c.binds_sender && c.binds_receiver && c.binds_checkpoint &&
        c.binds_round_sequence && c.replay_protected &&
        c.payload_binding_signatures && c.binds_message_kind;
}

AuthenticatedMpcExchange::AuthenticatedMpcExchange(
    int rank, int world_size, MPI_Comm comm)
    : rank_(rank), world_size_(world_size), comm_(comm) {}

bool AuthenticatedMpcExchange::ready() const {
    const auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.ready() || auth.rank() != rank_ ||
        auth.world_size() != world_size_ ||
        auth.RegistryCommitment() == Digest{})
        return false;
    int comm_rank = -1;
    int comm_size = 0;
    MPI_Comm_rank(comm_, &comm_rank);
    MPI_Comm_size(comm_, &comm_size);
    return comm_rank == rank_ && comm_size == world_size_;
}

AuthenticatedMpcTransportCapabilities
AuthenticatedMpcExchange::Capabilities() const {
    AuthenticatedMpcTransportCapabilities c;
    if (!ready()) return c;
    const auto& auth = Ed25519TransferAuthenticator::instance();
    c.available = true;
    c.cryptographic_authentication = true;
    c.external_registry_anchor_verified =
        auth.ExternalRegistryAnchorVerified() &&
        auth.ExternalRegistryAnchor() == auth.RegistryCommitment();
    c.binds_sender = true;
    c.binds_receiver = true;
    c.binds_checkpoint = true;
    c.binds_round_sequence = true;
    c.replay_protected = true;
    c.payload_binding_signatures = true;
    c.binds_message_kind = true;
    c.protocol_id = MPC_PROTOCOL_ID;
    c.registry_commitment = auth.RegistryCommitment();
    c.external_registry_anchor = c.external_registry_anchor_verified
        ? auth.ExternalRegistryAnchor() : Digest{};
    c.implementation_binding = hash_words({MPC_IMPL_DOMAIN, 5ULL});
    c.capability_binding =
        compute_authenticated_mpc_transport_capability_binding(c);
    return c;
}

bool AuthenticatedMpcExchange::production_authenticated_ready() const {
    return production_ready_authenticated_mpc_transport_capabilities(
        Capabilities());
}

Digest AuthenticatedMpcExchange::ProductionCapabilityBinding() const {
    const auto capabilities = Capabilities();
    return production_ready_authenticated_mpc_transport_capabilities(capabilities)
        ? capabilities.capability_binding : Digest{};
}

void AuthenticatedMpcExchange::RecordLocalFailure(
    AuthenticatedMpcLocalFailureKind kind,
    const AuthenticatedMpcMessageContext& context,
    bool has_claimed_sender, uint32_t claimed_sender,
    uint32_t claimed_receiver, const Digest& payload_binding) const {
    if (kind == AuthenticatedMpcLocalFailureKind::UNKNOWN) return;
    AuthenticatedMpcLocalFailureObservation failure;
    failure.available = true;
    failure.kind = kind;
    failure.context = context;
    failure.has_claimed_sender = has_claimed_sender;
    failure.claimed_sender = claimed_sender;
    failure.claimed_receiver = claimed_receiver;
    failure.payload_binding = payload_binding;
    failure.failure_binding =
        compute_authenticated_mpc_local_failure_binding(failure);
    if (failure.failure_binding == Digest{}) return;
    constexpr size_t MAX_LOCAL_FAILURES = 256;
    if (local_failures_.size() >= MAX_LOCAL_FAILURES)
        local_failures_.erase(local_failures_.begin());
    local_failures_.push_back(std::move(failure));
}

bool AuthenticatedMpcExchange::SameContextOnAllRanks(
    const AuthenticatedMpcMessageContext& context) const {
    if (!ready()) return false;
    if (!validate_authenticated_mpc_message_context(context)) {
        RecordLocalFailure(AuthenticatedMpcLocalFailureKind::INVALID_CONTEXT,
                           context);
        return false;
    }
    if (CheckpointRetired(context.sid, context.checkpoint)) {
        RecordLocalFailure(AuthenticatedMpcLocalFailureKind::RETIRED_CHECKPOINT,
                           context);
        return false;
    }
    const Digest binding = compute_authenticated_mpc_context_binding(context);
    std::vector<uint8_t> gathered(
        static_cast<size_t>(world_size_) * binding.bytes.size());
    MPI_Allgather(binding.bytes.data(), static_cast<int>(binding.bytes.size()),
                  MPI_BYTE, gathered.data(),
                  static_cast<int>(binding.bytes.size()), MPI_BYTE, comm_);
    for (int i = 0; i < world_size_; ++i) {
        const uint8_t* begin = gathered.data() +
            static_cast<size_t>(i) * binding.bytes.size();
        if (!std::equal(binding.bytes.begin(), binding.bytes.end(), begin)) {
            RecordLocalFailure(
                AuthenticatedMpcLocalFailureKind::CONTEXT_DISAGREEMENT, context);
            return false;
        }
    }
    return true;
}

bool AuthenticatedMpcExchange::ObserveVerifiedEnvelope(
    const AuthenticatedMpcMessageContext& context,
    uint32_t sender, uint32_t receiver,
    const std::vector<u64>& payload,
    const std::array<uint8_t, 64>& signature) const {
    const Digest local_payload_binding =
        compute_authenticated_mpc_payload_binding(payload);
    if (!validate_authenticated_mpc_message_context(context) ||
        payload.empty() || sender >= static_cast<uint32_t>(world_size_) ||
        (receiver != BROADCAST_RECEIVER &&
         receiver >= static_cast<uint32_t>(world_size_))) {
        RecordLocalFailure(AuthenticatedMpcLocalFailureKind::MALFORMED_ENVELOPE,
            context, true, sender, receiver, local_payload_binding);
        return false;
    }
    const auto& auth = Ed25519TransferAuthenticator::instance();
    const std::vector<u64> message =
        build_authenticated_mpc_signed_message(
            context, sender, receiver,
            static_cast<size_t>(world_size_),
            static_cast<uint64_t>(payload.size()),
            local_payload_binding);
    if (message.empty()) {
        RecordLocalFailure(AuthenticatedMpcLocalFailureKind::MALFORMED_ENVELOPE,
            context, true, sender, receiver, local_payload_binding);
        return false;
    }
    if (!auth.VerifyWords(MPC_SIGNATURE_DOMAIN, message, signature, sender)) {
        RecordLocalFailure(AuthenticatedMpcLocalFailureKind::INVALID_SIGNATURE,
            context, true, sender, receiver, local_payload_binding);
        return false;
    }

    const Digest context_binding =
        compute_authenticated_mpc_context_binding(context);

    // First classify an exact logical-context reuse. Two different valid
    // payloads are attributable signed equivocation. Replaying the identical
    // valid envelope is rejected, but deliberately does not create blame.
    for (const auto& previous : verified_envelopes_) {
        const auto& pctx = previous.context;
        const bool same_context =
            pctx.protocol_domain == context.protocol_domain &&
            pctx.sid == context.sid && pctx.checkpoint == context.checkpoint &&
            pctx.round == context.round && pctx.sequence == context.sequence &&
            pctx.message_kind == context.message_kind;
        if (!same_context || previous.context_binding != context_binding ||
            previous.sender != sender || previous.receiver != receiver)
            continue;
        if (previous.payload_word_count ==
                static_cast<uint64_t>(payload.size()) &&
            previous.payload_binding == local_payload_binding) {
            RecordLocalFailure(AuthenticatedMpcLocalFailureKind::EXACT_REPLAY,
                context, true, sender, receiver, local_payload_binding);
            return false;
        }
        VerifiedEnvelopeRecord conflicting{
            context_binding, context, sender, receiver,
            static_cast<uint64_t>(payload.size()),
            local_payload_binding, signature};
        // One conflicting pair is sufficient for public attribution. Keep at
        // most one pending certificate per logical context/sender/receiver so
        // a malicious signer cannot amplify memory use by signing many
        // alternate payloads for the same context.
        const auto existing = std::find_if(
            pending_equivocations_.begin(), pending_equivocations_.end(),
            [&](const PendingEquivocationRecord& pending) {
                return pending.first.context_binding == previous.context_binding &&
                    pending.first.sender == previous.sender &&
                    pending.first.receiver == previous.receiver;
            });
        if (existing == pending_equivocations_.end())
            pending_equivocations_.push_back(
                PendingEquivocationRecord{previous, std::move(conflicting)});
        RecordLocalFailure(AuthenticatedMpcLocalFailureKind::SIGNED_EQUIVOCATION,
            context, true, sender, receiver, local_payload_binding);
        return false;
    }

    // Enforce freshness only after signature verification and equivocation
    // classification. Sequence numbers are strictly increasing within a
    // protocol/session/checkpoint/round/message-kind/sender/receiver stream.
    // An old sequence is rejected as replay/stale traffic, never as blame.
    SequenceHighWaterRecord* high_water = nullptr;
    for (auto& record : sequence_high_water_) {
        if (record.protocol_domain == context.protocol_domain &&
            record.sid == context.sid &&
            record.checkpoint == context.checkpoint &&
            record.round == context.round &&
            record.message_kind == context.message_kind &&
            record.sender == sender && record.receiver == receiver) {
            high_water = &record;
            break;
        }
    }
    if (high_water) {
        if (context.sequence <= high_water->max_sequence) {
            RecordLocalFailure(
                AuthenticatedMpcLocalFailureKind::SEQUENCE_REGRESSION,
                context, true, sender, receiver, local_payload_binding);
            return false;
        }
        high_water->max_sequence = context.sequence;
    } else {
        sequence_high_water_.push_back(SequenceHighWaterRecord{
            context.protocol_domain, context.sid, context.checkpoint,
            context.round, context.message_kind,
            sender, receiver, context.sequence});
    }

    verified_envelopes_.push_back(VerifiedEnvelopeRecord{
        context_binding, context, sender, receiver,
        static_cast<uint64_t>(payload.size()),
        local_payload_binding, signature});
    return true;
}

bool AuthenticatedMpcExchange::LastEquivocationEvidence(
    AuthenticatedMpcEquivocationEvidence* evidence) const {
    if (!evidence || pending_equivocations_.empty()) return false;
    const PendingEquivocationRecord& pending = pending_equivocations_.back();
    return LastEquivocationEvidence(
        pending.first.context.sid, pending.first.context.checkpoint, evidence);
}

bool AuthenticatedMpcExchange::LastEquivocationEvidence(
    uint64_t sid, CheckpointId checkpoint,
    AuthenticatedMpcEquivocationEvidence* evidence) const {
    if (!evidence || sid == 0 || checkpoint == 0) return false;
    const auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.ready() || auth.RegistryCommitment() == Digest{}) return false;

    auto observation_from_record = [&](const VerifiedEnvelopeRecord& record) {
        AuthenticatedMpcSignedEnvelopeObservation observation;
        observation.available = true;
        observation.context = record.context;
        observation.sender = record.sender;
        observation.receiver = record.receiver;
        observation.payload_word_count = record.payload_word_count;
        observation.payload_binding = record.payload_binding;
        observation.signature = record.signature;
        observation.registry_commitment = auth.RegistryCommitment();
        observation.observation_binding =
            compute_authenticated_mpc_signed_envelope_observation_binding(
                observation);
        return observation;
    };
    for (auto it = pending_equivocations_.rbegin();
         it != pending_equivocations_.rend(); ++it) {
        if (it->first.context.sid != sid ||
            it->first.context.checkpoint != checkpoint ||
            it->second.context.sid != sid ||
            it->second.context.checkpoint != checkpoint ||
            it->first.payload_word_count == 0 ||
            it->second.payload_word_count == 0 ||
            it->first.payload_binding == Digest{} ||
            it->second.payload_binding == Digest{})
            continue;
        const auto first = observation_from_record(it->first);
        const auto second = observation_from_record(it->second);
        if (combine_authenticated_mpc_equivocation_observations(
                first, second, auth.PublicKeys(),
                auth.RegistryCommitment(), evidence))
            return true;
    }
    return false;
}

bool AuthenticatedMpcExchange::ExportVerifiedEnvelopeObservations(
    uint64_t sid, CheckpointId checkpoint,
    std::vector<AuthenticatedMpcSignedEnvelopeObservation>* observations) const {
    if (!observations || sid == 0 || checkpoint == 0 ||
        CheckpointRetired(sid, checkpoint))
        return false;
    observations->clear();
    const auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.ready() || auth.RegistryCommitment() == Digest{}) return false;

    auto append_record = [&](const VerifiedEnvelopeRecord& record,
                             bool allow_reconciliation_control) -> bool {
        if (record.context.sid != sid ||
            record.context.checkpoint != checkpoint ||
            record.payload_word_count == 0 ||
            record.payload_binding == Digest{} ||
            (!allow_reconciliation_control &&
             record.context.protocol_domain ==
                 MPC_OBSERVATION_RECONCILE_DOMAIN))
            return true;
        AuthenticatedMpcSignedEnvelopeObservation observation;
        observation.available = true;
        observation.context = record.context;
        observation.sender = record.sender;
        observation.receiver = record.receiver;
        observation.payload_word_count = record.payload_word_count;
        observation.payload_binding = record.payload_binding;
        observation.signature = record.signature;
        observation.registry_commitment = auth.RegistryCommitment();
        observation.observation_binding =
            compute_authenticated_mpc_signed_envelope_observation_binding(
                observation);
        if (observation.observation_binding == Digest{} ||
            !verify_authenticated_mpc_signed_envelope_observation(
                observation, auth.PublicKeys(), auth.RegistryCommitment()))
            return false;
        const auto duplicate = std::find_if(
            observations->begin(), observations->end(),
            [&](const AuthenticatedMpcSignedEnvelopeObservation& previous) {
                return previous.observation_binding ==
                    observation.observation_binding;
            });
        if (duplicate == observations->end())
            observations->push_back(std::move(observation));
        return true;
    };

    for (const auto& record : verified_envelopes_)
        if (!append_record(record, false)) return false;
    for (const auto& pending : pending_equivocations_) {
        if ((pending.first.context.sid == sid &&
             pending.first.context.checkpoint == checkpoint) ||
            (pending.second.context.sid == sid &&
             pending.second.context.checkpoint == checkpoint)) {
            if (!append_record(pending.first, true) ||
                !append_record(pending.second, true))
                return false;
        }
    }
    return !observations->empty();
}

bool AuthenticatedMpcExchange::ExportVerifiedEnvelopeShapeTrace(
    uint64_t sid, CheckpointId checkpoint,
    AuthenticatedMpcEnvelopeShapeTrace* trace) const {
    if(!trace)return false;
    *trace={};
    if(sid==0 || checkpoint==0 || CheckpointRetired(sid,checkpoint))
        return false;
    // Every accepted record has already passed Ed25519 verification,
    // context freshness and replay/equivocation checks in ObserveVerifiedEnvelope.
    // This routine MUST NOT export the payload hash or signature: even such
    // opaque values may correlate to a private operation or statement.
    constexpr u64 SHAPE_DOMAIN=0x5056313035545243ULL; // PV105TRC
    using ShapeRow=std::array<u64,7>;
    std::vector<ShapeRow> rows;
    rows.reserve(verified_envelopes_.size());
    for(const auto& record:verified_envelopes_){
        const auto& ctx=record.context;
        if(ctx.sid!=sid || ctx.checkpoint!=checkpoint)continue;
        if(record.payload_word_count==0 ||
           record.context_binding==Digest{} ||
           record.payload_binding==Digest{})return false;
        rows.push_back({ctx.protocol_domain,ctx.checkpoint,
                        ctx.round,ctx.sequence,ctx.message_kind,
                        (static_cast<u64>(record.sender)<<32) |
                        static_cast<u64>(record.receiver),
                        record.payload_word_count});
    }
    if(rows.empty())return false;
    const auto bind_rows=[&](const std::vector<ShapeRow>& ordered){
        std::vector<u64> words;
        words.reserve(2+ordered.size()*7);
        words.push_back(SHAPE_DOMAIN);
        words.push_back(static_cast<u64>(ordered.size()));
        for(const auto& row:ordered)
            words.insert(words.end(),row.begin(),row.end());
        return hash_words(words);
    };
    const Digest received=bind_rows(rows);
    std::sort(rows.begin(),rows.end());
    const Digest canonical=bind_rows(rows);
    if(received==Digest{} || canonical==Digest{})return false;
    trace->available=true;
    trace->verified_messages=static_cast<uint64_t>(rows.size());
    trace->arrival_order_binding=received;
    trace->canonical_multiset_binding=canonical;
    return true;
}

bool AuthenticatedMpcExchange::ReconcileCheckpointObservations(
    const AuthenticatedMpcMessageContext& reconciliation_context,
    uint64_t sid, CheckpointId checkpoint,
    AuthenticatedMpcObservationReconciliation* reconciliation,
    Digest* transcript_binding) const {
    if (!reconciliation || sid == 0 || checkpoint == 0 ||
        !validate_authenticated_mpc_message_context(reconciliation_context) ||
        reconciliation_context.sid != sid ||
        reconciliation_context.checkpoint != checkpoint ||
        CheckpointRetired(sid, checkpoint) ||
        !production_authenticated_ready())
        return false;
    *reconciliation = AuthenticatedMpcObservationReconciliation{};
    if (transcript_binding) *transcript_binding = Digest{};

    bool has_local_records = false;
    for (const auto& record : verified_envelopes_) {
        if (record.context.sid == sid &&
            record.context.checkpoint == checkpoint &&
            record.context.protocol_domain != MPC_OBSERVATION_RECONCILE_DOMAIN) {
            has_local_records = true;
            break;
        }
    }
    if (!has_local_records) {
        for (const auto& pending : pending_equivocations_) {
            if ((pending.first.context.sid == sid &&
                 pending.first.context.checkpoint == checkpoint) ||
                (pending.second.context.sid == sid &&
                 pending.second.context.checkpoint == checkpoint)) {
                has_local_records = true;
                break;
            }
        }
    }

    std::vector<AuthenticatedMpcSignedEnvelopeObservation> local_observations;
    if (has_local_records &&
        !ExportVerifiedEnvelopeObservations(
            sid, checkpoint, &local_observations))
        return false;
    if (local_observations.size() > MAX_RECONCILED_OBSERVATIONS_PER_RANK)
        return false;

    const AuthenticatedMpcMessageContext count_context =
        observation_reconciliation_subcontext(
            reconciliation_context, MPC_OBSERVATION_COUNT_STAGE);
    std::vector<u64> gathered_counts;
    Digest count_transport_binding{};
    if (!AllGatherWords(
            count_context,
            {static_cast<u64>(local_observations.size())},
            &gathered_counts, &count_transport_binding) ||
        gathered_counts.size() != static_cast<size_t>(world_size_) ||
        count_transport_binding == Digest{})
        return false;

    size_t max_count = 0;
    for (u64 count : gathered_counts) {
        if (count > MAX_RECONCILED_OBSERVATIONS_PER_RANK ||
            count > static_cast<u64>(std::numeric_limits<size_t>::max()))
            return false;
        max_count = std::max(max_count, static_cast<size_t>(count));
    }
    if (max_count == 0 ||
        max_count > std::numeric_limits<size_t>::max() /
                        MPC_OBSERVATION_WIRE_WORDS)
        return false;
    const size_t words_per_rank =
        max_count * MPC_OBSERVATION_WIRE_WORDS;
    if (world_size_ <= 0 ||
        words_per_rank > static_cast<size_t>(std::numeric_limits<int>::max()) ||
        words_per_rank > std::numeric_limits<size_t>::max() /
                             static_cast<size_t>(world_size_))
        return false;
    const size_t expected_wire_words =
        static_cast<size_t>(world_size_) * words_per_rank;

    std::vector<u64> local_wire(words_per_rank, 0ULL);
    for (size_t i = 0; i < local_observations.size(); ++i) {
        const std::vector<u64> encoded = encode_observation(local_observations[i]);
        if (encoded.size() != MPC_OBSERVATION_WIRE_WORDS) return false;
        std::copy(encoded.begin(), encoded.end(),
                  local_wire.begin() +
                      static_cast<std::ptrdiff_t>(
                          i * MPC_OBSERVATION_WIRE_WORDS));
    }

    const AuthenticatedMpcMessageContext data_context =
        observation_reconciliation_subcontext(
            reconciliation_context, MPC_OBSERVATION_DATA_STAGE);
    std::vector<u64> gathered_wire;
    Digest data_transport_binding{};
    if (!AllGatherWords(
            data_context, local_wire, &gathered_wire,
            &data_transport_binding) ||
        gathered_wire.size() != expected_wire_words ||
        data_transport_binding == Digest{})
        return false;

    std::vector<AuthenticatedMpcSignedEnvelopeObservation> merged;
    for (int participant = 0; participant < world_size_; ++participant) {
        const size_t declared =
            static_cast<size_t>(gathered_counts[static_cast<size_t>(participant)]);
        const size_t participant_base =
            static_cast<size_t>(participant) * words_per_rank;
        for (size_t i = 0; i < declared; ++i) {
            AuthenticatedMpcSignedEnvelopeObservation observation;
            const size_t offset = participant_base +
                i * MPC_OBSERVATION_WIRE_WORDS;
            if (!decode_observation(gathered_wire, offset, &observation) ||
                observation.context.sid != sid ||
                observation.context.checkpoint != checkpoint) {
                // Preserve one invalid placeholder so reconciliation records
                // malformed or cross-namespace contributions as rejected
                // rather than silently dropping them or contaminating this
                // checkpoint's evidence set.
                merged.push_back(
                    AuthenticatedMpcSignedEnvelopeObservation{});
                continue;
            }
            merged.push_back(std::move(observation));
        }
    }
    if (merged.empty()) return false;

    const auto& auth = Ed25519TransferAuthenticator::instance();
    const auto reconciled = reconcile_authenticated_mpc_observations(
        merged, auth.PublicKeys(), auth.ExternalRegistryAnchor());
    if (!reconciled.valid || reconciled.observation_set_binding == Digest{})
        return false;
    *reconciliation = reconciled;

    if (transcript_binding) {
        std::vector<u64> transcript_words = {
            MPC_OBSERVATION_RECONCILE_DOMAIN,
            sid, checkpoint, reconciliation_context.round,
            reconciliation_context.sequence,
            static_cast<u64>(world_size_),
            static_cast<u64>(reconciled.input_count),
            static_cast<u64>(reconciled.accepted_count),
            static_cast<u64>(reconciled.rejected_count),
            static_cast<u64>(reconciled.duplicate_count),
            reconciled.equivocation_found ? 1ULL : 0ULL};
        append_digest(count_transport_binding, &transcript_words);
        append_digest(data_transport_binding, &transcript_words);
        append_digest(reconciled.observation_set_binding, &transcript_words);
        append_digest(reconciled.evidence.evidence_binding, &transcript_words);
        for (u64 count : gathered_counts) transcript_words.push_back(count);
        *transcript_binding = hash_words(transcript_words);
        if (*transcript_binding == Digest{}) return false;
    }
    return true;
}

bool AuthenticatedMpcExchange::AcknowledgeEquivocationEvidence(
    uint64_t sid, CheckpointId checkpoint,
    const Digest& evidence_binding) const {
    if (sid == 0 || checkpoint == 0 || evidence_binding == Digest{})
        return false;
    const auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.ready() || auth.RegistryCommitment() == Digest{}) return false;

    auto observation_from_record = [&](const VerifiedEnvelopeRecord& record) {
        AuthenticatedMpcSignedEnvelopeObservation observation;
        observation.available = true;
        observation.context = record.context;
        observation.sender = record.sender;
        observation.receiver = record.receiver;
        observation.payload_word_count = record.payload_word_count;
        observation.payload_binding = record.payload_binding;
        observation.signature = record.signature;
        observation.registry_commitment = auth.RegistryCommitment();
        observation.observation_binding =
            compute_authenticated_mpc_signed_envelope_observation_binding(
                observation);
        return observation;
    };

    for (auto it = pending_equivocations_.begin();
         it != pending_equivocations_.end(); ++it) {
        if (it->first.context.sid != sid ||
            it->first.context.checkpoint != checkpoint ||
            it->second.context.sid != sid ||
            it->second.context.checkpoint != checkpoint)
            continue;
        AuthenticatedMpcEquivocationEvidence evidence;
        const auto first = observation_from_record(it->first);
        const auto second = observation_from_record(it->second);
        if (!combine_authenticated_mpc_equivocation_observations(
                first, second, auth.PublicKeys(),
                auth.RegistryCommitment(), &evidence))
            continue;
        if (evidence.evidence_binding != evidence_binding) continue;
        pending_equivocations_.erase(it);
        return true;
    }
    return false;
}

bool AuthenticatedMpcExchange::LastLocalFailure(
    AuthenticatedMpcLocalFailureObservation* failure) const {
    if (!failure || local_failures_.empty()) return false;
    *failure = local_failures_.back();
    return failure->available && failure->failure_binding != Digest{} &&
        failure->failure_binding ==
            compute_authenticated_mpc_local_failure_binding(*failure);
}

bool AuthenticatedMpcExchange::LastLocalFailure(
    uint64_t sid, CheckpointId checkpoint,
    AuthenticatedMpcLocalFailureObservation* failure) const {
    if (!failure || sid == 0 || checkpoint == 0) return false;
    for (auto it = local_failures_.rbegin(); it != local_failures_.rend(); ++it) {
        if (it->context.sid != sid || it->context.checkpoint != checkpoint)
            continue;
        *failure = *it;
        return failure->available && failure->failure_binding != Digest{} &&
            failure->failure_binding ==
                compute_authenticated_mpc_local_failure_binding(*failure);
    }
    return false;
}

void AuthenticatedMpcExchange::ClearLocalFailures() const {
    local_failures_.clear();
}

void AuthenticatedMpcExchange::ClearEquivocationEvidence() const {
    verified_envelopes_.clear();
    pending_equivocations_.clear();
}

bool AuthenticatedMpcExchange::CheckpointRetired(
    uint64_t sid, CheckpointId checkpoint) const {
    if (sid == 0 || checkpoint == 0) return false;
    return std::find_if(retired_checkpoints_.begin(), retired_checkpoints_.end(),
        [&](const RetiredCheckpointNamespace& retired) {
            return retired.sid == sid && retired.checkpoint == checkpoint;
        }) != retired_checkpoints_.end();
}

bool AuthenticatedMpcExchange::RetireCheckpoint(
    uint64_t sid, CheckpointId checkpoint) const {
    if (sid == 0 || checkpoint == 0) return false;
    if (CheckpointRetired(sid, checkpoint)) return true;
    const auto pending = std::find_if(
        pending_equivocations_.begin(), pending_equivocations_.end(),
        [sid, checkpoint](const PendingEquivocationRecord& record) {
            return (record.first.context.sid == sid &&
                    record.first.context.checkpoint == checkpoint) ||
                   (record.second.context.sid == sid &&
                    record.second.context.checkpoint == checkpoint);
        });
    if (pending != pending_equivocations_.end()) return false;

    verified_envelopes_.erase(
        std::remove_if(verified_envelopes_.begin(), verified_envelopes_.end(),
            [sid, checkpoint](const VerifiedEnvelopeRecord& record) {
                return record.context.sid == sid &&
                    record.context.checkpoint == checkpoint;
            }),
        verified_envelopes_.end());
    sequence_high_water_.erase(
        std::remove_if(sequence_high_water_.begin(), sequence_high_water_.end(),
            [sid, checkpoint](const SequenceHighWaterRecord& record) {
                return record.sid == sid && record.checkpoint == checkpoint;
            }),
        sequence_high_water_.end());
    local_failures_.erase(
        std::remove_if(local_failures_.begin(), local_failures_.end(),
            [sid, checkpoint](const AuthenticatedMpcLocalFailureObservation& f) {
                return f.context.sid == sid && f.context.checkpoint == checkpoint;
            }),
        local_failures_.end());
    retired_checkpoints_.push_back(
        RetiredCheckpointNamespace{sid, checkpoint});
    return true;
}

bool AuthenticatedMpcExchange::BroadcastWords(
    const AuthenticatedMpcMessageContext& context,
    int broadcaster,
    const std::vector<u64>& broadcaster_payload,
    std::vector<u64>* payload,
    Digest* transcript_binding) const {
    if (!payload || broadcaster < 0 || broadcaster >= world_size_ ||
        !SameContextOnAllRanks(context))
        return false;
    u64 count = rank_ == broadcaster
        ? static_cast<u64>(broadcaster_payload.size()) : 0ULL;
    MPI_Bcast(&count, 1, MPI_UINT64_T, broadcaster, comm_);
    if (count == 0 || count > static_cast<u64>(std::numeric_limits<int>::max()))
        return false;
    if (rank_ == broadcaster) {
        if (broadcaster_payload.size() != static_cast<size_t>(count))
            return false;
        *payload = broadcaster_payload;
    } else {
        payload->resize(static_cast<size_t>(count));
    }

    const auto& auth = Ed25519TransferAuthenticator::instance();
    std::array<uint8_t, 64> signature{};
    if (rank_ == broadcaster) {
        const std::vector<u64> message = signed_message(
            context, static_cast<uint32_t>(broadcaster), BROADCAST_RECEIVER,
            world_size_, *payload);
        if (message.empty() ||
            !auth.SignWords(MPC_SIGNATURE_DOMAIN, message, &signature))
            return false;
    }
    MPI_Bcast(payload->data(), static_cast<int>(count), MPI_UINT64_T,
              broadcaster, comm_);
    MPI_Bcast(signature.data(), static_cast<int>(signature.size()),
              MPI_UNSIGNED_CHAR, broadcaster, comm_);
    const uint64_t logical_envelope_bytes =
        count * sizeof(u64) + signature.size();
    experiment_increment_authenticated_collective();
    const uint64_t broadcast_peers =
        static_cast<uint64_t>(world_size_ - 1);
    const uint64_t broadcast_payload_bytes =
        count * sizeof(u64);
    if (rank_ == broadcaster) {
        experiment_add_authenticated_envelope_traffic(
            logical_envelope_bytes * broadcast_peers,
            0, broadcast_peers, 0);
        experiment_add_authenticated_traffic_breakdown(
            broadcast_payload_bytes * broadcast_peers, 0,
            signature.size() * broadcast_peers, 0, false);
    } else {
        experiment_add_authenticated_envelope_traffic(
            0, logical_envelope_bytes, 0, 1);
        experiment_add_authenticated_traffic_breakdown(
            0, broadcast_payload_bytes, 0, signature.size(), false);
    }

    const std::vector<u64> received_message = signed_message(
        context, static_cast<uint32_t>(broadcaster), BROADCAST_RECEIVER,
        world_size_, *payload);
    if (received_message.empty() ||
        !ObserveVerifiedEnvelope(
            context, static_cast<uint32_t>(broadcaster), BROADCAST_RECEIVER,
            *payload, signature))
        return false;
    if (transcript_binding) {
        const auto capabilities = Capabilities();
        std::vector<u64> words = transcript_prefix(
            MPC_BROADCAST_OP, context, world_size_, capabilities);
        words.push_back(static_cast<u64>(broadcaster));
        words.push_back(BROADCAST_RECEIVER);
        append_digest(auth.PublicKeyId(static_cast<uint32_t>(broadcaster)),
                      &words);
        append_signature(signature, &words);
        words.push_back(count);
        words.insert(words.end(), payload->begin(), payload->end());
        *transcript_binding = hash_words(words);
        if (*transcript_binding == Digest{}) return false;
    }
    return true;
}

bool AuthenticatedMpcExchange::AllGatherWords(
    const AuthenticatedMpcMessageContext& context,
    const std::vector<u64>& local_payload,
    std::vector<u64>* all_payloads,
    Digest* transcript_binding) const {
    if (!all_payloads || local_payload.empty() ||
        local_payload.size() > static_cast<size_t>(std::numeric_limits<int>::max()) ||
        !SameContextOnAllRanks(context))
        return false;

    const u64 local_count = static_cast<u64>(local_payload.size());
    std::vector<u64> counts(static_cast<size_t>(world_size_));
    MPI_Allgather(&local_count, 1, MPI_UINT64_T,
                  counts.data(), 1, MPI_UINT64_T, comm_);
    for (u64 count : counts)
        if (count != local_count) return false;

    const auto& auth = Ed25519TransferAuthenticator::instance();
    const std::vector<u64> local_message = signed_message(
        context, static_cast<uint32_t>(rank_), BROADCAST_RECEIVER,
        world_size_, local_payload);
    if (local_message.empty()) return false;
    std::array<uint8_t, 64> local_signature{};
    if (!auth.SignWords(MPC_SIGNATURE_DOMAIN, local_message, &local_signature))
        return false;

    const int payload_count = static_cast<int>(local_payload.size());
    all_payloads->resize(
        static_cast<size_t>(world_size_) * local_payload.size());
    MPI_Allgather(local_payload.data(), payload_count, MPI_UINT64_T,
                  all_payloads->data(), payload_count, MPI_UINT64_T, comm_);
    std::vector<uint8_t> signatures(
        static_cast<size_t>(world_size_) * local_signature.size());
    MPI_Allgather(local_signature.data(), static_cast<int>(local_signature.size()),
                  MPI_UNSIGNED_CHAR, signatures.data(),
                  static_cast<int>(local_signature.size()),
                  MPI_UNSIGNED_CHAR, comm_);
    const uint64_t logical_envelope_bytes =
        static_cast<uint64_t>(local_payload.size() * sizeof(u64) +
                              local_signature.size());
    const uint64_t peer_count = static_cast<uint64_t>(world_size_ - 1);
    experiment_increment_authenticated_collective();
    experiment_add_authenticated_envelope_traffic(
        logical_envelope_bytes * peer_count,
        logical_envelope_bytes * peer_count, peer_count, peer_count);
    const uint64_t gathered_payload_bytes =
        static_cast<uint64_t>(local_payload.size() * sizeof(u64)) *
        peer_count;
    const uint64_t gathered_overhead_bytes =
        static_cast<uint64_t>(local_signature.size()) * peer_count;
    experiment_add_authenticated_traffic_breakdown(
        gathered_payload_bytes, gathered_payload_bytes,
        gathered_overhead_bytes, gathered_overhead_bytes, false);

    const auto capabilities = Capabilities();
    std::vector<u64> transcript_words = transcript_prefix(
        MPC_ALLGATHER_OP, context, world_size_, capabilities);
    for (int sender = 0; sender < world_size_; ++sender) {
        const size_t payload_offset =
            static_cast<size_t>(sender) * local_payload.size();
        std::vector<u64> payload(
            all_payloads->begin() + static_cast<std::ptrdiff_t>(payload_offset),
            all_payloads->begin() + static_cast<std::ptrdiff_t>(
                payload_offset + local_payload.size()));
        const std::vector<u64> message = signed_message(
            context, static_cast<uint32_t>(sender), BROADCAST_RECEIVER,
            world_size_, payload);
        std::array<uint8_t, 64> signature{};
        std::memcpy(signature.data(),
            signatures.data() + static_cast<size_t>(sender) * signature.size(),
            signature.size());
        if (message.empty() ||
            !ObserveVerifiedEnvelope(
                context, static_cast<uint32_t>(sender), BROADCAST_RECEIVER,
                payload, signature))
            return false;
        transcript_words.push_back(static_cast<u64>(sender));
        transcript_words.push_back(BROADCAST_RECEIVER);
        append_digest(auth.PublicKeyId(static_cast<uint32_t>(sender)),
                      &transcript_words);
        append_signature(signature, &transcript_words);
        transcript_words.push_back(static_cast<u64>(payload.size()));
        transcript_words.insert(
            transcript_words.end(), payload.begin(), payload.end());
    }

    const Digest transcript = hash_words(transcript_words);
    if (transcript == Digest{}) return false;
    if (transcript_binding) *transcript_binding = transcript;
    return true;
}

bool AuthenticatedMpcExchange::AllTrue(
    const AuthenticatedMpcMessageContext& context,
    bool local_value, bool* all_true,
    Digest* transcript_binding) const {
    if (!all_true) return false;
    std::vector<u64> gathered;
    Digest transcript{};
    if (!AllGatherWords(
            context, {local_value ? 1ULL : 0ULL},
            &gathered, &transcript) ||
        gathered.size() != static_cast<size_t>(world_size_))
        return false;
    bool value = true;
    for (u64 word : gathered) {
        if (word > 1) return false;
        value = value && word != 0;
    }
    *all_true = value;
    if (transcript_binding) *transcript_binding = transcript;
    return true;
}

bool AuthenticatedMpcExchange::ScatterWords(
    const AuthenticatedMpcMessageContext& context,
    int dealer, const std::vector<u64>& dealer_payloads,
    size_t words_per_receiver, std::vector<u64>* received_payload,
    Digest* transcript_binding) const {
    if (!received_payload || dealer < 0 || dealer >= world_size_ ||
        words_per_receiver == 0 ||
        words_per_receiver >
            static_cast<size_t>(std::numeric_limits<int>::max()) ||
        (rank_ == dealer
             ? dealer_payloads.size() !=
                   static_cast<size_t>(world_size_) * words_per_receiver
             : !dealer_payloads.empty()) ||
        !SameContextOnAllRanks(context))
        return false;

    const auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.ready() || auth.RegistryCommitment() == Digest{})
        return false;

    // Scatter is a one-dealer operation.  The previous implementation reused
    // AllToAllWords, which forced every non-dealer to transmit a full-size
    // zero payload to every peer.  We instead authenticate only the N
    // dealer->receiver payloads and bind all of them to one signed batch root.
    std::vector<uint8_t> dealer_signatures(
        static_cast<size_t>(world_size_) * 64, 0);
    std::vector<u64> leaf_words(
        static_cast<size_t>(world_size_) * 4, 0);
    std::array<uint8_t, 64> batch_signature{};

    if (rank_ == dealer) {
        for (int receiver = 0; receiver < world_size_; ++receiver) {
            const size_t offset =
                static_cast<size_t>(receiver) * words_per_receiver;
            const u64* payload =
                dealer_payloads.data() + offset;
            const Digest payload_binding =
                payload_binding_from_words(payload, words_per_receiver);
            const std::vector<u64> message =
                build_authenticated_mpc_signed_message(
                    context, static_cast<uint32_t>(dealer),
                    static_cast<uint32_t>(receiver),
                    static_cast<size_t>(world_size_),
                    static_cast<uint64_t>(words_per_receiver),
                    payload_binding);
            std::array<uint8_t, 64> signature{};
            if (message.empty() ||
                !auth.SignWords(
                    MPC_SIGNATURE_DOMAIN, message, &signature))
                return false;
            std::memcpy(
                dealer_signatures.data() +
                    static_cast<size_t>(receiver) * signature.size(),
                signature.data(), signature.size());

            if (payload_binding == Digest{}) return false;
            for (size_t word = 0; word < 4; ++word) {
                std::memcpy(
                    &leaf_words[static_cast<size_t>(receiver) * 4 + word],
                    payload_binding.bytes.data() + 8 * word, 8);
            }
        }

        std::vector<u64> root_words = transcript_prefix(
            MPC_SCATTER_BATCH_ROOT_DOMAIN,
            context, world_size_, Capabilities());
        root_words.push_back(static_cast<u64>(dealer));
        root_words.push_back(static_cast<u64>(words_per_receiver));
        for (int receiver = 0; receiver < world_size_; ++receiver) {
            root_words.push_back(static_cast<u64>(receiver));
            const Digest leaf = digest_from_words(
                leaf_words, static_cast<size_t>(receiver) * 4);
            if (leaf == Digest{}) return false;
            append_digest(leaf, &root_words);
        }
        const Digest batch_root = hash_words(root_words);
        if (batch_root == Digest{}) return false;

        std::vector<u64> batch_message = {
            MPC_SCATTER_BATCH_ROOT_DOMAIN,
            static_cast<u64>(dealer),
            static_cast<u64>(world_size_),
            static_cast<u64>(words_per_receiver)};
        append_digest(
            compute_authenticated_mpc_context_binding(context),
            &batch_message);
        append_digest(batch_root, &batch_message);
        if (!auth.SignWords(
                MPC_SCATTER_BATCH_SIGNATURE_DOMAIN,
                batch_message, &batch_signature))
            return false;
    }

    // The compact leaf table and one batch signature are common to all
    // receivers.  They make the recipient-specific payloads part of one
    // checkpoint-scoped authenticated batch without broadcasting the payloads.
    MPI_Bcast(
        leaf_words.data(), static_cast<int>(leaf_words.size()),
        MPI_UINT64_T, dealer, comm_);
    MPI_Bcast(
        batch_signature.data(), static_cast<int>(batch_signature.size()),
        MPI_UNSIGNED_CHAR, dealer, comm_);

    std::vector<u64> root_words = transcript_prefix(
        MPC_SCATTER_BATCH_ROOT_DOMAIN,
        context, world_size_, Capabilities());
    root_words.push_back(static_cast<u64>(dealer));
    root_words.push_back(static_cast<u64>(words_per_receiver));
    for (int receiver = 0; receiver < world_size_; ++receiver) {
        root_words.push_back(static_cast<u64>(receiver));
        const Digest leaf = digest_from_words(
            leaf_words, static_cast<size_t>(receiver) * 4);
        if (leaf == Digest{}) return false;
        append_digest(leaf, &root_words);
    }
    const Digest batch_root = hash_words(root_words);
    if (batch_root == Digest{}) return false;

    std::vector<u64> batch_message = {
        MPC_SCATTER_BATCH_ROOT_DOMAIN,
        static_cast<u64>(dealer),
        static_cast<u64>(world_size_),
        static_cast<u64>(words_per_receiver)};
    append_digest(
        compute_authenticated_mpc_context_binding(context),
        &batch_message);
    append_digest(batch_root, &batch_message);
    if (!auth.VerifyWords(
            MPC_SCATTER_BATCH_SIGNATURE_DOMAIN, batch_message,
            batch_signature, static_cast<uint32_t>(dealer)))
        return false;

    received_payload->resize(words_per_receiver);
    MPI_Scatter(
        rank_ == dealer ? dealer_payloads.data() : nullptr,
        static_cast<int>(words_per_receiver), MPI_UINT64_T,
        received_payload->data(),
        static_cast<int>(words_per_receiver), MPI_UINT64_T,
        dealer, comm_);

    std::array<uint8_t, 64> local_signature{};
    MPI_Scatter(
        rank_ == dealer ? dealer_signatures.data() : nullptr,
        static_cast<int>(local_signature.size()), MPI_UNSIGNED_CHAR,
        local_signature.data(),
        static_cast<int>(local_signature.size()), MPI_UNSIGNED_CHAR,
        dealer, comm_);

    const Digest local_payload_binding =
        compute_authenticated_mpc_payload_binding(*received_payload);
    const Digest committed_local_binding = digest_from_words(
        leaf_words, static_cast<size_t>(rank_) * 4);
    if (local_payload_binding == Digest{} ||
        local_payload_binding != committed_local_binding)
        return false;

    if (!ObserveVerifiedEnvelope(
            context, static_cast<uint32_t>(dealer),
            static_cast<uint32_t>(rank_),
            *received_payload, local_signature))
        return false;

    const uint64_t peer_count =
        static_cast<uint64_t>(world_size_ - 1);
    const uint64_t recipient_envelope_bytes =
        static_cast<uint64_t>(
            words_per_receiver * sizeof(u64) +
            local_signature.size());
    const uint64_t batch_summary_bytes =
        static_cast<uint64_t>(
            leaf_words.size() * sizeof(u64) +
            batch_signature.size());
    experiment_increment_authenticated_collective();
    const bool baseline_equivalent_payload =
        context.protocol_domain ==
            AUTHENTICATED_MPC_BASELINE_INPUT_DOMAIN;
    const uint64_t recipient_payload_bytes =
        static_cast<uint64_t>(words_per_receiver * sizeof(u64));
    const uint64_t recipient_overhead_bytes =
        static_cast<uint64_t>(local_signature.size()) +
        batch_summary_bytes;
    if (rank_ == dealer) {
        experiment_add_authenticated_envelope_traffic(
            (recipient_envelope_bytes + batch_summary_bytes) * peer_count,
            0, 2 * peer_count, 0);
        experiment_add_authenticated_traffic_breakdown(
            recipient_payload_bytes * peer_count, 0,
            recipient_overhead_bytes * peer_count, 0,
            baseline_equivalent_payload);
    } else {
        experiment_add_authenticated_envelope_traffic(
            0, recipient_envelope_bytes + batch_summary_bytes,
            0, 2);
        experiment_add_authenticated_traffic_breakdown(
            0, recipient_payload_bytes,
            0, recipient_overhead_bytes,
            baseline_equivalent_payload);
    }

    if (transcript_binding) {
        std::vector<u64> words = transcript_prefix(
            MPC_SCATTER_OP, context, world_size_, Capabilities());
        words.push_back(static_cast<u64>(dealer));
        words.push_back(static_cast<u64>(words_per_receiver));
        append_digest(
            auth.PublicKeyId(static_cast<uint32_t>(dealer)), &words);
        append_digest(batch_root, &words);
        append_signature(batch_signature, &words);
        *transcript_binding = hash_words(words);
        if (*transcript_binding == Digest{}) return false;
    }
    return true;
}

bool AuthenticatedMpcExchange::AllToAllWords(
    const AuthenticatedMpcMessageContext& context,
    const std::vector<u64>& local_payloads,
    size_t words_per_receiver,
    std::vector<u64>* received_payloads,
    Digest* transcript_binding) const {
    if (!received_payloads || words_per_receiver == 0 ||
        words_per_receiver > static_cast<size_t>(std::numeric_limits<int>::max()) ||
        local_payloads.size() !=
            static_cast<size_t>(world_size_) * words_per_receiver ||
        !SameContextOnAllRanks(context))
        return false;

    const u64 local_words_per_receiver =
        static_cast<u64>(words_per_receiver);
    std::vector<u64> sizes(static_cast<size_t>(world_size_));
    MPI_Allgather(&local_words_per_receiver, 1, MPI_UINT64_T,
                  sizes.data(), 1, MPI_UINT64_T, comm_);
    for (u64 size : sizes)
        if (size != local_words_per_receiver) return false;

    const auto& auth = Ed25519TransferAuthenticator::instance();
    std::vector<uint8_t> send_signatures(
        static_cast<size_t>(world_size_) * 64);
    for (int receiver = 0; receiver < world_size_; ++receiver) {
        const size_t offset =
            static_cast<size_t>(receiver) * words_per_receiver;
        std::vector<u64> payload(
            local_payloads.begin() + static_cast<std::ptrdiff_t>(offset),
            local_payloads.begin() + static_cast<std::ptrdiff_t>(
                offset + words_per_receiver));
        const std::vector<u64> message = signed_message(
            context, static_cast<uint32_t>(rank_),
            static_cast<uint32_t>(receiver), world_size_, payload);
        std::array<uint8_t, 64> signature{};
        if (message.empty() ||
            !auth.SignWords(MPC_SIGNATURE_DOMAIN, message, &signature))
            return false;
        std::memcpy(send_signatures.data() +
                        static_cast<size_t>(receiver) * signature.size(),
                    signature.data(), signature.size());
    }

    received_payloads->resize(local_payloads.size());
    MPI_Alltoall(local_payloads.data(), static_cast<int>(words_per_receiver),
                 MPI_UINT64_T, received_payloads->data(),
                 static_cast<int>(words_per_receiver), MPI_UINT64_T, comm_);
    std::vector<uint8_t> received_signatures(
        static_cast<size_t>(world_size_) * 64);
    MPI_Alltoall(send_signatures.data(), 64, MPI_UNSIGNED_CHAR,
                 received_signatures.data(), 64, MPI_UNSIGNED_CHAR, comm_);
    const uint64_t logical_envelope_bytes =
        static_cast<uint64_t>(words_per_receiver * sizeof(u64) + 64);
    const uint64_t peer_count = static_cast<uint64_t>(world_size_ - 1);
    experiment_increment_authenticated_collective();
    experiment_add_authenticated_envelope_traffic(
        logical_envelope_bytes * peer_count,
        logical_envelope_bytes * peer_count, peer_count, peer_count);
    const uint64_t alltoall_payload_bytes =
        static_cast<uint64_t>(words_per_receiver * sizeof(u64)) *
        peer_count;
    const uint64_t alltoall_overhead_bytes =
        64ULL * peer_count;
    experiment_add_authenticated_traffic_breakdown(
        alltoall_payload_bytes, alltoall_payload_bytes,
        alltoall_overhead_bytes, alltoall_overhead_bytes, false);

    const auto capabilities = Capabilities();
    // Each receiver first commits to the complete set of signed messages it
    // verified locally. These receiver summaries are then themselves
    // authenticated and all-gathered, yielding one globally canonical
    // transcript even though the point-to-point payloads differ by receiver.
    std::vector<u64> receiver_transcript_words = transcript_prefix(
        MPC_ALLTOALL_RECEIVER_SUMMARY_DOMAIN,
        context, world_size_, capabilities);
    receiver_transcript_words.push_back(static_cast<u64>(rank_));
    receiver_transcript_words.push_back(static_cast<u64>(words_per_receiver));
    for (int sender = 0; sender < world_size_; ++sender) {
        const size_t offset =
            static_cast<size_t>(sender) * words_per_receiver;
        std::vector<u64> payload(
            received_payloads->begin() + static_cast<std::ptrdiff_t>(offset),
            received_payloads->begin() + static_cast<std::ptrdiff_t>(
                offset + words_per_receiver));
        std::array<uint8_t, 64> signature{};
        std::memcpy(signature.data(),
            received_signatures.data() +
                static_cast<size_t>(sender) * signature.size(),
            signature.size());
        const std::vector<u64> message = signed_message(
            context, static_cast<uint32_t>(sender),
            static_cast<uint32_t>(rank_), world_size_, payload);
        if (message.empty() ||
            !ObserveVerifiedEnvelope(
                context, static_cast<uint32_t>(sender),
                static_cast<uint32_t>(rank_), payload, signature))
            return false;
        receiver_transcript_words.push_back(static_cast<u64>(sender));
        receiver_transcript_words.push_back(static_cast<u64>(rank_));
        append_digest(auth.PublicKeyId(static_cast<uint32_t>(sender)),
                      &receiver_transcript_words);
        append_signature(signature, &receiver_transcript_words);
        receiver_transcript_words.push_back(static_cast<u64>(payload.size()));
        receiver_transcript_words.insert(
            receiver_transcript_words.end(), payload.begin(), payload.end());
    }

    const Digest receiver_summary = hash_words(receiver_transcript_words);
    if (receiver_summary == Digest{}) return false;
    std::vector<u64> local_summary_words;
    append_digest(receiver_summary, &local_summary_words);
    const AuthenticatedMpcMessageContext summary_context =
        alltoall_summary_subcontext(context);
    if (!validate_authenticated_mpc_message_context(summary_context))
        return false;
    std::vector<u64> gathered_summary_words;
    Digest summary_transport_binding{};
    if (!AllGatherWords(
            summary_context, local_summary_words,
            &gathered_summary_words, &summary_transport_binding) ||
        gathered_summary_words.size() !=
            static_cast<size_t>(world_size_) * 4 ||
        summary_transport_binding == Digest{})
        return false;

    std::vector<u64> transcript_words = transcript_prefix(
        MPC_ALLTOALL_OP, context, world_size_, capabilities);
    transcript_words.push_back(static_cast<u64>(words_per_receiver));
    transcript_words.push_back(static_cast<u64>(world_size_));
    append_digest(
        compute_authenticated_mpc_context_binding(summary_context),
        &transcript_words);
    for (int receiver = 0; receiver < world_size_; ++receiver) {
        const Digest summary = digest_from_words(
            gathered_summary_words, static_cast<size_t>(receiver) * 4);
        if (summary == Digest{}) return false;
        transcript_words.push_back(static_cast<u64>(receiver));
        append_digest(summary, &transcript_words);
    }
    append_digest(summary_transport_binding, &transcript_words);
    const Digest transcript = hash_words(transcript_words);
    if (transcript == Digest{}) return false;
    if (transcript_binding) *transcript_binding = transcript;
    return true;
}

bool AuthenticatedMpcExchange::AllGatherWords(
    u64 protocol_domain, uint64_t sid, uint64_t step,
    const std::vector<u64>& local_payload,
    std::vector<u64>* all_payloads,
    Digest* transcript_binding) const {
    AuthenticatedMpcMessageContext context;
    context.protocol_domain = protocol_domain;
    context.sid = sid;
    context.checkpoint = step;
    context.round = 0;
    context.sequence = step;
    context.message_kind = MPC_LEGACY_MESSAGE_KIND;
    return AllGatherWords(
        context, local_payload, all_payloads, transcript_binding);
}

bool AuthenticatedMpcExchange::SelfTest(int rank, int world_size) {
    if (world_size < 2 || rank < 0 || rank >= world_size) return false;
    AuthenticatedMpcExchange exchange(rank, world_size, comm_);
    if (!exchange.ready()) return false;
    const auto capabilities = exchange.Capabilities();
    int local_ok = validate_authenticated_mpc_transport_capabilities(
        capabilities) && capabilities.replay_protected ? 1 : 0;
    auto same_digest_on_all_ranks = [&](const Digest& digest) {
        if (digest == Digest{}) return false;
        std::vector<uint8_t> gathered_digests(
            static_cast<size_t>(world_size) * digest.bytes.size());
        MPI_Allgather(
            digest.bytes.data(), static_cast<int>(digest.bytes.size()), MPI_BYTE,
            gathered_digests.data(), static_cast<int>(digest.bytes.size()),
            MPI_BYTE, comm_);
        for (int peer = 0; peer < world_size; ++peer) {
            const uint8_t* begin = gathered_digests.data() +
                static_cast<size_t>(peer) * digest.bytes.size();
            if (!std::equal(digest.bytes.begin(), digest.bytes.end(), begin))
                return false;
        }
        return true;
    };

    AuthenticatedMpcMessageContext gather_context;
    gather_context.protocol_domain = MPC_SELFTEST_DOMAIN;
    gather_context.sid = 0x4d50434155544853ULL; // MPCAUTHS
    gather_context.checkpoint = 7;
    gather_context.round = 3;
    gather_context.sequence = 1;
    gather_context.message_kind = 0x4741544845523031ULL; // GATHER01
    AuthenticatedMpcMessageContext alternate_namespace = gather_context;
    alternate_namespace.protocol_domain ^= 0x0101010101010101ULL;
    const auto reconcile_namespace_a = observation_reconciliation_subcontext(
        gather_context, MPC_OBSERVATION_COUNT_STAGE);
    const auto reconcile_namespace_b = observation_reconciliation_subcontext(
        alternate_namespace, MPC_OBSERVATION_COUNT_STAGE);
    if (reconcile_namespace_a.protocol_domain !=
            MPC_OBSERVATION_RECONCILE_DOMAIN ||
        reconcile_namespace_b.protocol_domain !=
            MPC_OBSERVATION_RECONCILE_DOMAIN ||
        reconcile_namespace_a.message_kind == 0 ||
        reconcile_namespace_b.message_kind == 0 ||
        reconcile_namespace_a.message_kind ==
            reconcile_namespace_b.message_kind ||
        compute_authenticated_mpc_context_binding(reconcile_namespace_a) ==
            compute_authenticated_mpc_context_binding(reconcile_namespace_b))
        local_ok = 0;
    const std::vector<u64> local_payload = {
        static_cast<u64>(rank),
        static_cast<u64>(rank + 17),
        0x415554484d504354ULL};
    std::vector<u64> gathered;
    Digest gather_transcript{};
    if (!exchange.AllGatherWords(
            gather_context, local_payload,
            &gathered, &gather_transcript) ||
        gather_transcript == Digest{} ||
        gathered.size() != static_cast<size_t>(world_size) * 3)
        local_ok = 0;
    for (int sender = 0; sender < world_size && local_ok; ++sender) {
        const size_t offset = static_cast<size_t>(sender) * 3;
        if (gathered[offset] != static_cast<u64>(sender) ||
            gathered[offset + 1] != static_cast<u64>(sender + 17) ||
            gathered[offset + 2] != 0x415554484d504354ULL)
            local_ok = 0;
    }

    AuthenticatedMpcMessageContext broadcast_context = gather_context;
    broadcast_context.sequence = 2;
    broadcast_context.message_kind = 0x42524f4144433031ULL; // BROADC01
    std::vector<u64> broadcaster_payload;
    if (rank == 0)
        broadcaster_payload = {0x42524f4144434153ULL, 99ULL, 1234ULL};
    std::vector<u64> broadcast_payload;
    Digest broadcast_transcript{};
    if (!exchange.BroadcastWords(
            broadcast_context, 0, broadcaster_payload,
            &broadcast_payload, &broadcast_transcript) ||
        broadcast_transcript == Digest{} ||
        broadcast_payload !=
            std::vector<u64>({0x42524f4144434153ULL, 99ULL, 1234ULL}))
        local_ok = 0;

    AuthenticatedMpcMessageContext alltrue_context = gather_context;
    alltrue_context.sequence = 3;
    alltrue_context.message_kind = 0x414c4c5452554531ULL; // ALLTRUE1
    bool all_true = false;
    Digest alltrue_transcript{};
    if (!exchange.AllTrue(
            alltrue_context, true, &all_true, &alltrue_transcript) ||
        !all_true || alltrue_transcript == Digest{})
        local_ok = 0;

    AuthenticatedMpcMessageContext scatter_context = gather_context;
    scatter_context.sequence = 4;
    scatter_context.message_kind = 0x5343415454455231ULL; // SCATTER1
    std::vector<u64> scatter_send;
    if (rank == 0) {
        scatter_send.resize(static_cast<size_t>(world_size) * 2);
        for (int receiver = 0; receiver < world_size; ++receiver) {
            scatter_send[static_cast<size_t>(receiver) * 2] =
                static_cast<u64>(receiver);
            scatter_send[static_cast<size_t>(receiver) * 2 + 1] = 777ULL;
        }
    }
    std::vector<u64> scatter_received;
    Digest scatter_transcript{};
    if (!exchange.ScatterWords(
            scatter_context, 0, scatter_send, 2,
            &scatter_received, &scatter_transcript) ||
        scatter_transcript == Digest{} ||
        !same_digest_on_all_ranks(scatter_transcript) ||
        scatter_received != std::vector<u64>({static_cast<u64>(rank), 777ULL}))
        local_ok = 0;

    AuthenticatedMpcMessageContext alltoall_context = gather_context;
    alltoall_context.sequence = 5;
    alltoall_context.message_kind = 0x414c4c32414c3031ULL; // ALL2AL01
    std::vector<u64> alltoall_send(
        static_cast<size_t>(world_size) * 2);
    for (int receiver = 0; receiver < world_size; ++receiver) {
        const size_t offset = static_cast<size_t>(receiver) * 2;
        alltoall_send[offset] = static_cast<u64>(rank);
        alltoall_send[offset + 1] = static_cast<u64>(receiver);
    }
    std::vector<u64> alltoall_received;
    Digest alltoall_transcript{};
    if (!exchange.AllToAllWords(
            alltoall_context, alltoall_send, 2,
            &alltoall_received, &alltoall_transcript) ||
        alltoall_transcript == Digest{} ||
        !same_digest_on_all_ranks(alltoall_transcript) ||
        alltoall_received.size() !=
            static_cast<size_t>(world_size) * 2)
        local_ok = 0;
    for (int sender = 0; sender < world_size && local_ok; ++sender) {
        const size_t offset = static_cast<size_t>(sender) * 2;
        if (alltoall_received[offset] != static_cast<u64>(sender) ||
            alltoall_received[offset + 1] != static_cast<u64>(rank))
            local_ok = 0;
    }

    const auto& auth = Ed25519TransferAuthenticator::instance();
    AuthenticatedMpcMessageContext signed_context = gather_context;
    signed_context.sequence = 6;
    signed_context.message_kind = 0x54414d5045523031ULL; // TAMPER01
    const std::vector<u64> tamper_payload = {static_cast<u64>(rank)};
    std::vector<u64> message = signed_message(
        signed_context, static_cast<uint32_t>(rank), BROADCAST_RECEIVER,
        world_size, tamper_payload);
    std::array<uint8_t, 64> signature{};
    if (message.empty() ||
        !auth.SignWords(MPC_SIGNATURE_DOMAIN, message, &signature) ||
        !auth.VerifyWords(MPC_SIGNATURE_DOMAIN, message, signature,
                          static_cast<uint32_t>(rank)))
        local_ok = 0;
    signed_context.checkpoint += 1;
    const std::vector<u64> tampered_message = signed_message(
        signed_context, static_cast<uint32_t>(rank), BROADCAST_RECEIVER,
        world_size, tamper_payload);
    if (auth.VerifyWords(MPC_SIGNATURE_DOMAIN, tampered_message, signature,
                         static_cast<uint32_t>(rank)))
        local_ok = 0;

    exchange.ClearEquivocationEvidence();
    AuthenticatedMpcMessageContext equivocation_context = gather_context;
    equivocation_context.sequence = 7;
    equivocation_context.message_kind = 0x4551564341434831ULL; // EQVCACH1
    std::vector<u64> equivocation_gathered;
    Digest equivocation_transcript{};
    const std::vector<u64> first_equivocation_payload = {
        static_cast<u64>(rank), 100ULL};
    if (!exchange.AllGatherWords(
            equivocation_context, first_equivocation_payload,
            &equivocation_gathered, &equivocation_transcript) ||
        equivocation_transcript == Digest{})
        local_ok = 0;
    exchange.ClearLocalFailures();
    if (exchange.AllGatherWords(
            equivocation_context, first_equivocation_payload,
            &equivocation_gathered, &equivocation_transcript))
        local_ok = 0;
    AuthenticatedMpcLocalFailureObservation replay_failure;
    if (!exchange.LastLocalFailure(
            equivocation_context.sid, equivocation_context.checkpoint,
            &replay_failure) ||
        replay_failure.kind != AuthenticatedMpcLocalFailureKind::EXACT_REPLAY ||
        replay_failure.failure_binding == Digest{})
        local_ok = 0;
    const std::vector<u64> second_equivocation_payload = {
        static_cast<u64>(rank), 101ULL};
    if (exchange.AllGatherWords(
            equivocation_context, second_equivocation_payload,
            &equivocation_gathered, &equivocation_transcript))
        local_ok = 0;
    AuthenticatedMpcLocalFailureObservation equivocation_failure;
    if (!exchange.LastLocalFailure(
            equivocation_context.sid, equivocation_context.checkpoint,
            &equivocation_failure) ||
        equivocation_failure.kind !=
            AuthenticatedMpcLocalFailureKind::SIGNED_EQUIVOCATION ||
        equivocation_failure.failure_binding == Digest{})
        local_ok = 0;
    AuthenticatedMpcEquivocationEvidence cached_equivocation;
    if (!exchange.LastEquivocationEvidence(&cached_equivocation) ||
        !verify_authenticated_mpc_equivocation_evidence(
            cached_equivocation, auth.RegistryCommitment()) ||
        cached_equivocation.context.sequence != equivocation_context.sequence ||
        cached_equivocation.first_payload_word_count == 0 ||
        cached_equivocation.second_payload_word_count == 0 ||
        cached_equivocation.first_payload_binding ==
            cached_equivocation.second_payload_binding)
        local_ok = 0;
    std::vector<AuthenticatedMpcSignedEnvelopeObservation> observations;
    if (!exchange.ExportVerifiedEnvelopeObservations(
            equivocation_context.sid, equivocation_context.checkpoint,
            &observations)) {
        local_ok = 0;
    } else {
        const auto reconciled = reconcile_authenticated_mpc_observations(
            observations, auth.PublicKeys(), auth.RegistryCommitment());
        if (!reconciled.valid || !reconciled.equivocation_found ||
            reconciled.observation_set_binding == Digest{} ||
            reconciled.evidence.evidence_binding !=
                cached_equivocation.evidence_binding)
            local_ok = 0;
        const Digest target_context =
            compute_authenticated_mpc_context_binding(equivocation_context);
        const AuthenticatedMpcSignedEnvelopeObservation* first_observation = nullptr;
        const AuthenticatedMpcSignedEnvelopeObservation* second_observation = nullptr;
        for (const auto& observation : observations) {
            if (compute_authenticated_mpc_context_binding(observation.context) !=
                    target_context ||
                observation.sender != cached_equivocation.sender ||
                observation.receiver != cached_equivocation.receiver)
                continue;
            if (observation.payload_binding ==
                    cached_equivocation.first_payload_binding)
                first_observation = &observation;
            if (observation.payload_binding ==
                    cached_equivocation.second_payload_binding)
                second_observation = &observation;
        }
        AuthenticatedMpcEquivocationEvidence recombined;
        if (!first_observation || !second_observation ||
            !combine_authenticated_mpc_equivocation_observations(
                *first_observation, *second_observation,
                auth.PublicKeys(), auth.RegistryCommitment(), &recombined) ||
            recombined.evidence_binding != cached_equivocation.evidence_binding)
            local_ok = 0;
    }
    if (exchange.production_authenticated_ready()) {
        AuthenticatedMpcMessageContext reconciliation_context =
            equivocation_context;
        reconciliation_context.sequence = 70;
        reconciliation_context.message_kind =
            0x4f42535245434f4eULL; // OBSRECON
        AuthenticatedMpcObservationReconciliation collective_reconciliation;
        Digest reconciliation_transcript{};
        if (!exchange.ReconcileCheckpointObservations(
                reconciliation_context,
                equivocation_context.sid, equivocation_context.checkpoint,
                &collective_reconciliation, &reconciliation_transcript) ||
            !collective_reconciliation.valid ||
            !collective_reconciliation.equivocation_found ||
            collective_reconciliation.evidence.evidence_binding !=
                cached_equivocation.evidence_binding ||
            collective_reconciliation.observation_set_binding == Digest{} ||
            reconciliation_transcript == Digest{})
            local_ok = 0;
    }
    exchange.ClearEquivocationEvidence();
    if (exchange.LastEquivocationEvidence(&cached_equivocation))
        local_ok = 0;

    // Simulate split-view broadcast equivocation: sender 0 signs two different
    // payloads for the same broadcast-labeled context, but each observer sees
    // only one. No local cache can blame before observation dissemination.
    if (exchange.production_authenticated_ready() && world_size >= 2) {
        AuthenticatedMpcMessageContext split_context = gather_context;
        split_context.sid = 0x53504c49544f4253ULL; // SPLITOBS
        split_context.checkpoint = 83;
        split_context.round = 4;
        split_context.sequence = 1;
        split_context.message_kind = 0x53504c49544d5347ULL; // SPLITMSG
        const std::vector<u64> split_a = {0ULL, 601ULL};
        const std::vector<u64> split_b = {0ULL, 602ULL};
        std::vector<u64> split_send_words;
        std::vector<uint8_t> split_send_signatures;
        int split_ready = 1;
        if (rank == 0) {
            split_send_words.resize(static_cast<size_t>(world_size) * 2);
            split_send_signatures.resize(static_cast<size_t>(world_size) * 64);
            for (int recipient = 0; recipient < world_size; ++recipient) {
                const std::vector<u64>& selected =
                    recipient == world_size - 1 ? split_b : split_a;
                const std::vector<u64> split_message = signed_message(
                    split_context, 0U, BROADCAST_RECEIVER,
                    world_size, selected);
                std::array<uint8_t, 64> split_signature{};
                if (split_message.empty() ||
                    !auth.SignWords(MPC_SIGNATURE_DOMAIN, split_message,
                                    &split_signature)) {
                    split_ready = 0;
                    break;
                }
                std::copy(selected.begin(), selected.end(),
                          split_send_words.begin() +
                              static_cast<std::ptrdiff_t>(recipient * 2));
                std::memcpy(split_send_signatures.data() +
                                static_cast<size_t>(recipient) * 64,
                            split_signature.data(), 64);
            }
        }
        MPI_Bcast(&split_ready, 1, MPI_INT, 0, comm_);
        if (!split_ready) {
            local_ok = 0;
        } else {
            std::vector<u64> split_received(2);
            std::array<uint8_t, 64> split_signature{};
            MPI_Scatter(rank == 0 ? split_send_words.data() : nullptr,
                        2, MPI_UINT64_T,
                        split_received.data(), 2, MPI_UINT64_T, 0, comm_);
            MPI_Scatter(rank == 0 ? split_send_signatures.data() : nullptr,
                        64, MPI_UNSIGNED_CHAR,
                        split_signature.data(), 64, MPI_UNSIGNED_CHAR, 0, comm_);
            if (!exchange.ObserveVerifiedEnvelope(
                    split_context, 0U, BROADCAST_RECEIVER,
                    split_received, split_signature))
                local_ok = 0;
            AuthenticatedMpcEquivocationEvidence local_split_evidence;
            if (exchange.LastEquivocationEvidence(
                    split_context.sid, split_context.checkpoint,
                    &local_split_evidence))
                local_ok = 0;

            AuthenticatedMpcMessageContext split_reconcile_context = split_context;
            split_reconcile_context.sequence = 2;
            split_reconcile_context.message_kind =
                0x53504c4954524543ULL; // SPLITREC
            AuthenticatedMpcObservationReconciliation split_reconciliation;
            Digest split_reconciliation_transcript{};
            if (!exchange.ReconcileCheckpointObservations(
                    split_reconcile_context,
                    split_context.sid, split_context.checkpoint,
                    &split_reconciliation,
                    &split_reconciliation_transcript) ||
                !split_reconciliation.valid ||
                !split_reconciliation.equivocation_found ||
                split_reconciliation.accepted_count < 2 ||
                split_reconciliation.evidence.sender != 0U ||
                split_reconciliation.evidence.receiver != BROADCAST_RECEIVER ||
                split_reconciliation.evidence.context.sid != split_context.sid ||
                split_reconciliation.evidence.context.checkpoint !=
                    split_context.checkpoint ||
                split_reconciliation_transcript == Digest{})
                local_ok = 0;
            if (exchange.LastEquivocationEvidence(
                    split_context.sid, split_context.checkpoint,
                    &local_split_evidence))
                local_ok = 0;
            if (!exchange.RetireCheckpoint(
                    split_context.sid, split_context.checkpoint))
                local_ok = 0;
        }
    }

    // Two independent namespaces may accumulate attributable evidence before
    // either one is consumed. Acknowledging one must not erase the other.
    AuthenticatedMpcMessageContext pending_a = gather_context;
    pending_a.sid = 0x50454e44494e4741ULL; // PENDINGA
    pending_a.checkpoint = 81;
    pending_a.sequence = 1;
    pending_a.message_kind = 0x50454e444d534741ULL; // PENDMSGA
    AuthenticatedMpcMessageContext pending_b = pending_a;
    pending_b.sid = 0x50454e44494e4742ULL; // PENDINGB
    pending_b.checkpoint = 82;
    pending_b.message_kind = 0x50454e444d534742ULL; // PENDMSGB
    auto observe_signed = [&](const AuthenticatedMpcMessageContext& context,
                              const std::vector<u64>& payload) -> bool {
        const std::vector<u64> signed_words = signed_message(
            context, static_cast<uint32_t>(rank), BROADCAST_RECEIVER,
            world_size, payload);
        std::array<uint8_t, 64> signed_signature{};
        return !signed_words.empty() &&
            auth.SignWords(MPC_SIGNATURE_DOMAIN, signed_words,
                           &signed_signature) &&
            exchange.ObserveVerifiedEnvelope(
                context, static_cast<uint32_t>(rank), BROADCAST_RECEIVER,
                payload, signed_signature);
    };
    const std::vector<u64> pending_a_first = {
        static_cast<u64>(rank), 401ULL};
    const std::vector<u64> pending_a_second = {
        static_cast<u64>(rank), 402ULL};
    const std::vector<u64> pending_a_third = {
        static_cast<u64>(rank), 403ULL};
    const std::vector<u64> pending_b_first = {
        static_cast<u64>(rank), 501ULL};
    const std::vector<u64> pending_b_second = {
        static_cast<u64>(rank), 502ULL};
    if (!observe_signed(pending_a, pending_a_first) ||
        observe_signed(pending_a, pending_a_second) ||
        exchange.pending_equivocations_.size() != 1 ||
        observe_signed(pending_a, pending_a_third) ||
        exchange.pending_equivocations_.size() != 1 ||
        !observe_signed(pending_b, pending_b_first) ||
        observe_signed(pending_b, pending_b_second) ||
        exchange.pending_equivocations_.size() != 2)
        local_ok = 0;
    AuthenticatedMpcEquivocationEvidence pending_a_evidence;
    AuthenticatedMpcEquivocationEvidence pending_b_evidence;
    if (!exchange.LastEquivocationEvidence(
            pending_a.sid, pending_a.checkpoint, &pending_a_evidence) ||
        !exchange.LastEquivocationEvidence(
            pending_b.sid, pending_b.checkpoint, &pending_b_evidence) ||
        pending_a_evidence.evidence_binding == Digest{} ||
        pending_b_evidence.evidence_binding == Digest{} ||
        pending_a_evidence.evidence_binding == pending_b_evidence.evidence_binding)
        local_ok = 0;
    if (!exchange.AcknowledgeEquivocationEvidence(
            pending_a.sid, pending_a.checkpoint,
            pending_a_evidence.evidence_binding) ||
        exchange.LastEquivocationEvidence(
            pending_a.sid, pending_a.checkpoint, &cached_equivocation) ||
        !exchange.LastEquivocationEvidence(
            pending_b.sid, pending_b.checkpoint, &cached_equivocation) ||
        cached_equivocation.evidence_binding != pending_b_evidence.evidence_binding ||
        !exchange.RetireCheckpoint(pending_a.sid, pending_a.checkpoint) ||
        exchange.RetireCheckpoint(pending_b.sid, pending_b.checkpoint))
        local_ok = 0;
    if (!exchange.AcknowledgeEquivocationEvidence(
            pending_b.sid, pending_b.checkpoint,
            pending_b_evidence.evidence_binding) ||
        !exchange.RetireCheckpoint(pending_b.sid, pending_b.checkpoint))
        local_ok = 0;

    AuthenticatedMpcMessageContext replay_context = gather_context;
    replay_context.sequence = 8;
    replay_context.message_kind = 0x5245504c41593031ULL; // REPLAY01
    const std::vector<u64> replay_payload = {
        static_cast<u64>(rank), 200ULL};
    std::vector<u64> replay_message = signed_message(
        replay_context, static_cast<uint32_t>(rank), BROADCAST_RECEIVER,
        world_size, replay_payload);
    std::array<uint8_t, 64> replay_signature{};
    if (replay_message.empty() ||
        !auth.SignWords(MPC_SIGNATURE_DOMAIN, replay_message,
                        &replay_signature) ||
        !exchange.ObserveVerifiedEnvelope(
            replay_context, static_cast<uint32_t>(rank), BROADCAST_RECEIVER,
            replay_payload, replay_signature))
        local_ok = 0;
    if (exchange.ObserveVerifiedEnvelope(
            replay_context, static_cast<uint32_t>(rank), BROADCAST_RECEIVER,
            replay_payload, replay_signature))
        local_ok = 0;
    if (exchange.LastEquivocationEvidence(&cached_equivocation))
        local_ok = 0;

    AuthenticatedMpcMessageContext stale_context = replay_context;
    stale_context.sequence = 7;
    const std::vector<u64> stale_payload = {
        static_cast<u64>(rank), 201ULL};
    std::vector<u64> stale_message = signed_message(
        stale_context, static_cast<uint32_t>(rank), BROADCAST_RECEIVER,
        world_size, stale_payload);
    std::array<uint8_t, 64> stale_signature{};
    if (stale_message.empty() ||
        !auth.SignWords(MPC_SIGNATURE_DOMAIN, stale_message,
                        &stale_signature) ||
        exchange.ObserveVerifiedEnvelope(
            stale_context, static_cast<uint32_t>(rank), BROADCAST_RECEIVER,
            stale_payload, stale_signature))
        local_ok = 0;
    if (exchange.LastEquivocationEvidence(&cached_equivocation))
        local_ok = 0;

    AuthenticatedMpcMessageContext fresh_context = replay_context;
    fresh_context.sequence = 9;
    const std::vector<u64> fresh_payload = {
        static_cast<u64>(rank), 202ULL};
    std::vector<u64> fresh_message = signed_message(
        fresh_context, static_cast<uint32_t>(rank), BROADCAST_RECEIVER,
        world_size, fresh_payload);
    std::array<uint8_t, 64> fresh_signature{};
    if (fresh_message.empty() ||
        !auth.SignWords(MPC_SIGNATURE_DOMAIN, fresh_message,
                        &fresh_signature) ||
        !exchange.ObserveVerifiedEnvelope(
            fresh_context, static_cast<uint32_t>(rank), BROADCAST_RECEIVER,
            fresh_payload, fresh_signature))
        local_ok = 0;
    exchange.ClearEquivocationEvidence();

    AuthenticatedMpcMessageContext retire_context = gather_context;
    retire_context.checkpoint = 77;
    retire_context.sequence = 1;
    retire_context.message_kind = 0x5245544952453031ULL; // RETIRE01
    std::vector<u64> retirement_gathered;
    Digest retirement_transcript{};
    if (!exchange.AllGatherWords(
            retire_context, {static_cast<u64>(rank), 301ULL},
            &retirement_gathered, &retirement_transcript) ||
        retirement_transcript == Digest{})
        local_ok = 0;
    if (exchange.AllGatherWords(
            retire_context, {static_cast<u64>(rank), 302ULL},
            &retirement_gathered, &retirement_transcript))
        local_ok = 0;
    if (exchange.RetireCheckpoint(
            retire_context.sid, retire_context.checkpoint))
        local_ok = 0;
    AuthenticatedMpcEquivocationEvidence retirement_evidence;
    if (!exchange.LastEquivocationEvidence(&retirement_evidence))
        local_ok = 0;
    if (!exchange.AcknowledgeEquivocationEvidence(
            retire_context.sid, retire_context.checkpoint,
            retirement_evidence.evidence_binding))
        local_ok = 0;
    if (!exchange.RetireCheckpoint(
            retire_context.sid, retire_context.checkpoint) ||
        !exchange.CheckpointRetired(
            retire_context.sid, retire_context.checkpoint) ||
        !exchange.RetireCheckpoint(
            retire_context.sid, retire_context.checkpoint))
        local_ok = 0;
    retire_context.sequence = 2;
    if (exchange.AllGatherWords(
            retire_context, {static_cast<u64>(rank), 303ULL},
            &retirement_gathered, &retirement_transcript))
        local_ok = 0;
    AuthenticatedMpcMessageContext reused_context = retire_context;
    reused_context.sid = retire_context.sid + 1;
    reused_context.sequence = 1;
    if (!exchange.AllGatherWords(
            reused_context, {static_cast<u64>(rank), 304ULL},
            &retirement_gathered, &retirement_transcript) ||
        retirement_transcript == Digest{})
        local_ok = 0;

    if (exchange.production_authenticated_ready() !=
        production_ready_authenticated_mpc_transport_capabilities(capabilities))
        local_ok = 0;
    if (exchange.production_authenticated_ready() !=
        (exchange.ProductionCapabilityBinding() != Digest{}))
        local_ok = 0;

    int global_ok = 0;
    MPI_Allreduce(&local_ok, &global_ok, 1, MPI_INT, MPI_MIN, comm_);
    if (rank == 0) {
        std::cout << "[PVIA][authenticated-mpc-exchange-selftest] gather="
                  << (global_ok ? "PASS" : "FAIL")
                  << " broadcast=" << (global_ok ? "PASS" : "FAIL")
                  << " alltoall=" << (global_ok ? "PASS" : "FAIL")
                  << " equivocation-cache="
                  << (global_ok ? "PASS" : "FAIL")
                  << " replay-guard="
                  << (global_ok ? "PASS" : "FAIL")
                  << " retirement="
                  << (global_ok ? "PASS" : "FAIL")
                  << " registry="
                  << (exchange.production_authenticated_ready()
                          ? "ANCHORED" : "SESSION-ONLY")
                  << " result=" << (global_ok ? "PASS" : "FAIL") << "\n";
    }
    return global_ok != 0;
}

} // namespace pvia
