#include "MultiplicationConsistencyProof.hpp"
#include "MultiplicationConsistencyProviderAbiC.h"
#include "MultiplicationConsistencySharingWitness.hpp"

#include <cstring>
#include <limits>

namespace pvia {
namespace {

constexpr u64 MUL_STATEMENT_DOMAIN = PVIA_MC_STATEMENT_BINDING_DOMAIN;
constexpr u64 MUL_PROOF_DOMAIN = PVIA_MC_PROOF_COMMITMENT_DOMAIN;
constexpr u64 MUL_CAP_DOMAIN = PVIA_MC_CAPABILITY_BINDING_DOMAIN;
constexpr u64 MUL_SET_DOMAIN = 0x50564d554c534554ULL;       // PVMULSET
constexpr u64 MUL_FAILURE_CERT_CODEC_DOMAIN =
    0x50564d554c434552ULL; // PVMULCER
constexpr u64 MUL_FAILURE_CERT_CODEC_VERSION = 1ULL;
// Keep the failure-certificate codec aligned with the supported RS
// multiplication self-test range. Each participant contributes one signed
// preflight status and one verified envelope observation.
constexpr size_t MUL_FAILURE_CERT_MAX_PARTICIPANTS = 128;
constexpr size_t MUL_FAILURE_CERT_MAX_PAYLOAD_WORDS = 64;

void append_digest(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

Digest read_digest(const std::vector<u64>& words, size_t offset) {
    Digest digest{};
    if (offset > words.size() || words.size() - offset < 4) return digest;
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(digest.bytes.data() + 8 * i, &words[offset + i], 8);
    return digest;
}

void append_mpc_context(
    const AuthenticatedMpcMessageContext& context,
    std::vector<u64>* words) {
    if (!words) return;
    words->push_back(context.protocol_domain);
    words->push_back(context.sid);
    words->push_back(context.checkpoint);
    words->push_back(context.round);
    words->push_back(context.sequence);
    words->push_back(context.message_kind);
}

void append_signed_observation(
    const AuthenticatedMpcSignedEnvelopeObservation& observation,
    std::vector<u64>* words) {
    if (!words) return;
    words->push_back(observation.available ? 1ULL : 0ULL);
    append_mpc_context(observation.context, words);
    words->push_back(observation.sender);
    words->push_back(observation.receiver);
    words->push_back(observation.payload_word_count);
    append_digest(observation.payload_binding, words);
    for (size_t i = 0; i < 8; ++i) {
        u64 word = 0;
        std::memcpy(&word, observation.signature.data() + 8 * i, 8);
        words->push_back(word);
    }
    append_digest(observation.registry_commitment, words);
    append_digest(observation.observation_binding, words);
}

template <typename T>
bool take_word(const std::vector<u64>& words, size_t* cursor, T* value) {
    static_assert(sizeof(T) <= sizeof(u64),
                  "certificate codec word target must fit in u64");
    if (!cursor || !value || *cursor >= words.size()) return false;
    *value = static_cast<T>(words[(*cursor)++]);
    return true;
}

bool take_digest(const std::vector<u64>& words, size_t* cursor,
                 Digest* digest) {
    if (!cursor || !digest || *cursor > words.size() ||
        words.size() - *cursor < 4)
        return false;
    *digest = read_digest(words, *cursor);
    *cursor += 4;
    return true;
}

bool take_mpc_context(const std::vector<u64>& words, size_t* cursor,
                      AuthenticatedMpcMessageContext* context) {
    if (!context) return false;
    return take_word(words, cursor, &context->protocol_domain) &&
        take_word(words, cursor, &context->sid) &&
        take_word(words, cursor, &context->checkpoint) &&
        take_word(words, cursor, &context->round) &&
        take_word(words, cursor, &context->sequence) &&
        take_word(words, cursor, &context->message_kind);
}

bool take_signed_observation(
    const std::vector<u64>& words, size_t* cursor,
    AuthenticatedMpcSignedEnvelopeObservation* observation) {
    if (!cursor || !observation) return false;
    u64 available = 0, sender = 0, receiver = 0;
    AuthenticatedMpcSignedEnvelopeObservation decoded;
    if (!take_word(words, cursor, &available) || available != 1 ||
        !take_mpc_context(words, cursor, &decoded.context) ||
        !take_word(words, cursor, &sender) ||
        !take_word(words, cursor, &receiver) ||
        sender > std::numeric_limits<uint32_t>::max() ||
        receiver > std::numeric_limits<uint32_t>::max() ||
        !take_word(words, cursor, &decoded.payload_word_count) ||
        !take_digest(words, cursor, &decoded.payload_binding))
        return false;
    decoded.available = true;
    decoded.sender = static_cast<uint32_t>(sender);
    decoded.receiver = static_cast<uint32_t>(receiver);
    for (size_t i = 0; i < 8; ++i) {
        u64 word = 0;
        if (!take_word(words, cursor, &word)) return false;
        std::memcpy(decoded.signature.data() + 8 * i, &word, 8);
    }
    if (!take_digest(words, cursor, &decoded.registry_commitment) ||
        !take_digest(words, cursor, &decoded.observation_binding))
        return false;
    *observation = decoded;
    return true;
}

} // namespace

Digest compute_multiplication_consistency_statement_binding(
    const MultiplicationConsistencyStatement& statement) {
    std::vector<u64> words = {
        MUL_STATEMENT_DOMAIN,
        statement.sid,
        statement.checkpoint,
        statement.multiplication_id,
        statement.dealer};
    append_digest(statement.lhs_sharing_binding, &words);
    append_digest(statement.rhs_sharing_binding, &words);
    append_digest(statement.output_sharing_binding, &words);
    append_digest(statement.context_binding, &words);
    return hash_words(words);
}

bool validate_multiplication_consistency_statement(
    const MultiplicationConsistencyStatement& statement) {
    if (statement.sid == 0 || statement.checkpoint == 0 ||
        statement.multiplication_id == 0 ||
        statement.lhs_sharing_binding == Digest{} ||
        statement.rhs_sharing_binding == Digest{} ||
        statement.output_sharing_binding == Digest{} ||
        statement.context_binding == Digest{} ||
        statement.statement_binding == Digest{})
        return false;
    return statement.statement_binding ==
        compute_multiplication_consistency_statement_binding(statement);
}
bool validate_multiplication_consistency_witness_for_statement(
    const MultiplicationConsistencyStatement& statement,
    const MultiplicationConsistencyWitness& witness) {
    const auto canonical_field = [](const F& value) {
        return value.real < PVIA_MC_FIELD_MODULUS &&
               value.img < PVIA_MC_FIELD_MODULUS;
    };
    if (F::mod != PVIA_MC_FIELD_MODULUS ||
        !validate_multiplication_consistency_statement(statement) ||
        !canonical_field(witness.lhs_share) ||
        !canonical_field(witness.rhs_share) ||
        !canonical_field(witness.product_value) ||
        witness.product_value != witness.lhs_share * witness.rhs_share)
        return false;

    MultiplicationConsistencySharingWitnessEnvelope lhs;
    MultiplicationConsistencySharingWitnessEnvelope rhs;
    MultiplicationConsistencySharingWitnessEnvelope output;
    if (!decode_multiplication_consistency_sharing_witness(
            witness.lhs_sharing_witness_words, &lhs) ||
        !decode_multiplication_consistency_sharing_witness(
            witness.rhs_sharing_witness_words, &rhs) ||
        !decode_multiplication_consistency_sharing_witness(
            witness.output_sharing_witness_words, &output))
        return false;

    const auto input_kind_ok = [](
        MultiplicationConsistencySharingWitnessKind kind) {
        return kind ==
                   MultiplicationConsistencySharingWitnessKind::VSS_LOCAL ||
               kind ==
                   MultiplicationConsistencySharingWitnessKind::
                       LINEAR_COMBINATION;
    };
    return input_kind_ok(lhs.kind) && input_kind_ok(rhs.kind) &&
        output.kind ==
            MultiplicationConsistencySharingWitnessKind::VSS_DEALER &&
        lhs.sharing_binding == statement.lhs_sharing_binding &&
        rhs.sharing_binding == statement.rhs_sharing_binding &&
        output.sharing_binding == statement.output_sharing_binding;
}

Digest compute_multiplication_consistency_proof_commitment(
    const MultiplicationConsistencyProofArtifact& proof) {
    std::vector<u64> words = {
        MUL_PROOF_DOMAIN,
        proof.available ? 1ULL : 0ULL,
        proof.cryptographically_authenticated ? 1ULL : 0ULL,
        proof.zero_knowledge ? 1ULL : 0ULL,
        proof.proof_system_id,
        static_cast<u64>(proof.proof_words.size())};
    append_digest(proof.statement_binding, &words);
    append_digest(proof.transcript_binding, &words);
    words.insert(words.end(), proof.proof_words.begin(), proof.proof_words.end());
    return hash_words(words);
}

bool validate_multiplication_consistency_proof_artifact(
    const MultiplicationConsistencyStatement& statement,
    const MultiplicationConsistencyProofArtifact& proof) {
    if (!validate_multiplication_consistency_statement(statement) ||
        !proof.available || !proof.cryptographically_authenticated ||
        !proof.zero_knowledge || proof.proof_system_id == 0 ||
        proof.statement_binding != statement.statement_binding ||
        proof.transcript_binding == Digest{} || proof.proof_words.empty() ||
        proof.proof_commitment == Digest{})
        return false;
    return proof.proof_commitment ==
        compute_multiplication_consistency_proof_commitment(proof);
}

std::vector<u64> encode_multiplication_consistency_proof_artifact(
    const MultiplicationConsistencyProofArtifact& proof) {
    std::vector<u64> words = {
        proof.available ? 1ULL : 0ULL,
        proof.cryptographically_authenticated ? 1ULL : 0ULL,
        proof.zero_knowledge ? 1ULL : 0ULL,
        proof.proof_system_id};
    append_digest(proof.statement_binding, &words);
    append_digest(proof.transcript_binding, &words);
    append_digest(proof.proof_commitment, &words);
    words.push_back(static_cast<u64>(proof.proof_words.size()));
    words.insert(words.end(), proof.proof_words.begin(), proof.proof_words.end());
    return words;
}

bool decode_multiplication_consistency_proof_artifact(
    const std::vector<u64>& words,
    MultiplicationConsistencyProofArtifact* proof) {
    if (!proof || words.size() < 17) return false;
    if (words[0] > 1 || words[1] > 1 || words[2] > 1 ||
        words[3] > static_cast<u64>(std::numeric_limits<uint32_t>::max()))
        return false;
    const u64 proof_words = words[16];
    if (proof_words != static_cast<u64>(words.size() - 17)) return false;
    MultiplicationConsistencyProofArtifact decoded;
    decoded.available = words[0] != 0;
    decoded.cryptographically_authenticated = words[1] != 0;
    decoded.zero_knowledge = words[2] != 0;
    decoded.proof_system_id = static_cast<uint32_t>(words[3]);
    decoded.statement_binding = read_digest(words, 4);
    decoded.transcript_binding = read_digest(words, 8);
    decoded.proof_commitment = read_digest(words, 12);
    decoded.proof_words.assign(words.begin() + 17, words.end());
    *proof = decoded;
    return true;
}

Digest compute_multiplication_consistency_set_binding(
    const std::vector<MultiplicationConsistencyProofArtifact>& proofs) {
    if (proofs.empty()) return Digest{};
    std::vector<u64> words = {
        MUL_SET_DOMAIN, static_cast<u64>(proofs.size())};
    for (const auto& proof : proofs) {
        if (!proof.available || !proof.cryptographically_authenticated ||
            !proof.zero_knowledge || proof.proof_system_id == 0 ||
            proof.statement_binding == Digest{} ||
            proof.transcript_binding == Digest{} || proof.proof_words.empty() ||
            proof.proof_commitment == Digest{} ||
            proof.proof_commitment !=
                compute_multiplication_consistency_proof_commitment(proof))
            return Digest{};
        append_digest(proof.proof_commitment, &words);
    }
    return hash_words(words);
}

Digest compute_reference_multiplication_rs_event_binding(
    const ReferenceMultiplicationRsEvent& event) {
    std::vector<u64> words = {
        0x5056525345564e54ULL, // PV RSEVNT
        1ULL, event.sid, event.checkpoint, event.multiplication_id,
        event.world_size, event.threshold,
        event.syndrome.real, event.syndrome.img,
        static_cast<u64>(event.output_sharing_bindings.size())};
    append_digest(event.lhs_sharing_binding, &words);
    append_digest(event.rhs_sharing_binding, &words);
    append_digest(event.joint_seed, &words);
    append_digest(event.joint_seed_binding, &words);
    append_digest(event.syndrome_opening_binding, &words);
    for (const Digest& binding : event.output_sharing_bindings)
        append_digest(binding, &words);
    return hash_words(words);
}

bool validate_reference_multiplication_rs_event(
    const ReferenceMultiplicationRsEvent& event) {
    if (event.sid == 0 || event.checkpoint == 0 ||
        event.multiplication_id == 0 || event.world_size < 4 ||
        event.threshold >= event.world_size ||
        3ULL * event.threshold >= event.world_size ||
        event.lhs_sharing_binding == Digest{} ||
        event.rhs_sharing_binding == Digest{} ||
        event.joint_seed == Digest{} ||
        event.joint_seed_binding == Digest{} ||
        event.syndrome.real >= F::mod ||
        event.syndrome.img >= F::mod ||
        event.syndrome_opening_binding == Digest{} ||
        event.output_sharing_bindings.size() != event.world_size ||
        event.event_binding == Digest{})
        return false;
    for (const Digest& binding : event.output_sharing_bindings)
        if (binding == Digest{}) return false;
    return event.event_binding ==
        compute_reference_multiplication_rs_event_binding(event);
}

std::vector<u64> encode_reference_multiplication_failure_status(
    const ReferenceMultiplicationRsEvent& event,
    uint32_t sender, uint64_t failure_code) {
    if (!validate_reference_multiplication_rs_event(event) ||
        event.syndrome == F(0) ||
        sender >= event.world_size || failure_code > 4)
        return {};
    std::vector<u64> words = {
        REFERENCE_MULTIPLICATION_FAILURE_STATUS_DOMAIN, 1ULL,
        event.sid, event.checkpoint, event.multiplication_id,
        event.world_size, event.threshold, sender, failure_code};
    append_digest(event.event_binding, &words);
    append_digest(event.output_sharing_bindings[sender], &words);
    return words;
}

Digest compute_reference_multiplication_failure_certificate_binding(
    const ReferenceMultiplicationFailureCertificate& certificate) {
    if (!certificate.available) return {};
    std::vector<u64> words = {
        0x505652534641494cULL, // PVRSFAIL
        1ULL, certificate.accused_dealer, certificate.failure_code,
        certificate.status_context.protocol_domain,
        certificate.status_context.sid,
        certificate.status_context.checkpoint,
        certificate.status_context.round,
        certificate.status_context.sequence,
        certificate.status_context.message_kind,
        static_cast<u64>(certificate.status_payloads.size()),
        static_cast<u64>(certificate.status_observations.size())};
    append_digest(certificate.event.event_binding, &words);
    append_digest(certificate.registry_commitment, &words);
    for (size_t i = 0; i < certificate.status_payloads.size(); ++i) {
        const auto& payload = certificate.status_payloads[i];
        words.push_back(static_cast<u64>(payload.size()));
        words.insert(words.end(), payload.begin(), payload.end());
        if (i < certificate.status_observations.size())
            append_digest(
                certificate.status_observations[i].observation_binding,
                &words);
    }
    return hash_words(words);
}

bool validate_reference_multiplication_failure_certificate(
    const ReferenceMultiplicationFailureCertificate& certificate) {
    if (!certificate.available ||
        !validate_reference_multiplication_rs_event(certificate.event) ||
        certificate.event.syndrome == F(0) ||
        certificate.accused_dealer >= certificate.event.world_size ||
        certificate.failure_code != static_cast<uint64_t>(
            ReferenceMultiplicationFailureCode::RELATION_PRECHECK_FAILED) ||
        certificate.status_context.protocol_domain !=
            REFERENCE_MULTIPLICATION_FAILURE_PROTOCOL_DOMAIN ||
        certificate.status_context.sid != certificate.event.sid ||
        certificate.status_context.checkpoint != certificate.event.checkpoint ||
        certificate.status_context.round !=
            certificate.event.multiplication_id ||
        certificate.status_context.sequence == 0 ||
        certificate.status_context.message_kind !=
            REFERENCE_MULTIPLICATION_FAILURE_STATUS_KIND ||
        certificate.registry_commitment == Digest{} ||
        certificate.status_payloads.size() != certificate.event.world_size ||
        certificate.status_observations.size() != certificate.event.world_size)
        return false;

    std::vector<bool> seen(certificate.event.world_size, false);
    size_t failure_count = 0;
    for (size_t i = 0; i < certificate.status_payloads.size(); ++i) {
        const auto& payload = certificate.status_payloads[i];
        const auto& observation = certificate.status_observations[i];
        if (payload.size() != 17 ||
            payload[0] != REFERENCE_MULTIPLICATION_FAILURE_STATUS_DOMAIN ||
            payload[1] != 1 ||
            payload[2] != certificate.event.sid ||
            payload[3] != certificate.event.checkpoint ||
            payload[4] != certificate.event.multiplication_id ||
            payload[5] != certificate.event.world_size ||
            payload[6] != certificate.event.threshold ||
            payload[7] >= certificate.event.world_size ||
            seen[static_cast<size_t>(payload[7])] ||
            (payload[8] != 0 &&
             payload[8] != static_cast<uint64_t>(
                 ReferenceMultiplicationFailureCode::RELATION_PRECHECK_FAILED)))
            return false;
        const uint32_t sender = static_cast<uint32_t>(payload[7]);
        seen[sender] = true;
        Digest event_binding{}, output_binding{};
        for (size_t j = 0; j < 4; ++j) {
            std::memcpy(event_binding.bytes.data() + 8*j,
                        &payload[9+j], 8);
            std::memcpy(output_binding.bytes.data() + 8*j,
                        &payload[13+j], 8);
        }
        if (event_binding != certificate.event.event_binding ||
            output_binding !=
                certificate.event.output_sharing_bindings[sender] ||
            observation.context.protocol_domain !=
                certificate.status_context.protocol_domain ||
            observation.context.sid != certificate.status_context.sid ||
            observation.context.checkpoint !=
                certificate.status_context.checkpoint ||
            observation.context.round != certificate.status_context.round ||
            observation.context.sequence !=
                certificate.status_context.sequence ||
            observation.context.message_kind !=
                certificate.status_context.message_kind ||
            observation.sender != sender ||
            observation.receiver != AUTHENTICATED_MPC_BROADCAST_RECEIVER ||
            !observation.available ||
            observation.observation_binding == Digest{} ||
            observation.payload_word_count != payload.size() ||
            observation.payload_binding !=
                compute_authenticated_mpc_payload_binding(payload) ||
            observation.registry_commitment !=
                certificate.registry_commitment ||
            observation.observation_binding !=
                compute_authenticated_mpc_signed_envelope_observation_binding(
                    observation))
            return false;
        if (payload[8] != 0) {
            ++failure_count;
            if (sender != certificate.accused_dealer ||
                payload[8] != certificate.failure_code)
                return false;
        }
    }
    if (failure_count != 1) return false;
    for (bool value : seen) if (!value) return false;
    return certificate.certificate_binding ==
        compute_reference_multiplication_failure_certificate_binding(
            certificate);
}

std::vector<u64> encode_reference_multiplication_failure_certificate(
    const ReferenceMultiplicationFailureCertificate& certificate) {
    if (!validate_reference_multiplication_failure_certificate(certificate) ||
        certificate.event.world_size > MUL_FAILURE_CERT_MAX_PARTICIPANTS)
        return {};
    std::vector<u64> words = {
        MUL_FAILURE_CERT_CODEC_DOMAIN, MUL_FAILURE_CERT_CODEC_VERSION, 1ULL,
        certificate.event.sid, certificate.event.checkpoint,
        certificate.event.multiplication_id, certificate.event.world_size,
        certificate.event.threshold};
    append_digest(certificate.event.lhs_sharing_binding, &words);
    append_digest(certificate.event.rhs_sharing_binding, &words);
    append_digest(certificate.event.joint_seed, &words);
    append_digest(certificate.event.joint_seed_binding, &words);
    words.push_back(certificate.event.syndrome.real);
    words.push_back(certificate.event.syndrome.img);
    append_digest(certificate.event.syndrome_opening_binding, &words);
    words.push_back(static_cast<u64>(
        certificate.event.output_sharing_bindings.size()));
    for (const Digest& binding :
         certificate.event.output_sharing_bindings)
        append_digest(binding, &words);
    append_digest(certificate.event.event_binding, &words);
    words.push_back(certificate.accused_dealer);
    words.push_back(certificate.failure_code);
    append_mpc_context(certificate.status_context, &words);
    words.push_back(static_cast<u64>(certificate.status_payloads.size()));
    for (const auto& payload : certificate.status_payloads) {
        if (payload.empty() ||
            payload.size() > MUL_FAILURE_CERT_MAX_PAYLOAD_WORDS)
            return {};
        words.push_back(static_cast<u64>(payload.size()));
        words.insert(words.end(), payload.begin(), payload.end());
    }
    words.push_back(static_cast<u64>(certificate.status_observations.size()));
    for (const auto& observation : certificate.status_observations)
        append_signed_observation(observation, &words);
    append_digest(certificate.registry_commitment, &words);
    append_digest(certificate.certificate_binding, &words);
    return words;
}

bool decode_reference_multiplication_failure_certificate(
    const std::vector<u64>& words,
    ReferenceMultiplicationFailureCertificate* certificate) {
    if (!certificate || words.size() < 3 + 5 + 4*4 + 2 + 4 + 1 + 4 +
            2 + 6 + 1 + 1 + 30 + 4 + 4)
        return false;
    size_t cursor = 0;
    u64 magic = 0, version = 0, available = 0;
    ReferenceMultiplicationFailureCertificate decoded;
    u64 world_size = 0, threshold = 0;
    if (!take_word(words, &cursor, &magic) ||
        !take_word(words, &cursor, &version) ||
        !take_word(words, &cursor, &available) ||
        magic != MUL_FAILURE_CERT_CODEC_DOMAIN ||
        version != MUL_FAILURE_CERT_CODEC_VERSION || available != 1 ||
        !take_word(words, &cursor, &decoded.event.sid) ||
        !take_word(words, &cursor, &decoded.event.checkpoint) ||
        !take_word(words, &cursor, &decoded.event.multiplication_id) ||
        !take_word(words, &cursor, &world_size) ||
        !take_word(words, &cursor, &threshold) ||
        world_size < 4 || world_size > MUL_FAILURE_CERT_MAX_PARTICIPANTS ||
        threshold > std::numeric_limits<uint32_t>::max())
        return false;
    decoded.available = true;
    decoded.event.world_size = static_cast<uint32_t>(world_size);
    decoded.event.threshold = static_cast<uint32_t>(threshold);
    if (!take_digest(words, &cursor, &decoded.event.lhs_sharing_binding) ||
        !take_digest(words, &cursor, &decoded.event.rhs_sharing_binding) ||
        !take_digest(words, &cursor, &decoded.event.joint_seed) ||
        !take_digest(words, &cursor, &decoded.event.joint_seed_binding))
        return false;
    if (!take_word(words, &cursor, &decoded.event.syndrome.real) ||
        !take_word(words, &cursor, &decoded.event.syndrome.img) ||
        decoded.event.syndrome.real >= F::mod ||
        decoded.event.syndrome.img >= F::mod ||
        !take_digest(words, &cursor,
                     &decoded.event.syndrome_opening_binding))
        return false;
    u64 output_count = 0;
    if (!take_word(words, &cursor, &output_count) ||
        output_count != world_size ||
        output_count > MUL_FAILURE_CERT_MAX_PARTICIPANTS)
        return false;
    decoded.event.output_sharing_bindings.resize(
        static_cast<size_t>(output_count));
    for (auto& binding : decoded.event.output_sharing_bindings)
        if (!take_digest(words, &cursor, &binding)) return false;
    if (!take_digest(words, &cursor, &decoded.event.event_binding))
        return false;
    u64 accused = 0;
    if (!take_word(words, &cursor, &accused) ||
        accused > std::numeric_limits<uint32_t>::max() ||
        !take_word(words, &cursor, &decoded.failure_code))
        return false;
    decoded.accused_dealer = static_cast<uint32_t>(accused);
    if (!take_mpc_context(words, &cursor, &decoded.status_context))
        return false;
    u64 payload_count = 0;
    if (!take_word(words, &cursor, &payload_count) ||
        payload_count != world_size ||
        payload_count > MUL_FAILURE_CERT_MAX_PARTICIPANTS)
        return false;
    decoded.status_payloads.resize(static_cast<size_t>(payload_count));
    for (auto& payload : decoded.status_payloads) {
        u64 payload_size = 0;
        if (!take_word(words, &cursor, &payload_size) ||
            payload_size == 0 ||
            payload_size > MUL_FAILURE_CERT_MAX_PAYLOAD_WORDS ||
            payload_size > words.size() - cursor)
            return false;
        payload.assign(words.begin() + static_cast<std::ptrdiff_t>(cursor),
                       words.begin() + static_cast<std::ptrdiff_t>(
                           cursor + static_cast<size_t>(payload_size)));
        cursor += static_cast<size_t>(payload_size);
    }
    u64 observation_count = 0;
    if (!take_word(words, &cursor, &observation_count) ||
        observation_count != world_size ||
        observation_count > MUL_FAILURE_CERT_MAX_PARTICIPANTS)
        return false;
    decoded.status_observations.resize(
        static_cast<size_t>(observation_count));
    for (auto& observation : decoded.status_observations)
        if (!take_signed_observation(words, &cursor, &observation))
            return false;
    if (!take_digest(words, &cursor, &decoded.registry_commitment) ||
        !take_digest(words, &cursor, &decoded.certificate_binding) ||
        cursor != words.size() ||
        !validate_reference_multiplication_failure_certificate(decoded))
        return false;
    *certificate = std::move(decoded);
    return true;
}

Digest compute_multiplication_consistency_relation_binding() {
    const std::vector<u64> words = {
        PVIA_MC_RELATION_BINDING_DOMAIN,
        PVIA_MC_RELATION_VERSION,
        static_cast<u64>(PVIA_MC_ABI_VERSION),
        PVIA_MC_FIELD_MODULUS,
        static_cast<u64>(PVIA_MC_FIELD_COMPONENT_WORDS),
        PVIA_MC_FIELD_EXTENSION_I_SQUARED_IS_NEG_ONE,
        PVIA_MC_STATEMENT_BINDING_DOMAIN,
        PVIA_MC_STATEMENT_ABI_DOMAIN,
        static_cast<u64>(PVIA_MC_STATEMENT_WORDS),
        PVIA_MC_WITNESS_ABI_DOMAIN,
        static_cast<u64>(PVIA_MC_WITNESS_HEADER_WORDS),
        PVIA_MC_SHARING_WITNESS_DOMAIN,
        PVIA_MC_SHARING_WITNESS_VERSION,
        PVIA_MC_SHARING_KIND_VSS_LOCAL,
        PVIA_MC_SHARING_KIND_LINEAR_COMBINATION,
        PVIA_MC_SHARING_KIND_VSS_DEALER,
        PVIA_MC_VSS_TRANSCRIPT_DOMAIN,
        PVIA_MC_VSS_DEALER_WITNESS_DOMAIN,
        PVIA_MC_VSS_LOCAL_WITNESS_DOMAIN,
        PVIA_MC_VSS_WITNESS_VERSION,
        static_cast<u64>(PVIA_MC_VSS_DEALER_FIXED_WORDS),
        static_cast<u64>(PVIA_MC_VSS_LOCAL_FIXED_WORDS),
        PVIA_MC_LINEAR_BINDING_DOMAIN,
        PVIA_MC_LINEAR_WITNESS_DOMAIN,
        static_cast<u64>(PVIA_MC_LINEAR_FIXED_WORDS)};
    return hash_words(words);
}

Digest compute_multiplication_consistency_capability_binding(
    const MultiplicationConsistencyCapabilities& capabilities) {
    std::vector<u64> words = {
        MUL_CAP_DOMAIN,
        capabilities.available ? 1ULL : 0ULL,
        capabilities.malicious_sound ? 1ULL : 0ULL,
        capabilities.zero_knowledge ? 1ULL : 0ULL,
        capabilities.binds_input_sharings ? 1ULL : 0ULL,
        capabilities.binds_output_sharing ? 1ULL : 0ULL,
        capabilities.protocol_id};
    append_digest(capabilities.relation_binding, &words);
    append_digest(capabilities.implementation_binding, &words);
    return hash_words(words);
}

bool validate_multiplication_consistency_capabilities(
    const MultiplicationConsistencyCapabilities& capabilities) {
    const Digest expected_relation =
        compute_multiplication_consistency_relation_binding();
    if (!capabilities.available || capabilities.protocol_id == 0 ||
        expected_relation == Digest{} ||
        capabilities.relation_binding != expected_relation ||
        capabilities.implementation_binding == Digest{} ||
        capabilities.capability_binding == Digest{})
        return false;
    return capabilities.capability_binding ==
        compute_multiplication_consistency_capability_binding(capabilities);
}
bool production_ready_multiplication_consistency_capabilities(
    const MultiplicationConsistencyCapabilities& capabilities) {
    return validate_multiplication_consistency_capabilities(capabilities) &&
        capabilities.malicious_sound && capabilities.zero_knowledge &&
        capabilities.binds_input_sharings &&
        capabilities.binds_output_sharing;
}

MultiplicationConsistencyCapabilities
FailClosedMultiplicationConsistencyProofBackend::Capabilities() const {
    return MultiplicationConsistencyCapabilities{};
}

MultiplicationConsistencyProofArtifact
FailClosedMultiplicationConsistencyProofBackend::Prove(
    const MultiplicationConsistencyStatement& statement,
    const MultiplicationConsistencyWitness&) const {
    MultiplicationConsistencyProofArtifact proof;
    proof.statement_binding = statement.statement_binding;
    return proof;
}

bool FailClosedMultiplicationConsistencyProofBackend::Verify(
    const MultiplicationConsistencyStatement&,
    const MultiplicationConsistencyProofArtifact&) const {
    return false;
}

} // namespace pvia
