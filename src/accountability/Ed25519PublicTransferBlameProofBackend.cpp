#include "Ed25519PublicTransferBlameProofBackend.hpp"

#include "TransferAuthentication.hpp"

#include <array>
#include <cstring>
#include <vector>

namespace pvia {
namespace {

constexpr uint32_t PROOF_SYSTEM_ID = 0x50544532U; // PTE2
constexpr u64 TRANSCRIPT_DOMAIN = 0x5054453254524e53ULL; // PTE2TRNS
constexpr u64 ENVELOPE_MAGIC = 0x5054453252454732ULL; // PTE2REG2
constexpr u64 ENVELOPE_VERSION = 2;
constexpr size_t ENVELOPE_HEADER_WORDS = 8;

struct ProofEnvelope {
    std::vector<std::array<uint8_t, 32>> public_keys;
    Digest registry_commitment{};
    std::vector<u64> evidence_words;
};

Digest ed25519_transfer_blame_engine_binding(u64 domain) {
    auto& auth = Ed25519TransferAuthenticator::instance();
    const auto signature_capabilities = auth.SignatureCapabilities();
    const Digest registry = auth.RegistryCommitment();
    const Digest anchor = auth.ExternalRegistryAnchor();
    if (!auth.ready() || !auth.ExternalRegistryAnchorVerified() ||
        registry == Digest{} || anchor != registry ||
        !validate_accountability_signature_capabilities(
            signature_capabilities))
        return {};
    std::vector<u64> words = {
        domain, static_cast<u64>(auth.world_size()),
        signature_capabilities.scheme_id,
        static_cast<u64>(signature_capabilities.public_key_bytes),
        static_cast<u64>(signature_capabilities.signature_bytes)};
    for (const Digest* digest : {
             &registry, &anchor,
             &signature_capabilities.implementation_binding,
             &signature_capabilities.capability_binding}) {
        for (size_t i = 0; i < 4; ++i) {
            u64 word = 0;
            std::memcpy(&word, digest->bytes.data() + 8 * i, 8);
            words.push_back(word);
        }
    }
    return hash_words(words);
}

Digest load_digest(const std::vector<u64>& words, size_t offset) {
    Digest digest;
    std::memcpy(digest.bytes.data(), words.data() + offset,
                digest.bytes.size());
    return digest;
}

void append_digest_words(const Digest& digest, std::vector<u64>* words) {
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

std::vector<u64> encode_envelope(const ProofEnvelope& envelope) {
    if (envelope.public_keys.empty() ||
        envelope.registry_commitment == Digest{} ||
        envelope.evidence_words.empty())
        return {};
    std::vector<u64> words = {
        ENVELOPE_MAGIC,
        ENVELOPE_VERSION,
        static_cast<u64>(envelope.public_keys.size()),
        static_cast<u64>(envelope.evidence_words.size())
    };
    append_digest_words(envelope.registry_commitment, &words);
    for (const auto& key : envelope.public_keys) {
        for (size_t i = 0; i < 4; ++i) {
            u64 word = 0;
            std::memcpy(&word, key.data() + 8 * i, 8);
            words.push_back(word);
        }
    }
    words.insert(words.end(), envelope.evidence_words.begin(),
                 envelope.evidence_words.end());
    return words;
}

bool decode_envelope(const std::vector<u64>& words, ProofEnvelope* envelope) {
    if (!envelope || words.size() < ENVELOPE_HEADER_WORDS ||
        words[0] != ENVELOPE_MAGIC || words[1] != ENVELOPE_VERSION)
        return false;
    const size_t key_count = static_cast<size_t>(words[2]);
    const size_t evidence_count = static_cast<size_t>(words[3]);
    if (key_count == 0 || evidence_count == 0) return false;
    const size_t expected = ENVELOPE_HEADER_WORDS + key_count * 4 + evidence_count;
    if (words.size() != expected) return false;
    ProofEnvelope out;
    out.registry_commitment = load_digest(words, 4);
    if (out.registry_commitment == Digest{}) return false;
    out.public_keys.resize(key_count);
    size_t cursor = ENVELOPE_HEADER_WORDS;
    for (size_t i = 0; i < key_count; ++i) {
        for (size_t j = 0; j < 4; ++j)
            std::memcpy(out.public_keys[i].data() + 8 * j,
                        &words[cursor + j], 8);
        cursor += 4;
    }
    out.evidence_words.assign(words.begin() + cursor, words.end());
    if (compute_ed25519_registry_commitment(out.public_keys) !=
        out.registry_commitment)
        return false;
    *envelope = out;
    return true;
}

bool decode_transfer_evidence_with_public_key(
    const std::vector<u64>& words,
    const std::array<uint8_t, 32>& public_key,
    PublicTransferEvidence* evidence) {
    if (!evidence || words.size() < 65) return false;
    const size_t observation_words = static_cast<size_t>(words[64]);
    if (observation_words != PUBLIC_TRANSFER_OBSERVATION_WORDS ||
        words.size() != 65 + observation_words)
        return false;

    PublicTransferEvidence out;
    out.available = words[0] != 0;
    out.cryptographically_authenticated = words[1] != 0;
    out.accused.owner = static_cast<uint32_t>(words[2]);
    out.accused.object_id = words[3];
    out.label.sid = words[4];
    out.label.phase = static_cast<Phase>(static_cast<uint32_t>(words[5]));
    out.label.round = static_cast<uint32_t>(words[6]);
    out.label.owner = static_cast<uint32_t>(words[7]);
    out.label.obligation = static_cast<Obligation>(static_cast<uint32_t>(words[8]));
    out.label.object_id = words[9];
    out.checkpoint = words[10];
    out.relation = static_cast<RelationKind>(static_cast<uint32_t>(words[11]));
    out.expected = load_digest(words, 12);
    out.actual = load_digest(words, 16);
    out.residual_commitment = load_digest(words, 20);
    out.operation_statement_binding = load_digest(words, 24);
    out.dispute_binding = load_digest(words, 28);
    out.checkpoint_root = load_digest(words, 32);
    out.scope_binding = load_digest(words, 36);
    out.batch_check_binding = load_digest(words, 40);
    out.transfer_transcript_binding = load_digest(words, 44);
    out.authentication_commitment = load_digest(words, 48);
    out.recursive_transcript_binding = load_digest(words, 52);
    out.localization_commitment = load_digest(words, 56);
    out.observation_binding = load_digest(words, 60);

    std::vector<u64> observation_words_vec(words.begin() + 65, words.end());
    if (!decode_public_transfer_observation_unchecked(
            observation_words_vec, &out.observation))
        return false;
    out.evidence_binding = compute_public_transfer_evidence_binding(out);
    if (!validate_public_transfer_evidence_claim_with_public_key(
            out, public_key))
        return false;
    *evidence = out;
    return true;
}

PublicBlameStatement statement_from_evidence(
    const PublicTransferEvidence& evidence,
    const std::array<uint8_t, 32>& public_key) {
    PublicBlameStatement statement;
    if (!validate_public_transfer_evidence_claim_with_public_key(
            evidence, public_key))
        return statement;
    statement.sid = evidence.label.sid;
    statement.accused = evidence.accused;
    statement.label = evidence.label;
    statement.checkpoint = evidence.checkpoint;
    statement.relation = evidence.relation;
    statement.kernel = AuditRelationKernel::UNKNOWN;
    statement.evidence_kind = AuditEvidenceKind::PUBLIC_TRANSFER;
    statement.expected = evidence.expected;
    statement.actual = evidence.actual;
    statement.residual_commitment = evidence.residual_commitment;
    statement.operation_statement_binding = evidence.operation_statement_binding;
    statement.dispute_binding = evidence.dispute_binding;
    statement.audit_evidence_binding = evidence.evidence_binding;
    statement.predecessor_root = Digest{};
    statement.checkpoint_root = evidence.checkpoint_root;
    statement.statement_binding = compute_public_blame_statement_binding(statement);
    return statement;
}

Digest compute_transparent_transcript(
    const std::vector<u64>& public_inputs,
    const std::vector<u64>& proof_words,
    const Digest& registry_binding) {
    if (registry_binding == Digest{}) return Digest{};
    const Digest public_inputs_binding = hash_words(public_inputs);
    const Digest proof_words_binding = hash_words(proof_words);
    std::vector<u64> words = {
        TRANSCRIPT_DOMAIN,
        static_cast<u64>(public_inputs.size()),
        static_cast<u64>(proof_words.size())
    };
    append_digest_words(public_inputs_binding, &words);
    append_digest_words(proof_words_binding, &words);
    append_digest_words(registry_binding, &words);
    return hash_words(words);
}

bool decode_and_match(
    const std::vector<u64>& public_inputs,
    const std::vector<u64>& proof_words,
    const Digest* expected_registry,
    PublicTransferEvidence* evidence,
    ProofEnvelope* decoded_envelope) {
    ProofEnvelope envelope;
    if (!decode_envelope(proof_words, &envelope)) return false;
    if (expected_registry &&
        (*expected_registry == Digest{} ||
         envelope.registry_commitment != *expected_registry))
        return false;

    if (envelope.evidence_words.size() < 10) return false;
    const uint32_t signer = static_cast<uint32_t>(envelope.evidence_words[7]);
    if (signer >= envelope.public_keys.size()) return false;
    PublicTransferEvidence decoded;
    if (!decode_transfer_evidence_with_public_key(
            envelope.evidence_words, envelope.public_keys[signer], &decoded))
        return false;
    const PublicBlameStatement statement = statement_from_evidence(
        decoded, envelope.public_keys[signer]);
    if (statement.statement_binding == Digest{} ||
        encode_public_blame_statement(statement) != public_inputs)
        return false;
    if (evidence) *evidence = decoded;
    if (decoded_envelope) *decoded_envelope = envelope;
    return true;
}

} // namespace

Digest Ed25519PublicTransferBlameProofBackend::ProductionCapabilityBinding() const {
    return ed25519_transfer_blame_engine_binding(0x50565452424c5031ULL);
}

ExternalPublicBlameProof Ed25519PublicTransferBlameProofBackend::Prove(
    const std::vector<u64>& public_inputs,
    const std::vector<u64>& transfer_evidence) const {
    ExternalPublicBlameProof proof;
    const auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.ready() || auth.RegistryCommitment() == Digest{} ||
        auth.PublicKeys().empty())
        return proof;

    ProofEnvelope envelope;
    envelope.public_keys = auth.PublicKeys();
    envelope.registry_commitment = auth.RegistryCommitment();
    envelope.evidence_words = transfer_evidence;
    const std::vector<u64> proof_words = encode_envelope(envelope);
    if (proof_words.empty()) return proof;

    PublicTransferEvidence evidence;
    if (!decode_and_match(public_inputs, proof_words,
                          &envelope.registry_commitment, &evidence, nullptr))
        return proof;
    const Digest transcript = compute_transparent_transcript(
        public_inputs, proof_words, envelope.registry_commitment);
    if (transcript == Digest{}) return proof;
    proof.available = true;
    proof.cryptographically_authenticated = true;
    proof.proof_system_id = PROOF_SYSTEM_ID;
    proof.transcript_binding = transcript;
    proof.proof_words = proof_words;
    return proof;
}

bool Ed25519PublicTransferBlameProofBackend::Verify(
    const std::vector<u64>& public_inputs,
    const ExternalPublicBlameProof& proof) const {
    if (!proof.available || !proof.cryptographically_authenticated ||
        proof.proof_system_id != PROOF_SYSTEM_ID ||
        proof.transcript_binding == Digest{} || proof.proof_words.empty())
        return false;
    const auto& auth = Ed25519TransferAuthenticator::instance();
    const Digest current_registry = auth.RegistryCommitment();
    if (!auth.ready() || current_registry == Digest{}) return false;
    ProofEnvelope envelope;
    if (!decode_and_match(public_inputs, proof.proof_words,
                          &current_registry, nullptr, &envelope))
        return false;
    return proof.transcript_binding == compute_transparent_transcript(
        public_inputs, proof.proof_words, envelope.registry_commitment);
}

bool Ed25519PublicTransferBlameProofBackend::VerifyAnchored(
    const std::vector<u64>& public_inputs,
    const ExternalPublicBlameProof& proof,
    const Digest& expected_registry_anchor) const {
    if (!proof.available || !proof.cryptographically_authenticated ||
        proof.proof_system_id != PROOF_SYSTEM_ID ||
        proof.transcript_binding == Digest{} || proof.proof_words.empty() ||
        expected_registry_anchor == Digest{})
        return false;
    ProofEnvelope envelope;
    if (!decode_and_match(public_inputs, proof.proof_words,
                          &expected_registry_anchor, nullptr, &envelope))
        return false;
    return proof.transcript_binding == compute_transparent_transcript(
        public_inputs, proof.proof_words, envelope.registry_commitment);
}

} // namespace pvia
