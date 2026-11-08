#include "PublicBlameProof.hpp"
#include "PublicTransferEvidence.hpp"
#include "Sp1VssRecoveryProofProvider.hpp"

#include <cstring>
#include <limits>

namespace pvia {
namespace {

constexpr u64 PRIVATE_BLAME_CERT_MAGIC = 0x5056494150424331ULL; // PVIAPBC1
constexpr u64 PRIVATE_BLAME_CERT_LEGACY_VERSION = 1;
constexpr u64 PRIVATE_BLAME_CERT_VERSION = 2;
constexpr u64 PRIVATE_RECOVERY_PROOF_PAYLOAD_MAGIC = 0x5056525052594431ULL;
constexpr size_t PRIVATE_BLAME_CERT_FIXED_WORDS = 72;
constexpr size_t PRIVATE_BLAME_CERT_MAX_VECTOR_WORDS = 1ULL << 20;

void append_digest_words(const Digest& digest, std::vector<u64>& words) {
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words.push_back(word);
    }
}

Digest load_digest_words(const std::vector<u64>& words, size_t offset) {
    Digest digest{};
    if (offset > words.size() || words.size() - offset < 4) return digest;
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(digest.bytes.data() + i * 8, &words[offset + i], 8);
    return digest;
}

bool inspect_recovery_proof_artifact(
    const std::vector<uint8_t>& bytes,
    const std::vector<u64>& expected_statement,
    uint32_t* proof_system_id,
    Digest* statement_binding,
    Digest* artifact_commitment) {
    constexpr size_t kHeaderWords = 18;
    constexpr size_t kStatementWords = 85;
    constexpr size_t kHeaderBytes = kHeaderWords * 8;
    constexpr uint64_t kMagic = 0x5056524350524631ULL;
    if (bytes.size() < kHeaderBytes + kStatementWords * 8 ||
        expected_statement.size() != kStatementWords)
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
        header[17] != 68103 || header[4] != kStatementWords ||
        header[2] == 0 || header[2] > (1ULL << 30) ||
        header[2] != bytes.size() - kHeaderBytes - kStatementWords * 8 ||
        header[3] != kHeaderWords + kStatementWords + (header[2] + 7) / 8)
        return false;
    for (size_t i = 0; i < kStatementWords; ++i) {
        uint64_t embedded = 0;
        if (!read_word(kHeaderBytes + i * 8, &embedded) ||
            embedded != static_cast<uint64_t>(expected_statement[i]))
            return false;
    }
    auto load_digest = [&header](size_t offset) {
        Digest digest{};
        for (size_t i = 0; i < 4; ++i)
            for (size_t j = 0; j < 8; ++j)
                digest.bytes[i * 8 + j] =
                    static_cast<uint8_t>(header[offset + i] >> (8 * j));
        return digest;
    };
    if (proof_system_id) *proof_system_id = static_cast<uint32_t>(header[17]);
    if (statement_binding) *statement_binding = load_digest(5);
    if (artifact_commitment) *artifact_commitment = load_digest(13);
    return (!statement_binding || *statement_binding != Digest{}) &&
           (!artifact_commitment || *artifact_commitment != Digest{});
}


OperationRef ref_from_label(const Label& label) {
    return OperationRef{label.owner, label.object_id};
}

bool is_public_transfer_relation(RelationKind relation) {
    return relation == RelationKind::MESSAGE_BINDING ||
           relation == RelationKind::RECEIVE_CONSUME;
}

} // namespace

std::vector<u64> encode_public_blame_statement(
    const PublicBlameStatement& statement) {
    std::vector<u64> words = {
        statement.sid,
        statement.accused.owner,
        statement.accused.object_id,
        static_cast<u64>(statement.label.phase),
        statement.label.round,
        statement.label.owner,
        static_cast<u64>(statement.label.obligation),
        statement.label.object_id,
        statement.checkpoint,
        static_cast<u64>(statement.relation),
        static_cast<u64>(statement.kernel),
        static_cast<u64>(statement.evidence_kind)
    };
    append_digest_words(statement.expected, words);
    append_digest_words(statement.actual, words);
    append_digest_words(statement.residual_commitment, words);
    append_digest_words(statement.operation_statement_binding, words);
    append_digest_words(statement.dispute_binding, words);
    append_digest_words(statement.audit_evidence_binding, words);
    append_digest_words(statement.predecessor_root, words);
    append_digest_words(statement.checkpoint_root, words);
    return words;
}

Digest compute_public_blame_statement_binding(
    const PublicBlameStatement& statement) {
    return hash_words(encode_public_blame_statement(statement));
}

PublicBlameStatement make_public_blame_statement(
    const Violation& violation,
    const RecoverableAuditShare& audit,
    const AuthenticatedRecoveryArtifact& recovery) {
    PublicBlameStatement statement;
    if (!violation.valid || !audit.valid ||
        audit.evidence_kind != AuditEvidenceKind::PRIVATE_RECOVERY ||
        is_public_transfer_relation(violation.relation) ||
        audit.witness_digest != compute_recovery_artifact_binding(recovery) ||
        audit.predecessor_root != recovery.predecessor_root ||
        audit.checkpoint_root != recovery.checkpoint_root)
        return statement;
    statement.sid = violation.label.sid;
    statement.accused = ref_from_label(violation.label);
    statement.label = violation.label;
    statement.checkpoint = violation.checkpoint;
    statement.relation = violation.relation;
    statement.kernel = violation.kernel;
    statement.evidence_kind = AuditEvidenceKind::PRIVATE_RECOVERY;
    statement.expected = violation.expected;
    statement.actual = violation.actual;
    statement.residual_commitment = violation.residual_commitment;
    statement.operation_statement_binding = violation.operation_statement_binding;
    statement.dispute_binding = violation.dispute_binding;
    statement.audit_evidence_binding =
        compute_recovery_artifact_binding(recovery);
    statement.predecessor_root = audit.predecessor_root;
    statement.checkpoint_root = audit.checkpoint_root;
    statement.statement_binding =
        compute_public_blame_statement_binding(statement);
    return statement;
}

PublicBlameStatement make_public_blame_statement(
    const Violation& violation,
    const RecoverableAuditShare& audit,
    const PublicTransferEvidence& evidence) {
    PublicBlameStatement statement;
    if (!violation.valid || !audit.valid || !evidence.available ||
        !evidence.cryptographically_authenticated ||
        audit.evidence_kind != AuditEvidenceKind::PUBLIC_TRANSFER ||
        !is_public_transfer_relation(violation.relation) ||
        violation.kernel != AuditRelationKernel::UNKNOWN ||
        evidence.accused != ref_from_label(violation.label) ||
        evidence.label.sid != violation.label.sid ||
        evidence.label.phase != violation.label.phase ||
        evidence.label.round != violation.label.round ||
        evidence.label.owner != violation.label.owner ||
        evidence.label.obligation != violation.label.obligation ||
        evidence.label.object_id != violation.label.object_id ||
        evidence.checkpoint != violation.checkpoint ||
        evidence.relation != violation.relation ||
        evidence.expected != violation.expected ||
        evidence.actual != violation.actual ||
        evidence.residual_commitment != violation.residual_commitment ||
        evidence.operation_statement_binding != violation.operation_statement_binding ||
        evidence.dispute_binding != violation.dispute_binding ||
        audit.predecessor_root != Digest{} ||
        audit.checkpoint_root != evidence.checkpoint_root ||
        audit.witness_digest != evidence.evidence_binding ||
        !validate_public_transfer_evidence_claim(evidence))
        return statement;
    statement.sid = violation.label.sid;
    statement.accused = ref_from_label(violation.label);
    statement.label = violation.label;
    statement.checkpoint = violation.checkpoint;
    statement.relation = violation.relation;
    statement.kernel = violation.kernel;
    statement.evidence_kind = AuditEvidenceKind::PUBLIC_TRANSFER;
    statement.expected = violation.expected;
    statement.actual = violation.actual;
    statement.residual_commitment = violation.residual_commitment;
    statement.operation_statement_binding = violation.operation_statement_binding;
    statement.dispute_binding = violation.dispute_binding;
    statement.audit_evidence_binding = evidence.evidence_binding;
    statement.predecessor_root = audit.predecessor_root;
    statement.checkpoint_root = audit.checkpoint_root;
    statement.statement_binding =
        compute_public_blame_statement_binding(statement);
    return statement;
}

PublicBlameStatement make_public_blame_statement(
    const BlameCertificate& certificate) {
    PublicBlameStatement statement;
    if (!certificate.valid || certificate.debug_only) return statement;
    if (certificate.evidence_kind == AuditEvidenceKind::PRIVATE_RECOVERY) {
        AuthenticatedRecoveryArtifact recovery;
        const AuthenticatedRecoveryRequest request =
            make_recovery_request(certificate);
        if (certificate.recovery_artifact_words.empty() ||
            request.request_binding == Digest{} ||
            !decode_authenticated_recovery_artifact(
                certificate.recovery_artifact_words, &recovery) ||
            !validate_recovery_artifact(request, recovery) ||
            compute_recovery_artifact_binding(recovery) !=
                certificate.audit_witness_digest ||
            recovery.accused != OperationRef{
                certificate.label.owner, certificate.label.object_id} ||
            recovery.predecessor_root != certificate.predecessor_root ||
            recovery.checkpoint_root != certificate.checkpoint_root)
            return statement;
    } else if (certificate.evidence_kind == AuditEvidenceKind::PUBLIC_TRANSFER) {
        if (!certificate.recovery_artifact_words.empty()) return statement;
    } else {
        return statement;
    }
    statement.sid = certificate.sid;
    statement.accused = OperationRef{
        certificate.accused, certificate.label.object_id};
    statement.label = certificate.label;
    statement.checkpoint = certificate.checkpoint;
    statement.relation = certificate.relation;
    statement.kernel = certificate.kernel;
    statement.evidence_kind = certificate.evidence_kind;
    statement.expected = certificate.expected;
    statement.actual = certificate.actual;
    statement.residual_commitment = certificate.residual_commitment;
    statement.operation_statement_binding = certificate.operation_statement_binding;
    statement.dispute_binding = certificate.dispute_binding;
    statement.audit_evidence_binding = certificate.audit_witness_digest;
    statement.predecessor_root = certificate.predecessor_root;
    statement.checkpoint_root = certificate.checkpoint_root;
    statement.statement_binding =
        compute_public_blame_statement_binding(statement);
    return statement;
}

Digest compute_public_blame_proof_commitment(
    const PublicBlameProofArtifact& artifact) {
    std::vector<u64> words = {
        artifact.available ? 1ULL : 0ULL,
        artifact.cryptographically_authenticated ? 1ULL : 0ULL,
        artifact.proof_system_id,
        static_cast<u64>(artifact.proof_words.size())
    };
    append_digest_words(artifact.statement_binding, words);
    append_digest_words(artifact.transcript_binding, words);
    words.insert(words.end(), artifact.proof_words.begin(),
                 artifact.proof_words.end());
    const bool has_recovery_proof =
        artifact.recovery_proof_system_id != 0 ||
        artifact.recovery_proof_statement_binding != Digest{} ||
        artifact.recovery_proof_artifact_commitment != Digest{} ||
        !artifact.recovery_proof_statement_words.empty() ||
        !artifact.recovery_proof_artifact_bytes.empty();
    if (has_recovery_proof) {
        words.push_back(artifact.recovery_proof_system_id);
        append_digest_words(artifact.recovery_proof_statement_binding, words);
        append_digest_words(artifact.recovery_proof_artifact_commitment, words);
        words.push_back(static_cast<u64>(
            artifact.recovery_proof_statement_words.size()));
        words.insert(words.end(),
                     artifact.recovery_proof_statement_words.begin(),
                     artifact.recovery_proof_statement_words.end());
        words.push_back(static_cast<u64>(
            artifact.recovery_proof_artifact_bytes.size()));
        for (size_t offset = 0;
             offset < artifact.recovery_proof_artifact_bytes.size(); offset += 8) {
            u64 word = 0;
            for (size_t j = 0; j < 8 &&
                 offset + j < artifact.recovery_proof_artifact_bytes.size(); ++j)
                word |= static_cast<u64>(
                    artifact.recovery_proof_artifact_bytes[offset + j]) << (8 * j);
            words.push_back(word);
        }
    }
    return hash_words(words);
}

bool validate_public_blame_proof_artifact(
    const PublicBlameStatement& statement,
    const PublicBlameProofArtifact& artifact) {
    if (!artifact.available || !artifact.cryptographically_authenticated ||
        artifact.proof_system_id == 0)
        return false;
    if (statement.statement_binding == Digest{} ||
        statement.statement_binding !=
            compute_public_blame_statement_binding(statement))
        return false;
    if (artifact.statement_binding != statement.statement_binding ||
        artifact.transcript_binding == Digest{} || artifact.proof_words.empty())
        return false;
    if (statement.sid == 0 || statement.label.sid != statement.sid ||
        statement.accused != ref_from_label(statement.label) ||
        statement.checkpoint == 0 || statement.relation == RelationKind::UNKNOWN ||
        statement.evidence_kind == AuditEvidenceKind::UNKNOWN)
        return false;
    if (statement.kernel != AuditRelationKernel::UNKNOWN &&
        relation_for_kernel(statement.kernel) != statement.relation)
        return false;
    if (statement.kernel == AuditRelationKernel::UNKNOWN &&
        statement.relation == RelationKind::PRIVATE_DERIVATION)
        return false;
    if (statement.evidence_kind == AuditEvidenceKind::PUBLIC_TRANSFER) {
        if (!is_public_transfer_relation(statement.relation) ||
            statement.kernel != AuditRelationKernel::UNKNOWN ||
            statement.predecessor_root != Digest{})
            return false;
    } else if (statement.evidence_kind == AuditEvidenceKind::PRIVATE_RECOVERY) {
        if (is_public_transfer_relation(statement.relation))
            return false;
    } else {
        return false;
    }
    if (statement.operation_statement_binding == Digest{} ||
        statement.dispute_binding == Digest{} ||
        statement.audit_evidence_binding == Digest{} ||
        statement.checkpoint_root == Digest{})
        return false;
    const bool has_recovery_proof =
        artifact.recovery_proof_system_id != 0 ||
        artifact.recovery_proof_statement_binding != Digest{} ||
        artifact.recovery_proof_artifact_commitment != Digest{} ||
        !artifact.recovery_proof_statement_words.empty() ||
        !artifact.recovery_proof_artifact_bytes.empty();
    if (statement.evidence_kind == AuditEvidenceKind::PUBLIC_TRANSFER &&
        has_recovery_proof)
        return false;
    if (has_recovery_proof) {
        if (statement.evidence_kind != AuditEvidenceKind::PRIVATE_RECOVERY ||
            artifact.recovery_proof_system_id != 68103 ||
            artifact.recovery_proof_statement_binding == Digest{} ||
            artifact.recovery_proof_artifact_commitment == Digest{} ||
            artifact.recovery_proof_statement_words.size() != 85 ||
            artifact.recovery_proof_artifact_bytes.empty())
            return false;
        uint32_t parsed_system_id = 0;
        Digest parsed_statement_binding{};
        Digest parsed_artifact_commitment{};
        if (!inspect_recovery_proof_artifact(
                artifact.recovery_proof_artifact_bytes,
                artifact.recovery_proof_statement_words,
                &parsed_system_id, &parsed_statement_binding,
                &parsed_artifact_commitment) ||
            parsed_system_id != artifact.recovery_proof_system_id ||
            parsed_statement_binding != artifact.recovery_proof_statement_binding ||
            parsed_artifact_commitment != artifact.recovery_proof_artifact_commitment)
            return false;
    }
    return artifact.proof_commitment ==
           compute_public_blame_proof_commitment(artifact);
}


std::vector<u64> encode_private_recovery_blame_certificate(
    const BlameCertificate& certificate) {
    if (!certificate.valid || certificate.debug_only ||
        certificate.evidence_kind != AuditEvidenceKind::PRIVATE_RECOVERY ||
        !certificate.predecessor_evidence.empty() ||
        !certificate.checkpoint_evidence.empty() ||
        certificate.predecessor_evidence_complete ||
        certificate.recovery_artifact_words.empty() ||
        certificate.public_proof_words.empty())
        return {};
    const PublicBlameStatement statement =
        make_public_blame_statement(certificate);
    if (statement.statement_binding == Digest{} ||
        statement.statement_binding != certificate.blame_statement_binding)
        return {};

    const bool has_recovery_proof =
        certificate.recovery_proof_system_id != 0 ||
        certificate.recovery_proof_statement_binding != Digest{} ||
        certificate.recovery_proof_artifact_commitment != Digest{} ||
        !certificate.recovery_proof_statement_words.empty() ||
        !certificate.recovery_proof_artifact_bytes.empty();
    std::vector<u64> recovery_payload;
    u64 codec_version = PRIVATE_BLAME_CERT_LEGACY_VERSION;
    if (has_recovery_proof) {
        if (certificate.recovery_proof_system_id != 68103 ||
            certificate.recovery_proof_statement_binding == Digest{} ||
            certificate.recovery_proof_artifact_commitment == Digest{} ||
            certificate.recovery_proof_statement_words.size() != 85 ||
            certificate.recovery_proof_artifact_bytes.empty() ||
            certificate.recovery_proof_artifact_bytes.size() >
                PRIVATE_BLAME_CERT_MAX_VECTOR_WORDS * sizeof(u64))
            return {};
        codec_version = PRIVATE_BLAME_CERT_VERSION;
        recovery_payload = {
            PRIVATE_RECOVERY_PROOF_PAYLOAD_MAGIC, 1ULL,
            static_cast<u64>(certificate.recovery_artifact_words.size()),
            static_cast<u64>(certificate.recovery_proof_system_id),
            static_cast<u64>(certificate.recovery_proof_statement_words.size()),
            static_cast<u64>(certificate.recovery_proof_artifact_bytes.size())
        };
        recovery_payload.insert(
            recovery_payload.end(),
            certificate.recovery_artifact_words.begin(),
            certificate.recovery_artifact_words.end());
        recovery_payload.insert(
            recovery_payload.end(),
            certificate.recovery_proof_statement_words.begin(),
            certificate.recovery_proof_statement_words.end());
        for (size_t offset = 0;
             offset < certificate.recovery_proof_artifact_bytes.size();
             offset += 8) {
            u64 word = 0;
            for (size_t j = 0; j < 8 &&
                 offset + j < certificate.recovery_proof_artifact_bytes.size(); ++j)
                word |= static_cast<u64>(
                    certificate.recovery_proof_artifact_bytes[offset + j]) << (8 * j);
            recovery_payload.push_back(word);
        }
    } else {
        if (certificate.recovery_proof_statement_binding != Digest{} ||
            certificate.recovery_proof_artifact_commitment != Digest{} ||
            !certificate.recovery_proof_statement_words.empty() ||
            !certificate.recovery_proof_artifact_bytes.empty())
            return {};
        recovery_payload = certificate.recovery_artifact_words;
    }
    if (recovery_payload.empty() ||
        recovery_payload.size() > PRIVATE_BLAME_CERT_MAX_VECTOR_WORDS)
        return {};

    PublicBlameProofArtifact proof;
    proof.available = true;
    proof.cryptographically_authenticated = true;
    proof.proof_system_id = certificate.public_proof_system_id;
    proof.statement_binding = certificate.blame_statement_binding;
    proof.proof_commitment = certificate.public_proof_commitment;
    proof.transcript_binding = certificate.public_proof_transcript_binding;
    proof.proof_words = certificate.public_proof_words;
    proof.recovery_proof_system_id = certificate.recovery_proof_system_id;
    proof.recovery_proof_statement_binding =
        certificate.recovery_proof_statement_binding;
    proof.recovery_proof_artifact_commitment =
        certificate.recovery_proof_artifact_commitment;
    proof.recovery_proof_statement_words =
        certificate.recovery_proof_statement_words;
    proof.recovery_proof_artifact_bytes =
        certificate.recovery_proof_artifact_bytes;
    if (!validate_public_blame_proof_artifact(statement, proof) ||
        certificate.proof_digest != certificate.public_proof_commitment ||
        certificate.transcript_digest !=
            certificate.public_proof_transcript_binding)
        return {};

    std::vector<u64> words = {
        PRIVATE_BLAME_CERT_MAGIC, codec_version,
        1ULL, 0ULL,
        static_cast<u64>(certificate.evidence_kind),
        certificate.sid, certificate.accused, certificate.label.sid,
        static_cast<u64>(certificate.label.phase), certificate.label.round,
        certificate.label.owner,
        static_cast<u64>(certificate.label.obligation),
        certificate.label.object_id, certificate.checkpoint,
        static_cast<u64>(certificate.relation),
        static_cast<u64>(certificate.kernel),
        certificate.predecessor_evidence_complete ? 1ULL : 0ULL,
        certificate.public_proof_system_id,
        static_cast<u64>(recovery_payload.size()),
        static_cast<u64>(certificate.public_proof_words.size())};
    append_digest_words(certificate.expected, words);
    append_digest_words(certificate.actual, words);
    append_digest_words(certificate.residual_commitment, words);
    append_digest_words(certificate.operation_statement_binding, words);
    append_digest_words(certificate.dispute_binding, words);
    append_digest_words(certificate.predecessor_root, words);
    append_digest_words(certificate.checkpoint_root, words);
    append_digest_words(certificate.audit_witness_digest, words);
    append_digest_words(certificate.blame_statement_binding, words);
    append_digest_words(certificate.public_proof_commitment, words);
    append_digest_words(certificate.public_proof_transcript_binding, words);
    append_digest_words(certificate.transcript_digest, words);
    append_digest_words(certificate.proof_digest, words);
    words.insert(words.end(), recovery_payload.begin(), recovery_payload.end());
    words.insert(words.end(), certificate.public_proof_words.begin(),
                 certificate.public_proof_words.end());
    return words.size() == PRIVATE_BLAME_CERT_FIXED_WORDS +
            recovery_payload.size() + certificate.public_proof_words.size()
        ? words : std::vector<u64>{};
}

bool decode_private_recovery_blame_certificate(
    const std::vector<u64>& words,
    BlameCertificate* certificate) {
    if (!certificate || words.size() < PRIVATE_BLAME_CERT_FIXED_WORDS ||
        words[0] != PRIVATE_BLAME_CERT_MAGIC ||
        (words[1] != PRIVATE_BLAME_CERT_LEGACY_VERSION &&
         words[1] != PRIVATE_BLAME_CERT_VERSION) ||
        words[2] != 1 || words[3] != 0 ||
        words[4] != static_cast<u64>(AuditEvidenceKind::PRIVATE_RECOVERY) ||
        words[8] < static_cast<u64>(Phase::INIT) ||
        words[8] > static_cast<u64>(Phase::SCALAR_AGGREGATION) ||
        words[10] > std::numeric_limits<uint32_t>::max() ||
        words[11] < static_cast<u64>(Obligation::DERIVE) ||
        words[11] > static_cast<u64>(Obligation::OPEN) ||
        words[14] < static_cast<u64>(RelationKind::PRIVATE_DERIVATION) ||
        words[14] > static_cast<u64>(RelationKind::PUBLICATION) ||
        words[15] < static_cast<u64>(AuditRelationKernel::COSUMCHECK_ZERO) ||
        words[15] > static_cast<u64>(AuditRelationKernel::PUBLISH_AGGREGATE) ||
        words[16] != 0 ||
        words[17] > std::numeric_limits<uint32_t>::max())
        return false;
    const u64 recovery_count = words[18];
    const u64 proof_count = words[19];
    if (recovery_count == 0 ||
        recovery_count > PRIVATE_BLAME_CERT_MAX_VECTOR_WORDS ||
        proof_count == 0 ||
        proof_count > PRIVATE_BLAME_CERT_MAX_VECTOR_WORDS ||
        recovery_count > std::numeric_limits<size_t>::max() -
            PRIVATE_BLAME_CERT_FIXED_WORDS ||
        proof_count > std::numeric_limits<size_t>::max() -
            PRIVATE_BLAME_CERT_FIXED_WORDS -
            static_cast<size_t>(recovery_count) ||
        words.size() != PRIVATE_BLAME_CERT_FIXED_WORDS +
            static_cast<size_t>(recovery_count + proof_count))
        return false;

    BlameCertificate out;
    out.valid = true;
    out.debug_only = false;
    out.evidence_kind = AuditEvidenceKind::PRIVATE_RECOVERY;
    out.sid = words[5];
    if (words[6] > std::numeric_limits<uint32_t>::max() ||
        words[7] != out.sid ||
        words[9] > std::numeric_limits<uint32_t>::max() ||
        words[12] == 0 || words[13] == 0)
        return false;
    out.accused = static_cast<uint32_t>(words[6]);
    out.label.sid = words[7];
    out.label.phase = static_cast<Phase>(static_cast<uint32_t>(words[8]));
    out.label.round = static_cast<uint32_t>(words[9]);
    out.label.owner = static_cast<uint32_t>(words[10]);
    out.label.obligation = static_cast<Obligation>(
        static_cast<uint32_t>(words[11]));
    out.label.object_id = words[12];
    out.checkpoint = words[13];
    out.relation = static_cast<RelationKind>(
        static_cast<uint32_t>(words[14]));
    out.kernel = static_cast<AuditRelationKernel>(
        static_cast<uint32_t>(words[15]));
    out.predecessor_evidence_complete = words[16] != 0;
    out.public_proof_system_id = static_cast<uint32_t>(words[17]);

    size_t offset = 20;
    out.expected = load_digest_words(words, offset); offset += 4;
    out.actual = load_digest_words(words, offset); offset += 4;
    out.residual_commitment = load_digest_words(words, offset); offset += 4;
    out.operation_statement_binding = load_digest_words(words, offset); offset += 4;
    out.dispute_binding = load_digest_words(words, offset); offset += 4;
    out.predecessor_root = load_digest_words(words, offset); offset += 4;
    out.checkpoint_root = load_digest_words(words, offset); offset += 4;
    out.audit_witness_digest = load_digest_words(words, offset); offset += 4;
    out.blame_statement_binding = load_digest_words(words, offset); offset += 4;
    out.public_proof_commitment = load_digest_words(words, offset); offset += 4;
    out.public_proof_transcript_binding = load_digest_words(words, offset); offset += 4;
    out.transcript_digest = load_digest_words(words, offset); offset += 4;
    out.proof_digest = load_digest_words(words, offset); offset += 4;

    const size_t payload_start = PRIVATE_BLAME_CERT_FIXED_WORDS;
    const size_t payload_end = payload_start + static_cast<size_t>(recovery_count);
    if (words[1] == PRIVATE_BLAME_CERT_LEGACY_VERSION) {
        out.recovery_artifact_words.assign(
            words.begin() + static_cast<std::ptrdiff_t>(payload_start),
            words.begin() + static_cast<std::ptrdiff_t>(payload_end));
    } else {
        const auto payload_begin =
            words.begin() + static_cast<std::ptrdiff_t>(payload_start);
        if (recovery_count < 6 ||
            payload_begin[0] != PRIVATE_RECOVERY_PROOF_PAYLOAD_MAGIC ||
            payload_begin[1] != 1)
            return false;
        const u64 recovery_words_count = payload_begin[2];
        const u64 recovery_proof_system_id = payload_begin[3];
        const u64 statement_count = payload_begin[4];
        const u64 artifact_byte_count = payload_begin[5];
        if (recovery_words_count == 0 ||
            recovery_words_count > PRIVATE_BLAME_CERT_MAX_VECTOR_WORDS ||
            recovery_proof_system_id != 68103 ||
            statement_count != 85 ||
            artifact_byte_count == 0 ||
            artifact_byte_count > PRIVATE_BLAME_CERT_MAX_VECTOR_WORDS * 8)
            return false;
        const u64 artifact_word_count = (artifact_byte_count + 7) / 8;
        if (6 + recovery_words_count + statement_count + artifact_word_count !=
            recovery_count)
            return false;
        size_t payload_offset = payload_start + 6;
        out.recovery_artifact_words.assign(
            words.begin() + static_cast<std::ptrdiff_t>(payload_offset),
            words.begin() + static_cast<std::ptrdiff_t>(
                payload_offset + static_cast<size_t>(recovery_words_count)));
        payload_offset += static_cast<size_t>(recovery_words_count);
        out.recovery_proof_statement_words.assign(
            words.begin() + static_cast<std::ptrdiff_t>(payload_offset),
            words.begin() + static_cast<std::ptrdiff_t>(
                payload_offset + static_cast<size_t>(statement_count)));
        payload_offset += static_cast<size_t>(statement_count);
        out.recovery_proof_artifact_bytes.resize(
            static_cast<size_t>(artifact_byte_count));
        for (size_t i = 0; i < static_cast<size_t>(artifact_word_count); ++i) {
            const u64 packed = words[payload_offset + i];
            for (size_t j = 0; j < 8; ++j) {
                const size_t byte_index = i * 8 + j;
                const uint8_t byte = static_cast<uint8_t>(packed >> (8 * j));
                if (byte_index < out.recovery_proof_artifact_bytes.size())
                    out.recovery_proof_artifact_bytes[byte_index] = byte;
                else if (byte != 0)
                    return false;
            }
        }
        out.recovery_proof_system_id =
            static_cast<uint32_t>(recovery_proof_system_id);
        if (!inspect_recovery_proof_artifact(
                out.recovery_proof_artifact_bytes,
                out.recovery_proof_statement_words,
                &out.recovery_proof_system_id,
                &out.recovery_proof_statement_binding,
                &out.recovery_proof_artifact_commitment))
            return false;
    }

    out.public_proof_words.assign(
        words.begin() + static_cast<std::ptrdiff_t>(payload_end),
        words.end());
    if (out.sid == 0 || out.accused != out.label.owner ||
        out.relation == RelationKind::UNKNOWN ||
        out.kernel == AuditRelationKernel::UNKNOWN ||
        relation_for_kernel(out.kernel) != out.relation ||
        out.operation_statement_binding == Digest{} ||
        out.dispute_binding == Digest{} ||
        out.audit_witness_digest == Digest{} ||
        out.public_proof_system_id == 0)
        return false;
    const PublicBlameStatement statement = make_public_blame_statement(out);
    if (statement.statement_binding == Digest{} ||
        statement.statement_binding != out.blame_statement_binding)
        return false;
    PublicBlameProofArtifact proof;
    proof.available = true;
    proof.cryptographically_authenticated = true;
    proof.proof_system_id = out.public_proof_system_id;
    proof.statement_binding = out.blame_statement_binding;
    proof.proof_commitment = out.public_proof_commitment;
    proof.transcript_binding = out.public_proof_transcript_binding;
    proof.proof_words = out.public_proof_words;
    proof.recovery_proof_system_id = out.recovery_proof_system_id;
    proof.recovery_proof_statement_binding =
        out.recovery_proof_statement_binding;
    proof.recovery_proof_artifact_commitment =
        out.recovery_proof_artifact_commitment;
    proof.recovery_proof_statement_words = out.recovery_proof_statement_words;
    proof.recovery_proof_artifact_bytes = out.recovery_proof_artifact_bytes;
    if (!validate_public_blame_proof_artifact(statement, proof) ||
        out.proof_digest != out.public_proof_commitment ||
        out.transcript_digest != out.public_proof_transcript_binding)
        return false;
    *certificate = std::move(out);
    return true;
}

PublicBlameProofArtifact BackendPublicBlameProofEngine::Prove(
    const PublicBlameStatement& statement,
    const AuthenticatedRecoveryArtifact& recovery) const {
    PublicBlameProofArtifact artifact;
    if (statement.evidence_kind != AuditEvidenceKind::PRIVATE_RECOVERY ||
        statement.statement_binding == Digest{} ||
        statement.statement_binding != compute_public_blame_statement_binding(statement) ||
        !recovery.available || !recovery.cryptographically_authenticated ||
        statement.audit_evidence_binding != compute_recovery_artifact_binding(recovery) ||
        recovery.recovery_proof_system_id != 68103 ||
        recovery.recovery_proof_statement_binding == Digest{} ||
        recovery.recovery_proof_artifact_commitment == Digest{} ||
        recovery.recovery_proof_statement_words.size() != 85 ||
        recovery.recovery_proof_artifact_bytes.empty())
        return artifact;
    // Proving only checks the canonical envelope and its statement binding.
    // The expensive Groth16 verification is deferred to the final public
    // certificate-verification gate, which must run before acceptance.
    uint32_t parsed_recovery_proof_system_id = 0;
    Digest parsed_recovery_statement_binding{};
    Digest parsed_recovery_artifact_commitment{};
    if (!inspect_recovery_proof_artifact(
            recovery.recovery_proof_artifact_bytes,
            recovery.recovery_proof_statement_words,
            &parsed_recovery_proof_system_id,
            &parsed_recovery_statement_binding,
            &parsed_recovery_artifact_commitment) ||
        parsed_recovery_proof_system_id != recovery.recovery_proof_system_id ||
        parsed_recovery_statement_binding !=
            recovery.recovery_proof_statement_binding ||
        parsed_recovery_artifact_commitment !=
            recovery.recovery_proof_artifact_commitment)
        return artifact;
    const std::vector<u64> public_inputs = encode_public_blame_statement(statement);
    const ExternalPublicBlameProof external = backend_.Prove(public_inputs, recovery);
    if (!external.available || !external.cryptographically_authenticated ||
        external.proof_system_id == 0 || external.transcript_binding == Digest{} ||
        external.proof_words.empty() || !backend_.Verify(public_inputs, external))
        return artifact;
    artifact.available = true;
    artifact.cryptographically_authenticated = true;
    artifact.proof_system_id = external.proof_system_id;
    artifact.statement_binding = statement.statement_binding;
    artifact.transcript_binding = external.transcript_binding;
    artifact.proof_words = external.proof_words;
    artifact.recovery_proof_system_id = recovery.recovery_proof_system_id;
    artifact.recovery_proof_statement_binding =
        recovery.recovery_proof_statement_binding;
    artifact.recovery_proof_artifact_commitment =
        recovery.recovery_proof_artifact_commitment;
    artifact.recovery_proof_statement_words =
        recovery.recovery_proof_statement_words;
    artifact.recovery_proof_artifact_bytes =
        recovery.recovery_proof_artifact_bytes;
    artifact.proof_commitment = compute_public_blame_proof_commitment(artifact);
    return artifact;
}

bool BackendPublicBlameProofEngine::Verify(
    const PublicBlameStatement& statement,
    const PublicBlameProofArtifact& artifact) const {
    if (statement.evidence_kind != AuditEvidenceKind::PRIVATE_RECOVERY ||
        artifact.recovery_proof_system_id != 68103 ||
        !validate_public_blame_proof_artifact(statement, artifact))
        return false;
    Sp1VssRecoveryProofProvider recovery_verifier;
    Sp1VssRecoveryProofReceipt recovery_receipt;
    if (!recovery_verifier.VerifyArtifactBytes(
            artifact.recovery_proof_artifact_bytes,
            artifact.recovery_proof_statement_words, &recovery_receipt) ||
        recovery_receipt.proof_system_id != artifact.recovery_proof_system_id ||
        recovery_receipt.statement_binding !=
            artifact.recovery_proof_statement_binding ||
        recovery_receipt.artifact_commitment !=
            artifact.recovery_proof_artifact_commitment)
        return false;
    ExternalPublicBlameProof external;
    external.available = artifact.available;
    external.cryptographically_authenticated = artifact.cryptographically_authenticated;
    external.proof_system_id = artifact.proof_system_id;
    external.transcript_binding = artifact.transcript_binding;
    external.proof_words = artifact.proof_words;
    return backend_.Verify(encode_public_blame_statement(statement), external);
}

PublicBlameProofArtifact FailClosedPublicBlameProofEngine::Prove(
    const PublicBlameStatement& statement,
    const AuthenticatedRecoveryArtifact&) const {
    PublicBlameProofArtifact artifact;
    artifact.available = false;
    artifact.cryptographically_authenticated = false;
    artifact.statement_binding = statement.statement_binding;
    return artifact;
}

bool FailClosedPublicBlameProofEngine::Verify(
    const PublicBlameStatement&,
    const PublicBlameProofArtifact&) const {
    return false;
}

} // namespace pvia
