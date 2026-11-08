#include "AuthenticatedAuditRecovery.hpp"
#include "TransferAuthentication.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <vector>

namespace pvia {
namespace {

constexpr u64 RECOVERY_ARTIFACT_MAGIC = 0x5056494152435631ULL; // PVIARCV1
constexpr u64 RECOVERY_ARTIFACT_VERSION = 1;
constexpr size_t RECOVERY_ARTIFACT_WORDS = 70;
constexpr u64 AUTH_RECEIPT_DOMAIN = 0x5056524341555431ULL; // PVRCAUT1

void append_digest_words(const Digest& digest, std::vector<u64>& words);

std::vector<u64> recovery_receipt_message(
    const AuthenticatedRecoveryRequest& request,
    const AuthenticatedRecoveryArtifact& artifact) {
    if (artifact.recovery_auth_signer == 0xffffffffU ||
        artifact.recovered_audit_commitment == Digest{} ||
        artifact.recovery_transcript_binding == Digest{} ||
        artifact.recovery_agreement_binding == Digest{} ||
        artifact.recovery_replay_head == Digest{} ||
        artifact.recovery_registry_binding == Digest{} ||
        artifact.predecessor_root == Digest{} ||
        artifact.checkpoint_root == Digest{})
        return {};
    std::vector<u64> words = {
        AUTH_RECEIPT_DOMAIN, artifact.recovery_auth_signer,
        request.checkpoint, static_cast<u64>(request.relation),
        static_cast<u64>(request.kernel)};
    append_digest_words(request.request_binding, words);
    append_digest_words(request.operation_statement_binding, words);
    append_digest_words(request.dispute_binding, words);
    append_digest_words(artifact.recovered_audit_commitment, words);
    append_digest_words(artifact.recovery_transcript_binding, words);
    append_digest_words(artifact.recovery_agreement_binding, words);
    append_digest_words(artifact.recovery_replay_head, words);
    append_digest_words(artifact.recovery_registry_binding, words);
    append_digest_words(artifact.predecessor_root, words);
    append_digest_words(artifact.checkpoint_root, words);
    return words;
}

Digest recovery_receipt_commitment(
    const std::vector<u64>& message,
    uint32_t signer,
    const Digest& registry_binding,
    const std::array<uint8_t, 64>& signature) {
    if (message.empty() || signer == 0xffffffffU ||
        registry_binding == Digest{})
        return {};
    std::vector<u64> words = {AUTH_RECEIPT_DOMAIN, signer};
    words.insert(words.end(), message.begin(), message.end());
    append_digest_words(registry_binding, words);
    for (size_t i = 0; i < signature.size(); i += 8) {
        u64 word = 0;
        std::memcpy(&word, signature.data() + i, 8);
        words.push_back(word);
    }
    return hash_words(words);
}

void append_digest_words(const Digest& digest, std::vector<u64>& words) {
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words.push_back(word);
    }
}

OperationRef ref_from_label(const Label& label) {
    return OperationRef{label.owner, label.object_id};
}

class SelfAssertedRecoveryBackend final
    : public AuthenticatedAuditRecoveryBackend {
public:
    Digest ProductionCapabilityBinding() const override {
        return hash_words({0x5245434f56564552ULL, 1ULL});
    }

    AuthenticatedRecoveryArtifact Recover(
        const AuthenticatedRecoveryRequest& request,
        int,
        int) const override {
        AuthenticatedRecoveryArtifact artifact;
        artifact.available = true;
        artifact.cryptographically_authenticated = true;
        artifact.accused = ref_from_label(request.label);
        artifact.checkpoint = request.checkpoint;
        artifact.relation = request.relation;
        artifact.kernel = request.kernel;
        artifact.request_binding = request.request_binding;
        artifact.operation_statement_binding =
            request.operation_statement_binding;
        artifact.dispute_binding = request.dispute_binding;
        artifact.predecessor_root =
            hash_words({0x5245435052454431ULL, request.checkpoint});
        artifact.checkpoint_root = request.checkpoint_root;
        artifact.recovered_audit_commitment =
            hash_words({0x5245434155444954ULL, request.checkpoint});
        artifact.recovery_transcript_binding =
            hash_words({0x5245435452414e53ULL, request.checkpoint});
        artifact.authentication_proof_commitment =
            hash_words({0x52454350524f4f46ULL, request.checkpoint});
        return artifact;
    }

    bool Verify(
        const AuthenticatedRecoveryRequest&,
        const AuthenticatedRecoveryArtifact&) const override {
        verify_called_ = true;
        return false;
    }

    bool verify_called() const { return verify_called_; }

private:
    mutable bool verify_called_ = false;
};

} // namespace
Digest compute_recovery_request_binding(
    const AuthenticatedRecoveryRequest& request) {
    std::vector<u64> words = {
        request.label.sid,
        static_cast<u64>(request.label.phase),
        request.label.round,
        request.label.owner,
        static_cast<u64>(request.label.obligation),
        request.label.object_id,
        request.checkpoint,
        static_cast<u64>(request.relation),
        static_cast<u64>(request.kernel)
    };
    append_digest_words(request.expected, words);
    append_digest_words(request.actual, words);
    append_digest_words(request.residual_commitment, words);
    append_digest_words(request.operation_statement_binding, words);
    append_digest_words(request.dispute_binding, words);
    append_digest_words(request.checkpoint_root, words);
    return hash_words(words);
}
AuthenticatedRecoveryRequest make_recovery_request(
    const Violation& violation,
    const AuditCheckpointView& checkpoint) {
    AuthenticatedRecoveryRequest request;
    if (!violation.valid || violation.operation_statement_binding == Digest{} ||
        !checkpoint.sealed || checkpoint.root == Digest{} ||
        checkpoint.id != violation.checkpoint)
        return request;
    request.label = violation.label;
    request.checkpoint = violation.checkpoint;
    request.relation = violation.relation;
    request.kernel = violation.kernel;
    request.expected = violation.expected;
    request.actual = violation.actual;
    request.residual_commitment = violation.residual_commitment;
    request.operation_statement_binding = violation.operation_statement_binding;
    request.dispute_binding = violation.dispute_binding;
    request.checkpoint_root = checkpoint.root;
    request.request_binding = compute_recovery_request_binding(request);
    return request;
}
AuthenticatedRecoveryRequest make_recovery_request(
    const BlameCertificate& certificate) {
    AuthenticatedRecoveryRequest request;
    if (!certificate.valid || certificate.debug_only ||
        certificate.evidence_kind != AuditEvidenceKind::PRIVATE_RECOVERY ||
        certificate.sid == 0 || certificate.label.sid != certificate.sid ||
        certificate.accused != certificate.label.owner ||
        static_cast<uint32_t>(certificate.label.phase) <
            static_cast<uint32_t>(Phase::INIT) ||
        static_cast<uint32_t>(certificate.label.phase) >
            static_cast<uint32_t>(Phase::SCALAR_AGGREGATION) ||
        static_cast<uint32_t>(certificate.label.obligation) <
            static_cast<uint32_t>(Obligation::DERIVE) ||
        static_cast<uint32_t>(certificate.label.obligation) >
            static_cast<uint32_t>(Obligation::OPEN) ||
        certificate.checkpoint == 0 ||
        certificate.relation == RelationKind::UNKNOWN ||
        certificate.kernel == AuditRelationKernel::UNKNOWN ||
        relation_for_kernel(certificate.kernel) != certificate.relation)
        return request;
    request.label = certificate.label;
    request.checkpoint = certificate.checkpoint;
    request.relation = certificate.relation;
    request.kernel = certificate.kernel;
    request.expected = certificate.expected;
    request.actual = certificate.actual;
    request.residual_commitment = certificate.residual_commitment;
    request.operation_statement_binding =
        certificate.operation_statement_binding;
    request.dispute_binding = certificate.dispute_binding;
    request.checkpoint_root = certificate.checkpoint_root;
    request.request_binding = compute_recovery_request_binding(request);
    return request;
}

Digest compute_recovery_artifact_binding(
    const AuthenticatedRecoveryArtifact& artifact) {
    std::vector<u64> words = {
        artifact.available ? 1ULL : 0ULL,
        artifact.cryptographically_authenticated ? 1ULL : 0ULL,
        artifact.accused.owner,
        artifact.accused.object_id,
        artifact.checkpoint,
        static_cast<u64>(artifact.relation),
        static_cast<u64>(artifact.kernel)
    };
    append_digest_words(artifact.request_binding, words);
    append_digest_words(artifact.operation_statement_binding, words);
    append_digest_words(artifact.dispute_binding, words);
    append_digest_words(artifact.predecessor_root, words);
    append_digest_words(artifact.checkpoint_root, words);
    append_digest_words(artifact.recovered_audit_commitment, words);
    append_digest_words(artifact.recovery_transcript_binding, words);
    append_digest_words(artifact.authentication_proof_commitment, words);
    append_digest_words(artifact.recovery_share_commitment, words);
    append_digest_words(artifact.recovery_registry_binding, words);
    append_digest_words(artifact.recovery_agreement_binding, words);
    append_digest_words(artifact.recovery_replay_head, words);
    words.push_back(artifact.recovery_auth_signer);
    append_digest_words(artifact.recovery_auth_registry_binding, words);
    for (size_t i = 0; i < artifact.recovery_auth_signature.size(); i += 8) {
        u64 word = 0;
        std::memcpy(&word, artifact.recovery_auth_signature.data() + i, 8);
        words.push_back(word);
    }
    return hash_words(words);
}
std::vector<u64> encode_authenticated_recovery_artifact(
    const AuthenticatedRecoveryArtifact& artifact) {
    const bool signature_present = std::any_of(
        artifact.recovery_auth_signature.begin(),
        artifact.recovery_auth_signature.end(),
        [](uint8_t byte) { return byte != 0; });
    if (!artifact.available || !artifact.cryptographically_authenticated ||
        artifact.request_binding == Digest{} ||
        artifact.operation_statement_binding == Digest{} ||
        artifact.dispute_binding == Digest{} ||
        artifact.predecessor_root == Digest{} ||
        artifact.checkpoint_root == Digest{} ||
        artifact.recovered_audit_commitment == Digest{} ||
        artifact.recovery_transcript_binding == Digest{} ||
        artifact.authentication_proof_commitment == Digest{} ||
        artifact.recovery_auth_signer == 0xffffffffU ||
        artifact.recovery_auth_signer != artifact.accused.owner ||
        artifact.recovery_auth_registry_binding == Digest{} ||
        artifact.recovery_share_commitment == Digest{} ||
        artifact.recovery_registry_binding == Digest{} ||
        artifact.recovery_agreement_binding == Digest{} ||
        artifact.recovery_replay_head == Digest{} || !signature_present ||
        artifact.recovered_audit_commitment !=
            compute_recovered_audit_commitment(
                artifact.request_binding,
                artifact.recovery_share_commitment,
                artifact.recovery_registry_binding))
        return {};

    std::vector<u64> words = {
        RECOVERY_ARTIFACT_MAGIC, RECOVERY_ARTIFACT_VERSION,
        1ULL, 1ULL, artifact.accused.owner, artifact.accused.object_id,
        artifact.checkpoint, static_cast<u64>(artifact.relation),
        static_cast<u64>(artifact.kernel)};
    append_digest_words(artifact.request_binding, words);
    append_digest_words(artifact.operation_statement_binding, words);
    append_digest_words(artifact.dispute_binding, words);
    append_digest_words(artifact.predecessor_root, words);
    append_digest_words(artifact.checkpoint_root, words);
    append_digest_words(artifact.recovered_audit_commitment, words);
    append_digest_words(artifact.recovery_transcript_binding, words);
    append_digest_words(artifact.authentication_proof_commitment, words);
    append_digest_words(artifact.recovery_share_commitment, words);
    append_digest_words(artifact.recovery_registry_binding, words);
    append_digest_words(artifact.recovery_agreement_binding, words);
    append_digest_words(artifact.recovery_replay_head, words);
    words.push_back(artifact.recovery_auth_signer);
    append_digest_words(artifact.recovery_auth_registry_binding, words);
    for (size_t i = 0; i < artifact.recovery_auth_signature.size(); i += 8) {
        u64 word = 0;
        std::memcpy(&word, artifact.recovery_auth_signature.data() + i, 8);
        words.push_back(word);
    }
    return words.size() == RECOVERY_ARTIFACT_WORDS ? words
                                                   : std::vector<u64>{};
}

bool decode_authenticated_recovery_artifact(
    const std::vector<u64>& words,
    AuthenticatedRecoveryArtifact* artifact) {
    if (!artifact || words.size() != RECOVERY_ARTIFACT_WORDS ||
        words[0] != RECOVERY_ARTIFACT_MAGIC ||
        words[1] != RECOVERY_ARTIFACT_VERSION ||
        words[2] != 1 || words[3] != 1 ||
        words[4] > std::numeric_limits<uint32_t>::max() ||
        words[7] > std::numeric_limits<uint32_t>::max() ||
        words[8] > std::numeric_limits<uint32_t>::max() ||
        words[57] > std::numeric_limits<uint32_t>::max())
        return false;

    AuthenticatedRecoveryArtifact out;
    out.available = true;
    out.cryptographically_authenticated = true;
    out.accused.owner = static_cast<uint32_t>(words[4]);
    out.accused.object_id = words[5];
    out.checkpoint = words[6];
    out.relation = static_cast<RelationKind>(
        static_cast<uint32_t>(words[7]));
    out.kernel = static_cast<AuditRelationKernel>(
        static_cast<uint32_t>(words[8]));
    size_t offset = 9;
    auto load_next_digest = [&words, &offset]() {
        Digest digest{};
        if (offset + 4 <= words.size()) {
            for (size_t i = 0; i < 4; ++i)
                std::memcpy(digest.bytes.data() + i * 8,
                            &words[offset + i], 8);
        }
        offset += 4;
        return digest;
    };
    out.request_binding = load_next_digest();
    out.operation_statement_binding = load_next_digest();
    out.dispute_binding = load_next_digest();
    out.predecessor_root = load_next_digest();
    out.checkpoint_root = load_next_digest();
    out.recovered_audit_commitment = load_next_digest();
    out.recovery_transcript_binding = load_next_digest();
    out.authentication_proof_commitment = load_next_digest();
    out.recovery_share_commitment = load_next_digest();
    out.recovery_registry_binding = load_next_digest();
    out.recovery_agreement_binding = load_next_digest();
    out.recovery_replay_head = load_next_digest();
    out.recovery_auth_signer = static_cast<uint32_t>(words[offset++]);
    out.recovery_auth_registry_binding = load_next_digest();
    for (size_t i = 0; i < 8; ++i)
        std::memcpy(out.recovery_auth_signature.data() + i * 8,
                    &words[offset + i], 8);
    offset += 8;

    const bool signature_present = std::any_of(
        out.recovery_auth_signature.begin(),
        out.recovery_auth_signature.end(),
        [](uint8_t byte) { return byte != 0; });
    if (offset != words.size() || out.recovery_auth_signer == 0xffffffffU ||
        out.recovery_auth_signer != out.accused.owner ||
        out.request_binding == Digest{} ||
        out.operation_statement_binding == Digest{} ||
        out.dispute_binding == Digest{} || out.predecessor_root == Digest{} ||
        out.checkpoint_root == Digest{} ||
        out.recovered_audit_commitment == Digest{} ||
        out.recovery_transcript_binding == Digest{} ||
        out.authentication_proof_commitment == Digest{} ||
        out.recovery_share_commitment == Digest{} ||
        out.recovery_registry_binding == Digest{} ||
        out.recovery_agreement_binding == Digest{} ||
        out.recovery_replay_head == Digest{} ||
        out.recovery_auth_registry_binding == Digest{} ||
        !signature_present ||
        out.recovered_audit_commitment !=
            compute_recovered_audit_commitment(
                out.request_binding, out.recovery_share_commitment,
                out.recovery_registry_binding) ||
        compute_recovery_artifact_binding(out) == Digest{})
        return false;
    *artifact = std::move(out);
    return true;
}

Digest compute_recovered_audit_commitment(
    const Digest& request_binding,
    const Digest& share_commitment,
    const Digest& registry_binding) {
    if (request_binding == Digest{} || share_commitment == Digest{} ||
        registry_binding == Digest{})
        return {};
    constexpr u64 domain = 0x5056524353485231ULL; // PVRCSHR1
    std::vector<u64> words = {domain};
    append_digest_words(request_binding, words);
    append_digest_words(share_commitment, words);
    append_digest_words(registry_binding, words);
    return hash_words(words);
}

bool validate_recovery_artifact(
    const AuthenticatedRecoveryRequest& request,
    const AuthenticatedRecoveryArtifact& artifact) {
    if (!artifact.available || !artifact.cryptographically_authenticated)
        return false;
    if (request.request_binding == Digest{} ||
        request.operation_statement_binding == Digest{} ||
        request.dispute_binding == Digest{} ||
        request.residual_commitment == Digest{} ||
        request.checkpoint_root == Digest{} ||
        static_cast<uint32_t>(request.label.phase) <
            static_cast<uint32_t>(Phase::INIT) ||
        static_cast<uint32_t>(request.label.phase) >
            static_cast<uint32_t>(Phase::SCALAR_AGGREGATION) ||
        static_cast<uint32_t>(request.label.obligation) <
            static_cast<uint32_t>(Obligation::DERIVE) ||
        static_cast<uint32_t>(request.label.obligation) >
            static_cast<uint32_t>(Obligation::OPEN) ||
        request.relation == RelationKind::UNKNOWN ||
        request.kernel == AuditRelationKernel::UNKNOWN ||
        relation_for_kernel(request.kernel) != request.relation ||
        request.request_binding != compute_recovery_request_binding(request))
        return false;
    if (artifact.accused != ref_from_label(request.label) ||
        artifact.checkpoint != request.checkpoint ||
        artifact.relation != request.relation ||
        artifact.kernel != request.kernel)
        return false;
    if (artifact.request_binding != request.request_binding ||
        artifact.operation_statement_binding != request.operation_statement_binding ||
        artifact.dispute_binding != request.dispute_binding ||
        artifact.checkpoint_root != request.checkpoint_root)
        return false;
    if (artifact.recovered_audit_commitment == Digest{} ||
        artifact.recovery_transcript_binding == Digest{} ||
        artifact.authentication_proof_commitment == Digest{})
        return false;

    const bool has_any_portable_receipt =
        artifact.recovery_share_commitment != Digest{} ||
        artifact.recovery_registry_binding != Digest{} ||
        artifact.recovery_agreement_binding != Digest{} ||
        artifact.recovery_replay_head != Digest{} ||
        artifact.recovery_auth_signer != 0xffffffffU ||
        artifact.recovery_auth_registry_binding != Digest{} ||
        std::any_of(artifact.recovery_auth_signature.begin(),
                    artifact.recovery_auth_signature.end(),
                    [](uint8_t byte) { return byte != 0; });
    if (has_any_portable_receipt) {
        if (artifact.recovery_share_commitment == Digest{} ||
            artifact.recovery_registry_binding == Digest{} ||
            artifact.recovery_agreement_binding == Digest{} ||
            artifact.recovery_replay_head == Digest{} ||
            artifact.recovery_auth_signer != request.label.owner ||
            artifact.recovery_auth_registry_binding == Digest{} ||
            !std::any_of(artifact.recovery_auth_signature.begin(),
                         artifact.recovery_auth_signature.end(),
                         [](uint8_t byte) { return byte != 0; }) ||
            artifact.recovered_audit_commitment !=
                compute_recovered_audit_commitment(
                    request.request_binding,
                    artifact.recovery_share_commitment,
                    artifact.recovery_registry_binding))
            return false;
    }
    return compute_recovery_artifact_binding(artifact) != Digest{};
}
bool verify_authenticated_recovery_receipt(
    const AuthenticatedRecoveryRequest& request,
    const AuthenticatedRecoveryArtifact& artifact,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& expected_registry_commitment) {
    if (!validate_recovery_artifact(request, artifact) ||
        expected_registry_commitment == Digest{} ||
        artifact.recovery_auth_registry_binding !=
            expected_registry_commitment ||
        artifact.recovery_auth_signer != request.label.owner)
        return false;
    const std::vector<u64> message =
        recovery_receipt_message(request, artifact);
    const Digest expected_receipt_commitment =
        recovery_receipt_commitment(
            message, artifact.recovery_auth_signer,
            artifact.recovery_auth_registry_binding,
            artifact.recovery_auth_signature);
    return expected_receipt_commitment != Digest{} &&
        artifact.authentication_proof_commitment ==
            expected_receipt_commitment &&
        verify_ed25519_words_with_public_registry(
            AUTH_RECEIPT_DOMAIN, message,
            artifact.recovery_auth_signature,
            artifact.recovery_auth_signer, public_keys,
            expected_registry_commitment);
}

bool BackendAuthenticatedAuditRecoveryEngine::Verify(
    const AuthenticatedRecoveryRequest& request,
    const AuthenticatedRecoveryArtifact& artifact) const {
    return validate_recovery_artifact(request, artifact) &&
           backend_.Verify(request, artifact);
}

AuthenticatedRecoveryArtifact
BackendAuthenticatedAuditRecoveryEngine::Recover(
    const AuthenticatedRecoveryRequest& request,
    int rank,
    int world_size) const {
    AuthenticatedRecoveryArtifact unavailable;
    unavailable.accused = ref_from_label(request.label);
    unavailable.checkpoint = request.checkpoint;
    unavailable.relation = request.relation;
    unavailable.kernel = request.kernel;
    unavailable.request_binding = request.request_binding;
    unavailable.operation_statement_binding =
        request.operation_statement_binding;
    unavailable.dispute_binding = request.dispute_binding;
    unavailable.checkpoint_root = request.checkpoint_root;

    if (request.request_binding == Digest{} ||
        request.request_binding != compute_recovery_request_binding(request))
        return unavailable;
    const AuthenticatedRecoveryArtifact artifact =
        backend_.Recover(request, rank, world_size);
    if (!Verify(request, artifact))
        return unavailable;
    return artifact;
}

bool run_authenticated_audit_recovery_verifier_selftest() {
    AuthenticatedRecoveryRequest request;
    request.label.sid = 0x52454353454c4631ULL;
    request.label.phase = Phase::FOLD;
    request.label.obligation = Obligation::FOLD;
    request.label.round = 3;
    request.label.owner = 1;
    request.label.object_id = 17;
    request.checkpoint = 0x524543434b503031ULL;
    request.relation = RelationKind::FOLDING;
    request.kernel = AuditRelationKernel::FOLD_RS;
    request.expected = hash_words({0x5245434558504543ULL, 1ULL});
    request.actual = hash_words({0x5245434143545541ULL, 2ULL});
    request.residual_commitment = hash_words({0x5245435245534944ULL, 3ULL});
    request.operation_statement_binding =
        hash_words({0x5245434f5042494eULL, 4ULL});
    request.dispute_binding = hash_words({0x5245434449535055ULL, 5ULL});
    request.checkpoint_root = hash_words({0x524543434b505254ULL, 6ULL});
    request.request_binding = compute_recovery_request_binding(request);
    if (request.request_binding == Digest{}) return false;

    SelfAssertedRecoveryBackend backend;
    BackendAuthenticatedAuditRecoveryEngine engine(backend);
    if (engine.ProductionCapabilityBinding() == Digest{}) return false;
    const AuthenticatedRecoveryArtifact result = engine.Recover(request, 0, 4);
    return backend.verify_called() && !result.available &&
           !result.cryptographically_authenticated &&
           !engine.Verify(request, result);
}

AuthenticatedRecoveryArtifact
FailClosedAuthenticatedAuditRecoveryEngine::Recover(
    const AuthenticatedRecoveryRequest& request,
    int,
    int) const {
    AuthenticatedRecoveryArtifact artifact;
    artifact.available = false;
    artifact.cryptographically_authenticated = false;
    artifact.accused = ref_from_label(request.label);
    artifact.checkpoint = request.checkpoint;
    artifact.relation = request.relation;
    artifact.kernel = request.kernel;
    artifact.request_binding = request.request_binding;
    artifact.operation_statement_binding = request.operation_statement_binding;
    artifact.dispute_binding = request.dispute_binding;
    artifact.checkpoint_root = request.checkpoint_root;
    return artifact;
}

} // namespace pvia
