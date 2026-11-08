#include "PrivateResidualShareStore.hpp"

#include <cstring>
#include <algorithm>

namespace pvia {
namespace {

constexpr u64 RESIDUAL_COMPUTE_DOMAIN = 0x5056524553434f4dULL; // PVRESCOM
constexpr u64 RESIDUAL_SHARE_DOMAIN = 0x5056524553534841ULL;   // PVRESSHA
constexpr u64 RESIDUAL_AUTH_DOMAIN = 0x5056524553415554ULL;    // PVRESAUT

void append_digest(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

bool same_ref(const OperationRef& lhs, const OperationRef& rhs) {
    return lhs.owner == rhs.owner && lhs.object_id == rhs.object_id;
}

bool label_matches_ref(const Label& label, const OperationRef& ref) {
    return label.owner == ref.owner && label.object_id == ref.object_id;
}

bool is_native_sumcheck_kernel(AuditRelationKernel kernel) {
    using K = AuditRelationKernel;
    return kernel == K::COSUMCHECK_ZERO ||
           kernel == K::COSUMCHECK_QUADRATIC ||
           kernel == K::COSUMCHECK_BATCH ||
           kernel == K::DSC_QUADRATIC ||
           kernel == K::DSC_CUBIC;
}

} // namespace
Digest compute_private_residual_computation_binding(
    const PrivateResidualShare& share) {
    std::vector<u64> words = {
        RESIDUAL_COMPUTE_DOMAIN,
        share.label.sid,
        static_cast<u64>(share.label.phase),
        share.label.round,
        share.ref.owner,
        share.ref.object_id,
        static_cast<u64>(share.relation),
        static_cast<u64>(share.kernel),
        share.checkpoint,
        static_cast<u64>(share.values.size())
    };
    append_digest(hash_field_vector(share.values), &words);
    words.push_back(share.source_state_id);
    words.push_back(share.source_state_owner);
    append_digest(share.source_state_digest, &words);
    if (is_native_sumcheck_kernel(share.kernel))
        append_digest(share.source_state_layout_binding, &words);
    words.push_back(share.source_state_authentication_scheme_id);
    append_digest(share.source_state_authentication_binding, &words);
    append_digest(share.public_aux_root, &words);
    append_digest(share.expected, &words);
    append_digest(share.actual, &words);
    append_digest(share.operation_statement_binding, &words);
    return hash_words(words);
}

Digest compute_private_residual_share_commitment(
    const PrivateResidualShare& share) {
    std::vector<u64> words = {
        RESIDUAL_SHARE_DOMAIN,
        share.authenticated ? 1ULL : 0ULL
    };
    append_digest(share.computation_binding, &words);
    append_digest(share.authentication_binding, &words);
    return hash_words(words);
}
Digest compute_private_residual_authentication_artifact_binding(
    const PrivateResidualAuthenticationArtifact& artifact) {
    std::vector<u64> words = {
        RESIDUAL_AUTH_DOMAIN,
        artifact.available ? 1ULL : 0ULL,
        artifact.cryptographically_authenticated ? 1ULL : 0ULL,
        artifact.scheme_id
    };
    append_digest(artifact.computation_binding, &words);
    words.push_back(artifact.source_state_id);
    words.push_back(artifact.source_state_owner);
    append_digest(artifact.source_state_digest, &words);
    words.push_back(artifact.source_state_authentication_scheme_id);
    append_digest(artifact.source_state_authentication_binding, &words);
    append_digest(artifact.public_aux_root, &words);
    append_digest(artifact.operation_statement_binding, &words);
    append_digest(artifact.proof_commitment, &words);
    append_digest(artifact.transcript_binding, &words);
    words.push_back(artifact.issuer_id);
    words.push_back(artifact.issuer_sequence);
    append_digest(hash_bytes(
        artifact.proof_signature.data(),artifact.proof_signature.size()),&words);
    return hash_words(words);
}

bool validate_private_residual_authentication_artifact(
    const PrivateResidualShare& share,
    const PrivateResidualAuthenticationArtifact& artifact) {
    if (!artifact.available || !artifact.cryptographically_authenticated ||
        artifact.scheme_id == 0 || artifact.proof_commitment == Digest{} ||
        artifact.transcript_binding == Digest{} ||
        share.source_state_id == 0 ||
        share.source_state_authentication_scheme_id == 0 ||
        share.source_state_authentication_binding == Digest{})
        return false;
    if (artifact.scheme_id !=
            share.source_state_authentication_scheme_id ||
        artifact.computation_binding != share.computation_binding ||
        artifact.source_state_id != share.source_state_id ||
        artifact.source_state_owner != share.source_state_owner ||
        artifact.source_state_digest != share.source_state_digest ||
        artifact.source_state_authentication_scheme_id !=
            share.source_state_authentication_scheme_id ||
        artifact.source_state_authentication_binding !=
            share.source_state_authentication_binding ||
        artifact.public_aux_root != share.public_aux_root ||
        artifact.operation_statement_binding !=
            share.operation_statement_binding)
        return false;
    const bool has_signature=std::any_of(
        artifact.proof_signature.begin(),artifact.proof_signature.end(),
        [](uint8_t byte){return byte!=0;});
    if ((artifact.issuer_id || artifact.issuer_sequence || has_signature) &&
        (!artifact.issuer_id || !artifact.issuer_sequence || !has_signature ||
         artifact.proof_commitment!=hash_bytes(
             artifact.proof_signature.data(),artifact.proof_signature.size())))
        return false;
    return artifact.binding != Digest{} && artifact.binding ==
        compute_private_residual_authentication_artifact_binding(artifact);
}
bool validate_private_residual_share(
    const PrivateResidualShare& share) {
    if (!share.computation_valid || share.values.empty() ||
        share.label.sid == 0 || !label_matches_ref(share.label, share.ref) ||
        share.relation == RelationKind::UNKNOWN ||
        share.kernel == AuditRelationKernel::UNKNOWN ||
        share.checkpoint == 0 || share.source_state_id == 0 ||
        share.source_state_digest == Digest{} ||
        (is_native_sumcheck_kernel(share.kernel) &&
         share.source_state_layout_binding == Digest{}) ||
        share.operation_statement_binding == Digest{})
        return false;
    if (share.computation_binding !=
        compute_private_residual_computation_binding(share))
        return false;
    if (share.authenticated) {
        if (share.authentication_binding == Digest{} ||
            !validate_private_residual_authentication_artifact(
                share, share.authentication) ||
            share.authentication_binding != share.authentication.binding)
            return false;
    } else {
        const auto& artifact = share.authentication;
        if (share.authentication_binding != Digest{} || artifact.available ||
            artifact.cryptographically_authenticated || artifact.scheme_id != 0 ||
            artifact.computation_binding != Digest{} ||
            artifact.source_state_id != 0 || artifact.source_state_owner != 0 ||
            artifact.source_state_digest != Digest{} ||
            artifact.source_state_authentication_scheme_id != 0 ||
            artifact.source_state_authentication_binding != Digest{} ||
            artifact.public_aux_root != Digest{} ||
            artifact.operation_statement_binding != Digest{} ||
            artifact.proof_commitment != Digest{} ||
            artifact.transcript_binding != Digest{} ||
            artifact.issuer_id != 0 || artifact.issuer_sequence != 0 ||
            std::any_of(artifact.proof_signature.begin(),
                artifact.proof_signature.end(),
                [](uint8_t byte){return byte!=0;}) ||
            artifact.binding != Digest{})
            return false;
    }
    return share.commitment ==
        compute_private_residual_share_commitment(share);
}

bool PrivateResidualShareStore::Put(
    const PrivateResidualShare& share) {
    if (!validate_private_residual_share(share)) return false;
    for (auto& current : shares_) {
        if (same_ref(current.ref, share.ref)) {
            current = share;
            return true;
        }
    }
    shares_.push_back(share);
    return true;
}
const PrivateResidualShare* PrivateResidualShareStore::Find(
    const OperationRef& ref) const {
    for (const auto& share : shares_)
        if (same_ref(share.ref, ref)) return &share;
    return nullptr;
}

PrivateResidualShare* PrivateResidualShareStore::Find(
    const OperationRef& ref) {
    for (auto& share : shares_)
        if (same_ref(share.ref, ref)) return &share;
    return nullptr;
}

} // namespace pvia
