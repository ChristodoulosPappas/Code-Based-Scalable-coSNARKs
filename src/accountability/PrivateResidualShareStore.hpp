#pragma once

#include "PVIA.hpp"

#include <array>

#include <vector>

namespace pvia {

struct PrivateResidualAuthenticationArtifact {
    bool available = false;
    bool cryptographically_authenticated = false;
    uint64_t scheme_id = 0;
    Digest computation_binding{};
    StateId source_state_id = 0;
    uint32_t source_state_owner = 0;
    Digest source_state_digest{};
    uint64_t source_state_authentication_scheme_id = 0;
    Digest source_state_authentication_binding{};
    Digest public_aux_root{};
    Digest operation_statement_binding{};
    Digest proof_commitment{};
    Digest transcript_binding{};
    // Present for externally signed provenance receipts. Legacy isolated
    // selftests may leave these fields zero; production verifiers must pin
    // issuer identity/key and verify the signature explicitly.
    uint64_t issuer_id = 0;
    uint64_t issuer_sequence = 0;
    std::array<uint8_t,64> proof_signature{};
    Digest binding{};
};

// Backend-owned private residual material. Runtime never receives `values`.
// `authenticated` may be set only after a concrete cryptographic residual
// authenticator validates the computation binding.
struct PrivateResidualShare {
    OperationRef ref{};
    Label label{};
    RelationKind relation = RelationKind::UNKNOWN;
    AuditRelationKernel kernel = AuditRelationKernel::UNKNOWN;
    CheckpointId checkpoint = 0;
    std::vector<F> values;
    StateId source_state_id = 0;
    uint32_t source_state_owner = 0;
    Digest source_state_digest{};
    // Nonzero for native Sumcheck residuals; binds the private segment partition.
    Digest source_state_layout_binding{};
    uint64_t source_state_authentication_scheme_id = 0;
    Digest source_state_authentication_binding{};
    Digest public_aux_root{};
    Digest expected{};
    Digest actual{};
    Digest operation_statement_binding{};
    Digest computation_binding{};
    PrivateResidualAuthenticationArtifact authentication{};
    Digest authentication_binding{};
    Digest commitment{};
    bool computation_valid = false;
    bool authenticated = false;
};

Digest compute_private_residual_computation_binding(
    const PrivateResidualShare& share);
Digest compute_private_residual_share_commitment(
    const PrivateResidualShare& share);
Digest compute_private_residual_authentication_artifact_binding(
    const PrivateResidualAuthenticationArtifact& artifact);
bool validate_private_residual_authentication_artifact(
    const PrivateResidualShare& share,
    const PrivateResidualAuthenticationArtifact& artifact);
bool validate_private_residual_share(
    const PrivateResidualShare& share);
class PrivateResidualShareStore {
public:
    bool Put(const PrivateResidualShare& share);
    const PrivateResidualShare* Find(const OperationRef& ref) const;
    PrivateResidualShare* Find(const OperationRef& ref);
    size_t size() const { return shares_.size(); }
    void Clear() { shares_.clear(); }

private:
    std::vector<PrivateResidualShare> shares_;
};

// Authentication is deliberately a separate boundary from deterministic
// residual computation. A signature over a self-claimed residual is not
// sufficient; concrete implementations must authenticate the underlying MPC
// share/provenance before returning success.
class PrivateResidualShareAuthenticator {
public:
    virtual ~PrivateResidualShareAuthenticator() = default;
    virtual uint64_t SchemeId() const = 0;
    virtual bool Authenticate(
        const PrivateResidualShare& share,
        PrivateResidualAuthenticationArtifact* artifact) const = 0;
};

} // namespace pvia
