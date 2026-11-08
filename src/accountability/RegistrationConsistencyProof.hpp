#pragma once

#include "PVIA.hpp"

#include <vector>

namespace pvia {

// The public native-state provenance supplied to registration. These
// non-secret identifiers/digests bind a proof statement; they do not
// themselves authenticate a native share or prove equality of secrets.
struct RegistrationNativeContext {
    StateId native_state_id = 0;
    uint64_t authentication_scheme_id = 0;
    Digest authentication_binding{};
    Digest predecessor_root{};
    Digest checkpoint_root{};
};

bool validate_registration_native_context(
    const RegistrationNativeContext& context);
Digest compute_registration_native_context_binding(
    const RegistrationNativeContext& context);

struct RegistrationConsistencyStatement {
    uint64_t sid = 0;
    CheckpointId checkpoint = 0;
    OperationRef ref{};
    AuditRelationKernel kernel = AuditRelationKernel::UNKNOWN;
    size_t state_element_count = 0;
    size_t output_element_count = 0;
    Digest public_state_digest{};
    Digest public_actual_digest{};
    // Public binding of the native FOLD_RS challenge used to evaluate the
    // registered transition. Do not treat this as a hiding commitment.
    Digest public_challenge_binding{};
    RegistrationNativeContext native_context{};
    Digest operation_statement_binding{};
    Digest sharing_transcript_binding{};
    Digest statement_binding{};
};

Digest compute_registration_consistency_statement_binding(
    const RegistrationConsistencyStatement& statement);
// Canonical public 46-u64 SP1 statement. No native shares or VSS coefficients.
std::vector<u64> encode_registration_consistency_statement_words(
    const RegistrationConsistencyStatement& statement);
bool validate_registration_consistency_statement(
    const RegistrationConsistencyStatement& statement);
struct RegistrationConsistencyProofArtifact {
    bool available = false;
    bool cryptographically_authenticated = false;
    bool zero_knowledge = false;
    uint32_t proof_system_id = 0;
    Digest statement_binding{};
    Digest transcript_binding{};
    Digest proof_commitment{};
    std::vector<u64> proof_words;
};

Digest compute_registration_consistency_proof_commitment(
    const RegistrationConsistencyProofArtifact& proof);
bool validate_registration_consistency_proof_artifact(
    const RegistrationConsistencyStatement& statement,
    const RegistrationConsistencyProofArtifact& proof);
Digest compute_registration_consistency_set_binding(
    const std::vector<RegistrationConsistencyProofArtifact>& proofs);

struct RegistrationConsistencyCapabilities {
    bool available = false;
    bool malicious_sound = false;
    bool zero_knowledge = false;
    bool binds_sharing_transcript = false;
    // A reference/synthetic proof must never be admitted via a generic
    // runtime production-ready capability check.
    bool reference_test_only = false;
    uint64_t protocol_id = 0;
    Digest implementation_binding{};
    Digest capability_binding{};
};

Digest compute_registration_consistency_capability_binding(
    const RegistrationConsistencyCapabilities& capabilities);
bool validate_registration_consistency_capabilities(
    const RegistrationConsistencyCapabilities& capabilities);
bool production_ready_registration_consistency_capabilities(
    const RegistrationConsistencyCapabilities& capabilities);

struct RegistrationConsistencyWitness {
    std::vector<F> state_values;
    std::vector<F> actual_output;
    // Public FOLD challenge used in the native transition, not a secret.
    F public_challenge{};
    // Encoded PRIVATE ReferenceVssDealerWitness. Never serialize in a
    // public proof artifact or transmit to a verifier.
    std::vector<u64> sharing_witness_words;
};

// Concrete reference relation, evaluated only where the dealer witness
// is available. Checks FOLD semantics and that the polynomial constants
// of the VSS encoding match the native values. NOT a ZK proof or a
// production distributed proof backend.
bool evaluate_reference_registration_consistency_relation(
    const RegistrationConsistencyStatement& statement,
    const RegistrationConsistencyWitness& witness);

class RegistrationConsistencyProofBackend {
public:
    virtual ~RegistrationConsistencyProofBackend() = default;
    virtual RegistrationConsistencyCapabilities Capabilities() const = 0;
    virtual RegistrationConsistencyProofArtifact Prove(
        const RegistrationConsistencyStatement& statement,
        const RegistrationConsistencyWitness& witness) const = 0;
    virtual bool Verify(
        const RegistrationConsistencyStatement& statement,
        const RegistrationConsistencyProofArtifact& proof) const = 0;
};
class FailClosedRegistrationConsistencyProofBackend final
    : public RegistrationConsistencyProofBackend {
public:
    RegistrationConsistencyCapabilities Capabilities() const override;
    RegistrationConsistencyProofArtifact Prove(
        const RegistrationConsistencyStatement& statement,
        const RegistrationConsistencyWitness& witness) const override;
    bool Verify(
        const RegistrationConsistencyStatement& statement,
        const RegistrationConsistencyProofArtifact& proof) const override;
};

} // namespace pvia
