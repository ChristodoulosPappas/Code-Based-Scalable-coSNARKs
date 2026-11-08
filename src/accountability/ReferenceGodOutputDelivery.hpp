#pragma once
#include "PVIA.hpp"
#include "AuthenticatedMpcExchange.hpp"
#include "MultiplicationConsistencyProof.hpp"
#include <mpi.h>
#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace pvia {

struct ReferenceVssReceipt;

// Output-specific relation statement. The external verifier must establish
// that the released values are the result certified by the supplied set of
// multiplication-consistency proofs; digest equality alone is not a proof.
struct ReferenceGodOutputConsistencyStatement {
    uint64_t sid = 0;
    CheckpointId checkpoint = 0;
    Digest scope_binding{};
    uint64_t output_value_count = 0;
    Digest output_values_binding{};
    Digest multiplication_proof_set_binding{};
    std::vector<MultiplicationConsistencyStatement> multiplication_statements;
    Digest statement_binding{};
};

Digest compute_reference_god_output_consistency_statement_binding(
    const ReferenceGodOutputConsistencyStatement& statement);
bool validate_reference_god_output_consistency_statement(
    const ReferenceGodOutputConsistencyStatement& statement);
std::vector<u64> encode_reference_god_output_consistency_statement_abi(
    const ReferenceGodOutputConsistencyStatement& statement);
bool decode_reference_god_output_consistency_statement_abi(
    const std::vector<uint64_t>& words,
    ReferenceGodOutputConsistencyStatement* statement);

struct ReferenceGodOutputConsistencyWitness {
    std::vector<F> output_values;
    std::vector<MultiplicationConsistencyWitness> multiplication_witnesses;
};
bool validate_reference_god_output_consistency_witness(
    const ReferenceGodOutputConsistencyStatement& statement,
    const ReferenceGodOutputConsistencyWitness& witness);
std::vector<u64> encode_reference_god_output_consistency_witness_abi(
    const ReferenceGodOutputConsistencyStatement& statement,
    const ReferenceGodOutputConsistencyWitness& witness);
bool decode_reference_god_output_consistency_witness_abi(
    const ReferenceGodOutputConsistencyStatement& statement,
    const std::vector<uint64_t>& words,
    ReferenceGodOutputConsistencyWitness* witness);

struct ReferenceGodOutputConsistencyProofArtifact {
    bool available = false;
    bool cryptographically_authenticated = false;
    bool zero_knowledge = false;
    uint32_t proof_system_id = 0;
    Digest statement_binding{};
    Digest transcript_binding{};
    Digest proof_commitment{};
    std::vector<u64> proof_words;
};

Digest compute_reference_god_output_consistency_proof_commitment(
    const ReferenceGodOutputConsistencyProofArtifact& proof);
bool validate_reference_god_output_consistency_proof(
    const ReferenceGodOutputConsistencyStatement& statement,
    const ReferenceGodOutputConsistencyProofArtifact& proof);

struct ReferenceGodOutputConsistencyCapabilities {
    bool available = false;
    bool malicious_sound = false;
    bool zero_knowledge = false;
    bool binds_output_values = false;
    bool binds_multiplication_proof_set = false;
    bool binds_scope_and_session = false;
    bool external_registry_anchor_verified = false;
    uint64_t protocol_id = 0;
    Digest external_registry_anchor{};
    Digest relation_binding{};
    Digest implementation_binding{};
    Digest capability_binding{};
};

Digest compute_reference_god_output_consistency_relation_binding();
Digest compute_reference_god_output_consistency_capability_binding(
    const ReferenceGodOutputConsistencyCapabilities& capabilities);
bool validate_reference_god_output_consistency_capabilities(
    const ReferenceGodOutputConsistencyCapabilities& capabilities);
bool production_ready_reference_god_output_consistency_capabilities(
    const ReferenceGodOutputConsistencyCapabilities& capabilities);

struct ReferenceGodOutputConsistencyProviderCallbacks {
    std::function<ReferenceGodOutputConsistencyProofArtifact(
        const ReferenceGodOutputConsistencyStatement&,
        const std::vector<u64>& provider_witness_words)> prove;
    std::function<bool(
        const ReferenceGodOutputConsistencyStatement&,
        const ReferenceGodOutputConsistencyProofArtifact&)> verify;
    // Must verify the capability/implementation anchor against a trusted root;
    // returning true for a nonzero digest alone is not sufficient.
    std::function<bool(
        const ReferenceGodOutputConsistencyCapabilities&)> verify_external_anchor;
    std::function<std::string()> last_error;
};

class ReferenceGodOutputConsistencyProofBackend {
public:
    virtual ~ReferenceGodOutputConsistencyProofBackend() = default;
    virtual ReferenceGodOutputConsistencyCapabilities Capabilities() const = 0;
    virtual ReferenceGodOutputConsistencyProofArtifact Prove(
        const ReferenceGodOutputConsistencyStatement& statement,
        const std::vector<u64>& provider_witness_words) const = 0;
    virtual bool Verify(
        const ReferenceGodOutputConsistencyStatement& statement,
        const ReferenceGodOutputConsistencyProofArtifact& proof) const = 0;
    virtual bool external_anchor_verified() const { return false; }
};

class ExternalReferenceGodOutputConsistencyProofAdapter final
    : public ReferenceGodOutputConsistencyProofBackend {
public:
    ExternalReferenceGodOutputConsistencyProofAdapter(
        ReferenceGodOutputConsistencyCapabilities capabilities,
        uint32_t expected_proof_system_id,
        ReferenceGodOutputConsistencyProviderCallbacks callbacks);
    bool ready() const { return ready_; }
    const std::string& last_error() const { return last_error_; }
    ReferenceGodOutputConsistencyCapabilities Capabilities() const override;
    ReferenceGodOutputConsistencyProofArtifact Prove(
        const ReferenceGodOutputConsistencyStatement& statement,
        const std::vector<u64>& provider_witness_words) const override;
    bool Verify(
        const ReferenceGodOutputConsistencyStatement& statement,
        const ReferenceGodOutputConsistencyProofArtifact& proof) const override;
    bool external_anchor_verified() const override {
        return ready_ && external_anchor_verified_;
    }
private:
    ReferenceGodOutputConsistencyCapabilities capabilities_{};
    uint32_t expected_proof_system_id_ = 0;
    ReferenceGodOutputConsistencyProviderCallbacks callbacks_{};
    bool ready_ = false;
    bool external_anchor_verified_ = false;
    mutable std::string last_error_;
};

class ReferenceGodOutputConsistencyBackendRegistry final {
public:
    static bool InstallAccepted(
        const ReferenceGodOutputConsistencyProofBackend* backend);
    static const ReferenceGodOutputConsistencyProofBackend* Current();
    static Digest CurrentAcceptanceBinding();
    static void Clear();
private:
    struct State {
        const ReferenceGodOutputConsistencyProofBackend* backend = nullptr;
        Digest acceptance_binding{};
    };
    static State& state();
    static void Restore(
        const ReferenceGodOutputConsistencyProofBackend* backend,
        const Digest& acceptance_binding);
    friend class ScopedReferenceGodOutputConsistencyBackendRegistration;
};

class ScopedReferenceGodOutputConsistencyBackendRegistration final {
public:
    explicit ScopedReferenceGodOutputConsistencyBackendRegistration(
        const ReferenceGodOutputConsistencyProofBackend* backend);
    ~ScopedReferenceGodOutputConsistencyBackendRegistration();
    ScopedReferenceGodOutputConsistencyBackendRegistration(
        const ScopedReferenceGodOutputConsistencyBackendRegistration&) = delete;
    ScopedReferenceGodOutputConsistencyBackendRegistration& operator=(
        const ScopedReferenceGodOutputConsistencyBackendRegistration&) = delete;
    bool active() const { return active_; }
private:
    const ReferenceGodOutputConsistencyProofBackend* previous_backend_ = nullptr;
    Digest previous_acceptance_binding_{};
    bool active_ = false;
};

struct ReferenceGodOutputConsistencyProofBundle {
    const MultiplicationConsistencyProofBackend* multiplication_backend = nullptr;
    const ReferenceGodOutputConsistencyProofBackend* output_backend = nullptr;
    std::vector<MultiplicationConsistencyStatement> multiplication_statements;
    std::vector<MultiplicationConsistencyProofArtifact> multiplication_proofs;
    ReferenceGodOutputConsistencyStatement output_statement{};
    ReferenceGodOutputConsistencyProofArtifact output_proof{};
};

// Recoverable evidence for the three surviving signers. Unlike a digest-only
// certificate this carries the actual Ed25519 signatures, allowing an
// independent verifier to check it against a separately pinned public roster.
// It certifies survivor agreement, NOT the underlying computation or full GOD.
struct ReferenceGodSurvivorCertificate {
    bool available = false;
    int original_world_size = 0;
    int failed_original_rank = -1;
    std::vector<int> active_original_ranks;
    AuthenticatedMpcMessageContext recovery_context{};
    Digest registry_commitment{};
    Digest roster_binding{};
    Digest candidate_binding{};
    std::vector<std::array<uint8_t, 64>> vote_signatures;
};

// N=4, t=1 reference output delivery. A crash consumes the entire fault
// budget, so post-crash survivors must be honest in the N=4 experiment.
struct ReferenceGodOutput {
    bool available = false;
    std::vector<F> values;
    uint32_t delivered_participants = 0;
    uint32_t corrected_participants = 0;
    Digest scope_binding{};
    Digest transcript_binding{};
    Digest transport_binding{};
    Digest agreement_certificate{};
    ReferenceGodSurvivorCertificate survivor_certificate{};
    uint32_t agreement_votes = 0;
    bool authenticated_transport = false;
    bool external_registry_anchor_verified = false;
    bool production_authenticated_transport = false;
    bool reliable_broadcast_verified = false;
    bool survivor_agreement_verified = false;
    // Runtime-only observation for this recovery invocation. It is not
    // established by the portable survivor-vote certificate and must be
    // supplied by the caller only after an actual process-loss event.
    bool process_crash_tolerant = false;
    bool verifiable_sharing_verified = false;
    bool authenticated_vss_verified = false;
    Digest vss_transcript_binding{};
    bool vss_recovery_backend_verified = false;
    bool sp1_vss_recovery_proof_imported = false;
    Digest vss_registry_binding{};
    Digest vss_recovery_artifact_binding{};
    Digest vss_recovery_proof_binding{};
    bool multiplication_consistency_verified = false;
    Digest multiplication_proof_set_binding{};
    Digest output_consistency_statement_binding{};
    Digest output_consistency_proof_binding{};
    // Set only when a protocol compiler manifest proves that the supplied
    // multiplication relation set covers the complete application execution.
    bool complete_application_relation_set_verified = false;
    bool production_god_authorized = false;
};

// Composition artifact linking a PublicJudge-verified multiplication-failure
// certificate to the existing signed survivor-output recovery certificate.
// It records protocol-abort attribution and survivor agreement, not proof of
// the hidden multiplication inequality or production GOD authorization.
struct ReferenceGodMultiplicationFailureRecovery {
    bool available = false;
    uint32_t excluded_original_rank = 0;
    Digest external_registry_anchor{};
    Digest multiplication_failure_certificate_binding{};
    std::vector<u64> encoded_multiplication_failure_certificate;
    ReferenceGodOutput survivor_output{};
    Digest recovery_binding{};
};

Digest compute_reference_god_multiplication_failure_recovery_binding(
    const ReferenceGodMultiplicationFailureRecovery& recovery);
bool verify_reference_god_multiplication_failure_recovery(
    const ReferenceGodMultiplicationFailureRecovery& recovery,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& externally_pinned_registry_anchor);
std::vector<u64> encode_reference_god_multiplication_failure_recovery(
    const ReferenceGodMultiplicationFailureRecovery& recovery);
bool decode_reference_god_multiplication_failure_recovery(
    const std::vector<u64>& words,
    ReferenceGodMultiplicationFailureRecovery* recovery);
bool verify_encoded_reference_god_multiplication_failure_recovery(
    const std::vector<u64>& words,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& externally_pinned_registry_anchor);

// Verifies the multiplication-failure artifact first, derives the excluded
// identity from its signed report, then invokes the existing survivor-output
// recovery protocol on the caller-provided active communicator.
bool open_reference_god_output_after_verified_multiplication_failure_n4(
    int original_rank, int original_world_size,
    const std::vector<int>& active_original_ranks,
    const std::vector<F>& local_share_vector,
    const Digest& scope_binding,
    const AuthenticatedMpcMessageContext& recovery_context,
    const ReferenceVssReceipt& vss_receipt,
    MPI_Comm active_comm,
    const std::vector<u64>& encoded_multiplication_failure_certificate,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& externally_pinned_registry_anchor,
    ReferenceGodMultiplicationFailureRecovery* recovery,
    const ReferenceGodOutputConsistencyProofBundle* consistency_proof = nullptr);

// Verifies the survivor-vote certificate with no MPI calls and no secret
// keys. The caller MUST supply a trusted registry commitment obtained
// independently of the certificate. This verifies signatures and bindings
// only; it does not prove that a process actually crashed, nor VSS or
// multiplication correctness. The runtime-only crash flag is never imported.
bool verify_reference_god_survivor_certificate(
    const ReferenceGodOutput& output,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& trusted_registry_commitment);

// Canonical, non-secret ABI for archiving signed survivor agreement.
// Importing this record never grants production authorization. Use the
// independent public-key verifier with an externally pinned key registry.
std::vector<u64> encode_reference_god_survivor_certificate_abi(
    const ReferenceGodOutput& output);
bool decode_reference_god_survivor_certificate_abi(
    const std::vector<u64>& words, ReferenceGodOutput* output);

// Offline validation: reads only public certificate and public-key files;
// requires an independently supplied 32-byte registry anchor.
bool verify_reference_god_survivor_certificate_files(
    const std::string& certificate_words_path,
    const std::string& public_registry_hex_path,
    const std::string& trusted_registry_anchor_hex,
    std::string* detail);


bool reconstruct_reference_god_output_n4(
    const std::vector<int>& providers,
    const std::vector<std::vector<F>>& shares,
    const Digest& scope_binding,
    ReferenceGodOutput* output);

bool open_reference_god_output_n4(
    int rank, int world_size,
    const std::vector<F>& local_share_vector,
    bool send_share,
    const Digest& scope_binding,
    ReferenceGodOutput* output,
    MPI_Comm comm = MPI_COMM_WORLD);

// Reference-only output reconstruction on a three-survivor communicator
// formed after a verified exclusion or process failure. The caller supplies
// the active communicator and its mapping to the original N=4 roster. This
// function does not detect crashes or establish production GOD authorization.
bool open_reference_god_output_after_failure_n4(
    int original_rank, int original_world_size,
    const std::vector<int>& active_original_ranks,
    const std::vector<F>& local_share_vector,
    const Digest& scope_binding,
    const AuthenticatedMpcMessageContext& recovery_context,
    const ReferenceVssReceipt& vss_receipt,
    MPI_Comm active_comm,
    ReferenceGodOutput* output,
    const ReferenceGodOutputConsistencyProofBundle* consistency_proof = nullptr,
    bool process_crash_tolerant = false);

// ULFM-only N=4 recovery selftest. The optional proof bundle must remain
// alive for the duration of the call. A one-rank crash consumes the complete
// t=1 fault budget: the three survivors are assumed honest in this mode.
bool run_reference_god_output_crash_recovery_n4_selftest(
    int rank, int world_size,
    const std::vector<F>* expected_output = nullptr,
    const Digest* scope_binding = nullptr,
    const AuthenticatedMpcMessageContext* recovery_context = nullptr,
    const ReferenceGodOutputConsistencyProofBundle* consistency_proof = nullptr);

// Authenticated N=4 output opening plus an n-t quorum certificate.
// This authenticates per-rank contributions and binds the result to a
 // session/checkpoint. MPI collectives still require every rank to be alive;
 // set require_production_anchor=true for externally anchored identities.
bool open_authenticated_reference_god_output_n4(
    int rank, int world_size,
    const std::vector<F>& local_share_vector,
    bool send_share,
    const Digest& scope_binding,
    const AuthenticatedMpcMessageContext& base_context,
    const AuthenticatedMpcExchange& exchange,
    ReferenceGodOutput* output,
    bool require_production_anchor = true,
    const ReferenceGodOutputConsistencyProofBundle* consistency_proof = nullptr);

// Capability predicate for downstream release gates. It deliberately remains
// false until authenticated identity anchoring, reliable broadcast, crash
// handling, and multiplication-consistency proof verification are all present.
bool reference_god_output_production_authorized(
    const ReferenceGodOutput& output);

bool run_reference_god_output_bundle_n4_selftest(
    int rank, int world_size,
    const std::string& multiplication_library_path,
    const std::string& output_library_path,
    const std::string& relation_vector_path);

bool run_reference_god_authenticated_output_n4_selftest(
    int rank, int world_size);

bool run_reference_god_output_n4_selftest(int rank, int world_size);

} // namespace pvia
