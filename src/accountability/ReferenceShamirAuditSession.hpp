#pragma once

#include "FoldResidualComputationBackend.hpp"
#include "ReferenceShamirMpc.hpp"
#include "ReferenceBivariateVss.hpp"
#include "RegistrationConsistencyProof.hpp"
#include "RegistrationOriginEndorsements.hpp"

#include <vector>

namespace pvia {

struct ReferenceShamirSelectedAuditWitness {
    bool available = false;
    OperationRef ref{};
    std::vector<F> state_shares;
    std::vector<F> actual_output_shares;
    ReferenceVssLocalWitness registration_vss_witness{};
    ReferenceVssReceipt registration_vss_receipt{};
};

struct ReferenceShamirBatchResult {
    bool available = false;
    bool clean = false;
    CheckpointId checkpoint = 0;
    size_t operation_count = 0;
    Digest registration_binding{};
    Digest public_coin_transcript_binding{};
    Digest challenge_binding{};
    Digest multiplication_consistency_binding{};
    Digest opening_transcript_binding{};
};

struct ReferenceShamirSubsetResult {
    bool available = false;
    bool clean = false;
    CheckpointId checkpoint = 0;
    size_t operation_count = 0;
    Digest registration_binding{};
    Digest subset_binding{};
    Digest public_coin_transcript_binding{};
    Digest challenge_binding{};
    Digest opening_transcript_binding{};
};

// Checkpoint-scoped development realization of the PAAPS activation boundary.
// Private FOLD state/output is Shamir-shared during registration and only local
// shares survive in the session. The later batch check does not contact the
// responsible owner again. This is a real MPC execution primitive, but not yet
// malicious-secure/GOD: activation can use detectable bivariate VSS when
// 3t<n, and batch opening/public coins are commit-reveal bound with robust
// Reed--Solomon decoding when 3t<n. Multiplication/degree reduction and
// guaranteed delivery remain reference-only.
class ReferenceShamirAuditSession {
public:
    ReferenceShamirAuditSession(
        uint64_t session_id, CheckpointId checkpoint,
        int rank, int world_size, int threshold,
        const RegistrationConsistencyProofBackend*
            registration_consistency_backend = nullptr,
        const MultiplicationConsistencyProofBackend*
            multiplication_consistency_backend = nullptr,
        const AuthenticatedMpcExchange* authenticated_exchange = nullptr,
        const RegistrationOriginApprovalBackend*
            registration_origin_approval_backend = nullptr,
        bool permit_reference_registration_test_only = false);

    bool RegisterFoldOperation(
        uint32_t owner, const OperationRef& ref, const F& public_challenge,
        const Digest& public_state_digest,
        const Digest& public_actual_digest,
        const Digest& operation_statement_binding,
        const std::vector<F>& owner_private_state,
        const std::vector<F>& owner_actual_output,
        const RegistrationNativeContext& native_context = {});
    // All ranks must agree on the public operation descriptors before the
    // random audit challenge is sampled.
    bool SealRegistration();

    // Public-only access to the exact VSS/native binding used by this
    // checkpoint's proof; never exposes the owner's dealer witness.
    bool ReadRegisteredPublicConsistencyStatement(
        const OperationRef& ref,
        RegistrationConsistencyStatement* out) const;
    // Fail closed after an out-of-band public-proof rejection. A checkpoint
    // aborted here cannot later be partially sealed or batch-checked.
    void AbortRegistrationBeforeSeal();

    ReferenceShamirBatchResult BatchCheck() const;
    // Checks a deterministic subset using only residual shares sealed during
    // registration; no owner private value is requested after sealing.
    ReferenceShamirSubsetResult BatchCheckSubset(
        const std::vector<OperationRef>& operations,
        const Digest& domain_binding, uint64_t round_tag) const;
    bool SelectAuditWitness(
        const OperationRef& ref,
        ReferenceShamirSelectedAuditWitness* witness) const;

    bool sealed() const { return sealed_; }
    size_t operation_count() const { return operations_.size(); }
    // Confirm that a native statement is represented by this sealed batch's
    // exact operation descriptor, not merely by a matching checkpoint ID.
    bool ContainsOperationBinding(
        const OperationRef& ref,
        const Digest& operation_statement_binding,
        const Digest& public_state_digest,
        const Digest& public_actual_digest) const;
    Digest registration_binding() const { return registration_binding_; }
    Digest registration_consistency_binding() const {
        return registration_consistency_binding_;
    }
    bool detectable_registration() const { return vss_.valid(); }
    bool multiplication_consistency_enabled() const {
        return multiplication_consistency_backend_ != nullptr;
    }
    bool authenticated_transport_enabled() const {
        return authenticated_exchange_ != nullptr &&
            mpc_.authenticated_transport_available();
    }
    Digest authenticated_transport_capability_binding() const {
        return mpc_.authenticated_transport_capability_binding();
    }
    Digest authenticated_transport_transcript_binding() const {
        return authenticated_transport_transcript_binding_;
    }

private:
    struct FoldOperationShares {
        uint32_t owner = 0;
        OperationRef ref{};
        F public_challenge{};
        Digest public_state_digest{};
        Digest public_actual_digest{};
        Digest operation_statement_binding{};
        Digest vss_transcript_binding{};
        ReferenceVssLocalWitness vss_local_witness{};
        ReferenceVssReceipt vss_receipt{};
        RegistrationConsistencyStatement registration_consistency_statement{};
        RegistrationConsistencyProofArtifact registration_consistency_proof{};
        std::vector<F> state_shares;
        std::vector<F> actual_output_shares;
        std::vector<F> residual_shares;
    };

    Digest ComputeRegistrationBinding() const;
    AuthenticatedMpcMessageContext NextTransportContext(
        u64 message_kind, uint64_t round = 0) const;
    void BindTransportTranscript(const Digest& binding) const;
    bool CollectiveSameWord(
        u64 local_value, u64 message_kind, uint64_t round,
        u64* agreed_value) const;
    bool CollectiveAllTrue(
        bool local_value, u64 message_kind, uint64_t round) const;
    bool CollectiveSameDigest(
        const Digest& local_digest, u64 message_kind, uint64_t round) const;
    bool BroadcastWords(
        int owner, const std::vector<u64>& owner_payload,
        u64 message_kind, uint64_t round, std::vector<u64>* payload) const;
    F DeriveCoefficient(
        const Digest& joint_seed, const OperationRef& ref,
        size_t coordinate) const;
    bool BuildFingerprintProvenance(
        const Digest& joint_seed, const F& fingerprint_share,
        ReferenceLinearSharingProvenance* provenance) const;

    uint64_t session_id_ = 0;
    CheckpointId checkpoint_ = 0;
    int rank_ = -1;
    int world_size_ = 0;
    ReferenceShamirMpc mpc_;
    ReferenceBivariateVss vss_;
    const RegistrationConsistencyProofBackend* registration_consistency_backend_ = nullptr;
    const RegistrationOriginApprovalBackend*
        registration_origin_approval_backend_ = nullptr;
    const MultiplicationConsistencyProofBackend* multiplication_consistency_backend_ = nullptr;
    const AuthenticatedMpcExchange* authenticated_exchange_ = nullptr;
    mutable uint64_t transport_sequence_ = 1;
    mutable Digest authenticated_transport_transcript_binding_{};
    std::vector<FoldOperationShares> operations_;
    // A failed register poisons the entire checkpoint transaction. Earlier
    // successfully registered operations cannot be selectively sealed.
    bool registration_failed_ = false;
    const bool permit_reference_registration_test_only_;
    bool sealed_ = false;
    Digest registration_binding_{};
    Digest registration_consistency_binding_{};
};

// Isolated registration pre-prove MPI regression: real ephemeral Ed25519
// endorsements and a synthetic registration consistency proof backend.
bool run_registration_origin_preprove_gate_selftest(int rank, int world_size);
bool run_reference_shamir_mpc_selftest(int rank, int world_size);

} // namespace pvia
