#pragma once

#include "PVIA.hpp"
#include "TransferAuthentication.hpp"

#include <mpi.h>
#include <array>
#include <vector>

namespace pvia {

constexpr u64 AUTHENTICATED_MPC_SIGNATURE_DOMAIN =
    0x50564d5043415554ULL; // PVMPCAUT
constexpr uint32_t AUTHENTICATED_MPC_BROADCAST_RECEIVER = 0xffffffffU;
constexpr u64 AUTHENTICATED_MPC_BASELINE_INPUT_DOMAIN =
    0x505649494e505554ULL; // PVIINPUT

struct AuthenticatedMpcEquivocationEvidence;
struct AuthenticatedMpcSignedEnvelopeObservation;
struct AuthenticatedMpcObservationReconciliation;

struct AuthenticatedMpcMessageContext {
    u64 protocol_domain = 0;
    uint64_t sid = 0;
    CheckpointId checkpoint = 0;
    uint64_t round = 0;
    uint64_t sequence = 0;
    u64 message_kind = 0;
};

Digest compute_authenticated_mpc_context_binding(
    const AuthenticatedMpcMessageContext& context);
bool validate_authenticated_mpc_message_context(
    const AuthenticatedMpcMessageContext& context);
Digest compute_authenticated_mpc_payload_binding(
    const std::vector<u64>& payload);
std::vector<u64> build_authenticated_mpc_signed_message(
    const AuthenticatedMpcMessageContext& context,
    uint32_t sender, uint32_t receiver, size_t world_size,
    uint64_t payload_word_count, const Digest& payload_binding);

// Observational message *shape* for an independently verified session.
// No plaintext, payload digest, signature or session identifier is included.
// Test instrumentation only: shape equality is not cryptographic privacy.
struct AuthenticatedMpcEnvelopeShapeTrace {
    bool available = false;
    uint64_t verified_messages = 0;
    Digest arrival_order_binding{};
    Digest canonical_multiset_binding{};
};

struct AuthenticatedMpcTransportCapabilities {
    bool available = false;
    bool cryptographic_authentication = false;
    bool external_registry_anchor_verified = false;
    bool binds_sender = false;
    bool binds_receiver = false;
    bool binds_checkpoint = false;
    bool binds_round_sequence = false;
    bool replay_protected = false;
    bool payload_binding_signatures = false;
    bool binds_message_kind = false;
    uint64_t protocol_id = 0;
    Digest registry_commitment{};
    Digest external_registry_anchor{};
    Digest implementation_binding{};
    Digest capability_binding{};
};

Digest compute_authenticated_mpc_transport_capability_binding(
    const AuthenticatedMpcTransportCapabilities& capabilities);
bool validate_authenticated_mpc_transport_capabilities(
    const AuthenticatedMpcTransportCapabilities& capabilities);
bool production_ready_authenticated_mpc_transport_capabilities(
    const AuthenticatedMpcTransportCapabilities& capabilities);

enum class AuthenticatedMpcLocalFailureKind : uint32_t {
    UNKNOWN = 0,
    INVALID_CONTEXT = 1,
    RETIRED_CHECKPOINT = 2,
    CONTEXT_DISAGREEMENT = 3,
    MALFORMED_ENVELOPE = 4,
    INVALID_SIGNATURE = 5,
    EXACT_REPLAY = 6,
    SEQUENCE_REGRESSION = 7,
    SIGNED_EQUIVOCATION = 8
};

// Local diagnostic only. A claimed sender attached to an invalid signature is
// not an accused party and this object is never public blame evidence.
struct AuthenticatedMpcLocalFailureObservation {
    bool available = false;
    AuthenticatedMpcLocalFailureKind kind =
        AuthenticatedMpcLocalFailureKind::UNKNOWN;
    AuthenticatedMpcMessageContext context{};
    bool has_claimed_sender = false;
    uint32_t claimed_sender = 0;
    uint32_t claimed_receiver = 0;
    Digest payload_binding{};
    Digest failure_binding{};
};

Digest compute_authenticated_mpc_local_failure_binding(
    const AuthenticatedMpcLocalFailureObservation& failure);

// Ed25519-authenticated transport over MPI collectives. MPI only moves bytes;
// signatures bind the logical sender/receiver and full audit context. This
// primitive still does NOT provide reliable broadcast, liveness, or GOD.
class AuthenticatedMpcExchange {
public:
    static constexpr uint32_t BROADCAST_RECEIVER =
        AUTHENTICATED_MPC_BROADCAST_RECEIVER;

    AuthenticatedMpcExchange(
        int rank, int world_size,
        MPI_Comm comm = MPI_COMM_WORLD);

    bool ready() const;
    AuthenticatedMpcTransportCapabilities Capabilities() const;
    bool production_authenticated_ready() const;
    Digest ProductionCapabilityBinding() const;

    bool BroadcastWords(
        const AuthenticatedMpcMessageContext& context,
        int broadcaster,
        const std::vector<u64>& broadcaster_payload,
        std::vector<u64>* payload,
        Digest* transcript_binding = nullptr) const;

    bool AllGatherWords(
        const AuthenticatedMpcMessageContext& context,
        const std::vector<u64>& local_payload,
        std::vector<u64>* all_payloads,
        Digest* transcript_binding = nullptr) const;

    bool AllTrue(
        const AuthenticatedMpcMessageContext& context,
        bool local_value, bool* all_true,
        Digest* transcript_binding = nullptr) const;

    bool ScatterWords(
        const AuthenticatedMpcMessageContext& context,
        int dealer, const std::vector<u64>& dealer_payloads,
        size_t words_per_receiver, std::vector<u64>* received_payload,
        Digest* transcript_binding = nullptr) const;

    bool AllToAllWords(
        const AuthenticatedMpcMessageContext& context,
        const std::vector<u64>& local_payloads,
        size_t words_per_receiver,
        std::vector<u64>* received_payloads,
        Digest* transcript_binding = nullptr) const;

    // Legacy development shim. New audit/MPC code should pass an explicit
    // AuthenticatedMpcMessageContext instead of overloading "step".
    bool AllGatherWords(
        u64 protocol_domain, uint64_t sid, uint64_t step,
        const std::vector<u64>& local_payload,
        std::vector<u64>* all_payloads,
        Digest* transcript_binding = nullptr) const;

    // Returns the most recent pair of conflicting, individually valid signed
    // envelopes observed for the same sender/receiver/context. Invalid
    // signatures alone are never converted into blame evidence.
    bool LastEquivocationEvidence(
        AuthenticatedMpcEquivocationEvidence* evidence) const;
    bool LastEquivocationEvidence(
        uint64_t sid, CheckpointId checkpoint,
        AuthenticatedMpcEquivocationEvidence* evidence) const;
    bool LastLocalFailure(
        AuthenticatedMpcLocalFailureObservation* failure) const;
    bool LastLocalFailure(
        uint64_t sid, CheckpointId checkpoint,
        AuthenticatedMpcLocalFailureObservation* failure) const;
    void ClearLocalFailures() const;
    bool ExportVerifiedEnvelopeObservations(
        uint64_t sid, CheckpointId checkpoint,
        std::vector<AuthenticatedMpcSignedEnvelopeObservation>* observations) const;
    // Profiles only the already-verified receive-side envelope contexts.
    // Normalizes SID to support independent runs of identical public layout.
    // Equal digest does NOT imply payload or timing indistinguishability.
    bool ExportVerifiedEnvelopeShapeTrace(
        uint64_t sid, CheckpointId checkpoint,
        AuthenticatedMpcEnvelopeShapeTrace* trace) const;
    // Best-effort authenticated dissemination of redacted observations. This
    // improves evidence availability but is not reliable broadcast/liveness/GOD.
    bool ReconcileCheckpointObservations(
        const AuthenticatedMpcMessageContext& reconciliation_context,
        uint64_t sid, CheckpointId checkpoint,
        AuthenticatedMpcObservationReconciliation* reconciliation,
        Digest* transcript_binding = nullptr) const;
    bool AcknowledgeEquivocationEvidence(
        uint64_t sid, CheckpointId checkpoint,
        const Digest& evidence_binding) const;
    // Development/selftest reset only. Production lifecycle code should use
    // AcknowledgeEquivocationEvidence followed by RetireCheckpoint.
    void ClearEquivocationEvidence() const;

    // Explicit lifecycle boundary. Tombstones are session-scoped because
    // CheckpointId is only phase/round/generation scoped and can repeat across
    // independent protocol sessions. Callers must invoke this consistently on
    // all ranks only after authenticated higher-level checkpoint finalization.
    bool RetireCheckpoint(uint64_t sid, CheckpointId checkpoint) const;
    bool CheckpointRetired(uint64_t sid, CheckpointId checkpoint) const;

    bool SelfTest(int rank, int world_size);

private:
    struct VerifiedEnvelopeRecord {
        Digest context_binding{};
        AuthenticatedMpcMessageContext context{};
        uint32_t sender = 0;
        uint32_t receiver = 0;
        uint64_t payload_word_count = 0;
        Digest payload_binding{};
        std::array<uint8_t, 64> signature{};
    };
    struct SequenceHighWaterRecord {
        u64 protocol_domain = 0;
        uint64_t sid = 0;
        CheckpointId checkpoint = 0;
        uint64_t round = 0;
        u64 message_kind = 0;
        uint32_t sender = 0;
        uint32_t receiver = 0;
        uint64_t max_sequence = 0;
    };
    struct RetiredCheckpointNamespace {
        uint64_t sid = 0;
        CheckpointId checkpoint = 0;
    };
    struct PendingEquivocationRecord {
        VerifiedEnvelopeRecord first{};
        VerifiedEnvelopeRecord second{};
    };

    bool SameContextOnAllRanks(
        const AuthenticatedMpcMessageContext& context) const;
    bool ObserveVerifiedEnvelope(
        const AuthenticatedMpcMessageContext& context,
        uint32_t sender, uint32_t receiver,
        const std::vector<u64>& payload,
        const std::array<uint8_t, 64>& signature) const;

    void RecordLocalFailure(
        AuthenticatedMpcLocalFailureKind kind,
        const AuthenticatedMpcMessageContext& context,
        bool has_claimed_sender = false,
        uint32_t claimed_sender = 0,
        uint32_t claimed_receiver = 0,
        const Digest& payload_binding = Digest{}) const;

    int rank_ = -1;
    int world_size_ = 0;
    MPI_Comm comm_ = MPI_COMM_WORLD;
    mutable std::vector<VerifiedEnvelopeRecord> verified_envelopes_;
    mutable std::vector<SequenceHighWaterRecord> sequence_high_water_;
    mutable std::vector<RetiredCheckpointNamespace> retired_checkpoints_;
    mutable std::vector<PendingEquivocationRecord> pending_equivocations_;
    mutable std::vector<AuthenticatedMpcLocalFailureObservation> local_failures_;
};

} // namespace pvia
