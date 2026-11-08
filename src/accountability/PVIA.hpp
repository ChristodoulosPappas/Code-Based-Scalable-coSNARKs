#pragma once

#include "../polynomial.h"
#include "../typedef.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

namespace pvia {

class AuditBackend;
struct RobustAuditAbortCertificate;

using RecordId = uint64_t;
using StateId = uint64_t;
using CheckpointId = uint64_t;

struct OperationRef {
    uint32_t owner = 0;
    uint64_t object_id = 0;
};
bool operator==(const OperationRef& lhs, const OperationRef& rhs);
bool operator!=(const OperationRef& lhs, const OperationRef& rhs);

struct OperationRefHash {
    size_t operator()(const OperationRef& ref) const noexcept {
        uint64_t x = ref.object_id ^
            (static_cast<uint64_t>(ref.owner) * 0x9e3779b97f4a7c15ULL);
        x ^= x >> 30;
        x *= 0xbf58476d1ce4e5b9ULL;
        x ^= x >> 27;
        x *= 0x94d049bb133111ebULL;
        x ^= x >> 31;
        return static_cast<size_t>(x);
    }
};

constexpr uint64_t META_MAGIC = 0x505649415f4d4554ULL; // "PVIA_MET"
constexpr int META_WORDS = 76;
constexpr int META_TAG = 29001;
constexpr u64 META_SCHEMA_VERSION = 6;
constexpr int META_PREDECESSOR_ROOT_OFFSET = 16;
constexpr int META_CHECKPOINT_INDEX = 20;
constexpr int META_PREDECESSOR_COUNT_INDEX = 21;
constexpr int META_SCHEMA_INDEX = 22;
constexpr int META_PREDECESSOR_EVIDENCE_FLAG_INDEX = 23;
constexpr int META_PREDECESSOR_OWNER_INDEX = 24;
constexpr int META_PREDECESSOR_OBJECT_INDEX = 25;
constexpr int META_PREDECESSOR_ACTUAL_OFFSET = 26;
constexpr int META_PREDECESSOR_PREV_ROOT_OFFSET = 30;
constexpr int META_PREDECESSOR_OBLIGATION_INDEX = 34;
constexpr int META_PUBLIC_AUX_COUNT_INDEX = 35;
constexpr int META_PUBLIC_AUX_ROOT_OFFSET = 36;
constexpr int META_PUBLIC_AUX_EVIDENCE_FLAG_INDEX = 40;
constexpr int META_PUBLIC_AUX_KIND_INDEX = 41;
constexpr int META_PUBLIC_AUX_DIGEST_OFFSET = 42;
constexpr int META_STATE_DEP_COUNT_INDEX = 46;
constexpr int META_STATE_DEP_ROOT_OFFSET = 47;
constexpr int META_STATE_DEP_EVIDENCE_FLAG_INDEX = 51;
constexpr int META_STATE_DEP_OWNER_INDEX = 52;
constexpr int META_STATE_DEP_ID_INDEX = 53;
constexpr int META_STATE_DEP_DIGEST_OFFSET = 54;
constexpr int META_RELATION_KERNEL_INDEX = 58;
constexpr int META_AUTH_SIGNER_INDEX = 59;
constexpr int META_AUTH_KEY_ID_OFFSET = 60;
constexpr int META_AUTH_WIRE_DIGEST_OFFSET = 64;
constexpr int META_AUTH_SIGNATURE_OFFSET = 68;
constexpr int META_AUTH_SIGNATURE_WORDS = 8;

enum class Phase : uint32_t {
    UNKNOWN = 0,
    INIT = 1,
    COSUMCHECK_ZERO = 2,
    COSUMCHECK_QUADRATIC = 3,
    COSUMCHECK_BATCH = 4,
    PCS = 5,
    DISTRIBUTED_SUMCHECK = 6,
    ENCODING = 7,
    ORACLE = 8,
    FOLD = 9,
    OPENING = 10,
    PUBLIC_DIRECT_VALIDATION = 11,
    SCALAR_AGGREGATION = 12
};
enum class Obligation : uint32_t {
    UNKNOWN = 0,
    DERIVE = 1,
    SEND = 2,
    RECEIVE = 3,
    CONSUME = 4,
    AGGREGATE = 5,
    PUBLISH = 6,
    ASSEMBLE = 7,
    COMMIT = 8,
    FOLD = 9,
    OPEN = 10
};

enum class RelationKind : uint32_t {
    UNKNOWN = 0,
    PRIVATE_DERIVATION = 1,
    MESSAGE_BINDING = 2,
    RECEIVE_CONSUME = 3,
    ASSEMBLY = 4,
    AGGREGATION = 5,
    COMMITMENT = 6,
    FOLDING = 7,
    OPENING = 8,
    PUBLICATION = 9
};

enum class AuditRelationKernel : uint32_t {
    UNKNOWN = 0,
    COSUMCHECK_ZERO = 1,
    COSUMCHECK_QUADRATIC = 2,
    COSUMCHECK_BATCH = 3,
    DSC_QUADRATIC = 4,
    DSC_CUBIC = 5,
    DSC_SPARROW_QUADRATIC = 6,
    DSC_SPARROW_CUBIC = 7,
    PCS_OPEN_ROUND = 8,
    PCS_BATCH_OPEN_ROUND = 9,
    ENCODING_FIRST_STAGE = 10,
    ENCODING_ASSEMBLE = 11,
    ENCODING_STAGE2 = 12,
    ENCODING_DIRECT_STAGE2 = 13,
    ORACLE_MERKLE_COMMIT = 14,
    FOLD_RS = 15,
    OPEN_QUERY = 16,
    PRODUCT_FRONTIER = 17,
    SPARSE_TRANSCRIPT = 18,
    AGGREGATE_CODED = 19,
    AGGREGATE_WEIGHTED = 20,
    AGGREGATE_BATCH = 21,
    PUBLISH_AGGREGATE = 22
};

enum class AuditPrivatePayloadKind : uint32_t {
    FIELD_VECTOR = 1,
    WORD_VECTOR = 2,
    QUADRATIC = 3,
    CUBIC = 4
};

enum class AuditPayloadStage : uint32_t {
    REGISTER_INPUT = 1,
    ACTIVATE_OUTPUT = 2
};

enum class AuditPublicAuxKind : uint32_t {
    SUMCHECK_CHALLENGE = 1,
    AGGREGATION_WEIGHTS = 2,
    FOLD_CHALLENGE = 3,
    ASSEMBLY_LAYOUT = 4,
    OPEN_QUERY = 5,
    COMMIT_DOMAIN = 6,
    GENERIC_FIELDS = 7,
    GENERIC_WORDS = 8,
    PUBLIC_VALIDATION_CONTEXT = 9
};

enum class AuditEvidenceKind : uint32_t {
    UNKNOWN = 0,
    PRIVATE_RECOVERY = 1,
    PUBLIC_TRANSFER = 2
};

struct Digest {
    std::array<uint8_t, 32> bytes{};

    bool operator==(const Digest& other) const;
    bool operator!=(const Digest& other) const;
    std::string hex() const;
};

struct Label {
    uint64_t sid = 0;
    Phase phase = Phase::UNKNOWN;
    uint32_t round = 0;
    uint32_t owner = 0;
    Obligation obligation = Obligation::UNKNOWN;
    uint64_t object_id = 0;
};
struct FieldStateSegment {
    const std::vector<F>* values = nullptr;
    size_t offset = 0;
    size_t count = 0;
};

struct StateRecord {
    StateId id = 0;
    Label label{};
    Digest digest{};
    std::string name;
    bool debug_only = true;
};

struct AuditStateView {
    StateId id = 0;
    Label label{};
    Digest digest{};
    std::string name;
    bool debug_only = true;
};

struct PublicAuxEvidence {
    AuditPublicAuxKind kind = AuditPublicAuxKind::GENERIC_WORDS;
    Digest digest{};
};

struct StateDependencyEvidence {
    uint32_t owner = 0;
    StateId state_id = 0;
    Digest digest{};
};

struct Record {
    RecordId id = 0;
    Label label{};
    Digest expected{};
    Digest actual{};
    RelationKind relation = RelationKind::UNKNOWN;
    AuditRelationKernel kernel = AuditRelationKernel::UNKNOWN;
    Digest relation_statement{};
    std::vector<PublicAuxEvidence> public_aux_evidence;
    Digest public_aux_root{};
    uint32_t declared_public_aux_count = 0;
    bool public_aux_evidence_complete = true;
    std::vector<OperationRef> predecessors;
    Digest predecessor_root{};
    Digest audit_commitment{};
    CheckpointId checkpoint = 0;
    CheckpointId source_checkpoint_hint = 0;
    uint32_t declared_predecessor_count = 0;
    OperationRef declared_predecessor_ref{};
    Digest declared_predecessor_actual{};
    Digest declared_predecessor_predecessor_root{};
    Obligation declared_predecessor_obligation = Obligation::UNKNOWN;
    bool has_declared_predecessor_evidence = false;
    bool predecessor_evidence_complete = true;
    std::vector<StateId> private_state_dependencies;
    std::vector<StateDependencyEvidence> state_dependency_evidence;
    Digest state_dependency_root{};
    uint32_t declared_state_dependency_count = 0;
    bool state_dependency_evidence_complete = true;
    // Local-only lifecycle state. These flags are never serialized into the
    // public transcript/certificate; they gate private residual finalization.
    bool private_input_bound = false;
    bool private_output_bound = false;
    bool private_relation_finalized = false;
    bool active = false;
    bool observed_remote = false;
    bool debug_only = true;
};

struct CheckpointRecord {
    CheckpointId id = 0;
    uint64_t sid = 0;
    Phase phase = Phase::UNKNOWN;
    uint32_t round = 0;
    uint32_t generation = 0;
    std::vector<OperationRef> operations;
    Digest root{};
    bool sealed = false;
};

struct OperationEvidence {
    OperationRef ref{};
    Obligation obligation = Obligation::UNKNOWN;
    RelationKind relation = RelationKind::UNKNOWN;
    AuditRelationKernel kernel = AuditRelationKernel::UNKNOWN;
    Digest expected{};
    Digest actual{};
    Digest predecessor_root{};
    Digest relation_statement{};
    Digest public_aux_root{};
    uint32_t public_aux_count = 0;
    bool public_aux_evidence_complete = true;
    std::vector<PublicAuxEvidence> public_aux_evidence;
    Digest state_dependency_root{};
    uint32_t state_dependency_count = 0;
    bool state_dependency_evidence_complete = true;
    std::vector<StateDependencyEvidence> state_dependency_evidence;
    CheckpointId source_checkpoint_hint = 0;
    uint32_t predecessor_count = 0;
};

struct AuditOperationView {
    OperationRef ref{};
    Label label{};
    RelationKind relation = RelationKind::UNKNOWN;
    AuditRelationKernel kernel = AuditRelationKernel::UNKNOWN;
    Digest expected{};
    Digest actual{};
    Digest predecessor_root{};
    Digest relation_statement{};
    Digest public_aux_root{};
    uint32_t public_aux_count = 0;
    bool public_aux_evidence_complete = true;
    Digest state_dependency_root{};
    uint32_t state_dependency_count = 0;
    bool state_dependency_evidence_complete = true;
    CheckpointId checkpoint = 0;
    CheckpointId source_checkpoint_hint = 0;
    uint32_t predecessor_count = 0;
    bool predecessor_evidence_complete = true;
    bool active = false;
    bool observed_remote = false;
};

struct AuditCheckpointView {
    CheckpointId id = 0;
    Phase phase = Phase::UNKNOWN;
    uint32_t round = 0;
    uint32_t generation = 0;
    std::vector<OperationRef> operations;
    Digest root{};
    bool sealed = false;
};

struct Violation {
    bool valid = false;
    Label label{};
    Digest expected{};
    Digest actual{};
    uint32_t responsible_rank = 0;
    CheckpointId checkpoint = 0;
    RelationKind relation = RelationKind::UNKNOWN;
    AuditRelationKernel kernel = AuditRelationKernel::UNKNOWN;
    Digest residual_commitment{};
    Digest operation_statement_binding{};
    Digest dispute_binding{};
    uint64_t sequence = 0;
    bool resolved = false;
};

struct ObligationSet {
    uint64_t session_id = 0;
    Phase phase = Phase::UNKNOWN;
    uint32_t round = 0;
    uint32_t generation = 0;
    bool exact_round = true;
    CheckpointId checkpoint = 0;
    Digest checkpoint_root{};
    std::vector<Obligation> obligations;
    std::vector<OperationRef> operations;
    // Canonical lane partition for secure failure handling. The coordinator
    // derives these from the checkpoint and broadcasts them with the scope.
    std::vector<OperationRef> private_operations;
    std::vector<OperationRef> transfer_operations;
};

struct BatchCheckResult {
    // `available` distinguishes an implemented audit backend from a scaffold
    // that deliberately fails closed. Debug results are available but are not
    // cryptographically authenticated.
    bool available = true;
    bool cryptographically_authenticated = false;
    bool ok = true;
    CheckpointId checkpoint = 0;
    size_t checked_operations = 0;
    size_t mismatches = 0;
    size_t participant_count = 0;
    Digest scope_binding{};
    Digest participant_commitment_root{};
    Digest challenge_transcript_binding{};
    Digest challenge{};
    Digest security_attestation_binding{};
    Digest aggregate_residual_commitment{};
};

struct RecoverableAuditShare {
    bool valid = false;
    bool debug_only = true;
    AuditEvidenceKind evidence_kind = AuditEvidenceKind::UNKNOWN;
    Label label{};
    RelationKind relation = RelationKind::UNKNOWN;
    AuditRelationKernel kernel = AuditRelationKernel::UNKNOWN;
    Digest expected{};
    Digest actual{};
    Digest residual_commitment{};
    Digest operation_statement_binding{};
    Digest dispute_binding{};
    Digest predecessor_root{};
    Digest checkpoint_root{};
    Digest witness_digest{};
};

struct BlameCertificate {
    bool valid = false;
    bool debug_only = true;
    AuditEvidenceKind evidence_kind = AuditEvidenceKind::UNKNOWN;
    uint64_t sid = 0;
    uint32_t accused = 0;
    Label label{};
    CheckpointId checkpoint = 0;
    RelationKind relation = RelationKind::UNKNOWN;
    AuditRelationKernel kernel = AuditRelationKernel::UNKNOWN;
    Digest expected{};
    Digest actual{};
    Digest residual_commitment{};
    Digest operation_statement_binding{};
    Digest dispute_binding{};
    Digest predecessor_root{};
    Digest checkpoint_root{};
    std::vector<OperationEvidence> predecessor_evidence;
    std::vector<OperationEvidence> checkpoint_evidence;
    bool predecessor_evidence_complete = true;
    Digest audit_witness_digest{};
    // Canonical 70-word AuthenticatedRecoveryArtifact for PRIVATE_RECOVERY.
    // Empty for PUBLIC_TRANSFER certificates.
    std::vector<u64> recovery_artifact_words;
    // Optional portable SP1/Groth16 proof of the VSS interpolation relation.
    // The public statement is repeated here so a detached verifier can compare
    // it with an independently derived statement before verifying the proof.
    uint32_t recovery_proof_system_id = 0;
    Digest recovery_proof_statement_binding{};
    Digest recovery_proof_artifact_commitment{};
    std::vector<u64> recovery_proof_statement_words;
    std::vector<uint8_t> recovery_proof_artifact_bytes;
    Digest blame_statement_binding{};
    uint32_t public_proof_system_id = 0;
    Digest public_proof_commitment{};
    Digest public_proof_transcript_binding{};
    std::vector<u64> public_proof_words;
    Digest transcript_digest{};
    Digest proof_digest{};
};
struct Config {
    bool enabled = false;
    bool verbose = false;
    uint64_t session_id = 1;
};

Digest hash_bytes(const uint8_t* data, size_t size);
Digest hash_words(const std::vector<u64>& words);
Digest hash_word_span(const u64* words, size_t count);
Digest hash_field_vector(const std::vector<F>& values);
Digest hash_field_segments(
    const std::vector<const std::vector<F>*>& segments);
Digest hash_quadratic(const quadratic_poly& poly);
Digest hash_cubic(const cubic_poly& poly);
RelationKind relation_for_obligation(Obligation obligation);
RelationKind relation_for_kernel(AuditRelationKernel kernel);
Digest compute_public_aux_root(
    const std::vector<PublicAuxEvidence>& evidence);
Digest compute_state_dependency_root(
    const std::vector<StateDependencyEvidence>& evidence);
Digest compute_relation_statement(const Label& label, RelationKind relation,
                                  AuditRelationKernel kernel,
                                  const Digest& expected,
                                  const Digest& predecessor_root,
                                  uint32_t predecessor_count,
                                  const Digest& state_dependency_root,
                                  uint32_t state_dependency_count,
                                  const Digest& public_aux_root,
                                  uint32_t public_aux_count);
Digest compute_residual_commitment(const Label& label, RelationKind relation,
                                   AuditRelationKernel kernel,
                                   const Digest& expected, const Digest& actual);

class Runtime {
public:
    static Runtime& instance();

    void initialize_from_environment(int rank, int world_size);
    void shutdown();

    bool enabled() const { return config_.enabled; }
    bool verbose() const { return config_.verbose; }
    int rank() const { return rank_; }
    int world_size() const { return world_size_; }
    uint64_t session_id() const { return config_.session_id; }
    const Config& config() const { return config_; }

    RecordId allocate_object_id() { return next_id_++; }

    StateId import_state(const std::string& name, Phase phase,
                         const std::vector<F>& local_share);
    StateId import_state_segments(
        const std::string& name, Phase phase,
        const std::vector<const std::vector<F>*>& segments);
    StateId import_state_slices(
        const std::string& name, Phase phase,
        const std::vector<FieldStateSegment>& segments);
    StateId import_state_prehashed(
        const std::string& name, Phase phase,
        const std::vector<F>& local_share, const Digest& digest);
    bool bind_state_authentication(
        StateId state_id, uint64_t scheme_id,
        const Digest& authentication_binding);

    RecordId prepare_vector(Phase phase, uint32_t round,
                            Obligation obligation,
                            const std::vector<F>& expected);
    RecordId register_vector_operation(
        Phase phase, uint32_t round, Obligation obligation,
        const std::vector<F>& expected,
        const std::vector<OperationRef>& predecessors);
    RecordId register_vector_operation_prehashed(
        Phase phase, uint32_t round, Obligation obligation,
        const std::vector<F>& expected, const Digest& expected_digest,
        const std::vector<OperationRef>& predecessors);
    RecordId register_word_operation(
        Phase phase, uint32_t round, Obligation obligation,
        const std::vector<u64>& expected,
        const std::vector<OperationRef>& predecessors);
    RecordId register_public_digest_validation(
        Phase phase, uint32_t round,
        const Digest& expected, const Digest& actual,
        const std::vector<u64>& public_context);
    RecordId register_quadratic_operation(
        Phase phase, uint32_t round, Obligation obligation,
        const quadratic_poly& expected,
        const std::vector<OperationRef>& predecessors);
    RecordId register_cubic_operation(
        Phase phase, uint32_t round, Obligation obligation,
        const cubic_poly& expected,
        const std::vector<OperationRef>& predecessors);
    RecordId prepare_followup_vector(Obligation obligation,
                                     const std::vector<F>& expected);
    uint32_t pending_round() const { return pending_valid_ ? pending_.label.round : 0; }
    Phase pending_phase() const { return pending_valid_ ? pending_.label.phase : Phase::UNKNOWN; }
    OperationRef latest_operation_ref(Phase phase) const;
    OperationRef latest_operation_ref(Phase phase, uint32_t owner) const;
    OperationRef previous_round_operation_ref(
        Phase phase, uint32_t round, Obligation obligation) const;
    std::vector<OperationRef> checkpoint_operations(
        Phase phase, uint32_t round) const;
    std::vector<OperationRef> checkpoint_operations(
        Phase phase, uint32_t round, Obligation obligation) const;
    RecordId prepare_quadratic(Phase phase, uint32_t round,
                               Obligation obligation,
                               const quadratic_poly& expected);
    RecordId prepare_cubic(Phase phase, uint32_t round,
                           Obligation obligation,
                           const cubic_poly& expected);

    void activate_vector(RecordId id,
                         const std::vector<F>& actual);
    void activate_vector_prehashed(
        RecordId id, const std::vector<F>& actual,
        const Digest& actual_digest);
    void activate_words(RecordId id,
                        const std::vector<u64>& actual);
    void set_next_commit_predecessor(const OperationRef& ref);
    OperationRef consume_next_commit_predecessor();
    void set_next_commit_state_dependency(StateId state_id);
    StateId consume_next_commit_state_dependency();
    void activate_quadratic(RecordId id,
                            const quadratic_poly& actual);
    void activate_cubic(RecordId id,
                        const cubic_poly& actual);
    void bind_state_dependencies(
        RecordId id, const std::vector<StateId>& state_ids);
    void bind_relation_kernel(RecordId id, AuditRelationKernel kernel);
    void bind_public_field_aux(
        RecordId id, AuditPublicAuxKind kind, const std::vector<F>& values);
    void bind_public_word_aux(
        RecordId id, AuditPublicAuxKind kind, const std::vector<u64>& values);


    bool has_pending_record() const { return pending_valid_; }

    std::array<u64, META_WORDS>
    make_pending_meta(const std::vector<u64>& payload, bool seal = true) const;
    std::array<u64, META_WORDS>
    make_pending_meta_digest(
        const Digest& payload_digest, bool seal = true) const;

    // Build metadata for a transcript-direct transfer object that is not
    // represented by the single pending operation record (e.g., one
    // destination segment of an MPI all-to-all).  In the current debug
    // backend this binds the sender, phase/round and payload digest.
    std::array<u64, META_WORDS>
    make_direct_meta(Phase phase, uint32_t round, Obligation obligation,
                     uint64_t object_id,
                     const std::vector<u64>& payload,
                     bool seal = true) const;
    std::array<u64, META_WORDS>
    make_direct_meta_digest(Phase phase, uint32_t round,
                            Obligation obligation, uint64_t object_id,
                            const Digest& payload_digest,
                            bool seal = true) const;

    bool seal_transfer_meta(
        std::array<u64, META_WORDS>& meta,
        const std::vector<u64>& wire_payload) const;
    bool seal_transfer_meta_digest(
        std::array<u64, META_WORDS>& meta,
        const Digest& wire_digest) const;

    void observe_outgoing_transfer(
        const std::array<u64, META_WORDS>& meta,
        const std::vector<u64>& payload);
    void observe_outgoing_transfer_digest(
        const std::array<u64, META_WORDS>& meta,
        const Digest& payload_digest);
    void observe_direct_local(
        const std::array<u64, META_WORDS>& meta,
        const std::vector<u64>& payload);
    void observe_local_payload(const std::vector<u64>& payload);
    void observe_local_payload_digest(const Digest& payload_digest);
    // Reuse an already-built signed metadata record for local transcript
    // bookkeeping instead of rebuilding and re-signing the same payload.
    void observe_local_meta(
        const std::array<u64, META_WORDS>& meta,
        const std::vector<u64>& payload);
    void observe_local_meta_digest(
        const std::array<u64, META_WORDS>& meta,
        const Digest& payload_digest);
    void record_pending_relation_violation();
    void observe_remote_meta(int sender,
                             const std::array<u64, META_WORDS>& meta,
                             const std::vector<u64>& payload);
    void observe_remote_meta_digest(
        int sender, const std::array<u64, META_WORDS>& meta,
        const Digest& payload_digest);
    bool strict_remote_transfer_valid(
        int sender, const std::array<u64, META_WORDS>& meta,
        const std::vector<u64>& payload) const;
    bool strict_remote_transfer_valid_digest(
        int sender, const std::array<u64, META_WORDS>& meta,
        const Digest& payload_digest) const;

    // Debug representation of transcript-direct public evidence.  This is
    // used when the verifier itself can compute both sides of a public
    // relation, such as a folding/query consistency check.
    void record_public_vector_violation(
        Phase phase, uint32_t round, Obligation obligation,
        uint32_t owner, uint64_t object_id,
        const std::vector<F>& expected,
        const std::vector<F>& actual,
        const std::vector<u64>& public_aux_words = {});

    void consume_pending();

    CheckpointId checkpoint_id(Phase phase, uint32_t round) const;
    void seal_checkpoint_instance(Phase phase, uint32_t round);
    ObligationSet make_scope(Phase phase, uint32_t round, bool exact_round = true) const;
    BatchCheckResult debug_batch_check(const ObligationSet& scope) const;
    Violation debug_dispute(const ObligationSet& scope,
                            const BatchCheckResult& batch) const;
    RecoverableAuditShare recover_debug_audit(const Violation& violation) const;
    BlameCertificate lift_debug_blame(const Violation& violation,
                                       const RecoverableAuditShare& audit) const;
    // The backend pointer is non-owning. Generic backends may be attached late
    // and receive public registry replay, but private state shares are never
    // retained for replay. Secure backends should therefore attach before the
    // first state/operation/checkpoint is recorded.
    void set_audit_backend(AuditBackend* backend);
    // Passive source observer receives native execution callbacks without
    // replacing the audit backend or claiming release authorization.
    // Attach before state import; no private state is retained for replay.
    bool set_source_observer(AuditBackend* observer);
    AuditBackend* source_observer() const { return source_observer_; }
    AuditBackend* audit_backend() const { return audit_backend_override_; }
    bool can_attach_secure_backend() const {
        return states_.empty() && operations_.empty() && checkpoints_.empty();
    }
    // Optional separately hosted replay-head gate. When the corresponding
    // environment requirement is enabled, every rank participates in the
    // collective decision while rank 0 advances the remote anchor exactly once.
    using ExternalReleaseAnchorGate =
        std::function<bool(const char*, Phase, uint32_t, const Digest&)>;
    void set_external_release_anchor_gate(ExternalReleaseAnchorGate gate);
    bool external_release_anchor_required() const {
        return external_release_anchor_required_;
    }
    // Active-security release gate. With an attached secure backend,
    // require an authenticated exact-checkpoint batch check before a
    // candidate value may influence the public transcript. If configured,
    // the external replay-head decision is the final fail-closed condition.
    bool pre_release_gate(const char* release_name, Phase phase,
                          uint32_t round);
    // Optional strict PVIA P1-05 gate. Each observed native FOLD starts a
    // fresh authorization epoch; a verified issuer receipt must authorize the
    // exact source/computation binding before the Merkle commitment release
    // gate can pass.
    bool private_residual_provenance_required() const {
        return require_private_residual_provenance_;
    }
    void begin_private_residual_provenance_gate(
        uint32_t expected_round = 0);
    bool bind_private_residual_provenance_source(
        const Digest& statement_binding,
        const Digest& computation_binding);
    bool authorize_private_residual_provenance(
        const Digest& statement_binding,
        const Digest& computation_binding,
        const Digest& check_transcript_binding,
        uint64_t issuer_id, uint64_t minimum_accepted_sequence);
    bool private_residual_provenance_release_gate(
        const char* release_name) const;
    bool handle_global_failure(const char* check_name, Phase phase, uint32_t round);
    bool handle_global_failure_with_backend(
        const char* check_name, Phase phase, uint32_t round,
        AuditBackend& backend);

    bool has_failure() const { return latest_certificate_.valid; }
    const BlameCertificate& latest_certificate() const {
        return latest_certificate_;
    }
    // Separate coordinator-local public abort artifact. This is not a
    // BlameCertificate and does not change has_failure() semantics.
    bool has_robust_abort_certificate() const {
        return !latest_robust_abort_certificate_words_.empty();
    }
    bool latest_robust_abort_certificate(
        RobustAuditAbortCertificate* certificate) const;
    Digest robust_abort_registry_anchor() const {
        return latest_robust_abort_registry_anchor_;
    }
    bool debug_judge(const BlameCertificate& cert) const;
    bool debug_judge_share(const BlameCertificate& cert) const;
    const std::vector<BlameCertificate>& certificates() const { return certificates_; }
    void print_summary() const;

private:
    Runtime() = default;

    RecordId prepare_record(
        Phase phase, uint32_t round, Obligation obligation,
        const Digest& expected,
        const std::vector<OperationRef>& predecessors = {});
    static OperationRef operation_ref(const Label& label);
    Record* find_operation(const OperationRef& ref);
    const Record* find_operation(const OperationRef& ref) const;
    CheckpointRecord& ensure_checkpoint(Phase phase, uint32_t round);
    CheckpointRecord* find_checkpoint(CheckpointId id);
    const CheckpointRecord* find_checkpoint(CheckpointId id) const;
    CheckpointRecord* find_latest_checkpoint(Phase phase, uint32_t round);
    const CheckpointRecord* find_latest_checkpoint(Phase phase, uint32_t round) const;
    static CheckpointId make_checkpoint_id(
        Phase phase, uint32_t round, uint32_t generation);
    Digest compute_predecessor_root(
        const std::vector<OperationRef>& predecessors) const;
    Digest compute_checkpoint_root(const CheckpointRecord& checkpoint) const;
    void seal_checkpoint(Phase phase, uint32_t round);
    void register_observed_operation(
        const std::array<u64, META_WORDS>& meta, bool observed_remote);
    void activate_record(RecordId id, const Digest& actual);
    void bind_private_field_operation(
        RecordId id, AuditPrivatePayloadKind kind, AuditPayloadStage stage,
        const std::vector<F>& values);
    void bind_private_word_operation(
        RecordId id, AuditPayloadStage stage,
        const std::vector<u64>& values);
    void bind_public_aux_digest(
        RecordId id, AuditPublicAuxKind kind, const Digest& digest);
    void maybe_finalize_private_relation(RecordId id);
    void record_violation(const Label& label,
                          const Digest& expected,
                          const Digest& actual);
    bool scope_matches(const Violation& violation,
                       const ObligationSet& scope) const;
    ObligationSet scope_for_check(const char* check_name, Phase phase,
                                  uint32_t round, bool exact_round) const;
    void mark_resolved(const Violation& violation);
    AuditStateView make_audit_state_view(const StateRecord& state) const;
    AuditOperationView make_audit_operation_view(const Record& record) const;
    AuditCheckpointView make_audit_checkpoint_view(
        const CheckpointRecord& checkpoint) const;
    void observe_public_transfer(
        const std::array<u64, META_WORDS>& meta,
        const Digest& payload_digest,
        bool remote_observation,
        int sender_override = -1);
    void update_transcript(const std::array<u64, META_WORDS>& meta);

    Config config_{};
    int rank_ = 0;
    int world_size_ = 1;
    RecordId next_id_ = 1;
    StateId next_state_id_ = 1;

    std::vector<StateRecord> states_;
    std::unordered_map<StateId, size_t> state_index_;
    std::vector<Record> operations_;
    std::unordered_map<OperationRef, size_t, OperationRefHash> operation_index_;
    std::unordered_map<uint32_t, size_t> latest_active_by_phase_;
    std::unordered_map<uint64_t, size_t> latest_active_by_phase_owner_;
    std::vector<CheckpointRecord> checkpoints_;
    std::unordered_map<CheckpointId, size_t> checkpoint_index_;
    std::unordered_map<uint64_t, size_t> latest_checkpoint_index_;
    std::vector<OperationRef> public_transfer_refs_;
    std::unordered_set<OperationRef, OperationRefHash> public_transfer_ref_set_;
    std::vector<Violation> violations_;
    std::vector<BlameCertificate> certificates_;
    uint64_t next_violation_sequence_ = 1;

    Record pending_{};
    bool pending_valid_ = false;
    OperationRef next_commit_predecessor_{};
    bool next_commit_predecessor_valid_ = false;
    StateId next_commit_state_dependency_ = 0;
    bool next_commit_state_dependency_valid_ = false;

    Digest transcript_digest_{};
    uint64_t transcript_records_ = 0;

    // One-shot cache for the pattern strict_remote_transfer_valid(...)
    // immediately followed by observe_remote_meta(...) on the same bytes.
    // The cache never authenticates new data: sender, complete metadata, and
    // payload digest must all match, and a hit is consumed immediately.
    mutable bool verified_transfer_cache_valid_ = false;
    mutable int verified_transfer_cache_sender_ = -1;
    mutable Digest verified_transfer_cache_meta_digest_{};
    mutable Digest verified_transfer_cache_payload_digest_{};

    AuditBackend* audit_backend_override_ = nullptr;
    AuditBackend* source_observer_ = nullptr;
    ExternalReleaseAnchorGate external_release_anchor_gate_{};
    bool external_release_anchor_required_ = false;
    bool require_private_residual_provenance_ = false;
    bool private_residual_provenance_gate_started_ = false;
    bool private_residual_source_bound_ = false;
    bool private_residual_provenance_authorized_ = false;
    Digest private_residual_statement_binding_{};
    Digest private_residual_computation_binding_{};
    Digest private_residual_check_transcript_binding_{};
    uint64_t private_residual_issuer_id_ = 0;
    uint64_t private_residual_minimum_sequence_ = 0;
    uint32_t private_residual_expected_round_ = 0;
    bool private_residual_provenance_release_consumed_ = false;
    uint32_t private_residual_provenance_consumed_round_ = 0;
    BlameCertificate latest_certificate_{};
    std::vector<u64> latest_robust_abort_certificate_words_;
    Digest latest_robust_abort_registry_anchor_{};
};

} // namespace pvia
