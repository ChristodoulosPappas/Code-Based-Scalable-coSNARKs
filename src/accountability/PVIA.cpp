#include "PVIA.hpp"
#include "PublicJudge.hpp"
#include "AuditBackend.hpp"
#include "PublicTransferObservation.hpp"
#include "TransferAuthentication.hpp"
#include "PublicTransferCertificateCodec.hpp"
#include "AuditScopeClassifier.hpp"
#include "RobustAuditSession.hpp"
#include "RobustAuditAbortCertificateCodec.hpp"
#include "ExperimentMetrics.hpp"
#include "ProtocolTrafficMetrics.hpp"
#include "../../Blake/blake3.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <mpi.h>

namespace pvia {
namespace {

bool env_flag(const char* name, bool default_value) {
    const char* value = std::getenv(name);
    if (!value) return default_value;
    std::string s(value);
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s == "1" || s == "true" || s == "yes" || s == "on";
}

long long env_int(const char* name, long long default_value) {
    const char* value = std::getenv(name);
    if (!value) return default_value;
    try { return std::stoll(value); }
    catch (...) { return default_value; }
}

std::string env_string(const char* name) {
    const char* value = std::getenv(name);
    return value ? std::string(value) : std::string();
}

bool same_failure_scope(
    const ObligationSet& expected, const ObligationSet& actual) {
    return expected.session_id == actual.session_id &&
        expected.phase == actual.phase &&
        expected.round == actual.round &&
        expected.generation == actual.generation &&
        expected.exact_round == actual.exact_round &&
        expected.checkpoint == actual.checkpoint &&
        expected.checkpoint_root == actual.checkpoint_root &&
        expected.obligations == actual.obligations &&
        expected.operations == actual.operations &&
        expected.private_operations == actual.private_operations &&
        expected.transfer_operations == actual.transfer_operations;
}

void digest_to_words(const Digest& d, u64* out4) {
    std::memcpy(out4, d.bytes.data(), 32);
}

Digest words_to_digest(const u64* in4) {
    Digest d;
    std::memcpy(d.bytes.data(), in4, 32);
    return d;
}

void append_digest_words(const Digest& digest, std::vector<u64>& words) {
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + i * 8, 8);
        words.push_back(word);
    }
}

Label label_from_meta(const std::array<u64, META_WORDS>& meta) {
    Label label;
    label.sid = meta[1];
    label.phase = static_cast<Phase>(static_cast<uint32_t>(meta[2]));
    label.round = static_cast<uint32_t>(meta[3]);
    label.owner = static_cast<uint32_t>(meta[4]);
    label.obligation = static_cast<Obligation>(static_cast<uint32_t>(meta[5]));
    label.object_id = meta[6];
    return label;
}

RelationKind relation_for_obligation_impl(Obligation obligation) {
    switch (obligation) {
        case Obligation::DERIVE: return RelationKind::PRIVATE_DERIVATION;
        case Obligation::SEND: return RelationKind::MESSAGE_BINDING;
        case Obligation::RECEIVE:
        case Obligation::CONSUME: return RelationKind::RECEIVE_CONSUME;
        case Obligation::ASSEMBLE: return RelationKind::ASSEMBLY;
        case Obligation::AGGREGATE: return RelationKind::AGGREGATION;
        case Obligation::PUBLISH: return RelationKind::PUBLICATION;
        case Obligation::COMMIT: return RelationKind::COMMITMENT;
        case Obligation::FOLD: return RelationKind::FOLDING;
        case Obligation::OPEN: return RelationKind::OPENING;
        default: return RelationKind::UNKNOWN;
    }
}

} // namespace

RelationKind relation_for_obligation(Obligation obligation) {
    return relation_for_obligation_impl(obligation);
}

RelationKind relation_for_kernel(AuditRelationKernel kernel) {
    using K = AuditRelationKernel;
    switch (kernel) {
        case K::COSUMCHECK_ZERO:
        case K::COSUMCHECK_QUADRATIC:
        case K::COSUMCHECK_BATCH:
        case K::DSC_QUADRATIC:
        case K::DSC_CUBIC:
        case K::DSC_SPARROW_QUADRATIC:
        case K::DSC_SPARROW_CUBIC:
        case K::PCS_OPEN_ROUND:
        case K::PCS_BATCH_OPEN_ROUND:
        case K::ENCODING_FIRST_STAGE:
        case K::ENCODING_STAGE2:
        case K::ENCODING_DIRECT_STAGE2:
        case K::PRODUCT_FRONTIER:
        case K::SPARSE_TRANSCRIPT:
            return RelationKind::PRIVATE_DERIVATION;
        case K::ENCODING_ASSEMBLE: return RelationKind::ASSEMBLY;
        case K::ORACLE_MERKLE_COMMIT: return RelationKind::COMMITMENT;
        case K::FOLD_RS: return RelationKind::FOLDING;
        case K::OPEN_QUERY: return RelationKind::OPENING;
        case K::AGGREGATE_CODED:
        case K::AGGREGATE_WEIGHTED:
        case K::AGGREGATE_BATCH:
            return RelationKind::AGGREGATION;
        case K::PUBLISH_AGGREGATE: return RelationKind::PUBLICATION;
        default: return RelationKind::UNKNOWN;
    }
}

bool Digest::operator==(const Digest& other) const {
    return bytes == other.bytes;
}

bool Digest::operator!=(const Digest& other) const {
    return !(*this == other);
}

bool operator==(const OperationRef& lhs, const OperationRef& rhs) {
    return lhs.owner == rhs.owner && lhs.object_id == rhs.object_id;
}

bool operator!=(const OperationRef& lhs, const OperationRef& rhs) {
    return !(lhs == rhs);
}

std::string Digest::hex() const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) oss << std::setw(2) << static_cast<int>(b);
    return oss.str();
}

Digest hash_bytes(const uint8_t* data, size_t size) {
    Digest out;
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    if (size > 0) blake3_hasher_update(&hasher, data, size);
    blake3_hasher_finalize(&hasher, out.bytes.data(), out.bytes.size());
    return out;
}

Digest hash_word_span(const u64* words, size_t count) {
    if (count == 0) return hash_bytes(nullptr, 0);
    if (!words) return Digest{};
    return hash_bytes(
        reinterpret_cast<const uint8_t*>(words), count * sizeof(u64));
}

Digest hash_words(const std::vector<u64>& words) {
    return hash_word_span(words.data(), words.size());
}

Digest hash_field_vector(const std::vector<F>& values) {
    // Canonical field-vector encoding is (real,img) per element. F itself is
    // laid out as (img,real), so hashing raw object memory would silently
    // change transcript/state digests. Stream bounded chunks in canonical
    // order to avoid a full-size temporary vector without changing bytes.
    Digest out;
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    constexpr size_t FIELDS_PER_CHUNK = 1024;
    std::array<u64, 2 * FIELDS_PER_CHUNK> words{};
    for (size_t base = 0; base < values.size(); base += FIELDS_PER_CHUNK) {
        const size_t count =
            std::min(FIELDS_PER_CHUNK, values.size() - base);
        for (size_t i = 0; i < count; ++i) {
            words[2 * i] = values[base + i].real;
            words[2 * i + 1] = values[base + i].img;
        }
        blake3_hasher_update(
            &hasher,
            reinterpret_cast<const uint8_t*>(words.data()),
            2 * count * sizeof(u64));
    }
    blake3_hasher_finalize(&hasher, out.bytes.data(), out.bytes.size());
    return out;
}

Digest hash_field_slices(
    const std::vector<FieldStateSegment>& segments) {
    // Byte-for-byte equivalent to hashing the concatenation of the selected
    // field ranges in order. Slice boundaries are deliberately not encoded.
    Digest out;
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    constexpr size_t FIELDS_PER_CHUNK = 1024;
    std::array<u64, 2 * FIELDS_PER_CHUNK> words{};
    for (const auto& segment : segments) {
        if (!segment.values ||
            segment.offset > segment.values->size() ||
            segment.count > segment.values->size() - segment.offset)
            return Digest{};
        size_t consumed = 0;
        while (consumed < segment.count) {
            const size_t count = std::min(
                FIELDS_PER_CHUNK, segment.count - consumed);
            const size_t base = segment.offset + consumed;
            for (size_t i = 0; i < count; ++i) {
                words[2 * i] = (*segment.values)[base + i].real;
                words[2 * i + 1] = (*segment.values)[base + i].img;
            }
            blake3_hasher_update(
                &hasher,
                reinterpret_cast<const uint8_t*>(words.data()),
                2 * count * sizeof(u64));
            consumed += count;
        }
    }
    blake3_hasher_finalize(&hasher, out.bytes.data(), out.bytes.size());
    return out;
}

Digest hash_field_segments(
    const std::vector<const std::vector<F>*>& segments) {
    std::vector<FieldStateSegment> slices;
    slices.reserve(segments.size());
    for (const auto* segment : segments) {
        if (!segment) return Digest{};
        slices.push_back(FieldStateSegment{segment, 0, segment->size()});
    }
    return hash_field_slices(slices);
}

Digest hash_quadratic(const quadratic_poly& poly) {
    std::vector<u64> words = {
        poly.a.real, poly.a.img,
        poly.b.real, poly.b.img,
        poly.c.real, poly.c.img
    };
    return hash_words(words);
}

Digest hash_cubic(const cubic_poly& poly) {
    std::vector<u64> words = {
        poly.a.real, poly.a.img,
        poly.b.real, poly.b.img,
        poly.c.real, poly.c.img,
        poly.d.real, poly.d.img
    };
    return hash_words(words);
}

Digest compute_public_aux_root(
    const std::vector<PublicAuxEvidence>& evidence) {
    std::vector<u64> words;
    for (const auto& item : evidence) {
        words.push_back(static_cast<u64>(item.kind));
        append_digest_words(item.digest, words);
    }
    return hash_words(words);
}

Digest compute_state_dependency_root(
    const std::vector<StateDependencyEvidence>& evidence) {
    std::vector<u64> words;
    for (const auto& item : evidence) {
        words.push_back(item.owner);
        words.push_back(item.state_id);
        append_digest_words(item.digest, words);
    }
    return hash_words(words);
}

Digest compute_relation_statement(
    const Label& label, RelationKind relation, AuditRelationKernel kernel,
    const Digest& expected,
    const Digest& predecessor_root, uint32_t predecessor_count,
    const Digest& state_dependency_root, uint32_t state_dependency_count,
    const Digest& public_aux_root, uint32_t public_aux_count) {
    std::vector<u64> words = {
        label.sid,
        static_cast<u64>(label.phase),
        label.round,
        label.owner,
        static_cast<u64>(label.obligation),
        label.object_id,
        static_cast<u64>(relation),
        static_cast<u64>(kernel),
        predecessor_count,
        state_dependency_count,
        public_aux_count
    };
    append_digest_words(expected, words);
    append_digest_words(predecessor_root, words);
    append_digest_words(state_dependency_root, words);
    append_digest_words(public_aux_root, words);
    return hash_words(words);
}

namespace {
Digest compute_message_binding_statement(
    const Label& transfer_label,
    const Record& source,
    const Digest& registered_digest) {
    if (transfer_label.obligation != Obligation::SEND ||
        transfer_label.sid != source.label.sid ||
        transfer_label.phase != source.label.phase ||
        transfer_label.round != source.label.round ||
        transfer_label.owner != source.label.owner ||
        transfer_label.object_id != source.label.object_id)
        return Digest{};
    return compute_relation_statement(
        transfer_label, RelationKind::MESSAGE_BINDING,
        AuditRelationKernel::UNKNOWN, registered_digest,
        source.predecessor_root, source.declared_predecessor_count,
        source.state_dependency_root, source.declared_state_dependency_count,
        source.public_aux_root, source.declared_public_aux_count);
}
} // namespace

Digest compute_residual_commitment(const Label& label, RelationKind relation,
                                   AuditRelationKernel kernel,
                                   const Digest& expected, const Digest& actual) {
    std::vector<u64> words = {
        label.sid,
        static_cast<u64>(label.phase),
        label.round,
        label.owner,
        static_cast<u64>(label.obligation),
        label.object_id,
        static_cast<u64>(relation),
        static_cast<u64>(kernel)
    };
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, expected.bytes.data() + i * 8, 8);
        words.push_back(word);
    }
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, actual.bytes.data() + i * 8, 8);
        words.push_back(word);
    }
    return hash_words(words);
}

uint64_t phase_round_index_key(Phase phase, uint32_t round) {
    return (static_cast<uint64_t>(static_cast<uint32_t>(phase)) << 32) |
           static_cast<uint64_t>(round);
}

uint64_t phase_owner_index_key(Phase phase, uint32_t owner) {
    return (static_cast<uint64_t>(static_cast<uint32_t>(phase)) << 32) |
           static_cast<uint64_t>(owner);
}

Runtime& Runtime::instance() {
    static Runtime runtime;
    return runtime;
}

void Runtime::initialize_from_environment(int rank, int world_size) {
    rank_ = rank;
    world_size_ = world_size;
    config_.enabled = env_flag("PVIA_ENABLE", false);
    config_.verbose = env_flag("PVIA_VERBOSE", false);
    external_release_anchor_required_ = env_flag(
        "PVIA_REQUIRE_EXTERNAL_RELEASE_ANCHOR", false);
    external_release_anchor_gate_ = {};
    require_private_residual_provenance_ = env_flag(
        "PVIA_P105_REQUIRE_PRIVATE_RESIDUAL_PROVENANCE", false);
    private_residual_provenance_gate_started_ = false;
    private_residual_source_bound_ = false;
    private_residual_provenance_authorized_ = false;
    private_residual_statement_binding_ = Digest{};
    private_residual_computation_binding_ = Digest{};
    private_residual_check_transcript_binding_ = Digest{};
    private_residual_issuer_id_ = 0;
    private_residual_minimum_sequence_ = 0;
    private_residual_expected_round_ = 0;
    private_residual_provenance_release_consumed_ = false;
    private_residual_provenance_consumed_round_ = 0;
    config_.session_id = static_cast<uint64_t>(
        env_int("PVIA_SESSION_ID", 1));
    reset_experiment_metrics_from_environment(
        rank_, world_size_, config_.session_id);

    next_id_ = 1;
    next_state_id_ = 1;
    states_.clear();
    state_index_.clear();
    operations_.clear();
    operation_index_.clear();
    latest_active_by_phase_.clear();
    latest_active_by_phase_owner_.clear();
    checkpoints_.clear();
    checkpoint_index_.clear();
    latest_checkpoint_index_.clear();
    public_transfer_refs_.clear();
    public_transfer_ref_set_.clear();
    violations_.clear();
    certificates_.clear();
    // The accountability runtime records thousands of short-lived operations
    // in the larger paper configurations.  Reserving the common-case capacity
    // avoids repeated relocation/rehashing without changing canonical order.
    states_.reserve(32);
    state_index_.reserve(64);
    operations_.reserve(4096);
    operation_index_.reserve(4096);
    latest_active_by_phase_.reserve(32);
    latest_active_by_phase_owner_.reserve(256);
    checkpoints_.reserve(256);
    checkpoint_index_.reserve(256);
    latest_checkpoint_index_.reserve(256);
    public_transfer_refs_.reserve(4096);
    public_transfer_ref_set_.reserve(4096);
    violations_.reserve(64);
    certificates_.reserve(16);
    next_violation_sequence_ = 1;
    pending_valid_ = false;
    next_commit_predecessor_ = OperationRef{};
    next_commit_predecessor_valid_ = false;
    transcript_digest_ = Digest{};
    transcript_records_ = 0;
    latest_certificate_ = BlameCertificate{};
    latest_robust_abort_certificate_words_.clear();
    latest_robust_abort_registry_anchor_ = Digest{};

    auto& transfer_auth = Ed25519TransferAuthenticator::instance();
    if (config_.enabled) {
        ExperimentDurationScope runtime_init_metrics_scope(
            ExperimentDurationKind::RUNTIME_INIT);
        const bool registry_ready = transfer_auth.Initialize(rank_, world_size_);
        if (registry_ready) {
            ExperimentControlTrafficScope traffic_scope(
                ExperimentControlTrafficKind::RUNTIME_INIT);
            record_control_allgather(32, world_size_);
        }
    } else {
        transfer_auth.Reset();
    }

    if (config_.enabled && rank_ == 0) {
        std::cout << "[PVIA] development accountability path enabled"
                  << " (sid=" << config_.session_id << ")\n";
        std::cout << "[PVIA] Ed25519 transfer authentication: "
                  << (transfer_auth.ready() ? "ready" : "UNAVAILABLE")
                  << "\n";
        if (transfer_auth.ready()) {
            std::cout << "[PVIA] transfer key registry commitment="
                      << transfer_auth.RegistryCommitment().hex()
                      << " anchored="
                      << (transfer_auth.ExternalRegistryAnchorVerified()
                              ? "yes" : "no")
                      << "\n";
        }
        if (!audit_backend_override_) {
            std::cout << "[PVIA] WARNING: no external audit backend attached; "
                      << "the default path is DEBUG-ONLY and does not provide "
                      << "cryptographic public authentication or zero-knowledge "
                      << "blame lifting.\n";
        } else {
            std::cout << "[PVIA] external audit backend attached before protocol "
                      << "state import; backend-specific security checks apply.\n";
        }
    }
}

void Runtime::shutdown() {
    if (config_.enabled && rank_ == 0) print_summary();
    if (experiment_metrics_enabled()) {
        const bool wrote = emit_experiment_metrics_csv(
            rank_, world_size_, config_.session_id);
        if (!wrote && rank_ == 0)
            std::cout << "[PVIA][metrics] FAILED to write metrics CSV\n";
    }
    Ed25519TransferAuthenticator::instance().Reset();
}

StateId Runtime::import_state(const std::string& name, Phase phase,
                              const std::vector<F>& local_share) {
    if (!config_.enabled) return 0;

    StateRecord state;
    state.id = next_state_id_++;
    state.name = name;
    state.digest = hash_field_vector(local_share);
    state.label.sid = config_.session_id;
    state.label.phase = phase;
    state.label.round = 0;
    state.label.owner = static_cast<uint32_t>(rank_);
    state.label.obligation = Obligation::DERIVE;
    state.label.object_id = state.id;
    states_.push_back(state);
    state_index_[state.id] = states_.size() - 1;
    if (audit_backend_override_ || source_observer_) {
        const AuditStateView view = make_audit_state_view(states_.back());
        const std::vector<size_t> segment_lengths{local_share.size()};
        if (audit_backend_override_) {
            audit_backend_override_->OnImportStateMetadata(view);
            audit_backend_override_->OnBindPrivateStateSegments(
                view, local_share, segment_lengths);
        }
        if (source_observer_) {
            source_observer_->OnImportStateMetadata(view);
            source_observer_->OnBindPrivateStateSegments(
                view, local_share, segment_lengths);
        }
    }

    if (config_.verbose) {
        std::cout << "[PVIA][rank " << rank_ << "] import state "
                  << name << " id=" << state.id
                  << " digest=" << state.digest.hex().substr(0, 12)
                  << "...\n";
    }
    return state.id;
}

StateId Runtime::import_state_segments(
    const std::string& name, Phase phase,
    const std::vector<const std::vector<F>*>& segments) {
    if (segments.empty()) return 0;
    std::vector<FieldStateSegment> slices;
    slices.reserve(segments.size());
    for (const auto* segment : segments) {
        if (!segment) return 0;
        slices.push_back(FieldStateSegment{segment, 0, segment->size()});
    }
    return import_state_slices(name, phase, slices);
}

StateId Runtime::import_state_slices(
    const std::string& name, Phase phase,
    const std::vector<FieldStateSegment>& segments) {
    if (!config_.enabled || segments.empty()) return 0;

    StateRecord state;
    state.id = next_state_id_++;
    state.name = name;
    state.digest = hash_field_slices(segments);
    if (state.digest == Digest{}) return 0;
    state.label.sid = config_.session_id;
    state.label.phase = phase;
    state.label.round = 0;
    state.label.owner = static_cast<uint32_t>(rank_);
    state.label.obligation = Obligation::DERIVE;
    state.label.object_id = state.id;
    states_.push_back(state);
    state_index_[state.id] = states_.size() - 1;

    if (audit_backend_override_ || source_observer_) {
        size_t total = 0;
        std::vector<size_t> segment_lengths;
        segment_lengths.reserve(segments.size());
        for (const auto& segment : segments) {
            if (!segment.values ||
                segment.offset > segment.values->size() ||
                segment.count > segment.values->size() - segment.offset ||
                total > std::numeric_limits<size_t>::max() - segment.count)
                return 0;
            total += segment.count;
            segment_lengths.push_back(segment.count);
        }
        std::vector<F> concatenated;
        concatenated.reserve(total);
        for (const auto& segment : segments) {
            concatenated.insert(
                concatenated.end(),
                segment.values->begin() +
                    static_cast<std::ptrdiff_t>(segment.offset),
                segment.values->begin() +
                    static_cast<std::ptrdiff_t>(
                        segment.offset + segment.count));
        }
        const AuditStateView view = make_audit_state_view(states_.back());
        if (audit_backend_override_) {
            audit_backend_override_->OnImportStateMetadata(view);
            audit_backend_override_->OnBindPrivateStateSegments(
                view, concatenated, segment_lengths);
        }
        if (source_observer_) {
            source_observer_->OnImportStateMetadata(view);
            source_observer_->OnBindPrivateStateSegments(
                view, concatenated, segment_lengths);
        }
    }

    if (config_.verbose) {
        std::cout << "[PVIA][rank " << rank_ << "] import sliced state "
                  << name << " id=" << state.id
                  << " digest=" << state.digest.hex().substr(0, 12)
                  << "... segments=" << segments.size() << "\n";
    }
    return state.id;
}


StateId Runtime::import_state_prehashed(
    const std::string& name, Phase phase,
    const std::vector<F>& local_share, const Digest& digest) {
    if (!config_.enabled || digest == Digest{}) return 0;

    StateRecord state;
    state.id = next_state_id_++;
    state.name = name;
    state.digest = digest;
    state.label.sid = config_.session_id;
    state.label.phase = phase;
    state.label.round = 0;
    state.label.owner = static_cast<uint32_t>(rank_);
    state.label.obligation = Obligation::DERIVE;
    state.label.object_id = state.id;
    states_.push_back(state);
    state_index_[state.id] = states_.size() - 1;

    if (audit_backend_override_ || source_observer_) {
        const AuditStateView view = make_audit_state_view(states_.back());
        const std::vector<size_t> segment_lengths{local_share.size()};
        if (audit_backend_override_) {
            audit_backend_override_->OnImportStateMetadata(view);
            audit_backend_override_->OnBindPrivateStateSegments(
                view, local_share, segment_lengths);
        }
        if (source_observer_) {
            source_observer_->OnImportStateMetadata(view);
            source_observer_->OnBindPrivateStateSegments(
                view, local_share, segment_lengths);
        }
    }
    return state.id;
}

bool Runtime::bind_state_authentication(
    StateId state_id, uint64_t scheme_id,
    const Digest& authentication_binding) {
    if (!config_.enabled || !audit_backend_override_ || state_id == 0 ||
        scheme_id == 0 || authentication_binding == Digest{})
        return false;
    const auto state_it = state_index_.find(state_id);
    if (state_it == state_index_.end() ||
        state_it->second >= states_.size())
        return false;
    const StateRecord& state = states_[state_it->second];
    return audit_backend_override_->OnBindPrivateStateAuthentication(
        make_audit_state_view(state), scheme_id,
        authentication_binding);
}

AuditStateView Runtime::make_audit_state_view(
    const StateRecord& state) const {
    AuditStateView view;
    view.id = state.id;
    view.label = state.label;
    view.digest = state.digest;
    view.name = state.name;
    view.debug_only = state.debug_only;
    return view;
}

AuditOperationView Runtime::make_audit_operation_view(
    const Record& record) const {
    AuditOperationView view;
    view.ref = operation_ref(record.label);
    view.label = record.label;
    view.relation = record.relation;
    view.kernel = record.kernel;
    view.expected = record.expected;
    view.actual = record.actual;
    view.predecessor_root = record.predecessor_root;
    view.relation_statement = record.relation_statement;
    view.public_aux_root = record.public_aux_root;
    view.public_aux_count = record.declared_public_aux_count;
    view.public_aux_evidence_complete = record.public_aux_evidence_complete;
    view.state_dependency_root = record.state_dependency_root;
    view.state_dependency_count = record.declared_state_dependency_count;
    view.state_dependency_evidence_complete =
        record.state_dependency_evidence_complete;
    view.checkpoint = record.checkpoint;
    view.source_checkpoint_hint = record.source_checkpoint_hint;
    view.predecessor_count = record.declared_predecessor_count;
    view.predecessor_evidence_complete =
        record.predecessor_evidence_complete;
    view.active = record.active;
    view.observed_remote = record.observed_remote;
    return view;
}

AuditCheckpointView Runtime::make_audit_checkpoint_view(
    const CheckpointRecord& checkpoint) const {
    AuditCheckpointView view;
    view.id = checkpoint.id;
    view.phase = checkpoint.phase;
    view.round = checkpoint.round;
    view.generation = checkpoint.generation;
    view.operations = checkpoint.operations;
    view.root = checkpoint.root;
    view.sealed = checkpoint.sealed;
    return view;
}

bool Runtime::set_source_observer(AuditBackend* observer) {
    if (observer == source_observer_) return true;
    // The native private shares and operation payloads are callback-only.
    // Never attach an observer after the protocol has started.
    if (observer && (!states_.empty() || !operations_.empty() ||
                     !checkpoints_.empty() ||
                     observer == audit_backend_override_))
        return false;
    source_observer_ = observer;
    return true;
}

void Runtime::set_external_release_anchor_gate(
    ExternalReleaseAnchorGate gate) {
    external_release_anchor_gate_ = gate;
}

void Runtime::set_audit_backend(AuditBackend* backend) {
    if (audit_backend_override_ == backend) return;
    audit_backend_override_ = backend;
    if (!audit_backend_override_) return;

    for (const auto& state : states_)
        audit_backend_override_->OnImportStateMetadata(
            make_audit_state_view(state));
    if (!states_.empty() && config_.verbose) {
        std::cout << "[PVIA] backend attached after state import: replayed "
                  << "metadata only; private share bindings are not retained\n";
    }

    for (const auto& operation : operations_) {
        const AuditOperationView view = make_audit_operation_view(operation);
        audit_backend_override_->OnRegisterOperation(view);
        if (operation.active)
            audit_backend_override_->OnActivateOperation(view);
    }
    for (const auto& checkpoint : checkpoints_) {
        if (checkpoint.sealed)
            audit_backend_override_->OnSealCheckpoint(
                make_audit_checkpoint_view(checkpoint));
    }
}

OperationRef Runtime::operation_ref(const Label& label) {
    OperationRef ref;
    ref.owner = label.owner;
    ref.object_id = label.object_id;
    return ref;
}

Record* Runtime::find_operation(const OperationRef& ref) {
    const auto it = operation_index_.find(ref);
    if (it == operation_index_.end() || it->second >= operations_.size())
        return nullptr;
    return &operations_[it->second];
}

const Record* Runtime::find_operation(const OperationRef& ref) const {
    const auto it = operation_index_.find(ref);
    if (it == operation_index_.end() || it->second >= operations_.size())
        return nullptr;
    return &operations_[it->second];
}

CheckpointRecord& Runtime::ensure_checkpoint(Phase phase, uint32_t round) {
    CheckpointRecord* latest = find_latest_checkpoint(phase, round);
    if (latest && !latest->sealed) return *latest;

    const uint32_t generation = latest ? latest->generation + 1 : 0;
    CheckpointRecord checkpoint;
    checkpoint.id = make_checkpoint_id(phase, round, generation);
    checkpoint.phase = phase;
    checkpoint.round = round;
    checkpoint.generation = generation;
    checkpoints_.push_back(checkpoint);
    const size_t index = checkpoints_.size() - 1;
    checkpoint_index_[checkpoint.id] = index;
    latest_checkpoint_index_[phase_round_index_key(phase, round)] = index;
    return checkpoints_.back();
}

CheckpointRecord* Runtime::find_checkpoint(CheckpointId id) {
    const auto it = checkpoint_index_.find(id);
    if (it == checkpoint_index_.end() || it->second >= checkpoints_.size())
        return nullptr;
    return &checkpoints_[it->second];
}

const CheckpointRecord* Runtime::find_checkpoint(CheckpointId id) const {
    const auto it = checkpoint_index_.find(id);
    if (it == checkpoint_index_.end() || it->second >= checkpoints_.size())
        return nullptr;
    return &checkpoints_[it->second];
}

CheckpointRecord* Runtime::find_latest_checkpoint(Phase phase, uint32_t round) {
    const auto it = latest_checkpoint_index_.find(
        phase_round_index_key(phase, round));
    if (it == latest_checkpoint_index_.end() ||
        it->second >= checkpoints_.size())
        return nullptr;
    return &checkpoints_[it->second];
}

const CheckpointRecord* Runtime::find_latest_checkpoint(
    Phase phase, uint32_t round) const {
    const auto it = latest_checkpoint_index_.find(
        phase_round_index_key(phase, round));
    if (it == latest_checkpoint_index_.end() ||
        it->second >= checkpoints_.size())
        return nullptr;
    return &checkpoints_[it->second];
}

CheckpointId Runtime::make_checkpoint_id(
    Phase phase, uint32_t round, uint32_t generation) {
    return (static_cast<uint64_t>(static_cast<uint32_t>(phase) & 0xffU) << 56) |
           (static_cast<uint64_t>(round) << 24) |
           static_cast<uint64_t>(generation & 0x00ffffffU);
}

OperationRef Runtime::latest_operation_ref(Phase phase) const {
    const auto it =
        latest_active_by_phase_.find(static_cast<uint32_t>(phase));
    if (it == latest_active_by_phase_.end() ||
        it->second >= operations_.size())
        return OperationRef{};
    return operation_ref(operations_[it->second].label);
}

OperationRef Runtime::latest_operation_ref(Phase phase, uint32_t owner) const {
    const auto it = latest_active_by_phase_owner_.find(
        phase_owner_index_key(phase, owner));
    if (it == latest_active_by_phase_owner_.end() ||
        it->second >= operations_.size())
        return OperationRef{};
    return operation_ref(operations_[it->second].label);
}

OperationRef Runtime::previous_round_operation_ref(
    Phase phase, uint32_t round, Obligation obligation) const {
    if (round == 0) return OperationRef{};

    uint32_t generation = 0;
    const CheckpointRecord* current = find_latest_checkpoint(phase, round);
    if (current)
        generation = current->sealed ? current->generation + 1 : current->generation;

    const CheckpointRecord* previous = find_checkpoint(
        make_checkpoint_id(phase, round - 1, generation));
    if (!previous) return OperationRef{};

    for (auto it = previous->operations.rbegin();
         it != previous->operations.rend(); ++it) {
        const Record* operation = find_operation(*it);
        if (operation && operation->active &&
            operation->label.obligation == obligation)
            return *it;
    }
    return OperationRef{};
}

std::vector<OperationRef> Runtime::checkpoint_operations(
    Phase phase, uint32_t round) const {
    const CheckpointRecord* checkpoint =
        find_latest_checkpoint(phase, round);
    return checkpoint ? checkpoint->operations : std::vector<OperationRef>{};
}

std::vector<OperationRef> Runtime::checkpoint_operations(
    Phase phase, uint32_t round, Obligation obligation) const {
    std::vector<OperationRef> result;
    const CheckpointRecord* checkpoint =
        find_latest_checkpoint(phase, round);
    if (!checkpoint) return result;
    for (const auto& ref : checkpoint->operations) {
        const Record* operation = find_operation(ref);
        if (operation && operation->label.obligation == obligation)
            result.push_back(ref);
    }
    return result;
}

Digest Runtime::compute_predecessor_root(
    const std::vector<OperationRef>& predecessors) const {
    std::vector<u64> words;
    for (const auto& ref : predecessors) {
        words.push_back(ref.owner);
        words.push_back(ref.object_id);
        const Record* predecessor = find_operation(ref);
        if (predecessor) {
            append_digest_words(predecessor->actual, words);
            append_digest_words(predecessor->predecessor_root, words);
        }
    }
    return hash_words(words);
}

Digest Runtime::compute_checkpoint_root(
    const CheckpointRecord& checkpoint) const {
    std::vector<OperationRef> refs = checkpoint.operations;
    std::sort(refs.begin(), refs.end(),
        [](const OperationRef& lhs, const OperationRef& rhs) {
            if (lhs.owner != rhs.owner) return lhs.owner < rhs.owner;
            return lhs.object_id < rhs.object_id;
        });
    std::vector<u64> words = { checkpoint.id,
        static_cast<u64>(checkpoint.phase), checkpoint.round };
    for (const auto& ref : refs) {
        words.push_back(ref.owner);
        words.push_back(ref.object_id);
        const Record* operation = find_operation(ref);
        if (!operation) continue;
        words.push_back(static_cast<u64>(operation->label.obligation));
        words.push_back(static_cast<u64>(operation->relation));
        words.push_back(static_cast<u64>(operation->kernel));
        words.push_back(operation->source_checkpoint_hint);
        words.push_back(operation->declared_predecessor_count);
        words.push_back(operation->declared_state_dependency_count);
        words.push_back(operation->declared_public_aux_count);
        append_digest_words(operation->expected, words);
        append_digest_words(operation->actual, words);
        append_digest_words(operation->predecessor_root, words);
        append_digest_words(operation->state_dependency_root, words);
        append_digest_words(operation->public_aux_root, words);
        append_digest_words(operation->relation_statement, words);
    }
    return hash_words(words);
}

void Runtime::seal_checkpoint(Phase phase, uint32_t round) {
    CheckpointRecord* checkpoint = find_latest_checkpoint(phase, round);
    if (!checkpoint) checkpoint = &ensure_checkpoint(phase, round);
    if (checkpoint->sealed) return;
    checkpoint->root = compute_checkpoint_root(*checkpoint);
    checkpoint->sealed = true;
    if (audit_backend_override_)
        audit_backend_override_->OnSealCheckpoint(
            make_audit_checkpoint_view(*checkpoint));
    if (source_observer_)
        source_observer_->OnSealCheckpoint(
            make_audit_checkpoint_view(*checkpoint));
}

void Runtime::seal_checkpoint_instance(Phase phase, uint32_t round) {
    seal_checkpoint(phase, round);
}

RecordId Runtime::prepare_record(
    Phase phase, uint32_t round, Obligation obligation,
    const Digest& expected,
    const std::vector<OperationRef>& predecessors) {
    Record rec;
    rec.id = next_id_++;
    rec.label.sid = config_.session_id;
    rec.label.phase = phase;
    rec.label.round = round;
    rec.label.owner = static_cast<uint32_t>(rank_);
    rec.label.obligation = obligation;
    rec.label.object_id = rec.id;
    rec.expected = expected;
    rec.actual = expected;
    rec.predecessors = predecessors;
    rec.predecessor_root = compute_predecessor_root(predecessors);
    rec.public_aux_root = compute_public_aux_root(rec.public_aux_evidence);
    rec.declared_public_aux_count = 0;
    rec.public_aux_evidence_complete = true;
    rec.state_dependency_root = compute_state_dependency_root({});
    rec.declared_state_dependency_count = 0;
    rec.state_dependency_evidence_complete = true;
    rec.relation = relation_for_obligation(obligation);
    rec.kernel = AuditRelationKernel::UNKNOWN;
    rec.relation_statement = compute_relation_statement(
        rec.label, rec.relation, rec.kernel, rec.expected, rec.predecessor_root,
        static_cast<uint32_t>(predecessors.size()),
        rec.state_dependency_root, rec.declared_state_dependency_count,
        rec.public_aux_root, rec.declared_public_aux_count);
    CheckpointRecord& checkpoint = ensure_checkpoint(phase, round);
    rec.checkpoint = checkpoint.id;
    rec.source_checkpoint_hint = checkpoint.id;
    rec.declared_predecessor_count =
        static_cast<uint32_t>(predecessors.size());
    rec.predecessor_evidence_complete = true;
    rec.active = false;
    rec.observed_remote = false;
    rec.debug_only = true;

    operations_.push_back(rec);
    operation_index_[operation_ref(operations_.back().label)] =
        operations_.size() - 1;
    checkpoint.operations.push_back(operation_ref(rec.label));
    checkpoint.sealed = false;
    if (audit_backend_override_)
        audit_backend_override_->OnRegisterOperation(
            make_audit_operation_view(operations_.back()));
    if (source_observer_)
        source_observer_->OnRegisterOperation(
            make_audit_operation_view(operations_.back()));

    pending_ = rec;
    pending_valid_ = true;
    return rec.id;
}

RecordId Runtime::prepare_vector(Phase phase, uint32_t round,
                                 Obligation obligation,
                                 const std::vector<F>& expected) {
    return register_vector_operation(phase, round, obligation, expected, {});
}

RecordId Runtime::register_vector_operation(
    Phase phase, uint32_t round, Obligation obligation,
    const std::vector<F>& expected,
    const std::vector<OperationRef>& predecessors) {
    if (!config_.enabled) return 0;
    const RecordId id = prepare_record(phase, round, obligation,
                                       hash_field_vector(expected), predecessors);
    bind_private_field_operation(
        id, AuditPrivatePayloadKind::FIELD_VECTOR,
        AuditPayloadStage::REGISTER_INPUT, expected);
    return id;
}


RecordId Runtime::register_vector_operation_prehashed(
    Phase phase, uint32_t round, Obligation obligation,
    const std::vector<F>& expected, const Digest& expected_digest,
    const std::vector<OperationRef>& predecessors) {
    if (!config_.enabled || expected_digest == Digest{}) return 0;
    const RecordId id = prepare_record(
        phase, round, obligation, expected_digest, predecessors);
    bind_private_field_operation(
        id, AuditPrivatePayloadKind::FIELD_VECTOR,
        AuditPayloadStage::REGISTER_INPUT, expected);
    return id;
}

RecordId Runtime::register_word_operation(
    Phase phase, uint32_t round, Obligation obligation,
    const std::vector<u64>& expected,
    const std::vector<OperationRef>& predecessors) {
    if (!config_.enabled) return 0;
    const RecordId id = prepare_record(phase, round, obligation,
                                       hash_words(expected), predecessors);
    bind_private_word_operation(id, AuditPayloadStage::REGISTER_INPUT, expected);
    return id;
}

RecordId Runtime::register_public_digest_validation(
    Phase phase, uint32_t round,
    const Digest& expected, const Digest& actual,
    const std::vector<u64>& public_context) {
    if (!config_.enabled || expected == Digest{} || actual == Digest{} ||
        public_context.empty())
        return 0;
    const RecordId id = prepare_record(
        phase, round, Obligation::PUBLISH, expected, {});
    bind_public_word_aux(
        id, AuditPublicAuxKind::PUBLIC_VALIDATION_CONTEXT, public_context);
    activate_record(id, actual);
    record_pending_relation_violation();
    consume_pending();
    seal_checkpoint(phase, round);
    return id;
}

RecordId Runtime::register_quadratic_operation(
    Phase phase, uint32_t round, Obligation obligation,
    const quadratic_poly& expected,
    const std::vector<OperationRef>& predecessors) {
    if (!config_.enabled) return 0;
    const RecordId id = prepare_record(phase, round, obligation,
                                       hash_quadratic(expected), predecessors);
    const std::vector<F> coefficients = {expected.a, expected.b, expected.c};
    bind_private_field_operation(
        id, AuditPrivatePayloadKind::QUADRATIC,
        AuditPayloadStage::REGISTER_INPUT, coefficients);
    return id;
}

RecordId Runtime::register_cubic_operation(
    Phase phase, uint32_t round, Obligation obligation,
    const cubic_poly& expected,
    const std::vector<OperationRef>& predecessors) {
    if (!config_.enabled) return 0;
    const RecordId id = prepare_record(phase, round, obligation,
                                       hash_cubic(expected), predecessors);
    const std::vector<F> coefficients = {
        expected.a, expected.b, expected.c, expected.d};
    bind_private_field_operation(
        id, AuditPrivatePayloadKind::CUBIC,
        AuditPayloadStage::REGISTER_INPUT, coefficients);
    return id;
}

RecordId Runtime::prepare_followup_vector(Obligation obligation,
                                          const std::vector<F>& expected) {
    if (!config_.enabled) return 0;
    Phase phase = Phase::UNKNOWN;
    uint32_t round = 0;
    std::vector<OperationRef> predecessors;
    if (pending_valid_) {
        phase = pending_.label.phase;
        round = pending_.label.round;
        predecessors.push_back(operation_ref(pending_.label));
    }
    return register_vector_operation(phase, round, obligation,
                                     expected, predecessors);
}

RecordId Runtime::prepare_quadratic(Phase phase, uint32_t round,
                                    Obligation obligation,
                                    const quadratic_poly& expected) {
    if (!config_.enabled) return 0;
    return register_quadratic_operation(phase, round, obligation, expected, {});
}

RecordId Runtime::prepare_cubic(Phase phase, uint32_t round,
                                Obligation obligation,
                                const cubic_poly& expected) {
    if (!config_.enabled) return 0;
    return register_cubic_operation(phase, round, obligation, expected, {});
}

void Runtime::activate_record(RecordId id, const Digest& actual) {
    if (!config_.enabled || !pending_valid_) return;
    if (pending_.id != id) return;

    pending_.actual = actual;
    pending_.active = true;
    if (Record* operation = find_operation(operation_ref(pending_.label))) {
        operation->actual = actual;
        operation->active = true;
        const OperationRef active_ref = operation_ref(operation->label);
        const auto active_it = operation_index_.find(active_ref);
        if (active_it != operation_index_.end()) {
            const size_t active_index = active_it->second;
            auto& phase_index = latest_active_by_phase_[
                static_cast<uint32_t>(operation->label.phase)];
            auto& owner_index = latest_active_by_phase_owner_[
                phase_owner_index_key(
                    operation->label.phase, operation->label.owner)];
            if (phase_index <= active_index) phase_index = active_index;
            if (owner_index <= active_index) owner_index = active_index;
        }
        if (CheckpointRecord* checkpoint = find_checkpoint(operation->checkpoint))
            checkpoint->sealed = false;
        if (audit_backend_override_)
            audit_backend_override_->OnActivateOperation(
                make_audit_operation_view(*operation));
        if (source_observer_)
            source_observer_->OnActivateOperation(
                make_audit_operation_view(*operation));
    }

    if (config_.verbose) {
        std::cout << "[PVIA][rank " << rank_ << "] activate object="
                  << pending_.id << " phase="
                  << static_cast<uint32_t>(pending_.label.phase)
                  << " round=" << pending_.label.round
                  << " expected=" << pending_.expected.hex().substr(0, 12)
                  << " actual=" << pending_.actual.hex().substr(0, 12)
                  << "\n";
    }
}

void Runtime::bind_private_field_operation(
    RecordId id, AuditPrivatePayloadKind kind, AuditPayloadStage stage,
    const std::vector<F>& values) {
    if (!config_.enabled ||
        (!audit_backend_override_ && !source_observer_) || id == 0) return;
    OperationRef ref;
    ref.owner = static_cast<uint32_t>(rank_);
    ref.object_id = id;
    Record* operation = find_operation(ref);
    if (!operation) return;
    if (stage == AuditPayloadStage::ACTIVATE_OUTPUT && !operation->active) return;
    if (stage == AuditPayloadStage::REGISTER_INPUT)
        operation->private_input_bound = true;
    else
        operation->private_output_bound = true;
    if (audit_backend_override_)
        audit_backend_override_->OnBindPrivateFieldOperation(
            make_audit_operation_view(*operation), kind, stage, values);
    if (source_observer_)
        source_observer_->OnBindPrivateFieldOperation(
            make_audit_operation_view(*operation), kind, stage, values);
    if (stage == AuditPayloadStage::ACTIVATE_OUTPUT)
        maybe_finalize_private_relation(id);
}

void Runtime::bind_private_word_operation(
    RecordId id, AuditPayloadStage stage, const std::vector<u64>& values) {
    if (!config_.enabled ||
        (!audit_backend_override_ && !source_observer_) || id == 0) return;
    OperationRef ref;
    ref.owner = static_cast<uint32_t>(rank_);
    ref.object_id = id;
    Record* operation = find_operation(ref);
    if (!operation) return;
    if (stage == AuditPayloadStage::ACTIVATE_OUTPUT && !operation->active) return;
    if (stage == AuditPayloadStage::REGISTER_INPUT)
        operation->private_input_bound = true;
    else
        operation->private_output_bound = true;
    if (audit_backend_override_)
        audit_backend_override_->OnBindPrivateWordOperation(
            make_audit_operation_view(*operation), stage, values);
    if (source_observer_)
        source_observer_->OnBindPrivateWordOperation(
            make_audit_operation_view(*operation), stage, values);
    if (stage == AuditPayloadStage::ACTIVATE_OUTPUT)
        maybe_finalize_private_relation(id);
}

void Runtime::maybe_finalize_private_relation(RecordId id) {
    if (!config_.enabled ||
        (!audit_backend_override_ && !source_observer_) || id == 0) return;
    OperationRef ref;
    ref.owner = static_cast<uint32_t>(rank_);
    ref.object_id = id;
    Record* operation = find_operation(ref);
    if (!operation || operation->observed_remote) return;
    if (!operation->active || !operation->private_input_bound ||
        !operation->private_output_bound || operation->private_relation_finalized)
        return;
    operation->private_relation_finalized = true;
    if (audit_backend_override_)
        audit_backend_override_->OnFinalizePrivateRelation(
            make_audit_operation_view(*operation));
    if (source_observer_)
        source_observer_->OnFinalizePrivateRelation(
            make_audit_operation_view(*operation));
}

void Runtime::activate_vector(RecordId id,
                              const std::vector<F>& actual) {
    if (!config_.enabled) return;
    activate_record(id, hash_field_vector(actual));
    bind_private_field_operation(
        id, AuditPrivatePayloadKind::FIELD_VECTOR,
        AuditPayloadStage::ACTIVATE_OUTPUT, actual);
}


void Runtime::activate_vector_prehashed(
    RecordId id, const std::vector<F>& actual,
    const Digest& actual_digest) {
    if (!config_.enabled || actual_digest == Digest{}) return;
    activate_record(id, actual_digest);
    bind_private_field_operation(
        id, AuditPrivatePayloadKind::FIELD_VECTOR,
        AuditPayloadStage::ACTIVATE_OUTPUT, actual);
}

void Runtime::activate_words(RecordId id,
                             const std::vector<u64>& actual) {
    if (!config_.enabled) return;
    activate_record(id, hash_words(actual));
    bind_private_word_operation(id, AuditPayloadStage::ACTIVATE_OUTPUT, actual);
}

void Runtime::bind_state_dependencies(
    RecordId id, const std::vector<StateId>& state_ids) {
    if (!config_.enabled || id == 0) return;
    OperationRef ref;
    ref.owner = static_cast<uint32_t>(rank_);
    ref.object_id = id;
    Record* operation = find_operation(ref);
    if (!operation || operation->observed_remote) return;

    operation->private_state_dependencies = state_ids;
    operation->state_dependency_evidence.clear();
    operation->state_dependency_evidence_complete = true;
    for (StateId state_id : state_ids) {
        const auto state_it = state_index_.find(state_id);
        if (state_it == state_index_.end() ||
            state_it->second >= states_.size()) {
            operation->state_dependency_evidence_complete = false;
            continue;
        }
        const StateRecord& state = states_[state_it->second];
        StateDependencyEvidence evidence;
        evidence.owner = state.label.owner;
        evidence.state_id = state.id;
        evidence.digest = state.digest;
        operation->state_dependency_evidence.push_back(evidence);
    }
    operation->declared_state_dependency_count =
        static_cast<uint32_t>(state_ids.size());
    if (operation->state_dependency_evidence.size() != state_ids.size())
        operation->state_dependency_evidence_complete = false;
    operation->state_dependency_root =
        compute_state_dependency_root(operation->state_dependency_evidence);
    operation->relation_statement = compute_relation_statement(
        operation->label, operation->relation, operation->kernel, operation->expected,
        operation->predecessor_root, operation->declared_predecessor_count,
        operation->state_dependency_root,
        operation->declared_state_dependency_count,
        operation->public_aux_root, operation->declared_public_aux_count);
    operation->private_relation_finalized = false;
    if (CheckpointRecord* checkpoint = find_checkpoint(operation->checkpoint))
        checkpoint->sealed = false;
    if (pending_valid_ && pending_.id == id) pending_ = *operation;

    if (audit_backend_override_ || source_observer_) {
        if (audit_backend_override_)
            audit_backend_override_->OnBindOperationStateDependencies(
                make_audit_operation_view(*operation), state_ids);
        if (source_observer_)
            source_observer_->OnBindOperationStateDependencies(
                make_audit_operation_view(*operation), state_ids);
        maybe_finalize_private_relation(id);
    }
}

void Runtime::bind_relation_kernel(
    RecordId id, AuditRelationKernel kernel) {
    if (!config_.enabled || id == 0) return;
    OperationRef ref;
    ref.owner = static_cast<uint32_t>(rank_);
    ref.object_id = id;
    Record* operation = find_operation(ref);
    if (!operation || operation->observed_remote) return;
    // Kernel selection is part of the relation statement and therefore must
    // be fixed before activation/transcript publication. Late rebinding would
    // make the private evaluator and public metadata disagree.
    if (operation->active) {
        if (config_.verbose) {
            std::cout << "[PVIA] refusing late relation-kernel binding for object="
                      << id << "\n";
        }
        return;
    }
    const RelationKind kernel_relation = relation_for_kernel(kernel);
    if (kernel != AuditRelationKernel::UNKNOWN &&
        kernel_relation != operation->relation) {
        if (config_.verbose) {
            std::cout << "[PVIA] refusing relation-kernel mismatch for object="
                      << id << " relation="
                      << static_cast<uint32_t>(operation->relation)
                      << " kernel=" << static_cast<uint32_t>(kernel) << "\n";
        }
        return;
    }
    operation->kernel = kernel;
    operation->relation_statement = compute_relation_statement(
        operation->label, operation->relation, operation->kernel,
        operation->expected, operation->predecessor_root,
        operation->declared_predecessor_count, operation->state_dependency_root,
        operation->declared_state_dependency_count, operation->public_aux_root,
        operation->declared_public_aux_count);
    operation->private_relation_finalized = false;
    if (CheckpointRecord* checkpoint = find_checkpoint(operation->checkpoint))
        checkpoint->sealed = false;
    if (pending_valid_ && pending_.id == id) pending_ = *operation;
}

void Runtime::bind_public_aux_digest(
    RecordId id, AuditPublicAuxKind kind, const Digest& digest) {
    if (!config_.enabled || id == 0) return;
    OperationRef ref;
    ref.owner = static_cast<uint32_t>(rank_);
    ref.object_id = id;
    Record* operation = find_operation(ref);
    if (!operation) return;

    PublicAuxEvidence evidence;
    evidence.kind = kind;
    evidence.digest = digest;
    operation->public_aux_evidence.push_back(evidence);
    operation->declared_public_aux_count =
        static_cast<uint32_t>(operation->public_aux_evidence.size());
    operation->public_aux_root =
        compute_public_aux_root(operation->public_aux_evidence);
    operation->public_aux_evidence_complete = true;
    operation->relation_statement = compute_relation_statement(
        operation->label, operation->relation, operation->kernel, operation->expected,
        operation->predecessor_root, operation->declared_predecessor_count,
        operation->state_dependency_root,
        operation->declared_state_dependency_count,
        operation->public_aux_root, operation->declared_public_aux_count);
    // Public relation material changed; re-finalize only after the backend
    // receives the concrete auxiliary values.
    operation->private_relation_finalized = false;
    if (CheckpointRecord* checkpoint = find_checkpoint(operation->checkpoint))
        checkpoint->sealed = false;

    if (pending_valid_ && pending_.id == id)
        pending_ = *operation;
}

void Runtime::bind_public_field_aux(
    RecordId id, AuditPublicAuxKind kind, const std::vector<F>& values) {
    if (!config_.enabled) return;
    bind_public_aux_digest(id, kind, hash_field_vector(values));
    if (!audit_backend_override_ && !source_observer_) return;
    OperationRef ref;
    ref.owner = static_cast<uint32_t>(rank_);
    ref.object_id = id;
    const Record* operation = find_operation(ref);
    if (!operation) return;
    if (audit_backend_override_)
        audit_backend_override_->OnBindPublicFieldAux(
            make_audit_operation_view(*operation), kind, values);
    if (source_observer_)
        source_observer_->OnBindPublicFieldAux(
            make_audit_operation_view(*operation), kind, values);
    maybe_finalize_private_relation(id);
}

void Runtime::bind_public_word_aux(
    RecordId id, AuditPublicAuxKind kind, const std::vector<u64>& values) {
    if (!config_.enabled) return;
    bind_public_aux_digest(id, kind, hash_words(values));
    if (!audit_backend_override_ && !source_observer_) return;
    OperationRef ref;
    ref.owner = static_cast<uint32_t>(rank_);
    ref.object_id = id;
    const Record* operation = find_operation(ref);
    if (!operation) return;
    if (audit_backend_override_)
        audit_backend_override_->OnBindPublicWordAux(
            make_audit_operation_view(*operation), kind, values);
    if (source_observer_)
        source_observer_->OnBindPublicWordAux(
            make_audit_operation_view(*operation), kind, values);
    maybe_finalize_private_relation(id);
}

void Runtime::set_next_commit_predecessor(const OperationRef& ref) {
    if (!config_.enabled || ref.object_id == 0) return;
    next_commit_predecessor_ = ref;
    next_commit_predecessor_valid_ = true;
}

OperationRef Runtime::consume_next_commit_predecessor() {
    if (!config_.enabled || !next_commit_predecessor_valid_)
        return OperationRef{};
    OperationRef ref = next_commit_predecessor_;
    next_commit_predecessor_ = OperationRef{};
    next_commit_predecessor_valid_ = false;
    return ref;
}

void Runtime::set_next_commit_state_dependency(StateId state_id) {
    if (!config_.enabled || state_id == 0) return;
    next_commit_state_dependency_ = state_id;
    next_commit_state_dependency_valid_ = true;
}

StateId Runtime::consume_next_commit_state_dependency() {
    if (!config_.enabled || !next_commit_state_dependency_valid_)
        return 0;
    const StateId state_id = next_commit_state_dependency_;
    next_commit_state_dependency_ = 0;
    next_commit_state_dependency_valid_ = false;
    return state_id;
}

void Runtime::activate_quadratic(RecordId id,
                                 const quadratic_poly& actual) {
    if (!config_.enabled) return;
    activate_record(id, hash_quadratic(actual));
    const std::vector<F> coefficients = {actual.a, actual.b, actual.c};
    bind_private_field_operation(
        id, AuditPrivatePayloadKind::QUADRATIC,
        AuditPayloadStage::ACTIVATE_OUTPUT, coefficients);
}

void Runtime::activate_cubic(RecordId id,
                             const cubic_poly& actual) {
    if (!config_.enabled) return;
    activate_record(id, hash_cubic(actual));
    const std::vector<F> coefficients = {actual.a, actual.b, actual.c, actual.d};
    bind_private_field_operation(
        id, AuditPrivatePayloadKind::CUBIC,
        AuditPayloadStage::ACTIVATE_OUTPUT, coefficients);
}

std::array<u64, META_WORDS>
Runtime::make_pending_meta(
    const std::vector<u64>& payload, bool seal) const {
    return make_pending_meta_digest(hash_words(payload), seal);
}

std::array<u64, META_WORDS>
Runtime::make_pending_meta_digest(
    const Digest& payload_digest, bool seal) const {
    std::array<u64, META_WORDS> meta{};
    if (payload_digest == Digest{}) return meta;

    meta[0] = META_MAGIC;
    meta[1] = config_.session_id;

    if (pending_valid_) {
        meta[2] = static_cast<u64>(pending_.label.phase);
        meta[3] = pending_.label.round;
        meta[4] = pending_.label.owner;
        meta[5] = static_cast<u64>(pending_.label.obligation);
        meta[6] = pending_.label.object_id;
        meta[7] = pending_.active ? 1ULL : 0ULL;
        if (pending_.expected != pending_.actual) meta[7] |= 2ULL;
        digest_to_words(pending_.actual, &meta[8]);
        digest_to_words(pending_.expected, &meta[12]);
        digest_to_words(pending_.predecessor_root,
                        &meta[META_PREDECESSOR_ROOT_OFFSET]);
        meta[META_CHECKPOINT_INDEX] = pending_.checkpoint;
        meta[META_PREDECESSOR_COUNT_INDEX] =
            static_cast<u64>(pending_.predecessors.size());
        meta[META_SCHEMA_INDEX] = META_SCHEMA_VERSION;
        meta[META_RELATION_KERNEL_INDEX] = static_cast<u64>(pending_.kernel);
        meta[META_PUBLIC_AUX_COUNT_INDEX] = pending_.declared_public_aux_count;
        digest_to_words(pending_.public_aux_root, &meta[META_PUBLIC_AUX_ROOT_OFFSET]);
        if (!pending_.public_aux_evidence.empty()) {
            meta[META_PUBLIC_AUX_EVIDENCE_FLAG_INDEX] = 1;
            meta[META_PUBLIC_AUX_KIND_INDEX] =
                static_cast<u64>(pending_.public_aux_evidence.front().kind);
            digest_to_words(pending_.public_aux_evidence.front().digest,
                            &meta[META_PUBLIC_AUX_DIGEST_OFFSET]);
        }
        meta[META_STATE_DEP_COUNT_INDEX] = pending_.declared_state_dependency_count;
        digest_to_words(pending_.state_dependency_root, &meta[META_STATE_DEP_ROOT_OFFSET]);
        if (!pending_.state_dependency_evidence.empty()) {
            const auto& evidence = pending_.state_dependency_evidence.front();
            meta[META_STATE_DEP_EVIDENCE_FLAG_INDEX] = 1;
            meta[META_STATE_DEP_OWNER_INDEX] = evidence.owner;
            meta[META_STATE_DEP_ID_INDEX] = evidence.state_id;
            digest_to_words(evidence.digest, &meta[META_STATE_DEP_DIGEST_OFFSET]);
        }
        if (!pending_.predecessors.empty()) {
            const Record* predecessor = find_operation(pending_.predecessors.front());
            if (predecessor) {
                meta[META_PREDECESSOR_EVIDENCE_FLAG_INDEX] = 1;
                meta[META_PREDECESSOR_OWNER_INDEX] = predecessor->label.owner;
                meta[META_PREDECESSOR_OBJECT_INDEX] = predecessor->label.object_id;
                digest_to_words(predecessor->actual,
                                &meta[META_PREDECESSOR_ACTUAL_OFFSET]);
                digest_to_words(predecessor->predecessor_root,
                                &meta[META_PREDECESSOR_PREV_ROOT_OFFSET]);
                meta[META_PREDECESSOR_OBLIGATION_INDEX] =
                    static_cast<u64>(predecessor->label.obligation);
            }
        }
    } else {
        meta[2] = static_cast<u64>(Phase::UNKNOWN);
        meta[3] = 0;
        meta[4] = static_cast<u64>(rank_);
        meta[5] = static_cast<u64>(Obligation::UNKNOWN);
        meta[6] = 0;
        meta[7] = 1ULL;
        digest_to_words(payload_digest, &meta[8]);
        digest_to_words(payload_digest, &meta[12]);
        const Digest empty_predecessor_root = hash_words(std::vector<u64>{});
        digest_to_words(empty_predecessor_root,
                        &meta[META_PREDECESSOR_ROOT_OFFSET]);
        meta[META_CHECKPOINT_INDEX] = 0;
        meta[META_PREDECESSOR_COUNT_INDEX] = 0;
        meta[META_SCHEMA_INDEX] = META_SCHEMA_VERSION;
        meta[META_RELATION_KERNEL_INDEX] = static_cast<u64>(AuditRelationKernel::UNKNOWN);
        meta[META_PUBLIC_AUX_COUNT_INDEX] = 0;
        const Digest empty_aux_root = compute_public_aux_root({});
        digest_to_words(empty_aux_root, &meta[META_PUBLIC_AUX_ROOT_OFFSET]);
        meta[META_STATE_DEP_COUNT_INDEX] = 0;
        const Digest empty_state_root = compute_state_dependency_root({});
        digest_to_words(empty_state_root, &meta[META_STATE_DEP_ROOT_OFFSET]);
    }
    if (config_.enabled && seal)
        seal_transfer_meta_digest(meta, payload_digest);
    return meta;
}

std::array<u64, META_WORDS>
Runtime::make_direct_meta(Phase phase, uint32_t round,
                          Obligation obligation, uint64_t object_id,
                          const std::vector<u64>& payload,
                          bool seal) const {
    return make_direct_meta_digest(
        phase, round, obligation, object_id, hash_words(payload), seal);
}

std::array<u64, META_WORDS>
Runtime::make_direct_meta_digest(
    Phase phase, uint32_t round, Obligation obligation, uint64_t object_id,
    const Digest& payload_digest, bool seal) const {
    std::array<u64, META_WORDS> meta{};
    if (payload_digest == Digest{}) return meta;
    meta[0] = META_MAGIC;
    meta[1] = config_.session_id;
    meta[2] = static_cast<u64>(phase);
    meta[3] = round;
    meta[4] = static_cast<u64>(rank_);
    meta[5] = static_cast<u64>(obligation);
    meta[6] = object_id;
    meta[7] = 1ULL;
    digest_to_words(payload_digest, &meta[8]);
    digest_to_words(payload_digest, &meta[12]);

    std::vector<OperationRef> predecessors;
    if (phase == Phase::ENCODING && obligation == Obligation::SEND) {
        const OperationRef predecessor =
            latest_operation_ref(phase, static_cast<uint32_t>(rank_));
        if (predecessor.object_id != 0) predecessors.push_back(predecessor);
    }
    const Digest predecessor_root = compute_predecessor_root(predecessors);
    digest_to_words(predecessor_root, &meta[META_PREDECESSOR_ROOT_OFFSET]);
    meta[META_CHECKPOINT_INDEX] = checkpoint_id(phase, round);
    meta[META_PREDECESSOR_COUNT_INDEX] =
        static_cast<u64>(predecessors.size());
    meta[META_SCHEMA_INDEX] = META_SCHEMA_VERSION;
    meta[META_RELATION_KERNEL_INDEX] = static_cast<u64>(AuditRelationKernel::UNKNOWN);
    meta[META_PUBLIC_AUX_COUNT_INDEX] = 0;
    const Digest empty_aux_root = compute_public_aux_root({});
    digest_to_words(empty_aux_root, &meta[META_PUBLIC_AUX_ROOT_OFFSET]);
    meta[META_STATE_DEP_COUNT_INDEX] = 0;
    const Digest empty_state_root = compute_state_dependency_root({});
    digest_to_words(empty_state_root, &meta[META_STATE_DEP_ROOT_OFFSET]);
    if (!predecessors.empty()) {
        const Record* predecessor = find_operation(predecessors.front());
        if (predecessor) {
            meta[META_PREDECESSOR_EVIDENCE_FLAG_INDEX] = 1;
            meta[META_PREDECESSOR_OWNER_INDEX] = predecessor->label.owner;
            meta[META_PREDECESSOR_OBJECT_INDEX] = predecessor->label.object_id;
            digest_to_words(predecessor->actual,
                            &meta[META_PREDECESSOR_ACTUAL_OFFSET]);
            digest_to_words(predecessor->predecessor_root,
                            &meta[META_PREDECESSOR_PREV_ROOT_OFFSET]);
            meta[META_PREDECESSOR_OBLIGATION_INDEX] =
                static_cast<u64>(predecessor->label.obligation);
        }
    }
    if (config_.enabled && seal) seal_transfer_meta_digest(meta, payload_digest);
    return meta;
}

bool Runtime::seal_transfer_meta(
    std::array<u64, META_WORDS>& meta,
    const std::vector<u64>& wire_payload) const {
    if (!config_.enabled) return false;
    ExperimentDurationScope metrics_scope(
        ExperimentDurationKind::TRANSFER_METADATA_SEAL);
    return Ed25519TransferAuthenticator::instance().Seal(
        &meta, wire_payload);
}

bool Runtime::seal_transfer_meta_digest(
    std::array<u64, META_WORDS>& meta,
    const Digest& wire_digest) const {
    if (!config_.enabled || wire_digest == Digest{}) return false;
    ExperimentDurationScope metrics_scope(
        ExperimentDurationKind::TRANSFER_METADATA_SEAL);
    return Ed25519TransferAuthenticator::instance().SealDigest(
        &meta, wire_digest);
}

void Runtime::register_observed_operation(
    const std::array<u64, META_WORDS>& meta, bool observed_remote) {
    if (!config_.enabled || meta[0] != META_MAGIC) return;
    const Label label = label_from_meta(meta);
    const OperationRef ref = operation_ref(label);
    const u64 schema = meta[META_SCHEMA_INDEX];
    const bool v2 = schema >= 2;
    const bool v3 = schema >= 3;
    const bool v4 = schema >= 4;
    const bool v5 = schema >= 5;
    const Digest declared_predecessor_root = v2
        ? words_to_digest(&meta[META_PREDECESSOR_ROOT_OFFSET])
        : hash_words(std::vector<u64>{});
    const CheckpointId source_checkpoint =
        v2 ? meta[META_CHECKPOINT_INDEX] : 0;
    const uint32_t predecessor_count = v2
        ? static_cast<uint32_t>(meta[META_PREDECESSOR_COUNT_INDEX]) : 0;
    const bool has_predecessor_evidence = v2 &&
        meta[META_PREDECESSOR_EVIDENCE_FLAG_INDEX] != 0;
    const uint32_t public_aux_count = v3
        ? static_cast<uint32_t>(meta[META_PUBLIC_AUX_COUNT_INDEX]) : 0;
    const Digest declared_public_aux_root = v3
        ? words_to_digest(&meta[META_PUBLIC_AUX_ROOT_OFFSET])
        : compute_public_aux_root({});
    const bool has_public_aux_evidence = v3 &&
        meta[META_PUBLIC_AUX_EVIDENCE_FLAG_INDEX] != 0;
    const uint32_t state_dependency_count = v4
        ? static_cast<uint32_t>(meta[META_STATE_DEP_COUNT_INDEX]) : 0;
    const Digest declared_state_dependency_root = v4
        ? words_to_digest(&meta[META_STATE_DEP_ROOT_OFFSET])
        : compute_state_dependency_root({});
    const bool has_state_dependency_evidence = v4 &&
        meta[META_STATE_DEP_EVIDENCE_FLAG_INDEX] != 0;
    const AuditRelationKernel declared_kernel = v5
        ? static_cast<AuditRelationKernel>(static_cast<uint32_t>(
              meta[META_RELATION_KERNEL_INDEX]))
        : AuditRelationKernel::UNKNOWN;

    auto apply_declared_dependency = [&](Record& record) {
        record.predecessor_root = declared_predecessor_root;
        record.kernel = declared_kernel;
        record.source_checkpoint_hint = source_checkpoint;
        record.declared_predecessor_count = predecessor_count;
        record.has_declared_predecessor_evidence = has_predecessor_evidence;
        record.predecessor_evidence_complete =
            predecessor_count == 0 ||
            (predecessor_count == 1 && has_predecessor_evidence);
        record.public_aux_root = declared_public_aux_root;
        record.declared_public_aux_count = public_aux_count;
        record.public_aux_evidence.clear();
        record.public_aux_evidence_complete =
            public_aux_count == 0 ||
            (public_aux_count == 1 && has_public_aux_evidence);
        record.state_dependency_root = declared_state_dependency_root;
        record.declared_state_dependency_count = state_dependency_count;
        record.state_dependency_evidence.clear();
        record.state_dependency_evidence_complete =
            state_dependency_count == 0 ||
            (state_dependency_count == 1 && has_state_dependency_evidence);
        if (has_state_dependency_evidence) {
            StateDependencyEvidence state_evidence;
            state_evidence.owner = static_cast<uint32_t>(
                meta[META_STATE_DEP_OWNER_INDEX]);
            state_evidence.state_id = meta[META_STATE_DEP_ID_INDEX];
            state_evidence.digest = words_to_digest(&meta[META_STATE_DEP_DIGEST_OFFSET]);
            record.state_dependency_evidence.push_back(state_evidence);
        }
        if (has_public_aux_evidence) {
            PublicAuxEvidence aux;
            aux.kind = static_cast<AuditPublicAuxKind>(
                static_cast<uint32_t>(meta[META_PUBLIC_AUX_KIND_INDEX]));
            aux.digest = words_to_digest(&meta[META_PUBLIC_AUX_DIGEST_OFFSET]);
            record.public_aux_evidence.push_back(aux);
        }
        if (has_predecessor_evidence) {
            record.declared_predecessor_ref.owner =
                static_cast<uint32_t>(meta[META_PREDECESSOR_OWNER_INDEX]);
            record.declared_predecessor_ref.object_id =
                meta[META_PREDECESSOR_OBJECT_INDEX];
            record.declared_predecessor_actual =
                words_to_digest(&meta[META_PREDECESSOR_ACTUAL_OFFSET]);
            record.declared_predecessor_predecessor_root =
                words_to_digest(&meta[META_PREDECESSOR_PREV_ROOT_OFFSET]);
            record.declared_predecessor_obligation = static_cast<Obligation>(
                static_cast<uint32_t>(meta[META_PREDECESSOR_OBLIGATION_INDEX]));
        }
    };

    Record* existing = find_operation(ref);
    if (existing) {
        existing->expected = words_to_digest(&meta[12]);
        existing->actual = words_to_digest(&meta[8]);
        existing->active = (meta[7] & 1ULL) != 0;
        existing->observed_remote = existing->observed_remote || observed_remote;
        if (existing->active) {
            const auto existing_it = operation_index_.find(ref);
            if (existing_it != operation_index_.end()) {
                const size_t existing_index = existing_it->second;
                auto& phase_index = latest_active_by_phase_[
                    static_cast<uint32_t>(existing->label.phase)];
                auto& owner_index = latest_active_by_phase_owner_[
                    phase_owner_index_key(
                        existing->label.phase, existing->label.owner)];
                if (phase_index <= existing_index)
                    phase_index = existing_index;
                if (owner_index <= existing_index)
                    owner_index = existing_index;
            }
        }
        if (v2) apply_declared_dependency(*existing);
        existing->relation = relation_for_obligation(existing->label.obligation);
        existing->relation_statement = compute_relation_statement(
            existing->label, existing->relation, existing->kernel, existing->expected,
            existing->predecessor_root, existing->declared_predecessor_count,
            existing->state_dependency_root,
            existing->declared_state_dependency_count,
            existing->public_aux_root, existing->declared_public_aux_count);
        if (audit_backend_override_ && existing->active)
            audit_backend_override_->OnActivateOperation(
                make_audit_operation_view(*existing));
        return;
    }

    Record record;
    record.id = label.object_id;
    record.label = label;
    record.expected = words_to_digest(&meta[12]);
    record.actual = words_to_digest(&meta[8]);
    if (v2) apply_declared_dependency(record);
    else {
        record.predecessor_root = hash_words(std::vector<u64>{});
        record.public_aux_root = compute_public_aux_root({});
        record.declared_public_aux_count = 0;
        record.public_aux_evidence_complete = true;
        record.state_dependency_root = compute_state_dependency_root({});
        record.declared_state_dependency_count = 0;
        record.state_dependency_evidence_complete = true;
    }
    record.relation = relation_for_obligation(record.label.obligation);
    record.relation_statement = compute_relation_statement(
        record.label, record.relation, record.kernel, record.expected,
        record.predecessor_root, record.declared_predecessor_count,
        record.state_dependency_root, record.declared_state_dependency_count,
        record.public_aux_root, record.declared_public_aux_count);

    CheckpointRecord& checkpoint = ensure_checkpoint(label.phase, label.round);
    record.checkpoint = checkpoint.id;
    if (record.source_checkpoint_hint == 0)
        record.source_checkpoint_hint = checkpoint.id;
    record.active = (meta[7] & 1ULL) != 0;
    record.observed_remote = observed_remote;
    operations_.push_back(record);
    operation_index_[operation_ref(operations_.back().label)] =
        operations_.size() - 1;
    if (record.active) {
        const size_t new_index = operations_.size() - 1;
        auto& phase_index = latest_active_by_phase_[
            static_cast<uint32_t>(record.label.phase)];
        auto& owner_index = latest_active_by_phase_owner_[
            phase_owner_index_key(
                record.label.phase, record.label.owner)];
        if (phase_index <= new_index) phase_index = new_index;
        if (owner_index <= new_index) owner_index = new_index;
    }
    checkpoint.operations.push_back(ref);
    checkpoint.sealed = false;
    if (audit_backend_override_) {
        const AuditOperationView view =
            make_audit_operation_view(operations_.back());
        audit_backend_override_->OnRegisterOperation(view);
        if (record.active)
            audit_backend_override_->OnActivateOperation(view);
    }
}

void Runtime::observe_public_transfer(
    const std::array<u64, META_WORDS>& meta,
    const Digest& payload_digest,
    bool remote_observation,
    int sender_override) {
    Label source_label = label_from_meta(meta);
    const OperationRef ref = operation_ref(source_label);
    const Record* operation = find_operation(ref);
    if (!operation) return;
    if (public_transfer_ref_set_.insert(ref).second)
        public_transfer_refs_.push_back(ref);
    if (!audit_backend_override_) return;

    PublicTransferObservation observation;
    observation.valid = true;
    observation.ref = ref;
    observation.source_label = source_label;
    observation.transfer_label = source_label;
    observation.transfer_label.obligation = Obligation::SEND;
    if (sender_override >= 0)
        observation.transfer_label.owner = static_cast<uint32_t>(sender_override);
    observation.checkpoint = meta[META_CHECKPOINT_INDEX];
    observation.observer_rank = static_cast<uint32_t>(rank_);
    observation.predecessor_root =
        words_to_digest(&meta[META_PREDECESSOR_ROOT_OFFSET]);
    observation.predecessor_count =
        static_cast<uint32_t>(meta[META_PREDECESSOR_COUNT_INDEX]);
    observation.state_dependency_root =
        words_to_digest(&meta[META_STATE_DEP_ROOT_OFFSET]);
    observation.state_dependency_count =
        static_cast<uint32_t>(meta[META_STATE_DEP_COUNT_INDEX]);
    observation.public_aux_root =
        words_to_digest(&meta[META_PUBLIC_AUX_ROOT_OFFSET]);
    observation.public_aux_count =
        static_cast<uint32_t>(meta[META_PUBLIC_AUX_COUNT_INDEX]);
    observation.registered_digest = words_to_digest(&meta[8]);
    observation.payload_digest = payload_digest;
    observation.operation_statement_binding = compute_relation_statement(
        observation.transfer_label, RelationKind::MESSAGE_BINDING,
        AuditRelationKernel::UNKNOWN, observation.registered_digest,
        observation.predecessor_root, observation.predecessor_count,
        observation.state_dependency_root, observation.state_dependency_count,
        observation.public_aux_root, observation.public_aux_count);
    observation.metadata_binding = hash_bytes(
        reinterpret_cast<const uint8_t*>(meta.data()),
        META_WORDS * sizeof(u64));
    observation.authenticated_metadata = meta;
    observation.remote_observation = remote_observation;
    audit_backend_override_->OnObservePublicTransfer(observation);
}

void Runtime::observe_outgoing_transfer(
    const std::array<u64, META_WORDS>& meta,
    const std::vector<u64>& payload) {
    observe_outgoing_transfer_digest(meta, hash_words(payload));
}

void Runtime::observe_outgoing_transfer_digest(
    const std::array<u64, META_WORDS>& meta,
    const Digest& payload_digest) {
    if (!config_.enabled || payload_digest == Digest{}) return;
    auto& transfer_auth = Ed25519TransferAuthenticator::instance();
    if (!transfer_auth.ready() ||
        meta[0] != META_MAGIC ||
        meta[META_SCHEMA_INDEX] < 6 ||
        meta[META_AUTH_SIGNER_INDEX] != static_cast<u64>(rank_) ||
        meta[4] != static_cast<u64>(rank_) ||
        words_to_digest(&meta[META_AUTH_KEY_ID_OFFSET]) !=
            transfer_auth.PublicKeyId(static_cast<uint32_t>(rank_)))
        return;
    if (words_to_digest(&meta[META_AUTH_WIRE_DIGEST_OFFSET]) != payload_digest)
        return;
    register_observed_operation(meta, false);
    observe_public_transfer(meta, payload_digest, false, -1);
    update_transcript(meta);
    const Digest registered_digest = words_to_digest(&meta[8]);
    if (registered_digest != payload_digest) {
        Label label = label_from_meta(meta);
        label.obligation = Obligation::SEND;
        record_violation(label, registered_digest, payload_digest);
    }
}

void Runtime::observe_direct_local(
    const std::array<u64, META_WORDS>& meta,
    const std::vector<u64>& payload) {
    observe_outgoing_transfer(meta, payload);
}

void Runtime::update_transcript(
    const std::array<u64, META_WORDS>& meta) {
    // Byte-for-byte equivalent to hashing
    // transcript_digest || canonical_metadata, but without allocating and
    // copying a temporary buffer for every observed transfer.
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(
        &hasher, transcript_digest_.bytes.data(),
        transcript_digest_.bytes.size());
    blake3_hasher_update(
        &hasher, reinterpret_cast<const uint8_t*>(meta.data()),
        META_WORDS * sizeof(u64));
    blake3_hasher_finalize(
        &hasher, transcript_digest_.bytes.data(),
        transcript_digest_.bytes.size());
    ++transcript_records_;
}

void Runtime::record_violation(const Label& label,
                               const Digest& expected,
                               const Digest& actual) {
    Violation v;
    v.valid = true;
    v.label = label;
    v.expected = expected;
    v.actual = actual;
    v.responsible_rank = label.owner;
    v.relation = relation_for_obligation(label.obligation);
    if (const Record* operation = find_operation(operation_ref(label))) {
        v.checkpoint = operation->checkpoint;
        v.kernel = (operation->kernel != AuditRelationKernel::UNKNOWN &&
                    relation_for_kernel(operation->kernel) == v.relation)
            ? operation->kernel : AuditRelationKernel::UNKNOWN;
        if (v.relation == RelationKind::MESSAGE_BINDING &&
            label.obligation == Obligation::SEND) {
            v.operation_statement_binding = compute_message_binding_statement(
                label, *operation, expected);
        } else {
            v.operation_statement_binding = operation->relation_statement;
        }
    } else {
        v.checkpoint = ensure_checkpoint(label.phase, label.round).id;
        v.kernel = AuditRelationKernel::UNKNOWN;
        v.operation_statement_binding = Digest{};
    }
    v.residual_commitment = compute_residual_commitment(
        label, v.relation, v.kernel, expected, actual);
    v.sequence = next_violation_sequence_++;
    v.resolved = false;
    violations_.push_back(v);

    if (config_.verbose && rank_ == 0) {
        std::cout << "[PVIA][candidate] obligation mismatch: P"
                  << label.owner << " phase="
                  << static_cast<uint32_t>(label.phase)
                  << " round=" << label.round
                  << " object=" << label.object_id << "\n";
    }
}

void Runtime::record_pending_relation_violation() {
    if (!config_.enabled || !pending_valid_ || !pending_.active) return;
    if (pending_.expected == pending_.actual) return;
    record_violation(pending_.label, pending_.expected, pending_.actual);
}

void Runtime::observe_local_payload(const std::vector<u64>& payload) {
    if (!config_.enabled) return;
    observe_local_payload_digest(hash_words(payload));
}

void Runtime::observe_local_payload_digest(const Digest& payload_digest) {
    if (!config_.enabled || payload_digest == Digest{}) return;
    // Local transcript observation does not cross a trust boundary; avoid
    // both a signature and materializing a wire-format copy when the caller
    // already has the canonical digest.
    const auto meta = make_pending_meta_digest(payload_digest, false);
    observe_local_meta_digest(meta, payload_digest);
}

void Runtime::observe_local_meta(
    const std::array<u64, META_WORDS>& meta,
    const std::vector<u64>& payload) {
    observe_local_meta_digest(meta, hash_words(payload));
}

void Runtime::observe_local_meta_digest(
    const std::array<u64, META_WORDS>& meta,
    const Digest& payload_digest) {
    if (!config_.enabled || payload_digest == Digest{} ||
        meta[0] != META_MAGIC || meta[1] != config_.session_id)
        return;
    const Digest actual = words_to_digest(&meta[8]);
    const Digest expected = words_to_digest(&meta[12]);

    update_transcript(meta);

    Label label = label_from_meta(meta);
    if (expected != actual) {
        // The activated value differs from the value derived before the deviation.
        record_violation(label, expected, actual);
    } else if (payload_digest != actual) {
        // The registered value was correct but the actually transmitted bytes changed.
        label.obligation = Obligation::SEND;
        record_violation(label, actual, payload_digest);
    }
}

bool Runtime::strict_remote_transfer_valid(
    int sender, const std::array<u64, META_WORDS>& meta,
    const std::vector<u64>& payload) const {
    return strict_remote_transfer_valid_digest(
        sender, meta, hash_words(payload));
}

bool Runtime::strict_remote_transfer_valid_digest(
    int sender, const std::array<u64, META_WORDS>& meta,
    const Digest& payload_digest) const {
    if (!config_.enabled) return true;
    if (meta[0] != META_MAGIC || payload_digest == Digest{}) return false;
    auto& transfer_auth = Ed25519TransferAuthenticator::instance();
    if (!transfer_auth.ready() || !transfer_auth.Verify(meta, sender)) return false;
    const Digest signed_wire_digest =
        words_to_digest(&meta[META_AUTH_WIRE_DIGEST_OFFSET]);
    if (signed_wire_digest != payload_digest) return false;
    const Label label = label_from_meta(meta);
    if (label.sid != config_.session_id ||
        label.owner != static_cast<uint32_t>(sender) ||
        label.obligation != Obligation::SEND)
        return false;
    const Digest actual = words_to_digest(&meta[8]);
    const Digest expected = words_to_digest(&meta[12]);
    const bool valid =
        expected == actual && payload_digest == actual;
    if (valid) {
        verified_transfer_cache_sender_ = sender;
        verified_transfer_cache_meta_digest_ = hash_bytes(
            reinterpret_cast<const uint8_t*>(meta.data()),
            META_WORDS * sizeof(u64));
        verified_transfer_cache_payload_digest_ = payload_digest;
        verified_transfer_cache_valid_ =
            verified_transfer_cache_meta_digest_ != Digest{};
    } else {
        verified_transfer_cache_valid_ = false;
    }
    return valid;
}

void Runtime::observe_remote_meta(
    int sender,
    const std::array<u64, META_WORDS>& meta,
    const std::vector<u64>& payload) {
    observe_remote_meta_digest(sender, meta, hash_words(payload));
}

void Runtime::observe_remote_meta_digest(
    int sender,
    const std::array<u64, META_WORDS>& meta,
    const Digest& payload_digest) {
    if (!config_.enabled) return;
    ExperimentDurationScope observe_metrics_scope(
        ExperimentDurationKind::TRANSFER_METADATA_OBSERVE);
    experiment_add_transfer_metadata_receive(
        static_cast<uint64_t>(META_WORDS) * sizeof(u64));
    if (meta[0] != META_MAGIC) {
        if (rank_ == 0)
            std::cout << "[PVIA] invalid metadata magic from rank "
                      << sender << "\n";
        return;
    }

    auto& transfer_auth = Ed25519TransferAuthenticator::instance();
    if (payload_digest == Digest{}) return;
    const Digest meta_digest = hash_bytes(
        reinterpret_cast<const uint8_t*>(meta.data()),
        META_WORDS * sizeof(u64));

    bool authenticated_metadata = false;
    if (verified_transfer_cache_valid_ &&
        verified_transfer_cache_sender_ == sender &&
        verified_transfer_cache_meta_digest_ == meta_digest &&
        verified_transfer_cache_payload_digest_ == payload_digest) {
        authenticated_metadata = true;
        // Consume the cache entry.  A later replay of identical bytes must
        // still pass the ordinary authentication/replay path.
        verified_transfer_cache_valid_ = false;
    } else {
        verified_transfer_cache_valid_ = false;
        ExperimentDurationScope verify_metrics_scope(
            ExperimentDurationKind::TRANSFER_METADATA_VERIFY);
        authenticated_metadata =
            transfer_auth.ready() && transfer_auth.Verify(meta, sender);
    }
    if (!authenticated_metadata) {
        if (config_.verbose)
            std::cout << "[PVIA] rejecting unauthenticated transfer metadata from rank "
                      << sender << "\n";
        return;
    }
    const Digest signed_wire_digest =
        words_to_digest(&meta[META_AUTH_WIRE_DIGEST_OFFSET]);
    if (signed_wire_digest != payload_digest) {
        if (config_.verbose)
            std::cout << "[PVIA] rejecting transfer whose payload is not covered by sender signature from rank "
                      << sender << "\n";
        return;
    }
    register_observed_operation(meta, true);
    Label label = label_from_meta(meta);
    const Digest actual = words_to_digest(&meta[8]);
    const Digest expected = words_to_digest(&meta[12]);

    observe_public_transfer(
        meta, payload_digest, true, sender);
    update_transcript(meta);

    if (label.sid != config_.session_id ||
        label.owner != static_cast<uint32_t>(sender)) {
        Label send_label = label;
        send_label.owner = static_cast<uint32_t>(sender);
        send_label.obligation = Obligation::SEND;
        record_violation(send_label, actual, payload_digest);
    } else if (expected != actual) {
        record_violation(label, expected, actual);
    } else if (payload_digest != actual) {
        label.obligation = Obligation::SEND;
        record_violation(label, actual, payload_digest);
    }
}

void Runtime::record_public_vector_violation(
    Phase phase, uint32_t round, Obligation obligation,
    uint32_t owner, uint64_t object_id,
    const std::vector<F>& expected,
    const std::vector<F>& actual,
    const std::vector<u64>& public_aux_words) {
    if (!config_.enabled) return;
    Label label;
    label.sid = config_.session_id;
    label.phase = phase;
    label.round = round;
    label.owner = owner;
    label.obligation = obligation;
    label.object_id = object_id;
    const Digest expected_digest = hash_field_vector(expected);
    const Digest actual_digest = hash_field_vector(actual);
    const OperationRef ref = operation_ref(label);
    if (!find_operation(ref)) {
        std::vector<OperationRef> predecessors;
        if (phase == Phase::OPENING && obligation == Obligation::OPEN) {
            OperationRef predecessor = latest_operation_ref(Phase::FOLD, owner);
            if (predecessor.object_id == 0)
                predecessor = latest_operation_ref(Phase::ORACLE, owner);
            if (predecessor.object_id != 0) predecessors.push_back(predecessor);
        }
        Record record;
        record.id = object_id;
        record.label = label;
        record.expected = expected_digest;
        record.actual = actual_digest;
        record.predecessors = predecessors;
        record.predecessor_root = compute_predecessor_root(predecessors);
        if (!public_aux_words.empty()) {
            PublicAuxEvidence aux;
            aux.kind = AuditPublicAuxKind::OPEN_QUERY;
            aux.digest = hash_words(public_aux_words);
            record.public_aux_evidence.push_back(aux);
        }
        record.public_aux_root = compute_public_aux_root(record.public_aux_evidence);
        record.declared_public_aux_count =
            static_cast<uint32_t>(record.public_aux_evidence.size());
        record.public_aux_evidence_complete = true;
        record.state_dependency_root = compute_state_dependency_root({});
        record.declared_state_dependency_count = 0;
        record.state_dependency_evidence_complete = true;
        record.relation = relation_for_obligation(obligation);
        record.kernel = (phase == Phase::OPENING && obligation == Obligation::OPEN)
            ? AuditRelationKernel::OPEN_QUERY : AuditRelationKernel::UNKNOWN;
        record.relation_statement = compute_relation_statement(
            record.label, record.relation, record.kernel, record.expected,
            record.predecessor_root, static_cast<uint32_t>(predecessors.size()),
            record.state_dependency_root, record.declared_state_dependency_count,
            record.public_aux_root, record.declared_public_aux_count);
        CheckpointRecord& checkpoint = ensure_checkpoint(phase, round);
        record.checkpoint = checkpoint.id;
        record.source_checkpoint_hint = checkpoint.id;
        record.declared_predecessor_count =
            static_cast<uint32_t>(predecessors.size());
        record.predecessor_evidence_complete = true;
        record.active = true;
        operations_.push_back(record);
        operation_index_[operation_ref(operations_.back().label)] =
            operations_.size() - 1;
        checkpoint.operations.push_back(ref);
        checkpoint.sealed = false;
        if (audit_backend_override_) {
            const AuditOperationView view =
                make_audit_operation_view(operations_.back());
            audit_backend_override_->OnRegisterOperation(view);
            audit_backend_override_->OnActivateOperation(view);
        }
    }
    record_violation(label, expected_digest, actual_digest);
}

CheckpointId Runtime::checkpoint_id(Phase phase, uint32_t round) const {
    const CheckpointRecord* checkpoint = find_latest_checkpoint(phase, round);
    return checkpoint ? checkpoint->id : 0;
}

ObligationSet Runtime::make_scope(Phase phase, uint32_t round,
                                  bool exact_round) const {
    ObligationSet scope;
    scope.session_id = config_.session_id;
    scope.phase = phase;
    scope.round = round;
    scope.exact_round = exact_round;
    return scope;
}

bool Runtime::scope_matches(const Violation& violation,
                            const ObligationSet& scope) const {
    if (!violation.valid || violation.resolved) return false;
    if (scope.session_id != 0 && violation.label.sid != scope.session_id)
        return false;
    if (scope.phase != Phase::UNKNOWN && violation.label.phase != scope.phase)
        return false;
    if (scope.exact_round && violation.label.round != scope.round)
        return false;
    if (scope.checkpoint != 0 && violation.checkpoint != scope.checkpoint)
        return false;
    if (!scope.operations.empty()) {
        const OperationRef ref = operation_ref(violation.label);
        if (std::find(scope.operations.begin(), scope.operations.end(), ref) ==
            scope.operations.end())
            return false;
    }
    if (!scope.obligations.empty() &&
        std::find(scope.obligations.begin(), scope.obligations.end(),
                  violation.label.obligation) == scope.obligations.end())
        return false;
    return true;
}

ObligationSet Runtime::scope_for_check(const char* check_name, Phase phase,
                                              uint32_t round,
                                              bool exact_round) const {
    ObligationSet scope = make_scope(phase, round, exact_round);
    const std::string name = check_name ? std::string(check_name) : std::string();

    auto add = [&](Obligation obligation) {
        scope.obligations.push_back(obligation);
    };

    if (name.find("query_fold") != std::string::npos) {
        add(Obligation::OPEN);
    } else if (name.find("final_codeword") != std::string::npos) {
        add(Obligation::SEND);
        add(Obligation::FOLD);
        add(Obligation::OPEN);
    } else if (name.find("sparse_product") != std::string::npos) {
        add(Obligation::DERIVE);
        add(Obligation::SEND);
        add(Obligation::ASSEMBLE);
        add(Obligation::AGGREGATE);
        add(Obligation::PUBLISH);
    } else {
        // Sumcheck/PCS polynomial identities are affected by local derivation,
        // transfer binding, or aggregator behavior.
        add(Obligation::DERIVE);
        add(Obligation::SEND);
        add(Obligation::AGGREGATE);
        add(Obligation::PUBLISH);
    }
    if (exact_round) {
        const CheckpointId id = checkpoint_id(phase, round);
        if (const CheckpointRecord* checkpoint = find_checkpoint(id)) {
            scope.checkpoint = id;
            scope.generation = checkpoint->generation;
            scope.checkpoint_root = checkpoint->sealed
                ? checkpoint->root : compute_checkpoint_root(*checkpoint);
            const bool transfer_requested = std::any_of(
                scope.obligations.begin(), scope.obligations.end(),
                [](Obligation obligation) {
                    return classify_audit_obligation(obligation) ==
                           AuditScopeLane::PUBLIC_TRANSFER;
                });
            for (const auto& ref : checkpoint->operations) {
                const Record* operation = find_operation(ref);
                if (!operation) continue;
                const bool obligation_selected = scope.obligations.empty() ||
                    std::find(scope.obligations.begin(), scope.obligations.end(),
                              operation->label.obligation) != scope.obligations.end();
                const AuditScopeLane relation_lane =
                    classify_audit_relation(operation->relation);
                const bool private_selected = obligation_selected &&
                    (relation_lane == AuditScopeLane::PRIVATE_RESIDUAL ||
                     relation_lane == AuditScopeLane::PRIVATE_AND_TRANSFER);
                const bool explicit_transfer = obligation_selected &&
                    (relation_lane == AuditScopeLane::PUBLIC_TRANSFER ||
                     relation_lane == AuditScopeLane::PRIVATE_AND_TRANSFER);
                const bool observed_transfer = transfer_requested &&
                    public_transfer_ref_set_.find(ref) !=
                    public_transfer_ref_set_.end();
                if (private_selected)
                    scope.private_operations.push_back(ref);
                if (explicit_transfer || observed_transfer)
                    scope.transfer_operations.push_back(ref);
                if (private_selected || explicit_transfer || observed_transfer)
                    scope.operations.push_back(ref);
            }
        }
    }
    return scope;
}

BatchCheckResult Runtime::debug_batch_check(
    const ObligationSet& scope) const {
    BatchCheckResult result;
    result.available = true;
    result.cryptographically_authenticated = false;
    result.checkpoint = scope.checkpoint != 0
        ? scope.checkpoint : checkpoint_id(scope.phase, scope.round);

    std::vector<u64> challenge_words = {
        config_.session_id,
        static_cast<u64>(scope.phase),
        scope.round,
        scope.generation,
        scope.exact_round ? 1ULL : 0ULL,
        result.checkpoint,
        static_cast<u64>(scope.operations.size()),
        static_cast<u64>(scope.obligations.size())
    };
    for (const auto obligation : scope.obligations)
        challenge_words.push_back(static_cast<u64>(obligation));
    if (const CheckpointRecord* checkpoint = find_checkpoint(result.checkpoint)) {
        const Digest root = checkpoint->sealed
            ? checkpoint->root : compute_checkpoint_root(*checkpoint);
        append_digest_words(root, challenge_words);
    } else {
        append_digest_words(Digest{}, challenge_words);
    }
    append_digest_words(transcript_digest_, challenge_words);
    result.challenge = hash_words(challenge_words);

    auto operation_in_scope = [&](const Record& operation) {
        if (scope.session_id != 0 && operation.label.sid != scope.session_id)
            return false;
        if (scope.phase != Phase::UNKNOWN &&
            operation.label.phase != scope.phase)
            return false;
        if (scope.exact_round && operation.label.round != scope.round)
            return false;
        if (scope.checkpoint != 0 && operation.checkpoint != scope.checkpoint)
            return false;
        if (!scope.operations.empty()) {
            const OperationRef ref = operation_ref(operation.label);
            if (std::find(scope.operations.begin(), scope.operations.end(), ref) ==
                scope.operations.end())
                return false;
        }
        if (!scope.obligations.empty() &&
            std::find(scope.obligations.begin(), scope.obligations.end(),
                      operation.label.obligation) == scope.obligations.end())
            return false;
        return operation.active;
    };

    for (const auto& operation : operations_)
        if (operation_in_scope(operation)) ++result.checked_operations;

    std::vector<u64> residual_words;
    append_digest_words(result.challenge, residual_words);
    residual_words.push_back(result.checked_operations);
    for (const auto& violation : violations_) {
        if (!scope_matches(violation, scope)) continue;
        ++result.mismatches;
        residual_words.push_back(violation.sequence);
        residual_words.push_back(violation.label.owner);
        residual_words.push_back(violation.label.object_id);
        residual_words.push_back(static_cast<u64>(violation.relation));
        residual_words.push_back(static_cast<u64>(violation.kernel));
        append_digest_words(violation.residual_commitment, residual_words);
    }
    residual_words.push_back(result.mismatches);
    result.aggregate_residual_commitment = hash_words(residual_words);
    result.ok = result.mismatches == 0;
    return result;
}

Violation Runtime::debug_dispute(
    const ObligationSet& scope, const BatchCheckResult& batch) const {
    const BatchCheckResult recomputed = debug_batch_check(scope);
    if (batch.ok || recomputed.ok) return Violation{};
    if (batch.checkpoint != recomputed.checkpoint ||
        batch.checked_operations != recomputed.checked_operations ||
        batch.mismatches != recomputed.mismatches ||
        batch.challenge != recomputed.challenge ||
        batch.aggregate_residual_commitment !=
            recomputed.aggregate_residual_commitment)
        return Violation{};

    for (const auto& violation : violations_)
        if (scope_matches(violation, scope)) return violation;
    return Violation{};
}

RecoverableAuditShare Runtime::recover_debug_audit(
    const Violation& violation) const {
    RecoverableAuditShare audit;
    if (!violation.valid) return audit;
    audit.valid = true;
    audit.debug_only = true;
    audit.label = violation.label;
    audit.relation = violation.relation;
    audit.kernel = violation.kernel;
    audit.expected = violation.expected;
    audit.actual = violation.actual;
    audit.residual_commitment = violation.residual_commitment;
    audit.operation_statement_binding = violation.operation_statement_binding;
    audit.dispute_binding = violation.dispute_binding;
    if (const Record* operation = find_operation(operation_ref(violation.label)))
        audit.predecessor_root = operation->predecessor_root;
    if (const CheckpointRecord* checkpoint = find_checkpoint(violation.checkpoint))
        audit.checkpoint_root = checkpoint->sealed
            ? checkpoint->root : compute_checkpoint_root(*checkpoint);

    std::vector<u64> words = {
        violation.label.sid,
        static_cast<u64>(violation.label.phase),
        violation.label.round,
        violation.label.owner,
        static_cast<u64>(violation.label.obligation),
        violation.label.object_id,
        static_cast<u64>(violation.relation),
        static_cast<u64>(violation.kernel)
    };
    for (size_t i = 0; i < 4; ++i) {
        u64 w = 0;
        std::memcpy(&w, violation.expected.bytes.data() + i * 8, 8);
        words.push_back(w);
    }
    for (size_t i = 0; i < 4; ++i) {
        u64 w = 0;
        std::memcpy(&w, violation.actual.bytes.data() + i * 8, 8);
        words.push_back(w);
    }
    for (size_t i = 0; i < 4; ++i) {
        u64 w = 0;
        std::memcpy(&w, violation.residual_commitment.bytes.data() + i * 8, 8);
        words.push_back(w);
    }
    append_digest_words(audit.operation_statement_binding, words);
    append_digest_words(audit.dispute_binding, words);
    append_digest_words(audit.predecessor_root, words);
    append_digest_words(audit.checkpoint_root, words);
    audit.witness_digest = hash_words(words);
    return audit;
}

BlameCertificate Runtime::lift_debug_blame(
    const Violation& violation,
    const RecoverableAuditShare& audit) const {
    BlameCertificate cert;
    if (!violation.valid || !audit.valid) return cert;
    if (audit.label.sid != violation.label.sid ||
        audit.label.object_id != violation.label.object_id ||
        audit.expected != violation.expected ||
        audit.actual != violation.actual ||
        audit.residual_commitment != violation.residual_commitment ||
        audit.operation_statement_binding != violation.operation_statement_binding ||
        audit.dispute_binding != violation.dispute_binding)
        return cert;
    cert.valid = true;
    cert.debug_only = true;
    cert.sid = config_.session_id;
    cert.accused = violation.responsible_rank;
    cert.label = violation.label;
    cert.checkpoint = violation.checkpoint;
    cert.relation = violation.relation;
    cert.kernel = violation.kernel;
    cert.expected = violation.expected;
    cert.actual = violation.actual;
    cert.residual_commitment = violation.residual_commitment;
    cert.operation_statement_binding = violation.operation_statement_binding;
    cert.dispute_binding = audit.dispute_binding;
    cert.predecessor_root = audit.predecessor_root;
    cert.checkpoint_root = audit.checkpoint_root;
    if (const Record* operation = find_operation(operation_ref(violation.label))) {
        cert.predecessor_evidence_complete =
            operation->predecessor_evidence_complete;
        for (const auto& ref : operation->predecessors) {
            const Record* predecessor = find_operation(ref);
            if (!predecessor) {
                cert.predecessor_evidence_complete = false;
                continue;
            }
            OperationEvidence evidence;
            evidence.ref = ref;
            evidence.obligation = predecessor->label.obligation;
            evidence.relation = predecessor->relation;
            evidence.kernel = predecessor->kernel;
            evidence.expected = predecessor->expected;
            evidence.actual = predecessor->actual;
            evidence.predecessor_root = predecessor->predecessor_root;
            evidence.relation_statement = predecessor->relation_statement;
            evidence.public_aux_root = predecessor->public_aux_root;
            evidence.public_aux_count = predecessor->declared_public_aux_count;
            evidence.public_aux_evidence_complete = predecessor->public_aux_evidence_complete;
            evidence.public_aux_evidence = predecessor->public_aux_evidence;
            evidence.state_dependency_root = predecessor->state_dependency_root;
            evidence.state_dependency_count = predecessor->declared_state_dependency_count;
            evidence.state_dependency_evidence_complete =
                predecessor->state_dependency_evidence_complete;
            evidence.state_dependency_evidence = predecessor->state_dependency_evidence;
            evidence.source_checkpoint_hint = predecessor->source_checkpoint_hint;
            evidence.predecessor_count = predecessor->declared_predecessor_count;
            cert.predecessor_evidence.push_back(evidence);
        }
        if (operation->predecessors.empty() &&
            operation->declared_predecessor_count > 0 &&
            operation->has_declared_predecessor_evidence) {
            OperationEvidence evidence;
            evidence.ref = operation->declared_predecessor_ref;
            evidence.obligation = operation->declared_predecessor_obligation;
            evidence.relation = relation_for_obligation(
                operation->declared_predecessor_obligation);
            evidence.actual = operation->declared_predecessor_actual;
            evidence.predecessor_root =
                operation->declared_predecessor_predecessor_root;
            cert.predecessor_evidence.push_back(evidence);
        }
        if (cert.predecessor_evidence.size() !=
            operation->declared_predecessor_count)
            cert.predecessor_evidence_complete = false;
    } else {
        cert.predecessor_evidence_complete = false;
    }
    if (const CheckpointRecord* checkpoint = find_checkpoint(violation.checkpoint)) {
        for (const auto& ref : checkpoint->operations) {
            const Record* member = find_operation(ref);
            if (!member) continue;
            OperationEvidence evidence;
            evidence.ref = ref;
            evidence.obligation = member->label.obligation;
            evidence.relation = member->relation;
            evidence.kernel = member->kernel;
            evidence.expected = member->expected;
            evidence.actual = member->actual;
            evidence.predecessor_root = member->predecessor_root;
            evidence.relation_statement = member->relation_statement;
            evidence.public_aux_root = member->public_aux_root;
            evidence.public_aux_count = member->declared_public_aux_count;
            evidence.public_aux_evidence_complete = member->public_aux_evidence_complete;
            evidence.public_aux_evidence = member->public_aux_evidence;
            evidence.state_dependency_root = member->state_dependency_root;
            evidence.state_dependency_count = member->declared_state_dependency_count;
            evidence.state_dependency_evidence_complete =
                member->state_dependency_evidence_complete;
            evidence.state_dependency_evidence = member->state_dependency_evidence;
            evidence.source_checkpoint_hint = member->source_checkpoint_hint;
            evidence.predecessor_count = member->declared_predecessor_count;
            cert.checkpoint_evidence.push_back(evidence);
        }
    }
    cert.audit_witness_digest = audit.witness_digest;
    cert.transcript_digest = transcript_digest_;
    cert.proof_digest = PublicJudge::compute_debug_proof_digest(cert);
    return cert;
}

void Runtime::mark_resolved(const Violation& violation) {
    for (auto& current : violations_) {
        if (current.sequence == violation.sequence) {
            current.resolved = true;
            return;
        }
    }
}

void Runtime::begin_private_residual_provenance_gate(
    uint32_t expected_round) {
    if (!require_private_residual_provenance_) return;
    private_residual_expected_round_ = expected_round;
    private_residual_provenance_gate_started_ = true;
    private_residual_source_bound_ = false;
    private_residual_provenance_authorized_ = false;
    private_residual_statement_binding_ = Digest{};
    private_residual_computation_binding_ = Digest{};
    private_residual_check_transcript_binding_ = Digest{};
    private_residual_issuer_id_ = 0;
    private_residual_minimum_sequence_ = 0;
    private_residual_provenance_release_consumed_ = false;
    private_residual_provenance_consumed_round_ = 0;
}

bool Runtime::bind_private_residual_provenance_source(
    const Digest& statement_binding,
    const Digest& computation_binding) {
    if (!require_private_residual_provenance_) return true;
    if (!config_.enabled || !private_residual_provenance_gate_started_ ||
        private_residual_source_bound_ ||
        private_residual_provenance_authorized_ ||
        statement_binding == Digest{} || computation_binding == Digest{})
        return false;
    private_residual_statement_binding_ = statement_binding;
    private_residual_computation_binding_ = computation_binding;
    private_residual_source_bound_ = true;
    return true;
}

bool Runtime::authorize_private_residual_provenance(
    const Digest& statement_binding,
    const Digest& computation_binding,
    const Digest& check_transcript_binding,
    uint64_t issuer_id, uint64_t minimum_accepted_sequence) {
    if (!require_private_residual_provenance_) return true;
    if (!config_.enabled || !private_residual_provenance_gate_started_ ||
        !private_residual_source_bound_ ||
        private_residual_statement_binding_ == Digest{} ||
        private_residual_computation_binding_ == Digest{} ||
        statement_binding != private_residual_statement_binding_ ||
        computation_binding != private_residual_computation_binding_ ||
        check_transcript_binding == Digest{} ||
        issuer_id == 0 || minimum_accepted_sequence == 0)
        return false;
    private_residual_check_transcript_binding_ = check_transcript_binding;
    private_residual_issuer_id_ = issuer_id;
    private_residual_minimum_sequence_ = minimum_accepted_sequence;
    private_residual_provenance_authorized_ = true;
    return true;
}

bool Runtime::private_residual_provenance_release_gate(
    const char* release_name) const {
    if (!require_private_residual_provenance_) return true;
    const bool expected_release = release_name &&
        std::string(release_name) ==
            "folded_codeword_merkle_commitment";
    const bool allowed = config_.enabled && expected_release &&
        private_residual_provenance_gate_started_ &&
        private_residual_provenance_authorized_ &&
        private_residual_statement_binding_ != Digest{} &&
        private_residual_computation_binding_ != Digest{} &&
        private_residual_check_transcript_binding_ != Digest{} &&
        private_residual_issuer_id_ != 0 &&
        private_residual_minimum_sequence_ != 0;
    if (rank_ == 0) {
        std::cout << "[PVIA][residual-provenance-release-gate] "
                  << (allowed ? "ALLOW" : "WITHHOLD")
                  << " release="
                  << (release_name ? release_name : "unnamed")
                  << " gate_started="
                  << (private_residual_provenance_gate_started_ ? "true" : "false")
                  << " authenticated="
                  << (private_residual_provenance_authorized_ ? "true" : "false")
                  << " transcript_bound="
                  << (private_residual_check_transcript_binding_ != Digest{} ? "true" : "false")
                  << "\n";
    }
    return allowed;
}

bool Runtime::pre_release_gate(const char* release_name,
                               Phase phase, uint32_t round) {
    const auto external_anchor_allows = [&]() {
        if (!external_release_anchor_required_) return true;
        const std::string label = release_name ? release_name : "unnamed";
        std::vector<u64> context_words = {
            0x5056494152454c47ULL, config_.session_id,
            static_cast<u64>(static_cast<uint32_t>(phase)),
            static_cast<u64>(round), transcript_records_,
            static_cast<u64>(label.size())};
        for (size_t offset = 0; offset < transcript_digest_.bytes.size();
             offset += sizeof(u64)) {
            u64 word = 0;
            std::memcpy(&word, transcript_digest_.bytes.data() + offset,
                        sizeof(word));
            context_words.push_back(word);
        }
        for (size_t offset = 0; offset < label.size(); offset += sizeof(u64)) {
            u64 word = 0;
            const size_t count = std::min(sizeof(u64), label.size() - offset);
            for (size_t i = 0; i < count; ++i)
                word |= static_cast<u64>(
                    static_cast<unsigned char>(label[offset + i])) << (8 * i);
            context_words.push_back(word);
        }
        const Digest release_context = hash_words(context_words);
        int collective_allow = 0;
        if (rank_ == 0 && external_release_anchor_gate_) {
            try {
                collective_allow = external_release_anchor_gate_(
                    label.c_str(), phase, round, release_context) ? 1 : 0;
            } catch (...) {
                collective_allow = 0;
            }
        }
        if (MPI_Bcast(&collective_allow, 1, MPI_INT, 0,
                      MPI_COMM_WORLD) != MPI_SUCCESS)
            collective_allow = 0;
        if (rank_ == 0) {
            std::cout << "[PVIA][external-release-anchor-gate] "
                      << (collective_allow ? "ALLOW" : "WITHHOLD")
                      << " release=" << label
                      << " phase=" << static_cast<uint32_t>(phase)
                      << " round=" << round << "\n";
        }
        return collective_allow == 1;
    };

    // After a successful strict release, block any second FOLD release in
    // the same round, but allow later protocol phases to use their own gates.
    if (require_private_residual_provenance_ &&
        private_residual_provenance_release_consumed_ &&
        phase == Phase::FOLD &&
        round == private_residual_provenance_consumed_round_) {
        if (rank_ == 0)
            std::cout << "[PVIA][residual-provenance-release-gate] "
                      << "WITHHOLD release="
                      << (release_name ? release_name : "unnamed")
                      << " reason=fold-release-already-consumed\n";
        return false;
    }
    // Strict provenance is a prerequisite, not an optional audit feature:
    // disabling the general PVIA diagnostics must never turn a pending
    // provenance decision into an implicit allow.
    if (require_private_residual_provenance_ &&
        private_residual_provenance_gate_started_) {
        if (phase != Phase::FOLD ||
            round != private_residual_expected_round_) {
            if (rank_ == 0)
                std::cout << "[PVIA][residual-provenance-release-gate] "
                          << "WITHHOLD release="
                          << (release_name ? release_name : "unnamed")
                          << " reason=scope-mismatch expected_phase="
                          << static_cast<uint32_t>(Phase::FOLD)
                          << " expected_round=" << private_residual_expected_round_
                          << " actual_phase=" << static_cast<uint32_t>(phase)
                          << " actual_round=" << round << "\n";
            return false;
        }
        if (!private_residual_provenance_release_gate(release_name))
            return false;
        // Authorization is a one-shot capability for the exact Merkle commitment
        // release. Do not let it authorize duplicate or unrelated release
        // points in the same FOLD epoch.
        private_residual_provenance_authorized_ = false;
        private_residual_source_bound_ = false;
        private_residual_statement_binding_ = Digest{};
        private_residual_computation_binding_ = Digest{};
        private_residual_check_transcript_binding_ = Digest{};
        private_residual_issuer_id_ = 0;
        private_residual_minimum_sequence_ = 0;
        private_residual_provenance_gate_started_ = false;
        private_residual_provenance_release_consumed_ = true;
        private_residual_provenance_consumed_round_ = round;
    }
    if (!config_.enabled) return !external_release_anchor_required_;
    const char* capture_env =
        std::getenv("PVIA_P105_NATIVE_SOURCE_CAPTURE");
    const char* stop_env =
        std::getenv("PVIA_P105_NATIVE_SOURCE_CAPTURE_STOP_AFTER_FIRST");
    // This explicit capture-only mode observes one real native fold and exits
    // before the proof continues. Do not use it to produce a proof result.
    if (!require_private_residual_provenance_ &&
        capture_env && std::string(capture_env) != "0" &&
        stop_env && std::string(stop_env) != "0")
        return external_anchor_allows();
    if (!audit_backend_override_) {
        if (config_.verbose && rank_ == 0)
            std::cout << "[PVIA][ReleaseGate] debug-only path; no secure backend "
                      << "attached for release="
                      << (release_name ? release_name : "unnamed")
                      << " phase=" << static_cast<uint32_t>(phase)
                      << " round=" << round << "\n";
        return external_anchor_allows();
    }

    const char* name = release_name ? release_name : "pre-release";
    seal_checkpoint(phase, round);
    const ObligationSet local_scope = scope_for_check(name, phase, round, true);
    const ObligationSet scope = audit_backend_override_->SynchronizeFailureScope(
        local_scope, rank_, world_size_);
    if (!same_failure_scope(local_scope, scope)) return false;
    const BatchCheckResult batch = audit_backend_override_->BatchCheck(scope);
    const bool allowed = batch.available && batch.ok &&
                         batch.cryptographically_authenticated;
    if (rank_ == 0 && config_.verbose)
        std::cout << "[PVIA][ReleaseGate] " << name
                  << " phase=" << static_cast<uint32_t>(phase)
                  << " round=" << round
                  << " result=" << (allowed ? "ALLOW" : "WITHHOLD") << "\n";
    return allowed && external_anchor_allows();
}

bool Runtime::handle_global_failure(const char* check_name,
                                    Phase phase, uint32_t round) {
    if (!config_.enabled) return false;
    if (audit_backend_override_) {
        return handle_global_failure_with_backend(
            check_name, phase, round, *audit_backend_override_);
    }
    DebugAuditBackend backend(*this);
    return handle_global_failure_with_backend(
        check_name, phase, round, backend);
}

bool Runtime::handle_global_failure_with_backend(
    const char* check_name, Phase phase, uint32_t round,
    AuditBackend& backend) {
    if (!config_.enabled) return false;
    ExperimentDurationScope failure_total_timer(
        ExperimentDurationKind::FAILURE_TOTAL);
    experiment_increment_failure_handling();
    latest_robust_abort_certificate_words_.clear();
    latest_robust_abort_registry_anchor_ = Digest{};
    const bool collective = backend.RequiresCollectiveFailureHandling();
    if (!collective && rank_ != 0) return true;

    if (rank_ == 0) std::cout << "[PVIA][BatchCheck] global check failed: "
              << check_name << " phase="
              << static_cast<uint32_t>(phase)
              << " round=" << round << "\n";

    seal_checkpoint(phase, round);
    const ObligationSet local_scope =
        scope_for_check(check_name, phase, round, true);
    const uint64_t scope_sync_start_ns = experiment_now_ns();
    ObligationSet scope = backend.SynchronizeFailureScope(
        local_scope, rank_, world_size_);
    experiment_add_duration(ExperimentDurationKind::SCOPE_SYNC,
        experiment_now_ns() - scope_sync_start_ns);
    if (!same_failure_scope(local_scope, scope)) {
        if (rank_ == 0)
            std::cout << "[PVIA][ScopeSync] backend changed the failure scope; "
                      << "refusing audit output\n";
        return false;
    }
    const uint64_t batch_start_ns = experiment_now_ns();
    BatchCheckResult batch = backend.BatchCheck(scope);
    experiment_add_duration(ExperimentDurationKind::BATCH_CHECK,
        experiment_now_ns() - batch_start_ns);
    if (!batch.available) {
        RobustAuditTerminationOutput termination;
        const uint64_t termination_query_start_ns = experiment_now_ns();
        const bool got_robust_termination =
            backend.GetLastRobustTermination(&termination);
        experiment_add_duration(
            ExperimentDurationKind::ROBUST_TERMINATION_QUERY,
            experiment_now_ns() - termination_query_start_ns);
        const bool has_robust_termination = got_robust_termination &&
            termination.available && termination.checkpoint == scope.checkpoint;
        if (has_robust_termination && termination.kind ==
                RobustAuditTerminationKind::DETECTABLE_UNATTRIBUTABLE_ABORT)
            experiment_record_unattributable_abort();
        if (has_robust_termination && termination.kind ==
                RobustAuditTerminationKind::PUBLICLY_ATTRIBUTABLE_ABORT)
            experiment_record_public_abort();
        if (rank_ == 0) {
            if (has_robust_termination &&
                termination.kind ==
                    RobustAuditTerminationKind::DETECTABLE_UNATTRIBUTABLE_ABORT) {
                std::cout << "[PVIA][RobustAudit] detectable but unattributable "
                          << "abort; refusing to produce blame evidence\n";
            } else if (has_robust_termination &&
                       termination.kind ==
                           RobustAuditTerminationKind::PUBLICLY_ATTRIBUTABLE_ABORT) {
                RobustAuditAbortCertificate certificate;
                const auto& auth = Ed25519TransferAuthenticator::instance();
                const uint64_t certificate_fetch_start_ns =
                    experiment_now_ns();
                const bool certificate_fetched =
                    backend.GetLastRobustAbortCertificate(&certificate);
                experiment_add_duration(
                    ExperimentDurationKind::ROBUST_CERTIFICATE_FETCH,
                    experiment_now_ns() - certificate_fetch_start_ns);
                bool certificate_ready = certificate_fetched &&
                    certificate.checkpoint.id == scope.checkpoint &&
                    certificate.output.abort_binding ==
                        termination.public_abort_binding &&
                    auth.ExternalRegistryAnchorVerified() &&
                    certificate.output.external_registry_anchor ==
                        auth.ExternalRegistryAnchor();
                if (certificate_ready) {
                    const uint64_t certificate_verify_start_ns =
                        experiment_now_ns();
                    certificate_ready = verify_robust_audit_abort_certificate(
                        certificate, auth.ExternalRegistryAnchor());
                    experiment_add_duration(
                        ExperimentDurationKind::ROBUST_CERTIFICATE_VERIFY,
                        experiment_now_ns() - certificate_verify_start_ns);
                }
                std::vector<u64> canonical_certificate_words;
                if (certificate_ready) {
                    const uint64_t certificate_encode_start_ns =
                        experiment_now_ns();
                    canonical_certificate_words =
                        encode_robust_audit_abort_certificate(certificate);
                    experiment_add_duration(
                        ExperimentDurationKind::ROBUST_CERTIFICATE_ENCODE,
                        experiment_now_ns() - certificate_encode_start_ns);
                    certificate_ready = !canonical_certificate_words.empty();
                    if (certificate_ready)
                        experiment_add_robust_certificate_bytes(
                            canonical_certificate_words.size() * sizeof(u64));
                }
                if (certificate_ready) {
                    latest_robust_abort_certificate_words_ =
                        canonical_certificate_words;
                    latest_robust_abort_registry_anchor_ =
                        auth.ExternalRegistryAnchor();
                }
                std::cout << "[PVIA][RobustAudit] public-abort termination "
                          << (certificate_ready ? "certificate verified; "
                                                : "status available; ")
                          << "refusing to derive generic blame evidence "
                          << "from runtime status alone\n";
                const char* export_path =
                    std::getenv("PVIA_ROBUST_ABORT_CERT_OUT");
                if (export_path && *export_path) {
                    const uint64_t certificate_export_start_ns =
                        experiment_now_ns();
                    const bool wrote = certificate_ready &&
                        write_robust_audit_abort_certificate_file(
                            export_path, certificate);
                    experiment_add_duration(
                        ExperimentDurationKind::ROBUST_CERTIFICATE_EXPORT,
                        experiment_now_ns() - certificate_export_start_ns);
                    std::cout << "[PVIA][robust-abort-certificate-export] "
                              << (wrote ? "wrote " : "FAILED ")
                              << export_path << "\n";
                }
            } else {
                std::cout << "[PVIA][BatchCheck] selected audit backend unavailable; "
                          << "refusing to produce blame evidence\n";
            }
        }
        return false;
    }
    if (batch.ok) {
        if (collective) {
            // Secure collective audit requires one canonical checkpoint root.
            // Do not broaden attribution across checkpoints when the exact
            // checkpoint has no authenticated mismatch.
            if (rank_ == 0)
                std::cout << "[PVIA][Dispute] exact secure checkpoint has no "
                          << "authenticated mismatch; treating failure as "
                          << "non-attributable rather than broadening scope\n";
            return true;
        }
        // Debug-only compatibility path for delayed public checks.
        // Fall back only within the same phase; never cross protocol phases.
        const ObligationSet fallback_local_scope =
            scope_for_check(check_name, phase, round, false);
        const uint64_t fallback_scope_sync_start_ns = experiment_now_ns();
        scope = backend.SynchronizeFailureScope(
            fallback_local_scope, rank_, world_size_);
        experiment_add_duration(ExperimentDurationKind::SCOPE_SYNC,
            experiment_now_ns() - fallback_scope_sync_start_ns);
        if (!same_failure_scope(fallback_local_scope, scope)) {
            if (rank_ == 0)
                std::cout << "[PVIA][ScopeSync] backend changed the fallback "
                          << "failure scope; refusing audit output\n";
            return false;
        }
        const uint64_t fallback_batch_start_ns = experiment_now_ns();
        batch = backend.BatchCheck(scope);
        experiment_add_duration(ExperimentDurationKind::BATCH_CHECK,
            experiment_now_ns() - fallback_batch_start_ns);
        if (!batch.available) {
            std::cout << "[PVIA][BatchCheck] selected audit backend unavailable "
                      << "during same-phase fallback\n";
            return false;
        }
        if (batch.ok) {
            std::cout << "[PVIA][Dispute] no attributable obligation mismatch "
                      << "in this checkpoint/phase; selected audit backend "
                      << "treats the failure as non-attributable\n";
            return true;
        }
        std::cout << "[PVIA][BatchCheck] exact checkpoint empty; using "
                  << "same-phase unresolved obligation set\n";
    }

    std::cout << "[PVIA][BatchCheck] checked="
              << batch.checked_operations
              << " mismatches=" << batch.mismatches
              << " challenge=" << batch.challenge.hex().substr(0, 16)
              << "... residual-commitment="
              << batch.aggregate_residual_commitment.hex().substr(0, 16)
              << "... authenticated="
              << (batch.cryptographically_authenticated ? "yes" : "no")
              << "\n";

    const Violation violation = backend.Dispute(scope, batch);
    if (!violation.valid) return true;
    seal_checkpoint(violation.label.phase, violation.label.round);
    const RecoverableAuditShare audit = backend.RecoverAudit(violation);
    BlameCertificate cert = backend.LiftBlame(violation, audit);
    if (cert.debug_only && !cert.predecessor_evidence_complete) {
        std::cout << "[PVIA][LiftBlame] debug dependency evidence incomplete; "
                  << "debug public judge must reject rather than risk framing\n";
    }
    const bool accepted = backend.Judge(cert, config_.session_id);

    if (accepted) {
        latest_certificate_ = cert;
        certificates_.push_back(cert);
        mark_resolved(violation);
        if (rank_ == 0 &&
            cert.evidence_kind == AuditEvidenceKind::PUBLIC_TRANSFER) {
            const std::string output_path = env_string("PVIA_TRANSFER_CERT_OUT");
            if (!output_path.empty()) {
                const bool wrote = write_public_transfer_blame_certificate_file(
                    output_path, cert);
                std::cout << "[PVIA][certificate-export] "
                          << (wrote ? "wrote " : "FAILED ")
                          << output_path << "\n";
            }
        }
    }

    std::cout << "[PVIA][Dispute] localized P"
              << violation.responsible_rank
              << " obligation="
              << static_cast<uint32_t>(violation.label.obligation)
              << " object=" << violation.label.object_id
              << " checkpoint=" << violation.checkpoint << "\n";
    std::cout << "[PVIA][RecoverAudit] "
              << (audit.debug_only ? "debug" : "authenticated")
              << " witness="
              << audit.witness_digest.hex().substr(0, 16) << "...\n";
    std::cout << "[PVIA][LiftBlame] "
              << (cert.debug_only ? "debug" : "secure")
              << " certificate judge="
              << (accepted ? "ACCEPT" : "REJECT") << "\n";
    return true;
}

void Runtime::consume_pending() {
    pending_valid_ = false;
    pending_ = Record{};
}

bool Runtime::latest_robust_abort_certificate(
    RobustAuditAbortCertificate* certificate) const {
    if (!certificate || latest_robust_abort_certificate_words_.empty() ||
        latest_robust_abort_registry_anchor_ == Digest{})
        return false;
    RobustAuditAbortCertificate decoded;
    if (!decode_robust_audit_abort_certificate(
            latest_robust_abort_certificate_words_, &decoded) ||
        !verify_robust_audit_abort_certificate(
            decoded, latest_robust_abort_registry_anchor_))
        return false;
    *certificate = decoded;
    return true;
}

bool Runtime::debug_judge(const BlameCertificate& cert) const {
    return debug_judge_share(cert);
}

bool Runtime::debug_judge_share(const BlameCertificate& cert) const {
    return PublicJudge::VerifyDebug(cert, config_.session_id);
}

void Runtime::print_summary() const {
    std::cout << "[PVIA] transcript records=" << transcript_records_
              << " digest="
              << transcript_digest_.hex().substr(0, 16) << "...\n";

    size_t sealed_checkpoints = 0;
    for (const auto& checkpoint : checkpoints_)
        if (checkpoint.sealed) ++sealed_checkpoints;
    size_t remote_incomplete_dependencies = 0;
    for (const auto& operation : operations_) {
        if (operation.observed_remote &&
            !operation.predecessor_evidence_complete)
            ++remote_incomplete_dependencies;
    }
    std::cout << "[PVIA] registry operations=" << operations_.size()
              << " checkpoints=" << checkpoints_.size()
              << " sealed=" << sealed_checkpoints
              << " remote-dependency-incomplete="
              << remote_incomplete_dependencies << "\n";

    std::cout << "[PVIA] unresolved candidates=";
    size_t unresolved = 0;
    for (const auto& v : violations_) if (!v.resolved) ++unresolved;
    std::cout << unresolved << " certificates=" << certificates_.size() << "\n";
    std::cout << "[PVIA] verified robust-abort artifact="
              << (has_robust_abort_certificate() ? "stored-separately" : "none")
              << "\n";

    if (!latest_certificate_.valid) {
        std::cout << "[PVIA] no generic blame certificate generated\n";
        return;
    }

    if (latest_certificate_.debug_only) {
        const bool accepted = debug_judge(latest_certificate_);
        std::cout << "[PVIA] DEBUG blame certificate: accused=P"
                  << latest_certificate_.accused
                  << " phase="
                  << static_cast<uint32_t>(latest_certificate_.label.phase)
                  << " round=" << latest_certificate_.label.round
                  << " judge=" << (accepted ? "ACCEPT" : "REJECT")
                  << "\n";
        std::cout << "[PVIA] This certificate is development-only and is NOT "
                  << "a cryptographically secure public blame proof.\n";
    } else {
        std::cout << "[PVIA] secure-provider certificate stored: accused=P"
                  << latest_certificate_.accused
                  << " phase="
                  << static_cast<uint32_t>(latest_certificate_.label.phase)
                  << " round=" << latest_certificate_.label.round
                  << " (verification was delegated to the selected backend)\n";
    }
}

} // namespace pvia
