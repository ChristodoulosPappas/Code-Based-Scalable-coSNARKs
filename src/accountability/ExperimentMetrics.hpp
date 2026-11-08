#pragma once

#include <cstdint>
#include <string>

namespace pvia {

enum class ExperimentControlTrafficKind : uint32_t {
    GENERAL = 0,
    RUNTIME_INIT = 1,
    PREPROCESSING = 2,
    INITIAL_VALIDITY = 3,
    PUBLIC_DIRECT_VALIDATION = 4,
    CONSISTENCY_PROVIDER = 5
};

enum class ExperimentDurationKind : uint32_t {
    FAILURE_TOTAL = 1,
    SCOPE_SYNC = 2,
    BATCH_CHECK = 3,
    ROBUST_TERMINATION_QUERY = 4,
    ROBUST_CERTIFICATE_FETCH = 5,
    ROBUST_CERTIFICATE_VERIFY = 6,
    ROBUST_CERTIFICATE_ENCODE = 7,
    ROBUST_CERTIFICATE_EXPORT = 8,
    TRANSFER_METADATA_SEAL = 9,
    TRANSFER_METADATA_OBSERVE = 10,
    TRANSFER_METADATA_VERIFY = 11,
    RUNTIME_INIT = 12,
    PREPROCESSING = 13,
    INITIAL_VALIDITY = 14,
    PUBLIC_DIRECT_VALIDATION = 15,
    CONSISTENCY_PROVIDER = 16
};

struct ExperimentMetricsSnapshot {
    bool enabled = false;
    uint64_t program_total_ns = 0;
    uint64_t peak_rss_kb = 0;
    uint64_t authenticated_envelope_sent_bytes = 0;
    uint64_t authenticated_envelope_recv_bytes = 0;
    // Breakdown of authenticated transport bytes. Baseline-equivalent payload
    // is application data the native prover already sends (e.g. input shares);
    // PVIA-only payload is introduced by accountability/MPC checks; overhead
    // is signatures and compact authenticated summaries.
    uint64_t authenticated_baseline_payload_sent_bytes = 0;
    uint64_t authenticated_baseline_payload_recv_bytes = 0;
    uint64_t authenticated_pvia_payload_sent_bytes = 0;
    uint64_t authenticated_pvia_payload_recv_bytes = 0;
    uint64_t authenticated_overhead_sent_bytes = 0;
    uint64_t authenticated_overhead_recv_bytes = 0;
    // Native application payload used to distribute the initial packed
    // witness/input shares. This is recorded in both disabled and enabled
    // runs so end-to-end transport can be compared on the same boundary.
    uint64_t baseline_input_payload_sent_bytes = 0;
    uint64_t baseline_input_payload_recv_bytes = 0;
    uint64_t authenticated_envelope_sent_messages = 0;
    uint64_t authenticated_envelope_recv_messages = 0;
    uint64_t authenticated_collective_calls = 0;
    // Logical application payload added by protocol-control collectives that
    // are outside the legacy coPIOP communication counter.
    uint64_t protocol_control_sent_bytes = 0;
    uint64_t protocol_control_recv_bytes = 0;
    uint64_t protocol_control_sent_messages = 0;
    uint64_t protocol_control_recv_messages = 0;
    uint64_t protocol_control_collective_calls = 0;
    uint64_t runtime_init_control_sent_bytes = 0;
    uint64_t runtime_init_control_recv_bytes = 0;
    uint64_t runtime_init_control_collective_calls = 0;
    uint64_t preprocessing_control_sent_bytes = 0;
    uint64_t preprocessing_control_recv_bytes = 0;
    uint64_t preprocessing_control_collective_calls = 0;
    uint64_t initial_validity_control_sent_bytes = 0;
    uint64_t initial_validity_control_recv_bytes = 0;
    uint64_t initial_validity_control_collective_calls = 0;
    uint64_t initial_validity_runs = 0;
    uint64_t initial_validity_strong_runs = 0;
    uint64_t consistency_provider_present = 0;
    uint64_t consistency_provider_production_ready = 0;
    uint64_t consistency_provider_acceptance_present = 0;
    uint64_t consistency_provider_protocol_id = 0;
    uint64_t consistency_provider_control_sent_bytes = 0;
    uint64_t consistency_provider_control_recv_bytes = 0;
    uint64_t consistency_provider_control_collective_calls = 0;
    uint64_t public_direct_validation_control_sent_bytes = 0;
    uint64_t public_direct_validation_control_recv_bytes = 0;
    uint64_t public_direct_validation_control_collective_calls = 0;
    // Aggregate signed PVIA metadata actually delivered to remote ranks.
    uint64_t transfer_metadata_recv_bytes = 0;
    uint64_t transfer_metadata_recv_messages = 0;
    uint64_t transfer_metadata_seal_calls = 0;
    uint64_t transfer_metadata_seal_ns = 0;
    uint64_t transfer_metadata_observe_calls = 0;
    uint64_t transfer_metadata_observe_ns = 0;
    uint64_t transfer_metadata_verify_calls = 0;
    uint64_t transfer_metadata_verify_ns = 0;
    uint64_t runtime_init_ns = 0;
    uint64_t preprocessing_ns = 0;
    uint64_t initial_validity_ns = 0;
    uint64_t public_direct_validation_ns = 0;
    uint64_t consistency_provider_ns = 0;
    uint64_t failure_handling_calls = 0;
    uint64_t failure_total_ns = 0;
    uint64_t scope_sync_ns = 0;
    uint64_t batch_check_ns = 0;
    uint64_t robust_termination_query_ns = 0;
    uint64_t robust_certificate_fetch_ns = 0;
    uint64_t robust_certificate_verify_ns = 0;
    uint64_t robust_certificate_encode_ns = 0;
    uint64_t robust_certificate_export_ns = 0;
    uint64_t robust_certificate_canonical_bytes = 0;
    uint64_t public_abort_events = 0;
    uint64_t unattributable_abort_events = 0;
};

void reset_experiment_metrics_from_environment(
    int rank, int world_size, uint64_t session_id);
bool experiment_metrics_enabled();
uint64_t experiment_now_ns();
void experiment_add_authenticated_envelope_traffic(
    uint64_t sent_bytes, uint64_t recv_bytes,
    uint64_t sent_messages, uint64_t recv_messages);
void experiment_add_authenticated_traffic_breakdown(
    uint64_t payload_sent_bytes, uint64_t payload_recv_bytes,
    uint64_t overhead_sent_bytes, uint64_t overhead_recv_bytes,
    bool baseline_equivalent_payload);
void experiment_add_baseline_input_payload_traffic(
    uint64_t sent_bytes, uint64_t recv_bytes);
void experiment_increment_authenticated_collective();
void experiment_add_protocol_control_traffic(
    uint64_t sent_bytes, uint64_t recv_bytes,
    uint64_t sent_messages, uint64_t recv_messages,
    uint64_t collective_calls = 1);
void experiment_add_transfer_metadata_receive(
    uint64_t bytes, uint64_t messages = 1);
void experiment_record_initial_validity(bool strong_consistency);
void experiment_record_consistency_provider_status(
    bool present, bool production_ready, bool acceptance_present,
    uint64_t protocol_id);
void experiment_increment_failure_handling();
void experiment_add_duration(
    ExperimentDurationKind kind, uint64_t duration_ns);
void experiment_add_robust_certificate_bytes(uint64_t bytes);
void experiment_record_public_abort();
void experiment_record_unattributable_abort();
ExperimentMetricsSnapshot experiment_metrics_snapshot();
bool emit_experiment_metrics_csv(
    int rank, int world_size, uint64_t session_id);

} // namespace pvia

namespace pvia {
class ExperimentControlTrafficScope {
public:
    explicit ExperimentControlTrafficScope(ExperimentControlTrafficKind kind);
    ~ExperimentControlTrafficScope();
    ExperimentControlTrafficScope(const ExperimentControlTrafficScope&) = delete;
    ExperimentControlTrafficScope& operator=(const ExperimentControlTrafficScope&) = delete;
private:
    ExperimentControlTrafficKind previous_ =
        ExperimentControlTrafficKind::GENERAL;
    bool active_ = false;
};

class ExperimentDurationScope {
public:
    explicit ExperimentDurationScope(ExperimentDurationKind kind);
    ~ExperimentDurationScope();
    ExperimentDurationScope(const ExperimentDurationScope&) = delete;
    ExperimentDurationScope& operator=(const ExperimentDurationScope&) = delete;
private:
    ExperimentDurationKind kind_;
    uint64_t start_ns_ = 0;
    bool active_ = false;
};
} // namespace pvia
