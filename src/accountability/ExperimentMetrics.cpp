#include "ExperimentMetrics.hpp"

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#if defined(__unix__) || defined(__APPLE__)
#include <sys/resource.h>
#endif

namespace pvia {
namespace {

ExperimentMetricsSnapshot g_metrics;
std::string g_output_dir;
std::string g_label;
uint64_t g_program_start_ns = 0;
thread_local ExperimentControlTrafficKind g_control_traffic_kind =
    ExperimentControlTrafficKind::GENERAL;

bool env_enabled(const char* name) {
    const char* value = std::getenv(name);
    if (!value) return false;
    const std::string s(value);
    return s == "1" || s == "true" || s == "TRUE" ||
        s == "yes" || s == "YES" || s == "on" || s == "ON";
}



uint64_t process_peak_rss_kb() {
#if defined(__unix__) || defined(__APPLE__)
    struct rusage usage {};
    if (getrusage(RUSAGE_SELF, &usage) != 0)
        return 0;
#if defined(__APPLE__)
    return static_cast<uint64_t>(usage.ru_maxrss) / 1024ULL;
#else
    return static_cast<uint64_t>(usage.ru_maxrss);
#endif
#else
    return 0;
#endif
}

std::string env_string_value(const char* name) {
    const char* value = std::getenv(name);
    return value ? std::string(value) : std::string();
}

} // namespace

void reset_experiment_metrics_from_environment(
    int, int, uint64_t) {
    g_metrics = ExperimentMetricsSnapshot{};
    g_metrics.enabled = env_enabled("PVIA_EXPERIMENT_METRICS");
    g_control_traffic_kind = ExperimentControlTrafficKind::GENERAL;
    g_program_start_ns = experiment_now_ns();
    g_output_dir = env_string_value("PVIA_EXPERIMENT_METRICS_DIR");
    g_label = env_string_value("PVIA_EXPERIMENT_LABEL");
}

bool experiment_metrics_enabled() {
    return g_metrics.enabled;
}

uint64_t experiment_now_ns() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

void experiment_add_authenticated_envelope_traffic(
    uint64_t sent_bytes, uint64_t recv_bytes,
    uint64_t sent_messages, uint64_t recv_messages) {
    if (!g_metrics.enabled) return;
    g_metrics.authenticated_envelope_sent_bytes += sent_bytes;
    g_metrics.authenticated_envelope_recv_bytes += recv_bytes;
    g_metrics.authenticated_envelope_sent_messages += sent_messages;
    g_metrics.authenticated_envelope_recv_messages += recv_messages;
}

void experiment_add_authenticated_traffic_breakdown(
    uint64_t payload_sent_bytes, uint64_t payload_recv_bytes,
    uint64_t overhead_sent_bytes, uint64_t overhead_recv_bytes,
    bool baseline_equivalent_payload) {
    if (!g_metrics.enabled) return;
    if (baseline_equivalent_payload) {
        g_metrics.authenticated_baseline_payload_sent_bytes += payload_sent_bytes;
        g_metrics.authenticated_baseline_payload_recv_bytes += payload_recv_bytes;
    } else {
        g_metrics.authenticated_pvia_payload_sent_bytes += payload_sent_bytes;
        g_metrics.authenticated_pvia_payload_recv_bytes += payload_recv_bytes;
    }
    g_metrics.authenticated_overhead_sent_bytes += overhead_sent_bytes;
    g_metrics.authenticated_overhead_recv_bytes += overhead_recv_bytes;
}

void experiment_add_baseline_input_payload_traffic(
    uint64_t sent_bytes, uint64_t recv_bytes) {
    if (!g_metrics.enabled) return;
    g_metrics.baseline_input_payload_sent_bytes += sent_bytes;
    g_metrics.baseline_input_payload_recv_bytes += recv_bytes;
}

void experiment_increment_authenticated_collective() {
    if (g_metrics.enabled) ++g_metrics.authenticated_collective_calls;
}

void experiment_add_protocol_control_traffic(
    uint64_t sent_bytes, uint64_t recv_bytes,
    uint64_t sent_messages, uint64_t recv_messages,
    uint64_t collective_calls) {
    if (!g_metrics.enabled) return;
    g_metrics.protocol_control_sent_bytes += sent_bytes;
    g_metrics.protocol_control_recv_bytes += recv_bytes;
    g_metrics.protocol_control_sent_messages += sent_messages;
    g_metrics.protocol_control_recv_messages += recv_messages;
    g_metrics.protocol_control_collective_calls += collective_calls;
    switch (g_control_traffic_kind) {
        case ExperimentControlTrafficKind::RUNTIME_INIT:
            g_metrics.runtime_init_control_sent_bytes += sent_bytes;
            g_metrics.runtime_init_control_recv_bytes += recv_bytes;
            g_metrics.runtime_init_control_collective_calls += collective_calls;
            break;
        case ExperimentControlTrafficKind::PREPROCESSING:
            g_metrics.preprocessing_control_sent_bytes += sent_bytes;
            g_metrics.preprocessing_control_recv_bytes += recv_bytes;
            g_metrics.preprocessing_control_collective_calls += collective_calls;
            break;
        case ExperimentControlTrafficKind::INITIAL_VALIDITY:
            g_metrics.initial_validity_control_sent_bytes += sent_bytes;
            g_metrics.initial_validity_control_recv_bytes += recv_bytes;
            g_metrics.initial_validity_control_collective_calls += collective_calls;
            break;
        case ExperimentControlTrafficKind::PUBLIC_DIRECT_VALIDATION:
            g_metrics.public_direct_validation_control_sent_bytes += sent_bytes;
            g_metrics.public_direct_validation_control_recv_bytes += recv_bytes;
            g_metrics.public_direct_validation_control_collective_calls += collective_calls;
            break;
        case ExperimentControlTrafficKind::CONSISTENCY_PROVIDER:
            g_metrics.consistency_provider_control_sent_bytes += sent_bytes;
            g_metrics.consistency_provider_control_recv_bytes += recv_bytes;
            g_metrics.consistency_provider_control_collective_calls += collective_calls;
            break;
        case ExperimentControlTrafficKind::GENERAL:
            break;
    }
}

void experiment_add_transfer_metadata_receive(
    uint64_t bytes, uint64_t messages) {
    if (!g_metrics.enabled) return;
    g_metrics.transfer_metadata_recv_bytes += bytes;
    g_metrics.transfer_metadata_recv_messages += messages;
}

void experiment_record_initial_validity(bool strong_consistency) {
    if (!g_metrics.enabled) return;
    ++g_metrics.initial_validity_runs;
    if (strong_consistency)
        ++g_metrics.initial_validity_strong_runs;
}

void experiment_record_consistency_provider_status(
    bool present, bool production_ready, bool acceptance_present,
    uint64_t protocol_id) {
    if (!g_metrics.enabled) return;
    g_metrics.consistency_provider_present = present ? 1ULL : 0ULL;
    g_metrics.consistency_provider_production_ready =
        production_ready ? 1ULL : 0ULL;
    g_metrics.consistency_provider_acceptance_present =
        acceptance_present ? 1ULL : 0ULL;
    g_metrics.consistency_provider_protocol_id = protocol_id;
}

void experiment_increment_failure_handling() {
    if (g_metrics.enabled) ++g_metrics.failure_handling_calls;
}
void experiment_add_duration(
    ExperimentDurationKind kind, uint64_t duration_ns) {
    if (!g_metrics.enabled) return;
    switch (kind) {
        case ExperimentDurationKind::FAILURE_TOTAL:
            g_metrics.failure_total_ns += duration_ns; break;
        case ExperimentDurationKind::SCOPE_SYNC:
            g_metrics.scope_sync_ns += duration_ns; break;
        case ExperimentDurationKind::BATCH_CHECK:
            g_metrics.batch_check_ns += duration_ns; break;
        case ExperimentDurationKind::ROBUST_TERMINATION_QUERY:
            g_metrics.robust_termination_query_ns += duration_ns; break;
        case ExperimentDurationKind::ROBUST_CERTIFICATE_FETCH:
            g_metrics.robust_certificate_fetch_ns += duration_ns; break;
        case ExperimentDurationKind::ROBUST_CERTIFICATE_VERIFY:
            g_metrics.robust_certificate_verify_ns += duration_ns; break;
        case ExperimentDurationKind::ROBUST_CERTIFICATE_ENCODE:
            g_metrics.robust_certificate_encode_ns += duration_ns; break;
        case ExperimentDurationKind::ROBUST_CERTIFICATE_EXPORT:
            g_metrics.robust_certificate_export_ns += duration_ns; break;
        case ExperimentDurationKind::TRANSFER_METADATA_SEAL:
            ++g_metrics.transfer_metadata_seal_calls;
            g_metrics.transfer_metadata_seal_ns += duration_ns; break;
        case ExperimentDurationKind::TRANSFER_METADATA_OBSERVE:
            ++g_metrics.transfer_metadata_observe_calls;
            g_metrics.transfer_metadata_observe_ns += duration_ns; break;
        case ExperimentDurationKind::TRANSFER_METADATA_VERIFY:
            ++g_metrics.transfer_metadata_verify_calls;
            g_metrics.transfer_metadata_verify_ns += duration_ns; break;
        case ExperimentDurationKind::RUNTIME_INIT:
            g_metrics.runtime_init_ns += duration_ns; break;
        case ExperimentDurationKind::PREPROCESSING:
            g_metrics.preprocessing_ns += duration_ns; break;
        case ExperimentDurationKind::INITIAL_VALIDITY:
            g_metrics.initial_validity_ns += duration_ns; break;
        case ExperimentDurationKind::PUBLIC_DIRECT_VALIDATION:
            g_metrics.public_direct_validation_ns += duration_ns; break;
        case ExperimentDurationKind::CONSISTENCY_PROVIDER:
            g_metrics.consistency_provider_ns += duration_ns; break;
    }
}

void experiment_add_robust_certificate_bytes(uint64_t bytes) {
    if (g_metrics.enabled) g_metrics.robust_certificate_canonical_bytes += bytes;
}
void experiment_record_public_abort() {
    if (g_metrics.enabled) ++g_metrics.public_abort_events;
}
void experiment_record_unattributable_abort() {
    if (g_metrics.enabled) ++g_metrics.unattributable_abort_events;
}
ExperimentMetricsSnapshot experiment_metrics_snapshot() {
    return g_metrics;
}

bool emit_experiment_metrics_csv(
    int rank, int world_size, uint64_t session_id) {
    if (!g_metrics.enabled) return true;
    const uint64_t now_ns = experiment_now_ns();
    g_metrics.program_total_ns = now_ns >= g_program_start_ns
        ? now_ns - g_program_start_ns : 0;
    g_metrics.peak_rss_kb = process_peak_rss_kb();
    std::ostringstream row;
    row << "label,session_id,rank,world_size,program_total_ns,peak_rss_kb,auth_sent_bytes,auth_recv_bytes,"
        << "auth_baseline_payload_sent_bytes,auth_baseline_payload_recv_bytes,"
        << "auth_pvia_payload_sent_bytes,auth_pvia_payload_recv_bytes,"
        << "auth_overhead_sent_bytes,auth_overhead_recv_bytes,"
        << "baseline_input_payload_sent_bytes,baseline_input_payload_recv_bytes,"
        << "auth_sent_messages,auth_recv_messages,auth_collective_calls,"
        << "control_sent_bytes,control_recv_bytes,control_sent_messages,"
        << "control_recv_messages,control_collective_calls,"
        << "runtime_init_control_sent_bytes,runtime_init_control_recv_bytes,"
        << "runtime_init_control_collective_calls,"
        << "preprocessing_control_sent_bytes,preprocessing_control_recv_bytes,"
        << "preprocessing_control_collective_calls,"
        << "initial_validity_control_sent_bytes,initial_validity_control_recv_bytes,"
        << "initial_validity_control_collective_calls,"
        << "initial_validity_runs,initial_validity_strong_runs,"
        << "consistency_provider_present,"
        << "consistency_provider_production_ready,"
        << "consistency_provider_acceptance_present,"
        << "consistency_provider_protocol_id,"
        << "consistency_provider_control_sent_bytes,"
        << "consistency_provider_control_recv_bytes,"
        << "consistency_provider_control_collective_calls,"
        << "public_direct_validation_control_sent_bytes,"
        << "public_direct_validation_control_recv_bytes,"
        << "public_direct_validation_control_collective_calls,"
        << "transfer_meta_recv_bytes,transfer_meta_recv_messages,"
        << "transfer_meta_seal_calls,transfer_meta_seal_ns,"
        << "transfer_meta_observe_calls,transfer_meta_observe_ns,"
        << "transfer_meta_verify_calls,transfer_meta_verify_ns,"
        << "runtime_init_ns,preprocessing_ns,initial_validity_ns,"
        << "public_direct_validation_ns,consistency_provider_ns,"
        << "failure_handling_calls,failure_total_ns,scope_sync_ns,batch_check_ns,"
        << "termination_query_ns,cert_fetch_ns,cert_verify_ns,cert_encode_ns,"
        << "cert_export_ns,cert_canonical_bytes,public_abort_events,"
        << "unattributable_abort_events\n";
    row << g_label << ',' << session_id << ',' << rank << ',' << world_size << ','
        << g_metrics.program_total_ns << ','
        << g_metrics.peak_rss_kb << ','
        << g_metrics.authenticated_envelope_sent_bytes << ','
        << g_metrics.authenticated_envelope_recv_bytes << ','
        << g_metrics.authenticated_baseline_payload_sent_bytes << ','
        << g_metrics.authenticated_baseline_payload_recv_bytes << ','
        << g_metrics.authenticated_pvia_payload_sent_bytes << ','
        << g_metrics.authenticated_pvia_payload_recv_bytes << ','
        << g_metrics.authenticated_overhead_sent_bytes << ','
        << g_metrics.authenticated_overhead_recv_bytes << ','
        << g_metrics.baseline_input_payload_sent_bytes << ','
        << g_metrics.baseline_input_payload_recv_bytes << ','
        << g_metrics.authenticated_envelope_sent_messages << ','
        << g_metrics.authenticated_envelope_recv_messages << ','
        << g_metrics.authenticated_collective_calls << ','
        << g_metrics.protocol_control_sent_bytes << ','
        << g_metrics.protocol_control_recv_bytes << ','
        << g_metrics.protocol_control_sent_messages << ','
        << g_metrics.protocol_control_recv_messages << ','
        << g_metrics.protocol_control_collective_calls << ','
        << g_metrics.runtime_init_control_sent_bytes << ','
        << g_metrics.runtime_init_control_recv_bytes << ','
        << g_metrics.runtime_init_control_collective_calls << ','
        << g_metrics.preprocessing_control_sent_bytes << ','
        << g_metrics.preprocessing_control_recv_bytes << ','
        << g_metrics.preprocessing_control_collective_calls << ','
        << g_metrics.initial_validity_control_sent_bytes << ','
        << g_metrics.initial_validity_control_recv_bytes << ','
        << g_metrics.initial_validity_control_collective_calls << ','
        << g_metrics.initial_validity_runs << ','
        << g_metrics.initial_validity_strong_runs << ','
        << g_metrics.consistency_provider_present << ','
        << g_metrics.consistency_provider_production_ready << ','
        << g_metrics.consistency_provider_acceptance_present << ','
        << g_metrics.consistency_provider_protocol_id << ','
        << g_metrics.consistency_provider_control_sent_bytes << ','
        << g_metrics.consistency_provider_control_recv_bytes << ','
        << g_metrics.consistency_provider_control_collective_calls << ','
        << g_metrics.public_direct_validation_control_sent_bytes << ','
        << g_metrics.public_direct_validation_control_recv_bytes << ','
        << g_metrics.public_direct_validation_control_collective_calls << ','
        << g_metrics.transfer_metadata_recv_bytes << ','
        << g_metrics.transfer_metadata_recv_messages << ','
        << g_metrics.transfer_metadata_seal_calls << ','
        << g_metrics.transfer_metadata_seal_ns << ','
        << g_metrics.transfer_metadata_observe_calls << ','
        << g_metrics.transfer_metadata_observe_ns << ','
        << g_metrics.transfer_metadata_verify_calls << ','
        << g_metrics.transfer_metadata_verify_ns << ','
        << g_metrics.runtime_init_ns << ','
        << g_metrics.preprocessing_ns << ','
        << g_metrics.initial_validity_ns << ','
        << g_metrics.public_direct_validation_ns << ','
        << g_metrics.consistency_provider_ns << ','
        << g_metrics.failure_handling_calls << ',' << g_metrics.failure_total_ns << ','
        << g_metrics.scope_sync_ns << ',' << g_metrics.batch_check_ns << ','
        << g_metrics.robust_termination_query_ns << ','
        << g_metrics.robust_certificate_fetch_ns << ','
        << g_metrics.robust_certificate_verify_ns << ','
        << g_metrics.robust_certificate_encode_ns << ','
        << g_metrics.robust_certificate_export_ns << ','
        << g_metrics.robust_certificate_canonical_bytes << ','
        << g_metrics.public_abort_events << ','
        << g_metrics.unattributable_abort_events << '\n';
    std::cout << "[PVIA][metrics] "
              << "label=" << g_label
              << " rank=" << rank << '/' << world_size
              << " program_total_ns=" << g_metrics.program_total_ns
              << " peak_rss_kb=" << g_metrics.peak_rss_kb
              << " auth_sent_bytes="
              << g_metrics.authenticated_envelope_sent_bytes
              << " auth_recv_bytes="
              << g_metrics.authenticated_envelope_recv_bytes
              << " control_sent_bytes="
              << g_metrics.protocol_control_sent_bytes
              << " control_recv_bytes="
              << g_metrics.protocol_control_recv_bytes
              << " control_collectives="
              << g_metrics.protocol_control_collective_calls
              << " transfer_meta_recv_bytes="
              << g_metrics.transfer_metadata_recv_bytes
              << " failure_total_ns=" << g_metrics.failure_total_ns
              << " cert_bytes="
              << g_metrics.robust_certificate_canonical_bytes << "\n";
    if (g_output_dir.empty()) return true;
    std::ostringstream path;
    path << g_output_dir;
    if (!g_output_dir.empty() && g_output_dir.back() != '/' &&
        g_output_dir.back() != '\\')
        path << '/';
    path << "pvia_metrics_rank_" << rank << ".csv";
    std::ofstream out(path.str().c_str(), std::ios::out | std::ios::trunc);
    if (!out) return false;
    out << row.str();
    return static_cast<bool>(out);
}

} // namespace pvia

namespace pvia {
ExperimentControlTrafficScope::ExperimentControlTrafficScope(
    ExperimentControlTrafficKind kind)
    : previous_(g_control_traffic_kind),
      active_(experiment_metrics_enabled()) {
    if (active_) g_control_traffic_kind = kind;
}

ExperimentControlTrafficScope::~ExperimentControlTrafficScope() {
    if (active_) g_control_traffic_kind = previous_;
}

ExperimentDurationScope::ExperimentDurationScope(
    ExperimentDurationKind kind)
    : kind_(kind),
      start_ns_(experiment_now_ns()),
      active_(experiment_metrics_enabled()) {}

ExperimentDurationScope::~ExperimentDurationScope() {
    if (!active_) return;
    const uint64_t end_ns = experiment_now_ns();
    if (end_ns >= start_ns_)
        experiment_add_duration(kind_, end_ns - start_ns_);
}
} // namespace pvia
