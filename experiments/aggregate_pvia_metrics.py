#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path
from statistics import mean

OPTIONAL_BREAKDOWN_FIELDS = {
    'auth_baseline_payload_sent_bytes',
    'auth_baseline_payload_recv_bytes',
    'auth_pvia_payload_sent_bytes',
    'auth_pvia_payload_recv_bytes',
    'auth_overhead_sent_bytes',
    'auth_overhead_recv_bytes',
    'baseline_input_payload_sent_bytes',
    'baseline_input_payload_recv_bytes',
}

COUNTER_SUM_FIELDS = [
    'auth_sent_bytes', 'auth_recv_bytes',
    'auth_baseline_payload_sent_bytes', 'auth_baseline_payload_recv_bytes',
    'auth_pvia_payload_sent_bytes', 'auth_pvia_payload_recv_bytes',
    'auth_overhead_sent_bytes', 'auth_overhead_recv_bytes',
    'baseline_input_payload_sent_bytes', 'baseline_input_payload_recv_bytes',
    'auth_sent_messages', 'auth_recv_messages',
    'auth_collective_calls', 'control_sent_bytes', 'control_recv_bytes',
    'control_sent_messages', 'control_recv_messages',
    'control_collective_calls',
    'runtime_init_control_sent_bytes', 'runtime_init_control_recv_bytes',
    'runtime_init_control_collective_calls',
    'preprocessing_control_sent_bytes', 'preprocessing_control_recv_bytes',
    'preprocessing_control_collective_calls',
    'initial_validity_control_sent_bytes', 'initial_validity_control_recv_bytes',
    'initial_validity_control_collective_calls',
    'initial_validity_runs', 'initial_validity_strong_runs',
    'consistency_provider_control_sent_bytes',
    'consistency_provider_control_recv_bytes',
    'consistency_provider_control_collective_calls',
    'public_direct_validation_control_sent_bytes',
    'public_direct_validation_control_recv_bytes',
    'public_direct_validation_control_collective_calls',
    'transfer_meta_recv_bytes',
    'transfer_meta_recv_messages', 'transfer_meta_seal_calls',
    'transfer_meta_observe_calls', 'transfer_meta_verify_calls',
    'failure_handling_calls',
    'cert_canonical_bytes', 'public_abort_events',
    'unattributable_abort_events',
]
CONSENSUS_STATE_FIELDS = [
    'consistency_provider_present',
    'consistency_provider_production_ready',
    'consistency_provider_acceptance_present',
    'consistency_provider_protocol_id',
]
RESOURCE_FIELDS = ['peak_rss_kb']

# These counters are cluster-summed for end-to-end communication accounting,
# but their per-rank distribution is also useful for interpreting scalability.
RANK_DISTRIBUTION_FIELDS = [
    'auth_sent_bytes', 'auth_recv_bytes',
    'control_sent_bytes', 'control_recv_bytes',
    'runtime_init_control_sent_bytes', 'runtime_init_control_recv_bytes',
    'preprocessing_control_sent_bytes', 'preprocessing_control_recv_bytes',
    'initial_validity_control_sent_bytes', 'initial_validity_control_recv_bytes',
    'consistency_provider_control_sent_bytes',
    'consistency_provider_control_recv_bytes',
    'public_direct_validation_control_sent_bytes',
    'public_direct_validation_control_recv_bytes',
]

TIME_FIELDS = [
    'program_total_ns', 'transfer_meta_seal_ns',
    'transfer_meta_observe_ns', 'transfer_meta_verify_ns',
    'runtime_init_ns', 'preprocessing_ns', 'initial_validity_ns',
    'public_direct_validation_ns', 'consistency_provider_ns',
    'failure_total_ns', 'scope_sync_ns', 'batch_check_ns',
    'termination_query_ns', 'cert_fetch_ns', 'cert_verify_ns',
    'cert_encode_ns', 'cert_export_ns',
]

def load_rows(directory: Path):
    rows = []
    for path in sorted(directory.glob('pvia_metrics_rank_*.csv')):
        with path.open(newline='') as f:
            data = list(csv.DictReader(f))
        if len(data) != 1:
            raise ValueError(f'{path}: expected exactly one data row')
        row = data[0]
        row['_file'] = str(path)
        rows.append(row)
    if not rows:
        raise ValueError(f'no pvia_metrics_rank_*.csv in {directory}')
    return rows
def aggregate(rows):
    worlds = {int(r['world_size']) for r in rows}
    sessions = {r['session_id'] for r in rows}
    labels = {r['label'] for r in rows}
    if len(worlds) != 1 or len(sessions) != 1 or len(labels) != 1:
        raise ValueError('metrics rows disagree on world/session/label')
    world_size = next(iter(worlds))
    if len(rows) != world_size:
        raise ValueError(f'expected {world_size} rank rows, got {len(rows)}')
    out = {
        'label': next(iter(labels)),
        'session_id': next(iter(sessions)),
        'world_size': world_size,
        'rank_rows': len(rows),
    }
    for field in COUNTER_SUM_FIELDS:
        if field in OPTIONAL_BREAKDOWN_FIELDS:
            out['sum_' + field] = sum(int(r.get(field, 0) or 0) for r in rows)
        else:
            out['sum_' + field] = sum(int(r[field]) for r in rows)
    for field in RANK_DISTRIBUTION_FIELDS:
        vals = [int(r[field]) for r in rows]
        out['mean_rank_' + field] = int(mean(vals))
        out['max_rank_' + field] = max(vals)
    for field in CONSENSUS_STATE_FIELDS:
        values = [int(r[field]) for r in rows]
        if len(set(values)) != 1:
            raise ValueError(
                f'{field} differs by rank: {sorted(set(values))}')
        out[field] = values[0]
    for field in TIME_FIELDS:
        vals = [int(r[field]) for r in rows]
        out['mean_' + field] = int(mean(vals))
        out['max_' + field] = max(vals)
    for field in RESOURCE_FIELDS:
        vals = [int(r[field]) for r in rows]
        out['mean_' + field] = int(mean(vals))
        out['max_' + field] = max(vals)
    provider_flags = (
        out['consistency_provider_present'],
        out['consistency_provider_production_ready'],
        out['consistency_provider_acceptance_present'])
    if provider_flags == (0, 0, 0):
        if out['consistency_provider_protocol_id'] != 0:
            raise ValueError(
                'inactive consistency provider has nonzero protocol id')
    elif provider_flags == (1, 1, 1):
        if out['consistency_provider_protocol_id'] <= 0:
            raise ValueError(
                'active consistency provider has invalid protocol id')
    else:
        raise ValueError(
            f'inconsistent provider readiness state: {provider_flags}')
    out['sent_recv_bytes_match'] = int(
        out['sum_auth_sent_bytes'] == out['sum_auth_recv_bytes'])
    out['sent_recv_messages_match'] = int(
        out['sum_auth_sent_messages'] == out['sum_auth_recv_messages'])
    out['control_sent_recv_bytes_match'] = int(
        out['sum_control_sent_bytes'] == out['sum_control_recv_bytes'])
    out['control_sent_recv_messages_match'] = int(
        out['sum_control_sent_messages'] == out['sum_control_recv_messages'])
    control_calls = [int(r['control_collective_calls']) for r in rows]
    if len(set(control_calls)) != 1:
        raise ValueError(
            f'control collective calls differ by rank: {sorted(set(control_calls))}')
    out['control_collective_calls_per_rank'] = control_calls[0]
    category_prefixes = [
        'runtime_init', 'preprocessing', 'initial_validity',
        'consistency_provider', 'public_direct_validation']
    for prefix in category_prefixes:
        calls = [int(r[f'{prefix}_control_collective_calls']) for r in rows]
        if len(set(calls)) != 1:
            raise ValueError(
                f'{prefix} control collective calls differ by rank: '
                f'{sorted(set(calls))}')
        out[f'{prefix}_control_collective_calls_per_rank'] = calls[0]
    categorized_sent = sum(
        out[f'sum_{prefix}_control_sent_bytes']
        for prefix in category_prefixes)
    categorized_recv = sum(
        out[f'sum_{prefix}_control_recv_bytes']
        for prefix in category_prefixes)
    categorized_calls = sum(
        out[f'sum_{prefix}_control_collective_calls']
        for prefix in category_prefixes)
    out['unclassified_control_sent_bytes'] = (
        out['sum_control_sent_bytes'] - categorized_sent)
    out['unclassified_control_recv_bytes'] = (
        out['sum_control_recv_bytes'] - categorized_recv)
    out['unclassified_control_collective_calls'] = (
        out['sum_control_collective_calls'] - categorized_calls)
    if min(
            out['unclassified_control_sent_bytes'],
            out['unclassified_control_recv_bytes'],
            out['unclassified_control_collective_calls']) < 0:
        raise ValueError('categorized control counters exceed total counters')
    out['control_scope_partition_complete'] = int(
        out['unclassified_control_sent_bytes'] == 0 and
        out['unclassified_control_recv_bytes'] == 0 and
        out['unclassified_control_collective_calls'] == 0)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('metrics_dir', type=Path)
    ap.add_argument('--output', type=Path)
    args = ap.parse_args()
    rows = load_rows(args.metrics_dir)
    out = aggregate(rows)
    output = args.output or (args.metrics_dir / 'metrics_aggregate.csv')
    with output.open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(out.keys()))
        w.writeheader(); w.writerow(out)
    print(output)
    print('logical_bytes_sent=', out['sum_auth_sent_bytes'])
    print('control_bytes_sent=', out['sum_control_sent_bytes'])
    print('control_collectives_per_rank=', out['control_collective_calls_per_rank'])
    print('runtime_init_control_bytes_sent=', out['sum_runtime_init_control_sent_bytes'])
    print('preprocessing_control_bytes_sent=', out['sum_preprocessing_control_sent_bytes'])
    print('initial_validity_control_bytes_sent=', out['sum_initial_validity_control_sent_bytes'])
    print('consistency_provider_control_bytes_sent=', out['sum_consistency_provider_control_sent_bytes'])
    print('public_direct_validation_control_bytes_sent=', out['sum_public_direct_validation_control_sent_bytes'])
    print('unclassified_control_bytes_sent=', out['unclassified_control_sent_bytes'])
    print('control_scope_partition_complete=', out['control_scope_partition_complete'])
    print('consistency_provider_present=', out['consistency_provider_present'])
    print('consistency_provider_production_ready=', out['consistency_provider_production_ready'])
    print('consistency_provider_acceptance_present=', out['consistency_provider_acceptance_present'])
    print('consistency_provider_protocol_id=', out['consistency_provider_protocol_id'])
    print('peak_rss_max_mib=', out['max_peak_rss_kb'] / 1024.0)
    print('failure_max_ms=', out['max_failure_total_ns'] / 1e6)
    print('sent_recv_bytes_match=', out['sent_recv_bytes_match'])
    print('control_sent_recv_bytes_match=', out['control_sent_recv_bytes_match'])
    print('control_sent_recv_messages_match=', out['control_sent_recv_messages_match'])

if __name__ == '__main__':
    main()

