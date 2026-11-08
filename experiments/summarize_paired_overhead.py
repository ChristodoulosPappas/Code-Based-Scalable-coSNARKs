#!/usr/bin/env python3
import csv, math, statistics, sys

if len(sys.argv) != 4:
    raise SystemExit('usage: summarize_paired_overhead.py RAW PAIRED SUMMARY')
raw_path, paired_path, summary_path = sys.argv[1:]
with open(raw_path, newline='') as f:
    rows = list(csv.DictReader(f))
by_iter = {}
for row in rows:
    by_iter.setdefault(row['iteration'], {})[row['scenario']] = row
metrics = {
    'program_total_ms': ('max_program_total_ns', 1e6),
    'peak_rss_mb': ('max_peak_rss_kb', 1024.0),
    'rank0_pt_ms': ('rank0_pt_s', 1e-3),
    'verifier_total_ms': ('verifier_total_s', 1e-3),
    'proof_kb': ('proof_kb', 1.0),
    'reported_comm_mb': ('reported_comm_mb', 1.0),
    'interaction_rounds': ('interaction_rounds', 1.0),
}
available_fields = set(rows[0]) if rows else set()
metrics = {
    name: spec for name, spec in metrics.items()
    if spec[0] in available_fields
}
paired_rows = []
for iteration in sorted(by_iter, key=lambda x: int(x)):
    pair = by_iter[iteration]
    if set(pair) != {'disabled', 'enabled'}:
        raise SystemExit(f'incomplete pair at iteration {iteration}')
    out = {'iteration': iteration}
    for name, (field, scale) in metrics.items():
        disabled = float(pair['disabled'][field]) / scale
        enabled = float(pair['enabled'][field]) / scale
        out[f'disabled_{name}'] = disabled
        out[f'enabled_{name}'] = enabled
        out[f'{name}_delta'] = enabled - disabled
        out[f'{name}_overhead_pct'] = (enabled / disabled - 1.0) * 100.0 if disabled else 0.0
    paired_rows.append(out)

fields = list(paired_rows[0]) if paired_rows else ['iteration']
with open(paired_path, 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader(); writer.writerows(paired_rows)

def percentile(values, q):
    values = sorted(values)
    if not values: return 0.0
    if len(values) == 1: return values[0]
    pos = (len(values) - 1) * q
    lo, hi = math.floor(pos), math.ceil(pos)
    if lo == hi: return values[lo]
    return values[lo] + (values[hi] - values[lo]) * (pos - lo)

summary_rows = []
for metric in fields:
    if metric == 'iteration': continue
    values = [float(row[metric]) for row in paired_rows]
    summary_rows.append({
        'metric': metric, 'n': len(values),
        'mean': statistics.mean(values),
        'median': statistics.median(values),
        'stddev': statistics.stdev(values) if len(values) > 1 else 0.0,
        'p95': percentile(values, 0.95),
        'min': min(values), 'max': max(values),
    })
with open(summary_path, 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['metric','n','mean','median','stddev','p95','min','max'])
    writer.writeheader(); writer.writerows(summary_rows)
print(f'PAIRED_OVERHEAD_SUMMARY: PASS pairs={len(paired_rows)}')
