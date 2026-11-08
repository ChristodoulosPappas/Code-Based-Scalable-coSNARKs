#!/usr/bin/env python3
import argparse
import csv
import math
import statistics
from collections import defaultdict
from pathlib import Path

ID_FIELDS = {'scenario', 'iteration', 'label', 'session_id', 'consistency_provider_protocol_id'}

def percentile(values, q):
    xs = sorted(values)
    if not xs:
        return 0.0
    if len(xs) == 1:
        return xs[0]
    pos = (len(xs) - 1) * q
    lo = int(math.floor(pos)); hi = int(math.ceil(pos))
    if lo == hi:
        return xs[lo]
    return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('raw_csv', type=Path)
    ap.add_argument('summary_csv', type=Path)
    args = ap.parse_args()
    with args.raw_csv.open(newline='') as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise SystemExit('no repeated metrics rows')
    groups = defaultdict(list)
    for row in rows:
        groups[row['scenario']].append(row)
    numeric_fields = [
        k for k in rows[0].keys()
        if k not in ID_FIELDS and k not in {'rank_rows'}
    ]
    out_rows = []
    for scenario, items in sorted(groups.items()):
        for field in numeric_fields:
            try:
                vals = [float(r[field]) for r in items]
            except (TypeError, ValueError):
                continue
            out_rows.append({
                'scenario': scenario,
                'metric': field,
                'n': len(vals),
                'mean': statistics.mean(vals),
                'median': statistics.median(vals),
                'stddev': statistics.stdev(vals) if len(vals) > 1 else 0.0,
                'p95': percentile(vals, 0.95),
                'min': min(vals),
                'max': max(vals),
            })
    fields = ['scenario','metric','n','mean','median','stddev','p95','min','max']
    with args.summary_csv.open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader(); w.writerows(out_rows)
    print(args.summary_csv)

if __name__ == '__main__':
    main()
