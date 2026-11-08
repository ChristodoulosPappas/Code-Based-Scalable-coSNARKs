#!/usr/bin/env python3
"""Verify a PVIA test-only release-gate run from its raw log and provenance.

This establishes a reproducible evidence record for release-gate *wiring*.
It does not validate a private residual evaluator, proof soundness, or ZK.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

SCHEMA = "pvia-release-gate-evidence/v1"
EXPECTED_RELEASES = {
    "cosumcheck": "cosumcheck_quadratic_round_release",
    "distributed-sumcheck": "distributed_quadratic_round_release",
    "encoding": "encoding_stage2_codeword",
    "pcs-open": "pcs_open_round_release",
    "pcs-batch-open": "pcs_batch_open_round_release",
}
LINE = re.compile(
    r"^\[PVIA\]\[release-gate-matrix\]"
    r" family=([a-z-]+) release=([a-z0-9_]+)"
    r" phase=(\d+) round=(\d+) kernel=(\d+)"
    r" positive=(ALLOW|WITHHOLD)"
    r" injected=(ALLOW|WITHHOLD)"
    r" exact-scope=(BOUND|UNBOUND)"
    r" result=(PASS|FAIL)$"
)


def reject(message):
    raise ValueError(message)


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for buf in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(buf)
    return h.hexdigest()


def require_file(path):
    p = Path(path).resolve(strict=True)
    if not p.is_file():
        reject("missing regular file: " + str(p))
    return p


def parse_summary(path):
    rows = {}
    for text in path.read_text(encoding="utf-8").splitlines():
        text = text.strip()
        if not text or text == "PVIA RELEASE GATE MATRIX: PASS":
            continue
        if "=" not in text:
            reject("unexpected summary record")
        k, v = text.split("=", 1)
        if not k or k in rows:
            reject("duplicate or empty summary key")
        rows[k] = v
    expected = {
        "np": "4",
        "cases": "5",
        "exact_scope": "BOUND",
        "private_localization": "folding-only",
        "other_families": "release-blocking-only",
        "decision_backend": "test-only",
        "claim_scope": "release-gate-withholding-semantics",
    }
    for key, value in expected.items():
        if rows.get(key) != value:
            reject("summary mismatch: " + key)
    for family, stem in (
        ("cosumcheck", "cosumcheck"),
        ("distributed-sumcheck", "distributed_sumcheck"),
        ("encoding", "encoding"),
        ("pcs-open", "pcs_open"),
        ("pcs-batch-open", "pcs_batch_open"),
    ):
        for suffix, val in (("positive", "ALLOW"), ("injected", "WITHHOLD")):
            if rows.get(stem + "_" + suffix) != val:
                reject("summary outcome mismatch: " + family + " " + suffix)
    if "PVIA RELEASE GATE MATRIX: PASS" not in path.read_text(encoding="utf-8"):
        reject("missing successful summary header")
    return rows


def check_records(manifest_path, raw_path, summary_path, allow_head_drift=False):
    provenance = json.loads(manifest_path.read_text(encoding="utf-8"))
    if provenance.get("schema") != "pvia-run-provenance/v1":
        reject("unrecognized provenance schema")
    if provenance.get("run_type") != "regression-selftest":
        reject("this verifier accepts test-only regression runs only")
    if provenance.get("claim_scope") != "provenance-only; not a cryptographic security attestation":
        reject("provenance claim-scope mismatch")
    root = Path(provenance["repo_realpath"]).resolve(strict=True)
    if not (root / "CMakeLists.txt").is_file() or not (root / "src" / "CMakeLists.txt").is_file():
        reject("repo root does not contain the PAR-coSNARK source tree")
    executable = require_file(provenance["binary_realpath"])
    script = require_file(provenance["script_realpath"])
    if executable != root / "build-par" / "src" / "pigeon":
        reject("unexpected executable path")
    if script != root / "experiments" / "run_release_gate_matrix_xfusion.sh":
        reject("wrong release-gate entrypoint")
    if digest(executable) != provenance.get("binary_sha256"):
        reject("binary changed since preflight")
    if digest(script) != provenance.get("script_sha256"):
        reject("entrypoint changed since preflight")
    if provenance.get("binary_built_from_current_head") != "NOT_ATTESTED":
        reject("unsupported binary-source attestation")
    if raw_path.parent != manifest_path.parent or summary_path.parent != manifest_path.parent:
        reject("log, summary and manifest must share an output directory")
    actual_commit = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    original_commit = provenance.get("repo_commit", "")
    if actual_commit != original_commit and not allow_head_drift:
        reject("repo HEAD changed since preflight")
    summary = parse_summary(summary_path)
    records = {}
    for line in raw_path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("[PVIA][release-gate-matrix]"):
            continue
        matched = LINE.fullmatch(line.strip())
        if not matched:
            reject("malformed release trace")
        family, release, phase, round_, kernel, positive, injected, scope, result = matched.groups()
        if family in records:
            reject("duplicate release family: " + family)
        if EXPECTED_RELEASES.get(family) != release:
            reject("unexpected release-family mapping")
        if positive != "ALLOW" or injected != "WITHHOLD" or scope != "BOUND" or result != "PASS":
            reject("unexpected release-gate outcome")
        records[family] = {
            "release": release,
            "phase": int(phase),
            "round": int(round_),
            "kernel": int(kernel),
            "positive": positive,
            "injected": injected,
            "scope": scope,
            "status": result,
        }
    if set(records) != set(EXPECTED_RELEASES):
        reject("missing release families")
    end = re.findall(
        r"^\[PVIA\]\[release-gate-matrix-summary\]"
        r" cases=(\d+) private-localization=([a-z-]+)"
        r" other-families=([a-z-]+)(?: strict-provenance=([a-z-]+))? result=(PASS|FAIL)$",
        raw_path.read_text(encoding="utf-8"), re.MULTILINE,
    )
    if (len(end) != 1 or end[0][0] != "5" or end[0][1] != "folding-only" or
            end[0][2] != "release-blocking-only" or end[0][4] != "PASS"):
        reject("incorrect or duplicated final release summary")

    return {
        "schema": SCHEMA,
        "verdict": "PASS_TEST_ONLY",
        "claim_scope": "release-gate wiring; NOT a cryptographic residual proof",
        "backend": "test-only decision backend",
        "production_private_evaluators": "NOT_ESTABLISHED",
        "repo_commit_at_preflight": original_commit,
        "repo_head_at_verification": actual_commit,
        "repo_head_drift_accepted": actual_commit != original_commit,
        "binary_sha256": provenance["binary_sha256"],
        "script_sha256": provenance["script_sha256"],
        "provenance_manifest_sha256": digest(manifest_path),
        "raw_log_sha256": digest(raw_path),
        "summary_sha256": digest(summary_path),
        "cases": records,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--allow-head-drift", action="store_true")
    args = parser.parse_args()
    try:
        record = check_records(
            require_file(args.manifest), require_file(args.log),
            require_file(args.summary), args.allow_head_drift,
        )
        output = args.out.absolute()
        if output.exists():
            reject("refusing to overwrite existing evidence")
        if output.parent != args.manifest.absolute().parent:
            reject("evidence must be in the run output directory")
        with output.open("x", encoding="utf-8") as target:
            json.dump(record, target, indent=2, sort_keys=True)
            target.write("\n")
    except (OSError, KeyError, ValueError, json.JSONDecodeError,
            subprocess.CalledProcessError) as exc:
        parser.exit(2, "PVIA EVIDENCE REJECTED: " + str(exc) + "\n")
    print("PVIA RELEASE-GATE EVIDENCE: PASS_TEST_ONLY", str(output))


if __name__ == "__main__":
    main()
