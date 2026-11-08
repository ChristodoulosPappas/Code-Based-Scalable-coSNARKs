#!/usr/bin/env python3
"""Fail-closed provenance preflight for PVIA batching benchmark entrypoints.

This is a run-identity record, not an attestation that an existing binary was
built from the current HEAD or that a production security backend was used.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import subprocess
from pathlib import Path


SCHEMA = "pvia-run-provenance/v1"


def fail(message):
    raise SystemExit("PVIA PROVENANCE REJECTED: " + message)


def git(root, *args):
    result = subprocess.run(
        ["git", "-C", str(root), *args], text=True, capture_output=True
    )
    if result.returncode:
        fail("git " + " ".join(args) + " failed: " + result.stderr.strip())
    return result.stdout.strip()


def file_hash(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def inside(path, directory):
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--script", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-commit", default=os.getenv("PVIA_EXPECTED_COMMIT", ""))
    parser.add_argument("--expected-binary-sha256",
                        default=os.getenv("PVIA_EXPECTED_BINARY_SHA256", ""))
    parser.add_argument("--require-pins", action="store_true")
    parser.add_argument("--provider-mode", default="NOT_VERIFIED")
    parser.add_argument("--run-type", default="regression-selftest")
    args = parser.parse_args()

    root = args.root.resolve(strict=True)
    script = args.script.resolve(strict=True)
    binary = args.binary.resolve(strict=True)
    if not (root / "CMakeLists.txt").is_file() or not (root / "src" / "CMakeLists.txt").is_file():
        fail("root does not contain the PAR-coSNARK source tree")
    if git(root, "rev-parse", "--show-toplevel") != str(root):
        fail("root is not the canonical git worktree")
    if script.parent != root / "experiments" or not script.is_file():
        fail("script must be an experiment entrypoint in the selected root")
    if not inside(binary, root) or not binary.is_file():
        fail("binary must be an existing file inside the selected root")
    if not os.access(binary, os.X_OK):
        fail("binary is not executable")
    cache = binary.parent.parent / "CMakeCache.txt"
    if cache.is_file():
        matches = [line.split("=", 1)[-1].strip() for line in
                   cache.read_text(errors="replace").splitlines()
                   if line.startswith("CMAKE_HOME_DIRECTORY:INTERNAL=")]
        if len(matches) != 1 or Path(matches[0]).resolve() != root:
            fail("CMake build-tree source root does not match experiment root")

    commit = git(root, "rev-parse", "HEAD")
    digest = file_hash(binary)
    expected_commit = args.expected_commit.strip()
    expected_binary = args.expected_binary_sha256.strip().lower()
    if args.require_pins and not (expected_commit and expected_binary):
        fail("strict run requires both expected commit and binary sha256")
    if expected_commit and (not re.fullmatch("[0-9a-fA-F]{7,40}", expected_commit)
                            or not commit.startswith(expected_commit.lower())):
        fail("git commit mismatch")
    if expected_binary and (not re.fullmatch("[0-9a-f]{64}", expected_binary)
                            or expected_binary != digest):
        fail("binary sha256 mismatch")
    if args.run_type == "paper-performance" and not (
        expected_commit and expected_binary and args.require_pins
    ):
        fail("paper-performance requires --require-pins and both expected hashes")

    # No private keys, raw session identifiers, environment dump, or secret
    # witness material is read or serialized.
    tracked_dirty = bool(git(root, "status", "--porcelain", "--untracked-files=no"))
    untracked_present = bool(git(root, "ls-files", "--others", "--exclude-standard"))
    record = {
        "schema": SCHEMA,
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "repo_realpath": str(root),
        "repo_commit": commit,
        "repo_branch": git(root, "branch", "--show-current"),
        "tracked_dirty": tracked_dirty,
        "untracked_present": untracked_present,
        "binary_realpath": str(binary),
        "binary_sha256": digest,
        "binary_executable_bytes": binary.stat().st_size,
        "binary_built_from_current_head": "NOT_ATTESTED",
        "script_realpath": str(script),
        "script_sha256": file_hash(script),
        "build_root_checked": cache.is_file(),
        "expected_commit": expected_commit or "NOT_PINNED",
        "expected_binary_sha256": expected_binary or "NOT_PINNED",
        "strict_hash_pins": bool(args.require_pins),
        "provider_mode": args.provider_mode,
        "production_security_activated": "NOT_VERIFIED",
        "run_type": args.run_type,
        "claim_scope": "provenance-only; not a cryptographic security attestation",
        "host": platform.node(),
        "platform": platform.platform(),
        "mpi_model": "single-host-unless-independently-attested",
        "parameters": "NOT_RECORDED_BY_PREFLIGHT",
        "benchmark_success": "NOT_YET_RUN",
    }
    output = args.output.absolute()
    if output.exists():
        fail("manifest already exists; will not overwrite " + str(output))
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("x", encoding="utf-8") as stream:
            json.dump(record, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except FileExistsError:
        fail("manifest collision")
    print("PVIA RUN PROVENANCE: RECORDED " + str(output))
    print("commit=" + commit + " binary_sha256=" + digest)


if __name__ == "__main__":
    main()
