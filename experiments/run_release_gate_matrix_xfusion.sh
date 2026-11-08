#!/usr/bin/env bash
set -euo pipefail
export OMPI_MCA_btl=^openib
ROOT="${ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
BUILD_DIR="${BUILD_DIR:-$ROOT/build-par}"
BUILD="${BUILD:-0}"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="${OUT:-$ROOT/experiments/results/release_gate_matrix_$STAMP}"
TMP="$(mktemp -d /tmp/pvia-release-gate-matrix.XXXXXX)"
mkdir -p "$OUT"

cd "$ROOT"
case "$BUILD" in
  1) cmake --build "$BUILD_DIR" -j2 > "$OUT/build.log" 2>&1 ;;
  0) printf 'build skipped by caller\n' > "$OUT/build.log" ;;
  *) echo "BUILD must be 0 or 1" >&2; exit 2 ;;
esac

# Fail closed on wrong worktree/build artifact before starting the benchmark.
pvia_provenance=(--root "$ROOT" --script "$ROOT/experiments/run_release_gate_matrix_xfusion.sh"
  --binary "$BUILD_DIR/src/pigeon" --output "$OUT/MANIFEST.json"
  --provider-mode "reference-or-configured" --run-type regression-selftest)
if [[ "${PVIA_REQUIRE_PINNED_PROVENANCE:-0}" == "1" ]]; then
  pvia_provenance+=(--require-pins)
fi
python3 "$ROOT/experiments/pvia_run_provenance.py" "${pvia_provenance[@]}"

for r in 0 1 2 3; do
  umask 077
  openssl rand -hex 32 > "$TMP/rank_${r}.key"
done

mpirun -np 4 env \
  PVIA_ENABLE=1 \
  PVIA_SESSION_ID=532001 \
  PVIA_RELEASE_GATE_MATRIX_SELFTEST=1 \
  "PVIA_TRANSFER_PRIVATE_KEY_FILE=$TMP/rank_{rank}.key" \
  "$BUILD_DIR/src/pigeon" 2 0 > "$OUT/run.log" 2>&1

for family in cosumcheck distributed-sumcheck encoding pcs-open pcs-batch-open; do
  grep -q "\[PVIA\]\[release-gate-matrix\] family=$family .*positive=ALLOW injected=WITHHOLD exact-scope=BOUND result=PASS" "$OUT/run.log"
done
grep -q '\[PVIA\]\[release-gate-matrix-summary\] cases=5 private-localization=folding-only other-families=release-blocking-only .*result=PASS' "$OUT/run.log"

cat > "$OUT/SUMMARY.txt" <<EOF
PVIA RELEASE GATE MATRIX: PASS
np=4
cases=5
cosumcheck_positive=ALLOW
cosumcheck_injected=WITHHOLD
distributed_sumcheck_positive=ALLOW
distributed_sumcheck_injected=WITHHOLD
encoding_positive=ALLOW
encoding_injected=WITHHOLD
pcs_open_positive=ALLOW
pcs_open_injected=WITHHOLD
pcs_batch_open_positive=ALLOW
pcs_batch_open_injected=WITHHOLD
exact_scope=BOUND
private_localization=folding-only
other_families=release-blocking-only
decision_backend=test-only
claim_scope=release-gate-withholding-semantics
EOF
# Verify the raw per-family MPI trace and seal its provenance into
# a separate immutable evidence record. No security proof is implied.
python3 "$ROOT/experiments/verify_pvia_run_evidence.py" \
  --manifest "$OUT/MANIFEST.json" \
  --log "$OUT/run.log" \
  --summary "$OUT/SUMMARY.txt" \
  --out "$OUT/VERIFIED_EVIDENCE.json"
cat "$OUT/SUMMARY.txt"
echo "results=$OUT"
