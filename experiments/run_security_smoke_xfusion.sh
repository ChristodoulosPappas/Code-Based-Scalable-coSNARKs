#!/usr/bin/env bash
set -euo pipefail

ROOT="${ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
BUILD_DIR="${BUILD_DIR:-$ROOT/build-par}"
NP="${NP:-4}"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="${OUT:-$ROOT/experiments/results/security_smoke_$STAMP}"
TMP="$(mktemp -d /tmp/pvia-exp.XXXXXX)"
mkdir -p "$OUT"
chmod 700 "$TMP"
trap 'rm -rf -- "$TMP"' EXIT

if [[ "$NP" != "4" ]]; then
  echo "This smoke script is currently pinned to verified NP=4." >&2
  exit 2
fi

for r in 0 1 2 3; do
  umask 077
  openssl rand -hex 32 > "$TMP/rank_${r}.key"
done

cd "$ROOT"
cmake --build "$BUILD_DIR" -j2 | tee "$OUT/build.log"

COMMON=(mpirun -np 4 env PVIA_ENABLE=1 PVIA_SESSION_ID=424249
  PVIA_ROBUST_TERMINATION_RUNTIME_SELFTEST=1
  "PVIA_TRANSFER_PRIVATE_KEY_FILE=$TMP/rank_{rank}.key")
"${COMMON[@]}" "$BUILD_DIR/src/pigeon" 2 0 > "$OUT/runtime_unanchored.log" 2>&1
anchor="$(grep -oE 'transfer key registry commitment=[0-9a-f]{64}' \
  "$OUT/runtime_unanchored.log" | head -1 | cut -d= -f2)"
if [[ ! "$anchor" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Failed to derive registry anchor" >&2
  exit 3
fi
printf '%s\n' "$anchor" > "$OUT/registry_anchor.txt"

cert="$OUT/runtime_robust_abort.cert"
"${COMMON[@]}" "PVIA_TRANSFER_REGISTRY_ANCHOR=$anchor" \
  "PVIA_ROBUST_ABORT_CERT_OUT=$cert" \
  "$BUILD_DIR/src/pigeon" 2 0 > "$OUT/runtime_anchored.log" 2>&1

grep -q 'attached-bundle-public=BOUND' "$OUT/runtime_anchored.log"
grep -q 'attached-bundle-local-failure=UNATTRIBUTABLE' "$OUT/runtime_anchored.log"
grep -q 'attached-bundle-stale-clear=BOUND' "$OUT/runtime_anchored.log"
grep -q '\[PVIA\]\[robust-termination-runtime-selftest\] PASS' "$OUT/runtime_anchored.log"
test -s "$cert"

mpirun -np 1 "$BUILD_DIR/src/pigeon" \
  --pvia-robust-abort-judge "$cert" "$anchor" \
  > "$OUT/judge_accept.log" 2>&1
grep -q '\[PVIA\]\[robust-abort-judge\] ACCEPT' "$OUT/judge_accept.log"
if [[ "${anchor:0:1}" == "0" ]]; then
  wrong_anchor="1${anchor:1}"
else
  wrong_anchor="0${anchor:1}"
fi
set +e
mpirun -np 1 "$BUILD_DIR/src/pigeon" \
  --pvia-robust-abort-judge "$cert" "$wrong_anchor" \
  > "$OUT/judge_reject.log" 2>&1
reject_rc=$?
set -e
if [[ "$reject_rc" != "8" ]]; then
  echo "Wrong-anchor judge returned $reject_rc, expected 8" >&2
  exit 4
fi
grep -q '\[PVIA\]\[robust-abort-judge\] REJECT' "$OUT/judge_reject.log"

mpirun -np 4 env PVIA_ENABLE=1 PVIA_SESSION_ID=424242 \
  PVIA_SHAMIR_MPC_SELFTEST=1 \
  "PVIA_TRANSFER_PRIVATE_KEY_FILE=$TMP/rank_{rank}.key" \
  "PVIA_TRANSFER_REGISTRY_ANCHOR=$anchor" \
  "$BUILD_DIR/src/pigeon" 2 0 > "$OUT/shamir4_anchored.log" 2>&1
grep -q 'auth-transport=BOUND' "$OUT/shamir4_anchored.log"
grep -q 'equivocation-evidence=BOUND' "$OUT/shamir4_anchored.log"
grep -q 'robust-abort=BOUND' "$OUT/shamir4_anchored.log"
grep -q 'registration-consistency=BOUND' "$OUT/shamir4_anchored.log"
grep -q 'registration-negatives=REJECTED' "$OUT/shamir4_anchored.log"
grep -q 'result=PASS' "$OUT/shamir4_anchored.log"
cert_bytes="$(wc -c < "$cert")"
cat > "$OUT/SUMMARY.txt" <<EOF
PVIA SECURITY SMOKE: PASS
np=4
attached_bundle_public=BOUND
attached_bundle_local_failure=UNATTRIBUTABLE
attached_bundle_stale_clear=BOUND
judge_correct_anchor=ACCEPT
judge_wrong_anchor=REJECT_RC8
shamir4_anchored=PASS
certificate_bytes=$cert_bytes
registry_anchor=$anchor
EOF

cat "$OUT/SUMMARY.txt"
echo "results=$OUT"
