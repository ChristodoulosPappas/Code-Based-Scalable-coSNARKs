#!/usr/bin/env bash
set -euo pipefail
export OMPI_MCA_btl=^openib

ROOT="${ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
BUILD_DIR="${BUILD_DIR:-$ROOT/build-par}"
NP="${NP:-4}"
REPEATS="${REPEATS:-10}"
WARMUP="${WARMUP:-2}"
M_LOG="${M_LOG:-10}"
CIR="${CIR:-1}"
SUMCHECK_LOG="${SUMCHECK_LOG:-8}"
PC_LOG="${PC_LOG:-9}"
MULTREE_LOG="${MULTREE_LOG:-6}"
DEFAULT_RAYON_THREADS="$(( $(nproc) / NP ))"
if [[ "$DEFAULT_RAYON_THREADS" -lt 1 ]]; then
  DEFAULT_RAYON_THREADS=1
fi
RAYON_THREADS="${RAYON_NUM_THREADS:-$DEFAULT_RAYON_THREADS}"
OMP_THREADS="${OMP_NUM_THREADS:-1}"
# SP1 launches gnark-cli (Go); cap its scheduler independently from Rayon.
GOMAXPROCS_THREADS="${GOMAXPROCS:-$DEFAULT_RAYON_THREADS}"
[[ "$RAYON_THREADS" =~ ^[1-9][0-9]*$ ]] || {
  echo "RAYON_NUM_THREADS must be a positive integer" >&2
  exit 2
}
[[ "$OMP_THREADS" =~ ^[1-9][0-9]*$ ]] || {
  echo "OMP_NUM_THREADS must be a positive integer" >&2
  exit 2
}
[[ "$GOMAXPROCS_THREADS" =~ ^[1-9][0-9]*$ ]] || {
  echo "GOMAXPROCS must be a positive integer" >&2
  exit 2
}
export RAYON_NUM_THREADS="$RAYON_THREADS"
export OMP_NUM_THREADS="$OMP_THREADS"
export GOMAXPROCS="$GOMAXPROCS_THREADS"
BUILD="${BUILD:-1}"
RESUME="${RESUME:-0}"
PREPROCESS_POOL_DIR="${PREPROCESS_POOL_DIR:-}"
PREPROCESS_POOL_START_SLOT="${PREPROCESS_POOL_START_SLOT:-0}"
VALIDITY_RELATION_CACHE_FILE="${VALIDITY_RELATION_CACHE_FILE:-}"
SP1_ENABLED="${PVIA_SP1_ENABLED:-0}"
RS_MUL_SYNDROME="${PVIA_RS_MUL_SYNDROME:-0}"
case "$RS_MUL_SYNDROME" in 0|1) ;; *) echo "PVIA_RS_MUL_SYNDROME must be 0 or 1" >&2; exit 2 ;; esac
if [[ "$SP1_ENABLED" == "1" && "$RS_MUL_SYNDROME" == "1" ]]; then
  echo "RS syndrome mode is an alternative to SP1; choose one" >&2
  exit 2
fi
MC_PROVIDER_LIBRARY="${PVIA_MC_PROVIDER_LIBRARY:-}"
MC_PROVIDER_PROOF_SYSTEM_ID="${PVIA_MC_PROVIDER_PROOF_SYSTEM_ID:-}"
MC_STAGE_TRACE="${PVIA_SP1_MC_STAGE_TRACE:-0}"
case "$SP1_ENABLED" in
  0) MC_PROVIDER_LIBRARY=""; MC_PROVIDER_PROOF_SYSTEM_ID="" ;;
  1)
    [[ -n "$MC_PROVIDER_LIBRARY" && -n "$MC_PROVIDER_PROOF_SYSTEM_ID" ]] || {
      echo "PVIA_SP1_ENABLED=1 requires library and proof system id" >&2; exit 2;
    } ;;
  *) echo "PVIA_SP1_ENABLED must be 0 or 1" >&2; exit 2 ;;
esac
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="${OUT:-$ROOT/experiments/results/copiop_overhead_$STAMP}"
TMP="$(mktemp -d /tmp/pvia-copiop.XXXXXX)"
mkdir -p "$OUT"; chmod 700 "$TMP"
trap 'rm -rf -- "$TMP"' EXIT
if [[ -n "$PREPROCESS_POOL_DIR" ]]; then
  [[ -d "$PREPROCESS_POOL_DIR" ]] || {
    echo "PREPROCESS_POOL_DIR does not exist: $PREPROCESS_POOL_DIR" >&2
    exit 2
  }
  [[ "$PREPROCESS_POOL_START_SLOT" =~ ^[0-9]+$ ]] || {
    echo "PREPROCESS_POOL_START_SLOT must be a non-negative integer" >&2
    exit 2
  }
  printf 'preprocess_pool_enabled=1
preprocess_pool_dir=%s
preprocess_pool_start_slot=%s
'     "$PREPROCESS_POOL_DIR" "$PREPROCESS_POOL_START_SLOT"     > "$OUT/preprocessing_pool.txt"
else
  printf 'preprocess_pool_enabled=0
' > "$OUT/preprocessing_pool.txt"
fi

if [[ -n "$VALIDITY_RELATION_CACHE_FILE" ]]; then
  [[ -f "$VALIDITY_RELATION_CACHE_FILE" ]] || {
    echo "VALIDITY_RELATION_CACHE_FILE does not exist: $VALIDITY_RELATION_CACHE_FILE" >&2
    exit 2
  }
  relation_cache_sha="$(sha256sum "$VALIDITY_RELATION_CACHE_FILE" | awk '{print $1}')"
  printf 'validity_relation_cache_enabled=1
validity_relation_cache_file=%s
validity_relation_cache_sha256=%s
' "$VALIDITY_RELATION_CACHE_FILE" "$relation_cache_sha"     > "$OUT/validity_relation_cache.txt"
else
  printf 'validity_relation_cache_enabled=0
' > "$OUT/validity_relation_cache.txt"
fi

if [[ "$NP" != "4" && "$NP" != "8" && "$NP" != "16" &&
      "$NP" != "32" && "$NP" != "64" && "$NP" != "128" ]]; then
  echo "coPIOP overhead runner allows NP=4,8,16,32,64,128" >&2
  exit 2
fi
# N=64 uses logical CPU slots; N=128 additionally oversubscribes 16 ranks.
MPI_ARGS=()
if (( NP > 56 )); then
  MPI_ARGS+=(--use-hwthread-cpus)
fi
if (( NP > 112 )); then
  MPI_ARGS+=(--oversubscribe)
fi
for ((r=0;r<NP;r++)); do
  umask 077
  openssl rand -hex 32 > "$TMP/rank_${r}.key"
done
cd "$ROOT"
case "$BUILD" in
  1) cmake --build "$BUILD_DIR" -j2 > "$OUT/build.log" 2>&1 ;;
  0) printf 'build skipped by caller; preflight build already completed\n' > "$OUT/build.log" ;;
  *) echo "BUILD must be 0 or 1" >&2; exit 2 ;;
esac

# Make the configured multiplication-consistency provider explicit in each
# enabled MPI run and preserve its identity beside the benchmark provenance.
[[ "$MC_STAGE_TRACE" == "0" || "$MC_STAGE_TRACE" == "1" ]] || {
  echo "PVIA_SP1_MC_STAGE_TRACE must be 0 or 1" >&2
  exit 2
}
PROVIDER_MODE="reference-fast-passive-bgw"
if [[ -n "$MC_PROVIDER_LIBRARY" || -n "$MC_PROVIDER_PROOF_SYSTEM_ID" ]]; then
  [[ -n "$MC_PROVIDER_LIBRARY" && -n "$MC_PROVIDER_PROOF_SYSTEM_ID" ]] || {
    echo "PVIA_MC_PROVIDER_LIBRARY and PVIA_MC_PROVIDER_PROOF_SYSTEM_ID must be set together" >&2
    exit 2
  }
  [[ -r "$MC_PROVIDER_LIBRARY" ]] || {
    echo "multiplication-consistency provider is not readable: $MC_PROVIDER_LIBRARY" >&2
    exit 2
  }
  [[ "$MC_PROVIDER_PROOF_SYSTEM_ID" =~ ^[0-9]+$ ]] || {
    echo "PVIA_MC_PROVIDER_PROOF_SYSTEM_ID must be a positive integer" >&2
    exit 2
  }
  PROVIDER_MODE="sp1-groth16-multiplication-consistency-candidate"
  provider_sha256="$(sha256sum "$MC_PROVIDER_LIBRARY" | awk '{print $1}')"
  python3 - "$OUT/PROVIDER_MANIFEST.json" "$MC_PROVIDER_LIBRARY" \
    "$MC_PROVIDER_PROOF_SYSTEM_ID" "$provider_sha256" "$MC_STAGE_TRACE" <<'PY'
import json,os,sys
path,library,proof_system_id,digest,stage_trace=sys.argv[1:]
record={
  "schema":"pvia-multiplication-consistency-provider-run/v1",
  "provider_library":library,
  "provider_library_sha256":digest,
  "proof_system_id":int(proof_system_id),
  "provider_mode":"candidate",
  "stage_trace_enabled":stage_trace=="1",
  "gomaxprocs":int(os.environ.get("GOMAXPROCS","0")),
  "runtime_acceptance_required":True,
  "authenticated_transport_expected":True,
  "runtime_acceptance_fields":[
    "enabled_consistency_provider_active",
    "enabled_initial_validity_strong_active",
    "authenticated_transport"
  ],
  "claim_scope":"provider identity and run configuration only; not a security attestation"
}
with open(path,"x",encoding="utf-8") as f:
    json.dump(record,f,indent=2,sort_keys=True)
    f.write("\n")
print("PVIA_PROVIDER_MANIFEST: RECORDED "+path)
PY
fi

# Preserve the effective benchmark environment, including prover parallelism.
{
  echo "schema=pvia-copiop-run-environment/v1"
  echo "world_size=$NP"
  echo "M_LOG=$M_LOG"
  echo "CIR=$CIR"
  echo "SUMCHECK_LOG=$SUMCHECK_LOG"
  echo "PC_LOG=$PC_LOG"
  echo "MULTREE_LOG=$MULTREE_LOG"
  echo "repeats=$REPEATS"
  echo "warmup=$WARMUP"
  echo "RAYON_NUM_THREADS=$RAYON_THREADS"
  echo "OMP_NUM_THREADS=$OMP_THREADS"
  echo "GOMAXPROCS=$GOMAXPROCS_THREADS"
  echo "PVIA_RUN_TYPE=${PVIA_RUN_TYPE:-regression-selftest}"
  echo "PVIA_SP1_MC_STAGE_TRACE=$MC_STAGE_TRACE"
  echo "PVIA_SP1_ENABLED=$SP1_ENABLED"
  echo "PVIA_RS_MUL_SYNDROME=$RS_MUL_SYNDROME"
  echo "rs_product_syndrome_conditional_malicious_consistency=$RS_MUL_SYNDROME"
  echo "provider_mode=$PROVIDER_MODE"
  echo "claim_scope=$([[ "$SP1_ENABLED" == "0" ]] && echo passive-reference-not-malicious-multiplication-consistency || echo sp1-candidate)"
  echo "provider_library=$MC_PROVIDER_LIBRARY"
  echo "provider_proof_system_id=${MC_PROVIDER_PROOF_SYSTEM_ID:-NOT_CONFIGURED}"
  echo "provider_library_sha256=${provider_sha256:-NOT_CONFIGURED}"
  echo "git_commit=$(git rev-parse HEAD)"
  echo "binary_sha256=$(sha256sum "$BUILD_DIR/src/pigeon" | awk '{print $1}')"
} > "$OUT/RUN_ENV.txt"

# Bind each nested paper run to its actual executable and source worktree.
pvia_provenance=(--root "$ROOT" --script "$ROOT/experiments/run_copiop_overhead_xfusion.sh"
  --binary "$BUILD_DIR/src/pigeon" --output "$OUT/MANIFEST.json"
  --provider-mode "$PROVIDER_MODE"
  --run-type "${PVIA_RUN_TYPE:-regression-selftest}")
if [[ "${PVIA_REQUIRE_PINNED_PROVENANCE:-0}" == "1" ]]; then
  pvia_provenance+=(--require-pins)
fi
python3 "$ROOT/experiments/pvia_run_provenance.py" "${pvia_provenance[@]}"
ANCHOR_PROBE="$OUT/anchor_probe.log"
mpirun "${MPI_ARGS[@]}" -np "$NP" -x RAYON_NUM_THREADS -x OMP_NUM_THREADS -x GOMAXPROCS env \
  -u PVIA_MC_PROVIDER_LIBRARY \
  -u PVIA_MC_PROVIDER_PROOF_SYSTEM_ID \
  PVIA_ENABLE=1 PVIA_SESSION_ID=426000 \
  "PVIA_TRANSFER_PRIVATE_KEY_FILE=$TMP/rank_{rank}.key" \
  "$BUILD_DIR/src/pigeon" 2 0 > "$ANCHOR_PROBE" 2>&1
anchor="$(grep -oE 'transfer key registry commitment=[0-9a-f]{64}' \
  "$ANCHOR_PROBE" | head -1 | cut -d= -f2)"
[[ "$anchor" =~ ^[0-9a-f]{64}$ ]] || exit 3
printf '%s\n' "$anchor" > "$OUT/registry_anchor.txt"

RAW="$OUT/raw_runs.csv"
if [[ "$RESUME" != "1" || ! -s "$RAW" ]]; then
python3 - "$RAW" <<'PY'
import csv,sys
fields=['scenario','iteration','label','session_id','world_size','rank_rows',
       'mean_program_total_ns','max_program_total_ns',
       'mean_peak_rss_kb','max_peak_rss_kb',
       'rank0_pt_s','rank0_cpu_pt_s',
       'rank0_comp_s','verifier_total_s','proof_kb','reported_comm_mb',
       'interaction_rounds','sum_auth_sent_bytes','sum_auth_recv_bytes',
       'sum_auth_baseline_payload_sent_bytes','sum_auth_baseline_payload_recv_bytes',
       'sum_auth_pvia_payload_sent_bytes','sum_auth_pvia_payload_recv_bytes',
       'sum_auth_overhead_sent_bytes','sum_auth_overhead_recv_bytes',
       'sum_baseline_input_payload_sent_bytes','sum_baseline_input_payload_recv_bytes',
       'sum_auth_collective_calls',
       'sum_control_sent_bytes','sum_control_recv_bytes',
       'mean_rank_control_sent_bytes','max_rank_control_sent_bytes',
       'sum_control_sent_messages','sum_control_recv_messages',
       'control_collective_calls_per_rank','control_sent_recv_bytes_match',
       'control_sent_recv_messages_match',
       'sum_runtime_init_control_sent_bytes','sum_runtime_init_control_recv_bytes',
       'runtime_init_control_collective_calls_per_rank',
       'sum_preprocessing_control_sent_bytes','sum_preprocessing_control_recv_bytes',
       'mean_rank_preprocessing_control_sent_bytes','max_rank_preprocessing_control_sent_bytes',
       'preprocessing_control_collective_calls_per_rank',
       'sum_initial_validity_control_sent_bytes','sum_initial_validity_control_recv_bytes',
       'mean_rank_initial_validity_control_sent_bytes','max_rank_initial_validity_control_sent_bytes',
       'initial_validity_control_collective_calls_per_rank',
       'sum_initial_validity_runs','sum_initial_validity_strong_runs',
       'consistency_provider_present','consistency_provider_production_ready',
       'consistency_provider_acceptance_present','consistency_provider_protocol_id',
       'sum_consistency_provider_control_sent_bytes',
       'sum_consistency_provider_control_recv_bytes',
       'consistency_provider_control_collective_calls_per_rank',
       'unclassified_control_sent_bytes','unclassified_control_recv_bytes',
       'unclassified_control_collective_calls','control_scope_partition_complete',
       'sum_transfer_meta_recv_bytes','sum_transfer_meta_recv_messages',
       'sum_transfer_meta_seal_calls','sum_transfer_meta_observe_calls',
       'sum_transfer_meta_verify_calls',
       'sum_public_direct_validation_control_sent_bytes',
       'sum_public_direct_validation_control_recv_bytes',
       'mean_rank_public_direct_validation_control_sent_bytes',
       'max_rank_public_direct_validation_control_sent_bytes',
       'public_direct_validation_control_collective_calls_per_rank',
       'max_transfer_meta_seal_ns',
       'max_transfer_meta_observe_ns','max_transfer_meta_verify_ns',
       'max_runtime_init_ns','max_preprocessing_ns','max_initial_validity_ns',
       'max_public_direct_validation_ns','max_consistency_provider_ns',
       'sent_recv_bytes_match','sent_recv_messages_match']
with open(sys.argv[1],'w',newline='') as f:
    csv.DictWriter(f,fieldnames=fields).writeheader()
PY
fi

append_case() {
  local scenario="$1" iteration="$2" aggregate="$3" log="$4"
  python3 - "$RAW" "$scenario" "$iteration" "$aggregate" "$log" <<'PY'
import csv,re,sys
raw,scenario,iteration,aggregate,log=sys.argv[1:]
with open(aggregate,newline='') as f: m=next(csv.DictReader(f))
txt=open(log,errors='replace').read()
rank0=re.search(r'Id\s*:\s*0, Pt:\s*([0-9.]+), CPU Only Pt:\s*([0-9.]+), Computation only:\s*([0-9.]+), Vt:\s*([0-9.]+)',txt)
ver=re.search(r'Vt\s*:\s*([0-9.]+) sec, Ps:\s*([0-9.]+) KB, Com:\s*([0-9.]+) MB',txt)
rounds=re.search(r'Interaction Rounds:\s*(\d+)',txt)
if not rank0 or not ver or not rounds or 'Error' in txt:
    raise SystemExit('failed to parse successful coPIOP run')
out={
 'scenario':scenario,'iteration':iteration,'label':m['label'],
 'session_id':m['session_id'],'world_size':m['world_size'],'rank_rows':m['rank_rows'],
 'mean_program_total_ns':m['mean_program_total_ns'],
 'max_program_total_ns':m['max_program_total_ns'],
 'mean_peak_rss_kb':m['mean_peak_rss_kb'],
 'max_peak_rss_kb':m['max_peak_rss_kb'],
 'rank0_pt_s':rank0.group(1),'rank0_cpu_pt_s':rank0.group(2),
 'rank0_comp_s':rank0.group(3),'verifier_total_s':ver.group(1),
 'proof_kb':ver.group(2),'reported_comm_mb':ver.group(3),
 'interaction_rounds':rounds.group(1),'sum_auth_sent_bytes':m['sum_auth_sent_bytes'],
 'sum_auth_recv_bytes':m['sum_auth_recv_bytes'],
 'sum_auth_baseline_payload_sent_bytes':m.get('sum_auth_baseline_payload_sent_bytes','0'),
 'sum_auth_baseline_payload_recv_bytes':m.get('sum_auth_baseline_payload_recv_bytes','0'),
 'sum_auth_pvia_payload_sent_bytes':m.get('sum_auth_pvia_payload_sent_bytes','0'),
 'sum_auth_pvia_payload_recv_bytes':m.get('sum_auth_pvia_payload_recv_bytes','0'),
 'sum_auth_overhead_sent_bytes':m.get('sum_auth_overhead_sent_bytes','0'),
 'sum_auth_overhead_recv_bytes':m.get('sum_auth_overhead_recv_bytes','0'),
 'sum_baseline_input_payload_sent_bytes':m.get('sum_baseline_input_payload_sent_bytes','0'),
 'sum_baseline_input_payload_recv_bytes':m.get('sum_baseline_input_payload_recv_bytes','0'),
 'sum_auth_collective_calls':m['sum_auth_collective_calls'],
 'sum_control_sent_bytes':m['sum_control_sent_bytes'],
 'sum_control_recv_bytes':m['sum_control_recv_bytes'],
 'mean_rank_control_sent_bytes':m['mean_rank_control_sent_bytes'],
 'max_rank_control_sent_bytes':m['max_rank_control_sent_bytes'],
 'sum_control_sent_messages':m['sum_control_sent_messages'],
 'sum_control_recv_messages':m['sum_control_recv_messages'],
 'control_collective_calls_per_rank':m['control_collective_calls_per_rank'],
 'control_sent_recv_bytes_match':m['control_sent_recv_bytes_match'],
 'control_sent_recv_messages_match':m['control_sent_recv_messages_match'],
 'sum_runtime_init_control_sent_bytes':m['sum_runtime_init_control_sent_bytes'],
 'sum_runtime_init_control_recv_bytes':m['sum_runtime_init_control_recv_bytes'],
 'runtime_init_control_collective_calls_per_rank':m['runtime_init_control_collective_calls_per_rank'],
 'sum_preprocessing_control_sent_bytes':m['sum_preprocessing_control_sent_bytes'],
 'sum_preprocessing_control_recv_bytes':m['sum_preprocessing_control_recv_bytes'],
 'mean_rank_preprocessing_control_sent_bytes':m['mean_rank_preprocessing_control_sent_bytes'],
 'max_rank_preprocessing_control_sent_bytes':m['max_rank_preprocessing_control_sent_bytes'],
 'preprocessing_control_collective_calls_per_rank':m['preprocessing_control_collective_calls_per_rank'],
 'sum_initial_validity_control_sent_bytes':m['sum_initial_validity_control_sent_bytes'],
 'sum_initial_validity_control_recv_bytes':m['sum_initial_validity_control_recv_bytes'],
 'mean_rank_initial_validity_control_sent_bytes':m['mean_rank_initial_validity_control_sent_bytes'],
 'max_rank_initial_validity_control_sent_bytes':m['max_rank_initial_validity_control_sent_bytes'],
 'initial_validity_control_collective_calls_per_rank':m['initial_validity_control_collective_calls_per_rank'],
 'sum_initial_validity_runs':m['sum_initial_validity_runs'],
 'sum_initial_validity_strong_runs':m['sum_initial_validity_strong_runs'],
 'consistency_provider_present':m['consistency_provider_present'],
 'consistency_provider_production_ready':m['consistency_provider_production_ready'],
 'consistency_provider_acceptance_present':m['consistency_provider_acceptance_present'],
 'consistency_provider_protocol_id':m['consistency_provider_protocol_id'],
 'sum_consistency_provider_control_sent_bytes':m['sum_consistency_provider_control_sent_bytes'],
 'sum_consistency_provider_control_recv_bytes':m['sum_consistency_provider_control_recv_bytes'],
 'consistency_provider_control_collective_calls_per_rank':m['consistency_provider_control_collective_calls_per_rank'],
 'unclassified_control_sent_bytes':m['unclassified_control_sent_bytes'],
 'unclassified_control_recv_bytes':m['unclassified_control_recv_bytes'],
 'unclassified_control_collective_calls':m['unclassified_control_collective_calls'],
 'control_scope_partition_complete':m['control_scope_partition_complete'],
 'sum_transfer_meta_recv_bytes':m['sum_transfer_meta_recv_bytes'],
 'sum_transfer_meta_recv_messages':m['sum_transfer_meta_recv_messages'],
 'sum_transfer_meta_seal_calls':m['sum_transfer_meta_seal_calls'],
 'sum_transfer_meta_observe_calls':m['sum_transfer_meta_observe_calls'],
 'sum_transfer_meta_verify_calls':m['sum_transfer_meta_verify_calls'],
 'sum_public_direct_validation_control_sent_bytes':m['sum_public_direct_validation_control_sent_bytes'],
 'sum_public_direct_validation_control_recv_bytes':m['sum_public_direct_validation_control_recv_bytes'],
 'mean_rank_public_direct_validation_control_sent_bytes':m['mean_rank_public_direct_validation_control_sent_bytes'],
 'max_rank_public_direct_validation_control_sent_bytes':m['max_rank_public_direct_validation_control_sent_bytes'],
 'public_direct_validation_control_collective_calls_per_rank':m['public_direct_validation_control_collective_calls_per_rank'],
 'max_transfer_meta_seal_ns':m['max_transfer_meta_seal_ns'],
 'max_transfer_meta_observe_ns':m['max_transfer_meta_observe_ns'],
 'max_transfer_meta_verify_ns':m['max_transfer_meta_verify_ns'],
 'max_runtime_init_ns':m['max_runtime_init_ns'],
 'max_preprocessing_ns':m['max_preprocessing_ns'],
 'max_initial_validity_ns':m['max_initial_validity_ns'],
 'max_public_direct_validation_ns':m['max_public_direct_validation_ns'],
 'max_consistency_provider_ns':m['max_consistency_provider_ns'],
 'sent_recv_bytes_match':m['sent_recv_bytes_match'],
 'sent_recv_messages_match':m['sent_recv_messages_match']}
with open(raw,newline='') as f:
    reader=csv.DictReader(f)
    fields=reader.fieldnames
    existing=list(reader)
existing=[
    r for r in existing
    if not (r.get('scenario')==scenario and r.get('iteration')==iteration)]
with open(raw,'w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=fields)
    w.writeheader()
    w.writerows(existing)
    w.writerow(out)
PY
}

run_case() {
  local scenario="$1" tag="$2" session="$3" save="$4"
  local pool_slot="${5:-}"
  local dir="$OUT/${scenario}_${tag}"; mkdir -p "$dir/metrics"
  local envs=(PVIA_EXPERIMENT_METRICS=1 "PVIA_EXPERIMENT_LABEL=$scenario"
    "PVIA_EXPERIMENT_METRICS_DIR=$dir/metrics" "PVIA_SESSION_ID=$session"
    "PVIA_SP1_ENABLED=$SP1_ENABLED"
    "PVIA_RS_MUL_SYNDROME=$RS_MUL_SYNDROME")
  if [[ "$scenario" == "disabled" ]]; then
    envs+=(PVIA_ENABLE=0)
  else
    envs+=(PVIA_ENABLE=1
      "PVIA_TRANSFER_PRIVATE_KEY_FILE=$TMP/rank_{rank}.key"
      "PVIA_TRANSFER_REGISTRY_ANCHOR=$anchor")
    if [[ "$SP1_ENABLED" == "0" ]]; then
      envs+=(PVIA_DISABLE_DIRECT_ZERO_OPEN=1)
    fi
    if [[ -n "$MC_PROVIDER_LIBRARY" ]]; then
      envs+=(
        "PVIA_MC_PROVIDER_LIBRARY=$MC_PROVIDER_LIBRARY"
        "PVIA_MC_PROVIDER_PROOF_SYSTEM_ID=$MC_PROVIDER_PROOF_SYSTEM_ID")
      if [[ "$MC_STAGE_TRACE" == "1" ]]; then
        envs+=(PVIA_SP1_MC_STAGE_TRACE=1)
      fi
    fi
    if [[ -n "$PREPROCESS_POOL_DIR" ]]; then
      [[ "$pool_slot" =~ ^[0-9]+$ ]] || {
        echo "missing preprocessing pool slot for enabled case $tag" >&2
        return 2
      }
      envs+=(
        PVIA_PREPROCESS_POOL_CONSUME=1
        "PVIA_PREPROCESS_POOL_DIR=$PREPROCESS_POOL_DIR"
        "PVIA_PREPROCESS_POOL_SLOT=$pool_slot")
    fi
    if [[ -n "$VALIDITY_RELATION_CACHE_FILE" ]]; then
      envs+=(
        "PVIA_VALIDITY_RELATION_CACHE_FILE=$VALIDITY_RELATION_CACHE_FILE")
    fi
  fi
  local metric_count
  metric_count="$(find "$dir/metrics" -maxdepth 1 -type f     -name 'pvia_metrics_rank_*.csv' | wc -l)"
  local reusable=0
  if [[ "$RESUME" == "1" && -f "$dir/run.log" &&
        "$metric_count" -eq "$NP" ]] &&
     grep -q 'Interaction Rounds:' "$dir/run.log"; then
    if [[ "$scenario" != "enabled" ]] ||
       grep -q 'anchored=yes' "$dir/run.log"; then
      reusable=1
    fi
  fi

  if [[ "$reusable" == "0" ]]; then
    if [[ "$scenario" == "disabled" ]]; then
      mpirun "${MPI_ARGS[@]}" -np "$NP" -x RAYON_NUM_THREADS -x OMP_NUM_THREADS -x GOMAXPROCS env \
        -u PVIA_MC_PROVIDER_LIBRARY \
        -u PVIA_MC_PROVIDER_PROOF_SYSTEM_ID \
        "${envs[@]}" \
        "$BUILD_DIR/src/pigeon" \
        0 "$M_LOG" "$CIR" "$SUMCHECK_LOG" "$PC_LOG" "$MULTREE_LOG" \
        > "$dir/run.log" 2>&1
    else
      mpirun "${MPI_ARGS[@]}" -np "$NP" -x RAYON_NUM_THREADS -x OMP_NUM_THREADS -x GOMAXPROCS env \
        -u PVIA_MC_PROVIDER_LIBRARY -u PVIA_MC_PROVIDER_PROOF_SYSTEM_ID "${envs[@]}" \
        "$BUILD_DIR/src/pigeon" \
        0 "$M_LOG" "$CIR" "$SUMCHECK_LOG" "$PC_LOG" "$MULTREE_LOG" \
        > "$dir/run.log" 2>&1
    fi
  else
    printf 'reused completed case: %s_%s
' "$scenario" "$tag"       >> "$OUT/resume.log"
  fi

  grep -q 'Interaction Rounds:' "$dir/run.log"
  if [[ "$scenario" == "enabled" ]]; then
    grep -q 'anchored=yes' "$dir/run.log"
    if [[ "$SP1_ENABLED" == "0" ]]; then
      if [[ "$RS_MUL_SYNDROME" == "1" ]]; then
        grep -Fq '[PVIA][zero-test] mode=rs-syndrome-bgw' "$dir/run.log" || {
          echo "RS checked BGW masked opening missing" >&2; return 23;
        }
        grep -Eq '\[PVIA\]\[rs-product-syndrome\].*result=PASS' "$dir/run.log" || {
          echo "RS product parity PASS missing" >&2; return 24;
        }
      else
        grep -Fq '[PVIA][zero-test] mode=passive-bgw' "$dir/run.log" || {
          echo "passive BGW single-masked opening not observed" >&2; return 23;
        }
      fi
      ! grep -Fq '[PVIA][consistency-provider] active protocol_id=' "$dir/run.log" || {
        echo "SP1 unexpectedly active" >&2; return 24;
      }
    fi
  fi
  python3 experiments/aggregate_pvia_metrics.py "$dir/metrics" \
    --output "$dir/aggregate.csv" > "$dir/aggregate.log"
  if [[ "$save" == "1" ]]; then
    append_case "$scenario" "$tag" "$dir/aggregate.csv" "$dir/run.log"
  fi
}

for ((i=1;i<=WARMUP;i++)); do
  pool_slot=$((PREPROCESS_POOL_START_SLOT + i - 1))
  run_case disabled "warmup_$i" $((426100+i)) 0 ""
  run_case enabled "warmup_$i" $((426200+i)) 0 "$pool_slot"
done

for ((i=1;i<=REPEATS;i++)); do
  pool_slot=$((PREPROCESS_POOL_START_SLOT + WARMUP + i - 1))
  if (( i % 2 == 1 )); then
    run_case disabled "$i" $((426300+i)) 1 ""
    run_case enabled "$i" $((426400+i)) 1 "$pool_slot"
  else
    run_case enabled "$i" $((426400+i)) 1 "$pool_slot"
    run_case disabled "$i" $((426300+i)) 1 ""
  fi
done

python3 experiments/summarize_repeated_metrics.py \
  "$RAW" "$OUT/summary_stats.csv" > "$OUT/summary.log"
python3 experiments/summarize_paired_overhead.py \
  "$RAW" "$OUT/paired_runs.csv" "$OUT/paired_summary.csv" > "$OUT/paired.log"
python3 - "$OUT/summary_stats.csv" "$OUT/paired_summary.csv" "$OUT/SUMMARY.txt" "$REPEATS" "$WARMUP" "$RAW" <<'PY'
import csv,sys
summary,paired_summary,out,repeats,warmup,raw_path=sys.argv[1:]
with open(summary,newline='') as f: rows=list(csv.DictReader(f))
with open(paired_summary,newline='') as f: paired_rows=list(csv.DictReader(f))
def pstat(metric,key='mean'):
    for r in paired_rows:
        if r['metric']==metric: return float(r[key])
    raise KeyError((metric,key))
def mean(sc,metric):
    for r in rows:
        if r['scenario']==sc and r['metric']==metric:
            return float(r['mean'])
    raise KeyError((sc,metric))
d_total=mean('disabled','max_program_total_ns')
e_total=mean('enabled','max_program_total_ns')
d_peak=mean('disabled','max_peak_rss_kb')
e_peak=mean('enabled','max_peak_rss_kb')
d_pt=mean('disabled','rank0_pt_s'); e_pt=mean('enabled','rank0_pt_s')
d_comm=mean('disabled','reported_comm_mb'); e_comm=mean('enabled','reported_comm_mb')
d_meta=mean('disabled','sum_transfer_meta_recv_bytes')
e_meta=mean('enabled','sum_transfer_meta_recv_bytes')
e_meta_msgs=mean('enabled','sum_transfer_meta_recv_messages')
e_auth_sent=mean('enabled','sum_auth_sent_bytes')
e_auth_recv=mean('enabled','sum_auth_recv_bytes')
e_auth_baseline_payload_sent=mean('enabled','sum_auth_baseline_payload_sent_bytes')
e_auth_baseline_payload_recv=mean('enabled','sum_auth_baseline_payload_recv_bytes')
e_auth_pvia_payload_sent=mean('enabled','sum_auth_pvia_payload_sent_bytes')
e_auth_pvia_payload_recv=mean('enabled','sum_auth_pvia_payload_recv_bytes')
e_auth_overhead_sent=mean('enabled','sum_auth_overhead_sent_bytes')
e_auth_overhead_recv=mean('enabled','sum_auth_overhead_recv_bytes')
d_baseline_input=mean('disabled','sum_baseline_input_payload_sent_bytes')
e_baseline_input=mean('enabled','sum_baseline_input_payload_sent_bytes')
e_auth_collectives=mean('enabled','sum_auth_collective_calls')
e_auth_bytes_match=mean('enabled','sent_recv_bytes_match')
e_control_sent=mean('enabled','sum_control_sent_bytes')
e_control_recv=mean('enabled','sum_control_recv_bytes')
e_control_sent_msgs=mean('enabled','sum_control_sent_messages')
e_control_recv_msgs=mean('enabled','sum_control_recv_messages')
e_control_collectives=mean('enabled','control_collective_calls_per_rank')
e_control_bytes_match=mean('enabled','control_sent_recv_bytes_match')
e_control_messages_match=mean('enabled','control_sent_recv_messages_match')
e_runtime_init_control=mean('enabled','sum_runtime_init_control_sent_bytes')
e_preprocessing_control=mean('enabled','sum_preprocessing_control_sent_bytes')
e_validity_control=mean('enabled','sum_initial_validity_control_sent_bytes')
e_provider_control=mean('enabled','sum_consistency_provider_control_sent_bytes')
e_public_direct_control=mean('enabled','sum_public_direct_validation_control_sent_bytes')
e_control_sent_per_rank=mean('enabled','mean_rank_control_sent_bytes')
e_control_sent_max_rank=mean('enabled','max_rank_control_sent_bytes')
e_preprocessing_control_per_rank=mean('enabled','mean_rank_preprocessing_control_sent_bytes')
e_preprocessing_control_max_rank=mean('enabled','max_rank_preprocessing_control_sent_bytes')
e_validity_control_per_rank=mean('enabled','mean_rank_initial_validity_control_sent_bytes')
e_validity_control_max_rank=mean('enabled','max_rank_initial_validity_control_sent_bytes')
e_public_direct_control_per_rank=mean('enabled','mean_rank_public_direct_validation_control_sent_bytes')
e_public_direct_control_max_rank=mean('enabled','max_rank_public_direct_validation_control_sent_bytes')
e_runtime_init_collectives=mean('enabled','runtime_init_control_collective_calls_per_rank')
e_preprocessing_collectives=mean('enabled','preprocessing_control_collective_calls_per_rank')
e_validity_collectives=mean('enabled','initial_validity_control_collective_calls_per_rank')
e_provider_control_collectives=mean('enabled','consistency_provider_control_collective_calls_per_rank')
e_validity_runs=mean('enabled','sum_initial_validity_runs')
e_validity_strong_runs=mean('enabled','sum_initial_validity_strong_runs')
e_validity_strong_active=(
    1 if e_validity_runs > 0 and abs(e_validity_strong_runs-e_validity_runs) < 0.5
    else 0)
e_provider_present=mean('enabled','consistency_provider_present')
e_provider_ready=mean('enabled','consistency_provider_production_ready')
e_provider_acceptance=mean('enabled','consistency_provider_acceptance_present')
with open(raw_path,newline='') as raw_file:
    raw_rows=list(csv.DictReader(raw_file))
provider_protocol_ids = {
    int(row['consistency_provider_protocol_id'])
    for row in raw_rows if row['scenario'] == 'enabled'
}
if len(provider_protocol_ids) > 1:
    raise SystemExit(
        f'inconsistent provider protocol ids across enabled runs: {sorted(provider_protocol_ids)}')
e_provider_protocol_id = next(iter(provider_protocol_ids), 0)
e_provider_active=(
    1 if e_provider_present > 0.5 and e_provider_ready > 0.5 and
    e_provider_acceptance > 0.5 and e_provider_protocol_id > 0.5 else 0)
e_public_direct_collectives=mean('enabled','public_direct_validation_control_collective_calls_per_rank')
e_unclassified_control=mean('enabled','unclassified_control_sent_bytes')
e_scope_partition_complete=mean('enabled','control_scope_partition_complete')
e_seal_calls=mean('enabled','sum_transfer_meta_seal_calls')
e_seal_ns=mean('enabled','max_transfer_meta_seal_ns')
e_observe_ns=mean('enabled','max_transfer_meta_observe_ns')
e_verify_ns=mean('enabled','max_transfer_meta_verify_ns')
def overhead(a,b): return (b/a-1.0)*100.0 if a else 0.0
lines=[
 'PVIA coPIOP OVERHEAD: PASS', f'repeats={repeats}', f'warmup={warmup}',
 f'disabled_program_total_mean_ms={d_total/1e6:.6f}',
 f'enabled_program_total_mean_ms={e_total/1e6:.6f}',
 f'program_total_overhead_pct={overhead(d_total,e_total):.3f}',
 f'disabled_peak_rss_max_mean_mib={d_peak/1024.0:.6f}',
 f'enabled_peak_rss_max_mean_mib={e_peak/1024.0:.6f}',
 f'peak_rss_overhead_pct={overhead(d_peak,e_peak):.3f}',
 f'disabled_rank0_pt_mean_s={d_pt:.6f}', f'enabled_rank0_pt_mean_s={e_pt:.6f}',
 f'rank0_pt_overhead_pct={overhead(d_pt,e_pt):.3f}',
 f'disabled_reported_comm_mean_mb={d_comm:.6f}',
 f'enabled_reported_comm_mean_mb={e_comm:.6f}',
 f'reported_comm_overhead_pct={overhead(d_comm,e_comm):.3f}',
 f'disabled_pvia_metadata_recv_mean_bytes={d_meta:.3f}',
 f'enabled_pvia_metadata_recv_mean_bytes={e_meta:.3f}',
 f'enabled_pvia_metadata_recv_mean_mib={e_meta/(1024.0*1024.0):.6f}',
 f'enabled_pvia_metadata_recv_mean_messages={e_meta_msgs:.3f}',
 f'enabled_authenticated_control_sent_mean_bytes={e_auth_sent:.3f}',
 f'enabled_authenticated_control_recv_mean_bytes={e_auth_recv:.3f}',
 f'enabled_auth_baseline_payload_sent_mean_bytes={e_auth_baseline_payload_sent:.3f}',
 f'enabled_auth_baseline_payload_recv_mean_bytes={e_auth_baseline_payload_recv:.3f}',
 f'enabled_auth_pvia_payload_sent_mean_bytes={e_auth_pvia_payload_sent:.3f}',
 f'enabled_auth_pvia_payload_recv_mean_bytes={e_auth_pvia_payload_recv:.3f}',
 f'enabled_auth_overhead_sent_mean_bytes={e_auth_overhead_sent:.3f}',
 f'enabled_auth_overhead_recv_mean_bytes={e_auth_overhead_recv:.3f}',
 f'disabled_baseline_input_payload_sent_mean_bytes={d_baseline_input:.3f}',
 f'enabled_baseline_input_payload_sent_mean_bytes={e_baseline_input:.3f}',
 f'baseline_input_payload_match={1 if abs(d_baseline_input-e_baseline_input) < 0.5 else 0}',
 f'enabled_authenticated_control_collective_sum_calls={e_auth_collectives:.3f}',
 f'enabled_authenticated_control_bytes_match={e_auth_bytes_match:.0f}',
 f'enabled_control_sent_mean_bytes={e_control_sent:.3f}',
 f'enabled_control_recv_mean_bytes={e_control_recv:.3f}',
 f'enabled_control_cluster_total_mean_bytes={e_control_sent:.3f}',
 f'enabled_control_per_rank_mean_bytes={e_control_sent_per_rank:.3f}',
 f'enabled_control_max_rank_mean_bytes={e_control_sent_max_rank:.3f}',
 f'enabled_control_sent_mean_messages={e_control_sent_msgs:.3f}',
 f'enabled_control_recv_mean_messages={e_control_recv_msgs:.3f}',
 f'enabled_control_collectives_per_rank={e_control_collectives:.3f}',
 f'enabled_control_bytes_match={e_control_bytes_match:.0f}',
 f'enabled_control_messages_match={e_control_messages_match:.0f}',
 f'enabled_runtime_init_control_mean_bytes={e_runtime_init_control:.3f}',
 f'enabled_preprocessing_control_mean_bytes={e_preprocessing_control:.3f}',
 f'enabled_preprocessing_control_cluster_total_mean_bytes={e_preprocessing_control:.3f}',
 f'enabled_preprocessing_control_per_rank_mean_bytes={e_preprocessing_control_per_rank:.3f}',
 f'enabled_preprocessing_control_max_rank_mean_bytes={e_preprocessing_control_max_rank:.3f}',
 f'enabled_initial_validity_control_mean_bytes={e_validity_control:.3f}',
 f'enabled_initial_validity_control_cluster_total_mean_bytes={e_validity_control:.3f}',
 f'enabled_initial_validity_control_per_rank_mean_bytes={e_validity_control_per_rank:.3f}',
 f'enabled_initial_validity_control_max_rank_mean_bytes={e_validity_control_max_rank:.3f}',
 f'enabled_consistency_provider_control_mean_bytes={e_provider_control:.3f}',
 f'enabled_public_direct_validation_control_mean_bytes={e_public_direct_control:.3f}',
 f'enabled_public_direct_validation_control_cluster_total_mean_bytes={e_public_direct_control:.3f}',
 f'enabled_public_direct_validation_control_per_rank_mean_bytes={e_public_direct_control_per_rank:.3f}',
 f'enabled_public_direct_validation_control_max_rank_mean_bytes={e_public_direct_control_max_rank:.3f}',
 f'enabled_offline_control_mean_bytes={e_runtime_init_control + e_preprocessing_control:.3f}',
 f'enabled_runtime_init_control_collectives={e_runtime_init_collectives:.3f}',
 f'enabled_preprocessing_control_collectives={e_preprocessing_collectives:.3f}',
 f'enabled_initial_validity_control_collectives={e_validity_collectives:.3f}',
 f'enabled_consistency_provider_control_collectives={e_provider_control_collectives:.3f}',
 f'enabled_initial_validity_run_rank_count={e_validity_runs:.3f}',
 f'enabled_initial_validity_strong_run_rank_count={e_validity_strong_runs:.3f}',
 f'enabled_initial_validity_strong_active={e_validity_strong_active}',
 f'enabled_consistency_provider_present={e_provider_present:.0f}',
 f'enabled_consistency_provider_production_ready={e_provider_ready:.0f}',
 f'enabled_consistency_provider_acceptance_present={e_provider_acceptance:.0f}',
 f'enabled_consistency_provider_protocol_id={e_provider_protocol_id}',
 f'enabled_consistency_provider_active={e_provider_active}',
 f'enabled_public_direct_validation_control_collectives={e_public_direct_collectives:.3f}',
 f'enabled_unclassified_control_mean_bytes={e_unclassified_control:.3f}',
 f'enabled_control_scope_partition_complete={e_scope_partition_complete:.0f}',
 f'enabled_online_accounted_comm_mean_mb={e_comm + (e_auth_sent + e_provider_control + e_validity_control + e_public_direct_control + e_meta)/(1024.0*1024.0):.6f}',
 f'enabled_online_incremental_accounted_comm_mean_mb={e_comm + (e_auth_sent - e_auth_baseline_payload_sent + e_provider_control + e_validity_control + e_public_direct_control + e_meta)/(1024.0*1024.0):.6f}',
 f'enabled_online_incremental_pvia_extra_mean_mb={(e_auth_sent - e_auth_baseline_payload_sent + e_provider_control + e_validity_control + e_public_direct_control + e_meta)/(1024.0*1024.0):.6f}',
 f'disabled_comparable_total_comm_mean_mb={d_comm + d_baseline_input/(1024.0*1024.0):.6f}',
 f'enabled_accounted_comm_mean_mb={e_comm + (e_auth_sent + e_control_sent + e_meta)/(1024.0*1024.0):.6f}',
 f'comparable_total_comm_overhead_pct={overhead(d_comm + d_baseline_input/(1024.0*1024.0), e_comm + (e_auth_sent + e_control_sent + e_meta)/(1024.0*1024.0)):.3f}',
 f'enabled_incremental_pvia_extra_mean_mb={(e_auth_sent - e_auth_baseline_payload_sent + e_control_sent + e_meta)/(1024.0*1024.0):.6f}',
 f'enabled_accounted_comm_excluding_baseline_input_payload_mean_mb={e_comm + (e_auth_sent - e_auth_baseline_payload_sent + e_control_sent + e_meta)/(1024.0*1024.0):.6f}',
 f'enabled_pvia_metadata_seal_mean_calls={e_seal_calls:.3f}',
 f'pvia_metadata_vs_reported_comm_pct={100.0*e_meta/(e_comm*1024.0*1024.0) if e_comm else 0.0:.3f}',
 f'control_vs_reported_comm_pct={100.0*e_control_sent/(e_comm*1024.0*1024.0) if e_comm else 0.0:.3f}',
 f'enabled_authenticated_control_vs_reported_comm_pct={100.0*e_auth_sent/(e_comm*1024.0*1024.0) if e_comm else 0.0:.3f}',
 f'enabled_transfer_meta_seal_maxrank_mean_ms={e_seal_ns/1e6:.6f}',
 f'enabled_transfer_meta_observe_maxrank_mean_ms={e_observe_ns/1e6:.6f}',
 f'enabled_transfer_meta_verify_maxrank_mean_ms={e_verify_ns/1e6:.6f}',
 f'transfer_meta_verify_vs_observe_pct={100.0*e_verify_ns/e_observe_ns if e_observe_ns else 0.0:.3f}',
 f'paired_program_overhead_mean_pct={pstat("program_total_ms_overhead_pct"):.3f}',
 f'paired_program_overhead_median_pct={pstat("program_total_ms_overhead_pct","median"):.3f}',
 f'paired_program_overhead_p95_pct={pstat("program_total_ms_overhead_pct","p95"):.3f}',
 f'paired_program_overhead_stddev_pct={pstat("program_total_ms_overhead_pct","stddev"):.3f}',
 f'paired_peak_rss_overhead_mean_pct={pstat("peak_rss_mb_overhead_pct"):.3f}',
 f'paired_peak_rss_overhead_median_pct={pstat("peak_rss_mb_overhead_pct","median"):.3f}',
 f'paired_peak_rss_overhead_p95_pct={pstat("peak_rss_mb_overhead_pct","p95"):.3f}',
 f'paired_peak_rss_overhead_stddev_pct={pstat("peak_rss_mb_overhead_pct","stddev"):.3f}',
 f'paired_rank0_pt_overhead_mean_pct={pstat("rank0_pt_ms_overhead_pct"):.3f}',
 f'paired_rank0_pt_overhead_median_pct={pstat("rank0_pt_ms_overhead_pct","median"):.3f}',
 f'paired_rank0_pt_overhead_p95_pct={pstat("rank0_pt_ms_overhead_pct","p95"):.3f}',
 f'paired_rank0_pt_overhead_stddev_pct={pstat("rank0_pt_ms_overhead_pct","stddev"):.3f}',
 'claim_scope=runtime-and-accountability-overhead; production-backend-validation-reported-separately']
open(out,'w').write('\n'.join(lines)+'\n')
PY
if [[ -n "$MC_PROVIDER_LIBRARY" ]]; then
  grep -qx 'enabled_consistency_provider_active=1' "$OUT/SUMMARY.txt" || {
    echo "configured provider was not active in the enabled measurements" >&2
    exit 20
  }
  grep -qx 'enabled_initial_validity_strong_active=1' "$OUT/SUMMARY.txt" || {
    echo "strong initial-validity provider path was not active in the enabled measurements" >&2
    exit 21
  }
  grep -Fq 'authenticated_transport=1' "$OUT/enabled_1/run.log" || {
    echo "provider acceptance did not use the authenticated batched MPC path" >&2
    exit 22
  }
fi

# Record proof-provider cold-start stages separately from the coPIOP timing.
if [[ -n "$MC_PROVIDER_LIBRARY" ]]; then
  python3 - "$OUT/enabled_1/run.log" "$OUT/PROVIDER_STAGE_SUMMARY.csv" "$NP" <<'PY'
import csv, re, statistics, sys
from pathlib import Path
log_path, output_path, world = sys.argv[1:]
world = int(world)
text = Path(log_path).read_text(errors="replace")
stages = [
    "key_setup_begin", "key_setup_end",
    "groth16_prove_begin", "groth16_prove_end",
    "groth16_verify_begin", "groth16_verify_end",
    "verified_proof_inprocess_hit", "verified_proof_inprocess_miss",
]
rows = []
for stage in stages:
    values = re.findall(r"stage=" + re.escape(stage) + r"(?: elapsed_ms=([0-9]+))?", text)
    times = [int(value) for value in values if value]
    rows.append({
        "stage": stage, "count": len(values), "timed_count": len(times),
        "mean_ms": f"{statistics.mean(times):.3f}" if times else "",
        "median_ms": f"{statistics.median(times):.3f}" if times else "",
        "min_ms": min(times) if times else "",
        "max_ms": max(times) if times else "",
    })
prove_times = [
    int(value) for value in re.findall(
        r"stage=groth16_prove_end elapsed_ms=([0-9]+)", text)
]
for start in range(0, len(prove_times), world):
    batch = prove_times[start:start + world]
    if len(batch) != world:
        continue
    rows.append({
        "stage": f"groth16_prove_batch_{start // world + 1}",
        "count": len(batch), "timed_count": len(batch),
        "mean_ms": f"{statistics.mean(batch):.3f}",
        "median_ms": f"{statistics.median(batch):.3f}",
        "min_ms": min(batch), "max_ms": max(batch),
    })
with open(output_path, "w", newline="", encoding="utf-8") as stream:
    writer = csv.DictWriter(stream, fieldnames=[
        "stage", "count", "timed_count", "mean_ms", "median_ms",
        "min_ms", "max_ms"])
    writer.writeheader()
    writer.writerows(rows)
print("PVIA_PROVIDER_STAGE_SUMMARY: RECORDED " + output_path)
PY
fi

python3 - "$OUT/MANIFEST.json" "$NP" "$M_LOG" "$CIR" "$SUMCHECK_LOG" "$PC_LOG" "$MULTREE_LOG" "$REPEATS" "$WARMUP" "$RAYON_THREADS" "$OMP_THREADS" "$GOMAXPROCS_THREADS" <<'PY'
import json, sys
path, np, mlog, cir, sumcheck, pc, multree, repeats, warmup, rayon, omp, gomaxprocs = sys.argv[1:]
record = json.load(open(path, encoding="utf-8"))
record["benchmark_success"] = "PASS"
record["parameters"] = (
    f"world_size={np}; M_LOG={mlog}; CIR={cir}; "
    f"SUMCHECK_LOG={sumcheck}; PC_LOG={pc}; MULTREE_LOG={multree}; "
    f"repeats={repeats}; warmup={warmup}; "
    f"RAYON_NUM_THREADS={rayon}; OMP_NUM_THREADS={omp}; "
    f"GOMAXPROCS={gomaxprocs}"
)
with open(path, "w", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write(chr(10))
PY

echo "provider_mode=$PROVIDER_MODE" >> "$OUT/SUMMARY.txt"
cat "$OUT/SUMMARY.txt"
echo "raw=$RAW"
echo "summary=$OUT/summary_stats.csv"
echo "results=$OUT"
