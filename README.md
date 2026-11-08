# PAR-coSNARK Artifact

This repository contains the research implementation and selected evaluation
materials for **PAR-coSNARK**, a release-gated accountability compiler for
collaborative zk-SNARKs. The artifact is intended for source inspection,
rebuilding, regression testing, and review of the reported measurements.

This is a research artifact, not a production security library.

## Artifact contents

- **src/**: collaborative prover and accountability implementation.
- **Blake/**, **lib/**: bundled cryptographic dependencies required by the build.
- **experiments/**: build, regression, evaluation, and verification scripts.
- **artifact_data/**: compact CSV, JSON, manifest, and certificate outputs selected
  from the evaluation runs. Large transient logs and build products are omitted.

Development notes, chat handoffs, local build directories, and intermediate
debug logs are not part of the artifact.

## Requirements

The artifact was tested on Linux x86-64 with GCC 9.4, CMake, Open MPI 3.1, and
OpenSSL 1.1.1f. A compatible x86-64 CPU with AVX and SHA instruction support is
required by the current compiler flags.

On Ubuntu/Debian, install the build dependencies:

~~~bash
sudo apt-get update
sudo apt-get install -y \
  build-essential cmake \
  openmpi-bin libopenmpi-dev \
  libssl-dev openssl \
  python3
~~~

The XKCP static library and its headers, as well as the BLAKE3 source, are
included in the repository. The default C++ build does not require a separate
Rust toolchain.

## Build

From the repository root:

~~~bash
cmake -S . -B build-par -DCMAKE_BUILD_TYPE=Release
cmake --build build-par -j2
test -x build-par/src/pigeon && echo BUILD_OK
~~~

The -j2 setting is conservative for reproducible builds. Increase the job count
only if sufficient memory is available.

## Run the regression checks

The release-gate matrix runs five positive and injected-failure cases with four
MPI participants:

~~~bash
BUILD_DIR="$PWD/build-par" BUILD=0 \
  bash experiments/run_release_gate_matrix_xfusion.sh
~~~

The security smoke test checks the reference registration and transport paths,
robust-abort certificate acceptance/rejection, and the corresponding Shamir
self-tests:

~~~bash
BUILD_DIR="$PWD/build-par" \
  bash experiments/run_security_smoke_xfusion.sh
~~~

Both scripts create timestamped output directories under experiments/results/.
The second script rebuilds the executable before running. These checks validate
the implemented test paths and withholding behavior; they are not, by
themselves, a cryptographic proof of end-to-end malicious security or a
production-release authorization.

## Run a small performance smoke test

The following command runs one small paired baseline/compiled comparison with
four participants. It is intended to check the build and measurement pipeline,
not to reproduce the headline paper parameters:

~~~bash
BUILD_DIR="$PWD/build-par" \
NP=4 REPEATS=1 WARMUP=0 \
M_LOG=10 SUMCHECK_LOG=8 PC_LOG=9 MULTREE_LOG=6 \
BUILD=0 \
OUT="$PWD/experiments/results/performance-smoke" \
bash experiments/run_copiop_overhead_xfusion.sh
~~~

The general overhead runner currently accepts NP=4, 8, 16, 32. The
paper-facing measurements through 64 participants are supplied as compact
results and manifests in artifact_data/performance/; the smoke command above
does not rerun the full multi-scale evaluation.

## Included performance results

The primary performance set uses N = 4, 8, 16, 32, 64. The reported
measurements are single paired runs per scale (repeats=1, warmup=0), not
multi-run averages or confidence intervals.

| Participants | Proving-time overhead | Full communication overhead |
|---:|---:|---:|
| 4  | 7.778%  | 0.486% |
| 8  | 10.350% | 1.159% |
| 16 | 12.723% | 3.101% |
| 32 | 3.227%  | 10.610% |
| 64 | 13.156% | 49.404% |

The N=128 measurements are retained as exploratory data and are not part of
the primary performance set.

**Evaluation scope.** The headline performance configuration uses the
reference-fast-passive-bgw provider, with online SP1 proving disabled and the
strong multiplication-consistency provider inactive. These measurements
therefore characterize the reference execution path; they must not be
interpreted as performance results for a fully malicious-secure production
backend.

## Data layout

- **artifact_data/performance/**: six-scale timing and communication tables,
  per-scale summaries and manifests, offline preprocessing measurements,
  prefix-search measurements, and abort-latency data.
- **artifact_data/functional/**: compact evidence for the release-gate matrix,
  the security smoke test, and the same-run native/M4 reference gate.

The original run-specific logs are intentionally not included. The supplied
manifests and compact result files preserve the measurements and the key
verification outputs needed for artifact review.
