#pragma once
namespace pvia {
// Standalone reference MPI test: generate SP1-compatible private input by
// assembling committed rows held by distinct non-owner ranks. No Groth16
// proving here, no public witness publication or privacy guarantees.
bool run_reference_distributed_row_registration_selftest(
    int rank,int world_size);
}
