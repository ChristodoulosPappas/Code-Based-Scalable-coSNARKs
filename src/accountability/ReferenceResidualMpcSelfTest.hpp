#pragma once

#include <cstddef>

namespace pvia {

bool run_reference_residual_mpc_selftest(int rank, int world_size);

// Isolated N=4 positive and corrupt-dealer regression for private RS
// multiplication consistency. Test fixture; not a full GOD assertion.
bool run_reference_rs_multiplication_selftest(int rank, int world_size);
class Runtime;
// Functional wiring regression only. The separately verified public-abort
// fixture is NOT a proof attributing the RS mismatch to its injected dealer.
bool run_reference_rs_e2e_selftest(Runtime& runtime,
                                  int rank, int world_size);

bool run_reference_activated_private_owner_selftest(
    int rank, int world_size);

bool run_reference_residual_localization_benchmark(
    int rank, int world_size, size_t total_operations,
    bool fault_last, int owner0_position = -1);

} // namespace pvia
