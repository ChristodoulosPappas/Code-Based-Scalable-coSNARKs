#pragma once

#include "PVIA.hpp"

#include <mpi.h>
#include <utility>
#include <vector>

namespace pvia {

struct InitialValidityGateResult {
    bool executed = false;
    bool valid = false;
    StateId validated_state = 0;
    OperationRef validation_operation{};
    Digest public_coin_binding{};
    Digest zero_test_binding{};
    Digest validation_binding{};
    Digest relation_definition_binding{};
    Digest transport_capability_binding{};
    Digest compressed_sharing_binding{};
    Digest consistency_capability_binding{};
    Digest consistency_acceptance_binding{};
    Digest multiplication_consistency_binding{};
    // Collective commitment to each participant local residual inputs
    // and derived contribution. This is an execution binding, not a ZK proof.
    Digest local_contribution_binding{};
    bool authenticated_transport_used = false;
    bool strong_consistency_used = false;
    size_t packed_blocks = 0;
    size_t linked_witness_slots = 0;
    size_t linked_constraint_slots = 0;
    int reference_threshold = 0;
};

// Development/reference implementation of the paper's initial private
// validity gate for the packed vL/vR/vO representation.
//
// The gate binds the distributed public R1CS relation, compresses both
// witness-to-wire linear derivation residuals and multiplicative residuals
// after the input shares have been fixed, converts the combined compressed
// value to a VSS-backed Shamir representation and reveals only the zero/nonzero
// result through the masked zero-test primitive. The reference/passive path
// retains the canonical sharing binding without materializing local provenance
// witnesses; the strong consistency path retains full provenance. When a
// production-ready multiplication-consistency backend is installed, the gate
// automatically uses the consistency-bound zero-test path; otherwise it keeps
// the reference path fail-closed with respect to the stronger claim.
bool run_initial_packed_validity_gate(
    Runtime& runtime,
    const std::vector<F>& witness_share,
    const std::vector<F>& vL_share,
    const std::vector<F>& vR_share,
    const std::vector<F>& vO_share,
    const std::vector<std::vector<std::pair<int,int>>>& pA,
    const std::vector<std::vector<std::pair<int,int>>>& pB,
    const std::vector<std::vector<std::pair<int,int>>>& pC,
    const std::vector<StateId>& input_states,
    int k,
    int packed_width,
    InitialValidityGateResult* result,
    MPI_Comm comm = MPI_COMM_WORLD);

} // namespace pvia
