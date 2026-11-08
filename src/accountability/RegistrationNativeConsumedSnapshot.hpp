#pragma once

#include "RegistrationConsistencyProof.hpp"

namespace pvia {
class PrivateStateMaterialStore;
class PrivateAuditMaterialStore;

// Copies the exact native state/output/challenge currently held in the
// finalized local source stores. It is NOT an independently certified
// executor record or a globally synchronized state snapshot.
struct RegistrationNativeConsumedSnapshot {
    std::vector<F> state_values;
    std::vector<F> actual_output;
    F public_challenge{};
    Digest pre_vss_claim_binding{};
    Digest consumed_record_binding{};
};

// Recompute the canonical binding from the statement, captured values, and
// sealed checkpoint. This is a local integrity equation, not a signature.
Digest compute_registration_native_consumed_record_binding(
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeConsumedSnapshot& snapshot,
    const AuditCheckpointView& checkpoint);

// Read and bind private values from the source stores, rather than
// synthesizing a second owner input after the pre-VSS receipt is signed.
// The statement's post-VSS digest may be a placeholder at this stage.
bool read_registration_native_consumed_snapshot(
    const RegistrationConsistencyStatement& pre_vss_statement,
    const PrivateStateMaterialStore& states,
    const PrivateAuditMaterialStore& operations,
    const AuditCheckpointView& checkpoint,
    RegistrationNativeConsumedSnapshot* output);

// Re-read the local native source and reject any post-capture drift.
bool registration_native_consumed_snapshot_still_matches(
    const RegistrationConsistencyStatement& pre_vss_statement,
    const PrivateStateMaterialStore& states,
    const PrivateAuditMaterialStore& operations,
    const AuditCheckpointView& checkpoint,
    const RegistrationNativeConsumedSnapshot& captured);

// PRIVATE reference-only registration equality preflight. Recompute the
// checkpoint-bound native source record, compare ALL captured state/output
// coordinates and the FOLD challenge against the private VSS witness, then
// evaluate the VSS polynomial-constant and FOLD relation. Fail closed on
// empty/stale source binding. This is NOT a ZK verifier, does not authenticate
// the native executor, and must not authorize a production release.
bool verify_reference_registered_native_snapshot_witness_equality(
    const RegistrationConsistencyStatement& statement,
    const RegistrationConsistencyWitness& witness,
    const RegistrationNativeConsumedSnapshot& captured,
    const AuditCheckpointView& checkpoint);

// Pluggable boundary between the accountability layer and the native
// execution/state owner. A production executor can implement this interface
// without exposing its internal store representation to the MPC backend.
class RegistrationNativeSourceProvider {
public:
    virtual ~RegistrationNativeSourceProvider() = default;
    virtual bool capture(
        const RegistrationConsistencyStatement& pre_vss_statement,
        RegistrationNativeConsumedSnapshot* output) const = 0;
    virtual bool still_matches(
        const RegistrationConsistencyStatement& pre_vss_statement,
        const RegistrationNativeConsumedSnapshot& captured) const = 0;
};

// Adapter for the current finalized local stores. This remains the reference
// implementation; it does not itself certify that the stores came from a
// real coSNARK executor.
class RegistrationNativeStoreSourceProvider final
    : public RegistrationNativeSourceProvider {
public:
    RegistrationNativeStoreSourceProvider(
        const PrivateStateMaterialStore& states,
        const PrivateAuditMaterialStore& operations,
        const AuditCheckpointView& checkpoint);
    bool capture(
        const RegistrationConsistencyStatement& pre_vss_statement,
        RegistrationNativeConsumedSnapshot* output) const override;
    bool still_matches(
        const RegistrationConsistencyStatement& pre_vss_statement,
        const RegistrationNativeConsumedSnapshot& captured) const override;
private:
    const PrivateStateMaterialStore& states_;
    const PrivateAuditMaterialStore& operations_;
    const AuditCheckpointView& checkpoint_;
};

} // namespace pvia
