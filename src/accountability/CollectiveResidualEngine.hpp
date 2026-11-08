#pragma once

#include "PrivateResidualRegistry.hpp"

namespace pvia {

// Public/opaque result of collective residual localization.  It identifies the
// operation selected by the secure dispute protocol without exposing a clear
// residual value.
struct CollectiveDisputeResult {
    bool available = false;
    bool cryptographically_authenticated = false;
    bool found = false;
    OperationRef accused{};
    CheckpointId checkpoint = 0;
    RelationKind relation = RelationKind::UNKNOWN;
    AuditRelationKernel kernel = AuditRelationKernel::UNKNOWN;
    Label label{};
    Digest expected{};
    Digest actual{};
    Digest residual_commitment{};
    Digest operation_statement_binding{};
    Digest batch_result_binding{};
    Digest public_evidence_binding{};
    Digest security_attestation_binding{};
    Digest recursive_transcript_binding{};
    Digest localization_commitment{};
};

// Canonical description of one party's input to a collective BatchCheck.
// Only commitments/labels are represented here; residual values remain inside
// the concrete secure engine.
struct CollectiveBatchDescriptor {
    ObligationSet scope{};
    uint32_t local_owner = 0;
    int world_size = 1;
    size_t local_handle_count = 0;
    Digest local_commitment_root{};
    Digest descriptor_digest{};
};
Digest compute_collective_scope_binding(const ObligationSet& scope);
Digest compute_collective_descriptor_digest(
    const ObligationSet& scope,
    uint32_t local_owner,
    int world_size,
    size_t local_handle_count,
    const Digest& local_commitment_root);
Digest compute_collective_batch_result_binding(const BatchCheckResult& result);
Digest compute_collective_dispute_binding(
    const CollectiveDisputeResult& result);
Violation materialize_collective_violation(
    const CollectiveDisputeResult& result);

CollectiveBatchDescriptor make_collective_batch_descriptor(
    const ObligationSet& scope,
    const LocalResidualBatchView& local_view,
    int rank,
    int world_size);

bool validate_collective_batch_result(
    const ObligationSet& scope,
    const BatchCheckResult& result,
    int world_size);

bool validate_collective_dispute_result(
    const ObligationSet& scope,
    const BatchCheckResult& batch,
    const CollectiveDisputeResult& result);

class CollectiveResidualEngine {
public:
    virtual ~CollectiveResidualEngine() = default;
    virtual Digest ProductionCapabilityBinding() const { return {}; }

    virtual BatchCheckResult BatchCheck(
        const ObligationSet& scope,
        const LocalResidualBatchView& local_view,
        int rank,
        int world_size) const = 0;

    virtual CollectiveDisputeResult Dispute(
        const ObligationSet& scope,
        const BatchCheckResult& batch,
        const LocalResidualBatchView& local_view,
        int rank,
        int world_size) const = 0;
};
// Safe placeholder used until an authenticated collective MPC/audit engine is
// installed.  It never reports an authenticated batch result or localization.
class FailClosedCollectiveResidualEngine final : public CollectiveResidualEngine {
public:
    BatchCheckResult BatchCheck(
        const ObligationSet& scope,
        const LocalResidualBatchView& local_view,
        int rank,
        int world_size) const override;

    CollectiveDisputeResult Dispute(
        const ObligationSet& scope,
        const BatchCheckResult& batch,
        const LocalResidualBatchView& local_view,
        int rank,
        int world_size) const override;
};

} // namespace pvia
