#pragma once

#include "PVIA.hpp"

#include <vector>

namespace pvia {

// Opaque local handle for an operation residual. The clear residual is owned by
// the concrete secure provider / MPC backend and is never returned to Runtime.
struct PrivateResidualHandle {
    OperationRef ref{};
    Label label{};
    RelationKind relation = RelationKind::UNKNOWN;
    AuditRelationKernel kernel = AuditRelationKernel::UNKNOWN;
    CheckpointId checkpoint = 0;
    Digest commitment{};
    bool available = false;
    bool authenticated = false;
};

struct LocalResidualBatchView {
    ObligationSet scope{};
    uint32_t local_owner = 0;
    std::vector<PrivateResidualHandle> handles;
    Digest commitment_root{};
    bool complete_for_owner = false;
    bool all_authenticated = false;
};

// Canonical local source root; PRIVATE trust anchor, never a public
// localization certificate. Rejects invalid or duplicate handle layouts.
Digest compute_private_residual_local_handle_root(
    const std::vector<PrivateResidualHandle>& handles);

class PrivateResidualRegistry {
public:
    void Put(const PrivateResidualHandle& handle);
    const PrivateResidualHandle* Find(const OperationRef& ref) const;
    std::vector<PrivateResidualHandle> Select(
        const ObligationSet& scope) const;
    LocalResidualBatchView BuildLocalBatchView(
        const ObligationSet& scope, uint32_t local_owner) const;
    size_t size() const { return handles_.size(); }

private:
    std::vector<PrivateResidualHandle> handles_;
};

} // namespace pvia
