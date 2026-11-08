#pragma once

#include "PublicTransferCheckEngine.hpp"

namespace pvia {

// Concrete transcript-direct transfer backend. It treats Ed25519-verified
// transfer metadata as the authentication boundary; MPI is used only to
// reconcile already-authenticated public facts across ranks.
class Ed25519PublicTransferCheckBackend final
    : public PublicTransferCheckBackend {
public:
    Digest ProductionCapabilityBinding() const override;
    PublicTransferCheckResult Check(
        const ObligationSet& scope,
        const std::vector<PublicTransferObservation>& local_observations,
        int rank,
        int world_size) const override;

    CollectiveDisputeResult Dispute(
        const ObligationSet& scope,
        const PublicTransferCheckResult& check,
        const std::vector<PublicTransferObservation>& local_observations,
        int rank,
        int world_size) const override;

private:
    // Check() already performs the collective reconciliation.  Cache only the
    // resulting public canonical facts, keyed by both scope and check
    // bindings, so the immediately following Dispute() can avoid repeating
    // the same collective.  Any binding mismatch forces a full recomputation.
    mutable Digest cached_scope_binding_{};
    mutable Digest cached_check_binding_{};
    mutable std::vector<OperationRef> cached_refs_;
    mutable std::vector<Digest> cached_metadata_bindings_;
    mutable std::vector<uint8_t> cached_mismatches_;
};

} // namespace pvia
