#pragma once

#include "CollectiveResidualEngine.hpp"
#include "PublicTransferObservation.hpp"

namespace pvia {

struct PublicTransferCheckResult {
    bool available = false;
    bool cryptographically_authenticated = false;
    bool ok = false;
    CheckpointId checkpoint = 0;
    size_t checked_operations = 0;
    size_t mismatches = 0;
    Digest scope_binding{};
    Digest transcript_binding{};
    Digest authentication_commitment{};
};

Digest compute_public_transfer_check_binding(
    const PublicTransferCheckResult& result);
bool validate_public_transfer_check_result(
    const ObligationSet& scope,
    const PublicTransferCheckResult& result);

BatchCheckResult make_public_transfer_batch_envelope(
    const ObligationSet& scope,
    const PublicTransferCheckResult& result,
    int world_size);
bool validate_public_transfer_dispute_result(
    const ObligationSet& scope,
    const PublicTransferCheckResult& check,
    const CollectiveDisputeResult& result);
bool public_transfer_observation_supports_dispute(
    const PublicTransferObservation& observation,
    const CollectiveDisputeResult& result);
bool find_public_transfer_observation_for_dispute(
    const PublicTransferObservationStore& observations,
    const ObligationSet& scope,
    const CollectiveDisputeResult& result,
    PublicTransferObservation* matched);

class PublicTransferCheckEngine {
public:
    virtual ~PublicTransferCheckEngine() = default;
    virtual Digest ProductionCapabilityBinding() const { return {}; }

    virtual PublicTransferCheckResult Check(
        const ObligationSet& scope,
        const PublicTransferObservationStore& observations,
        int rank,
        int world_size) const = 0;

    virtual CollectiveDisputeResult Dispute(
        const ObligationSet& scope,
        const PublicTransferCheckResult& check,
        const PublicTransferObservationStore& observations,
        int rank,
        int world_size) const = 0;
};

class PublicTransferCheckBackend {
public:
    virtual ~PublicTransferCheckBackend() = default;
    virtual Digest ProductionCapabilityBinding() const { return {}; }
    virtual PublicTransferCheckResult Check(
        const ObligationSet& scope,
        const std::vector<PublicTransferObservation>& local_observations,
        int rank,
        int world_size) const = 0;
    virtual CollectiveDisputeResult Dispute(
        const ObligationSet& scope,
        const PublicTransferCheckResult& check,
        const std::vector<PublicTransferObservation>& local_observations,
        int rank,
        int world_size) const = 0;
};

class BackendPublicTransferCheckEngine final
    : public PublicTransferCheckEngine {
public:
    explicit BackendPublicTransferCheckEngine(
        const PublicTransferCheckBackend& backend) : backend_(backend) {}
    PublicTransferCheckResult Check(
        const ObligationSet& scope,
        const PublicTransferObservationStore& observations,
        int rank,
        int world_size) const override;
    CollectiveDisputeResult Dispute(
        const ObligationSet& scope,
        const PublicTransferCheckResult& check,
        const PublicTransferObservationStore& observations,
        int rank,
        int world_size) const override;
    Digest ProductionCapabilityBinding() const override {
        return backend_.ProductionCapabilityBinding();
    }
private:
    const PublicTransferCheckBackend& backend_;
};

class FailClosedPublicTransferCheckEngine final
    : public PublicTransferCheckEngine {
public:
    PublicTransferCheckResult Check(
        const ObligationSet& scope,
        const PublicTransferObservationStore& observations,
        int rank,
        int world_size) const override;
    CollectiveDisputeResult Dispute(
        const ObligationSet& scope,
        const PublicTransferCheckResult& check,
        const PublicTransferObservationStore& observations,
        int rank,
        int world_size) const override;
};

} // namespace pvia
