#pragma once

#include "ExternalMultiplicationConsistencyProofAdapter.hpp"
#include "MultiplicationConsistencyBackendRegistry.hpp"

#include <memory>

namespace pvia {

class ExternalMultiplicationConsistencyProviderSession final {
public:
    ExternalMultiplicationConsistencyProviderSession(
        MultiplicationConsistencyCapabilities capabilities,
        uint32_t expected_proof_system_id,
        MultiplicationConsistencyProviderCallbacks callbacks);

    bool Activate(
        int rank, int world_size,
        MPI_Comm comm = MPI_COMM_WORLD);

    void Reset();

    bool adapter_ready() const { return adapter_.ready(); }
    bool active() const {
        return registration_ && registration_->active();
    }

    const ExternalMultiplicationConsistencyProofAdapter& backend() const {
        return adapter_;
    }

    const std::string& last_error() const { return adapter_.last_error(); }

    const MultiplicationConsistencyProviderAcceptanceResult&
    acceptance() const {
        return acceptance_;
    }

    const MultiplicationConsistencyProviderAcceptanceResult&
    last_attempt() const {
        return last_attempt_;
    }

private:
    ExternalMultiplicationConsistencyProofAdapter adapter_;
    MultiplicationConsistencyProviderAcceptanceResult acceptance_{};
    MultiplicationConsistencyProviderAcceptanceResult last_attempt_{};
    std::unique_ptr<ScopedMultiplicationConsistencyBackendRegistration>
        registration_;
};

} // namespace pvia
