#include "ExternalMultiplicationConsistencyProviderSession.hpp"

namespace pvia {

ExternalMultiplicationConsistencyProviderSession::
ExternalMultiplicationConsistencyProviderSession(
    MultiplicationConsistencyCapabilities capabilities,
    uint32_t expected_proof_system_id,
    MultiplicationConsistencyProviderCallbacks callbacks)
    : adapter_(
          std::move(capabilities),
          expected_proof_system_id,
          std::move(callbacks)) {}

bool ExternalMultiplicationConsistencyProviderSession::Activate(
    int rank, int world_size, MPI_Comm comm) {
    Reset();
    if (!adapter_.ready())
        return false;

    MultiplicationConsistencyProviderAcceptanceResult candidate;
    const bool accepted = run_multiplication_consistency_provider_acceptance(
        rank, world_size, adapter_, &candidate, comm);
    last_attempt_ = candidate;
    if (!accepted || !candidate.available ||
        candidate.acceptance_binding == Digest{})
        return false;

    auto registration =
        std::make_unique<ScopedMultiplicationConsistencyBackendRegistration>(
            &adapter_, &candidate);
    if (!registration->active())
        return false;
    if (MultiplicationConsistencyBackendRegistry::Current() != &adapter_ ||
        MultiplicationConsistencyBackendRegistry::CurrentAcceptanceBinding() !=
            candidate.acceptance_binding)
        return false;

    acceptance_ = candidate;
    registration_ = std::move(registration);
    return true;
}

void ExternalMultiplicationConsistencyProviderSession::Reset() {
    registration_.reset();
    acceptance_ = MultiplicationConsistencyProviderAcceptanceResult{};
    last_attempt_ = MultiplicationConsistencyProviderAcceptanceResult{};
}

} // namespace pvia
