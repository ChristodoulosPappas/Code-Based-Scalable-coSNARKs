#pragma once

#include "MultiplicationConsistencyProof.hpp"

#include <functional>
#include <string>
#include <utility>

namespace pvia {

struct MultiplicationConsistencyProviderCallbacks {
    std::function<MultiplicationConsistencyProofArtifact(
        const MultiplicationConsistencyStatement&,
        const MultiplicationConsistencyWitness&)> prove;
    std::function<bool(
        const MultiplicationConsistencyStatement&,
        const MultiplicationConsistencyProofArtifact&)> verify;
    std::function<std::string()> last_error;
};

// Adapter for an externally supplied proof provider.  This class contributes
// no proof construction of its own: readiness requires caller-supplied
// capabilities and both callbacks, and every returned artifact is checked
// against the repository's canonical statement/artifact format.
class ExternalMultiplicationConsistencyProofAdapter final
    : public MultiplicationConsistencyProofBackend {
public:
    ExternalMultiplicationConsistencyProofAdapter(
        MultiplicationConsistencyCapabilities capabilities,
        uint32_t expected_proof_system_id,
        MultiplicationConsistencyProviderCallbacks callbacks);

    bool ready() const { return ready_; }

    MultiplicationConsistencyCapabilities Capabilities() const override;
    const std::string& last_error() const { return last_error_; }
    MultiplicationConsistencyProofArtifact Prove(
        const MultiplicationConsistencyStatement& statement,
        const MultiplicationConsistencyWitness& witness) const override;
    bool Verify(
        const MultiplicationConsistencyStatement& statement,
        const MultiplicationConsistencyProofArtifact& proof) const override;

private:
    MultiplicationConsistencyCapabilities capabilities_{};
    uint32_t expected_proof_system_id_ = 0;
    MultiplicationConsistencyProviderCallbacks callbacks_{};
    bool ready_ = false;
    mutable std::string last_error_;
};

} // namespace pvia
