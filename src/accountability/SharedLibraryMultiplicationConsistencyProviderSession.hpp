#pragma once

#include "ExternalMultiplicationConsistencyProviderSession.hpp"
#include "MultiplicationConsistencyProviderAbi.hpp"

#include <memory>
#include <string>

namespace pvia {

class SharedLibraryMultiplicationConsistencyProviderSession final {
public:
    SharedLibraryMultiplicationConsistencyProviderSession(
        std::string library_path,
        uint32_t expected_proof_system_id);
    ~SharedLibraryMultiplicationConsistencyProviderSession();

    bool Load();
    bool Activate(
        int rank, int world_size,
        MPI_Comm comm = MPI_COMM_WORLD);
    void Reset();

    bool loaded() const { return handle_ != nullptr && session_ != nullptr; }
    bool active() const { return session_ && session_->active(); }
    const std::string& error() const { return error_; }
    const MultiplicationConsistencyCapabilities& capabilities() const {
        return capabilities_;
    }
    const MultiplicationConsistencyProviderAcceptanceResult* acceptance() const {
        return session_ ? &session_->acceptance() : nullptr;
    }

private:
    friend bool run_reference_god_output_bundle_n4_selftest(int, int, const std::string&, const std::string&, const std::string&);
    const MultiplicationConsistencyProofBackend* backend() const {
        return session_ ? &session_->backend() : nullptr;
    }
    MultiplicationConsistencyProofArtifact Prove(
        const MultiplicationConsistencyStatement& statement,
        const MultiplicationConsistencyWitness& witness) const;
    bool Verify(
        const MultiplicationConsistencyStatement& statement,
        const MultiplicationConsistencyProofArtifact& proof) const;
    bool CollectiveProviderAgreement(
        int rank, int world_size, MPI_Comm comm) const;
    void Close();

    std::string library_path_;
    uint32_t expected_proof_system_id_ = 0;
    void* handle_ = nullptr;
    MultiplicationConsistencyAbiVersionFn version_fn_ = nullptr;
    MultiplicationConsistencyAbiCapabilitiesFn capabilities_fn_ = nullptr;
    MultiplicationConsistencyAbiProveFn prove_fn_ = nullptr;
    MultiplicationConsistencyAbiVerifyFn verify_fn_ = nullptr;
    MultiplicationConsistencyCapabilities capabilities_{};
    std::unique_ptr<ExternalMultiplicationConsistencyProviderSession> session_;
    std::string error_;
    mutable std::string provider_operation_error_;
};

} // namespace pvia
