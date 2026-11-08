#pragma once

#include "ReferenceGodOutputDelivery.hpp"
#include "ReferenceGodOutputConsistencyProviderAbi.h"

#include <functional>
#include <memory>
#include <string>

namespace pvia {

bool run_reference_god_output_provider_abi_selftest(
    const std::string& library_path, std::string* result_message);
bool run_reference_god_output_provider_artifact_selftest(
    const std::string& statement_words_path,
    const std::string& witness_words_path,
    const std::string& proof_artifact_words_path,
    std::string* result_message);

class SharedLibraryReferenceGodOutputConsistencyProvider final {
public:
    using ExternalAnchorVerifier = std::function<bool(
        const ReferenceGodOutputConsistencyCapabilities&)>;

    SharedLibraryReferenceGodOutputConsistencyProvider(
        std::string library_path,
        ReferenceGodOutputConsistencyCapabilities accepted_capabilities,
        uint32_t expected_proof_system_id,
        ExternalAnchorVerifier verify_external_anchor);
    ~SharedLibraryReferenceGodOutputConsistencyProvider();

    static bool QueryCapabilities(
        const std::string& library_path,
        ReferenceGodOutputConsistencyCapabilities* capabilities,
        std::string* error_message);

    bool Load();
    bool Activate(int rank, int world_size, MPI_Comm comm = MPI_COMM_WORLD);
    void Reset();

    bool loaded() const { return handle_ != nullptr && adapter_ && adapter_->ready(); }
    bool active() const { return registration_ && registration_->active(); }
    const std::string& error() const { return error_; }
    const ReferenceGodOutputConsistencyCapabilities& capabilities() const {
        return accepted_capabilities_;
    }

private:
    using VersionFn = uint32_t (*)();
    using CapabilitiesFn = int32_t (*)(uint64_t*, size_t*);
    using ProveFn = int32_t (*)(
        const uint64_t*, size_t, const uint64_t*, size_t, uint64_t*, size_t*);
    using VerifyFn = int32_t (*)(const uint64_t*, size_t, const uint64_t*, size_t);
    using LastErrorFn = size_t (*)(uint8_t*, size_t*);

    ReferenceGodOutputConsistencyProofArtifact Prove(
        const ReferenceGodOutputConsistencyStatement& statement,
        const std::vector<u64>& provider_witness_words) const;
    bool Verify(
        const ReferenceGodOutputConsistencyStatement& statement,
        const ReferenceGodOutputConsistencyProofArtifact& proof) const;
    bool DecodeProviderCapabilities(
        const std::vector<uint64_t>& words,
        ReferenceGodOutputConsistencyCapabilities* capabilities) const;
    bool VerifyProviderIdentity();
    bool CollectiveProviderAgreement(int rank, int world_size, MPI_Comm comm) const;
    std::string ProviderLastError() const;
    void Close();

    std::string library_path_;
    ReferenceGodOutputConsistencyCapabilities accepted_capabilities_{};
    ReferenceGodOutputConsistencyCapabilities provider_capabilities_{};
    uint32_t expected_proof_system_id_ = 0;
    ExternalAnchorVerifier verify_external_anchor_;
    void* handle_ = nullptr;
    VersionFn version_fn_ = nullptr;
    CapabilitiesFn capabilities_fn_ = nullptr;
    ProveFn prove_fn_ = nullptr;
    VerifyFn verify_fn_ = nullptr;
    LastErrorFn last_error_fn_ = nullptr;
    bool provider_identity_verified_ = false;
    std::unique_ptr<ExternalReferenceGodOutputConsistencyProofAdapter> adapter_;
    std::unique_ptr<ScopedReferenceGodOutputConsistencyBackendRegistration> registration_;
    std::string error_;
    mutable std::string provider_operation_error_;
};

} // namespace pvia
