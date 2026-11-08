#pragma once

#include "PublicBlameProof.hpp"
#include "PublicTransferEvidence.hpp"

namespace pvia {

class PublicTransferBlameProofEngine {
public:
    virtual ~PublicTransferBlameProofEngine() = default;
    virtual Digest ProductionCapabilityBinding() const { return {}; }
    virtual PublicBlameProofArtifact Prove(
        const PublicBlameStatement& statement,
        const PublicTransferEvidence& evidence) const = 0;
    virtual bool Verify(
        const PublicBlameStatement& statement,
        const PublicBlameProofArtifact& proof) const = 0;
};

class PublicTransferBlameProofBackend {
public:
    virtual ~PublicTransferBlameProofBackend() = default;
    virtual Digest ProductionCapabilityBinding() const { return {}; }
    virtual ExternalPublicBlameProof Prove(
        const std::vector<u64>& public_inputs,
        const std::vector<u64>& transfer_evidence) const = 0;
    virtual bool Verify(
        const std::vector<u64>& public_inputs,
        const ExternalPublicBlameProof& proof) const = 0;
};

class BackendPublicTransferBlameProofEngine final
    : public PublicTransferBlameProofEngine {
public:
    explicit BackendPublicTransferBlameProofEngine(
        const PublicTransferBlameProofBackend& backend)
        : backend_(backend) {}
    PublicBlameProofArtifact Prove(
        const PublicBlameStatement& statement,
        const PublicTransferEvidence& evidence) const override;
    bool Verify(
        const PublicBlameStatement& statement,
        const PublicBlameProofArtifact& proof) const override;
    Digest ProductionCapabilityBinding() const override {
        return backend_.ProductionCapabilityBinding();
    }
private:
    const PublicTransferBlameProofBackend& backend_;
};

class FailClosedPublicTransferBlameProofEngine final
    : public PublicTransferBlameProofEngine {
public:
    PublicBlameProofArtifact Prove(
        const PublicBlameStatement& statement,
        const PublicTransferEvidence& evidence) const override;
    bool Verify(
        const PublicBlameStatement& statement,
        const PublicBlameProofArtifact& proof) const override;
};

} // namespace pvia
