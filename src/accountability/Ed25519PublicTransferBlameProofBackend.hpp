#pragma once

#include "PublicTransferBlameProof.hpp"

namespace pvia {

// Transparent public proof for transcript-direct SEND violations.
// The proof carries canonical public transfer evidence; authenticity comes
// from the sender's Ed25519 signature, not from MPI or from a ZK system.
class Ed25519PublicTransferBlameProofBackend final
    : public PublicTransferBlameProofBackend {
public:
    Digest ProductionCapabilityBinding() const override;
    ExternalPublicBlameProof Prove(
        const std::vector<u64>& public_inputs,
        const std::vector<u64>& transfer_evidence) const override;

    bool Verify(
        const std::vector<u64>& public_inputs,
        const ExternalPublicBlameProof& proof) const override;

    bool VerifyAnchored(
        const std::vector<u64>& public_inputs,
        const ExternalPublicBlameProof& proof,
        const Digest& expected_registry_anchor) const;
};

} // namespace pvia
