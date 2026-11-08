#pragma once

#include "Ed25519PublicTransferBlameProofBackend.hpp"
#include "Ed25519PublicTransferCheckBackend.hpp"
#include "SecureAuditComposition.hpp"

namespace pvia {

// Owns the concrete PUBLIC_TRANSFER components and installs them through the
// standard secure composition boundary. PRIVATE_RECOVERY remains unavailable.
class Ed25519TransferSecureRuntime {
public:
    Ed25519TransferSecureRuntime();

    bool ready() const { return bundle_.ready(); }
    bool Attach(Runtime& runtime) { return bundle_.Attach(runtime); }
    void Detach() { bundle_.Detach(); }
    bool SessionAuthenticationReady(bool require_external_anchor) const;
    bool RunFailureHandlerSelfTest(Runtime& runtime, int rank, int world_size);

    SecureAuditBackend& backend() { return bundle_.backend(); }
    const SecureAuditBackend& backend() const { return bundle_.backend(); }

private:
    Ed25519PublicTransferCheckBackend check_backend_;
    BackendPublicTransferCheckEngine check_engine_;
    Ed25519PublicTransferBlameProofBackend proof_backend_;
    BackendPublicTransferBlameProofEngine proof_engine_;
    SecureAuditRuntimeBundle bundle_;
};

} // namespace pvia
