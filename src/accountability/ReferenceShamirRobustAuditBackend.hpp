#pragma once

#include "RobustAuditSession.hpp"
#include "ReferenceShamirAuditSession.hpp"

#include <memory>
#include <vector>

namespace pvia {

// Development adapter for exercising the Route-A robust-session boundary with
// genuine distributed Shamir/BGW computation. It is intentionally PASSIVE:
// Capabilities() can never satisfy the production PRIVATE secure gate.
class ReferenceShamirRobustAuditBackend final
    : public RobustAuditSessionBackend {
public:
    ReferenceShamirRobustAuditBackend(
        int rank, int world_size, int threshold,
        const RegistrationConsistencyProofBackend*
            registration_consistency_backend = nullptr,
        const MultiplicationConsistencyProofBackend*
            multiplication_consistency_backend = nullptr,
        const AuthenticatedMpcExchange*
            authenticated_exchange = nullptr);

    RobustAuditCapabilities Capabilities() const override;
    RobustAuditActivation Activate(
        const AuditCheckpointView& checkpoint,
        const PrivateStateMaterialStore& states,
        const PrivateAuditMaterialStore& materials) override;
    RobustAuditSessionOutput Execute(
        const ObligationSet& scope,
        int rank,
        int world_size) override;
    RobustAuditAbortOutput ReconcileAbortCollectively(
        const AuditCheckpointView& checkpoint,
        const RobustAuditActivation* activation,
        int rank, int world_size) override;
    RobustAuditAbortOutput LastAbort() const override;
    bool LastAuthenticatedTransportFailure(
        const AuditCheckpointView& checkpoint,
        const RobustAuditActivation* activation,
        Digest* failure_binding) const override;
    bool VerifyPublicAbort(
        const AuditCheckpointView& checkpoint,
        const RobustAuditActivation* activation,
        const RobustAuditAbortOutput& output) const override;
    bool VerifyPublicBlame(
        const PublicBlameStatement& statement,
        const PublicBlameProofArtifact& proof) const override;
private:
    struct Entry {
        CheckpointId checkpoint = 0;
        uint64_t sid = 0;
        AuditCheckpointView checkpoint_view{};
        RobustAuditActivation activation{};
        std::unique_ptr<ReferenceShamirAuditSession> session;
        std::vector<OperationRef> operations;
    };

    Entry* FindEntry(CheckpointId checkpoint, uint64_t sid);
    const Entry* FindEntry(CheckpointId checkpoint, uint64_t sid) const;
    Entry* FindEntryForCheckpoint(const AuditCheckpointView& checkpoint);
    const Entry* FindEntryForCheckpoint(
        const AuditCheckpointView& checkpoint) const;
    AuthenticatedMpcMessageContext NextTransportContext(
        uint64_t namespace_sid, CheckpointId checkpoint,
        u64 message_kind, uint64_t round = 0) const;

    int rank_ = -1;
    int world_size_ = 0;
    int threshold_ = -1;
    const RegistrationConsistencyProofBackend*
        registration_consistency_backend_ = nullptr;
    const MultiplicationConsistencyProofBackend*
        multiplication_consistency_backend_ = nullptr;
    const AuthenticatedMpcExchange* authenticated_exchange_ = nullptr;
    mutable uint64_t transport_sequence_ = 1;
    RobustAuditCapabilities capabilities_{};
    RobustAuditAbortOutput last_abort_{};
    AuditCheckpointView last_checkpoint_view_{};
    std::vector<Entry> entries_;
};

} // namespace pvia
