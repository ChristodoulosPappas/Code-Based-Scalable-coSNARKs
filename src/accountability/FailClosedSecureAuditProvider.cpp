#include "FailClosedSecureAuditProvider.hpp"

namespace pvia {

void FailClosedSecureAuditProvider::RegisterStateMetadata(
    const AuditStateView&) {}

void FailClosedSecureAuditProvider::BindPrivateState(
    const AuditStateView&, const std::vector<F>&) {}

bool FailClosedSecureAuditProvider::BindPrivateStateAuthentication(
    const AuditStateView&, uint64_t, const Digest&) {
    return false;
}

void FailClosedSecureAuditProvider::BindPrivateFieldOperation(
    const AuditOperationView&, AuditPrivatePayloadKind, AuditPayloadStage,
    const std::vector<F>&) {}

void FailClosedSecureAuditProvider::BindPrivateWordOperation(
    const AuditOperationView&, AuditPayloadStage, const std::vector<u64>&) {}

void FailClosedSecureAuditProvider::BindOperationStateDependencies(
    const AuditOperationView&, const std::vector<StateId>&) {}

void FailClosedSecureAuditProvider::BindPublicFieldAux(
    const AuditOperationView&, AuditPublicAuxKind, const std::vector<F>&) {}

void FailClosedSecureAuditProvider::BindPublicWordAux(
    const AuditOperationView&, AuditPublicAuxKind, const std::vector<u64>&) {}

void FailClosedSecureAuditProvider::FinalizePrivateRelation(
    const AuditOperationView&) {}

void FailClosedSecureAuditProvider::RegisterOperation(
    const AuditOperationView&) {}

void FailClosedSecureAuditProvider::ActivateOperation(
    const AuditOperationView&) {}

void FailClosedSecureAuditProvider::SealCheckpoint(
    const AuditCheckpointView&) {}

void FailClosedSecureAuditProvider::ObservePublicTransfer(
    const PublicTransferObservation&) {}

bool FailClosedSecureAuditProvider::RequiresCollectiveFailureHandling() const {
    return false;
}

ObligationSet FailClosedSecureAuditProvider::SynchronizeFailureScope(
    const ObligationSet& local_scope, int, int) const {
    return local_scope;
}

BatchCheckResult FailClosedSecureAuditProvider::PrivateBatchCheck(
    const ObligationSet& scope) const {
    BatchCheckResult result;
    result.available = false;
    result.cryptographically_authenticated = false;
    result.ok = false;
    result.checkpoint = scope.checkpoint;
    return result;
}

Violation FailClosedSecureAuditProvider::PrivateDispute(
    const ObligationSet&, const BatchCheckResult&) const {
    return Violation{};
}

RecoverableAuditShare
FailClosedSecureAuditProvider::RecoverAuthenticatedAudit(
    const Violation&) const {
    return RecoverableAuditShare{};
}

BlameCertificate FailClosedSecureAuditProvider::ProvePublicBlame(
    const Violation&, const RecoverableAuditShare&) const {
    return BlameCertificate{};
}

bool FailClosedSecureAuditProvider::VerifyPublicBlame(
    const BlameCertificate&, uint64_t) const {
    return false;
}

} // namespace pvia
