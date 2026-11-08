#include "SecureAuditBackend.hpp"

namespace pvia {

void SecureAuditBackend::OnImportStateMetadata(
    const AuditStateView& state) {
    provider_.RegisterStateMetadata(state);
}

void SecureAuditBackend::OnBindPrivateState(
    const AuditStateView& state, const std::vector<F>& local_share) {
    provider_.BindPrivateState(state, local_share);
}

void SecureAuditBackend::OnBindPrivateStateSegments(
    const AuditStateView& state, const std::vector<F>& local_share,
    const std::vector<size_t>& segment_lengths) {
    provider_.BindPrivateStateSegments(state, local_share, segment_lengths);
}

bool SecureAuditBackend::OnBindPrivateStateAuthentication(
    const AuditStateView& state, uint64_t scheme_id,
    const Digest& authentication_binding) {
    return provider_.BindPrivateStateAuthentication(
        state, scheme_id, authentication_binding);
}

void SecureAuditBackend::OnBindPrivateFieldOperation(
    const AuditOperationView& operation, AuditPrivatePayloadKind kind,
    AuditPayloadStage stage, const std::vector<F>& values) {
    provider_.BindPrivateFieldOperation(operation, kind, stage, values);
}

void SecureAuditBackend::OnBindPrivateWordOperation(
    const AuditOperationView& operation, AuditPayloadStage stage,
    const std::vector<u64>& values) {
    provider_.BindPrivateWordOperation(operation, stage, values);
}

void SecureAuditBackend::OnBindOperationStateDependencies(
    const AuditOperationView& operation,
    const std::vector<StateId>& state_ids) {
    provider_.BindOperationStateDependencies(operation, state_ids);
}

void SecureAuditBackend::OnBindPublicFieldAux(
    const AuditOperationView& operation, AuditPublicAuxKind kind,
    const std::vector<F>& values) {
    provider_.BindPublicFieldAux(operation, kind, values);
}

void SecureAuditBackend::OnBindPublicWordAux(
    const AuditOperationView& operation, AuditPublicAuxKind kind,
    const std::vector<u64>& values) {
    provider_.BindPublicWordAux(operation, kind, values);
}

void SecureAuditBackend::OnFinalizePrivateRelation(
    const AuditOperationView& operation) {
    provider_.FinalizePrivateRelation(operation);
}

void SecureAuditBackend::OnRegisterOperation(
    const AuditOperationView& operation) {
    provider_.RegisterOperation(operation);
}

void SecureAuditBackend::OnActivateOperation(
    const AuditOperationView& operation) {
    provider_.ActivateOperation(operation);
}

void SecureAuditBackend::OnSealCheckpoint(
    const AuditCheckpointView& checkpoint) {
    provider_.SealCheckpoint(checkpoint);
}

void SecureAuditBackend::OnObservePublicTransfer(
    const PublicTransferObservation& observation) {
    provider_.ObservePublicTransfer(observation);
}

bool SecureAuditBackend::RequiresCollectiveFailureHandling() const {
    return provider_.RequiresCollectiveFailureHandling();
}

ObligationSet SecureAuditBackend::SynchronizeFailureScope(
    const ObligationSet& local_scope, int rank, int world_size) const {
    return provider_.SynchronizeFailureScope(local_scope, rank, world_size);
}

bool SecureAuditBackend::GetLastRobustTermination(
    RobustAuditTerminationOutput* output) const {
    return provider_.GetLastRobustTermination(output);
}

bool SecureAuditBackend::GetLastRobustAbortCertificate(
    RobustAuditAbortCertificate* certificate) const {
    return provider_.GetLastRobustAbortCertificate(certificate);
}

BatchCheckResult SecureAuditBackend::BatchCheck(
    const ObligationSet& scope) const {
    return provider_.PrivateBatchCheck(scope);
}

Violation SecureAuditBackend::Dispute(
    const ObligationSet& scope,
    const BatchCheckResult& batch) const {
    return provider_.PrivateDispute(scope, batch);
}

RecoverableAuditShare SecureAuditBackend::RecoverAudit(
    const Violation& violation) const {
    return provider_.RecoverAuthenticatedAudit(violation);
}

BlameCertificate SecureAuditBackend::LiftBlame(
    const Violation& violation,
    const RecoverableAuditShare& audit) const {
    return provider_.ProvePublicBlame(violation, audit);
}

bool SecureAuditBackend::Judge(
    const BlameCertificate& certificate,
    uint64_t expected_session_id) const {
    return provider_.VerifyPublicBlame(certificate, expected_session_id);
}

bool SecureAuditBackend::ReadRelationProofReceipt(
    AuditRelationKernel kernel,
    AuditRelationProofReceipt* receipt) const {
    if (!receipt) return false;
    *receipt = AuditRelationProofReceipt{};
    return provider_.ReadRelationProofReceipt(kernel, receipt);
}

} // namespace pvia
