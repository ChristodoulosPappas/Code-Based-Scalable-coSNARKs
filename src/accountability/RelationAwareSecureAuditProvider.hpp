#pragma once

#include "PrivateAuditMaterialStore.hpp"
#include "PrivateStateMaterialStore.hpp"
#include "PrivateResidualRegistry.hpp"
#include "KernelResidualEvaluator.hpp"
#include "CollectiveResidualEngine.hpp"
#include "AuthenticatedAuditRecovery.hpp"
#include "PublicBlameProof.hpp"
#include "PublicJudge.hpp"
#include "TransferAuthentication.hpp"
#include "MpiAuditScopeSynchronizer.hpp"
#include "AuditScopeClassifier.hpp"
#include "PublicTransferCheckEngine.hpp"
#include "MpiPublicTransferObservationExchange.hpp"
#include "PublicTransferEvidence.hpp"
#include "PublicTransferBlameProof.hpp"
#include "HybridAuditCheck.hpp"
#include "SecureAuditBackend.hpp"
#include "RobustAuditSession.hpp"
#include "RobustAuditAbortCertificateCodec.hpp"

namespace pvia {

// Reusable base for a concrete secure audit provider. It organizes local-only
// private material and dispatches relation-specific residual evaluation, but
// does not itself implement MPC, authenticated sharing, ZK, or blame proofs.
class RelationAwareSecureAuditProvider : public SecureAuditProvider {
public:
    void RegisterStateMetadata(const AuditStateView& state) final {
        if (state_store_.RegisterMetadata(state))
            OnStoredStateMetadata(state);
    }

    void BindPrivateState(
        const AuditStateView& state,
        const std::vector<F>& local_share) final {
        if (!capture_private_material_) return;
        if (state_store_.BindPrivateState(state, local_share))
            OnStoredPrivateState(state, local_share);
    }

    void BindPrivateStateSegments(
        const AuditStateView& state, const std::vector<F>& local_share,
        const std::vector<size_t>& segment_lengths) final {
        if (!capture_private_material_) return;
        if (state_store_.BindPrivateStateSegments(
                state, local_share, segment_lengths))
            OnStoredPrivateStateSegments(state, local_share, segment_lengths);
    }

    bool BindPrivateStateAuthentication(
        const AuditStateView& state, uint64_t scheme_id,
        const Digest& authentication_binding) final {
        if (!capture_private_material_) return false;
        if (!state_store_.BindAuthentication(
                state, scheme_id, authentication_binding))
            return false;
        OnStoredPrivateStateAuthentication(
            state, scheme_id, authentication_binding);
        return true;
    }

    bool RequiresCollectiveFailureHandling() const final { return true; }
    ObligationSet SynchronizeFailureScope(
        const ObligationSet& local_scope, int rank, int world_size) const final {
        collective_rank_ = rank;
        collective_world_size_ = world_size;
        last_failure_scope_ = SynchronizeCollectiveScope(
            local_scope, rank, world_size);
        return last_failure_scope_;
    }

    bool GetLastRobustTermination(
        RobustAuditTerminationOutput* output) const final {
        if (!output || !last_robust_termination_valid_) return false;
        *output = last_robust_termination_;
        return true;
    }

    bool GetLastRobustAbortCertificate(
        RobustAuditAbortCertificate* certificate) const final {
        if (!certificate || !last_robust_abort_valid_ ||
            !last_robust_termination_valid_ ||
            last_robust_termination_.kind !=
                RobustAuditTerminationKind::PUBLICLY_ATTRIBUTABLE_ABORT ||
            last_robust_termination_.checkpoint != last_robust_abort_.checkpoint ||
            last_robust_termination_.public_abort_binding !=
                last_robust_abort_.abort_binding)
            return false;
        const AuditCheckpointView* checkpoint =
            FindCheckpointView(last_robust_abort_.checkpoint);
        if (!checkpoint) return false;

        RobustAuditAbortCertificate candidate;
        candidate.checkpoint = *checkpoint;
        candidate.capabilities = RobustCapabilities();
        candidate.output = last_robust_abort_;
        if (last_robust_abort_.stage == RobustAuditAbortStage::EXECUTION) {
            const RobustAuditActivation* activation =
                FindRobustActivation(last_robust_abort_.checkpoint);
            if (!activation) return false;
            candidate.has_activation = true;
            candidate.activation = *activation;
        } else if (last_robust_abort_.stage !=
                   RobustAuditAbortStage::ACTIVATION) {
            return false;
        }
        // last_robust_abort_valid_ is set only after VerifyPublicAbort() has
        // succeeded for this checkpoint/activation.  Return the assembled
        // artifact here without re-running full certificate verification; the
        // Runtime/Judge boundary verifies the complete certificate exactly once
        // before publication or external use.
        *certificate = candidate;
        return true;
    }

    BatchCheckResult PrivateBatchCheck(
        const ObligationSet& scope) const final {
        BatchCheckResult unavailable;
        unavailable.available = false;
        unavailable.cryptographically_authenticated = false;
        unavailable.ok = false;
        unavailable.checkpoint = scope.checkpoint;

        last_scope_partition_ = AuditScopePartition{};
        last_private_batch_ = BatchCheckResult{};
        last_transfer_check_ = PublicTransferCheckResult{};
        last_transfer_dispute_ = CollectiveDisputeResult{};
        last_transfer_observation_ = PublicTransferObservation{};
        last_transfer_observation_valid_ = false;
        last_hybrid_components_ = HybridAuditBatchComponents{};
        last_hybrid_batch_ = unavailable;
        last_robust_output_ = RobustAuditSessionOutput{};
        const bool preserve_activation_termination =
            last_robust_termination_valid_ &&
            last_robust_termination_.checkpoint == scope.checkpoint &&
            last_robust_termination_.stage == RobustAuditAbortStage::ACTIVATION &&
            (last_robust_termination_.kind !=
                 RobustAuditTerminationKind::PUBLICLY_ATTRIBUTABLE_ABORT ||
             (last_robust_abort_valid_ &&
              last_robust_abort_.checkpoint == scope.checkpoint &&
              last_robust_termination_.public_abort_binding ==
                  last_robust_abort_.abort_binding));
        const bool preserve_activation_public_abort =
            preserve_activation_termination &&
            last_robust_termination_.kind ==
                RobustAuditTerminationKind::PUBLICLY_ATTRIBUTABLE_ABORT;
        if (!preserve_activation_public_abort) {
            last_robust_abort_ = RobustAuditAbortOutput{};
            last_robust_abort_valid_ = false;
        }
        if (!preserve_activation_termination) {
            last_robust_termination_ = RobustAuditTerminationOutput{};
            last_robust_termination_valid_ = false;
        }
        last_private_used_robust_session_ = false;

        const AuditScopePartition partition = partition_audit_scope(
            scope, [this](const OperationRef& ref) {
                return ClassifyOperationForAudit(ref);
            });
        last_scope_partition_ = partition;
        if (!partition.complete) return unavailable;

        HybridAuditBatchComponents components;
        // A missing lane is unavailable, not successful.  Only installed
        // cryptographic lanes participate in the envelope.  This lets a
        // transfer-only composition independently attribute a signed SEND
        // mismatch while leaving unchecked private causes non-attributable.
        components.private_present = capture_private_material_ &&
            !partition.private_scope.operations.empty() &&
            (RobustPrivateRouteReady() || collective_engine_);
        components.transfer_present = transfer_engine_ &&
            !partition.transfer_scope.operations.empty();
        if (!components.private_present && !components.transfer_present)
            return unavailable;

        if (components.private_present) {
            if (RobustPrivateRouteReady()) {
                const RobustAuditActivation* activation =
                    FindRobustActivation(partition.private_scope.checkpoint);
                if (!activation) return unavailable;
                last_robust_termination_ = RobustAuditTerminationOutput{};
                last_robust_termination_valid_ = false;
                last_robust_output_ = robust_session_backend_->Execute(
                    partition.private_scope, collective_rank_,
                    collective_world_size_);
                const bool robust_output_valid =
                    validate_robust_audit_session_output(
                        partition.private_scope, RobustCapabilities(),
                        *activation, last_robust_output_,
                        collective_world_size_) &&
                    (last_robust_output_.clean ||
                     robust_session_backend_->VerifyPublicBlame(
                         last_robust_output_.statement,
                         last_robust_output_.proof));
                if (!robust_output_valid) {
                    const AuditCheckpointView* checkpoint =
                        FindCheckpointView(partition.private_scope.checkpoint);
                    RobustAuditAbortOutput abort;
                    // PrivateBatchCheck runs after failure-scope synchronization.
                    // Give the backend one explicit collective opportunity to
                    // reconcile redacted observations before falling back to
                    // its local-only abort cache.
                    if (checkpoint &&
                        production_ready_identifiable_abort_capabilities(
                            RobustCapabilities())) {
                        abort = robust_session_backend_->ReconcileAbortCollectively(
                            *checkpoint, activation,
                            collective_rank_, collective_world_size_);
                    }
                    if (!abort.available)
                        abort = robust_session_backend_->LastAbort();
                    if (checkpoint && abort.available &&
                        robust_session_backend_->VerifyPublicAbort(
                            *checkpoint, activation, abort)) {
                        last_robust_abort_ = abort;
                        last_robust_termination_valid_ =
                            build_robust_audit_termination_from_verified_public_abort(
                                *checkpoint, RobustCapabilities(), activation, abort,
                                &last_robust_termination_);
                        last_robust_abort_valid_ = last_robust_termination_valid_;
                        if (!last_robust_abort_valid_)
                            last_robust_abort_ = RobustAuditAbortOutput{};
                    }
                    if (checkpoint && !last_robust_termination_valid_) {
                        Digest local_failure_binding{};
                        if (robust_session_backend_->LastAuthenticatedTransportFailure(
                                *checkpoint, activation, &local_failure_binding)) {
                            last_robust_termination_valid_ =
                                build_robust_audit_transport_failure_termination(
                                    *checkpoint, RobustCapabilities(), activation,
                                    RobustAuditAbortStage::EXECUTION,
                                    local_failure_binding,
                                    &last_robust_termination_);
                        }
                    }
                    if (checkpoint && !last_robust_termination_valid_) {
                        last_robust_termination_valid_ =
                            build_robust_audit_unattributable_abort_termination(
                                *checkpoint, RobustCapabilities(), activation,
                                RobustAuditAbortStage::EXECUTION,
                                RobustAuditUnattributableAbortReason::EXECUTION_UNAVAILABLE,
                                &last_robust_termination_);
                    }
                    return unavailable;
                }
                const AuditCheckpointView* completed_checkpoint =
                    FindCheckpointView(partition.private_scope.checkpoint);
                if (!completed_checkpoint ||
                    !build_robust_audit_termination_from_validated_session_output(
                        *completed_checkpoint, RobustCapabilities(), *activation,
                        last_robust_output_, &last_robust_termination_))
                    return unavailable;
                last_robust_termination_valid_ = true;
                components.private_result = last_robust_output_.batch;
                last_private_used_robust_session_ = true;
            } else {
                if (!collective_engine_) return unavailable;
                const LocalResidualBatchView local_view =
                    residual_registry_.BuildLocalBatchView(
                        partition.private_scope,
                        static_cast<uint32_t>(collective_rank_));
                if (!local_view.complete_for_owner || !local_view.all_authenticated)
                    return unavailable;
                components.private_result = collective_engine_->BatchCheck(
                    partition.private_scope, local_view,
                    collective_rank_, collective_world_size_);
                if (!validate_collective_batch_result(
                        partition.private_scope, components.private_result,
                        collective_world_size_))
                    return unavailable;
            }
            last_private_batch_ = components.private_result;
        }
        if (components.transfer_present) {
            if (!transfer_engine_) return unavailable;
            components.transfer_result = transfer_engine_->Check(
                partition.transfer_scope, transfer_store_,
                collective_rank_, collective_world_size_);
            if (!validate_public_transfer_check_result(
                    partition.transfer_scope, components.transfer_result))
                return unavailable;
            last_transfer_check_ = components.transfer_result;
        }

        const BatchCheckResult hybrid = make_hybrid_audit_batch_envelope(
            scope, partition, components, collective_world_size_);
        if (!validate_hybrid_audit_batch_envelope(
                scope, partition, components, hybrid,
                collective_world_size_))
            return unavailable;
        last_hybrid_components_ = components;
        last_hybrid_batch_ = hybrid;
        return hybrid;
    }

    Violation PrivateDispute(
        const ObligationSet& scope,
        const BatchCheckResult& batch) const final {
        if (!validate_hybrid_audit_batch_envelope(
                scope, last_scope_partition_, last_hybrid_components_,
                batch, collective_world_size_))
            return Violation{};
        const bool private_failed =
            last_hybrid_components_.private_present &&
            !last_private_batch_.ok;
        const bool transfer_failed =
            last_hybrid_components_.transfer_present &&
            !last_transfer_check_.ok;

        if (!private_failed && !transfer_failed) return Violation{};
        // Two independent authenticated boundaries failed. Without an
        // additional cross-lane attribution proof, selecting either lane
        // would risk framing, so fail closed.
        if (private_failed && transfer_failed) return Violation{};

        if (private_failed) {
            if (last_private_used_robust_session_) {
                if (!last_robust_output_.available ||
                    last_robust_output_.clean ||
                    !last_robust_output_.violation.valid ||
                    last_robust_output_.violation.checkpoint != scope.checkpoint)
                    return Violation{};
                return last_robust_output_.violation;
            }
            if (!collective_engine_) return Violation{};
            const LocalResidualBatchView local_view =
                residual_registry_.BuildLocalBatchView(
                    last_scope_partition_.private_scope,
                    static_cast<uint32_t>(collective_rank_));
            if (!local_view.complete_for_owner || !local_view.all_authenticated)
                return Violation{};
            const CollectiveDisputeResult located = collective_engine_->Dispute(
                last_scope_partition_.private_scope, last_private_batch_,
                local_view, collective_rank_, collective_world_size_);
            if (!validate_collective_dispute_result(
                    last_scope_partition_.private_scope,
                    last_private_batch_, located))
                return Violation{};
            const Violation violation =
                materialize_collective_violation(located);
            if (!violation.valid ||
                violation.dispute_binding !=
                    compute_collective_dispute_binding(located))
                return Violation{};
            return violation;
        }

        if (!transfer_engine_) return Violation{};
        const CollectiveDisputeResult located = transfer_engine_->Dispute(
            last_scope_partition_.transfer_scope, last_transfer_check_,
            transfer_store_, collective_rank_, collective_world_size_);
        if (!validate_public_transfer_dispute_result(
                last_scope_partition_.transfer_scope,
                last_transfer_check_, located))
            return Violation{};
        PublicTransferObservation observation;
        if (!MpiPublicTransferObservationExchange::Resolve(
                transfer_store_, last_scope_partition_.transfer_scope, located,
                collective_rank_, collective_world_size_, &observation))
            return Violation{};
        last_transfer_observation_ = observation;
        last_transfer_observation_valid_ = true;
        last_transfer_dispute_ = located;
        const Violation violation = materialize_collective_violation(located);
        if (!violation.valid ||
            violation.dispute_binding != compute_collective_dispute_binding(located))
            return Violation{};
        return violation;
    }

    RecoverableAuditShare RecoverAuthenticatedAudit(
        const Violation& violation) const final {
        RecoverableAuditShare unavailable;
        if (!violation.valid || violation.dispute_binding == Digest{} ||
            last_failure_scope_.checkpoint != violation.checkpoint ||
            last_failure_scope_.checkpoint_root == Digest{})
            return unavailable;

        if (classify_audit_relation(violation.relation) ==
            AuditScopeLane::PUBLIC_TRANSFER) {
            if (!validate_public_transfer_dispute_result(
                    last_scope_partition_.transfer_scope,
                    last_transfer_check_, last_transfer_dispute_))
                return unavailable;
            if (!last_transfer_observation_valid_ ||
                !public_transfer_observation_supports_dispute(
                    last_transfer_observation_, last_transfer_dispute_))
                return unavailable;
            const PublicTransferObservation& observation =
                last_transfer_observation_;
            const PublicTransferEvidence evidence =
                make_public_transfer_evidence(
                    violation, last_scope_partition_.transfer_scope,
                    last_transfer_check_, last_transfer_dispute_, observation);
            if (!validate_public_transfer_evidence(
                    violation, last_scope_partition_.transfer_scope,
                    last_transfer_check_, last_transfer_dispute_, observation,
                    evidence))
                return unavailable;
            CacheTransferEvidence(evidence);
            RecoverableAuditShare audit;
            audit.valid = true;
            audit.debug_only = false;
            audit.evidence_kind = AuditEvidenceKind::PUBLIC_TRANSFER;
            audit.label = violation.label;
            audit.relation = violation.relation;
            audit.kernel = violation.kernel;
            audit.expected = violation.expected;
            audit.actual = violation.actual;
            audit.residual_commitment = violation.residual_commitment;
            audit.operation_statement_binding = violation.operation_statement_binding;
            audit.dispute_binding = violation.dispute_binding;
            audit.predecessor_root = Digest{};
            audit.checkpoint_root = evidence.checkpoint_root;
            audit.witness_digest = evidence.evidence_binding;
            return audit;
        }

        if (last_private_used_robust_session_) {
            if (!last_robust_output_.available || last_robust_output_.clean ||
                !last_robust_output_.violation.valid ||
                last_robust_output_.violation.dispute_binding !=
                    violation.dispute_binding ||
                last_robust_output_.violation.label.owner !=
                    violation.label.owner ||
                last_robust_output_.violation.label.object_id !=
                    violation.label.object_id)
                return unavailable;
            const AuthenticatedRecoveryArtifact& artifact =
                last_robust_output_.recovery;
            AuditCheckpointView checkpoint;
            checkpoint.id = last_failure_scope_.checkpoint;
            checkpoint.phase = last_failure_scope_.phase;
            checkpoint.round = last_failure_scope_.round;
            checkpoint.generation = last_failure_scope_.generation;
            checkpoint.operations = last_failure_scope_.operations;
            checkpoint.root = last_failure_scope_.checkpoint_root;
            checkpoint.sealed = true;
            const AuthenticatedRecoveryRequest request =
                make_recovery_request(violation, checkpoint);
            if (request.request_binding == Digest{} ||
                !validate_recovery_artifact(request, artifact))
                return unavailable;
            CacheRecoveryArtifact(artifact);
            RecoverableAuditShare audit;
            audit.valid = true;
            audit.debug_only = false;
            audit.evidence_kind = AuditEvidenceKind::PRIVATE_RECOVERY;
            audit.label = violation.label;
            audit.relation = violation.relation;
            audit.kernel = violation.kernel;
            audit.expected = violation.expected;
            audit.actual = violation.actual;
            audit.residual_commitment = violation.residual_commitment;
            audit.operation_statement_binding =
                violation.operation_statement_binding;
            audit.dispute_binding = violation.dispute_binding;
            audit.predecessor_root = artifact.predecessor_root;
            audit.checkpoint_root = artifact.checkpoint_root;
            audit.witness_digest =
                compute_recovery_artifact_binding(artifact);
            return audit;
        }

        if (!recovery_engine_) return unavailable;
        AuditCheckpointView checkpoint;
        checkpoint.id = last_failure_scope_.checkpoint;
        checkpoint.phase = last_failure_scope_.phase;
        checkpoint.round = last_failure_scope_.round;
        checkpoint.generation = last_failure_scope_.generation;
        checkpoint.operations = last_failure_scope_.operations;
        checkpoint.root = last_failure_scope_.checkpoint_root;
        checkpoint.sealed = true;
        const AuthenticatedRecoveryRequest request =
            make_recovery_request(violation, checkpoint);
        if (request.request_binding == Digest{}) return unavailable;
        const AuthenticatedRecoveryArtifact artifact = recovery_engine_->Recover(
            request, collective_rank_, collective_world_size_);
        if (!validate_recovery_artifact(request, artifact)) return unavailable;
        CacheRecoveryArtifact(artifact);
        RecoverableAuditShare audit;
        audit.valid = true;
        audit.debug_only = false;
        audit.evidence_kind = AuditEvidenceKind::PRIVATE_RECOVERY;
        audit.label = violation.label;
        audit.relation = violation.relation;
        audit.kernel = violation.kernel;
        audit.expected = violation.expected;
        audit.actual = violation.actual;
        audit.residual_commitment = violation.residual_commitment;
        audit.operation_statement_binding = violation.operation_statement_binding;
        audit.dispute_binding = violation.dispute_binding;
        audit.predecessor_root = artifact.predecessor_root;
        audit.checkpoint_root = artifact.checkpoint_root;
        audit.witness_digest = compute_recovery_artifact_binding(artifact);
        return audit;
    }

    BlameCertificate ProvePublicBlame(
        const Violation& violation,
        const RecoverableAuditShare& audit) const final {
        BlameCertificate unavailable;
        if (!violation.valid || !audit.valid || audit.debug_only)
            return unavailable;

        PublicBlameStatement statement;
        PublicBlameProofArtifact proof;
        std::vector<u64> portable_recovery_words;
        if (audit.evidence_kind == AuditEvidenceKind::PRIVATE_RECOVERY) {
            const OperationRef ref{violation.label.owner, violation.label.object_id};
            const AuthenticatedRecoveryArtifact* recovery =
                FindRecoveryArtifact(ref);
            if (!recovery || !ValidateRecoveredAuditShare(
                    violation, audit, *recovery))
                return unavailable;
            portable_recovery_words =
                encode_authenticated_recovery_artifact(*recovery);
            if (portable_recovery_words.empty()) return unavailable;
            if (last_private_used_robust_session_) {
                if (!RobustPrivateRouteReady() ||
                    last_robust_output_.clean ||
                    last_robust_output_.violation.dispute_binding !=
                        violation.dispute_binding)
                    return unavailable;
                statement = last_robust_output_.statement;
                proof = last_robust_output_.proof;
                const PublicBlameStatement expected_statement =
                    make_public_blame_statement(violation, audit, *recovery);
                if (statement.statement_binding == Digest{} ||
                    expected_statement.statement_binding == Digest{} ||
                    statement.statement_binding !=
                        expected_statement.statement_binding ||
                    !validate_public_blame_proof_artifact(statement, proof) ||
                    !robust_session_backend_->VerifyPublicBlame(
                        statement, proof))
                    return unavailable;
            } else {
                if (!blame_proof_engine_) return unavailable;
                statement = make_public_blame_statement(
                    violation, audit, *recovery);
                if (statement.statement_binding == Digest{}) return unavailable;
                proof = blame_proof_engine_->Prove(statement, *recovery);
                if (!validate_public_blame_proof_artifact(statement, proof) ||
                    !blame_proof_engine_->Verify(statement, proof))
                    return unavailable;
            }
        } else if (audit.evidence_kind == AuditEvidenceKind::PUBLIC_TRANSFER) {
            if (!transfer_blame_proof_engine_) return unavailable;
            const OperationRef ref{violation.label.owner, violation.label.object_id};
            const PublicTransferEvidence* evidence = FindTransferEvidence(ref);
            if (!evidence || !ValidatePublicTransferAuditShare(
                    violation, audit, *evidence))
                return unavailable;
            statement = make_public_blame_statement(
                violation, audit, *evidence);
            if (statement.statement_binding == Digest{}) return unavailable;
            proof = transfer_blame_proof_engine_->Prove(statement, *evidence);
            if (!validate_public_blame_proof_artifact(statement, proof) ||
                !transfer_blame_proof_engine_->Verify(statement, proof))
                return unavailable;
        } else {
            return unavailable;
        }

        BlameCertificate cert;
        cert.valid = true;
        cert.debug_only = false;
        cert.evidence_kind = audit.evidence_kind;
        cert.sid = violation.label.sid;
        cert.accused = violation.responsible_rank;
        cert.label = violation.label;
        cert.checkpoint = violation.checkpoint;
        cert.relation = violation.relation;
        cert.kernel = violation.kernel;
        cert.expected = violation.expected;
        cert.actual = violation.actual;
        cert.residual_commitment = violation.residual_commitment;
        cert.operation_statement_binding = violation.operation_statement_binding;
        cert.dispute_binding = violation.dispute_binding;
        cert.predecessor_root = audit.predecessor_root;
        cert.checkpoint_root = audit.checkpoint_root;
        cert.audit_witness_digest = audit.witness_digest;
        cert.recovery_artifact_words = std::move(portable_recovery_words);
        cert.recovery_proof_system_id = proof.recovery_proof_system_id;
        cert.recovery_proof_statement_binding =
            proof.recovery_proof_statement_binding;
        cert.recovery_proof_artifact_commitment =
            proof.recovery_proof_artifact_commitment;
        cert.recovery_proof_statement_words =
            proof.recovery_proof_statement_words;
        cert.recovery_proof_artifact_bytes =
            proof.recovery_proof_artifact_bytes;
        cert.blame_statement_binding = statement.statement_binding;
        cert.public_proof_system_id = proof.proof_system_id;
        cert.public_proof_commitment = proof.proof_commitment;
        cert.public_proof_transcript_binding = proof.transcript_binding;
        cert.public_proof_words = proof.proof_words;
        cert.transcript_digest = proof.transcript_binding;
        cert.proof_digest = proof.proof_commitment;
        cert.predecessor_evidence_complete = false;
        if (!ValidateBuiltBlameCertificate(violation, audit, cert))
            return unavailable;
        return cert;
    }

    bool VerifyPublicBlame(
        const BlameCertificate& certificate,
        uint64_t expected_session_id) const final {
        if (!certificate.valid || certificate.debug_only ||
            certificate.sid != expected_session_id ||
            certificate.evidence_kind == AuditEvidenceKind::UNKNOWN)
            return false;
        const PublicBlameStatement statement =
            make_public_blame_statement(certificate);
        if (statement.statement_binding == Digest{} ||
            certificate.blame_statement_binding != statement.statement_binding)
            return false;
        PublicBlameProofArtifact proof;
        proof.available = true;
        proof.cryptographically_authenticated = true;
        proof.proof_system_id = certificate.public_proof_system_id;
        proof.statement_binding = certificate.blame_statement_binding;
        proof.proof_commitment = certificate.public_proof_commitment;
        proof.transcript_binding = certificate.public_proof_transcript_binding;
        proof.proof_words = certificate.public_proof_words;
        proof.recovery_proof_system_id = certificate.recovery_proof_system_id;
        proof.recovery_proof_statement_binding =
            certificate.recovery_proof_statement_binding;
        proof.recovery_proof_artifact_commitment =
            certificate.recovery_proof_artifact_commitment;
        proof.recovery_proof_statement_words =
            certificate.recovery_proof_statement_words;
        proof.recovery_proof_artifact_bytes =
            certificate.recovery_proof_artifact_bytes;
        if (!validate_public_blame_proof_artifact(statement, proof))
            return false;
        if (certificate.evidence_kind ==
            AuditEvidenceKind::PRIVATE_RECOVERY) {
            auto& authenticator = Ed25519TransferAuthenticator::instance();
            if (!authenticator.ready() ||
                !authenticator.ExternalRegistryAnchorVerified() ||
                authenticator.ExternalRegistryAnchor() !=
                    authenticator.RegistryCommitment() ||
                !PublicJudge::VerifyRecoveryReceipt(
                    certificate, authenticator.PublicKeys(),
                    authenticator.ExternalRegistryAnchor()) ||
                !PublicJudge::ValidateRecoveryRelationStatement(
                    certificate, certificate.recovery_proof_statement_words))
                return false;
            // Recheck the portable recovery artifact against the verifier's
            // independently pinned VSS registry/root configuration. The
            // target's Ed25519 receipt alone is not an independent VSS pin.
            const AuthenticatedRecoveryRequest recovery_request =
                make_recovery_request(certificate);
            AuthenticatedRecoveryArtifact recovery_artifact;
            if (!recovery_engine_ ||
                !decode_authenticated_recovery_artifact(
                    certificate.recovery_artifact_words, &recovery_artifact) ||
                !recovery_engine_->Verify(recovery_request, recovery_artifact))
                return false;
            // Groth16 verification is mandatory for every public recovery
            // certificate, independent of which blame-proof backend is used.
            if (!PublicJudge::VerifyRecoveryRelationProof(
                    certificate,
                    certificate.recovery_proof_statement_words))
                return false;
            if (RobustPrivateRouteReady())
                return robust_session_backend_ &&
                    robust_session_backend_->VerifyPublicBlame(
                        statement, proof);
            return blame_proof_engine_ &&
                blame_proof_engine_->Verify(statement, proof);
        }
        if (certificate.evidence_kind ==
            AuditEvidenceKind::PUBLIC_TRANSFER) {
            return transfer_blame_proof_engine_ &&
                transfer_blame_proof_engine_->Verify(statement, proof);
        }
        return false;
    }

    void RegisterOperation(const AuditOperationView& operation) final {
        material_store_.RegisterOperation(operation);
        OnStoredOperationRegistered(operation);
    }

    void ActivateOperation(const AuditOperationView& operation) final {
        material_store_.ActivateOperation(operation);
        OnStoredOperationActivated(operation);
    }

    void ObservePublicTransfer(
        const PublicTransferObservation& observation) final {
        transfer_store_.Put(observation);
        OnStoredPublicTransfer(observation);
    }

    void SealCheckpoint(const AuditCheckpointView& checkpoint) final {
        bool replaced = false;
        for (auto& current : checkpoint_views_) {
            if (current.id == checkpoint.id) {
                current = checkpoint;
                replaced = true;
                break;
            }
        }
        if (!replaced) checkpoint_views_.push_back(checkpoint);
        if (robust_session_backend_ && checkpoint.sealed &&
            CheckpointHasPrivateMaterial(checkpoint)) {
            last_robust_abort_ = RobustAuditAbortOutput{};
            last_robust_abort_valid_ = false;
            last_robust_termination_ = RobustAuditTerminationOutput{};
            last_robust_termination_valid_ = false;
            const RobustAuditCapabilities capabilities = RobustCapabilities();
            if (validate_robust_audit_capabilities(capabilities)) {
                const RobustAuditActivation activation =
                    robust_session_backend_->Activate(
                        checkpoint, state_store_, material_store_);
                if (validate_robust_audit_activation(
                        checkpoint, capabilities, activation)) {
                    CacheRobustActivation(activation);
                } else {
                    InvalidateRobustActivation(checkpoint.id);
                    const RobustAuditAbortOutput abort =
                        robust_session_backend_->LastAbort();
                    if (abort.available &&
                        robust_session_backend_->VerifyPublicAbort(
                            checkpoint, nullptr, abort)) {
                        last_robust_abort_ = abort;
                        last_robust_termination_valid_ =
                            build_robust_audit_termination_from_verified_public_abort(
                                checkpoint, capabilities, nullptr, abort,
                                &last_robust_termination_);
                        last_robust_abort_valid_ = last_robust_termination_valid_;
                        if (!last_robust_abort_valid_)
                            last_robust_abort_ = RobustAuditAbortOutput{};
                    }
                    if (!last_robust_termination_valid_) {
                        Digest local_failure_binding{};
                        if (robust_session_backend_->LastAuthenticatedTransportFailure(
                                checkpoint, nullptr, &local_failure_binding)) {
                            last_robust_termination_valid_ =
                                build_robust_audit_transport_failure_termination(
                                    checkpoint, capabilities, nullptr,
                                    RobustAuditAbortStage::ACTIVATION,
                                    local_failure_binding,
                                    &last_robust_termination_);
                        }
                    }
                    if (!last_robust_termination_valid_) {
                        last_robust_termination_valid_ =
                            build_robust_audit_unattributable_abort_termination(
                                checkpoint, capabilities, nullptr,
                                RobustAuditAbortStage::ACTIVATION,
                                RobustAuditUnattributableAbortReason::ACTIVATION_UNAVAILABLE,
                                &last_robust_termination_);
                    }
                }
            } else {
                InvalidateRobustActivation(checkpoint.id);
            }
        }
        OnStoredCheckpointSealed(checkpoint);
    }

    void BindPrivateFieldOperation(
        const AuditOperationView& operation, AuditPrivatePayloadKind kind,
        AuditPayloadStage stage, const std::vector<F>& values) final {
        if (!capture_private_material_) return;
        material_store_.BindPrivateField(operation, kind, stage, values);
        OnStoredPrivateField(operation, kind, stage, values);
    }
    void BindPrivateWordOperation(
        const AuditOperationView& operation, AuditPayloadStage stage,
        const std::vector<u64>& values) final {
        if (!capture_private_material_) return;
        material_store_.BindPrivateWords(operation, stage, values);
        OnStoredPrivateWords(operation, stage, values);
    }

    void BindOperationStateDependencies(
        const AuditOperationView& operation,
        const std::vector<StateId>& state_ids) final {
        material_store_.BindStateDependencies(operation, state_ids);
        OnStoredStateDependencies(operation, state_ids);
    }

    void BindPublicFieldAux(
        const AuditOperationView& operation, AuditPublicAuxKind kind,
        const std::vector<F>& values) final {
        material_store_.BindPublicFieldAux(operation, kind, values);
        OnStoredPublicFieldAux(operation, kind, values);
    }

    void BindPublicWordAux(
        const AuditOperationView& operation, AuditPublicAuxKind kind,
        const std::vector<u64>& values) final {
        material_store_.BindPublicWordAux(operation, kind, values);
        OnStoredPublicWordAux(operation, kind, values);
    }

    void FinalizePrivateRelation(
        const AuditOperationView& operation) final {
        if (!capture_private_material_) return;
        if (!material_store_.ReadyForResidual(operation.ref)) {
            FinalizeInvalidMaterial(operation);
            return;
        }
        const PrivateOperationMaterial* material =
            material_store_.Find(operation.ref);
        if (!material) {
            FinalizeInvalidMaterial(operation);
            return;
        }
        for (StateId state_id : material->state_dependencies) {
            if (!state_store_.VerifyDigest(state_id)) {
                FinalizeInvalidMaterial(operation);
                return;
            }
        }
        if (operation.kernel != AuditRelationKernel::UNKNOWN) {
            const KernelResidualContext context{operation, *material, state_store_};
            if (!validate_kernel_residual_material(context)) {
                FinalizeInvalidMaterial(operation);
                return;
            }
        }
        const PrivateResidualHandle handle = EvaluateResidual(operation, *material);
        if (!handle.available || handle.ref != operation.ref ||
            handle.relation != operation.relation ||
            handle.kernel != operation.kernel) {
            FinalizeUnavailableResidual(operation, handle);
            return;
        }
        residual_registry_.Put(handle);
        material_store_.MarkFinalized(operation.ref);
        OnResidualFinalized(operation, handle);
    }
protected:
    void SetPrivateMaterialCapture(bool enabled) {
        capture_private_material_ = enabled;
    }
    bool CapturesPrivateMaterial() const { return capture_private_material_; }

    PrivateStateMaterialStore& state_store() { return state_store_; }
    const PrivateStateMaterialStore& state_store() const { return state_store_; }

    virtual void OnStoredStateMetadata(const AuditStateView&) {}
    virtual void OnStoredPrivateState(
        const AuditStateView&, const std::vector<F>&) {}
    virtual void OnStoredPrivateStateSegments(
        const AuditStateView& state, const std::vector<F>& local_share,
        const std::vector<size_t>&) {
        OnStoredPrivateState(state, local_share);
    }
    virtual void OnStoredPrivateStateAuthentication(
        const AuditStateView&, uint64_t, const Digest&) {}

    virtual ObligationSet SynchronizeCollectiveScope(
        const ObligationSet& local_scope, int rank, int world_size) const {
        const uint64_t sequence = failure_scope_sync_sequence_++;
        if (sequence == 0) return ObligationSet{};
        return MpiAuditScopeSynchronizer::SynchronizeAuthenticated(
            local_scope, rank, world_size, sequence);
    }

    PrivateAuditMaterialStore& material_store() { return material_store_; }
    const PrivateAuditMaterialStore& material_store() const {
        return material_store_;
    }
    const PrivateResidualRegistry& residual_registry() const {
        return residual_registry_;
    }
    void InstallKernelResidualEvaluator(
        const KernelResidualEvaluator* evaluator) {
        kernel_evaluators_.Add(evaluator);
    }
    bool HasKernelResidualEvaluator(AuditRelationKernel kernel) const {
        return kernel_evaluators_.Has(kernel);
    }
    void InstallCollectiveResidualEngine(
        const CollectiveResidualEngine* engine) {
        collective_engine_ = engine;
    }
    bool HasCollectiveResidualEngine() const {
        return collective_engine_ != nullptr;
    }
    void InstallRobustAuditSessionBackend(
        RobustAuditSessionBackend* backend) {
        robust_session_backend_ = backend;
    }
    void SetRobustPrivateSecurityRequirement(
        RobustAuditSecurityLevel level) {
        robust_private_security_requirement_ = level;
    }
    RobustAuditSecurityLevel RobustPrivateSecurityRequirement() const {
        return robust_private_security_requirement_;
    }
    bool HasRobustAuditSessionBackend() const {
        return robust_session_backend_ != nullptr;
    }
    bool HasLastRobustAbort() const { return last_robust_abort_valid_; }
    const RobustAuditAbortOutput& LastRobustAbort() const {
        return last_robust_abort_;
    }
    bool HasLastRobustTermination() const {
        return last_robust_termination_valid_;
    }
    const RobustAuditTerminationOutput& LastRobustTermination() const {
        return last_robust_termination_;
    }
    void InstallPublicTransferCheckEngine(
        const PublicTransferCheckEngine* engine) {
        transfer_engine_ = engine;
    }
    bool HasPublicTransferCheckEngine() const {
        return transfer_engine_ != nullptr;
    }
    const PublicTransferObservationStore& transfer_store() const {
        return transfer_store_;
    }
    void InstallAuthenticatedAuditRecoveryEngine(
        const AuthenticatedAuditRecoveryEngine* engine) {
        recovery_engine_ = engine;
    }
    bool HasAuthenticatedAuditRecoveryEngine() const {
        return recovery_engine_ != nullptr;
    }
    void InstallPublicBlameProofEngine(
        const PublicBlameProofEngine* engine) {
        blame_proof_engine_ = engine;
    }
    bool HasPublicBlameProofEngine() const {
        return blame_proof_engine_ != nullptr;
    }
    void InstallPublicTransferBlameProofEngine(
        const PublicTransferBlameProofEngine* engine) {
        transfer_blame_proof_engine_ = engine;
    }
    bool HasPublicTransferBlameProofEngine() const {
        return transfer_blame_proof_engine_ != nullptr;
    }
    const AuthenticatedRecoveryArtifact* FindRecoveryArtifact(
        const OperationRef& ref) const {
        for (const auto& entry : recovery_artifacts_)
            if (entry.first == ref) return &entry.second;
        return nullptr;
    }
    const PublicTransferEvidence* FindTransferEvidence(
        const OperationRef& ref) const {
        for (const auto& entry : transfer_evidence_)
            if (entry.first == ref) return &entry.second;
        return nullptr;
    }

    virtual void OnStoredOperationRegistered(const AuditOperationView&) {}
    virtual void OnStoredOperationActivated(const AuditOperationView&) {}
    virtual void OnStoredCheckpointSealed(const AuditCheckpointView&) {}
    virtual void OnStoredPublicTransfer(const PublicTransferObservation&) {}
    virtual void OnStoredPrivateField(
        const AuditOperationView&, AuditPrivatePayloadKind,
        AuditPayloadStage, const std::vector<F>&) {}
    virtual void OnStoredPrivateWords(
        const AuditOperationView&, AuditPayloadStage,
        const std::vector<u64>&) {}
    virtual void OnStoredStateDependencies(
        const AuditOperationView&, const std::vector<StateId>&) {}
    virtual void OnStoredPublicFieldAux(
        const AuditOperationView&, AuditPublicAuxKind,
        const std::vector<F>&) {}
    virtual void OnStoredPublicWordAux(
        const AuditOperationView&, AuditPublicAuxKind,
        const std::vector<u64>&) {}
    virtual void OnResidualFinalized(
        const AuditOperationView&, const PrivateResidualHandle&) {}
    virtual void FinalizeInvalidMaterial(const AuditOperationView&) = 0;
    virtual void FinalizeUnavailableResidual(
        const AuditOperationView&, const PrivateResidualHandle&) = 0;
    virtual PrivateResidualHandle EvaluatePrivateDerivationResidual(
        const AuditOperationView&) = 0;
    virtual PrivateResidualHandle EvaluateMessageBindingResidual(
        const AuditOperationView&) = 0;
    virtual PrivateResidualHandle EvaluateReceiveConsumeResidual(
        const AuditOperationView&) = 0;
    virtual PrivateResidualHandle EvaluateAssemblyResidual(
        const AuditOperationView&) = 0;
    virtual PrivateResidualHandle EvaluateAggregationResidual(
        const AuditOperationView&) = 0;
    virtual PrivateResidualHandle EvaluateCommitmentResidual(
        const AuditOperationView&) = 0;
    virtual PrivateResidualHandle EvaluateFoldingResidual(
        const AuditOperationView&) = 0;
    virtual PrivateResidualHandle EvaluateOpeningResidual(
        const AuditOperationView&) = 0;
    virtual PrivateResidualHandle EvaluatePublicationResidual(
        const AuditOperationView&) = 0;
    virtual PrivateResidualHandle EvaluateUnsupportedResidual(
        const AuditOperationView&) = 0;
    virtual PrivateResidualHandle EvaluateUnsupportedKernelResidual(
        const AuditOperationView&, AuditRelationKernel) = 0;

private:
    AuditScopeLane ClassifyOperationForAudit(
        const OperationRef& ref) const {
        const PrivateOperationMaterial* material = material_store_.Find(ref);
        const bool observed_transfer = transfer_store_.Has(ref);
        AuditScopeLane lane = AuditScopeLane::UNSUPPORTED;
        if (material) lane = classify_audit_relation(material->operation.relation);
        if (observed_transfer &&
            (lane == AuditScopeLane::PRIVATE_RESIDUAL ||
             lane == AuditScopeLane::PRIVATE_AND_TRANSFER))
            return AuditScopeLane::PRIVATE_AND_TRANSFER;
        if (lane != AuditScopeLane::UNSUPPORTED) return lane;
        return observed_transfer
            ? AuditScopeLane::PUBLIC_TRANSFER
            : AuditScopeLane::UNSUPPORTED;
    }

    RobustAuditCapabilities RobustCapabilities() const {
        return robust_session_backend_
            ? robust_session_backend_->Capabilities()
            : RobustAuditCapabilities{};
    }

    bool RobustPrivateRouteReady() const {
        if (!robust_session_backend_) return false;
        const RobustAuditCapabilities capabilities = RobustCapabilities();
        if (robust_private_security_requirement_ ==
            RobustAuditSecurityLevel::MALICIOUS_GOD)
            return production_ready_robust_audit_capabilities(capabilities);
        if (robust_private_security_requirement_ ==
            RobustAuditSecurityLevel::MALICIOUS_ABORT)
            return production_ready_identifiable_abort_capabilities(capabilities);
        return false;
    }

    bool CheckpointHasPrivateMaterial(
        const AuditCheckpointView& checkpoint) const {
        for (const OperationRef& ref : checkpoint.operations) {
            const PrivateOperationMaterial* material = material_store_.Find(ref);
            if (!material) continue;
            const AuditScopeLane lane =
                classify_audit_relation(material->operation.relation);
            if (lane == AuditScopeLane::PRIVATE_RESIDUAL ||
                lane == AuditScopeLane::PRIVATE_AND_TRANSFER)
                return true;
        }
        return false;
    }

    const AuditCheckpointView* FindCheckpointView(
        CheckpointId checkpoint) const {
        for (const auto& view : checkpoint_views_)
            if (view.id == checkpoint) return &view;
        return nullptr;
    }

    const RobustAuditActivation* FindRobustActivation(
        CheckpointId checkpoint) const {
        for (const auto& activation : robust_activations_)
            if (activation.checkpoint == checkpoint) return &activation;
        return nullptr;
    }

    void CacheRobustActivation(const RobustAuditActivation& activation) {
        for (auto& current : robust_activations_) {
            if (current.checkpoint == activation.checkpoint) {
                current = activation;
                return;
            }
        }
        robust_activations_.push_back(activation);
    }

    void InvalidateRobustActivation(CheckpointId checkpoint) {
        robust_activations_.erase(
            std::remove_if(robust_activations_.begin(), robust_activations_.end(),
                [checkpoint](const RobustAuditActivation& activation) {
                    return activation.checkpoint == checkpoint;
                }),
            robust_activations_.end());
    }

    bool ValidatePublicTransferAuditShare(
        const Violation& violation,
        const RecoverableAuditShare& audit,
        const PublicTransferEvidence& evidence) const {
        if (!audit.valid || audit.debug_only ||
            audit.evidence_kind != AuditEvidenceKind::PUBLIC_TRANSFER ||
            !evidence.available || !evidence.cryptographically_authenticated)
            return false;
        if (audit.label.sid != violation.label.sid ||
            audit.label.owner != violation.label.owner ||
            audit.label.object_id != violation.label.object_id ||
            audit.relation != violation.relation ||
            audit.kernel != violation.kernel ||
            audit.expected != violation.expected ||
            audit.actual != violation.actual ||
            audit.residual_commitment != violation.residual_commitment ||
            audit.operation_statement_binding != violation.operation_statement_binding ||
            audit.dispute_binding != violation.dispute_binding)
            return false;
        const OperationRef ref{violation.label.owner, violation.label.object_id};
        if (audit.predecessor_root != Digest{} ||
            audit.checkpoint_root != evidence.checkpoint_root ||
            audit.witness_digest != evidence.evidence_binding ||
            evidence.accused != ref ||
            evidence.label.sid != violation.label.sid ||
            evidence.label.phase != violation.label.phase ||
            evidence.label.round != violation.label.round ||
            evidence.label.obligation != violation.label.obligation ||
            evidence.checkpoint != violation.checkpoint ||
            evidence.relation != violation.relation ||
            evidence.expected != violation.expected ||
            evidence.actual != violation.actual ||
            evidence.residual_commitment != violation.residual_commitment ||
            evidence.operation_statement_binding !=
                violation.operation_statement_binding ||
            evidence.dispute_binding != violation.dispute_binding)
            return false;
        return validate_public_transfer_evidence_claim(evidence);
    }

    bool ValidateRecoveredAuditShare(
        const Violation& violation,
        const RecoverableAuditShare& audit,
        const AuthenticatedRecoveryArtifact& artifact) const {
        if (!audit.valid || audit.debug_only ||
            audit.evidence_kind != AuditEvidenceKind::PRIVATE_RECOVERY)
            return false;
        if (audit.label.sid != violation.label.sid ||
            audit.label.owner != violation.label.owner ||
            audit.label.object_id != violation.label.object_id ||
            audit.relation != violation.relation ||
            audit.kernel != violation.kernel ||
            audit.expected != violation.expected ||
            audit.actual != violation.actual ||
            audit.residual_commitment != violation.residual_commitment ||
            audit.operation_statement_binding != violation.operation_statement_binding ||
            audit.dispute_binding != violation.dispute_binding)
            return false;
        if (audit.predecessor_root != artifact.predecessor_root ||
            audit.checkpoint_root != artifact.checkpoint_root)
            return false;
        return audit.witness_digest ==
               compute_recovery_artifact_binding(artifact);
    }

    bool ValidateBuiltBlameCertificate(
        const Violation& violation,
        const RecoverableAuditShare& audit,
        const BlameCertificate& cert) const {
        if (!cert.valid || cert.debug_only ||
            cert.evidence_kind == AuditEvidenceKind::UNKNOWN ||
            cert.evidence_kind != audit.evidence_kind)
            return false;
        if (cert.sid != violation.label.sid ||
            cert.accused != violation.responsible_rank ||
            cert.label.sid != violation.label.sid ||
            cert.label.owner != violation.label.owner ||
            cert.label.object_id != violation.label.object_id ||
            cert.checkpoint != violation.checkpoint ||
            cert.relation != violation.relation ||
            cert.kernel != violation.kernel)
            return false;
        if (cert.evidence_kind == AuditEvidenceKind::PUBLIC_TRANSFER &&
            cert.predecessor_root != Digest{})
            return false;
        if (cert.expected != violation.expected ||
            cert.actual != violation.actual ||
            cert.residual_commitment != violation.residual_commitment ||
            cert.operation_statement_binding != violation.operation_statement_binding ||
            cert.dispute_binding != violation.dispute_binding ||
            cert.predecessor_root != audit.predecessor_root ||
            cert.checkpoint_root != audit.checkpoint_root ||
            cert.audit_witness_digest != audit.witness_digest ||
            cert.blame_statement_binding == Digest{} ||
            cert.public_proof_system_id == 0 ||
            cert.public_proof_commitment == Digest{} ||
            cert.public_proof_transcript_binding == Digest{} ||
            cert.public_proof_words.empty())
            return false;
        if (cert.evidence_kind == AuditEvidenceKind::PRIVATE_RECOVERY) {
            const AuthenticatedRecoveryRequest request =
                make_recovery_request(cert);
            AuthenticatedRecoveryArtifact recovery;
            if (cert.recovery_artifact_words.empty() ||
                request.request_binding == Digest{} ||
                !decode_authenticated_recovery_artifact(
                    cert.recovery_artifact_words, &recovery) ||
                !validate_recovery_artifact(request, recovery) ||
                !recovery_engine_ ||
                !recovery_engine_->Verify(request, recovery) ||
                compute_recovery_artifact_binding(recovery) !=
                    audit.witness_digest ||
                recovery.predecessor_root != audit.predecessor_root ||
                recovery.checkpoint_root != audit.checkpoint_root ||
                cert.recovery_proof_system_id != 68103 ||
                cert.recovery_proof_statement_binding == Digest{} ||
                cert.recovery_proof_artifact_commitment == Digest{} ||
                cert.recovery_proof_statement_words.size() != 85 ||
                cert.recovery_proof_artifact_bytes.empty() ||
                !PublicJudge::ValidateRecoveryRelationStatement(
                    cert, cert.recovery_proof_statement_words))
                return false;
        } else if (!cert.recovery_artifact_words.empty() ||
                   cert.recovery_proof_system_id != 0 ||
                   !cert.recovery_proof_statement_words.empty() ||
                   !cert.recovery_proof_artifact_bytes.empty()) {
            return false;
        }
        return true;
    }

    void CacheRecoveryArtifact(
        const AuthenticatedRecoveryArtifact& artifact) const {
        for (auto& entry : recovery_artifacts_) {
            if (entry.first == artifact.accused) {
                entry.second = artifact;
                return;
            }
        }
        recovery_artifacts_.push_back({artifact.accused, artifact});
    }

    void CacheTransferEvidence(
        const PublicTransferEvidence& evidence) const {
        for (auto& entry : transfer_evidence_) {
            if (entry.first == evidence.accused) {
                entry.second = evidence;
                return;
            }
        }
        transfer_evidence_.push_back({evidence.accused, evidence});
    }

    PrivateResidualHandle EvaluateResidual(
        const AuditOperationView& operation,
        const PrivateOperationMaterial& material) {
        if (operation.kernel != AuditRelationKernel::UNKNOWN) {
            const KernelResidualEvaluator* evaluator =
                kernel_evaluators_.Find(operation.kernel);
            if (!evaluator)
                return EvaluateUnsupportedKernelResidual(
                    operation, operation.kernel);
            const KernelResidualContext context{operation, material, state_store_};
            return evaluator->Evaluate(context);
        }

        switch (operation.relation) {
            case RelationKind::PRIVATE_DERIVATION:
                return EvaluatePrivateDerivationResidual(operation);
            case RelationKind::MESSAGE_BINDING:
                return EvaluateMessageBindingResidual(operation);
            case RelationKind::RECEIVE_CONSUME:
                return EvaluateReceiveConsumeResidual(operation);
            case RelationKind::ASSEMBLY:
                return EvaluateAssemblyResidual(operation);
            case RelationKind::AGGREGATION:
                return EvaluateAggregationResidual(operation);
            case RelationKind::COMMITMENT:
                return EvaluateCommitmentResidual(operation);
            case RelationKind::FOLDING:
                return EvaluateFoldingResidual(operation);
            case RelationKind::OPENING:
                return EvaluateOpeningResidual(operation);
            case RelationKind::PUBLICATION:
                return EvaluatePublicationResidual(operation);
            default:
                return EvaluateUnsupportedResidual(operation);
        }
    }

    bool capture_private_material_ = true;
    PrivateStateMaterialStore state_store_;
    PrivateAuditMaterialStore material_store_;
    PrivateResidualRegistry residual_registry_;
    PublicTransferObservationStore transfer_store_;
    KernelResidualEvaluatorRegistry kernel_evaluators_;
    const CollectiveResidualEngine* collective_engine_ = nullptr;
    RobustAuditSessionBackend* robust_session_backend_ = nullptr;
    RobustAuditSecurityLevel robust_private_security_requirement_ =
        RobustAuditSecurityLevel::MALICIOUS_GOD;
    std::vector<RobustAuditActivation> robust_activations_;
    const PublicTransferCheckEngine* transfer_engine_ = nullptr;
    const AuthenticatedAuditRecoveryEngine* recovery_engine_ = nullptr;
    const PublicBlameProofEngine* blame_proof_engine_ = nullptr;
    const PublicTransferBlameProofEngine* transfer_blame_proof_engine_ = nullptr;
    std::vector<AuditCheckpointView> checkpoint_views_;
    mutable std::vector<std::pair<OperationRef, AuthenticatedRecoveryArtifact>>
        recovery_artifacts_;
    mutable std::vector<std::pair<OperationRef, PublicTransferEvidence>>
        transfer_evidence_;
    mutable ObligationSet last_failure_scope_{};
    mutable AuditScopePartition last_scope_partition_{};
    mutable BatchCheckResult last_private_batch_{};
    mutable PublicTransferCheckResult last_transfer_check_{};
    mutable CollectiveDisputeResult last_transfer_dispute_{};
    mutable PublicTransferObservation last_transfer_observation_{};
    mutable bool last_transfer_observation_valid_ = false;
    mutable HybridAuditBatchComponents last_hybrid_components_{};
    mutable BatchCheckResult last_hybrid_batch_{};
    mutable RobustAuditSessionOutput last_robust_output_{};
    mutable RobustAuditAbortOutput last_robust_abort_{};
    mutable bool last_robust_abort_valid_ = false;
    mutable RobustAuditTerminationOutput last_robust_termination_{};
    mutable bool last_robust_termination_valid_ = false;
    mutable bool last_private_used_robust_session_ = false;
    mutable uint64_t failure_scope_sync_sequence_ = 1;
    mutable int collective_rank_ = 0;
    mutable int collective_world_size_ = 1;
};

} // namespace pvia
