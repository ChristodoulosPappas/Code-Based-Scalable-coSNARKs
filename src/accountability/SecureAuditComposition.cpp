#include "SecureAuditComposition.hpp"

#include <algorithm>
#include <utility>

namespace pvia {
namespace {

bool native_sumcheck_kernel_index(
    AuditRelationKernel kernel, size_t* index) {
    if (!index) return false;
    switch (kernel) {
        case AuditRelationKernel::COSUMCHECK_ZERO: *index = 0; return true;
        case AuditRelationKernel::COSUMCHECK_QUADRATIC: *index = 1; return true;
        case AuditRelationKernel::COSUMCHECK_BATCH: *index = 2; return true;
        case AuditRelationKernel::DSC_QUADRATIC: *index = 3; return true;
        case AuditRelationKernel::DSC_CUBIC: *index = 4; return true;
        default: return false;
    }
}

bool has_required_kernel(
    const SecureAuditComponents& components,
    AuditRelationKernel kernel) {
    if (kernel == AuditRelationKernel::UNKNOWN) return false;
    for (const KernelResidualEvaluator* evaluator :
         components.kernel_evaluators) {
        if (evaluator && evaluator->Supports(kernel)) return true;
    }
    return false;
}

} // namespace

ComposedSecureAuditProvider::ComposedSecureAuditProvider(
    SecureAuditComponents components,
    bool private_material_capture,
    RobustAuditSecurityLevel private_security_requirement)
    : components_(std::move(components)) {
    SetPrivateMaterialCapture(private_material_capture);
    SetRobustPrivateSecurityRequirement(private_security_requirement);
    if (components_.robust_session_backend)
        InstallRobustAuditSessionBackend(components_.robust_session_backend);
    if (components_.collective_engine)
        InstallCollectiveResidualEngine(components_.collective_engine);
    if (components_.transfer_engine)
        InstallPublicTransferCheckEngine(components_.transfer_engine);
    if (components_.recovery_engine)
        InstallAuthenticatedAuditRecoveryEngine(components_.recovery_engine);
    if (components_.private_blame_proof_engine)
        InstallPublicBlameProofEngine(
            components_.private_blame_proof_engine);
    if (components_.transfer_blame_proof_engine)
        InstallPublicTransferBlameProofEngine(
            components_.transfer_blame_proof_engine);

    for (const KernelResidualEvaluator* evaluator :
         components_.kernel_evaluators) {
        if (!evaluator) continue;
        InstallKernelResidualEvaluator(evaluator);
        ++installed_kernel_evaluators_;
    }
}

bool ComposedSecureAuditProvider::Ready(
    const SecureAuditRequirements& requirements) const {
    if (!requirements.private_lane && !requirements.transfer_lane)
        return false;
    if (!requirements.private_lane &&
        !requirements.required_kernels.empty())
        return false;
    if (requirements.private_lane) {
        if (requirements.private_security_level !=
                RobustAuditSecurityLevel::MALICIOUS_GOD &&
            requirements.private_security_level !=
                RobustAuditSecurityLevel::MALICIOUS_ABORT)
            return false;
        if (RobustPrivateSecurityRequirement() !=
            requirements.private_security_level)
            return false;
        bool robust_ready = false;
        RobustAuditCapabilities robust_capabilities;
        if (components_.robust_session_backend) {
            robust_capabilities = components_.robust_session_backend->Capabilities();
            robust_ready = requirements.private_security_level ==
                    RobustAuditSecurityLevel::MALICIOUS_GOD
                ? production_ready_robust_audit_capabilities(robust_capabilities)
                : production_ready_identifiable_abort_capabilities(
                    robust_capabilities);
            if (robust_ready) {
                for (AuditRelationKernel kernel : requirements.required_kernels) {
                    if (!robust_audit_supports_kernel(robust_capabilities, kernel))
                        return false;
                }
            }
        }
        const bool legacy_ready =
            requirements.private_security_level ==
                RobustAuditSecurityLevel::MALICIOUS_GOD &&
            components_.collective_engine &&
            components_.collective_engine->ProductionCapabilityBinding() != Digest{} &&
            components_.recovery_engine &&
            components_.recovery_engine->ProductionCapabilityBinding() != Digest{} &&
            components_.private_blame_proof_engine &&
            components_.private_blame_proof_engine->ProductionCapabilityBinding() != Digest{};
        // Non-null pointers (including fail-closed adapters) are not a
        // security claim. Legacy engines must expose an explicit production
        // capability binding before they can satisfy composition readiness.
        if (!robust_ready && !legacy_ready) return false;
        if (!robust_ready) {
            for (AuditRelationKernel kernel : requirements.required_kernels) {
                if (!has_required_kernel(components_, kernel)) return false;
            }
        }
    }
    if (requirements.transfer_lane) {
        if (!components_.transfer_engine ||
            components_.transfer_engine->ProductionCapabilityBinding() == Digest{} ||
            !components_.transfer_blame_proof_engine ||
            components_.transfer_blame_proof_engine->ProductionCapabilityBinding() == Digest{})
            return false;
    }
    return true;
}

void ComposedSecureAuditProvider::FinalizeInvalidMaterial(
    const AuditOperationView& operation) {
    size_t index = 0;
    if (native_sumcheck_kernel_index(operation.kernel, &index))
        ++native_sumcheck_invalid_count_;
}

void ComposedSecureAuditProvider::FinalizeUnavailableResidual(
    const AuditOperationView& operation, const PrivateResidualHandle&) {
    size_t index = 0;
    if (native_sumcheck_kernel_index(operation.kernel, &index))
        ++native_sumcheck_unavailable_count_;
}

void ComposedSecureAuditProvider::OnResidualFinalized(
    const AuditOperationView& operation,
    const PrivateResidualHandle& handle) {
    size_t index = 0;
    if (native_sumcheck_kernel_index(operation.kernel, &index) &&
        handle.available && handle.ref == operation.ref &&
        handle.checkpoint == operation.checkpoint)
        ++native_sumcheck_finalized_counts_[index];
}

bool ComposedSecureAuditProvider::ReadRelationProofReceipt(
    AuditRelationKernel kernel,
    AuditRelationProofReceipt* receipt) const {
    if (!receipt) return false;
    *receipt = AuditRelationProofReceipt{};
    if (!components_.native_sumcheck_proof_provider) return false;
    Sp1SumcheckProofReceipt native;
    if (!components_.native_sumcheck_proof_provider->ReadLatestReceipt(
            kernel, &native))
        return false;
    receipt->available = native.available;
    receipt->proof_verified = native.proof_verified;
    receipt->production_privacy_confirmed =
        native.production_privacy_confirmed;
    receipt->kernel = native.kernel;
    receipt->operation_ref = native.operation_ref;
    receipt->checkpoint = native.checkpoint;
    receipt->relation_statement = native.relation_statement;
    receipt->proof_system_id = native.proof_system_id;
    receipt->proof_word_count = native.proof_word_count;
    receipt->statement_binding = native.statement_binding;
    receipt->artifact_commitment = native.artifact_commitment;
    return receipt->available && receipt->proof_verified;
}

PrivateResidualHandle ComposedSecureAuditProvider::UnavailableResidual(
    const AuditOperationView& operation,
    AuditRelationKernel kernel_override) {
    PrivateResidualHandle handle;
    handle.ref = operation.ref;
    handle.label = operation.label;
    handle.relation = operation.relation;
    handle.kernel = kernel_override == AuditRelationKernel::UNKNOWN
        ? operation.kernel : kernel_override;
    handle.checkpoint = operation.checkpoint;
    return handle;
}

#define PVIA_UNAVAILABLE_RELATION_METHOD(name) \
PrivateResidualHandle ComposedSecureAuditProvider::name( \
    const AuditOperationView& operation) { \
    return UnavailableResidual(operation); \
}

PVIA_UNAVAILABLE_RELATION_METHOD(EvaluatePrivateDerivationResidual)
PVIA_UNAVAILABLE_RELATION_METHOD(EvaluateMessageBindingResidual)
PVIA_UNAVAILABLE_RELATION_METHOD(EvaluateReceiveConsumeResidual)
PVIA_UNAVAILABLE_RELATION_METHOD(EvaluateAssemblyResidual)
PVIA_UNAVAILABLE_RELATION_METHOD(EvaluateAggregationResidual)
PVIA_UNAVAILABLE_RELATION_METHOD(EvaluateCommitmentResidual)
PVIA_UNAVAILABLE_RELATION_METHOD(EvaluateFoldingResidual)
PVIA_UNAVAILABLE_RELATION_METHOD(EvaluateOpeningResidual)
PVIA_UNAVAILABLE_RELATION_METHOD(EvaluatePublicationResidual)
PVIA_UNAVAILABLE_RELATION_METHOD(EvaluateUnsupportedResidual)

#undef PVIA_UNAVAILABLE_RELATION_METHOD

PrivateResidualHandle
ComposedSecureAuditProvider::EvaluateUnsupportedKernelResidual(
    const AuditOperationView& operation, AuditRelationKernel kernel) {
    return UnavailableResidual(operation, kernel);
}

bool run_secure_audit_composition_readiness_selftest() {
    FailClosedCollectiveResidualEngine collective;
    FailClosedAuthenticatedAuditRecoveryEngine recovery;
    FailClosedPublicBlameProofEngine private_blame;
    SecureAuditComponents private_components;
    private_components.collective_engine = &collective;
    private_components.recovery_engine = &recovery;
    private_components.private_blame_proof_engine = &private_blame;
    SecureAuditRequirements private_requirements;
    private_requirements.private_lane = true;
    private_requirements.transfer_lane = false;
    private_requirements.private_security_level =
        RobustAuditSecurityLevel::MALICIOUS_GOD;
    ComposedSecureAuditProvider private_provider(
        private_components, true, RobustAuditSecurityLevel::MALICIOUS_GOD);
    if (private_provider.Ready(private_requirements)) return false;

    FailClosedPublicTransferCheckEngine transfer;
    FailClosedPublicTransferBlameProofEngine transfer_blame;
    SecureAuditComponents transfer_components;
    transfer_components.transfer_engine = &transfer;
    transfer_components.transfer_blame_proof_engine = &transfer_blame;
    SecureAuditRequirements transfer_requirements;
    transfer_requirements.private_lane = false;
    transfer_requirements.transfer_lane = true;
    ComposedSecureAuditProvider transfer_provider(
        transfer_components, false, RobustAuditSecurityLevel::MALICIOUS_GOD);
    return !transfer_provider.Ready(transfer_requirements) &&
        run_authenticated_audit_recovery_verifier_selftest();
}

SecureAuditRuntimeBundle::SecureAuditRuntimeBundle(
    SecureAuditComponents components,
    SecureAuditRequirements requirements)
    : provider_(std::move(components), requirements.private_lane,
                requirements.private_security_level),
      backend_(provider_),
      requirements_(std::move(requirements)) {}

SecureAuditRuntimeBundle::~SecureAuditRuntimeBundle() {
    Detach();
}

bool SecureAuditRuntimeBundle::Attach(Runtime& runtime) {
    if (!ready()) return false;
    if (runtime.audit_backend() == &backend_) {
        attached_runtime_ = &runtime;
        return true;
    }
    // Secure providers need the original private-share notifications. Runtime
    // deliberately does not retain private shares for late replay, so refuse a
    // late secure attachment instead of silently running with incomplete state.
    if (!runtime.can_attach_secure_backend()) return false;
    if (attached_runtime_ && attached_runtime_ != &runtime) Detach();
    runtime.set_audit_backend(&backend_);
    attached_runtime_ = &runtime;
    return runtime.audit_backend() == &backend_;
}

void SecureAuditRuntimeBundle::Detach() {
    if (!attached_runtime_) return;
    if (attached_runtime_->audit_backend() == &backend_)
        attached_runtime_->set_audit_backend(nullptr);
    attached_runtime_ = nullptr;
}

} // namespace pvia
