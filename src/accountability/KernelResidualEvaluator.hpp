#pragma once

#include "PrivateAuditMaterialStore.hpp"
#include "PrivateResidualRegistry.hpp"
#include "PrivateStateMaterialStore.hpp"

#include <vector>

namespace pvia {

enum class KernelPayloadRequirement : uint32_t {
    ANY = 0,
    FIELD = 1,
    WORD = 2
};

struct KernelResidualRequirements {
    RelationKind relation = RelationKind::UNKNOWN;
    KernelPayloadRequirement payload = KernelPayloadRequirement::ANY;
    uint32_t min_state_dependencies = 0;
    std::vector<AuditPublicAuxKind> required_field_aux;
    std::vector<AuditPublicAuxKind> required_word_aux;
};

KernelResidualRequirements kernel_residual_requirements(
    AuditRelationKernel kernel);
struct KernelResidualContext {
    const AuditOperationView& operation;
    const PrivateOperationMaterial& material;
    const PrivateStateMaterialStore& states;

    const PrivateStateMaterial* state(size_t index) const;
    size_t state_segment_count(size_t index) const;
    bool state_segment(
        size_t state_index, size_t segment_index,
        FieldStateSegment* segment) const;
    const std::vector<F>* field_aux(AuditPublicAuxKind kind) const;
    const std::vector<u64>* word_aux(AuditPublicAuxKind kind) const;
};

bool validate_kernel_residual_material(
    const KernelResidualContext& context);

// A concrete secure backend supplies one or more evaluators.  Evaluators own
// the cryptographic residual representation; Runtime sees only opaque handles.
class KernelResidualEvaluator {
public:
    virtual ~KernelResidualEvaluator() = default;
    virtual bool Supports(AuditRelationKernel kernel) const = 0;
    virtual PrivateResidualHandle Evaluate(
        const KernelResidualContext& context) const = 0;
};

// Adapter boundary for a concrete authenticated MPC residual backend.
// The backend returns an opaque authenticated handle; this wrapper verifies
// that the handle is bound to the exact Runtime operation descriptor.
class KernelResidualBackend {
public:
    virtual ~KernelResidualBackend() = default;
    virtual PrivateResidualHandle EvaluateKernel(
        const KernelResidualContext& context) const = 0;
};

class BackendKernelResidualEvaluator final : public KernelResidualEvaluator {
public:
    BackendKernelResidualEvaluator(
        const KernelResidualBackend& backend,
        std::vector<AuditRelationKernel> supported_kernels);

    bool Supports(AuditRelationKernel kernel) const override;
    PrivateResidualHandle Evaluate(
        const KernelResidualContext& context) const override;

private:
    const KernelResidualBackend& backend_;
    std::vector<AuditRelationKernel> supported_kernels_;
};

class KernelResidualEvaluatorRegistry {
public:
    void Add(const KernelResidualEvaluator* evaluator);
    const KernelResidualEvaluator* Find(AuditRelationKernel kernel) const;
    bool Has(AuditRelationKernel kernel) const { return Find(kernel) != nullptr; }

private:
    // Non-owning: concrete providers keep evaluator objects alive.
    std::vector<const KernelResidualEvaluator*> evaluators_;
};

} // namespace pvia
