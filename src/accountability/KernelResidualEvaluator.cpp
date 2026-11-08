#include "KernelResidualEvaluator.hpp"

#include <algorithm>
#include <initializer_list>
#include <utility>

namespace pvia {
namespace {

bool has_field_aux(const PrivateOperationMaterial& material,
                   AuditPublicAuxKind kind) {
    return std::any_of(material.field_aux.begin(), material.field_aux.end(),
        [&](const auto& item) { return item.first == kind; });
}

bool has_word_aux(const PrivateOperationMaterial& material,
                  AuditPublicAuxKind kind) {
    return std::any_of(material.word_aux.begin(), material.word_aux.end(),
        [&](const auto& item) { return item.first == kind; });
}

KernelResidualRequirements field_kernel(
    RelationKind relation, uint32_t min_states = 0,
    std::initializer_list<AuditPublicAuxKind> field_aux = {}) {
    KernelResidualRequirements req;
    req.relation = relation;
    req.payload = KernelPayloadRequirement::FIELD;
    req.min_state_dependencies = min_states;
    req.required_field_aux.assign(field_aux.begin(), field_aux.end());
    return req;
}

} // namespace
KernelResidualRequirements kernel_residual_requirements(
    AuditRelationKernel kernel) {
    using K = AuditRelationKernel;
    using R = RelationKind;
    using A = AuditPublicAuxKind;
    switch (kernel) {
        case K::COSUMCHECK_ZERO:
        case K::COSUMCHECK_QUADRATIC:
        case K::COSUMCHECK_BATCH:
        case K::DSC_QUADRATIC:
        case K::DSC_CUBIC:
        case K::DSC_SPARROW_QUADRATIC:
        case K::DSC_SPARROW_CUBIC:
        case K::PCS_OPEN_ROUND:
        case K::PCS_BATCH_OPEN_ROUND:
            return field_kernel(R::PRIVATE_DERIVATION, 1,
                                {A::SUMCHECK_CHALLENGE});
        case K::ENCODING_FIRST_STAGE:
        case K::ENCODING_STAGE2:
        case K::ENCODING_DIRECT_STAGE2:
        case K::PRODUCT_FRONTIER:
            return field_kernel(R::PRIVATE_DERIVATION, 1);
        case K::SPARSE_TRANSCRIPT:
            return field_kernel(R::PRIVATE_DERIVATION, 1,
                                {A::GENERIC_FIELDS});
        case K::ENCODING_ASSEMBLE:
            return field_kernel(R::ASSEMBLY, 1, {A::ASSEMBLY_LAYOUT});
        case K::ORACLE_MERKLE_COMMIT: {
            KernelResidualRequirements req;
            req.relation = R::COMMITMENT;
            req.payload = KernelPayloadRequirement::WORD;
            req.min_state_dependencies = 1;
            req.required_word_aux = {A::COMMIT_DOMAIN};
            return req;
        }
        case K::FOLD_RS:
            return field_kernel(R::FOLDING, 1, {A::FOLD_CHALLENGE});
        case K::OPEN_QUERY:
            return field_kernel(R::OPENING, 0, {A::OPEN_QUERY});
        case K::AGGREGATE_CODED:
        case K::AGGREGATE_WEIGHTED:
        case K::AGGREGATE_BATCH:
            return field_kernel(R::AGGREGATION, 0,
                                {A::AGGREGATION_WEIGHTS});
        case K::PUBLISH_AGGREGATE:
            return field_kernel(R::PUBLICATION, 0);
        default:
            return KernelResidualRequirements{};
    }
}

const PrivateStateMaterial* KernelResidualContext::state(size_t index) const {
    if (index >= material.state_dependencies.size()) return nullptr;
    return states.Find(material.state_dependencies[index]);
}
size_t KernelResidualContext::state_segment_count(size_t index) const {
    const PrivateStateMaterial* material_state = state(index);
    return material_state ? material_state->segment_lengths.size() : 0;
}

bool KernelResidualContext::state_segment(
    size_t state_index, size_t segment_index,
    FieldStateSegment* segment) const {
    if (!segment) return false;
    const PrivateStateMaterial* material_state = state(state_index);
    if (!material_state || !material_state->has_private_share ||
        segment_index >= material_state->segment_lengths.size() ||
        !states.VerifySegmentLayout(material_state->state.id))
        return false;
    size_t offset = 0;
    for (size_t i = 0; i < segment_index; ++i) {
        const size_t length = material_state->segment_lengths[i];
        if (offset > material_state->local_share.size() - length)
            return false;
        offset += length;
    }
    const size_t count = material_state->segment_lengths[segment_index];
    if (offset > material_state->local_share.size() ||
        count > material_state->local_share.size() - offset)
        return false;
    *segment = FieldStateSegment{
        &material_state->local_share, offset, count};
    return true;
}

const std::vector<F>* KernelResidualContext::field_aux(
    AuditPublicAuxKind kind) const {
    for (const auto& item : material.field_aux)
        if (item.first == kind) return &item.second;
    return nullptr;
}

const std::vector<u64>* KernelResidualContext::word_aux(
    AuditPublicAuxKind kind) const {
    for (const auto& item : material.word_aux)
        if (item.first == kind) return &item.second;
    return nullptr;
}

bool validate_kernel_residual_material(
    const KernelResidualContext& context) {
    const RelationKind canonical_relation =
        relation_for_kernel(context.operation.kernel);
    const KernelResidualRequirements req =
        kernel_residual_requirements(context.operation.kernel);
    if (canonical_relation == RelationKind::UNKNOWN ||
        canonical_relation != context.operation.relation ||
        req.relation != canonical_relation)
        return false;
    if (context.material.state_dependencies.size() <
        req.min_state_dependencies)
        return false;

    if (req.payload == KernelPayloadRequirement::FIELD &&
        (!context.material.has_field_input ||
         !context.material.has_field_output))
        return false;
    if (req.payload == KernelPayloadRequirement::WORD &&
        (!context.material.has_word_input ||
         !context.material.has_word_output))
        return false;

    for (AuditPublicAuxKind kind : req.required_field_aux)
        if (!has_field_aux(context.material, kind)) return false;
    for (AuditPublicAuxKind kind : req.required_word_aux)
        if (!has_word_aux(context.material, kind)) return false;

    for (size_t i = 0; i < context.material.state_dependencies.size(); ++i) {
        const PrivateStateMaterial* state = context.state(i);
        if (!state || !state->has_private_share) return false;
    }
    return true;
}

BackendKernelResidualEvaluator::BackendKernelResidualEvaluator(
    const KernelResidualBackend& backend,
    std::vector<AuditRelationKernel> supported_kernels)
    : backend_(backend), supported_kernels_(std::move(supported_kernels)) {}

bool BackendKernelResidualEvaluator::Supports(
    AuditRelationKernel kernel) const {
    if (kernel == AuditRelationKernel::UNKNOWN) return false;
    return std::find(supported_kernels_.begin(), supported_kernels_.end(),
                     kernel) != supported_kernels_.end();
}

PrivateResidualHandle BackendKernelResidualEvaluator::Evaluate(
    const KernelResidualContext& context) const {
    PrivateResidualHandle unavailable;
    unavailable.ref = context.operation.ref;
    unavailable.label = context.operation.label;
    unavailable.relation = context.operation.relation;
    unavailable.kernel = context.operation.kernel;
    unavailable.checkpoint = context.operation.checkpoint;

    if (!Supports(context.operation.kernel) ||
        !validate_kernel_residual_material(context))
        return unavailable;

    const PrivateResidualHandle handle = backend_.EvaluateKernel(context);
    const Label& a = handle.label;
    const Label& b = context.operation.label;
    if (!handle.available || !handle.authenticated ||
        handle.ref != context.operation.ref ||
        a.sid != b.sid || a.phase != b.phase || a.round != b.round ||
        a.owner != b.owner || a.obligation != b.obligation ||
        a.object_id != b.object_id ||
        handle.relation != context.operation.relation ||
        handle.kernel != context.operation.kernel ||
        handle.checkpoint != context.operation.checkpoint ||
        handle.commitment == Digest{})
        return unavailable;
    return handle;
}

void KernelResidualEvaluatorRegistry::Add(
    const KernelResidualEvaluator* evaluator) {
    if (!evaluator) return;
    if (std::find(evaluators_.begin(), evaluators_.end(), evaluator) ==
        evaluators_.end())
        evaluators_.push_back(evaluator);
}

const KernelResidualEvaluator* KernelResidualEvaluatorRegistry::Find(
    AuditRelationKernel kernel) const {
    for (auto it = evaluators_.rbegin(); it != evaluators_.rend(); ++it)
        if ((*it)->Supports(kernel)) return *it;
    return nullptr;
}

} // namespace pvia
