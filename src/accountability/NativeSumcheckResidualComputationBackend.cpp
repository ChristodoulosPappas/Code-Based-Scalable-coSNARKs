#include "NativeSumcheckResidualComputationBackend.hpp"

#include <algorithm>
#include <cstdlib>
#include <string>

namespace pvia {
namespace {

PrivateResidualHandle unavailable_handle(
    const KernelResidualContext& context) {
    PrivateResidualHandle handle;
    handle.ref = context.operation.ref;
    handle.label = context.operation.label;
    handle.relation = context.operation.relation;
    handle.kernel = context.operation.kernel;
    handle.checkpoint = context.operation.checkpoint;
    return handle;
}

bool same_field_vector(
    const std::vector<F>& lhs, const std::vector<F>& rhs) {
    return lhs == rhs;
}

bool get_segments(
    const KernelResidualContext& context, size_t expected_count,
    std::vector<FieldStateSegment>* segments, size_t* pair_count) {
    if (!segments || !pair_count ||
        context.state_segment_count(0) != expected_count)
        return false;
    segments->clear();
    segments->reserve(expected_count);
    size_t common_count = 0;
    for (size_t i = 0; i < expected_count; ++i) {
        FieldStateSegment segment;
        if (!context.state_segment(0, i, &segment) ||
            !segment.values || segment.count == 0 ||
            segment.count % 2 != 0)
            return false;
        if (i == 0) common_count = segment.count;
        else if (segment.count != common_count) return false;
        segments->push_back(segment);
    }
    *pair_count = common_count / 2;
    return *pair_count != 0;
}

bool pair_linear(
    const FieldStateSegment& segment, size_t pair,
    F* constant, F* slope) {
    if (!constant || !slope || !segment.values ||
        pair >= segment.count / 2)
        return false;
    const size_t offset = segment.offset + 2 * pair;
    if (offset >= segment.values->size() ||
        segment.values->size() - offset < 2)
        return false;
    *constant = (*segment.values)[offset];
    *slope = (*segment.values)[offset + 1] - *constant;
    return true;
}

void add_product_of_two_linears(
    std::vector<F>* coefficients,
    const F& a0, const F& a1, const F& b0, const F& b1) {
    (*coefficients)[0] += a0 * b0;
    (*coefficients)[1] += a0 * b1 + a1 * b0;
    (*coefficients)[2] += a1 * b1;
}

} // namespace

bool recompute_native_sumcheck_polynomial(
    const KernelResidualContext& context,
    std::vector<F>* coefficients) {
    if (!coefficients || context.operation.relation !=
            RelationKind::PRIVATE_DERIVATION ||
        context.material.state_dependencies.size() != 1)
        return false;

    const std::vector<F>* aux =
        context.field_aux(AuditPublicAuxKind::SUMCHECK_CHALLENGE);
    if (!aux) return false;

    std::vector<FieldStateSegment> segments;
    size_t pairs = 0;
    const AuditRelationKernel kernel = context.operation.kernel;

    switch (kernel) {
        case AuditRelationKernel::COSUMCHECK_ZERO: {
            if (aux->size() < 2 ||
                !get_segments(context, 6, &segments, &pairs))
                return false;
            const F mask_scale = (*aux)[1];
            coefficients->assign(4, F(0));
            for (size_t j = 0; j < pairs; ++j) {
                F a0, a1, b0, b1, out0, out1;
                F beta0, beta1, mask_a0, mask_a1, mask_b0, mask_b1;
                if (!pair_linear(segments[0], j, &a0, &a1) ||
                    !pair_linear(segments[1], j, &b0, &b1) ||
                    !pair_linear(segments[2], j, &out0, &out1) ||
                    !pair_linear(segments[3], j, &beta0, &beta1) ||
                    !pair_linear(segments[4], j, &mask_a0, &mask_a1) ||
                    !pair_linear(segments[5], j, &mask_b0, &mask_b1))
                    return false;

                const F p0 = a0 * b0 +
                    mask_scale * mask_a0 * mask_b0 - out0;
                const F p1 = a0 * b1 + a1 * b0 +
                    mask_scale * (mask_a0 * mask_b1 +
                                  mask_a1 * mask_b0) - out1;
                const F p2 = a1 * b1 +
                    mask_scale * mask_a1 * mask_b1;

                (*coefficients)[0] += p0 * beta0;
                (*coefficients)[1] += p0 * beta1 + p1 * beta0;
                (*coefficients)[2] += p1 * beta1 + p2 * beta0;
                (*coefficients)[3] += p2 * beta1;
            }
            std::reverse(coefficients->begin(), coefficients->end());
            return true;
        }

        case AuditRelationKernel::COSUMCHECK_QUADRATIC:
        case AuditRelationKernel::DSC_QUADRATIC: {
            if (aux->empty() ||
                !get_segments(context, 2, &segments, &pairs))
                return false;
            coefficients->assign(3, F(0));
            for (size_t j = 0; j < pairs; ++j) {
                F a0, a1, b0, b1;
                if (!pair_linear(segments[0], j, &a0, &a1) ||
                    !pair_linear(segments[1], j, &b0, &b1))
                    return false;
                add_product_of_two_linears(
                    coefficients, a0, a1, b0, b1);
            }
            std::reverse(coefficients->begin(), coefficients->end());
            return true;
        }

        case AuditRelationKernel::COSUMCHECK_BATCH: {
            if (aux->size() < 2 ||
                !get_segments(context, 6, &segments, &pairs))
                return false;
            const F mask_scale = (*aux)[1];
            coefficients->assign(3, F(0));
            for (size_t j = 0; j < pairs; ++j) {
                F a0, a1, b0, b1, c0, c1, d0, d1;
                F mask_a0, mask_a1, mask_b0, mask_b1;
                if (!pair_linear(segments[0], j, &a0, &a1) ||
                    !pair_linear(segments[1], j, &b0, &b1) ||
                    !pair_linear(segments[2], j, &c0, &c1) ||
                    !pair_linear(segments[3], j, &d0, &d1) ||
                    !pair_linear(segments[4], j, &mask_a0, &mask_a1) ||
                    !pair_linear(segments[5], j, &mask_b0, &mask_b1))
                    return false;
                add_product_of_two_linears(
                    coefficients, a0, a1, b0, b1);
                add_product_of_two_linears(
                    coefficients, c0, c1, d0, d1);
                (*coefficients)[0] +=
                    mask_scale * mask_a0 * mask_b0;
                (*coefficients)[1] += mask_scale *
                    (mask_a0 * mask_b1 + mask_a1 * mask_b0);
                (*coefficients)[2] +=
                    mask_scale * mask_a1 * mask_b1;
            }
            std::reverse(coefficients->begin(), coefficients->end());
            return true;
        }

        case AuditRelationKernel::DSC_CUBIC: {
            if (aux->empty() ||
                !get_segments(context, 3, &segments, &pairs))
                return false;
            coefficients->assign(4, F(0));
            for (size_t j = 0; j < pairs; ++j) {
                F a0, a1, b0, b1, c0, c1;
                if (!pair_linear(segments[0], j, &a0, &a1) ||
                    !pair_linear(segments[1], j, &b0, &b1) ||
                    !pair_linear(segments[2], j, &c0, &c1))
                    return false;
                (*coefficients)[0] += a0 * b0 * c0;
                (*coefficients)[1] +=
                    a1 * b0 * c0 + a0 * b1 * c0 + a0 * b0 * c1;
                (*coefficients)[2] +=
                    a1 * b1 * c0 + a1 * b0 * c1 + a0 * b1 * c1;
                (*coefficients)[3] += a1 * b1 * c1;
            }
            std::reverse(coefficients->begin(), coefficients->end());
            return true;
        }

        default:
            return false;
    }
}

PrivateResidualHandle
NativeSumcheckResidualComputationBackend::EvaluateKernel(
    const KernelResidualContext& context) const {
    PrivateResidualHandle unavailable = unavailable_handle(context);
    if (!validate_kernel_residual_material(context) ||
        context.material.state_dependencies.size() != 1 ||
        !context.material.has_field_input ||
        !context.material.has_field_output)
        return unavailable;

    const bool cubic =
        context.operation.kernel == AuditRelationKernel::COSUMCHECK_ZERO ||
        context.operation.kernel == AuditRelationKernel::DSC_CUBIC;
    const AuditPrivatePayloadKind expected_kind = cubic
        ? AuditPrivatePayloadKind::CUBIC
        : AuditPrivatePayloadKind::QUADRATIC;
    if (context.material.field_kind != expected_kind)
        return unavailable;

    const PrivateStateMaterial* state = context.state(0);
    if (!state || !state->has_private_share ||
        !context.states.VerifyDigest(state->state.id) ||
        state->segment_layout_binding == Digest{} ||
        context.operation.actual == Digest{} ||
        context.operation.relation_statement == Digest{})
        return unavailable;

    std::vector<F> recomputed;
    if (!recompute_native_sumcheck_polynomial(context, &recomputed) ||
        !same_field_vector(recomputed, context.material.field_input) ||
        recomputed.size() != context.material.field_output.size())
        return unavailable;

    // Development-only export mode persists raw private witness material;
    // never enable it for production data. It captures validated
    // Statement/Witness words from the live Native context without spending
    // a Groth16 proof inside the MPI round. The inputs can then be proved
    // concurrently and independently.
    const char* export_env =
        std::getenv("PVIA_SP1_SUMCHECK_EXPORT_INPUTS");
    const bool export_inputs =
        export_env && std::string(export_env) != "0";
    if (sp1_proof_provider_ && export_inputs) {
        if (!sp1_proof_provider_->ExportRelationInput(context))
            return unavailable;
    } else if (sp1_proof_provider_ &&
               sp1_proof_provider_->Enabled(context.operation.kernel)) {
        // Optional candidate proof path. It is deliberately opt-in and its
        // receipt is not authenticated MPC provenance or production readiness.
        Sp1SumcheckProofReceipt receipt;
        if (!sp1_proof_provider_->ProveAndVerify(context, &receipt) ||
            !receipt.available || !receipt.proof_verified ||
            receipt.production_privacy_confirmed ||
            receipt.proof_system_id != 68102 ||
            receipt.kernel != context.operation.kernel ||
            receipt.operation_ref != context.operation.ref ||
            receipt.checkpoint != context.operation.checkpoint ||
            receipt.relation_statement != context.operation.relation_statement ||
            receipt.statement_binding == Digest{} ||
            receipt.artifact_commitment == Digest{})
            return unavailable;
    }

    PrivateResidualShare share;
    share.ref = context.operation.ref;
    share.label = context.operation.label;
    share.relation = context.operation.relation;
    share.kernel = context.operation.kernel;
    share.checkpoint = context.operation.checkpoint;
    share.values.resize(recomputed.size(), F(0));
    for (size_t i = 0; i < recomputed.size(); ++i)
        share.values[i] = context.material.field_output[i] - recomputed[i];
    share.source_state_id = state->state.id;
    share.source_state_owner = state->state.label.owner;
    share.source_state_digest = state->state.digest;
    share.source_state_layout_binding = state->segment_layout_binding;
    if (state->has_authentication) {
        share.source_state_authentication_scheme_id =
            state->authentication_scheme_id;
        share.source_state_authentication_binding =
            state->authentication_binding;
    }
    share.public_aux_root = context.operation.public_aux_root;
    share.expected = context.operation.expected;
    share.actual = context.operation.actual;
    share.operation_statement_binding =
        context.operation.relation_statement;
    share.computation_valid = true;
    share.computation_binding =
        compute_private_residual_computation_binding(share);

    if (authenticator_ &&
        share.source_state_authentication_scheme_id != 0 &&
        authenticator_->SchemeId() ==
            share.source_state_authentication_scheme_id) {
        PrivateResidualAuthenticationArtifact artifact;
        if (authenticator_->Authenticate(share, &artifact) &&
            artifact.scheme_id == authenticator_->SchemeId() &&
            validate_private_residual_authentication_artifact(
                share, artifact)) {
            share.authentication = artifact;
            share.authentication_binding = artifact.binding;
            share.authenticated = true;
        }
    }

    share.commitment = compute_private_residual_share_commitment(share);
    if (!store_.Put(share)) return unavailable;

    PrivateResidualHandle handle;
    handle.ref = share.ref;
    handle.label = share.label;
    handle.relation = share.relation;
    handle.kernel = share.kernel;
    handle.checkpoint = share.checkpoint;
    handle.commitment = share.commitment;
    handle.available = true;
    handle.authenticated = share.authenticated;
    return handle;
}

bool NativeSumcheckKernelResidualEvaluator::Supports(
    AuditRelationKernel kernel) const {
    using K = AuditRelationKernel;
    return kernel == K::COSUMCHECK_ZERO ||
           kernel == K::COSUMCHECK_QUADRATIC ||
           kernel == K::COSUMCHECK_BATCH ||
           kernel == K::DSC_QUADRATIC ||
           kernel == K::DSC_CUBIC;
}

PrivateResidualHandle NativeSumcheckKernelResidualEvaluator::Evaluate(
    const KernelResidualContext& context) const {
    if (!Supports(context.operation.kernel)) {
        PrivateResidualHandle unavailable = unavailable_handle(context);
        return unavailable;
    }
    return backend_.EvaluateKernel(context);
}

} // namespace pvia
