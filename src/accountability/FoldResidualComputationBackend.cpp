#include "FoldResidualComputationBackend.hpp"
#include "utils.hpp"

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
    const std::vector<F>& lhs,
    const std::vector<F>& rhs) {
    if (lhs.size() != rhs.size()) return false;
    for (size_t i = 0; i < lhs.size(); ++i)
        if (lhs[i] != rhs[i]) return false;
    return true;
}

} // namespace

bool recompute_fold_rs_output(
    const std::vector<F>& input,
    const F& challenge,
    std::vector<F>* output) {
    if (!output || input.size() < 2 || input.size() % 2 != 0)
        return false;
    size_t n = input.size();
    unsigned log_n = 0;
    size_t power = 1;
    while (power < n) {
        power <<= 1;
        ++log_n;
    }
    if (power != n) return false;

    const F two_inv = F(2).inv();
    F omega = getRootOfUnity(static_cast<int>(log_n));
    omega = omega.inv();
    F inv_omega = F(1);
    output->assign(n / 2, F(0));
    for (size_t i = 0; i < n / 2; ++i) {
        (*output)[i] = two_inv * (
            (F(1) - challenge) * (input[i] + input[i + n / 2]) +
            challenge * inv_omega * (input[i] - input[i + n / 2]));
        inv_omega = inv_omega * omega;
    }
    return true;
}

PrivateResidualHandle FoldResidualComputationBackend::EvaluateKernel(
    const KernelResidualContext& context) const {
    PrivateResidualHandle unavailable = unavailable_handle(context);
    if (context.operation.kernel != AuditRelationKernel::FOLD_RS ||
        context.operation.relation != RelationKind::FOLDING ||
        !validate_kernel_residual_material(context))
        return unavailable;

    const PrivateStateMaterial* state = context.state(0);
    const std::vector<F>* challenge =
        context.field_aux(AuditPublicAuxKind::FOLD_CHALLENGE);
    if (!state || !state->has_private_share || !challenge ||
        challenge->size() != 1 || !context.material.has_field_input ||
        !context.material.has_field_output)
        return unavailable;
    std::vector<F> expected;
    if (!recompute_fold_rs_output(
            state->local_share, challenge->front(), &expected) ||
        !same_field_vector(expected, context.material.field_input) ||
        expected.size() != context.material.field_output.size())
        return unavailable;

    PrivateResidualShare share;
    share.ref = context.operation.ref;
    share.label = context.operation.label;
    share.relation = context.operation.relation;
    share.kernel = context.operation.kernel;
    share.checkpoint = context.operation.checkpoint;
    share.values.resize(expected.size(), F(0));
    for (size_t i = 0; i < expected.size(); ++i)
        share.values[i] = context.material.field_output[i] - expected[i];
    share.source_state_id = state->state.id;
    share.source_state_owner = state->state.label.owner;
    share.source_state_digest = state->state.digest;
    if (state->has_authentication) {
        share.source_state_authentication_scheme_id =
            state->authentication_scheme_id;
        share.source_state_authentication_binding =
            state->authentication_binding;
    }
    share.public_aux_root = context.operation.public_aux_root;
    share.expected = context.operation.expected;
    share.actual = context.operation.actual;
    share.operation_statement_binding = context.operation.relation_statement;
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

bool FoldResidualComputationBackend::AuthenticateStoredShare(
    const OperationRef& ref,
    const PrivateResidualShareAuthenticator& authenticator) {
    PrivateResidualShare* current=store_.Find(ref);
    if(!current || current->authenticated ||
       !validate_private_residual_share(*current) ||
       !current->computation_valid ||
       current->computation_binding!=
           compute_private_residual_computation_binding(*current))
        return false;
    PrivateResidualAuthenticationArtifact artifact{};
    if(!authenticator.Authenticate(*current,&artifact) ||
       artifact.scheme_id!=authenticator.SchemeId() ||
       !validate_private_residual_authentication_artifact(*current,artifact))
        return false;
    PrivateResidualShare updated=*current;
    updated.authentication=artifact;
    updated.authentication_binding=artifact.binding;
    updated.authenticated=true;
    updated.commitment=compute_private_residual_share_commitment(updated);
    return store_.Put(updated);
}

} // namespace pvia
