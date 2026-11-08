#include "RegistrationNativeLocalRecord.hpp"

#include "PrivateStateMaterialStore.hpp"
#include "PrivateAuditMaterialStore.hpp"

#include <algorithm>

namespace pvia {

bool verify_registration_local_native_record(
    const RegistrationConsistencyStatement& statement,
    const PrivateStateMaterialStore& states,
    const PrivateAuditMaterialStore& operations,
    const AuditCheckpointView& checkpoint) {
    if (!validate_registration_consistency_statement(statement) ||
        !checkpoint.sealed || checkpoint.id != statement.checkpoint ||
        checkpoint.root == Digest{} ||
        checkpoint.root != statement.native_context.checkpoint_root ||
        std::count(checkpoint.operations.begin(), checkpoint.operations.end(),
                   statement.ref) != 1)
        return false;

    const StateId id = statement.native_context.native_state_id;
    const PrivateStateMaterial* state = states.Find(id);
    const PrivateOperationMaterial* operation =
        operations.Find(statement.ref);
    if (!state || !operation || !state->has_private_share ||
        !states.VerifyDigest(id) || !states.VerifyAuthentication(id) ||
        state->state.label.sid != statement.sid ||
        state->state.label.owner != statement.ref.owner ||
        state->state.digest != statement.public_state_digest ||
        state->local_share.size() != statement.state_element_count ||
        state->authentication_scheme_id !=
            statement.native_context.authentication_scheme_id ||
        state->authentication_binding !=
            statement.native_context.authentication_binding)
        return false;

    const AuditOperationView& native = operation->operation;
    if (!operation->finalized || !native.active || native.observed_remote ||
        native.ref != statement.ref ||
        native.label.sid != statement.sid ||
        native.label.owner != statement.ref.owner ||
        native.label.object_id != statement.ref.object_id ||
        native.label.phase != Phase::FOLD ||
        native.label.obligation != Obligation::FOLD ||
        native.relation != RelationKind::FOLDING ||
        native.checkpoint != statement.checkpoint ||
        operation->field_kind != AuditPrivatePayloadKind::FIELD_VECTOR ||
        native.kernel != AuditRelationKernel::FOLD_RS ||
        native.actual != statement.public_actual_digest ||
        native.relation_statement != statement.operation_statement_binding ||
        native.predecessor_root != statement.native_context.predecessor_root ||
        native.state_dependency_count != 1 ||
        native.state_dependency_root != compute_state_dependency_root({
            StateDependencyEvidence{statement.ref.owner, id,
                                    statement.public_state_digest}}) ||
        native.public_aux_count != 1 ||
        !operations.VerifyPublicAuxCommitment(statement.ref) ||
        operation->state_dependencies.size() != 1 ||
        operation->state_dependencies.front() != id ||
        !operation->has_field_output ||
        operation->field_output.size() != statement.output_element_count ||
        !operations.VerifyPrivatePayloadDigests(statement.ref))
        return false;

    size_t challenge_count = 0;
    for (const auto& aux : operation->field_aux) {
        if (aux.first != AuditPublicAuxKind::FOLD_CHALLENGE) continue;
        if (aux.second.size() != 1 ||
            hash_field_vector(aux.second) !=
                statement.public_challenge_binding)
            return false;
        ++challenge_count;
    }
    return challenge_count == 1;
}

} // namespace pvia
