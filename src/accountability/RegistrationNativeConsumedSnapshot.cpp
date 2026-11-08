#include "RegistrationNativeConsumedSnapshot.hpp"

#include "PrivateAuditMaterialStore.hpp"
#include "PrivateStateMaterialStore.hpp"
#include "RegistrationNativeLocalRecord.hpp"
#include "RegistrationPreVssReceipt.hpp"

#include <algorithm>

namespace pvia {
namespace {
constexpr u64 CONSUMED_RECORD_DOMAIN = 0x5056524e43534e31ULL; // PVRNCSN1

void digest_to_words(const Digest& d, std::vector<u64>* words) {
    for (size_t i = 0; i < 4; ++i) {
        u64 value = 0;
        for (size_t j = 0; j < 8; ++j)
            value |= static_cast<u64>(d.bytes[8 * i + j]) << (8 * j);
        words->push_back(value);
    }
}
} // namespace

Digest compute_registration_native_consumed_record_binding(
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeConsumedSnapshot& snapshot,
    const AuditCheckpointView& checkpoint) {
    if (!validate_registration_consistency_statement(statement) ||
        !checkpoint.sealed || checkpoint.id != statement.checkpoint ||
        checkpoint.root == Digest{} ||
        checkpoint.root != statement.native_context.checkpoint_root ||
        std::count(checkpoint.operations.begin(), checkpoint.operations.end(),
                   statement.ref) != 1 ||
        snapshot.state_values.size() != statement.state_element_count ||
        snapshot.actual_output.size() != statement.output_element_count ||
        statement.native_context.authentication_binding == Digest{})
        return {};
    const auto prefix = registration_pre_vss_claim_words(statement);
    if (prefix.size() != 38 ||
        hash_words(prefix) != snapshot.pre_vss_claim_binding ||
        hash_field_vector(snapshot.state_values) !=
            statement.public_state_digest ||
        hash_field_vector(snapshot.actual_output) !=
            statement.public_actual_digest ||
        hash_field_vector({snapshot.public_challenge}) !=
            statement.public_challenge_binding)
        return {};

    std::vector<u64> binding_words = {
        CONSUMED_RECORD_DOMAIN,
        statement.sid, statement.checkpoint,
        static_cast<u64>(statement.ref.owner),
        statement.ref.object_id,
        statement.native_context.native_state_id,
        statement.native_context.authentication_scheme_id,
        static_cast<u64>(snapshot.state_values.size()),
        static_cast<u64>(snapshot.actual_output.size())
    };
    digest_to_words(snapshot.pre_vss_claim_binding, &binding_words);
    digest_to_words(hash_field_vector(snapshot.state_values), &binding_words);
    digest_to_words(hash_field_vector(snapshot.actual_output), &binding_words);
    digest_to_words(hash_field_vector({snapshot.public_challenge}), &binding_words);
    digest_to_words(checkpoint.root, &binding_words);
    digest_to_words(statement.native_context.authentication_binding,
                    &binding_words);
    return hash_words(binding_words);
}

bool verify_reference_registered_native_snapshot_witness_equality(
    const RegistrationConsistencyStatement& statement,
    const RegistrationConsistencyWitness& witness,
    const RegistrationNativeConsumedSnapshot& captured,
    const AuditCheckpointView& checkpoint) {
    // The native record is locally authenticated only to the finalized
    // reference stores/receipt. Do NOT promote this private comparison to
    // a production zero-knowledge registration capability.
    const Digest native_binding =
        compute_registration_native_consumed_record_binding(
            statement, captured, checkpoint);
    if (native_binding == Digest{} ||
        captured.consumed_record_binding != native_binding ||
        captured.pre_vss_claim_binding == Digest{} ||
        captured.state_values != witness.state_values ||
        captured.actual_output != witness.actual_output ||
        captured.public_challenge != witness.public_challenge ||
        witness.sharing_witness_words.empty())
        return false;
    return evaluate_reference_registration_consistency_relation(
        statement, witness);
}

bool read_registration_native_consumed_snapshot(
    const RegistrationConsistencyStatement& pre_vss_statement,
    const PrivateStateMaterialStore& states,
    const PrivateAuditMaterialStore& operations,
    const AuditCheckpointView& checkpoint,
    RegistrationNativeConsumedSnapshot* output) {
    if (!output || !verify_registration_local_native_record(
            pre_vss_statement, states, operations, checkpoint))
        return false;
    const auto* state =
        states.Find(pre_vss_statement.native_context.native_state_id);
    const auto* operation = operations.Find(pre_vss_statement.ref);
    if (!state || !operation || !state->has_private_share ||
        !operation->has_field_output ||
        state->local_share.size() != pre_vss_statement.state_element_count ||
        operation->field_output.size() !=
            pre_vss_statement.output_element_count)
        return false;
    size_t challenges = 0;
    F challenge{};
    for (const auto& aux : operation->field_aux) {
        if (aux.first != AuditPublicAuxKind::FOLD_CHALLENGE) continue;
        if (aux.second.size() != 1) return false;
        challenge = aux.second[0];
        ++challenges;
    }
    if (challenges != 1 ||
        hash_field_vector(state->local_share) !=
            pre_vss_statement.public_state_digest ||
        hash_field_vector(operation->field_output) !=
            pre_vss_statement.public_actual_digest ||
        hash_field_vector({challenge}) !=
            pre_vss_statement.public_challenge_binding)
        return false;

    const auto prefix = registration_pre_vss_claim_words(pre_vss_statement);
    if (prefix.size() != 38) return false;
    RegistrationNativeConsumedSnapshot captured;
    captured.state_values = state->local_share;
    captured.actual_output = operation->field_output;
    captured.public_challenge = challenge;
    captured.pre_vss_claim_binding = hash_words(prefix);
    captured.consumed_record_binding =
        compute_registration_native_consumed_record_binding(
            pre_vss_statement, captured, checkpoint);
    if (captured.consumed_record_binding == Digest{}) return false;
    *output = std::move(captured);
    return true;
}

bool registration_native_consumed_snapshot_still_matches(
    const RegistrationConsistencyStatement& pre_vss_statement,
    const PrivateStateMaterialStore& states,
    const PrivateAuditMaterialStore& operations,
    const AuditCheckpointView& checkpoint,
    const RegistrationNativeConsumedSnapshot& captured) {
    if (captured.consumed_record_binding == Digest{} ||
        captured.pre_vss_claim_binding == Digest{})
        return false;
    RegistrationNativeConsumedSnapshot current;
    return read_registration_native_consumed_snapshot(
               pre_vss_statement, states, operations,
               checkpoint, &current) &&
        current.pre_vss_claim_binding == captured.pre_vss_claim_binding &&
        current.consumed_record_binding == captured.consumed_record_binding &&
        current.state_values == captured.state_values &&
        current.actual_output == captured.actual_output &&
        current.public_challenge == captured.public_challenge;
}

RegistrationNativeStoreSourceProvider::RegistrationNativeStoreSourceProvider(
    const PrivateStateMaterialStore& states,
    const PrivateAuditMaterialStore& operations,
    const AuditCheckpointView& checkpoint)
    : states_(states), operations_(operations), checkpoint_(checkpoint) {}

bool RegistrationNativeStoreSourceProvider::capture(
    const RegistrationConsistencyStatement& pre_vss_statement,
    RegistrationNativeConsumedSnapshot* output) const {
    return read_registration_native_consumed_snapshot(
        pre_vss_statement, states_, operations_, checkpoint_, output);
}

bool RegistrationNativeStoreSourceProvider::still_matches(
    const RegistrationConsistencyStatement& pre_vss_statement,
    const RegistrationNativeConsumedSnapshot& captured) const {
    return registration_native_consumed_snapshot_still_matches(
        pre_vss_statement, states_, operations_, checkpoint_, captured);
}

} // namespace pvia
