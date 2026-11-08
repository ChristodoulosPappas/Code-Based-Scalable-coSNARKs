#include "ExternalMultiplicationConsistencyProofAdapter.hpp"
#include "MultiplicationConsistencyWitnessRelation.hpp"
#include "MultiplicationConsistencyProviderAbi.hpp"
#include "MultiplicationConsistencyProviderAbiHelpers.h"

#include <utility>

namespace pvia {

ExternalMultiplicationConsistencyProofAdapter::
ExternalMultiplicationConsistencyProofAdapter(
    MultiplicationConsistencyCapabilities capabilities,
    uint32_t expected_proof_system_id,
    MultiplicationConsistencyProviderCallbacks callbacks)
    : capabilities_(std::move(capabilities)),
      expected_proof_system_id_(expected_proof_system_id),
      callbacks_(std::move(callbacks)) {
    ready_ =
        expected_proof_system_id_ != 0 &&
        production_ready_multiplication_consistency_capabilities(
            capabilities_) &&
        static_cast<bool>(callbacks_.prove) &&
        static_cast<bool>(callbacks_.verify);
}

MultiplicationConsistencyCapabilities
ExternalMultiplicationConsistencyProofAdapter::Capabilities() const {
    return ready_ ? capabilities_ : MultiplicationConsistencyCapabilities{};
}

MultiplicationConsistencyProofArtifact
ExternalMultiplicationConsistencyProofAdapter::Prove(
    const MultiplicationConsistencyStatement& statement,
    const MultiplicationConsistencyWitness& witness) const {
    MultiplicationConsistencyProofArtifact proof;
    last_error_.clear();
    if (!ready_) {
        last_error_ = "adapter is not ready";
        return proof;
    }
    if (!validate_multiplication_consistency_statement(statement)) {
        last_error_ = "multiplication statement validation failed";
        return proof;
    }
    if (!validate_multiplication_consistency_provider_witness_relation(
            statement, witness)) {
        last_error_ = "provider witness relation validation failed";
        return proof;
    }
    const auto statement_words =
        encode_multiplication_consistency_statement_abi(statement);
    const auto witness_words =
        encode_multiplication_consistency_witness_abi(witness);
    pvia_mc_statement_view c_statement{};
    pvia_mc_witness_view c_witness{};
    if (!pvia_mc_parse_statement(
            statement_words.data(), statement_words.size(), &c_statement) ||
        !pvia_mc_parse_witness(
            witness_words.data(), witness_words.size(), &c_witness) ||
        !pvia_mc_validate_witness_payloads(&c_witness)) {
        last_error_ = "provider ABI statement/witness preflight failed";
        return proof;
    }
    proof = callbacks_.prove(statement, witness);
    const auto append_callback_error = [this]() {
        if (!callbacks_.last_error) return;
        const std::string detail = callbacks_.last_error();
        if (!detail.empty()) last_error_ += "; provider detail: " + detail;
    };
    if (proof.proof_system_id != expected_proof_system_id_) {
        last_error_ = "provider proof-system id mismatch (got " +
            std::to_string(proof.proof_system_id) + ", expected " +
            std::to_string(expected_proof_system_id_) + ")";
        append_callback_error();
        return MultiplicationConsistencyProofArtifact{};
    }
    if (!validate_multiplication_consistency_proof_artifact(statement, proof)) {
        last_error_ = "provider proof artifact failed canonical validation";
        append_callback_error();
        return MultiplicationConsistencyProofArtifact{};
    }
    if (!callbacks_.verify(statement, proof)) {
        last_error_ = "provider verification callback rejected the proof";
        append_callback_error();
        return MultiplicationConsistencyProofArtifact{};
    }
    last_error_.clear();
    return proof;
}

bool ExternalMultiplicationConsistencyProofAdapter::Verify(
    const MultiplicationConsistencyStatement& statement,
    const MultiplicationConsistencyProofArtifact& proof) const {
    last_error_.clear();
    if (!ready_) {
        last_error_ = "adapter is not ready";
        return false;
    }
    if (proof.proof_system_id != expected_proof_system_id_) {
        last_error_ = "provider proof-system id mismatch";
        return false;
    }
    if (!validate_multiplication_consistency_statement(statement) ||
        !validate_multiplication_consistency_proof_artifact(statement, proof)) {
        last_error_ = "provider proof verification preflight failed";
        return false;
    }
    if (!callbacks_.verify(statement, proof)) {
        last_error_ = "provider verification callback rejected the proof";
        if (callbacks_.last_error) {
            const std::string detail = callbacks_.last_error();
            if (!detail.empty()) last_error_ += "; provider detail: " + detail;
        }
        return false;
    }
    return true;
}

} // namespace pvia
