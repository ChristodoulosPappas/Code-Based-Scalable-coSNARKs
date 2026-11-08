#include "RegistrationConsistencyProof.hpp"
#include "ReferenceBivariateVss.hpp"
#include "FoldResidualComputationBackend.hpp"
#include <limits>

#include <cstring>

namespace pvia {
namespace {

constexpr u64 REG_STATEMENT_DOMAIN = 0x5056524547435354ULL; // PVREGCST
constexpr u64 REG_PROOF_DOMAIN = 0x5056524547505246ULL;     // PVREGPRF
constexpr u64 REG_SET_DOMAIN = 0x5056524547534554ULL;       // PVREGSET
constexpr u64 REG_CAP_DOMAIN = 0x5056524547434150ULL;       // PVREGCAP

void append_digest(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

} // namespace

bool validate_registration_native_context(
    const RegistrationNativeContext& context) {
    return context.native_state_id != 0 &&
        context.authentication_scheme_id != 0 &&
        context.authentication_binding != Digest{} &&
        context.predecessor_root != Digest{} &&
        context.checkpoint_root != Digest{};
}

Digest compute_registration_native_context_binding(
    const RegistrationNativeContext& context) {
    if (!validate_registration_native_context(context)) return Digest{};
    std::vector<u64> words = {
        0x50565245474e4154ULL, // PVREGNAT
        context.native_state_id, context.authentication_scheme_id};
    append_digest(context.authentication_binding, &words);
    append_digest(context.predecessor_root, &words);
    append_digest(context.checkpoint_root, &words);
    return hash_words(words);
}

namespace {
std::vector<u64> registration_statement_payload_words(
    const RegistrationConsistencyStatement& statement) {
    std::vector<u64> words = {
        REG_STATEMENT_DOMAIN, statement.sid, statement.checkpoint,
        statement.ref.owner, statement.ref.object_id,
        static_cast<u64>(statement.kernel),
        static_cast<u64>(statement.state_element_count),
        static_cast<u64>(statement.output_element_count)};
    append_digest(statement.public_state_digest, &words);
    append_digest(statement.public_actual_digest, &words);
    append_digest(statement.public_challenge_binding, &words);
    words.push_back(statement.native_context.native_state_id);
    words.push_back(statement.native_context.authentication_scheme_id);
    append_digest(statement.native_context.authentication_binding, &words);
    append_digest(statement.native_context.predecessor_root, &words);
    append_digest(statement.native_context.checkpoint_root, &words);
    append_digest(statement.operation_statement_binding, &words);
    append_digest(statement.sharing_transcript_binding, &words);
    return words;
}

}

Digest compute_registration_consistency_statement_binding(
    const RegistrationConsistencyStatement& statement) {
    return hash_words(registration_statement_payload_words(statement));
}

std::vector<u64> encode_registration_consistency_statement_words(
    const RegistrationConsistencyStatement& statement) {
    if (statement.kernel != AuditRelationKernel::FOLD_RS ||
        !validate_registration_consistency_statement(statement))
        return {};
    std::vector<u64> words = registration_statement_payload_words(statement);
    if (words.size() != 42) return {};
    append_digest(statement.statement_binding, &words);
    return words;
}

bool validate_registration_consistency_statement(
    const RegistrationConsistencyStatement& statement) {
    if (statement.sid == 0 || statement.checkpoint == 0 ||
        statement.kernel == AuditRelationKernel::UNKNOWN ||
        statement.state_element_count == 0 ||
        statement.output_element_count == 0 ||
        statement.public_state_digest == Digest{} ||
        statement.public_actual_digest == Digest{} ||
        statement.public_challenge_binding == Digest{} ||
        !validate_registration_native_context(statement.native_context) ||
        statement.operation_statement_binding == Digest{} ||
        statement.sharing_transcript_binding == Digest{} ||
        statement.statement_binding == Digest{})
        return false;
    return statement.statement_binding ==
        compute_registration_consistency_statement_binding(statement);
}

Digest compute_registration_consistency_proof_commitment(
    const RegistrationConsistencyProofArtifact& proof) {
    std::vector<u64> words = {
        REG_PROOF_DOMAIN,
        proof.available ? 1ULL : 0ULL,
        proof.cryptographically_authenticated ? 1ULL : 0ULL,
        proof.zero_knowledge ? 1ULL : 0ULL,
        proof.proof_system_id,
        static_cast<u64>(proof.proof_words.size())};
    append_digest(proof.statement_binding, &words);
    append_digest(proof.transcript_binding, &words);
    words.insert(words.end(), proof.proof_words.begin(), proof.proof_words.end());
    return hash_words(words);
}

bool validate_registration_consistency_proof_artifact(
    const RegistrationConsistencyStatement& statement,
    const RegistrationConsistencyProofArtifact& proof) {
    if (!validate_registration_consistency_statement(statement) ||
        !proof.available || !proof.cryptographically_authenticated ||
        !proof.zero_knowledge || proof.proof_system_id == 0 ||
        proof.statement_binding != statement.statement_binding ||
        proof.transcript_binding == Digest{} || proof.proof_words.empty() ||
        proof.proof_commitment == Digest{})
        return false;
    return proof.proof_commitment ==
        compute_registration_consistency_proof_commitment(proof);
}
Digest compute_registration_consistency_set_binding(
    const std::vector<RegistrationConsistencyProofArtifact>& proofs) {
    if (proofs.empty()) return Digest{};
    std::vector<u64> words = {
        REG_SET_DOMAIN, static_cast<u64>(proofs.size())};
    for (const auto& proof : proofs) {
        if (!proof.available || !proof.cryptographically_authenticated ||
            !proof.zero_knowledge || proof.proof_system_id == 0 ||
            proof.statement_binding == Digest{} ||
            proof.transcript_binding == Digest{} ||
            proof.proof_words.empty() || proof.proof_commitment == Digest{} ||
            proof.proof_commitment !=
                compute_registration_consistency_proof_commitment(proof))
            return Digest{};
        append_digest(proof.proof_commitment, &words);
    }
    return hash_words(words);
}

Digest compute_registration_consistency_capability_binding(
    const RegistrationConsistencyCapabilities& capabilities) {
    std::vector<u64> words = {
        REG_CAP_DOMAIN,
        capabilities.available ? 1ULL : 0ULL,
        capabilities.malicious_sound ? 1ULL : 0ULL,
        capabilities.zero_knowledge ? 1ULL : 0ULL,
        capabilities.binds_sharing_transcript ? 1ULL : 0ULL,
        capabilities.reference_test_only ? 1ULL : 0ULL,
        capabilities.protocol_id};
    append_digest(capabilities.implementation_binding, &words);
    return hash_words(words);
}
bool validate_registration_consistency_capabilities(
    const RegistrationConsistencyCapabilities& capabilities) {
    if (!capabilities.available || capabilities.protocol_id == 0 ||
        capabilities.implementation_binding == Digest{} ||
        capabilities.capability_binding == Digest{})
        return false;
    return capabilities.capability_binding ==
        compute_registration_consistency_capability_binding(capabilities);
}

bool production_ready_registration_consistency_capabilities(
    const RegistrationConsistencyCapabilities& capabilities) {
    return validate_registration_consistency_capabilities(capabilities) &&
        capabilities.malicious_sound && capabilities.zero_knowledge &&
        capabilities.binds_sharing_transcript &&
        !capabilities.reference_test_only;
}

bool evaluate_reference_registration_consistency_relation(
    const RegistrationConsistencyStatement& statement,
    const RegistrationConsistencyWitness& witness) {
    if (!validate_registration_consistency_statement(statement) ||
        statement.kernel != AuditRelationKernel::FOLD_RS ||
        witness.state_values.size() != statement.state_element_count ||
        witness.actual_output.size() != statement.output_element_count ||
        witness.sharing_witness_words.empty() ||
        hash_field_vector(witness.state_values) !=
            statement.public_state_digest ||
        hash_field_vector(witness.actual_output) !=
            statement.public_actual_digest ||
        hash_field_vector({witness.public_challenge}) !=
            statement.public_challenge_binding)
        return false;

    ReferenceVssDealerWitness dealer;
    if (!decode_reference_vss_dealer_witness(
            witness.sharing_witness_words, &dealer) ||
        !validate_reference_vss_dealer_witness(dealer) ||
        dealer.dealer != static_cast<int>(statement.ref.owner) ||
        dealer.transcript_binding != statement.sharing_transcript_binding)
        return false;

    if (statement.state_element_count >
        std::numeric_limits<size_t>::max() -
            statement.output_element_count)
        return false;
    const size_t count = statement.state_element_count +
        statement.output_element_count;
    const size_t dimension = static_cast<size_t>(dealer.threshold) + 1;
    if (dimension == 0 ||
        dimension > std::numeric_limits<size_t>::max() / dimension ||
        dealer.element_count != count ||
        dimension * dimension > std::numeric_limits<size_t>::max() / 2 ||
        count > std::numeric_limits<size_t>::max() /
            (dimension * dimension * 2))
        return false;
    const size_t stride = dimension * dimension * 2;
    if (dealer.coefficient_words.size() != count * stride)
        return false;

    // A symmetric bivariate VSS polynomial F_k(x,y) encodes the
    // registered secret at F_k(0,0), namely the first field coefficient.
    // The dealer witness has already been checked against every row
    // commitment and this registration's VSS transcript.
    for (size_t k = 0; k < count; ++k) {
        const u64 real = dealer.coefficient_words[k * stride];
        const u64 imag = dealer.coefficient_words[k * stride + 1];
        if (real >= F::mod || imag >= F::mod) return false;
        const F registered(static_cast<long long>(real),
                           static_cast<long long>(imag));
        const F native = k < statement.state_element_count
            ? witness.state_values[k]
            : witness.actual_output[k - statement.state_element_count];
        if (registered != native) return false;
    }
    std::vector<F> expected;
    if (!recompute_fold_rs_output(
            witness.state_values, witness.public_challenge, &expected) ||
        expected.size() != witness.actual_output.size())
        return false;

    // The output may be incorrect during accountability: we bind its
    // *actual* native value to VSS, without requiring clean FOLD output.
    // The separate private residual relation determines correctness.
    return true;
}

RegistrationConsistencyCapabilities
FailClosedRegistrationConsistencyProofBackend::Capabilities() const {
    return RegistrationConsistencyCapabilities{};
}

RegistrationConsistencyProofArtifact
FailClosedRegistrationConsistencyProofBackend::Prove(
    const RegistrationConsistencyStatement& statement,
    const RegistrationConsistencyWitness&) const {
    RegistrationConsistencyProofArtifact proof;
    proof.statement_binding = statement.statement_binding;
    return proof;
}
bool FailClosedRegistrationConsistencyProofBackend::Verify(
    const RegistrationConsistencyStatement&,
    const RegistrationConsistencyProofArtifact&) const {
    return false;
}

} // namespace pvia
