#include "FoldResidualComputationSelfTest.hpp"

#include "FoldResidualComputationBackend.hpp"
#include "NativeSumcheckResidualComputationBackend.hpp"
#include "Sp1SumcheckProofProvider.hpp"
#include "Ed25519PrivateResidualShareAuthenticator.hpp"
#include "ResidualNativeSourcePinReceipt.hpp"
#include <openssl/evp.h>
#include <cstdlib>
#include <unistd.h>
#include <fstream>
#include <sys/stat.h>
#include "FailClosedSecureAuditProvider.hpp"
#include "SecureAuditComposition.hpp"

namespace pvia {
namespace {
bool make_test_ed25519_keypair(
    std::array<uint8_t,32>* private_key,
    std::array<uint8_t,32>* public_key) {
    if(!private_key || !public_key) return false;
    EVP_PKEY_CTX* context=EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519,nullptr);
    EVP_PKEY* key=nullptr;
    const bool generated=context &&
        EVP_PKEY_keygen_init(context)==1 &&
        EVP_PKEY_keygen(context,&key)==1;
    size_t private_size=private_key->size();
    size_t public_size=public_key->size();
    const bool extracted=generated &&
        EVP_PKEY_get_raw_private_key(
            key,private_key->data(),&private_size)==1 &&
        EVP_PKEY_get_raw_public_key(
            key,public_key->data(),&public_size)==1 &&
        private_size==private_key->size() &&
        public_size==public_key->size();
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(context);
    return extracted;
}

bool sign_test_provenance_receipt(
    PrivateResidualProvenanceReceipt* receipt,
    const std::array<uint8_t,32>& private_key) {
    if(!receipt) return false;
    const auto message=private_residual_provenance_signing_message(*receipt);
    if(message.empty()) return false;
    EVP_PKEY* key=EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519,nullptr,private_key.data(),private_key.size());
    if(!key) return false;
    EVP_MD_CTX* context=EVP_MD_CTX_new();
    size_t signature_size=receipt->signature.size();
    const bool signed_ok=context &&
        EVP_DigestSignInit(context,nullptr,nullptr,nullptr,key)==1 &&
        EVP_DigestSign(context,receipt->signature.data(),&signature_size,
                       message.data(),message.size())==1 &&
        signature_size==receipt->signature.size();
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    return signed_ok;
}

class MalformedResidualAuthenticator final
    : public PrivateResidualShareAuthenticator {
public:
    uint64_t SchemeId() const override { return 0x5445535450524f56ULL; }

    bool Authenticate(
        const PrivateResidualShare& share,
        PrivateResidualAuthenticationArtifact* artifact) const override {
        if (!artifact) return false;
        artifact->available = true;
        artifact->cryptographically_authenticated = true;
        artifact->scheme_id = SchemeId();
        artifact->computation_binding = share.computation_binding;
        artifact->source_state_id = share.source_state_id;
        artifact->source_state_owner = share.source_state_owner;
        artifact->source_state_digest = share.source_state_digest;
        artifact->source_state_authentication_scheme_id =
            share.source_state_authentication_scheme_id;
        artifact->source_state_authentication_binding =
            share.source_state_authentication_binding;
        artifact->public_aux_root = share.public_aux_root;
        artifact->operation_statement_binding =
            share.operation_statement_binding;
        artifact->proof_commitment = hash_words({1ULL});
        artifact->transcript_binding = hash_words({2ULL});
        artifact->binding = Digest{};
        return true;
    }
};
} // namespace

namespace {

bool run_native_sumcheck_case(
    AuditRelationKernel kernel, const std::vector<std::vector<F>>& segments,
    const std::vector<F>& aux, uint64_t case_id, bool corrupt_output,
    const Sp1SumcheckProofProvider* sp1_provider = nullptr,
    const Sp1SumcheckProofProvider* proof_provider = nullptr) {
    std::vector<F> flattened;
    std::vector<size_t> segment_lengths;
    for (const auto& segment : segments) {
        segment_lengths.push_back(segment.size());
        flattened.insert(flattened.end(), segment.begin(), segment.end());
    }
    if (flattened.empty() || segments.empty()) return false;

    AuditStateView state;
    state.id = 100 + case_id;
    state.label.sid = 77;
    state.label.phase = kernel == AuditRelationKernel::COSUMCHECK_ZERO
        ? Phase::COSUMCHECK_ZERO
        : (kernel == AuditRelationKernel::COSUMCHECK_QUADRATIC
            ? Phase::COSUMCHECK_QUADRATIC
            : (kernel == AuditRelationKernel::COSUMCHECK_BATCH
                ? Phase::COSUMCHECK_BATCH : Phase::DISTRIBUTED_SUMCHECK));
    state.label.round = 2;
    state.label.owner = 0;
    state.label.obligation = Obligation::DERIVE;
    state.label.object_id = state.id;
    state.digest = hash_field_vector(flattened);

    PrivateStateMaterialStore states;
    if (!states.RegisterMetadata(state) ||
        !states.BindPrivateStateSegments(state, flattened, segment_lengths) ||
        !states.VerifyDigest(state.id) ||
        !states.VerifySegmentLayout(state.id) ||
        !states.BindPrivateStateSegments(state, flattened, segment_lengths))
        return false;

    // A different partition of the same flattened values must not overwrite
    // the already captured local source layout.
    if (states.BindPrivateStateSegments(
            state, flattened, std::vector<size_t>{flattened.size()}))
        return false;

    AuditOperationView operation;
    operation.ref.owner = 0;
    operation.ref.object_id = 500 + case_id;
    operation.label.sid = state.label.sid;
    operation.label.phase = state.label.phase;
    operation.label.round = state.label.round;
    operation.label.owner = 0;
    operation.label.obligation = Obligation::DERIVE;
    operation.label.object_id = operation.ref.object_id;
    operation.relation = RelationKind::PRIVATE_DERIVATION;
    operation.kernel = kernel;
    operation.checkpoint = 900 + case_id;
    operation.active = true;
    operation.observed_remote = false;
    operation.public_aux_count = 1;
    operation.relation_statement = hash_words({0x53554d434845434bULL, case_id});

    PrivateOperationMaterial source_material;
    source_material.operation = operation;
    source_material.state_dependencies = {state.id};
    source_material.field_aux.emplace_back(
        AuditPublicAuxKind::SUMCHECK_CHALLENGE, aux);
    KernelResidualContext source_context{
        operation, source_material, states};
    std::vector<F> coefficients;
    if (!recompute_native_sumcheck_polynomial(
            source_context, &coefficients) || coefficients.empty())
        return false;

    const bool cubic =
        kernel == AuditRelationKernel::COSUMCHECK_ZERO ||
        kernel == AuditRelationKernel::DSC_CUBIC;
    const AuditPrivatePayloadKind kind = cubic
        ? AuditPrivatePayloadKind::CUBIC
        : AuditPrivatePayloadKind::QUADRATIC;
    std::vector<F> actual = coefficients;
    if (corrupt_output) actual[0] += F(1);
    operation.expected = hash_field_vector(coefficients);
    operation.actual = hash_field_vector(actual);
    operation.public_aux_root = compute_public_aux_root(
        std::vector<PublicAuxEvidence>{PublicAuxEvidence{
            AuditPublicAuxKind::SUMCHECK_CHALLENGE, hash_field_vector(aux)}});

    PrivateAuditMaterialStore materials;
    materials.RegisterOperation(operation);
    materials.BindPrivateField(
        operation, kind, AuditPayloadStage::REGISTER_INPUT, coefficients);
    materials.BindPrivateField(
        operation, kind, AuditPayloadStage::ACTIVATE_OUTPUT, actual);
    materials.BindStateDependencies(operation, {state.id});
    materials.BindPublicFieldAux(
        operation, AuditPublicAuxKind::SUMCHECK_CHALLENGE, aux);
    if (!materials.ReadyForResidual(operation.ref)) return false;

    const PrivateOperationMaterial* material =
        materials.Find(operation.ref);
    if (!material) return false;
    KernelResidualContext context{operation, *material, states};
    if (sp1_provider && sp1_provider->Available()) {
        std::vector<uint64_t> statement_words, witness_words;
        if (!sp1_provider->BuildRelationInput(
                context, &statement_words, &witness_words) ||
            !sp1_provider->ValidateRelationInput(
                statement_words, witness_words))
            return false;
    }
    PrivateResidualShareStore shares;
    NativeSumcheckResidualComputationBackend backend(
        shares, nullptr, proof_provider);
    const PrivateResidualHandle handle = backend.EvaluateKernel(context);
    const PrivateResidualShare* share = shares.Find(operation.ref);
    if (!handle.available || handle.authenticated || !share ||
        !validate_private_residual_share(*share) ||
        share->source_state_layout_binding !=
            states.Find(state.id)->segment_layout_binding ||
        share->values.size() != coefficients.size())
        return false;

    for (size_t i = 0; i < share->values.size(); ++i) {
        const F expected = corrupt_output && i == 0 ? F(1) : F(0);
        if (share->values[i] != expected) return false;
    }
    return true;
}

bool run_native_sumcheck_backend_selftest() {
    const std::vector<F> a = {F(1), F(2), F(3), F(5)};
    const std::vector<F> b = {F(7), F(11), F(13), F(17)};
    const std::vector<F> c = {F(19), F(23), F(29), F(31)};
    const std::vector<F> d = {F(37), F(41), F(43), F(47)};
    const std::vector<F> beta = {F(2), F(3), F(5), F(7)};
    const std::vector<F> mask_a = {F(53), F(59), F(61), F(67)};
    const std::vector<F> mask_b = {F(71), F(73), F(79), F(83)};
    const std::vector<F> ordinary_aux = {F(97)};
    const std::vector<F> masked_aux = {F(101), F(3)};

    Sp1SumcheckProofProvider sp1_provider;
    const char* provider_library =
        std::getenv("PVIA_SP1_SUMCHECK_PROVIDER_LIBRARY");
    const Sp1SumcheckProofProvider* sp1 = nullptr;
    if (provider_library && *provider_library) {
        if (!sp1_provider.Available()) return false;
        sp1 = &sp1_provider;
    }

    return
        run_native_sumcheck_case(
            AuditRelationKernel::COSUMCHECK_ZERO,
            {a, b, c, beta, mask_a, mask_b}, masked_aux, 1, false, sp1, nullptr) &&
        run_native_sumcheck_case(
            AuditRelationKernel::COSUMCHECK_QUADRATIC,
            {a, b}, ordinary_aux, 2, false, sp1, nullptr) &&
        run_native_sumcheck_case(
            AuditRelationKernel::COSUMCHECK_BATCH,
            {a, b, c, d, mask_a, mask_b}, masked_aux, 3, false, sp1, nullptr) &&
        run_native_sumcheck_case(
            AuditRelationKernel::DSC_QUADRATIC,
            {a, b}, ordinary_aux, 4, false, sp1, sp1) &&
        run_native_sumcheck_case(
            AuditRelationKernel::DSC_CUBIC,
            {a, b, c}, ordinary_aux, 5, false, sp1, nullptr) &&
        run_native_sumcheck_case(
            AuditRelationKernel::DSC_CUBIC,
            {a, b, c}, ordinary_aux, 6, true, nullptr, nullptr);
}

} // namespace

bool run_fold_residual_computation_selftest() {
    if (!run_native_sumcheck_backend_selftest()) return false;
    const std::vector<F> input = {
        F(1), F(2), F(3), F(4), F(5), F(6), F(7), F(8)};
    const F challenge = F(3);
    std::vector<F> expected;
    if (!recompute_fold_rs_output(input, challenge, &expected) ||
        expected.empty())
        return false;

    std::vector<F> actual = expected;
    actual[0] = actual[0] + F(1);

    AuditStateView state_view;
    state_view.id = 1;
    state_view.label.sid = 1;
    state_view.label.phase = Phase::FOLD;
    state_view.label.owner = 0;
    state_view.digest = hash_field_vector(input);
    PrivateStateMaterialStore states;
    states.RegisterMetadata(state_view);
    states.BindPrivateState(state_view, input);
    const Digest synthetic_state_auth = hash_words({0x5056494153544154ULL});
    if (!states.BindAuthentication(state_view, 0x5445535450524f56ULL,
                                   synthetic_state_auth) ||
        !states.BindAuthentication(state_view, 0x5445535450524f56ULL,
                                   synthetic_state_auth) ||
        states.BindAuthentication(state_view, 0x5445535450524f57ULL,
                                  synthetic_state_auth) ||
        states.BindAuthentication(state_view, 0x5445535450524f56ULL,
                                  hash_words({0xBADULL})) ||
        !states.VerifyDigest(state_view.id) ||
        !states.VerifyAuthentication(state_view.id))
        return false;

    // StateId is an immutable protocol identity. Repeated identical imports
    // are harmless, while a digest/label mutation invalidates that ID and
    // cannot reattach the previous share or authentication.
    if (!states.RegisterMetadata(state_view) ||
        !states.BindPrivateState(state_view, input))
        return false;
    PrivateStateMaterialStore changed_share;
    if (!changed_share.RegisterMetadata(state_view) ||
        !changed_share.BindPrivateState(state_view, input))
        return false;
    std::vector<F> alternate_share = input;
    alternate_share[0] += F(1);
    if (changed_share.BindPrivateState(state_view, alternate_share) ||
        !changed_share.VerifyDigest(state_view.id))
        return false;
    PrivateStateMaterialStore mutated_state;
    if (!mutated_state.RegisterMetadata(state_view) ||
        !mutated_state.BindPrivateState(state_view, input) ||
        !mutated_state.BindAuthentication(state_view,
            0x5445535450524f56ULL, synthetic_state_auth))
        return false;
    AuditStateView altered = state_view;
    altered.digest = hash_field_vector(alternate_share);
    if (mutated_state.RegisterMetadata(altered) ||
        mutated_state.BindPrivateState(altered, alternate_share) ||
        mutated_state.BindAuthentication(altered,
            0x5445535450524f56ULL, synthetic_state_auth) ||
        mutated_state.Find(state_view.id) != nullptr ||
        mutated_state.VerifyDigest(state_view.id) ||
        mutated_state.VerifyAuthentication(state_view.id) ||
        mutated_state.RegisterMetadata(state_view))
        return false;
    PrivateStateMaterialStore shifted_label;
    if (!shifted_label.RegisterMetadata(state_view) ||
        !shifted_label.BindPrivateState(state_view, input))
        return false;
    altered = state_view;
    altered.label.sid += 1;
    if (shifted_label.RegisterMetadata(altered) ||
        shifted_label.Find(state_view.id) != nullptr)
        return false;

    FailClosedSecureAuditProvider fail_closed_provider;
    if (fail_closed_provider.BindPrivateStateAuthentication(
            state_view, 0x5445535450524f56ULL, synthetic_state_auth))
        return false;

    SecureAuditComponents empty_components;
    ComposedSecureAuditProvider composed_provider(empty_components, true);
    composed_provider.RegisterStateMetadata(state_view);
    composed_provider.BindPrivateState(state_view, input);
    SecureAuditBackend composed_backend(composed_provider);
    if (!composed_backend.OnBindPrivateStateAuthentication(
            state_view, 0x5445535450524f56ULL, synthetic_state_auth) ||
        composed_backend.OnBindPrivateStateAuthentication(
            state_view, 0x5445535450524f57ULL, synthetic_state_auth) ||
        composed_provider.Ready(SecureAuditRequirements{}))
        return false;

    // A native SP1 candidate-proof provider is diagnostic evidence only. It
    // must not satisfy the production secure-composition requirements or
    // cause an absent relation receipt to be reported as available.
    Sp1SumcheckProofProvider candidate_only_proof_provider;
    SecureAuditComponents candidate_only_components;
    candidate_only_components.native_sumcheck_proof_provider =
        &candidate_only_proof_provider;
    ComposedSecureAuditProvider candidate_only_provider(
        candidate_only_components, true);
    SecureAuditBackend candidate_only_backend(candidate_only_provider);
    SecureAuditRequirements candidate_only_requirements;
    candidate_only_requirements.private_lane = true;
    candidate_only_requirements.transfer_lane = false;
    candidate_only_requirements.private_security_level =
        RobustAuditSecurityLevel::MALICIOUS_GOD;
    candidate_only_requirements.required_kernels = {
        AuditRelationKernel::COSUMCHECK_ZERO,
        AuditRelationKernel::COSUMCHECK_QUADRATIC,
        AuditRelationKernel::COSUMCHECK_BATCH,
        AuditRelationKernel::DSC_QUADRATIC,
        AuditRelationKernel::DSC_CUBIC};
    AuditRelationProofReceipt absent_candidate_receipt;
    if (candidate_only_provider.Ready(candidate_only_requirements) ||
        candidate_only_backend.ReadRelationProofReceipt(
            AuditRelationKernel::COSUMCHECK_ZERO,
            &absent_candidate_receipt) ||
        absent_candidate_receipt.available ||
        absent_candidate_receipt.proof_verified)
        return false;
    AuditOperationView operation;
    operation.ref = OperationRef{0, 1};
    operation.label.sid = 1;
    operation.label.phase = Phase::FOLD;
    operation.label.round = 0;
    operation.label.owner = 0;
    operation.label.obligation = Obligation::FOLD;
    operation.label.object_id = 1;
    operation.relation = RelationKind::FOLDING;
    operation.kernel = AuditRelationKernel::FOLD_RS;
    operation.expected = hash_field_vector(expected);
    operation.actual = hash_field_vector(actual);
    operation.predecessor_root = hash_words(std::vector<u64>{});
    operation.predecessor_count = 0;
    operation.checkpoint = 1;
    operation.active = true;

    StateDependencyEvidence state_evidence;
    state_evidence.owner = 0;
    state_evidence.state_id = state_view.id;
    state_evidence.digest = state_view.digest;
    operation.state_dependency_root =
        compute_state_dependency_root({state_evidence});
    operation.state_dependency_count = 1;

    PublicAuxEvidence aux_evidence;
    aux_evidence.kind = AuditPublicAuxKind::FOLD_CHALLENGE;
    aux_evidence.digest = hash_field_vector({challenge});
    operation.public_aux_root = compute_public_aux_root({aux_evidence});
    operation.public_aux_count = 1;
    operation.relation_statement = compute_relation_statement(
        operation.label, operation.relation, operation.kernel,
        operation.expected, operation.predecessor_root,
        operation.predecessor_count, operation.state_dependency_root,
        operation.state_dependency_count, operation.public_aux_root,
        operation.public_aux_count);
    if (operation.relation_statement == Digest{}) return false;

    PrivateOperationMaterial material;
    material.operation = operation;
    material.has_field_input = true;
    material.has_field_output = true;
    material.field_input = expected;
    material.field_output = actual;
    material.state_dependencies.push_back(state_view.id);
    material.field_aux.push_back(
        {AuditPublicAuxKind::FOLD_CHALLENGE, {challenge}});
    material.public_aux_evidence.push_back(aux_evidence);

    KernelResidualContext context{operation, material, states};
    if (!validate_kernel_residual_material(context)) return false;

    PrivateResidualShareStore store;
    FoldResidualComputationBackend backend(store);
    const PrivateResidualHandle raw = backend.EvaluateKernel(context);
    if (!raw.available || raw.authenticated || raw.commitment == Digest{})
        return false;
    const PrivateResidualShare* share = store.Find(operation.ref);
    if (!share || !validate_private_residual_share(*share) ||
        share->authenticated || share->values.size() != expected.size() ||
        share->values[0] == F(0))
        return false;
    for (size_t i = 1; i < share->values.size(); ++i)
        if (share->values[i] != F(0)) return false;

    // Exercise the concrete Ed25519 provenance path using an ephemeral
    // selftest issuer key. This demonstrates the verifier wiring only; the
    // test key is not a production trust anchor or source of real provenance.
    std::array<uint8_t,32> test_private_key{};
    std::array<uint8_t,32> test_public_key{};
    if(!make_test_ed25519_keypair(
            &test_private_key,&test_public_key))
        return false;
    constexpr uint64_t TEST_ISSUER_ID=0x5056494150525631ULL;
    constexpr uint64_t TEST_MIN_SEQUENCE=41;
    PrivateResidualProvenanceReceipt receipt;
    receipt.issuer_id=TEST_ISSUER_ID;
    receipt.sequence=TEST_MIN_SEQUENCE;
    receipt.scheme_id=0x5445535450524f56ULL;
    receipt.computation_binding=share->computation_binding;
    if(!sign_test_provenance_receipt(&receipt,test_private_key) ||
       !verify_private_residual_provenance_receipt(
            receipt,test_public_key,TEST_ISSUER_ID,receipt.scheme_id,
            TEST_MIN_SEQUENCE,share->computation_binding))
        return false;
    const std::string receipt_path=
        "/tmp/pvia_residual_provenance_receipt_selftest_"+
        std::to_string(static_cast<unsigned long long>(::getpid()));
    ::unlink(receipt_path.c_str());
    PrivateResidualProvenanceReceipt loaded_receipt;
    const bool receipt_io_ok=
        write_private_residual_provenance_receipt_file(receipt_path,receipt) &&
        read_private_residual_provenance_receipt_file(
            receipt_path,&loaded_receipt) &&
        loaded_receipt.issuer_id==receipt.issuer_id &&
        loaded_receipt.sequence==receipt.sequence &&
        loaded_receipt.scheme_id==receipt.scheme_id &&
        loaded_receipt.computation_binding==receipt.computation_binding &&
        loaded_receipt.signature==receipt.signature &&
        verify_private_residual_provenance_receipt(
            loaded_receipt,test_public_key,TEST_ISSUER_ID,receipt.scheme_id,
            TEST_MIN_SEQUENCE,share->computation_binding);
    ::unlink(receipt_path.c_str());
    if(!receipt_io_ok) return false;
    const std::string public_key_path=
        "/tmp/pvia_residual_provenance_public_key_selftest_"+
        std::to_string(static_cast<unsigned long long>(::getpid()));
    ::unlink(public_key_path.c_str());
    {
        std::ofstream public_key_file(public_key_path,
                                      std::ios::out|std::ios::binary);
        if(!public_key_file) return false;
        static const char hex[]="0123456789abcdef";
        for(uint8_t byte:test_public_key) {
            public_key_file.put(hex[byte>>4]);
            public_key_file.put(hex[byte&15]);
        }
    }
    ::chmod(public_key_path.c_str(),0600);
    std::array<uint8_t,32> loaded_public_key{};
    const bool public_key_io_ok=
        read_private_residual_provenance_public_key_file(
            public_key_path,&loaded_public_key) &&
        loaded_public_key==test_public_key;
    ::unlink(public_key_path.c_str());
    if(!public_key_io_ok) return false;
    PrivateResidualProvenanceReceipt bad_signature=receipt;
    bad_signature.signature[0]^=0x01;
    PrivateResidualProvenanceReceipt bad_binding=receipt;
    bad_binding.computation_binding=hash_words({0xBADB1DULL});
    if(verify_private_residual_provenance_receipt(
            bad_signature,test_public_key,TEST_ISSUER_ID,receipt.scheme_id,
            TEST_MIN_SEQUENCE,share->computation_binding) ||
       verify_private_residual_provenance_receipt(
            bad_binding,test_public_key,TEST_ISSUER_ID,receipt.scheme_id,
            TEST_MIN_SEQUENCE,share->computation_binding))
        return false;
    std::array<uint8_t,32> wrong_public_key=test_public_key;
    wrong_public_key[0]^=0x80;
    if(verify_private_residual_provenance_receipt(
            receipt,wrong_public_key,TEST_ISSUER_ID,receipt.scheme_id,
            TEST_MIN_SEQUENCE,share->computation_binding) ||
       verify_private_residual_provenance_receipt(
            receipt,test_public_key,TEST_ISSUER_ID,receipt.scheme_id,
            TEST_MIN_SEQUENCE+1,share->computation_binding) ||
       verify_private_residual_provenance_receipt(
            receipt,test_public_key,TEST_ISSUER_ID+1,receipt.scheme_id,
            TEST_MIN_SEQUENCE,share->computation_binding))
        return false;

    Ed25519PrivateResidualShareAuthenticator signed_authenticator(
        receipt.scheme_id,TEST_ISSUER_ID,TEST_MIN_SEQUENCE,test_public_key,
        {receipt});
    PrivateResidualShareStore signed_store;
    FoldResidualComputationBackend signed_backend(
        signed_store,&signed_authenticator);
    const PrivateResidualHandle signed_handle=
        signed_backend.EvaluateKernel(context);
    const PrivateResidualShare* signed_share=signed_store.Find(operation.ref);
    if(!signed_handle.available || !signed_handle.authenticated ||
       !signed_share || !signed_share->authenticated ||
       signed_share->authentication.issuer_id!=TEST_ISSUER_ID ||
       signed_share->authentication.issuer_sequence!=TEST_MIN_SEQUENCE ||
       !verify_private_residual_authentication_artifact_signature(
            *signed_share,signed_share->authentication,test_public_key,
            TEST_ISSUER_ID,TEST_MIN_SEQUENCE))
        return false;
    ResidualNativeSourcePinReceipt matching_source_pin{};
    matching_source_pin.issuer_id=TEST_ISSUER_ID;
    matching_source_pin.sequence=TEST_MIN_SEQUENCE;
    if(!verify_private_residual_provenance_matches_source_pin(
            *signed_share,matching_source_pin,test_public_key,
            TEST_ISSUER_ID,TEST_MIN_SEQUENCE))
        return false;
    ResidualNativeSourcePinReceipt wrong_source_pin_sequence=
        matching_source_pin;
    ++wrong_source_pin_sequence.sequence;
    ResidualNativeSourcePinReceipt wrong_source_pin_issuer=
        matching_source_pin;
    ++wrong_source_pin_issuer.issuer_id;
    if(verify_private_residual_provenance_matches_source_pin(
            *signed_share,wrong_source_pin_sequence,test_public_key,
            TEST_ISSUER_ID,TEST_MIN_SEQUENCE) ||
       verify_private_residual_provenance_matches_source_pin(
            *signed_share,wrong_source_pin_issuer,test_public_key,
            TEST_ISSUER_ID,TEST_MIN_SEQUENCE))
        return false;
    PrivateResidualAuthenticationArtifact tampered_artifact=
        signed_share->authentication;
    tampered_artifact.proof_signature[3]^=0x20;
    if(verify_private_residual_authentication_artifact_signature(
            *signed_share,tampered_artifact,test_public_key,
            TEST_ISSUER_ID,TEST_MIN_SEQUENCE))
        return false;

    // A successfully used issuer sequence cannot authenticate a second share
    // in this authenticator instance, even if the exact operation is replayed.
    PrivateResidualShareStore replay_store;
    FoldResidualComputationBackend replay_backend(
        replay_store,&signed_authenticator);
    const PrivateResidualHandle replay_handle=
        replay_backend.EvaluateKernel(context);
    const PrivateResidualShare* replay_share=replay_store.Find(operation.ref);
    if(!replay_handle.available || replay_handle.authenticated ||
       !replay_share || replay_share->authenticated)
        return false;

    // Persistent replay policy must survive authenticator reconstruction.
    const std::string replay_ledger_path=
        "/tmp/pvia_residual_provenance_replay_ledger_"+
        std::to_string(static_cast<unsigned long long>(::getpid()));
    ::unlink(replay_ledger_path.c_str());
    Ed25519PrivateResidualShareAuthenticator persistent_authenticator(
        receipt.scheme_id,TEST_ISSUER_ID,TEST_MIN_SEQUENCE,test_public_key,
        {receipt},replay_ledger_path);
    PrivateResidualShareStore persistent_store;
    FoldResidualComputationBackend persistent_backend(
        persistent_store,&persistent_authenticator);
    const PrivateResidualHandle persistent_handle=
        persistent_backend.EvaluateKernel(context);
    const PrivateResidualShare* persistent_share=
        persistent_store.Find(operation.ref);
    if(!persistent_handle.available || !persistent_handle.authenticated ||
       !persistent_share || !persistent_share->authenticated) {
        ::unlink(replay_ledger_path.c_str());
        return false;
    }
    Ed25519PrivateResidualShareAuthenticator restarted_authenticator(
        receipt.scheme_id,TEST_ISSUER_ID,TEST_MIN_SEQUENCE,test_public_key,
        {receipt},replay_ledger_path);
    PrivateResidualShareStore restarted_store;
    FoldResidualComputationBackend restarted_backend(
        restarted_store,&restarted_authenticator);
    const PrivateResidualHandle restarted_handle=
        restarted_backend.EvaluateKernel(context);
    const PrivateResidualShare* restarted_share=
        restarted_store.Find(operation.ref);
    ::unlink(replay_ledger_path.c_str());
    if(!restarted_handle.available || restarted_handle.authenticated ||
       !restarted_share || restarted_share->authenticated)
        return false;

    auto rejected_receipt=[&](
        const PrivateResidualProvenanceReceipt& candidate_receipt,
        const std::array<uint8_t,32>& candidate_key,
        uint64_t minimum_sequence) {
        Ed25519PrivateResidualShareAuthenticator candidate_auth(
            receipt.scheme_id,TEST_ISSUER_ID,minimum_sequence,candidate_key,
            {candidate_receipt});
        PrivateResidualShareStore candidate_store;
        FoldResidualComputationBackend candidate_backend(
            candidate_store,&candidate_auth);
        const PrivateResidualHandle candidate_handle=
            candidate_backend.EvaluateKernel(context);
        const PrivateResidualShare* candidate_share=
            candidate_store.Find(operation.ref);
        return candidate_handle.available && !candidate_handle.authenticated &&
            candidate_share && !candidate_share->authenticated;
    };
    if(!rejected_receipt(bad_signature,test_public_key,TEST_MIN_SEQUENCE) ||
       !rejected_receipt(bad_binding,test_public_key,TEST_MIN_SEQUENCE) ||
       !rejected_receipt(receipt,wrong_public_key,TEST_MIN_SEQUENCE) ||
       !rejected_receipt(receipt,test_public_key,TEST_MIN_SEQUENCE+1))
        return false;
    Ed25519PrivateResidualShareAuthenticator ambiguous_authenticator(
        receipt.scheme_id,TEST_ISSUER_ID,TEST_MIN_SEQUENCE,test_public_key,
        {receipt,receipt});
    PrivateResidualShareStore ambiguous_store;
    FoldResidualComputationBackend ambiguous_backend(
        ambiguous_store,&ambiguous_authenticator);
    const PrivateResidualHandle ambiguous_handle=
        ambiguous_backend.EvaluateKernel(context);
    const PrivateResidualShare* ambiguous_share=
        ambiguous_store.Find(operation.ref);
    if(!ambiguous_handle.available || ambiguous_handle.authenticated ||
       !ambiguous_share || ambiguous_share->authenticated)
        return false;

    PrivateResidualShareStore malformed_store;
    MalformedResidualAuthenticator malformed_auth;
    FoldResidualComputationBackend malformed_backend(
        malformed_store, &malformed_auth);
    const PrivateResidualHandle malformed =
        malformed_backend.EvaluateKernel(context);
    const PrivateResidualShare* malformed_share =
        malformed_store.Find(operation.ref);
    if (!malformed.available || malformed.authenticated ||
        !malformed_share || malformed_share->authenticated ||
        malformed_share->authentication_binding != Digest{})
        return false;

    BackendKernelResidualEvaluator secure_gate(
        backend, {AuditRelationKernel::FOLD_RS});
    const PrivateResidualHandle gated = secure_gate.Evaluate(context);
    if (gated.available || gated.authenticated)
        return false;
    return true;
}

} // namespace pvia
