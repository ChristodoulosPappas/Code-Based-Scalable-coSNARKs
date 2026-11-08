#include "ReferenceResidualMpcSelfTest.hpp"

#include "ReferenceShamirResidualMpcBackend.hpp"
#include "ReferenceShamirMpc.hpp"
#include "ReferenceBivariateVss.hpp"
#include "PublicJudge.hpp"
#include "TransferAuthentication.hpp"
#include "RobustTerminationRuntimeSelfTest.hpp"
#include "ReferenceGodOutputDelivery.hpp"
#include "ResidualMpcMaliciousSecurity.hpp"
#include "AttestedResidualMpcBackend.hpp"
#include "AttestedResidualRuntimeBundle.hpp"
#include "ExternalMultiplicationConsistencyProviderSession.hpp"
#include "MultiplicationConsistencyProviderAbi.hpp"
#include "MultiplicationConsistencySharingWitness.hpp"
#include "ResidualActivationScope.hpp"
#include "AuthenticatedMpcAbortEvidence.hpp"
#include "PrivateResidualRegistry.hpp"
#include "AuthenticatedResidualProtocol.hpp"
#include "ResidualFingerprintLinearity.hpp"
#include "FoldResidualComputationBackend.hpp"
#include "KernelResidualEvaluator.hpp"
#include "SecureAuditComposition.hpp"
#include "ExperimentMetrics.hpp"
#include "ResidualNativeSourcePinReceipt.hpp"
#include "Ed25519PrivateResidualShareAuthenticator.hpp"
#include "RegistrationPreVssReceipt.hpp"
#include "RegistrationReceiptReplayLedger.hpp"
#include "ReferenceNativeIssuerKeyAdapter.hpp"
#include "RegistrationNativeIssuerPublicFile.hpp"
#include <memory>
#include <cerrno>
#include <cstdlib>
#include "PrivateStateMaterialStore.hpp"
#include "PrivateAuditMaterialStore.hpp"
#include <openssl/evp.h>

#include <mpi.h>

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace pvia {
namespace {

constexpr u64 SELFTEST_AUTH_SCHEME = 0x50565253454c4641ULL; // PVRSELFA
constexpr u64 SELFTEST_STATE_DOMAIN = 0x5056525354415445ULL; // PVRSTATE
constexpr u64 SELFTEST_EXPECTED_DOMAIN = 0x5056524558504543ULL; // PVREXPEC
constexpr u64 SELFTEST_ACTUAL_DOMAIN = 0x5056524143545541ULL; // PVRACTUA
constexpr u64 SELFTEST_AUX_DOMAIN = 0x5056524155583031ULL; // PVRAUX01
constexpr u64 SELFTEST_PROOF_DOMAIN = 0x5056525052463031ULL; // PVRPRF01
constexpr u64 SELFTEST_TRANSCRIPT_DOMAIN = 0x50565254524e3031ULL; // PVRTRN01
constexpr u64 SELFTEST_SCOPE_DOMAIN = 0x50565253434f5045ULL; // PVRSCOPE

std::string p105_hex_bytes(const uint8_t* data,size_t size) {
    static constexpr char digits[]="0123456789abcdef";
    std::string out;
    out.reserve(size*2);
    for(size_t i=0;i<size;++i) {
        out.push_back(digits[data[i]>>4]);
        out.push_back(digits[data[i]&0x0f]);
    }
    return out;
}
std::string p105_hex_digest(const Digest& digest) {
    return p105_hex_bytes(digest.bytes.data(),digest.bytes.size());
}
std::string p105_hex_u64_words(const std::vector<u64>& words) {
    std::vector<uint8_t> encoded;
    encoded.reserve(words.size()*8);
    for(const u64 word:words)
        for(unsigned i=0;i<8;++i)
            encoded.push_back(static_cast<uint8_t>(word>>(8*i)));
    return p105_hex_bytes(encoded.data(),encoded.size());
}
bool p105_rank_path(const char* pattern,int rank,std::string* path) {
    if(!pattern || !*pattern || !path)return false;
    std::string value(pattern);
    const auto at=value.find("{rank}");
    if(at==std::string::npos)return false;
    value.replace(at,6,std::to_string(rank));
    if(value.find("{rank}")!=std::string::npos)return false;
    *path=value;
    return true;
}
bool p105_write_private_request(const std::string& path,
    const ResidualNativeSourcePinReceipt& receipt,
    const std::vector<uint8_t>& native_message,
    const std::vector<uint8_t>& pin_message,
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeConsumedSnapshot& snapshot,
    const AuditCheckpointView& checkpoint,
    const std::vector<uint8_t>& executor_attestation_message,
    const std::array<uint8_t,64>& executor_attestation_signature) {
    const auto claim_words=registration_pre_vss_claim_words(statement);
    if(path.empty() || native_message.empty() || pin_message.empty() ||
       executor_attestation_message.empty() ||
       claim_words.size()!=38 ||
       hash_words(claim_words)!=snapshot.pre_vss_claim_binding ||
       snapshot.consumed_record_binding!=receipt.native_consumed_record_binding)
        return false;
    const Digest state_digest=hash_field_vector(snapshot.state_values);
    const Digest output_digest=hash_field_vector(snapshot.actual_output);
    const Digest challenge_digest=hash_field_vector({snapshot.public_challenge});
    if(state_digest==Digest{} || output_digest==Digest{} ||
       challenge_digest==Digest{} || checkpoint.root==Digest{} ||
       statement.native_context.authentication_binding==Digest{})
        return false;
    std::string content="PVIA_P105_NATIVE_ISSUER_REQUEST_V2\n";
    content+="issuer_id="+std::to_string(receipt.issuer_id)+"\n";
    content+="sequence="+std::to_string(receipt.sequence)+"\n";
    content+="sid="+std::to_string(receipt.sid)+"\n";
    content+="checkpoint="+std::to_string(receipt.checkpoint)+"\n";
    content+="owner="+std::to_string(receipt.owner)+"\n";
    content+="scope_binding="+p105_hex_digest(receipt.scope_binding)+"\n";
    content+="local_residual_root="+p105_hex_digest(receipt.local_residual_root)+"\n";
    content+="native_consumed_record_binding="+
        p105_hex_digest(receipt.native_consumed_record_binding)+"\n";
    content+="pre_vss_claim_binding="+
        p105_hex_digest(receipt.registration_pre_vss_claim_binding)+"\n";
    content+="object_id="+std::to_string(statement.ref.object_id)+"\n";
    content+="native_state_id="+
        std::to_string(statement.native_context.native_state_id)+"\n";
    content+="authentication_scheme_id="+
        std::to_string(statement.native_context.authentication_scheme_id)+"\n";
    content+="state_count="+std::to_string(snapshot.state_values.size())+"\n";
    content+="output_count="+std::to_string(snapshot.actual_output.size())+"\n";
    content+="state_digest="+p105_hex_digest(state_digest)+"\n";
    content+="output_digest="+p105_hex_digest(output_digest)+"\n";
    content+="challenge_digest="+p105_hex_digest(challenge_digest)+"\n";
    content+="checkpoint_root="+p105_hex_digest(checkpoint.root)+"\n";
    content+="native_authentication_binding="+
        p105_hex_digest(statement.native_context.authentication_binding)+"\n";
    content+="pre_vss_claim_words_hex="+p105_hex_u64_words(claim_words)+"\n";
    content+="executor_attestation_message_hex="+
        p105_hex_bytes(executor_attestation_message.data(),
                       executor_attestation_message.size())+"\n";
    content+="executor_attestation_signature_hex="+
        p105_hex_bytes(executor_attestation_signature.data(),
                       executor_attestation_signature.size())+"\n";
    content+="native_execution_message_hex="+
        p105_hex_bytes(native_message.data(),native_message.size())+"\n";
    content+="residual_source_pin_message_hex="+
        p105_hex_bytes(pin_message.data(),pin_message.size())+"\n";
    const int fd=::open(path.c_str(),
        O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)return false;
    size_t offset=0;
    bool ok=true;
    while(offset<content.size()) {
        const ssize_t n=::write(fd,content.data()+offset,content.size()-offset);
        if(n<0 && errno==EINTR)continue;
        if(n<=0){ok=false;break;}
        offset+=static_cast<size_t>(n);
    }
    if(ok)ok=::fsync(fd)==0;
    if(::close(fd)!=0)ok=false;
    return ok;
}

void append_digest_words_selftest(
    const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

class SelfTestResidualAuthenticator final
    : public PrivateResidualShareAuthenticator {
public:
    uint64_t SchemeId() const override { return SELFTEST_AUTH_SCHEME; }

    bool Authenticate(
        const PrivateResidualShare& share,
        PrivateResidualAuthenticationArtifact* artifact) const override {
        if (!artifact || !share.computation_valid ||
            share.computation_binding == Digest{} ||
            share.source_state_id == 0 ||
            share.source_state_authentication_scheme_id != SchemeId() ||
            share.source_state_authentication_binding == Digest{})
            return false;
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
        artifact->proof_commitment = hash_words({
            SELFTEST_PROOF_DOMAIN, share.label.sid,
            share.ref.owner, share.ref.object_id});
        artifact->transcript_binding = hash_words({
            SELFTEST_TRANSCRIPT_DOMAIN, share.label.sid,
            share.checkpoint, share.ref.owner, share.ref.object_id});
        artifact->binding =
            compute_private_residual_authentication_artifact_binding(*artifact);
        return validate_private_residual_authentication_artifact(
            share, *artifact);
    }
};

// Synthetic multiplication-consistency backend for MPI wiring tests only.
// It checks the dealer-local witness before emitting a marker proof, but its
// public Verify routine is not a cryptographic ZK verifier. It is intentionally
// confined to this anonymous self-test namespace and never installed by the
// production/reference runtime adapter.
class SelfTestMultiplicationConsistencyBackend final
    : public MultiplicationConsistencyProofBackend {
public:
    size_t prove_count() const { return prove_count_; }

    MultiplicationConsistencyCapabilities Capabilities() const override {
        MultiplicationConsistencyCapabilities capabilities;
        capabilities.available = true;
        capabilities.malicious_sound = true;
        capabilities.zero_knowledge = true;
        capabilities.binds_input_sharings = true;
        capabilities.binds_output_sharing = true;
        capabilities.protocol_id = 0x4d554c5445535450ULL; // MULTESTP
        capabilities.relation_binding =
            compute_multiplication_consistency_relation_binding();
        capabilities.implementation_binding =
            hash_words({0x4d554c5445535449ULL}); // MULTESTI
        capabilities.capability_binding =
            compute_multiplication_consistency_capability_binding(capabilities);
        return capabilities;
    }

    MultiplicationConsistencyProofArtifact Prove(
        const MultiplicationConsistencyStatement& statement,
        const MultiplicationConsistencyWitness& witness) const override {
        MultiplicationConsistencyProofArtifact proof;
        if (!validate_multiplication_consistency_statement(statement) ||
            witness.product_value != witness.lhs_share * witness.rhs_share)
            return proof;
        auto validate_input = [&](
            const std::vector<u64>& words, const Digest& binding,
            const F& expected_share) -> bool {
            MultiplicationConsistencySharingWitnessEnvelope envelope;
            if (!decode_multiplication_consistency_sharing_witness(
                    words, &envelope) ||
                envelope.sharing_binding != binding)
                return false;
            if (envelope.kind ==
                MultiplicationConsistencySharingWitnessKind::
                    LINEAR_COMBINATION) {
                ReferenceLinearSharingProvenance linear;
                if (!decode_reference_linear_sharing_provenance(
                        envelope.payload_words, &linear) ||
                    linear.binding != binding ||
                    linear.local_share != expected_share)
                    return false;
                for (const auto& source : linear.sources) {
                    if (source.local_witness.participant !=
                            static_cast<int>(statement.dealer) ||
                        source.local_witness.transcript_binding !=
                            source.sharing_binding)
                        return false;
                }
                return true;
            }
            if (envelope.kind !=
                MultiplicationConsistencySharingWitnessKind::VSS_LOCAL)
                return false;
            ReferenceVssLocalWitness direct;
            if (!decode_reference_vss_local_witness(
                    envelope.payload_words, &direct) ||
                direct.participant != static_cast<int>(statement.dealer) ||
                direct.transcript_binding != binding ||
                direct.local_row_words.size() < 2)
                return false;
            const F direct_value(
                static_cast<long long>(direct.local_row_words[0]),
                static_cast<long long>(direct.local_row_words[1]));
            return direct_value == expected_share;
        };
        MultiplicationConsistencySharingWitnessEnvelope output_envelope;
        ReferenceVssDealerWitness output_witness;
        if (!validate_input(
                witness.lhs_sharing_witness_words,
                statement.lhs_sharing_binding, witness.lhs_share) ||
            !validate_input(
                witness.rhs_sharing_witness_words,
                statement.rhs_sharing_binding, witness.rhs_share) ||
            !decode_multiplication_consistency_sharing_witness(
                witness.output_sharing_witness_words, &output_envelope) ||
            output_envelope.kind !=
                MultiplicationConsistencySharingWitnessKind::VSS_DEALER ||
            output_envelope.sharing_binding !=
                statement.output_sharing_binding ||
            !decode_reference_vss_dealer_witness(
                output_envelope.payload_words, &output_witness) ||
            output_witness.dealer != static_cast<int>(statement.dealer) ||
            output_witness.transcript_binding !=
                statement.output_sharing_binding ||
            output_witness.coefficient_words.size() < 2)
            return proof;
        const F shared_constant(
            static_cast<long long>(output_witness.coefficient_words[0]),
            static_cast<long long>(output_witness.coefficient_words[1]));
        if (shared_constant != witness.product_value) return proof;
        proof.available = true;
        proof.cryptographically_authenticated = true;
        proof.zero_knowledge = true;
        proof.proof_system_id = 0x4d554c54U; // MULT
        proof.statement_binding = statement.statement_binding;
        proof.transcript_binding = Transcript(statement);
        proof.proof_words = {
            0x4d554c5445535457ULL,
            static_cast<u64>(statement.dealer)};
        proof.proof_commitment =
            compute_multiplication_consistency_proof_commitment(proof);
        ++prove_count_;
        return proof;
    }

    bool Verify(
        const MultiplicationConsistencyStatement& statement,
        const MultiplicationConsistencyProofArtifact& proof) const override {
        if (!validate_multiplication_consistency_proof_artifact(
                statement, proof))
            return false;
        return proof.proof_words == std::vector<u64>{
                   0x4d554c5445535457ULL,
                   static_cast<u64>(statement.dealer)} &&
               proof.transcript_binding == Transcript(statement);
    }

private:
    mutable size_t prove_count_ = 0;

    static Digest Transcript(
        const MultiplicationConsistencyStatement& statement) {
        std::vector<u64> words = {
            0x4d554c5445535454ULL,
            statement.sid, statement.checkpoint,
            statement.multiplication_id, statement.dealer};
        append_digest_words_selftest(statement.statement_binding, &words);
        append_digest_words_selftest(statement.output_sharing_binding, &words);
        return hash_words(words);
    }
};

// Synthetic malicious-security provider for adapter wiring tests only.
// It is confined to this self-test translation unit and is not a production
// public-abort or malicious-security implementation.
class SelfTestResidualMpcMaliciousSecurityProvider final
    : public ResidualMpcMaliciousSecurityProvider {
public:
    SelfTestResidualMpcMaliciousSecurityProvider(
        const Digest& residual_implementation_binding,
        const Digest& strong_consistency_capability_binding,
        const Digest& authenticated_transport_capability_binding)
        : residual_implementation_binding_(residual_implementation_binding),
          strong_consistency_capability_binding_(
              strong_consistency_capability_binding),
          identifiable_abort_capability_binding_(
              make_signed_equivocation_abort_evidence_capabilities(
                  authenticated_transport_capability_binding).capability_binding) {}

    ResidualMpcMaliciousSecurityCapabilities Capabilities() const override {
        ResidualMpcMaliciousSecurityCapabilities c;
        c.available = true;
        c.protocol_id = 0x52534d4154545354ULL; // RSMATTST
        c.security_level = RobustAuditSecurityLevel::MALICIOUS_ABORT;
        c.malicious_secure = true;
        c.binds_residual_implementation = true;
        c.binds_failure_before_activation = true;
        c.publicly_identifiable_abort = true;
        c.guaranteed_output_delivery = false;
        c.residual_implementation_binding = residual_implementation_binding_;
        c.strong_consistency_capability_binding =
            strong_consistency_capability_binding_;
        c.identifiable_abort_capability_binding =
            identifiable_abort_capability_binding_;
        c.delivery_capability_binding = Digest{};
        c.implementation_binding = hash_words({0x52534d415454494dULL});
        c.capability_binding =
            compute_residual_mpc_malicious_security_capability_binding(c);
        return c;
    }

    ResidualMpcSecurityAttestation AttestActivatedState(
        const ObligationSet& scope,
        const ResidualMpcCapabilities& residual,
        const Digest& activation_binding,
        const Digest& strong_consistency_capability_binding) const override {
        ResidualMpcSecurityAttestation a;
        const auto security = Capabilities();
        if (!validate_residual_mpc_capabilities(residual) ||
            residual.implementation_binding != residual_implementation_binding_ ||
            activation_binding == Digest{} ||
            strong_consistency_capability_binding !=
                security.strong_consistency_capability_binding)
            return a;
        a.available = true;
        a.sid = scope.session_id;
        a.checkpoint = scope.checkpoint;
        a.security_level = security.security_level;
        a.scope_binding = compute_collective_scope_binding(scope);
        a.residual_mpc_capability_binding = residual.capability_binding;
        a.activation_binding = activation_binding;
        a.strong_consistency_capability_binding =
            strong_consistency_capability_binding;
        a.identifiable_abort_capability_binding =
            security.identifiable_abort_capability_binding;
        a.delivery_capability_binding = security.delivery_capability_binding;
        a.security_capability_binding = security.capability_binding;
        a.attestation_binding = compute_residual_mpc_security_attestation_binding(a);
        return a;
    }

    bool VerifyAttestation(
        const ObligationSet& scope,
        const ResidualMpcCapabilities& residual,
        const ResidualMpcSecurityAttestation& attestation,
        RobustAuditSecurityLevel required_security) const override {
        return validate_residual_mpc_security_attestation(
            scope, residual, Capabilities(), attestation, required_security);
    }

private:
    Digest residual_implementation_binding_{};
    Digest strong_consistency_capability_binding_{};
    Digest identifiable_abort_capability_binding_{};
};

struct ProviderCaseResult {
    bool ran = false;
    bool batch_ok = false;
    bool localized = false;
    bool production_gate_rejected = false;
};

ProviderCaseResult run_provider_integration_case(
    int rank, int world_size, bool inject_fault) {
    ProviderCaseResult result;
    if (world_size != 4 || rank < 0 || rank >= world_size)
        return result;

    const uint64_t sid =
        0x525350524f560000ULL + (inject_fault ? 2ULL : 1ULL);
    const CheckpointId checkpoint = static_cast<CheckpointId>(
        0x7100 + (inject_fault ? 2 : 1));
    const uint32_t round = inject_fault ? 22U : 21U;
    const uint32_t faulty_owner = static_cast<uint32_t>(world_size / 2);
    const OperationRef local_ref{
        static_cast<uint32_t>(rank),
        static_cast<uint64_t>(4000 + rank)};

    std::vector<F> input;
    for (int i = 0; i < 8; ++i)
        input.push_back(F(static_cast<long long>(1 + rank * 8 + i)));
    const F challenge(5);
    std::vector<F> expected;
    if (!recompute_fold_rs_output(input, challenge, &expected) ||
        expected.empty())
        return result;
    std::vector<F> actual = expected;
    if (inject_fault && static_cast<uint32_t>(rank) == faulty_owner)
        actual.front() += F(1);

    AuditStateView state;
    state.id = static_cast<StateId>(0x5000 + rank);
    state.label.sid = sid;
    state.label.phase = Phase::FOLD;
    state.label.round = round;
    state.label.owner = static_cast<uint32_t>(rank);
    state.label.obligation = Obligation::DERIVE;
    state.label.object_id = state.id;
    state.digest = hash_field_vector(input);
    state.name = "reference-residual-provider-state";
    state.debug_only = true;
    const Digest state_authentication = hash_words({
        SELFTEST_AUTH_SCHEME, sid, state.id,
        static_cast<u64>(rank)});

    AuditOperationView operation;
    operation.ref = local_ref;
    operation.label.sid = sid;
    operation.label.phase = Phase::FOLD;
    operation.label.round = round;
    operation.label.owner = static_cast<uint32_t>(rank);
    operation.label.obligation = Obligation::FOLD;
    operation.label.object_id = local_ref.object_id;
    operation.relation = RelationKind::FOLDING;
    operation.kernel = AuditRelationKernel::FOLD_RS;
    operation.expected = hash_field_vector(expected);
    operation.actual = hash_field_vector(actual);
    operation.predecessor_root = hash_words(std::vector<u64>{});
    operation.predecessor_count = 0;
    operation.checkpoint = checkpoint;
    operation.active = true;

    StateDependencyEvidence state_evidence;
    state_evidence.owner = static_cast<uint32_t>(rank);
    state_evidence.state_id = state.id;
    state_evidence.digest = state.digest;
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
    if (operation.relation_statement == Digest{}) return result;

    PrivateResidualShareStore shares;
    SelfTestResidualAuthenticator authenticator;
    FoldResidualComputationBackend fold_backend(shares, &authenticator);
    BackendKernelResidualEvaluator fold_evaluator(
        fold_backend, {AuditRelationKernel::FOLD_RS});

    AuthenticatedMpcExchange exchange(rank, world_size);
    if (!exchange.production_authenticated_ready()) return result;
    ReferenceShamirMpc mpc(rank, world_size, (world_size - 1) / 3);
    ReferenceShamirResidualMpcBackend residual_backend(
        shares, mpc, exchange);
    MpcBackedAuthenticatedResidualProtocol passive(
        residual_backend, RobustAuditSecurityLevel::REFERENCE_PASSIVE);
    if (!passive.ready()) return result;
    ProtocolBackedCollectiveResidualEngine collective_engine(passive);

    SecureAuditComponents components;
    components.collective_engine = &collective_engine;
    components.kernel_evaluators.push_back(&fold_evaluator);
    ComposedSecureAuditProvider provider(
        components, true, RobustAuditSecurityLevel::REFERENCE_PASSIVE);
    SecureAuditRequirements reference_requirements;
    reference_requirements.private_lane = true;
    reference_requirements.transfer_lane = false;
    reference_requirements.private_security_level =
        RobustAuditSecurityLevel::REFERENCE_PASSIVE;
    reference_requirements.required_kernels = {
        AuditRelationKernel::FOLD_RS};
    result.production_gate_rejected =
        !provider.Ready(reference_requirements);
    if (!result.production_gate_rejected) return result;

    provider.RegisterStateMetadata(state);
    provider.BindPrivateState(state, input);
    if (!provider.BindPrivateStateAuthentication(
            state, SELFTEST_AUTH_SCHEME, state_authentication))
        return result;
    provider.RegisterOperation(operation);
    provider.BindOperationStateDependencies(operation, {state.id});
    provider.BindPublicFieldAux(
        operation, AuditPublicAuxKind::FOLD_CHALLENGE, {challenge});
    provider.BindPrivateFieldOperation(
        operation, AuditPrivatePayloadKind::FIELD_VECTOR,
        AuditPayloadStage::REGISTER_INPUT, expected);
    provider.BindPrivateFieldOperation(
        operation, AuditPrivatePayloadKind::FIELD_VECTOR,
        AuditPayloadStage::ACTIVATE_OUTPUT, actual);
    provider.ActivateOperation(operation);
    provider.FinalizePrivateRelation(operation);

    ObligationSet scope;
    scope.session_id = sid;
    scope.phase = Phase::FOLD;
    scope.round = round;
    scope.generation = 1;
    scope.exact_round = true;
    scope.checkpoint = checkpoint;
    scope.checkpoint_root = hash_words({
        SELFTEST_SCOPE_DOMAIN, sid, checkpoint, round, 0x50524f56ULL});
    scope.obligations = {Obligation::FOLD};
    for (int owner = 0; owner < world_size; ++owner) {
        OperationRef ref{
            static_cast<uint32_t>(owner),
            static_cast<uint64_t>(4000 + owner)};
        scope.operations.push_back(ref);
        scope.private_operations.push_back(ref);
    }

    const ObligationSet synchronized =
        provider.SynchronizeFailureScope(scope, rank, world_size);
    if (synchronized.checkpoint != checkpoint ||
        synchronized.operations.size() != scope.operations.size() ||
        synchronized.private_operations.size() != scope.private_operations.size())
        return result;
    const BatchCheckResult batch =
        provider.PrivateBatchCheck(synchronized);
    if (!batch.available || !batch.cryptographically_authenticated)
        return result;
    result.ran = true;
    result.batch_ok = batch.ok;
    if (!inject_fault) {
        result.localized = true;
        return result;
    }
    if (batch.ok) return result;

    const Violation violation =
        provider.PrivateDispute(synchronized, batch);
    result.localized =
        violation.valid &&
        violation.responsible_rank == faulty_owner &&
        violation.checkpoint == checkpoint &&
        violation.relation == RelationKind::FOLDING &&
        violation.kernel == AuditRelationKernel::FOLD_RS &&
        violation.expected != violation.actual &&
        violation.residual_commitment != Digest{} &&
        violation.dispute_binding != Digest{};
    return result;
}

bool make_authenticated_share_bound(
    uint64_t sid, CheckpointId checkpoint, uint32_t round,
    const OperationRef& ref, bool faulty,
    const Digest& predecessor_root, uint32_t predecessor_count,
    PrivateResidualShare* share_out,
    PrivateResidualHandle* handle_out) {
    if (!share_out || !handle_out) return false;

    PrivateResidualShare share;
    share.ref = ref;
    share.label.sid = sid;
    share.label.phase = Phase::FOLD;
    share.label.round = round;
    share.label.owner = ref.owner;
    share.label.obligation = Obligation::FOLD;
    share.label.object_id = ref.object_id;
    share.relation = RelationKind::FOLDING;
    share.kernel = AuditRelationKernel::FOLD_RS;
    share.checkpoint = checkpoint;
    share.values = {F(0), faulty ? F(7) : F(0)};
    share.source_state_id = 1000 + ref.object_id;
    share.source_state_owner = ref.owner;
    share.source_state_digest = hash_words({
        SELFTEST_STATE_DOMAIN, sid, ref.owner, ref.object_id});
    share.source_state_authentication_scheme_id = SELFTEST_AUTH_SCHEME;
    share.source_state_authentication_binding = hash_words({
        SELFTEST_AUTH_SCHEME, sid, ref.owner, ref.object_id});
    share.public_aux_root = hash_words({
        SELFTEST_AUX_DOMAIN, sid, ref.owner, ref.object_id});
    share.expected = hash_words({
        SELFTEST_EXPECTED_DOMAIN, sid, ref.owner, ref.object_id});
    share.actual = faulty
        ? hash_words({SELFTEST_ACTUAL_DOMAIN, sid, ref.owner, ref.object_id})
        : share.expected;
    const Digest state_dependency_root = hash_words({
        SELFTEST_SCOPE_DOMAIN, sid, ref.owner, ref.object_id, 1});
    share.operation_statement_binding = compute_relation_statement(
        share.label, share.relation, share.kernel, share.expected,
        predecessor_root, predecessor_count, state_dependency_root, 1,
        share.public_aux_root, 1);
    share.computation_valid = true;
    share.computation_binding =
        compute_private_residual_computation_binding(share);

    PrivateResidualAuthenticationArtifact artifact;
    artifact.available = true;
    artifact.cryptographically_authenticated = true;
    artifact.scheme_id = SELFTEST_AUTH_SCHEME;
    artifact.computation_binding = share.computation_binding;
    artifact.source_state_id = share.source_state_id;
    artifact.source_state_owner = share.source_state_owner;
    artifact.source_state_digest = share.source_state_digest;
    artifact.source_state_authentication_scheme_id =
        share.source_state_authentication_scheme_id;
    artifact.source_state_authentication_binding =
        share.source_state_authentication_binding;
    artifact.public_aux_root = share.public_aux_root;
    artifact.operation_statement_binding =
        share.operation_statement_binding;
    artifact.proof_commitment = hash_words({
        SELFTEST_PROOF_DOMAIN, sid, ref.owner, ref.object_id});
    artifact.transcript_binding = hash_words({
        SELFTEST_TRANSCRIPT_DOMAIN, sid, ref.owner, ref.object_id});
    artifact.binding =
        compute_private_residual_authentication_artifact_binding(artifact);

    share.authentication = artifact;
    share.authentication_binding = artifact.binding;
    share.authenticated = true;
    share.commitment = compute_private_residual_share_commitment(share);
    if (!validate_private_residual_share(share))
        return false;

    PrivateResidualHandle handle;
    handle.ref = share.ref;
    handle.label = share.label;
    handle.relation = share.relation;
    handle.kernel = share.kernel;
    handle.checkpoint = share.checkpoint;
    handle.commitment = share.commitment;
    handle.available = true;
    handle.authenticated = true;

    *share_out = share;
    *handle_out = handle;
    return true;
}

bool make_authenticated_share(
    uint64_t sid, CheckpointId checkpoint, uint32_t round,
    const OperationRef& ref, bool faulty,
    PrivateResidualShare* share_out,
    PrivateResidualHandle* handle_out) {
    const Digest predecessor_root = hash_words({
        SELFTEST_SCOPE_DOMAIN, sid, ref.owner, ref.object_id, 0});
    return make_authenticated_share_bound(
        sid, checkpoint, round, ref, faulty,
        predecessor_root, 0, share_out, handle_out);
}

struct CaseResult {
    bool ran = false;
    bool batch_ok = false;
    bool localized = false;
    bool activated_before_failure = false;
    bool store_independent = false;
    bool activated_vss_bound = false;
    bool strong_zero_consistency = false;
    bool reference_security_attestation_empty = false;
    bool attested_malicious_gate = false;
    bool attested_scope_gate = false;
    bool runtime_bundle_bound = false;
    bool runtime_reference_only = false;
    bool runtime_default_failclosed = false;
    bool sealed_activation_scope_bound = false;
    bool sealed_activation_local_fragment_bound = false;
    bool sealed_activation_sync_bound = false;
    bool sealed_activation_tamper_rejected = false;
    bool composed_security_provider_bound = false;
    bool detached_transport_scope_rejected = false;
    bool attested_batch_ok = false;
    bool attested_security_transcript_bound = false;
    bool attested_localized = false;
    bool failclosed_security_provider_rejected = false;
    bool attested_god_rejected = false;
    bool attested_state_drift_rejected = false;
    bool security_capability_gate_bound = false;
    bool passive_gate = false;
    bool malicious_abort_rejected = false;
    bool god_rejected = false;
};

CaseResult run_case(
    int rank, int world_size, bool inject_fault) {
    CaseResult result;
    if (world_size < 4 || rank < 0 || rank >= world_size)
        return result;

    const uint64_t sid =
        0x52534d5043540000ULL + (inject_fault ? 2ULL : 1ULL);
    const CheckpointId checkpoint =
        static_cast<CheckpointId>(0x7000 + (inject_fault ? 2 : 1));
    const uint32_t round = inject_fault ? 12U : 11U;
    const uint32_t faulty_owner =
        static_cast<uint32_t>(world_size / 2);

    ObligationSet scope;
    scope.session_id = sid;
    scope.phase = Phase::FOLD;
    scope.round = round;
    scope.generation = 1;
    scope.exact_round = true;
    scope.checkpoint = checkpoint;
    scope.checkpoint_root = hash_words({
        SELFTEST_SCOPE_DOMAIN, sid, checkpoint, round});
    scope.obligations = {Obligation::FOLD};
    for (int owner = 0; owner < world_size; ++owner) {
        OperationRef ref{
            static_cast<uint32_t>(owner),
            static_cast<uint64_t>(2000 + owner)};
        scope.operations.push_back(ref);
        scope.private_operations.push_back(ref);
    }

    PrivateResidualShareStore store;
    PrivateResidualRegistry registry;
    const OperationRef local_ref{
        static_cast<uint32_t>(rank),
        static_cast<uint64_t>(2000 + rank)};
    PrivateResidualShare local_share;
    PrivateResidualHandle local_handle;
    const bool local_fault =
        inject_fault && static_cast<uint32_t>(rank) == faulty_owner;
    if (!make_authenticated_share(
            sid, checkpoint, round, local_ref, local_fault,
            &local_share, &local_handle) ||
        !store.Put(local_share))
        return result;
    registry.Put(local_handle);
    const LocalResidualBatchView local_view =
        registry.BuildLocalBatchView(scope, static_cast<uint32_t>(rank));
    if (!local_view.complete_for_owner || !local_view.all_authenticated ||
        local_view.handles.size() != 1)
        return result;

    AuditCheckpointView sealed_checkpoint;
    sealed_checkpoint.id = scope.checkpoint;
    sealed_checkpoint.phase = scope.phase;
    sealed_checkpoint.round = scope.round;
    sealed_checkpoint.generation = scope.generation;
    sealed_checkpoint.operations = scope.operations;
    sealed_checkpoint.root = scope.checkpoint_root;
    sealed_checkpoint.sealed = true;

    auto populate_activation_materials = [&](
        PrivateAuditMaterialStore* materials, bool tamper_round,
        int owner_filter) {
        if (!materials) return;
        for (size_t i = 0; i < scope.operations.size(); ++i) {
            const OperationRef& ref = scope.operations[i];
            if (owner_filter >= 0 &&
                ref.owner != static_cast<uint32_t>(owner_filter))
                continue;
            AuditOperationView operation;
            operation.ref = ref;
            operation.label.sid = sid;
            operation.label.phase = scope.phase;
            operation.label.round =
                tamper_round && i == 0 ? round + 1 : round;
            operation.label.owner = ref.owner;
            operation.label.obligation = Obligation::FOLD;
            operation.label.object_id = ref.object_id;
            operation.relation = RelationKind::FOLDING;
            operation.kernel = AuditRelationKernel::FOLD_RS;
            operation.checkpoint = checkpoint;
            materials->RegisterOperation(operation);
            materials->MarkFinalized(ref);
        }
    };

    PrivateAuditMaterialStore activation_materials;
    populate_activation_materials(&activation_materials, false, -1);
    ObligationSet activation_scope;
    result.sealed_activation_scope_bound =
        build_private_residual_activation_scope(
            sealed_checkpoint, activation_materials, &activation_scope) &&
        activation_scope.session_id == scope.session_id &&
        activation_scope.phase == scope.phase &&
        activation_scope.round == scope.round &&
        activation_scope.generation == scope.generation &&
        activation_scope.exact_round == scope.exact_round &&
        activation_scope.checkpoint == scope.checkpoint &&
        activation_scope.checkpoint_root == scope.checkpoint_root &&
        activation_scope.obligations == scope.obligations &&
        activation_scope.operations == scope.operations &&
        activation_scope.private_operations == scope.private_operations &&
        activation_scope.transfer_operations.empty();
    if (!result.sealed_activation_scope_bound) return result;

    PrivateAuditMaterialStore tampered_activation_materials;
    populate_activation_materials(&tampered_activation_materials, true, -1);
    ObligationSet tampered_activation_scope;
    result.sealed_activation_tamper_rejected =
        !build_private_residual_activation_scope(
            sealed_checkpoint, tampered_activation_materials,
            &tampered_activation_scope);
    if (!result.sealed_activation_tamper_rejected) return result;

    PrivateAuditMaterialStore local_activation_materials;
    populate_activation_materials(
        &local_activation_materials, false, rank);
    ObligationSet local_activation_fragment;
    result.sealed_activation_local_fragment_bound =
        build_local_private_residual_activation_scope(
            sealed_checkpoint, local_activation_materials,
            static_cast<uint32_t>(rank), sid,
            &local_activation_fragment) &&
        local_activation_fragment.session_id == sid &&
        local_activation_fragment.checkpoint == checkpoint &&
        local_activation_fragment.operations.size() == 1 &&
        local_activation_fragment.operations.front() == local_ref &&
        local_activation_fragment.private_operations ==
            local_activation_fragment.operations &&
        local_activation_fragment.transfer_operations.empty() &&
        local_activation_fragment.obligations == scope.obligations;
    if (!result.sealed_activation_local_fragment_bound) return result;

    const int threshold = (world_size - 1) / 3;
    AuthenticatedMpcExchange exchange(rank, world_size);
    if (!exchange.production_authenticated_ready())
        return result;
    // Check the empty-provider case before an accepted provider is scoped
    // into the process registry.
    AttestedResidualRuntimeBundle default_failclosed_runtime(
        store, exchange, rank, world_size, threshold, sid, nullptr,
        MPI_COMM_WORLD);
    result.runtime_default_failclosed =
        !default_failclosed_runtime.ready() &&
        default_failclosed_runtime.engine().ProductionCapabilityBinding() ==
            Digest{} &&
        !default_failclosed_runtime.ActivateForScope(
            activation_scope, registry);

    SelfTestMultiplicationConsistencyBackend multiplication_backend;

    // Canonical provider ABI roundtrip.
    MultiplicationConsistencyStatement abi_statement;
    abi_statement.sid = sid;
    abi_statement.checkpoint = checkpoint;
    abi_statement.multiplication_id = 0x41424901ULL;
    abi_statement.dealer = static_cast<uint32_t>(rank);
    abi_statement.lhs_sharing_binding =
        hash_words({0x41424911ULL, static_cast<u64>(rank)});
    abi_statement.rhs_sharing_binding =
        hash_words({0x41424912ULL, static_cast<u64>(rank)});
    abi_statement.output_sharing_binding =
        hash_words({0x41424913ULL, static_cast<u64>(rank)});
    abi_statement.context_binding =
        hash_words({0x41424914ULL, sid, checkpoint});
    abi_statement.statement_binding =
        compute_multiplication_consistency_statement_binding(abi_statement);
    MultiplicationConsistencyStatement decoded_statement;
    const auto statement_words =
        encode_multiplication_consistency_statement_abi(abi_statement);
    if (!decode_multiplication_consistency_statement_abi(
            statement_words, &decoded_statement) ||
        decoded_statement.statement_binding !=
            abi_statement.statement_binding ||
        decoded_statement.dealer != abi_statement.dealer)
        return result;

    MultiplicationConsistencyWitness abi_witness;
    abi_witness.lhs_share = F(3, 4);
    abi_witness.rhs_share = F(5, 6);
    abi_witness.product_value =
        abi_witness.lhs_share * abi_witness.rhs_share;
    abi_witness.lhs_sharing_witness_words = {1, 2, 3};
    abi_witness.rhs_sharing_witness_words = {4, 5};
    abi_witness.output_sharing_witness_words = {6, 7, 8, 9};
    MultiplicationConsistencyWitness decoded_witness;
    const auto witness_words =
        encode_multiplication_consistency_witness_abi(abi_witness);
    if (!decode_multiplication_consistency_witness_abi(
            witness_words, &decoded_witness) ||
        decoded_witness.lhs_share != abi_witness.lhs_share ||
        decoded_witness.rhs_share != abi_witness.rhs_share ||
        decoded_witness.product_value != abi_witness.product_value ||
        decoded_witness.lhs_sharing_witness_words !=
            abi_witness.lhs_sharing_witness_words ||
        decoded_witness.rhs_sharing_witness_words !=
            abi_witness.rhs_sharing_witness_words ||
        decoded_witness.output_sharing_witness_words !=
            abi_witness.output_sharing_witness_words)
        return result;

    MultiplicationConsistencyCapabilities decoded_capabilities;
    const auto capabilities_words =
        encode_multiplication_consistency_capabilities_abi(
            multiplication_backend.Capabilities());
    if (!decode_multiplication_consistency_capabilities_abi(
            capabilities_words, &decoded_capabilities) ||
        decoded_capabilities.capability_binding !=
            multiplication_backend.Capabilities().capability_binding)
        return result;

    MultiplicationConsistencyProviderCallbacks provider_callbacks;
    provider_callbacks.prove =
        [&](const MultiplicationConsistencyStatement& statement,
            const MultiplicationConsistencyWitness& witness) {
            return multiplication_backend.Prove(statement, witness);
        };
    provider_callbacks.verify =
        [&](const MultiplicationConsistencyStatement& statement,
            const MultiplicationConsistencyProofArtifact& proof) {
            return multiplication_backend.Verify(statement, proof);
        };
    ExternalMultiplicationConsistencyProviderSession provider_session(
        multiplication_backend.Capabilities(),
        0x4d554c54U,
        std::move(provider_callbacks));
    if (!provider_session.Activate(
            rank, world_size, MPI_COMM_WORLD) ||
        !provider_session.active() ||
        !provider_session.acceptance().available)
        return result;

    AttestedResidualRuntimeBundle residual_runtime(
        store, exchange, rank, world_size, threshold, sid,
        nullptr, MPI_COMM_WORLD);
    if (!result.runtime_default_failclosed ||
        !residual_runtime.ready() ||
        !residual_runtime.ActivateSealedCheckpoint(
            sealed_checkpoint, local_activation_materials, registry))
        return result;
    const ObligationSet& synchronized_activation_scope =
        residual_runtime.last_activation_scope();
    result.sealed_activation_sync_bound =
        residual_runtime.last_activation_scope_sync_binding() != Digest{} &&
        synchronized_activation_scope.session_id == scope.session_id &&
        synchronized_activation_scope.phase == scope.phase &&
        synchronized_activation_scope.round == scope.round &&
        synchronized_activation_scope.generation == scope.generation &&
        synchronized_activation_scope.checkpoint == scope.checkpoint &&
        synchronized_activation_scope.checkpoint_root == scope.checkpoint_root &&
        synchronized_activation_scope.obligations == scope.obligations &&
        synchronized_activation_scope.operations == scope.operations &&
        synchronized_activation_scope.private_operations ==
            scope.private_operations &&
        synchronized_activation_scope.transfer_operations.empty();
    if (!result.sealed_activation_sync_bound) return result;
    ReferenceShamirResidualMpcBackend& backend = residual_runtime.data_plane();
    result.runtime_reference_only =
        residual_runtime.engine().ProductionCapabilityBinding() == Digest{};
    result.runtime_bundle_bound = residual_runtime.ready_for_scope(
        synchronized_activation_scope) && result.runtime_reference_only;
    if (!result.runtime_bundle_bound ||
        !backend.HasActivatedResiduals(synchronized_activation_scope) ||
        backend.activation_binding() == Digest{})
        return result;
    result.activated_before_failure = true;
    result.activated_vss_bound = backend.HasActivatedVssProvenance(scope);
    if (!result.activated_vss_bound) return result;
    store.Clear();
    result.store_independent = store.size() == 0;
    if (!result.store_independent) return result;

    const ResidualMpcCapabilities capabilities = backend.Capabilities();
    ResidualMpcCapabilities forged = capabilities;
    forged.security_level = RobustAuditSecurityLevel::MALICIOUS_ABORT;
    forged.publicly_identifiable_abort = true;
    forged.identifiable_abort_capability_binding = hash_words({
        SELFTEST_SCOPE_DOMAIN, sid, checkpoint, 0x43415031ULL});
    forged.capability_binding = compute_residual_mpc_capability_binding(forged);
    const bool rejects_without_malicious_security =
        !validate_residual_mpc_capabilities(forged);
    forged.malicious_secure = true;
    forged.activation_before_failure = false;
    forged.capability_binding = compute_residual_mpc_capability_binding(forged);
    const bool rejects_without_failure_before_activation =
        !validate_residual_mpc_capabilities(forged);
    result.security_capability_gate_bound =
        !capabilities.malicious_secure &&
        capabilities.activation_before_failure &&
        capabilities.authenticated_channel_capability_binding != Digest{} &&
        capabilities.identifiable_abort_capability_binding == Digest{} &&
        capabilities.delivery_capability_binding == Digest{} &&
        rejects_without_malicious_security &&
        rejects_without_failure_before_activation;
    if (!validate_residual_mpc_capabilities(capabilities) ||
        capabilities.security_level !=
            RobustAuditSecurityLevel::REFERENCE_PASSIVE ||
        !result.security_capability_gate_bound)
        return result;

    MpcBackedAuthenticatedResidualProtocol passive(
        backend, RobustAuditSecurityLevel::REFERENCE_PASSIVE);
    MpcBackedAuthenticatedResidualProtocol malicious_abort(
        backend, RobustAuditSecurityLevel::MALICIOUS_ABORT);
    MpcBackedAuthenticatedResidualProtocol god(
        backend, RobustAuditSecurityLevel::MALICIOUS_GOD);
    result.passive_gate = passive.ready();
    result.malicious_abort_rejected = !malicious_abort.ready();
    result.god_rejected = !god.ready();
    if (!result.passive_gate ||
        !result.malicious_abort_rejected ||
        !result.god_rejected)
        return result;

    const Digest strong_capability_binding =
        residual_runtime.strong_consistency_capability_binding();
    const ResidualMpcMaliciousSecurityCapabilities composed_security =
        residual_runtime.security_capabilities();
    const AuthenticatedMpcAbortEvidenceCapabilities abort_security =
        make_signed_equivocation_abort_evidence_capabilities(
            capabilities.authenticated_channel_capability_binding);
    result.composed_security_provider_bound =
        validate_residual_mpc_malicious_security_capabilities(
            composed_security) &&
        composed_security.security_level ==
            RobustAuditSecurityLevel::MALICIOUS_ABORT &&
        composed_security.strong_consistency_capability_binding ==
            strong_capability_binding &&
        production_ready_authenticated_mpc_abort_evidence_capabilities(
            abort_security) &&
        composed_security.identifiable_abort_capability_binding ==
            abort_security.capability_binding &&
        !composed_security.guaranteed_output_delivery;
    if (!result.composed_security_provider_bound) return result;

    ComposedResidualMpcMaliciousAbortSecurityProvider
        detached_transport_provider(
            capabilities.implementation_binding, multiplication_backend,
            hash_words({SELFTEST_SCOPE_DOMAIN, sid, checkpoint,
                        0x4445544143484544ULL}));
    AttestedResidualMpcBackend detached_transport_backend(
        backend, detached_transport_provider,
        RobustAuditSecurityLevel::MALICIOUS_ABORT);
    MpcBackedAuthenticatedResidualProtocol detached_transport_protocol(
        detached_transport_backend,
        RobustAuditSecurityLevel::MALICIOUS_ABORT);
    result.detached_transport_scope_rejected =
        detached_transport_protocol.ready() &&
        !detached_transport_protocol.ready_for_scope(scope);
    if (!result.detached_transport_scope_rejected) return result;

    const AttestedResidualMpcBackend& attested_backend =
        residual_runtime.attested_backend();
    const MpcBackedAuthenticatedResidualProtocol& attested_protocol =
        residual_runtime.protocol();
    FailClosedResidualMpcMaliciousSecurityProvider fail_closed_provider;
    AttestedResidualMpcBackend fail_closed_backend(
        backend, fail_closed_provider,
        RobustAuditSecurityLevel::MALICIOUS_ABORT);
    MpcBackedAuthenticatedResidualProtocol fail_closed_protocol(
        fail_closed_backend, RobustAuditSecurityLevel::MALICIOUS_ABORT);
    MpcBackedAuthenticatedResidualProtocol attested_god(
        attested_backend, RobustAuditSecurityLevel::MALICIOUS_GOD);
    result.attested_malicious_gate = attested_protocol.ready();
    result.attested_scope_gate = attested_protocol.ready_for_scope(scope);
    result.failclosed_security_provider_rejected =
        !fail_closed_protocol.ready() &&
        !fail_closed_protocol.ready_for_scope(scope);
    result.attested_god_rejected = !attested_god.ready();
    if (strong_capability_binding == Digest{} ||
        !result.attested_malicious_gate ||
        !result.attested_scope_gate ||
        !result.failclosed_security_provider_rejected ||
        !result.attested_god_rejected)
        return result;

    ProtocolBackedCollectiveResidualEngine engine(passive);
    const BatchCheckResult batch =
        engine.BatchCheck(scope, local_view, rank, world_size);
    if (!batch.available || !batch.cryptographically_authenticated)
        return result;
    result.ran = true;
    result.batch_ok = batch.ok;
    result.reference_security_attestation_empty =
        batch.security_attestation_binding == Digest{};
    if (!result.reference_security_attestation_empty) return result;
    result.strong_zero_consistency = multiplication_backend.prove_count() > 0;
    if (!result.strong_zero_consistency) return result;

    const ProtocolBackedCollectiveResidualEngine& attested_engine =
        residual_runtime.engine();
    const BatchCheckResult attested_batch =
        attested_engine.BatchCheck(scope, local_view, rank, world_size);
    result.attested_batch_ok =
        attested_batch.available &&
        attested_batch.cryptographically_authenticated &&
        attested_batch.ok == batch.ok;
    result.attested_security_transcript_bound =
        attested_batch.security_attestation_binding != Digest{} &&
        validate_collective_batch_result(scope, attested_batch, world_size);
    if (!result.attested_batch_ok ||
        !result.attested_security_transcript_bound)
        return result;

    auto reject_attested_state_drift = [&]() -> bool {
        const CollectiveBatchDescriptor drift_descriptor =
            make_collective_batch_descriptor(
                scope, local_view, rank, world_size);
        const CollectiveResidualCommitmentSet drift_commitments =
            attested_backend.CommitResidualBatch(
                scope, drift_descriptor, local_view, rank, world_size);
        if (!validate_participant_commitment_set(
                scope, drift_descriptor, drift_commitments, world_size) ||
            drift_commitments.security_attestation_binding == Digest{})
            return false;
        residual_runtime.ClearActivatedResiduals();
        const bool scope_gate_rejected =
            !residual_runtime.ready_for_scope(scope);
        const AuthenticatedChallengeTranscript drift_challenge =
            attested_backend.DeriveJointChallenge(
                scope, drift_descriptor, drift_commitments, rank, world_size);
        return scope_gate_rejected &&
               !drift_challenge.available &&
               !drift_challenge.cryptographically_authenticated;
    };

    if (!inject_fault) {
        result.localized = true;
        result.attested_localized = true;
        result.attested_state_drift_rejected =
            reject_attested_state_drift();
        return result;
    }
    if (batch.ok || batch.mismatches == 0)
        return result;

    const CollectiveDisputeResult dispute =
        engine.Dispute(scope, batch, local_view, rank, world_size);
    const OperationRef expected_accused{
        faulty_owner,
        static_cast<uint64_t>(2000 + faulty_owner)};
    result.localized =
        dispute.available &&
        dispute.cryptographically_authenticated &&
        dispute.found &&
        dispute.accused == expected_accused &&
        dispute.expected != dispute.actual &&
        dispute.residual_commitment != Digest{} &&
        dispute.recursive_transcript_binding != Digest{} &&
        dispute.localization_commitment != Digest{} &&
        validate_collective_dispute_result(scope, batch, dispute);
    if (!result.localized) return result;

    const CollectiveDisputeResult attested_dispute =
        attested_engine.Dispute(
            scope, attested_batch, local_view, rank, world_size);
    result.attested_localized =
        attested_dispute.available &&
        attested_dispute.cryptographically_authenticated &&
        attested_dispute.found &&
        attested_dispute.accused == expected_accused &&
        attested_dispute.security_attestation_binding ==
            attested_batch.security_attestation_binding &&
        attested_dispute.security_attestation_binding != Digest{} &&
        attested_dispute.expected != attested_dispute.actual &&
        validate_collective_dispute_result(
            scope, attested_batch, attested_dispute);
    result.attested_state_drift_rejected =
        result.attested_localized && reject_attested_state_drift();
    return result;
}

bool run_causal_no_framing_case(int rank, int world_size) {
    if (world_size < 4 || rank < 0 || rank >= world_size) return false;

    const uint64_t sid = 0x43415553414c4e46ULL; // CAUSALNF
    const CheckpointId checkpoint = static_cast<CheckpointId>(0x7010);
    const uint32_t round = 16U;
    const uint32_t upstream_owner = 1U;
    const uint32_t downstream_owner = 2U;

    ObligationSet scope;
    scope.session_id = sid;
    scope.phase = Phase::FOLD;
    scope.round = round;
    scope.generation = 1;
    scope.exact_round = true;
    scope.checkpoint = checkpoint;
    scope.checkpoint_root = hash_words({
        SELFTEST_SCOPE_DOMAIN, sid, checkpoint, round, 0x43415553414cULL});
    scope.obligations = {Obligation::FOLD};
    for (int owner = 0; owner < world_size; ++owner) {
        OperationRef ref{
            static_cast<uint32_t>(owner),
            static_cast<uint64_t>(6000 + owner)};
        scope.operations.push_back(ref);
        scope.private_operations.push_back(ref);
    }

    const OperationRef upstream_ref{
        upstream_owner, static_cast<uint64_t>(6000 + upstream_owner)};
    const OperationRef downstream_ref{
        downstream_owner, static_cast<uint64_t>(6000 + downstream_owner)};

    // Reproduce Runtime::compute_predecessor_root for the downstream
    // statement, using the faulty upstream operation's authenticated actual.
    const Digest upstream_actual = hash_words({
        SELFTEST_ACTUAL_DOMAIN, sid,
        upstream_ref.owner, upstream_ref.object_id});
    const Digest upstream_predecessor_root = hash_words({
        SELFTEST_SCOPE_DOMAIN, sid,
        upstream_ref.owner, upstream_ref.object_id, 0});
    std::vector<u64> predecessor_words = {
        upstream_ref.owner, upstream_ref.object_id};
    append_digest_words_selftest(upstream_actual, &predecessor_words);
    append_digest_words_selftest(
        upstream_predecessor_root, &predecessor_words);
    const Digest downstream_predecessor_root =
        hash_words(predecessor_words);

    const OperationRef local_ref{
        static_cast<uint32_t>(rank),
        static_cast<uint64_t>(6000 + rank)};
    const bool local_fault =
        static_cast<uint32_t>(rank) == upstream_owner;
    const bool is_downstream =
        static_cast<uint32_t>(rank) == downstream_owner;
    const Digest local_predecessor_root = is_downstream
        ? downstream_predecessor_root
        : hash_words({
            SELFTEST_SCOPE_DOMAIN, sid,
            local_ref.owner, local_ref.object_id, 0});
    const uint32_t local_predecessor_count =
        is_downstream ? 1U : 0U;

    PrivateResidualShareStore store;
    PrivateResidualRegistry registry;
    PrivateResidualShare local_share;
    PrivateResidualHandle local_handle;
    if (!make_authenticated_share_bound(
            sid, checkpoint, round, local_ref, local_fault,
            local_predecessor_root, local_predecessor_count,
            &local_share, &local_handle) ||
        !store.Put(local_share))
        return false;
    registry.Put(local_handle);

    const LocalResidualBatchView local_view =
        registry.BuildLocalBatchView(
            scope, static_cast<uint32_t>(rank));
    if (!local_view.complete_for_owner ||
        !local_view.all_authenticated ||
        local_view.handles.size() != 1)
        return false;

    const int threshold = (world_size - 1) / 3;
    AuthenticatedMpcExchange exchange(rank, world_size);
    if (!exchange.production_authenticated_ready()) return false;
    ReferenceShamirMpc mpc(rank, world_size, threshold);
    ReferenceShamirResidualMpcBackend backend(store, mpc, exchange);
    MpcBackedAuthenticatedResidualProtocol passive(
        backend, RobustAuditSecurityLevel::REFERENCE_PASSIVE);
    if (!passive.ready()) return false;
    ProtocolBackedCollectiveResidualEngine engine(passive);

    const BatchCheckResult batch =
        engine.BatchCheck(scope, local_view, rank, world_size);
    if (!batch.available || !batch.cryptographically_authenticated ||
        batch.ok || batch.mismatches == 0)
        return false;

    const CollectiveDisputeResult dispute =
        engine.Dispute(scope, batch, local_view, rank, world_size);
    const bool downstream_local_valid =
        !is_downstream || (
            local_share.expected == local_share.actual &&
            local_share.values.size() == 2 &&
            local_share.values[0] == F(0) &&
            local_share.values[1] == F(0));
    const bool downstream_predecessor_bound =
        !is_downstream ||
        local_share.operation_statement_binding ==
            compute_relation_statement(
                local_share.label, local_share.relation,
                local_share.kernel, local_share.expected,
                downstream_predecessor_root, 1,
                hash_words({
                    SELFTEST_SCOPE_DOMAIN, sid,
                    downstream_ref.owner,
                    downstream_ref.object_id, 1}),
                1, local_share.public_aux_root, 1);

    const bool local_ok =
        downstream_local_valid &&
        downstream_predecessor_bound &&
        dispute.available &&
        dispute.cryptographically_authenticated &&
        dispute.found &&
        dispute.accused == upstream_ref &&
        dispute.accused != downstream_ref &&
        dispute.expected != dispute.actual &&
        validate_collective_dispute_result(scope, batch, dispute);

    int local = local_ok ? 1 : 0;
    int global = 0;
    MPI_Allreduce(
        &local, &global, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    if (rank == 0) {
        std::cout
            << "[PVIA][causal-no-framing-selftest]"
            << " upstream=" << upstream_owner
            << " downstream=" << downstream_owner
            << " downstream-local=VALID"
            << " predecessor-bound=BOUND"
            << " mismatch=DETECTED"
            << " accused=UPSTREAM"
            << " downstream-framing=REJECTED"
            << " result=" << (global ? "PASS" : "FAIL")
            << "\n";
    }
    return global != 0;
}

bool run_tampered_preflight_case(int rank, int world_size) {
    if (world_size < 4 || rank < 0 || rank >= world_size) return false;
    const uint64_t sid = 0x52534d5043540003ULL;
    const CheckpointId checkpoint = static_cast<CheckpointId>(0x7003);
    const uint32_t round = 13U;

    ObligationSet scope;
    scope.session_id = sid;
    scope.phase = Phase::FOLD;
    scope.round = round;
    scope.generation = 1;
    scope.exact_round = true;
    scope.checkpoint = checkpoint;
    scope.checkpoint_root = hash_words({
        SELFTEST_SCOPE_DOMAIN, sid, checkpoint, round});
    scope.obligations = {Obligation::FOLD};
    for (int owner = 0; owner < world_size; ++owner) {
        OperationRef ref{
            static_cast<uint32_t>(owner),
            static_cast<uint64_t>(3000 + owner)};
        scope.operations.push_back(ref);
        scope.private_operations.push_back(ref);
    }

    PrivateResidualShareStore store;
    PrivateResidualRegistry registry;
    const OperationRef local_ref{
        static_cast<uint32_t>(rank),
        static_cast<uint64_t>(3000 + rank)};
    PrivateResidualShare local_share;
    PrivateResidualHandle local_handle;
    if (!make_authenticated_share(
            sid, checkpoint, round, local_ref, false,
            &local_share, &local_handle) ||
        !store.Put(local_share))
        return false;
    registry.Put(local_handle);
    LocalResidualBatchView local_view =
        registry.BuildLocalBatchView(scope, static_cast<uint32_t>(rank));
    if (!local_view.complete_for_owner || !local_view.all_authenticated ||
        local_view.handles.size() != 1)
        return false;

    // Only one rank corrupts its opaque handle after registry construction.
    // The backend must synchronize readiness and fail closed on every rank;
    // no peer may enter a later MPI collective alone.
    if (rank == 0)
        local_view.handles.front().commitment = hash_words({0xBAD0C0DEULL});

    const int threshold = (world_size - 1) / 3;
    AuthenticatedMpcExchange exchange(rank, world_size);
    if (!exchange.production_authenticated_ready()) return false;
    ReferenceShamirMpc mpc(rank, world_size, threshold);
    ReferenceShamirResidualMpcBackend backend(store, mpc, exchange);
    MpcBackedAuthenticatedResidualProtocol passive(
        backend, RobustAuditSecurityLevel::REFERENCE_PASSIVE);
    if (!passive.ready()) return false;
    ProtocolBackedCollectiveResidualEngine engine(passive);
    const BatchCheckResult batch =
        engine.BatchCheck(scope, local_view, rank, world_size);
    return !batch.available && !batch.cryptographically_authenticated;
}

} // namespace

class CountingResidualProtocol final
    : public AuthenticatedResidualProtocol {
public:
    explicit CountingResidualProtocol(
        const AuthenticatedResidualProtocol& inner)
        : inner_(inner) {}

    CollectiveResidualCommitmentSet CommitResidualBatch(
        const ObligationSet& scope,
        const CollectiveBatchDescriptor& descriptor,
        const LocalResidualBatchView& local_view,
        int rank, int world_size) const override {
        return inner_.CommitResidualBatch(
            scope, descriptor, local_view, rank, world_size);
    }

    AuthenticatedChallengeTranscript DeriveJointChallenge(
        const ObligationSet& scope,
        const CollectiveBatchDescriptor& descriptor,
        const CollectiveResidualCommitmentSet& commitments,
        int rank, int world_size) const override {
        return inner_.DeriveJointChallenge(
            scope, descriptor, commitments, rank, world_size);
    }

    BatchCheckResult RandomLinearBatchCheck(
        const ObligationSet& scope,
        const CollectiveBatchDescriptor& descriptor,
        const LocalResidualBatchView& local_view,
        const CollectiveResidualCommitmentSet& commitments,
        const AuthenticatedChallengeTranscript& transcript,
        int rank, int world_size) const override {
        return inner_.RandomLinearBatchCheck(
            scope, descriptor, local_view, commitments,
            transcript, rank, world_size);
    }

    ResidualSubsetCheckResult CheckResidualSubset(
        const ObligationSet& scope,
        const BatchCheckResult& batch,
        const ResidualSubsetDescriptor& subset,
        const LocalResidualBatchView& local_view,
        int rank, int world_size) const override {
        ++subset_checks_;
        if (subset.depth > max_depth_) max_depth_ = subset.depth;
        return inner_.CheckResidualSubset(
            scope, batch, subset, local_view, rank, world_size);
    }

    CollectiveDisputeResult FinalizeLocalization(
        const ObligationSet& scope,
        const BatchCheckResult& batch,
        const OperationRef& accused,
        const Digest& recursive_binding,
        const LocalResidualBatchView& local_view,
        int rank, int world_size) const override {
        ++finalize_calls_;
        return inner_.FinalizeLocalization(
            scope, batch, accused, recursive_binding,
            local_view, rank, world_size);
    }

    uint64_t subset_checks() const { return subset_checks_; }
    uint32_t recursive_levels() const {
        return subset_checks_ == 0 ? 0U : max_depth_ + 1U;
    }
    uint64_t finalize_calls() const { return finalize_calls_; }

private:
    const AuthenticatedResidualProtocol& inner_;
    mutable uint64_t subset_checks_ = 0;
    mutable uint32_t max_depth_ = 0;
    mutable uint64_t finalize_calls_ = 0;
};

bool run_reference_residual_localization_benchmark(
    int rank, int world_size, size_t total_operations,
    bool fault_last, int owner0_position) {
    if (world_size < 4 || rank < 0 || rank >= world_size ||
        total_operations < static_cast<size_t>(world_size) ||
        total_operations % static_cast<size_t>(world_size) != 0)
        return false;

    if(!run_residual_batch_global_additivity_selftest())return false;
    const uint64_t sid = Runtime::instance().session_id();
    const uint32_t round = 31U;
    const CheckpointId checkpoint =
        (static_cast<uint64_t>(Phase::FOLD) << 56) |
        (static_cast<uint64_t>(round) << 24) |
        static_cast<uint64_t>(total_operations);

    ObligationSet scope;
    scope.session_id = sid;
    scope.phase = Phase::FOLD;
    scope.round = round;
    scope.generation = 1;
    scope.exact_round = true;
    scope.checkpoint = checkpoint;
    scope.checkpoint_root = hash_words({
        SELFTEST_SCOPE_DOMAIN, sid, checkpoint, round,
        static_cast<u64>(total_operations),
        fault_last ? 1ULL : 0ULL});
    scope.obligations = {Obligation::FOLD};

    const size_t per_owner =
        total_operations / static_cast<size_t>(world_size);
    for (int owner = 0; owner < world_size; ++owner) {
        for (size_t j = 0; j < per_owner; ++j) {
            scope.operations.push_back(OperationRef{
                static_cast<uint32_t>(owner),
                static_cast<uint64_t>(
                    800000 + static_cast<uint64_t>(owner) * 100000 + j)});
        }
    }
    scope.private_operations = scope.operations;
    // Same attributed owner, distinct private operation: this is a
    // disclosure-diagnostic fixture, NOT an oblivious backend.
    if(owner0_position >= 0 &&
       (owner0_position > 2 || per_owner < 3))return false;
    size_t selected_index=0;
    if(owner0_position == 1)selected_index=per_owner/2;
    else if(owner0_position == 2)selected_index=per_owner-1;
    const OperationRef fault_ref=owner0_position>=0
        ? scope.operations[selected_index]
        : (fault_last ? scope.operations.back() : scope.operations.front());

    PrivateResidualShareStore store;
    PrivateResidualRegistry registry;
    for (size_t j = 0; j < per_owner; ++j) {
        const OperationRef ref{
            static_cast<uint32_t>(rank),
            static_cast<uint64_t>(
                800000 + static_cast<uint64_t>(rank) * 100000 + j)};
        const bool faulty = ref == fault_ref;
        PrivateResidualShare share;
        PrivateResidualHandle handle;
        if (!make_authenticated_share(
                sid, checkpoint, round, ref, faulty,
                &share, &handle) ||
            !store.Put(share))
            return false;
        registry.Put(handle);
    }

    const LocalResidualBatchView local_view =
        registry.BuildLocalBatchView(
            scope, static_cast<uint32_t>(rank));
    if (!local_view.complete_for_owner ||
        !local_view.all_authenticated ||
        local_view.handles.size() != per_owner)
        return false;

    AuthenticatedMpcExchange exchange(rank, world_size);
    if (!exchange.production_authenticated_ready()) return false;
    ReferenceShamirMpc mpc(
        rank, world_size, (world_size - 1) / 3);
    ReferenceShamirResidualMpcBackend backend(store, mpc, exchange);
    MpcBackedAuthenticatedResidualProtocol base_protocol(
        backend, RobustAuditSecurityLevel::REFERENCE_PASSIVE);
    if (!base_protocol.ready()) return false;
    CountingResidualProtocol counted(base_protocol);
    ProtocolBackedCollectiveResidualEngine engine(counted);

    const ExperimentMetricsSnapshot before =
        experiment_metrics_snapshot();
    const uint64_t batch_start = experiment_now_ns();
    const BatchCheckResult batch =
        engine.BatchCheck(scope, local_view, rank, world_size);
    const uint64_t batch_end = experiment_now_ns();
    if (!batch.available || !batch.cryptographically_authenticated ||
        batch.ok || batch.mismatches == 0)
        return false;

    const ExperimentMetricsSnapshot after_batch =
        experiment_metrics_snapshot();
    // E08 honest evidence boundary: the active reference backend really
    // exposes recursive choices. Demanding hidden-location semantics must
    // refuse without scheduling ANY subset checks or revealing an operation.
    const auto hidden=engine.DisputeObliviously(
        scope,batch,local_view,rank,world_size);
    if(hidden.available || hidden.found ||
       counted.subset_checks()!=0 || counted.finalize_calls()!=0)
        return false;
    const uint64_t dispute_start = experiment_now_ns();
    const CollectiveDisputeResult dispute =
        engine.Dispute(
            scope, batch, local_view, rank, world_size);
    const uint64_t dispute_end = experiment_now_ns();
    const ExperimentMetricsSnapshot after =
        experiment_metrics_snapshot();

    const bool local_ok =
        dispute.available &&
        dispute.cryptographically_authenticated &&
        dispute.found &&
        dispute.accused == fault_ref &&
        dispute.expected != dispute.actual &&
        counted.finalize_calls() == 1 &&
        validate_collective_dispute_result(scope, batch, dispute);

    int local = local_ok ? 1 : 0;
    int global = 0;
    MPI_Allreduce(
        &local, &global, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);

    const uint64_t local_batch_ns = batch_end - batch_start;
    const uint64_t local_dispute_ns = dispute_end - dispute_start;
    uint64_t max_batch_ns = 0;
    uint64_t max_dispute_ns = 0;
    MPI_Reduce(
        &local_batch_ns, &max_batch_ns, 1, MPI_UINT64_T,
        MPI_MAX, 0, MPI_COMM_WORLD);
    MPI_Reduce(
        &local_dispute_ns, &max_dispute_ns, 1, MPI_UINT64_T,
        MPI_MAX, 0, MPI_COMM_WORLD);

    const uint64_t local_batch_auth_sent =
        after_batch.authenticated_envelope_sent_bytes -
        before.authenticated_envelope_sent_bytes;
    const uint64_t local_dispute_auth_sent =
        after.authenticated_envelope_sent_bytes -
        after_batch.authenticated_envelope_sent_bytes;
    const uint64_t local_batch_control_sent =
        after_batch.protocol_control_sent_bytes -
        before.protocol_control_sent_bytes;
    const uint64_t local_dispute_control_sent =
        after.protocol_control_sent_bytes -
        after_batch.protocol_control_sent_bytes;
    uint64_t sum_batch_auth_sent = 0;
    uint64_t sum_dispute_auth_sent = 0;
    uint64_t sum_batch_control_sent = 0;
    uint64_t sum_dispute_control_sent = 0;
    MPI_Reduce(
        &local_batch_auth_sent, &sum_batch_auth_sent,
        1, MPI_UINT64_T, MPI_SUM, 0, MPI_COMM_WORLD);
    MPI_Reduce(
        &local_dispute_auth_sent, &sum_dispute_auth_sent,
        1, MPI_UINT64_T, MPI_SUM, 0, MPI_COMM_WORLD);
    MPI_Reduce(
        &local_batch_control_sent, &sum_batch_control_sent,
        1, MPI_UINT64_T, MPI_SUM, 0, MPI_COMM_WORLD);
    MPI_Reduce(
        &local_dispute_control_sent, &sum_dispute_control_sent,
        1, MPI_UINT64_T, MPI_SUM, 0, MPI_COMM_WORLD);

    uint64_t subset_min = 0, subset_max = 0;
    uint32_t depth_min = 0, depth_max = 0;
    const uint64_t local_subset = counted.subset_checks();
    const uint32_t local_depth = counted.recursive_levels();
    MPI_Reduce(
        &local_subset, &subset_min, 1, MPI_UINT64_T,
        MPI_MIN, 0, MPI_COMM_WORLD);
    MPI_Reduce(
        &local_subset, &subset_max, 1, MPI_UINT64_T,
        MPI_MAX, 0, MPI_COMM_WORLD);
    MPI_Reduce(
        &local_depth, &depth_min, 1, MPI_UNSIGNED,
        MPI_MIN, 0, MPI_COMM_WORLD);
    MPI_Reduce(
        &local_depth, &depth_max, 1, MPI_UNSIGNED,
        MPI_MAX, 0, MPI_COMM_WORLD);

    if (rank == 0) {
        const bool counters_agree =
            subset_min == subset_max && depth_min == depth_max;
        std::cout
            << "[PVIA][localization-scaling]"
            << " q=" << total_operations
            << " fault=" << (owner0_position==0 ? "owner0_first" :
                             owner0_position==1 ? "owner0_middle" :
                             owner0_position==2 ? "owner0_last" :
                             fault_last ? "last" : "first")
            << " depth=" << depth_max
            << " subset_checks=" << subset_max
            << " batch_ns=" << max_batch_ns
            << " dispute_ns=" << max_dispute_ns
            << " batch_auth_sent_bytes=" << sum_batch_auth_sent
            << " dispute_auth_sent_bytes=" << sum_dispute_auth_sent
            << " batch_control_sent_bytes=" << sum_batch_control_sent
            << " dispute_control_sent_bytes=" << sum_dispute_control_sent
            << " accused_owner=" << dispute.accused.owner
            << " accused_object=" << dispute.accused.object_id
            << " counters_agree="
            << (counters_agree ? "yes" : "no")
            << " result="
            << (global && counters_agree ? "PASS" : "FAIL")
            << "\n";
    }
    return global != 0;
}

bool run_reference_residual_mpc_selftest(
    int rank, int world_size) {
    const CaseResult clean =
        run_case(rank, world_size, false);
    const CaseResult faulty =
        run_case(rank, world_size, true);
    const bool tampered_preflight_rejected =
        run_tampered_preflight_case(rank, world_size);
    const bool causal_no_framing =
        run_causal_no_framing_case(rank, world_size);
    const ProviderCaseResult provider_clean =
        run_provider_integration_case(rank, world_size, false);
    const ProviderCaseResult provider_faulty =
        run_provider_integration_case(rank, world_size, true);
    const bool malicious_security_boundary =
        run_residual_mpc_malicious_security_boundary_selftest();

    const bool local_ok =
        clean.ran && clean.batch_ok && clean.localized &&
        clean.activated_before_failure && clean.store_independent &&
        clean.activated_vss_bound && clean.strong_zero_consistency &&
        clean.reference_security_attestation_empty &&
        clean.attested_malicious_gate && clean.attested_scope_gate &&
        clean.runtime_bundle_bound && clean.runtime_reference_only &&
        clean.runtime_default_failclosed &&
        clean.sealed_activation_scope_bound &&
        clean.sealed_activation_local_fragment_bound &&
        clean.sealed_activation_sync_bound &&
        clean.sealed_activation_tamper_rejected &&
        clean.composed_security_provider_bound &&
        clean.detached_transport_scope_rejected &&
        clean.attested_batch_ok &&
        clean.attested_security_transcript_bound && clean.attested_localized &&
        clean.failclosed_security_provider_rejected &&
        clean.attested_god_rejected && clean.attested_state_drift_rejected &&
        clean.security_capability_gate_bound &&
        clean.passive_gate &&
        clean.malicious_abort_rejected && clean.god_rejected &&
        faulty.ran && !faulty.batch_ok && faulty.localized &&
        faulty.activated_before_failure && faulty.store_independent &&
        faulty.activated_vss_bound && faulty.strong_zero_consistency &&
        faulty.reference_security_attestation_empty &&
        faulty.attested_malicious_gate && faulty.attested_scope_gate &&
        faulty.runtime_bundle_bound && faulty.runtime_reference_only &&
        faulty.runtime_default_failclosed &&
        faulty.sealed_activation_scope_bound &&
        faulty.sealed_activation_local_fragment_bound &&
        faulty.sealed_activation_sync_bound &&
        faulty.sealed_activation_tamper_rejected &&
        faulty.composed_security_provider_bound &&
        faulty.detached_transport_scope_rejected &&
        faulty.attested_batch_ok &&
        faulty.attested_security_transcript_bound && faulty.attested_localized &&
        faulty.failclosed_security_provider_rejected &&
        faulty.attested_god_rejected && faulty.attested_state_drift_rejected &&
        faulty.security_capability_gate_bound &&
        faulty.passive_gate &&
        faulty.malicious_abort_rejected && faulty.god_rejected &&
        malicious_security_boundary && tampered_preflight_rejected &&
        causal_no_framing &&
        provider_clean.ran && provider_clean.batch_ok &&
        provider_clean.localized &&
        provider_clean.production_gate_rejected &&
        provider_faulty.ran && !provider_faulty.batch_ok &&
        provider_faulty.localized &&
        provider_faulty.production_gate_rejected;
    int local = local_ok ? 1 : 0;
    int global = 0;
    MPI_Allreduce(&local, &global, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);

    if (rank == 0) {
        std::cout
            << "[PVIA][reference-residual-mpc-selftest]"
            << " clean=" << (clean.ran && clean.batch_ok ? "PASS" : "FAIL")
            << " mismatch="
            << (faulty.ran && !faulty.batch_ok ? "DETECTED" : "MISSED")
            << " localization=" << (faulty.localized ? "BOUND" : "FAIL")
            << " activated-before-failure="
            << (clean.activated_before_failure && faulty.activated_before_failure
                    ? "BOUND" : "FAIL")
            << " post-activation-store="
            << (clean.store_independent && faulty.store_independent
                    ? "INDEPENDENT" : "DEPENDENT")
            << " activated-vss="
            << (clean.activated_vss_bound && faulty.activated_vss_bound
                    ? "BOUND" : "FAIL")
            << " strong-zero-consistency="
            << (clean.strong_zero_consistency &&
                faulty.strong_zero_consistency ? "BOUND" : "FAIL")
            << " reference-security-attestation="
            << (clean.reference_security_attestation_empty &&
                faulty.reference_security_attestation_empty
                    ? "EMPTY" : "UNEXPECTED")
            << " attested-malicious="
            << (clean.attested_malicious_gate && faulty.attested_malicious_gate
                    ? "READY" : "FAIL")
            << " attested-scope-gate="
            << (clean.attested_scope_gate && faulty.attested_scope_gate
                    ? "BOUND" : "FAIL")
            << " runtime-bundle="
            << (clean.runtime_bundle_bound && faulty.runtime_bundle_bound
                    ? "BOUND" : "FAIL")
            << " runtime-production-binding="
            << (clean.runtime_reference_only && faulty.runtime_reference_only
                    ? "EMPTY" : "UNEXPECTED")
            << " runtime-default-proof="
            << (clean.runtime_default_failclosed &&
                faulty.runtime_default_failclosed
                    ? "REJECTED" : "ACCEPTED")
            << " sealed-activation-scope="
            << (clean.sealed_activation_scope_bound && faulty.sealed_activation_scope_bound
                    ? "BOUND" : "FAIL")
            << " sealed-activation-local="
            << (clean.sealed_activation_local_fragment_bound &&
                faulty.sealed_activation_local_fragment_bound
                    ? "BOUND" : "FAIL")
            << " sealed-activation-sync="
            << (clean.sealed_activation_sync_bound &&
                faulty.sealed_activation_sync_bound
                    ? "BOUND" : "FAIL")
            << " sealed-activation-tamper="
            << (clean.sealed_activation_tamper_rejected &&
                faulty.sealed_activation_tamper_rejected
                    ? "REJECTED" : "ACCEPTED")
            << " composed-malicious-provider="
            << (clean.composed_security_provider_bound &&
                faulty.composed_security_provider_bound ? "BOUND" : "FAIL")
            << " detached-transport-scope="
            << (clean.detached_transport_scope_rejected &&
                faulty.detached_transport_scope_rejected
                    ? "REJECTED" : "ACCEPTED")
            << " attested-security-transcript="
            << (clean.attested_security_transcript_bound &&
                faulty.attested_security_transcript_bound ? "BOUND" : "FAIL")
            << " attested-localization="
            << (faulty.attested_localized ? "BOUND" : "FAIL")
            << " failclosed-security-provider="
            << (clean.failclosed_security_provider_rejected &&
                faulty.failclosed_security_provider_rejected
                    ? "REJECTED" : "ACCEPTED")
            << " attested-god="
            << (clean.attested_god_rejected && faulty.attested_god_rejected
                    ? "REJECTED" : "ACCEPTED")
            << " attested-state-drift="
            << (clean.attested_state_drift_rejected &&
                faulty.attested_state_drift_rejected
                    ? "REJECTED" : "ACCEPTED")
            << " capability-contract="
            << (clean.security_capability_gate_bound &&
                faulty.security_capability_gate_bound ? "BOUND" : "FAIL")
            << " malicious-security-boundary="
            << (malicious_security_boundary ? "BOUND" : "FAIL")
            << " passive-gate=" << (faulty.passive_gate ? "READY" : "FAIL")
            << " malicious-abort="
            << (faulty.malicious_abort_rejected ? "REJECTED" : "ACCEPTED")
            << " god=" << (faulty.god_rejected ? "REJECTED" : "ACCEPTED")
            << " tamper-preflight="
            << (tampered_preflight_rejected ? "REJECTED" : "FAIL")
            << " causal-no-framing="
            << (causal_no_framing ? "BOUND" : "FAIL")
            << " provider-clean="
            << (provider_clean.ran && provider_clean.batch_ok ? "PASS" : "FAIL")
            << " provider-mismatch="
            << (provider_faulty.ran && !provider_faulty.batch_ok
                    ? "DETECTED" : "MISSED")
            << " provider-localization="
            << (provider_faulty.localized ? "BOUND" : "FAIL")
            << " provider-production-gate="
            << (provider_clean.production_gate_rejected &&
                provider_faulty.production_gate_rejected
                    ? "REJECTED" : "ACCEPTED")
            << " result=" << (global ? "PASS" : "FAIL")
            << "\n";
    }
    return global != 0;
}


// Formal P1-05 reference bridge fixture: real native-style authenticated
// residuals are VSS-activated before store erasure, then consumed ONLY from
// the activated MPC state with a commit-bound joint challenge. This is still
// not the paper's full R_q native release path or private public ZK.
bool run_reference_activated_private_owner_selftest(
    int rank,int world_size) {
    if(rank<0 || rank>=world_size ||
       world_size<4 || world_size>16)return false;
    const char* private_position=
        std::getenv("PVIA_P105_ACTIVATED_PRIVATE_POSITION");
    const std::string mode=rank==0 && private_position
        ? std::string(private_position) : "other-party";
    const char* fast_oblivious_env=std::getenv(
        "PVIA_P105_OBLIVIOUS_AUDIT_FAST");
    const bool fast_oblivious_audit=fast_oblivious_env &&
        std::string(fast_oblivious_env)!="0";
    if(rank==0 && mode!="first" && mode!="middle" &&
       mode!="last" && mode!="none")return false;
    if(rank==0 && fast_oblivious_audit &&
       mode!="first" && mode!="none")return false;
    const uint64_t sid=Runtime::instance().session_id();
    const uint32_t round=33U;
    const CheckpointId checkpoint=
        (static_cast<uint64_t>(Phase::FOLD)<<56) |
        (static_cast<uint64_t>(round)<<24) |
        static_cast<uint64_t>(world_size+2);
    if(!sid)return false;
    ObligationSet scope;
    scope.session_id=sid;
    scope.phase=Phase::FOLD;
    scope.round=round;
    scope.generation=1;
    scope.exact_round=true;
    scope.checkpoint=checkpoint;
    scope.checkpoint_root=hash_words({
        SELFTEST_SCOPE_DOMAIN,sid,checkpoint,
        static_cast<u64>(world_size),0x5056313035415632ULL});
    scope.obligations={Obligation::FOLD};
    for(int owner=0;owner<world_size;++owner) {
        const int slots=owner==0?(fast_oblivious_audit?1:3):1;
        for(int pos=0;pos<slots;++pos)
            scope.operations.push_back({
                static_cast<uint32_t>(owner),
                910000ULL+static_cast<uint64_t>(owner)*100ULL+
                    static_cast<uint64_t>(pos)});
    }
    scope.private_operations=scope.operations;
    PrivateResidualShareStore store;
    PrivateResidualRegistry registry;
    const int my_slots=rank==0?(fast_oblivious_audit?1:3):1;
    for(int pos=0;pos<my_slots;++pos) {
        const OperationRef ref{
            static_cast<uint32_t>(rank),
            910000ULL+static_cast<uint64_t>(rank)*100ULL+
                static_cast<uint64_t>(pos)};
        const bool faulty=rank==0 &&
            ((mode=="first" && pos==0) ||
             (!fast_oblivious_audit && mode=="middle" && pos==1) ||
             (!fast_oblivious_audit && mode=="last" && pos==2));
        PrivateResidualShare share;
        PrivateResidualHandle handle;
        if(!make_authenticated_share(
                sid,checkpoint,round,ref,faulty,&share,&handle))
            return false;
        {
            // All candidates use native-style FOLD_RS values and layout.
            // The checked residual is actual - recomputed for every slot.
            const F native_delta=faulty?F(7):F(0);
            share.values={native_delta};
            const char* mismatched=std::getenv(
                "PVIA_P105_SIGNED_SOURCE_NEGATIVE");
            if(rank==0 && mismatched &&
                ((std::string(mismatched)=="fold_relation" && pos==0) ||
                 (std::string(mismatched)=="fold_all_middle" && pos==1) ||
                 (std::string(mismatched)=="fold_all_last" && pos==2)))
                share.values[0]=F(9); // recompute authentication/root
            share.source_state_id=94000ULL+
                static_cast<u64>(rank)*10ULL+static_cast<u64>(pos);
            share.source_state_digest=
                hash_field_vector({F(13),F(13)});
            share.source_state_authentication_scheme_id=
                SELFTEST_AUTH_SCHEME;
            share.source_state_authentication_binding=hash_words({
                SELFTEST_SCOPE_DOMAIN,sid,checkpoint,
                0x4e41544956454155ULL});
            share.public_aux_root=compute_public_aux_root({
                PublicAuxEvidence{AuditPublicAuxKind::FOLD_CHALLENGE,
                    hash_field_vector({F(7)})}});
            const F folded_expected=(F(1)-F(7))*F(13);
            share.expected=hash_field_vector({folded_expected});
            share.actual=hash_field_vector({folded_expected+native_delta});
            share.computation_binding=
                compute_private_residual_computation_binding(share);
            share.authentication.computation_binding=
                share.computation_binding;
            share.authentication.source_state_id=share.source_state_id;
            share.authentication.source_state_owner=share.source_state_owner;
            share.authentication.source_state_digest=
                share.source_state_digest;
            share.authentication.source_state_authentication_scheme_id=
                share.source_state_authentication_scheme_id;
            share.authentication.source_state_authentication_binding=
                share.source_state_authentication_binding;
            share.authentication.public_aux_root=share.public_aux_root;
            share.authentication.binding=
                compute_private_residual_authentication_artifact_binding(
                    share.authentication);
            share.authentication_binding=share.authentication.binding;
            share.commitment=compute_private_residual_share_commitment(share);
            handle.commitment=share.commitment;
            if(!validate_private_residual_share(share))
                return false;
        }
        if(!store.Put(share))return false;
        registry.Put(handle);
    }
    LocalResidualBatchView local_view=
        registry.BuildLocalBatchView(
            scope,static_cast<uint32_t>(rank));
    if(!local_view.complete_for_owner ||
       !local_view.all_authenticated ||
       local_view.handles.size()!=static_cast<size_t>(my_slots))
        return false;
    AuthenticatedMpcExchange exchange(rank,world_size);
    if(!exchange.production_authenticated_ready())return false;
    ReferenceShamirMpc mpc(
        rank,world_size,(world_size-1)/3);
    ReferenceShamirResidualMpcBackend backend(store,mpc,exchange);

    ReferencePrivateOwnerSelectionResult rejected;
    Digest rejected_binding{};
    // Missing activation and missing challenge are refused before networking.
    if(backend.LocalizeActivatedPrivateOwner(
            scope,local_view,{}, {},rank,world_size,
            &rejected,&rejected_binding) ||
       rejected.available || rejected_binding!=Digest{})
        return false;
    // The test runner pins a local root prior to VSS activation. Production
    // callers must obtain this pin from an independently trusted native
    // source; the fixture alone is NOT that trust boundary.
    const char* negative_flag=std::getenv("PVIA_P105_BAD_SOURCE_PIN");
    const bool bad_pin_case=negative_flag &&
        std::string(negative_flag)=="1";
    const auto environment_enabled=[](const char* key){
        const char* value=std::getenv(key);
        return value && std::string(value)=="1";
    };
    const bool bad_view_case=environment_enabled(
        "PVIA_P105_CORRUPT_SOURCE_VIEW_ROOT");
    const bool missing_pin_case=environment_enabled(
        "PVIA_P105_MISSING_SOURCE_PIN");
    LocalResidualBatchView activation_view=local_view;
    Digest pinned_local_root=local_view.commitment_root;
    if(bad_pin_case && rank==0)
        pinned_local_root=hash_words({
            SELFTEST_SCOPE_DOMAIN,sid,checkpoint,0x42414450494eULL});
    if(bad_view_case && rank==0) {
        activation_view.commitment_root=hash_words({
            SELFTEST_SCOPE_DOMAIN,sid,checkpoint,0x56494557524f4f54ULL});
        // Match the bogus root in the claimed pin: only recomputation
        // from the real handle list catches the inconsistency.
        pinned_local_root=activation_view.commitment_root;
    }
    const Digest* provided_pin=missing_pin_case
        ? nullptr : &pinned_local_root;
    // Signed source-root path uses an ephemeral, per-rank Ed25519
    // native-issuer FIXTURE. Real deployments MUST pin an external issuer
    // identity/key and native consumed-source binding before invocation.
    const char* signed_case_env=std::getenv(
        "PVIA_P105_SIGNED_SOURCE_NEGATIVE");
    const std::string signed_case=signed_case_env
        ? std::string(signed_case_env) : std::string();
    const char* missing_issuer_fixture=std::getenv(
        "PVIA_P105_CONFIGURED_ISSUER_MISSING_TEST_RANK0");
    const bool missing_configured_issuer=missing_issuer_fixture &&
        std::string(missing_issuer_fixture)=="1";
    const bool signed_negative=
        (!signed_case.empty() &&
         signed_case!="private_residual_provenance_valid") ||
        missing_configured_issuer;
    const bool uses_signed_path=!bad_pin_case && !bad_view_case &&
        !missing_pin_case;
    bool activated=false;
    if(uses_signed_path) {
        const char* issuer_key_dir=std::getenv(
            "PVIA_P105_NATIVE_ISSUER_KEY_DIR");
        const char* issuer_public_dir=std::getenv(
            "PVIA_P105_NATIVE_ISSUER_PUBLIC_KEY_DIR");
        const char* request_export_template=std::getenv(
            "PVIA_P105_NATIVE_ISSUER_REQUEST_EXPORT_TEMPLATE");
        const char* pin_receipt_template=std::getenv(
            "PVIA_P105_NATIVE_PIN_RECEIPT_TEMPLATE");
        const char* native_receipt_template=std::getenv(
            "PVIA_P105_NATIVE_EXECUTION_RECEIPT_TEMPLATE");
        const bool use_configured_key=issuer_key_dir && *issuer_key_dir;
        const bool public_only_configured=issuer_public_dir && *issuer_public_dir;
        const bool external_request_mode=
            request_export_template && *request_export_template;
        const bool external_receipt_mode=
            (pin_receipt_template && *pin_receipt_template) ||
            (native_receipt_template && *native_receipt_template);
        if((external_request_mode && external_receipt_mode) ||
           (public_only_configured && !external_request_mode &&
            !external_receipt_mode))
            return false;
        const bool external_public_mode=
            external_request_mode || external_receipt_mode;
        const bool provisioned=use_configured_key || public_only_configured ||
            external_public_mode;
        const u64 issuer_id=provisioned
            ? 0x5056494154495300ULL+static_cast<u64>(rank)+1ULL
            : 730000ULL+static_cast<u64>(rank);
        u64 issuer_sequence=provisioned?7ULL:101ULL;
        const char* issuer_sequence_env=std::getenv(
            "PVIA_P105_NATIVE_ISSUER_SEQUENCE");
        if(issuer_sequence_env && *issuer_sequence_env) {
            for(const char* p=issuer_sequence_env; *p; ++p)
                if(*p<'0' || *p>'9') return false;
            char* end=nullptr;
            errno=0;
            const unsigned long long parsed=std::strtoull(
                issuer_sequence_env,&end,10);
            if(errno!=0 || end==issuer_sequence_env || !end ||
               *end!=0 || parsed==0)
                return false;
            issuer_sequence=static_cast<u64>(parsed);
        }
        Digest native_source{};
        // Synthetic pre-VSS *claim* using the actual canonical registration
        // statement codec. The data values remain a fixture; they are not
        // asserted to be the native coPIOP's consumed state.
        RegistrationConsistencyStatement registration_claim;
        registration_claim.sid=sid;
        registration_claim.checkpoint=checkpoint;
        registration_claim.ref={
            static_cast<uint32_t>(rank),
            910000ULL+static_cast<u64>(rank)*100ULL};
        registration_claim.kernel=AuditRelationKernel::FOLD_RS;
        registration_claim.state_element_count=2;
        registration_claim.output_element_count=1;
        registration_claim.public_state_digest=
            hash_field_vector({F(13),F(13)});
        const bool native_first_faulty=rank==0 && mode=="first";
        const F native_output=(F(1)-F(7))*F(13)+
            (native_first_faulty?F(7):F(0));
        registration_claim.public_actual_digest=
            hash_field_vector({native_output});
        registration_claim.public_challenge_binding=hash_field_vector({F(7)});
        registration_claim.native_context.native_state_id=
            94000ULL+static_cast<u64>(rank)*10ULL;
        registration_claim.native_context.authentication_scheme_id=
            SELFTEST_AUTH_SCHEME;
        registration_claim.native_context.authentication_binding=hash_words({
            SELFTEST_SCOPE_DOMAIN,sid,checkpoint,0x4e41544956454155ULL});
        registration_claim.native_context.predecessor_root=hash_words({
            SELFTEST_SCOPE_DOMAIN,sid,checkpoint,0x5052454445434553ULL});
        registration_claim.native_context.checkpoint_root=scope.checkpoint_root;
        const PrivateResidualShare* native_residual_share=
            store.Find(registration_claim.ref);
        if(!native_residual_share)return false;
        registration_claim.operation_statement_binding=
            native_residual_share->operation_statement_binding;
        registration_claim.sharing_transcript_binding=hash_words({
            SELFTEST_SCOPE_DOMAIN,sid,checkpoint,
            static_cast<u64>(rank),0x53484152494e4721ULL});
        registration_claim.statement_binding=
            compute_registration_consistency_statement_binding(
                registration_claim);
        const auto canonical_pre_vss=
            registration_pre_vss_claim_words(registration_claim);
        if(canonical_pre_vss.size()!=38)return false;
        const Digest pre_vss_claim=hash_words(canonical_pre_vss);
        // Use the EXISTING canonical native-record readers rather than
        // creating a synthetic RegistrationNativeConsumedSnapshot by hand.
        AuditCheckpointView native_checkpoint;
        native_checkpoint.id=checkpoint;
        native_checkpoint.root=scope.checkpoint_root;
        native_checkpoint.sealed=true;
        native_checkpoint.operations.push_back(registration_claim.ref);
        AuditStateView native_state;
        native_state.id=registration_claim.native_context.native_state_id;
        native_state.label.sid=sid;
        native_state.label.owner=static_cast<uint32_t>(rank);
        native_state.digest=registration_claim.public_state_digest;
        PrivateStateMaterialStore native_state_store;
        if(!native_state_store.BindPrivateState(
                native_state,{F(13),F(13)}) ||
           !native_state_store.BindAuthentication(
                native_state,
                registration_claim.native_context.authentication_scheme_id,
                registration_claim.native_context.authentication_binding))
            return false;
        AuditOperationView native_operation;
        native_operation.ref=registration_claim.ref;
        native_operation.label.sid=sid;
        native_operation.label.owner=static_cast<uint32_t>(rank);
        native_operation.label.object_id=registration_claim.ref.object_id;
        native_operation.label.phase=Phase::FOLD;
        native_operation.label.obligation=Obligation::FOLD;
        native_operation.relation=RelationKind::FOLDING;
        native_operation.kernel=AuditRelationKernel::FOLD_RS;
        native_operation.checkpoint=checkpoint;
        native_operation.active=true;
        native_operation.actual=registration_claim.public_actual_digest;
        native_operation.relation_statement=
            registration_claim.operation_statement_binding;
        native_operation.predecessor_root=
            registration_claim.native_context.predecessor_root;
        native_operation.state_dependency_count=1;
        native_operation.state_dependency_root=compute_state_dependency_root({
            StateDependencyEvidence{static_cast<uint32_t>(rank),
                registration_claim.native_context.native_state_id,
                registration_claim.public_state_digest}});
        native_operation.public_aux_count=1;
        native_operation.public_aux_root=compute_public_aux_root({
            PublicAuxEvidence{AuditPublicAuxKind::FOLD_CHALLENGE,
                registration_claim.public_challenge_binding}});
        PrivateAuditMaterialStore native_operation_store;
        native_operation_store.RegisterOperation(native_operation);
        native_operation_store.BindPrivateField(native_operation,
            AuditPrivatePayloadKind::FIELD_VECTOR,
            AuditPayloadStage::ACTIVATE_OUTPUT,{native_output});
        native_operation_store.BindStateDependencies(native_operation,{
            registration_claim.native_context.native_state_id});
        native_operation_store.BindPublicFieldAux(native_operation,
            AuditPublicAuxKind::FOLD_CHALLENGE,{F(7)});
        native_operation_store.MarkFinalized(registration_claim.ref);
        // Register all other local candidate slots in the same finalized
        // native store. The first operation still supplies the signed
        // registration claim; the signed owner root covers every handle.
        for(int pos=1;pos<my_slots;++pos) {
            const OperationRef ref{
                static_cast<uint32_t>(rank),
                910000ULL+static_cast<u64>(rank)*100ULL+
                    static_cast<u64>(pos)};
            const auto* residual=store.Find(ref);
            if(!residual)return false;
            const bool slot_faulty=rank==0 &&
                ((mode=="middle" && pos==1) ||
                 (mode=="last" && pos==2));
            AuditStateView next_state=native_state;
            next_state.id=residual->source_state_id;
            next_state.digest=residual->source_state_digest;
            if(!native_state_store.BindPrivateState(
                    next_state,{F(13),F(13)}) ||
               !native_state_store.BindAuthentication(
                    next_state,SELFTEST_AUTH_SCHEME,
                    residual->source_state_authentication_binding))
                return false;
            AuditOperationView next_operation=native_operation;
            next_operation.ref=ref;
            next_operation.label.object_id=ref.object_id;
            next_operation.actual=residual->actual;
            next_operation.relation_statement=
                residual->operation_statement_binding;
            next_operation.public_aux_root=residual->public_aux_root;
            next_operation.state_dependency_root=
                compute_state_dependency_root({
                    StateDependencyEvidence{
                        static_cast<uint32_t>(rank),next_state.id,
                        next_state.digest}});
            native_checkpoint.operations.push_back(ref);
            native_operation_store.RegisterOperation(next_operation);
            native_operation_store.BindPrivateField(next_operation,
                AuditPrivatePayloadKind::FIELD_VECTOR,
                AuditPayloadStage::ACTIVATE_OUTPUT,
                {(F(1)-F(7))*F(13)+(slot_faulty?F(7):F(0))});
            native_operation_store.BindStateDependencies(
                next_operation,{next_state.id});
            native_operation_store.BindPublicFieldAux(
                next_operation,AuditPublicAuxKind::FOLD_CHALLENGE,{F(7)});
            native_operation_store.MarkFinalized(ref);
        }
        RegistrationNativeStoreSourceProvider native_source_provider(
            native_state_store,native_operation_store,native_checkpoint);
        RegistrationNativeConsumedSnapshot captured;
        if(!native_source_provider.capture(registration_claim,&captured) ||
           captured.pre_vss_claim_binding!=pre_vss_claim ||
           !native_source_provider.still_matches(registration_claim,captured))
            return false;
        native_source=captured.consumed_record_binding;
        EVP_PKEY* issuer_key=nullptr;
        std::array<uint8_t,32> issuer_public{};
        bool generated=false;
        if(external_public_mode) {
            // The verifier opens only public pins; receipt signatures are
            // supplied by the separate signer process.
            generated=public_only_configured &&
                LoadReferenceNativeIssuerPublicKey(
                    issuer_public_dir,rank,&issuer_public);
        }else if(use_configured_key) {
            // Legacy configured mode signs inside the reference fixture.
            generated=LoadReferenceNativeIssuerSigningKey(
                issuer_key_dir,rank,&issuer_key,&issuer_public);
        }else{
            EVP_PKEY_CTX* keygen=
                EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519,nullptr);
            generated=keygen && EVP_PKEY_keygen_init(keygen)==1 &&
                EVP_PKEY_keygen(keygen,&issuer_key)==1 && issuer_key;
            EVP_PKEY_CTX_free(keygen);
            if(generated){
                size_t public_length=issuer_public.size();
                generated=EVP_PKEY_get_raw_public_key(
                    issuer_key,issuer_public.data(),&public_length)==1 &&
                    public_length==issuer_public.size();
            }
        }
        // An invalid local provisioned key must enter the same
        // collective activation readiness check as other ranks.
        // Signing failure becomes an invalid zero-signature receipt.
        const char* missing_test=std::getenv(
            "PVIA_P105_CONFIGURED_ISSUER_MISSING_TEST_RANK0");
        if(provisioned && rank==0 && missing_test &&
           std::string(missing_test)=="1"){
            generated=false;
            EVP_PKEY_free(issuer_key);
            issuer_key=nullptr;
            issuer_public={};
        }
        if(!generated && !provisioned){
            EVP_PKEY_free(issuer_key);
            return false;
        }
        const bool public_ok=generated && issuer_key;
        // Positive strict-gate fixture: the same issuer key/sequence signs
        // the per-share computation receipt and the source-pin receipt. Update
        // the private handle root before the source pin is constructed.
        if(signed_case=="private_residual_provenance_valid") {
            bool local_provenance_ok=false;
            PrivateResidualShare* share=store.Find(registration_claim.ref);
            if(public_ok && share && share->computation_binding==
                    compute_private_residual_computation_binding(*share)) {
                PrivateResidualProvenanceReceipt provenance{};
                provenance.issuer_id=issuer_id;
                provenance.sequence=issuer_sequence;
                provenance.scheme_id=
                    share->source_state_authentication_scheme_id;
                provenance.computation_binding=share->computation_binding;
                const auto message=
                    private_residual_provenance_signing_message(provenance);
                EVP_MD_CTX* provenance_ctx=EVP_MD_CTX_new();
                size_t provenance_sig_len=provenance.signature.size();
                const bool provenance_signed=!message.empty() &&
                    provenance_ctx && issuer_key &&
                    EVP_DigestSignInit(provenance_ctx,nullptr,nullptr,nullptr,
                                       issuer_key)==1 &&
                    EVP_DigestSign(provenance_ctx,provenance.signature.data(),
                        &provenance_sig_len,message.data(),message.size())==1 &&
                    provenance_sig_len==provenance.signature.size();
                EVP_MD_CTX_free(provenance_ctx);
                Ed25519PrivateResidualShareAuthenticator provenance_verifier(
                    provenance.scheme_id,issuer_id,issuer_sequence,
                    issuer_public,{provenance});
                PrivateResidualAuthenticationArtifact artifact{};
                local_provenance_ok=provenance_signed &&
                    provenance_verifier.Authenticate(*share,&artifact);
                if(local_provenance_ok) {
                    share->authentication=artifact;
                    share->authentication_binding=artifact.binding;
                    share->authenticated=true;
                    share->commitment=
                        compute_private_residual_share_commitment(*share);
                    local_provenance_ok=validate_private_residual_share(*share);
                }
                if(local_provenance_ok) {
                    const PrivateResidualHandle* old_handle=
                        registry.Find(share->ref);
                    if(old_handle) {
                        PrivateResidualHandle updated=*old_handle;
                        updated.commitment=share->commitment;
                        updated.authenticated=true;
                        registry.Put(updated);
                    } else {
                        local_provenance_ok=false;
                    }
                }
            }
            int local_ok=local_provenance_ok?1:0;
            int all_ok=0;
            MPI_Allreduce(&local_ok,&all_ok,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
            if(!all_ok) {
                EVP_PKEY_free(issuer_key);
                return false;
            }
            local_view=registry.BuildLocalBatchView(
                scope,static_cast<uint32_t>(rank));
            activation_view=local_view;
            pinned_local_root=local_view.commitment_root;
        }
        ResidualNativeSourcePinReceipt issuer_receipt;
        issuer_receipt.issuer_id=issuer_id;
        issuer_receipt.sequence=issuer_sequence;
        issuer_receipt.sid=sid;
        issuer_receipt.checkpoint=checkpoint;
        issuer_receipt.owner=static_cast<uint32_t>(rank);
        issuer_receipt.scope_binding=compute_collective_scope_binding(scope);
        issuer_receipt.local_residual_root=local_view.commitment_root;
        issuer_receipt.native_consumed_record_binding=native_source;
        issuer_receipt.registration_pre_vss_claim_binding=pre_vss_claim;
        const auto signed_bytes=
            residual_native_source_pin_signing_message(issuer_receipt);
        EVP_MD_CTX* signctx=EVP_MD_CTX_new();
        size_t siglen=issuer_receipt.signature.size();
        const bool signed_ok=public_ok && !signed_bytes.empty() &&
            signctx && issuer_key &&
            EVP_DigestSignInit(
                signctx,nullptr,nullptr,nullptr,issuer_key)==1 &&
            EVP_DigestSign(signctx,issuer_receipt.signature.data(),&siglen,
                           signed_bytes.data(),signed_bytes.size())==1 &&
            siglen==issuer_receipt.signature.size();
        EVP_MD_CTX_free(signctx);
        if(!signed_ok && !provisioned) {
            EVP_PKEY_free(issuer_key);
            return false;
        }
        RegistrationNativeExecutionReceipt native_receipt;
        native_receipt.issuer_id=issuer_id;
        native_receipt.sequence=issuer_sequence;
        native_receipt.pre_vss_claim_binding=pre_vss_claim;
        native_receipt.consumed_record_binding=native_source;
        const auto native_bytes=registration_native_execution_receipt_message(
            registration_claim,issuer_id,issuer_sequence,
            pre_vss_claim,native_source);
        if(external_request_mode) {
            std::string request_path;
            const char* executor_key_dir=std::getenv(
                "PVIA_P105_NATIVE_EXECUTOR_KEY_DIR");
            EVP_PKEY* executor_key=nullptr;
            std::array<uint8_t,32> executor_public{};
            const bool executor_key_ok=executor_key_dir && *executor_key_dir &&
                LoadReferenceNativeExecutorSigningKey(
                    executor_key_dir,rank,&executor_key,&executor_public);
            // The exported source record is accepted only if the exact local
            // stores still match the snapshot immediately before attestation.
            // This closes the capture-to-export gap on the reference path.
            const char* request_drift_env=std::getenv(
                "PVIA_P105_EXTERNAL_REQUEST_DRIFT");
            if(request_drift_env && *request_drift_env && rank==0) {
                const std::string drift(request_drift_env);
                if(drift=="state") {
                    auto* value=native_state_store.Find(
                        registration_claim.native_context.native_state_id);
                    if(value && !value->local_share.empty())
                        value->local_share[0]+=F(1);
                } else if(drift=="output") {
                    auto* value=native_operation_store.Find(registration_claim.ref);
                    if(value && !value->field_output.empty())
                        value->field_output[0]+=F(1);
                } else if(drift=="challenge") {
                    auto* value=native_operation_store.Find(registration_claim.ref);
                    if(value && !value->field_aux.empty() &&
                       !value->field_aux.front().second.empty())
                        value->field_aux.front().second[0]+=F(1);
                } else if(drift=="checkpoint") {
                    native_checkpoint.root=hash_words({
                        SELFTEST_SCOPE_DOMAIN,sid,checkpoint,
                        0x4558504f52544452ULL});
                } else {
                    // Unknown test-hook values fail closed.
                    captured.consumed_record_binding=Digest{};
                }
            }
            const bool source_still_matches=
                native_source_provider.still_matches(
                    registration_claim,captured);
            if(rank==0)
                std::cout<<"PVIA_P105_EXTERNAL_SOURCE_RECHECK: "
                         <<(source_still_matches?"PASS":"FAIL")<<std::endl;
            const auto executor_message=
                registration_native_execution_attestation_message(
                    registration_claim,captured,native_checkpoint,
                    issuer_receipt.scope_binding,
                    issuer_receipt.local_residual_root);
            std::array<uint8_t,64> executor_signature{};
            EVP_MD_CTX* executor_sign_ctx=EVP_MD_CTX_new();
            size_t executor_signature_size=executor_signature.size();
            const bool executor_signed=source_still_matches &&
                executor_key_ok && !executor_message.empty() && executor_sign_ctx &&
                EVP_DigestSignInit(executor_sign_ctx,nullptr,nullptr,nullptr,
                                   executor_key)==1 &&
                EVP_DigestSign(executor_sign_ctx,executor_signature.data(),
                    &executor_signature_size,executor_message.data(),
                    executor_message.size())==1 &&
                executor_signature_size==executor_signature.size();
            EVP_MD_CTX_free(executor_sign_ctx);
            EVP_PKEY_free(executor_key);
            const bool wrote=executor_signed &&
                p105_rank_path(request_export_template,rank,&request_path) &&
                p105_write_private_request(
                    request_path,issuer_receipt,native_bytes,signed_bytes,
                    registration_claim,captured,native_checkpoint,
                    executor_message,executor_signature);
            const int local_request_ok=wrote?1:0;
            int all_requests_ok=0;
            MPI_Allreduce(&local_request_ok,&all_requests_ok,
                          1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
            if(rank==0)
                std::cout<<"PVIA_P105_EXTERNAL_ISSUER_REQUEST: "
                         <<(all_requests_ok?"PASS":"FAIL")
                         <<" rank_count="<<world_size<<std::endl;
            return all_requests_ok!=0;
        }
        EVP_MD_CTX* native_signctx=EVP_MD_CTX_new();
        size_t native_sig_len=native_receipt.signature.size();
        const bool native_signed=!native_bytes.empty() && native_signctx &&
            issuer_key && EVP_DigestSignInit(
                native_signctx,nullptr,nullptr,nullptr,issuer_key)==1 &&
            EVP_DigestSign(
                native_signctx,native_receipt.signature.data(),
                &native_sig_len,native_bytes.data(),native_bytes.size())==1 &&
            native_sig_len==native_receipt.signature.size();
        EVP_MD_CTX_free(native_signctx);
        EVP_PKEY_free(issuer_key);
        if((!native_signed ||
           !verify_registration_native_execution_receipt_public(
                registration_claim,native_receipt,native_source,
                issuer_public,issuer_id,issuer_sequence)) &&
           !provisioned)
            return false;
        if(external_receipt_mode) {
            ResidualNativeSourcePinReceipt external_pin{};
            RegistrationNativeExecutionReceipt external_native{};
            std::string pin_path,native_path;
            const bool paths_ok=
                p105_rank_path(pin_receipt_template,rank,&pin_path) &&
                p105_rank_path(native_receipt_template,rank,&native_path);
            const bool pin_loaded=paths_ok &&
                read_residual_native_source_pin_receipt_file(
                    pin_path,&external_pin);
            const bool native_loaded=paths_ok &&
                read_registration_native_issuer_public_file(
                    native_path,&external_native);
            if(pin_loaded)issuer_receipt=external_pin;
            else issuer_receipt.signature.fill(0);
            if(native_loaded)native_receipt=external_native;
            else native_receipt.signature.fill(0);
        }

        Digest expected_native=native_source;
        Digest expected_claim=pre_vss_claim;
        u64 minimum_seq=issuer_sequence;
        if(rank==0) {
            if(signed_case=="signature")
                issuer_receipt.signature[0]^=0x80;
            else if(signed_case=="issuer_key")
                issuer_public[0]^=0x40;
            else if(signed_case=="native_record")
                expected_native=hash_words({
                    SELFTEST_SCOPE_DOMAIN,sid,checkpoint,
                    0x4241444e41544956ULL});
            else if(signed_case=="pre_vss_claim")
                expected_claim=hash_words({
                    SELFTEST_SCOPE_DOMAIN,sid,checkpoint,
                    0x4241445052455653ULL});
            else if(signed_case=="wrong_checkpoint")
                ++issuer_receipt.checkpoint;
            else if(signed_case=="scope_binding")
                issuer_receipt.scope_binding=hash_words({
                    SELFTEST_SCOPE_DOMAIN,sid,checkpoint,
                    0x42414453434f5045ULL});
            else if(signed_case=="local_residual_root")
                issuer_receipt.local_residual_root=hash_words({
                    SELFTEST_SCOPE_DOMAIN,sid,checkpoint,
                    0x424144524f4f54ULL});
            else if(signed_case=="wrong_session")
                ++issuer_receipt.sid;
            else if(signed_case=="stale_sequence")
                ++minimum_seq;
            else if(signed_case=="native_execution_signature")
                native_receipt.signature[4]^=0x20;
            else if(signed_case=="native_execution_sequence")
                --native_receipt.sequence;
            else if(signed_case=="native_execution_claim")
                registration_claim.operation_statement_binding=hash_words({
                    SELFTEST_SCOPE_DOMAIN,sid,checkpoint,
                    0x4f5448455253544dULL});
            else if(signed_case=="snapshot_record")
                captured.consumed_record_binding=hash_words({
                    SELFTEST_SCOPE_DOMAIN,sid,checkpoint,0x424144534e4150ULL});
            else if(signed_case=="snapshot_claim")
                captured.pre_vss_claim_binding=hash_words({
                    SELFTEST_SCOPE_DOMAIN,sid,checkpoint,0x424144435041ULL});
            else if(signed_case=="snapshot_output")
                captured.actual_output={F(22)};
            else if(signed_case=="snapshot_challenge")
                captured.public_challenge=F(8);
            else if(signed_case=="snapshot_empty")
                captured.state_values.clear();
            else if(signed_case=="live_state_drift")
                native_state_store.Find(
                    registration_claim.native_context.native_state_id)
                    ->local_share[0]+=F(1);
            else if(signed_case=="live_output_drift")
                native_operation_store.Find(registration_claim.ref)
                    ->field_output[0]+=F(1);
            else if(signed_case=="live_challenge_drift")
                native_operation_store.Find(registration_claim.ref)
                    ->field_aux.front().second[0]+=F(1);
            else if(signed_case=="live_checkpoint_drift")
                native_checkpoint.root=hash_words({
                    SELFTEST_SCOPE_DOMAIN,sid,checkpoint,
                    0x4c495645434850ULL});
        }
        // The isolated test runner provisions per-rank, owner-only
        // persistent directories before spawning MPI ranks.
        std::unique_ptr<RegistrationReceiptReplayLedger> native_replay;
        const char* replay_template=std::getenv(
            "PVIA_P105_NATIVE_REPLAY_DIR_TEMPLATE");
        if(replay_template && *replay_template) {
            std::string replay_dir(replay_template);
            const auto at=replay_dir.find("{rank}");
            if(at==std::string::npos)return false;
            replay_dir.replace(at,6,std::to_string(rank));
            native_replay.reset(new RegistrationReceiptReplayLedger(
                replay_dir));
            if(rank==0 && (signed_case=="replay_duplicate" ||
                           signed_case=="replay_different_session")) {
                ResidualNativeSourcePinReceipt preseed=issuer_receipt;
                if(signed_case=="replay_different_session")
                    preseed.sid+=99999; // local ledger mechanics only
                if(!native_replay->ConsumeNativeSourcePinOnce(preseed))
                    return false;
            }
        }
        // A missing/mismatched externally provisioned test key follows
        // the same authenticated all-rank preflight (not an early exit).
        // Its receipt and externally pinned public key stay invalid.
        // First validate the expected pre-VSS binding policy without
        // broadcasting either signed receipt. Invalid local policy is
        // consumed by the joint readiness round, never a local early exit.
        const bool claim_policy_ok=expected_claim==pre_vss_claim;
        const Digest effective_expected_native=claim_policy_ok
            ? expected_native : Digest{};
        // Reference fixture carries an independently supplied expected
        // native digest; the snapshot supplies the actual local state.
        // An incorrect expected digest must also reject collectively.
        if(expected_native!=native_source ||
           effective_expected_native==Digest{})
            captured.consumed_record_binding=Digest{};
        activated=backend.ActivateResidualsWithLiveNativeSnapshot(
            scope,activation_view,rank,world_size,
            issuer_receipt,registration_claim,native_receipt,
            captured,native_source_provider,native_state_store,
            native_operation_store,native_checkpoint,
            issuer_public,issuer_id,minimum_seq,
            true,true,native_replay.get(),
            signed_case=="private_residual_provenance_missing" ||
            signed_case=="private_residual_provenance_valid");
        // Reopen the same owner-local ledger after a successful release.
        // A reused signed issuer sequence must remain rejected.
        if(activated && native_replay && !signed_negative) {
            const RegistrationReceiptReplayLedger reopened(
                std::string(replay_template).replace(
                    std::string(replay_template).find("{rank}"),6,
                    std::to_string(rank)));
            if(reopened.ConsumeNativeSourcePinOnce(issuer_receipt))
                return false;
        }
    } else {
        activated=backend.ActivateResiduals(
            scope,activation_view,rank,world_size,true,provided_pin);
    }
    if(bad_pin_case || bad_view_case || missing_pin_case ||
       signed_negative) {
        const int mine=(!activated &&
            !backend.HasActivatedResiduals(scope) &&
            !backend.private_owner_activation_mode())?1:0;
        int total=0;
        MPI_Allreduce(&mine,&total,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
        if(rank==0)
            std::cout<<"PVIA_ACTIVATED_PRIVATE_BAD_SOURCE_PIN"
                     <<" result="<<(total?"PASS":"FAIL")
                     <<" activation=REJECTED_ALL_RANKS"
                     <<" failure_kind="<<(signed_negative?
                         "SIGNED_ISSUER_POLICY":
                         bad_pin_case?"PIN_MISMATCH":
                         bad_view_case?"ROOT_RECOMPUTATION":"MISSING_PIN")
                     <<" visible_raw_source=NO"<<std::endl;
        return total!=0;
    }
    if(!activated ||
       !backend.HasActivatedVssProvenance(scope) ||
       !backend.private_owner_activation_mode() ||
       !backend.PrivateOwnerActivationMetadataRedacted(scope) ||
       backend.activation_binding()==Digest{})
        return false;
    store.Clear();
    if(store.size()!=0 || !backend.HasActivatedVssProvenance(scope))
        return false;

    const ExperimentMetricsSnapshot before=experiment_metrics_snapshot();
    const CollectiveBatchDescriptor desc=
        backend.PrivateOwnerPublicBatchDescriptor(
            scope,local_view,rank,world_size);
    const CollectiveBatchDescriptor leaked_desc=
        make_collective_batch_descriptor(
            scope,local_view,rank,world_size);
    // This local check is safe: no participant sends the raw descriptor.
    if(desc.local_commitment_root==Digest{} ||
       desc.descriptor_digest==Digest{} ||
       leaked_desc.local_commitment_root==
           desc.local_commitment_root)return false;
    // A legacy descriptor would publicly commit to private source values:
    // the privacy mode refuses it collectively, not just at the API docs.
    const CollectiveResidualCommitmentSet rejected_public=
        backend.CommitResidualBatch(
            scope,leaked_desc,local_view,rank,world_size);
    if(rejected_public.available ||
       rejected_public.cryptographically_authenticated)
        return false;
    const CollectiveResidualCommitmentSet commitments=
        backend.CommitResidualBatch(
            scope,desc,local_view,rank,world_size);
    if(!validate_participant_commitment_set(
            scope,desc,commitments,world_size))
        return false;
    const AuthenticatedChallengeTranscript challenge=
        backend.DeriveJointChallenge(
            scope,desc,commitments,rank,world_size);
    if(!validate_challenge_transcript(
            scope,commitments,challenge,world_size))
        return false;
    // In the private mode, no old public zero-bit, subset or operation
    // release API is permitted to bypass the protected selector.
    if(backend.RandomLinearBatchCheck(
           scope,desc,local_view,commitments,challenge,
           rank,world_size).available ||
       backend.CheckResidualSubset(
           scope,{}, {},local_view,rank,world_size).available ||
       backend.FinalizeLocalization(
           scope,{},scope.operations.front(),Digest{},
           local_view,rank,world_size).available)
        return false;
    const Digest activation=backend.activation_binding();
    const auto changed_challenge=[&] {
        auto mutated=challenge;
        mutated.challenge=hash_words({
            SELFTEST_SCOPE_DOMAIN,sid,checkpoint,
            0x5056313035424144ULL});
        return mutated;
    }();
    if(backend.LocalizeActivatedPrivateOwner(
            scope,local_view,commitments,changed_challenge,
            rank,world_size,&rejected,&rejected_binding) ||
       rejected.available || rejected_binding!=Digest{})
        return false;
    // Exercise the full privacy-mode API once. The API runs the selector
    // internally, so the selftest does not separately invoke the expensive
    // selection circuit and accidentally double the protocol rounds.
    MpcBackedAuthenticatedResidualProtocol private_mode_protocol(
        backend,RobustAuditSecurityLevel::REFERENCE_PASSIVE);
    ProtocolBackedCollectiveResidualEngine private_mode_engine(
        private_mode_protocol);
    const auto private_audit=private_mode_engine.AuditObliviously(
        scope,local_view,rank,world_size);
    const bool positive=private_audit.available &&
        private_audit.found && private_audit.attributed_party==0;
    const bool empty=private_audit.available && !private_audit.found;
    const bool local_ok=rank==0
        ? (mode=="none"?empty:positive)
        : (positive||empty);
    // Only rank 0 receives the private fixture mode. Other ranks must not
    // infer "no fault" from their local placeholder mode.
    const bool private_audit_expected=local_ok;
    MpcBackedAuthenticatedResidualProtocol default_security_protocol(backend);
    MpcBackedAuthenticatedResidualProtocol god_security_protocol(
        backend,RobustAuditSecurityLevel::MALICIOUS_GOD);
    const auto default_audit=default_security_protocol.AuditObliviously(
        scope,local_view,rank,world_size);
    const auto god_audit=god_security_protocol.AuditObliviously(
        scope,local_view,rank,world_size);
    const bool private_checks_ok=
        local_ok && private_audit.available &&
        private_audit.cryptographically_authenticated &&
        private_audit.reference_only &&
        private_audit.checkpoint==scope.checkpoint &&
        private_audit.batch_result_binding!=Digest{} &&
        private_audit.public_evidence_binding!=Digest{} &&
        private_audit_expected &&
        !default_security_protocol.SupportsObliviousAudit(scope) &&
        !default_audit.available &&
        !god_security_protocol.SupportsObliviousAudit(scope) &&
        !god_audit.available;
    const char* trace_env=std::getenv("PVIA_P105_OBLIVIOUS_AUDIT_TRACE");
    if(trace_env && std::string(trace_env)!="0") {
        // MPI may merge rank stderr streams. Emit each short diagnostic in
        // one write so concurrent ranks cannot interleave fields mid-line.
        std::ostringstream trace;
        trace<<"[PVIA][oblivious-audit-trace] rank="<<rank
             <<" available="<<private_audit.available
             <<" found="<<private_audit.found
             <<" owner="<<private_audit.attributed_party
             <<" local_ok="<<local_ok
             <<" expected="<<private_audit_expected
             <<" authenticated="<<private_audit.cryptographically_authenticated
             <<" reference_only="<<private_audit.reference_only
             <<" batch_binding="<<(private_audit.batch_result_binding!=Digest{})
             <<" evidence_binding="<<(private_audit.public_evidence_binding!=Digest{})
             <<" default_available="<<default_audit.available
             <<" god_available="<<god_audit.available
             <<" checks_ok="<<private_checks_ok<<'\n';
        const std::string trace_line=trace.str();
        (void)::write(STDERR_FILENO,trace_line.data(),trace_line.size());
    }
    // Do not let a local selftest failure return while other ranks enter
    // the later MPI_Gather/Allreduce; all ranks agree on the result first.
    const int local_checks=private_checks_ok?1:0;
    int all_checks=0;
    MPI_Allreduce(&local_checks,&all_checks,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
    if(!all_checks)return false;
    // Public TEST-ONLY diagnostic negative control. An extra authenticated
    // collective across every rank must change the structural trace, while
    // preserving the same selected owner. It is not a hidden-data branch.
    const char* shape_delta_env=std::getenv("PVIA_P105_PUBLIC_SHAPE_DELTA");
    const bool public_shape_delta=shape_delta_env &&
        std::string(shape_delta_env)=="1";
    if(public_shape_delta) {
        AuthenticatedMpcMessageContext delta_context;
        delta_context.protocol_domain=0x505631303544454cULL; // PV105DEL
        delta_context.sid=sid;
        delta_context.checkpoint=checkpoint;
        delta_context.round=55;
        delta_context.sequence=1;
        delta_context.message_kind=0x5056313035544354ULL;
        std::vector<u64> delta_out;
        if(!exchange.AllGatherWords(
            delta_context,{static_cast<u64>(rank)+1},
            &delta_out) ||
           delta_out.size()!=static_cast<size_t>(world_size))
            return false;
    }
    // Exact per-receiver authenticated-envelope SHAPE audit. Both hashes
    // exclude the SID, cryptographic payload/signature and any private q*.
    // Full structural records include protocol domain, checkpoint, round,
    // sequence, message kind, sender, receiver and payload word length.
    AuthenticatedMpcEnvelopeShapeTrace local_shape;
    AuthenticatedMpcEnvelopeShapeTrace not_this_session;
    const bool shape_ok=exchange.ExportVerifiedEnvelopeShapeTrace(
        sid,checkpoint,&local_shape) &&
        local_shape.available && local_shape.verified_messages>0 &&
        local_shape.arrival_order_binding!=Digest{} &&
        local_shape.canonical_multiset_binding!=Digest{} &&
        !exchange.ExportVerifiedEnvelopeShapeTrace(
            sid+98765ULL,checkpoint,&not_this_session) &&
        !not_this_session.available;
    uint64_t shape_words[9]={};
    if(shape_ok) {
        shape_words[0]=local_shape.verified_messages;
        std::memcpy(&shape_words[1],
            local_shape.arrival_order_binding.bytes.data(),32);
        std::memcpy(&shape_words[5],
            local_shape.canonical_multiset_binding.bytes.data(),32);
    }
    std::vector<uint64_t> all_shapes(
        rank==0?static_cast<size_t>(world_size)*9:0);
    MPI_Gather(shape_words,9,MPI_UINT64_T,
               rank==0?all_shapes.data():nullptr,9,MPI_UINT64_T,
               0,MPI_COMM_WORLD);
    Digest global_order_shape{};
    Digest global_canonical_shape{};
    uint64_t total_shape_messages=0;
    if(rank==0) {
        constexpr u64 GLOBAL_SHAPE_DOMAIN=0x5056313035475354ULL;
        std::vector<u64> ordering={GLOBAL_SHAPE_DOMAIN,1,
                                   static_cast<u64>(world_size)};
        std::vector<u64> canonical={GLOBAL_SHAPE_DOMAIN,2,
                                    static_cast<u64>(world_size)};
        for(int peer=0;peer<world_size;++peer) {
            const size_t offset=static_cast<size_t>(peer)*9;
            const u64 n=all_shapes[offset];
            total_shape_messages+=n;
            ordering.push_back(n);
            canonical.push_back(n);
            ordering.insert(ordering.end(),
                all_shapes.begin()+offset+1,
                all_shapes.begin()+offset+5);
            canonical.insert(canonical.end(),
                all_shapes.begin()+offset+5,
                all_shapes.begin()+offset+9);
        }
        global_order_shape=hash_words(ordering);
        global_canonical_shape=hash_words(canonical);
    }
    const auto digest_hex=[](const Digest& value) {
        constexpr char hex[]="0123456789abcdef";
        std::string out;
        out.reserve(value.bytes.size()*2);
        for(uint8_t byte:value.bytes) {
            out.push_back(hex[byte>>4]);
            out.push_back(hex[byte&15]);
        }
        return out;
    };
    const ExperimentMetricsSnapshot after=experiment_metrics_snapshot();
    const uint64_t sent[4]={
        after.authenticated_envelope_sent_bytes-
            before.authenticated_envelope_sent_bytes,
        after.authenticated_envelope_sent_messages-
            before.authenticated_envelope_sent_messages,
        after.protocol_control_sent_bytes-
            before.protocol_control_sent_bytes,
        after.protocol_control_sent_messages-
            before.protocol_control_sent_messages};
    uint64_t totals[4]={};
    MPI_Reduce(sent,totals,4,MPI_UINT64_T,
               MPI_SUM,0,MPI_COMM_WORLD);
    backend.ClearActivatedResiduals();
    rejected={};
    rejected_binding={};
    const bool stale_rejected=
        !backend.LocalizeActivatedPrivateOwner(
            scope,local_view,commitments,challenge,
            rank,world_size,&rejected,&rejected_binding) &&
        !rejected.available && rejected_binding==Digest{};
    const int local=(local_ok && stale_rejected && shape_ok)?1:0;
    int all=0;
    MPI_Allreduce(&local,&all,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
    if(rank==0) {
        std::cout<<"PVIA_ACTIVATED_PRIVATE_OWNER"
                 <<" result="<<(all?"PASS":"FAIL")
                 <<" public_owner="<<(mode=="none"?"NONE":"0")
                 <<" operations="<<scope.operations.size()
                 <<" selector_multiplications="
                     <<3*scope.operations.size()-2
                 <<" vss_activation=BEFORE_STORE_ERASURE"
                 <<" store_erased=YES"
                 <<" commitment_challenge=BOUND"
                 <<" metadata_redacted=YES"
                 <<" independent_local_root=PIN_CHECKED"
                 <<" native_issuer_receipt=ED25519_CHECKED"
                 <<" native_source_pin=ED25519_CHECKED"
                 <<" native_issuer_pair=SAME_ISSUER_SEQUENCE"
                 <<" issuer_key_provisioning="
                 <<((std::getenv("PVIA_P105_NATIVE_PIN_RECEIPT_TEMPLATE") ||
                     std::getenv("PVIA_P105_NATIVE_EXECUTION_RECEIPT_TEMPLATE"))
                    ?"EXTERNAL_SIGNED_RECEIPT":
                    (std::getenv("PVIA_P105_NATIVE_ISSUER_KEY_DIR") &&
                     *std::getenv("PVIA_P105_NATIVE_ISSUER_KEY_DIR"))
                    ?"CONFIGURED_TEST_KEY":"EPHEMERAL_TEST_KEY")
                 <<" captured_native_snapshot=CHECKED"
                 <<" native_store_reread=VERIFIED"
                 <<" native_fold_residual=COORDINATES_CHECKED"
                 <<" all_native_candidates=CHECKED"
                 <<" native_issuer_replay=SINGLE_USE_CHECKED"
                 <<" public_root=PUBLIC_LAYOUT_ONLY"
                 <<" stale_activation=REJECTED"
                 <<" auth_bytes="<<totals[0]
                 <<" auth_messages="<<totals[1]
                 <<" control_bytes="<<totals[2]
                 <<" control_messages="<<totals[3]
                 <<" shape_observed_envelopes="<<total_shape_messages
                 <<" canonical_shape="<<digest_hex(global_canonical_shape)
                 <<" arrival_shape="<<digest_hex(global_order_shape)
                 <<" shape_scope=PER_PARTY_VERIFIED_ENVELOPES"
                 <<" source=ACTIVATED_REFERENCE_RESIDUAL"
                 <<" formal_P105=NOT_ESTABLISHED"
                 <<std::endl;
        std::cout<<"[PVIA][oblivious-audit-api] result="
                 <<(all!=0?"PASS":"FAIL")
                 <<" reference_only=true public_output=OWNER_OR_NONE"
                 <<" operation_identifier=HIDDEN"
                 <<" malicious_security=NOT_CLAIMED"
                 <<std::endl;
    }
    return all!=0;
}

bool run_reference_rs_multiplication_selftest(int rank, int world_size) {
    if (world_size < 4 || world_size > 128) return false;
    const int threshold = (world_size - 1) / 3;
    if (3 * threshold >= world_size) return false;
    AuthenticatedMpcExchange exchange(rank, world_size);
    if (!exchange.production_authenticated_ready()) return false;
    ReferenceShamirMpc mpc(rank, world_size, threshold);
    if (!mpc.SetAuthenticatedTransport(&exchange, 552000, 1))
        return false;
    const auto share_input = [&](F value, std::vector<F>* shares) {
        const std::vector<F> plaintext =
            rank == 0 ? std::vector<F>{value} : std::vector<F>{};
        return mpc.ShareVectorFromDealerKnownSize(
            0, plaintext, 1, shares) && shares->size() == 1;
    };
    std::vector<F> lhs, rhs;
    if (!share_input(F(7), &lhs) ||
        !share_input(F(11), &rhs))
        return false;
    F product(0);
    Digest product_binding{};
    const char* old_selftest = std::getenv("PVIA_REFERENCE_RS_MUL_SELFTEST");
    const std::string saved_selftest = old_selftest ? old_selftest : "";
    setenv("PVIA_REFERENCE_RS_MUL_SELFTEST", "1", 1);
    const bool multiplied = mpc.Multiply(
        lhs.front(), rhs.front(), &product, &product_binding);
    if (old_selftest)
        setenv("PVIA_REFERENCE_RS_MUL_SELFTEST", saved_selftest.c_str(), 1);
    else
        unsetenv("PVIA_REFERENCE_RS_MUL_SELFTEST");
    const bool fault = std::getenv("PVIA_TEST_RS_MUL_FAULT_DEALER") &&
        std::strcmp(std::getenv("PVIA_TEST_RS_MUL_FAULT_DEALER"), "1") == 0;
    bool local_pass = false;
    if (fault) {
        local_pass = !multiplied;
    } else if (multiplied && product_binding != Digest{}) {
        F opened(0);
        Digest opening_binding{};
        local_pass = mpc.Open(product, &opened, &opening_binding) &&
            opening_binding != Digest{} && opened == F(77);
    }
    int local = local_pass ? 1 : 0, global = 0;
    MPI_Allreduce(&local, &global, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    if (rank == 0)
        std::cout << "[PVIA][rs-product-selftest] mode="
                  << (fault ? "corrupt-dealer" : "clean")
                  << " multiplication=" << (fault ? "REJECTED" :
                      (multiplied ? "ACCEPTED" : "FAILED"))
                  << " output=" << (fault ? "WITHHELD" :
                      (local_pass ? "77" : "INVALID"))
                  << " security_scope=VSS_RS_PRODUCT_CONSISTENCY_ONLY"
                  << " result=" << (global ? "PASS" : "FAIL")
                  << std::endl;
    return global != 0;
}

// Builds the strong multiplication path with local VSS provenance. A
// deliberately corrupted local product causes its own proof preflight to
// fail; the rank is recovered from the sender-signed status envelope, not
// copied from the test fault-injection setting.
bool run_reference_rs_multiplication_strong_selftest(
    int rank, int world_size, bool inject_fault,
    ReferenceMultiplicationFailureCertificate* output_certificate,
    std::vector<u64>* output_encoded_certificate) {
    if ((inject_fault &&
         (!output_certificate || !output_encoded_certificate)) ||
        world_size < 4 || world_size > 128 ||
        rank < 0 || rank >= world_size)
        return false;
    if (output_certificate)
        *output_certificate = ReferenceMultiplicationFailureCertificate{};
    if (output_encoded_certificate)
        output_encoded_certificate->clear();
    auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.ExternalRegistryAnchorVerified() ||
        auth.ExternalRegistryAnchor() != auth.RegistryCommitment())
        return false;

    AuthenticatedMpcExchange exchange(rank, world_size);
    if (!exchange.production_authenticated_ready()) return false;
    const int threshold = (world_size - 1) / 3;
    const uint64_t sid = inject_fault ? 552100ULL : 552099ULL;
    const CheckpointId checkpoint = inject_fault
        ? 0x0000000000010001ULL : 0x0000000000010000ULL;
    const uint64_t multiplication_id = inject_fault
        ? 0x52534d554c000001ULL : 0x52534d554c000000ULL;
    ReferenceBivariateVss vss(rank, world_size, threshold);
    if (!vss.valid()) return false;

    auto share_input = [&](F value, u64 message_kind,
                           std::vector<F>* shares,
                           ReferenceVssReceipt* receipt,
                           ReferenceVssLocalWitness* witness) -> bool {
        const std::vector<F> plaintext =
            rank == 0 ? std::vector<F>{value} : std::vector<F>{};
        AuthenticatedMpcMessageContext context;
        context.protocol_domain =
            REFERENCE_MULTIPLICATION_FAILURE_PROTOCOL_DOMAIN;
        context.sid = sid;
        context.checkpoint = checkpoint;
        context.round = multiplication_id;
        context.sequence = message_kind;
        context.message_kind = message_kind;
        return vss.ShareVectorFromDealerAuthenticated(
            0, plaintext, shares, receipt, exchange, context,
            nullptr, witness) && shares->size() == 1 &&
            receipt->available && receipt->consistent &&
            receipt->transcript_binding != Digest{} &&
            witness->available &&
            witness->transcript_binding == receipt->transcript_binding;
    };

    std::vector<F> lhs, rhs;
    ReferenceVssReceipt lhs_receipt, rhs_receipt;
    ReferenceVssLocalWitness lhs_witness, rhs_witness;
    if (!share_input(F(7), 0x4d554c494e4c4853ULL,
                     &lhs, &lhs_receipt, &lhs_witness) ||
        !share_input(F(11), 0x4d554c494e524853ULL,
                     &rhs, &rhs_receipt, &rhs_witness))
        return false;

    ReferenceMultiplicationConsistencyContext context;
    context.sid = sid;
    context.checkpoint = checkpoint;
    context.multiplication_id = multiplication_id;
    context.lhs_sharing_binding = lhs_receipt.transcript_binding;
    context.rhs_sharing_binding = rhs_receipt.transcript_binding;
    context.context_binding = hash_words({
        0x52534d554c435458ULL, sid, checkpoint, multiplication_id,
        static_cast<u64>(world_size), static_cast<u64>(threshold)});

    ReferenceMultiplicationConsistencyLocalWitness local_witness;
    local_witness.lhs_sharing_witness_words =
        encode_reference_vss_local_witness(lhs_witness);
    local_witness.rhs_sharing_witness_words =
        encode_reference_vss_local_witness(rhs_witness);
    if (local_witness.lhs_sharing_witness_words.empty() ||
        local_witness.rhs_sharing_witness_words.empty())
        return false;

    SelfTestMultiplicationConsistencyBackend proof_backend;
    ReferenceShamirMpc mpc(rank, world_size, threshold);
    if (!mpc.SetAuthenticatedTransport(&exchange, sid, checkpoint) ||
        !mpc.SetMultiplicationConsistencyProofBackend(&proof_backend))
        return false;

    const char* old_rs = std::getenv("PVIA_RS_MUL_SYNDROME");
    const char* old_selftest = std::getenv("PVIA_REFERENCE_RS_MUL_SELFTEST");
    const char* old_fault = std::getenv("PVIA_TEST_RS_MUL_FAULT_DEALER");
    const std::string saved_rs = old_rs ? old_rs : "";
    const std::string saved_selftest = old_selftest ? old_selftest : "";
    const std::string saved_fault = old_fault ? old_fault : "";
    setenv("PVIA_RS_MUL_SYNDROME", "1", 1);
    setenv("PVIA_REFERENCE_RS_MUL_SELFTEST", "1", 1);
    setenv("PVIA_TEST_RS_MUL_FAULT_DEALER",
           inject_fault ? "1" : "0", 1);

    F product(0);
    Digest product_binding{};
    std::vector<ReferenceMultiplicationFailureCertificate> certificates;
    std::vector<std::vector<u64>> encoded_certificates;
    const bool multiplied = mpc.MultiplyWithConsistency(
        lhs.front(), rhs.front(), context, local_witness,
        &product, &product_binding, &certificates, &encoded_certificates);

    if (old_rs) setenv("PVIA_RS_MUL_SYNDROME", saved_rs.c_str(), 1);
    else unsetenv("PVIA_RS_MUL_SYNDROME");
    if (old_selftest)
        setenv("PVIA_REFERENCE_RS_MUL_SELFTEST", saved_selftest.c_str(), 1);
    else unsetenv("PVIA_REFERENCE_RS_MUL_SELFTEST");
    if (old_fault)
        setenv("PVIA_TEST_RS_MUL_FAULT_DEALER", saved_fault.c_str(), 1);
    else unsetenv("PVIA_TEST_RS_MUL_FAULT_DEALER");

    if (!inject_fault) {
        F opened(0);
        Digest opening_binding{};
        bool clean_ok = multiplied && certificates.empty() &&
            encoded_certificates.empty() && product_binding != Digest{} &&
            mpc.Open(product, &opened, &opening_binding) &&
            opening_binding != Digest{} && opened == F(77);
        int clean_local = clean_ok ? 1 : 0, clean_global = 0;
        MPI_Allreduce(&clean_local, &clean_global, 1, MPI_INT, MPI_MIN,
                      MPI_COMM_WORLD);
        if (rank == 0)
            std::cout << "[PVIA][rs-product-strong-clean] result="
                      << (clean_global ? "PASS" : "FAIL")
                      << " output=" << (clean_global ? "77" : "WITHHELD")
                      << std::endl;
        return clean_global != 0;
    }

    bool valid = !multiplied && certificates.size() == 1 &&
        encoded_certificates.size() == 1;
    std::vector<u64> encoded_certificate_words;
    if (valid) {
        *output_certificate = certificates.front();
        encoded_certificate_words = encoded_certificates.front();
        ReferenceMultiplicationFailureCertificate decoded_certificate;
        valid = !encoded_certificate_words.empty() &&
            PublicJudge::VerifyMultiplicationFailureCertificate(
                *output_certificate, auth.PublicKeys(),
                auth.ExternalRegistryAnchor()) &&
            PublicJudge::VerifyMultiplicationFailureCertificate(
                encoded_certificate_words, auth.PublicKeys(),
                auth.ExternalRegistryAnchor()) &&
            decode_reference_multiplication_failure_certificate(
                encoded_certificate_words, &decoded_certificate) &&
            PublicJudge::VerifyMultiplicationFailureCertificate(
                decoded_certificate, auth.PublicKeys(),
                auth.ExternalRegistryAnchor()) &&
            encode_reference_multiplication_failure_certificate(
                decoded_certificate) == encoded_certificate_words;
        if (valid) *output_certificate = decoded_certificate;
    }
    if (valid) {
        auto wrong_anchor = hash_words({0x52534d554c424144ULL});
        valid = !PublicJudge::VerifyMultiplicationFailureCertificate(
            *output_certificate, auth.PublicKeys(), wrong_anchor);
    }
    if (valid) {
        auto tampered = *output_certificate;
        tampered.status_payloads[tampered.accused_dealer][8] = 0;
        tampered.certificate_binding =
            compute_reference_multiplication_failure_certificate_binding(
                tampered);
        valid = !PublicJudge::VerifyMultiplicationFailureCertificate(
            tampered, auth.PublicKeys(), auth.ExternalRegistryAnchor());
    }
    if (valid) {
        auto reframed = *output_certificate;
        reframed.accused_dealer =
            (reframed.accused_dealer + 1) % static_cast<uint32_t>(world_size);
        reframed.certificate_binding =
            compute_reference_multiplication_failure_certificate_binding(
                reframed);
        valid = !PublicJudge::VerifyMultiplicationFailureCertificate(
            reframed, auth.PublicKeys(), auth.ExternalRegistryAnchor());
    }
    // Recompute the unkeyed outer bindings after each mutation so these
    // negative checks exercise the actual Ed25519/context/roster verifier,
    // rather than merely detecting a stale local digest.
    if (valid) {
        auto bad_signature = *output_certificate;
        auto& observation =
            bad_signature.status_observations[bad_signature.accused_dealer];
        observation.signature[0] ^= 0x01;
        observation.observation_binding =
            compute_authenticated_mpc_signed_envelope_observation_binding(
                observation);
        bad_signature.certificate_binding =
            compute_reference_multiplication_failure_certificate_binding(
                bad_signature);
        valid = !PublicJudge::VerifyMultiplicationFailureCertificate(
            bad_signature, auth.PublicKeys(), auth.ExternalRegistryAnchor());
    }
    if (valid) {
        auto missing_ack = *output_certificate;
        missing_ack.status_payloads.pop_back();
        missing_ack.status_observations.pop_back();
        missing_ack.certificate_binding =
            compute_reference_multiplication_failure_certificate_binding(
                missing_ack);
        valid = !PublicJudge::VerifyMultiplicationFailureCertificate(
            missing_ack, auth.PublicKeys(), auth.ExternalRegistryAnchor());
    }
    if (valid) {
        auto duplicate_sender = *output_certificate;
        duplicate_sender.status_payloads[1] =
            duplicate_sender.status_payloads[0];
        duplicate_sender.status_observations[1] =
            duplicate_sender.status_observations[0];
        duplicate_sender.certificate_binding =
            compute_reference_multiplication_failure_certificate_binding(
                duplicate_sender);
        valid = !PublicJudge::VerifyMultiplicationFailureCertificate(
            duplicate_sender, auth.PublicKeys(), auth.ExternalRegistryAnchor());
    }
    if (valid) {
        auto tampered_event = *output_certificate;
        tampered_event.event.syndrome =
            tampered_event.event.syndrome + F(1);
        tampered_event.event.event_binding =
            compute_reference_multiplication_rs_event_binding(
                tampered_event.event);
        tampered_event.certificate_binding =
            compute_reference_multiplication_failure_certificate_binding(
                tampered_event);
        valid = !PublicJudge::VerifyMultiplicationFailureCertificate(
            tampered_event, auth.PublicKeys(), auth.ExternalRegistryAnchor());
    }
    if (valid) {
        auto truncated = encoded_certificate_words;
        truncated.pop_back();
        ReferenceMultiplicationFailureCertificate decoded;
        valid = !decode_reference_multiplication_failure_certificate(
            truncated, &decoded) &&
            !PublicJudge::VerifyMultiplicationFailureCertificate(
                truncated, auth.PublicKeys(), auth.ExternalRegistryAnchor());
    }
    if (valid) {
        auto trailing = encoded_certificate_words;
        trailing.push_back(0);
        ReferenceMultiplicationFailureCertificate decoded;
        valid = !decode_reference_multiplication_failure_certificate(
            trailing, &decoded) &&
            !PublicJudge::VerifyMultiplicationFailureCertificate(
                trailing, auth.PublicKeys(), auth.ExternalRegistryAnchor());
    }
    if (valid) {
        auto wrong_magic = encoded_certificate_words;
        wrong_magic[0] ^= 1;
        ReferenceMultiplicationFailureCertificate decoded;
        valid = !decode_reference_multiplication_failure_certificate(
            wrong_magic, &decoded) &&
            !PublicJudge::VerifyMultiplicationFailureCertificate(
                wrong_magic, auth.PublicKeys(), auth.ExternalRegistryAnchor());
    }

    int local = valid ? 1 : 0, global = 0;
    MPI_Allreduce(&local, &global, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    if (rank == 0) {
        std::cout << "[PVIA][rs-product-public-failure] result="
                  << (global ? "PASS" : "FAIL")
                  << " accused="
                  << (certificates.size() == 1
                      ? certificates.front().accused_dealer : 9999)
                  << " source=verified-signed-preflight-report"
                  << " event=collectively-signed-nonzero-rs-syndrome"
                  << " semantics=SELF_REPORTED_PROTOCOL_FAILURE"
                  << " signature_tamper=REJECTED"
                  << " missing_ack=REJECTED"
                  << " duplicate_sender=REJECTED"
                  << " event_tamper=REJECTED"
                  << " codec_roundtrip=PASS"
                  << " public_judge_encoded=PASS"
                  << " codec_truncated=REJECTED"
                  << " codec_trailing=REJECTED"
                  << " codec_bad_magic=REJECTED"
                  << " product_inequality_zk=NOT_ESTABLISHED"
                  << std::endl;
    }
    if (global && output_encoded_certificate)
        *output_encoded_certificate = encoded_certificate_words;
    return global != 0;
}

// N=4 bridge from the PublicJudge-verified multiplication-failure
// certificate into the existing signed GOD survivor-output recovery protocol.
// The excluded process remains alive; this is verified survivor-group recovery,
// not a process-crash/ULFM claim.
bool run_reference_rs_god_survivor_recovery_n4(
    int rank, int world_size, uint32_t excluded_rank,
    const std::vector<u64>& encoded_failure_certificate,
    int* survivor_count) {
    if (!survivor_count || world_size != 4 || rank < 0 || rank >= 4)
        return false;
    *survivor_count = 0;
    auto& auth = Ed25519TransferAuthenticator::instance();
    ReferenceMultiplicationFailureCertificate failure;
    bool local_ready =
        decode_reference_multiplication_failure_certificate(
            encoded_failure_certificate, &failure) &&
        auth.ready() && auth.ExternalRegistryAnchorVerified() &&
        auth.ExternalRegistryAnchor() == auth.RegistryCommitment() &&
        PublicJudge::VerifyMultiplicationFailureCertificate(
            encoded_failure_certificate, auth.PublicKeys(),
            auth.ExternalRegistryAnchor()) &&
        failure.accused_dealer == excluded_rank &&
        failure.event.world_size == 4 &&
        failure.event.sid == 552100ULL &&
        failure.event.checkpoint == 0x0000000000010001ULL;
    int local = local_ready ? 1 : 0, agreed = 0;
    MPI_Allreduce(&local, &agreed, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    if (!agreed) return false;

    constexpr uint64_t sid = 552100ULL;
    constexpr CheckpointId checkpoint = 0x0000000000010001ULL;
    constexpr u64 god_domain = 0x5056474f444e3431ULL; // PVGODN41
    constexpr u64 god_scope_domain = 0x5056474f44534350ULL; // PVGODSCP
    constexpr u64 god_crash_share_domain = 0x5056474f44435348ULL;
    ReferenceBivariateVss vss(rank, 4, 1);
    AuthenticatedMpcExchange exchange(rank, 4);
    local_ready = vss.valid() && exchange.production_authenticated_ready();
    local = local_ready ? 1 : 0;
    MPI_Allreduce(&local, &agreed, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    if (!agreed) return false;

    AuthenticatedMpcMessageContext vss_context;
    vss_context.protocol_domain = god_domain;
    vss_context.sid = sid;
    vss_context.checkpoint = checkpoint;
    vss_context.round = 9101ULL;
    vss_context.sequence = 9101ULL;
    vss_context.message_kind = 0x56535301ULL;
    std::vector<F> local_shares;
    ReferenceVssReceipt vss_receipt;
    const std::vector<F> secret = rank == 0
        ? std::vector<F>{F(77)} : std::vector<F>{};
    const bool vss_ready = vss.ShareVectorFromDealerAuthenticated(
        0, secret, &local_shares, &vss_receipt, exchange, vss_context) &&
        local_shares.size() == 1 && vss_receipt.available &&
        vss_receipt.consistent && vss_receipt.world_size == 4 &&
        vss_receipt.threshold == 1 &&
        vss_receipt.transcript_binding != Digest{};
    local = vss_ready ? 1 : 0;
    MPI_Allreduce(&local, &agreed, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    if (!agreed) return false;

    const Digest scope = hash_words({
        god_scope_domain, sid, 4ULL, 1ULL});
    AuthenticatedMpcMessageContext recovery_context;
    recovery_context.protocol_domain = god_domain;
    recovery_context.sid = sid;
    recovery_context.checkpoint = checkpoint;
    recovery_context.round = 9201ULL;
    recovery_context.sequence = 9201ULL;
    recovery_context.message_kind = god_crash_share_domain;
    std::vector<int> active_original_ranks;
    for (int original = 0; original < 4; ++original)
        if (original != static_cast<int>(excluded_rank))
            active_original_ranks.push_back(original);

    MPI_Comm active_comm = MPI_COMM_NULL;
    const int split_rc = MPI_Comm_split(
        MPI_COMM_WORLD, rank == static_cast<int>(excluded_rank)
            ? MPI_UNDEFINED : 1, rank, &active_comm);
    local_ready = split_rc == MPI_SUCCESS &&
        (rank == static_cast<int>(excluded_rank)
            ? active_comm == MPI_COMM_NULL
            : active_comm != MPI_COMM_NULL);
    local = local_ready ? 1 : 0;
    MPI_Allreduce(&local, &agreed, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    if (!agreed) {
        if (active_comm != MPI_COMM_NULL) MPI_Comm_free(&active_comm);
        return false;
    }

    ReferenceGodMultiplicationFailureRecovery recovery;
    bool survivor_ok = true;
    if (rank != static_cast<int>(excluded_rank)) {
        survivor_ok =
            open_reference_god_output_after_verified_multiplication_failure_n4(
                rank, 4, active_original_ranks, local_shares, scope,
                recovery_context, vss_receipt, active_comm,
                encoded_failure_certificate, auth.PublicKeys(),
                auth.ExternalRegistryAnchor(), &recovery, nullptr) &&
            recovery.available &&
            recovery.excluded_original_rank == excluded_rank &&
            recovery.survivor_output.values == std::vector<F>{F(77)} &&
            !recovery.survivor_output.process_crash_tolerant &&
            recovery.survivor_output.survivor_certificate.active_original_ranks ==
                active_original_ranks &&
            verify_reference_god_multiplication_failure_recovery(
                recovery, auth.PublicKeys(), auth.ExternalRegistryAnchor());
        bool recovery_wrong_anchor_rejected = false;
        bool recovery_wrong_roster_rejected = false;
        bool recovery_link_tamper_rejected = false;
        bool recovery_output_tamper_rejected = false;
        bool recovery_codec_roundtrip = false;
        bool recovery_codec_truncated_rejected = false;
        bool recovery_codec_trailing_rejected = false;
        bool recovery_codec_bad_magic_rejected = false;
        if (survivor_ok) {
            ReferenceGodMultiplicationFailureRecovery rejected;
            const Digest wrong_anchor = hash_words({
                god_domain, 0x424144414e43484fULL});
            recovery_wrong_anchor_rejected =
                !open_reference_god_output_after_verified_multiplication_failure_n4(
                    rank, 4, active_original_ranks, local_shares, scope,
                    recovery_context, vss_receipt, active_comm,
                    encoded_failure_certificate, auth.PublicKeys(),
                    wrong_anchor, &rejected, nullptr);
            std::vector<int> wrong_roster = active_original_ranks;
            wrong_roster[0] = static_cast<int>(excluded_rank);
            recovery_wrong_roster_rejected =
                !open_reference_god_output_after_verified_multiplication_failure_n4(
                    rank, 4, wrong_roster, local_shares, scope,
                    recovery_context, vss_receipt, active_comm,
                    encoded_failure_certificate, auth.PublicKeys(),
                    auth.ExternalRegistryAnchor(), &rejected, nullptr);
            auto bad_link = recovery;
            bad_link.excluded_original_rank =
                (excluded_rank + 1U) % 4U;
            bad_link.recovery_binding =
                compute_reference_god_multiplication_failure_recovery_binding(
                    bad_link);
            recovery_link_tamper_rejected =
                !verify_reference_god_multiplication_failure_recovery(
                    bad_link, auth.PublicKeys(), auth.ExternalRegistryAnchor());
            auto bad_output = recovery;
            bad_output.survivor_output.values[0] += F(1);
            bad_output.recovery_binding =
                compute_reference_god_multiplication_failure_recovery_binding(
                    bad_output);
            recovery_output_tamper_rejected =
                !verify_reference_god_multiplication_failure_recovery(
                    bad_output, auth.PublicKeys(), auth.ExternalRegistryAnchor());

            const std::vector<u64> encoded_recovery =
                encode_reference_god_multiplication_failure_recovery(recovery);
            ReferenceGodMultiplicationFailureRecovery decoded_recovery;
            recovery_codec_roundtrip = !encoded_recovery.empty() &&
                decode_reference_god_multiplication_failure_recovery(
                    encoded_recovery, &decoded_recovery) &&
                verify_reference_god_multiplication_failure_recovery(
                    decoded_recovery, auth.PublicKeys(),
                    auth.ExternalRegistryAnchor()) &&
                !decoded_recovery.survivor_output.process_crash_tolerant &&
                verify_encoded_reference_god_multiplication_failure_recovery(
                    encoded_recovery, auth.PublicKeys(),
                    auth.ExternalRegistryAnchor()) &&
                encode_reference_god_multiplication_failure_recovery(
                    decoded_recovery) == encoded_recovery;
            if (!encoded_recovery.empty()) {
                auto truncated_recovery = encoded_recovery;
                truncated_recovery.pop_back();
                ReferenceGodMultiplicationFailureRecovery malformed;
                recovery_codec_truncated_rejected =
                    !decode_reference_god_multiplication_failure_recovery(
                        truncated_recovery, &malformed) &&
                    !verify_encoded_reference_god_multiplication_failure_recovery(
                        truncated_recovery, auth.PublicKeys(),
                        auth.ExternalRegistryAnchor());
                auto trailing_recovery = encoded_recovery;
                trailing_recovery.push_back(0);
                recovery_codec_trailing_rejected =
                    !decode_reference_god_multiplication_failure_recovery(
                        trailing_recovery, &malformed) &&
                    !verify_encoded_reference_god_multiplication_failure_recovery(
                        trailing_recovery, auth.PublicKeys(),
                        auth.ExternalRegistryAnchor());
                auto bad_magic_recovery = encoded_recovery;
                bad_magic_recovery[0] ^= 1ULL;
                recovery_codec_bad_magic_rejected =
                    !decode_reference_god_multiplication_failure_recovery(
                        bad_magic_recovery, &malformed) &&
                    !verify_encoded_reference_god_multiplication_failure_recovery(
                        bad_magic_recovery, auth.PublicKeys(),
                        auth.ExternalRegistryAnchor());
            }
            survivor_ok = recovery_wrong_anchor_rejected &&
                recovery_wrong_roster_rejected &&
                recovery_link_tamper_rejected &&
                recovery_output_tamper_rejected &&
                recovery_codec_roundtrip &&
                recovery_codec_truncated_rejected &&
                recovery_codec_trailing_rejected &&
                recovery_codec_bad_magic_rejected;
        }
        *survivor_count = 3;
    }
    if (active_comm != MPI_COMM_NULL &&
        MPI_Comm_free(&active_comm) != MPI_SUCCESS)
        survivor_ok = false;
    local = survivor_ok ? 1 : 0;
    MPI_Allreduce(&local, &agreed, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    if (rank == 0)
        std::cout << "[PVIA][rs-god-failure-recovery] result="
                  << (agreed ? "PASS" : "FAIL")
                  << " excluded=" << excluded_rank
                  << " survivor_votes=3"
                  << " output=" << (agreed ? "77" : "WITHHELD")
                  << " multiplication_certificate=PUBLIC_JUDGE_VERIFIED"
                  << " survivor_certificate=VERIFIED"
                  << " wrong_anchor=REJECTED"
                  << " wrong_roster=REJECTED"
                  << " recovery_link_tamper=REJECTED"
                  << " recovery_output_tamper=REJECTED"
                  << " recovery_codec=PASS"
                  << " recovery_codec_truncated=REJECTED"
                  << " recovery_codec_trailing=REJECTED"
                  << " recovery_codec_bad_magic=REJECTED"
                  << " portable_crash_claim=NOT_ASSERTED"
                  << " crash_tolerance=NOT_CLAIMED"
                  << std::endl;
    if (agreed) *survivor_count = 3;
    return agreed != 0;
}

// RS-reject -> collectively signed RS-event summary -> sender-signed
// proof-preflight failure report -> PublicJudge -> signed survivor-output
// recovery. The certificate attributes a signed protocol abort report; it is
// NOT a zero-knowledge proof that the hidden product inequality is true.
bool run_reference_rs_e2e_selftest(
    Runtime& runtime, int rank, int world_size) {
    if (world_size < 4 || world_size > 128 || rank < 0 ||
        rank >= world_size || 3*((world_size-1)/3) >= world_size)
        return false;
    const char* fault = std::getenv("PVIA_TEST_RS_MUL_FAULT_DEALER");
    const char* rs_mode = std::getenv("PVIA_RS_MUL_SYNDROME");
    if (!fault || std::strcmp(fault, "1") != 0 ||
        !rs_mode || std::strcmp(rs_mode, "1") != 0 ||
        !runtime.enabled())
        return false;

    const double started = MPI_Wtime();
    const bool rs_rejected =
        run_reference_rs_multiplication_selftest(rank, world_size);
    ReferenceMultiplicationFailureCertificate rs_failure_certificate;
    std::vector<u64> rs_failure_encoded_certificate;
    const bool strong_clean =
        run_reference_rs_multiplication_strong_selftest(
            rank, world_size, false, nullptr, nullptr);
    const bool rs_failure_attributed =
        run_reference_rs_multiplication_strong_selftest(
            rank, world_size, true, &rs_failure_certificate,
            &rs_failure_encoded_certificate);
    const auto& rs_auth = Ed25519TransferAuthenticator::instance();
    ReferenceMultiplicationFailureCertificate decoded_rs_failure_certificate;
    const bool rs_certificate_publicly_verified =
        rs_failure_attributed && !rs_failure_encoded_certificate.empty() &&
        rs_auth.ready() && rs_auth.ExternalRegistryAnchorVerified() &&
        PublicJudge::VerifyMultiplicationFailureCertificate(
            rs_failure_certificate, rs_auth.PublicKeys(),
            rs_auth.ExternalRegistryAnchor()) &&
        PublicJudge::VerifyMultiplicationFailureCertificate(
            rs_failure_encoded_certificate, rs_auth.PublicKeys(),
            rs_auth.ExternalRegistryAnchor()) &&
        decode_reference_multiplication_failure_certificate(
            rs_failure_encoded_certificate, &decoded_rs_failure_certificate) &&
        PublicJudge::VerifyMultiplicationFailureCertificate(
            decoded_rs_failure_certificate, rs_auth.PublicKeys(),
            rs_auth.ExternalRegistryAnchor()) &&
        encode_reference_multiplication_failure_certificate(
            decoded_rs_failure_certificate) == rs_failure_encoded_certificate;
    const uint32_t excluded_rank = rs_certificate_publicly_verified
        ? rs_failure_certificate.accused_dealer
        : std::numeric_limits<uint32_t>::max();
    const double after_rs = MPI_Wtime();
    int local = (rs_rejected && strong_clean && rs_failure_attributed &&
                 rs_certificate_publicly_verified) ? 1 : 0, agreed = 0;
    MPI_Allreduce(&local, &agreed, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    if (!agreed) return false;
    // Separate attached-public demo checks an authenticated/anchored abort
    // certificate. It does NOT prove this RS syndrome came from rank 1.
    const bool public_abort_fixture =
        run_robust_termination_runtime_selftest(runtime, rank, world_size);
    const double after_public_fixture = MPI_Wtime();
    local = public_abort_fixture ? 1 : 0;
    MPI_Allreduce(&local, &agreed, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    if (!agreed) return false;

    // The original reference N=4 GOD fixture verifies omissions, one
    // erroneous share, and rejection of beyond-bound / stale scopes.
    // Larger n have only survivor recomputation below, not GOD.
    bool god_fixture_ok = true;
    if (world_size == 4)
        god_fixture_ok =
            run_reference_god_output_n4_selftest(rank, world_size);
    const double after_god_fixture = MPI_Wtime();
    local = god_fixture_ok ? 1 : 0;
    MPI_Allreduce(&local, &agreed, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    if (!agreed) return false;

    bool recovery_ok = true;
    int survivor_count = world_size - 1;
    if (world_size == 4) {
        recovery_ok = run_reference_rs_god_survivor_recovery_n4(
            rank, world_size, excluded_rank,
            rs_failure_encoded_certificate, &survivor_count);
    } else {
        // Larger-N runs retain the reference-only survivor recomputation.
        // N=4 uses the existing signed GOD survivor-output recovery above.
        MPI_Comm survivors = MPI_COMM_NULL;
        const int color = static_cast<uint32_t>(rank) == excluded_rank
            ? MPI_UNDEFINED : 1;
        if (MPI_Comm_split(MPI_COMM_WORLD, color, rank, &survivors) !=
            MPI_SUCCESS) return false;
        if (color != MPI_UNDEFINED) {
            int srank = -1, ssize = 0;
            if (MPI_Comm_rank(survivors, &srank) != MPI_SUCCESS ||
                MPI_Comm_size(survivors, &ssize) != MPI_SUCCESS)
                recovery_ok = false;
            survivor_count = ssize;
            if (recovery_ok) {
                ReferenceShamirMpc mpc(
                    srank, ssize, (ssize-1)/3, survivors);
                std::vector<F> lhs, rhs;
                const std::vector<F> l =
                    srank == 0 ? std::vector<F>{F(7)} : std::vector<F>{};
                const std::vector<F> r =
                    srank == 0 ? std::vector<F>{F(11)} : std::vector<F>{};
                Digest product_binding{}, opening_binding{};
                F product(0), opened(0);
                unsetenv("PVIA_RS_MUL_SYNDROME");
                recovery_ok = mpc.ShareVectorFromDealer(0, l, &lhs) &&
                    mpc.ShareVectorFromDealer(0, r, &rhs) &&
                    lhs.size() == 1 && rhs.size() == 1 &&
                    mpc.Multiply(lhs[0], rhs[0], &product,
                                 &product_binding) &&
                    product_binding != Digest{} &&
                    mpc.Open(product, &opened, &opening_binding) &&
                    opening_binding != Digest{} && opened == F(77);
                setenv("PVIA_RS_MUL_SYNDROME", "1", 1);
            }
        }
        if (survivors != MPI_COMM_NULL &&
            MPI_Comm_free(&survivors) != MPI_SUCCESS)
            recovery_ok = false;
    }
    const double after_recompute = MPI_Wtime();
    local = recovery_ok ? 1 : 0;
    MPI_Allreduce(&local, &agreed, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    if (!agreed) return false;

    double durations[4] = {
        (after_rs-started)*1000.0,
        (after_public_fixture-after_rs)*1000.0,
        (after_god_fixture-after_public_fixture)*1000.0,
        (after_recompute-after_god_fixture)*1000.0};
    double maximum[4]{};
    MPI_Allreduce(durations, maximum, 4, MPI_DOUBLE, MPI_MAX,
                  MPI_COMM_WORLD);
    if (rank == 0) {
        std::cout << "[PVIA][rs-e2e] result=PASS"
                  << " n=" << world_size
                  << " t=" << (world_size-1)/3
                  << " rs_mismatch=REJECTED"
                  << " publication=WITHHELD"
                  << " attached_public_abort_fixture=VERIFIED"
                  << " strong_clean_multiply=PASS"
                  << " rs_failure_certificate=VERIFIED"
                  << " excluded_rank=" << excluded_rank
                  << " exclusion_basis=PUBLIC_JUDGE_VERIFIED_SIGNED_REPORT"
                  << " failure_semantics=SELF_REPORTED_PROTOCOL_FAILURE"
                  << " survivor_count=" << survivor_count
                  << " survivor_recompute=PASS"
                  << " survivor_recovery="
                  << (world_size==4 ? "SIGNED_GOD_CERTIFICATE"
                                    : "REFERENCE_RECOMPUTE")
                  << " recovered_output=77"
                  << " god_n4_reference_fixture="
                  << (world_size==4 ? "PASS" : "NOT_APPLICABLE")
                  << " production_malicious_GOD=NOT_ESTABLISHED"
                  << " rs_reject_ms=" << maximum[0]
                  << " attached_public_fixture_ms=" << maximum[1]
                  << " god_fixture_ms=" << maximum[2]
                  << " survivor_recompute_ms=" << maximum[3]
                  << std::endl;
    }
    return true;
}

} // namespace pvia
