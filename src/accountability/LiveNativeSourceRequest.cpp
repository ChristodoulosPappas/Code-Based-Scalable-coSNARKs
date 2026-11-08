#include "LiveNativeSourceRequest.hpp"
#include "ReferenceNativeIssuerKeyAdapter.hpp"
#include "RegistrationNativeExecutionReceipt.hpp"
#include "RegistrationPreVssReceipt.hpp"
#include "ResidualNativeSourcePinReceipt.hpp"
#include "CollectiveResidualEngine.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <openssl/evp.h>
#include <string>
#include <unistd.h>
#include <vector>

namespace pvia {
namespace {
constexpr u64 LIVE_SOURCE_DOMAIN = 0x5056524c53524331ULL; // PVRLSRC1
constexpr u64 LIVE_SOURCE_VERSION = 2;
constexpr u64 ISSUER_ID_BASE = 0x5056494154495300ULL;

std::string hex_bytes(const uint8_t* bytes, size_t count) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(2 * count);
    for (size_t i = 0; i < count; ++i) {
        out.push_back(digits[bytes[i] >> 4]);
        out.push_back(digits[bytes[i] & 15]);
    }
    return out;
}
std::string digest_hex(const Digest& digest) {
    return hex_bytes(digest.bytes.data(), digest.bytes.size());
}
void append_u64(std::vector<uint8_t>* out, u64 word) {
    for (size_t i=0; i<8; ++i)
        out->push_back(static_cast<uint8_t>(word >> (8*i)));
}
void append_digest(std::vector<uint8_t>* out, const Digest& digest) {
    out->insert(out->end(), digest.bytes.begin(), digest.bytes.end());
}
bool write_exclusive(const std::string& path, const std::string& data) {
    if (path.empty()) return false;
    int fd=::open(path.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd<0) return false;
    size_t offset=0;
    bool ok=true;
    while (offset<data.size()) {
        const ssize_t n=::write(fd,data.data()+offset,data.size()-offset);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) {ok=false;break;}
        offset+=static_cast<size_t>(n);
    }
    if (ok) ok=::fsync(fd)==0;
    if (::close(fd)!=0) ok=false;
    if (!ok) ::unlink(path.c_str());
    return ok;
}
} // namespace

bool WriteLiveNativeSourceRequestV2(
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeConsumedSnapshot& snapshot,
    const AuditCheckpointView& checkpoint,
    const Digest& residual_computation_binding,
    const Digest& residual_commitment,
    const std::string& executor_key_directory,
    int mpi_rank, u64 issuer_sequence,
    const std::string& destination) {
    if (mpi_rank<0 || mpi_rank>=64 || issuer_sequence==0 ||
        statement.ref.owner!=static_cast<uint32_t>(mpi_rank) ||
        destination.empty() || executor_key_directory.empty() ||
        residual_computation_binding==Digest{} ||
        residual_commitment==Digest{} ||
        !checkpoint.sealed || checkpoint.id!=statement.checkpoint ||
        !validate_registration_consistency_statement(statement) ||
        compute_registration_native_consumed_record_binding(
            statement,snapshot,checkpoint)!=snapshot.consumed_record_binding)
        return false;
    const auto claim=registration_pre_vss_claim_words(statement);
    if (claim.size()!=38 ||
        hash_words(claim)!=snapshot.pre_vss_claim_binding)
        return false;
    const u64 issuer_id=ISSUER_ID_BASE+
        static_cast<u64>(mpi_rank)+1ULL;
    const auto native_message=registration_native_execution_receipt_message(
        statement,issuer_id,issuer_sequence,
        snapshot.pre_vss_claim_binding,snapshot.consumed_record_binding);
    if (native_message.empty()) return false;
    const Digest state_digest=hash_field_vector(snapshot.state_values);
    const Digest output_digest=hash_field_vector(snapshot.actual_output);
    const Digest challenge_digest=hash_field_vector({snapshot.public_challenge});
    if (state_digest!=statement.public_state_digest ||
        output_digest!=statement.public_actual_digest ||
        challenge_digest!=statement.public_challenge_binding)
        return false;
    std::vector<uint8_t> attestation;
    append_u64(&attestation,LIVE_SOURCE_DOMAIN);
    append_u64(&attestation,LIVE_SOURCE_VERSION);
    attestation.insert(attestation.end(),
                       native_message.begin(),native_message.end());
    append_digest(&attestation,state_digest);
    append_digest(&attestation,output_digest);
    append_digest(&attestation,challenge_digest);
    append_digest(&attestation,checkpoint.root);
    append_digest(&attestation,
                  statement.native_context.authentication_binding);
    append_digest(&attestation,residual_computation_binding);
    append_digest(&attestation,residual_commitment);

    EVP_PKEY* executor_key=nullptr;
    std::array<uint8_t,32> executor_public{};
    if (!LoadReferenceNativeExecutorSigningKey(
            executor_key_directory,mpi_rank,&executor_key,&executor_public))
        return false;
    std::array<uint8_t,64> signature{};
    EVP_MD_CTX* ctx=EVP_MD_CTX_new();
    size_t siglen=signature.size();
    const bool signed_ok=ctx &&
        EVP_DigestSignInit(ctx,nullptr,nullptr,nullptr,executor_key)==1 &&
        EVP_DigestSign(ctx,signature.data(),&siglen,
                       attestation.data(),attestation.size())==1 &&
        siglen==signature.size();
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(executor_key);
    if (!signed_ok) return false;
    std::vector<uint8_t> claim_bytes;
    for (u64 word: claim) append_u64(&claim_bytes,word);

    std::string content="PVIA_P105_LIVE_NATIVE_SOURCE_REQUEST_V2\n";
    const auto add=[&content](const char* key,const std::string& value) {
        content+=key; content+='='; content+=value; content+='\n';
    };
    add("source_kind","reference_live_runtime_fold");
    add("residual_authenticated","0");
    add("residual_computation_binding",digest_hex(residual_computation_binding));
    add("residual_commitment",digest_hex(residual_commitment));
    add("issuer_id",std::to_string(issuer_id));
    add("sequence",std::to_string(issuer_sequence));
    add("sid",std::to_string(statement.sid));
    add("checkpoint",std::to_string(statement.checkpoint));
    add("owner",std::to_string(statement.ref.owner));
    add("object_id",std::to_string(statement.ref.object_id));
    add("native_state_id",std::to_string(statement.native_context.native_state_id));
    add("authentication_scheme_id",
        std::to_string(statement.native_context.authentication_scheme_id));
    add("state_count",std::to_string(snapshot.state_values.size()));
    add("output_count",std::to_string(snapshot.actual_output.size()));
    add("state_digest",digest_hex(state_digest));
    add("output_digest",digest_hex(output_digest));
    add("challenge_digest",digest_hex(challenge_digest));
    add("checkpoint_root",digest_hex(checkpoint.root));
    add("native_authentication_binding",
        digest_hex(statement.native_context.authentication_binding));
    add("pre_vss_claim_binding",digest_hex(snapshot.pre_vss_claim_binding));
    add("native_consumed_record_binding",
        digest_hex(snapshot.consumed_record_binding));
    add("pre_vss_claim_words_hex",
        hex_bytes(claim_bytes.data(),claim_bytes.size()));
    add("native_execution_message_hex",
        hex_bytes(native_message.data(),native_message.size()));
    add("executor_attestation_message_hex",
        hex_bytes(attestation.data(),attestation.size()));
    add("executor_attestation_signature_hex",
        hex_bytes(signature.data(),signature.size()));
    return write_exclusive(destination,content);
}


bool BuildLiveNativeSourceOperationBinding(
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeConsumedSnapshot& snapshot,
    const AuditCheckpointView& checkpoint,
    LiveNativeSourceOperationBinding* output) {
    if (!output || !statement.sid || !statement.checkpoint ||
        statement.checkpoint != checkpoint.id || !checkpoint.sealed ||
        checkpoint.root == Digest{} || statement.ref.owner >= 64 ||
        statement.ref.object_id == 0 ||
        std::count(checkpoint.operations.begin(), checkpoint.operations.end(),
                   statement.ref) != 1 ||
        !validate_registration_consistency_statement(statement) ||
        compute_registration_native_consumed_record_binding(
            statement, snapshot, checkpoint) != snapshot.consumed_record_binding)
        return false;

    const auto claim = registration_pre_vss_claim_words(statement);
    if (claim.size() != 38 ||
        hash_words(claim) != snapshot.pre_vss_claim_binding)
        return false;
    const Digest state_digest = hash_field_vector(snapshot.state_values);
    const Digest output_digest = hash_field_vector(snapshot.actual_output);
    const Digest challenge_digest =
        hash_field_vector({snapshot.public_challenge});
    if (state_digest != statement.public_state_digest ||
        output_digest != statement.public_actual_digest ||
        challenge_digest != statement.public_challenge_binding)
        return false;

    LiveNativeSourceOperationBinding result{};
    result.ref = statement.ref;
    result.native_consumed_record_binding = snapshot.consumed_record_binding;
    result.registration_pre_vss_claim_binding = snapshot.pre_vss_claim_binding;
    if (result.native_consumed_record_binding == Digest{} ||
        result.registration_pre_vss_claim_binding == Digest{})
        return false;
    *output = result;
    return true;
}

ObligationSet BuildLiveNativeSourcePinScope(
    const RegistrationConsistencyStatement& statement,
    const AuditCheckpointView& checkpoint) {
    return BuildLiveNativeSourcePinScope(
        std::vector<RegistrationConsistencyStatement>{statement}, checkpoint);
}

ObligationSet BuildLiveNativeSourcePinScope(
    const std::vector<RegistrationConsistencyStatement>& statements,
    const AuditCheckpointView& checkpoint) {
    ObligationSet scope{};
    if (statements.empty() || !checkpoint.id || !checkpoint.sealed ||
        checkpoint.root == Digest{})
        return scope;
    const auto& first = statements.front();
    if (!first.sid || first.checkpoint != checkpoint.id ||
        first.ref.owner >= 64 || !first.ref.object_id)
        return scope;

    std::vector<OperationRef> refs;
    refs.reserve(statements.size());
    for (const auto& statement : statements) {
        if (!validate_registration_consistency_statement(statement) ||
            statement.sid != first.sid ||
            statement.checkpoint != checkpoint.id ||
            statement.ref.owner != first.ref.owner ||
            !statement.ref.object_id ||
            statement.kernel != AuditRelationKernel::FOLD_RS ||
            std::count(checkpoint.operations.begin(),
                       checkpoint.operations.end(), statement.ref) != 1)
            return ObligationSet{};
        refs.push_back(statement.ref);
    }
    std::sort(refs.begin(), refs.end(),
        [](const OperationRef& a, const OperationRef& b) {
            if (a.owner != b.owner) return a.owner < b.owner;
            return a.object_id < b.object_id;
        });
    for (size_t i = 1; i < refs.size(); ++i)
        if (refs[i - 1].owner == refs[i].owner &&
            refs[i - 1].object_id == refs[i].object_id)
            return ObligationSet{};

    scope.session_id = first.sid;
    scope.phase = checkpoint.phase;
    scope.round = checkpoint.round;
    scope.generation = checkpoint.generation;
    scope.exact_round = true;
    scope.checkpoint = checkpoint.id;
    scope.checkpoint_root = checkpoint.root;
    scope.operations = refs;
    scope.private_operations = refs;
    return scope;
}

bool WriteLiveNativeSourcePinRequestV1(
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeConsumedSnapshot& snapshot,
    const AuditCheckpointView& checkpoint,
    const Digest& local_residual_root,
    const Digest& residual_commitment,
    const std::string& executor_key_directory,
    int mpi_rank, u64 issuer_sequence,
    const std::string& destination) {
    LiveNativeSourceOperationBinding operation_binding{};
    if (mpi_rank < 0 || mpi_rank >= 64 || issuer_sequence == 0 ||
        statement.ref.owner != static_cast<uint32_t>(mpi_rank) ||
        destination.empty() || executor_key_directory.empty() ||
        local_residual_root == Digest{} || residual_commitment == Digest{} ||
        !BuildLiveNativeSourceOperationBinding(
            statement, snapshot, checkpoint, &operation_binding))
        return false;
    const auto claim = registration_pre_vss_claim_words(statement);
    if (claim.size() != 38 ||
        hash_words(claim) != snapshot.pre_vss_claim_binding)
        return false;
    const ObligationSet scope =
        BuildLiveNativeSourcePinScope(statement, checkpoint);
    const Digest scope_binding = compute_collective_scope_binding(scope);
    if (scope_binding == Digest{} || scope.operations.size() != 1 ||
        scope.operations.front() != statement.ref)
        return false;
    const Digest state_digest = hash_field_vector(snapshot.state_values);
    const Digest output_digest = hash_field_vector(snapshot.actual_output);
    const Digest challenge_digest =
        hash_field_vector({snapshot.public_challenge});
    if (state_digest != statement.public_state_digest ||
        output_digest != statement.public_actual_digest ||
        challenge_digest != statement.public_challenge_binding)
        return false;
    const auto attestation =
        registration_native_execution_attestation_message(
            statement, snapshot, checkpoint, scope_binding,
            local_residual_root);
    if (attestation.empty()) return false;

    const u64 issuer_id = ISSUER_ID_BASE +
        static_cast<u64>(mpi_rank) + 1ULL;
    EVP_PKEY* executor_key = nullptr;
    std::array<uint8_t,32> executor_public{};
    if (!LoadReferenceNativeExecutorSigningKey(
            executor_key_directory, mpi_rank,
            &executor_key, &executor_public))
        return false;
    std::array<uint8_t,64> signature{};
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    size_t siglen = signature.size();
    const bool signed_ok = ctx &&
        EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, executor_key) == 1 &&
        EVP_DigestSign(ctx, signature.data(), &siglen,
                       attestation.data(), attestation.size()) == 1 &&
        siglen == signature.size();
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(executor_key);
    if (!signed_ok) return false;

    const auto native_message = registration_native_execution_receipt_message(
        statement, issuer_id, issuer_sequence,
        snapshot.pre_vss_claim_binding,
        snapshot.consumed_record_binding);
    ResidualNativeSourcePinReceipt pin{};
    pin.issuer_id = issuer_id;
    pin.sequence = issuer_sequence;
    pin.sid = statement.sid;
    pin.checkpoint = statement.checkpoint;
    pin.owner = static_cast<uint32_t>(mpi_rank);
    pin.scope_binding = scope_binding;
    pin.local_residual_root = local_residual_root;
    pin.native_consumed_record_binding =
        operation_binding.native_consumed_record_binding;
    pin.registration_pre_vss_claim_binding =
        operation_binding.registration_pre_vss_claim_binding;
    const auto pin_message = residual_native_source_pin_signing_message(pin);
    if (native_message.empty() || pin_message.empty()) return false;

    std::vector<uint8_t> claim_bytes;
    for (u64 word : claim) append_u64(&claim_bytes, word);
    std::string content = "PVIA_P105_NATIVE_ISSUER_REQUEST_V2\n";
    const auto add = [&content](const char* key, const std::string& value) {
        content += key; content += '='; content += value; content += '\n';
    };
    add("issuer_id", std::to_string(issuer_id));
    add("sequence", std::to_string(issuer_sequence));
    add("sid", std::to_string(statement.sid));
    add("checkpoint", std::to_string(statement.checkpoint));
    add("owner", std::to_string(statement.ref.owner));
    add("scope_binding", digest_hex(scope_binding));
    add("local_residual_root", digest_hex(local_residual_root));
    add("native_consumed_record_binding",
        digest_hex(snapshot.consumed_record_binding));
    add("pre_vss_claim_binding", digest_hex(snapshot.pre_vss_claim_binding));
    add("object_id", std::to_string(statement.ref.object_id));
    add("native_state_id",
        std::to_string(statement.native_context.native_state_id));
    add("authentication_scheme_id",
        std::to_string(statement.native_context.authentication_scheme_id));
    add("state_count", std::to_string(snapshot.state_values.size()));
    add("output_count", std::to_string(snapshot.actual_output.size()));
    add("state_digest", digest_hex(state_digest));
    add("output_digest", digest_hex(output_digest));
    add("challenge_digest", digest_hex(challenge_digest));
    add("checkpoint_root", digest_hex(checkpoint.root));
    add("scope_phase", std::to_string(static_cast<u64>(scope.phase)));
    add("scope_round", std::to_string(scope.round));
    add("scope_generation", std::to_string(scope.generation));
    add("scope_exact_round", "1");
    add("relation", std::to_string(static_cast<u64>(RelationKind::FOLDING)));
    add("kernel", std::to_string(static_cast<u64>(statement.kernel)));
    add("label_obligation", std::to_string(static_cast<u64>(Obligation::FOLD)));
    add("residual_commitment", digest_hex(residual_commitment));
    add("native_authentication_binding",
        digest_hex(statement.native_context.authentication_binding));
    add("pre_vss_claim_words_hex",
        hex_bytes(claim_bytes.data(), claim_bytes.size()));
    add("executor_attestation_message_hex",
        hex_bytes(attestation.data(), attestation.size()));
    add("executor_attestation_signature_hex",
        hex_bytes(signature.data(), signature.size()));
    add("native_execution_message_hex",
        hex_bytes(native_message.data(), native_message.size()));
    add("residual_source_pin_message_hex",
        hex_bytes(pin_message.data(), pin_message.size()));
    return write_exclusive(destination, content);
}

} // namespace pvia
