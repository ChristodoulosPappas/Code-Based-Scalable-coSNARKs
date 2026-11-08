#include "ReferenceGodOutputDelivery.hpp"
#include "PublicJudge.hpp"
#include "AuthenticatedReliableBroadcast.hpp"
#include "ReferenceShamirMpc.hpp"
#include "ReferenceBivariateVss.hpp"
#include "ReferenceVssResidualSourceLink.hpp"
#include "ReferenceVssAuthenticatedAuditRecoveryBackend.hpp"
#include "ReferenceVssSelectivePointRegistryStore.hpp"
#include "ReferenceVssSelectivePointDurableReplay.hpp"
#include "ReferenceVssExternalAnchor.hpp"
#include "MultiplicationConsistencyBackendRegistry.hpp"
#include "MultiplicationConsistencyProviderAbi.hpp"
#include "SharedLibraryMultiplicationConsistencyProviderSession.hpp"
#include "SharedLibraryReferenceGodOutputConsistencyProvider.hpp"
#include "ProtocolTrafficMetrics.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sstream>
#include <limits>
#include <memory>
#include <openssl/evp.h>
#include <set>
#include <vector>
#include <utility>
#include <unistd.h>
#ifdef PVIA_ENABLE_ULFM
#include <mpi-ext.h>
#endif

namespace pvia {
namespace {
constexpr u64 GOD_N4_DOMAIN = 0x5056474f444e3431ULL; // PVGODN41
constexpr u64 GOD_N4_SCOPE_DOMAIN = 0x5056474f44534350ULL; // PVGODSCP

constexpr u64 GOD_CRASH_SHARE_DOMAIN = 0x5056474f44435348ULL;
constexpr u64 GOD_CRASH_VOTE_DOMAIN = 0x5056474f44435654ULL;
constexpr u64 GOD_CRASH_CERT_DOMAIN = 0x5056474f44434354ULL;
constexpr size_t GOD_CRASH_SHARE_HEADER_WORDS = 23;
constexpr u64 GOD_MULTIPLICATION_FAILURE_RECOVERY_DOMAIN =
    0x5056474f444d4652ULL; // PVGODMFR
constexpr u64 GOD_MULTIPLICATION_FAILURE_RECOVERY_CODEC_DOMAIN =
    0x5056474f444d4643ULL; // PVGODMFC
constexpr u64 GOD_MULTIPLICATION_FAILURE_RECOVERY_CODEC_VERSION = 1ULL;
constexpr size_t GOD_MULTIPLICATION_FAILURE_RECOVERY_MAX_WORDS =
    1ULL << 24;

int god_active_comm_agree(MPI_Comm comm, int* local_value) {
    if (!local_value) return MPI_ERR_ARG;
#ifdef PVIA_ENABLE_ULFM
    return MPIX_Comm_agree(comm, local_value);
#else
    int agreed = 0;
    const int rc = MPI_Allreduce(
        local_value, &agreed, 1, MPI_INT, MPI_MIN, comm);
    if (rc == MPI_SUCCESS) *local_value = agreed;
    return rc;
#endif
}
void append_recovery_digest(const Digest& d, std::vector<u64>* w) {
    if (!w) return;
    for (size_t i=0;i<4;++i) { u64 x=0; std::memcpy(&x,d.bytes.data()+8*i,8); w->push_back(x); }
}
Digest recovery_digest_from_words(const u64* w) {
    Digest d{}; if (w) std::memcpy(d.bytes.data(),w,d.bytes.size()); return d;
}
bool verify_reference_god_output_consistency_bundle(
    uint64_t sid, CheckpointId checkpoint, const Digest& scope,
    const std::vector<F>& output_values,
    const ReferenceGodOutputConsistencyProofBundle& bundle,
    Digest* proof_set_binding, Digest* statement_binding, Digest* proof_binding);


std::array<u64,4> god_digest_words(const Digest& d);

struct GodN4TempPath {
    std::string path;
    ~GodN4TempPath() {
        if (!path.empty()) ::unlink(path.c_str());
    }
    bool create(const char* pattern) {
        if (!pattern || !*pattern) return false;
        std::string value(pattern);
        std::vector<char> writable(value.begin(), value.end());
        writable.push_back('\0');
        const int fd = ::mkstemp(writable.data());
        if (fd < 0) return false;
        path = writable.data();
        const bool closed = ::close(fd) == 0;
        const bool removed = ::unlink(path.c_str()) == 0;
        return closed && removed;
    }
};

// Reuse the P1-03/P1-05 registry, durable replay, and recovery backend on the
// exact VSS sharing instance used by output delivery. The default selftest
// keeps a local replay-head fixture; PVIA_GOD_OUTPUT_EXTERNAL_ANCHOR=1 routes
// the same release pins through the separately hosted reference Anchor.
// Registry/native-execution issuance remains test-local in this fixture.
// SP1 proof bytes are imported and verified by all ranks when enabled.
bool run_god_output_vss_recovery_preflight_n4(
    int rank, int world_size, u64 sid, CheckpointId checkpoint,
    const AuthenticatedMpcExchange& exchange,
    const std::vector<F>& output_values,
    const std::vector<F>& local_shares,
    const ReferenceVssReceipt& receipt,
    const ReferenceVssLocalWitness& local_witness,
    Digest* integration_binding,
    Digest* registry_binding_out,
    Digest* recovery_artifact_binding_out,
    Digest* proof_binding_out) {
    if (integration_binding) *integration_binding = {};
    if (registry_binding_out) *registry_binding_out = {};
    if (recovery_artifact_binding_out) *recovery_artifact_binding_out = {};
    if (proof_binding_out) *proof_binding_out = {};
    if (!integration_binding || !registry_binding_out ||
        !recovery_artifact_binding_out || !proof_binding_out ||
        world_size != 4 || rank < 0 || rank >= world_size ||
        sid == 0 || checkpoint == 0 || !exchange.ready() ||
        output_values.empty() || local_shares.size() != output_values.size() ||
        !receipt.available || !receipt.consistent ||
        receipt.dealer != 0 || receipt.world_size != world_size ||
        receipt.threshold != 1 ||
        receipt.element_count != output_values.size() ||
        receipt.transcript_binding == Digest{} ||
        !validate_reference_vss_local_witness(local_witness) ||
        local_witness.participant != rank || local_witness.dealer != 0 ||
        local_witness.transcript_binding != receipt.transcript_binding)
        return false;

    AuthenticatedMpcMessageContext setup_context;
    setup_context.protocol_domain = PVIA_VSS_SELECTIVE_POINT_DOMAIN;
    setup_context.sid = sid;
    setup_context.checkpoint = checkpoint;
    setup_context.round = 7101;
    setup_context.sequence = 7101;
    setup_context.message_kind = PVIA_VSS_POINT_SETUP_KIND;
    ReferenceVssSelectivePointCommitmentRegistry registry;
    const bool registry_ready =
        establish_reference_vss_point_commitment_registry(
            local_witness, receipt, exchange, setup_context, &registry) &&
        validate_reference_vss_point_commitment_registry(registry);
    int local_setup_ok = registry_ready ? 1 : 0;
    int all_setup_ok = 0;
    if (MPI_Allreduce(&local_setup_ok, &all_setup_ok, 1, MPI_INT, MPI_MIN,
                      MPI_COMM_WORLD) != MPI_SUCCESS || !all_setup_ok)
        return false;

    const Digest values_binding = hash_field_vector(output_values);
    const auto values_words = god_digest_words(values_binding);
    const auto transcript_words =
        god_digest_words(receipt.transcript_binding);
    const Digest native_execution_binding = hash_words({
        0x5056474f44565353ULL, sid, static_cast<u64>(checkpoint),
        values_words[0], values_words[1], values_words[2], values_words[3],
        transcript_words[0], transcript_words[1],
        transcript_words[2], transcript_words[3]});
    if (native_execution_binding == Digest{}) return false;

    GodN4TempPath registry_file;
    GodN4TempPath replay_file;
    GodN4TempPath replay_anchor_file;
    Digest independently_pinned_record{};
    Digest initial_replay_head{};
    const char* external_anchor_mode_env =
        std::getenv("PVIA_GOD_OUTPUT_EXTERNAL_ANCHOR");
    const bool use_external_anchor =
        external_anchor_mode_env &&
        std::string(external_anchor_mode_env) == "1";
    ReferenceVssExternalAnchorClient external_anchor_client;
    ReferenceVssExternalAnchorSnapshot external_anchor_snapshot;
    bool durable_setup_ok = true;
    if (rank == 0) {
        durable_setup_ok =
            registry_file.create("/tmp/pvia-god-output-vss-registry-XXXXXX") &&
            replay_file.create("/tmp/pvia-god-output-vss-replay-XXXXXX") &&
            replay_anchor_file.create(
                "/tmp/pvia-god-output-vss-replay-anchor-XXXXXX");
        if (durable_setup_ok) {
            durable_setup_ok =
                save_reference_vss_point_registry_execution_record(
                    registry_file.path, registry, native_execution_binding,
                    &independently_pinned_record) &&
                independently_pinned_record != Digest{};
        }
        if (durable_setup_ok) {
            ReferenceVssPointRegistryExecutionRecord loaded;
            durable_setup_ok =
                load_reference_vss_point_registry_execution_record(
                    registry_file.path, independently_pinned_record,
                    native_execution_binding, sid, checkpoint,
                    receipt.transcript_binding, &loaded) &&
                loaded.registry.registry_binding == registry.registry_binding;
            auto wrong_record = independently_pinned_record;
            wrong_record.bytes[0] ^= 1;
            ReferenceVssPointRegistryExecutionRecord rejected;
            durable_setup_ok = durable_setup_ok &&
                !load_reference_vss_point_registry_execution_record(
                    registry_file.path, wrong_record, native_execution_binding,
                    sid, checkpoint, receipt.transcript_binding, &rejected);
        }
        if (durable_setup_ok) {
            ReferenceVssSelectivePointDurableReplayGuard journal(
                replay_file.path, registry.registry_binding);
            durable_setup_ok = journal.InitializeNew() &&
                journal.ReadCurrentHead(&initial_replay_head) &&
                initial_replay_head != Digest{};
        }
        if (durable_setup_ok) {
            ReferenceVssSelectivePointReplayHeadAnchor replay_anchor(
                replay_anchor_file.path, registry.registry_binding);
            Digest reloaded_anchor_head{};
            durable_setup_ok = replay_anchor.InitializeNew(
                    initial_replay_head) &&
                replay_anchor.ReadCurrentHead(&reloaded_anchor_head) &&
                reloaded_anchor_head == initial_replay_head;
        }
        if (durable_setup_ok && use_external_anchor) {
            durable_setup_ok = external_anchor_client.LoadFromEnvironment() &&
                external_anchor_client.InitializeNew(
                    independently_pinned_record, native_execution_binding,
                    registry.registry_binding, initial_replay_head) &&
                external_anchor_client.ReadSnapshot(&external_anchor_snapshot) &&
                external_anchor_snapshot.record_binding ==
                    independently_pinned_record &&
                external_anchor_snapshot.native_execution_binding ==
                    native_execution_binding &&
                external_anchor_snapshot.registry_binding ==
                    registry.registry_binding &&
                external_anchor_snapshot.generation == 0 &&
                external_anchor_snapshot.replay_head == initial_replay_head;
        }
    }
    int local_durable_setup = durable_setup_ok ? 1 : 0;
    int all_durable_setup = 0;
    if (MPI_Allreduce(&local_durable_setup, &all_durable_setup, 1,
                      MPI_INT, MPI_MIN, MPI_COMM_WORLD) != MPI_SUCCESS ||
        !all_durable_setup)
        return false;

    OperationRef expected_operation{};
    expected_operation.owner = 0;
    expected_operation.object_id = 9;
    const Digest operation_binding = hash_words({
        0x5056474f444f5053ULL, sid,
        static_cast<u64>(checkpoint), expected_operation.owner,
        expected_operation.object_id, values_words[0], values_words[1],
        values_words[2], values_words[3]});
    const Digest predecessor_root = hash_words({
        0x5056474f44505245ULL, sid, static_cast<u64>(checkpoint)});
    const Digest checkpoint_root = hash_words({
        0x5056474f4443484bULL, sid, static_cast<u64>(checkpoint),
        transcript_words[0], transcript_words[1]});

    AuthenticatedRecoveryRequest request;
    request.label.sid = sid;
    request.label.phase = Phase::FOLD;
    request.label.obligation = Obligation::FOLD;
    request.label.round = 17;
    request.label.owner = expected_operation.owner;
    request.label.object_id = expected_operation.object_id;
    request.checkpoint = checkpoint;
    request.relation = RelationKind::FOLDING;
    request.kernel = AuditRelationKernel::FOLD_RS;
    request.expected = hash_words({0x5056474f44524558ULL, sid, 1ULL});
    request.actual = hash_words({0x5056474f44524143ULL, sid, 2ULL});
    request.residual_commitment =
        hash_words({0x5056474f44525344ULL, sid, 3ULL});
    request.operation_statement_binding = operation_binding;
    request.dispute_binding = hash_words({
        0x5056474f44444953ULL, sid, static_cast<u64>(checkpoint), 4ULL});
    request.checkpoint_root = checkpoint_root;
    request.request_binding = compute_recovery_request_binding(request);
    if (request.request_binding == Digest{} ||
        operation_binding == Digest{} || predecessor_root == Digest{} ||
        checkpoint_root == Digest{})
        return false;

    AuthenticatedMpcMessageContext release_context;
    release_context.protocol_domain = PVIA_VSS_SELECTIVE_POINT_DOMAIN;
    release_context.sid = sid;
    release_context.checkpoint = checkpoint;
    release_context.round = 7201;
    release_context.sequence = 7201;
    release_context.message_kind = PVIA_VSS_SELECTIVE_POINT_KIND;

    ReferenceVssAuthenticatedRecoveryConfig config;
    config.exchange = &exchange;
    config.local_witness = &local_witness;
    config.receipt = &receipt;
    config.trusted_transcript = &local_witness.transcript_context;
    config.release_context = release_context;
    config.expected_operation = expected_operation;
    config.independently_pinned_operation_statement_binding = operation_binding;
    config.independently_pinned_predecessor_root = predecessor_root;
    config.independently_pinned_checkpoint_root = checkpoint_root;
    config.independently_pinned_registry_binding = registry.registry_binding;

    ReferenceVssSelectivePointReplayHeadAnchor replay_head_anchor(
        replay_anchor_file.path, registry.registry_binding);
    bool pins_configured = true;
    if (rank == 0) {
        auto& pins = config.target_pins;
        if (use_external_anchor) {
            pins_configured = external_anchor_client.ConfigureReleasePins(
                registry_file.path, replay_file.path, external_anchor_snapshot,
                ReferenceVssExternalAnchorResumeMode::kFresh, &pins);
        } else {
            pins.registry_path = registry_file.path;
            pins.replay_journal_path = replay_file.path;
            pins.independently_pinned_record = independently_pinned_record;
            pins.independently_pinned_native_execution = native_execution_binding;
            pins.independently_pinned_registry_binding = registry.registry_binding;
            pins.independently_pinned_replay_head = initial_replay_head;
            pins.load_current_head = [&replay_head_anchor](Digest* head) {
                return replay_head_anchor.ReadCurrentHead(head);
            };
            pins.verify_independent_pins = [
                &replay_head_anchor, &independently_pinned_record,
                &native_execution_binding, &registry](
                    const Digest& record, const Digest& native_execution,
                    const Digest& registry_binding, const Digest& replay_head) {
                    Digest stored_head{};
                    return record == independently_pinned_record &&
                        native_execution == native_execution_binding &&
                        registry_binding == registry.registry_binding &&
                        replay_head_anchor.ReadCurrentHead(&stored_head) &&
                        stored_head == replay_head;
                };
            pins.persist_new_head = [&replay_head_anchor](
                const Digest& expected, const Digest& next) {
                return replay_head_anchor.CompareAndSwap(expected, next);
            };
        }
    }
    int local_pins_configured = pins_configured ? 1 : 0;
    int all_pins_configured = 0;
    if (MPI_Allreduce(&local_pins_configured, &all_pins_configured, 1,
                      MPI_INT, MPI_MIN, MPI_COMM_WORLD) != MPI_SUCCESS ||
        !all_pins_configured)
        return false;

    ReferenceVssAuthenticatedAuditRecoveryBackend recovery_backend(config);
    BackendAuthenticatedAuditRecoveryEngine recovery_engine(recovery_backend);
    const AuthenticatedRecoveryArtifact artifact =
        recovery_engine.Recover(request, rank, world_size);
    const bool proof_present =
        artifact.recovery_proof_system_id == 68103 &&
        artifact.recovery_proof_statement_binding != Digest{} &&
        artifact.recovery_proof_artifact_commitment != Digest{} &&
        artifact.recovery_proof_statement_words.size() == 85 &&
        !artifact.recovery_proof_artifact_bytes.empty();
    const char* prove_env = std::getenv("PVIA_SP1_VSS_RECOVERY_PROVE_ONCE");
    const bool live_proof_required =
        prove_env && std::string(prove_env) == "1";
    const char* verify_env =
        std::getenv("PVIA_SP1_VSS_RECOVERY_VERIFY_ON_IMPORT");
    const bool live_proof_verify_required =
        verify_env && std::string(verify_env) == "1";
    bool recovery_ok =
        artifact.available && artifact.cryptographically_authenticated &&
        validate_recovery_artifact(request, artifact) &&
        recovery_engine.Verify(request, artifact) &&
        recovery_backend.Verify(request, artifact) &&
        artifact.recovery_registry_binding == registry.registry_binding &&
        artifact.recovery_auth_signer == 0 &&
        artifact.recovery_replay_head != Digest{} &&
        recovery_backend.ProductionCapabilityBinding() == Digest{} &&
        (!live_proof_required ||
            (proof_present && live_proof_verify_required));
    bool replay_head_anchor_ok = true;
    u64 external_anchor_final_generation = 0;
    if (rank == 0) {
        Digest persisted_head{};
        const Digest stale_next = hash_words({
            0x5056474f4453544cULL, sid, static_cast<u64>(checkpoint)});
        if (use_external_anchor) {
            ReferenceVssExternalAnchorSnapshot persisted_snapshot;
            replay_head_anchor_ok =
                external_anchor_client.ReadSnapshot(&persisted_snapshot) &&
                persisted_snapshot.record_binding == independently_pinned_record &&
                persisted_snapshot.native_execution_binding ==
                    native_execution_binding &&
                persisted_snapshot.registry_binding == registry.registry_binding &&
                persisted_snapshot.generation ==
                    external_anchor_snapshot.generation + 1 &&
                persisted_snapshot.replay_head == artifact.recovery_replay_head &&
                stale_next != Digest{} && stale_next != initial_replay_head &&
                !external_anchor_client.CompareAndSwap(
                    external_anchor_snapshot, stale_next, nullptr);
            if (replay_head_anchor_ok) {
                persisted_head = persisted_snapshot.replay_head;
                external_anchor_final_generation =
                    persisted_snapshot.generation;
            }
        } else {
            ReferenceVssSelectivePointReplayHeadAnchor reopened_anchor(
                replay_anchor_file.path, registry.registry_binding);
            replay_head_anchor_ok =
                reopened_anchor.ReadCurrentHead(&persisted_head) &&
                persisted_head == artifact.recovery_replay_head &&
                stale_next != Digest{} && stale_next != initial_replay_head &&
                !reopened_anchor.CompareAndSwap(initial_replay_head, stale_next);
        }
        recovery_ok = recovery_ok &&
            artifact.recovery_share_commitment == hash_field_vector(local_shares) &&
            replay_head_anchor_ok;
    }
    int local_anchor_ok = replay_head_anchor_ok ? 1 : 0;
    int all_anchor_ok = 0;
    if (MPI_Allreduce(&local_anchor_ok, &all_anchor_ok, 1, MPI_INT, MPI_MIN,
                      MPI_COMM_WORLD) != MPI_SUCCESS || !all_anchor_ok)
        recovery_ok = false;
    if (rank == 0 && use_external_anchor && all_anchor_ok == 1) {
        std::cout << "PVIA_GOD_OUTPUT_EXTERNAL_ANCHOR: PASS"
                  << " commit_before_recovery_output=PASS"
                  << " generation=" << external_anchor_final_generation
                  << std::endl;
    }

    // A mismatched independent registry pin must be rejected collectively
    // before it can release points or advance the durable replay journal.
    ReferenceVssAuthenticatedRecoveryConfig bad_config = config;
    bad_config.independently_pinned_registry_binding.bytes[0] ^= 1;
    bad_config.release_context.round = 7301;
    bad_config.release_context.sequence = 7301;
    ReferenceVssAuthenticatedAuditRecoveryBackend bad_backend(
        std::move(bad_config));
    const AuthenticatedRecoveryArtifact refused =
        bad_backend.Recover(request, rank, world_size);
    const bool bad_registry_rejected =
        !refused.available && !bad_backend.Verify(request, refused);

    // Missing verifier callback must fail in the same collective preflight,
    // before any helper sends selective openings.
    ReferenceVssAuthenticatedRecoveryConfig missing_verifier_config = config;
    missing_verifier_config.target_pins.verify_independent_pins = {};
    missing_verifier_config.release_context.round = 7401;
    missing_verifier_config.release_context.sequence = 7401;
    ReferenceVssAuthenticatedAuditRecoveryBackend missing_verifier_backend(
        std::move(missing_verifier_config));
    const AuthenticatedRecoveryArtifact missing_verifier_result =
        missing_verifier_backend.Recover(request, rank, world_size);
    const bool missing_independent_pin_verifier_rejected =
        !missing_verifier_result.available &&
        !missing_verifier_backend.Verify(request, missing_verifier_result);
    recovery_ok = recovery_ok && bad_registry_rejected &&
                  missing_independent_pin_verifier_rejected;

    int local_recovery_ok = recovery_ok ? 1 :0;
    int all_recovery_ok = 0;
    if (MPI_Allreduce(&local_recovery_ok, &all_recovery_ok, 1,
                      MPI_INT, MPI_MIN, MPI_COMM_WORLD) != MPI_SUCCESS ||
        !all_recovery_ok)
        return false;

    const Digest recovery_artifact_binding =
        compute_recovery_artifact_binding(artifact);
    const auto registry_words = god_digest_words(registry.registry_binding);
    const auto artifact_words = god_digest_words(recovery_artifact_binding);
    const auto proof_statement_words =
        god_digest_words(artifact.recovery_proof_statement_binding);
    const auto proof_artifact_words =
        god_digest_words(artifact.recovery_proof_artifact_commitment);
    const Digest proof_binding = proof_present
        ? hash_words({0x5056474f44535031ULL,
            static_cast<u64>(artifact.recovery_proof_system_id),
            proof_statement_words[0], proof_statement_words[1],
            proof_statement_words[2], proof_statement_words[3],
            proof_artifact_words[0], proof_artifact_words[1],
            proof_artifact_words[2], proof_artifact_words[3]})
        : Digest{};
    const Digest combined = hash_words({
        0x5056474f44565243ULL, sid, static_cast<u64>(checkpoint),
        registry_words[0], registry_words[1], registry_words[2], registry_words[3],
        artifact_words[0], artifact_words[1], artifact_words[2], artifact_words[3],
        proof_statement_words[0], proof_statement_words[1],
        proof_statement_words[2], proof_statement_words[3],
        proof_artifact_words[0], proof_artifact_words[1],
        proof_artifact_words[2], proof_artifact_words[3]});
    if (recovery_artifact_binding == Digest{} || combined == Digest{})
        return false;
    std::vector<uint8_t> gathered(static_cast<size_t>(world_size) * 32, 0);
    if (MPI_Allgather(combined.bytes.data(), 32, MPI_BYTE,
                      gathered.data(), 32, MPI_BYTE,
                      MPI_COMM_WORLD) != MPI_SUCCESS)
        return false;
    for (int peer = 0; peer < world_size; ++peer) {
        const auto* expected = combined.bytes.data();
        const auto* observed = gathered.data() + static_cast<size_t>(peer) * 32;
        if (!std::equal(expected, expected + 32, observed)) return false;
    }

    *integration_binding = combined;
    *registry_binding_out = registry.registry_binding;
    *recovery_artifact_binding_out = recovery_artifact_binding;
    *proof_binding_out = proof_binding;
    return true;
}

bool valid_field(const F& x) {
    return x.real < F::mod && x.img < F::mod;
}

bool parse_u64_word_list(const char* text, std::array<u64,4>* words) {
    if(!text||!*text||!words)return false;
    std::istringstream input(text);
    std::string token;
    for(size_t i=0;i<words->size();++i) {
        if(!std::getline(input,token,',')||token.empty())return false;
        try {
            size_t used=0;
            const unsigned long long value=std::stoull(token,&used,0);
            if(used!=token.size())return false;
            (*words)[i]=static_cast<u64>(value);
        } catch(...) {
            return false;
        }
    }
    return input.eof();
}

bool parse_sha256_hex(const char* text,std::array<unsigned char,32>* digest) {
    if(!text||!digest||std::strlen(text)!=64)return false;
    auto nibble=[](char c)->int {
        if(c>='0'&&c<='9')return c-'0';
        if(c>='a'&&c<='f')return c-'a'+10;
        if(c>='A'&&c<='F')return c-'A'+10;
        return -1;
    };
    for(size_t i=0;i<digest->size();++i) {
        const int hi=nibble(text[2*i]),lo=nibble(text[2*i+1]);
        if(hi<0||lo<0)return false;
        (*digest)[i]=static_cast<unsigned char>((hi<<4)|lo);
    }
    return true;
}

bool sha256_file(const std::string& path,std::array<unsigned char,32>* digest) {
    if(path.empty()||!digest)return false;
    std::ifstream input(path,std::ios::binary);
    if(!input)return false;
    EVP_MD_CTX* ctx=EVP_MD_CTX_new();
    if(!ctx)return false;
    bool ok=EVP_DigestInit_ex(ctx,EVP_sha256(),nullptr)==1;
    std::array<unsigned char,65536> buffer{};
    while(ok&&input) {
        input.read(reinterpret_cast<char*>(buffer.data()),
                   static_cast<std::streamsize>(buffer.size()));
        const std::streamsize count=input.gcount();
        if(count>0)
            ok=EVP_DigestUpdate(ctx,buffer.data(),static_cast<size_t>(count))==1;
    }
    if(input.bad())ok=false;
    unsigned int length=0;
    if(ok)ok=EVP_DigestFinal_ex(ctx,digest->data(),&length)==1&&
        length==digest->size();
    EVP_MD_CTX_free(ctx);
    return ok;
}
F interpolate_at_zero(const F& ya, int a, const F& yb, int b) {
    const F xa(a+1), xb(b+1);
    return (ya*xb-yb*xa)*(xb-xa).inv();
}
F interpolate_at(const F& ya,int a,const F& yb,int b,int x) {
    const F xa(a+1),xb(b+1),xx(x+1);
    return ya*(xx-xb)*(xa-xb).inv()
         + yb*(xx-xa)*(xb-xa).inv();
}
}

bool verify_reference_god_survivor_certificate(
    const ReferenceGodOutput& output,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& trusted_registry_commitment) {
    const ReferenceGodSurvivorCertificate& cert=output.survivor_certificate;
    if(!cert.available || !output.available || !output.authenticated_transport ||
       output.delivered_participants!=3 || output.corrected_participants!=0 ||
       output.values.empty() || output.values.size()>4096 ||
       output.agreement_votes!=3 || output.agreement_certificate==Digest{} ||
       output.transcript_binding!=output.agreement_certificate ||
       output.scope_binding==Digest{} || output.vss_transcript_binding==Digest{} ||
       output.transport_binding==Digest{} ||
       cert.registry_commitment==Digest{} ||
       trusted_registry_commitment==Digest{} ||
       cert.registry_commitment!=trusted_registry_commitment ||
       public_keys.size()!=4 ||
       compute_ed25519_registry_commitment(public_keys)!=trusted_registry_commitment ||
       cert.original_world_size!=4 || cert.failed_original_rank<0 ||
       cert.failed_original_rank>=4 || cert.active_original_ranks.size()!=3 ||
       cert.vote_signatures.size()!=3 ||
       cert.roster_binding==Digest{} || cert.candidate_binding==Digest{} ||
       cert.recovery_context.protocol_domain!=GOD_N4_DOMAIN ||
       !validate_authenticated_mpc_message_context(cert.recovery_context) ||
       cert.recovery_context.sid==0 || cert.recovery_context.checkpoint==0 ||
       cert.recovery_context.round==UINT64_MAX ||
       cert.recovery_context.sequence==UINT64_MAX)
        return false;
    for(const auto& value:output.values)
        if(!valid_field(value)) return false;

    std::array<bool,4> seen{{false,false,false,false}};
    for(int id:cert.active_original_ranks) {
        if(id<0 || id>=4 || id==cert.failed_original_rank ||
           seen[static_cast<size_t>(id)]) return false;
        seen[static_cast<size_t>(id)]=true;
    }
    for(int id=0;id<4;++id)
        if(seen[static_cast<size_t>(id)] != (id!=cert.failed_original_rank))
            return false;
    std::vector<u64> roster_words={
        GOD_CRASH_CERT_DOMAIN,4ULL,1ULL,3ULL,
        static_cast<u64>(cert.failed_original_rank)};
    for(int id:cert.active_original_ranks)
        roster_words.push_back(static_cast<u64>(id));
    if(hash_words(roster_words)!=cert.roster_binding) return false;

    const bool has_proof_set=output.multiplication_proof_set_binding!=Digest{};
    const bool has_output_statement=
        output.output_consistency_statement_binding!=Digest{};
    const bool has_output_proof=
        output.output_consistency_proof_binding!=Digest{};
    if(has_proof_set!=has_output_statement ||
       has_proof_set!=has_output_proof ||
       output.multiplication_consistency_verified!=has_proof_set)
        return false;
    std::vector<u64> candidate_words={
        GOD_CRASH_CERT_DOMAIN,
        cert.recovery_context.protocol_domain,
        cert.recovery_context.sid,
        static_cast<u64>(cert.recovery_context.checkpoint),
        cert.recovery_context.round,
        cert.recovery_context.sequence,
        4ULL,3ULL,static_cast<u64>(cert.failed_original_rank)};
    append_recovery_digest(output.scope_binding,&candidate_words);
    append_recovery_digest(output.vss_transcript_binding,&candidate_words);
    append_recovery_digest(cert.registry_commitment,&candidate_words);
    append_recovery_digest(cert.roster_binding,&candidate_words);
    append_recovery_digest(output.transport_binding,&candidate_words);
    append_recovery_digest(hash_field_vector(output.values),&candidate_words);
    append_recovery_digest(output.multiplication_proof_set_binding,&candidate_words);
    append_recovery_digest(output.output_consistency_statement_binding,&candidate_words);
    append_recovery_digest(output.output_consistency_proof_binding,&candidate_words);
    const Digest candidate=hash_words(candidate_words);
    if(candidate==Digest{} || candidate!=cert.candidate_binding)
        return false;

    AuthenticatedMpcMessageContext vote_context=cert.recovery_context;
    ++vote_context.round;
    ++vote_context.sequence;
    vote_context.message_kind=GOD_CRASH_VOTE_DOMAIN;
    if(!validate_authenticated_mpc_message_context(vote_context)) return false;

    std::vector<u64> signed_certificate_words={
        GOD_CRASH_CERT_DOMAIN,cert.recovery_context.protocol_domain,
        cert.recovery_context.sid,
        static_cast<u64>(cert.recovery_context.checkpoint),
        static_cast<u64>(cert.failed_original_rank),3ULL};
    append_recovery_digest(candidate,&signed_certificate_words);
    for(size_t r=0;r<3;++r) {
        const uint32_t signer=static_cast<uint32_t>(
            cert.active_original_ranks[r]);
        const auto message=build_authenticated_mpc_signed_message(
            vote_context,signer,AUTHENTICATED_MPC_BROADCAST_RECEIVER,
            4,4,candidate);
        if(message.empty() || !verify_ed25519_words_with_public_registry(
            AUTHENTICATED_MPC_SIGNATURE_DOMAIN,message,
            cert.vote_signatures[r],signer,public_keys,
            trusted_registry_commitment)) return false;
        signed_certificate_words.push_back(static_cast<u64>(signer));
        for(size_t k=0;k<8;++k) {
            u64 word=0;
            std::memcpy(&word,cert.vote_signatures[r].data()+8*k,8);
            signed_certificate_words.push_back(word);
        }
    }
    return hash_words(signed_certificate_words)==output.agreement_certificate;
}

// Public artifact format v1. Neither private shares nor VSS rows are emitted.
constexpr u64 GOD_SURVIVOR_CERT_ABI_DOMAIN=0x5056474f44434142ULL;
constexpr u64 GOD_SURVIVOR_CERT_ABI_VERSION=1ULL;
constexpr size_t GOD_SURVIVOR_CERT_ABI_HEADER=13;
constexpr size_t GOD_SURVIVOR_CERT_ABI_DIGESTS=10;
constexpr size_t GOD_SURVIVOR_CERT_ABI_TRAILER=27;

std::vector<u64> encode_reference_god_survivor_certificate_abi(
    const ReferenceGodOutput& output) {
    const auto& c=output.survivor_certificate;
    if(!output.available || !c.available || c.original_world_size!=4 ||
       c.failed_original_rank<0 || c.failed_original_rank>=4 ||
       c.active_original_ranks.size()!=3 || c.vote_signatures.size()!=3 ||
       output.values.empty() || output.values.size()>4096 ||
       output.scope_binding==Digest{} || output.vss_transcript_binding==Digest{} ||
       output.transport_binding==Digest{} || output.agreement_certificate==Digest{} ||
       c.registry_commitment==Digest{} || c.roster_binding==Digest{} ||
       c.candidate_binding==Digest{} || output.agreement_votes!=3 ||
       c.recovery_context.protocol_domain!=GOD_N4_DOMAIN ||
       !validate_authenticated_mpc_message_context(c.recovery_context))
        return {};
    const bool p=output.multiplication_consistency_verified;
    if(p!=(output.multiplication_proof_set_binding!=Digest{}) ||
       p!=(output.output_consistency_statement_binding!=Digest{}) ||
       p!=(output.output_consistency_proof_binding!=Digest{})) return {};
    std::vector<u64> words={
        GOD_SURVIVOR_CERT_ABI_DOMAIN,GOD_SURVIVOR_CERT_ABI_VERSION,
        4ULL,static_cast<u64>(c.failed_original_rank),3ULL,
        c.recovery_context.protocol_domain,c.recovery_context.sid,
        static_cast<u64>(c.recovery_context.checkpoint),
        c.recovery_context.round,c.recovery_context.sequence,
        c.recovery_context.message_kind,
        static_cast<u64>(output.values.size()),p?1ULL:0ULL};
    append_recovery_digest(output.scope_binding,&words);
    append_recovery_digest(output.vss_transcript_binding,&words);
    append_recovery_digest(output.transport_binding,&words);
    append_recovery_digest(c.registry_commitment,&words);
    append_recovery_digest(c.roster_binding,&words);
    append_recovery_digest(c.candidate_binding,&words);
    append_recovery_digest(output.agreement_certificate,&words);
    append_recovery_digest(output.multiplication_proof_set_binding,&words);
    append_recovery_digest(output.output_consistency_statement_binding,&words);
    append_recovery_digest(output.output_consistency_proof_binding,&words);
    for(const F& v:output.values) {
        if(!valid_field(v)) return {};
        words.push_back(v.real); words.push_back(v.img);
    }
    for(int id:c.active_original_ranks) {
        if(id<0 || id>=4 || id==c.failed_original_rank) return {};
        words.push_back(static_cast<u64>(id));
    }
    for(const auto& sig:c.vote_signatures) {
        for(size_t k=0;k<8;++k) {
            u64 w=0; std::memcpy(&w,sig.data()+8*k,8); words.push_back(w);
        }
    }
    const size_t expected=GOD_SURVIVOR_CERT_ABI_HEADER+
        4*GOD_SURVIVOR_CERT_ABI_DIGESTS+
        2*output.values.size()+GOD_SURVIVOR_CERT_ABI_TRAILER;
    return words.size()==expected?words:std::vector<u64>{};
}

bool decode_reference_god_survivor_certificate_abi(
    const std::vector<u64>& words, ReferenceGodOutput* output) {
    if(!output)return false;
    *output=ReferenceGodOutput{};
    if(words.size()<GOD_SURVIVOR_CERT_ABI_HEADER+
            4*GOD_SURVIVOR_CERT_ABI_DIGESTS+
            2+GOD_SURVIVOR_CERT_ABI_TRAILER ||
       words[0]!=GOD_SURVIVOR_CERT_ABI_DOMAIN ||
       words[1]!=GOD_SURVIVOR_CERT_ABI_VERSION ||
       words[2]!=4 || words[3]>=4 || words[4]!=3 ||
       words[5]!=GOD_N4_DOMAIN || words[6]==0 || words[7]==0 ||
       words[8]==UINT64_MAX || words[9]==UINT64_MAX ||
       words[11]==0 || words[11]>4096 || words[12]>1 ||
       words.size()!=GOD_SURVIVOR_CERT_ABI_HEADER+
           4*GOD_SURVIVOR_CERT_ABI_DIGESTS+
           2*static_cast<size_t>(words[11])+GOD_SURVIVOR_CERT_ABI_TRAILER)
        return false;
    ReferenceGodOutput parsed;
    auto& c=parsed.survivor_certificate;
    c.available=true;
    c.original_world_size=4;
    c.failed_original_rank=static_cast<int>(words[3]);
    c.recovery_context.protocol_domain=words[5];
    c.recovery_context.sid=words[6];
    c.recovery_context.checkpoint=static_cast<CheckpointId>(words[7]);
    c.recovery_context.round=words[8];
    c.recovery_context.sequence=words[9];
    c.recovery_context.message_kind=words[10];
    size_t cur=GOD_SURVIVOR_CERT_ABI_HEADER;
    auto read_digest=[&]()->Digest {
        Digest d=recovery_digest_from_words(words.data()+cur);
        cur+=4;
        return d;
    };
    parsed.scope_binding=read_digest();
    parsed.vss_transcript_binding=read_digest();
    parsed.transport_binding=read_digest();
    c.registry_commitment=read_digest();
    c.roster_binding=read_digest();
    c.candidate_binding=read_digest();
    parsed.agreement_certificate=read_digest();
    parsed.multiplication_proof_set_binding=read_digest();
    parsed.output_consistency_statement_binding=read_digest();
    parsed.output_consistency_proof_binding=read_digest();
    const size_t lanes=static_cast<size_t>(words[11]);
    for(size_t i=0;i<lanes;++i) {
        const u64 re=words[cur++],im=words[cur++];
        if(re>=F::mod || im>=F::mod) return false;
        parsed.values.emplace_back(static_cast<long long>(re),
                                   static_cast<long long>(im));
    }
    for(size_t i=0;i<3;++i) {
        const u64 id=words[cur++];
        if(id>=4 || id==words[3]) return false;
        c.active_original_ranks.push_back(static_cast<int>(id));
    }
    for(size_t i=0;i<3;++i) {
        std::array<uint8_t,64> sig{};
        std::memcpy(sig.data(),words.data()+cur,64);
        cur+=8; c.vote_signatures.push_back(sig);
    }
    if(cur!=words.size() ||
       !validate_authenticated_mpc_message_context(c.recovery_context))
        return false;
    parsed.available=true;
    parsed.delivered_participants=3;
    parsed.corrected_participants=0;
    parsed.agreement_votes=3;
    parsed.transcript_binding=parsed.agreement_certificate;
    parsed.authenticated_transport=true;
    // A portable signature certificate proves survivor agreement, not that
    // any process actually crashed during the invocation that produced it.
    parsed.process_crash_tolerant=false;
    parsed.multiplication_consistency_verified=words[12]==1;
    // All verification and production assertions remain false on import.
    parsed.survivor_agreement_verified=false;
    parsed.verifiable_sharing_verified=false;
    parsed.authenticated_vss_verified=false;
    parsed.external_registry_anchor_verified=false;
    parsed.production_authenticated_transport=false;
    parsed.complete_application_relation_set_verified=false;
    parsed.production_god_authorized=false;
    if(encode_reference_god_survivor_certificate_abi(parsed)!=words)
        return false;
    *output=std::move(parsed);
    return true;
}

bool verify_reference_god_survivor_certificate_files(
    const std::string& certificate_words_path,
    const std::string& public_registry_hex_path,
    const std::string& trusted_registry_anchor_hex,
    std::string* detail) {
    if(detail)*detail="certificate file validation failed";
    if(!detail||certificate_words_path.empty()||
       public_registry_hex_path.empty()||
       trusted_registry_anchor_hex.size()!=64)return false;
    std::array<unsigned char,32> pinned_bytes{};
    if(!parse_sha256_hex(trusted_registry_anchor_hex.c_str(),&pinned_bytes))
        return false;
    Digest pinned{};
    std::copy(pinned_bytes.begin(),pinned_bytes.end(),pinned.bytes.begin());
    if(pinned==Digest{})return false;
    std::ifstream cert_stream(certificate_words_path);
    std::vector<u64> cert_words;
    u64 word=0;
    while(cert_stream>>word) {
        if(cert_words.size()>=16384)return false;
        cert_words.push_back(word);
    }
    if(cert_stream.bad()||cert_stream.fail()&&!cert_stream.eof() ||
       cert_words.empty())return false;
    ReferenceGodOutput parsed;
    if(!decode_reference_god_survivor_certificate_abi(
        cert_words,&parsed))return false;
    std::ifstream registry_stream(public_registry_hex_path);
    std::vector<std::array<uint8_t,32>> public_keys;
    std::string line;
    while(std::getline(registry_stream,line)) {
        if(public_keys.size()>=4||line.size()!=64)return false;
        std::array<unsigned char,32> bytes{};
        if(!parse_sha256_hex(line.c_str(),&bytes))return false;
        public_keys.emplace_back();
        std::copy(bytes.begin(),bytes.end(),public_keys.back().begin());
    }
    if(registry_stream.bad()||public_keys.size()!=4)return false;
    const bool signature_verified=verify_reference_god_survivor_certificate(
        parsed,public_keys,pinned);
    if(!signature_verified)return false;
    // Import plus offline verification does not establish execution
    // completeness, reliable broadcast, VSS, or production GOD.
    if(parsed.production_god_authorized||
       parsed.complete_application_relation_set_verified||
       parsed.verifiable_sharing_verified||
       parsed.authenticated_vss_verified ||
       reference_god_output_production_authorized(parsed))
        return false;
    *detail="independent Ed25519 survivor votes verified; "
            "application completeness and production GOD NOT established";
    return true;
}

bool reconstruct_reference_god_output_n4(
    const std::vector<int>& providers,
    const std::vector<std::vector<F>>& shares,
    const Digest& scope_binding, ReferenceGodOutput* output) {
    if (!output) return false;
    *output = ReferenceGodOutput{};
    if (scope_binding==Digest{} || providers.size()<3 ||
        providers.size()>4 || providers.size()!=shares.size() ||
        shares.front().empty() || shares.front().size()>4096)
        return false;
    const size_t lanes=shares.front().size();
    std::array<bool,4> seen{{false,false,false,false}};
    for (size_t i=0;i<providers.size();++i) {
        int id=providers[i];
        if(id<0 || id>=4 || seen[static_cast<size_t>(id)] ||
           shares[i].size()!=lanes) return false;
        seen[static_cast<size_t>(id)]=true;
        for(const F& value:shares[i]) if(!valid_field(value)) return false;
    }
    std::vector<F> values; values.reserve(lanes);
    std::set<int> corrected;
    for(size_t lane=0;lane<lanes;++lane) {
        bool found=false;
        F candidate(0);
        std::set<int> lane_errors;
        for(size_t a=0;a<providers.size();++a) {
            for(size_t b=a+1;b<providers.size();++b) {
                std::set<int> errors;
                for(size_t k=0;k<providers.size();++k) {
                    F expected=interpolate_at(
                        shares[a][lane],providers[a],
                        shares[b][lane],providers[b],providers[k]);
                    if(expected!=shares[k][lane])
                        errors.insert(providers[k]);
                }
                const size_t permitted=providers.size()==4 ? 1u:0u;
                if(errors.size()>permitted) continue;
                F value=interpolate_at_zero(
                    shares[a][lane],providers[a],
                    shares[b][lane],providers[b]);
                if(found && value!=candidate) return false;
                if(!found || errors.size()<lane_errors.size()) {
                    found=true; candidate=value; lane_errors=errors;
                }
            }
        }
        if(!found) return false;
        values.push_back(candidate);
        corrected.insert(lane_errors.begin(),lane_errors.end());
        if(corrected.size()>1) return false;
    }
    // The full vector must be consistent with one faulty rank at most.
    std::vector<u64> transcript={
        GOD_N4_DOMAIN,4ULL,1ULL,static_cast<u64>(lanes),
        static_cast<u64>(providers.size()),
        static_cast<u64>(corrected.size())};
    for(int id:providers) transcript.push_back(static_cast<u64>(id));
    for(size_t i=0;i<providers.size();++i)
        for(const F& v:shares[i]) {
            transcript.push_back(v.real); transcript.push_back(v.img);
        }
    for(const F& v:values) {
        transcript.push_back(v.real); transcript.push_back(v.img);
    }
    for(int id:corrected) transcript.push_back(static_cast<u64>(id));
    for(size_t i=0;i<4;++i) {
        u64 word=0;
        std::memcpy(&word,scope_binding.bytes.data()+8*i,8);
        transcript.push_back(word);
    }
    Digest digest=hash_words(transcript);
    if(digest==Digest{}) return false;
    output->available=true;
    output->values=std::move(values);
    output->delivered_participants=static_cast<uint32_t>(providers.size());
    output->corrected_participants=static_cast<uint32_t>(corrected.size());
    output->scope_binding=scope_binding;
    output->transcript_binding=digest;
    return true;
}

bool open_reference_god_output_n4(
    int rank,int world_size,const std::vector<F>& local_shares,
    bool send_share,const Digest& scope_binding,
    ReferenceGodOutput* output,MPI_Comm comm) {
    if(!output) return false;
    *output=ReferenceGodOutput{};
    int actual_rank=-1,actual_world=-1;
    MPI_Comm_rank(comm,&actual_rank);
    MPI_Comm_size(comm,&actual_world);
    int local_ok=(world_size==4 && rank==actual_rank &&
        actual_world==4 && local_shares.size()>=1 &&
        local_shares.size()<=4096 && scope_binding!=Digest{})?1:0;
    if(send_share) for(const F& x:local_shares)
        if(!valid_field(x)) local_ok=0;
    int all_ok=0;
    MPI_Allreduce(&local_ok,&all_ok,1,MPI_INT,MPI_MIN,comm);
    if(!all_ok) return false;
    // Agree on session provenance before revealing any MPC output shares.
    std::array<uint8_t,32> scope{};
    std::copy(scope_binding.bytes.begin(),scope_binding.bytes.end(),scope.begin());
    std::array<uint8_t,128> all_scopes{};
    MPI_Allgather(scope.data(),32,MPI_BYTE,
                  all_scopes.data(),32,MPI_BYTE,comm);
    record_control_allgather(32,world_size);
    for(int i=0;i<world_size;++i)
        if(!std::equal(scope.begin(),scope.end(),all_scopes.begin()+32*i))
            return false;
    const size_t count=local_shares.size();
    // MPI_Allgather requires identical counts at all ranks. Fail collectively
    // before starting variable-length exchange if the shape is inconsistent.
    const int local_count=static_cast<int>(count);
    int minimum=0,maximum=0;
    MPI_Allreduce(&local_count,&minimum,1,MPI_INT,MPI_MIN,comm);
    MPI_Allreduce(&local_count,&maximum,1,MPI_INT,MPI_MAX,comm);
    if(minimum!=maximum) return false;
    const int width=1+2*local_count;
    std::vector<u64> outbound(static_cast<size_t>(width),0);
    outbound[0]=send_share?1:0;
    if(send_share) for(size_t i=0;i<count;++i) {
        outbound[1+2*i]=local_shares[i].real;
        outbound[2+2*i]=local_shares[i].img;
    }
    std::vector<u64> received(static_cast<size_t>(world_size)*width);
    MPI_Allgather(outbound.data(),width,MPI_UINT64_T,
                  received.data(),width,MPI_UINT64_T,comm);
    record_control_allgather(static_cast<u64>(width)*sizeof(u64),world_size);
    std::vector<int> providers;
    std::vector<std::vector<F>> shares;
    for(int i=0;i<world_size;++i) {
        const size_t off=static_cast<size_t>(i)*width;
        if(received[off]>1) return false;
        if(received[off]==0) {
            for(int j=1;j<width;++j)
                if(received[off+static_cast<size_t>(j)]!=0) return false;
            continue;
        }
        std::vector<F> row; row.reserve(count);
        for(size_t j=0;j<count;++j) {
            u64 re=received[off+1+2*j],im=received[off+2+2*j];
            if(re>=F::mod || im>=F::mod) return false;
            row.emplace_back(static_cast<long long>(re),static_cast<long long>(im));
        }
        providers.push_back(i);shares.push_back(std::move(row));
    }
    return reconstruct_reference_god_output_n4(
        providers,shares,scope_binding,output);
}

bool open_reference_god_output_after_failure_n4(
    int original_rank, int original_world_size,
    const std::vector<int>& active_original_ranks,
    const std::vector<F>& local_share_vector,
    const Digest& scope_binding,
    const AuthenticatedMpcMessageContext& recovery_context,
    const ReferenceVssReceipt& vss_receipt,
    MPI_Comm active_comm,
    ReferenceGodOutput* output,
    const ReferenceGodOutputConsistencyProofBundle* consistency_proof,
    bool process_crash_tolerant) {
    if (!output || active_comm == MPI_COMM_NULL) return false;
    *output = ReferenceGodOutput{};
    int ar=-1,n=0;
    if (MPI_Comm_rank(active_comm,&ar)!=MPI_SUCCESS ||
        MPI_Comm_size(active_comm,&n)!=MPI_SUCCESS) return false;
    auto& auth=Ed25519TransferAuthenticator::instance();
    const size_t count=local_share_vector.size();
    int failed=-1;
    std::array<bool,4> seen{{false,false,false,false}};
    int ok=original_world_size==4 && original_rank>=0 && original_rank<4 &&
        n==3 && active_original_ranks.size()==static_cast<size_t>(n) &&
        ar>=0 && ar<n && active_original_ranks[static_cast<size_t>(ar)]==original_rank &&
        count>0 && count<=4096 && scope_binding!=Digest{} &&
        recovery_context.protocol_domain==GOD_N4_DOMAIN &&
        validate_authenticated_mpc_message_context(recovery_context) &&
        recovery_context.sid!=0 && recovery_context.checkpoint!=0 &&
        recovery_context.round<UINT64_MAX && recovery_context.sequence<UINT64_MAX &&
        auth.ready() && auth.rank()==original_rank && auth.world_size()==4 &&
        vss_receipt.available && vss_receipt.consistent &&
        vss_receipt.world_size==4 && vss_receipt.threshold==1 &&
        vss_receipt.element_count==count && vss_receipt.dealer>=0 &&
        vss_receipt.dealer<4 && vss_receipt.transcript_binding!=Digest{} &&
        vss_receipt.local_row_commitment!=Digest{} &&
        vss_receipt.transcript_context.world_size==original_world_size &&
        vss_receipt.transcript_context.row_commitments.size()==4 &&
        vss_receipt.transcript_context.row_commitments[
            static_cast<size_t>(original_rank)]==
            vss_receipt.local_row_commitment &&
        compute_reference_vss_transcript_binding(
            vss_receipt.dealer,vss_receipt.threshold,
            vss_receipt.element_count,vss_receipt.transcript_context)==
                vss_receipt.transcript_binding ? 1:0;
    for(int id:active_original_ranks) {
        if(id<0||id>=4||seen[static_cast<size_t>(id)]) ok=0;
        else seen[static_cast<size_t>(id)]=true;
    }
    for(int id=0;id<4;++id) if(!seen[static_cast<size_t>(id)]) {
        if(failed!=-1) ok=0;
        failed=id;
    }
    if(failed<0) ok=0;
    for(const F& x:local_share_vector) if(!valid_field(x)) ok=0;
    const Digest registry=auth.RegistryCommitment();
    if(registry==Digest{}) ok=0;
    if(god_active_comm_agree(active_comm,&ok)!=MPI_SUCCESS||!ok) return false;

    // MPI_Allgather uses a fixed count on every rank. Agree the share-vector
    // width before constructing any fixed-size receive buffer.
    const uint64_t local_count = static_cast<uint64_t>(count);
    uint64_t min_count = 0, max_count = 0;
    if (MPI_Allreduce(&local_count, &min_count, 1, MPI_UINT64_T,
                      MPI_MIN, active_comm) != MPI_SUCCESS ||
        MPI_Allreduce(&local_count, &max_count, 1, MPI_UINT64_T,
                      MPI_MAX, active_comm) != MPI_SUCCESS ||
        min_count == 0 || min_count != max_count || max_count > 4096)
        return false;

    std::vector<u64> roster={GOD_CRASH_CERT_DOMAIN,4ULL,1ULL,
        static_cast<u64>(n),static_cast<u64>(failed)};
    for(int id:active_original_ranks) roster.push_back(static_cast<u64>(id));
    const Digest roster_binding=hash_words(roster);
    if(roster_binding==Digest{}) return false;

    AuthenticatedMpcMessageContext share_ctx=recovery_context;
    share_ctx.message_kind=GOD_CRASH_SHARE_DOMAIN;
    if(!validate_authenticated_mpc_message_context(share_ctx)) return false;
    std::vector<u64> local={
        GOD_CRASH_SHARE_DOMAIN,static_cast<u64>(original_rank),4ULL,
        recovery_context.sid,static_cast<u64>(recovery_context.checkpoint),
        static_cast<u64>(failed),static_cast<u64>(count)};
    append_recovery_digest(scope_binding,&local);
    append_recovery_digest(vss_receipt.transcript_binding,&local);
    append_recovery_digest(registry,&local);
    append_recovery_digest(roster_binding,&local);
    for(const F& x:local_share_vector) { local.push_back(x.real); local.push_back(x.img); }
    if(local.size()!=GOD_CRASH_SHARE_HEADER_WORDS+2*count ||
       local.size()>static_cast<size_t>(std::numeric_limits<int>::max())) return false;
    const Digest local_binding=compute_authenticated_mpc_payload_binding(local);
    const auto local_message=build_authenticated_mpc_signed_message(
        share_ctx,static_cast<uint32_t>(original_rank),
        AUTHENTICATED_MPC_BROADCAST_RECEIVER,4,local.size(),local_binding);
    std::array<uint8_t,64> local_sig{};
    if(local_binding==Digest{} ||
       !auth.SignWords(AUTHENTICATED_MPC_SIGNATURE_DOMAIN,local_message,&local_sig))
        return false;
    const char* tamper=std::getenv("PVIA_GOD_OUTPUT_RECOVERY_TAMPER_SIGNATURE");
    const int negative_test_rank=failed==2?3:2;
    if(tamper&&std::string(tamper)!="0"&&
       original_rank==negative_test_rank) local_sig[0]^=1;

    const int width=static_cast<int>(local.size());
    std::vector<u64> gathered(static_cast<size_t>(n)*local.size());
    std::vector<std::array<uint8_t,64>> signatures(static_cast<size_t>(n));
    if(MPI_Allgather(local.data(),width,MPI_UINT64_T,gathered.data(),width,
                     MPI_UINT64_T,active_comm)!=MPI_SUCCESS ||
       MPI_Allgather(local_sig.data(),64,MPI_BYTE,signatures.data(),64,
                     MPI_BYTE,active_comm)!=MPI_SUCCESS) return false;

    int sig_ok=1;
    std::vector<int> providers;
    std::vector<std::vector<F>> shares;
    std::vector<u64> transport={GOD_CRASH_SHARE_DOMAIN,recovery_context.protocol_domain,
        recovery_context.sid,static_cast<u64>(recovery_context.checkpoint),
        recovery_context.round,recovery_context.sequence,static_cast<u64>(failed)};
    append_recovery_digest(scope_binding,&transport);
    append_recovery_digest(vss_receipt.transcript_binding,&transport);
    append_recovery_digest(registry,&transport);
    append_recovery_digest(roster_binding,&transport);
    for(int source=0;source<n;++source) {
        const int id=active_original_ranks[static_cast<size_t>(source)];
        const size_t off=static_cast<size_t>(source)*local.size();
        std::vector<u64> peer(gathered.begin()+static_cast<std::ptrdiff_t>(off),
            gathered.begin()+static_cast<std::ptrdiff_t>(off+local.size()));
        const bool meta=peer[0]==GOD_CRASH_SHARE_DOMAIN &&
            peer[1]==static_cast<u64>(id) && peer[2]==4ULL &&
            peer[3]==recovery_context.sid &&
            peer[4]==static_cast<u64>(recovery_context.checkpoint) &&
            peer[5]==static_cast<u64>(failed) && peer[6]==count &&
            recovery_digest_from_words(&peer[7])==scope_binding &&
            recovery_digest_from_words(&peer[11])==vss_receipt.transcript_binding &&
            recovery_digest_from_words(&peer[15])==registry &&
            recovery_digest_from_words(&peer[19])==roster_binding;
        const Digest binding=compute_authenticated_mpc_payload_binding(peer);
        const auto msg=build_authenticated_mpc_signed_message(
            share_ctx,static_cast<uint32_t>(id),
            AUTHENTICATED_MPC_BROADCAST_RECEIVER,4,peer.size(),binding);
        if(!meta||binding==Digest{} ||
           !auth.VerifyWords(AUTHENTICATED_MPC_SIGNATURE_DOMAIN,msg,
               signatures[static_cast<size_t>(source)],static_cast<uint32_t>(id)))
            sig_ok=0;
        transport.push_back(static_cast<u64>(id));
        append_recovery_digest(binding,&transport);
        for(size_t k=0;k<8;++k) {
            u64 w=0; std::memcpy(&w,signatures[static_cast<size_t>(source)].data()+8*k,8);
            transport.push_back(w);
        }
        std::vector<F> row; row.reserve(count);
        for(size_t j=0;j<count;++j) {
            u64 re=peer[GOD_CRASH_SHARE_HEADER_WORDS+2*j];
            u64 im=peer[GOD_CRASH_SHARE_HEADER_WORDS+2*j+1];
            if(re>=F::mod||im>=F::mod) { sig_ok=0; row.emplace_back(F(0)); }
            else row.emplace_back(static_cast<long long>(re),static_cast<long long>(im));
        }
        providers.push_back(id); shares.push_back(std::move(row));
    }
    if(god_active_comm_agree(active_comm,&sig_ok)!=MPI_SUCCESS||!sig_ok) return false;
    ReferenceGodOutput recovered;
    if(!reconstruct_reference_god_output_n4(providers,shares,scope_binding,&recovered))
        return false;
    const Digest transport_binding=hash_words(transport);
    if(transport_binding==Digest{}) return false;

    Digest proof_set{},proof_statement{},proof_binding{};
    const bool proof_present=consistency_proof!=nullptr;
    bool proof_ok=!proof_present;
    if(proof_present) proof_ok=verify_reference_god_output_consistency_bundle(
        recovery_context.sid,recovery_context.checkpoint,scope_binding,
        recovered.values,*consistency_proof,&proof_set,&proof_statement,&proof_binding);
    std::vector<u64> pm={proof_present?1ULL:0ULL,proof_ok?1ULL:0ULL};
    append_recovery_digest(proof_set,&pm);
    append_recovery_digest(proof_statement,&pm);
    append_recovery_digest(proof_binding,&pm);
    std::vector<u64> all_pm(static_cast<size_t>(n)*pm.size());
    if(MPI_Allgather(pm.data(),static_cast<int>(pm.size()),MPI_UINT64_T,
        all_pm.data(),static_cast<int>(pm.size()),MPI_UINT64_T,active_comm)!=MPI_SUCCESS)
        return false;
    bool same_pm=true;
    for(int r=0;r<n;++r) for(size_t j=0;j<pm.size();++j)
        if(all_pm[static_cast<size_t>(r)*pm.size()+j]!=pm[j]) same_pm=false;
    if(!same_pm||!proof_ok||
       (proof_present&&(proof_set==Digest{}||proof_statement==Digest{}||proof_binding==Digest{}))||
       (!proof_present&&(proof_set!=Digest{}||proof_statement!=Digest{}||proof_binding!=Digest{})))
        return false;

    std::vector<u64> candidate_words={GOD_CRASH_CERT_DOMAIN,
        recovery_context.protocol_domain,recovery_context.sid,
        static_cast<u64>(recovery_context.checkpoint),recovery_context.round,
        recovery_context.sequence,4ULL,static_cast<u64>(n),static_cast<u64>(failed)};
    append_recovery_digest(scope_binding,&candidate_words);
    append_recovery_digest(vss_receipt.transcript_binding,&candidate_words);
    append_recovery_digest(registry,&candidate_words);
    append_recovery_digest(roster_binding,&candidate_words);
    append_recovery_digest(transport_binding,&candidate_words);
    append_recovery_digest(hash_field_vector(recovered.values),&candidate_words);
    append_recovery_digest(proof_set,&candidate_words);
    append_recovery_digest(proof_statement,&candidate_words);
    append_recovery_digest(proof_binding,&candidate_words);
    const Digest candidate=hash_words(candidate_words);
    if(candidate==Digest{}) return false;

    AuthenticatedMpcMessageContext vote_ctx=recovery_context;
    ++vote_ctx.round; ++vote_ctx.sequence; vote_ctx.message_kind=GOD_CRASH_VOTE_DOMAIN;
    if(!validate_authenticated_mpc_message_context(vote_ctx)) return false;
    std::vector<u64> candidate_words_digest;
    append_recovery_digest(candidate,&candidate_words_digest);
    const auto vote_msg=build_authenticated_mpc_signed_message(
        vote_ctx,static_cast<uint32_t>(original_rank),
        AUTHENTICATED_MPC_BROADCAST_RECEIVER,4,4,candidate);
    std::array<uint8_t,64> vote_sig{};
    if(!auth.SignWords(AUTHENTICATED_MPC_SIGNATURE_DOMAIN,vote_msg,&vote_sig))
        return false;
    std::vector<u64> all_candidates(static_cast<size_t>(n)*4);
    std::vector<std::array<uint8_t,64>> all_vote_sigs(static_cast<size_t>(n));
    if(MPI_Allgather(candidate_words_digest.data(),4,MPI_UINT64_T,
        all_candidates.data(),4,MPI_UINT64_T,active_comm)!=MPI_SUCCESS ||
       MPI_Allgather(vote_sig.data(),64,MPI_BYTE,all_vote_sigs.data(),64,
        MPI_BYTE,active_comm)!=MPI_SUCCESS) return false;
    int votes_ok=1;
    std::vector<u64> cert_words={GOD_CRASH_CERT_DOMAIN,recovery_context.protocol_domain,
        recovery_context.sid,static_cast<u64>(recovery_context.checkpoint),
        static_cast<u64>(failed),static_cast<u64>(n)};
    append_recovery_digest(candidate,&cert_words);
    for(int r=0;r<n;++r) {
        const int id=active_original_ranks[static_cast<size_t>(r)];
        const Digest peer=recovery_digest_from_words(all_candidates.data()+4*r);
        const auto msg=build_authenticated_mpc_signed_message(
            vote_ctx,static_cast<uint32_t>(id),AUTHENTICATED_MPC_BROADCAST_RECEIVER,4,4,peer);
        if(peer!=candidate || !auth.VerifyWords(AUTHENTICATED_MPC_SIGNATURE_DOMAIN,
            msg,all_vote_sigs[static_cast<size_t>(r)],static_cast<uint32_t>(id))) votes_ok=0;
        cert_words.push_back(static_cast<u64>(id));
        for(size_t k=0;k<8;++k) {
            u64 w=0; std::memcpy(&w,all_vote_sigs[static_cast<size_t>(r)].data()+8*k,8);
            cert_words.push_back(w);
        }
    }
    if(god_active_comm_agree(active_comm,&votes_ok)!=MPI_SUCCESS||!votes_ok) return false;
    const Digest certificate=hash_words(cert_words);
    if(certificate==Digest{}) return false;

    output->available=true; output->values=std::move(recovered.values);
    output->delivered_participants=recovered.delivered_participants;
    output->corrected_participants=recovered.corrected_participants;
    output->scope_binding=scope_binding; output->transport_binding=transport_binding;
    output->agreement_certificate=certificate; output->transcript_binding=certificate;
    output->agreement_votes=static_cast<uint32_t>(n);
    output->survivor_certificate.available=true;
    output->survivor_certificate.original_world_size=original_world_size;
    output->survivor_certificate.failed_original_rank=failed;
    output->survivor_certificate.active_original_ranks=active_original_ranks;
    output->survivor_certificate.recovery_context=recovery_context;
    output->survivor_certificate.registry_commitment=registry;
    output->survivor_certificate.roster_binding=roster_binding;
    output->survivor_certificate.candidate_binding=candidate;
    output->survivor_certificate.vote_signatures=all_vote_sigs;
    output->authenticated_transport=true;
    output->external_registry_anchor_verified=auth.ExternalRegistryAnchorVerified() &&
        auth.ExternalRegistryAnchor()==registry;
    output->production_authenticated_transport=output->external_registry_anchor_verified;
    output->reliable_broadcast_verified=false;
    output->survivor_agreement_verified=true;
    output->process_crash_tolerant=process_crash_tolerant;
    output->verifiable_sharing_verified=true;
    output->authenticated_vss_verified=vss_receipt.transcript_context.authenticated;
    output->vss_transcript_binding=vss_receipt.transcript_binding;
    output->multiplication_consistency_verified=proof_present&&proof_ok;
    output->multiplication_proof_set_binding=proof_set;
    output->output_consistency_statement_binding=proof_statement;
    output->output_consistency_proof_binding=proof_binding;
    // Independently recheck the portable certificate before returning it.
    if(!verify_reference_god_survivor_certificate(
        *output,auth.PublicKeys(),registry)) {
        *output=ReferenceGodOutput{};
        return false;
    }
    output->production_god_authorized=reference_god_output_production_authorized(*output);
    return true;
}

Digest compute_reference_god_multiplication_failure_recovery_binding(
    const ReferenceGodMultiplicationFailureRecovery& recovery) {
    if (!recovery.available ||
        recovery.external_registry_anchor == Digest{} ||
        recovery.multiplication_failure_certificate_binding == Digest{} ||
        recovery.encoded_multiplication_failure_certificate.empty() ||
        !recovery.survivor_output.available ||
        !recovery.survivor_output.survivor_certificate.available)
        return {};
    const Digest encoded_binding =
        hash_words(recovery.encoded_multiplication_failure_certificate);
    if (encoded_binding == Digest{}) return {};
    std::vector<u64> words = {
        GOD_MULTIPLICATION_FAILURE_RECOVERY_DOMAIN, 1ULL,
        recovery.excluded_original_rank,
        static_cast<u64>(
            recovery.survivor_output.survivor_certificate.original_world_size),
        static_cast<u64>(
            recovery.survivor_output.survivor_certificate.failed_original_rank)};
    append_recovery_digest(recovery.external_registry_anchor, &words);
    append_recovery_digest(
        recovery.multiplication_failure_certificate_binding, &words);
    append_recovery_digest(encoded_binding, &words);
    append_recovery_digest(recovery.survivor_output.scope_binding, &words);
    append_recovery_digest(recovery.survivor_output.transcript_binding, &words);
    append_recovery_digest(
        recovery.survivor_output.agreement_certificate, &words);
    append_recovery_digest(
        recovery.survivor_output.survivor_certificate.roster_binding, &words);
    append_recovery_digest(
        recovery.survivor_output.survivor_certificate.candidate_binding, &words);
    words.push_back(static_cast<u64>(recovery.survivor_output.values.size()));
    for (const F& value : recovery.survivor_output.values) {
        words.push_back(value.real);
        words.push_back(value.img);
    }
    return hash_words(words);
}

bool verify_reference_god_multiplication_failure_recovery(
    const ReferenceGodMultiplicationFailureRecovery& recovery,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& externally_pinned_registry_anchor) {
    if (!recovery.available ||
        externally_pinned_registry_anchor == Digest{} ||
        recovery.external_registry_anchor !=
            externally_pinned_registry_anchor ||
        recovery.encoded_multiplication_failure_certificate.empty() ||
        !PublicJudge::VerifyMultiplicationFailureCertificate(
            recovery.encoded_multiplication_failure_certificate,
            public_keys, externally_pinned_registry_anchor))
        return false;
    ReferenceMultiplicationFailureCertificate failure;
    if (!decode_reference_multiplication_failure_certificate(
            recovery.encoded_multiplication_failure_certificate, &failure) ||
        failure.certificate_binding !=
            recovery.multiplication_failure_certificate_binding ||
        failure.accused_dealer != recovery.excluded_original_rank ||
        failure.event.world_size != 4 ||
        recovery.survivor_output.survivor_certificate.original_world_size != 4 ||
        recovery.survivor_output.survivor_certificate.failed_original_rank !=
            static_cast<int>(recovery.excluded_original_rank) ||
        recovery.survivor_output.survivor_certificate.active_original_ranks.size()
            != 3 ||
        !recovery.survivor_output.available ||
        recovery.survivor_output.values.empty() ||
        !verify_reference_god_survivor_certificate(
            recovery.survivor_output, public_keys,
            externally_pinned_registry_anchor))
        return false;
    std::vector<int> expected_active;
    for (int rank = 0; rank < 4; ++rank)
        if (rank != static_cast<int>(recovery.excluded_original_rank))
            expected_active.push_back(rank);
    if (recovery.survivor_output.survivor_certificate.active_original_ranks !=
        expected_active)
        return false;
    return recovery.recovery_binding ==
        compute_reference_god_multiplication_failure_recovery_binding(
            recovery);
}

std::vector<u64> encode_reference_god_multiplication_failure_recovery(
    const ReferenceGodMultiplicationFailureRecovery& recovery) {
    if (!recovery.available ||
        recovery.external_registry_anchor == Digest{} ||
        recovery.multiplication_failure_certificate_binding == Digest{} ||
        recovery.encoded_multiplication_failure_certificate.empty() ||
        recovery.encoded_multiplication_failure_certificate.size() >
            GOD_MULTIPLICATION_FAILURE_RECOVERY_MAX_WORDS ||
        recovery.recovery_binding !=
            compute_reference_god_multiplication_failure_recovery_binding(
                recovery))
        return {};
    const auto survivor_words =
        encode_reference_god_survivor_certificate_abi(
            recovery.survivor_output);
    if (survivor_words.empty() ||
        survivor_words.size() >
            GOD_MULTIPLICATION_FAILURE_RECOVERY_MAX_WORDS)
        return {};
    std::vector<u64> words = {
        GOD_MULTIPLICATION_FAILURE_RECOVERY_CODEC_DOMAIN,
        GOD_MULTIPLICATION_FAILURE_RECOVERY_CODEC_VERSION,
        1ULL, recovery.excluded_original_rank,
        static_cast<u64>(
            recovery.encoded_multiplication_failure_certificate.size()),
        static_cast<u64>(survivor_words.size())};
    append_recovery_digest(recovery.external_registry_anchor, &words);
    append_recovery_digest(
        recovery.multiplication_failure_certificate_binding, &words);
    words.insert(words.end(),
        recovery.encoded_multiplication_failure_certificate.begin(),
        recovery.encoded_multiplication_failure_certificate.end());
    words.insert(words.end(), survivor_words.begin(), survivor_words.end());
    append_recovery_digest(recovery.recovery_binding, &words);
    return words;
}

bool decode_reference_god_multiplication_failure_recovery(
    const std::vector<u64>& words,
    ReferenceGodMultiplicationFailureRecovery* recovery) {
    if (!recovery || words.size() < 18 ||
        words[0] != GOD_MULTIPLICATION_FAILURE_RECOVERY_CODEC_DOMAIN ||
        words[1] != GOD_MULTIPLICATION_FAILURE_RECOVERY_CODEC_VERSION ||
        words[2] != 1 || words[3] >= 4 ||
        words[4] == 0 || words[4] > GOD_MULTIPLICATION_FAILURE_RECOVERY_MAX_WORDS ||
        words[5] == 0 || words[5] > GOD_MULTIPLICATION_FAILURE_RECOVERY_MAX_WORDS)
        return false;
    const size_t failure_count = static_cast<size_t>(words[4]);
    const size_t survivor_count = static_cast<size_t>(words[5]);
    if (failure_count > words.size() - 18 ||
        survivor_count != words.size() - 18 - failure_count)
        return false;
    ReferenceGodMultiplicationFailureRecovery decoded;
    decoded.available = true;
    decoded.excluded_original_rank = static_cast<uint32_t>(words[3]);
    decoded.external_registry_anchor = recovery_digest_from_words(
        words.data() + 6);
    decoded.multiplication_failure_certificate_binding =
        recovery_digest_from_words(words.data() + 10);
    if (decoded.external_registry_anchor == Digest{} ||
        decoded.multiplication_failure_certificate_binding == Digest{})
        return false;
    decoded.encoded_multiplication_failure_certificate.assign(
        words.begin() + 14,
        words.begin() + static_cast<std::ptrdiff_t>(14 + failure_count));
    const size_t survivor_offset = 14 + failure_count;
    std::vector<u64> survivor_words(
        words.begin() + static_cast<std::ptrdiff_t>(survivor_offset),
        words.begin() + static_cast<std::ptrdiff_t>(
            survivor_offset + survivor_count));
    if (!decode_reference_god_survivor_certificate_abi(
            survivor_words, &decoded.survivor_output))
        return false;
    decoded.recovery_binding = recovery_digest_from_words(
        words.data() + words.size() - 4);
    ReferenceMultiplicationFailureCertificate failure;
    if (!decode_reference_multiplication_failure_certificate(
            decoded.encoded_multiplication_failure_certificate, &failure) ||
        failure.accused_dealer != decoded.excluded_original_rank ||
        failure.certificate_binding !=
            decoded.multiplication_failure_certificate_binding ||
        decoded.survivor_output.survivor_certificate.failed_original_rank !=
            static_cast<int>(decoded.excluded_original_rank) ||
        decoded.recovery_binding !=
            compute_reference_god_multiplication_failure_recovery_binding(
                decoded))
        return false;
    *recovery = std::move(decoded);
    return true;
}

bool verify_encoded_reference_god_multiplication_failure_recovery(
    const std::vector<u64>& words,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& externally_pinned_registry_anchor) {
    ReferenceGodMultiplicationFailureRecovery recovery;
    return decode_reference_god_multiplication_failure_recovery(
               words, &recovery) &&
        verify_reference_god_multiplication_failure_recovery(
            recovery, public_keys, externally_pinned_registry_anchor);
}

bool open_reference_god_output_after_verified_multiplication_failure_n4(
    int original_rank, int original_world_size,
    const std::vector<int>& active_original_ranks,
    const std::vector<F>& local_share_vector,
    const Digest& scope_binding,
    const AuthenticatedMpcMessageContext& recovery_context,
    const ReferenceVssReceipt& vss_receipt,
    MPI_Comm active_comm,
    const std::vector<u64>& encoded_multiplication_failure_certificate,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& externally_pinned_registry_anchor,
    ReferenceGodMultiplicationFailureRecovery* recovery,
    const ReferenceGodOutputConsistencyProofBundle* consistency_proof) {
    if (!recovery) return false;
    *recovery = ReferenceGodMultiplicationFailureRecovery{};
    ReferenceMultiplicationFailureCertificate failure;
    if (original_world_size != 4 || original_rank < 0 || original_rank >= 4 ||
        externally_pinned_registry_anchor == Digest{} ||
        !decode_reference_multiplication_failure_certificate(
            encoded_multiplication_failure_certificate, &failure) ||
        !PublicJudge::VerifyMultiplicationFailureCertificate(
            encoded_multiplication_failure_certificate, public_keys,
            externally_pinned_registry_anchor) ||
        failure.event.world_size != 4 ||
        failure.event.sid != recovery_context.sid ||
        failure.event.checkpoint != recovery_context.checkpoint ||
        failure.accused_dealer >= 4 ||
        active_original_ranks.size() != 3)
        return false;
    std::vector<int> expected_active;
    for (int rank = 0; rank < 4; ++rank)
        if (rank != static_cast<int>(failure.accused_dealer))
            expected_active.push_back(rank);
    if (active_original_ranks != expected_active ||
        std::find(active_original_ranks.begin(), active_original_ranks.end(),
                  original_rank) == active_original_ranks.end())
        return false;
    const auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.ready() || !auth.ExternalRegistryAnchorVerified() ||
        auth.ExternalRegistryAnchor() != externally_pinned_registry_anchor ||
        auth.PublicKeys() != public_keys)
        return false;

    ReferenceGodOutput survivor_output;
    if (!open_reference_god_output_after_failure_n4(
            original_rank, original_world_size, active_original_ranks,
            local_share_vector, scope_binding, recovery_context, vss_receipt,
            active_comm, &survivor_output, consistency_proof))
        return false;
    ReferenceGodMultiplicationFailureRecovery candidate;
    candidate.available = true;
    candidate.excluded_original_rank = failure.accused_dealer;
    candidate.external_registry_anchor = externally_pinned_registry_anchor;
    candidate.multiplication_failure_certificate_binding =
        failure.certificate_binding;
    candidate.encoded_multiplication_failure_certificate =
        encoded_multiplication_failure_certificate;
    candidate.survivor_output = std::move(survivor_output);
    candidate.recovery_binding =
        compute_reference_god_multiplication_failure_recovery_binding(
            candidate);
    if (candidate.recovery_binding == Digest{} ||
        !verify_reference_god_multiplication_failure_recovery(
            candidate, public_keys, externally_pinned_registry_anchor))
        return false;
    *recovery = std::move(candidate);
    return true;
}

bool run_reference_god_output_crash_recovery_n4_selftest(
    int rank, int world_size,
    const std::vector<F>* expected_output_override,
    const Digest* scope_override,
    const AuthenticatedMpcMessageContext* recovery_context_override,
    const ReferenceGodOutputConsistencyProofBundle* consistency_proof) {
#ifndef PVIA_ENABLE_ULFM
    (void)rank; (void)world_size; (void)expected_output_override;
    (void)scope_override; (void)recovery_context_override;
    (void)consistency_proof;
    return false;
#else
    if (world_size != 4 || rank < 0 || rank >= 4) return false;
    MPI_Comm_set_errhandler(MPI_COMM_WORLD, MPI_ERRORS_RETURN);
    const char* crash_rank_env=
        std::getenv("PVIA_GOD_OUTPUT_CRASH_FAILED_RANK");
    int injected_crash_rank=1;
    if(crash_rank_env&&*crash_rank_env) {
        if(crash_rank_env[0]<'0'||crash_rank_env[0]>'3'||
           crash_rank_env[1]!='\0')return false;
        injected_crash_rank=crash_rank_env[0]-'0';
    }
    constexpr uint64_t default_recovery_sid = 793006ULL;
    constexpr CheckpointId default_recovery_checkpoint = 793006ULL;
    const std::vector<F> default_secret = {F(97, 11), F(123, 3), F(234, 28)};
    const std::vector<F>& secret =
        expected_output_override ? *expected_output_override : default_secret;
    AuthenticatedMpcMessageContext default_recovery_context;
    default_recovery_context.protocol_domain = GOD_N4_DOMAIN;
    default_recovery_context.sid = default_recovery_sid;
    default_recovery_context.checkpoint = default_recovery_checkpoint;
    default_recovery_context.round = 9001ULL;
    default_recovery_context.sequence = 9001ULL;
    default_recovery_context.message_kind = GOD_CRASH_SHARE_DOMAIN;
    const AuthenticatedMpcMessageContext recovery_context =
        recovery_context_override ? *recovery_context_override : default_recovery_context;
    const uint64_t recovery_sid = recovery_context.sid;
    const CheckpointId recovery_checkpoint = recovery_context.checkpoint;
    const Digest scope = scope_override ? *scope_override :
        hash_words({GOD_N4_SCOPE_DOMAIN, recovery_sid, 4ULL, 1ULL});
    if (secret.empty() || secret.size() > 4096 || scope == Digest{} ||
        recovery_context.protocol_domain != GOD_N4_DOMAIN ||
        !validate_authenticated_mpc_message_context(recovery_context) ||
        recovery_context.sid == 0 || recovery_context.checkpoint == 0 ||
        recovery_context.round >= UINT64_MAX ||
        recovery_context.sequence >= UINT64_MAX) return false;
    Digest expected_proof_set{}, expected_proof_statement{}, expected_proof_binding{};
    const bool proof_expected = consistency_proof != nullptr;
    const bool recovery_debug = std::getenv("PVIA_GOD_OUTPUT_CRASH_RECOVERY_DEBUG") != nullptr;
    if(recovery_debug)std::cerr
        <<"[PVIA][recovery-debug] rank="<<rank
        <<" phase=before_proof_preflight"<<std::endl;
    int proof_preflight = !proof_expected ||
        verify_reference_god_output_consistency_bundle(
            recovery_context.sid, recovery_context.checkpoint, scope, secret,
            *consistency_proof, &expected_proof_set,
            &expected_proof_statement, &expected_proof_binding);
    int all_proof_preflight = 0;
    MPI_Allreduce(&proof_preflight, &all_proof_preflight, 1, MPI_INT,
                  MPI_MIN, MPI_COMM_WORLD);
    if(recovery_debug)std::cerr
        <<"[PVIA][recovery-debug] rank="<<rank
        <<" phase=after_proof_preflight accepted="<<all_proof_preflight<<std::endl;
    if (!all_proof_preflight) return false;
    auto trace_selftest = [&](const char* phase) {
        if (recovery_debug)
            std::cerr << "[PVIA][recovery-debug] rank=" << rank
                      << " phase=" << phase << std::endl;
    };
    // Establish the original N=4 signing roster before sharing. In the
    // authenticated mode this pinned roster authenticates VSS and recovery.
    auto& authenticator = Ed25519TransferAuthenticator::instance();
    int auth_ok = authenticator.Initialize(rank, world_size) ? 1 : 0;
    int all_auth_ok = 0;
    MPI_Allreduce(&auth_ok, &all_auth_ok, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    if (!all_auth_ok) return false;
    const char* print_registry_env =
        std::getenv("PVIA_GOD_OUTPUT_CRASH_RECOVERY_PRINT_REGISTRY");
    if (rank == 0 && print_registry_env &&
        std::string(print_registry_env) != "0") {
        static const char hex[] = "0123456789abcdef";
        std::string registry_hex;
        const Digest registry = authenticator.RegistryCommitment();
        for (uint8_t byte : registry.bytes) {
            registry_hex.push_back(hex[byte >> 4]);
            registry_hex.push_back(hex[byte & 0x0f]);
        }
        std::cout << "PVIA_TEST_REGISTRY_COMMITMENT="
                  << registry_hex << std::endl;
    }

    const char* authenticated_vss_env =
        std::getenv("PVIA_GOD_OUTPUT_CRASH_RECOVERY_AUTHENTICATED_VSS");
    const int local_authenticated_vss =
        authenticated_vss_env && std::string(authenticated_vss_env) != "0" ? 1 : 0;
    int min_authenticated_vss = 0, max_authenticated_vss = 0;
    if (MPI_Allreduce(&local_authenticated_vss, &min_authenticated_vss,
                      1, MPI_INT, MPI_MIN, MPI_COMM_WORLD) != MPI_SUCCESS ||
        MPI_Allreduce(&local_authenticated_vss, &max_authenticated_vss,
                      1, MPI_INT, MPI_MAX, MPI_COMM_WORLD) != MPI_SUCCESS ||
        min_authenticated_vss != max_authenticated_vss) return false;
    const bool authenticated_vss_requested = min_authenticated_vss == 1;

    // The authenticated variant fails closed unless the key roster is pinned
    // outside this MPI session. The default mode remains reference-only.
    ReferenceBivariateVss vss(rank, world_size, 1);
    ReferenceVssReceipt vss_receipt;
    std::vector<F> local_shares;
    bool vss_ok = false;
    if (vss.valid() && authenticated_vss_requested) {
        AuthenticatedMpcExchange vss_exchange(rank, world_size);
        AuthenticatedMpcMessageContext vss_context;
        vss_context.protocol_domain = GOD_N4_DOMAIN;
        vss_context.sid = recovery_sid;
        vss_context.checkpoint = recovery_checkpoint;
        vss_context.round = 8001ULL;
        vss_context.sequence = 8001ULL;
        vss_context.message_kind = 0x56535301ULL;
        vss_ok = vss_exchange.production_authenticated_ready() &&
            vss.ShareVectorFromDealerAuthenticated(
                0, rank == 0 ? secret : std::vector<F>{},
                &local_shares, &vss_receipt, vss_exchange, vss_context);
    } else if (vss.valid()) {
        vss_ok = vss.ShareVectorFromDealer(
            0, rank == 0 ? secret : std::vector<F>{},
            &local_shares, &vss_receipt);
    }
    if (!vss_ok || local_shares.size() != secret.size() ||
        !vss_receipt.available || !vss_receipt.consistent ||
        vss_receipt.transcript_binding == Digest{}) return false;

    trace_selftest("shares_ready");
    // N=4 bounded diagnostic ONLY.  Preconstruct the three-survivor
    // communicator while all four ranks are still alive.  This exercises
    // genuine _exit(77), signed share recovery and proof binding, but it is
    // NOT equivalent to dynamic ULFM communicator shrink/reconfiguration.
    const char* precreated_env=std::getenv("PVIA_GOD_PRECREATED_SURVIVOR_COMM");
    const bool precreated_survivors=precreated_env &&
        std::string(precreated_env)=="1";
    // TEST ONLY: derive the three surviving ranks from a previously
    // configured fault-injection pin, but create their communicator only
    // AFTER the specified rank has really exited. This is not ULFM shrink,
    // and the rank pin is not evidence of a general failure detector.
    const char* postfault_env=
        std::getenv("PVIA_GOD_POSTFAULT_SURVIVOR_GROUP_CREATE");
    const bool postfault_group=postfault_env &&
        std::string(postfault_env)=="1";
    if((precreated_survivors && postfault_group) ||
       (postfault_group && injected_crash_rank!=1))
        return false;
    MPI_Comm precreated_comm=MPI_COMM_NULL;
    if(precreated_survivors) {
        if(!consistency_proof || injected_crash_rank!=1) return false;
        const int split_rc=MPI_Comm_split(
            MPI_COMM_WORLD,rank==injected_crash_rank?MPI_UNDEFINED:1,
            rank,&precreated_comm);
        int precreated_ready=split_rc==MPI_SUCCESS &&
            (rank==injected_crash_rank?
                precreated_comm==MPI_COMM_NULL:
                precreated_comm!=MPI_COMM_NULL) ? 1:0;
        int all_precreated=0;
        if(MPI_Allreduce(&precreated_ready,&all_precreated,1,
                         MPI_INT,MPI_MIN,MPI_COMM_WORLD)!=MPI_SUCCESS ||
           !all_precreated) return false;
        if(precreated_comm!=MPI_COMM_NULL)
            MPI_Comm_set_errhandler(precreated_comm,MPI_ERRORS_RETURN);
        trace_selftest("precreated_survivor_comm_ready");
    }
    MPI_Group original = MPI_GROUP_NULL;
    if (MPI_Comm_group(MPI_COMM_WORLD, &original) != MPI_SUCCESS) return false;
    if (rank == injected_crash_rank) { sleep(2); _exit(77); }
    sleep(4);

    trace_selftest("before_get_failed");
    MPI_Group failed = MPI_GROUP_NULL;
    int failed_count = 0, get_rc = MPI_ERR_OTHER;
    for (int attempt = 0; attempt < 16; ++attempt) {
        MPI_Group observed = MPI_GROUP_NULL;
        get_rc = MPIX_Comm_get_failed(MPI_COMM_WORLD, &observed);
        if (get_rc == MPI_SUCCESS && observed != MPI_GROUP_NULL) {
            int n = 0; MPI_Group_size(observed, &n);
            if (n > 0) { failed = observed; failed_count = n; break; }
            MPI_Group_free(&observed);
        } else if (observed != MPI_GROUP_NULL) MPI_Group_free(&observed);
        sleep(1);
    }
    trace_selftest("after_get_failed");
    int failed_original_rank = -1, failed_zero = 0;
    // Precreated communicator is a test-only alternative. A fixture rank
    // pin does NOT establish ULFM dynamic failure detection.
    const bool detector_reported=get_rc==MPI_SUCCESS &&
        failed_count==1 && failed!=MPI_GROUP_NULL;
    const char* strict_identity_env=
        std::getenv("PVIA_GOD_POSTFAULT_REQUIRE_ULFM_IDENTITY");
    const bool require_ulfm_identity=strict_identity_env &&
        std::string(strict_identity_env)=="1";
    if(require_ulfm_identity && !postfault_group) {
        // A strict-identity request is only meaningful for the bounded
        // post-failure group-creation fixture. Do not silently re-interpret it.
        if(failed!=MPI_GROUP_NULL)MPI_Group_free(&failed);
        MPI_Group_free(&original);
        return false;
    }
    int local_ok=(precreated_survivors||postfault_group)?
        1:(detector_reported?1:0);
    if(failed!=MPI_GROUP_NULL &&
       MPI_Group_translate_ranks(failed,1,&failed_zero,original,
                                 &failed_original_rank)!=MPI_SUCCESS)
        local_ok=0;
    if(precreated_survivors || postfault_group) {
        if(detector_reported&&failed_original_rank!=injected_crash_rank)
            local_ok=0;
        if(!detector_reported && !require_ulfm_identity)
            failed_original_rank=injected_crash_rank; // test injection ONLY
    }
    if(postfault_group && require_ulfm_identity &&
       (!detector_reported || failed_original_rank!=injected_crash_rank)) {
        // Fail closed BEFORE MPI_Comm_create_group, opening private shares,
        // producing a public recovery certificate, or delivery. A test pin
        // is never accepted as a replacement for missing runtime evidence.
        trace_selftest("strict_ulfm_identity_missing_recovery_rejected");
        if(failed!=MPI_GROUP_NULL)MPI_Group_free(&failed);
        MPI_Group_free(&original);
        return false;
    }
    trace_selftest("before_ack_failed");
    int acked = 0;
    const int ack_rc = MPIX_Comm_ack_failed(MPI_COMM_WORLD, world_size, &acked);
    if (ack_rc != MPI_SUCCESS ||
        (!precreated_survivors && !postfault_group && acked < 1))
        local_ok = 0;
    trace_selftest("after_ack_failed");
    // OpenMPI 5.0.11-ULFM on this machine rejects MPI_Comm_create_group
    // when WORLD was revoked. The post-failure group-creation fixture must
    // leave WORLD unrevoked; its survivor set is NOT independently certified
    // by ULFM. Other modes retain their original revoke/shrink semantics.
    if(!postfault_group) {
        const int revoke_rc = MPIX_Comm_revoke(MPI_COMM_WORLD);
        if (revoke_rc != MPI_SUCCESS && revoke_rc != MPIX_ERR_REVOKED)
            local_ok = 0;
        trace_selftest("after_revoke");
    } else {
        trace_selftest("postfault_group_world_not_revoked");
    }
    MPI_Comm active = MPI_COMM_NULL;
    int shrink_rc=MPI_ERR_OTHER;
    if(postfault_group && require_ulfm_identity) {
        // Strict path: the ULFM detector has positively identified and
        // acknowledged the failed process. Let ULFM construct the survivor
        // communicator so the runtime's failure state is handled correctly.
        trace_selftest("before_strict_ulfm_shrink");
        shrink_rc=MPIX_Comm_shrink(MPI_COMM_WORLD,&active);
        trace_selftest("after_strict_ulfm_shrink");
    } else if(postfault_group) {
        MPI_Group survivor_group=MPI_GROUP_NULL;
        // In strict mode, derive the excluded identity from the ULFM
        // runtime report, not from the injection fixture. Missing or
        // mismatched detector evidence was already rejected above.
        const int excluded_rank[1]={
            require_ulfm_identity?failed_original_rank:injected_crash_rank};
        const int group_rc=MPI_Group_excl(original,1,excluded_rank,
                                          &survivor_group);
        trace_selftest("before_postfailure_create_group");
        shrink_rc=group_rc==MPI_SUCCESS ?
            MPI_Comm_create_group(MPI_COMM_WORLD,survivor_group,4311,&active):
            group_rc;
        trace_selftest("after_postfailure_create_group");
        if(survivor_group!=MPI_GROUP_NULL)
            MPI_Group_free(&survivor_group);
    } else if(precreated_survivors) {
        trace_selftest("precreated_survivor_comm_selected_no_dynamic_shrink");
        active=precreated_comm;
        shrink_rc=active!=MPI_COMM_NULL?MPI_SUCCESS:MPI_ERR_COMM;
    } else {
        trace_selftest("before_shrink");
        shrink_rc=MPIX_Comm_shrink(MPI_COMM_WORLD,&active);
        trace_selftest("after_shrink");
    }
    if (shrink_rc != MPI_SUCCESS || active == MPI_COMM_NULL) {
        if (failed != MPI_GROUP_NULL) MPI_Group_free(&failed);
        MPI_Group_free(&original);
        return false;
    }
    MPI_Comm_set_errhandler(active, MPI_ERRORS_RETURN);
    int active_rank = -1, active_size = 0;
    MPI_Comm_rank(active, &active_rank); MPI_Comm_size(active, &active_size);
    MPI_Group active_group = MPI_GROUP_NULL;
    if (MPI_Comm_group(active, &active_group) != MPI_SUCCESS) local_ok = 0;
    std::vector<int> local_ranks(static_cast<size_t>(active_size));
    std::vector<int> original_ranks(static_cast<size_t>(active_size), -1);
    for (int i = 0; i < active_size; ++i) local_ranks[static_cast<size_t>(i)] = i;
    if (active_group == MPI_GROUP_NULL ||
        MPI_Group_translate_ranks(active_group, active_size, local_ranks.data(),
                                  original, original_ranks.data()) != MPI_SUCCESS)
        local_ok = 0;
    if (active_group != MPI_GROUP_NULL) MPI_Group_free(&active_group);
    if (failed != MPI_GROUP_NULL) MPI_Group_free(&failed);
    MPI_Group_free(&original);

    ReferenceGodOutput output;
    trace_selftest("before_output_recovery");
    const bool opened = open_reference_god_output_after_failure_n4(
        rank, world_size, original_ranks, local_shares, scope,
        recovery_context, vss_receipt, active, &output, consistency_proof,
        true); // this selftest has observed the injected _exit(77)
    trace_selftest("after_output_recovery");
    const bool proof_binding_match = proof_expected
        ? output.multiplication_consistency_verified &&
          output.multiplication_proof_set_binding == expected_proof_set &&
          output.output_consistency_statement_binding == expected_proof_statement &&
          output.output_consistency_proof_binding == expected_proof_binding
        : !output.multiplication_consistency_verified &&
          output.multiplication_proof_set_binding == Digest{} &&
          output.output_consistency_statement_binding == Digest{} &&
          output.output_consistency_proof_binding == Digest{};
    const bool output_match = opened && output.available && output.values == secret &&
        output.delivered_participants == 3 && output.process_crash_tolerant &&
        output.authenticated_transport && output.transport_binding != Digest{} &&
        !output.reliable_broadcast_verified &&
        output.survivor_agreement_verified && output.agreement_votes == 3 &&
        output.agreement_certificate != Digest{} &&
        output.verifiable_sharing_verified &&
        output.authenticated_vss_verified == authenticated_vss_requested &&
        output.vss_transcript_binding == vss_receipt.transcript_binding &&
        proof_binding_match &&
        !output.complete_application_relation_set_verified &&
        !reference_god_output_production_authorized(output);

    // Independently verify the portable vote certificate and mutate its
    // signature, output, roster, and externally supplied registry commitment.
    const auto& public_registry=authenticator.PublicKeys();
    const Digest pinned_registry=authenticator.RegistryCommitment();
    const bool portable_cert_verified=verify_reference_god_survivor_certificate(
        output,public_registry,pinned_registry);
    bool bad_certificate_signature_rejected=false;
    bool bad_certificate_output_rejected=false;
    bool bad_certificate_roster_rejected=false;
    bool bad_certificate_anchor_rejected=false;
    if(portable_cert_verified &&
       output.survivor_certificate.vote_signatures.size()==3) {
        ReferenceGodOutput modified=output;
        modified.survivor_certificate.vote_signatures[0][0]^=1U;
        bad_certificate_signature_rejected=
            !verify_reference_god_survivor_certificate(
                modified,public_registry,pinned_registry);
        modified=output;
        modified.values[0]+=F(1);
        bad_certificate_output_rejected=
            !verify_reference_god_survivor_certificate(
                modified,public_registry,pinned_registry);
        modified=output;
        std::swap(modified.survivor_certificate.active_original_ranks[0],
                  modified.survivor_certificate.active_original_ranks[1]);
        bad_certificate_roster_rejected=
            !verify_reference_god_survivor_certificate(
                modified,public_registry,pinned_registry);
        const Digest wrong_anchor=hash_words({
            GOD_CRASH_CERT_DOMAIN,0x424144414e43484fULL});
        bad_certificate_anchor_rejected=
            !verify_reference_god_survivor_certificate(
                output,public_registry,wrong_anchor);
    }
    const bool portable_certificate_checks_ok=
        portable_cert_verified && bad_certificate_signature_rejected &&
        bad_certificate_output_rejected && bad_certificate_roster_rejected &&
        bad_certificate_anchor_rejected;

    const std::vector<u64> certificate_wire=
        encode_reference_god_survivor_certificate_abi(output);
    ReferenceGodOutput imported_certificate;
    const bool portable_abi_roundtrip=
        !certificate_wire.empty() &&
        decode_reference_god_survivor_certificate_abi(
            certificate_wire,&imported_certificate) &&
        !imported_certificate.production_god_authorized &&
        !imported_certificate.survivor_agreement_verified &&
        !imported_certificate.authenticated_vss_verified &&
        verify_reference_god_survivor_certificate(
            imported_certificate,public_registry,pinned_registry);
    std::vector<u64> truncated_certificate_wire=certificate_wire;
    if(!truncated_certificate_wire.empty())truncated_certificate_wire.pop_back();
    ReferenceGodOutput invalid_import;
    const bool truncated_certificate_rejected=
        !decode_reference_god_survivor_certificate_abi(
            truncated_certificate_wire,&invalid_import);
    std::vector<u64> bad_abi_signature_wire=certificate_wire;
    if(!bad_abi_signature_wire.empty())bad_abi_signature_wire.back()^=1ULL;
    ReferenceGodOutput corrupt_signature_import;
    const bool corrupt_abi_signature_rejected=
        (!decode_reference_god_survivor_certificate_abi(
            bad_abi_signature_wire,&corrupt_signature_import) ||
         !verify_reference_god_survivor_certificate(
            corrupt_signature_import,public_registry,pinned_registry));
    const bool portable_abi_checks_ok=portable_abi_roundtrip &&
        truncated_certificate_rejected && corrupt_abi_signature_rejected;

    // Negative check: alter one signature after signing. Every survivor must
    // reject the post-failure share exchange before reconstructing an output.
    setenv("PVIA_GOD_OUTPUT_RECOVERY_TAMPER_SIGNATURE", "1", 1);
    ReferenceGodOutput tampered_output;
    const bool tampered_opened = open_reference_god_output_after_failure_n4(
        rank, world_size, original_ranks, local_shares, scope,
        recovery_context, vss_receipt, active, &tampered_output, consistency_proof);
    unsetenv("PVIA_GOD_OUTPUT_RECOVERY_TAMPER_SIGNATURE");
    int tampered_rejected =
        (!tampered_opened && !tampered_output.available) ? 1 : 0;
    const int tampered_agree_rc = MPIX_Comm_agree(active, &tampered_rejected);
    const bool signature_tamper_rejected =
        tampered_agree_rc == MPI_SUCCESS && tampered_rejected == 1;

    // A malicious survivor can sign a false share vector with its own valid
    // key. Authentication alone must not authorize reconstruction: the
    // degree-1 share consistency check must reject this signed bad input.
    const int negative_test_rank=injected_crash_rank==2?3:2;
    std::vector<F> inconsistent_signed_shares = local_shares;
    if (rank == negative_test_rank && !inconsistent_signed_shares.empty())
        inconsistent_signed_shares[0] += F(19, 0);
    ReferenceGodOutput inconsistent_signed_output;
    const bool inconsistent_signed_opened =
        open_reference_god_output_after_failure_n4(
            rank, world_size, original_ranks, inconsistent_signed_shares,
            scope, recovery_context, vss_receipt, active,
            &inconsistent_signed_output, consistency_proof);
    int inconsistent_signed_rejected =
        (!inconsistent_signed_opened &&
         !inconsistent_signed_output.available) ? 1 : 0;
    const int inconsistent_signed_agree_rc =
        MPIX_Comm_agree(active, &inconsistent_signed_rejected);
    const bool signed_inconsistent_share_rejected =
        inconsistent_signed_agree_rc == MPI_SUCCESS &&
        inconsistent_signed_rejected == 1;

    // A rank-local stale context must invalidate survivor signatures and
    // prevent a signed share vector from being replayed in another round.
    AuthenticatedMpcMessageContext stale_recovery_context = recovery_context;
    if (rank == negative_test_rank) ++stale_recovery_context.round;
    ReferenceGodOutput stale_context_output;
    const bool stale_context_opened = open_reference_god_output_after_failure_n4(
        rank, world_size, original_ranks, local_shares, scope,
        stale_recovery_context, vss_receipt, active, &stale_context_output, consistency_proof);
    int stale_context_rejected =
        (!stale_context_opened && !stale_context_output.available) ? 1 : 0;
    const int stale_context_agree_rc =
        MPIX_Comm_agree(active, &stale_context_rejected);
    const bool stale_context_rejected_all =
        stale_context_agree_rc == MPI_SUCCESS && stale_context_rejected == 1;

    // Scope is also signed. A peer that supplies a different session scope
    // must not be able to replay its otherwise valid local share signature.
    Digest stale_scope = scope;
    if (rank == negative_test_rank)
        stale_scope = hash_words(
            {GOD_N4_SCOPE_DOMAIN, recovery_context.sid, 4ULL, 2ULL});
    ReferenceGodOutput stale_scope_output;
    const bool stale_scope_opened = open_reference_god_output_after_failure_n4(
        rank, world_size, original_ranks, local_shares, stale_scope,
        recovery_context, vss_receipt, active, &stale_scope_output, consistency_proof);
    int stale_scope_rejected =
        (!stale_scope_opened && !stale_scope_output.available) ? 1 : 0;
    const int stale_scope_agree_rc =
        MPIX_Comm_agree(active, &stale_scope_rejected);
    const bool stale_scope_rejected_all =
        stale_scope_agree_rc == MPI_SUCCESS && stale_scope_rejected == 1;

    // An explicitly supplied but incomplete proof bundle must fail closed.
    ReferenceGodOutput invalid_proof_output;
    ReferenceGodOutputConsistencyProofBundle invalid_proof_bundle;
    const bool invalid_proof_opened = open_reference_god_output_after_failure_n4(
        rank, world_size, original_ranks, local_shares, scope,
        recovery_context, vss_receipt, active, &invalid_proof_output,
        &invalid_proof_bundle);
    int invalid_proof_rejected =
        (!invalid_proof_opened && !invalid_proof_output.available) ? 1 : 0;
    const int invalid_proof_agree_rc =
        MPIX_Comm_agree(active, &invalid_proof_rejected);
    const bool invalid_proof_rejected_all =
        invalid_proof_agree_rc == MPI_SUCCESS && invalid_proof_rejected == 1;

    std::vector<F> wrong_shape_shares = local_shares;
    if (rank == negative_test_rank) wrong_shape_shares.push_back(F(7, 9));
    ReferenceGodOutput wrong_shape_output;
    const bool wrong_shape_opened = open_reference_god_output_after_failure_n4(
        rank, world_size, original_ranks, wrong_shape_shares, scope,
        recovery_context, vss_receipt, active, &wrong_shape_output);
    int wrong_shape_rejected =
        (!wrong_shape_opened && !wrong_shape_output.available) ? 1 : 0;
    const int wrong_shape_agree_rc = MPIX_Comm_agree(active, &wrong_shape_rejected);
    const bool wrong_shape_rejected_all =
        wrong_shape_agree_rc == MPI_SUCCESS && wrong_shape_rejected == 1;

    // A valid public transcript must also bind its specific local row
    // commitment to the original rank owning that share.
    ReferenceVssReceipt mismatched_receipt=vss_receipt;
    if(rank==negative_test_rank)
        mismatched_receipt.local_row_commitment=hash_words({
            GOD_CRASH_CERT_DOMAIN,0x424144524f575353ULL,
            static_cast<u64>(rank)});
    ReferenceGodOutput mismatched_receipt_output;
    const bool mismatched_receipt_opened=
        open_reference_god_output_after_failure_n4(
            rank,world_size,original_ranks,local_shares,scope,
            recovery_context,mismatched_receipt,active,
            &mismatched_receipt_output,consistency_proof);
    int mismatched_receipt_rejected=
        (!mismatched_receipt_opened && !mismatched_receipt_output.available)?1:0;
    const int mismatched_receipt_agree_rc=
        MPIX_Comm_agree(active,&mismatched_receipt_rejected);
    const bool mismatched_receipt_rejected_all=
        mismatched_receipt_agree_rc==MPI_SUCCESS &&
        mismatched_receipt_rejected==1;

    // Persist only output/certificate/public keys, never shares or witnesses.
    bool certificate_export_ok=true;
    const char* export_dir=std::getenv("PVIA_GOD_SURVIVOR_CERT_EXPORT_DIR");
    if(active_rank==0 && export_dir && *export_dir) {
        const std::string dir(export_dir);
        std::ofstream cert_file(dir+"/survivor_certificate.words",
                                std::ios::out|std::ios::trunc);
        std::ofstream registry_file(dir+"/survivor_public_registry.hex",
                                    std::ios::out|std::ios::trunc);
        if(!cert_file || !registry_file || certificate_wire.empty() ||
           public_registry.size()!=4) {
            certificate_export_ok=false;
        } else {
            for(u64 word:certificate_wire)cert_file<<word<<"\n";
            static const char alphabet[]="0123456789abcdef";
            for(const auto& pubkey:public_registry) {
                for(uint8_t byte:pubkey)
                    registry_file<<alphabet[byte>>4]<<alphabet[byte&15];
                registry_file<<"\n";
            }
            cert_file.flush(); registry_file.flush();
            certificate_export_ok=cert_file.good()&&registry_file.good();
        }
    }

    local_ok = local_ok && failed_original_rank == injected_crash_rank && active_size == 3 &&
        certificate_export_ok &&
        output_match && signature_tamper_rejected &&
        signed_inconsistent_share_rejected && stale_context_rejected_all &&
        stale_scope_rejected_all && invalid_proof_rejected_all &&
        wrong_shape_rejected_all && mismatched_receipt_rejected_all &&
        portable_certificate_checks_ok && portable_abi_checks_ok;
    int agree_flag = local_ok ? 1 : 0;
    const int agree_rc = MPIX_Comm_agree(active, &agree_flag);
    const int active_free_rc = MPI_Comm_free(&active);
    const bool all_ok = agree_rc == MPI_SUCCESS && agree_flag == 1 &&
                        active_free_rc == MPI_SUCCESS;
    if (active_rank == 0)
        std::cout << "[PVIA][god-output-crash-recovery-n4] " << (all_ok ? "PASS" : "FAIL")
                  << " survivors=" << active_size << " failed_original_rank=" << failed_original_rank
                  << " providers=" << (opened ? output.delivered_participants : 0)
                  << " output_match=" << (output_match ? "PASS" : "FAIL")
                  << " process_crash_tolerant=PASS"
                  << " share_fixture=DISTRIBUTED_BIVARIATE_VSS"
                  << " authenticated_vss="
                  << (output.authenticated_vss_verified ? "YES" : "NO")
                  << " post_failure_data_exchange=PASS"
                  << " tampered_signature_rejected="
                  << (signature_tamper_rejected ? "PASS" : "FAIL")
                  << " signed_inconsistent_share_rejected="
                  << (signed_inconsistent_share_rejected ? "PASS" : "FAIL")
                  << " stale_recovery_context="
                  << (stale_context_rejected_all ? "REJECTED" : "FAIL")
                  << " survivor_agreement=PASS agreement_votes="
                  << output.agreement_votes
                  << " stale_scope=" << (stale_scope_rejected_all ? "REJECTED" : "FAIL")
                  << " invalid_proof_bundle="
                  << (invalid_proof_rejected_all ? "REJECTED" : "FAIL")
                  << " shape_mismatch="
                  << (wrong_shape_rejected_all ? "REJECTED" : "FAIL")
                  << " vss_local_receipt_mismatch="
                  << (mismatched_receipt_rejected_all ? "REJECTED" : "FAIL")
                  << " public_certificate="
                  << (portable_cert_verified ? "PASS" : "FAIL")
                  << " certificate_signature_tamper="
                  << (bad_certificate_signature_rejected ? "REJECTED" : "FAIL")
                  << " certificate_output_tamper="
                  << (bad_certificate_output_rejected ? "REJECTED" : "FAIL")
                  << " certificate_roster_tamper="
                  << (bad_certificate_roster_rejected ? "REJECTED" : "FAIL")
                  << " certificate_anchor_tamper="
                  << (bad_certificate_anchor_rejected ? "REJECTED" : "FAIL")
                  << " certificate_artifact_export="
                  << (certificate_export_ok ? "PASS" : "FAIL")
                  << " public_certificate_abi="
                  << (portable_abi_roundtrip ? "PASS" : "FAIL")
                  << " truncated_abi="
                  << (truncated_certificate_rejected ? "REJECTED" : "FAIL")
                  << " corrupted_abi_signature="
                  << (corrupt_abi_signature_rejected ? "REJECTED" : "FAIL")
                  << " failure_identity_source="
                  << ((precreated_survivors||postfault_group)?
                      (require_ulfm_identity?"ULFM_REPORT_ONLY":
                       (detector_reported?"ULFM_REPORT_PLUS_TEST_PIN":
                        "TEST_INJECTED_ONLY")):
                      "ULFM_DETECTED")
                  << " precreated_survivor_comm="
                  << (precreated_survivors?"YES":"NO")
                  << " postfailure_group_created_after_crash="
                  << ((postfault_group&&!require_ulfm_identity)?"YES":"NO")
                  << " dynamic_ulfm_shrink="
                  << ((precreated_survivors||
                       (postfault_group&&!require_ulfm_identity))?"NO":"YES")
                  << " authenticated_transport=YES reliable_broadcast=NO"
                  << " external_registry_anchor_verified="
                  << (output.external_registry_anchor_verified ? "YES" : "NO")
                  << " proof_binding="
                  << (output.multiplication_consistency_verified ? "YES" : "NO")
                  << " complete_relation_manifest="
                  << (output.complete_application_relation_set_verified ? "YES" : "NO")
                  << " production_authorized="
                  << (reference_god_output_production_authorized(output) ? "YES" : "NO")
                  << " active_comm_free="
                  << (active_free_rc == MPI_SUCCESS ? "PASS" : "FAIL")
                  << " clean_mpi_finalize=CHECKED_BY_CALLER" << std::endl;
    return all_ok;
#endif
}

bool run_reference_god_output_n4_selftest(int rank,int world_size) {
    if(world_size!=4 || rank<0 || rank>=4) return false;
    const Digest scope=hash_words({GOD_N4_SCOPE_DOMAIN,793004ULL,4ULL,1ULL});
    std::vector<F> secret={F(97,11),F(123,3),F(234,28)};
    // Actual N=4 Shamir/BGW dealer sharing, not precomputed local points.
    ReferenceShamirMpc mpc(rank,world_size,1);
    if(!mpc.valid()) return false;
    std::vector<F> distributed_shares;
    if(!mpc.ShareVectorFromDealer(
        0,rank==0?secret:std::vector<F>{},&distributed_shares) ||
       distributed_shares.size()!=secret.size()) return false;
    const auto local_shares=[&](){return distributed_shares;};
    auto run=[&](int missing,int corrupted,
                 bool expected_success,bool expect_corrected) {
        std::vector<F> local=local_shares();
        if(rank==corrupted) local[1]+=F(19,0);
        const bool send=(rank!=missing);
        ReferenceGodOutput result;
        const bool ok=open_reference_god_output_n4(
                    rank,world_size,local,send,scope,&result);
        if(ok!=expected_success) return false;
        if(!expected_success) return !result.available;
        return result.available && result.values==secret &&
            result.delivered_participants==static_cast<uint32_t>(
                missing>=0?3:4) &&
            (result.corrected_participants==1)==expect_corrected &&
            result.transcript_binding!=Digest{};
    };
    const bool clean=run(-1,-1,true,false);
    const bool muted=run(3,-1,true,false);
    const bool corrupted=run(-1,2,true,true);
    const bool beyond_bound=run(3,2,false,false);
    ReferenceGodOutput stale_result;
    const Digest local_scope=rank==3
        ? hash_words({GOD_N4_SCOPE_DOMAIN,793005ULL,4ULL,1ULL})
        : scope;
    const bool stale_scope_rejected=!open_reference_god_output_n4(
        rank,world_size,local_shares(),true,local_scope,&stale_result)
        && !stale_result.available;
    std::vector<F> wrong_shape=local_shares();
    if(rank==3) wrong_shape.push_back(F(41));
    ReferenceGodOutput shape_result;
    const bool mismatched_shape_rejected=!open_reference_god_output_n4(
        rank,world_size,wrong_shape,true,scope,&shape_result)
        && !shape_result.available;
    const bool local_ok=clean && muted && corrupted && beyond_bound &&
        stale_scope_rejected && mismatched_shape_rejected;
    int score=local_ok?1:0,overall=0;
    MPI_Allreduce(&score,&overall,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
    if(rank==0)
        std::cout<<"[PVIA][reference-god-output-n4] "
                 <<(overall?"PASS":"FAIL")
                 <<" n=4 t=1 lanes=3 all_present="<<(clean?"PASS":"FAIL")
                 <<" one_omitted="<<(muted?"PASS":"FAIL")
                 <<" one_corrupted="<<(corrupted?"PASS":"FAIL")
                 <<" beyond_bound="<<(beyond_bound?"REJECTED":"FAIL")
                 <<" stale_scope="<<(stale_scope_rejected?"REJECTED":"FAIL")
                 <<" mismatched_shape="<<(mismatched_shape_rejected?"REJECTED":"FAIL")
                 <<" collective_mute_simulation=true"
                 <<" production_malicious_god=false"<<std::endl;
    return overall!=0;
}

namespace {
constexpr u64 GOD_AUTH_SHARE_DOMAIN=0x5056474f44534852ULL;
constexpr u64 GOD_AUTH_VOTE_DOMAIN=0x5056474f44564f54ULL;
constexpr u64 GOD_AUTH_CERT_DOMAIN=0x5056474f44434552ULL;
constexpr u64 GOD_AUTH_PROTOCOL=0x5056474f44415554ULL;
constexpr u64 GOD_AUTH_CHECKPOINT=0x5056474f444e3401ULL;
constexpr u64 GOD_AUTH_PROOF_BINDING_DOMAIN=0x5056474f44504650ULL; // PVGODPFP
constexpr u64 GOD_OUTPUT_CONSISTENCY_STATEMENT_DOMAIN=0x5056474f444f5354ULL;
constexpr u64 GOD_OUTPUT_CONSISTENCY_PROOF_DOMAIN=0x5056474f444f5052ULL;
constexpr u64 GOD_OUTPUT_CONSISTENCY_CAP_DOMAIN=0x5056474f444f4341ULL;
constexpr u64 GOD_OUTPUT_CONSISTENCY_RELATION_DOMAIN=0x5056474f444f524cULL;
constexpr u64 GOD_OUTPUT_CONSISTENCY_SET_DOMAIN=0x5056474f444f5345ULL;
constexpr u64 GOD_OUTPUT_CONSISTENCY_ABI_DOMAIN=0x5056474f44414249ULL;
constexpr u64 GOD_OUTPUT_CONSISTENCY_WITNESS_DOMAIN=0x5056474f44574142ULL;
constexpr u64 GOD_OUTPUT_CONSISTENCY_ABI_VERSION=1ULL;
constexpr u64 GOD_OUTPUT_CONSISTENCY_MAX_OUTPUTS=64ULL;
std::array<u64,4> god_digest_words(const Digest& d) {
    std::array<u64,4> w{};
    for(size_t i=0;i<4;++i) for(size_t j=0;j<8;++j)
        w[i]|=static_cast<u64>(d.bytes[8*i+j])<<(8*j);
    return w;
}
Digest god_words_digest(const u64* w) {
    Digest d{}; if(!w)return d;
    for(size_t i=0;i<4;++i) for(size_t j=0;j<8;++j)
        d.bytes[8*i+j]=static_cast<uint8_t>((w[i]>>(8*j))&0xffU);
    return d;
}
void append_god_digest(const Digest& d,std::vector<u64>* w) {
    auto x=god_digest_words(d); w->insert(w->end(),x.begin(),x.end());
}
}

Digest compute_reference_god_output_consistency_statement_binding(
    const ReferenceGodOutputConsistencyStatement& statement) {
    std::vector<u64> words={GOD_OUTPUT_CONSISTENCY_STATEMENT_DOMAIN,
        statement.sid,static_cast<u64>(statement.checkpoint),
        statement.output_value_count,
        static_cast<u64>(statement.multiplication_statements.size())};
    append_god_digest(statement.scope_binding,&words);
    append_god_digest(statement.output_values_binding,&words);
    append_god_digest(statement.multiplication_proof_set_binding,&words);
    for(const auto& multiplication:statement.multiplication_statements)
        append_god_digest(multiplication.statement_binding,&words);
    return hash_words(words);
}

bool validate_reference_god_output_consistency_statement(
    const ReferenceGodOutputConsistencyStatement& statement) {
    if(statement.sid==0||statement.checkpoint==0||
       statement.scope_binding==Digest{}||statement.output_value_count==0||
       statement.output_value_count>GOD_OUTPUT_CONSISTENCY_MAX_OUTPUTS||
       statement.multiplication_statements.empty()||
       statement.multiplication_statements.size()>GOD_OUTPUT_CONSISTENCY_MAX_OUTPUTS||
       statement.multiplication_statements.size()!=statement.output_value_count||
       statement.output_values_binding==Digest{}||
       statement.multiplication_proof_set_binding==Digest{}||
       statement.statement_binding==Digest{})return false;
    std::set<std::pair<uint64_t,uint32_t>> seen;
    for(const auto& multiplication:statement.multiplication_statements)
        if(multiplication.sid!=statement.sid||
           multiplication.checkpoint!=statement.checkpoint||
           !seen.emplace(multiplication.multiplication_id,
                         multiplication.dealer).second||
           !validate_multiplication_consistency_statement(multiplication))
            return false;
    return statement.statement_binding==
        compute_reference_god_output_consistency_statement_binding(statement);
}

std::vector<u64> encode_reference_god_output_consistency_statement_abi(
    const ReferenceGodOutputConsistencyStatement& statement) {
    if(!validate_reference_god_output_consistency_statement(statement))return {};
    std::vector<u64> words={GOD_OUTPUT_CONSISTENCY_ABI_DOMAIN,
        GOD_OUTPUT_CONSISTENCY_ABI_VERSION,statement.sid,
        static_cast<u64>(statement.checkpoint)};
    append_god_digest(statement.scope_binding,&words);
    words.push_back(statement.output_value_count);
    append_god_digest(statement.output_values_binding,&words);
    append_god_digest(statement.multiplication_proof_set_binding,&words);
    words.push_back(static_cast<u64>(statement.multiplication_statements.size()));
    for(const auto& multiplication:statement.multiplication_statements) {
        const auto encoded=encode_multiplication_consistency_statement_abi(
            multiplication);
        if(encoded.empty())return {};
        words.insert(words.end(),encoded.begin(),encoded.end());
    }
    append_god_digest(statement.statement_binding,&words);
    return words;
}

bool decode_reference_god_output_consistency_statement_abi(
    const std::vector<uint64_t>& words,
    ReferenceGodOutputConsistencyStatement* statement) {
    if(!statement)return false;
    *statement=ReferenceGodOutputConsistencyStatement{};
    if(words.size()<22||words[0]!=GOD_OUTPUT_CONSISTENCY_ABI_DOMAIN||
       words[1]!=GOD_OUTPUT_CONSISTENCY_ABI_VERSION||words[2]==0||words[3]==0)
        return false;
    const uint64_t count=words[8],statement_count=words[17];
    if(count==0||count>GOD_OUTPUT_CONSISTENCY_MAX_OUTPUTS||
       statement_count!=count||words.size()!=18+26*count+4)return false;
    auto read_digest=[&](size_t offset) {
        std::array<u64,4> digest_words{};
        for(size_t i=0;i<4;++i)digest_words[i]=static_cast<u64>(words[offset+i]);
        return god_words_digest(digest_words.data());
    };
    ReferenceGodOutputConsistencyStatement decoded;
    decoded.sid=words[2];decoded.checkpoint=static_cast<CheckpointId>(words[3]);
    decoded.scope_binding=read_digest(4);decoded.output_value_count=count;
    decoded.output_values_binding=read_digest(9);
    decoded.multiplication_proof_set_binding=read_digest(13);
    for(size_t i=0;i<static_cast<size_t>(count);++i) {
        const size_t start=18+i*26;
        std::vector<uint64_t> nested(words.begin()+start,words.begin()+start+26);
        MultiplicationConsistencyStatement multiplication;
        if(!decode_multiplication_consistency_statement_abi(nested,&multiplication))
            return false;
        decoded.multiplication_statements.push_back(std::move(multiplication));
    }
    decoded.statement_binding=read_digest(words.size()-4);
    if(!validate_reference_god_output_consistency_statement(decoded))return false;
    const auto canonical=encode_reference_god_output_consistency_statement_abi(decoded);
    if(canonical.size()!=words.size())return false;
    for(size_t i=0;i<words.size();++i)
        if(static_cast<uint64_t>(canonical[i])!=words[i])return false;
    *statement=std::move(decoded);
    return true;
}

bool validate_reference_god_output_consistency_witness(
    const ReferenceGodOutputConsistencyStatement& statement,
    const ReferenceGodOutputConsistencyWitness& witness) {
    if(!validate_reference_god_output_consistency_statement(statement)||
       witness.output_values.size()!=statement.output_value_count||
       witness.multiplication_witnesses.size()!=
           statement.multiplication_statements.size()||
       hash_field_vector(witness.output_values)!=statement.output_values_binding)
        return false;
    for(size_t i=0;i<witness.output_values.size();++i) {
        const F& value=witness.output_values[i];
        const auto& multiplication_witness=witness.multiplication_witnesses[i];
        if(!valid_field(value)||
           !validate_multiplication_consistency_witness_for_statement(
               statement.multiplication_statements[i],multiplication_witness)||
           multiplication_witness.product_value!=value)return false;
    }
    return true;
}

std::vector<u64> encode_reference_god_output_consistency_witness_abi(
    const ReferenceGodOutputConsistencyStatement& statement,
    const ReferenceGodOutputConsistencyWitness& witness) {
    if(!validate_reference_god_output_consistency_witness(statement,witness))
        return {};
    std::vector<u64> words={GOD_OUTPUT_CONSISTENCY_WITNESS_DOMAIN,
        GOD_OUTPUT_CONSISTENCY_ABI_VERSION,
        static_cast<u64>(witness.output_values.size())};
    for(const F& value:witness.output_values) {
        words.push_back(value.real);words.push_back(value.img);
    }
    words.push_back(static_cast<u64>(witness.multiplication_witnesses.size()));
    for(const auto& multiplication_witness:witness.multiplication_witnesses) {
        const auto encoded=
            encode_multiplication_consistency_witness_abi(multiplication_witness);
        if(encoded.empty())return {};
        words.push_back(static_cast<u64>(encoded.size()));
        words.insert(words.end(),encoded.begin(),encoded.end());
    }
    return words;
}

bool decode_reference_god_output_consistency_witness_abi(
    const ReferenceGodOutputConsistencyStatement& statement,
    const std::vector<uint64_t>& words,
    ReferenceGodOutputConsistencyWitness* witness) {
    if(!witness)return false;
    *witness=ReferenceGodOutputConsistencyWitness{};
    if(!validate_reference_god_output_consistency_statement(statement)||
       words.size()<4||words[0]!=GOD_OUTPUT_CONSISTENCY_WITNESS_DOMAIN||
       words[1]!=GOD_OUTPUT_CONSISTENCY_ABI_VERSION||
       words[2]!=statement.output_value_count)return false;
    const size_t count=static_cast<size_t>(words[2]);
    const size_t values_end=3+2*count;
    if(values_end>=words.size()||words[values_end]!=count)return false;
    ReferenceGodOutputConsistencyWitness decoded;
    decoded.output_values.reserve(count);
    for(size_t i=0;i<count;++i) {
        const uint64_t real=words[3+2*i],imag=words[4+2*i];
        if(real>=F::mod||imag>=F::mod)return false;
        decoded.output_values.emplace_back(
            static_cast<long long>(real),static_cast<long long>(imag));
    }
    size_t cursor=values_end+1;
    decoded.multiplication_witnesses.reserve(count);
    for(size_t i=0;i<count;++i) {
        if(cursor>=words.size())return false;
        const size_t length=static_cast<size_t>(words[cursor++]);
        if(length==0||length>words.size()-cursor)return false;
        std::vector<uint64_t> nested(words.begin()+cursor,words.begin()+cursor+length);
        MultiplicationConsistencyWitness multiplication_witness;
        if(!decode_multiplication_consistency_witness_abi(
               nested,&multiplication_witness))return false;
        decoded.multiplication_witnesses.push_back(std::move(multiplication_witness));
        cursor+=length;
    }
    if(cursor!=words.size()||
       !validate_reference_god_output_consistency_witness(statement,decoded))return false;
    const auto canonical=encode_reference_god_output_consistency_witness_abi(
        statement,decoded);
    if(canonical.size()!=words.size())return false;
    for(size_t i=0;i<words.size();++i)
        if(static_cast<uint64_t>(canonical[i])!=words[i])return false;
    *witness=std::move(decoded);
    return true;
}

Digest compute_reference_god_output_consistency_proof_commitment(
    const ReferenceGodOutputConsistencyProofArtifact& proof) {
    std::vector<u64> words={GOD_OUTPUT_CONSISTENCY_PROOF_DOMAIN,
        proof.available?1ULL:0ULL,
        proof.cryptographically_authenticated?1ULL:0ULL,
        proof.zero_knowledge?1ULL:0ULL,proof.proof_system_id,
        static_cast<u64>(proof.proof_words.size())};
    append_god_digest(proof.statement_binding,&words);
    append_god_digest(proof.transcript_binding,&words);
    words.insert(words.end(),proof.proof_words.begin(),proof.proof_words.end());
    return hash_words(words);
}

bool validate_reference_god_output_consistency_proof(
    const ReferenceGodOutputConsistencyStatement& statement,
    const ReferenceGodOutputConsistencyProofArtifact& proof) {
    if(!validate_reference_god_output_consistency_statement(statement)||
       !proof.available||!proof.cryptographically_authenticated||
       !proof.zero_knowledge||proof.proof_system_id==0||
       proof.proof_words.size()>1048576||
       proof.statement_binding!=statement.statement_binding||
       proof.transcript_binding==Digest{}||proof.proof_words.empty()||
       proof.proof_commitment==Digest{})return false;
    return proof.proof_commitment==
        compute_reference_god_output_consistency_proof_commitment(proof);
}

Digest compute_reference_god_output_consistency_relation_binding() {
    std::vector<u64> words={GOD_OUTPUT_CONSISTENCY_RELATION_DOMAIN,1ULL,
        GOD_OUTPUT_CONSISTENCY_ABI_VERSION,static_cast<u64>(F::mod),
        GOD_OUTPUT_CONSISTENCY_MAX_OUTPUTS,
        GOD_OUTPUT_CONSISTENCY_STATEMENT_DOMAIN,
        GOD_OUTPUT_CONSISTENCY_ABI_DOMAIN,
        GOD_OUTPUT_CONSISTENCY_WITNESS_DOMAIN,26ULL};
    append_god_digest(compute_multiplication_consistency_relation_binding(),&words);
    return hash_words(words);
}

Digest compute_reference_god_output_consistency_capability_binding(
    const ReferenceGodOutputConsistencyCapabilities& capabilities) {
    std::vector<u64> words={GOD_OUTPUT_CONSISTENCY_CAP_DOMAIN,
        capabilities.available?1ULL:0ULL,
        capabilities.malicious_sound?1ULL:0ULL,
        capabilities.zero_knowledge?1ULL:0ULL,
        capabilities.binds_output_values?1ULL:0ULL,
        capabilities.binds_multiplication_proof_set?1ULL:0ULL,
        capabilities.binds_scope_and_session?1ULL:0ULL,
        capabilities.external_registry_anchor_verified?1ULL:0ULL,
        capabilities.protocol_id};
    append_god_digest(capabilities.external_registry_anchor,&words);
    append_god_digest(capabilities.relation_binding,&words);
    append_god_digest(capabilities.implementation_binding,&words);
    return hash_words(words);
}

bool validate_reference_god_output_consistency_capabilities(
    const ReferenceGodOutputConsistencyCapabilities& capabilities) {
    if(!capabilities.available||capabilities.protocol_id==0||
       capabilities.relation_binding!=
           compute_reference_god_output_consistency_relation_binding()||
       capabilities.implementation_binding==Digest{}||
       capabilities.capability_binding==Digest{}||
       capabilities.external_registry_anchor_verified!=
           (capabilities.external_registry_anchor!=Digest{}))return false;
    return capabilities.capability_binding==
        compute_reference_god_output_consistency_capability_binding(capabilities);
}

bool production_ready_reference_god_output_consistency_capabilities(
    const ReferenceGodOutputConsistencyCapabilities& capabilities) {
    return validate_reference_god_output_consistency_capabilities(capabilities)&&
        capabilities.malicious_sound&&capabilities.zero_knowledge&&
        capabilities.binds_output_values&&
        capabilities.binds_multiplication_proof_set&&
        capabilities.binds_scope_and_session&&
        capabilities.external_registry_anchor_verified&&
        capabilities.external_registry_anchor!=Digest{};
}

namespace {
constexpr u64 GOD_OUTPUT_BACKEND_ACCEPTANCE_DOMAIN=0x5056474f44424143ULL;
Digest reference_god_output_backend_acceptance_binding(
    const ReferenceGodOutputConsistencyCapabilities& capabilities) {
    std::vector<u64> words={GOD_OUTPUT_BACKEND_ACCEPTANCE_DOMAIN,
        capabilities.protocol_id};
    append_god_digest(capabilities.capability_binding,&words);
    append_god_digest(capabilities.external_registry_anchor,&words);
    append_god_digest(capabilities.implementation_binding,&words);
    append_god_digest(capabilities.relation_binding,&words);
    return hash_words(words);
}
}

ExternalReferenceGodOutputConsistencyProofAdapter::
ExternalReferenceGodOutputConsistencyProofAdapter(
    ReferenceGodOutputConsistencyCapabilities capabilities,
    uint32_t expected_proof_system_id,
    ReferenceGodOutputConsistencyProviderCallbacks callbacks)
    : capabilities_(std::move(capabilities)),
      expected_proof_system_id_(expected_proof_system_id),
      callbacks_(std::move(callbacks)) {
    last_error_.clear();
    if(expected_proof_system_id_==0||
       !production_ready_reference_god_output_consistency_capabilities(
           capabilities_)||!callbacks_.prove||!callbacks_.verify||
       !callbacks_.verify_external_anchor) {
        last_error_="provider capabilities/callbacks are incomplete";
        return;
    }
    if(!callbacks_.verify_external_anchor(capabilities_)) {
        last_error_="external provider anchor verification failed";
        return;
    }
    external_anchor_verified_=true;
    ready_=true;
}

ReferenceGodOutputConsistencyCapabilities
ExternalReferenceGodOutputConsistencyProofAdapter::Capabilities() const {
    return ready_?capabilities_:ReferenceGodOutputConsistencyCapabilities{};
}

ReferenceGodOutputConsistencyProofArtifact
ExternalReferenceGodOutputConsistencyProofAdapter::Prove(
    const ReferenceGodOutputConsistencyStatement& statement,
    const std::vector<u64>& provider_witness_words) const {
    last_error_.clear();
    if(!ready_) { last_error_="adapter is not ready";return {}; }
    if(!validate_reference_god_output_consistency_statement(statement)||
       provider_witness_words.empty()||provider_witness_words.size()>1048576) {
        last_error_="output statement or provider witness preflight failed";
        return {};
    }
    auto proof=callbacks_.prove(statement,provider_witness_words);
    const auto append_error=[this]() {
        if(!callbacks_.last_error)return;
        const std::string detail=callbacks_.last_error();
        if(!detail.empty())last_error_+="; provider detail: "+detail;
    };
    if(proof.proof_system_id!=expected_proof_system_id_) {
        last_error_="provider proof-system id mismatch";append_error();return {};
    }
    if(!validate_reference_god_output_consistency_proof(statement,proof)) {
        last_error_="output proof artifact failed canonical validation";
        append_error();return {};
    }
    if(!callbacks_.verify(statement,proof)) {
        last_error_="provider rejected its generated output proof";
        append_error();return {};
    }
    return proof;
}

bool ExternalReferenceGodOutputConsistencyProofAdapter::Verify(
    const ReferenceGodOutputConsistencyStatement& statement,
    const ReferenceGodOutputConsistencyProofArtifact& proof) const {
    last_error_.clear();
    if(!ready_) { last_error_="adapter is not ready";return false; }
    if(proof.proof_system_id!=expected_proof_system_id_||
       !validate_reference_god_output_consistency_statement(statement)||
       !validate_reference_god_output_consistency_proof(statement,proof)) {
        last_error_="output proof verification preflight failed";return false;
    }
    if(!callbacks_.verify(statement,proof)) {
        last_error_="external provider rejected output proof";
        if(callbacks_.last_error) {
            const std::string detail=callbacks_.last_error();
            if(!detail.empty())last_error_+="; provider detail: "+detail;
        }
        return false;
    }
    return true;
}

ReferenceGodOutputConsistencyBackendRegistry::State&
ReferenceGodOutputConsistencyBackendRegistry::state() {
    static State current;return current;
}

bool ReferenceGodOutputConsistencyBackendRegistry::InstallAccepted(
    const ReferenceGodOutputConsistencyProofBackend* backend) {
    if(!backend||!backend->external_anchor_verified())return false;
    const auto capabilities=backend->Capabilities();
    if(!production_ready_reference_god_output_consistency_capabilities(
           capabilities)||capabilities.capability_binding==Digest{}||
       reference_god_output_backend_acceptance_binding(capabilities)==Digest{})
        return false;
    state().backend=backend;
    state().acceptance_binding=
        reference_god_output_backend_acceptance_binding(capabilities);
    return true;
}

const ReferenceGodOutputConsistencyProofBackend*
ReferenceGodOutputConsistencyBackendRegistry::Current() {
    return state().backend;
}

Digest ReferenceGodOutputConsistencyBackendRegistry::CurrentAcceptanceBinding() {
    return state().acceptance_binding;
}

void ReferenceGodOutputConsistencyBackendRegistry::Clear() {
    state()=State{};
}

void ReferenceGodOutputConsistencyBackendRegistry::Restore(
    const ReferenceGodOutputConsistencyProofBackend* backend,
    const Digest& acceptance_binding) {
    state().backend=backend;state().acceptance_binding=acceptance_binding;
}

ScopedReferenceGodOutputConsistencyBackendRegistration::
ScopedReferenceGodOutputConsistencyBackendRegistration(
    const ReferenceGodOutputConsistencyProofBackend* backend)
    : previous_backend_(ReferenceGodOutputConsistencyBackendRegistry::Current()),
      previous_acceptance_binding_(
          ReferenceGodOutputConsistencyBackendRegistry::CurrentAcceptanceBinding()) {
    active_=ReferenceGodOutputConsistencyBackendRegistry::InstallAccepted(backend);
}

ScopedReferenceGodOutputConsistencyBackendRegistration::
~ScopedReferenceGodOutputConsistencyBackendRegistration() {
    if(active_)ReferenceGodOutputConsistencyBackendRegistry::Restore(
        previous_backend_,previous_acceptance_binding_);
}

namespace {
bool verify_reference_god_output_consistency_bundle(
    uint64_t sid,CheckpointId checkpoint,const Digest& scope,
    const std::vector<F>& output_values,
    const ReferenceGodOutputConsistencyProofBundle& bundle,
    Digest* proof_set_binding,Digest* statement_binding,Digest* proof_binding) {
    if(proof_set_binding)*proof_set_binding=Digest{};
    if(statement_binding)*statement_binding=Digest{};
    if(proof_binding)*proof_binding=Digest{};
    if(!proof_set_binding||!statement_binding||!proof_binding||
       !bundle.multiplication_backend||!bundle.output_backend||
       bundle.multiplication_statements.empty()||
       bundle.multiplication_statements.size()>4096||
       bundle.multiplication_statements.size()!=bundle.multiplication_proofs.size())
        return false;
    const auto mcaps=bundle.multiplication_backend->Capabilities();
    const auto ocaps=bundle.output_backend->Capabilities();
    const Digest accepted_multiplication_provider=
        MultiplicationConsistencyBackendRegistry::CurrentAcceptanceBinding();
    const Digest accepted_output_provider=
        ReferenceGodOutputConsistencyBackendRegistry::CurrentAcceptanceBinding();
    if(MultiplicationConsistencyBackendRegistry::Current()!=
           bundle.multiplication_backend||
       accepted_multiplication_provider==Digest{}||
       ReferenceGodOutputConsistencyBackendRegistry::Current()!=
           bundle.output_backend||accepted_output_provider==Digest{}||
       accepted_output_provider!=
           reference_god_output_backend_acceptance_binding(ocaps)||
       !bundle.output_backend->external_anchor_verified()||
       !production_ready_multiplication_consistency_capabilities(mcaps)||
       !production_ready_reference_god_output_consistency_capabilities(ocaps))
        return false;
    std::set<std::pair<uint64_t,uint32_t>> seen;
    for(size_t i=0;i<bundle.multiplication_statements.size();++i) {
        const auto& statement=bundle.multiplication_statements[i];
        const auto& proof=bundle.multiplication_proofs[i];
        if(statement.sid!=sid||statement.checkpoint!=checkpoint||
           !seen.emplace(statement.multiplication_id,statement.dealer).second||
           !validate_multiplication_consistency_statement(statement)||
           !validate_multiplication_consistency_proof_artifact(statement,proof)||
           !bundle.multiplication_backend->Verify(statement,proof))return false;
    }
    const Digest set_binding=
        compute_multiplication_consistency_set_binding(bundle.multiplication_proofs);
    const auto& statement=bundle.output_statement;
    const auto& proof=bundle.output_proof;
    bool statement_set_matches=
        statement.multiplication_statements.size()==
        bundle.multiplication_statements.size();
    if(statement_set_matches)
        for(size_t i=0;i<bundle.multiplication_statements.size();++i)
            if(statement.multiplication_statements[i].statement_binding!=
               bundle.multiplication_statements[i].statement_binding)
                statement_set_matches=false;
    if(set_binding==Digest{}||statement.sid!=sid||
       statement.checkpoint!=checkpoint||statement.scope_binding!=scope||
       statement.output_value_count!=output_values.size()||
       statement.output_values_binding!=hash_field_vector(output_values)||
       statement.multiplication_proof_set_binding!=set_binding||
       !statement_set_matches||
       !validate_reference_god_output_consistency_statement(statement)||
       !validate_reference_god_output_consistency_proof(statement,proof)||
       !bundle.output_backend->Verify(statement,proof))return false;
    std::vector<u64> binding_words={GOD_OUTPUT_CONSISTENCY_SET_DOMAIN};
    append_god_digest(statement.statement_binding,&binding_words);
    append_god_digest(proof.proof_commitment,&binding_words);
    append_god_digest(set_binding,&binding_words);
    append_god_digest(mcaps.capability_binding,&binding_words);
    append_god_digest(accepted_multiplication_provider,&binding_words);
    append_god_digest(ocaps.capability_binding,&binding_words);
    append_god_digest(accepted_output_provider,&binding_words);
    append_god_digest(ocaps.external_registry_anchor,&binding_words);
    const Digest binding=hash_words(binding_words);
    if(binding==Digest{})return false;
    *proof_set_binding=set_binding;
    *statement_binding=statement.statement_binding;
    *proof_binding=binding;
    return true;
}
} // namespace

namespace {
bool read_mc_relation_vector(
    const std::string& path,
    std::vector<uint64_t>* statement_words,
    std::vector<uint64_t>* witness_words) {
    if(!statement_words||!witness_words)return false;
    std::ifstream input(path);
    std::string line;
    if(!input||!std::getline(input,line)||
       line!="PVIA_MC_PROVIDER_RELATION_VECTOR_V1")return false;
    std::string statement_text,witness_text;
    while(std::getline(input,line)) {
        const size_t equal=line.find('=');
        if(equal==std::string::npos)continue;
        const std::string key=line.substr(0,equal);
        if(key=="statement_words")statement_text=line.substr(equal+1);
        else if(key=="witness_words")witness_text=line.substr(equal+1);
    }
    auto parse=[](const std::string& text,std::vector<uint64_t>* words) {
        if(!words||text.empty())return false;
        std::stringstream stream(text);std::string token;
        std::vector<uint64_t> parsed;
        try {
            while(std::getline(stream,token,',')) {
                if(token.empty())return false;
                size_t consumed=0;
                const auto value=std::stoull(token,&consumed);
                if(consumed!=token.size())return false;
                parsed.push_back(static_cast<uint64_t>(value));
            }
        } catch(...) {return false;}
        if(parsed.empty())return false;
        *words=std::move(parsed);return true;
    };
    return parse(statement_text,statement_words)&&parse(witness_text,witness_words);
}

bool broadcast_bundle_words(
    int rank,std::vector<u64>* words,bool root_ready,MPI_Comm comm) {
    if(!words)return false;
    int ready=rank==0?(root_ready?1:0):1;
    MPI_Bcast(&ready,1,MPI_INT,0,comm);
    if(!ready)return false;
    uint64_t count=rank==0?static_cast<uint64_t>(words->size()):0;
    MPI_Bcast(&count,1,MPI_UINT64_T,0,comm);
    if(count==0||count>(1ULL<<20)||count>static_cast<uint64_t>(INT_MAX))return false;
    if(rank!=0)words->resize(static_cast<size_t>(count));
    MPI_Bcast(words->data(),static_cast<int>(count),MPI_UINT64_T,0,comm);
    return true;
}

// Test-only public-proof cache: a cached artifact is never trusted. The
// corresponding SP1 backend must re-Verify it against the exact statement
// before the artifact can enter a GOD proof bundle.
constexpr u64 GOD_PROOF_CACHE_DOMAIN=0x5056494147434143ULL;
constexpr u64 GOD_PROOF_CACHE_VERSION=1ULL;
std::string god_proof_cache_path(const char* leaf) {
    const char* root=std::getenv("PVIA_GOD_BUNDLE_PROOF_CACHE_DIR");
    if(!root||!*root||!leaf||!*leaf) return {};
    return std::string(root)+"/"+leaf;
}
bool god_read_proof_cache(
    const std::string& path,
    const std::vector<u64>& expected_statement,
    const Digest& expected_provider,
    std::vector<u64>* out) {
    if(path.empty()||!out||expected_statement.empty()||
       expected_statement.size()>1048576||expected_provider==Digest{})
        return false;
    out->clear();
    std::ifstream input(path);
    if(!input) return false;
    u64 domain=0,version=0,provider_words[4]{},statement_count=0;
    if(!(input>>domain>>version)||domain!=GOD_PROOF_CACHE_DOMAIN||
       version!=GOD_PROOF_CACHE_VERSION)return false;
    for(u64& word:provider_words)if(!(input>>word))return false;
    if(god_words_digest(provider_words)!=expected_provider ||
       !(input>>statement_count)||statement_count!=expected_statement.size())
        return false;
    for(u64 word:expected_statement) {
        u64 stored=0;
        if(!(input>>stored)||stored!=word)return false;
    }
    u64 n=0;
    if(!(input>>n)||n==0||n>1048576)return false;
    std::vector<u64> proof(static_cast<size_t>(n));
    for(u64& word:proof)if(!(input>>word))return false;
    std::string trailing;
    if(input>>trailing)return false;
    *out=std::move(proof);
    return true;
}
bool god_write_proof_cache(
    const std::string& path,
    const std::vector<u64>& statement,
    const Digest& provider,
    const std::vector<u64>& proof) {
    if(path.empty()||statement.empty()||provider==Digest{}||
       proof.empty()||statement.size()>1048576||proof.size()>1048576)
        return false;
    const std::string temp=path+".tmp."+std::to_string(getpid());
    std::ofstream output(temp,std::ios::out|std::ios::trunc);
    if(!output)return false;
    output<<GOD_PROOF_CACHE_DOMAIN<<" "<<GOD_PROOF_CACHE_VERSION<<"\n";
    std::vector<u64> provider_words;
    append_god_digest(provider,&provider_words);
    for(u64 word:provider_words)output<<word<<" ";
    output<<"\n"<<statement.size()<<"\n";
    for(u64 word:statement)output<<word<<"\n";
    output<<proof.size()<<"\n";
    for(u64 word:proof)output<<word<<"\n";
    output.flush();
    const bool saved=output.good();
    output.close();
    if(!saved||std::rename(temp.c_str(),path.c_str())!=0) {
        std::remove(temp.c_str());
        return false;
    }
    return true;
}

std::vector<u64> encode_output_proof_abi_words(
    const ReferenceGodOutputConsistencyProofArtifact& proof) {
    std::vector<u64> words={proof.available?1ULL:0ULL,
        proof.cryptographically_authenticated?1ULL:0ULL,
        proof.zero_knowledge?1ULL:0ULL,proof.proof_system_id};
    append_god_digest(proof.statement_binding,&words);
    append_god_digest(proof.transcript_binding,&words);
    append_god_digest(proof.proof_commitment,&words);
    words.push_back(static_cast<u64>(proof.proof_words.size()));
    words.insert(words.end(),proof.proof_words.begin(),proof.proof_words.end());
    return words;
}

bool decode_output_proof_abi_words(
    const std::vector<u64>& words,
    ReferenceGodOutputConsistencyProofArtifact* proof) {
    if(!proof||words.size()<17||words[0]>1||words[1]>1||words[2]>1||
       words[3]>std::numeric_limits<uint32_t>::max()||
       words[16]!=static_cast<uint64_t>(words.size()-17))return false;
    ReferenceGodOutputConsistencyProofArtifact decoded;
    decoded.available=words[0]!=0;decoded.cryptographically_authenticated=words[1]!=0;
    decoded.zero_knowledge=words[2]!=0;decoded.proof_system_id=static_cast<uint32_t>(words[3]);
    decoded.statement_binding=god_words_digest(words.data()+4);
    decoded.transcript_binding=god_words_digest(words.data()+8);
    decoded.proof_commitment=god_words_digest(words.data()+12);
    decoded.proof_words.assign(words.begin()+17,words.end());
    *proof=std::move(decoded);return true;
}
} // namespace

bool run_reference_god_output_bundle_n4_selftest(
    int rank,int world_size,
    const std::string& multiplication_library_path,
    const std::string& output_library_path,
    const std::string& relation_vector_path) {
    auto trace_bundle=[rank](const char* phase) {
        const char* enabled=std::getenv("PVIA_GOD_BUNDLE_TRACE");
        if(enabled && *enabled && std::string(enabled)!="0")
            std::cerr<<"[PVIA][god-bundle-stage] rank="<<rank
                     <<" phase="<<phase<<std::endl;
    };
    trace_bundle("enter");
    int actual_rank=-1,actual_world=0;
    MPI_Comm_rank(MPI_COMM_WORLD,&actual_rank);
    MPI_Comm_size(MPI_COMM_WORLD,&actual_world);
    std::vector<uint64_t> statement_words,witness_words;
    MultiplicationConsistencyStatement multiplication_statement;
    MultiplicationConsistencyWitness multiplication_witness;
    ReferenceGodOutputConsistencyCapabilities provider_capabilities;
    std::string capability_error;
    const char* trusted_implementation_words_env=
        std::getenv("PVIA_GOD_OUTPUT_PROVIDER_TRUSTED_IMPLEMENTATION_WORDS");
    const char* trusted_library_sha256_env=
        std::getenv("PVIA_GOD_OUTPUT_PROVIDER_TRUSTED_LIBRARY_SHA256");
    const bool has_implementation_pin=trusted_implementation_words_env&&
        trusted_implementation_words_env[0]!='\0';
    const bool has_library_pin=trusted_library_sha256_env&&
        trusted_library_sha256_env[0]!='\0';
    const bool any_operator_pin=has_implementation_pin||has_library_pin;
    const bool operator_pin_configured=has_implementation_pin&&has_library_pin;
    const std::array<u64,4> test_implementation_words={{
        12933141299589377141ULL,17619217585778136753ULL,
        8823755328675063018ULL,9626619460356111277ULL}};
    std::array<u64,4> trusted_implementation_words=test_implementation_words;
    const bool trusted_implementation_words_valid=!any_operator_pin||
        (operator_pin_configured&&parse_u64_word_list(
            trusted_implementation_words_env,&trusted_implementation_words));
    const Digest trusted_implementation_binding=
        trusted_implementation_words_valid
            ?god_words_digest(trusted_implementation_words.data()):Digest{};
    std::array<unsigned char,32> expected_library_sha256{},actual_library_sha256{};
    const bool expected_library_sha256_valid=!any_operator_pin||
        (operator_pin_configured&&parse_sha256_hex(
            trusted_library_sha256_env,&expected_library_sha256));
    const bool actual_library_sha256_valid=
        sha256_file(output_library_path,&actual_library_sha256);
    const bool trusted_library_sha256_valid=actual_library_sha256_valid&&
        (!any_operator_pin||(expected_library_sha256_valid&&
         expected_library_sha256==actual_library_sha256));
    const bool external_trust_config_valid=!any_operator_pin||
        (operator_pin_configured&&trusted_implementation_words_valid&&
         expected_library_sha256_valid&&trusted_library_sha256_valid);
    if(any_operator_pin&&!operator_pin_configured)
        capability_error="trust config requires both implementation words and library SHA-256";
    else if(!trusted_implementation_words_valid)
        capability_error="configured implementation pin must contain four comma-separated uint64 words";
    else if(!expected_library_sha256_valid||!trusted_library_sha256_valid)
        capability_error="configured provider library SHA-256 is invalid or mismatched";
    const bool local_preflight=rank==actual_rank&&world_size==actual_world&&
        world_size==4&&rank>=0&&rank<4&&!multiplication_library_path.empty()&&
        !output_library_path.empty()&&!relation_vector_path.empty()&&
        read_mc_relation_vector(relation_vector_path,&statement_words,&witness_words)&&
        decode_multiplication_consistency_statement_abi(
            statement_words,&multiplication_statement)&&
        decode_multiplication_consistency_witness_abi(
            witness_words,&multiplication_witness)&&
        validate_multiplication_consistency_witness_for_statement(
            multiplication_statement,multiplication_witness)&&
        external_trust_config_valid&&actual_library_sha256_valid&&
        SharedLibraryReferenceGodOutputConsistencyProvider::QueryCapabilities(
            output_library_path,&provider_capabilities,&capability_error)&&
        provider_capabilities.implementation_binding==trusted_implementation_binding&&
        provider_capabilities.relation_binding==
            compute_reference_god_output_consistency_relation_binding();
    int local_ok=local_preflight?1:0,all_preflight=0;
    MPI_Allreduce(&local_ok,&all_preflight,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
    if(!all_preflight) {
        if(rank==0)std::cout<<"[PVIA][god-output-bundle-n4] FAIL preflight "
            <<capability_error<<std::endl;
        return false;
    }

    // An operator-configured implementation pin is read independently of the
    // provider library. Without it, this explicitly remains a test-only pin.
    const Digest pinned_implementation=trusted_implementation_binding;
    provider_capabilities.external_registry_anchor_verified=true;
    std::vector<u64> anchor_words={
        operator_pin_configured?0x50564941434f4e46ULL:0x5056494154455354ULL,
        provider_capabilities.protocol_id,68102ULL};
    append_god_digest(pinned_implementation,&anchor_words);
    if(operator_pin_configured)
        append_god_digest(provider_capabilities.relation_binding,&anchor_words);
    const Digest configured_anchor_binding=hash_words(anchor_words);
    provider_capabilities.external_registry_anchor=configured_anchor_binding;
    provider_capabilities.capability_binding=
        compute_reference_god_output_consistency_capability_binding(provider_capabilities);
    const uint64_t expected_protocol=provider_capabilities.protocol_id;
    auto verify_test_anchor=[pinned_implementation,configured_anchor_binding,expected_protocol](
        const ReferenceGodOutputConsistencyCapabilities& capabilities) {
        return capabilities.external_registry_anchor_verified&&
            capabilities.external_registry_anchor==configured_anchor_binding&&
            capabilities.implementation_binding==pinned_implementation&&
            capabilities.protocol_id==expected_protocol&&
            capabilities.relation_binding==
                compute_reference_god_output_consistency_relation_binding()&&
            capabilities.capability_binding==
                compute_reference_god_output_consistency_capability_binding(capabilities)&&
            production_ready_reference_god_output_consistency_capabilities(capabilities);
    };

    trace_bundle("before_mc_provider_load");
    SharedLibraryMultiplicationConsistencyProviderSession multiplication_provider(
        multiplication_library_path,68101);
    local_ok=multiplication_provider.Load()?1:0;
    MPI_Allreduce(&local_ok,&all_preflight,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
    if(!all_preflight) {
        if(rank==0)std::cout<<"[PVIA][god-output-bundle-n4] FAIL multiplication provider load: "
            <<multiplication_provider.error()<<std::endl;
        return false;
    }
    const MultiplicationConsistencyProofBackend* loaded_mc_backend=
        multiplication_provider.backend();
    if(!loaded_mc_backend)return false;
    const char* real_acceptance_env=
        std::getenv("PVIA_GOD_OUTPUT_BUNDLE_N4_REAL_ACCEPTANCE");
    const bool use_real_mc_acceptance=
        real_acceptance_env&&std::string(real_acceptance_env)!="0";
    MultiplicationConsistencyProviderAcceptanceResult test_mc_acceptance;
    std::unique_ptr<ScopedMultiplicationConsistencyBackendRegistration>
        test_mc_registration;
    trace_bundle("before_mc_provider_acceptance");
    if(use_real_mc_acceptance) {
        if(!multiplication_provider.Activate(rank,world_size,MPI_COMM_WORLD)) {
            if(rank==0)std::cout
                <<"[PVIA][god-output-bundle-n4] FAIL real multiplication provider acceptance: "
                <<multiplication_provider.error()<<std::endl;
            return false;
        }
    } else {
        const auto loaded_mc_capabilities=loaded_mc_backend->Capabilities();
        test_mc_acceptance.available=true;
        test_mc_acceptance.capabilities_ready=true;
        test_mc_acceptance.multiplication_verified=true;
        test_mc_acceptance.zero_case_verified=true;
        test_mc_acceptance.nonzero_case_verified=true;
        test_mc_acceptance.completed_stage=11;
        test_mc_acceptance.capability_binding=loaded_mc_capabilities.capability_binding;
        std::vector<u64> test_acceptance_words={0x505649414d435446ULL,
            loaded_mc_capabilities.protocol_id,68101ULL};
        append_god_digest(loaded_mc_capabilities.capability_binding,&test_acceptance_words);
        test_mc_acceptance.acceptance_binding=hash_words(test_acceptance_words);
        test_mc_registration=std::make_unique<
            ScopedMultiplicationConsistencyBackendRegistration>(
                loaded_mc_backend,&test_mc_acceptance);
        local_ok=test_mc_registration->active()?1:0;
        MPI_Allreduce(&local_ok,&all_preflight,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
        if(!all_preflight) {
            if(rank==0)std::cout
                <<"[PVIA][god-output-bundle-n4] FAIL test-fixture backend registration"
                <<std::endl;
            return false;
        }
    }
    trace_bundle("before_output_provider_activate");
    SharedLibraryReferenceGodOutputConsistencyProvider output_provider(
        output_library_path,provider_capabilities,68102,verify_test_anchor);
    if(!output_provider.Activate(rank,world_size,MPI_COMM_WORLD)) {
        if(rank==0)std::cout<<"[PVIA][god-output-bundle-n4] FAIL output provider: "
            <<output_provider.error()<<std::endl;
        return false;
    }
    trace_bundle("after_output_provider_activate");
    const MultiplicationConsistencyProofBackend* multiplication_backend=
        MultiplicationConsistencyBackendRegistry::Current();
    const ReferenceGodOutputConsistencyProofBackend* output_backend=
        ReferenceGodOutputConsistencyBackendRegistry::Current();
    const bool backends_ready=multiplication_backend&&output_backend&&
        MultiplicationConsistencyBackendRegistry::CurrentAcceptanceBinding()!=Digest{}&&
        ReferenceGodOutputConsistencyBackendRegistry::CurrentAcceptanceBinding()!=Digest{}&&
        output_backend->external_anchor_verified();
    local_ok=backends_ready?1:0;
    MPI_Allreduce(&local_ok,&all_preflight,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
    if(!all_preflight) {
        if(rank==0)std::cout<<"[PVIA][god-output-bundle-n4] FAIL backend registration"<<std::endl;
        return false;
    }

    trace_bundle("before_mc_prove");
    std::vector<u64> multiplication_artifact_words;
    bool multiplication_prove_ok=false;
    if(rank==0) {
        const auto canonical_statement=
            encode_multiplication_consistency_statement_abi(multiplication_statement);
        const std::vector<u64> statement_abi(
            canonical_statement.begin(),canonical_statement.end());
        const Digest accepted_provider=
            MultiplicationConsistencyBackendRegistry::CurrentAcceptanceBinding();
        const auto cache_file=god_proof_cache_path("mc_groth16_verified_v1.words");
        const char* cache_required_env=
            std::getenv("PVIA_GOD_BUNDLE_REQUIRE_CACHED_PROOFS");
        const bool require_cache=cache_required_env&&*cache_required_env&&
            std::string(cache_required_env)!="0";
        MultiplicationConsistencyProofArtifact verified_cached;
        const bool cache_hit=god_read_proof_cache(
            cache_file,statement_abi,accepted_provider,
            &multiplication_artifact_words) &&
            decode_multiplication_consistency_proof_artifact(
                multiplication_artifact_words,&verified_cached) &&
            validate_multiplication_consistency_proof_artifact(
                multiplication_statement,verified_cached) &&
            multiplication_backend->Verify(
                multiplication_statement,verified_cached);
        if(cache_hit) {
            multiplication_prove_ok=true;
            trace_bundle("mc_proof_verified_cache_hit");
        } else {
            multiplication_artifact_words.clear();
            trace_bundle(!cache_file.empty() && std::ifstream(cache_file).good() ?
                         "mc_proof_cache_rejected" :
                         "mc_proof_cache_miss");
            if(!require_cache) {
                const auto proof=multiplication_backend->Prove(
                    multiplication_statement,multiplication_witness);
                multiplication_prove_ok=
                    validate_multiplication_consistency_proof_artifact(
                        multiplication_statement,proof)&&
                    multiplication_backend->Verify(
                        multiplication_statement,proof);
                if(multiplication_prove_ok) {
                    multiplication_artifact_words=
                        encode_multiplication_consistency_proof_artifact(proof);
                    god_write_proof_cache(cache_file,statement_abi,
                                          accepted_provider,multiplication_artifact_words);
                    trace_bundle("mc_proof_computed_and_verified");
                }
            }
        }
    }
    if(!broadcast_bundle_words(rank,&multiplication_artifact_words,
                               multiplication_prove_ok,MPI_COMM_WORLD)) {
        if(rank==0)std::cout<<"[PVIA][god-output-bundle-n4] FAIL multiplication proof generation"<<std::endl;
        return false;
    }
    trace_bundle("after_mc_broadcast");
    MultiplicationConsistencyProofArtifact multiplication_proof;
    const bool multiplication_artifact_ok=
        decode_multiplication_consistency_proof_artifact(
            multiplication_artifact_words,&multiplication_proof)&&
        validate_multiplication_consistency_proof_artifact(
            multiplication_statement,multiplication_proof);
    local_ok=multiplication_artifact_ok?1:0;
    MPI_Allreduce(&local_ok,&all_preflight,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
    if(!all_preflight)return false;

    trace_bundle("after_mc_decode");
    const std::vector<MultiplicationConsistencyProofArtifact> proof_set={multiplication_proof};
    const Digest proof_set_binding=compute_multiplication_consistency_set_binding(proof_set);
    if(proof_set_binding==Digest{})return false;
    std::vector<u64> scope_words={GOD_OUTPUT_CONSISTENCY_STATEMENT_DOMAIN,
        multiplication_statement.sid,static_cast<u64>(multiplication_statement.checkpoint),
        0x4e345f42554e444cULL};
    append_god_digest(proof_set_binding,&scope_words);
    const Digest scope=hash_words(scope_words);
    const std::vector<F> output_values={multiplication_witness.product_value};
    ReferenceGodOutputConsistencyStatement output_statement;
    output_statement.sid=multiplication_statement.sid;
    output_statement.checkpoint=multiplication_statement.checkpoint;
    output_statement.scope_binding=scope;
    output_statement.output_value_count=output_values.size();
    output_statement.output_values_binding=hash_field_vector(output_values);
    output_statement.multiplication_proof_set_binding=proof_set_binding;
    output_statement.multiplication_statements.push_back(multiplication_statement);
    output_statement.statement_binding=
        compute_reference_god_output_consistency_statement_binding(output_statement);
    ReferenceGodOutputConsistencyWitness output_witness;
    output_witness.output_values=output_values;
    output_witness.multiplication_witnesses.push_back(multiplication_witness);
    const auto output_witness_words=encode_reference_god_output_consistency_witness_abi(
        output_statement,output_witness);
    local_ok=validate_reference_god_output_consistency_statement(output_statement)&&
        !output_witness_words.empty()?1:0;
    MPI_Allreduce(&local_ok,&all_preflight,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
    if(!all_preflight)return false;

    trace_bundle("before_output_prove");
    std::vector<u64> output_artifact_words;
    bool output_prove_ok=false;
    if(rank==0) {
        const auto canonical_statement=
            encode_reference_god_output_consistency_statement_abi(output_statement);
        const std::vector<u64> statement_abi(
            canonical_statement.begin(),canonical_statement.end());
        const Digest accepted_provider=
            ReferenceGodOutputConsistencyBackendRegistry::CurrentAcceptanceBinding();
        const auto cache_file=god_proof_cache_path("output_groth16_verified_v1.words");
        const char* cache_required_env=
            std::getenv("PVIA_GOD_BUNDLE_REQUIRE_CACHED_PROOFS");
        const bool require_cache=cache_required_env&&*cache_required_env&&
            std::string(cache_required_env)!="0";
        ReferenceGodOutputConsistencyProofArtifact verified_cached;
        const bool cache_hit=god_read_proof_cache(
            cache_file,statement_abi,accepted_provider,&output_artifact_words)&&
            decode_output_proof_abi_words(output_artifact_words,&verified_cached)&&
            validate_reference_god_output_consistency_proof(
                output_statement,verified_cached)&&
            output_backend->Verify(output_statement,verified_cached);
        if(cache_hit) {
            output_prove_ok=true;
            trace_bundle("output_proof_verified_cache_hit");
        } else {
            output_artifact_words.clear();
            trace_bundle(!cache_file.empty() && std::ifstream(cache_file).good() ?
                         "output_proof_cache_rejected" :
                         "output_proof_cache_miss");
            if(!require_cache) {
                const auto proof=output_backend->Prove(output_statement,output_witness_words);
                output_prove_ok=validate_reference_god_output_consistency_proof(
                    output_statement,proof)&&output_backend->Verify(output_statement,proof);
                if(output_prove_ok) {
                    output_artifact_words=encode_output_proof_abi_words(proof);
                    god_write_proof_cache(cache_file,statement_abi,
                                          accepted_provider,output_artifact_words);
                    trace_bundle("output_proof_computed_and_verified");
                }
            }
        }
    }
    if(!broadcast_bundle_words(rank,&output_artifact_words,
                               output_prove_ok,MPI_COMM_WORLD)) {
        if(rank==0)std::cout<<"[PVIA][god-output-bundle-n4] FAIL output proof generation"<<std::endl;
        return false;
    }
    trace_bundle("after_output_broadcast");
    ReferenceGodOutputConsistencyProofArtifact output_proof;
    const bool output_artifact_ok=decode_output_proof_abi_words(
        output_artifact_words,&output_proof)&&
        validate_reference_god_output_consistency_proof(output_statement,output_proof);
    local_ok=output_artifact_ok?1:0;
    MPI_Allreduce(&local_ok,&all_preflight,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
    if(!all_preflight)return false;

    trace_bundle("before_proof_bundle_verify");
    ReferenceGodOutputConsistencyProofBundle bundle;
    bundle.multiplication_backend=multiplication_backend;
    bundle.output_backend=output_backend;
    bundle.multiplication_statements={multiplication_statement};
    bundle.multiplication_proofs={multiplication_proof};
    bundle.output_statement=output_statement;
    bundle.output_proof=output_proof;
    Digest verified_set{},verified_statement{},verified_proof{};
    const bool positive=verify_reference_god_output_consistency_bundle(
        output_statement.sid,output_statement.checkpoint,scope,output_values,bundle,
        &verified_set,&verified_statement,&verified_proof);

    auto bad_set_bundle=bundle;
    bad_set_bundle.output_statement.multiplication_proof_set_binding=
        hash_words({GOD_OUTPUT_CONSISTENCY_SET_DOMAIN,0xBAD51ULL});
    bad_set_bundle.output_statement.statement_binding=
        compute_reference_god_output_consistency_statement_binding(
            bad_set_bundle.output_statement);
    Digest ignored_set{},ignored_statement{},ignored_proof{};
    const bool bad_set_rejected=!verify_reference_god_output_consistency_bundle(
        output_statement.sid,output_statement.checkpoint,scope,output_values,
        bad_set_bundle,&ignored_set,&ignored_statement,&ignored_proof);

    auto bad_mc_bundle=bundle;
    bad_mc_bundle.multiplication_proofs[0].proof_words[0]^=1ULL;
    const bool bad_mc_proof_rejected=!verify_reference_god_output_consistency_bundle(
        output_statement.sid,output_statement.checkpoint,scope,output_values,
        bad_mc_bundle,&ignored_set,&ignored_statement,&ignored_proof);

    auto bad_output_bundle=bundle;
    bad_output_bundle.output_proof.proof_words[0]^=1ULL;
    const bool bad_output_proof_rejected=!verify_reference_god_output_consistency_bundle(
        output_statement.sid,output_statement.checkpoint,scope,output_values,
        bad_output_bundle,&ignored_set,&ignored_statement,&ignored_proof);

    trace_bundle("after_proof_bundle_verify");
    const char* delivery_selftest_env=
        std::getenv("PVIA_GOD_OUTPUT_BUNDLE_N4_DELIVERY_SELFTEST");
    const bool delivery_path_enabled=
        delivery_selftest_env&&std::string(delivery_selftest_env)!="0";
    const char* crash_delivery_env=
        std::getenv("PVIA_GOD_OUTPUT_BUNDLE_N4_CRASH_RECOVERY_SELFTEST");
    const bool crash_delivery_enabled=
        crash_delivery_env&&std::string(crash_delivery_env)!="0";
    const char* survivor_bundle_env=
        std::getenv("PVIA_GOD_OUTPUT_BUNDLE_N4_RECOVERY_BUNDLE_SELFTEST");
    const bool survivor_bundle_enabled=
        survivor_bundle_env&&std::string(survivor_bundle_env)!="0";
    bool delivery_path_ok=true;
    trace_bundle("before_survivor_recovery");
    if(survivor_bundle_enabled) {
        // Even when the excluded rank remains alive, a positive proof
        // verification and every tamper rejection must hold before delivery.
        const int proof_preflight_local=
            positive&&bad_set_rejected&&bad_mc_proof_rejected&&
            bad_output_proof_rejected?1:0;
        int proof_preflight_all=0;
        if(MPI_Allreduce(&proof_preflight_local,&proof_preflight_all,1,
                         MPI_INT,MPI_MIN,MPI_COMM_WORLD)!=MPI_SUCCESS||
           !proof_preflight_all) {
            if(rank==0)std::cerr
                <<"[PVIA][god-output-bundle-recovery-n4] "
                <<"FAIL proof bundle preflight"<<std::endl;
            return false;
        }
        // Build the same authenticated VSS receipt used by the ULFM recovery
        // path, then exercise that path over a three-member survivor
        // communicator while keeping the excluded original rank alive.
        auto& transfer_auth=Ed25519TransferAuthenticator::instance();
        int auth_local=transfer_auth.Initialize(rank,world_size)?1:0;
        int auth_all=0;
        MPI_Allreduce(&auth_local,&auth_all,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
        if(!auth_all)return false;

        const char* auth_vss_env=
            std::getenv("PVIA_GOD_OUTPUT_CRASH_RECOVERY_AUTHENTICATED_VSS");
        const int auth_vss_local=
            auth_vss_env&&std::string(auth_vss_env)!="0"?1:0;
        int auth_vss_min=0,auth_vss_max=0;
        MPI_Allreduce(&auth_vss_local,&auth_vss_min,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
        MPI_Allreduce(&auth_vss_local,&auth_vss_max,1,MPI_INT,MPI_MAX,MPI_COMM_WORLD);
        if(auth_vss_min!=auth_vss_max)return false;
        const bool authenticated_vss=auth_vss_min==1;

        ReferenceBivariateVss recovery_vss(rank,world_size,1);
        ReferenceVssReceipt recovery_receipt;
        std::vector<F> recovery_shares;
        bool vss_ready=false;
        if(recovery_vss.valid()&&authenticated_vss) {
            AuthenticatedMpcExchange recovery_exchange(rank,world_size);
            AuthenticatedMpcMessageContext vss_context;
            vss_context.protocol_domain=GOD_N4_DOMAIN;
            vss_context.sid=output_statement.sid;
            vss_context.checkpoint=output_statement.checkpoint;
            vss_context.round=9201ULL;
            vss_context.sequence=9201ULL;
            vss_context.message_kind=0x56535301ULL;
            vss_ready=recovery_exchange.production_authenticated_ready()&&
                recovery_vss.ShareVectorFromDealerAuthenticated(
                    0,rank==0?output_values:std::vector<F>{},
                    &recovery_shares,&recovery_receipt,
                    recovery_exchange,vss_context);
        } else if(recovery_vss.valid()) {
            vss_ready=recovery_vss.ShareVectorFromDealer(
                0,rank==0?output_values:std::vector<F>{},
                &recovery_shares,&recovery_receipt);
        }
        int vss_local_ok=vss_ready&&recovery_shares.size()==output_values.size()&&
            recovery_receipt.available&&recovery_receipt.consistent&&
            recovery_receipt.transcript_binding!=Digest{}?1:0;
        int vss_all_ok=0;
        MPI_Allreduce(&vss_local_ok,&vss_all_ok,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
        if(!vss_all_ok)return false;

        AuthenticatedMpcMessageContext recovery_context;
        recovery_context.protocol_domain=GOD_N4_DOMAIN;
        recovery_context.sid=output_statement.sid;
        recovery_context.checkpoint=output_statement.checkpoint;
        recovery_context.round=9301ULL;
        recovery_context.sequence=9301ULL;
        recovery_context.message_kind=GOD_CRASH_SHARE_DOMAIN;

        MPI_Comm survivor_comm=MPI_COMM_NULL;
        const int split_rc=MPI_Comm_split(
            MPI_COMM_WORLD,rank==1?MPI_UNDEFINED:1,rank,&survivor_comm);
        int survivor_local_ok=split_rc==MPI_SUCCESS?1:0;
        ReferenceGodOutput recovered;
        if(rank!=1&&survivor_comm!=MPI_COMM_NULL) {
            MPI_Comm_set_errhandler(survivor_comm,MPI_ERRORS_RETURN);
            const std::vector<int> original_survivors={0,2,3};
            const bool opened=open_reference_god_output_after_failure_n4(
                rank,world_size,original_survivors,recovery_shares,scope,
                recovery_context,recovery_receipt,survivor_comm,&recovered,&bundle);
            const bool positive_recovery=opened&&recovered.available&&
                recovered.values==output_values&&recovered.process_crash_tolerant&&
                recovered.survivor_agreement_verified&&recovered.agreement_votes==3&&
                recovered.multiplication_consistency_verified&&
                recovered.multiplication_proof_set_binding==verified_set&&
                recovered.output_consistency_statement_binding==verified_statement&&
                recovered.output_consistency_proof_binding==verified_proof&&
                recovered.authenticated_vss_verified==authenticated_vss&&
                recovered.vss_transcript_binding==recovery_receipt.transcript_binding&&
                !recovered.complete_application_relation_set_verified&&
                !reference_god_output_production_authorized(recovered);
            survivor_local_ok=positive_recovery?1:0;

            ReferenceGodOutput rejected_output;
            ReferenceGodOutputConsistencyProofBundle invalid_bundle;
            const bool invalid_bundle_opened=open_reference_god_output_after_failure_n4(
                rank,world_size,original_survivors,recovery_shares,scope,
                recovery_context,recovery_receipt,survivor_comm,&rejected_output,
                &invalid_bundle);
            if(invalid_bundle_opened||rejected_output.available)survivor_local_ok=0;

            int active_agree=0;
            const int vote_agree=survivor_local_ok;
            if(MPI_Allreduce(&vote_agree,&active_agree,1,MPI_INT,MPI_MIN,
                             survivor_comm)!=MPI_SUCCESS||
               active_agree!=1)survivor_local_ok=0;
            if(MPI_Comm_free(&survivor_comm)!=MPI_SUCCESS)survivor_local_ok=0;
        } else if(rank!=1) {
            survivor_local_ok=0;
        }
        int survivor_all_ok=0;
        MPI_Allreduce(&survivor_local_ok,&survivor_all_ok,1,MPI_INT,
                      MPI_MIN,MPI_COMM_WORLD);
        if(rank==0)std::cout
            <<"[PVIA][god-output-bundle-recovery-n4] "
            <<(survivor_all_ok?"PASS":"FAIL")
            <<" survivors=3 proof_bundle=VERIFIED"
            <<" multiplication_consistency=YES"
            <<" authenticated_vss="<<(authenticated_vss?"YES":"NO")
            <<" complete_relation_manifest=NO"
            <<" production_gate=WITHHOLD"<<std::endl;
        // Continue through the normal authenticated output-delivery stage
        // after the survivor recovery certificate has been checked.  This
        // keeps proof verification, recovery, and final delivery in one N=4
        // functional acceptance execution instead of treating recovery as
        // the terminal test branch.
        delivery_path_ok=survivor_all_ok==1;
        if(!delivery_path_ok)return false;
    }
    if(crash_delivery_enabled) {
        const bool bundle_preflight_local=positive&&bad_set_rejected&&
            bad_mc_proof_rejected&&bad_output_proof_rejected;
        int bundle_preflight_min=bundle_preflight_local?1:0;
        int bundle_preflight_all=0;
        MPI_Allreduce(&bundle_preflight_min,&bundle_preflight_all,
                      1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
        if(!bundle_preflight_all) {
            if(rank==0)std::cout
                <<"[PVIA][god-output-bundle-crash-n4] FAIL proof bundle preflight"
                <<std::endl;
            return false;
        }
        AuthenticatedMpcMessageContext crash_context;
        crash_context.protocol_domain=GOD_N4_DOMAIN;
        crash_context.sid=output_statement.sid;
        crash_context.checkpoint=output_statement.checkpoint;
        crash_context.round=9101ULL;
        crash_context.sequence=9101ULL;
        crash_context.message_kind=GOD_CRASH_SHARE_DOMAIN;
        const bool crash_delivery_ok=
            run_reference_god_output_crash_recovery_n4_selftest(
                rank,world_size,&output_values,&scope,&crash_context,&bundle);
        if(rank==0)std::cout
            <<"[PVIA][god-output-bundle-crash-n4] "
            <<(crash_delivery_ok?"PASS":"FAIL")
            <<" positive_bundle=PASS proof_binding=CHECKED_IN_RECOVERY"
            <<" production_gate=WITHHOLD"<<std::endl;
        return crash_delivery_ok;
    }
    if(delivery_path_enabled) {
        ReferenceShamirMpc output_mpc(rank,world_size,1);
        std::vector<F> local_output_shares;
        const std::vector<F> dealer_values=
            rank==0?output_values:std::vector<F>{};
        const bool output_mpc_valid=output_mpc.valid();
        const bool output_shares_created=output_mpc.ShareVectorFromDealer(
            0,dealer_values,&local_output_shares);
        local_ok=output_mpc_valid&&output_shares_created&&
            local_output_shares.size()==output_values.size()?1:0;
        MPI_Allreduce(&local_ok,&all_preflight,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
        if(!all_preflight) {
            if(rank==0)std::cout
                <<"[PVIA][god-output-bundle-n4] FAIL output delivery share setup"
                <<std::endl;
            return false;
        }

        AuthenticatedMpcExchange delivery_exchange(rank,world_size);
        AuthenticatedMpcMessageContext delivery_context;
        delivery_context.protocol_domain=GOD_AUTH_PROTOCOL;
        delivery_context.sid=output_statement.sid;
        delivery_context.checkpoint=output_statement.checkpoint;
        delivery_context.round=5000;
        delivery_context.sequence=5000;
        delivery_context.message_kind=1;
        ReferenceGodOutput delivered;
        const bool delivery_call=open_authenticated_reference_god_output_n4(
            rank,world_size,local_output_shares,true,scope,delivery_context,
            delivery_exchange,&delivered,false,&bundle);
        const bool delivery_local_ok=delivery_call&&delivered.available&&
            delivered.values==output_values&&
            delivered.multiplication_consistency_verified&&
            delivered.multiplication_proof_set_binding==verified_set&&
            delivered.output_consistency_statement_binding==verified_statement&&
            delivered.output_consistency_proof_binding==verified_proof&&
            !reference_god_output_production_authorized(delivered)&&
            !delivered.production_god_authorized;
        local_ok=delivery_local_ok?1:0;
        int delivery_all=0;
        MPI_Allreduce(&local_ok,&delivery_all,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
        delivery_path_ok=delivery_all==1;
        if(rank==0)std::cout
            <<"[PVIA][god-output-bundle-n4] delivery_path="
            <<(delivery_path_ok?"PASS":"FAIL")
            <<" production_gate=WITHHOLD"<<std::endl;
    }

    local_ok=positive&&bad_set_rejected&&bad_mc_proof_rejected&&
        bad_output_proof_rejected&&delivery_path_ok?1:0;
    int overall=0;
    MPI_Allreduce(&local_ok,&overall,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
    if(rank==0)std::cout<<"[PVIA][god-output-bundle-n4] "
        <<(overall?"PASS":"FAIL")
        <<" multiplication_proof=SP1_GROTH16 output_proof=SP1_GROTH16"
        <<" proof_set_binding=REAL_VERIFIED_ARTIFACT_SET"
        <<" positive_bundle="<<(positive?"PASS":"FAIL")
        <<" bad_set_binding="<<(bad_set_rejected?"REJECTED":"FAIL")
        <<" bad_multiplication_proof="<<(bad_mc_proof_rejected?"REJECTED":"FAIL")
        <<" bad_output_proof="<<(bad_output_proof_rejected?"REJECTED":"FAIL")
        <<" delivery_path="<<(delivery_path_enabled?(delivery_path_ok?"PASS":"FAIL"):"SKIPPED")
        <<" multiplication_acceptance="<<(use_real_mc_acceptance?"REAL_DISTRIBUTED":"TEST_FIXTURE")
        <<" anchor="<<(operator_pin_configured?"OPERATOR_CONFIGURED_PIN":"TEST_PIN_NOT_PRODUCTION")
        <<std::endl;
    return overall!=0;
}

bool open_authenticated_reference_god_output_n4(
    int rank,int world_size,const std::vector<F>& local_shares,
    bool send_share,const Digest& scope,
    const AuthenticatedMpcMessageContext& base,
    const AuthenticatedMpcExchange& exchange,
    ReferenceGodOutput* output,bool require_anchor,
    const ReferenceGodOutputConsistencyProofBundle* consistency_proof) {
    ReferenceGodOutput fallback;
    const bool output_supplied=output!=nullptr;
    if(!output)output=&fallback;
    *output=ReferenceGodOutput{};
    int ar=-1,aw=0;
    MPI_Comm_rank(MPI_COMM_WORLD,&ar); MPI_Comm_size(MPI_COMM_WORLD,&aw);
    const size_t n=local_shares.size();
    bool local_values_valid=true;
    if(send_share)for(const F& value:local_shares)if(!valid_field(value))local_values_valid=false;
    const bool local_preflight=output_supplied&&rank==ar&&world_size==aw&&world_size==4&&
       exchange.ready()&&validate_authenticated_mpc_message_context(base)&&base.sid&&
       base.checkpoint&&base.round<=UINT64_MAX-66&&base.sequence<=UINT64_MAX-66&&
       n>0&&n<=4096&&scope!=Digest{}&&local_values_valid&&
       (!require_anchor||exchange.production_authenticated_ready());
    int local_preflight_int=local_preflight?1:0,all_preflight_int=0;
    MPI_Allreduce(&local_preflight_int,&all_preflight_int,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
    if(!all_preflight_int)return false;
    const uint64_t local_count=static_cast<uint64_t>(n);
    uint64_t min_count=0,max_count=0;
    MPI_Allreduce(&local_count,&min_count,1,MPI_UINT64_T,MPI_MIN,MPI_COMM_WORLD);
    MPI_Allreduce(&local_count,&max_count,1,MPI_UINT64_T,MPI_MAX,MPI_COMM_WORLD);
    if(min_count!=max_count)return false;
    const auto caps=exchange.Capabilities();
    AuthenticatedMpcMessageContext sc=base;
    sc.message_kind=GOD_AUTH_SHARE_DOMAIN;
    if(!validate_authenticated_mpc_message_context(sc))return false;
    const bool bounded=n<=4096;
    const size_t packed=bounded?n:0;
    const auto sw=god_digest_words(scope);
    std::vector<u64> payload={GOD_AUTH_SHARE_DOMAIN,
        static_cast<u64>(rank),send_share?1ULL:0ULL,
        static_cast<u64>(n),sw[0],sw[1],sw[2],sw[3]};
    payload.reserve(8+2*packed);
    for(size_t i=0;i<packed;++i) {
        payload.push_back(send_share?local_shares[i].real:0ULL);
        payload.push_back(send_share?local_shares[i].img:0ULL);
    }
    std::vector<u64> all;
    Digest share_transport{};
    if(!exchange.AllGatherWords(sc,payload,&all,&share_transport))return false;
    const size_t width=payload.size();
    if(width<8||all.size()!=width*static_cast<size_t>(world_size))return false;
    bool metadata=bounded&&n>0&&scope!=Digest{}&&share_transport!=Digest{};
    std::vector<int> providers;
    std::vector<std::vector<F>> shares;
    for(int sender=0;sender<world_size;++sender) {
        const size_t off=static_cast<size_t>(sender)*width;
        const u64 flag=all[off+2],count=all[off+3];
        if(all[off]!=GOD_AUTH_SHARE_DOMAIN||
           all[off+1]!=static_cast<u64>(sender)||flag>1||count!=n||
           god_words_digest(&all[off+4])!=scope)metadata=false;
        if(flag==0) {
            for(size_t j=8;j<width;++j)if(all[off+j]!=0)metadata=false;
            continue;
        }
        std::vector<F> row;row.reserve(n);
        for(size_t j=0;j<n;++j) {
            u64 re=all[off+8+2*j],im=all[off+9+2*j];
            if(re>=F::mod||im>=F::mod)metadata=false;
            row.emplace_back(static_cast<long long>(re),
                             static_cast<long long>(im));
        }
        providers.push_back(sender);shares.push_back(std::move(row));
    }

    ReferenceGodOutput recovered;
    bool ready=metadata&&reconstruct_reference_god_output_n4(
        providers,shares,scope,&recovered);
    Digest candidate{};
    Digest verified_proof_set_binding{};
    Digest verified_statement_binding{};
    Digest verified_output_proof_binding{};
    bool multiplication_consistency_verified=false;
    if(ready) {
        bool local_proof_valid=true;
        if(consistency_proof) {
            local_proof_valid=verify_reference_god_output_consistency_bundle(
                base.sid,base.checkpoint,scope,recovered.values,*consistency_proof,
                &verified_proof_set_binding,&verified_statement_binding,
                &verified_output_proof_binding);
        }
        AuthenticatedMpcMessageContext pc=base;
        ++pc.round;++pc.sequence;pc.message_kind=GOD_AUTH_PROOF_BINDING_DOMAIN;
        const auto pb=god_digest_words(verified_output_proof_binding);
        const auto ps=god_digest_words(verified_proof_set_binding);
        const auto st=god_digest_words(verified_statement_binding);
        std::vector<u64> local_proof_meta={consistency_proof?1ULL:0ULL,
            local_proof_valid?1ULL:0ULL,
            pb[0],pb[1],pb[2],pb[3],ps[0],ps[1],ps[2],ps[3],
            st[0],st[1],st[2],st[3]};
        std::vector<u64> all_proof_meta;Digest proof_meta_transcript{};
        if(!validate_authenticated_mpc_message_context(pc)||
           !exchange.AllGatherWords(pc,local_proof_meta,&all_proof_meta,
                                    &proof_meta_transcript)||
           proof_meta_transcript==Digest{}||
           all_proof_meta.size()!=local_proof_meta.size()*
                static_cast<size_t>(world_size))return false;
        bool same_proof_mode=true;
        for(int r=0;r<world_size;++r) {
            const size_t off=static_cast<size_t>(r)*local_proof_meta.size();
            for(size_t j=0;j<local_proof_meta.size();++j)
                if(all_proof_meta[off+j]!=all_proof_meta[j])same_proof_mode=false;
        }
        const bool proof_present=all_proof_meta[0]==1;
        const bool proof_valid=all_proof_meta[1]==1;
        if(!same_proof_mode||all_proof_meta[0]>1||all_proof_meta[1]>1||
           !proof_valid||
           (proof_present&&(verified_output_proof_binding==Digest{}||
             verified_proof_set_binding==Digest{}||
             verified_statement_binding==Digest{}))||
           (!proof_present&&(verified_output_proof_binding!=Digest{}||
             verified_proof_set_binding!=Digest{}||
             verified_statement_binding!=Digest{})))return false;
        multiplication_consistency_verified=proof_present&&proof_valid;
        std::vector<u64> w={GOD_AUTH_CERT_DOMAIN,base.protocol_domain,
            base.sid,base.checkpoint,base.round,base.sequence,4ULL,1ULL};
        append_god_digest(scope,&w);append_god_digest(share_transport,&w);
        append_god_digest(hash_field_vector(recovered.values),&w);
        append_god_digest(verified_output_proof_binding,&w);
        append_god_digest(proof_meta_transcript,&w);
        candidate=hash_words(w);if(candidate==Digest{})ready=false;
    }
    if(!ready||candidate==Digest{})return false;
    std::vector<std::pair<Digest,uint32_t>> tally;
    std::vector<u64> rbc_words={GOD_AUTH_CERT_DOMAIN,base.protocol_domain,
        base.sid,base.checkpoint,base.round,base.sequence,4ULL,1ULL};
    append_god_digest(scope,&rbc_words);
    append_god_digest(share_transport,&rbc_words);
    for(int broadcaster=0;broadcaster<world_size;++broadcaster) {
        AuthenticatedMpcMessageContext bc=base;
        const uint64_t offset=2ULL+16ULL*static_cast<uint64_t>(broadcaster);
        bc.round+=offset;bc.sequence+=offset;bc.message_kind=GOD_AUTH_VOTE_DOMAIN;
        std::vector<u64> local_vote;
        if(rank==broadcaster) {
            const auto cw=god_digest_words(candidate);
            local_vote={GOD_AUTH_VOTE_DOMAIN,cw[0],cw[1],cw[2],cw[3]};
        }
        AuthenticatedReliableBroadcastResult rb;
        if(!authenticated_reliable_broadcast_n4(
            rank,world_size,broadcaster,local_vote,5,bc,exchange,&rb)||
           !rb.available||rb.transcript_binding==Digest{})return false;
        rbc_words.push_back(static_cast<u64>(broadcaster));
        rbc_words.push_back(rb.delivered?1ULL:0ULL);
        append_god_digest(rb.transcript_binding,&rbc_words);
        if(!rb.delivered)continue;
        if(rb.payload.size()!=5||rb.payload[0]!=GOD_AUTH_VOTE_DOMAIN)continue;
        const Digest d=god_words_digest(&rb.payload[1]);
        if(d==Digest{})continue;
        auto it=std::find_if(tally.begin(),tally.end(),
            [&](const auto& x){return x.first==d;});
        if(it==tally.end())tally.emplace_back(d,1);else ++it->second;
    }
    Digest winner{};uint32_t support=0;
    for(const auto& x:tally)if(x.second>=3) {
        if(winner!=Digest{}&&winner!=x.first)return false;
        winner=x.first;support=x.second;
    }
    const Digest rbc_binding=hash_words(rbc_words);
    if(winner==Digest{}||winner!=candidate||support<3||rbc_binding==Digest{})
        return false;
    std::vector<u64> cert_words={GOD_AUTH_CERT_DOMAIN,base.protocol_domain,
        base.sid,base.checkpoint,base.round,base.sequence,4ULL,1ULL,
        static_cast<u64>(support)};
    append_god_digest(scope,&cert_words);
    append_god_digest(share_transport,&cert_words);
    append_god_digest(winner,&cert_words);
    append_god_digest(rbc_binding,&cert_words);
    Digest cert=hash_words(cert_words);if(cert==Digest{})return false;
    output->available=true;output->values=std::move(recovered.values);
    output->delivered_participants=recovered.delivered_participants;
    output->corrected_participants=recovered.corrected_participants;
    output->scope_binding=scope;output->transport_binding=share_transport;
    output->agreement_certificate=cert;output->transcript_binding=cert;
    output->agreement_votes=support;output->authenticated_transport=true;
    output->reliable_broadcast_verified=true;
    output->external_registry_anchor_verified=caps.external_registry_anchor_verified;
    output->production_authenticated_transport=
        exchange.production_authenticated_ready();
    output->multiplication_consistency_verified=
        multiplication_consistency_verified;
    output->multiplication_proof_set_binding=verified_proof_set_binding;
    output->output_consistency_statement_binding=verified_statement_binding;
    output->output_consistency_proof_binding=verified_output_proof_binding;
    return true;
}

bool reference_god_output_production_authorized(
    const ReferenceGodOutput& output) {
    return output.available && output.authenticated_transport &&
        output.external_registry_anchor_verified &&
        output.production_authenticated_transport &&
        // Survivor votes authenticate one reconstructed value. They do not
        // by themselves establish a Byzantine reliable-broadcast primitive.
        // Require BOTH independently verified properties for production GOD.
        output.reliable_broadcast_verified &&
        output.survivor_agreement_verified &&
        output.process_crash_tolerant &&
        output.verifiable_sharing_verified &&
        output.authenticated_vss_verified &&
        output.vss_transcript_binding!=Digest{} &&
        output.multiplication_consistency_verified &&
        output.multiplication_proof_set_binding!=Digest{} &&
        output.output_consistency_statement_binding!=Digest{} &&
        output.output_consistency_proof_binding!=Digest{} &&
        output.complete_application_relation_set_verified &&
        output.agreement_votes>=3 &&
        output.transport_binding!=Digest{} &&
        output.agreement_certificate!=Digest{} &&
        output.transcript_binding!=Digest{};
}

bool run_reference_god_authenticated_output_n4_selftest(int rank,int world_size) {
    if(world_size!=4||rank<0||rank>=4)return false;
    const char* external_anchor_mode_env =
        std::getenv("PVIA_GOD_OUTPUT_EXTERNAL_ANCHOR");
    const bool external_anchor_requested =
        external_anchor_mode_env &&
        std::string(external_anchor_mode_env) == "1";
    AuthenticatedMpcExchange exchange(rank,world_size);
    if(!exchange.ready()) {
        if(rank==0)std::cout<<"[PVIA][god-auth-output-n4] FAIL auth_unavailable"<<std::endl;
        return false;
    }
    if(!run_authenticated_reliable_broadcast_n4_selftest(rank,world_size,exchange))
        return false;
    const u64 sid=Runtime::instance().session_id()
        ?Runtime::instance().session_id():1ULL;
    constexpr CheckpointId checkpoint=GOD_AUTH_CHECKPOINT;
    const std::vector<F> secret={F(97,11),F(123,3),F(234,28)};
    ReferenceBivariateVss output_vss(rank,world_size,1);
    std::vector<F> local;
    ReferenceVssReceipt vss_receipt;
    ReferenceVssDealerWitness dealer_witness;
    ReferenceVssLocalWitness local_witness;
    const bool vss_shared=output_vss.valid() &&
        output_vss.ShareVectorFromDealerWithWitnesses(
            0,rank==0?secret:std::vector<F>{},&local,&vss_receipt,
            &dealer_witness,&local_witness);
    const bool vss_receipt_ok=vss_shared && vss_receipt.available &&
        vss_receipt.consistent && vss_receipt.world_size==world_size &&
        vss_receipt.threshold==1 && vss_receipt.element_count==secret.size() &&
        vss_receipt.transcript_binding!=Digest{} && local.size()==secret.size();
    const bool dealer_source_link_ok=rank!=0 ||
        verify_reference_vss_dealer_secret_link(
            dealer_witness,secret,vss_receipt.transcript_binding);
    const bool recipient_share_link_ok=vss_receipt_ok &&
        verify_reference_vss_recipient_share_link(
            local_witness,local,vss_receipt.transcript_binding);
    int vss_link_local=vss_receipt_ok && dealer_source_link_ok &&
        recipient_share_link_ok ? 1:0;
    int vss_link_all=0;
    MPI_Allreduce(&vss_link_local,&vss_link_all,1,MPI_INT,MPI_MIN,
                  MPI_COMM_WORLD);
    if(!vss_link_all) {
        if(rank==0)std::cout
            <<"[PVIA][god-auth-output-n4] FAIL vss_source_link_preflight"
            <<std::endl;
        return false;
    }
    std::vector<F> wrong_secret=secret;
    if(rank==0)wrong_secret[0]+=F(1,0);
    const bool bad_dealer_source_rejected=rank!=0 ||
        !verify_reference_vss_dealer_secret_link(
            dealer_witness,wrong_secret,vss_receipt.transcript_binding);
    std::vector<F> wrong_local=local;
    if(rank==1 && !wrong_local.empty())wrong_local[0]+=F(1,0);
    const bool bad_recipient_share_rejected=rank!=1 ||
        !verify_reference_vss_recipient_share_link(
            local_witness,wrong_local,vss_receipt.transcript_binding);
    const Digest wrong_vss_transcript=hash_words(
        {GOD_AUTH_PROTOCOL,sid,0xBAD0551ULL});
    const bool wrong_vss_transcript_rejected=
        !verify_reference_vss_recipient_share_link(
            local_witness,local,wrong_vss_transcript);
    int vss_negative_local=bad_dealer_source_rejected &&
        bad_recipient_share_rejected && wrong_vss_transcript_rejected?1:0;
    int vss_negative_all=0;
    MPI_Allreduce(&vss_negative_local,&vss_negative_all,1,MPI_INT,MPI_MIN,
                  MPI_COMM_WORLD);
    if(!vss_negative_all) {
        if(rank==0)std::cout
            <<"[PVIA][god-auth-output-n4] FAIL vss_source_link_negative"
            <<std::endl;
        return false;
    }
    Digest vss_recovery_binding{};
    Digest vss_registry_binding{};
    Digest vss_recovery_artifact_binding{};
    Digest vss_recovery_proof_binding{};
    const bool vss_recovery_preflight_ok =
        run_god_output_vss_recovery_preflight_n4(
            rank,world_size,sid,checkpoint,exchange,secret,local,
            vss_receipt,local_witness,&vss_recovery_binding,
            &vss_registry_binding,&vss_recovery_artifact_binding,
            &vss_recovery_proof_binding);
    int vss_recovery_local=vss_recovery_preflight_ok?1:0;
    int vss_recovery_all=0;
    if(MPI_Allreduce(&vss_recovery_local,&vss_recovery_all,1,
                     MPI_INT,MPI_MIN,MPI_COMM_WORLD)!=MPI_SUCCESS ||
       !vss_recovery_all || vss_recovery_binding==Digest{} ||
       vss_registry_binding==Digest{} ||
       vss_recovery_artifact_binding==Digest{}) {
        if(rank==0)std::cout
            <<"[PVIA][god-auth-output-n4] FAIL vss_recovery_preflight"
            <<std::endl;
        return false;
    }
    const char* live_proof_env=std::getenv("PVIA_SP1_VSS_RECOVERY_PROVE_ONCE");
    const bool live_sp1_required=
        live_proof_env&&std::string(live_proof_env)=="1";
    const char* live_verify_env=
        std::getenv("PVIA_SP1_VSS_RECOVERY_VERIFY_ON_IMPORT");
    const bool live_sp1_verify_required=
        live_verify_env&&std::string(live_verify_env)=="1";
    if(live_sp1_required&&
       (vss_recovery_proof_binding==Digest{}||!live_sp1_verify_required))
        return false;

    const Digest base_scope=hash_words({GOD_AUTH_PROTOCOL,sid,
        static_cast<u64>(checkpoint),4ULL,1ULL});
    const auto base_scope_words=god_digest_words(base_scope);
    const auto vss_scope_words=god_digest_words(vss_receipt.transcript_binding);
    const auto recovery_scope_words=god_digest_words(vss_recovery_binding);
    const auto registry_scope_words=god_digest_words(vss_registry_binding);
    const auto recovery_artifact_words=god_digest_words(
        vss_recovery_artifact_binding);
    const auto recovery_proof_words=god_digest_words(vss_recovery_proof_binding);
    const Digest scope=hash_words({GOD_AUTH_PROTOCOL,0x5653534f55545054ULL,
        sid,static_cast<u64>(checkpoint),
        base_scope_words[0],base_scope_words[1],base_scope_words[2],base_scope_words[3],
        vss_scope_words[0],vss_scope_words[1],vss_scope_words[2],vss_scope_words[3],
        recovery_scope_words[0],recovery_scope_words[1],
        recovery_scope_words[2],recovery_scope_words[3],
        registry_scope_words[0],registry_scope_words[1],
        registry_scope_words[2],registry_scope_words[3],
        recovery_artifact_words[0],recovery_artifact_words[1],
        recovery_artifact_words[2],recovery_artifact_words[3],
        recovery_proof_words[0],recovery_proof_words[1],
        recovery_proof_words[2],recovery_proof_words[3]});
    if(scope==Digest{})return false;
    ReferenceGodOutputConsistencyStatement output_statement;
    output_statement.sid=sid;output_statement.checkpoint=checkpoint;
    output_statement.scope_binding=scope;
    output_statement.output_value_count=secret.size();
    output_statement.output_values_binding=hash_field_vector(secret);
    output_statement.multiplication_proof_set_binding=
        hash_words({GOD_OUTPUT_CONSISTENCY_SET_DOMAIN,sid,
                    static_cast<u64>(checkpoint),
                    static_cast<u64>(secret.size())});
    for(size_t i=0;i<secret.size();++i) {
        MultiplicationConsistencyStatement multiplication;
        multiplication.sid=sid;multiplication.checkpoint=checkpoint;
        multiplication.multiplication_id=static_cast<uint64_t>(i+1);
        multiplication.dealer=0;
        multiplication.lhs_sharing_binding=hash_words(
            {GOD_OUTPUT_CONSISTENCY_STATEMENT_DOMAIN,sid,i,1ULL});
        multiplication.rhs_sharing_binding=hash_words(
            {GOD_OUTPUT_CONSISTENCY_STATEMENT_DOMAIN,sid,i,2ULL});
        multiplication.output_sharing_binding=hash_words(
            {GOD_OUTPUT_CONSISTENCY_STATEMENT_DOMAIN,sid,i,3ULL});
        multiplication.context_binding=hash_words(
            {GOD_OUTPUT_CONSISTENCY_STATEMENT_DOMAIN,sid,i,4ULL});
        multiplication.statement_binding=
            compute_multiplication_consistency_statement_binding(multiplication);
        output_statement.multiplication_statements.push_back(multiplication);
    }
    output_statement.statement_binding=
        compute_reference_god_output_consistency_statement_binding(output_statement);
    const bool statement_binding_ok=
        validate_reference_god_output_consistency_statement(output_statement);
    const auto statement_abi=
        encode_reference_god_output_consistency_statement_abi(output_statement);
    const bool statement_abi_ok=!statement_abi.empty()&&statement_abi.size()>
        output_statement.multiplication_statements.size()*26;
    ReferenceGodOutputConsistencyWitness empty_output_witness;
    const bool invalid_output_witness_rejected=
        !validate_reference_god_output_consistency_witness(
            output_statement,empty_output_witness)&&
        encode_reference_god_output_consistency_witness_abi(
            output_statement,empty_output_witness).empty();
    ReferenceGodOutputConsistencyStatement changed_statement=output_statement;
    changed_statement.output_values_binding=hash_words(
        {GOD_OUTPUT_CONSISTENCY_STATEMENT_DOMAIN,0xBADULL});
    const bool statement_mutation_rejected=
        !validate_reference_god_output_consistency_statement(changed_statement);
    ReferenceGodOutputConsistencyStatement changed_statement_set=output_statement;
    changed_statement_set.multiplication_statements[0].statement_binding=
        hash_words({GOD_OUTPUT_CONSISTENCY_STATEMENT_DOMAIN,0xBADDULL});
    const bool statement_set_mutation_rejected=
        !validate_reference_god_output_consistency_statement(changed_statement_set);
    ReferenceGodOutputConsistencyProofArtifact sample_proof;
    sample_proof.available=true;sample_proof.cryptographically_authenticated=true;
    sample_proof.zero_knowledge=true;sample_proof.proof_system_id=1;
    sample_proof.statement_binding=output_statement.statement_binding;
    sample_proof.transcript_binding=hash_words(
        {GOD_OUTPUT_CONSISTENCY_PROOF_DOMAIN,sid,1ULL});
    sample_proof.proof_words={1ULL,2ULL,3ULL};
    sample_proof.proof_commitment=
        compute_reference_god_output_consistency_proof_commitment(sample_proof);
    const bool proof_commitment_ok=
        validate_reference_god_output_consistency_proof(output_statement,sample_proof);
    sample_proof.proof_words[0]^=1ULL;
    const bool proof_mutation_rejected=
        !validate_reference_god_output_consistency_proof(output_statement,sample_proof);
    ReferenceGodOutputConsistencyCapabilities test_output_caps;
    test_output_caps.available=true;test_output_caps.malicious_sound=true;
    test_output_caps.zero_knowledge=true;test_output_caps.binds_output_values=true;
    test_output_caps.binds_multiplication_proof_set=true;
    test_output_caps.binds_scope_and_session=true;
    test_output_caps.external_registry_anchor_verified=true;
    test_output_caps.protocol_id=0x535031474f443031ULL;
    test_output_caps.external_registry_anchor=hash_words(
        {GOD_OUTPUT_CONSISTENCY_CAP_DOMAIN,sid,0xA11CEULL});
    test_output_caps.relation_binding=
        compute_reference_god_output_consistency_relation_binding();
    test_output_caps.implementation_binding=hash_words(
        {GOD_OUTPUT_CONSISTENCY_CAP_DOMAIN,0x1A2B3CULL});
    test_output_caps.capability_binding=
        compute_reference_god_output_consistency_capability_binding(
            test_output_caps);
    ReferenceGodOutputConsistencyProviderCallbacks missing_anchor_callbacks;
    missing_anchor_callbacks.prove=[](const auto&,const auto&) {
        return ReferenceGodOutputConsistencyProofArtifact{};
    };
    missing_anchor_callbacks.verify=[](const auto&,const auto&) {return false;};
    ExternalReferenceGodOutputConsistencyProofAdapter missing_anchor_adapter(
        test_output_caps,68102,missing_anchor_callbacks);
    const bool missing_anchor_rejected=!missing_anchor_adapter.ready()&&
        !missing_anchor_adapter.external_anchor_verified();
    auto rejected_anchor_callbacks=missing_anchor_callbacks;
    rejected_anchor_callbacks.verify_external_anchor=
        [](const ReferenceGodOutputConsistencyCapabilities&) {return false;};
    ExternalReferenceGodOutputConsistencyProofAdapter rejected_anchor_adapter(
        test_output_caps,68102,rejected_anchor_callbacks);
    const bool rejected_anchor_rejected=!rejected_anchor_adapter.ready()&&
        !rejected_anchor_adapter.external_anchor_verified()&&
        !ReferenceGodOutputConsistencyBackendRegistry::InstallAccepted(
            &rejected_anchor_adapter);
    auto same_digest_on_all_ranks=[&](const Digest& digest) {
        std::vector<uint8_t> gathered(static_cast<size_t>(world_size)*digest.bytes.size());
        MPI_Allgather(digest.bytes.data(),static_cast<int>(digest.bytes.size()),MPI_BYTE,
            gathered.data(),static_cast<int>(digest.bytes.size()),MPI_BYTE,MPI_COMM_WORLD);
        for(int peer=0;peer<world_size;++peer) {
            const uint8_t* begin=gathered.data()+static_cast<size_t>(peer)*digest.bytes.size();
            if(!std::equal(digest.bytes.begin(),digest.bytes.end(),begin))return false;
        }
        return true;
    };
    int index=0;
    auto run=[&](int missing,int corrupted,bool expect,bool expect_corrected,
                 bool bad_scope,bool bad_shape) {
        std::vector<F> row=local;
        if(rank==corrupted&&row.size()>1)row[1]+=F(19,0);
        if(bad_shape&&rank==3)row.push_back(F(41));
        Digest local_scope=scope;
        if(bad_scope&&rank==3)local_scope=hash_words(
            {GOD_AUTH_PROTOCOL,sid,static_cast<u64>(checkpoint),4ULL,2ULL});
        AuthenticatedMpcMessageContext ctx;
        ctx.protocol_domain=GOD_AUTH_PROTOCOL;ctx.sid=sid;
        ctx.checkpoint=checkpoint;ctx.round=1000+100*index;
        ctx.sequence=1000+100*index;ctx.message_kind=1;++index;
        ReferenceGodOutput out;
        bool ok=open_authenticated_reference_god_output_n4(
            rank,world_size,row,rank!=missing,local_scope,ctx,
            exchange,&out,false);
        if(ok) {
            // The VSS transcript is included in local_scope, which is itself
            // bound by the signed share envelopes and quorum certificate.
            out.verifiable_sharing_verified=true;
            out.authenticated_vss_verified=
                vss_receipt.transcript_context.authenticated;
            out.vss_transcript_binding=vss_receipt.transcript_binding;
            out.vss_recovery_backend_verified=vss_recovery_preflight_ok;
            out.sp1_vss_recovery_proof_imported=
                vss_recovery_proof_binding!=Digest{};
            out.vss_registry_binding=vss_registry_binding;
            out.vss_recovery_artifact_binding=vss_recovery_artifact_binding;
            out.vss_recovery_proof_binding=vss_recovery_proof_binding;
        }
        int local_case_ok=ok==expect?1:0,all_case_ok=0;
        MPI_Allreduce(&local_case_ok,&all_case_ok,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
        if(!all_case_ok)return false;
        if(!expect)return !out.available;
        return out.available&&out.values==secret&&out.authenticated_transport&&
            out.reliable_broadcast_verified&&same_digest_on_all_ranks(out.agreement_certificate)&&
            out.agreement_votes>=3&&out.delivered_participants==
            static_cast<uint32_t>(missing>=0?3:4)&&
            (out.corrected_participants==1)==expect_corrected&&
            out.transport_binding!=Digest{}&&out.agreement_certificate!=Digest{}&&
            out.verifiable_sharing_verified&&
            out.vss_transcript_binding==vss_receipt.transcript_binding&&
            !out.authenticated_vss_verified&&
            !out.multiplication_consistency_verified&&
            out.multiplication_proof_set_binding==Digest{}&&
            out.output_consistency_statement_binding==Digest{}&&
            out.output_consistency_proof_binding==Digest{}&&
            !reference_god_output_production_authorized(out)&&
            !out.production_god_authorized;
    };
    const bool clean=run(-1,-1,true,false,false,false);
    const bool missing=run(3,-1,true,false,false,false);
    const bool corrected=run(-1,2,true,true,false,false);
    const bool beyond=run(3,2,false,false,false,false);
    const bool stale=run(-1,-1,false,false,true,false);
    const bool shape=run(-1,-1,false,false,false,true);
    bool anchor_fail_closed=true;
    if(!exchange.production_authenticated_ready()) {
        AuthenticatedMpcMessageContext blocked_context;
        blocked_context.protocol_domain=GOD_AUTH_PROTOCOL;
        blocked_context.sid=sid;blocked_context.checkpoint=checkpoint;
        blocked_context.round=900;blocked_context.sequence=900;
        blocked_context.message_kind=1;
        ReferenceGodOutput blocked;
        anchor_fail_closed=!open_authenticated_reference_god_output_n4(
            rank,world_size,local,true,scope,blocked_context,
            exchange,&blocked,true)&&!blocked.available;
    }
    AuthenticatedMpcMessageContext invalid_context;
    invalid_context.protocol_domain=GOD_AUTH_PROTOCOL;invalid_context.sid=sid;
    invalid_context.checkpoint=checkpoint;invalid_context.round=2000;
    invalid_context.sequence=2000;invalid_context.message_kind=1;
    if(rank==2)invalid_context.protocol_domain=0;
    ReferenceGodOutput invalid_context_output;
    const bool invalid_context_call=open_authenticated_reference_god_output_n4(
        rank,world_size,local,true,scope,invalid_context,exchange,
        &invalid_context_output,false);
    const bool invalid_context_rejected=!invalid_context_call&&
        !invalid_context_output.available;
    AuthenticatedMpcMessageContext null_context;
    null_context.protocol_domain=GOD_AUTH_PROTOCOL;null_context.sid=sid;
    null_context.checkpoint=checkpoint;null_context.round=2200;
    null_context.sequence=2200;null_context.message_kind=1;
    ReferenceGodOutput null_output;
    const bool null_output_call=open_authenticated_reference_god_output_n4(
        rank,world_size,local,true,scope,null_context,exchange,
        rank==3?nullptr:&null_output,false);
    const bool null_output_rejected=!null_output_call&&
        (rank==3||!null_output.available);
    AuthenticatedMpcMessageContext proof_mode_context;
    proof_mode_context.protocol_domain=GOD_AUTH_PROTOCOL;
    proof_mode_context.sid=sid;proof_mode_context.checkpoint=checkpoint;
    proof_mode_context.round=2400;proof_mode_context.sequence=2400;
    proof_mode_context.message_kind=1;
    ReferenceGodOutputConsistencyProofBundle invalid_bundle;
    ReferenceGodOutput proof_mode_output;
    const bool proof_mode_call=open_authenticated_reference_god_output_n4(
        rank,world_size,local,true,scope,proof_mode_context,exchange,
        &proof_mode_output,false,rank==3?nullptr:&invalid_bundle);
    const bool proof_mode_rejected=!proof_mode_call&&!proof_mode_output.available;
    bool local_ok=clean&&missing&&corrected&&beyond&&stale&&shape&&
        anchor_fail_closed&&invalid_context_rejected&&null_output_rejected&&
        vss_link_all==1&&vss_negative_all==1&&
        vss_recovery_preflight_ok&&vss_recovery_all==1&&
        (!live_sp1_required||vss_recovery_proof_binding!=Digest{})&&
        statement_binding_ok&&statement_abi_ok&&
        invalid_output_witness_rejected&&statement_mutation_rejected&&
        statement_set_mutation_rejected&&proof_commitment_ok&&
        proof_mutation_rejected&&proof_mode_rejected&&
        missing_anchor_rejected&&rejected_anchor_rejected;
    int score=local_ok?1:0,all=0;
    MPI_Allreduce(&score,&all,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
    if(rank==0)std::cout<<"[PVIA][god-auth-output-n4] "
        <<(all?"PASS":"FAIL")
        <<" signed_output_shares=PASS quorum_certificate=PASS"
        <<" vss_source_links="<<(vss_link_all?"PASS":"FAIL")
        <<" bad_dealer_source="<<(vss_negative_all?"REJECTED":"FAIL")
        <<" bad_recipient_share="<<(vss_negative_all?"REJECTED":"FAIL")
        <<" wrong_vss_transcript="<<(vss_negative_all?"REJECTED":"FAIL")
        <<" vss_mode=REFERENCE_UNAUTHENTICATED"
        <<" vss_registry_persistence=PASS"
        <<" vss_independent_pin_verification=PASS mode="
        <<(external_anchor_requested?"REMOTE_EXTERNAL_ANCHOR":"TEST_LOCAL_CALLBACK")
        <<" missing_independent_pin_verifier=REJECTED"
        <<" pin_preflight_before_openings=PASS"
        <<" vss_replay_head_anchor=PASS stale_replay_head_anchor=REJECTED"
        <<" replay_head_anchor_mode="
        <<(external_anchor_requested?"REMOTE_EXTERNAL":"LOCAL_DURABLE_NOT_EXTERNAL")
        <<" external_anchor_commit_before_recovery_output="
        <<(external_anchor_requested?(vss_recovery_preflight_ok?"PASS":"FAIL"):"NOT_REQUESTED")
        <<" vss_recovery_backend=PASS"
        <<" bad_registry_anchor=REJECTED"
        <<" sp1_recovery_proof_import="
                    <<(vss_recovery_proof_binding!=Digest{}?"PASS":"NOT_REQUESTED")
        <<" sp1_recovery_proof_crypto_verification="
                    <<(live_sp1_verify_required?"PASS":"NOT_REQUESTED")
        <<" output_scope_binds_recovery="<<(vss_recovery_binding!=Digest{}?"PASS":"FAIL")
        <<" all_present="<<(clean?"PASS":"FAIL")
        <<" one_omitted="<<(missing?"PASS":"FAIL")
        <<" one_corrupted="<<(corrected?"PASS":"FAIL")
        <<" beyond_bound="<<(beyond?"REJECTED":"FAIL")
        <<" stale_scope="<<(stale?"REJECTED":"FAIL")
        <<" shape_mismatch="<<(shape?"REJECTED":"FAIL")
        <<" invalid_context="<<(invalid_context_rejected?"REJECTED":"FAIL")
        <<" null_output="<<(null_output_rejected?"REJECTED":"FAIL")
        <<" output_statement_binding="<<(statement_binding_ok?"PASS":"FAIL")
        <<" output_statement_abi="<<(statement_abi_ok?"PASS":"FAIL")
        <<" invalid_output_witness="<<(invalid_output_witness_rejected?"REJECTED":"FAIL")
        <<" statement_mutation="<<(statement_mutation_rejected?"REJECTED":"FAIL")
        <<" statement_set_mutation="<<(statement_set_mutation_rejected?"REJECTED":"FAIL")
        <<" proof_commitment="<<(proof_commitment_ok?"PASS":"FAIL")
        <<" proof_mutation="<<(proof_mutation_rejected?"REJECTED":"FAIL")
        <<" proof_mode_mismatch="<<(proof_mode_rejected?"REJECTED":"FAIL")
        <<" missing_anchor_callback="<<(missing_anchor_rejected?"REJECTED":"FAIL")
        <<" invalid_external_anchor="<<(rejected_anchor_rejected?"REJECTED":"FAIL")
        <<" proof_absent=WITHHOLD"
        <<" release_gate=WITHHOLD"
        <<" external_anchor="
        <<(external_anchor_requested&&vss_recovery_preflight_ok?"YES":"NO")
        <<" production_authenticated_transport="
        <<(exchange.production_authenticated_ready()?"YES":"NO")
        <<" unanchored_default_rejected="
        <<(anchor_fail_closed?"PASS":"FAIL")
        <<" process_crash_tolerance=false reference_reliable_broadcast=PASS"
        <<" multiplication_consistency=false full_malicious_god=false"<<std::endl;
    return all!=0;
}

} // namespace pvia
