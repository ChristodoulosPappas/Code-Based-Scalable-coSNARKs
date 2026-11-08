#include "ReferenceVssSelectivePointSelfTest.hpp"
#include "ReferenceVssSelectivePointRecovery.hpp"
#include "ReferenceVssSelectivePointEnvelope.hpp"
#include "ReferenceVssSelectivePointCommitment.hpp"
#include "ReferenceVssSelectivePointRegistryStore.hpp"
#include "ReferenceVssPointNativeIssuerBridge.hpp"
#include "ReferenceVssSelectivePointDurableReplay.hpp"
#include "ReferenceVssSelectiveReleaseCoordinator.hpp"
#include "ReferenceVssExternalAnchor.hpp"
#include "ReferenceVssAuthenticatedAuditRecoveryBackend.hpp"
#include "RegistrationPreVssReceipt.hpp"
#include <openssl/evp.h>
#include "TransferAuthentication.hpp"
#include "PublicBlameProof.hpp"
#include "PublicJudge.hpp"
#include "Sp1VssRecoveryProofProvider.hpp"

#include <mpi.h>
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <array>
#include <string>
#include <unistd.h>
#include <limits>
#include <vector>

namespace pvia {
namespace {
struct ExternalAnchorJournalCleanup {
    std::string path;
    ~ExternalAnchorJournalCleanup() {
        if (!path.empty()) ::unlink(path.c_str());
    }
};

bool external_anchor_collective_ok(bool local_ok) {
    int value = local_ok ? 1 : 0;
    int all = 0;
    return MPI_Allreduce(&value, &all, 1, MPI_INT, MPI_MIN,
                         MPI_COMM_WORLD) == MPI_SUCCESS && all == 1;
}
} // namespace

// End-to-end integration against the separately hosted Anchor. This is
// enabled only by the dedicated N=4 runner; ordinary local selftests retain
// their existing file-backed fixture and do not require an external service.
bool run_reference_vss_external_anchor_coordinator_integration(
    const AuthenticatedMpcExchange& exchange,
    const ReferenceVssLocalWitness& local,
    int rank, int world_size, int target,
    const ReferenceVssReceipt& receipt,
    const ReferenceVssTranscriptContext& transcript,
    const AuthenticatedMpcMessageContext& base_context,
    const std::string& registry_path,
    const Digest& record_binding,
    const Digest& native_execution_binding,
    const Digest& registry_binding,
    const std::vector<F>& expected_share) {
    if (world_size != 4 || target != 0 || rank < 0 || rank >= world_size)
        return false;

    ExternalAnchorJournalCleanup journal_cleanup;
    std::string journal_path;
    Digest initial_head{};
    bool setup_ok = true;
    ReferenceVssExternalAnchorClient client;
    ReferenceVssExternalAnchorSnapshot snapshot;
    if (rank == target) {
        char name[] = "/tmp/pvia-external-anchor-coordinator-XXXXXX";
        const int fd = ::mkstemp(name);
        if (fd < 0) {
            setup_ok = false;
        } else {
            ::close(fd);
            ::unlink(name);
            journal_path = name;
            journal_cleanup.path = journal_path;
            ReferenceVssSelectivePointDurableReplayGuard journal(
                journal_path, registry_binding);
            setup_ok = journal.InitializeNew() &&
                journal.ReadCurrentHead(&initial_head) &&
                initial_head != Digest{};
        }
        setup_ok = setup_ok && client.LoadFromEnvironment() &&
            client.InitializeNew(record_binding, native_execution_binding,
                                 registry_binding, initial_head) &&
            client.ReadSnapshot(&snapshot) &&
            snapshot.record_binding == record_binding &&
            snapshot.native_execution_binding == native_execution_binding &&
            snapshot.registry_binding == registry_binding &&
            snapshot.generation == 0 && snapshot.replay_head == initial_head;
    }
    if (!setup_ok && rank == target)
        std::cerr << "PVIA_VSS_EXTERNAL_ANCHOR_COORDINATOR_N4: FAIL"
                  << " stage=anchor_and_journal_setup" << std::endl;
    if (!external_anchor_collective_ok(setup_ok)) return false;

    auto configure = [&](ReferenceVssExternalAnchorClient& selected_client,
                         const ReferenceVssExternalAnchorSnapshot& selected_snapshot,
                         ReferenceVssExternalAnchorResumeMode mode,
                         ReferenceVssSelectiveReleasePins* pins) {
        if (rank != target) return true;
        return selected_client.ConfigureReleasePins(
            registry_path, journal_path, selected_snapshot, mode, pins);
    };
    auto make_context = [&](u64 delta) {
        auto context = base_context;
        context.round += delta;
        context.sequence += delta;
        return context;
    };
    auto check_stage = [&](bool local_ok, const char* stage) {
        if (!local_ok && rank == target)
            std::cerr << "PVIA_VSS_EXTERNAL_ANCHOR_COORDINATOR_N4: FAIL"
                      << " stage=" << stage << std::endl;
        return external_anchor_collective_ok(local_ok);
    };

    // Fresh release: no recovery callback is enabled; the coordinator must
    // append the batch, CAS the remote head, reload it, then expose the share.
    const auto fresh_context = make_context(101);
    ReferenceVssSelectiveReleasePins fresh_pins;
    bool configured = configure(client, snapshot,
        ReferenceVssExternalAnchorResumeMode::kFresh, &fresh_pins);
    if (rank == target) configured = configured &&
        !fresh_pins.authorize_pending_resume &&
        !fresh_pins.authorize_committed_resume;
    if (!check_stage(configured, "fresh_mode_configuration")) return false;
    std::vector<F> recovered;
    Digest released_head{};
    ReferenceVssRecoveryProofWitness witness;
    bool released = release_reference_vss_selective_share_collective(
        exchange, local, target, receipt, transcript, fresh_context,
        rank == target ? &fresh_pins : nullptr,
        &recovered, &released_head, &witness);
    bool stage_ok = rank == target
        ? released && recovered == expected_share &&
              released_head != Digest{} && witness.available
        : released && recovered.empty() && released_head == Digest{} &&
              !witness.available;
    if (rank == target) {
        ReferenceVssExternalAnchorSnapshot after;
        stage_ok = stage_ok && client.ReadSnapshot(&after) &&
            after.generation == 1 && after.replay_head == released_head;
        if (stage_ok) snapshot = after;
    }
    if (!check_stage(stage_ok, "fresh_release")) return false;

    // Pending-resume window: let the coordinator fsync its complete journal
    // batch but deliberately suppress the remote CAS. No share may escape.
    const auto pending_context = make_context(102);
    ReferenceVssSelectiveReleasePins pending_write_pins;
    configured = configure(client, snapshot,
        ReferenceVssExternalAnchorResumeMode::kFresh, &pending_write_pins);
    if (rank == target && configured) {
        pending_write_pins.persist_new_head =
            [](const Digest&, const Digest&) { return false; };
    }
    if (!check_stage(configured, "pending_write_configuration")) return false;
    recovered.clear();
    released_head = {};
    witness = ReferenceVssRecoveryProofWitness{};
    released = release_reference_vss_selective_share_collective(
        exchange, local, target, receipt, transcript, pending_context,
        rank == target ? &pending_write_pins : nullptr,
        &recovered, &released_head, &witness);
    stage_ok = rank == target
        ? !released && recovered.empty() && released_head == Digest{} &&
              !witness.available
        : released && recovered.empty() && released_head == Digest{} &&
              !witness.available;
    if (rank == target) {
        ReferenceVssExternalAnchorSnapshot unchanged;
        stage_ok = stage_ok && client.ReadSnapshot(&unchanged) &&
            unchanged.generation == snapshot.generation &&
            unchanged.replay_head == snapshot.replay_head;
    }
    if (!check_stage(stage_ok, "pending_journal_without_cas")) return false;
    if (rank == target) {
        ReferenceVssSelectivePointDurableReplayGuard diagnostic_journal(
            journal_path, registry_binding);
        const std::vector<int> helpers{1, 2, 3};
        Digest diagnostic_pending_head{};
        const bool journal_pending =
            diagnostic_journal.VerifyPendingBatchWithPinnedHead(
                pending_context, helpers, target, snapshot.replay_head,
                &diagnostic_pending_head);
        const bool remote_attestation = journal_pending &&
            client.AttestTransition(snapshot, pending_context, target,
                                    helpers, diagnostic_pending_head);
        std::cerr << "PVIA_EXTERNAL_ANCHOR_PENDING_DIAGNOSTIC"
                  << " journal_pending=" << (journal_pending ? "PASS" : "FAIL")
                  << " remote_attestation="
                  << (remote_attestation ? "PASS" : "FAIL")
                  << " pending_head_nonzero="
                  << (diagnostic_pending_head != Digest{} ? "YES" : "NO")
                  << " generation=" << snapshot.generation << std::endl;
    }

    // Reconstruct both the service client and its transport-facing MPI
    // exchange, matching a process restart after the journal fsync.
    ReferenceVssExternalAnchorClient pending_restart_client;
    ReferenceVssExternalAnchorSnapshot pending_restart_snapshot;
    bool pending_restart_ok = true;
    if (rank == target) {
        pending_restart_ok = pending_restart_client.LoadFromEnvironment() &&
            pending_restart_client.ReadSnapshot(&pending_restart_snapshot) &&
            pending_restart_snapshot.generation == snapshot.generation &&
            pending_restart_snapshot.replay_head == snapshot.replay_head;
    }
    if (!check_stage(pending_restart_ok, "pending_client_restart")) return false;
    ReferenceVssSelectiveReleasePins pending_resume_pins;
    configured = configure(pending_restart_client, pending_restart_snapshot,
        ReferenceVssExternalAnchorResumeMode::kPending,
        &pending_resume_pins);
    if (!check_stage(configured, "pending_resume_configuration")) return false;
    // The failed first attempt already consumed this context in the
    // authenticated exchange. A process restart also recreates its transport
    // replay state, so model that boundary with a fresh exchange object.
    AuthenticatedMpcExchange pending_resume_exchange(rank, world_size);
    if (!check_stage(pending_resume_exchange.ready(),
                     "pending_resume_exchange_restart")) return false;
    recovered.clear();
    released_head = {};
    witness = ReferenceVssRecoveryProofWitness{};
    released = release_reference_vss_selective_share_collective(
        pending_resume_exchange, local, target, receipt, transcript,
        pending_context, rank == target ? &pending_resume_pins : nullptr,
        &recovered, &released_head, &witness);
    stage_ok = rank == target
        ? released && recovered == expected_share &&
              released_head != Digest{} && witness.available
        : released && recovered.empty() && released_head == Digest{} &&
              !witness.available;
    if (rank == target && !released)
        std::cerr << "PVIA_EXTERNAL_ANCHOR_PENDING_RELEASE_RETURNED_FALSE"
                  << std::endl;
    if (rank == target) {
        ReferenceVssExternalAnchorSnapshot after;
        stage_ok = stage_ok && pending_restart_client.ReadSnapshot(&after) &&
            after.generation == snapshot.generation + 1 &&
            after.replay_head == released_head;
        if (stage_ok) snapshot = after;
    }
    if (!check_stage(stage_ok, "pending_resume")) return false;

    // Committed-resume window: the service CAS succeeds, but the callback
    // intentionally drops its acknowledgement. The target must withhold
    // output until a fresh client reloads and verifies the committed batch.
    const auto committed_context = make_context(103);
    ReferenceVssSelectiveReleasePins lost_ack_pins;
    configured = configure(client, snapshot,
        ReferenceVssExternalAnchorResumeMode::kFresh, &lost_ack_pins);
    if (rank == target && configured) {
        const auto durable_cas = lost_ack_pins.persist_new_head;
        lost_ack_pins.persist_new_head =
            [durable_cas](const Digest& old_head, const Digest& next_head) {
                (void)durable_cas(old_head, next_head);
                return false;
            };
    }
    if (!check_stage(configured, "committed_write_configuration")) return false;
    recovered.clear();
    released_head = {};
    witness = ReferenceVssRecoveryProofWitness{};
    released = release_reference_vss_selective_share_collective(
        exchange, local, target, receipt, transcript, committed_context,
        rank == target ? &lost_ack_pins : nullptr,
        &recovered, &released_head, &witness);
    stage_ok = rank == target
        ? !released && recovered.empty() && released_head == Digest{} &&
              !witness.available
        : released && recovered.empty() && released_head == Digest{} &&
              !witness.available;
    ReferenceVssExternalAnchorClient restarted_client;
    ReferenceVssExternalAnchorSnapshot restarted_snapshot;
    if (rank == target) {
        stage_ok = stage_ok && restarted_client.LoadFromEnvironment() &&
            restarted_client.ReadSnapshot(&restarted_snapshot) &&
            restarted_snapshot.generation == snapshot.generation + 1 &&
            restarted_snapshot.replay_head != snapshot.replay_head;
    }
    if (!check_stage(stage_ok, "committed_cas_ack_lost")) return false;

    // Reconstruct the client object and use committed-resume mode. A changed
    // context must be rejected before any helper opening is released.
    ReferenceVssSelectiveReleasePins committed_resume_pins;
    configured = configure(restarted_client, restarted_snapshot,
        ReferenceVssExternalAnchorResumeMode::kCommitted,
        &committed_resume_pins);
    if (!check_stage(configured, "committed_resume_configuration")) return false;
    AuthenticatedMpcExchange committed_resume_exchange(rank, world_size);
    if (!check_stage(committed_resume_exchange.ready(),
                     "committed_resume_exchange_restart")) return false;
    auto wrong_context = committed_context;
    ++wrong_context.round;
    ++wrong_context.sequence;
    recovered.clear();
    released_head = {};
    witness = ReferenceVssRecoveryProofWitness{};
    released = release_reference_vss_selective_share_collective(
        committed_resume_exchange, local, target, receipt, transcript,
        wrong_context, rank == target ? &committed_resume_pins : nullptr,
        &recovered, &released_head, &witness);
    stage_ok = !released && recovered.empty() && released_head == Digest{} &&
        !witness.available;
    if (!check_stage(stage_ok, "wrong_context_preflight")) return false;

    // Use a fresh authenticated transport after the negative preflight, just
    // as a restarted participant would. The rejected context must not be
    // allowed to consume or poison the subsequent committed resume.
    AuthenticatedMpcExchange committed_delivery_exchange(rank, world_size);
    if (!check_stage(committed_delivery_exchange.ready(),
                     "committed_delivery_exchange_restart")) return false;
    recovered.clear();
    released_head = {};
    witness = ReferenceVssRecoveryProofWitness{};
    released = release_reference_vss_selective_share_collective(
        committed_delivery_exchange, local, target, receipt, transcript,
        committed_context,
        rank == target ? &committed_resume_pins : nullptr,
        &recovered, &released_head, &witness);
    stage_ok = rank == target
        ? released && recovered == expected_share &&
              released_head == restarted_snapshot.replay_head &&
              witness.available
        : released && recovered.empty() && released_head == Digest{} &&
              !witness.available;
    if (rank == target) {
        ReferenceVssExternalAnchorSnapshot unchanged;
        stage_ok = stage_ok && restarted_client.ReadSnapshot(&unchanged) &&
            unchanged.generation == restarted_snapshot.generation &&
            unchanged.replay_head == restarted_snapshot.replay_head;
    }
    if (!check_stage(stage_ok, "committed_resume_delivery")) return false;

    if (rank == target) {
        std::cout << "PVIA_VSS_EXTERNAL_ANCHOR_COORDINATOR_N4: PASS"
                  << " fresh_release=PASS"
                  << " pending_client_restart=PASS"
                  << " pending_resume=PASS"
                  << " committed_resume=PASS"
                  << " cas_before_delivery=PASS"
                  << " lost_ack_output_withheld=PASS"
                  << " wrong_context_preflight=REJECTED"
                  << " final_generation=" << restarted_snapshot.generation
                  << std::endl;
    }
    return true;
}
bool run_reference_vss_selective_point_selftest(
    int rank,int world_size) {
    if(world_size<4 || rank<0 || rank>=world_size)return false;
    // Test-only ephemeral keys unless the caller supplies a pre-provisioned
    // per-rank key file and externally anchored registry. The MPI transport
    // still verifies the Ed25519 signature of EVERY sender slot.
    auto& authentication=Ed25519TransferAuthenticator::instance();
    if(!authentication.Initialize(rank,world_size)) return false;
    AuthenticatedMpcExchange exchange(rank,world_size);
    if(!exchange.ready())return false;
    const int threshold=(world_size-1)/3;
    ReferenceBivariateVss vss(rank,world_size,threshold);
    if(!vss.valid())return false;
    const size_t elements=12;
    std::vector<F> plaintext;
    if(rank==0) {
        for(size_t k=0;k<elements;++k)
            plaintext.emplace_back(
                static_cast<long long>(k+31),
                static_cast<long long>(2*k+41));
    }
    std::vector<F> original_share;
    ReferenceVssReceipt receipt;
    ReferenceVssLocalWitness local;
    const bool shared=vss.ShareVectorFromDealerWithLocalWitness(
        0,plaintext,&original_share,&receipt,&local);
    int local_good=shared && receipt.available && receipt.consistent &&
        validate_reference_vss_local_witness(local) &&
        original_share.size()==elements &&
        receipt.element_count==elements ? 1:0;
    int all_good=0;
    MPI_Allreduce(&local_good,&all_good,1,
                  MPI_INT,MPI_MIN,MPI_COMM_WORLD);
    if(!all_good)return false;
    const char* injection=std::getenv(
        "PVIA_VSS_SELECTIVE_INJECT_WRONG_POINT");
    const bool injected=injection && *injection && *injection!='0';

    // Commit all target evaluations before any selective release.  Each
    // target checks its column against the cross-evaluations of the private
    // symmetric VSS row, and authenticated ACKs finalize one shared matrix.
    AuthenticatedMpcMessageContext setup_context;
    setup_context.protocol_domain = PVIA_VSS_SELECTIVE_POINT_DOMAIN;
    setup_context.sid = 0x5031303356535331ULL;
    setup_context.checkpoint = 0x505431030001ULL;
    setup_context.round = 1;
    setup_context.sequence = 1;
    setup_context.message_kind = PVIA_VSS_POINT_SETUP_KIND;
    ReferenceVssSelectivePointCommitmentRegistry registry;
    if (!establish_reference_vss_point_commitment_registry(
            local, receipt, exchange, setup_context, &registry)) return false;

    // Test-only issuer key fixture. The bridge below verifies REAL Ed25519
    // signatures on the existing paired native source and FINAL statement.
    // A production caller must independently pin its issuer public key,
    // source-record digest and issuer sequence policy.
    RegistrationConsistencyStatement statement;
    statement.sid = setup_context.sid;
    statement.checkpoint = setup_context.checkpoint;
    statement.ref.owner = 0;
    statement.ref.object_id = 9;
    statement.kernel = AuditRelationKernel::FOLD_RS;
    statement.state_element_count = elements;
    statement.output_element_count = elements;
    statement.public_state_digest = hash_words({0x7011, setup_context.sid});
    statement.public_actual_digest = hash_words({0x7012, setup_context.sid});
    statement.public_challenge_binding = hash_words({0x7013, setup_context.sid});
    statement.native_context.native_state_id = 33;
    statement.native_context.authentication_scheme_id = 1;
    statement.native_context.authentication_binding = hash_words({0x7020});
    statement.native_context.predecessor_root = hash_words({0x7021});
    statement.native_context.checkpoint_root = hash_words({0x7022});
    statement.operation_statement_binding = hash_words({0x7023});
    statement.sharing_transcript_binding = receipt.transcript_binding;
    statement.statement_binding =
        compute_registration_consistency_statement_binding(statement);
    if (!validate_registration_consistency_statement(statement)) return false;

    std::array<uint8_t, 32> private_seed{};
    private_seed[0] = 0x29; // TEST ONLY: never use this seed in production
    private_seed[31] = 0x34;
    EVP_PKEY* key = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, private_seed.data(), private_seed.size());
    if (!key) return false;
    struct KeyCleanup {
        EVP_PKEY* key;
        ~KeyCleanup() { EVP_PKEY_free(key); }
    } key_cleanup{key};
    std::array<uint8_t,32> issuer_public_key{};
    size_t pub_len=issuer_public_key.size();
    if (EVP_PKEY_get_raw_public_key(
            key,issuer_public_key.data(),&pub_len)!=1 ||
        pub_len!=issuer_public_key.size()) return false;
    auto sign=[&](const std::vector<uint8_t>& message,
                  std::array<uint8_t,64>* signature) {
        if(message.empty()) return false;
        EVP_MD_CTX* ctx=EVP_MD_CTX_new();
        size_t signature_len=signature->size();
        const bool ok=ctx &&
            EVP_DigestSignInit(ctx,nullptr,nullptr,nullptr,key)==1 &&
            EVP_DigestSign(ctx,signature->data(),&signature_len,
                           message.data(),message.size())==1 &&
            signature_len==signature->size();
        EVP_MD_CTX_free(ctx);
        return ok;
    };
    constexpr u64 issuer_id=13;
    constexpr u64 issuer_sequence=19;
    RegistrationNativeIssuerReleaseEvidence issuer_evidence;
    issuer_evidence.source_receipt.issuer_id=issuer_id;
    issuer_evidence.source_receipt.sequence=issuer_sequence;
    issuer_evidence.source_receipt.pre_vss_claim_binding =
        hash_words(registration_pre_vss_claim_words(statement));
    const Digest expected_consumed = hash_words({
        0x5056534e41543131ULL, setup_context.sid,
        setup_context.checkpoint, static_cast<u64>(elements)});
    issuer_evidence.source_receipt.consumed_record_binding=expected_consumed;
    if (!sign(registration_native_execution_receipt_message(
            statement,issuer_id,issuer_sequence,
            issuer_evidence.source_receipt.pre_vss_claim_binding,
            expected_consumed), &issuer_evidence.source_receipt.signature))
        return false;
    issuer_evidence.final_statement_binding=statement.statement_binding;
    if (!sign(registration_native_issuer_release_message(
            statement,issuer_evidence.source_receipt),
            &issuer_evidence.final_signature)) return false;
    char store_name[] = "/tmp/pvia-point-registry-XXXXXX";
    const int store_fd = ::mkstemp(store_name);
    if (store_fd < 0) return false;
    ::close(store_fd);
    ::unlink(store_name);
    struct RegistryFileCleanup {
        std::string path;
        ~RegistryFileCleanup() { ::unlink(path.c_str()); }
    } cleanup{store_name};

    Digest native_execution_binding{};
    Digest externally_pinned_record{};
    if (!save_reference_vss_registry_from_verified_native_issuer(
            cleanup.path, registry, statement, issuer_evidence,
            expected_consumed, issuer_public_key, issuer_id,
            issuer_sequence, &native_execution_binding,
            &externally_pinned_record)) return false;
    auto bad_evidence = issuer_evidence;
    bad_evidence.final_signature[0] ^= 1;
    Digest refused{};
    if (derive_verified_reference_vss_native_execution_binding(
            registry,statement,bad_evidence,expected_consumed,
            issuer_public_key,issuer_id,issuer_sequence,&refused))
        return false;
    if (derive_verified_reference_vss_native_execution_binding(
            registry,statement,issuer_evidence,hash_words({0x888}),
            issuer_public_key,issuer_id,issuer_sequence,&refused))
        return false;
    if (derive_verified_reference_vss_native_execution_binding(
            registry,statement,issuer_evidence,expected_consumed,
            issuer_public_key,issuer_id,issuer_sequence+1,&refused))
        return false;
    auto changed_statement=statement;
    changed_statement.sid++;
    changed_statement.statement_binding=
        compute_registration_consistency_statement_binding(changed_statement);
    if (derive_verified_reference_vss_native_execution_binding(
            registry,changed_statement,issuer_evidence,expected_consumed,
            issuer_public_key,issuer_id,issuer_sequence,&refused))
        return false;
    if (native_execution_binding==Digest{} ||
        externally_pinned_record==Digest{}) return false;
    if (externally_pinned_record !=
        compute_reference_vss_point_registry_execution_binding(
            registry, native_execution_binding)) return false;
    ReferenceVssPointRegistryExecutionRecord resumed;
    if (!load_reference_vss_point_registry_execution_record(
            cleanup.path, externally_pinned_record,
            native_execution_binding, setup_context.sid,
            setup_context.checkpoint, receipt.transcript_binding,
            &resumed)) return false;
    if (resumed.registry.registry_binding != registry.registry_binding ||
        resumed.registry.signed_ack_transport !=
            registry.signed_ack_transport) return false;
    {
        auto wrong_record = externally_pinned_record;
        wrong_record.bytes[0] ^= 1;
        auto wrong_execution = native_execution_binding;
        wrong_execution.bytes[0] ^= 1;
        ReferenceVssPointRegistryExecutionRecord rejected;
        if (load_reference_vss_point_registry_execution_record(
                cleanup.path, wrong_record, native_execution_binding,
                setup_context.sid, setup_context.checkpoint,
                receipt.transcript_binding, &rejected) ||
            load_reference_vss_point_registry_execution_record(
                cleanup.path, externally_pinned_record, wrong_execution,
                setup_context.sid, setup_context.checkpoint,
                receipt.transcript_binding, &rejected) ||
            load_reference_vss_point_registry_execution_record(
                cleanup.path, externally_pinned_record,
                native_execution_binding, setup_context.sid + 1,
                setup_context.checkpoint, receipt.transcript_binding,
                &rejected) ||
            load_reference_vss_point_registry_execution_record(
                cleanup.path, externally_pinned_record,
                native_execution_binding, setup_context.sid,
                setup_context.checkpoint + 1, receipt.transcript_binding,
                &rejected)) return false;
        auto wrong_transcript = receipt.transcript_binding;
        wrong_transcript.bytes[0] ^= 1;
        if (load_reference_vss_point_registry_execution_record(
                cleanup.path, externally_pinned_record,
                native_execution_binding, setup_context.sid,
                setup_context.checkpoint, wrong_transcript, &rejected))
            return false;
    }

    char journal_name[] = "/tmp/pvia-point-replay-XXXXXX";
    const int journal_fd = ::mkstemp(journal_name);
    if (journal_fd < 0) return false;
    ::close(journal_fd);
    ::unlink(journal_name);
    RegistryFileCleanup journal_cleanup{journal_name};
    ReferenceVssSelectivePointDurableReplayGuard durable_guard(
        journal_cleanup.path, registry.registry_binding);
    if(!durable_guard.InitializeNew() || durable_guard.InitializeNew())
        return false;
    Digest externally_pinned_head{};
    if(!durable_guard.ReadCurrentHead(&externally_pinned_head) ||
       externally_pinned_head==Digest{}) return false;

    // The separate P1-05 coordinator uses a distinct receiver-local journal,
    // while retaining the same authenticated setup registry and pins.
    char coordinated_name[] = "/tmp/pvia-point-coordinated-XXXXXX";
    const int coordinated_fd=::mkstemp(coordinated_name);
    if(coordinated_fd<0)return false;
    ::close(coordinated_fd);
    ::unlink(coordinated_name);
    RegistryFileCleanup coordinated_cleanup{coordinated_name};
    ReferenceVssSelectivePointDurableReplayGuard coordinated_log(
        coordinated_cleanup.path,registry.registry_binding);
    if(!coordinated_log.InitializeNew())return false;
    Digest coordinated_pinned_head{};
    if(!coordinated_log.ReadCurrentHead(&coordinated_pinned_head) ||
       coordinated_pinned_head==Digest{})return false;
    char coordinated_anchor_name[] =
        "/tmp/pvia-point-coordinated-anchor-XXXXXX";
    const int coordinated_anchor_fd = ::mkstemp(coordinated_anchor_name);
    if (coordinated_anchor_fd < 0) return false;
    ::close(coordinated_anchor_fd);
    ::unlink(coordinated_anchor_name);
    RegistryFileCleanup coordinated_anchor_cleanup{coordinated_anchor_name};
    ReferenceVssSelectivePointReplayHeadAnchor coordinated_anchor(
        coordinated_anchor_cleanup.path, registry.registry_binding);
    if (!coordinated_anchor.InitializeNew(coordinated_pinned_head)) return false;

    // Only the target's mailbox gets nonzero point values. AllToAllWords
    // authenticates each sender->receiver envelope against the rank key;
    // unused destinations receive an authenticated zero-payload slot.
    const int targets[]={0,world_size/2,world_size-1};
    int local_success=1;
    bool observed_bad_opening = false;
    ReferenceVssSelectivePointReplayGuard replay_guard;
    for(const int target:targets) {
        AuthenticatedMpcMessageContext context;
        context.protocol_domain=PVIA_VSS_SELECTIVE_POINT_DOMAIN;
        context.sid=0x5031303356535331ULL; // session supplied independently
        context.checkpoint=0x505431030001ULL;
        context.round=static_cast<u64>(2*target+1);
        context.sequence=static_cast<u64>(2*target+1);
        context.message_kind=PVIA_VSS_SELECTIVE_POINT_KIND;
        ReferenceVssSelectivePoint opening;
        const bool helper=(rank!=target);
        const bool made=!helper ||
            make_reference_vss_selective_point(local,target,&opening);
        std::vector<u64> encoded;
        const bool packed=!helper ||
            encode_reference_vss_selective_point_envelope(
                opening,receipt,context,&encoded);
        const size_t packet_words=26+elements*2;
        std::vector<u64> sender(static_cast<size_t>(world_size)*packet_words,0);
        if(helper && made && packed && encoded.size()==packet_words) {
            // The negative test changes a source value BEFORE signing the
            // envelope. It exercises point consistency, not signature forgery.
            if(injected && rank==1 && target==0) {
                opening.values[0]+=F(1);
                encoded.clear();
                if(!encode_reference_vss_selective_point_envelope(
                       opening,receipt,context,&encoded)) return false;
            }
            std::copy(encoded.begin(),encoded.end(),
                      sender.begin()+static_cast<size_t>(target)*packet_words);
        }
        const int source_good=(made && packed &&
                               (!helper || encoded.size()==packet_words))?1:0;
        int sources_good=0;
        MPI_Allreduce(&source_good,&sources_good,1,
                      MPI_INT,MPI_MIN,MPI_COMM_WORLD);
        if(!sources_good)return false;
        std::vector<u64> inbound;
        Digest transport_binding{};
        if(!exchange.AllToAllWords(context,sender,packet_words,
                                   &inbound,&transport_binding) ||
           transport_binding==Digest{})return false;
        if(rank==target) {
            std::vector<ReferenceVssSelectivePoint> packets;
            std::vector<std::vector<u64>> original_packets;
            for(int participant=0;participant<world_size;++participant) {
                if(participant==target)continue;
                const size_t offset=static_cast<size_t>(participant)*packet_words;
                std::vector<u64> wire(
                    inbound.begin()+static_cast<std::ptrdiff_t>(offset),
                    inbound.begin()+static_cast<std::ptrdiff_t>(offset+packet_words));
                ReferenceVssSelectivePoint packet;
                if(!decode_reference_vss_selective_point_envelope(
                       wire,participant,target,receipt,
                       local.transcript_context,context,&packet) ||
                   !replay_guard.Observe(context,participant,target))
                    return false;
                const bool committed = verify_reference_vss_point_commitment(
                    registry, packet, receipt, context);
                if (!committed) {
                    // A sender can sign an internally well-formed but
                    // incorrect point.  Reject it even when exactly t+1
                    // helpers would otherwise interpolate it.
                    observed_bad_opening = true;
                    if (!(injected && target == 0 && participant == 1))
                        local_success = 0;
                }
                if (committed) {
                    // Pin the previous head outside the log (selftest local
                    // variable); a real executor must update its trusted
                    // high-water journal after every successful fsync.
                    Digest observed_head{};
                    if (!durable_guard.ObserveWithPinnedHead(
                            context,participant,target,externally_pinned_head,
                            &observed_head))
                        local_success=0;
                    else externally_pinned_head=observed_head;
                    ReferenceVssSelectivePointDurableReplayGuard restarted(
                        journal_cleanup.path,registry.registry_binding);
                    Digest refused_head{};
                    if (restarted.ObserveWithPinnedHead(
                            context,participant,target,externally_pinned_head,
                            &refused_head))
                        local_success=0;
                    auto stale_pin=externally_pinned_head;
                    stale_pin.bytes[0]^=1;
                    auto next=context;
                    next.sequence+=1;
                    if (restarted.ObserveWithPinnedHead(
                            next,participant,target,stale_pin,&refused_head))
                        local_success=0;
                    Digest next_head{};
                    if (!restarted.ObserveWithPinnedHead(
                            next,participant,target,externally_pinned_head,
                            &next_head))
                        local_success=0;
                    else externally_pinned_head=next_head;
                    ReferenceVssSelectivePointDurableReplayGuard again(
                        journal_cleanup.path,registry.registry_binding);
                    if (again.ObserveWithPinnedHead(
                            context,participant,target,externally_pinned_head,
                            &refused_head))
                        local_success=0;
                    Digest verified_head{};
                    if(!again.ReadCurrentHead(&verified_head) ||
                       verified_head!=externally_pinned_head)
                        local_success=0;
                }
                original_packets.push_back(std::move(wire));
                packets.push_back(std::move(packet));
            }
            // Exact replay, signed sender/recipient/context confusion, stale
            // session and payload tampering are independently rejected.
            if(!packets.empty()) {
                ReferenceVssSelectivePoint ignored;
                const auto& wire=original_packets.front();
                const int verified_sender=packets.front().helper;
                auto try_decode=[&](const std::vector<u64>& candidate,
                                   const AuthenticatedMpcMessageContext& ctx) {
                    return decode_reference_vss_selective_point_envelope(
                        candidate,verified_sender,target,receipt,
                        local.transcript_context,ctx,&ignored);
                };
                local_success=local_success &&
                    !replay_guard.Observe(context,verified_sender,target);
                auto stale=context;
                stale.sequence+=1;
                local_success=local_success && !try_decode(wire,stale);
                stale=context;
                stale.sid+=1;
                local_success=local_success && !try_decode(wire,stale);
                stale=context;
                stale.checkpoint+=1;
                local_success=local_success && !try_decode(wire,stale);
                auto bad_wire=wire;
                bad_wire[2]=static_cast<u64>(target);
                local_success=local_success && !try_decode(bad_wire,context);
                bad_wire=wire;
                bad_wire[3]=static_cast<u64>((target+1)%world_size);
                local_success=local_success && !try_decode(bad_wire,context);
                bad_wire=wire;
                bad_wire[9]^=1;
                local_success=local_success && !try_decode(bad_wire,context);
                bad_wire=wire;
                bad_wire[13]^=1;
                local_success=local_success && !try_decode(bad_wire,context);
                bad_wire=wire;
                bad_wire.back()^=1;
                local_success=local_success && !try_decode(bad_wire,context);
                bad_wire=wire;
                bad_wire[1]+=1;
                local_success=local_success && !try_decode(bad_wire,context);
                // A different authenticated sender cannot claim a peer's
                // signed slot, even with a structurally valid nested packet.
                local_success=local_success &&
                    !decode_reference_vss_selective_point_envelope(
                        wire,target,target,receipt,local.transcript_context,
                        context,&ignored);
            }

            auto recover=[&](const std::vector<ReferenceVssSelectivePoint>& points,
                             const ReferenceVssReceipt& source,
                             std::vector<F>* result) {
                return recover_reference_vss_share_from_points(
                    target,source,local.transcript_context,points,result);
            };
            std::vector<F> restored;
            const bool accepted = recover_reference_vss_share_from_persisted_points(
                cleanup.path, externally_pinned_record,
                native_execution_binding, target, receipt,
                local.transcript_context, context, packets, &restored);
            if(injected && target==0) {
                local_success=local_success && observed_bad_opening && !accepted;
            } else {
                local_success=local_success && accepted &&
                    restored==original_share;
                if(accepted) {
                    const size_t need=static_cast<size_t>(threshold+1);
                    std::vector<ReferenceVssSelectivePoint> minimal(
                        packets.begin(),packets.begin()+need);
                    std::vector<F> minimum;
                    // Exactly t+1 arbitrarily modified points interpolate,
                    // but do NOT pass the pre-established point commitments.
                    auto changed_minimal = minimal;
                    changed_minimal[0].values[0] += F(1);
                    local_success = local_success &&
                        recover(changed_minimal, receipt, &minimum) &&
                        !recover_reference_vss_share_from_committed_points(
                            target, receipt, local.transcript_context,
                            registry, context, changed_minimal, &minimum) &&
                        !verify_reference_vss_point_commitment(
                            registry, changed_minimal[0], receipt, context);
                    auto bad_registry = registry;
                    bad_registry.commitments[0].bytes[0] ^= 1;
                    local_success = local_success &&
                        !verify_reference_vss_point_commitment(
                            bad_registry, minimal[0], receipt, context);
                    auto other_session = context;
                    other_session.sid++;
                    local_success = local_success &&
                        !verify_reference_vss_point_commitment(
                            registry, minimal[0], receipt, other_session);
                    local_success=local_success &&
                        recover_reference_vss_share_from_persisted_points(
                            cleanup.path, externally_pinned_record,
                            native_execution_binding, target, receipt,
                            local.transcript_context, context, minimal,
                            &minimum) &&
                        minimum==original_share;
                    auto bad=packets;
                    bad[0].values[0]+=F(1);
                    local_success=local_success &&
                        !recover(bad,receipt,&minimum);
                    bad=packets;
                    bad[1]=bad[0];
                    local_success=local_success &&
                        !recover(bad,receipt,&minimum);
                    bad=packets;
                    bad[0].target=(target+1)%world_size;
                    local_success=local_success &&
                        !recover(bad,receipt,&minimum);
                    bad=packets;
                    bad[0].helper_row_commitment.bytes[0]^=1;
                    local_success=local_success &&
                        !recover(bad,receipt,&minimum);
                    bad=packets;
                    bad[0].transcript_binding.bytes[0]^=1;
                    local_success=local_success &&
                        !recover(bad,receipt,&minimum);
                    bad=packets;
                    bad[0].values.pop_back();
                    local_success=local_success &&
                        !recover(bad,receipt,&minimum);
                    bad=packets;
                    bad.resize(need-1);
                    local_success=local_success &&
                        !recover(bad,receipt,&minimum);
                    auto bad_receipt=receipt;
                    bad_receipt.transcript_binding.bytes[0]^=1;
                    local_success=local_success &&
                        !recover(packets,bad_receipt,&minimum);
                }
            }
        }
        int globally_ok=0;
        MPI_Allreduce(&local_success,&globally_ok,1,
                      MPI_INT,MPI_MIN,MPI_COMM_WORLD);
        if(!globally_ok)return false;

        // Exercise the integrated release path on the same real signed MPI
        // context, but with a NEW sequence/round to avoid frame replay.
        auto coordinated_context=context;
        coordinated_context.round+=1;
        coordinated_context.sequence+=1;
        const char* external_anchor_mode =
            std::getenv("PVIA_EXTERNAL_ANCHOR_INTEGRATED");
        if (target == 0 && external_anchor_mode &&
            std::string(external_anchor_mode) == "1") {
            if (!run_reference_vss_external_anchor_coordinator_integration(
                    exchange, local, rank, world_size, target, receipt,
                    local.transcript_context, coordinated_context,
                    cleanup.path, externally_pinned_record,
                    native_execution_binding, registry.registry_binding,
                    original_share))
                return false;
        }
        ReferenceVssSelectiveReleasePins pins;
        if(rank==target) {
            pins.registry_path=cleanup.path;
            pins.replay_journal_path=coordinated_cleanup.path;
            pins.independently_pinned_record=externally_pinned_record;
            pins.independently_pinned_registry_binding=registry.registry_binding;
            pins.independently_pinned_native_execution=native_execution_binding;
            pins.independently_pinned_replay_head=coordinated_pinned_head;
            pins.load_current_head = [&coordinated_anchor](Digest* head) {
                return coordinated_anchor.ReadCurrentHead(head);
            };
            pins.verify_independent_pins = [
                &coordinated_anchor, &externally_pinned_record,
                &native_execution_binding, &registry](
                    const Digest& record, const Digest& native_execution,
                    const Digest& registry_binding, const Digest& replay_head) {
                    Digest stored_head{};
                    return record == externally_pinned_record &&
                        native_execution == native_execution_binding &&
                        registry_binding == registry.registry_binding &&
                        coordinated_anchor.ReadCurrentHead(&stored_head) &&
                        stored_head == replay_head;
                };
            pins.persist_new_head=[&coordinated_anchor,&coordinated_pinned_head](
                const Digest& expected,const Digest& next) {
                if(next==Digest{} ||
                   !coordinated_anchor.CompareAndSwap(expected,next))
                    return false;
                coordinated_pinned_head=next;
                return true;
            };
            // The injected test already covers a signed bad point in the
            // raw path. Here a separately corrupted external record pin
            // proves the integrated coordinator rejects before journaling.
            if(injected && target==0)
                pins.independently_pinned_record.bytes[0]^=1;
        }
        std::vector<F> coordinated_recovered;
        Digest coordinated_head{};
        ReferenceVssRecoveryProofWitness coordinated_proof_witness;
        const bool coordinator_ok=
            release_reference_vss_selective_share_collective(
                exchange,local,target,receipt,local.transcript_context,
                coordinated_context,rank==target?&pins:nullptr,
                &coordinated_recovered,&coordinated_head,
                &coordinated_proof_witness);
        int integrated_good=1;
        if(rank==target) {
            Digest actual_head{};
            if(!coordinated_log.ReadCurrentHead(&actual_head))
                integrated_good=0;
            if(injected && target==0) {
                integrated_good=integrated_good &&
                    !coordinator_ok && coordinated_recovered.empty() &&
                    coordinated_head==Digest{} &&
                    !coordinated_proof_witness.available &&
                    actual_head==coordinated_pinned_head;
            } else {
                integrated_good=integrated_good && coordinator_ok &&
                    coordinated_recovered==original_share &&
                    coordinated_head==coordinated_pinned_head &&
                    coordinated_proof_witness.available &&
                    coordinated_proof_witness.target==target &&
                    coordinated_proof_witness.world_size==world_size &&
                    coordinated_proof_witness.threshold==receipt.threshold &&
                    coordinated_proof_witness.element_count==receipt.element_count &&
                    coordinated_proof_witness.vss_transcript==receipt.transcript_binding &&
                    coordinated_proof_witness.registry_binding==registry.registry_binding &&
                    coordinated_proof_witness.commitments.size()==
                        static_cast<size_t>(world_size*world_size) &&
                    coordinated_proof_witness.openings.size()==
                        static_cast<size_t>(world_size-1) &&
                    actual_head==coordinated_pinned_head;
                // All senders were committed as a single replay batch.
                // Reapplying the same batch, even after reconstruction of
                // the guard object, must fail and leave the tip unchanged.
                std::vector<int> helper_set;
                for(int h=0;h<world_size;++h)
                    if(h!=target)helper_set.push_back(h);
                ReferenceVssSelectivePointDurableReplayGuard restarted(
                    coordinated_cleanup.path,registry.registry_binding);
                Digest refused_head{};
                integrated_good=integrated_good &&
                    !restarted.ObserveBatchWithPinnedHead(
                        coordinated_context,helper_set,target,
                        coordinated_pinned_head,&refused_head) &&
                    refused_head==Digest{};
                helper_set.push_back(helper_set.front());
                integrated_good=integrated_good &&
                    !restarted.ObserveBatchWithPinnedHead(
                        coordinated_context,helper_set,target,
                        coordinated_pinned_head,&refused_head);
            }
        } else {
            integrated_good=coordinator_ok &&
                coordinated_recovered.empty() &&
                coordinated_head==Digest{} &&
                !coordinated_proof_witness.available;
        }
        int integrated_all=0;
        MPI_Allreduce(&integrated_good,&integrated_all,1,
                      MPI_INT,MPI_MIN,MPI_COMM_WORLD);
        if(!integrated_all)return false;
    }
    // The independent trusted-head update can fail AFTER the journal batch
    // is fsynced. The coordinator must not publish a recovered share then.
    // A retry may resume only the exact same release-context suffix; a
    // changed context must remain rejected.
    {
        AuthenticatedMpcMessageContext fail_context=setup_context;
        fail_context.round=static_cast<u64>(2*world_size+1);
        fail_context.sequence=static_cast<u64>(2*world_size+1);
        fail_context.message_kind=PVIA_VSS_SELECTIVE_POINT_KIND;
        ReferenceVssSelectiveReleasePins pins;
        if(rank==0) {
            pins.registry_path=cleanup.path;
            pins.replay_journal_path=coordinated_cleanup.path;
            pins.independently_pinned_record=externally_pinned_record;
            pins.independently_pinned_registry_binding=registry.registry_binding;
            pins.independently_pinned_native_execution=native_execution_binding;
            pins.independently_pinned_replay_head=coordinated_pinned_head;
            pins.load_current_head = [&coordinated_anchor](Digest* head) {
                return coordinated_anchor.ReadCurrentHead(head);
            };
            pins.verify_independent_pins = [
                &coordinated_anchor, &externally_pinned_record,
                &native_execution_binding, &registry](
                    const Digest& record, const Digest& native_execution,
                    const Digest& registry_binding, const Digest& replay_head) {
                    Digest stored_head{};
                    return record == externally_pinned_record &&
                        native_execution == native_execution_binding &&
                        registry_binding == registry.registry_binding &&
                        coordinated_anchor.ReadCurrentHead(&stored_head) &&
                        stored_head == replay_head;
                };
            pins.persist_new_head=[&coordinated_anchor,&coordinated_pinned_head](
                const Digest& expected,const Digest& next) {
                if (expected != coordinated_pinned_head || next == Digest{} ||
                    !coordinated_anchor.CompareAndSwap(expected,next))
                    return false;
                coordinated_pinned_head = next;
                // Model a process/connection failure after the durable anchor
                // CAS committed but before its success response reached caller.
                return false;
            };
        }
        std::vector<F> unavailable;
        Digest unavailable_head{};
        const Digest anchor_before_lost_ack =
            rank==0 ? coordinated_pinned_head : Digest{};
        const bool accepted=release_reference_vss_selective_share_collective(
            exchange,local,0,receipt,local.transcript_context,
            fail_context,rank==0?&pins:nullptr,
            &unavailable,&unavailable_head);
        // Reconstruct the file-backed anchor object to model a fresh process.
        ReferenceVssSelectivePointReplayHeadAnchor restarted_anchor(
            coordinated_anchor_cleanup.path, registry.registry_binding);
        int local_integrated=1;
        if(rank==0) {
            Digest moved_tip{}, reloaded_head{};
            if(!coordinated_log.ReadCurrentHead(&moved_tip) ||
               moved_tip==anchor_before_lost_ack ||
               coordinated_pinned_head!=moved_tip ||
               !restarted_anchor.ReadCurrentHead(&reloaded_head) ||
               reloaded_head!=moved_tip ||
               accepted || !unavailable.empty() ||
               unavailable_head!=Digest{})local_integrated=0;
            std::vector<int> helpers;
            for(int h=1;h<world_size;++h)helpers.push_back(h);
            ReferenceVssSelectivePointDurableReplayGuard restarted(
                coordinated_cleanup.path,registry.registry_binding);
            Digest resumed_head{};
            if(!restarted.ObserveBatchWithPinnedHead(
                    fail_context,helpers,0,anchor_before_lost_ack,
                    &resumed_head) || resumed_head!=moved_tip)
                local_integrated=0;
            if(!restarted.VerifyCommittedBatchWithPinnedHead(
                    fail_context,helpers,0,moved_tip))
                local_integrated=0;
            auto next_context=fail_context;
            ++next_context.round;
            ++next_context.sequence;
            if(restarted.VerifyCommittedBatchWithPinnedHead(
                    next_context,helpers,0,moved_tip))
                local_integrated=0;
            std::vector<int> wrong_helpers=helpers;
            if(!wrong_helpers.empty()) wrong_helpers.pop_back();
            if(restarted.VerifyCommittedBatchWithPinnedHead(
                    fail_context,wrong_helpers,0,moved_tip))
                local_integrated=0;
        } else {
            if(!accepted || !unavailable.empty() ||
               unavailable_head!=Digest{})local_integrated=0;
        }
        int globally_integrated=0;
        MPI_Allreduce(&local_integrated,&globally_integrated,1,
                      MPI_INT,MPI_MIN,MPI_COMM_WORLD);
        if(!globally_integrated)return false;
        // A fresh exchange and a newly opened file-backed anchor model restart.
        AuthenticatedMpcExchange restarted_exchange(rank,world_size);
        if(!restarted_exchange.ready())return false;
        int retry_cas_calls=0;
        if(rank==0) {
            pins.independently_pinned_replay_head=coordinated_pinned_head;
            pins.load_current_head = [&restarted_anchor](Digest* head) {
                return restarted_anchor.ReadCurrentHead(head);
            };
            pins.verify_independent_pins = [
                &restarted_anchor, &externally_pinned_record,
                &native_execution_binding, &registry](
                    const Digest& record, const Digest& native_execution,
                    const Digest& registry_binding, const Digest& replay_head) {
                    Digest stored_head{};
                    return record == externally_pinned_record &&
                        native_execution == native_execution_binding &&
                        registry_binding == registry.registry_binding &&
                        restarted_anchor.ReadCurrentHead(&stored_head) &&
                        stored_head == replay_head;
                };
            std::vector<int> expected_helpers;
            for(int h=1;h<world_size;++h)expected_helpers.push_back(h);
            const Digest expected_head=coordinated_pinned_head;
            pins.authorize_committed_resume = [
                &restarted_anchor, fail_context, expected_helpers, expected_head](
                    const AuthenticatedMpcMessageContext& candidate_context,
                    int candidate_target, const std::vector<int>& candidate_senders,
                    const Digest& candidate_head) {
                    Digest live_head{};
                    return candidate_context.protocol_domain==fail_context.protocol_domain &&
                        candidate_context.sid==fail_context.sid &&
                        candidate_context.checkpoint==fail_context.checkpoint &&
                        candidate_context.round==fail_context.round &&
                        candidate_context.sequence==fail_context.sequence &&
                        candidate_context.message_kind==fail_context.message_kind &&
                        candidate_target==0 &&
                        candidate_senders==expected_helpers &&
                        candidate_head==expected_head &&
                        restarted_anchor.ReadCurrentHead(&live_head) &&
                        live_head==candidate_head;
                };
            pins.persist_new_head=[&retry_cas_calls](
                const Digest&,const Digest&) {
                ++retry_cas_calls;
                return false;
            };
        }

        // A changed context must be rejected in preflight, before helpers
        // release any opening under a different request identity.
        auto wrong_resume_context=fail_context;
        ++wrong_resume_context.round;
        ++wrong_resume_context.sequence;
        std::vector<F> wrong_resume_output;
        Digest wrong_resume_head{};
        ReferenceVssRecoveryProofWitness wrong_resume_witness;
        const bool wrong_resumed=release_reference_vss_selective_share_collective(
            restarted_exchange,local,0,receipt,local.transcript_context,
            wrong_resume_context,rank==0?&pins:nullptr,
            &wrong_resume_output,&wrong_resume_head,&wrong_resume_witness);
        int wrong_retry_local =
            !wrong_resumed && wrong_resume_output.empty() &&
            wrong_resume_head==Digest{} && !wrong_resume_witness.available;
        if(rank==0) {
            Digest unchanged_head{};
            wrong_retry_local = wrong_retry_local &&
                restarted_anchor.ReadCurrentHead(&unchanged_head) &&
                unchanged_head==coordinated_pinned_head &&
                retry_cas_calls==0;
        }
        int wrong_retry_global=0;
        MPI_Allreduce(&wrong_retry_local,&wrong_retry_global,1,
                      MPI_INT,MPI_MIN,MPI_COMM_WORLD);
        if(!wrong_retry_global)return false;

        std::vector<F> resumed_output;
        Digest resumed_output_head{};
        const bool resumed=release_reference_vss_selective_share_collective(
            restarted_exchange,local,0,receipt,local.transcript_context,
            fail_context,rank==0?&pins:nullptr,
            &resumed_output,&resumed_output_head);
        int retry_local=1;
        if(rank==0) {
            Digest reloaded_head{};
            if(!restarted_anchor.ReadCurrentHead(&reloaded_head) ||
               reloaded_head!=coordinated_pinned_head ||
               !resumed || resumed_output!=original_share ||
               resumed_output_head!=coordinated_pinned_head ||
               retry_cas_calls!=0)
                retry_local=0;
        } else if(!resumed || !resumed_output.empty() ||
                  resumed_output_head!=Digest{}) {
            retry_local=0;
        }
        int retry_global=0;
        MPI_Allreduce(&retry_local,&retry_global,1,
                      MPI_INT,MPI_MIN,MPI_COMM_WORLD);
        if(!retry_global)return false;
        if(rank==0)
            std::cout << "PVIA_VSS_POST_CAS_COORDINATOR_RESUME: PASS"
                      << " exact_batch=PASS duplicate_append=NO"
                      << " repeat_cas=NO pending_request_preflight=PASS"
                      << " wrong_context_before_openings=REJECTED"
                      << " file_anchor_reload=PASS" << std::endl;
    }
    if(rank==0) {
        // A syntactically valid truncated PREFIX is not accepted once the
        // trusted high-water anchor names a later committed journal tip.
        if(::truncate(journal_cleanup.path.c_str(),6*8)!=0)return false;
        Digest old_head{};
        if(!durable_guard.ReadCurrentHead(&old_head) ||
           old_head==externally_pinned_head) return false;
        AuthenticatedMpcMessageContext rolled=setup_context;
        rolled.message_kind=PVIA_VSS_SELECTIVE_POINT_KIND;
        rolled.round=101;
        rolled.sequence=101;
        Digest refused_head{};
        if(durable_guard.ObserveWithPinnedHead(
            rolled,1,0,externally_pinned_head,&refused_head))return false;
        std::fstream log(journal_cleanup.path,
            std::ios::binary | std::ios::in | std::ios::out);
        char byte=0;
        if(!log || !(log.seekg(8 * 2).read(&byte,1))) return false;
        byte^=1;
        log.seekp(8 * 6).write(&byte,1).flush();
        if(!log)return false;
        AuthenticatedMpcMessageContext after=setup_context;
        after.message_kind=PVIA_VSS_SELECTIVE_POINT_KIND;
        after.round=101;
        after.sequence=101;
        ReferenceVssSelectivePointDurableReplayGuard restarted(
            journal_cleanup.path,registry.registry_binding);
        if(restarted.Observe(after,1,0))return false;
        log.close();
        if(::unlink(journal_cleanup.path.c_str())!=0)return false;
        if(restarted.Observe(after,1,0))return false;
    }
    // Bridge the already-tested selective VSS release into PVIA's
    // AuthenticatedAuditRecoveryBackend interface. This adapter remains
    // explicitly reference-only: its signed receipt is not a ZK proof.
    {
        char backend_journal_name[] =
            "/tmp/pvia-point-pvia-recovery-XXXXXX";
        const int backend_journal_fd = ::mkstemp(backend_journal_name);
        if (backend_journal_fd < 0) return false;
        ::close(backend_journal_fd);
        ::unlink(backend_journal_name);
        RegistryFileCleanup backend_journal_cleanup{backend_journal_name};
        ReferenceVssSelectivePointDurableReplayGuard backend_journal(
            backend_journal_cleanup.path, registry.registry_binding);
        if (!backend_journal.InitializeNew()) return false;
        Digest backend_initial_head{};
        if (!backend_journal.ReadCurrentHead(&backend_initial_head) ||
            backend_initial_head == Digest{}) return false;

        AuthenticatedMpcMessageContext backend_context;
        backend_context.protocol_domain = PVIA_VSS_SELECTIVE_POINT_DOMAIN;
        backend_context.sid = setup_context.sid;
        backend_context.checkpoint = setup_context.checkpoint;
        backend_context.round = 701;
        backend_context.sequence = 701;
        backend_context.message_kind = PVIA_VSS_SELECTIVE_POINT_KIND;

        ReferenceVssAuthenticatedRecoveryConfig backend_config;
        backend_config.exchange = &exchange;
        backend_config.local_witness = &local;
        backend_config.receipt = &receipt;
        backend_config.trusted_transcript = &local.transcript_context;
        backend_config.release_context = backend_context;
        backend_config.expected_operation = statement.ref;
        backend_config.independently_pinned_operation_statement_binding =
            statement.operation_statement_binding;
        backend_config.independently_pinned_predecessor_root =
            statement.native_context.predecessor_root;
        backend_config.independently_pinned_checkpoint_root =
            statement.native_context.checkpoint_root;
        backend_config.independently_pinned_registry_binding =
            registry.registry_binding;

        Digest backend_pinned_head = backend_initial_head;
        if (rank == 0) {
            auto& pins = backend_config.target_pins;
            pins.registry_path = cleanup.path;
            pins.replay_journal_path = backend_journal_cleanup.path;
            pins.independently_pinned_record = externally_pinned_record;
            pins.independently_pinned_native_execution =
                native_execution_binding;
            pins.independently_pinned_registry_binding =
                registry.registry_binding;
            pins.independently_pinned_replay_head = backend_pinned_head;
            pins.load_current_head = [&backend_pinned_head](Digest* head) {
                if (!head || backend_pinned_head == Digest{}) return false;
                *head = backend_pinned_head;
                return true;
            };
            pins.verify_independent_pins = [
                &backend_pinned_head, &externally_pinned_record,
                &native_execution_binding, &registry](
                    const Digest& record, const Digest& native_execution,
                    const Digest& registry_binding, const Digest& replay_head) {
                    return record == externally_pinned_record &&
                        native_execution == native_execution_binding &&
                        registry_binding == registry.registry_binding &&
                        replay_head == backend_pinned_head;
                };
            pins.persist_new_head = [&backend_pinned_head](
                const Digest& expected, const Digest& next) {
                if (expected != backend_pinned_head || next == Digest{})
                    return false;
                backend_pinned_head = next;
                return true;
            };
        }

        AuthenticatedRecoveryRequest request;
        request.label.sid = backend_context.sid;
        request.label.phase = Phase::FOLD;
        request.label.obligation = Obligation::FOLD;
        request.label.round = 17;
        request.label.owner = statement.ref.owner;
        request.label.object_id = statement.ref.object_id;
        request.checkpoint = backend_context.checkpoint;
        request.relation = RelationKind::FOLDING;
        request.kernel = AuditRelationKernel::FOLD_RS;
        request.expected = hash_words({0x5256434558504543ULL, 1ULL});
        request.actual = hash_words({0x5256434143545541ULL, 2ULL});
        request.residual_commitment =
            hash_words({0x5256435245534944ULL, 3ULL});
        request.operation_statement_binding =
            statement.operation_statement_binding;
        request.dispute_binding = hash_words({0x5256434449535055ULL, 4ULL});
        request.checkpoint_root = statement.native_context.checkpoint_root;
        request.request_binding = compute_recovery_request_binding(request);
        if (request.request_binding == Digest{}) return false;

        ReferenceVssAuthenticatedRecoveryConfig bad_registry_config =
            backend_config;
        bad_registry_config.independently_pinned_registry_binding.bytes[0] ^= 1;
        ReferenceVssAuthenticatedRecoveryConfig independent_verifier_config;
        independent_verifier_config.expected_operation = statement.ref;
        independent_verifier_config
            .independently_pinned_operation_statement_binding =
                statement.operation_statement_binding;
        independent_verifier_config.independently_pinned_predecessor_root =
            statement.native_context.predecessor_root;
        independent_verifier_config.independently_pinned_checkpoint_root =
            statement.native_context.checkpoint_root;
        independent_verifier_config.independently_pinned_registry_binding =
            registry.registry_binding;

        ReferenceVssAuthenticatedAuditRecoveryBackend recovery_backend(
            std::move(backend_config));
        ReferenceVssAuthenticatedAuditRecoveryBackend independent_verifier(
            std::move(independent_verifier_config));
        BackendAuthenticatedAuditRecoveryEngine recovery_engine(
            recovery_backend);
        const AuthenticatedRecoveryArtifact recovered_artifact =
            recovery_engine.Recover(request, rank, world_size);
        bool adapter_ok =
            recovered_artifact.available &&
            recovered_artifact.cryptographically_authenticated &&
            validate_recovery_artifact(request, recovered_artifact) &&
            recovery_backend.Verify(request, recovered_artifact) &&
            independent_verifier.Verify(request, recovered_artifact) &&
            recovered_artifact.recovery_auth_signer ==
                static_cast<uint32_t>(statement.ref.owner) &&
            recovered_artifact.recovery_auth_registry_binding != Digest{} &&
            recovery_backend.ProductionCapabilityBinding() == Digest{};
        const std::vector<u64> encoded_recovery =
            encode_authenticated_recovery_artifact(recovered_artifact);
        AuthenticatedRecoveryArtifact decoded_recovery;
        adapter_ok = adapter_ok && encoded_recovery.size() == 70 &&
            decode_authenticated_recovery_artifact(
                encoded_recovery, &decoded_recovery) &&
            compute_recovery_artifact_binding(decoded_recovery) ==
                compute_recovery_artifact_binding(recovered_artifact) &&
            recovery_engine.Verify(request, decoded_recovery) &&
            independent_verifier.Verify(request, decoded_recovery);
        adapter_ok = adapter_ok &&
            verify_authenticated_recovery_receipt(
                request, decoded_recovery, authentication.PublicKeys(),
                authentication.RegistryCommitment());
        Digest wrong_registry_anchor = authentication.RegistryCommitment();
        wrong_registry_anchor.bytes[0] ^= 1;
        adapter_ok = adapter_ok &&
            !verify_authenticated_recovery_receipt(
                request, decoded_recovery, authentication.PublicKeys(),
                wrong_registry_anchor);

        BlameCertificate portable_certificate;
        portable_certificate.valid = true;
        portable_certificate.debug_only = false;
        portable_certificate.evidence_kind = AuditEvidenceKind::PRIVATE_RECOVERY;
        portable_certificate.sid = request.label.sid;
        portable_certificate.accused = request.label.owner;
        portable_certificate.label = request.label;
        portable_certificate.checkpoint = request.checkpoint;
        portable_certificate.relation = request.relation;
        portable_certificate.kernel = request.kernel;
        portable_certificate.expected = request.expected;
        portable_certificate.actual = request.actual;
        portable_certificate.residual_commitment = request.residual_commitment;
        portable_certificate.operation_statement_binding =
            request.operation_statement_binding;
        portable_certificate.dispute_binding = request.dispute_binding;
        portable_certificate.predecessor_root = decoded_recovery.predecessor_root;
        portable_certificate.checkpoint_root = decoded_recovery.checkpoint_root;
        portable_certificate.audit_witness_digest =
            compute_recovery_artifact_binding(decoded_recovery);
        portable_certificate.predecessor_evidence_complete = false;
        portable_certificate.recovery_artifact_words = encoded_recovery;
        const PublicBlameStatement portable_statement =
            make_public_blame_statement(portable_certificate);
        adapter_ok = adapter_ok &&
            portable_statement.statement_binding != Digest{};
        portable_certificate.blame_statement_binding =
            portable_statement.statement_binding;

        PublicBlameProofArtifact portable_proof;
        portable_proof.available = true;
        portable_proof.cryptographically_authenticated = true;
        portable_proof.proof_system_id = 0x50564941U;
        portable_proof.statement_binding =
            portable_certificate.blame_statement_binding;
        portable_proof.transcript_binding =
            hash_words({0x5056494150524f4fULL, request.checkpoint});
        portable_proof.proof_words = {0x5056494154455354ULL, 1ULL, 2ULL};

        // Exercise certificate codec v2 with a structurally canonical SP1
        // artifact envelope. This is deliberately NOT a Groth16 proof: the
        // independent N=4 SP1 suite verifies real proofs and tamper rejection.
        constexpr u64 kRecoveryArtifactMagic = 0x5056524350524631ULL;
        constexpr u64 kRecoveryStatementDomain = 0x5056524350525331ULL;
        constexpr u64 kRecoveryProofSystemId = 68103ULL;
        constexpr size_t kRecoveryStatementWords = 85;
        auto append_digest_words_local = [](const Digest& digest,
                                            std::vector<u64>* words) {
            for (size_t i = 0; i < 4; ++i) {
                u64 limb = 0;
                for (size_t j = 0; j < 8; ++j)
                    limb |= static_cast<u64>(digest.bytes[i * 8 + j]) << (8 * j);
                words->push_back(limb);
            }
        };
        std::vector<u64> request_context_words = {
            request.label.sid,
            static_cast<u64>(request.label.phase),
            request.label.round,
            request.label.owner,
            static_cast<u64>(request.label.obligation),
            request.label.object_id,
            request.checkpoint,
            static_cast<u64>(request.relation),
            static_cast<u64>(request.kernel)
        };
        append_digest_words_local(request.expected, &request_context_words);
        append_digest_words_local(request.actual, &request_context_words);
        append_digest_words_local(request.residual_commitment, &request_context_words);
        append_digest_words_local(
            request.operation_statement_binding, &request_context_words);
        append_digest_words_local(request.dispute_binding, &request_context_words);
        append_digest_words_local(request.checkpoint_root, &request_context_words);
        const Digest request_context_binding = hash_words(request_context_words);

        const std::array<Digest, 18> relation_digests = {{
            registry.vss_transcript,
            registry.setup_context_binding,
            registry.signed_commit_transport,
            registry.signed_ack_transport,
            registry.registry_binding,
            request.request_binding,
            request.operation_statement_binding,
            request.dispute_binding,
            decoded_recovery.predecessor_root,
            decoded_recovery.checkpoint_root,
            decoded_recovery.recovery_share_commitment,
            decoded_recovery.recovered_audit_commitment,
            decoded_recovery.recovery_agreement_binding,
            decoded_recovery.recovery_replay_head,
            decoded_recovery.recovery_auth_registry_binding,
            decoded_recovery.authentication_proof_commitment,
            decoded_recovery.recovery_transcript_binding,
            request_context_binding
        }};
        std::vector<u64> relation_statement(13, 0);
        relation_statement[0] = kRecoveryStatementDomain;
        relation_statement[1] = 1;
        relation_statement[2] = static_cast<u64>(world_size);
        relation_statement[3] = static_cast<u64>(threshold);
        relation_statement[4] = static_cast<u64>(request.label.owner);
        relation_statement[5] = static_cast<u64>(registry.element_count);
        relation_statement[6] = request.label.sid;
        relation_statement[7] = request.checkpoint;
        relation_statement[8] = registry.setup_round;
        relation_statement[9] = registry.setup_sequence;
        relation_statement[10] = static_cast<u64>(request.relation);
        relation_statement[11] = static_cast<u64>(request.kernel);
        relation_statement[12] =
            static_cast<u64>(decoded_recovery.recovery_auth_signer);
        for (const auto& digest : relation_digests)
            append_digest_words_local(digest, &relation_statement);
        if (relation_statement.size() != kRecoveryStatementWords)
            return false;
        const Digest recovery_statement_binding = hash_words(relation_statement);
        const Digest recovery_transcript_binding =
            hash_words({0x5056524350525452ULL, request.checkpoint});
        const u64 dummy_proof_word = 0x5056494150524f4fULL;
        std::vector<u64> recovery_artifact_commitment_words = {
            kRecoveryArtifactMagic, 1ULL, kRecoveryProofSystemId,
            static_cast<u64>(kRecoveryStatementWords), 1ULL
        };
        append_digest_words_local(
            recovery_statement_binding, &recovery_artifact_commitment_words);
        append_digest_words_local(
            recovery_transcript_binding, &recovery_artifact_commitment_words);
        recovery_artifact_commitment_words.insert(
            recovery_artifact_commitment_words.end(),
            relation_statement.begin(), relation_statement.end());
        recovery_artifact_commitment_words.push_back(dummy_proof_word);
        const Digest recovery_artifact_commitment =
            hash_words(recovery_artifact_commitment_words);

        auto store_word_le = [](std::vector<uint8_t>* bytes,
                                size_t offset, u64 word) {
            for (size_t j = 0; j < 8; ++j)
                (*bytes)[offset + j] =
                    static_cast<uint8_t>(word >> (8 * j));
        };
        std::vector<uint8_t> recovery_proof_bytes(
            (18 + kRecoveryStatementWords + 1) * sizeof(u64), 0);
        std::array<u64, 18> recovery_header{};
        recovery_header[0] = kRecoveryArtifactMagic;
        recovery_header[1] = 1;
        recovery_header[2] = sizeof(u64);
        recovery_header[3] = 18 + kRecoveryStatementWords + 1;
        recovery_header[4] = kRecoveryStatementWords;
        auto digest_to_header = [&recovery_header](
            const Digest& digest, size_t offset) {
            for (size_t i = 0; i < 4; ++i) {
                u64 limb = 0;
                for (size_t j = 0; j < 8; ++j)
                    limb |= static_cast<u64>(digest.bytes[i * 8 + j]) << (8 * j);
                recovery_header[offset + i] = limb;
            }
        };
        digest_to_header(recovery_statement_binding, 5);
        digest_to_header(recovery_transcript_binding, 9);
        digest_to_header(recovery_artifact_commitment, 13);
        recovery_header[17] = kRecoveryProofSystemId;
        for (size_t i = 0; i < recovery_header.size(); ++i)
            store_word_le(&recovery_proof_bytes, i * 8, recovery_header[i]);
        for (size_t i = 0; i < relation_statement.size(); ++i)
            store_word_le(&recovery_proof_bytes, (18 + i) * 8,
                          relation_statement[i]);
        store_word_le(
            &recovery_proof_bytes, (18 + kRecoveryStatementWords) * 8,
            dummy_proof_word);

        char proof_fixture_path[] =
            "/tmp/pvia_sp1_recovery_envelope_fixture_XXXXXX";
        const int proof_fixture_fd = ::mkstemp(proof_fixture_path);
        bool proof_envelope_load_ok = proof_fixture_fd >= 0;
        if (proof_fixture_fd >= 0) {
            ::close(proof_fixture_fd);
            {
                std::ofstream fixture(
                    proof_fixture_path,
                    std::ios::binary | std::ios::out | std::ios::trunc);
                fixture.write(
                    reinterpret_cast<const char*>(recovery_proof_bytes.data()),
                    static_cast<std::streamsize>(recovery_proof_bytes.size()));
                proof_envelope_load_ok = proof_envelope_load_ok &&
                    static_cast<bool>(fixture);
            }
            Sp1VssRecoveryProofProvider proof_provider;
            Sp1VssRecoveryProofReceipt structural_receipt;
            proof_envelope_load_ok = proof_envelope_load_ok &&
                proof_provider.LoadArtifact(
                    proof_fixture_path, relation_statement,
                    &structural_receipt) &&
                structural_receipt.available &&
                !structural_receipt.proof_verified &&
                structural_receipt.proof_system_id == kRecoveryProofSystemId &&
                structural_receipt.statement_words == relation_statement &&
                structural_receipt.artifact_bytes == recovery_proof_bytes &&
                structural_receipt.statement_binding ==
                    recovery_statement_binding &&
                structural_receipt.artifact_commitment ==
                    recovery_artifact_commitment;
            ::unlink(proof_fixture_path);
        }
        adapter_ok = adapter_ok && proof_envelope_load_ok;

        const bool has_live_sp1_proof =
            recovered_artifact.recovery_proof_system_id == kRecoveryProofSystemId &&
            recovered_artifact.recovery_proof_statement_binding != Digest{} &&
            recovered_artifact.recovery_proof_artifact_commitment != Digest{} &&
            recovered_artifact.recovery_proof_statement_words.size() ==
                kRecoveryStatementWords &&
            !recovered_artifact.recovery_proof_artifact_bytes.empty();
        const char* prove_once_env =
            std::getenv("PVIA_SP1_VSS_RECOVERY_PROVE_ONCE");
        const bool live_sp1_proof_required =
            prove_once_env && std::string(prove_once_env) == "1";
        adapter_ok = adapter_ok &&
            (!live_sp1_proof_required || has_live_sp1_proof);
        if (has_live_sp1_proof) {
            portable_proof.recovery_proof_system_id =
                recovered_artifact.recovery_proof_system_id;
            portable_proof.recovery_proof_statement_binding =
                recovered_artifact.recovery_proof_statement_binding;
            portable_proof.recovery_proof_artifact_commitment =
                recovered_artifact.recovery_proof_artifact_commitment;
            portable_proof.recovery_proof_statement_words =
                recovered_artifact.recovery_proof_statement_words;
            portable_proof.recovery_proof_artifact_bytes =
                recovered_artifact.recovery_proof_artifact_bytes;
        } else {
            portable_proof.recovery_proof_system_id =
                static_cast<uint32_t>(kRecoveryProofSystemId);
            portable_proof.recovery_proof_statement_binding =
                recovery_statement_binding;
            portable_proof.recovery_proof_artifact_commitment =
                recovery_artifact_commitment;
            portable_proof.recovery_proof_statement_words = relation_statement;
            portable_proof.recovery_proof_artifact_bytes = recovery_proof_bytes;
        }
        portable_proof.proof_commitment =
            compute_public_blame_proof_commitment(portable_proof);
        portable_certificate.recovery_proof_system_id =
            portable_proof.recovery_proof_system_id;
        portable_certificate.recovery_proof_statement_binding =
            portable_proof.recovery_proof_statement_binding;
        portable_certificate.recovery_proof_artifact_commitment =
            portable_proof.recovery_proof_artifact_commitment;
        portable_certificate.recovery_proof_statement_words =
            portable_proof.recovery_proof_statement_words;
        portable_certificate.recovery_proof_artifact_bytes =
            portable_proof.recovery_proof_artifact_bytes;
        portable_certificate.public_proof_system_id =
            portable_proof.proof_system_id;
        portable_certificate.public_proof_commitment =
            portable_proof.proof_commitment;
        portable_certificate.public_proof_transcript_binding =
            portable_proof.transcript_binding;
        portable_certificate.public_proof_words = portable_proof.proof_words;
        portable_certificate.transcript_digest =
            portable_proof.transcript_binding;
        portable_certificate.proof_digest = portable_proof.proof_commitment;
        adapter_ok = adapter_ok &&
            PublicJudge::ValidateRecoveryRelationStatement(
                portable_certificate,
                portable_proof.recovery_proof_statement_words);

        const std::vector<u64> portable_certificate_words =
            encode_private_recovery_blame_certificate(portable_certificate);
        BlameCertificate decoded_certificate;
        adapter_ok = adapter_ok && !portable_certificate_words.empty() &&
            portable_certificate_words[1] == 2 &&
            decode_private_recovery_blame_certificate(
                portable_certificate_words, &decoded_certificate) &&
            decoded_certificate.recovery_proof_system_id ==
                kRecoveryProofSystemId &&
            decoded_certificate.recovery_proof_statement_words ==
                portable_proof.recovery_proof_statement_words &&
            decoded_certificate.recovery_proof_artifact_bytes ==
                portable_proof.recovery_proof_artifact_bytes &&
            PublicJudge::ValidateRecoveryRelationStatement(
                decoded_certificate,
                decoded_certificate.recovery_proof_statement_words) &&
            PublicJudge::VerifyRecoveryReceipt(
                decoded_certificate, authentication.PublicKeys(),
                authentication.RegistryCommitment()) &&
            !PublicJudge::VerifyRecoveryReceipt(
                decoded_certificate, authentication.PublicKeys(),
                wrong_registry_anchor);
        std::vector<u64> tampered_certificate_words =
            portable_certificate_words;
        if (tampered_certificate_words.size() > 72 + 69)
            tampered_certificate_words[72 + 69] ^= 1;
        BlameCertificate rejected_certificate;
        adapter_ok = adapter_ok &&
            !decode_private_recovery_blame_certificate(
                tampered_certificate_words, &rejected_certificate);

        std::vector<u64> tampered_recovery_wire = encoded_recovery;
        if (!tampered_recovery_wire.empty())
            tampered_recovery_wire.back() ^= 1;
        AuthenticatedRecoveryArtifact tampered_decoded_recovery;
        adapter_ok = adapter_ok &&
            decode_authenticated_recovery_artifact(
                tampered_recovery_wire, &tampered_decoded_recovery) &&
            !independent_verifier.Verify(request, tampered_decoded_recovery);

        auto changed_artifact = recovered_artifact;
        changed_artifact.authentication_proof_commitment.bytes[0] ^= 1;
        adapter_ok = adapter_ok &&
            !independent_verifier.Verify(request, changed_artifact);
        auto changed_signature = recovered_artifact;
        changed_signature.recovery_auth_signature[0] ^= 1;
        adapter_ok = adapter_ok &&
            compute_recovery_artifact_binding(changed_signature) !=
                compute_recovery_artifact_binding(recovered_artifact) &&
            !independent_verifier.Verify(request, changed_signature);
        auto changed_share_commitment = recovered_artifact;
        changed_share_commitment.recovery_share_commitment.bytes[0] ^= 1;
        adapter_ok = adapter_ok &&
            !independent_verifier.Verify(request, changed_share_commitment);
        if (rank == 0)
            adapter_ok = adapter_ok &&
                backend_pinned_head != backend_initial_head;
        int adapter_local = adapter_ok ? 1 : 0;
        int adapter_global = 0;
        MPI_Allreduce(&adapter_local, &adapter_global, 1,
                      MPI_INT, MPI_MIN, MPI_COMM_WORLD);
        if (!adapter_global) return false;

        // A target whose independent registry anchor disagrees with the
        // configured registry binding must fail collectively before release.
        ReferenceVssAuthenticatedAuditRecoveryBackend bad_registry_backend(
            std::move(bad_registry_config));
        const AuthenticatedRecoveryArtifact refused =
            bad_registry_backend.Recover(request, rank, world_size);
        const bool rejected_bad_registry =
            !refused.available &&
            !bad_registry_backend.Verify(request, refused);
        int rejected_local = rejected_bad_registry ? 1 : 0;
        int rejected_global = 0;
        MPI_Allreduce(&rejected_local, &rejected_global, 1,
                      MPI_INT, MPI_MIN, MPI_COMM_WORLD);
        if (!rejected_global) return false;
    }

    // File corruption must fail even if the embedded, now-stale hash is
    // present. The external anchor is never recovered from the file.
    {
        std::fstream file(cleanup.path,
            std::ios::binary | std::ios::in | std::ios::out);
        char byte = 0;
        if (!file || !(file.seekg(8 * 33).read(&byte, 1))) return false;
        byte ^= 1;
        file.seekp(8 * 33).write(&byte, 1).flush();
        if (!file) return false;
    }
    ReferenceVssPointRegistryExecutionRecord corrupted;
    if (load_reference_vss_point_registry_execution_record(
            cleanup.path, externally_pinned_record,
            native_execution_binding, setup_context.sid,
            setup_context.checkpoint, receipt.transcript_binding,
            &corrupted)) return false;
    if(rank==0) {
        std::cout << "PVIA_VSS_SELECTIVE_POINT: PASS"
                  << " scope=TARGET_ONLY_POINT_VALUES"
                  << " full_row_transfer=NO"
                  << " injected=" << (injected?"REJECTED":"NONE")
                  << " privacy=NOT_ATTESTED"
                  << " transport=ED25519_MPI"
                  << " opening=VSS_CROSSCHECKED_HASH_REGISTRY"
                  << " registry_store=EXECUTION_BOUND_DISK"
                  << " native_issuer=VERIFIED_ED25519_V2"
                  << " replay_store=DURABLE_SEQUENCE_JOURNAL"
                  << " replay_head=EXTERNAL_PIN_REQUIRED"
                  << " integrated_release=SIGNED_BATCH_GATE"
                  << " pvia_recovery_backend=REFERENCE_ONLY"
                  << " external_keys="
                  << (exchange.production_authenticated_ready()?"ANCHORED":"TEST_ONLY")
                  << std::endl;
    }
    return true;
}
} // namespace pvia
