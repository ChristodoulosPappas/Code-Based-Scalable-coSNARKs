#include "ReferenceShamirAuditSession.hpp"
#include "ReferenceVssAuthenticatedAuditRecoveryBackend.hpp"
#include "MultiplicationConsistencySharingWitness.hpp"
#include "MultiplicationConsistencyProviderAbi.hpp"
#include "MultiplicationConsistencyProviderAcceptance.hpp"
#include "MultiplicationConsistencyProviderRelationReference.h"
#include "RobustAuditSession.hpp"
#include "AuthenticatedMpcAbortEvidence.hpp"
#include "TransferAuthentication.hpp"
#include "RegistrationNativeLocalRecord.hpp"
#include "RegistrationNativeConsumedSnapshot.hpp"
#include "RegistrationNativeExecutionReceipt.hpp"
#include "RegistrationNativeIssuerPublicFile.hpp"
#include "ReferenceNativeIssuerKeyAdapter.hpp"
#include "RegistrationPreVssReceipt.hpp"
#include "RegistrationOriginEvidencePair.hpp"
#include "RegistrationPublicOriginBundle.hpp"
#include "RegistrationPrivateTestVectorExport.hpp"
#include "RegistrationReceiptReplayLedger.hpp"
#include <sys/stat.h>
#include <spawn.h>
#include <sys/wait.h>
#include <signal.h>
#include <chrono>
#include <unistd.h>
#include <cstdlib>
#include <cerrno>
#include <string>
#include "PrivateStateMaterialStore.hpp"
#include "PrivateAuditMaterialStore.hpp"
#include "../utils.hpp"

#include <mpi.h>

#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <sstream>
#include <iostream>
#include <limits>
#include <memory>
#include <openssl/evp.h>
#include <utility>
#include <vector>

namespace pvia {
namespace {

constexpr u64 SESSION_BIND_DOMAIN = 0x5056415544534553ULL; // PVAUDSES
constexpr u64 COEFFICIENT_DOMAIN = 0x5056415544434f45ULL;  // PVAUDCOE
constexpr u64 CHALLENGE_DOMAIN = 0x505641554443484cULL;    // PVAUDCHL
constexpr u64 BATCH_ZERO_MULTIPLICATION_ID =
    0x50564241545a4552ULL; // PVBATZER
constexpr u64 SUBSET_COEFFICIENT_DOMAIN = 0x5056415544534346ULL; // PVAUDSCF
constexpr u64 SUBSET_CHALLENGE_DOMAIN = 0x5056415544534348ULL;   // PVAUDSCH
constexpr u64 AUDIT_AUTH_KIND_SUBSET_DOMAIN = 0x535542444f4d3031ULL; // SUBDOM01
constexpr u64 AUDIT_AUTH_KIND_SUBSET_COIN = 0x535542434f494e31ULL;   // SUBCOIN1
constexpr u64 AUDIT_AUTH_KIND_SUBSET_OPEN = 0x5355424f50454e31ULL;   // SUBOPEN1
constexpr u64 AUDIT_AUTH_PROTOCOL_DOMAIN = 0x5056415544415554ULL; // PVAUDAUT
constexpr u64 AUDIT_AUTH_TRANSCRIPT_DOMAIN = 0x505641555454524eULL; // PVAUTTRN
constexpr u64 AUDIT_AUTH_KIND_BACKEND_MODE = 0x5247424d4f444531ULL; // RGBMODE1
constexpr u64 AUDIT_AUTH_KIND_REG_READY = 0x5247524541445931ULL; // RGREADY1
constexpr u64 AUDIT_AUTH_KIND_REG_CAP = 0x5247434150303031ULL; // RGCAP001
constexpr u64 AUDIT_AUTH_KIND_NATIVE_READY = 0x52474e4154524459ULL; // RGNATRDY
constexpr u64 AUDIT_AUTH_KIND_NATIVE_BIND = 0x52474e4154424e44ULL; // RGNATBND
constexpr u64 AUDIT_AUTH_KIND_OWNER_READY = 0x4f574e5244593031ULL; // OWNRDY01
constexpr u64 AUDIT_AUTH_KIND_REG_REQUEST_READY = 0x5247525152445931ULL; // RGRQRDY1
constexpr u64 AUDIT_AUTH_KIND_REG_REQUEST_SCOPE = 0x5247525153435031ULL; // RGRQSCP1
constexpr u64 AUDIT_AUTH_KIND_REG_OWNER_SOURCE = 0x52474f574e535231ULL; // RGOWNSR1
constexpr u64 AUDIT_AUTH_KIND_PAYLOAD_SHAPE = 0x5041595348503031ULL; // PAYSHP01
constexpr u64 AUDIT_AUTH_KIND_VSS = 0x5245475653533031ULL; // REGVSS01
constexpr u64 AUDIT_AUTH_KIND_REG_PROOF = 0x5245475052463031ULL; // REGPRF01
constexpr u64 AUDIT_AUTH_KIND_REG_VERIFY = 0x5245475652463031ULL; // REGVRF01
constexpr u64 AUDIT_AUTH_KIND_REG_ORIGIN = 0x52474f5249473031ULL; // RGORIG01
constexpr u64 AUDIT_AUTH_KIND_REG_REPLAY = 0x52475245504c3031ULL; // RGREPL01
constexpr u64 AUDIT_AUTH_KIND_REG_LOCAL = 0x52474f524c4f4331ULL; // RGORLOC1
constexpr u64 AUDIT_AUTH_KIND_REG_ORIGIN_READY = 0x52474f5244523031ULL; // RGORDR01
constexpr u64 AUDIT_AUTH_KIND_SEAL_BINDING = 0x5345414c424e4431ULL; // SEALBND1
constexpr u64 AUDIT_AUTH_KIND_REG_SET = 0x5245475345543031ULL; // REGSET01
constexpr u64 AUDIT_AUTH_KIND_SEAL_REG_CAP = 0x5345474341503031ULL; // SEGCAP01
constexpr u64 AUDIT_AUTH_KIND_SEAL_REG_PROOF = 0x5345475052463031ULL; // SEGPRF01
constexpr u64 AUDIT_AUTH_KIND_BATCH_COIN = 0x4241544348434f49ULL; // BATCHCOI
constexpr u64 AUDIT_AUTH_KIND_BATCH_STRONG_MODE = 0x42415443484d4f44ULL; // BATCHMOD
constexpr u64 AUDIT_AUTH_KIND_BATCH_PROVENANCE = 0x4650524f56424e44ULL; // FPROVBND
constexpr u64 AUDIT_AUTH_KIND_BATCH_MUL_BINDING = 0x424d554c424e4431ULL; // BMULBND1
constexpr u64 AUDIT_AUTH_KIND_BATCH_OPEN_BINDING = 0x424f504e424e4431ULL; // BOPNBND1

void append_digest(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

F digest_to_field(const Digest& digest) {
    u64 real = 0, img = 0;
    std::memcpy(&real, digest.bytes.data(), 8);
    std::memcpy(&img, digest.bytes.data() + 8, 8);
    return F(static_cast<long long>(real % F::mod),
             static_cast<long long>(img % F::mod));
}

Digest digest_from_words(const std::vector<u64>& words, size_t offset) {
    Digest digest{};
    if (offset > words.size() || words.size() - offset < 4) return digest;
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(digest.bytes.data() + 8 * i, &words[offset + i], 8);
    return digest;
}

bool all_ranks_same_digest(const Digest& digest, int world_size) {
    std::vector<uint8_t> gathered(
        static_cast<size_t>(world_size) * digest.bytes.size());
    MPI_Allgather(digest.bytes.data(), static_cast<int>(digest.bytes.size()),
                  MPI_BYTE, gathered.data(), static_cast<int>(digest.bytes.size()),
                  MPI_BYTE, MPI_COMM_WORLD);
    for (int i = 0; i < world_size; ++i) {
        const uint8_t* begin = gathered.data() +
            static_cast<size_t>(i) * digest.bytes.size();
        if (!std::equal(digest.bytes.begin(), digest.bytes.end(), begin))
            return false;
    }
    return true;
}


std::vector<u64> encode_registration_proof(
    const RegistrationConsistencyProofArtifact& proof) {
    std::vector<u64> words = {
        proof.available ? 1ULL : 0ULL,
        proof.cryptographically_authenticated ? 1ULL : 0ULL,
        proof.zero_knowledge ? 1ULL : 0ULL,
        proof.proof_system_id,
        static_cast<u64>(proof.proof_words.size())};
    append_digest(proof.statement_binding, &words);
    append_digest(proof.transcript_binding, &words);
    append_digest(proof.proof_commitment, &words);
    words.insert(words.end(), proof.proof_words.begin(), proof.proof_words.end());
    return words;
}

bool decode_registration_proof(
    const std::vector<u64>& words,
    RegistrationConsistencyProofArtifact* proof) {
    if (!proof || words.size() < 17 || words[0] > 1 || words[1] > 1 ||
        words[2] > 1 || words[3] > std::numeric_limits<uint32_t>::max() ||
        words[4] >
            static_cast<u64>(std::numeric_limits<size_t>::max()))
        return false;
    const size_t proof_count = static_cast<size_t>(words[4]);
    if (proof_count != words.size() - 17) return false;
    *proof = RegistrationConsistencyProofArtifact{};
    proof->available = words[0] != 0;
    proof->cryptographically_authenticated = words[1] != 0;
    proof->zero_knowledge = words[2] != 0;
    proof->proof_system_id = static_cast<uint32_t>(words[3]);
    proof->statement_binding = digest_from_words(words, 5);
    proof->transcript_binding = digest_from_words(words, 9);
    proof->proof_commitment = digest_from_words(words, 13);
    proof->proof_words.assign(words.begin() + 17, words.end());
    return true;
}


} // namespace
ReferenceShamirAuditSession::ReferenceShamirAuditSession(
    uint64_t session_id, CheckpointId checkpoint,
    int rank, int world_size, int threshold,
    const RegistrationConsistencyProofBackend*
        registration_consistency_backend,
    const MultiplicationConsistencyProofBackend*
        multiplication_consistency_backend,
    const AuthenticatedMpcExchange* authenticated_exchange,
    const RegistrationOriginApprovalBackend*
        registration_origin_approval_backend,
    bool permit_reference_registration_test_only)
    : session_id_(session_id), checkpoint_(checkpoint),
      rank_(rank), world_size_(world_size),
      mpc_(rank, world_size, threshold),
      vss_(rank, world_size, threshold),
      registration_consistency_backend_(registration_consistency_backend),
      registration_origin_approval_backend_(
          registration_origin_approval_backend),
      permit_reference_registration_test_only_(
          permit_reference_registration_test_only) {
    if (authenticated_exchange &&
        mpc_.SetAuthenticatedTransport(
            authenticated_exchange, session_id_, checkpoint_))
        authenticated_exchange_ = authenticated_exchange;
    if (multiplication_consistency_backend &&
        mpc_.SetMultiplicationConsistencyProofBackend(
            multiplication_consistency_backend) &&
        mpc_.multiplication_consistency_available())
        multiplication_consistency_backend_ =
            multiplication_consistency_backend;
}

AuthenticatedMpcMessageContext
ReferenceShamirAuditSession::NextTransportContext(
    u64 message_kind, uint64_t round) const {
    AuthenticatedMpcMessageContext context;
    if (!authenticated_transport_enabled() || message_kind == 0)
        return context;
    context.protocol_domain = AUDIT_AUTH_PROTOCOL_DOMAIN;
    context.sid = session_id_;
    context.checkpoint = checkpoint_;
    context.round = round;
    context.sequence = transport_sequence_++;
    context.message_kind = message_kind;
    return context;
}

void ReferenceShamirAuditSession::BindTransportTranscript(
    const Digest& binding) const {
    if (!authenticated_transport_enabled() || binding == Digest{}) return;
    std::vector<u64> words = {
        AUDIT_AUTH_TRANSCRIPT_DOMAIN, session_id_, checkpoint_};
    append_digest(authenticated_transport_capability_binding(), &words);
    append_digest(authenticated_transport_transcript_binding_, &words);
    append_digest(binding, &words);
    authenticated_transport_transcript_binding_ = hash_words(words);
}

bool ReferenceShamirAuditSession::CollectiveSameWord(
    u64 local_value, u64 message_kind, uint64_t round,
    u64* agreed_value) const {
    if (!agreed_value || message_kind == 0) return false;
    if (authenticated_transport_enabled()) {
        std::vector<u64> gathered;
        Digest binding{};
        if (!authenticated_exchange_->AllGatherWords(
                NextTransportContext(message_kind, round),
                {local_value}, &gathered, &binding) ||
            gathered.size() != static_cast<size_t>(world_size_))
            return false;
        for (u64 value : gathered)
            if (value != gathered.front()) return false;
        *agreed_value = gathered.front();
        BindTransportTranscript(binding);
        return authenticated_transport_transcript_binding_ != Digest{};
    }
    std::vector<u64> gathered(static_cast<size_t>(world_size_));
    MPI_Allgather(&local_value, 1, MPI_UINT64_T,
                  gathered.data(), 1, MPI_UINT64_T, MPI_COMM_WORLD);
    for (u64 value : gathered)
        if (value != gathered.front()) return false;
    *agreed_value = gathered.front();
    return true;
}

bool ReferenceShamirAuditSession::CollectiveAllTrue(
    bool local_value, u64 message_kind, uint64_t round) const {
    if (message_kind == 0) return false;
    if (authenticated_transport_enabled()) {
        bool all_true = false;
        Digest binding{};
        if (!authenticated_exchange_->AllTrue(
                NextTransportContext(message_kind, round),
                local_value, &all_true, &binding))
            return false;
        BindTransportTranscript(binding);
        return all_true && authenticated_transport_transcript_binding_ != Digest{};
    }
    int local = local_value ? 1 : 0;
    int global = 0;
    MPI_Allreduce(&local, &global, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    return global != 0;
}

bool ReferenceShamirAuditSession::CollectiveSameDigest(
    const Digest& local_digest, u64 message_kind, uint64_t round) const {
    if (local_digest == Digest{} || message_kind == 0) return false;
    if (authenticated_transport_enabled()) {
        std::vector<u64> local_words;
        append_digest(local_digest, &local_words);
        std::vector<u64> gathered;
        Digest binding{};
        if (!authenticated_exchange_->AllGatherWords(
                NextTransportContext(message_kind, round),
                local_words, &gathered, &binding) ||
            gathered.size() != static_cast<size_t>(world_size_) * 4)
            return false;
        const Digest first = digest_from_words(gathered, 0);
        if (first == Digest{}) return false;
        for (int participant = 1; participant < world_size_; ++participant)
            if (digest_from_words(
                    gathered, static_cast<size_t>(participant) * 4) != first)
                return false;
        BindTransportTranscript(binding);
        return authenticated_transport_transcript_binding_ != Digest{};
    }
    return all_ranks_same_digest(local_digest, world_size_);
}

bool ReferenceShamirAuditSession::BroadcastWords(
    int owner, const std::vector<u64>& owner_payload,
    u64 message_kind, uint64_t round, std::vector<u64>* payload) const {
    if (!payload || owner < 0 || owner >= world_size_ || message_kind == 0)
        return false;
    if (authenticated_transport_enabled()) {
        Digest binding{};
        if (!authenticated_exchange_->BroadcastWords(
                NextTransportContext(message_kind, round), owner,
                owner_payload, payload, &binding))
            return false;
        BindTransportTranscript(binding);
        return authenticated_transport_transcript_binding_ != Digest{};
    }
    u64 word_count = rank_ == owner
        ? static_cast<u64>(owner_payload.size()) : 0ULL;
    MPI_Bcast(&word_count, 1, MPI_UINT64_T, owner, MPI_COMM_WORLD);
    if (word_count > static_cast<u64>(std::numeric_limits<int>::max()) ||
        word_count > static_cast<u64>(std::numeric_limits<size_t>::max()))
        return false;
    if (rank_ == owner) {
        *payload = owner_payload;
    } else {
        payload->assign(static_cast<size_t>(word_count), 0);
    }
    if (word_count > 0)
        MPI_Bcast(payload->data(), static_cast<int>(word_count),
                  MPI_UINT64_T, owner, MPI_COMM_WORLD);
    return true;
}

bool ReferenceShamirAuditSession::RegisterFoldOperation(
    uint32_t owner, const OperationRef& ref, const F& public_challenge,
    const Digest& public_state_digest,
    const Digest& public_actual_digest,
    const Digest& operation_statement_binding,
    const std::vector<F>& owner_private_state,
    const std::vector<F>& owner_actual_output,
    const RegistrationNativeContext& native_context) {
    // A checkpoint registration is atomic at the acceptance boundary:
    // after any rejected operation, no subset of its earlier operations
    // may reach SEALED. This guard covers every local/collective return.
    bool completed = false;
    struct FailureGuard {
        bool& failed;
        bool& completed;
        ~FailureGuard() { if (!completed) failed = true; }
    } failure_guard{registration_failed_, completed};
    // No party is allowed to return alone before its peers enter VSS:
    // even a malformed argument, duplicate registration or poisoned
    // checkpoint must become one collective fail-closed transaction.
    const bool local_ready =
        !registration_failed_ && !sealed_ && mpc_.valid() &&
        session_id_ != 0 && checkpoint_ != 0 && ref.object_id != 0 &&
        owner < static_cast<uint32_t>(world_size_) && ref.owner == owner &&
        public_state_digest != Digest{} &&
        public_actual_digest != Digest{} &&
        operation_statement_binding != Digest{} &&
        !std::any_of(operations_.begin(), operations_.end(),
            [&](const FoldOperationShares& item) { return item.ref == ref; });
    if (!CollectiveAllTrue(
            local_ready, AUDIT_AUTH_KIND_REG_REQUEST_READY, 0))
        return false;

    // A rank-local public description change MUST be caught *before*
    // pre-VSS origin approval, private sharing or proof invocation.
    // This covers both proof-enabled and reference-only sessions.
    std::vector<u64> descriptor = {
        0x5056524547515244ULL, // PVREGQRD
        session_id_, checkpoint_, owner, ref.owner, ref.object_id,
        static_cast<u64>(operations_.size()),
        static_cast<u64>(world_size_),
        static_cast<u64>(mpc_.threshold())};
    append_digest(public_state_digest, &descriptor);
    append_digest(public_actual_digest, &descriptor);
    append_digest(operation_statement_binding, &descriptor);
    append_digest(hash_field_vector({public_challenge}), &descriptor);
    if (!CollectiveSameDigest(
            hash_words(descriptor), AUDIT_AUTH_KIND_REG_REQUEST_SCOPE, 0))
        return false;
    const u64 local_backend_mode =
        registration_consistency_backend_ ? 1ULL : 0ULL;
    u64 backend_mode = 0;
    if (!CollectiveSameWord(local_backend_mode,
            AUDIT_AUTH_KIND_BACKEND_MODE, ref.object_id, &backend_mode))
        return false;
    const bool require_registration_consistency = backend_mode != 0;
    RegistrationConsistencyCapabilities registration_capabilities;
    if (require_registration_consistency) {
        const bool local_native_ready =
            validate_registration_native_context(native_context);
        if (!CollectiveAllTrue(local_native_ready,
                AUDIT_AUTH_KIND_NATIVE_READY, ref.object_id))
            return false;
        const Digest native_binding =
            compute_registration_native_context_binding(native_context);
        if (!CollectiveSameDigest(native_binding,
                AUDIT_AUTH_KIND_NATIVE_BIND, ref.object_id))
            return false;
        // Presence is checked BEFORE native VSS sharing. If only a subset
        // of ranks configured an endorser, nobody enters its collectives.
        if (!CollectiveAllTrue(
                registration_origin_approval_backend_ != nullptr,
                AUDIT_AUTH_KIND_REG_ORIGIN_READY, ref.object_id))
            return false;
        registration_capabilities =
            registration_consistency_backend_->Capabilities();
        const bool local_ready =
            production_ready_registration_consistency_capabilities(
                registration_capabilities) ||
            (permit_reference_registration_test_only_ &&
             registration_capabilities.reference_test_only &&
             validate_registration_consistency_capabilities(
                 registration_capabilities) &&
             registration_capabilities.malicious_sound &&
             registration_capabilities.zero_knowledge &&
             registration_capabilities.binds_sharing_transcript);
        if (!CollectiveAllTrue(local_ready, AUDIT_AUTH_KIND_REG_READY,
                ref.object_id) ||
            !CollectiveSameDigest(
                registration_capabilities.capability_binding,
                AUDIT_AUTH_KIND_REG_CAP, ref.object_id) ||
            !vss_.valid())
            return false;
    }
    int local_consistency = 1;
    if (rank_ == static_cast<int>(owner)) {
        local_consistency = !owner_private_state.empty() &&
            !owner_actual_output.empty() &&
            hash_field_vector(owner_private_state) == public_state_digest &&
            hash_field_vector(owner_actual_output) == public_actual_digest ? 1 : 0;
    }
    if (!CollectiveAllTrue(local_consistency != 0,
            AUDIT_AUTH_KIND_OWNER_READY, ref.object_id))
        return false;

    if (require_registration_consistency) {
        // Before any VSS sharing, collectively require the owner-side
        // native source adapter to accept the concrete input vectors.
        // The pre-sharing 38-word claim deliberately omits any future
        // VSS transcript; the dummy digest below is never signed.
        bool owner_source_ready = true;
        if (rank_ == static_cast<int>(owner)) {
            RegistrationConsistencyStatement pre_vss;
            pre_vss.sid = session_id_;
            pre_vss.checkpoint = checkpoint_;
            pre_vss.ref = ref;
            pre_vss.kernel = AuditRelationKernel::FOLD_RS;
            pre_vss.state_element_count = owner_private_state.size();
            pre_vss.output_element_count = owner_actual_output.size();
            pre_vss.public_state_digest = public_state_digest;
            pre_vss.public_actual_digest = public_actual_digest;
            pre_vss.public_challenge_binding =
                hash_field_vector({public_challenge});
            pre_vss.native_context = native_context;
            pre_vss.operation_statement_binding =
                operation_statement_binding;
            pre_vss.sharing_transcript_binding =
                hash_words({0x5056524558505258ULL});
            pre_vss.statement_binding =
                compute_registration_consistency_statement_binding(pre_vss);
            owner_source_ready =
                registration_origin_approval_backend_->
                    CheckOwnerNativeInputBeforeVss(
                        pre_vss, owner_private_state, owner_actual_output,
                        public_challenge);
        }
        if (!CollectiveAllTrue(owner_source_ready,
                AUDIT_AUTH_KIND_REG_OWNER_SOURCE, ref.object_id))
            return false;
    }

    std::vector<u64> owner_sizes;
    if (rank_ == static_cast<int>(owner))
        owner_sizes = {static_cast<u64>(owner_private_state.size()),
                       static_cast<u64>(owner_actual_output.size())};
    std::vector<u64> received_sizes;
    if (!BroadcastWords(static_cast<int>(owner), owner_sizes,
            AUDIT_AUTH_KIND_PAYLOAD_SHAPE, ref.object_id, &received_sizes) ||
        received_sizes.size() != 2)
        return false;
    const u64 payload_sizes[2] = {received_sizes[0], received_sizes[1]};
    if (payload_sizes[0] == 0 || payload_sizes[1] == 0 ||
        payload_sizes[0] > static_cast<u64>(std::numeric_limits<size_t>::max()) ||
        payload_sizes[1] > static_cast<u64>(std::numeric_limits<size_t>::max()) ||
        payload_sizes[0] > std::numeric_limits<u64>::max() - payload_sizes[1])
        return false;
    std::vector<F> combined_plaintext;
    if (rank_ == static_cast<int>(owner)) {
        combined_plaintext.reserve(owner_private_state.size() +
                                   owner_actual_output.size());
        combined_plaintext.insert(combined_plaintext.end(),
                                  owner_private_state.begin(),
                                  owner_private_state.end());
        combined_plaintext.insert(combined_plaintext.end(),
                                  owner_actual_output.begin(),
                                  owner_actual_output.end());
    }
    std::vector<F> combined_shares;
    Digest vss_transcript_binding{};
    ReferenceVssLocalWitness vss_local_witness;
    ReferenceVssReceipt vss_receipt;
    ReferenceVssDealerWitness vss_dealer_witness;
    if (vss_.valid()) {
        const bool shared = authenticated_transport_enabled()
            ? vss_.ShareVectorFromDealerAuthenticated(
                static_cast<int>(owner), combined_plaintext,
                &combined_shares, &vss_receipt, *authenticated_exchange_,
                NextTransportContext(AUDIT_AUTH_KIND_VSS, ref.object_id),
                require_registration_consistency ? &vss_dealer_witness : nullptr,
                &vss_local_witness)
            : require_registration_consistency
                ? vss_.ShareVectorFromDealerWithWitnesses(
                    static_cast<int>(owner), combined_plaintext,
                    &combined_shares, &vss_receipt, &vss_dealer_witness,
                    &vss_local_witness)
                : vss_.ShareVectorFromDealerWithLocalWitness(
                    static_cast<int>(owner), combined_plaintext,
                    &combined_shares, &vss_receipt, &vss_local_witness);
        if (!shared || !vss_receipt.available || !vss_receipt.consistent ||
            vss_receipt.transcript_binding == Digest{} ||
            !validate_reference_vss_local_witness(vss_local_witness) ||
            vss_local_witness.transcript_binding !=
                vss_receipt.transcript_binding)
            return false;
        vss_transcript_binding = vss_receipt.transcript_binding;
        if (authenticated_transport_enabled())
            BindTransportTranscript(vss_receipt.transcript_binding);
    } else {
        if (authenticated_transport_enabled() ||
            !mpc_.ShareVectorFromDealer(
                static_cast<int>(owner), combined_plaintext, &combined_shares))
            return false;
    }
    const size_t state_count = static_cast<size_t>(payload_sizes[0]);
    const size_t actual_count = static_cast<size_t>(payload_sizes[1]);
    if (combined_shares.size() != state_count + actual_count) return false;
    std::vector<F> state_shares(
        combined_shares.begin(), combined_shares.begin() + state_count);
    std::vector<F> actual_shares(
        combined_shares.begin() + state_count, combined_shares.end());

    RegistrationConsistencyProofArtifact registration_proof;
    RegistrationConsistencyStatement registration_statement;
    if (require_registration_consistency) {
        RegistrationConsistencyStatement& statement = registration_statement;
        statement.sid = session_id_;
        statement.checkpoint = checkpoint_;
        statement.ref = ref;
        statement.kernel = AuditRelationKernel::FOLD_RS;
        statement.state_element_count = state_count;
        statement.output_element_count = actual_count;
        statement.public_state_digest = public_state_digest;
        statement.public_actual_digest = public_actual_digest;
        statement.public_challenge_binding =
            hash_field_vector({public_challenge});
        statement.native_context = native_context;
        statement.operation_statement_binding = operation_statement_binding;
        statement.sharing_transcript_binding = vss_transcript_binding;
        statement.statement_binding =
            compute_registration_consistency_statement_binding(statement);
        if (!validate_registration_consistency_statement(statement)) return false;
        // Public endorsements must be checked BEFORE any ZK registration
        // proof is released. Missing backends fail collectively; a passive
        // reference run without a ZK backend does not take this path.
        // Presence was already collectively authenticated before VSS.
        // No rank enters signature collectives unless every signer has
        // locally approved the exact post-VSS public statement.
        const bool local_record_checked =
            registration_origin_approval_backend_->CheckLocalNativeOrigin(
                statement);
        if (!CollectiveAllTrue(local_record_checked,
                AUDIT_AUTH_KIND_REG_LOCAL, ref.object_id))
            return false;
        const bool local_origin_approved =
            registration_origin_approval_backend_->ApprovePublicOrigin(statement);
        if (!CollectiveAllTrue(local_origin_approved,
                AUDIT_AUTH_KIND_REG_ORIGIN, ref.object_id))
            return false;
        // A durable local reservation is REQUIRED before any prover
        // invocation. A partial multi-rank reservation cannot roll back:
        // subsequent attempts must fail closed and be reconciled.
        const bool origin_consumed =
            registration_origin_approval_backend_->ConsumeApprovedOrigin(
                statement);
        if (!CollectiveAllTrue(origin_consumed,
                AUDIT_AUTH_KIND_REG_REPLAY, ref.object_id))
            return false;
        std::vector<u64> owner_proof_words;
        if (rank_ == static_cast<int>(owner)) {
            RegistrationConsistencyWitness witness;
            witness.state_values = owner_private_state;
            witness.actual_output = owner_actual_output;
            witness.public_challenge = public_challenge;
            witness.sharing_witness_words =
                encode_reference_vss_dealer_witness(vss_dealer_witness);
            if (evaluate_reference_registration_consistency_relation(
                    statement, witness)) {
                registration_proof = registration_consistency_backend_->Prove(
                    statement, witness);
            }
            owner_proof_words = encode_registration_proof(registration_proof);
        }
        std::vector<u64> proof_words;
        if (!BroadcastWords(static_cast<int>(owner), owner_proof_words,
                AUDIT_AUTH_KIND_REG_PROOF, ref.object_id, &proof_words) ||
            !decode_registration_proof(proof_words, &registration_proof))
            return false;
        const bool local_verified =
            validate_registration_consistency_proof_artifact(
                statement, registration_proof) &&
            registration_consistency_backend_->Verify(
                statement, registration_proof);
        if (!CollectiveAllTrue(local_verified, AUDIT_AUTH_KIND_REG_VERIFY,
                ref.object_id))
            return false;
    }

    std::vector<F> expected_shares;
    if (!recompute_fold_rs_output(
            state_shares, public_challenge, &expected_shares) ||
        expected_shares.size() != actual_shares.size())
        return false;
    FoldOperationShares operation;
    operation.owner = owner;
    operation.ref = ref;
    operation.public_challenge = public_challenge;
    operation.public_state_digest = public_state_digest;
    operation.public_actual_digest = public_actual_digest;
    operation.operation_statement_binding = operation_statement_binding;
    operation.vss_transcript_binding = vss_transcript_binding;
    operation.vss_local_witness = std::move(vss_local_witness);
    operation.vss_receipt = std::move(vss_receipt);
    operation.registration_consistency_statement =
        std::move(registration_statement);
    operation.registration_consistency_proof =
        std::move(registration_proof);
    operation.state_shares = std::move(state_shares);
    operation.actual_output_shares = std::move(actual_shares);
    operation.residual_shares.resize(operation.actual_output_shares.size(), F(0));
    for (size_t i = 0; i < operation.actual_output_shares.size(); ++i)
        operation.residual_shares[i] =
            operation.actual_output_shares[i] - expected_shares[i];
    operations_.push_back(std::move(operation));
    completed = true;
    return true;
}

Digest ReferenceShamirAuditSession::ComputeRegistrationBinding() const {
    std::vector<u64> words = {
        SESSION_BIND_DOMAIN,
        session_id_,
        checkpoint_,
        static_cast<u64>(world_size_),
        static_cast<u64>(mpc_.threshold()),
        authenticated_transport_enabled() ? 1ULL : 0ULL,
        static_cast<u64>(operations_.size())};
    if (authenticated_transport_enabled()) {
        const Digest capability_binding =
            authenticated_transport_capability_binding();
        if (capability_binding == Digest{} ||
            authenticated_transport_transcript_binding_ == Digest{})
            return Digest{};
        append_digest(capability_binding, &words);
        append_digest(authenticated_transport_transcript_binding_, &words);
    }
    for (const auto& operation : operations_) {
        words.push_back(operation.owner);
        words.push_back(operation.ref.object_id);
        words.push_back(static_cast<u64>(operation.residual_shares.size()));
        append_digest(hash_field_vector({operation.public_challenge}), &words);
        append_digest(operation.public_state_digest, &words);
        append_digest(operation.public_actual_digest, &words);
        append_digest(operation.operation_statement_binding, &words);
        append_digest(operation.vss_transcript_binding, &words);
        append_digest(
            operation.registration_consistency_proof.proof_commitment,
            &words);
    }
    return hash_words(words);
}

bool ReferenceShamirAuditSession::ReadRegisteredPublicConsistencyStatement(
    const OperationRef& ref,
    RegistrationConsistencyStatement* out) const {
    if (!out || registration_failed_ || sealed_ ||
        !registration_consistency_backend_) return false;
    for (const auto& op : operations_) {
        if (!(op.ref == ref)) continue;
        const auto& stmt = op.registration_consistency_statement;
        if (stmt.ref != ref ||
            stmt.sid != session_id_ ||
            stmt.checkpoint != checkpoint_ ||
            stmt.public_state_digest != op.public_state_digest ||
            stmt.public_actual_digest != op.public_actual_digest ||
            stmt.sharing_transcript_binding != op.vss_transcript_binding ||
            stmt.operation_statement_binding !=
                op.operation_statement_binding ||
            !validate_registration_consistency_statement(stmt))
            return false;
        *out = stmt;
        return true;
    }
    return false;
}

bool ReferenceShamirAuditSession::ContainsOperationBinding(
    const OperationRef& ref,
    const Digest& operation_statement_binding,
    const Digest& public_state_digest,
    const Digest& public_actual_digest) const {
    if (!sealed_ || registration_failed_ || ref.object_id == 0 ||
        operation_statement_binding == Digest{} ||
        public_state_digest == Digest{} || public_actual_digest == Digest{})
        return false;
    for (const auto& operation : operations_) {
        if (operation.ref != ref) continue;
        return operation.owner == ref.owner &&
            operation.operation_statement_binding ==
                operation_statement_binding &&
            operation.public_state_digest == public_state_digest &&
            operation.public_actual_digest == public_actual_digest;
    }
    return false;
}

void ReferenceShamirAuditSession::AbortRegistrationBeforeSeal() {
    if (!sealed_) registration_failed_ = true;
}

bool ReferenceShamirAuditSession::SealRegistration() {
    if (registration_failed_) return false;
    // A failed seal invalidates the transaction, including any previously
    // verified operations. Never allow a retry with a different proof set.
    bool completed = false;
    struct FailureGuard {
        bool& failed;
        bool& completed;
        ~FailureGuard() { if (!completed) failed = true; }
    } failure_guard{registration_failed_, completed};
    if (sealed_ || !mpc_.valid() || operations_.empty()) return false;
    const Digest local_binding = ComputeRegistrationBinding();
    if (local_binding == Digest{} ||
        !CollectiveSameDigest(local_binding, AUDIT_AUTH_KIND_SEAL_BINDING, 0))
        return false;
    Digest registration_consistency_binding{};
    if (registration_consistency_backend_) {
        const auto capabilities = registration_consistency_backend_->Capabilities();
        const bool ready =
            production_ready_registration_consistency_capabilities(capabilities) ||
            (permit_reference_registration_test_only_ &&
             capabilities.reference_test_only &&
             validate_registration_consistency_capabilities(capabilities) &&
             capabilities.malicious_sound && capabilities.zero_knowledge &&
             capabilities.binds_sharing_transcript);
        if (!CollectiveAllTrue(ready, AUDIT_AUTH_KIND_SEAL_REG_CAP, 0) ||
            !CollectiveSameDigest(capabilities.capability_binding,
                AUDIT_AUTH_KIND_SEAL_REG_CAP, 1))
            return false;
        std::vector<RegistrationConsistencyProofArtifact> proofs;
        proofs.reserve(operations_.size());
        // Every party RE-verifies the same registered proof against the
        // stored VSS/native statement immediately before checkpoint seal.
        // A backend changing state between PROVED and SEALED fails globally.
        for (const auto& operation : operations_) {
            const auto& stmt = operation.registration_consistency_statement;
            const auto& proof = operation.registration_consistency_proof;
            const bool local_verified =
                stmt.sid == session_id_ &&
                stmt.checkpoint == checkpoint_ &&
                stmt.ref == operation.ref &&
                stmt.ref.owner == operation.owner &&
                stmt.public_state_digest == operation.public_state_digest &&
                stmt.public_actual_digest == operation.public_actual_digest &&
                stmt.sharing_transcript_binding == operation.vss_transcript_binding &&
                stmt.operation_statement_binding == operation.operation_statement_binding &&
                validate_registration_consistency_statement(stmt) &&
                validate_registration_consistency_proof_artifact(stmt, proof) &&
                registration_consistency_backend_->Verify(stmt, proof);
            if (!CollectiveAllTrue(local_verified,
                    AUDIT_AUTH_KIND_SEAL_REG_PROOF,
                    operation.ref.object_id))
                return false;
            proofs.push_back(proof);
        }
        registration_consistency_binding =
            compute_registration_consistency_set_binding(proofs);
        if (registration_consistency_binding == Digest{} ||
            !CollectiveSameDigest(registration_consistency_binding,
                AUDIT_AUTH_KIND_REG_SET, 0))
            return false;
    }
    registration_binding_ = local_binding;
    registration_consistency_binding_ = registration_consistency_binding;
    sealed_ = true;
    completed = true;
    return true;
}

F ReferenceShamirAuditSession::DeriveCoefficient(
    const Digest& joint_seed, const OperationRef& ref,
    size_t coordinate) const {
    std::vector<u64> words = {
        COEFFICIENT_DOMAIN,
        session_id_, checkpoint_, ref.owner, ref.object_id,
        static_cast<u64>(coordinate)};
    append_digest(registration_binding_, &words);
    append_digest(joint_seed, &words);
    return digest_to_field(hash_words(words));
}

bool ReferenceShamirAuditSession::BuildFingerprintProvenance(
    const Digest& joint_seed, const F& fingerprint_share,
    ReferenceLinearSharingProvenance* provenance) const {
    if (!provenance || joint_seed == Digest{} || operations_.empty() ||
        !vss_.valid())
        return false;
    std::vector<ReferenceLinearSharingSource> sources;
    sources.reserve(operations_.size());
    for (const auto& operation : operations_) {
        const size_t state_count = operation.state_shares.size();
        const size_t output_count = operation.actual_output_shares.size();
        if (state_count < 2 || state_count % 2 != 0 ||
            output_count != state_count / 2 ||
            operation.vss_transcript_binding == Digest{} ||
            !validate_reference_vss_local_witness(
                operation.vss_local_witness) ||
            operation.vss_local_witness.transcript_binding !=
                operation.vss_transcript_binding ||
            operation.vss_local_witness.element_count !=
                state_count + output_count)
            return false;

        unsigned log_n = 0;
        size_t power = 1;
        while (power < state_count) {
            power <<= 1;
            ++log_n;
        }
        if (power != state_count) return false;
        const F two_inv = F(2).inv();
        F omega = getRootOfUnity(static_cast<int>(log_n));
        omega = omega.inv();
        F inv_omega(1);
        std::vector<F> coefficients(
            state_count + output_count, F(0));
        for (size_t i = 0; i < output_count; ++i) {
            const F audit_coefficient =
                DeriveCoefficient(joint_seed, operation.ref, i);
            const F left_fold = two_inv * (
                (F(1) - operation.public_challenge) +
                operation.public_challenge * inv_omega);
            const F right_fold = two_inv * (
                (F(1) - operation.public_challenge) -
                operation.public_challenge * inv_omega);
            coefficients[i] += F(0) - audit_coefficient * left_fold;
            coefficients[i + output_count] +=
                F(0) - audit_coefficient * right_fold;
            coefficients[state_count + i] += audit_coefficient;
            inv_omega *= omega;
        }
        ReferenceLinearSharingSource source;
        source.sharing_binding = operation.vss_transcript_binding;
        source.element_coefficients = std::move(coefficients);
        source.local_witness = operation.vss_local_witness;
        sources.push_back(std::move(source));
    }
    if (!build_reference_linear_sharing_provenance(
            std::move(sources), provenance))
        return false;
    return provenance->local_share == fingerprint_share &&
        provenance->binding != Digest{};
}

ReferenceShamirBatchResult ReferenceShamirAuditSession::BatchCheck() const {
    ReferenceShamirBatchResult result;
    result.checkpoint = checkpoint_;
    result.operation_count = operations_.size();
    result.registration_binding = registration_binding_;
    if (!sealed_ || registration_binding_ == Digest{} || operations_.empty())
        return result;
    Digest joint_seed{};
    Digest public_coin_transcript_binding{};
    if (!mpc_.JointPublicSeed(
            &joint_seed, &public_coin_transcript_binding) ||
        public_coin_transcript_binding == Digest{})
        return result;
    result.public_coin_transcript_binding =
        public_coin_transcript_binding;
    if (!CollectiveSameDigest(
            public_coin_transcript_binding, AUDIT_AUTH_KIND_BATCH_COIN,
            BATCH_ZERO_MULTIPLICATION_ID))
        return result;
    std::vector<u64> challenge_words = {
        CHALLENGE_DOMAIN, session_id_, checkpoint_};
    append_digest(registration_binding_, &challenge_words);
    append_digest(public_coin_transcript_binding, &challenge_words);
    append_digest(joint_seed, &challenge_words);
    result.challenge_binding = hash_words(challenge_words);

    F fingerprint_share(0);
    for (const auto& operation : operations_) {
        for (size_t coordinate = 0;
             coordinate < operation.residual_shares.size(); ++coordinate) {
            const F coefficient = DeriveCoefficient(
                joint_seed, operation.ref, coordinate);
            fingerprint_share +=
                coefficient * operation.residual_shares[coordinate];
        }
    }

    const u64 local_strong_mode =
        multiplication_consistency_backend_ ? 1ULL : 0ULL;
    u64 agreed_strong_mode = 0;
    if (!CollectiveSameWord(
            local_strong_mode, AUDIT_AUTH_KIND_BATCH_STRONG_MODE,
            BATCH_ZERO_MULTIPLICATION_ID, &agreed_strong_mode) ||
        agreed_strong_mode > 1)
        return result;

    bool is_zero = false;
    Digest opening_transcript_binding{};
    if (agreed_strong_mode != 0) {
        ReferenceLinearSharingProvenance fingerprint_provenance;
        if (!BuildFingerprintProvenance(
                joint_seed, fingerprint_share, &fingerprint_provenance) ||
            !CollectiveSameDigest(
                fingerprint_provenance.binding,
                AUDIT_AUTH_KIND_BATCH_PROVENANCE,
                BATCH_ZERO_MULTIPLICATION_ID))
            return result;
        ReferenceMaskedZeroConsistencyContext zero_context;
        zero_context.sid = session_id_;
        zero_context.checkpoint = checkpoint_;
        zero_context.multiplication_id = BATCH_ZERO_MULTIPLICATION_ID;
        zero_context.context_binding = result.challenge_binding;
        Digest multiplication_consistency_binding{};
        if (!mpc_.MaskedZeroTestWithConsistency(
                fingerprint_provenance, zero_context,
                &is_zero, &opening_transcript_binding,
                &multiplication_consistency_binding) ||
            opening_transcript_binding == Digest{} ||
            multiplication_consistency_binding == Digest{})
            return result;
        result.multiplication_consistency_binding =
            multiplication_consistency_binding;
        if (!CollectiveSameDigest(
                multiplication_consistency_binding,
                AUDIT_AUTH_KIND_BATCH_MUL_BINDING,
                BATCH_ZERO_MULTIPLICATION_ID))
            return result;
    } else {
        if (!mpc_.MaskedZeroTest(
                fingerprint_share, &is_zero, &opening_transcript_binding) ||
            opening_transcript_binding == Digest{})
            return result;
    }
    result.opening_transcript_binding = opening_transcript_binding;
    if (!CollectiveSameDigest(
            opening_transcript_binding, AUDIT_AUTH_KIND_BATCH_OPEN_BINDING,
            BATCH_ZERO_MULTIPLICATION_ID))
        return result;
    result.available = true;
    result.clean = is_zero;
    return result;
}

ReferenceShamirSubsetResult ReferenceShamirAuditSession::BatchCheckSubset(
    const std::vector<OperationRef>& requested_operations,
    const Digest& domain_binding, uint64_t round_tag) const {
    ReferenceShamirSubsetResult result;
    result.checkpoint = checkpoint_;
    result.registration_binding = registration_binding_;
    if (!sealed_ || registration_binding_ == Digest{} ||
        requested_operations.empty() || domain_binding == Digest{} ||
        round_tag == 0)
        return result;

    std::vector<OperationRef> refs = requested_operations;
    std::sort(refs.begin(), refs.end(),
        [](const OperationRef& lhs, const OperationRef& rhs) {
            if (lhs.owner != rhs.owner) return lhs.owner < rhs.owner;
            return lhs.object_id < rhs.object_id;
        });
    if (std::adjacent_find(refs.begin(), refs.end()) != refs.end())
        return result;

    std::vector<const FoldOperationShares*> selected;
    selected.reserve(refs.size());
    for (const OperationRef& ref : refs) {
        const FoldOperationShares* found = nullptr;
        for (const auto& operation : operations_) {
            if (operation.ref == ref) {
                found = &operation;
                break;
            }
        }
        if (!found || found->residual_shares.empty()) return result;
        selected.push_back(found);
    }
    result.operation_count = selected.size();

    std::vector<u64> subset_words = {
        SUBSET_CHALLENGE_DOMAIN, session_id_, checkpoint_, round_tag,
        static_cast<u64>(refs.size())};
    append_digest(registration_binding_, &subset_words);
    append_digest(domain_binding, &subset_words);
    for (const OperationRef& ref : refs) {
        subset_words.push_back(ref.owner);
        subset_words.push_back(ref.object_id);
    }
    result.subset_binding = hash_words(subset_words);
    if (result.subset_binding == Digest{} ||
        !CollectiveSameDigest(
            result.subset_binding, AUDIT_AUTH_KIND_SUBSET_DOMAIN, round_tag))
        return result;

    Digest joint_seed{};
    Digest public_coin_transcript_binding{};
    if (!mpc_.JointPublicSeed(&joint_seed, &public_coin_transcript_binding) ||
        joint_seed == Digest{} || public_coin_transcript_binding == Digest{} ||
        !CollectiveSameDigest(
            public_coin_transcript_binding,
            AUDIT_AUTH_KIND_SUBSET_COIN, round_tag))
        return result;
    result.public_coin_transcript_binding = public_coin_transcript_binding;

    std::vector<u64> challenge_words = {
        SUBSET_CHALLENGE_DOMAIN, session_id_, checkpoint_, round_tag};
    append_digest(registration_binding_, &challenge_words);
    append_digest(domain_binding, &challenge_words);
    append_digest(result.subset_binding, &challenge_words);
    append_digest(public_coin_transcript_binding, &challenge_words);
    append_digest(joint_seed, &challenge_words);
    result.challenge_binding = hash_words(challenge_words);
    if (result.challenge_binding == Digest{}) return result;

    F fingerprint_share(0);
    for (const FoldOperationShares* operation : selected) {
        for (size_t coordinate = 0;
             coordinate < operation->residual_shares.size(); ++coordinate) {
            std::vector<u64> coefficient_words = {
                SUBSET_COEFFICIENT_DOMAIN, session_id_, checkpoint_, round_tag,
                operation->ref.owner, operation->ref.object_id,
                static_cast<u64>(coordinate)};
            append_digest(registration_binding_, &coefficient_words);
            append_digest(domain_binding, &coefficient_words);
            append_digest(result.subset_binding, &coefficient_words);
            append_digest(joint_seed, &coefficient_words);
            const F coefficient = digest_to_field(hash_words(coefficient_words));
            fingerprint_share += coefficient *
                operation->residual_shares[coordinate];
        }
    }

    bool is_zero = false;
    Digest opening_transcript_binding{};
    if (!mpc_.MaskedZeroTest(
            fingerprint_share, &is_zero, &opening_transcript_binding) ||
        opening_transcript_binding == Digest{} ||
        !CollectiveSameDigest(
            opening_transcript_binding,
            AUDIT_AUTH_KIND_SUBSET_OPEN, round_tag))
        return result;
    result.opening_transcript_binding = opening_transcript_binding;
    result.available = true;
    result.clean = is_zero;
    return result;
}

bool ReferenceShamirAuditSession::SelectAuditWitness(
    const OperationRef& ref,
    ReferenceShamirSelectedAuditWitness* witness) const {
    if (!witness || !sealed_) return false;
    *witness = ReferenceShamirSelectedAuditWitness{};
    for (const auto& operation : operations_) {
        if (operation.ref != ref) continue;
        if (operation.state_shares.empty() ||
            operation.actual_output_shares.empty())
            return false;
        if (operation.vss_transcript_binding != Digest{} &&
            (!validate_reference_vss_local_witness(
                 operation.vss_local_witness) ||
             operation.vss_local_witness.transcript_binding !=
                 operation.vss_transcript_binding ||
             !operation.vss_receipt.available ||
             !operation.vss_receipt.consistent ||
             operation.vss_receipt.transcript_binding !=
                 operation.vss_transcript_binding ||
             operation.vss_receipt.local_row_commitment !=
                 operation.vss_local_witness.local_row_commitment))
            return false;
        witness->available = true;
        witness->ref = ref;
        witness->state_shares = operation.state_shares;
        witness->actual_output_shares = operation.actual_output_shares;
        witness->registration_vss_witness = operation.vss_local_witness;
        witness->registration_vss_receipt = operation.vss_receipt;
        return true;
    }
    return false;
}

namespace {
// Execute the real SP1 guest against this run's PRIVATE test vector, not a
// historical proof. The test owner is the only rank given that file. The
// executable paths are configured explicitly; no shell or public witness
// serialization is used by this verifier process.
extern "C" char** environ;
bool RunReferenceSp1Process(
    const std::vector<std::string>& arguments, int timeout_seconds) {
    if (arguments.empty() || timeout_seconds < 1) return false;
    struct stat st{};
    if (::lstat(arguments[0].c_str(), &st) != 0 ||
        !S_ISREG(st.st_mode)) return false;
    // The child sees the same MPI environment but does not use MPI.
    // Redirect both streams to avoid exposing private-vector paths in
    // diagnostic output from the SP1 SDK.
    posix_spawn_file_actions_t actions;
    if (::posix_spawn_file_actions_init(&actions) != 0) return false;
    const int quiet = ::open("/dev/null", O_WRONLY | O_CLOEXEC);
    bool actions_ready = quiet >= 0 &&
        ::posix_spawn_file_actions_adddup2(
            &actions, quiet, STDOUT_FILENO) == 0 &&
        ::posix_spawn_file_actions_adddup2(
            &actions, quiet, STDERR_FILENO) == 0;
    pid_t pid = -1;
    int spawned = -1;
    if (actions_ready) {
        std::vector<char*> argv;
        argv.reserve(arguments.size() + 1);
        for (const auto& word : arguments)
            argv.push_back(const_cast<char*>(word.c_str()));
        argv.push_back(nullptr);
        spawned = ::posix_spawn(
            &pid, arguments[0].c_str(), &actions, nullptr,
            argv.data(), ::environ);
    }
    ::posix_spawn_file_actions_destroy(&actions);
    if (quiet >= 0) ::close(quiet);
    if (spawned != 0 || pid <= 0) return false;
    int status = 0;
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::seconds(timeout_seconds);
    while (true) {
        const pid_t done = ::waitpid(pid, &status, WNOHANG);
        if (done == pid) return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        if (done < 0) return false;
        if (std::chrono::steady_clock::now() >= deadline) {
            ::kill(pid, SIGKILL);
            ::waitpid(pid, &status, 0);
            return false;
        }
        ::usleep(50000);
    }
}

bool RunReferenceSp1GuestOnPrivateVector(
    const std::string& executable, const std::string& elf,
    const std::string& private_path) {
    struct stat st{};
    return !elf.empty() && !private_path.empty() &&
        ::lstat(elf.c_str(), &st) == 0 && S_ISREG(st.st_mode) &&
        ::lstat(private_path.c_str(), &st) == 0 && S_ISREG(st.st_mode) &&
        (st.st_mode & 0077) == 0 &&
        RunReferenceSp1Process(
            {executable, "execute", elf, "--input", private_path}, 40);
}

// A public expected statement is generated from the CURRENT checkpoint's
// C++ registration statement, NOT copied from the prover's bundle.
bool WriteReferenceSp1ExpectedStatement(
    const std::string& filename,
    const RegistrationConsistencyStatement& statement) {
    auto words = encode_registration_consistency_statement_words(statement);
    if (words.size() != 46) return false;
    std::ostringstream out;
    out << "[";
    for (size_t i = 0; i < words.size(); ++i) {
        if (i) out << ",";
        out << words[i];
    }
    out << "]\n";
    const std::string json = out.str();
    const int fd = ::open(filename.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    size_t offset = 0;
    bool ok = true;
    while (offset < json.size()) {
        const ssize_t n = ::write(
            fd, json.data() + offset, json.size() - offset);
        if (n <= 0) { ok = false; break; }
        offset += static_cast<size_t>(n);
    }
    if (ok) ok = ::fsync(fd) == 0;
    if (::close(fd) != 0) ok = false;
    if (!ok) ::unlink(filename.c_str());
    return ok;
}

bool RunReferenceSp1Groth16ForCurrentRegistration(
    const std::string& host, const std::string& elf,
    const std::string& private_file, const std::string& proof_directory,
    const std::string& pinned_elf_blake3,
    const std::string& pinned_verifying_key,
    const RegistrationConsistencyStatement& statement) {
    if (host.empty() || elf.empty() || private_file.empty() ||
        proof_directory.empty() ||
        pinned_elf_blake3.size() != 64 ||
        pinned_verifying_key.size() != 66 ||
        pinned_verifying_key.substr(0, 2) != "0x")
        return false;
    struct stat st{};
    if (::lstat(elf.c_str(), &st) != 0 || !S_ISREG(st.st_mode) ||
        ::lstat(private_file.c_str(), &st) != 0 ||
        !S_ISREG(st.st_mode) || (st.st_mode & 0077) != 0 ||
        ::lstat(proof_directory.c_str(), &st) == 0)
        return false;
    const std::string expected = proof_directory + ".expected-public.json";
    if (!WriteReferenceSp1ExpectedStatement(expected, statement))
        return false;
    if (!RunReferenceSp1Process({
            host, "prove", elf, proof_directory, "--proof-mode", "groth16",
            "--input", private_file}, 1200))
        return false;
    return RunReferenceSp1Process({
        host, "verify", elf, proof_directory, "--proof-mode", "groth16",
        "--expected-statement", expected,
        "--expected-elf-blake3", pinned_elf_blake3,
        "--expected-vkey-hash", pinned_verifying_key}, 120);
}

// Synthetic wiring backend used only by this translation unit's self-test.
// It deliberately does not model a real ZK proof system and is never exposed
// through a runtime constructor. Its sole purpose is to exercise the generic
// registration-consistency proof plumbing end to end.
class SelfTestRegistrationConsistencyBackend final
    : public RegistrationConsistencyProofBackend {
public:
    size_t prove_calls() const { return prove_calls_; }
    void SetForcedProofFailure(bool value) { force_proof_failure_ = value; }
    void SetForcedVerificationFailure(bool value) {
        force_verification_failure_ = value;
    }
    void SetPrivateTestVectorOutput(std::string path) {
        private_export_path_ = std::move(path);
    }
    void SetRequiredSp1GuestExecution(
        std::string executable, std::string elf) {
        required_sp1_executable_ = std::move(executable);
        required_sp1_elf_ = std::move(elf);
    }
    void SetRequiredSp1Groth16Proof(
        std::string proof_directory, std::string pinned_elf_blake3,
        std::string pinned_vkey) {
        required_sp1_proof_directory_ = std::move(proof_directory);
        required_sp1_elf_digest_ = std::move(pinned_elf_blake3);
        required_sp1_vkey_ = std::move(pinned_vkey);
    }
    bool sp1_groth16_attempted() const { return groth16_attempted_; }
    bool sp1_groth16_accepted() const { return groth16_accepted_; }
    bool sp1_execution_attempted() const { return sp1_attempted_; }
    bool sp1_execution_accepted() const { return sp1_accepted_; }
    RegistrationConsistencyCapabilities Capabilities() const override {
        RegistrationConsistencyCapabilities capabilities;
        capabilities.available = true;
        capabilities.malicious_sound = true;
        capabilities.zero_knowledge = true;
        capabilities.binds_sharing_transcript = true;
        capabilities.reference_test_only = true;
        capabilities.protocol_id = 0x5245475445535450ULL; // REGTESTP
        capabilities.implementation_binding =
            hash_words({0x5245475445535449ULL}); // REGTESTI
        capabilities.capability_binding =
            compute_registration_consistency_capability_binding(capabilities);
        return capabilities;
    }

    RegistrationConsistencyProofArtifact Prove(
        const RegistrationConsistencyStatement& statement,
        const RegistrationConsistencyWitness& witness) const override {
        ++prove_calls_;
        RegistrationConsistencyProofArtifact proof;
        // Negative-only fault injection used to test fail-closed
        // publication. Never assert cryptographic validity on failure.
        if (force_proof_failure_) return proof;
        if (!validate_registration_consistency_statement(statement) ||
            hash_field_vector(witness.state_values) !=
                statement.public_state_digest ||
            hash_field_vector(witness.actual_output) !=
                statement.public_actual_digest)
            return proof;
        // Only this synthetic selftest backend can opt in to writing
        // a PRIVATE real-MPI VSS dealer witness for offline SP1 experiments.
        // The generic/native runtime does not read this environment flag.
        if (!private_export_path_.empty() &&
            !write_registration_private_test_vector_once(
                private_export_path_, statement, witness))
            return proof;
        if (!required_sp1_executable_.empty()) {
            // Fail CLOSED before even constructing the synthetic proof.
            // This is only a real SP1 Guest execution check, NOT an SP1
            // Groth16 proof verifier or a production attestation.
            sp1_attempted_ = true;
            sp1_accepted_ = RunReferenceSp1GuestOnPrivateVector(
                required_sp1_executable_, required_sp1_elf_,
                private_export_path_);
            if (!sp1_accepted_) return proof;
        }
        if (!required_sp1_proof_directory_.empty()) {
            groth16_attempted_ = true;
            groth16_accepted_ =
                sp1_accepted_ && RunReferenceSp1Groth16ForCurrentRegistration(
                    required_sp1_executable_, required_sp1_elf_,
                    private_export_path_, required_sp1_proof_directory_,
                    required_sp1_elf_digest_, required_sp1_vkey_, statement);
            if (!groth16_accepted_) return proof;
        }
        proof.available = true;
        proof.cryptographically_authenticated = true;
        proof.zero_knowledge = true;
        proof.proof_system_id = 0x52454754U; // REGT
        proof.statement_binding = statement.statement_binding;
        proof.transcript_binding = Transcript(statement);
        proof.proof_words = {
            0x5245475445535457ULL,
            static_cast<u64>(statement.state_element_count),
            static_cast<u64>(statement.output_element_count)};
        proof.proof_commitment =
            compute_registration_consistency_proof_commitment(proof);
        return proof;
    }


    bool Verify(
        const RegistrationConsistencyStatement& statement,
        const RegistrationConsistencyProofArtifact& proof) const override {
        if (force_verification_failure_) return false;
        if (!validate_registration_consistency_proof_artifact(statement, proof))
            return false;
        const std::vector<u64> expected_words = {
            0x5245475445535457ULL,
            static_cast<u64>(statement.state_element_count),
            static_cast<u64>(statement.output_element_count)};
        return proof.proof_words == expected_words &&
               proof.transcript_binding == Transcript(statement);
    }

private:
    bool force_proof_failure_ = false;
    bool force_verification_failure_ = false;
    mutable bool sp1_attempted_ = false;
    mutable bool sp1_accepted_ = false;
    mutable bool groth16_attempted_ = false;
    mutable bool groth16_accepted_ = false;
    std::string private_export_path_;
    std::string required_sp1_executable_;
    std::string required_sp1_elf_;
    std::string required_sp1_proof_directory_;
    std::string required_sp1_elf_digest_;
    std::string required_sp1_vkey_;
    mutable size_t prove_calls_ = 0;
    mutable size_t relation_reference_count_ = 0;
    mutable size_t vss_local_prove_count_ = 0;
    mutable size_t linear_prove_count_ = 0;

    static Digest Transcript(
        const RegistrationConsistencyStatement& statement) {
        std::vector<u64> words = {
            0x5245475445535454ULL, statement.sid, statement.checkpoint,
            statement.ref.owner, statement.ref.object_id};
        append_digest(statement.statement_binding, &words);
        append_digest(statement.sharing_transcript_binding, &words);
        return hash_words(words);
    }
 };

// Test-only Ed25519 quorum: its pin is from this test's ephemeral
// MPI key registry and it does not authenticate native secret shares.
class SelfTestEd25519OriginApprovalBackend final
    : public RegistrationOriginApprovalBackend {
public:
    explicit SelfTestEd25519OriginApprovalBackend(
        bool reject_signature = false,
        bool require_external_anchor = false,
        bool reject_paired_receipt_signature = false,
        bool require_consumed_snapshot = false,
        bool require_native_issuer_receipt = false)
        : reject_signature_(reject_signature),
          require_external_anchor_(require_external_anchor),
          reject_paired_receipt_signature_(
              reject_paired_receipt_signature),
          require_consumed_snapshot_(require_consumed_snapshot),
          require_native_issuer_receipt_(require_native_issuer_receipt) {}
    void BindReplayLedger(const RegistrationReceiptReplayLedger* ledger) {
        ledger_ = ledger;
    }
    // The exporter is inaccessible until the whole MPI session
    // reports a *verified registration proof + sealed clean batch*.
    // This test-only latch is set ONLY after the actual BatchCheck.
    void AuthorizePostProofExport(bool verified_clean_batch) {
        proof_release_authorized_ =
            verified_clean_batch && paired_evidence_ready_;
    }
    bool ExportApprovedPublicBundle(
        const std::string& new_public_path) const {
        return proof_release_authorized_ && paired_evidence_ready_ &&
            !new_public_path.empty() &&
            verify_registration_origin_evidence_pair(
                approved_public_bundle_.statement,
                approved_public_bundle_.signatures,
                approved_public_bundle_.public_keys,
                approved_registry_pin_,
                approved_public_bundle_.public_keys.size() -
                    (approved_public_bundle_.public_keys.size() - 1) / 3,
                true) &&
            write_registration_public_origin_bundle(
                new_public_path, approved_public_bundle_);
    }
    bool ExportApprovedNativeIssuerReceipt(
        const std::string& public_file) const {
        return proof_release_authorized_ && paired_evidence_ready_ &&
            issuer_release_ready_ && consumed_snapshot_ &&
            require_native_issuer_receipt_ && !public_file.empty() &&
            verify_registration_native_execution_receipt(
                approved_public_bundle_.statement,
                *consumed_snapshot_, issuer_receipt_,
                pinned_issuer_key_, expected_issuer_id_,
                minimum_issuer_sequence_) &&
            verify_registration_native_issuer_release_evidence(
                approved_public_bundle_.statement, issuer_release_evidence_,
                consumed_snapshot_->consumed_record_binding,
                pinned_issuer_key_, expected_issuer_id_,
                minimum_issuer_sequence_) &&
            write_registration_native_issuer_release_file(
                public_file, issuer_release_evidence_);
    }
    std::array<uint8_t, 32> ApprovedNativeIssuerKey() const {
        return paired_evidence_ready_ && proof_release_authorized_
            ? pinned_issuer_key_ : std::array<uint8_t,32>{};
    }
    Digest ApprovedNativeConsumedBinding() const {
        return paired_evidence_ready_ && proof_release_authorized_
            ? issuer_receipt_.consumed_record_binding : Digest{};
    }
    u64 ApprovedNativeIssuerId() const {
        return paired_evidence_ready_ && proof_release_authorized_
            ? expected_issuer_id_ : 0;
    }
    u64 ApprovedNativeIssuerSequence() const {
        return paired_evidence_ready_ && proof_release_authorized_
            ? issuer_receipt_.sequence : 0;
    }
    Digest ApprovedStatementBinding() const {
        return paired_evidence_ready_
            ? approved_public_bundle_.statement.statement_binding
            : Digest{};
    }
    Digest ApprovedRegistryPin() const {
        return paired_evidence_ready_ ? approved_registry_pin_ : Digest{};
    }
    void BindPreVssReceipt(const RegistrationPreVssReceipt& receipt) {
        receipt_ = receipt;
        has_receipt_ = true;
    }
    void BindLocalRecords(const PrivateStateMaterialStore* states,
                          const PrivateAuditMaterialStore* operations,
                          const AuditCheckpointView* checkpoint) {
        states_ = states;
        operations_ = operations;
        checkpoint_ = checkpoint;
    }
    void BindConsumedSnapshot(
        const RegistrationNativeConsumedSnapshot* snapshot) {
        consumed_snapshot_ = snapshot;
    }
    // Test-only source of the SAME issuer's private key, kept in the
    // opt-in MPI fixture scope. Production providers sign externally.
    void BindTestIssuerFinalSigningKey(EVP_PKEY* borrowed_key) {
        fixture_release_signing_key_ = borrowed_key;
    }
    void BindNativeIssuerReceipt(
        const RegistrationNativeExecutionReceipt& receipt,
        const std::array<uint8_t, 32>& independently_pinned_public_key,
        u64 expected_issuer_id, u64 minimum_sequence) {
        issuer_receipt_ = receipt;
        pinned_issuer_key_ = independently_pinned_public_key;
        expected_issuer_id_ = expected_issuer_id;
        minimum_issuer_sequence_ = minimum_sequence;
        has_issuer_receipt_ = true;
    }
    bool CheckOwnerNativeInputBeforeVss(
        const RegistrationConsistencyStatement& proposed_statement,
        const std::vector<F>& owner_private_state,
        const std::vector<F>& owner_actual_output,
        const F& public_challenge) const override {
        if (!states_ || !operations_ || !checkpoint_) return false;
        RegistrationNativeConsumedSnapshot current;
        return read_registration_native_consumed_snapshot(
                   proposed_statement, *states_, *operations_,
                   *checkpoint_, &current) &&
            current.state_values == owner_private_state &&
            current.actual_output == owner_actual_output &&
            current.public_challenge == public_challenge &&
            (!require_consumed_snapshot_ ||
                (consumed_snapshot_ &&
                 current.consumed_record_binding ==
                     consumed_snapshot_->consumed_record_binding &&
                 current.pre_vss_claim_binding ==
                     consumed_snapshot_->pre_vss_claim_binding &&
                 current.state_values == consumed_snapshot_->state_values &&
                 current.actual_output == consumed_snapshot_->actual_output &&
                 current.public_challenge ==
                     consumed_snapshot_->public_challenge)) &&
            (!require_native_issuer_receipt_ ||
                (has_issuer_receipt_ &&
                 verify_registration_native_execution_receipt(
                     proposed_statement, current, issuer_receipt_,
                     pinned_issuer_key_, expected_issuer_id_,
                     minimum_issuer_sequence_)));
    }
    bool CheckLocalNativeOrigin(
        const RegistrationConsistencyStatement& statement) const override {
        auto& auth = Ed25519TransferAuthenticator::instance();
        return states_ && operations_ && checkpoint_ && has_receipt_ &&
            auth.ready() && auth.rank() >= 0 &&
            (!require_external_anchor_ ||
                (auth.ExternalRegistryAnchorVerified() &&
                 auth.ExternalRegistryAnchor() == auth.RegistryCommitment())) &&
            verify_registration_local_native_record(
                statement, *states_, *operations_, *checkpoint_) &&
            (!require_consumed_snapshot_ ||
                (consumed_snapshot_ &&
                 registration_native_consumed_snapshot_still_matches(
                     statement, *states_, *operations_,
                     *checkpoint_, *consumed_snapshot_))) &&
            (!require_native_issuer_receipt_ ||
                (has_issuer_receipt_ && consumed_snapshot_ &&
                 verify_registration_native_execution_receipt(
                     statement, *consumed_snapshot_, issuer_receipt_,
                     pinned_issuer_key_, expected_issuer_id_,
                     minimum_issuer_sequence_))) &&
            verify_registration_pre_vss_receipt(
                statement, receipt_, auth.PublicKeys(),
                auth.RegistryCommitment(), static_cast<uint32_t>(auth.rank()));
    }
    bool ApprovePublicOrigin(
        const RegistrationConsistencyStatement& statement) const override {
        // Do not permit an earlier successful operation's signatures
        // to be exported after a later failed or mutated approval.
        paired_evidence_ready_ = false;
        proof_release_authorized_ = false;
        issuer_release_ready_ = false;
        issuer_release_evidence_ = RegistrationNativeIssuerReleaseEvidence{};
        approved_public_bundle_ = RegistrationPublicOriginBundle{};
        approved_registry_pin_ = Digest{};
        auto& auth = Ed25519TransferAuthenticator::instance();
        const auto keys = auth.PublicKeys();
        const Digest pin = auth.RegistryCommitment();
        if (!auth.ready() || keys.size() < 4) return false;
        const std::vector<u64> message =
            registration_origin_endorsement_message(statement);
        std::array<uint8_t, 64> signature{};
        const int local_ready =
            CheckLocalNativeOrigin(statement) && message.size() == 46 &&
            auth.SignWords(REGISTRATION_ORIGIN_ENDORSEMENT_DOMAIN,
                           message, &signature) ? 1 : 0;
        int globally_ready = 0;
        MPI_Allreduce(&local_ready, &globally_ready, 1, MPI_INT,
                      MPI_MIN, MPI_COMM_WORLD);
        if (!globally_ready) return false;
        const int n = static_cast<int>(keys.size());
        std::vector<uint8_t> signatures(static_cast<size_t>(n) * 64);
        MPI_Allgather(signature.data(), 64, MPI_BYTE, signatures.data(),
                      64, MPI_BYTE, MPI_COMM_WORLD);
        std::vector<uint8_t> pre_vss_signatures(static_cast<size_t>(n) * 64);
        MPI_Allgather(receipt_.signature.data(), 64, MPI_BYTE,
                      pre_vss_signatures.data(), 64, MPI_BYTE,
                      MPI_COMM_WORLD);
        // Test-only mutation of public evidence after collection.
        if (reject_signature_) signatures[0] ^= 1;
        if (reject_paired_receipt_signature_) pre_vss_signatures[0] ^= 1;
        RegistrationOriginEvidencePair evidence;
        for (int signer = 0; signer < n; ++signer) {
            RegistrationOriginEndorsement final_entry;
            final_entry.signer = static_cast<uint32_t>(signer);
            std::copy_n(signatures.begin() + static_cast<size_t>(signer) * 64,
                        64, final_entry.signature.begin());
            evidence.final_endorsements.push_back(final_entry);
            RegistrationPreVssReceipt first_entry;
            first_entry.signer = static_cast<uint32_t>(signer);
            std::copy_n(
                pre_vss_signatures.begin() + static_cast<size_t>(signer) * 64,
                64, first_entry.signature.begin());
            evidence.pre_vss_receipts.push_back(first_entry);
        }
        // Public-only joint verification: a final-statement quorum is
        // invalid unless precisely the same set authenticated the
        // execution-scoped pre-VSS prefix. This is NOT native equality.
        const bool approved = verify_registration_origin_evidence_pair(
            statement, evidence, keys, pin,
            keys.size() - (keys.size() - 1) / 3, true);
        if (approved && require_native_issuer_receipt_) {
            if (!has_issuer_receipt_ || !fixture_release_signing_key_)
                return false;
            issuer_release_evidence_.source_receipt=issuer_receipt_;
            issuer_release_evidence_.final_statement_binding=
                statement.statement_binding;
            const auto final_message=
                registration_native_issuer_release_message(
                    statement,issuer_receipt_);
            using SignCtx=std::unique_ptr<EVP_MD_CTX,
                                          decltype(&EVP_MD_CTX_free)>;
            SignCtx ctx(EVP_MD_CTX_new(),EVP_MD_CTX_free);
            size_t signature_size=
                issuer_release_evidence_.final_signature.size();
            if (final_message.empty() || !ctx ||
                EVP_DigestSignInit(ctx.get(),nullptr,nullptr,nullptr,
                    fixture_release_signing_key_)!=1 ||
                EVP_DigestSign(ctx.get(),
                    issuer_release_evidence_.final_signature.data(),
                    &signature_size,final_message.data(),
                    final_message.size())!=1 ||
                signature_size!=issuer_release_evidence_.final_signature.size() ||
                !verify_registration_native_issuer_release_evidence(
                    statement,issuer_release_evidence_,
                    issuer_receipt_.consumed_record_binding,
                    pinned_issuer_key_,expected_issuer_id_,
                    minimum_issuer_sequence_))
                return false;
            issuer_release_ready_=true;
        }
        if (approved) {
            approved_public_bundle_.statement = statement;
            approved_public_bundle_.signatures = std::move(evidence);
            approved_public_bundle_.public_keys = keys;
            approved_registry_pin_ = pin;
            paired_evidence_ready_ = true;
        }
        return approved;
    }
    bool ConsumeApprovedOrigin(
        const RegistrationConsistencyStatement& statement) const override {
        auto& auth = Ed25519TransferAuthenticator::instance();
        return ledger_ && CheckLocalNativeOrigin(statement) &&
            auth.rank() >= 0 &&
            ledger_->ConsumeOnce(statement, static_cast<uint32_t>(auth.rank()));
    }
private:
    bool reject_signature_ = false;
    bool require_external_anchor_ = false;
    bool reject_paired_receipt_signature_ = false;
    bool require_consumed_snapshot_ = false;
    bool require_native_issuer_receipt_ = false;
    bool has_issuer_receipt_ = false;
    u64 expected_issuer_id_ = 0;
    u64 minimum_issuer_sequence_ = 0;
    RegistrationNativeExecutionReceipt issuer_receipt_{};
    mutable RegistrationNativeIssuerReleaseEvidence issuer_release_evidence_{};
    mutable bool issuer_release_ready_ = false;
    EVP_PKEY* fixture_release_signing_key_ = nullptr; // borrowed test-only
    std::array<uint8_t, 32> pinned_issuer_key_{};
    const RegistrationNativeConsumedSnapshot* consumed_snapshot_ = nullptr;
    mutable bool paired_evidence_ready_ = false;
    mutable bool proof_release_authorized_ = false;
    mutable RegistrationPublicOriginBundle approved_public_bundle_{};
    mutable Digest approved_registry_pin_{};
    const RegistrationReceiptReplayLedger* ledger_ = nullptr;
    bool has_receipt_ = false;
    RegistrationPreVssReceipt receipt_{};
    const PrivateStateMaterialStore* states_ = nullptr;
    const PrivateAuditMaterialStore* operations_ = nullptr;
    const AuditCheckpointView* checkpoint_ = nullptr;
};

// Synthetic multiplication-consistency backend for MPI wiring tests only.
// It checks the dealer-local witness before emitting a marker proof, but its
// public Verify routine is not a cryptographic ZK verifier. It is intentionally
// confined to this anonymous self-test namespace and never installed by the
// production/reference runtime adapter.
class SelfTestMultiplicationConsistencyBackend final
    : public MultiplicationConsistencyProofBackend {
public:
    size_t relation_reference_count() const {
        return relation_reference_count_;
    }
    size_t vss_local_prove_count() const {
        return vss_local_prove_count_;
    }
    size_t linear_prove_count() const {
        return linear_prove_count_;
    }

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

        const std::vector<uint64_t> statement_words =
            encode_multiplication_consistency_statement_abi(statement);
        const std::vector<uint64_t> witness_words =
            encode_multiplication_consistency_witness_abi(witness);
        if (statement_words.empty() || witness_words.empty() ||
            !pvia_mc_reference_validate_relation(
                statement_words.data(), statement_words.size(),
                witness_words.data(), witness_words.size()))
            return proof;

        MultiplicationConsistencySharingWitnessEnvelope lhs_envelope;
        MultiplicationConsistencySharingWitnessEnvelope rhs_envelope;
        if (!decode_multiplication_consistency_sharing_witness(
                witness.lhs_sharing_witness_words, &lhs_envelope) ||
            !decode_multiplication_consistency_sharing_witness(
                witness.rhs_sharing_witness_words, &rhs_envelope))
            return proof;

        const bool relation_vector_is_linear =
            lhs_envelope.kind ==
                MultiplicationConsistencySharingWitnessKind::
                    LINEAR_COMBINATION ||
            rhs_envelope.kind ==
                MultiplicationConsistencySharingWitnessKind::
                    LINEAR_COMBINATION;
        bool& relation_vector_written =
            relation_vector_is_linear
                ? exported_linear_vector_
                : exported_vss_vector_;
        const char* relation_vector_dir =
            std::getenv("PVIA_MC_PROVIDER_VECTOR_DIR");
        if (!relation_vector_written && relation_vector_dir &&
            relation_vector_dir[0] != 0) {
            int mpi_rank = 0;
            MPI_Comm_rank(MPI_COMM_WORLD, &mpi_rank);
            const std::string kind =
                relation_vector_is_linear ? "linear" : "vss_local";
            const std::string path =
                std::string(relation_vector_dir) +
                "/relation_" + kind + "_rank" +
                std::to_string(mpi_rank) + ".txt";
            std::ofstream out(path, std::ios::out | std::ios::trunc);
            if (out) {
                const auto relation_binding =
                    compute_multiplication_consistency_relation_binding();
                out << "PVIA_MC_PROVIDER_RELATION_VECTOR_V1\n";
                out << "abi_version="
                    << MULTIPLICATION_CONSISTENCY_PROVIDER_ABI_VERSION
                    << "\n";
                out << "kind=" << kind << "\n";
                out << "rank=" << mpi_rank << "\n";
                out << "dealer=" << statement.dealer << "\n";
                out << "relation_binding="
                    << relation_binding.hex() << "\n";
                const std::vector<u64> statement_digest_words(
                    statement_words.begin(), statement_words.end());
                const std::vector<u64> witness_digest_words(
                    witness_words.begin(), witness_words.end());
                out << "statement_digest="
                    << hash_words(statement_digest_words).hex() << "\n";
                out << "witness_digest="
                    << hash_words(witness_digest_words).hex() << "\n";
                out << "statement_word_count="
                    << statement_words.size() << "\n";
                out << "statement_words=";
                for (size_t i = 0; i < statement_words.size(); ++i) {
                    if (i != 0) out << ",";
                    out << statement_words[i];
                }
                out << "\n";
                out << "witness_word_count="
                    << witness_words.size() << "\n";
                out << "witness_words=";
                for (size_t i = 0; i < witness_words.size(); ++i) {
                    if (i != 0) out << ",";
                    out << witness_words[i];
                }
                out << "\n";
                relation_vector_written = true;
            }
        }

        // Optional self-test-only export of every local relation witness.
        // The ordinary exporter above remains one-per-kind for its legacy
        // 2*N vector check. This opt-in path uses a statement-derived suffix
        // so clean/faulty contexts and repeated operations never overwrite.
        const char* export_all_env =
            std::getenv("PVIA_MC_PROVIDER_VECTOR_EXPORT_ALL");
        if (export_all_env && export_all_env[0] == '1' &&
            export_all_env[1] == 0 &&
            relation_vector_dir && relation_vector_dir[0] != 0) {
            int export_all_rank = 0;
            MPI_Comm_rank(MPI_COMM_WORLD, &export_all_rank);
            const std::string export_all_kind =
                relation_vector_is_linear ? "linear" : "vss_local";
            const std::string export_all_statement_tag =
                statement.statement_binding.hex().substr(0, 16);
            const std::string export_all_path =
                std::string(relation_vector_dir) + "/relation_all_" +
                export_all_kind + "_rank" + std::to_string(export_all_rank) +
                "_id" + std::to_string(statement.multiplication_id) + "_" +
                export_all_statement_tag + ".txt";
            std::ofstream export_all_out(
                export_all_path, std::ios::out | std::ios::trunc);
            if (export_all_out) {
                const auto export_all_relation_binding =
                    compute_multiplication_consistency_relation_binding();
                const std::vector<u64> export_all_statement_digest_words(
                    statement_words.begin(), statement_words.end());
                const std::vector<u64> export_all_witness_digest_words(
                    witness_words.begin(), witness_words.end());
                export_all_out << "PVIA_MC_PROVIDER_RELATION_VECTOR_V1" << std::endl;
                export_all_out << "abi_version="
                    << MULTIPLICATION_CONSISTENCY_PROVIDER_ABI_VERSION << std::endl;
                export_all_out << "kind=" << export_all_kind << std::endl;
                export_all_out << "rank=" << export_all_rank << std::endl;
                export_all_out << "dealer=" << statement.dealer << std::endl;
                export_all_out << "relation_binding="
                    << export_all_relation_binding.hex() << std::endl;
                export_all_out << "statement_digest="
                    << hash_words(export_all_statement_digest_words).hex() << std::endl;
                export_all_out << "witness_digest="
                    << hash_words(export_all_witness_digest_words).hex() << std::endl;
                export_all_out << "statement_word_count="
                    << statement_words.size() << std::endl;
                export_all_out << "statement_words=";
                for (size_t i = 0; i < statement_words.size(); ++i) {
                    if (i != 0) export_all_out << ",";
                    export_all_out << statement_words[i];
                }
                export_all_out << std::endl;
                export_all_out << "witness_word_count="
                    << witness_words.size() << std::endl;
                export_all_out << "witness_words=";
                for (size_t i = 0; i < witness_words.size(); ++i) {
                    if (i != 0) export_all_out << ",";
                    export_all_out << witness_words[i];
                }
                export_all_out << std::endl;
            }
        }

        ++relation_reference_count_;
        if (lhs_envelope.kind ==
                MultiplicationConsistencySharingWitnessKind::VSS_LOCAL ||
            rhs_envelope.kind ==
                MultiplicationConsistencySharingWitnessKind::VSS_LOCAL)
            ++vss_local_prove_count_;
        if (lhs_envelope.kind ==
                MultiplicationConsistencySharingWitnessKind::LINEAR_COMBINATION ||
            rhs_envelope.kind ==
                MultiplicationConsistencySharingWitnessKind::LINEAR_COMBINATION)
            ++linear_prove_count_;

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
    mutable size_t relation_reference_count_ = 0;
    mutable size_t vss_local_prove_count_ = 0;
    mutable size_t linear_prove_count_ = 0;
    mutable bool exported_vss_vector_ = false;
    mutable bool exported_linear_vector_ = false;
    static Digest Transcript(
        const MultiplicationConsistencyStatement& statement) {
        std::vector<u64> words = {
            0x4d554c5445535454ULL,
            statement.sid, statement.checkpoint,
            statement.multiplication_id, statement.dealer};
        append_digest(statement.statement_binding, &words);
        append_digest(statement.output_sharing_binding, &words);
        return hash_words(words);
    }
};

bool run_strong_batch_once(
    int rank, int world_size, bool inject_mismatch,
    ReferenceShamirBatchResult* batch_out) {
    if (!batch_out || world_size < 3) return false;
    const int threshold = (world_size - 1) / 3;
    SelfTestMultiplicationConsistencyBackend multiplication_backend;
    const uint64_t sid = 0x5354524f4e474241ULL; // STRONGBA
    const CheckpointId checkpoint = inject_mismatch
        ? 0x5354524f4e470002ULL : 0x5354524f4e470001ULL;
    ReferenceShamirAuditSession session(
        sid, checkpoint, rank, world_size, threshold,
        nullptr, &multiplication_backend);
    if (!session.multiplication_consistency_enabled()) return false;

    for (int owner = 0; owner < world_size; ++owner) {
        const F challenge(owner + 5, owner + 1);
        std::vector<F> state(8);
        for (size_t i = 0; i < state.size(); ++i)
            state[i] = F(
                700 * (owner + 1) + static_cast<int>(i) + 1,
                30 + static_cast<int>(i));
        std::vector<F> output;
        if (!recompute_fold_rs_output(state, challenge, &output))
            return false;
        if (inject_mismatch && owner == 0 && !output.empty())
            output[0] += F(1);
        std::vector<F> owner_state;
        std::vector<F> owner_output;
        if (rank == owner) {
            owner_state = state;
            owner_output = output;
        }
        const OperationRef ref{
            static_cast<uint32_t>(owner),
            static_cast<uint64_t>(0x53540000ULL + owner)};
        const Digest statement = hash_words({
            sid, checkpoint, static_cast<u64>(owner), ref.object_id,
            0x5354524f4e47464fULL});
        if (!session.RegisterFoldOperation(
                static_cast<uint32_t>(owner), ref, challenge,
                hash_field_vector(state), hash_field_vector(output),
                statement, owner_state, owner_output))
            return false;
    }
    if (!session.SealRegistration()) return false;
    *batch_out = session.BatchCheck();
    return batch_out->available &&
        batch_out->multiplication_consistency_binding != Digest{} &&
        batch_out->opening_transcript_binding != Digest{} &&
        multiplication_backend.relation_reference_count() > 0 &&
        multiplication_backend.linear_prove_count() > 0;
}

bool run_one_reference_session(
    int rank, int world_size, bool inject_mismatch,
    ReferenceShamirBatchResult* batch_out) {
    if (!batch_out || world_size < 3) return false;
    const int threshold = (world_size - 1) / 2;
    if (2 * threshold >= world_size) return false;
    const uint64_t sid = 0x5245464d50434155ULL; // REFMPCAU
    const CheckpointId checkpoint = inject_mismatch
        ? 0x5245464d50430002ULL : 0x5245464d50430001ULL;
    ReferenceShamirAuditSession session(
        sid, checkpoint, rank, world_size, threshold);

    for (int owner = 0; owner < world_size; ++owner) {
        const F challenge(owner + 3);
        std::vector<F> canonical_state(8);
        for (size_t i = 0; i < canonical_state.size(); ++i)
            canonical_state[i] =
                F(100 * (owner + 1) + static_cast<int>(i) + 1);
        std::vector<F> canonical_output;
        if (!recompute_fold_rs_output(
                canonical_state, challenge, &canonical_output))
            return false;
        if (inject_mismatch && owner == 0 && !canonical_output.empty())
            canonical_output[0] += F(1);

        std::vector<F> private_state;
        std::vector<F> actual_output;
        if (rank == owner) {
            private_state = canonical_state;
            actual_output = canonical_output;
        }
        const OperationRef ref{
            static_cast<uint32_t>(owner),
            static_cast<uint64_t>(1000 + owner)};
        const Digest statement = hash_words({
            sid, checkpoint, static_cast<u64>(owner), ref.object_id,
            0x464f4c445f524546ULL});
        if (!session.RegisterFoldOperation(
                static_cast<uint32_t>(owner), ref, challenge,
                hash_field_vector(canonical_state),
                hash_field_vector(canonical_output), statement,
                private_state, actual_output))
            return false;
    }

    if (!session.SealRegistration()) return false;
    for (int owner = 0; owner < world_size; ++owner) {
        ReferenceShamirSelectedAuditWitness witness;
        const OperationRef ref{static_cast<uint32_t>(owner),
                               static_cast<uint64_t>(1000 + owner)};
        if (!session.SelectAuditWitness(ref, &witness) || !witness.available ||
            witness.state_shares.size() != 8 ||
            witness.actual_output_shares.size() != 4 ||
            !witness.registration_vss_receipt.available ||
            !witness.registration_vss_receipt.consistent ||
            witness.registration_vss_receipt.dealer != owner ||
            witness.registration_vss_receipt.world_size != world_size ||
            witness.registration_vss_receipt.element_count !=
                witness.state_shares.size() +
                    witness.actual_output_shares.size() ||
            witness.registration_vss_receipt.transcript_binding !=
                witness.registration_vss_witness.transcript_binding ||
            witness.registration_vss_receipt.local_row_commitment !=
                witness.registration_vss_witness.local_row_commitment)
            return false;
        ReferenceVssAuthenticatedRecoveryConfig bound_recovery_config;
        if (!bind_reference_shamir_selected_audit_witness(
                witness, &bound_recovery_config) ||
            bound_recovery_config.local_witness !=
                &witness.registration_vss_witness ||
            bound_recovery_config.receipt !=
                &witness.registration_vss_receipt ||
            bound_recovery_config.trusted_transcript !=
                &witness.registration_vss_witness.transcript_context)
            return false;
    }
    *batch_out = session.BatchCheck();
    return batch_out->available &&
           batch_out->operation_count == static_cast<size_t>(world_size);
}
bool run_registration_consistency_wiring_selftest(
    int rank, int world_size, bool* consistency_bound) {
    if (!consistency_bound || world_size < 4) return false;
    const int threshold = (world_size - 1) / 3;
    SelfTestRegistrationConsistencyBackend backend;
    // Require a local source-store consumption snapshot for the
    // standard signed reference MPI registration path.
    SelfTestEd25519OriginApprovalBackend signed_origin(
        false, false, false, true, true);
    auto& test_auth = Ed25519TransferAuthenticator::instance();
    if (!test_auth.Initialize(rank, world_size)) return false;
    const uint64_t sid = 0x524547434f4e5354ULL; // REGCONST
    const CheckpointId checkpoint = 0x524547434f4e0001ULL;
    ReferenceShamirAuditSession session(
        sid, checkpoint, rank, world_size, threshold,
        &backend, nullptr, nullptr, &signed_origin, true);

    const F challenge(7, 3);
    std::vector<F> state(8);
    for (size_t i = 0; i < state.size(); ++i)
        state[i] = F(static_cast<long long>(300 + i),
                     static_cast<long long>(900 + 2 * i));
    std::vector<F> output;
    if (!recompute_fold_rs_output(state, challenge, &output)) return false;
    std::vector<F> owner_state;
    std::vector<F> owner_output;
    if (rank == 0) {
        owner_state = state;
        owner_output = output;
    }
    const OperationRef ref{0, 0x524547434f4e0002ULL};
    RegistrationNativeContext native;
    native.native_state_id = 0x524547434f4e0003ULL;
    native.authentication_scheme_id = 0x524547434f4e0004ULL;
    native.authentication_binding =
        hash_words({sid, checkpoint, 0x4e41544956454155ULL});
    native.predecessor_root = hash_words({sid, 0x50524544524f4f54ULL});
    native.checkpoint_root = hash_words({checkpoint, 0x43484b50524f4f54ULL});
    const Digest operation_statement = hash_words({
        sid, checkpoint, ref.owner, ref.object_id, 0x524547434f4e5354ULL});

    // This selftest instantiates per-rank copies of a synthetic executed
    // record; they are NOT authenticated distributed native shares.
    AuditCheckpointView local_checkpoint;
    local_checkpoint.id = checkpoint;
    local_checkpoint.root = native.checkpoint_root;
    local_checkpoint.operations.push_back(ref);
    local_checkpoint.sealed = true;
    AuditStateView state_view;
    state_view.id = native.native_state_id;
    state_view.label.sid = sid;
    state_view.label.owner = ref.owner;
    state_view.digest = hash_field_vector(state);
    PrivateStateMaterialStore local_states;
    if (!local_states.BindPrivateState(state_view, state) ||
        !local_states.BindAuthentication(
            state_view, native.authentication_scheme_id,
            native.authentication_binding))
        return false;
    AuditOperationView operation_view;
    operation_view.ref = ref;
    operation_view.label.sid = sid;
    operation_view.label.owner = ref.owner;
    operation_view.label.object_id = ref.object_id;
    operation_view.label.phase = Phase::FOLD;
    operation_view.label.obligation = Obligation::FOLD;
    operation_view.relation = RelationKind::FOLDING;
    operation_view.kernel = AuditRelationKernel::FOLD_RS;
    operation_view.checkpoint = checkpoint;
    operation_view.active = true;
    operation_view.actual = hash_field_vector(output);
    operation_view.relation_statement = operation_statement;
    operation_view.predecessor_root = native.predecessor_root;
    operation_view.state_dependency_count = 1;
    operation_view.state_dependency_root =
        compute_state_dependency_root({StateDependencyEvidence{
            ref.owner, native.native_state_id, hash_field_vector(state)}});
    operation_view.public_aux_count = 1;
    operation_view.public_aux_root = compute_public_aux_root({
        PublicAuxEvidence{AuditPublicAuxKind::FOLD_CHALLENGE,
                          hash_field_vector({challenge})}});
    PrivateAuditMaterialStore local_operations;
    local_operations.RegisterOperation(operation_view);
    local_operations.BindPrivateField(operation_view,
        AuditPrivatePayloadKind::FIELD_VECTOR,
        AuditPayloadStage::ACTIVATE_OUTPUT, output);
    local_operations.BindStateDependencies(operation_view,
        {native.native_state_id});
    local_operations.BindPublicFieldAux(operation_view,
        AuditPublicAuxKind::FOLD_CHALLENGE, {challenge});
    local_operations.MarkFinalized(ref);
    signed_origin.BindLocalRecords(
        &local_states, &local_operations, &local_checkpoint);

    // Pure local tests complement the real MPI negative paths: root,
    // signature-metadata and lifecycle drift must never look acceptable.
    RegistrationConsistencyStatement local_claim;
    local_claim.sid = sid;
    local_claim.checkpoint = checkpoint;
    local_claim.ref = ref;
    local_claim.kernel = AuditRelationKernel::FOLD_RS;
    local_claim.state_element_count = state.size();
    local_claim.output_element_count = output.size();
    local_claim.public_state_digest = hash_field_vector(state);
    local_claim.public_actual_digest = hash_field_vector(output);
    local_claim.public_challenge_binding = hash_field_vector({challenge});
    local_claim.native_context = native;
    local_claim.operation_statement_binding = operation_statement;
    local_claim.sharing_transcript_binding =
        hash_words({sid, checkpoint, 0x5653534c4f43414cULL});
    local_claim.statement_binding =
        compute_registration_consistency_statement_binding(local_claim);

    // Read the owner input actually stored in the finalized native
    // record, rather than trusting a second caller-assembled vector.
    RegistrationNativeConsumedSnapshot consumed;
    if (!read_registration_native_consumed_snapshot(
            local_claim, local_states, local_operations,
            local_checkpoint, &consumed) ||
        consumed.public_challenge != challenge ||
        !registration_native_consumed_snapshot_still_matches(
            local_claim, local_states, local_operations,
            local_checkpoint, consumed))
        return false;
    if (rank == 0) {
        owner_state = consumed.state_values;
        owner_output = consumed.actual_output;
    }
    signed_origin.BindConsumedSnapshot(&consumed);

    // Fixture-only: independently generated Ed25519 issuer identity
    // is pinned BEFORE verification and is distinct from the MPI
    // transport/endowment registry. This key is NOT a production
    // execution service identity.
    using TestIssuerKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using TestIssuerContext = std::unique_ptr<EVP_PKEY_CTX,
                                              decltype(&EVP_PKEY_CTX_free)>;
    EVP_PKEY* raw_issuer_key = nullptr;
    std::array<uint8_t, 32> test_issuer_pin{};
    const char* configured_directory =
        std::getenv("PVIA_REG_NATIVE_ISSUER_KEY_DIR");
    const bool use_configured_key =
        configured_directory && *configured_directory;
    bool key_ok = false;
    if (use_configured_key) {
        // Identity provisioned in a separate setup step. The owner-key
        // directory and each seed must be private; each public pin is
        // compared with the public key derived from the seed.
        key_ok = LoadReferenceNativeIssuerSigningKey(
            configured_directory, rank, &raw_issuer_key, &test_issuer_pin);
    } else {
        TestIssuerContext issuer_gen(
            EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr),
            EVP_PKEY_CTX_free);
        key_ok = issuer_gen &&
            EVP_PKEY_keygen_init(issuer_gen.get()) == 1 &&
            EVP_PKEY_keygen(issuer_gen.get(), &raw_issuer_key) == 1;
        if (key_ok) {
            size_t pin_size = test_issuer_pin.size();
            key_ok =
                EVP_PKEY_get_raw_public_key(
                    raw_issuer_key, test_issuer_pin.data(), &pin_size) == 1 &&
                pin_size == test_issuer_pin.size();
        }
    }
    // Collectively reject an incomplete/mismatched provisioned roster,
    // rather than leaving some MPI ranks waiting at a later VSS barrier.
    int local_key_ok = key_ok ? 1 : 0;
    int everyone_key_ok = 0;
    MPI_Allreduce(&local_key_ok, &everyone_key_ok,
                  1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    TestIssuerKey issuer_key(raw_issuer_key, EVP_PKEY_free);
    if (!everyone_key_ok) return false;
    constexpr u64 TEST_ISSUER_ID_PREFIX = 0x5056494154495300ULL;
    constexpr u64 TEST_ISSUANCE_SEQUENCE = 7;
    RegistrationNativeExecutionReceipt native_issuer_receipt;
    native_issuer_receipt.issuer_id =
        TEST_ISSUER_ID_PREFIX + static_cast<u64>(rank + 1);
    native_issuer_receipt.sequence = TEST_ISSUANCE_SEQUENCE;
    native_issuer_receipt.pre_vss_claim_binding =
        consumed.pre_vss_claim_binding;
    native_issuer_receipt.consumed_record_binding =
        consumed.consumed_record_binding;
    const auto issuer_message =
        registration_native_execution_receipt_message(
            local_claim, native_issuer_receipt.issuer_id,
            native_issuer_receipt.sequence,
            native_issuer_receipt.pre_vss_claim_binding,
            native_issuer_receipt.consumed_record_binding);
    using TestIssuerDigestCtx = std::unique_ptr<EVP_MD_CTX,
                                               decltype(&EVP_MD_CTX_free)>;
    TestIssuerDigestCtx issuer_sign(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    size_t signature_size = native_issuer_receipt.signature.size();
    if (!issuer_sign || issuer_message.empty() ||
        EVP_DigestSignInit(issuer_sign.get(), nullptr, nullptr, nullptr,
                           issuer_key.get()) != 1 ||
        EVP_DigestSign(issuer_sign.get(),
                       native_issuer_receipt.signature.data(),
                       &signature_size, issuer_message.data(),
                       issuer_message.size()) != 1 ||
        signature_size != native_issuer_receipt.signature.size())
        return false;
    const u64 test_issuer_id = native_issuer_receipt.issuer_id;
    auto issuer_verifies = [&](const RegistrationConsistencyStatement& claim,
                              const RegistrationNativeConsumedSnapshot& snap,
                              const RegistrationNativeExecutionReceipt& receipt,
                              const std::array<uint8_t, 32>& pin,
                              u64 issuer_id, u64 minimum_sequence) {
        return verify_registration_native_execution_receipt(
            claim, snap, receipt, pin, issuer_id, minimum_sequence);
    };
    if (!issuer_verifies(local_claim, consumed, native_issuer_receipt,
                        test_issuer_pin, test_issuer_id,
                        TEST_ISSUANCE_SEQUENCE) ||
        !verify_registration_native_execution_receipt_public(
            local_claim, native_issuer_receipt,
            consumed.consumed_record_binding,
            test_issuer_pin, test_issuer_id, TEST_ISSUANCE_SEQUENCE) ||
        verify_registration_native_execution_receipt_public(
            local_claim, native_issuer_receipt,
            hash_words({0x505652574e475049ULL}),
            test_issuer_pin, test_issuer_id, TEST_ISSUANCE_SEQUENCE))
        return false;
    signed_origin.BindNativeIssuerReceipt(
        native_issuer_receipt, test_issuer_pin,
        test_issuer_id, TEST_ISSUANCE_SEQUENCE);
    signed_origin.BindTestIssuerFinalSigningKey(issuer_key.get());

    // Mint the test-only signed *pre-VSS* record BEFORE any registration
    // session shares private state. This receipt must not be reconstructed
    // or re-signed as a reaction to the post-VSS transcript.
    const auto pre_vss_words = registration_pre_vss_claim_words(local_claim);
    RegistrationPreVssReceipt pre_vss_receipt;
    pre_vss_receipt.signer = static_cast<uint32_t>(rank);
    if (pre_vss_words.size() != 38 ||
        !test_auth.SignWords(REGISTRATION_PRE_VSS_RECEIPT_DOMAIN,
                             pre_vss_words, &pre_vss_receipt.signature) ||
        !verify_registration_pre_vss_receipt(
            local_claim, pre_vss_receipt, test_auth.PublicKeys(),
            test_auth.RegistryCommitment(), static_cast<uint32_t>(rank)))
        return false;
    signed_origin.BindPreVssReceipt(pre_vss_receipt);
    // Every MPI rank gets a private test directory, not a shared
    // production ledger or independently trusted monotonic counter.
    char replay_template[] = "/tmp/pvia-pre-vss-replay-XXXXXX";
    const char* replay_directory = ::mkdtemp(replay_template);
    if (!replay_directory) return false;
    const std::string replay_path(replay_directory);
    const RegistrationReceiptReplayLedger ledger(replay_path);
    signed_origin.BindReplayLedger(&ledger);
    const auto& public_registry = test_auth.PublicKeys();
    const Digest test_registry_pin = test_auth.RegistryCommitment();
    auto receipt_verifies = [&](const RegistrationConsistencyStatement& value,
                                const RegistrationPreVssReceipt& receipt) {
        return verify_registration_pre_vss_receipt(
            value, receipt, public_registry, test_registry_pin,
            static_cast<uint32_t>(rank));
    };
    if (!receipt_verifies(local_claim, pre_vss_receipt)) return false;
    auto changed_issuer_record = native_issuer_receipt;
    changed_issuer_record.signature[8] ^= 1;
    if (issuer_verifies(local_claim, consumed, changed_issuer_record,
                       test_issuer_pin, test_issuer_id,
                       TEST_ISSUANCE_SEQUENCE))
        return false;
    changed_issuer_record = native_issuer_receipt;
    changed_issuer_record.issuer_id ^= 1;
    if (issuer_verifies(local_claim, consumed, changed_issuer_record,
                       test_issuer_pin, test_issuer_id,
                       TEST_ISSUANCE_SEQUENCE))
        return false;
    changed_issuer_record = native_issuer_receipt;
    changed_issuer_record.sequence--;
    if (issuer_verifies(local_claim, consumed, changed_issuer_record,
                       test_issuer_pin, test_issuer_id, 1))
        return false;
    if (issuer_verifies(local_claim, consumed, native_issuer_receipt,
                       test_issuer_pin, test_issuer_id,
                       TEST_ISSUANCE_SEQUENCE + 1))
        return false;
    auto wrong_issuer_pin = test_issuer_pin;
    wrong_issuer_pin[0] ^= 1;
    if (issuer_verifies(local_claim, consumed, native_issuer_receipt,
                       wrong_issuer_pin, test_issuer_id,
                       TEST_ISSUANCE_SEQUENCE))
        return false;
    changed_issuer_record = native_issuer_receipt;
    changed_issuer_record.consumed_record_binding =
        hash_words({0x1234ULL});
    if (issuer_verifies(local_claim, consumed, changed_issuer_record,
                       test_issuer_pin, test_issuer_id,
                       TEST_ISSUANCE_SEQUENCE))
        return false;
    auto other_native_scope = local_claim;
    other_native_scope.sid ^= 1;
    if (issuer_verifies(other_native_scope, consumed, native_issuer_receipt,
                       test_issuer_pin, test_issuer_id,
                       TEST_ISSUANCE_SEQUENCE))
        return false;
    auto other_source_snapshot = consumed;
    other_source_snapshot.state_values[0] += F(1);
    // The issuer receipt authenticates the local snapshot COMMITMENT.
    // Private-data equality is separately enforced by local store rereads.
    if (registration_native_consumed_snapshot_still_matches(
            local_claim, local_states, local_operations,
            local_checkpoint, other_source_snapshot))
        return false;
    RegistrationPreVssReceipt invalid_receipt = pre_vss_receipt;
    invalid_receipt.signature[3] ^= 1;
    if (receipt_verifies(local_claim, invalid_receipt)) return false;
    invalid_receipt = pre_vss_receipt;
    invalid_receipt.signer = static_cast<uint32_t>((rank + 1) % world_size);
    if (receipt_verifies(local_claim, invalid_receipt)) return false;
    if (verify_registration_pre_vss_receipt(
            local_claim, pre_vss_receipt, public_registry,
            hash_words({0xbadc0deULL}), static_cast<uint32_t>(rank)))
        return false;
    RegistrationConsistencyStatement changed_claim = local_claim;
    changed_claim.sid ^= 1;
    if (receipt_verifies(changed_claim, pre_vss_receipt)) return false;
    changed_claim = local_claim;
    changed_claim.checkpoint ^= 1;
    if (receipt_verifies(changed_claim, pre_vss_receipt)) return false;
    changed_claim = local_claim;
    changed_claim.ref.object_id ^= 1;
    if (receipt_verifies(changed_claim, pre_vss_receipt)) return false;
    changed_claim = local_claim;
    changed_claim.native_context.authentication_binding =
        hash_words({0xbadc0deULL});
    if (receipt_verifies(changed_claim, pre_vss_receipt)) return false;
    changed_claim = local_claim;
    changed_claim.public_actual_digest = hash_words({0xbadc0deULL});
    if (receipt_verifies(changed_claim, pre_vss_receipt)) return false;
    std::array<uint8_t, 64> wrong_domain_sig{};
    if (!test_auth.SignWords(
            REGISTRATION_PRE_VSS_RECEIPT_DOMAIN ^ 1ULL,
            pre_vss_words, &wrong_domain_sig))
        return false;
    invalid_receipt = pre_vss_receipt;
    invalid_receipt.signature = wrong_domain_sig;
    if (receipt_verifies(local_claim, invalid_receipt)) return false;

    if (!verify_registration_local_native_record(
            local_claim, local_states, local_operations, local_checkpoint))
        return false;
    // Post-capture mutations must be rejected, including data-only
    // mutations that keep unchanged state/operation metadata.
    auto consumed_changed_state = local_states;
    consumed_changed_state.Find(native.native_state_id)
        ->local_share[0] += F(1);
    if (registration_native_consumed_snapshot_still_matches(
            local_claim, consumed_changed_state,
            local_operations, local_checkpoint, consumed))
        return false;
    auto consumed_changed_output = local_operations;
    consumed_changed_output.Find(ref)->field_output[0] += F(1);
    if (registration_native_consumed_snapshot_still_matches(
            local_claim, local_states,
            consumed_changed_output, local_checkpoint, consumed))
        return false;
    auto consumed_changed_challenge = local_operations;
    consumed_changed_challenge.Find(ref)
        ->field_aux.front().second[0] += F(1);
    if (registration_native_consumed_snapshot_still_matches(
            local_claim, local_states,
            consumed_changed_challenge, local_checkpoint, consumed))
        return false;
    auto consumed_changed_scope = local_claim;
    consumed_changed_scope.checkpoint ^= 1;
    consumed_changed_scope.statement_binding =
        compute_registration_consistency_statement_binding(
            consumed_changed_scope);
    if (registration_native_consumed_snapshot_still_matches(
            consumed_changed_scope, local_states,
            local_operations, local_checkpoint, consumed))
        return false;
    auto changed_ops = local_operations;
    changed_ops.Find(ref)->operation.state_dependency_root =
        hash_words({0xbaadbeefULL});
    if (verify_registration_local_native_record(
            local_claim, local_states, changed_ops, local_checkpoint))
        return false;
    changed_ops = local_operations;
    changed_ops.Find(ref)->operation.public_aux_root =
        hash_words({0xbaadbeefULL});
    if (verify_registration_local_native_record(
            local_claim, local_states, changed_ops, local_checkpoint))
        return false;
    changed_ops = local_operations;
    changed_ops.Find(ref)->finalized = false;
    if (verify_registration_local_native_record(
            local_claim, local_states, changed_ops, local_checkpoint))
        return false;
    changed_ops = local_operations;
    changed_ops.Find(ref)->field_aux.front().second[0] += F(1);
    if (verify_registration_local_native_record(
            local_claim, local_states, changed_ops, local_checkpoint))
        return false;
    auto changed_state_metadata = local_states;
    changed_state_metadata.Find(native.native_state_id)
        ->authentication_binding = hash_words({0xbaadbeefULL});
    if (verify_registration_local_native_record(
            local_claim, changed_state_metadata, local_operations,
            local_checkpoint))
        return false;
    auto changed_checkpoint = local_checkpoint;
    changed_checkpoint.root = hash_words({0xbaadbeefULL});
    if (verify_registration_local_native_record(
            local_claim, local_states, local_operations, changed_checkpoint))
        return false;
    changed_checkpoint = local_checkpoint;
    changed_checkpoint.operations.push_back(ref);
    if (verify_registration_local_native_record(
            local_claim, local_states, local_operations, changed_checkpoint))
        return false;
    changed_ops = local_operations;
    changed_ops.Find(ref)->operation.label.phase = Phase::UNKNOWN;
    if (verify_registration_local_native_record(
            local_claim, local_states, changed_ops, local_checkpoint))
        return false;

    // Verify the generic BEFORE-VSS input-source gate. These requests
    // supply valid caller hashes for substituted owner values, but they
    // cannot match the finalized native material store. Nothing may
    // reach VSS or registration proving on these cases.
    std::vector<F> substituted_state = state;
    substituted_state[0] += F(1);
    std::vector<F> substituted_owner_state;
    if (rank == 0) substituted_owner_state = substituted_state;
    ReferenceShamirAuditSession state_source_mismatch(
        sid, checkpoint, rank, world_size, threshold,
        &backend, nullptr, nullptr, &signed_origin, true);
    if (state_source_mismatch.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(substituted_state),
            hash_field_vector(output), operation_statement,
            substituted_owner_state, owner_output, native))
        return false;

    std::vector<F> substituted_output = output;
    substituted_output[0] += F(1);
    std::vector<F> substituted_owner_output;
    if (rank == 0) substituted_owner_output = substituted_output;
    ReferenceShamirAuditSession output_source_mismatch(
        sid, checkpoint, rank, world_size, threshold,
        &backend, nullptr, nullptr, &signed_origin, true);
    if (output_source_mismatch.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(state),
            hash_field_vector(substituted_output),
            operation_statement, owner_state,
            substituted_owner_output, native))
        return false;

    const F substituted_challenge = challenge + F(1);
    ReferenceShamirAuditSession challenge_source_mismatch(
        sid, checkpoint, rank, world_size, threshold,
        &backend, nullptr, nullptr, &signed_origin, true);
    if (challenge_source_mismatch.RegisterFoldOperation(
            0, ref, substituted_challenge,
            hash_field_vector(state), hash_field_vector(output),
            operation_statement, owner_state, owner_output, native))
        return false;

    // The same authenticated-capability backend must reject when no
    // origin approval provider was supplied, even with valid VSS metadata.
    ReferenceShamirAuditSession no_origin(
        sid, checkpoint + 1, rank, world_size, threshold, &backend);
    RegistrationNativeContext missing_native = native;
    missing_native.checkpoint_root =
        hash_words({checkpoint + 1, 0x43484b50524f4f54ULL});
    if (no_origin.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(state),
            hash_field_vector(output), operation_statement,
            owner_state, owner_output, missing_native))
        return false;
    // One rank missing a configured backend must fail *before* any
    // signer enters a backend-specific signature Allgather.
    ReferenceShamirAuditSession split_origin(
        sid, checkpoint + 2, rank, world_size, threshold,
        &backend, nullptr, nullptr,
        rank == 1 ? nullptr : &signed_origin);
    missing_native.checkpoint_root =
        hash_words({checkpoint + 2, 0x43484b50524f4f54ULL});
    if (split_origin.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(state),
            hash_field_vector(output), operation_statement,
            owner_state, owner_output, missing_native))
        return false;
    if (backend.prove_calls() != 0) return false;
    SelfTestEd25519OriginApprovalBackend corrupt_origin(true);
    AuditCheckpointView corrupt_checkpoint = local_checkpoint;
    corrupt_checkpoint.id = checkpoint + 3;
    corrupt_checkpoint.root =
        hash_words({checkpoint + 3, 0x43484b50524f4f54ULL});
    PrivateAuditMaterialStore corrupt_operations = local_operations;
    if (PrivateOperationMaterial* item = corrupt_operations.Find(ref))
        item->operation.checkpoint = checkpoint + 3;
    corrupt_origin.BindLocalRecords(
        &local_states, &corrupt_operations, &corrupt_checkpoint);
    RegistrationConsistencyStatement corrupt_pre_vss = local_claim;
    corrupt_pre_vss.checkpoint = checkpoint + 3;
    corrupt_pre_vss.native_context.checkpoint_root =
        corrupt_checkpoint.root;
    const auto corrupt_pre_vss_words =
        registration_pre_vss_claim_words(corrupt_pre_vss);
    RegistrationPreVssReceipt corrupt_pre_vss_receipt;
    corrupt_pre_vss_receipt.signer = static_cast<uint32_t>(rank);
    if (!test_auth.SignWords(REGISTRATION_PRE_VSS_RECEIPT_DOMAIN,
                            corrupt_pre_vss_words,
                            &corrupt_pre_vss_receipt.signature))
        return false;
    corrupt_origin.BindPreVssReceipt(corrupt_pre_vss_receipt);
    ReferenceShamirAuditSession corrupted_origin(
        sid, checkpoint + 3, rank, world_size, threshold,
        &backend, nullptr, nullptr, &corrupt_origin, true);
    missing_native.checkpoint_root =
        hash_words({checkpoint + 3, 0x43484b50524f4f54ULL});
    if (corrupted_origin.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(state),
            hash_field_vector(output), operation_statement,
            owner_state, owner_output, missing_native))
        return false;
    // Rejection under a required independently pinned issuer record:
    // one rank without issuer certificate cannot pass the final gate.
    SelfTestEd25519OriginApprovalBackend missing_native_issuer(
        false, false, false, true, true);
    missing_native_issuer.BindLocalRecords(
        &local_states, &local_operations, &local_checkpoint);
    missing_native_issuer.BindConsumedSnapshot(&consumed);
    missing_native_issuer.BindPreVssReceipt(pre_vss_receipt);
    ReferenceShamirAuditSession missing_issuer_session(
        sid, checkpoint, rank, world_size, threshold,
        &backend, nullptr, nullptr, &missing_native_issuer, true);
    if (missing_issuer_session.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(state),
            hash_field_vector(output), operation_statement,
            owner_state, owner_output, native))
        return false;

    SelfTestEd25519OriginApprovalBackend other_issuer_origin(
        false, false, false, true, true);
    other_issuer_origin.BindLocalRecords(
        &local_states, &local_operations, &local_checkpoint);
    other_issuer_origin.BindConsumedSnapshot(&consumed);
    other_issuer_origin.BindPreVssReceipt(pre_vss_receipt);
    if (rank == 1) {
        other_issuer_origin.BindNativeIssuerReceipt(
            native_issuer_receipt, wrong_issuer_pin,
            test_issuer_id, TEST_ISSUANCE_SEQUENCE);
    } else {
        other_issuer_origin.BindNativeIssuerReceipt(
            native_issuer_receipt, test_issuer_pin,
            test_issuer_id, TEST_ISSUANCE_SEQUENCE);
    }
    ReferenceShamirAuditSession issuer_pin_session(
        sid, checkpoint, rank, world_size, threshold,
        &backend, nullptr, nullptr, &other_issuer_origin, true);
    if (issuer_pin_session.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(state),
            hash_field_vector(output), operation_statement,
            owner_state, owner_output, native))
        return false;

    // Missing source consumption capture must be rejected collectively
    // before source signers can approve a final registration statement.
    SelfTestEd25519OriginApprovalBackend absent_consumed(
        false, false, false, true);
    absent_consumed.BindLocalRecords(
        &local_states, &local_operations, &local_checkpoint);
    absent_consumed.BindPreVssReceipt(pre_vss_receipt);
    ReferenceShamirAuditSession absent_consumed_session(
        sid, checkpoint, rank, world_size, threshold,
        &backend, nullptr, nullptr, &absent_consumed, true);
    if (absent_consumed_session.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(state),
            hash_field_vector(output), operation_statement,
            owner_state, owner_output, native))
        return false;

    // A single rank's changed captured input after pre-VSS signature
    // must prevent the collective registration and all proving.
    RegistrationNativeConsumedSnapshot stale_consumed = consumed;
    if (rank == 1) stale_consumed.state_values[0] += F(1);
    SelfTestEd25519OriginApprovalBackend stale_origin(
        false, false, false, true);
    stale_origin.BindLocalRecords(
        &local_states, &local_operations, &local_checkpoint);
    stale_origin.BindPreVssReceipt(pre_vss_receipt);
    stale_origin.BindConsumedSnapshot(&stale_consumed);
    ReferenceShamirAuditSession stale_consumed_session(
        sid, checkpoint, rank, world_size, threshold,
        &backend, nullptr, nullptr, &stale_origin, true);
    if (stale_consumed_session.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(state),
            hash_field_vector(output), operation_statement,
            owner_state, owner_output, native))
        return false;

    // After successful local/collective checks, alter just the
    // *collected public pre-VSS evidence* at every verifier. All final
    // signatures remain intact. Pairwise verification must deny Prove.
    SelfTestEd25519OriginApprovalBackend invalid_pair(
        false, false, true);
    invalid_pair.BindLocalRecords(
        &local_states, &local_operations, &local_checkpoint);
    invalid_pair.BindPreVssReceipt(pre_vss_receipt);
    invalid_pair.BindReplayLedger(&ledger);
    ReferenceShamirAuditSession invalid_pair_session(
        sid, checkpoint, rank, world_size, threshold,
        &backend, nullptr, nullptr, &invalid_pair, true);
    if (invalid_pair_session.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(state),
            hash_field_vector(output), operation_statement,
            owner_state, owner_output, native))
        return false;

    // A rank with a mutated pre-VSS receipt must not reach the final
    // public statement endorsement, even with perfectly matching records.
    SelfTestEd25519OriginApprovalBackend changed_receipt_backend;
    changed_receipt_backend.BindLocalRecords(
        &local_states, &local_operations, &local_checkpoint);
    RegistrationPreVssReceipt changed_receipt = pre_vss_receipt;
    if (rank == 1) changed_receipt.signature[17] ^= 1;
    changed_receipt_backend.BindPreVssReceipt(changed_receipt);
    ReferenceShamirAuditSession changed_receipt_session(
        sid, checkpoint, rank, world_size, threshold,
        &backend, nullptr, nullptr, &changed_receipt_backend, true);
    if (changed_receipt_session.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(state),
            hash_field_vector(output), operation_statement,
            owner_state, owner_output, native))
        return false;

    SelfTestEd25519OriginApprovalBackend missing_receipt_backend;
    missing_receipt_backend.BindLocalRecords(
        &local_states, &local_operations, &local_checkpoint);
    ReferenceShamirAuditSession missing_receipt_session(
        sid, checkpoint, rank, world_size, threshold,
        &backend, nullptr, nullptr, &missing_receipt_backend, true);
    if (missing_receipt_session.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(state),
            hash_field_vector(output), operation_statement,
            owner_state, owner_output, native))
        return false;

    // A single rank with a mismatched locally retained output cannot
    // endorse the public statement. Other ranks may have valid records.
    PrivateAuditMaterialStore altered_operations = local_operations;
    PrivateOperationMaterial* altered = altered_operations.Find(ref);
    if (!altered || altered->field_output.empty()) return false;
    altered->field_output[0] += F(1);
    SelfTestEd25519OriginApprovalBackend drifted_output;
    drifted_output.BindLocalRecords(&local_states,
        rank == 1 ? &altered_operations : &local_operations,
        &local_checkpoint);
    drifted_output.BindPreVssReceipt(pre_vss_receipt);
    ReferenceShamirAuditSession drifted_session(
        sid, checkpoint, rank, world_size, threshold,
        &backend, nullptr, nullptr, &drifted_output, true);
    if (drifted_session.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(state),
            hash_field_vector(output), operation_statement,
            owner_state, owner_output, native))
        return false;

    // The same negative check covers a mismatched local private state
    // even when its public digest metadata remains unchanged.
    PrivateStateMaterialStore altered_states = local_states;
    PrivateStateMaterial* altered_state = altered_states.Find(native.native_state_id);
    if (!altered_state || altered_state->local_share.empty()) return false;
    altered_state->local_share[0] += F(1);
    SelfTestEd25519OriginApprovalBackend drifted_state;
    drifted_state.BindLocalRecords(
        rank == 1 ? &altered_states : &local_states,
        &local_operations, &local_checkpoint);
    drifted_state.BindPreVssReceipt(pre_vss_receipt);
    ReferenceShamirAuditSession drifted_state_session(
        sid, checkpoint, rank, world_size, threshold,
        &backend, nullptr, nullptr, &drifted_state, true);
    if (drifted_state_session.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(state),
            hash_field_vector(output), operation_statement,
            owner_state, owner_output, native))
        return false;
    // The exchanged registry alone is not an independently governed
    // public-key trust anchor. Exercise the missing-anchor rejection only
    // when this MPI run is actually unanchored. In an anchored run, verify
    // that the configured pin matches the exchanged registry instead of
    // incorrectly treating the expected anchor as a test failure.
    if (test_auth.ExternalRegistryAnchorVerified()) {
        if (test_auth.ExternalRegistryAnchor() !=
            test_auth.RegistryCommitment())
            return false;
    } else {
        SelfTestEd25519OriginApprovalBackend external_anchor_required(
            false, true);
        external_anchor_required.BindLocalRecords(
            &local_states, &local_operations, &local_checkpoint);
        external_anchor_required.BindPreVssReceipt(pre_vss_receipt);
        external_anchor_required.BindReplayLedger(&ledger);
        ReferenceShamirAuditSession unanchored(
            sid, checkpoint, rank, world_size, threshold,
            &backend, nullptr, nullptr, &external_anchor_required, true);
        if (unanchored.RegisterFoldOperation(
                0, ref, challenge, hash_field_vector(state),
                hash_field_vector(output), operation_statement,
                owner_state, owner_output, native))
            return false;
    }

    // The origin checks can be valid, but missing a replay ledger
    // must still fail closed before the synthetic prover is called.
    SelfTestEd25519OriginApprovalBackend missing_ledger_origin;
    missing_ledger_origin.BindLocalRecords(
        &local_states, &local_operations, &local_checkpoint);
    missing_ledger_origin.BindPreVssReceipt(pre_vss_receipt);
    ReferenceShamirAuditSession missing_ledger_session(
        sid, checkpoint, rank, world_size, threshold,
        &backend, nullptr, nullptr, &missing_ledger_origin, true);
    if (missing_ledger_session.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(state),
            hash_field_vector(output), operation_statement,
            owner_state, owner_output, native))
        return false;

    // Generic session admission must reject synthetic proofs even if a
    // local reference backend advertises ZK-like artifact bits.
    if (production_ready_registration_consistency_capabilities(
            backend.Capabilities()))
        return false;
    ReferenceShamirAuditSession production_denial(
        sid, checkpoint, rank, world_size, threshold,
        &backend, nullptr, nullptr, &signed_origin);
    if (production_denial.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(state),
            hash_field_vector(output), operation_statement,
            owner_state, owner_output, native) ||
        production_denial.SealRegistration() ||
        production_denial.BatchCheck().available)
        return false;

    // Rejected proof paths, including true signature and local record
    // mismatch failures, must never invoke even the test proof backend.
    if (backend.prove_calls() != 0) return false;

    // Each case changes one rank's public registration descriptor only.
    // All ranks must fail at the new PRE-VSS agreement, with no MPC
    // sharing, signer approval, proof generation, or public release.
    if (const char* requested_fault =
            std::getenv("PVIA_REG_PREPROVE_DESCRIPTOR_FAULT")) {
        const std::string fault(requested_fault);
        const bool supported =
            fault == "state" || fault == "challenge" ||
            fault == "owner" || fault == "operation" ||
            fault == "missing_digest";
        if (!supported) return false;
        auto changed_ref = ref;
        uint32_t changed_owner = 0;
        F changed_challenge = challenge;
        Digest changed_state = hash_field_vector(state);
        if (rank == 1) {
            if (fault == "state") {
                changed_state = hash_words({
                    sid, checkpoint, 0x5354415445445246ULL});
            } else if (fault == "challenge") {
                changed_challenge += F(1);
            } else if (fault == "owner") {
                changed_owner = 1;
                changed_ref.owner = 1;
            } else if (fault == "operation") {
                ++changed_ref.object_id;
            } else if (fault == "missing_digest") {
                changed_state = Digest{};
            }
        }
        const bool accepted = session.RegisterFoldOperation(
            changed_owner, changed_ref, changed_challenge, changed_state,
            hash_field_vector(output), operation_statement,
            owner_state, owner_output, native);
        const bool seal_refused = !session.SealRegistration();
        const bool batch_refused = !session.BatchCheck().available;
        const bool proof_not_run = backend.prove_calls() == 0;
        const char* public_out =
            std::getenv("PVIA_REG_PREPROVE_PUBLIC_EXPORT");
        const bool public_absent = !public_out || !*public_out ||
            ::access(public_out, F_OK) != 0;
        const std::string marker =
            RegistrationReceiptReplayLedger::MarkerName(
                local_claim, static_cast<uint32_t>(rank));
        const bool ledger_unused = !marker.empty() &&
            ::access((replay_path + "/" + marker).c_str(), F_OK) != 0;
        const bool cleaned = ::rmdir(replay_path.c_str()) == 0;
        *consistency_bound = !accepted && seal_refused &&
            batch_refused && proof_not_run && public_absent &&
            ledger_unused && cleaned;
        test_auth.Reset();
        return true;
    }

    // This fault-injected branch exercises a real MPI registration
    // transaction whose test-only proof backend deliberately refuses to
    // produce an artifact AFTER signed origin and VSS acceptance.
    // It must NOT emit a public paired-origin artifact on proof failure.
    const bool reject_proof_for_test =
        std::getenv("PVIA_REG_PREPROVE_FORCE_PROOF_FAILURE") != nullptr;
    if (reject_proof_for_test) {
        backend.SetForcedProofFailure(true);
        const bool registered = session.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(state),
            hash_field_vector(output), operation_statement,
            owner_state, owner_output, native);
        const std::string marker =
            RegistrationReceiptReplayLedger::MarkerName(
                local_claim, static_cast<uint32_t>(rank));
        const bool expected_call_count =
            backend.prove_calls() == (rank == 0 ? 1ULL : 0ULL);
        const char* public_path =
            std::getenv("PVIA_REG_PREPROVE_PUBLIC_EXPORT");
        const bool export_refused_without_proof = !public_path ||
            !*public_path ||
            !signed_origin.ExportApprovedPublicBundle(public_path);
        const bool no_export = !public_path || !*public_path ||
            ::access(public_path, F_OK) != 0;
        const bool rejected = !registered && expected_call_count &&
            signed_origin.ApprovedStatementBinding() != Digest{} &&
            no_export && export_refused_without_proof;
        const bool cleaned = !marker.empty() &&
            ::unlink((replay_path + "/" + marker).c_str()) == 0 &&
            ::rmdir(replay_path.c_str()) == 0;
        *consistency_bound = rejected && cleaned;
        test_auth.Reset();
        return true;
    }

    // Optional test-only LIVE SP1 Guest admission check: the current owner
    // writes its newly generated private VSS witness and executes the
    // genuine SP1 Guest before it may produce the reference proof artifact.
    // No current-run Groth16 proof is produced here.
    const char* sp1_host = std::getenv("PVIA_REG_P101_SP1_EXECUTE_HOST");
    const char* sp1_elf = std::getenv("PVIA_REG_P101_SP1_GUEST_ELF");
    const bool sp1_enabled = sp1_host && *sp1_host;
    if (sp1_enabled) {
        const char* private_path =
            std::getenv("PVIA_REG_PRIVATE_FIXTURE_EXPORT");
        if (!sp1_elf || !*sp1_elf || !private_path || !*private_path)
            return false;
        backend.SetRequiredSp1GuestExecution(sp1_host, sp1_elf);
        if (const char* proof_dir =
                std::getenv("PVIA_REG_P101_SP1_GROTH16_OUTPUT_DIR")) {
            const char* pin_elf =
                std::getenv("PVIA_REG_P101_SP1_EXPECTED_ELF_BLAKE3");
            const char* pin_vk =
                std::getenv("PVIA_REG_P101_SP1_EXPECTED_VKEY_HASH");
            if (!*proof_dir || !pin_elf || !*pin_elf ||
                !pin_vk || !*pin_vk) return false;
            backend.SetRequiredSp1Groth16Proof(
                proof_dir, pin_elf, pin_vk);
        }
    }
    // Explicit offline experiment only. The owner-only private witness
    // file is NEVER included in public bundles, stdout or Git.
    if (const char* private_out =
            std::getenv("PVIA_REG_PRIVATE_FIXTURE_EXPORT");
        private_out && *private_out)
        backend.SetPrivateTestVectorOutput(private_out);
    const bool registered = session.RegisterFoldOperation(
        0, ref, challenge, hash_field_vector(state),
        hash_field_vector(output), operation_statement,
        owner_state, owner_output, native);
    if (sp1_enabled &&
        std::getenv("PVIA_REG_P101_SP1_EXECUTE_EXPECT_REJECT")) {
        const bool request_groth16 = std::getenv(
            "PVIA_REG_P101_SP1_GROTH16_OUTPUT_DIR") != nullptr;
        const bool owner_attempted =
            (request_groth16
                ? backend.sp1_groth16_attempted()
                : backend.sp1_execution_attempted()) == (rank == 0);
        const bool owner_refused =
            !(request_groth16
                ? backend.sp1_groth16_accepted()
                : backend.sp1_execution_accepted());
        const bool no_batch = !session.BatchCheck().available;
        const bool no_seal = !session.SealRegistration();
        const char* public_path =
            std::getenv("PVIA_REG_PREPROVE_PUBLIC_EXPORT");
        const bool no_public = !public_path || !*public_path ||
            ::access(public_path, F_OK) != 0;
        const std::string marker =
            RegistrationReceiptReplayLedger::MarkerName(
                local_claim, static_cast<uint32_t>(rank));
        const bool cleaned = !marker.empty() &&
            ::unlink((replay_path + "/" + marker).c_str()) == 0 &&
            ::rmdir(replay_path.c_str()) == 0;
        *consistency_bound = !registered && owner_attempted &&
            owner_refused && no_batch && no_seal && no_public &&
            backend.prove_calls() == (rank == 0 ? 1ULL : 0ULL) &&
            cleaned;
        test_auth.Reset();
        return true;
    }
    const bool request_groth16 = std::getenv(
        "PVIA_REG_P101_SP1_GROTH16_OUTPUT_DIR") != nullptr;
    if (!registered || (sp1_enabled &&
            (backend.sp1_execution_attempted() != (rank == 0) ||
             (rank == 0 && !backend.sp1_execution_accepted()) ||
             (request_groth16 &&
              (backend.sp1_groth16_attempted() != (rank == 0) ||
               (rank == 0 && !backend.sp1_groth16_accepted()))))))
        return false;

    // The owner already produced + verified a fresh real Groth16.
    // Before ANY seal, EVERY rank independently runs the public SP1
    // Groth16 verifier against its own canonical C++ statement and an
    // independently configured VK/ELF pin. A single rejecting party
    // poisons the entire checkpoint and prevents publication. This is
    // an N=4 REFERENCE path, not a production MPC trust upgrade.
    if (request_groth16) {
        const std::string proof_dir =
            std::getenv("PVIA_REG_P101_SP1_GROTH16_OUTPUT_DIR");
        RegistrationConsistencyStatement my_statement;
        bool independently_verified =
            session.ReadRegisteredPublicConsistencyStatement(
                ref, &my_statement) &&
            my_statement.statement_binding ==
                signed_origin.ApprovedStatementBinding();
        const std::string public_expected = proof_dir +
            ".verify-rank-" + std::to_string(rank) + ".json";
        if (independently_verified)
            independently_verified = WriteReferenceSp1ExpectedStatement(
                public_expected, my_statement);
        std::string vkey_pin =
            std::getenv("PVIA_REG_P101_SP1_EXPECTED_VKEY_HASH");
        const char* fault_rank =
            std::getenv("PVIA_REG_P101_SP1_FORCE_VERIFIER_REJECT_RANK");
        if (fault_rank && std::string(fault_rank) == std::to_string(rank))
            vkey_pin[2] = vkey_pin[2] == '0' ? '1' : '0';
        if (independently_verified)
            independently_verified = RunReferenceSp1Process({
                sp1_host, "verify", sp1_elf, proof_dir,
                "--proof-mode", "groth16",
                "--expected-statement", public_expected,
                "--expected-elf-blake3",
                    std::getenv("PVIA_REG_P101_SP1_EXPECTED_ELF_BLAKE3"),
                "--expected-vkey-hash", vkey_pin}, 120);
        int local_verdict = independently_verified ? 1 : 0;
        int verified_ranks = 0;
        MPI_Allreduce(&local_verdict, &verified_ranks, 1, MPI_INT,
                      MPI_SUM, MPI_COMM_WORLD);
        if (verified_ranks != world_size) {
            session.AbortRegistrationBeforeSeal();
            const bool no_seal = !session.SealRegistration();
            const bool no_batch = !session.BatchCheck().available;
            const char* public_out =
                std::getenv("PVIA_REG_PREPROVE_PUBLIC_EXPORT");
            const bool no_public = !public_out || !*public_out ||
                ::access(public_out, F_OK) != 0;
            const std::string marker =
                RegistrationReceiptReplayLedger::MarkerName(
                    local_claim, static_cast<uint32_t>(rank));
            const bool cleaned = !marker.empty() &&
                ::unlink((replay_path + "/" + marker).c_str()) == 0 &&
                ::rmdir(replay_path.c_str()) == 0;
            const char* requested_fault =
                std::getenv("PVIA_REG_P101_SP1_FORCE_VERIFIER_REJECT_RANK");
            *consistency_bound = requested_fault &&
                std::string(requested_fault) == "1" &&
                verified_ranks == world_size - 1 &&
                no_seal && no_batch && no_public && cleaned &&
                backend.prove_calls() == (rank == 0 ? 1ULL : 0ULL);
            test_auth.Reset();
            return *consistency_bound;
        }
        if (rank == 0)
            std::cout << "PVIA_REG_P101_ALL_RANK_GROTH16: PASS"
                      << " rank_count=" << world_size
                      << " verifier_count=" << verified_ranks
                      << " expected_statement=CXX_LOCAL"
                      << " pinned_vkey=REQUIRED"
                      << " before_seal=true"
                      << " source=REFERENCE_ONLY"
                      << std::endl;
    }

    // A single rank's verifier failure after all parties previously
    // accepted the proof must block sealing on all four ranks.
    if (std::getenv("PVIA_REG_PREPROVE_SEAL_REVERIFY_FAILURE")) {
        if (rank == 1) backend.SetForcedVerificationFailure(true);
        const bool seal_rejected = !session.SealRegistration();
        const bool repeated_seal_rejected = !session.SealRegistration();
        const bool batch_rejected = !session.BatchCheck().available;
        const bool proof_once =
            backend.prove_calls() == (rank == 0 ? 1ULL : 0ULL);
        const char* public_out =
            std::getenv("PVIA_REG_PREPROVE_PUBLIC_EXPORT");
        const bool no_public_export = !public_out || !*public_out ||
            ::access(public_out, F_OK) != 0;
        const std::string marker =
            RegistrationReceiptReplayLedger::MarkerName(
                local_claim, static_cast<uint32_t>(rank));
        const bool cleaned = !marker.empty() &&
            ::unlink((replay_path + "/" + marker).c_str()) == 0 &&
            ::rmdir(replay_path.c_str()) == 0;
        *consistency_bound = seal_rejected && repeated_seal_rejected &&
            batch_rejected && proof_once && no_public_export && cleaned;
        test_auth.Reset();
        return true;
    }

    // N=4 transactional negative: a second registration with an already
    // accepted identity must poison the entire checkpoint, not permit
    // sealing only its first successful operation. The test contains a
    // real prior signed-origin/VSS/proof transaction, not a mock gate.
    if (std::getenv("PVIA_REG_PREPROVE_DUPLICATE_AFTER_VALID")) {
        const bool duplicate_rejected = !session.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(state),
            hash_field_vector(output), operation_statement,
            owner_state, owner_output, native);
        const bool further_refused = !session.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(state),
            hash_field_vector(output), operation_statement,
            owner_state, owner_output, native);
        const bool seal_refused = !session.SealRegistration();
        const bool batch_refused = !session.BatchCheck().available;
        const bool no_proof_reissued =
            backend.prove_calls() == (rank == 0 ? 1ULL : 0ULL);
        const char* public_out =
            std::getenv("PVIA_REG_PREPROVE_PUBLIC_EXPORT");
        const bool export_refused = !public_out || !*public_out ||
            !signed_origin.ExportApprovedPublicBundle(public_out);
        const bool no_public_export = !public_out || !*public_out ||
            ::access(public_out, F_OK) != 0;
        const std::string marker =
            RegistrationReceiptReplayLedger::MarkerName(
                local_claim, static_cast<uint32_t>(rank));
        const bool cleaned = !marker.empty() &&
            ::unlink((replay_path + "/" + marker).c_str()) == 0 &&
            ::rmdir(replay_path.c_str()) == 0;
        *consistency_bound = duplicate_rejected && further_refused &&
            seal_refused && batch_refused && no_proof_reissued &&
            export_refused && no_public_export && cleaned;
        test_auth.Reset();
        return true;
    }

    if (!session.SealRegistration()) return false;
    const ReferenceShamirBatchResult batch = session.BatchCheck();
    const bool originally_accepted = batch.available && batch.clean &&
        session.registration_consistency_binding() != Digest{} &&
        backend.prove_calls() == (rank == 0 ? 1ULL : 0ULL);
    int local_accepted = originally_accepted ? 1 : 0;
    int globally_accepted = 0;
    MPI_Allreduce(&local_accepted, &globally_accepted,
                  1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    signed_origin.AuthorizePostProofExport(globally_accepted != 0);
    // Publication is a separate, strictly post-proof/post-seal step:
    // it must never occur during origin approval or on proof failure.
    int export_ok = 1;
    if (rank == 0 && globally_accepted) {
        const char* public_path =
            std::getenv("PVIA_REG_PREPROVE_PUBLIC_EXPORT");
        // Both public files belong to the same transaction. Requesting
        // a native-issuer file without an existing paired public path
        // must never create a detached issuer artifact.
        const char* issuer_path =
            std::getenv("PVIA_REG_PREPROVE_NATIVE_ISSUER_EXPORT");
        if (issuer_path && *issuer_path &&
            (!public_path || !*public_path ||
             std::string(issuer_path)==std::string(public_path)))
            export_ok = 0;
        // Preflight both exclusive output paths. Full filesystem
        // atomicity across two separate files is not asserted here.
        auto fresh_public_target = [](const char* path) {
            if (!path || !*path) return true;
            struct stat metadata {};
            if (::lstat(path,&metadata)==0) return false;
            return errno==ENOENT;
        };
        if (!fresh_public_target(public_path) ||
            !fresh_public_target(issuer_path))
            export_ok=0;
        if (export_ok && public_path && *public_path) {
            const Digest expected = signed_origin.ApprovedStatementBinding();
            const Digest key_pin = signed_origin.ApprovedRegistryPin();
            export_ok = expected != Digest{} && key_pin != Digest{} &&
                signed_origin.ExportApprovedPublicBundle(public_path);
            if (export_ok && issuer_path && *issuer_path) {
                export_ok = signed_origin.ExportApprovedNativeIssuerReceipt(
                    issuer_path);
                if (export_ok) {
                    const auto issuer_key =
                        signed_origin.ApprovedNativeIssuerKey();
                    constexpr char HEX[] = "0123456789abcdef";
                    std::string public_key_hex;
                    for (const uint8_t byte : issuer_key) {
                        public_key_hex.push_back(HEX[byte >> 4]);
                        public_key_hex.push_back(HEX[byte & 15]);
                    }
                    std::cout << "PVIA_REG_NATIVE_ISSUER_TEST_PINS:"
                              << " key=" << public_key_hex
                              << " consumed="
                              << signed_origin.ApprovedNativeConsumedBinding().hex()
                              << " issuer_id="
                              << signed_origin.ApprovedNativeIssuerId()
                              << " sequence="
                              << signed_origin.ApprovedNativeIssuerSequence()
                              << (use_configured_key ?
                                      " origin=CONFIGURED_TEST_KEY" :
                                      " origin=SEPARATE_EPHEMERAL_TEST_KEY")
                              << std::endl;
                }
            }
            if (export_ok)
                std::cout << "PVIA_REG_PREPROVE_TEST_PINS: statement="
                          << expected.hex()
                          << " registry=" << key_pin.hex()
                          << " origin=EPHEMERAL_MPI_VSS_TEST_ONLY"
                          << " proof_backend=SYNTHETIC"
                          << std::endl;
        }
    }
    MPI_Bcast(&export_ok, 1, MPI_INT, 0, MPI_COMM_WORLD);

    // A new session instance tries the same execution identity with
    // the SAME persistent ledger directory. Signatures remain valid,
    // but the replay reservation must fail collectively, before Prove.
    ReferenceShamirAuditSession replayed(
        sid, checkpoint, rank, world_size, threshold,
        &backend, nullptr, nullptr, &signed_origin, true);
    const bool replay_rejected = !replayed.RegisterFoldOperation(
        0, ref, challenge, hash_field_vector(state),
        hash_field_vector(output), operation_statement,
        owner_state, owner_output, native);
    const bool proof_not_repeated =
        backend.prove_calls() == (rank == 0 ? 1ULL : 0ULL);
    // Delete only the exact marker and private directory created by
    // this selftest; never clean a caller's working directory.
    const std::string marker =
        RegistrationReceiptReplayLedger::MarkerName(local_claim,
                                                      static_cast<uint32_t>(rank));
    const bool marker_present = !marker.empty() &&
        ::access((replay_path + "/" + marker).c_str(), F_OK) == 0;
    const bool cleaned =
        marker_present &&
        ::unlink((replay_path + "/" + marker).c_str()) == 0 &&
        ::rmdir(replay_path.c_str()) == 0;
    *consistency_bound = originally_accepted && globally_accepted &&
        export_ok && replay_rejected && proof_not_repeated && cleaned;
    test_auth.Reset();
    return true;
}


// Self-test-only registration relation negatives.  The synthetic backend
// above exercises binding and rejection semantics, NOT zero knowledge or a
// production cryptographic proof of native/registered state equality.
bool run_registration_consistency_negative_selftest(
    int rank, int world_size) {
    if (world_size < 3) return false;
    SelfTestRegistrationConsistencyBackend backend;
    const uint64_t sid = 0x5245474e45474154ULL; // REGNEGAT
    const CheckpointId checkpoint = 0x5245474e45470001ULL;
    const F challenge(7, 3);
    const OperationRef ref{0, 0x5245474e45470002ULL};
    std::vector<F> state(8);
    for (size_t i = 0; i < state.size(); ++i)
        state[i] = F(static_cast<long long>(300 + i),
                     static_cast<long long>(900 + 2 * i));
    std::vector<F> output;
    if (!recompute_fold_rs_output(state, challenge, &output)) return false;

    RegistrationConsistencyStatement statement;
    statement.sid = sid;
    statement.checkpoint = checkpoint;
    statement.ref = ref;
    statement.kernel = AuditRelationKernel::FOLD_RS;
    statement.state_element_count = state.size();
    statement.output_element_count = output.size();
    statement.public_state_digest = hash_field_vector(state);
    statement.public_actual_digest = hash_field_vector(output);
    statement.public_challenge_binding = hash_field_vector({challenge});
    statement.native_context.native_state_id = 0x5245474e45470003ULL;
    statement.native_context.authentication_scheme_id =
        0x5245474e45470004ULL;
    statement.native_context.authentication_binding =
        hash_words({sid, checkpoint, 0x4e41544956454155ULL});
    statement.native_context.predecessor_root =
        hash_words({sid, 0x50524544524f4f54ULL});
    statement.native_context.checkpoint_root =
        hash_words({checkpoint, 0x43484b50524f4f54ULL});
    statement.operation_statement_binding =
        hash_words({sid, checkpoint, ref.owner, ref.object_id});
    statement.sharing_transcript_binding =
        hash_words({sid, checkpoint, 0x5653535245474e47ULL});
    statement.statement_binding =
        compute_registration_consistency_statement_binding(statement);
    RegistrationConsistencyWitness witness;
    witness.state_values = state;
    witness.actual_output = output;
    const RegistrationConsistencyProofArtifact proof =
        backend.Prove(statement, witness);
    if (!validate_registration_consistency_proof_artifact(statement, proof) ||
        !backend.Verify(statement, proof))
        return false;

    // Exercise the ACTUAL VSS dealer polynomial, rather than checking a
    // synthetic marker with only public hashes. Dealer-private material
    // is evaluated locally and NEVER sent to the public verifier.
    ReferenceBivariateVss relation_vss(
        rank, world_size, (world_size - 1) / 3);
    std::vector<F> relation_plaintext;
    if (rank == 0) {
        relation_plaintext = state;
        relation_plaintext.insert(relation_plaintext.end(),
                                  output.begin(), output.end());
    }
    std::vector<F> relation_shares;
    ReferenceVssReceipt relation_receipt;
    ReferenceVssDealerWitness relation_dealer;
    ReferenceVssLocalWitness relation_local;
    const bool relation_shared = relation_vss.ShareVectorFromDealerWithWitnesses(
        0, relation_plaintext, &relation_shares, &relation_receipt,
        &relation_dealer, &relation_local);
    int reference_relation_ok = relation_shared &&
        relation_receipt.available && relation_receipt.consistent &&
        validate_reference_vss_local_witness(relation_local) ? 1 : 0;
    if (rank == 0 && reference_relation_ok) {
        RegistrationConsistencyStatement real_statement = statement;
        real_statement.sharing_transcript_binding =
            relation_receipt.transcript_binding;
        real_statement.statement_binding =
            compute_registration_consistency_statement_binding(real_statement);
        RegistrationConsistencyWitness real_witness = witness;
        real_witness.public_challenge = challenge;
        real_witness.sharing_witness_words =
            encode_reference_vss_dealer_witness(relation_dealer);
        // Explicit opt-in test fixture only; this contains private dealer
        // coefficients and MUST NOT be produced by a production prover.
        bool fixture_ok = true;
        if (const char* fixture_path =
                std::getenv("PVIA_REGISTRATION_TEST_VECTOR_OUT")) {
            fixture_ok = [&]() -> bool {
            const auto public_words =
                encode_registration_consistency_statement_words(real_statement);
            if (public_words.size() != 46) return false;
            std::ostringstream json;
            json << "{\"abi_version\":1";
            auto append_words = [&](const char* key,
                                    const std::vector<u64>& values) {
                json << ",\"" << key << "\":[";
                for (size_t i = 0; i < values.size(); ++i) {
                    if (i) json << ',';
                    json << values[i];
                }
                json << ']';
            };
            auto field_words = [](const std::vector<F>& values) {
                std::vector<u64> out;
                for (const F& v : values) {
                    out.push_back(v.real);
                    out.push_back(v.img);
                }
                return out;
            };
            append_words("statement_words", public_words);
            append_words("native_state_words",
                         field_words(real_witness.state_values));
            append_words("actual_output_words",
                         field_words(real_witness.actual_output));
            append_words("public_challenge_words",
                         {challenge.real, challenge.img});
            append_words("vss_dealer_witness_words",
                         real_witness.sharing_witness_words);
            json << "}\n";
            const std::string serialized = json.str();
            const int fd = ::open(fixture_path,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
            if (fd < 0) return false;
            size_t offset = 0;
            while (offset < serialized.size()) {
                const ssize_t n = ::write(fd, serialized.data() + offset,
                                         serialized.size() - offset);
                if (n <= 0) { ::close(fd); return false; }
                offset += static_cast<size_t>(n);
            }
            if (::close(fd) != 0) return false;
            return true;
            }();
        }
        // Join the native captured-state digest relation with the ACTUAL
        // private VSS dealer polynomial, rather than comparing only public
        // statement hashes. This local gate is reference-only, NOT ZK.
        AuditCheckpointView equality_checkpoint;
        equality_checkpoint.id=real_statement.checkpoint;
        equality_checkpoint.phase=Phase::FOLD;
        equality_checkpoint.operations.push_back(real_statement.ref);
        equality_checkpoint.root=
            real_statement.native_context.checkpoint_root;
        equality_checkpoint.sealed=true;
        RegistrationNativeConsumedSnapshot equality_native;
        equality_native.state_values=real_witness.state_values;
        equality_native.actual_output=real_witness.actual_output;
        equality_native.public_challenge=challenge;
        equality_native.pre_vss_claim_binding=hash_words(
            registration_pre_vss_claim_words(real_statement));
        equality_native.consumed_record_binding=
            compute_registration_native_consumed_record_binding(
                real_statement,equality_native,equality_checkpoint);
        const bool full_reference_private_equality=
            verify_reference_registered_native_snapshot_witness_equality(
                real_statement,real_witness,equality_native,
                equality_checkpoint);
        auto changed_native=equality_native;
        changed_native.state_values[0]+=F(1);
        const bool changed_native_state_rejected=
            !verify_reference_registered_native_snapshot_witness_equality(
                real_statement,real_witness,changed_native,
                equality_checkpoint);
        changed_native=equality_native;
        changed_native.actual_output[0]+=F(1);
        const bool changed_native_output_rejected=
            !verify_reference_registered_native_snapshot_witness_equality(
                real_statement,real_witness,changed_native,
                equality_checkpoint);
        changed_native=equality_native;
        changed_native.public_challenge+=F(1);
        const bool changed_native_challenge_rejected=
            !verify_reference_registered_native_snapshot_witness_equality(
                real_statement,real_witness,changed_native,
                equality_checkpoint);
        changed_native=equality_native;
        changed_native.consumed_record_binding=hash_words({0xBADULL});
        const bool changed_native_binding_rejected=
            !verify_reference_registered_native_snapshot_witness_equality(
                real_statement,real_witness,changed_native,
                equality_checkpoint);
        auto changed_equality_checkpoint=equality_checkpoint;
        changed_equality_checkpoint.root=hash_words({0xBADULL});
        const bool changed_native_checkpoint_rejected=
            !verify_reference_registered_native_snapshot_witness_equality(
                real_statement,real_witness,equality_native,
                changed_equality_checkpoint);
        auto changed_equality_witness=real_witness;
        changed_equality_witness.sharing_witness_words.back()^=1ULL;
        const bool changed_private_vss_rejected=
            !verify_reference_registered_native_snapshot_witness_equality(
                real_statement,changed_equality_witness,equality_native,
                equality_checkpoint);
        changed_equality_witness=real_witness;
        changed_equality_witness.state_values[0]+=F(1);
        const bool changed_private_state_rejected=
            !verify_reference_registered_native_snapshot_witness_equality(
                real_statement,changed_equality_witness,equality_native,
                equality_checkpoint);
        // Full VSS coefficient equality is tested here for every native
        // state/output F value. Actual native executor provenance remains
        // separately unproved in this test-only fixture.
        const bool native_vss_reference_gate_passed=
            full_reference_private_equality &&
            changed_native_state_rejected &&
            changed_native_output_rejected &&
            changed_native_challenge_rejected &&
            changed_native_binding_rejected &&
            changed_native_checkpoint_rejected &&
            changed_private_vss_rejected &&
            changed_private_state_rejected;
        const bool accepts_real =
            evaluate_reference_registration_consistency_relation(
                real_statement, real_witness);
        RegistrationConsistencyWitness changed = real_witness;
        changed.state_values[0] += F(1);
        const bool changed_state_rejected =
            !evaluate_reference_registration_consistency_relation(
                real_statement, changed);
        changed = real_witness;
        changed.actual_output[0] += F(1);
        const bool changed_output_rejected =
            !evaluate_reference_registration_consistency_relation(
                real_statement, changed);
        changed = real_witness;
        changed.sharing_witness_words.back() ^= 1ULL;
        const bool changed_vss_rejected =
            !evaluate_reference_registration_consistency_relation(
                real_statement, changed);
        changed = real_witness;
        changed.public_challenge += F(1);
        const bool changed_challenge_rejected =
            !evaluate_reference_registration_consistency_relation(
                real_statement, changed);
        real_statement = statement; // different VSS transcript
        const bool changed_transcript_rejected =
            !evaluate_reference_registration_consistency_relation(
                real_statement, real_witness);
        reference_relation_ok =
            native_vss_reference_gate_passed &&
            fixture_ok && accepts_real &&
            changed_state_rejected && changed_output_rejected &&
            changed_vss_rejected &&
            changed_challenge_rejected && changed_transcript_rejected ? 1 : 0;
    }
    int all_reference_relation_ok = 0;
    MPI_Allreduce(&reference_relation_ok, &all_reference_relation_ok, 1,
                  MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    if (!all_reference_relation_ok) return false;

    auto context_is_rejected = [&](RegistrationConsistencyStatement changed) {
        changed.statement_binding =
            compute_registration_consistency_statement_binding(changed);
        return validate_registration_consistency_statement(changed) &&
            !validate_registration_consistency_proof_artifact(changed, proof) &&
            !backend.Verify(changed, proof);
    };
    RegistrationConsistencyStatement wrong = statement;
    ++wrong.sid;
    if (!context_is_rejected(wrong)) return false;
    wrong = statement;
    ++wrong.checkpoint;
    if (!context_is_rejected(wrong)) return false;
    wrong = statement;
    ++wrong.ref.object_id;
    if (!context_is_rejected(wrong)) return false;
    wrong = statement;
    wrong.public_challenge_binding = hash_field_vector({F(9, 4)});
    if (!context_is_rejected(wrong)) return false;
    wrong = statement;
    wrong.sharing_transcript_binding =
        hash_words({sid, checkpoint, 0x4449464656535321ULL});
    if (!context_is_rejected(wrong)) return false;
    wrong = statement;
    wrong.operation_statement_binding =
        hash_words({sid, checkpoint, 0x444946464f504552ULL});
    if (!context_is_rejected(wrong)) return false;
    wrong = statement;
    wrong.public_actual_digest = hash_field_vector({F(101, 29)});
    if (!context_is_rejected(wrong)) return false;
    wrong = statement;
    wrong.native_context.native_state_id += 1;
    if (!context_is_rejected(wrong)) return false;
    wrong = statement;
    wrong.native_context.authentication_scheme_id += 1;
    if (!context_is_rejected(wrong)) return false;
    wrong = statement;
    wrong.native_context.authentication_binding =
        hash_words({sid, 0x4241444e41544956ULL});
    if (!context_is_rejected(wrong)) return false;
    wrong = statement;
    wrong.native_context.predecessor_root =
        hash_words({sid, 0x4241445052454443ULL});
    if (!context_is_rejected(wrong)) return false;
    wrong = statement;
    wrong.native_context.checkpoint_root =
        hash_words({checkpoint, 0x42414443484b5054ULL});
    if (!context_is_rejected(wrong)) return false;
    wrong = statement;
    wrong.native_context.authentication_binding = Digest{};
    wrong.statement_binding =
        compute_registration_consistency_statement_binding(wrong);
    if (validate_registration_consistency_statement(wrong) ||
        backend.Verify(wrong, proof)) return false;

    RegistrationConsistencyWitness mismatched_witness = witness;
    mismatched_witness.state_values[0] += F(1);
    if (backend.Prove(statement, mismatched_witness).available) return false;
    mismatched_witness = witness;
    mismatched_witness.actual_output[0] += F(1);
    if (backend.Prove(statement, mismatched_witness).available) return false;

    RegistrationConsistencyProofArtifact tampered = proof;
    ++tampered.proof_words[0];
    if (validate_registration_consistency_proof_artifact(statement, tampered))
        return false;
    tampered.proof_commitment =
        compute_registration_consistency_proof_commitment(tampered);
    if (backend.Verify(statement, tampered)) return false;

    FailClosedRegistrationConsistencyProofBackend fail_closed;
    if (production_ready_registration_consistency_capabilities(
            fail_closed.Capabilities()) ||
        fail_closed.Prove(statement, witness).available ||
        fail_closed.Verify(statement, proof))
        return false;

    // This additional four-party run checks that an owner whose private
    // registration input differs from its public context cannot register,
    // seal, or enter a batch-check path. It exits before VSS networking.
    const int threshold = (world_size - 1) / 3;
    ReferenceShamirAuditSession disagree(
        sid + 3, checkpoint, rank, world_size, threshold, &backend);
    RegistrationNativeContext inconsistent = statement.native_context;
    if (rank == 0)
        inconsistent.predecessor_root =
            hash_words({sid, 0x53494e474c455241ULL}); // SINGLERA
    std::vector<F> honest_state;
    std::vector<F> honest_output;
    if (rank == 0) {
        honest_state = state;
        honest_output = output;
    }
    if (disagree.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(state),
            hash_field_vector(output),
            hash_words({sid + 3, checkpoint, ref.owner, ref.object_id}),
            honest_state, honest_output, inconsistent) ||
        disagree.SealRegistration() || disagree.BatchCheck().available)
        return false;
    ReferenceShamirAuditSession rejected(
        sid + 1, checkpoint, rank, world_size, threshold, &backend);
    std::vector<F> owner_state;
    std::vector<F> owner_output;
    if (rank == 0) {
        owner_state = state;
        owner_state[0] += F(1);
        owner_output = output;
    }
    const bool accepted = rejected.RegisterFoldOperation(
        0, ref, challenge, hash_field_vector(state),
        hash_field_vector(output),
        hash_words({sid + 1, checkpoint, ref.owner, ref.object_id}),
        owner_state, owner_output, statement.native_context);
    if (accepted || rejected.SealRegistration() ||
        rejected.BatchCheck().available)
        return false;
    // Separately check that a missing native-provenance context is rejected
    // even when the owner provides a consistent private state/output.
    ReferenceShamirAuditSession missing_native(
        sid + 2, checkpoint, rank, world_size, threshold, &backend);
    if (rank == 0) {
        owner_state = state;
    }
    if (missing_native.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(state),
            hash_field_vector(output),
            hash_words({sid + 2, checkpoint, ref.owner, ref.object_id}),
            owner_state, owner_output) ||
        missing_native.SealRegistration() ||
        missing_native.BatchCheck().available)
        return false;
    return true;
}

bool run_multiplication_consistency_wiring_selftest(
    int rank, int world_size, bool* consistency_bound,
    bool* missing_backend_rejected) {
    if (!consistency_bound || !missing_backend_rejected || world_size < 3)
        return false;
    const int threshold = (world_size - 1) / 3;
    ReferenceBivariateVss vss(rank, world_size, threshold);
    ReferenceShamirMpc mpc(rank, world_size, threshold);
    if (!vss.valid() || !mpc.valid() ||
        !mpc.detectable_degree_reduction_available())
        return false;

    const F lhs_secret(13, 5);
    const F rhs_secret(17, 2);
    std::vector<F> lhs_plaintext;
    std::vector<F> rhs_plaintext;
    if (rank == 0) lhs_plaintext = {lhs_secret};
    const int rhs_dealer = world_size > 1 ? 1 : 0;
    if (rank == rhs_dealer) rhs_plaintext = {rhs_secret};
    std::vector<F> lhs_shares;
    std::vector<F> rhs_shares;
    ReferenceVssReceipt lhs_receipt;
    ReferenceVssReceipt rhs_receipt;
    ReferenceVssDealerWitness lhs_dealer_witness;
    ReferenceVssDealerWitness rhs_dealer_witness;
    ReferenceVssLocalWitness lhs_local_witness;
    ReferenceVssLocalWitness rhs_local_witness;
    if (!vss.ShareVectorFromDealerWithWitnesses(
            0, lhs_plaintext, &lhs_shares, &lhs_receipt,
            &lhs_dealer_witness, &lhs_local_witness) ||
        !vss.ShareVectorFromDealerWithWitnesses(
            rhs_dealer, rhs_plaintext, &rhs_shares, &rhs_receipt,
            &rhs_dealer_witness, &rhs_local_witness) ||
        lhs_shares.size() != 1 || rhs_shares.size() != 1 ||
        lhs_receipt.transcript_binding == Digest{} ||
        rhs_receipt.transcript_binding == Digest{} ||
        !validate_reference_vss_local_witness(lhs_local_witness) ||
        !validate_reference_vss_local_witness(rhs_local_witness))
        return false;

    ReferenceMultiplicationConsistencyContext context;
    context.sid = 0x4d554c434f4e5354ULL; // MULCONST
    context.checkpoint = 0x4d554c434f4e0001ULL;
    context.multiplication_id = 1;
    context.lhs_sharing_binding = lhs_receipt.transcript_binding;
    context.rhs_sharing_binding = rhs_receipt.transcript_binding;
    context.context_binding = hash_words({
        0x4d554c434f4e4354ULL, context.sid, context.checkpoint,
        context.multiplication_id});

    ReferenceMultiplicationConsistencyLocalWitness local_witness;
    local_witness.lhs_sharing_witness_words =
        encode_reference_vss_local_witness(lhs_local_witness);
    local_witness.rhs_sharing_witness_words =
        encode_reference_vss_local_witness(rhs_local_witness);
    if (local_witness.lhs_sharing_witness_words.empty() ||
        local_witness.rhs_sharing_witness_words.empty())
        return false;

    ReferenceShamirMpc fail_closed_mpc(rank, world_size, threshold);
    F rejected_product(0);
    Digest rejected_binding{};
    *missing_backend_rejected = !fail_closed_mpc.MultiplyWithConsistency(
        lhs_shares.front(), rhs_shares.front(), context, local_witness,
        &rejected_product, &rejected_binding);

    SelfTestMultiplicationConsistencyBackend backend;
    if (!mpc.SetMultiplicationConsistencyProofBackend(&backend) ||
        !mpc.multiplication_consistency_available())
        return false;
    F product_share(0);
    Digest multiplication_binding{};
    if (!mpc.MultiplyWithConsistency(
            lhs_shares.front(), rhs_shares.front(), context, local_witness,
            &product_share, &multiplication_binding) ||
        multiplication_binding == Digest{})
        return false;
    F opened_product(0);
    Digest opening_binding{};
    if (!mpc.Open(product_share, &opened_product, &opening_binding) ||
        opening_binding == Digest{})
        return false;
    *consistency_bound =
        opened_product == lhs_secret * rhs_secret &&
        backend.relation_reference_count() > 0 &&
        backend.vss_local_prove_count() > 0;
    return true;
}

bool run_robust_opening_and_coin_selftest(
    int rank, int world_size,
    bool* corrected_open, bool* excessive_fault_rejected,
    bool* public_coin_bound, bool* degree_reduction_bound,
    bool* random_sharing_bound) {
    if (!corrected_open || !excessive_fault_rejected || !public_coin_bound ||
        !degree_reduction_bound || !random_sharing_bound || world_size < 3)
        return false;
    const int threshold = (world_size - 1) / 3;
    ReferenceShamirMpc mpc(rank, world_size, threshold);
    if (!mpc.valid() || !mpc.robust_opening_available()) return false;

    const int dealer = 0;
    const F secret(0x12345, 0x6789);
    std::vector<F> plaintext;
    if (rank == dealer) plaintext = {secret};
    std::vector<F> shares;
    if (!mpc.ShareVectorFromDealer(dealer, plaintext, &shares) ||
        shares.size() != 1)
        return false;

    F one_fault_share = shares.front();
    if (rank < threshold) one_fault_share += F(17, 9);
    F corrected(0);
    Digest corrected_binding{};
    const bool corrected_ok =
        mpc.Open(one_fault_share, &corrected, &corrected_binding);
    *corrected_open = corrected_ok && corrected == secret &&
        corrected_binding != Digest{};

    F too_many_faults_share = shares.front();
    if (rank <= threshold) too_many_faults_share += F(23, 11);
    F should_not_open(0);
    Digest rejected_binding{};
    const bool excessive_opened =
        mpc.Open(too_many_faults_share, &should_not_open, &rejected_binding);
    *excessive_fault_rejected = !excessive_opened;

    Digest seed{};
    Digest coin_binding{};
    *public_coin_bound =
        mpc.JointPublicSeed(&seed, &coin_binding) &&
        seed != Digest{} && coin_binding != Digest{};

    F random_test_share(0);
    Digest random_test_binding{};
    *random_sharing_bound = mpc.RandomSharedField(
        &random_test_share, &random_test_binding) &&
        random_test_binding != Digest{} &&
        mpc.detectable_degree_reduction_available();


    const F lhs_secret(5, 2);
    const F rhs_secret(9, 4);
    std::vector<F> product_plaintext;
    if (rank == dealer) product_plaintext = {lhs_secret, rhs_secret};
    std::vector<F> product_inputs;
    if (!mpc.ShareVectorFromDealer(
            dealer, product_plaintext, &product_inputs) ||
        product_inputs.size() != 2)
        return false;
    F product_share(0);
    Digest multiplication_binding{};
    const bool multiplication_ok = mpc.Multiply(
        product_inputs[0], product_inputs[1], &product_share,
        &multiplication_binding);
    F opened_product(0);
    Digest product_opening_binding{};
    const bool product_opened = multiplication_ok &&
        mpc.Open(product_share, &opened_product, &product_opening_binding);
    *degree_reduction_bound = product_opened &&
        opened_product == lhs_secret * rhs_secret &&
        multiplication_binding != Digest{} &&
        product_opening_binding != Digest{} &&
        mpc.detectable_degree_reduction_available();
    return true;
}
bool run_authenticated_passive_opening_selftest(
    int rank, int world_size, bool* exercised, bool* opening_bound) {
    if (!exercised || !opening_bound || world_size < 2 ||
        rank < 0 || rank >= world_size)
        return false;
    *exercised = false;
    *opening_bound = false;
    // n=3,t=1 is the smallest valid 2t<n configuration outside 3t<n.
    // Other world sizes leave this targeted branch not applicable.
    if (world_size != 3) {
        *opening_bound = true;
        return true;
    }
    AuthenticatedMpcExchange exchange(rank, world_size);
    if (!exchange.production_authenticated_ready()) {
        *opening_bound = true;
        return true;
    }
    *exercised = true;
    constexpr int threshold = 1;
    if (2 * threshold >= world_size || 3 * threshold < world_size)
        return false;
    ReferenceShamirMpc mpc(rank, world_size, threshold);
    const uint64_t sid = 0x4155544850415353ULL; // AUTHPASS
    const CheckpointId checkpoint = 0x4155544850410001ULL;
    if (!mpc.SetAuthenticatedTransport(&exchange, sid, checkpoint) ||
        !mpc.authenticated_transport_available() ||
        mpc.robust_opening_available())
        return false;
    const F secret(37, 11);
    std::vector<F> dealer_plaintext;
    if (rank == 0) dealer_plaintext = {secret};
    std::vector<F> local_shares;
    if (!mpc.ShareVectorFromDealer(
            0, dealer_plaintext, &local_shares) ||
        local_shares.size() != 1)
        return false;
    F opened(0);
    Digest opening_binding{};
    if (!mpc.Open(local_shares.front(), &opened, &opening_binding))
        return false;
    *opening_bound = opened == secret && opening_binding != Digest{};
    return true;
}

bool run_authenticated_session_transport_selftest(
    int rank, int world_size, bool* exercised, bool* transport_bound) {
    if (!exercised || !transport_bound || world_size < 3) return false;
    *exercised = false;
    *transport_bound = false;
    auto fail = [&](const char* stage) {
        if (rank == 0)
            std::cerr << "[PVIA][auth-session-selftest] failed-stage="
                      << stage << "\n";
        return false;
    };
    AuthenticatedMpcExchange exchange(rank, world_size);
    if (!exchange.production_authenticated_ready()) {
        *transport_bound = true;
        return true;
    }
    *exercised = true;
    const int threshold = (world_size - 1) / 3;
    if (3 * threshold >= world_size) return fail("threshold");
    const uint64_t sid = 0x4155544853455353ULL; // AUTHSESS
    const CheckpointId checkpoint = 0x4155544853450001ULL;
    SelfTestMultiplicationConsistencyBackend multiplication_backend;
    ReferenceShamirAuditSession session(
        sid, checkpoint, rank, world_size, threshold,
        nullptr, &multiplication_backend, &exchange);
    if (!session.authenticated_transport_enabled() ||
        session.authenticated_transport_capability_binding() !=
            exchange.ProductionCapabilityBinding())
        return fail("transport-install");
    const F challenge(11, 2);
    std::vector<F> state(8);
    for (size_t i = 0; i < state.size(); ++i)
        state[i] = F(static_cast<long long>(700 + i),
                     static_cast<long long>(900 + i));
    std::vector<F> output;
    if (!recompute_fold_rs_output(state, challenge, &output))
        return fail("recompute");
    std::vector<F> owner_state;
    std::vector<F> owner_output;
    if (rank == 0) {
        owner_state = state;
        owner_output = output;
    }
    const OperationRef ref{0U, 0x41555448534d4b31ULL};
    const Digest statement = hash_words({
        sid, checkpoint, ref.owner, ref.object_id,
        0x4155544853544d54ULL});
    if (!session.RegisterFoldOperation(
            0U, ref, challenge, hash_field_vector(state),
            hash_field_vector(output), statement,
            owner_state, owner_output))
        return fail("register");
    if (!session.SealRegistration())
        return fail("seal-registration");
    const Digest session_transport =
        session.authenticated_transport_transcript_binding();
    if (session_transport == Digest{})
        return fail("registration-transport-binding");
    const ReferenceShamirBatchResult batch = session.BatchCheck();
    const Digest final_session_transport =
        session.authenticated_transport_transcript_binding();
    *transport_bound = batch.available && batch.clean &&
        batch.operation_count == 1 &&
        batch.registration_binding != Digest{} &&
        batch.public_coin_transcript_binding != Digest{} &&
        batch.challenge_binding != Digest{} &&
        batch.multiplication_consistency_binding != Digest{} &&
        batch.opening_transcript_binding != Digest{} &&
        final_session_transport != Digest{} &&
        final_session_transport != session_transport;
    if (!*transport_bound && rank == 0) {
        std::cerr << "[PVIA][auth-session-selftest] available="
                  << (batch.available ? 1 : 0)
                  << " clean=" << (batch.clean ? 1 : 0)
                  << " operations=" << batch.operation_count
                  << " registration="
                  << (batch.registration_binding != Digest{} ? 1 : 0)
                  << " public-coin="
                  << (batch.public_coin_transcript_binding != Digest{} ? 1 : 0)
                  << " challenge="
                  << (batch.challenge_binding != Digest{} ? 1 : 0)
                  << " opening="
                  << (batch.opening_transcript_binding != Digest{} ? 1 : 0)
                  << " session-transport-before="
                  << (session_transport != Digest{} ? 1 : 0)
                  << " session-transport-after="
                  << (final_session_transport != Digest{} ? 1 : 0)
                  << " multiplication="
                  << (batch.multiplication_consistency_binding != Digest{} ? 1 : 0)
                  << " session-transport-evolved="
                  << (final_session_transport != session_transport ? 1 : 0)
                  << "\n";
    }
    return true;
}

bool run_preactivated_subset_localization_selftest(
    int rank, int world_size, bool* subset_bound,
    bool* localization_bound) {
    if (!subset_bound || !localization_bound || world_size < 3)
        return false;
    *subset_bound = false;
    *localization_bound = false;
    if (world_size < 4) {
        *subset_bound = true;
        *localization_bound = true;
        return true;
    }

    const int threshold = (world_size - 1) / 3;
    if (3 * threshold >= world_size) return false;
    const uint64_t sid = 0x5052454143545355ULL; // PREACTSU
    const CheckpointId checkpoint = 0x5052454143540001ULL;
    AuthenticatedMpcExchange exchange(rank, world_size);
    const AuthenticatedMpcExchange* exchange_ptr =
        exchange.production_authenticated_ready() ? &exchange : nullptr;
    ReferenceShamirAuditSession session(
        sid, checkpoint, rank, world_size, threshold,
        nullptr, nullptr, exchange_ptr);

    const uint32_t faulty_owner = static_cast<uint32_t>(world_size / 2);
    std::vector<OperationRef> refs;
    std::vector<F> post_activation_shadow;
    for (int owner = 0; owner < world_size; ++owner) {
        const F challenge(owner + 11);
        std::vector<F> state(8);
        for (size_t i = 0; i < state.size(); ++i)
            state[i] = F(500 * (owner + 1) + static_cast<int>(i) + 1);
        std::vector<F> output;
        if (!recompute_fold_rs_output(state, challenge, &output))
            return false;
        if (static_cast<uint32_t>(owner) == faulty_owner && !output.empty())
            output.front() += F(1);

        const OperationRef ref{
            static_cast<uint32_t>(owner),
            static_cast<uint64_t>(0x6000 + owner)};
        refs.push_back(ref);
        std::vector<F> owner_state;
        std::vector<F> owner_output;
        if (rank == owner) {
            owner_state = state;
            owner_output = output;
            post_activation_shadow = output;
        }
        const Digest statement = hash_words({
            sid, checkpoint, static_cast<u64>(owner), ref.object_id,
            0x5052454143545354ULL}); // PREACTST
        if (!session.RegisterFoldOperation(
                static_cast<uint32_t>(owner), ref, challenge,
                hash_field_vector(state), hash_field_vector(output),
                statement, owner_state, owner_output))
            return false;
    }
    if (!session.SealRegistration()) return false;

    // Mutate the caller-owned shadow after activation. Subsequent checks must
    // depend only on session-resident Shamir/VSS shares, never on this source.
    for (F& value : post_activation_shadow) value = F(0);

    auto domain_for = [&](const std::vector<OperationRef>& subset,
                          u64 depth, u64 side) {
        std::vector<u64> words = {
            0x505245535542444dULL, sid, checkpoint, depth, side,
            static_cast<u64>(subset.size())}; // PRESUBDM
        for (const OperationRef& ref : subset) {
            words.push_back(ref.owner);
            words.push_back(ref.object_id);
        }
        return hash_words(words);
    };

    const ReferenceShamirSubsetResult full = session.BatchCheckSubset(
        refs, domain_for(refs, 0, 2), 1);
    const uint32_t clean_owner = (faulty_owner + 1U) %
        static_cast<uint32_t>(world_size);
    const std::vector<OperationRef> clean_single = {
        refs[static_cast<size_t>(clean_owner)]};
    const ReferenceShamirSubsetResult clean = session.BatchCheckSubset(
        clean_single, domain_for(clean_single, 0, 3), 2);
    *subset_bound = full.available && !full.clean &&
        full.subset_binding != Digest{} && full.challenge_binding != Digest{} &&
        full.opening_transcript_binding != Digest{} &&
        clean.available && clean.clean && clean.subset_binding != Digest{};
    if (!*subset_bound) return true;

    std::vector<OperationRef> candidates = refs;
    uint32_t depth = 0;
    uint64_t round_tag = 10;
    while (candidates.size() > 1) {
        const size_t mid = candidates.size() / 2;
        std::vector<OperationRef> left(
            candidates.begin(), candidates.begin() + mid);
        const ReferenceShamirSubsetResult left_result =
            session.BatchCheckSubset(
                left, domain_for(left, depth, 0), round_tag++);
        if (!left_result.available) return true;
        if (!left_result.clean) {
            candidates = std::move(left);
        } else {
            std::vector<OperationRef> right(
                candidates.begin() + mid, candidates.end());
            const ReferenceShamirSubsetResult right_result =
                session.BatchCheckSubset(
                    right, domain_for(right, depth, 1), round_tag++);
            if (!right_result.available || right_result.clean) return true;
            candidates = std::move(right);
        }
        ++depth;
    }
    const OperationRef expected{
        faulty_owner, static_cast<uint64_t>(0x6000 + faulty_owner)};
    *localization_bound = candidates.size() == 1 &&
        candidates.front() == expected;
    return true;
}

} // namespace

bool run_registration_origin_preprove_gate_selftest(
    int rank, int world_size) {
    bool registration_bound = false;
    const bool ok = run_registration_consistency_wiring_selftest(
        rank, world_size, &registration_bound);
    int local = ok && registration_bound ? 1 : 0;
    int global = 0;
    MPI_Allreduce(&local, &global, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    if (rank == 0 &&
        std::getenv("PVIA_REG_PREPROVE_DESCRIPTOR_FAULT")) {
        std::cout << "PVIA_REG_DESCRIPTOR_PREFLIGHT_NEGATIVE: "
                  << (global ? "PASS" : "FAIL")
                  << " rank_count=" << world_size
                  << " fault="
                  << std::getenv("PVIA_REG_PREPROVE_DESCRIPTOR_FAULT")
                  << " pre_vss_agreement=REJECTED"
                  << " sealed=false batch_unavailable=true"
                  << " prover_calls=ZERO public_export=ABSENT"
                  << " proof_backend=SYNTHETIC"
                  << " production_native_equality=NOT_ATTESTED"
                  << std::endl;
        return global != 0;
    }
    if (rank == 0 &&
        std::getenv("PVIA_REG_P101_SP1_FORCE_VERIFIER_REJECT_RANK")) {
        std::cout << "PVIA_REG_P101_ALL_RANK_GROTH16_NEGATIVE: "
                  << (global ? "PASS" : "FAIL")
                  << " rank_count=" << world_size
                  << " verified_ranks=3"
                  << " single_verifier_rejected=true"
                  << " sealed=false batch_unavailable=true"
                  << " public_export=ABSENT"
                  << " source=REFERENCE_ONLY"
                  << std::endl;
        return global != 0;
    }
    if (rank == 0 && std::getenv("PVIA_REG_P101_SP1_GROTH16_OUTPUT_DIR") &&
        std::getenv("PVIA_REG_P101_SP1_EXECUTE_EXPECT_REJECT")) {
        std::cout << "PVIA_REG_P101_LIVE_GROTH16: "
                  << (global ? "PASS" : "FAIL")
                  << " rank_count=4 fresh_mpi_vss=YES"
                  << " groth16_verify=REJECTED"
                  << " sealed=false batch_unavailable=true"
                  << " public_export=ABSENT"
                  << " native_source=REFERENCE_ONLY"
                  << std::endl;
        return global != 0;
    }
    if (rank == 0 && std::getenv("PVIA_REG_P101_SP1_EXECUTE_HOST") &&
        std::getenv("PVIA_REG_P101_SP1_EXECUTE_EXPECT_REJECT")) {
        std::cout << "PVIA_REG_P101_LIVE_SP1_GUEST: "
                  << (global ? "PASS" : "FAIL")
                  << " rank_count=" << world_size
                  << " current_mpi_vss=YES"
                  << " guest_execution=REJECTED"
                  << " sealed=false batch_unavailable=true"
                  << " public_export=ABSENT"
                  << " proof_backend=SYNTHETIC_NOT_GROTH16"
                  << std::endl;
        return global != 0;
    }
    if (rank == 0 &&
        std::getenv("PVIA_REG_PREPROVE_SEAL_REVERIFY_FAILURE")) {
        std::cout << "PVIA_REG_SEAL_REVERIFY_NEGATIVE: "
                  << (global ? "PASS" : "FAIL")
                  << " rank_count=" << world_size
                  << " first_registration=SIGNED_VSS_PROOF"
                  << " single_verifier_drift=INJECTED"
                  << " collective_reverify=REJECTED"
                  << " sealed=false batch_unavailable=true"
                  << " public_export=ABSENT"
                  << " proof_backend=SYNTHETIC"
                  << " production_native_equality=NOT_ATTESTED"
                  << std::endl;
        return global != 0;
    }
    if (rank == 0 &&
        std::getenv("PVIA_REG_PREPROVE_DUPLICATE_AFTER_VALID")) {
        std::cout << "PVIA_REG_PARTIAL_SEAL_NEGATIVE: "
                  << (global ? "PASS" : "FAIL")
                  << " rank_count=" << world_size
                  << " first_registration=SIGNED_VSS_PROOF"
                  << " second_registration=DUPLICATE_REJECTED"
                  << " session_poisoned=true"
                  << " sealed=false batch_unavailable=true"
                  << " public_export=ABSENT"
                  << " proof_backend=SYNTHETIC"
                  << " production_native_equality=NOT_ATTESTED"
                  << std::endl;
        return global != 0;
    }
    if (rank == 0 &&
        std::getenv("PVIA_REG_PREPROVE_FORCE_PROOF_FAILURE")) {
        std::cout << "PVIA_REG_PROOF_FAILURE_EXPORT_GATE: "
                  << (global ? "PASS" : "FAIL")
                  << " proof_backend=SYNTHETIC_FORCED_FAILURE"
                  << " export=ABSENT"
                  << " owner_prove_calls=ONE"
                  << " native_equality=NOT_ATTESTED"
                  << std::endl;
        return global != 0;
    }
    if (rank == 0 && global &&
        std::getenv("PVIA_REG_P101_SP1_GROTH16_OUTPUT_DIR"))
        std::cout << "PVIA_REG_P101_LIVE_GROTH16: PASS"
                  << " rank_count=4 fresh_mpi_vss=YES"
                  << " groth16_verify=ACCEPTED_BEFORE_REFERENCE_PROOF"
                  << " public_pair=AFTER_GATE"
                  << " native_source=REFERENCE_ONLY"
                  << " full_release_gate_verified=false"
                  << std::endl;
    if (rank == 0 && global &&
        std::getenv("PVIA_REG_P101_SP1_EXECUTE_HOST"))
        std::cout << "PVIA_REG_P101_LIVE_SP1_GUEST: PASS"
                  << " rank_count=" << world_size
                  << " current_mpi_vss=YES"
                  << " guest_execution=ACCEPTED_BEFORE_REFERENCE_PROOF"
                  << " public_pair=AFTER_GATE"
                  << " proof_backend=SYNTHETIC_NOT_GROTH16"
                  << std::endl;
    if (rank == 0 && global)
        std::cout << "PVIA_REG_REFERENCE_PROOF_PRODUCTION_DENIAL: PASS"
                  << " rank_count=" << world_size
                  << " synthetic_capability=REFERENCE_ONLY"
                  << " ordinary_runtime_registration=REJECTED"
                  << " reference_test_override=EXPLICIT_ONLY"
                  << std::endl;
    if (rank == 0)
        std::cout << "PVIA_REG_ORIGIN_PREPROVE: "
                  << (global ? "PASS" : "FAIL")
                  << " mode=EPHEMERAL_SIGNED_MPI_REGISTRATION"
                  << " missing_origin=REJECTED"
                  << " mixed_config=REJECTED"
                  << " corrupt_signature=REJECTED"
                  << " local_pre_sign_barrier=PASS"
                  << " presharing_receipt=VERIFIED"
                  << " paired_public_evidence=VERIFIED"
                  << " native_consumed_snapshot=VERIFIED"
                  << " native_issuer_receipt=VERIFIED"
                  << " native_issuer_signature_tamper=REJECTED"
                  << " native_issuer_scope_drift=REJECTED"
                  << " native_issuer_sequence_drift=REJECTED"
                  << " native_issuer_wrong_pin=REJECTED"
                  << " native_issuer_missing=REJECTED"
                  << " native_issuer_mpi_pin_mismatch=REJECTED"
                  << " snapshot_state_drift=REJECTED"
                  << " snapshot_output_drift=REJECTED"
                  << " snapshot_challenge_drift=REJECTED"
                  << " snapshot_checkpoint_drift=REJECTED"
                  << " missing_consumed_snapshot=REJECTED"
                  << " stale_consumed_snapshot=REJECTED"
                  << " owner_state_substitution_pre_vss=REJECTED"
                  << " owner_output_substitution_pre_vss=REJECTED"
                  << " owner_challenge_substitution_pre_vss=REJECTED"
                  << " paired_receipt_tamper=REJECTED"
                  << " receipt_tamper=REJECTED"
                  << " missing_receipt=REJECTED"
                  << " replay_second_session=REJECTED"
                  << " missing_replay_ledger=REJECTED"
                  << " missing_external_anchor=REJECTED"
                  << " local_output_drift=REJECTED"
                  << " local_share_drift=REJECTED"
                  << " prove_on_reject=ZERO"
                  << " native_equality=NOT_ATTESTED"
                  << std::endl;
    return global != 0;
}

bool run_reference_shamir_mpc_selftest(int rank, int world_size) {
    const char* acceptance_capture_only =
        std::getenv("PVIA_MC_PROVIDER_ACCEPTANCE_CAPTURE_ONLY");
    if (acceptance_capture_only && acceptance_capture_only[0] == '1' &&
        acceptance_capture_only[1] == 0) {
        const char* vector_dir = std::getenv("PVIA_MC_PROVIDER_VECTOR_DIR");
        const char* export_all =
            std::getenv("PVIA_MC_PROVIDER_VECTOR_EXPORT_ALL");
        if (!vector_dir || vector_dir[0] == 0 ||
            !export_all || export_all[0] != '1' || export_all[1] != 0)
            return false;

        SelfTestMultiplicationConsistencyBackend capture_backend;
        MultiplicationConsistencyProviderAcceptanceResult capture_result;
        const bool acceptance_capture_pass =
            run_multiplication_consistency_provider_acceptance(
                rank, world_size, capture_backend, &capture_result,
                MPI_COMM_WORLD);
        const int local_capture_ok =
            acceptance_capture_pass && capture_result.available &&
            capture_result.capabilities_ready &&
            capture_result.multiplication_verified &&
            capture_result.zero_case_verified &&
            capture_result.nonzero_case_verified &&
            capture_result.completed_stage == 11 &&
            capture_result.acceptance_binding != Digest{} &&
            capture_backend.relation_reference_count() == 3 &&
            capture_backend.vss_local_prove_count() == 1 &&
            capture_backend.linear_prove_count() == 2 ? 1 : 0;
        int global_capture_ok = 0;
        MPI_Allreduce(&local_capture_ok, &global_capture_ok, 1,
                      MPI_INT, MPI_MIN, MPI_COMM_WORLD);
        if (rank == 0) {
            std::cout << "[PVIA][mc-acceptance-vector-capture] "
                      << (global_capture_ok ? "PASS" : "FAIL")
                      << " ranks=" << world_size
                      << " proof_inputs_per_rank=3"
                      << " vss_local=1 linear=2"
                      << " capture_backend=SELFTEST_ONLY"
                      << " cryptographic_acceptance=NOT_CLAIMED"
                      << std::endl;
        }
        return global_capture_ok == 1;
    }
    bool authenticated_passive_open_exercised = false;
    bool authenticated_passive_open_bound = false;
    const bool authenticated_passive_open_run =
        run_authenticated_passive_opening_selftest(
            rank, world_size, &authenticated_passive_open_exercised,
            &authenticated_passive_open_bound);
    bool authenticated_transport_exercised = false;
    bool authenticated_transport_bound = false;
    const bool authenticated_transport_run =
        run_authenticated_session_transport_selftest(
            rank, world_size, &authenticated_transport_exercised,
            &authenticated_transport_bound);
    const bool equivocation_evidence_bound =
        !authenticated_transport_exercised ||
        run_authenticated_mpc_equivocation_evidence_selftest(
            rank, world_size);
    const bool robust_abort_output_bound =
        !authenticated_transport_exercised ||
        run_robust_audit_abort_output_selftest(rank, world_size);

    ReferenceShamirBatchResult clean;
    ReferenceShamirBatchResult faulty;
    const bool clean_run = run_one_reference_session(
        rank, world_size, false, &clean);
    const bool faulty_run = run_one_reference_session(
        rank, world_size, true, &faulty);
    bool preactivated_subset_bound = false;
    bool preactivated_localization_bound = false;
    const bool preactivated_subset_run =
        run_preactivated_subset_localization_selftest(
            rank, world_size, &preactivated_subset_bound,
            &preactivated_localization_bound);

    bool corrected_open = false;
    bool excessive_fault_rejected = false;
    bool public_coin_bound = false;
    bool degree_reduction_bound = false;
    bool random_sharing_bound = false;
    const bool robust_primitives_run =
        run_robust_opening_and_coin_selftest(
            rank, world_size, &corrected_open,
            &excessive_fault_rejected, &public_coin_bound,
            &degree_reduction_bound, &random_sharing_bound);

    bool registration_consistency_bound = false;
    const bool registration_consistency_run =
        run_registration_consistency_wiring_selftest(
            rank, world_size, &registration_consistency_bound);
    const bool registration_context_rejected =
        run_registration_consistency_negative_selftest(rank, world_size);

    bool multiplication_consistency_bound = false;
    bool missing_multiplication_backend_rejected = false;
    const bool multiplication_consistency_run =
        run_multiplication_consistency_wiring_selftest(
            rank, world_size, &multiplication_consistency_bound,
            &missing_multiplication_backend_rejected);

    ReferenceShamirBatchResult strong_clean;
    ReferenceShamirBatchResult strong_faulty;
    const bool strong_clean_run = run_strong_batch_once(
        rank, world_size, false, &strong_clean);
    const bool strong_faulty_run = run_strong_batch_once(
        rank, world_size, true, &strong_faulty);
    const bool strong_batch_bound =
        strong_clean_run && strong_clean.clean &&
        strong_clean.multiplication_consistency_binding != Digest{} &&
        strong_faulty_run && !strong_faulty.clean &&
        strong_faulty.multiplication_consistency_binding != Digest{};

    const bool batch_transcripts_bound =
        clean.public_coin_transcript_binding != Digest{} &&
        clean.challenge_binding != Digest{} &&
        clean.opening_transcript_binding != Digest{} &&
        faulty.public_coin_transcript_binding != Digest{} &&
        faulty.opening_transcript_binding != Digest{};
    int local_ok = authenticated_passive_open_run &&
        authenticated_passive_open_bound && authenticated_transport_run &&
        authenticated_transport_bound && equivocation_evidence_bound &&
        robust_abort_output_bound &&
        clean_run && clean.available && clean.clean &&
        faulty_run && faulty.available && !faulty.clean &&
        preactivated_subset_run && preactivated_subset_bound &&
        preactivated_localization_bound &&
        batch_transcripts_bound && robust_primitives_run &&
        corrected_open && excessive_fault_rejected && public_coin_bound &&
        degree_reduction_bound && random_sharing_bound &&
        registration_consistency_run && registration_consistency_bound &&
        registration_context_rejected &&
        multiplication_consistency_run && multiplication_consistency_bound &&
        missing_multiplication_backend_rejected && strong_batch_bound ? 1 : 0;
    int global_ok = 0;
    MPI_Allreduce(&local_ok, &global_ok, 1, MPI_INT, MPI_MIN,
                  MPI_COMM_WORLD);
    if (rank == 0) {
        const int threshold = world_size > 0 ? (world_size - 1) / 2 : -1;
        const int robust_threshold = world_size > 0 ? (world_size - 1) / 3 : -1;
        std::cout << "[PVIA][shamir-mpc-selftest] threshold=" << threshold
                  << " robust-threshold=" << robust_threshold
                  << " operations=" << clean.operation_count
                  << " auth-passive-open="
                  << (world_size != 3
                          ? "N/A"
                          : (authenticated_passive_open_exercised
                                 ? (authenticated_passive_open_bound ? "BOUND" : "FAIL")
                                 : "UNANCHORED-SKIP"))
                  << " auth-transport="
                  << (authenticated_transport_exercised
                          ? (authenticated_transport_bound ? "BOUND" : "FAIL")
                          : "UNANCHORED-SKIP")
                  << " equivocation-evidence="
                  << (authenticated_transport_exercised
                          ? (equivocation_evidence_bound ? "BOUND" : "FAIL")
                          : "UNANCHORED-SKIP")
                  << " robust-abort="
                  << (authenticated_transport_exercised
                          ? (robust_abort_output_bound ? "BOUND" : "FAIL")
                          : "UNANCHORED-SKIP")
                  << " clean=" << (clean.clean ? "PASS" : "FAIL")
                  << " mismatch=" << (!faulty.clean ? "DETECTED" : "MISSED")
                  << " preactivated-subset="
                  << (preactivated_subset_bound ? "BOUND" : "FAIL")
                  << " preactivated-localization="
                  << (preactivated_localization_bound ? "BOUND" : "FAIL")
                  << " robust-open=" << (corrected_open ? "PASS" : "FAIL")
                  << " over-threshold="
                  << (excessive_fault_rejected ? "REJECTED" : "ACCEPTED")
                  << " public-coin=" << (public_coin_bound ? "BOUND" : "FAIL")
                  << " degree-reduction="
                  << (degree_reduction_bound ? "VSS-BOUND" : "FAIL")
                  << " random-sharing="
                  << (random_sharing_bound ? "VSS-BOUND" : "FAIL")
                  << " registration-consistency="
                  << (registration_consistency_bound ? "BOUND" : "FAIL")
                  << " registration-negatives="
                  << (registration_context_rejected ? "REJECTED" : "FAILED")
                  << " registration-vss-reference="
                  << (registration_context_rejected ? "BOUND" : "FAIL")
                  << " multiplication-consistency="
                  << (multiplication_consistency_bound ? "BOUND" : "FAIL")
                  << " missing-mul-backend="
                  << (missing_multiplication_backend_rejected
                          ? "REJECTED" : "ACCEPTED")
                  << " strong-batch="
                  << (strong_clean.clean ? "BOUND" : "FAIL")
                  << " strong-mismatch="
                  << (strong_faulty_run && !strong_faulty.clean
                          ? "DETECTED" : "MISSED")
                  << " transcript="
                  << (batch_transcripts_bound ? "BOUND" : "MISSING")
                  << " result=" << (global_ok ? "PASS" : "FAIL")
                  << "\n";
    }
    return global_ok != 0;
}

} // namespace pvia
