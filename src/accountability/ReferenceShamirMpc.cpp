#include "ReferenceShamirMpc.hpp"
#include "ReferenceBivariateVss.hpp"
#include "AuthenticatedMpcAbortEvidence.hpp"
#include "PublicJudge.hpp"
#include "TransferAuthentication.hpp"
#include "MultiplicationConsistencySharingWitness.hpp"
#include "MultiplicationConsistencyWitnessRelation.hpp"
#include "ProtocolTrafficMetrics.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <limits>
#include <utility>
#include <vector>

namespace pvia {
namespace {

constexpr u64 SHAMIR_SEED_DOMAIN = 0x505653484d534545ULL; // PVSHMSEE
constexpr u64 COMMIT_DOMAIN = 0x50564352434f4d4dULL;      // PVCRCOMM
constexpr u64 COMMIT_TRANSCRIPT_DOMAIN = 0x5056435254524e53ULL; // PVCRTRNS
constexpr u64 OPEN_REVEAL_DOMAIN = 0x50564f50454e4352ULL; // PVOPENCR
constexpr u64 OPEN_RESULT_DOMAIN = 0x50564f50454e5253ULL; // PVOPENRS
constexpr u64 DEGREE2T_OPEN_REVEAL_DOMAIN =
    0x50564432544f504eULL; // PVD2TOPN
constexpr u64 DEGREE2T_OPEN_RESULT_DOMAIN =
    0x5056443254524553ULL; // PVD2TRES
constexpr u64 SEED_REVEAL_DOMAIN = 0x5056534545444352ULL; // PVSEEDCR
constexpr u64 MULTIPLY_TRANSCRIPT_DOMAIN = 0x50564d554c545452ULL; // PVMULTTR
constexpr u64 ZERO_TEST_TRANSCRIPT_DOMAIN = 0x50565a45524f5452ULL; // PVZEROTR
constexpr u64 LOCAL_SUM_TRANSCRIPT_DOMAIN = 0x50564c53554d5452ULL; // PVLSUMTR
constexpr u64 RANDOM_SHARE_TRANSCRIPT_DOMAIN = 0x5056524e44534852ULL; // PVRNDSHR
constexpr u64 RANDOM_MASK_POOL_TRANSCRIPT_DOMAIN =
    0x5056524d534b504cULL; // PVRMSKPL
constexpr u64 MULTIPLY_CONSISTENCY_REQUEST_DOMAIN =
    0x50564d554c435251ULL; // PVMULCRQ
constexpr u64 STRONG_ZERO_TEST_TRANSCRIPT_DOMAIN =
    0x50565a45524f4353ULL; // PVZEROCS
constexpr u64 AUTH_MPC_PROTOCOL_DOMAIN = 0x505653484d415554ULL; // PVSHMAUT
constexpr u64 AUTH_KIND_COMMIT_COUNT = 0x434f4d434e543031ULL; // COMCNT01
constexpr u64 AUTH_KIND_COMMITMENTS = 0x434f4d4d49543031ULL; // COMMIT01
constexpr u64 AUTH_KIND_REVEALS = 0x52455645414c3031ULL; // REVEAL01
constexpr u64 AUTH_KIND_RANDOM_VSS = 0x524e445653533031ULL; // RNDVSS01
constexpr u64 AUTH_KIND_LOCAL_SUM_VSS = 0x4c53555653533031ULL; // LSU VSS01
constexpr u64 AUTH_KIND_MULTIPLY_VSS = 0x4d554c5653533031ULL; // MULVSS01
constexpr u64 AUTH_KIND_RANDOM_MODE = 0x524e444d4f444531ULL; // RNDMODE1
constexpr u64 AUTH_KIND_RANDOM_READY = 0x524e445245414431ULL; // RNDREAD1
constexpr u64 AUTH_KIND_MULTIPLY_MODE = 0x4d554c4d4f444531ULL; // MULMODE1
constexpr u64 RS_PRODUCT_PARITY_DOMAIN = 0x5253504152495459ULL; // RSPARITY
constexpr u64 AUTH_KIND_PROOF_MODE = 0x5052464d4f444531ULL; // PRFMODE1
constexpr u64 AUTH_KIND_PROOF_READY = 0x5052465245414431ULL; // PRFREAD1
constexpr u64 AUTH_KIND_PROOF_CAP = 0x5052464341503031ULL; // PRFCAP01
constexpr u64 AUTH_KIND_CONTEXT_READY = 0x4354585245414431ULL; // CTXREAD1
constexpr u64 AUTH_KIND_REQUEST_BINDING = 0x525142494e443031ULL; // RQBIND01
constexpr u64 AUTH_KIND_PROVER_STATUS = 0x5052565354415431ULL; // PRVSTAT1
constexpr u64 AUTH_KIND_PROVER_PREFLIGHT = 0x5052565052464c31ULL; // PRVPRFL1
constexpr u64 AUTH_KIND_PROOF_BROADCAST = 0x5052464252435431ULL; // PRFBRCT1
constexpr u64 AUTH_KIND_PROOF_BATCH_SIZE = 0x5052464253495a31ULL; // PRFBSIZ1
constexpr u64 AUTH_KIND_PROOF_BATCH_DATA = 0x5052464244415431ULL; // PRFBDAT1
constexpr u64 AUTH_KIND_PROOF_STATEMENTS = 0x5052465354415431ULL; // PRFSTAT1
constexpr u64 AUTH_KIND_VERIFY_AGREEMENT = 0x5652464147524531ULL; // VRFAGRE1
constexpr u64 AUTH_KIND_PROOF_SET = 0x5052465345543031ULL; // PRFSET01
constexpr u64 AUTH_KIND_FAILURE_CERT_VERIFY =
    0x4641494c56455249ULL; // FAILVERI
constexpr u64 AUTH_KIND_FAILURE_CERT_BINDING =
    0x4641494c42494e44ULL; // FAILBIND
constexpr u64 AUTH_KIND_ZERO_PREFLIGHT_READY = 0x5a50524652445931ULL; // ZPRFRDY1
constexpr u64 AUTH_KIND_ZERO_PREFLIGHT_BINDING = 0x5a50524642494e31ULL; // ZPRFBIN1
constexpr u64 AUTH_KIND_ZERO_RANDOM_PAIR = 0x5a524e4450414952ULL; // ZRNDPAIR
constexpr u64 ZERO_PREFLIGHT_PAIR_DOMAIN = 0x50565a5052465041ULL; // PVZPRFPA
constexpr u64 ZERO_RANDOM_PAIR_DOMAIN = 0x50565a524e445041ULL; // PVZRNDPA
constexpr u64 AUTH_KIND_DIRECT_SHAPE = 0x4453484150453031ULL; // DSHAPE01
constexpr u64 AUTH_KIND_DIRECT_SHAPE_READY = 0x4453485244593031ULL; // DSHRDY01
constexpr u64 AUTH_KIND_DIRECT_DEALER_STATUS = 0x4444535441543031ULL; // DDSTAT01
constexpr u64 AUTH_KIND_DIRECT_SHARES = 0x4453484152453031ULL; // DSHARE01
constexpr u64 DIRECT_SHARE_TRANSCRIPT_DOMAIN = 0x5056444952534852ULL; // PVDIRSHR

void pack_field(const F& value, u64* out) {
    out[0] = value.real;
    out[1] = value.img;
}

F unpack_field(const u64* in) {
    return F(static_cast<long long>(in[0]),
             static_cast<long long>(in[1]));
}

bool all_ranks_true(int local, MPI_Comm comm) {
    int global = 0;
    int world_size = 0;
    MPI_Comm_size(comm, &world_size);
    MPI_Allreduce(&local, &global, 1, MPI_INT, MPI_MIN, comm);
    record_control_allreduce(sizeof(int), world_size);
    return global != 0;
}

bool all_ranks_same_digest(
    const Digest& digest, int world_size, MPI_Comm comm) {
    if (world_size <= 0) return false;
    const size_t digest_bytes = digest.bytes.size();
    std::vector<uint8_t> gathered(
        static_cast<size_t>(world_size) * digest_bytes);
    MPI_Allgather(digest.bytes.data(), static_cast<int>(digest_bytes), MPI_BYTE,
                  gathered.data(), static_cast<int>(digest_bytes), MPI_BYTE,
                  comm);
    record_control_allgather(static_cast<uint64_t>(digest_bytes), world_size);
    for (int i = 0; i < world_size; ++i) {
        const uint8_t* begin = gathered.data() +
            static_cast<size_t>(i) * digest_bytes;
        if (!std::equal(digest.bytes.begin(), digest.bytes.end(), begin))
            return false;
    }
    return true;
}

void append_digest_words(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

Digest digest_from_bytes(const uint8_t* bytes) {
    Digest digest{};
    if (bytes)
        std::memcpy(digest.bytes.data(), bytes, digest.bytes.size());
    return digest;
}

Digest digest_from_words(const std::vector<u64>& words, size_t offset) {
    Digest digest{};
    if (offset > words.size() || words.size() - offset < 4) return digest;
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(digest.bytes.data() + 8 * i, &words[offset + i], 8);
    return digest;
}

} // namespace
ReferenceShamirMpc::ReferenceShamirMpc(
    int rank, int world_size, int threshold, MPI_Comm comm,
    const MultiplicationConsistencyProofBackend*
        multiplication_consistency_backend)
    : rank_(rank), world_size_(world_size), threshold_(threshold), comm_(comm),
      multiplication_consistency_backend_(multiplication_consistency_backend) {}

bool ReferenceShamirMpc::valid() const {
    return world_size_ > 0 && rank_ >= 0 && rank_ < world_size_ &&
           threshold_ >= 0 && 2 * threshold_ < world_size_;
}

bool ReferenceShamirMpc::SetAuthenticatedTransport(
    const AuthenticatedMpcExchange* exchange,
    uint64_t sid, CheckpointId checkpoint) {
    if (!exchange) {
        authenticated_exchange_ = nullptr;
        transport_sid_ = 0;
        transport_checkpoint_ = 0;
        transport_sequence_ = 1;
        passive_random_mode_cached_ = false;
        passive_random_mode_binding_ = Digest{};
        passive_multiply_mode_cached_ = false;
        passive_multiply_mode_binding_ = Digest{};
        passive_random_mask_pool_.clear();
        passive_random_mask_bindings_.clear();
        passive_random_mask_next_ = 0;
        return true;
    }
    if (sid == 0 || checkpoint == 0 ||
        !exchange->production_authenticated_ready())
        return false;
    authenticated_exchange_ = exchange;
    transport_sid_ = sid;
    transport_checkpoint_ = checkpoint;
    transport_sequence_ = 1;
    passive_random_mode_cached_ = false;
    passive_random_mode_binding_ = Digest{};
    passive_multiply_mode_cached_ = false;
    passive_multiply_mode_binding_ = Digest{};
    passive_random_mask_pool_.clear();
    passive_random_mask_bindings_.clear();
    passive_random_mask_next_ = 0;
    return true;
}

bool ReferenceShamirMpc::authenticated_transport_available() const {
    return authenticated_exchange_ && transport_sid_ != 0 &&
        transport_checkpoint_ != 0 &&
        authenticated_exchange_->production_authenticated_ready();
}

Digest ReferenceShamirMpc::authenticated_transport_capability_binding() const {
    return authenticated_transport_available()
        ? authenticated_exchange_->ProductionCapabilityBinding() : Digest{};
}

AuthenticatedMpcMessageContext ReferenceShamirMpc::NextTransportContext(
    u64 protocol_domain, u64 message_kind, uint64_t round) const {
    AuthenticatedMpcMessageContext context;
    if (!authenticated_transport_available() || protocol_domain == 0 ||
        message_kind == 0)
        return context;
    context.protocol_domain = protocol_domain;
    context.sid = transport_sid_;
    context.checkpoint = transport_checkpoint_;
    context.round = round;
    context.sequence = transport_sequence_++;
    context.message_kind = message_kind;
    return context;
}

bool ReferenceShamirMpc::CollectiveSameWord(
    u64 local_value, u64 message_kind, uint64_t round,
    u64* agreed_value, Digest* transcript_binding) const {
    if (!agreed_value || message_kind == 0) return false;
    if (authenticated_transport_available()) {
        std::vector<u64> gathered;
        Digest binding{};
        if (!authenticated_exchange_->AllGatherWords(
                NextTransportContext(
                    AUTH_MPC_PROTOCOL_DOMAIN, message_kind, round),
                {local_value}, &gathered, &binding) ||
            gathered.size() != static_cast<size_t>(world_size_))
            return false;
        for (u64 value : gathered)
            if (value != gathered.front()) return false;
        *agreed_value = gathered.front();
        if (transcript_binding) *transcript_binding = binding;
        return binding != Digest{};
    }
    std::vector<u64> gathered(static_cast<size_t>(world_size_));
    MPI_Allgather(&local_value, 1, MPI_UINT64_T,
                  gathered.data(), 1, MPI_UINT64_T, comm_);
    record_control_allgather(sizeof(u64), world_size_);
    for (u64 value : gathered)
        if (value != gathered.front()) return false;
    *agreed_value = gathered.front();
    if (transcript_binding) *transcript_binding = Digest{};
    return true;
}

bool ReferenceShamirMpc::CollectiveSameDigest(
    const Digest& local_digest, u64 message_kind, uint64_t round,
    Digest* transcript_binding) const {
    if (local_digest == Digest{} || message_kind == 0) return false;
    if (authenticated_transport_available()) {
        std::vector<u64> local_words;
        append_digest_words(local_digest, &local_words);
        std::vector<u64> gathered;
        Digest binding{};
        if (!authenticated_exchange_->AllGatherWords(
                NextTransportContext(
                    AUTH_MPC_PROTOCOL_DOMAIN, message_kind, round),
                local_words, &gathered, &binding) ||
            gathered.size() != static_cast<size_t>(world_size_) * 4)
            return false;
        const Digest first = digest_from_words(gathered, 0);
        if (first == Digest{}) return false;
        for (int rank = 1; rank < world_size_; ++rank)
            if (digest_from_words(gathered,
                    static_cast<size_t>(rank) * 4) != first)
                return false;
        if (transcript_binding) *transcript_binding = binding;
        return binding != Digest{};
    }
    const bool same = all_ranks_same_digest(local_digest, world_size_, comm_);
    if (transcript_binding) *transcript_binding = Digest{};
    return same;
}

bool ReferenceShamirMpc::CollectiveAllTrue(
    bool local_value, u64 message_kind, uint64_t round,
    Digest* transcript_binding) const {
    if (message_kind == 0) return false;
    if (authenticated_transport_available()) {
        bool all_true = false;
        Digest binding{};
        if (!authenticated_exchange_->AllTrue(
                NextTransportContext(
                    AUTH_MPC_PROTOCOL_DOMAIN, message_kind, round),
                local_value, &all_true, &binding))
            return false;
        if (transcript_binding) *transcript_binding = binding;
        return all_true && binding != Digest{};
    }
    const bool result = all_ranks_true(local_value ? 1 : 0, comm_);
    if (transcript_binding) *transcript_binding = Digest{};
    return result;
}


bool ReferenceShamirMpc::RandomField(F* value) const {
    if (!value) return false;
    std::vector<F> values;
    if (!RandomFieldVector(1, &values) || values.size() != 1) return false;
    *value = values.front();
    return true;
}

bool ReferenceShamirMpc::RandomFieldVector(
    size_t count, std::vector<F>* values) const {
    if (!values) return false;
    values->clear();
    if (count == 0) return true;
    if (count > std::numeric_limits<size_t>::max() / 2) return false;
    std::vector<u64> words(count * 2);
    unsigned char* bytes = reinterpret_cast<unsigned char*>(words.data());
    const size_t total_bytes = words.size() * sizeof(u64);
    constexpr size_t MAX_RAND_CHUNK = 1u << 20;
    size_t offset = 0;
    while (offset < total_bytes) {
        const size_t chunk = std::min(MAX_RAND_CHUNK, total_bytes - offset);
        if (RAND_bytes(bytes + offset, static_cast<int>(chunk)) != 1)
            return false;
        offset += chunk;
    }
    values->resize(count);
    for (size_t i = 0; i < count; ++i) {
        words[2 * i] %= F::mod;
        words[2 * i + 1] %= F::mod;
        (*values)[i] = F(static_cast<long long>(words[2 * i]),
                         static_cast<long long>(words[2 * i + 1]));
    }
    return true;
}


bool ReferenceShamirMpc::RandomWordVector(
    size_t count, std::vector<u64>* words) const {
    if (!words) return false;
    words->assign(count, 0);
    if (count == 0) return true;
    unsigned char* bytes = reinterpret_cast<unsigned char*>(words->data());
    const size_t total_bytes = count * sizeof(u64);
    constexpr size_t MAX_RAND_CHUNK = 1u << 20;
    size_t offset = 0;
    while (offset < total_bytes) {
        const size_t chunk = std::min(MAX_RAND_CHUNK, total_bytes - offset);
        if (RAND_bytes(bytes + offset, static_cast<int>(chunk)) != 1)
            return false;
        offset += chunk;
    }
    return true;
}

bool ReferenceShamirMpc::CommitRevealWords(
    u64 domain, const std::vector<u64>& local_payload,
    std::vector<u64>* all_payloads, Digest* transcript_binding) const {
    if (!valid() || !all_payloads || local_payload.empty()) return false;
    constexpr size_t NONCE_WORDS = 4;
    if (local_payload.size() >
        static_cast<size_t>(std::numeric_limits<int>::max()) - NONCE_WORDS)
        return false;
    const bool authenticated = authenticated_transport_available();
    const u64 local_payload_words = static_cast<u64>(local_payload.size());
    std::vector<u64> payload_word_counts(static_cast<size_t>(world_size_), 0);
    Digest count_transport_binding{};
    if (authenticated) {
        std::vector<u64> gathered_counts;
        if (!authenticated_exchange_->AllGatherWords(
                NextTransportContext(AUTH_MPC_PROTOCOL_DOMAIN,
                    AUTH_KIND_COMMIT_COUNT, domain),
                {local_payload_words}, &gathered_counts,
                &count_transport_binding) ||
            gathered_counts.size() != static_cast<size_t>(world_size_))
            return false;
        payload_word_counts = std::move(gathered_counts);
    } else {
        MPI_Allgather(
            &local_payload_words, 1, MPI_UINT64_T,
            payload_word_counts.data(), 1, MPI_UINT64_T, comm_);
        record_control_allgather(sizeof(u64), world_size_);
    }
    for (u64 count : payload_word_counts)
        if (count != local_payload_words) return false;

    std::vector<u64> nonce;
    if (!RandomWordVector(NONCE_WORDS, &nonce)) return false;
    std::vector<u64> commitment_words = {
        COMMIT_DOMAIN, domain,
        static_cast<u64>(world_size_),
        static_cast<u64>(threshold_),
        static_cast<u64>(rank_),
        static_cast<u64>(local_payload.size())};
    commitment_words.insert(
        commitment_words.end(), local_payload.begin(), local_payload.end());
    commitment_words.insert(
        commitment_words.end(), nonce.begin(), nonce.end());
    const Digest local_commitment = hash_words(commitment_words);
    if (local_commitment == Digest{}) return false;

    std::vector<Digest> commitments(static_cast<size_t>(world_size_));
    Digest commitment_transport_binding{};
    if (authenticated) {
        std::vector<u64> local_commitment_words;
        append_digest_words(local_commitment, &local_commitment_words);
        std::vector<u64> gathered_commitment_words;
        if (!authenticated_exchange_->AllGatherWords(
                NextTransportContext(AUTH_MPC_PROTOCOL_DOMAIN,
                    AUTH_KIND_COMMITMENTS, domain),
                local_commitment_words, &gathered_commitment_words,
                &commitment_transport_binding) ||
            gathered_commitment_words.size() !=
                static_cast<size_t>(world_size_) * 4)
            return false;
        for (int participant = 0; participant < world_size_; ++participant)
            commitments[static_cast<size_t>(participant)] =
                digest_from_words(gathered_commitment_words,
                    static_cast<size_t>(participant) * 4);
    } else {
        const size_t digest_bytes = local_commitment.bytes.size();
        if (digest_bytes > static_cast<size_t>(std::numeric_limits<int>::max()))
            return false;
        std::vector<uint8_t> gathered(
            static_cast<size_t>(world_size_) * digest_bytes);
        MPI_Allgather(
            local_commitment.bytes.data(), static_cast<int>(digest_bytes), MPI_BYTE,
            gathered.data(), static_cast<int>(digest_bytes), MPI_BYTE, comm_);
        record_control_allgather(static_cast<uint64_t>(digest_bytes), world_size_);
        for (int participant = 0; participant < world_size_; ++participant)
            commitments[static_cast<size_t>(participant)] = digest_from_bytes(
                gathered.data() + static_cast<size_t>(participant) * digest_bytes);
    }

    std::vector<u64> local_reveal = local_payload;
    local_reveal.insert(local_reveal.end(), nonce.begin(), nonce.end());
    std::vector<u64> reveals;
    Digest reveal_transport_binding{};
    if (authenticated) {
        if (!authenticated_exchange_->AllGatherWords(
                NextTransportContext(AUTH_MPC_PROTOCOL_DOMAIN,
                    AUTH_KIND_REVEALS, domain),
                local_reveal, &reveals, &reveal_transport_binding) ||
            reveals.size() !=
                static_cast<size_t>(world_size_) * local_reveal.size())
            return false;
    } else {
        const int reveal_count = static_cast<int>(local_reveal.size());
        reveals.resize(static_cast<size_t>(world_size_) * local_reveal.size());
        MPI_Allgather(
            local_reveal.data(), reveal_count, MPI_UINT64_T,
            reveals.data(), reveal_count, MPI_UINT64_T, comm_);
        record_control_allgather(
            static_cast<uint64_t>(local_reveal.size() * sizeof(u64)),
            world_size_);
    }

    all_payloads->assign(
        static_cast<size_t>(world_size_) * local_payload.size(), 0);
    std::vector<u64> transcript_words = {
        COMMIT_TRANSCRIPT_DOMAIN, domain,
        authenticated ? 1ULL : 0ULL,
        static_cast<u64>(world_size_),
        static_cast<u64>(threshold_),
        static_cast<u64>(local_payload.size())};
    if (authenticated) {
        append_digest_words(authenticated_transport_capability_binding(),
                            &transcript_words);
        append_digest_words(count_transport_binding, &transcript_words);
        append_digest_words(commitment_transport_binding, &transcript_words);
        append_digest_words(reveal_transport_binding, &transcript_words);
    }
    for (int participant = 0; participant < world_size_; ++participant) {
        const size_t reveal_offset =
            static_cast<size_t>(participant) * local_reveal.size();
        std::vector<u64> expected_words = {
            COMMIT_DOMAIN, domain,
            static_cast<u64>(world_size_),
            static_cast<u64>(threshold_),
            static_cast<u64>(participant),
            static_cast<u64>(local_payload.size())};
        expected_words.insert(
            expected_words.end(),
            reveals.begin() + static_cast<std::ptrdiff_t>(reveal_offset),
            reveals.begin() + static_cast<std::ptrdiff_t>(
                reveal_offset + local_reveal.size()));
        const Digest expected_commitment = hash_words(expected_words);
        const Digest received_commitment =
            commitments[static_cast<size_t>(participant)];
        if (expected_commitment == Digest{} ||
            expected_commitment != received_commitment)
            return false;
        append_digest_words(received_commitment, &transcript_words);
        for (size_t j = 0; j < local_reveal.size(); ++j)
            transcript_words.push_back(reveals[reveal_offset + j]);
        for (size_t j = 0; j < local_payload.size(); ++j)
            (*all_payloads)[static_cast<size_t>(participant) *
                                local_payload.size() + j] =
                reveals[reveal_offset + j];
    }
    const Digest transcript = hash_words(transcript_words);
    if (transcript == Digest{}) return false;
    if (transcript_binding) *transcript_binding = transcript;
    return true;
}

bool ReferenceShamirMpc::RobustDecodeShamir(
    const std::vector<F>& shares, F* opened) const {
    if (!opened || !robust_opening_available() ||
        shares.size() != static_cast<size_t>(world_size_))
        return false;

    auto solve_full_rank = [](
        std::vector<std::vector<F>> matrix,
        std::vector<F> rhs,
        size_t variables,
        std::vector<F>* solution) -> bool {
        if (!solution || matrix.size() != rhs.size() || variables == 0)
            return false;
        std::vector<int> pivot_row(variables, -1);
        size_t row = 0;
        for (size_t col = 0; col < variables; ++col) {
            size_t pivot = row;
            while (pivot < matrix.size() &&
                   matrix[pivot][col] == F(0))
                ++pivot;
            if (pivot == matrix.size()) return false;
            if (pivot != row) {
                std::swap(matrix[pivot], matrix[row]);
                std::swap(rhs[pivot], rhs[row]);
            }
            const F inv = matrix[row][col].inv();
            for (size_t c = col; c < variables; ++c)
                matrix[row][c] *= inv;
            rhs[row] *= inv;

            for (size_t r = 0; r < matrix.size(); ++r) {
                if (r == row || matrix[r][col] == F(0)) continue;
                const F factor = matrix[r][col];
                for (size_t c = col; c < variables; ++c)
                    matrix[r][c] =
                        matrix[r][c] - factor * matrix[row][c];
                rhs[r] = rhs[r] - factor * rhs[row];
            }
            pivot_row[col] = static_cast<int>(row);
            ++row;
        }
        for (size_t r = row; r < matrix.size(); ++r) {
            bool all_zero = true;
            for (size_t c = 0; c < variables; ++c) {
                if (matrix[r][c] != F(0)) {
                    all_zero = false;
                    break;
                }
            }
            if (all_zero && rhs[r] != F(0)) return false;
        }
        solution->assign(variables, F(0));
        for (size_t col = 0; col < variables; ++col) {
            if (pivot_row[col] < 0) return false;
            (*solution)[col] = rhs[static_cast<size_t>(pivot_row[col])];
        }
        return true;
    };

    auto evaluate = [](const std::vector<F>& coefficients, const F& x) {
        F value(0);
        for (size_t i = coefficients.size(); i-- > 0;)
            value = value * x + coefficients[i];
        return value;
    };

    const int degree = threshold_;
    for (int errors = 0; errors <= threshold_; ++errors) {
        const int q_degree = degree + errors;
        const size_t variables =
            static_cast<size_t>(q_degree + 1 + errors);
        if (variables > shares.size()) break;

        std::vector<std::vector<F>> matrix(
            shares.size(), std::vector<F>(variables, F(0)));
        std::vector<F> rhs(shares.size(), F(0));
        for (int i = 0; i < world_size_; ++i) {
            const F x(i + 1);
            const F y = shares[static_cast<size_t>(i)];
            F power(1);
            for (int j = 0; j <= q_degree; ++j) {
                matrix[static_cast<size_t>(i)][static_cast<size_t>(j)] = power;
                power *= x;
            }
            power = F(1);
            for (int j = 0; j < errors; ++j) {
                matrix[static_cast<size_t>(i)][
                    static_cast<size_t>(q_degree + 1 + j)] =
                    F(0) - y * power;
                power *= x;
            }
            F x_to_errors(1);
            for (int j = 0; j < errors; ++j) x_to_errors *= x;
            rhs[static_cast<size_t>(i)] = y * x_to_errors;
        }

        std::vector<F> solution;
        if (!solve_full_rank(matrix, rhs, variables, &solution))
            continue;

        std::vector<F> q(
            solution.begin(),
            solution.begin() + static_cast<std::ptrdiff_t>(q_degree + 1));
        std::vector<F> error_locator(
            static_cast<size_t>(errors + 1), F(0));
        for (int j = 0; j < errors; ++j)
            error_locator[static_cast<size_t>(j)] =
                solution[static_cast<size_t>(q_degree + 1 + j)];
        error_locator[static_cast<size_t>(errors)] = F(1);

        std::vector<F> remainder = q;
        std::vector<F> polynomial(
            static_cast<size_t>(degree + 1), F(0));
        bool division_valid = true;
        for (int k = q_degree; k >= errors; --k) {
            const int quotient_index = k - errors;
            const F coefficient = remainder[static_cast<size_t>(k)];
            if (quotient_index > degree && coefficient != F(0)) {
                division_valid = false;
                break;
            }
            if (quotient_index <= degree)
                polynomial[static_cast<size_t>(quotient_index)] = coefficient;
            for (int j = 0; j <= errors; ++j) {
                const size_t index =
                    static_cast<size_t>(quotient_index + j);
                remainder[index] =
                    remainder[index] -
                    coefficient * error_locator[static_cast<size_t>(j)];
            }
        }
        if (!division_valid) continue;
        bool exact_division = true;
        for (int j = 0; j < errors; ++j) {
            if (remainder[static_cast<size_t>(j)] != F(0)) {
                exact_division = false;
                break;
            }
        }
        if (!exact_division) continue;

        int mismatches = 0;
        for (int i = 0; i < world_size_; ++i) {
            if (evaluate(polynomial, F(i + 1)) !=
                shares[static_cast<size_t>(i)])
                ++mismatches;
        }
        if (mismatches <= errors) {
            *opened = polynomial.front();
            return true;
        }
    }
    return false;
}

F ReferenceShamirMpc::LagrangeAtZero(
    int point_index, int point_count) const {
    const F xi(point_index + 1);
    F coefficient(1);
    for (int j = 0; j < point_count; ++j) {
        if (j == point_index) continue;
        const F xj(j + 1);
        coefficient *= (-xj) * (xi - xj).inv();
    }
    return coefficient;
}
bool ReferenceShamirMpc::ShareVectorFromDealer(
    int dealer, const std::vector<F>& dealer_plaintext,
    std::vector<F>* local_shares) const {
    return ShareVectorFromDealerInternal(
        dealer, dealer_plaintext, local_shares, nullptr, 0);
}

bool ReferenceShamirMpc::ShareVectorFromDealerKnownSize(
    int dealer, const std::vector<F>& dealer_plaintext,
    size_t authenticated_element_count,
    std::vector<F>* local_shares) const {
    if (authenticated_element_count == 0 ||
        !authenticated_transport_available())
        return false;
    return ShareVectorFromDealerInternal(
        dealer, dealer_plaintext, local_shares, nullptr,
        authenticated_element_count);
}

bool ReferenceShamirMpc::ShareVectorFromDealerInternal(
    int dealer, const std::vector<F>& dealer_plaintext,
    std::vector<F>* local_shares, Digest* transport_binding,
    size_t authenticated_element_count) const {
    if (!valid() || !local_shares || dealer < 0 || dealer >= world_size_)
        return false;
    if (transport_binding) *transport_binding = Digest{};
    const bool authenticated = authenticated_transport_available();
    std::vector<Digest> auth_bindings;

    const bool shape_already_authenticated =
        authenticated_element_count != 0;
    if (shape_already_authenticated && !authenticated)
        return false;

    u64 element_count = shape_already_authenticated
        ? static_cast<u64>(authenticated_element_count)
        : (rank_ == dealer
            ? static_cast<u64>(dealer_plaintext.size()) : 0ULL);
    if (!shape_already_authenticated) {
        if (authenticated) {
            std::vector<u64> shape_payload;
            if (rank_ == dealer) shape_payload = {element_count};
            std::vector<u64> received_shape;
            Digest binding{};
            if (!authenticated_exchange_->BroadcastWords(
                    NextTransportContext(
                        AUTH_MPC_PROTOCOL_DOMAIN,
                        AUTH_KIND_DIRECT_SHAPE,
                        static_cast<uint64_t>(dealer)),
                    dealer, shape_payload, &received_shape, &binding) ||
                received_shape.size() != 1 || binding == Digest{})
                return false;
            element_count = received_shape.front();
            auth_bindings.push_back(binding);
        } else {
            MPI_Bcast(&element_count, 1, MPI_UINT64_T, dealer, comm_);
            record_control_broadcast(
                sizeof(u64), dealer, rank_, world_size_);
        }
    }

    const bool local_shape_ok = element_count > 0 &&
        element_count <= static_cast<u64>(
            std::numeric_limits<size_t>::max() / 2) &&
        (rank_ != dealer || dealer_plaintext.size() == element_count);
    if (!shape_already_authenticated) {
        if (authenticated) {
            Digest binding{};
            if (!CollectiveAllTrue(
                    local_shape_ok, AUTH_KIND_DIRECT_SHAPE_READY,
                    static_cast<uint64_t>(dealer), &binding))
                return false;
            auth_bindings.push_back(binding);
        } else if (!all_ranks_true(
                       local_shape_ok ? 1 : 0, comm_)) {
            return false;
        }
    }

    const size_t count = static_cast<size_t>(element_count);
    const size_t words_per_rank = count * 2;
    std::vector<u64> send_words;
    int dealer_random_ok = local_shape_ok ? 1 : 0;
    if (rank_ == dealer && dealer_random_ok) {
        if (words_per_rank > std::numeric_limits<size_t>::max() /
                                 static_cast<size_t>(world_size_)) {
            dealer_random_ok = 0;
        } else {
            send_words.resize(static_cast<size_t>(world_size_) * words_per_rank);
        }
        std::vector<F> coefficients;
        if (dealer_random_ok && threshold_ > 0) {
            if (count > std::numeric_limits<size_t>::max() /
                            static_cast<size_t>(threshold_) ||
                !RandomFieldVector(count * static_cast<size_t>(threshold_),
                                   &coefficients))
                dealer_random_ok = 0;
        }
        if (dealer_random_ok) {
            for (int recipient = 0; recipient < world_size_; ++recipient) {
                const F x(recipient + 1);
                for (size_t k = 0; k < count; ++k) {
                    F value = dealer_plaintext[k];
                    if (threshold_ == 1) {
                        value += coefficients[k] * x;
                    } else if (threshold_ > 1) {
                        F power = x;
                        const size_t base = k * static_cast<size_t>(threshold_);
                        for (int degree = 0; degree < threshold_; ++degree) {
                            value += coefficients[base + static_cast<size_t>(degree)] *
                                     power;
                            power *= x;
                        }
                    }
                    pack_field(value, &send_words[
                        static_cast<size_t>(recipient) * words_per_rank + 2 * k]);
                }
            }
        }
    }
    if (authenticated) {
        std::vector<u64> status_payload;
        if (rank_ == dealer)
            status_payload = {dealer_random_ok ? 1ULL : 0ULL};
        std::vector<u64> received_status;
        Digest binding{};
        if (!authenticated_exchange_->BroadcastWords(
                NextTransportContext(AUTH_MPC_PROTOCOL_DOMAIN,
                    AUTH_KIND_DIRECT_DEALER_STATUS,
                    static_cast<uint64_t>(dealer)),
                dealer, status_payload, &received_status, &binding) ||
            received_status.size() != 1 || received_status.front() > 1 ||
            binding == Digest{})
            return false;
        dealer_random_ok = received_status.front() != 0 ? 1 : 0;
        auth_bindings.push_back(binding);
    } else {
        MPI_Bcast(&dealer_random_ok, 1, MPI_INT, dealer, comm_);
        record_control_broadcast(sizeof(int), dealer, rank_, world_size_);
    }
    if (!dealer_random_ok ||
        words_per_rank > static_cast<size_t>(std::numeric_limits<int>::max()))
        return false;

    std::vector<u64> receive_words(words_per_rank);
    if (authenticated) {
        std::vector<u64> scatter_payload;
        if (rank_ == dealer) scatter_payload = send_words;
        Digest binding{};
        if (!authenticated_exchange_->ScatterWords(
                NextTransportContext(AUTH_MPC_PROTOCOL_DOMAIN,
                    AUTH_KIND_DIRECT_SHARES, static_cast<uint64_t>(dealer)),
                dealer, scatter_payload, words_per_rank,
                &receive_words, &binding) ||
            receive_words.size() != words_per_rank || binding == Digest{})
            return false;
        auth_bindings.push_back(binding);
    } else {
        MPI_Scatter(rank_ == dealer ? send_words.data() : nullptr,
                    static_cast<int>(words_per_rank), MPI_UINT64_T,
                    receive_words.data(), static_cast<int>(words_per_rank),
                    MPI_UINT64_T, dealer, comm_);
        record_control_scatter(
            static_cast<uint64_t>(words_per_rank * sizeof(u64)),
            dealer, rank_, world_size_);
    }

    local_shares->resize(count);
    for (size_t k = 0; k < local_shares->size(); ++k)
        (*local_shares)[k] = unpack_field(&receive_words[2 * k]);
    if (authenticated && transport_binding) {
        std::vector<u64> words = {
            DIRECT_SHARE_TRANSCRIPT_DOMAIN, static_cast<u64>(dealer),
            static_cast<u64>(world_size_), static_cast<u64>(threshold_),
            element_count};
        append_digest_words(authenticated_transport_capability_binding(), &words);
        for (const Digest& binding : auth_bindings)
            append_digest_words(binding, &words);
        *transport_binding = hash_words(words);
        if (*transport_binding == Digest{}) return false;
    }
    return true;
}

bool ReferenceShamirMpc::ShareLocalContribution(
    const F& secret, int dealer, F* local_share,
    Digest* transport_binding) const {
    if (!local_share) return false;
    std::vector<F> plaintext;
    if (rank_ == dealer) plaintext.push_back(secret);
    std::vector<F> shares;
    if (!ShareVectorFromDealerInternal(
            dealer, plaintext, &shares, transport_binding) ||
        shares.size() != 1)
        return false;
    *local_share = shares.front();
    return true;
}

bool ReferenceShamirMpc::RandomSharedField(
    F* local_share, Digest* transcript_binding) const {
    return RandomSharedFieldInternal(
        local_share, nullptr, transcript_binding);
}

bool ReferenceShamirMpc::RandomSharedFieldWithProvenance(
    F* local_share, ReferenceLinearSharingProvenance* provenance,
    Digest* transcript_binding) const {
    if (!provenance) return false;
    *provenance = ReferenceLinearSharingProvenance{};
    return RandomSharedFieldInternal(
        local_share, provenance, transcript_binding);
}

bool ReferenceShamirMpc::PreparePassiveRandomMasks(
    size_t count) const {
    if (count == 0) return true;
    if (!valid() || !authenticated_transport_available() ||
        !detectable_degree_reduction_available())
        return false;

    const size_t available =
        passive_random_mask_pool_.size() >= passive_random_mask_next_
            ? passive_random_mask_pool_.size() -
                  passive_random_mask_next_
            : 0;
    if (available >= count) return true;

    // A pool is prepared only at a batch-failure boundary, before recursive
    // localization starts.  Discard any exhausted prefix rather than mixing
    // masks from distinct preparation transcripts.
    passive_random_mask_pool_.clear();
    passive_random_mask_bindings_.clear();
    passive_random_mask_next_ = 0;

    u64 agreed_provenance_mode = 0;
    Digest mode_binding{};
    if (passive_random_mode_cached_) {
        mode_binding = passive_random_mode_binding_;
    } else {
        if (!CollectiveSameWord(
                0ULL, AUTH_KIND_RANDOM_MODE, 0,
                &agreed_provenance_mode, &mode_binding) ||
            agreed_provenance_mode != 0 ||
            mode_binding == Digest{})
            return false;
        passive_random_mode_cached_ = true;
        passive_random_mode_binding_ = mode_binding;
    }

    const int random_contributor_count = threshold_ + 1;
    if (random_contributor_count <= 0 ||
        random_contributor_count > world_size_)
        return false;

    const bool contributes_random =
        rank_ < random_contributor_count;
    std::vector<F> own_random(count, F(0));
    const bool local_random_ok =
        !contributes_random ||
        RandomFieldVector(count, &own_random);
    Digest random_ready_binding{};
    if (!CollectiveAllTrue(
            local_random_ok, AUTH_KIND_RANDOM_READY,
            static_cast<uint64_t>(count),
            &random_ready_binding))
        return false;

    ReferenceBivariateVss vss(
        rank_, world_size_, threshold_, comm_);
    if (!vss.valid()) return false;

    std::vector<F> dealer_major_shares;
    std::vector<ReferenceVssReceipt> receipts;
    const AuthenticatedMpcMessageContext batch_context =
        NextTransportContext(
            AUTH_MPC_PROTOCOL_DOMAIN,
            AUTH_KIND_RANDOM_VSS,
            static_cast<uint64_t>(count));
    if (!vss.ShareVectorsFromPrefixDealersAuthenticated(
            random_contributor_count, own_random, count,
            &dealer_major_shares, &receipts,
            *authenticated_exchange_, batch_context,
            nullptr) ||
        dealer_major_shares.size() !=
            static_cast<size_t>(random_contributor_count) * count ||
        receipts.size() !=
            static_cast<size_t>(random_contributor_count))
        return false;

    passive_random_mask_pool_.assign(count, F(0));
    passive_random_mask_bindings_.assign(count, Digest{});
    for (int dealer = 0;
         dealer < random_contributor_count; ++dealer) {
        const auto& receipt =
            receipts[static_cast<size_t>(dealer)];
        if (!receipt.available || !receipt.consistent ||
            receipt.dealer != dealer ||
            receipt.element_count != count ||
            receipt.transcript_binding == Digest{})
            return false;
        for (size_t element = 0;
             element < count; ++element) {
            passive_random_mask_pool_[element] +=
                dealer_major_shares[
                    static_cast<size_t>(dealer) * count +
                    element];
        }
    }

    for (size_t element = 0;
         element < count; ++element) {
        std::vector<u64> words = {
            RANDOM_MASK_POOL_TRANSCRIPT_DOMAIN,
            static_cast<u64>(world_size_),
            static_cast<u64>(threshold_),
            static_cast<u64>(random_contributor_count),
            static_cast<u64>(count),
            static_cast<u64>(element)};
        append_digest_words(
            authenticated_transport_capability_binding(),
            &words);
        append_digest_words(mode_binding, &words);
        append_digest_words(random_ready_binding, &words);
        for (const auto& receipt : receipts)
            append_digest_words(
                receipt.transcript_binding, &words);
        passive_random_mask_bindings_[element] =
            hash_words(words);
        if (passive_random_mask_bindings_[element] ==
            Digest{})
            return false;
    }
    return true;
}

bool ReferenceShamirMpc::RandomSharedFieldInternal(
    F* local_share, ReferenceLinearSharingProvenance* provenance,
    Digest* transcript_binding) const {
    if (!valid() || !local_share) return false;
    const u64 local_provenance_mode = provenance ? 1ULL : 0ULL;
    u64 agreed_provenance_mode = 0;
    Digest mode_binding{};
    if (!provenance && authenticated_transport_available() &&
        passive_random_mode_cached_) {
        agreed_provenance_mode = 0;
        mode_binding = passive_random_mode_binding_;
    } else {
        if (!CollectiveSameWord(
                local_provenance_mode, AUTH_KIND_RANDOM_MODE, 0,
                &agreed_provenance_mode, &mode_binding))
            return false;
        if (!provenance && authenticated_transport_available() &&
            agreed_provenance_mode == 0 && mode_binding != Digest{}) {
            passive_random_mode_cached_ = true;
            passive_random_mode_binding_ = mode_binding;
        }
    }
    if (agreed_provenance_mode != local_provenance_mode)
        return false;

    if (!provenance &&
        passive_random_mask_next_ <
            passive_random_mask_pool_.size()) {
        const size_t index = passive_random_mask_next_++;
        if (index >= passive_random_mask_bindings_.size() ||
            passive_random_mask_bindings_[index] == Digest{})
            return false;
        *local_share =
            passive_random_mask_pool_[index];
        if (transcript_binding)
            *transcript_binding =
                passive_random_mask_bindings_[index];
        if (passive_random_mask_next_ ==
            passive_random_mask_pool_.size()) {
            passive_random_mask_pool_.clear();
            passive_random_mask_bindings_.clear();
            passive_random_mask_next_ = 0;
        }
        return true;
    }

    // A random shared secret only needs one honest random contribution.
    // Under the reference 3t<n setting, a fixed set of t+1 contributors
    // necessarily contains an honest party against any static corruption set
    // of size at most t.  Restricting random dealers to this set avoids n
    // independent VSS sharings on every random-mask generation.
    const int random_contributor_count = threshold_ + 1;
    if (random_contributor_count <= 0 ||
        random_contributor_count > world_size_)
        return false;
    const bool contributes_random = rank_ < random_contributor_count;
    F own_random(0);
    const bool local_random_ok =
        !contributes_random || RandomField(&own_random);
    Digest random_ready_binding{};
    if (!CollectiveAllTrue(local_random_ok, AUTH_KIND_RANDOM_READY, 0,
            &random_ready_binding))
        return false;

    const bool use_vss = detectable_degree_reduction_available();
    if (provenance && !use_vss) return false;
    std::vector<u64> transcript_words = {
        RANDOM_SHARE_TRANSCRIPT_DOMAIN,
        use_vss ? 1ULL : 0ULL,
        provenance ? 1ULL : 0ULL,
        authenticated_transport_available() ? 1ULL : 0ULL,
        static_cast<u64>(world_size_),
        static_cast<u64>(threshold_),
        static_cast<u64>(random_contributor_count)};
    if (authenticated_transport_available()) {
        append_digest_words(authenticated_transport_capability_binding(),
                            &transcript_words);
        append_digest_words(mode_binding, &transcript_words);
        append_digest_words(random_ready_binding, &transcript_words);
    }
    F sum(0);
    std::vector<ReferenceLinearSharingSource> sources;
    if (provenance)
        sources.reserve(static_cast<size_t>(random_contributor_count));
    if (use_vss) {
        ReferenceBivariateVss vss(rank_, world_size_, threshold_, comm_);
        if (!vss.valid()) return false;
        if (authenticated_transport_available()) {
            std::vector<F> batch_shares;
            std::vector<ReferenceVssReceipt> batch_receipts;
            std::vector<ReferenceVssLocalWitness> batch_witnesses;
            const AuthenticatedMpcMessageContext batch_context =
                NextTransportContext(
                    AUTH_MPC_PROTOCOL_DOMAIN, AUTH_KIND_RANDOM_VSS, 0);
            if (!vss.ShareScalarsFromPrefixDealersAuthenticated(
                    random_contributor_count, own_random,
                    &batch_shares, &batch_receipts,
                    *authenticated_exchange_, batch_context,
                    provenance ? &batch_witnesses : nullptr) ||
                batch_shares.size() !=
                    static_cast<size_t>(random_contributor_count) ||
                batch_receipts.size() !=
                    static_cast<size_t>(random_contributor_count) ||
                (provenance && batch_witnesses.size() !=
                    static_cast<size_t>(random_contributor_count)))
                return false;

            for (int dealer = 0;
                 dealer < random_contributor_count; ++dealer) {
                const auto& receipt =
                    batch_receipts[static_cast<size_t>(dealer)];
                if (!receipt.available || !receipt.consistent ||
                    receipt.dealer != dealer ||
                    receipt.transcript_binding == Digest{})
                    return false;
                sum += batch_shares[static_cast<size_t>(dealer)];
                transcript_words.push_back(static_cast<u64>(dealer));
                append_digest_words(
                    receipt.transcript_binding, &transcript_words);
                if (provenance) {
                    auto& local_witness =
                        batch_witnesses[static_cast<size_t>(dealer)];
                    if (!validate_reference_vss_local_witness(local_witness) ||
                        local_witness.transcript_binding !=
                            receipt.transcript_binding)
                        return false;
                    ReferenceLinearSharingSource source;
                    source.sharing_binding = receipt.transcript_binding;
                    source.element_coefficients = {F(1)};
                    source.local_witness = std::move(local_witness);
                    sources.push_back(std::move(source));
                }
            }
        } else {
            for (int dealer = 0;
                 dealer < random_contributor_count; ++dealer) {
                std::vector<F> plaintext;
                if (rank_ == dealer) plaintext.push_back(own_random);
                std::vector<F> shares;
                ReferenceVssReceipt receipt;
                ReferenceVssLocalWitness local_witness;
                const bool shared = provenance
                    ? vss.ShareVectorFromDealerWithLocalWitness(
                        dealer, plaintext, &shares, &receipt,
                        &local_witness)
                    : vss.ShareVectorFromDealer(
                        dealer, plaintext, &shares, &receipt);
                if (!shared || shares.size() != 1 ||
                    !receipt.available || !receipt.consistent ||
                    receipt.transcript_binding == Digest{})
                    return false;
                sum += shares.front();
                transcript_words.push_back(static_cast<u64>(dealer));
                append_digest_words(
                    receipt.transcript_binding, &transcript_words);
                if (provenance) {
                    if (!validate_reference_vss_local_witness(local_witness) ||
                        local_witness.transcript_binding !=
                            receipt.transcript_binding)
                        return false;
                    ReferenceLinearSharingSource source;
                    source.sharing_binding = receipt.transcript_binding;
                    source.element_coefficients = {F(1)};
                    source.local_witness = std::move(local_witness);
                    sources.push_back(std::move(source));
                }
            }
        }
    } else {
        for (int dealer = 0;
             dealer < random_contributor_count; ++dealer) {
            F contribution_share(0);
            const F contribution = rank_ == dealer ? own_random : F(0);
            Digest direct_share_binding{};
            if (!ShareLocalContribution(
                    contribution, dealer, &contribution_share,
                    &direct_share_binding))
                return false;
            if (authenticated_transport_available() &&
                direct_share_binding == Digest{})
                return false;
            sum += contribution_share;
            transcript_words.push_back(static_cast<u64>(dealer));
            if (authenticated_transport_available())
                append_digest_words(direct_share_binding, &transcript_words);
        }
    }
    *local_share = sum;
    if (provenance) {
        if (!build_reference_linear_sharing_provenance(
                std::move(sources), provenance) ||
            provenance->local_share != sum || provenance->binding == Digest{})
            return false;
        append_digest_words(provenance->binding, &transcript_words);
    }
    if (transcript_binding) {
        *transcript_binding = hash_words(transcript_words);
        if (*transcript_binding == Digest{}) return false;
    }
    return true;
}

bool ReferenceShamirMpc::SetMultiplicationConsistencyProofBackend(
    const MultiplicationConsistencyProofBackend* backend) {
    if (!backend) {
        multiplication_consistency_backend_ = nullptr;
        return true;
    }
    const MultiplicationConsistencyCapabilities capabilities =
        backend->Capabilities();
    if (!production_ready_multiplication_consistency_capabilities(capabilities))
        return false;
    multiplication_consistency_backend_ = backend;
    return true;
}

bool ReferenceShamirMpc::multiplication_consistency_available() const {
    return detectable_degree_reduction_available() &&
        multiplication_consistency_backend_ &&
        production_ready_multiplication_consistency_capabilities(
            multiplication_consistency_backend_->Capabilities());
}

Digest ReferenceShamirMpc::multiplication_consistency_capability_binding() const {
    if (!multiplication_consistency_available()) return {};
    const MultiplicationConsistencyCapabilities capabilities =
        multiplication_consistency_backend_->Capabilities();
    return capabilities.capability_binding;
}

bool ReferenceShamirMpc::ShareLocalSum(
    const F& local_contribution, F* local_share,
    Digest* linear_binding,
    Digest* transcript_binding) const {
    if (!valid() || !local_share || !linear_binding ||
        !detectable_degree_reduction_available())
        return false;

    ReferenceBivariateVss vss(rank_, world_size_, threshold_, comm_);
    if (!vss.valid()) return false;

    F sum(0);
    std::vector<ReferenceLinearSharingSource> binding_sources;
    binding_sources.reserve(static_cast<size_t>(world_size_));
    std::vector<u64> transcript_words = {
        LOCAL_SUM_TRANSCRIPT_DOMAIN,
        authenticated_transport_available() ? 1ULL : 0ULL,
        static_cast<u64>(world_size_),
        static_cast<u64>(threshold_)};
    if (authenticated_transport_available()) {
        append_digest_words(
            authenticated_transport_capability_binding(),
            &transcript_words);

        std::vector<F> batch_shares;
        std::vector<ReferenceVssReceipt> batch_receipts;
        const AuthenticatedMpcMessageContext batch_context =
            NextTransportContext(
                AUTH_MPC_PROTOCOL_DOMAIN,
                AUTH_KIND_LOCAL_SUM_VSS, 0);
        if (!vss.ShareScalarsFromPrefixDealersAuthenticated(
                world_size_, local_contribution,
                &batch_shares, &batch_receipts,
                *authenticated_exchange_, batch_context,
                nullptr) ||
            batch_shares.size() !=
                static_cast<size_t>(world_size_) ||
            batch_receipts.size() !=
                static_cast<size_t>(world_size_))
            return false;

        for (int dealer = 0; dealer < world_size_; ++dealer) {
            const auto& receipt =
                batch_receipts[static_cast<size_t>(dealer)];
            if (!receipt.available || !receipt.consistent ||
                receipt.dealer != dealer ||
                receipt.transcript_binding == Digest{})
                return false;

            sum += batch_shares[static_cast<size_t>(dealer)];
            ReferenceLinearSharingSource source;
            source.sharing_binding = receipt.transcript_binding;
            source.element_coefficients = {F(1)};
            binding_sources.push_back(std::move(source));

            transcript_words.push_back(
                static_cast<u64>(dealer));
            append_digest_words(
                receipt.transcript_binding,
                &transcript_words);
        }
    } else {
        for (int dealer = 0; dealer < world_size_; ++dealer) {
            std::vector<F> plaintext;
            if (rank_ == dealer)
                plaintext.push_back(local_contribution);
            std::vector<F> shares;
            ReferenceVssReceipt receipt;
            if (!vss.ShareVectorFromDealer(
                    dealer, plaintext, &shares, &receipt) ||
                shares.size() != 1 ||
                !receipt.available || !receipt.consistent ||
                receipt.dealer != dealer ||
                receipt.transcript_binding == Digest{})
                return false;

            sum += shares.front();
            ReferenceLinearSharingSource source;
            source.sharing_binding = receipt.transcript_binding;
            source.element_coefficients = {F(1)};
            binding_sources.push_back(std::move(source));

            transcript_words.push_back(
                static_cast<u64>(dealer));
            append_digest_words(
                receipt.transcript_binding,
                &transcript_words);
        }
    }

    const Digest binding =
        compute_reference_linear_sharing_binding(
            binding_sources);
    if (binding == Digest{}) return false;

    *local_share = sum;
    *linear_binding = binding;
    append_digest_words(binding, &transcript_words);
    if (transcript_binding) {
        *transcript_binding = hash_words(transcript_words);
        if (*transcript_binding == Digest{})
            return false;
    }
    return true;
}

bool ReferenceShamirMpc::ShareLocalSumWithProvenance(
    const F& local_contribution, F* local_share,
    ReferenceLinearSharingProvenance* provenance,
    Digest* transcript_binding) const {
    if (!valid() || !local_share || !provenance ||
        !detectable_degree_reduction_available())
        return false;
    *provenance = ReferenceLinearSharingProvenance{};

    ReferenceBivariateVss vss(rank_, world_size_, threshold_, comm_);
    if (!vss.valid()) return false;

    F sum(0);
    std::vector<ReferenceLinearSharingSource> sources;
    sources.reserve(static_cast<size_t>(world_size_));
    std::vector<u64> transcript_words = {
        LOCAL_SUM_TRANSCRIPT_DOMAIN,
        authenticated_transport_available() ? 1ULL : 0ULL,
        static_cast<u64>(world_size_),
        static_cast<u64>(threshold_)};
    if (authenticated_transport_available()) {
        append_digest_words(
            authenticated_transport_capability_binding(), &transcript_words);
    }

    if (authenticated_transport_available()) {
        std::vector<F> batch_shares;
        std::vector<ReferenceVssReceipt> batch_receipts;
        std::vector<ReferenceVssLocalWitness> batch_witnesses;
        const AuthenticatedMpcMessageContext batch_context =
            NextTransportContext(
                AUTH_MPC_PROTOCOL_DOMAIN, AUTH_KIND_LOCAL_SUM_VSS, 0);
        if (!vss.ShareScalarsFromPrefixDealersAuthenticated(
                world_size_, local_contribution,
                &batch_shares, &batch_receipts,
                *authenticated_exchange_, batch_context,
                &batch_witnesses) ||
            batch_shares.size() != static_cast<size_t>(world_size_) ||
            batch_receipts.size() != static_cast<size_t>(world_size_) ||
            batch_witnesses.size() != static_cast<size_t>(world_size_))
            return false;

        for (int dealer = 0; dealer < world_size_; ++dealer) {
            const auto& receipt =
                batch_receipts[static_cast<size_t>(dealer)];
            auto& local_witness =
                batch_witnesses[static_cast<size_t>(dealer)];
            if (!receipt.available || !receipt.consistent ||
                receipt.dealer != dealer ||
                receipt.transcript_binding == Digest{} ||
                !validate_reference_vss_local_witness(local_witness) ||
                local_witness.transcript_binding !=
                    receipt.transcript_binding)
                return false;

            sum += batch_shares[static_cast<size_t>(dealer)];
            ReferenceLinearSharingSource source;
            source.sharing_binding = receipt.transcript_binding;
            source.element_coefficients = {F(1)};
            source.local_witness = std::move(local_witness);
            sources.push_back(std::move(source));

            transcript_words.push_back(static_cast<u64>(dealer));
            append_digest_words(
                receipt.transcript_binding, &transcript_words);
        }
    } else {
        for (int dealer = 0; dealer < world_size_; ++dealer) {
            std::vector<F> plaintext;
            if (rank_ == dealer)
                plaintext.push_back(local_contribution);
            std::vector<F> shares;
            ReferenceVssReceipt receipt;
            ReferenceVssLocalWitness local_witness;
            if (!vss.ShareVectorFromDealerWithLocalWitness(
                    dealer, plaintext, &shares, &receipt,
                    &local_witness) ||
                shares.size() != 1 || !receipt.available ||
                !receipt.consistent ||
                receipt.transcript_binding == Digest{} ||
                !validate_reference_vss_local_witness(local_witness) ||
                local_witness.transcript_binding !=
                    receipt.transcript_binding)
                return false;

            sum += shares.front();
            ReferenceLinearSharingSource source;
            source.sharing_binding = receipt.transcript_binding;
            source.element_coefficients = {F(1)};
            source.local_witness = std::move(local_witness);
            sources.push_back(std::move(source));

            transcript_words.push_back(static_cast<u64>(dealer));
            append_digest_words(
                receipt.transcript_binding, &transcript_words);
        }
    }

    if (!build_reference_linear_sharing_provenance(
            std::move(sources), provenance) ||
        provenance->local_share != sum || provenance->binding == Digest{})
        return false;
    *local_share = sum;
    append_digest_words(provenance->binding, &transcript_words);
    if (transcript_binding) {
        *transcript_binding = hash_words(transcript_words);
        if (*transcript_binding == Digest{}) return false;
    }
    return true;
}

bool ReferenceShamirMpc::MultiplyVector(
    const std::vector<F>& lhs_shares,
    const std::vector<F>& rhs_shares,
    std::vector<F>* product_shares,
    Digest* transcript_binding) const {
    if(!product_shares)return false;
    product_shares->clear();
    if(transcript_binding)*transcript_binding={};
    if(!valid() || !authenticated_transport_available() ||
       !detectable_degree_reduction_available() ||
       lhs_shares.empty() || lhs_shares.size()>64 ||
       lhs_shares.size()!=rhs_shares.size())return false;
    const size_t width=lhs_shares.size();
    u64 agreed_width=0;
    Digest width_binding{};
    constexpr u64 VECTOR_WIDTH_KIND=0x4d56454357445448ULL; // MVECWDTH
    constexpr u64 VECTOR_VSS_KIND=0x4d56454356535331ULL; // MVECVSS1
    constexpr u64 VECTOR_TRANSCRIPT_DOMAIN=0x50564d5645435452ULL;
    if(!CollectiveSameWord(
           static_cast<u64>(width),VECTOR_WIDTH_KIND,0,
           &agreed_width,&width_binding) ||
       agreed_width!=width || width_binding==Digest{})
        return false;
    const int dealer_count=2*threshold_+1;
    if(dealer_count<=0 || dealer_count>world_size_)return false;
    std::vector<F> local_products(width);
    for(size_t i=0;i<width;++i)
        local_products[i]=lhs_shares[i]*rhs_shares[i];
    ReferenceBivariateVss vss(rank_,world_size_,threshold_,comm_);
    if(!vss.valid())return false;
    std::vector<F> shared;
    std::vector<ReferenceVssReceipt> receipts;
    if(!vss.ShareVectorsFromPrefixDealersAuthenticated(
           dealer_count,local_products,width,&shared,&receipts,
           *authenticated_exchange_,
           NextTransportContext(AUTH_MPC_PROTOCOL_DOMAIN,VECTOR_VSS_KIND),
           nullptr) ||
       shared.size()!=width*static_cast<size_t>(dealer_count) ||
       receipts.size()!=static_cast<size_t>(dealer_count))
        return false;
    product_shares->assign(width,F(0));
    std::vector<u64> transcript={
        VECTOR_TRANSCRIPT_DOMAIN,
        static_cast<u64>(width),
        static_cast<u64>(dealer_count),
        static_cast<u64>(world_size_),
        static_cast<u64>(threshold_)};
    append_digest_words(width_binding,&transcript);
    for(int dealer=0;dealer<dealer_count;++dealer){
        const auto& receipt=receipts[static_cast<size_t>(dealer)];
        if(!receipt.available || !receipt.consistent ||
           receipt.dealer!=dealer ||
           receipt.element_count!=width ||
           receipt.transcript_binding==Digest{})return false;
        const F weight=LagrangeAtZero(dealer,dealer_count);
        for(size_t lane=0;lane<width;++lane)
            (*product_shares)[lane]+=
                weight*shared[static_cast<size_t>(dealer)*width+lane];
        transcript.push_back(static_cast<u64>(dealer));
        append_digest_words(receipt.transcript_binding,&transcript);
    }
    const Digest binding=hash_words(transcript);
    if(binding==Digest{})return false;
    if(transcript_binding)*transcript_binding=binding;
    return true;
}

bool ReferenceShamirMpc::Multiply(
    const F& lhs_share, const F& rhs_share, F* product_share,
    Digest* transcript_binding) const {
    return MultiplyInternal(
        lhs_share, rhs_share, nullptr, nullptr,
        product_share, transcript_binding, nullptr, nullptr);
}

bool ReferenceShamirMpc::MultiplyWithConsistency(
    const F& lhs_share, const F& rhs_share,
    const ReferenceMultiplicationConsistencyContext& context,
    F* product_share, Digest* transcript_binding) const {
    return MultiplyInternal(
        lhs_share, rhs_share, &context, nullptr,
        product_share, transcript_binding, nullptr, nullptr);
}

bool ReferenceShamirMpc::MultiplyWithConsistency(
    const F& lhs_share, const F& rhs_share,
    const ReferenceMultiplicationConsistencyContext& context,
    const ReferenceMultiplicationConsistencyLocalWitness& local_witness,
    F* product_share, Digest* transcript_binding) const {
    return MultiplyInternal(
        lhs_share, rhs_share, &context, &local_witness,
        product_share, transcript_binding, nullptr, nullptr);
}

bool ReferenceShamirMpc::MultiplyWithConsistency(
    const F& lhs_share, const F& rhs_share,
    const ReferenceMultiplicationConsistencyContext& context,
    const ReferenceMultiplicationConsistencyLocalWitness& local_witness,
    F* product_share, Digest* transcript_binding,
    std::vector<ReferenceMultiplicationFailureCertificate>*
        failure_certificates,
    std::vector<std::vector<u64>>* encoded_failure_certificates) const {
    return MultiplyInternal(
        lhs_share, rhs_share, &context, &local_witness,
        product_share, transcript_binding, failure_certificates,
        encoded_failure_certificates);
}

bool ReferenceShamirMpc::MultiplyInternal(
    const F& lhs_share, const F& rhs_share,
    const ReferenceMultiplicationConsistencyContext* context,
    const ReferenceMultiplicationConsistencyLocalWitness* local_witness,
    F* product_share, Digest* transcript_binding,
    std::vector<ReferenceMultiplicationFailureCertificate>*
        failure_certificates,
    std::vector<std::vector<u64>>* encoded_failure_certificates) const {
    if (!valid() || !product_share) return false;
    if (failure_certificates) failure_certificates->clear();
    if (encoded_failure_certificates)
        encoded_failure_certificates->clear();
    // The RS-syndrome path checks that ALL committed local products lie on
    // the degree-2t product polynomial. If n>3t, the n-t honest evaluations
    // uniquely determine that polynomial. The public challenge is sampled
    // only AFTER each dealer's VSS output is bound, so malicious dealers
    // cannot adapt their local products to the compressed parity check.
    const char* rs_mode_env = std::getenv("PVIA_RS_MUL_SYNDROME");
    const bool local_rs_mode = rs_mode_env &&
        std::strcmp(rs_mode_env, "1") == 0;
    const u64 local_multiply_mode =
        (context ? 1ULL : 0ULL) | (local_rs_mode ? 2ULL : 0ULL);
    u64 agreed_multiply_mode = 0;
    Digest require_mode_binding{};
    if (!context && !local_rs_mode &&
        authenticated_transport_available() &&
        passive_multiply_mode_cached_) {
        agreed_multiply_mode = 0;
        require_mode_binding = passive_multiply_mode_binding_;
    } else {
        if (!CollectiveSameWord(
                local_multiply_mode, AUTH_KIND_MULTIPLY_MODE, 0,
                &agreed_multiply_mode, &require_mode_binding))
            return false;
        if (local_multiply_mode == 0 &&
            authenticated_transport_available() &&
            require_mode_binding != Digest{}) {
            passive_multiply_mode_cached_ = true;
            passive_multiply_mode_binding_ = require_mode_binding;
        }
    }
    if (agreed_multiply_mode != local_multiply_mode)
        return false;
    const bool require_consistency = (agreed_multiply_mode & 1ULL) != 0;
    const bool rs_check = (agreed_multiply_mode & 2ULL) != 0;
    if (rs_check && (!authenticated_transport_available() ||
                     !detectable_degree_reduction_available()))
        return false;

    MultiplicationConsistencyCapabilities proof_capabilities;
    Digest request_binding{};
    std::vector<Digest> consistency_control_bindings;
    if (require_consistency) {
        const u64 local_mode =
            multiplication_consistency_backend_ ? 1ULL : 0ULL;
        u64 agreed_mode = 0;
        Digest proof_mode_binding{};
        if (!CollectiveSameWord(local_mode, AUTH_KIND_PROOF_MODE, 0,
                &agreed_mode, &proof_mode_binding) || agreed_mode != 1ULL)
            return false;
        proof_capabilities = multiplication_consistency_backend_->Capabilities();
        const int local_ready =
            detectable_degree_reduction_available() &&
            production_ready_multiplication_consistency_capabilities(
                proof_capabilities) ? 1 : 0;
        Digest proof_ready_binding{};
        if (!CollectiveAllTrue(local_ready != 0, AUTH_KIND_PROOF_READY, 0,
                &proof_ready_binding))
            return false;
        Digest proof_capability_agreement_binding{};
        if (!CollectiveSameDigest(proof_capabilities.capability_binding,
                AUTH_KIND_PROOF_CAP, 0,
                &proof_capability_agreement_binding))
            return false;
        const bool local_context_ok = context && context->sid != 0 &&
            context->checkpoint != 0 && context->multiplication_id != 0 &&
            context->lhs_sharing_binding != Digest{} &&
            context->rhs_sharing_binding != Digest{} &&
            context->context_binding != Digest{};
        Digest context_ready_binding{};
        if (!CollectiveAllTrue(local_context_ok, AUTH_KIND_CONTEXT_READY, 0,
                &context_ready_binding))
            return false;
        std::vector<u64> request_words = {
            MULTIPLY_CONSISTENCY_REQUEST_DOMAIN,
            context->sid, context->checkpoint, context->multiplication_id,
            static_cast<u64>(world_size_), static_cast<u64>(threshold_)};
        append_digest_words(context->lhs_sharing_binding, &request_words);
        append_digest_words(context->rhs_sharing_binding, &request_words);
        append_digest_words(context->context_binding, &request_words);
        request_binding = hash_words(request_words);
        Digest request_agreement_binding{};
        if (request_binding == Digest{} ||
            !CollectiveSameDigest(request_binding, AUTH_KIND_REQUEST_BINDING,
                context->multiplication_id, &request_agreement_binding))
            return false;
        if (authenticated_transport_available()) {
            consistency_control_bindings = {
                proof_mode_binding, proof_ready_binding,
                proof_capability_agreement_binding, context_ready_binding,
                request_agreement_binding};
        }
    }

    F local_product = lhs_share * rhs_share;
    // Deliberately confined to the isolated selftest entry point. This
    // simulates a faulty dealer who VSS-shares an incorrect local product.
    if (rs_check && std::getenv("PVIA_REFERENCE_RS_MUL_SELFTEST")) {
        const char* corrupt = std::getenv("PVIA_TEST_RS_MUL_FAULT_DEALER");
        if (corrupt && std::strcmp(corrupt, "1") == 0 && rank_ == 1)
            local_product += F(1);
    }
    const bool use_vss = detectable_degree_reduction_available();
    if (require_consistency && !use_vss) return false;
    std::vector<u64> transcript_words = {
        MULTIPLY_TRANSCRIPT_DOMAIN,
        use_vss ? 1ULL : 0ULL,
        require_consistency ? 1ULL : 0ULL,
        rs_check ? 1ULL : 0ULL,
        authenticated_transport_available() ? 1ULL : 0ULL,
        static_cast<u64>(world_size_),
        static_cast<u64>(threshold_)};
    if (authenticated_transport_available()) {
        append_digest_words(authenticated_transport_capability_binding(),
                            &transcript_words);
        append_digest_words(require_mode_binding, &transcript_words);
        for (const Digest& binding : consistency_control_bindings)
            append_digest_words(binding, &transcript_words);
    }
    if (require_consistency) {
        append_digest_words(proof_capabilities.capability_binding,
                            &transcript_words);
        append_digest_words(request_binding, &transcript_words);
    }

    F reduced_share(0);
    ReferenceMultiplicationRsEvent rs_event;
    bool rs_event_nonzero = false;
    std::vector<MultiplicationConsistencyProofArtifact> proofs;
    if (require_consistency) proofs.reserve(static_cast<size_t>(world_size_));
    if (use_vss) {
        ReferenceBivariateVss vss(rank_, world_size_, threshold_, comm_);
        if (!vss.valid()) return false;
        if (authenticated_transport_available() && !require_consistency) {
            // The local products are evaluations of a degree-2t polynomial.
            // The reference-passive fast path therefore needs only 2t+1
            // evaluation points to reconstruct its value at zero before
            // resharing.  The strong-consistency path below deliberately
            // retains all participants because its proof set is per dealer.
            const int reduction_dealer_count =
                rs_check ? world_size_ : 2 * threshold_ + 1;
            if (reduction_dealer_count <= 0 ||
                reduction_dealer_count > world_size_ ||
                2 * threshold_ >= world_size_)
                return false;
            std::vector<F> batch_shares;
            std::vector<ReferenceVssReceipt> batch_receipts;
            const AuthenticatedMpcMessageContext batch_context =
                NextTransportContext(
                    AUTH_MPC_PROTOCOL_DOMAIN, AUTH_KIND_MULTIPLY_VSS, 0);
            if (!vss.ShareScalarsFromPrefixDealersAuthenticated(
                    reduction_dealer_count, local_product,
                    &batch_shares, &batch_receipts,
                    *authenticated_exchange_, batch_context, nullptr) ||
                batch_shares.size() !=
                    static_cast<size_t>(reduction_dealer_count) ||
                batch_receipts.size() !=
                    static_cast<size_t>(reduction_dealer_count))
                return false;
            transcript_words.push_back(
                static_cast<u64>(reduction_dealer_count));
            for (int dealer = 0;
                 dealer < reduction_dealer_count; ++dealer) {
                const auto& receipt =
                    batch_receipts[static_cast<size_t>(dealer)];
                if (!receipt.available || !receipt.consistent ||
                    receipt.dealer != dealer ||
                    receipt.transcript_binding == Digest{})
                    return false;
                // Only 2t+1 product evaluations are needed to interpolate
                // the degree-2t product at zero, but RS mode authenticates
                // ALL n evaluations before taking these first 2t+1.
                if (dealer < 2 * threshold_ + 1)
                    reduced_share +=
                        LagrangeAtZero(dealer, 2 * threshold_ + 1) *
                        batch_shares[static_cast<size_t>(dealer)];
                transcript_words.push_back(static_cast<u64>(dealer));
                append_digest_words(
                    receipt.transcript_binding, &transcript_words);
            }
            if (rs_check) {
                Digest seed{}, seed_binding{};
                if (!JointPublicSeed(&seed, &seed_binding) ||
                    seed == Digest{} || seed_binding == Digest{})
                    return false;
                const int checks = world_size_ - 2 * threshold_ - 1;
                if (checks < 1) return false;
                F syndrome_share(0);
                for (int dealer = 0; dealer < world_size_; ++dealer) {
                    const F xi(dealer + 1);
                    F denominator(1);
                    for (int other = 0; other < world_size_; ++other)
                        if (other != dealer)
                            denominator *= xi - F(other + 1);
                    if (denominator == F(0)) return false;
                    // Dual RS parity-check rows are
                    // x_i^k / prod_{j!=i}(x_i-x_j), 0<=k<n-2t-1.
                    // Randomly compress all rows into one hidden sharing;
                    // only its (normally zero) syndrome is opened.
                    F compressed_coefficient(1);
                    F xpower(xi);
                    for (int k = 1; k < checks; ++k) {
                        std::vector<u64> coeff_words = {
                            RS_PRODUCT_PARITY_DOMAIN,
                            static_cast<u64>(world_size_),
                            static_cast<u64>(threshold_),
                            static_cast<u64>(k)};
                        append_digest_words(seed, &coeff_words);
                        const Digest coeff_digest = hash_words(coeff_words);
                        if (coeff_digest == Digest{}) return false;
                        u64 limbs[2]{};
                        std::memcpy(&limbs[0], coeff_digest.bytes.data(), 8);
                        std::memcpy(&limbs[1], coeff_digest.bytes.data()+8, 8);
                        // Digest limbs are arbitrary 64-bit words, whereas
                        // fieldElement's constructor expects canonical
                        // representatives in [0, F::mod). Reduce both
                        // coordinates before constructing the extension-field
                        // coefficient; otherwise arithmetic may start from
                        // non-canonical values and produce false RS syndromes.
                        const F coeff(
                            static_cast<long long>(limbs[0] % F::mod),
                            static_cast<long long>(limbs[1] % F::mod));
                        compressed_coefficient += coeff * xpower;
                        xpower *= xi;
                    }
                    syndrome_share +=
                        denominator.inv() * compressed_coefficient *
                        batch_shares[static_cast<size_t>(dealer)];
                }
                F opened_syndrome(0);
                Digest syndrome_opening_binding{};
                if (!Open(syndrome_share, &opened_syndrome,
                          &syndrome_opening_binding) ||
                    syndrome_opening_binding == Digest{})
                    return false;
                if (rank_ == 0 &&
                    (std::getenv("PVIA_EXPERIMENT_METRICS") ||
                     std::getenv("PVIA_REFERENCE_RS_MUL_SELFTEST"))) {
                    std::fprintf(stderr,
                        "[PVIA][rs-product-syndrome] checks=%d "
                        "n=%d t=%d result=%s opening=one-syndrome-only\n",
                        checks, world_size_, threshold_,
                        opened_syndrome == F(0) ? "PASS" : "REJECT");
                }
                if (opened_syndrome != F(0)) return false;
                transcript_words.push_back(RS_PRODUCT_PARITY_DOMAIN);
                transcript_words.push_back(static_cast<u64>(checks));
                append_digest_words(seed_binding, &transcript_words);
                append_digest_words(seed, &transcript_words);
                append_digest_words(
                    syndrome_opening_binding, &transcript_words);
            }
        } else if (authenticated_transport_available() && require_consistency) {
            // Strong path: batch all dealer VSS rows first, then each dealer
            // generates its own consistency proof concurrently. The old loop
            // proved/broadcast one dealer at a time, multiplying SP1 proving
            // latency by N even though all four witnesses are independent.
            const AuthenticatedMpcMessageContext batch_context =
                NextTransportContext(
                    AUTH_MPC_PROTOCOL_DOMAIN, AUTH_KIND_MULTIPLY_VSS,
                    context->multiplication_id);
            std::vector<F> batch_shares;
            std::vector<ReferenceVssReceipt> batch_receipts;
            std::vector<ReferenceVssDealerWitness> dealer_witnesses;
            if (!vss.ShareScalarsFromPrefixDealersAuthenticated(
                    world_size_, local_product, &batch_shares,
                    &batch_receipts, *authenticated_exchange_,
                    batch_context, nullptr, &dealer_witnesses) ||
                batch_shares.size() != static_cast<size_t>(world_size_) ||
                batch_receipts.size() != static_cast<size_t>(world_size_) ||
                dealer_witnesses.size() != static_cast<size_t>(world_size_))
                return false;

            // In the strong path, bind the RS syndrome to the same ordered
            // dealer VSS receipts and multiplication statement before any
            // per-dealer proof-preflight status is collected.
            if (rs_check) {
                Digest seed{}, seed_binding{};
                if (!JointPublicSeed(&seed, &seed_binding) ||
                    seed == Digest{} || seed_binding == Digest{})
                    return false;
                const int checks = world_size_ - 2 * threshold_ - 1;
                if (checks < 1) return false;
                F syndrome_share(0);
                for (int dealer = 0; dealer < world_size_; ++dealer) {
                    const F xi(dealer + 1);
                    F denominator(1);
                    for (int other = 0; other < world_size_; ++other)
                        if (other != dealer)
                            denominator *= xi - F(other + 1);
                    if (denominator == F(0)) return false;
                    F compressed_coefficient(1);
                    F xpower(xi);
                    for (int k = 1; k < checks; ++k) {
                        std::vector<u64> coeff_words = {
                            RS_PRODUCT_PARITY_DOMAIN,
                            static_cast<u64>(world_size_),
                            static_cast<u64>(threshold_),
                            static_cast<u64>(k)};
                        append_digest_words(seed, &coeff_words);
                        const Digest coeff_digest = hash_words(coeff_words);
                        if (coeff_digest == Digest{}) return false;
                        u64 limbs[2]{};
                        std::memcpy(&limbs[0], coeff_digest.bytes.data(), 8);
                        std::memcpy(&limbs[1], coeff_digest.bytes.data()+8, 8);
                        // Digest limbs are arbitrary 64-bit words, whereas
                        // fieldElement's constructor expects canonical
                        // representatives in [0, F::mod). Reduce both
                        // coordinates before constructing the extension-field
                        // coefficient; otherwise arithmetic may start from
                        // non-canonical values and produce false RS syndromes.
                        const F coeff(
                            static_cast<long long>(limbs[0] % F::mod),
                            static_cast<long long>(limbs[1] % F::mod));
                        compressed_coefficient += coeff * xpower;
                        xpower *= xi;
                    }
                    syndrome_share +=
                        denominator.inv() * compressed_coefficient *
                        batch_shares[static_cast<size_t>(dealer)];
                }
                F opened_syndrome(0);
                Digest opening_binding{};
                if (!Open(syndrome_share, &opened_syndrome,
                          &opening_binding) ||
                    opening_binding == Digest{})
                    return false;
                rs_event.sid = context->sid;
                rs_event.checkpoint = context->checkpoint;
                rs_event.multiplication_id = context->multiplication_id;
                rs_event.world_size = static_cast<uint32_t>(world_size_);
                rs_event.threshold = static_cast<uint32_t>(threshold_);
                rs_event.lhs_sharing_binding = context->lhs_sharing_binding;
                rs_event.rhs_sharing_binding = context->rhs_sharing_binding;
                rs_event.joint_seed = seed;
                rs_event.joint_seed_binding = seed_binding;
                rs_event.syndrome = opened_syndrome;
                rs_event.syndrome_opening_binding = opening_binding;
                rs_event.output_sharing_bindings.reserve(
                    static_cast<size_t>(world_size_));
                for (int dealer = 0; dealer < world_size_; ++dealer) {
                    const auto& receipt =
                        batch_receipts[static_cast<size_t>(dealer)];
                    if (!receipt.available || !receipt.consistent ||
                        receipt.dealer != dealer ||
                        receipt.transcript_binding == Digest{})
                        return false;
                    rs_event.output_sharing_bindings.push_back(
                        receipt.transcript_binding);
                }
                rs_event.event_binding =
                    compute_reference_multiplication_rs_event_binding(rs_event);
                if (!validate_reference_multiplication_rs_event(rs_event))
                    return false;
                rs_event_nonzero = opened_syndrome != F(0);
                transcript_words.push_back(RS_PRODUCT_PARITY_DOMAIN);
                transcript_words.push_back(static_cast<u64>(checks));
                append_digest_words(seed_binding, &transcript_words);
                append_digest_words(seed, &transcript_words);
                append_digest_words(opening_binding, &transcript_words);
                append_digest_words(rs_event.event_binding, &transcript_words);
                if (rank_ == 0 &&
                    (std::getenv("PVIA_EXPERIMENT_METRICS") ||
                     std::getenv("PVIA_REFERENCE_RS_MUL_SELFTEST"))) {
                    std::fprintf(stderr,
                        "[PVIA][rs-product-syndrome-strong] checks=%d "
                        "n=%d t=%d result=%s opening=one-syndrome-only\n",
                        checks, world_size_, threshold_,
                        rs_event_nonzero ? "REJECT" : "PASS");
                }
            }

            std::vector<MultiplicationConsistencyStatement> statements(
                static_cast<size_t>(world_size_));
            bool statements_ready = true;
            for (int dealer = 0; dealer < world_size_; ++dealer) {
                const auto& receipt =
                    batch_receipts[static_cast<size_t>(dealer)];
                if (!receipt.available || !receipt.consistent ||
                    receipt.dealer != dealer ||
                    receipt.transcript_binding == Digest{}) {
                    statements_ready = false;
                    continue;
                }
                reduced_share +=
                    LagrangeAtZero(dealer, world_size_) *
                    batch_shares[static_cast<size_t>(dealer)];
                transcript_words.push_back(static_cast<u64>(dealer));
                append_digest_words(
                    receipt.transcript_binding, &transcript_words);

                auto& statement = statements[static_cast<size_t>(dealer)];
                statement.sid = context->sid;
                statement.checkpoint = context->checkpoint;
                statement.multiplication_id = context->multiplication_id;
                statement.dealer = static_cast<uint32_t>(dealer);
                statement.lhs_sharing_binding =
                    context->lhs_sharing_binding;
                statement.rhs_sharing_binding =
                    context->rhs_sharing_binding;
                statement.output_sharing_binding =
                    receipt.transcript_binding;
                statement.context_binding = context->context_binding;
                statement.statement_binding =
                    compute_multiplication_consistency_statement_binding(
                        statement);
                if (!validate_multiplication_consistency_statement(statement))
                    statements_ready = false;
            }
            Digest statement_ready_binding{};
            if (!CollectiveAllTrue(
                    statements_ready, AUTH_KIND_PROOF_STATEMENTS,
                    context->multiplication_id, &statement_ready_binding) ||
                statement_ready_binding == Digest{})
                return false;
            append_digest_words(statement_ready_binding, &transcript_words);

            MultiplicationConsistencyProofArtifact local_proof;
            std::vector<u64> encoded_local_proof;
            bool local_prover_ready = false;
            int local_preflight_reason = 1;
            int local_proof_failure_reason = 0;
            MultiplicationConsistencyStatement local_statement{};
            MultiplicationConsistencyWitness local_witness_artifact;
            if (rank_ >= 0 && rank_ < world_size_ && local_witness) {
                const size_t own = static_cast<size_t>(rank_);
                const auto& dealer_witness = dealer_witnesses[own];
                const auto& receipt = batch_receipts[own];
                local_statement = statements[own];
                if (dealer_witness.available &&
                    dealer_witness.dealer == rank_ &&
                    dealer_witness.transcript_binding ==
                        receipt.transcript_binding &&
                    !dealer_witness.coefficient_words.empty()) {
                    local_witness_artifact.lhs_share = lhs_share;
                    local_witness_artifact.rhs_share = rhs_share;
                    local_witness_artifact.product_value = local_product;
                    const bool input_witness_ready =
                        wrap_reference_multiplication_consistency_input_sharing_witness(
                            local_witness->lhs_sharing_witness_words,
                            local_statement.lhs_sharing_binding,
                            &local_witness_artifact.lhs_sharing_witness_words) &&
                        wrap_reference_multiplication_consistency_input_sharing_witness(
                            local_witness->rhs_sharing_witness_words,
                            local_statement.rhs_sharing_binding,
                            &local_witness_artifact.rhs_sharing_witness_words);
                    const std::vector<u64> output_payload =
                        encode_reference_vss_dealer_witness(dealer_witness);
                    const bool output_witness_ready =
                        !output_payload.empty() &&
                        wrap_reference_multiplication_consistency_sharing_witness(
                            MultiplicationConsistencySharingWitnessKind::VSS_DEALER,
                            output_payload,
                            local_statement.output_sharing_binding,
                            &local_witness_artifact.output_sharing_witness_words);
                    if (!input_witness_ready) {
                        local_preflight_reason = 2;
                    } else if (!output_witness_ready) {
                        local_preflight_reason = 3;
                    } else if (!validate_multiplication_consistency_provider_witness_relation(
                                   local_statement, local_witness_artifact)) {
                        local_preflight_reason = 4;
                    } else {
                        local_preflight_reason = 0;
                    }
                }
            }
            if (rs_check && rs_event_nonzero) {
                const std::vector<u64> local_status =
                    encode_reference_multiplication_failure_status(
                        rs_event, static_cast<uint32_t>(rank_),
                        static_cast<uint64_t>(local_preflight_reason));
                if (local_status.size() != 17) return false;
                const AuthenticatedMpcMessageContext status_context =
                    NextTransportContext(
                        REFERENCE_MULTIPLICATION_FAILURE_PROTOCOL_DOMAIN,
                        REFERENCE_MULTIPLICATION_FAILURE_STATUS_KIND,
                        context->multiplication_id);
                std::vector<u64> all_status_words;
                Digest status_transcript_binding{};
                if (!authenticated_exchange_->AllGatherWords(
                        status_context, local_status, &all_status_words,
                        &status_transcript_binding) ||
                    status_transcript_binding == Digest{} ||
                    all_status_words.size() !=
                        static_cast<size_t>(world_size_) * local_status.size())
                    return false;

                std::vector<std::vector<u64>> status_payloads;
                status_payloads.reserve(static_cast<size_t>(world_size_));
                size_t failed_preflight_count = 0;
                uint32_t accused_dealer = 0;
                bool status_codes_supported = true;
                for (int sender = 0; sender < world_size_; ++sender) {
                    const auto begin = all_status_words.begin() +
                        static_cast<std::ptrdiff_t>(
                            static_cast<size_t>(sender) * local_status.size());
                    std::vector<u64> payload(
                        begin, begin + static_cast<std::ptrdiff_t>(
                            local_status.size()));
                    if (payload[7] != static_cast<u64>(sender) ||
                        payload[8] > 4)
                        status_codes_supported = false;
                    if (payload[8] == static_cast<uint64_t>(
                            ReferenceMultiplicationFailureCode::
                                RELATION_PRECHECK_FAILED)) {
                        ++failed_preflight_count;
                        accused_dealer = static_cast<uint32_t>(sender);
                    } else if (payload[8] != 0) {
                        status_codes_supported = false;
                    }
                    status_payloads.push_back(std::move(payload));
                }

                std::vector<AuthenticatedMpcSignedEnvelopeObservation>
                    exported_observations;
                if (!authenticated_exchange_->ExportVerifiedEnvelopeObservations(
                        context->sid, context->checkpoint,
                        &exported_observations))
                    return false;
                std::vector<AuthenticatedMpcSignedEnvelopeObservation>
                    status_observations;
                for (const auto& observation : exported_observations) {
                    const auto& observed = observation.context;
                    if (observed.protocol_domain != status_context.protocol_domain ||
                        observed.sid != status_context.sid ||
                        observed.checkpoint != status_context.checkpoint ||
                        observed.round != status_context.round ||
                        observed.sequence != status_context.sequence ||
                        observed.message_kind != status_context.message_kind ||
                        observation.receiver !=
                            AUTHENTICATED_MPC_BROADCAST_RECEIVER)
                        continue;
                    status_observations.push_back(observation);
                }
                std::sort(status_observations.begin(),
                          status_observations.end(),
                    [](const auto& lhs, const auto& rhs) {
                        return lhs.sender < rhs.sender;
                    });

                ReferenceMultiplicationFailureCertificate certificate;
                std::vector<u64> encoded_certificate;
                bool public_certificate_ready =
                    status_codes_supported && failed_preflight_count == 1 &&
                    status_observations.size() ==
                        static_cast<size_t>(world_size_);
                const auto& auth =
                    Ed25519TransferAuthenticator::instance();
                if (public_certificate_ready) {
                    certificate.available = true;
                    certificate.event = rs_event;
                    certificate.accused_dealer = accused_dealer;
                    certificate.failure_code = static_cast<uint64_t>(
                        ReferenceMultiplicationFailureCode::
                            RELATION_PRECHECK_FAILED);
                    certificate.status_context = status_context;
                    certificate.status_payloads = status_payloads;
                    certificate.status_observations = status_observations;
                    certificate.registry_commitment =
                        auth.RegistryCommitment();
                    certificate.certificate_binding =
                        compute_reference_multiplication_failure_certificate_binding(
                            certificate);
                    public_certificate_ready =
                        auth.ready() &&
                        auth.ExternalRegistryAnchorVerified() &&
                        auth.ExternalRegistryAnchor() ==
                            certificate.registry_commitment &&
                        validate_reference_multiplication_failure_certificate(
                            certificate) &&
                        PublicJudge::VerifyMultiplicationFailureCertificate(
                            certificate, auth.PublicKeys(),
                            auth.ExternalRegistryAnchor());
                }
                if (public_certificate_ready) {
                    encoded_certificate =
                        encode_reference_multiplication_failure_certificate(
                            certificate);
                    ReferenceMultiplicationFailureCertificate decoded;
                    public_certificate_ready =
                        !encoded_certificate.empty() &&
                        PublicJudge::VerifyMultiplicationFailureCertificate(
                            encoded_certificate, auth.PublicKeys(),
                            auth.ExternalRegistryAnchor()) &&
                        decode_reference_multiplication_failure_certificate(
                            encoded_certificate, &decoded) &&
                        decoded.certificate_binding ==
                            certificate.certificate_binding &&
                        PublicJudge::VerifyMultiplicationFailureCertificate(
                            decoded, auth.PublicKeys(),
                            auth.ExternalRegistryAnchor()) &&
                        encode_reference_multiplication_failure_certificate(
                            decoded) == encoded_certificate;
                }

                // Every participant must independently accept the same
                // externally anchored certificate before it is surfaced to
                // the caller. The product remains withheld regardless.
                Digest certificate_verify_agreement{};
                if (!CollectiveAllTrue(
                        public_certificate_ready,
                        AUTH_KIND_FAILURE_CERT_VERIFY,
                        context->multiplication_id,
                        &certificate_verify_agreement) ||
                    certificate_verify_agreement == Digest{})
                    return false;
                const Digest encoded_certificate_binding =
                    hash_words(encoded_certificate);
                Digest certificate_binding_agreement{};
                if (encoded_certificate_binding == Digest{} ||
                    !CollectiveSameDigest(
                        encoded_certificate_binding,
                        AUTH_KIND_FAILURE_CERT_BINDING,
                        context->multiplication_id,
                        &certificate_binding_agreement) ||
                    certificate_binding_agreement == Digest{})
                    return false;
                if (failure_certificates)
                    failure_certificates->push_back(certificate);
                if (encoded_failure_certificates)
                    encoded_failure_certificates->push_back(
                        std::move(encoded_certificate));
                // A nonzero syndrome always withholds the product. The
                // optional evidence output now contains only a certificate
                // accepted by PublicJudge against the external key anchor.
                return false;
            }

            Digest preflight_binding{};
            if (!CollectiveAllTrue(
                    local_preflight_reason == 0,
                    AUTH_KIND_PROVER_PREFLIGHT,
                    context->multiplication_id, &preflight_binding) ||
                preflight_binding == Digest{}) {
                std::fprintf(stderr,
                    "[PVIA][mc-provider] rank=%d witness preflight failed reason=%d\n",
                    rank_, local_preflight_reason);
                return false;
            }
            local_prover_ready = false;
            if (local_preflight_reason == 0) {
                local_proof = multiplication_consistency_backend_->Prove(
                    local_statement, local_witness_artifact);
                if (validate_multiplication_consistency_proof_artifact(
                        local_statement, local_proof)) {
                    encoded_local_proof =
                        encode_multiplication_consistency_proof_artifact(
                            local_proof);
                    local_prover_ready =
                        encoded_local_proof.size() >= 17 &&
                        encoded_local_proof.size() <= (1ULL << 24);
                    if (!local_prover_ready) local_proof_failure_reason = 6;
                } else {
                    local_proof_failure_reason = 5;
                }
            }
            Digest prover_status_binding{};
            if (!CollectiveAllTrue(
                    local_prover_ready, AUTH_KIND_PROVER_STATUS,
                    context->multiplication_id, &prover_status_binding) ||
                prover_status_binding == Digest{}) {
                if (!local_prover_ready) {
                    std::fprintf(stderr,
                        "[PVIA][mc-provider] rank=%d proof generation/encoding failed reason=%d\n",
                        rank_, local_proof_failure_reason);
                }
                return false;
            }


            // All ranks announce their proof lengths, pad to a common width,
            // and gather the complete proof set in one authenticated exchange.
            std::vector<u64> local_proof_size = {
                static_cast<u64>(encoded_local_proof.size())};
            std::vector<u64> all_proof_sizes;
            Digest proof_size_binding{};
            if (!authenticated_exchange_->AllGatherWords(
                    NextTransportContext(
                        AUTH_MPC_PROTOCOL_DOMAIN,
                        AUTH_KIND_PROOF_BATCH_SIZE,
                        context->multiplication_id),
                    local_proof_size, &all_proof_sizes,
                    &proof_size_binding) ||
                all_proof_sizes.size() != static_cast<size_t>(world_size_) ||
                proof_size_binding == Digest{})
                return false;
            size_t max_proof_size = 0;
            for (u64 word_count : all_proof_sizes) {
                if (word_count < 17 || word_count > (1ULL << 24) ||
                    word_count > static_cast<u64>(
                        std::numeric_limits<size_t>::max()))
                    return false;
                max_proof_size = std::max(
                    max_proof_size, static_cast<size_t>(word_count));
            }
            if (max_proof_size == 0 ||
                static_cast<size_t>(world_size_) >
                    std::numeric_limits<size_t>::max() / max_proof_size)
                return false;
            std::vector<u64> padded_local_proof = encoded_local_proof;
            padded_local_proof.resize(max_proof_size, 0);
            std::vector<u64> all_encoded_proofs;
            Digest proof_data_binding{};
            if (!authenticated_exchange_->AllGatherWords(
                    NextTransportContext(
                        AUTH_MPC_PROTOCOL_DOMAIN,
                        AUTH_KIND_PROOF_BATCH_DATA,
                        context->multiplication_id),
                    padded_local_proof, &all_encoded_proofs,
                    &proof_data_binding) ||
                all_encoded_proofs.size() !=
                    static_cast<size_t>(world_size_) * max_proof_size ||
                proof_data_binding == Digest{})
                return false;

            bool all_proofs_verified = true;
            for (int dealer = 0; dealer < world_size_; ++dealer) {
                const size_t size =
                    static_cast<size_t>(
                        all_proof_sizes[static_cast<size_t>(dealer)]);
                const size_t offset =
                    static_cast<size_t>(dealer) * max_proof_size;
                std::vector<u64> encoded(
                    all_encoded_proofs.begin() +
                        static_cast<std::ptrdiff_t>(offset),
                    all_encoded_proofs.begin() +
                        static_cast<std::ptrdiff_t>(offset + size));
                MultiplicationConsistencyProofArtifact proof;
                const bool verified =
                    decode_multiplication_consistency_proof_artifact(
                        encoded, &proof) &&
                    validate_multiplication_consistency_proof_artifact(
                        statements[static_cast<size_t>(dealer)], proof) &&
                    multiplication_consistency_backend_->Verify(
                        statements[static_cast<size_t>(dealer)], proof);
                if (!verified) {
                    all_proofs_verified = false;
                    continue;
                }
                append_digest_words(proof.proof_commitment, &transcript_words);
                proofs.push_back(std::move(proof));
            }
            Digest verify_agreement_binding{};
            if (!CollectiveAllTrue(
                    all_proofs_verified &&
                        proofs.size() == static_cast<size_t>(world_size_),
                    AUTH_KIND_VERIFY_AGREEMENT,
                    context->multiplication_id, &verify_agreement_binding) ||
                verify_agreement_binding == Digest{})
                return false;
            append_digest_words(prover_status_binding, &transcript_words);
            append_digest_words(proof_size_binding, &transcript_words);
            append_digest_words(proof_data_binding, &transcript_words);
            append_digest_words(verify_agreement_binding, &transcript_words);
        } else {
            for (int dealer = 0; dealer < world_size_; ++dealer) {
            std::vector<F> plaintext;
            if (rank_ == dealer) plaintext.push_back(local_product);
            std::vector<F> shares;
            ReferenceVssReceipt receipt;
            ReferenceVssDealerWitness dealer_witness;
            bool shared = false;
            if (authenticated_transport_available()) {
                shared = vss.ShareVectorFromDealerAuthenticated(
                    dealer, plaintext, &shares, &receipt,
                    *authenticated_exchange_,
                    NextTransportContext(AUTH_MPC_PROTOCOL_DOMAIN,
                        AUTH_KIND_MULTIPLY_VSS,
                        static_cast<uint64_t>(dealer)),
                    require_consistency ? &dealer_witness : nullptr, nullptr);
            } else {
                shared = require_consistency
                    ? vss.ShareVectorFromDealerWithWitness(
                        dealer, plaintext, &shares, &receipt, &dealer_witness)
                    : vss.ShareVectorFromDealer(
                        dealer, plaintext, &shares, &receipt);
            }
            if (!shared || shares.size() != 1 || !receipt.available ||
                !receipt.consistent || receipt.transcript_binding == Digest{})
                return false;
            reduced_share +=
                LagrangeAtZero(dealer, world_size_) * shares.front();
            transcript_words.push_back(static_cast<u64>(dealer));
            append_digest_words(receipt.transcript_binding, &transcript_words);

            if (require_consistency) {
                MultiplicationConsistencyStatement statement;
                statement.sid = context->sid;
                statement.checkpoint = context->checkpoint;
                statement.multiplication_id = context->multiplication_id;
                statement.dealer = static_cast<uint32_t>(dealer);
                statement.lhs_sharing_binding = context->lhs_sharing_binding;
                statement.rhs_sharing_binding = context->rhs_sharing_binding;
                statement.output_sharing_binding = receipt.transcript_binding;
                statement.context_binding = context->context_binding;
                statement.statement_binding =
                    compute_multiplication_consistency_statement_binding(statement);
                if (!validate_multiplication_consistency_statement(statement))
                    return false;

                MultiplicationConsistencyProofArtifact local_proof;
                int prover_ready = 1;
                if (rank_ == dealer) {
                    if (!dealer_witness.available ||
                        dealer_witness.dealer != dealer ||
                        dealer_witness.transcript_binding !=
                            receipt.transcript_binding ||
                        dealer_witness.coefficient_words.empty()) {
                        prover_ready = 0;
                    } else {
                        MultiplicationConsistencyWitness witness;
                        witness.lhs_share = lhs_share;
                        witness.rhs_share = rhs_share;
                        witness.product_value = local_product;
                        const std::vector<u64> output_payload =
                            encode_reference_vss_dealer_witness(dealer_witness);
                        const bool input_witness_ready =
                            local_witness &&
                            wrap_reference_multiplication_consistency_input_sharing_witness(
                                local_witness->lhs_sharing_witness_words,
                                statement.lhs_sharing_binding,
                                &witness.lhs_sharing_witness_words) &&
                            wrap_reference_multiplication_consistency_input_sharing_witness(
                                local_witness->rhs_sharing_witness_words,
                                statement.rhs_sharing_binding,
                                &witness.rhs_sharing_witness_words);
                        const bool output_witness_ready =
                            !output_payload.empty() &&
                            wrap_reference_multiplication_consistency_sharing_witness(
                                MultiplicationConsistencySharingWitnessKind::VSS_DEALER,
                                output_payload,
                                statement.output_sharing_binding,
                                &witness.output_sharing_witness_words);
                        if (!input_witness_ready ||
                            !output_witness_ready) {
                            prover_ready = 0;
                        } else {
                            local_proof =
                                multiplication_consistency_backend_->Prove(
                                    statement, witness);
                            if (!validate_multiplication_consistency_proof_artifact(
                                    statement, local_proof) ||
                                !multiplication_consistency_backend_->Verify(
                                    statement, local_proof))
                                prover_ready = 0;
                        }
                    }
                }
                Digest prover_status_binding{};
                if (authenticated_transport_available()) {
                    std::vector<u64> status_payload;
                    if (rank_ == dealer)
                        status_payload = {prover_ready ? 1ULL : 0ULL};
                    std::vector<u64> received_status;
                    if (!authenticated_exchange_->BroadcastWords(
                            NextTransportContext(AUTH_MPC_PROTOCOL_DOMAIN,
                                AUTH_KIND_PROVER_STATUS,
                                static_cast<uint64_t>(dealer)),
                            dealer, status_payload, &received_status,
                            &prover_status_binding) ||
                        received_status.size() != 1 ||
                        received_status.front() != 1ULL)
                        return false;
                } else {
                    MPI_Bcast(&prover_ready, 1, MPI_INT, dealer, comm_);
                    record_control_broadcast(
                        sizeof(int), dealer, rank_, world_size_);
                    if (!prover_ready) return false;
                }
                std::vector<u64> encoded;
                if (rank_ == dealer) {
                    encoded = encode_multiplication_consistency_proof_artifact(
                        local_proof);
                    if (encoded.empty()) return false;
                }
                Digest proof_broadcast_binding{};
                if (authenticated_transport_available()) {
                    std::vector<u64> received_proof;
                    if (!authenticated_exchange_->BroadcastWords(
                            NextTransportContext(AUTH_MPC_PROTOCOL_DOMAIN,
                                AUTH_KIND_PROOF_BROADCAST,
                                static_cast<uint64_t>(dealer)),
                            dealer, encoded, &received_proof,
                            &proof_broadcast_binding))
                        return false;
                    encoded = std::move(received_proof);
                } else {
                    u64 encoded_count = rank_ == dealer
                        ? static_cast<u64>(encoded.size()) : 0ULL;
                    MPI_Bcast(&encoded_count, 1, MPI_UINT64_T, dealer, comm_);
                    record_control_broadcast(
                        sizeof(u64), dealer, rank_, world_size_);
                    if (encoded_count < 17 || encoded_count > static_cast<u64>(
                            std::numeric_limits<int>::max()))
                        return false;
                    if (rank_ != dealer)
                        encoded.resize(static_cast<size_t>(encoded_count));
                    MPI_Bcast(encoded.data(), static_cast<int>(encoded_count),
                              MPI_UINT64_T, dealer, comm_);
                    record_control_broadcast(
                        static_cast<uint64_t>(encoded_count * sizeof(u64)),
                        dealer, rank_, world_size_);
                }
                if (encoded.size() < 17) return false;
                MultiplicationConsistencyProofArtifact proof;
                const int local_verified =
                    decode_multiplication_consistency_proof_artifact(
                        encoded, &proof) &&
                    validate_multiplication_consistency_proof_artifact(
                        statement, proof) &&
                    multiplication_consistency_backend_->Verify(
                        statement, proof) ? 1 : 0;
                Digest verify_agreement_binding{};
                if (!CollectiveAllTrue(local_verified != 0,
                        AUTH_KIND_VERIFY_AGREEMENT,
                        static_cast<uint64_t>(dealer),
                        &verify_agreement_binding))
                    return false;
                proofs.push_back(proof);
                append_digest_words(proof.proof_commitment, &transcript_words);
                if (authenticated_transport_available()) {
                    append_digest_words(prover_status_binding, &transcript_words);
                    append_digest_words(proof_broadcast_binding, &transcript_words);
                    append_digest_words(verify_agreement_binding, &transcript_words);
                }
            }
        }
        }
    } else {
        for (int dealer = 0; dealer < world_size_; ++dealer) {
            F reshared(0);
            const F dealer_value = rank_ == dealer ? local_product : F(0);
            Digest direct_share_binding{};
            if (!ShareLocalContribution(
                    dealer_value, dealer, &reshared, &direct_share_binding))
                return false;
            if (authenticated_transport_available() &&
                direct_share_binding == Digest{})
                return false;
            reduced_share += LagrangeAtZero(dealer, world_size_) * reshared;
            transcript_words.push_back(static_cast<u64>(dealer));
            if (authenticated_transport_available())
                append_digest_words(direct_share_binding, &transcript_words);
        }
    }
    if (require_consistency) {
        const Digest proof_set_binding =
            compute_multiplication_consistency_set_binding(proofs);
        Digest proof_set_agreement_binding{};
        if (proof_set_binding == Digest{} ||
            !CollectiveSameDigest(proof_set_binding, AUTH_KIND_PROOF_SET, 0,
                &proof_set_agreement_binding))
            return false;
        append_digest_words(proof_set_binding, &transcript_words);
        if (authenticated_transport_available())
            append_digest_words(proof_set_agreement_binding, &transcript_words);
    }
    *product_share = reduced_share;
    if (transcript_binding) {
        *transcript_binding = hash_words(transcript_words);
        if (*transcript_binding == Digest{}) return false;
    }
    return true;
}

bool ReferenceShamirMpc::Open(
    const F& local_share, F* opened, Digest* transcript_binding) const {
    if (!valid() || !opened) return false;

    const bool robust = robust_opening_available();
    const bool authenticated = authenticated_transport_available();
    if (robust || authenticated) {
        // With 3t<n, commit-reveal is followed by Reed--Solomon correction.
        // When only 2t<n holds, an installed authenticated transport still
        // prevents sender/context substitution, but reconstruction remains
        // passive: signed bad shares are not corrected.
        std::vector<u64> local_payload(2);
        pack_field(local_share, local_payload.data());
        std::vector<u64> all_payloads;
        Digest reveal_binding{};
        if (!CommitRevealWords(
                OPEN_REVEAL_DOMAIN, local_payload,
                &all_payloads, &reveal_binding) ||
            all_payloads.size() != static_cast<size_t>(world_size_) * 2 ||
            reveal_binding == Digest{})
            return false;

        std::vector<F> shares(static_cast<size_t>(world_size_));
        for (int i = 0; i < world_size_; ++i)
            shares[static_cast<size_t>(i)] =
                unpack_field(&all_payloads[static_cast<size_t>(2 * i)]);
        F value(0);
        if (robust) {
            if (!RobustDecodeShamir(shares, &value)) return false;
        } else {
            const int reconstruction_points = threshold_ + 1;
            if (reconstruction_points <= 0 ||
                reconstruction_points > world_size_)
                return false;
            for (int i = 0; i < reconstruction_points; ++i)
                value += LagrangeAtZero(i, reconstruction_points) *
                    shares[static_cast<size_t>(i)];
        }
        *opened = value;

        if (transcript_binding) {
            std::vector<u64> words = {
                OPEN_RESULT_DOMAIN,
                robust ? 1ULL : 0ULL,
                authenticated ? 1ULL : 0ULL,
                static_cast<u64>(world_size_),
                static_cast<u64>(threshold_),
                value.real, value.img};
            append_digest_words(reveal_binding, &words);
            *transcript_binding = hash_words(words);
            if (*transcript_binding == Digest{}) return false;
        }
        return true;
    }

    std::array<u64, 2> local_words{};
    pack_field(local_share, local_words.data());
    std::vector<u64> gathered;
    if (rank_ == 0) gathered.resize(static_cast<size_t>(world_size_) * 2);
    MPI_Gather(local_words.data(), 2, MPI_UINT64_T,
               rank_ == 0 ? gathered.data() : nullptr, 2, MPI_UINT64_T,
               0, comm_);
    record_control_gather(2 * sizeof(u64), 0, rank_, world_size_);

    F value(0);
    if (rank_ == 0) {
        const int reconstruction_points = threshold_ + 1;
        for (int i = 0; i < reconstruction_points; ++i) {
            const F share =
                unpack_field(&gathered[static_cast<size_t>(2 * i)]);
            value += LagrangeAtZero(i, reconstruction_points) * share;
        }
    }
    std::array<u64, 2> opened_words{};
    if (rank_ == 0) pack_field(value, opened_words.data());
    MPI_Bcast(opened_words.data(), 2, MPI_UINT64_T, 0, comm_);
    record_control_broadcast(2 * sizeof(u64), 0, rank_, world_size_);
    *opened = unpack_field(opened_words.data());
    if (transcript_binding) {
        *transcript_binding = hash_words({
            OPEN_RESULT_DOMAIN, 0ULL,
            static_cast<u64>(world_size_),
            static_cast<u64>(threshold_),
            opened->real, opened->img});
    }
    return true;
}

bool ReferenceShamirMpc::OpenMaskedDegree2tProduct(
    const F& local_product, F* opened,
    Digest* transcript_binding) const {
    if (!valid() || !opened || threshold_ < 0)
        return false;
    const int degree = 2 * threshold_;
    const int reconstruction_points = degree + 1;
    if (degree < 0 || reconstruction_points <= 0 ||
        reconstruction_points > world_size_)
        return false;

    std::vector<F> shares(static_cast<size_t>(world_size_), F(0));
    Digest reveal_binding{};
    const bool commit_reveal =
        authenticated_transport_available() ||
        robust_opening_available();

    if (commit_reveal) {
        std::vector<u64> local_payload(2);
        pack_field(local_product, local_payload.data());
        std::vector<u64> all_payloads;
        if (!CommitRevealWords(
                DEGREE2T_OPEN_REVEAL_DOMAIN,
                local_payload, &all_payloads, &reveal_binding) ||
            all_payloads.size() !=
                static_cast<size_t>(world_size_) * 2 ||
            reveal_binding == Digest{})
            return false;
        for (int participant = 0;
             participant < world_size_; ++participant) {
            shares[static_cast<size_t>(participant)] =
                unpack_field(
                    &all_payloads[
                        static_cast<size_t>(2 * participant)]);
        }
    } else {
        std::array<u64, 2> local_words{};
        pack_field(local_product, local_words.data());
        std::vector<u64> gathered(
            static_cast<size_t>(world_size_) * 2, 0);
        MPI_Allgather(
            local_words.data(), 2, MPI_UINT64_T,
            gathered.data(), 2, MPI_UINT64_T, comm_);
        record_control_allgather(
            2 * sizeof(u64), world_size_);
        for (int participant = 0;
             participant < world_size_; ++participant) {
            shares[static_cast<size_t>(participant)] =
                unpack_field(
                    &gathered[
                        static_cast<size_t>(2 * participant)]);
        }
    }

    // Interpolate the degree-2t polynomial from the minimum number of points.
    F value(0);
    for (int i = 0; i < reconstruction_points; ++i) {
        value += LagrangeAtZero(i, reconstruction_points) *
                 shares[static_cast<size_t>(i)];
    }

    // In the 3t<n regime, any forged product evaluation is detectable:
    // the honest parties contribute more than 2t points on the true product
    // polynomial.  If one of the interpolation points is malformed, at least
    // one honest extra point disagrees with the resulting degree-2t polynomial.
    const bool detectable = 3 * threshold_ < world_size_;
    if (detectable &&
        reconstruction_points < world_size_) {
        std::vector<F> denominator_inverse(
            static_cast<size_t>(reconstruction_points), F(0));
        for (int basis = 0;
             basis < reconstruction_points; ++basis) {
            const F xb(basis + 1);
            F denominator(1);
            for (int other = 0;
                 other < reconstruction_points; ++other) {
                if (other == basis) continue;
                denominator *= xb - F(other + 1);
            }
            if (denominator == F(0)) return false;
            denominator_inverse[static_cast<size_t>(basis)] =
                denominator.inv();
        }
        for (int participant = reconstruction_points;
             participant < world_size_; ++participant) {
            const F x(participant + 1);
            F expected(0);
            for (int basis = 0;
                 basis < reconstruction_points; ++basis) {
                F numerator(1);
                for (int other = 0;
                     other < reconstruction_points; ++other) {
                    if (other == basis) continue;
                    numerator *= x - F(other + 1);
                }
                expected +=
                    shares[static_cast<size_t>(basis)] *
                    numerator *
                    denominator_inverse[
                        static_cast<size_t>(basis)];
            }
            if (expected !=
                shares[static_cast<size_t>(participant)])
                return false;
        }
    }

    *opened = value;
    if (transcript_binding) {
        std::vector<u64> words = {
            DEGREE2T_OPEN_RESULT_DOMAIN,
            commit_reveal ? 1ULL : 0ULL,
            detectable ? 1ULL : 0ULL,
            static_cast<u64>(world_size_),
            static_cast<u64>(threshold_),
            static_cast<u64>(degree),
            static_cast<u64>(reconstruction_points),
            value.real, value.img};
        if (commit_reveal)
            append_digest_words(reveal_binding, &words);
        *transcript_binding = hash_words(words);
        if (*transcript_binding == Digest{})
            return false;
    }
    return true;
}

bool ReferenceShamirMpc::MaskedZeroTest(
    const F& secret_share, bool* is_zero,
    Digest* transcript_binding) const {
    if (!valid() || !is_zero) return false;
    F random_share(0);
    Digest random_sharing_binding{};
    if (!RandomSharedField(&random_share, &random_sharing_binding) ||
        random_sharing_binding == Digest{})
        return false;

    // Never reveal each local degree-2t product by default. The BGW
    // path reduces privately then opens one masked result only.
    const char* allow_legacy =
        std::getenv("PVIA_ALLOW_LEGACY_DIRECT_ZERO_OPEN");
    const bool direct_open =
        allow_legacy && std::strcmp(allow_legacy, "1") == 0 &&
        std::getenv("PVIA_DISABLE_DIRECT_ZERO_OPEN") == nullptr;
    const bool rs_enabled = !direct_open &&
        std::getenv("PVIA_RS_MUL_SYNDROME") &&
        std::strcmp(std::getenv("PVIA_RS_MUL_SYNDROME"), "1") == 0;
    if (rank_ == 0 && std::getenv("PVIA_EXPERIMENT_METRICS"))
        std::fprintf(stderr,
            "[PVIA][zero-test] mode=%s security=%s\n",
            direct_open ? "legacy-direct-open" :
                (rs_enabled ? "rs-syndrome-bgw" : "passive-bgw"),
            rs_enabled ? "conditional-vss-product-consistency" :
                         "passive-only");
    F opened(0);
    Digest product_binding{};
    if (direct_open) {
        const F local_product = random_share * secret_share;
        if (!OpenMaskedDegree2tProduct(
                local_product, &opened, &product_binding) ||
            product_binding == Digest{})
            return false;
    } else {
        F masked_share(0);
        Digest multiplication_binding{};
        if (!Multiply(
                random_share, secret_share, &masked_share,
                &multiplication_binding) ||
            multiplication_binding == Digest{})
            return false;
        Digest opening_binding{};
        if (!Open(masked_share, &opened, &opening_binding) ||
            opening_binding == Digest{})
            return false;
        product_binding = hash_words({
            ZERO_TEST_TRANSCRIPT_DOMAIN, 0ULL,
            static_cast<u64>(world_size_),
            static_cast<u64>(threshold_)});
        if (product_binding == Digest{}) return false;
        std::vector<u64> fallback_words = {
            ZERO_TEST_TRANSCRIPT_DOMAIN, 0ULL,
            static_cast<u64>(world_size_),
            static_cast<u64>(threshold_)};
        append_digest_words(multiplication_binding, &fallback_words);
        append_digest_words(opening_binding, &fallback_words);
        product_binding = hash_words(fallback_words);
        if (product_binding == Digest{}) return false;
    }

    *is_zero = (opened == F(0));
    if (transcript_binding) {
        std::vector<u64> words = {
            ZERO_TEST_TRANSCRIPT_DOMAIN,
            direct_open ? 1ULL : 0ULL,
            detectable_degree_reduction_available() ? 1ULL : 0ULL,
            robust_opening_available() ? 1ULL : 0ULL,
            static_cast<u64>(world_size_),
            static_cast<u64>(threshold_),
            *is_zero ? 1ULL : 0ULL};
        append_digest_words(random_sharing_binding, &words);
        append_digest_words(product_binding, &words);
        *transcript_binding = hash_words(words);
        if (*transcript_binding == Digest{}) return false;
    }
    return true;
}
bool ReferenceShamirMpc::MaskedZeroTestWithConsistency(
    const ReferenceLinearSharingProvenance& secret_provenance,
    const ReferenceMaskedZeroConsistencyContext& context,
    bool* is_zero, Digest* transcript_binding,
    Digest* multiplication_consistency_binding) const {
    if (!valid() || !is_zero) return false;
    const bool authenticated = authenticated_transport_available();
    std::vector<Digest> consistency_control_bindings;

    const bool local_secret_valid =
        validate_reference_linear_sharing_provenance(secret_provenance);
    const bool local_context_valid =
        context.sid != 0 && context.checkpoint != 0 &&
        context.multiplication_id != 0 &&
        context.context_binding != Digest{};

    // The previous implementation checked secret/context readiness in two
    // separate collectives. Requiring every rank to satisfy both predicates
    // is equivalent to one collective over their conjunction.
    Digest preflight_ready_binding{};
    if (!CollectiveAllTrue(
            local_secret_valid && local_context_valid,
            AUTH_KIND_ZERO_PREFLIGHT_READY, 0,
            &preflight_ready_binding))
        return false;

    std::vector<u64> context_words = {
        STRONG_ZERO_TEST_TRANSCRIPT_DOMAIN,
        context.sid, context.checkpoint, context.multiplication_id};
    append_digest_words(context.context_binding, &context_words);
    const Digest zero_context_binding = hash_words(context_words);
    if (zero_context_binding == Digest{})
        return false;

    // Likewise, equality of both bindings on every rank is equivalent
    // (up to collision resistance of the binding hash) to equality of a
    // domain-separated digest of the ordered pair.
    std::vector<u64> preflight_words = {
        ZERO_PREFLIGHT_PAIR_DOMAIN,
        context.sid, context.checkpoint, context.multiplication_id};
    append_digest_words(secret_provenance.binding, &preflight_words);
    append_digest_words(zero_context_binding, &preflight_words);
    const Digest preflight_pair_binding = hash_words(preflight_words);
    Digest preflight_agreement_binding{};
    if (preflight_pair_binding == Digest{} ||
        !CollectiveSameDigest(
            preflight_pair_binding, AUTH_KIND_ZERO_PREFLIGHT_BINDING,
            context.multiplication_id, &preflight_agreement_binding))
        return false;

    F random_share(0);
    ReferenceLinearSharingProvenance random_provenance;
    Digest random_sharing_binding{};
    if (!RandomSharedFieldWithProvenance(
            &random_share, &random_provenance,
            &random_sharing_binding) ||
        random_sharing_binding == Digest{})
        return false;

    std::vector<u64> random_pair_words = {
        ZERO_RANDOM_PAIR_DOMAIN,
        context.sid, context.checkpoint, context.multiplication_id};
    append_digest_words(random_provenance.binding, &random_pair_words);
    append_digest_words(random_sharing_binding, &random_pair_words);
    const Digest random_pair_binding = hash_words(random_pair_words);
    Digest random_pair_agreement_binding{};
    if (random_pair_binding == Digest{} ||
        !CollectiveSameDigest(
            random_pair_binding, AUTH_KIND_ZERO_RANDOM_PAIR,
            context.multiplication_id, &random_pair_agreement_binding))
        return false;

    if (authenticated) {
        consistency_control_bindings = {
            preflight_ready_binding,
            preflight_agreement_binding,
            random_pair_agreement_binding};
    }

    ReferenceMultiplicationConsistencyContext multiplication_context;
    multiplication_context.sid = context.sid;
    multiplication_context.checkpoint = context.checkpoint;
    multiplication_context.multiplication_id = context.multiplication_id;
    multiplication_context.lhs_sharing_binding = random_provenance.binding;
    multiplication_context.rhs_sharing_binding = secret_provenance.binding;
    multiplication_context.context_binding = context.context_binding;

    ReferenceMultiplicationConsistencyLocalWitness local_witness;
    local_witness.lhs_sharing_witness_words =
        encode_reference_linear_sharing_provenance(random_provenance);
    local_witness.rhs_sharing_witness_words =
        encode_reference_linear_sharing_provenance(secret_provenance);
    if (local_witness.lhs_sharing_witness_words.empty() ||
        local_witness.rhs_sharing_witness_words.empty())
        return false;

    F masked_share(0);
    Digest multiplication_binding{};
    if (!MultiplyWithConsistency(
            random_share, secret_provenance.local_share,
            multiplication_context, local_witness,
            &masked_share, &multiplication_binding) ||
        multiplication_binding == Digest{})
        return false;
    if (multiplication_consistency_binding)
        *multiplication_consistency_binding = multiplication_binding;
    F opened(0);
    Digest opening_binding{};
    if (!Open(masked_share, &opened, &opening_binding) ||
        opening_binding == Digest{})
        return false;
    *is_zero = opened == F(0);
    if (transcript_binding) {
        std::vector<u64> words = {
            STRONG_ZERO_TEST_TRANSCRIPT_DOMAIN,
            context.sid, context.checkpoint, context.multiplication_id,
            authenticated ? 1ULL : 0ULL,
            *is_zero ? 1ULL : 0ULL};
        if (authenticated) {
            append_digest_words(
                authenticated_transport_capability_binding(), &words);
            for (const Digest& binding : consistency_control_bindings)
                append_digest_words(binding, &words);
        }
        append_digest_words(context.context_binding, &words);
        append_digest_words(secret_provenance.binding, &words);
        append_digest_words(random_provenance.binding, &words);
        append_digest_words(random_sharing_binding, &words);
        append_digest_words(multiplication_binding, &words);
        append_digest_words(opening_binding, &words);
        *transcript_binding = hash_words(words);
        if (*transcript_binding == Digest{}) return false;
    }
    return true;
}

bool ReferenceShamirMpc::JointPublicSeed(
    Digest* seed, Digest* transcript_binding) const {
    if (!valid() || !seed) return false;
    std::vector<u64> local;
    if (!RandomWordVector(4, &local)) return false;

    std::vector<u64> revealed;
    Digest reveal_binding{};
    if (!CommitRevealWords(
            SEED_REVEAL_DOMAIN, local, &revealed, &reveal_binding))
        return false;
    if (revealed.size() != static_cast<size_t>(world_size_) * local.size())
        return false;

    std::vector<u64> words = {
        SHAMIR_SEED_DOMAIN,
        static_cast<u64>(world_size_),
        static_cast<u64>(threshold_),
        static_cast<u64>(local.size())};
    append_digest_words(reveal_binding, &words);
    words.insert(words.end(), revealed.begin(), revealed.end());
    *seed = hash_words(words);
    if (*seed == Digest{}) return false;
    if (transcript_binding) *transcript_binding = reveal_binding;
    return true;
}


} // namespace pvia
