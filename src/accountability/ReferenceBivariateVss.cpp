#include "ReferenceBivariateVss.hpp"
#include "ReferenceVssResidualSourceLink.hpp"
#include "ReferenceVssShareRecovery.hpp"
#include "ProtocolTrafficMetrics.hpp"
#include "MultiplicationConsistencyProviderAbiC.h"

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <limits>
#include <vector>

namespace pvia {
namespace {

constexpr u64 VSS_TRANSCRIPT_DOMAIN = PVIA_MC_VSS_TRANSCRIPT_DOMAIN;
constexpr u64 VSS_DEALER_WITNESS_DOMAIN = PVIA_MC_VSS_DEALER_WITNESS_DOMAIN;
constexpr u64 VSS_LOCAL_WITNESS_DOMAIN = PVIA_MC_VSS_LOCAL_WITNESS_DOMAIN;
constexpr u64 VSS_AUTH_SHAPE = 0x5653534153484150ULL; // VSSASHAP
constexpr u64 VSS_AUTH_SHAPE_OK = 0x5653534153484f4bULL; // VSSASHOK
constexpr u64 VSS_AUTH_DEALER_OK = 0x56535341444c524fULL; // VSSADLRO
constexpr u64 VSS_AUTH_ROWS = 0x56535341524f5753ULL; // VSSAROWS
constexpr u64 VSS_AUTH_CROSS = 0x5653534143524f53ULL; // VSSACROS
constexpr u64 VSS_AUTH_CONSISTENCY = 0x56535341434f4e53ULL; // VSSACONS
constexpr u64 VSS_AUTH_COMMITMENTS = 0x56535341434d4954ULL; // VSSACMIT
constexpr u64 VSS_AUTH_BATCH_READY = 0x5653424154524459ULL; // VSBATRDY
constexpr u64 VSS_AUTH_BATCH_ROWS = 0x5653424154524f57ULL; // VSBATROW
constexpr u64 VSS_AUTH_BATCH_CROSS = 0x5653424154435253ULL; // VSBATCRS
constexpr u64 VSS_AUTH_BATCH_CONSISTENCY = 0x5653424154434f4eULL; // VSBATCON
constexpr u64 VSS_AUTH_BATCH_COMMITMENTS = 0x5653424154434d54ULL; // VSBATCMT
constexpr u64 VSS_AUTH_BATCH_FINAL = 0x565342415446494eULL; // VSBATFIN
constexpr u64 VSS_BATCH_BINDING_DOMAIN = 0x5056565353424154ULL; // PVVSSBAT

void pack_field(const F& value, u64* out) {
    out[0] = value.real;
    out[1] = value.img;
}

F unpack_field(const u64* in) {
    return F(static_cast<long long>(in[0]),
             static_cast<long long>(in[1]));
}

void append_digest_words(const Digest& digest, std::vector<u64>* words) {
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

Digest read_digest_words(const std::vector<u64>& words, size_t offset) {
    Digest digest{};
    if (offset > words.size() || words.size() - offset < 4) return digest;
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(digest.bytes.data() + 8 * i, &words[offset + i], 8);
    return digest;
}
bool random_field_vector(size_t count, std::vector<F>* values) {
    if (!values) return false;
    values->clear();
    if (count == 0) return true;
    if (count > std::numeric_limits<size_t>::max() / 2) return false;
    std::vector<u64> words(count * 2);
    unsigned char* bytes = reinterpret_cast<unsigned char*>(words.data());
    const size_t total_bytes = words.size() * sizeof(u64);
    constexpr size_t MAX_CHUNK = 1u << 20;
    size_t offset = 0;
    while (offset < total_bytes) {
        const size_t chunk = std::min(MAX_CHUNK, total_bytes - offset);
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

F evaluate_polynomial(const F* coefficients, int degree, const F& x) {
    F value(0);
    for (int d = degree; d >= 0; --d)
        value = value * x + coefficients[d];
    return value;
}
F lagrange_at_zero(int index, int count) {
    const F xi(index + 1);
    F coefficient(1);
    for (int j = 0; j < count; ++j) {
        if (j == index) continue;
        const F xj(j + 1);
        coefficient *= (-xj) * (xi - xj).inv();
    }
    return coefficient;
}

bool all_ranks_true(int local_ok, MPI_Comm comm) {
    int global_ok = 0;
    int world_size = 0;
    MPI_Comm_size(comm, &world_size);
    MPI_Allreduce(&local_ok, &global_ok, 1, MPI_INT, MPI_MIN, comm);
    record_control_allreduce(sizeof(int), world_size);
    return global_ok != 0;
}

AuthenticatedMpcMessageContext vss_subcontext(
    const AuthenticatedMpcMessageContext& base, u64 stage) {
    AuthenticatedMpcMessageContext context = base;
    context.message_kind = base.message_kind ^ stage;
    if (context.message_kind == 0) context.message_kind = stage;
    return context;
}

Digest derive_vss_batch_transport_binding(
    const AuthenticatedMpcMessageContext& base,
    u64 stage, int dealer, const Digest& batch_binding) {
    if (!validate_authenticated_mpc_message_context(base) ||
        stage == 0 || dealer < 0 || batch_binding == Digest{})
        return {};
    std::vector<u64> words = {
        VSS_BATCH_BINDING_DOMAIN, stage,
        static_cast<u64>(dealer)};
    append_digest_words(
        compute_authenticated_mpc_context_binding(base), &words);
    append_digest_words(batch_binding, &words);
    return hash_words(words);
}

} // namespace

Digest compute_reference_vss_transcript_binding(
    int dealer, int threshold, size_t element_count,
    const ReferenceVssTranscriptContext& context) {
    if (dealer < 0 || threshold < 0 || element_count == 0 ||
        context.world_size < 2 || dealer >= context.world_size ||
        threshold >= context.world_size ||
        context.row_commitments.size() !=
            static_cast<size_t>(context.world_size))
        return {};
    if (context.authenticated) {
        if (context.capability_binding == Digest{} ||
            context.transport_bindings.empty())
            return {};
    } else if (context.capability_binding != Digest{} ||
               !context.transport_bindings.empty()) {
        return {};
    }
    for (const Digest& digest : context.row_commitments)
        if (digest == Digest{}) return {};
    for (const Digest& digest : context.transport_bindings)
        if (digest == Digest{}) return {};

    std::vector<u64> words = {
        VSS_TRANSCRIPT_DOMAIN,
        static_cast<u64>(dealer),
        static_cast<u64>(context.world_size),
        static_cast<u64>(threshold),
        static_cast<u64>(element_count),
        context.authenticated ? 1ULL : 0ULL,
        static_cast<u64>(context.transport_bindings.size())};
    if (context.authenticated) {
        append_digest_words(context.capability_binding, &words);
        for (const Digest& binding : context.transport_bindings)
            append_digest_words(binding, &words);
    }
    for (const Digest& row_digest : context.row_commitments)
        append_digest_words(row_digest, &words);
    return hash_words(words);
}

static bool compute_reference_vss_dealer_row_commitments(
    const ReferenceVssDealerWitness& witness,
    std::vector<Digest>* row_commitments) {
    if (!row_commitments || witness.dealer < 0 || witness.threshold < 0 ||
        witness.element_count == 0 ||
        witness.transcript_context.world_size < 2 ||
        witness.dealer >= witness.transcript_context.world_size)
        return false;
    const size_t dimension = static_cast<size_t>(witness.threshold + 1);
    if (dimension == 0 ||
        witness.element_count > std::numeric_limits<size_t>::max() /
            dimension ||
        witness.element_count * dimension >
            std::numeric_limits<size_t>::max() / dimension)
        return false;
    const size_t fields =
        witness.element_count * dimension * dimension;
    if (fields > std::numeric_limits<size_t>::max() / 2 ||
        witness.coefficient_words.size() != fields * 2)
        return false;

    std::vector<F> coefficients(fields);
    for (size_t i = 0; i < fields; ++i) {
        if (witness.coefficient_words[2 * i] >= PVIA_MC_FIELD_MODULUS ||
            witness.coefficient_words[2 * i + 1] >= PVIA_MC_FIELD_MODULUS)
            return false;
        coefficients[i] = unpack_field(&witness.coefficient_words[2 * i]);
    }
    for (size_t k = 0; k < witness.element_count; ++k) {
        for (size_t a = 0; a < dimension; ++a) {
            for (size_t b = 0; b < dimension; ++b) {
                if (coefficients[(k * dimension + a) * dimension + b] !=
                    coefficients[(k * dimension + b) * dimension + a])
                    return false;
            }
        }
    }

    row_commitments->clear();
    row_commitments->reserve(
        static_cast<size_t>(witness.transcript_context.world_size));
    const size_t fields_per_rank = witness.element_count * dimension;
    for (int participant = 0;
         participant < witness.transcript_context.world_size;
         ++participant) {
        const F x(participant + 1);
        std::vector<F> local_rows(fields_per_rank, F(0));
        for (size_t k = 0; k < witness.element_count; ++k) {
            for (size_t b = 0; b < dimension; ++b) {
                F value(0);
                F power(1);
                for (size_t a = 0; a < dimension; ++a) {
                    value +=
                        coefficients[(k * dimension + a) * dimension + b] *
                        power;
                    power *= x;
                }
                local_rows[k * dimension + b] = value;
            }
        }
        row_commitments->push_back(hash_field_vector(local_rows));
    }
    return true;
}

bool validate_reference_vss_dealer_witness(
    const ReferenceVssDealerWitness& witness) {
    if (!witness.available || witness.dealer < 0 || witness.threshold < 0 ||
        witness.element_count == 0 || witness.transcript_binding == Digest{})
        return false;
    std::vector<Digest> derived_commitments;
    if (!compute_reference_vss_dealer_row_commitments(
            witness, &derived_commitments) ||
        derived_commitments != witness.transcript_context.row_commitments)
        return false;
    return compute_reference_vss_transcript_binding(
               witness.dealer, witness.threshold, witness.element_count,
               witness.transcript_context) ==
        witness.transcript_binding;
}

bool validate_reference_vss_local_witness(
    const ReferenceVssLocalWitness& witness) {
    if (!witness.available || witness.dealer < 0 ||
        witness.participant < 0 || witness.threshold < 0 ||
        witness.element_count == 0 ||
        witness.local_row_commitment == Digest{} ||
        witness.transcript_binding == Digest{} ||
        witness.transcript_context.world_size < 2 ||
        witness.dealer >= witness.transcript_context.world_size ||
        witness.participant >= witness.transcript_context.world_size ||
        witness.transcript_context.row_commitments.size() !=
            static_cast<size_t>(witness.transcript_context.world_size))
        return false;
    const size_t dimension = static_cast<size_t>(witness.threshold + 1);
    if (witness.element_count >
        std::numeric_limits<size_t>::max() / dimension)
        return false;
    const size_t fields = witness.element_count * dimension;
    if (fields > std::numeric_limits<size_t>::max() / 2 ||
        witness.local_row_words.size() != fields * 2)
        return false;
    std::vector<F> row(fields);
    for (size_t i = 0; i < fields; ++i) {
        if (witness.local_row_words[2 * i] >= PVIA_MC_FIELD_MODULUS ||
            witness.local_row_words[2 * i + 1] >= PVIA_MC_FIELD_MODULUS)
            return false;
        row[i] = unpack_field(&witness.local_row_words[2 * i]);
    }
    if (hash_field_vector(row) != witness.local_row_commitment ||
        witness.transcript_context.row_commitments[
            static_cast<size_t>(witness.participant)] !=
            witness.local_row_commitment)
        return false;
    return compute_reference_vss_transcript_binding(
               witness.dealer, witness.threshold, witness.element_count,
               witness.transcript_context) ==
        witness.transcript_binding;
}

namespace {
constexpr u64 VSS_WITNESS_VERSION = PVIA_MC_VSS_WITNESS_VERSION;
constexpr size_t VSS_DEALER_WITNESS_FIXED_WORDS = PVIA_MC_VSS_DEALER_FIXED_WORDS;
constexpr size_t VSS_LOCAL_WITNESS_FIXED_WORDS = PVIA_MC_VSS_LOCAL_FIXED_WORDS;

void append_digest_vector(
    const std::vector<Digest>& digests, std::vector<u64>* words) {
    for (const Digest& digest : digests)
        append_digest_words(digest, words);
}

bool read_digest_vector(
    const std::vector<u64>& words, size_t* offset, size_t count,
    std::vector<Digest>* digests) {
    if (!offset || !digests ||
        count > (words.size() - std::min(*offset, words.size())) / 4)
        return false;
    digests->clear();
    digests->reserve(count);
    for (size_t i = 0; i < count; ++i) {
        digests->push_back(read_digest_words(words, *offset));
        *offset += 4;
    }
    return true;
}
} // namespace

std::vector<u64> encode_reference_vss_dealer_witness(
    const ReferenceVssDealerWitness& witness) {
    if (!validate_reference_vss_dealer_witness(witness)) return {};
    const auto& context = witness.transcript_context;
    std::vector<u64> words = {
        VSS_DEALER_WITNESS_DOMAIN,
        VSS_WITNESS_VERSION,
        static_cast<u64>(witness.dealer),
        static_cast<u64>(context.world_size),
        static_cast<u64>(witness.threshold),
        static_cast<u64>(witness.element_count),
        context.authenticated ? 1ULL : 0ULL,
        static_cast<u64>(context.transport_bindings.size()),
        static_cast<u64>(context.row_commitments.size()),
        static_cast<u64>(witness.coefficient_words.size())};
    append_digest_words(context.capability_binding, &words);
    append_digest_words(witness.transcript_binding, &words);
    append_digest_vector(context.transport_bindings, &words);
    append_digest_vector(context.row_commitments, &words);
    words.insert(words.end(), witness.coefficient_words.begin(),
                 witness.coefficient_words.end());
    return words;
}

std::vector<u64> encode_reference_vss_local_witness(
    const ReferenceVssLocalWitness& witness) {
    if (!validate_reference_vss_local_witness(witness)) return {};
    const auto& context = witness.transcript_context;
    std::vector<u64> words = {
        VSS_LOCAL_WITNESS_DOMAIN,
        VSS_WITNESS_VERSION,
        static_cast<u64>(witness.dealer),
        static_cast<u64>(witness.participant),
        static_cast<u64>(context.world_size),
        static_cast<u64>(witness.threshold),
        static_cast<u64>(witness.element_count),
        context.authenticated ? 1ULL : 0ULL,
        static_cast<u64>(context.transport_bindings.size()),
        static_cast<u64>(context.row_commitments.size()),
        static_cast<u64>(witness.local_row_words.size())};
    append_digest_words(context.capability_binding, &words);
    append_digest_words(witness.local_row_commitment, &words);
    append_digest_words(witness.transcript_binding, &words);
    append_digest_vector(context.transport_bindings, &words);
    append_digest_vector(context.row_commitments, &words);
    words.insert(words.end(), witness.local_row_words.begin(),
                 witness.local_row_words.end());
    return words;
}

bool decode_reference_vss_dealer_witness(
    const std::vector<u64>& words, ReferenceVssDealerWitness* witness) {
    if (!witness || words.size() < VSS_DEALER_WITNESS_FIXED_WORDS ||
        words[0] != VSS_DEALER_WITNESS_DOMAIN ||
        words[1] != VSS_WITNESS_VERSION ||
        words[2] > static_cast<u64>(std::numeric_limits<int>::max()) ||
        words[3] > static_cast<u64>(std::numeric_limits<int>::max()) ||
        words[4] > static_cast<u64>(std::numeric_limits<int>::max()) ||
        words[5] > static_cast<u64>(std::numeric_limits<size_t>::max()) ||
        words[6] > 1)
        return false;
    const size_t transport_count = static_cast<size_t>(words[7]);
    const size_t row_count = static_cast<size_t>(words[8]);
    const size_t coefficient_count = static_cast<size_t>(words[9]);
    if (row_count != static_cast<size_t>(words[3]))
        return false;
    size_t expected = VSS_DEALER_WITNESS_FIXED_WORDS;
    if (transport_count >
            (std::numeric_limits<size_t>::max() - expected) / 4)
        return false;
    expected += transport_count * 4;
    if (row_count > (std::numeric_limits<size_t>::max() - expected) / 4)
        return false;
    expected += row_count * 4;
    if (coefficient_count > std::numeric_limits<size_t>::max() - expected)
        return false;
    expected += coefficient_count;
    if (words.size() != expected) return false;

    ReferenceVssDealerWitness decoded;
    decoded.available = true;
    decoded.dealer = static_cast<int>(words[2]);
    decoded.transcript_context.world_size = static_cast<int>(words[3]);
    decoded.threshold = static_cast<int>(words[4]);
    decoded.element_count = static_cast<size_t>(words[5]);
    decoded.transcript_context.authenticated = words[6] != 0;
    decoded.transcript_context.capability_binding =
        read_digest_words(words, 10);
    decoded.transcript_binding = read_digest_words(words, 14);
    size_t offset = VSS_DEALER_WITNESS_FIXED_WORDS;
    if (!read_digest_vector(
            words, &offset, transport_count,
            &decoded.transcript_context.transport_bindings) ||
        !read_digest_vector(
            words, &offset, row_count,
            &decoded.transcript_context.row_commitments))
        return false;
    decoded.coefficient_words.assign(words.begin() + offset, words.end());
    if (!validate_reference_vss_dealer_witness(decoded)) return false;
    *witness = std::move(decoded);
    return true;
}

bool decode_reference_vss_local_witness(
    const std::vector<u64>& words, ReferenceVssLocalWitness* witness) {
    if (!witness || words.size() < VSS_LOCAL_WITNESS_FIXED_WORDS ||
        words[0] != VSS_LOCAL_WITNESS_DOMAIN ||
        words[1] != VSS_WITNESS_VERSION ||
        words[2] > static_cast<u64>(std::numeric_limits<int>::max()) ||
        words[3] > static_cast<u64>(std::numeric_limits<int>::max()) ||
        words[4] > static_cast<u64>(std::numeric_limits<int>::max()) ||
        words[5] > static_cast<u64>(std::numeric_limits<int>::max()) ||
        words[6] > static_cast<u64>(std::numeric_limits<size_t>::max()) ||
        words[7] > 1)
        return false;
    const size_t transport_count = static_cast<size_t>(words[8]);
    const size_t row_count = static_cast<size_t>(words[9]);
    const size_t local_row_count = static_cast<size_t>(words[10]);
    if (row_count != static_cast<size_t>(words[4]))
        return false;
    size_t expected = VSS_LOCAL_WITNESS_FIXED_WORDS;
    if (transport_count >
            (std::numeric_limits<size_t>::max() - expected) / 4)
        return false;
    expected += transport_count * 4;
    if (row_count > (std::numeric_limits<size_t>::max() - expected) / 4)
        return false;
    expected += row_count * 4;
    if (local_row_count > std::numeric_limits<size_t>::max() - expected)
        return false;
    expected += local_row_count;
    if (words.size() != expected) return false;

    ReferenceVssLocalWitness decoded;
    decoded.available = true;
    decoded.dealer = static_cast<int>(words[2]);
    decoded.participant = static_cast<int>(words[3]);
    decoded.transcript_context.world_size = static_cast<int>(words[4]);
    decoded.threshold = static_cast<int>(words[5]);
    decoded.element_count = static_cast<size_t>(words[6]);
    decoded.transcript_context.authenticated = words[7] != 0;
    decoded.transcript_context.capability_binding =
        read_digest_words(words, 11);
    decoded.local_row_commitment = read_digest_words(words, 15);
    decoded.transcript_binding = read_digest_words(words, 19);
    size_t offset = VSS_LOCAL_WITNESS_FIXED_WORDS;
    if (!read_digest_vector(
            words, &offset, transport_count,
            &decoded.transcript_context.transport_bindings) ||
        !read_digest_vector(
            words, &offset, row_count,
            &decoded.transcript_context.row_commitments))
        return false;
    decoded.local_row_words.assign(words.begin() + offset, words.end());
    if (!validate_reference_vss_local_witness(decoded)) return false;
    *witness = std::move(decoded);
    return true;
}

ReferenceBivariateVss::ReferenceBivariateVss(
    int rank, int world_size, int threshold, MPI_Comm comm)
    : rank_(rank), world_size_(world_size), threshold_(threshold), comm_(comm) {}

bool ReferenceBivariateVss::valid() const {
    return rank_ >= 0 && rank_ < world_size_ && world_size_ >= 2 &&
           threshold_ >= 0 && 3 * threshold_ < world_size_;
}

bool ReferenceBivariateVss::ShareVectorFromDealer(
    int dealer, const std::vector<F>& dealer_plaintext,
    std::vector<F>* local_shares, ReferenceVssReceipt* receipt) const {
    return ShareVectorInternal(
        dealer, dealer_plaintext, false, local_shares, receipt);
}
bool ReferenceBivariateVss::ShareVectorFromDealerWithWitness(
    int dealer, const std::vector<F>& dealer_plaintext,
    std::vector<F>* local_shares, ReferenceVssReceipt* receipt,
    ReferenceVssDealerWitness* dealer_witness) const {
    if (!dealer_witness) return false;
    return ShareVectorInternal(
        dealer, dealer_plaintext, false, local_shares, receipt,
        dealer_witness);
}
bool ReferenceBivariateVss::ShareVectorFromDealerWithLocalWitness(
    int dealer, const std::vector<F>& dealer_plaintext,
    std::vector<F>* local_shares, ReferenceVssReceipt* receipt,
    ReferenceVssLocalWitness* local_witness) const {
    if (!local_witness) return false;
    return ShareVectorInternal(
        dealer, dealer_plaintext, false, local_shares, receipt,
        nullptr, local_witness);
}
bool ReferenceBivariateVss::ShareVectorFromDealerWithWitnesses(
    int dealer, const std::vector<F>& dealer_plaintext,
    std::vector<F>* local_shares, ReferenceVssReceipt* receipt,
    ReferenceVssDealerWitness* dealer_witness,
    ReferenceVssLocalWitness* local_witness) const {
    if (!dealer_witness || !local_witness) return false;
    return ShareVectorInternal(
        dealer, dealer_plaintext, false, local_shares, receipt,
        dealer_witness, local_witness);
}

bool ReferenceBivariateVss::ShareVectorFromDealerAuthenticated(
    int dealer, const std::vector<F>& dealer_plaintext,
    std::vector<F>* local_shares, ReferenceVssReceipt* receipt,
    const AuthenticatedMpcExchange& exchange,
    const AuthenticatedMpcMessageContext& context,
    ReferenceVssDealerWitness* dealer_witness,
    ReferenceVssLocalWitness* local_witness) const {
    if (!exchange.production_authenticated_ready() ||
        !validate_authenticated_mpc_message_context(context))
        return false;
    return ShareVectorInternal(
        dealer, dealer_plaintext, false, local_shares, receipt,
        dealer_witness, local_witness, &exchange, &context);
}

bool ReferenceBivariateVss::ShareScalarsFromPrefixDealersAuthenticated(
    int dealer_count, const F& local_dealer_plaintext,
    std::vector<F>* local_shares,
    std::vector<ReferenceVssReceipt>* receipts,
    const AuthenticatedMpcExchange& exchange,
    const AuthenticatedMpcMessageContext& context,
    std::vector<ReferenceVssLocalWitness>* local_witnesses,
    std::vector<ReferenceVssDealerWitness>* dealer_witnesses) const {
    const std::vector<F> plaintext = {local_dealer_plaintext};
    return ShareVectorsFromPrefixDealersAuthenticated(
        dealer_count, plaintext, 1, local_shares, receipts,
        exchange, context, local_witnesses, dealer_witnesses);
}

bool ReferenceBivariateVss::ShareVectorsFromPrefixDealersAuthenticated(
    int dealer_count,
    const std::vector<F>& local_dealer_plaintext,
    size_t element_count,
    std::vector<F>* local_shares,
    std::vector<ReferenceVssReceipt>* receipts,
    const AuthenticatedMpcExchange& exchange,
    const AuthenticatedMpcMessageContext& context,
    std::vector<ReferenceVssLocalWitness>* local_witnesses,
    std::vector<ReferenceVssDealerWitness>* dealer_witnesses) const {
    if (!valid() || dealer_count <= 0 || dealer_count > world_size_ ||
        element_count == 0 ||
        local_dealer_plaintext.size() != element_count ||
        !local_shares || !receipts ||
        !exchange.production_authenticated_ready() ||
        !validate_authenticated_mpc_message_context(context))
        return false;

    local_shares->clear();
    receipts->clear();
    if (local_witnesses) local_witnesses->clear();
    if (dealer_witnesses) dealer_witnesses->clear();

    const size_t dimension = static_cast<size_t>(threshold_ + 1);
    if (dimension == 0 ||
        dimension > std::numeric_limits<size_t>::max() / dimension)
        return false;
    const size_t matrix_fields = dimension * dimension;
    if (element_count >
            std::numeric_limits<size_t>::max() / matrix_fields ||
        dimension >
            static_cast<size_t>(std::numeric_limits<int>::max()) / 2)
        return false;
    const size_t dealer_matrix_fields = element_count * matrix_fields;

    const bool active_dealer = rank_ < dealer_count;
    std::vector<F> local_coefficients;
    int local_ready = 1;
    if (active_dealer) {
        local_coefficients.assign(dealer_matrix_fields, F(0));
        const size_t upper_random =
            dimension * (dimension + 1) / 2 - 1;
        if (upper_random > 0 &&
            element_count >
                std::numeric_limits<size_t>::max() / upper_random)
            return false;
        std::vector<F> random_coefficients;
        if (upper_random > 0 &&
            !random_field_vector(
                element_count * upper_random, &random_coefficients)) {
            local_ready = 0;
        } else {
            size_t random_index = 0;
            for (size_t element = 0;
                 element < element_count; ++element) {
                const size_t matrix_base =
                    element * matrix_fields;
                for (size_t a = 0; a < dimension; ++a) {
                    for (size_t b = a; b < dimension; ++b) {
                        F coefficient;
                        if (a == 0 && b == 0) {
                            coefficient =
                                local_dealer_plaintext[element];
                        } else {
                            coefficient =
                                random_coefficients[random_index++];
                        }
                        local_coefficients[
                            matrix_base + a * dimension + b] =
                            coefficient;
                        local_coefficients[
                            matrix_base + b * dimension + a] =
                            coefficient;
                    }
                }
            }
        }
    }

    // Readiness is piggybacked on the first row exchange.  Each active
    // dealer contributes element_count independent bivariate polynomials.
    if (element_count >
        (std::numeric_limits<size_t>::max() - 1) /
            (2 * dimension))
        return false;
    const size_t row_words_per_receiver =
        1 + 2 * element_count * dimension;
    if (row_words_per_receiver >
        static_cast<size_t>(std::numeric_limits<int>::max()))
        return false;

    std::vector<u64> row_send(
        static_cast<size_t>(world_size_) * row_words_per_receiver, 0);
    for (int recipient = 0; recipient < world_size_; ++recipient) {
        const size_t recipient_base =
            static_cast<size_t>(recipient) * row_words_per_receiver;
        row_send[recipient_base] = local_ready ? 1ULL : 0ULL;
        if (!active_dealer) continue;
        const F x(recipient + 1);
        for (size_t element = 0;
             element < element_count; ++element) {
            const size_t matrix_base =
                element * matrix_fields;
            for (size_t b = 0; b < dimension; ++b) {
                F row_coefficient(0);
                F power(1);
                for (size_t a = 0; a < dimension; ++a) {
                    row_coefficient +=
                        local_coefficients[
                            matrix_base + a * dimension + b] *
                        power;
                    power *= x;
                }
                const size_t field_index =
                    element * dimension + b;
                pack_field(
                    row_coefficient,
                    &row_send[
                        recipient_base + 1 +
                        2 * field_index]);
            }
        }
    }

    std::vector<u64> row_recv;
    Digest rows_binding{};
    if (!exchange.AllToAllWords(
            vss_subcontext(context, VSS_AUTH_BATCH_ROWS),
            row_send, row_words_per_receiver,
            &row_recv, &rows_binding) ||
        row_recv.size() != row_send.size() ||
        rows_binding == Digest{})
        return false;

    bool observed_ready = true;
    for (int sender = 0; sender < world_size_; ++sender) {
        const size_t sender_base =
            static_cast<size_t>(sender) * row_words_per_receiver;
        if (row_recv[sender_base] != 1ULL)
            observed_ready = false;
    }

    const size_t row_fields_per_dealer =
        element_count * dimension;
    std::vector<std::vector<F>> local_rows(
        static_cast<size_t>(dealer_count),
        std::vector<F>(row_fields_per_dealer, F(0)));
    for (int dealer = 0; dealer < dealer_count; ++dealer) {
        const size_t base =
            static_cast<size_t>(dealer) *
                row_words_per_receiver + 1;
        for (size_t field = 0;
             field < row_fields_per_dealer; ++field) {
            local_rows[static_cast<size_t>(dealer)][field] =
                unpack_field(&row_recv[base + 2 * field]);
        }
    }

    if (element_count >
        std::numeric_limits<size_t>::max() /
            (2 * static_cast<size_t>(dealer_count)))
        return false;
    const size_t cross_words_per_receiver =
        2 * static_cast<size_t>(dealer_count) *
        element_count;
    if (cross_words_per_receiver >
        static_cast<size_t>(std::numeric_limits<int>::max()))
        return false;
    std::vector<u64> cross_send(
        static_cast<size_t>(world_size_) *
            cross_words_per_receiver, 0);
    for (int target = 0; target < world_size_; ++target) {
        const F target_point(target + 1);
        const size_t target_base =
            static_cast<size_t>(target) *
            cross_words_per_receiver;
        for (int dealer = 0; dealer < dealer_count; ++dealer) {
            for (size_t element = 0;
                 element < element_count; ++element) {
                const F intersection = evaluate_polynomial(
                    &local_rows[static_cast<size_t>(dealer)]
                               [element * dimension],
                    threshold_, target_point);
                const size_t field_index =
                    static_cast<size_t>(dealer) *
                        element_count + element;
                pack_field(
                    intersection,
                    &cross_send[
                        target_base + 2 * field_index]);
            }
        }
    }

    std::vector<u64> cross_recv;
    Digest cross_binding{};
    if (!exchange.AllToAllWords(
            vss_subcontext(context, VSS_AUTH_BATCH_CROSS),
            cross_send, cross_words_per_receiver,
            &cross_recv, &cross_binding) ||
        cross_recv.size() != cross_send.size() ||
        cross_binding == Digest{})
        return false;

    int local_consistent = observed_ready ? 1 : 0;
    for (int sender = 0;
         sender < world_size_ && local_consistent; ++sender) {
        const F sender_point(sender + 1);
        const size_t sender_base =
            static_cast<size_t>(sender) *
            cross_words_per_receiver;
        for (int dealer = 0;
             dealer < dealer_count && local_consistent; ++dealer) {
            for (size_t element = 0;
                 element < element_count; ++element) {
                const F mine = evaluate_polynomial(
                    &local_rows[static_cast<size_t>(dealer)]
                               [element * dimension],
                    threshold_, sender_point);
                const size_t field_index =
                    static_cast<size_t>(dealer) *
                        element_count + element;
                const F theirs = unpack_field(
                    &cross_recv[
                        sender_base + 2 * field_index]);
                if (mine != theirs) {
                    local_consistent = 0;
                    break;
                }
            }
        }
    }

    std::vector<Digest> local_commitments(
        static_cast<size_t>(dealer_count));
    std::vector<u64> commitment_words(
        static_cast<size_t>(dealer_count) * 4, 0);
    for (int dealer = 0; dealer < dealer_count; ++dealer) {
        const Digest commitment =
            hash_field_vector(
                local_rows[static_cast<size_t>(dealer)]);
        if (commitment == Digest{}) return false;
        local_commitments[static_cast<size_t>(dealer)] =
            commitment;
        for (size_t word = 0; word < 4; ++word) {
            std::memcpy(
                &commitment_words[
                    static_cast<size_t>(dealer) * 4 + word],
                commitment.bytes.data() + 8 * word, 8);
        }
    }

    std::vector<u64> final_words(
        1 + static_cast<size_t>(dealer_count) * 4, 0);
    final_words[0] = local_consistent ? 1ULL : 0ULL;
    std::copy(
        commitment_words.begin(), commitment_words.end(),
        final_words.begin() + 1);

    std::vector<u64> gathered_final;
    Digest final_binding{};
    if (!exchange.AllGatherWords(
            vss_subcontext(context, VSS_AUTH_BATCH_FINAL),
            final_words, &gathered_final, &final_binding) ||
        gathered_final.size() !=
            static_cast<size_t>(world_size_) *
                final_words.size() ||
        final_binding == Digest{})
        return false;

    std::vector<u64> gathered_commitments(
        static_cast<size_t>(world_size_) *
            static_cast<size_t>(dealer_count) * 4, 0);
    const size_t final_stride = final_words.size();
    for (int participant = 0;
         participant < world_size_; ++participant) {
        const size_t final_base =
            static_cast<size_t>(participant) * final_stride;
        if (gathered_final[final_base] != 1ULL)
            return false;
        const size_t commit_dst =
            static_cast<size_t>(participant) *
            static_cast<size_t>(dealer_count) * 4;
        std::copy(
            gathered_final.begin() +
                static_cast<std::ptrdiff_t>(
                    final_base + 1),
            gathered_final.begin() +
                static_cast<std::ptrdiff_t>(
                    final_base + 1 +
                    static_cast<size_t>(dealer_count) * 4),
            gathered_commitments.begin() +
                static_cast<std::ptrdiff_t>(commit_dst));
    }

    const Digest capability_binding =
        exchange.ProductionCapabilityBinding();
    if (capability_binding == Digest{}) return false;

    if (static_cast<size_t>(dealer_count) >
        std::numeric_limits<size_t>::max() /
            element_count)
        return false;
    local_shares->resize(
        static_cast<size_t>(dealer_count) *
        element_count);
    receipts->resize(static_cast<size_t>(dealer_count));
    if (local_witnesses)
        local_witnesses->resize(
            static_cast<size_t>(dealer_count));
    if (dealer_witnesses)
        dealer_witnesses->resize(
            static_cast<size_t>(dealer_count));

    for (int dealer = 0; dealer < dealer_count; ++dealer) {
        ReferenceVssTranscriptContext transcript_context;
        transcript_context.world_size = world_size_;
        transcript_context.authenticated = true;
        transcript_context.capability_binding =
            capability_binding;
        const std::array<std::pair<u64, Digest>, 3>
            batch_stages = {{
                {VSS_AUTH_BATCH_ROWS, rows_binding},
                {VSS_AUTH_BATCH_CROSS, cross_binding},
                {VSS_AUTH_BATCH_FINAL, final_binding}
            }};
        transcript_context.transport_bindings.reserve(
            batch_stages.size());
        for (const auto& stage : batch_stages) {
            const Digest derived =
                derive_vss_batch_transport_binding(
                    context, stage.first, dealer,
                    stage.second);
            if (derived == Digest{}) return false;
            transcript_context.transport_bindings.push_back(
                derived);
        }

        transcript_context.row_commitments.resize(
            static_cast<size_t>(world_size_));
        for (int participant = 0;
             participant < world_size_; ++participant) {
            const size_t offset =
                (static_cast<size_t>(participant) *
                     static_cast<size_t>(dealer_count) +
                 static_cast<size_t>(dealer)) * 4;
            const Digest row_commitment =
                read_digest_words(
                    gathered_commitments, offset);
            if (row_commitment == Digest{})
                return false;
            transcript_context.row_commitments[
                static_cast<size_t>(participant)] =
                row_commitment;
        }

        ReferenceVssReceipt receipt;
        receipt.available = true;
        receipt.consistent = true;
        receipt.dealer = dealer;
        receipt.world_size = world_size_;
        receipt.threshold = threshold_;
        receipt.element_count = element_count;
        receipt.local_row_commitment =
            local_commitments[
                static_cast<size_t>(dealer)];
        receipt.transcript_binding =
            compute_reference_vss_transcript_binding(
                dealer, threshold_, element_count,
                transcript_context);
        if (receipt.transcript_binding == Digest{})
            return false;

        for (size_t element = 0;
             element < element_count; ++element) {
            (*local_shares)[
                static_cast<size_t>(dealer) *
                    element_count + element] =
                local_rows[static_cast<size_t>(dealer)]
                          [element * dimension];
        }
        (*receipts)[static_cast<size_t>(dealer)] =
            receipt;

        if (local_witnesses) {
            ReferenceVssLocalWitness witness;
            witness.available = true;
            witness.dealer = dealer;
            witness.participant = rank_;
            witness.threshold = threshold_;
            witness.element_count = element_count;
            witness.local_row_commitment =
                receipt.local_row_commitment;
            witness.transcript_binding =
                receipt.transcript_binding;
            witness.transcript_context =
                transcript_context;
            witness.local_row_words.resize(
                2 * row_fields_per_dealer);
            for (size_t field = 0;
                 field < row_fields_per_dealer; ++field) {
                pack_field(
                    local_rows[static_cast<size_t>(dealer)]
                              [field],
                    &witness.local_row_words[2 * field]);
            }
            if (!validate_reference_vss_local_witness(
                    witness))
                return false;
            (*local_witnesses)[
                static_cast<size_t>(dealer)] =
                std::move(witness);
        }
        // The batch already has the dealer's private coefficient matrix and
        // the complete authenticated transcript context. Return that witness
        // only to the local dealer so strong multiplication proofs can be
        // generated in parallel after all VSS receipts are fixed.
        if (dealer_witnesses && rank_ == dealer) {
            ReferenceVssDealerWitness witness;
            witness.available = true;
            witness.dealer = dealer;
            witness.threshold = threshold_;
            witness.element_count = element_count;
            witness.transcript_binding = receipt.transcript_binding;
            witness.transcript_context = transcript_context;
            witness.coefficient_words.resize(
                2 * local_coefficients.size());
            for (size_t i = 0; i < local_coefficients.size(); ++i)
                pack_field(
                    local_coefficients[i],
                    &witness.coefficient_words[2 * i]);
            if (!validate_reference_vss_dealer_witness(witness))
                return false;
            (*dealer_witnesses)[static_cast<size_t>(dealer)] =
                std::move(witness);
        }
    }

    return true;
}

bool ReferenceBivariateVss::ShareVectorInternal(
    int dealer, const std::vector<F>& dealer_plaintext,
    bool inject_dealer_equivocation,
    std::vector<F>* local_shares, ReferenceVssReceipt* receipt,
    ReferenceVssDealerWitness* dealer_witness,
    ReferenceVssLocalWitness* local_witness,
    const AuthenticatedMpcExchange* authenticated_exchange,
    const AuthenticatedMpcMessageContext* authenticated_context) const {
    if (!valid() || !local_shares || !receipt ||
        dealer < 0 || dealer >= world_size_)
        return false;
    const bool authenticated =
        authenticated_exchange != nullptr || authenticated_context != nullptr;
    if (authenticated &&
        (!authenticated_exchange || !authenticated_context ||
         !authenticated_exchange->production_authenticated_ready() ||
         !validate_authenticated_mpc_message_context(*authenticated_context)))
        return false;
    std::vector<Digest> transport_bindings;
    *receipt = ReferenceVssReceipt{};
    if (dealer_witness) *dealer_witness = ReferenceVssDealerWitness{};
    if (local_witness) *local_witness = ReferenceVssLocalWitness{};
    local_shares->clear();

    u64 element_count = rank_ == dealer
        ? static_cast<u64>(dealer_plaintext.size()) : 0ULL;
    if (authenticated) {
        std::vector<u64> shape_payload;
        if (rank_ == dealer) shape_payload = {element_count};
        std::vector<u64> received_shape;
        Digest transport_binding{};
        if (!authenticated_exchange->BroadcastWords(
                vss_subcontext(*authenticated_context, VSS_AUTH_SHAPE),
                dealer, shape_payload, &received_shape, &transport_binding) ||
            received_shape.size() != 1 || transport_binding == Digest{})
            return false;
        element_count = received_shape.front();
        transport_bindings.push_back(transport_binding);
    } else {
        MPI_Bcast(&element_count, 1, MPI_UINT64_T, dealer, comm_);
        record_control_broadcast(sizeof(u64), dealer, rank_, world_size_);
    }
    const int shape_ok = element_count > 0 &&
        element_count <= static_cast<u64>(std::numeric_limits<size_t>::max()) &&
        (rank_ != dealer || dealer_plaintext.size() == element_count);
    if (authenticated) {
        bool all_shape_ok = false;
        Digest transport_binding{};
        if (!authenticated_exchange->AllTrue(
                vss_subcontext(*authenticated_context, VSS_AUTH_SHAPE_OK),
                shape_ok != 0, &all_shape_ok, &transport_binding) ||
            !all_shape_ok || transport_binding == Digest{})
            return false;
        transport_bindings.push_back(transport_binding);
    } else if (!all_ranks_true(shape_ok ? 1 : 0, comm_)) {
        return false;
    }

    const size_t count = static_cast<size_t>(element_count);
    const size_t dimension = static_cast<size_t>(threshold_ + 1);
    if (count > std::numeric_limits<size_t>::max() /
                    (dimension * dimension))
        return false;
    const size_t matrix_words = count * dimension * dimension;
    std::vector<F> coefficient_matrices;
    std::vector<u64> dealer_send_words;
    int dealer_ok = 1;
    if (rank_ == dealer) {
        coefficient_matrices.assign(matrix_words, F(0));
        const size_t upper_per_secret =
            dimension * (dimension + 1) / 2 - 1;
        std::vector<F> random_coefficients;
        if (count > 0 && upper_per_secret > 0 &&
            (count > std::numeric_limits<size_t>::max() / upper_per_secret ||
             !random_field_vector(count * upper_per_secret,
                                  &random_coefficients))) {
            dealer_ok = 0;
        }
        size_t random_index = 0;
        if (dealer_ok) {
            for (size_t k = 0; k < count; ++k) {
                for (size_t a = 0; a < dimension; ++a) {
                    for (size_t b = a; b < dimension; ++b) {
                        F coefficient;
                        if (a == 0 && b == 0)
                            coefficient = dealer_plaintext[k];
                        else
                            coefficient = random_coefficients[random_index++];
                        coefficient_matrices[(k * dimension + a) * dimension + b] =
                            coefficient;
                        coefficient_matrices[(k * dimension + b) * dimension + a] =
                            coefficient;
                    }
                }
            }
        }
    }
    if (authenticated) {
        std::vector<u64> dealer_status;
        if (rank_ == dealer) dealer_status = {dealer_ok ? 1ULL : 0ULL};
        std::vector<u64> received_status;
        Digest transport_binding{};
        if (!authenticated_exchange->BroadcastWords(
                vss_subcontext(*authenticated_context, VSS_AUTH_DEALER_OK),
                dealer, dealer_status, &received_status, &transport_binding) ||
            received_status.size() != 1 || received_status.front() > 1 ||
            transport_binding == Digest{})
            return false;
        dealer_ok = received_status.front() != 0 ? 1 : 0;
        transport_bindings.push_back(transport_binding);
    } else {
        MPI_Bcast(&dealer_ok, 1, MPI_INT, dealer, comm_);
        record_control_broadcast(sizeof(int), dealer, rank_, world_size_);
    }
    if (!dealer_ok) return false;

    const size_t fields_per_rank = count * dimension;
    if (fields_per_rank > static_cast<size_t>(std::numeric_limits<int>::max()) / 2)
        return false;
    const size_t words_per_rank = fields_per_rank * 2;
    if (rank_ == dealer) {
        if (words_per_rank > std::numeric_limits<size_t>::max() /
                                 static_cast<size_t>(world_size_))
            return false;
        dealer_send_words.resize(
            words_per_rank * static_cast<size_t>(world_size_));
        for (int recipient = 0; recipient < world_size_; ++recipient) {
            const F x(recipient + 1);
            for (size_t k = 0; k < count; ++k) {
                for (size_t b = 0; b < dimension; ++b) {
                    F row_coefficient(0);
                    F power(1);
                    for (size_t a = 0; a < dimension; ++a) {
                        row_coefficient +=
                            coefficient_matrices[(k * dimension + a) *
                                                 dimension + b] * power;
                        power *= x;
                    }
                    const size_t field_index = k * dimension + b;
                    pack_field(row_coefficient,
                        &dealer_send_words[
                            static_cast<size_t>(recipient) * words_per_rank +
                            2 * field_index]);
                }
            }
        }
        if (inject_dealer_equivocation && world_size_ > 1 && count > 0) {
            const int target = (dealer + 1) % world_size_;
            const size_t offset = static_cast<size_t>(target) * words_per_rank;
            F tampered = unpack_field(&dealer_send_words[offset]);
            tampered += F(1);
            pack_field(tampered, &dealer_send_words[offset]);
        }
    }

    std::vector<u64> local_row_words(words_per_rank);
    if (authenticated) {
        std::vector<u64> scatter_payload;
        if (rank_ == dealer) scatter_payload = dealer_send_words;
        Digest transport_binding{};
        if (!authenticated_exchange->ScatterWords(
                vss_subcontext(*authenticated_context, VSS_AUTH_ROWS),
                dealer, scatter_payload, words_per_rank,
                &local_row_words, &transport_binding) ||
            local_row_words.size() != words_per_rank ||
            transport_binding == Digest{})
            return false;
        transport_bindings.push_back(transport_binding);
    } else {
        MPI_Scatter(rank_ == dealer ? dealer_send_words.data() : nullptr,
                    static_cast<int>(words_per_rank), MPI_UINT64_T,
                    local_row_words.data(), static_cast<int>(words_per_rank),
                    MPI_UINT64_T, dealer, comm_);
        record_control_scatter(
            static_cast<uint64_t>(words_per_rank * sizeof(u64)),
            dealer, rank_, world_size_);
    }
    std::vector<F> local_rows(fields_per_rank);
    for (size_t i = 0; i < fields_per_rank; ++i)
        local_rows[i] = unpack_field(&local_row_words[2 * i]);
    const size_t cross_words_per_peer = count * 2;
    if (cross_words_per_peer >
        static_cast<size_t>(std::numeric_limits<int>::max()))
        return false;
    std::vector<u64> cross_send(
        cross_words_per_peer * static_cast<size_t>(world_size_));
    for (int target = 0; target < world_size_; ++target) {
        const F x(target + 1);
        for (size_t k = 0; k < count; ++k) {
            const F intersection = evaluate_polynomial(
                &local_rows[k * dimension], threshold_, x);
            pack_field(intersection,
                &cross_send[static_cast<size_t>(target) *
                                cross_words_per_peer +
                            2 * k]);
        }
    }
    std::vector<u64> cross_recv(cross_send.size());
    if (authenticated) {
        Digest transport_binding{};
        if (!authenticated_exchange->AllToAllWords(
                vss_subcontext(*authenticated_context, VSS_AUTH_CROSS),
                cross_send, cross_words_per_peer,
                &cross_recv, &transport_binding) ||
            cross_recv.size() != cross_send.size() ||
            transport_binding == Digest{})
            return false;
        transport_bindings.push_back(transport_binding);
    } else {
        MPI_Alltoall(cross_send.data(), static_cast<int>(cross_words_per_peer),
                     MPI_UINT64_T,
                     cross_recv.data(), static_cast<int>(cross_words_per_peer),
                     MPI_UINT64_T, comm_);
        record_control_all_peer_exchange(
            static_cast<uint64_t>(cross_words_per_peer * sizeof(u64)),
            world_size_);
    }

    int local_consistent = 1;
    for (int sender = 0; sender < world_size_ && local_consistent; ++sender) {
        const F sender_point(sender + 1);
        for (size_t k = 0; k < count; ++k) {
            const F mine = evaluate_polynomial(
                &local_rows[k * dimension], threshold_, sender_point);
            const F theirs = unpack_field(
                &cross_recv[static_cast<size_t>(sender) *
                                cross_words_per_peer +
                            2 * k]);
            if (mine != theirs) {
                local_consistent = 0;
                break;
            }
        }
    }
    if (authenticated) {
        bool all_consistent = false;
        Digest transport_binding{};
        if (!authenticated_exchange->AllTrue(
                vss_subcontext(
                    *authenticated_context, VSS_AUTH_CONSISTENCY),
                local_consistent != 0, &all_consistent,
                &transport_binding) ||
            !all_consistent || transport_binding == Digest{})
            return false;
        transport_bindings.push_back(transport_binding);
    } else if (!all_ranks_true(local_consistent, comm_)) {
        return false;
    }
    local_shares->resize(count);
    for (size_t k = 0; k < count; ++k)
        (*local_shares)[k] = local_rows[k * dimension];

    const Digest local_row_commitment = hash_field_vector(local_rows);
    std::vector<Digest> row_commitments(static_cast<size_t>(world_size_));
    if (authenticated) {
        std::vector<u64> local_commitment_words;
        append_digest_words(local_row_commitment, &local_commitment_words);
        std::vector<u64> gathered_words;
        Digest transport_binding{};
        if (!authenticated_exchange->AllGatherWords(
                vss_subcontext(
                    *authenticated_context, VSS_AUTH_COMMITMENTS),
                local_commitment_words, &gathered_words,
                &transport_binding) ||
            gathered_words.size() != static_cast<size_t>(world_size_) * 4 ||
            transport_binding == Digest{})
            return false;
        transport_bindings.push_back(transport_binding);
        for (int participant = 0; participant < world_size_; ++participant)
            row_commitments[static_cast<size_t>(participant)] =
                read_digest_words(gathered_words,
                    static_cast<size_t>(participant) * 4);
    } else {
        std::vector<uint8_t> gathered_commitments(
            static_cast<size_t>(world_size_) * local_row_commitment.bytes.size());
        MPI_Allgather(local_row_commitment.bytes.data(),
                      static_cast<int>(local_row_commitment.bytes.size()), MPI_BYTE,
                      gathered_commitments.data(),
                      static_cast<int>(local_row_commitment.bytes.size()), MPI_BYTE,
                      comm_);
        record_control_allgather(
            static_cast<uint64_t>(local_row_commitment.bytes.size()),
            world_size_);
        for (int participant = 0; participant < world_size_; ++participant) {
            Digest row_digest{};
            std::memcpy(row_digest.bytes.data(),
                gathered_commitments.data() +
                    static_cast<size_t>(participant) * row_digest.bytes.size(),
                row_digest.bytes.size());
            row_commitments[static_cast<size_t>(participant)] = row_digest;
        }
    }
    ReferenceVssTranscriptContext transcript_context;
    transcript_context.world_size = world_size_;
    transcript_context.authenticated = authenticated;
    if (authenticated) {
        transcript_context.capability_binding =
            authenticated_exchange->ProductionCapabilityBinding();
        if (transcript_context.capability_binding == Digest{})
            return false;
    }
    transcript_context.transport_bindings = transport_bindings;
    transcript_context.row_commitments = row_commitments;

    receipt->available = true;
    receipt->consistent = true;
    receipt->dealer = dealer;
    receipt->world_size = world_size_;
    receipt->threshold = threshold_;
    receipt->element_count = count;
    receipt->local_row_commitment = local_row_commitment;
    receipt->transcript_context = transcript_context;
    receipt->transcript_binding =
        compute_reference_vss_transcript_binding(
            dealer, threshold_, count, transcript_context);
    if (receipt->transcript_binding == Digest{}) return false;
    if (local_witness) {
        local_witness->available = true;
        local_witness->dealer = dealer;
        local_witness->participant = rank_;
        local_witness->threshold = threshold_;
        local_witness->element_count = count;
        local_witness->local_row_commitment = local_row_commitment;
        local_witness->transcript_binding = receipt->transcript_binding;
        local_witness->transcript_context = transcript_context;
        local_witness->local_row_words = local_row_words;
    }
    if (dealer_witness && rank_ == dealer) {
        if (coefficient_matrices.size() >
            std::numeric_limits<size_t>::max() / 2)
            return false;
        dealer_witness->available = true;
        dealer_witness->dealer = dealer;
        dealer_witness->threshold = threshold_;
        dealer_witness->element_count = count;
        dealer_witness->transcript_binding = receipt->transcript_binding;
        dealer_witness->transcript_context = transcript_context;
        dealer_witness->coefficient_words.resize(
            coefficient_matrices.size() * 2);
        for (size_t i = 0; i < coefficient_matrices.size(); ++i)
            pack_field(coefficient_matrices[i],
                &dealer_witness->coefficient_words[2 * i]);
    }
    return true;
}
bool ReferenceBivariateVss::SelfTest(int rank, int world_size) {
    if (world_size < 4 || rank < 0 || rank >= world_size) return false;
    const int threshold = (world_size - 1) / 3;
    ReferenceBivariateVss vss(rank, world_size, threshold);
    if (!vss.valid()) return false;

    const int dealer = 0;
    std::vector<F> canonical(8);
    for (size_t i = 0; i < canonical.size(); ++i)
        canonical[i] = F(static_cast<long long>(100 + i),
                         static_cast<long long>(700 + 3 * i));
    std::vector<F> plaintext;
    if (rank == dealer) plaintext = canonical;
    std::vector<F> local_shares;
    ReferenceVssReceipt receipt;
    ReferenceVssDealerWitness dealer_witness;
    ReferenceVssLocalWitness local_witness;
    const bool honest_ok = vss.ShareVectorFromDealerWithWitnesses(
        dealer, plaintext, &local_shares, &receipt,
        &dealer_witness, &local_witness);
    int local_ok = honest_ok && receipt.available && receipt.consistent &&
        receipt.threshold == threshold &&
        receipt.element_count == canonical.size() &&
        local_shares.size() == canonical.size() &&
        validate_reference_vss_local_witness(local_witness) ? 1 : 0;

    if (local_ok) {
        const std::vector<u64> encoded_local =
            encode_reference_vss_local_witness(local_witness);
        ReferenceVssLocalWitness decoded_local;
        if (encoded_local.empty() ||
            !decode_reference_vss_local_witness(
                encoded_local, &decoded_local) ||
            decoded_local.transcript_binding != receipt.transcript_binding ||
            decoded_local.local_row_commitment !=
                local_witness.local_row_commitment ||
            compute_reference_vss_transcript_binding(
                decoded_local.dealer, decoded_local.threshold,
                decoded_local.element_count,
                decoded_local.transcript_context) !=
                receipt.transcript_binding)
            local_ok = 0;
    }

    if (local_ok && rank == dealer) {
        const std::vector<u64> encoded_dealer =
            encode_reference_vss_dealer_witness(dealer_witness);
        ReferenceVssDealerWitness decoded_dealer;
        if (!validate_reference_vss_dealer_witness(dealer_witness) ||
            encoded_dealer.empty() ||
            !decode_reference_vss_dealer_witness(
                encoded_dealer, &decoded_dealer) ||
            decoded_dealer.transcript_binding != receipt.transcript_binding ||
            compute_reference_vss_transcript_binding(
                decoded_dealer.dealer, decoded_dealer.threshold,
                decoded_dealer.element_count,
                decoded_dealer.transcript_context) !=
                receipt.transcript_binding)
            local_ok = 0;
    }

    if (local_ok) {
        std::vector<F> changed_local = local_shares;
        changed_local[0] += F(1);
        const Digest bad_transcript = hash_words({
            0x505649415653534cULL, receipt.element_count});
        if (!verify_reference_vss_recipient_share_link(
                local_witness, local_shares, receipt.transcript_binding) ||
            verify_reference_vss_recipient_share_link(
                local_witness, changed_local, receipt.transcript_binding) ||
            verify_reference_vss_recipient_share_link(
                local_witness, local_shares, bad_transcript) ||
            verify_reference_vss_recipient_authenticated_share_link(
                local_witness, local_shares, receipt.transcript_binding,
                hash_words({0x5056494156535343ULL})))
            local_ok = 0;
    }

    if (local_ok && rank == dealer) {
        // VSS linkage: dealer polynomial's constant coefficients must match
        // the caller's privately expected vector, not a value supplied by
        // the witness itself.
        std::vector<F> tampered_secret = canonical;
        tampered_secret[0] += F(1);
        const Digest wrong_transcript = hash_words({
            0x505649415653534cULL, receipt.element_count});
        if (!verify_reference_vss_dealer_secret_link(
                dealer_witness, canonical, receipt.transcript_binding) ||
            verify_reference_vss_dealer_secret_link(
                dealer_witness, tampered_secret, receipt.transcript_binding) ||
            verify_reference_vss_dealer_secret_link(
                dealer_witness, canonical, wrong_transcript) ||
            verify_reference_vss_dealer_authenticated_source_link(
                dealer_witness, canonical, receipt.transcript_binding,
                hash_words({0x5056494156535343ULL})))
            local_ok = 0;
    }

    std::vector<u64> local_words(canonical.size() * 2);
    if (local_ok) {
        for (size_t i = 0; i < local_shares.size(); ++i)
            pack_field(local_shares[i], &local_words[2 * i]);
    }
    std::vector<u64> all_words(
        static_cast<size_t>(world_size) * local_words.size());
    MPI_Allgather(local_words.data(), static_cast<int>(local_words.size()),
                  MPI_UINT64_T,
                  all_words.data(), static_cast<int>(local_words.size()),
                  MPI_UINT64_T, MPI_COMM_WORLD);
    if (local_ok && rank == 0) {
        const int points = threshold + 1;
        for (size_t k = 0; k < canonical.size(); ++k) {
            F reconstructed(0);
            for (int i = 0; i < points; ++i) {
                const size_t off = static_cast<size_t>(i) * local_words.size() +
                                   2 * k;
                reconstructed += lagrange_at_zero(i, points) *
                                 unpack_field(&all_words[off]);
            }
            if (reconstructed != canonical[k]) {
                local_ok = 0;
                break;
            }
        }
    }
    // Diagnostic-only recovery fixture: the MPI selftest exchanges raw
    // private helper rows ONLY inside this explicit research test. This is
    // not the privacy-preserving recovery transport or public evidence.
    const size_t expected_row_words =
        canonical.size()*static_cast<size_t>(threshold+1)*2;
    std::vector<u64> row_payload(expected_row_words,0);
    if(local_witness.local_row_words.size()==expected_row_words)
        row_payload=local_witness.local_row_words;
    else local_ok=0;
    std::vector<u64> gathered_rows(
        static_cast<size_t>(world_size)*expected_row_words);
    MPI_Allgather(row_payload.data(),static_cast<int>(expected_row_words),
                  MPI_UINT64_T,gathered_rows.data(),
                  static_cast<int>(expected_row_words),
                  MPI_UINT64_T,MPI_COMM_WORLD);
    int recovery_ok=local_ok;
    if(rank==0 && recovery_ok) {
        auto recovered_matches = [&](int missing,
                                    const std::vector<ReferenceVssLocalWitness>& rows) {
            std::vector<F> restored;
            if(!recover_reference_vss_share_from_rows(
                   missing,receipt,rows,&restored) ||
               restored.size()!=canonical.size()) return false;
            for(size_t k=0;k<canonical.size();++k) {
                const size_t off=static_cast<size_t>(missing)*
                                  local_words.size()+2*k;
                if(restored[k]!=unpack_field(&all_words[off]))
                    return false;
            }
            return true;
        };
        const int missing_candidates[] = {0,world_size/2,world_size-1};
        for(int missing:missing_candidates) {
            std::vector<ReferenceVssLocalWitness> helpers;
            for(int participant=0;participant<world_size;++participant) {
                if(participant==missing)continue;
                ReferenceVssLocalWitness witness=local_witness;
                witness.participant=participant;
                witness.local_row_commitment=
                    witness.transcript_context.row_commitments[
                        static_cast<size_t>(participant)];
                const auto begin=gathered_rows.begin()+
                    static_cast<size_t>(participant)*expected_row_words;
                witness.local_row_words.assign(
                    begin,begin+expected_row_words);
                helpers.push_back(std::move(witness));
            }
            if(!recovered_matches(missing,helpers)) {
                recovery_ok=0;break;
            }
            const size_t required=static_cast<size_t>(threshold+1);
            std::vector<ReferenceVssLocalWitness> minimal(
                helpers.begin(),helpers.begin()+required);
            if(!recovered_matches(missing,minimal)) {
                recovery_ok=0;break;
            }
            std::vector<F> recovered;
            auto corrupted=helpers;
            corrupted[0].local_row_words[0]^=1;
            if(recover_reference_vss_share_from_rows(
                   missing,receipt,corrupted,&recovered)) {
                recovery_ok=0;break;
            }
            auto repeated=helpers;
            repeated[1]=repeated[0];
            if(recover_reference_vss_share_from_rows(
                   missing,receipt,repeated,&recovered)) {
                recovery_ok=0;break;
            }
            auto too_few=minimal;
            too_few.pop_back();
            if(recover_reference_vss_share_from_rows(
                   missing,receipt,too_few,&recovered)) {
                recovery_ok=0;break;
            }
            auto altered_binding=receipt;
            altered_binding.transcript_binding.bytes[0]^=1;
            if(recover_reference_vss_share_from_rows(
                   missing,altered_binding,helpers,&recovered)) {
                recovery_ok=0;break;
            }
            auto wrong_epoch=helpers;
            wrong_epoch[0].transcript_binding.bytes[0]^=1;
            if(recover_reference_vss_share_from_rows(
                   missing,receipt,wrong_epoch,&recovered)) {
                recovery_ok=0;break;
            }
            auto included_missing=helpers;
            included_missing[0].participant=missing;
            if(recover_reference_vss_share_from_rows(
                   missing,receipt,included_missing,&recovered)) {
                recovery_ok=0;break;
            }
        }
    }
    MPI_Bcast(&recovery_ok,1,MPI_INT,0,MPI_COMM_WORLD);
    local_ok=local_ok && recovery_ok;

    std::vector<F> bad_shares;
    ReferenceVssReceipt bad_receipt;
    const bool equivocation_accepted = vss.ShareVectorInternal(
        dealer, plaintext, true, &bad_shares, &bad_receipt);
    const int detected = equivocation_accepted ? 0 : 1;
    int detected_all = 0;
    MPI_Allreduce(&detected, &detected_all, 1, MPI_INT, MPI_MIN,
                  MPI_COMM_WORLD);
    int final_ok = local_ok && detected_all ? 1 : 0;
    int global_ok = 0;
    MPI_Allreduce(&final_ok, &global_ok, 1, MPI_INT, MPI_MIN,
                  MPI_COMM_WORLD);
    if (rank == 0) {
        std::cout << "[PVIA][bivariate-vss-selftest] threshold="
                  << threshold
                  << " honest=" << (local_ok ? "PASS" : "FAIL")
                  << " codec=" << (local_ok ? "BOUND" : "FAIL")
                  << " share_recovery="
                  << (recovery_ok ? "PASS" : "FAIL")
                  << " recovery_inputs=OFFLINE_PRIVATE_TEST_ROWS"
                  << " equivocation="
                  << (detected_all ? "DETECTED" : "MISSED")
                  << " result=" << (global_ok ? "PASS" : "FAIL")
                  << "\n";
    }
    return global_ok != 0;
}

} // namespace pvia
