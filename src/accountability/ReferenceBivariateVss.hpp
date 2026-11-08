#pragma once

#include "PVIA.hpp"
#include "AuthenticatedMpcExchange.hpp"

#include <mpi.h>
#include <vector>

namespace pvia {

struct ReferenceVssTranscriptContext {
    int world_size = 0;
    bool authenticated = false;
    Digest capability_binding{};
    std::vector<Digest> transport_bindings;
    std::vector<Digest> row_commitments;
};

Digest compute_reference_vss_transcript_binding(
    int dealer, int threshold, size_t element_count,
    const ReferenceVssTranscriptContext& context);

struct ReferenceVssReceipt {
    bool available = false;
    bool consistent = false;
    int dealer = -1;
    int world_size = 0;
    int threshold = -1;
    size_t element_count = 0;
    Digest local_row_commitment{};
    Digest transcript_binding{};
    ReferenceVssTranscriptContext transcript_context{};
};

struct ReferenceVssDealerWitness {
    bool available = false;
    int dealer = -1;
    int threshold = -1;
    size_t element_count = 0;
    Digest transcript_binding{};
    ReferenceVssTranscriptContext transcript_context{};
    // Dealer-local encoding of the symmetric bivariate coefficient matrices.
    // Never broadcast by ReferenceBivariateVss; intended only as prover input.
    std::vector<u64> coefficient_words;
};

struct ReferenceVssLocalWitness {
    bool available = false;
    int dealer = -1;
    int participant = -1;
    int threshold = -1;
    size_t element_count = 0;
    Digest local_row_commitment{};
    Digest transcript_binding{};
    ReferenceVssTranscriptContext transcript_context{};
    // Recipient-local bivariate row coefficients. This is private provenance
    // material and is never included in the public VSS transcript.
    std::vector<u64> local_row_words;
};

bool validate_reference_vss_dealer_witness(
    const ReferenceVssDealerWitness& witness);
bool validate_reference_vss_local_witness(
    const ReferenceVssLocalWitness& witness);
std::vector<u64> encode_reference_vss_dealer_witness(
    const ReferenceVssDealerWitness& witness);
std::vector<u64> encode_reference_vss_local_witness(
    const ReferenceVssLocalWitness& witness);
bool decode_reference_vss_dealer_witness(
    const std::vector<u64>& words, ReferenceVssDealerWitness* witness);
bool decode_reference_vss_local_witness(
    const std::vector<u64>& words, ReferenceVssLocalWitness* witness);

// Development/reference VSS based on a symmetric bivariate polynomial.
// For t < n/3 and authenticated private channels, honest parties either
// obtain shares of one well-defined degree-t secret sharing or detect an
// inconsistency and abort. It does NOT provide guaranteed output delivery,
// Byzantine-resilient broadcast, or the packed ABDE construction.
class ReferenceBivariateVss {
public:
    ReferenceBivariateVss(
        int rank, int world_size, int threshold,
        MPI_Comm comm = MPI_COMM_WORLD);

    bool valid() const;

    bool ShareVectorFromDealer(
        int dealer,
        const std::vector<F>& dealer_plaintext,
        std::vector<F>* local_shares,
        ReferenceVssReceipt* receipt) const;
    bool ShareVectorFromDealerWithWitness(
        int dealer, const std::vector<F>& dealer_plaintext,
        std::vector<F>* local_shares, ReferenceVssReceipt* receipt,
        ReferenceVssDealerWitness* dealer_witness) const;
    bool ShareVectorFromDealerWithLocalWitness(
        int dealer, const std::vector<F>& dealer_plaintext,
        std::vector<F>* local_shares, ReferenceVssReceipt* receipt,
        ReferenceVssLocalWitness* local_witness) const;
    bool ShareVectorFromDealerWithWitnesses(
        int dealer, const std::vector<F>& dealer_plaintext,
        std::vector<F>* local_shares, ReferenceVssReceipt* receipt,
        ReferenceVssDealerWitness* dealer_witness,
        ReferenceVssLocalWitness* local_witness) const;

    // Production-authenticated transport path. This requires an Ed25519
    // registry anchored outside the current MPI session and binds every VSS
    // communication phase into the resulting receipt transcript.
    bool ShareVectorFromDealerAuthenticated(
        int dealer, const std::vector<F>& dealer_plaintext,
        std::vector<F>* local_shares, ReferenceVssReceipt* receipt,
        const AuthenticatedMpcExchange& exchange,
        const AuthenticatedMpcMessageContext& context,
        ReferenceVssDealerWitness* dealer_witness = nullptr,
        ReferenceVssLocalWitness* local_witness = nullptr) const;

    // Batched scalar VSS for a deterministic prefix of dealers. Each active
    // dealer still samples an independent symmetric bivariate polynomial and
    // receives an independent receipt. Only the transport rounds are packed.
    // This path is intended for scalar resharing/randomness/degree reduction.
    bool ShareScalarsFromPrefixDealersAuthenticated(
        int dealer_count, const F& local_dealer_plaintext,
        std::vector<F>* local_shares,
        std::vector<ReferenceVssReceipt>* receipts,
        const AuthenticatedMpcExchange& exchange,
        const AuthenticatedMpcMessageContext& context,
        std::vector<ReferenceVssLocalWitness>* local_witnesses = nullptr,
        std::vector<ReferenceVssDealerWitness>* dealer_witnesses = nullptr) const;

    // Generalization of the scalar-prefix batch to a fixed-width vector per
    // active dealer.  The output is dealer-major:
    // local_shares[dealer * element_count + element].
    // Each dealer receives one receipt/local witness covering its complete
    // vector, while rows/cross-check/finalization share the same three
    // authenticated transport stages across all elements and dealers.
    bool ShareVectorsFromPrefixDealersAuthenticated(
        int dealer_count,
        const std::vector<F>& local_dealer_plaintext,
        size_t element_count,
        std::vector<F>* local_shares,
        std::vector<ReferenceVssReceipt>* receipts,
        const AuthenticatedMpcExchange& exchange,
        const AuthenticatedMpcMessageContext& context,
        std::vector<ReferenceVssLocalWitness>* local_witnesses = nullptr,
        std::vector<ReferenceVssDealerWitness>* dealer_witnesses = nullptr) const;

    static bool SelfTest(int rank, int world_size);

private:
    bool ShareVectorInternal(
        int dealer,
        const std::vector<F>& dealer_plaintext,
        bool inject_dealer_equivocation,
        std::vector<F>* local_shares,
        ReferenceVssReceipt* receipt,
        ReferenceVssDealerWitness* dealer_witness = nullptr,
        ReferenceVssLocalWitness* local_witness = nullptr,
        const AuthenticatedMpcExchange* authenticated_exchange = nullptr,
        const AuthenticatedMpcMessageContext* authenticated_context = nullptr) const;

    int rank_ = -1;
    int world_size_ = 0;
    int threshold_ = -1;
    MPI_Comm comm_ = MPI_COMM_WORLD;
};

} // namespace pvia
