#pragma once

#include "PVIA.hpp"
#include "AuthenticatedMpcExchange.hpp"
#include "MultiplicationConsistencyProof.hpp"
#include "ReferenceLinearSharingProvenance.hpp"

#include <mpi.h>
#include <vector>

namespace pvia {

struct ReferenceMultiplicationConsistencyContext {
    uint64_t sid = 0;
    CheckpointId checkpoint = 0;
    uint64_t multiplication_id = 0;
    Digest lhs_sharing_binding{};
    Digest rhs_sharing_binding{};
    Digest context_binding{};
};

struct ReferenceMultiplicationConsistencyLocalWitness {
    std::vector<u64> lhs_sharing_witness_words;
    std::vector<u64> rhs_sharing_witness_words;
};

struct ReferenceMaskedZeroConsistencyContext {
    uint64_t sid = 0;
    CheckpointId checkpoint = 0;
    uint64_t multiplication_id = 0;
    Digest context_binding{};
};

// Development/reference MPC over the project's field. This is genuine
// distributed Shamir/BGW computation. The checkpoint registration layer may
// use bivariate VSS, and this primitive provides commit-reveal public coins and
// Reed--Solomon robust opening when 3t<n. Degree-reduction contributions are
// also reshared through detectable bivariate VSS in that regime. It is still
// NOT a malicious-secure ABDE/GOD backend: VSS does not prove that a dealer
// reshared its true local product, and guaranteed delivery is absent. Formal
// PRIVATE_RECOVERY therefore stays fail closed.
class ReferenceShamirMpc {
public:
    ReferenceShamirMpc(
        int rank, int world_size, int threshold,
        MPI_Comm comm = MPI_COMM_WORLD,
        const MultiplicationConsistencyProofBackend*
            multiplication_consistency_backend = nullptr);

    bool valid() const;
    int rank() const { return rank_; }
    int world_size() const { return world_size_; }
    int threshold() const { return threshold_; }
    bool robust_opening_available() const {
        return valid() && 3 * threshold_ < world_size_;
    }
    bool detectable_degree_reduction_available() const {
        return valid() && 3 * threshold_ < world_size_;
    }

    bool ShareVectorFromDealer(
        int dealer, const std::vector<F>& dealer_plaintext,
        std::vector<F>* local_shares) const;
    // Same Shamir sharing as ShareVectorFromDealer, but reuses an element
    // count that has already been authenticated by the caller's enclosing
    // protocol. This avoids a redundant shape broadcast/AllTrue round.
    // It is intentionally available only with authenticated transport.
    bool ShareVectorFromDealerKnownSize(
        int dealer, const std::vector<F>& dealer_plaintext,
        size_t authenticated_element_count,
        std::vector<F>* local_shares) const;
    // Sum of independently sampled random contributions. When 3t<n each
    // contribution is bivariate-VSS shared, preventing dealer equivocation.
    // Uniformity follows when at least one participant samples honestly.
    bool RandomSharedField(
        F* local_share, Digest* transcript_binding = nullptr) const;
    bool RandomSharedFieldWithProvenance(
        F* local_share, ReferenceLinearSharingProvenance* provenance,
        Digest* transcript_binding = nullptr) const;

    // Re-share one private local contribution from every participant and sum
    // the resulting degree-t sharings. The returned linear binding commits to
    // the same ordered VSS receipts used by the provenance-carrying variant,
    // but this passive fast path deliberately avoids materializing recipient-
    // local VSS witnesses that are needed only by strong multiplication proofs.
    bool ShareLocalSum(
        const F& local_contribution, F* local_share,
        Digest* linear_binding,
        Digest* transcript_binding = nullptr) const;

    // Provenance-preserving counterpart used by the strong consistency path.
    bool ShareLocalSumWithProvenance(
        const F& local_contribution, F* local_share,
        ReferenceLinearSharingProvenance* provenance,
        Digest* transcript_binding = nullptr) const;

    // BGW degree reduction for t < n/2. Inputs are degree-t Shamir shares;
    // the output is again a degree-t sharing of their product. When 3t<n,
    // every degree-reduction contribution is reshared through bivariate
    // VSS, making equivocation detectable. This does NOT prove that a
    // malicious dealer contributed its correct local product.
    bool Multiply(const F& lhs_share, const F& rhs_share,
                  F* product_share,
                  Digest* transcript_binding = nullptr) const;
    // Batched honest-reference BGW degree reductions. Computes one secret
    // product per lane but shares all local products in ONE authenticated
    // vector-VSS instance per layer. Public width is agreed collectively.
    // This is passive (no multiplication-consistency proof/GOD); scalar
    // Multiply and strong MultiplyWithConsistency are unchanged.
    bool MultiplyVector(const std::vector<F>& lhs_shares,
                        const std::vector<F>& rhs_shares,
                        std::vector<F>* product_shares,
                        Digest* transcript_binding = nullptr) const;

    // Strong path: in addition to VSS-backed degree reduction, require one
    // publicly verifiable proof per dealer that its reshared contribution is
    // the product of the local shares bound by lhs/rhs sharing provenance.
    bool MultiplyWithConsistency(
        const F& lhs_share, const F& rhs_share,
        const ReferenceMultiplicationConsistencyContext& context,
        F* product_share, Digest* transcript_binding = nullptr) const;
    bool MultiplyWithConsistency(
        const F& lhs_share, const F& rhs_share,
        const ReferenceMultiplicationConsistencyContext& context,
        const ReferenceMultiplicationConsistencyLocalWitness& local_witness,
        F* product_share, Digest* transcript_binding = nullptr) const;
    // Optional public evidence output for an RS-detected event followed by
    // a sender-authenticated multiplication-proof preflight refusal.
    bool MultiplyWithConsistency(
        const F& lhs_share, const F& rhs_share,
        const ReferenceMultiplicationConsistencyContext& context,
        const ReferenceMultiplicationConsistencyLocalWitness& local_witness,
        F* product_share, Digest* transcript_binding,
        std::vector<ReferenceMultiplicationFailureCertificate>*
            failure_certificates,
        std::vector<std::vector<u64>>* encoded_failure_certificates =
            nullptr) const;

    bool SetMultiplicationConsistencyProofBackend(
        const MultiplicationConsistencyProofBackend* backend);
    bool multiplication_consistency_available() const;
    Digest multiplication_consistency_capability_binding() const;
    bool SetAuthenticatedTransport(
        const AuthenticatedMpcExchange* exchange,
        uint64_t sid, CheckpointId checkpoint);
    bool authenticated_transport_available() const;
    Digest authenticated_transport_capability_binding() const;

    // Reconstruct a degree-t shared value. When 3t<n this first commit-reveals
    // every opening share and then corrects up to t Byzantine values via
    // Reed--Solomon decoding. For 2t<n but 3t>=n, an installed authenticated
    // transport still uses signed commit-reveal before passive interpolation;
    // without that transport the legacy passive MPI opening remains for
    // development compatibility. Neither passive case is advertised as robust.
    bool Open(const F& local_share, F* opened,
              Digest* transcript_binding = nullptr) const;

    // Reveals only whether secret_share is zero by opening r*secret_share for
    // a fresh secret-shared random r. False zero occurs only if r=0.
    bool MaskedZeroTest(const F& secret_share, bool* is_zero,
                        Digest* transcript_binding = nullptr) const;
    // Rejecting-path optimization: pre-generate independent random Shamir
    // masks in one authenticated vector VSS batch.  MaskedZeroTest consumes
    // these masks one-by-one; when the pool is empty it falls back to the
    // original on-demand generation path.
    bool PreparePassiveRandomMasks(size_t count) const;
    bool MaskedZeroTestWithConsistency(
        const ReferenceLinearSharingProvenance& secret_provenance,
        const ReferenceMaskedZeroConsistencyContext& context,
        bool* is_zero, Digest* transcript_binding = nullptr,
        Digest* multiplication_consistency_binding = nullptr) const;

    // Commit-reveal public coin after private inputs have already been shared.
    // The transcript binding commits to the ordered commitments and reveals.
    bool JointPublicSeed(Digest* seed,
                         Digest* transcript_binding = nullptr) const;

private:
    bool RandomSharedFieldInternal(
        F* local_share, ReferenceLinearSharingProvenance* provenance,
        Digest* transcript_binding) const;
    bool RandomField(F* value) const;
    bool RandomFieldVector(size_t count, std::vector<F>* values) const;
    bool RandomWordVector(size_t count, std::vector<u64>* words) const;
    bool CommitRevealWords(
        u64 domain, const std::vector<u64>& local_payload,
        std::vector<u64>* all_payloads, Digest* transcript_binding) const;
    bool RobustDecodeShamir(
        const std::vector<F>& shares, F* opened) const;
    // Zero-test fast path: local products of two degree-t sharings form a
    // degree-2t sharing.  Since the masked product is opened immediately,
    // reconstruct it directly instead of first degree-reducing it back to t.
    // Under 3t<n, extra revealed points are checked against the interpolated
    // degree-2t polynomial so malformed local products fail closed.
    bool OpenMaskedDegree2tProduct(
        const F& local_product, F* opened,
        Digest* transcript_binding = nullptr) const;
    F LagrangeAtZero(int point_index, int point_count) const;
    bool ShareVectorFromDealerInternal(
        int dealer, const std::vector<F>& dealer_plaintext,
        std::vector<F>* local_shares, Digest* transport_binding,
        size_t authenticated_element_count = 0) const;
    bool ShareLocalContribution(
        const F& secret, int dealer, F* local_share,
        Digest* transport_binding = nullptr) const;
    bool MultiplyInternal(
        const F& lhs_share, const F& rhs_share,
        const ReferenceMultiplicationConsistencyContext* context,
        const ReferenceMultiplicationConsistencyLocalWitness* local_witness,
        F* product_share, Digest* transcript_binding,
        std::vector<ReferenceMultiplicationFailureCertificate>*
            failure_certificates,
        std::vector<std::vector<u64>>* encoded_failure_certificates) const;
    AuthenticatedMpcMessageContext NextTransportContext(
        u64 protocol_domain, u64 message_kind, uint64_t round = 0) const;
    bool CollectiveSameWord(
        u64 local_value, u64 message_kind, uint64_t round,
        u64* agreed_value, Digest* transcript_binding = nullptr) const;
    bool CollectiveSameDigest(
        const Digest& local_digest, u64 message_kind, uint64_t round,
        Digest* transcript_binding = nullptr) const;
    bool CollectiveAllTrue(
        bool local_value, u64 message_kind, uint64_t round,
        Digest* transcript_binding = nullptr) const;

    int rank_ = -1;
    int world_size_ = 0;
    int threshold_ = -1;
    MPI_Comm comm_ = MPI_COMM_WORLD;
    const MultiplicationConsistencyProofBackend*
        multiplication_consistency_backend_ = nullptr;
    const AuthenticatedMpcExchange* authenticated_exchange_ = nullptr;
    uint64_t transport_sid_ = 0;
    CheckpointId transport_checkpoint_ = 0;
    mutable uint64_t transport_sequence_ = 1;

    // Passive localization repeatedly invokes the same public API modes under
    // one authenticated audit session.  Cache the first collective agreement
    // so later recursive subset checks do not spend a network round
    // re-confirming constants that cannot change within this session.
    mutable bool passive_random_mode_cached_ = false;
    mutable Digest passive_random_mode_binding_{};
    mutable bool passive_multiply_mode_cached_ = false;
    mutable Digest passive_multiply_mode_binding_{};

    mutable std::vector<F> passive_random_mask_pool_;
    mutable std::vector<Digest> passive_random_mask_bindings_;
    mutable size_t passive_random_mask_next_ = 0;
};

} // namespace pvia
