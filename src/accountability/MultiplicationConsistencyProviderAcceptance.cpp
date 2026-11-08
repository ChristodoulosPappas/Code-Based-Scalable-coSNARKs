#include "MultiplicationConsistencyProviderAcceptance.hpp"
#include "AuthenticatedMpcExchange.hpp"

#include "ReferenceBivariateVss.hpp"
#include "ReferenceShamirMpc.hpp"

#include <cstring>
#include <vector>

namespace pvia {
namespace {

constexpr u64 ACCEPTANCE_DOMAIN = 0x50564d4341434350ULL; // PVM CACCP
constexpr u64 CONTEXT_DOMAIN = 0x50564d4343545854ULL; // PVMCCTXT
constexpr u64 ZERO_CONTEXT_DOMAIN = 0x50564d435a45524fULL; // PVMCZERO

void append_digest_words(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

Digest context_binding(
    u64 domain, uint64_t sid, CheckpointId checkpoint,
    uint64_t multiplication_id,
    const Digest& lhs = Digest{}, const Digest& rhs = Digest{}) {
    std::vector<u64> words = {
        domain, sid, checkpoint, multiplication_id};
    if (lhs != Digest{}) append_digest_words(lhs, &words);
    if (rhs != Digest{}) append_digest_words(rhs, &words);
    return hash_words(words);
}

bool all_ranks_true(bool local, MPI_Comm comm) {
    int value = local ? 1 : 0;
    int agreed = 0;
    MPI_Allreduce(&value, &agreed, 1, MPI_INT, MPI_MIN, comm);
    return agreed == 1;
}

} // namespace

bool run_multiplication_consistency_provider_acceptance(
    int rank, int world_size,
    const MultiplicationConsistencyProofBackend& backend,
    MultiplicationConsistencyProviderAcceptanceResult* result,
    MPI_Comm comm) {
    if (!result) return false;
    *result = MultiplicationConsistencyProviderAcceptanceResult{};

    int actual_rank = -1;
    int actual_world = 0;
    MPI_Comm_rank(comm, &actual_rank);
    MPI_Comm_size(comm, &actual_world);
    if (rank != actual_rank || world_size != actual_world ||
        rank < 0 || rank >= world_size || world_size < 4)
        return false;

    const auto capabilities = backend.Capabilities();
    if (!production_ready_multiplication_consistency_capabilities(
            capabilities))
        return false;
    result->capabilities_ready = true;
    result->completed_stage = 1;
    result->capability_binding = capabilities.capability_binding;

    const int threshold = (world_size - 1) / 3;
    constexpr uint64_t sid = 0x50564d4341430001ULL;
    constexpr CheckpointId checkpoint = 0x50564d4341430002ULL;
    ReferenceBivariateVss vss(rank, world_size, threshold, comm);
    AuthenticatedMpcExchange authenticated_exchange(rank, world_size, comm);
    ReferenceShamirMpc mpc(
        rank, world_size, threshold, comm, &backend);
    if (!vss.valid() || !mpc.valid() ||
        !mpc.multiplication_consistency_available())
        return false;

    const bool local_transport_ready =
        authenticated_exchange.production_authenticated_ready();
    const bool all_transport_ready =
        all_ranks_true(local_transport_ready, comm);
    const bool no_transport_ready =
        all_ranks_true(!local_transport_ready, comm);
    if (!all_transport_ready && !no_transport_ready)
        return false;
    if (all_transport_ready) {
        const bool local_transport_installed =
            mpc.SetAuthenticatedTransport(
                &authenticated_exchange, sid, checkpoint);
        if (!all_ranks_true(local_transport_installed, comm))
            return false;
        result->authenticated_transport_used = true;
        result->authenticated_transport_capability_binding =
            authenticated_exchange.ProductionCapabilityBinding();
        if (!all_ranks_true(
                result->authenticated_transport_capability_binding !=
                    Digest{}, comm))
            return false;
    }
    result->completed_stage = 2;

    const F lhs_secret(13, 5);
    const F rhs_secret(17, 2);
    const int lhs_dealer = 0;
    const int rhs_dealer = world_size > 1 ? 1 : 0;
    std::vector<F> lhs_plaintext;
    std::vector<F> rhs_plaintext;
    if (rank == lhs_dealer) lhs_plaintext = {lhs_secret};
    if (rank == rhs_dealer) rhs_plaintext = {rhs_secret};

    std::vector<F> lhs_shares;
    std::vector<F> rhs_shares;
    ReferenceVssReceipt lhs_receipt;
    ReferenceVssReceipt rhs_receipt;
    ReferenceVssLocalWitness lhs_local_witness;
    ReferenceVssLocalWitness rhs_local_witness;
    if (!vss.ShareVectorFromDealerWithLocalWitness(
            lhs_dealer, lhs_plaintext, &lhs_shares, &lhs_receipt,
            &lhs_local_witness) ||
        !vss.ShareVectorFromDealerWithLocalWitness(
            rhs_dealer, rhs_plaintext, &rhs_shares, &rhs_receipt,
            &rhs_local_witness) ||
        lhs_shares.size() != 1 || rhs_shares.size() != 1 ||
        lhs_receipt.transcript_binding == Digest{} ||
        rhs_receipt.transcript_binding == Digest{} ||
        !validate_reference_vss_local_witness(lhs_local_witness) ||
        !validate_reference_vss_local_witness(rhs_local_witness))
        return false;
    result->completed_stage = 3;

    ReferenceMultiplicationConsistencyContext multiply_context;
    multiply_context.sid = sid;
    multiply_context.checkpoint = checkpoint;
    multiply_context.multiplication_id = 1;
    multiply_context.lhs_sharing_binding =
        lhs_receipt.transcript_binding;
    multiply_context.rhs_sharing_binding =
        rhs_receipt.transcript_binding;
    multiply_context.context_binding = context_binding(
        CONTEXT_DOMAIN, sid, checkpoint,
        multiply_context.multiplication_id,
        multiply_context.lhs_sharing_binding,
        multiply_context.rhs_sharing_binding);
    if (multiply_context.context_binding == Digest{})
        return false;

    ReferenceMultiplicationConsistencyLocalWitness local_witness;
    local_witness.lhs_sharing_witness_words =
        encode_reference_vss_local_witness(lhs_local_witness);
    local_witness.rhs_sharing_witness_words =
        encode_reference_vss_local_witness(rhs_local_witness);
    if (local_witness.lhs_sharing_witness_words.empty() ||
        local_witness.rhs_sharing_witness_words.empty())
        return false;

    F product_share(0);
    Digest multiplication_binding{};
    if (!mpc.MultiplyWithConsistency(
            lhs_shares.front(), rhs_shares.front(),
            multiply_context, local_witness,
            &product_share, &multiplication_binding) ||
        multiplication_binding == Digest{})
        return false;
    result->completed_stage = 4;
    F opened_product(0);
    Digest product_opening_binding{};
    if (!mpc.Open(
            product_share, &opened_product,
            &product_opening_binding) ||
        product_opening_binding == Digest{})
        return false;
    result->completed_stage = 5;
    result->multiplication_verified =
        opened_product == lhs_secret * rhs_secret;
    result->multiplication_binding = multiplication_binding;
    if (!all_ranks_true(result->multiplication_verified, comm))
        return false;
    result->completed_stage = 6;

    F zero_share(0);
    ReferenceLinearSharingProvenance zero_provenance;
    Digest zero_sharing_binding{};
    if (!mpc.ShareLocalSumWithProvenance(
            F(0), &zero_share, &zero_provenance,
            &zero_sharing_binding) ||
        zero_sharing_binding == Digest{})
        return false;
    result->completed_stage = 7;
    ReferenceMaskedZeroConsistencyContext zero_context;
    zero_context.sid = sid;
    zero_context.checkpoint = checkpoint;
    zero_context.multiplication_id = 2;
    zero_context.context_binding = context_binding(
        ZERO_CONTEXT_DOMAIN, sid, checkpoint,
        zero_context.multiplication_id,
        zero_provenance.binding);
    bool zero_result = false;
    Digest zero_opening_binding{};
    Digest zero_consistency_binding{};
    if (zero_context.context_binding == Digest{} ||
        !mpc.MaskedZeroTestWithConsistency(
            zero_provenance, zero_context,
            &zero_result, &zero_opening_binding,
            &zero_consistency_binding) ||
        zero_opening_binding == Digest{} ||
        zero_consistency_binding == Digest{})
        return false;
    result->zero_case_verified = zero_result;
    result->zero_case_binding = zero_consistency_binding;
    if (!all_ranks_true(result->zero_case_verified, comm))
        return false;
    result->completed_stage = 8;

    const F local_nonzero = rank == 0 ? F(1) : F(0);
    F nonzero_share(0);
    ReferenceLinearSharingProvenance nonzero_provenance;
    Digest nonzero_sharing_binding{};
    if (!mpc.ShareLocalSumWithProvenance(
            local_nonzero, &nonzero_share,
            &nonzero_provenance, &nonzero_sharing_binding) ||
        nonzero_sharing_binding == Digest{})
        return false;
    result->completed_stage = 9;
    ReferenceMaskedZeroConsistencyContext nonzero_context;
    nonzero_context.sid = sid;
    nonzero_context.checkpoint = checkpoint;
    nonzero_context.multiplication_id = 3;
    nonzero_context.context_binding = context_binding(
        ZERO_CONTEXT_DOMAIN, sid, checkpoint,
        nonzero_context.multiplication_id,
        nonzero_provenance.binding);
    bool nonzero_result = true;
    Digest nonzero_opening_binding{};
    Digest nonzero_consistency_binding{};
    if (nonzero_context.context_binding == Digest{} ||
        !mpc.MaskedZeroTestWithConsistency(
            nonzero_provenance, nonzero_context,
            &nonzero_result, &nonzero_opening_binding,
            &nonzero_consistency_binding) ||
        nonzero_opening_binding == Digest{} ||
        nonzero_consistency_binding == Digest{})
        return false;
    result->nonzero_case_verified = !nonzero_result;
    result->nonzero_case_binding = nonzero_consistency_binding;
    if (!all_ranks_true(result->nonzero_case_verified, comm))
        return false;
    result->completed_stage = 10;

    std::vector<u64> acceptance_words = {
        ACCEPTANCE_DOMAIN,
        static_cast<u64>(world_size),
        static_cast<u64>(threshold),
        sid,
        checkpoint};
    append_digest_words(result->capability_binding, &acceptance_words);
    acceptance_words.push_back(
        result->authenticated_transport_used ? 1ULL : 0ULL);
    if (result->authenticated_transport_used)
        append_digest_words(
            result->authenticated_transport_capability_binding,
            &acceptance_words);
    append_digest_words(result->multiplication_binding, &acceptance_words);
    append_digest_words(result->zero_case_binding, &acceptance_words);
    append_digest_words(result->nonzero_case_binding, &acceptance_words);
    result->acceptance_binding = hash_words(acceptance_words);
    result->completed_stage = 11;
    result->available =
        result->acceptance_binding != Digest{} &&
        result->capabilities_ready &&
        result->multiplication_verified &&
        result->zero_case_verified &&
        result->nonzero_case_verified;
    return all_ranks_true(result->available, comm);
}

} // namespace pvia
