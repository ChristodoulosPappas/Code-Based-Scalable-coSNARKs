#include "Ed25519PublicTransferCheckBackend.hpp"
#include "TransferAuthentication.hpp"

#include <mpi.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <limits>
#include <vector>

namespace pvia {
namespace {

constexpr u64 CHECK_DOMAIN = 0x4544323535313942ULL; // "ED25519B"
constexpr u64 AUTH_DOMAIN  = 0x4544323535415554ULL; // "ED255AUT"
constexpr u64 RECURSIVE_DOMAIN = 0x5452465245435552ULL; // "TRFRECUR"
constexpr u64 LOCALIZE_DOMAIN  = 0x5452464c4f43414cULL; // "TRFLOCAL"

struct CanonicalTransferFact {
    OperationRef ref{};
    Digest metadata_binding{};
    bool mismatch = false;
};

Digest ed25519_transfer_engine_binding(u64 domain) {
    auto& auth = Ed25519TransferAuthenticator::instance();
    const auto signature_capabilities = auth.SignatureCapabilities();
    const Digest registry = auth.RegistryCommitment();
    const Digest anchor = auth.ExternalRegistryAnchor();
    if (!auth.ready() || !auth.ExternalRegistryAnchorVerified() ||
        registry == Digest{} || anchor != registry ||
        !validate_accountability_signature_capabilities(
            signature_capabilities))
        return {};
    std::vector<u64> words = {
        domain, static_cast<u64>(auth.world_size()),
        signature_capabilities.scheme_id,
        static_cast<u64>(signature_capabilities.public_key_bytes),
        static_cast<u64>(signature_capabilities.signature_bytes)};
    for (const Digest* digest : {
             &registry, &anchor,
             &signature_capabilities.implementation_binding,
             &signature_capabilities.capability_binding}) {
        for (size_t i = 0; i < 4; ++i) {
            u64 word = 0;
            std::memcpy(&word, digest->bytes.data() + 8 * i, 8);
            words.push_back(word);
        }
    }
    return hash_words(words);
}

void append_digest_words(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

void digest_to_words(const Digest& digest, u64* out) {
    std::memcpy(out, digest.bytes.data(), digest.bytes.size());
}

Digest words_to_digest(const u64* words) {
    Digest digest;
    std::memcpy(digest.bytes.data(), words, digest.bytes.size());
    return digest;
}
bool runtime_matches(int rank, int world_size) {
    int comm_rank = -1;
    int comm_size = 0;
    MPI_Comm_rank(MPI_COMM_WORLD, &comm_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &comm_size);
    return rank == comm_rank && world_size == comm_size &&
           rank >= 0 && rank < world_size && world_size > 0;
}

bool same_ref(const OperationRef& lhs, const OperationRef& rhs) {
    return lhs.owner == rhs.owner && lhs.object_id == rhs.object_id;
}

bool local_candidate_for_ref(
    const OperationRef& ref,
    const std::vector<PublicTransferObservation>& observations,
    PublicTransferObservation* candidate,
    bool* conflict) {
    if (conflict) *conflict = false;
    bool found = false;
    PublicTransferObservation selected;
    Digest metadata_binding{};
    bool mismatch = false;
    for (const auto& observation : observations) {
        if (!same_ref(observation.ref, ref)) continue;
        if (!validate_public_transfer_observation(observation)) continue;
        const bool current_mismatch =
            observation.registered_digest != observation.payload_digest;
        if (!found) {
            found = true;
            selected = observation;
            metadata_binding = observation.metadata_binding;
            mismatch = current_mismatch;
            continue;
        }
        if (observation.metadata_binding != metadata_binding ||
            current_mismatch != mismatch) {
            if (conflict) *conflict = true;
        }
    }
    if (found && candidate) *candidate = selected;
    return found;
}
bool derive_canonical_facts(
    const ObligationSet& scope,
    const std::vector<PublicTransferObservation>& local_observations,
    int rank,
    int world_size,
    std::vector<CanonicalTransferFact>* facts) {
    if (!facts || !runtime_matches(rank, world_size) ||
        scope.operations.empty())
        return false;
    facts->clear();
    facts->reserve(scope.operations.size());

    struct LocalCandidate {
        bool found = false;
        bool conflict = false;
        bool mismatch = false;
        Digest metadata_binding{};
    };

    const size_t operation_count = scope.operations.size();
    if (operation_count >
        static_cast<size_t>(std::numeric_limits<int>::max() / 7))
        return false;

    // Map one operation reference to every matching position in the scope.
    // A scope should normally contain unique references, but retaining all
    // positions preserves the previous behavior even for a duplicated ref.
    using RefKey = std::pair<uint32_t, uint64_t>;
    std::map<RefKey, std::vector<size_t>> positions;
    for (size_t i = 0; i < operation_count; ++i) {
        const auto& ref = scope.operations[i];
        positions[{ref.owner, ref.object_id}].push_back(i);
    }

    std::vector<LocalCandidate> local(operation_count);
    // The previous implementation revalidated every local observation once
    // for every scope operation. Validate each observation exactly once, then
    // distribute its authenticated fact to matching scope positions.
    for (const auto& observation : local_observations) {
        const auto pos_it = positions.find(
            {observation.ref.owner, observation.ref.object_id});
        if (pos_it == positions.end()) continue;
        if (!validate_public_transfer_observation(observation)) continue;

        const bool mismatch =
            observation.registered_digest != observation.payload_digest;
        for (size_t index : pos_it->second) {
            LocalCandidate& candidate = local[index];
            if (!candidate.found) {
                candidate.found = true;
                candidate.mismatch = mismatch;
                candidate.metadata_binding = observation.metadata_binding;
                continue;
            }
            if (candidate.metadata_binding != observation.metadata_binding ||
                candidate.mismatch != mismatch)
                candidate.conflict = true;
        }
    }

    // Seven words per operation:
    // present | conflict | mismatch | metadata_binding[4].
    // Batch every operation into one collective instead of one Allgather per
    // operation. The canonical fact ordering remains scope.operations order.
    constexpr size_t WORDS_PER_FACT = 7;
    const size_t local_word_count = operation_count * WORDS_PER_FACT;
    std::vector<u64> send(local_word_count, 0);
    for (size_t i = 0; i < operation_count; ++i) {
        const size_t base = i * WORDS_PER_FACT;
        send[base + 0] = local[i].found ? 1ULL : 0ULL;
        send[base + 1] = local[i].conflict ? 1ULL : 0ULL;
        send[base + 2] =
            local[i].found && local[i].mismatch ? 1ULL : 0ULL;
        if (local[i].found)
            digest_to_words(local[i].metadata_binding, &send[base + 3]);
    }

    if (local_word_count >
        static_cast<size_t>(std::numeric_limits<int>::max()))
        return false;
    if (local_word_count >
        std::numeric_limits<size_t>::max() /
            static_cast<size_t>(world_size))
        return false;

    std::vector<u64> gathered(
        static_cast<size_t>(world_size) * local_word_count);
    MPI_Allgather(
        send.data(), static_cast<int>(local_word_count), MPI_UINT64_T,
        gathered.data(), static_cast<int>(local_word_count), MPI_UINT64_T,
        MPI_COMM_WORLD);

    for (size_t i = 0; i < operation_count; ++i) {
        bool found = false;
        Digest canonical_binding{};
        bool canonical_mismatch = false;
        for (int peer = 0; peer < world_size; ++peer) {
            const size_t base =
                static_cast<size_t>(peer) * local_word_count +
                i * WORDS_PER_FACT;
            const u64* row = gathered.data() + base;
            if (row[1] != 0) return false;
            if (row[0] == 0) continue;
            const Digest binding = words_to_digest(&row[3]);
            const bool mismatch = row[2] != 0;
            if (!found) {
                found = true;
                canonical_binding = binding;
                canonical_mismatch = mismatch;
                continue;
            }
            if (binding != canonical_binding ||
                mismatch != canonical_mismatch)
                return false;
        }
        if (!found || canonical_binding == Digest{}) return false;

        CanonicalTransferFact fact;
        fact.ref = scope.operations[i];
        fact.metadata_binding = canonical_binding;
        fact.mismatch = canonical_mismatch;
        facts->push_back(fact);
    }
    return true;
}

Digest compute_transcript_binding(
    const ObligationSet& scope,
    const std::vector<CanonicalTransferFact>& facts) {
    std::vector<u64> words = {CHECK_DOMAIN, scope.session_id,
        static_cast<u64>(scope.phase), scope.round, scope.checkpoint,
        static_cast<u64>(facts.size())};
    append_digest_words(compute_collective_scope_binding(scope), &words);
    for (const auto& fact : facts) {
        words.push_back(fact.ref.owner);
        words.push_back(fact.ref.object_id);
        words.push_back(fact.mismatch ? 1ULL : 0ULL);
        append_digest_words(fact.metadata_binding, &words);
    }
    return hash_words(words);
}

Digest compute_authentication_commitment(
    const ObligationSet& scope,
    const std::vector<CanonicalTransferFact>& facts,
    const Digest& transcript_binding) {
    std::vector<u64> words = {AUTH_DOMAIN, scope.session_id,
        scope.checkpoint, static_cast<u64>(facts.size())};
    append_digest_words(transcript_binding, &words);
    append_digest_words(
        Ed25519TransferAuthenticator::instance().RegistryCommitment(), &words);
    for (const auto& fact : facts)
        append_digest_words(fact.metadata_binding, &words);
    return hash_words(words);
}

const CanonicalTransferFact* first_mismatch(
    const std::vector<CanonicalTransferFact>& facts) {
    for (const auto& fact : facts)
        if (fact.mismatch) return &fact;
    return nullptr;
}
bool resolve_mismatch_observation(
    const CanonicalTransferFact& fact,
    const std::vector<PublicTransferObservation>& local_observations,
    int rank,
    int world_size,
    PublicTransferObservation* resolved) {
    PublicTransferObservation local;
    bool conflict = false;
    const bool local_present = local_candidate_for_ref(
        fact.ref, local_observations, &local, &conflict) && !conflict &&
        local.metadata_binding == fact.metadata_binding &&
        local.registered_digest != local.payload_digest;

    int local_holder = local_present ? rank : world_size;
    int source_rank = world_size;
    MPI_Allreduce(&local_holder, &source_rank, 1, MPI_INT, MPI_MIN,
                  MPI_COMM_WORLD);
    if (source_rank < 0 || source_rank >= world_size) return false;

    std::vector<u64> encoded(PUBLIC_TRANSFER_OBSERVATION_WORDS, 0);
    int local_encode_ok = 1;
    if (rank == source_rank) {
        encoded = encode_public_transfer_observation(local);
        local_encode_ok = encoded.size() == PUBLIC_TRANSFER_OBSERVATION_WORDS
            ? 1 : 0;
    }
    int encode_ok = 0;
    MPI_Allreduce(&local_encode_ok, &encode_ok, 1, MPI_INT, MPI_MIN,
                  MPI_COMM_WORLD);
    if (!encode_ok) return false;
    MPI_Bcast(encoded.data(), static_cast<int>(encoded.size()), MPI_UINT64_T,
              source_rank, MPI_COMM_WORLD);

    PublicTransferObservation observation;
    if (!decode_public_transfer_observation(encoded, &observation)) return false;
    if (observation.observer_rank != static_cast<uint32_t>(source_rank) ||
        !same_ref(observation.ref, fact.ref) ||
        observation.metadata_binding != fact.metadata_binding ||
        observation.registered_digest == observation.payload_digest)
        return false;
    if (resolved) *resolved = observation;
    return true;
}
Digest compute_recursive_binding(
    const PublicTransferCheckResult& check,
    const PublicTransferObservation& observation) {
    std::vector<u64> words = {RECURSIVE_DOMAIN};
    append_digest_words(compute_public_transfer_check_binding(check), &words);
    append_digest_words(observation.metadata_binding, &words);
    append_digest_words(
        compute_public_transfer_observation_binding(observation), &words);
    return hash_words(words);
}

Digest compute_localization_commitment(
    const PublicTransferObservation& observation,
    const Digest& residual_commitment) {
    std::vector<u64> words = {LOCALIZE_DOMAIN,
        observation.ref.owner, observation.ref.object_id,
        observation.checkpoint};
    append_digest_words(observation.metadata_binding, &words);
    append_digest_words(observation.operation_statement_binding, &words);
    append_digest_words(residual_commitment, &words);
    return hash_words(words);
}

} // namespace

Digest Ed25519PublicTransferCheckBackend::ProductionCapabilityBinding() const {
    return ed25519_transfer_engine_binding(0x5056545243484b31ULL);
}

PublicTransferCheckResult Ed25519PublicTransferCheckBackend::Check(
    const ObligationSet& scope,
    const std::vector<PublicTransferObservation>& local_observations,
    int rank,
    int world_size) const {
    PublicTransferCheckResult result;
    result.checkpoint = scope.checkpoint;
    cached_scope_binding_ = Digest{};
    cached_check_binding_ = Digest{};
    cached_refs_.clear();
    cached_metadata_bindings_.clear();
    cached_mismatches_.clear();
    if (scope.operations.empty() || scope.session_id == 0 ||
        scope.checkpoint == 0 || !runtime_matches(rank, world_size))
        return result;

    std::vector<CanonicalTransferFact> facts;
    if (!derive_canonical_facts(
            scope, local_observations, rank, world_size, &facts))
        return result;
    size_t mismatches = 0;
    for (const auto& fact : facts)
        if (fact.mismatch) ++mismatches;

    result.available = true;
    result.cryptographically_authenticated = true;
    result.ok = mismatches == 0;
    result.checked_operations = facts.size();
    result.mismatches = mismatches;
    result.scope_binding = compute_collective_scope_binding(scope);
    result.transcript_binding = compute_transcript_binding(scope, facts);
    result.authentication_commitment = compute_authentication_commitment(
        scope, facts, result.transcript_binding);

    const Digest scope_binding = compute_collective_scope_binding(scope);
    const Digest check_binding = compute_public_transfer_check_binding(result);
    if (scope_binding != Digest{} && check_binding != Digest{}) {
        cached_scope_binding_ = scope_binding;
        cached_check_binding_ = check_binding;
        cached_refs_.reserve(facts.size());
        cached_metadata_bindings_.reserve(facts.size());
        cached_mismatches_.reserve(facts.size());
        for (const auto& fact : facts) {
            cached_refs_.push_back(fact.ref);
            cached_metadata_bindings_.push_back(fact.metadata_binding);
            cached_mismatches_.push_back(fact.mismatch ? 1U : 0U);
        }
    }
    return result;
}
CollectiveDisputeResult Ed25519PublicTransferCheckBackend::Dispute(
    const ObligationSet& scope,
    const PublicTransferCheckResult& check,
    const std::vector<PublicTransferObservation>& local_observations,
    int rank,
    int world_size) const {
    CollectiveDisputeResult result;
    result.checkpoint = scope.checkpoint;
    if (!validate_public_transfer_check_result(scope, check) || check.ok ||
        !runtime_matches(rank, world_size))
        return result;

    std::vector<CanonicalTransferFact> facts;
    const Digest scope_binding = compute_collective_scope_binding(scope);
    const Digest check_binding = compute_public_transfer_check_binding(check);
    const bool cache_shape_ok =
        cached_scope_binding_ == scope_binding &&
        cached_check_binding_ == check_binding &&
        cached_refs_.size() == check.checked_operations &&
        cached_refs_.size() == cached_metadata_bindings_.size() &&
        cached_refs_.size() == cached_mismatches_.size();

    if (cache_shape_ok) {
        facts.reserve(cached_refs_.size());
        for (size_t i = 0; i < cached_refs_.size(); ++i) {
            CanonicalTransferFact fact;
            fact.ref = cached_refs_[i];
            fact.metadata_binding = cached_metadata_bindings_[i];
            fact.mismatch = cached_mismatches_[i] != 0;
            facts.push_back(fact);
        }
        // Cache use is allowed only if the cached facts still reproduce the
        // complete authenticated batch statement supplied to Dispute().
        if (compute_transcript_binding(scope, facts) !=
                check.transcript_binding ||
            compute_authentication_commitment(
                scope, facts, check.transcript_binding) !=
                check.authentication_commitment)
            facts.clear();
    }

    if (facts.empty() &&
        !derive_canonical_facts(
            scope, local_observations, rank, world_size, &facts))
        return result;

    const CanonicalTransferFact* mismatch = first_mismatch(facts);
    if (!mismatch) return result;
    if (compute_transcript_binding(scope, facts) != check.transcript_binding ||
        compute_authentication_commitment(
            scope, facts, check.transcript_binding) !=
            check.authentication_commitment)
        return result;

    PublicTransferObservation observation;
    if (!resolve_mismatch_observation(
            *mismatch, local_observations, rank, world_size, &observation))
        return result;

    result.available = true;
    result.cryptographically_authenticated = true;
    result.found = true;
    result.accused = observation.ref;
    result.checkpoint = observation.checkpoint;
    result.relation = RelationKind::MESSAGE_BINDING;
    result.kernel = AuditRelationKernel::UNKNOWN;
    result.label = observation.transfer_label;
    result.expected = observation.registered_digest;
    result.actual = observation.payload_digest;
    result.residual_commitment = compute_residual_commitment(
        result.label, result.relation, result.kernel,
        result.expected, result.actual);
    result.operation_statement_binding =
        observation.operation_statement_binding;
    result.batch_result_binding = compute_public_transfer_check_binding(check);
    result.public_evidence_binding =
        compute_public_transfer_observation_binding(observation);
    result.recursive_transcript_binding =
        compute_recursive_binding(check, observation);
    result.localization_commitment = compute_localization_commitment(
        observation, result.residual_commitment);
    return result;
}

} // namespace pvia
