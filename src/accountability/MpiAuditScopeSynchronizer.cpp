#include "MpiAuditScopeSynchronizer.hpp"
#include "AuthenticatedMpcExchange.hpp"
#include "CollectiveResidualEngine.hpp"

#include <mpi.h>
#include <cstring>
#include <limits>
#include <utility>
#include <vector>

namespace pvia {
namespace {
constexpr u64 SCOPE_SYNC_PROTOCOL_DOMAIN = 0x505653434f504531ULL; // PVSCOPE1
constexpr u64 SCOPE_SYNC_BROADCAST_KIND = 0x53434f5045424331ULL; // SCOPEBC1
constexpr u64 SCOPE_SYNC_AGREE_KIND = 0x53434f5045414731ULL; // SCOPEAG1
constexpr u64 SCOPE_WIRE_MAGIC = 0x505653434f504557ULL; // PVSCOPEW
constexpr u64 SCOPE_WIRE_VERSION = 1ULL;
constexpr size_t MAX_SCOPE_ITEMS = 1U << 20;

void append_digest(const Digest& digest, std::vector<u64>* words) {
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

Digest read_digest(const std::vector<u64>& words, size_t offset) {
    Digest digest{};
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(digest.bytes.data() + 8 * i, &words[offset + i], 8);
    return digest;
}

std::vector<u64> encode_scope(const ObligationSet& scope) {
    if (scope.session_id == 0 || scope.checkpoint == 0 ||
        scope.checkpoint_root == Digest{} ||
        scope.obligations.size() > MAX_SCOPE_ITEMS ||
        scope.operations.size() > MAX_SCOPE_ITEMS ||
        scope.private_operations.size() > MAX_SCOPE_ITEMS ||
        scope.transfer_operations.size() > MAX_SCOPE_ITEMS)
        return {};
    std::vector<u64> words = {
        SCOPE_WIRE_MAGIC, SCOPE_WIRE_VERSION, scope.session_id,
        static_cast<u64>(scope.phase), scope.round, scope.generation,
        scope.exact_round ? 1ULL : 0ULL, scope.checkpoint,
        static_cast<u64>(scope.obligations.size()),
        static_cast<u64>(scope.operations.size()),
        static_cast<u64>(scope.private_operations.size()),
        static_cast<u64>(scope.transfer_operations.size())};
    append_digest(scope.checkpoint_root, &words);
    for (Obligation obligation : scope.obligations)
        words.push_back(static_cast<u64>(obligation));
    auto append_refs = [&](const std::vector<OperationRef>& refs) {
        for (const auto& ref : refs) {
            words.push_back(ref.owner);
            words.push_back(ref.object_id);
        }
    };
    append_refs(scope.operations);
    append_refs(scope.private_operations);
    append_refs(scope.transfer_operations);
    return words;
}

bool decode_scope(const std::vector<u64>& words, ObligationSet* scope) {
    if (!scope || words.size() < 16 || words[0] != SCOPE_WIRE_MAGIC ||
        words[1] != SCOPE_WIRE_VERSION || words[2] == 0 || words[7] == 0 ||
        words[6] > 1 || words[8] > MAX_SCOPE_ITEMS ||
        words[9] > MAX_SCOPE_ITEMS || words[10] > MAX_SCOPE_ITEMS ||
        words[11] > MAX_SCOPE_ITEMS)
        return false;
    const size_t obligations = static_cast<size_t>(words[8]);
    const size_t operations = static_cast<size_t>(words[9]);
    const size_t private_operations = static_cast<size_t>(words[10]);
    const size_t transfer_operations = static_cast<size_t>(words[11]);
    if (operations > (std::numeric_limits<size_t>::max() / 2) -
                         private_operations - transfer_operations)
        return false;
    const size_t ref_words = 2 *
        (operations + private_operations + transfer_operations);
    if (obligations > std::numeric_limits<size_t>::max() - 16 - ref_words ||
        words.size() != 16 + obligations + ref_words)
        return false;
    ObligationSet out;
    out.session_id = words[2];
    if (words[3] > static_cast<u64>(Phase::OPENING)) return false;
    out.phase = static_cast<Phase>(static_cast<uint32_t>(words[3]));
    out.round = static_cast<uint32_t>(words[4]);
    out.generation = static_cast<uint32_t>(words[5]);
    out.exact_round = words[6] != 0;
    out.checkpoint = words[7];
    out.checkpoint_root = read_digest(words, 12);
    if (out.phase == Phase::UNKNOWN || out.checkpoint_root == Digest{}) return false;
    size_t offset = 16;
    out.obligations.reserve(obligations);
    for (size_t i = 0; i < obligations; ++i) {
        const u64 raw_obligation = words[offset++];
        if (raw_obligation == 0 ||
            raw_obligation > static_cast<u64>(Obligation::OPEN))
            return false;
        out.obligations.push_back(static_cast<Obligation>(
            static_cast<uint32_t>(raw_obligation)));
    }
    auto read_refs = [&](size_t count, std::vector<OperationRef>* refs) -> bool {
        refs->reserve(count);
        for (size_t i = 0; i < count; ++i) {
            const u64 raw_owner = words[offset++];
            const u64 object_id = words[offset++];
            if (raw_owner > std::numeric_limits<uint32_t>::max() ||
                object_id == 0)
                return false;
            refs->push_back(OperationRef{
                static_cast<uint32_t>(raw_owner), object_id});
        }
        return true;
    };
    if (!read_refs(operations, &out.operations) ||
        !read_refs(private_operations, &out.private_operations) ||
        !read_refs(transfer_operations, &out.transfer_operations))
        return false;
    *scope = std::move(out);
    return true;
}
} // namespace

ObligationSet MpiAuditScopeSynchronizer::Synchronize(
    const ObligationSet& local_scope, int rank, int world_size,
    int coordinator_rank) {
    (void)world_size;
    ObligationSet scope = local_scope;

    uint64_t header[7] = {
        scope.session_id,
        static_cast<uint64_t>(scope.phase),
        static_cast<uint64_t>(scope.round),
        static_cast<uint64_t>(scope.generation),
        scope.exact_round ? 1ULL : 0ULL,
        static_cast<uint64_t>(scope.checkpoint),
        static_cast<uint64_t>(scope.obligations.size())
    };
    MPI_Bcast(header, 7, MPI_UINT64_T, coordinator_rank, MPI_COMM_WORLD);

    if (rank != coordinator_rank) {
        scope.session_id = header[0];
        scope.phase = static_cast<Phase>(static_cast<uint32_t>(header[1]));
        scope.round = static_cast<uint32_t>(header[2]);
        scope.generation = static_cast<uint32_t>(header[3]);
        scope.exact_round = header[4] != 0;
        scope.checkpoint = header[5];
        scope.obligations.resize(static_cast<size_t>(header[6]));
    }
    uint64_t checkpoint_root_words[4] = {0, 0, 0, 0};
    if (rank == coordinator_rank) {
        for (size_t i = 0; i < 4; ++i)
            std::memcpy(&checkpoint_root_words[i],
                        scope.checkpoint_root.bytes.data() + 8 * i, 8);
    }
    MPI_Bcast(checkpoint_root_words, 4, MPI_UINT64_T,
              coordinator_rank, MPI_COMM_WORLD);
    if (rank != coordinator_rank) {
        for (size_t i = 0; i < 4; ++i)
            std::memcpy(scope.checkpoint_root.bytes.data() + 8 * i,
                        &checkpoint_root_words[i], 8);
    }
    std::vector<uint32_t> obligations(scope.obligations.size());
    if (rank == coordinator_rank) {
        for (size_t i = 0; i < scope.obligations.size(); ++i)
            obligations[i] = static_cast<uint32_t>(scope.obligations[i]);
    }
    if (!obligations.empty()) {
        MPI_Bcast(obligations.data(), static_cast<int>(obligations.size()),
                  MPI_UINT32_T, coordinator_rank, MPI_COMM_WORLD);
    }
    if (rank != coordinator_rank) {
        for (size_t i = 0; i < obligations.size(); ++i)
            scope.obligations[i] = static_cast<Obligation>(obligations[i]);
    }

    uint64_t operation_count = static_cast<uint64_t>(scope.operations.size());
    MPI_Bcast(&operation_count, 1, MPI_UINT64_T,
              coordinator_rank, MPI_COMM_WORLD);
    if (rank != coordinator_rank)
        scope.operations.resize(static_cast<size_t>(operation_count));

    std::vector<uint64_t> operation_words(
        static_cast<size_t>(operation_count) * 2, 0);
    if (rank == coordinator_rank) {
        for (size_t i = 0; i < scope.operations.size(); ++i) {
            operation_words[2 * i] = scope.operations[i].owner;
            operation_words[2 * i + 1] = scope.operations[i].object_id;
        }
    }
    if (!operation_words.empty()) {
        MPI_Bcast(operation_words.data(),
                  static_cast<int>(operation_words.size()), MPI_UINT64_T,
                  coordinator_rank, MPI_COMM_WORLD);
    }
    if (rank != coordinator_rank) {
        for (size_t i = 0; i < scope.operations.size(); ++i) {
            scope.operations[i].owner =
                static_cast<uint32_t>(operation_words[2 * i]);
            scope.operations[i].object_id = operation_words[2 * i + 1];
        }
    }

    auto broadcast_refs = [&](std::vector<OperationRef>& refs) {
        uint64_t count = static_cast<uint64_t>(refs.size());
        MPI_Bcast(&count, 1, MPI_UINT64_T, coordinator_rank, MPI_COMM_WORLD);
        if (rank != coordinator_rank) refs.resize(static_cast<size_t>(count));
        std::vector<uint64_t> words(static_cast<size_t>(count) * 2, 0);
        if (rank == coordinator_rank) {
            for (size_t i = 0; i < refs.size(); ++i) {
                words[2 * i] = refs[i].owner;
                words[2 * i + 1] = refs[i].object_id;
            }
        }
        if (!words.empty())
            MPI_Bcast(words.data(), static_cast<int>(words.size()),
                      MPI_UINT64_T, coordinator_rank, MPI_COMM_WORLD);
        if (rank != coordinator_rank) {
            for (size_t i = 0; i < refs.size(); ++i) {
                refs[i].owner = static_cast<uint32_t>(words[2 * i]);
                refs[i].object_id = words[2 * i + 1];
            }
        }
    };
    broadcast_refs(scope.private_operations);
    broadcast_refs(scope.transfer_operations);
    return scope;
}

ObligationSet MpiAuditScopeSynchronizer::SynchronizeAuthenticated(
    const ObligationSet& local_scope, int rank, int world_size,
    uint64_t sync_sequence, int coordinator_rank) {
    ObligationSet unavailable;
    if (rank < 0 || world_size <= 0 || rank >= world_size ||
        coordinator_rank < 0 || coordinator_rank >= world_size ||
        sync_sequence == 0 || local_scope.session_id == 0 ||
        local_scope.checkpoint == 0 || local_scope.checkpoint_root == Digest{})
        return unavailable;

    AuthenticatedMpcExchange exchange(rank, world_size);
    if (!exchange.production_authenticated_ready()) return unavailable;

    // Every participant already constructs the complete failure scope locally.
    // The previous protocol first authenticated a coordinator broadcast of that
    // full scope and then ran a second authenticated all-gather of its digest.
    // Since acceptance required every local scope to equal the coordinator
    // scope, this is equivalent to authenticating each participant's scope
    // binding once and requiring unanimous equality.  This removes one
    // collective and also keeps all ranks in the same collective when a local
    // mismatch is present instead of allowing an early-return divergence.
    const Digest local_scope_binding =
        compute_collective_scope_binding(local_scope);
    if (local_scope_binding == Digest{}) return unavailable;

    AuthenticatedMpcMessageContext agreement_context;
    agreement_context.protocol_domain = SCOPE_SYNC_PROTOCOL_DOMAIN;
    agreement_context.sid = local_scope.session_id;
    agreement_context.checkpoint = local_scope.checkpoint;
    agreement_context.round = local_scope.round;
    agreement_context.sequence = sync_sequence;
    agreement_context.message_kind = SCOPE_SYNC_AGREE_KIND;

    std::vector<u64> local_binding_words;
    append_digest(local_scope_binding, &local_binding_words);
    std::vector<u64> gathered_bindings;
    Digest agreement_binding{};
    if (!exchange.AllGatherWords(
            agreement_context, local_binding_words,
            &gathered_bindings, &agreement_binding) ||
        gathered_bindings.size() != static_cast<size_t>(world_size) * 4 ||
        agreement_binding == Digest{})
        return unavailable;

    for (int participant = 0; participant < world_size; ++participant) {
        if (read_digest(
                gathered_bindings,
                static_cast<size_t>(participant) * 4) != local_scope_binding)
            return unavailable;
    }
    return local_scope;
}

} // namespace pvia
