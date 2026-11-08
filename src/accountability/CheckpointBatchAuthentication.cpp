#include "CheckpointBatchAuthentication.hpp"

#include "TransferAuthentication.hpp"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <mpi.h>

namespace pvia {
namespace {

constexpr u64 BATCH_LEAF_DOMAIN =
    0x50564241544c4546ULL; // PVBATLEF
constexpr u64 BATCH_NODE_DOMAIN =
    0x50564241544e4f44ULL; // PVBATNOD
constexpr u64 BATCH_ROOT_DOMAIN =
    0x5056424154524f54ULL; // PVBATROT
constexpr u64 BATCH_SIGNATURE_DOMAIN =
    0x5056424154534947ULL; // PVBATSIG

void append_digest(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(
            &word, digest.bytes.data() + 8 * i, sizeof(word));
        words->push_back(word);
    }
}

Digest hash_node(
    const Digest& left, const Digest& right, size_t level) {
    std::vector<u64> words = {
        BATCH_NODE_DOMAIN, static_cast<u64>(level)};
    append_digest(left, &words);
    append_digest(right, &words);
    return hash_words(words);
}

Digest merkle_root(const std::vector<Digest>& leaves) {
    if (leaves.empty()) return Digest{};
    for (const Digest& leaf : leaves)
        if (leaf == Digest{}) return Digest{};

    std::vector<Digest> level = leaves;
    size_t depth = 0;
    while (level.size() > 1) {
        std::vector<Digest> next;
        next.reserve((level.size() + 1) / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            const Digest& left = level[i];
            const Digest& right =
                i + 1 < level.size() ? level[i + 1] : level[i];
            const Digest node = hash_node(left, right, depth);
            if (node == Digest{}) return Digest{};
            next.push_back(node);
        }
        level.swap(next);
        ++depth;
    }
    return level.front();
}

std::vector<u64> signed_root_message(
    uint64_t sid,
    CheckpointId checkpoint,
    uint32_t sender,
    uint64_t leaf_count,
    const Digest& root) {
    if (sid == 0 || checkpoint == 0 ||
        leaf_count == 0 || root == Digest{})
        return {};
    std::vector<u64> words = {
        BATCH_ROOT_DOMAIN,
        sid,
        checkpoint,
        static_cast<u64>(sender),
        leaf_count};
    append_digest(root, &words);
    return words;
}

} // namespace

Digest compute_checkpoint_batch_leaf(
    const CheckpointBatchLeaf& leaf) {
    if (leaf.sid == 0 || leaf.checkpoint == 0 ||
        leaf.metadata_binding == Digest{} ||
        leaf.payload_binding == Digest{})
        return Digest{};
    std::vector<u64> words = {
        BATCH_LEAF_DOMAIN,
        leaf.sid,
        leaf.checkpoint,
        static_cast<u64>(leaf.sender),
        leaf.ordinal};
    append_digest(leaf.metadata_binding, &words);
    append_digest(leaf.payload_binding, &words);
    return hash_words(words);
}

Digest compute_checkpoint_batch_root(
    const std::vector<Digest>& leaves) {
    const Digest tree_root = merkle_root(leaves);
    if (tree_root == Digest{}) return Digest{};
    std::vector<u64> words = {
        BATCH_ROOT_DOMAIN,
        static_cast<u64>(leaves.size())};
    append_digest(tree_root, &words);
    return hash_words(words);
}

bool build_checkpoint_batch_proof(
    const std::vector<Digest>& leaves,
    size_t leaf_index,
    CheckpointBatchProof* proof) {
    if (!proof || leaves.empty() || leaf_index >= leaves.size())
        return false;
    for (const Digest& leaf : leaves)
        if (leaf == Digest{}) return false;

    *proof = CheckpointBatchProof{};
    proof->leaf_index = leaf_index;
    proof->leaf_count = leaves.size();

    std::vector<Digest> level = leaves;
    size_t index = leaf_index;
    while (level.size() > 1) {
        const size_t sibling_index =
            (index % 2 == 0)
                ? std::min(index + 1, level.size() - 1)
                : index - 1;
        proof->siblings.push_back(level[sibling_index]);

        std::vector<Digest> next;
        next.reserve((level.size() + 1) / 2);
        const size_t depth = proof->siblings.size() - 1;
        for (size_t i = 0; i < level.size(); i += 2) {
            const Digest& left = level[i];
            const Digest& right =
                i + 1 < level.size() ? level[i + 1] : level[i];
            next.push_back(hash_node(left, right, depth));
        }
        index /= 2;
        level.swap(next);
    }
    return true;
}

bool verify_checkpoint_batch_proof(
    const Digest& leaf,
    const CheckpointBatchProof& proof,
    const Digest& expected_root) {
    if (leaf == Digest{} || expected_root == Digest{} ||
        proof.leaf_count == 0 ||
        proof.leaf_index >= proof.leaf_count)
        return false;

    size_t expected_levels = 0;
    for (size_t width = proof.leaf_count; width > 1;
         width = (width + 1) / 2)
        ++expected_levels;
    if (proof.siblings.size() != expected_levels)
        return false;

    Digest current = leaf;
    size_t index = proof.leaf_index;
    size_t width = proof.leaf_count;
    for (size_t level = 0; level < proof.siblings.size(); ++level) {
        const Digest& sibling = proof.siblings[level];
        if (sibling == Digest{}) return false;
        if (index % 2 == 0)
            current = hash_node(current, sibling, level);
        else
            current = hash_node(sibling, current, level);
        if (current == Digest{}) return false;
        index /= 2;
        width = (width + 1) / 2;
        (void)width;
    }

    std::vector<u64> root_words = {
        BATCH_ROOT_DOMAIN,
        static_cast<u64>(proof.leaf_count)};
    append_digest(current, &root_words);
    return hash_words(root_words) == expected_root;
}

bool sign_checkpoint_batch_root(
    uint64_t sid,
    CheckpointId checkpoint,
    uint32_t sender,
    const std::vector<Digest>& leaves,
    SignedCheckpointBatchRoot* signed_root) {
    if (!signed_root || leaves.empty())
        return false;
    auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.ready() || sender != static_cast<uint32_t>(auth.rank()))
        return false;

    SignedCheckpointBatchRoot out;
    out.sid = sid;
    out.checkpoint = checkpoint;
    out.sender = sender;
    out.leaf_count = static_cast<uint64_t>(leaves.size());
    out.root = compute_checkpoint_batch_root(leaves);
    const std::vector<u64> message = signed_root_message(
        out.sid, out.checkpoint, out.sender,
        out.leaf_count, out.root);
    if (message.empty() ||
        !auth.SignWords(
            BATCH_SIGNATURE_DOMAIN, message, &out.signature))
        return false;
    out.valid = true;
    *signed_root = out;
    return true;
}

bool verify_checkpoint_batch_root(
    const SignedCheckpointBatchRoot& signed_root) {
    if (!signed_root.valid ||
        signed_root.sid == 0 ||
        signed_root.checkpoint == 0 ||
        signed_root.leaf_count == 0 ||
        signed_root.root == Digest{})
        return false;
    auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.ready() ||
        signed_root.sender >=
            static_cast<uint32_t>(auth.world_size()))
        return false;
    const std::vector<u64> message = signed_root_message(
        signed_root.sid,
        signed_root.checkpoint,
        signed_root.sender,
        signed_root.leaf_count,
        signed_root.root);
    return !message.empty() &&
        auth.VerifyWords(
            BATCH_SIGNATURE_DOMAIN,
            message,
            signed_root.signature,
            signed_root.sender);
}

bool run_checkpoint_batch_authentication_selftest(
    int rank, int world_size) {
    auto& auth = Ed25519TransferAuthenticator::instance();
    bool local_ok =
        auth.ready() &&
        rank >= 0 &&
        world_size == auth.world_size();

    const uint64_t sid = 0x5042494153454c46ULL ^
        static_cast<uint64_t>(rank + 1);
    const CheckpointId checkpoint =
        0x4300000000000000ULL |
        static_cast<uint64_t>(rank + 1);

    std::vector<Digest> leaves;
    constexpr size_t leaf_count = 7;
    leaves.reserve(leaf_count);
    for (size_t i = 0; i < leaf_count && local_ok; ++i) {
        const Digest meta = hash_words({
            0x4d455441ULL,
            static_cast<u64>(rank),
            static_cast<u64>(i)});
        const Digest payload = hash_words({
            0x5041594c4f4144ULL,
            static_cast<u64>(rank),
            static_cast<u64>(i),
            static_cast<u64>(i * i + 17)});
        CheckpointBatchLeaf leaf;
        leaf.sid = sid;
        leaf.checkpoint = checkpoint;
        leaf.sender = static_cast<uint32_t>(rank);
        leaf.ordinal = static_cast<uint64_t>(i);
        leaf.metadata_binding = meta;
        leaf.payload_binding = payload;
        const Digest digest = compute_checkpoint_batch_leaf(leaf);
        local_ok = digest != Digest{};
        if (local_ok) leaves.push_back(digest);
    }

    const Digest root =
        local_ok ? compute_checkpoint_batch_root(leaves) : Digest{};
    local_ok = local_ok && root != Digest{};

    for (size_t i = 0; i < leaves.size() && local_ok; ++i) {
        CheckpointBatchProof proof;
        local_ok =
            build_checkpoint_batch_proof(leaves, i, &proof) &&
            verify_checkpoint_batch_proof(
                leaves[i], proof, root);
        if (!local_ok) break;

        Digest tampered_leaf = leaves[i];
        tampered_leaf.bytes[0] ^= 0x01;
        local_ok =
            !verify_checkpoint_batch_proof(
                tampered_leaf, proof, root);
        if (!local_ok) break;

        if (!proof.siblings.empty()) {
            CheckpointBatchProof tampered_proof = proof;
            tampered_proof.siblings[0].bytes[0] ^= 0x01;
            local_ok =
                !verify_checkpoint_batch_proof(
                    leaves[i], tampered_proof, root);
        }
    }

    SignedCheckpointBatchRoot signed_root;
    if (local_ok) {
        local_ok = sign_checkpoint_batch_root(
            sid, checkpoint,
            static_cast<uint32_t>(rank),
            leaves, &signed_root);
    }
    if (local_ok)
        local_ok = verify_checkpoint_batch_root(signed_root);

    if (local_ok) {
        SignedCheckpointBatchRoot wrong_checkpoint = signed_root;
        wrong_checkpoint.checkpoint ^= 1ULL;
        local_ok =
            !verify_checkpoint_batch_root(wrong_checkpoint);
    }
    if (local_ok && world_size > 1) {
        SignedCheckpointBatchRoot wrong_signer = signed_root;
        wrong_signer.sender =
            static_cast<uint32_t>((rank + 1) % world_size);
        local_ok =
            !verify_checkpoint_batch_root(wrong_signer);
    }

    int local = local_ok ? 1 : 0;
    int global = 0;
    MPI_Allreduce(
        &local, &global, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    if (rank == 0) {
        std::cout
            << "[PVIA][checkpoint-batch-auth-selftest] "
            << (global ? "PASS" : "FAIL")
            << " leaves=" << leaf_count
            << " proof_depth=3"
            << "\n";
    }
    return global == 1;
}

} // namespace pvia
