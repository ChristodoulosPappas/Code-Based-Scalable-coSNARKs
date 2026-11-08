#pragma once

#include "PVIA.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace pvia {

struct CheckpointBatchLeaf {
    uint64_t sid = 0;
    CheckpointId checkpoint = 0;
    uint32_t sender = 0;
    uint64_t ordinal = 0;
    Digest metadata_binding{};
    Digest payload_binding{};
};

struct CheckpointBatchProof {
    size_t leaf_index = 0;
    size_t leaf_count = 0;
    std::vector<Digest> siblings;
};

struct SignedCheckpointBatchRoot {
    bool valid = false;
    uint64_t sid = 0;
    CheckpointId checkpoint = 0;
    uint32_t sender = 0;
    uint64_t leaf_count = 0;
    Digest root{};
    std::array<uint8_t, 64> signature{};
};

Digest compute_checkpoint_batch_leaf(
    const CheckpointBatchLeaf& leaf);
Digest compute_checkpoint_batch_root(
    const std::vector<Digest>& leaves);
bool build_checkpoint_batch_proof(
    const std::vector<Digest>& leaves,
    size_t leaf_index,
    CheckpointBatchProof* proof);
bool verify_checkpoint_batch_proof(
    const Digest& leaf,
    const CheckpointBatchProof& proof,
    const Digest& expected_root);

bool sign_checkpoint_batch_root(
    uint64_t sid,
    CheckpointId checkpoint,
    uint32_t sender,
    const std::vector<Digest>& leaves,
    SignedCheckpointBatchRoot* signed_root);
bool verify_checkpoint_batch_root(
    const SignedCheckpointBatchRoot& signed_root);

bool run_checkpoint_batch_authentication_selftest(
    int rank, int world_size);

} // namespace pvia
