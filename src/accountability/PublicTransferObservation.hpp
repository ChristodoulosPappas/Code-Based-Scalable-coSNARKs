#pragma once

#include "PVIA.hpp"

#include <unordered_map>

namespace pvia {

constexpr size_t PUBLIC_TRANSFER_OBSERVATION_BASE_WORDS = 49;
constexpr size_t PUBLIC_TRANSFER_OBSERVATION_WORDS =
    PUBLIC_TRANSFER_OBSERVATION_BASE_WORDS + META_WORDS;

struct PublicTransferObservation {
    bool valid = false;
    OperationRef ref{};
    Label source_label{};
    Label transfer_label{};
    CheckpointId checkpoint = 0;
    uint32_t observer_rank = 0;
    Digest predecessor_root{};
    uint32_t predecessor_count = 0;
    Digest state_dependency_root{};
    uint32_t state_dependency_count = 0;
    Digest public_aux_root{};
    uint32_t public_aux_count = 0;
    Digest registered_digest{};
    Digest payload_digest{};
    Digest operation_statement_binding{};
    Digest metadata_binding{};
    std::array<u64, META_WORDS> authenticated_metadata{};
    bool remote_observation = false;
};

std::vector<u64> encode_public_transfer_observation(
    const PublicTransferObservation& observation);
bool decode_public_transfer_observation(
    const std::vector<u64>& words,
    PublicTransferObservation* observation);
bool decode_public_transfer_observation_unchecked(
    const std::vector<u64>& words,
    PublicTransferObservation* observation);
bool validate_public_transfer_observation_with_public_key(
    const PublicTransferObservation& observation,
    const std::array<uint8_t, 32>& public_key);
Digest compute_public_transfer_observation_binding(
    const PublicTransferObservation& observation);
bool validate_public_transfer_observation(
    const PublicTransferObservation& observation);

class PublicTransferObservationStore {
public:
    void Put(const PublicTransferObservation& observation);
    bool Has(const OperationRef& ref) const;
    std::vector<PublicTransferObservation> Select(
        const ObligationSet& scope) const;
    size_t size() const { return observations_.size(); }

private:
    std::vector<PublicTransferObservation> observations_;
    std::unordered_map<CheckpointId, std::vector<size_t>>
        checkpoint_index_;
    std::unordered_map<OperationRef, std::vector<size_t>, OperationRefHash>
        ref_index_;
};

} // namespace pvia
