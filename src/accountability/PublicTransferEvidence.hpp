#pragma once

#include "PublicTransferCheckEngine.hpp"

namespace pvia {

struct PublicTransferEvidence {
    bool available = false;
    bool cryptographically_authenticated = false;
    OperationRef accused{};
    Label label{};
    CheckpointId checkpoint = 0;
    RelationKind relation = RelationKind::UNKNOWN;
    Digest expected{};
    Digest actual{};
    Digest residual_commitment{};
    Digest operation_statement_binding{};
    Digest dispute_binding{};
    Digest checkpoint_root{};
    Digest scope_binding{};
    Digest batch_check_binding{};
    Digest transfer_transcript_binding{};
    Digest authentication_commitment{};
    Digest recursive_transcript_binding{};
    Digest localization_commitment{};
    PublicTransferObservation observation{};
    Digest observation_binding{};
    Digest evidence_binding{};
};
Digest compute_public_transfer_evidence_binding(
    const PublicTransferEvidence& evidence);

PublicTransferEvidence make_public_transfer_evidence(
    const Violation& violation,
    const ObligationSet& transfer_scope,
    const PublicTransferCheckResult& check,
    const CollectiveDisputeResult& dispute,
    const PublicTransferObservation& observation);

bool validate_public_transfer_evidence_claim(
    const PublicTransferEvidence& evidence);
bool validate_public_transfer_evidence_claim_with_public_key(
    const PublicTransferEvidence& evidence,
    const std::array<uint8_t, 32>& public_key);
bool validate_public_transfer_evidence(
    const Violation& violation,
    const ObligationSet& transfer_scope,
    const PublicTransferCheckResult& check,
    const CollectiveDisputeResult& dispute,
    const PublicTransferObservation& observation,
    const PublicTransferEvidence& evidence);

std::vector<u64> encode_public_transfer_evidence(
    const PublicTransferEvidence& evidence);

} // namespace pvia
