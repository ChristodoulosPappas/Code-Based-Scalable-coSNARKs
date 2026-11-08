#pragma once

#include "PVIA.hpp"

#include <utility>
#include <vector>

namespace pvia {

// Local-only cache for a concrete secure audit provider. None of these values
// are serialized by Runtime or placed in a public blame certificate.
struct PrivateOperationMaterial {
    AuditOperationView operation{};
    AuditPrivatePayloadKind field_kind =
        AuditPrivatePayloadKind::FIELD_VECTOR;

    bool has_field_input = false;
    bool has_field_output = false;
    bool has_word_input = false;
    bool has_word_output = false;
    bool finalized = false;

    std::vector<F> field_input;
    std::vector<F> field_output;
    std::vector<u64> word_input;
    std::vector<u64> word_output;
    std::vector<StateId> state_dependencies;

    std::vector<std::pair<AuditPublicAuxKind, std::vector<F>>> field_aux;
    std::vector<std::pair<AuditPublicAuxKind, std::vector<u64>>> word_aux;
    std::vector<PublicAuxEvidence> public_aux_evidence;
};

class PrivateAuditMaterialStore {
public:
    void RegisterOperation(const AuditOperationView& operation);
    void ActivateOperation(const AuditOperationView& operation);

    void BindPrivateField(
        const AuditOperationView& operation,
        AuditPrivatePayloadKind kind,
        AuditPayloadStage stage,
        const std::vector<F>& values);
    void BindPrivateWords(
        const AuditOperationView& operation,
        AuditPayloadStage stage,
        const std::vector<u64>& values);

    void BindStateDependencies(
        const AuditOperationView& operation,
        const std::vector<StateId>& state_ids);
    void BindPublicFieldAux(
        const AuditOperationView& operation,
        AuditPublicAuxKind kind,
        const std::vector<F>& values);
    void BindPublicWordAux(
        const AuditOperationView& operation,
        AuditPublicAuxKind kind,
        const std::vector<u64>& values);

    void MarkFinalized(const OperationRef& ref);
    bool VerifyPrivatePayloadDigests(const OperationRef& ref) const;
    bool VerifyPublicAuxCommitment(const OperationRef& ref) const;
    bool ReadyForResidual(const OperationRef& ref) const;

    PrivateOperationMaterial* Find(const OperationRef& ref);
    const PrivateOperationMaterial* Find(const OperationRef& ref) const;

private:
    PrivateOperationMaterial& Ensure(const AuditOperationView& operation);
    std::vector<PrivateOperationMaterial> materials_;
};

} // namespace pvia
