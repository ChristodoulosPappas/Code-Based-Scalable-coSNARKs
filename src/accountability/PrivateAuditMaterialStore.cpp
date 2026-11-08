#include "PrivateAuditMaterialStore.hpp"

#include <algorithm>

namespace pvia {
namespace {

bool same_ref(const OperationRef& lhs, const OperationRef& rhs) {
    return lhs.owner == rhs.owner && lhs.object_id == rhs.object_id;
}

void upsert_aux_evidence(std::vector<PublicAuxEvidence>& evidence,
                         AuditPublicAuxKind kind, const Digest& digest) {
    for (auto& item : evidence) {
        if (item.kind == kind) {
            item.digest = digest;
            return;
        }
    }
    evidence.push_back(PublicAuxEvidence{kind, digest});
}

} // namespace

PrivateOperationMaterial& PrivateAuditMaterialStore::Ensure(
    const AuditOperationView& operation) {
    for (auto& material : materials_) {
        if (same_ref(material.operation.ref, operation.ref)) {
            material.operation = operation;
            return material;
        }
    }
    materials_.push_back(PrivateOperationMaterial{});
    materials_.back().operation = operation;
    return materials_.back();
}
void PrivateAuditMaterialStore::RegisterOperation(
    const AuditOperationView& operation) {
    PrivateOperationMaterial& material = Ensure(operation);
    material.finalized = false;
}

void PrivateAuditMaterialStore::ActivateOperation(
    const AuditOperationView& operation) {
    PrivateOperationMaterial& material = Ensure(operation);
    material.finalized = false;
}

void PrivateAuditMaterialStore::BindPrivateField(
    const AuditOperationView& operation, AuditPrivatePayloadKind kind,
    AuditPayloadStage stage, const std::vector<F>& values) {
    PrivateOperationMaterial& material = Ensure(operation);
    material.field_kind = kind;
    material.finalized = false;
    if (stage == AuditPayloadStage::REGISTER_INPUT) {
        material.field_input = values;
        material.has_field_input = true;
    } else {
        material.field_output = values;
        material.has_field_output = true;
    }
}

void PrivateAuditMaterialStore::BindPrivateWords(
    const AuditOperationView& operation, AuditPayloadStage stage,
    const std::vector<u64>& values) {
    PrivateOperationMaterial& material = Ensure(operation);
    material.finalized = false;
    if (stage == AuditPayloadStage::REGISTER_INPUT) {
        material.word_input = values;
        material.has_word_input = true;
    } else {
        material.word_output = values;
        material.has_word_output = true;
    }
}
void PrivateAuditMaterialStore::BindStateDependencies(
    const AuditOperationView& operation,
    const std::vector<StateId>& state_ids) {
    PrivateOperationMaterial& material = Ensure(operation);
    material.state_dependencies = state_ids;
    material.finalized = false;
}

void PrivateAuditMaterialStore::BindPublicFieldAux(
    const AuditOperationView& operation, AuditPublicAuxKind kind,
    const std::vector<F>& values) {
    PrivateOperationMaterial& material = Ensure(operation);
    material.finalized = false;
    bool replaced = false;
    for (auto& item : material.field_aux) {
        if (item.first == kind) {
            item.second = values;
            replaced = true;
            break;
        }
    }
    if (!replaced) material.field_aux.emplace_back(kind, values);
    upsert_aux_evidence(material.public_aux_evidence, kind,
                        hash_field_vector(values));
}

void PrivateAuditMaterialStore::BindPublicWordAux(
    const AuditOperationView& operation, AuditPublicAuxKind kind,
    const std::vector<u64>& values) {
    PrivateOperationMaterial& material = Ensure(operation);
    material.finalized = false;
    bool replaced = false;
    for (auto& item : material.word_aux) {
        if (item.first == kind) {
            item.second = values;
            replaced = true;
            break;
        }
    }
    if (!replaced) material.word_aux.emplace_back(kind, values);
    upsert_aux_evidence(material.public_aux_evidence, kind,
                        hash_words(values));
}

void PrivateAuditMaterialStore::MarkFinalized(const OperationRef& ref) {
    if (PrivateOperationMaterial* material = Find(ref))
        material->finalized = true;
}
bool PrivateAuditMaterialStore::VerifyPrivatePayloadDigests(
    const OperationRef& ref) const {
    const PrivateOperationMaterial* material = Find(ref);
    if (!material) return false;

    if (material->has_field_input &&
        hash_field_vector(material->field_input) != material->operation.expected)
        return false;
    if (material->has_word_input &&
        hash_words(material->word_input) != material->operation.expected)
        return false;
    if (material->has_field_output &&
        hash_field_vector(material->field_output) != material->operation.actual)
        return false;
    if (material->has_word_output &&
        hash_words(material->word_output) != material->operation.actual)
        return false;
    return true;
}

bool PrivateAuditMaterialStore::VerifyPublicAuxCommitment(
    const OperationRef& ref) const {
    const PrivateOperationMaterial* material = Find(ref);
    if (!material) return false;
    if (material->operation.public_aux_count !=
        material->public_aux_evidence.size())
        return false;
    return compute_public_aux_root(material->public_aux_evidence) ==
           material->operation.public_aux_root;
}

bool PrivateAuditMaterialStore::ReadyForResidual(
    const OperationRef& ref) const {
    const PrivateOperationMaterial* material = Find(ref);
    if (!material || material->operation.observed_remote ||
        !material->operation.active)
        return false;
    const bool field_ready =
        material->has_field_input && material->has_field_output;
    const bool word_ready =
        material->has_word_input && material->has_word_output;
    if (!field_ready && !word_ready) return false;
    return VerifyPrivatePayloadDigests(ref) && VerifyPublicAuxCommitment(ref);
}
PrivateOperationMaterial* PrivateAuditMaterialStore::Find(
    const OperationRef& ref) {
    for (auto& material : materials_) {
        if (same_ref(material.operation.ref, ref)) return &material;
    }
    return nullptr;
}

const PrivateOperationMaterial* PrivateAuditMaterialStore::Find(
    const OperationRef& ref) const {
    for (const auto& material : materials_) {
        if (same_ref(material.operation.ref, ref)) return &material;
    }
    return nullptr;
}

} // namespace pvia
