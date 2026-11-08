#pragma once

#include "RegistrationNativeConsumedSnapshot.hpp"
#include "PrivateResidualRegistry.hpp"
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace pvia {

// Reference-only native source request. Exports signed public digests and
// statement words from real coSNARK execution; no secret witness values.
// This is NOT a residual source-pin request and does not attest MPC residual
// authentication, full release authorization, or proof completion.
bool WriteLiveNativeSourceRequestV2(
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeConsumedSnapshot& snapshot,
    const AuditCheckpointView& checkpoint,
    const Digest& residual_computation_binding,
    const Digest& residual_commitment,
    const std::string& executor_key_directory,
    int mpi_rank,
    u64 issuer_sequence,
    const std::string& destination);

// Per-operation public bindings for the multi-operation source-pin path.
// Values are digests only; residual coordinates remain inside the local backend.
struct LiveNativeSourceOperationBinding {
    OperationRef ref{};
    Digest native_consumed_record_binding{};
    Digest registration_pre_vss_claim_binding{};
};

// Build a batch input only from a validated native statement/snapshot pair
// captured at the matching sealed checkpoint. The returned digests remain
// public bindings; the caller still verifies the corresponding issuer receipts.
bool BuildLiveNativeSourceOperationBinding(
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeConsumedSnapshot& snapshot,
    const AuditCheckpointView& checkpoint,
    LiveNativeSourceOperationBinding* output);

struct LiveNativeSourcePinBatchBinding {
    uint64_t session_id = 0;
    CheckpointId checkpoint = 0;
    uint32_t local_owner = 0;
    size_t operation_count = 0;
    Digest scope_binding{};
    Digest local_residual_root{};
    Digest operation_binding_root{};
    Digest batch_binding{};
};

// Private local receipt for the multi-operation batch binding. PVNPIN02 has a
// distinct fixed-width format so the existing PVNPIN01 wire contract is stable.
struct LiveNativeSourceBatchPinReceipt {
    u64 issuer_id = 0;
    u64 sequence = 0;
    u64 session_id = 0;
    CheckpointId checkpoint = 0;
    uint32_t owner = 0;
    u64 operation_count = 0;
    Digest scope_binding{};
    Digest local_residual_root{};
    Digest operation_binding_root{};
    Digest batch_binding{};
    std::array<uint8_t, 64> signature{};
};

std::vector<uint8_t> live_native_source_batch_pin_signing_message(
    const LiveNativeSourceBatchPinReceipt& receipt);
bool write_live_native_source_batch_pin_receipt_file(
    const std::string& path,
    const LiveNativeSourceBatchPinReceipt& receipt);
bool read_live_native_source_batch_pin_receipt_file(
    const std::string& path,
    LiveNativeSourceBatchPinReceipt* receipt);
bool verify_live_native_source_batch_pin_receipt(
    const ObligationSet& scope, uint32_t local_owner,
    const LocalResidualBatchView& local_view,
    const std::vector<LiveNativeSourceOperationBinding>& operation_bindings,
    const LiveNativeSourceBatchPinReceipt& receipt,
    const std::array<uint8_t, 32>& independently_pinned_issuer_key,
    u64 expected_issuer_id, u64 minimum_accepted_sequence);

// Derive a deterministic, owner-local aggregate binding over every operation
// in the local portion of a sealed scope. Requires an exact, authenticated
// LocalResidualBatchView and one native source/claim binding per local handle.
// This is a binding primitive, not an issuer signature or secure release gate.
bool compute_live_native_source_pin_batch_binding(
    const ObligationSet& scope, uint32_t local_owner,
    const LocalResidualBatchView& local_view,
    const std::vector<LiveNativeSourceOperationBinding>& operation_bindings,
    LiveNativeSourcePinBatchBinding* output);

// Deterministic regression for canonical ordering, completeness, and mutation
// sensitivity of the multi-operation binding primitive.
bool run_live_native_source_batch_binding_selftest();

// Public material fixture verification for actual coSNARK source records.
// The declared handles are NOT independently authenticated private shares;
// this checks C++ scope/binding/issuer signature only, not runtime authorization.
bool verify_live_native_real_batch_public_fixture(const std::string& path);

// Canonical one-operation scope used only by the live-native source-pin
// handshake. The root itself is computed only after the local residual
// provenance receipt has been accepted.
ObligationSet BuildLiveNativeSourcePinScope(
    const RegistrationConsistencyStatement& statement,
    const AuditCheckpointView& checkpoint);
ObligationSet BuildLiveNativeSourcePinScope(
    const std::vector<RegistrationConsistencyStatement>& statements,
    const AuditCheckpointView& checkpoint);

// Second-stage request: executor-signs the exact native source binding,
// canonical scope and authenticated local residual root. It carries digests
// only; an external issuer validates this request before issuing PVNPIN01.
bool WriteLiveNativeSourcePinRequestV1(
    const RegistrationConsistencyStatement& statement,
    const RegistrationNativeConsumedSnapshot& snapshot,
    const AuditCheckpointView& checkpoint,
    const Digest& local_residual_root,
    const Digest& residual_commitment,
    const std::string& executor_key_directory,
    int mpi_rank,
    u64 issuer_sequence,
    const std::string& destination);
}
