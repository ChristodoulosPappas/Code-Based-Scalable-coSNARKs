#pragma once

#include "RegistrationConsistencyProof.hpp"
#include "ResidualNativeSourcePinReceipt.hpp"

#include <cstdint>
#include <string>
#include <utility>

namespace pvia {

struct LiveNativeSourceBatchPinReceipt;

// POSIX fail-closed, local-disk SINGLE-USE claim ledger.
// Atomic O_EXCL prevents duplicate scopes on an owner-private directory.
// Not tamperproof against the owner, rollback, deleted files, compromised
// filesystem or different machines. Not a hardware monotonic counter.
class RegistrationReceiptReplayLedger {
public:
    explicit RegistrationReceiptReplayLedger(std::string directory)
        : directory_(std::move(directory)) {}

    // Requires a canonical finalized statement. Treat a successful commit
    // as irreversible; no rollback on subsequent proof failure.
    bool ConsumeOnce(const RegistrationConsistencyStatement& statement,
                     uint32_t signer) const;

    static std::string MarkerName(
        const RegistrationConsistencyStatement& statement, uint32_t signer);

    // Owner-local durable single-use issuer/sequence marker, reusable by
    // the reference private VSS source-pinning path. It intentionally
    // excludes session/claim from marker identity to reject the SAME
    // issuer sequence even if a different signed scope is presented.
    // Call ONLY after verifying the root and native-execution signatures.
    bool ConsumeNativeSourcePinOnce(
        const ResidualNativeSourcePinReceipt& signed_root) const;
    static std::string NativeSourceMarkerName(
        const ResidualNativeSourcePinReceipt& signed_root);

    // PVNPIN02 uses a separate marker domain but the same owner-only,
    // atomic single-use ledger semantics as the PVNPIN01 path.
    bool ConsumeNativeSourceBatchPinOnce(
        const LiveNativeSourceBatchPinReceipt& receipt) const;
    static std::string NativeBatchPinMarkerName(
        const LiveNativeSourceBatchPinReceipt& receipt);
private:
    std::string directory_;
};

// Mechanics-only probe with deterministic PUBLIC test statement. This
// does not sign or verify any receipt and must never be called production.
bool run_registration_replay_ledger_persistence_probe(
    const std::string& owner_only_dir, bool changed_public_claim = false);

} // namespace pvia
