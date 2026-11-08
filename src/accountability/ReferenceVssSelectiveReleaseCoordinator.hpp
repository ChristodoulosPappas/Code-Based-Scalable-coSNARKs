#pragma once
#include "ReferenceVssSelectivePointRegistryStore.hpp"
#include "ReferenceVssSelectivePointRecovery.hpp"
#include "ReferenceVssSelectivePointDurableReplay.hpp"

#include <functional>
#include <string>
#include <vector>

namespace pvia {

// P1-05 integration starter. These pins originate OUTSIDE the registry file
// and replay log. Non-target ranks do not need target-local storage paths.
struct ReferenceVssSelectiveReleasePins {
    std::string registry_path;
    std::string replay_journal_path;
    Digest independently_pinned_record{};
    Digest independently_pinned_native_execution{};
    Digest independently_pinned_registry_binding{};
    Digest independently_pinned_replay_head{};
    // Reload the latest replay head from the independent trust source on each
    // recovery attempt. Do not rely only on a value cached before a crash.
    std::function<bool(Digest*)> load_current_head;
    // Verify all four pins against an independently managed trust source
    // before any helper opening is released to the target.
    // The selftest uses an explicit test-local fixture; production must supply
    // a separately administered external anchor with rollback protection.
    std::function<bool(const Digest&, const Digest&, const Digest&,
                       const Digest&)> verify_independent_pins;
    // Optional recovery-only attestation from the independent anchor.
    // It binds this exact context, target, helper set, and live head to a
    // service-signed response. The coordinator independently verifies the
    // complete committed journal batch before releasing any opening. The
    // reference service attests the remote high-water; it is not a separate
    // policy engine for the local journal.
    std::function<bool(const AuthenticatedMpcMessageContext&, int,
                       const std::vector<int>&, const Digest&)>
        authorize_committed_resume;
    // Recovery-only attestation for a complete journal suffix that was
    // fsynced before the independent anchor CAS. The coordinator first
    // verifies that exact suffix locally; this callback then obtains a
    // service-signed binding of the request, helper set, old pinned head,
    // and pending journal head before helper openings are released.
    std::function<bool(const AuthenticatedMpcMessageContext&, int,
                       const std::vector<int>&, const Digest&,
                       const Digest&)>
        authorize_pending_resume;
    // Commit the journal's next digest to the independently managed trusted
    // execution log before any recovered share is made available.
    // The callback must implement durable compare-and-swap on old/new heads.
    // The selftest uses a local fsync/flock store; production must supply a
    // separately administered external anchor with rollback protection.
    std::function<bool(const Digest&, const Digest&)> persist_new_head;
};

// Target-local proof witness captured only after every opening has been
// authenticated against the jointly established commitment matrix, the
// degree-t interpolation succeeds, and the durable replay-head update commits.
// It contains selective point values and must remain private; callers should
// pass it directly to the SP1 prover and never include it in public receipts.
struct ReferenceVssRecoveryProofWitness {
    bool available = false;
    int target = -1;
    int world_size = 0;
    int threshold = -1;
    size_t element_count = 0;
    u64 sid = 0;
    CheckpointId checkpoint = 0;
    u64 setup_round = 0;
    u64 setup_sequence = 0;
    Digest vss_transcript{};
    Digest setup_context_binding{};
    Digest signed_commit_transport{};
    Digest signed_ack_transport{};
    Digest registry_binding{};
    std::vector<Digest> commitments;
    std::vector<ReferenceVssSelectivePoint> openings;
};

// Collective on the existing authenticated MPI communicator. Each helper
// sends ONLY its f(helper,target) values to the intended target through
// Ed25519-authenticated AllToAllWords, never its full private VSS row.
//
// On target: decode every authenticated sender slot, reload the externally
// anchored cross-checked registry, validate every point, and recover before
// changing the replay state. A new request appends all helpers as one fsynced
// journal batch and advances the independent head. After restart, both crash
// windows are recoverable: an exact batch already named by the independent
// head can be resumed without another CAS; an exact pending journal suffix
// behind the old head can be preflighted, reused without duplicate append, and
// committed by retrying the independent CAS before output delivery.
//
// A failed validation never publishes a share. Partial writes remain
// fail-closed; callers must reconcile the independent high-water anchor.
// Journal and external-anchor updates are not one atomic transaction.
bool release_reference_vss_selective_share_collective(
    const AuthenticatedMpcExchange& exchange,
    const ReferenceVssLocalWitness& local,
    int target,
    const ReferenceVssReceipt& receipt,
    const ReferenceVssTranscriptContext& trusted_transcript,
    const AuthenticatedMpcMessageContext& release_context,
    const ReferenceVssSelectiveReleasePins* target_pins,
    std::vector<F>* target_recovered,
    Digest* target_new_replay_head,
    ReferenceVssRecoveryProofWitness* target_proof_witness = nullptr);

} // namespace pvia
