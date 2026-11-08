#pragma once
#include "ReferenceVssSelectivePointEnvelope.hpp"

#include <string>

namespace pvia {

// Linux POSIX local journal: append and fsync after each accepted signed,
// commitment-verified opening. The registry binding MUST come from an
// independently verified setup/record and is never trusted from the log.
// Local append-only journal guards process restarts and concurrent workers,
// NOT external rollback of the underlying storage by a privileged actor.
class ReferenceVssSelectivePointDurableReplayGuard {
public:
    explicit ReferenceVssSelectivePointDurableReplayGuard(
        std::string path, Digest expected_registry_binding);

    // Authorized once, at a NEW session's authenticated setup, before any
    // releases. O_EXCL refuses to reset an existing checkpoint journal.
    // The application must separately protect the session's journal path.
    bool InitializeNew() const;

    // Call only after successful signed-frame + envelope + point-commitment
    // checks. Never creates a missing journal: missing/truncated state fails.
    bool Observe(const AuthenticatedMpcMessageContext& context,
                 int sender, int target) const;

    // Return the fully verified tip of the on-disk journal. Store this
    // outside the journal in a trusted execution record.
    bool ReadCurrentHead(Digest* current_head) const;

    // Compare an INDEPENDENTLY pinned tip while holding the file lock and
    // append/fsync the next event. Returns the next tip to anchor externally.
    // No implicit fallback to the legacy unpinned Observe.
    bool ObserveWithPinnedHead(
        const AuthenticatedMpcMessageContext& context,
        int sender, int target,
        const Digest& independently_expected_head,
        Digest* new_head) const;

    // Commit a complete receiver's checked helper set under one file lock
    // and one fsync. If the exact complete batch is already the journal suffix
    // after independently_expected_head, return that tip without duplicating
    // entries. This supports retry after journal fsync but before external
    // anchor CAS. Partial/corrupt suffixes and different requests fail closed.
    // The caller MUST independently anchor the returned head.
    bool ObserveBatchWithPinnedHead(
        const AuthenticatedMpcMessageContext& context,
        const std::vector<int>& authenticated_senders,
        int target,
        const Digest& independently_expected_head,
        Digest* new_head) const;

    // Read-only preflight for recovery after journal fsync but before the
    // independent anchor CAS. The exact complete batch must be the final
    // suffix after independently_expected_head; no journal mutation occurs.
    bool VerifyPendingBatchWithPinnedHead(
        const AuthenticatedMpcMessageContext& context,
        const std::vector<int>& authenticated_senders,
        int target,
        const Digest& independently_expected_head,
        Digest* pending_head) const;

    // Verify that the journal tip is already pinned at expected_current_head
    // and that its complete final batch is exactly this request. This is used
    // after restart when the external CAS succeeded but output delivery did
    // not complete. It never mutates the journal or anchor.
    bool VerifyCommittedBatchWithPinnedHead(
        const AuthenticatedMpcMessageContext& context,
        const std::vector<int>& authenticated_senders,
        int target,
        const Digest& expected_current_head) const;

private:
    bool ObserveInternal(
        const AuthenticatedMpcMessageContext& context,
        int sender, int target,
        const Digest* expected_head, Digest* new_head) const;
    std::string path_;
    Digest registry_binding_{};
};

// Crash-durable local replay-head anchor. This protects against ordinary
// process restarts and concurrent writers, but not privileged rollback or
// replacement of the storage. Production callers must still use a separately
// administered external trust store for rollback-resistant anchoring.
class ReferenceVssSelectivePointReplayHeadAnchor {
public:
    explicit ReferenceVssSelectivePointReplayHeadAnchor(
        std::string path, Digest expected_registry_binding);

    bool InitializeNew(const Digest& initial_head) const;
    bool ReadCurrentHead(Digest* current_head) const;
    bool CompareAndSwap(const Digest& expected_head,
                        const Digest& next_head) const;

private:
    std::string path_;
    Digest registry_binding_{};
};

bool run_reference_vss_replay_head_anchor_selftest();
// Two separate MPI program invocations share only these durable files.
// The prepare phase persists a journal batch and advances the local replay
// anchor, then exits without delivery. Resume starts in a fresh process.
bool run_reference_vss_cross_process_recovery_selftest(
    int rank, int world_size, const std::string& phase,
    const std::string& directory);
} // namespace pvia
