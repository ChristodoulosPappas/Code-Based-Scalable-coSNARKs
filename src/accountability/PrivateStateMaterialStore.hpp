#pragma once

#include "PVIA.hpp"

#include <vector>

namespace pvia {

struct PrivateStateMaterial {
    AuditStateView state{};
    std::vector<F> local_share;
    // Private local layout; the residual computation pin binds these boundaries.
    std::vector<size_t> segment_lengths;
    Digest segment_layout_binding{};
    uint64_t authentication_scheme_id = 0;
    Digest authentication_binding{};
    bool has_private_share = false;
    bool has_authentication = false;
    // Once a StateId is presented with contradictory identity metadata,
    // discard it permanently; subsequent registration must use a new ID.
    bool invalidated = false;
};

class PrivateStateMaterialStore {
public:
    bool RegisterMetadata(const AuditStateView& state);
    bool BindPrivateState(
        const AuditStateView& state,
        const std::vector<F>& local_share);
    bool BindPrivateStateSegments(
        const AuditStateView& state, const std::vector<F>& local_share,
        const std::vector<size_t>& segment_lengths);
    bool BindAuthentication(
        const AuditStateView& state, uint64_t scheme_id,
        const Digest& authentication_binding);

    PrivateStateMaterial* Find(StateId id);
    const PrivateStateMaterial* Find(StateId id) const;
    bool VerifyDigest(StateId id) const;
    bool VerifySegmentLayout(StateId id) const;
    bool VerifyAuthentication(StateId id) const;

private:
    PrivateStateMaterial* Ensure(const AuditStateView& state);
    std::vector<PrivateStateMaterial> states_;
};

} // namespace pvia
