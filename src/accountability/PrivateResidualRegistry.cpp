#include "PrivateResidualRegistry.hpp"

#include <algorithm>
#include <cstring>

namespace pvia {

Digest compute_private_residual_local_handle_root(
    const std::vector<PrivateResidualHandle>& handles) {
    // Registry canonicalizes before computing the root. Independent users
    // of a pinned view must use precisely the same owner/object ordering.
    for(size_t i=0;i<handles.size();++i){
        const auto& current=handles[i];
        if(!current.available || !current.authenticated ||
           current.commitment==Digest{} || current.checkpoint==0 ||
           (i>0 && (handles[i-1].ref.owner>current.ref.owner ||
                (handles[i-1].ref.owner==current.ref.owner &&
                 handles[i-1].ref.object_id>=current.ref.object_id))))
            return {};
    }
    std::vector<u64> words;
    for(const auto& handle:handles) {
        words.push_back(handle.ref.owner);
        words.push_back(handle.ref.object_id);
        words.push_back(static_cast<u64>(handle.relation));
        words.push_back(static_cast<u64>(handle.kernel));
        for(size_t i=0;i<4;++i) {
            u64 part=0;
            std::memcpy(&part,handle.commitment.bytes.data()+8*i,8);
            words.push_back(part);
        }
    }
    return hash_words(words);
}

namespace {

bool same_ref(const OperationRef& lhs, const OperationRef& rhs) {
    return lhs.owner == rhs.owner && lhs.object_id == rhs.object_id;
}

bool contains_obligation(const std::vector<Obligation>& set,
                         Obligation obligation) {
    return set.empty() ||
           std::find(set.begin(), set.end(), obligation) != set.end();
}

bool contains_operation(const std::vector<OperationRef>& set,
                        const OperationRef& ref) {
    if (set.empty()) return true;
    return std::any_of(set.begin(), set.end(), [&](const OperationRef& item) {
        return same_ref(item, ref);
    });
}

} // namespace

void PrivateResidualRegistry::Put(const PrivateResidualHandle& handle) {
    for (auto& current : handles_) {
        if (same_ref(current.ref, handle.ref)) {
            current = handle;
            return;
        }
    }
    handles_.push_back(handle);
}
const PrivateResidualHandle* PrivateResidualRegistry::Find(
    const OperationRef& ref) const {
    for (const auto& handle : handles_) {
        if (same_ref(handle.ref, ref)) return &handle;
    }
    return nullptr;
}

std::vector<PrivateResidualHandle> PrivateResidualRegistry::Select(
    const ObligationSet& scope) const {
    std::vector<PrivateResidualHandle> out;
    for (const auto& handle : handles_) {
        if (!handle.available) continue;
        if (scope.session_id != 0 && handle.label.sid != scope.session_id)
            continue;
        if (scope.checkpoint != 0 && handle.checkpoint != scope.checkpoint)
            continue;
        if (scope.phase != Phase::UNKNOWN && handle.label.phase != scope.phase)
            continue;
        if (scope.exact_round && handle.label.round != scope.round)
            continue;
        if (!contains_obligation(scope.obligations, handle.label.obligation))
            continue;
        if (!contains_operation(scope.operations, handle.ref))
            continue;
        out.push_back(handle);
    }
    return out;
}

LocalResidualBatchView PrivateResidualRegistry::BuildLocalBatchView(
    const ObligationSet& scope, uint32_t local_owner) const {
    LocalResidualBatchView view;
    view.scope = scope;
    view.local_owner = local_owner;
    for (const auto& handle : Select(scope)) {
        if (handle.ref.owner == local_owner) view.handles.push_back(handle);
    }
    std::sort(view.handles.begin(), view.handles.end(),
        [](const PrivateResidualHandle& lhs, const PrivateResidualHandle& rhs) {
            return lhs.ref.object_id < rhs.ref.object_id;
        });

    size_t expected_local = 0;
    for (const auto& ref : scope.operations)
        if (ref.owner == local_owner) ++expected_local;
    view.complete_for_owner = scope.operations.empty() ||
                              expected_local == view.handles.size();
    view.all_authenticated = view.complete_for_owner;
    for (const auto& handle : view.handles)
        view.all_authenticated = view.all_authenticated && handle.authenticated;
    view.commitment_root =
        compute_private_residual_local_handle_root(view.handles);
    view.all_authenticated = view.all_authenticated &&
        view.commitment_root != Digest{};
    return view;
}

} // namespace pvia
