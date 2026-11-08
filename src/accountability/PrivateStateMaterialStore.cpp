#include "PrivateStateMaterialStore.hpp"

#include <cstring>
#include <limits>

namespace pvia {

namespace {

constexpr u64 PRIVATE_STATE_LAYOUT_DOMAIN = 0x505653544c415931ULL; // PVSTLAY1

Digest compute_segment_layout_binding(
    const AuditStateView& state,
    const std::vector<size_t>& segment_lengths) {
    std::vector<u64> words = {
        PRIVATE_STATE_LAYOUT_DOMAIN, state.id, state.label.sid,
        static_cast<u64>(state.label.phase), state.label.round,
        state.label.owner, static_cast<u64>(state.label.obligation),
        state.label.object_id, static_cast<u64>(segment_lengths.size())};
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, state.digest.bytes.data() + 8 * i, 8);
        words.push_back(word);
    }
    for (size_t length : segment_lengths)
        words.push_back(static_cast<u64>(length));
    return hash_words(words);
}

bool valid_segment_layout(
    const std::vector<F>& local_share,
    const std::vector<size_t>& segment_lengths) {
    if (local_share.empty() || segment_lengths.empty()) return false;
    size_t total = 0;
    for (size_t length : segment_lengths) {
        if (total > std::numeric_limits<size_t>::max() - length)
            return false;
        total += length;
    }
    return total == local_share.size();
}

bool same_identity(const AuditStateView& a, const AuditStateView& b) {
    // Only cryptographic/protocol identity fields are immutable. Display
    // names and debug flags are not trusted identity.
    return a.id == b.id && a.digest == b.digest &&
        a.label.sid == b.label.sid &&
        a.label.phase == b.label.phase &&
        a.label.round == b.label.round &&
        a.label.owner == b.label.owner &&
        a.label.obligation == b.label.obligation &&
        a.label.object_id == b.label.object_id;
}
} // namespace

PrivateStateMaterial* PrivateStateMaterialStore::Ensure(
    const AuditStateView& state) {
    if (state.id == 0 || state.label.sid == 0 ||
        state.digest == Digest{}) return nullptr;
    for (auto& item : states_) {
        if (item.state.id != state.id) continue;
        if (item.invalidated) return nullptr;
        if (!same_identity(item.state, state)) {
            // Reject state identity drift, including a metadata-only rewrite
            // made after an authenticated share was already stored.
            item.invalidated = true;
            item.local_share.clear();
            item.segment_lengths.clear();
            item.segment_layout_binding = Digest{};
            item.has_private_share = false;
            item.has_authentication = false;
            item.authentication_binding = Digest{};
            item.authentication_scheme_id = 0;
            return nullptr;
        }
        return &item;
    }
    states_.push_back(PrivateStateMaterial{});
    states_.back().state = state;
    return &states_.back();
}

bool PrivateStateMaterialStore::RegisterMetadata(
    const AuditStateView& state) {
    return Ensure(state) != nullptr;
}

bool PrivateStateMaterialStore::BindPrivateState(
    const AuditStateView& state, const std::vector<F>& local_share) {
    if (local_share.empty()) return false;
    return BindPrivateStateSegments(
        state, local_share, std::vector<size_t>{local_share.size()});
}

bool PrivateStateMaterialStore::BindPrivateStateSegments(
    const AuditStateView& state, const std::vector<F>& local_share,
    const std::vector<size_t>& segment_lengths) {
    if (!valid_segment_layout(local_share, segment_lengths)) return false;
    PrivateStateMaterial* material = Ensure(state);
    if (!material) return false;
    const Digest layout_binding =
        compute_segment_layout_binding(state, segment_lengths);
    if (layout_binding == Digest{}) return false;
    if (material->has_private_share) {
        // Same flattened bytes with a different partition is a conflicting bind.
        return material->local_share == local_share &&
               material->segment_lengths == segment_lengths &&
               material->segment_layout_binding == layout_binding;
    }
    material->local_share = local_share;
    material->segment_lengths = segment_lengths;
    material->segment_layout_binding = layout_binding;
    material->has_private_share = true;
    return true;
}

bool PrivateStateMaterialStore::BindAuthentication(
    const AuditStateView& state, uint64_t scheme_id,
    const Digest& authentication_binding) {
    if (scheme_id == 0 || authentication_binding == Digest{}) return false;
    PrivateStateMaterial* material = Ensure(state);
    if (!material) return false;
    if (material->has_authentication) {
        return material->authentication_scheme_id == scheme_id &&
               material->authentication_binding == authentication_binding;
    }
    material->authentication_scheme_id = scheme_id;
    material->authentication_binding = authentication_binding;
    material->has_authentication = true;
    return true;
}
PrivateStateMaterial* PrivateStateMaterialStore::Find(StateId id) {
    for (auto& item : states_) {
        if (item.state.id == id) return item.invalidated ? nullptr : &item;
    }
    return nullptr;
}

const PrivateStateMaterial* PrivateStateMaterialStore::Find(StateId id) const {
    for (const auto& item : states_) {
        if (item.state.id == id) return item.invalidated ? nullptr : &item;
    }
    return nullptr;
}

bool PrivateStateMaterialStore::VerifyDigest(StateId id) const {
    const PrivateStateMaterial* material = Find(id);
    if (!material || !material->has_private_share ||
        !VerifySegmentLayout(id))
        return false;
    return hash_field_vector(material->local_share) == material->state.digest;
}

bool PrivateStateMaterialStore::VerifySegmentLayout(StateId id) const {
    const PrivateStateMaterial* material = Find(id);
    if (!material || !material->has_private_share ||
        !valid_segment_layout(material->local_share, material->segment_lengths))
        return false;
    return material->segment_layout_binding ==
        compute_segment_layout_binding(
            material->state, material->segment_lengths);
}

bool PrivateStateMaterialStore::VerifyAuthentication(StateId id) const {
    const PrivateStateMaterial* material = Find(id);
    return material && material->has_authentication &&
        material->authentication_scheme_id != 0 &&
        material->authentication_binding != Digest{};
}

} // namespace pvia
