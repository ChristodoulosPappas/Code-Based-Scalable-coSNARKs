#pragma once

#include "ReferenceVssSelectiveReleaseCoordinator.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace pvia {

// Signed snapshot returned by the separately hosted replay-head anchor.
// generation is monotonic within the anchor service's persistent database.
struct ReferenceVssExternalAnchorSnapshot {
    Digest record_binding{};
    Digest native_execution_binding{};
    Digest registry_binding{};
    Digest replay_head{};
    uint64_t generation = 0;
};

// The release coordinator intentionally accepts exactly one recovery mode
// per invocation: a pending pre-CAS batch or an already committed batch.
enum class ReferenceVssExternalAnchorResumeMode : uint8_t {
    kFresh,
    kPending,
    kCommitted
};

// Client for the external anchor RPC service. Transport is expected to run
// inside an authenticated channel (the integration test uses an SSH reverse
// tunnel); every response is independently authenticated by the pinned
// Ed25519 service key, and every request carries an HMAC client credential.
class ReferenceVssExternalAnchorClient {
public:
    ReferenceVssExternalAnchorClient() = default;

    bool LoadFromEnvironment();

    bool InitializeNew(const Digest& record_binding,
                       const Digest& native_execution_binding,
                       const Digest& registry_binding,
                       const Digest& initial_replay_head) const;

    bool ReadSnapshot(ReferenceVssExternalAnchorSnapshot* snapshot) const;

    bool CompareAndSwap(
        const ReferenceVssExternalAnchorSnapshot& expected,
        const Digest& next_head,
        ReferenceVssExternalAnchorSnapshot* updated = nullptr) const;

    // The service signs an attestation binding the current remote snapshot
    // to this exact context/target/helper set/next-head request. The caller
    // must independently verify the local journal suffix before using it.
    bool AttestTransition(
        const ReferenceVssExternalAnchorSnapshot& expected,
        const AuthenticatedMpcMessageContext& context,
        int target, const std::vector<int>& helpers,
        const Digest& attested_next_head) const;

    // Installs callbacks consumed by the existing release coordinator. The
    // client object must outlive the release call and the captured callbacks.
    bool ConfigureReleasePins(
        const std::string& registry_path,
        const std::string& replay_journal_path,
        const ReferenceVssExternalAnchorSnapshot& expected_identity,
        ReferenceVssExternalAnchorResumeMode resume_mode,
        ReferenceVssSelectiveReleasePins* pins);

private:
    bool Ready() const;
    std::string host_ = "127.0.0.1";
    uint16_t port_ = 18765;
    std::array<uint8_t, 32> auth_token_{};
    std::array<uint8_t, 32> server_public_key_{};
};

class Runtime;

// Adapts the remote replay-head service to Runtime::pre_release_gate.
// Rank 0 performs one authenticated CAS per successful release decision;
// all ranks consume the same collective allow/withhold result.
class ReferenceVssExternalReleaseGate {
public:
    bool Initialize(int rank, int world_size, uint64_t session_id,
                    const Digest& registry_binding);
    bool Attach(Runtime& runtime);
    bool RunGateSelfTest(Runtime& runtime, int rank, int world_size);
    uint64_t generation() const { return snapshot_.generation; }
    bool resumed() const { return resumed_; }

private:
    bool Authorize(const char* release_name, uint32_t phase,
                   uint32_t round, const Digest& release_context);

    ReferenceVssExternalAnchorClient client_;
    ReferenceVssExternalAnchorSnapshot snapshot_{};
    Digest record_binding_{};
    Digest native_execution_binding_{};
    Digest registry_binding_{};
    Digest initial_replay_head_{};
    uint64_t session_id_ = 0;
    int rank_ = -1;
    int world_size_ = 0;
    bool initialized_ = false;
    bool resumed_ = false;
};

bool run_reference_vss_external_anchor_selftest(
    int rank, int world_size, const std::string& phase);

} // namespace pvia
