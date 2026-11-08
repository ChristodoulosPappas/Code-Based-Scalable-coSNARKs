#pragma once

#include "RegistrationConsistencyProof.hpp"

namespace pvia {
class PrivateStateMaterialStore;
class PrivateAuditMaterialStore;

// Local record/statement coherence check ONLY. Requires finalized operation,
// locally bound state/output, matching challenge and checkpoint metadata.
// VerifyAuthentication() checks metadata presence, NOT MAC/signature validity.
// Must be paired with an independently authenticated native execution record
// before making any production provenance or distributed-share claim.
bool verify_registration_local_native_record(
    const RegistrationConsistencyStatement& statement,
    const PrivateStateMaterialStore& states,
    const PrivateAuditMaterialStore& operations,
    const AuditCheckpointView& checkpoint);

} // namespace pvia
