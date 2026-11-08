#pragma once
#include "RegistrationConsistencyProof.hpp"
#include <string>

namespace pvia {

// TEST-ONLY owner-side offline bridge. Writes actual private reference MPI
// VSS dealer witness and native test vector as 0600 JSON. This data is
// STRICTLY PRIVATE and must NEVER be sent to a public verifier, committed,
// logged or automatically exported by production runtime.
bool write_registration_private_test_vector_once(
    const std::string& new_owner_only_path,
    const RegistrationConsistencyStatement& statement,
    const RegistrationConsistencyWitness& witness);
}
