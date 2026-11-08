#pragma once

#include "RegistrationOriginEvidencePair.hpp"

#include <string>

namespace pvia {

// PUBLIC evidence only: statement + registered public keys +
// two domain-separated Ed25519 signatures per claimed signer.
// Binary v1 is test/reference-only. Never serialize private state or keys.
struct RegistrationPublicOriginBundle {
    RegistrationConsistencyStatement statement;
    std::vector<std::array<uint8_t, 32>> public_keys;
    RegistrationOriginEvidencePair signatures;
};

// Exclusive, fail-closed public artifact writer. Does not overwrite.
bool write_registration_public_origin_bundle(
    const std::string& new_file, const RegistrationPublicOriginBundle& bundle);

// Independent *public-only* verifier; the two expected hashes MUST come
// from outside the supplied bundle. Does not use MPI, keys, or witnesses.
// Strictly parse the canonical 46-word public statement from a complete
// PVPAIR01 artifact. Used to bind an issuer signature to the same public
// statement as the independently verified MPI evidence.
bool read_registration_public_origin_statement_file(
    const std::string& file,
    RegistrationConsistencyStatement* statement);

bool verify_registration_public_origin_bundle_file(
    const std::string& file,
    const Digest& independently_expected_statement_binding,
    const Digest& independently_expected_registry_commitment,
    size_t minimum_distinct_signers,
    bool require_owner_signature);

// Strict 64-lowercase-hex parser for CLI anchor inputs.
bool parse_registration_public_digest_hex(
    const std::string& hex, Digest* out);

} // namespace pvia
