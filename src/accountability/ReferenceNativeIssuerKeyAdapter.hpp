#pragma once
// Reference-mode native issuer adapter. Key files are provisioned by an
// independent setup step; the MPI fixture never generates/rewrites them.
#include <array>
#include <cstdint>
#include <openssl/evp.h>
#include <string>

namespace pvia {
bool LoadReferenceNativeIssuerSigningKey(
    const std::string& private_key_directory, int mpi_rank,
    EVP_PKEY** private_key,
    std::array<uint8_t,32>* expected_public_key);

// Loads only the separately provisioned public pin. No private seed is
// opened or required by a process consuming externally signed receipts.
bool LoadReferenceNativeIssuerPublicKey(
    const std::string& public_key_directory, int mpi_rank,
    std::array<uint8_t,32>* expected_public_key);

// Separate reference-fixture executor role. Its seed directory is distinct
// from the issuer signer directory; only executor public pins go to the signer.
bool LoadReferenceNativeExecutorSigningKey(
    const std::string& private_key_directory, int mpi_rank,
    EVP_PKEY** private_key,
    std::array<uint8_t,32>* expected_public_key);
}
