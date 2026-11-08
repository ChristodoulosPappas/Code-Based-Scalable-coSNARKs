#pragma once

#include "PVIA.hpp"

#include <string>

namespace pvia {

// Canonical standalone encoding for non-debug PUBLIC_TRANSFER certificates.
// The format intentionally excludes private/predecessor/checkpoint evidence;
// all public authentication material lives inside public_proof_words.
std::vector<u64> encode_public_transfer_blame_certificate(
    const BlameCertificate& certificate);

bool decode_public_transfer_blame_certificate(
    const std::vector<u64>& words,
    BlameCertificate* certificate);

bool write_public_transfer_blame_certificate_file(
    const std::string& path, const BlameCertificate& certificate);
bool read_public_transfer_blame_certificate_file(
    const std::string& path, std::vector<u64>* encoded_certificate);
bool parse_public_transfer_registry_anchor_hex(
    const std::string& text, Digest* anchor);

} // namespace pvia
