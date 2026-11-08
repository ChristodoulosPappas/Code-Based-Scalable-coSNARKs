#pragma once

#include "AuthenticatedAuditRecovery.hpp"
#include "ReferenceVssSelectiveReleaseCoordinator.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace pvia {

struct Sp1VssRecoveryInputInfo {
    bool available = false;
    size_t statement_word_count = 0;
    size_t witness_word_count = 0;
    Digest statement_binding{};
    std::string path;
};

struct Sp1VssRecoveryProofReceipt {
    bool available = false;
    bool proof_verified = false;
    uint32_t proof_system_id = 0;
    Digest statement_binding{};
    Digest artifact_commitment{};
    std::vector<u64> statement_words;
    std::vector<uint8_t> artifact_bytes;
};

// Converts only the target-local, already authenticated recovery witness into
// the canonical SP1 relation ABI. The exported file is private proving input;
// it is not a portable public receipt.
class Sp1VssRecoveryProofProvider {
public:
    bool BuildRelationInput(
        const ReferenceVssRecoveryProofWitness& witness,
        const AuthenticatedRecoveryRequest& request,
        const AuthenticatedRecoveryArtifact& artifact,
        std::vector<u64>* statement_words,
        std::vector<u64>* witness_words) const;

    // output_dir must be a private directory owned by the current user
    // (mode 0700 or stricter). Files are created with O_EXCL and mode 0600.
    bool ExportRelationInput(
        const ReferenceVssRecoveryProofWitness& witness,
        const AuthenticatedRecoveryRequest& request,
        const AuthenticatedRecoveryArtifact& artifact,
        const std::string& output_dir,
        Sp1VssRecoveryInputInfo* info) const;

    // Load and structurally validate a portable artifact envelope against
    // caller-supplied statement words without performing Groth16 verification.
    bool LoadArtifact(
        const std::string& artifact_path,
        const std::vector<u64>& expected_statement_words,
        Sp1VssRecoveryProofReceipt* receipt) const;

    // Load a portable SP1 recovery artifact and independently verify Groth16.
    bool LoadAndVerifyArtifact(
        const std::string& artifact_path,
        const std::vector<u64>& expected_statement_words,
        Sp1VssRecoveryProofReceipt* receipt) const;
    bool VerifyArtifactBytes(
        const std::vector<uint8_t>& artifact_bytes,
        const std::vector<u64>& expected_statement_words,
        Sp1VssRecoveryProofReceipt* receipt = nullptr) const;
};

bool run_sp1_vss_recovery_proof_envelope_selftest();
bool run_sp1_vss_recovery_proof_envelope_selftest();
bool run_sp1_vss_recovery_proof_envelope_selftest();
bool run_sp1_vss_recovery_proof_verifier_selftest();

} // namespace pvia
