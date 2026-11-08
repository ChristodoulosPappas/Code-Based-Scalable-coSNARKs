#pragma once

#include "KernelResidualEvaluator.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pvia {

struct Sp1SumcheckProofReceipt {
    bool available = false;
    bool proof_verified = false;
    bool production_privacy_confirmed = false;
    uint32_t proof_system_id = 0;
    size_t proof_word_count = 0;
    Digest statement_binding{};
    Digest artifact_commitment{};
    AuditRelationKernel kernel = AuditRelationKernel::UNKNOWN;
    OperationRef operation_ref{};
    uint64_t checkpoint = 0;
    Digest relation_statement{};
};

// Cross-language bridge to the SP1 relation validator and an isolated
// standalone Groth16 prover process. Candidate proofs deliberately do not
// claim authenticated MPC provenance or production privacy approval.
class Sp1SumcheckProofProvider {
public:
    explicit Sp1SumcheckProofProvider(const std::string& library_path = "");
    ~Sp1SumcheckProofProvider();

    Sp1SumcheckProofProvider(const Sp1SumcheckProofProvider&) = delete;
    Sp1SumcheckProofProvider& operator=(const Sp1SumcheckProofProvider&) = delete;

    bool Available() const;
    bool Enabled(AuditRelationKernel kernel) const;
    bool ReadLatestReceipt(
        AuditRelationKernel kernel,
        Sp1SumcheckProofReceipt* receipt) const;
    bool BuildRelationInput(
        const KernelResidualContext& context,
        std::vector<uint64_t>* statement_words,
        std::vector<uint64_t>* witness_words) const;
    // Export one validated input per kernel from a live Native runtime
    // context. The binary format is consumed by prove_sumcheck_words.
    bool ExportRelationInput(const KernelResidualContext& context) const;
    bool ValidateRelationInput(
        const std::vector<uint64_t>& statement_words,
        const std::vector<uint64_t>& witness_words) const;
    bool ProveAndVerify(
        const KernelResidualContext& context,
        Sp1SumcheckProofReceipt* receipt) const;

private:
    bool EnsureLoaded() const;

    using AbiVersionFn = uint32_t (*)();
    using CapabilitiesFn = int (*)(uint64_t*, size_t*);
    using ValidateFn = int (*)(
        const uint64_t*, size_t, const uint64_t*, size_t);

    std::string library_path_;
    std::string prover_path_;
    std::string verifier_path_;
    mutable void* library_ = nullptr;
    mutable AbiVersionFn abi_version_ = nullptr;
    mutable CapabilitiesFn capabilities_ = nullptr;
    mutable ValidateFn validate_ = nullptr;
    mutable bool load_attempted_ = false;
    mutable bool capability_valid_ = false;
    mutable std::array<bool, 5> proof_attempted_{};
    mutable std::array<bool, 5> input_exported_{};
    mutable std::array<Sp1SumcheckProofReceipt, 5> receipts_{};
    mutable std::array<bool, 5> receipt_valid_{};
};

} // namespace pvia
