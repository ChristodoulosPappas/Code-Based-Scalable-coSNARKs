#include "ReleaseGateMatrixSelfTest.hpp"

#include "AuditBackend.hpp"
#include "PVIA.hpp"

#include <mpi.h>

#include <iostream>
#include <string>
#include <vector>

namespace pvia {
namespace {

class GateDecisionAuditBackend final : public AuditBackend {
public:
    void SetReject(bool reject) { reject_ = reject; }

    void Expect(Phase phase, uint32_t round, AuditRelationKernel kernel) {
        expected_phase_ = phase;
        expected_round_ = round;
        expected_kernel_ = kernel;
        activation_seen_ = false;
        batch_well_formed_ = false;
    }

    void OnActivateOperation(const AuditOperationView& operation) override {
        if (operation.label.phase == expected_phase_ &&
            operation.label.round == expected_round_ &&
            operation.kernel == expected_kernel_ &&
            operation.label.obligation == Obligation::DERIVE &&
            operation.relation == RelationKind::PRIVATE_DERIVATION) {
            activation_seen_ = true;
        }
    }

    BatchCheckResult BatchCheck(const ObligationSet& scope) const override {
        BatchCheckResult out;
        out.available = true;
        out.cryptographically_authenticated = true;
        out.ok = !reject_;
        out.checkpoint = scope.checkpoint;
        out.checked_operations = scope.operations.size();
        out.mismatches = reject_ ? 1 : 0;
        out.participant_count = 1;
        out.scope_binding = hash_words({
            scope.session_id,
            static_cast<u64>(scope.phase),
            scope.round,
            scope.checkpoint,
            static_cast<u64>(scope.operations.size()),
            reject_ ? 1ULL : 0ULL});
        out.participant_commitment_root = hash_words({
            0x4741544550415254ULL, scope.session_id, scope.checkpoint});
        out.challenge_transcript_binding = hash_words({
            0x474154454348414cULL, scope.session_id, scope.checkpoint});
        out.challenge = hash_words({
            0x4741544543484b31ULL, scope.session_id, scope.checkpoint});
        out.aggregate_residual_commitment = hash_words({
            0x4741544552455349ULL, scope.session_id, scope.checkpoint,
            reject_ ? 1ULL : 0ULL});
        batch_well_formed_ =
            activation_seen_ &&
            scope.phase == expected_phase_ &&
            scope.round == expected_round_ &&
            scope.exact_round &&
            scope.checkpoint != 0 &&
            !scope.operations.empty() &&
            out.checked_operations == scope.operations.size();
        return out;
    }

    Violation Dispute(
        const ObligationSet&, const BatchCheckResult&) const override {
        return {};
    }

    RecoverableAuditShare RecoverAudit(
        const Violation&) const override {
        return {};
    }

    BlameCertificate LiftBlame(
        const Violation&, const RecoverableAuditShare&) const override {
        return {};
    }

    bool Judge(const BlameCertificate&, uint64_t) const override {
        return false;
    }

    bool batch_well_formed() const { return batch_well_formed_; }

private:
    bool reject_ = false;
    Phase expected_phase_ = Phase::UNKNOWN;
    uint32_t expected_round_ = 0;
    AuditRelationKernel expected_kernel_ = AuditRelationKernel::UNKNOWN;
    mutable bool activation_seen_ = false;
    mutable bool batch_well_formed_ = false;
};

struct GateCase {
    const char* family;
    const char* release_name;
    Phase phase;
    uint32_t round;
    AuditRelationKernel kernel;
    bool quadratic;
};

bool register_candidate(
    Runtime& runtime, const GateCase& test, int rank) {
    const std::vector<F> values = {
        F(static_cast<u64>(rank + 1)),
        F(static_cast<u64>(test.round + 2)),
        F(static_cast<u64>(static_cast<uint32_t>(test.phase) + 3))};

    RecordId id = 0;
    if (test.quadratic) {
        const quadratic_poly poly(values[0], values[1], values[2]);
        id = runtime.register_quadratic_operation(
            test.phase, test.round, Obligation::DERIVE, poly, {});
        if (id == 0) return false;
        runtime.bind_relation_kernel(id, test.kernel);
        runtime.activate_quadratic(id, poly);
    } else {
        id = runtime.register_vector_operation(
            test.phase, test.round, Obligation::DERIVE, values, {});
        if (id == 0) return false;
        runtime.bind_relation_kernel(id, test.kernel);
        runtime.activate_vector(id, values);
    }
    runtime.consume_pending();
    return true;
}

} // namespace

bool run_release_gate_matrix_selftest(
    Runtime& runtime, int rank, int world_size) {
    if (!runtime.enabled() || world_size <= 0 ||
        rank < 0 || rank >= world_size)
        return false;

    const std::vector<GateCase> tests = {
        {"cosumcheck", "cosumcheck_quadratic_round_release",
         Phase::COSUMCHECK_QUADRATIC, 0,
         AuditRelationKernel::COSUMCHECK_QUADRATIC, true},
        {"distributed-sumcheck", "distributed_quadratic_round_release",
         Phase::DISTRIBUTED_SUMCHECK, 0,
         AuditRelationKernel::DSC_QUADRATIC, true},
        {"encoding", "encoding_stage2_codeword",
         Phase::ENCODING, 2,
         AuditRelationKernel::ENCODING_STAGE2, false},
        {"pcs-open", "pcs_open_round_release",
         Phase::PCS, 0,
         AuditRelationKernel::PCS_OPEN_ROUND, true},
        {"pcs-batch-open", "pcs_batch_open_round_release",
         Phase::PCS, 1,
         AuditRelationKernel::PCS_BATCH_OPEN_ROUND, false},
    };

    GateDecisionAuditBackend backend;
    runtime.set_audit_backend(&backend);

    bool local_ok = true;
    for (const auto& test : tests) {
        backend.Expect(test.phase, test.round, test.kernel);
        const bool registered =
            register_candidate(runtime, test, rank);

        backend.SetReject(false);
        const bool allowed = registered &&
            runtime.pre_release_gate(
                test.release_name, test.phase, test.round);
        const bool allow_scope_ok =
            backend.batch_well_formed();

        backend.SetReject(true);
        const bool rejected =
            registered &&
            !runtime.pre_release_gate(
                test.release_name, test.phase, test.round);
        const bool reject_scope_ok =
            backend.batch_well_formed();

        const bool case_ok =
            registered && allowed && allow_scope_ok &&
            rejected && reject_scope_ok;
        local_ok = local_ok && case_ok;

        if (rank == 0) {
            std::cout
                << "[PVIA][release-gate-matrix]"
                << " family=" << test.family
                << " release=" << test.release_name
                << " phase=" << static_cast<uint32_t>(test.phase)
                << " round=" << test.round
                << " kernel=" << static_cast<uint32_t>(test.kernel)
                << " positive=" << (allowed ? "ALLOW" : "FAIL")
                << " injected=" << (rejected ? "WITHHOLD" : "FAIL")
                << " exact-scope="
                << ((allow_scope_ok && reject_scope_ok) ? "BOUND" : "FAIL")
                << " result=" << (case_ok ? "PASS" : "FAIL")
                << "\n";
        }
    }

    runtime.set_audit_backend(nullptr);

    bool strict_provenance_ok = true;
    if (runtime.private_residual_provenance_required()) {
        runtime.begin_private_residual_provenance_gate(700);
        const bool missing_receipt_denied = !runtime.pre_release_gate(
            "strict_residual_provenance_missing", Phase::FOLD, 700);
        Digest statement_binding{};
        Digest computation_binding{};
        Digest check_transcript_binding{};
        statement_binding.bytes[0] = 0xA1;
        computation_binding.bytes[0] = 0xB2;
        check_transcript_binding.bytes[0] = 0xC3;
        const bool authorization_without_source_denied =
            !runtime.authorize_private_residual_provenance(
                statement_binding, computation_binding,
                check_transcript_binding, 7, 11);
        const bool source_bound =
            runtime.bind_private_residual_provenance_source(
                statement_binding, computation_binding);
        const bool duplicate_source_binding_denied =
            !runtime.bind_private_residual_provenance_source(
                statement_binding, computation_binding);
        const bool missing_transcript_denied =
            !runtime.authorize_private_residual_provenance(
                statement_binding, computation_binding, Digest{}, 7, 11);
        Digest changed_computation_binding = computation_binding;
        changed_computation_binding.bytes[0] ^= 0x01;
        const bool mismatched_binding_denied =
            !runtime.authorize_private_residual_provenance(
                statement_binding, changed_computation_binding,
                check_transcript_binding, 7, 11);
        const bool authorized = runtime.authorize_private_residual_provenance(
            statement_binding, computation_binding,
            check_transcript_binding, 7, 11);
        const bool wrong_round_denied =
            !runtime.pre_release_gate(
                "folded_codeword_commitment_preparation",
                Phase::FOLD, 701);
        const bool preparation_release_denied =
            !runtime.pre_release_gate(
                "folded_codeword_commitment_preparation",
                Phase::FOLD, 700);
        const bool authenticated_release_allowed =
            authorized && runtime.pre_release_gate(
                "folded_codeword_merkle_commitment",
                Phase::FOLD, 700);
        const bool duplicate_release_denied =
            !runtime.pre_release_gate(
                "folded_codeword_merkle_commitment",
                Phase::FOLD, 700);
        const bool unrelated_release_denied =
            !runtime.pre_release_gate(
                "unrelated_release_after_fold",
                Phase::FOLD, 700);
        const bool subsequent_phase_release_allowed =
            runtime.pre_release_gate(
                "pcs_open_round_release", Phase::PCS, 0);
        // A new FOLD starts a fresh authorization epoch; the previous
        // receipt must not authorize the next operation.
        runtime.begin_private_residual_provenance_gate(702);
        const bool next_fold_missing_receipt_denied =
            !runtime.pre_release_gate(
                "strict_residual_provenance_next_fold_missing",
                Phase::FOLD, 702);
        strict_provenance_ok = missing_receipt_denied &&
            authorization_without_source_denied && source_bound &&
            duplicate_source_binding_denied && missing_transcript_denied &&
            mismatched_binding_denied &&
            authorized && wrong_round_denied && preparation_release_denied &&
            authenticated_release_allowed && duplicate_release_denied &&
            unrelated_release_denied && subsequent_phase_release_allowed &&
            next_fold_missing_receipt_denied;
        local_ok = local_ok && strict_provenance_ok;
        if (rank == 0) {
            std::cout << "[PVIA][strict-residual-provenance-gate-selftest]"
                      << " missing-receipt=WITHHOLD"
                      << " no-source-binding=WITHHOLD"
                      << " duplicate-source-binding=WITHHOLD"
                      << " missing-transcript=WITHHOLD"
                      << " mismatched-binding=WITHHOLD"
                      << " wrong-round=WITHHOLD"
                      << " preparation-release=WITHHOLD"
                      << " authenticated=ALLOW"
                      << " duplicate-release=WITHHOLD"
                      << " unrelated-release=WITHHOLD"
                      << " next-phase-release=ALLOW"
                      << " next-fold-without-receipt=WITHHOLD"
                      << " result="
                      << (strict_provenance_ok ? "PASS" : "FAIL")
                      << "\n";
        }
    }

    int local = local_ok ? 1 : 0;
    int global = 0;
    MPI_Allreduce(
        &local, &global, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    if (rank == 0) {
        std::cout
            << "[PVIA][release-gate-matrix-summary]"
            << " cases=" << tests.size()
            << " private-localization=folding-only"
            << " other-families=release-blocking-only"
            << " strict-provenance="
            << (runtime.private_residual_provenance_required()
                    ? (strict_provenance_ok ? "PASS" : "FAIL")
                    : "not-requested")
            << " result=" << (global ? "PASS" : "FAIL")
            << "\n";
    }
    return global != 0;
}

} // namespace pvia
