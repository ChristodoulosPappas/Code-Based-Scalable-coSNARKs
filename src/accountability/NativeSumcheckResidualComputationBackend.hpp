#pragma once

#include "KernelResidualEvaluator.hpp"
#include "PrivateResidualShareStore.hpp"
#include "Sp1SumcheckProofProvider.hpp"

namespace pvia {

// Recomputes the five native coSumcheck/distributed-Sumcheck polynomial
// families from the exact private source segments captured by Runtime.
// The output is a local coefficient vector; it is not a proof or an
// authenticated MPC share.
bool recompute_native_sumcheck_polynomial(
    const KernelResidualContext& context,
    std::vector<F>* coefficients);

// Development/reference residual backend. It stores the coefficient-wise
// difference between the registered output and the polynomial recomputed from
// private source segments. Authentication remains a separate boundary.
class NativeSumcheckResidualComputationBackend final
    : public KernelResidualBackend {
public:
    explicit NativeSumcheckResidualComputationBackend(
        PrivateResidualShareStore& store,
        const PrivateResidualShareAuthenticator* authenticator = nullptr,
        const Sp1SumcheckProofProvider* sp1_proof_provider = nullptr)
        : store_(store), authenticator_(authenticator),
          sp1_proof_provider_(sp1_proof_provider) {}

    PrivateResidualHandle EvaluateKernel(
        const KernelResidualContext& context) const override;

private:
    PrivateResidualShareStore& store_;
    const PrivateResidualShareAuthenticator* authenticator_ = nullptr;
    const Sp1SumcheckProofProvider* sp1_proof_provider_ = nullptr;
};

// Kernel evaluator adapter for installation in a RelationAware provider.
class NativeSumcheckKernelResidualEvaluator final
    : public KernelResidualEvaluator {
public:
    explicit NativeSumcheckKernelResidualEvaluator(
        const NativeSumcheckResidualComputationBackend& backend)
        : backend_(backend) {}

    bool Supports(AuditRelationKernel kernel) const override;
    PrivateResidualHandle Evaluate(
        const KernelResidualContext& context) const override;

private:
    const NativeSumcheckResidualComputationBackend& backend_;
};

} // namespace pvia
