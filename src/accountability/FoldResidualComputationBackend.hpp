#pragma once

#include "KernelResidualEvaluator.hpp"
#include "PrivateResidualShareStore.hpp"

namespace pvia {

// Deterministically recomputes FOLD_RS from the bound private input state and
// public fold challenge, then stores the residual vector in backend-owned
// memory. Without a cryptographic share authenticator the returned handle is
// intentionally unauthenticated, so the secure provider continues to fail closed.
class FoldResidualComputationBackend final : public KernelResidualBackend {
public:
    explicit FoldResidualComputationBackend(
        PrivateResidualShareStore& store,
        const PrivateResidualShareAuthenticator* authenticator = nullptr)
        : store_(store), authenticator_(authenticator) {}

    PrivateResidualHandle EvaluateKernel(
        const KernelResidualContext& context) const override;

    // Apply an externally issued provenance receipt to an already computed
    // residual. The share is replaced only after full receipt verification.
    bool AuthenticateStoredShare(
        const OperationRef& ref,
        const PrivateResidualShareAuthenticator& authenticator);

private:
    PrivateResidualShareStore& store_;
    const PrivateResidualShareAuthenticator* authenticator_ = nullptr;
};

bool recompute_fold_rs_output(
    const std::vector<F>& input,
    const F& challenge,
    std::vector<F>* output);

} // namespace pvia
