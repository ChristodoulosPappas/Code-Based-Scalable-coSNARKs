#include "ReferenceVssResidualSourceLink.hpp"

#include <limits>

namespace pvia {

bool verify_reference_vss_dealer_secret_link(
    const ReferenceVssDealerWitness& witness,
    const std::vector<F>& expected_values,
    const Digest& expected_transcript) {
    if (expected_transcript == Digest{} ||
        witness.transcript_binding != expected_transcript ||
        expected_values.empty() ||
        expected_values.size() != witness.element_count ||
        !validate_reference_vss_dealer_witness(witness))
        return false;

    const size_t dimension=static_cast<size_t>(witness.threshold)+1;
    if (!dimension ||
        dimension > std::numeric_limits<size_t>::max()/dimension ||
        expected_values.size() >
            std::numeric_limits<size_t>::max()/(2*dimension*dimension))
        return false;
    const size_t stride=2*dimension*dimension;
    if (witness.coefficient_words.size()!=expected_values.size()*stride)
        return false;

    // The dealer's constant term P(0,0) is coefficient [0][0] for every
    // vector coordinate; VSS dealer-witness validation has already checked
    // coefficient canonicality, symmetric polynomials and all row hashes.
    for (size_t k=0;k<expected_values.size();++k) {
        const size_t offset=k*stride;
        if (witness.coefficient_words[offset] != expected_values[k].real ||
            witness.coefficient_words[offset+1] != expected_values[k].img)
            return false;
    }
    return true;
}

bool verify_reference_vss_dealer_authenticated_source_link(
    const ReferenceVssDealerWitness& witness,
    const std::vector<F>& expected_values,
    const Digest& pinned_transcript,
    const Digest& pinned_capability) {
    if (pinned_capability==Digest{} ||
        !witness.transcript_context.authenticated ||
        witness.transcript_context.capability_binding!=pinned_capability ||
        witness.transcript_context.transport_bindings.empty())
        return false;
    return verify_reference_vss_dealer_secret_link(
        witness,expected_values,pinned_transcript);
}
bool verify_reference_vss_recipient_share_link(
    const ReferenceVssLocalWitness& witness,
    const std::vector<F>& expected_shares,
    const Digest& pinned_transcript) {
    if (pinned_transcript==Digest{} ||
        witness.transcript_binding!=pinned_transcript ||
        expected_shares.empty() ||
        expected_shares.size()!=witness.element_count ||
        !validate_reference_vss_local_witness(witness))
        return false;
    const size_t dimension=static_cast<size_t>(witness.threshold)+1;
    if (dimension==0 ||
        expected_shares.size() >
            std::numeric_limits<size_t>::max()/(2*dimension))
        return false;
    for (size_t k=0; k<expected_shares.size(); ++k) {
        const size_t offset=2*k*dimension;
        if (witness.local_row_words[offset]!=expected_shares[k].real ||
            witness.local_row_words[offset+1]!=expected_shares[k].img)
            return false;
    }
    return true;
}

bool verify_reference_vss_recipient_authenticated_share_link(
    const ReferenceVssLocalWitness& witness,
    const std::vector<F>& expected_shares,
    const Digest& pinned_transcript,
    const Digest& pinned_capability) {
    if (pinned_capability==Digest{} ||
        !witness.transcript_context.authenticated ||
        witness.transcript_context.capability_binding!=pinned_capability ||
        witness.transcript_context.transport_bindings.empty())
        return false;
    return verify_reference_vss_recipient_share_link(
        witness,expected_shares,pinned_transcript);
}

} // namespace pvia
