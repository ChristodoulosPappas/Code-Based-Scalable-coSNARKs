#pragma once

#include "ReferenceBivariateVss.hpp"

namespace pvia {

// Checks that the committed dealer sharing polynomial's constant term is
// exactly the private vector that the caller expects. The expected vector
// and independently pinned transcript must originate from the private
// residual store / authenticated session policy, not from the witness.
//
// Does not authenticate transport or authorize residual-share activation.
bool verify_reference_vss_dealer_secret_link(
    const ReferenceVssDealerWitness& dealer_witness,
    const std::vector<F>& expected_private_values,
    const Digest& independently_expected_transcript);

// Stronger preflight: requires a VSS transcript that declares authenticated
// transport and is anchored to an independently supplied capability binding.
// This is only a source-to-VSS *linkage* check. It does not certify the
// transport's actual signature registry, malicious security, or provenance
// of the source values. Do not use it as a standalone authenticator.
bool verify_reference_vss_dealer_authenticated_source_link(
    const ReferenceVssDealerWitness& dealer_witness,
    const std::vector<F>& expected_private_values,
    const Digest& independently_expected_transcript,
    const Digest& independently_pinned_transport_capability);

// Verify the participant's private VSS shares against the constant
// coefficient of its already committed private polynomial row.
bool verify_reference_vss_recipient_share_link(
    const ReferenceVssLocalWitness& local_witness,
    const std::vector<F>& expected_local_shares,
    const Digest& independently_expected_transcript);
bool verify_reference_vss_recipient_authenticated_share_link(
    const ReferenceVssLocalWitness& local_witness,
    const std::vector<F>& expected_local_shares,
    const Digest& independently_expected_transcript,
    const Digest& independently_pinned_transport_capability);
}
