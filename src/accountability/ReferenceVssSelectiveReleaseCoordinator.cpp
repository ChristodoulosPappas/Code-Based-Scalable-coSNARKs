#include "ReferenceVssSelectiveReleaseCoordinator.hpp"
#include "ReferenceVssSelectivePointEnvelope.hpp"

#include <algorithm>
#include <limits>
#include <utility>
#include <vector>

#include <mpi.h>

namespace pvia {
bool release_reference_vss_selective_share_collective(
    const AuthenticatedMpcExchange& exchange,
    const ReferenceVssLocalWitness& local,
    int target,
    const ReferenceVssReceipt& receipt,
    const ReferenceVssTranscriptContext& transcript,
    const AuthenticatedMpcMessageContext& context,
    const ReferenceVssSelectiveReleasePins* pins,
    std::vector<F>* recovered,
    Digest* next_head,
    ReferenceVssRecoveryProofWitness* proof_witness) {
    if(!recovered || !next_head)return false;
    recovered->clear();
    *next_head={};
    if (proof_witness) *proof_witness = ReferenceVssRecoveryProofWitness{};
    int rank=-1;
    int n=0;
    if(MPI_Comm_rank(MPI_COMM_WORLD,&rank)!=MPI_SUCCESS ||
       MPI_Comm_size(MPI_COMM_WORLD,&n)!=MPI_SUCCESS)return false;

    const bool common_valid =
        exchange.ready() &&
        validate_authenticated_mpc_message_context(context) &&
        context.protocol_domain==PVIA_VSS_SELECTIVE_POINT_DOMAIN &&
        context.message_kind==PVIA_VSS_SELECTIVE_POINT_KIND &&
        n>=4 && n<=1024 && target>=0 && target<n &&
        receipt.available && receipt.consistent &&
        receipt.world_size==n && receipt.element_count>0 &&
        receipt.element_count<=static_cast<size_t>(
            (std::numeric_limits<int>::max()-26)/2) &&
        receipt.transcript_binding!=Digest{} &&
        local.participant==rank &&
        local.transcript_context.world_size==n;
    const bool correct_witness = validate_reference_vss_local_witness(local) &&
        local.transcript_context.world_size==n &&
        local.transcript_binding==receipt.transcript_binding &&
        local.element_count==receipt.element_count &&
        local.local_row_commitment==receipt.local_row_commitment;
    bool local_good=common_valid && correct_witness;
    ReferenceVssPointRegistryExecutionRecord record;
    ReferenceVssSelectiveReleasePins resolved_pins;
    // Reload and validate the target's independent pins BEFORE the collective
    // readiness barrier. Helpers must not send selective openings until the
    // target has authenticated its current replay-head high-water mark.
    if (rank == target) {
        bool target_pins_valid =
            pins &&
            pins->independently_pinned_record != Digest{} &&
            pins->independently_pinned_native_execution != Digest{} &&
            pins->independently_pinned_registry_binding != Digest{} &&
            static_cast<bool>(pins->load_current_head) &&
            static_cast<bool>(pins->verify_independent_pins) &&
            static_cast<bool>(pins->persist_new_head) &&
            !(pins->authorize_committed_resume &&
              pins->authorize_pending_resume) &&
            !pins->registry_path.empty() &&
            !pins->replay_journal_path.empty();
        Digest live_replay_head{};
        if (target_pins_valid) {
            target_pins_valid =
                pins->load_current_head(&live_replay_head) &&
                live_replay_head != Digest{};
        }
        if (target_pins_valid) {
            resolved_pins = *pins;
            resolved_pins.independently_pinned_replay_head = live_replay_head;
            target_pins_valid = pins->verify_independent_pins(
                pins->independently_pinned_record,
                pins->independently_pinned_native_execution,
                pins->independently_pinned_registry_binding,
                live_replay_head);
        }
        if (target_pins_valid) {
            target_pins_valid =
                load_reference_vss_point_registry_execution_record(
                    pins->registry_path,
                    pins->independently_pinned_record,
                    pins->independently_pinned_native_execution,
                    context.sid, context.checkpoint,
                    receipt.transcript_binding, &record) &&
                record.registry.registry_binding ==
                    pins->independently_pinned_registry_binding;
        }
        if (target_pins_valid && pins->authorize_pending_resume) {
            std::vector<int> expected_helpers;
            expected_helpers.reserve(static_cast<size_t>(n - 1));
            for (int helper = 0; helper < n; ++helper)
                if (helper != target) expected_helpers.push_back(helper);
            ReferenceVssSelectivePointDurableReplayGuard pending_journal(
                pins->replay_journal_path,
                record.registry.registry_binding);
            Digest pending_head{};
            target_pins_valid =
                pending_journal.VerifyPendingBatchWithPinnedHead(
                    context, expected_helpers, target,
                    live_replay_head, &pending_head) &&
                pending_head != live_replay_head &&
                pins->authorize_pending_resume(
                    context, target, expected_helpers,
                    live_replay_head, pending_head);
        }
        if (target_pins_valid && pins->authorize_committed_resume) {
            std::vector<int> expected_helpers;
            expected_helpers.reserve(static_cast<size_t>(n - 1));
            for (int helper = 0; helper < n; ++helper)
                if (helper != target) expected_helpers.push_back(helper);
            ReferenceVssSelectivePointDurableReplayGuard pending_journal(
                pins->replay_journal_path,
                record.registry.registry_binding);
            target_pins_valid =
                pins->authorize_committed_resume(
                    context, target, expected_helpers, live_replay_head) &&
                pending_journal.VerifyCommittedBatchWithPinnedHead(
                    context, expected_helpers, target, live_replay_head);
        }
        local_good = local_good && target_pins_valid;
    }
    ReferenceVssSelectivePoint opening;
    std::vector<u64> encoded;
    if(local_good && rank!=target) {
        local_good=make_reference_vss_selective_point(local,target,&opening) &&
          encode_reference_vss_selective_point_envelope(
              opening,receipt,context,&encoded);
    }
    int ready=local_good?1:0;
    int all_ready=0;
    if(MPI_Allreduce(&ready,&all_ready,1,MPI_INT,MPI_MIN,
                     MPI_COMM_WORLD)!=MPI_SUCCESS || !all_ready)
        return false;
    const size_t stride=26+2*receipt.element_count;
    if((rank!=target && encoded.size()!=stride) ||
       stride>static_cast<size_t>(std::numeric_limits<int>::max())/n)
        return false;
    std::vector<u64> outbound(static_cast<size_t>(n)*stride,0);
    if(rank!=target)
        std::copy(encoded.begin(),encoded.end(),
                  outbound.begin()+static_cast<size_t>(target)*stride);
    std::vector<u64> inbound;
    Digest signed_transport{};
    if(!exchange.AllToAllWords(context,outbound,stride,
                               &inbound,&signed_transport) ||
       signed_transport==Digest{} ||
       inbound.size()!=static_cast<size_t>(n)*stride)
        return false;
    if(rank!=target) return true;

    // The target passed the independent-pin and registry checks before the
    // collective readiness barrier, so no helper opening was sent on failure.
    // Self-delivery must be an empty, authenticated mailbox.
    for(size_t k=0;k<stride;++k)
        if(inbound[static_cast<size_t>(target)*stride+k]!=0)return false;
    std::vector<ReferenceVssSelectivePoint> points;
    std::vector<int> senders;
    points.reserve(static_cast<size_t>(n-1));
    senders.reserve(static_cast<size_t>(n-1));
    for(int helper=0;helper<n;++helper) {
        if(helper==target)continue;
        const auto begin=inbound.begin()+static_cast<size_t>(helper)*stride;
        std::vector<u64> wire(begin,begin+stride);
        ReferenceVssSelectivePoint point;
        if(!decode_reference_vss_selective_point_envelope(
                wire,helper,target,receipt,transcript,context,&point) ||
           !verify_reference_vss_point_commitment(
                record.registry,point,receipt,context))
            return false;
        points.push_back(std::move(point));
        senders.push_back(helper);
    }
    std::vector<F> candidate;
    if(!recover_reference_vss_share_from_committed_points(
          target,receipt,transcript,record.registry,context,
          points,&candidate))
        return false;
    ReferenceVssSelectivePointDurableReplayGuard journal(
        resolved_pins.replay_journal_path,record.registry.registry_binding);
    Digest committed_head{};
    const bool already_committed =
        journal.VerifyCommittedBatchWithPinnedHead(
            context,senders,target,
            resolved_pins.independently_pinned_replay_head);
    // A recovery-only caller may never fall through and create a new batch:
    // its exact committed suffix was authorized before helper openings.
    if (resolved_pins.authorize_committed_resume && !already_committed)
        return false;
    if (resolved_pins.authorize_pending_resume && already_committed)
        return false;
    // Revalidate the uncommitted suffix and old high-water mark after the
    // helper openings have been checked, immediately before retrying CAS.
    if (resolved_pins.authorize_pending_resume) {
        Digest live_head{}, pending_head{};
        if (!resolved_pins.load_current_head ||
            !resolved_pins.load_current_head(&live_head) ||
            live_head != resolved_pins.independently_pinned_replay_head ||
            !journal.VerifyPendingBatchWithPinnedHead(
                context, senders, target, live_head, &pending_head) ||
            pending_head == Digest{} ||
            !resolved_pins.authorize_pending_resume(
                context, target, senders, live_head, pending_head))
            return false;
    }
    if (already_committed) {
        // The independent anchor already names this exact final batch. This
        // is the restart path for a crash after CAS but before output delivery.
        committed_head = resolved_pins.independently_pinned_replay_head;
    } else {
        if(!journal.ObserveBatchWithPinnedHead(
              context,senders,target,
              resolved_pins.independently_pinned_replay_head,&committed_head) ||
           committed_head==Digest{})
            return false;
        // No share is exposed until the separate trusted head update succeeds.
        if(!resolved_pins.persist_new_head(
               resolved_pins.independently_pinned_replay_head,committed_head))
            return false;
    }
    // Always reload the independent anchor after the CAS (or committed
    // resume) and before publishing the recovered value. A successful callback
    // alone is not sufficient evidence that the durable head advanced.
    Digest live_head{};
    if (!resolved_pins.load_current_head ||
        !resolved_pins.load_current_head(&live_head) ||
        live_head != committed_head)
        return false;
    if (resolved_pins.authorize_committed_resume &&
        (!resolved_pins.authorize_committed_resume(
             context, target, senders, live_head) ||
         !journal.VerifyCommittedBatchWithPinnedHead(
             context, senders, target, live_head)))
        return false;
    if (resolved_pins.authorize_pending_resume &&
        !journal.VerifyCommittedBatchWithPinnedHead(
            context, senders, target, live_head))
        return false;
    *next_head=committed_head;
    *recovered=std::move(candidate);
    if (proof_witness) {
        proof_witness->available = true;
        proof_witness->target = target;
        proof_witness->world_size = receipt.world_size;
        proof_witness->threshold = receipt.threshold;
        proof_witness->element_count = receipt.element_count;
        proof_witness->sid = context.sid;
        proof_witness->checkpoint = context.checkpoint;
        proof_witness->setup_round = record.registry.setup_round;
        proof_witness->setup_sequence = record.registry.setup_sequence;
        proof_witness->vss_transcript = record.registry.vss_transcript;
        proof_witness->setup_context_binding =
            record.registry.setup_context_binding;
        proof_witness->signed_commit_transport =
            record.registry.signed_commit_transport;
        proof_witness->signed_ack_transport =
            record.registry.signed_ack_transport;
        proof_witness->registry_binding = record.registry.registry_binding;
        proof_witness->commitments = record.registry.commitments;
        proof_witness->openings = points;
    }
    return true;
}
} // namespace pvia
