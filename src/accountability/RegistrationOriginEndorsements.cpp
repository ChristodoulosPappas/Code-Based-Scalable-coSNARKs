#include "RegistrationOriginEndorsements.hpp"
#include "RegistrationOriginEvidencePair.hpp"
#include "RegistrationPublicOriginBundle.hpp"
#include <cstdlib>

#include "TransferAuthentication.hpp"

#include <mpi.h>

#include <algorithm>
#include <iostream>
#include <limits>
#include <fstream>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>

namespace pvia {

std::vector<u64> registration_origin_endorsement_message(
    const RegistrationConsistencyStatement& statement) {
    // The canonical encoding includes SID, checkpoint, operation, native
    // context and every digest; it rejects invalid or non-FOLD statements.
    return encode_registration_consistency_statement_words(statement);
}

bool verify_registration_origin_endorsements(
    const RegistrationConsistencyStatement& statement,
    const std::vector<RegistrationOriginEndorsement>& endorsements,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& independently_trusted_registry_commitment,
    size_t minimum_distinct_signers,
    bool require_owner_signature) {
    const std::vector<u64> message =
        registration_origin_endorsement_message(statement);
    if (message.size() != 46 || public_keys.empty() ||
        independently_trusted_registry_commitment == Digest{} ||
        // Under the reference bivariate VSS assumption 3t<n, require
        // at least n-t signatures even if a caller accidentally supplies
        // a weaker quorum. Explicit policies may request more.
        minimum_distinct_signers <
            public_keys.size() - (public_keys.size() - 1) / 3 ||
        minimum_distinct_signers > public_keys.size() ||
        endorsements.size() < minimum_distinct_signers ||
        endorsements.size() > public_keys.size() ||
        statement.ref.owner >= public_keys.size())
        return false;
    // The signature registry must be anchored independently of an
    // untrusted proof bundle. A self-reported registry is insufficient.
    if (compute_ed25519_registry_commitment(public_keys) !=
        independently_trusted_registry_commitment)
        return false;

    bool owner_signed = false;
    uint32_t previous = 0;
    bool seen = false;
    for (const auto& entry : endorsements) {
        if (entry.signer >= public_keys.size() ||
            (seen && entry.signer <= previous) ||
            !verify_ed25519_words_with_public_registry(
                REGISTRATION_ORIGIN_ENDORSEMENT_DOMAIN, message,
                entry.signature, entry.signer, public_keys,
                independently_trusted_registry_commitment))
            return false;
        owner_signed |= entry.signer == statement.ref.owner;
        previous = entry.signer;
        seen = true;
    }
    return !require_owner_signature || owner_signed;
}

namespace {

// Synthetic PUBLIC statement import for cross-language Groth16/PVIA
// verification fixture. This helper has NO private witness input.
bool read_test_public_statement(const char* path,
                                RegistrationConsistencyStatement* output) {
    if (!path || !*path || !output) return false;
    struct stat st {};
    if (::lstat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size != 46 * 8) return false;
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::array<unsigned char, 46 * 8> raw{};
    in.read(reinterpret_cast<char*>(raw.data()), raw.size());
    if (!in || in.peek() != std::char_traits<char>::eof()) return false;
    std::vector<u64> w(46);
    for (size_t i = 0; i < w.size(); ++i)
        for (size_t j = 0; j < 8; ++j)
            w[i] |= static_cast<u64>(raw[i * 8 + j]) << (8 * j);
    if (w[3] > std::numeric_limits<uint32_t>::max() ||
        w[6] > std::numeric_limits<uint32_t>::max() ||
        w[7] > std::numeric_limits<uint32_t>::max() ||
        w[5] != static_cast<u64>(AuditRelationKernel::FOLD_RS))
        return false;
    auto read_digest = [&](size_t offset) {
        Digest d{};
        for (size_t i = 0; i < 4; ++i)
            for (size_t j = 0; j < 8; ++j)
                d.bytes[8 * i + j] =
                    static_cast<uint8_t>(w[offset + i] >> (8 * j));
        return d;
    };
    RegistrationConsistencyStatement v;
    v.sid = w[1]; v.checkpoint = w[2];
    v.ref = OperationRef{static_cast<uint32_t>(w[3]), w[4]};
    v.kernel = AuditRelationKernel::FOLD_RS;
    v.state_element_count = static_cast<size_t>(w[6]);
    v.output_element_count = static_cast<size_t>(w[7]);
    v.public_state_digest = read_digest(8);
    v.public_actual_digest = read_digest(12);
    v.public_challenge_binding = read_digest(16);
    v.native_context.native_state_id = w[20];
    v.native_context.authentication_scheme_id = w[21];
    v.native_context.authentication_binding = read_digest(22);
    v.native_context.predecessor_root = read_digest(26);
    v.native_context.checkpoint_root = read_digest(30);
    v.operation_statement_binding = read_digest(34);
    v.sharing_transcript_binding = read_digest(38);
    v.statement_binding = read_digest(42);
    if (encode_registration_consistency_statement_words(v) != w)
        return false;
    *output = v;
    return true;
}

RegistrationConsistencyStatement synthetic_statement_for_test() {
    RegistrationConsistencyStatement s;
    s.sid = 0x50565245474f0001ULL;
    s.checkpoint = 0x50565245474f0002ULL;
    s.ref = OperationRef{0, 0x50565245474f0003ULL};
    s.kernel = AuditRelationKernel::FOLD_RS;
    s.state_element_count = 8;
    s.output_element_count = 4;
    s.public_state_digest = hash_words({0x1001ULL, 0x1002ULL});
    s.public_actual_digest = hash_words({0x2001ULL, 0x2002ULL});
    s.public_challenge_binding = hash_words({0x3001ULL, 0x3002ULL});
    s.native_context.native_state_id = 0x50565245474f0004ULL;
    s.native_context.authentication_scheme_id = 0x4544323535313921ULL;
    s.native_context.authentication_binding = hash_words({0x4001ULL});
    s.native_context.predecessor_root = hash_words({0x5001ULL});
    s.native_context.checkpoint_root = hash_words({0x6001ULL});
    s.operation_statement_binding = hash_words({0x7001ULL});
    s.sharing_transcript_binding = hash_words({0x8001ULL});
    s.statement_binding =
        compute_registration_consistency_statement_binding(s);
    return s;
}

bool altered_statement_rejects(
    RegistrationConsistencyStatement tampered,
    const std::vector<RegistrationOriginEndorsement>& endorsements,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& pinned, size_t quorum) {
    tampered.statement_binding =
        compute_registration_consistency_statement_binding(tampered);
    return !verify_registration_origin_endorsements(
        tampered, endorsements, public_keys, pinned, quorum, true);
}

} // namespace

bool run_registration_origin_endorsement_selftest(int rank, int world_size) {
    if (world_size < 4 || rank < 0 || rank >= world_size)
        return false;
    auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.Initialize(rank, world_size) || !auth.ready()) return false;
    RegistrationConsistencyStatement statement =
        synthetic_statement_for_test();
    // Explicit opt-in test fixture: this signer acts on a supplied
    // public statement, NOT an attestation of consumed native state.
    const char* public_fixture =
        std::getenv("PVIA_REG_PAIR_TEST_PUBLIC_STATEMENT");
    if (public_fixture && *public_fixture &&
        !read_test_public_statement(public_fixture, &statement)) {
        auth.Reset();
        return false;
    }
    const std::vector<u64> message =
        registration_origin_endorsement_message(statement);

    // This pin comes from the current ephemeral test key exchange only.
    // Production must obtain and validate it from independent governance.
    const Digest test_registry = auth.RegistryCommitment();
    const auto public_keys = auth.PublicKeys();
    std::array<uint8_t, 64> local_signature{};
    const bool local_signed =
        message.size() == 46 &&
        auth.SignWords(REGISTRATION_ORIGIN_ENDORSEMENT_DOMAIN,
                       message, &local_signature);
    int all_signed = 0;
    const int signed_flag = local_signed ? 1 : 0;
    MPI_Allreduce(&signed_flag, &all_signed, 1, MPI_INT, MPI_MIN,
                  MPI_COMM_WORLD);
    if (!all_signed) { auth.Reset(); return false; }

    std::vector<uint8_t> gathered(static_cast<size_t>(world_size) * 64);
    MPI_Allgather(local_signature.data(), 64, MPI_UNSIGNED_CHAR,
                  gathered.data(), 64, MPI_UNSIGNED_CHAR, MPI_COMM_WORLD);
    std::vector<RegistrationOriginEndorsement> endorsements;
    for (int signer = 0; signer < world_size; ++signer) {
        RegistrationOriginEndorsement entry;
        entry.signer = static_cast<uint32_t>(signer);
        std::copy_n(gathered.begin() + static_cast<size_t>(signer) * 64,
                    64, entry.signature.begin());
        endorsements.push_back(entry);
    }
    // Public-only two-stage evidence. This isolated selftest generates
    // both signatures from synthetic public data; the MPI registration
    // path separately enforces the real pre-VSS timing of first receipts.
    const std::vector<u64> prefix =
        registration_pre_vss_claim_words(statement);
    std::array<uint8_t, 64> early_signature{};
    const int early_ready =
        prefix.size() == 38 &&
        auth.SignWords(REGISTRATION_PRE_VSS_RECEIPT_DOMAIN,
                       prefix, &early_signature) ? 1 : 0;
    int all_early_ready = 0;
    MPI_Allreduce(&early_ready, &all_early_ready, 1, MPI_INT, MPI_MIN,
                  MPI_COMM_WORLD);
    if (!all_early_ready) { auth.Reset(); return false; }
    std::vector<uint8_t> gathered_early(static_cast<size_t>(world_size) * 64);
    MPI_Allgather(early_signature.data(), 64, MPI_BYTE,
                  gathered_early.data(), 64, MPI_BYTE, MPI_COMM_WORLD);
    RegistrationOriginEvidencePair paired;
    paired.final_endorsements = endorsements;
    for (int signer = 0; signer < world_size; ++signer) {
        RegistrationPreVssReceipt receipt;
        receipt.signer = static_cast<uint32_t>(signer);
        std::copy_n(
            gathered_early.begin() + static_cast<size_t>(signer) * 64,
            64, receipt.signature.begin());
        paired.pre_vss_receipts.push_back(receipt);
    }
    const size_t quorum = static_cast<size_t>(world_size - 1);
    bool paired_ok = verify_registration_origin_evidence_pair(
        statement, paired, public_keys, test_registry, quorum, true);
    auto paired_missing = paired;
    paired_missing.pre_vss_receipts.pop_back();
    paired_ok &= !verify_registration_origin_evidence_pair(
        statement, paired_missing, public_keys, test_registry, quorum, true);
    auto paired_pre_tampered = paired;
    paired_pre_tampered.pre_vss_receipts[0].signature[3] ^= 1;
    paired_ok &= !verify_registration_origin_evidence_pair(
        statement, paired_pre_tampered, public_keys, test_registry,
        quorum, true);
    auto paired_reordered = paired;
    std::swap(paired_reordered.pre_vss_receipts[0],
              paired_reordered.pre_vss_receipts[1]);
    paired_ok &= !verify_registration_origin_evidence_pair(
        statement, paired_reordered, public_keys, test_registry,
        quorum, true);
    auto paired_forged_signer = paired;
    paired_forged_signer.pre_vss_receipts[0].signer = 1;
    paired_ok &= !verify_registration_origin_evidence_pair(
        statement, paired_forged_signer, public_keys, test_registry,
        quorum, true);
    auto paired_final_tampered = paired;
    paired_final_tampered.final_endorsements[0].signature[3] ^= 1;
    paired_ok &= !verify_registration_origin_evidence_pair(
        statement, paired_final_tampered, public_keys, test_registry,
        quorum, true);
    auto paired_no_owner = paired;
    paired_no_owner.final_endorsements.erase(
        paired_no_owner.final_endorsements.begin());
    paired_no_owner.pre_vss_receipts.erase(
        paired_no_owner.pre_vss_receipts.begin());
    paired_ok &= !verify_registration_origin_evidence_pair(
        statement, paired_no_owner, public_keys, test_registry,
        quorum, true);
    paired_ok &= verify_registration_origin_evidence_pair(
        statement, paired_no_owner, public_keys, test_registry,
        quorum, false);
    auto paired_changed_sharing = statement;
    paired_changed_sharing.sharing_transcript_binding =
        hash_words({0xabad1deaULL});
    paired_changed_sharing.statement_binding =
        compute_registration_consistency_statement_binding(
            paired_changed_sharing);
    paired_ok &= !verify_registration_origin_evidence_pair(
        paired_changed_sharing, paired, public_keys, test_registry,
        quorum, true);
    auto paired_changed_execution = statement;
    paired_changed_execution.native_context.native_state_id ^= 1;
    paired_changed_execution.statement_binding =
        compute_registration_consistency_statement_binding(
            paired_changed_execution);
    paired_ok &= !verify_registration_origin_evidence_pair(
        paired_changed_execution, paired, public_keys, test_registry,
        quorum, true);
    paired_ok &= !verify_registration_origin_evidence_pair(
        statement, paired, public_keys, hash_words({0xabcdefULL}),
        quorum, true);
    auto paired_duplicate_keys = public_keys;
    paired_duplicate_keys[1] = paired_duplicate_keys[0];
    paired_ok &= !verify_registration_origin_evidence_pair(
        statement, paired, paired_duplicate_keys,
        compute_ed25519_registry_commitment(paired_duplicate_keys),
        quorum, true);
    paired_ok &= !verify_registration_origin_evidence_pair(
        statement, paired, public_keys, test_registry,
        static_cast<size_t>(world_size - 1) / 2, true);

    bool ok = paired_ok &&
        validate_registration_consistency_statement(statement) &&
        verify_registration_origin_endorsements(
            statement, endorsements, public_keys, test_registry,
            quorum, true);

    // A self-asserted hash-only native_context is NOT enough to provide
    // even the public endorsement: signatures are required.
    ok &= !verify_registration_origin_endorsements(
        statement, {}, public_keys, test_registry, quorum, true);
    auto less = endorsements;
    less.resize(quorum - 1);
    ok &= !verify_registration_origin_endorsements(
        statement, less, public_keys, test_registry, quorum, true);
    auto no_owner = endorsements;
    no_owner.erase(no_owner.begin());
    ok &= !verify_registration_origin_endorsements(
        statement, no_owner, public_keys, test_registry, quorum, true);
    ok &= verify_registration_origin_endorsements(
        statement, no_owner, public_keys, test_registry, quorum, false);
    auto duplicate = endorsements;
    duplicate[1] = duplicate[0];
    ok &= !verify_registration_origin_endorsements(
        statement, duplicate, public_keys, test_registry, quorum, true);
    auto shuffled = endorsements;
    std::swap(shuffled[0], shuffled[1]);
    ok &= !verify_registration_origin_endorsements(
        statement, shuffled, public_keys, test_registry, quorum, true);
    auto bad_signature = endorsements;
    bad_signature[0].signature[13] ^= 1;
    ok &= !verify_registration_origin_endorsements(
        statement, bad_signature, public_keys, test_registry, quorum, true);
    auto mismatched_signer = endorsements;
    std::swap(mismatched_signer[0].signature,
              mismatched_signer[1].signature);
    ok &= !verify_registration_origin_endorsements(
        statement, mismatched_signer, public_keys, test_registry,
        quorum, true);
    auto other_pin = hash_words({0x1111ULL, 0x2222ULL});
    ok &= !verify_registration_origin_endorsements(
        statement, endorsements, public_keys, other_pin, quorum, true);
    auto substituted_registry = public_keys;
    std::swap(substituted_registry[0], substituted_registry[1]);
    ok &= !verify_registration_origin_endorsements(
        statement, endorsements, substituted_registry, test_registry,
        quorum, true);
    ok &= !verify_registration_origin_endorsements(
        statement, endorsements, public_keys, Digest{}, quorum, true);
    ok &= !verify_registration_origin_endorsements(
        statement, endorsements, public_keys, test_registry, 0, true);
    ok &= !verify_registration_origin_endorsements(
        statement, endorsements, public_keys, test_registry,
        static_cast<size_t>(world_size - 1) / 2, true);
    auto duplicated_keys = public_keys;
    duplicated_keys[1] = duplicated_keys[0];
    const Digest duplicate_registry =
        compute_ed25519_registry_commitment(duplicated_keys);
    ok &= !verify_registration_origin_endorsements(
        statement, endorsements, duplicated_keys, duplicate_registry,
        quorum, true);
    std::array<uint8_t, 64> wrong_domain_signature{};
    if (auth.SignWords(REGISTRATION_ORIGIN_ENDORSEMENT_DOMAIN ^ 1ULL,
                       message, &wrong_domain_signature)) {
        auto wrong_domain = endorsements;
        wrong_domain[static_cast<size_t>(rank)].signature =
            wrong_domain_signature;
        ok &= !verify_registration_origin_endorsements(
            statement, wrong_domain, public_keys, test_registry,
            quorum, true);
    } else {
        ok = false;
    }

    ok &= !verify_registration_origin_endorsements(
        statement, endorsements, public_keys, test_registry,
        endorsements.size() + 1, true);

    auto mutated = statement;
    mutated.sid ^= 1;
    ok &= altered_statement_rejects(mutated, endorsements, public_keys,
                                    test_registry, quorum);
    mutated = statement; mutated.checkpoint ^= 1;
    ok &= altered_statement_rejects(mutated, endorsements, public_keys,
                                    test_registry, quorum);
    mutated = statement; mutated.ref.object_id ^= 1;
    ok &= altered_statement_rejects(mutated, endorsements, public_keys,
                                    test_registry, quorum);
    mutated = statement; mutated.ref.owner = 1;
    ok &= altered_statement_rejects(mutated, endorsements, public_keys,
                                    test_registry, quorum);
    mutated = statement; mutated.native_context.native_state_id ^= 1;
    ok &= altered_statement_rejects(mutated, endorsements, public_keys,
                                    test_registry, quorum);
    mutated = statement;
    mutated.native_context.authentication_binding =
        hash_words({0xbeefULL});
    ok &= altered_statement_rejects(mutated, endorsements, public_keys,
                                    test_registry, quorum);
    mutated = statement;
    mutated.native_context.predecessor_root = hash_words({0xbeefULL});
    ok &= altered_statement_rejects(mutated, endorsements, public_keys,
                                    test_registry, quorum);
    mutated = statement;
    mutated.native_context.checkpoint_root = hash_words({0xbeefULL});
    ok &= altered_statement_rejects(mutated, endorsements, public_keys,
                                    test_registry, quorum);
    mutated = statement;
    mutated.operation_statement_binding = hash_words({0xbeefULL});
    ok &= altered_statement_rejects(mutated, endorsements, public_keys,
                                    test_registry, quorum);
    mutated = statement;
    mutated.sharing_transcript_binding = hash_words({0xbeefULL});
    ok &= altered_statement_rejects(mutated, endorsements, public_keys,
                                    test_registry, quorum);
    mutated = statement;
    mutated.public_state_digest = hash_words({0xbeefULL});
    ok &= altered_statement_rejects(mutated, endorsements, public_keys,
                                    test_registry, quorum);
    mutated = statement;
    mutated.public_actual_digest = hash_words({0xbeefULL});
    ok &= altered_statement_rejects(mutated, endorsements, public_keys,
                                    test_registry, quorum);
    mutated = statement;
    mutated.public_challenge_binding = hash_words({0xbeefULL});
    ok &= altered_statement_rejects(mutated, endorsements, public_keys,
                                    test_registry, quorum);

    int local_ok = ok ? 1 : 0, global_ok = 0;
    MPI_Allreduce(&local_ok, &global_ok, 1, MPI_INT, MPI_MIN,
                  MPI_COMM_WORLD);
    // Opt-in PUBLIC-only artifact export. The root's file contains
    // statement, registered public keys and public signatures ONLY;
    // externally fixed trust pins are never read from this file.
    int export_ok = 1;
    if (rank == 0 && global_ok) {
        const char* public_path =
            std::getenv("PVIA_REG_PAIR_PUBLIC_EXPORT");
        if (public_path && *public_path) {
            RegistrationPublicOriginBundle bundle;
            bundle.statement = statement;
            bundle.public_keys = public_keys;
            bundle.signatures = paired;
            export_ok = write_registration_public_origin_bundle(
                public_path, bundle) ? 1 : 0;
            if (export_ok)
                std::cout << "PVIA_REG_PAIR_TEST_PINS:"
                          << " statement=" << statement.statement_binding.hex()
                          << " registry=" << test_registry.hex()
                          << " origin=EPHEMERAL_TEST_ONLY"
                          << std::endl;
        }
    }
    MPI_Bcast(&export_ok, 1, MPI_INT, 0, MPI_COMM_WORLD);
    global_ok = global_ok && export_ok;
    auth.Reset();
    if (rank == 0)
        std::cout << "PVIA_REG_ORIGIN_SELFTEST: "
                  << (global_ok ? "PASS" : "FAIL")
                  << " class=EPHEMERAL_ED25519_PUBLIC_ENDORSEMENT_ONLY"
                  << " distinct_signers=" << world_size
                  << " quorum=" << quorum
                  << " native_share_equality=NOT_ATTESTED"
                  << std::endl;
    if (rank == 0)
        std::cout << "PVIA_REG_PAIR_SELFTEST: "
                  << (global_ok ? "PASS" : "FAIL")
                  << " claim=PUBLIC_TWO_STAGE_SIGNATURES_ONLY"
                  << " signer_count=" << world_size
                  << " quorum=" << quorum
                  << " independent_registry=NOT_ATTESTED"
                  << " native_share_equality=NOT_ATTESTED"
                  << std::endl;
    return global_ok != 0;
}

} // namespace pvia
