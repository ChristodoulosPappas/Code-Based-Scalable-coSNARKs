#include "Sp1SumcheckProofProvider.hpp"

#include "NativeSumcheckResidualComputationBackend.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <fstream>
#include <cerrno>
#include <cstdio>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <limits>

#include <dlfcn.h>

namespace pvia {
namespace {

constexpr uint64_t SUMCHECK_STATEMENT_DOMAIN = 0x505653554d535431ULL;
constexpr uint64_t SUMCHECK_WITNESS_DOMAIN = 0x505653554d575431ULL;
constexpr uint64_t SUMCHECK_LAYOUT_DOMAIN = 0x505653544c415931ULL;
constexpr uint64_t SUMCHECK_AUX_KIND_CHALLENGE = 1ULL;
constexpr uint64_t SUMCHECK_ABI_VERSION = 1ULL;
constexpr uint64_t SUMCHECK_FIELD_MODULUS = 2305843009213693951ULL;
constexpr uint32_t SUMCHECK_SP1_GROTH16_SYSTEM_ID = 68102;
constexpr size_t SUMCHECK_STATEMENT_WORDS = 52;
constexpr size_t SUMCHECK_MAX_SEGMENT_FIELDS = 1U << 20;
constexpr size_t SUMCHECK_MAX_AUX_FIELDS = 32;
constexpr size_t SUMCHECK_PROOF_HEADER_WORDS = 17;
constexpr uint64_t SUMCHECK_CANDIDATE_PROTOCOL_ID = 0x5056494153554d32ULL;
constexpr uint64_t SUMCHECK_ARTIFACT_MAGIC = 0x505653554d505246ULL;
constexpr uint64_t SUMCHECK_PROOF_COMMITMENT_DOMAIN = 0x505653554d505246ULL;

void append_digest_words(const Digest& digest, std::vector<uint64_t>* words) {
    for (size_t i = 0; i < 4; ++i) {
        uint64_t word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

Digest digest_from_words(const std::vector<uint64_t>& words, size_t offset) {
    Digest digest{};
    if (offset > words.size() || words.size() - offset < 4) return digest;
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(digest.bytes.data() + 8 * i, &words[offset + i], 8);
    return digest;
}

bool append_field(const F& value, std::vector<uint64_t>* words) {
    if (!words || value.real >= SUMCHECK_FIELD_MODULUS ||
        value.img >= SUMCHECK_FIELD_MODULUS)
        return false;
    words->push_back(static_cast<uint64_t>(value.real));
    words->push_back(static_cast<uint64_t>(value.img));
    return true;
}

bool sumcheck_kernel_index(AuditRelationKernel kernel, size_t* index) {
    if (!index) return false;
    switch (kernel) {
        case AuditRelationKernel::COSUMCHECK_ZERO: *index = 0; return true;
        case AuditRelationKernel::COSUMCHECK_QUADRATIC: *index = 1; return true;
        case AuditRelationKernel::COSUMCHECK_BATCH: *index = 2; return true;
        case AuditRelationKernel::DSC_QUADRATIC: *index = 3; return true;
        case AuditRelationKernel::DSC_CUBIC: *index = 4; return true;
        default: return false;
    }
}

bool env_is_one(const char* name) {
    const char* value = std::getenv(name);
    return value && std::string(value) == "1";
}

bool expected_shape(
    AuditRelationKernel kernel, size_t* segments, size_t* coefficients) {
    if (!segments || !coefficients) return false;
    switch (kernel) {
        case AuditRelationKernel::COSUMCHECK_ZERO:
            *segments = 6; *coefficients = 4; return true;
        case AuditRelationKernel::COSUMCHECK_QUADRATIC:
            *segments = 2; *coefficients = 3; return true;
        case AuditRelationKernel::COSUMCHECK_BATCH:
            *segments = 6; *coefficients = 3; return true;
        case AuditRelationKernel::DSC_QUADRATIC:
            *segments = 2; *coefficients = 3; return true;
        case AuditRelationKernel::DSC_CUBIC:
            *segments = 3; *coefficients = 4; return true;
        default:
            return false;
    }
}

bool same_digest_words(
    const std::vector<uint64_t>& words, size_t offset, const Digest& digest) {
    if (offset > words.size() || words.size() - offset < 4) return false;
    return digest_from_words(words, offset) == digest;
}

bool run_independent_verifier(
    const std::string& verifier_path, const std::string& artifact_path) {
    if (verifier_path.empty() || artifact_path.empty()) return false;
    const pid_t child = fork();
    if (child < 0) return false;
    if (child == 0) {
        const char* home = std::getenv("HOME");
        const char* ld_library_path = std::getenv("LD_LIBRARY_PATH");
        const char* rayon_threads =
            std::getenv("PVIA_SP1_SUMCHECK_RAYON_THREADS");
        const std::string home_env =
            std::string("HOME=") + (home ? home : "/home/user");
        const std::string ld_env =
            std::string("LD_LIBRARY_PATH=") +
            (ld_library_path ? ld_library_path : "");
        const std::string rayon_env =
            std::string("RAYON_NUM_THREADS=") +
            (rayon_threads ? rayon_threads : "8");
        char path_env[] = "PATH=/usr/local/bin:/usr/bin:/bin";
        char tmp_env[] = "TMPDIR=/tmp";
        char* child_env[] = {
            path_env,
            const_cast<char*>(home_env.c_str()),
            const_cast<char*>(ld_env.c_str()),
            const_cast<char*>(rayon_env.c_str()),
            tmp_env,
            nullptr
        };
        char* child_argv[] = {
            const_cast<char*>(verifier_path.c_str()),
            const_cast<char*>(artifact_path.c_str()),
            nullptr
        };
        execve(verifier_path.c_str(), child_argv, child_env);
        _exit(127);
    }

    int status = 0;
    pid_t waited = -1;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    return waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

} // namespace

Sp1SumcheckProofProvider::Sp1SumcheckProofProvider(
    const std::string& library_path)
    : library_path_(library_path) {
    if (library_path_.empty()) {
        const char* configured =
            std::getenv("PVIA_SP1_SUMCHECK_PROVIDER_LIBRARY");
        if (configured) library_path_ = configured;
    }
    const char* executable =
        std::getenv("PVIA_SP1_SUMCHECK_PROVER_EXECUTABLE");
    if (executable) prover_path_ = executable;
    if (prover_path_.empty())
        prover_path_ =
            "experiments/sp1_provider/target/release/examples/prove_sumcheck_words";
    const char* verifier =
        std::getenv("PVIA_SP1_SUMCHECK_VERIFIER_EXECUTABLE");
    if (verifier) verifier_path_ = verifier;
    if (verifier_path_.empty())
        verifier_path_ =
            "experiments/sp1_provider/target/release/examples/verify_sumcheck_artifact";
}

Sp1SumcheckProofProvider::~Sp1SumcheckProofProvider() {
    if (library_) dlclose(library_);
}

bool Sp1SumcheckProofProvider::EnsureLoaded() const {
    if (load_attempted_) return capability_valid_;
    load_attempted_ = true;
    if (library_path_.empty()) return false;

    library_ = dlopen(library_path_.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!library_) {
        std::cerr << "[PVIA][sp1-sumcheck] dlopen failed: "
                  << dlerror() << "\n";
        return false;
    }

    abi_version_ = reinterpret_cast<AbiVersionFn>(
        dlsym(library_, "pvia_sumcheck_provider_abi_version"));
    capabilities_ = reinterpret_cast<CapabilitiesFn>(
        dlsym(library_, "pvia_sumcheck_candidate_capabilities"));
    validate_ = reinterpret_cast<ValidateFn>(
        dlsym(library_, "pvia_sumcheck_candidate_validate"));
    if (!abi_version_ || !capabilities_ || !validate_)
        return false;
    if (abi_version_() != 1) return false;

    size_t count = 0;
    if (!capabilities_(nullptr, &count) || count != 20) return false;
    std::vector<uint64_t> words(count, 0);
    if (!capabilities_(words.data(), &count) || count != 20) return false;
    capability_valid_ =
        words[0] == 0x505653554d434150ULL &&
        words[1] == 1 &&
        words[2] == 1 &&
        words[3] == 1 &&
        words[4] == 0 &&
        words[5] == 1 &&
        words[6] == 1 &&
        words[7] == SUMCHECK_CANDIDATE_PROTOCOL_ID;
    if (!capability_valid_) {
        std::cerr << "[PVIA][sp1-sumcheck] candidate capability rejected\n";
        return false;
    }
    std::cerr << "[PVIA][sp1-sumcheck] candidate ABI ready; "
                 "production_privacy_confirmed=0\n";
    return true;
}

bool Sp1SumcheckProofProvider::Available() const {
    return EnsureLoaded();
}

bool Sp1SumcheckProofProvider::Enabled(AuditRelationKernel kernel) const {
    size_t index = 0;
    if (!sumcheck_kernel_index(kernel, &index) || !EnsureLoaded())
        return false;

    // PROVE_ONCE preserves the historical one-artifact diagnostic mode.
    // PROVE_ALL emits at most one real-context proof for each native kernel.
    const bool prove_all = env_is_one("PVIA_SP1_SUMCHECK_PROVE_ALL");
    const bool prove_once = env_is_one("PVIA_SP1_SUMCHECK_PROVE_ONCE");
    if (!prove_all && !prove_once) return false;
    if (prove_all) {
        if (proof_attempted_[index]) return false;
    } else {
        for (bool attempted : proof_attempted_)
            if (attempted) return false;
    }

    // The diagnostic proof is intentionally generated by rank 0 only when
    // launched under MPI; other ranks retain the fast local relation check.
    const char* rank = std::getenv("OMPI_COMM_WORLD_RANK");
    if (!rank) rank = std::getenv("PMI_RANK");
    if (rank && std::atoi(rank) != 0) return false;
    return true;
}

bool Sp1SumcheckProofProvider::ReadLatestReceipt(
    AuditRelationKernel kernel,
    Sp1SumcheckProofReceipt* receipt) const {
    if (!receipt) return false;
    *receipt = Sp1SumcheckProofReceipt{};
    size_t index = 0;
    if (!sumcheck_kernel_index(kernel, &index) || !receipt_valid_[index])
        return false;
    *receipt = receipts_[index];
    return receipt->available && receipt->proof_verified;
}

bool Sp1SumcheckProofProvider::BuildRelationInput(
    const KernelResidualContext& context,
    std::vector<uint64_t>* statement_words,
    std::vector<uint64_t>* witness_words) const {
    if (!statement_words || !witness_words ||
        context.operation.relation != RelationKind::PRIVATE_DERIVATION ||
        context.material.state_dependencies.size() != 1 ||
        !context.material.has_field_input ||
        !context.material.has_field_output ||
        context.operation.ref.object_id == 0 ||
        context.operation.ref.object_id != context.operation.label.object_id ||
        context.operation.ref.owner != context.operation.label.owner ||
        context.operation.label.sid == 0 ||
        context.operation.checkpoint == 0 ||
        context.operation.expected == Digest{} ||
        context.operation.actual == Digest{} ||
        context.operation.relation_statement == Digest{} ||
        !validate_kernel_residual_material(context))
        return false;

    size_t expected_segments = 0, expected_coefficients = 0;
    if (!expected_shape(context.operation.kernel,
                       &expected_segments, &expected_coefficients))
        return false;

    const PrivateStateMaterial* state = context.state(0);
    const std::vector<F>* aux =
        context.field_aux(AuditPublicAuxKind::SUMCHECK_CHALLENGE);
    const size_t minimum_aux =
        context.operation.kernel == AuditRelationKernel::COSUMCHECK_ZERO ||
        context.operation.kernel == AuditRelationKernel::COSUMCHECK_BATCH ? 2 : 1;
    if (!state || !state->has_private_share || !aux ||
        aux->size() < minimum_aux || aux->size() > SUMCHECK_MAX_AUX_FIELDS ||
        state->state.id == 0 ||
        state->state.label.sid != context.operation.label.sid ||
        state->state.label.object_id != state->state.id ||
        state->segment_layout_binding == Digest{} ||
        !context.states.VerifyDigest(state->state.id) ||
        !context.states.VerifySegmentLayout(state->state.id) ||
        context.state_segment_count(0) != expected_segments ||
        context.material.field_input.size() != expected_coefficients ||
        context.material.field_output.size() != expected_coefficients ||
        hash_field_vector(context.material.field_input) !=
            context.operation.expected ||
        hash_field_vector(context.material.field_output) !=
            context.operation.actual)
        return false;

    // The five native kernels currently have one public field auxiliary:
    // SUMCHECK_CHALLENGE. Enforce that exact shape so the challenge root in the
    // guest statement is the same root committed by Runtime.
    if (context.material.public_aux_evidence.size() != 1 ||
        context.material.public_aux_evidence[0].kind !=
            AuditPublicAuxKind::SUMCHECK_CHALLENGE ||
        context.material.public_aux_evidence[0].digest != hash_field_vector(*aux) ||
        compute_public_aux_root(context.material.public_aux_evidence) !=
            context.operation.public_aux_root)
        return false;

    std::vector<FieldStateSegment> segments;
    std::vector<size_t> segment_lengths;
    std::vector<F> flattened;
    segments.reserve(expected_segments);
    segment_lengths.reserve(expected_segments);
    for (size_t i = 0; i < expected_segments; ++i) {
        FieldStateSegment segment;
        if (!context.state_segment(0, i, &segment) || !segment.values ||
            segment.count == 0 || segment.count > SUMCHECK_MAX_SEGMENT_FIELDS ||
            segment.count % 2 != 0)
            return false;
        if (segment.count != state->segment_lengths[i]) return false;
        segments.push_back(segment);
        segment_lengths.push_back(segment.count);
        for (size_t j = 0; j < segment.count; ++j) {
            const F& value = (*segment.values)[segment.offset + j];
            flattened.push_back(value);
        }
    }
    if (hash_field_vector(flattened) != state->state.digest) return false;

    std::vector<F> recomputed;
    if (!recompute_native_sumcheck_polynomial(context, &recomputed) ||
        recomputed != context.material.field_input ||
        recomputed.size() != context.material.field_output.size())
        return false;

    std::vector<F> residual(recomputed.size(), F(0));
    for (size_t i = 0; i < recomputed.size(); ++i)
        residual[i] = context.material.field_output[i] - recomputed[i];

    const Digest input_digest = hash_field_vector(context.material.field_input);
    const Digest output_digest = hash_field_vector(context.material.field_output);
    const Digest state_digest = state->state.digest;
    const Digest layout_digest = state->segment_layout_binding;
    const Digest aux_digest = hash_field_vector(*aux);
    const Digest residual_digest = hash_field_vector(residual);

    std::vector<u64> aux_root_words{SUMCHECK_AUX_KIND_CHALLENGE};
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, aux_digest.bytes.data() + 8 * i, 8);
        aux_root_words.push_back(word);
    }
    const Digest aux_root = hash_words(aux_root_words);

    std::vector<uint64_t> statement;
    statement.reserve(SUMCHECK_STATEMENT_WORDS);
    statement.push_back(SUMCHECK_STATEMENT_DOMAIN);
    statement.push_back(SUMCHECK_ABI_VERSION);
    statement.push_back(static_cast<uint64_t>(context.operation.kernel));
    statement.push_back(context.operation.label.sid);
    statement.push_back(context.operation.checkpoint);
    statement.push_back(0); // checkpoint generation is not carried by this ABI
    statement.push_back(context.operation.ref.object_id);
    statement.push_back(static_cast<uint64_t>(context.operation.label.phase));
    statement.push_back(context.operation.label.round);
    statement.push_back(state->state.id);
    statement.push_back(state->state.label.sid);
    statement.push_back(static_cast<uint64_t>(state->state.label.phase));
    statement.push_back(state->state.label.round);
    statement.push_back(state->state.label.owner);
    statement.push_back(static_cast<uint64_t>(state->state.label.obligation));
    statement.push_back(state->state.label.object_id);
    append_digest_words(input_digest, &statement);
    append_digest_words(output_digest, &statement);
    append_digest_words(state_digest, &statement);
    append_digest_words(layout_digest, &statement);
    append_digest_words(aux_root, &statement);
    append_digest_words(context.operation.relation_statement, &statement);
    append_digest_words(input_digest, &statement);
    append_digest_words(output_digest, &statement);
    append_digest_words(residual_digest, &statement);
    if (statement.size() != SUMCHECK_STATEMENT_WORDS) return false;

    std::vector<uint64_t> witness{
        SUMCHECK_WITNESS_DOMAIN, SUMCHECK_ABI_VERSION,
        static_cast<uint64_t>(segments.size())};
    for (const FieldStateSegment& segment : segments) {
        witness.push_back(static_cast<uint64_t>(segment.count));
        for (size_t j = 0; j < segment.count; ++j) {
            if (!append_field((*segment.values)[segment.offset + j], &witness))
                return false;
        }
    }
    witness.push_back(static_cast<uint64_t>(aux->size()));
    for (const F& value : *aux)
        if (!append_field(value, &witness)) return false;
    witness.push_back(static_cast<uint64_t>(context.material.field_input.size()));
    for (const F& value : context.material.field_input)
        if (!append_field(value, &witness)) return false;
    witness.push_back(static_cast<uint64_t>(context.material.field_output.size()));
    for (const F& value : context.material.field_output)
        if (!append_field(value, &witness)) return false;

    *statement_words = std::move(statement);
    *witness_words = std::move(witness);
    return true;
}

bool Sp1SumcheckProofProvider::ExportRelationInput(
    const KernelResidualContext& context) const {
    size_t kernel_index = 0;
    if (!sumcheck_kernel_index(context.operation.kernel, &kernel_index) ||
        !EnsureLoaded())
        return false;

    const char* output_dir =
        std::getenv("PVIA_SP1_SUMCHECK_EXPORT_DIR");
    if (!output_dir || !*output_dir) return false;

    const char* rank = std::getenv("OMPI_COMM_WORLD_RANK");
    if (!rank) rank = std::getenv("PMI_RANK");
    if (rank && std::atoi(rank) != 0) return true;
    if (input_exported_[kernel_index]) return true;

    std::vector<uint64_t> statement, witness;
    if (!BuildRelationInput(context, &statement, &witness) ||
        !ValidateRelationInput(statement, witness))
        return false;

    const std::string output_path =
        std::string(output_dir) + "/kernel_" +
        std::to_string(kernel_index + 1) + ".input.bin";
    std::ofstream output(
        output_path, std::ios::binary | std::ios::trunc);
    if (!output) return false;
    const uint64_t statement_count =
        static_cast<uint64_t>(statement.size());
    const uint64_t witness_count =
        static_cast<uint64_t>(witness.size());
    output.write(reinterpret_cast<const char*>(&statement_count), 8);
    output.write(reinterpret_cast<const char*>(&witness_count), 8);
    output.write(reinterpret_cast<const char*>(statement.data()),
                 static_cast<std::streamsize>(
                     statement.size() * sizeof(uint64_t)));
    output.write(reinterpret_cast<const char*>(witness.data()),
                 static_cast<std::streamsize>(
                     witness.size() * sizeof(uint64_t)));
    output.flush();
    if (!output) return false;
    output.close();
    // Native witness exports are private development artifacts. Restrict
    // access even when the caller created the output directory permissively.
    if (::chmod(output_path.c_str(), S_IRUSR | S_IWUSR) != 0) {
        std::remove(output_path.c_str());
        return false;
    }
    input_exported_[kernel_index] = true;

    std::cerr << "[PVIA][sp1-sumcheck-input-export] PASS kernel="
              << (kernel_index + 1)
              << " statement_words=" << statement.size()
              << " witness_words=" << witness.size()
              << " path=" << output_path << "\n";
    return true;
}

bool Sp1SumcheckProofProvider::ValidateRelationInput(
    const std::vector<uint64_t>& statement_words,
    const std::vector<uint64_t>& witness_words) const {
    return EnsureLoaded() &&
        validate_(statement_words.data(), statement_words.size(),
                  witness_words.data(), witness_words.size()) == 1;
}

bool Sp1SumcheckProofProvider::ProveAndVerify(
    const KernelResidualContext& context,
    Sp1SumcheckProofReceipt* receipt) const {
    if (!receipt) return false;
    *receipt = Sp1SumcheckProofReceipt{};
    size_t kernel_index = 0;
    if (!sumcheck_kernel_index(context.operation.kernel, &kernel_index) ||
        !EnsureLoaded() || prover_path_.empty())
        return false;
    const bool prove_all = env_is_one("PVIA_SP1_SUMCHECK_PROVE_ALL");
    if (prove_all) {
        if (proof_attempted_[kernel_index]) return false;
    } else {
        for (bool attempted : proof_attempted_)
            if (attempted) return false;
    }
    proof_attempted_[kernel_index] = true;

    std::vector<uint64_t> statement, witness;
    if (!BuildRelationInput(context, &statement, &witness) ||
        !ValidateRelationInput(statement, witness))
        return false;

    char input_template[] = "/tmp/pvia_sp1_sumcheck_input_XXXXXX";
    const int input_fd = mkstemp(input_template);
    if (input_fd < 0) return false;
    close(input_fd);
    const std::string input_path(input_template);

    const char* configured_artifact =
        std::getenv("PVIA_SP1_SUMCHECK_ARTIFACT_PATH");
    std::string output_path;
    const bool keep_output = configured_artifact && *configured_artifact;
    if (keep_output) {
        output_path = configured_artifact;
        if (prove_all) {
            const std::string marker = "%KERNEL%";
            const std::string replacement = std::to_string(kernel_index + 1);
            size_t marker_pos = output_path.find(marker);
            if (marker_pos != std::string::npos) {
                while (marker_pos != std::string::npos) {
                    output_path.replace(marker_pos, marker.size(), replacement);
                    marker_pos = output_path.find(marker, marker_pos + replacement.size());
                }
            } else {
                const size_t slash = output_path.find_last_of('/');
                const size_t dot = output_path.find_last_of('.');
                const size_t insert_at =
                    dot != std::string::npos &&
                    (slash == std::string::npos || dot > slash)
                    ? dot : output_path.size();
                output_path.insert(
                    insert_at, ".kernel_" + replacement);
            }
        }
    } else {
        char output_template[] = "/tmp/pvia_sp1_sumcheck_proof_XXXXXX";
        const int output_fd = mkstemp(output_template);
        if (output_fd < 0) {
            std::remove(input_path.c_str());
            return false;
        }
        close(output_fd);
        std::remove(output_template);
        output_path = output_template;
    }

    {
        std::ofstream input(input_path, std::ios::binary | std::ios::trunc);
        const uint64_t statement_count =
            static_cast<uint64_t>(statement.size());
        const uint64_t witness_count =
            static_cast<uint64_t>(witness.size());
        input.write(reinterpret_cast<const char*>(&statement_count), 8);
        input.write(reinterpret_cast<const char*>(&witness_count), 8);
        input.write(reinterpret_cast<const char*>(statement.data()),
                    static_cast<std::streamsize>(
                        statement.size() * sizeof(uint64_t)));
        input.write(reinterpret_cast<const char*>(witness.data()),
                    static_cast<std::streamsize>(
                        witness.size() * sizeof(uint64_t)));
        input.flush();
        if (!input) {
            std::remove(input_path.c_str());
            if (!keep_output) std::remove(output_path.c_str());
            return false;
        }
    }

    const pid_t child = fork();
    if (child < 0) {
        std::remove(input_path.c_str());
        if (!keep_output) std::remove(output_path.c_str());
        return false;
    }
    if (child == 0) {
        const char* home = std::getenv("HOME");
        const char* ld_library_path = std::getenv("LD_LIBRARY_PATH");
        const char* rayon_threads =
            std::getenv("PVIA_SP1_SUMCHECK_RAYON_THREADS");
        const std::string home_env =
            std::string("HOME=") + (home ? home : "/home/user");
        const std::string ld_env =
            std::string("LD_LIBRARY_PATH=") +
            (ld_library_path ? ld_library_path : "");
        const std::string rayon_env =
            std::string("RAYON_NUM_THREADS=") +
            (rayon_threads ? rayon_threads : "8");
        char path_env[] = "PATH=/usr/local/bin:/usr/bin:/bin";
        char tmp_env[] = "TMPDIR=/tmp";
        char* child_env[] = {
            path_env,
            const_cast<char*>(home_env.c_str()),
            const_cast<char*>(ld_env.c_str()),
            const_cast<char*>(rayon_env.c_str()),
            tmp_env,
            nullptr
        };
        char* child_argv[] = {
            const_cast<char*>(prover_path_.c_str()),
            const_cast<char*>(input_path.c_str()),
            const_cast<char*>(output_path.c_str()),
            nullptr
        };
        execve(prover_path_.c_str(), child_argv, child_env);
        _exit(127);
    }

    int status = 0;
    pid_t waited = -1;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    std::remove(input_path.c_str());
    if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (!keep_output) std::remove(output_path.c_str());
        return false;
    }

    std::ifstream artifact(output_path, std::ios::binary);
    if (!artifact) {
        if (!keep_output) std::remove(output_path.c_str());
        return false;
    }
    uint64_t header[SUMCHECK_PROOF_HEADER_WORDS] = {};
    artifact.read(reinterpret_cast<char*>(header), sizeof(header));
    if (!artifact || header[0] != SUMCHECK_ARTIFACT_MAGIC ||
        header[1] != 1 || header[2] == 0 ||
        header[2] > (1ULL << 30) ||
        header[3] <= SUMCHECK_PROOF_HEADER_WORDS ||
        header[3] > (1ULL << 22) ||
        header[16] != SUMCHECK_SP1_GROTH16_SYSTEM_ID) {
        if (!keep_output) std::remove(output_path.c_str());
        return false;
    }

    std::vector<uint8_t> proof_bytes(static_cast<size_t>(header[2]));
    artifact.read(reinterpret_cast<char*>(proof_bytes.data()),
                  static_cast<std::streamsize>(proof_bytes.size()));
    const bool exact_eof =
        artifact && artifact.peek() == std::ifstream::traits_type::eof();
    artifact.close();
    if (!exact_eof) {
        if (!keep_output) std::remove(output_path.c_str());
        return false;
    }

    std::vector<u64> statement_u64(statement.begin(), statement.end());
    const Digest expected_statement_binding = hash_words(statement_u64);
    const Digest statement_binding = digest_from_words(
        std::vector<uint64_t>(header, header + SUMCHECK_PROOF_HEADER_WORDS), 4);
    const Digest transcript_binding = digest_from_words(
        std::vector<uint64_t>(header, header + SUMCHECK_PROOF_HEADER_WORDS), 8);
    const Digest artifact_commitment = digest_from_words(
        std::vector<uint64_t>(header, header + SUMCHECK_PROOF_HEADER_WORDS), 12);
    if (statement_binding != expected_statement_binding ||
        transcript_binding == Digest{} ||
        artifact_commitment == Digest{}) {
        if (!keep_output) std::remove(output_path.c_str());
        return false;
    }

    std::vector<u64> provider_words;
    provider_words.reserve((proof_bytes.size() + 7) / 8);
    for (size_t offset = 0; offset < proof_bytes.size(); offset += 8) {
        u64 word = 0;
        const size_t count = std::min<size_t>(8, proof_bytes.size() - offset);
        std::memcpy(&word, proof_bytes.data() + offset, count);
        provider_words.push_back(word);
    }
    if (header[3] != SUMCHECK_PROOF_HEADER_WORDS + provider_words.size()) {
        if (!keep_output) std::remove(output_path.c_str());
        return false;
    }
    std::vector<u64> commitment_words = {
        SUMCHECK_PROOF_COMMITMENT_DOMAIN, 1, 1, 1,
        SUMCHECK_SP1_GROTH16_SYSTEM_ID,
        static_cast<uint64_t>(provider_words.size())};
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, statement_binding.bytes.data() + 8 * i, 8);
        commitment_words.push_back(word);
    }
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, transcript_binding.bytes.data() + 8 * i, 8);
        commitment_words.push_back(word);
    }
    commitment_words.insert(
        commitment_words.end(), provider_words.begin(), provider_words.end());
    if (hash_words(commitment_words) != artifact_commitment) {
        if (!keep_output) std::remove(output_path.c_str());
        return false;
    }

    // Re-open the serialized artifact in a separate verifier process and
    // perform SP1 Groth16 verification before creating a successful receipt.
    // A prover exit code or a valid artifact hash alone is not sufficient.
    if (!run_independent_verifier(verifier_path_, output_path)) {
        std::cerr << "[PVIA][sp1-sumcheck] independent Groth16 verifier failed; "
                     "candidate receipt withheld\n";
        if (!keep_output) std::remove(output_path.c_str());
        return false;
    }
    std::cerr << "[PVIA][sp1-sumcheck] independent Groth16 verifier PASS\n";

    receipt->available = true;
    receipt->proof_verified = true;
    receipt->production_privacy_confirmed = false;
    receipt->proof_system_id = SUMCHECK_SP1_GROTH16_SYSTEM_ID;
    receipt->proof_word_count = static_cast<size_t>(header[3]);
    receipt->statement_binding = statement_binding;
    receipt->artifact_commitment = artifact_commitment;
    receipt->kernel = context.operation.kernel;
    receipt->operation_ref = context.operation.ref;
    receipt->checkpoint = context.operation.checkpoint;
    receipt->relation_statement = context.operation.relation_statement;
    receipts_[kernel_index] = *receipt;
    receipt_valid_[kernel_index] = true;

    std::cerr << "[PVIA][sp1-sumcheck-candidate] PASS kernel="
              << static_cast<uint64_t>(context.operation.kernel)
              << " proof_words=" << receipt->proof_word_count
              << " statement_binding=" << receipt->statement_binding.hex()
              << " artifact_commitment=" << receipt->artifact_commitment.hex()
              << " artifact_path=" << (keep_output ? output_path : "temporary")
              << " privacy_confirmed=0\n";
    if (!keep_output) std::remove(output_path.c_str());
    return true;
}

} // namespace pvia
