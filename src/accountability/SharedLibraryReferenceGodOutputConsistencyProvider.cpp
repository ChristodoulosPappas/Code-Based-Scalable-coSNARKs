#include "SharedLibraryReferenceGodOutputConsistencyProvider.hpp"

#include <dlfcn.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <sstream>
#include <limits>
#include <utility>
#include <vector>

namespace pvia {
namespace {
constexpr size_t MAX_PROVIDER_WORDS = 1ULL << 20;
constexpr size_t PROOF_HEADER_WORDS = 17;

template <typename Fn>
Fn load_symbol(void* handle, const char* name) {
    return reinterpret_cast<Fn>(dlsym(handle, name));
}

template <typename Word>
void append_digest_words(const Digest& digest, std::vector<Word>* words) {
    if (!words) return;
    for (size_t i=0;i<4;++i) {
        Word word=0;
        for(size_t j=0;j<8;++j)
            word|=static_cast<Word>(digest.bytes[8*i+j])<<(8*j);
        words->push_back(word);
    }
}

template <typename Word>
Digest digest_from_words(const Word* words) {
    Digest digest{};
    if(!words)return digest;
    for(size_t i=0;i<4;++i)for(size_t j=0;j<8;++j)
        digest.bytes[8*i+j]=static_cast<uint8_t>((words[i]>>(8*j))&0xffU);
    return digest;
}

bool read_word_file(const std::string& path,std::vector<uint64_t>* words) {
    if(!words)return false;
    std::ifstream file(path);if(!file)return false;
    std::string line;if(!std::getline(file,line))return false;
    if(line.rfind("words=",0)==0)line.erase(0,6);
    std::stringstream stream(line);std::string token;
    std::vector<uint64_t> parsed;
    try {
        while(std::getline(stream,token,',')) {
            if(token.empty())continue;
            size_t consumed=0;const auto value=std::stoull(token,&consumed);
            if(consumed!=token.size())return false;
            parsed.push_back(static_cast<uint64_t>(value));
        }
    } catch(...) {return false;}
    if(parsed.empty())return false;
    *words=std::move(parsed);return true;
}

} // namespace

SharedLibraryReferenceGodOutputConsistencyProvider::
SharedLibraryReferenceGodOutputConsistencyProvider(
    std::string library_path,
    ReferenceGodOutputConsistencyCapabilities accepted_capabilities,
    uint32_t expected_proof_system_id,
    ExternalAnchorVerifier verify_external_anchor)
    : library_path_(std::move(library_path)),
      accepted_capabilities_(std::move(accepted_capabilities)),
      expected_proof_system_id_(expected_proof_system_id),
      verify_external_anchor_(std::move(verify_external_anchor)) {}

SharedLibraryReferenceGodOutputConsistencyProvider::
~SharedLibraryReferenceGodOutputConsistencyProvider() {
    Reset();
}

bool SharedLibraryReferenceGodOutputConsistencyProvider::QueryCapabilities(
    const std::string& library_path,
    ReferenceGodOutputConsistencyCapabilities* capabilities,
    std::string* error_message) {
    if(capabilities)*capabilities=ReferenceGodOutputConsistencyCapabilities{};
    if(error_message)error_message->clear();
    if(!capabilities||library_path.empty()) {
        if(error_message)*error_message="provider path or capability output is missing";
        return false;
    }
    void* handle=dlopen(library_path.c_str(),RTLD_NOW|RTLD_LOCAL);
    if(!handle) {
        const char* detail=dlerror();
        if(error_message)*error_message=detail?detail:"unable to load output provider";
        return false;
    }
    auto version=load_symbol<VersionFn>(handle,
        PVIA_GOD_OUTPUT_PROVIDER_ABI_VERSION_SYMBOL);
    auto query=load_symbol<CapabilitiesFn>(handle,
        PVIA_GOD_OUTPUT_PROVIDER_ABI_CAPABILITIES_SYMBOL);
    bool ok=false;
    if(!version||!query||version()!=PVIA_GOD_OUTPUT_PROVIDER_ABI_VERSION) {
        if(error_message)*error_message="provider ABI version/capability symbols are invalid";
    } else {
        size_t count=0;
        if(query(nullptr,&count)!=1||
           count!=PVIA_GOD_OUTPUT_PROVIDER_CAPABILITY_ABI_WORDS) {
            if(error_message)*error_message="provider capability size query failed";
        } else {
            std::vector<uint64_t> words(count);size_t actual=count;
            SharedLibraryReferenceGodOutputConsistencyProvider decoder(
                library_path,ReferenceGodOutputConsistencyCapabilities{},1,{});
            if(query(words.data(),&actual)==1&&actual==count&&
               decoder.DecodeProviderCapabilities(words,capabilities)) {
                ok=true;
            } else if(error_message) {
                *error_message="provider capability ABI validation failed";
            }
        }
    }
    dlclose(handle);
    return ok;
}

bool SharedLibraryReferenceGodOutputConsistencyProvider::
DecodeProviderCapabilities(
    const std::vector<uint64_t>& words,
    ReferenceGodOutputConsistencyCapabilities* capabilities) const {
    if(!capabilities||words.size()!=PVIA_GOD_OUTPUT_PROVIDER_CAPABILITY_ABI_WORDS||
       words[0]!=PVIA_GOD_OUTPUT_PROVIDER_CAPABILITY_ABI_DOMAIN||
       words[1]!=PVIA_GOD_OUTPUT_PROVIDER_ABI_VERSION)return false;
    for(size_t i=2;i<=8;++i)if(words[i]>1)return false;
    ReferenceGodOutputConsistencyCapabilities result;
    result.available=words[2]!=0;
    result.malicious_sound=words[3]!=0;
    result.zero_knowledge=words[4]!=0;
    result.binds_output_values=words[5]!=0;
    result.binds_multiplication_proof_set=words[6]!=0;
    result.binds_scope_and_session=words[7]!=0;
    result.external_registry_anchor_verified=words[8]!=0;
    result.protocol_id=words[9];
    result.external_registry_anchor=digest_from_words(words.data()+10);
    result.relation_binding=digest_from_words(words.data()+14);
    result.implementation_binding=digest_from_words(words.data()+18);
    result.capability_binding=digest_from_words(words.data()+22);
    if(!validate_reference_god_output_consistency_capabilities(result))return false;
    *capabilities=result;
    return true;
}

bool SharedLibraryReferenceGodOutputConsistencyProvider::VerifyProviderIdentity() {
    provider_identity_verified_=false;
    if(!validate_reference_god_output_consistency_capabilities(accepted_capabilities_)||
       !production_ready_reference_god_output_consistency_capabilities(accepted_capabilities_)||
       !verify_external_anchor_) {
        error_="accepted output-provider capabilities or external anchor verifier are missing";
        return false;
    }
    const bool matching=provider_capabilities_.available==accepted_capabilities_.available&&
        provider_capabilities_.malicious_sound==accepted_capabilities_.malicious_sound&&
        provider_capabilities_.zero_knowledge==accepted_capabilities_.zero_knowledge&&
        provider_capabilities_.binds_output_values==accepted_capabilities_.binds_output_values&&
        provider_capabilities_.binds_multiplication_proof_set==
            accepted_capabilities_.binds_multiplication_proof_set&&
        provider_capabilities_.binds_scope_and_session==
            accepted_capabilities_.binds_scope_and_session&&
        provider_capabilities_.protocol_id==accepted_capabilities_.protocol_id&&
        provider_capabilities_.relation_binding==accepted_capabilities_.relation_binding&&
        provider_capabilities_.implementation_binding==accepted_capabilities_.implementation_binding&&
        accepted_capabilities_.external_registry_anchor_verified&&
        accepted_capabilities_.external_registry_anchor!=Digest{}&&
        accepted_capabilities_.capability_binding==
            compute_reference_god_output_consistency_capability_binding(
                accepted_capabilities_);
    if(!matching) {
        error_="loaded provider identity does not match externally accepted capabilities";
        return false;
    }
    if(!verify_external_anchor_(accepted_capabilities_)) {
        error_="external output-provider anchor verification failed";
        return false;
    }
    provider_identity_verified_=true;
    return true;
}

bool SharedLibraryReferenceGodOutputConsistencyProvider::Load() {
    if(loaded())return true;
    Reset();
    if(library_path_.empty()||expected_proof_system_id_==0) {
        error_="provider path or proof-system id is missing";return false;
    }
    handle_=dlopen(library_path_.c_str(),RTLD_NOW|RTLD_LOCAL);
    if(!handle_) {
        const char* detail=dlerror();error_=detail?detail:"unable to load output provider";
        Close();return false;
    }
    version_fn_=load_symbol<VersionFn>(handle_,PVIA_GOD_OUTPUT_PROVIDER_ABI_VERSION_SYMBOL);
    capabilities_fn_=load_symbol<CapabilitiesFn>(handle_,PVIA_GOD_OUTPUT_PROVIDER_ABI_CAPABILITIES_SYMBOL);
    prove_fn_=load_symbol<ProveFn>(handle_,PVIA_GOD_OUTPUT_PROVIDER_ABI_PROVE_SYMBOL);
    verify_fn_=load_symbol<VerifyFn>(handle_,PVIA_GOD_OUTPUT_PROVIDER_ABI_VERIFY_SYMBOL);
    last_error_fn_=load_symbol<LastErrorFn>(handle_,PVIA_GOD_OUTPUT_PROVIDER_ABI_LAST_ERROR_SYMBOL);
    if(!version_fn_||!capabilities_fn_||!prove_fn_||!verify_fn_||!last_error_fn_) {
        error_="provider library is missing required output-proof ABI symbols";Close();return false;
    }
    if(version_fn_()!=PVIA_GOD_OUTPUT_PROVIDER_ABI_VERSION) {
        error_="output provider ABI version mismatch";Close();return false;
    }
    size_t count=0;
    if(capabilities_fn_(nullptr,&count)!=1||
       count!=PVIA_GOD_OUTPUT_PROVIDER_CAPABILITY_ABI_WORDS) {
        error_="output provider capability size query failed";Close();return false;
    }
    std::vector<uint64_t> words(count);size_t actual=count;
    if(capabilities_fn_(words.data(),&actual)!=1||actual!=count||
       !DecodeProviderCapabilities(words,&provider_capabilities_)) {
        error_="output provider capability ABI validation failed";Close();return false;
    }
    if(!VerifyProviderIdentity()) {Close();return false;}

    ReferenceGodOutputConsistencyProviderCallbacks callbacks;
    callbacks.prove=[this](const auto& statement,const auto& witness) {
        return Prove(statement,witness);
    };
    callbacks.verify=[this](const auto& statement,const auto& proof) {
        return Verify(statement,proof);
    };
    callbacks.verify_external_anchor=[this](const auto& capabilities) {
        return provider_identity_verified_&&
            capabilities.capability_binding==accepted_capabilities_.capability_binding&&
            validate_reference_god_output_consistency_capabilities(capabilities)&&
            verify_external_anchor_&&verify_external_anchor_(capabilities);
    };
    callbacks.last_error=[this]() { return provider_operation_error_; };
    adapter_=std::make_unique<ExternalReferenceGodOutputConsistencyProofAdapter>(
        accepted_capabilities_,expected_proof_system_id_,std::move(callbacks));
    if(!adapter_->ready()) {
        error_="external output-proof adapter rejected provider: "+adapter_->last_error();
        adapter_.reset();Close();return false;
    }
    error_.clear();return true;
}

bool SharedLibraryReferenceGodOutputConsistencyProvider::CollectiveProviderAgreement(
    int rank,int world_size,MPI_Comm comm) const {
    if(!loaded()||rank<0||world_size<=0||rank>=world_size)return false;
    std::vector<u64> local={PVIA_GOD_OUTPUT_PROVIDER_ABI_VERSION,
        expected_proof_system_id_,accepted_capabilities_.protocol_id};
    append_digest_words(accepted_capabilities_.capability_binding,&local);
    append_digest_words(accepted_capabilities_.relation_binding,&local);
    append_digest_words(accepted_capabilities_.implementation_binding,&local);
    append_digest_words(accepted_capabilities_.external_registry_anchor,&local);
    std::vector<u64> gathered(local.size()*static_cast<size_t>(world_size),0);
    MPI_Allgather(local.data(),static_cast<int>(local.size()),MPI_UINT64_T,
        gathered.data(),static_cast<int>(local.size()),MPI_UINT64_T,comm);
    for(int participant=1;participant<world_size;++participant) {
        const size_t offset=static_cast<size_t>(participant)*local.size();
        for(size_t i=0;i<local.size();++i)if(gathered[offset+i]!=local[i])return false;
    }
    return true;
}

bool SharedLibraryReferenceGodOutputConsistencyProvider::Activate(
    int rank,int world_size,MPI_Comm comm) {
    int local_loaded=Load()?1:0,all_loaded=0;
    MPI_Allreduce(&local_loaded,&all_loaded,1,MPI_INT,MPI_MIN,comm);
    if(!all_loaded)return false;
    if(!CollectiveProviderAgreement(rank,world_size,comm)) {
        error_="externally accepted output-provider identity differs across participants";
        return false;
    }
    registration_=std::make_unique<ScopedReferenceGodOutputConsistencyBackendRegistration>(
        adapter_.get());
    int local_active=registration_->active()?1:0,all_active=0;
    MPI_Allreduce(&local_active,&all_active,1,MPI_INT,MPI_MIN,comm);
    if(!all_active) {
        registration_.reset();error_="output provider backend registration failed collectively";
        return false;
    }
    error_.clear();return true;
}

ReferenceGodOutputConsistencyProofArtifact
SharedLibraryReferenceGodOutputConsistencyProvider::Prove(
    const ReferenceGodOutputConsistencyStatement& statement,
    const std::vector<u64>& provider_witness_words) const {
    provider_operation_error_.clear();
    ReferenceGodOutputConsistencyProofArtifact proof;
    if(!prove_fn_||!validate_reference_god_output_consistency_statement(statement)||
       provider_witness_words.empty()||provider_witness_words.size()>MAX_PROVIDER_WORDS) {
        provider_operation_error_="output statement/witness preflight failed";return proof;
    }
    const auto encoded_statement=encode_reference_god_output_consistency_statement_abi(statement);
    if(encoded_statement.empty()) {provider_operation_error_="statement ABI encoding failed";return proof;}
    const std::vector<uint64_t> statement_words(encoded_statement.begin(),encoded_statement.end());
    const std::vector<uint64_t> witness_words(provider_witness_words.begin(),provider_witness_words.end());
    size_t count=0;
    if(prove_fn_(statement_words.data(),statement_words.size(),
        witness_words.data(),witness_words.size(),nullptr,&count)!=1||
       count<PROOF_HEADER_WORDS||count>MAX_PROVIDER_WORDS) {
        provider_operation_error_=ProviderLastError();if(provider_operation_error_.empty())
            provider_operation_error_="provider proof-size query failed";return proof;
    }
    std::vector<uint64_t> words(count);size_t actual=count;
    if(prove_fn_(statement_words.data(),statement_words.size(),
        witness_words.data(),witness_words.size(),words.data(),&actual)!=1||
       actual!=count||words.size()<PROOF_HEADER_WORDS||words[0]!=1||words[1]!=1||
       words[2]!=1||words[3]!=expected_proof_system_id_||words[16]!=words.size()-PROOF_HEADER_WORDS) {
        provider_operation_error_=ProviderLastError();if(provider_operation_error_.empty())
            provider_operation_error_="provider returned a malformed output proof artifact";return proof;
    }
    proof.available=true;proof.cryptographically_authenticated=true;proof.zero_knowledge=true;
    proof.proof_system_id=static_cast<uint32_t>(words[3]);
    proof.statement_binding=digest_from_words(words.data()+4);
    proof.transcript_binding=digest_from_words(words.data()+8);
    proof.proof_commitment=digest_from_words(words.data()+12);
    proof.proof_words.assign(words.begin()+PROOF_HEADER_WORDS,words.end());
    if(!validate_reference_god_output_consistency_proof(statement,proof)) {
        provider_operation_error_="provider proof artifact failed C++ canonical validation";return {};
    }
    return proof;
}

bool SharedLibraryReferenceGodOutputConsistencyProvider::Verify(
    const ReferenceGodOutputConsistencyStatement& statement,
    const ReferenceGodOutputConsistencyProofArtifact& proof) const {
    provider_operation_error_.clear();
    if(!verify_fn_||!validate_reference_god_output_consistency_statement(statement)||
       !validate_reference_god_output_consistency_proof(statement,proof)) {
        provider_operation_error_="output proof failed C++ verification preflight";return false;
    }
    const auto encoded_statement=encode_reference_god_output_consistency_statement_abi(statement);
    if(encoded_statement.empty()) {provider_operation_error_="statement ABI encoding failed";return false;}
    const std::vector<uint64_t> statement_words(encoded_statement.begin(),encoded_statement.end());
    std::vector<uint64_t> words={proof.available?1ULL:0ULL,
        proof.cryptographically_authenticated?1ULL:0ULL,
        proof.zero_knowledge?1ULL:0ULL,proof.proof_system_id};
    append_digest_words(proof.statement_binding,&words);
    append_digest_words(proof.transcript_binding,&words);
    append_digest_words(proof.proof_commitment,&words);
    words.push_back(static_cast<u64>(proof.proof_words.size()));
    words.insert(words.end(),proof.proof_words.begin(),proof.proof_words.end());
    const int32_t result=verify_fn_(statement_words.data(),statement_words.size(),
        words.data(),words.size());
    if(result!=1) {
        provider_operation_error_=ProviderLastError();
        if(provider_operation_error_.empty())provider_operation_error_="SP1 output proof verification failed";
        return false;
    }
    return true;
}

std::string SharedLibraryReferenceGodOutputConsistencyProvider::ProviderLastError() const {
    if(!last_error_fn_)return {};
    size_t count=0;
    const size_t queried=last_error_fn_(nullptr,&count);
    if(queried==0||count==0||count>4096)return {};
    std::vector<uint8_t> bytes(count,0);size_t actual=count;
    if(last_error_fn_(bytes.data(),&actual)==0||actual==0||actual>bytes.size())return {};
    return std::string(reinterpret_cast<const char*>(bytes.data()));
}

void SharedLibraryReferenceGodOutputConsistencyProvider::Reset() {
    registration_.reset();adapter_.reset();Close();
}

void SharedLibraryReferenceGodOutputConsistencyProvider::Close() {
    provider_identity_verified_=false;
    version_fn_=nullptr;capabilities_fn_=nullptr;prove_fn_=nullptr;
    verify_fn_=nullptr;last_error_fn_=nullptr;
    if(handle_){dlclose(handle_);handle_=nullptr;}
}

bool run_reference_god_output_provider_abi_selftest(
    const std::string& library_path, std::string* result_message) {
    ReferenceGodOutputConsistencyCapabilities unanchored;
    SharedLibraryReferenceGodOutputConsistencyProvider provider(
        library_path,unanchored,68102,
        [](const ReferenceGodOutputConsistencyCapabilities&) { return true; });
    const bool unexpectedly_loaded=provider.Load();
    const bool rejected_for_missing_anchor=!unexpectedly_loaded&&
        provider.error().find("accepted output-provider capabilities")!=std::string::npos;
    if(result_message) {
        *result_message=rejected_for_missing_anchor
            ? "capability ABI matched; unanchored provider rejected as required"
            : "provider capability ABI mismatch or missing-anchor rejection failed: "+provider.error();
    }
    provider.Reset();
    return rejected_for_missing_anchor;
}

bool run_reference_god_output_provider_artifact_selftest(
    const std::string& statement_words_path,
    const std::string& witness_words_path,
    const std::string& proof_artifact_words_path,
    std::string* result_message) {
    std::vector<uint64_t> statement_words,witness_words,artifact_words;
    if(!read_word_file(statement_words_path,&statement_words)||
       !read_word_file(witness_words_path,&witness_words)||
       !read_word_file(proof_artifact_words_path,&artifact_words)) {
        if(result_message)*result_message="statement/witness/proof word file could not be parsed";
        return false;
    }
    ReferenceGodOutputConsistencyStatement statement;
    ReferenceGodOutputConsistencyWitness witness;
    if(!decode_reference_god_output_consistency_statement_abi(
           statement_words,&statement)||
       !decode_reference_god_output_consistency_witness_abi(
           statement,witness_words,&witness)||artifact_words.size()<PROOF_HEADER_WORDS||
       artifact_words[0]!=1||artifact_words[1]!=1||artifact_words[2]!=1||
       artifact_words[3]>std::numeric_limits<uint32_t>::max()||
       artifact_words[16]!=artifact_words.size()-PROOF_HEADER_WORDS) {
        if(result_message)*result_message="canonical statement/proof artifact ABI rejected";
        return false;
    }
    ReferenceGodOutputConsistencyProofArtifact proof;
    proof.available=true;proof.cryptographically_authenticated=true;
    proof.zero_knowledge=true;proof.proof_system_id=static_cast<uint32_t>(artifact_words[3]);
    proof.statement_binding=digest_from_words(artifact_words.data()+4);
    proof.transcript_binding=digest_from_words(artifact_words.data()+8);
    proof.proof_commitment=digest_from_words(artifact_words.data()+12);
    proof.proof_words.assign(artifact_words.begin()+PROOF_HEADER_WORDS,artifact_words.end());
    if(!validate_reference_god_output_consistency_proof(statement,proof)) {
        if(result_message)*result_message="C++ proof commitment validation failed";
        return false;
    }
    auto tampered=proof;
    if(tampered.proof_words.empty()) {
        if(result_message)*result_message="proof payload is empty";return false;
    }
    tampered.proof_words[0]^=1ULL;
    if(validate_reference_god_output_consistency_proof(statement,tampered)) {
        if(result_message)*result_message="tampered provider proof payload was accepted";
        return false;
    }
    if(result_message)*result_message=
        "cross-language statement/witness ABI and proof commitment PASS; payload tampering rejected";
    return true;
}

} // namespace pvia
