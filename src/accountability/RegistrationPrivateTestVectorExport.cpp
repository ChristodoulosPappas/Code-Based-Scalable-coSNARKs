#include "RegistrationPrivateTestVectorExport.hpp"

#include <cerrno>
#include <fcntl.h>
#include <sstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace pvia {
namespace {
void add_json_array(std::ostringstream& out, const char* key,
                    const std::vector<u64>& values, bool final) {
    out << '"' << key << "\":[";
    for (size_t i = 0; i < values.size(); ++i) {
        if (i) out << ',';
        out << values[i];
    }
    out << (final ? "]" : "],");
}
bool secure_write_new_file(const std::string& path, const std::string& data) {
    if (path.empty() || data.size() > 32 * 1024 * 1024) return false;
    const int fd = ::open(path.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    size_t off = 0;
    bool ok = true;
    while (off < data.size()) {
        const auto n = ::write(fd, data.data() + off, data.size() - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = false; break; }
        off += static_cast<size_t>(n);
    }
    ok = ok && ::fsync(fd) == 0;
    const bool closed = ::close(fd) == 0;
    // Failed/partial files remain reserved: never unlink in a verifier.
    return ok && closed;
}
} // namespace

bool write_registration_private_test_vector_once(
    const std::string& new_owner_only_path,
    const RegistrationConsistencyStatement& statement,
    const RegistrationConsistencyWitness& witness) {
    const auto public_statement =
        encode_registration_consistency_statement_words(statement);
    if (public_statement.size() != 46 ||
        !evaluate_reference_registration_consistency_relation(
            statement, witness))
        return false;
    std::vector<u64> state_words, output_words;
    state_words.reserve(witness.state_values.size() * 2);
    output_words.reserve(witness.actual_output.size() * 2);
    for (const auto& value : witness.state_values) {
        state_words.push_back(value.real);
        state_words.push_back(value.img);
    }
    for (const auto& value : witness.actual_output) {
        output_words.push_back(value.real);
        output_words.push_back(value.img);
    }
    std::ostringstream json;
    json << "{\"abi_version\":1,";
    add_json_array(json,"statement_words",public_statement,false);
    json << "\"public_challenge_words\":["
         << witness.public_challenge.real << ","
         << witness.public_challenge.img << "],";
    add_json_array(json,"native_state_words",state_words,false);
    add_json_array(json,"actual_output_words",output_words,false);
    add_json_array(json,"vss_dealer_witness_words",
                   witness.sharing_witness_words,true);
    json << "}\n";
    return secure_write_new_file(new_owner_only_path,json.str());
}
} // namespace pvia
