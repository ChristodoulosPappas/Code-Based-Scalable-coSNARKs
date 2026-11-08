#include "RegistrationPublicOriginBundle.hpp"
#include "TransferAuthentication.hpp"

#include <cerrno>
#include <climits>
#include <cstdint>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace pvia {
namespace {
constexpr uint8_t MAGIC[] = {'P','V','P','A','I','R','0','1'};
constexpr size_t MAX_PUBLIC_BUNDLE_BYTES = 32768;

void put_u32(std::vector<uint8_t>* bytes, uint32_t x) {
    for (unsigned i = 0; i < 4; ++i)
        bytes->push_back(static_cast<uint8_t>(x >> (i * 8)));
}
void put_u64(std::vector<uint8_t>* bytes, uint64_t x) {
    for (unsigned i = 0; i < 8; ++i)
        bytes->push_back(static_cast<uint8_t>(x >> (i * 8)));
}
bool take_u32(const std::vector<uint8_t>& bytes, size_t* offset,
              uint32_t* result) {
    if (*offset > bytes.size() || bytes.size() - *offset < 4) return false;
    *result = 0;
    for (unsigned i = 0; i < 4; ++i)
        *result |= static_cast<uint32_t>(bytes[(*offset)++]) << (i * 8);
    return true;
}
bool take_u64(const std::vector<uint8_t>& bytes, size_t* offset,
              uint64_t* result) {
    if (*offset > bytes.size() || bytes.size() - *offset < 8) return false;
    *result = 0;
    for (unsigned i = 0; i < 8; ++i)
        *result |= static_cast<uint64_t>(bytes[(*offset)++]) << (i * 8);
    return true;
}
bool take_fixed(const std::vector<uint8_t>& bytes, size_t* offset,
                uint8_t* dest, size_t len) {
    if (*offset > bytes.size() || bytes.size() - *offset < len) return false;
    for (size_t j = 0; j < len; ++j) dest[j] = bytes[(*offset)++];
    return true;
}
Digest read_digest_words(const std::vector<u64>& words, size_t offset) {
    Digest digest;
    for (size_t j = 0; j < 4; ++j)
        for (size_t i = 0; i < 8; ++i)
            digest.bytes[j * 8 + i] =
                static_cast<uint8_t>(words[offset + j] >> (i * 8));
    return digest;
}
bool parse_statement_words(const std::vector<u64>& w,
                           RegistrationConsistencyStatement* statement) {
    if (!statement || w.size() != 46 ||
        w[3] > UINT32_MAX || w[6] > SIZE_MAX || w[7] > SIZE_MAX ||
        w[5] != static_cast<uint64_t>(AuditRelationKernel::FOLD_RS))
        return false;
    RegistrationConsistencyStatement s;
    s.sid = w[1];
    s.checkpoint = w[2];
    s.ref.owner = static_cast<uint32_t>(w[3]);
    s.ref.object_id = w[4];
    s.kernel = AuditRelationKernel::FOLD_RS;
    s.state_element_count = static_cast<size_t>(w[6]);
    s.output_element_count = static_cast<size_t>(w[7]);
    s.public_state_digest = read_digest_words(w, 8);
    s.public_actual_digest = read_digest_words(w, 12);
    s.public_challenge_binding = read_digest_words(w, 16);
    s.native_context.native_state_id = w[20];
    s.native_context.authentication_scheme_id = w[21];
    s.native_context.authentication_binding = read_digest_words(w, 22);
    s.native_context.predecessor_root = read_digest_words(w, 26);
    s.native_context.checkpoint_root = read_digest_words(w, 30);
    s.operation_statement_binding = read_digest_words(w, 34);
    s.sharing_transcript_binding = read_digest_words(w, 38);
    s.statement_binding = read_digest_words(w, 42);
    if (encode_registration_consistency_statement_words(s) != w)
        return false;
    *statement = s;
    return true;
}
bool write_full(int fd, const std::vector<uint8_t>& bytes) {
    size_t offset = 0;
    while (offset < bytes.size()) {
        const auto count =
            ::write(fd, bytes.data() + offset, bytes.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        offset += static_cast<size_t>(count);
    }
    return true;
}
bool read_entire(const std::string& filename, std::vector<uint8_t>* data) {
    const int fd = ::open(filename.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat st {};
    const bool valid = ::fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_size > 0 &&
        static_cast<uint64_t>(st.st_size) <= MAX_PUBLIC_BUNDLE_BYTES;
    if (!valid) { ::close(fd); return false; }
    data->resize(static_cast<size_t>(st.st_size));
    size_t offset = 0;
    bool ok = true;
    while (offset < data->size()) {
        const auto count =
            ::read(fd, data->data() + offset, data->size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { ok = false; break; }
        offset += static_cast<size_t>(count);
    }
    ::close(fd);
    return ok;
}

} // namespace

bool parse_registration_public_digest_hex(const std::string& hex,
                                          Digest* out) {
    if (!out || hex.size() != 64) return false;
    Digest parsed;
    for (size_t i = 0; i < 32; ++i) {
        const char a = hex[2 * i], b = hex[2 * i + 1];
        const auto nibble = [](char ch) -> int {
            if (ch >= '0' && ch <= '9') return ch - '0';
            if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
            return -1;
        };
        const int hi = nibble(a), lo = nibble(b);
        if (hi < 0 || lo < 0) return false;
        parsed.bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    if (parsed == Digest{}) return false;
    *out = parsed;
    return true;
}

bool write_registration_public_origin_bundle(
    const std::string& new_file, const RegistrationPublicOriginBundle& b) {
    const auto statement_words =
        encode_registration_consistency_statement_words(b.statement);
    const auto n = b.public_keys.size();
    const auto m = b.signatures.final_endorsements.size();
    if (new_file.empty() || statement_words.size() != 46 ||
        n < 4 || n > 64 || m == 0 || m > n ||
        b.signatures.pre_vss_receipts.size() != m ||
        !verify_registration_origin_evidence_pair(
            b.statement, b.signatures, b.public_keys,
            compute_ed25519_registry_commitment(b.public_keys),
            n - (n - 1) / 3, true))
        return false;
    std::vector<uint8_t> bytes(std::begin(MAGIC), std::end(MAGIC));
    for (uint64_t word : statement_words) put_u64(&bytes, word);
    put_u32(&bytes, static_cast<uint32_t>(n));
    put_u32(&bytes, static_cast<uint32_t>(m));
    for (const auto& key : b.public_keys)
        bytes.insert(bytes.end(), key.begin(), key.end());
    for (size_t i = 0; i < m; ++i) {
        const auto& early = b.signatures.pre_vss_receipts[i];
        const auto& final = b.signatures.final_endorsements[i];
        put_u32(&bytes, early.signer);
        bytes.insert(bytes.end(), early.signature.begin(),
                     early.signature.end());
        bytes.insert(bytes.end(), final.signature.begin(),
                     final.signature.end());
    }
    if (bytes.size() > MAX_PUBLIC_BUNDLE_BYTES) return false;
    const int fd = ::open(new_file.c_str(),
                          O_WRONLY | O_CREAT | O_EXCL |
                          O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    const bool written = write_full(fd, bytes) && ::fsync(fd) == 0;
    const bool closed = ::close(fd) == 0;
    // No overwrite; a failed partial write remains unusable.
    return written && closed;
}

bool read_registration_public_origin_statement_file(
    const std::string& file,
    RegistrationConsistencyStatement* statement) {
    if (!statement) return false;
    std::vector<uint8_t> bytes;
    if (!read_entire(file, &bytes) || bytes.size() < 8+46*8+8)
        return false;
    for (size_t i=0;i<sizeof(MAGIC);++i)
        if (bytes[i]!=MAGIC[i]) return false;
    size_t pos=sizeof(MAGIC);
    std::vector<u64> words;
    words.reserve(46);
    for (size_t i=0;i<46;++i) {
        uint64_t word=0;
        if (!take_u64(bytes,&pos,&word)) return false;
        words.push_back(word);
    }
    uint32_t n=0,m=0;
    if (!take_u32(bytes,&pos,&n) || !take_u32(bytes,&pos,&m) ||
        n<4 || n>64 || m==0 || m>n ||
        bytes.size()-pos!=
            static_cast<size_t>(n)*32+static_cast<size_t>(m)*132)
        return false;
    return parse_statement_words(words,statement);
}

bool verify_registration_public_origin_bundle_file(
    const std::string& file,
    const Digest& independently_expected_statement_binding,
    const Digest& independently_expected_registry_commitment,
    size_t minimum_distinct_signers,
    bool require_owner_signature) {
    if (independently_expected_statement_binding == Digest{} ||
        independently_expected_registry_commitment == Digest{})
        return false;
    std::vector<uint8_t> bytes;
    if (!read_entire(file, &bytes) || bytes.size() < 384)
        return false;
    for (size_t i = 0; i < sizeof(MAGIC); ++i)
        if (bytes[i] != MAGIC[i]) return false;
    size_t offset = sizeof(MAGIC);
    std::vector<u64> words;
    for (size_t i = 0; i < 46; ++i) {
        uint64_t value = 0;
        if (!take_u64(bytes, &offset, &value)) return false;
        words.push_back(value);
    }
    RegistrationPublicOriginBundle bundle;
    if (!parse_statement_words(words, &bundle.statement) ||
        bundle.statement.statement_binding !=
            independently_expected_statement_binding)
        return false;
    uint32_t n = 0, m = 0;
    if (!take_u32(bytes, &offset, &n) ||
        !take_u32(bytes, &offset, &m) ||
        n < 4 || n > 64 || m == 0 || m > n ||
        bytes.size() - offset !=
            static_cast<size_t>(n) * 32 + static_cast<size_t>(m) * 132)
        return false;
    for (uint32_t i = 0; i < n; ++i) {
        std::array<uint8_t, 32> key{};
        if (!take_fixed(bytes, &offset, key.data(), key.size())) return false;
        bundle.public_keys.push_back(key);
    }
    for (uint32_t i = 0; i < m; ++i) {
        uint32_t signer = 0;
        RegistrationPreVssReceipt early;
        RegistrationOriginEndorsement final;
        if (!take_u32(bytes, &offset, &signer) ||
            !take_fixed(bytes, &offset, early.signature.data(),
                        early.signature.size()) ||
            !take_fixed(bytes, &offset, final.signature.data(),
                        final.signature.size()))
            return false;
        early.signer = signer;
        final.signer = signer;
        bundle.signatures.pre_vss_receipts.push_back(early);
        bundle.signatures.final_endorsements.push_back(final);
    }
    // A zero CLI minimum means the strict reference n-t floor, NOT
    // a one-signer approval. Callers can require a larger quorum.
    if (minimum_distinct_signers == 0)
        minimum_distinct_signers = static_cast<size_t>(n) -
            (static_cast<size_t>(n) - 1) / 3;
    return offset == bytes.size() &&
        verify_registration_origin_evidence_pair(
            bundle.statement, bundle.signatures, bundle.public_keys,
            independently_expected_registry_commitment,
            minimum_distinct_signers, require_owner_signature);
}

} // namespace pvia
