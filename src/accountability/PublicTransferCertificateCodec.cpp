#include "PublicTransferCertificateCodec.hpp"

#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>

namespace pvia {
namespace {

constexpr u64 CERT_MAGIC = 0x5056494154434552ULL; // PVIATCER
constexpr u64 CERT_VERSION = 1;
constexpr size_t CERT_FIXED_WORDS = 71;

void append_digest(const Digest& digest, std::vector<u64>* words) {
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

Digest load_digest(const std::vector<u64>& words, size_t offset) {
    Digest digest;
    std::memcpy(digest.bytes.data(), words.data() + offset,
                digest.bytes.size());
    return digest;
}

} // namespace
std::vector<u64> encode_public_transfer_blame_certificate(
    const BlameCertificate& certificate) {
    if (!certificate.valid || certificate.debug_only ||
        certificate.evidence_kind != AuditEvidenceKind::PUBLIC_TRANSFER ||
        !certificate.predecessor_evidence.empty() ||
        !certificate.checkpoint_evidence.empty() ||
        !certificate.recovery_artifact_words.empty() ||
        certificate.public_proof_words.empty())
        return {};

    std::vector<u64> words = {
        CERT_MAGIC,
        CERT_VERSION,
        certificate.valid ? 1ULL : 0ULL,
        certificate.debug_only ? 1ULL : 0ULL,
        static_cast<u64>(certificate.evidence_kind),
        certificate.sid,
        certificate.accused,
        certificate.label.sid,
        static_cast<u64>(certificate.label.phase),
        certificate.label.round,
        certificate.label.owner,
        static_cast<u64>(certificate.label.obligation),
        certificate.label.object_id,
        certificate.checkpoint,
        static_cast<u64>(certificate.relation),
        static_cast<u64>(certificate.kernel),
        certificate.predecessor_evidence_complete ? 1ULL : 0ULL,
        certificate.public_proof_system_id
    };
    append_digest(certificate.expected, &words);
    append_digest(certificate.actual, &words);
    append_digest(certificate.residual_commitment, &words);
    append_digest(certificate.operation_statement_binding, &words);
    append_digest(certificate.dispute_binding, &words);
    append_digest(certificate.predecessor_root, &words);
    append_digest(certificate.checkpoint_root, &words);
    append_digest(certificate.audit_witness_digest, &words);
    append_digest(certificate.blame_statement_binding, &words);
    append_digest(certificate.public_proof_commitment, &words);
    append_digest(certificate.public_proof_transcript_binding, &words);
    append_digest(certificate.transcript_digest, &words);
    append_digest(certificate.proof_digest, &words);
    words.push_back(static_cast<u64>(certificate.public_proof_words.size()));
    words.insert(words.end(), certificate.public_proof_words.begin(),
                 certificate.public_proof_words.end());
    return words;
}

bool decode_public_transfer_blame_certificate(
    const std::vector<u64>& words,
    BlameCertificate* certificate) {
    if (!certificate || words.size() < CERT_FIXED_WORDS ||
        words[0] != CERT_MAGIC || words[1] != CERT_VERSION)
        return false;
    const size_t proof_words = static_cast<size_t>(words[70]);
    if (proof_words == 0 || words.size() != CERT_FIXED_WORDS + proof_words)
        return false;
    BlameCertificate out;
    out.valid = words[2] != 0;
    out.debug_only = words[3] != 0;
    out.evidence_kind = static_cast<AuditEvidenceKind>(
        static_cast<uint32_t>(words[4]));
    out.sid = words[5];
    out.accused = static_cast<uint32_t>(words[6]);
    out.label.sid = words[7];
    out.label.phase = static_cast<Phase>(static_cast<uint32_t>(words[8]));
    out.label.round = static_cast<uint32_t>(words[9]);
    out.label.owner = static_cast<uint32_t>(words[10]);
    out.label.obligation = static_cast<Obligation>(static_cast<uint32_t>(words[11]));
    out.label.object_id = words[12];
    out.checkpoint = words[13];
    out.relation = static_cast<RelationKind>(static_cast<uint32_t>(words[14]));
    out.kernel = static_cast<AuditRelationKernel>(static_cast<uint32_t>(words[15]));
    out.predecessor_evidence_complete = words[16] != 0;
    out.public_proof_system_id = static_cast<uint32_t>(words[17]);
    out.expected = load_digest(words, 18);
    out.actual = load_digest(words, 22);
    out.residual_commitment = load_digest(words, 26);
    out.operation_statement_binding = load_digest(words, 30);
    out.dispute_binding = load_digest(words, 34);
    out.predecessor_root = load_digest(words, 38);
    out.checkpoint_root = load_digest(words, 42);
    out.audit_witness_digest = load_digest(words, 46);
    out.blame_statement_binding = load_digest(words, 50);
    out.public_proof_commitment = load_digest(words, 54);
    out.public_proof_transcript_binding = load_digest(words, 58);
    out.transcript_digest = load_digest(words, 62);
    out.proof_digest = load_digest(words, 66);
    out.public_proof_words.assign(words.begin() + CERT_FIXED_WORDS,
                                  words.end());

    if (!out.valid || out.debug_only ||
        out.evidence_kind != AuditEvidenceKind::PUBLIC_TRANSFER ||
        out.sid == 0 || out.label.sid != out.sid ||
        out.accused != out.label.owner ||
        out.label.obligation != Obligation::SEND ||
        out.relation != RelationKind::MESSAGE_BINDING ||
        out.kernel != AuditRelationKernel::UNKNOWN ||
        out.predecessor_root != Digest{} ||
        out.public_proof_system_id == 0 ||
        out.public_proof_commitment == Digest{} ||
        out.public_proof_transcript_binding == Digest{})
        return false;
    *certificate = out;
    return true;
}

bool write_public_transfer_blame_certificate_file(
    const std::string& path, const BlameCertificate& certificate) {
    if (path.empty()) return false;
    const std::vector<u64> words =
        encode_public_transfer_blame_certificate(certificate);
    if (words.empty()) return false;
    std::ofstream output(path, std::ios::out | std::ios::trunc);
    if (!output) return false;
    output << "PVIA_TRANSFER_CERT_V1\n" << words.size() << "\n";
    output << std::hex << std::setfill('0');
    for (u64 word : words)
        output << std::setw(16) << word << "\n";
    return output.good();
}

bool read_public_transfer_blame_certificate_file(
    const std::string& path, std::vector<u64>* encoded_certificate) {
    if (!encoded_certificate || path.empty()) return false;
    std::ifstream input(path);
    if (!input) return false;
    std::string line;
    if (!std::getline(input, line) || line != "PVIA_TRANSFER_CERT_V1")
        return false;
    if (!std::getline(input, line)) return false;
    size_t pos = 0;
    unsigned long long count = 0;
    try { count = std::stoull(line, &pos, 10); } catch (...) { return false; }
    if (pos != line.size() || count == 0 || count > (1ULL << 20))
        return false;
    std::vector<u64> words;
    words.reserve(static_cast<size_t>(count));
    for (unsigned long long i = 0; i < count; ++i) {
        if (!std::getline(input, line) || line.size() != 16) return false;
        pos = 0;
        unsigned long long word = 0;
        try { word = std::stoull(line, &pos, 16); } catch (...) { return false; }
        if (pos != line.size()) return false;
        words.push_back(static_cast<u64>(word));
    }
    while (std::getline(input, line))
        if (!line.empty()) return false;
    BlameCertificate decoded;
    if (!decode_public_transfer_blame_certificate(words, &decoded))
        return false;
    *encoded_certificate = std::move(words);
    return true;
}

bool parse_public_transfer_registry_anchor_hex(
    const std::string& text, Digest* anchor) {
    if (!anchor || text.size() != 64) return false;
    Digest out;
    for (size_t i = 0; i < out.bytes.size(); ++i) {
        const auto hex = [](char ch) -> int {
            if (ch >= '0' && ch <= '9') return ch - '0';
            if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
            if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
            return -1;
        };
        const int hi = hex(text[2 * i]);
        const int lo = hex(text[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    if (out == Digest{}) return false;
    *anchor = out;
    return true;
}

} // namespace pvia
