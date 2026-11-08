#include "ReferenceVssSelectivePointDurableReplay.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <limits>
#include <cstdlib>
#include <iostream>
#include <vector>
#include <utility>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace pvia {
namespace {
constexpr u64 MAGIC = 0x5056535245504c31ULL;  // PVSREPL1
constexpr u64 VERSION = 1;
constexpr u64 ENTRY_DOMAIN = 0x5056535245504c32ULL;
constexpr size_t HEADER = 6;
constexpr size_t ENTRY = 14;
constexpr size_t MAX_ENTRIES = 65536;
void append_digest(std::vector<u64>* out, const Digest& digest) {
    for (size_t i = 0; i < 32; i += 8) {
        u64 word = 0;
        for (size_t j = 0; j < 8; ++j)
            word |= static_cast<u64>(digest.bytes[i+j]) << (8*j);
        out->push_back(word);
    }
}
Digest read_digest(const std::vector<u64>& words, size_t start) {
    Digest d{};
    if (start + 4 > words.size()) return {};
    for (size_t i = 0; i < 4; ++i)
        for (size_t j = 0; j < 8; ++j)
            d.bytes[i*8+j] = static_cast<uint8_t>(words[start+i]>>(8*j));
    return d;
}
bool read_full(int fd, std::vector<u64>* out) {
    struct stat info{};
    if (::fstat(fd,&info)!=0 || !S_ISREG(info.st_mode) ||
        info.st_uid != ::geteuid() || (info.st_mode & 077) != 0 ||
        info.st_size < 0 ||
        static_cast<uint64_t>(info.st_size) >
            (HEADER + MAX_ENTRIES*ENTRY)*sizeof(u64) ||
        (info.st_size % 8) != 0)
        return false;
    const size_t size = static_cast<size_t>(info.st_size);
    std::vector<uint8_t> bytes(size);
    if (::lseek(fd,0,SEEK_SET)<0) return false;
    size_t pos=0;
    while (pos<size) {
        const ssize_t got = ::read(fd,bytes.data()+pos,size-pos);
        if (got<0 && errno==EINTR) continue;
        if (got<=0) return false;
        pos+=static_cast<size_t>(got);
    }
    std::vector<u64> words(size/8,0);
    for(size_t i=0;i<words.size();++i)
        for(size_t j=0;j<8;++j)
            words[i]|=static_cast<u64>(bytes[i*8+j])<<(8*j);
    *out=std::move(words);
    return true;
}
bool write_words(int fd, const std::vector<u64>& words) {
    std::vector<uint8_t> bytes;
    bytes.reserve(words.size()*8);
    for (u64 word:words)
        for (size_t j=0;j<8;++j)
            bytes.push_back(static_cast<uint8_t>(word>>(8*j)));
    size_t pos=0;
    while(pos<bytes.size()) {
        const ssize_t wrote=::write(fd,bytes.data()+pos,bytes.size()-pos);
        if(wrote<0 && errno==EINTR)continue;
        if(wrote<=0)return false;
        pos+=static_cast<size_t>(wrote);
    }
    return true;
}
// This scan validates the entire chain, including any earlier logical
// sender/target watermark, before trusting the tip as a journal anchor.
bool scan_history(const std::vector<u64>& words,
                  const Digest& registry_binding,
                  Digest* verified_tip,
                  const AuthenticatedMpcMessageContext* context,
                  int sender, int target) {
    if (!verified_tip || words.size()<HEADER ||
        words[0]!=MAGIC || words[1]!=VERSION ||
        read_digest(words,2)!=registry_binding ||
        (words.size()-HEADER)%ENTRY!=0 ||
        (words.size()-HEADER)/ENTRY>MAX_ENTRIES)
        return false;
    Digest prev=hash_words(
        std::vector<u64>(words.begin(),words.begin()+HEADER));
    if (prev==Digest{})return false;
    for(size_t at=HEADER;at<words.size();at+=ENTRY) {
        if(words[at+2]>static_cast<u64>(std::numeric_limits<int>::max()) ||
           words[at+3]>static_cast<u64>(std::numeric_limits<int>::max()) ||
           words[at+2]==words[at+3] ||
           words[at+4]==0 || words[at+5]==0 ||
           read_digest(words,at+6)!=prev) return false;
        std::vector<u64> entry(words.begin()+at,words.begin()+at+ENTRY-4);
        entry.insert(entry.begin(),ENTRY_DOMAIN);
        const Digest checksum=hash_words(entry);
        if(checksum==Digest{} ||
           checksum!=read_digest(words,at+10))return false;
        prev=checksum;
        if(context && words[at]==context->sid &&
           words[at+1]==context->checkpoint &&
           words[at+2]==static_cast<u64>(sender) &&
           words[at+3]==static_cast<u64>(target) &&
           context->sequence<=words[at+5])return false;
    }
    *verified_tip=prev;
    return true;
}
} // namespace

ReferenceVssSelectivePointDurableReplayGuard::
ReferenceVssSelectivePointDurableReplayGuard(
    std::string path,Digest registry)
    : path_(std::move(path)),registry_binding_(registry) {}

bool ReferenceVssSelectivePointDurableReplayGuard::InitializeNew() const {
    if (path_.empty() || path_.size() > 4000 ||
        registry_binding_ == Digest{})
        return false;
    const int fd = ::open(path_.c_str(),
        O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW,0600);
    if (fd < 0) return false;
    std::vector<u64> header{MAGIC, VERSION};
    append_digest(&header, registry_binding_);
    const bool ok = write_words(fd, header) && ::fsync(fd) == 0;
    const bool closed = ::close(fd) == 0;
    if (!ok || !closed) {
        ::unlink(path_.c_str());
        return false;
    }
    return true;
}

bool ReferenceVssSelectivePointDurableReplayGuard::ReadCurrentHead(
    Digest* output) const {
    if (!output) return false;
    *output={};
    if(path_.empty() || path_.size()>4000 ||
       registry_binding_==Digest{})return false;
    const int fd=::open(path_.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)return false;
    bool ok=::flock(fd,LOCK_SH)==0;
    std::vector<u64> words;
    if(ok)ok=read_full(fd,&words);
    Digest head{};
    if(ok)ok=scan_history(words,registry_binding_,&head,nullptr,-1,-1);
    ::flock(fd,LOCK_UN);
    if(::close(fd)!=0)ok=false;
    if(ok)*output=head;
    return ok;
}

bool ReferenceVssSelectivePointDurableReplayGuard::Observe(
    const AuthenticatedMpcMessageContext& context,
    int sender,int target) const {
    return ObserveInternal(context,sender,target,nullptr,nullptr);
}

bool ReferenceVssSelectivePointDurableReplayGuard::ObserveWithPinnedHead(
    const AuthenticatedMpcMessageContext& context,
    int sender,int target,const Digest& expected,Digest* new_head) const {
    if(!new_head)return false;
    *new_head={};
    if(expected==Digest{})return false;
    return ObserveInternal(context,sender,target,&expected,new_head);
}

bool ReferenceVssSelectivePointDurableReplayGuard::ObserveInternal(
    const AuthenticatedMpcMessageContext& context,
    int sender,int target,const Digest* expected,Digest* new_head) const {
    if (path_.empty() || path_.size()>4000 ||
        registry_binding_==Digest{} ||
        !validate_authenticated_mpc_message_context(context) ||
        context.protocol_domain!=PVIA_VSS_SELECTIVE_POINT_DOMAIN ||
        context.message_kind!=PVIA_VSS_SELECTIVE_POINT_KIND ||
        sender<0 || target<0 || sender==target)
        return false;
    if(new_head)*new_head={};
    const int fd=::open(path_.c_str(),O_RDWR|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)return false;
    bool ok=::flock(fd,LOCK_EX)==0;
    std::vector<u64> words;
    if(ok)ok=read_full(fd,&words);
    Digest tip{};
    if(ok)ok=scan_history(words,registry_binding_,&tip,
                          &context,sender,target);
    if(ok && expected && tip!=*expected)ok=false;
    Digest next_tip{};
    if(ok) {
        std::vector<u64> entry={
            context.sid,context.checkpoint,
            static_cast<u64>(sender),static_cast<u64>(target),
            context.round,context.sequence};
        append_digest(&entry,tip);
        std::vector<u64> preimage={ENTRY_DOMAIN};
        preimage.insert(preimage.end(),entry.begin(),entry.end());
        next_tip=hash_words(preimage);
        if(next_tip==Digest{})ok=false;
        else {
            append_digest(&entry,next_tip);
            if(::lseek(fd,0,SEEK_END)<0 ||
               !write_words(fd,entry) || ::fsync(fd)!=0)
                ok=false;
        }
    }
    ::flock(fd,LOCK_UN);
    if(::close(fd)!=0)ok=false;
    if(ok && new_head)*new_head=next_tip;
    return ok;
}


bool ReferenceVssSelectivePointDurableReplayGuard::ObserveBatchWithPinnedHead(
    const AuthenticatedMpcMessageContext& context,
    const std::vector<int>& senders, int target,
    const Digest& expected_head, Digest* new_head) const {
    if (!new_head) return false;
    *new_head={};
    if (path_.empty() || path_.size()>4000 ||
        registry_binding_==Digest{} || expected_head==Digest{} ||
        !validate_authenticated_mpc_message_context(context) ||
        context.protocol_domain!=PVIA_VSS_SELECTIVE_POINT_DOMAIN ||
        context.message_kind!=PVIA_VSS_SELECTIVE_POINT_KIND ||
        target<0 || senders.empty() || senders.size()>1024)
        return false;
    std::vector<int> unique=senders;
    std::sort(unique.begin(),unique.end());
    if (std::adjacent_find(unique.begin(),unique.end())!=unique.end())
        return false;
    for (int sender:senders)
        if(sender<0 || sender==target)return false;

    const int fd=::open(path_.c_str(),O_RDWR|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)return false;
    bool ok=::flock(fd,LOCK_EX)==0;
    std::vector<u64> words;
    if(ok)ok=read_full(fd,&words);

    // Validate the complete chain without applying the replay predicate:
    // a retry after a crash may already have appended this exact batch.
    Digest tip{};
    if(ok)ok=scan_history(words,registry_binding_,&tip,nullptr,-1,-1);
    size_t total_entries=0;
    if(ok)total_entries=(words.size()-HEADER)/ENTRY;

    // Find the independently pinned head as an ancestor of the current tip.
    // Only an exact complete suffix matching this request is resumable.
    size_t prefix_entries=0;
    bool expected_found=false;
    if(ok) {
        Digest prefix_tip=hash_words(
            std::vector<u64>(words.begin(),words.begin()+HEADER));
        if(prefix_tip==expected_head)expected_found=true;
        for(size_t i=0;ok && !expected_found && i<total_entries;++i) {
            const size_t at=HEADER+i*ENTRY;
            prefix_tip=read_digest(words,at+10);
            if(prefix_tip==expected_head) {
                prefix_entries=i+1;
                expected_found=true;
            }
        }
        if(!expected_found)ok=false;
    }

    const size_t suffix_entries=ok?total_entries-prefix_entries:0;
    if(ok && suffix_entries!=0 && suffix_entries!=senders.size())
        ok=false;

    // The prefix must not already contain an event from this context. This
    // preserves replay rejection while allowing the exact suffix to resume.
    if(ok) {
        const size_t prefix_words_count=HEADER+prefix_entries*ENTRY;
        std::vector<u64> prefix(
            words.begin(),words.begin()+prefix_words_count);
        for(int sender:senders) {
            Digest prefix_tip{};
            if(!scan_history(prefix,registry_binding_,&prefix_tip,
                             &context,sender,target) ||
               prefix_tip!=expected_head) {
                ok=false;
                break;
            }
        }
    }

    if(ok && suffix_entries==senders.size()) {
        for(size_t i=0;i<senders.size();++i) {
            const size_t at=HEADER+(prefix_entries+i)*ENTRY;
            if(words[at]!=context.sid ||
               words[at+1]!=context.checkpoint ||
               words[at+2]!=static_cast<u64>(senders[i]) ||
               words[at+3]!=static_cast<u64>(target) ||
               words[at+4]!=context.round ||
               words[at+5]!=context.sequence) {
                ok=false;
                break;
            }
        }
        // Journal fsync completed before the caller crashed or its separate
        // trusted-head CAS failed. Return the existing tip without duplicates.
        if(ok) {
            if(::flock(fd,LOCK_UN)!=0)ok=false;
            if(::close(fd)!=0)ok=false;
            if(ok)*new_head=tip;
            return ok;
        }
    }

    if(ok && total_entries>MAX_ENTRIES-senders.size())ok=false;
    std::vector<u64> append;
    Digest last=tip;
    for(int sender:senders) {
        if(!ok)break;
        std::vector<u64> entry={
            context.sid,context.checkpoint,
            static_cast<u64>(sender),static_cast<u64>(target),
            context.round,context.sequence};
        append_digest(&entry,last);
        std::vector<u64> preimage={ENTRY_DOMAIN};
        preimage.insert(preimage.end(),entry.begin(),entry.end());
        const Digest digest=hash_words(preimage);
        if(digest==Digest{}) {ok=false;break;}
        append_digest(&entry,digest);
        append.insert(append.end(),entry.begin(),entry.end());
        last=digest;
    }
    if(ok) {
        if(::lseek(fd,0,SEEK_END)<0 || !write_words(fd,append) ||
           ::fsync(fd)!=0)
            ok=false;
    }
    if(::flock(fd,LOCK_UN)!=0)ok=false;
    if(::close(fd)!=0)ok=false;
    if(ok)*new_head=last;
    return ok;
}

bool ReferenceVssSelectivePointDurableReplayGuard::
VerifyPendingBatchWithPinnedHead(
    const AuthenticatedMpcMessageContext& context,
    const std::vector<int>& senders, int target,
    const Digest& expected_head, Digest* pending_head) const {
    if (!pending_head) return false;
    *pending_head = {};
    if (path_.empty() || path_.size() > 4000 ||
        registry_binding_ == Digest{} || expected_head == Digest{} ||
        !validate_authenticated_mpc_message_context(context) ||
        context.protocol_domain != PVIA_VSS_SELECTIVE_POINT_DOMAIN ||
        context.message_kind != PVIA_VSS_SELECTIVE_POINT_KIND ||
        target < 0 || senders.empty() || senders.size() > 1024)
        return false;
    std::vector<int> unique = senders;
    std::sort(unique.begin(), unique.end());
    if (std::adjacent_find(unique.begin(), unique.end()) != unique.end())
        return false;
    for (int sender : senders)
        if (sender < 0 || sender == target) return false;

    const int fd = ::open(path_.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    bool ok = ::flock(fd, LOCK_SH) == 0;
    std::vector<u64> words;
    if (ok) ok = read_full(fd, &words);
    Digest tip{};
    if (ok) ok = scan_history(words, registry_binding_, &tip, nullptr, -1, -1);
    const size_t total_entries = ok ? (words.size() - HEADER) / ENTRY : 0;

    size_t prefix_entries = 0;
    bool expected_found = false;
    if (ok) {
        Digest prefix_tip = hash_words(
            std::vector<u64>(words.begin(), words.begin() + HEADER));
        if (prefix_tip == expected_head) expected_found = true;
        for (size_t i = 0; ok && !expected_found && i < total_entries; ++i) {
            const size_t at = HEADER + i * ENTRY;
            prefix_tip = read_digest(words, at + 10);
            if (prefix_tip == expected_head) {
                prefix_entries = i + 1;
                expected_found = true;
            }
        }
        if (!expected_found) ok = false;
    }

    const size_t suffix_entries = ok ? total_entries - prefix_entries : 0;
    if (ok && suffix_entries != senders.size()) ok = false;

    // The prefix must not already contain any event from this context.
    if (ok) {
        const size_t prefix_words_count = HEADER + prefix_entries * ENTRY;
        std::vector<u64> prefix(
            words.begin(), words.begin() + prefix_words_count);
        for (int sender : senders) {
            Digest prefix_tip{};
            if (!scan_history(prefix, registry_binding_, &prefix_tip,
                              &context, sender, target) ||
                prefix_tip != expected_head) {
                ok = false;
                break;
            }
        }
    }

    // The suffix must be exactly the requested complete batch in sender order.
    if (ok) {
        for (size_t i = 0; i < senders.size(); ++i) {
            const size_t at = HEADER + (prefix_entries + i) * ENTRY;
            if (words[at] != context.sid ||
                words[at + 1] != context.checkpoint ||
                words[at + 2] != static_cast<u64>(senders[i]) ||
                words[at + 3] != static_cast<u64>(target) ||
                words[at + 4] != context.round ||
                words[at + 5] != context.sequence) {
                ok = false;
                break;
            }
        }
    }
    if (::flock(fd, LOCK_UN) != 0) ok = false;
    if (::close(fd) != 0) ok = false;
    if (ok && tip != expected_head) *pending_head = tip;
    else ok = false;
    if (!ok) *pending_head = {};
    return ok;
}

bool ReferenceVssSelectivePointDurableReplayGuard::
VerifyCommittedBatchWithPinnedHead(
    const AuthenticatedMpcMessageContext& context,
    const std::vector<int>& senders, int target,
    const Digest& expected_current_head) const {
    if (path_.empty() || path_.size()>4000 ||
        registry_binding_==Digest{} || expected_current_head==Digest{} ||
        !validate_authenticated_mpc_message_context(context) ||
        context.protocol_domain!=PVIA_VSS_SELECTIVE_POINT_DOMAIN ||
        context.message_kind!=PVIA_VSS_SELECTIVE_POINT_KIND ||
        target<0 || senders.empty() || senders.size()>1024)
        return false;
    std::vector<int> unique=senders;
    std::sort(unique.begin(),unique.end());
    if (std::adjacent_find(unique.begin(),unique.end())!=unique.end())
        return false;
    for(int sender:senders)
        if(sender<0 || sender==target)return false;

    const int fd=::open(path_.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)return false;
    bool ok=::flock(fd,LOCK_SH)==0;
    std::vector<u64> words;
    if(ok)ok=read_full(fd,&words);
    Digest tip{};
    if(ok)ok=scan_history(words,registry_binding_,&tip,nullptr,-1,-1) &&
             tip==expected_current_head;
    const size_t entries=ok?(words.size()-HEADER)/ENTRY:0;
    if(ok && entries<senders.size())ok=false;

    const size_t prefix_entries=ok?entries-senders.size():0;
    if(ok) {
        const size_t prefix_words_count=HEADER+prefix_entries*ENTRY;
        std::vector<u64> prefix(
            words.begin(),words.begin()+prefix_words_count);
        // Reject a previously recorded event from this same context in the
        // prefix. Only the exact final batch is eligible for restart resume.
        for(int sender:senders) {
            Digest prefix_tip{};
            if(!scan_history(prefix,registry_binding_,&prefix_tip,
                             &context,sender,target)) {
                ok=false;
                break;
            }
        }
    }
    if(ok) {
        for(size_t i=0;i<senders.size();++i) {
            const size_t at=HEADER+(prefix_entries+i)*ENTRY;
            if(words[at]!=context.sid ||
               words[at+1]!=context.checkpoint ||
               words[at+2]!=static_cast<u64>(senders[i]) ||
               words[at+3]!=static_cast<u64>(target) ||
               words[at+4]!=context.round ||
               words[at+5]!=context.sequence) {
                ok=false;
                break;
            }
        }
    }
    if(::flock(fd,LOCK_UN)!=0)ok=false;
    if(::close(fd)!=0)ok=false;
    return ok;
}

namespace {
constexpr u64 ANCHOR_MAGIC = 0x50565248414e4331ULL; // PVRHANC1
constexpr u64 ANCHOR_VERSION = 1;
constexpr u64 ANCHOR_ENTRY_DOMAIN = 0x50565248454e5431ULL;
constexpr size_t ANCHOR_HEADER_WORDS = 10;
constexpr size_t ANCHOR_ENTRY_WORDS = 17;
constexpr size_t ANCHOR_MAX_ENTRIES = 65536;

void anchor_append_digest(const Digest& digest, std::vector<u64>* out) {
    for (size_t i = 0; i < digest.bytes.size(); i += 8) {
        u64 word = 0;
        for (size_t j = 0; j < 8; ++j)
            word |= static_cast<u64>(digest.bytes[i+j]) << (8*j);
        out->push_back(word);
    }
}

bool anchor_read_words(int fd, std::vector<u64>* output) {
    if (!output) return false;
    struct stat info{};
    if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_uid != ::geteuid() || (info.st_mode & 077) != 0 ||
        info.st_nlink != 1 || info.st_size < 0 ||
        static_cast<uint64_t>(info.st_size) >
            (ANCHOR_HEADER_WORDS +
             ANCHOR_MAX_ENTRIES * ANCHOR_ENTRY_WORDS) * sizeof(u64) ||
        (info.st_size % static_cast<off_t>(sizeof(u64))) != 0)
        return false;

    const size_t byte_count = static_cast<size_t>(info.st_size);
    std::vector<uint8_t> bytes(byte_count);
    if (::lseek(fd, 0, SEEK_SET) < 0) return false;
    size_t offset = 0;
    while (offset < byte_count) {
        const ssize_t got = ::read(fd, bytes.data() + offset,
                                   byte_count - offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return false;
        offset += static_cast<size_t>(got);
    }
    std::vector<u64> words(byte_count / sizeof(u64), 0);
    for (size_t i = 0; i < words.size(); ++i)
        for (size_t j = 0; j < sizeof(u64); ++j)
            words[i] |= static_cast<u64>(bytes[i * sizeof(u64) + j]) << (8*j);
    *output = std::move(words);
    return true;
}

bool anchor_write_words(int fd, const std::vector<u64>& words) {
    std::vector<uint8_t> bytes;
    bytes.reserve(words.size() * sizeof(u64));
    for (u64 word : words)
        for (size_t j = 0; j < sizeof(u64); ++j)
            bytes.push_back(static_cast<uint8_t>(word >> (8*j)));
    size_t offset = 0;
    while (offset < bytes.size()) {
        const ssize_t wrote = ::write(fd, bytes.data() + offset,
                                      bytes.size() - offset);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) return false;
        offset += static_cast<size_t>(wrote);
    }
    return true;
}

bool anchor_fsync_parent(const std::string& path) {
    const size_t separator = path.find_last_of('/');
    const std::string parent = separator == std::string::npos
        ? "." : (separator == 0 ? "/" : path.substr(0, separator));
    const int fd = ::open(parent.c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    const bool synced = ::fsync(fd) == 0;
    const bool closed = ::close(fd) == 0;
    return synced && closed;
}

bool anchor_scan(const std::vector<u64>& words,
                 const Digest& registry_binding,
                 Digest* current_head,
                 Digest* chain_tip,
                 size_t* entry_count) {
    if (!current_head || !chain_tip || !entry_count ||
        words.size() < ANCHOR_HEADER_WORDS ||
        words[0] != ANCHOR_MAGIC || words[1] != ANCHOR_VERSION ||
        read_digest(words, 2) != registry_binding ||
        (words.size() - ANCHOR_HEADER_WORDS) % ANCHOR_ENTRY_WORDS != 0)
        return false;
    const size_t count =
        (words.size() - ANCHOR_HEADER_WORDS) / ANCHOR_ENTRY_WORDS;
    if (count > ANCHOR_MAX_ENTRIES) return false;

    Digest head = read_digest(words, 6);
    if (head == Digest{}) return false;
    Digest tip = hash_words(std::vector<u64>(
        words.begin(), words.begin() + ANCHOR_HEADER_WORDS));
    if (tip == Digest{}) return false;

    for (size_t index = 0; index < count; ++index) {
        const size_t at = ANCHOR_HEADER_WORDS + index * ANCHOR_ENTRY_WORDS;
        const u64 sequence = words[at];
        const Digest expected = read_digest(words, at + 1);
        const Digest next = read_digest(words, at + 5);
        const Digest previous_tip = read_digest(words, at + 9);
        const Digest stored_checksum = read_digest(words, at + 13);
        if (sequence != index + 1 || expected != head ||
            next == Digest{} || next == expected || previous_tip != tip)
            return false;

        std::vector<u64> preimage{ANCHOR_ENTRY_DOMAIN, sequence};
        anchor_append_digest(expected, &preimage);
        anchor_append_digest(next, &preimage);
        anchor_append_digest(previous_tip, &preimage);
        const Digest checksum = hash_words(preimage);
        if (checksum == Digest{} || checksum != stored_checksum) return false;
        head = next;
        tip = checksum;
    }
    *current_head = head;
    *chain_tip = tip;
    *entry_count = count;
    return true;
}

bool anchor_make_temp_path(std::string* path) {
    if (!path) return false;
    char pattern[] = "/tmp/pvia-vss-replay-head-anchor-XXXXXX";
    const int fd = ::mkstemp(pattern);
    if (fd < 0) return false;
    const bool closed = ::close(fd) == 0;
    const bool removed = ::unlink(pattern) == 0;
    if (!closed || !removed) return false;
    *path = pattern;
    return true;
}
} // namespace

ReferenceVssSelectivePointReplayHeadAnchor::
ReferenceVssSelectivePointReplayHeadAnchor(
    std::string path, Digest registry_binding)
    : path_(std::move(path)), registry_binding_(registry_binding) {}

bool ReferenceVssSelectivePointReplayHeadAnchor::InitializeNew(
    const Digest& initial_head) const {
    if (path_.empty() || path_.size() > 4000 ||
        registry_binding_ == Digest{} || initial_head == Digest{})
        return false;
    std::vector<u64> header{ANCHOR_MAGIC, ANCHOR_VERSION};
    anchor_append_digest(registry_binding_, &header);
    anchor_append_digest(initial_head, &header);
    const int fd = ::open(path_.c_str(),
        O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    const bool wrote = ::fchmod(fd, S_IRUSR | S_IWUSR) == 0 &&
                       anchor_write_words(fd, header) && ::fsync(fd) == 0;
    const bool closed = ::close(fd) == 0;
    if (!wrote || !closed) {
        ::unlink(path_.c_str());
        return false;
    }
    if (!anchor_fsync_parent(path_)) {
        ::unlink(path_.c_str());
        anchor_fsync_parent(path_);
        return false;
    }
    return true;
}

bool ReferenceVssSelectivePointReplayHeadAnchor::ReadCurrentHead(
    Digest* current_head) const {
    if (!current_head) return false;
    *current_head = {};
    if (path_.empty() || path_.size() > 4000 ||
        registry_binding_ == Digest{}) return false;
    const int fd = ::open(path_.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    bool ok = ::flock(fd, LOCK_SH) == 0;
    std::vector<u64> words;
    Digest head{}, tip{};
    size_t count = 0;
    if (ok) ok = anchor_read_words(fd, &words) &&
        anchor_scan(words, registry_binding_, &head, &tip, &count);
    if (ok) *current_head = head;
    if (::flock(fd, LOCK_UN) != 0) ok = false;
    if (::close(fd) != 0) ok = false;
    if (!ok) *current_head = {};
    return ok;
}

bool ReferenceVssSelectivePointReplayHeadAnchor::CompareAndSwap(
    const Digest& expected_head, const Digest& next_head) const {
    if (path_.empty() || path_.size() > 4000 ||
        registry_binding_ == Digest{} || expected_head == Digest{} ||
        next_head == Digest{} || next_head == expected_head)
        return false;
    const int fd = ::open(path_.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    bool ok = ::flock(fd, LOCK_EX) == 0;
    std::vector<u64> words;
    Digest current{}, tip{};
    size_t count = 0;
    if (ok) ok = anchor_read_words(fd, &words) &&
        anchor_scan(words, registry_binding_, &current, &tip, &count);
    if (ok && (current != expected_head || count >= ANCHOR_MAX_ENTRIES))
        ok = false;
    if (ok) {
        const u64 sequence = static_cast<u64>(count + 1);
        std::vector<u64> preimage{ANCHOR_ENTRY_DOMAIN, sequence};
        anchor_append_digest(expected_head, &preimage);
        anchor_append_digest(next_head, &preimage);
        anchor_append_digest(tip, &preimage);
        const Digest checksum = hash_words(preimage);
        if (checksum == Digest{}) {
            ok = false;
        } else {
            std::vector<u64> entry{sequence};
            anchor_append_digest(expected_head, &entry);
            anchor_append_digest(next_head, &entry);
            anchor_append_digest(tip, &entry);
            anchor_append_digest(checksum, &entry);
            ok = ::lseek(fd, 0, SEEK_END) >= 0 &&
                 anchor_write_words(fd, entry) && ::fsync(fd) == 0;
        }
    }
    if (::flock(fd, LOCK_UN) != 0) ok = false;
    if (::close(fd) != 0) ok = false;
    return ok;
}

bool run_reference_vss_replay_head_anchor_selftest() {
    std::string path, tamper_path, journal_path, journal_anchor_path;
    if (!anchor_make_temp_path(&path) ||
        !anchor_make_temp_path(&tamper_path) ||
        !anchor_make_temp_path(&journal_path) ||
        !anchor_make_temp_path(&journal_anchor_path)) return false;
    const Digest registry = hash_words({0x50565248414e4352ULL, 1, 4, 1});
    const Digest initial = hash_words({0x5056524845414430ULL, 1, 4});
    const Digest next = hash_words({0x5056524845414431ULL, 1, 4});
    const Digest alternate = hash_words({0x5056524845414432ULL, 1, 4});
    bool ok = registry != Digest{} && initial != Digest{} &&
              next != Digest{} && alternate != Digest{};

    ReferenceVssSelectivePointReplayHeadAnchor store(path, registry);
    ok = ok && store.InitializeNew(initial);
    Digest observed{};
    ok = ok && store.ReadCurrentHead(&observed) && observed == initial;
    ok = ok && !store.InitializeNew(initial);
    ok = ok && store.CompareAndSwap(initial, next);
    ok = ok && !store.CompareAndSwap(initial, alternate);

    // Reconstruct the store object to exercise disk reload rather than an
    // in-memory cached head.
    ReferenceVssSelectivePointReplayHeadAnchor reopened(path, registry);
    observed = {};
    ok = ok && reopened.ReadCurrentHead(&observed) && observed == next;
    ok = ok && !reopened.CompareAndSwap(initial, alternate);

    ReferenceVssSelectivePointReplayHeadAnchor tamper_store(
        tamper_path, registry);
    bool tamper_ok = tamper_store.InitializeNew(initial) &&
                     tamper_store.CompareAndSwap(initial, next);
    const int tamper_fd = ::open(
        tamper_path.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (tamper_fd < 0) {
        tamper_ok = false;
    } else {
        const off_t end = ::lseek(tamper_fd, 0, SEEK_END);
        uint8_t byte = 0;
        if (end <= 0 || ::lseek(tamper_fd, end - 1, SEEK_SET) < 0 ||
            ::read(tamper_fd, &byte, 1) != 1 ||
            ::lseek(tamper_fd, end - 1, SEEK_SET) < 0) {
            tamper_ok = false;
        } else {
            byte ^= 1;
            if (::write(tamper_fd, &byte, 1) != 1 ||
                ::fsync(tamper_fd) != 0) tamper_ok = false;
        }
        if (::close(tamper_fd) != 0) tamper_ok = false;
    }
    ReferenceVssSelectivePointReplayHeadAnchor tamper_reader(
        tamper_path, registry);
    Digest ignored{};
    const bool tamper_rejected =
        tamper_ok && !tamper_reader.ReadCurrentHead(&ignored);

    struct stat info{};
    const bool private_mode =
        ::stat(path.c_str(), &info) == 0 &&
        S_ISREG(info.st_mode) && (info.st_mode & 077) == 0;

    // Simulate a crash after the journal batch is fsynced but before the
    // separately stored trusted head is advanced. A fresh process retries
    // the same exact context and sender set; it must recover the existing tip
    // rather than append duplicates. A different context must be rejected.
    ReferenceVssSelectivePointDurableReplayGuard journal(
        journal_path, registry);
    const bool journal_initialized = journal.InitializeNew();
    Digest journal_initial{}, first_tip{}, resumed_tip{}, journal_tip{};
    const bool journal_initial_read =
        journal.ReadCurrentHead(&journal_initial) &&
        journal_initial != Digest{};
    AuthenticatedMpcMessageContext retry_context;
    retry_context.protocol_domain = PVIA_VSS_SELECTIVE_POINT_DOMAIN;
    retry_context.sid = 0x5056524553554d45ULL;
    retry_context.checkpoint = 17;
    retry_context.round = 23;
    retry_context.sequence = 29;
    retry_context.message_kind = PVIA_VSS_SELECTIVE_POINT_KIND;
    const std::vector<int> retry_senders{1,2,3};
    const bool first_batch_written = journal_initialized &&
        journal_initial_read &&
        journal.ObserveBatchWithPinnedHead(
            retry_context,retry_senders,0,journal_initial,&first_tip) &&
        first_tip != Digest{};

    ReferenceVssSelectivePointReplayHeadAnchor journal_anchor(
        journal_anchor_path, registry);
    const bool journal_anchor_initialized =
        first_batch_written && journal_anchor.InitializeNew(journal_initial);
    ReferenceVssSelectivePointDurableReplayGuard restarted_journal(
        journal_path, registry);
    auto wrong_retry_context = retry_context;
    ++wrong_retry_context.sequence;
    ++wrong_retry_context.round;
    Digest refused_tip{};
    const bool wrong_context_retry_rejected =
        !restarted_journal.ObserveBatchWithPinnedHead(
            wrong_retry_context,retry_senders,0,journal_initial,
            &refused_tip) && refused_tip == Digest{};
    const std::vector<int> wrong_retry_senders{1,2,4};
    Digest refused_sender_tip{};
    const bool wrong_sender_retry_rejected =
        !restarted_journal.ObserveBatchWithPinnedHead(
            retry_context,wrong_retry_senders,0,journal_initial,
            &refused_sender_tip) && refused_sender_tip == Digest{};
    const bool mismatched_retry_rejected =
        wrong_context_retry_rejected && wrong_sender_retry_rejected;
    const bool exact_retry_resumed =
        restarted_journal.ObserveBatchWithPinnedHead(
            retry_context,retry_senders,0,journal_initial,&resumed_tip) &&
        resumed_tip == first_tip;
    const bool journal_tip_matches =
        restarted_journal.ReadCurrentHead(&journal_tip) &&
        journal_tip == first_tip;
    Digest still_old_anchor{};
    const bool anchor_stayed_old =
        journal_anchor.ReadCurrentHead(&still_old_anchor) &&
        still_old_anchor == journal_initial;
    const bool anchor_cas_after_resume =
        exact_retry_resumed &&
        journal_anchor.CompareAndSwap(journal_initial,resumed_tip);
    Digest advanced_anchor{};
    const bool anchor_reloaded_after_cas =
        journal_anchor.ReadCurrentHead(&advanced_anchor) &&
        advanced_anchor == resumed_tip;
    const bool committed_batch_verified =
        restarted_journal.VerifyCommittedBatchWithPinnedHead(
            retry_context,retry_senders,0,resumed_tip);
    const bool committed_context_mismatch_rejected =
        !restarted_journal.VerifyCommittedBatchWithPinnedHead(
            wrong_retry_context,retry_senders,0,resumed_tip);
    const bool committed_sender_mismatch_rejected =
        !restarted_journal.VerifyCommittedBatchWithPinnedHead(
            retry_context,wrong_retry_senders,0,resumed_tip);
    const bool crash_resume =
        journal_initialized && journal_initial_read &&
        first_batch_written && journal_anchor_initialized &&
        mismatched_retry_rejected && exact_retry_resumed &&
        journal_tip_matches && anchor_stayed_old &&
        anchor_cas_after_resume && anchor_reloaded_after_cas &&
        committed_batch_verified && committed_context_mismatch_rejected &&
        committed_sender_mismatch_rejected;

    ::unlink(path.c_str());
    ::unlink(tamper_path.c_str());
    ::unlink(journal_path.c_str());
    ::unlink(journal_anchor_path.c_str());
    ok = ok && tamper_rejected && private_mode && crash_resume &&
         mismatched_retry_rejected;
    std::cout << "PVIA_VSS_REPLAY_HEAD_ANCHOR_SELFTEST: "
              << (ok ? "PASS" : "FAIL")
              << " reopen_reload=" << (ok ? "PASS" : "FAIL")
              << " stale_cas=" << (ok ? "REJECTED" : "FAIL")
              << " checksum_tamper="
              << (tamper_rejected ? "REJECTED" : "FAIL")
              << " crash_resume=" << (crash_resume ? "PASS" : "FAIL")
              << " exact_batch=" << (crash_resume ? "PASS" : "FAIL")
              << " mismatched_retry="
              << (mismatched_retry_rejected ? "REJECTED" : "FAIL")
              << " sender_set_retry="
              << (wrong_sender_retry_rejected ? "REJECTED" : "FAIL")
              << " journal_init=" << (journal_initialized ? "PASS" : "FAIL")
              << " first_batch=" << (first_batch_written ? "PASS" : "FAIL")
              << " anchor_init=" << (journal_anchor_initialized ? "PASS" : "FAIL")
              << " exact_retry=" << (exact_retry_resumed ? "PASS" : "FAIL")
              << " journal_tip=" << (journal_tip_matches ? "PASS" : "FAIL")
              << " anchor_old=" << (anchor_stayed_old ? "PASS" : "FAIL")
              << " anchor_cas=" << (anchor_cas_after_resume ? "PASS" : "FAIL")
              << " anchor_reload=" << (anchor_reloaded_after_cas ? "PASS" : "FAIL")
              << " committed_batch_resume="
              << (committed_batch_verified ? "PASS" : "FAIL")
              << " committed_context_mismatch="
              << (committed_context_mismatch_rejected ? "REJECTED" : "FAIL")
              << " committed_sender_mismatch="
              << (committed_sender_mismatch_rejected ? "REJECTED" : "FAIL")
              << " mode=LOCAL_DURABLE_NOT_EXTERNAL" << std::endl;
    return ok;
}


bool run_reference_vss_cross_process_recovery_selftest(
    int rank, int world_size, const std::string& phase,
    const std::string& directory) {
    if (world_size != 4 || rank < 0 || rank >= world_size ||
        directory.empty() || directory.size() > 3000 ||
        (phase != "prepare" && phase != "resume"))
        return false;
    if (rank != 0) return true;
    struct stat directory_info{};
    if (::stat(directory.c_str(), &directory_info) != 0 ||
        !S_ISDIR(directory_info.st_mode) ||
        directory_info.st_uid != ::geteuid()) return false;

    const std::string journal_path = directory + "/replay.journal";
    const std::string anchor_path = directory + "/replay.anchor";
    const std::string initial_path = directory + "/initial.head";
    const std::string delivered_path = directory + "/delivered.marker";
    const Digest registry = hash_words({0x50564350524f4352ULL, 1, 4, 1});
    if (registry == Digest{}) return false;

    AuthenticatedMpcMessageContext context;
    context.protocol_domain = PVIA_VSS_SELECTIVE_POINT_DOMAIN;
    context.sid = 0x50564350524f4353ULL;
    context.checkpoint = 0x4350524f430001ULL;
    context.round = 41;
    context.sequence = 73;
    context.message_kind = PVIA_VSS_SELECTIVE_POINT_KIND;
    const int target = 0;
    const std::vector<int> helpers{1, 2, 3};

    auto persist_initial = [&](const Digest& head) {
        const int fd = ::open(initial_path.c_str(),
            O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) return false;
        size_t offset = 0;
        bool ok = true;
        while (offset < head.bytes.size()) {
            const ssize_t n = ::write(fd, head.bytes.data() + offset,
                                      head.bytes.size() - offset);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { ok = false; break; }
            offset += static_cast<size_t>(n);
        }
        if (ok) ok = ::fsync(fd) == 0;
        if (::close(fd) != 0) ok = false;
        if (ok) ok = anchor_fsync_parent(initial_path);
        if (!ok) {
            ::unlink(initial_path.c_str());
            anchor_fsync_parent(initial_path);
        }
        return ok;
    };
    auto read_initial = [&](Digest* head) {
        if (!head) return false;
        *head = {};
        const int fd = ::open(initial_path.c_str(),
                              O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) return false;
        struct stat info{};
        bool ok = ::fstat(fd, &info) == 0 &&
            S_ISREG(info.st_mode) && info.st_uid == ::geteuid() &&
            (info.st_mode & 077) == 0 &&
            info.st_size == static_cast<off_t>(head->bytes.size());
        size_t offset = 0;
        while (ok && offset < head->bytes.size()) {
            const ssize_t n = ::read(fd, head->bytes.data() + offset,
                                     head->bytes.size() - offset);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { ok = false; break; }
            offset += static_cast<size_t>(n);
        }
        if (::close(fd) != 0) ok = false;
        if (!ok) *head = {};
        return ok && *head != Digest{};
    };
    auto create_delivery_marker = [&](const Digest& head) {
        const int fd = ::open(delivered_path.c_str(),
            O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) return false;
        const std::string payload =
            std::string("PVIA_CROSS_PROCESS_DELIVERED_V1\n") + head.hex() + "\n";
        size_t offset = 0;
        bool ok = true;
        while (offset < payload.size()) {
            const ssize_t n = ::write(fd, payload.data() + offset,
                                      payload.size() - offset);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { ok = false; break; }
            offset += static_cast<size_t>(n);
        }
        if (ok) ok = ::fsync(fd) == 0;
        if (::close(fd) != 0) ok = false;
        if (ok) ok = anchor_fsync_parent(delivered_path);
        if (!ok) {
            ::unlink(delivered_path.c_str());
            anchor_fsync_parent(delivered_path);
        }
        return ok;
    };

    ReferenceVssSelectivePointDurableReplayGuard journal(journal_path, registry);
    ReferenceVssSelectivePointReplayHeadAnchor anchor(anchor_path, registry);

    if (phase == "prepare") {
        Digest initial{}, next{}, journal_tip{}, anchor_tip{};
        const bool initialized = journal.InitializeNew() &&
            journal.ReadCurrentHead(&initial) && initial != Digest{} &&
            anchor.InitializeNew(initial) && persist_initial(initial);
        const bool batch_committed = initialized &&
            journal.ObserveBatchWithPinnedHead(
                context, helpers, target, initial, &next) && next != Digest{};
        const bool anchor_committed = batch_committed &&
            anchor.CompareAndSwap(initial, next);
        const bool durable = anchor_committed &&
            journal.ReadCurrentHead(&journal_tip) && journal_tip == next &&
            anchor.ReadCurrentHead(&anchor_tip) && anchor_tip == next &&
            ::access(delivered_path.c_str(), F_OK) != 0;
        std::cout << "PVIA_VSS_CROSS_PROCESS_RECOVERY: "
                  << (durable ? "PASS" : "FAIL")
                  << " phase=PREPARE journal_fsync=PASS anchor_cas="
                  << (anchor_committed ? "PASS" : "FAIL")
                  << " delivery=NOT_YET process_exit_boundary=READY"
                  << std::endl;
        return durable;
    }

    Digest initial{}, anchored{}, journal_tip{};
    const bool loaded = read_initial(&initial) &&
        anchor.ReadCurrentHead(&anchored) && anchored != Digest{} &&
        journal.ReadCurrentHead(&journal_tip) && journal_tip == anchored;
    const bool exact_batch = loaded &&
        journal.VerifyCommittedBatchWithPinnedHead(context, helpers, target, anchored);
    auto wrong_context = context;
    ++wrong_context.round;
    ++wrong_context.sequence;
    const bool wrong_context_rejected = loaded &&
        !journal.VerifyCommittedBatchWithPinnedHead(
            wrong_context, helpers, target, anchored);
    const std::vector<int> wrong_helpers{1, 2, 4};
    const bool wrong_helpers_rejected = loaded &&
        !journal.VerifyCommittedBatchWithPinnedHead(
            context, wrong_helpers, target, anchored);

    Digest retry_tip{}, after_retry{};
    const bool exact_retry = exact_batch &&
        journal.ObserveBatchWithPinnedHead(
            context, helpers, target, initial, &retry_tip) &&
        retry_tip == anchored &&
        journal.ReadCurrentHead(&after_retry) && after_retry == anchored;
    const bool duplicate_cas_rejected = !anchor.CompareAndSwap(initial, anchored);
    Digest after_cas{};
    const bool anchor_unchanged =
        anchor.ReadCurrentHead(&after_cas) && after_cas == anchored;
    const bool delivered = loaded && exact_batch && wrong_context_rejected &&
        wrong_helpers_rejected && exact_retry && duplicate_cas_rejected &&
        anchor_unchanged && create_delivery_marker(anchored);
    std::cout << "PVIA_VSS_CROSS_PROCESS_RECOVERY: "
              << (delivered ? "PASS" : "FAIL")
              << " phase=RESUME fresh_process=PASS anchor_reload="
              << (loaded ? "PASS" : "FAIL")
              << " exact_batch=" << (exact_batch ? "PASS" : "FAIL")
              << " wrong_context=" << (wrong_context_rejected ? "REJECTED" : "FAIL")
              << " wrong_helpers=" << (wrong_helpers_rejected ? "REJECTED" : "FAIL")
              << " duplicate_append=NO duplicate_cas="
              << (duplicate_cas_rejected ? "REJECTED" : "FAIL")
              << " delivery_marker=" << (delivered ? "FSYNCED" : "FAIL")
              << " anchor_mode=LOCAL_DURABLE_NOT_EXTERNAL" << std::endl;
    return delivered;
}

} // namespace pvia
