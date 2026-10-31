#pragma once
// What an object is on disk: the metadata a key carries, the self-describing
// header in front of its bytes, and the journal record that names it.
//
// Pure encoding with no I/O, so a unit test and a fuzz target reach it without a ring.
#include <algorithm>
#include <array>
#include <cstring>
#include <initializer_list>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "../../shared/http/conditional.h"

#include "checksum.h"
#include "digest.h"

namespace socketley::storage
{

// An object's own checksum as raw bytes, which is base64 only in an answer and on disk.
struct object_checksum
{
    // Both are read here and written by set(), which keeps the value's storage fit for the algorithm.
    checksum_algo algo{checksum_algo::none};
    // The N of a COMPOSITE value's -N, and 0 for a checksum of the object's whole bytes.
    uint16_t composite{0};

    object_checksum() : m_small{} {}
    object_checksum(const object_checksum& o) : m_small{} { set(o.algo, o.raw_bytes(), o.composite); }
    object_checksum(object_checksum&& o) noexcept : algo(o.algo), composite(o.composite), m_small{}
    {
        std::memcpy(m_small, o.m_small, sizeof m_small);
        o.algo = checksum_algo::none;
    }
    object_checksum& operator=(const object_checksum& o)
    {
        if (this != &o)
            set(o.algo, o.raw_bytes(), o.composite);
        return *this;
    }
    object_checksum& operator=(object_checksum&& o) noexcept
    {
        if (this != &o)
        {
            release();
            algo      = o.algo;
            composite = o.composite;
            std::memcpy(m_small, o.m_small, sizeof m_small);
            o.algo = checksum_algo::none;
        }
        return *this;
    }
    ~object_checksum() { release(); }

    // The algorithm, its raw value (zeros past what is given) and the count of a composite one.
    void set(checksum_algo a, std::string_view raw = {}, uint16_t composite_count = 0);

    explicit operator bool() const { return algo != checksum_algo::none; }
    std::string_view raw_bytes() const
    {
        return {reinterpret_cast<const char*>(big() ? m_big : m_small), checksum_raw_len(algo)};
    }
    // The value as S3 shows it: base64, with -N after a composite one.
    std::string b64() const;
    // FULL_OBJECT or COMPOSITE.
    std::string_view type() const { return composite ? "COMPOSITE" : "FULL_OBJECT"; }

    bool operator==(const object_checksum& o) const
    {
        return algo == o.algo && composite == o.composite && raw_bytes() == o.raw_bytes();
    }

private:
    // A CRC's value inline, and a longer one's on the heap, so every object in memory spends 8 bytes on it.
    bool big() const { return checksum_raw_len(algo) > sizeof m_small; }
    void release()
    {
        if (big())
            delete[] m_big;
        algo = checksum_algo::none;
    }
    union
    {
        uint8_t  m_small[8];
        uint8_t* m_big;
    };
};

// A content type, which the objects of a store share one copy of for the first few hundred types it sees.
class content_type_ref
{
public:
    content_type_ref() = default;
    content_type_ref(const content_type_ref& o) { copy_from(o); }
    content_type_ref(content_type_ref&& o) noexcept : m_p(o.m_p) { o.m_p = 0; }
    content_type_ref& operator=(const content_type_ref& o)
    {
        if (this != &o)
        {
            release();
            copy_from(o);
        }
        return *this;
    }
    content_type_ref& operator=(content_type_ref&& o) noexcept
    {
        if (this != &o)
        {
            release();
            m_p   = o.m_p;
            o.m_p = 0;
        }
        return *this;
    }
    ~content_type_ref() { release(); }
    content_type_ref& operator=(std::string_view v);

    const std::string& str() const;
    operator const std::string&() const { return str(); }
    size_t size() const { return str().size(); }
    bool   empty() const { return str().empty(); }

    friend bool operator==(const content_type_ref& a, const content_type_ref& b) { return a.str() == b.str(); }
    friend bool operator==(const content_type_ref& a, std::string_view b) { return a.str() == b; }

private:
    // A string of the pool, which is never freed, or one of this value's own with the low bit set: a pointer wide,
    // since every object in memory has one.
    uintptr_t m_p{0};
    const std::string* ptr() const { return reinterpret_cast<const std::string*>(m_p & ~uintptr_t{1}); }
    bool owned() const { return (m_p & 1) != 0; }
    void release()
    {
        if (owned())
            delete ptr();
        m_p = 0;
    }
    void copy_from(const content_type_ref& o)
    {
        m_p = o.owned() ? reinterpret_cast<uintptr_t>(new std::string(*o.ptr())) | 1 : o.m_p;
    }
};

// An object's extra header entries, a pointer wide while there are none, which is most objects' case in memory.
class meta_extras
{
public:
    using value_type     = std::pair<std::string, std::string>;
    using iterator       = value_type*;
    using const_iterator = const value_type*;

    meta_extras() = default;
    meta_extras(std::initializer_list<value_type> l)
    {
        for (const value_type& v : l)
            push_back(v);
    }
    meta_extras(const meta_extras& o) : m_v(o.empty() ? nullptr : std::make_unique<std::vector<value_type>>(*o.m_v)) {}
    meta_extras(meta_extras&&) noexcept = default;
    meta_extras& operator=(const meta_extras& o)
    {
        if (this != &o)
            m_v = o.empty() ? nullptr : std::make_unique<std::vector<value_type>>(*o.m_v);
        return *this;
    }
    meta_extras& operator=(meta_extras&&) noexcept = default;
    meta_extras& operator=(std::initializer_list<value_type> l)
    {
        clear();
        for (const value_type& v : l)
            push_back(v);
        return *this;
    }

    iterator       begin() { return m_v ? m_v->data() : nullptr; }
    iterator       end() { return m_v ? m_v->data() + m_v->size() : nullptr; }
    const_iterator begin() const { return m_v ? m_v->data() : nullptr; }
    const_iterator end() const { return m_v ? m_v->data() + m_v->size() : nullptr; }
    size_t size() const { return m_v ? m_v->size() : 0; }
    bool   empty() const { return size() == 0; }
    value_type&       operator[](size_t i) { return (*m_v)[i]; }
    const value_type& operator[](size_t i) const { return (*m_v)[i]; }
    value_type&       back() { return m_v->back(); }
    const value_type& back() const { return m_v->back(); }

    template <class... A>
    value_type& emplace_back(A&&... a)
    {
        return vec().emplace_back(std::forward<A>(a)...);
    }
    void push_back(value_type v) { vec().push_back(std::move(v)); }
    void pop_back()
    {
        m_v->pop_back();
        if (m_v->empty())
            m_v.reset();
    }
    iterator erase(const_iterator at)
    {
        const auto i = at - begin();
        m_v->erase(m_v->begin() + i);
        if (m_v->empty())
        {
            m_v.reset();
            return nullptr;
        }
        return begin() + i;
    }
    iterator insert(const_iterator at, value_type v)
    {
        const auto i = at - begin();
        vec().insert(vec().begin() + i, std::move(v));
        return begin() + i;
    }
    void clear() { m_v.reset(); }

    bool operator==(const meta_extras& o) const
    {
        return size() == o.size() && std::equal(begin(), end(), o.begin());
    }

    template <class P>
    friend size_t erase_if(meta_extras& e, P pred)
    {
        if (!e.m_v)
            return 0;
        const size_t n = static_cast<size_t>(std::erase_if(*e.m_v, pred));
        if (e.m_v->empty())
            e.m_v.reset();
        return n;
    }

private:
    std::vector<value_type>& vec()
    {
        if (!m_v)
            m_v = std::make_unique<std::vector<value_type>>();
        return *m_v;
    }
    std::unique_ptr<std::vector<value_type>> m_v;
};

// Everything S3 tells a client about an object beyond its bytes.
struct object_meta
{
    uint64_t size{0};
    // Milliseconds since the epoch, the moment the object was committed.
    int64_t  mtime_ms{0};
    md5_t    md5{};
    // Zero for a single-part object, else the part count of the multipart ETag.
    uint32_t parts{0};
    // On disk it is the extra entry checksum_header(algo), so a header or journal written before reads the same.
    object_checksum checksum;
    content_type_ref content_type;
    // Lowercase header name and value: cache-control, content-disposition,
    // content-encoding, content-language, expires and every x-amz-meta-*.
    meta_extras extra;

    // The ETag as S3 spells it, without the quotes: 32 hex digits, and "-N"
    // after them for a multipart object.
    std::string etag() const
    {
        std::string e = hex(md5);
        if (parts)
        {
            e += '-';
            e += std::to_string(parts);
        }
        return e;
    }

    bool operator==(const object_meta&) const = default;
};

// Whether a comma-separated If-Match / If-None-Match list names `etag`, quoted or weak, or is "*".
using socketley::http::etag_list_matches;

// The extra entry an object's tags are kept in: each tag's key and value, each followed by a NUL.
inline constexpr std::string_view tags_extra = "x-amz-tagging";

// The object's tags in that encoding, empty when it has none.
std::string_view tags_of(const object_meta& m);
// Makes `tags` the object's tags, as the last extra entry, or removes them when it is empty.
void set_tags_extra(object_meta& m, std::string_view tags);

// The extra entry of a version whose bytes were moved to a tier: the tier's name, a ';', and the key they lie under
// below the tier's own path.  Its file keeps the header alone.
inline constexpr std::string_view tier_extra = "x-socketley-tier";
// The storage class a write asked for, kept for the classes whose objects are read at once like STANDARD's.
inline constexpr std::string_view class_extra = "x-socketley-class";
// The class to keep for `asked` (an x-amz-storage-class), empty for STANDARD and for an archive class, whose name
// would tell a client to restore what it can read now.
std::string_view kept_class(std::string_view asked);
// Makes `cls` the version's kept class, or removes it when it is empty.
void set_class_extra(object_meta& m, std::string_view cls);

struct tier_record
{
    std::string tier;
    std::string remote_key;
};
bool tier_of(const object_meta& m, tier_record& out);
inline bool is_tiered(const object_meta& m)
{
    for (const auto& e : m.extra)
        if (e.first == tier_extra)
            return true;
    return false;
}
// Makes `m` say its bytes are where `r` says, or here when `r` is null.
void set_tier_record(object_meta& m, const tier_record* r);
// The storage class a listing and a read name: the tier the version moved to, or STANDARD.
std::string_view storage_class_of(const object_meta& m);

// The extra entry a multipart object's part sizes are kept in: one size when
// every part but the last has it, else every size, comma-separated.
inline constexpr std::string_view part_sizes_extra = "x-socketley-part-sizes";
// The longest list kept, so the header stays within its bounds; a longer one is not recorded.
inline constexpr size_t max_part_sizes_bytes = 4096;

// The entry for parts of these sizes, empty when it would be longer than `max`.
std::string encode_part_sizes(const std::vector<uint64_t>& sizes, size_t max = max_part_sizes_bytes);

// The extra entry naming the numbers a multipart object's parts were uploaded as, when they are not 1..N:
// single numbers and ranges, comma-separated, such as 1-3,5,9.
inline constexpr std::string_view part_numbers_extra = "x-socketley-part-numbers";

// The entry for these ascending numbers, empty when they are 1..N or the entry would be longer than `max`.
std::string encode_part_numbers(const std::vector<uint32_t>& numbers, size_t max = max_part_sizes_bytes);

// The extra entry a multipart object's part checksums are kept in: the raw checksums in part order, in base64.
inline constexpr std::string_view part_checksums_extra = "x-socketley-part-checksums";

// The algorithm of the object's own checksum, which its parts' checksums are kept in too.
checksum_algo checksum_algo_of(const object_meta& m);

// A multipart object's parts in order: the number each was uploaded as, its size, and its raw checksum.
struct part_list
{
    std::vector<uint32_t> numbers;
    std::vector<uint64_t> sizes;
    // One per part in the object's algorithm, or none when the parts' checksums were not kept.
    std::vector<std::string> checksums;
};

// The parts `m`'s header records, a single-part object being its own part 1 with its own full-object checksum;
// false when they are not recorded there or do not add up to the object.
bool part_list_of(const object_meta& m, part_list& out);

// Removes what `m` records of its parts and of how its bytes lie, for a copy that is one part whatever its source was.
void clear_part_layout(object_meta& m);

// Gives `copy` the checksum `algo` of its whole bytes in place of any other: `src`'s own when that is one, else a
// placeholder of its length; true when the value must be taken from the bytes.
bool copy_checksum(object_meta& copy, const object_meta& src, checksum_algo algo);

// Makes `raw` `m`'s checksum of its whole bytes in `algo`.
void set_checksum(object_meta& m, checksum_algo algo, std::string_view raw);
// Makes `b64`, as S3 shows it, `m`'s checksum in `algo`, kept as an extra entry when it is not as b64() renders.
void set_checksum_b64(object_meta& m, checksum_algo algo, std::string b64);
// A checksum `algo` of no bytes yet, as wide as the value or, with `composite`, the -N it will have, so a header
// reserves room for it.
void reserve_checksum(object_meta& m, checksum_algo algo, uint16_t composite = 0);
// The bytes of the extra entry `m`'s checksum is on disk, 0 for none.
size_t checksum_meta_bytes(const object_meta& m);

// The algorithm S3 gives the checksum of a new object that arrives without one.
inline constexpr checksum_algo default_checksum_algo = checksum_algo::crc64nvme;

// The extra entry of a part of an upload with no algorithm: the part's own CRC64NVME in base64, which no client is
// shown and which the completion combines into the object's default checksum.
inline constexpr std::string_view part_crc_extra = "x-socketley-part-crc64nvme";

// The list in one canonical encoding, of 20 + 12 bytes per part, which is what a digest of it is taken over;
// a list with checksums is 24 bytes and then 12 and the checksum's width per part.
std::string encode_part_list(const part_list& l, uint64_t total);

// The extra entry of a multipart object whose part list did not fit in its header and follows its body
// instead, in the canonical encoding: the body's length on disk, a semicolon, and the list's SHA-256 in hex,
// and after another semicolon the width of each part's checksum when the list holds them.
inline constexpr std::string_view part_layout_extra = "x-socketley-part-layout";
// The extra entry an SSE-C object completed without its client's key keeps its part list's MAC in.
inline constexpr std::string_view sse_parts_extra = "x-socketley-sse-parts";
// The extra entry of an SSE-C upload whose key is wrapped as an upload's, which its completion removes.
inline constexpr std::string_view sse_upload_wrap_extra = "x-socketley-sse-wrap";

// Where a part list kept after the body lies, counted from the body's start, and the digest it must have.
struct part_trailer
{
    uint64_t at{0};
    uint64_t len{0};
    std::array<uint8_t, 32> digest{};
    // Bytes of each part's checksum in the list, 0 for a list without them.
    uint32_t width{0};
};

// False when `m` keeps no part list after its body.
bool part_trailer_of(const object_meta& m, part_trailer& out);

// The list `bytes` hold, false unless they are the ones `t` names and describe `m`.
bool decode_part_trailer(std::string_view bytes, const object_meta& m, const part_trailer& t, part_list& out);

// Records `l` in `m`'s header when each entry fits in `max` bytes, the numbers only when `numbers` asks and they are
// not 1..N, and otherwise names a trailer after a body of `body_stored` bytes, whose bytes are returned.
std::string record_part_list(object_meta& m, const part_list& l, uint64_t body_stored, bool numbers,
                             size_t max = max_part_sizes_bytes);

// The extra entry of a sealed body written to a pooled file: the MD5 of its bytes as they lie on disk, in hex,
// which is how a start knows the file is whole without the key that opens it.
inline constexpr std::string_view stored_md5_extra = "x-socketley-stored-md5";

// The extra entry naming the upload a multipart object was completed from, so a retried completion finds it.
inline constexpr std::string_view upload_id_extra = "x-socketley-upload-id";

// The extra entry a version of a key in a versioned bucket is named by: its order among the
// key's versions, whether it is a delete marker, and its id.
inline constexpr std::string_view version_extra = "x-socketley-version";

struct version_tag
{
    // Larger is newer, so a key's versions sort newest first by it.
    uint64_t    seq{0};
    // "null", or 32 lowercase hex digits.
    std::string id;
    bool        marker{false};
};

// The version `m` records; an object written without versioning is the null version of its own time.
version_tag version_of(const object_meta& m);
// Its id and its order alone, the id viewed where `m` keeps it, for the loops over a key's versions.
std::string_view version_id_of(const object_meta& m);
uint64_t version_seq_of(const object_meta& m);
// Whether `m` records a version, which only an object written to a versioned bucket does.
bool has_version(const object_meta& m);
// Whether `m` is a delete marker, cheaply false for an object with no version.
bool is_delete_marker(const object_meta& m);
void set_version_extra(object_meta& m, const version_tag& v);
void clear_version_extra(object_meta& m);
// A version id the store could have given, which is also what keeps one out of a path.
bool valid_version_id(std::string_view id);
// The version an id the store gave in a versioned bucket names, its order being the id's first sixteen digits; false
// for "null" and anything else.
bool version_of_id(std::string_view id, bool marker, version_tag& out);

// The extra entry of a replica naming the version id its source gave it, which the replica keeps when it is still the
// newest of its key.
inline constexpr std::string_view replica_version_extra = "x-socketley-replica-version";
// That id, empty for anything but a replica.
std::string_view replica_source_of(const object_meta& m);

// The extra entry of a write another node of the cluster made: the version that node gave it and the time it was
// written there, which every node keeps, so all of them hold the same versions of the same writes.
inline constexpr std::string_view cluster_extra = "x-socketley-cluster";

struct cluster_stamp
{
    version_tag tag;
    int64_t     mtime_ms{0};
};

// "<seq><m|v><id> <mtime>", the entry's value and the header a node's write to another carries.
std::string cluster_stamp_text(const cluster_stamp& s);
bool        parse_cluster_stamp(std::string_view text, cluster_stamp& out);
// The stamp `m` was written with, false for a write of this node's own.
bool        cluster_stamp_of(const object_meta& m, cluster_stamp& out);
void        set_cluster_extra(object_meta& m, const cluster_stamp& s);
void        clear_cluster_extra(object_meta& m);

// The extra entries of a version's object lock: its retention, 'G' or 'C' and the retain-until time in decimal
// milliseconds, and its legal hold, ON or OFF once one was ever set.
inline constexpr std::string_view retention_extra  = "x-socketley-retention";
inline constexpr std::string_view legal_hold_extra = "x-socketley-legal-hold";

enum class lock_mode : uint8_t
{
    none,
    governance,
    compliance,
};

struct retention
{
    lock_mode mode{lock_mode::none};
    int64_t   until_ms{0};

    bool operator==(const retention&) const = default;
};

// The retention's entry, empty for none, and the retention an entry names, false for one that names none.
std::string retention_value(const retention& r);
bool        retention_from_value(std::string_view v, retention& out);
retention retention_of(const object_meta& m);
// Makes `r` the version's retention, as an entry after the tags, or removes it when its mode is none.
void set_retention_extra(object_meta& m, const retention& r);
// ON, OFF, or empty for a version whose legal hold was never set.
std::string_view legal_hold_of(const object_meta& m);
void set_legal_hold_extra(object_meta& m, std::string_view status);
// Whether `m` carries either entry, which is what makes its slot record them.
bool has_lock_extra(const object_meta& m);
// Removes both, for a copy, whose lock is its own and never its source's.
void clear_lock_extras(object_meta& m);
// The extra entry a version's replication status is kept in, PENDING, COMPLETED, FAILED or REPLICA, which a GET and a
// HEAD answer as their header of the same name.
inline constexpr std::string_view replication_status_extra = "x-amz-replication-status";
// The status `m` records, empty for none.
std::string_view replication_status_of(const object_meta& m);
// Makes `status` the version's replication status, as an entry after the legal hold, or removes it when it is empty.
void set_replication_status(object_meta& m, std::string_view status);
// Whether the version may not be removed or replaced at `now_ms`: a legal hold is on, or a retention is in force
// that `bypass` does not lift, which it does only for GOVERNANCE.
bool lock_holds(const object_meta& m, int64_t now_ms, bool bypass);
// Whether a version retained as `cur` may be retained as `want` at `now_ms`: a COMPLIANCE retention in force only
// lengthened, a GOVERNANCE one lengthened freely and shortened, removed or made COMPLIANCE only with `bypass`.
bool retention_change_allowed(const retention& cur, const retention& want, int64_t now_ms, bool bypass);
// The path of a key's noncurrent version below its bucket directory.
std::string version_rel_path(std::string_view key, std::string_view id);

enum class part_status : uint8_t
{
    ok,
    // The object has fewer parts than the one asked for.
    out_of_range,
    // A multipart object completed without its sizes recorded.
    unknown,
    // The sizes follow the object's body, which has to be read for them.
    in_trailer,
};

// Where part `n` (from 1) of the object begins and how long it is, a single-part object being its own
// part 1, and into `list` when given the list that says so.
part_status part_range(const object_meta& m, uint32_t n, uint64_t& first, uint64_t& len, part_list* list = nullptr);
// The same from a list read after the body, which part_range() says it needs with in_trailer.
part_status part_range_in(const part_list& l, uint32_t n, uint64_t& first, uint64_t& len);

inline constexpr size_t object_header_align = 4096;
inline constexpr size_t max_key_bytes       = 1024;
// User metadata is 2 KB in S3 and the system fields ride beside it, so this is
// the total the header may carry before the request is refused.
inline constexpr size_t max_meta_bytes      = 8192;

// Appends the meta fields in the encoding both the header and the journal use.
void encode_meta(std::string& out, std::string_view key, const object_meta& m);

// The header that precedes an object's bytes, padded to a multiple of
// object_header_align and at least `min_len` long, so the body starts where
// the caller reserved room for it.
std::string encode_object_header(std::string_view key, const object_meta& m, size_t min_len = 0);

// The smallest header_len encode_object_header() will produce for this key and
// meta, so a writer can reserve exactly that much before the etag is known.
size_t object_header_len(std::string_view key, const object_meta& m);

enum class header_status : uint8_t
{
    ok,
    // The header is longer than the bytes given; `need` says how many are wanted.
    need_more,
    bad,
};

struct decoded_header
{
    header_status status{header_status::bad};
    size_t        header_len{0};
    size_t        need{0};
    std::string   key;
    object_meta   meta;
    // Where the header's own fields end and its zero padding begins.
    size_t        meta_end{0};
    // The slot in that padding whose tags replaced the ones the header was written with, -1 for none.
    int8_t        tag_slot{-1};
    uint64_t      tag_seq{0};
    // That slot replaced the object lock entries too, as only one written for a version with a lock does.
    bool          lock_slot{false};
    // And the replication status, as only one written for a version with a status does.
    bool          repl_slot{false};
};

// Tags, a retention, a legal hold and a replication status changed after an object was written go
// into one of two slots in the padding of its header's first 4 KiB, whole
// 512-byte sectors written in turn and checksummed with a sequence number, so a
// torn write of one leaves the other and the object's bytes, ETag and time never move.
decoded_header decode_object_header(std::string_view bytes);

// The bytes that make `want`'s tags, retention and legal hold those of the object `d` decoded, and the offset
// they go at, or empty when its header has no room for them.
std::string encode_tag_slot(const decoded_header& d, const object_meta& want, uint64_t& at);
// The same for a change of the tags alone.
std::string encode_tag_slot(const decoded_header& d, std::string_view tags, uint64_t& at);

// ─── The index journal ──────────────────────────────────────────────────────
inline constexpr std::string_view journal_magic = std::string_view("SKLIDX\x01\x00", 8);
inline constexpr size_t           journal_header_len = 24;

// A journal says which shard wrote it and under how many, because the owner of
// a key moves with the shard count and a journal from another split holds the
// wrong keys.
std::string encode_journal_header(uint32_t shard, uint32_t nshards);

// The journal format that records every version of a key, where format 2 recorded only its latest object.
inline constexpr uint32_t journal_format = 3;

enum class journal_header_status : uint8_t
{
    ok,
    // A journal of ours from another shard count: sound, and not what this split owns.
    other_layout,
    bad,
};

// `format`, when given, is told the format of a sound header.
journal_header_status journal_header_check(std::string_view bytes, uint32_t shard, uint32_t nshards,
                                           uint32_t* format = nullptr);

// put and del name a key's latest object; vput and vdel add and remove one of its other versions.
enum class record_type : uint8_t { put = 1, del = 2, vput = 3, vdel = 4 };

struct journal_record
{
    record_type type{record_type::put};
    std::string key;
    object_meta meta;        // put, vput
    int64_t     mtime_ms{0}; // del
    std::string version_id;  // vdel
};

// A version of `key` that is not its latest object: a noncurrent one, or a delete marker.
void encode_version_record(std::string& out, std::string_view key, const object_meta& m);
void encode_version_drop_record(std::string& out, std::string_view key, std::string_view version_id);
void encode_put_record(std::string& out, std::string_view key, const object_meta& m);
void encode_delete_record(std::string& out, std::string_view key, int64_t mtime_ms);

enum class record_status : uint8_t
{
    ok,
    // The bytes end inside a record, which is what a crash mid-append leaves.
    torn,
    // A whole record whose checksum or shape is wrong.
    corrupt,
};

struct decoded_record
{
    record_status  status{record_status::torn};
    size_t         consumed{0};
    journal_record rec;
};

decoded_record decode_journal_record(std::string_view bytes);

// The path of an object's file below a bucket's data directory.
std::string object_rel_path(std::string_view key);
std::string key_hash(std::string_view key);

}   // namespace socketley::storage
