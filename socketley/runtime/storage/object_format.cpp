#include "object_format.h"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <cstdio>
#include <mutex>
#include <unordered_map>

#include "compression.h"
#include "../../shared/util/crc.h"
#include "../../shared/util/byte_codec.h"
#include "../../shared/util/number_parse.h"
#include "../../shared/util/base64.h"
#include "../../shared/util/text_list.h"

namespace socketley::storage
{

namespace
{

constexpr std::string_view object_magic = std::string_view("SKLOBJ\x01\x00", 8);
constexpr uint32_t         object_version = 1;
// magic, version, header_len, meta length, crc.
constexpr size_t           prelude_len = 24;
// The sanity bound on one journal record: a key, its metadata and slack.
constexpr size_t           max_record_bytes = 64 * 1024;

constexpr std::string_view slot_magic = std::string_view("SKLTAG\x01\x00", 8);
// A slot whose payload is the tags, the retention and the legal hold, each a length and its bytes.
constexpr std::string_view lock_slot_magic = std::string_view("SKLTAG\x02\x00", 8);
// The same with the replication status after them.
constexpr std::string_view repl_slot_magic = std::string_view("SKLTAG\x03\x00", 8);
constexpr std::string_view part_list_magic = std::string_view("SKLPRT\x01\x00", 8);
// A part list that carries each part's checksum after its number and size.
constexpr std::string_view part_list_sums_magic = std::string_view("SKLPRT\x02\x00", 8);
// magic, sequence, payload length, crc.
constexpr size_t           slot_head  = 24;
constexpr size_t           sector     = 512;

// Where an object's two tag slots begin and how long each is, room 0 when its padding has no two sectors for them.
struct slot_layout
{
    size_t off[2]{};
    size_t room{0};
};

slot_layout layout_of(size_t meta_end, size_t header_len)
{
    slot_layout l;
    const size_t begin = (meta_end + sector - 1) / sector * sector;
    const size_t end   = std::min(header_len, object_header_align);
    if (end < begin + 2 * sector)
        return l;
    l.room   = (end - begin) / 2 / sector * sector;
    l.off[0] = begin;
    l.off[1] = begin + l.room;
    return l;
}

void put_str(std::string& out, std::string_view s)
{
    bytes::append32(out, static_cast<uint32_t>(s.size()));
    out.append(s);
}

struct reader
{
    std::string_view in;
    bool             ok{true};

    uint32_t u32()
    {
        if (in.size() < 4) { ok = false; return 0; }
        uint32_t v;
        std::memcpy(&v, in.data(), 4);
        in.remove_prefix(4);
        return v;
    }
    uint64_t u64()
    {
        if (in.size() < 8) { ok = false; return 0; }
        uint64_t v;
        std::memcpy(&v, in.data(), 8);
        in.remove_prefix(8);
        return v;
    }
    std::string_view str()
    {
        return raw(u32());
    }
    std::string_view raw(size_t n)
    {
        if (!ok || in.size() < n) { ok = false; return {}; }
        std::string_view s = in.substr(0, n);
        in.remove_prefix(n);
        return s;
    }
};

// The checksum `v` is in `a`, false unless b64() renders it back byte for byte.
bool parse_checksum(checksum_algo a, std::string_view v, object_checksum& out)
{
    const size_t width = checksum_raw_len(a);
    const size_t chars = checksum_b64_len(a);
    if (width == 0 || v.size() < chars)
        return false;
    uint16_t composite = 0;
    if (const std::string_view n = v.substr(chars); !n.empty())
    {
        uint64_t parts = 0;
        if (n.size() < 2 || n[0] != '-' || n[1] == '0' || !socketley::parse_whole(n.substr(1), parts) || parts > UINT16_MAX)
            return false;
        composite = static_cast<uint16_t>(parts);
    }
    std::string raw;
    if (!base64::decode(v.substr(0, chars), raw) || raw.size() != width)
        return false;
    out.set(a, raw, composite);
    return true;
}

// Takes an extra entry that is the object's checksum into `m.checksum`, false for any other entry.
bool lift_checksum(object_meta& m, std::string_view name, std::string_view value)
{
    if (m.checksum || !name.starts_with("x-amz-checksum-"))
        return false;
    const checksum_algo a = checksum_from_header(name);
    return a != checksum_algo::none && parse_checksum(a, value, m.checksum);
}

bool decode_meta(std::string_view body, std::string& key, object_meta& m)
{
    reader r{body};
    m.size     = r.u64();
    m.mtime_ms = static_cast<int64_t>(r.u64());
    if (r.in.size() < 16)
        return false;
    std::memcpy(m.md5.data(), r.in.data(), 16);
    r.in.remove_prefix(16);
    m.parts = r.u32();
    key     = std::string(r.str());
    m.content_type = r.str();
    const uint32_t n = r.u32();
    if (!r.ok || n > 4096)
        return false;
    m.extra.clear();
    m.checksum = {};
    for (uint32_t i = 0; i < n; ++i)
    {
        const std::string_view name = r.str();
        const std::string_view val  = r.str();
        if (!r.ok)
            return false;
        if (!lift_checksum(m, name, val))
            m.extra.emplace_back(std::string(name), std::string(val));
    }
    return r.ok && r.in.empty() && key.size() <= max_key_bytes;
}

// How many content types are shared and how long one may be, so a client cannot grow what is never freed.
constexpr size_t shared_types    = 512;
constexpr size_t shared_type_len = 128;

}   // namespace

content_type_ref& content_type_ref::operator=(std::string_view v)
{
    using pool_t = std::unordered_map<std::string_view, const std::string*>;
    // Leaked on purpose, so an assignment made while statics are torn down never meets a destroyed pool.
    static std::mutex& mu   = *new std::mutex;
    static pool_t&     pool = *new pool_t;
    // A view into the string this holds is copied first, since release() frees it.
    std::string held;
    if (owned())
    {
        const std::string* own = ptr();
        if (v.data() >= own->data() && v.data() <= own->data() + own->size())
        {
            held.assign(v);
            v = held;
        }
    }
    release();
    if (v.empty())
        return *this;
    if (v.size() <= shared_type_len)
    {
        std::lock_guard<std::mutex> g(mu);
        if (const auto it = pool.find(v); it != pool.end())
        {
            m_p = reinterpret_cast<uintptr_t>(it->second);
            return *this;
        }
        if (pool.size() < shared_types)
        {
            const std::string* s = new std::string(v);
            pool.emplace(*s, s);
            m_p = reinterpret_cast<uintptr_t>(s);
            return *this;
        }
    }
    m_p = reinterpret_cast<uintptr_t>(new std::string(v)) | 1;
    return *this;
}

const std::string& content_type_ref::str() const
{
    static const std::string none;
    return m_p ? *ptr() : none;
}

void object_checksum::set(checksum_algo a, std::string_view raw, uint16_t composite_count)
{
    // The bytes may be this checksum's own, so they are kept before its storage is let go.
    uint8_t keep[32]{};
    if (!raw.empty())
        std::memcpy(keep, raw.data(), std::min(raw.size(), sizeof keep));
    release();
    algo      = a;
    composite = composite_count;
    uint8_t* to = m_small;
    if (big())
        to = m_big = new uint8_t[32]{};
    else
        std::memset(m_small, 0, sizeof m_small);
    std::memcpy(to, keep, std::min<size_t>(checksum_raw_len(a), sizeof keep));
}

std::string object_checksum::b64() const
{
    if (algo == checksum_algo::none)
        return {};
    std::string v = base64::encode(raw_bytes());
    if (composite)
        v += "-" + std::to_string(composite);
    return v;
}

std::string_view tags_of(const object_meta& m)
{
    for (const auto& [n, v] : m.extra)
        if (n == tags_extra)
            return v;
    return {};
}

void set_tags_extra(object_meta& m, std::string_view tags)
{
    std::string kept(tags);
    erase_if(m.extra, [](const auto& e) { return e.first == tags_extra; });
    if (!kept.empty())
        m.extra.emplace_back(std::string(tags_extra), std::move(kept));
}

bool tier_of(const object_meta& m, tier_record& out)
{
    for (const auto& [n, v] : m.extra)
        if (n == tier_extra)
        {
            const size_t semi = v.find(';');
            if (semi == std::string::npos || semi == 0 || semi + 1 == v.size())
                return false;
            out.tier       = v.substr(0, semi);
            out.remote_key = v.substr(semi + 1);
            return true;
        }
    return false;
}

void set_tier_record(object_meta& m, const tier_record* r)
{
    erase_if(m.extra, [](const auto& e) { return e.first == tier_extra; });
    if (r)
        m.extra.emplace_back(std::string(tier_extra), r->tier + ";" + r->remote_key);
}

std::string_view storage_class_of(const object_meta& m)
{
    std::string_view kept;
    for (const auto& [n, v] : m.extra)
    {
        if (n == tier_extra)
            return std::string_view(v).substr(0, v.find(';'));
        if (n == class_extra)
            kept = v;
    }
    return kept.empty() ? std::string_view("STANDARD") : kept;
}

std::string_view kept_class(std::string_view asked)
{
    static constexpr std::string_view kept[] = {
        "REDUCED_REDUNDANCY", "STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER_IR", "EXPRESS_ONEZONE",
    };
    for (std::string_view k : kept)
        if (asked == k)
            return k;
    return {};
}

void set_class_extra(object_meta& m, std::string_view cls)
{
    erase_if(m.extra, [](const auto& e) { return e.first == class_extra; });
    if (!cls.empty())
        m.extra.emplace_back(std::string(class_extra), std::string(cls));
}

void encode_meta(std::string& out, std::string_view key, const object_meta& m)
{
    bytes::append64(out, m.size);
    bytes::append64(out, static_cast<uint64_t>(m.mtime_ms));
    out.append(reinterpret_cast<const char*>(m.md5.data()), 16);
    bytes::append32(out, m.parts);
    put_str(out, key);
    put_str(out, m.content_type.str());
    bytes::append32(out, static_cast<uint32_t>(m.extra.size() + (m.checksum ? 1 : 0)));
    for (const auto& [n, v] : m.extra)
    {
        put_str(out, n);
        put_str(out, v);
    }
    if (m.checksum)
    {
        put_str(out, checksum_header(m.checksum.algo));
        put_str(out, m.checksum.b64());
    }
}

std::string encode_part_sizes(const std::vector<uint64_t>& sizes, size_t max)
{
    if (sizes.empty())
        return {};
    bool uniform = true;
    for (size_t i = 1; i + 1 < sizes.size(); ++i)
        uniform = uniform && sizes[i] == sizes[0];
    if (uniform)
        return std::to_string(sizes[0]);
    std::string out;
    for (uint64_t s : sizes)
    {
        if (!out.empty())
            out += ',';
        out += std::to_string(s);
        if (out.size() > max)
            return {};
    }
    return out;
}

namespace
{

// Sixteen hex digits of order, 'm' or 'v', then the id.
constexpr size_t version_seq_digits = 16;

const std::string* version_value(const object_meta& m)
{
    for (const auto& [n, v] : m.extra)
        if (n == version_extra)
            return &v;
    return nullptr;
}

}   // namespace

bool valid_version_id(std::string_view id)
{
    if (id == "null")
        return true;
    if (id.size() != 32)
        return false;
    for (char c : id)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    return true;
}

bool version_of_id(std::string_view id, bool marker, version_tag& out)
{
    if (id == "null" || !valid_version_id(id))
        return false;
    uint64_t seq = 0;
    for (char c : id.substr(0, 16))
        seq = seq << 4 | static_cast<uint64_t>(c <= '9' ? c - '0' : c - 'a' + 10);
    out.seq    = seq;
    out.id     = std::string(id);
    out.marker = marker;
    return seq != 0;
}

std::string_view replica_source_of(const object_meta& m)
{
    for (const auto& [n, v] : m.extra)
        if (n == replica_version_extra)
            return v;
    return {};
}

namespace
{

// The order and id the version entry of `m` holds, false for an object with none or one that does not parse.
bool parse_version(const object_meta& m, uint64_t& seq, std::string_view& id, bool& marker)
{
    const std::string* v = version_value(m);
    if (!v || v->size() <= version_seq_digits + 1 || ((*v)[version_seq_digits] != 'm' && (*v)[version_seq_digits] != 'v'))
        return false;
    const auto r = std::from_chars(v->data(), v->data() + version_seq_digits, seq, 16);
    id = std::string_view(*v).substr(version_seq_digits + 1);
    marker = (*v)[version_seq_digits] == 'm';
    return r.ec == std::errc{} && r.ptr == v->data() + version_seq_digits && valid_version_id(id);
}

// The order of the null version an object written without versioning is.
uint64_t null_seq(const object_meta& m)
{
    return m.mtime_ms > 0 ? static_cast<uint64_t>(m.mtime_ms) * 1000 : 0;
}

}   // namespace

version_tag version_of(const object_meta& m)
{
    version_tag t;
    std::string_view id;
    if (parse_version(m, t.seq, id, t.marker))
    {
        t.id = std::string(id);
        return t;
    }
    t.seq    = null_seq(m);
    t.id     = "null";
    t.marker = false;
    return t;
}

std::string_view version_id_of(const object_meta& m)
{
    uint64_t seq = 0;
    std::string_view id;
    bool marker = false;
    return parse_version(m, seq, id, marker) ? id : std::string_view("null");
}

uint64_t version_seq_of(const object_meta& m)
{
    uint64_t seq = 0;
    std::string_view id;
    bool marker = false;
    return parse_version(m, seq, id, marker) ? seq : null_seq(m);
}

bool has_version(const object_meta& m)
{
    return version_value(m) != nullptr;
}

bool is_delete_marker(const object_meta& m)
{
    const std::string* v = version_value(m);
    return v && v->size() > version_seq_digits && (*v)[version_seq_digits] == 'm';
}

void set_version_extra(object_meta& m, const version_tag& v)
{
    char seq[version_seq_digits + 1];
    std::snprintf(seq, sizeof seq, "%016llx", static_cast<unsigned long long>(v.seq));
    std::string value(seq, version_seq_digits);
    value.push_back(v.marker ? 'm' : 'v');
    value += v.id;
    clear_version_extra(m);
    m.extra.emplace_back(std::string(version_extra), std::move(value));
}

void clear_version_extra(object_meta& m)
{
    erase_if(m.extra, [](const auto& e) { return e.first == version_extra; });
}

std::string cluster_stamp_text(const cluster_stamp& s)
{
    char seq[version_seq_digits + 1];
    std::snprintf(seq, sizeof seq, "%016llx", static_cast<unsigned long long>(s.tag.seq));
    std::string value(seq, version_seq_digits);
    value.push_back(s.tag.marker ? 'm' : 'v');
    value += s.tag.id;
    value.push_back(' ');
    value += std::to_string(s.mtime_ms);
    return value;
}

bool parse_cluster_stamp(std::string_view text, cluster_stamp& out)
{
    const size_t sp = text.find(' ');
    if (sp == std::string_view::npos || sp <= version_seq_digits + 1 ||
        (text[version_seq_digits] != 'm' && text[version_seq_digits] != 'v'))
        return false;
    uint64_t seq = 0;
    const auto r = std::from_chars(text.data(), text.data() + version_seq_digits, seq, 16);
    const std::string_view id = text.substr(version_seq_digits + 1, sp - version_seq_digits - 1);
    int64_t mtime = 0;
    const std::string_view ms = text.substr(sp + 1);
    const auto m = std::from_chars(ms.data(), ms.data() + ms.size(), mtime);
    if (r.ec != std::errc{} || r.ptr != text.data() + version_seq_digits || !valid_version_id(id) || seq == 0 ||
        m.ec != std::errc{} || m.ptr != ms.data() + ms.size() || mtime <= 0)
        return false;
    out.tag.seq    = seq;
    out.tag.id     = std::string(id);
    out.tag.marker = text[version_seq_digits] == 'm';
    out.mtime_ms   = mtime;
    return true;
}

bool cluster_stamp_of(const object_meta& m, cluster_stamp& out)
{
    for (const auto& [n, v] : m.extra)
        if (n == cluster_extra)
            return parse_cluster_stamp(v, out);
    return false;
}

void set_cluster_extra(object_meta& m, const cluster_stamp& s)
{
    clear_cluster_extra(m);
    m.extra.emplace_back(std::string(cluster_extra), cluster_stamp_text(s));
}

void clear_cluster_extra(object_meta& m)
{
    erase_if(m.extra, [](const auto& e) { return e.first == cluster_extra; });
}

std::string retention_value(const retention& r)
{
    if (r.mode == lock_mode::none)
        return {};
    return (r.mode == lock_mode::governance ? "G" : "C") + std::to_string(r.until_ms);
}

bool retention_from_value(std::string_view v, retention& out)
{
    out = retention{};
    if (v.size() < 2 || (v[0] != 'G' && v[0] != 'C'))
        return false;
    int64_t until = 0;
    const auto p = std::from_chars(v.data() + 1, v.data() + v.size(), until);
    if (p.ec != std::errc{} || p.ptr != v.data() + v.size())
        return false;
    out.mode     = v[0] == 'G' ? lock_mode::governance : lock_mode::compliance;
    out.until_ms = until;
    return true;
}

retention retention_of(const object_meta& m)
{
    retention r;
    for (const auto& [n, v] : m.extra)
        if (n == retention_extra && retention_from_value(v, r))
            return r;
    return {};
}

void set_retention_extra(object_meta& m, const retention& r)
{
    erase_if(m.extra, [](const auto& e) { return e.first == retention_extra; });
    if (r.mode != lock_mode::none)
        m.extra.emplace_back(std::string(retention_extra), retention_value(r));
}

std::string_view legal_hold_of(const object_meta& m)
{
    for (const auto& [n, v] : m.extra)
        if (n == legal_hold_extra)
            return v;
    return {};
}

void set_legal_hold_extra(object_meta& m, std::string_view status)
{
    std::string kept(status);
    erase_if(m.extra, [](const auto& e) { return e.first == legal_hold_extra; });
    if (!kept.empty())
        m.extra.emplace_back(std::string(legal_hold_extra), std::move(kept));
}

std::string_view replication_status_of(const object_meta& m)
{
    for (const auto& [n, v] : m.extra)
        if (n == replication_status_extra)
            return v;
    return {};
}

void set_replication_status(object_meta& m, std::string_view status)
{
    std::string kept(status);
    erase_if(m.extra, [](const auto& e) { return e.first == replication_status_extra; });
    if (!kept.empty())
        m.extra.emplace_back(std::string(replication_status_extra), std::move(kept));
}

bool has_lock_extra(const object_meta& m)
{
    for (const auto& [n, v] : m.extra)
        if (n == retention_extra || n == legal_hold_extra)
            return true;
    return false;
}

void clear_lock_extras(object_meta& m)
{
    erase_if(m.extra, [](const auto& e) { return e.first == retention_extra || e.first == legal_hold_extra; });
}

bool lock_holds(const object_meta& m, int64_t now_ms, bool bypass)
{
    if (!has_lock_extra(m))
        return false;
    if (legal_hold_of(m) == "ON")
        return true;
    const retention r = retention_of(m);
    if (r.mode == lock_mode::none || r.until_ms <= now_ms)
        return false;
    return r.mode == lock_mode::compliance || !bypass;
}

bool retention_change_allowed(const retention& cur, const retention& want, int64_t now_ms, bool bypass)
{
    if (cur.mode == lock_mode::none || cur.until_ms <= now_ms)
        return true;
    if (cur.mode == lock_mode::compliance)
        return want.mode == lock_mode::compliance && want.until_ms >= cur.until_ms;
    return (want.mode == lock_mode::governance && want.until_ms >= cur.until_ms) || bypass;
}

std::string version_rel_path(std::string_view key, std::string_view id)
{
    const std::string h = key_hash(key);
    std::string p = "versions/";
    p.append(h, 0, 2);
    p.push_back('/');
    p.append(h);
    p.push_back('.');
    p.append(id);
    return p;
}

namespace
{

const std::string* extra_of(const object_meta& m, std::string_view name)
{
    for (const auto& [n, v] : m.extra)
        if (n == name)
            return &v;
    return nullptr;
}

// Hands each item of a comma-separated list to `take`, false when one is refused.
template <typename F>
bool each_item(std::string_view v, F take)
{
    for (;;)
    {
        const size_t comma = v.find(',');
        if (!take(v.substr(0, comma)))
            return false;
        if (comma == std::string_view::npos)
            return true;
        v.remove_prefix(comma + 1);
    }
}

// The width of the list's checksums, 0 unless every part has one and all are as wide.
uint32_t checksum_width(const part_list& l)
{
    if (l.checksums.empty() || l.checksums.size() != l.sizes.size())
        return 0;
    for (const std::string& c : l.checksums)
        if (c.empty() || c.size() != l.checksums.front().size())
            return 0;
    return static_cast<uint32_t>(l.checksums.front().size());
}

// The checksums the header of `m` keeps of its `count` parts, a single-part object's being its own.
void header_checksums(const object_meta& m, uint32_t count, std::vector<std::string>& out)
{
    const checksum_algo a = checksum_algo_of(m);
    if (a == checksum_algo::none)
        return;
    const size_t width = checksum_raw_len(a);
    if (!m.parts)
    {
        // A composite value is of parts a copy no longer has, so it is no part's checksum.
        if (!m.checksum.composite && count == 1)
            out.emplace_back(m.checksum.raw_bytes());
        return;
    }
    const std::string* v = extra_of(m, part_checksums_extra);
    std::string raw;
    if (!v || !base64::decode(*v, raw) || raw.size() != width * count)
        return;
    for (uint32_t i = 0; i < count; ++i)
        out.push_back(raw.substr(i * width, width));
}

}   // namespace

checksum_algo checksum_algo_of(const object_meta& m)
{
    return m.checksum.algo;
}

std::string encode_part_numbers(const std::vector<uint32_t>& numbers, size_t max)
{
    bool plain = true;
    for (size_t i = 0; i < numbers.size(); ++i)
        plain = plain && numbers[i] == i + 1;
    if (plain)
        return {};
    std::string out;
    for (size_t i = 0; i < numbers.size();)
    {
        size_t j = i;
        while (j + 1 < numbers.size() && numbers[j + 1] == numbers[j] + 1)
            ++j;
        if (!out.empty())
            out += ',';
        out += std::to_string(numbers[i]);
        if (j > i)
            out += '-' + std::to_string(numbers[j]);
        if (out.size() > max)
            return {};
        i = j + 1;
    }
    return out;
}

bool part_list_of(const object_meta& m, part_list& out)
{
    out.numbers.clear();
    out.sizes.clear();
    out.checksums.clear();
    const uint32_t count = m.parts ? m.parts : 1;
    if (count == 1)
        out.sizes.push_back(m.size);
    else
    {
        const std::string* v = extra_of(m, part_sizes_extra);
        if (!v || v->empty())
            return false;
        if (v->find(',') == std::string::npos)
        {
            uint64_t each = 0;
            if (!socketley::parse_whole(*v, each) || each == 0 || each > m.size / (count - 1))
                return false;
            out.sizes.assign(count - 1, each);
            out.sizes.push_back(m.size - each * (count - 1));
        }
        else
        {
            // A list that does not add up to the object is trusted for no part of it.
            uint64_t total = 0;
            const bool ok = each_item(*v, [&](std::string_view item)
            {
                uint64_t s = 0;
                if (!socketley::parse_whole(item, s) || s > m.size - total || out.sizes.size() == count)
                    return false;
                total += s;
                out.sizes.push_back(s);
                return true;
            });
            if (!ok || out.sizes.size() != count || total != m.size)
                return false;
        }
    }
    const std::string* nv = extra_of(m, part_numbers_extra);
    if (!nv)
    {
        for (uint32_t i = 1; i <= count; ++i)
            out.numbers.push_back(i);
    }
    else
    {
        // Ascending and within S3's bounds, which is all a completion can have recorded.
        const bool ok = each_item(*nv, [&](std::string_view item)
        {
            const size_t dash = item.find('-');
            uint64_t lo = 0, hi = 0;
            if (!socketley::parse_whole(item.substr(0, dash), lo))
                return false;
            if (dash == std::string_view::npos)
                hi = lo;
            else if (!socketley::parse_whole(item.substr(dash + 1), hi))
                return false;
            if (lo < 1 || hi < lo || hi > 10000 || (!out.numbers.empty() && lo <= out.numbers.back()) ||
                out.numbers.size() + (hi - lo + 1) > count)
                return false;
            for (uint64_t n = lo; n <= hi; ++n)
                out.numbers.push_back(static_cast<uint32_t>(n));
            return true;
        });
        if (!ok || out.numbers.size() != count)
            return false;
    }
    header_checksums(m, count, out.checksums);
    return true;
}

void clear_part_layout(object_meta& m)
{
    erase_if(m.extra, [](const auto& e)
                  {
                      return e.first == part_sizes_extra || e.first == part_numbers_extra ||
                             e.first == part_checksums_extra || e.first == part_layout_extra ||
                             e.first == sse_parts_extra || e.first == upload_id_extra || e.first == lz4_extra ||
                             e.first == tier_extra;
                  });
}

bool copy_checksum(object_meta& copy, const object_meta& src, checksum_algo algo)
{
    erase_if(copy.extra, [](const auto& e) { return is_checksum_header(e.first); });
    copy.checksum = {};
    if (algo == checksum_algo::none)
        return false;
    // A composite value, with its -N, is of the source's parts and not of the bytes the copy holds.
    const bool whole = src.checksum.algo == algo && !src.checksum.composite;
    if (whole)
        copy.checksum = src.checksum;
    else
        reserve_checksum(copy, algo);
    return !whole;
}

void set_checksum(object_meta& m, checksum_algo algo, std::string_view raw)
{
    m.checksum.set(algo, raw);
}

void set_checksum_b64(object_meta& m, checksum_algo algo, std::string b64)
{
    if (parse_checksum(algo, b64, m.checksum))
        return;
    m.checksum = {};
    m.extra.emplace_back(std::string(checksum_header(algo)), std::move(b64));
}

size_t checksum_meta_bytes(const object_meta& m)
{
    return m.checksum ? checksum_header(m.checksum.algo).size() + m.checksum.b64().size() : 0;
}

void reserve_checksum(object_meta& m, checksum_algo algo, uint16_t composite)
{
    m.checksum.set(algo, {}, composite);
}

bool part_trailer_of(const object_meta& m, part_trailer& out)
{
    const std::string* v = extra_of(m, part_layout_extra);
    // No upload has more parts than S3's 10000, so a count past it is a meta not to size a read by.
    if (!v || m.parts == 0 || m.parts > 10000)
        return false;
    const std::string_view s(*v);
    const size_t semi  = s.find(';');
    const size_t semi2 = semi == std::string_view::npos ? semi : s.find(';', semi + 1);
    const std::string_view hexd = semi == std::string_view::npos ? std::string_view{}
                                                                  : s.substr(semi + 1, semi2 - semi - 1);
    uint64_t width = 0;
    if (!socketley::parse_whole(s.substr(0, semi), out.at) || hexd.size() != 2 * out.digest.size() ||
        (semi2 != std::string_view::npos && (!socketley::parse_whole(s.substr(semi2 + 1), width) || width == 0 || width > 64)))
        return false;
    for (size_t i = 0; i < out.digest.size(); ++i)
    {
        uint64_t b = 0;
        const auto r = std::from_chars(hexd.data() + 2 * i, hexd.data() + 2 * i + 2, b, 16);
        if (r.ec != std::errc{} || r.ptr != hexd.data() + 2 * i + 2)
            return false;
        out.digest[i] = static_cast<uint8_t>(b);
    }
    out.width = static_cast<uint32_t>(width);
    out.len   = width ? part_list_sums_magic.size() + 16 + (12 + width) * m.parts
                      : part_list_magic.size() + 12 + 12ull * m.parts;
    return true;
}

bool decode_part_trailer(std::string_view bytes, const object_meta& m, const part_trailer& t, part_list& out)
{
    const std::string_view magic = t.width ? part_list_sums_magic : part_list_magic;
    if (bytes.size() != t.len || bytes.substr(0, magic.size()) != magic)
        return false;
    digest_stream d(fetched_sha256());
    d.update(bytes.data(), bytes.size());
    if (d.finish<32>() != t.digest)
        return false;
    reader r{bytes.substr(magic.size())};
    const uint64_t total = r.u64();
    const uint32_t count = r.u32();
    const uint32_t width = t.width ? r.u32() : 0;
    if (!r.ok || total != m.size || count != m.parts || width != t.width)
        return false;
    out.numbers.clear();
    out.sizes.clear();
    out.checksums.clear();
    uint64_t sum = 0;
    for (uint32_t i = 0; i < count; ++i)
    {
        const uint32_t n = r.u32();
        const uint64_t s = r.u64();
        const std::string_view sum_of_part = r.raw(width);
        if (!r.ok || n < 1 || n > 10000 || (!out.numbers.empty() && n <= out.numbers.back()) || s > total - sum)
            return false;
        sum += s;
        out.numbers.push_back(n);
        out.sizes.push_back(s);
        if (width)
            out.checksums.emplace_back(sum_of_part);
    }
    return r.in.empty() && sum == total;
}

std::string record_part_list(object_meta& m, const part_list& l, uint64_t body_stored, bool numbers, size_t max)
{
    clear_part_layout(m);
    bool one_to_n = true;
    for (size_t i = 0; i < l.numbers.size(); ++i)
        one_to_n = one_to_n && l.numbers[i] == i + 1;
    std::string sizes = encode_part_sizes(l.sizes, max);
    std::string nums  = numbers && !one_to_n ? encode_part_numbers(l.numbers, max) : std::string{};
    const uint32_t width = checksum_width(l);
    std::string sums;
    for (size_t i = 0; width && i < l.checksums.size(); ++i)
        sums += l.checksums[i];
    sums = sums.empty() ? std::string{} : base64::encode(sums);
    if (!sizes.empty() && (!numbers || one_to_n || !nums.empty()) && sums.size() <= max)
    {
        m.extra.emplace_back(std::string(part_sizes_extra), std::move(sizes));
        if (!nums.empty())
            m.extra.emplace_back(std::string(part_numbers_extra), std::move(nums));
        if (!sums.empty())
            m.extra.emplace_back(std::string(part_checksums_extra), std::move(sums));
        return {};
    }
    std::string bytes = encode_part_list(l, m.size);
    digest_stream d(fetched_sha256());
    d.update(bytes.data(), bytes.size());
    const auto h = d.finish<32>();
    std::string layout = std::to_string(body_stored) + ";" + hex(h.data(), h.size());
    if (width)
        layout += ";" + std::to_string(width);
    m.extra.emplace_back(std::string(part_layout_extra), std::move(layout));
    return bytes;
}

std::string encode_part_list(const part_list& l, uint64_t total)
{
    const uint32_t width = checksum_width(l);
    std::string out(width ? part_list_sums_magic : part_list_magic);
    bytes::append64(out, total);
    bytes::append32(out, static_cast<uint32_t>(l.sizes.size()));
    if (width)
        bytes::append32(out, width);
    for (size_t i = 0; i < l.sizes.size(); ++i)
    {
        bytes::append32(out, i < l.numbers.size() ? l.numbers[i] : 0);
        bytes::append64(out, l.sizes[i]);
        if (width)
            out += l.checksums[i];
    }
    return out;
}

part_status part_range(const object_meta& m, uint32_t n, uint64_t& first, uint64_t& len, part_list* list)
{
    const uint32_t count = m.parts ? m.parts : 1;
    if (n < 1 || n > count)
        return part_status::out_of_range;
    part_trailer t;
    if (part_trailer_of(m, t))
        return part_status::in_trailer;
    part_list own;
    part_list& l = list ? *list : own;
    if (!part_list_of(m, l))
        return part_status::unknown;
    return part_range_in(l, n, first, len);
}

part_status part_range_in(const part_list& l, uint32_t n, uint64_t& first, uint64_t& len)
{
    if (n < 1 || n > l.sizes.size())
        return part_status::out_of_range;
    first = 0;
    for (uint32_t i = 0; i + 1 < n; ++i)
        first += l.sizes[i];
    len = l.sizes[n - 1];
    return part_status::ok;
}

size_t object_header_len(std::string_view key, const object_meta& m)
{
    std::string body;
    encode_meta(body, key, m);
    const size_t used = prelude_len + body.size();
    return (used + object_header_align - 1) / object_header_align * object_header_align;
}

std::string encode_object_header(std::string_view key, const object_meta& m, size_t min_len)
{
    std::string body;
    encode_meta(body, key, m);

    size_t len = (prelude_len + body.size() + object_header_align - 1) /
                 object_header_align * object_header_align;
    if (len < min_len)
        len = (min_len + object_header_align - 1) / object_header_align * object_header_align;

    std::string h;
    h.reserve(len);
    h.append(object_magic);
    bytes::append32(h, object_version);
    bytes::append32(h, static_cast<uint32_t>(len));
    bytes::append32(h, static_cast<uint32_t>(body.size()));
    // Over the prelude before the checksum and then the body, so a flipped bit
    // anywhere in what the header says is caught.
    uint32_t crc = crc::crc32c(h.data(), h.size());
    crc          = crc::crc32c(body.data(), body.size(), crc);
    bytes::append32(h, crc);
    h.append(body);
    h.resize(len, '\0');
    return h;
}

decoded_header decode_object_header(std::string_view bytes)
{
    decoded_header d;
    if (bytes.size() < prelude_len)
    {
        d.status = header_status::need_more;
        d.need   = prelude_len;
        return d;
    }
    if (bytes.substr(0, 8) != object_magic)
        return d;

    uint32_t version, header_len, body_len, crc;
    std::memcpy(&version, bytes.data() + 8, 4);
    std::memcpy(&header_len, bytes.data() + 12, 4);
    std::memcpy(&body_len, bytes.data() + 16, 4);
    std::memcpy(&crc, bytes.data() + 20, 4);
    if (version != object_version || header_len < prelude_len + body_len ||
        header_len % object_header_align != 0 || header_len > 64 * 1024)
        return d;

    if (bytes.size() < prelude_len + body_len)
    {
        d.status = header_status::need_more;
        d.need   = prelude_len + body_len;
        return d;
    }
    const std::string_view body = bytes.substr(prelude_len, body_len);
    uint32_t want = crc::crc32c(bytes.data(), 20);
    want          = crc::crc32c(body.data(), body.size(), want);
    if (want != crc)
        return d;
    if (!decode_meta(body, d.key, d.meta))
        return d;

    d.header_len = header_len;
    d.meta_end   = prelude_len + body_len;
    d.status     = header_status::ok;

    // The newest whole slot within the bytes given wins over the tags the header was written with.
    const slot_layout l = layout_of(d.meta_end, header_len);
    std::string_view tags;
    for (int i = 0; i < 2 && l.room; ++i)
    {
        const size_t off = l.off[i];
        if (bytes.size() < off + slot_head ||
            (bytes.substr(off, 8) != slot_magic && bytes.substr(off, 8) != lock_slot_magic &&
             bytes.substr(off, 8) != repl_slot_magic))
            continue;
        uint64_t seq;
        uint32_t len, scrc;
        std::memcpy(&seq, bytes.data() + off + 8, 8);
        std::memcpy(&len, bytes.data() + off + 16, 4);
        std::memcpy(&scrc, bytes.data() + off + 20, 4);
        if (slot_head + len > l.room || bytes.size() < off + slot_head + len || seq <= d.tag_seq)
            continue;
        const std::string_view payload = bytes.substr(off + slot_head, len);
        uint32_t c = crc::crc32c(bytes.data() + off, 20);
        c          = crc::crc32c(payload.data(), payload.size(), c);
        if (c != scrc)
            continue;
        const bool repl = bytes.substr(off, 8) == repl_slot_magic;
        if (repl || bytes.substr(off, 8) == lock_slot_magic)
        {
            reader r{payload};
            r.str();
            r.str();
            r.str();
            if (repl)
                r.str();
            if (!r.ok || !r.in.empty())
                continue;
        }
        d.tag_slot  = static_cast<int8_t>(i);
        d.tag_seq   = seq;
        d.repl_slot = repl;
        d.lock_slot = repl || bytes.substr(off, 8) == lock_slot_magic;
        tags        = payload;
    }
    if (d.tag_slot < 0)
        return d;
    if (!d.lock_slot)
    {
        set_tags_extra(d.meta, tags);
        return d;
    }
    reader r{tags};
    const std::string_view t    = r.str();
    const std::string_view ret  = r.str();
    const std::string_view hold = r.str();
    set_tags_extra(d.meta, t);
    erase_if(d.meta.extra, [](const auto& e) { return e.first == retention_extra; });
    if (!ret.empty())
        d.meta.extra.emplace_back(std::string(retention_extra), std::string(ret));
    set_legal_hold_extra(d.meta, hold);
    if (d.repl_slot)
        set_replication_status(d.meta, r.str());
    return d;
}

std::string encode_tag_slot(const decoded_header& d, const object_meta& want, uint64_t& at)
{
    const slot_layout l = layout_of(d.meta_end, d.header_len);
    if (d.status != header_status::ok || l.room == 0)
        return {};
    // The tags alone while no lock was ever recorded, so a header no version of the lock touched reads as it did.
    const bool repl = d.repl_slot || !replication_status_of(d.meta).empty() || !replication_status_of(want).empty();
    const bool lock = repl || d.lock_slot || has_lock_extra(d.meta) || has_lock_extra(want);
    std::string payload;
    if (lock)
    {
        std::string ret;
        for (const auto& [n, v] : want.extra)
            if (n == retention_extra)
                ret = v;
        put_str(payload, tags_of(want));
        put_str(payload, ret);
        put_str(payload, legal_hold_of(want));
        if (repl)
            put_str(payload, replication_status_of(want));
    }
    else
        payload = std::string(tags_of(want));
    if (slot_head + payload.size() > l.room)
        return {};
    std::string s(repl ? repl_slot_magic : lock ? lock_slot_magic : slot_magic);
    bytes::append64(s, d.tag_seq + 1);
    bytes::append32(s, static_cast<uint32_t>(payload.size()));
    uint32_t c = crc::crc32c(s.data(), s.size());
    c          = crc::crc32c(payload.data(), payload.size(), c);
    bytes::append32(s, c);
    s.append(payload);
    at = l.off[d.tag_slot == 0 ? 1 : 0];
    return s;
}

std::string encode_tag_slot(const decoded_header& d, std::string_view tags, uint64_t& at)
{
    object_meta want = d.meta;
    set_tags_extra(want, tags);
    return encode_tag_slot(d, want, at);
}

std::string encode_journal_header(uint32_t shard, uint32_t nshards)
{
    std::string h(journal_magic);
    bytes::append32(h, journal_format);
    bytes::append32(h, shard);
    bytes::append32(h, nshards);
    bytes::append32(h, 0);
    return h;
}

journal_header_status journal_header_check(std::string_view bytes, uint32_t shard, uint32_t nshards,
                                           uint32_t* format)
{
    if (bytes.size() < journal_header_len || bytes.substr(0, 8) != journal_magic)
        return journal_header_status::bad;
    uint32_t version, sh, n;
    std::memcpy(&version, bytes.data() + 8, 4);
    std::memcpy(&sh, bytes.data() + 12, 4);
    std::memcpy(&n, bytes.data() + 16, 4);
    if ((version != 2 && version != journal_format) || n == 0)
        return journal_header_status::bad;
    if (format)
        *format = version;
    if (sh != shard || n != nshards)
        return journal_header_status::other_layout;
    return journal_header_status::ok;
}

namespace
{

void frame_record(std::string& out, std::string_view payload)
{
    bytes::append32(out, static_cast<uint32_t>(payload.size()));
    bytes::append32(out, crc::crc32c(payload.data(), payload.size()));
    out.append(payload);
}

}   // namespace

void encode_put_record(std::string& out, std::string_view key, const object_meta& m)
{
    std::string p;
    p.push_back(static_cast<char>(record_type::put));
    encode_meta(p, key, m);
    frame_record(out, p);
}

void encode_delete_record(std::string& out, std::string_view key, int64_t mtime_ms)
{
    std::string p;
    p.push_back(static_cast<char>(record_type::del));
    bytes::append64(p, static_cast<uint64_t>(mtime_ms));
    put_str(p, key);
    frame_record(out, p);
}

void encode_version_record(std::string& out, std::string_view key, const object_meta& m)
{
    std::string p;
    p.push_back(static_cast<char>(record_type::vput));
    encode_meta(p, key, m);
    frame_record(out, p);
}

void encode_version_drop_record(std::string& out, std::string_view key, std::string_view version_id)
{
    std::string p;
    p.push_back(static_cast<char>(record_type::vdel));
    put_str(p, key);
    put_str(p, version_id);
    frame_record(out, p);
}

decoded_record decode_journal_record(std::string_view bytes)
{
    decoded_record d;
    if (bytes.size() < 8)
        return d;

    uint32_t len, crc;
    std::memcpy(&len, bytes.data(), 4);
    std::memcpy(&crc, bytes.data() + 4, 4);
    if (len == 0 || len > max_record_bytes)
    {
        d.status = record_status::corrupt;
        return d;
    }
    if (bytes.size() < 8u + len)
        return d;

    const std::string_view payload = bytes.substr(8, len);
    if (crc::crc32c(payload.data(), payload.size()) != crc)
    {
        d.status = record_status::corrupt;
        return d;
    }

    const auto type = static_cast<record_type>(static_cast<uint8_t>(payload[0]));
    const std::string_view rest = payload.substr(1);
    d.rec.type = type;
    if (type == record_type::put || type == record_type::vput)
    {
        if (!decode_meta(rest, d.rec.key, d.rec.meta))
        {
            d.status = record_status::corrupt;
            return d;
        }
    }
    else if (type == record_type::vdel)
    {
        reader r{rest};
        d.rec.key        = std::string(r.str());
        d.rec.version_id = std::string(r.str());
        if (!r.ok || !r.in.empty() || !valid_version_id(d.rec.version_id))
        {
            d.status = record_status::corrupt;
            return d;
        }
    }
    else if (type == record_type::del)
    {
        reader r{rest};
        d.rec.mtime_ms = static_cast<int64_t>(r.u64());
        d.rec.key      = std::string(r.str());
        if (!r.ok || !r.in.empty())
        {
            d.status = record_status::corrupt;
            return d;
        }
    }
    else
    {
        d.status = record_status::corrupt;
        return d;
    }

    d.consumed = 8u + len;
    d.status   = record_status::ok;
    return d;
}

std::string key_hash(std::string_view key)
{
    return sha256_hex(key);
}

std::string object_rel_path(std::string_view key)
{
    const std::string h = key_hash(key);
    std::string p;
    p.reserve(h.size() + 3);
    p.append(h, 0, 2);
    p.push_back('/');
    p.append(h);
    return p;
}

}   // namespace socketley::storage
