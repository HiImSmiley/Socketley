#include "object_format.h"

#include <algorithm>
#include <cstring>

#include "../../shared/raft_storage.h"

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

void put_u32(std::string& out, uint32_t v)
{
    char b[4];
    std::memcpy(b, &v, 4);
    out.append(b, 4);
}

void put_u64(std::string& out, uint64_t v)
{
    char b[8];
    std::memcpy(b, &v, 8);
    out.append(b, 8);
}

void put_str(std::string& out, std::string_view s)
{
    put_u32(out, static_cast<uint32_t>(s.size()));
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
        const uint32_t n = u32();
        if (!ok || in.size() < n) { ok = false; return {}; }
        std::string_view s = in.substr(0, n);
        in.remove_prefix(n);
        return s;
    }
};

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
    m.content_type = std::string(r.str());
    const uint32_t n = r.u32();
    if (!r.ok || n > 4096)
        return false;
    m.extra.clear();
    for (uint32_t i = 0; i < n; ++i)
    {
        std::string name(r.str());
        std::string val(r.str());
        if (!r.ok)
            return false;
        m.extra.emplace_back(std::move(name), std::move(val));
    }
    return r.ok && r.in.empty() && key.size() <= max_key_bytes;
}

}   // namespace

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
    std::erase_if(m.extra, [](const auto& e) { return e.first == tags_extra; });
    if (!kept.empty())
        m.extra.emplace_back(std::string(tags_extra), std::move(kept));
}

void encode_meta(std::string& out, std::string_view key, const object_meta& m)
{
    put_u64(out, m.size);
    put_u64(out, static_cast<uint64_t>(m.mtime_ms));
    out.append(reinterpret_cast<const char*>(m.md5.data()), 16);
    put_u32(out, m.parts);
    put_str(out, key);
    put_str(out, m.content_type);
    put_u32(out, static_cast<uint32_t>(m.extra.size()));
    for (const auto& [n, v] : m.extra)
    {
        put_str(out, n);
        put_str(out, v);
    }
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
    put_u32(h, object_version);
    put_u32(h, static_cast<uint32_t>(len));
    put_u32(h, static_cast<uint32_t>(body.size()));
    // Over the prelude before the checksum and then the body, so a flipped bit
    // anywhere in what the header says is caught.
    uint32_t crc = raft::storage::crc32c(h.data(), h.size());
    crc          = raft::storage::crc32c(body.data(), body.size(), crc);
    put_u32(h, crc);
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
    uint32_t want = raft::storage::crc32c(bytes.data(), 20);
    want          = raft::storage::crc32c(body.data(), body.size(), want);
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
        if (bytes.size() < off + slot_head || bytes.substr(off, 8) != slot_magic)
            continue;
        uint64_t seq;
        uint32_t len, scrc;
        std::memcpy(&seq, bytes.data() + off + 8, 8);
        std::memcpy(&len, bytes.data() + off + 16, 4);
        std::memcpy(&scrc, bytes.data() + off + 20, 4);
        if (slot_head + len > l.room || bytes.size() < off + slot_head + len || seq <= d.tag_seq)
            continue;
        const std::string_view payload = bytes.substr(off + slot_head, len);
        uint32_t c = raft::storage::crc32c(bytes.data() + off, 20);
        c          = raft::storage::crc32c(payload.data(), payload.size(), c);
        if (c != scrc)
            continue;
        d.tag_slot = static_cast<int8_t>(i);
        d.tag_seq  = seq;
        tags       = payload;
    }
    if (d.tag_slot >= 0)
        set_tags_extra(d.meta, tags);
    return d;
}

std::string encode_tag_slot(const decoded_header& d, std::string_view tags, uint64_t& at)
{
    const slot_layout l = layout_of(d.meta_end, d.header_len);
    if (d.status != header_status::ok || l.room == 0 || slot_head + tags.size() > l.room)
        return {};
    std::string s(slot_magic);
    put_u64(s, d.tag_seq + 1);
    put_u32(s, static_cast<uint32_t>(tags.size()));
    uint32_t c = raft::storage::crc32c(s.data(), s.size());
    c          = raft::storage::crc32c(tags.data(), tags.size(), c);
    put_u32(s, c);
    s.append(tags);
    at = l.off[d.tag_slot == 0 ? 1 : 0];
    return s;
}

std::string encode_journal_header(uint32_t shard, uint32_t nshards)
{
    std::string h(journal_magic);
    put_u32(h, 2);
    put_u32(h, shard);
    put_u32(h, nshards);
    put_u32(h, 0);
    return h;
}

journal_header_status journal_header_check(std::string_view bytes, uint32_t shard, uint32_t nshards)
{
    if (bytes.size() < journal_header_len || bytes.substr(0, 8) != journal_magic)
        return journal_header_status::bad;
    uint32_t version, sh, n;
    std::memcpy(&version, bytes.data() + 8, 4);
    std::memcpy(&sh, bytes.data() + 12, 4);
    std::memcpy(&n, bytes.data() + 16, 4);
    if (version != 2 || n == 0)
        return journal_header_status::bad;
    if (sh != shard || n != nshards)
        return journal_header_status::other_layout;
    return journal_header_status::ok;
}

namespace
{

void frame_record(std::string& out, std::string_view payload)
{
    put_u32(out, static_cast<uint32_t>(payload.size()));
    put_u32(out, raft::storage::crc32c(payload.data(), payload.size()));
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
    put_u64(p, static_cast<uint64_t>(mtime_ms));
    put_str(p, key);
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
    if (raft::storage::crc32c(payload.data(), payload.size()) != crc)
    {
        d.status = record_status::corrupt;
        return d;
    }

    const auto type = static_cast<record_type>(static_cast<uint8_t>(payload[0]));
    const std::string_view rest = payload.substr(1);
    d.rec.type = type;
    if (type == record_type::put)
    {
        if (!decode_meta(rest, d.rec.key, d.rec.meta))
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
