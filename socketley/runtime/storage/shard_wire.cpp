#include "shard_wire.h"

#include <algorithm>

#include "../../shared/byte_codec.h"

namespace socketley::storage::wire
{

namespace
{

constexpr size_t name_cap   = 4096;
constexpr size_t query_cap  = 64 * 1024;
constexpr size_t record_cap = 128 * 1024;

bytes::writer begin(op o)
{
    bytes::writer w;
    w.u32(magic);
    w.u8(static_cast<uint8_t>(o));
    return w;
}

// The reader positioned after a request's magic and op, false when either is not
// the one asked for.
bool open_request(bytes::reader& r, op want)
{
    uint32_t m = 0;
    uint8_t  o = 0;
    return r.u32(m) && m == magic && r.u8(o) && o == static_cast<uint8_t>(want);
}

bool decode_record(std::string_view record, std::string& key, object_meta& meta)
{
    const decoded_record d = decode_journal_record(record);
    if (d.status != record_status::ok || d.rec.type != record_type::put || d.consumed != record.size())
        return false;
    key  = d.rec.key;
    meta = d.rec.meta;
    return true;
}

bool status_byte(bytes::reader& r, st& s)
{
    uint8_t b = 0;
    if (!r.u8(b) || b > static_cast<uint8_t>(st::cancelled))
        return false;
    s = static_cast<st>(b);
    return true;
}

}   // namespace

bool request_op(std::string_view payload, op& out)
{
    bytes::reader r(payload);
    uint32_t m = 0;
    uint8_t  o = 0;
    if (!r.u32(m) || m != magic || !r.u8(o) || o < static_cast<uint8_t>(op::commit) ||
        o > static_cast<uint8_t>(op::drop_forget))
        return false;
    out = static_cast<op>(o);
    return true;
}

std::string encode_commit(const commit_request& req)
{
    bytes::writer w = begin(op::commit);
    w.bytes(req.bucket);
    w.bytes(req.key);
    w.bytes(req.tmp_name);
    w.u8(req.create_only ? 1 : 0);
    std::string rec;
    encode_put_record(rec, req.key, req.meta);
    w.bytes(rec);
    return w.take();
}

bool decode_commit(std::string_view payload, commit_request& out)
{
    bytes::reader r(payload);
    std::string rec, key;
    bool create_only = false;
    if (!open_request(r, op::commit) || !r.bytes(out.bucket, name_cap) || !r.bytes(out.key, name_cap) ||
        !r.bytes(out.tmp_name, name_cap) || !r.flag(create_only) || !r.bytes(rec, record_cap))
        return false;
    out.create_only = create_only;
    return decode_record(rec, key, out.meta) && key == out.key;
}

std::string encode_remove(std::string_view bucket, std::string_view key)
{
    bytes::writer w = begin(op::remove);
    w.bytes(bucket);
    w.bytes(key);
    return w.take();
}

bool decode_remove(std::string_view payload, std::string& bucket, std::string& key)
{
    bytes::reader r(payload);
    return open_request(r, op::remove) && r.bytes(bucket, name_cap) && r.bytes(key, name_cap);
}

std::string encode_list(std::string_view bucket, const list_query& q)
{
    bytes::writer w = begin(op::list);
    w.bytes(bucket);
    w.bytes(q.prefix);
    w.bytes(q.delimiter);
    w.bytes(q.start_after);
    w.bytes(q.resume_at);
    w.u8(q.has_resume ? 1 : 0);
    w.u64(q.max_keys);
    return w.take();
}

bool decode_list(std::string_view payload, std::string& bucket, list_query& q)
{
    bytes::reader r(payload);
    bool has_resume = false;
    uint64_t max_keys = 0;
    if (!open_request(r, op::list) || !r.bytes(bucket, name_cap) || !r.bytes(q.prefix, query_cap) ||
        !r.bytes(q.delimiter, query_cap) || !r.bytes(q.start_after, query_cap) ||
        !r.bytes(q.resume_at, query_cap) || !r.flag(has_resume) || !r.u64(max_keys))
        return false;
    q.has_resume = has_resume;
    q.max_keys   = static_cast<size_t>(max_keys);
    return true;
}

std::string encode_bucket(op o, std::string_view bucket, int64_t created_ms)
{
    bytes::writer w = begin(o);
    w.bytes(bucket);
    w.u64(static_cast<uint64_t>(created_ms));
    return w.take();
}

bool decode_bucket(std::string_view payload, std::string& bucket, int64_t& created_ms)
{
    bytes::reader r(payload);
    uint32_t m = 0;
    uint8_t  o = 0;
    uint64_t ms = 0;
    if (!r.u32(m) || m != magic || !r.u8(o) || !r.bytes(bucket, name_cap) || !r.u64(ms))
        return false;
    created_ms = static_cast<int64_t>(ms);
    return true;
}

std::string encode_status(st s)
{
    bytes::writer w;
    w.u8(static_cast<uint8_t>(s));
    return w.take();
}

std::string encode_removed(st s, bool existed)
{
    bytes::writer w;
    w.u8(static_cast<uint8_t>(s));
    w.u8(existed ? 1 : 0);
    return w.take();
}

std::string encode_created(st s, int64_t created_ms)
{
    bytes::writer w;
    w.u8(static_cast<uint8_t>(s));
    w.u64(static_cast<uint64_t>(created_ms));
    return w.take();
}

bool decode_status(std::string_view reply, st& s)
{
    bytes::reader r(reply);
    return status_byte(r, s);
}

bool decode_removed(std::string_view reply, st& s, bool& existed)
{
    bytes::reader r(reply);
    return status_byte(r, s) && r.flag(existed);
}

bool decode_created(std::string_view reply, st& s, int64_t& created_ms)
{
    bytes::reader r(reply);
    uint64_t ms = 0;
    if (!status_byte(r, s) || !r.u64(ms))
        return false;
    created_ms = static_cast<int64_t>(ms);
    return true;
}

void limit_page(list_page& page, size_t max_bytes)
{
    struct entry { const std::string* name; size_t cost; };
    std::vector<entry> all;
    all.reserve(page.objects.size() + page.prefixes.size());
    for (const list_entry& e : page.objects)
    {
        size_t cost = e.key.size() + e.meta.content_type.size() + 96;
        for (const auto& [n, v] : e.meta.extra)
            cost += n.size() + v.size() + 8;
        all.push_back({&e.key, cost});
    }
    for (const std::string& p : page.prefixes)
        all.push_back({&p, p.size() + 8});
    std::sort(all.begin(), all.end(), [](const entry& a, const entry& b) { return *a.name < *b.name; });

    size_t total = 0;
    for (const entry& e : all)
    {
        total += e.cost;
        if (total <= max_bytes)
            continue;
        // The first entry that does not fit is where the page now ends.
        const std::string cutoff = *e.name;
        std::erase_if(page.objects, [&](const list_entry& o) { return o.key >= cutoff; });
        std::erase_if(page.prefixes, [&](const std::string& p) { return p >= cutoff; });
        page.truncated = true;
        page.resume_at = cutoff;
        return;
    }
}

std::string encode_page(st s, const list_page& page)
{
    bytes::writer w;
    w.u8(static_cast<uint8_t>(s));
    w.u8(page.truncated ? 1 : 0);
    w.bytes(page.resume_at);
    w.u32(static_cast<uint32_t>(page.prefixes.size()));
    for (const std::string& p : page.prefixes)
        w.bytes(p);
    w.u32(static_cast<uint32_t>(page.objects.size()));
    for (const list_entry& e : page.objects)
    {
        std::string rec;
        encode_put_record(rec, e.key, e.meta);
        w.bytes(rec);
    }
    return w.take();
}

bool decode_page(std::string_view reply, st& s, list_page& out)
{
    bytes::reader r(reply);
    bool truncated = false;
    uint32_t np = 0, no = 0;
    out = list_page{};
    if (!status_byte(r, s) || !r.flag(truncated) || !r.bytes(out.resume_at, name_cap) || !r.u32(np))
        return false;
    out.truncated = truncated;
    // A forged count cannot reserve more than the bytes that are there.
    if (np > r.left() / 4)
        return false;
    for (uint32_t i = 0; i < np; ++i)
    {
        std::string p;
        if (!r.bytes(p, name_cap))
            return false;
        out.prefixes.push_back(std::move(p));
    }
    if (!r.u32(no) || no > r.left() / 4)
        return false;
    for (uint32_t i = 0; i < no; ++i)
    {
        std::string rec;
        list_entry e;
        if (!r.bytes(rec, record_cap) || !decode_record(rec, e.key, e.meta))
            return false;
        out.objects.push_back(std::move(e));
    }
    return true;
}

list_page merge_pages(const std::vector<list_page>& pages, size_t max_keys)
{
    struct item
    {
        const std::string* name;
        const list_entry*  object;   // null for a rolled-up prefix
    };

    // The furthest a truncated shard is known to: its own last name.
    bool        any_truncated = false;
    bool        bounded       = false;
    std::string horizon;
    std::vector<item> items;
    for (const list_page& p : pages)
    {
        const std::string* last = nullptr;
        for (const list_entry& e : p.objects)
        {
            items.push_back({&e.key, &e});
            last = &e.key;
        }
        // Each list is sorted alone, and the last name is the larger of the two ends.
        if (!p.objects.empty())
            last = &p.objects.back().key;
        for (const std::string& pr : p.prefixes)
            items.push_back({&pr, nullptr});
        if (!p.prefixes.empty() && (!last || p.prefixes.back() > *last))
            last = &p.prefixes.back();

        if (!p.truncated)
            continue;
        any_truncated = true;
        const std::string edge = last ? *last : std::string{};
        if (!bounded || edge < horizon)
            horizon = edge;
        bounded = true;
    }

    std::stable_sort(items.begin(), items.end(),
                     [](const item& a, const item& b) { return *a.name < *b.name; });

    list_page out;
    const std::string* taken_last = nullptr;
    bool               taken_prefix = false;
    size_t             count = 0;
    bool               more  = false;

    for (size_t i = 0; i < items.size(); ++i)
    {
        const item& it = items[i];
        // The same prefix from more than one shard is one entry.
        if (!it.object && taken_last && taken_prefix && *taken_last == *it.name)
            continue;
        if (bounded && *it.name > horizon)
            break;
        if (count >= max_keys)
        {
            more = true;
            break;
        }
        if (it.object)
            out.objects.push_back(*it.object);
        else
            out.prefixes.push_back(*it.name);
        taken_last   = it.name;
        taken_prefix = !it.object;
        ++count;
    }

    if (!more && !any_truncated)
        return out;

    // The next page begins just after the last name given, which is what
    // neither a shard's own next name nor a raw key inside a rolled-up prefix
    // can say for all the shards at once.
    if (!taken_last)
        return out;
    std::string resume = taken_prefix ? prefix_successor(*taken_last) : *taken_last + '\0';
    if (resume.empty())
        return out;
    out.truncated = true;
    out.resume_at = std::move(resume);
    return out;
}

}   // namespace socketley::storage::wire
