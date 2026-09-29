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
        o > static_cast<uint8_t>(op::mpu_list))
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

// ─── Multipart ──────────────────────────────────────────────────────────────

namespace
{

constexpr size_t id_cap = 128;

void put_meta(bytes::writer& w, std::string_view key, const object_meta& m)
{
    std::string rec;
    encode_put_record(rec, key, m);
    w.bytes(rec);
}

bool get_meta(bytes::reader& r, std::string& key, object_meta& m)
{
    std::string rec;
    return r.bytes(rec, record_cap) && decode_record(rec, key, m);
}

void put_part(bytes::writer& w, const mpu_part& p)
{
    w.u32(p.number);
    w.u64(p.size);
    for (const uint8_t b : p.md5)
        w.u8(b);
    w.u64(static_cast<uint64_t>(p.mtime_ms));
    w.u64(p.data_off);
    w.bytes(p.checksum_b64);
}

bool get_part(bytes::reader& r, mpu_part& p)
{
    uint64_t mt = 0, off = 0;
    if (!r.u32(p.number) || !r.u64(p.size))
        return false;
    for (uint8_t& b : p.md5)
        if (!r.u8(b))
            return false;
    if (!r.u64(mt) || !r.u64(off) || !r.bytes(p.checksum_b64, 256))
        return false;
    p.mtime_ms = static_cast<int64_t>(mt);
    p.data_off = static_cast<size_t>(off);
    return true;
}

bool algo_byte(bytes::reader& r, checksum_algo& a)
{
    uint8_t b = 0;
    if (!r.u8(b) || b > static_cast<uint8_t>(checksum_algo::sha256))
        return false;
    a = static_cast<checksum_algo>(b);
    return true;
}

}   // namespace

std::string encode_mpu_create(std::string_view bucket, std::string_view key, const object_meta& meta,
                              checksum_algo algo)
{
    bytes::writer w = begin(op::mpu_create);
    w.bytes(bucket);
    w.bytes(key);
    w.u8(static_cast<uint8_t>(algo));
    put_meta(w, key, meta);
    return w.take();
}

bool decode_mpu_create(std::string_view payload, std::string& bucket, std::string& key, object_meta& meta,
                       checksum_algo& algo)
{
    bytes::reader r(payload);
    std::string k2;
    return open_request(r, op::mpu_create) && r.bytes(bucket, name_cap) && r.bytes(key, name_cap) &&
           algo_byte(r, algo) && get_meta(r, k2, meta) && k2 == key;
}

std::string encode_mpu_ref(op o, const mpu_ref& ref)
{
    bytes::writer w = begin(o);
    w.bytes(ref.bucket);
    w.bytes(ref.key);
    w.bytes(ref.id);
    w.u32(ref.a);
    w.u32(ref.b);
    w.u8(ref.flag ? 1 : 0);
    return w.take();
}

bool decode_mpu_ref(std::string_view payload, op want, mpu_ref& ref)
{
    bytes::reader r(payload);
    return open_request(r, want) && r.bytes(ref.bucket, name_cap) && r.bytes(ref.key, name_cap) &&
           r.bytes(ref.id, id_cap) && r.u32(ref.a) && r.u32(ref.b) && r.flag(ref.flag);
}

std::string encode_mpu_part(const commit_request& req, std::string_view id, uint32_t number)
{
    bytes::writer w = begin(op::mpu_part);
    w.bytes(req.bucket);
    w.bytes(req.key);
    w.bytes(req.tmp_name);
    w.bytes(id);
    w.u32(number);
    put_meta(w, req.key, req.meta);
    return w.take();
}

bool decode_mpu_part(std::string_view payload, commit_request& req, std::string& id, uint32_t& number)
{
    bytes::reader r(payload);
    std::string k2;
    return open_request(r, op::mpu_part) && r.bytes(req.bucket, name_cap) && r.bytes(req.key, name_cap) &&
           r.bytes(req.tmp_name, name_cap) && r.bytes(id, id_cap) && r.u32(number) &&
           get_meta(r, k2, req.meta) && k2 == req.key;
}

std::string encode_mpu_prepare(const mpu_ref& ref, const std::vector<complete_part>& parts)
{
    bytes::writer w = begin(op::mpu_prepare);
    w.bytes(ref.bucket);
    w.bytes(ref.key);
    w.bytes(ref.id);
    w.u32(static_cast<uint32_t>(parts.size()));
    for (const complete_part& p : parts)
    {
        w.u32(p.number);
        w.bytes(p.etag);
        w.u8(static_cast<uint8_t>(p.checksum_algo_));
        w.bytes(p.checksum_b64);
    }
    return w.take();
}

bool decode_mpu_prepare(std::string_view payload, mpu_ref& ref, std::vector<complete_part>& parts)
{
    bytes::reader r(payload);
    uint32_t n = 0;
    if (!open_request(r, op::mpu_prepare) || !r.bytes(ref.bucket, name_cap) || !r.bytes(ref.key, name_cap) ||
        !r.bytes(ref.id, id_cap) || !r.u32(n) || n > 20000 || n > r.left() / 4)
        return false;
    parts.clear();
    for (uint32_t i = 0; i < n; ++i)
    {
        complete_part p;
        if (!r.u32(p.number) || !r.bytes(p.etag, 256) || !algo_byte(r, p.checksum_algo_) ||
            !r.bytes(p.checksum_b64, 256))
            return false;
        parts.push_back(std::move(p));
    }
    return true;
}

std::string encode_mpu_created(st s, std::string_view id)
{
    bytes::writer w;
    w.u8(static_cast<uint8_t>(s));
    w.bytes(id);
    return w.take();
}

bool decode_mpu_created(std::string_view reply, st& s, std::string& id)
{
    bytes::reader r(reply);
    return status_byte(r, s) && r.bytes(id, id_cap);
}

std::string encode_mpu_begin(st s, checksum_algo algo)
{
    bytes::writer w;
    w.u8(static_cast<uint8_t>(s));
    w.u8(static_cast<uint8_t>(algo));
    return w.take();
}

bool decode_mpu_begin(std::string_view reply, st& s, checksum_algo& algo)
{
    bytes::reader r(reply);
    return status_byte(r, s) && algo_byte(r, algo);
}

std::string encode_mpu_plan(const s3_error& err, const assemble_plan& plan)
{
    bytes::writer w;
    w.bytes(err.code);
    w.bytes(err.message);
    if (!err.code.empty())
        return w.take();
    w.bytes(plan.bucket);
    w.bytes(plan.id);
    w.bytes(plan.key);
    w.bytes(plan.checksum_b64);
    put_meta(w, plan.key, plan.meta);
    w.u32(static_cast<uint32_t>(plan.parts.size()));
    for (const mpu_part& p : plan.parts)
        put_part(w, p);
    return w.take();
}

bool decode_mpu_plan(std::string_view reply, s3_error& err, assemble_plan& plan)
{
    bytes::reader r(reply);
    std::string code, message;
    if (!r.bytes(code, 256) || !r.bytes(message, 4096))
        return false;
    if (!code.empty())
    {
        err         = make_error(code);
        err.message = std::move(message);
        return true;
    }
    err = s3_error{};
    uint32_t n = 0;
    std::string key;
    if (!r.bytes(plan.bucket, name_cap) || !r.bytes(plan.id, id_cap) || !r.bytes(plan.key, name_cap) ||
        !r.bytes(plan.checksum_b64, 256) || !get_meta(r, key, plan.meta) || !r.u32(n) || n > 20000 ||
        n > r.left() / 4)
        return false;
    plan.parts.clear();
    for (uint32_t i = 0; i < n; ++i)
    {
        mpu_part p;
        if (!get_part(r, p))
            return false;
        plan.parts.push_back(std::move(p));
    }
    return true;
}

std::string encode_parts_page(const parts_page& pg)
{
    bytes::writer w;
    w.u8(static_cast<uint8_t>(pg.status));
    w.bytes(pg.key);
    w.bytes(pg.id);
    w.u8(static_cast<uint8_t>(pg.algo));
    w.u8(pg.truncated ? 1 : 0);
    w.u32(pg.next_marker);
    w.u32(static_cast<uint32_t>(pg.rows.size()));
    for (const part_row& p : pg.rows)
    {
        w.u32(p.number);
        w.u64(static_cast<uint64_t>(p.mtime_ms));
        w.bytes(p.etag);
        w.u64(p.size);
        w.bytes(p.checksum_b64);
    }
    return w.take();
}

bool decode_parts_page(std::string_view reply, parts_page& pg)
{
    bytes::reader r(reply);
    uint32_t n = 0;
    bool trunc = false;
    if (!status_byte(r, pg.status) || !r.bytes(pg.key, name_cap) || !r.bytes(pg.id, id_cap) ||
        !algo_byte(r, pg.algo) || !r.flag(trunc) || !r.u32(pg.next_marker) || !r.u32(n) || n > 20000 ||
        n > r.left() / 4)
        return false;
    pg.truncated = trunc;
    pg.rows.clear();
    for (uint32_t i = 0; i < n; ++i)
    {
        part_row p;
        uint64_t mt = 0;
        if (!r.u32(p.number) || !r.u64(mt) || !r.bytes(p.etag, 256) || !r.u64(p.size) ||
            !r.bytes(p.checksum_b64, 256))
            return false;
        p.mtime_ms = static_cast<int64_t>(mt);
        p.algo     = pg.algo;
        pg.rows.push_back(std::move(p));
    }
    return true;
}

std::string encode_upload_list(const std::vector<upload_stub>& uploads)
{
    bytes::writer w;
    w.u32(static_cast<uint32_t>(uploads.size()));
    for (const upload_stub& u : uploads)
    {
        w.bytes(u.key);
        w.bytes(u.id);
        w.u64(static_cast<uint64_t>(u.initiated_ms));
    }
    return w.take();
}

bool decode_upload_list(std::string_view reply, std::vector<upload_stub>& uploads)
{
    bytes::reader r(reply);
    uint32_t n = 0;
    if (!r.u32(n) || n > r.left() / 4)
        return false;
    uploads.clear();
    for (uint32_t i = 0; i < n; ++i)
    {
        upload_stub u;
        uint64_t ms = 0;
        if (!r.bytes(u.key, name_cap) || !r.bytes(u.id, id_cap) || !r.u64(ms))
            return false;
        u.initiated_ms = static_cast<int64_t>(ms);
        uploads.push_back(std::move(u));
    }
    return true;
}

}   // namespace socketley::storage::wire
