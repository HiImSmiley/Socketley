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
    decoded_record d = decode_journal_record(record);
    if (d.status != record_status::ok || d.rec.type != record_type::put || d.consumed != record.size())
        return false;
    key  = std::move(d.rec.key);
    meta = std::move(d.rec.meta);
    return true;
}

bool status_byte(bytes::reader& r, st& s)
{
    uint8_t b = 0;
    if (!r.u8(b) || b > static_cast<uint8_t>(st::unavailable))
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
        o > static_cast<uint8_t>(op::hot_hold))
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
    std::string_view rec;
    std::string key;
    bool create_only = false;
    if (!open_request(r, op::commit) || !r.bytes(out.bucket, name_cap) || !r.bytes(out.key, name_cap) ||
        !r.bytes(out.tmp_name, name_cap) || !r.flag(create_only) || !r.view(rec, record_cap))
        return false;
    out.create_only = create_only;
    return decode_record(rec, key, out.meta) && key == out.key;
}

std::string encode_remove(std::string_view bucket, std::string_view key, std::string_view version_id)
{
    bytes::writer w = begin(op::remove);
    w.bytes(bucket);
    w.bytes(key);
    w.bytes(version_id);
    return w.take();
}

bool decode_remove(std::string_view payload, std::string& bucket, std::string& key, std::string* version_id)
{
    bytes::reader r(payload);
    std::string id;
    if (!open_request(r, op::remove) || !r.bytes(bucket, name_cap) || !r.bytes(key, name_cap) || !r.bytes(id, 256))
        return false;
    if (version_id)
        *version_id = std::move(id);
    return true;
}

std::string encode_set_tags(std::string_view bucket, std::string_view key, std::string_view version_id,
                            std::string_view tags)
{
    bytes::writer w = begin(op::set_tags);
    w.bytes(bucket);
    w.bytes(key);
    w.bytes(version_id);
    w.bytes(tags);
    return w.take();
}

bool decode_set_tags(std::string_view payload, std::string& bucket, std::string& key, std::string& version_id,
                     std::string& tags)
{
    bytes::reader r(payload);
    return open_request(r, op::set_tags) && r.bytes(bucket, name_cap) && r.bytes(key, name_cap) &&
           r.bytes(version_id, 256) && r.bytes(tags, record_cap);
}

std::string encode_hot_drop(std::string_view bucket, std::string_view key)
{
    bytes::writer w = begin(op::hot_drop);
    w.bytes(bucket);
    w.bytes(key);
    return w.take();
}

bool decode_hot_drop(std::string_view payload, std::string& bucket, std::string& key)
{
    bytes::reader r(payload);
    return open_request(r, op::hot_drop) && r.bytes(bucket, name_cap) && r.bytes(key, name_cap);
}

std::string encode_hot_owner_started(uint32_t shard)
{
    bytes::writer w = begin(op::hot_owner_started);
    w.u32(shard);
    return w.take();
}

bool decode_hot_owner_started(std::string_view payload, uint32_t& shard)
{
    bytes::reader r(payload);
    return open_request(r, op::hot_owner_started) && r.u32(shard);
}

std::string encode_hot_hold(uint32_t shard, const hold_entry* entries, size_t n)
{
    bytes::writer w = begin(op::hot_hold);
    w.u32(shard);
    w.u32(static_cast<uint32_t>(n));
    std::string rec;
    for (size_t i = 0; i < n; ++i)
    {
        w.bytes(entries[i].bucket);
        rec.clear();
        encode_put_record(rec, entries[i].key, entries[i].meta);
        w.bytes(rec);
    }
    return w.take();
}

bool decode_hot_hold(std::string_view payload, uint32_t& shard, std::vector<hold_entry>& out)
{
    bytes::reader r(payload);
    uint32_t n = 0;
    if (!open_request(r, op::hot_hold) || !r.u32(shard) || !r.u32(n) || n == 0 || n > max_holds)
        return false;
    out.resize(n);
    for (hold_entry& e : out)
    {
        std::string_view rec;
        if (!r.bytes(e.bucket, name_cap) || !r.view(rec, record_cap) || !decode_record(rec, e.key, e.meta))
            return false;
    }
    return r.left() == 0;
}

std::string encode_held(const std::vector<uint8_t>& held)
{
    bytes::writer w;
    w.u8(static_cast<uint8_t>(st::ok));
    w.bytes(std::string_view(reinterpret_cast<const char*>(held.data()), held.size()));
    return w.take();
}

bool decode_held(std::string_view reply, std::vector<uint8_t>& held)
{
    bytes::reader r(reply);
    st s = st::io_error;
    std::string_view v;
    if (!status_byte(r, s) || s != st::ok || !r.view(v, max_holds))
        return false;
    held.assign(v.begin(), v.end());
    return true;
}

std::string encode_doc(op o, bucket_doc kind, std::string_view bucket, std::string_view xml, uint64_t seq)
{
    bytes::writer w = begin(o);
    w.u8(static_cast<uint8_t>(kind));
    w.bytes(bucket);
    w.bytes(xml);
    w.u64(seq);
    return w.take();
}

bool decode_doc(std::string_view payload, op want, bucket_doc& kind, std::string& bucket, std::string& xml,
                uint64_t& seq)
{
    bytes::reader r(payload);
    uint8_t k = 0;
    if (!open_request(r, want) || !r.u8(k) || k > static_cast<uint8_t>(bucket_doc::versioning) ||
        !r.bytes(bucket, name_cap) || !r.bytes(xml, doc_max_bytes) || !r.u64(seq))
        return false;
    kind = static_cast<bucket_doc>(k);
    return true;
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

std::string encode_removed(const remove_result& r)
{
    bytes::writer w;
    w.u8(static_cast<uint8_t>(r.status));
    w.u8(r.existed ? 1 : 0);
    w.u8(r.marker ? 1 : 0);
    w.bytes(r.version_id);
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

bool decode_removed(std::string_view reply, remove_result& out)
{
    bytes::reader r(reply);
    out = remove_result{};
    return status_byte(r, out.status) && r.flag(out.existed) && r.flag(out.marker) && r.bytes(out.version_id, 256);
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

bool page_writer::fits(const std::string& name, size_t cost)
{
    if (m_cut)
        return false;
    m_total += cost;
    if (m_total <= m_max)
        return true;
    // The first entry that does not fit is where the page now ends.
    m_cut       = true;
    m_truncated = true;
    m_resume    = name;
    return false;
}

void page_writer::object(const std::string& key, const object_meta& meta)
{
    size_t cost = key.size() + meta.content_type.size() + 96;
    for (const auto& [n, v] : meta.extra)
        cost += n.size() + v.size() + 8;
    if (!fits(key, cost))
        return;
    m_record.clear();
    encode_put_record(m_record, key, meta);
    m_objects.bytes(m_record);
    ++m_object_count;
}

void page_writer::prefix(std::string common)
{
    if (!fits(common, common.size() + 8))
        return;
    m_prefixes.bytes(common);
    ++m_prefix_count;
}

void page_writer::truncated(const std::string& resume_at)
{
    if (m_cut)
        return;
    m_truncated = true;
    m_resume    = resume_at;
}

std::string page_writer::finish(st s)
{
    bytes::writer head;
    head.u8(static_cast<uint8_t>(s));
    head.u8(m_truncated ? 1 : 0);
    head.bytes(m_resume);
    head.u32(m_prefix_count);
    bytes::writer count;
    count.u32(m_object_count);
    std::string out = head.take();
    out += m_prefixes.take();
    out += count.take();
    out += m_objects.take();
    return out;
}

std::string encode_page(st s, const list_page& page, size_t max_bytes)
{
    page_writer w(max_bytes);
    // Objects and prefixes are each sorted, so merging the two gives them in the name order a walk would.
    size_t o = 0, p = 0;
    while (o < page.objects.size() || p < page.prefixes.size())
    {
        if (p == page.prefixes.size() || (o < page.objects.size() && page.objects[o].key < page.prefixes[p]))
        {
            w.object(page.objects[o].key, page.objects[o].meta);
            ++o;
        }
        else
            w.prefix(page.prefixes[p++]);
    }
    if (page.truncated)
        w.truncated(page.resume_at);
    return w.finish(s);
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
    out.objects.reserve(no);
    for (uint32_t i = 0; i < no; ++i)
    {
        std::string_view rec;
        list_entry& e = out.objects.emplace_back();
        if (!r.view(rec, record_cap) || !decode_record(rec, e.key, e.meta))
            return false;
    }
    return true;
}

list_page merge_pages(std::vector<list_page> pages, size_t max_keys)
{
    struct item
    {
        const std::string* name;
        list_entry*        object;   // null for a rolled-up prefix
    };

    // The furthest a truncated shard is known to: its own last name.
    bool        any_truncated = false;
    bool        bounded       = false;
    std::string horizon;
    std::vector<item> items;
    size_t            objects = 0;
    for (list_page& p : pages)
    {
        const std::string* last = nullptr;
        objects += p.objects.size();
        for (list_entry& e : p.objects)
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
    // Reserved whole, so the name of the last object taken stays where it was moved to.
    out.objects.reserve(std::min(objects, max_keys));
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
        {
            out.objects.push_back(std::move(*it.object));
            taken_last = &out.objects.back().key;
        }
        else
        {
            out.prefixes.push_back(*it.name);
            taken_last = it.name;
        }
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
    std::string_view rec;
    return r.view(rec, record_cap) && decode_record(rec, key, m);
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
    w.u8(p.in_place ? 1 : 0);
}

bool get_part(bytes::reader& r, mpu_part& p)
{
    uint64_t mt = 0, off = 0;
    if (!r.u32(p.number) || !r.u64(p.size))
        return false;
    for (uint8_t& b : p.md5)
        if (!r.u8(b))
            return false;
    if (!r.u64(mt) || !r.u64(off) || !r.bytes(p.checksum_b64, 256) || !r.flag(p.in_place))
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
    w.u64(ref.size);
    return w.take();
}

bool decode_mpu_ref(std::string_view payload, op want, mpu_ref& ref)
{
    bytes::reader r(payload);
    return open_request(r, want) && r.bytes(ref.bucket, name_cap) && r.bytes(ref.key, name_cap) &&
           r.bytes(ref.id, id_cap) && r.u32(ref.a) && r.u32(ref.b) && r.flag(ref.flag) && r.u64(ref.size);
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

std::string encode_mpu_begin(st s, checksum_algo algo, const part_place& place)
{
    bytes::writer w;
    w.u8(static_cast<uint8_t>(s));
    w.u8(static_cast<uint8_t>(algo));
    w.u64(place.off);
    w.u64(place.room);
    return w.take();
}

bool decode_mpu_begin(std::string_view reply, st& s, checksum_algo& algo, part_place& place)
{
    bytes::reader r(reply);
    place = part_place{};
    return status_byte(r, s) && algo_byte(r, algo) && r.u64(place.off) && r.u64(place.room);
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
    w.u8(plan.in_place ? 1 : 0);
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
    return r.flag(plan.in_place);
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

// ─── Versions ───────────────────────────────────────────────────────────────

std::string encode_committed(const put_result& r)
{
    bytes::writer w;
    w.u8(static_cast<uint8_t>(r.status));
    std::string value;
    for (const auto& [n, v] : r.meta.extra)
        if (n == version_extra)
            value = v;
    w.bytes(value);
    return w.take();
}

bool decode_committed(std::string_view reply, put_result& out)
{
    bytes::reader r(reply);
    std::string value;
    out = put_result{};
    if (!status_byte(r, out.status) || !r.bytes(value, 256))
        return false;
    if (!value.empty())
        out.meta.extra.emplace_back(std::string(version_extra), std::move(value));
    return true;
}

std::string encode_tagged(st s, std::string_view version_id)
{
    bytes::writer w;
    w.u8(static_cast<uint8_t>(s));
    w.bytes(version_id);
    return w.take();
}

bool decode_tagged(std::string_view reply, st& s, std::string& version_id)
{
    bytes::reader r(reply);
    return status_byte(r, s) && r.bytes(version_id, 256);
}

std::string encode_list_versions(std::string_view bucket, const version_query& q)
{
    bytes::writer w = begin(op::list_versions);
    w.bytes(bucket);
    w.bytes(q.prefix);
    w.bytes(q.delimiter);
    w.bytes(q.key_marker);
    w.bytes(q.version_marker);
    w.u64(q.max_keys);
    return w.take();
}

bool decode_list_versions(std::string_view payload, std::string& bucket, version_query& q)
{
    bytes::reader r(payload);
    uint64_t max_keys = 0;
    if (!open_request(r, op::list_versions) || !r.bytes(bucket, name_cap) || !r.bytes(q.prefix, query_cap) ||
        !r.bytes(q.delimiter, query_cap) || !r.bytes(q.key_marker, query_cap) ||
        !r.bytes(q.version_marker, 256) || !r.u64(max_keys))
        return false;
    q.max_keys = static_cast<size_t>(std::min<uint64_t>(max_keys, 1000));
    return true;
}

std::string encode_version_page(st s, const version_page& page)
{
    bytes::writer w;
    w.u8(static_cast<uint8_t>(s));
    w.u8(page.truncated ? 1 : 0);
    w.u32(static_cast<uint32_t>(page.items.size()));
    for (const version_item& it : page.items)
    {
        w.u8(static_cast<uint8_t>((it.prefix ? 1 : 0) | (it.latest ? 2 : 0)));
        if (it.prefix)
            w.bytes(it.key);
        else
            put_meta(w, it.key, it.meta);
    }
    return w.take();
}

bool decode_version_page(std::string_view reply, st& s, version_page& page)
{
    bytes::reader r(reply);
    uint32_t n = 0;
    bool truncated = false;
    page = version_page{};
    if (!status_byte(r, s) || !r.flag(truncated) || !r.u32(n) || n > 1000 || n > r.left())
        return false;
    page.truncated = truncated;
    for (uint32_t i = 0; i < n; ++i)
    {
        uint8_t f = 0;
        version_item it;
        if (!r.u8(f) || f > 3)
            return false;
        it.prefix = (f & 1) != 0;
        it.latest = (f & 2) != 0;
        if (it.prefix ? !r.bytes(it.key, query_cap) : !get_meta(r, it.key, it.meta))
            return false;
        page.items.push_back(std::move(it));
    }
    return true;
}

version_page merge_version_pages(std::vector<version_page> pages, size_t max_keys)
{
    // A key is one shard's, so its versions come from one page in order and only a common prefix repeats.
    std::vector<version_item> all;
    // A page cut short says nothing past its last key, so nothing past the first such key is known whole.
    bool        cut = false;
    std::string bound;
    for (const version_page& p : pages)
        if (p.truncated && !p.items.empty() && (!cut || p.items.back().key < bound))
        {
            cut   = true;
            bound = p.items.back().key;
        }
    for (version_page& p : pages)
        for (version_item& it : p.items)
            if (!cut || it.key <= bound)
                all.push_back(std::move(it));
    std::stable_sort(all.begin(), all.end(), [](const version_item& a, const version_item& b) { return a.key < b.key; });
    version_page out;
    for (version_item& it : all)
    {
        if (it.prefix && !out.items.empty() && out.items.back().prefix && out.items.back().key == it.key)
            continue;
        if (out.items.size() == max_keys)
        {
            out.truncated = true;
            break;
        }
        out.items.push_back(std::move(it));
    }
    if (cut)
        out.truncated = true;
    return out;
}

}   // namespace socketley::storage::wire
