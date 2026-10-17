#include "db_store.h"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <map>
#include <new>

#include <fcntl.h>
#include <unistd.h>

#include <openssl/rand.h>

#include "../../shared/byte_codec.h"
#include "../../shared/jws.h"
#include "../../shared/mutation_journal.h"
#include "../../shared/replaced_file.h"

namespace socketley::db
{

namespace
{

constexpr uint8_t rec_write = 1;
constexpr uint8_t ent_put   = 1;
constexpr uint8_t ent_del   = 2;
// A document's share of memory beside its JSON, for --max-bytes: its place, figures and the maps it sits in.
constexpr size_t doc_overhead = 96;
// A merge waits until the sealed segments hold this much that is dead, and more dead than alive.
constexpr uint64_t merge_floor = 32ull << 20;

error fail(int status, std::string_view code, std::string message)
{
    return error{status, std::string(code), std::move(message)};
}

std::string new_id()
{
    unsigned char b[16];
    if (RAND_bytes(b, sizeof b) != 1)
        return {};
    return socketley::jws::b64url(std::string_view(reinterpret_cast<const char*>(b), sizeof b));
}

// How deep a value nests, the object it is in counting as none, which json_reader's bound is measured against.
size_t depth_of(const jvalue& v)
{
    size_t d = 0;
    for (const auto& i : v.items)
        d = std::max(d, 1 + depth_of(i));
    for (const auto& [k, m] : v.members)
        d = std::max(d, 1 + depth_of(m));
    return d;
}

bool is_integer(const jvalue& v)
{
    return v.k == jvalue::kind::number && v.s.find_first_of(".eE") == std::string::npos;
}

bool system_field(std::string_view f)
{
    return f == "_id" || f == "_v" || f == "_owner";
}

std::string staged_key(std::string_view coll, std::string_view id)
{
    std::string k(coll);
    k += '\0';
    k += id;
    return k;
}

int64_t now_sec()
{
    return static_cast<int64_t>(::time(nullptr));
}

// A system field of a document as a query sees it, null for one of the document's own.
const jvalue* system_of(const doc& d, const std::string& id, std::string_view path, jvalue& scratch)
{
    if (path == "_id")
    {
        scratch.k = jvalue::kind::string;
        scratch.s = id;
        return &scratch;
    }
    if (path == "_owner")
    {
        if (d.owner.empty())
            return nullptr;
        scratch.k = jvalue::kind::string;
        scratch.s = d.owner;
        return &scratch;
    }
    scratch.k = jvalue::kind::number;
    scratch.s = std::to_string(d.v);
    return &scratch;
}

bool key_meets(const query::cond& c, const ikey& k)
{
    switch (c.op)
    {
        case query::cond::gt:     return k.rank == c.key.rank && c.key < k;
        case query::cond::gte:    return k.rank == c.key.rank && !(k < c.key);
        case query::cond::lt:     return k.rank == c.key.rank && k < c.key;
        case query::cond::lte:    return k.rank == c.key.rank && !(c.key < k);
        case query::cond::prefix: return k.rank == ikey::string && k.str.starts_with(c.value.s);
        default:                  return false;
    }
}

// The least key above `k`, so a bound past every entry of `k` is a lower_bound of it.
ikey after(ikey k)
{
    if (k.rank == ikey::number)
        k.num = std::nextafter(k.num, INFINITY);
    else
        k.str.push_back('\0');
    return k;
}

using index_entries = std::map<std::pair<ikey, std::string>, const doc*>;

// Whether an index's key is in the run an eq or a range picks, which is one run of the index, since it orders its
// entries by their values.
bool in_run(const query::cond& c, const ikey& k)
{
    return c.op == query::cond::eq ? k == c.key : key_meets(c, k);
}

// Where a walk of that run starts going up: at its first entry, or past it when the run is empty.
index_entries::const_iterator run_start(const index_entries& s, const query::cond& c)
{
    const auto at = [&](const ikey& k) { return s.lower_bound({k, std::string()}); };
    const ikey& k = c.key;
    switch (c.op)
    {
        case query::cond::gt:     return at(after(k));
        case query::cond::lt:
        case query::cond::lte:    return at(ikey{k.rank, -INFINITY, {}});
        case query::cond::prefix: return at(ikey{ikey::string, 0, c.value.s});
        default:                  return at(k);
    }
}

// Where a walk of that run starts going down: past its last entry.
index_entries::const_iterator run_end(const index_entries& s, const query::cond& c)
{
    const auto at = [&](const ikey& k) { return s.lower_bound({k, std::string()}); };
    const ikey& k = c.key;
    const ikey past{static_cast<uint8_t>(k.rank + 1), -INFINITY, {}};
    switch (c.op)
    {
        case query::cond::gt:
        case query::cond::gte: return at(past);
        case query::cond::lt:  return at(k);
        case query::cond::prefix:
        {
            ikey to{ikey::string, 0, c.value.s};
            while (!to.str.empty() && static_cast<unsigned char>(to.str.back()) == 0xff)
                to.str.pop_back();
            if (to.str.empty())
                return at(past);
            to.str.back() = static_cast<char>(static_cast<unsigned char>(to.str.back()) + 1);
            return at(to);
        }
        default: return at(after(k));
    }
}

bool meets(const query::cond& c, const jvalue* v)
{
    switch (c.op)
    {
        case query::cond::eq:
            return c.value.k == jvalue::kind::null ? (!v || v->k == jvalue::kind::null) : v && same(*v, c.value);
        case query::cond::ne:
            return c.value.k == jvalue::kind::null ? (v && v->k != jvalue::kind::null) : !v || !same(*v, c.value);
        case query::cond::in:
            for (const auto& i : c.value.items)
                if (v ? same(*v, i) : i.k == jvalue::kind::null)
                    return true;
            return false;
        case query::cond::exists:
            return (v != nullptr) == c.value.b;
        default:
            // An absent field is ordered as null, as an index orders it.
            return key_meets(c, key_of(v));
    }
}

bool scalar(const jvalue& v)
{
    return v.k != jvalue::kind::object && v.k != jvalue::kind::array;
}

// Whether a condition is answered from an index's key alone: not exists, which a key cannot tell from null, and no
// value an object or an array, which a key orders by its text.
bool by_key(const query::cond& c)
{
    if (c.op == query::cond::exists)
        return false;
    if (c.op == query::cond::in)
        return std::all_of(c.value.items.begin(), c.value.items.end(), scalar);
    return scalar(c.value);
}

bool meets_key(const query::cond& c, const ikey& k)
{
    switch (c.op)
    {
        case query::cond::eq: return k == c.key;
        case query::cond::ne: return !(k == c.key);
        case query::cond::in:
            for (const auto& i : c.value.items)
                if (k == key_of(&i))
                    return true;
            return false;
        default: return key_meets(c, k);
    }
}

// a + b as JSON writes it: in integers when both are and the sum fits, as a double otherwise.
bool add_numbers(const jvalue& a, const jvalue& b, jvalue& out)
{
    if (is_integer(a) && is_integer(b))
    {
        int64_t x = 0, y = 0, z = 0;
        const auto ra = std::from_chars(a.s.data(), a.s.data() + a.s.size(), x);
        const auto rb = std::from_chars(b.s.data(), b.s.data() + b.s.size(), y);
        if (ra.ec == std::errc() && rb.ec == std::errc() && !__builtin_add_overflow(x, y, &z))
        {
            out.k = jvalue::kind::number;
            out.s = std::to_string(z);
            return true;
        }
    }
    double x = 0, y = 0;
    if (!number_of(a, x) || !number_of(b, y) || !std::isfinite(x + y))
        return false;
    char buf[64];
    const auto r = std::to_chars(buf, buf + sizeof buf, x + y);
    out.k = jvalue::kind::number;
    out.s.assign(buf, r.ptr);
    return true;
}

}   // namespace

// ─── Records ────────────────────────────────────────────────────────────────

std::string encode_record(uint64_t seq, const std::vector<event>& evs, std::vector<uint64_t>* json_offs)
{
    socketley::bytes::writer w;
    size_t size = 1 + 8 + 4;
    for (const auto& e : evs)
        size += 1 + 4 + e.coll.size() + 4 + e.id.size() + (e.del ? 0 : 8 + 4 + e.owner.size() + 4 + e.json.size());
    w.reserve(size);
    w.u8(rec_write);
    w.u64(seq);
    w.u32(static_cast<uint32_t>(evs.size()));
    std::string out;
    for (const auto& e : evs)
    {
        w.u8(e.del ? ent_del : ent_put);
        w.bytes(e.coll);
        w.bytes(e.id);
        if (e.del)
            continue;
        w.u64(e.v);
        w.bytes(e.owner);
        w.bytes(e.json);
    }
    out = w.take();
    if (json_offs)
    {
        json_offs->clear();
        // Each put's JSON is the last field of its entry, so its offset is the sum of what came before it.
        size_t pos = 1 + 8 + 4;
        for (const auto& e : evs)
        {
            pos += 1 + 4 + e.coll.size() + 4 + e.id.size();
            if (e.del)
            {
                json_offs->push_back(0);
                continue;
            }
            pos += 8 + 4 + e.owner.size() + 4;
            json_offs->push_back(pos);
            pos += e.json.size();
        }
    }
    return out;
}

bool decode_record(std::string_view payload, std::vector<event>& out, std::vector<uint64_t>* json_offs,
                   uint64_t* seq_out)
{
    socketley::bytes::reader r(payload);
    uint8_t kind = 0;
    uint64_t seq = 0;
    uint32_t n = 0;
    if (!r.u8(kind) || kind != rec_write || !r.u64(seq) || !r.u32(n) || n > store::max_ops)
        return false;
    if (seq_out)
        *seq_out = seq;
    out.clear();
    if (json_offs)
        json_offs->clear();
    for (uint32_t i = 0; i < n; ++i)
    {
        event e;
        e.seq = seq;
        uint8_t t = 0;
        if (!r.u8(t) || !r.bytes(e.coll, 64) || !r.bytes(e.id, 128) || !valid_collection(e.coll))
            return false;
        if (t == ent_del)
        {
            e.del = true;
            if (json_offs)
                json_offs->push_back(0);
        }
        else if (t == ent_put)
        {
            std::string_view json;
            if (!r.u64(e.v) || !r.bytes(e.owner, 256))
                return false;
            const size_t before = payload.size() - r.left();
            if (!r.view(json, store::max_doc))
                return false;
            if (json_offs)
                json_offs->push_back(before + 4);
            e.json.assign(json);
        }
        else
            return false;
        out.push_back(std::move(e));
    }
    return r.left() == 0;
}

void write_doc(const std::string& id, const doc& d, std::string_view body_json, std::string& out)
{
    out += "{\"_id\":";
    write_string(id, out);
    out += ",\"_v\":";
    out += std::to_string(d.v);
    if (!d.owner.empty())
    {
        out += ",\"_owner\":";
        write_string(d.owner, out);
    }
    // The body's members follow, its own braces taken off.
    if (body_json.size() > 2)
    {
        out += ',';
        out.append(body_json.substr(1, body_json.size() - 2));
    }
    out += '}';
}

void copy_job::run()
{
    std::vector<std::string> payloads;
    payloads.reserve(items.size());
    std::unordered_map<uint32_t, int> fds;
    ok = true;
    for (auto& it : items)
    {
        int& fd = fds[it.from.seg];
        if (fd == 0)
        {
            char name[32];
            std::snprintf(name, sizeof name, "/seg-%08u.log", it.from.seg);
            fd = ::open((dir + name).c_str(), O_RDONLY | O_CLOEXEC);
            if (fd < 0)
                fd = -1;
        }
        event e;
        e.seq = it.seq;
        e.coll = it.coll;
        e.id = it.id;
        e.owner = it.owner;
        e.v = it.v;
        e.json.resize(it.from.len);
        size_t got = 0;
        while (fd >= 0 && got < e.json.size())
        {
            const ssize_t n = ::pread(fd, e.json.data() + got, e.json.size() - got,
                                      static_cast<off_t>(it.from.off + got));
            if (n <= 0)
                break;
            got += static_cast<size_t>(n);
        }
        if (got != e.json.size())
        {
            ok = false;
            why = "a document could not be read back from its segment";
            break;
        }
        std::vector<uint64_t> offs;
        payloads.push_back(encode_record(it.seq, {e}, &offs));
        it.to.len = it.from.len;
        it.to.off = offs[0];
    }
    for (auto& [seg, fd] : fds)
        if (fd > 0)
            ::close(fd);
    if (!ok)
        return;
    std::vector<uint64_t> where;
    if (!seglog::write_file(dest, payloads, where, why))
    {
        ok = false;
        return;
    }
    for (size_t i = 0; i < items.size(); ++i)
    {
        items[i].to.seg = dest_seg;
        items[i].to.off += where[i];
    }
}

bool apply_patch(jvalue& body, const jvalue& changes, error& err)
{
    if (changes.k != jvalue::kind::object || changes.members.empty())
    {
        err = fail(400, "bad_patch", "a patch is an object of set, unset, inc, push and pull");
        return false;
    }
    std::string why;
    const auto path_ok = [&](std::string_view p) {
        if (valid_path(p) && p.front() != '_')
            return true;
        err = fail(400, "bad_path", "a field is names of A-Z a-z 0-9 _ - joined by dots, not _ first: " + std::string(p));
        return false;
    };
    for (const auto& [verb, arg] : changes.members)
    {
        if (verb == "unset")
        {
            if (arg.k != jvalue::kind::array)
            {
                err = fail(400, "bad_patch", "unset takes an array of fields");
                return false;
            }
            for (const auto& p : arg.items)
            {
                if (p.k != jvalue::kind::string || !path_ok(p.s))
                {
                    if (err.status == 0)
                        err = fail(400, "bad_patch", "unset takes an array of fields");
                    return false;
                }
                erase_path(body, p.s);
            }
            continue;
        }
        if (verb != "set" && verb != "inc" && verb != "push" && verb != "pull")
        {
            err = fail(400, "bad_patch", "a patch takes set, unset, inc, push and pull, not " + verb);
            return false;
        }
        if (arg.k != jvalue::kind::object)
        {
            err = fail(400, "bad_patch", verb + " takes an object of fields and values");
            return false;
        }
        for (const auto& [path, value] : arg.members)
        {
            if (!path_ok(path))
                return false;
            if (verb == "pull")
            {
                jvalue* at = const_cast<jvalue*>(at_path(body, path));
                if (!at)
                    continue;
                if (at->k != jvalue::kind::array)
                {
                    err = fail(400, "not_array", path + " is not an array to pull from");
                    return false;
                }
                std::erase_if(at->items, [&](const jvalue& i) { return same(i, value); });
                continue;
            }
            jvalue* at = make_path(body, path, why);
            if (!at)
            {
                err = fail(400, "bad_path", path + ": " + why);
                return false;
            }
            if (verb == "set")
                *at = value;
            else if (verb == "inc")
            {
                if (value.k != jvalue::kind::number)
                {
                    err = fail(400, "not_number", "inc adds a number to " + path);
                    return false;
                }
                if (at->k == jvalue::kind::null)
                    *at = value;
                else if (at->k != jvalue::kind::number || !add_numbers(*at, value, *at))
                {
                    err = fail(400, "not_number", path + " is not a number a sum fits");
                    return false;
                }
            }
            else
            {
                if (at->k == jvalue::kind::null)
                    at->k = jvalue::kind::array;
                if (at->k != jvalue::kind::array)
                {
                    err = fail(400, "not_array", path + " is not an array to push to");
                    return false;
                }
                at->items.push_back(value);
            }
        }
    }
    return true;
}


// ─── The cache of documents read ────────────────────────────────────────────

struct cached_json
{
    const doc* d;
    location at;
    uint32_t len;
    // Its place among the store's blocks, which the hand walks.
    uint32_t index;
    bool used;

    char* bytes() { return reinterpret_cast<char*>(this + 1); }
    std::string_view json() const { return {reinterpret_cast<const char*>(this + 1), len}; }
};

store::~store()
{
    clear_cache();
}

void store::set_cache_bytes(uint64_t b)
{
    m_cache_limit = b;
    evict_to(b);
}

bool store::cached(const doc& d, std::string_view& out)
{
    cached_json* b = d.cache;
    if (!b || b->at.seg != d.at.seg || b->at.off != d.at.off)
        return false;
    b->used = true;
    ++m_hits;
    out = b->json();
    return true;
}

void store::cache_put(const doc& d, std::string_view json)
{
    if (json.size() > m_cache_limit / 4 || m_cache_limit == 0)
        return;
    cache_drop(d);
    auto* b = new (::operator new(sizeof(cached_json) + json.size()))
        cached_json{&d, d.at, static_cast<uint32_t>(json.size()), static_cast<uint32_t>(m_blocks.size()), true};
    std::memcpy(b->bytes(), json.data(), json.size());
    m_blocks.push_back(b);
    m_cache_bytes += json.size();
    d.cache = b;
    evict_to(m_cache_limit);
}

void store::cache_drop(const doc& d)
{
    if (d.cache && d.cache->d == &d)
        free_block(d.cache);
    d.cache = nullptr;
}

void store::free_block(cached_json* b)
{
    if (b->d->cache == b)
        b->d->cache = nullptr;
    m_cache_bytes -= b->len;
    cached_json* last = m_blocks.back();
    m_blocks[b->index] = last;
    last->index = b->index;
    m_blocks.pop_back();
    ::operator delete(b);
}

void store::evict_to(uint64_t limit)
{
    while (m_cache_bytes > limit && !m_blocks.empty())
    {
        if (m_hand >= m_blocks.size())
            m_hand = 0;
        cached_json* b = m_blocks[m_hand];
        if (b->used)
        {
            b->used = false;
            ++m_hand;
        }
        else
            // The last block takes its place, and is looked at next.
            free_block(b);
    }
}

void store::clear_cache()
{
    // The documents may be gone already: a block is let go without being looked through.
    for (cached_json* b : m_blocks)
        ::operator delete(b);
    m_blocks.clear();
    m_hand = 0;
    m_cache_bytes = 0;
}

bool store::json_of(const doc& d, std::string& out)
{
    if (d.at.seg == 0)
    {
        out.clear();
        return false;
    }
    if (std::string_view j; cached(d, j))
    {
        out.assign(j);
        return true;
    }
    ++m_misses;
    if (!m_log.read(d.at, out))
        return false;
    cache_put(d, out);
    return true;
}

bool store::body_of(const doc& d, jvalue& out)
{
    std::string json;
    return json_of(d, json) && json_reader(json).document(out);
}

// ─── Collections and documents ──────────────────────────────────────────────

store::coll_state* store::coll_of(std::string_view name)
{
    const auto it = m_colls.find(name);
    return it == m_colls.end() ? nullptr : &it->second;
}

const store::coll_state* store::coll_of(std::string_view name) const
{
    const auto it = m_colls.find(name);
    return it == m_colls.end() ? nullptr : &it->second;
}

store::coll_state& store::make_coll(const std::string& name)
{
    coll_state& c = m_colls[name];
    if (const collection_def* def = m_schema.find(name))
    {
        for (const auto& ix : def->indexes)
            c.indexes.push_back(index_state{ix, {}});
        c.ttl = def->ttl;
    }
    return c;
}

access store::access_of(std::string_view coll) const
{
    const collection_def* d = m_schema.find(coll);
    return d ? d->acc : access::priv;
}

void store::derive(const coll_state& c, const jvalue& body, doc& d) const
{
    d.keys.clear();
    for (const auto& ix : c.indexes)
        d.keys.push_back(key_of(at_path(body, ix.def.field)));
    d.expires = 0;
    double t = 0;
    if (const jvalue* v = c.ttl.empty() ? nullptr : at_path(body, c.ttl); v && number_of(*v, t) && t > 0)
        d.expires = t > 9.2e18 ? INT64_MAX : static_cast<int64_t>(std::ceil(t));
}

void store::index_doc(coll_state& c, const std::string& id, const doc& d, bool add)
{
    for (size_t i = 0; i < c.indexes.size() && i < d.keys.size(); ++i)
    {
        std::pair<ikey, std::string> e{d.keys[i], id};
        if (add)
            c.indexes[i].entries.emplace(std::move(e), &d);
        else
            c.indexes[i].entries.erase(e);
    }
    if (!d.owner.empty())
    {
        if (add)
            c.by_owner.emplace(std::pair{d.owner, id}, &d);
        else
            c.by_owner.erase({d.owner, id});
    }
}

void store::reindex(coll_state& c, const std::string& id, const doc* before, const doc* after, const doc* node)
{
    for (size_t i = 0; i < c.indexes.size(); ++i)
    {
        const ikey* was = before && i < before->keys.size() ? &before->keys[i] : nullptr;
        const ikey* is = after && i < after->keys.size() ? &after->keys[i] : nullptr;
        if (was && is && *was == *is)
            continue;
        if (was)
            c.indexes[i].entries.erase({*was, id});
        if (is)
            c.indexes[i].entries.emplace(std::pair{*is, id}, node);
    }
    const std::string none;
    const std::string& was = before ? before->owner : none;
    const std::string& is = after ? after->owner : none;
    if (was == is)
        return;
    if (!was.empty())
        c.by_owner.erase({was, id});
    if (!is.empty())
        c.by_owner.emplace(std::pair{is, id}, node);
}

void store::live_add(const doc& d, int64_t sign)
{
    if (d.at.seg == 0)
        return;
    uint64_t& l = m_live[d.at.seg];
    const uint64_t n = d.at.len + seglog::record_head + 64;
    l = sign > 0 ? l + n : (l > n ? l - n : 0);
}

void store::set_doc(coll_state& c, const std::string& coll, const std::string& id, doc* d)
{
    const auto it = c.docs.find(id);
    doc* now = nullptr;
    int64_t expired_before = 0;
    if (it != c.docs.end())
    {
        doc& old = it->second;
        // Only the index entries, the owner's and the expiry that change are touched.
        reindex(c, id, &old, d, &old);
        expired_before = old.expires;
        if (old.expires && (!d || d->expires != old.expires))
            m_expiry.erase({old.expires, coll, id});
        m_bytes -= std::min<uint64_t>(m_bytes, old.at.len + id.size() + old.owner.size() + doc_overhead);
        live_add(old, -1);
        const bool moved = !d || old.at.seg != d->at.seg || old.at.off != d->at.off;
        if (moved)
            cache_drop(old);
        if (d)
        {
            cached_json* const kept = old.cache;
            old = std::move(*d);
            old.cache = moved ? nullptr : kept;
            now = &old;
        }
        else
        {
            c.docs.erase(it);
            --m_docs;
        }
    }
    else if (d)
    {
        now = &c.docs.emplace(id, std::move(*d)).first->second;
        now->cache = nullptr;
        ++m_docs;
        reindex(c, id, nullptr, now, now);
    }
    if (!now)
        return;
    if (now->expires && now->expires != expired_before)
        m_expiry.emplace(now->expires, coll, id);
    m_bytes += now->at.len + id.size() + now->owner.size() + doc_overhead;
    live_add(*now, +1);
}

bool store::rebuild(coll_state& c, const std::string& name, const collection_def* def, std::string& why)
{
    std::vector<index_def> want = def ? def->indexes : std::vector<index_def>{};
    const std::string ttl = def ? def->ttl : std::string();
    bool same_set = want.size() == c.indexes.size() && ttl == c.ttl;
    for (size_t i = 0; same_set && i < want.size(); ++i)
        same_set = want[i].field == c.indexes[i].def.field;
    if (same_set)
    {
        for (size_t i = 0; i < want.size(); ++i)
            c.indexes[i].def.unique = want[i].unique;
        return true;
    }
    // Each document's values read again from its body, since the fields indexed changed.
    std::vector<std::pair<std::string, doc>> docs;
    docs.reserve(c.docs.size());
    coll_state probe;
    for (const auto& ix : want)
        probe.indexes.push_back(index_state{ix, {}});
    probe.ttl = ttl;
    for (const auto& [id, d] : c.docs)
    {
        jvalue body;
        if (!body_of(d, body))
        {
            why = "a document could not be read back to index it";
            return false;
        }
        doc nd = d;
        derive(probe, body, nd);
        docs.emplace_back(id, std::move(nd));
    }
    for (auto& [id, d] : c.docs)
        index_doc(c, id, d, false);
    c.indexes = std::move(probe.indexes);
    c.ttl = ttl;
    for (auto& [id, nd] : docs)
    {
        doc& d = c.docs.find(id)->second;
        if (d.expires)
            m_expiry.erase({d.expires, name, id});
        d.keys = std::move(nd.keys);
        d.expires = nd.expires;
        index_doc(c, id, d, true);
        if (d.expires)
            m_expiry.emplace(d.expires, name, id);
    }
    return true;
}

bool store::set_schema(const schema& s, std::string& why)
{
    // Every unique index the schema has checked against the documents before anything changes.
    for (auto& [name, c] : m_colls)
        if (const collection_def* def = s.find(name))
            for (const auto& ix : def->indexes)
            {
                if (!ix.unique)
                    continue;
                // The values already indexed answer when the field is; otherwise every body is read.
                int known = -1;
                for (size_t i = 0; i < c.indexes.size(); ++i)
                    if (c.indexes[i].def.field == ix.field)
                        known = static_cast<int>(i);
                std::set<ikey> seen;
                for (const auto& [id, d] : c.docs)
                {
                    ikey k;
                    if (known >= 0)
                        k = d.keys[static_cast<size_t>(known)];
                    else
                    {
                        jvalue body;
                        if (!body_of(d, body))
                        {
                            why = "a document could not be read back to check " + ix.field;
                            return false;
                        }
                        k = key_of(at_path(body, ix.field));
                    }
                    if (k.rank != ikey::null && !seen.insert(std::move(k)).second)
                    {
                        why = name + "." + ix.field + " cannot be unique: two documents hold one value";
                        return false;
                    }
                }
            }
    m_schema = s;
    for (auto& [name, c] : m_colls)
        if (!rebuild(c, name, m_schema.find(name), why))
            return false;
    return true;
}

// ─── Opening ────────────────────────────────────────────────────────────────

bool store::scan(uint32_t seg, uint64_t payload_off, std::string_view payload)
{
    std::vector<event> evs;
    std::vector<uint64_t> offs;
    uint64_t seq = 0;
    if (!decode_record(payload, evs, &offs, &seq))
        return false;
    m_seq = std::max(m_seq, seq);
    for (size_t i = 0; i < evs.size(); ++i)
    {
        const event& e = evs[i];
        m_seq = std::max(m_seq, e.seq);
        coll_state* c = coll_of(e.coll);
        if (!c)
            c = &make_coll(e.coll);
        // The latest record of a document wins, wherever a merge put the older ones.
        const auto it = c->docs.find(e.id);
        if (it != c->docs.end() && it->second.seq > e.seq)
            continue;
        c->last_seq = std::max(c->last_seq, e.seq);
        // A deletion is remembered, so an older record a later segment holds does not bring the document back.
        const std::string key = staged_key(e.coll, e.id);
        if (e.del)
        {
            set_doc(*c, e.coll, e.id, nullptr);
            m_tombs[key] = std::max(m_tombs[key], e.seq);
            continue;
        }
        if (const auto t = m_tombs.find(key); t != m_tombs.end() && t->second > e.seq)
            continue;
        doc d;
        d.owner = e.owner;
        d.v = e.v;
        d.seq = e.seq;
        d.at = location{seg, payload_off + offs[i], static_cast<uint32_t>(e.json.size())};
        if (!c->indexes.empty() || !c->ttl.empty())
        {
            jvalue body;
            if (!json_reader(e.json).document(body))
                return false;
            derive(*c, body, d);
        }
        set_doc(*c, e.coll, e.id, &d);
    }
    return true;
}

namespace
{

// The documents of the first format, a snapshot of JSON lines and a journal of records, as they stood last.
bool read_v1(const std::string& dir, std::map<std::pair<std::string, std::string>, event>& out, std::string& why)
{
    std::string text;
    if (read_whole_file(dir + "/data.snapshot", text))
    {
        bool header = false;
        for (std::string_view rest = text; !rest.empty();)
        {
            const size_t nl = rest.find('\n');
            const std::string_view line = rest.substr(0, nl);
            rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
            if (line.empty())
                continue;
            const size_t tab = line.find('\t');
            jvalue meta;
            if (!json_reader(line.substr(0, tab)).document(meta))
            {
                why = dir + "/data.snapshot is not a snapshot of this database";
                return false;
            }
            if (!header)
            {
                header = true;
                continue;
            }
            const jvalue* c = member(meta, "c");
            const jvalue* id = member(meta, "id");
            const jvalue* v = member(meta, "v");
            const jvalue* o = member(meta, "o");
            if (tab == std::string_view::npos || !c || !id || !v)
                continue;
            event e;
            e.coll = c->s;
            e.id = id->s;
            e.v = std::strtoull(v->s.c_str(), nullptr, 10);
            e.owner = o ? o->s : std::string();
            e.json.assign(line.substr(tab + 1));
            out[{e.coll, e.id}] = std::move(e);
        }
    }
    const std::string jpath = dir + "/data.journal";
    std::string owner;
    if (mutation_journal::probe(jpath, owner) != mutation_journal::probe_result::has_records)
        return true;
    mutation_journal::replay_stats st;
    bool bad = false;
    mutation_journal::replay(jpath, [&](std::string_view rec) {
        socketley::bytes::reader r(rec);
        uint8_t kind = 0;
        uint32_t n = 0;
        if (!r.u8(kind) || kind != rec_write || !r.u32(n))
        {
            bad = true;
            return;
        }
        for (uint32_t i = 0; i < n && !bad; ++i)
        {
            uint8_t t = 0;
            event e;
            if (!r.u8(t) || !r.bytes(e.coll, 64) || !r.bytes(e.id, 128))
            {
                bad = true;
                break;
            }
            if (t == ent_del)
            {
                out.erase({e.coll, e.id});
                continue;
            }
            if (!r.u64(e.v) || !r.bytes(e.owner, 256) || !r.bytes(e.json, store::max_doc))
            {
                bad = true;
                break;
            }
            out[{e.coll, e.id}] = std::move(e);
        }
    }, st);
    if (bad)
        why = jpath + " holds a record this build cannot read";
    return !bad;
}

}   // namespace

bool store::open(const std::string& dir, const schema& s, std::string& why)
{
    close();
    m_schema = s;
    // A database of the first format, a snapshot and a journal, is taken into segments once and its files kept aside.
    std::error_code ec;
    const bool v1 = std::filesystem::exists(dir + "/data.snapshot", ec) || std::filesystem::exists(dir + "/data.journal", ec);
    std::map<std::pair<std::string, std::string>, event> old;
    if (v1 && !read_v1(dir, old, why))
        return false;
    if (!m_log.open(dir, [this](uint32_t seg, uint64_t off, std::string_view p) { return scan(seg, off, p); }, why))
        return false;
    if (v1)
    {
        for (auto& [key, e] : old)
        {
            e.seq = ++m_seq;
            std::vector<uint64_t> offs;
            const location at = m_log.append(encode_record(e.seq, {e}, &offs));
            coll_state* c = coll_of(e.coll);
            if (!c)
                c = &make_coll(e.coll);
            c->last_seq = e.seq;
            doc d;
            d.owner = e.owner;
            d.v = e.v;
            d.seq = e.seq;
            d.at = location{at.seg, at.off + offs[0], static_cast<uint32_t>(e.json.size())};
            jvalue body;
            if (!json_reader(e.json).document(body))
            {
                why = "a document of the first format is no JSON object";
                return false;
            }
            derive(*c, body, d);
            set_doc(*c, e.coll, e.id, &d);
            std::string ignored;
            m_log.roll_if_full(ignored);
        }
        if (!m_log.sync())
        {
            why = "the documents of the first format could not be written into segments";
            return false;
        }
        for (const char* f : {"/data.snapshot", "/data.journal"})
            std::filesystem::rename(dir + f, dir + f + ".v1", ec);
    }
    // The deletions scan() remembered were for itself.
    m_tombs.clear();
    // The unique indexes hold as the documents read are, or the schema is refused.
    schema none;
    const schema wanted = m_schema;
    m_schema = none;
    for (auto& [name, c] : m_colls)
        for (auto& ix : c.indexes)
            ix.def.unique = false;
    if (!set_schema(wanted, why))
        return false;
    return true;
}

void store::close()
{
    m_log.close();
    m_colls.clear();
    m_expiry.clear();
    m_live.clear();
    m_staged.clear();
    clear_cache();
    m_docs = 0;
    m_bytes = 0;
    m_seq = 0;
    m_doomed.clear();
    m_pins = 0;
    m_job_running = false;
}

std::vector<std::string> store::collection_names() const
{
    std::vector<std::string> out;
    out.reserve(m_colls.size());
    for (const auto& [name, c] : m_colls)
        if (!c.docs.empty())
            out.push_back(name);
    std::sort(out.begin(), out.end());
    return out;
}

// ─── Reading ────────────────────────────────────────────────────────────────

bool store::expired(const doc& d) const
{
    return d.expires && d.expires <= now_sec();
}

bool store::may_read(const principal& who, access a, const doc& d) const
{
    if (expired(d))
        return false;
    if (who.kind == principal::key)
        return true;
    switch (a)
    {
        case access::priv:    return false;
        case access::owner:   return who.kind == principal::user && d.owner == who.sub;
        case access::shared:  return who.kind == principal::user;
        case access::open:
        case access::catalog: return true;
    }
    return false;
}

namespace
{

// Whether the principal may read the collection at all, and the error when not.
bool reach(const principal& who, access a, error& err)
{
    if (who.kind == principal::key)
        return true;
    if (who.kind == principal::anyone && (a == access::priv || a == access::owner || a == access::shared))
    {
        err = fail(401, "sign_in", "this collection is read by a signed-in account or a key");
        return false;
    }
    if (a == access::priv)
    {
        err = fail(403, "forbidden", "this collection is reached by a key only");
        return false;
    }
    return true;
}

}   // namespace

const doc* store::get(std::string_view coll, std::string_view id) const
{
    const coll_state* c = coll_of(coll);
    if (!c)
        return nullptr;
    const auto it = c->docs.find(id);
    return it == c->docs.end() || expired(it->second) ? nullptr : &it->second;
}

bool store::read(const principal& who, std::string_view coll, std::string_view id, std::string& out, error& err,
                 uint64_t& depends, uint64_t* version)
{
    depends = 0;
    const access a = access_of(coll);
    if (!reach(who, a, err))
        return false;
    const coll_state* c = coll_of(coll);
    // An absence rests on the collection's last change, which may be the deletion not yet on the disk.
    if (c)
        depends = c->last_seq;
    const auto it = c ? c->docs.find(id) : decltype(c->docs)::const_iterator{};
    // Another's document in an owner collection is answered as absent, so its id says nothing.
    if (!c || it == c->docs.end() || !may_read(who, a, it->second))
    {
        err = fail(404, "not_found", "no such document");
        return false;
    }
    depends = it->second.seq;
    if (version)
        *version = it->second.v;
    if (std::string_view j; cached(it->second, j))
    {
        write_doc(it->first, it->second, j, out);
        return true;
    }
    std::string json;
    if (!json_of(it->second, json))
    {
        err = fail(503, "unreadable", "the document could not be read from the disk");
        return false;
    }
    write_doc(it->first, it->second, json, out);
    return true;
}

bool store::parse_query(const jvalue& in, query& q, error& err)
{
    if (in.k != jvalue::kind::object)
    {
        err = fail(400, "bad_query", "a query is an object of where, sort, limit, skip and count");
        return false;
    }
    const auto field_ok = [&](std::string_view f) {
        if (system_field(f) || valid_path(f))
            return true;
        err = fail(400, "bad_path", "a field is names of A-Z a-z 0-9 _ - joined by dots: " + std::string(f));
        return false;
    };
    const auto whole = [](const jvalue& v, size_t& out) {
        if (!is_integer(v) || v.s.starts_with('-'))
            return false;
        const auto r = std::from_chars(v.s.data(), v.s.data() + v.s.size(), out);
        return r.ec == std::errc();
    };
    static constexpr std::pair<std::string_view, query::cond::op_t> ops[] = {
        {"eq", query::cond::eq},   {"ne", query::cond::ne},   {"gt", query::cond::gt},
        {"gte", query::cond::gte}, {"lt", query::cond::lt},   {"lte", query::cond::lte},
        {"in", query::cond::in},   {"prefix", query::cond::prefix}, {"exists", query::cond::exists},
    };
    const auto op_of = [&](std::string_view name, query::cond::op_t& out) {
        for (const auto& [n, o] : ops)
            if (n == name)
            {
                out = o;
                return true;
            }
        return false;
    };
    for (const auto& [k, v] : in.members)
    {
        if (k == "where")
        {
            if (v.k != jvalue::kind::object)
            {
                err = fail(400, "bad_query", "where is an object of fields and conditions");
                return false;
            }
            for (const auto& [field, cond] : v.members)
            {
                if (!field_ok(field))
                    return false;
                // An object all of whose names are conditions is conditions; any other value is what the field equals.
                bool conditions = cond.k == jvalue::kind::object && !cond.members.empty();
                query::cond::op_t o{};
                for (const auto& [name, arg] : cond.members)
                    conditions = conditions && op_of(name, o);
                if (!conditions)
                {
                    q.where.push_back({field, query::cond::eq, cond, key_of(&cond)});
                    continue;
                }
                for (const auto& [name, arg] : cond.members)
                {
                    op_of(name, o);
                    if ((o == query::cond::in && arg.k != jvalue::kind::array) ||
                        (o == query::cond::prefix && arg.k != jvalue::kind::string) ||
                        (o == query::cond::exists && arg.k != jvalue::kind::boolean))
                    {
                        err = fail(400, "bad_query", name + " takes " +
                                                         (o == query::cond::in       ? "an array"
                                                          : o == query::cond::prefix ? "a string"
                                                                                     : "true or false"));
                        return false;
                    }
                    q.where.push_back({field, o, arg, key_of(&arg)});
                }
            }
        }
        else if (k == "sort")
        {
            if (v.k != jvalue::kind::string || v.s.empty())
            {
                err = fail(400, "bad_query", "sort is a field, - first for the largest first");
                return false;
            }
            q.desc = v.s.front() == '-';
            q.sort = q.desc ? v.s.substr(1) : v.s;
            if (!field_ok(q.sort))
                return false;
        }
        else if (k == "limit")
        {
            if (!whole(v, q.limit) || q.limit < 1 || q.limit > max_limit)
            {
                err = fail(400, "bad_query", "limit is a whole number from 1 to " + std::to_string(max_limit));
                return false;
            }
        }
        else if (k == "skip")
        {
            if (!whole(v, q.skip))
            {
                err = fail(400, "bad_query", "skip is a whole number");
                return false;
            }
        }
        else if (k == "count")
        {
            if (v.k != jvalue::kind::boolean)
            {
                err = fail(400, "bad_query", "count is true or false");
                return false;
            }
            q.count = v.b;
        }
        else
        {
            err = fail(400, "bad_query", "a query takes where, sort, limit, skip and count, not " + k);
            return false;
        }
    }
    return true;
}


bool store::find(const principal& who, std::string_view coll, const query& q, std::string& out, error& err,
                 uint64_t& depends)
{
    depends = 0;
    const access a = access_of(coll);
    if (!reach(who, a, err))
        return false;
    coll_state* c = coll_of(coll);
    if (!c)
    {
        out += q.count ? "{\"count\":0}" : "{\"docs\":[]}";
        return true;
    }
    depends = c->last_seq;
    const bool own_only = who.kind == principal::user && a == access::owner;
    // Where each condition's field is indexed, so its value is read from the document's keys and not its body.
    const auto index_of = [&](std::string_view field) -> int {
        for (size_t i = 0; i < c->indexes.size(); ++i)
            if (c->indexes[i].def.field == field)
                return static_cast<int>(i);
        return -1;
    };
    std::vector<int> cond_ix;
    bool needs_body = false;
    for (const auto& cond : q.where)
    {
        const int ix = system_field(cond.field) ? -2 : index_of(cond.field);
        cond_ix.push_back(ix == -1 || (ix >= 0 && !by_key(cond)) ? -1 : ix);
        needs_body = needs_body || cond_ix.back() == -1;
    }
    const int sort_ix = q.sort.empty() || system_field(q.sort) ? -2 : index_of(q.sort);
    needs_body = needs_body || (!q.sort.empty() && sort_ix == -1);
    const index_state* walk = sort_ix >= 0 ? &c->indexes[static_cast<size_t>(sort_ix)] : nullptr;

    struct hit
    {
        const std::string* id;
        const doc* d;
        std::string json;
        ikey sort;
    };
    std::vector<hit> hits;
    const size_t enough = q.skip + q.limit + 1;
    jvalue scratch, body;
    std::string json;
    bool in_order = false;
    bool unreadable = false;
    // A candidate judged; false once the answer has what it needs.
    const auto consider = [&](const std::string* id, const doc* node) {
        const doc& d = *node;
        if (!may_read(who, a, d))
            return true;
        bool have_body = false;
        if (needs_body)
        {
            // Read in the cache where it lies, so only a document read from the disk is copied for its hit.
            std::string_view in;
            json.clear();
            if (!cached(d, in) && json_of(d, json))
                in = json;
            if (in.empty() || !json_reader(in).document(body))
            {
                unreadable = true;
                return false;
            }
            have_body = true;
        }
        for (size_t i = 0; i < q.where.size(); ++i)
        {
            const auto& cond = q.where[i];
            const bool ok = cond_ix[i] >= 0  ? meets_key(cond, d.keys[static_cast<size_t>(cond_ix[i])])
                            : cond_ix[i] == -2 ? meets(cond, system_of(d, *id, cond.field, scratch))
                                               : meets(cond, at_path(body, cond.field));
            if (!ok)
                return true;
        }
        hit h{id, &d, {}, {}};
        if (!q.sort.empty() && !in_order)
            h.sort = sort_ix >= 0      ? d.keys[static_cast<size_t>(sort_ix)]
                     : sort_ix == -2   ? key_of(system_of(d, *id, q.sort, scratch))
                                       : key_of(have_body ? at_path(body, q.sort) : nullptr);
        if (have_body)
            h.json = std::move(json);
        hits.push_back(std::move(h));
        return !in_order || q.count || hits.size() < enough;
    };
    // A source already in the answer's order, read from the end it starts at as far as the answer needs.
    const auto walk_run = [&](auto lo, auto hi) {
        in_order = true;
        if (q.desc)
        {
            while (hi != lo)
            {
                --hi;
                if (!consider(&hi->first.second, hi->second))
                    break;
            }
        }
        else
            for (; lo != hi && consider(&lo->first.second, lo->second); ++lo) {}
    };
    // One index's run of a condition, found with one descent: up from its start, or down from its end.
    const auto walk_cond = [&](const index_entries& s, const query::cond& cond) {
        in_order = true;
        if (q.desc)
        {
            for (auto it = run_end(s, cond); it != s.begin();)
            {
                --it;
                if (!in_run(cond, it->first.first) || !consider(&it->first.second, it->second))
                    break;
            }
        }
        else
            for (auto it = run_start(s, cond); it != s.end() && in_run(cond, it->first.first); ++it)
                if (!consider(&it->first.second, it->second))
                    break;
    };

    // Where the documents come from: the account's own or one index's run of values, read in place when their entries
    // are already in the answer's order, the sort's index, or every document.
    std::vector<std::pair<const std::string*, const doc*>> ids;
    const auto take_run = [&](const index_entries& s, const query::cond& cond) {
        for (auto it = run_start(s, cond); it != s.end() && in_run(cond, it->first.first); ++it)
            ids.emplace_back(&it->first.second, it->second);
    };
    bool planned = false;
    if (own_only)
    {
        // An account's own are in the order of their ids, which is an answer's when it names no sort.
        in_order = q.sort.empty();
        for (auto it = c->by_owner.lower_bound({who.sub, std::string()});
             it != c->by_owner.end() && it->first.first == who.sub; ++it)
        {
            if (!in_order)
                ids.emplace_back(&it->first.second, it->second);
            else if (!consider(&it->first.second, it->second))
                break;
        }
        planned = true;
    }
    for (const auto& cond : q.where)
    {
        if (planned)
            break;
        const int pos = system_field(cond.field) ? -1 : index_of(cond.field);
        if (pos < 0 || cond.op == query::cond::ne || cond.op == query::cond::exists)
            continue;
        const index_state& ix = c->indexes[static_cast<size_t>(pos)];
        planned = true;
        if (cond.op == query::cond::in)
        {
            for (const auto& v : cond.value.items)
            {
                query::cond one;
                one.key = key_of(&v);
                take_run(ix.entries, one);
            }
            continue;
        }
        if (sort_ix == pos || (q.sort.empty() && cond.op == query::cond::eq))
            walk_cond(ix.entries, cond);
        else
            take_run(ix.entries, cond);
    }
    if (!planned && walk)
        walk_run(walk->entries.begin(), walk->entries.end());
    else if (!planned)
    {
        ids.reserve(c->docs.size());
        for (const auto& [id, d] : c->docs)
            ids.emplace_back(&id, &d);
    }
    if (!in_order)
    {
        std::sort(ids.begin(), ids.end(), [](const auto& x, const auto& y) { return *x.first < *y.first; });
        ids.erase(std::unique(ids.begin(), ids.end(), [](const auto& x, const auto& y) { return *x.first == *y.first; }),
                  ids.end());
        for (const auto& [id, node] : ids)
            if (!consider(id, node))
                break;
    }
    if (unreadable)
    {
        err = fail(503, "unreadable", "a document could not be read from the disk");
        return false;
    }
    if (q.count)
    {
        out += "{\"count\":" + std::to_string(hits.size()) + "}";
        return true;
    }
    if (!in_order && !q.sort.empty())
        std::stable_sort(hits.begin(), hits.end(), [&](const hit& x, const hit& y) {
            if (x.sort == y.sort)
                return q.desc ? *y.id < *x.id : *x.id < *y.id;
            return q.desc ? y.sort < x.sort : x.sort < y.sort;
        });
    else if (!in_order && q.desc)
        std::reverse(hits.begin(), hits.end());
    out += "{\"docs\":[";
    const size_t end = std::min(hits.size(), q.skip + q.limit);
    for (size_t i = q.skip; i < end; ++i)
    {
        if (i > q.skip)
            out += ',';
        std::string_view j;
        const bool hit = hits[i].json.empty() && cached(*hits[i].d, j);
        if (!hit && hits[i].json.empty() && !json_of(*hits[i].d, hits[i].json))
        {
            err = fail(503, "unreadable", "a document could not be read from the disk");
            return false;
        }
        write_doc(*hits[i].id, *hits[i].d, hit ? j : std::string_view(hits[i].json), out);
    }
    out += ']';
    if (hits.size() > q.skip + q.limit)
        out += ",\"next\":" + std::to_string(q.skip + q.limit);
    out += '}';
    return true;
}

// ─── Writing ────────────────────────────────────────────────────────────────

bool store::unique_ok(const coll_state& c, const std::string& id, const doc& d, error& err) const
{
    for (size_t i = 0; i < c.indexes.size(); ++i)
    {
        const auto& ix = c.indexes[i];
        if (!ix.def.unique)
            continue;
        const ikey& k = d.keys[i];
        if (k.rank == ikey::null)
            continue;
        for (auto it = ix.entries.lower_bound({k, std::string()}); it != ix.entries.end() && it->first.first == k; ++it)
            if (it->first.second != id)
            {
                // A document whose time came holds its value no longer.
                if (expired(*it->second))
                    continue;
                err = fail(409, "taken", ix.def.field + " holds a value another document has: it is unique");
                return false;
            }
    }
    return true;
}

bool store::write(const principal& who, std::vector<write_op>& ops, std::string& out, error& err,
                  std::vector<event>* events, first_change* first)
{
    if (ops.empty() || ops.size() > max_ops)
    {
        err = fail(400, "bad_write", "a write is 1 to " + std::to_string(max_ops) + " changes");
        return false;
    }
    if (who.kind == principal::anyone)
    {
        err = fail(401, "sign_in", "writing takes a signed-in account or a key");
        return false;
    }
    // What each touched document was before, so a change that cannot be made takes back those made before it.
    struct undo
    {
        coll_state* c;
        std::string coll;
        std::string id;
        bool had;
        doc before;
    };
    std::vector<undo> undos;
    std::vector<std::string> made_colls;
    const uint64_t bytes_before = m_bytes;
    std::string results = "[";
    const auto rollback = [&] {
        for (auto it = undos.rbegin(); it != undos.rend(); ++it)
            set_doc(*it->c, it->coll, it->id, it->had ? &it->before : nullptr);
        for (const auto& name : made_colls)
            m_colls.erase(name);
        m_staged.clear();
    };
    const auto refuse = [&](error e) {
        rollback();
        err = std::move(e);
        return false;
    };
    const uint64_t seq = m_seq + 1;
    size_t total = 0;

    for (auto& op : ops)
    {
        if (!valid_collection(op.coll))
            return refuse(fail(400, "bad_collection", "a collection's name is 1 to 64 of a-z 0-9 _ -, a letter first"));
        const access a = access_of(op.coll);
        if (who.kind == principal::user && (a == access::priv || a == access::catalog))
            return refuse(fail(403, "forbidden", "this collection is written by a key only"));
        coll_state* c = coll_of(op.coll);
        if (!c)
        {
            if (m_colls.size() >= max_collections)
                return refuse(fail(507, "full", "a database holds at most " + std::to_string(max_collections) +
                                                    " collections"));
            c = &make_coll(op.coll);
            made_colls.push_back(op.coll);
        }
        if (op.kind == write_op::insert)
        {
            // An id the API reads as its own path, _ first, is drawn again.
            do
                op.id = new_id();
            while (!op.id.empty() && (!valid_id(op.id) || c->docs.contains(op.id)));
            if (op.id.empty())
                return refuse(fail(503, "no_randomness", "no randomness for an id"));
        }
        else if (!valid_id(op.id))
            return refuse(fail(400, "bad_id", "an id is 1 to 128 of A-Z a-z 0-9 . _ : @ + -, not _ first"));

        auto it = c->docs.find(op.id);
        // A document whose time came is gone, whatever the deletion that says so has not yet done.
        const doc* old = it == c->docs.end() || expired(it->second) ? nullptr : &it->second;
        if (op.if_absent && old)
            return refuse(fail(412, "exists", "the document exists"));
        if (op.if_v && (!old || old->v != op.if_v))
            return refuse(fail(412, "version", old ? "the document is at version " + std::to_string(old->v) + ", not " +
                                                         std::to_string(op.if_v)
                                                   : "no such document"));
        if ((op.kind == write_op::patch || op.kind == write_op::del) && !old)
            return refuse(fail(404, "not_found", "no such document"));
        if (first && &op == &ops.front())
            *first = first_change{old != nullptr, old ? old->v + 1 : 1};
        if (who.kind == principal::user && old && old->owner != who.sub)
            return refuse(a == access::owner ? fail(404, "not_found", "no such document")
                                             : fail(403, "not_yours", "the document is another account's"));
        const std::string key = staged_key(op.coll, op.id);
        if (std::none_of(undos.begin(), undos.end(), [&](const undo& u) { return u.c == c && u.id == op.id; }))
            undos.push_back({c, op.coll, op.id, it != c->docs.end(), it != c->docs.end() ? it->second : doc{}});

        if (op.kind == write_op::del)
        {
            set_doc(*c, op.coll, op.id, nullptr);
            m_staged.erase(key);
            results += results.size() > 1 ? "," : "";
            results += "{\"_id\":";
            write_string(op.id, results);
            results += ",\"deleted\":true}";
            continue;
        }
        doc nd;
        if (op.kind == write_op::patch)
        {
            nd = *old;
            jvalue body;
            const auto s = m_staged.find(key);
            if (s != m_staged.end() ? !json_reader(s->second).document(body) : !body_of(*old, body))
                return refuse(fail(503, "unreadable", "the document could not be read from the disk"));
            if (!apply_patch(body, op.body, err))
            {
                error e = std::move(err);
                return refuse(std::move(e));
            }
            op.body = std::move(body);
        }
        else
        {
            if (op.body.k != jvalue::kind::object)
                return refuse(fail(400, "bad_document", "a document is a JSON object"));
            nd.owner = old ? old->owner : std::string();
            // What a document read back carries is taken off, and _owner set by a key alone.
            for (auto m = op.body.members.begin(); m != op.body.members.end();)
            {
                if (!m->first.starts_with('_'))
                {
                    ++m;
                    continue;
                }
                if (m->first == "_id" && (m->second.k != jvalue::kind::string || m->second.s != op.id))
                    return refuse(fail(400, "bad_document", "_id says another id than the one written"));
                if (m->first == "_owner" && who.kind == principal::key)
                {
                    if (m->second.k != jvalue::kind::string || m->second.s.size() > 256)
                        return refuse(fail(400, "bad_document", "_owner is an account's id"));
                    nd.owner = m->second.s;
                }
                else if (!system_field(m->first))
                    return refuse(fail(400, "bad_document", "a field's name starting with _ is the database's: " +
                                                                m->first));
                m = op.body.members.erase(m);
            }
            for (const auto& [k, v] : op.body.members)
                if (!valid_path(k) || k.find('.') != std::string::npos)
                    return refuse(fail(400, "bad_document", "a field's name is 1 to 64 of A-Z a-z 0-9 _ -: " + k));
        }
        if (who.kind == principal::user)
            nd.owner = who.sub;
        nd.v = old ? old->v + 1 : 1;
        nd.seq = seq;
        if (depth_of(op.body) > socketley::storage::json_max_depth)
            return refuse(fail(400, "too_deep", "a document nests at most " +
                                                    std::to_string(socketley::storage::json_max_depth) + " deep"));
        std::string json = to_json(op.body);
        if (json.size() > max_doc)
            return refuse(fail(413, "too_large", "a document is at most 1 MiB; keep large things in a storage and "
                                                 "their address here"));
        total += json.size();
        if (total > max_write)
            return refuse(fail(413, "too_large", "a write is at most 32 MiB"));
        derive(*c, op.body, nd);
        // No place on the disk yet: the length counts for the bounds, the place comes with the record.
        nd.at = location{0, 0, static_cast<uint32_t>(json.size())};
        if (!unique_ok(*c, op.id, nd, err))
        {
            error e = std::move(err);
            return refuse(std::move(e));
        }
        results += results.size() > 1 ? "," : "";
        write_doc(op.id, nd, json, results);
        set_doc(*c, op.coll, op.id, &nd);
        m_staged[key] = std::move(json);
    }
    if (m_max_bytes && m_bytes > m_max_bytes && m_bytes > bytes_before)
        return refuse(fail(507, "full", "the database holds its --max-bytes"));

    // One record of every touched document as it now is, and each one's place in it.
    std::vector<event> evs;
    evs.reserve(undos.size());
    for (const auto& u : undos)
    {
        event e;
        e.seq = seq;
        e.coll = u.coll;
        e.id = u.id;
        const auto it = u.c->docs.find(u.id);
        if (it == u.c->docs.end())
        {
            e.del = true;
            e.owner = u.had ? u.before.owner : std::string();
        }
        else
        {
            e.owner = it->second.owner;
            e.v = it->second.v;
            // Taken rather than copied: the staging is cleared once the record is made.
            e.json = std::move(m_staged[staged_key(u.coll, u.id)]);
        }
        evs.push_back(std::move(e));
    }
    std::vector<uint64_t> offs;
    const location at = m_log.append(encode_record(seq, evs, &offs));
    m_seq = seq;
    for (size_t i = 0; i < evs.size(); ++i)
    {
        auto& u = undos[i];
        u.c->last_seq = seq;
        if (evs[i].del)
            continue;
        doc& d = u.c->docs.find(u.id)->second;
        live_add(d, -1);
        d.at = location{at.seg, at.off + offs[i], static_cast<uint32_t>(evs[i].json.size())};
        live_add(d, +1);
        cache_put(d, evs[i].json);
    }
    m_staged.clear();
    if (events)
        for (auto& e : evs)
            events->push_back(std::move(e));
    std::string ignored;
    m_log.roll_if_full(ignored);
    out += results;
    out += ']';
    return true;
}

size_t store::expire(int64_t now, std::vector<event>* events)
{
    std::vector<write_op> ops;
    for (auto it = m_expiry.begin(); it != m_expiry.end() && std::get<0>(*it) <= now && ops.size() < max_ops; ++it)
    {
        write_op op;
        op.kind = write_op::del;
        op.coll = std::get<1>(*it);
        op.id = std::get<2>(*it);
        ops.push_back(std::move(op));
    }
    if (ops.empty())
        return 0;
    // Through write(), as a key, after the time came: expired() makes it absent, so the deletion is written directly.
    std::vector<event> evs;
    const uint64_t seq = m_seq + 1;
    for (const auto& op : ops)
    {
        coll_state* c = coll_of(op.coll);
        const auto it = c ? c->docs.find(op.id) : decltype(c->docs)::iterator{};
        if (!c || it == c->docs.end())
            continue;
        event e;
        e.seq = seq;
        e.coll = op.coll;
        e.id = op.id;
        e.owner = it->second.owner;
        e.del = true;
        set_doc(*c, op.coll, op.id, nullptr);
        c->last_seq = seq;
        evs.push_back(std::move(e));
    }
    if (evs.empty())
        return 0;
    m_log.append(encode_record(seq, evs));
    m_seq = seq;
    const size_t n = evs.size();
    if (events)
        for (auto& e : evs)
            events->push_back(std::move(e));
    std::string ignored;
    m_log.roll_if_full(ignored);
    return n;
}

int64_t store::next_expiry() const
{
    return m_expiry.empty() ? 0 : std::get<0>(*m_expiry.begin());
}

bool store::apply(const std::vector<event>& evs, std::string& why)
{
    // Events of one sequence number are one record, as the write that made them was.
    size_t from = 0;
    while (from < evs.size())
    {
        size_t to = from + 1;
        while (to < evs.size() && evs[to].seq == evs[from].seq)
            ++to;
        const std::vector<event> group(evs.begin() + static_cast<std::ptrdiff_t>(from),
                                       evs.begin() + static_cast<std::ptrdiff_t>(to));
        const uint64_t seq = group.front().seq;
        if (seq <= m_seq)
        {
            from = to;
            continue;
        }
        std::vector<uint64_t> offs;
        const location at = m_log.append(encode_record(seq, group, &offs));
        for (size_t i = 0; i < group.size(); ++i)
        {
            const event& e = group[i];
            if (!valid_collection(e.coll) || !valid_id(e.id))
            {
                why = "a change names no collection or id this database takes";
                return false;
            }
            coll_state* c = coll_of(e.coll);
            if (!c)
                c = &make_coll(e.coll);
            c->last_seq = seq;
            if (e.del)
            {
                set_doc(*c, e.coll, e.id, nullptr);
                continue;
            }
            doc d;
            d.owner = e.owner;
            d.v = e.v;
            d.seq = seq;
            d.at = location{at.seg, at.off + offs[i], static_cast<uint32_t>(e.json.size())};
            jvalue body;
            if (!json_reader(e.json).document(body))
            {
                why = "a change carries a document that is no JSON object";
                return false;
            }
            derive(*c, body, d);
            set_doc(*c, e.coll, e.id, &d);
            cache_put(c->docs.find(e.id)->second, e.json);
        }
        m_seq = seq;
        std::string ignored;
        m_log.roll_if_full(ignored);
        from = to;
    }
    return true;
}

void store::mark(uint64_t seq)
{
    if (seq <= m_seq)
        return;
    m_log.append(encode_record(seq, {}));
    m_seq = seq;
}

bool store::reset(std::string& why)
{
    if (!m_log.clear(why))
        return false;
    m_colls.clear();
    m_expiry.clear();
    m_live.clear();
    clear_cache();
    m_docs = 0;
    m_bytes = 0;
    m_seq = 0;
    m_doomed.clear();
    return true;
}

// ─── Merges, backups and whole copies ───────────────────────────────────────

std::vector<copy_job::item> store::everything()
{
    std::vector<copy_job::item> out;
    out.reserve(m_docs);
    for (const auto& [name, c] : m_colls)
        for (const auto& [id, d] : c.docs)
            if (!expired(d))
                out.push_back(copy_job::item{name, id, d.owner, d.v, d.seq, d.at, {}});
    // In the order they were written, so a copy taken in applies older changes first.
    std::sort(out.begin(), out.end(), [](const auto& x, const auto& y) { return x.seq < y.seq; });
    return out;
}

std::unique_ptr<copy_job> store::plan_merge()
{
    if (m_job_running)
        return nullptr;
    const std::vector<uint32_t> sealed = m_log.sealed();
    if (sealed.empty())
        return nullptr;
    uint64_t size = 0, live = 0;
    for (const uint32_t s : sealed)
    {
        size += m_log.size_of(s);
        const auto it = m_live.find(s);
        live += it == m_live.end() ? 0 : it->second;
    }
    const uint64_t dead = size > live ? size - live : 0;
    if (dead < merge_floor || dead < live)
        return nullptr;
    auto job = std::make_unique<copy_job>();
    job->merge = true;
    job->sources = sealed;
    job->dir = m_log.dir();
    for (const auto& [name, c] : m_colls)
        for (const auto& [id, d] : c.docs)
            if (std::find(sealed.begin(), sealed.end(), d.at.seg) != sealed.end())
                job->items.push_back(copy_job::item{name, id, d.owner, d.v, d.seq, d.at, {}});
    job->dest_seg = m_log.reserve();
    job->dest = m_log.path_of(job->dest_seg);
    m_job_running = true;
    return job;
}

std::unique_ptr<copy_job> store::plan_backup(const std::string& dest)
{
    if (m_job_running || !m_log.flush())
        return nullptr;
    auto job = std::make_unique<copy_job>();
    job->dir = m_log.dir();
    job->dest = dest;
    job->items = everything();
    m_job_running = true;
    return job;
}

void store::finish(copy_job& job)
{
    m_job_running = false;
    if (!job.ok || !job.merge)
        return;
    std::string why;
    if (!m_log.adopt(job.dest_seg, why))
        return;
    // A document still where the merge read it now lies where it was copied; one changed since stays where it went.
    for (const auto& it : job.items)
    {
        coll_state* c = coll_of(it.coll);
        if (!c)
            continue;
        const auto d = c->docs.find(it.id);
        if (d == c->docs.end() || d->second.seq != it.seq || d->second.at.seg != it.from.seg ||
            d->second.at.off != it.from.off)
            continue;
        cache_drop(d->second);
        live_add(d->second, -1);
        d->second.at = it.to;
        live_add(d->second, +1);
    }
    ++m_merges;
    for (const uint32_t s : job.sources)
        m_doomed.push_back(s);
    if (m_pins == 0)
        drop_doomed();
}

void store::unpin()
{
    if (m_pins > 0 && --m_pins == 0)
        drop_doomed();
}

void store::drop_doomed()
{
    for (const uint32_t s : m_doomed)
    {
        m_log.remove(s);
        m_live.erase(s);
    }
    m_doomed.clear();
}

}   // namespace socketley::db
