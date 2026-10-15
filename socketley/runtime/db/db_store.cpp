#include "db_store.h"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <filesystem>

#include <sys/stat.h>

#include <openssl/rand.h>

#include "../../shared/byte_codec.h"
#include "../../shared/jws.h"
#include "../../shared/replaced_file.h"

namespace socketley::db
{

namespace
{

constexpr uint8_t rec_write = 1;
constexpr uint8_t ent_put   = 1;
constexpr uint8_t ent_del   = 2;
constexpr std::string_view journal_owner = "socketley-db";
constexpr size_t doc_overhead = 96;
// Past either the journal is folded into a snapshot, so a start replays a bounded tail.
constexpr uint64_t compact_records = 100000;
constexpr uint64_t compact_bytes   = 64ull << 20;

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

// A field of a document as a query sees it: _id, _owner and _v beside the document's own.
const jvalue* field_of(const doc& d, const std::string& id, std::string_view path, jvalue& scratch)
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
    if (path == "_v")
    {
        scratch.k = jvalue::kind::number;
        scratch.s = std::to_string(d.v);
        return &scratch;
    }
    return at_path(d.body, path);
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
            return v && key_meets(c, key_of(v));
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

void put_entry(socketley::bytes::writer& w, std::string_view coll, std::string_view id, const doc* d,
               const std::string* json)
{
    w.u8(d ? ent_put : ent_del);
    w.bytes(coll);
    w.bytes(id);
    if (d)
    {
        w.u64(d->v);
        w.bytes(d->owner);
        w.bytes(*json);
    }
}

}   // namespace

void write_doc(const std::string& id, const doc& d, std::string& out)
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
    for (const auto& [k, m] : d.body.members)
    {
        out += ',';
        write_string(k, out);
        out += ':';
        write_json(m, out);
    }
    out += '}';
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

// ─── Opening and closing ────────────────────────────────────────────────────

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

access store::access_of(std::string_view coll) const
{
    const collection_def* d = m_schema.find(coll);
    return d ? d->acc : access::priv;
}

void store::index_doc(coll_state& c, const std::string& id, const doc& d, bool add)
{
    for (auto& ix : c.indexes)
    {
        std::pair<ikey, std::string> e{key_of(at_path(d.body, ix.def.field)), id};
        if (add)
            ix.entries.insert(std::move(e));
        else
            ix.entries.erase(e);
    }
    if (!d.owner.empty())
    {
        if (add)
            c.by_owner.emplace(d.owner, id);
        else
            c.by_owner.erase({d.owner, id});
    }
}

void store::set_doc(coll_state& c, const std::string& id, const doc* d)
{
    if (const auto it = c.docs.find(id); it != c.docs.end())
    {
        index_doc(c, id, it->second, false);
        m_bytes -= it->second.bytes;
        --m_docs;
        c.docs.erase(it);
    }
    if (d)
    {
        const auto [it, made] = c.docs.emplace(id, *d);
        index_doc(c, id, it->second, true);
        m_bytes += d->bytes;
        ++m_docs;
    }
}

void store::rebuild(coll_state& c, const collection_def* def)
{
    c.indexes.clear();
    if (def)
        for (const auto& d : def->indexes)
            c.indexes.push_back(index_state{d, {}});
    for (auto& ix : c.indexes)
        for (const auto& [id, d] : c.docs)
            ix.entries.emplace(key_of(at_path(d.body, ix.def.field)), id);
}

bool store::set_schema(const schema& s, std::string& why)
{
    // Every unique index the schema has checked against the documents before anything changes.
    for (const auto& [name, c] : m_colls)
        if (const collection_def* def = s.find(name))
            for (const auto& ix : def->indexes)
            {
                if (!ix.unique)
                    continue;
                std::set<ikey> seen;
                for (const auto& [id, d] : c.docs)
                {
                    ikey k = key_of(at_path(d.body, ix.field));
                    if (k.rank != ikey::null && !seen.insert(std::move(k)).second)
                    {
                        why = name + "." + ix.field + " cannot be unique: two documents hold one value";
                        return false;
                    }
                }
            }
    m_schema = s;
    for (auto& [name, c] : m_colls)
        rebuild(c, m_schema.find(name));
    return true;
}

bool store::apply(std::string_view record)
{
    socketley::bytes::reader r(record);
    uint8_t kind = 0;
    uint32_t n = 0;
    if (!r.u8(kind) || kind != rec_write || !r.u32(n) || n > max_ops)
        return false;
    for (uint32_t i = 0; i < n; ++i)
    {
        uint8_t e = 0;
        std::string coll, id;
        if (!r.u8(e) || !r.bytes(coll, 64) || !r.bytes(id, 128) || !valid_collection(coll))
            return false;
        coll_state* c = coll_of(coll);
        if (!c)
        {
            c = &m_colls[coll];
            rebuild(*c, m_schema.find(coll));
        }
        if (e == ent_del)
        {
            set_doc(*c, id, nullptr);
            continue;
        }
        if (e != ent_put)
            return false;
        doc d;
        std::string json;
        if (!r.u64(d.v) || !r.bytes(d.owner, 256) || !r.bytes(json, max_doc) || !json_reader(json).document(d.body))
            return false;
        d.bytes = json.size() + id.size() + d.owner.size() + doc_overhead;
        set_doc(*c, id, &d);
    }
    return true;
}

bool store::read_snapshot(const std::string& path, std::string& why)
{
    std::string text;
    if (!read_whole_file(path, text))
        return true;   // no snapshot yet: everything is in the journal
    m_snapshot_bytes = text.size();
    std::string_view rest = text;
    size_t line_no = 0;
    bool header = false;
    while (!rest.empty())
    {
        const size_t nl = rest.find('\n');
        const std::string_view line = rest.substr(0, nl);
        rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
        ++line_no;
        if (line.empty())
            continue;
        const std::string at = path + " line " + std::to_string(line_no);
        // A document's line is its place, a tab, and its fields, so a document as deep as a write allows still reads.
        const size_t tab = line.find('\t');
        jvalue meta;
        if (!json_reader(line.substr(0, tab)).document(meta))
        {
            why = at + " is not JSON";
            return false;
        }
        if (!header)
        {
            const jvalue* f = member(meta, "format");
            const jvalue* v = member(meta, "version");
            if (!f || f->k != jvalue::kind::string || f->s != journal_owner)
            {
                why = path + " is not a db snapshot";
                return false;
            }
            // A newer build's snapshot is left alone rather than read in part and written back without the rest.
            if (const uint64_t ver = v ? std::strtoull(v->s.c_str(), nullptr, 10) : 0; ver > format_version)
            {
                why = path + " is version " + std::to_string(ver) + ", newer than this build reads (" +
                      std::to_string(format_version) + "); start the build that wrote it";
                return false;
            }
            header = true;
            continue;
        }
        const jvalue* c = member(meta, "c");
        const jvalue* id = member(meta, "id");
        const jvalue* v = member(meta, "v");
        const jvalue* o = member(meta, "o");
        doc d;
        if (tab == std::string_view::npos || !c || c->k != jvalue::kind::string || !valid_collection(c->s) || !id ||
            id->k != jvalue::kind::string || !v || v->k != jvalue::kind::number ||
            !json_reader(line.substr(tab + 1)).document(d.body))
        {
            why = at + " is not a document";
            return false;
        }
        d.v = std::strtoull(v->s.c_str(), nullptr, 10);
        if (o && o->k == jvalue::kind::string)
            d.owner = o->s;
        d.bytes = line.size() - tab + id->s.size() + d.owner.size() + doc_overhead;
        coll_state& cs = m_colls[c->s];
        set_doc(cs, id->s, &d);
    }
    return true;
}

bool store::open(const std::string& dir, std::string& why)
{
    close();
    m_dir = dir;
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (!std::filesystem::is_directory(dir, ec))
    {
        why = "the data directory " + dir + " cannot be made";
        return false;
    }
    if (::chmod(dir.c_str(), 0700) != 0) {}
    if (!read_snapshot(dir + "/data.snapshot", why))
        return false;
    const std::string jpath = dir + "/data.journal";
    std::string owner;
    const auto probe = mutation_journal::probe(jpath, owner);
    if (probe == mutation_journal::probe_result::not_a_journal || probe == mutation_journal::probe_result::unreadable ||
        (probe == mutation_journal::probe_result::has_records && owner != journal_owner))
    {
        why = jpath + " is not this database's journal";
        return false;
    }
    if (probe == mutation_journal::probe_result::has_records)
    {
        mutation_journal::replay_stats st;
        bool bad = false;
        mutation_journal::replay(jpath, [&](std::string_view rec) {
            if (!apply(rec))
                bad = true;
            ++m_journal_records;
            m_journal_bytes += rec.size();
        }, st);
        if (bad)
        {
            why = jpath + " holds a record this build cannot read";
            return false;
        }
    }
    for (auto& [name, c] : m_colls)
        rebuild(c, m_schema.find(name));
    if (!m_journal.open_append(jpath, journal_owner))
    {
        why = jpath + " cannot be opened for writing";
        return false;
    }
    if ((m_journal_records >= compact_records || m_journal_bytes >= compact_bytes) && !compact(why))
        return false;
    return true;
}

void store::close()
{
    m_journal.close();
    m_colls.clear();
    m_docs = 0;
    m_bytes = 0;
    m_journal_records = 0;
    m_journal_bytes = 0;
    m_snapshot_bytes = 0;
}

bool store::compact(std::string& why)
{
    std::string out = "{\"format\":\"" + std::string(journal_owner) + "\",\"version\":" + std::to_string(format_version) +
                      "}\n";
    for (const auto& [name, c] : m_colls)
        for (const auto& [id, d] : c.docs)
        {
            out += "{\"c\":";
            write_string(name, out);
            out += ",\"id\":";
            write_string(id, out);
            out += ",\"v\":" + std::to_string(d.v);
            if (!d.owner.empty())
            {
                out += ",\"o\":";
                write_string(d.owner, out);
            }
            out += "}\t";
            write_json(d.body, out);
            out += '\n';
        }
    if (!replace_file(m_dir + "/data.snapshot", out, true))
    {
        why = "the snapshot could not be written";
        return false;
    }
    // Behind the snapshot that now holds their effects; a crash before this replays records already in it, which
    // changes nothing, since a record sets documents rather than changing them.
    if (!m_journal.reset())
    {
        why = "the journal could not be cut behind the snapshot";
        return false;
    }
    m_snapshot_bytes = out.size();
    m_journal_records = 0;
    m_journal_bytes = 0;
    return true;
}

std::vector<std::string> store::collection_names() const
{
    std::vector<std::string> out;
    out.reserve(m_colls.size());
    for (const auto& [name, c] : m_colls)
        out.push_back(name);
    std::sort(out.begin(), out.end());
    return out;
}

// ─── Reading ────────────────────────────────────────────────────────────────

bool store::may_read(const principal& who, access a, const doc& d) const
{
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
    return it == c->docs.end() ? nullptr : &it->second;
}

bool store::read(const principal& who, std::string_view coll, std::string_view id, std::string& out, error& err) const
{
    const access a = access_of(coll);
    if (!reach(who, a, err))
        return false;
    const coll_state* c = coll_of(coll);
    const auto it = c ? c->docs.find(id) : decltype(c->docs)::const_iterator{};
    // Another's document in an owner collection is answered as absent, so its id says nothing.
    if (!c || it == c->docs.end() || !may_read(who, a, it->second))
    {
        err = fail(404, "not_found", "no such document");
        return false;
    }
    write_doc(it->first, it->second, out);
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

bool store::find(const principal& who, std::string_view coll, const query& q, std::string& out, error& err) const
{
    const access a = access_of(coll);
    if (!reach(who, a, err))
        return false;
    const coll_state* c = coll_of(coll);
    if (!c)
    {
        out += q.count ? "{\"count\":0}" : "{\"docs\":[]}";
        return true;
    }
    const bool own_only = who.kind == principal::user && a == access::owner;
    const index_state* sort_ix = nullptr;
    for (const auto& ix : c->indexes)
        if (!q.sort.empty() && ix.def.field == q.sort)
            sort_ix = &ix;

    // Where the documents come from: the account's own, one index's values, one index's range, the sort's index in
    // its order, or every document.
    std::vector<const std::string*> ids;
    bool in_order = false;
    bool planned = false;
    if (own_only)
    {
        for (auto it = c->by_owner.lower_bound({who.sub, std::string()}); it != c->by_owner.end() && it->first == who.sub;
             ++it)
            ids.push_back(&it->second);
        planned = true;
    }
    for (const auto& cond : q.where)
    {
        if (planned)
            break;
        const index_state* ix = nullptr;
        for (const auto& i : c->indexes)
            if (i.def.field == cond.field)
                ix = &i;
        if (!ix)
            continue;
        if (cond.op == query::cond::eq || cond.op == query::cond::in)
        {
            const auto take = [&](const ikey& k) {
                for (auto it = ix->entries.lower_bound({k, std::string()}); it != ix->entries.end() && it->first == k;
                     ++it)
                    ids.push_back(&it->second);
            };
            if (cond.op == query::cond::eq)
                take(cond.key);
            else
                for (const auto& v : cond.value.items)
                    take(key_of(&v));
            planned = true;
        }
        else if (cond.op != query::cond::ne && cond.op != query::cond::exists)
        {
            // A range stays within the kind of its bound, from the bound up or from the kind's smallest value.
            ikey from = cond.key;
            if (cond.op == query::cond::lt || cond.op == query::cond::lte)
            {
                from.num = -INFINITY;
                from.str.clear();
            }
            for (auto it = ix->entries.lower_bound({from, std::string()});
                 it != ix->entries.end() && it->first.rank == cond.key.rank; ++it)
            {
                if (key_meets(cond, it->first))
                    ids.push_back(&it->second);
                else if (cond.op != query::cond::gt)
                    break;
            }
            planned = true;
        }
    }
    if (!planned && sort_ix)
    {
        in_order = true;
        if (q.desc)
            for (auto it = sort_ix->entries.rbegin(); it != sort_ix->entries.rend(); ++it)
                ids.push_back(&it->second);
        else
            for (const auto& e : sort_ix->entries)
                ids.push_back(&e.second);
    }
    else if (!planned)
    {
        ids.reserve(c->docs.size());
        for (const auto& [id, d] : c->docs)
            ids.push_back(&id);
    }
    if (!in_order)
    {
        std::sort(ids.begin(), ids.end(), [](const std::string* x, const std::string* y) { return *x < *y; });
        ids.erase(std::unique(ids.begin(), ids.end(), [](const std::string* x, const std::string* y) { return *x == *y; }),
                  ids.end());
    }

    std::vector<std::pair<const std::string*, const doc*>> hits;
    const size_t enough = q.skip + q.limit + 1;
    jvalue scratch;
    for (const std::string* id : ids)
    {
        const doc& d = c->docs.find(*id)->second;
        if (!may_read(who, a, d))
            continue;
        bool ok = true;
        for (const auto& cond : q.where)
            if (!meets(cond, field_of(d, *id, cond.field, scratch)))
            {
                ok = false;
                break;
            }
        if (!ok)
            continue;
        hits.emplace_back(id, &d);
        if (in_order && !q.count && hits.size() >= enough)
            break;
    }
    if (q.count)
    {
        out += "{\"count\":" + std::to_string(hits.size()) + "}";
        return true;
    }
    if (!in_order && !q.sort.empty())
    {
        std::vector<std::pair<ikey, size_t>> keys;
        keys.reserve(hits.size());
        for (size_t i = 0; i < hits.size(); ++i)
            keys.emplace_back(key_of(field_of(*hits[i].second, *hits[i].first, q.sort, scratch)), i);
        std::stable_sort(keys.begin(), keys.end(), [&](const auto& x, const auto& y) {
            if (x.first == y.first)
                return q.desc ? *hits[y.second].first < *hits[x.second].first
                              : *hits[x.second].first < *hits[y.second].first;
            return q.desc ? y.first < x.first : x.first < y.first;
        });
        std::vector<std::pair<const std::string*, const doc*>> sorted;
        sorted.reserve(hits.size());
        for (const auto& [k, i] : keys)
            sorted.push_back(hits[i]);
        hits.swap(sorted);
    }
    else if (!in_order && q.desc)
        std::reverse(hits.begin(), hits.end());
    out += "{\"docs\":[";
    const size_t end = std::min(hits.size(), q.skip + q.limit);
    for (size_t i = q.skip; i < end; ++i)
    {
        if (i > q.skip)
            out += ',';
        write_doc(*hits[i].first, *hits[i].second, out);
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
    for (const auto& ix : c.indexes)
    {
        if (!ix.def.unique)
            continue;
        const ikey k = key_of(at_path(d.body, ix.def.field));
        if (k.rank == ikey::null)
            continue;
        for (auto it = ix.entries.lower_bound({k, std::string()}); it != ix.entries.end() && it->first == k; ++it)
            if (it->second != id)
            {
                err = fail(409, "taken", ix.def.field + " holds a value another document has: it is unique");
                return false;
            }
    }
    return true;
}

bool store::write(const principal& who, std::vector<write_op>& ops, std::string& out, error& err)
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
            set_doc(*it->c, it->id, it->had ? &it->before : nullptr);
        for (const auto& name : made_colls)
            m_colls.erase(name);
    };
    const auto refuse = [&](error e) {
        rollback();
        err = std::move(e);
        return false;
    };

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
            c = &m_colls[op.coll];
            rebuild(*c, m_schema.find(op.coll));
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

        const auto it = c->docs.find(op.id);
        const doc* old = it == c->docs.end() ? nullptr : &it->second;
        if (op.if_absent && old)
            return refuse(fail(412, "exists", "the document exists"));
        if (op.if_v && (!old || old->v != op.if_v))
            return refuse(fail(412, "version", old ? "the document is at version " + std::to_string(old->v) + ", not " +
                                                         std::to_string(op.if_v)
                                                   : "no such document"));
        if ((op.kind == write_op::patch || op.kind == write_op::del) && !old)
            return refuse(fail(404, "not_found", "no such document"));
        if (who.kind == principal::user && old && old->owner != who.sub)
            return refuse(a == access::owner ? fail(404, "not_found", "no such document")
                                             : fail(403, "not_yours", "the document is another account's"));
        if (std::none_of(undos.begin(), undos.end(), [&](const undo& u) { return u.c == c && u.id == op.id; }))
            undos.push_back({c, op.coll, op.id, old != nullptr, old ? *old : doc{}});

        if (op.kind == write_op::del)
        {
            set_doc(*c, op.id, nullptr);
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
            if (!apply_patch(nd.body, op.body, err))
            {
                error e = std::move(err);
                return refuse(std::move(e));
            }
        }
        else
        {
            if (op.body.k != jvalue::kind::object)
                return refuse(fail(400, "bad_document", "a document is a JSON object"));
            nd.body = std::move(op.body);
            nd.owner = old ? old->owner : std::string();
            // What a document read back carries is taken off, and _owner set by a key alone.
            for (auto m = nd.body.members.begin(); m != nd.body.members.end();)
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
                m = nd.body.members.erase(m);
            }
            for (const auto& [k, v] : nd.body.members)
                if (!valid_path(k) || k.find('.') != std::string::npos)
                    return refuse(fail(400, "bad_document", "a field's name is 1 to 64 of A-Z a-z 0-9 _ -: " + k));
        }
        if (who.kind == principal::user)
            nd.owner = who.sub;
        nd.v = old ? old->v + 1 : 1;
        if (depth_of(nd.body) > socketley::storage::json_max_depth)
            return refuse(fail(400, "too_deep", "a document nests at most " +
                                                    std::to_string(socketley::storage::json_max_depth) + " deep"));
        const std::string json = to_json(nd.body);
        if (json.size() > max_doc)
            return refuse(fail(413, "too_large", "a document is at most 1 MiB; keep large things in a storage and "
                                                 "their address here"));
        nd.bytes = json.size() + op.id.size() + nd.owner.size() + doc_overhead;
        if (!unique_ok(*c, op.id, nd, err))
        {
            error e = std::move(err);
            return refuse(std::move(e));
        }
        set_doc(*c, op.id, &nd);
        results += results.size() > 1 ? "," : "";
        write_doc(op.id, c->docs.find(op.id)->second, results);
    }
    if (m_max_bytes && m_bytes > m_max_bytes && m_bytes > bytes_before)
        return refuse(fail(507, "full", "the database holds its --max-bytes"));

    socketley::bytes::writer w;
    w.u8(rec_write);
    w.u32(static_cast<uint32_t>(undos.size()));
    for (const auto& u : undos)
    {
        const auto it = u.c->docs.find(u.id);
        if (it == u.c->docs.end())
            put_entry(w, u.coll, u.id, nullptr, nullptr);
        else
        {
            const std::string json = to_json(it->second.body);
            put_entry(w, u.coll, u.id, &it->second, &json);
        }
    }
    const std::string rec = w.take();
    m_journal.append(rec);
    ++m_journal_records;
    m_journal_bytes += rec.size();
    if (m_journal_records >= compact_records ||
        m_journal_bytes >= std::max<uint64_t>(compact_bytes, 2 * m_snapshot_bytes))
    {
        std::string ignored;
        compact(ignored);
    }
    out += results;
    out += ']';
    return true;
}

}   // namespace socketley::db
