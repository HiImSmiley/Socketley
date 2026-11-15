// Fuzz target: the db runtime's readers of what a client sends -- a query, a patch, a document -- and of the schema
// file an operator gives it (socketley/runtime/db/).
//
// The first byte chooses: 0 a query, asked of a store with indexes and of one without; 1 a patch, made to a fixed
// document; 2 a document, written and read back; 3 a schema, parsed and set; 4 a record as a segment or a replica's
// stream hands one over; 5 streams opened from one peer, each with its own X-Forwarded-For, counted against the
// address each is charged to, as db_run counts a feed not asked by a key (at most 32 an address). For 5 the next byte
// picks the peer (an IPv4 address, an IPv6 one, an IPv4 one mapped into IPv6, 127.0.0.1 or ::1), whose bytes follow
// for the first three; then one X-Forwarded-For a line.
//
// Properties checked, beyond "did it crash":
//   * a query answers JSON, the same with the schema's indexes as without them;
//   * a patch that is made leaves a document that writes as JSON which reads back the same;
//   * a document that is written reads back as the fields it was given, with its version;
//   * a schema that parses names only valid collections and fields, and a store takes it or keeps the one before;
//   * a record that decodes encodes back to the same bytes, each document's JSON where its offset says;
//   * a peer elsewhere is charged as itself whatever X-Forwarded-For it sends, so it holds no more than 32 streams
//     however many addresses it names; behind the entrance a stream is charged to the hop named last, an IPv6 one
//     as its /64, and to nobody only when that is this machine or no address; and IPv4 mapped into IPv6 is IPv4.
#include "fuzz_common.h"
#include "runtime/db/db_doc.h"
#include "runtime/db/db_schema.h"
#include "runtime/db/db_store.h"
#include "shared/http/key_bar.h"

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace db = socketley::db;

namespace {

struct stores
{
    db::store indexed, plain;
    std::string dirs[2];
    stores()
    {
        char a[] = "/tmp/fuzz_db.XXXXXX", b[] = "/tmp/fuzz_db.XXXXXX";
        std::string why;
        db::schema s;
        if (!db::parse_schema("items private level name stats.hp unique:sku\n", s, why) || !::mkdtemp(a) ||
            !::mkdtemp(b) || !indexed.open(a, s, why) || !plain.open(b, db::schema{}, why))
            abort();
        dirs[0] = a;
        dirs[1] = b;
        const char* docs[] = {R"({"level":1,"name":"a","stats":{"hp":3},"sku":"x1"})",
                              R"({"level":5,"name":"b","tags":["q","r"]})",
                              R"({"level":"5","name":null,"stats":{"hp":-2.5}})",
                              R"({"name":"ab","sku":"x2","nested":{"deep":{"er":true}}})",
                              R"({"level":9,"stats":{"hp":3}})"};
        int n = 0;
        for (const char* d : docs)
            for (db::store* st : {&indexed, &plain})
            {
                std::vector<db::write_op> ops(1);
                ops[0].kind = db::write_op::put;
                ops[0].coll = "items";
                ops[0].id = "d" + std::to_string(n);
                if (!db::json_reader(d).document(ops[0].body))
                    abort();
                std::string out;
                db::error err;
                if (!st->write(db::principal{db::principal::key, {}}, ops, out, err))
                    abort();
                ++n;
            }
    }
    ~stores()
    {
        indexed.close();
        plain.close();
        for (const auto& d : dirs)
            std::filesystem::remove_all(d);
    }
};

stores& fixed()
{
    static stores s;
    return s;
}

const db::principal key{db::principal::key, {}};

void query(std::string_view text)
{
    db::jvalue v;
    if (!db::json_reader(text).document(v))
        return;
    db::query q;
    db::error err;
    if (!db::store::parse_query(v, q, err))
    {
        FUZZ_CHECK(err.status == 400, "a query refused is a 400");
        return;
    }
    std::string a, b;
    db::error ea, eb;
    uint64_t da_seq = 0, db_seq = 0;
    const bool ra = fixed().indexed.find(key, "items", q, a, ea, da_seq);
    const bool rb = fixed().plain.find(key, "items", q, b, eb, db_seq);
    FUZZ_CHECK(ra && rb, "both stores answer the query");
    // The two stores hold the same documents under ids numbered apart, so the answers are compared by shape.
    db::jvalue pa, pb;
    FUZZ_CHECK(db::json_reader(a).document(pa), "the indexed store answers JSON");
    FUZZ_CHECK(db::json_reader(b).document(pb), "the plain store answers JSON");
    const db::jvalue* da = db::member(pa, "docs");
    const db::jvalue* dbs = db::member(pb, "docs");
    FUZZ_CHECK((da == nullptr) == (dbs == nullptr), "both answers carry docs or neither");
    if (da)
        FUZZ_CHECK(da->items.size() == dbs->items.size(), "an index answers what a scan answers");
}

void patch(std::string_view text)
{
    db::jvalue changes;
    if (!db::json_reader(text).document(changes))
        return;
    db::jvalue doc;
    if (!db::json_reader(R"({"n":1,"f":2.5,"list":[1,"a"],"o":{"p":{"q":null}}})").document(doc))
        abort();
    db::error err;
    if (!db::apply_patch(doc, changes, err))
    {
        FUZZ_CHECK(err.status == 400, "a patch refused is a 400");
        return;
    }
    const std::string json = socketley::json::written(doc);
    db::jvalue back;
    // A document deeper than the reader takes is refused by the store's write, not by the patch, so it may not read.
    if (db::json_reader(json).document(back))
        FUZZ_CHECK(db::same(doc, back), "a patch made reads back the same");
}

void document(std::string_view text)
{
    std::vector<db::write_op> ops(1);
    ops[0].kind = db::write_op::put;
    ops[0].coll = "fuzzed";
    ops[0].id = "doc";
    if (!db::json_reader(text).document(ops[0].body))
        return;
    std::string out;
    db::error err;
    if (!fixed().plain.write(key, ops, out, err))
    {
        FUZZ_CHECK(err.status >= 400 && err.status < 600, "a document refused says an error status");
        return;
    }
    std::string read;
    uint64_t depends = 0;
    FUZZ_CHECK(fixed().plain.read(key, "fuzzed", "doc", read, err, depends), "a document written reads back");
    db::jvalue v;
    FUZZ_CHECK(db::json_reader(read).document(v), "its answer is JSON");
    FUZZ_CHECK(db::member(v, "_id") && db::member(v, "_v"), "with _id and _v");
}

void schema(std::string_view text)
{
    db::schema s;
    std::string why;
    if (!db::parse_schema(text, s, why))
        return;
    for (const auto& c : s.collections)
    {
        FUZZ_CHECK(db::valid_collection(c.name), "a schema names valid collections");
        for (const auto& ix : c.indexes)
            FUZZ_CHECK(db::valid_path(ix.field), "and valid fields");
    }
    // A schema the documents break is refused and the one before kept; either way the store still answers.
    const db::schema before = fixed().plain.get_schema();
    fixed().plain.set_schema(s, why);
    std::string out;
    db::error err;
    uint64_t depends = 0;
    FUZZ_CHECK(fixed().plain.find(key, "items", db::query{}, out, err, depends), "the store still answers under any schema");
    fixed().plain.set_schema(before, why);
}

void record(std::string_view bytes)
{
    std::vector<db::event> evs;
    std::vector<uint64_t> offs;
    uint64_t seq = 0;
    if (!db::decode_record(bytes, evs, &offs, &seq))
        return;
    std::vector<uint64_t> again;
    FUZZ_CHECK(db::encode_record(seq, evs, &again) == bytes, "a record decoded encodes back to its bytes");
    FUZZ_CHECK(again == offs, "with each document where its offset says");
    for (size_t i = 0; i < evs.size(); ++i)
        if (!evs[i].del)
            FUZZ_CHECK(bytes.substr(offs[i], evs[i].json.size()) == evs[i].json, "the offset names the JSON");
}

sockaddr_storage address(int family, const void* bytes)
{
    sockaddr_storage a{};
    a.ss_family = static_cast<sa_family_t>(family);
    if (family == AF_INET)
        std::memcpy(&reinterpret_cast<sockaddr_in&>(a).sin_addr, bytes, 4);
    else
        std::memcpy(&reinterpret_cast<sockaddr_in6&>(a).sin6_addr, bytes, 16);
    return a;
}

// The address a hop names, as db_run's peer would be had it come itself; false for a hop that names none.
bool named(std::string_view hop, sockaddr_storage& a)
{
    const std::string h(hop);
    unsigned char b[16];
    if (::inet_pton(AF_INET, h.c_str(), b) == 1)
        return a = address(AF_INET, b), true;
    if (::inet_pton(AF_INET6, h.c_str(), b) == 1)
        return a = address(AF_INET6, b), true;
    return false;
}

void streams(std::string_view in)
{
    using socketley::http::key_bar;
    if (in.empty())
        return;
    const unsigned pick = static_cast<uint8_t>(in[0]) % 5;
    in.remove_prefix(1);
    unsigned char b[16]{};
    const size_t need = pick == 0 || pick == 2 ? 4 : pick == 1 ? 16 : 0;
    if (in.size() < need)
        return;
    std::memcpy(b, in.data(), need);
    in.remove_prefix(need);
    sockaddr_storage peer{};
    if (pick == 0)
        peer = address(AF_INET, b);
    else if (pick == 1)
        peer = address(AF_INET6, b);
    else if (pick == 2)
    {
        unsigned char m[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
        std::memcpy(m + 12, b, 4);
        peer = address(AF_INET6, m);
        FUZZ_CHECK(key_bar::client(peer, {}) == key_bar::client(address(AF_INET, b), {}),
                   "IPv4 mapped into IPv6 is charged as the IPv4 address");
    }
    else if (pick == 3)
        peer = address(AF_INET, "\x7f\0\0\1");
    else
        peer = address(AF_INET6, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1");

    const std::string alone = key_bar::client(peer, {});
    const bool here = pick >= 3 || alone.empty();
    if (pick == 3 || pick == 4)
        FUZZ_CHECK(alone.empty(), "this machine on its own is charged to nobody");
    if (pick == 1 && !here)
    {
        // Its /64: another address in it is the same client.
        unsigned char other[16];
        std::memcpy(other, b, 16);
        for (int i = 8; i < 16; ++i)
            other[i] = static_cast<unsigned char>(~other[i]);
        in6_addr a6, o6;
        std::memcpy(&a6, b, 16);
        std::memcpy(&o6, other, 16);
        if (!IN6_IS_ADDR_V4MAPPED(&a6) && !IN6_IS_ADDR_V4MAPPED(&o6) && !IN6_IS_ADDR_LOOPBACK(&o6))
            FUZZ_CHECK(key_bar::client(address(AF_INET6, other), {}) == alone, "an IPv6 address is charged as its /64");
    }

    constexpr size_t per_client = 32;
    std::map<std::string, size_t> open;
    size_t admitted = 0;
    while (!in.empty())
    {
        const size_t nl = std::min(in.find('\n'), in.size());
        const std::string_view xff = in.substr(0, nl);
        in.remove_prefix(std::min(nl + 1, in.size()));
        const std::string who = key_bar::client(peer, xff);
        FUZZ_CHECK(who.empty() || who.size() == 4 || who.size() == 8, "a client is an IPv4 address or an IPv6 /64");
        if (!here)
            FUZZ_CHECK(who == alone, "a peer elsewhere chose who it is charged as by X-Forwarded-For");
        else
        {
            const std::string_view hop = http_last_forwarded_hop(xff);
            FUZZ_CHECK(hop.empty() || (hop.data() >= xff.data() && hop.data() + hop.size() <= xff.data() + xff.size()),
                       "the hop lies in the header");
            sockaddr_storage a{};
            const std::string expect = named(hop, a) ? key_bar::client(a, {}) : std::string();
            FUZZ_CHECK(who == expect, "behind the entrance a stream is charged to the address the last hop names");
        }
        if (!who.empty())
        {
            if (open[who] >= per_client)
                continue;
            ++open[who];
        }
        ++admitted;
    }
    if (!here)
        FUZZ_CHECK(admitted <= per_client, "a peer elsewhere held more than 32 streams");
}

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz::set_current(data, size);
    if (size < 1)
        return 0;
    const std::string_view rest(reinterpret_cast<const char*>(data) + 1, size - 1);
    switch (data[0] % 6)
    {
        case 0: query(rest); break;
        case 1: patch(rest); break;
        case 2: document(rest); break;
        case 3: schema(rest); break;
        case 4: record(rest); break;
        default: streams(rest); break;
    }
    return 0;
}
