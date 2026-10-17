// The db runtime's core without a socket: documents read and written back, the schema and keys files, every access a
// principal has, patches, unique indexes, writes made whole or not at all, queries with and without an index, and the
// journal and snapshot a restart reads.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <ctime>
#include <filesystem>
#include <map>
#include <fstream>
#include <random>
#include <string>
#include <unistd.h>

#include "runtime/db/db_doc.h"
#include "runtime/db/db_docmap.h"
#include "runtime/db/db_schema.h"
#include "runtime/db/db_store.h"
#include "shared/byte_codec.h"
#include "shared/mutation_journal.h"

using namespace socketley::db;

namespace
{

jvalue parse(const std::string& text)
{
    jvalue v;
    REQUIRE_MESSAGE(json_reader(text).document(v), text);
    return v;
}

struct tmpdir
{
    std::string path;
    tmpdir()
    {
        char t[] = "/tmp/test_db.XXXXXX";
        REQUIRE(::mkdtemp(t));
        path = t;
    }
    ~tmpdir() { std::filesystem::remove_all(path); }
};

const principal key{principal::key, {}};
const principal nobody{principal::anyone, {}};
principal user(const char* sub) { return principal{principal::user, sub}; }

schema make_schema(const char* text)
{
    schema s;
    std::string why;
    REQUIRE_MESSAGE(parse_schema(text, s, why), why);
    return s;
}

// One change, made alone; the status it failed with, 0 when it was made.
int put(store& st, const principal& who, const char* coll, const char* id, const std::string& body, uint64_t if_v = 0,
        bool if_absent = false)
{
    std::vector<write_op> ops(1);
    ops[0].kind = write_op::put;
    ops[0].coll = coll;
    ops[0].id = id;
    ops[0].body = parse(body);
    ops[0].if_v = if_v;
    ops[0].if_absent = if_absent;
    std::string out;
    error err;
    return st.write(who, ops, out, err) ? 0 : err.status;
}

int patch(store& st, const principal& who, const char* coll, const char* id, const std::string& changes)
{
    std::vector<write_op> ops(1);
    ops[0].kind = write_op::patch;
    ops[0].coll = coll;
    ops[0].id = id;
    ops[0].body = parse(changes);
    std::string out;
    error err;
    return st.write(who, ops, out, err) ? 0 : err.status;
}

int del(store& st, const principal& who, const char* coll, const char* id)
{
    std::vector<write_op> ops(1);
    ops[0].kind = write_op::del;
    ops[0].coll = coll;
    ops[0].id = id;
    std::string out;
    error err;
    return st.write(who, ops, out, err) ? 0 : err.status;
}

// The document as the store answers it, or the status it refused with.
std::string get(store& st, const principal& who, const char* coll, const char* id)
{
    std::string out;
    error err;
    uint64_t depends = 0;
    if (!st.read(who, coll, id, out, err, depends))
        return std::to_string(err.status);
    return out;
}

std::string find(store& st, const principal& who, const char* coll, const std::string& q)
{
    query parsed;
    error err;
    if (!store::parse_query(parse(q), parsed, err))
        return "bad " + err.message;
    std::string out;
    uint64_t depends = 0;
    if (!st.find(who, coll, parsed, out, err, depends))
        return std::to_string(err.status);
    return out;
}

// The ids a query answers, in order.
std::string ids_of(const std::string& found)
{
    jvalue v;
    if (!json_reader(found).document(v))
        return found;
    std::string out;
    if (const jvalue* docs = member(v, "docs"))
        for (const auto& d : docs->items)
            out += member(d, "_id")->s + " ";
    if (const jvalue* next = member(v, "next"))
        out += "next=" + next->s;
    return out;
}

}   // namespace

TEST_CASE("a collection's map finds, keeps and lets go of what a map would, and a node keeps its place")
{
    struct val
    {
        int n{0};
    };
    socketley::db::doc_map<val> m;
    std::map<std::string, int> want;
    std::map<std::string, const void*> place;
    std::mt19937 rng(11);
    for (int i = 0; i < 200000; ++i)
    {
        const std::string id = "k" + std::to_string(rng() % 3000);
        switch (rng() % 3)
        {
            case 0:
            {
                const auto [it, made] = m.emplace(id, val{i});
                REQUIRE(made == !want.contains(id));
                if (made)
                {
                    want[id] = i;
                    place[id] = &it->second;
                }
                break;
            }
            case 1:
                if (auto it = m.find(id); it != m.end())
                {
                    REQUIRE(want.contains(id));
                    m.erase(it);
                    want.erase(id);
                    place.erase(id);
                }
                else
                    REQUIRE(!want.contains(id));
                break;
            default:
            {
                const auto it = m.find(id);
                REQUIRE((it != m.end()) == want.contains(id));
                if (it != m.end())
                {
                    REQUIRE(it->second.n == want[id]);
                    REQUIRE(&it->second == place[id]);
                }
            }
        }
        REQUIRE(m.size() == want.size());
    }
    std::map<std::string, int> seen;
    for (const auto& [id, v] : m)
        REQUIRE(seen.emplace(id, v.n).second);
    CHECK(seen == want);
    m.clear();
    CHECK(m.empty());
    CHECK(m.begin() == m.end());
}

TEST_CASE("documents: written as read, paths, and the order an index keeps")
{
    const std::string text = R"({"a":1,"b":"x\"y\n","c":[true,false,null],"d":{"e":-1.5e3},"f":"ü"})";
    CHECK(to_json(parse(text)) == text);

    jvalue d = parse(R"({"a":{"b":{"c":1}}})");
    CHECK(at_path(d, "a.b.c")->s == "1");
    CHECK(at_path(d, "a.x") == nullptr);
    CHECK(at_path(d, "a.b.c.d") == nullptr);
    std::string why;
    jvalue* made = make_path(d, "a.n.m", why);
    REQUIRE(made);
    made->k = jvalue::kind::number;
    made->s = "2";
    CHECK(to_json(d) == R"({"a":{"b":{"c":1},"n":{"m":2}}})");
    CHECK(make_path(d, "a.b.c.z", why) == nullptr);
    CHECK(erase_path(d, "a.b"));
    CHECK_FALSE(erase_path(d, "a.b"));
    CHECK(to_json(d) == R"({"a":{"n":{"m":2}}})");

    CHECK(valid_path("a.b_c.d-e"));
    CHECK_FALSE(valid_path(""));
    CHECK_FALSE(valid_path("a..b"));
    CHECK_FALSE(valid_path("a.b."));
    CHECK_FALSE(valid_path("a b"));
    CHECK_FALSE(valid_path("a.b.c.d.e.f.g.h.i"));

    // null < false < true < numbers < strings < the rest, and numbers by value.
    const ikey order[] = {key_of(nullptr), key_of(&(d = parse(R"({"v":false})")).members[0].second),
                          key_of(&(d = parse(R"({"v":true})")).members[0].second),
                          key_of(&(d = parse(R"({"v":-10})")).members[0].second),
                          key_of(&(d = parse(R"({"v":2})")).members[0].second),
                          key_of(&(d = parse(R"({"v":10})")).members[0].second),
                          key_of(&(d = parse(R"({"v":"10"})")).members[0].second),
                          key_of(&(d = parse(R"({"v":"9"})")).members[0].second),
                          key_of(&(d = parse(R"({"v":[1]})")).members[0].second)};
    for (size_t i = 0; i + 1 < std::size(order); ++i)
        CHECK_MESSAGE(order[i] < order[i + 1], i);
    CHECK(key_of(&(d = parse(R"({"v":1.0})")).members[0].second) == key_of(&(d = parse(R"({"v":1})")).members[0].second));
    CHECK(same(parse(R"({"a":1,"b":[2]})"), parse(R"({"b":[2.0],"a":1})")));
    CHECK_FALSE(same(parse(R"({"a":1})"), parse(R"({"a":1,"b":2})")));
}

TEST_CASE("schema and keys files")
{
    schema s;
    std::string why;
    REQUIRE(parse_schema("# a comment\ncharacters owner level unique:name stats.hp # trailing\n\n"
                         "scores public score\nproducts catalog unique:sku\n",
                         s, why));
    REQUIRE(s.collections.size() == 3);
    CHECK(s.find("characters")->acc == access::owner);
    CHECK(s.find("characters")->indexes.size() == 3);
    CHECK(s.find("characters")->indexes[1].unique);
    CHECK(s.find("characters")->indexes[2].field == "stats.hp");
    CHECK(s.find("scores")->acc == access::open);
    CHECK(s.find("nothing") == nullptr);

    CHECK_FALSE(parse_schema("characters\n", s, why));
    CHECK_FALSE(parse_schema("characters everyone\n", s, why));
    CHECK(why.find("line 1") != std::string::npos);
    CHECK_FALSE(parse_schema("Characters owner\n", s, why));
    CHECK_FALSE(parse_schema("a owner\na shared\n", s, why));
    CHECK_FALSE(parse_schema("a owner x x\n", s, why));
    CHECK_FALSE(parse_schema("a owner _id\n", s, why));
    CHECK_FALSE(parse_schema("a owner a..b\n", s, why));
    // A refused file leaves what was read before.
    CHECK(s.collections.size() == 3);

    std::vector<service_key> keys;
    REQUIRE(parse_keys("backend 0123456789abcdef\n# none\nother  fedcba9876543210xyz\n", keys, why));
    REQUIRE(keys.size() == 2);
    CHECK(keys[1].secret == "fedcba9876543210xyz");
    CHECK_FALSE(parse_keys("short 123\n", keys, why));
    CHECK_FALSE(parse_keys("a 0123456789abcdef\na 0123456789abcdef\n", keys, why));
    CHECK_FALSE(parse_keys("a 0123456789abcdef extra\n", keys, why));

    CHECK(valid_id("abc-1.2:x@y+z_"));
    CHECK_FALSE(valid_id("_query"));
    CHECK_FALSE(valid_id("a/b"));
    CHECK_FALSE(valid_id(std::string(129, 'a')));
    CHECK(valid_collection("orders_2"));
    CHECK_FALSE(valid_collection("2orders"));
}

TEST_CASE("reading and writing: versions, preconditions, and what each principal reaches")
{
    tmpdir t;
    store st;
    std::string why;
    REQUIRE(st.open(t.path, schema{}, why));
    REQUIRE(st.set_schema(make_schema("chars owner\nposts shared\nscores public\nproducts catalog\n"), why));

    // A key writes anywhere, and versions count from 1.
    CHECK(put(st, key, "secrets", "s1", R"({"v":1})") == 0);
    CHECK(get(st, key, "secrets", "s1") == R"({"_id":"s1","_v":1,"v":1})");
    CHECK(put(st, key, "secrets", "s1", R"({"v":2})", 1) == 0);
    CHECK(put(st, key, "secrets", "s1", R"({"v":3})", 1) == 412);
    CHECK(put(st, key, "secrets", "s1", R"({"v":3})", 0, true) == 412);
    CHECK(put(st, key, "secrets", "s2", R"({"v":3})", 0, true) == 0);
    CHECK(get(st, key, "secrets", "s1") == R"({"_id":"s1","_v":2,"v":2})");
    // Nobody but a key reaches a collection the schema does not name.
    CHECK(get(st, user("u1"), "secrets", "s1") == "403");
    CHECK(get(st, nobody, "secrets", "s1") == "401");
    CHECK(put(st, user("u1"), "secrets", "s3", "{}") == 403);
    CHECK(put(st, nobody, "secrets", "s3", "{}") == 401);

    // An owner collection: each account its own, another's answered as absent.
    CHECK(put(st, user("u1"), "chars", "c1", R"({"name":"a"})") == 0);
    CHECK(get(st, user("u1"), "chars", "c1") == R"({"_id":"c1","_v":1,"_owner":"u1","name":"a"})");
    CHECK(get(st, user("u2"), "chars", "c1") == "404");
    CHECK(get(st, nobody, "chars", "c1") == "401");
    CHECK(put(st, user("u2"), "chars", "c1", R"({"name":"b"})") == 404);
    CHECK(patch(st, user("u2"), "chars", "c1", R"({"set":{"name":"b"}})") == 404);
    CHECK(del(st, user("u2"), "chars", "c1") == 404);
    CHECK(get(st, key, "chars", "c1").find("\"_owner\":\"u1\"") != std::string::npos);
    // A user cannot hand a document to another account; a key can.
    CHECK(put(st, user("u1"), "chars", "c2", R"({"_owner":"u2"})") == 0);
    CHECK(get(st, user("u1"), "chars", "c2").find("\"_owner\":\"u1\"") != std::string::npos);
    CHECK(put(st, key, "chars", "c3", R"({"_owner":"u2","name":"given"})") == 0);
    CHECK(get(st, user("u2"), "chars", "c3").find("given") != std::string::npos);
    // A key's replacement keeps the owner it does not name.
    CHECK(put(st, key, "chars", "c3", R"({"name":"again"})") == 0);
    CHECK(get(st, user("u2"), "chars", "c3").find("again") != std::string::npos);

    // Shared: every account reads, each writes its own.
    CHECK(put(st, user("u1"), "posts", "p1", R"({"t":"hi"})") == 0);
    CHECK(get(st, user("u2"), "posts", "p1").find("hi") != std::string::npos);
    CHECK(get(st, nobody, "posts", "p1") == "401");
    CHECK(put(st, user("u2"), "posts", "p1", R"({"t":"mine"})") == 403);
    // Public: anybody reads.  Catalog: anybody reads, a key writes.
    CHECK(put(st, user("u1"), "scores", "x", R"({"score":1})") == 0);
    CHECK(get(st, nobody, "scores", "x").find("score") != std::string::npos);
    CHECK(put(st, nobody, "scores", "y", R"({"score":1})") == 401);
    CHECK(put(st, user("u1"), "products", "p", "{}") == 403);
    CHECK(put(st, key, "products", "p", R"({"price":5})") == 0);
    CHECK(get(st, nobody, "products", "p").find("price") != std::string::npos);

    // What a document read back carries is taken off when it is written again.
    std::string back = get(st, user("u1"), "chars", "c1");
    CHECK(put(st, user("u1"), "chars", "c1", back) == 0);
    CHECK(get(st, user("u1"), "chars", "c1") == R"({"_id":"c1","_v":2,"_owner":"u1","name":"a"})");
    CHECK(put(st, user("u1"), "chars", "c1", R"({"_id":"other"})") == 400);
    CHECK(put(st, user("u1"), "chars", "c1", R"({"_secret":1})") == 400);
    CHECK(put(st, user("u1"), "chars", "c1", R"({"a b":1})") == 400);
    CHECK(put(st, key, "chars", "_bad", "{}") == 400);
    CHECK(put(st, key, "Bad", "x", "{}") == 400);

    CHECK(del(st, user("u1"), "chars", "c1") == 0);
    CHECK(get(st, user("u1"), "chars", "c1") == "404");
    CHECK(del(st, user("u1"), "chars", "c1") == 404);

    // An insert is given an id.
    std::vector<write_op> ops(1);
    ops[0].kind = write_op::insert;
    ops[0].coll = "chars";
    ops[0].body = parse(R"({"n":1})");
    std::string out;
    error err;
    REQUIRE(st.write(user("u1"), ops, out, err));
    jvalue res = parse("{\"r\":" + out + "}");
    const std::string id = member(res, "r")->items[0].members[0].second.s;
    CHECK(id.size() == 22);
    CHECK(get(st, user("u1"), "chars", id.c_str()).find("\"n\":1") != std::string::npos);
    // Every id an insert gives is one the API takes back, though base64url may start one with _.
    bool all_valid = true;
    for (int i = 0; i < 2000; ++i)
    {
        std::vector<write_op> one(1);
        one[0].kind = write_op::insert;
        one[0].coll = "many";
        one[0].body = parse("{}");
        std::string o;
        REQUIRE(st.write(key, one, o, err));
        const jvalue r = parse("{\"r\":" + o + "}");
        all_valid = all_valid && valid_id(member(r, "r")->items[0].members[0].second.s);
    }
    CHECK(all_valid);
}

TEST_CASE("patches")
{
    tmpdir t;
    store st;
    std::string why;
    REQUIRE(st.open(t.path, schema{}, why));
    REQUIRE(put(st, key, "c", "d", R"({"n":1,"f":1.5,"tags":["a"],"o":{"x":1}})") == 0);
    CHECK(patch(st, key, "c", "d",
                R"({"inc":{"n":2,"f":1,"new":5},"set":{"o.y":"z","deep.er":true},"push":{"tags":"b","list":1},
                    "pull":{"tags":"a"},"unset":["o.x"]})") == 0);
    CHECK(get(st, key, "c", "d") ==
          R"({"_id":"d","_v":2,"n":3,"f":2.5,"tags":["b"],"o":{"y":"z"},"new":5,"deep":{"er":true},"list":[1]})");
    // An integer sum past int64 is carried on as a double rather than wrapped.
    CHECK(put(st, key, "c", "big", R"({"n":9223372036854775807})") == 0);
    CHECK(patch(st, key, "c", "big", R"({"inc":{"n":1}})") == 0);
    CHECK(get(st, key, "c", "big").find("\"n\":9223372036854775808") != std::string::npos);
    CHECK(patch(st, key, "c", "d", R"({"inc":{"f":0.25}})") == 0);
    CHECK(get(st, key, "c", "d").find("\"f\":2.75") != std::string::npos);
    // What cannot be done changes nothing.
    CHECK(patch(st, key, "c", "d", R"({"inc":{"tags":1}})") == 400);
    CHECK(patch(st, key, "c", "d", R"({"push":{"n":1}})") == 400);
    CHECK(patch(st, key, "c", "d", R"({"set":{"n.x":1}})") == 400);
    CHECK(patch(st, key, "c", "d", R"({"set":{"_id":1}})") == 400);
    CHECK(patch(st, key, "c", "d", R"({"rename":{"n":"m"}})") == 400);
    CHECK(patch(st, key, "c", "d", R"({"inc":{"n":"1"}})") == 400);
    CHECK(patch(st, key, "c", "d", "{}") == 400);
    CHECK(patch(st, key, "c", "nothing", R"({"set":{"a":1}})") == 404);
    CHECK(get(st, key, "c", "d").find("\"_v\":3") != std::string::npos);
    // A document nests no deeper than a restart can read it back: a path eight deep and a value thirteen deep is a
    // patch that reads, and a document that would not.
    std::string deep = "{\"set\":{\"a.b.c.d.e.f.g.h\":";
    for (int i = 0; i < 13; ++i)
        deep += "{\"b\":";
    deep += "1";
    for (int i = 0; i < 13; ++i)
        deep += "}";
    deep += "}}";
    CHECK(patch(st, key, "c", "d", deep) == 400);
    CHECK(patch(st, key, "c", "d", R"({"set":{"a.b.c.d.e.f.g.h":1}})") == 0);
}

TEST_CASE("unique indexes, and a write made whole or not at all")
{
    tmpdir t;
    store st;
    std::string why;
    REQUIRE(st.open(t.path, schema{}, why));
    REQUIRE(st.set_schema(make_schema("u private unique:name\n"), why));
    CHECK(put(st, key, "u", "a", R"({"name":"x"})") == 0);
    CHECK(put(st, key, "u", "b", R"({"name":"x"})") == 409);
    CHECK(put(st, key, "u", "b", R"({"name":"y"})") == 0);
    CHECK(put(st, key, "u", "a", R"({"name":"x","more":1})") == 0);   // its own value is no clash
    CHECK(patch(st, key, "u", "b", R"({"set":{"name":"x"}})") == 409);
    // Absent values are not unique values.
    CHECK(put(st, key, "u", "c", "{}") == 0);
    CHECK(put(st, key, "u", "d", "{}") == 0);

    // Three changes, the third refused: the first two are taken back, documents and indexes alike.
    const size_t docs = st.documents();
    const uint64_t bytes = st.bytes();
    std::vector<write_op> ops(3);
    ops[0].kind = write_op::put;
    ops[0].coll = "u";
    ops[0].id = "e";
    ops[0].body = parse(R"({"name":"z"})");
    ops[1].kind = write_op::del;
    ops[1].coll = "u";
    ops[1].id = "a";
    ops[2].kind = write_op::put;
    ops[2].coll = "u";
    ops[2].id = "f";
    ops[2].body = parse(R"({"name":"y"})");
    std::string out;
    error err;
    CHECK_FALSE(st.write(key, ops, out, err));
    CHECK(err.status == 409);
    CHECK(st.documents() == docs);
    CHECK(st.bytes() == bytes);
    CHECK(get(st, key, "u", "e") == "404");
    CHECK(get(st, key, "u", "a").find("\"x\"") != std::string::npos);
    // The index forgot e's z and still holds a's x.
    CHECK(put(st, key, "u", "g", R"({"name":"z"})") == 0);
    CHECK(put(st, key, "u", "h", R"({"name":"x"})") == 409);
    // A refused write that made a collection takes it back too.
    std::vector<write_op> two(2);
    two[0].kind = write_op::put;
    two[0].coll = "fresh";
    two[0].id = "a";
    two[0].body = parse("{}");
    two[1].kind = write_op::del;
    two[1].coll = "fresh";
    two[1].id = "nothing";
    CHECK_FALSE(st.write(key, two, out, err));
    CHECK(err.status == 404);
    CHECK(st.collection_names() == std::vector<std::string>{"u"});
    // And a later write within one sees the earlier: delete then make again.
    std::vector<write_op> swap(2);
    swap[0].kind = write_op::del;
    swap[0].coll = "u";
    swap[0].id = "a";
    swap[1].kind = write_op::put;
    swap[1].coll = "u";
    swap[1].id = "i";
    swap[1].body = parse(R"({"name":"x"})");
    CHECK(st.write(key, swap, out, err));

    // A schema whose new unique index two documents already break is refused, and the old one kept.
    REQUIRE(put(st, key, "u", "j", R"({"tag":1})") == 0);
    REQUIRE(put(st, key, "u", "k", R"({"tag":1})") == 0);
    CHECK_FALSE(st.set_schema(make_schema("u private unique:name unique:tag\n"), why));
    CHECK(why.find("tag") != std::string::npos);
    CHECK(put(st, key, "u", "l", R"({"name":"x"})") == 409);
}

TEST_CASE("queries: conditions, sorting and pages, with and without an index")
{
    tmpdir t;
    store st;
    std::string why;
    REQUIRE(st.open(t.path, schema{}, why));
    REQUIRE(st.set_schema(make_schema("p private level name\n"), why));
    const char* docs[] = {R"({"level":5,"name":"bob","tag":"x"})", R"({"level":1,"name":"al","tag":"y"})",
                          R"({"level":9,"name":"bea"})",           R"({"level":"9","name":"cy"})",
                          R"({"name":"di","tag":null})",           R"({"level":5,"name":"ed","tag":"x"})"};
    for (int i = 0; i < 6; ++i)
        REQUIRE(put(st, key, "p", ("d" + std::to_string(i)).c_str(), docs[i]) == 0);

    CHECK(ids_of(find(st, key, "p", R"({"where":{"level":5}})")) == "d0 d5 ");
    CHECK(ids_of(find(st, key, "p", R"({"where":{"tag":"x"}})")) == "d0 d5 ");
    CHECK(ids_of(find(st, key, "p", R"({"where":{"level":{"gt":1}}})")) == "d0 d2 d5 ");
    CHECK(ids_of(find(st, key, "p", R"({"where":{"level":{"gte":1,"lt":9}}})")) == "d0 d1 d5 ");
    CHECK(ids_of(find(st, key, "p", R"({"where":{"level":{"lte":5}}})")) == "d0 d1 d5 ");
    CHECK(ids_of(find(st, key, "p", R"({"where":{"name":{"prefix":"b"}}})")) == "d0 d2 ");
    CHECK(ids_of(find(st, key, "p", R"({"where":{"level":{"in":[1,9,"9"]}}})")) == "d1 d2 d3 ");
    CHECK(ids_of(find(st, key, "p", R"({"where":{"tag":{"exists":false}}})")) == "d2 d3 ");
    CHECK(ids_of(find(st, key, "p", R"({"where":{"tag":null}})")) == "d2 d3 d4 ");
    CHECK(ids_of(find(st, key, "p", R"({"where":{"tag":{"ne":"x"}}})")) == "d1 d2 d3 d4 ");
    CHECK(ids_of(find(st, key, "p", R"({"where":{"_id":{"in":["d4","d1"]}}})")) == "d1 d4 ");
    CHECK(ids_of(find(st, key, "p", R"({"where":{"level":5,"tag":"x","name":"ed"}})")) == "d5 ");

    // Sorted by an indexed field and by one that is not, the same order: kinds first, then values, then ids.
    CHECK(ids_of(find(st, key, "p", R"({"sort":"level"})")) == "d4 d1 d0 d5 d2 d3 ");
    CHECK(ids_of(find(st, key, "p", R"({"sort":"-level"})")) == "d3 d2 d5 d0 d1 d4 ");
    CHECK(ids_of(find(st, key, "p", R"({"sort":"tag"})")) == "d2 d3 d4 d0 d5 d1 ");
    CHECK(ids_of(find(st, key, "p", R"({"sort":"-tag"})")) == "d1 d5 d0 d4 d3 d2 ");
    CHECK(ids_of(find(st, key, "p", R"({"sort":"level","limit":2})")) == "d4 d1 next=2");
    CHECK(ids_of(find(st, key, "p", R"({"sort":"level","limit":2,"skip":2})")) == "d0 d5 next=4");
    CHECK(ids_of(find(st, key, "p", R"({"sort":"level","limit":2,"skip":4})")) == "d2 d3 ");
    CHECK(ids_of(find(st, key, "p", R"({"limit":5})")) == "d0 d1 d2 d3 d4 next=5");
    CHECK(find(st, key, "p", R"({"where":{"level":5},"count":true})") == R"({"count":2})");
    CHECK(find(st, key, "nothing", "{}") == R"({"docs":[]})");

    CHECK(find(st, key, "p", R"({"where":{"a b":1}})").starts_with("bad"));
    CHECK(find(st, key, "p", R"({"limit":0})").starts_with("bad"));
    CHECK(find(st, key, "p", R"({"limit":1001})").starts_with("bad"));
    CHECK(find(st, key, "p", R"({"skip":-1})").starts_with("bad"));
    CHECK(find(st, key, "p", R"({"where":{"x":{"in":1}}})").starts_with("bad"));
    CHECK(find(st, key, "p", R"({"order":"x"})").starts_with("bad"));
    // An object that is not all conditions is a value to equal.
    REQUIRE(put(st, key, "p", "o", R"({"pos":{"x":1,"gt":2}})") == 0);
    CHECK(ids_of(find(st, key, "p", R"({"where":{"pos":{"gt":2,"x":1}}})")) == "o ");

    // An account's query in an owner collection sees its own documents alone.
    REQUIRE(st.set_schema(make_schema("p private level name\nmine owner level\n"), why));
    for (int i = 0; i < 4; ++i)
        REQUIRE(put(st, user(i % 2 ? "u1" : "u2"), "mine", ("m" + std::to_string(i)).c_str(),
                    "{\"level\":" + std::to_string(i) + "}") == 0);
    CHECK(ids_of(find(st, user("u1"), "mine", "{}")) == "m1 m3 ");
    CHECK(ids_of(find(st, user("u1"), "mine", R"({"limit":1})")) == "m1 next=1");
    CHECK(ids_of(find(st, user("u1"), "mine", R"({"where":{"level":{"gte":0}},"sort":"-level"})")) == "m3 m1 ");
    CHECK(ids_of(find(st, key, "mine", R"({"where":{"_owner":"u2"}})")) == "m0 m2 ");
    CHECK(find(st, nobody, "mine", "{}") == "401");
    CHECK(find(st, user("u1"), "p", "{}") == "403");
}

TEST_CASE("queries: an index answers what a scan answers, over random documents and conditions")
{
    tmpdir t1, t2;
    store indexed, plain;
    std::string why;
    REQUIRE(indexed.open(t1.path, schema{}, why));
    REQUIRE(plain.open(t2.path, schema{}, why));
    REQUIRE(indexed.set_schema(make_schema("r private a b.c s\n"), why));
    std::mt19937 rng(7);
    const auto value = [&](int kind) -> std::string {
        switch (kind % 5)
        {
            case 0: return std::to_string(static_cast<int>(rng() % 7) - 3);
            case 1: return std::string("\"") + static_cast<char>('a' + rng() % 4) + static_cast<char>('a' + rng() % 3) + "\"";
            case 2: return rng() % 2 ? "true" : "false";
            case 3: return "null";
            default: return std::to_string(static_cast<int>(rng() % 5)) + ".5";
        }
    };
    for (int i = 0; i < 300; ++i)
    {
        std::string body = "{";
        if (rng() % 4)
            body += "\"a\":" + value(static_cast<int>(rng() % 5)) + ",";
        if (rng() % 3)
            body += "\"b\":{\"c\":" + value(static_cast<int>(rng() % 5)) + "},";
        body += "\"s\":" + value(rng() % 2 ? 1 : 0) + "}";
        const std::string id = "k" + std::to_string(rng() % 400);
        REQUIRE(put(indexed, key, "r", id.c_str(), body) == put(plain, key, "r", id.c_str(), body));
    }
    const char* fields[] = {"a", "b.c", "s"};
    const char* ops[] = {"eq", "ne", "gt", "gte", "lt", "lte", "in", "prefix", "exists"};
    for (int i = 0; i < 2000; ++i)
    {
        std::string q = "{\"where\":{";
        const int conds = static_cast<int>(rng() % 3);
        for (int c = 0; c < conds; ++c)
        {
            const char* op = ops[rng() % std::size(ops)];
            std::string arg = std::string(op) == "in"       ? "[" + value(static_cast<int>(rng())) + "," + value(static_cast<int>(rng())) + "]"
                              : std::string(op) == "prefix" ? std::string("\"") + static_cast<char>('a' + rng() % 4) + "\""
                              : std::string(op) == "exists" ? (rng() % 2 ? "true" : "false")
                                                            : value(static_cast<int>(rng()));
            q += std::string(c ? "," : "") + "\"" + fields[(i + c) % 3] + "\":{\"" + op + "\":" + arg + "}";
        }
        q += "}";
        if (rng() % 2)
            q += std::string(",\"sort\":\"") + (rng() % 2 ? "-" : "") + fields[rng() % 3] + "\"";
        if (rng() % 3 == 0)
            q += ",\"limit\":" + std::to_string(1 + rng() % 20) + ",\"skip\":" + std::to_string(rng() % 10);
        q += "}";
        const std::string a = find(indexed, key, "r", q);
        const std::string b = find(plain, key, "r", q);
        REQUIRE_MESSAGE(a == b, q);
    }
}

TEST_CASE("persistence: segments, and what a restart reads")
{
    tmpdir t;
    std::string why;
    {
        store st;
        REQUIRE(st.open(t.path, schema{}, why));
        REQUIRE(put(st, key, "a", "x", R"({"n":1,"deep":{"list":[1,{"y":"ü\u0001"}]}})") == 0);
        REQUIRE(put(st, key, "a", "y", R"({"n":2,"_owner":"u"})") == 0);
        REQUIRE(patch(st, key, "a", "x", R"({"inc":{"n":5}})") == 0);
        REQUIRE(put(st, key, "b", "z", "{}") == 0);
        REQUIRE(del(st, key, "b", "z") == 0);
        CHECK(st.seq() == 5);
        REQUIRE(st.sync());
    }
    std::string before;
    {
        store st;
        REQUIRE_MESSAGE(st.open(t.path, schema{}, why), why);
        CHECK(st.seq() == 5);
        before = get(st, key, "a", "x") + get(st, key, "a", "y");
        CHECK(before == "{\"_id\":\"x\",\"_v\":2,\"n\":6,\"deep\":{\"list\":[1,{\"y\":\"ü\\u0001\"}]}}"
                        "{\"_id\":\"y\",\"_v\":1,\"_owner\":\"u\",\"n\":2}");
        CHECK(get(st, key, "b", "z") == "404");
        REQUIRE(put(st, key, "a", "w", R"({"after":true})") == 0);
        REQUIRE(st.sync());
    }
    {
        // A unique index the documents break refuses the start.
        store st;
        REQUIRE_MESSAGE(st.open(t.path, make_schema("a private unique:n\nb private\n"), why), why);
        REQUIRE(put(st, key, "a", "dup", R"({"n":6})") == 409);
        REQUIRE(st.set_schema(schema{}, why));
        REQUIRE(put(st, key, "a", "dup", R"({"n":6})") == 0);
        REQUIRE(st.sync());
        store again;
        CHECK_FALSE(again.open(t.path, make_schema("a private unique:n\n"), why));
        CHECK(why.find("cannot be unique") != std::string::npos);
        REQUIRE(del(st, key, "a", "dup") == 0);
        REQUIRE(st.sync());
    }
    {
        store st;
        REQUIRE_MESSAGE(st.open(t.path, make_schema("a private unique:n\n"), why), why);
        CHECK(get(st, key, "a", "x") + get(st, key, "a", "y") == before);
        CHECK(get(st, key, "a", "w").find("after") != std::string::npos);
        CHECK(st.documents() == 3);
        CHECK(put(st, key, "a", "v", R"({"n":6})") == 409);
    }
    // A record a crash cut short is no record: the newest segment ends where the last whole one does.
    const std::string seg = t.path + "/seg-00000001.log";
    const auto size_before = std::filesystem::file_size(seg);
    {
        std::ofstream j(seg, std::ios::app | std::ios::binary);
        j.write("\x40\x00\x00\x00\x01\x02\x03\x04garbage", 15);
    }
    {
        store st;
        REQUIRE_MESSAGE(st.open(t.path, schema{}, why), why);
        CHECK(st.documents() == 3);
        CHECK(std::filesystem::file_size(seg) == size_before);
    }
    // The room of zeros a crash left past the newest segment's last record is cut, its documents kept.
    {
        tmpdir copy;
        {
            store st;
            REQUIRE_MESSAGE(st.open(t.path, schema{}, why), why);
            REQUIRE(put(st, key, "a", "room", R"({"r":1})") == 0);
            REQUIRE(st.sync());
        }
        std::filesystem::copy_file(seg, copy.path + "/seg-00000001.log");
        std::filesystem::resize_file(copy.path + "/seg-00000001.log", std::filesystem::file_size(seg) + (1u << 20));
        store st;
        REQUIRE_MESSAGE(st.open(copy.path, schema{}, why), why);
        CHECK(st.documents() == 4);
        CHECK(get(st, key, "a", "room").find("\"r\":1") != std::string::npos);
        CHECK(std::filesystem::file_size(copy.path + "/seg-00000001.log") == std::filesystem::file_size(seg));
    }
    // A segment that is not one is refused rather than read in part.
    {
        std::fstream f(seg, std::ios::in | std::ios::out | std::ios::binary);
        f.write("NOTADB!!", 8);
    }
    {
        store st;
        CHECK_FALSE(st.open(t.path, schema{}, why));
        CHECK(why.find("not a segment") != std::string::npos);
    }
}

TEST_CASE("segments: rolled, merged off the loop, and read back across a restart, with more than the cache holds")
{
    tmpdir t;
    std::string why;
    std::map<std::string, std::string> want;
    {
        store st;
        REQUIRE(st.open(t.path, make_schema("big private n\n"), why));
        st.set_cache_bytes(256 << 10);
        const std::string pad(4000, 'p');
        // 50k writes of 4 KB over 1000 ids: 200 MB written, 4 MB alive, so the sealed segments are mostly dead.
        for (int i = 0; i < 50000; ++i)
        {
            const std::string id = "d" + std::to_string(i % 1000);
            const std::string body = "{\"n\":" + std::to_string(i) + ",\"pad\":\"" + pad + "\"}";
            REQUIRE(put(st, key, "big", id.c_str(), body) == 0);
            want[id] = std::to_string(i);
            // Synced as a loop would, so rooms are made ahead of the records across the segments' rolls.
            if (i % 64 == 0)
                REQUIRE(st.sync());
        }
        REQUIRE(st.sync());
        CHECK(st.segments() > 2);
        const uint64_t disk = st.disk_bytes();
        auto job = st.plan_merge();
        REQUIRE(job);
        // Writes go on while the merge runs; the merge leaves what they changed where they put it.
        REQUIRE(put(st, key, "big", "d7", "{\"n\":-7,\"pad\":\"x\"}") == 0);
        want["d7"] = "-7";
        REQUIRE(del(st, key, "big", "d8") == 0);
        want.erase("d8");
        job->run();
        REQUIRE_MESSAGE(job->ok, job->why);
        st.finish(*job);
        CHECK(st.merges() == 1);
        CHECK(st.disk_bytes() < disk / 4);
        CHECK(!st.plan_merge());
        for (const auto& [id, n] : want)
            REQUIRE_MESSAGE(get(st, key, "big", id.c_str()).find("\"n\":" + n + ",") != std::string::npos, id);
        CHECK(get(st, key, "big", "d8") == "404");
        CHECK(st.cache_misses() > 0);
        CHECK(ids_of(find(st, key, "big", R"({"where":{"n":{"lt":0}}})")) == "d7 ");
        REQUIRE(st.sync());
    }
    {
        store st;
        REQUIRE_MESSAGE(st.open(t.path, make_schema("big private n\n"), why), why);
        CHECK(st.documents() == want.size());
        for (const auto& [id, n] : want)
            REQUIRE_MESSAGE(get(st, key, "big", id.c_str()).find("\"n\":" + n + ",") != std::string::npos, id);
        CHECK(get(st, key, "big", "d8") == "404");
        CHECK(ids_of(find(st, key, "big", R"({"where":{"n":{"lt":0}}})")) == "d7 ");
    }
}

TEST_CASE("documents with a time to go, by the schema's ttl field")
{
    tmpdir t;
    store st;
    std::string why;
    REQUIRE(st.open(t.path, make_schema("s owner ttl:exp unique:token\n"), why));
    const int64_t now = static_cast<int64_t>(::time(nullptr));
    REQUIRE(put(st, user("u"), "s", "gone", "{\"exp\":" + std::to_string(now - 1) + ",\"token\":\"t1\"}") == 0);
    REQUIRE(put(st, user("u"), "s", "soon", "{\"exp\":" + std::to_string(now + 3600) + "}") == 0);
    REQUIRE(put(st, user("u"), "s", "never", "{}") == 0);
    // Gone the moment its time comes, before the deletion is written; and its unique value with it.
    CHECK(get(st, user("u"), "s", "gone") == "404");
    CHECK(ids_of(find(st, user("u"), "s", "{}")) == "never soon ");
    CHECK(put(st, user("u"), "s", "other", R"({"token":"t1"})") == 0);
    CHECK(st.next_expiry() == now - 1);
    std::vector<event> evs;
    CHECK(st.expire(now, &evs) == 1);
    REQUIRE(evs.size() == 1);
    CHECK((evs[0].del && evs[0].id == "gone" && evs[0].owner == "u"));
    CHECK(st.next_expiry() == now + 3600);
    CHECK(st.expire(now, &evs) == 0);
    // A patch that moves the time moves the expiry.
    REQUIRE(patch(st, user("u"), "s", "soon", "{\"set\":{\"exp\":" + std::to_string(now - 5) + "}}") == 0);
    CHECK(get(st, user("u"), "s", "soon") == "404");
    CHECK(st.expire(now, nullptr) == 1);
    CHECK(st.next_expiry() == 0);
    REQUIRE(st.sync());
    store again;
    st.close();
    REQUIRE(again.open(t.path, make_schema("s owner ttl:exp unique:token\n"), why));
    CHECK(ids_of(find(again, user("u"), "s", "{}")) == "never other ");
}

TEST_CASE("a replica's apply: another database's changes, with their own sequence numbers")
{
    tmpdir a, b;
    store primary, replica;
    std::string why;
    REQUIRE(primary.open(a.path, schema{}, why));
    REQUIRE(replica.open(b.path, make_schema("c private n\n"), why));
    std::vector<event> evs;
    std::vector<write_op> ops(2);
    ops[0].kind = write_op::put;
    ops[0].coll = "c";
    ops[0].id = "x";
    ops[0].body = parse(R"({"n":1})");
    ops[1].kind = write_op::put;
    ops[1].coll = "c";
    ops[1].id = "y";
    ops[1].body = parse(R"({"n":2,"_owner":"o"})");
    std::string out;
    error err;
    REQUIRE(primary.write(key, ops, out, err, &evs));
    REQUIRE(del(primary, key, "c", "x") == 0);
    std::vector<write_op> one(1);
    one[0].kind = write_op::patch;
    one[0].coll = "c";
    one[0].id = "y";
    one[0].body = parse(R"({"inc":{"n":40}})");
    REQUIRE(primary.write(key, one, out, err, &evs));
    std::vector<write_op> gone(1);
    gone[0].kind = write_op::del;
    gone[0].coll = "c";
    gone[0].id = "x";
    // x was put and then deleted outside `evs`; the replica is told the deletion through a record of its own.
    REQUIRE(evs.size() == 3);
    CHECK((evs[0].seq == 1 && evs[1].seq == 1 && evs[2].seq == 3));
    REQUIRE(replica.apply(evs, why));
    CHECK(replica.seq() == 3);
    CHECK(get(replica, key, "c", "y") == R"({"_id":"y","_v":2,"_owner":"o","n":42})");
    CHECK(get(replica, key, "c", "x").find("\"n\":1") != std::string::npos);
    // Applied again, nothing changes: the replica is past them.
    REQUIRE(replica.apply(evs, why));
    CHECK(replica.seq() == 3);
    REQUIRE(replica.sync());
    replica.close();
    store back;
    REQUIRE(back.open(b.path, make_schema("c private n\n"), why));
    CHECK(back.seq() == 3);
    CHECK(ids_of(find(back, key, "c", R"({"where":{"n":42}})")) == "y ");
    REQUIRE(back.reset(why));
    CHECK((back.documents() == 0 && back.seq() == 0));
    back.close();
    store empty;
    REQUIRE(empty.open(b.path, schema{}, why));
    CHECK(empty.documents() == 0);
    // The record round trip: what is encoded decodes to the same changes, each document's place known.
    std::vector<uint64_t> offs, offs2;
    const std::string rec = encode_record(9, evs, &offs);
    std::vector<event> back_evs;
    REQUIRE(decode_record(rec, back_evs, &offs2));
    CHECK(offs == offs2);
    REQUIRE(back_evs.size() == evs.size());
    for (size_t i = 0; i < evs.size(); ++i)
    {
        CHECK(back_evs[i].json == evs[i].json);
        if (!evs[i].del)
            CHECK(rec.substr(offs[i], evs[i].json.size()) == evs[i].json);
    }
}

TEST_CASE("a backup: every document copied off the loop into one file a store opens")
{
    tmpdir t, dest;
    store st;
    std::string why;
    REQUIRE(st.open(t.path, schema{}, why));
    for (int i = 0; i < 100; ++i)
        REQUIRE(put(st, key, "c", ("k" + std::to_string(i)).c_str(), "{\"i\":" + std::to_string(i) + "}") == 0);
    REQUIRE(del(st, key, "c", "k5") == 0);
    auto job = st.plan_backup(dest.path + "/seg-00000001.log");
    REQUIRE(job);
    CHECK(!st.plan_backup(dest.path + "/other"));
    job->run();
    REQUIRE_MESSAGE(job->ok, job->why);
    st.finish(*job);
    store restored;
    REQUIRE_MESSAGE(restored.open(dest.path, schema{}, why), why);
    CHECK(restored.documents() == 99);
    CHECK(restored.seq() == st.seq() - 1);
    CHECK(get(restored, key, "c", "k42") == get(st, key, "c", "k42"));
    CHECK(get(restored, key, "c", "k5") == "404");
}

TEST_CASE("--max-bytes refuses what would grow past it, and lets what shrinks through")
{
    tmpdir t;
    store st;
    std::string why;
    REQUIRE(st.open(t.path, schema{}, why));
    st.set_max_bytes(2000);
    const std::string big = "{\"x\":\"" + std::string(700, 'a') + "\"}";
    CHECK(put(st, key, "c", "a", big) == 0);
    CHECK(put(st, key, "c", "b", big) == 0);
    CHECK(put(st, key, "c", "c", big) == 507);
    CHECK(st.documents() == 2);
    CHECK(put(st, key, "c", "a", "{}") == 0);
    CHECK(put(st, key, "c", "c", big) == 0);
    CHECK(del(st, key, "c", "c") == 0);
    // A document past 1 MiB is refused whatever the bound.
    st.set_max_bytes(0);
    CHECK(put(st, key, "c", "huge", "{\"x\":\"" + std::string(store::max_doc, 'a') + "\"}") == 413);
}

TEST_CASE("a database of the first format, a snapshot and a journal, is taken into segments once")
{
    tmpdir t;
    {
        std::ofstream snap(t.path + "/data.snapshot");
        snap << "{\"format\":\"socketley-db\",\"version\":1}\n"
             << "{\"c\":\"chars\",\"id\":\"a\",\"v\":3,\"o\":\"u1\"}\t{\"name\":\"Merlin\",\"level\":4}\n"
             << "{\"c\":\"chars\",\"id\":\"gone\",\"v\":1}\t{}\n";
        mutation_journal j;
        REQUIRE(j.open_append(t.path + "/data.journal", "socketley-db"));
        socketley::bytes::writer w;
        w.u8(1);
        w.u32(2);
        w.u8(1);
        w.bytes("chars");
        w.bytes("b");
        w.u64(1);
        w.bytes("");
        w.bytes("{\"name\":\"Nimue\",\"level\":9}");
        w.u8(2);
        w.bytes("chars");
        w.bytes("gone");
        j.append(w.take());
        REQUIRE(j.sync());
    }
    std::string why;
    {
        store st;
        REQUIRE_MESSAGE(st.open(t.path, make_schema("chars owner level\n"), why), why);
        CHECK(st.documents() == 2);
        CHECK(get(st, key, "chars", "a") == R"({"_id":"a","_v":3,"_owner":"u1","name":"Merlin","level":4})");
        CHECK(get(st, key, "chars", "gone") == "404");
        CHECK(ids_of(find(st, key, "chars", R"({"where":{"level":{"gt":5}}})")) == "b ");
        CHECK(std::filesystem::exists(t.path + "/data.snapshot.v1"));
        CHECK(!std::filesystem::exists(t.path + "/data.journal"));
    }
    store again;
    REQUIRE_MESSAGE(again.open(t.path, make_schema("chars owner level\n"), why), why);
    CHECK(again.documents() == 2);
    CHECK(get(again, key, "chars", "b").find("Nimue") != std::string::npos);
}
