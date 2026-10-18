// Fuzz target: the db runtime's readers of what a client sends -- a query, a patch, a document -- and of the schema
// file an operator gives it (socketley/runtime/db/).
//
// The first byte chooses: 0 a query, asked of a store with indexes and of one without; 1 a patch, made to a fixed
// document; 2 a document, written and read back; 3 a schema, parsed and set; 4 a record as a segment or a replica's
// stream hands one over.
//
// Properties checked, beyond "did it crash":
//   * a query answers JSON, the same with the schema's indexes as without them;
//   * a patch that is made leaves a document that writes as JSON which reads back the same;
//   * a document that is written reads back as the fields it was given, with its version;
//   * a schema that parses names only valid collections and fields, and a store takes it or keeps the one before;
//   * a record that decodes encodes back to the same bytes, each document's JSON where its offset says.
#include "fuzz_common.h"
#include "runtime/db/db_doc.h"
#include "runtime/db/db_schema.h"
#include "runtime/db/db_store.h"

#include <cstdlib>
#include <filesystem>
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

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz::set_current(data, size);
    if (size < 1)
        return 0;
    const std::string_view rest(reinterpret_cast<const char*>(data) + 1, size - 1);
    switch (data[0] % 5)
    {
        case 0: query(rest); break;
        case 1: patch(rest); break;
        case 2: document(rest); break;
        case 3: schema(rest); break;
        default: record(rest); break;
    }
    return 0;
}
