#pragma once
// The db runtime's documents: collections of JSON objects under ids, each with a version that grows by one with every
// change and the account that owns it, indexed by the fields the schema names, read and written by a principal the
// schema's access decides for.
//
// A write is one or more changes made together or not at all, kept as one record in a journal; the journal is synced
// by the caller, once for every write of a turn, before any of them is answered. Now and then the whole is written as
// a snapshot naming its format version, and the journal cut behind it; a snapshot newer than this build reads is
// refused rather than rewritten without what it does not understand.
#include <cstdint>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "db_doc.h"
#include "db_schema.h"
#include "../../shared/mutation_journal.h"
#include "../../shared/transparent_string.h"

namespace socketley::db
{

// Who asks: anybody, a signed-in account by its id, or a service key, which reaches everything.
struct principal
{
    enum kind_t : uint8_t { anyone, user, key };
    kind_t kind{anyone};
    std::string sub;
};

struct doc
{
    std::string owner;
    uint64_t v{0};
    jvalue body;
    // What it holds against --max-bytes: its JSON, its id and owner, and a fixed share for the maps it sits in.
    size_t bytes{0};
};

// One change of a write.
struct write_op
{
    enum kind_t : uint8_t { put, insert, patch, del };
    kind_t kind{put};
    std::string coll;
    std::string id;
    // The document of a put or an insert; the changes of a patch: set, unset, inc, push and pull.
    jvalue body;
    // The version the document must be at, 0 for any.
    uint64_t if_v{0};
    // A put that must make the document rather than replace one.
    bool if_absent{false};
};

struct query
{
    struct cond
    {
        enum op_t : uint8_t { eq, ne, gt, gte, lt, lte, in, prefix, exists };
        std::string field;
        op_t op{eq};
        jvalue value;
        // The value as an index orders it, made once rather than once a document.
        ikey key;
    };
    std::vector<cond> where;
    std::string sort;
    bool desc{false};
    size_t limit{100};
    size_t skip{0};
    bool count{false};
};

// A failed call's answer: an HTTP status and a sentence.
struct error
{
    int status{0};
    std::string code;
    std::string message;
};

class store
{
public:
    static constexpr uint32_t format_version = 1;
    static constexpr size_t   max_doc        = 1u << 20;
    static constexpr size_t   max_ops        = 256;
    static constexpr size_t   max_limit      = 1000;
    static constexpr size_t   max_collections = 1024;

    store() = default;
    store(const store&) = delete;
    store& operator=(const store&) = delete;

    // The documents kept under `dir`, read whole: the snapshot, then every journal record after it.
    bool open(const std::string& dir, std::string& why);
    void close();

    // The schema the next calls are judged and indexed by; false, and the one before kept, when a unique index it
    // adds already has two documents of one value.
    bool set_schema(const schema& s, std::string& why);
    const schema& get_schema() const { return m_schema; }

    // The most bytes the documents may hold, 0 for no bound.
    void set_max_bytes(uint64_t b) { m_max_bytes = b; }

    // A document as it is kept, null when there is none, whoever asks.
    const doc* get(std::string_view coll, std::string_view id) const;
    // A document as JSON, with _id, _v and _owner; false with `err` when it is absent or not the principal's to read.
    bool read(const principal& who, std::string_view coll, std::string_view id, std::string& out, error& err) const;
    // The changes made, each document as it now is written to `out` as a JSON array, and recorded in the journal,
    // which the caller syncs before answering; none of them made when one cannot be.
    bool write(const principal& who, std::vector<write_op>& ops, std::string& out, error& err);
    // The documents of a collection a query picks, as {"docs":[...]} and "next" when there are more.
    bool find(const principal& who, std::string_view coll, const query& q, std::string& out, error& err) const;

    // The journal's records on the disk; flush() writes them to the file, which the caller then syncs on journal_fd().
    bool sync() { return m_journal.sync(); }
    bool flush() { return m_journal.flush(); }
    int journal_fd() const { return m_journal.fd(); }
    bool dirty() const { return m_journal.pending_bytes() > 0; }

    // Writes the snapshot now and cuts the journal behind it.
    bool compact(std::string& why);

    size_t collections() const { return m_colls.size(); }
    size_t documents() const { return m_docs; }
    uint64_t bytes() const { return m_bytes; }
    uint64_t journal_records() const { return m_journal_records; }
    std::vector<std::string> collection_names() const;

    // A query's JSON, read; false with `err` when it is not one.
    static bool parse_query(const jvalue& in, query& q, error& err);

private:
    struct index_state
    {
        index_def def;
        std::set<std::pair<ikey, std::string>> entries;
    };
    struct coll_state
    {
        std::unordered_map<std::string, doc, string_hash, string_equal> docs;
        std::vector<index_state> indexes;
        // Every document by its owner, so an account's own are found without a scan.
        std::set<std::pair<std::string, std::string>> by_owner;
    };

    coll_state* coll_of(std::string_view name);
    const coll_state* coll_of(std::string_view name) const;
    access access_of(std::string_view coll) const;
    void index_doc(coll_state& c, const std::string& id, const doc& d, bool add);
    // The document `id` replaced by `d`, or removed when `d` is null, its indexes and bytes with it.
    void set_doc(coll_state& c, const std::string& id, const doc* d);
    void rebuild(coll_state& c, const collection_def* def);
    bool apply(std::string_view record);
    bool read_snapshot(const std::string& path, std::string& why);
    bool may_read(const principal& who, access a, const doc& d) const;
    bool unique_ok(const coll_state& c, const std::string& id, const doc& d, error& err) const;

    std::string m_dir;
    schema m_schema;
    std::unordered_map<std::string, coll_state, string_hash, string_equal> m_colls;
    size_t m_docs{0};
    uint64_t m_bytes{0};
    uint64_t m_max_bytes{0};
    mutation_journal m_journal;
    uint64_t m_journal_records{0};
    uint64_t m_journal_bytes{0};
    uint64_t m_snapshot_bytes{0};
};

// The JSON a document is answered as: its fields with _id, _v and _owner first.
void write_doc(const std::string& id, const doc& d, std::string& out);

// The changes of a patch made to `body`; false with `err` when one cannot be.
bool apply_patch(jvalue& body, const jvalue& changes, error& err);

}   // namespace socketley::db
