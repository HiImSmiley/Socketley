#pragma once
// The db runtime's documents: collections of JSON objects under ids, each with a version that grows by one with every
// change and the account that owns it, indexed by the fields the schema names, read and written by a principal the
// schema's access decides for.
//
// The documents live in the segments of a seglog; memory holds where each one is, its version, owner and the values
// its indexes order it by, and a cache of the documents last read, so a database may hold far more than memory. Every
// write is one record carrying a sequence number; a write is made whole in memory or not at all, then recorded, and the
// caller syncs before answering. Sealed segments whose documents have mostly moved on are merged off the loop.
#include <cstdint>
#include <memory>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include "db_doc.h"
#include "db_docmap.h"
#include "db_log.h"
#include "db_schema.h"
#include "../../shared/util/transparent_string.h"

namespace socketley::db
{

// Who asks: anybody, a signed-in account by its id, or a service key, which reaches everything.
struct principal
{
    enum kind_t : uint8_t { anyone, user, key };
    kind_t kind{anyone};
    std::string sub;
};

// A document's JSON held in memory, its bytes right after it, so a read reaches both in one place.
struct cached_json;

struct doc
{
    std::string owner;
    uint64_t v{0};
    // The record that wrote it, which a reader waits to be on the disk.
    uint64_t seq{0};
    // When it goes, in seconds since 1970, by its collection's ttl field; 0 for never.
    int64_t expires{0};
    location at;
    // Its values for its collection's indexes, in the schema's order.
    std::vector<ikey> keys;
    // Its JSON in the store's cache, set and cleared by the store alone and only on the document in its map; a copy's
    // is never read.
    mutable cached_json* cache{nullptr};
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

// A document as it became, or its deletion, as a feed and a replica are told.
struct event
{
    uint64_t seq{0};
    std::string coll;
    std::string id;
    std::string owner;
    uint64_t v{0};
    bool del{false};
    std::string json;
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

// Documents copied into a new segment off the loop: a merge's living ones, or a backup's every one.
struct copy_job
{
    struct item
    {
        std::string coll, id, owner;
        uint64_t v{0}, seq{0};
        location from;
        location to;
    };
    std::vector<item> items;
    std::vector<uint32_t> sources;
    std::string dir;
    std::string dest;
    uint32_t dest_seg{0};
    bool merge{false};
    // Filled by run().
    bool ok{false};
    std::string why;

    // Reads each document where it is and writes the new segment; safe off the loop, since sealed segments do not
    // change and a document's bytes in the newest stay where they were written.
    void run();
};

class store
{
public:
    static constexpr uint32_t format_version = 2;
    static constexpr size_t   max_doc        = 1u << 20;
    static constexpr size_t   max_write      = 32u << 20;
    static constexpr size_t   max_ops        = 256;
    static constexpr size_t   max_limit      = 1000;
    // The document bytes a query not asked by a key reads for conditions and a sort no index answers.
    static constexpr size_t   max_scan_bytes = 8u << 20;
    static constexpr size_t   max_collections = 1024;

    store() = default;
    ~store();
    store(const store&) = delete;
    store& operator=(const store&) = delete;

    // The documents kept under `dir`, judged and indexed by `s`; false with `why` when they do not read or a unique
    // index the schema has is broken by two of them.
    bool open(const std::string& dir, const schema& s, std::string& why);

    // ── A shard reading shard 0's log ───────────────────────────────────────
    // The documents of `dir` as its writer has made them durable, up to change `until`, read and never written.
    bool follow_open(const std::string& dir, const schema& s, uint64_t until, std::string& why);
    // The changes past those read, up to `until`, each told to `events`; false when the log no longer goes on from
    // where the reading stands -- cleared, restored, or merged past it -- which a follow_open answers.
    bool follow(uint64_t until, std::vector<event>* events);
    // Documents a merge moved, found where it put them, and the segments it removed let go.
    void follow_layout();
    bool following() const { return m_following; }
    // How often the writer's set of segments changed, which a reader of its log follows.
    uint64_t layout() const { return m_log.layout(); }
    void close();

    // The schema the next calls are judged and indexed by; false, and the one before kept, when a unique index it
    // adds already has two documents of one value.
    bool set_schema(const schema& s, std::string& why);
    const schema& get_schema() const { return m_schema; }

    // The most bytes the documents may hold, 0 for no bound; and the most the cache of documents read holds.
    void set_max_bytes(uint64_t b) { m_max_bytes = b; }
    void set_cache_bytes(uint64_t b);

    // A document's place and figures, null when there is none, it went, or whoever asks may not see it.
    const doc* get(std::string_view coll, std::string_view id) const;
    // A document as JSON, with _id, _v and _owner; false with `err` when it is absent or not the principal's to read.
    // `depends` is the sequence number the answer rests on, which the caller waits to be on the disk, and `version`
    // the document's.
    bool read(const principal& who, std::string_view coll, std::string_view id, std::string& out, error& err,
              uint64_t& depends, uint64_t* version = nullptr);
    // The changes made, each document as it now is written to `out` as a JSON array, recorded, and told to `events`;
    // none of them made when one cannot be.
    // What a write's first change found and left: whether its document was there, and the version it made.
    struct first_change
    {
        bool existed{false};
        uint64_t version{0};
    };
    bool write(const principal& who, std::vector<write_op>& ops, std::string& out, error& err,
               std::vector<event>* events = nullptr, first_change* first = nullptr);
    // The documents of a collection a query picks, as {"docs":[...]} and "next" when there are more.
    bool find(const principal& who, std::string_view coll, const query& q, std::string& out, error& err,
              uint64_t& depends);

    // Documents whose time came, deleted as one write; none when none is due.
    size_t expire(int64_t now, std::vector<event>* events);
    // When the next document goes, 0 for none.
    int64_t next_expiry() const;

    // Another database's changes, as its feed told them, made here with their own sequence numbers.
    bool apply(const std::vector<event>& evs, std::string& why);
    // Every document gone, as a replica empties itself before it takes a whole copy.
    bool reset(std::string& why);
    // The sequence number a whole copy was taken at, kept though no document carries it.
    void mark(uint64_t seq);

    // The records written to the file, and synced; the newest segment's descriptor for a sync made elsewhere.
    bool flush() { return m_log.flush(); }
    bool sync() { return m_log.sync(); }
    int journal_fd() const { return m_log.fd(); }
    // True while a full segment is sealed off the loop and the newest's sync must wait for it.
    bool sealing() { return m_log.sealing(); }
    // The last sequence number written.
    uint64_t seq() const { return m_seq; }

    // A merge of the sealed segments when they are more dead than alive, or a backup of every document into `dest`;
    // null when none is due or one is running. finish() takes its result back on the loop.
    std::unique_ptr<copy_job> plan_merge();
    std::unique_ptr<copy_job> plan_backup(const std::string& dest);
    void finish(copy_job& job);
    // Segments kept while something outside reads documents by where they are, a replica's copy being sent.
    void pin() { ++m_pins; }
    void unpin();
    // Every living document's place and figures at seq(), for a whole copy sent out.
    std::vector<copy_job::item> everything();
    // A document's JSON from where it is.
    bool body_at(const location& at, std::string& out) { return m_log.read(at, out); }

    size_t collections() const { return m_colls.size(); }
    size_t documents() const { return m_docs; }
    uint64_t bytes() const { return m_bytes; }
    uint64_t disk_bytes() const { return m_log.total_bytes(); }
    size_t segments() const { return m_log.sealed().size() + 1; }
    uint64_t cache_hits() const { return m_hits; }
    uint64_t cache_misses() const { return m_misses; }

    // A reading request first tried without waiting for the disk: a document the page cache does not hold is noted in
    // `wanted` and read as missing, and one in `fetched`, by where it lies, is read from there; null ends it.
    struct fetched_doc
    {
        location at;
        std::string json;
    };
    void probe(std::vector<location>* wanted, const std::vector<fetched_doc>* fetched)
    {
        m_wanted = wanted;
        m_fetched = fetched;
    }
    // The documents a probe noted, as a descriptor of their own each and where they lie in it.
    int dup_fd_of(const location& at) { return m_log.dup_fd_of(at); }
    uint64_t merges() const { return m_merges; }
    std::vector<std::string> collection_names() const;

    // A query's JSON, read; false with `err` when it is not one.
    static bool parse_query(const jvalue& in, query& q, error& err);

private:
    struct index_state
    {
        index_def def;
        // Each document by its value and id, to its node in the collection, which keeps its place while it lives.
        std::map<std::pair<ikey, std::string>, const doc*> entries;
    };
    struct coll_state
    {
        doc_map<doc> docs;
        std::vector<index_state> indexes;
        // Every document by its owner, so an account's own are found without a scan.
        std::map<std::pair<std::string, std::string>, const doc*> by_owner;
        std::string ttl;
        // The last write that changed the collection, which a query's answer rests on.
        uint64_t last_seq{0};
    };
    coll_state* coll_of(std::string_view name);
    const coll_state* coll_of(std::string_view name) const;
    coll_state& make_coll(const std::string& name);
    access access_of(std::string_view coll) const;
    void index_doc(coll_state& c, const std::string& id, const doc& d, bool add);
    // The index entries and the owner's of `id` moved from what `before` holds to what `after` does, either null, the
    // entries made naming `node`.
    void reindex(coll_state& c, const std::string& id, const doc* before, const doc* after, const doc* node);
    // The document `id` replaced by `d`, or removed when `d` is null, with its indexes, expiry, bytes and cache.
    // `id` made `*d`, which is moved from, or removed when `d` is null.
    void set_doc(coll_state& c, const std::string& coll, const std::string& id, doc* d);
    // The keys and expiry a body gives a document of `c`.
    void derive(const coll_state& c, const jvalue& body, doc& d) const;
    bool rebuild(coll_state& c, const std::string& name, const collection_def* def, std::string& why);
    void drop_doomed();
    // One record read into the documents, its changes told to `events` when it is given.
    bool scan(uint32_t seg, uint64_t payload_off, std::string_view payload, std::vector<event>* events = nullptr);
    // A document a merge wrote again, taken at its new place when it is still the version there.
    void relocate(const event& e, uint32_t seg, uint64_t off);
    bool may_read(const principal& who, access a, const doc& d) const;
    bool unique_ok(const coll_state& c, const std::string& id, const doc& d, error& err) const;
    bool expired(const doc& d) const;
    // A document's JSON: a write's own, the cache's, or the disk's.
    bool json_of(const doc& d, std::string& out);
    bool body_of(const doc& d, jvalue& out);
    // The cached JSON of `d`, marked used; valid until the cache next changes.
    bool cached(const doc& d, std::string_view& out);
    void cache_put(const doc& d, std::string_view json);
    void cache_drop(const doc& d);
    void free_block(cached_json* b);
    // Blocks evicted until the cache holds `limit`: a hand clears the bit a read sets and takes the first block found
    // clear, so a hit moves nothing.
    void evict_to(uint64_t limit);
    void clear_cache();
    void live_add(const doc& d, int64_t sign);

    seglog m_log;
    std::vector<location>* m_wanted{nullptr};
    const std::vector<fetched_doc>* m_fetched{nullptr};
    schema m_schema;
    std::unordered_map<std::string, coll_state, string_hash, string_equal> m_colls;
    size_t m_docs{0};
    uint64_t m_bytes{0};
    uint64_t m_max_bytes{0};
    uint64_t m_seq{0};
    // When documents go: (time, collection, id).
    std::set<std::tuple<int64_t, std::string, std::string>> m_expiry;
    // The bytes of living documents each segment holds, against which a merge judges its dead ones.
    std::unordered_map<uint32_t, uint64_t> m_live;
    // A write's documents before they have a place on the disk, by collection and id.
    std::unordered_map<std::string, std::string> m_staged;
    // The deletions a start has read, so an older record read after one does not bring its document back.
    std::unordered_map<std::string, uint64_t> m_tombs;

    std::vector<cached_json*> m_blocks;
    size_t m_hand{0};
    uint64_t m_cache_bytes{0};
    uint64_t m_cache_limit{64ull << 20};
    uint64_t m_hits{0}, m_misses{0};

    bool m_job_running{false};
    int m_pins{0};
    std::vector<uint32_t> m_doomed;
    bool m_following{false};
    // Where the reading of the writer's log stands, and every segment whose records it has taken in.
    uint32_t m_follow_seg{0};
    uint64_t m_follow_off{0};
    std::set<uint32_t> m_seen_segs;
    uint64_t m_merges{0};
};

// The JSON a document is answered as: its fields with _id, _v and _owner first.
void write_doc(const std::string& id, const doc& d, std::string_view body_json, std::string& out);

// The changes of a patch made to `body`; false with `err` when one cannot be.
bool apply_patch(jvalue& body, const jvalue& changes, error& err);

// A write record's documents, as a feed tells them: what scan() reads and apply() writes.
bool decode_record(std::string_view payload, std::vector<event>& out, std::vector<uint64_t>* json_offs = nullptr,
                   uint64_t* seq = nullptr);
std::string encode_record(uint64_t seq, const std::vector<event>& evs, std::vector<uint64_t>* json_offs = nullptr);

}   // namespace socketley::db
