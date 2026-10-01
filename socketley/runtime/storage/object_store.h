#pragma once
// The buckets and objects of one storage runtime, on one directory.
//
// Everything after open() is asynchronous on the runtime's ring through
// file_io, so a slow disk shows up as latency on the requests waiting for it
// and never as a loop that stopped serving its other connections.
//
// ─── LAYOUT ─────────────────────────────────────────────────────────────────
//   <dir>/<bucket>/created            decimal milliseconds since the epoch
//   <dir>/<bucket>/cors               the bucket's CORSConfiguration, when it has one, written by shard 0
//   <dir>/<bucket>/index.<shard>      the journal of puts and deletes
//   <dir>/<bucket>/tmp/<random>       a body on its way in
//   <dir>/<bucket>/lifecycle          its LifecycleConfiguration, likewise
//   <dir>/<bucket>/data/ab/<hash>     header + bytes, hash = sha256(key) in hex; the 256 ab
//                                     directories are made and synced with the bucket
//   <dir>/.trash/                     a deleted bucket, removed at the next start
//
// The object file is the truth and the journal is what makes a listing cheap:
// a start after a clean stop trusts the journal, and any other start reads
// every header and reconciles the journal against them.  So an answer waits for
// the file, its rename and its directory, and never for the journal, which is
// written behind it and synced in a group.
#include <algorithm>
#include <cstdint>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "checksum.h"
#include "object_format.h"
#include "../../shared/event_loop.h"
#include "../../shared/file_io.h"
#include "../../shared/hash_pool.h"

namespace socketley::storage
{

struct cors_config;
struct lifecycle_config;

// The configuration documents a bucket keeps beside its objects, each in a file named for it.
enum class bucket_doc : uint8_t
{
    cors,
    lifecycle,
};
// The most a document may be, so it crosses to a sibling shard in one message.
inline constexpr size_t doc_max_bytes = 4u << 20;

// What an operation came to, named for the S3 error a client is given.
enum class st : uint8_t
{
    ok,
    no_such_bucket,
    no_such_key,
    bucket_exists,
    bucket_not_empty,
    invalid_bucket_name,
    key_too_long,
    metadata_too_large,
    too_large,
    bad_digest,
    storage_full,
    // Another operation on the same bucket has to finish first.
    busy,
    // A create-only write found the key already there.
    precondition_failed,
    io_error,
    cancelled,
};

const char* status_name(st s);

// The smallest string greater than every string that begins with `s`, empty
// when there is none because `s` is all 0xFF bytes.
std::string prefix_successor(std::string s);

struct bucket_info
{
    std::string name;
    int64_t     created_ms{0};
};

struct list_query
{
    std::string prefix;
    std::string delimiter;
    // Exclusive, S3's start-after and V1's marker.
    std::string start_after;
    // Inclusive, what a previous page said comes next; wins over start_after.
    std::string resume_at;
    bool        has_resume{false};
    size_t      max_keys{1000};
};

struct list_entry
{
    std::string key;
    object_meta meta;
};

struct list_page
{
    std::vector<list_entry>  objects;
    std::vector<std::string> prefixes;
    bool                     truncated{false};
    // Where the next page begins, meaningful when truncated.
    std::string              resume_at;
};

// What a walk of a listing reports, in key order, so a caller that renders each
// entry need not have it copied into a page first.
class list_visitor
{
public:
    virtual ~list_visitor() = default;
    virtual void object(const std::string& key, const object_meta& meta) = 0;
    virtual void prefix(std::string common) = 0;
    // The walk stopped with more behind it, which starts at `resume_at`.
    virtual void truncated(const std::string& resume_at) = 0;
};

struct put_result
{
    st          status{st::ok};
    object_meta meta;
};

struct open_result
{
    st          status{st::ok};
    int         fd{-1};
    object_meta meta;
    size_t      data_off{0};
    // Bytes of the body that arrived with the header read, so a small object
    // needs no second read.
    std::string prefetch;
};

// What has been stored, for `stats`.
struct store_totals
{
    uint64_t objects{0};
    uint64_t bytes{0};
    uint64_t buckets{0};
    uint64_t journal_records{0};
    uint64_t compactions{0};
    uint64_t fsyncs{0};
    uint64_t puts{0};
    uint64_t deletes{0};
    // Tag changes written into their object's header, and those that needed the object written again.
    uint64_t tag_writes{0};
    uint64_t tag_rewrites{0};
};

struct recovery_report
{
    uint64_t buckets{0};
    uint64_t objects{0};
    uint64_t tmp_removed{0};
    // Journal records whose file was gone.
    uint64_t dropped{0};
    // Files whose journal record was missing or different.
    uint64_t adopted{0};
    uint64_t torn_tails{0};
    uint64_t rebuilt_journals{0};
    uint64_t corrupt_files{0};
    // Answered puts whose rename a crash took, moved into place from their pool file.
    uint64_t rolled_forward{0};
    bool     clean_start{false};
};

struct store_options
{
    std::string dir;
    uint32_t    shard{0};
    uint32_t    nshards{1};
    // Zero means no quota.
    uint64_t    max_bytes{0};
    // Named so a test can lower it.
    uint64_t    max_object_bytes{5ull << 30};
    // A journal is rewritten once it holds this many records more than the
    // live objects need, and no sooner than the floor below.
    uint64_t    compact_floor{4096};
};

class object_store;

// What the owner of a key needs to make a body a visible object.
struct commit_request
{
    std::string bucket;
    std::string key;
    // In the bucket's tmp directory, written and synced.
    std::string tmp_name;
    object_meta meta;
    // Refused with precondition_failed when the key already exists, decided by
    // the owner under the key's lane so two racing creators cannot both win.
    bool        create_only{false};
    // A file from the bucket's pool, whose name was durable before the body
    // was written, so the answer waits for the rename and not for its sync.
    bool        pooled{false};
};

// A body being written, from the first byte to the commit.
//
// The staged bytes are written in large pieces while the next ones arrive, the
// digest is taken as they go past, and nothing but the two staging buffers is
// ever held: a 5 GiB object needs no more memory than a 5 MiB one.
class put_op : public std::enable_shared_from_this<put_op>
{
public:
    ~put_op();

    // Where the next bytes go and how many fit, so a receive can land straight
    // in the staging buffer; staged() says how many did.  Zero room means a
    // write is in flight, and the ready callback says when it is not.
    char*  stage_ptr();
    size_t stage_room() const;
    void   staged(size_t n);

    // Copies in as many of `p` as fit and returns how many, for a caller whose
    // bytes are not in place already.
    size_t append(const char* p, size_t n);

    void on_ready(std::function<void()> cb) { m_ready_cb = std::move(cb); }

    // The commit refuses to replace an object that is already there.
    void set_create_only(bool on)
    {
        m_create_only = on;
        // A pooled file is rolled forward after a crash, which a condition would have refused.
        if (on && m_pooled)
            fail(st::io_error);
    }

    // Called once, with the reason, if the write fails before finish().
    void on_failed(std::function<void(st)> cb) { m_failed_cb = std::move(cb); }

    bool failed() const { return m_status != st::ok; }
    st   status() const { return m_status; }
    uint64_t received() const { return m_received; }

    // All the bytes are in.  An expected digest that does not match the body
    // fails the operation with bad_digest before anything is committed.
    void finish(const md5_t* expected_md5, std::function<void(put_result)> cb);

    // The body will not complete: the temporary file is removed.
    void abort();

    // Takes the checksum of the body as it is staged and checks it against
    // `expected_b64` (empty for none) when the body is complete.  The caller
    // has put an entry named checksum_header(algo) in the meta given to
    // begin_put, holding a value of the length the checksum has, so that the
    // header reserved room for it.
    void track_checksum(checksum_algo algo, std::string expected_b64);
    // The value a trailer carried after the body, which is checked at finish().
    void expect_checksum(std::string b64);

    // Where a finished body goes instead of into the object namespace: a
    // multipart part, which the caller renames and keeps track of itself.
    using committer = std::function<void(commit_request, std::function<void(put_result)>)>;
    void set_committer(committer c)
    {
        m_committer = std::move(c);
        // A pooled file is rolled forward into the object namespace, which is not where this one goes.
        if (m_pooled)
            fail(st::io_error);
    }

    // The body goes to `path` at `off`, at most `room` bytes of it, and the temporary
    // file holds the header alone: a multipart part written where its object will read it.
    void place_body(std::string path, uint64_t off, uint64_t room);

    // The object's key and bucket, for the caller's log line.
    const std::string& key() const { return m_key; }

private:
    friend class object_store;
    put_op() = default;

    // `hashing` is a buffer whose write is done and whose digest is not, held
    // because a helper thread is still reading it.
    enum class stage_state : uint8_t { free, filling, full, writing, hashing };

    struct stage
    {
        // Shared with the digest jobs, which may outlive this operation.
        std::shared_ptr<char[]> data;
        size_t                  fill{0};
        // Where the bytes not yet handed to the digests begin.
        size_t                  hashed{0};
        uint64_t                file_off{0};
        stage_state             state{stage_state::free};
        // Digest jobs of this buffer that have not reported.
        uint32_t                hash_out{0};
    };

    // The digests of a body, which a helper thread updates while the operation
    // is waiting for it, and which the operation reads only after they are done.
    struct hash_state
    {
        md5_stream                       md5;
        std::unique_ptr<checksum_stream> ck;
    };

    void on_hashed(int stage_index);
    // Hands what the active buffer holds past `hashed` to the digests; `last` is the end of the body.
    void hash_staged(bool last);
    void finish_now();
    void begin(object_store* store, std::string bucket, std::string key, object_meta meta,
               uint64_t expected, bool size_known, bool plain);
    void pump();
    void flush(stage& s);
    void on_write_done(stage& s, int64_t res);
    void fail(st why);
    void maybe_finish();
    void synced(int64_t res);
    void cleanup_tmp();
    void release();

    object_store*         m_store{nullptr};
    std::shared_ptr<bool> m_alive;
    std::string           m_bucket;
    std::string           m_key;
    object_meta           m_meta;
    std::string           m_tmp_name;
    std::string           m_header;
    size_t                m_header_len{0};
    size_t                m_cap{0};
    stage                 m_stage[2];
    int                   m_active{0};
    int                   m_tmp_fd{-1};
    bool                  m_opening{true};
    bool                  m_pooled{false};
    bool                  m_released{false};
    // Bytes reserved against the quota until this operation ends.
    uint64_t              m_reserved{0};

    uint64_t   m_received{0};
    // The body's length when it was promised, and never reached otherwise.
    uint64_t   m_whole{UINT64_MAX};
    // Where the next buffer to be filled begins in the file.
    uint64_t   m_next_off{0};
    std::shared_ptr<hash_state> m_hs;
    // Body pieces hashed on the pool's threads rather than here, when the body is big enough to be worth the hop.
    bool        m_async{false};
    uint32_t    m_lane{0};
    uint32_t    m_hash_out{0};
    bool        m_finish_wait{false};
    md5_t       m_expect_md5{};
    bool        m_has_expect_md5{false};
    std::string m_ck_expect;
    committer   m_committer;
    st         m_status{st::ok};
    // A body placed into another file by place_body(), and the syncs still owed before the commit.
    bool        m_placed{false};
    bool        m_placing{false};
    int         m_place_fd{-1};
    uint64_t    m_place_off{0};
    uint64_t    m_place_room{0};
    int         m_syncs_left{0};

    bool                             m_eof{false};
    bool                             m_first_written{false};
    bool                             m_header_done{false};
    bool                             m_header_writing{false};
    bool                             m_sync_started{false};
    bool                             m_tmp_committed{false};
    bool                             m_create_only{false};
    mutable bool                     m_want_ready{false};
    std::function<void(put_result)>  m_done;
    std::function<void()>            m_ready_cb;
    std::function<void(st)>          m_failed_cb;
    bool                             m_notified_failed{false};
};

// The steps of a store that belong to another shard, handed to whatever carries a request to a sibling.
class shard_peers
{
public:
    virtual ~shard_peers() = default;
    virtual void commit(uint32_t owner, commit_request req, std::function<void(put_result)> cb) = 0;
    virtual void remove(uint32_t owner, std::string bucket, std::string key,
                        std::function<void(st, bool existed)> cb) = 0;
    virtual void set_tags(uint32_t owner, std::string bucket, std::string key, std::string tags,
                          std::function<void(st)> cb) = 0;
    // Tells every sibling to drop what it holds of the key, and `done` runs once each has answered or is gone.
    virtual void invalidate(std::string bucket, std::string key, std::function<void()> done) = 0;
};

class object_store
{
public:
    object_store(event_loop& loop, file_io& io, store_options opts);
    ~object_store();

    object_store(const object_store&)            = delete;
    object_store& operator=(const object_store&) = delete;

    // Reads the directory, removes what a crash left and reconciles the
    // journals; blocking, and only ever called before the runtime serves.
    bool open(std::string& err, recovery_report* report = nullptr);

    // Marks the directory as cleanly stopped when nothing is in flight, so the
    // next start can trust its journals; blocking, called from teardown.
    void close(bool clean);

    // ── Buckets ─────────────────────────────────────────────────────────────
    bool has_bucket(std::string_view name) const;
    std::vector<bucket_info> buckets() const;
    void create_bucket(std::string name, std::function<void(st)> cb);
    void delete_bucket(std::string name, std::function<void(st)> cb);

    // The halves of a bucket's life that a sharded runtime runs on more than
    // one shard: the others take up a bucket shard 0 made, and drop one in
    // three steps so that no shard is left holding a directory that moved.
    void adopt_bucket(std::string name, int64_t created_ms, std::function<void(st)> cb);
    int64_t bucket_created_ms(std::string_view name) const;
    // Refuses a bucket that holds objects or work, and otherwise stops it
    // taking any until it is dropped or the drop is aborted.
    st   drop_check(std::string_view name);
    void drop_abort(std::string_view name);
    void drop_rename(std::string name, std::function<void(st)> cb);
    void drop_forget(std::string_view name);
    // Whatever else a bucket holds that a drop must not throw away, such as an
    // upload begun and never completed: true keeps the bucket.
    void set_drop_guard(std::function<bool(std::string_view bucket)> guard) { m_drop_guard = std::move(guard); }
    // Removes a body that will not become anything from the bucket's tmp directory.
    void remove_tmp(std::string_view bucket, std::string tmp_name);

    // ── Configuration documents: CORS and lifecycle ─────────────────────────
    // Makes `xml` the bucket's document of `kind` on disk, or removes it when it is empty, and then here; shard 0's half.
    void write_doc(bucket_doc kind, std::string name, std::string xml, std::function<void(st)> cb);
    // Takes up a document another shard wrote.
    st adopt_doc(bucket_doc kind, std::string_view name, std::string_view xml);

    // Whether any bucket has CORS rules, so a request to a store without them looks nothing up.
    bool any_cors() const { return m_cors_buckets != 0; }
    // The bucket's CORS rules, null when it has none; valid until they next change.
    const cors_config* bucket_cors(std::string_view name) const;
    // The bucket's lifecycle rules, null when it has none.
    std::shared_ptr<const lifecycle_config> lifecycle(std::string_view name) const;
    // How many buckets have lifecycle rules.
    size_t lifecycle_buckets() const { return m_lifecycle_buckets; }
    // Told whenever a bucket's lifecycle rules change here.
    void set_lifecycle_listener(std::function<void()> fn) { m_lifecycle_listener = std::move(fn); }

    // ── Sharding ────────────────────────────────────────────────────────────
    uint32_t shard() const { return m_opts.shard; }
    uint32_t shards() const { return m_opts.nshards; }
    uint32_t owner_of(std::string_view bucket, std::string_view key) const;
    bool     owns(std::string_view bucket, std::string_view key) const
    {
        return owner_of(bucket, key) == m_opts.shard;
    }
    void set_peers(shard_peers* peers) { m_peers = peers; }

    // ── Objects, answered from memory ───────────────────────────────────────
    // Holds only the keys this shard owns, and the pointer is valid until the next operation that changes the bucket.
    const object_meta* find(std::string_view bucket, std::string_view key) const;

    // ── Hot small objects, kept in memory ───────────────────────────────────
    // The bytes of small objects, so a hot one is answered without opening its
    // file.  A key this shard owns is dropped wherever its index entry changes
    // and taken only while it still matches the index; another shard's key has
    // no index entry here, so its owner tells every sibling to drop it before
    // the commit or the delete is answered, and a read that a drop arrived
    // during is not kept.
    static constexpr uint64_t hot_max_object = 60000;
    // The bytes of `key` when they are held for exactly the version `current` names.
    const std::string* hot_get(std::string_view bucket, std::string_view key, const object_meta& current);
    // A held copy, found by one lookup, with the index's own record of its version when this shard owns the key.
    struct hot_hit
    {
        const object_meta* meta{nullptr};
        // Null when only the metadata of another shard's key is held, which is what a HEAD of it keeps.
        const std::string* body{nullptr};
        // The response headers of this version as text, empty until a reader renders them.
        std::string*       head{nullptr};
        // The copy is of another shard's key, so `meta` is what its read found and not an index record.
        bool               foreign{false};
    };
    bool hot_find(std::string_view bucket, std::string_view key, hot_hit& out);
    // Keeps what a read brought in, when `read` is still the indexed version.
    void hot_put(std::string_view bucket, std::string_view key, const object_meta& read, std::string_view body);
    uint64_t hot_bytes() const { return m_hot_bytes; }
    // Counts the headers just rendered into a held copy's `head` against the budget.
    void hot_charge(size_t n) { m_hot_bytes += n; }
    // Read before a read of another shard's key starts, and handed back to hot_put_foreign when it ends.
    uint64_t hot_epoch() const { return m_drop_epoch; }
    // Keeps what a read of another shard's key brought in, unless a drop of that key or of its bucket arrived since `epoch`;
    // an empty `body` keeps the metadata alone, for an object of any size.
    void hot_put_foreign(std::string_view bucket, std::string_view key, uint64_t epoch, const object_meta& read,
                         std::string_view body);
    // The owner's word that the key changed: drops it and refuses the reads that were in flight.
    void hot_invalidate(std::string_view bucket, std::string_view key);
    // A sibling started, so every copy of its keys may be older than its files, and so may every read in flight.
    void hot_forget_owner(uint32_t shard);

    // The metadata of any object, from memory when this shard owns the key and
    // from the object's own header otherwise.
    void stat_object(std::string_view bucket, std::string_view key,
                     std::function<void(st, const object_meta&)> cb);
    // The same for a key the caller knows is another shard's, whose header is read once and kept until its owner's drop.
    void stat_foreign(std::string_view bucket, std::string_view key,
                      std::function<void(st, const object_meta&)> cb);
    st list(std::string_view bucket, const list_query& q, list_page& out) const;
    // The same walk, reported to `v` as it goes.
    st list_walk(std::string_view bucket, const list_query& q, list_visitor& v) const;

    // ── Writes ──────────────────────────────────────────────────────────────
    // Null with `why` set when the request cannot start at all; the body is
    // then fed to the returned operation.  `expected` is the size a
    // Content-Length promised, and 0 with size_known false when it is not
    // known.  `plain` is a put of an object with no condition and no
    // committer, which may take a file from the pool.
    std::shared_ptr<put_op> begin_put(std::string_view bucket, std::string_view key,
                                      object_meta meta, uint64_t expected, bool size_known,
                                      st& why, bool plain = false);

    // The largest body a pooled file takes, since a start reads it whole to roll it forward.
    static constexpr uint64_t pooled_max = 1u << 20;

    // The step that makes a written body the object, run here when this shard owns the key and by the owner otherwise.
    void commit(commit_request req, std::function<void(put_result)> cb);

    // The step itself, which only the owner of the key may run.
    void commit_local(commit_request req, std::function<void(put_result)> cb);

    // `existed` says whether there was an object to remove.
    void remove(std::string_view bucket, std::string_view key, std::function<void(st, bool existed)> cb);
    // `only_if`, when given, is asked under the key's lane and keeps an object it says no to.
    void remove_local(std::string_view bucket, std::string_view key, std::function<void(st, bool existed)> cb,
                      std::function<bool(const object_meta&)> only_if = {});

    // Makes `tags`, in the encoding of tags_of(), an object's tags, keeping its bytes, ETag and time.
    void set_tags(std::string_view bucket, std::string_view key, std::string tags, std::function<void(st)> cb);
    // The step itself, which only the owner of the key may run.
    void set_tags_local(std::string_view bucket, std::string_view key, std::string tags, std::function<void(st)> cb);

    // A new body made of an existing object's, with the metadata `meta` names.
    void copy(std::string_view src_bucket, std::string_view src_key,
              std::string_view dst_bucket, std::string_view dst_key, object_meta meta,
              std::function<void(put_result)> cb);

    // ── Reads ───────────────────────────────────────────────────────────────
    // Opens the object's file and reads its header, with up to `prefetch` bytes
    // of the body behind it; the caller closes the descriptor.
    void open_object(std::string_view bucket, std::string_view key, size_t prefetch,
                     std::function<void(open_result)> cb);

    store_totals totals() const;
    const store_options& options() const { return m_opts; }

    // The quota may move under a serving store; what is held stays held.
    void set_max_bytes(uint64_t bytes) { m_opts.max_bytes = bytes; }

    // Where a body's digests are taken when it is big; null takes them in line.
    void set_hash_pool(hash_pool* pool) { m_hash = pool; }

    // Whether anything is still being written, which a clean stop must wait out.
    bool busy() const;
    // Busy with anything but a journal write: what a clean stop cannot wait out.
    bool working() const;

    // Bodies on their way in across every bucket, for a cap on what streaming puts hold.
    uint32_t active_puts() const { return m_puts_active; }

    uint64_t now_ms() const;

    // The name of a fresh file in a bucket's tmp directory, named for this shard
    // so a restart removes only the files its own uploads left.
    std::string tmp_name() const;

    // Bytes something outside the object namespace holds on the disk, counted
    // against the quota until they are given back.
    void hold_bytes(uint64_t n) { m_reserved += n; }
    void release_bytes(uint64_t n) { m_reserved -= std::min(m_reserved, n); }

private:
    friend class put_op;
    struct bucket;
    struct lane;
    static inline uint64_t s_bucket_gen = 0;

    // The journal of one bucket.
    struct journal
    {
        int         fd{-1};
        uint64_t    off{0};
        uint64_t    records{0};
        std::string pending;
        uint64_t    pending_records{0};
        std::vector<std::function<void(bool)>> pending_cbs;
        std::string inflight;
        uint64_t    inflight_records{0};
        std::vector<std::function<void(bool)>> inflight_cbs;
        bool        writing{false};
        bool        frozen{false};
        // Written and not yet synced: the records a crash may take, which the
        // next start finds again by reading the object files.
        bool        dirty{false};
        uint64_t    dirty_bytes{0};
        // Run once the journal has nothing queued, in flight or unsynced.
        std::vector<std::function<void()>> idle_cbs;
        // Records the next compaction may not be attempted before.
        uint64_t    compact_after{0};
    };

    struct bucket
    {
        std::string name;
        // Tells this bucket from one made again under its name.
        uint64_t    gen{++s_bucket_gen};
        int64_t     created_ms{0};
        int         dir_fd{-1};
        int         data_fd{-1};
        int         tmp_fd{-1};
        std::map<std::string, object_meta, std::less<>> objects;
        uint64_t    bytes{0};
        journal     j;
        // Keys with a commit in flight, and what waits behind each.
        std::unordered_map<std::string, std::vector<std::function<void()>>> lanes;
        uint32_t    active_puts{0};
        uint32_t    active_ops{0};
        bool        closing{false};
        std::shared_ptr<const cors_config> cors;
        std::shared_ptr<const lifecycle_config> lifecycle;
        // The compaction's cursor, valid while journal.frozen.
        std::map<std::string, object_meta, std::less<>>::const_iterator dump_it;
        int         dump_fd{-1};
        uint64_t    dump_off{0};
        // pool/, made by the first refill, and its empty files, open, whose
        // names a sync of pool/ has made durable.
        int         pool_fd{-1};
        std::vector<std::pair<std::string, int>> pool;
        uint32_t    pool_making{0};
        // Syncs of pool/: whoever asks while one runs is covered by the next.
        bool        pool_syncing{false};
        std::vector<std::function<void(bool)>> pool_sync_next;
    };

    bucket* find_bucket(std::string_view name);
    const bucket* find_bucket(std::string_view name) const;

    // Startup, blocking.
    struct recovering;
    bool recover_bucket(const std::string& name, recovery_report& rep, std::vector<recovering>& out,
                        std::string& err);
    bool finish_bucket(recovering& r, recovery_report& rep, std::string& err);
    bool load_journal(bucket& b, std::string& bad_why, bool& torn, bool& corrupt, bool& other_layout,
                      recovery_report& rep);
    // Reads every object file of the buckets that need it, on threads; false when a directory could not be read whole.
    bool reconcile_with_files(std::vector<recovering>& rs, recovery_report& rep, std::string& err);
    bool rewrite_journal_sync(bucket& b, std::string& err);

    // The journal.
    // `cb` may be empty: the object files are the truth, so a caller that has made its change
    // durable does not wait for the record.
    void journal_append(bucket& b, std::string_view record, std::function<void(bool)> cb);
    // Writes and syncs what is queued, blocking, for a stop; false if a journal is busy.
    bool settle_journals();
    void journal_kick(bucket& b);
    bool compact_due(const bucket& b) const;
    void maybe_compact(bucket& b);

    // The pool of pre-made files for small puts, and the syncs of pool/ they need.
    bool take_pooled(bucket& b, std::string& name, int& fd);
    void pool_refill(bucket& b);
    void pool_open_dir(bucket& b);
    void pool_close(bucket& b);
    void sync_pool(bucket& b, std::function<void(bool)> cb);
    void sync_pool_round(const std::string& bucket_name);
    // Removes a temporary file, and for a pooled one waits until the removal is durable.
    void drop_tmp(bucket& b, const std::string& tmp, bool pooled, std::function<void()> then);
    // The rest of a pooled commit once its rename is done: the answer, then the syncs.
    void commit_pooled(bucket& b, const std::string& key, const object_meta& meta, int leaf,
                       std::function<void()> release, std::function<void(put_result)> cb);
    uint64_t roll_forward_pooled(bucket& b, std::unordered_set<std::string>& keep);
    void compact_step(std::shared_ptr<bool> alive, const std::string& name);
    void compact_finish(const std::string& name, bool ok);

    // Per-key serialisation of the steps that make an object visible.
    void lane_enter(bucket& b, const std::string& key, std::function<void()> run);
    void lane_leave(const std::string& bucket_name, const std::string& key);

    void ensure_dirs(const std::string& bucket_name, const std::string& rel,
                     std::function<void(int leaf_fd, st)> cb, bool repaired = false);
    void apply_put(bucket& b, const std::string& key, const object_meta& meta);
    void apply_delete(bucket& b, const std::string& key);
    // A tag change whose header is read: written into one of its slots, or the object written again with it.
    struct tag_change;
    void tags_in_place(std::shared_ptr<tag_change> tc, std::string slot, uint64_t at);
    void tags_rewrite(std::shared_ptr<tag_change> tc, uint64_t data_off);
    void tags_written(std::shared_ptr<tag_change> tc, st s, bool changed);
    // Runs `next` once every sibling has dropped its copy of a key this shard just changed.
    void invalidate_siblings(const std::string& bucket_name, const std::string& key, std::function<void()> next);

    // What a quota lets this shard hold: an equal share, since the shards
    // cannot see each other's bytes.
    uint64_t quota() const;
    void create_bucket_impl(std::string name, bool adopt, int64_t created_ms,
                            std::function<void(st)> cb);
    void forget_bucket(const std::string& name);

    event_loop*   m_loop;
    file_io*      m_io;
    store_options m_opts;
    int           m_root_fd{-1};
    std::map<std::string, std::unique_ptr<bucket>, std::less<>> m_buckets;
    std::unordered_set<std::string> m_creating;
    shard_peers* m_peers{nullptr};
    hash_pool*   m_hash{nullptr};
    std::function<bool(std::string_view)> m_drop_guard;
    std::function<void()> m_lifecycle_listener;
    // A test hook: a commit of a key with this prefix kills the process after
    // its rename and before its journal record.
    std::string m_kill_after_rename;

    struct hot_entry
    {
        std::string id;        // bucket, a NUL, key
        std::string body;
        object_meta meta;
        std::string head;
        // The index's record of the key, null for another shard's: valid until hot_drop, which every change to that record makes first.
        const object_meta* live;
    };
    // What an entry counts against the budget: its bytes, its name, the headers rendered for it and, with no body, its metadata.
    static uint64_t held_bytes(const hot_entry& e)
    {
        uint64_t n = e.body.size() + e.id.size() + e.head.size();
        if (!e.body.empty())
            return n;
        n += sizeof(hot_entry) + e.meta.content_type.size();
        for (const auto& [name, value] : e.meta.extra)
            n += name.size() + value.size();
        return n;
    }
    void hot_insert(const std::string& id, const object_meta& read, std::string_view body, const object_meta* live);
    void hot_drop(std::string_view bucket, std::string_view key);
    void hot_drop_bucket(std::string_view bucket);
    const std::string& hot_id(std::string_view bucket, std::string_view key);
    std::list<hot_entry>                                         m_hot_lru;   // most recent first
    std::unordered_map<std::string_view, std::list<hot_entry>::iterator> m_hot_index;
    uint64_t    m_hot_bytes{0};
    uint64_t    m_hot_budget{32ull << 20};
    std::string m_hot_scratch;
    // The keys dropped last, so a read can ask whether its own was among those that arrived while it ran.
    static constexpr size_t drop_ring_size = 64;
    void hot_note_drop(uint64_t id_hash);
    uint64_t m_drop_epoch{0};
    uint64_t m_drop_ring[drop_ring_size]{};
    uint64_t m_reserved{0};
    // Buckets with CORS rules and with lifecycle rules.
    uint32_t m_cors_buckets{0};
    uint32_t m_lifecycle_buckets{0};
    static const char* doc_file(bucket_doc kind);
    // The one place a bucket's document is parsed and taken up, an empty one removing it; false when it does not parse.
    bool take_doc(bucket& b, bucket_doc kind, std::string_view xml);
    store_totals m_totals;
    // Set false when the store goes away, so a callback still in the ring finds out.
    std::shared_ptr<bool> m_alive;
    uint32_t m_inflight{0};
    uint32_t m_puts_active{0};
    bool     m_clean_start{false};
    // A journal write or sync failed, so a stop is not a clean one.
    bool     m_journal_lost{false};
    // A sync of pool/ or of an object directory failed, so a stop is not a clean one.
    bool     m_sync_lost{false};
    // Descriptors held by every bucket's pool.
    uint32_t m_pool_fds{0};
};

}   // namespace socketley::storage
