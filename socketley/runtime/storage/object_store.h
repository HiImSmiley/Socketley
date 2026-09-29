#pragma once
// The buckets and objects of one storage runtime, on one directory.
//
// Everything after open() is asynchronous on the runtime's ring through
// file_io, so a slow disk shows up as latency on the requests waiting for it
// and never as a loop that stopped serving its other connections.
//
// ─── LAYOUT ─────────────────────────────────────────────────────────────────
//   <dir>/<bucket>/created            decimal milliseconds since the epoch
//   <dir>/<bucket>/index.<shard>      the journal of puts and deletes
//   <dir>/<bucket>/tmp/<random>       a body on its way in
//   <dir>/<bucket>/data/ab/cd/<hash>  header + bytes, hash = sha256(key) in hex
//   <dir>/.trash/                     a deleted bucket, removed at the next start
//
// The object file is the truth and the journal is what makes a listing cheap:
// a start after a clean stop trusts the journal, and any other start reads
// every header and reconciles the journal against them.
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "object_format.h"
#include "../../shared/event_loop.h"
#include "../../shared/file_io.h"

namespace socketley::storage
{

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
    io_error,
    cancelled,
};

const char* status_name(st s);

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

    // The object's key and bucket, for the caller's log line.
    const std::string& key() const { return m_key; }

private:
    friend class object_store;
    put_op() = default;

    enum class stage_state : uint8_t { free, filling, full, writing };

    struct stage
    {
        std::unique_ptr<char[]> data;
        size_t                  fill{0};
        uint64_t                file_off{0};
        stage_state             state{stage_state::free};
    };

    void begin(object_store* store, std::string bucket, std::string key, object_meta meta,
               uint64_t expected, bool size_known);
    void pump();
    void flush(stage& s);
    void on_write_done(stage& s, int64_t res);
    void fail(st why);
    void maybe_finish();
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
    bool                  m_released{false};
    // Bytes reserved against the quota until this operation ends.
    uint64_t              m_reserved{0};

    uint64_t   m_received{0};
    // Where the next buffer to be filled begins in the file.
    uint64_t   m_next_off{0};
    md5_stream m_md5;
    st         m_status{st::ok};

    bool                             m_eof{false};
    bool                             m_first_written{false};
    bool                             m_header_done{false};
    bool                             m_header_writing{false};
    bool                             m_sync_started{false};
    bool                             m_tmp_committed{false};
    mutable bool                     m_want_ready{false};
    std::function<void(put_result)>  m_done;
    std::function<void()>            m_ready_cb;
    std::function<void(st)>          m_failed_cb;
    bool                             m_notified_failed{false};
};

// What the owner of a key needs to make a body a visible object.
struct commit_request
{
    std::string bucket;
    std::string key;
    // In the bucket's tmp directory, written and synced.
    std::string tmp_name;
    object_meta meta;
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

    // ── Objects, answered from memory ───────────────────────────────────────
    // The pointer is valid until the next operation that changes the bucket.
    const object_meta* find(std::string_view bucket, std::string_view key) const;
    st list(std::string_view bucket, const list_query& q, list_page& out) const;

    // ── Writes ──────────────────────────────────────────────────────────────
    // Null with `why` set when the request cannot start at all; the body is
    // then fed to the returned operation.  `expected` is the size a
    // Content-Length promised, and 0 with size_known false when it is not
    // known.
    std::shared_ptr<put_op> begin_put(std::string_view bucket, std::string_view key,
                                      object_meta meta, uint64_t expected, bool size_known,
                                      st& why);

    // The single step that makes a written body the object: rename, sync, journal.
    // A function call now, and the one a shard would send to the key's owner.
    void commit(commit_request req, std::function<void(put_result)> cb);

    // `existed` says whether there was an object to remove.
    void remove(std::string_view bucket, std::string_view key, std::function<void(st, bool existed)> cb);

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

    // Whether anything is still being written, which a clean stop must wait out.
    bool busy() const;

    uint64_t now_ms() const;

private:
    friend class put_op;
    struct bucket;
    struct lane;

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
        // Records the next compaction may not be attempted before.
        uint64_t    compact_after{0};
    };

    struct bucket
    {
        std::string name;
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
        std::unordered_set<std::string> made_dirs;
        // The compaction's cursor, valid while journal.frozen.
        std::map<std::string, object_meta, std::less<>>::const_iterator dump_it;
        int         dump_fd{-1};
        uint64_t    dump_off{0};
    };

    bucket* find_bucket(std::string_view name);
    const bucket* find_bucket(std::string_view name) const;

    // Startup, blocking.
    bool recover_bucket(const std::string& name, recovery_report& rep, std::string& err);
    bool load_journal(bucket& b, std::string& bad_why, bool& torn, bool& corrupt, recovery_report& rep);
    void reconcile_with_files(bucket& b, recovery_report& rep);
    bool rewrite_journal_sync(bucket& b, std::string& err);

    // The journal.
    void journal_append(bucket& b, std::string_view record, std::function<void(bool)> cb);
    void journal_kick(bucket& b);
    void maybe_compact(bucket& b);
    void compact_step(std::shared_ptr<bool> alive, const std::string& name);
    void compact_finish(const std::string& name, bool ok);

    // Per-key serialisation of the steps that make an object visible.
    void lane_enter(bucket& b, const std::string& key, std::function<void()> run);
    void lane_leave(const std::string& bucket_name, const std::string& key);

    void ensure_dirs(const std::string& bucket_name, const std::string& rel,
                     std::function<void(int leaf_fd, st)> cb);
    void apply_put(bucket& b, const std::string& key, const object_meta& meta);
    void apply_delete(bucket& b, const std::string& key);

    static std::string tmp_name();

    event_loop*   m_loop;
    file_io*      m_io;
    store_options m_opts;
    int           m_root_fd{-1};
    std::map<std::string, std::unique_ptr<bucket>, std::less<>> m_buckets;
    std::unordered_set<std::string> m_creating;
    uint64_t m_reserved{0};
    store_totals m_totals;
    // Set false when the store goes away, so a callback still in the ring finds out.
    std::shared_ptr<bool> m_alive;
    uint32_t m_inflight{0};
    bool     m_clean_start{false};
};

}   // namespace socketley::storage
