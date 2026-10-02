#pragma once
// The buckets and objects of one storage runtime, on one directory.
//
// Everything after open() is asynchronous on the runtime's ring through
// file_io, so a slow disk shows up as latency on the requests waiting for it
// and never as a loop that stopped serving its other connections.
//
// ─── LAYOUT ─────────────────────────────────────────────────────────────────
//   <dir>/<bucket>/created            decimal milliseconds since the epoch, and on a second line the
//                                     id of the user that owns the bucket when it is not the default
//   <dir>/<bucket>/cors               the bucket's CORSConfiguration, when it has one, written by shard 0
//   <dir>/<bucket>/encryption         its ServerSideEncryptionConfiguration, likewise
//   <dir>/<bucket>/index.<shard>      the journal of puts and deletes
//   <dir>/<bucket>/tmp/<random>       a body on its way in
//   <dir>/<bucket>/lifecycle          its LifecycleConfiguration, likewise
//   <dir>/<bucket>/notification       its NotificationConfiguration, likewise
//   <dir>/<bucket>/object-lock        its ObjectLockConfiguration, likewise, which is never removed
//   <dir>/<bucket>/policy             its bucket policy, likewise
//   <dir>/<bucket>/versioning         its VersioningConfiguration, likewise
//   <dir>/<bucket>/versions/ab/<hash>.<id>
//                                     a noncurrent version of a key in a versioned bucket, made
//                                     with its 256 directories before the first configuration
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
#include "sse.h"
#include "../../shared/event_loop.h"
#include "../../shared/file_io.h"
#include "../../shared/cache_shard_map.h"
#include "../../shared/hash_pool.h"

namespace socketley::storage
{

struct cors_config;
struct lifecycle_config;
struct lock_config;
struct notify_config;
class bucket_policy;

// The configuration documents a bucket keeps beside its objects, each in a file named for it.
enum class bucket_doc : uint8_t
{
    cors,
    lifecycle,
    policy,
    versioning,
    encryption,
    tagging,
    object_lock,
    notification,
};
// Every kind, for the walks that settle or take up all of a bucket's documents.
inline constexpr bucket_doc all_bucket_docs[] = {bucket_doc::cors,       bucket_doc::lifecycle, bucket_doc::policy,
                                                 bucket_doc::versioning, bucket_doc::encryption, bucket_doc::tagging,
                                                 bucket_doc::object_lock, bucket_doc::notification};

// A bucket's versioning: never configured, keeping every version, or writing the null version.
enum class versioning : uint8_t
{
    off,
    enabled,
    suspended,
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
    // A version id the key has no version of.
    no_such_version,
    // The version asked for is a delete marker, which has no bytes or tags.
    delete_marker,
    // A shard that had to take part could not be reached, so nothing was changed.
    unavailable,
    // The version is under a retention or a legal hold that the request may not lift.
    locked,
    // The change does not fit the bucket's other configuration: object lock and versioning that is not Enabled.
    invalid_bucket_state,
};

const char* status_name(st s);

// The smallest string greater than every string that begins with `s`, empty
// when there is none because `s` is all 0xFF bytes.
std::string prefix_successor(std::string s);

struct bucket_info
{
    std::string name;
    int64_t     created_ms{0};
    // Empty for the default owner.
    std::string owner;
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

// What a delete did: removed a version, or put a delete marker in front of the key.
struct remove_result
{
    st          status{st::ok};
    bool        existed{false};
    // The version removed, or the one made, is a delete marker.
    bool        marker{false};
    // The version removed or made, empty when the bucket keeps none.
    std::string version_id{};
};

// A query of ListObjectVersions.
struct version_query
{
    std::string prefix;
    std::string delimiter;
    // Exclusive: what a previous page returned last, a key alone or a key and one of its versions.
    std::string key_marker;
    std::string version_marker;
    size_t      max_keys{1000};
};

struct version_item
{
    // The key, or the common prefix when `prefix`.
    std::string key;
    object_meta meta;
    bool        latest{false};
    bool        prefix{false};
};

// A page of ListObjectVersions, in S3's order: key ascending, each key's versions newest first.
struct version_page
{
    std::vector<version_item> items;
    bool                      truncated{false};
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
    // The file is a delete marker, whose metadata `meta` holds and whose status is no_such_key.
    bool        delete_marker{false};
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
    // Object and version files whose headers the start read, zero when every journal was trusted.
    uint64_t start_files_read{0};
    // Empty files every bucket's pool holds ready for a small put, durable in pool/.
    uint64_t pool_ready{0};
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
    // Noncurrent versions and delete markers read from the files, and copies a crash left of a version kept elsewhere.
    uint64_t versions{0};
    uint64_t version_duplicates{0};
    // Files whose headers were read.
    uint64_t files_read{0};
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

// The preconditions of a conditional write, If-Match and If-None-Match as the request gave them.
struct put_condition
{
    std::string if_match;
    std::string if_none_match;

    bool any() const { return !if_match.empty() || !if_none_match.empty(); }
};

// Whether a write under `c` may replace `current`, null for a key that is not there:
// ok, precondition_failed, or no_such_key for an If-Match with nothing to match.
st check_put_condition(const put_condition& c, const object_meta* current);

// Who asked for a change, as an event record names them: the user id or "anonymous", and the client's address.
struct change_origin
{
    std::string principal;
    std::string source_ip;
};

// A change of what a version keeps in its header's slots, made in place by the owner of its key.
struct header_change
{
    enum class kind : uint8_t { tags, retention, legal_hold };
    kind        what{kind::tags};
    // The tags in the encoding of tags_of(), the retention in retention_extra's (empty to remove it), or ON or OFF.
    std::string value;
    // The caller may shorten, remove or change a GOVERNANCE retention.
    bool        bypass{false};
    change_origin who{};
};

// What made a change, which decides the event a bucket's notification configuration is told of it as.
enum class change_cause : uint8_t
{
    put,
    post,
    copy,
    complete,
    remove,
    lifecycle,
};

// A change to an object, told by the owner of its key to whoever sends its bucket's events.
struct change_note
{
    std::string bucket;
    std::string key;
    change_origin who;
    // One notify_event bit.
    uint16_t    event{0};
    // The object's size and ETag, which a removal has none of.
    bool        has_object{false};
    uint64_t    size{0};
    std::string etag;
    std::string version_id;
};

// What the owner of a key needs to make a body a visible object.
struct commit_request
{
    std::string bucket;
    std::string key;
    // In the bucket's tmp directory, written and synced.
    std::string tmp_name;
    object_meta meta;
    // Decided by the owner under the key's lane, so two racing conditional writers cannot both win.
    put_condition cond;
    // A file from the bucket's pool, whose name was durable before the body
    // was written, so the answer waits for the rename and not for its sync.
    bool        pooled{false};
    change_cause cause{change_cause::put};
    change_origin who;
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

    // The commit is refused unless what the key holds then meets `c`.
    void set_condition(put_condition c)
    {
        m_cond = std::move(c);
        // A pooled file is rolled forward after a crash, which a condition would have refused.
        if (m_cond.any() && m_pooled)
            fail(st::io_error);
    }
    // The commit refuses to replace an object that is already there.
    void set_create_only(bool on) { set_condition(on ? put_condition{{}, "*"} : put_condition{}); }

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

    // What the commit is told it is and who asked for it, for the event it may make.
    void set_cause(change_cause c) { m_cause = c; }
    void set_origin(change_origin who) { m_who = std::move(who); }

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
        // The sealed chunks of `data`, written instead of it when the body is encrypted.
        std::shared_ptr<char[]> out;
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
               uint64_t expected, bool size_known, bool plain, const sse_seal_spec* seal);
    void pump();
    void flush(stage& s);
    // The bytes a buffer takes before it is written: an encrypted body's are whole chunks.
    size_t limit(const stage& s) const { return m_seal && s.file_off != 0 ? m_cap - m_header_len : m_cap; }
    // Seals an encrypted buffer's chunks, then writes them where the body's layout puts them.
    void flush_sealed(stage& s);
    void write_sealed(stage& s, size_t lead, size_t n, bool last);
    // Writes the empty chunk that ends a sealed body whose length is whole chunks and whose buffers are written.
    void write_sealed_tail();
    // Puts the digest of a pooled body's sealed bytes into its header, in front of them in the buffer.
    bool seal_pooled_header(stage& s, size_t lead, bool last, const md5_t& digest);
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
    // The key the body is encrypted with, shared with the jobs that seal it, and their lane.
    std::shared_ptr<const sse_seal_spec> m_seal;
    uint32_t    m_seal_lane{0};
    // The chunk that ends the sealed stream has been written, and the one written on its own when no buffer held it.
    bool        m_tail_sealed{false};
    bool        m_tail_writing{false};
    std::array<char, sse_overhead> m_tail{};
    committer   m_committer;
    change_cause m_cause{change_cause::put};
    change_origin m_who;
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
    put_condition                    m_cond;
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
    // `version_id` empty deletes the key as the bucket's versioning says, and otherwise that version of it.
    // `bypass` lets the removal of a version go past a GOVERNANCE retention.
    virtual void remove(uint32_t owner, std::string bucket, std::string key, std::string version_id, bool bypass,
                        change_origin who, std::function<void(remove_result)> cb) = 0;
    virtual void change_header(uint32_t owner, std::string bucket, std::string key, std::string version_id,
                               header_change change, std::function<void(st, std::string version_id)> cb) = 0;
    // Tells every sibling that may hold the key to drop it, and `done` runs once each has answered or is gone.
    virtual void invalidate(std::string bucket, std::string key, std::function<void()> done) = 0;
    // Asks the owner whether `read` is the version it indexes, which also has it tell this shard when that changes.
    virtual void hold(uint32_t owner, std::string bucket, std::string key, const object_meta& read,
                      std::function<void(bool)> cb) = 0;
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
    // `owner` is the id of the user that made it, empty for the default owner.
    void create_bucket(std::string name, std::string owner, std::function<void(st)> cb);
    void delete_bucket(std::string name, std::function<void(st)> cb);
    // The id of the user that owns a bucket, empty for the default owner or a bucket that is not here.
    std::string_view bucket_owner(std::string_view name) const;

    // The halves of a bucket's life that a sharded runtime runs on more than
    // one shard: the others take up a bucket shard 0 made, and drop one in
    // three steps so that no shard is left holding a directory that moved.
    void adopt_bucket(std::string name, int64_t created_ms, std::string owner, std::function<void(st)> cb);
    int64_t bucket_created_ms(std::string_view name) const;
    // Refuses a bucket that holds objects or work, and otherwise stops it
    // taking any until it is dropped or the drop is aborted.
    st   drop_check(std::string_view name);
    void drop_abort(std::string_view name);
    void drop_rename(std::string name, std::function<void(st)> cb);
    void drop_forget(std::string_view name);
    // Whatever else is at work in a bucket that a drop must wait out, such as a
    // completion being assembled: true keeps the bucket.
    void set_drop_guard(std::function<bool(std::string_view bucket)> guard) { m_drop_guard = std::move(guard); }
    // Told the name of each bucket this shard lets go of, so what else it kept of the bucket goes too.
    void set_forget_listener(std::function<void(const std::string& bucket)> fn) { m_forget_listener = std::move(fn); }
    // Removes a body that will not become anything from the bucket's tmp directory.
    void remove_tmp(std::string_view bucket, std::string tmp_name);

    // ── Configuration documents: CORS, lifecycle and policy ─────────────────
    // Shard 0 changes a document in three steps, and the file `<kind>.new` exists exactly while a change is
    // undecided: staged writes it, committed makes it the document (an empty one removes it), abandoned removes it.
    void stage_doc(bucket_doc kind, std::string name, std::string xml, std::function<void(st)> cb);
    // `cb` hears whether the change is now the file every shard settles by, and how the syncs went.
    void commit_doc(bucket_doc kind, std::string name, std::string xml, std::function<void(bool visible, st)> cb);
    void abandon_doc(bucket_doc kind, std::string name, std::function<void()> cb);
    // Takes up a document another shard wrote.
    st adopt_doc(bucket_doc kind, std::string_view name, std::string_view xml);

    // A shard told that change `seq` may happen serves nothing of the bucket until it knows how it ended.
    st doubt_doc(bucket_doc kind, std::string_view name, uint64_t seq);
    // How change `seq` ended: `xml` is the document it made, or null when it was abandoned.
    void decided_doc(bucket_doc kind, std::string_view name, uint64_t seq, const std::string* xml);
    // Whether any bucket here is in doubt, so a request to a store with none looks nothing up.
    bool any_doubt() const { return m_doubt_buckets != 0; }
    // Settles a bucket in doubt from the files shard 0 decides by; false while a change to it is undecided.
    bool docs_settled(std::string_view name);
    void settle_all_docs();

    // Whether any bucket has CORS rules, so a request to a store without them looks nothing up.
    bool any_cors() const { return m_cors_buckets != 0; }
    // The bucket's CORS rules, null when it has none; valid until they next change.
    const cors_config* bucket_cors(std::string_view name) const;
    // The bucket's Tagging document, null when it has none.
    std::shared_ptr<const std::string> bucket_tagging(std::string_view name) const;
    // The bucket's object lock configuration, null when object lock was never enabled on it.
    std::shared_ptr<const lock_config> bucket_lock(std::string_view name) const;
    // Whether a document of `kind` may become `xml` beside the bucket's others, which shard 0 asks in the order of its changes.
    st doc_conflict(bucket_doc kind, std::string_view name, std::string_view xml) const;
    // The bucket's lifecycle rules, null when it has none.
    std::shared_ptr<const lifecycle_config> lifecycle(std::string_view name) const;
    // How many buckets have lifecycle rules.
    size_t lifecycle_buckets() const { return m_lifecycle_buckets; }
    // Whether any bucket has a policy, so a request to a store without one looks nothing up.
    bool any_policy() const { return m_policy_buckets != 0; }
    // Whether the bucket encrypts every new object it is given without being asked to.
    bool bucket_encrypts(std::string_view name) const;
    // The bucket's policy, null when it has none; valid until it next changes.
    const bucket_policy* policy(std::string_view name) const;
    // Told whenever a bucket's lifecycle rules change here.
    void set_lifecycle_listener(std::function<void()> fn) { m_lifecycle_listener = std::move(fn); }
    // The bucket's notification configuration, null when it has none.
    std::shared_ptr<const notify_config> bucket_notify(std::string_view name) const;
    // Told by the owner of a key of each change to an object of a bucket with a notification configuration; the
    // change is answered once the listener runs `answer`.
    using change_listener = std::function<void(change_note, std::function<void()> answer)>;
    void set_change_listener(change_listener fn) { m_change_listener = std::move(fn); }

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
    // Keeps what a read of another shard's key brought in once its owner has said it is current, unless a drop of
    // that key or of its bucket arrived since `epoch`; an empty `body` keeps the metadata alone, for an object of any size.
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
    // committer, which may take a file from the pool.  `seal`, when given, is
    // the key the body is encrypted with, whose record `meta` already carries.
    std::shared_ptr<put_op> begin_put(std::string_view bucket, std::string_view key,
                                      object_meta meta, uint64_t expected, bool size_known,
                                      st& why, bool plain = false, const sse_seal_spec* seal = nullptr);

    // The largest body a pooled file takes, since a start reads it whole to roll it forward.
    static constexpr uint64_t pooled_max = 1u << 20;

    // The step that makes a written body the object, run here when this shard owns the key and by the owner otherwise.
    void commit(commit_request req, std::function<void(put_result)> cb);

    // The step itself, which only the owner of the key may run.
    void commit_local(commit_request req, std::function<void(put_result)> cb);

    // `existed` says whether there was an object to remove; in a versioned bucket a delete marker is put in front of it.
    void remove(std::string_view bucket, std::string_view key, std::function<void(st, bool existed)> cb);
    // `only_if`, when given, is asked under the key's lane and keeps an object it says no to.
    void remove_local(std::string_view bucket, std::string_view key, std::function<void(st, bool existed)> cb,
                      std::function<bool(const object_meta&)> only_if = {},
                      change_cause cause = change_cause::remove, change_origin who = {});
    // The same with the version: `version_id` empty deletes the key, and otherwise removes that version for good,
    // which a retention or legal hold refuses as st::locked unless `bypass` lifts a GOVERNANCE retention.
    void remove_version(std::string_view bucket, std::string_view key, std::string version_id,
                        std::function<void(remove_result)> cb, bool bypass = false, change_origin who = {});
    // `only_if` is asked of the version that would be removed, or of the latest before a marker covers it.
    void remove_version_local(std::string_view bucket, std::string_view key, std::string version_id,
                              std::function<void(remove_result)> cb,
                              std::function<bool(const object_meta&)> only_if = {}, bool bypass = false,
                              change_cause cause = change_cause::remove, change_origin who = {});

    // Makes `change` of an object or of its version `version_id`, keeping its bytes, ETag and time; `cb` is told
    // the version it changed.
    void change_header(std::string_view bucket, std::string_view key, std::string version_id, header_change change,
                       std::function<void(st, std::string)> cb);
    // The step itself, which only the owner of the key may run.
    void change_header_local(std::string_view bucket, std::string_view key, std::string version_id,
                             header_change change, std::function<void(st, std::string)> cb);
    // Makes `tags`, in the encoding of tags_of(), the tags of an object or of its version `version_id`.
    void set_tags(std::string_view bucket, std::string_view key, std::string version_id, std::string tags,
                  std::function<void(st, std::string)> cb, change_origin who = {})
    {
        change_header(bucket, key, std::move(version_id),
                      header_change{header_change::kind::tags, std::move(tags), false, std::move(who)}, std::move(cb));
    }
    void set_tags(std::string_view bucket, std::string_view key, std::string tags, std::function<void(st)> cb)
    {
        set_tags(bucket, key, {}, std::move(tags), [cb = std::move(cb)](st s, std::string) { cb(s); });
    }

    // A new body made of an existing object's, or of its version `src_version` when that is not empty, with the
    // metadata `meta` names and the checksum `algo` of its bytes, or none.
    void copy(std::string_view src_bucket, std::string_view src_key, std::string src_version,
              std::string_view dst_bucket, std::string_view dst_key, object_meta meta, checksum_algo algo,
              std::function<void(put_result)> cb, change_origin who = {});
    void copy(std::string_view src_bucket, std::string_view src_key, std::string_view dst_bucket,
              std::string_view dst_key, object_meta meta, std::function<void(put_result)> cb,
              checksum_algo algo = checksum_algo::none)
    {
        copy(src_bucket, src_key, {}, dst_bucket, dst_key, std::move(meta), algo, std::move(cb));
    }

    // ── Versions ────────────────────────────────────────────────────────────
    versioning bucket_versioning(std::string_view bucket) const;
    // The delete marker that is the key's latest version, null when it has none; this shard's keys only.
    const object_meta* latest_marker(std::string_view bucket, std::string_view key) const;
    // Version `version_id` of a key this shard owns, from memory; null when there is none.
    const object_meta* find_version(std::string_view bucket, std::string_view key, std::string_view version_id) const;
    // Opens version `version_id` of any key, where its owner put it, as open_object does the latest; a delete
    // marker is no_such_key with `delete_marker` set and its metadata.
    void open_version(std::string_view bucket, std::string_view key, std::string version_id, size_t prefetch,
                      std::function<void(open_result)> cb);
    // The metadata of version `version_id` of any key; a delete marker is st::delete_marker with its metadata.
    void stat_version(std::string_view bucket, std::string_view key, std::string version_id,
                      std::function<void(st, const object_meta&)> cb);
    // This shard's part of ListObjectVersions.
    st list_versions(std::string_view bucket, const version_query& q, version_page& out) const;
    // Each key at or after `from` under `prefix` with versions behind its latest or a delete marker as its latest,
    // with its latest object (null when that is a marker) and its other versions newest first, at most `max_keys`;
    // the key to go on at, empty when there are no more.
    using version_walk = std::function<void(const std::string& key, const object_meta* latest,
                                            const std::vector<object_meta>& versions)>;
    std::string walk_versioned_keys(std::string_view bucket, std::string_view prefix, std::string_view from,
                                    size_t max_keys, const version_walk& fn) const;

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
    hash_pool* hashes() const { return m_hash; }
    // False once the store is gone, for work of a caller's that outlives a callback.
    const std::shared_ptr<bool>& alive_token() const { return m_alive; }

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
        std::string owner;
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
        std::shared_ptr<const bucket_policy> policy;
        // The bucket's own Tagging document, as it was set.
        std::shared_ptr<const std::string> tagging;
        // Its object lock configuration, which once set is never removed.
        std::shared_ptr<const lock_config> lock;
        std::shared_ptr<const notify_config> notify;
        versioning  vstate{versioning::off};
        // Per key, every version but a latest that is not a delete marker, newest first: the key's
        // noncurrent versions, behind its latest when that is a marker; empty unless the bucket was versioned.
        std::map<std::string, std::vector<object_meta>, std::less<>> versions;
        // The documents, a bit per kind, this shard may hold an old copy of, and the change each is waiting on.
        uint8_t     doc_doubt{0};
        uint64_t    doc_doubt_seq[std::size(all_bucket_docs)]{};
        // New objects are encrypted with the master key when they ask for nothing else.
        bool        encrypts{false};
        // How many entries `versions` holds across its keys.
        uint64_t    nversions{0};
        // The compaction's cursor: the key it goes on at, in objects and then in versions, valid while journal.frozen.
        std::string dump_key;
        bool        dump_versions{false};
        bool        dump_done{false};
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
                      uint32_t& format, recovery_report& rep);
    // Makes the versions the walk found of a bucket that has versions/ its index, and repairs what a crash left of them.
    void load_versions(recovering& r, recovery_report& rep, bool& changed);
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
    // What every step of a commit shares, so a step's callback holds one pointer and not copies of the rest.
    struct commit_state
    {
        std::shared_ptr<bool>           alive;
        commit_request                  req;
        std::function<void(put_result)> cb;
        std::string                     rel;
        // The syncs a pooled commit hands the lane on after, and whether every one of them held.
        int                             syncs_left{2};
        bool                            synced{true};
    };
    using commit_ptr = std::shared_ptr<commit_state>;
    // The lane is handed on and the bucket released once nothing of the commit is left to do.
    void commit_release(const commit_state& c);
    // Every way out but a pooled commit's answer, which releases before the caller hears because it may start the next operation.
    void commit_done(const commit_ptr& c, st s);
    // A refusal after the body was synced, which for a pooled file first makes its removal durable.
    void commit_refuse(const commit_ptr& c, st s);
    // The rest of a pooled commit once its rename is done: the answer, then the syncs.
    void commit_pooled(bucket& b, const commit_ptr& c, int leaf);
    // `versioned` keeps the version a pool file replaces, as a versioned commit would have.
    uint64_t roll_forward_pooled(bucket& b, std::unordered_set<std::string>& keep, bool versioned);
    void compact_step(std::shared_ptr<bool> alive, const std::string& name);
    void compact_finish(const std::string& name, bool ok);

    // Per-key serialisation of the steps that make an object visible.
    void lane_enter(bucket& b, const std::string& key, std::function<void()> run);
    void lane_leave(const std::string& bucket_name, const std::string& key);

    void ensure_dirs(const std::string& bucket_name, const std::string& rel,
                     std::function<void(int leaf_fd, st)> cb, bool repaired = false);
    void apply_put(bucket& b, const std::string& key, const object_meta& meta);
    void apply_delete(bucket& b, const std::string& key);
    // Opens the object file at `rel` below `dir_fd` and reads its header, which must be `key`'s.
    void open_file(int dir_fd, std::string rel, std::string key, size_t prefetch, std::function<void(open_result)> cb);

    // The versioned halves of a commit and a delete, run under the key's lane by its owner.
    struct vop;
    // Whether the key is written and deleted as a versioned one.
    static bool versioned(const bucket& b, std::string_view key)
    {
        return b.vstate != versioning::off || (!b.versions.empty() && b.versions.contains(key));
    }
    // The order of the newest version `key` has, zero for none.
    static uint64_t newest_seq(const bucket& b, std::string_view key);
    // The version a new latest of `key` is given, newer than every one it has.
    version_tag next_version(const bucket& b, const std::string& key, bool marker) const;
    // Whether the version a writer put in a body's header is one the owner can give it as it stands.
    bool stamp_holds(const bucket& b, const std::string& key, const object_meta& meta) const;
    // The index's other versions of a key, each change journaled: `m` in its place by order, or the version `id` gone.
    void version_add(bucket& b, const std::string& key, const object_meta& m);
    void version_drop(bucket& b, const std::string& key, std::string_view id);
    // The same on a list alone, for the journal's replay: the version of `m`'s id replaced, or false when it was not there.
    static bool place_version(std::vector<object_meta>& list, const object_meta& m, uint64_t* replaced_size = nullptr);
    static bool erase_version(std::vector<object_meta>& list, std::string_view id, uint64_t* size = nullptr);
    void commit_versioned(std::string bucket, std::string key, std::string tmp, bool pooled, object_meta meta,
                          std::function<void()> release, std::function<void(put_result)> cb);
    void remove_versioned(std::string bucket, std::string key, std::string version_id,
                          std::function<bool(const object_meta&)> only_if, bool bypass,
                          std::function<void()> release, std::function<void(remove_result)> cb);
    void vop_header(std::shared_ptr<vop> v);
    void vop_copy(std::shared_ptr<vop> v, int src, uint64_t data_off);
    void vop_install(std::shared_ptr<vop> v);
    // A pooled version renamed into place: the answer, then the syncs, then the lane.
    void vop_pooled(std::shared_ptr<vop> v, bool drop_null);
    void vop_end(std::shared_ptr<vop> v, st s);
    // The index's half of a new latest, which `meta` is, once its file is in place.
    void version_install(bucket& b, const std::string& key, const object_meta& meta);
    // The index's half of a version removed for good, promoting the one behind it; true when the latest changed.
    bool version_forget(bucket& b, const std::string& key, const std::string& id);
    // A read of a version where it is, and where it moved to if a rename took it meanwhile.
    struct version_probe;
    void version_probe_step(std::shared_ptr<version_probe> p);
    // The bytes of noncurrent versions, counted with the bucket's.
    void version_bytes(bucket& b, int64_t delta);
    // A header change whose header is read: written into one of its slots, or the object written again with it.
    struct tag_change;
    void tags_in_place(std::shared_ptr<tag_change> tc, std::string slot, uint64_t at);
    void tags_rewrite(std::shared_ptr<tag_change> tc, uint64_t data_off);
    void tags_written(std::shared_ptr<tag_change> tc, st s, bool changed);
    // Runs `next` once every sibling has dropped its copy of a key this shard just changed.
    void invalidate_siblings(const std::string& bucket_name, const std::string& key, std::function<void()> next);

    // What a quota lets this shard hold: an equal share, since the shards
    // cannot see each other's bytes.
    uint64_t quota() const;
    void create_bucket_impl(std::string name, bool adopt, int64_t created_ms, std::string owner,
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
    std::function<void(const std::string&)> m_forget_listener;
    std::function<void()> m_lifecycle_listener;
    change_listener m_change_listener;
    // The answers to a commit, a removal and a header change, which wait for the event they make when the bucket has
    // a notification configuration.
    std::function<void(put_result)> noted_commit(const bucket& b, const commit_request& req,
                                                 std::function<void(put_result)> cb);
    std::function<void(remove_result)> noted_remove(const bucket& b, std::string_view key, bool by_version,
                                                    change_cause cause, change_origin who,
                                                    std::function<void(remove_result)> cb);
    std::function<void(st, std::string)> noted_header(const bucket& b, std::string_view key, const header_change& c,
                                                      std::function<void(st, std::string)> cb);
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
    // Whether a read of another shard's key that began at `epoch` may still be kept: no drop of it or of its bucket since.
    bool hot_foreign_fresh(std::string_view bucket, std::string_view key, uint64_t epoch);
    uint64_t m_drop_epoch{0};
    uint64_t m_drop_ring[drop_ring_size]{};
    // For each slot of another shard, the drop epoch from which its owner drops this shard for any key of it, or 0.
    std::vector<uint64_t> m_held_since = std::vector<uint64_t>(cache_slot_count, 0);
    uint64_t m_reserved{0};
    // Buckets with CORS rules, with lifecycle rules and with a policy.
    uint32_t m_cors_buckets{0};
    uint32_t m_lifecycle_buckets{0};
    uint32_t m_policy_buckets{0};
    // Buckets with a document in doubt.
    uint32_t m_doubt_buckets{0};
    static const char* doc_file(bucket_doc kind);
    // The one place a bucket's document is parsed and taken up, an empty one removing it; false with `why` when it
    // does not parse, and a policy that does not then refuses everything but its own operations.
    bool take_doc(bucket& b, bucket_doc kind, std::string_view xml, std::string* why = nullptr);
    void set_doubt(bucket& b, bucket_doc kind, uint64_t seq);
    void clear_doubt(bucket& b, bucket_doc kind);
    // Reads a document of `kind` as shard 0 decided it into `xml`; false while it is undecided or cannot be read.
    static bool read_decided_doc(int dir_fd, bucket_doc kind, std::string& xml);
    bool settle_bucket(bucket& b);
    bool versioning_settled(bucket& b);
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
