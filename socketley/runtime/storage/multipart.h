#pragma once
// Multipart uploads of one storage runtime: the uploads that are open, the
// parts each holds, and the steps that create, complete and abort them.
//
// ─── LAYOUT ─────────────────────────────────────────────────────────────────
//   <dir>/<bucket>/mpu/<upload-id>/meta   the object-to-be, in an object header
//   <dir>/<bucket>/mpu/<upload-id>/<n>    part n: an object header, then its bytes
//   <dir>/<bucket>/mpu/<upload-id>/data   the object being made, its header's room first
//
// A part is written like any object body, to a temporary file that is synced,
// and is then renamed to its number, so a part is either whole or not there.
//
// A part whose place in the object is known when it starts is written there
// instead, into `data` at its offset, and its numbered file is the header alone,
// naming that offset; the shard that owns the upload hands out each place once.
// A completion whose parts all sit where the object needs them writes the header
// in front and commits `data` as the object, so its bytes are written once.
// An upload exists once its meta file and directory are on the disk, which is
// before the client is told its id, and a crash leaves every acknowledged
// upload and part.  A start reads the directory to find them again.
//
// An upload is kept until it is completed or aborted, or until it has been open
// for the runtime's expiry when one is set.  Its parts count against the
// quota while they are held.
//
// Everything after open() is asynchronous on the runtime's ring, so a large
// assembly shows up as latency on the request that asked for it.
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "checksum.h"
#include "object_store.h"
#include "s3_auth.h"
#include "s3_multipart_xml.h"
#include "../../shared/event_loop.h"
#include "../../shared/file_io.h"

namespace socketley::storage
{

inline constexpr uint64_t mpu_min_part_bytes = 5ull << 20;
inline constexpr uint32_t mpu_max_parts      = 10000;

// The header entry of a part written into the upload's data file: where its bytes begin there.
inline constexpr std::string_view mpu_place_extra = "x-socketley-mpu-at";
// Fixed width, so the header's room is reserved before the part's offset is written into it.
std::string encode_place(uint64_t off);
// 0 when the meta names no place, which no part has since the object's header comes first.
uint64_t place_of(const object_meta& meta);

// Where a part's body goes when it is written into the upload's data file; off 0 is a file of its own.
struct part_place
{
    uint64_t    off{0};
    uint64_t    room{0};
    std::string path;
    // The upload's encryption record, which every part is sealed under whether or not it has a place; empty for none.
    std::string sse;
};

struct mpu_part
{
    uint32_t    number{0};
    uint64_t    size{0};
    md5_t       md5{};
    int64_t     mtime_ms{0};
    // Where the bytes begin in the part's file, or in the upload's data file when in_place.
    size_t      data_off{0};
    bool        in_place{false};
    // In the upload's algorithm, empty when it has none.
    std::string checksum_b64;

    std::string etag() const { return hex(md5); }
};

enum class mpu_state : uint8_t
{
    open,
    // Being completed: no part may start, and the ones in flight are waited for.
    sealed,
    // Being aborted or finished: it is not listed and is going away.
    removing,
};

struct mpu_upload
{
    std::string bucket;
    std::string id;
    std::string key;
    // What the finished object carries besides its bytes; its size and etag are made at the end.
    object_meta meta;
    int64_t     initiated_ms{0};
    checksum_algo algo{checksum_algo::none};
    std::map<uint32_t, mpu_part> parts;
    int         dir_fd{-1};
    mpu_state   state{mpu_state::open};
    // Bytes of parts counted against the quota.
    uint64_t    held{0};
    // Part commits in flight, which an abort or a completion waits out.
    uint32_t    committing{0};
    // A completion another shard is assembling: when it was sealed for that, so
    // an assembler that died leaves the upload open again after a while.
    bool        remote_sealed{false};
    int64_t     sealed_ms{0};
    std::function<void()> on_idle;
    // Commits of one part number wait behind each other, so the disk and the
    // list of parts end in the same state.
    std::map<uint32_t, std::vector<std::function<void()>>> lanes;
    // Parts written into the data file: where part 1 begins there (0 when the upload
    // has no data file), and the size the first part placed fixed for every other.
    uint64_t    place_base{0};
    uint64_t    place_size{0};
    // Every number ever given a place, since a place is written by one body only.
    std::set<uint32_t> placed;
    // Places given whose part has not been committed, with the room each was given.
    std::map<uint32_t, uint64_t> placing;
    // No place is given and no completion is made without a copy: a start or a failed
    // completion cannot know who may still write into the data file.
    bool        place_frozen{false};
    // The completion under way commits the data file itself.
    bool        place_planned{false};
};

struct complete_result
{
    // An empty code is success.
    s3_error    error;
    object_meta meta;
    // The checksum of the whole object, when the upload had an algorithm.
    std::string checksum_b64;
};

// What the assembly of a completed upload needs, decided against what the upload
// holds and so handed to whichever shard reads the parts and writes the object.
struct assemble_plan
{
    std::string bucket;
    std::string id;
    std::string key;
    // The object as it will be: size, ETag, parts and the composite checksum included.
    object_meta meta;
    std::string checksum_b64;
    std::vector<mpu_part> parts;
    // The parts are where the object needs them in the upload's data file, which
    // becomes the object once its header is written in front.
    bool        in_place{false};
};

// What a completion's assembler makes of the object's meta before its header is written; an error refuses it.
using complete_binder = std::function<s3_error(object_meta&)>;

// One page of an upload's parts, as ListParts answers it.
struct parts_page
{
    // no_such_key when the upload is missing or on its way out.
    st            status{st::ok};
    std::string   key;
    std::string   id;
    checksum_algo algo{checksum_algo::none};
    std::vector<part_row> rows;
    bool          truncated{false};
    uint32_t      next_marker{0};
};

struct mpu_totals
{
    uint64_t uploads{0};
    uint64_t parts{0};
    uint64_t bytes{0};
};

struct assemble_state;
struct part_commit;

class multipart_store
{
public:
    multipart_store(event_loop& loop, file_io& io, object_store& store);
    ~multipart_store();

    multipart_store(const multipart_store&)            = delete;
    multipart_store& operator=(const multipart_store&) = delete;

    // Finds the uploads a stop left, removes what a crash left half made and
    // counts what is held; blocking, and only ever called before serving.
    bool open(std::string& err);

    const mpu_upload* find(std::string_view bucket, std::string_view id) const;
    // The uploads of a bucket that are not being closed, in no particular order.
    std::vector<const mpu_upload*> uploads_of(std::string_view bucket) const;
    // Whether a bucket has any, which stops it being deleted.
    bool bucket_has_uploads(std::string_view bucket) const;
    mpu_totals totals() const;

    // The id is given to `cb` when st is ok.
    void create(std::string bucket, std::string key, object_meta meta, checksum_algo algo,
                std::function<void(st, std::string)> cb);

    // Whether a part may be started on this upload, and the algorithm its
    // checksum is taken with; no_such_key stands for an upload that is missing
    // or on its way out.
    st begin_part(std::string_view bucket, std::string_view id, checksum_algo& algo) const;
    // The same for an UploadPart of `expected` bytes (when `known`), which is given a
    // place in the data file in `place` when it can be written there, and is told
    // there what the upload's parts are sealed under.
    st begin_part(std::string_view bucket, std::string_view id, uint32_t number, uint64_t expected, bool known,
                  checksum_algo& algo, part_place& place);
    std::string data_path(std::string_view bucket, std::string_view id) const;

    // What a part's body is given, in place of the store's own commit: the file
    // is renamed into the upload and remembered.  `st::cancelled` reaches `done`
    // when the upload went away while the body was on its way in.
    put_op::committer part_committer(std::string bucket, std::string id, uint32_t number);

    // Makes one object of the parts a client lists, validated against what was
    // uploaded, and removes the upload once the object is committed.  `progress`
    // runs as the bytes move, so the caller can tell a slow assembly from a stuck one.
    void complete(std::string bucket, std::string id, std::vector<complete_part> parts,
                  std::function<void()> progress, std::function<void(complete_result)> cb,
                  complete_binder bind = {});

    // The two halves of `complete`, for a completion whose assembly runs on
    // another shard: this one validates the list against the upload and seals it,
    // the assembler makes the object from the plan, and this one is then told to
    // remove the upload or to open it again.
    void prepare_complete(std::string bucket, std::string id, std::vector<complete_part> parts,
                          std::function<void(s3_error, assemble_plan)> cb, bool remote = false);
    // Reads the plan's parts and commits the object through the store, so the
    // owner of the key is the one that renames it; the upload is not touched.
    void assemble_plan_object(assemble_plan plan, std::function<void()> progress,
                              std::function<void(complete_result)> cb, complete_binder bind = {});
    void finish_complete(std::string bucket, std::string id, bool ok);

    // The parts of an upload, `max_parts` of them after `marker`.
    parts_page list_parts(std::string_view bucket, std::string_view id, std::string_view key,
                          uint32_t marker, uint32_t max_parts) const;

    // Opens the completions whose assembler has not answered for `older_than_ms`.
    void unseal_stale(int64_t older_than_ms);

    // False when there was no such upload.  `cb` runs once its files are gone.
    bool abort(std::string_view bucket, std::string_view id, std::function<void()> cb);

    // Aborts the open uploads begun before `cutoff_ms`, and returns how many.
    size_t expire(int64_t cutoff_ms);

    // Completions whose part list was too long for the header and was written after the body.
    uint64_t trailers() const { return m_trailers; }

    // Whether anything is in flight, which a stop does not wait for but a test may.
    bool busy() const { return m_inflight != 0; }

private:
    using key_t = std::string;

    mpu_upload* find_mut(std::string_view bucket, std::string_view id);
    static key_t key_of(std::string_view bucket, std::string_view id);

    std::string base_of(std::string_view bucket) const;
    std::string upload_path(std::string_view bucket, std::string_view id) const;

    void lane_enter(std::string_view bucket, std::string_view id, uint32_t number, std::function<void()> run);
    void lane_leave(std::string_view bucket, std::string_view id, uint32_t number);
    void part_finished(std::string_view bucket, std::string_view id);

    void remove_upload(std::string bucket, std::string id, std::function<void()> cb);
    void remove_files(std::string bucket, std::string id, std::vector<uint32_t> parts, std::function<void()> cb);
    void forget(const std::string& bucket, const std::string& id);

    void run_part_commit(std::shared_ptr<part_commit> pc);
    void finish_part(const std::shared_ptr<part_commit>& pc, int64_t res, bool renamed);
    void assemble(std::shared_ptr<assemble_state> a);
    void assemble_copy(std::shared_ptr<assemble_state> a);
    void assemble_commit(const std::shared_ptr<assemble_state>& a);
    void assemble_fail(const std::shared_ptr<assemble_state>& a, st why);
    void assemble_fail(const std::shared_ptr<assemble_state>& a, s3_error why);
    // The upload is open again after a completion that did not finish.
    void reopen(mpu_upload& u);
    void assemble_pump(const std::shared_ptr<assemble_state>& a);
    void assemble_finish(const std::shared_ptr<assemble_state>& a);

    bool recover_bucket(const std::string& bucket, std::string& err);

    event_loop*  m_loop;
    file_io*     m_io;
    object_store* m_store;
    std::map<key_t, std::unique_ptr<mpu_upload>> m_uploads;
    std::shared_ptr<bool> m_alive;
    uint32_t     m_inflight{0};
    // The most a part list may take in a header before it is kept after the body, and how many have been.
    size_t       m_list_max{max_part_sizes_bytes};
    uint64_t     m_trailers{0};
};

}   // namespace socketley::storage
