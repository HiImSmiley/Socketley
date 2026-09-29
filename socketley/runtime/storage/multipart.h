#pragma once
// Multipart uploads of one storage runtime: the uploads that are open, the
// parts each holds, and the steps that create, complete and abort them.
//
// ─── LAYOUT ─────────────────────────────────────────────────────────────────
//   <dir>/<bucket>/mpu/<upload-id>/meta   the object-to-be, in an object header
//   <dir>/<bucket>/mpu/<upload-id>/<n>    part n: an object header, then its bytes
//
// A part is written like any object body, to a temporary file that is synced,
// and is then renamed to its number, so a part is either whole or not there.
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

struct mpu_part
{
    uint32_t    number{0};
    uint64_t    size{0};
    md5_t       md5{};
    int64_t     mtime_ms{0};
    // Where the bytes begin in the part's file.
    size_t      data_off{0};
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
    std::function<void()> on_idle;
    // Commits of one part number wait behind each other, so the disk and the
    // list of parts end in the same state.
    std::map<uint32_t, std::vector<std::function<void()>>> lanes;
};

struct complete_result
{
    // An empty code is success.
    s3_error    error;
    object_meta meta;
    // The checksum of the whole object, when the upload had an algorithm.
    std::string checksum_b64;
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

    // What a part's body is given, in place of the store's own commit: the file
    // is renamed into the upload and remembered.  `st::cancelled` reaches `done`
    // when the upload went away while the body was on its way in.
    put_op::committer part_committer(std::string bucket, std::string id, uint32_t number);

    // Makes one object of the parts a client lists, validated against what was
    // uploaded, and removes the upload once the object is committed.  `progress`
    // runs as the bytes move, so the caller can tell a slow assembly from a stuck one.
    void complete(std::string bucket, std::string id, std::vector<complete_part> parts,
                  std::function<void()> progress, std::function<void(complete_result)> cb);

    // False when there was no such upload.  `cb` runs once its files are gone.
    bool abort(std::string_view bucket, std::string_view id, std::function<void()> cb);

    // Aborts the open uploads begun before `cutoff_ms`, and returns how many.
    size_t expire(int64_t cutoff_ms);

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
    void assemble_pump(const std::shared_ptr<assemble_state>& a);
    void assemble_finish(const std::shared_ptr<assemble_state>& a);

    bool recover_bucket(const std::string& bucket, std::string& err);

    event_loop*  m_loop;
    file_io*     m_io;
    object_store* m_store;
    std::map<key_t, std::unique_ptr<mpu_upload>> m_uploads;
    std::shared_ptr<bool> m_alive;
    uint32_t     m_inflight{0};
};

}   // namespace socketley::storage
