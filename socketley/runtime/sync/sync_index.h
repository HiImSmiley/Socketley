#pragma once
// What a sync last carried, so a file that has not changed is not carried again and one that is gone is known to
// have been there at all.
//
// Without this record a `--mode out` job cannot tell a file deleted here from a file never carried, and an `inout`
// job cannot tell a deletion on one side from a creation on the other.
//
// A record lost is always safe: the file is carried again, or a removal is asked for again and answered 404. A
// record that claims what never happened is not: a file it says was carried is never sent. So every record carries
// a checksum and the first one that fails it ends the file, and nothing is synced to the disk per record -- a crash
// of the machine costs what the last moments carried, once more.
//
// With a ring attached the writes and syncs go through it, never on the loop: one write and one sync at a time, each
// sync covering every record written before it began, and a rewrite's bytes are synced there before it takes the
// index's name. Nothing waits for them,
// since a record is written only once what it records is on the disk (see sync_index.cpp).
//
// ─── THE FILE ───────────────────────────────────────────────────────────────
// <state>/sync/<runtime>.index, 0600, "SKLSYNC2" and then records, the later winning:
//   u32 body length, u32 crc32 of the body, body
//   body: u8 kind, u16 + target, u16 + path, u64 size, i64 mtime_ns, u8 + etag
// Kind 'p' is carried, 'd' gone, and 's' the scope -- the directory and the prefix the records are of, first in the
// file; an index of another scope is begun again rather than read, since its paths name other objects.
// The file is written again from the live set once it has grown to twice it.
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace socketley
{
class file_io;
}

namespace socketley::sync
{

// What one file looked like when it was last carried to one target.
struct index_entry
{
    uint64_t    size{0};
    int64_t     mtime_ns{0};
    std::string etag;
};

// The key of a record: which target, and which path below the directory.
struct index_key
{
    std::string target;
    std::string path;

    bool operator==(const index_key& o) const { return target == o.target && path == o.path; }
};

struct index_key_hash
{
    size_t operator()(const index_key& k) const
    {
        return std::hash<std::string>{}(k.target) * 1099511628211u ^ std::hash<std::string>{}(k.path);
    }
};

using index_map = std::unordered_map<index_key, index_entry, index_key_hash>;

class sync_index
{
public:
    // The longest path a record holds, which is PATH_MAX.
    static constexpr size_t max_path = 4096;

    sync_index() = default;
    ~sync_index();
    sync_index(const sync_index&)            = delete;
    sync_index& operator=(const sync_index&) = delete;

    // Reads `path`, which need not exist, for the job `scope` names; false with `why` for a file that is not one of
    // these or cannot be written. One of another scope is begun again.
    bool open(std::string path, std::string_view scope, std::string& why);
    // The record of one file, nullptr when there is none.
    const index_entry* find(std::string_view target, std::string_view path) const;
    // Records that `path` is now carried; false with `why` when the record could not be written.
    bool carried(std::string_view target, std::string_view path, const index_entry& e, std::string& why);
    // Records that `path` is gone from the target.
    bool gone(std::string_view target, std::string_view path, std::string& why);
    // Forgets every target not in `targets`, whose objects this job no longer answers for.
    void retain(const std::vector<std::string>& targets);

    const index_map& all() const { return m_live; }
    size_t size() const { return m_live.size(); }
    // Syncs and rewrites go through `io` from here on, and what goes wrong in one of them is told to `failed`; without
    // it they block, as a test's index does. Attached before open(), and `io` outlives every operation it was given.
    void attach(file_io& io, std::function<void(const std::string&)> failed);
    // Writes the live set over the file once the dead records are as many as the live, or at once with `force`. With a
    // ring the rewrite is begun here and takes the name once its bytes are synced; records written meanwhile go to the
    // old file and are carried into the new one.
    bool compact(std::string& why, bool force = false);
    // Begins a sync of what was written, which nothing waits for: at the end of a walk and at a stop.
    void flush();
    // Runs `then` once every record written so far is on the disk, with false when a sync of it failed; at once when
    // they already are.
    void when_durable(std::function<void(bool)> then);
    // Whether every record written so far is on the disk.
    bool durable() const { return m_synced >= m_written; }
    // A rewrite begun and not yet in place.
    bool rewriting() const { return m_rewrite != nullptr; }

private:
    struct held_fd;
    struct rewrite;

    bool append(std::string_view body, std::string& why);
    bool write_fresh(std::string& why);
    // The live set as the file begins: the magic, the scope and a record per entry.
    std::string snapshot() const;
    // A fresh file of `text` beside the index, which `fd` is left open on; false with `why`.
    bool write_beside(const std::string& text, int& fd, std::string& why) const;
    // The records queued behind the write in flight, written in one, when none is.
    void write_next();
    // The rewrite's next bytes written and synced in the ring.
    void rewrite_step();
    void rewrite_failed(const std::string& why);
    // Carries what was recorded meanwhile into the synced rewrite, or renames it over the index once nothing waits to
    // go in and no write or sync names the old file.
    void install();
    void drop_rewrite();
    // The next sync in the ring, when records that landed were asked to be synced and none is in flight.
    void sync_next();
    // A sync that covered the records up to `upto` ended.
    void synced(uint64_t upto, bool ok);
    // The blocking sync of a test's index: the file, and its directory when a rename is not yet on the disk.
    bool sync_here();
    void fail(const std::string& why);

    std::string m_path;
    std::string m_scope;
    std::shared_ptr<held_fd> m_file;
    // The index's directory, synced after a rename so the name points at the file whose records were synced.
    std::shared_ptr<held_fd> m_dir;
    bool        m_dir_dirty{false};
    file_io*    m_io{nullptr};
    std::function<void(const std::string&)> m_failed;
    // Records queued since open(), how many of them are in the file, and how many on the disk under the index's name;
    // and up to which a sync was asked for.
    uint64_t    m_written{0};
    uint64_t    m_landed{0};
    uint64_t    m_synced{0};
    uint64_t    m_sync_wanted{0};
    // Records queued behind the write in flight, with the ring.
    std::string m_buf;
    bool        m_writing{false};
    bool        m_syncing{false};
    std::vector<std::pair<uint64_t, std::function<void(bool)>>> m_waiting;
    // Shared with the operations that write and sync it.
    std::shared_ptr<rewrite> m_rewrite;
    // Bumped by open(), so a completion of an index opened again finds nothing of its own; the completions hold it
    // weakly, so one that comes after the index is gone does nothing.
    std::shared_ptr<uint64_t> m_gen{std::make_shared<uint64_t>(0)};
    // The length of the file with what is queued for it, so a write that went in short is cut back to the last whole
    // record and the next goes where the last ends.
    uint64_t    m_size{0};
    index_map   m_live;
    // Records in the file, live and dead, so compaction can be decided without reading it again.
    size_t      m_records{0};
    bool        m_stale{false};
};

}   // namespace socketley::sync
