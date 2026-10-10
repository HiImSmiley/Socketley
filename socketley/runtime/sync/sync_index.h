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
// ─── THE FILE ───────────────────────────────────────────────────────────────
// <state>/sync/<runtime>.index, 0600, "SKLSYNC2" and then records, the later winning:
//   u32 body length, u32 crc32 of the body, body
//   body: u8 kind, u16 + target, u16 + path, u64 size, i64 mtime_ns, u8 + etag
// Kind 'p' is carried, 'd' gone, and 's' the scope -- the directory and the prefix the records are of, first in the
// file; an index of another scope is begun again rather than read, since its paths name other objects.
// The file is written again from the live set once it has grown to twice it.
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

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
    // Writes the live set over the file once the dead records are as many as the live, or at once with `force`.
    bool compact(std::string& why, bool force = false);
    // Puts what was written on the disk, at the end of a walk and at a stop.
    void flush();

private:
    bool append(std::string_view body, std::string& why);
    bool write_fresh(std::string& why);

    std::string m_path;
    std::string m_scope;
    int         m_fd{-1};
    // The length of the file, so a write that went in short is cut back to the last whole record.
    uint64_t    m_size{0};
    index_map   m_live;
    // Records in the file, live and dead, so compaction can be decided without reading it again.
    size_t      m_records{0};
    bool        m_stale{false};
};

}   // namespace socketley::sync
