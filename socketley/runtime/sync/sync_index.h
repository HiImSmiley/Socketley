#pragma once
// What a sync last carried, so a file that has not changed is not carried again and one that is gone is known to
// have been there at all.
//
// Without this record a `--mode out` job cannot tell a file deleted here from a file never carried, and an `inout`
// job cannot tell a deletion on one side from a creation on the other. It is therefore written before the next
// change is begun, not at the end of a run: a sync killed halfway must not forget what it already carried.
//
// ─── THE FILE ───────────────────────────────────────────────────────────────
// <state>/sync/<runtime>.index, 0600, "SKLSYNC1" and then one record per change, the later record winning:
//   u8 kind ('p' carried, 'd' gone), u16 + target, u16 + path, u64 size, i64 mtime_ns, u8 + etag
// Appending rather than rewriting is what makes a crash cost one record and not the whole memory; the file is
// written again from the live set once it has grown to twice it.
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

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
    // Reads `path`, which need not exist; false with `why` for a file that is not one of these.
    bool open(std::string path, std::string& why);
    // The record of one file, nullptr when there is none.
    const index_entry* find(std::string_view target, std::string_view path) const;
    // Records that `path` is now carried; false with `why` when the record could not be written.
    bool carried(std::string_view target, std::string_view path, const index_entry& e, std::string& why);
    // Records that `path` is gone from the target.
    bool gone(std::string_view target, std::string_view path, std::string& why);

    const index_map& all() const { return m_live; }
    size_t size() const { return m_live.size(); }
    // Writes the live set over the file, dropping the records the appending left behind.
    bool compact(std::string& why);

private:
    bool append(char kind, std::string_view target, std::string_view path, const index_entry& e, std::string& why);

    std::string m_path;
    index_map   m_live;
    // Records in the file, live and dead, so compaction can be decided without reading it again.
    size_t      m_records{0};
};

}   // namespace socketley::sync
