#pragma once
// The Sieve scripts of a mail runtime's users, files under its state that every shard reads: a user's scripts by
// name, the one active named beside them, the scripts every user may include, and what vacation answered and
// duplicate saw.  What ManageSieve and the CLI put is compiled first and refused with the error where it does not;
// the active script is compiled once per change of it or of what it includes, and handed to the delivery as it is.
// Every call may block on the disk, so callers make it from the pool; a change takes the user's lock, so two shards
// cannot pass a bound together.
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "mail_sieve.h"

namespace socketley::mail
{

class sieve_store
{
public:
    explicit sieve_store(std::string dir) : m_dir(std::move(dir)) {}

    // The bounds a user's scripts are kept within, as ManageSieve's HAVESPACE tells them.
    static constexpr size_t max_script = 64u << 10;
    static constexpr size_t max_scripts = 32;
    static constexpr size_t max_user = 1u << 20;
    // What vacation and duplicate remember for a user, the oldest let go past it.
    static constexpr size_t max_memory = 10000;

    // The user whose scripts are the ones :global includes, a name no login gives.
    static const std::string global_user;

    // A name a script may have: printable, no '/', at most 128 bytes.
    static bool name_ok(std::string_view name);

    // `user`'s scripts by name and whether each is the active one.
    std::vector<std::pair<std::string, bool>> list(const std::string& user) const;
    bool get(const std::string& user, const std::string& name, std::string& text) const;
    // Kept where it compiles; `why` says where it does not, or what a bound refused (`code` QUOTA, ... for it).
    bool put(const std::string& user, const std::string& name, std::string_view text, std::string& code,
             std::string& why);
    // Whether a script named `name` could be put, `size` bytes of it.
    bool fits(const std::string& user, const std::string& name, uint64_t size, std::string& code) const;
    bool remove(const std::string& user, const std::string& name, std::string& code, std::string& why);
    bool rename(const std::string& user, const std::string& from, const std::string& to, std::string& code,
                std::string& why);
    // `name` the active one, or none where it is empty; one that does not compile with what it includes is refused.
    bool activate(const std::string& user, const std::string& name, std::string& code, std::string& why);
    std::string active_name(const std::string& user) const;

    // The active script compiled, null where there is none or it no longer compiles; safe from any thread.
    std::shared_ptr<const sieve::script> active(const std::string& user);
    // The script `name` compiled, as imapsieve runs one a folder names; null where there is none.
    std::shared_ptr<const sieve::script> named(const std::string& user, const std::string& name);

    // Whether a vacation with `handle` answered `sender` for `user` within `seconds`; marks it answered when not, and
    // says it was where the memory cannot be read or written, so an unknown answers no one twice.
    bool answered(const std::string& user, const std::string& handle, const std::string& sender, uint32_t seconds,
                  int64_t now_s);
    // Whether duplicate kept `key` for `user` and it has not run out; and keeping it for `seconds` more.
    bool seen(const std::string& user, std::string_view key, int64_t now_s);
    void keep_seen(const std::string& user, std::string_view key, uint32_t seconds, int64_t now_s);

private:
    std::string user_dir(const std::string& user) const;
    std::string path_of(const std::string& user, const std::string& name) const;
    // The script text include asks for: the user's own, or one of global_user's.
    sieve::loader loader_for(const std::string& user) const;

    // A file's identity and its last change, which a rewrite in the same clock tick still moves.
    struct stamp
    {
        uint64_t ino{0}, size{0};
        int64_t mtime_ns{-1}, ctime_ns{-1};
        bool operator==(const stamp&) const = default;
    };
    static stamp stamp_of(const std::string& path);

    std::string m_dir;
    struct compiled
    {
        std::string name;
        stamp active_stamp;
        // The script and every one it included or asked for, as they were when it was compiled.
        std::vector<std::pair<std::string, stamp>> files;
        std::shared_ptr<const sieve::script> script;
    };
    // `c` compiled again where its script or one it includes changed since; under m_mu.
    std::shared_ptr<const sieve::script> fresh(compiled& c, const std::string& user, const char* what);
    // What one kind of memory of one user holds: each key's hash and when it runs out, read from its file up to
    // `read` bytes, the inode it was read from, and the lines the file holds past what is live.
    struct memory
    {
        std::unordered_map<std::string, int64_t> until;
        uint64_t ino{0}, read{0}, lines{0};
    };
    // Whether `key` is live in `kind`, after the lines other shards appended are read in; false with `ok` cleared
    // where the file cannot be read.
    bool recall(const std::string& user, const char* kind, const std::string& hash, int64_t now_s, bool& ok);
    bool remember(const std::string& user, const char* kind, const std::string& hash, int64_t until, int64_t now_s);
    memory& memory_of(const std::string& user, const char* kind);

    std::mutex m_mu;
    std::unordered_map<std::string, compiled> m_cache;
    std::unordered_map<std::string, compiled> m_named;
    std::unordered_map<std::string, memory> m_memory;
};

}   // namespace socketley::mail
