#pragma once
// The Sieve scripts of a mail runtime's users, files under its state that every shard reads: a user's scripts by
// name, the one active named beside them, and whom a vacation answered when.  What ManageSieve and the CLI put is
// compiled first and refused with the error where it does not; the active script is compiled once per change and
// handed to the delivery as it is.
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

    // A name a script may have: printable, no '/', at most 128 bytes.
    static bool name_ok(std::string_view name);

    // `user`'s scripts by name and whether each is the active one.
    std::vector<std::pair<std::string, bool>> list(const std::string& user) const;
    bool get(const std::string& user, const std::string& name, std::string& text) const;
    // Kept where it compiles; `why` says where it does not, or what a bound refused (`code` QUOTA, ... for it).
    bool put(const std::string& user, const std::string& name, std::string_view text, std::string& code,
             std::string& why);
    // Whether `size` more bytes of a script named `name` would fit.
    bool fits(const std::string& user, const std::string& name, uint64_t size, std::string& code) const;
    bool remove(const std::string& user, const std::string& name, std::string& code, std::string& why);
    bool rename(const std::string& user, const std::string& from, const std::string& to, std::string& code,
                std::string& why);
    // `name` the active one, or none where it is empty.
    bool activate(const std::string& user, const std::string& name, std::string& code, std::string& why);
    std::string active_name(const std::string& user) const;

    // The active script compiled, null where there is none or it no longer compiles; safe from any thread.
    std::shared_ptr<const sieve::script> active(const std::string& user);

    // Whether a vacation with `handle` answered `sender` for `user` within `seconds`; marks it answered when not.
    bool answered(const std::string& user, const std::string& handle, const std::string& sender, uint32_t seconds,
                  int64_t now_s);

private:
    std::string user_dir(const std::string& user) const;
    std::string path_of(const std::string& user, const std::string& name) const;

    std::string m_dir;
    struct compiled
    {
        std::string name;
        int64_t mtime_ns{-1};
        int64_t active_mtime_ns{-1};
        std::shared_ptr<const sieve::script> script;
    };
    std::mutex m_mu;
    std::unordered_map<std::string, compiled> m_cache;
};

}   // namespace socketley::mail
