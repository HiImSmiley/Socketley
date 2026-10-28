#include "type_registry.h"
#include "runtime_instance.h"

#include <cctype>
#include <deque>
#include <iterator>
#include <mutex>
#include <shared_mutex>
#include <string>

namespace
{

struct entry
{
    std::string           name;
    type_registry::factory make;
};

// A deque so a name's address never moves, because type_to_string hands the
// c_str() out past the lock.
std::deque<entry>& entries()
{
    static std::deque<entry> e;
    return e;
}

std::shared_mutex& registry_mutex()
{
    static std::shared_mutex m;
    return m;
}

// The same shape a runtime name has, because a type name travels the same
// command lines, state files and frames.
bool valid_type_name(std::string_view name)
{
    if (name.empty() || name.size() > 64 || name[0] == '.' || name[0] == '-')
        return false;
    for (char c : name)
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_')
            return false;
    return true;
}

// The built-in types by name, one table both directions are read from.
struct builtin_name
{
    runtime_type     type;
    std::string_view name;
};
constexpr builtin_name builtins[] = {
    {runtime_server, "server"},   {runtime_client, "client"}, {runtime_proxy, "proxy"},
    {runtime_cache, "cache"},     {runtime_storage, "storage"}, {runtime_dns, "dns"},
    {runtime_sync, "sync"},       {runtime_idp, "idp"},       {runtime_db, "db"},
    {runtime_mqtt, "mqtt"},       {runtime_mail, "mail"},     {runtime_tunnel, "tunnel"},
};

// Every built-in is below first_registered, so no registered type is handed a built-in's id.
static_assert(std::size(builtins) == type_registry::first_registered &&
              []
              {
                  for (const auto& b : builtins)
                      if (b.type >= type_registry::first_registered)
                          return false;
                  return true;
              }());

bool builtin_lookup(std::string_view name, runtime_type& out)
{
    for (const auto& b : builtins)
        if (b.name == name)
        {
            out = b.type;
            return true;
        }
    return false;
}

// The shared claim-or-find walk under an exclusive lock, because register and
// intern differ only in what they do to an entry that already exists.
enum class claim_mode : uint8_t { intern_only, register_once, adopt };

bool claim(std::string_view name, type_registry::factory make,
           claim_mode mode, runtime_type& out)
{
    if (builtin_lookup(name, out))
        return mode == claim_mode::intern_only && !make;
    if (!valid_type_name(name))
        return false;

    std::unique_lock lock(registry_mutex());
    auto& e = entries();

    for (size_t i = 0; i < e.size(); ++i)
    {
        if (e[i].name != name)
            continue;
        // A factory-less entry came from a replica map and may be upgraded
        // once; a second factory for one name is a programming error, except
        // where the daemon deliberately takes the name over.
        if (mode == claim_mode::register_once)
        {
            if (e[i].make)
                return false;
            e[i].make = std::move(make);
        }
        else if (mode == claim_mode::adopt)
        {
            e[i].make = std::move(make);
        }
        out = static_cast<runtime_type>(type_registry::first_registered + i);
        return true;
    }

    // The id is a uint8_t everywhere a runtime_type travels in this process.
    if (type_registry::first_registered + e.size() > 255)
        return false;

    out = static_cast<runtime_type>(type_registry::first_registered + e.size());
    e.push_back({std::string(name), std::move(make)});
    return true;
}

} // namespace

namespace type_registry
{

bool register_type(std::string_view name, factory make, runtime_type& out)
{
    if (!make)
        return false;
    return claim(name, std::move(make), claim_mode::register_once, out);
}

bool adopt(std::string_view name, factory make, runtime_type& out)
{
    if (!make)
        return false;
    return claim(name, std::move(make), claim_mode::adopt, out);
}

bool lookup(std::string_view name, runtime_type& out)
{
    if (builtin_lookup(name, out))
        return true;

    std::shared_lock lock(registry_mutex());
    auto& e = entries();
    for (size_t i = 0; i < e.size(); ++i)
    {
        if (e[i].name == name)
        {
            out = static_cast<runtime_type>(first_registered + i);
            return true;
        }
    }
    return false;
}

bool intern(std::string_view name, runtime_type& out)
{
    return claim(name, nullptr, claim_mode::intern_only, out);
}

std::unique_ptr<runtime_instance> make(runtime_type t, std::string_view name)
{
    factory f;
    {
        std::shared_lock lock(registry_mutex());
        auto& e = entries();
        const size_t i = static_cast<size_t>(t) - first_registered;
        if (t < first_registered || i >= e.size() || !e[i].make)
            return nullptr;
        f = e[i].make;
    }
    // Outside the lock, because a factory is caller code and may look a name
    // up while it builds.
    return f(name);
}

bool is_registered(runtime_type t)
{
    if (t < first_registered)
        return false;
    std::shared_lock lock(registry_mutex());
    return static_cast<size_t>(t) - first_registered < entries().size();
}

} // namespace type_registry

const char* type_to_string(runtime_type t)
{
    for (const auto& b : builtins)
        if (b.type == t)
            return b.name.data();

    std::shared_lock lock(registry_mutex());
    auto& e = entries();
    const size_t i = static_cast<size_t>(t) - type_registry::first_registered;
    if (i < e.size())
        return e[i].name.c_str();
    return "unknown";
}
