#include "lua_setup.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <filesystem>

#include "runtime_schema.h"
#include "type_manifest.h"
#include "../cli/command_hashing.h"
#include "../cli/runtime_type_parser.h"

namespace lua_setup
{

namespace
{

// What a value in a setup is allowed to be, which is also what it becomes on the command line.
enum class key_kind : uint8_t
{
    text,       // --flag <string>
    integer,    // --flag <whole number>
    number,     // --flag <number>
    scalar,     // --flag <string or number>, for values like 256M and 0-3
    boolean,    // --flag, emitted only when the value is true
    list,       // --flag a,b,c
    list_semi,  // --flag a;b;c
};

struct config_key
{
    std::string_view name;
    std::string_view flag;
    key_kind         kind;
};

// The keys a setup named before every flag had one, kept under those names; a flag this table does not name is a key
// of its own name, from the schema, so the two cannot drift apart.
constexpr config_key config_keys[] = {
    // ── Every type ──────────────────────────────────────────────────────────
    { "port",               "-p",                   key_kind::integer },
    { "bind",               "--bind",               key_kind::text    },
    { "listen",             "--listen",             key_kind::text    },
    { "shards",             "--shards",             key_kind::integer },
    { "log",                "--log",                key_kind::text    },
    { "write",              "-w",                   key_kind::text    },
    { "group",              "-g",                   key_kind::text    },
    { "cpus",               "--cpus",               key_kind::scalar  },
    { "max_connections",    "--max-connections",    key_kind::integer },
    { "rate_limit",         "--rate-limit",         key_kind::number  },
    { "global_rate_limit",  "--global-rate-limit",  key_kind::number  },
    // scalar, not integer: a duration key takes `300` or `"5m"`, and the
    // daemon's duration parser is the one judge of both spellings.
    { "idle_timeout",       "--idle-timeout",       key_kind::scalar  },
    { "write_buffer",       "--write-buffer",       key_kind::scalar  },
    { "read_buffer",        "--read-buffer",        key_kind::scalar  },
    { "drain",              "--drain",              key_kind::boolean },
    { "test",               "--test",               key_kind::boolean },
    { "tls",                "--tls",                key_kind::boolean },
    { "cert",               "--cert",               key_kind::text    },
    { "key",                "--key",                key_kind::text    },
    { "ca",                 "--ca",                 key_kind::text    },

    // ── Server ──────────────────────────────────────────────────────────────
    { "mode",               "--mode",               key_kind::text    },
    { "send_to",            "--send-to",            key_kind::text    },
    { "udp",                "--udp",                key_kind::boolean },
    { "http",               "--http",               key_kind::text    },
    { "http_cache",         "--http-cache",         key_kind::boolean },
    { "no_inject",          "--no-inject",          key_kind::boolean },
    { "master_pw",          "--master-pw",          key_kind::text    },
    // scalar, for a db's cache size as well as a server's cache runtime.
    { "cache",              "--cache",              key_kind::scalar  },
    { "upstreams",          "--upstream",           key_kind::list_semi },

    // ── Client ──────────────────────────────────────────────────────────────
    { "target",             "-t",                   key_kind::text    },

    // ── Proxy ───────────────────────────────────────────────────────────────
    { "backends",           "--backend",            key_kind::list    },
    { "protocol",           "--protocol",           key_kind::text    },
    { "strategy",           "--strategy",           key_kind::text    },
    { "health_check",       "--health-check",       key_kind::text    },
    { "health_interval",    "--health-interval",    key_kind::scalar  },
    { "health_path",        "--health-path",        key_kind::text    },
    { "health_threshold",   "--health-threshold",   key_kind::integer },
    { "circuit_threshold",  "--circuit-threshold",  key_kind::integer },
    { "circuit_timeout",    "--circuit-timeout",    key_kind::scalar  },
    { "backend_timeout",    "--backend-timeout",    key_kind::scalar  },
    { "retry",              "--retry",              key_kind::integer },
    { "retry_all",          "--retry-all",          key_kind::boolean },
    { "client_ca",          "--client-ca",          key_kind::text    },
    { "client_cert",        "--client-cert",        key_kind::text    },
    { "client_key",         "--client-key",         key_kind::text    },
    { "sidecar",            "--sidecar",            key_kind::boolean },
    { "auth",               "--auth",               key_kind::text    },
    { "redirect_https",     "--redirect-https",     key_kind::integer },

    // ── Cache ───────────────────────────────────────────────────────────────
    { "persistent",         "--persistent",         key_kind::text    },
    { "persistent_interval","--persistent-interval",key_kind::scalar  },
    { "maxmemory",          "--maxmemory",          key_kind::scalar  },
    { "eviction",           "--eviction",           key_kind::text    },
    { "resp",               "--resp",               key_kind::boolean },
    { "replicate",          "--replicate",          key_kind::text    },
    { "cluster",            "--cluster",            key_kind::boolean },
    { "public",             "--public",             key_kind::boolean },

    // ── Storage ─────────────────────────────────────────────────────────────
    { "dir",                "--dir",                key_kind::text    },
    { "anonymous",          "--anonymous",          key_kind::boolean },
    { "acls",               "--acls",               key_kind::boolean },
    { "max_bytes",          "--max-bytes",          key_kind::scalar  },
    { "access_key",         "--access-key",         key_kind::text    },
    { "secret_key",         "--secret-key",         key_kind::text    },
    { "credentials",        "--credentials",        key_kind::text    },
    { "sse_key_file",       "--sse-key-file",       key_kind::text    },
    // A list, as a proxy names several; one name is the list of one.
    { "domain",             "--domain",             key_kind::list    },
    { "website_domain",     "--website-domain",     key_kind::text    },
    { "notify_targets",     "--notify-targets",     key_kind::text    },
    { "replication_targets", "--replication-targets", key_kind::text   },
    { "tiers",              "--tiers",              key_kind::text    },
    { "federation",         "--federation",         key_kind::text    },
    { "tls_offloaded",      "--tls-offloaded",      key_kind::text    },
    { "nodes",              "--nodes",              key_kind::text    },
    { "fsync",              "--fsync",              key_kind::text    },
    { "sync",               "--sync",               key_kind::text    },
    { "fsync_interval",     "--fsync-interval",     key_kind::scalar  },
    { "mpu_expire",         "--mpu-expire",         key_kind::scalar  },
    { "scrub",              "--scrub",              key_kind::scalar  },
    { "compress",           "--compress",           key_kind::scalar  },

    // ── DNS ─────────────────────────────────────────────────────────────────
    { "zone",               "--zone",               key_kind::list    },
    { "transfer",           "--transfer",           key_kind::list    },
    { "notify",             "--notify",             key_kind::list    },
    { "publish",            "--publish",            key_kind::list    },
    { "proxy",              "--proxy",              key_kind::text    },
    { "rrl",                "--rrl",                key_kind::integer },

    // ── sync ────────────────────────────────────────────────────────────────
    // dir, credentials and mode are above, shared with the storage and the server's; a mail runtime's one storage is
    // the list of one.
    { "storage",            "--storage",            key_kind::list    },
    { "prefix",             "--prefix",             key_kind::text    },
    { "exclude",            "--exclude",            key_kind::list    },
    { "repositories",       "--repositories",       key_kind::text    },
    { "every",              "--every",              key_kind::scalar  },

    // ── idp ─────────────────────────────────────────────────────────────────
    { "clients",            "--clients",            key_kind::text    },
    { "issuer",             "--issuer",             key_kind::text    },
    { "cookie_domain",      "--cookie-domain",      key_kind::text    },
    { "resources",          "--resources",          key_kind::text    },
    { "ssh_ca",             "--ssh-ca",             key_kind::integer },
    // ── tunnel ──────────────────────────────────────────────────────────────
    { "to",                 "--to",                 key_kind::text    },
    { "join",               "--join",               key_kind::text    },
    { "offer",              "--offer",              key_kind::text    },
    { "forward",            "--forward",            key_kind::text    },
    { "idp",                "--idp",                key_kind::text    },
    { "idp_audience",       "--idp-audience",       key_kind::text    },
    // ── db ──────────────────────────────────────────────────────────────────
    // cache and replicate are above, shared with the server's and the cache's.
    { "schema",             "--schema",             key_kind::text    },
    { "keys",               "--keys",               key_kind::text    },
    { "origins",            "--origins",            key_kind::text    },
    { "replicate_key",      "--replicate-key",      key_kind::text    },
    { "backup_dir",         "--backup-dir",         key_kind::text    },
    { "backup_every",       "--backup-every",       key_kind::scalar  },
    { "backup_keep",        "--backup-keep",        key_kind::integer },
    // ── mqtt ────────────────────────────────────────────────────────────────
    // idp, anonymous, persistent and persistent_interval are above, shared with the storage's and the cache's.
    { "users",              "--users",              key_kind::text    },
    { "acl",                "--acl",                key_kind::text    },
    { "routes",             "--routes",             key_kind::text    },
    { "ws",                 "--ws",                 key_kind::integer },
    { "max_packet",         "--max-packet",         key_kind::scalar  },
    { "session_expiry",     "--session-expiry",     key_kind::scalar  },
    { "session_queue",      "--session-queue",      key_kind::integer },
    { "retained_max",       "--retained-max",       key_kind::scalar  },
    { "max_sessions",       "--max-sessions",       key_kind::integer },
    { "keepalive_max",      "--keepalive-max",      key_kind::integer },
};

const config_key* table_row_of_flag(std::string_view flag)
{
    for (const config_key& k : config_keys)
        if (k.flag == flag)
            return &k;
    return nullptr;
}

// A flag's key where the table names none: its name without the dashes, a hyphen an underscore.
std::string derived_key(std::string_view flag)
{
    std::string k(flag.substr(flag.starts_with("--") ? 2 : 1));
    std::replace(k.begin(), k.end(), '-', '_');
    return k;
}

key_kind kind_of(std::string_view schema_kind)
{
    if (schema_kind == "int")
        return key_kind::integer;
    if (schema_kind == "switch" || schema_kind == "bool")
        return key_kind::boolean;
    if (schema_kind == "duration" || schema_kind == "size")
        return key_kind::scalar;
    if (schema_kind == "list")
        return key_kind::list;
    return key_kind::text;
}


}   // namespace

bool volatile_key(std::string_view key)
{
    static constexpr std::string_view keys[] = {"name", "id", "type", "was_running", "owner", "pid", "shard_index",
                                                "mesh_wired", "managed", "exec_path", "child_policy", "companion_path",
                                                "external_runtime", "cluster_replica"};
    return std::find(std::begin(keys), std::end(keys), key) != std::end(keys);
}

std::vector<std::pair<std::string, socketley::json::jvalue>> settings_of(const socketley::json::jvalue& state,
                                                                        runtime_type type,
                                                                        std::vector<std::string>& unmapped)
{
    using socketley::json::jvalue;
    std::vector<std::pair<std::string, jvalue>> out;
    const auto flags = runtime_schema::flags_for(type);
    std::string bash;
    for (const auto& [key, v] : state.members)
    {
        if (volatile_key(key) || v.k == jvalue::kind::null)
            continue;
        // A client's printing is one key of the letters it prints with.
        if (key == "bash_output" || key == "bash_prefix" || key == "bash_timestamp")
        {
            if (v.k == jvalue::kind::boolean && v.b)
                bash += key == "bash_output" ? "b" : key == "bash_prefix" ? "p" : "t";
            continue;
        }
        const auto f = std::find_if(flags.begin(), flags.end(), [&](const auto& e) { return e.state_key == key; });
        if (f == flags.end())
        {
            unmapped.push_back(key);
            continue;
        }
        std::string name;
        key_kind kind = kind_of(f->kind);
        if (f->flag == "--lua")
            name = "lua";
        else if (f->flag == "--reconnect")
            name = "reconnect";
        else if (const config_key* row = table_row_of_flag(f->flag))
        {
            name = std::string(row->name);
            kind = row->kind;
        }
        else
            name = derived_key(f->flag);
        // A switch that is off, a text that is empty and a list of none say nothing a setup has to.
        if ((v.k == jvalue::kind::boolean && !v.b && kind == key_kind::boolean) ||
            (v.k == jvalue::kind::string && v.s.empty()) || (v.k == jvalue::kind::array && v.items.empty()))
            continue;
        jvalue value = v;
        // A list the state keeps as one string of its entries is a table of them.
        if ((kind == key_kind::list || kind == key_kind::list_semi) && v.k == jvalue::kind::string)
        {
            value = jvalue{};
            value.k = jvalue::kind::array;
            const char sep = kind == key_kind::list ? ',' : ';';
            for (std::string_view rest = v.s; !rest.empty();)
            {
                const size_t at = rest.find(sep);
                jvalue item;
                item.k = jvalue::kind::string;
                item.s = std::string(rest.substr(0, at));
                if (!item.s.empty())
                    value.items.push_back(std::move(item));
                rest = at == std::string_view::npos ? std::string_view{} : rest.substr(at + 1);
            }
        }
        out.emplace_back(std::move(name), std::move(value));
    }
    // A dns runtime that says no entrance keeps none, and one a setup says nothing of is given its own.
    if (type == runtime_dns && !socketley::json::member(state, "proxy"))
    {
        jvalue none;
        none.k = jvalue::kind::string;
        none.s = "none";
        out.emplace_back("proxy", std::move(none));
    }
    if (!bash.empty())
    {
        jvalue b;
        b.k = jvalue::kind::string;
        b.s = bash;
        out.emplace_back("bash", std::move(b));
    }
    return out;
}

std::string lua_literal(const socketley::json::jvalue& v)
{
    using socketley::json::jvalue;
    switch (v.k)
    {
        case jvalue::kind::null: return "nil";
        case jvalue::kind::boolean: return v.b ? "true" : "false";
        case jvalue::kind::number: return v.s;
        case jvalue::kind::string:
        {
            std::string out = "\"";
            for (const char ch : v.s)
            {
                const auto u = static_cast<unsigned char>(ch);
                if (ch == '"' || ch == '\\')
                    out += {'\\', ch};
                else if (ch == '\n')
                    out += "\\n";
                else if (u < 32 || u == 127)
                {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\%03u", u);
                    out += buf;
                }
                else
                    out += ch;
            }
            return out + "\"";
        }
        case jvalue::kind::array:
        {
            std::string out = "{";
            for (size_t i = 0; i < v.items.size(); ++i)
                out += (i ? ", " : " ") + lua_literal(v.items[i]) + (i + 1 == v.items.size() ? " " : "");
            return out + "}";
        }
        case jvalue::kind::object:
        {
            std::string out = "{";
            bool first = true;
            for (const auto& [k, m] : v.members)
            {
                out += (first ? " " : ", ") + k + " = " + lua_literal(m);
                first = false;
            }
            return out + (first ? "}" : " }");
        }
    }
    return "nil";
}

#ifndef SOCKETLEY_NO_LUA

namespace
{

// Flags that are keys of another shape, beside the table: the script, a client's reconnect, its printing, and start.
constexpr std::string_view special_flags[] = {"--lua", "--reconnect"};

bool special_flag(std::string_view flag)
{
    return std::find(std::begin(special_flags), std::end(special_flags), flag) != std::end(special_flags);
}


// Keys with no flag of their own, listed so an unknown key can still be refused by name.
constexpr std::string_view special_keys[] = {
    "type", "name", "config", "lua", "bash", "start", "reconnect", "daemon_process",
};


// The keys a runtime of `type` takes beside the table's: one for each flag of the schema the table has no row for.
std::vector<config_key> schema_keys(runtime_type type, std::vector<std::string>& names)
{
    std::vector<config_key> out;
    const auto flags = runtime_schema::flags_for(type);
    names.reserve(flags.size());
    for (const auto& f : flags)
        if (!special_flag(f.flag) && !table_row_of_flag(f.flag) && f.flag.starts_with("--"))
            names.push_back(derived_key(f.flag));
    size_t i = 0;
    for (const auto& f : flags)
        if (!special_flag(f.flag) && !table_row_of_flag(f.flag) && f.flag.starts_with("--"))
            out.push_back({names[i++], f.flag, kind_of(f.kind)});
    return out;
}


// %.10g rather than std::to_string, which writes a rate of 1.5 as 1.500000 and
// would put six digits of noise into every command the daemon logs.
std::string number_to_text(double v)
{
    char buf[32];
    // A whole number below 2^53 is exact in a double, and %.10g would round it above ten digits.
    const bool whole = v == std::floor(v) && std::fabs(v) < 9007199254740992.0;
    std::snprintf(buf, sizeof buf, whole ? "%.0f" : "%.10g", v);
    return buf;
}

// A space travels inside its argument, a tab does not, so a value with one would arrive as two arguments.
std::string refuse_whitespace(std::string_view key, const std::string& value)
{
    if (value.find('\t') == std::string::npos)
        return {};
    return std::string(key) + ": a value cannot contain a tab, because the "
           "daemon's command line splits on it (\"" + value + "\")\n";
}

// A relative path is one beside the setup's first file, wherever the command that reads it was typed.
std::string beside(const std::string& base, std::string_view flag, const std::string& value)
{
    const bool path = runtime_schema::is_path_flag(flag) || flag == "--lua" ||
                      (flag == "--zone" && value.find('/') != std::string::npos);
    if (!path || value.empty() || value.front() == '/')
        return value;
    return (std::filesystem::path(base) / value).lexically_normal().string();
}

// One key, appended to the words or refused with the reason, nothing where the key is absent.
std::string emit_key(const config_key& key, const sol::table& entry, const std::string& base,
                     std::vector<std::string>& words)
{
    const sol::object obj = entry[key.name];
    if (!obj.valid() || obj == sol::nil)
        return {};

    const std::string name(key.name);

    switch (key.kind)
    {
        case key_kind::boolean:
        {
            if (obj.get_type() != sol::type::boolean)
                return name + ": expected true or false\n";
            if (obj.as<bool>())
                words.emplace_back(key.flag);
            return {};
        }

        case key_kind::integer:
        case key_kind::number:
        {
            if (obj.get_type() != sol::type::number)
                return name + ": expected a number\n";
            const double v = obj.as<double>();
            if (key.kind == key_kind::integer && v != std::floor(v))
                return name + ": expected a whole number\n";
            words.emplace_back(key.flag);
            words.push_back(number_to_text(v));
            return {};
        }

        case key_kind::text:
        case key_kind::scalar:
        {
            std::string value;
            if (obj.get_type() == sol::type::string)
                value = obj.as<std::string>();
            else if (key.kind == key_kind::scalar && obj.get_type() == sol::type::number)
                value = number_to_text(obj.as<double>());
            else if (key.kind == key_kind::scalar)
                return name + ": expected a string or a number\n";
            else
                return name + ": expected a string\n";

            if (value.empty())
                return name + ": the value is empty\n";
            std::string resolved = beside(base, key.flag, value);
            if (std::string why = refuse_whitespace(key.name, resolved); !why.empty())
                return why;

            words.emplace_back(key.flag);
            words.push_back(std::move(resolved));
            return {};
        }

        case key_kind::list:
        case key_kind::list_semi:
        {
            const char sep = key.kind == key_kind::list ? ',' : ';';
            std::vector<std::string> values;
            // One entry may be written as itself rather than as the list of one.
            if (obj.get_type() == sol::type::string)
                values.push_back(obj.as<std::string>());
            else if (obj.get_type() != sol::type::table)
                return name + ": expected a list of strings\n";
            else
            {
                const sol::table t = obj.as<sol::table>();
                for (size_t i = 1; i <= t.size(); ++i)
                {
                    const sol::object e = t[i];
                    if (e.get_type() != sol::type::string)
                        return name + ": every entry has to be a string\n";
                    values.push_back(e.as<std::string>());
                }
            }

            std::string joined;
            for (const std::string& value : values)
            {
                if (value.empty())
                    return name + ": an entry is empty\n";
                const std::string resolved = beside(base, key.flag, value);
                if (std::string why = refuse_whitespace(key.name, resolved); !why.empty())
                    return why;
                // An entry holding the separator would arrive as two.
                if (resolved.find(sep) != std::string::npos)
                    return name + ": an entry cannot hold '" + std::string(1, sep) + "', which separates the list (\"" +
                           resolved + "\")\n";
                if (!joined.empty())
                    joined += sep;
                joined += resolved;
            }

            // An empty list is the operator asking for nothing rather than for
            // a flag with no value, which the daemon would refuse.
            if (!joined.empty())
            {
                words.emplace_back(key.flag);
                words.push_back(std::move(joined));
            }
            return {};
        }
    }

    return {};
}

// The keys with no straightforward flag: an alias, a tri-state, a value that
// may be a bool or a number, and one key that is refused outright.
std::string emit_special_keys(const sol::table& entry, const std::string& base, std::vector<std::string>& words,
                              int& start)
{
    // `daemon_process` is refused rather than ignored, for either value,
    // because a key that means nothing still implies this build has an
    // opinion about it.
    if (entry["daemon_process"].valid())
        return "daemon_process is no longer a setting: every runtime runs in "
               "its own process. Remove the line.\n";

    // Two spellings of the handler script, because a file naming both means two different scripts and only one can run.
    {
        const sol::object cfg = entry["config"];
        const sol::object lua = entry["lua"];
        const bool has_cfg = cfg.valid() && cfg != sol::nil;
        const bool has_lua = lua.valid() && lua != sol::nil;

        if (has_cfg && has_lua)
            return "config and lua are two spellings of one key: name the "
                   "handler script once\n";

        if (has_cfg || has_lua)
        {
            const sol::object& obj = has_cfg ? cfg : lua;
            if (obj.get_type() != sol::type::string)
                return "config: expected a string\n";
            const std::string value = obj.as<std::string>();
            if (value.empty())
                return "config: the value is empty\n";
            if (std::string why = refuse_whitespace("config", value); !why.empty())
                return why;
            words.emplace_back("--lua");
            words.push_back(beside(base, "--lua", value));
        }
    }

    // Infinite when true and bounded when a number, which is the flag's own
    // shape: --reconnect alone means keep trying.
    {
        const sol::object obj = entry["reconnect"];
        if (obj.valid() && obj != sol::nil)
        {
            if (obj.get_type() == sol::type::boolean)
            {
                if (obj.as<bool>())
                    words.emplace_back("--reconnect");
            }
            else if (obj.get_type() == sol::type::number)
            {
                const double v = obj.as<double>();
                if (v != std::floor(v) || v < 0)
                    return "reconnect: expected true or a count of attempts\n";
                words.emplace_back("--reconnect");
                words.push_back(number_to_text(v));
            }
            else
            {
                return "reconnect: expected true or a count of attempts\n";
            }
        }
    }

    {
        const sol::object obj = entry["bash"];
        if (obj.valid() && obj != sol::nil)
        {
            if (obj.get_type() != sol::type::string)
                return "bash: expected a string\n";

            bool prefix = false;
            bool stamp = false;
            for (const char c : obj.as<std::string>())
            {
                if (c == 'p')
                    prefix = true;
                else if (c == 't')
                    stamp = true;
                else if (c != 'b')
                    return "bash: expected b, p, t or a combination\n";
            }
            words.emplace_back(prefix && stamp ? "-bpt" : prefix ? "-bp" : stamp ? "-bt" : "-b");
        }
    }

    {
        const sol::object obj = entry["start"];
        if (obj.valid() && obj != sol::nil)
        {
            if (obj.get_type() != sol::type::boolean)
                return "start: expected true or false\n";
            start = obj.as<bool>() ? 1 : 0;
        }
    }

    return {};
}

// A key nobody handles is a typo, and a typo used to configure nothing while
// the runtime came up looking correct.
std::string refuse_unknown_keys(const sol::table& entry, const std::vector<config_key>& extra,
                                const type_manifest::manifest* man)
{
    for (auto& pair : entry)
    {
        if (pair.first.get_type() != sol::type::string)
            return "a runtime entry takes named keys, not a list\n";

        const std::string name = pair.first.as<std::string>();
        bool known = std::any_of(std::begin(config_keys), std::end(config_keys), [&](const config_key& k) { return k.name == name; }) ||
                     std::any_of(std::begin(special_keys), std::end(special_keys), [&](std::string_view k) { return k == name; }) ||
                     std::any_of(extra.begin(), extra.end(), [&](const config_key& k) { return k.name == name; });

        // A registered type's manifest schema is part of the key set, held to
        // the same rule as the table above.
        if (!known && man)
            for (const auto& sk : man->schema)
                if (sk.name == name) { known = true; break; }

        if (!known)
            return "unknown key: " + name + "\n";
    }

    return {};
}

// A registered type's schema keys through the same emit_key the table rows
// take, one synthesized row each -- except a bool, which is emitted with an
// explicit value because omitting it must mean "take the manifest's default"
// rather than "false".
std::string emit_manifest_keys(const type_manifest::manifest& man, const sol::table& entry, const std::string& base,
                               std::vector<std::string>& words)
{
    for (const auto& sk : man.schema)
    {
        const std::string flag = "--" + sk.name;

        if (sk.kind == type_manifest::key_kind::bool_key)
        {
            const sol::object obj = entry[sk.name];
            if (!obj.valid() || obj == sol::nil)
                continue;
            if (obj.get_type() != sol::type::boolean)
                return sk.name + ": expected true or false\n";
            words.push_back(flag);
            words.emplace_back(obj.as<bool>() ? "true" : "false");
            continue;
        }

        const key_kind kind = sk.kind == type_manifest::key_kind::int_key
                                  ? key_kind::integer
                                  : key_kind::text;
        const config_key row{sk.name, flag, kind};
        if (std::string why = emit_key(row, entry, base, words); !why.empty())
            return why;
    }

    return {};
}

// The whole entry, the table's keys first and then the schema's, so two runs of one file produce the same command,
// the first refusal ending it because a half-built command configures something nobody asked for.
void build(runtime_entry& e, runtime_type type, const sol::table& entry, const std::string& base)
{
    const type_manifest::manifest* man = type_manifest::find(type);
    std::vector<std::string> names;
    const std::vector<config_key> extra = schema_keys(type, names);
    if (std::string why = refuse_unknown_keys(entry, extra, man); !why.empty())
    {
        e.refused = why;
        return;
    }
    std::vector<std::string>& words = e.create;
    words = {"create", e.type, e.name};
    for (const config_key& key : config_keys)
        if (std::string why = emit_key(key, entry, base, words); !why.empty())
        {
            e.refused = why;
            return;
        }
    for (const config_key& key : extra)
        if (std::string why = emit_key(key, entry, base, words); !why.empty())
        {
            e.refused = why;
            return;
        }
    if (man)
        if (std::string why = emit_manifest_keys(*man, entry, base, words); !why.empty())
        {
            e.refused = why;
            return;
        }
    if (std::string why = emit_special_keys(entry, base, words, e.start); !why.empty())
        e.refused = why;
}

void flatten(const sol::table& list, const std::string& base, std::vector<runtime_entry>& out, int depth)
{
    for (size_t i = 1; i <= list.size(); ++i)
    {
        const sol::object item = list[i];
        runtime_entry e;
        if (item.get_type() != sol::type::table)
        {
            e.refused = "every entry in `runtimes` is a table with a name and a type\n";
            out.push_back(std::move(e));
            continue;
        }
        const sol::table t = item.as<sol::table>();
        // A list among the entries, as an include of a directory gives, is its entries.
        const sol::object first = t[1];
        if (first.valid() && first != sol::nil && depth < 16)
        {
            flatten(t, base, out, depth + 1);
            continue;
        }
        // sol::optional like every other field below, because a plain std::string read converts whatever is there in
        // Release rather than throwing on a misspelled key.
        const auto type_opt = t["type"].get<sol::optional<std::string>>();
        const auto name_opt = t["name"].get<sol::optional<std::string>>();
        if (!name_opt || name_opt->empty())
        {
            e.refused = "runtime entry without a name: every entry in `runtimes` needs name and type\n";
            out.push_back(std::move(e));
            continue;
        }
        e.name = *name_opt;
        runtime_type type;
        if (!type_opt || type_opt->empty())
            e.refused = "it has no type (server, client, proxy, cache, storage, dns, sync, idp, db, mqtt, mail, "
                        "tunnel, or a registered type)\n";
        else if (e.type = *type_opt; !parse_runtime_type(e.type.c_str(), type))
            e.refused = "unknown runtime type: " + e.type + "\n";
        else
            build(e, type, t, base);
        out.push_back(std::move(e));
    }
}

}   // namespace

void open(sol::state& lua, const std::string& top)
{
    // string and math are open because a setup builds names and port numbers, while os and io stay shut: this file
    // describes runtimes and reaching the filesystem from it is a second thing to review.
    lua.open_libraries(sol::lib::base, sol::lib::package, sol::lib::table, sol::lib::string, sol::lib::math);
    const std::string base = std::filesystem::path(top).parent_path().string();
    // include(path): the value a file returns, or a list of each .lua's of a directory, read in name order.
    lua.set_function("include", [base](sol::this_state ts, const std::string& path) -> sol::object {
        sol::state_view l(ts);
        const std::filesystem::path p = path.starts_with("/") ? std::filesystem::path(path)
                                                              : std::filesystem::path(base) / path;
        const auto run = [&l](const std::filesystem::path& file) -> sol::object {
            sol::load_result chunk = l.load_file(file.string());
            if (!chunk.valid())
            {
                const sol::error err = chunk;
                throw sol::error(err.what());
            }
            sol::protected_function_result r = chunk.get<sol::protected_function>()();
            if (!r.valid())
            {
                const sol::error err = r;
                throw sol::error(err.what());
            }
            return r.get<sol::object>();
        };
        std::error_code ec;
        if (!std::filesystem::is_directory(p, ec))
            return run(p);
        std::vector<std::filesystem::path> files;
        std::filesystem::directory_iterator dir(p, ec);
        if (ec)
            throw sol::error("include: cannot read " + p.string() + ": " + ec.message());
        for (const auto& f : dir)
            if (f.path().extension() == ".lua")
                files.push_back(f.path());
        std::sort(files.begin(), files.end());
        sol::table list = l.create_table();
        for (const auto& f : files)
            list.add(run(f));
        return list;
    });
}

std::vector<runtime_entry> runtimes(sol::state& lua, const std::string& top, std::string& why)
{
    std::vector<runtime_entry> out;
    // Its type asked first: a reference that is valid() may still be a number or a string, which Release reads as a
    // table without a word.
    const sol::object obj = lua["runtimes"];
    if (!obj.valid() || obj.get_type() == sol::type::lua_nil)
        return out;
    if (obj.get_type() != sol::type::table)
    {
        why = "`runtimes` is a list of tables, one per runtime\n";
        return out;
    }
    flatten(obj.as<sol::table>(), std::filesystem::path(top).parent_path().string(), out, 0);
    return out;
}

#endif

}   // namespace lua_setup
