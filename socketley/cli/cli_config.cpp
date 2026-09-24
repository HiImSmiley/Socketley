#include "cli.h"
#include <cmath>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <string>
#include <sol/sol.hpp>

#include "runtime_type_parser.h"
#include "ipc_client.h"
#include "command_hashing.h"
#include "../daemon/type_manifest.h"
#include "../shared/paths.h"

namespace {

// What a value in a configuration is allowed to be, which is also what it
// becomes on the command line.
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

// Every flag a create accepts, one row each, because the two sets drifting
// apart is the whole defect this table exists to close: a key this file did
// not name used to be dropped in silence, and the health-check, circuit,
// retry and TLS families could not be reached from a configuration at all.
// Keys the daemon has no flag for are handled beside the table, not in it.
constexpr config_key config_keys[] = {
    // ── Every type ──────────────────────────────────────────────────────────
    { "port",               "-p",                   key_kind::integer },
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
    { "master_pw",          "--master-pw",          key_kind::text    },
    { "cache",              "--cache",              key_kind::text    },
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

    // ── Cache ───────────────────────────────────────────────────────────────
    { "persistent",         "--persistent",         key_kind::text    },
    { "persistent_interval","--persistent-interval",key_kind::scalar  },
    { "maxmemory",          "--maxmemory",          key_kind::scalar  },
    { "eviction",           "--eviction",           key_kind::text    },
    { "resp",               "--resp",               key_kind::boolean },
    { "replicate",          "--replicate",          key_kind::text    },
    { "cluster",            "--cluster",            key_kind::boolean },
    { "public",             "--public",             key_kind::boolean },
};

// Keys with no flag of their own, listed so an unknown key can still be
// refused by name.
constexpr std::string_view special_keys[] = {
    "type", "name", "config", "lua", "bash", "start", "reconnect",
    "daemon_process",
};

// %.10g rather than std::to_string, which writes a rate of 1.5 as 1.500000 and
// would put six digits of noise into every command the daemon logs.
std::string number_to_text(double v)
{
    char buf[32];
    std::snprintf(buf, sizeof buf, "%.10g", v);
    return buf;
}

// The daemon's parser splits on whitespace and has no quoting, so a value with
// a space in it would arrive as two arguments and configure something else.
std::string refuse_whitespace(std::string_view key, const std::string& value)
{
    if (value.find_first_of(" \t") == std::string::npos)
        return {};

    return std::string(key) + ": a value cannot contain whitespace, because the "
           "daemon's command line has no quoting (\"" + value + "\")\n";
}

// One key, appended to the command or refused with the reason, returning the
// empty string when the key was absent.
std::string emit_key(const config_key& key, const sol::table& entry, std::string& command)
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
                command += " " + std::string(key.flag);
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
            command += " " + std::string(key.flag) + " " + number_to_text(v);
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
            if (std::string why = refuse_whitespace(key.name, value); !why.empty())
                return why;

            command += " " + std::string(key.flag) + " " + value;
            return {};
        }

        case key_kind::list:
        case key_kind::list_semi:
        {
            if (obj.get_type() != sol::type::table)
                return name + ": expected a list of strings\n";

            const char sep = key.kind == key_kind::list ? ',' : ';';
            std::string joined;

            for (auto& element : obj.as<sol::table>())
            {
                if (element.second.get_type() != sol::type::string)
                    return name + ": every entry has to be a string\n";

                const std::string value = element.second.as<std::string>();
                if (value.empty())
                    return name + ": an entry is empty\n";
                if (std::string why = refuse_whitespace(key.name, value); !why.empty())
                    return why;

                if (!joined.empty())
                    joined += sep;
                joined += value;
            }

            // An empty list is the operator asking for nothing rather than for
            // a flag with no value, which the daemon would refuse.
            if (!joined.empty())
                command += " " + std::string(key.flag) + " " + joined;
            return {};
        }
    }

    return {};
}

// The keys with no straightforward flag: an alias, a tri-state, a value that
// may be a bool or a number, and one key that is refused outright.
std::string emit_special_keys(const sol::table& entry, std::string& command, bool& autostart)
{
    // `daemon_process` is refused rather than ignored, for either value,
    // because a key that means nothing still implies this build has an
    // opinion about it.
    if (entry["daemon_process"].valid())
        return "daemon_process is no longer a setting: every runtime runs in "
               "its own process. Remove the line.\n";

    // Two spellings of the handler script, with `config` winning, because a
    // file naming both means two different scripts and only one can run.
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
            command += " --lua " + value;
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
                    command += " --reconnect";
            }
            else if (obj.get_type() == sol::type::number)
            {
                const double v = obj.as<double>();
                if (v != std::floor(v) || v < 0)
                    return "reconnect: expected true or a count of attempts\n";
                command += " --reconnect " + number_to_text(v);
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

            switch (fnv1a(obj.as<std::string>()))
            {
                case fnv1a("pt"):
                case fnv1a("tp"):
                case fnv1a("bpt"):
                case fnv1a("btp"):
                    command += " -bpt";
                    break;
                case fnv1a("p"):
                case fnv1a("bp"):
                    command += " -bp";
                    break;
                case fnv1a("t"):
                case fnv1a("bt"):
                    command += " -bt";
                    break;
                default:
                    command += " -b";
                    break;
            }
        }
    }

    {
        const sol::object obj = entry["start"];
        if (obj.valid() && obj != sol::nil)
        {
            if (obj.get_type() != sol::type::boolean)
                return "start: expected true or false\n";
            autostart = obj.as<bool>();
        }
    }

    return {};
}

// A key nobody handles is a typo, and a typo used to configure nothing while
// the runtime came up looking correct.
std::string refuse_unknown_keys(const sol::table& entry,
                                const type_manifest::manifest* man)
{
    for (auto& pair : entry)
    {
        if (pair.first.get_type() != sol::type::string)
            return "a runtime entry takes named keys, not a list\n";

        const std::string name = pair.first.as<std::string>();
        bool known = false;

        for (const config_key& key : config_keys)
            if (key.name == name) { known = true; break; }

        if (!known)
            for (std::string_view key : special_keys)
                if (key == name) { known = true; break; }

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
std::string emit_manifest_keys(const type_manifest::manifest& man,
                               const sol::table& entry, std::string& command)
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
            command += " " + flag + (obj.as<bool>() ? " true" : " false");
            continue;
        }

        const key_kind kind = sk.kind == type_manifest::key_kind::int_key
                                  ? key_kind::integer
                                  : key_kind::text;
        const config_key row{sk.name, flag, kind};
        if (std::string why = emit_key(row, entry, command); !why.empty())
            return why;
    }

    return {};
}

// The whole entry, in table order so two runs of one file produce the same
// command, with the first refusal ending it because a half-built command line
// configures something nobody asked for.
std::string build_create_command(const std::string& type_str, const std::string& name,
                                 const sol::table& entry, std::string& command,
                                 const type_manifest::manifest* man)
{
    bool autostart = false;

    if (std::string why = refuse_unknown_keys(entry, man); !why.empty())
        return why;

    command = "create " + type_str + " " + name;

    for (const config_key& key : config_keys)
        if (std::string why = emit_key(key, entry, command); !why.empty())
            return why;

    if (man)
        if (std::string why = emit_manifest_keys(*man, entry, command); !why.empty())
            return why;

    if (std::string why = emit_special_keys(entry, command, autostart); !why.empty())
        return why;

    // Last, so a runtime is fully configured before it is asked to run.
    if (autostart)
        command += " -s";

    return {};
}

// A daemon setting the daemon reads at startup and cannot be told afterwards,
// refused by name rather than dropped, because a file that sets a log level
// nothing applies reads as if it did.
std::string refuse_startup_only_daemon_keys(const sol::table& daemon)
{
    for (std::string_view key : { "log_level", "metrics_port", "cpus" })
    {
        if (!daemon[key].valid())
            continue;

        return std::string(key) + " is read when the daemon starts and cannot be "
               "set on a running one: put it in the daemon's own configuration "
               "file and point SOCKETLEY_CONFIG at it\n";
    }

    return {};
}

} // namespace

int cli_config(int argc, char** argv)
{
    if (argc < 3)
    {
        std::cerr << "usage: socketley --lua <lua path>\n";
        return 1;
    }

    // Registered types before any entry is read, because parse_runtime_type
    // resolves through the registry these fill.
    type_manifest::load_dir(socketley_paths::resolve().types_dir);

    sol::state lua;

    // string and math are open because a configuration builds names and port
    // numbers, while os and io stay shut: this file describes runtimes and
    // reaching the filesystem from it is a second thing to review.
    lua.open_libraries(sol::lib::base, sol::lib::package, sol::lib::table,
                       sol::lib::string, sol::lib::math);

    sol::load_result script = lua.load_file(argv[2]);

    if (!script.valid())
    {
        sol::error err = script;
        std::cerr << "failed to load config: " << err.what() << "\n";
        return 1;
    }

    // Deliberately not bounded by lua_deadline, because this chunk runs in the
    // CLI process, holds nothing anybody is waiting on, and can be ended with
    // a keystroke.
    sol::protected_function_result result = script();

    if (!result.valid())
    {
        sol::error err = result;
        std::cerr << "error executing config: " << err.what() << "\n";
        return 1;
    }

    // Apply daemon settings (name, cluster) before runtimes
    sol::optional<sol::table> daemon = lua["daemon"].get<sol::optional<sol::table>>();
    if (daemon)
    {
        if (std::string why = refuse_startup_only_daemon_keys(*daemon); !why.empty())
        {
            std::cerr << why;
            return 1;
        }

        sol::optional<std::string> name = (*daemon)["name"].get<sol::optional<std::string>>();
        if (name && !name->empty())
        {
            std::string response;
            int rc = ipc_send("daemon-name " + *name, response);
            if (rc < 0) { return ipc_report_failure(rc); }
            if (rc != 0) { if (!response.empty()) std::cerr << response; return rc; }
        }

        sol::optional<std::string> cluster = (*daemon)["cluster"].get<sol::optional<std::string>>();
        if (cluster && !cluster->empty())
        {
            std::string response;
            int rc = ipc_send("daemon-cluster " + *cluster, response);
            if (rc < 0) { return ipc_report_failure(rc); }
            if (rc != 0) { if (!response.empty()) std::cerr << response; return rc; }
        }
    }

    sol::table runtimes = lua["runtimes"];

    if (!runtimes.valid())
        return 0;

    // The daemon's exit code and sentence are read rather than only whether
    // the socket answered, because a config file whose every runtime failed
    // reported success and printed nothing -- collected rather than returned
    // at the first failure.
    int failed = 0;

    for (auto& pair : runtimes)
    {
        sol::table t = pair.second;

        // sol::optional like every other field below, because a plain
        // std::string read converts whatever is there in Release rather than
        // throwing on a misspelled key.
        sol::optional<std::string> type_opt = t["type"].get<sol::optional<std::string>>();
        sol::optional<std::string> name_opt = t["name"].get<sol::optional<std::string>>();

        if (!name_opt || name_opt->empty())
        {
            std::cerr << "runtime entry without a name: every entry in `runtimes` "
                         "needs name and type\n";
            ++failed;
            continue;
        }
        if (!type_opt || type_opt->empty())
        {
            std::cerr << "runtime \"" << *name_opt << "\" has no type "
                         "(server, client, proxy, cache, or a registered type)\n";
            ++failed;
            continue;
        }

        const std::string type_str = *type_opt;
        const std::string name     = *name_opt;

        runtime_type type;

        if (!parse_runtime_type(type_str.c_str(), type))
        {
            std::cerr << "unknown runtime type: " << type_str << "\n";
            ++failed;
            continue;
        }

        std::string command;

        if (std::string why = build_create_command(type_str, name, t, command,
                                                   type_manifest::find(type));
            !why.empty())
        {
            std::cerr << "could not create " << name << ":\n  " << why;
            ++failed;
            continue;
        }

        std::string response;
        const int rc = ipc_send(command, response);

        if (rc < 0)
        {
            // No daemon is a different thing from a runtime that would not
            // build: nothing after this can succeed either, so it stops here.
            return ipc_report_failure(rc);
        }

        if (rc != 0)
        {
            std::cerr << "could not create " << name << ":\n";
            if (!response.empty())
            {
                // The daemon's own sentence, indented so a multi-line refusal
                // reads as belonging to the runtime named above it.
                std::istringstream lines(response);
                std::string line;
                while (std::getline(lines, line))
                    std::cerr << "  " << line << "\n";
            }
            else
            {
                std::cerr << "  the daemon refused it and said nothing "
                             "(exit " << rc << ")\n";
            }
            ++failed;
            continue;
        }

        // Success is silent, but a create that printed something while
        // succeeding has something to say and dropping it here is what this
        // change is about.
        if (!response.empty())
            std::cout << response;
    }

    if (failed > 0)
    {
        std::cerr << failed << " of " << runtimes.size()
                  << " runtimes in this configuration were not created\n";
        return 1;
    }

    return 0;
}
