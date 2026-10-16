#pragma once
// The usage line for a daemon verb, in one place because the CLI answers
// `<verb> --help` without a daemon and the daemon answers a short argv, and two
// copies of the same sentence drift.
#include <string>
#include <string_view>

namespace command_usage {

// Empty for a verb that has no usage line of its own, which the caller reads as
// "not a daemon verb" rather than as an empty answer.
//
// ─── EVERY VERB THE CLI FORWARDS, NOT A SELECTION ───────────────────────────
// A verb missing from this list does not fall back to anything: `<verb>
// --help` is forwarded instead, and the daemon answers it by running the
// command.  `ls --help` listed the runtimes, `ping --help` pinged, and stats,
// reload, reload-lua and restart exited 0 with nothing at all.  So the list is
// the dispatch table in cli.cpp, and a verb added there belongs here.
inline constexpr std::string_view for_verb(std::string_view verb)
{
    if (verb == "create") return "create <type> <name> [flags]";
    if (verb == "attach") return "attach <type> <name> <port> [--owner <name>] [--pid <pid>]";
    if (verb == "add")    return "add <path> [--name <name>] [-s]";
    if (verb == "start")  return "start <name|pattern>... [-i]";
    if (verb == "stop")   return "stop <name|pattern>...";
    if (verb == "restart") return "restart <name> [edit flags] [-i]";
    if (verb == "remove") return "remove <name|pattern>...";
    if (verb == "owner")  return "owner <name>";
    if (verb == "send")   return "send <name> <message>";
    if (verb == "edit")   return "edit <name> [flags]";
    if (verb == "show")   return "show <name|pattern>...";
    if (verb == "import") return "import <name> <json>";
    if (verb == "stats")  return "stats <name|pattern>...";
    if (verb == "reload") return "reload <name|pattern>...";
    if (verb == "reload-lua") return "reload-lua <name|pattern>...";
    if (verb == "ls")     return "ls [--json|-j|--format json] [--silent|-s] [columns...]";
    if (verb == "ps")     return "ps [-a|--all] [--json|-j|--format json] [--silent|-s] [columns...]";
    if (verb == "ping")   return "ping";
    if (verb == "dashboard") return "dashboard";
    if (verb == "idp-user")
        return "idp-user <idp> add <user> [--password <pw>|-] [--name ..] [--email ..] [--groups a,b] [--set k=v] "
               "[--reset] | passwd <user> --password <pw>|- [--reset] | set <user> k=v... | disable|enable|logout|"
               "remove|show <user> | list | import <storage>";
    if (verb == "db-backup")  return "db-backup <db> <file>";
    if (verb == "db-restore") return "db-restore <db> <file>";
    if (verb == "cluster")
        return "cluster [ls|ps|group <name>|stats|watch|show <daemon>|raft-status|placement|"
               "create <type> <name> [flags] [--replicas <n>]|scale <name> <n>|remove <name>]";
    return {};
}

// The verb that also reads its message from a pipe, and the two whose
// argument is a set of column names -- said here so the short form and
// `--help` cannot answer with different halves of it.
inline constexpr std::string_view second_line(std::string_view verb)
{
    if (verb == "send") return "       echo 'msg' | socketley send <name>";
    if (verb == "ls")
        return "       columns: --id --name --type --port --status --conn "
               "--owner --created --group";
    if (verb == "ps")
        return "       columns: --id --name --type --port --uptime --conn "
               "--owner --created";
    return {};
}

// The whole answer, so a call site spells the verb once and neither end owns
// the wording.
inline std::string line(std::string_view verb)
{
    std::string out = "usage: " + std::string(for_verb(verb)) + "\n";
    if (const std::string_view s = second_line(verb); !s.empty())
        out += std::string(s) + "\n";
    return out;
}

}  // namespace command_usage
