// `socketley <runtime> <verb> ...`: whatever belongs to one runtime said with its name first, the verb read against
// its type and the command it has always been run as. The older forms (`db-query <db>`, `mqtt-pub <mqtt>`,
// `tunnel <edge> invite`, `metrics <metrics> query`, ...) stay, so a script and the dashboard keep working.
#include "cli.h"

#include <cctype>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "../daemon/ipc_client.h"
#include "../shared/json/json_doc.h"

namespace
{

// How a verb becomes the command it stands for: `<cmd> <name> <rest>`, `<cmd> <name> <verb> <rest>`, or
// `<cmd> <name> <word> <rest>`.
enum class shape : uint8_t { name_rest, name_verb_rest, name_word_rest };

struct verb
{
    std::string_view type, name, cmd;
    shape how;
    std::string_view word, help;
};

constexpr verb verbs[] = {
    {"db", "query", "db-query", shape::name_rest, {}, "query <collection> ['<query json>']"},
    {"db", "backup", "db-backup", shape::name_rest, {}, "backup <file>"},
    {"db", "restore", "db-restore", shape::name_rest, {}, "restore <file>"},
    {"mqtt", "pub", "mqtt-pub", shape::name_rest, {}, "pub [--qos 0|1|2] [--retain] <topic> [payload]"},
    {"mqtt", "sub", "mqtt-sub", shape::name_rest, {}, "sub <filter> [--count <n>]"},
    {"mqtt", "sessions", "mqtt-sessions", shape::name_rest, {}, "sessions"},
    {"mqtt", "kick", "mqtt-kick", shape::name_rest, {}, "kick <client> [--end]"},
    {"mqtt", "retained", "mqtt-retained", shape::name_rest, {}, "retained [filter] | --clear <topic>"},
    {"idp", "user", "idp-user", shape::name_rest, {}, "user add|set|del|list|show|reset ..."},
    {"idp", "ssh-ca", "idp-ssh", shape::name_word_rest, "ca", "ssh-ca"},
    {"idp", "login", "login", shape::name_rest, {}, "login [--client <id>]"},
    {"idp", "logout", "logout", shape::name_rest, {}, "logout"},
    {"idp", "ssh-cert", "ssh-cert", shape::name_rest, {}, "ssh-cert [--key <file.pub>]"},
    {"dns", "dnssec", "dnssec", shape::name_rest, {}, "dnssec"},
    {"tunnel", "invite", "tunnel", shape::name_verb_rest, {}, "invite <agent> [--http ..] [--tcp ..] [--udp ..]"},
    {"tunnel", "set", "tunnel", shape::name_verb_rest, {}, "set <agent> [--http ..] [--tcp ..] [--udp ..]"},
    {"tunnel", "list", "tunnel", shape::name_verb_rest, {}, "list"},
    {"tunnel", "shares", "tunnel", shape::name_verb_rest, {}, "shares"},
    {"tunnel", "revoke", "tunnel", shape::name_verb_rest, {}, "revoke <agent>"},
    {"mail", "send", "send", shape::name_rest, {}, "send --to <address> [--subject ..] [--text ..] | --template <file> .."},
    {"mail", "queue", "mail", shape::name_verb_rest, {}, "queue [filter]"},
    {"mail", "show", "mail", shape::name_verb_rest, {}, "show <id>"},
    {"mail", "flush", "mail", shape::name_verb_rest, {}, "flush [id]"},
    {"mail", "drop", "mail", shape::name_verb_rest, {}, "drop <id>"},
    {"mail", "dns", "mail", shape::name_verb_rest, {}, "dns [--check]"},
    {"mail", "trace", "mail", shape::name_verb_rest, {}, "trace <address>"},
    {"mail", "usage", "mail", shape::name_verb_rest, {}, "usage [user]"},
    {"mail", "suppressed", "mail", shape::name_verb_rest, {}, "suppressed"},
    {"mail", "forgive", "mail", shape::name_verb_rest, {}, "forgive <address>"},
    {"mail", "unsubscribed", "mail", shape::name_verb_rest, {}, "unsubscribed"},
    {"mail", "resubscribe", "mail", shape::name_verb_rest, {}, "resubscribe <address>"},
    {"mail", "learn", "mail", shape::name_verb_rest, {}, "learn <user>/<folder> --as spam|ham"},
    {"mail", "export", "mail", shape::name_verb_rest, {}, "export <user> [dir]"},
    {"mail", "import", "mail", shape::name_verb_rest, {}, "import <user> <file.mbox|dir>"},
    {"mail", "sieve", "mail", shape::name_verb_rest, {}, "sieve <user> list|get|put|check|activate|deactivate|delete .."},
    {"metrics", "query", "metrics", shape::name_verb_rest, {}, "query '<promql>' [--at <time>]"},
    {"metrics", "query_range", "metrics", shape::name_verb_rest, {}, "query_range '<promql>' [--start] [--end] [--step]"},
    {"metrics", "series", "metrics", shape::name_verb_rest, {}, "series '<selector>'"},
    {"metrics", "targets", "metrics", shape::name_verb_rest, {}, "targets"},
    {"metrics", "rules", "metrics", shape::name_verb_rest, {}, "rules"},
    {"metrics", "alerts", "metrics", shape::name_verb_rest, {}, "alerts [--recent]"},
    {"metrics", "logs", "metrics", shape::name_verb_rest, {}, "logs ['<logql>'] [--since <duration>] [--limit <n>]"},
    {"metrics", "stats", "metrics", shape::name_verb_rest, {}, "stats"},
    {"server", "send", "send", shape::name_rest, {}, "send <message>"},
    {"client", "send", "send", shape::name_rest, {}, "send <message>"},
    {"proxy", "send", "send", shape::name_rest, {}, "send <message>"},
};

// What every runtime answers to, whatever its type, run as the command of the same name.
constexpr std::string_view lifecycle[] = {"start", "stop", "restart", "remove", "show", "stats", "edit", "reload",
                                          "reload-lua", "owner"};

// A cache's own verbs, which the daemon's `action` reads; the list `help` gives.
constexpr std::string_view cache_verbs[] = {
    "get", "set", "del", "exists", "incr", "decr", "incrby", "decrby", "append", "mget", "mset", "keys", "size",
    "expire", "ttl", "persist", "lpush", "rpush", "lpop", "rpop", "llen", "lrange", "lindex", "sadd", "srem",
    "sismember", "scard", "smembers", "hset", "hget", "hdel", "hlen", "hgetall", "publish", "flush", "load",
    "memory", "send"};

// The type of the runtime `name`, empty when the daemon has none of that name.
std::string type_of(std::string_view name)
{
    std::string listing;
    if (ipc_send("ls --json", listing) != 0)
        return {};
    while (!listing.empty() && std::isspace(static_cast<unsigned char>(listing.back())))
        listing.pop_back();
    socketley::json::json_policy any;
    any.object_root = false;
    socketley::json::jvalue all;
    if (!socketley::json::json_reader(listing, any).document(all))
        return {};
    for (const auto& r : all.items)
        if (socketley::json::string_of(r, "name") == name)
            return std::string(socketley::json::string_of(r, "type"));
    return {};
}

int run(std::vector<std::string> words)
{
    std::vector<char*> av;
    for (auto& w : words)
        av.push_back(w.data());
    av.push_back(nullptr);
    return cli_dispatch(static_cast<int>(words.size()), av.data());
}

void help(std::string_view name, std::string_view type)
{
    std::cout << "socketley " << name << " <verb> ... -- a " << type << " runtime's verbs:\n";
    for (const verb& v : verbs)
        if (v.type == type)
            std::cout << "  " << v.help << "\n";
    if (type == "cache")
    {
        std::cout << " ";
        for (const auto v : cache_verbs)
            std::cout << " " << v;
        std::cout << "\n";
    }
    std::cout << "and every runtime's:";
    for (const auto v : lifecycle)
        std::cout << " " << v;
    std::cout << "\n";
}

}   // namespace

bool cli_is_type_verb(std::string_view type, std::string_view word)
{
    for (const verb& v : verbs)
        if (v.type == type && v.name == word)
            return true;
    return false;
}

int cli_runtime_verb(int argc, char** argv)
{
    const std::string name = argv[1];
    const std::string_view word = argc >= 3 ? argv[2] : "help";
    const std::string type = type_of(name);
    // A name the daemon does not know goes on as it always did, and is answered as no such runtime.
    if (type.empty())
        return argc >= 3 ? cli_runtime_action(argc, argv) : (std::cout << "unknown command or runtime: " << name << "\n", 1);
    if (word == "help" || word == "--help" || word == "-h")
        return help(name, type), 0;
    for (const verb& v : verbs)
    {
        if (v.type != type || v.name != word)
            continue;
        std::vector<std::string> w = {argv[0], std::string(v.cmd), name};
        if (v.how == shape::name_verb_rest)
            w.emplace_back(word);
        else if (v.how == shape::name_word_rest)
            w.emplace_back(v.word);
        for (int i = 3; i < argc; ++i)
            w.emplace_back(argv[i]);
        return run(std::move(w));
    }
    for (const auto l : lifecycle)
        if (l == word)
        {
            std::vector<std::string> w = {argv[0], std::string(word), name};
            for (int i = 3; i < argc; ++i)
                w.emplace_back(argv[i]);
            return run(std::move(w));
        }
    if (type == "cache")
        return cli_runtime_action(argc, argv);
    std::cout << word << " is no verb of a " << type << " runtime; socketley " << name << " help lists them\n";
    return 1;
}
