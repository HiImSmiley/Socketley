#pragma once
// A tunnel edge's agents: who may connect, by which secret, and which services each offers under which name.
// `socketley tunnel <edge> invite|revoke` writes it in the daemon, the edge's worker reads it again when it changes,
// and the daemon routes each HTTP service's name to the socket the edge serves it on.
//
// ─── THE FILE ───────────────────────────────────────────────────────────────
//   <state>/tunnel/<edge>/agents, a line each:
//     agent <name> invited|joined <sha256 hex of the secret> <service>[,<service>...]
//   a service `http:<name>`, reached at <name>.<the edge's domain>, or `tcp:<name>:<port>`, a port on the edge.
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace socketley::tunnel
{

struct service
{
    bool http{true};
    std::string name;
    uint16_t port{0};
};

struct agent
{
    std::string name;
    // Invited agents hold a one-time secret, joined ones the key the edge gave them in its place.
    bool joined{false};
    std::string secret_hash;
    std::vector<service> services;
};

// <state>/tunnel/<edge>/, its agents file, and the socket an HTTP service of it is served on, in /tmp under a hash
// when the state directory is too deep for a socket's path.
std::string edge_dir(std::string_view edge);
std::string agents_path(std::string_view edge);
std::string service_socket(std::string_view edge, std::string_view service);
// <state>/tunnel/<agent>/key, the key an agent runtime was given when it joined.
std::string agent_key_path(std::string_view agent_runtime);

// A name an agent or a service may have: a DNS label, lower case.
bool valid_name(std::string_view name);

// The agents of a file's text; false with `why` naming the line for anything else.
bool parse_agents(std::string_view text, std::vector<agent>& out, std::string& why);
std::string render_agents(const std::vector<agent>& agents);

// `--http a,b --tcp c:25565` as services; false with `why` for a bad name or port.
bool parse_services(std::string_view http_csv, std::string_view tcp_csv, std::vector<service>& out, std::string& why);

// Why `a`'s services clash with another agent's, naming them twice or a port twice; empty when they do not.
std::string clash(const std::vector<agent>& agents, const agent& a);

// The edge's agents read, changed by `change`, and written back whole, under a lock the daemon and the edge's worker
// both take; false with `why` when the file cannot be read or written or `change` refuses.
bool update_agents(std::string_view edge, const std::function<bool(std::vector<agent>&, std::string& why)>& change,
                   std::string& why);
// The edge's agents as the file holds them now; an absent file is none.
bool load_agents(std::string_view edge, std::vector<agent>& out, std::string& why);

// SHA-256 of a secret, hex, as the file keeps it.
std::string hash_secret(std::string_view secret);

// `<agent>.<secret>`, as an invitation or a key is handed over, split; false for anything else.
bool split_credential(std::string_view cred, std::string& name, std::string& secret);

}   // namespace socketley::tunnel
