#include "tunnel_registry.h"

#include <charconv>
#include <filesystem>

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include "../../shared/crypto/jws.h"
#include "../../shared/loop/blocking_write.h"
#include "../../shared/net/unix_listener.h"
#include "../../shared/persist/paths.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/util/hex.h"
#include "../../shared/util/text_list.h"

namespace socketley::tunnel
{

namespace
{

std::vector<std::string_view> words(std::string_view line)
{
    std::vector<std::string_view> out;
    while (!line.empty())
    {
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t'))
            line.remove_prefix(1);
        const size_t n = std::min(line.find_first_of(" \t"), line.size());
        if (n)
            out.push_back(line.substr(0, n));
        line.remove_prefix(n);
    }
    return out;
}

bool parse_service(std::string_view s, service& out)
{
    if (s.starts_with("http:"))
    {
        s.remove_prefix(5);
        const size_t eq = s.find('=');
        out.http = true;
        out.name = std::string(s.substr(0, eq));
        out.auth = eq == std::string_view::npos ? std::string() : std::string(s.substr(eq + 1));
        out.port = 0;
        // A visitor's --auth spec, kept whole on the line: nothing in it may end the item, the field or the line, start
        // a comment, or leave one of its +-joined methods empty, which would let every visitor through.
        bool auth_ok = eq == std::string_view::npos ||
                       (!out.auth.empty() && out.auth.front() != '+' && out.auth.back() != '+' &&
                        out.auth.find("++") == std::string::npos);
        for (const char c : out.auth)
            auth_ok = auth_ok && c > ' ' && c != ',' && c != '#' && c != 0x7f;
        return valid_name(out.name) && auth_ok;
    }
    if (!s.starts_with("tcp:"))
        return false;
    s.remove_prefix(4);
    // `<name>:<port>`, or `<name>:<address>:<port>` for a port opened on that address alone.
    const size_t first = s.find(':'), colon = s.rfind(':');
    if (colon == std::string_view::npos)
        return false;
    out.http = false;
    out.name = std::string(s.substr(0, first));
    out.bind = first == colon ? std::string() : std::string(s.substr(first + 1, colon - first - 1));
    if (in_addr a{}; !out.bind.empty() && ::inet_pton(AF_INET, out.bind.c_str(), &a) != 1)
        return false;
    const std::string_view p = s.substr(colon + 1);
    uint32_t port = 0;
    const auto [end, ec] = std::from_chars(p.data(), p.data() + p.size(), port);
    if (ec != std::errc{} || end != p.data() + p.size() || port == 0 || port > 65535)
        return false;
    out.port = static_cast<uint16_t>(port);
    return valid_name(out.name);
}

std::string render_service(const service& s)
{
    if (s.http)
        return "http:" + s.name + (s.auth.empty() ? "" : "=" + s.auth);
    return "tcp:" + s.name + (s.bind.empty() ? "" : ":" + s.bind) + ":" + std::to_string(s.port);
}

}   // namespace

std::string edge_dir(std::string_view edge)
{
    return (socketley_paths::resolve().state_dir / "tunnel" / std::string(edge)).string();
}

std::string agents_path(std::string_view edge)
{
    return edge_dir(edge) + "/agents";
}

std::string service_socket(std::string_view edge, std::string_view service)
{
    std::string path = edge_dir(edge) + "/" + std::string(service) + ".sock";
    // A Unix socket's path holds 107 bytes; a deep state directory names one by a hash of the path instead.
    if (path.size() < 100)
        return path;
    const std::string d = jws::sha256(path);
    // Beside the daemon's socket in the directory its companion nodes use, since in /tmp anyone could bind the name first.
    std::string hashed =
        socketley_paths::resolve().socket_path.string() + ".rt/tunnel-" + hex_encode(d.data(), 8) + ".sock";
    return unix_sock::path_refusal(hashed).empty() ? hashed : std::string();
}

std::string service_socket_refusal(std::string_view edge, const std::string& sock)
{
    if (sock.empty())
        return "the state directory is too deep for its socket, and the daemon's socket for a short one";
    if (sock.starts_with(edge_dir(edge) + "/"))
        return {};
    const std::string dir = unix_sock::node_dir_of(sock);
    return unix_sock::secure_node_dir(dir) ? std::string() : dir + " is not a directory of this user's alone";
}

std::string agent_key_path(std::string_view agent_runtime)
{
    return edge_dir(agent_runtime) + "/key";
}

bool valid_name(std::string_view name)
{
    if (name.empty() || name.size() > 63 || name.front() == '-' || name.back() == '-')
        return false;
    for (const char c : name)
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
            return false;
    return true;
}

bool parse_agents(std::string_view text, std::vector<agent>& out, std::string& why)
{
    out.clear();
    size_t line_no = 0;
    while (!text.empty())
    {
        ++line_no;
        std::string_view line = take_item(text, '\n');
        if (const size_t h = line.find('#'); h != std::string_view::npos)
            line = line.substr(0, h);
        const auto w = words(line);
        if (w.empty())
            continue;
        const std::string where = "line " + std::to_string(line_no) + ": ";
        if (w.size() != 5 || w[0] != "agent" || !valid_name(w[1]) || (w[2] != "invited" && w[2] != "joined") ||
            w[3].size() != 64)
        {
            why = where + "an agent is: agent <name> invited|joined <hash> <services>";
            return false;
        }
        agent a;
        a.name = std::string(w[1]);
        a.joined = w[2] == "joined";
        a.secret_hash = std::string(w[3]);
        std::string_view list = w[4];
        while (!list.empty())
        {
            service s;
            if (!parse_service(take_item(list), s))
            {
                why = where + "a service is http:<name> or tcp:<name>:<port>";
                return false;
            }
            a.services.push_back(std::move(s));
        }
        if (const std::string c = clash(out, a); !c.empty())
        {
            why = where + c;
            return false;
        }
        out.push_back(std::move(a));
    }
    return true;
}

std::string render_agents(const std::vector<agent>& agents)
{
    std::string out = "# Written by socketley tunnel invite and revoke.\n";
    for (const agent& a : agents)
    {
        out += "agent " + a.name + (a.joined ? " joined " : " invited ") + a.secret_hash + " ";
        for (size_t i = 0; i < a.services.size(); ++i)
        {
            if (i)
                out += ',';
            out += render_service(a.services[i]);
        }
        out += "\n";
    }
    return out;
}

std::vector<std::string_view> auth_methods(std::string_view auth)
{
    std::vector<std::string_view> out;
    while (!auth.empty())
        out.push_back(take_item(auth, '+'));
    return out;
}

bool parse_services(std::string_view http_csv, std::string_view tcp_csv, std::vector<service>& out, std::string& why)
{
    out.clear();
    while (!http_csv.empty())
    {
        service s;
        const std::string_view n = trim_blanks(take_item(http_csv));
        if (!parse_service("http:" + std::string(n), s))
        {
            why = "--http takes service names, lower-case letters, digits and -, each with =<auth> to ask its visitors "
                  "for one";
            return false;
        }
        out.push_back(std::move(s));
    }
    while (!tcp_csv.empty())
    {
        service s;
        const std::string_view n = trim_blanks(take_item(tcp_csv));
        if (!parse_service("tcp:" + std::string(n), s))
        {
            why = "--tcp takes <name>:<port>, the port the edge serves it on, or <name>:<address>:<port> for that "
                  "address alone";
            return false;
        }
        out.push_back(std::move(s));
    }
    if (out.empty())
    {
        why = "an agent offers at least one service: --http <name> or --tcp <name>:<port>";
        return false;
    }
    return true;
}

std::string clash(const std::vector<agent>& agents, const agent& a)
{
    for (size_t i = 0; i < a.services.size(); ++i)
        for (size_t j = 0; j < i; ++j)
            if (a.services[i].name == a.services[j].name ||
                (!a.services[i].http && !a.services[j].http && a.services[i].port == a.services[j].port))
                return "the service " + a.services[i].name + " is named twice";
    for (const agent& o : agents)
    {
        if (o.name == a.name)
            continue;
        for (const service& s : o.services)
            for (const service& t : a.services)
                if (s.name == t.name || (!s.http && !t.http && s.port == t.port))
                    return "the service " + t.name + (s.name == t.name ? "" : " (port " + std::to_string(t.port) + ")") +
                           " is already " + o.name + "'s";
    }
    return {};
}

bool load_agents(std::string_view edge, std::vector<agent>& out, std::string& why)
{
    std::string text;
    if (!read_file(agents_path(edge), text, {.missing_ok = true}, &why))
        return false;
    return parse_agents(text, out, why);
}

bool update_agents(std::string_view edge, const std::function<bool(std::vector<agent>&, std::string& why)>& change,
                   std::string& why)
{
    std::error_code ec;
    std::filesystem::create_directories(edge_dir(edge), ec);
    const std::string lock_path = edge_dir(edge) + "/agents.lock";
    const int lock = ::open(lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock < 0 || ::flock(lock, LOCK_EX) < 0)
    {
        if (lock >= 0)
            ::close(lock);
        why = "the agents of " + std::string(edge) + " cannot be locked";
        return false;
    }
    std::vector<agent> agents;
    bool ok = load_agents(edge, agents, why) && change(agents, why);
    if (ok)
    {
        const std::string text = render_agents(agents);
        const std::string path = agents_path(edge), tmp = path + ".new";
        const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        ok = fd >= 0 && write_all(fd, text.data(), text.size()) && ::fsync(fd) == 0;
        if (fd >= 0)
            ::close(fd);
        ok = ok && ::rename(tmp.c_str(), path.c_str()) == 0;
        if (!ok)
            why = "the agents of " + std::string(edge) + " could not be written";
    }
    ::close(lock);
    return ok;
}

std::string hash_secret(std::string_view secret)
{
    const std::string d = jws::sha256(secret);
    return hex_encode(d.data(), d.size());
}

bool split_credential(std::string_view cred, std::string& name, std::string& secret)
{
    const size_t dot = cred.find('.');
    if (dot == std::string_view::npos || !valid_name(cred.substr(0, dot)) || cred.size() - dot - 1 < 32)
        return false;
    name = std::string(cred.substr(0, dot));
    secret = std::string(cred.substr(dot + 1));
    return true;
}

}   // namespace socketley::tunnel
