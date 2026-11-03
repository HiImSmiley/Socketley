#include "mcp_run.h"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <mutex>
#include <shared_mutex>
#include <sstream>

#include <sys/stat.h>

#include "mcp_instance.h"
#include "../../shared/http/http_framing.h"
#include "../../shared/http/status.h"
#include "../../shared/http/request_head.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/runtime/runtime_manager.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/text_list.h"
#include "../../shared/util/wall_clock.h"
#include "../../shared/util/version.h"

namespace socketley::mcp
{

namespace
{

constexpr int64_t idle_secs = 120;
constexpr size_t max_head = 16 * 1024;
constexpr size_t max_body = 4u << 20;
constexpr size_t max_conns = 4096;
// A secret shorter than this is no key, so a typo does not let a guess in.
constexpr size_t min_secret = 16;

namespace js = socketley::json;

tool_def daemon_def(std::string name, std::string description, std::string schema, bool writes)
{
    tool_def t;
    t.name = std::move(name);
    t.description = std::move(description);
    t.input_schema = std::move(schema);
    t.read_only = !writes;
    t.destructive = writes;
    t.idempotent = true;
    t.open_world = false;
    t.admin_only = writes;
    return t;
}

const std::string name_schema =
    R"({"type":"object","properties":{"name":{"type":"string","description":"The runtime's name"}},"required":["name"],"additionalProperties":false})";

}   // namespace

mcp_run::mcp_run(mcp_instance& owner, event_loop& loop)
    : m_owner(owner), m_loop(loop), m_http(loop, this, owner, *this, max_conns)
{
}

mcp_run::~mcp_run() = default;

bool mcp_run::start(std::string& why)
{
    m_info.name = std::string(m_owner.get_name());
    m_info.title = m_info.name;
    m_info.version = SOCKETLEY_VERSION;
    m_info.instructions = std::string(m_owner.get_instructions());
    std::string_view list = m_owner.get_origins();
    while (!list.empty())
        if (const std::string_view o = take_item(list, ','); !o.empty())
        {
            if (o == "*")
                m_any_origin = true;
            else
                m_origins.emplace_back(o);
        }
    if (!m_owner.get_keys_path().empty() && !reload_keys(why))
        return false;
    if (!m_owner.get_idp().empty())
    {
        m_resource = m_owner.resource();
        const std::string_view more = m_owner.get_idp_audience();
        m_idp.configure(m_owner.get_idp(), more.empty() ? m_resource : m_resource + "," + std::string(more));
        m_metadata_url = resource_metadata_url();
        m_metadata_path = m_metadata_url.substr(m_metadata_url.find('/', m_metadata_url.find("://") + 3));
    }
    collect();
    if (!m_http.listen_tcp(m_owner.bind_in_addr(), m_owner.effective_port(), m_owner.get_shards() > 1, why))
        return false;
    m_loop.register_owner(this);
    m_http.start_accepting();
    return true;
}

void mcp_run::stop()
{
    if (m_stopped)
        return;
    m_stopped = true;
    m_http.stop();
    if (m_tick_armed)
        m_loop.submit_timeout_remove(&m_tick_req);
}

bool mcp_run::drained() const
{
    return m_loop.owner_drained(this);
}

void mcp_run::on_loop_turn()
{
    m_http.on_loop_turn();
}

void mcp_run::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req)
        return;
    if (req == &m_tick_req)
    {
        m_tick_armed = false;
        if (m_stopped)
            return;
        m_http.sweep(wall::now_sec_coarse(), idle_secs);
        arm_tick();
        return;
    }
    m_http.on_cqe(req, cqe);
}

void mcp_run::arm_tick()
{
    if (m_tick_armed || m_stopped || m_http.empty())
        return;
    m_tick_req = io_request{};
    m_tick_req.owner = this;
    m_tick_req.type = op_timeout;
    m_tick_ts = {5, 0};
    m_tick_armed = m_loop.submit_timeout(&m_tick_ts, &m_tick_req);
}

std::shared_ptr<socketley::http::server_conn> mcp_run::make_conn()
{
    return std::make_shared<socketley::http::server_conn>();
}

void mcp_run::accepted(const std::shared_ptr<socketley::http::server_conn>&)
{
    arm_tick();
}

bool mcp_run::reload_keys(std::string& why)
{
    const std::string path(m_owner.get_keys_path());
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0)
    {
        why = "the keys file " + path + " cannot be read";
        return false;
    }
    const int64_t mtime = static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec;
    if (mtime == m_keys_mtime)
        return true;
    std::ifstream f(path);
    if (!f)
    {
        why = "the keys file " + path + " cannot be read";
        return false;
    }
    std::unordered_map<std::string, key> keys;
    std::string line;
    size_t n = 0;
    while (std::getline(f, line))
    {
        ++n;
        if (const size_t hash = line.find('#'); hash != std::string::npos)
            line.erase(hash);
        std::istringstream words(line);
        std::string name, secret, role;
        if (!(words >> name))
            continue;
        if (!(words >> secret) || secret.size() < min_secret || ((words >> role) && role != "admin"))
        {
            why = path + " line " + std::to_string(n) + " is no `name secret [admin]` with a secret of " +
                  std::to_string(min_secret) + " characters or more";
            return false;
        }
        keys[secret] = key{name, role == "admin"};
    }
    m_keys = std::move(keys);
    m_keys_mtime = mtime;
    return true;
}

void mcp_run::collect()
{
    const auto& d = m_owner.declared();
    if (d.gen == m_declared_seen)
        return;
    m_declared_seen = d.gen;
    m_tools.clear();
    m_resources.clear();
    m_prompts.clear();
    for (const auto& t : d.tools)
        m_tools.push_back(t.def);
    if (m_owner.get_tools() == "daemon")
    {
        m_tools.push_back(daemon_def("socketley_list", "Lists every runtime of this socketley daemon with its type, "
                                     "state, port, connections and owner.",
                                     R"({"type":"object","additionalProperties":false})", false));
        m_tools.push_back(daemon_def("socketley_get", "One runtime of this socketley daemon: its type, state, port, "
                                     "connections and owner.", name_schema, false));
        m_tools.push_back(daemon_def("socketley_start", "Starts a runtime of this socketley daemon.", name_schema, true));
        m_tools.push_back(daemon_def("socketley_stop", "Stops a runtime of this socketley daemon.", name_schema, true));
    }
    for (const auto& r : d.resources)
        m_resources.push_back(r.def);
    for (const auto& p : d.prompts)
        m_prompts.push_back(p.def);
}

void mcp_run::call_tool(const tool_def& t, const json::jvalue& args, const caller& who, tool_done done)
{
    if (t.name.starts_with("socketley_") && m_owner.get_tools() == "daemon" &&
        std::none_of(m_owner.declared().tools.begin(), m_owner.declared().tools.end(),
                     [&](const lua_tool& l) { return l.def.name == t.name; }))
    {
        tool_result out;
        const bool ok = daemon_tool(t, args, who, out);
        done(ok, std::move(out), {});
        return;
    }
    for (const auto& l : m_owner.declared().tools)
        if (l.def.name == t.name)
        {
            // A copy, since a handler that waits may outlive this declaration when the script is read again.
            const auto call = l.call;
            call(args, who, std::move(done));
            return;
        }
    done(false, {}, "the tool " + t.name + " is no longer declared");
}

bool mcp_run::read_resource(const resource_def& r, const caller& who, std::string& contents, std::string& why)
{
    for (const auto& l : m_owner.declared().resources)
        if (l.def.uri == r.uri)
            return l.read(who, contents, why);
    why = "the resource " + r.uri + " is no longer declared";
    return false;
}

bool mcp_run::get_prompt(const prompt_def& p, const json::jvalue& args, const caller& who, std::string& messages,
                         std::string& description, std::string& why)
{
    for (const auto& l : m_owner.declared().prompts)
        if (l.def.name == p.name)
            return l.get(args, who, messages, description, why);
    why = "the prompt " + p.name + " is no longer declared";
    return false;
}

bool mcp_run::daemon_tool(const tool_def& t, const json::jvalue& args, const caller&, tool_result& out)
{
    auto* mgr = m_owner.get_runtime_manager();
    const auto text = [&](const std::string& s, bool error = false) {
        out.content = "[{\"type\":\"text\",\"text\":" + js::quote(s) + "}]";
        out.is_error = error;
        return true;
    };
    if (!mgr)
        return text("this runtime reaches no daemon", true);
    const auto describe = [](runtime_instance& rt) {
        std::string o = "{\"name\":" + js::quote(rt.get_name()) + ",\"type\":" + js::quote(type_to_string(rt.get_type())) +
                        ",\"state\":" + js::quote(state_to_string(rt.get_state())) +
                        ",\"port\":" + std::to_string(rt.get_port()) +
                        ",\"connections\":" + std::to_string(rt.reported_connection_count());
        const std::string_view ow = rt.get_owner();
        o += ",\"owner\":" + (ow.empty() ? std::string("null") : js::quote(ow));
        return o + "}";
    };
    if (t.name == "socketley_list")
    {
        std::string list = "[";
        {
            std::shared_lock lock(mgr->mutex);
            bool first = true;
            for (const auto& [name, rt] : mgr->list())
            {
                if (!rt)
                    continue;
                list += first ? "" : ",";
                first = false;
                list += describe(*rt);
            }
        }
        list += "]";
        out.structured = "{\"runtimes\":" + list + "}";
        return text(out.structured);
    }
    const std::string name(js::string_of(args, "name"));
    if (name.empty())
        return text("name is the runtime's name", true);
    if (t.name == "socketley_get")
    {
        std::shared_lock lock(mgr->mutex);
        runtime_instance* rt = mgr->get(name);
        if (!rt)
            return text("there is no runtime called " + name, true);
        out.structured = describe(*rt);
        return text(out.structured);
    }
    // Asked of the daemon, which every change to the runtimes goes through.
    const std::string op = t.name == "socketley_start" ? "start" : "stop";
    if (name == m_owner.get_name() && op == "stop")
        return text("this server does not stop itself", true);
    std::string err;
    if (!mgr->has_map_sink() || !mgr->map_mutate(op, name, {}, err))
        return text(err.empty() ? name + " could not be " + (op == "start" ? "started" : "stopped") : err, true);
    return text(name + (op == "start" ? " is starting" : " is stopping"));
}

bool mcp_run::authenticate(std::string_view a, caller& who)
{
    if (a.size() <= 7 || !(a.starts_with("Bearer ") || a.starts_with("bearer ")))
        return false;
    const std::string_view token = a.substr(7);
    if (!m_owner.get_keys_path().empty())
    {
        std::string why;
        if (!reload_keys(why) && why != m_keys_error)
        {
            LOG_WARN(("mcp " + std::string(m_owner.get_name()) + ": " + why + "; the keys read before stay").c_str());
            m_keys_error = why;
        }
        if (const auto it = m_keys.find(std::string(token)); it != m_keys.end())
        {
            who = caller{it->second.name, it->second.admin, {}};
            return true;
        }
    }
    socketley::idp::session_verifier::who w;
    if (!m_idp.enabled() || !m_idp.check_bearer(token, w))
        return false;
    who = caller{w.username, w.admin, w.sub};
    return true;
}

std::string mcp_run::resource_metadata_url() const
{
    const size_t path = m_resource.find('/', m_resource.find("://") + 3);
    return m_resource.substr(0, path) + "/.well-known/oauth-protected-resource" +
           (path == std::string::npos ? std::string() : m_resource.substr(path));
}

std::string mcp_run::resource_metadata()
{
    const std::string issuer = m_idp.issuer();
    if (issuer.empty())
        return {};
    return "{\"resource\":" + js::quote(m_resource) + ",\"authorization_servers\":[" + js::quote(issuer) +
           "],\"scopes_supported\":[\"openid\",\"offline_access\"],\"bearer_methods_supported\":[\"header\"],"
           "\"resource_name\":" + js::quote(m_owner.get_name()) + "}";
}

void mcp_run::answer(const std::shared_ptr<socketley::http::server_conn>& c, int status, std::string_view body,
                     std::string_view extra)
{
    if (status >= 400)
        ++m_refused;
    std::string& o = c->out;
    o += "HTTP/1.1 " + std::to_string(status) + " " + socketley::http::status_text(status) + "\r\n";
    if (!body.empty())
        o += "Content-Type: application/json\r\n";
    o += "Content-Length: " + std::to_string(body.size()) + "\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n";
    o += extra;
    if (!c->keep_alive)
        o += "Connection: close\r\n";
    o += "\r\n";
    o += body;
}

void mcp_run::serve(const std::shared_ptr<socketley::http::server_conn>& c)
{
    while (!c->dead && !c->waiting && !c->in.empty())
    {
        socketley::http::request_view v;
        int refusal = 400;
        headers h;
        std::string authorization, origin;
        const int r = socketley::http::take_request(c->in, max_head, max_body, v, refusal,
                                                    [&](std::string_view f, std::string_view value) {
            if (header_name_equals(f, "mcp-protocol-version", 20))
                h.protocol_version.assign(value);
            else if (header_name_equals(f, "mcp-method", 10))
                h.method.assign(value);
            else if (header_name_equals(f, "mcp-name", 8))
                h.name.assign(value);
            else if (header_name_equals(f, "authorization", 13))
                authorization.assign(value);
            else if (header_name_equals(f, "origin", 6))
                origin.assign(value);
        });
        if (r == 0)
            break;
        if (r < 0)
        {
            c->keep_alive = false;
            answer(c, refusal, {});
            break;
        }
        const std::string method(v.method), path(v.path);
        const std::string body = c->in.substr(v.head_len, v.body_len);
        c->in.erase(0, v.head_len + v.body_len);
        c->keep_alive = !v.close;
        runtime_instance::stat_add(m_owner.m_stat_total_messages, 1);

        // A page of another site is not let call it, as the revision asks of every server; a client that is no
        // browser sends no Origin.
        const bool origin_ok = origin.empty() || m_any_origin ||
                               std::find(m_origins.begin(), m_origins.end(), origin) != m_origins.end();
        std::string cors;
        if (!origin.empty() && origin_ok)
            cors = "Access-Control-Allow-Origin: " + (m_any_origin ? std::string("*") : origin) +
                   "\r\nAccess-Control-Expose-Headers: WWW-Authenticate\r\nVary: Origin\r\n";
        if (!origin_ok)
        {
            answer(c, 403, R"({"error":"this origin may not call the server"})");
            continue;
        }
        // Where a client finds the idp it signs in at, asked before it has a token, at the address the revision
        // has it look first and at the host's own.
        if (m_idp.enabled() && (path == m_metadata_path || path == "/.well-known/oauth-protected-resource"))
        {
            if (method == "OPTIONS")
                answer(c, 204, {}, "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET\r\n"
                                   "Access-Control-Max-Age: 600\r\n");
            else if (method != "GET" && method != "HEAD")
                answer(c, 405, {}, "Allow: GET\r\n");
            else if (const std::string doc = resource_metadata(); doc.empty())
                answer(c, 503, R"({"error":"the idp's key is not known yet"})", "Retry-After: 1\r\n");
            else
                answer(c, 200, doc, "Access-Control-Allow-Origin: *\r\n");
            continue;
        }
        if (path != "/mcp" && path != "/")
        {
            answer(c, 404, R"({"error":"the endpoint is /mcp"})", cors);
            continue;
        }
        if (method == "OPTIONS")
        {
            answer(c, 204, {}, cors + "Access-Control-Allow-Methods: POST\r\nAccess-Control-Allow-Headers: Authorization, "
                                      "Content-Type, MCP-Protocol-Version, Mcp-Method, Mcp-Name, Mcp-Session-Id\r\n"
                                      "Access-Control-Max-Age: 600\r\n");
            continue;
        }
        // No stream of its own and no session to end, as 2026-07-28 has it.
        if (method != "POST")
        {
            answer(c, 405, {}, cors + "Allow: POST\r\n");
            continue;
        }
        caller who;
        if ((!m_owner.get_keys_path().empty() || m_idp.enabled()) && !authenticate(authorization, who))
        {
            // A client that can sign in is told where, and which scopes to ask for (RFC 9728 5.1).
            const std::string challenge =
                m_idp.enabled()
                    ? "WWW-Authenticate: Bearer resource_metadata=\"" + m_metadata_url + "\", scope=\"openid offline_access\"" +
                          (authorization.empty() ? std::string() : ", error=\"invalid_token\"") + "\r\n"
                    : std::string("WWW-Authenticate: Bearer realm=\"mcp\"\r\n");
            answer(c, 401, R"({"error":"a key or a sign-in of this server is asked for"})", cors + challenge);
            continue;
        }
        collect();
        // A tool whose handler waits answers on a later turn, and nothing more is read off the connection meanwhile.
        auto in_line = std::make_shared<bool>(true);
        std::weak_ptr<socketley::http::server_conn> weak = c;
        c->waiting = true;
        handle(*this, m_info, h, body, who, [this, weak, cors, in_line](reply rep) {
            auto cc = weak.lock();
            if (!cc || cc->dead || m_stopped)
                return;
            cc->waiting = false;
            answer(cc, rep.status, rep.body, cors);
            if (!*in_line)
                m_http.resume(cc);
        });
        *in_line = false;
    }
}

std::string mcp_run::stats() const
{
    const counters& s = socketley::mcp::stats();
    return "requests:" + std::to_string(s.requests) + "\ntool_calls:" + std::to_string(s.tool_calls) +
           "\ntool_errors:" + std::to_string(s.tool_errors) + "\nerrors:" + std::to_string(s.errors) +
           "\nlegacy_requests:" + std::to_string(s.legacy) + "\nrefused:" + std::to_string(m_refused) +
           "\ntools:" + std::to_string(m_tools.size()) + "\nresources:" + std::to_string(m_resources.size()) +
           "\nprompts:" + std::to_string(m_prompts.size()) + "\nkeys:" + std::to_string(m_keys.size()) + "\n";
}

}   // namespace socketley::mcp
