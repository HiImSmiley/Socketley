#include "idp_run.h"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <fstream>
#include <sstream>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "idp_instance.h"
#include "../../shared/http/http_framing.h"
#include "../../shared/crypto/jws.h"
#include "../../shared/util/logging.h"
#include "../../shared/runtime/runtime_manager.h"
#include "../../shared/ipc/shard_target.h"
#include "../../shared/storage/storage_rpc.h"
#include "../storage/checksum.h"
#include "../storage/password_hash.h"
#include "../storage/scrypt.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/persist/replaced_file.h"
#include "../../shared/http/status.h"
#include "../../shared/http/request_head.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/util/wall_clock.h"
#include "../../shared/http/cookie.h"
#include "../../shared/util/base64.h"
#include "../../shared/util/random_id.h"
#include "../../shared/util/text_list.h"
#include "../../shared/crypto/mac.h"
#include "../../shared/net/peer_address.h"

namespace socketley::idp
{

namespace
{

constexpr int64_t code_secs     = 60;
constexpr int64_t token_secs    = 3600;
constexpr int64_t refresh_secs  = 30 * 86400;
constexpr int64_t session_secs  = 12 * 3600;
constexpr int64_t remember_secs = 30 * 86400;
constexpr int64_t idle_secs     = 60;
constexpr size_t  max_head      = 16 * 1024;
constexpr size_t  max_body      = 16 * 1024;
constexpr size_t  max_conns     = 4096;
constexpr int     miss_limit    = 5;
constexpr int64_t miss_window   = 15 * 60;

std::string peer_text(const sockaddr_storage& a)
{
    char buf[INET6_ADDRSTRLEN] = {};
    if (a.ss_family == AF_INET)
        ::inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in&>(a).sin_addr, buf, sizeof buf);
    else if (a.ss_family == AF_INET6)
        ::inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6&>(a).sin6_addr, buf, sizeof buf);
    return buf;
}

std::string claim(const claims& c, std::string_view k)
{
    const auto it = c.find(k);
    return it == c.end() ? std::string() : it->second;
}

int64_t claim_int(const claims& c, std::string_view k)
{
    const std::string v = claim(c, k);
    int64_t out = 0;
    std::from_chars(v.data(), v.data() + v.size(), out);
    return out;
}

// When a token of this provider was given, to the millisecond its own claim says, or its iat's second.
int64_t issued_ms(const claims& c)
{
    const int64_t ms = claim_int(c, "iat_ms");
    return ms ? ms : claim_int(c, "iat") * 1000;
}

std::string page(std::string_view title, std::string_view body)
{
    return "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" "
           "content=\"width=device-width,initial-scale=1\"><title>" +
           html_escape(title) +
           "</title><style>body{font-family:system-ui,sans-serif;background:#f4f5f7;margin:0;display:flex;"
           "min-height:100vh;align-items:center;justify-content:center}main{background:#fff;padding:2rem 2.2rem;"
           "border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);width:min(22rem,90vw)}h1{font-size:1.25rem;"
           "margin:0 0 1.2rem}label{display:block;font-size:.85rem;margin:.8rem 0 .3rem;color:#444}"
           "input[type=text],input[type=password]{width:100%;box-sizing:border-box;padding:.6rem;border:1px solid "
           "#ccd;border-radius:6px;font-size:1rem}button{margin-top:1.2rem;width:100%;padding:.65rem;border:0;"
           "border-radius:6px;background:#2d6cdf;color:#fff;font-size:1rem;cursor:pointer}.err{color:#b3261e;"
           "font-size:.9rem;margin:.4rem 0 0}.small{font-size:.85rem;color:#555}.row{display:flex;gap:.4rem;"
           "align-items:center;margin-top:.8rem;font-size:.85rem}a{color:#2d6cdf}</style></head><body><main>" +
           std::string(body) + "</main></body></html>";
}

// The parameters an authorize request carries through the sign-in form, and nothing else.
constexpr std::string_view carried[] = {"client_id", "redirect_uri", "response_type", "scope", "state", "nonce",
                                        "code_challenge", "code_challenge_method", "rd"};

// One scrypt holds 16 MiB and a thread makes up to four at once, so four threads are sixteen at most, shared out
// among the shards.
unsigned hash_threads(uint32_t shards)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    const int n = ::sched_getaffinity(0, sizeof set, &set) == 0 ? CPU_COUNT(&set) : 1;
    const unsigned all = static_cast<unsigned>(std::clamp(n, 1, 4));
    return std::max(1u, (all + shards - 1) / shards);
}

}   // namespace

idp_run::idp_run(idp_instance& owner, event_loop& loop)
    : m_owner(owner), m_loop(loop), m_io(loop, this), m_http(loop, this, owner, *this, max_conns),
      m_hash(hash_threads(std::max<uint32_t>(1, owner.get_shards())))
{
}

idp_run::~idp_run()
{
    *m_alive = false;
    m_hash.stop();
    m_loop.deregister_owner(this);
    if (m_key)
        EVP_PKEY_free(m_key);
}

bool idp_run::start(std::string& why)
{
    m_shards = std::max<uint32_t>(1, m_owner.get_shards());
    m_shard = m_owner.get_shard_index();
    m_reader = m_shards > 1 && m_shard > 0;
    m_issuer = m_owner.issuer();
    m_issuer_json = socketley::json::quote(m_issuer);
    m_cookie_domain = std::string(m_owner.get_cookie_domain());
    m_secure_cookie = m_issuer.starts_with("https://");

    std::string err;
    m_key = socketley::jws::load_or_make_key(idp_key_path(m_owner.get_name()), "the signing key", err);
    if (!m_key)
    {
        why = err;
        return false;
    }
    m_kid = socketley::jws::thumbprint(m_key);
    m_secret = token_secret(m_key);
    if (m_secret.empty())
    {
        why = "the signing key's private half cannot be read";
        return false;
    }
    const std::string pub = socketley::jws::jwk_of(m_key);
    m_jwk = pub.substr(0, pub.size() - 1) + ",\"kid\":" + socketley::json::quote(m_kid) + ",\"use\":\"sig\",\"alg\":\"ES256\"}";
    // The public half where a proxy of this daemon reads it, written whole so a reader never sees half of it, by
    // shard 0 alone, since every shard holds the same key.
    if (!m_reader)
    {
        const std::string path = idp_jwks_path(m_owner.get_name());
        const std::string doc = "{\"issuer\":" + socketley::json::quote(m_issuer) + ",\"keys\":[" + m_jwk + "]}\n";
        if (!replace_file(path, doc, durability::none, nullptr, 0644))
        {
            why = "the public key could not be written to " + path;
            return false;
        }
    }
    load_clients();
    if (!m_clients_error.empty())
    {
        why = m_clients_error;
        return false;
    }
    if (!(m_reader ? m_accounts.follow_open(idp_accounts_dir(m_owner.get_name()), why)
                   : m_accounts.open(idp_accounts_dir(m_owner.get_name()), why)))
        return false;
    publish_accounts();
    // Password hashes are made and checked off the loop, which an scrypt would hold for tens of milliseconds.
    m_loop.register_owner(this);
    if (!m_hash.attach(m_io))
        m_hash.stop();

    if (!m_http.listen_tcp(m_owner.bind_in_addr(), m_owner.effective_port(), m_shards > 1, why))
        return false;
    m_loop.register_owner(this);
    m_http.start_accepting();
    LOG_INFO(("idp " + std::string(m_owner.get_name()) + ": issuer " + m_issuer + ", " +
              std::to_string(m_accounts.size()) + " account(s), " + std::to_string(m_clients.size()) + " client(s)").c_str());
    return true;
}

void idp_run::stop()
{
    if (m_stopped)
        return;
    m_stopped = true;
    // Answers to what this shard asked another are not wanted once it stops.
    if (auto* mgr = m_owner.get_runtime_manager())
        mgr->requests().drop_origin(this);
    m_crossed.clear();
    m_http.stop();
    // The hashing thread ends before the descriptor it wakes the loop through is closed.
    m_hash.retire(m_loop);
    m_accounts.close();
}

bool idp_run::drained() const
{
    return m_loop.owner_drained(this);
}

void idp_run::on_loop_turn()
{
    m_http.on_loop_turn();
}

std::string idp_run::stats() const
{
    return "issuer:" + m_issuer + "\naccounts:" + std::to_string(m_accounts.size()) +
           "\nclients:" + std::to_string(m_clients.size()) + "\nsign_ins:" + std::to_string(m_c.sign_ins) +
           "\nsign_ins_refused:" + std::to_string(m_c.refused) + "\nsign_ins_barred:" + std::to_string(m_c.barred) +
           "\ncodes:" + std::to_string(m_c.codes) + "\ntokens:" + std::to_string(m_c.tokens) +
           "\nrefreshes:" + std::to_string(m_c.refreshes) + "\nuserinfo:" + std::to_string(m_c.userinfo) +
           (m_shards > 1 ? "\nshard:" + std::to_string(m_shard) + "/" + std::to_string(m_shards) +
                               "\nrole:" + (m_reader ? "reader" : "writer") + "\ncrossed:" + std::to_string(m_c.crossed) +
                               "\ncrossings_served:" + std::to_string(m_c.crossings_served) +
                               "\nreopened:" + std::to_string(m_c.reopened)
                         : std::string()) +
           (m_clients_error.empty() ? std::string() : "\nclients_error:" + m_clients_error) + "\n";
}

// ─── Connections ────────────────────────────────────────────────────────────

void idp_run::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req)
        return;
    if (file_io::owns_type(req->type))
    {
        m_io.on_cqe(cqe);
        return;
    }
    if (req == &m_tick_req)
    {
        m_tick_armed = false;
        tick();
        return;
    }
    m_http.on_cqe(req, cqe);
}

std::shared_ptr<socketley::http::server_conn> idp_run::make_conn()
{
    return std::make_shared_for_overwrite<conn>();
}

void idp_run::accepted(const std::shared_ptr<conn>&)
{
    arm_tick();
}

// Requests in order, one at a time: one whose answer waits on the storage holds those behind it.
void idp_run::serve(const std::shared_ptr<conn>& c)
{
    while (!c->dead && !c->waiting && !c->in.empty())
    {
        request rq;
        int refusal = 400;
        const int r = take_request(*c, rq, refusal);
        if (r == 0)
            break;
        if (r < 0)
        {
            c->keep_alive = false;
            respond(c, refusal, "text/plain", "the request could not be read\n");
            break;
        }
        runtime_instance::stat_add(m_owner.m_stat_total_messages, 1);
        handle(c, rq);
    }
}

// Once a second while there is anything to look after: idle connections, codes to forget, failures to age; an
// idle provider is woken by nothing.
void idp_run::arm_tick()
{
    if (m_tick_armed || m_stopped)
        return;
    m_tick_req = io_request{};
    m_tick_req.owner = this;
    m_tick_req.type = op_timeout;
    m_tick_ts = {1, 0};
    m_tick_armed = m_loop.submit_timeout(&m_tick_ts, &m_tick_req);
}

void idp_run::tick()
{
    if (m_stopped)
        return;
    const int64_t now = wall::now_sec();
    m_http.sweep(now, idle_secs);
    std::erase_if(m_codes, [now](const auto& kv) { return kv.second.expires <= now; });
    // A loop rather than erase_if, whose predicate GCC 12's library hands each entry as const.
    for (auto it = m_misses.begin(); it != m_misses.end();)
    {
        std::erase_if(it->second.at, [now](int64_t t) { return now - t > miss_window; });
        it = it->second.at.empty() ? m_misses.erase(it) : std::next(it);
    }
    if (!m_http.empty() || !m_codes.empty() || !m_misses.empty())
        arm_tick();
}

// ─── HTTP ───────────────────────────────────────────────────────────────────

int idp_run::take_request(conn& c, request& rq, int& refusal)
{
    socketley::http::request_view v;
    const int r = socketley::http::take_request(c.in, max_head, max_body, v, refusal,
                                                [&rq](std::string_view f, std::string_view value) {
        if (header_name_equals(f, "cookie", 6))
        {
            if (!rq.cookie.empty())
                rq.cookie += "; ";
            rq.cookie.append(value);
        }
        else if (header_name_equals(f, "authorization", 13))
            rq.authorization.assign(value);
        else if (header_name_equals(f, "content-type", 12))
            rq.content_type.assign(value);
        else if (header_name_equals(f, "x-forwarded-for", 15))
            rq.forwarded_for.assign(value);
        else if (header_name_equals(f, "host", 4))
            rq.host.assign(value);
    });
    if (r <= 0)
        return r;
    rq.method.assign(v.method);
    rq.path.assign(v.path);
    rq.query.assign(v.query);
    rq.body.assign(c.in, v.head_len, v.body_len);
    c.in.erase(0, v.head_len + v.body_len);
    c.keep_alive = !v.close;
    return 1;
}

void idp_run::respond(const std::shared_ptr<conn>& c, int status, std::string_view type, std::string_view body,
                      std::string_view extra_headers)
{
    std::string& o = c->out;
    o += "HTTP/1.1 ";
    o += std::to_string(status);
    o += ' ';
    o += socketley::http::status_text(status);
    o += "\r\nContent-Type: ";
    o += type;
    o += "\r\nContent-Length: ";
    o += std::to_string(body.size());
    o += "\r\nCache-Control: no-store\r\nPragma: no-cache\r\nX-Content-Type-Options: nosniff\r\n"
         "Referrer-Policy: no-referrer\r\n";
    if (type.starts_with("text/html"))
        o += "X-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; "
             "frame-ancestors 'none'\r\n";
    o += extra_headers;
    if (!c->keep_alive)
        o += "Connection: close\r\n";
    o += "\r\n";
    o += body;
}

void idp_run::redirect(const std::shared_ptr<conn>& c, std::string_view location, std::string_view extra_headers)
{
    std::string h = "Location: " + std::string(location) + "\r\n" + std::string(extra_headers);
    respond(c, 302, "text/plain", "", h);
}

void idp_run::json_error(const std::shared_ptr<conn>& c, int status, std::string_view error,
                         std::string_view description, std::string_view extra_headers)
{
    respond(c, status, "application/json",
            "{\"error\":" + socketley::json::quote(error) + ",\"error_description\":" + socketley::json::quote(description) + "}",
            "Access-Control-Allow-Origin: *\r\n" + std::string(extra_headers));
}

void idp_run::handle(const std::shared_ptr<conn>& c, request& rq)
{
    // What shard 0 has written by now, so an answer here is as current as one it would give.
    catch_up();
    // The clients file, looked at again at most once a second.
    if (const int64_t now = wall::now_sec(); now != m_clients_checked)
    {
        m_clients_checked = now;
        load_clients();
    }
    const std::string_view p = rq.path;
    const bool get = rq.method == "GET" || rq.method == "HEAD";
    const bool post = rq.method == "POST";
    if (rq.method == "OPTIONS")
    {
        // A browser's preflight for the endpoints a single-page client calls.
        respond(c, 200, "text/plain", "",
                "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST\r\n"
                "Access-Control-Allow-Headers: Authorization, Content-Type\r\nAccess-Control-Max-Age: 600\r\n");
        return;
    }
    if (p == "/.well-known/openid-configuration" && get)
        discovery(c);
    else if (p == "/jwks" && get)
        jwks(c);
    else if ((p == "/authorize" || p == "/login") && get)
        authorize(c, rq);
    else if ((p == "/authorize" || p == "/login") && post)
        sign_in(c, rq);
    else if (p == "/token" && post)
        token(c, rq);
    else if (p == "/userinfo" && (get || post))
        userinfo(c, rq);
    else if (p == "/logout" && (get || post))
        logout(c, rq);
    else if (p == "/" && get)
        home(c, rq);
    else if (p == "/account" && get)
        account_page(c, rq, {}, {}, 200);
    else if ((p == "/account" || p == "/account/everywhere") && post)
        account_post(c, rq);
    else if (p == "/account/password" && post)
        password_post(c, rq);
    else if (p == "/.well-known/openid-configuration" || p == "/jwks" || p == "/authorize" || p == "/login" ||
             p == "/token" || p == "/userinfo" || p == "/logout" || p == "/" || p.starts_with("/account"))
        respond(c, 405, "text/plain", "method not allowed\n");
    else
        respond(c, 404, "text/plain", "not found\n");
}

// ─── Discovery and keys ─────────────────────────────────────────────────────

void idp_run::discovery(const std::shared_ptr<conn>& c)
{
    const std::string& i = m_issuer;
    respond(c, 200, "application/json",
            "{\"issuer\":" + socketley::json::quote(i) + ",\"authorization_endpoint\":" + socketley::json::quote(i + "/authorize") +
                ",\"token_endpoint\":" + socketley::json::quote(i + "/token") + ",\"userinfo_endpoint\":" +
                socketley::json::quote(i + "/userinfo") + ",\"jwks_uri\":" + socketley::json::quote(i + "/jwks") +
                ",\"end_session_endpoint\":" + socketley::json::quote(i + "/logout") +
                ",\"response_types_supported\":[\"code\"],\"grant_types_supported\":[\"authorization_code\","
                "\"refresh_token\"],\"subject_types_supported\":[\"public\"],\"id_token_signing_alg_values_supported\":"
                "[\"ES256\"],\"scopes_supported\":[\"openid\",\"profile\",\"email\",\"offline_access\"],"
                "\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\",\"none\"],"
                "\"code_challenge_methods_supported\":[\"S256\"],\"claims_supported\":[\"sub\",\"name\","
                "\"preferred_username\",\"email\",\"groups\"]}",
            "Access-Control-Allow-Origin: *\r\n");
}

void idp_run::jwks(const std::shared_ptr<conn>& c)
{
    respond(c, 200, "application/json", "{\"keys\":[" + m_jwk + "]}", "Access-Control-Allow-Origin: *\r\n");
}

// ─── Clients ────────────────────────────────────────────────────────────────

void idp_run::load_clients()
{
    const std::string path(m_owner.get_clients());
    if (path.empty())
        return;
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0)
    {
        m_clients_error = "the clients file " + path + " cannot be read";
        if (m_clients_stamp)
            LOG_WARN(("idp " + std::string(m_owner.get_name()) + ": " + m_clients_error +
                      "; the clients read before stay").c_str());
        return;
    }
    const socketley::file_stamp mtime = socketley::file_stamp::of(st);
    if (mtime == m_clients_stamp)
        return;
    std::string text;
    std::vector<client> fresh;
    std::string why;
    if (!socketley::read_whole_file(path, text) || !parse_clients(text, fresh, why))
    {
        m_clients_error = "the clients file " + path + ": " + (why.empty() ? "cannot be read" : why);
        // A file broken while running keeps the clients read before it, and says so once.
        if (m_clients_stamp)
            LOG_WARN(("idp " + std::string(m_owner.get_name()) + ": " + m_clients_error +
                      "; the clients read before stay").c_str());
        m_clients_stamp = mtime;
        return;
    }
    m_clients = std::move(fresh);
    m_clients_error.clear();
    m_clients_stamp = mtime;
}

const client* idp_run::find_client(std::string_view id)
{
    for (const auto& c : m_clients)
        if (c.id == id)
            return &c;
    return nullptr;
}

// ─── Sessions ───────────────────────────────────────────────────────────────

const account* idp_run::session_of(const request& rq) const
{
    // Every skl_idp cookie the request carries, since a browser sends one per domain it was set for.
    const int64_t now = wall::now_sec();
    const account* found = nullptr;
    http::for_each_cookie(rq.cookie, session_cookie_name, [&](std::string_view v) {
        claims c;
        std::string why;
        if (!m_verified.verify(m_key, m_kid, "session+jwt", m_issuer, v, now, c, why) || claim(c, "aud") != "session")
            return false;
        const account* a = m_accounts.by_id(claim(c, "sub"));
        if (a && !a->disabled() && still_signed_in(*a, issued_ms(c)))
            found = a;
        return found != nullptr;
    });
    return found;
}

std::string idp_run::session_cookie(const account& who, bool remember) const
{
    const int64_t now = wall::now_sec();
    const int64_t life = remember ? remember_secs : session_secs;
    // What a proxy or a storage verifying the cookie on its own needs: the id, the username and the admin bit.
    const std::string body = "\"iss\":" + m_issuer_json + ",\"aud\":\"session\",\"sub\":" +
                             socketley::json::quote(who.id) + ",\"preferred_username\":" + socketley::json::quote(who.username()) +
                             ",\"email\":" + socketley::json::quote(who.field("email")) + ",\"admin\":" +
                             (who.in_group("admins") ? "true" : "false") + ",\"iat\":" + std::to_string(now) +
                             ",\"iat_ms\":" + std::to_string(wall::now_ms()) +
                             ",\"auth_time\":" + std::to_string(now) + ",\"exp\":" + std::to_string(now + life);
    std::string h = "Set-Cookie: " + std::string(session_cookie_name) + "=" + sign_token(m_key, m_kid, "session+jwt", body) +
                    "; Path=/; HttpOnly; SameSite=Lax";
    if (remember)
        h += "; Max-Age=" + std::to_string(life);
    if (m_secure_cookie)
        h += "; Secure";
    if (!m_cookie_domain.empty())
        h += "; Domain=" + m_cookie_domain;
    return h + "\r\n";
}

bool idp_run::still_signed_in(const account& who, int64_t issued)
{
    const std::string_view before = who.field("revoked_before");
    if (before.empty())
        return true;
    int64_t floor = 0;
    std::from_chars(before.data(), before.data() + before.size(), floor);
    return issued >= floor;
}

std::string idp_run::profile_claims(const account& who) const
{
    const std::string_view name = who.field("name").empty() ? who.username() : who.field("name");
    std::string out = ",\"name\":" + socketley::json::quote(name) + ",\"preferred_username\":" + socketley::json::quote(who.username());
    if (const std::string_view e = who.field("email"); !e.empty())
        out += ",\"email\":" + socketley::json::quote(e);
    if (const std::string_view p = who.field("picture"); !p.empty())
        out += ",\"picture\":" + socketley::json::quote(p);
    std::string groups;
    std::string_view g = who.field("groups");
    while (!g.empty())
    {
        std::string_view one = http_trim_ows(take_item(g));
        if (one.empty())
            continue;
        if (!groups.empty())
            groups += ',';
        groups += socketley::json::quote(one);
    }
    if (!groups.empty())
        out += ",\"groups\":[" + groups + "]";
    return out;
}

std::string idp_run::clear_cookie() const
{
    std::string h = "Set-Cookie: " + std::string(session_cookie_name) + "=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";
    if (m_secure_cookie)
        h += "; Secure";
    if (!m_cookie_domain.empty())
        h += "; Domain=" + m_cookie_domain;
    return h + "\r\n";
}

std::string idp_run::client_ip(const conn& c, const request& rq) const
{
    // Behind the entrance, a hop on this machine, the client is the last one it names.
    if (is_loopback(c.peer))
        if (const std::string_view f = http_last_forwarded_hop(rq.forwarded_for); !f.empty())
            return std::string(f);
    return peer_text(c.peer);
}

bool idp_run::barred(const std::string& ip, int64_t now)
{
    const auto it = m_misses.find(ip);
    if (it == m_misses.end())
        return false;
    std::erase_if(it->second.at, [now](int64_t t) { return now - t > miss_window; });
    return static_cast<int>(it->second.at.size()) >= miss_limit;
}

void idp_run::missed(const std::string& ip, int64_t now, std::function<void()> then)
{
    m_misses[ip].at.push_back(now);
    arm_tick();
    // Every shard bars the address, which would otherwise have five tries at each, and the failure is answered once
    // they all have, so the next try is barred wherever it lands.
    auto left = std::make_shared<uint32_t>(1);
    auto one = [left, then](bool, std::string_view)
    {
        if (--*left == 0)
            then();
    };
    for (uint32_t j = 0; j < m_shards && m_shards > 1; ++j)
        if (j != m_shard)
        {
            ++*left;
            if (!cross(j, shard_call{shard_call::miss, ip, {}, now}, one))
                --*left;
        }
    one(true, {});
}

// ─── Authorize and sign in ──────────────────────────────────────────────────

const client* idp_run::checked_client(const std::shared_ptr<conn>& c, const params& p, bool& answered)
{
    answered = false;
    const client* cl = find_client(param(p, "client_id"));
    const std::string_view back = param(p, "redirect_uri");
    // Without a known client and one of its own addresses there is nowhere safe to send an error, so it is shown.
    if (!cl || !cl->allows(back))
    {
        answered = true;
        respond(c, 400, "text/html; charset=utf-8",
                page("Sign-in refused", "<h1>This sign-in cannot go on</h1><p class=\"small\">The application asked "
                                        "with a client or a return address this provider does not know.</p>"));
        return nullptr;
    }
    const std::string sep = back.find('?') == std::string_view::npos ? "?" : "&";
    const std::string state = std::string(param(p, "state"));
    auto fail = [&](std::string_view error, std::string_view desc)
    {
        answered = true;
        redirect(c, std::string(back) + sep + "error=" + url_encode(error) + "&error_description=" +
                        url_encode(desc) + (state.empty() ? "" : "&state=" + url_encode(state)));
    };
    if (param(p, "response_type") != "code")
    {
        fail("unsupported_response_type", "only the authorization code flow is served");
        return nullptr;
    }
    if (!has_scope(param(p, "scope"), "openid"))
    {
        fail("invalid_scope", "the scope must hold openid");
        return nullptr;
    }
    const std::string_view challenge = param(p, "code_challenge");
    if (!challenge.empty() && param(p, "code_challenge_method") != "S256")
    {
        fail("invalid_request", "only the S256 code challenge method is served");
        return nullptr;
    }
    if (cl->is_public() && challenge.empty())
    {
        fail("invalid_request", "a public client must send a PKCE code challenge");
        return nullptr;
    }
    return cl;
}

void idp_run::login_page(const std::shared_ptr<conn>& c, const params& p, std::string_view error, int status)
{
    std::string hidden;
    for (const auto name : carried)
        if (const std::string_view v = param(p, name); !v.empty())
            hidden += "<input type=\"hidden\" name=\"" + std::string(name) + "\" value=\"" + html_escape(v) + "\">";
    const std::string host = url_host(m_issuer);
    const std::string body =
        "<h1>Sign in</h1><form method=\"post\">" + hidden +
        "<label for=\"u\">User</label><input id=\"u\" type=\"text\" name=\"username\" autocomplete=\"username\" "
        "autofocus required value=\"" + html_escape(param(p, "username")) +
        "\"><label for=\"p\">Password</label><input id=\"p\" type=\"password\" name=\"password\" "
        "autocomplete=\"current-password\" required><div class=\"row\"><input id=\"r\" type=\"checkbox\" "
        "name=\"remember\" value=\"1\"><label for=\"r\" style=\"margin:0\">Stay signed in</label></div>" +
        (error.empty() ? std::string() : "<p class=\"err\">" + html_escape(error) + "</p>") +
        "<button type=\"submit\">Sign in</button></form><p class=\"small\">" + html_escape(host) + "</p>";
    respond(c, status, "text/html; charset=utf-8", page("Sign in", body));
}

void idp_run::authorize(const std::shared_ptr<conn>& c, const request& rq)
{
    const params p = parse_form(rq.query);
    const bool oauth = rq.path == "/authorize";
    if (oauth)
    {
        bool answered = false;
        if (!checked_client(c, p, answered))
            return;
    }
    else if (const std::string_view rd = param(p, "rd"); !rd.empty() && !return_allowed(rd, m_issuer, m_cookie_domain))
    {
        respond(c, 400, "text/html; charset=utf-8",
                page("Sign-in refused", "<h1>This sign-in cannot go on</h1><p class=\"small\">The page asked to "
                                        "return to an address outside this provider's domain.</p>"));
        return;
    }
    if (const account* who = param(p, "prompt") != "login" ? session_of(rq) : nullptr)
    {
        grant(c, p, *who, {});
        return;
    }
    login_page(c, p, {}, 200);
}

void idp_run::sign_in(const std::shared_ptr<conn>& c, const request& rq)
{
    params p = parse_form(rq.body);
    // The authorize parameters travel in the form; a POST to /authorize may also carry them in its query.
    for (auto& kv : parse_form(rq.query))
        if (param(p, kv.first).empty())
            p.push_back(std::move(kv));
    if (rq.path == "/authorize")
    {
        bool answered = false;
        if (!checked_client(c, p, answered))
            return;
    }
    else if (const std::string_view rd = param(p, "rd"); !rd.empty() && !return_allowed(rd, m_issuer, m_cookie_domain))
    {
        respond(c, 400, "text/plain", "the return address is outside this provider's domain\n");
        return;
    }
    const std::string user(param(p, "username"));
    const std::string password(param(p, "password"));
    if (user.empty() || password.empty())
    {
        login_page(c, p, "Give your user and password.", 400);
        return;
    }
    const std::string ip = client_ip(*c, rq);
    if (barred(ip, wall::now_sec()))
    {
        ++m_c.barred;
        login_page(c, p, "Too many failed sign-ins from here; try again in a quarter of an hour.", 429);
        return;
    }
    const account* who = m_accounts.by_name(user);
    std::weak_ptr<conn> weak = c;
    const bool remember = param(p, "remember") == "1";
    c->waiting = true;
    check_password(who, password, [this, weak, p = std::move(p), ip, user, remember](bool ok)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        const account* a = m_accounts.by_name(user);
        if (!ok || !a || a->disabled())
        {
            ++m_c.refused;
            LOG_INFO(("idp " + std::string(m_owner.get_name()) + ": a sign-in as \"" + user + "\" from " + ip +
                      " was refused").c_str());
            missed(ip, wall::now_sec(), [this, weak, p]
            {
                auto c2 = weak.lock();
                if (!c2 || c2->dead)
                    return;
                c2->waiting = false;
                login_page(c2, p, "The user or password is not right.", 401);
                m_http.resume(c2);
            });
            return;
        }
        cc->waiting = false;
        if (a->field("reset") == "1")
            reset_page(cc, p, {}, 200);
        else
        {
            ++m_c.sign_ins;
            grant(cc, p, *a, session_cookie(*a, remember));
        }
        m_http.resume(cc);
    });
}

void idp_run::check_password(const account* who, std::string_view password, std::function<void(bool)> then)
{
    // An unknown user or one without a password costs a hash all the same, so the time says nothing about who exists.
    static const std::string dummy = socketley::storage::password_hash("socketley-no-such-user");
    const std::string hash(who && !who->field("password").empty() ? who->field("password") : std::string_view(dummy));
    const bool real = who && !who->field("password").empty();
    if (!m_hash.enabled())
    {
        const bool ok = socketley::storage::password_matches(hash, password);
        then(real && ok);
        return;
    }
    {
        std::lock_guard<std::mutex> g(m_checks->mu);
        m_checks->waiting.push_back({hash, std::string(password), real, std::move(then)});
    }
    // A piece of work for each check, which takes whatever checks wait, so the thread that is free makes them together.
    m_hash.submit(m_hash.next_lane(), [checks = m_checks, pool = &m_hash, alive = m_alive]
    {
        std::vector<password_checks::check> batch;
        {
            std::lock_guard<std::mutex> g(checks->mu);
            while (!checks->waiting.empty() && batch.size() < socketley::storage::scrypt::max_batch)
            {
                batch.push_back(std::move(checks->waiting.front()));
                checks->waiting.pop_front();
            }
        }
        std::vector<socketley::storage::password_check> asked;
        for (const auto& c : batch)
            asked.push_back({c.hash, c.password});
        socketley::storage::password_matches_many(asked);
        for (size_t i = 0; i < batch.size(); ++i)
            pool->post_done([alive, then = std::move(batch[i].then), ok = batch[i].real && asked[i].matches] {
                if (*alive)
                    then(ok);
            });
    }, [] {});
}

void idp_run::hash_password(std::string_view password, std::function<void(std::string)> then)
{
    auto result = std::make_shared<std::string>();
    auto work = [pw = std::string(password), result] { *result = socketley::storage::password_hash(pw); };
    m_hash.submit(m_hash.next_lane(), std::move(work), [alive = m_alive, result, then = std::move(then)] {
        if (*alive)
            then(std::move(*result));
    });
}

void idp_run::grant(const std::shared_ptr<conn>& c, const params& p, const account& who, std::string_view set_cookie)
{
    const client* cl = find_client(param(p, "client_id"));
    // A sign-in for a page behind a proxy, or for this provider itself, rather than for a client.
    if (!cl)
    {
        const std::string_view rd = param(p, "rd");
        redirect(c, rd.empty() ? std::string_view("/") : rd, set_cookie);
        return;
    }
    code_entry e;
    e.client_id = cl->id;
    e.redirect.assign(param(p, "redirect_uri"));
    e.sub = who.id;
    e.nonce.assign(param(p, "nonce"));
    e.scope.assign(param(p, "scope"));
    e.challenge.assign(param(p, "code_challenge"));
    const int64_t now = wall::now_sec();
    e.auth_time = now;
    e.expires = now + code_secs;
    // Named by the shard that keeps it, which the exchange is taken to.
    const std::string token = random_b64url(32);
    const std::string code = m_shards > 1 && !token.empty() ? std::to_string(m_shard) + "." + token : token;
    if (code.empty())
    {
        respond(c, 503, "text/plain", "no randomness for a code\n");
        return;
    }
    m_codes.emplace(code, std::move(e));
    ++m_c.codes;
    arm_tick();
    const std::string_view redirect_uri = param(p, "redirect_uri");
    const std::string_view state = param(p, "state");
    std::string to(redirect_uri);
    to += redirect_uri.find('?') == std::string_view::npos ? '?' : '&';
    to += "code=" + url_encode(code);
    if (!state.empty())
        to += "&state=" + url_encode(state);
    to += "&iss=" + url_encode(m_issuer);
    redirect(c, to, set_cookie);
}

// ─── Tokens ─────────────────────────────────────────────────────────────────

void idp_run::issue_tokens(const std::shared_ptr<conn>& c, const client& cl, const code_entry& e, const account& who)
{
    const int64_t now = wall::now_sec();
    const std::string jti = random_b64url(32);
    const std::string profile = profile_claims(who);
    const std::string aud = socketley::json::quote(cl.id);
    const std::string scope = socketley::json::quote(e.scope);
    const std::string exp = std::to_string(now + token_secs);
    std::string common;
    common.reserve(256);
    common.append("\"iss\":").append(m_issuer_json).append(",\"sub\":").append(socketley::json::quote(who.id));
    common.append(",\"iat\":").append(std::to_string(now)).append(",\"iat_ms\":").append(std::to_string(wall::now_ms()));
    common.append(",\"auth_time\":").append(std::to_string(e.auth_time));
    // Each token's claims made in the one string, the common ones first.
    std::string claims;
    claims.reserve(common.size() + profile.size() + 256);
    claims.assign(common).append(",\"aud\":").append(aud).append(",\"exp\":").append(exp);
    if (!e.nonce.empty())
        claims.append(",\"nonce\":").append(socketley::json::quote(e.nonce));
    claims.append(profile);
    const std::string id_token = sign_token(m_key, m_kid, "JWT", claims);
    claims.assign(common).append(",\"aud\":").append(aud).append(",\"client_id\":").append(aud);
    claims.append(",\"scope\":").append(scope).append(",\"jti\":\"").append(jti).append("\",\"exp\":").append(exp);
    claims.append(profile);
    const std::string access = sign_token(m_key, m_kid, "at+jwt", claims);
    std::string refresh;
    if (has_scope(e.scope, "offline_access") || !cl.is_public())
    {
        claims.assign(common).append(",\"aud\":\"refresh\",\"client_id\":").append(aud).append(",\"scope\":");
        claims.append(scope).append(",\"exp\":").append(std::to_string(now + refresh_secs));
        refresh = sign_secret_token(m_secret, "refresh+jwt", claims);
    }
    // A token is base64url and dots, which a JSON string holds as they are.
    std::string body;
    body.reserve(access.size() + id_token.size() + refresh.size() + scope.size() + 128);
    body.append("{\"access_token\":\"").append(access).append("\",\"token_type\":\"Bearer\",\"expires_in\":");
    body.append(std::to_string(token_secs)).append(",\"id_token\":\"").append(id_token).append("\",\"scope\":");
    body.append(scope);
    if (!refresh.empty())
        body.append(",\"refresh_token\":\"").append(refresh).append("\"");
    body += '}';
    ++m_c.tokens;
    respond(c, 200, "application/json", body, "Access-Control-Allow-Origin: *\r\n");
}

void idp_run::token(const std::shared_ptr<conn>& c, const request& rq)
{
    const params p = parse_form(rq.body);
    // The client, by HTTP Basic or by the form, and a public one by its id alone.
    std::string id(param(p, "client_id")), secret(param(p, "client_secret"));
    bool basic = false;
    if (std::string_view cred; http_auth_credentials(rq.authorization, "basic", cred))
    {
        std::string decoded;
        if (base64::decode(cred, decoded))
            if (const size_t colon = decoded.find(':'); colon != std::string::npos)
            {
                // RFC 6749 2.3.1 form-encodes both halves before they are joined.
                const params half = parse_form("i=" + decoded.substr(0, colon) + "&s=" + decoded.substr(colon + 1));
                id.assign(param(half, "i"));
                secret.assign(param(half, "s"));
                basic = true;
            }
    }
    const client* cl = find_client(id);
    const bool authenticated =
        cl && (cl->is_public() ? secret.empty() : crypto::secure_equal(secret, cl->secret));
    if (!authenticated)
    {
        json_error(c, 401, "invalid_client", "the client is not known or its secret is not right",
                   basic ? "WWW-Authenticate: Basic realm=\"" + m_issuer + "\"\r\n" : std::string());
        return;
    }
    const std::string_view grant = param(p, "grant_type");
    if (grant == "authorization_code")
    {
        const std::string code(param(p, "code"));
        uint32_t keeper = m_shard;
        if (code_shard(code, m_shards, keeper) && keeper != m_shard)
        {
            std::weak_ptr<conn> weak = c;
            const bool asked = cross(keeper, shard_call{shard_call::redeem, code, {}, 0},
                                     [this, weak, p, client_id = cl->id](bool answered, std::string_view reply)
            {
                auto cc = weak.lock();
                if (!cc || cc->dead)
                    return;
                cc->waiting = false;
                bool found = false;
                code_entry e;
                if (!answered || !decode_code(reply, found, e))
                    found = false;
                // The clients file may have been read again meanwhile, so the client is found again by its id.
                if (const client* again = find_client(client_id))
                    redeemed(cc, *again, p, found, e);
                else
                    json_error(cc, 401, "invalid_client", "the client is not known or its secret is not right");
                m_http.resume(cc);
            });
            if (asked)
                c->waiting = true;
            else
                json_error(c, 400, "invalid_grant", "the code is not known, was used, or has expired");
            return;
        }
        const auto it = m_codes.find(code);
        if (it == m_codes.end())
        {
            redeemed(c, *cl, p, false, {});
            return;
        }
        // Good once, whatever this exchange comes to.
        const code_entry e = std::move(it->second);
        m_codes.erase(it);
        redeemed(c, *cl, p, true, e);
        return;
    }
    if (grant == "refresh_token")
    {
        claims r;
        std::string why;
        if (!verify_secret_token(m_secret, "refresh+jwt", m_issuer, param(p, "refresh_token"), wall::now_sec(), r, why) ||
            claim(r, "aud") != "refresh" || claim(r, "client_id") != cl->id)
        {
            json_error(c, 400, "invalid_grant", "the refresh token is not one this client may use");
            return;
        }
        // The account is looked at again, so one removed, disabled, made to reset its password or signed out
        // everywhere since gets nothing.
        const account* who = m_accounts.by_id(claim(r, "sub"));
        if (!who || who->disabled() || who->field("reset") == "1" || !still_signed_in(*who, issued_ms(r)))
        {
            json_error(c, 400, "invalid_grant", "the account is no longer one that may sign in");
            return;
        }
        code_entry e;
        e.sub = who->id;
        e.scope = claim(r, "scope");
        e.auth_time = claim_int(r, "auth_time");
        ++m_c.refreshes;
        issue_tokens(c, *cl, e, *who);
        return;
    }
    json_error(c, 400, "unsupported_grant_type", "only authorization_code and refresh_token are served");
}

void idp_run::redeemed(const std::shared_ptr<conn>& c, const client& cl, const params& p, bool found,
                       const code_entry& e)
{
    if (!found)
    {
        json_error(c, 400, "invalid_grant", "the code is not known, was used, or has expired");
        return;
    }
    if (e.expires <= wall::now_sec() || e.client_id != cl.id || e.redirect != param(p, "redirect_uri"))
    {
        json_error(c, 400, "invalid_grant", "the code was not given to this client for this redirect");
        return;
    }
    if (!e.challenge.empty() && !pkce_matches(param(p, "code_verifier"), e.challenge))
    {
        json_error(c, 400, "invalid_grant", "the code verifier does not match the challenge");
        return;
    }
    const account* who = m_accounts.by_id(e.sub);
    if (!who || who->disabled())
    {
        json_error(c, 400, "invalid_grant", "the account is no longer one that may sign in");
        return;
    }
    issue_tokens(c, cl, e, *who);
}

void idp_run::userinfo(const std::shared_ptr<conn>& c, const request& rq)
{
    std::string_view token;
    if (!http_auth_credentials(rq.authorization, "bearer", token))
    {
        json_error(c, 401, "invalid_token", "a bearer access token is required",
                   "WWW-Authenticate: Bearer error=\"invalid_token\"\r\n");
        return;
    }
    claims a;
    std::string why;
    if (!m_verified.verify(m_key, m_kid, "at+jwt", m_issuer, token, wall::now_sec(), a, why) ||
        !has_scope(claim(a, "scope"), "openid"))
    {
        json_error(c, 401, "invalid_token", "the access token is not valid: " + why,
                   "WWW-Authenticate: Bearer error=\"invalid_token\"\r\n");
        return;
    }
    // Answered from the account as it is now, which is what userinfo is for beside the token's copy.
    const account* who = m_accounts.by_id(claim(a, "sub"));
    if (!who || who->disabled() || !still_signed_in(*who, issued_ms(a)))
    {
        json_error(c, 401, "invalid_token", "the account is no longer one that may sign in",
                   "WWW-Authenticate: Bearer error=\"invalid_token\"\r\n");
        return;
    }
    ++m_c.userinfo;
    respond(c, 200, "application/json", "{\"sub\":" + socketley::json::quote(who->id) + profile_claims(*who) + "}",
            "Access-Control-Allow-Origin: *\r\n");
}

void idp_run::logout(const std::shared_ptr<conn>& c, const request& rq)
{
    params p = parse_form(rq.query);
    for (auto& kv : parse_form(rq.body))
        p.push_back(std::move(kv));
    const std::string_view to = param(p, "post_logout_redirect_uri");
    bool known = false;
    for (const auto& cl : m_clients)
        if (cl.allows(to))
            known = true;
    if (!to.empty() && (known || return_allowed(to, m_issuer, m_cookie_domain)))
    {
        const std::string_view state = param(p, "state");
        std::string loc(to);
        if (!state.empty())
            loc += std::string(to.find('?') == std::string_view::npos ? "?" : "&") + "state=" + url_encode(state);
        redirect(c, loc, clear_cookie());
        return;
    }
    respond(c, 200, "text/html; charset=utf-8",
            page("Signed out", "<h1>Signed out</h1><p class=\"small\">You can close this page.</p>"), clear_cookie());
}

void idp_run::home(const std::shared_ptr<conn>& c, const request& rq)
{
    const account* who = session_of(rq);
    if (!who)
    {
        login_page(c, {}, {}, 200);
        return;
    }
    const std::string_view name = who->field("name").empty() ? who->username() : who->field("name");
    respond(c, 200, "text/html; charset=utf-8",
            page("Signed in", "<h1>Signed in</h1><p>as <b>" + html_escape(name) + "</b></p><p><a href=\"/account\">"
                              "Your account</a></p><form method=\"post\" action=\"/logout\"><button "
                              "type=\"submit\">Sign out</button></form>"));
}

void idp_run::reset_page(const std::shared_ptr<conn>& c, const params& p, std::string_view error, int status)
{
    std::string hidden;
    for (const auto name : carried)
        if (const std::string_view v = param(p, name); !v.empty())
            hidden += "<input type=\"hidden\" name=\"" + std::string(name) + "\" value=\"" + html_escape(v) + "\">";
    const std::string body =
        "<h1>Set a new password</h1><p class=\"small\">Your password must be set again before you go on.</p>"
        "<form method=\"post\" action=\"/account/password\">" + hidden +
        "<input type=\"hidden\" name=\"username\" value=\"" + html_escape(param(p, "username")) +
        "\"><label for=\"o\">Current password</label><input id=\"o\" type=\"password\" name=\"current\" "
        "autocomplete=\"current-password\" required><label for=\"n\">New password</label><input id=\"n\" "
        "type=\"password\" name=\"new\" autocomplete=\"new-password\" required>" +
        (error.empty() ? std::string() : "<p class=\"err\">" + html_escape(error) + "</p>") +
        "<button type=\"submit\">Set password</button></form>";
    respond(c, status, "text/html; charset=utf-8", page("Set a new password", body));
}

void idp_run::account_page(const std::shared_ptr<conn>& c, const request& rq, std::string_view note,
                           std::string_view error, int status)
{
    const account* who = session_of(rq);
    if (!who)
    {
        redirect(c, "/login?rd=" + url_encode("/account"));
        return;
    }
    const std::string body =
        "<h1>Your account</h1><p class=\"small\">Signed in as <b>" + html_escape(who->username()) + "</b></p>" +
        (note.empty() ? std::string() : "<p class=\"small\">" + html_escape(note) + "</p>") +
        (error.empty() ? std::string() : "<p class=\"err\">" + html_escape(error) + "</p>") +
        "<form method=\"post\" action=\"/account\"><label for=\"dn\">Name</label><input id=\"dn\" type=\"text\" "
        "name=\"name\" value=\"" + html_escape(who->field("name")) + "\"><label for=\"em\">E-mail</label><input "
        "id=\"em\" type=\"text\" name=\"email\" value=\"" + html_escape(who->field("email")) +
        "\"><button type=\"submit\">Save</button></form><form method=\"post\" action=\"/account/password\"><label "
        "for=\"o\">Current password</label><input id=\"o\" type=\"password\" name=\"current\" autocomplete=\""
        "current-password\" required><label for=\"n\">New password</label><input id=\"n\" type=\"password\" "
        "name=\"new\" autocomplete=\"new-password\" required><button type=\"submit\">Change password</button></form>"
        "<form method=\"post\" action=\"/account/everywhere\"><button type=\"submit\">Sign out everywhere</button>"
        "</form>";
    respond(c, status, "text/html; charset=utf-8", page("Your account", body));
}

void idp_run::account_post(const std::shared_ptr<conn>& c, const request& rq)
{
    const account* who = session_of(rq);
    if (!who)
    {
        redirect(c, "/login?rd=" + url_encode("/account"));
        return;
    }
    std::weak_ptr<conn> weak = c;
    c->waiting = true;
    if (rq.path == "/account/everywhere")
    {
        // Every session and refresh token given before now stops holding, this browser's too.
        update_account(who->id, {{"revoked_before", std::to_string(wall::now_ms())}},
                       [this, weak, rq](bool ok, const std::string& why)
        {
            auto cc = weak.lock();
            if (!cc || cc->dead)
                return;
            cc->waiting = false;
            if (!ok)
                account_page(cc, rq, {}, why, 500);
            else
                respond(cc, 200, "text/html; charset=utf-8",
                        page("Signed out", "<h1>Signed out everywhere</h1><p class=\"small\">Every session of this "
                                           "account has ended.</p>"),
                        clear_cookie());
            m_http.resume(cc);
        });
        return;
    }
    const params p = parse_form(rq.body);
    update_account(who->id, {{"name", std::string(param(p, "name"))}, {"email", std::string(param(p, "email"))}},
                   [this, weak, rq](bool ok, const std::string& why)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        cc->waiting = false;
        if (!ok)
            account_page(cc, rq, {}, why, 400);
        else
            account_page(cc, rq, "Saved.", {}, 200);
        m_http.resume(cc);
    });
}

void idp_run::password_post(const std::shared_ptr<conn>& c, const request& rq)
{
    params p = parse_form(rq.body);
    // Signed in, the account is the session's; at a forced reset it is the one named, proven by its old password.
    const account* who = session_of(rq);
    const bool from_reset = !who;
    if (!who)
        who = m_accounts.by_name(param(p, "username"));
    const std::string ip = client_ip(*c, rq);
    if (barred(ip, wall::now_sec()))
    {
        ++m_c.barred;
        respond(c, 429, "text/plain", "Too many failed sign-ins from here; try again in a quarter of an hour.\n");
        return;
    }
    const std::string current(param(p, "current"));
    const std::string fresh(param(p, "new"));
    const std::string id = who ? who->id : std::string();
    const std::string problem = socketley::storage::password_problem(fresh, who ? who->username() : "");
    std::weak_ptr<conn> weak = c;
    c->waiting = true;
    check_password(who, current, [this, weak, rq, p, ip, id, fresh, problem, from_reset](bool ok)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        const account* a = m_accounts.by_id(id);
        auto fail = [&](std::string_view msg, int status)
        {
            cc->waiting = false;
            if (from_reset)
                reset_page(cc, p, msg, status);
            else
                account_page(cc, rq, {}, msg, status);
            m_http.resume(cc);
        };
        if (!ok || !a || a->disabled())
        {
            missed(ip, wall::now_sec(), [this, weak, rq, p, from_reset]
            {
                auto c2 = weak.lock();
                if (!c2 || c2->dead)
                    return;
                c2->waiting = false;
                if (from_reset)
                    reset_page(c2, p, "The current password is not right.", 401);
                else
                    account_page(c2, rq, {}, "The current password is not right.", 401);
                m_http.resume(c2);
            });
            return;
        }
        if (!problem.empty())
        {
            fail(problem, 400);
            return;
        }
        hash_password(fresh, [this, weak, p, id, from_reset](std::string hash)
        {
            auto c2 = weak.lock();
            if (!c2 || c2->dead)
                return;
            auto refused = [this, &c2]
            {
                c2->waiting = false;
                respond(c2, 500, "text/plain", "the password could not be kept\n");
                m_http.resume(c2);
            };
            if (hash.empty() || !m_accounts.by_id(id))
            {
                refused();
                return;
            }
            // A new password ends the sessions given before it, as a stolen one would want.
            update_account(id, {{"password", hash}, {"reset", ""}, {"password_set", std::to_string(wall::now_sec())},
                                {"revoked_before", std::to_string(wall::now_ms())}},
                           [this, weak, p, id, from_reset](bool ok, const std::string&)
            {
                auto c3 = weak.lock();
                if (!c3 || c3->dead)
                    return;
                c3->waiting = false;
                const account* a2 = ok ? m_accounts.by_id(id) : nullptr;
                if (!a2)
                    respond(c3, 500, "text/plain", "the password could not be kept\n");
                else
                {
                    ++m_c.sign_ins;
                    if (from_reset)
                        grant(c3, p, *a2, session_cookie(*a2, false));
                    else
                        respond(c3, 200, "text/html; charset=utf-8",
                                page("Password changed", "<h1>Password changed</h1><p class=\"small\">Every other "
                                                         "session has ended.</p><p><a href=\"/account\">Your "
                                                         "account</a></p>"),
                                session_cookie(*a2, false));
                }
                m_http.resume(c3);
            });
        });
    });
}

}   // namespace socketley::idp

// ─── socketley idp-user ─────────────────────────────────────────────────────

namespace socketley::idp
{

void idp_run::answer_command(uint64_t ticket, std::string_view text)
{
    // A change a command made is said to the other shards before it is answered, so none answers from before it.
    publish_accounts();
    if (auto* mgr = m_owner.get_runtime_manager())
        mgr->requests().complete_deferred(ticket, request_status::ok, text);
}

void idp_run::command(uint64_t ticket, std::string_view payload)
{
    std::vector<std::string> args;
    payload.remove_prefix(command_marker.size());
    // A page of a storage's users the daemon fetched for `import`, raw after its first line.
    if (constexpr std::string_view page = "import-data\n"; payload.starts_with(page))
    {
        import_page(ticket, payload.substr(page.size()));
        return;
    }
    while (!payload.empty())
    {
        args.emplace_back(take_item(payload, '\n'));
    }
    if (args.empty())
    {
        answer_command(ticket, "error: idp-user needs an action");
        return;
    }
    const std::string action = args[0];
    if (action == "list")
    {
        std::string out;
        for (const account* a : m_accounts.all())
            out += std::string(a->username()) + "\t" + a->id + "\t" +
                   (a->field("groups").empty() ? "-" : std::string(a->field("groups"))) +
                   (a->disabled() ? "\tdisabled" : "") + (a->field("password").empty() ? "\tno-password" : "") + "\n";
        answer_command(ticket, out);
        return;
    }
    if (args.size() < 2)
    {
        answer_command(ticket, "error: idp-user " + action + " needs a username");
        return;
    }
    const std::string user = args[1];
    if (action == "add")
    {
        field_list fields{{"username", user}, {"created", std::to_string(wall::now_sec())}};
        std::string password;
        for (size_t i = 2; i < args.size(); ++i)
        {
            const std::string& a = args[i];
            const bool more = i + 1 < args.size();
            if (a == "--password" && more)
                password = args[++i];
            else if (a == "--name" && more)
                fields.emplace_back("name", args[++i]);
            else if (a == "--email" && more)
                fields.emplace_back("email", args[++i]);
            else if (a == "--groups" && more)
                fields.emplace_back("groups", args[++i]);
            else if (a == "--reset")
                fields.emplace_back("reset", "1");
            else if (a == "--set" && more)
            {
                const std::string& kv = args[++i];
                const size_t eq = kv.find('=');
                if (eq == std::string::npos || eq == 0)
                {
                    answer_command(ticket, "error: --set takes name=value");
                    return;
                }
                fields.emplace_back(kv.substr(0, eq), kv.substr(eq + 1));
            }
            else
            {
                answer_command(ticket, "error: idp-user add takes --password, --name, --email, --groups, --set "
                                       "name=value and --reset, not '" + a + "'");
                return;
            }
        }
        for (const auto& [k, v] : fields)
            if (k == "password" || k == "revoked_before")
            {
                answer_command(ticket, "error: the field " + k + " is set by the provider, not by --set");
                return;
            }
        if (m_accounts.by_name(user))
        {
            answer_command(ticket, "error: the username \"" + user + "\" is taken");
            return;
        }
        if (!password.empty())
            if (const std::string problem = socketley::storage::password_problem(password, user); !problem.empty())
            {
                answer_command(ticket, "error: " + problem);
                return;
            }
        auto create = [this, ticket](field_list f)
        {
            std::string id, why;
            if (!m_accounts.create(f, id, why))
                answer_command(ticket, "error: " + why);
            else
                answer_command(ticket, id + "\n");
        };
        if (password.empty())
            create(std::move(fields));
        else
            hash_password(password, [create, fields = std::move(fields)](std::string hash) mutable {
                fields.emplace_back("password", std::move(hash));
                fields.emplace_back("password_set", std::to_string(wall::now_sec()));
                create(std::move(fields));
            });
        return;
    }
    const account* who = m_accounts.by_name(user);
    if (!who)
    {
        answer_command(ticket, "error: no account \"" + user + "\"");
        return;
    }
    const std::string id = who->id;
    auto apply = [this, ticket, id](const field_list& f, std::string_view done)
    {
        std::string why;
        if (!m_accounts.update(id, f, why))
            answer_command(ticket, "error: " + why);
        else
            answer_command(ticket, done);
    };
    if (action == "passwd")
    {
        std::string password;
        bool reset = false;
        for (size_t i = 2; i < args.size(); ++i)
            if (args[i] == "--password" && i + 1 < args.size())
                password = args[++i];
            else if (args[i] == "--reset")
                reset = true;
            else
            {
                answer_command(ticket, "error: idp-user passwd takes --password and --reset, not '" + args[i] + "'");
                return;
            }
        if (const std::string problem = socketley::storage::password_problem(password, user); !problem.empty())
        {
            answer_command(ticket, "error: " + problem);
            return;
        }
        hash_password(password, [apply, reset](std::string hash) {
            const std::string now = std::to_string(wall::now_sec());
            apply({{"password", std::move(hash)}, {"password_set", now}, {"revoked_before", std::to_string(wall::now_ms())},
                   {"reset", reset ? "1" : ""}},
                  "");
        });
        return;
    }
    if (action == "set")
    {
        field_list f;
        for (size_t i = 2; i < args.size(); ++i)
        {
            const size_t eq = args[i].find('=');
            if (eq == std::string::npos || eq == 0)
            {
                answer_command(ticket, "error: set takes name=value, an empty value to remove the field");
                return;
            }
            std::string k = args[i].substr(0, eq);
            if (k == "password" || k == "revoked_before")
            {
                answer_command(ticket, "error: the field " + k + " is set by the provider; use passwd or logout");
                return;
            }
            f.emplace_back(std::move(k), args[i].substr(eq + 1));
        }
        if (f.empty())
        {
            answer_command(ticket, "error: set needs name=value");
            return;
        }
        apply(f, "");
        return;
    }
    if (action == "disable" || action == "enable")
    {
        apply({{"disabled", action == "disable" ? "1" : ""}}, "");
        return;
    }
    if (action == "logout")
    {
        apply({{"revoked_before", std::to_string(wall::now_ms())}}, "");
        return;
    }
    if (action == "remove")
    {
        std::string why;
        if (!m_accounts.remove(id, why))
            answer_command(ticket, "error: " + why);
        else
            answer_command(ticket, "");
        return;
    }
    if (action == "show")
    {
        std::string out = "id: " + id + "\n";
        for (const auto& [k, v] : who->fields)
            out += k + ": " + (k == "password" ? std::string("(set)") : v) + "\n";
        answer_command(ticket, out);
        return;
    }
    answer_command(ticket, "error: unknown action '" + action +
                               "'; idp-user takes add, passwd, set, disable, enable, logout, remove, show, list "
                               "and import");
}

void idp_run::import_page(uint64_t ticket, std::string_view reply)
{
    storage_rpc::reply r;
    if (!storage_rpc::decode(reply, storage_rpc::op::users, r))
    {
        answer_command(ticket, "error: the answer is not a storage's list of users");
        return;
    }
    if (!r.ok)
    {
        answer_command(ticket, "error: " + r.message);
        return;
    }
    // A user is taken with the password hash it has there, which is the same scrypt this provider checks; one whose
    // name is an account here already is left as the account is.
    size_t kept = 0;
    std::vector<field_list> fresh;
    for (const auto& u : r.objects)
    {
        if (m_accounts.by_name(u.key))
        {
            ++kept;
            continue;
        }
        field_list f{{"username", u.key}, {"created", std::to_string(wall::now_sec())}};
        for (const auto& [k, v] : u.metadata)
        {
            if (v.empty())
                continue;
            if (k == "admin")
            {
                if (v == "1")
                    f.emplace_back("groups", "admins");
            }
            else if (k == "name" || k == "email" || k == "password" || k == "reset")
                f.emplace_back(k, v);
        }
        fresh.push_back(std::move(f));
    }
    std::string errors;
    const size_t added = m_accounts.create_many(fresh, errors);
    answer_command(ticket, std::to_string(added) + " " + std::to_string(kept) + "\n" + errors);
}

// ─── Shards ─────────────────────────────────────────────────────────────────

void idp_run::publish_accounts()
{
    if (m_shards <= 1 || m_reader)
        return;
    const uint64_t id = m_accounts.journal_id(), end = m_accounts.journal_end();
    if (id == m_told_id && end == m_told_end)
        return;
    m_told_id = id;
    m_told_end = end;
    m_owner.shard_stats_table().publish_words(end, id);
}

void idp_run::catch_up()
{
    if (!m_reader)
        return;
    // The length before the journal it is of, since shard 0 says the journal first.
    auto& table = m_owner.shard_stats_table();
    const uint64_t end = table.word_at(0, 0);
    const uint64_t id = table.word_at(0, 1);
    if (m_accounts.follow(id, end))
        return;
    // Shard 0 has begun a new journal behind a snapshot, which is read whole.
    ++m_c.reopened;
    std::string why;
    if (!m_accounts.follow_open(idp_accounts_dir(m_owner.get_name()), why))
    {
        // Said once a reason, since it is tried again at the next request.
        if (why != m_follow_error)
            LOG_WARN(("idp " + std::string(m_owner.get_name()) + " shard " + std::to_string(m_shard) +
                      ": shard 0's accounts could not be read: " + why)
                         .c_str());
        m_follow_error = why;
        return;
    }
    m_follow_error.clear();
    m_accounts.follow(id, end);
}

bool idp_run::cross(uint32_t shard, const shard_call& call, std::function<void(bool, std::string_view)> then)
{
    auto* mgr = m_owner.get_runtime_manager();
    if (!mgr)
        return false;
    const uint64_t cookie = m_next_cookie++;
    m_crossed.emplace(cookie, std::move(then));
    if (!mgr->requests().post(this, cookie, shard_target(m_owner.get_name(), shard), encode_call(call)))
    {
        m_crossed.erase(cookie);
        return false;
    }
    ++m_c.crossed;
    return true;
}

void idp_run::on_request_reply(uint64_t cookie, request_status st, std::string_view reply)
{
    // An answer nobody waits for any more, since this shard stopped.
    const auto it = m_crossed.find(cookie);
    if (it == m_crossed.end())
        return;
    auto then = std::move(it->second);
    m_crossed.erase(it);
    then(st == request_status::ok, reply);
}

void idp_run::update_account(const std::string& id, field_list fields,
                             std::function<void(bool, const std::string&)> then)
{
    if (!m_reader)
    {
        std::string why;
        const bool ok = m_accounts.update(id, fields, why);
        publish_accounts();
        then(ok, why);
        return;
    }
    auto answered = [this, then](bool delivered, std::string_view reply)
    {
        bool ok = false;
        std::string why;
        if (!delivered || !decode_result(reply, ok, why))
        {
            ok = false;
            why = "shard 0, which keeps the accounts, did not answer";
        }
        // Shard 0 said the change before it answered, so it is read here before anything is answered from it.
        catch_up();
        then(ok, why);
    };
    if (!cross(0, shard_call{shard_call::update, id, std::move(fields), 0}, answered))
        then(false, "shard 0, which keeps the accounts, cannot be asked");
}

void idp_run::shard_answer(uint64_t ticket, std::string_view payload)
{
    auto* mgr = m_owner.get_runtime_manager();
    if (!mgr)
        return;
    shard_call call;
    if (!decode_call(payload, call))
    {
        mgr->requests().complete_deferred(ticket, request_status::ok, {});
        return;
    }
    ++m_c.crossings_served;
    switch (call.op)
    {
        case shard_call::redeem:
        {
            // Good once, whatever the exchange at the asking shard comes to.
            const auto it = m_codes.find(call.key);
            if (it == m_codes.end())
            {
                mgr->requests().complete_deferred(ticket, request_status::ok, encode_code(nullptr));
                return;
            }
            const std::string reply = encode_code(&it->second);
            m_codes.erase(it);
            mgr->requests().complete_deferred(ticket, request_status::ok, reply);
            return;
        }
        case shard_call::update:
        {
            std::string why;
            const bool ok = !m_reader && m_accounts.update(call.key, call.fields, why);
            if (m_reader)
                why = "the accounts are written by shard 0";
            publish_accounts();
            mgr->requests().complete_deferred(ticket, request_status::ok, encode_result(ok, why));
            return;
        }
        case shard_call::miss:
            m_misses[call.key].at.push_back(call.at);
            arm_tick();
            mgr->requests().complete_deferred(ticket, request_status::ok, {});
            return;
    }
    mgr->requests().complete_deferred(ticket, request_status::ok, {});
}

}   // namespace socketley::idp
