#include "idp_run.h"
#include "idp_totp.h"
#include "../../shared/util/qr_code.h"

#include "../../shared/util/ascii.h"

#include <algorithm>
#include <charconv>
#include <cstring>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sched.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "idp_instance.h"
#include "../../shared/http/http_framing.h"
#include "../../shared/crypto/ed25519.h"
#include "../../shared/crypto/jws.h"
#include "../../shared/crypto/ssh_cert.h"
#include "../../shared/util/logging.h"
#include "../../shared/runtime/runtime_manager.h"
#include "../../shared/ipc/shard_target.h"
#include "../../shared/storage/storage_rpc.h"
#include "../storage/password_hash.h"
#include "../storage/scrypt.h"
#include "../storage/storage_ui_kit.h"
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
constexpr int64_t device_secs   = 600;
constexpr int64_t device_poll_s = 5;
constexpr size_t  max_devices   = 10000;
constexpr std::string_view device_grant = "urn:ietf:params:oauth:grant-type:device_code";
constexpr int64_t token_secs    = 3600;
constexpr int64_t refresh_secs  = 30 * 86400;
constexpr int64_t session_secs  = 12 * 3600;
constexpr int64_t remember_secs = 30 * 86400;
constexpr int64_t idle_secs     = 60;
constexpr size_t  max_head      = 16 * 1024;
constexpr size_t  max_body      = 16 * 1024;
constexpr size_t  max_conns     = 4096;
// What the endpoints a page's script calls say to every origin alike.
constexpr std::string_view any_origin = "Access-Control-Allow-Origin: *\r\n";
constexpr int     miss_limit    = 5;
// Failures at one IPv6 /48 before all of it is refused, sixteen /64s' worth, as a site is given 65536 of them.
constexpr int     network_limit = 16 * miss_limit;
// Failures at one account before each try waits, from 30 seconds to 5 minutes, and wrong codes likewise.
constexpr int     account_free  = 10;
constexpr int     code_free     = 5;
// Wrong codes one password step may be followed by before it must be given again.
constexpr int     code_tries    = 3;
constexpr int64_t known_secs    = 90 * 86400;
// The refresh token families an account keeps, the oldest given up past them: a field each, rt.<id> "<generation> <expires>".
constexpr size_t  max_families  = 32;
constexpr std::string_view family_prefix = "rt.";
// How long a sign-in buys SSH certificates for, refreshed tokens and all.
constexpr int64_t ssh_auth_secs = 12 * 3600;
// Why a change that waited on a field still holding a value was not made.
constexpr std::string_view changed_meanwhile = "the account changed meanwhile";

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

// A refresh token family's field read: the generation its newest token is, and when the family ends.
bool read_family(std::string_view v, uint64_t& generation, int64_t& expires)
{
    const size_t sp = v.find(' ');
    if (sp == std::string_view::npos)
        return false;
    const auto g = std::from_chars(v.data(), v.data() + sp, generation);
    const auto e = std::from_chars(v.data() + sp + 1, v.data() + v.size(), expires);
    return g.ec == std::errc{} && g.ptr == v.data() + sp && e.ec == std::errc{} && e.ptr == v.data() + v.size() &&
           generation > 0;
}

// The fields that remove `who`'s families that have ended, and its oldest past the most it keeps beside a new one.
field_list stale_families(const account& who, int64_t now)
{
    field_list out;
    std::vector<std::pair<int64_t, std::string>> live;
    for (const auto& [k, v] : who.fields)
    {
        if (!k.starts_with(family_prefix))
            continue;
        uint64_t g = 0;
        int64_t exp = 0;
        if (!read_family(v, g, exp) || exp <= now)
            out.emplace_back(k, "");
        else
            live.emplace_back(exp, k);
    }
    std::sort(live.begin(), live.end());
    for (size_t i = 0; i + max_families <= live.size(); ++i)
        out.emplace_back(live[i].second, "");
    return out;
}

// An account's app passwords, a line each: label, hash and when it was made, apart by tabs.
std::vector<std::string> app_password_lines(std::string_view field)
{
    std::vector<std::string> out;
    for (std::string_view rest = field; !rest.empty();)
    {
        const size_t nl = rest.find('\n');
        if (const std::string_view l = rest.substr(0, nl); !l.empty())
            out.emplace_back(l);
        rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
    }
    return out;
}

// Whether `lines` hold an app password labelled `label`.
bool has_app_password(const std::vector<std::string>& lines, std::string_view label)
{
    return std::any_of(lines.begin(), lines.end(),
                       [&](const std::string& l) { return std::string_view(l).substr(0, l.find('\t')) == label; });
}

// The storage interface's look, its sign-in card with the page's own forms in it, so a sign-in reads as one product.
std::string page(std::string_view title, std::string_view body)
{
    static const std::string head =
        "<style>" + std::string(socketley::storage::storage_ui_style()) +
        "body{overflow:auto}.page{position:relative;min-height:100%;display:flex;padding:16px}.page>.lcard{margin:auto}"
        ".lcard h2{margin:30px 0 4px;font-size:16px}.lcard form .btn{width:100%;justify-content:center;height:44px;"
        "margin-top:18px}.lcard .row{display:flex;align-items:center;gap:10px;margin-top:10px}.lcard .row .btn{width:"
        "auto;margin:0}.lcard .row span{flex:1}.lcard .acts{display:flex;gap:10px}.lcard a{color:var(--a1)}"
        ".lcard code{font-family:var(--mono);font-size:15px;letter-spacing:.06em}</style></head><body>"
        "<div id=\"aurora\"><i></i><i></i><i></i></div><div id=\"login\"><div class=\"orb o1\"></div><div "
        "class=\"orb o2\"></div><div class=\"orb o3\"></div></div><div class=\"page\"><main class=\"lcard\">"
        "<div class=\"logo\"><div class=\"mk\"><svg viewBox=\"0 0 24 24\"><path d=\"M7 5.5v13l11-6.5z\"/></svg>"
        "</div>socketley</div>";
    return "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" "
           "content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cdefs%3E%3ClinearGradient id='g' x2='1' y2='1'%3E%3Cstop stop-color='%23c084fc'/%3E%3Cstop offset='.55' stop-color='%23f472b6'/%3E%3Cstop offset='1' stop-color='%23fb923c'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='24' height='24' rx='6' fill='url(%23g)'/%3E%3Cpath d='M14.5 9.5a3 3 0 1 1-6 0 3 3 0 0 1 6 0zM13.6 11.8 18 16.2v2.3h-2.3v-1.6h-1.6v-1.6l-2-2' fill='none' stroke='%23fff' stroke-width='1.9' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E\"><title>" +
           html_escape(title) + "</title>" + head + std::string(body) + "</main></div></body></html>";
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
    if (m_ssh_ca)
        EVP_PKEY_free(m_ssh_ca);
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
    m_ssh_hours = m_owner.get_ssh_ca_hours();
    if (m_ssh_hours)
    {
        m_ssh_ca = socketley::ed25519::load_or_make(idp_ssh_ca_path(m_owner.get_name()), "the SSH CA key", err);
        if (!m_ssh_ca)
        {
            why = err;
            return false;
        }
        m_ssh_ca_line = socketley::ssh::line_of(socketley::ssh::ed25519_blob(socketley::ed25519::public_raw(m_ssh_ca)),
                                                std::string(m_owner.get_name()) + "-ssh-ca");
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
    // The accounts' standing beside the key, before any session is signed, so a proxy never verifies one without it.
    if (!publish_standing())
    {
        why = "the accounts' standing could not be written to " + idp_standing_path(m_owner.get_name());
        return false;
    }
    publish_accounts();
    // Password hashes are made and checked off the loop, which an scrypt would hold for tens of milliseconds.
    m_loop.register_owner(this);
    if (!m_hash.attach(m_io))
        m_hash.stop();

    if (!m_http.listen_tcp(m_owner.bind_in_addr(), m_owner.effective_port(), m_shards > 1, why))
        return false;
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
    for (auto it = m_devices.begin(); it != m_devices.end();)
    {
        if (it->second.expires > now)
        {
            ++it;
            continue;
        }
        m_user_codes.erase(it->second.user_code);
        it = m_devices.erase(it);
    }
    m_limits.age(now);
    if (!m_http.empty() || !m_codes.empty() || !m_limits.empty() || !m_devices.empty())
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
        else if (header_name_equals(f, "x-forwarded-for", 15))
            rq.forwarded_for.assign(value);
        else if (header_name_equals(f, "origin", 6))
            rq.origin.assign(value);
        else if (header_name_equals(f, "referer", 7))
            rq.referer.assign(value);
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
    // Same-origin rather than no-referrer, under which a browser would post this provider's own forms as Origin: null.
    o += "\r\nCache-Control: no-store\r\nPragma: no-cache\r\nX-Content-Type-Options: nosniff\r\n"
         "Referrer-Policy: same-origin\r\n";
    if (type.starts_with("text/html"))
        o += "X-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
             "frame-ancestors 'none'\r\n";
    o += extra_headers;
    if (!c->keep_alive)
        o += "Connection: close\r\n";
    o += "\r\n";
    o += body;
}

void idp_run::redirect(const std::shared_ptr<conn>& c, std::string_view location, std::string_view extra_headers)
{
    // A control character in a Location would end the field and write headers of the caller's choosing.
    if (std::any_of(location.begin(), location.end(), [](char ch) { return static_cast<unsigned char>(ch) < 0x20 || ch == 0x7f; }))
    {
        respond(c, 400, "text/plain", "the return address is not one this provider sends to\n");
        return;
    }
    std::string h = "Location: " + std::string(location) + "\r\n" + std::string(extra_headers);
    respond(c, 302, "text/plain", "", h);
}

void idp_run::json_error(const std::shared_ptr<conn>& c, int status, std::string_view error,
                         std::string_view description, std::string_view extra_headers)
{
    respond(c, status, "application/json",
            "{\"error\":" + socketley::json::quote(error) + ",\"error_description\":" + socketley::json::quote(description) + "}",
            std::string(any_origin) + std::string(extra_headers));
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
                std::string(any_origin) + "Access-Control-Allow-Methods: GET, POST\r\n"
                "Access-Control-Allow-Headers: Authorization, Content-Type\r\nAccess-Control-Max-Age: 600\r\n");
        return;
    }
    // A form that signs in or changes an account is taken only from this provider's pages, or a browser on another
    // site could post one and sign its visitor into an account of the site's choosing.
    if (post && (p == "/login" || p == "/authorize" || p == "/device" || p.starts_with("/account")) &&
        !form_origin_allowed(rq.origin.empty() ? rq.referer : rq.origin, m_issuer, m_cookie_domain))
    {
        respond(c, 403, "text/plain", "a form posted from another site is not taken here\n");
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
    else if (p == "/device_authorization" && post)
        device_authorization(c, rq);
    else if (p == "/device" && get)
        device_page(c, rq, {}, {}, 200);
    else if (p == "/device" && post)
        device_post(c, rq);
    else if (p == "/ssh/ca.pub" && get)
        ssh_ca_pub(c);
    else if (p == "/ssh/user-cert" && post)
        ssh_user_cert(c, rq);
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
    else if ((p == "/account/totp" || p == "/account/app-password") && post)
        security_post(c, rq);
    else if (p == "/.well-known/openid-configuration" || p == "/jwks" || p == "/authorize" || p == "/login" ||
             p == "/token" || p == "/userinfo" || p == "/logout" || p == "/" || p.starts_with("/account") ||
             p == "/device" || p == "/device_authorization" || p == "/ssh/ca.pub" || p == "/ssh/user-cert")
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
                ",\"device_authorization_endpoint\":" + socketley::json::quote(i + "/device_authorization") +
                ",\"response_types_supported\":[\"code\"],\"grant_types_supported\":[\"authorization_code\","
                "\"refresh_token\",\"urn:ietf:params:oauth:grant-type:device_code\"],\"subject_types_supported\":[\"public\"],\"id_token_signing_alg_values_supported\":"
                "[\"ES256\"],\"scopes_supported\":[\"openid\",\"profile\",\"email\",\"offline_access\"],"
                "\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\",\"none\"],"
                "\"code_challenge_methods_supported\":[\"S256\"],\"claims_supported\":[\"sub\",\"name\","
                "\"preferred_username\",\"email\",\"groups\"]}",
            any_origin);
}

void idp_run::jwks(const std::shared_ptr<conn>& c)
{
    respond(c, 200, "application/json", "{\"keys\":[" + m_jwk + "]}", any_origin);
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

const account* idp_run::session_of(const request& rq, int64_t* auth_time) const
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
        if (a && !a->disabled() && a->field("reset") != "1" && still_signed_in(*a, issued_ms(c)))
        {
            found = a;
            if (auth_time)
                *auth_time = claim_int(c, "auth_time");
        }
        return found != nullptr;
    });
    return found;
}

std::string idp_run::session_cookie(const account& who, bool remember) const
{
    const int64_t now = wall::now_sec();
    const int64_t life = remember ? remember_secs : session_secs;
    // What a proxy or a storage verifying the cookie on its own needs: the id, the username, an e-mail this provider
    // vouches for and the admin bit.
    const std::string body = "\"iss\":" + m_issuer_json + ",\"aud\":\"session\",\"sub\":" +
                             socketley::json::quote(who.id) + ",\"preferred_username\":" + socketley::json::quote(who.username()) +
                             ",\"email\":" + socketley::json::quote(trusted_email(who)) + ",\"email_verified\":" +
                             (email_trusted(who) ? "true" : "false") + ",\"admin\":" +
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
    // A browser given a session is one the account signed in on, which guesses at it from elsewhere do not hold up.
    return h + "\r\n" + known_cookie(who);
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
        out += ",\"email\":" + socketley::json::quote(e) + ",\"email_verified\":" + (email_trusted(who) ? "true" : "false");
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

bool idp_run::own_domain(std::string_view domain) const
{
    std::string_view cookie = m_cookie_domain;
    if (cookie.starts_with("."))
        cookie.remove_prefix(1);
    return socketley::ascii::iequals(domain, url_host(m_issuer)) || (!cookie.empty() && socketley::ascii::iequals(domain, cookie));
}

bool idp_run::email_trusted(const account& who) const
{
    const std::string_view e = who.field("email");
    if (e.empty() || !email_problem(e).empty())
        return false;
    if (who.field("email_verified") == "1")
        return true;
    const size_t at = e.find('@');
    return socketley::ascii::iequals(e.substr(0, at), who.username()) && own_domain(e.substr(at + 1));
}

std::string idp_run::self_email_problem(const account& who, std::string_view email) const
{
    if (std::string why = email_problem(email); !why.empty() || email.empty())
        return why;
    const size_t at = email.find('@');
    const std::string_view domain = email.substr(at + 1);
    // The name a mail runtime files the address under, its +tag aside.
    const std::string_view base = email.substr(0, std::min(at, email.find('+')));
    bool served = own_domain(domain);
    for (const account* a : m_accounts.all())
    {
        if (a->id == who.id || !email_trusted(*a))
            continue;
        const std::string_view theirs = a->field("email");
        if (socketley::ascii::iequals(theirs, email))
            return "that address is another account's";
        // A domain an admin gave an address in is one a mail runtime here may serve.
        if (socketley::ascii::iequals(theirs.substr(theirs.find('@') + 1), domain))
            served = true;
    }
    if (const account* a = served ? m_accounts.by_name(base) : nullptr; a && a->id != who.id)
        return "that address is another account's";
    return {};
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
    const std::string net = network_key(ip);
    return m_limits.barred(address_key(ip), now, miss_limit) ||
           (!net.empty() && m_limits.barred(net, now, network_limit));
}

std::vector<std::string> idp_run::hold(const std::string& ip, const std::string& acct)
{
    std::vector<std::string> keys{address_key(ip), acct};
    if (std::string net = network_key(ip); !net.empty())
        keys.push_back(std::move(net));
    for (const auto& k : keys)
        m_limits.begin(k);
    return keys;
}

void idp_run::release(const std::vector<std::string>& keys)
{
    for (const auto& k : keys)
        m_limits.end(k);
}

std::string idp_run::known_cookie(const account& who) const
{
    const int64_t now = wall::now_sec();
    const std::string body = "\"iss\":" + m_issuer_json + ",\"aud\":\"known\",\"sub\":" + socketley::json::quote(who.id) +
                             ",\"iat\":" + std::to_string(now) + ",\"exp\":" + std::to_string(now + known_secs);
    // The provider's own host alone reads it, so it names no domain.
    std::string h = "Set-Cookie: " + std::string(known_cookie_name) + "=" + sign_secret_token(m_secret, "known+jwt", body) +
                    "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + std::to_string(known_secs);
    if (m_secure_cookie)
        h += "; Secure";
    return h + "\r\n";
}

bool idp_run::known_device(const request& rq, const account* who) const
{
    return who && http::for_each_cookie(rq.cookie, known_cookie_name, [&](std::string_view v) {
               claims c;
               std::string why;
               return verify_secret_token(m_secret, "known+jwt", m_issuer, v, wall::now_sec(), c, why) &&
                      claim(c, "aud") == "known" && claim(c, "sub") == who->id;
           });
}

std::string idp_run::account_key(const request& rq, std::string_view prefix, const account* who,
                                 std::string_view user) const
{
    if (known_device(rq, who))
        return std::string(prefix) + "known:" + who->id;
    std::string name(who ? who->username() : user);
    socketley::ascii::lower_in_place(name);
    return std::string(prefix) + "user:" + name;
}

void idp_run::missed(const std::string& ip, const std::string& acct, int64_t now, std::function<void()> then)
{
    std::vector<std::string> keys{address_key(ip)};
    if (std::string net = network_key(ip); !net.empty())
        keys.push_back(std::move(net));
    if (!acct.empty())
        keys.push_back(acct);
    count_failed(std::move(keys), now, std::move(then));
}

void idp_run::count_failed(std::vector<std::string> keys, int64_t now, std::function<void()> then)
{
    for (const auto& k : keys)
        m_limits.failed(k, now);
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
            for (const auto& k : keys)
            {
                ++*left;
                if (!cross(j, shard_call{shard_call::miss, k, {}, now}, one))
                    --*left;
            }
    one(true, {});
}

// ─── Authorize and sign in ──────────────────────────────────────────────────

const client* idp_run::checked_client(const std::shared_ptr<conn>& c, const params& p)
{
    const client* cl = find_client(param(p, "client_id"));
    const std::string_view back = param(p, "redirect_uri");
    // Without a known client and one of its own addresses there is nowhere safe to send an error, so it is shown.
    if (!cl || !cl->allows(back))
    {
        respond(c, 400, "text/html; charset=utf-8",
                page("Sign-in refused", "<h1>This sign-in cannot go on</h1><p class=\"mut\">The application asked "
                                        "with a client or a return address this provider does not know.</p>"));
        return nullptr;
    }
    const std::string sep = back.find('?') == std::string_view::npos ? "?" : "&";
    const std::string state = std::string(param(p, "state"));
    auto fail = [&](std::string_view error, std::string_view desc)
    {
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
    // The domain the session cookie covers is what one sign-in opens, else the provider's own host.
    const std::string host = m_cookie_domain.empty() ? url_host(m_issuer) : m_cookie_domain;
    const std::string body =
        "<h1>Welcome back</h1><p class=\"mut\">Sign in to " + html_escape(host) + ".</p><form method=\"post\">" +
        hidden + "<label for=\"u\">User</label><input class=\"inp\" id=\"u\" type=\"text\" name=\"username\" "
        "autocomplete=\"username\" autofocus required value=\"" + html_escape(param(p, "username")) +
        "\"><label for=\"p\">Password</label><input class=\"inp\" id=\"p\" type=\"password\" name=\"password\" "
        "autocomplete=\"current-password\" required><label class=\"chk\"><input type=\"checkbox\" name=\"remember\" "
        "value=\"1\"> Stay signed in on this device</label>" +
        (error.empty() ? std::string() : "<p class=\"err\">" + html_escape(error) + "</p>") +
        "<button class=\"btn pri\" type=\"submit\">Sign in</button></form>";
    respond(c, status, "text/html; charset=utf-8", page("Sign in", body));
}

// `n` bytes from the kernel's generator, for a key or an app password; empty where it gave none.
static std::string random_string(size_t n)
{
    std::string b(n, '\0');
    return socketley::random_bytes(b.data(), n) ? b : std::string();
}

void idp_run::code_page(const std::shared_ptr<conn>& c, const std::string& pending, std::string_view error, int status)
{
    const std::string body =
        "<h1>Sign in</h1><p class=\"mut\">The code your authenticator app shows now.</p><form method=\"post\">"
        "<input type=\"hidden\" name=\"pending\" value=\"" + html_escape(pending) + "\"><label for=\"c\">Code</label>"
        "<input class=\"inp\" id=\"c\" type=\"text\" name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" "
        "pattern=\"[0-9 ]{6,7}\" autofocus required>" +
        (error.empty() ? std::string() : "<p class=\"err\">" + html_escape(error) + "</p>") +
        "<button class=\"btn pri\" type=\"submit\">Sign in</button></form>";
    respond(c, status, "text/html; charset=utf-8", page("Sign in", body));
}

void idp_run::check_code(const account& a, std::string_view code, std::function<void(bool)> then)
{
    std::string secret;
    const std::string was(a.field("totp_step"));
    uint64_t last = 0;
    std::from_chars(was.data(), was.data() + was.size(), last);
    const uint64_t step = base32_decode(a.field("totp"), secret) ? totp_step(secret, code, wall::now_sec(), last) : 0;
    if (!step)
    {
        then(false);
        return;
    }
    // Taken only while the step kept is the one read here, so the same code sent to two shards at once is taken once.
    update_account(a.id, {{"?totp_step", was}, {"totp_step", std::to_string(step)}},
                   [then = std::move(then)](bool ok, const std::string&) { then(ok); });
}

void idp_run::second_step(const std::shared_ptr<conn>& c, const request& rq, params p)
{
    const std::string token(param(p, "pending"));
    const std::string ip = client_ip(*c, rq);
    const auto it = m_pending.find(token);
    // A reset's token is no second step's: its code was asked for already.
    if (it == m_pending.end() || it->second.until_s < wall::now_sec() || it->second.reset)
    {
        if (it != m_pending.end())
            m_pending.erase(it);
        login_page(c, {}, "The sign-in took too long; sign in again.", 401);
        return;
    }
    const int64_t now = wall::now_sec();
    const account* a = m_accounts.by_id(it->second.id);
    if (!a || a->disabled())
    {
        m_pending.erase(it);
        login_page(c, {}, "The user or password is not right.", 401);
        return;
    }
    if (!known_device(rq, a) && barred(ip, now))
    {
        ++m_c.barred;
        login_page(c, it->second.p, "Too many failed sign-ins from here; try again in a quarter of an hour.", 429);
        return;
    }
    const std::string acct = account_key(rq, "code:", a, {});
    if (const int64_t wait = m_limits.wait(acct, now, code_free); wait > 0)
    {
        ++m_c.barred;
        code_page(c, token, "Too many wrong codes for this user; try again in " + std::to_string(wait) + " seconds.",
                  429);
        return;
    }
    std::weak_ptr<conn> weak = c;
    c->waiting = true;
    check_code(*a, param(p, "code"), [this, weak, token, ip, acct, now](bool right)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        // Looked up again, as another request may have ended it while the code was taken.
        const auto pit = m_pending.find(token);
        const account* who = pit == m_pending.end() ? nullptr : m_accounts.by_id(pit->second.id);
        if (!who)
        {
            cc->waiting = false;
            login_page(cc, {}, "The sign-in took too long; sign in again.", 401);
            m_http.resume(cc);
            return;
        }
        if (!right)
        {
            ++m_c.refused;
            // A few wrong codes end the sign-in, whose password must then be given again.
            const bool ended = ++pit->second.misses >= code_tries;
            const params back = pit->second.p;
            if (ended)
                m_pending.erase(pit);
            missed(ip, acct, now, [this, weak, token, ended, back] {
                auto c2 = weak.lock();
                if (!c2 || c2->dead)
                    return;
                c2->waiting = false;
                if (ended)
                    login_page(c2, back, "That code was wrong too many times; sign in again.", 401);
                else
                    code_page(c2, token, "That code is not the one the app shows.", 401);
                m_http.resume(c2);
            });
            return;
        }
        const params carried = pit->second.p;
        const bool remember = pit->second.remember;
        m_pending.erase(pit);
        cc->waiting = false;
        if (who->field("reset") == "1")
            reset_after_sign_in(cc, *who, carried, remember);
        else
        {
            signed_in(*who, ip, "with password and code");
            grant(cc, carried, *who, session_cookie(*who, remember));
        }
        m_http.resume(cc);
    });
}

void idp_run::reset_after_sign_in(const std::shared_ptr<conn>& c, const account& a, const params& p, bool remember)
{
    const int64_t now = wall::now_sec();
    std::erase_if(m_pending, [now](const auto& kv) { return kv.second.until_s < now; });
    if (m_pending.size() >= 10000)
    {
        login_page(c, p, "Too many sign-ins are waiting; try again in a minute.", 429);
        return;
    }
    const std::string token = socketley::random_hex(24);
    m_pending[token] = {a.id, remember, p, now + 600, true};
    reset_page(c, token, {}, 200);
}

void idp_run::authorize(const std::shared_ptr<conn>& c, const request& rq)
{
    const params p = parse_form(rq.query);
    const bool oauth = rq.path == "/authorize";
    if (oauth)
    {
        if (!checked_client(c, p))
            return;
    }
    else if (const std::string_view rd = param(p, "rd"); !rd.empty() && !return_allowed(rd, m_issuer, m_cookie_domain))
    {
        respond(c, 400, "text/html; charset=utf-8",
                page("Sign-in refused", "<h1>This sign-in cannot go on</h1><p class=\"mut\">The page asked to "
                                        "return to an address outside this provider's domain.</p>"));
        return;
    }
    int64_t auth_time = 0;
    if (const account* who = param(p, "prompt") != "login" ? session_of(rq, &auth_time) : nullptr)
    {
        // The code says when the person signed in, not when the browser came back with the session.
        grant(c, p, *who, {}, auth_time);
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
        if (!checked_client(c, p))
            return;
    }
    else if (const std::string_view rd = param(p, "rd"); !rd.empty() && !return_allowed(rd, m_issuer, m_cookie_domain))
    {
        respond(c, 400, "text/plain", "the return address is outside this provider's domain\n");
        return;
    }
    // The code of the second step, for a sign-in whose password was right.
    if (!param(p, "pending").empty())
    {
        second_step(c, rq, std::move(p));
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
    const int64_t now = wall::now_sec();
    const account* who = m_accounts.by_name(user);
    // A browser the account signed in on is held to the account's own key alone, so others behind its address
    // failing do not lock it out.
    if (!known_device(rq, who) && barred(ip, now))
    {
        ++m_c.barred;
        login_page(c, p, "Too many failed sign-ins from here; try again in a quarter of an hour.", 429);
        return;
    }
    const std::string acct = account_key(rq, {}, who, user);
    if (const int64_t wait = m_limits.wait(acct, now, account_free); wait > 0)
    {
        ++m_c.barred;
        login_page(c, p, "Too many failed sign-ins as this user; try again in " + std::to_string(wait) + " seconds.",
                   429);
        return;
    }
    if (hashing_full())
    {
        login_page(c, p, "Too many sign-ins are being checked; try again in a moment.", 503);
        return;
    }
    // Counted while its hash is made, so many sent at once are each counted against those sent beside them.
    const std::vector<std::string> held = hold(ip, acct);
    std::weak_ptr<conn> weak = c;
    const bool remember = param(p, "remember") == "1";
    c->waiting = true;
    check_password(who, password, [this, weak, p = std::move(p), ip, held, acct, user, remember](bool ok)
    {
        release(held);
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        const account* a = m_accounts.by_name(user);
        if (!ok || !a || a->disabled())
        {
            ++m_c.refused;
            LOG_INFO(("idp " + std::string(m_owner.get_name()) + ": a sign-in as \"" + user + "\" from " + ip +
                      " was refused").c_str());
            missed(ip, acct, wall::now_sec(), [this, weak, p]
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
        // The code before a forced reset, so a password alone never sets a new one and signs in with it.
        if (!a->field("totp").empty())
        {
            // Its password right, the code is asked for, what the sign-in carries kept here five minutes.
            const int64_t now = wall::now_sec();
            std::erase_if(m_pending, [now](const auto& kv) { return kv.second.until_s < now; });
            if (m_pending.size() < 10000)
            {
                const std::string token = socketley::random_hex(24);
                m_pending[token] = {a->id, remember, p, now + 300};
                code_page(cc, token, {}, 200);
            }
            else
                login_page(cc, p, "Too many sign-ins are waiting for their code; try again in a minute.", 429);
        }
        else if (a->field("reset") == "1")
            reset_after_sign_in(cc, *a, p, remember);
        else
        {
            signed_in(*a, ip, "with password");
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
    check_hash(hash, real, password, std::move(then));
}

void idp_run::check_mail_password(const account* who, std::string password, std::function<void(bool)> then)
{
    // An app password a line: label, hash and when it was made, apart by tabs.
    std::vector<std::string> hashes;
    if (who)
        for (std::string_view rest = who->field("app_passwords"); !rest.empty();)
        {
            const size_t nl = rest.find('\n');
            const std::string_view line = rest.substr(0, nl);
            rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
            const size_t t1 = line.find('\t'), t2 = t1 == std::string_view::npos ? t1 : line.find('\t', t1 + 1);
            if (t2 != std::string_view::npos)
                hashes.emplace_back(line.substr(t1 + 1, t2 - t1 - 1));
        }
    const bool second = who && !who->field("totp").empty();
    auto list = std::make_shared<const std::vector<std::string>>(std::move(hashes));
    // With a second step on, a mail app signs in with an app password alone, as it has no code to give.
    if (second || !list->empty())
    {
        if (second)
        {
            if (list->empty())
                check_password(nullptr, password, [then](bool) { then(false); });
            else
                check_app_passwords(list, 0, std::move(password), std::move(then));
            return;
        }
        check_password(who, password, [this, list, password, then](bool ok) {
            if (ok)
                then(true);
            else
                check_app_passwords(list, 0, password, then);
        });
        return;
    }
    check_password(who, password, std::move(then));
}

void idp_run::check_app_passwords(std::shared_ptr<const std::vector<std::string>> hashes, size_t i, std::string password,
                                  std::function<void(bool)> then)
{
    if (i >= hashes->size())
        return then(false);
    const std::string hash = (*hashes)[i];
    check_hash(hash, true, password, [this, hashes, i, password, then](bool ok) {
        if (ok)
            then(true);
        else
            check_app_passwords(hashes, i + 1, password, then);
    });
}

void idp_run::check_hash(std::string hash, bool real, std::string_view password, std::function<void(bool)> then)
{
    if (!m_hash.enabled())
    {
        const bool ok = socketley::storage::password_matches(hash, password);
        then(real && ok);
        return;
    }
    ++m_hashing;
    auto counted = [this, then = std::move(then)](bool ok)
    {
        --m_hashing;
        then(ok);
    };
    {
        std::lock_guard<std::mutex> g(m_checks->mu);
        m_checks->waiting.push_back({hash, std::string(password), real, std::move(counted)});
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

void idp_run::grant(const std::shared_ptr<conn>& c, const params& p, const account& who, std::string_view set_cookie,
                    int64_t auth_time)
{
    // A code goes only to one of the client's own addresses, whichever path the sign-in came by.
    const client* cl = nullptr;
    if (!param(p, "client_id").empty())
    {
        cl = checked_client(c, p);
        if (!cl)
            return;
    }
    // A sign-in for a page behind a proxy, or for this provider itself, rather than for a client.
    if (!cl)
    {
        // Checked here as well as where the sign-in began, since every path that signs someone in ends here.
        const std::string_view rd = param(p, "rd");
        redirect(c, rd.empty() || !return_allowed(rd, m_issuer, m_cookie_domain) ? std::string_view("/") : rd, set_cookie);
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
    e.auth_time = auth_time ? auth_time : now;
    e.issued_ms = wall::now_ms();
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
    if (!has_scope(e.scope, "offline_access") && cl.is_public())
    {
        send_tokens(c, cl, e, who, {}, 0);
        return;
    }
    const int64_t now = wall::now_sec();
    const std::string family = socketley::random_hex(8);
    if (family.empty())
    {
        json_error(c, 503, "temporarily_unavailable", "no randomness for a refresh token");
        return;
    }
    // The family is kept with the account before its first token is given, so every shard knows it.
    field_list fields = stale_families(who, now);
    fields.emplace_back(std::string(family_prefix) + family, "1 " + std::to_string(now + refresh_secs));
    std::weak_ptr<conn> weak = c;
    c->waiting = true;
    update_account(who.id, std::move(fields),
                   [this, weak, client_id = cl.id, e, id = who.id, family](bool ok, const std::string&)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        cc->waiting = false;
        const client* again = find_client(client_id);
        const account* a = m_accounts.by_id(id);
        if (!ok || !again || !a)
            json_error(cc, 503, "temporarily_unavailable", "the sign-in could not be kept; try again");
        else
            send_tokens(cc, *again, e, *a, family, 1);
        m_http.resume(cc);
    });
}

void idp_run::send_tokens(const std::shared_ptr<conn>& c, const client& cl, const code_entry& e, const account& who,
                          std::string_view family, uint64_t generation)
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
    // The admin bit a session cookie carries, so a runtime taking the token can tell an admin as it does from a cookie.
    claims.append(",\"admin\":").append(who.in_group("admins") ? "true" : "false");
    const std::string access = sign_token(m_key, m_kid, "at+jwt", claims);
    std::string refresh;
    if (!family.empty())
    {
        claims.assign(common).append(",\"aud\":\"refresh\",\"client_id\":").append(aud).append(",\"scope\":");
        claims.append(scope).append(",\"fam\":\"").append(family).append("\",\"gen\":");
        claims.append(std::to_string(generation)).append(",\"exp\":").append(std::to_string(now + refresh_secs));
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
    respond(c, 200, "application/json", body, any_origin);
}

const client* idp_run::requesting_client(const std::shared_ptr<conn>& c, const request& rq, const params& p)
{
    const std::string ip = client_ip(*c, rq);
    const int64_t now = wall::now_sec();
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
    // Only a confidential client's secret can be guessed at, and its guesses bar that alone, so a page posting
    // here from a browser cannot lock its address out of signing in.
    const bool secret_asked = cl && !cl->is_public();
    const std::string secret_key = "secret:" + address_key(ip);
    if (secret_asked && m_limits.barred(secret_key, now, miss_limit))
    {
        ++m_c.barred;
        json_error(c, 429, "temporarily_unavailable", "too many wrong client secrets from here; try again in a "
                                                      "quarter of an hour");
        return nullptr;
    }
    const bool authenticated =
        cl && (cl->is_public() ? secret.empty() : crypto::secure_equal(secret, cl->secret));
    if (!authenticated)
    {
        if (secret_asked)
            count_failed({secret_key}, now, [] {});
        json_error(c, 401, "invalid_client", "the client is not known or its secret is not right",
                   basic ? "WWW-Authenticate: Basic realm=\"" + m_issuer + "\"\r\n" : std::string());
        return nullptr;
    }
    return cl;
}

void idp_run::token(const std::shared_ptr<conn>& c, const request& rq)
{
    const params p = parse_form(rq.body);
    const client* cl = requesting_client(c, rq, p);
    if (!cl)
        return;
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
                // Its tokens may wait on the refresh family being kept, which resumes the connection itself.
                if (!cc->waiting)
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
        refresh_grant(c, *cl, r, *who);
        return;
    }
    if (grant == device_grant)
    {
        device_token(c, *cl, std::string(param(p, "device_code")));
        return;
    }
    json_error(c, 400, "unsupported_grant_type", "only authorization_code, refresh_token and device_code are served");
}

void idp_run::refresh_grant(const std::shared_ptr<conn>& c, const client& cl, const claims& r, const account& who)
{
    const std::string family = claim(r, "fam");
    uint64_t generation = 0;
    const std::string g = claim(r, "gen");
    std::from_chars(g.data(), g.data() + g.size(), generation);
    const std::string field = std::string(family_prefix) + family;
    const std::string was(who.field(field));
    uint64_t newest = 0;
    int64_t expires = 0;
    const int64_t now = wall::now_sec();
    // A token of a family the account no longer keeps, or of none, as one given before families were, is spent.
    if (family.size() != 16 || !generation || !read_family(was, newest, expires) || expires <= now)
    {
        json_error(c, 400, "invalid_grant", "the refresh token's sign-in has ended");
        return;
    }
    const std::string id = who.id, user(who.username());
    // One before the newest was used before, so whoever holds the newest may have stolen either: the family ends.
    const auto reused = [this, id, user, field, client_id = cl.id](const std::shared_ptr<conn>& cc)
    {
        LOG_WARN(("idp " + std::string(m_owner.get_name()) + ": a refresh token of \"" + user + "\" for " + client_id +
                  " came again after it was used; that sign-in is ended").c_str());
        update_account(id, {{field, ""}}, [](bool, const std::string&) {});
        json_error(cc, 400, "invalid_grant", "the refresh token was used already; its sign-in has ended");
    };
    if (newest != generation)
    {
        reused(c);
        return;
    }
    code_entry e;
    e.sub = who.id;
    e.scope = claim(r, "scope");
    e.auth_time = claim_int(r, "auth_time");
    std::weak_ptr<conn> weak = c;
    c->waiting = true;
    // The next generation taken only while this one is still the newest, so the same token sent twice gets one.
    update_account(id, {{"?" + field, was}, {field, std::to_string(generation + 1) + " " + std::to_string(now + refresh_secs)}},
                   [this, weak, client_id = cl.id, e, id, family, generation, reused](bool ok, const std::string& why)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        cc->waiting = false;
        const client* again = find_client(client_id);
        const account* a = m_accounts.by_id(id);
        if (!ok && why == changed_meanwhile)
            reused(cc);
        else if (!ok || !again || !a)
            json_error(cc, 503, "temporarily_unavailable", "the refresh could not be kept; try again");
        else
        {
            ++m_c.refreshes;
            send_tokens(cc, *again, e, *a, family, generation + 1);
        }
        m_http.resume(cc);
    });
}

// ─── The SSH certificate authority ──────────────────────────────────────────

void idp_run::ssh_ca_pub(const std::shared_ptr<conn>& c)
{
    if (!m_ssh_ca)
    {
        respond(c, 404, "text/plain", "this provider signs no SSH certificates\n");
        return;
    }
    respond(c, 200, "text/plain", m_ssh_ca_line + "\n", any_origin);
}

std::vector<std::string> idp_run::ssh_principals(const account& who)
{
    std::vector<std::string> out{std::string(who.username())};
    std::string_view groups = who.field("groups");
    while (!groups.empty())
    {
        const std::string_view g = socketley::trim_blanks(take_item(groups));
        if (g == "admins")
            out.emplace_back("root");
        else if (g.starts_with("ssh:") && g.size() > 4)
            out.emplace_back(g.substr(4));
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

void idp_run::ssh_user_cert(const std::shared_ptr<conn>& c, const request& rq)
{
    if (!m_ssh_ca)
    {
        respond(c, 404, "text/plain", "this provider signs no SSH certificates\n");
        return;
    }
    std::string_view token;
    claims a;
    std::string why;
    const int64_t now = wall::now_sec();
    if (!http_auth_credentials(rq.authorization, "bearer", token) ||
        !m_verified.verify(m_key, m_kid, "at+jwt", m_issuer, token, now, a, why))
    {
        respond(c, 401, "text/plain", "a valid bearer access token is required\n",
                "WWW-Authenticate: Bearer error=\"invalid_token\"\r\n");
        return;
    }
    // A token a web application was given cannot be turned into a way onto the user's servers.
    const client* cl = find_client(claim(a, "client_id"));
    if (!cl || !cl->ssh)
    {
        respond(c, 403, "text/plain", "the token was given to a client that may not ask for SSH certificates\n");
        return;
    }
    const account* who = m_accounts.by_id(claim(a, "sub"));
    if (!who || who->disabled() || who->field("reset") == "1" || !still_signed_in(*who, issued_ms(a)))
    {
        respond(c, 403, "text/plain", "the account is no longer one that may sign in\n");
        return;
    }
    // A sign-in buys certificates for a while, so a refresh token alone does not go on buying them (RFC 9470).
    if (now - claim_int(a, "auth_time") > ssh_auth_secs)
    {
        respond(c, 401, "text/plain",
                "the sign-in is more than " + std::to_string(ssh_auth_secs / 3600) +
                    " hours old; sign in again with `socketley login`\n",
                "WWW-Authenticate: Bearer error=\"insufficient_user_authentication\", max_age=" +
                    std::to_string(ssh_auth_secs) + "\r\n");
        return;
    }
    socketley::ssh::public_key key;
    if (!socketley::ssh::parse_public_key(param(parse_form(rq.body), "public_key"), key, why))
    {
        respond(c, 400, "text/plain", "public_key: " + why + "\n");
        return;
    }
    socketley::ssh::cert_request req;
    req.subject_blob = key.blob;
    req.kind = socketley::ssh::cert_kind::user;
    req.serial = socketley::random_u64();
    req.key_id = std::string(who->username()) + "@" + url_host(m_issuer);
    req.principals = ssh_principals(*who);
    // Five minutes back, for a server whose clock is a little behind this one.
    req.valid_after = static_cast<uint64_t>(now - 300);
    req.valid_before = static_cast<uint64_t>(now + int64_t{m_ssh_hours} * 3600);
    req.extensions = socketley::ssh::default_user_extensions();
    const std::string cert = socketley::ssh::sign_cert(req, m_ssh_ca, why);
    if (cert.empty())
    {
        respond(c, 500, "text/plain", "the certificate could not be signed: " + why + "\n");
        return;
    }
    ++m_c.ssh_certs;
    std::string names;
    for (const auto& pr : req.principals)
        names += (names.empty() ? "" : ",") + pr;
    LOG_INFO(("idp " + std::string(m_owner.get_name()) + ": SSH certificate " + std::to_string(req.serial) + " for \"" +
              std::string(who->username()) + "\" as " + names + ", " + std::to_string(m_ssh_hours) + " h, key " +
              socketley::ssh::fingerprint(key.blob) + " from " + client_ip(*c, rq)).c_str());
    respond(c, 200, "text/plain", socketley::ssh::line_of(cert, key.comment.empty() ? req.key_id : key.comment) + "\n");
}

std::string idp_run::ssh_host_cert(std::string_view key_line, std::string_view names, uint32_t days)
{
    if (!m_ssh_ca)
        return "error: this provider signs no SSH certificates; give it --ssh-ca";
    socketley::ssh::public_key key;
    std::string why;
    if (!socketley::ssh::parse_public_key(key_line, key, why))
        return "error: " + why;
    socketley::ssh::cert_request req;
    req.subject_blob = key.blob;
    req.kind = socketley::ssh::cert_kind::host;
    req.serial = socketley::random_u64();
    while (!names.empty())
        if (const std::string_view n = socketley::trim_blanks(take_item(names)); !n.empty())
            req.principals.emplace_back(n);
    if (req.principals.empty())
        return "error: a host certificate names at least one host";
    req.key_id = req.principals.front();
    const int64_t now = wall::now_sec();
    req.valid_after = static_cast<uint64_t>(now - 300);
    req.valid_before = static_cast<uint64_t>(now + int64_t{days} * 86400);
    const std::string cert = socketley::ssh::sign_cert(req, m_ssh_ca, why);
    if (cert.empty())
        return "error: " + why;
    LOG_INFO(("idp " + std::string(m_owner.get_name()) + ": SSH host certificate " + std::to_string(req.serial) +
              " for " + std::string(req.key_id) + ", " + std::to_string(days) + " days, key " +
              socketley::ssh::fingerprint(key.blob)).c_str());
    return socketley::ssh::line_of(cert, req.key_id);
}

// ─── The device grant ───────────────────────────────────────────────────────

void idp_run::signed_in(const account& who, std::string_view ip, std::string_view how)
{
    ++m_c.sign_ins;
    LOG_INFO(("idp " + std::string(m_owner.get_name()) + ": \"" + std::string(who.username()) + "\" signed in " +
              std::string(how) + (ip.empty() ? std::string() : " from " + std::string(ip))).c_str());
}

void idp_run::device_authorization(const std::shared_ptr<conn>& c, const request& rq)
{
    const params p = parse_form(rq.body);
    const client* cl = requesting_client(c, rq, p);
    if (!cl)
        return;
    if (!cl->device)
    {
        json_error(c, 400, "unauthorized_client", "the client may not use the device grant; give it `device` in "
                                                  "--clients");
        return;
    }
    if (m_devices.size() >= max_devices)
    {
        json_error(c, 503, "temporarily_unavailable", "too many device sign-ins are waiting; try again in a minute");
        return;
    }
    // A user code this shard keeps, so whichever shard the person's browser reaches can ask the right one.
    std::string user_code, normal;
    for (int i = 0; i < 256; ++i)
    {
        std::string candidate = make_user_code();
        std::string n = normal_user_code(candidate);
        if (n.empty() || user_code_shard(n, m_shards) != m_shard || m_user_codes.contains(n))
            continue;
        user_code = std::move(candidate);
        normal = std::move(n);
        break;
    }
    const std::string token = random_b64url(32);
    const std::string device_code = m_shards > 1 && !token.empty() ? std::to_string(m_shard) + "." + token : token;
    if (user_code.empty() || token.empty())
    {
        json_error(c, 503, "temporarily_unavailable", "no randomness for a code");
        return;
    }
    const int64_t now = wall::now_sec();
    device_entry e;
    e.client_id = cl->id;
    e.scope.assign(param(p, "scope"));
    e.user_code = normal;
    e.expires = now + device_secs;
    e.next_poll = now;
    m_devices.emplace(device_code, std::move(e));
    m_user_codes.emplace(normal, device_code);
    ++m_c.devices;
    arm_tick();
    const std::string page_url = m_issuer + "/device";
    respond(c, 200, "application/json",
            "{\"device_code\":" + socketley::json::quote(device_code) + ",\"user_code\":" +
                socketley::json::quote(user_code) + ",\"verification_uri\":" + socketley::json::quote(page_url) +
                ",\"verification_uri_complete\":" + socketley::json::quote(page_url + "?user_code=" + user_code) +
                ",\"expires_in\":" + std::to_string(device_secs) + ",\"interval\":" + std::to_string(device_poll_s) +
                "}",
            any_origin);
}

void idp_run::device_page(const std::shared_ptr<conn>& c, const request& rq, std::string_view note,
                          std::string_view error, int status)
{
    const account* who = session_of(rq);
    if (!who)
    {
        // Signed in first, and brought back here with the code the address carried.
        const std::string back = "/device" + (rq.query.empty() ? std::string() : "?" + rq.query);
        redirect(c, "/login?rd=" + url_encode(back));
        return;
    }
    const params q = parse_form(rq.method == "POST" ? rq.body : rq.query);
    const std::string_view name = who->field("name").empty() ? who->username() : who->field("name");
    std::string body = "<h1>Sign in a device</h1>";
    // A code the address carried is only filled in: what it allows is shown, and allowed, on the next page.
    if (!note.empty())
        body += "<p>" + html_escape(note) + "</p><p class=\"mut\">You can close this page.</p>";
    else
        body += "<p class=\"mut\">Signed in as <b>" + html_escape(name) +
                "</b>. Give the code a device of yours shows you right now; the next page says which application "
                "asks and what it may do before anything is allowed.</p><form method=\"post\" action=\"/device\">"
                "<label for=\"u\">Code</label><input class=\"inp\" id=\"u\" type=\"text\" name=\"user_code\" "
                "autocomplete=\"off\" autocapitalize=\"characters\" autofocus required value=\"" +
                html_escape(param(q, "user_code")) + "\">" +
                (error.empty() ? std::string() : "<p class=\"err\">" + html_escape(error) + "</p>") +
                "<button class=\"btn pri\" type=\"submit\" name=\"action\" value=\"look\">Continue</button></form>";
    respond(c, status, "text/html; charset=utf-8", page("Sign in a device", body));
}

bool idp_run::device_needs_proof(const device_entry& e) const
{
    const auto it = std::find_if(m_clients.begin(), m_clients.end(), [&](const client& cl) { return cl.id == e.client_id; });
    return m_ssh_ca && it != m_clients.end() && it->ssh;
}

void idp_run::device_confirm(const std::shared_ptr<conn>& c, const account& who, const std::string& user_code,
                             const device_entry& e, std::string_view error, int status)
{
    const std::string_view name = who.field("name").empty() ? who.username() : who.field("name");
    const std::string shown = user_code.size() == 8 ? user_code.substr(0, 4) + "-" + user_code.substr(4) : user_code;
    std::string body = "<h1>Allow this device?</h1><p class=\"mut\">Signed in as <b>" + html_escape(name) +
                       "</b>.</p><p>The application <b>" + html_escape(e.client_id) +
                       "</b> asks, for the device showing <code>" + html_escape(shown) + "</code>, to act as you" +
                       (has_scope(e.scope, "offline_access") ? " until you sign out everywhere" : " for an hour") +
                       ".</p>";
    const bool proof = device_needs_proof(e);
    if (proof)
    {
        const std::vector<std::string> as = ssh_principals(who);
        std::string names;
        for (size_t i = 0; i < as.size(); ++i)
            names += (i == 0 ? "" : i + 1 == as.size() ? " and " : ", ") + std::string("<b>") + html_escape(as[i]) + "</b>";
        body += "<p class=\"err\">It can also get SSH certificates for your servers, logging in to them as " + names +
                (who.in_group("admins") ? ", root being one: whoever holds the device has every server" : "") +
                ".</p>";
    }
    body += "<p class=\"mut\">Allow it only if you started this sign-in yourself, just now, on a device in front of "
            "you. If someone sent you this link or this code, refuse it.</p><form method=\"post\" action=\"/device\">"
            "<input type=\"hidden\" name=\"user_code\" value=\"" + html_escape(user_code) + "\">";
    if (proof && !who.field("totp").empty())
        body += "<label for=\"tc\">The code your authenticator app shows, to allow it</label><input class=\"inp\" "
                "id=\"tc\" type=\"text\" name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" required>";
    else if (proof)
        body += "<label for=\"pw\">Your password, to allow it</label><input class=\"inp\" id=\"pw\" type=\"password\" "
                "name=\"password\" autocomplete=\"current-password\" required>";
    body += (error.empty() ? std::string() : "<p class=\"err\">" + html_escape(error) + "</p>") +
            "<div class=\"acts\"><button class=\"btn pri\" type=\"submit\" name=\"action\" value=\"allow\">Allow"
            "</button><button class=\"btn\" type=\"submit\" name=\"action\" value=\"deny\" formnovalidate>Refuse"
            "</button></div></form>";
    respond(c, status, "text/html; charset=utf-8", page("Allow this device?", body));
}

void idp_run::find_device(const std::string& normal, int64_t now, std::function<void(bool, const device_entry&)> then)
{
    const uint32_t keeper = user_code_shard(normal, m_shards);
    if (keeper == m_shard)
    {
        const auto u = m_user_codes.find(normal);
        const auto d = u == m_user_codes.end() ? m_devices.end() : m_devices.find(u->second);
        const bool found = d != m_devices.end() && d->second.expires > now && d->second.state == device_entry::pending;
        then(found, found ? d->second : device_entry{});
        return;
    }
    const bool asked = cross(keeper, shard_call{shard_call::device_peek, normal, {}, now},
                             [then](bool answered, std::string_view reply) {
        device_poll what = device_poll::gone;
        device_entry e;
        if (!answered || !decode_device(reply, what, e))
            what = device_poll::gone;
        then(what == device_poll::pending, e);
    });
    if (!asked)
        then(false, {});
}

void idp_run::decide_at(const std::string& normal, bool allow, const std::string& sub, int64_t now,
                        std::function<void(bool)> then)
{
    const uint32_t keeper = user_code_shard(normal, m_shards);
    if (keeper == m_shard)
    {
        then(decide_device(normal, allow, sub, now));
        return;
    }
    const bool asked = cross(keeper, shard_call{shard_call::device_decide, normal,
                                                {{"allow", allow ? "1" : "0"}, {"sub", sub}}, now},
                             [then](bool answered, std::string_view reply) {
        bool ok = false;
        std::string why;
        if (!answered || !decode_result(reply, ok, why))
            ok = false;
        then(ok);
    });
    if (!asked)
        then(false);
}

void idp_run::device_post(const std::shared_ptr<conn>& c, const request& rq)
{
    const account* who = session_of(rq);
    if (!who)
    {
        device_page(c, rq, {}, {}, 401);
        return;
    }
    const std::string ip = client_ip(*c, rq);
    const int64_t now = wall::now_sec();
    if (barred(ip, now))
    {
        ++m_c.barred;
        device_page(c, rq, {}, "Too many wrong codes from here; try again in a quarter of an hour.", 429);
        return;
    }
    const params p = parse_form(rq.body);
    const std::string normal = normal_user_code(param(p, "user_code"));
    const std::string action(param(p, "action"));
    const std::string id = who->id, user(who->username());
    std::weak_ptr<conn> weak = c;
    // The connection answered and let go on, once whatever it waited on is done.
    const auto done = [this](const std::shared_ptr<conn>& cc) {
        cc->waiting = false;
        m_http.resume(cc);
    };
    // A code that is no grant's counts like a wrong one.
    const auto unknown = [this, ip, now](const std::shared_ptr<conn>& cc, const request& r) {
        missed(ip, {}, now, [] {});
        device_page(cc, r, {}, "That code is not known or has expired.", 400);
    };
    if (normal.empty())
    {
        unknown(c, rq);
        return;
    }
    c->waiting = true;
    if (action == "deny")
    {
        decide_at(normal, false, id, now, [this, weak, rq, ip, user, unknown, done](bool ok) {
            auto cc = weak.lock();
            if (!cc || cc->dead)
                return;
            if (!ok)
                unknown(cc, rq);
            else
            {
                LOG_INFO(("idp " + std::string(m_owner.get_name()) + ": \"" + user + "\" refused a device sign-in from " + ip).c_str());
                device_page(cc, rq, "The device was refused.", {}, 200);
            }
            done(cc);
        });
        return;
    }
    find_device(normal, now, [this, weak, rq, p, normal, action, id, user, ip, now, unknown, done](
                                 bool found, const device_entry& e) {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        const account* me = m_accounts.by_id(id);
        if (!found || !me)
        {
            unknown(cc, rq);
            done(cc);
            return;
        }
        // Only a post from the page that said what it allows allows anything.
        if (action != "allow")
        {
            device_confirm(cc, *me, normal, e, {}, 200);
            done(cc);
            return;
        }
        const auto allow = [this, weak, rq, normal, id, user, ip, now, unknown, done] {
            decide_at(normal, true, id, now, [this, weak, rq, user, ip, unknown, done](bool ok) {
                auto c2 = weak.lock();
                if (!c2 || c2->dead)
                    return;
                if (!ok)
                    unknown(c2, rq);
                else
                {
                    LOG_INFO(("idp " + std::string(m_owner.get_name()) + ": \"" + user + "\" allowed a device sign-in from " + ip).c_str());
                    device_page(c2, rq, "The device is signed in.", {}, 200);
                }
                done(c2);
            });
        };
        if (!device_needs_proof(e))
        {
            allow();
            return;
        }
        // Proved again here, as approving it gives SSH certificates.
        prove_again(cc, rq, *me, p, [this, weak, id, normal, e, allow, done](int status, std::string_view why) {
            if (status == 0)
            {
                allow();
                return;
            }
            auto c2 = weak.lock();
            if (!c2 || c2->dead)
                return;
            if (const account* a = m_accounts.by_id(id))
                device_confirm(c2, *a, normal, e, why, status);
            else
                respond(c2, 401, "text/plain", "the account is no longer one that may sign in\n");
            done(c2);
        });
    });
}

void idp_run::prove_again(const std::shared_ptr<conn>& c, const request& rq, const account& who, const params& p,
                          std::function<void(int, std::string_view)> then)
{
    const std::string ip = client_ip(*c, rq);
    const int64_t now = wall::now_sec();
    const bool by_code = !who.field("totp").empty();
    const std::string acct = account_key(rq, by_code ? "code:" : "", &who, {});
    if (!known_device(rq, &who) && barred(ip, now))
    {
        ++m_c.barred;
        then(429, "Too many failed tries from here; try again in a quarter of an hour.");
        return;
    }
    if (const int64_t wait = m_limits.wait(acct, now, by_code ? code_free : account_free); wait > 0)
    {
        ++m_c.barred;
        then(429, "Too many failed tries as this user; try again in " + std::to_string(wait) + " seconds.");
        return;
    }
    // A wrong answer is answered once every shard counts it.
    const auto wrong = [this, ip, acct, now, then](std::string_view why) {
        missed(ip, acct, now, [then, text = std::string(why)] { then(401, text); });
    };
    if (by_code)
    {
        check_code(who, param(p, "code"), [then, wrong](bool right) {
            if (right)
                then(0, {});
            else
                wrong("That code is not the one the app shows.");
        });
        return;
    }
    if (hashing_full())
    {
        then(503, "Too many sign-ins are being checked; try again in a moment.");
        return;
    }
    const std::vector<std::string> held = hold(ip, acct);
    check_password(&who, param(p, "password"), [this, held, then, wrong](bool right) {
        release(held);
        if (right)
            then(0, {});
        else
            wrong("The password is not right.");
    });
}

bool idp_run::decide_device(const std::string& user_code, bool allow, const std::string& sub, int64_t at)
{
    const auto u = m_user_codes.find(user_code);
    if (u == m_user_codes.end())
        return false;
    const auto d = m_devices.find(u->second);
    if (d == m_devices.end() || d->second.expires <= at || d->second.state != device_entry::pending)
        return false;
    d->second.state = allow ? device_entry::approved : device_entry::denied;
    d->second.sub = sub;
    d->second.auth_time = at;
    d->second.issued_ms = wall::now_ms();
    // A decided code is decided once, and no second person can take it over.
    m_user_codes.erase(u);
    return true;
}

device_poll idp_run::poll_device(const std::string& device_code, std::string_view client_id, int64_t now,
                                 device_entry& out)
{
    const auto it = m_devices.find(device_code);
    if (it == m_devices.end() || it->second.client_id != client_id)
        return device_poll::gone;
    device_entry& e = it->second;
    if (e.expires <= now)
    {
        m_user_codes.erase(e.user_code);
        m_devices.erase(it);
        return device_poll::gone;
    }
    if (e.state == device_entry::pending)
    {
        // RFC 8628 3.5: a client that asks too often is told to slow down, and waits five seconds longer each time.
        if (now < e.next_poll)
        {
            e.next_poll += device_poll_s;
            return device_poll::slow_down;
        }
        e.next_poll = now + device_poll_s;
        return device_poll::pending;
    }
    out = e;
    const device_poll what = e.state == device_entry::approved ? device_poll::approved : device_poll::denied;
    m_user_codes.erase(e.user_code);
    m_devices.erase(it);
    return what;
}

void idp_run::device_token(const std::shared_ptr<conn>& c, const client& cl, std::string device_code)
{
    const int64_t now = wall::now_sec();
    uint32_t keeper = m_shard;
    if (!code_shard(device_code, m_shards, keeper) || keeper == m_shard)
    {
        device_entry e;
        const device_poll what = poll_device(device_code, cl.id, now, e);
        device_answered(c, cl, what, e);
        return;
    }
    std::weak_ptr<conn> weak = c;
    const bool asked = cross(keeper, shard_call{shard_call::device_ask, device_code, {{"client_id", cl.id}}, now},
                             [this, weak, client_id = cl.id](bool answered, std::string_view reply)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        cc->waiting = false;
        device_poll what = device_poll::gone;
        device_entry e;
        if (!answered || !decode_device(reply, what, e))
            what = device_poll::gone;
        if (const client* again = find_client(client_id))
            device_answered(cc, *again, what, e);
        else
            json_error(cc, 401, "invalid_client", "the client is not known or its secret is not right");
        if (!cc->waiting)
            m_http.resume(cc);
    });
    if (asked)
        c->waiting = true;
    else
        json_error(c, 400, "expired_token", "the device code is not known or has expired");
}

void idp_run::device_answered(const std::shared_ptr<conn>& c, const client& cl, device_poll what,
                              const device_entry& e)
{
    switch (what)
    {
        case device_poll::pending:
            json_error(c, 400, "authorization_pending", "the person has not allowed the code yet");
            return;
        case device_poll::slow_down:
            json_error(c, 400, "slow_down", "asked again too soon; wait five seconds longer between polls");
            return;
        case device_poll::denied:
            json_error(c, 400, "access_denied", "the person refused the code");
            return;
        case device_poll::gone:
            json_error(c, 400, "expired_token", "the device code is not known or has expired");
            return;
        case device_poll::approved:
            break;
    }
    // The account is looked at again, so one disabled, made to reset its password or signed out everywhere since
    // the person allowed the code gets nothing.
    const account* who = m_accounts.by_id(e.sub);
    if (!who || who->disabled() || who->field("reset") == "1" || !still_signed_in(*who, e.issued_ms))
    {
        json_error(c, 400, "invalid_grant", "the account is no longer one that may sign in");
        return;
    }
    code_entry granted;
    granted.client_id = cl.id;
    granted.sub = who->id;
    granted.scope = e.scope;
    granted.auth_time = e.auth_time;
    issue_tokens(c, cl, granted, *who);
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
    // As for a device, a code given before the account was disabled, made to reset or signed out everywhere is void.
    const account* who = m_accounts.by_id(e.sub);
    if (!who || who->disabled() || who->field("reset") == "1" || !still_signed_in(*who, e.issued_ms))
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
            any_origin);
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
            page("Signed out", "<h1>Signed out</h1><p class=\"mut\">You can close this page.</p>"), clear_cookie());
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
            page("Signed in", "<h1>Signed in</h1><p class=\"mut\">as <b>" + html_escape(name) + "</b></p><form "
                              "method=\"get\" action=\"/account\"><button class=\"btn pri\" type=\"submit\">Your "
                              "account</button></form><form method=\"post\" action=\"/logout\"><button class=\"btn\" "
                              "type=\"submit\">Sign out</button></form>"));
}

void idp_run::reset_page(const std::shared_ptr<conn>& c, const std::string& token, std::string_view error, int status)
{
    // The sign-in it finishes is the token's, kept here with where it goes on to, and not what the form says.
    const std::string body =
        "<h1>Set a new password</h1><p class=\"mut\">Your password must be set again before you go on.</p>"
        "<form method=\"post\" action=\"/account/password\"><input type=\"hidden\" name=\"reset_token\" value=\"" +
        html_escape(token) + "\"><label for=\"o\">Current password</label><input class=\"inp\" id=\"o\" type=\"password\" name=\"current\" "
        "autocomplete=\"current-password\" required><label for=\"n\">New password</label><input class=\"inp\" id=\"n\" "
        "type=\"password\" name=\"new\" autocomplete=\"new-password\" required>" +
        (error.empty() ? std::string() : "<p class=\"err\">" + html_escape(error) + "</p>") +
        "<button class=\"btn pri\" type=\"submit\">Set password</button></form>";
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
        "<h1>Your account</h1><p class=\"mut\">Signed in as <b>" + html_escape(who->username()) + "</b></p>" +
        (note.empty() ? std::string() : "<p class=\"mut\">" + html_escape(note) + "</p>") +
        (error.empty() ? std::string() : "<p class=\"err\">" + html_escape(error) + "</p>") +
        "<form method=\"post\" action=\"/account\"><label for=\"dn\">Name</label><input class=\"inp\" id=\"dn\" type=\"text\" "
        "name=\"name\" value=\"" + html_escape(who->field("name")) + "\"><label for=\"em\">E-mail</label><input class=\"inp\" "
        "id=\"em\" type=\"text\" name=\"email\" value=\"" + html_escape(who->field("email")) +
        "\"><button class=\"btn pri\" type=\"submit\">Save</button></form><h2>Password</h2><form method=\"post\" action=\"/account/password\"><label "
        "for=\"o\">Current password</label><input class=\"inp\" id=\"o\" type=\"password\" name=\"current\" autocomplete=\""
        "current-password\" required><label for=\"n\">New password</label><input class=\"inp\" id=\"n\" type=\"password\" "
        "name=\"new\" autocomplete=\"new-password\" required><button class=\"btn pri\" type=\"submit\">Change password</button></form>"
        "<form method=\"post\" action=\"/account/everywhere\"><button class=\"btn bad\" type=\"submit\">Sign out everywhere</button>"
        "</form>" + security_html(*who);
    respond(c, status, "text/html; charset=utf-8", page("Your account", body));
}

std::string idp_run::security_html(const account& who)
{
    std::string out = "<h2>Two-step sign-in</h2>";
    if (who.field("totp").empty())
        out += "<p class=\"mut\">Off: your password alone signs you in.</p><form method=\"post\" "
               "action=\"/account/totp\"><input type=\"hidden\" name=\"do\" value=\"start\"><label for=\"tp\">Your password, "
               "to turn it on</label><input class=\"inp\" id=\"tp\" type=\"password\" name=\"password\" "
               "autocomplete=\"current-password\" required><button class=\"btn pri\" type=\"submit\">Turn on</button></form>";
    else
        out += "<p class=\"mut\">On: a code from your authenticator app follows your password, and mail apps sign in "
               "with an app password.</p><form method=\"post\" action=\"/account/totp\"><input type=\"hidden\" "
               "name=\"do\" value=\"off\"><label for=\"tc\">Code</label><input class=\"inp\" id=\"tc\" type=\"text\" name=\"code\" "
               "inputmode=\"numeric\" autocomplete=\"one-time-code\" required><button class=\"btn bad\" type=\"submit\">Turn off</button>"
               "</form>";
    out += "<h2>App passwords</h2><p class=\"mut\">For a mail app on a phone or a computer: each its own, taken back "
           "on its own.</p>";
    for (std::string_view rest = who.field("app_passwords"); !rest.empty();)
    {
        const size_t nl = rest.find('\n');
        const std::string_view line = rest.substr(0, nl);
        rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
        if (line.empty())
            continue;
        const std::string label(line.substr(0, line.find('\t')));
        out += "<form method=\"post\" action=\"/account/app-password\" class=\"row\"><input type=\"hidden\" "
               "name=\"do\" value=\"remove\"><input type=\"hidden\" name=\"label\" value=\"" + html_escape(label) +
               "\"><span>" + html_escape(label) + "</span><button class=\"btn sm bad\" type=\"submit\">Remove</button></form>";
    }
    out += "<form method=\"post\" action=\"/account/app-password\"><input type=\"hidden\" name=\"do\" value=\"add\">"
           "<label for=\"al\">For</label><input class=\"inp\" id=\"al\" type=\"text\" name=\"label\" placeholder=\"Phone\" "
           "maxlength=\"64\" required>";
    // Made only once the person proves again who they are, as a session alone would otherwise open the mail.
    if (who.field("totp").empty())
        out += "<label for=\"ap\">Your password, to make one</label><input class=\"inp\" id=\"ap\" type=\"password\" "
               "name=\"password\" autocomplete=\"current-password\" required>";
    else
        out += "<label for=\"ac\">The code your authenticator app shows, to make one</label><input class=\"inp\" id=\"ac\" "
               "type=\"text\" name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" required>";
    out += "<button class=\"btn pri\" type=\"submit\">Make one</button></form>";
    return out;
}

void idp_run::security_post(const std::shared_ptr<conn>& c, const request& rq)
{
    const account* who = session_of(rq);
    if (!who)
    {
        redirect(c, "/login?rd=" + url_encode("/account"));
        return;
    }
    const params p = parse_form(rq.body);
    const std::string what(param(p, "do")), id = who->id;
    std::weak_ptr<conn> weak = c;
    const auto saved = [this, weak, rq](std::string_view note) {
        return [this, weak, rq, note = std::string(note)](bool ok, const std::string& why) {
            auto cc = weak.lock();
            if (!cc || cc->dead)
                return;
            cc->waiting = false;
            if (ok)
                account_page(cc, rq, note, {}, 200);
            else
                account_page(cc, rq, {}, why, 400);
            m_http.resume(cc);
        };
    };
    if (rq.path == "/account/totp")
    {
        const int64_t now = wall::now_sec();
        std::erase_if(m_enrolling, [now](const auto& kv) { return kv.second.second < now; });
        // A key on is replaced only by turning it off first, which takes a code of it, so a session alone never can.
        if ((what == "start" || what == "confirm") && !who->field("totp").empty())
        {
            m_enrolling.erase(id);
            account_page(c, rq, {}, "Two-step sign-in is on already; turn it off first, with a code your app shows.", 400);
            return;
        }
        if (what == "start")
        {
            // The password asked first, so a session alone cannot put a key of its own on the account.
            c->waiting = true;
            prove_again(c, rq, *who, p, [this, weak, rq, id](int status, std::string_view why) {
                auto cc = weak.lock();
                if (!cc || cc->dead)
                    return;
                cc->waiting = false;
                const account* me = m_accounts.by_id(id);
                const std::string seed = status == 0 && me && me->field("totp").empty() ? random_string(20) : std::string();
                if (seed.empty())
                {
                    account_page(cc, rq, {}, status ? why : "Two-step sign-in could not be begun; try again.",
                                 status ? status : 503);
                    m_http.resume(cc);
                    return;
                }
                // The key shown once, taken into the account only when a code of it proves the app has it.
                const std::string key = base32_encode(seed);
                m_enrolling[id] = {key, wall::now_sec() + 600};
                const std::string uri = totp_uri(url_host(m_issuer), me->username(), key);
                std::string grouped;
                for (size_t i = 0; i < key.size(); i += 4)
                    grouped += (i ? " " : "") + key.substr(i, 4);
                respond(cc, 200, "text/html; charset=utf-8",
                        page("Two-step sign-in",
                             "<h1>Two-step sign-in</h1><p class=\"mut\">Scan this with your authenticator app, or add the "
                             "key below by hand, then give the code it shows.</p><div style=\"width:200px;margin:16px 0;"
                             "border-radius:12px;overflow:hidden\">" + socketley::qr::svg(uri) + "</div><p><code>" +
                             html_escape(grouped) + "</code></p><p class=\"mut\">"
                             "<a href=\"" + html_escape(uri) + "\">Open in an authenticator app</a></p><form method=\"post\" "
                             "action=\"/account/totp\"><input type=\"hidden\" name=\"do\" value=\"confirm\"><label for=\"tc\">"
                             "Code</label><input class=\"inp\" id=\"tc\" type=\"text\" name=\"code\" inputmode=\"numeric\" "
                             "autocomplete=\"one-time-code\" autofocus required><button class=\"btn pri\" type=\"submit\">Turn on</button></form>"));
                m_http.resume(cc);
            });
            return;
        }
        if (what == "confirm")
        {
            const auto it = m_enrolling.find(id);
            std::string secret;
            const uint64_t step = it == m_enrolling.end() || !base32_decode(it->second.first, secret)
                                      ? 0 : totp_step(secret, param(p, "code"), now, 0);
            if (!step)
            {
                account_page(c, rq, {}, "That code is not the one the app shows; turn it on again.", 400);
                m_enrolling.erase(id);
                return;
            }
            const std::string key = it->second.first;
            m_enrolling.erase(it);
            c->waiting = true;
            // The code that turned it on is taken, so it signs nobody in after, and only while no key was set since.
            update_account(id, {{"?totp", ""}, {"totp", key}, {"totp_step", std::to_string(step)}},
                           saved("Two-step sign-in is on."));
            return;
        }
        if (what == "off")
        {
            // A code of it, its wrong ones counted, as turning it off is the one way to replace it.
            c->waiting = true;
            prove_again(c, rq, *who, p, [this, weak, rq, id, saved](int status, std::string_view why) {
                auto cc = weak.lock();
                if (!cc || cc->dead)
                    return;
                if (status != 0)
                {
                    cc->waiting = false;
                    account_page(cc, rq, {}, why, status);
                    m_http.resume(cc);
                    return;
                }
                update_account(id, {{"totp", ""}}, saved("Two-step sign-in is off."));
            });
            return;
        }
    }
    if (rq.path == "/account/app-password")
    {
        const std::string label(param(p, "label"));
        // The list as read here, which a change waits on still holding at shard 0, so none made meanwhile is undone.
        const std::string was(who->field("app_passwords"));
        std::vector<std::string> lines = app_password_lines(was);
        if (label.empty() || label.size() > 64 || label.find_first_of("\t\n") != std::string::npos)
        {
            account_page(c, rq, {}, "Name what the app password is for.", 400);
            return;
        }
        if (what == "remove")
        {
            std::erase_if(lines, [&](const std::string& l) { return std::string_view(l).substr(0, l.find('\t')) == label; });
            std::string joined;
            for (const auto& l : lines)
                joined += l + "\n";
            c->waiting = true;
            update_account(id, {{"?app_passwords", was}, {"app_passwords", joined}}, saved("Removed."));
            return;
        }
        if (what == "add")
        {
            if (lines.size() >= 10 || has_app_password(lines, label))
            {
                account_page(c, rq, {}, lines.size() >= 10 ? "Ten app passwords are the most; remove one first."
                                                           : "An app password of that name is there already.", 400);
                return;
            }
            const std::string raw = random_string(16);
            if (raw.size() != 16)
            {
                account_page(c, rq, {}, "No randomness for a password; try again.", 503);
                return;
            }
            std::string pw;
            for (size_t i = 0; i < 16; ++i)
                pw += std::string(i && i % 4 == 0 ? "-" : "") + static_cast<char>('a' + static_cast<unsigned char>(raw[i]) % 26);
            c->waiting = true;
            prove_again(c, rq, *who, p, [this, weak, rq, id, label, pw](int status, std::string_view why) {
                if (status != 0)
                {
                    auto cc = weak.lock();
                    if (!cc || cc->dead)
                        return;
                    cc->waiting = false;
                    account_page(cc, rq, {}, why, status);
                    m_http.resume(cc);
                    return;
                }
                hash_password(pw, [this, weak, rq, id, label, pw](std::string hash) {
                    auto cc = weak.lock();
                    if (!cc || cc->dead)
                        return;
                    // Read again, as an app password removed or made while this one was checked and hashed stays so.
                    const account* me = m_accounts.by_id(id);
                    const std::string now_was(me ? me->field("app_passwords") : std::string_view{});
                    const std::vector<std::string> now_lines = app_password_lines(now_was);
                    if (hash.empty() || !me || now_lines.size() >= 10 || has_app_password(now_lines, label))
                    {
                        cc->waiting = false;
                        account_page(cc, rq, {}, hash.empty() ? "The password could not be made; try again."
                                                              : "Ten app passwords are the most, or one of that name is there already.",
                                     hash.empty() ? 503 : 400);
                        m_http.resume(cc);
                        return;
                    }
                    std::string joined;
                    for (const auto& l : now_lines)
                        joined += l + "\n";
                    joined += label + "\t" + hash + "\t" + std::to_string(wall::now_sec()) + "\n";
                    update_account(id, {{"?app_passwords", now_was}, {"app_passwords", joined}},
                                   [this, weak, rq, label, pw](bool ok, const std::string& why) {
                        auto cc = weak.lock();
                        if (!cc || cc->dead)
                            return;
                        cc->waiting = false;
                        if (!ok)
                            account_page(cc, rq, {}, why, 400);
                        else
                            account_page(cc, rq, "The app password for " + label + ", shown this once: " + pw, {}, 200);
                        m_http.resume(cc);
                    });
                });
            });
            return;
        }
    }
    respond(c, 400, "text/plain", "no such change\n");
}

void idp_run::account_post(const std::shared_ptr<conn>& c, const request& rq)
{
    const account* who = session_of(rq);
    if (!who)
    {
        redirect(c, "/login?rd=" + url_encode("/account"));
        return;
    }
    field_list fields;
    if (rq.path != "/account/everywhere")
    {
        const params p = parse_form(rq.body);
        const std::string email(http_trim_ows(param(p, "email")));
        fields.emplace_back("name", std::string(param(p, "name")));
        // An address its holder gives themselves is one nobody vouched for, and one left as it was stays as it was.
        if (email != who->field("email"))
        {
            if (const std::string why = self_email_problem(*who, email); !why.empty())
            {
                account_page(c, rq, {}, why, 400);
                return;
            }
            fields.emplace_back("email", email);
            fields.emplace_back("email_verified", "");
        }
    }
    std::weak_ptr<conn> weak = c;
    c->waiting = true;
    if (rq.path == "/account/everywhere")
    {
        // Every session, refresh token and app password given before now stops holding, this browser's too.
        update_account(who->id, {{"revoked_before", std::to_string(wall::now_ms())}, {"app_passwords", ""}},
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
                        page("Signed out", "<h1>Signed out everywhere</h1><p class=\"mut\">Every session and every app "
                                           "password of this account has ended.</p>"),
                        clear_cookie());
            m_http.resume(cc);
        });
        return;
    }
    update_account(who->id, std::move(fields), [this, weak, rq](bool ok, const std::string& why)
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
    // Signed in, the account is the session's; at a forced reset it is the one a sign-in that passed every step and
    // found the reset left its token for, and nothing a form names.
    const account* who = session_of(rq);
    const bool from_reset = !who;
    const std::string token(param(p, "reset_token"));
    params carried_on;
    if (from_reset)
    {
        const auto it = m_pending.find(token);
        if (token.empty() || it == m_pending.end() || !it->second.reset || it->second.until_s < wall::now_sec())
        {
            login_page(c, {}, "The sign-in took too long; sign in again.", 401);
            return;
        }
        who = m_accounts.by_id(it->second.id);
        if (!who || who->field("reset") != "1")
        {
            m_pending.erase(it);
            login_page(c, {}, "Sign in again.", 401);
            return;
        }
        carried_on = it->second.p;
    }
    const std::string ip = client_ip(*c, rq);
    const int64_t now = wall::now_sec();
    if (!known_device(rq, who) && barred(ip, now))
    {
        ++m_c.barred;
        respond(c, 429, "text/plain", "Too many failed sign-ins from here; try again in a quarter of an hour.\n");
        return;
    }
    const std::string acct = account_key(rq, {}, who, {});
    if (const int64_t wait = m_limits.wait(acct, now, account_free); wait > 0)
    {
        ++m_c.barred;
        respond(c, 429, "text/plain", "Too many failed sign-ins as this user; try again in " + std::to_string(wait) +
                                          " seconds.\n");
        return;
    }
    if (hashing_full())
    {
        respond(c, 503, "text/plain", "Too many sign-ins are being checked; try again in a moment.\n");
        return;
    }
    const std::vector<std::string> held = hold(ip, acct);
    const std::string current(param(p, "current"));
    const std::string fresh(param(p, "new"));
    const std::string id = who ? who->id : std::string();
    const std::string problem = socketley::storage::password_problem(fresh, who ? who->username() : "");
    std::weak_ptr<conn> weak = c;
    c->waiting = true;
    check_password(who, current, [this, weak, rq, token, carried_on, ip, held, acct, id, fresh, problem, from_reset](bool ok)
    {
        release(held);
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        const account* a = m_accounts.by_id(id);
        auto fail = [&](std::string_view msg, int status)
        {
            cc->waiting = false;
            if (from_reset)
                reset_page(cc, token, msg, status);
            else
                account_page(cc, rq, {}, msg, status);
            m_http.resume(cc);
        };
        if (!ok || !a || a->disabled())
        {
            missed(ip, acct, wall::now_sec(), [this, weak, rq, token, from_reset]
            {
                auto c2 = weak.lock();
                if (!c2 || c2->dead)
                    return;
                c2->waiting = false;
                if (from_reset)
                    reset_page(c2, token, "The current password is not right.", 401);
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
        hash_password(fresh, [this, weak, token, carried_on, id, from_reset](std::string hash)
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
            // A new password ends the sessions and app passwords given before it, as a stolen one would want.
            update_account(id, {{"password", hash}, {"reset", ""}, {"password_set", std::to_string(wall::now_sec())},
                                {"revoked_before", std::to_string(wall::now_ms())}, {"app_passwords", ""}},
                           [this, weak, token, carried_on, id, from_reset](bool ok, const std::string&)
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
                    signed_in(*a2, {}, "with a new password");
                    if (from_reset)
                    {
                        const bool remember = m_pending.contains(token) && m_pending[token].remember;
                        m_pending.erase(token);
                        grant(c3, carried_on, *a2, session_cookie(*a2, remember));
                    }
                    else
                        respond(c3, 200, "text/html; charset=utf-8",
                                page("Password changed", "<h1>Password changed</h1><p class=\"mut\">Every other "
                                                         "session and every app password has ended.</p><p><a "
                                                         "href=\"/account\">Your account</a></p>"),
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

namespace
{

// Why the e-mail an admin gives an account in `f` is no plain address; one that is is vouched for, unless `f` says.
std::string admin_email(field_list& f)
{
    const auto e = std::find_if(f.begin(), f.end(), [](const auto& kv) { return kv.first == "email"; });
    if (e == f.end())
        return {};
    if (std::string why = email_problem(e->second); !why.empty())
        return why;
    if (std::none_of(f.begin(), f.end(), [](const auto& kv) { return kv.first == "email_verified"; }))
        f.emplace_back("email_verified", e->second.empty() ? "" : "1");
    return {};
}

}   // namespace

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
    // The SSH authority's public key, and a host certificate: `ssh-host <key line> <names> <days>`.
    if (action == "ssh-ca")
    {
        answer_command(ticket, m_ssh_ca ? m_ssh_ca_line + "\n"
                                        : std::string("error: this provider signs no SSH certificates; give it --ssh-ca"));
        return;
    }
    if (action == "ssh-host")
    {
        uint32_t days = 0;
        if (args.size() != 4 || std::from_chars(args[3].data(), args[3].data() + args[3].size(), days).ec != std::errc{} ||
            days < 1 || days > 3650)
        {
            answer_command(ticket, "error: idp-user ssh-host takes a public key line, names and 1 to 3650 days");
            return;
        }
        const std::string out = ssh_host_cert(args[1], args[2], days);
        answer_command(ticket, out.starts_with("error: ") ? out : out + "\n");
        return;
    }
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
    // A mail runtime asking whether an address is a user's, and whether a password it was given is theirs: by the
    // username, the address being an e-mail this provider vouches for, or its name being a username.
    const auto named = [this](std::string_view name) -> const account* {
        if (const account* a = m_accounts.by_name(name))
            return a;
        const size_t at = name.find('@');
        if (at == std::string_view::npos)
            return nullptr;
        for (const account* a : m_accounts.all())
            if (email_trusted(*a) && socketley::ascii::iequals(a->field("email"), name))
                return a;
        return m_accounts.by_name(name.substr(0, at));
    };
    if (action == "lookup")
    {
        const account* who = named(user);
        // The user, the email and the mail quota a mail runtime keeps their mailbox within.
        answer_command(ticket, who && !who->disabled() ? "ok " + std::string(who->username()) + "\t" +
                                                             std::string(trusted_email(*who)) + "\t" +
                                                             std::string(who->field("mail_quota"))
                                                       : std::string("none"));
        return;
    }
    if (action == "verify")
    {
        const account* who = named(user);
        if (who && who->disabled())
            who = nullptr;
        const std::string name = who ? std::string(who->username()) : std::string();
        const std::string email = who ? std::string(trusted_email(*who)) : std::string();
        const std::string quota = who ? std::string(who->field("mail_quota")) : std::string();
        check_mail_password(who, args.size() > 2 ? args[2] : std::string(), [this, ticket, name, email, quota](bool ok) {
            answer_command(ticket, ok ? "ok " + name + "\t" + email + "\t" + quota : std::string("error: no"));
        });
        return;
    }
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
                if (kv.compare(0, eq, "username") == 0 || kv.compare(0, eq, "created") == 0)
                {
                    answer_command(ticket, "error: the field " + kv.substr(0, eq) + " is set by the provider, not by --set");
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
        if (const std::string why = admin_email(fields); !why.empty())
        {
            answer_command(ticket, "error: " + why);
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
            hash_password(password, [this, ticket, create, fields = std::move(fields)](std::string hash) mutable {
            if (hash.empty())
            {
                answer_command(ticket, "error: the password could not be hashed");
                return;
            }
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
    // totp <user> on|off: a second step of signing in, its key given once to put into an authenticator app.
    if (action == "totp")
    {
        const std::string how = args.size() > 2 ? args[2] : std::string();
        if (how == "off")
        {
            apply({{"totp", ""}}, "ok");
            return;
        }
        if (how != "on")
        {
            answer_command(ticket, "error: idp-user totp <user> on|off");
            return;
        }
        const std::string seed = random_string(20);
        if (seed.empty())
        {
            answer_command(ticket, "error: no randomness for a key");
            return;
        }
        const std::string key = base32_encode(seed);
        apply({{"totp", key}}, totp_uri(url_host(m_issuer), user, key) + "\nkey: " + key);
        return;
    }
    // app-password <user> add <label> | remove <label> | list: passwords a mail app signs in with, each its own.
    if (action == "app-password")
    {
        const std::string how = args.size() > 2 ? args[2] : std::string(), label = args.size() > 3 ? args[3] : std::string();
        const auto parse_lines = [](const account* a) {
            std::vector<std::string> out;
            for (std::string_view rest = a ? a->field("app_passwords") : std::string_view{}; !rest.empty();)
            {
                const size_t nl = rest.find('\n');
                if (const std::string_view l = rest.substr(0, nl); !l.empty())
                    out.emplace_back(l);
                rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
            }
            return out;
        };
        std::vector<std::string> lines = parse_lines(who);
        const auto label_of = [](const std::string& l) { return l.substr(0, l.find('\t')); };
        if (how == "list")
        {
            std::string out;
            for (const auto& l : lines)
                out += label_of(l) + "\n";
            answer_command(ticket, out);
            return;
        }
        if (label.empty() || label.find_first_of("\t\n") != std::string::npos || label.size() > 64 ||
            (how != "add" && how != "remove"))
        {
            answer_command(ticket, "error: idp-user app-password <user> add <label> | remove <label> | list");
            return;
        }
        const bool had = std::any_of(lines.begin(), lines.end(), [&](const std::string& l) { return label_of(l) == label; });
        if (how == "remove")
        {
            if (!had)
            {
                answer_command(ticket, "error: " + user + " has no app password named " + label);
                return;
            }
            std::erase_if(lines, [&](const std::string& l) { return label_of(l) == label; });
            std::string joined;
            for (const auto& l : lines)
                joined += l + "\n";
            apply({{"app_passwords", joined}}, "ok");
            return;
        }
        if (had || lines.size() >= 10)
        {
            answer_command(ticket, had ? "error: " + user + " has an app password named " + label + " already"
                                       : "error: " + user + " has ten app passwords; remove one first");
            return;
        }
        // Four groups of four letters, typed on a phone without a mistake, about 75 bits.
        const std::string raw = random_string(16);
        if (raw.size() != 16)
        {
            answer_command(ticket, "error: no randomness for a password");
            return;
        }
        std::string pw;
        for (size_t i = 0; i < 16; ++i)
            pw += std::string(i && i % 4 == 0 ? "-" : "") + static_cast<char>('a' + static_cast<unsigned char>(raw[i]) % 26);
        hash_password(pw, [this, apply, parse_lines, ticket, id, user, label, pw](std::string hash) {
            if (hash.empty())
            {
                answer_command(ticket, "error: the password could not be hashed");
                return;
            }
            // Read again here, since another change to the list may have landed while the hash ran.
            const std::vector<std::string> lines = parse_lines(m_accounts.by_id(id));
            const auto label_of = [](const std::string& l) { return l.substr(0, l.find('\t')); };
            if (lines.size() >= 10 || std::any_of(lines.begin(), lines.end(), [&](const std::string& l) { return label_of(l) == label; }))
            {
                answer_command(ticket, "error: " + user + " has ten app passwords or one named " + label + " already");
                return;
            }
            std::string joined;
            for (const auto& l : lines)
                joined += l + "\n";
            joined += label + "\t" + hash + "\t" + std::to_string(wall::now_sec()) + "\n";
            apply({{"app_passwords", joined}}, pw);
        });
        return;
    }
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
        hash_password(password, [this, ticket, apply, reset](std::string hash) {
            if (hash.empty())
            {
                answer_command(ticket, "error: the password could not be hashed");
                return;
            }
            const std::string now = std::to_string(wall::now_sec());
            apply({{"password", std::move(hash)}, {"password_set", now}, {"revoked_before", std::to_string(wall::now_ms())},
                   {"reset", reset ? "1" : ""}, {"app_passwords", ""}},
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
        if (const std::string why = admin_email(f); !why.empty())
        {
            answer_command(ticket, "error: " + why);
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
        // Its app passwords too, as signing out everywhere on the account page ends them.
        apply({{"revoked_before", std::to_string(wall::now_ms())}, {"app_passwords", ""}}, "");
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
    std::string admins;
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
            // An admin here is root by SSH certificate, more than a storage's admin may hand out, so it is only said.
            if (k == "admin")
            {
                if (v == "1")
                    admins += u.key + " was an admin of the storage and is none here; idp-user " +
                              std::string(m_owner.get_name()) + " set " + u.key + " groups=admins makes it one\n";
            }
            // A storage user's e-mail is taken as one nobody here vouched for.
            else if (k == "name" || (k == "email" && email_problem(v).empty()) || k == "password" || k == "reset")
                f.emplace_back(k, v);
        }
        fresh.push_back(std::move(f));
    }
    std::string errors;
    const size_t added = m_accounts.create_many(fresh, errors);
    answer_command(ticket, std::to_string(added) + " " + std::to_string(kept) + "\n" + errors + admins);
}

// ─── Shards ─────────────────────────────────────────────────────────────────

bool idp_run::publish_standing()
{
    if (m_reader || m_accounts.changes() == m_standing_at)
        return true;
    std::string doc(standing_format);
    for (const account* a : m_accounts.all())
    {
        // An id a line cannot hold is left out, so its sessions are refused rather than misread.
        if (a->id.find_first_of(" \t\r\n") != std::string::npos)
            continue;
        standing s;
        const std::string_view before = a->field("revoked_before");
        std::from_chars(before.data(), before.data() + before.size(), s.revoked_before);
        s.admin = a->in_group("admins");
        s.disabled = a->disabled();
        s.reset = a->field("reset") == "1";
        append_standing(doc, a->id, s);
    }
    if (doc != m_standing)
    {
        // Synced, since a crash that brought back the file before a sign-out would let its sessions in again.
        std::string why;
        const std::string path = idp_standing_path(m_owner.get_name());
        if (!replace_file(path, doc, durability::data_and_dir, &why))
        {
            LOG_WARN(("idp " + std::string(m_owner.get_name()) + ": " + path + " could not be written: " + why).c_str());
            return false;
        }
        m_standing = std::move(doc);
    }
    m_standing_at = m_accounts.changes();
    return true;
}

void idp_run::publish_accounts()
{
    publish_standing();
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

bool idp_run::write_account(const std::string& id, const field_list& fields, std::string& why)
{
    const account* a = m_accounts.by_id(id);
    field_list set;
    for (const auto& [k, v] : fields)
        if (!k.starts_with('?'))
            set.emplace_back(k, v);
        else if (!a || a->field(std::string_view(k).substr(1)) != v)
        {
            why = std::string(changed_meanwhile);
            return false;
        }
    return m_accounts.update(id, set, why);
}

void idp_run::update_account(const std::string& id, field_list fields,
                             std::function<void(bool, const std::string&)> then)
{
    if (!m_reader)
    {
        std::string why;
        const bool ok = write_account(id, fields, why);
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
            const bool ok = !m_reader && write_account(call.key, call.fields, why);
            if (m_reader)
                why = "the accounts are written by shard 0";
            publish_accounts();
            mgr->requests().complete_deferred(ticket, request_status::ok, encode_result(ok, why));
            return;
        }
        case shard_call::miss:
            m_limits.failed(call.key, call.at);
            arm_tick();
            mgr->requests().complete_deferred(ticket, request_status::ok, {});
            return;
        case shard_call::device_decide:
        {
            std::string allow, sub;
            for (const auto& [k, v] : call.fields)
            {
                if (k == "allow")
                    allow = v;
                else if (k == "sub")
                    sub = v;
            }
            const bool ok = !sub.empty() && decide_device(call.key, allow == "1", sub, call.at);
            mgr->requests().complete_deferred(ticket, request_status::ok, encode_result(ok, {}));
            return;
        }
        case shard_call::device_peek:
        {
            const auto u = m_user_codes.find(call.key);
            const auto d = u == m_user_codes.end() ? m_devices.end() : m_devices.find(u->second);
            const bool waiting = d != m_devices.end() && d->second.expires > call.at && d->second.state == device_entry::pending;
            mgr->requests().complete_deferred(ticket, request_status::ok,
                                              encode_device(waiting ? device_poll::pending : device_poll::gone,
                                                            waiting ? &d->second : nullptr));
            return;
        }
        case shard_call::device_ask:
        {
            std::string client_id;
            for (const auto& [k, v] : call.fields)
                if (k == "client_id")
                    client_id = v;
            device_entry e;
            const device_poll what = poll_device(call.key, client_id, call.at, e);
            mgr->requests().complete_deferred(ticket, request_status::ok,
                                              encode_device(what, what == device_poll::approved ? &e : nullptr));
            return;
        }
    }
    mgr->requests().complete_deferred(ticket, request_status::ok, {});
}

}   // namespace socketley::idp
