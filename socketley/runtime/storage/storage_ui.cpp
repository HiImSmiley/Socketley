// The web interface at /~ui/: one page, served from the binary, that browses, uploads to, shares from and plays
// what the runtime holds, through /~dav/, /~share/ and /~media/; its sign-in, a cookie sealed with the access key's own
// secret (/~ui/session).
#include "storage_run.h"


#include <chrono>
#include <cstdlib>

#include "digest.h"
#include "s3_names.h"
#include "small_file.h"
#include "../../shared/http_framing.h"
#include "../../shared/state_persistence.h"

namespace socketley::storage
{

namespace
{

#include "storage_ui_page.inc"

constexpr std::string_view cookie_name = "skl_ui";
// How long a sign-in lasts: a browser's session, or a month when asked to stay.
constexpr int64_t session_ms  = 12ll * 3600 * 1000;
constexpr int64_t remember_ms = 30ll * 24 * 3600 * 1000;

int64_t wall_ms()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string_view cookie_value(std::string_view header, std::string_view name)
{
    while (!header.empty())
    {
        const size_t semi = header.find(';');
        std::string_view part = header.substr(0, semi);
        header = semi == std::string_view::npos ? std::string_view{} : header.substr(semi + 1);
        while (!part.empty() && part.front() == ' ')
            part.remove_prefix(1);
        if (part.size() > name.size() && part.starts_with(name) && part[name.size()] == '=')
            return part.substr(name.size() + 1);
    }
    return {};
}

void jstr(std::string& o, std::string_view v)
{
    o += '"';
    o += sp_detail::json_escape(v);
    o += '"';
}

}   // namespace

bool storage_run::has_ui_cookie(const conn& c)
{
    return !cookie_value(c.req.header("cookie"), cookie_name).empty();
}

bool storage_run::ui_cookie(const std::shared_ptr<conn>& c, auth_verdict& v)
{
    // <access key, base64url>.<expiry in ms>.<HMAC-SHA256 under the key's secret, hex>
    const std::string_view val = cookie_value(c->req.header("cookie"), cookie_name);
    if (val.empty())
        return false;
    v.allowed = false;
    const size_t a = val.find('.'), b = a == std::string_view::npos ? a : val.find('.', a + 1);
    std::string key;
    if (b == std::string_view::npos || !base64url_decode(val.substr(0, a), key) || key.empty())
        return true;
    const std::string_view exp_text = val.substr(a + 1, b - a - 1);
    char* end = nullptr;
    const std::string exp_s(exp_text);
    const long long exp = std::strtoll(exp_s.c_str(), &end, 10);
    if (exp_s.empty() || !end || *end || exp < wall_ms())
        return true;
    v = m_auth->authorize_ui_session(key, exp, val.substr(b + 1));
    return true;
}

std::string storage_run::attachment_of(std::string_view key)
{
    const size_t slash = key.rfind('/');
    const std::string_view name = slash == std::string_view::npos ? key : key.substr(slash + 1);
    // A plain name for old clients, without what would end or break its quotes, and the name itself as RFC 6266 gives it.
    std::string plain;
    for (const char ch : name)
        plain += (static_cast<unsigned char>(ch) < 0x20 || static_cast<unsigned char>(ch) >= 0x7f || ch == '"' ||
                  ch == '\\') ? '_' : ch;
    std::string out = "attachment; filename=\"" + plain + "\"; filename*=UTF-8''";
    url_encode_to(out, name, false);
    return out;
}

void storage_run::op_ui(const std::shared_ptr<conn>& c)
{
    const s3_request& r = c->req;
    if (r.key == "session")
    {
        ui_session(c);
        return;
    }
    if (r.method != "GET" && r.method != "HEAD")
    {
        app_reply(c, 405, "The interface is read only.\n");
        return;
    }
    // The page changes only with the binary, so a browser's copy is asked after and answered 304 while it holds.
    static const std::string etag = "\"" + sha256_hex(ui_page).substr(0, 16) + "\"";
    response resp;
    resp.headers.emplace_back("ETag", etag);
    resp.headers.emplace_back("Cache-Control", "no-cache");
    if (r.header("if-none-match").find(etag) != std::string_view::npos)
    {
        resp.status = 304;
        resp.head_only = true;
        resp.has_length_override = true;
        send_response(c, std::move(resp));
        return;
    }
    resp.headers.emplace_back("Content-Type", "text/html; charset=utf-8");
    resp.headers.emplace_back("Content-Security-Policy",
                              "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                              "media-src 'self' blob:; img-src 'self' blob: data:; frame-ancestors 'none'");
    resp.headers.emplace_back("X-Content-Type-Options", "nosniff");
    resp.body_view = ui_page;
    resp.head_only = r.method == "HEAD";
    send_response(c, std::move(resp));
}

// POST signs in with Basic credentials and sets the cookie (?remember for a month), GET says who is signed in, and
// DELETE signs out. The cookie is HttpOnly, so the page's script never holds the secret or the session, and
// SameSite=Strict, so no other site's request carries it.
void storage_run::ui_session(const std::shared_ptr<conn>& c)
{
    s3_request& r = c->req;
    const std::string secure_attr = secure(*c) ? "; Secure" : "";
    if (r.method == "DELETE")
    {
        response out;
        out.status = 204;
        out.headers.emplace_back("Set-Cookie", std::string(cookie_name) + "=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict" + secure_attr);
        send_response(c, std::move(out));
        return;
    }
    if (r.method != "GET" && r.method != "POST")
    {
        app_reply(c, 405, "Sign in with POST, ask with GET, sign out with DELETE.\n");
        return;
    }
    // A sign-in is made from the credentials themselves and never from a session, so a cookie cannot extend itself.
    const std::string_view h = r.header("authorization");
    if (r.method == "POST" && !h.starts_with("Basic ") && !h.starts_with("basic "))
    {
        static const std::vector<header_ref> none;
        request_view rv;
        rv.method   = r.method;
        rv.raw_path = r.raw_path;
        rv.headers  = &none;
        if (!m_auth->authorize(rv).allowed)
        {
            app_reply(c, 401, "Sign in with an access key as the user name and its secret as the password.\n");
            return;
        }
    }
    if (!app_login(c, "socketley"))
        return;
    const user_identity* u = c->user.get();
    response out;
    out.status = 200;
    int64_t expires = 0;
    if (r.method == "POST" && !c->anonymous)
    {
        std::string pair;
        base64_decode(http_trim_ows(h.substr(6)), pair);
        const size_t colon = pair.find(':');
        const std::string_view key = std::string_view(pair).substr(0, colon), secret = std::string_view(pair).substr(colon + 1);
        const bool remember = r.has_query("remember");
        expires = wall_ms() + (remember ? remember_ms : session_ms);
        std::string cookie = std::string(cookie_name) + "=" + base64url_encode(key) + "." + std::to_string(expires) + "." +
                             hmac_sha256_hex(secret, ui_session_text(key, expires)) +
                             "; Path=/; HttpOnly; SameSite=Strict" + secure_attr;
        if (remember)
            cookie += "; Max-Age=" + std::to_string(remember_ms / 1000);
        out.headers.emplace_back("Set-Cookie", std::move(cookie));
    }
    std::string o = "{\"user\":";
    jstr(o, u ? std::string_view(u->id) : std::string_view{});
    o += ",\"name\":";
    jstr(o, u ? m_auth->display_name(u->id) : std::string{});
    o += u && u->admin ? ",\"admin\":true" : ",\"admin\":false";
    o += c->anonymous ? ",\"anonymous\":true" : ",\"anonymous\":false";
    o += ",\"expires\":" + std::to_string(expires) + "}";
    out.headers.emplace_back("Content-Type", "application/json");
    out.headers.emplace_back("Cache-Control", "no-store");
    out.body = std::move(o);
    send_response(c, std::move(out));
}

}   // namespace socketley::storage
