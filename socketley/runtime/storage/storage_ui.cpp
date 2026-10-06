// The web interface at /~ui/: one page, served from the binary, that browses, uploads to, shares from and plays
// what the runtime holds, through /~dav/, /~share/ and /~media/; its sign-in, a cookie sealed with the access key's own
// secret (/~ui/session); the films each user has part watched (/~ui/progress); and who else a library is shared with
// (/~ui/access).
#include "storage_run.h"

#include <sys/file.h>
#include <sys/stat.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>

#include "digest.h"
#include "json_doc.h"
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
// The positions kept for a user, the most recently watched first.
constexpr size_t  progress_max = 200;

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

std::string num(double v)
{
    char buf[32];
    std::snprintf(buf, sizeof buf, "%.3f", v);
    return buf;
}

const jvalue* member(const jvalue& o, std::string_view n)
{
    for (const auto& [k, v] : o.members)
        if (k == n)
            return &v;
    return nullptr;
}

std::string str_of(const jvalue& o, std::string_view n)
{
    const jvalue* v = member(o, n);
    return v && v->k == jvalue::kind::string ? v->s : std::string{};
}

double num_of(const jvalue& o, std::string_view n)
{
    const jvalue* v = member(o, n);
    return v && v->k == jvalue::kind::number ? std::strtod(v->s.c_str(), nullptr) : 0;
}

// One film's position: where it was left, its length, the version it was watched in, and when.
struct position
{
    std::string bucket, key, etag;
    double      t{0}, d{0};
    int64_t     at{0};
};

std::vector<position> read_positions(const std::string& path)
{
    std::vector<position> out;
    std::string text;
    jvalue root;
    if (!read_small_file(path, text) || !json_reader(text).document(root))
        return out;
    const jvalue* items = member(root, "items");
    if (!items || items->k != jvalue::kind::array)
        return out;
    for (const jvalue& i : items->items)
    {
        position p;
        p.bucket = str_of(i, "b");
        p.key    = str_of(i, "k");
        p.etag   = str_of(i, "e");
        p.t      = num_of(i, "t");
        p.d      = num_of(i, "d");
        p.at     = static_cast<int64_t>(num_of(i, "at"));
        if (!p.bucket.empty() && !p.key.empty())
            out.push_back(std::move(p));
    }
    return out;
}

std::string positions_json(const std::vector<position>& ps)
{
    std::string o = "{\"items\":[";
    for (size_t i = 0; i < ps.size(); ++i)
    {
        const position& p = ps[i];
        o += i ? ",{\"b\":" : "{\"b\":";
        jstr(o, p.bucket);
        o += ",\"k\":";
        jstr(o, p.key);
        o += ",\"e\":";
        jstr(o, p.etag);
        o += ",\"t\":" + num(p.t) + ",\"d\":" + num(p.d) + ",\"at\":" + std::to_string(p.at) + "}";
    }
    o += "]}";
    return o;
}

// A JSON value written back as JSON, for a policy read, changed and stored again.
void to_json(std::string& o, const jvalue& v)
{
    switch (v.k)
    {
        case jvalue::kind::null: o += "null"; return;
        case jvalue::kind::boolean: o += v.b ? "true" : "false"; return;
        case jvalue::kind::number: o += v.s; return;
        case jvalue::kind::string: jstr(o, v.s); return;
        case jvalue::kind::array:
            o += '[';
            for (size_t i = 0; i < v.items.size(); ++i)
            {
                o += i ? "," : "";
                to_json(o, v.items[i]);
            }
            o += ']';
            return;
        case jvalue::kind::object:
            o += '{';
            for (size_t i = 0; i < v.members.size(); ++i)
            {
                o += i ? "," : "";
                jstr(o, v.members[i].first);
                o += ':';
                to_json(o, v.members[i].second);
            }
            o += '}';
            return;
    }
}

// The statements the interface writes into a bucket's policy are named by their Sid, socketley-ui-<access>:<user>,
// and it reads and changes only those; whatever else the policy says stays as it was.
constexpr std::string_view ui_sid = "socketley-ui-";

constexpr std::string_view read_actions[]  = {"s3:ListBucket", "s3:GetBucketLocation", "s3:GetObject"};
constexpr std::string_view write_actions[] = {"s3:ListBucket", "s3:GetBucketLocation", "s3:GetObject", "s3:PutObject",
                                     "s3:DeleteObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts",
                                     "s3:ListBucketVersions", "s3:GetObjectVersion", "s3:DeleteObjectVersion"};

std::string ui_statement(std::string_view bucket, std::string_view user, bool write)
{
    std::string o = "{\"Sid\":";
    jstr(o, std::string(ui_sid) + (write ? "write:" : "read:") + std::string(user));
    o += ",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":[";
    jstr(o, "arn:aws:iam::000000000000:user/" + std::string(user));
    o += "]},\"Action\":[";
    const std::string_view* acts = write ? write_actions : read_actions;
    const size_t n = write ? std::size(write_actions) : std::size(read_actions);
    for (size_t i = 0; i < n; ++i)
    {
        o += i ? "," : "";
        jstr(o, acts[i]);
    }
    o += "],\"Resource\":[";
    jstr(o, "arn:aws:s3:::" + std::string(bucket));
    o += ',';
    jstr(o, "arn:aws:s3:::" + std::string(bucket) + "/*");
    o += "]}";
    return o;
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
    if (r.key == "progress")
    {
        ui_progress(c);
        return;
    }
    if (r.key == "access")
    {
        ui_access(c);
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

// GET lists the films the signed-in user has part watched, those it may still read in the version it watched, the
// most recent first; POST {bucket, key, t, d} keeps where one was left, and t below 0 forgets it. Each user's are a
// file of their own, <dir>/.ui/progress/<sha-256 of the user>.json, changed under a lock beside it, entry by entry,
// so two devices watching different films keep both.
void storage_run::ui_progress(const std::shared_ptr<conn>& c)
{
    s3_request& r = c->req;
    if (r.method != "GET" && r.method != "POST")
    {
        app_reply(c, 405, "Positions are read with GET and kept with POST.\n");
        return;
    }
    if (!app_login(c, "socketley"))
        return;
    if (r.method == "POST")
    {
        if (r.chunked || (r.has_content_length && r.content_length > 16 * 1024))
        {
            r.keep_alive = false;
            app_reply(c, 413, "Request body too large.\n");
            return;
        }
        collect_body(c, 16 * 1024);
        return;
    }
    const std::string who = c->user ? c->user->id : c->anonymous ? std::string("anonymous") : c->principal;
    const std::string path = m_store.options().dir + "/.ui/progress/" + sha256_hex(who).substr(0, 32) + ".json";
    std::vector<position> ps = read_positions(path);
    std::sort(ps.begin(), ps.end(), [](const position& a, const position& b) { return a.at > b.at; });
    if (ps.size() > 60)
        ps.resize(60);
    // Each is looked at as it is now: what the user may no longer read, or was replaced or removed since, is left out.
    struct gather
    {
        std::vector<position> ps;
        std::vector<std::string> out;
        size_t left{0};
    };
    auto g = std::make_shared<gather>();
    for (position& p : ps)
        if (app_allowed(c, "GET", p.bucket, p.key))
            g->ps.push_back(std::move(p));
    g->out.resize(g->ps.size());
    g->left = g->ps.size();
    std::weak_ptr<conn> weak = c;
    auto finish = [this, weak, g]()
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        std::string o = "[";
        bool first = true;
        for (const std::string& s : g->out)
            if (!s.empty())
            {
                o += first ? "" : ",";
                first = false;
                o += s;
            }
        o += "]";
        response out;
        out.status = 200;
        out.headers.emplace_back("Content-Type", "application/json");
        out.headers.emplace_back("Cache-Control", "no-store");
        out.body = std::move(o);
        send_response(cc, std::move(out));
    };
    if (!g->left)
    {
        finish();
        return;
    }
    for (size_t i = 0; i < g->ps.size(); ++i)
        m_store.stat_object(g->ps[i].bucket, g->ps[i].key, [g, i, finish](st s, const object_meta& m)
        {
            const position& p = g->ps[i];
            if (s == st::ok && m.etag() == p.etag)
            {
                std::string o = "{\"bucket\":";
                jstr(o, p.bucket);
                o += ",\"key\":";
                jstr(o, p.key);
                o += ",\"t\":" + num(p.t) + ",\"d\":" + num(p.d) + ",\"at\":" + std::to_string(p.at) +
                     ",\"size\":" + std::to_string(m.size) + ",\"type\":";
                jstr(o, m.content_type.str());
                o += "}";
                g->out[i] = std::move(o);
            }
            if (--g->left == 0)
                finish();
        });
}

void storage_run::ui_body(const std::shared_ptr<conn>& c)
{
    if (c->req.key == "access")
        ui_access_body(c);
    else
        ui_progress_body(c);
}

void storage_run::ui_progress_body(const std::shared_ptr<conn>& c)
{
    jvalue req;
    if (!json_reader(c->body).document(req))
    {
        app_reply(c, 400, "The body is a JSON object: bucket, key, t and d.\n");
        return;
    }
    position p;
    p.bucket = str_of(req, "bucket");
    p.key    = str_of(req, "key");
    p.t      = num_of(req, "t");
    p.d      = num_of(req, "d");
    if (p.bucket.empty() || p.key.empty() || !(p.d >= 0) || p.t > p.d + 1)
    {
        app_reply(c, 400, "A position names a bucket and a key, and lies within the film's length.\n");
        return;
    }
    // A user keeps positions only in what it may read, and the version it watched is the one there now.
    if (!app_allowed(c, "GET", p.bucket, p.key))
    {
        app_reply(c, 403, "You may not read that.\n");
        return;
    }
    const std::string who = c->user ? c->user->id : c->anonymous ? std::string("anonymous") : c->principal;
    std::weak_ptr<conn> weak = c;
    const std::string bucket = p.bucket, key = p.key;
    m_store.stat_object(bucket, key, [this, weak, who, p = std::move(p)](st s, const object_meta& m) mutable
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (s != st::ok)
        {
            app_reply(cc, 404, "No such object.\n");
            return;
        }
        p.etag = m.etag();
        p.at   = wall_ms();
        const std::string dir = m_store.options().dir + "/.ui";
        if ((::mkdir(dir.c_str(), 0700) < 0 && errno != EEXIST) ||
            (::mkdir((dir + "/progress").c_str(), 0700) < 0 && errno != EEXIST))
        {
            app_reply(cc, 500, "The positions' folder cannot be made.\n");
            return;
        }
        const std::string path = dir + "/progress/" + sha256_hex(who).substr(0, 32) + ".json";
        const int fd = ::open((path + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (fd < 0 || ::flock(fd, LOCK_EX) < 0)
        {
            if (fd >= 0)
                ::close(fd);
            app_reply(cc, 500, "The positions could not be locked.\n");
            return;
        }
        std::vector<position> ps = read_positions(path);
        std::erase_if(ps, [&p](const position& x) { return x.bucket == p.bucket && x.key == p.key; });
        if (p.t >= 0)
            ps.push_back(std::move(p));
        std::sort(ps.begin(), ps.end(), [](const position& a, const position& b) { return a.at > b.at; });
        if (ps.size() > progress_max)
            ps.resize(progress_max);
        const bool ok = write_small_file(path, positions_json(ps), false);
        ::flock(fd, LOCK_UN);
        ::close(fd);
        app_reply(cc, ok ? 204 : 500, ok ? std::string{} : "The position could not be kept.\n");
    });
}

// GET ?bucket= says who else may read or write a library, as the statements the interface wrote into its policy say;
// POST {bucket, user, access: read | write | none} changes that for one user. Both are its owner's, or whoever may read
// and write the bucket's policy; the statements are named by their Sid, and the rest of the policy is kept.
void storage_run::ui_access(const std::shared_ptr<conn>& c)
{
    s3_request& r = c->req;
    if (r.method != "GET" && r.method != "POST")
    {
        app_reply(c, 405, "Access is read with GET and changed with POST.\n");
        return;
    }
    if (!app_login(c, "socketley"))
        return;
    if (r.method == "POST")
    {
        if (r.chunked || (r.has_content_length && r.content_length > 16 * 1024))
        {
            r.keep_alive = false;
            app_reply(c, 413, "Request body too large.\n");
            return;
        }
        collect_body(c, 16 * 1024);
        return;
    }
    const std::string bucket(r.get_query("bucket"));
    if (!m_store.has_bucket(bucket))
    {
        app_reply(c, 404, "No such bucket.\n");
        return;
    }
    if (!app_allowed(c, "GET", bucket, {}, "policy"))
    {
        app_reply(c, 403, "Only who may read the library's policy sees who it is shared with.\n");
        return;
    }
    std::string o = "{\"bucket\":";
    jstr(o, bucket);
    o += ",\"owner\":";
    jstr(o, owner_of(bucket));
    o += ",\"grants\":[";
    bool first = true;
    jvalue root;
    if (const bucket_policy* p = m_store.policy(bucket); p && json_reader(p->text()).document(root))
        if (const jvalue* st = member(root, "Statement"))
        {
            const auto one = [&](const jvalue& x)
            {
                const std::string sid = str_of(x, "Sid");
                const size_t colon = sid.find(':');
                if (!sid.starts_with(ui_sid) || colon == std::string::npos)
                    return;
                o += first ? "{\"user\":" : ",{\"user\":";
                first = false;
                jstr(o, sid.substr(colon + 1));
                o += ",\"access\":";
                jstr(o, sid.substr(ui_sid.size(), colon - ui_sid.size()));
                o += "}";
            };
            if (st->k == jvalue::kind::array)
                for (const jvalue& x : st->items)
                    one(x);
            else if (st->k == jvalue::kind::object)
                one(*st);
        }
    o += "]}";
    app_reply(c, 200, std::move(o), "application/json");
}

void storage_run::ui_access_body(const std::shared_ptr<conn>& c)
{
    jvalue req;
    if (!json_reader(c->body).document(req))
    {
        app_reply(c, 400, "The body is a JSON object: bucket, user and access.\n");
        return;
    }
    const std::string bucket = str_of(req, "bucket"), user = str_of(req, "user"), access = str_of(req, "access");
    if (access != "read" && access != "write" && access != "none")
    {
        app_reply(c, 400, "Access is read, write or none.\n");
        return;
    }
    if (!m_store.has_bucket(bucket))
    {
        app_reply(c, 404, "No such bucket.\n");
        return;
    }
    if (!app_allowed(c, "PUT", bucket, {}, "policy"))
    {
        app_reply(c, 403, "Only who may change the library's policy shares it.\n");
        return;
    }
    if (user.empty() || user.size() > 127 || user.find_first_of(" /:=,*?\"") != std::string::npos ||
        !m_auth->has_user(user))
    {
        app_reply(c, 404, "No such user.\n");
        return;
    }
    if (user == owner_of(bucket))
    {
        app_reply(c, 400, "The library is that user's own.\n");
        return;
    }
    // The policy as it is, without this user's statements of ours, and with the one asked for.
    jvalue root;
    std::vector<std::string> statements;
    std::string head;
    if (const bucket_policy* p = m_store.policy(bucket); p && json_reader(p->text()).document(root))
        for (const auto& [k, v] : root.members)
        {
            if (k != "Statement")
            {
                if (k == "Version")
                    continue;
                head += ",";
                jstr(head, k);
                head += ":";
                to_json(head, v);
                continue;
            }
            const auto keep = [&](const jvalue& x)
            {
                const std::string sid = str_of(x, "Sid");
                if (sid.starts_with(ui_sid) && sid.ends_with(":" + user))
                    return;
                std::string t;
                to_json(t, x);
                statements.push_back(std::move(t));
            };
            if (v.k == jvalue::kind::array)
                for (const jvalue& x : v.items)
                    keep(x);
            else if (v.k == jvalue::kind::object)
                keep(v);
        }
    if (access != "none")
        statements.push_back(ui_statement(bucket, user, access == "write"));
    std::string text;
    if (!statements.empty())
    {
        text = "{\"Version\":\"2012-10-17\"" + head + ",\"Statement\":[";
        for (size_t i = 0; i < statements.size(); ++i)
            text += (i ? "," : "") + statements[i];
        text += "]}";
        bucket_policy checked;
        s3_error err;
        if (!bucket_policy::compile(text, bucket, checked, err))
        {
            app_reply(c, 400, "The policy would not be one: " + err.message + "\n");
            return;
        }
    }
    store_doc(c, bucket_doc::policy, bucket, std::move(text), 204);
}

}   // namespace socketley::storage
