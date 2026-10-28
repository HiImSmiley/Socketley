// The runtime's own applications under paths no bucket can have, and the first of them, WebDAV: /~dav/ is every
// bucket its user may see, a bucket a folder, and a key's slashes its subfolders, so a bucket mounts as a drive.
// A file's GET, PUT, DELETE, COPY and MOVE go down the S3 path, judged and stored as S3's are; what S3 has no
// operation for, a folder's listing, making, removal, copy and move, is done here over the keys under it.
#include "storage_run.h"

#include <algorithm>


#include "digest.h"
#include "s3_names.h"
#include "s3_xml.h"
#include "sse.h"
#include "../../shared/util/logging.h"
#include "../../shared/persist/state_persistence.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/util/base64.h"
#include "../../shared/util/random_id.h"

namespace socketley::storage
{

namespace
{

enum app_kind : uint8_t
{
    app_none,
    app_dav,
    app_share,
    app_ui,
    app_media,
};

constexpr uint64_t app_body_limit = 256 * 1024;
// A folder's copy reads each of its objects whole, so one past this is refused rather than held.
constexpr uint64_t tree_object_max = 256ull << 20;
constexpr size_t   listing_max     = 100000;

std::string dav_href(std::string_view bucket, std::string_view key)
{
    std::string h = "/~dav/";
    if (!bucket.empty())
    {
        url_encode_to(h, bucket, true);
        h += '/';
    }
    url_encode_to(h, key, true);
    return h;
}

std::string_view last_name(std::string_view key)
{
    if (!key.empty() && key.back() == '/')
        key.remove_suffix(1);
    const size_t slash = key.rfind('/');
    return slash == std::string_view::npos ? key : key.substr(slash + 1);
}

void xml_text(std::string& x, std::string_view name, std::string_view v)
{
    x += "<D:";
    x += name;
    x += '>';
    xml_escape_to(x, v);
    x += "</D:";
    x += name;
    x += '>';
}

void dir_response(std::string& x, std::string_view href, std::string_view name, int64_t mtime_ms,
                  std::string_view owner = {})
{
    x += "<D:response><D:href>";
    xml_escape_to(x, href);
    x += "</D:href><D:propstat><D:prop>";
    xml_text(x, "displayname", name);
    x += "<D:resourcetype><D:collection/></D:resourcetype>";
    if (mtime_ms > 0)
        xml_text(x, "getlastmodified", http_date(mtime_ms));
    // Whose library it is, in a namespace of its own, so the UI can set other people's apart from the user's.
    if (!owner.empty())
    {
        x += "<S:owner xmlns:S=\"urn:socketley:storage\">";
        xml_escape_to(x, owner);
        x += "</S:owner>";
    }
    x += "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>";
}

void file_response(std::string& x, std::string_view href, std::string_view name, const object_meta& m)
{
    x += "<D:response><D:href>";
    xml_escape_to(x, href);
    x += "</D:href><D:propstat><D:prop>";
    xml_text(x, "displayname", name);
    x += "<D:resourcetype/>";
    xml_text(x, "getcontentlength", std::to_string(m.size));
    xml_text(x, "getcontenttype", m.content_type.empty() ? std::string_view("application/octet-stream")
                                                        : std::string_view(m.content_type.str()));
    xml_text(x, "getetag", "\"" + m.etag() + "\"");
    xml_text(x, "getlastmodified", http_date(m.mtime_ms));
    xml_text(x, "creationdate", iso8601(m.mtime_ms));
    x += "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>";
}

constexpr std::string_view multistatus_head = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">";

// The bucket and key a /~dav/ path names, from what follows /~dav/.
void split_dav(std::string_view rest, std::string& bucket, std::string& key)
{
    const size_t slash = rest.find('/');
    bucket.assign(rest.substr(0, slash));
    key.assign(slash == std::string_view::npos ? std::string_view{} : rest.substr(slash + 1));
}

}   // namespace

// ─── The applications ───────────────────────────────────────────────────────

bool storage_run::app_request(const std::shared_ptr<conn>& c)
{
    s3_request& r = c->req;
    if (r.vhost || r.bucket.empty() || r.bucket.front() != '~')
        return false;
    if (r.bucket == "~dav")
    {
        r.app = app_dav;
        op_dav(c);
    }
    else if (r.bucket == "~share")
    {
        r.app = app_share;
        op_share(c);
    }
    else if (r.bucket == "~ui")
    {
        r.app = app_ui;
        op_ui(c);
    }
    else if (r.bucket == "~media")
    {
        r.app = app_media;
        op_media(c);
    }
    else
        send_error_st(c, st::invalid_bucket_name);
    return true;
}

void storage_run::app_body(const std::shared_ptr<conn>& c)
{
    switch (c->req.app)
    {
        case app_dav: dav_body(c); return;
        case app_share: share_body(c); return;
        case app_ui: ui_body(c); return;
        default: send_error(c, make_error("InternalError")); return;
    }
}

void storage_run::app_reply(const std::shared_ptr<conn>& c, int status, std::string body, std::string_view type)
{
    response r;
    r.status = status;
    if (!body.empty())
        r.headers.emplace_back("Content-Type", std::string(type));
    r.body = std::move(body);
    send_response(c, std::move(r));
}

std::string storage_run::miss_key(conn& c)
{
    client_address(c);
    // One holder of an IPv6 network has its whole /64, so that is what counts as one address.
    return std::string(1, static_cast<char>(c.ip.family)) +
           std::string(reinterpret_cast<const char*>(c.ip.addr), c.ip.family == 4 ? 4 : c.ip.family == 6 ? 8 : 0);
}

bool storage_run::login_barred(const std::shared_ptr<conn>& c)
{
    const int64_t left = m_misses.barred_for(miss_key(*c), std::chrono::steady_clock::now());
    if (!left)
        return false;
    response r;
    r.status = 429;
    r.headers.emplace_back("Retry-After", std::to_string(left));
    r.headers.emplace_back("Content-Type", "text/plain; charset=utf-8");
    r.body = "Too many failed sign-ins from this address; try again later.\n";
    count_error(*c, "SlowDown");
    send_response(c, std::move(r));
    return true;
}

void storage_run::login_missed(conn& c)
{
    m_misses.missed(miss_key(c), std::chrono::steady_clock::now());
}

bool storage_run::app_login(const std::shared_ptr<conn>& c, std::string_view realm)
{
    const std::string_view h = c->req.header("authorization");
    auth_verdict v;
    if (std::string_view cred; http_auth_credentials(h, "basic", cred))
    {
        // An address that keeps guessing is refused even the right secret, so the answer tells it nothing.
        if (login_barred(c))
            return false;
        std::string pair;
        const size_t colon = base64::decode(cred, pair) ? pair.find(':') : std::string::npos;
        // An access key and its secret, or a user's name and the password of its login profile.
        if (colon != std::string::npos)
        {
            const std::string_view name = std::string_view(pair).substr(0, colon), secret = std::string_view(pair).substr(colon + 1);
            v = m_auth->authorize_basic(name, secret);
            if (!v.allowed)
                v = m_auth->authorize_password(name, secret);
        }
        else
            v.allowed = false;
        if (!v.allowed)
            login_missed(*c);
    }
    else if (ui_cookie(c, v) || idp_cookie(c, v))
    {
        // A browser's session sends its cookie with whatever it asks, another site's form too: a change made under
        // the cookie alone must carry the interface's own header, which no page elsewhere can add without CORS.
        const std::string_view m = c->req.method;
        if (v.allowed && m != "GET" && m != "HEAD" && m != "OPTIONS" && m != "PROPFIND" &&
            c->req.header("x-socketley-ui").empty())
        {
            app_reply(c, 403, "A change made with the web interface's session comes from the web interface.\n");
            return false;
        }
    }
    else
    {
        // No credentials: let in on a runtime that takes none, and asked for them otherwise.
        static const std::vector<header_ref> none;
        request_view rv;
        rv.method   = c->req.method;
        rv.raw_path = c->req.raw_path;
        rv.headers  = &none;
        v = m_auth->authorize(rv);
    }
    if (!v.allowed)
    {
        response r;
        // Signed in at the identity provider as an account that is no user here: known, and let in to nothing.
        if (c->by_idp_refused)
        {
            app_reply(c, 403, "The account signed in is no user of this storage.\n");
            return false;
        }
        r.status = 401;
        // The web interface asks for credentials itself, and a browser's own prompt would come before its form, as it
        // would over a player whose session ran out.
        if (c->req.header("x-socketley-ui").empty() && !has_ui_cookie(*c))
            r.headers.emplace_back("WWW-Authenticate", "Basic realm=\"" + std::string(realm) + "\", charset=\"UTF-8\"");
        // Where the --idp runtime signs a browser in and back to this interface, which the page offers.
        if (m_idp.enabled())
            if (const std::string_view host = c->req.header("host"); !host.empty() &&
                host.find_first_of("\r\n /") == std::string_view::npos)
                if (std::string to = m_idp.login_url(std::string(secure(*c) ? "https://" : "http://") +
                                                     std::string(host) + "/~ui/");
                    !to.empty())
                    r.headers.emplace_back("X-Socketley-Idp-Login", std::move(to));
        r.headers.emplace_back("Content-Type", "text/plain; charset=utf-8");
        r.body = "Sign in with a user's name and password, or an access key and its secret.\n";
        count_error(*c, "AccessDenied");
        send_response(c, std::move(r));
        return false;
    }
    c->principal = std::move(v.principal);
    c->user      = std::move(v.user);
    c->anonymous = v.anonymous;
    return true;
}

bool storage_run::lists_bucket(const std::shared_ptr<conn>& c, const bucket_info& b)
{
    const user_identity* u = c->user.get();
    const std::string_view me = u ? std::string_view(u->id) : default_owner;
    return !u || u->admin || (b.owner.empty() ? default_owner : std::string_view(b.owner)) == me ||
           (m_store.policy(b.name) && app_allowed(c, "GET", b.name, {}));
}

bool storage_run::app_allowed(const std::shared_ptr<conn>& c, std::string_view method, std::string_view bucket,
                              std::string_view key, std::string_view query)
{
    // Nothing to judge leaves the verdict at its allowed default, decided before any copy.
    if (!needs_judging(c->anonymous ? nullptr : c->user.get()))
        return true;
    s3_request& r = c->req;
    // The request is judged as the S3 operation it stands for, and put back as it was.
    const std::string_view old_method = r.method;
    std::string old_bucket = std::move(r.bucket), old_key = std::move(r.key);
    auto old_query = std::move(r.query);
    r.method = method;
    r.bucket.assign(bucket);
    r.key.assign(key);
    r.query.clear();
    if (!query.empty())
        r.query.emplace_back(std::string(query), std::string{});
    auth_verdict v;
    v.anonymous = c->anonymous;
    v.user      = c->user;
    v.principal = c->principal;
    static const std::vector<header_ref> none;
    request_view rv;
    rv.method  = r.method;
    rv.headers = &none;
    rv.bucket  = r.bucket;
    rv.key     = r.key;
    if ((v.allowed || v.anonymous) && needs_judging(v.anonymous ? nullptr : v.user.get()))
        apply_policy(c, rv, v);
    r.method = old_method;
    r.bucket = std::move(old_bucket);
    r.key    = std::move(old_key);
    r.query  = std::move(old_query);
    return v.allowed;
}

void storage_run::app_forward(const std::shared_ptr<conn>& c, std::string_view method, std::string bucket,
                              std::string key, std::string_view extra_name, std::string extra_value,
                              std::vector<std::pair<std::string, std::string>> query)
{
    s3_request& r = c->req;
    r.method = method;
    r.bucket = std::move(bucket);
    r.key    = std::move(key);
    r.query  = std::move(query);
    r.app = app_none;
    if (!extra_name.empty())
    {
        c->app_header = std::move(extra_value);
        r.headers.push_back({extra_name, c->app_header});
    }
    request_view rv;
    rv.method  = r.method;
    rv.headers = &r.headers;
    rv.bucket  = r.bucket;
    rv.key     = r.key;
    auth_verdict v;
    v.anonymous = c->anonymous;
    v.user      = c->user;
    v.principal = c->principal;
    if ((v.allowed || v.anonymous) && needs_judging(v.anonymous ? nullptr : v.user.get()))
        apply_policy(c, rv, v);
    if (!v.allowed)
    {
        c->on_answer = nullptr;
        app_reply(c, 403, "Access denied.\n");
        return;
    }
    c->hook = nullptr;
    hook_request(c);
}

void storage_run::app_list(std::string bucket, list_query q, std::function<void(st, list_page)> done)
{
    // Page after page into one, each page's answer holding the walk, up to the bound of a listing.
    struct pager
    {
        std::string bucket;
        list_query q;
        list_page all;
        std::function<void(st, list_page)> done;
        std::weak_ptr<pager> self;
        std::function<void()> step;
    };
    auto p = std::make_shared<pager>();
    p->bucket = std::move(bucket);
    p->q = std::move(q);
    p->done = std::move(done);
    p->self = p;
    pager* raw = p.get();
    raw->step = [this, raw]()
    {
        m_node.list(raw->bucket, raw->q, [raw, hold = raw->self.lock()](st s, list_page page)
        {
            for (list_entry& e : page.objects)
                raw->all.objects.push_back(std::move(e));
            for (std::string& x : page.prefixes)
                raw->all.prefixes.push_back(std::move(x));
            if (s == st::ok && page.truncated && raw->all.objects.size() + raw->all.prefixes.size() < listing_max)
            {
                raw->q.resume_at  = page.resume_at;
                raw->q.has_resume = true;
                raw->step();
                return;
            }
            raw->all.truncated = s == st::ok && page.truncated;
            auto finish = std::move(raw->done);
            finish(s, std::move(raw->all));
        });
    };
    raw->step();
}

// ─── WebDAV ─────────────────────────────────────────────────────────────────

void storage_run::op_dav(const std::shared_ptr<conn>& c)
{
    s3_request& r = c->req;
    if (r.method == "OPTIONS")
    {
        response resp;
        resp.headers.emplace_back("DAV", "1, 2");
        resp.headers.emplace_back("MS-Author-Via", "DAV");
        resp.headers.emplace_back("Allow", "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK");
        send_response(c, std::move(resp));
        return;
    }
    if (!app_login(c, "socketley"))
        return;
    std::string bucket, key;
    split_dav(r.key, bucket, key);
    // A file's upload in parts, S3's multipart under the drive's sign-in, so a browser sends a large file's parts
    // side by side: POST ?uploads begins it, PUT ?partNumber&uploadId streams a part, POST ?uploadId completes it
    // and DELETE ?uploadId abandons it, each judged by the policies as the S3 operation it is; GET ?uploadId lists the
    // parts that arrived, so an upload broken off is taken up again where it stopped.
    const bool file = !bucket.empty() && !key.empty() && key.back() != '/';
    if (file && ((r.method == "POST" && (r.has_query("uploads") || r.has_query("uploadId"))) ||
                 ((r.method == "PUT" || r.method == "DELETE" || r.method == "GET") && r.has_query("uploadId"))))
    {
        std::vector<std::pair<std::string, std::string>> mpu;
        for (auto& q : r.query)
            if (q.first == "uploads" || q.first == "uploadId" || q.first == "partNumber" || q.first == "max-parts" ||
                q.first == "part-number-marker")
                mpu.push_back(std::move(q));
        app_forward(c, r.method, std::move(bucket), std::move(key), {}, {}, std::move(mpu));
        return;
    }
    // A folder read with ?list is its listing as the web interface reads it: compact JSON, with an ETag of its own so
    // a look for changes that finds none is a 304 and no body.
    if ((r.method == "GET" || r.method == "HEAD") && !bucket.empty() && r.has_query("list"))
    {
        if (!key.empty() && key.back() != '/')
            key += '/';
        dav_list(c, std::move(bucket), std::move(key));
        return;
    }
    // A folder read with ?zip is one archive of everything under it, or of the names ?n= gives, files or folders.
    if ((r.method == "GET" || r.method == "HEAD") && !bucket.empty() && r.has_query("zip"))
    {
        if (!key.empty() && key.back() != '/')
            key += '/';
        if (!app_allowed(c, "GET", bucket, {}))
        {
            app_reply(c, 403, "Access denied.\n");
            return;
        }
        std::vector<std::string> only;
        for (const auto& [k, v] : r.query)
            if (k == "n" && !v.empty())
                only.push_back(v);
        std::string archive = key.empty() ? bucket : key.substr(0, key.size() - 1);
        archive = archive.substr(archive.rfind('/') + 1);
        zip_start(c, std::move(bucket), std::move(key), std::move(only), std::move(archive), nullptr);
        return;
    }
    // A file read with ?download is saved by a browser, under its own name.
    if (r.method == "GET" && file && r.has_query("download"))
    {
        std::vector<std::pair<std::string, std::string>> q;
        q.emplace_back("response-content-disposition", attachment_of(key));
        app_forward(c, "GET", std::move(bucket), std::move(key), {}, {}, std::move(q));
        return;
    }
    // A file's PUT streams down the S3 path as it arrives; anything else is read whole first, which is nothing for
    // the methods that carry no body.
    if (r.method == "PUT" && file)
    {
        // WebDAV clients count an upload as 201 Created and read an S3 200 as neither that nor 204.
        c->on_answer = [this](const std::shared_ptr<conn>& cc, response& resp)
        {
            if (resp.status == 200)
            {
                resp.status = 201;
                resp.body.clear();
                std::erase_if(resp.headers, [](const auto& h) { return h.first == "Content-Type"; });
            }
            send_response(cc, std::move(resp));
        };
        app_forward(c, "PUT", std::move(bucket), std::move(key));
        return;
    }
    if (r.chunked || (r.has_content_length && r.content_length > app_body_limit))
    {
        r.keep_alive = false;
        app_reply(c, 413, "Request body too large.\n");
        return;
    }
    collect_body(c, app_body_limit);
}

void storage_run::dav_body(const std::shared_ptr<conn>& c)
{
    s3_request& r = c->req;
    std::string bucket, key;
    split_dav(r.key, bucket, key);
    const std::string_view m = r.method;
    const bool folder_path = key.empty() || key.back() == '/';

    if (m == "PROPFIND")
    {
        dav_propfind(c, bucket, key);
        return;
    }
    if (m == "GET" && r.has_query("trash") && !bucket.empty() && folder_path)
    {
        dav_trash(c, std::move(bucket), std::move(key));
        return;
    }
    if (m == "POST" && r.has_query("restore") && !bucket.empty() && !folder_path)
    {
        dav_restore(c, std::move(bucket), std::move(key));
        return;
    }
    // A ZIP posted to with ?unzip is unpacked on the server into a folder beside it named as it is without its
    // extension, numbered when that name is taken.
    if (m == "POST" && r.has_query("unzip") && !bucket.empty() && !folder_path)
    {
        std::string dst = key;
        const size_t slash = dst.rfind('/');
        // A name that is all extension, as ".zip" is, keeps it, or its folder would be the bucket's root.
        if (const size_t dot = dst.rfind('.'); dot != std::string::npos && dot > (slash == std::string::npos ? 0 : slash + 1))
            dst.resize(dot);
        unzip_start(c, std::move(bucket), std::move(key), std::move(dst));
        return;
    }
    if (m == "PROPPATCH")
    {
        // Properties are not kept; each one asked for is answered as set, as clients that stamp times expect.
        std::string x(multistatus_head);
        x += "<D:response><D:href>";
        xml_escape_to(x, dav_href(bucket, key));
        x += "</D:href><D:propstat><D:prop/><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>";
        app_reply(c, 207, std::move(x), "application/xml; charset=utf-8");
        return;
    }
    if (m == "LOCK")
    {
        // Locks are granted and not enforced, which is what the drives of Windows and macOS need to write at all.
        const std::string id = random_hex(16);
        if (id.empty())
        {
            app_reply(c, 503, "No random bytes could be had for a lock token.\n");
            return;
        }
        const std::string token = "opaquelocktoken:" + id;
        std::string x = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:prop xmlns:D=\"DAV:\"><D:lockdiscovery><D:activelock>"
                        "<D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope><D:depth>0</D:depth>"
                        "<D:timeout>Second-3600</D:timeout><D:locktoken><D:href>" + token +
                        "</D:href></D:locktoken></D:activelock></D:lockdiscovery></D:prop>";
        response resp;
        resp.headers.emplace_back("Lock-Token", "<" + token + ">");
        resp.headers.emplace_back("Content-Type", "application/xml; charset=utf-8");
        resp.body = std::move(x);
        send_response(c, std::move(resp));
        return;
    }
    if (m == "UNLOCK")
    {
        app_reply(c, 204);
        return;
    }
    if (m == "MKCOL")
    {
        if (bucket.empty())
        {
            app_reply(c, 403, "The root holds buckets, made by MKCOL /~dav/<bucket>/.\n");
            return;
        }
        if (key.empty())
        {
            // A folder at the root is a bucket.
            c->on_answer = [this](const std::shared_ptr<conn>& cc, response& resp)
            {
                response out;
                out.status = resp.status == 200 ? 201 : resp.status == 409 ? 405 : resp.status;
                send_response(cc, std::move(out));
            };
            app_forward(c, "PUT", std::move(bucket), {});
            return;
        }
        if (!app_allowed(c, "PUT", bucket, key))
        {
            app_reply(c, 403, "Access denied.\n");
            return;
        }
        // A folder is the empty object its name ends in a slash, which S3 browsers show as one too.
        std::string marker = key.back() == '/' ? key : key + "/";
        std::weak_ptr<conn> weak = c;
        list_query q;
        q.prefix   = marker;
        q.max_keys = 1;
        // A folder that exists, by its marker or by anything under it, is 405 and written nothing, as RFC 4918 has
        // it: clients make a file's folder before each upload, and a write each time would queue them on one key.
        m_node.list(bucket, q, [this, weak, bucket, marker](st s, list_page p)
        {
            auto cc = weak.lock();
            if (!cc || cc->dead)
                return;
            if (s == st::ok && (!p.objects.empty() || !p.prefixes.empty()))
            {
                app_reply(cc, 405, "The folder exists.\n");
                return;
            }
            s3_error err;
            object_meta meta;
            meta.content_type = "application/x-directory";
            auto w = put_whole(bucket, marker, std::move(meta), std::string{}, [this, weak](st s2, const put_result*)
            {
                if (auto c2 = weak.lock(); c2 && !c2->dead)
                    app_reply(c2, s2 == st::ok ? 201 : s2 == st::no_such_bucket ? 409 : 507);
            }, err);
            if (!w)
                app_reply(cc, err.status ? err.status : 500, err.message + "\n");
        });
        return;
    }
    if (bucket.empty())
    {
        if (m == "GET" || m == "HEAD")
        {
            dav_collection(c, bucket, key);
            return;
        }
        app_reply(c, 405, "The root is read only.\n");
        return;
    }

    // A path without a trailing slash may be a file or a folder, which only a look tells apart.
    auto proceed = [this](const std::shared_ptr<conn>& cc, std::string b, std::string k, bool folder)
    {
        const std::string_view method = cc->req.method;
        if (folder)
        {
            if (method == "GET" || method == "HEAD")
                dav_collection(cc, b, k);
            else if (method == "DELETE" || method == "COPY" || method == "MOVE")
            {
                std::string dst_b, dst_k;
                if (method != "DELETE")
                {
                    std::string_view dest = cc->req.header("destination");
                    if (const size_t at = dest.find("/~dav/"); at != std::string_view::npos)
                        dest = dest.substr(at + 6);
                    else
                        dest = {};
                    std::string decoded;
                    if (dest.empty() || !percent_decode(dest, decoded, false))
                    {
                        app_reply(cc, 400, "A Destination under /~dav/ is needed.\n");
                        return;
                    }
                    split_dav(decoded, dst_b, dst_k);
                    if (dst_b.empty())
                    {
                        app_reply(cc, 403, "A folder is copied into a bucket.\n");
                        return;
                    }
                    if (!dst_k.empty() && dst_k.back() != '/')
                        dst_k += '/';
                }
                std::string prefix = k.empty() || k.back() == '/' ? k : k + "/";
                // Onto itself every copy lands on its own source and the move then removes it; into itself the copies
                // land where the listing is still walking (RFC 4918 9.8.5, 9.9.4).
                if (method != "DELETE" && dst_b == b &&
                    (dst_k.starts_with(prefix) || (!dst_k.empty() && prefix.starts_with(dst_k))))
                {
                    app_reply(cc, 403, "A folder is not copied or moved onto itself or into itself.\n");
                    return;
                }
                if (prefix.empty() && method == "DELETE")
                {
                    if (cc->req.has_query("contents"))
                    {
                        dav_purge(cc, std::move(b));
                        return;
                    }
                    // A bucket removed through its folder is removed only empty, as DeleteBucket is.
                    cc->on_answer = [this](const std::shared_ptr<conn>& c2, response& resp)
                    {
                        response out;
                        out.status = resp.status;
                        // Said in words, since the S3 body is XML a file manager would show as it is.
                        if (resp.status == 409)
                            out.body = "The library still holds files; delete it with its contents.\n";
                        send_response(c2, std::move(out));
                    };
                    app_forward(cc, "DELETE", std::move(b), {});
                    return;
                }
                if (method == "DELETE")
                {
                    dav_tree(cc, std::move(b), std::move(prefix), {}, {}, false);
                    return;
                }
                const bool copy = method == "COPY";
                std::weak_ptr<conn> weak = cc;
                dav_unless_taken(cc, dst_b, dst_k, true, [this, weak, b, prefix, dst_b, dst_k, copy]()
                {
                    if (auto c2 = weak.lock(); c2 && !c2->dead)
                        dav_tree(c2, b, prefix, dst_b, dst_k, copy);
                });
            }
            else
                app_reply(cc, 405, "Not a method of a folder.\n");
            return;
        }
        if (method == "GET" || method == "HEAD")
        {
            app_forward(cc, method == "GET" ? "GET" : "HEAD", std::move(b), std::move(k));
            return;
        }
        if (method == "DELETE")
        {
            app_forward(cc, "DELETE", std::move(b), std::move(k));
            return;
        }
        if (method == "COPY" || method == "MOVE")
        {
            std::string_view dest = cc->req.header("destination");
            const size_t at = dest.find("/~dav/");
            std::string decoded, dst_b, dst_k;
            if (at == std::string_view::npos || !percent_decode(dest.substr(at + 6), decoded, false))
            {
                app_reply(cc, 400, "A Destination under /~dav/ is needed.\n");
                return;
            }
            split_dav(decoded, dst_b, dst_k);
            if (dst_b.empty() || dst_k.empty() || dst_k.back() == '/')
            {
                app_reply(cc, 409, "A file's Destination is a file.\n");
                return;
            }
            if (dst_b == b && dst_k == k)
            {
                app_reply(cc, 403, "A file is not copied or moved onto itself.\n");
                return;
            }
            const bool move = method == "MOVE";
            if (move && !app_allowed(cc, "DELETE", b, k))
            {
                app_reply(cc, 403, "Access denied.\n");
                return;
            }
            std::string source = "/";
            url_encode_to(source, b, true);
            source += '/';
            url_encode_to(source, k, true);
            std::weak_ptr<conn> wc = cc;
            dav_unless_taken(cc, dst_b, dst_k, false, [this, wc, move, b, k, dst_b, dst_k, source]() mutable
            {
                auto fc = wc.lock();
                if (!fc || fc->dead)
                    return;
                // A move is the copy and then the source's removal, answered once both are done.
                fc->on_answer = [this, move, b, k](const std::shared_ptr<conn>& c2, response& resp)
                {
                    if (resp.status != 200)
                    {
                        send_response(c2, std::move(resp));
                        return;
                    }
                    if (!move)
                    {
                        response out;
                        out.status = 201;
                        send_response(c2, std::move(out));
                        return;
                    }
                    std::weak_ptr<conn> weak = c2;
                    m_store.remove_version(b, k, {}, [this, weak, b, k](remove_result rr)
                    {
                        if (rr.status == st::ok && rr.existed)
                            notify_delete(b, k);
                        if (auto c3 = weak.lock(); c3 && !c3->dead)
                        {
                            response out;
                            out.status = rr.status == st::ok ? 201 : 500;
                            send_response(c3, std::move(out));
                        }
                    });
                };
                app_forward(fc, "PUT", std::move(dst_b), std::move(dst_k), "x-amz-copy-source", std::move(source));
            });
            return;
        }
        app_reply(cc, 405, "Not a method of a file.\n");
    };
    if (folder_path)
    {
        proceed(c, std::move(bucket), std::move(key), true);
        return;
    }
    std::weak_ptr<conn> weak = c;
    m_store.stat_object(bucket, key, [this, weak, bucket, key, proceed](st s, const object_meta&)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (s == st::ok)
        {
            proceed(cc, bucket, key, false);
            return;
        }
        // No file of the name: a folder of it, when anything is under it.
        list_query q;
        q.prefix   = key + "/";
        q.max_keys = 1;
        m_node.list(bucket, q, [this, weak, bucket, key, proceed](st s2, list_page p)
        {
            auto c2 = weak.lock();
            if (!c2 || c2->dead)
                return;
            if (s2 != st::ok || (p.objects.empty() && p.prefixes.empty()))
            {
                app_reply(c2, 404, "Not found.\n");
                return;
            }
            proceed(c2, bucket, key, true);
        });
    });
}

void storage_run::dav_list(const std::shared_ptr<conn>& c, std::string bucket, std::string prefix)
{
    if (!m_store.has_bucket(bucket))
    {
        app_reply(c, 404, "No such bucket.\n");
        return;
    }
    if (!app_allowed(c, "GET", bucket, {}))
    {
        app_reply(c, 403, "Access denied.\n");
        return;
    }
    list_query q;
    q.prefix    = prefix;
    q.delimiter = "/";
    q.max_keys  = 1000;
    std::weak_ptr<conn> weak = c;
    app_list(bucket, std::move(q), [this, weak, prefix](st s, list_page p)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (s != st::ok || (!prefix.empty() && p.objects.empty() && p.prefixes.empty()))
        {
            app_reply(cc, 404, "Not found.\n");
            return;
        }
        // {"d":[name,...],"f":[[name,size,mtime_ms,type],...]}: a quarter of a PROPFIND's bytes for each entry.
        std::string x;
        x.reserve(64 + p.prefixes.size() * 24 + p.objects.size() * 72);
        x += "{\"d\":[";
        bool first = true;
        for (const std::string& sub : p.prefixes)
        {
            x += first ? "\"" : ",\"";
            x += socketley::json::escape(last_name(sub));
            x += '"';
            first = false;
        }
        x += "],\"f\":[";
        first = true;
        for (const list_entry& e : p.objects)
        {
            if (e.key == prefix)
                continue;
            x += first ? "[\"" : ",[\"";
            x += socketley::json::escape(last_name(e.key));
            x += "\",";
            x += std::to_string(e.meta.size);
            x += ',';
            x += std::to_string(e.meta.mtime_ms);
            x += ",\"";
            x += socketley::json::escape(e.meta.content_type.empty() ? std::string_view("application/octet-stream")
                                                         : std::string_view(e.meta.content_type.str()));
            x += "\"]";
            first = false;
        }
        x += "]}";
        // FNV-1a over the listing: the same names, sizes, times and types are the same tag.
        uint64_t h = 1469598103934665603ull;
        for (const unsigned char ch : x)
            h = (h ^ ch) * 1099511628211ull;
        static constexpr char hexd[] = "0123456789abcdef";
        std::string tag = "\"l";
        for (int i = 60; i >= 0; i -= 4)
            tag += hexd[(h >> i) & 15];
        tag += '"';
        response resp;
        resp.headers.emplace_back("ETag", tag);
        resp.headers.emplace_back("Cache-Control", "no-cache");
        if (etag_list_matches(cc->req.header("if-none-match"), tag.substr(1, tag.size() - 2)))
            resp.status = 304;
        else
        {
            resp.status = 200;
            resp.headers.emplace_back("Content-Type", "application/json");
            resp.body = std::move(x);
        }
        send_response(cc, std::move(resp));
    });
}

void storage_run::dav_propfind(const std::shared_ptr<conn>& c, const std::string& bucket, const std::string& key)
{
    const std::string_view depth = c->req.header("depth");
    const bool children = depth != "0";
    // The root: every bucket its user owns, every bucket a policy lets the user list, or every bucket for an admin.
    if (bucket.empty())
    {
        std::string x(multistatus_head);
        dir_response(x, "/~dav/", "", 0);
        if (children)
        {
            for (const bucket_info& b : m_store.buckets())
                if (lists_bucket(c, b))
                    dir_response(x, dav_href(b.name, {}), b.name, b.created_ms,
                                 b.owner.empty() ? default_owner : std::string_view(b.owner));
        }
        x += "</D:multistatus>";
        app_reply(c, 207, std::move(x), "application/xml; charset=utf-8");
        return;
    }
    if (!m_store.has_bucket(bucket))
    {
        app_reply(c, 404, "No such bucket.\n");
        return;
    }
    if (!app_allowed(c, "GET", bucket, {}))
    {
        app_reply(c, 403, "Access denied.\n");
        return;
    }
    std::weak_ptr<conn> weak = c;
    // The listing under the path as a folder, and the file of its name when it has no slash.
    auto list_folder = [this, weak, bucket, children](std::string prefix, bool must_exist)
    {
        list_query q;
        q.prefix    = prefix;
        q.delimiter = "/";
        q.max_keys  = children ? 1000 : 1;
        auto answer = [this, weak, bucket, prefix, children, must_exist](st s, list_page p)
        {
            auto cc = weak.lock();
            if (!cc || cc->dead)
                return;
            if (s != st::ok || (must_exist && p.objects.empty() && p.prefixes.empty()))
            {
                app_reply(cc, 404, "Not found.\n");
                return;
            }
            std::string x(multistatus_head);
            dir_response(x, dav_href(bucket, prefix), prefix.empty() ? std::string_view(bucket) : last_name(prefix), 0);
            if (children)
            {
                for (const std::string& sub : p.prefixes)
                    dir_response(x, dav_href(bucket, sub), last_name(sub), 0);
                for (const list_entry& e : p.objects)
                    if (e.key != prefix)
                        file_response(x, dav_href(bucket, e.key), last_name(e.key), e.meta);
            }
            x += "</D:multistatus>";
            app_reply(cc, 207, std::move(x), "application/xml; charset=utf-8");
        };
        // Its children are every page of the folder; the folder alone is whether it has one entry.
        if (children)
            app_list(bucket, std::move(q), std::move(answer));
        else
            m_node.list(bucket, q, std::move(answer));
    };
    if (key.empty() || key.back() == '/')
    {
        list_folder(key, !key.empty());
        return;
    }
    m_store.stat_object(bucket, key, [this, weak, bucket, key, list_folder](st s, const object_meta& m)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (s != st::ok)
        {
            list_folder(key + "/", true);
            return;
        }
        std::string x(multistatus_head);
        file_response(x, dav_href(bucket, key), last_name(key), m);
        x += "</D:multistatus>";
        app_reply(cc, 207, std::move(x), "application/xml; charset=utf-8");
    });
}

void storage_run::dav_collection(const std::shared_ptr<conn>& c, const std::string& bucket, const std::string& key)
{
    // A folder opened in a browser is a page of links to what is in it.
    std::weak_ptr<conn> weak = c;
    auto page = [](std::string_view title, const std::vector<std::pair<std::string, std::string>>& links)
    {
        std::string h = "<!doctype html><meta charset=\"utf-8\"><title>";
        xml_escape_to(h, title);
        h += "</title><h1>";
        xml_escape_to(h, title);
        h += "</h1><ul>";
        for (const auto& [href, name] : links)
        {
            h += "<li><a href=\"";
            xml_escape_to(h, href);
            h += "\">";
            xml_escape_to(h, name);
            h += "</a></li>";
        }
        h += "</ul>";
        return h;
    };
    if (bucket.empty())
    {
        std::vector<std::pair<std::string, std::string>> links;
        for (const bucket_info& b : m_store.buckets())
            if (lists_bucket(c, b))
                links.emplace_back(dav_href(b.name, {}), b.name + "/");
        app_reply(c, 200, page("/", links), "text/html; charset=utf-8");
        return;
    }
    if (!app_allowed(c, "GET", bucket, {}))
    {
        app_reply(c, 403, "Access denied.\n");
        return;
    }
    list_query q;
    q.prefix    = key.empty() || key.back() == '/' ? key : key + "/";
    q.delimiter = "/";
    const std::string prefix = q.prefix;
    app_list(bucket, std::move(q), [this, weak, bucket, prefix, page](st s, list_page p)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (s != st::ok)
        {
            app_reply(cc, 404, "Not found.\n");
            return;
        }
        std::vector<std::pair<std::string, std::string>> links;
        for (const std::string& sub : p.prefixes)
            links.emplace_back(dav_href(bucket, sub), std::string(last_name(sub)) + "/");
        for (const list_entry& e : p.objects)
            if (e.key != prefix)
                links.emplace_back(dav_href(bucket, e.key), std::string(last_name(e.key)));
        app_reply(cc, 200, page(bucket + "/" + prefix, links), "text/html; charset=utf-8");
    });
}

void storage_run::dav_tree(const std::shared_ptr<conn>& c, std::string bucket, std::string prefix,
                           std::string dst_bucket, std::string dst_prefix, bool keep_source)
{
    const bool removing = dst_bucket.empty();
    if (!app_allowed(c, "GET", bucket, {}) || (!keep_source && !app_allowed(c, "DELETE", bucket, prefix)) ||
        (!removing && !app_allowed(c, "PUT", dst_bucket, dst_prefix)))
    {
        app_reply(c, 403, "Access denied.\n");
        return;
    }
    // Every key under the folder, then each one copied and or removed in turn; each outstanding step's answer holds
    // the walk, which goes with the last one.
    struct walk
    {
        std::weak_ptr<conn> who;
        std::string bucket, prefix, dst_bucket, dst_prefix;
        bool keep_source{false}, removing{false};
        // One page of the folder at a time, the next asked for once this one is handed out.
        std::vector<list_entry> keys;
        size_t at{0}, failed{0}, inflight{0};
        bool more{false}, listing{false};
        // A completion that comes back inside the loop that started it asks for one more turn instead of recursing.
        bool pumping{false}, again{false}, answered{false};
        list_query q;
        std::weak_ptr<walk> self;
        std::function<void()> next, page;
        std::function<void(const list_entry&)> one;
    };
    auto w = std::make_shared<walk>();
    w->self = w;
    w->who = c;
    w->bucket = std::move(bucket);
    w->prefix = std::move(prefix);
    w->dst_bucket = std::move(dst_bucket);
    w->dst_prefix = std::move(dst_prefix);
    w->keep_source = keep_source;
    w->removing = removing;
    w->q.prefix = w->prefix;
    w->q.max_keys = 1000;
    walk* raw = w.get();

    // An object done, well or not, makes room for the next.
    auto done = [raw]()
    {
        --raw->inflight;
        raw->next();
    };
    auto remove_then_done = [this, raw, done](const std::string& key)
    {
        m_store.remove_version(raw->bucket, key, {}, [this, raw, key, done, hold = raw->self.lock()](remove_result rr)
        {
            if (rr.status != st::ok)
                ++raw->failed;
            else if (rr.existed)
                notify_delete(raw->bucket, key);
            done();
        });
    };
    w->one = [this, raw, done, remove_then_done](const list_entry& e)
    {
        // Each key is judged as the single file's operation is, since a policy may deny on a key under the folder.
        const auto allowed = [this, raw](std::string_view method, const std::string& bucket, const std::string& key)
        {
            const auto cc = raw->who.lock();
            return cc && !cc->dead && app_allowed(cc, method, bucket, key);
        };
        const std::string dst_key = raw->removing ? std::string{} : raw->dst_prefix + e.key.substr(raw->prefix.size());
        if ((!raw->keep_source && !allowed("DELETE", raw->bucket, e.key)) ||
            (!raw->removing && (!allowed("GET", raw->bucket, e.key) || !allowed("PUT", raw->dst_bucket, dst_key))))
        {
            ++raw->failed;
            done();
            return;
        }
        if (raw->removing)
        {
            remove_then_done(e.key);
            return;
        }
        // A copy reads the object whole, so one past the bound, or one only its client's key opens, is not copied.
        if (e.meta.size > tree_object_max || sse_mode_of(e.meta) == sse_mode::c)
        {
            ++raw->failed;
            done();
            return;
        }
        const std::string src_key = e.key;
        m_store.open_object(raw->bucket, e.key, static_cast<size_t>(stored_size(e.meta)),
                            [this, raw, done, remove_then_done, dst_key, src_key, hold = raw->self.lock()](open_result o)
        {
            if (o.fd >= 0)
                m_loop.close_fd(o.fd);
            std::string body;
            bool ok = o.status == st::ok;
            if (ok && is_encrypted(o.meta))
            {
                sse_key key{};
                s3_error err;
                ok = sse_data_key(o.meta, std::nullopt, key, err) && sse_open_body(o.meta, key, o.prefetch, body);
            }
            else if (ok && is_tiered(o.meta))
                ok = false;
            else if (ok && is_compressed(o.meta))
                ok = lz4_open_body(o.meta, o.prefetch, body);
            else if (ok)
                body = o.prefetch.substr(0, static_cast<size_t>(std::min<uint64_t>(o.meta.size, o.prefetch.size())));
            if (!ok || body.size() != o.meta.size)
            {
                ++raw->failed;
                done();
                return;
            }
            // What a file's COPY keeps, its headers, user metadata and tags; nothing of how the source was stored.
            object_meta meta;
            meta.content_type = o.meta.content_type;
            for (const auto& [k, v] : o.meta.extra)
                if (k.starts_with("x-amz-meta-") || k == "cache-control" || k == "content-disposition" ||
                    k == "content-encoding" || k == "content-language" || k == "expires")
                    meta.extra.push_back({k, v});
            set_tags_extra(meta, tags_of(o.meta));
            s3_error err;
            auto put = put_whole(raw->dst_bucket, dst_key, std::move(meta), std::move(body),
                                 [raw, done, remove_then_done, src_key, hold](st s, const put_result*)
            {
                if (s != st::ok)
                    ++raw->failed;
                if (s == st::ok && !raw->keep_source)
                    remove_then_done(src_key);
                else
                    done();
            }, err);
            if (!put)
            {
                ++raw->failed;
                done();
            }
        });
    };
    // Removals go 32 at a time, which their syncs share; copies 4, as each holds an object in memory.
    w->next = [this, raw]()
    {
        if (raw->pumping)
        {
            raw->again = true;
            return;
        }
        raw->pumping = true;
        const size_t window = raw->removing ? 32 : 4;
        do
        {
            raw->again = false;
            while (raw->inflight < window && raw->at < raw->keys.size())
            {
                ++raw->inflight;
                const list_entry e = raw->keys[raw->at++];
                raw->one(e);
            }
        } while (raw->again);
        raw->pumping = false;
        if (raw->at == raw->keys.size() && raw->more && !raw->listing)
        {
            raw->keys.clear();
            raw->at = 0;
            raw->listing = true;
            raw->page();
            return;
        }
        if (raw->at == raw->keys.size() && raw->inflight == 0 && !raw->listing && !raw->answered)
        {
            raw->answered = true;
            if (auto cc = raw->who.lock(); cc && !cc->dead)
                app_reply(cc, raw->failed ? 500 : raw->removing ? 204 : 201,
                          raw->failed ? std::to_string(raw->failed) + " of the folder's objects failed.\n" : std::string{});
            // The walk's functions hold nothing of it, so it goes with the last answer that held it.
            raw->one = nullptr;
        }
    };
    w->page = [this, raw]()
    {
        m_node.list(raw->bucket, raw->q, [raw, hold = raw->self.lock()](st s, list_page p)
        {
            raw->listing = false;
            if (s != st::ok)
                ++raw->failed;
            for (list_entry& e : p.objects)
                raw->keys.push_back(std::move(e));
            raw->more = s == st::ok && p.truncated;
            if (raw->more)
            {
                raw->q.resume_at  = p.resume_at;
                raw->q.has_resume = true;
            }
            raw->next();
        });
    };
    raw->listing = true;
    raw->page();
}

void storage_run::dav_unless_taken(const std::shared_ptr<conn>& c, const std::string& bucket, const std::string& key,
                                   bool folder, std::function<void()> then)
{
    const std::string_view o = c->req.header("overwrite");
    if (o != "F" && o != "f")
    {
        then();
        return;
    }
    std::weak_ptr<conn> weak = c;
    auto answer = [this, weak, then = std::move(then)](bool taken)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (taken)
            app_reply(cc, 412, "The Destination exists, and Overwrite is F.\n");
        else
            then();
    };
    if (!folder)
    {
        m_store.stat_object(bucket, key, [answer](st s, const object_meta&) { answer(s == st::ok); });
        return;
    }
    list_query q;
    q.prefix   = key;
    q.max_keys = 1;
    m_node.list(bucket, q, [answer](st s, list_page p) { answer(s == st::ok && !p.objects.empty()); });
}

void storage_run::dav_purge(const std::shared_ptr<conn>& c, std::string bucket)
{
    // Asked as the operations it stands for: removing the bucket, and every version in it.
    if (!app_allowed(c, "DELETE", bucket, {}) || !app_allowed(c, "DELETE", bucket, "x", "versionId"))
    {
        app_reply(c, 403, "Access denied.\n");
        return;
    }
    struct walk
    {
        std::weak_ptr<conn> who;
        std::string bucket;
        version_query q;
        std::vector<std::pair<std::string, std::string>> items;
        size_t at{0}, failed{0}, inflight{0};
        bool more{false}, listing{false}, pumping{false}, again{false}, answered{false};
        std::weak_ptr<walk> self;
        std::function<void()> next, page;
    };
    auto w = std::make_shared<walk>();
    w->who = c;
    w->bucket = std::move(bucket);
    w->q.max_keys = 1000;
    w->self = w;
    walk* raw = w.get();
    // Every version and marker, 32 removals at a time, the next page asked for once this one is handed out.
    w->next = [this, raw]()
    {
        if (raw->pumping)
        {
            raw->again = true;
            return;
        }
        raw->pumping = true;
        do
        {
            raw->again = false;
            while (raw->inflight < 32 && raw->at < raw->items.size())
            {
                const auto& [key, version] = raw->items[raw->at++];
                // Each version is judged as its own DeleteObjectVersion is, since a policy may deny on a key in it.
                if (const auto cc = raw->who.lock();
                    !cc || cc->dead || !app_allowed(cc, "DELETE", raw->bucket, key, "versionId"))
                {
                    ++raw->failed;
                    continue;
                }
                ++raw->inflight;
                m_store.remove_version(raw->bucket, key, version,
                                       [this, raw, key = key, hold = raw->self.lock()](remove_result rr)
                {
                    if (rr.status != st::ok)
                        ++raw->failed;
                    else if (rr.existed)
                        notify_delete(raw->bucket, key);
                    --raw->inflight;
                    raw->next();
                });
            }
        } while (raw->again);
        raw->pumping = false;
        if (raw->at < raw->items.size() || raw->inflight > 0 || raw->listing || raw->answered)
            return;
        if (raw->more && !raw->failed)
        {
            raw->items.clear();
            raw->at = 0;
            raw->listing = true;
            raw->page();
            return;
        }
        raw->answered = true;
        auto cc = raw->who.lock();
        if (!cc || cc->dead)
            return;
        if (raw->failed)
        {
            app_reply(cc, 409, std::to_string(raw->failed) + " of the library's files could not be removed; a file " +
                                   "under retention or legal hold stays until it is released, and one a policy keeps stays.\n");
            return;
        }
        cc->on_answer = [this](const std::shared_ptr<conn>& c2, response& resp)
        {
            response out;
            out.status = resp.status;
            if (resp.status == 409)
                out.body = "The library is emptied, and something still holds it: an upload in progress, or a file "
                           "written meanwhile.\n";
            send_response(c2, std::move(out));
        };
        app_forward(cc, "DELETE", raw->bucket, {});
    };
    w->page = [this, raw]()
    {
        m_node.list_versions(raw->bucket, raw->q, [this, raw, hold = raw->self.lock()](st s, version_page p)
        {
            raw->listing = false;
            if (s != st::ok)
            {
                if (auto cc = raw->who.lock(); cc && !cc->dead && !raw->answered)
                {
                    raw->answered = true;
                    app_reply(cc, s == st::no_such_bucket ? 404 : 500, "The library's files could not be listed.\n");
                }
                return;
            }
            for (const version_item& it : p.items)
                if (!it.prefix)
                    raw->items.emplace_back(it.key, std::string(version_id_of(it.meta)));
            raw->more = p.truncated && !p.items.empty();
            if (raw->more)
            {
                raw->q.key_marker = p.items.back().key;
                raw->q.version_marker = std::string(version_id_of(p.items.back().meta));
            }
            raw->next();
        });
    };
    raw->listing = true;
    raw->page();
}

void storage_run::dav_trash(const std::shared_ptr<conn>& c, std::string bucket, std::string prefix)
{
    if (!app_allowed(c, "GET", bucket, {}, "versions"))
    {
        app_reply(c, 403, "Access denied.\n");
        return;
    }
    // A key whose newest version is a delete marker is in the trash, with the version behind the marker to restore.
    struct walk
    {
        std::weak_ptr<conn> who;
        std::string bucket, out, key;
        version_query q;
        size_t found{0};
        bool deleted{false}, first{true};
        // Each page's answer holds the walk, so it lives exactly as long as a page is outstanding.
        std::weak_ptr<walk> self;
        std::function<void()> page;
    };
    auto w = std::make_shared<walk>();
    w->who = c;
    w->bucket = std::move(bucket);
    w->q.prefix = std::move(prefix);
    w->out = "[";
    w->self = w;
    walk* raw = w.get();
    w->page = [this, raw]()
    {
        m_node.list_versions(raw->bucket, raw->q, [this, raw, hold = raw->self.lock()](st s, version_page p)
        {
            for (const version_item& it : p.items)
            {
                if (it.prefix)
                    continue;
                if (it.latest)
                {
                    // A marker with nothing behind it still closes its entry before the next key.
                    if (raw->deleted)
                        raw->out += ",\"size\":0}";
                    raw->key = it.key;
                    raw->deleted = is_delete_marker(it.meta);
                    if (raw->deleted)
                    {
                        raw->out += raw->first ? "{" : ",{";
                        raw->first = false;
                        raw->out += "\"key\":\"" + socketley::json::escape(it.key) + "\",\"deleted\":\"" +
                                    iso8601(it.meta.mtime_ms) + "\"";
                    }
                    continue;
                }
                // The first version behind a marker is what a restore brings back.
                if (raw->deleted && it.key == raw->key && !is_delete_marker(it.meta))
                {
                    raw->out += ",\"size\":" + std::to_string(it.meta.size) + "}";
                    raw->deleted = false;
                    ++raw->found;
                }
            }
            if (s == st::ok && p.truncated && !p.items.empty() && raw->found < listing_max)
            {
                raw->q.key_marker = p.items.back().key;
                raw->q.version_marker = std::string(version_id_of(p.items.back().meta));
                raw->page();
                return;
            }
            // A marker with nothing behind it on the last page still closes its entry.
            if (raw->deleted)
                raw->out += ",\"size\":0}";
            raw->out += "]";
            if (auto cc = raw->who.lock(); cc && !cc->dead)
            {
                if (s == st::ok)
                    app_reply(cc, 200, std::move(raw->out), "application/json");
                else
                    app_reply(cc, s == st::no_such_bucket ? 404 : 500, "The versions could not be listed.\n");
            }
        });
    };
    raw->page();
}

void storage_run::dav_restore(const std::shared_ptr<conn>& c, std::string bucket, std::string key)
{
    if (!app_allowed(c, "DELETE", bucket, key, "versionId"))
    {
        app_reply(c, 403, "Access denied.\n");
        return;
    }
    // The key sorts first among those it is a prefix of, so its newest version leads the page.
    version_query q;
    q.prefix = key;
    q.max_keys = 1;
    std::weak_ptr<conn> weak = c;
    m_node.list_versions(bucket, q, [this, weak, bucket, key](st s, version_page p)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (s != st::ok || p.items.empty() || p.items.front().key != key || !p.items.front().latest ||
            !is_delete_marker(p.items.front().meta))
        {
            app_reply(cc, 409, "The file is not in the trash.\n");
            return;
        }
        m_store.remove_version(bucket, key, std::string(version_id_of(p.items.front().meta)), [this, weak](remove_result rr)
        {
            if (auto c2 = weak.lock(); c2 && !c2->dead)
                app_reply(c2, rr.status == st::ok ? 204 : 500);
        });
    });
}

}   // namespace socketley::storage
