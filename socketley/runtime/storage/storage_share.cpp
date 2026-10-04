// Share links: a user makes a link to an object or a folder, which anyone holding it reads, or uploads into,
// without credentials — for as long, as often and with the password its maker chose. Each link is a small JSON
// file under <dir>/.shares/, which every shard reads, and whose download count is kept under the file's lock.
#include "storage_run.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <chrono>
#include <charconv>

#include "digest.h"
#include "json_doc.h"
#include "s3_names.h"
#include "s3_xml.h"
#include "../../shared/logging.h"
#include "../../shared/state_persistence.h"

namespace socketley::storage
{

struct share_link
{
    std::string id;
    std::string bucket;
    // An object's key, or for a folder its prefix ending in a slash (empty for the whole bucket).
    std::string key;
    bool        folder{false};
    std::string owner;
    int64_t     created_ms{0};
    int64_t     expires_ms{0};
    std::string pw_salt;
    std::string pw_hash;
    uint64_t    max_downloads{0};
    uint64_t    downloads{0};
    bool        upload{false};
    // The maker's label for the link.
    std::string note;
};

namespace
{

void jstr(std::string& out, std::string_view v)
{
    out += '"';
    out += sp_detail::json_escape(v);
    out += '"';
}

std::string share_json(const share_link& s)
{
    std::string o = "{\"id\":";
    jstr(o, s.id);
    o += ",\"bucket\":";
    jstr(o, s.bucket);
    o += ",\"key\":";
    jstr(o, s.key);
    o += s.folder ? ",\"folder\":true" : ",\"folder\":false";
    o += ",\"owner\":";
    jstr(o, s.owner);
    o += ",\"created\":" + std::to_string(s.created_ms) + ",\"expires\":" + std::to_string(s.expires_ms);
    o += ",\"salt\":";
    jstr(o, s.pw_salt);
    o += ",\"hash\":";
    jstr(o, s.pw_hash);
    o += ",\"max_downloads\":" + std::to_string(s.max_downloads) + ",\"downloads\":" + std::to_string(s.downloads);
    o += s.upload ? ",\"upload\":true" : ",\"upload\":false";
    o += ",\"note\":";
    jstr(o, s.note);
    o += "}";
    return o;
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

uint64_t num_of(const jvalue& o, std::string_view n)
{
    const jvalue* v = member(o, n);
    uint64_t x = 0;
    if (v && v->k == jvalue::kind::number)
        std::from_chars(v->s.data(), v->s.data() + v->s.size(), x);
    return x;
}

bool flag_of(const jvalue& o, std::string_view n)
{
    const jvalue* v = member(o, n);
    return v && v->k == jvalue::kind::boolean && v->b;
}

bool parse_share(std::string_view text, share_link& s)
{
    jvalue root;
    if (!json_reader(text).document(root))
        return false;
    s.id = str_of(root, "id");
    s.bucket = str_of(root, "bucket");
    s.key = str_of(root, "key");
    s.folder = flag_of(root, "folder");
    s.owner = str_of(root, "owner");
    s.created_ms = static_cast<int64_t>(num_of(root, "created"));
    s.expires_ms = static_cast<int64_t>(num_of(root, "expires"));
    s.pw_salt = str_of(root, "salt");
    s.pw_hash = str_of(root, "hash");
    s.max_downloads = num_of(root, "max_downloads");
    s.downloads = num_of(root, "downloads");
    s.upload = flag_of(root, "upload");
    s.note = str_of(root, "note");
    return !s.id.empty() && !s.bucket.empty();
}

bool valid_id(std::string_view id)
{
    if (id.size() != 22)
        return false;
    for (char ch : id)
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_'))
            return false;
    return true;
}

bool read_text(const std::string& path, std::string& out)
{
    out.clear();
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    char buf[8192];
    for (;;)
    {
        const ssize_t n = ::read(fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
        {
            ::close(fd);
            return n == 0;
        }
        out.append(buf, static_cast<size_t>(n));
    }
}

bool write_text(const std::string& path, const std::string& text)
{
    const std::string tmp = path + ".tmp." + std::to_string(::getpid());
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    bool ok = ::write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size());
    ok = ::fsync(fd) == 0 && ok;
    ok = ::close(fd) == 0 && ok;
    if (!ok || ::rename(tmp.c_str(), path.c_str()) < 0)
    {
        ::unlink(tmp.c_str());
        return false;
    }
    return true;
}

std::string pw_hash(std::string_view salt, std::string_view password)
{
    return sha256_hex(std::string(salt) + std::string(password));
}

std::string random_hex(size_t n)
{
    unsigned char raw[32];
    if (n > sizeof raw || RAND_bytes(raw, static_cast<int>(n)) != 1)
        return {};
    return hex(raw, n);
}

std::string_view last_name_of(std::string_view key)
{
    const size_t slash = key.rfind('/');
    return slash == std::string_view::npos ? key : key.substr(slash + 1);
}

int64_t now_ms()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string share_view_json(const share_link& s)
{
    std::string o = "{\"id\":";
    jstr(o, s.id);
    o += ",\"url\":";
    jstr(o, "/~share/" + s.id + (s.folder ? "/" : ""));
    o += ",\"bucket\":";
    jstr(o, s.bucket);
    o += ",\"key\":";
    jstr(o, s.key);
    o += s.folder ? ",\"folder\":true" : ",\"folder\":false";
    o += ",\"expires\":";
    jstr(o, s.expires_ms ? iso8601(s.expires_ms) : std::string{});
    o += s.pw_hash.empty() ? ",\"password\":false" : ",\"password\":true";
    o += ",\"max_downloads\":" + std::to_string(s.max_downloads) + ",\"downloads\":" + std::to_string(s.downloads);
    o += s.upload ? ",\"upload\":true" : ",\"upload\":false";
    o += ",\"note\":";
    jstr(o, s.note);
    o += ",\"owner\":";
    jstr(o, s.owner);
    o += "}";
    return o;
}

}   // namespace

bool storage_run::share_open(const std::shared_ptr<conn>& c, std::string_view id, share_link& s)
{
    std::string text;
    if (!valid_id(id) || !read_text(m_store.options().dir + "/.shares/" + std::string(id) + ".json", text) ||
        !parse_share(text, s))
    {
        app_reply(c, 404, "No such link.\n");
        return false;
    }
    if (s.expires_ms && now_ms() > s.expires_ms)
    {
        app_reply(c, 410, "This link has expired.\n");
        return false;
    }
    if (s.pw_hash.empty())
        return true;
    // Any user name, and the link's password, as a browser asks for them.
    const std::string_view h = c->req.header("authorization");
    std::string pair;
    if ((h.starts_with("Basic ") || h.starts_with("basic ")) && base64_decode(http_trim_ows(h.substr(6)), pair))
    {
        const size_t colon = pair.find(':');
        const std::string got = pw_hash(s.pw_salt, colon == std::string::npos ? std::string_view{} :
                                                                               std::string_view(pair).substr(colon + 1));
        if (got.size() == s.pw_hash.size() && CRYPTO_memcmp(got.data(), s.pw_hash.data(), got.size()) == 0)
            return true;
    }
    response resp;
    resp.status = 401;
    resp.headers.emplace_back("WWW-Authenticate", "Basic realm=\"shared link\", charset=\"UTF-8\"");
    resp.headers.emplace_back("Content-Type", "text/plain; charset=utf-8");
    resp.body = "This link has a password.\n";
    send_response(c, std::move(resp));
    return false;
}

bool storage_run::share_target(const std::shared_ptr<conn>& c, std::string_view id, std::string_view rel,
                               std::string& bucket, std::string& key)
{
    share_link s;
    if (!share_open(c, id, s))
        return false;
    if (!s.folder && !rel.empty())
    {
        app_reply(c, 404, "No such file in this link.\n");
        return false;
    }
    bucket = s.bucket;
    key    = s.folder ? s.key + std::string(rel) : s.key;
    return true;
}

void storage_run::op_share(const std::shared_ptr<conn>& c)
{
    s3_request& r = c->req;
    // POST /~share makes a link and its body says to what; anything else names one by its id.
    if (r.method == "POST" || ((r.method == "GET" || r.method == "DELETE") && r.key.empty()))
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
    const std::string_view rest = r.key;
    const size_t slash = rest.find('/');
    const std::string id(rest.substr(0, slash));
    const std::string rel(slash == std::string_view::npos ? std::string_view{} : rest.substr(slash + 1));
    const std::string path = m_store.options().dir + "/.shares/" + id + ".json";
    share_link s;
    std::string text;
    // A link's maker revokes it with credentials, which a link's visitor has none of.
    if (r.method == "DELETE" && rel.empty())
    {
        if (!valid_id(id) || !read_text(path, text) || !parse_share(text, s))
        {
            app_reply(c, 404, "No such link.\n");
            return;
        }
        if (!app_login(c, "socketley"))
            return;
        const user_identity* u = c->user.get();
        if (u && !u->admin && u->id != s.owner)
        {
            app_reply(c, 403, "Only its maker or an admin revokes a link.\n");
            return;
        }
        ::unlink(path.c_str());
        app_reply(c, 204);
        return;
    }
    if (!share_open(c, id, s))
        return;
    c->share_id = id;
    const bool reading = r.method == "GET" || r.method == "HEAD";
    if (!reading && !(r.method == "PUT" && s.folder && s.upload && !rel.empty() && rel.back() != '/'))
    {
        app_reply(c, 405, s.upload ? "Upload with PUT into the folder.\n" : "This link is read only.\n");
        return;
    }
    std::string key = s.folder ? s.key + rel : s.key;
    if (!s.folder && !rel.empty())
    {
        app_reply(c, 404, "No such file in this link.\n");
        return;
    }
    // A folder link without a file is a page of what is in it, and with ?format=json a list.
    if (reading && s.folder && (rel.empty() || rel.back() == '/'))
    {
        list_query q;
        q.prefix    = key;
        q.delimiter = "/";
        const bool json = r.has_query("format") && r.get_query("format") == "json";
        std::weak_ptr<conn> weak = c;
        const std::string base = "/~share/" + id + "/";
        const std::string prefix = q.prefix;
        app_list(s.bucket, std::move(q), [this, weak, json, base, prefix, folder_prefix = s.key, upload = s.upload](st st_, list_page p)
        {
            auto cc = weak.lock();
            if (!cc || cc->dead)
                return;
            if (st_ != st::ok)
            {
                app_reply(cc, 404, "Not found.\n");
                return;
            }
            const std::string here = prefix.substr(folder_prefix.size());
            if (json)
            {
                std::string o = "{\"folders\":[";
                for (size_t i = 0; i < p.prefixes.size(); ++i)
                {
                    o += i ? "," : "";
                    jstr(o, p.prefixes[i].substr(prefix.size()));
                }
                o += "],\"files\":[";
                bool first = true;
                for (const list_entry& e : p.objects)
                {
                    if (e.key == prefix)
                        continue;
                    o += first ? "{" : ",{";
                    first = false;
                    o += "\"name\":";
                    jstr(o, e.key.substr(prefix.size()));
                    o += ",\"size\":" + std::to_string(e.meta.size) + ",\"modified\":";
                    jstr(o, iso8601(e.meta.mtime_ms));
                    o += ",\"type\":";
                    jstr(o, e.meta.content_type.str());
                    o += "}";
                }
                o += upload ? "],\"upload\":true}" : "],\"upload\":false}";
                app_reply(cc, 200, std::move(o), "application/json");
                return;
            }
            std::string h = "<!doctype html><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">"
                            "<title>Shared folder</title><style>body{font-family:system-ui;max-width:48rem;margin:2rem auto;"
                            "padding:0 1rem}li{margin:.3rem 0}</style><h1>Shared folder";
            if (!here.empty())
            {
                h += ": ";
                xml_escape_to(h, here);
            }
            h += "</h1><ul>";
            for (const std::string& sub : p.prefixes)
            {
                h += "<li><a href=\"";
                std::string href = base;
                url_encode_to(href, sub.substr(folder_prefix.size()), true);
                xml_escape_to(h, href);
                h += "\">";
                xml_escape_to(h, sub.substr(prefix.size()));
                h += "</a></li>";
            }
            for (const list_entry& e : p.objects)
            {
                if (e.key == prefix)
                    continue;
                std::string href = base;
                url_encode_to(href, e.key.substr(folder_prefix.size()), true);
                h += "<li><a href=\"";
                xml_escape_to(h, href);
                h += "\">";
                xml_escape_to(h, e.key.substr(prefix.size()));
                h += "</a> (" + std::to_string(e.meta.size) + " bytes)</li>";
            }
            h += "</ul>";
            if (upload)
                h += "<p><input type=\"file\" id=\"f\" multiple> <button onclick=\"up()\">Upload</button> <span id=\"s\"></span>"
                     "<script>async function up(){const s=document.getElementById('s');for(const f of document.getElementById('f').files){"
                     "s.textContent='Uploading '+f.name+'…';const r=await fetch(location.pathname+encodeURIComponent(f.name),"
                     "{method:'PUT',body:f});s.textContent=r.ok?'Uploaded '+f.name:'Failed: '+r.status}setTimeout(()=>location.reload(),600)}"
                     "</script>";
            app_reply(cc, 200, std::move(h), "text/html; charset=utf-8");
        });
        return;
    }
    // A download counts against the link's limit, once per reading from the start: a player's later ranges do not.
    const std::string_view range = r.header("range");
    if (r.method == "GET" && s.max_downloads && (range.empty() || range.starts_with("bytes=0-")))
    {
        const int fd = ::open(path.c_str(), O_RDWR | O_CLOEXEC);
        bool allowed = false;
        if (fd >= 0 && ::flock(fd, LOCK_EX) == 0)
        {
            share_link now;
            if (read_text(path, text) && parse_share(text, now) && now.downloads < now.max_downloads)
            {
                ++now.downloads;
                allowed = write_text(path, share_json(now));
            }
            ::flock(fd, LOCK_UN);
        }
        if (fd >= 0)
            ::close(fd);
        if (!allowed)
        {
            app_reply(c, 410, "This link has been used as often as it may be.\n");
            return;
        }
    }
    // The object itself, as the S3 path serves it, judged by the link and not by any policy.
    if (r.method == "PUT")
    {
        c->on_answer = [this](const std::shared_ptr<conn>& cc, response& resp)
        {
            response out;
            out.status = resp.status == 200 ? 201 : resp.status;
            send_response(cc, std::move(out));
        };
    }
    s3_request& q = c->req;
    const bool download = q.has_query("download");
    q.method = r.method == "HEAD" ? std::string_view("HEAD") : r.method == "PUT" ? std::string_view("PUT")
                                                                                 : std::string_view("GET");
    q.bucket = s.bucket;
    q.key    = std::move(key);
    q.query.clear();
    q.app = 0;
    if (download)
        q.query.emplace_back("response-content-disposition",
                             "attachment; filename=\"" + std::string(last_name_of(q.key)) + "\"");
    c->anonymous = true;
    c->user.reset();
    c->hook = nullptr;
    hook_request(c);
}

void storage_run::share_body(const std::shared_ptr<conn>& c)
{
    s3_request& r = c->req;
    // The management of links is a user's: SigV4 as for S3, or the password of a browser's sign-in.
    if (r.header("authorization").starts_with("AWS4-HMAC-SHA256"))
    {
        request_view rv;
        rv.method       = r.method;
        rv.raw_path     = r.raw_path;
        rv.raw_query    = r.raw_query;
        rv.host         = r.host;
        rv.payload_hash = r.payload_hash;
        rv.headers      = &r.headers;
        rv.tls          = c->ssl != nullptr;
        const std::string body_hash = sha256_hex(c->body);
        rv.body_sha256_hex = body_hash;
        auth_verdict v = m_auth->authorize(rv);
        if (!v.allowed)
        {
            app_reply(c, 403, "Access denied.\n");
            return;
        }
        c->principal = std::move(v.principal);
        c->user      = std::move(v.user);
        c->anonymous = v.anonymous;
    }
    else if (!app_login(c, "socketley"))
        return;

    const std::string dir = m_store.options().dir + "/.shares";
    const user_identity* u = c->user.get();
    if (r.method == "GET")
    {
        // The caller's links, every link for an admin.
        std::string o = "[";
        bool first = true;
        if (DIR* d = ::opendir(dir.c_str()))
        {
            while (dirent* e = ::readdir(d))
            {
                std::string_view n = e->d_name;
                if (!n.ends_with(".json"))
                    continue;
                std::string text;
                share_link s;
                if (!read_text(dir + "/" + std::string(n), text) || !parse_share(text, s))
                    continue;
                // An expired link is gone for good, and is cleared away here rather than listed.
                if (s.expires_ms && now_ms() > s.expires_ms)
                {
                    ::unlink((dir + "/" + std::string(n)).c_str());
                    continue;
                }
                if (u && !u->admin && s.owner != u->id)
                    continue;
                o += first ? "" : ",";
                first = false;
                o += share_view_json(s);
            }
            ::closedir(d);
        }
        o += "]";
        app_reply(c, 200, std::move(o), "application/json");
        return;
    }
    if (r.method != "POST")
    {
        app_reply(c, 405, "Links are made with POST and listed with GET.\n");
        return;
    }
    jvalue req;
    if (!json_reader(c->body).document(req))
    {
        app_reply(c, 400, "The body is a JSON object: bucket, key, and optionally expires_in, password, max_downloads, upload.\n");
        return;
    }
    share_link s;
    s.bucket = str_of(req, "bucket");
    s.key    = str_of(req, "key");
    s.folder = s.key.empty() || s.key.back() == '/';
    s.upload = flag_of(req, "upload");
    s.max_downloads = num_of(req, "max_downloads");
    const uint64_t expires_in = num_of(req, "expires_in");
    const std::string password = str_of(req, "password");
    s.note = str_of(req, "note").substr(0, 200);
    if (!m_store.has_bucket(s.bucket))
    {
        app_reply(c, 404, "No such bucket.\n");
        return;
    }
    if (s.upload && !s.folder)
    {
        app_reply(c, 400, "An upload link is a folder's: a key ending in a slash, or none.\n");
        return;
    }
    // A link gives what its maker may do, and nothing more.
    if (!app_allowed(c, "GET", s.bucket, s.folder ? std::string_view{} : std::string_view(s.key)) ||
        (s.upload && !app_allowed(c, "PUT", s.bucket, s.key)))
    {
        app_reply(c, 403, "You may not share what you may not read.\n");
        return;
    }
    s.owner = u ? u->id : std::string(default_owner);
    s.created_ms = now_ms();
    s.expires_ms = expires_in ? s.created_ms + static_cast<int64_t>(expires_in) * 1000 : 0;
    if (!password.empty())
    {
        s.pw_salt = random_hex(16);
        s.pw_hash = pw_hash(s.pw_salt, password);
    }
    unsigned char raw[16];
    if (RAND_bytes(raw, sizeof raw) != 1)
    {
        app_reply(c, 500, "No random bytes for a link.\n");
        return;
    }
    s.id = base64url_encode(std::string_view(reinterpret_cast<const char*>(raw), sizeof raw));
    if (::mkdir(dir.c_str(), 0700) < 0 && errno != EEXIST)
    {
        app_reply(c, 500, "The links' folder cannot be made.\n");
        return;
    }
    if (!write_text(dir + "/" + s.id + ".json", share_json(s)))
    {
        app_reply(c, 500, "The link could not be kept.\n");
        return;
    }
    app_reply(c, 201, share_view_json(s), "application/json");
}

}   // namespace socketley::storage
