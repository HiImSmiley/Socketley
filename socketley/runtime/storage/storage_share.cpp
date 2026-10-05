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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
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
    // In a cluster, each node's own count of the downloads, whose sum is `downloads`.
    std::map<std::string, uint64_t> by_node;
    bool        upload{false};
    // The maker's label for the link.
    std::string note;
    // What the link names is removed when the link ends: at its expiry, or a while after its last download.
    bool        burn{false};
    // When the last download a limit allows was counted.
    int64_t     drained_ms{0};
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
    if (!s.by_node.empty())
    {
        o += ",\"by_node\":{";
        bool first = true;
        for (const auto& [node, n] : s.by_node)
        {
            o += first ? "" : ",";
            first = false;
            jstr(o, node);
            o += ":" + std::to_string(n);
        }
        o += "}";
    }
    o += s.upload ? ",\"upload\":true" : ",\"upload\":false";
    o += ",\"note\":";
    jstr(o, s.note);
    if (s.burn)
        o += ",\"burn\":true,\"drained\":" + std::to_string(s.drained_ms);
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
    if (const jvalue* by = member(root, "by_node"); by && by->k == jvalue::kind::object)
        for (const auto& [node, v] : by->members)
            s.by_node[node] = num_of(*by, node);
    s.upload = flag_of(root, "upload");
    s.note = str_of(root, "note");
    s.burn = flag_of(root, "burn");
    s.drained_ms = static_cast<int64_t>(num_of(root, "drained"));
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
    o += s.burn ? ",\"burn\":true" : ",\"burn\":false";
    o += "}";
    return o;
}

// How long a burning link's files outlive its last allowed download, so a browser resuming that download finds them;
// SOCKETLEY_SHARE_BURN_GRACE_SECS shortens it, a test aid.
int64_t burn_grace_ms()
{
    static const int64_t ms = []
    {
        const char* e = std::getenv("SOCKETLEY_SHARE_BURN_GRACE_SECS");
        int64_t secs = 600;
        if (e && *e)
            std::from_chars(e, e + std::strlen(e), secs);
        return std::max<int64_t>(0, secs) * 1000;
    }();
    return ms;
}

std::string human_size(uint64_t n)
{
    static const char* units[] = {"bytes", "KB", "MB", "GB", "TB"};
    double v = static_cast<double>(n);
    int u = 0;
    while (v >= 1000 && u < 4)
    {
        v /= 1000;
        ++u;
    }
    char buf[32];
    std::snprintf(buf, sizeof buf, u ? "%.1f %s" : "%.0f %s", v, units[u]);
    return buf;
}

// The page a burning file's link opens on, which counts nothing: a chat's preview of the link reads this and not the
// file, and the file is taken with ?download.
std::string landing_page(const share_link& s, std::string_view name, const object_meta* m, int64_t now)
{
    std::string h = "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" "
                    "content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex\"><title>";
    xml_escape_to(h, name);
    h += "</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;"
         "justify-content:center;padding:16px;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#f1f0ff;"
         "background:radial-gradient(700px 500px at 15% 10%,#6d28d9aa,transparent 60%),radial-gradient(700px 500px at "
         "90% 90%,#db277799,transparent 60%),radial-gradient(600px 400px at 80% 10%,#0891b288,transparent 60%),#07060d}"
         ".c{width:100%;max-width:440px;padding:34px 30px;border-radius:24px;background:rgba(16,12,30,.72);border:1px solid "
         "rgba(255,255,255,.12);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);text-align:center;"
         "box-shadow:0 30px 80px -30px #000}.i{width:76px;height:76px;margin:0 auto 18px;border-radius:22px;display:flex;"
         "align-items:center;justify-content:center;background:linear-gradient(135deg,#a855f7,#ec4899 55%,#f97316);"
         "box-shadow:0 14px 40px -12px #ec4899}h1{font-size:20px;margin:0 0 6px;word-break:break-all}p{margin:0;color:#b9b3d6}"
         ".m{display:flex;gap:8px;justify-content:center;flex-wrap:wrap;margin:18px 0 24px}.m span{padding:4px 11px;"
         "border-radius:99px;background:rgba(255,255,255,.08);font-size:13px}a.b{display:block;padding:14px;border-radius:14px;"
         "color:#fff;text-decoration:none;font-weight:700;background:linear-gradient(135deg,#a855f7,#ec4899 55%,#f97316);"
         "box-shadow:0 12px 30px -10px #ec4899}a.b:hover{filter:brightness(1.1)}small{display:block;margin-top:16px;"
         "color:#7d7799}</style><div class=\"c\"><div class=\"i\"><svg width=\"34\" height=\"34\" viewBox=\"0 0 24 24\" "
         "fill=\"none\" stroke=\"#fff\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path "
         "d=\"M12 4v11m-4.5-4.5L12 15l4.5-4.5M4 15v3.5A1.5 1.5 0 0 0 5.5 20h13a1.5 1.5 0 0 0 1.5-1.5V15\"/></svg></div><h1>";
    xml_escape_to(h, name);
    h += "</h1><p>Someone sent you a file.</p><div class=\"m\">";
    if (m)
        h += "<span>" + human_size(m->size) + "</span>";
    if (s.max_downloads)
    {
        const uint64_t left = s.max_downloads > s.downloads ? s.max_downloads - s.downloads : 0;
        h += "<span>" + std::to_string(left) + (left == 1 ? " download left" : " downloads left") + "</span>";
    }
    if (s.expires_ms)
    {
        const int64_t mins = std::max<int64_t>(1, (s.expires_ms - now) / 60000);
        h += "<span>gone in " + (mins >= 2880 ? std::to_string(mins / 1440) + " days" : mins >= 120 ?
             std::to_string(mins / 60) + " hours" : std::to_string(mins) + " minutes") + "</span>";
    }
    h += "</div><a class=\"b\" href=\"?download\">Download</a><small>The file is deleted when the link ends.</small></div>";
    return h;
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
        // A link that burns takes what it names with it, by the sweep, which finds it under its new name.
        if (s.burn)
        {
            if (::rename(path.c_str(), (m_store.options().dir + "/.shares/" + id + ".burning").c_str()) < 0)
            {
                app_reply(c, 500, "The link could not be ended.\n");
                return;
            }
            ++m_burns;
            m_burn_next = {};
            arm_sweep();
        }
        else
            ::unlink(path.c_str());
        ::unlink((path + ".lock").c_str());
        share_sent(id, {}, [this, weak = std::weak_ptr<conn>(c)]()
        {
            if (auto cc = weak.lock(); cc && !cc->dead)
                app_reply(cc, 204);
        });
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
    // A burning file's link opens on a page, and the file itself is read with ?download.
    if (s.burn && !s.folder && r.method == "GET" && !r.has_query("download"))
    {
        app_reply(c, 200, landing_page(s, last_name_of(key), m_store.find(s.bucket, key), now_ms()),
                  "text/html; charset=utf-8");
        return;
    }
    // A download counts against the link's limit, once per reading from the start: a player's later ranges do not.
    const std::string_view range = r.header("range");
    if (r.method == "GET" && s.max_downloads && (range.empty() || range.starts_with("bytes=0-")))
    {
        // Locked by a file of its own: the link's file is renamed over at every count, and a lock on it would be on
        // the inode another request no longer opens.
        const int fd = ::open((path + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        bool allowed = false;
        if (fd >= 0 && ::flock(fd, LOCK_EX) == 0)
        {
            share_link now;
            if (read_text(path, text) && parse_share(text, now) && now.downloads < now.max_downloads)
            {
                // A node of a cluster counts its own, which every node adds up with the others'.
                if (!m_cluster_self.empty())
                {
                    if (now.by_node.empty() && now.downloads)
                        now.by_node["-"] = now.downloads;
                    ++now.by_node[m_cluster_self];
                }
                ++now.downloads;
                if (now.burn && now.downloads >= now.max_downloads)
                    now.drained_ms = now_ms();
                allowed = write_text(path, share_json(now));
                if (allowed)
                    share_sent(id, share_json(now), {});
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
        rv.tls          = secure(*c);
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
                    // One that burns is left to the sweep, which removes what it names first.
                    if (s.burn)
                        continue;
                    ::unlink((dir + "/" + std::string(n)).c_str());
                    ::unlink((dir + "/" + std::string(n) + ".lock").c_str());
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
    s.burn = flag_of(req, "burn");
    if (!m_store.has_bucket(s.bucket))
    {
        app_reply(c, 404, "No such bucket.\n");
        return;
    }
    if (s.burn && (s.upload || (!expires_in && !s.max_downloads)))
    {
        app_reply(c, 400, "A link that burns what it names ends: give it expires_in or max_downloads, and no upload.\n");
        return;
    }
    // A cluster's nodes each own their keys, and the sweep removes on this node only.
    if (s.burn && !m_cluster_self.empty())
    {
        app_reply(c, 400, "Links that burn are not made in a cluster.\n");
        return;
    }
    if (s.upload && !s.folder)
    {
        app_reply(c, 400, "An upload link is a folder's: a key ending in a slash, or none.\n");
        return;
    }
    // A link gives what its maker may do, and nothing more.
    if (!app_allowed(c, "GET", s.bucket, s.folder ? std::string_view{} : std::string_view(s.key)) ||
        (s.upload && !app_allowed(c, "PUT", s.bucket, s.key)) ||
        (s.burn && !app_allowed(c, "DELETE", s.bucket, s.key)))
    {
        app_reply(c, 403, s.burn ? "You may not burn what you may not delete.\n" : "You may not share what you may not read.\n");
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
    if (s.burn)
    {
        ++m_burns;
        arm_sweep();
    }
    share_sent(s.id, share_json(s), [this, weak = std::weak_ptr<conn>(c), view = share_view_json(s)]() mutable
    {
        if (auto cc = weak.lock(); cc && !cc->dead)
            app_reply(cc, 201, std::move(view), "application/json");
    });
}

void storage_run::share_sent(const std::string& id, std::string json, std::function<void()> then)
{
    // A link made or revoked is on the other nodes' way before its maker hears so; a download's count is not waited for.
    const bool queued = m_repl.enqueue_nodes({'i', {}, {}, {}, {}, encode_cluster_record({'h', id, 0, std::move(json), {}})});
    if (!then)
        return;
    if (queued)
        m_repl.sync(std::move(then));
    else
        then();
}

st storage_run::share_take(const std::string& id, const std::string& json)
{
    if (!valid_id(id))
        return st::invalid_bucket_name;
    const std::string dir  = m_store.options().dir + "/.shares";
    const std::string path = dir + "/" + id + ".json";
    if (json.empty())
    {
        ::unlink(path.c_str());
        ::unlink((path + ".lock").c_str());
        return st::ok;
    }
    share_link in;
    if (!parse_share(json, in) || in.id != id)
        return st::invalid_bucket_name;
    if (::mkdir(dir.c_str(), 0700) < 0 && errno != EEXIST)
        return st::io_error;
    const int fd = ::open((path + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0 || ::flock(fd, LOCK_EX) < 0)
    {
        if (fd >= 0)
            ::close(fd);
        return st::io_error;
    }
    // Each node's count only grows, and the downloads are their sum.
    std::string text;
    share_link now;
    if (read_text(path, text) && parse_share(text, now))
        for (const auto& [node, n] : now.by_node)
            in.by_node[node] = std::max(in.by_node[node], n);
    if (!in.by_node.empty())
    {
        in.downloads = 0;
        for (const auto& [node, n] : in.by_node)
            in.downloads += n;
    }
    const bool ok = write_text(path, share_json(in));
    ::flock(fd, LOCK_UN);
    ::close(fd);
    return ok ? st::ok : st::io_error;
}

std::vector<std::string> storage_run::share_records()
{
    std::vector<std::string> out;
    const std::string dir = m_store.options().dir + "/.shares";
    if (DIR* d = ::opendir(dir.c_str()))
    {
        while (dirent* e = ::readdir(d))
        {
            const std::string_view n = e->d_name;
            std::string text;
            share_link s;
            if (n.ends_with(".json") && read_text(dir + "/" + std::string(n), text) && parse_share(text, s))
                out.push_back(encode_cluster_record({'h', s.id, 0, std::move(text), {}}));
        }
        ::closedir(d);
    }
    return out;
}

// ─── Links that burn ────────────────────────────────────────────────────────
// Every few seconds, while any are known, the links that burn are looked over: one past its expiry, or past the grace
// after its last allowed download, is renamed to <id>.burning, which ends it for every reader at once, and what it
// names is removed; the file goes when that is done. A .burning file found at a start is taken up again. Two shards
// may both take up one left at a start, and the second's removals find nothing.

void storage_run::share_burn_tick()
{
    const auto now = std::chrono::steady_clock::now();
    if (now < m_burn_next)
        return;
    m_burn_next = now + std::chrono::seconds(5);
    const std::string dir = m_store.options().dir + "/.shares";
    const int64_t t = now_ms();
    size_t seen = 0;
    DIR* d = ::opendir(dir.c_str());
    if (!d)
    {
        m_burns = 0;
        return;
    }
    while (dirent* e = ::readdir(d))
    {
        const std::string_view n = e->d_name;
        const bool burning = n.ends_with(".burning");
        if (!burning && !n.ends_with(".json"))
            continue;
        std::string text;
        share_link s;
        const std::string path = dir + "/" + std::string(n);
        if (!read_text(path, text) || !parse_share(text, s) || !s.burn)
            continue;
        ++seen;
        if (m_burning.count(s.id))
            continue;
        if (!burning)
        {
            const bool due = (s.expires_ms && t > s.expires_ms) || (s.drained_ms && t > s.drained_ms + burn_grace_ms());
            if (!due || ::rename(path.c_str(), (dir + "/" + s.id + ".burning").c_str()) < 0)
                continue;
            ::unlink((path + ".lock").c_str());
            share_sent(s.id, {}, nullptr);
        }
        share_burn(s.id, s.bucket, s.key, s.folder);
    }
    ::closedir(d);
    m_burns = seen;
}

void storage_run::share_burn(std::string id, std::string bucket, std::string key, bool folder)
{
    m_burning.insert(id);
    struct burn
    {
        std::string id, bucket;
        size_t left{0};
        size_t removed{0};
    };
    auto b = std::make_shared<burn>();
    b->id = id;
    b->bucket = bucket;
    auto one_done = [this, b](st s, bool existed)
    {
        if (s == st::ok && existed)
            ++b->removed;
        else if (s != st::ok && s != st::no_such_key && s != st::no_such_bucket)
            LOG_WARN(("storage: a burning link could not remove from " + b->bucket + ": " + status_name(s)).c_str());
        if (--b->left)
            return;
        ::unlink((m_store.options().dir + "/.shares/" + b->id + ".burning").c_str());
        m_burning.erase(b->id);
        LOG_INFO(("storage: link " + b->id + " ended and removed " + std::to_string(b->removed) + " object(s) of " +
                  b->bucket).c_str());
    };
    if (!folder)
    {
        b->left = 1;
        m_store.remove(bucket, key, one_done);
        return;
    }
    list_query q;
    q.prefix = key;
    app_list(bucket, std::move(q), [this, b, bucket, one_done](st s, list_page p)
    {
        if (s != st::ok || p.objects.empty())
        {
            b->left = 1;
            one_done(st::ok, false);
            return;
        }
        b->left = p.objects.size();
        for (const list_entry& e : p.objects)
            m_store.remove(bucket, e.key, one_done);
    });
}

}   // namespace socketley::storage
