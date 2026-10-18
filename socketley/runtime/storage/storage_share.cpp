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
#include <cctype>
#include <charconv>

#include "digest.h"
#include "../../shared/json/json_doc.h"
#include "s3_names.h"
#include "s3_xml.h"
#include "../../shared/util/logging.h"
#include "../../shared/persist/state_persistence.h"
#include "../../shared/persist/replaced_file.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/util/wall_clock.h"
#include "../../shared/util/base64.h"
#include "../../shared/util/random_id.h"

using socketley::json::jvalue;
using socketley::json::json_reader;

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
    // A webhook told of each download, and of the files' removal when the link burns.
    std::string notify;
};

namespace
{

std::string share_json(const share_link& s)
{
    std::string o = "{\"id\":";
    socketley::json::quote_into(o, s.id);
    o += ",\"bucket\":";
    socketley::json::quote_into(o, s.bucket);
    o += ",\"key\":";
    socketley::json::quote_into(o, s.key);
    o += s.folder ? ",\"folder\":true" : ",\"folder\":false";
    o += ",\"owner\":";
    socketley::json::quote_into(o, s.owner);
    o += ",\"created\":" + std::to_string(s.created_ms) + ",\"expires\":" + std::to_string(s.expires_ms);
    o += ",\"salt\":";
    socketley::json::quote_into(o, s.pw_salt);
    o += ",\"hash\":";
    socketley::json::quote_into(o, s.pw_hash);
    o += ",\"max_downloads\":" + std::to_string(s.max_downloads) + ",\"downloads\":" + std::to_string(s.downloads);
    if (!s.by_node.empty())
    {
        o += ",\"by_node\":{";
        bool first = true;
        for (const auto& [node, n] : s.by_node)
        {
            o += first ? "" : ",";
            first = false;
            socketley::json::quote_into(o, node);
            o += ':';
            o += std::to_string(n);
        }
        o += "}";
    }
    o += s.upload ? ",\"upload\":true" : ",\"upload\":false";
    o += ",\"note\":";
    socketley::json::quote_into(o, s.note);
    if (s.burn)
        o += ",\"burn\":true,\"drained\":" + std::to_string(s.drained_ms);
    if (!s.notify.empty())
    {
        o += ",\"notify\":";
        socketley::json::quote_into(o, s.notify);
    }
    o += "}";
    return o;
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
    s.notify = str_of(root, "notify");
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

std::string pw_hash(std::string_view salt, std::string_view password)
{
    return sha256_hex(std::string(salt) + std::string(password));
}

std::string_view last_name_of(std::string_view key)
{
    const size_t slash = key.rfind('/');
    return slash == std::string_view::npos ? key : key.substr(slash + 1);
}

std::string share_view_json(const share_link& s)
{
    std::string o = "{\"id\":";
    socketley::json::quote_into(o, s.id);
    o += ",\"url\":";
    socketley::json::quote_into(o, "/~share/" + s.id + (s.folder ? "/" : ""));
    o += ",\"bucket\":";
    socketley::json::quote_into(o, s.bucket);
    o += ",\"key\":";
    socketley::json::quote_into(o, s.key);
    o += s.folder ? ",\"folder\":true" : ",\"folder\":false";
    o += ",\"expires\":";
    socketley::json::quote_into(o, s.expires_ms ? iso8601(s.expires_ms) : std::string{});
    o += s.pw_hash.empty() ? ",\"password\":false" : ",\"password\":true";
    o += ",\"max_downloads\":" + std::to_string(s.max_downloads) + ",\"downloads\":" + std::to_string(s.downloads);
    o += s.upload ? ",\"upload\":true" : ",\"upload\":false";
    o += ",\"note\":";
    socketley::json::quote_into(o, s.note);
    o += ",\"owner\":";
    socketley::json::quote_into(o, s.owner);
    o += s.burn ? ",\"burn\":true" : ",\"burn\":false";
    o += s.notify.empty() ? ",\"notify\":false" : ",\"notify\":true";
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

// Whether a link's file is a film, by its name, which a page that plays it is decided by before the object is read.
bool film_name(std::string_view name)
{
    const size_t dot = name.rfind('.');
    if (dot == std::string_view::npos)
        return false;
    std::string ext(name.substr(dot + 1));
    for (char& ch : ext)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    for (std::string_view e : {"mp4", "m4v", "mov", "mkv", "webm", "avi", "wmv", "flv", "ts", "mts", "m2ts", "mpg",
                               "mpeg", "3gp", "ogv"})
        if (ext == e)
            return true;
    return false;
}

// Whether a film's link answers with its page, which is always but for a player reading by range, since a chat's
// preview comes by HEAD or GET under names that change and embeds nothing when it is told the film itself.
bool wants_page(const s3_request& r)
{
    return r.header("range").empty();
}

// A film's link as a page that plays it, with the Open Graph a chat embeds a player by.
std::string film_page(std::string_view name, const object_meta* m, std::string_view page_url, std::string_view video_url,
                      std::string_view chat_url, std::string_view poster_url, std::string_view prepare_url, int64_t width, int64_t height)
{
    auto meta = [](std::string& h, std::string_view attr, std::string_view k, std::string_view v)
    {
        h += "<meta ";
        h += attr;
        h += "=\"";
        h += k;
        h += "\" content=\"";
        xml_escape_to(h, v);
        h += "\">";
    };
    std::string h = "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" "
                    "content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex\"><title>";
    xml_escape_to(h, name);
    h += "</title>";
    // The tags Vice's clip links give Discord, which plays files of any size by them: the still it shows first, so
    // it need not make one, and the film as a URL ending in .mp4, named as the player's stream as well.
    meta(h, "property", "og:site_name", "socketley");
    meta(h, "property", "og:title", name);
    meta(h, "property", "og:url", page_url);
    meta(h, "property", "og:image", poster_url);
    if (!chat_url.empty())
    {
        meta(h, "property", "og:type", "video.other");
        meta(h, "property", "og:video", chat_url);
        meta(h, "property", "og:video:url", chat_url);
        if (chat_url.starts_with("https:"))
            meta(h, "property", "og:video:secure_url", chat_url);
        meta(h, "property", "og:video:type", "video/mp4");
        meta(h, "property", "og:video:width", std::to_string(width));
        meta(h, "property", "og:video:height", std::to_string(height));
        meta(h, "name", "twitter:card", "player");
        meta(h, "name", "twitter:player", chat_url);
        meta(h, "name", "twitter:player:stream", chat_url);
        meta(h, "name", "twitter:player:stream:content_type", "video/mp4");
        meta(h, "name", "twitter:player:width", std::to_string(width));
        meta(h, "name", "twitter:player:height", std::to_string(height));
        meta(h, "name", "twitter:image", poster_url);
    }
    else
        meta(h, "name", "twitter:card", "summary_large_image");
    meta(h, "name", "theme-color", "#a855f7");
    h += "<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:"
         "center;padding:16px;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#f1f0ff;background:"
         "radial-gradient(700px 500px at 15% 10%,#6d28d9aa,transparent 60%),radial-gradient(700px 500px at 90% 90%,"
         "#db277799,transparent 60%),#07060d}.c{width:100%;max-width:1100px}video{width:100%;max-height:80vh;"
         "border-radius:18px;background:#000;box-shadow:0 30px 80px -30px #000}.r{display:flex;align-items:center;gap:12px;"
         "margin-top:14px}h1{font-size:18px;margin:0;flex:1;word-break:break-all}.m{color:#b9b3d6;font-size:13px}"
         "a.b{padding:10px 18px;border-radius:12px;color:#fff;text-decoration:none;font-weight:700;background:"
         "linear-gradient(135deg,#a855f7,#ec4899 55%,#f97316)}</style><div class=\"c\"><video controls playsinline "
         "preload=\"metadata\" poster=\"";
    xml_escape_to(h, poster_url);
    h += "\" src=\"";
    xml_escape_to(h, video_url);
    h += "\"></video><div class=\"r\"><h1>";
    xml_escape_to(h, name);
    h += "</h1>";
    if (m)
        h += "<span class=\"m\">" + human_size(m->size) + "</span>";
    h += "<a class=\"b\" href=\"?download\">Download</a></div></div>";
    // A film no browser plays as it is gets its web copy asked for, which the next look at the link plays.
    if (!prepare_url.empty())
    {
        h += "<script>fetch(\"";
        xml_escape_to(h, prepare_url);
        h += "\").catch(function(){})</script>";
    }
    return h;
}

}   // namespace

bool storage_run::share_open(const std::shared_ptr<conn>& c, std::string_view id, share_link& s)
{
    std::string text;
    if (!valid_id(id) || !read_whole_file(m_store.options().dir + "/.shares/" + std::string(id) + ".json", text) ||
        !parse_share(text, s))
    {
        app_reply(c, 404, "No such link.\n");
        return false;
    }
    if (s.expires_ms && wall::now_ms() > s.expires_ms)
    {
        app_reply(c, 410, "This link has expired.\n");
        return false;
    }
    if (s.pw_hash.empty())
        return true;
    // Any user name, and the link's password, as a browser asks for them.
    const std::string_view h = c->req.header("authorization");
    std::string pair;
    if (std::string_view cred; http_auth_credentials(h, "basic", cred))
    {
        if (login_barred(c))
            return false;
        if (base64::decode(cred, pair))
        {
            const size_t colon = pair.find(':');
            const std::string got = pw_hash(s.pw_salt, colon == std::string::npos ? std::string_view{} :
                                                                                   std::string_view(pair).substr(colon + 1));
            if (got.size() == s.pw_hash.size() && CRYPTO_memcmp(got.data(), s.pw_hash.data(), got.size()) == 0)
                return true;
        }
        login_missed(*c);
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
        if (!valid_id(id) || !read_whole_file(path, text) || !parse_share(text, s))
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
            const std::string to = m_store.options().dir + "/.shares/" + id + ".burning";
            if (::rename(path.c_str(), to.c_str()) < 0)
            {
                app_reply(c, 500, "The link could not be ended.\n");
                return;
            }
            ::utimensat(AT_FDCWD, to.c_str(), nullptr, 0);
            share_burn(s.id, s.bucket, s.key, s.folder);
            if (!s.notify.empty())
                share_tell(s.notify, "deleted", s.bucket, s.key, s.downloads, s.max_downloads, s.expires_ms, true);
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
    if (reading && s.folder && (rel.empty() || rel.back() == '/') && !r.has_query("zip"))
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
                    socketley::json::quote_into(o, p.prefixes[i].substr(prefix.size()));
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
                    socketley::json::quote_into(o, e.key.substr(prefix.size()));
                    o += ",\"size\":" + std::to_string(e.meta.size) + ",\"modified\":";
                    socketley::json::quote_into(o, iso8601(e.meta.mtime_ms));
                    o += ",\"type\":";
                    socketley::json::quote_into(o, e.meta.content_type.str());
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
            if (!p.objects.empty() || !p.prefixes.empty())
                h += "<p><a href=\"?zip\"><b>Download all as a ZIP</b></a></p>";
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
        // Its size from whichever shard owns the key: this one's index holds only its own.
        m_store.stat_object(s.bucket, key, [this, weak = std::weak_ptr<conn>(c), s, key](st found, const object_meta& m)
        {
            auto cc = weak.lock();
            if (!cc || cc->dead)
                return;
            app_reply(cc, 200, landing_page(s, last_name_of(key), found == st::ok ? &m : nullptr, wall::now_ms()),
                      "text/html; charset=utf-8");
        });
        return;
    }
    // A film's link opens, for a browser or a chat's preview, on a page that plays it; ?raw is the file itself.
    if (!s.folder && !s.burn && (r.method == "GET" || r.method == "HEAD") && !r.has_query("download") &&
        !r.has_query("raw") && film_name(last_name_of(key)) && wants_page(r))
    {
        const std::string base = (secure(*c) ? "https://" : "http://") + std::string(r.header("host"));
        m_store.stat_object(s.bucket, key, [this, weak = std::weak_ptr<conn>(c), s, key, id, base](st found,
                                                                                                const object_meta& m)
        {
            auto cc = weak.lock();
            if (!cc || cc->dead)
                return;
            if (found != st::ok)
            {
                app_reply(cc, 404, "No such file in this link.\n");
                return;
            }
            std::shared_ptr<const media_probe> p;
            bool web_made = false;
            media_known(s.bucket, key, m.etag(), p, web_made);
            const std::string page = base + "/~share/" + id;
            // The web copy once it is made, whose index is in front so a chat plays it before it has all of it; until
            // then the file itself, which plays wherever it is H.264 in an MP4.
            const std::string web = base + "/~media/web/~share/" + id;
            const std::string video = web_made ? web : page + "?raw";
            // A chat is given only the web copy, as <id>.mp4: until it is made a chat shows the still alone.
            const std::string chat = web_made ? web + ".mp4" : std::string();
            // The web copy's own size, which a chat sizes its player by.
            int64_t width = 1280, height = 720;
            if (p && p->width > 0 && p->height > 0)
            {
                const web_plan plan = web_plan_of(*p);
                width = plan.width;
                height = plan.height;
            }
            app_reply(cc, 200, film_page(last_name_of(key), &m, page, video, chat, base + "/~media/thumb-1280/~share/" + id,
                                         web_made ? std::string() : web + "?prepare", width, height),
                      "text/html; charset=utf-8");
        });
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
            if (read_whole_file(path, text) && parse_share(text, now) && now.downloads < now.max_downloads)
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
                    now.drained_ms = wall::now_ms();
                allowed = replace_file(path, share_json(now), durability::data_and_dir);
                if (allowed)
                    share_sent(id, share_json(now), {});
                if (allowed && !now.notify.empty())
                    share_tell(now.notify, "downloaded", now.bucket, now.key, now.downloads, now.max_downloads, now.expires_ms,
                               now.burn);
                if (allowed)
                    inbox_add(now.owner, "share", "Downloaded: " + std::string(last_name_of(key)),
                              std::to_string(now.downloads) + " of " + std::to_string(now.max_downloads) +
                                  " downloads through your link");
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
    // A folder's link read with ?zip is the folder, or the part of it under the path, as one archive; it counts as one
    // download.
    if (reading && s.folder && r.has_query("zip"))
    {
        if (!key.empty() && key.back() != '/')
            key += '/';
        std::string archive = key.size() > s.key.size() ? key.substr(0, key.size() - 1) : s.key.empty() ? s.bucket
                              : s.key.substr(0, s.key.size() - 1);
        archive = archive.substr(archive.rfind('/') + 1);
        c->anonymous = true;
        c->user.reset();
        zip_start(c, s.bucket, std::move(key), {}, std::move(archive), true);
        return;
    }
    // The object itself, as the S3 path serves it, judged by the link and not by any policy.
    if (r.method == "PUT")
    {
        // A file put into a folder through its link is news for whoever made the link.
        c->on_answer = [this, owner = s.owner, bucket = s.bucket, put = key](const std::shared_ptr<conn>& cc, response& resp)
        {
            if (resp.status == 200)
                inbox_add(owner, "share", "Uploaded through your link: " + std::string(last_name_of(put)),
                          "Into " + bucket + "/" + put.substr(0, put.rfind('/') + 1),
                          "#/" + bucket + "/" + put.substr(0, put.rfind('/') + 1));
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
    // The interface's own header, which keeps a quote or a control character in the name from breaking it.
    if (download)
        q.query.emplace_back("response-content-disposition", attachment_of(q.key));
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
                if (!read_whole_file(dir + "/" + std::string(n), text) || !parse_share(text, s))
                    continue;
                // An expired link is gone for good, and is cleared away here rather than listed.
                if (s.expires_ms && wall::now_ms() > s.expires_ms)
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
    s.notify = str_of(req, "notify");
    if (!s.notify.empty() && !notify_allowed(s.notify))
    {
        app_reply(c, 400, "A link's notify is an https webhook of Discord, Slack or ntfy (or what "
                          "SOCKETLEY_SHARE_NOTIFY_ALLOW names).\n");
        return;
    }
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
    s.created_ms = wall::now_ms();
    // A lifetime past a hundred years is one that does not end, and is not multiplied past int64 into the past.
    constexpr uint64_t century_s = 100ull * 365 * 86400;
    s.expires_ms = !expires_in || expires_in > century_s ? 0 : s.created_ms + static_cast<int64_t>(expires_in) * 1000;
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
    s.id = base64url::encode(std::string_view(reinterpret_cast<const char*>(raw), sizeof raw));
    if (::mkdir(dir.c_str(), 0700) < 0 && errno != EEXIST)
    {
        app_reply(c, 500, "The links' folder cannot be made.\n");
        return;
    }
    if (!replace_file(dir + "/" + s.id + ".json", share_json(s), durability::data_and_dir))
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
    if (read_whole_file(path, text) && parse_share(text, now))
        for (const auto& [node, n] : now.by_node)
            in.by_node[node] = std::max(in.by_node[node], n);
    if (!in.by_node.empty())
    {
        in.downloads = 0;
        for (const auto& [node, n] : in.by_node)
            in.downloads += n;
    }
    const bool ok = replace_file(path, share_json(in), durability::data_and_dir);
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
            if (n.ends_with(".json") && read_whole_file(dir + "/" + std::string(n), text) && parse_share(text, s))
                out.push_back(encode_cluster_record({'h', s.id, 0, std::move(text), {}}));
        }
        ::closedir(d);
    }
    return out;
}

// ─── Links that burn ────────────────────────────────────────────────────────
// Every few seconds, while any are known, the links that burn are looked over: one past its expiry, or past the grace
// after its last allowed download, is renamed to <id>.burning, which ends it for every reader at once, and what it
// names is removed; the file goes when that is done. The shard that renamed it stamps it and removes; a .burning file
// stamped more than a minute ago was left by a stop and is taken up again, stamped anew, by the first shard to see it.

void storage_run::share_burn_tick()
{
    const auto now = std::chrono::steady_clock::now();
    if (now < m_burn_next)
        return;
    m_burn_next = now + std::chrono::seconds(5);
    const std::string dir = m_store.options().dir + "/.shares";
    const int64_t t = wall::now_ms();
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
        if (!read_whole_file(path, text) || !parse_share(text, s) || !s.burn)
            continue;
        ++seen;
        if (m_burning.count(s.id))
            continue;
        if (!burning)
        {
            const bool due = (s.expires_ms && t > s.expires_ms) || (s.drained_ms && t > s.drained_ms + burn_grace_ms());
            const std::string to = dir + "/" + s.id + ".burning";
            if (!due || ::rename(path.c_str(), to.c_str()) < 0)
                continue;
            // Stamped now, so another shard's look leaves it to this one.
            ::utimensat(AT_FDCWD, to.c_str(), nullptr, 0);
            ::unlink((path + ".lock").c_str());
            share_sent(s.id, {}, nullptr);
            share_burn(s.id, s.bucket, s.key, s.folder);
            if (!s.notify.empty())
                share_tell(s.notify, "deleted", s.bucket, s.key, s.downloads, s.max_downloads, s.expires_ms, true);
            continue;
        }
        // A .burning file another shard is at was stamped within the minute; one older was left by a stop.
        struct stat sb{};
        if (::stat(path.c_str(), &sb) == 0 && t - (static_cast<int64_t>(sb.st_mtim.tv_sec) * 1000) < 60000)
            continue;
        ::utimensat(AT_FDCWD, path.c_str(), nullptr, 0);
        share_burn(s.id, s.bucket, s.key, s.folder);
    }
    ::closedir(d);
    // The webhooks' exchanges that stalled end, and peers left with nothing to do go.
    const auto tnow = std::chrono::steady_clock::now();
    for (auto it = m_hooks.begin(); it != m_hooks.end();)
    {
        it->second->peer->tick(tnow);
        if (!it->second->peer->busy() && it->second->queue.empty() && tnow - it->second->used > std::chrono::seconds(30))
            it = m_hooks.erase(it);
        else
            ++it;
    }
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

// ─── Telling a webhook of a link's downloads ────────────────────────────────
// A link's notify is a URL its maker gives, which the runtime then POSTs to: so it is only one of the prefixes
// SOCKETLEY_SHARE_NOTIFY_ALLOW names, comma-separated, by default the webhooks of Discord and Slack and ntfy.sh, and
// never another address a user would have the runtime reach for them.
bool storage_run::notify_allowed(std::string_view url)
{
    static const std::vector<std::string> allow = []
    {
        std::vector<std::string> out;
        const char* e = std::getenv("SOCKETLEY_SHARE_NOTIFY_ALLOW");
        std::string_view v = e && *e ? std::string_view(e)
                                     : "https://discord.com/api/webhooks/,https://discordapp.com/api/webhooks/,"
                                       "https://hooks.slack.com/,https://ntfy.sh/";
        while (!v.empty())
        {
            const size_t comma = v.find(',');
            std::string_view one = v.substr(0, comma);
            while (!one.empty() && one.front() == ' ')
                one.remove_prefix(1);
            if (!one.empty())
                out.emplace_back(one);
            v = comma == std::string_view::npos ? std::string_view{} : v.substr(comma + 1);
        }
        return out;
    }();
    http_target t;
    std::string why;
    if (url.size() > 1000 || !parse_http_url(url, t, why))
        return false;
    for (const std::string& a : allow)
        if (url.starts_with(a))
            return true;
    return false;
}

void storage_run::share_tell(const std::string& url, std::string_view what, const std::string& bucket,
                             const std::string& key, uint64_t downloads, uint64_t max_downloads, int64_t expires_ms,
                             bool burn)
{
    const std::string_view name = key.empty() ? std::string_view(bucket)
                                  : key.back() == '/' ? std::string_view(key).substr(0, key.size() - 1) : std::string_view(key);
    const std::string_view shown = name.substr(name.rfind('/') == std::string_view::npos ? 0 : name.rfind('/') + 1);
    std::string text;
    if (what == "deleted")
        text = "\xF0\x9F\x94\xA5 " + std::string(shown) + " was deleted: its link ended.";
    else
    {
        text = "\xF0\x9F\x93\xA5 " + std::string(shown) + " was downloaded";
        text += max_downloads ? " (" + std::to_string(downloads) + " of " + std::to_string(max_downloads) + ")."
                              : " (" + std::to_string(downloads) + (downloads == 1 ? " time)." : " times).");
        if (burn && max_downloads && downloads >= max_downloads)
            text += " That was the last: it is deleted in a few minutes.";
    }
    std::string body = "{\"content\":";
    body += '"' + socketley::json::escape(text) + '"';
    body += ",\"text\":\"" + socketley::json::escape(text) + "\",\"event\":\"" + std::string(what) + "\",\"bucket\":\"" +
            socketley::json::escape(bucket) + "\",\"key\":\"" + socketley::json::escape(key) + "\",\"downloads\":" +
            std::to_string(downloads) + ",\"max_downloads\":" + std::to_string(max_downloads) + ",\"expires\":" +
            std::to_string(expires_ms) + "}";
    // Parsed before a slot is made for it, so a URL that is none leaves no empty hook behind for the sweep.
    auto found = m_hooks.find(url);
    if (found == m_hooks.end() || !found->second)
    {
        http_target t;
        std::string why;
        if (!parse_http_url(url, t, why))
            return;
        found = m_hooks.insert_or_assign(url, std::make_unique<hook_peer>()).first;
        found->second->peer = std::make_unique<http_peer>(m_loop, m_io, m_hash, t, std::string{}, "a link's webhook");
    }
    auto& h = found->second;
    // At most a few waiting, so a webhook that does not answer cannot hold memory without bound.
    if (h->queue.size() < 16)
        h->queue.push_back(std::move(body));
    h->used = std::chrono::steady_clock::now();
    share_tell_next(url);
    arm_sweep();
}

void storage_run::share_tell_next(const std::string& url)
{
    auto it = m_hooks.find(url);
    if (it == m_hooks.end() || it->second->peer->busy() || it->second->queue.empty())
        return;
    hook_peer& h = *it->second;
    const http_target& t = h.peer->target();
    http_request req;
    req.body = std::move(h.queue.front());
    h.queue.pop_front();
    req.head = "POST " + (t.path.empty() ? std::string("/") : t.path) + " HTTP/1.1\r\nHost: " + t.authority() +
               "\r\nUser-Agent: socketley\r\nContent-Type: application/json\r\nContent-Length: " +
               std::to_string(req.body.size()) + "\r\n\r\n";
    h.peer->exchange(std::move(req), [this, url](http_answer a)
    {
        if (a.status < 200 || a.status >= 300)
            LOG_WARN(("storage: a link's webhook answered " + std::to_string(a.status) +
                      (a.failure.empty() ? std::string{} : " (" + a.failure + ")")).c_str());
        share_tell_next(url);
    });
}

}   // namespace socketley::storage
