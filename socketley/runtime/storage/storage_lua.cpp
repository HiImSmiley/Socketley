// What a script does in a storage runtime: on_request decides whether a request
// goes on, and on_put and on_delete are told what was committed.
//
// All three run on a coroutine, so a hook that asks another runtime something
// -- another storage runtime through socketley.storage, say -- stops itself and
// the loop goes on serving; the connection whose request it holds is not read
// from until it answers.
#include "storage_run.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "s3_xml.h"
#include "storage_instance.h"
#include "../../shared/logging.h"

#ifndef SOCKETLEY_NO_LUA
#include "../../shared/lua_context.h"
#include "../../shared/lua_suspend.h"
#endif

namespace socketley::storage
{

namespace
{

[[maybe_unused]] std::string peer_of(int fd)
{
    struct sockaddr_storage ss{};
    socklen_t len = sizeof(ss);
    if (fd < 0 || ::getpeername(fd, reinterpret_cast<struct sockaddr*>(&ss), &len) != 0)
        return {};
    char host[INET6_ADDRSTRLEN] = {};
    if (ss.ss_family == AF_INET)
    {
        const auto* a = reinterpret_cast<const struct sockaddr_in*>(&ss);
        ::inet_ntop(AF_INET, &a->sin_addr, host, sizeof(host));
        return std::string(host) + ":" + std::to_string(ntohs(a->sin_port));
    }
    if (ss.ss_family == AF_INET6)
    {
        const auto* a = reinterpret_cast<const struct sockaddr_in6*>(&ss);
        ::inet_ntop(AF_INET6, &a->sin6_addr, host, sizeof(host));
        return "[" + std::string(host) + "]:" + std::to_string(ntohs(a->sin6_port));
    }
    return "unix";
}

}   // namespace

std::string_view storage_run::operation_name(const s3_request& r)
{
    const bool service = r.bucket.empty();
    const bool bucket_level = !service && r.key.empty();
    const std::string_view m = r.method;
    if (service)
        return m == "GET" ? "ListBuckets" : "Unknown";
    if (r.has_query("acl"))
        return bucket_level ? (m == "GET" ? "GetBucketAcl" : "PutBucketAcl") : (m == "GET" ? "GetObjectAcl" : "PutObjectAcl");
    if (bucket_level && r.has_query("ownershipControls"))
        return m == "GET" ? "GetBucketOwnershipControls" : "PutBucketOwnershipControls";
    if (bucket_level && r.has_query("cors"))
        return m == "GET" ? "GetBucketCors" : m == "PUT" ? "PutBucketCors" : m == "DELETE" ? "DeleteBucketCors" : "Unknown";
    if (bucket_level && r.has_query("policyStatus"))
        return m == "GET" ? "GetBucketPolicyStatus" : "Unknown";
    if (bucket_level && r.has_query("policy"))
        return m == "GET" ? "GetBucketPolicy" : m == "PUT" ? "PutBucketPolicy" : m == "DELETE" ? "DeleteBucketPolicy" : "Unknown";
    if (bucket_level && r.has_query("versioning"))
        return m == "GET" ? "GetBucketVersioning" : m == "PUT" ? "PutBucketVersioning" : "Unknown";
    if (bucket_level && r.has_query("versions"))
        return m == "GET" ? "ListObjectVersions" : "Unknown";
    if (bucket_level && r.has_query("encryption"))
        return m == "GET" ? "GetBucketEncryption" : m == "PUT" ? "PutBucketEncryption"
             : m == "DELETE" ? "DeleteBucketEncryption" : "Unknown";
    if (bucket_level && r.has_query("lifecycle"))
        return m == "GET" ? "GetBucketLifecycleConfiguration" : m == "PUT" ? "PutBucketLifecycleConfiguration"
             : m == "DELETE" ? "DeleteBucketLifecycle" : "Unknown";
    if (bucket_level)
    {
        if (m == "GET")
            return r.has_query("uploads") ? "ListMultipartUploads"
                 : r.has_query("location") ? "GetBucketLocation"
                 : r.get_query("list-type") == "2" ? "ListObjectsV2" : "ListObjects";
        if (m == "PUT")
            return "CreateBucket";
        if (m == "DELETE")
            return "DeleteBucket";
        if (m == "HEAD")
            return "HeadBucket";
        if (m == "POST" && r.has_query("delete"))
            return "DeleteObjects";
        return "Unknown";
    }
    if (r.has_query("tagging"))
        return m == "GET" ? "GetObjectTagging" : m == "PUT" ? "PutObjectTagging"
             : m == "DELETE" ? "DeleteObjectTagging" : "Unknown";
    const bool upload = r.has_query("uploadId");
    if (m == "GET")
        return upload ? "ListParts" : r.has_query("attributes") ? "GetObjectAttributes" : "GetObject";
    if (m == "HEAD")
        return "HeadObject";
    if (m == "PUT")
    {
        if (upload && r.has_query("partNumber"))
            return r.has_header("x-amz-copy-source") ? "UploadPartCopy" : "UploadPart";
        return r.has_header("x-amz-copy-source") ? "CopyObject" : "PutObject";
    }
    if (m == "DELETE")
        return upload ? "AbortMultipartUpload" : "DeleteObject";
    if (m == "POST")
    {
        if (r.has_query("uploads"))
            return "CreateMultipartUpload";
        if (upload)
            return "CompleteMultipartUpload";
    }
    return "Unknown";
}

#ifndef SOCKETLEY_NO_LUA

namespace
{

void set_info(sol::state& L, sol::table& t, const storage_rpc::object_info& i)
{
    t["size"]         = static_cast<double>(i.size);
    t["etag"]         = i.etag;
    t["content_type"] = i.content_type;
    t["mtime_ms"]     = static_cast<double>(i.mtime_ms);
    sol::table md = L.create_table();
    for (const auto& [k, v] : i.metadata)
        md[k] = v;
    t["metadata"] = md;
}

// What on_request returned, as the refusal it amounts to or none.  A raise is a
// refusal that says so, because a hook whose failure lets requests through is
// the same defect as one that was never there.
bool read_verdict(lua_State* th, int n, const char* error, std::string_view name, s3_error& deny)
{
    if (error)
    {
        // Already said by the suspender, with the callback's name on it.
        deny = make_error("InternalError");
        return true;
    }
    if (n == 0 || lua_type(th, 1) == LUA_TNIL)
        return false;
    switch (lua_type(th, 1))
    {
        case LUA_TBOOLEAN:
            if (lua_toboolean(th, 1))
                return false;
            deny = make_error("AccessDenied");
            return true;
        case LUA_TSTRING:
        {
            size_t len = 0;
            const char* p = lua_tolstring(th, 1, &len);
            deny = make_error(std::string_view(p, len));
            // A code this runtime has no status for is still a refusal, and a
            // client refused is not told the server broke.
            if (deny.status == 500 && deny.code != "InternalError")
                deny.status = 403;
            return true;
        }
        case LUA_TTABLE:
        {
            std::string code = "AccessDenied";
            std::string message;
            int status = 0;
            lua_getfield(th, 1, "deny");
            if (lua_type(th, -1) == LUA_TSTRING)
                code.assign(lua_tostring(th, -1));
            lua_pop(th, 1);
            lua_getfield(th, 1, "message");
            if (lua_type(th, -1) == LUA_TSTRING)
                message.assign(lua_tostring(th, -1));
            lua_pop(th, 1);
            lua_getfield(th, 1, "status");
            if (lua_type(th, -1) == LUA_TNUMBER)
                status = static_cast<int>(lua_tointeger(th, -1));
            lua_pop(th, 1);
            deny = make_error(code);
            if (deny.status == 500 && deny.code != "InternalError")
                deny.status = 403;
            if (!message.empty())
                deny.message = message;
            if (status >= 400 && status <= 599)
                deny.status = status;
            return true;
        }
        default:
            break;
    }
    std::cerr << lua_diag::tag(name) << " on_request returned a "
              << lua_typename(th, lua_type(th, 1))
              << "; return nothing or true to allow, false or an S3 error code to refuse"
              << " -- the request is refused\n";
    deny = make_error("InternalError");
    return true;
}

}   // namespace

void storage_run::hook_request(const std::shared_ptr<conn>& c)
{
    lua_context* lua = m_owner.lua();
    if (!lua || !lua->has_on_request())
    {
        route(c);
        return;
    }

    s3_request& r = c->req;
    sol::state& L = lua->state();
    sol::table req = L.create_table(0, 14);
    req["method"]      = r.method;
    req["operation"]   = std::string(operation_name(r));
    req["bucket"]      = r.bucket;
    req["key"]         = r.key;
    req["path"]        = r.raw_path;
    req["query"]       = r.raw_query;
    req["host"]        = r.host;
    req["request_id"]  = r.request_id;
    req["principal"]   = c->principal;
    req["tls"]         = c->ssl != nullptr;
    if (c->peer.empty())
        c->peer = peer_of(c->fd);
    req["client"]      = c->peer;
    if (r.has_content_length)
        req["content_length"] = static_cast<double>(r.content_length);
    sol::table headers = L.create_table(0, static_cast<int>(r.headers.size()));
    for (const auto& [k, v] : r.headers)
        headers[k] = v;
    req["headers"] = headers;

    c->ph = phase::hook_wait;
    const uint64_t id = c->id;
    const std::string name(m_owner.get_name());
    auto& sus = lua->suspender();
    sus.set_next_result([this, id, name](lua_State* th, int n, const char* error)
    {
        s3_error deny;
        const bool refuse = read_verdict(th, n, error, name, deny);
        hook_done(id, refuse ? &deny : nullptr);
    });
    lua_suspender::id_t sid = 0;
    sus.start(lua->raw_on_request(), "on_request", lua->callback_timeout_ms(), sid, req);
}

void storage_run::hook_done(uint64_t id, const s3_error* deny)
{
    auto c = find(id);
    if (!c || c->dead || c->ph != phase::hook_wait)
        return;
    c->last_progress = std::chrono::steady_clock::now();
    if (deny)
    {
        // The body of a refused request is not read, so the connection cannot be reused.
        c->req.keep_alive = false;
        send_error(c, *deny, true);
        return;
    }
    route(c);
}

void storage_run::notify_put(std::string_view bucket, std::string_view key, const object_meta& m)
{
    lua_context* lua = m_owner.lua();
    if (!lua || !lua->has_on_put() || m_stopped)
        return;
    sol::state& L = lua->state();
    sol::table t = L.create_table(0, 5);
    set_info(L, t, rpc_info_of(m));
    lua_suspender::id_t id = 0;
    lua->suspender().start(lua->raw_on_put(), "on_put", lua->callback_timeout_ms(), id,
                           std::string(bucket), std::string(key), t);
}

void storage_run::notify_delete(std::string_view bucket, std::string_view key)
{
    lua_context* lua = m_owner.lua();
    if (!lua || !lua->has_on_delete() || m_stopped)
        return;
    lua_suspender::id_t id = 0;
    lua->suspender().start(lua->raw_on_delete(), "on_delete", lua->callback_timeout_ms(), id,
                           std::string(bucket), std::string(key));
}

#else   // SOCKETLEY_NO_LUA

void storage_run::hook_request(const std::shared_ptr<conn>& c) { route(c); }
void storage_run::hook_done(uint64_t, const s3_error*) {}
void storage_run::notify_put(std::string_view, std::string_view, const object_meta&) {}
void storage_run::notify_delete(std::string_view, std::string_view) {}

#endif

}   // namespace socketley::storage
