#include "mqtt_routes.h"

#include <algorithm>

#include <charconv>
#include <ctime>

#include "mqtt_auth.h"
#include "mqtt_command.h"
#include "mqtt_topics.h"
#include "../cache/stream_log.h"
#include "../../shared/http/http_url.h"
#include "../../shared/ipc/one_command.h"
#include "../../shared/json/json_doc.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/lua/db_call.h"
#include "../../shared/storage/storage_rpc.h"
#include "../../shared/util/base64.h"
#include "../../shared/util/byte_codec.h"
#include "../../shared/util/text_list.h"

namespace socketley::mqtt
{

const char* target_kind_name(target_kind k)
{
    switch (k)
    {
        case target_kind::cache_stream:  return "cache stream";
        case target_kind::cache_channel: return "cache channel";
        case target_kind::db:            return "db";
        case target_kind::storage:       return "storage";
        case target_kind::server:        return "server";
        case target_kind::mqtt:          return "mqtt";
        case target_kind::webhook:       return "webhook";
    }
    return "?";
}

bool plus_levels(std::string_view filter, std::string_view topic, std::vector<std::string_view>& out)
{
    out.clear();
    if (!topic_matches(filter, topic))
        return false;
    const auto f = split_levels(filter);
    const auto t = split_levels(topic);
    for (size_t i = 0; i < f.size() && i < t.size(); ++i)
        if (f[i] == "+")
            out.push_back(t[i]);
    return true;
}

void payload_json(std::string& out, std::string_view payload)
{
    if (valid_utf8(payload))
        socketley::json::quote_into(out, payload);
    else
    {
        out += "{\"base64\":\"";
        out += socketley::base64::encode(payload);
        out += "\"}";
    }
}

namespace
{

// The placeholders of a rule's template filled in; a level that a name cannot hold is replaced by '_'.
std::string expand(std::string_view tpl, const message& m, const std::vector<std::string_view>& plus, bool for_id,
                   bool for_key = false)
{
    std::string out;
    for (size_t i = 0; i < tpl.size(); ++i)
    {
        if (tpl[i] != '%' || i + 1 >= tpl.size())
        {
            out += tpl[i];
            continue;
        }
        const char k = tpl[i + 1];
        std::string_view v;
        bool known = true;
        if (k >= '1' && k <= '9')
        {
            const size_t at = static_cast<size_t>(k - '1');
            v = at < plus.size() ? plus[at] : std::string_view{};
        }
        else if (k == 'c')
            v = m.from_client;
        else if (k == 't')
            v = m.topic;
        else
            known = false;
        if (!known)
        {
            out += tpl[i];
            continue;
        }
        for (const char c : v)
            out += ((for_id && (c == '/' || c == '?' || c == '#')) ||
                    (for_key && (c == ' ' || c == '\t' || c == '\r' || c == '\n')))
                       ? '_'
                       : c;
        ++i;
    }
    return out;
}

std::string expand_time(std::string_view tpl, int64_t now_ms)
{
    const time_t secs = static_cast<time_t>(now_ms / 1000);
    struct tm t{};
    gmtime_r(&secs, &t);
    std::string out;
    char buf[16];
    for (size_t i = 0; i < tpl.size(); ++i)
    {
        if (tpl[i] == '%' && i + 1 < tpl.size())
        {
            const char k = tpl[i + 1];
            int v = -1, width = 2;
            if (k == 'Y')
            {
                v = t.tm_year + 1900;
                width = 4;
            }
            else if (k == 'm')
                v = t.tm_mon + 1;
            else if (k == 'd')
                v = t.tm_mday;
            else if (k == 'H')
                v = t.tm_hour;
            else if (k == 'M')
                v = t.tm_min;
            if (v >= 0)
            {
                std::snprintf(buf, sizeof buf, "%0*d", width, v);
                out += buf;
                ++i;
                continue;
            }
        }
        out += tpl[i];
    }
    return out;
}

bool placeholders_ok(std::string_view tpl, size_t plus_count, bool allow_time, bool allow_topic, std::string& why)
{
    for (size_t i = 0; i + 1 < tpl.size(); ++i)
    {
        if (tpl[i] != '%')
            continue;
        const char k = tpl[i + 1];
        if (k >= '1' && k <= '9')
        {
            if (static_cast<size_t>(k - '0') > plus_count)
            {
                why = std::string("%") + k + " names a '+' the filter does not have";
                return false;
            }
        }
        else if (k == 't' && !allow_topic)
        {
            why = "%t holds '/', which this name cannot";
            return false;
        }
        else if ((k == 'Y' || k == 'm' || k == 'd' || k == 'H' || k == 'M') && !allow_time)
        {
            why = std::string("%") + k + " is a time, which only a storage prefix takes";
            return false;
        }
        ++i;
    }
    return true;
}

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

bool valid_runtime_name(std::string_view n)
{
    if (n.empty() || n.size() > 128)
        return false;
    for (const char c : n)
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == '#'))
            return false;
    return true;
}

}   // namespace

bool route_table::parse(std::string_view text, std::string& why)
{
    m_routes.clear();
    size_t n = 0;
    while (!text.empty())
    {
        ++n;
        std::string_view line = trim(socketley::take_item(text, '\n'));
        if (line.empty())
            continue;
        const size_t gap = line.find_first_of(" \t");
        const std::string_view filter = line.substr(0, gap);
        std::string_view rest = gap == std::string_view::npos ? std::string_view{} : trim(line.substr(gap));
        const size_t gap2 = rest.find_first_of(" \t");
        const std::string_view target = rest.substr(0, gap2);
        const auto refuse = [&](const std::string& what) {
            why = "line " + std::to_string(n) + ": " + what;
            return false;
        };
        // A comment: a '#' that no target follows.
        if (filter.front() == '#' && target.find("://") == std::string_view::npos)
            continue;
        if (gap2 != std::string_view::npos)
        {
            const std::string_view after = trim(rest.substr(gap2));
            if (!after.empty() && after.front() != '#')
                return refuse("`" + std::string(after) + "` follows the target");
        }
        if (target.empty())
            return refuse("`" + std::string(filter) + "` has no target");
        if (!valid_filter(filter) || filter.starts_with("$share/"))
            return refuse("`" + std::string(filter) + "` is not a topic filter");
        size_t plus_count = 0;
        for (const auto l : split_levels(filter))
            plus_count += l == "+";

        route r;
        r.filter = std::string(filter);
        r.text   = std::string(filter) + " " + std::string(target);
        const size_t scheme_end = target.find("://");
        if (scheme_end == std::string_view::npos)
            return refuse("`" + std::string(target) + "` is not cache://, db://, storage://, server://, mqtt:// or a URL");
        const std::string_view scheme = target.substr(0, scheme_end);
        // A webhook names a host and not a runtime: the message is POSTed to it as JSON.
        if (scheme == "http" || scheme == "https")
        {
            socketley::http_target t;
            std::string problem;
            if (!socketley::parse_http_url(target, t, problem))
                return refuse(problem);
            r.kind = target_kind::webhook;
            r.name = std::string(target);
            m_routes.push_back(std::move(r));
            continue;
        }
        std::string_view path = target.substr(scheme_end + 3);
        const std::string_view runtime = socketley::take_item(path, '/');
        if (!valid_runtime_name(runtime))
            return refuse("`" + std::string(runtime) + "` is not a runtime name");
        r.runtime = std::string(runtime);
        std::string problem;
        if (scheme == "cache")
        {
            const std::string_view kind = socketley::take_item(path, '/');
            if ((kind != "stream" && kind != "channel") || path.empty())
                return refuse("a cache target is cache://<runtime>/stream/<key> or cache://<runtime>/channel/<name>");
            r.kind = kind == "stream" ? target_kind::cache_stream : target_kind::cache_channel;
            r.name = std::string(path);
            if (r.name.find_first_of(" \t") != std::string::npos)
                return refuse("a cache key holds no space");
            if (!placeholders_ok(r.name, plus_count, false, true, problem))
                return refuse(problem);
        }
        else if (scheme == "db")
        {
            const std::string_view coll = socketley::take_item(path, '/');
            if (coll.empty() || path.find('/') != std::string_view::npos)
                return refuse("a db target is db://<runtime>/<collection>[/<id>]");
            r.kind   = target_kind::db;
            r.name   = std::string(coll);
            r.detail = std::string(path);
            if (r.name.find("%c") != std::string::npos)
                return refuse("%c is not put into a collection name");
            if (!placeholders_ok(r.name, 0, false, false, problem) ||
                !placeholders_ok(r.detail, plus_count, false, false, problem))
                return refuse(problem);
        }
        else if (scheme == "storage")
        {
            const std::string_view bucket = socketley::take_item(path, '/');
            if (bucket.empty())
                return refuse("a storage target is storage://<runtime>/<bucket>[/<prefix>]");
            r.kind   = target_kind::storage;
            r.name   = std::string(bucket);
            r.detail = std::string(path);
            if (!r.detail.empty() && r.detail.back() != '/')
                r.detail += '/';
            if (r.name.find("%c") != std::string::npos || r.detail.find("%c") != std::string::npos)
                return refuse("%c is not put into a storage object, which holds the messages of many clients");
            if (!placeholders_ok(r.name, 0, false, false, problem) || !placeholders_ok(r.detail, 0, true, false, problem))
                return refuse(problem);
        }
        else if (scheme == "server")
        {
            if (!path.empty())
                return refuse("a server target is server://<runtime>");
            r.kind = target_kind::server;
        }
        else if (scheme == "mqtt")
        {
            if (path.empty())
                return refuse("an mqtt target is mqtt://<runtime>/<topic>");
            r.kind = target_kind::mqtt;
            r.name = std::string(path);
            if (!placeholders_ok(r.name, plus_count, false, true, problem))
                return refuse(problem);
        }
        else
            return refuse("`" + std::string(scheme) + "://` is not cache://, db://, storage://, server://, mqtt:// or "
                          "http(s)://");
        m_routes.push_back(std::move(r));
    }
    return true;
}

std::string route_table::request_for(const route& r, const message& m, const std::vector<std::string_view>& plus)
{
    switch (r.kind)
    {
        case target_kind::cache_stream:
        {
            const std::string key = expand(r.name, m, plus, false, true);
            const std::string qos = std::to_string(m.qos);
            const std::string_view args[] = {"xadd", key, "*", "topic", m.topic, "payload", m.payload,
                                             "qos", qos, "client", m.from_client};
            std::string cmd(socketley::one_command_marker);
            cmd += "xapply " + key + " ";
            stream_args_encode(cmd, args, std::size(args));
            return cmd;
        }
        case target_kind::cache_channel:
        {
            std::string cmd(socketley::one_command_marker);
            cmd += "publish " + expand(r.name, m, plus, false, true) + " ";
            cmd += m.payload;
            return cmd;
        }
        case target_kind::db:
        {
            std::string body;
            socketley::json::jvalue v;
            if (socketley::json::json_reader(m.payload).document(v))
                body = m.payload;
            else
            {
                body = "{\"topic\":";
                socketley::json::quote_into(body, m.topic);
                body += ",\"payload\":";
                payload_json(body, m.payload);
                body += ",\"client\":";
                socketley::json::quote_into(body, m.from_client);
                body += ",\"qos\":" + std::to_string(m.qos) + "}";
            }
            const std::string id = expand(r.detail, m, plus, true);
            std::string call(socketley::db::call_marker);
            call += "{\"method\":\"";
            call += id.empty() ? "POST" : "PUT";
            call += "\",\"path\":";
            socketley::json::quote_into(call, "/c/" + r.name + (id.empty() ? "" : "/" + id));
            call += ",\"body\":" + body + "}";
            return call;
        }
        case target_kind::server:
        {
            std::string line = "{\"topic\":";
            socketley::json::quote_into(line, m.topic);
            line += ",\"payload\":";
            payload_json(line, m.payload);
            line += "}";
            return line;
        }
        case target_kind::mqtt:
            return command_publish(expand(r.name, m, plus, false), m.payload, m.qos, m.retain,
                                   static_cast<uint8_t>(m.hops + 1));
        case target_kind::webhook:
        {
            std::string body = "{\"topic\":";
            socketley::json::quote_into(body, m.topic);
            body += ",\"payload\":";
            payload_json(body, m.payload);
            body += ",\"qos\":" + std::to_string(m.qos) + ",\"retain\":";
            body += m.retain ? "true" : "false";
            body += ",\"client\":";
            socketley::json::quote_into(body, m.from_client);
            body += "}";
            return body;
        }
        case target_kind::storage:
            break;
    }
    return {};
}

void route_table::offer(const message& m, int64_t now, uint32_t shard)
{
    std::vector<std::string_view> plus;
    for (auto& r : m_routes)
    {
        if (!plus_levels(r.filter, m.topic, plus))
            continue;
        if (r.kind == target_kind::mqtt && m.hops >= max_hops)
        {
            ++r.dropped;
            r.last_error = "a message reached this rule through " + std::to_string(max_hops) +
                           " mqtt:// rules and is not passed on: rules that lead back to themselves";
            continue;
        }
        if (r.kind == target_kind::storage)
        {
            if (r.batch.empty())
                r.batch_started_ms = now;
            r.batch += "{\"at\":" + std::to_string(now) + ",\"topic\":";
            socketley::json::quote_into(r.batch, m.topic);
            r.batch += ",\"payload\":";
            payload_json(r.batch, m.payload);
            r.batch += ",\"qos\":" + std::to_string(m.qos) + ",\"client\":";
            socketley::json::quote_into(r.batch, m.from_client);
            r.batch += "}\n";
            ++r.batch_lines;
            if (r.batch.size() >= batch_bytes)
                cut_batches(now, shard, false);
            continue;
        }
        r.push(request_for(r, m, plus), queue_limit);
    }
}

void route_table::cut_batches(int64_t now, uint32_t shard, bool force)
{
    for (auto& r : m_routes)
    {
        if (r.kind != target_kind::storage || r.batch.empty())
            continue;
        if (!force && r.batch.size() < batch_bytes && now - r.batch_started_ms < batch_ms)
            continue;
        const time_t secs = static_cast<time_t>(now / 1000);
        struct tm t{};
        gmtime_r(&secs, &t);
        char stamp[32];
        std::snprintf(stamp, sizeof stamp, "%02d%02d%02d", t.tm_hour, t.tm_min, t.tm_sec);
        storage_rpc::request q;
        q.kind = storage_rpc::op::put;
        q.bucket = r.name;
        q.key = expand_time(r.detail, now) + stamp + "-" + std::to_string(shard) + "-" +
                std::to_string(++r.batch_seq) + ".ndjson";
        q.data = std::move(r.batch);
        q.content_type = "application/x-ndjson";
        r.batch.clear();
        r.batch_lines = 0;
        r.push(storage_rpc::encode(q), queue_limit);
    }
}

void route::push(std::string bytes, size_t limit)
{
    // Built only when it may be said, since this runs for every message a rule takes.
    std::string full;
    if (queue.size() >= limit)
        full = "mqtt: the rule for " + filter + " holds " + std::to_string(limit) +
               " requests its target has not taken; the oldest are dropped";
    if (!gate.admit(queue.size(), 1, limit, full.c_str(), "mqtt rule request(s) were dropped"))
    {
        queue.pop_front();
        ++dropped;
    }
    queue.push_back({++next_seq, std::move(bytes)});
}

void route::back_off(int64_t now)
{
    backoff_ms  = std::min<uint32_t>(backoff_ms ? backoff_ms * 2 : 200, 5000);
    retry_at_ms = now + backoff_ms;
}

void route::put_back(route_request q)
{
    auto at = queue.begin();
    while (at != queue.end() && at->seq < q.seq)
        ++at;
    queue.insert(at, std::move(q));
}

std::string route_table::save(const std::vector<std::vector<const route_request*>>& flying) const
{
    socketley::bytes::writer w;
    w.u32(static_cast<uint32_t>(m_routes.size()));
    for (size_t i = 0; i < m_routes.size(); ++i)
    {
        const route& r = m_routes[i];
        std::vector<const route_request*> sent = i < flying.size() ? flying[i] : std::vector<const route_request*>{};
        std::sort(sent.begin(), sent.end(), [](const auto* a, const auto* b) { return a->seq < b->seq; });
        w.bytes(r.text);
        w.u32(static_cast<uint32_t>(sent.size() + r.queue.size()));
        // The two merged by number, so the file holds them in the order they were made.
        size_t k = 0;
        for (const auto& q : r.queue)
        {
            for (; k < sent.size() && sent[k]->seq < q.seq; ++k)
                w.bytes(sent[k]->bytes);
            w.bytes(q.bytes);
        }
        for (; k < sent.size(); ++k)
            w.bytes(sent[k]->bytes);
        w.bytes(r.batch);
        w.u64(r.batch_seq);
    }
    return w.take();
}

void route_table::load(std::string_view bytes)
{
    socketley::bytes::reader rd(bytes);
    uint32_t n = 0;
    if (!rd.u32(n))
        return;
    std::vector<char> restored(m_routes.size(), 0);
    for (uint32_t i = 0; i < n; ++i)
    {
        std::string text, batch;
        uint32_t count = 0;
        uint64_t seq = 0;
        if (!rd.bytes(text, 1u << 16) || !rd.u32(count) || count > queue_limit + window)
            return;
        std::deque<route_request> held;
        for (uint32_t k = 0; k < count; ++k)
        {
            route_request q;
            q.seq = k + 1;
            if (!rd.bytes(q.bytes, 64u << 20))
                return;
            held.push_back(std::move(q));
        }
        if (!rd.bytes(batch, 64u << 20) || !rd.u64(seq))
            return;
        for (size_t ri = 0; ri < m_routes.size(); ++ri)
            if (!restored[ri] && m_routes[ri].text == text)
            {
                restored[ri] = 1;
                route& r = m_routes[ri];
                r.queue = std::move(held);
                r.next_seq = r.queue.size();
                r.batch = std::move(batch);
                r.batch_seq = seq;
                if (!r.batch.empty())
                    r.batch_started_ms = 0;
                break;
            }
    }
}

reply_verdict judge_reply(target_kind k, std::string_view reply, std::string& why)
{
    switch (k)
    {
        case target_kind::cache_stream:
        case target_kind::cache_channel:
            if (reply.starts_with("error") || reply.starts_with("ERR") || reply.starts_with("-") ||
                reply.starts_with("wrong") || reply.starts_with("usage"))
            {
                why = std::string(reply.substr(0, reply.find('\n')));
                return reply_verdict::refused;
            }
            return reply_verdict::delivered;
        case target_kind::db:
        {
            socketley::json::jvalue v;
            int status = 0;
            if (socketley::json::json_reader(reply).document(v))
                if (const auto* s = socketley::json::member(v, "status"))
                    std::from_chars(s->s.data(), s->s.data() + s->s.size(), status);
            if (status >= 200 && status < 300)
                return reply_verdict::delivered;
            why = std::string(reply.substr(0, 200));
            return status >= 500 || status == 0 ? reply_verdict::retry : reply_verdict::refused;
        }
        case target_kind::storage:
        {
            storage_rpc::reply r;
            if (!storage_rpc::decode(reply, storage_rpc::op::put, r))
            {
                why = "the storage's answer does not read";
                return reply_verdict::retry;
            }
            if (r.ok)
                return reply_verdict::delivered;
            why = r.code + ": " + r.message;
            return r.code == "ServiceUnavailable" || r.code == "SlowDown" || r.code == "InternalError"
                       ? reply_verdict::retry
                       : reply_verdict::refused;
        }
        case target_kind::mqtt:
            if (reply == "ok")
                return reply_verdict::delivered;
            why = std::string(reply.substr(0, 200));
            return reply_verdict::refused;
        case target_kind::server:
            return reply_verdict::delivered;
        case target_kind::webhook:
        {
            // The status alone, as a webhook says what it has to say in it.
            int status = 0;
            std::from_chars(reply.data(), reply.data() + reply.size(), status);
            if (status >= 200 && status < 300)
                return reply_verdict::delivered;
            why = status ? "the webhook answered " + std::string(reply) : "the webhook did not answer";
            // One that is down, busy or asks for time is tried again; one that says the message is wrong is not.
            return status == 0 || status == 408 || status == 429 || status >= 500 ? reply_verdict::retry
                                                                                  : reply_verdict::refused;
        }
    }
    return reply_verdict::refused;
}

}   // namespace socketley::mqtt
