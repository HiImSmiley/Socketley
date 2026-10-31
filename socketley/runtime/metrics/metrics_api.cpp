// The Prometheus HTTP API of a metrics runtime, as Grafana's Prometheus data source calls it, and the same answers as
// lines for the CLI.
#include "metrics_run.h"

#include <algorithm>
#include <charconv>
#include <cmath>

#include "metrics_instance.h"
#include "metrics_promql.h"
#include "metrics_time.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/runtime/metric_catalog.h"
#include "../../shared/runtime/metric_text.h"
#include "../../shared/util/version.h"
#include "../../shared/util/wall_clock.h"

namespace socketley::metrics
{

namespace
{

// The version Grafana is told, a Prometheus whose API this one answers.
constexpr std::string_view prometheus_version = "2.53.0";
// What a time left out stands for in /series and /labels: everything the store holds.
constexpr int64_t min_time = INT64_MIN / 4;
constexpr int64_t max_time = INT64_MAX / 4;

void fail(api_reply& out, bool text, int status, std::string_view type, std::string_view msg)
{
    out.status = status;
    if (text)
    {
        out.type = "text/plain; charset=utf-8";
        out.body.assign(msg);
        out.body += '\n';
        return;
    }
    out.body = "{\"status\":\"error\",\"errorType\":";
    json::quote_into(out.body, type);
    out.body += ",\"error\":";
    json::quote_into(out.body, msg);
    out.body += '}';
}

void success(api_reply& out, std::string_view data)
{
    out.status = 200;
    out.body.reserve(data.size() + 32);
    out.body = "{\"status\":\"success\",\"data\":";
    out.body += data;
    out.body += '}';
}

int status_of(const std::string& type)
{
    if (type == "bad_data")
        return 400;
    if (type == "timeout" || type == "canceled")
        return 503;
    return 422;
}

// A step or a timeout: seconds with a fraction, or a Prometheus duration.
bool parse_step(std::string_view s, int64_t& ms)
{
    double d = 0;
    if (const auto r = std::from_chars(s.data(), s.data() + s.size(), d);
        r.ec == std::errc() && r.ptr == s.data() + s.size())
    {
        if (!std::isfinite(d) || d > 9.0e12)
            return false;
        ms = static_cast<int64_t>(std::llround(d * 1000.0));
        return true;
    }
    return parse_duration(s, ms);
}

// `name{a="b",...}` as PromQL writes a series.
void series_text(const label_set& ls, std::string& out)
{
    out += label_value(ls, name_label);
    bool first = true;
    for (const auto& l : ls)
    {
        if (l.name == name_label)
            continue;
        out += first ? "{" : ",";
        first = false;
        out += l.name;
        out += "=\"";
        socketley::metric_text::label_escape_into(out, l.value);
        out += '"';
    }
    if (!first)
        out += '}';
    else if (label_value(ls, name_label).empty())
        out += "{}";
}

void labels_json(const label_set& ls, std::string& out)
{
    out += '{';
    bool first = true;
    for (const auto& l : ls)
    {
        out += first ? "" : ",";
        first = false;
        json::quote_into(out, l.name);
        out += ':';
        json::quote_into(out, l.value);
    }
    out += '}';
}

void strings_json(const std::vector<std::string>& v, std::string& out)
{
    out += '[';
    for (size_t i = 0; i < v.size(); ++i)
    {
        if (i)
            out += ',';
        json::quote_into(out, v[i]);
    }
    out += ']';
}

void result_text(const query_result& r, std::string& out)
{
    switch (r.kind)
    {
        case result_kind::scalar:
            format_value(r.scalar, out);
            out += '\n';
            return;
        case result_kind::string:
            out += r.str;
            out += '\n';
            return;
        case result_kind::vector:
            for (const auto& s : r.series)
            {
                series_text(s.labels, out);
                out += ' ';
                format_value(s.points.empty() ? 0 : s.points[0].v, out);
                out += '\n';
            }
            return;
        case result_kind::matrix:
            for (const auto& s : r.series)
            {
                series_text(s.labels, out);
                out += '\n';
                for (const auto& p : s.points)
                {
                    out += "  ";
                    out += format_rfc3339(p.t);
                    out += "  ";
                    format_value(p.v, out);
                    out += '\n';
                }
            }
            return;
    }
}

}   // namespace

void metrics_run::api(std::string_view path, const api_params& p, api_reply& out, bool text)
{
    if (path == "/api/v1/query" || path == "/api/v1/query_range")
        return api_query(p, out, text, path == "/api/v1/query_range");
    if (path == "/api/v1/series")
        return api_series(p, out, text);
    if (path == "/api/v1/labels")
        return api_labels(p, out, {});
    if (path.starts_with("/api/v1/label/") && path.ends_with("/values") && path.size() > 21)
        return api_labels(p, out, path.substr(14, path.size() - 21));
    if (path == "/api/v1/metadata")
        return api_metadata(p, out);
    if (path == "/api/v1/targets")
        return api_targets(out, text);
    if (path == "/api/v1/status/store")
        return api_stats(out, text);
    if (path == "/metrics")
        return self_metrics(out);
    if (path == "/api/v1/status/buildinfo")
    {
        std::string d = "{\"version\":\"";
        d += prometheus_version;
        d += "\",\"revision\":\"socketley " SOCKETLEY_VERSION "\",\"branch\":\"socketley\",\"buildUser\":\"socketley\","
             "\"buildDate\":\"\",\"goVersion\":\"none\"}";
        return success(out, d);
    }
    if (path == "/api/v1/status/runtimeinfo")
    {
        std::string d = "{\"startTime\":";
        json::quote_into(d, format_rfc3339(m_started_ms));
        d += ",\"CWD\":\"/\",\"reloadConfigSuccess\":true,\"lastConfigTime\":";
        json::quote_into(d, format_rfc3339(m_started_ms));
        d += ",\"corruptionCount\":0,\"goroutineCount\":1,\"GOMAXPROCS\":1,\"GOMEMLIMIT\":0,\"GOGC\":\"\","
             "\"GODEBUG\":\"\",\"storageRetention\":";
        json::quote_into(d, format_duration_ms(static_cast<int64_t>(m_owner.get_keep()) * 1000));
        d += '}';
        return success(out, d);
    }
    if (path == "/api/v1/status/flags")
        return success(out, "{}");
    if (path == "/api/v1/query_exemplars")
        return success(out, "[]");
    if (path.starts_with("/loki/api/v1/"))
        return api_logs(path, p, out, text);
    if (path == "/-/checkpoint")
    {
        std::string_view h;
        int64_t secs = 0;
        if (p.get("hold", h))
            std::from_chars(h.data(), h.data() + h.size(), secs);
        const int64_t now = wall::now_ms_coarse();
        m_store.checkpoint(secs > 0 ? now + std::min<int64_t>(secs, 3600) * 1000 : INT64_MIN);
        m_store_due = now;
        out.body = secs > 0 ? "written, maintenance held for " + std::to_string(std::min<int64_t>(secs, 3600)) + "s\n"
                            : "written\n";
        out.type = "text/plain; charset=utf-8";
        return;
    }
    if (path == "/api/v1/rules")
    {
        rules_filter f;
        if (std::string_view t; p.get("type", t))
        {
            if (t != "alert" && t != "record")
                return fail(out, text, 400, "bad_data", "type is alert or record");
            f.alerts = t == "alert";
            f.records = t == "record";
        }
        if (std::string_view x; p.get("exclude_alerts", x))
            f.exclude_alerts = x == "true" || x == "1";
        std::string d;
        if (text)
        {
            if (m_rules)
                m_rules->render_rules_text(d);
            out.body = std::move(d);
            out.type = "text/plain; charset=utf-8";
            return;
        }
        if (m_rules)
            m_rules->render_rules(d, f);
        else
            d = "{\"groups\":[]}";
        return success(out, d);
    }
    if (path == "/api/v1/alerts")
    {
        std::string d;
        // socketley's own shape, the firing alerts and the notifications of late, for the dashboard and `alerts --recent`.
        if (std::string_view r; p.get("recent", r) && r == "1")
        {
            dashboard_alerts(d);
            out.body = std::move(d);
            return;
        }
        if (text)
        {
            if (m_rules)
                m_rules->render_alerts_text(d);
            out.body = std::move(d);
            out.type = "text/plain";
            return;
        }
        if (m_rules)
            m_rules->render_alerts(d);
        else
            d = "{\"alerts\":[]}";
        return success(out, d);
    }
    fail(out, text, 404, "not_found", "no such API: " + std::string(path));
}

void metrics_run::api_query(const api_params& p, api_reply& out, bool text, bool range)
{
    std::string_view q;
    if (!p.get("query", q) || q.empty())
        return fail(out, text, 400, "bad_data", "invalid parameter \"query\": no query given");
    ++m_c.queries;
    query_result r;
    query_error err;
    bool ok = false;
    std::string_view v;
    if (!range)
    {
        int64_t t = wall::now_ms();
        if (p.get("time", v) && !v.empty() && !parse_api_time(v, t))
            return fail(out, text, 400, "bad_data", "invalid parameter \"time\": cannot parse \"" + std::string(v) +
                                                        "\" to a valid timestamp");
        ok = m_engine.eval_instant(q, t, r, err);
    }
    else
    {
        int64_t start = 0, end = 0, step = 0;
        for (const auto& [name, at] : {std::pair{"start", &start}, {"end", &end}})
            if (!p.get(name, v) || !parse_api_time(v, *at))
                return fail(out, text, 400, "bad_data", "invalid parameter \"" + std::string(name) +
                                                            "\": cannot parse \"" + std::string(v) +
                                                            "\" to a valid timestamp");
        if (end < start)
            return fail(out, text, 400, "bad_data", "invalid parameter \"end\": end timestamp must not be before "
                                                    "start time");
        if (!p.get("step", v) || !parse_step(v, step))
            return fail(out, text, 400, "bad_data", "invalid parameter \"step\": cannot parse \"" + std::string(v) +
                                                        "\" to a valid duration");
        if (step <= 0)
            return fail(out, text, 400, "bad_data", "zero or negative query resolution step widths are not accepted. "
                                                    "Try a positive integer");
        if ((end - start) / step > m_engine.limits().max_points_per_series)
            return fail(out, text, 400, "bad_data", "exceeded maximum resolution of 11,000 points per timeseries. "
                                                    "Try decreasing the query resolution (?step=XX)");
        ok = m_engine.eval_range(q, start, end, step, r, err);
    }
    if (!ok)
        return fail(out, text, status_of(err.type), err.type.empty() ? "execution" : err.type, err.message);
    if (text)
    {
        out.status = 200;
        out.type = "text/plain; charset=utf-8";
        result_text(r, out.body);
        return;
    }
    std::string d;
    render_json(r, d);
    success(out, d);
}

namespace
{

// A Loki time: nanoseconds as an integer, or seconds and RFC 3339 as Prometheus takes them.
bool loki_time(std::string_view s, int64_t& ms)
{
    int64_t n = 0;
    const auto r = std::from_chars(s.data(), s.data() + s.size(), n);
    if (r.ec == std::errc() && r.ptr == s.data() + s.size() && s.size() >= 16)
        return ms = n / 1'000'000, true;
    return parse_api_time(s, ms);
}

}   // namespace

void metrics_run::api_logs(std::string_view path, const api_params& p, api_reply& out, bool text)
{
    if (!m_logs.is_open())
        return fail(out, text, 404, "not_found", "this metrics runtime keeps no logs: --logs");
    m_logs.flush();
    const int64_t now = wall::now_ms();
    std::string_view v;
    int64_t start = now - 3'600'000, end = now;
    if (p.get("start", v) && !v.empty() && !loki_time(v, start))
        return fail(out, text, 400, "bad_data", "invalid start: " + std::string(v));
    if (p.get("end", v) && !v.empty() && !loki_time(v, end))
        return fail(out, text, 400, "bad_data", "invalid end: " + std::string(v));
    if (p.get("since", v) && !v.empty())
    {
        int64_t d = 0;
        if (!parse_duration(v, d))
            return fail(out, text, 400, "bad_data", "invalid since: " + std::string(v));
        start = end - d;
    }
    const std::string_view inst = m_local.instance();
    std::string d;
    if (path == "/loki/api/v1/labels")
    {
        log_label_names(m_logs, inst, start, end, d);
        return success(out, d);
    }
    if (path.starts_with("/loki/api/v1/label/") && path.ends_with("/values"))
    {
        const std::string_view name = path.substr(19, path.size() - 19 - 7);
        log_label_values(m_logs, inst, name, start, end, d);
        return success(out, d);
    }
    const bool range = path == "/loki/api/v1/query_range";
    if (!range && path != "/loki/api/v1/query")
        return fail(out, text, 404, "not_found", "no such API: " + std::string(path));
    std::string_view q;
    if (!p.get("query", q) || q.empty())
        return fail(out, text, 400, "bad_data", "query is required");
    size_t limit = 100;
    if (p.get("limit", v) && !v.empty())
    {
        uint64_t n = 0;
        if (std::from_chars(v.data(), v.data() + v.size(), n).ec != std::errc() || n == 0)
            return fail(out, text, 400, "bad_data", "invalid limit: " + std::string(v));
        limit = static_cast<size_t>(std::min<uint64_t>(n, 50'000));
    }
    const bool backward = !(p.get("direction", v) && v == "forward");
    logql lq;
    bool is_log = true;
    std::string why;
    if (!parse_logql(q, lq, is_log, why))
        return fail(out, text, 400, "bad_data", why);
    // Without a selector it is PromQL, which the metrics engine answers, as Grafana's check `vector(1)+vector(1)`.
    if (!is_log)
    {
        api_params pp = p;
        return api_query(pp, out, text, range);
    }
    if (range)
    {
        int64_t step = std::max<int64_t>(1000, (end - start) / 250);
        if (p.get("step", v) && !v.empty())
        {
            double secs = 0;
            int64_t dms = 0;
            if (parse_duration(v, dms))
                step = dms;
            else if (std::from_chars(v.data(), v.data() + v.size(), secs).ec == std::errc() && secs > 0)
                step = static_cast<int64_t>(secs * 1000);
            else
                return fail(out, text, 400, "bad_data", "invalid step: " + std::string(v));
        }
        if (end < start || (end - start) / std::max<int64_t>(step, 1) > 11'000)
            return fail(out, text, 400, "bad_data", "the range holds more than 11000 steps");
        logql_range(m_logs, lq, inst, start, end, step, limit, backward, d);
    }
    else
    {
        int64_t t = now;
        if (p.get("time", v) && !v.empty() && !loki_time(v, t))
            return fail(out, text, 400, "bad_data", "invalid time: " + std::string(v));
        logql_instant(m_logs, lq, inst, t, limit, d);
    }
    if (!text)
        return success(out, d);
    // For the CLI, a line a log line, oldest first, as the daemon wrote it.
    if (!lq.fn.empty())
    {
        out.body = d;
        out.type = "application/json";
        return;
    }
    label_set ls;
    std::vector<std::string> rows;
    m_logs.scan(start, end, true, [&](const log_view& l) {
        log_labels(l, inst, ls);
        if (logql_matches(lq, ls, l.text))
            rows.emplace_back(std::string(l.text));
        return rows.size() < limit;
    });
    std::string body;
    for (size_t i = rows.size(); i-- > 0;)
        body += rows[i] + "\n";
    out.body = std::move(body);
    out.type = "text/plain; charset=utf-8";
}

bool metrics_run::time_range(const api_params& p, int64_t& mint, int64_t& maxt, api_reply& out)
{
    mint = min_time;
    maxt = max_time;
    std::string_view v;
    if (p.get("start", v) && !v.empty() && !parse_api_time(v, mint))
    {
        fail(out, false, 400, "bad_data", "invalid parameter \"start\": cannot parse \"" + std::string(v) +
                                               "\" to a valid timestamp");
        return false;
    }
    if (p.get("end", v) && !v.empty() && !parse_api_time(v, maxt))
    {
        fail(out, false, 400, "bad_data", "invalid parameter \"end\": cannot parse \"" + std::string(v) +
                                               "\" to a valid timestamp");
        return false;
    }
    return true;
}

bool metrics_run::matched(const api_params& p, int64_t mint, int64_t maxt, std::vector<uint32_t>& ids,
                          api_reply& out, bool& any)
{
    std::vector<std::string_view> sels;
    p.all("match[]", sels);
    any = !sels.empty();
    std::vector<uint32_t> one;
    for (const std::string_view sel : sels)
    {
        std::unique_ptr<expr_node> e;
        query_error err;
        if (!parse_promql(sel, m_engine.limits().max_query_length, e, err))
        {
            fail(out, false, 400, "bad_data", "invalid parameter \"match[]\": " + err.message);
            return false;
        }
        if (e->k != expr_node::kind::vector_sel)
        {
            fail(out, false, 400, "bad_data", "invalid parameter \"match[]\": " + std::string(sel) +
                                                   " is no series selector");
            return false;
        }
        one.clear();
        m_store.select(e->matchers, mint, maxt, one);
        ids.insert(ids.end(), one.begin(), one.end());
    }
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    return true;
}

void metrics_run::api_series(const api_params& p, api_reply& out, bool text)
{
    int64_t mint = 0, maxt = 0;
    if (!time_range(p, mint, maxt, out))
        return;
    std::vector<uint32_t> ids;
    bool any = false;
    if (!matched(p, mint, maxt, ids, out, any))
        return;
    if (!any)
        return fail(out, text, 400, "bad_data", "no match[] parameter provided");
    std::string_view v;
    size_t limit = SIZE_MAX;
    if (p.get("limit", v) && !v.empty())
        if (const auto r = std::from_chars(v.data(), v.data() + v.size(), limit); r.ec != std::errc() || limit == 0)
            limit = SIZE_MAX;
    if (ids.size() > limit)
        ids.resize(limit);
    if (text)
    {
        out.status = 200;
        out.type = "text/plain; charset=utf-8";
        for (const uint32_t id : ids)
        {
            series_text(m_store.labels(id), out.body);
            out.body += '\n';
        }
        return;
    }
    std::string d = "[";
    for (size_t i = 0; i < ids.size(); ++i)
    {
        if (i)
            d += ',';
        labels_json(m_store.labels(ids[i]), d);
    }
    d += ']';
    success(out, d);
}

void metrics_run::api_labels(const api_params& p, api_reply& out, std::string_view name)
{
    int64_t mint = 0, maxt = 0;
    if (!time_range(p, mint, maxt, out))
        return;
    std::vector<uint32_t> ids;
    bool any = false;
    if (!matched(p, mint, maxt, ids, out, any))
        return;
    std::vector<std::string> v;
    if (!any)
    {
        if (name.empty())
            m_store.label_names(v);
        else
            m_store.label_values(name, v);
    }
    else
        for (const uint32_t id : ids)
            for (const auto& l : m_store.labels(id))
                if (name.empty())
                    v.push_back(l.name);
                else if (l.name == name)
                    v.push_back(l.value);
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());
    std::string d;
    strings_json(v, d);
    success(out, d);
}

void metrics_run::api_metadata(const api_params& p, api_reply& out)
{
    std::vector<std::string> names;
    std::string_view only, v;
    if (p.get("metric", only) && !only.empty())
        names.emplace_back(only);
    else
        m_store.label_values(name_label, names);
    size_t limit = SIZE_MAX;
    if (p.get("limit", v) && !v.empty())
        if (const auto r = std::from_chars(v.data(), v.data() + v.size(), limit); r.ec != std::errc() || limit == 0)
            limit = SIZE_MAX;
    static constexpr std::string_view types[] = {"unknown", "counter", "gauge", "histogram", "summary"};
    std::string d = "{";
    size_t n = 0;
    for (const auto& name : names)
    {
        if (n == limit)
            break;
        const metric_type t = m_store.type_of(name);
        const std::string_view help = m_store.help_of(name);
        if (t == metric_type::untyped && help.empty())
            continue;
        d += n++ ? "," : "";
        json::quote_into(d, name);
        d += ":[{\"type\":\"";
        d += types[static_cast<size_t>(t)];
        d += "\",\"help\":";
        json::quote_into(d, help);
        d += ",\"unit\":\"\"}]";
    }
    d += '}';
    success(out, d);
}

void metrics_run::api_targets(api_reply& out, bool text)
{
    const local_stats& l = m_local.stats();
    // The local feed answered within two of its intervals, or it is down.
    const bool local_up = m_owner.get_local() && l.last_ms && wall::now_ms_coarse() - l.last_ms <= 2 * m_every_ms + 5000;
    if (text)
    {
        out.status = 200;
        out.type = "text/plain; charset=utf-8";
        if (m_owner.get_local())
            out.body += "socketley\tlocal\t" + std::string(local_up ? "up" : "down") + "\tevery " +
                        format_duration_ms(m_every_ms) + "\t" + std::to_string(l.series) + " series\n";
        m_scrape.targets_text(out.body);
        return;
    }
    std::string d = "{\"activeTargets\":[";
    bool first = true;
    if (m_owner.get_local())
    {
        first = false;
        d += "{\"discoveredLabels\":{\"__address__\":\"local\",\"job\":\"socketley\"},\"labels\":{\"instance\":";
        json::quote_into(d, m_local.instance());
        d += ",\"job\":\"socketley\"},\"scrapePool\":\"socketley\",\"scrapeUrl\":\"local:\",\"globalUrl\":\"local:\","
             "\"lastError\":\"\",\"lastScrape\":";
        json::quote_into(d, l.last_ms ? format_rfc3339(l.last_ms) : std::string("0001-01-01T00:00:00Z"));
        d += ",\"lastScrapeDuration\":0,\"health\":";
        d += !l.last_ms ? "\"unknown\"" : local_up ? "\"up\"" : "\"down\"";
        d += ",\"scrapeInterval\":";
        json::quote_into(d, format_duration_ms(m_every_ms));
        d += ",\"scrapeTimeout\":";
        json::quote_into(d, format_duration_ms(m_every_ms));
        d += '}';
    }
    m_scrape.targets_json(d, first);
    d += "],\"droppedTargets\":[]}";
    success(out, d);
}

void metrics_run::api_stats(api_reply& out, bool text)
{
    const std::string s = stats();
    if (text)
    {
        out.status = 200;
        out.type = "text/plain; charset=utf-8";
        out.body = s;
        return;
    }
    std::string d = "{";
    bool first = true;
    for (std::string_view rest = s; !rest.empty();)
    {
        const size_t nl = rest.find('\n');
        const std::string_view line = rest.substr(0, nl);
        rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
        const size_t colon = line.find(':');
        if (colon == std::string_view::npos)
            continue;
        d += first ? "" : ",";
        first = false;
        json::quote_into(d, line.substr(0, colon));
        d += ':';
        d += line.substr(colon + 1);
    }
    d += '}';
    success(out, d);
}

void metrics_run::self_metrics(api_reply& out)
{
    out.status = 200;
    out.type = "text/plain; version=0.0.4; charset=utf-8";
    const auto* e = socketley::metric_catalog::entry_for(runtime_metrics);
    if (!e)
        return;
    socketley::metric_catalog::figures fig;
    fig.parse(runtime_metrics, stats());
    const socketley::metric_catalog::source src{m_owner.get_name(), &fig};
    socketley::metric_text::writer w(out.body);
    socketley::metric_catalog::emit(*e, std::span<const socketley::metric_catalog::source>(&src, 1), w);
    w.finish();
}

}   // namespace socketley::metrics
