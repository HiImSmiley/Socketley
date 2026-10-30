#include "metrics_logs.h"

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstring>

#include "metrics_query.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/loop/blocking_write.h"
#include "../../shared/persist/private_dir.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/util/crc.h"
#include "../../shared/util/logging.h"

namespace socketley::metrics
{

namespace
{

constexpr int64_t a_day = 86'400'000;
constexpr size_t record_head = 8;
constexpr size_t max_text = 64u << 10;
constexpr std::string_view levels[] = {"debug", "info", "warn", "error"};

uint8_t level_code(std::string_view l)
{
    for (uint8_t i = 0; i < 4; ++i)
        if (levels[i] == l)
            return i;
    return 1;
}

int64_t day_of(int64_t t)
{
    return (t >= 0 ? t / a_day : (t - a_day + 1) / a_day) * a_day;
}

uint32_t get32(const char* p)
{
    uint32_t v = 0;
    std::memcpy(&v, p, 4);
    return v;
}

// The files of `dir` as (day, name), ascending.
std::vector<std::pair<int64_t, std::string>> day_files(const std::string& dir)
{
    std::vector<std::pair<int64_t, std::string>> out;
    if (DIR* d = ::opendir(dir.c_str()))
    {
        while (const dirent* e = ::readdir(d))
        {
            const std::string_view n = e->d_name;
            if (!n.ends_with(".log"))
                continue;
            int64_t day = 0;
            const auto r = std::from_chars(n.data(), n.data() + n.size() - 4, day);
            if (r.ec == std::errc() && r.ptr == n.data() + n.size() - 4)
                out.emplace_back(day, std::string(n));
        }
        ::closedir(d);
    }
    std::sort(out.begin(), out.end());
    return out;
}

}   // namespace

log_store::~log_store() { close(); }

std::string log_store::path_of(int64_t day) const
{
    return m_dir + "/" + std::to_string(day) + ".log";
}

bool log_store::open(const std::string& dir, int64_t keep_ms, std::string& why)
{
    if (!private_dir(dir, true))
        return why = dir + " is not a directory of this user's alone", false;
    m_dir = dir;
    m_keep_ms = keep_ms;
    const auto files = day_files(dir);
    m_st.files = files.size();
    // The newest line kept, so the first lines sent after a start are not kept twice.
    if (!files.empty())
    {
        std::vector<std::pair<size_t, size_t>> recs;
        std::string data;
        read_file(m_dir + "/" + files.back().second, recs, data);
        if (!recs.empty())
        {
            int64_t t = 0;
            std::memcpy(&t, data.data() + recs.back().first, 8);
            m_last_t = t;
        }
    }
    m_open = true;
    return true;
}

void log_store::read_file(const std::string& path, std::vector<std::pair<size_t, size_t>>& recs, std::string& data) const
{
    recs.clear();
    if (!socketley::read_file(path, data))
        return;
    size_t at = 0;
    while (at + record_head <= data.size())
    {
        const uint32_t len = get32(data.data() + at);
        const uint32_t crc = get32(data.data() + at + 4);
        // A record that does not fit or does not check is where a crash cut the file.
        if (len < 11 || len > max_text + 512 || at + record_head + len > data.size() ||
            socketley::crc::crc32c(data.data() + at + record_head, static_cast<size_t>(len)) != crc)
        {
            ++m_st.torn;
            break;
        }
        recs.emplace_back(at + record_head, len);
        at += record_head + len;
    }
}

void log_store::append(int64_t t, std::string_view level, std::string_view runtime, std::string_view text)
{
    if (!m_open)
        return;
    if (text.size() > max_text)
        text = text.substr(0, max_text);
    if (runtime.size() > 255)
        runtime = runtime.substr(0, 255);
    const int64_t day = day_of(t);
    if (day != m_day)
    {
        flush();
        if (m_fd >= 0)
            ::close(m_fd);
        m_fd = ::open(path_of(day).c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        m_day = day;
        ++m_st.files;
    }
    // In this machine's byte order, as the reader takes it back; the files are this machine's alone.
    const uint16_t rl = static_cast<uint16_t>(runtime.size());
    const uint32_t len = static_cast<uint32_t>(11 + runtime.size() + text.size());
    const size_t at = m_buf.size();
    m_buf.resize(at + record_head + 11);
    char* p = m_buf.data() + at;
    std::memcpy(p, &len, 4);
    std::memcpy(p + record_head, &t, 8);
    p[record_head + 8] = static_cast<char>(level_code(level));
    std::memcpy(p + record_head + 9, &rl, 2);
    m_buf += runtime;
    m_buf += text;
    const uint32_t crc = socketley::crc::crc32c(m_buf.data() + at + record_head, static_cast<size_t>(len));
    std::memcpy(m_buf.data() + at + 4, &crc, 4);
    m_last_t = std::max(m_last_t, t);
    ++m_st.lines;
}

void log_store::flush()
{
    if (!m_buf.empty() && m_fd >= 0)
    {
        if (!write_all(m_fd, m_buf.data(), m_buf.size()))
            LOG_WARN(("metrics: " + path_of(m_day) + " could not be written; its lines are lost").c_str());
        m_st.bytes_on_disk += m_buf.size();
    }
    m_buf.clear();
}

void log_store::retain(int64_t now)
{
    // Whole days, as their files, once they lie wholly past the retention.
    for (const auto& [day, name] : day_files(m_dir))
        if (day + a_day + m_keep_ms < now && day != m_day && ::unlink((m_dir + "/" + name).c_str()) == 0 && m_st.files)
            --m_st.files;
}

void log_store::close()
{
    if (!m_open)
        return;
    if (!m_buf.empty() && m_fd >= 0 && !write_all(m_fd, m_buf.data(), m_buf.size())) {}
    m_buf.clear();
    if (m_fd >= 0)
        ::close(m_fd);
    m_fd = -1;
    m_open = false;
}

void log_store::scan(int64_t mint, int64_t maxt, bool backward, const std::function<bool(const log_view&)>& each) const
{
    auto files = day_files(m_dir);
    if (backward)
        std::reverse(files.begin(), files.end());
    std::vector<std::pair<size_t, size_t>> recs;
    std::string data;
    for (const auto& [day, name] : files)
    {
        if (day > maxt || day + a_day <= mint)
            continue;
        read_file(m_dir + "/" + name, recs, data);
        const auto one = [&](const std::pair<size_t, size_t>& r) {
            const char* p = data.data() + r.first;
            log_view v;
            std::memcpy(&v.t, p, 8);
            if (v.t < mint || v.t > maxt)
                return true;
            const uint8_t lv = static_cast<uint8_t>(p[8]);
            v.level = levels[lv < 4 ? lv : 1];
            uint16_t rl = 0;
            std::memcpy(&rl, p + 9, 2);
            if (11u + rl > r.second)
                return true;
            v.runtime = std::string_view(p + 11, rl);
            v.text = std::string_view(p + 11 + rl, r.second - 11 - rl);
            return each(v);
        };
        if (backward)
        {
            for (size_t i = recs.size(); i-- > 0;)
                if (!one(recs[i]))
                    return;
        }
        else
            for (const auto& r : recs)
                if (!one(r))
                    return;
    }
}

// ── LogQL ─────────────────────────────────────────────────────────────────

namespace
{

struct lexer
{
    std::string_view s;
    size_t at{0};
    void ws()
    {
        while (at < s.size() && (s[at] == ' ' || s[at] == '\t' || s[at] == '\n' || s[at] == '\r'))
            ++at;
    }
    bool eat(std::string_view t)
    {
        ws();
        if (s.substr(at, t.size()) != t)
            return false;
        at += t.size();
        return true;
    }
    bool ident(std::string& out)
    {
        ws();
        const size_t b = at;
        while (at < s.size() && (std::isalnum(static_cast<unsigned char>(s[at])) || s[at] == '_' ||
                                 (at > b && s[at] == ':')))
            ++at;
        out.assign(s.substr(b, at - b));
        return !out.empty() && !std::isdigit(static_cast<unsigned char>(out[0]));
    }
    bool string(std::string& out)
    {
        ws();
        out.clear();
        if (at >= s.size())
            return false;
        const char q = s[at];
        if (q == '`')
        {
            const size_t e = s.find('`', at + 1);
            if (e == std::string_view::npos)
                return false;
            out.assign(s.substr(at + 1, e - at - 1));
            at = e + 1;
            return true;
        }
        if (q != '"')
            return false;
        for (++at; at < s.size(); ++at)
        {
            const char c = s[at];
            if (c == '"')
            {
                ++at;
                return true;
            }
            if (c == '\\' && at + 1 < s.size())
            {
                const char n = s[++at];
                out += n == 'n' ? '\n' : n == 't' ? '\t' : n;
            }
            else
                out += c;
        }
        return false;
    }
    bool end()
    {
        ws();
        return at == s.size();
    }
};

bool grouping(lexer& lx, logql& q)
{
    const bool by = lx.eat("by");
    if (!by && !lx.eat("without"))
        return true;
    q.without = !by;
    if (!lx.eat("("))
        return false;
    for (std::string id; !lx.eat(")");)
    {
        if (!q.grouping.empty() && !lx.eat(","))
            return false;
        if (!lx.ident(id))
            return false;
        q.grouping.push_back(id);
    }
    return true;
}

bool log_expr(lexer& lx, logql& q, std::string& why)
{
    if (!lx.eat("{"))
        return why = "parse error : syntax error: unexpected input, expecting {", false;
    for (bool first = true; !lx.eat("}"); first = false)
    {
        if (!first && !lx.eat(","))
            return why = "parse error : syntax error: expecting , or }", false;
        matcher m;
        if (!lx.ident(m.name))
            return why = "parse error : syntax error: expecting a label name", false;
        if (lx.eat("=~"))
            m.op = match_op::re;
        else if (lx.eat("!~"))
            m.op = match_op::nre;
        else if (lx.eat("!="))
            m.op = match_op::ne;
        else if (lx.eat("="))
            m.op = match_op::eq;
        else
            return why = "parse error : syntax error: expecting = != =~ or !~", false;
        if (!lx.string(m.value))
            return why = "parse error : syntax error: expecting a quoted value", false;
        std::shared_ptr<regex> re;
        if (m.op == match_op::re || m.op == match_op::nre)
        {
            re = std::make_shared<regex>();
            if (std::string w; !re->compile(m.value, w))
                return why = "parse error : invalid regex " + m.value + ": " + w, false;
        }
        q.selector.push_back(std::move(m));
        q.selector_re.push_back(std::move(re));
    }
    if (q.selector.empty())
        return why = "parse error : queries require at least one regexp or equality matcher", false;
    for (;;)
    {
        logql::filter f;
        if (lx.eat("|="))
            f.k = logql::filter::kind::contains;
        else if (lx.eat("!="))
            f.k = logql::filter::kind::not_contains;
        else if (lx.eat("|~"))
            f.k = logql::filter::kind::re;
        else if (lx.eat("!~"))
            f.k = logql::filter::kind::not_re;
        else
            break;
        if (!lx.string(f.text))
            return why = "parse error : syntax error: a line filter takes a quoted string", false;
        if (f.k == logql::filter::kind::re || f.k == logql::filter::kind::not_re)
        {
            f.re = std::make_shared<regex>();
            if (std::string w; !f.re->compile(".*(?:" + f.text + ").*", w))
                return why = "parse error : invalid regex " + f.text + ": " + w, false;
        }
        q.filters.push_back(std::move(f));
    }
    return true;
}

bool metric_expr(lexer& lx, logql& q, std::string& why)
{
    const size_t mark = lx.at;
    std::string id;
    if (!lx.ident(id))
        return why = "parse error : syntax error: unexpected input", false;
    if (id == "sum" || id == "count" || id == "min" || id == "max" || id == "avg")
    {
        if (!q.agg.empty())
            return why = "parse error : one aggregation around a range function is taken", false;
        q.agg = id;
        if (!grouping(lx, q) || !lx.eat("("))
            return why = "parse error : syntax error: expecting (", false;
        if (!metric_expr(lx, q, why))
            return false;
        if (!lx.eat(")"))
            return why = "parse error : syntax error: expecting )", false;
        if (q.grouping.empty() && !grouping(lx, q))
            return why = "parse error : syntax error in by/without", false;
        return true;
    }
    if (id != "count_over_time" && id != "rate" && id != "bytes_over_time" && id != "bytes_rate")
    {
        lx.at = mark;
        return why = "parse error : " + id + " is not a function this LogQL takes", false;
    }
    q.fn = id;
    if (!lx.eat("(") || !log_expr(lx, q, why))
        return why.empty() ? (why = "parse error : syntax error: expecting (", false) : false;
    if (!lx.eat("["))
        return why = "parse error : a range function takes a range, as [5m]", false;
    const size_t close = lx.s.find(']', lx.at);
    if (close == std::string_view::npos || !parse_duration(lx.s.substr(lx.at, close - lx.at), q.range_ms) ||
        q.range_ms <= 0)
        return why = "parse error : the range is a duration, as [5m]", false;
    lx.at = close + 1;
    if (!lx.eat(")"))
        return why = "parse error : syntax error: expecting )", false;
    return true;
}

std::string key_of(const label_set& ls)
{
    std::string k;
    for (const auto& l : ls)
        (k += l.name) += '\1', (k += l.value) += '\2';
    return k;
}

void json_labels(const label_set& ls, std::string& out)
{
    out += '{';
    for (size_t i = 0; i < ls.size(); ++i)
    {
        if (i)
            out += ',';
        json::quote_into(out, ls[i].name);
        out += ':';
        json::quote_into(out, ls[i].value);
    }
    out += '}';
}

// Each stream's lines in a window, a metric query's values at `steps`, grouped as its aggregation says.
struct series_values
{
    label_set labels;
    std::vector<double> v;
    std::vector<bool> has;
};

void metric_eval(const log_store& s, const logql& q, std::string_view instance, int64_t start, int64_t end,
                 int64_t step, std::vector<series_values>& out, size_t& nsteps)
{
    nsteps = static_cast<size_t>((end - start) / std::max<int64_t>(step, 1)) + 1;
    struct stream
    {
        label_set labels;
        std::vector<std::pair<int64_t, size_t>> lines;
    };
    std::map<std::string, stream> streams;
    label_set ls;
    s.scan(start - q.range_ms + 1, end, false, [&](const log_view& l) {
        log_labels(l, instance, ls);
        if (logql_matches(q, ls, l.text))
        {
            auto& st = streams[key_of(ls)];
            if (st.labels.empty())
                st.labels = ls;
            st.lines.emplace_back(l.t, l.text.size());
        }
        return true;
    });
    const bool bytes = q.fn.starts_with("bytes");
    const bool per_second = q.fn == "rate" || q.fn == "bytes_rate";
    std::map<std::string, series_values> groups;
    std::map<std::string, std::vector<double>> seen;
    for (auto& [k, st] : streams)
    {
        label_set g;
        for (const auto& l : st.labels)
        {
            const bool named = std::find(q.grouping.begin(), q.grouping.end(), l.name) != q.grouping.end();
            if (q.agg.empty() || named != q.without)
                g.push_back(l);
        }
        const std::string gk = key_of(g);
        auto& sv = groups[gk];
        auto& n = seen[gk];
        if (sv.v.empty())
        {
            sv.labels = g;
            sv.v.assign(nsteps, 0);
            sv.has.assign(nsteps, false);
            n.assign(nsteps, 0);
        }
        // A window (t - range, t] at each step, two cursors walking the stream's lines once.
        size_t lo = 0, hi = 0;
        double in_window = 0;
        for (size_t i = 0; i < nsteps; ++i)
        {
            const int64_t t = start + static_cast<int64_t>(i) * step;
            for (; hi < st.lines.size() && st.lines[hi].first <= t; ++hi)
                in_window += bytes ? static_cast<double>(st.lines[hi].second) : 1;
            for (; lo < hi && st.lines[lo].first <= t - q.range_ms; ++lo)
                in_window -= bytes ? static_cast<double>(st.lines[lo].second) : 1;
            if (hi == lo)
                continue;
            const double v = per_second ? in_window / (static_cast<double>(q.range_ms) / 1000.0) : in_window;
            const bool first = !sv.has[i];
            sv.has[i] = true;
            n[i] += 1;
            if (q.agg == "min")
                sv.v[i] = first ? v : std::min(sv.v[i], v);
            else if (q.agg == "max")
                sv.v[i] = first ? v : std::max(sv.v[i], v);
            else if (q.agg == "count")
                sv.v[i] += 1;
            else
                sv.v[i] += v;
        }
    }
    if (q.agg == "avg")
        for (auto& [k, sv] : groups)
            for (size_t i = 0; i < nsteps; ++i)
                if (sv.has[i])
                    sv.v[i] /= seen[k][i];
    for (auto& [k, sv] : groups)
        out.push_back(std::move(sv));
}

}   // namespace

bool parse_logql(std::string_view q, logql& out, bool& is_log, std::string& why)
{
    out = {};
    lexer lx{q};
    lx.ws();
    is_log = true;
    if (lx.at < q.size() && q[lx.at] == '{')
    {
        if (!log_expr(lx, out, why))
            return false;
    }
    else if (!metric_expr(lx, out, why))
    {
        // Without a selector anywhere it is PromQL, which the metrics engine answers, as Grafana's `vector(1)+vector(1)`.
        if (q.find('{') == std::string_view::npos || out.fn.empty())
        {
            is_log = false;
            why.clear();
            return true;
        }
        return false;
    }
    if (!lx.end())
        return why = "parse error : syntax error: unexpected input at " + std::to_string(lx.at), false;
    return true;
}

void log_labels(const log_view& l, std::string_view instance, label_set& out)
{
    out.clear();
    out.push_back({"instance", std::string(instance)});
    out.push_back({"job", "socketley"});
    out.push_back({"level", std::string(l.level)});
    if (!l.runtime.empty())
        out.push_back({"name", std::string(l.runtime)});
}

bool logql_matches(const logql& q, const label_set& labels, std::string_view text)
{
    for (size_t i = 0; i < q.selector.size(); ++i)
    {
        const matcher& m = q.selector[i];
        const std::string_view v = label_value(labels, m.name);
        const bool ok = m.op == match_op::eq   ? v == m.value
                        : m.op == match_op::ne ? v != m.value
                        : m.op == match_op::re ? q.selector_re[i]->matches(v)
                                               : !q.selector_re[i]->matches(v);
        if (!ok)
            return false;
    }
    for (const auto& f : q.filters)
    {
        const bool ok = f.k == logql::filter::kind::contains       ? text.find(f.text) != std::string_view::npos
                        : f.k == logql::filter::kind::not_contains ? text.find(f.text) == std::string_view::npos
                        : f.k == logql::filter::kind::re           ? f.re->matches(text)
                                                                   : !f.re->matches(text);
        if (!ok)
            return false;
    }
    return true;
}

void logql_range(const log_store& s, const logql& q, std::string_view instance, int64_t start, int64_t end,
                 int64_t step, size_t limit, bool backward, std::string& out)
{
    if (!q.fn.empty())
    {
        std::vector<series_values> sv;
        size_t n = 0;
        metric_eval(s, q, instance, start, end, step, sv, n);
        out += "{\"resultType\":\"matrix\",\"result\":[";
        bool first = true;
        for (const auto& x : sv)
        {
            out += first ? "{\"metric\":" : ",{\"metric\":";
            first = false;
            json_labels(x.labels, out);
            out += ",\"values\":[";
            bool f2 = true;
            for (size_t i = 0; i < n; ++i)
            {
                if (!x.has[i])
                    continue;
                out += f2 ? "[" : ",[";
                f2 = false;
                format_timestamp(start + static_cast<int64_t>(i) * step, out);
                out += ",\"";
                format_value(x.v[i], out);
                out += "\"]";
            }
            out += "]}";
        }
        out += "],\"stats\":{}}";
        return;
    }
    struct stream
    {
        label_set labels;
        std::vector<std::pair<int64_t, std::string>> lines;
    };
    std::map<std::string, stream> streams;
    label_set ls;
    size_t taken = 0;
    s.scan(start, end, backward, [&](const log_view& l) {
        log_labels(l, instance, ls);
        if (!logql_matches(q, ls, l.text))
            return true;
        auto& st = streams[key_of(ls)];
        if (st.labels.empty())
            st.labels = ls;
        st.lines.emplace_back(l.t, std::string(l.text));
        return ++taken < limit;
    });
    out += "{\"resultType\":\"streams\",\"result\":[";
    bool first = true;
    for (const auto& [k, st] : streams)
    {
        out += first ? "{\"stream\":" : ",{\"stream\":";
        first = false;
        json_labels(st.labels, out);
        out += ",\"values\":[";
        for (size_t i = 0; i < st.lines.size(); ++i)
        {
            out += i ? ",[\"" : "[\"";
            // Nanoseconds, as Loki writes them, a line's place in its millisecond kept apart by the last digits.
            out += std::to_string(st.lines[i].first * 1'000'000 + static_cast<int64_t>(i % 1000));
            out += "\",";
            json::quote_into(out, st.lines[i].second);
            out += ']';
        }
        out += "]}";
    }
    out += "],\"stats\":{}}";
}

void logql_instant(const log_store& s, const logql& q, std::string_view instance, int64_t t, size_t limit,
                   std::string& out)
{
    if (q.fn.empty())
        return logql_range(s, q, instance, t - 3'600'000, t, 1000, limit, true, out);
    std::vector<series_values> sv;
    size_t n = 0;
    metric_eval(s, q, instance, t, t, 1000, sv, n);
    out += "{\"resultType\":\"vector\",\"result\":[";
    bool first = true;
    for (const auto& x : sv)
    {
        if (!x.has[0])
            continue;
        out += first ? "{\"metric\":" : ",{\"metric\":";
        first = false;
        json_labels(x.labels, out);
        out += ",\"value\":[";
        format_timestamp(t, out);
        out += ",\"";
        format_value(x.v[0], out);
        out += "\"]}";
    }
    out += "],\"stats\":{}}";
}

void log_label_names(const log_store& s, std::string_view, int64_t start, int64_t end, std::string& out)
{
    bool named = false;
    s.scan(start, end, true, [&](const log_view& l) {
        named = named || !l.runtime.empty();
        return !named;
    });
    out += named ? R"(["instance","job","level","name"])" : R"(["instance","job","level"])";
}

void log_label_values(const log_store& s, std::string_view instance, std::string_view name, int64_t start, int64_t end,
                      std::string& out)
{
    std::vector<std::string> vals;
    if (name == "job")
        vals.push_back("socketley");
    else if (name == "instance")
        vals.emplace_back(instance);
    else if (name == "level" || name == "name")
    {
        std::map<std::string, bool> seen;
        s.scan(start, end, true, [&](const log_view& l) {
            const std::string_view v = name == "level" ? l.level : l.runtime;
            if (!v.empty())
                seen.emplace(std::string(v), true);
            return seen.size() < 10'000;
        });
        for (const auto& [v, _] : seen)
            vals.push_back(v);
    }
    out += '[';
    for (size_t i = 0; i < vals.size(); ++i)
    {
        if (i)
            out += ',';
        json::quote_into(out, vals[i]);
    }
    out += ']';
}

}   // namespace socketley::metrics
