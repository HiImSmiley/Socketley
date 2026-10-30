#include "metrics_local.h"

#include <algorithm>

namespace socketley::metrics
{

namespace
{

metric_type type_of_kind(uint8_t kind)
{
    // The catalog's kinds, in its order: counter, gauge, untyped.
    switch (kind)
    {
        case 0: return metric_type::counter;
        case 1: return metric_type::gauge;
        default: return metric_type::untyped;
    }
}

}   // namespace

// The frame's sections applied to the feed as they are read.
namespace
{

// The runtime a daemon's line is about: the quoted name after `runtime` or a type's name, first thing after its tags.
std::string_view named_runtime(std::string_view text)
{
    size_t at = 0;
    while (at < text.size() && text[at] == '[')
    {
        const size_t e = text.find("] ", at);
        if (e == std::string_view::npos)
            return {};
        at = e + 2;
    }
    const size_t q = text.find(" '", at);
    if (q == std::string_view::npos || q - at > 16)
        return {};
    static constexpr std::string_view words[] = {"runtime", "server", "client", "proxy", "cache", "storage", "dns",
                                                 "sync", "idp", "db", "mqtt", "mail", "tunnel", "metrics"};
    const std::string_view w = text.substr(at, q - at);
    if (std::find(std::begin(words), std::end(words), w) == std::end(words))
        return {};
    const size_t e = text.find('\'', q + 2);
    if (e == std::string_view::npos || e - q - 2 > 128 || e == q + 2)
        return {};
    const std::string_view name = text.substr(q + 2, e - q - 2);
    return name.find(' ') == std::string_view::npos ? name : std::string_view{};
}

}   // namespace

struct feed_visitor
{
    local_feed& f;
    int64_t stamp{0};
    bool resync{false};

    void head(uint64_t ticket, uint8_t flags, std::string_view instance)
    {
        stamp = static_cast<int64_t>(ticket);
        resync = flags & worker_proto::series_resync;
        if (!resync)
            return;
        ++f.m_stats.resyncs;
        f.m_before.clear();
        for (const auto& k : f.m_keys)
            if (k.live && k.series != no_series)
                f.m_before.push_back(k.series);
        f.m_keys.clear();
        f.m_fams.clear();
        f.m_instance.assign(instance);
        // The first since this process started: what the store holds of this daemon from before ends now too, unless
        // the frame names it again, so a series gone across a restart is not seen for the five minutes of a lookback.
        if (!f.m_started)
        {
            f.m_started = true;
            // Its own up aside, which it writes after the frame at the same stamp.
            const matcher ms[3] = {{"job", match_op::eq, "socketley"}, {"instance", match_op::eq, f.m_instance},
                                   {std::string(name_label), match_op::ne, "up"}};
            std::vector<uint32_t> held;
            f.m_store.select(ms, stamp - 5 * 60'000, stamp, held);
            f.m_before.insert(f.m_before.end(), held.begin(), held.end());
        }
    }

    void family(uint32_t id, uint8_t kind, std::string_view name, std::string_view help)
    {
        // An id is the daemon's count of families, so one far past it is a frame not to trust with an allocation.
        if (id > f.m_fams.size() + 4096)
            return;
        if (id >= f.m_fams.size())
            f.m_fams.resize(id + 1);
        auto& fam = f.m_fams[id];
        fam.name.assign(name);
        fam.help.assign(help);
        fam.type = type_of_kind(kind);
        f.m_store.set_meta(fam.name, fam.type, fam.help);
    }

    void key(uint32_t id, uint32_t fam, std::span<const worker_proto::series_label_view> labels)
    {
        if (fam >= f.m_fams.size() || f.m_fams[fam].name.empty() || id > f.m_keys.size() + 65536)
            return;
        label_set& ls = f.m_scratch;
        ls.clear();
        ls.push_back({std::string(name_label), f.m_fams[fam].name});
        // The labels a scrape adds, as Prometheus adds them, and one of the daemon's own by either name kept aside.
        for (const auto& l : labels)
        {
            if (l.value.empty() || l.name == name_label)
                continue;
            if (l.name == "job" || l.name == "instance")
                ls.push_back({"exported_" + std::string(l.name), std::string(l.value)});
            else
                ls.push_back({std::string(l.name), std::string(l.value)});
        }
        ls.push_back({"job", "socketley"});
        if (!f.m_instance.empty())
            ls.push_back({"instance", f.m_instance});
        std::sort(ls.begin(), ls.end(), [](const label& a, const label& b) { return a.name < b.name; });
        ls.erase(std::unique(ls.begin(), ls.end(), [](const label& a, const label& b) { return a.name == b.name; }),
                 ls.end());
        if (id >= f.m_keys.size())
            f.m_keys.resize(id + 1);
        auto& k = f.m_keys[id];
        if (k.live && k.series != no_series)
            f.m_store.mark_stale(k.series, stamp);
        k = {f.m_store.get_or_create(ls), 0, true, false};
    }

    void value(uint32_t id, double v)
    {
        if (id >= f.m_keys.size() || !f.m_keys[id].live)
            return;
        f.m_keys[id].v = v;
        f.m_keys[id].moved = true;
    }

    // A section of log lines is taken once: the one that goes on from the cursor this worker holds.
    bool log_section(uint64_t from, uint64_t next)
    {
        if (!f.m_logs || from != f.m_log_cursor)
            return false;
        first_logs = from == 0;
        f.m_log_cursor = next;
        return true;
    }

    void log(const worker_proto::series_log_line& l)
    {
        const int64_t t = static_cast<int64_t>(l.at_ms);
        // The first lines after a start are the daemon's newest, some of them kept before the restart.
        if (first_logs && t <= f.m_logs->last_t())
            return;
        // A line about a runtime names it as `runtime '<name>'` or `<type> '<name>'` after its tags, and is that
        // runtime's whichever process wrote it: the daemon, or a worker passing on the daemon's state.
        std::string_view rt = named_runtime(l.text);
        if (rt.empty())
            rt = l.runtime;
        f.m_logs->append(t, l.level, rt, l.text);
        ++f.m_stats.log_lines;
        f.m_log_counts[{std::string(rt), std::string(l.level)}].n += 1;
    }

    bool first_logs{false};

    void gone(uint32_t id)
    {
        if (id >= f.m_keys.size() || !f.m_keys[id].live)
            return;
        auto& k = f.m_keys[id];
        if (k.series != no_series)
            f.m_store.mark_stale(k.series, stamp);
        k = {};
    }
};

std::string local_feed::pull(int64_t stamp, bool extra, int64_t now)
{
    // An answer that never came cannot be told from one the daemon applied, so the next asks for everything.
    const size_t before = m_pending.size();
    std::erase_if(m_pending, [&](const pending& p) { return now - p.asked > answer_ms; });
    if (m_pending.size() != before)
    {
        put_up(stamp, 0);
        m_stats.lost += before - m_pending.size();
        m_resync = true;
    }
    for (const pending& p : m_pending)
        if (p.extra == extra)
            return {};
    uint8_t flags = m_resync ? worker_proto::series_resync : 0;
    // A tick's pull carries the log cursor; one between ticks leaves the lines to it.
    if (m_logs && !extra)
        flags |= worker_proto::series_logs;
    m_resync = false;
    m_pending.push_back({stamp, now, extra});
    if (extra)
        ++m_stats.extra;
    return worker_proto::frame(worker_proto::frame_type::series_pull,
                               worker_proto::encode_series_pull(static_cast<uint64_t>(stamp), flags, m_log_cursor));
}

void local_feed::refused(int64_t stamp)
{
    std::erase_if(m_pending, [&](const pending& p) { return p.stamp == stamp; });
    m_resync = true;
}

void local_feed::on_feed(std::string_view payload)
{
    feed_visitor v{*this};
    if (!worker_proto::decode_series_feed(payload, v))
    {
        // What was applied of it is not what the daemon thinks was, so the next pull starts over.
        m_resync = true;
        return;
    }
    ++m_stats.frames;
    m_stats.bytes += payload.size();
    if (v.resync)
    {
        // A series the daemon no longer has, from before the resync, ends here.
        std::vector<uint32_t> now;
        for (const auto& k : m_keys)
            if (k.live && k.series != no_series)
                now.push_back(k.series);
        std::sort(now.begin(), now.end());
        for (const uint32_t id : m_before)
            if (!std::binary_search(now.begin(), now.end(), id))
                m_store.mark_stale(id, v.stamp);
        m_before.clear();
    }
    const auto it = std::find_if(m_pending.begin(), m_pending.end(),
                                 [&](const pending& p) { return p.stamp == v.stamp; });
    // A late answer to a pull taken as lost is applied, so the ids stay the daemon's, and appends nothing.
    if (it == m_pending.end())
        return;
    const bool extra = it->extra;
    m_pending.erase(it);
    append(v.stamp, extra);
    if (!extra)
    {
        put_up(v.stamp, 1);
        count_logs(v.stamp);
    }
    m_stats.last_ms = v.stamp;
}

void local_feed::count_logs(int64_t stamp)
{
    for (auto& [key, c] : m_log_counts)
    {
        if (c.series == no_series)
        {
            label_set ls = {{std::string(name_label), "socketley_log_lines_total"}, {"instance", m_instance},
                            {"job", "socketley"}, {"level", key.second}};
            if (!key.first.empty())
                ls.push_back({"name", key.first});
            std::sort(ls.begin(), ls.end(), [](const label& a, const label& b) { return a.name < b.name; });
            c.series = m_store.get_or_create(ls);
            m_store.set_meta("socketley_log_lines_total", metric_type::counter,
                             "Log lines the daemon and its workers wrote, by runtime and level, since this runtime started.");
        }
        if (c.series != no_series)
            m_store.append(c.series, stamp, c.n);
    }
}

void local_feed::put_up(int64_t stamp, double v)
{
    if (m_instance.empty())
        return;
    if (m_up == no_series)
        m_up = m_store.get_or_create({{std::string(name_label), "up"}, {"instance", m_instance}, {"job", "socketley"}});
    if (m_up != no_series)
        m_store.append(m_up, stamp, v);
}

void local_feed::append(int64_t stamp, bool only_moved)
{
    uint64_t live = 0;
    for (auto& k : m_keys)
    {
        if (!k.live)
            continue;
        ++live;
        if (k.series != no_series && (!only_moved || k.moved))
            m_store.append(k.series, stamp, k.v);
        k.moved = false;
    }
    m_stats.series = live;
}

bool local_feed::runtimes_changed(std::string_view payload)
{
    std::vector<worker_proto::runtime_wire> rts;
    if (!worker_proto::decode_runtime_map(payload, rts))
        return false;
    std::sort(rts.begin(), rts.end(), [](const auto& a, const auto& b) { return a.name < b.name; });
    std::string now;
    for (const auto& r : rts)
    {
        now += r.name;
        now += '\0';
        now += static_cast<char>('0' + r.state);
        now += '\n';
    }
    const bool first = m_runtimes.empty();
    if (now == m_runtimes)
        return false;
    m_runtimes = std::move(now);
    return !first;
}

}   // namespace socketley::metrics
