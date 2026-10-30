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
    const uint8_t flags = m_resync ? worker_proto::series_resync : 0;
    m_resync = false;
    m_pending.push_back({stamp, now, extra});
    if (extra)
        ++m_stats.extra;
    return worker_proto::frame(worker_proto::frame_type::series_pull,
                               worker_proto::encode_series_pull(static_cast<uint64_t>(stamp), flags));
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
        put_up(v.stamp, 1);
    m_stats.last_ms = v.stamp;
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
