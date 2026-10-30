#include "metrics_scrape.h"

#include <algorithm>
#include <cmath>

#include "metrics_query.h"
#include "metrics_time.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/wall_clock.h"

namespace socketley::metrics
{

namespace
{

bool valid_label_name(std::string_view n)
{
    if (n.empty() || n.starts_with("__") || (n[0] >= '0' && n[0] <= '9'))
        return false;
    for (const char c : n)
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'))
            return false;
    return true;
}

uint64_t fnv(std::string_view s)
{
    uint64_t h = 1469598103934665603ull;
    for (const char c : s)
        h = (h ^ static_cast<unsigned char>(c)) * 1099511628211ull;
    return h;
}

// The first time after `now` that is `offset` past a whole multiple of `every`.
int64_t next_after(int64_t now, int64_t every, int64_t offset)
{
    const int64_t k = (now - offset) >= 0 ? (now - offset) / every + 1 : 0;
    return k * every + offset;
}

bool same(const target_config& a, const target_config& b)
{
    return a.name == b.name && a.url == b.url && a.every_ms == b.every_ms && a.timeout_ms == b.timeout_ms &&
           a.bearer == b.bearer && a.labels == b.labels;
}

}   // namespace

bool parse_targets(std::string_view text, int64_t default_every_ms, std::vector<target_config>& out, std::string& why)
{
    out.clear();
    for (const auto& line : socketley::split_target_lines(text))
    {
        const auto refuse = [&](std::string w) {
            why = "line " + std::to_string(line.line_no) + ": " + w;
            return false;
        };
        if (line.fields.size() < 2)
            return refuse("a target is `name url`, then every=, timeout= or labels");
        target_config t;
        t.name.assign(line.fields[0]);
        if (!socketley::valid_target_name(t.name))
            return refuse("a target's name is letters, digits, '-', '_' and '.'");
        for (const auto& o : out)
            if (o.name == t.name)
                return refuse("the target " + t.name + " is named twice");
        t.url.assign(line.fields[1]);
        if (std::string bad; !socketley::parse_http_url(t.url, t.where, bad))
            return refuse(t.url + ": " + bad);
        t.every_ms = default_every_ms;
        for (size_t i = 2; i < line.fields.size(); ++i)
        {
            const std::string_view f = line.fields[i];
            const size_t eq = f.find('=');
            if (eq == std::string_view::npos || eq == 0)
                return refuse(std::string(f) + " is no name=value");
            const std::string_view k = f.substr(0, eq), v = f.substr(eq + 1);
            if (k == "every" || k == "timeout")
            {
                int64_t ms = 0;
                if (!parse_duration(v, ms) || ms < 1000 || ms > 3600 * 1000)
                    return refuse(std::string(k) + "= is a duration from 1s to 1h");
                (k == "every" ? t.every_ms : t.timeout_ms) = ms;
                continue;
            }
            if (k == "bearer")
            {
                std::string tok;
                if (!socketley::read_file(std::string(v), tok))
                    return refuse(std::string(v) + " does not read");
                while (!tok.empty() && (tok.back() == '\n' || tok.back() == '\r' || tok.back() == ' '))
                    tok.pop_back();
                if (tok.empty() || tok.find_first_of("\r\n") != std::string::npos)
                    return refuse(std::string(v) + " holds no token of one line");
                t.bearer = std::move(tok);
                continue;
            }
            if (!valid_label_name(k) || k == "job" || k == "instance")
                return refuse(std::string(k) + " is no label a target may set");
            t.labels.push_back({std::string(k), std::string(v)});
        }
        if (t.timeout_ms == 0)
            t.timeout_ms = std::min<int64_t>(t.every_ms, 10'000);
        if (t.timeout_ms > t.every_ms)
            return refuse("timeout= is no longer than every=");
        std::sort(t.labels.begin(), t.labels.end(), [](const label& a, const label& b) { return a.name < b.name; });
        for (size_t i = 1; i < t.labels.size(); ++i)
            if (t.labels[i].name == t.labels[i - 1].name)
                return refuse("the label " + t.labels[i].name + " is given twice");
        out.push_back(std::move(t));
    }
    return true;
}

struct scraper::target
{
    target_config cfg;
    std::string instance;
    std::unique_ptr<socketley::http_peer> peer;
    std::shared_ptr<bool> alive{std::make_shared<bool>(true)};
    int64_t offset{0};
    int64_t next{0};

    // The scrape in flight: the time it is stamped with, and when it began.
    bool running{false};
    bool timed_out{false};
    int64_t stamp{0};
    int64_t began_ms{0};
    std::chrono::steady_clock::time_point began{};

    // Scrapes counted from 1, and the last that answered, whose series a scrape without them ends.
    uint64_t n{0};
    uint64_t ok_n{0};
    struct entry
    {
        uint32_t id;
        uint64_t seen;
    };
    std::unordered_map<std::string, entry, string_hash, string_equal> cache;
    struct meta
    {
        metric_type type{metric_type::untyped};
        std::string help;
        bool dirty{false};
    };
    std::unordered_map<std::string, meta, string_hash, string_equal> metas;
    uint32_t up_id{no_series}, dur_id{no_series}, samples_id{no_series};

    // What the last scrape came to.
    bool tried{false};
    bool up{false};
    std::string last_error;
    int64_t last_ms{0};
    double last_secs{0};
    uint64_t last_samples{0};
    uint64_t series{0};
};

scraper::scraper(event_loop& loop, file_io& io, hash_pool& resolver, store& s, std::string owner)
    : m_loop(loop), m_io(io), m_resolver(resolver), m_store(s), m_owner(std::move(owner))
{
}

scraper::~scraper()
{
    stop();
}

void scraper::stop()
{
    *m_alive = false;
    for (auto& t : m_targets)
    {
        *t->alive = false;
        if (t->peer)
            t->peer->stop();
    }
}

bool scraper::configure(std::string path, int64_t default_every_ms, std::string& why)
{
    m_path = std::move(path);
    m_stamp = socketley::file_stamp::of(m_path);
    std::string text;
    if (!socketley::read_file(m_path, text, {.missing_ok = false, .max_bytes = 1u << 20}, &why))
        return false;
    std::vector<target_config> cfgs;
    if (!parse_targets(text, default_every_ms, cfgs, why))
    {
        why = m_path + ": " + why;
        return false;
    }
    const int64_t now = wall::now_ms_coarse();
    std::vector<std::unique_ptr<target>> next;
    for (auto& c : cfgs)
    {
        // A target whose line did not change goes on with its connection, its cache and its schedule.
        const auto it = std::find_if(m_targets.begin(), m_targets.end(),
                                     [&](const auto& t) { return t && same(t->cfg, c); });
        if (it != m_targets.end())
        {
            next.push_back(std::move(*it));
            continue;
        }
        auto t = std::make_unique<target>();
        t->cfg = std::move(c);
        t->instance = t->cfg.where.host + ":" + std::to_string(t->cfg.where.port);
        t->offset = static_cast<int64_t>(fnv(t->cfg.name) % static_cast<uint64_t>(t->cfg.every_ms));
        t->next = next_after(now, t->cfg.every_ms, t->offset);
        label_set ls = t->cfg.labels;
        ls.push_back({"instance", t->instance});
        ls.push_back({"job", t->cfg.name});
        ls.push_back({std::string(name_label), ""});
        const auto put = [&](std::string_view metric, uint32_t& id) {
            for (auto& l : ls)
                if (l.name == name_label)
                    l.value.assign(metric);
            label_set sorted = ls;
            std::sort(sorted.begin(), sorted.end(), [](const label& a, const label& b) { return a.name < b.name; });
            id = m_store.get_or_create(sorted);
        };
        put("up", t->up_id);
        put("scrape_duration_seconds", t->dur_id);
        put("scrape_samples_scraped", t->samples_id);
        next.push_back(std::move(t));
    }
    m_store.set_meta("up", metric_type::gauge, "1 when the last scrape of a target answered, 0 when it did not.");
    m_store.set_meta("scrape_duration_seconds", metric_type::gauge, "How long the last scrape of a target took.");
    m_store.set_meta("scrape_samples_scraped", metric_type::gauge, "Samples the last scrape of a target gave.");
    // A target gone from the file has its series end now, as Prometheus ends them.
    for (auto& t : m_targets)
    {
        if (!t)
            continue;
        *t->alive = false;
        if (t->peer)
            t->peer->stop();
        for (const auto& [k, e] : t->cache)
            if (e.seen == t->ok_n && e.id != no_series)
                m_store.mark_stale(e.id, now);
        for (const uint32_t id : {t->up_id, t->dur_id, t->samples_id})
            if (id != no_series)
                m_store.mark_stale(id, now);
    }
    m_targets = std::move(next);
    return true;
}

void scraper::refresh(int64_t default_every_ms)
{
    if (m_path.empty())
        return;
    const auto st = socketley::file_stamp::of(m_path);
    if (m_stamp && *m_stamp == st)
        return;
    std::string why;
    if (!configure(m_path, default_every_ms, why))
        LOG_ERROR(("metrics " + m_owner + ": " + why + "; the targets before are kept").c_str());
    else
        LOG_INFO(("metrics " + m_owner + ": " + std::to_string(m_targets.size()) + " target(s) from " + m_path).c_str());
}

int64_t scraper::next_due() const
{
    int64_t at = INT64_MAX;
    for (const auto& t : m_targets)
        at = std::min(at, t->next);
    return at;
}

bool scraper::busy() const
{
    return std::any_of(m_targets.begin(), m_targets.end(), [](const auto& t) { return t->running; });
}

size_t scraper::up() const
{
    return static_cast<size_t>(std::count_if(m_targets.begin(), m_targets.end(), [](const auto& t) { return t->up; }));
}

void scraper::run_due(int64_t now)
{
    for (auto& t : m_targets)
    {
        // A timer is a millisecond or two early by the coarse clock, which is the same tick.
        if (t->next > now + 2)
            continue;
        const int64_t stamp = t->next;
        t->next = next_after(std::max(now, stamp), t->cfg.every_ms, t->offset);
        // A target still answering the last scrape skips this one, as Prometheus does.
        if (!t->running)
            start(*t, stamp);
    }
}

void scraper::start(target& t, int64_t stamp)
{
    if (!t.peer)
        t.peer = std::make_unique<socketley::http_peer>(m_loop, m_io, m_resolver, t.cfg.where, std::string{},
                                                        "metrics " + m_owner + ": the target " + t.cfg.name);
    t.running = true;
    t.timed_out = false;
    t.stamp = stamp;
    t.began = std::chrono::steady_clock::now();
    t.began_ms = wall::now_ms_coarse();
    socketley::http_request rq;
    char secs[32];
    std::snprintf(secs, sizeof secs, "%g", static_cast<double>(t.cfg.timeout_ms) / 1000.0);
    rq.head = "GET " + (t.cfg.where.path.empty() ? std::string("/") : t.cfg.where.path) +
              " HTTP/1.1\r\nHost: " + t.cfg.where.authority() +
              "\r\nAccept: text/plain;version=0.0.4,*/*;q=0.1\r\nUser-Agent: socketley-metrics\r\n"
              "X-Prometheus-Scrape-Timeout-Seconds: " + secs + "\r\nConnection: keep-alive\r\n";
    if (!t.cfg.bearer.empty())
        rq.head += "Authorization: Bearer " + t.cfg.bearer + "\r\n";
    rq.head += "\r\n";
    rq.answer_secs = static_cast<int>((t.cfg.timeout_ms + 999) / 1000);
    rq.max_answer = max_body;
    target* tp = &t;
    std::weak_ptr<bool> alive = t.alive;
    t.peer->exchange(std::move(rq), [this, tp, alive](socketley::http_answer a) {
        const auto held = alive.lock();
        if (!held || !*held)
            return;
        finish(*tp, a);
    });
}

void scraper::finish(target& t, const socketley::http_answer& a)
{
    t.running = false;
    ++m_fig.scrapes;
    if (t.timed_out)
        return fail(t, "the scrape took longer than its timeout of " + format_duration_ms(t.cfg.timeout_ms));
    if (a.status != 200)
        return fail(t, a.status ? "the target answered HTTP " + std::to_string(a.status)
                                : (a.failure.empty() ? std::string("no answer") : a.failure));

    // The sink of this scrape: a hit costs a hash of the line's bytes, a miss reads its labels into a label set.
    struct sink final : text_sink
    {
        store& s;
        target& t;
        scrape_figures& fig;
        int64_t stamp;
        uint64_t n;
        uint64_t samples{0};
        label_set ls;

        sink(store& st, target& tg, scrape_figures& f, int64_t at, uint64_t no) : s(st), t(tg), fig(f), stamp(at), n(no)
        {
        }

        void on_sample(const text_sample& x) override
        {
            ++samples;
            uint32_t id = no_series;
            if (const auto it = t.cache.find(x.series); it != t.cache.end())
            {
                id = it->second.id;
                // A refused series is not marked seen, so it ages out of the cache and is asked for again.
                if (id == no_series)
                    return;
                it->second.seen = n;
            }
            else
            {
                ls.clear();
                ls.push_back({std::string(name_label), std::string(x.name)});
                for (const text_label& l : x.labels)
                {
                    if (l.value.empty() || l.name == name_label)
                        continue;
                    // A label the target sets wins, and the scraped one is kept beside it, as honor_labels: false.
                    const bool clash = l.name == "job" || l.name == "instance" ||
                                       std::any_of(t.cfg.labels.begin(), t.cfg.labels.end(),
                                                   [&](const label& c) { return c.name == l.name; });
                    ls.push_back({clash ? "exported_" + std::string(l.name) : std::string(l.name),
                                  std::string(l.value)});
                }
                for (const label& c : t.cfg.labels)
                    ls.push_back(c);
                ls.push_back({"instance", t.instance});
                ls.push_back({"job", t.cfg.name});
                std::sort(ls.begin(), ls.end(), [](const label& a, const label& b) { return a.name < b.name; });
                ls.erase(std::unique(ls.begin(), ls.end(),
                                     [](const label& a, const label& b) { return a.name == b.name; }),
                         ls.end());
                id = s.get_or_create(ls);
                if (id == no_series)
                    ++fig.series_refused;
                t.cache.emplace(std::string(x.series), target::entry{id, id == no_series ? 0 : n});
                if (id == no_series)
                    return;
            }
            s.append(id, x.has_timestamp ? x.timestamp_ms : stamp, x.value);
        }

        void on_type(std::string_view family, metric_type type) override
        {
            auto it = t.metas.find(family);
            if (it == t.metas.end())
                it = t.metas.emplace(std::string(family), target::meta{}).first;
            if (it->second.type != type)
            {
                it->second.type = type;
                it->second.dirty = true;
            }
        }

        void on_help(std::string_view family, std::string_view help) override
        {
            auto it = t.metas.find(family);
            if (it == t.metas.end())
                it = t.metas.emplace(std::string(family), target::meta{}).first;
            if (it->second.help != help)
            {
                it->second.help.assign(help);
                it->second.dirty = true;
            }
        }
    };

    const uint64_t n = ++t.n;
    sink k(m_store, t, m_fig, t.stamp, n);
    text_stats st;
    m_parser.parse(a.body, k, st);
    m_fig.samples += k.samples;
    m_fig.lines_refused += st.refused;
    for (auto& [name, m] : t.metas)
        if (m.dirty)
        {
            m_store.set_meta(name, m.type, m.help);
            m.dirty = false;
        }
    // What the last scrape had and this one did not ends at this one's time; what is long unseen leaves the cache.
    uint64_t live = 0;
    for (auto it = t.cache.begin(); it != t.cache.end();)
    {
        auto& e = it->second;
        if (e.seen == n)
            ++live;
        else if (e.seen == t.ok_n && e.id != no_series && t.ok_n != 0)
            m_store.mark_stale(e.id, t.stamp);
        if (e.seen + 10 < n)
            it = t.cache.erase(it);
        else
            ++it;
    }
    t.ok_n = n;
    t.series = live;
    t.up = true;
    t.tried = true;
    t.last_error.clear();
    t.last_samples = k.samples;
    put_up(t, 1, std::chrono::duration<double>(std::chrono::steady_clock::now() - t.began).count(),
           static_cast<double>(k.samples));
}

void scraper::fail(target& t, std::string why)
{
    ++m_fig.failures;
    ++t.n;
    // A target that does not answer has all its series end, as a series it no longer sends does.
    if (t.ok_n != 0)
        for (const auto& [k, e] : t.cache)
            if (e.seen == t.ok_n && e.id != no_series)
                m_store.mark_stale(e.id, t.stamp);
    t.ok_n = 0;
    t.series = 0;
    if (t.up || !t.tried || t.last_error != why)
        LOG_WARN(("metrics " + m_owner + ": the target " + t.cfg.name + " (" + t.cfg.url + ") is down: " + why).c_str());
    t.up = false;
    t.tried = true;
    t.last_error = std::move(why);
    t.last_samples = 0;
    put_up(t, 0, std::chrono::duration<double>(std::chrono::steady_clock::now() - t.began).count(), 0);
}

void scraper::put_up(target& t, double up, double secs, double samples)
{
    t.last_ms = t.began_ms;
    t.last_secs = secs;
    if (t.up_id != no_series)
        m_store.append(t.up_id, t.stamp, up);
    if (t.dur_id != no_series)
        m_store.append(t.dur_id, t.stamp, secs);
    if (t.samples_id != no_series)
        m_store.append(t.samples_id, t.stamp, samples);
}

void scraper::tick(int64_t now)
{
    const auto steady = std::chrono::steady_clock::now();
    for (auto& t : m_targets)
    {
        if (!t->peer)
            continue;
        if (t->running && now - t->began_ms > t->cfg.timeout_ms)
        {
            // Ended here, which tells the scrape it failed; the connection goes with it, a new one for the next.
            t->timed_out = true;
            auto peer = std::move(t->peer);
            peer->stop();
            continue;
        }
        t->peer->tick(steady);
    }
}

void scraper::targets_json(std::string& out, bool& first) const
{
    for (const auto& t : m_targets)
    {
        out += first ? "" : ",";
        first = false;
        const auto& w = t->cfg.where;
        out += "{\"discoveredLabels\":{\"__address__\":";
        json::quote_into(out, t->instance);
        out += ",\"__metrics_path__\":";
        json::quote_into(out, w.path.empty() ? std::string_view("/") : std::string_view(w.path));
        out += ",\"__scheme__\":";
        out += w.tls ? "\"https\"" : "\"http\"";
        out += ",\"job\":";
        json::quote_into(out, t->cfg.name);
        out += "},\"labels\":{";
        bool f = true;
        label_set ls = t->cfg.labels;
        ls.push_back({"instance", t->instance});
        ls.push_back({"job", t->cfg.name});
        std::sort(ls.begin(), ls.end(), [](const label& a, const label& b) { return a.name < b.name; });
        for (const auto& l : ls)
        {
            out += f ? "" : ",";
            f = false;
            json::quote_into(out, l.name);
            out += ':';
            json::quote_into(out, l.value);
        }
        out += "},\"scrapePool\":";
        json::quote_into(out, t->cfg.name);
        out += ",\"scrapeUrl\":";
        json::quote_into(out, t->cfg.url);
        out += ",\"globalUrl\":";
        json::quote_into(out, t->cfg.url);
        out += ",\"lastError\":";
        json::quote_into(out, t->last_error);
        out += ",\"lastScrape\":";
        json::quote_into(out, t->tried ? format_rfc3339(t->last_ms) : std::string("0001-01-01T00:00:00Z"));
        out += ",\"lastScrapeDuration\":";
        format_value(t->last_secs, out);
        out += ",\"health\":";
        out += !t->tried ? "\"unknown\"" : t->up ? "\"up\"" : "\"down\"";
        out += ",\"scrapeInterval\":";
        json::quote_into(out, format_duration_ms(t->cfg.every_ms));
        out += ",\"scrapeTimeout\":";
        json::quote_into(out, format_duration_ms(t->cfg.timeout_ms));
        out += '}';
    }
}

void scraper::targets_text(std::string& out) const
{
    for (const auto& t : m_targets)
    {
        out += t->cfg.name;
        out += '\t';
        out += t->cfg.url;
        out += '\t';
        out += !t->tried ? "unknown" : t->up ? "up" : "down";
        out += "\tevery ";
        out += format_duration_ms(t->cfg.every_ms);
        out += '\t';
        out += std::to_string(t->series) + " series";
        if (t->tried)
        {
            char buf[48];
            std::snprintf(buf, sizeof buf, "\t%.3fs", t->last_secs);
            out += buf;
        }
        if (!t->last_error.empty())
            out += "\t" + t->last_error;
        out += '\n';
    }
}

}   // namespace socketley::metrics
