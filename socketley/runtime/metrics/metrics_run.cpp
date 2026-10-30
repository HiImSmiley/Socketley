#include "metrics_run.h"
#include "../../shared/persist/private_dir.h"

#include <algorithm>
#include <arpa/inet.h>
#include <charconv>

#include "metrics_instance.h"
#include "metrics_remote.h"
#include "../../shared/crypto/mac.h"
#include "../../shared/http/http_framing.h"
#include "../../shared/http/request_head.h"
#include "../../shared/http/status.h"
#include "../../shared/http/url.h"
#include "../../shared/ipc/worker_protocol.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/runtime/runtime_manager.h"
#include "../../shared/util/base64.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/wall_clock.h"

namespace socketley::metrics
{

namespace
{

constexpr int64_t idle_secs = 120;
constexpr size_t  max_head  = 16 * 1024;
constexpr size_t  max_body  = 1u << 20;
// A remote_write batch, which a Prometheus sends compressed and a few MiB at most.
constexpr size_t  max_write = 16u << 20;
constexpr size_t  max_conns = 256;
// The longest the timer sleeps, so idle connections are swept and a file changed is seen.
constexpr int64_t max_sleep_ms = 60'000;
// How often a scrape in flight is looked at for its timeout and a stalled connection.
constexpr int64_t watch_ms = 1000;
// How often --rules is looked at for a change.
constexpr int64_t rules_check_ms = 10'000;

// The first time after `now` that is a whole multiple of `every`.
int64_t aligned_after(int64_t now, int64_t every)
{
    return (now / every + 1) * every;
}

}   // namespace

bool api_params::get(std::string_view name, std::string_view& out) const
{
    for (const auto& [k, v] : kv)
        if (k == name)
        {
            out = v;
            return true;
        }
    return false;
}

void api_params::all(std::string_view name, std::vector<std::string_view>& out) const
{
    for (const auto& [k, v] : kv)
        if (k == name)
            out.push_back(v);
}

bool api_params::add_form(std::string_view form)
{
    bool ok = true;
    socketley::http::for_each_pair(form, [&](std::string_view k, std::string_view v) {
        std::string dk, dv;
        if (!socketley::http::percent_decode(k, dk, true) || !socketley::http::percent_decode(v, dv, true))
        {
            ok = false;
            return;
        }
        kv.emplace_back(std::move(dk), std::move(dv));
    });
    return ok;
}

metrics_run::metrics_run(metrics_instance& owner, event_loop& loop)
    : m_owner(owner), m_loop(loop), m_io(loop, this), m_http(loop, this, owner, *this, max_conns), m_engine(m_store),
      m_local(m_store), m_scrape(loop, m_io, m_resolver, m_store, std::string(owner.get_name())),
      m_archive(loop, m_io, m_resolver, std::string(owner.get_name()))
{
}

metrics_run::~metrics_run()
{
    m_scrape.stop();
    m_archive.stop();
    m_resolver.stop();
    m_loop.deregister_owner(this);
}

bool metrics_run::start(std::string& why)
{
    m_every_ms = static_cast<int64_t>(m_owner.get_every()) * 1000;
    store_config cfg;
    cfg.keep_raw = static_cast<int64_t>(m_owner.get_keep()) * 1000;
    std::vector<std::pair<int64_t, int64_t>> tiers;
    if (!parse_downsample(m_owner.get_downsample(), tiers, why))
        return false;
    cfg.tiers.clear();
    for (const auto& [step, keep] : tiers)
        cfg.tiers.push_back({step, keep});
    cfg.max_series = m_owner.get_max_series();
    cfg.durable = m_owner.get_durable();
    const std::string dir = metrics_data_dir(m_owner.get_name());
    // <state>/metrics/ is shared by every metrics runtime and made by the first.
    if (const std::string parent = dir.substr(0, dir.rfind('/')); !socketley::private_dir(parent, true))
        return why = parent + " is not a directory of this user's alone", false;
    if (!m_store.open(dir, cfg, why))
        return false;
    m_opened = true;

    if (const std::string keys(m_owner.get_keys_path()); !keys.empty())
    {
        m_keys.set_path(keys);
        if (!m_keys.refresh([](auto& out, std::string_view text, std::string& w) {
                return socketley::db::parse_keys(text, out, w);
            }, why))
            return false;
    }
    m_idp.configure(m_owner.get_idp(), m_owner.get_idp_audience());
    if (!m_resolver.attach(m_io))
        m_resolver.stop();
    if (const std::string path(m_owner.get_scrape_path()); !path.empty() && !m_scrape.configure(path, m_every_ms, why))
        return false;
    char host[256] = {};
    if (::gethostname(host, sizeof host - 1) == 0)
        m_host = host;
    m_rules = std::make_unique<rule_engine>(m_store, rule_hooks{
        [this](const label_set& ls) { return m_store.get_or_create(ls); },
        [this](uint32_t id, int64_t t, double v) {
            if (is_stale(v))
                m_store.mark_stale(id, t);
            else
                m_store.append(id, t, v);
        },
        [this](const alert_event& e) { on_alert(e); }});
    // A rules file that does not read is said and the built-in rules run, so a typo does not stop the monitoring.
    if (std::string bad; !load_rules(bad))
    {
        LOG_ERROR(("metrics " + std::string(m_owner.get_name()) + ": " + bad + "; the built-in rules run until it reads")
                      .c_str());
        if (!m_rules->load({}, {}, why))
            return false;
    }
    if (const std::string url(m_owner.get_archive()); !url.empty())
    {
        if (!m_archive.configure(url, std::string(m_owner.get_archive_credentials()), dir, why))
            return false;
        m_archive_due = 0;
    }
    if (m_owner.get_logs())
    {
        if (!m_logs.open(dir + "/logs", static_cast<int64_t>(m_owner.get_logs_keep()) * 1000, why))
            return false;
        m_local.keep_logs(&m_logs);
    }
    m_rules->persist_at(dir + "/alerts", wall::now_ms_coarse());

    // Loopback unless --bind names another address, which config_refusal() lets through only behind --keys or --idp.
    const uint32_t addr = m_owner.get_bind_address().empty() ? htonl(INADDR_LOOPBACK) : m_owner.bind_in_addr();
    if (!m_http.listen_tcp(addr, m_owner.effective_port(), false, why))
        return false;
    m_loop.register_owner(this);
    m_http.start_accepting();

    const int64_t now = wall::now_ms_coarse();
    m_started_ms = now;
    m_store_due = m_store.tick(now);
    if (m_owner.get_local())
    {
        // A first look at once, so a runtime just started answers with this daemon's series rather than nothing.
        pull_local(now, true, now);
        m_local_next = aligned_after(now, m_every_ms);
    }
    else
        m_local_next = INT64_MAX;
    arm_tick();
    LOG_INFO(("metrics " + std::string(m_owner.get_name()) + ": " + std::to_string(m_store.stats().series) +
              " series, " + (m_owner.get_local() ? "this daemon every " + std::to_string(m_owner.get_every()) + "s"
                                                 : std::string("no local feed")) +
              ", " + std::to_string(m_scrape.size()) + " target(s)")
                 .c_str());
    return true;
}

void metrics_run::stop()
{
    if (m_stopped)
        return;
    m_stopped = true;
    m_scrape.stop();
    m_archive.stop();
    m_http.stop();
    if (m_rules)
        m_rules->flush(wall::now_ms_coarse());
    m_logs.close();
    if (m_tick_armed)
        if (!m_loop.submit_timeout_remove(&m_tick_req)) {}
    if (m_opened)
        m_store.stop();
    m_opened = false;
}

bool metrics_run::drained() const
{
    return m_loop.owner_drained(this);
}

void metrics_run::on_loop_turn()
{
    if (m_stopped)
        return;
    m_http.on_loop_turn();
}

void metrics_run::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req)
        return;
    if (file_io::owns_type(req->type))
    {
        m_io.on_cqe(cqe);
        return;
    }
    if (req == &m_tick_req)
    {
        m_tick_armed = false;
        if (!m_stopped)
            tick();
        return;
    }
    m_http.on_cqe(req, cqe);
}

// ─── The tick ───────────────────────────────────────────────────────────────

void metrics_run::arm_tick()
{
    if (m_tick_armed || m_stopped)
        return;
    const int64_t now = wall::now_ms_coarse();
    int64_t at = std::min({m_local_next, m_scrape.next_due(), m_store_due, m_rules_due, m_archive_due,
                           now + max_sleep_ms});
    if (m_scrape.busy() || m_store.busy())
        at = std::min(at, now + watch_ms);
    const int64_t delay = std::max<int64_t>(at - now, 1);
    m_tick_at = at;
    m_tick_req = io_request{};
    m_tick_req.owner = this;
    m_tick_req.type = op_timeout;
    m_tick_ts = {delay / 1000, (delay % 1000) * 1000000};
    m_tick_armed = m_loop.submit_timeout(&m_tick_ts, &m_tick_req);
}

void metrics_run::tick()
{
    const int64_t now = wall::now_ms_coarse();
    ++m_c.ticks;
    // A timer is a millisecond or two early by the coarse clock, which is still the same tick.
    if (m_local_next <= now + 2)
    {
        const int64_t stamp = m_local_next;
        m_local_next = aligned_after(std::max(now, stamp), m_every_ms);
        pull_local(stamp, false, now);
    }
    m_scrape.refresh(m_every_ms);
    m_scrape.run_due(now);
    m_scrape.tick(now);
    if (m_store_due <= now + 2 || m_store.busy())
        m_store_due = m_store.tick(now);
    if (now - m_rules_checked >= rules_check_ms)
    {
        m_rules_checked = now;
        if (std::string why; !load_rules(why))
            LOG_WARN(("metrics " + std::string(m_owner.get_name()) + ": " + why + "; the rules before stay").c_str());
    }
    if (m_rules && m_rules_due <= now + 2)
        m_rules_due = m_rules->eval(now);
    if (const uint64_t blocks = m_store.stats().blocks; m_archive.enabled() && blocks != m_blocks_seen)
    {
        m_blocks_seen = blocks;
        m_archive.poke();
        m_archive_due = now;
    }
    if (m_archive_due <= now + 2)
        m_archive_due = m_archive.tick(now);
    if (m_logs.is_open())
    {
        m_logs.flush();
        if (now - m_logs_retained >= 3'600'000)
        {
            m_logs_retained = now;
            m_logs.retain(now);
        }
    }
    m_http.sweep(now / 1000, idle_secs);
    arm_tick();
}

namespace
{

// A WriteRequest's series into the store, each refused one counted rather than failing the rest.
struct write_into final : remote::write_sink
{
    store& st;
    label_set ls;
    uint64_t appended{0}, refused{0};
    explicit write_into(store& s) : st(s) {}

    void on_series(const remote::series& s) override
    {
        ls.clear();
        for (const auto& l : s.labels)
            if (!l.value.empty())
                ls.push_back({std::string(l.name), std::string(l.value)});
        std::sort(ls.begin(), ls.end(), [](const label& a, const label& b) { return a.name < b.name; });
        const uint32_t id = st.get_or_create(ls);
        if (id == no_series)
        {
            refused += s.samples.size();
            return;
        }
        for (const auto& x : s.samples)
            (st.append(id, x.timestamp_ms, x.value) ? appended : refused) += 1;
    }
    void on_metadata(const remote::metadata& m) override
    {
        static constexpr metric_type types[] = {metric_type::untyped, metric_type::counter, metric_type::gauge,
                                                metric_type::histogram, metric_type::histogram, metric_type::summary};
        st.set_meta(m.family, m.type < std::size(types) ? types[m.type] : metric_type::untyped, m.help);
    }
};

}   // namespace

bool metrics_run::receive(std::string_view body, std::string& why)
{
    write_into into(m_store);
    const remote::decode_result r = m_remote.decode_snappy(body, into);
    if (!r.ok)
        return why = std::string("not a remote_write request: ") + (r.error ? r.error : "it does not read"), false;
    m_c.received += into.appended;
    m_c.received_refused += into.refused;
    // Samples of a window long past are cut at the store's next look, which a sender of old ones should not wait for.
    m_store_due = std::min(m_store_due, wall::now_ms_coarse() + 1000);
    return true;
}

std::string metrics_run::alert_json(const alert_event& e) const
{
    return "{\"id\":" + socketley::json::quote(e.id()) + ",\"level\":" + socketley::json::quote(e.severity) +
           ",\"runtime\":" + socketley::json::quote(label_value(e.labels, "name")) +
           ",\"title\":" + socketley::json::quote(e.annotation("summary")) +
           ",\"detail\":" + socketley::json::quote(e.annotation("description")) +
           ",\"since\":" + std::to_string((e.fired_at ? e.fired_at : e.active_at) / 1000) +
           ",\"source\":" + socketley::json::quote(m_owner.get_name()) + "}";
}

void metrics_run::dashboard_alerts(std::string& out) const
{
    // What the page lists: firing alerts nothing inhibits, critical first and the newest first within a level.
    std::vector<std::pair<std::pair<bool, int64_t>, std::string>> active;
    if (m_rules)
        m_rules->each_alert([&](const alert_event& e) {
            if (e.to == alert_state::firing && !e.inhibited)
                active.push_back({{e.severity != "critical", -e.fired_at}, alert_json(e)});
        });
    std::sort(active.begin(), active.end(), [](const auto& x, const auto& y) { return x.first < y.first; });
    out += "{\"active\":[";
    for (size_t i = 0; i < active.size(); ++i)
        out += (i ? "," : "") + active[i].second;
    out += "],\"recent\":[";
    for (size_t i = m_recent.size(); i-- > 0;)
    {
        const auto& r = m_recent[i];
        out += i + 1 == m_recent.size() ? "{\"at\":" : ",{\"at\":";
        out += std::to_string(r.at) + ",\"raised\":" + (r.raised ? "true" : "false") + ",\"alert\":" + r.alert + "}";
    }
    out += "]}";
}

bool metrics_run::load_rules(std::string& why)
{
    const std::string path(m_owner.get_rules_path());
    std::optional<socketley::file_stamp> st;
    if (!path.empty())
        st = socketley::file_stamp::of(path);
    if ((m_rules->rule_count() > 0 && st == m_rules_stamp) || (m_rules_refused && st == m_rules_refused))
        return true;
    // A file that did not read is said once, not again until it changes.
    m_rules_refused = st;
    std::string text;
    if (!path.empty() && !socketley::read_file(path, text))
        return why = path + " does not read", false;
    if (!m_rules->load(text, path, why))
        return why = (path.empty() ? std::string("the built-in rules") : path) + ": " + why, false;
    m_rules_stamp = st;
    m_rules_refused.reset();
    m_rules_due = 0;
    return true;
}

void metrics_run::on_alert(const alert_event& e)
{
    if (!e.notify)
        return;
    const bool raised = e.to == alert_state::firing;
    // An alert over this daemon's series is said to be from this machine, one over a target's from the target.
    const std::string_view job = label_value(e.labels, "job");
    const std::string host = job.empty() || job == "socketley" ? m_host : std::string(job);
    const std::string id = e.id();
    const std::string a = alert_json(e);
    const std::string text = notification_text(e, host);
    std::string body = "{\"content\":" + socketley::json::quote(text) + ",\"text\":" + socketley::json::quote(text) +
                       ",\"state\":" + socketley::json::quote(raised ? "firing" : "resolved") +
                       ",\"host\":" + socketley::json::quote(host) + ",\"alert\":" + a + "}";
    std::string sub = "alerts/" + id;
    std::replace_if(sub.begin(), sub.end(), [](char c) { return c == '+' || c == '#'; }, '_');
    m_recent.push_back({wall::now_ms_coarse() / 1000, raised, a});
    if (m_recent.size() > max_recent)
        m_recent.pop_front();
    if (raised)
        LOG_WARN(("metrics " + std::string(m_owner.get_name()) + ": alert: " + text).c_str());
    else
        LOG_INFO(("metrics " + std::string(m_owner.get_name()) + ": alert resolved: " + text).c_str());
    const uint8_t to = notify_mask(m_owner.get_notify());
    if (to != 0 && !m_owner.send_to_daemon(worker_proto::frame(
                       worker_proto::frame_type::alert_note,
                       worker_proto::encode_alert_note(to, sub, raised ? a : std::string(), body))))
        LOG_WARN(("metrics " + std::string(m_owner.get_name()) + ": the daemon did not take an alert's notification").c_str());
}

void metrics_run::pull_local(int64_t stamp, bool extra, int64_t now)
{
    const std::string frame = m_local.pull(stamp, extra, now);
    if (frame.empty())
    {
        if (extra)
            m_extra_owed = true;
        return;
    }
    if (!m_owner.send_to_daemon(frame))
        m_local.refused(stamp);
}

void metrics_run::on_series_feed(std::string_view payload)
{
    if (m_stopped)
        return;
    m_local.on_feed(payload);
    if (m_extra_owed)
    {
        m_extra_owed = false;
        const int64_t now = wall::now_ms_coarse();
        // Asked only away from the next tick, which would carry the change a moment later anyway.
        if (m_local_next - now > 50)
            pull_local(now, true, now);
    }
}

void metrics_run::on_runtime_map(std::string_view payload)
{
    if (m_stopped || !m_owner.get_local() || !m_local.runtimes_changed(payload))
        return;
    const int64_t now = wall::now_ms_coarse();
    // A runtime that came, went or changed state is in the store now, not at the next tick.
    if (m_local_next - now > 50)
        pull_local(now, true, now);
}

// ─── Connections ────────────────────────────────────────────────────────────

std::shared_ptr<socketley::http::server_conn> metrics_run::make_conn()
{
    return std::make_shared_for_overwrite<socketley::http::server_conn>();
}

void metrics_run::serve(const std::shared_ptr<socketley::http::server_conn>& c)
{
    while (!c->dead && !c->in.empty())
    {
        request rq;
        int refusal = 400;
        const int r = take_request(*c, rq, refusal);
        if (r == 0)
            break;
        if (r < 0)
        {
            c->keep_alive = false;
            respond(*c, refusal, "application/json",
                    R"({"status":"error","errorType":"bad_data","error":"the request could not be read"})");
            break;
        }
        runtime_instance::stat_add(m_owner.m_stat_total_messages, 1);
        handle(c, rq);
    }
}

int metrics_run::take_request(socketley::http::server_conn& c, request& rq, int& refusal)
{
    socketley::http::request_view v;
    const int r = socketley::http::take_request(c.in, max_head, m_owner.get_receive() ? max_write : max_body, v, refusal,
                                                [&rq](std::string_view f, std::string_view value) {
        if (header_name_equals(f, "authorization", 13))
            rq.authorization.assign(value);
        else if (header_name_equals(f, "cookie", 6))
        {
            if (!rq.cookie.empty())
                rq.cookie += "; ";
            rq.cookie.append(value);
        }
        else if (header_name_equals(f, "content-type", 12))
            rq.content_type.assign(value);
    });
    if (r <= 0)
        return r;
    rq.method.assign(v.method);
    rq.path.assign(v.path);
    rq.query.assign(v.query);
    rq.body.assign(c.in, v.head_len, v.body_len);
    c.in.erase(0, v.head_len + v.body_len);
    c.keep_alive = !v.close;
    return 1;
}

void metrics_run::respond(socketley::http::server_conn& c, int status, std::string_view type, std::string_view body)
{
    char num[24];
    std::string& o = c.out;
    o += "HTTP/1.1 ";
    o.append(num, static_cast<size_t>(std::to_chars(num, num + sizeof num, status).ptr - num));
    o += ' ';
    o += socketley::http::status_text(status);
    o += "\r\nContent-Type: ";
    o += type;
    o += "\r\nContent-Length: ";
    o.append(num, static_cast<size_t>(std::to_chars(num, num + sizeof num, body.size()).ptr - num));
    o += "\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n";
    if (status == 401)
        o += "WWW-Authenticate: Basic realm=\"metrics\"\r\n";
    if (!c.keep_alive)
        o += "Connection: close\r\n";
    o += "\r\n";
    o += body;
}

bool metrics_run::admitted(const request& rq)
{
    if (!m_owner.guarded())
        return true;
    if (const int64_t now = wall::now_sec_coarse(); m_keys.configured() && now != m_keys_checked)
    {
        m_keys_checked = now;
        std::string why;
        if (!m_keys.refresh([](auto& out, std::string_view text, std::string& w) {
                return socketley::db::parse_keys(text, out, w);
            }, why))
            LOG_ERROR(("metrics " + std::string(m_owner.get_name()) + ": " + why + "; the keys before are kept").c_str());
    }
    std::string_view cred;
    if (http_auth_credentials(rq.authorization, "bearer", cred))
    {
        for (const auto& k : m_keys.value())
            if (socketley::crypto::secure_equal(k.secret, cred))
                return true;
        socketley::idp::session_verifier::who w;
        return m_idp.check_bearer(cred, w);
    }
    // Basic, as Grafana's data source sends it: a key's name and its secret.
    if (http_auth_credentials(rq.authorization, "basic", cred))
    {
        std::string plain;
        if (!socketley::base64::decode(cred, plain))
            return false;
        const size_t colon = plain.find(':');
        if (colon == std::string::npos)
            return false;
        const std::string_view user = std::string_view(plain).substr(0, colon);
        const std::string_view pass = std::string_view(plain).substr(colon + 1);
        bool ok = false;
        for (const auto& k : m_keys.value())
            ok |= k.name == user && socketley::crypto::secure_equal(k.secret, pass);
        return ok;
    }
    socketley::idp::session_verifier::who w;
    return !rq.cookie.empty() && m_idp.check(rq.cookie, w);
}

void metrics_run::handle(const std::shared_ptr<socketley::http::server_conn>& c, request& rq)
{
    ++m_c.requests;
    api_reply out;
    if (rq.path == "/-/healthy" || rq.path == "/-/ready")
    {
        respond(*c, 200, "text/plain; charset=utf-8",
                rq.path == "/-/healthy" ? "Prometheus Server is Healthy.\n" : "Prometheus Server is Ready.\n");
        return;
    }
    if (rq.method != "GET" && rq.method != "POST")
    {
        respond(*c, 405, "application/json",
                R"({"status":"error","errorType":"bad_data","error":"the API takes GET and POST"})");
        return;
    }
    if (!admitted(rq))
    {
        ++m_c.unauthorized;
        respond(*c, 401, "application/json",
                R"({"status":"error","errorType":"unauthorized","error":"a key of --keys, or a sign-in of --idp, is needed"})");
        return;
    }
    // A checkpoint is the daemon's to ask, for an export, and no client's.
    if (rq.path.starts_with("/-/checkpoint"))
        return respond(*c, 404, "text/plain; charset=utf-8", "no such path\n");
    if (rq.path == "/api/v1/write")
    {
        if (!m_owner.get_receive())
            return respond(*c, 404, "text/plain; charset=utf-8", "remote_write is taken with --receive\n");
        if (rq.method != "POST")
            return respond(*c, 405, "text/plain; charset=utf-8", "remote_write is a POST\n");
        std::string why;
        if (!receive(rq.body, why))
        {
            ++m_c.refused;
            return respond(*c, 400, "text/plain; charset=utf-8", why + "\n");
        }
        return respond(*c, 204, {}, {});
    }
    api_params p;
    bool ok = p.add_form(rq.query);
    if (rq.method == "POST" && rq.content_type.starts_with("application/x-www-form-urlencoded"))
        ok = ok && p.add_form(rq.body);
    if (!ok)
    {
        respond(*c, 400, "application/json",
                R"({"status":"error","errorType":"bad_data","error":"a parameter's escape is no escape"})");
        return;
    }
    api(rq.path, p, out, false);
    if (out.status >= 400)
        ++m_c.refused;
    respond(*c, out.status, out.type, out.body);
}

void metrics_run::call(uint64_t ticket, std::string_view payload)
{
    // text|json \n path \n form
    const size_t a = payload.find('\n');
    const size_t b = a == std::string_view::npos ? a : payload.find('\n', a + 1);
    auto* mgr = m_owner.get_runtime_manager();
    if (!mgr)
        return;
    if (b == std::string_view::npos)
    {
        mgr->requests().complete_deferred(ticket, request_status::ok, "400\nthe command could not be read\n");
        return;
    }
    const bool text = payload.substr(0, a) == "text";
    api_params p;
    api_reply out;
    if (!p.add_form(payload.substr(b + 1)))
        out = {400, "a parameter could not be read\n"};
    else
        api(payload.substr(a + 1, b - a - 1), p, out, text);
    mgr->requests().complete_deferred(ticket, request_status::ok, std::to_string(out.status) + "\n" + out.body);
}

std::string metrics_run::stats() const
{
    const store_stats s = m_store.stats();
    const local_stats& l = m_local.stats();
    const scrape_figures& f = m_scrape.figures();
    return "series:" + std::to_string(s.series) + "\nhead_series:" + std::to_string(s.head_series) +
           "\nmaintenance_held:" + std::to_string(s.held ? 1 : 0) +
           "\nlog_lines:" + std::to_string(m_logs.stats().lines) +
           "\nlog_bytes_on_disk:" + std::to_string(m_logs.stats().bytes_on_disk) +
           "\nlog_files:" + std::to_string(m_logs.stats().files) +
           "\nsamples:" + std::to_string(s.samples_appended) + "\nrefused_series:" + std::to_string(s.refused_series) +
           "\nrefused_out_of_order:" + std::to_string(s.refused_out_of_order) +
           "\nrefused_too_old:" + std::to_string(s.refused_too_old) + "\nbytes_on_disk:" + std::to_string(s.bytes_on_disk) +
           "\nbytes_in_ram:" + std::to_string(s.bytes_in_ram) + "\nblocks:" + std::to_string(s.blocks) +
           "\nhead_chunks:" + std::to_string(s.head_chunks) +
           "\nmaintenance_failures:" + std::to_string(s.maintenance_failures) +
           "\nlocal:" + (m_owner.get_local() ? "1" : "0") + "\nlocal_series:" + std::to_string(l.series) +
           "\nlocal_frames:" + std::to_string(l.frames) + "\nlocal_bytes:" + std::to_string(l.bytes) +
           "\nlocal_resyncs:" + std::to_string(l.resyncs) + "\nlocal_lost:" + std::to_string(l.lost) +
           "\nlocal_extra:" + std::to_string(l.extra) + "\ntargets:" + std::to_string(m_scrape.size()) +
           "\ntargets_up:" + std::to_string(m_scrape.up()) + "\nscrapes:" + std::to_string(f.scrapes) +
           "\nscrape_failures:" + std::to_string(f.failures) + "\nscraped_samples:" + std::to_string(f.samples) +
           "\nscrape_series_refused:" + std::to_string(f.series_refused) +
           "\nscrape_lines_refused:" + std::to_string(f.lines_refused) + "\nrequests:" + std::to_string(m_c.requests) +
           "\nqueries:" + std::to_string(m_c.queries) + "\nrefused:" + std::to_string(m_c.refused) +
           "\nunauthorized:" + std::to_string(m_c.unauthorized) + "\nticks:" + std::to_string(m_c.ticks) +
           "\nreceived_samples:" + std::to_string(m_c.received) + "\nreceived_refused:" +
           std::to_string(m_c.received_refused) + "\nrules:" + std::to_string(m_rules ? m_rules->rule_count() : 0) +
           "\nalerts_active:" + std::to_string(m_rules ? m_rules->active_alerts() : 0) +
           "\narchived_blocks:" + std::to_string(m_archive.figures().blocks) +
           "\narchived_bytes:" + std::to_string(m_archive.figures().bytes) +
           "\narchive_failures:" + std::to_string(m_archive.figures().failures) + "\n";
}

}   // namespace socketley::metrics
