// The metrics runtime's rules without a socket: the line format and its errors, the built-in set laid under a file,
// pending to firing to resolved with for= and keep=, inhibition, templates, recording rules feeding later ones, the
// ALERTS series, the state kept across a reopen, and every built-in rule firing on series made for it.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <algorithm>
#include <filesystem>
#include <string>
#include <unistd.h>
#include <vector>

#include "runtime/metrics/metrics_rules.h"
#include "runtime/metrics/metrics_store.h"

using namespace socketley::metrics;
namespace fs = std::filesystem;

namespace
{

// 2026-01-01T00:00:00Z.
constexpr int64_t T0 = 1767225600000;

struct tmpdir
{
    std::string path;
    tmpdir()
    {
        char t[] = "/tmp/test_metrics_rules.XXXXXX";
        REQUIRE(::mkdtemp(t) != nullptr);
        path = t;
    }
    ~tmpdir() { fs::remove_all(path); }
};

label_set L(std::initializer_list<std::pair<const char*, const char*>> kv)
{
    label_set ls;
    for (const auto& [k, v] : kv)
        ls.push_back(label{k, v});
    std::sort(ls.begin(), ls.end(), [](const label& a, const label& b) { return a.name < b.name; });
    return ls;
}

struct seen
{
    std::string rule;
    alert_state to;
    bool notify;
    std::string text;
};

// A store in a temp dir, a rule engine over it, and every change it reports.
struct rig
{
    tmpdir dir;
    store st;
    std::vector<seen> events;
    std::unique_ptr<rule_engine> rules;

    rig()
    {
        std::string why;
        store_config c;
        c.tiers.clear();
        REQUIRE_MESSAGE(st.open(dir.path + "/db", c, why), why);
        make();
    }
    void make()
    {
        rules = std::make_unique<rule_engine>(st, rule_hooks{
            [this](const label_set& ls) { return st.get_or_create(ls); },
            [this](uint32_t id, int64_t t, double v) {
                if (is_stale(v))
                    st.mark_stale(id, t);
                else
                    st.append(id, t, v);
            },
            [this](const alert_event& e) {
                events.push_back({std::string(e.rule), e.to, e.notify, notification_text(e, "host")});
            }});
    }
    void put(const label_set& ls, int64_t t, double v)
    {
        const uint32_t id = st.get_or_create(ls);
        REQUIRE(id != no_series);
        st.append(id, t, v);
    }
    bool load(const std::string& text, std::string* why_out = nullptr)
    {
        std::string why;
        const bool r = rules->load(text, text.empty() ? "" : "/rules", why);
        if (why_out)
            *why_out = why;
        return r;
    }
    size_t notified(std::string_view rule, alert_state to) const
    {
        return static_cast<size_t>(std::count_if(events.begin(), events.end(), [&](const seen& s) {
            return s.rule == rule && s.to == to && s.notify;
        }));
    }
    std::string alerts() const
    {
        std::string o;
        rules->render_alerts(o);
        return o;
    }
};

}   // namespace

TEST_CASE("the rules file reads, and says where it does not")
{
    rule_file f;
    std::string why;
    CHECK(parse_rules("# nothing\n\nevery=30s\n", "f", f, why));
    CHECK(f.every_ms == 30000);
    CHECK(parse_rules("alert A warning for=1m keep=30s team=x summary=\"a {{ $value }}\"\n    : up == 0\n"
                      "record r:x : sum(up)\noff TargetDown\n",
                      "f", f, why));
    REQUIRE(f.rules.size() == 2);
    CHECK(f.rules[0].name == "A");
    CHECK(f.rules[0].for_ms == 60000);
    CHECK(f.rules[0].keep_ms == 30000);
    CHECK(f.rules[0].expr.find("up == 0") != std::string::npos);
    CHECK(f.rules[1].k == rule_def::kind::record);
    REQUIRE(f.off.size() == 1);
    CHECK(f.off[0].first == "TargetDown");

    CHECK_FALSE(parse_rules("alert A warning : sum(\n", "f", f, why));
    CHECK(why.starts_with("line 1:"));
    CHECK_FALSE(parse_rules("# c\nalert B warning for=soon : up\n", "f", f, why));
    CHECK(why.starts_with("line 2:"));
    CHECK_FALSE(parse_rules("frobnicate x : up\n", "f", f, why));
    CHECK_FALSE(parse_rules("alert A warning : up\nalert A warning : up\n", "f", f, why));
    CHECK_FALSE(parse_rules("alert A warning summary=\"{{ $value \" : up\n", "f", f, why));
    CHECK_FALSE(parse_rules("record r : rate(up[5m]\n", "f", f, why));

    rule_file b;
    REQUIRE(parse_rules(builtin_rules(), "builtin", b, why));
    CHECK(b.rules.size() >= 14);
    std::vector<rule_def> merged;
    rule_file u;
    REQUIRE(parse_rules("off NoSuchRule\n", "f", u, why));
    CHECK_FALSE(merge_rules(b, &u, merged, why));
    REQUIRE(parse_rules("alert A warning inhibits=Nope : up\n", "f", u, why));
    CHECK_FALSE(merge_rules(b, &u, merged, why));
}

TEST_CASE("the built-in set is laid under the file: replaced by name, left out with off")
{
    rig r;
    REQUIRE(r.load(""));
    const size_t builtin = r.rules->rule_count();
    CHECK(builtin >= 14);
    std::string why;
    REQUIRE_MESSAGE(r.load("alert RuntimeFailed warning : vector(1)\noff TargetDown\nalert Mine warning : vector(1)\n",
                           &why),
                    why);
    CHECK(r.rules->rule_count() == builtin);
    std::string rules;
    r.rules->render_rules(rules);
    CHECK(rules.find("\"name\":\"TargetDown\"") == std::string::npos);
    CHECK(rules.find("\"name\":\"Mine\"") != std::string::npos);
    CHECK(rules.find("\"query\":\"vector(1)\"") != std::string::npos);
    // A file that does not read leaves the rules as they were.
    CHECK_FALSE(r.load("alert Broken warning : sum(\n", &why));
    CHECK(r.rules->rule_count() == builtin);
}

TEST_CASE("pending, firing after for=, kept for keep=, then resolved and told once each")
{
    rig r;
    REQUIRE(r.load("every=10s\noff TargetDown\nalert Hot critical for=20s keep=20s summary=\"{{ $labels.name }} is "
                   "{{ $value }}\" : temp > 50\n"));
    const label_set s = L({{"__name__", "temp"}, {"name", "a"}});
    int64_t t = T0;
    const auto step = [&](double v) {
        r.put(s, t, v);
        r.rules->eval(t);
        t += 10000;
    };
    step(10);
    CHECK(r.alerts().find("\"state\"") == std::string::npos);
    step(60);   // pending
    CHECK(r.alerts().find("\"state\":\"pending\"") != std::string::npos);
    CHECK(r.notified("Hot", alert_state::firing) == 0);
    step(61);   // held 10s
    CHECK(r.notified("Hot", alert_state::firing) == 0);
    step(62);   // held 20s: firing
    CHECK(r.alerts().find("\"state\":\"firing\"") != std::string::npos);
    REQUIRE(r.notified("Hot", alert_state::firing) == 1);
    const auto fired = std::find_if(r.events.begin(), r.events.end(), [](const seen& e) { return e.notify; });
    CHECK(fired->text.find("host: a is 62") != std::string::npos);
    step(63);
    CHECK(r.notified("Hot", alert_state::firing) == 1);
    step(10);   // gone, kept
    step(10);   // still kept: 10s of 20s
    CHECK(r.notified("Hot", alert_state::inactive) == 0);
    step(10);
    step(10);
    CHECK(r.notified("Hot", alert_state::inactive) == 1);
    CHECK(r.alerts() == "{\"alerts\":[]}");
    // A blip shorter than for= is never told of.
    step(70);
    step(10);
    CHECK(r.notified("Hot", alert_state::firing) == 1);
}

TEST_CASE("a critical alert silences the warning on the same labels")
{
    rig r;
    REQUIRE(r.load("every=10s\noff TargetDown\nalert Full critical inhibits=Nearly : fill >= 0.98\n"
                   "alert Nearly warning : fill >= 0.90\n"));
    const label_set a = L({{"__name__", "fill"}, {"name", "a"}});
    const label_set b = L({{"__name__", "fill"}, {"name", "b"}});
    int64_t t = T0;
    r.put(a, t, 0.99);
    r.put(b, t, 0.95);
    r.rules->eval(t);
    CHECK(r.notified("Full", alert_state::firing) == 1);
    // b has no critical alert, so its warning is told; a's is not.
    CHECK(r.notified("Nearly", alert_state::firing) == 1);
    std::string active;
    r.rules->each_alert([&](const alert_event& e) {
        if (e.to == alert_state::firing && !e.inhibited)
            active += std::string(e.rule) + ":" + std::string(label_value(e.labels, "name")) + " ";
    });
    CHECK(active == "Full:a Nearly:b ");
}

TEST_CASE("a recording rule writes a series a later rule reads, and ALERTS follows the alerts")
{
    rig r;
    REQUIRE(r.load("every=10s\noff TargetDown\nrecord job:up:sum : sum(up)\n"
                   "alert FewUp warning : job:up:sum < 2\n"));
    int64_t t = T0;
    r.put(L({{"__name__", "up"}, {"job", "a"}}), t, 1);
    r.put(L({{"__name__", "up"}, {"job", "b"}}), t, 0);
    r.rules->eval(t);
    query_engine q(r.st);
    query_result res;
    query_error err;
    REQUIRE(q.eval_instant("job:up:sum", t, res, err));
    REQUIRE(res.series.size() == 1);
    CHECK(res.series[0].points[0].v == 1);
    CHECK(r.notified("FewUp", alert_state::firing) == 1);
    REQUIRE(q.eval_instant("ALERTS{alertname=\"FewUp\"}", t, res, err));
    REQUIRE(res.series.size() == 1);
    CHECK(label_value(res.series[0].labels, "alertstate") == "firing");
    REQUIRE(q.eval_instant("ALERTS_FOR_STATE{alertname=\"FewUp\"}", t, res, err));
    CHECK(res.series.size() == 1);
    t += 10000;
    r.put(L({{"__name__", "up"}, {"job", "b"}}), t, 1);
    r.put(L({{"__name__", "up"}, {"job", "a"}}), t, 1);
    r.rules->eval(t);
    CHECK(r.notified("FewUp", alert_state::inactive) == 1);
    REQUIRE(q.eval_instant("ALERTS{alertname=\"FewUp\"}", t + 1, res, err));
    CHECK(res.series.empty());
}

TEST_CASE("templates")
{
    rule_template tp;
    std::string why, out;
    const label_set ls = L({{"name", "web"}, {"path", "/srv"}});
    REQUIRE(parse_template("{{ $labels.name }} at {{ .Labels.path }}: {{ $value | humanizePercentage }}", tp, why));
    expand_template(tp, ls, 0.0725, out);
    CHECK(out == "web at /srv: 7.25%");
    out.clear();
    REQUIRE(parse_template("{{ humanize1024 $value }}B, {{ $value | printf \"%.1f\" }}, {{ $labels.none }}.", tp, why));
    expand_template(tp, ls, 2048, out);
    CHECK(out == "2kiB, 2048.0, .");
    out.clear();
    REQUIRE(parse_template("{{ $value | humanizeDuration }}", tp, why));
    expand_template(tp, ls, 90061, out);
    CHECK(out == "1d 1h 1m 1s");
    CHECK_FALSE(parse_template("{{ $value | shout }}", tp, why));
    CHECK_FALSE(parse_template("{{ $value", tp, why));
}

TEST_CASE("the alerts' state survives a reopen: no second notification, for= progress kept")
{
    rig r;
    const std::string rules = "every=10s\noff TargetDown\nalert Hot warning for=30s : temp > 50\n"
                              "alert Now warning : temp > 50\n";
    REQUIRE(r.load(rules));
    r.rules->persist_at(r.dir.path + "/alerts", T0);
    const label_set s = L({{"__name__", "temp"}, {"name", "a"}});
    int64_t t = T0;
    for (int i = 0; i < 2; ++i, t += 10000)
    {
        r.put(s, t, 60);
        r.rules->eval(t);
    }
    CHECK(r.notified("Now", alert_state::firing) == 1);
    CHECK(r.notified("Hot", alert_state::firing) == 0);
    r.rules->flush(t);
    r.events.clear();
    r.make();
    REQUIRE(r.load(rules));
    r.rules->persist_at(r.dir.path + "/alerts", t);
    for (int i = 0; i < 2; ++i, t += 10000)
    {
        r.put(s, t, 60);
        r.rules->eval(t);
    }
    CHECK(r.notified("Now", alert_state::firing) == 0);
    // Pending since T0+10s, so firing at T0+40s, the second evaluation after the reopen.
    CHECK(r.notified("Hot", alert_state::firing) == 1);
}

TEST_CASE("every built-in rule fires on series made for it")
{
    rig r;
    REQUIRE(r.load(""));
    const int64_t start = T0;
    struct fact
    {
        label_set ls;
        double v;
        double step;   // added each 10s, for a counter
    };
    const std::vector<fact> facts = {
        {L({{"__name__", "socketley_runtime_failure"}, {"name", "a"}, {"reason", "boom"}, {"type", "cache"}}), 1, 0},
        {L({{"__name__", "socketley_sync_failing"}, {"name", "s"}}), 3, 0},
        {L({{"__name__", "socketley_runtime_restarts_total"}, {"name", "a"}}), 0, 1},
        {L({{"__name__", "socketley_cert_expiry_seconds"}, {"name", "w"}, {"path", "/c"}}), -5, 0},
        {L({{"__name__", "socketley_cert_expiry_seconds"}, {"name", "x"}, {"path", "/d"}}), 2 * 86400, 0},
        {L({{"__name__", "socketley_cert_expiry_seconds"}, {"name", "y"}, {"path", "/e"}}), 10 * 86400, 0},
        {L({{"__name__", "socketley_disk_free_ratio"}, {"path", "/"}}), 0.03, 0},
        {L({{"__name__", "socketley_disk_free_ratio"}, {"path", "/b"}}), 0.08, 0},
        {L({{"__name__", "socketley_host_memory_available_ratio"}}), 0.04, 0},
        {L({{"__name__", "socketley_runtime_quota_ratio"}, {"name", "q"}, {"type", "storage"}}), 0.99, 0},
        {L({{"__name__", "socketley_runtime_quota_ratio"}, {"name", "r"}, {"type", "storage"}}), 0.92, 0},
        {L({{"__name__", "socketley_mail_queued"}, {"name", "m"}}), 1500, 0},
        {L({{"__name__", "socketley_mail_queued"}, {"name", "n"}}), 150, 0},
        {L({{"__name__", "socketley_mail_blocklisted"}, {"name", "m"}}), 1, 0},
        {L({{"__name__", "socketley_git_mirror_failed"}, {"id", "1"}, {"name", "g"}, {"repo", "r"}}), 1, 0},
        {L({{"__name__", "up"}, {"instance", "h:1"}, {"job", "j"}}), 0, 0},
        {L({{"__name__", "socketley_tunnel_agents_joined"}, {"name", "t"}}), 2, 0},
        {L({{"__name__", "socketley_tunnel_agents_connected"}, {"name", "t"}}), 1, 0},
        {L({{"__name__", "socketley_tunnel_datagrams_total"}, {"name", "t"}}), 0, 10},
        {L({{"__name__", "socketley_tunnel_datagrams_dropped_total"}, {"name", "t"}}), 0, 1},
        {L({{"__name__", "socketley_idp_sign_ins_barred_total"}, {"name", "i"}}), 0, 3},
    };
    for (int64_t t = start; t <= start + 10 * 60000; t += 10000)
    {
        for (const auto& f : facts)
            r.put(f.ls, t, f.v + f.step * static_cast<double>((t - start) / 10000));
        r.rules->eval(t);
    }
    for (const char* name : {"RuntimeFailed", "SyncFailing", "RuntimeRestarting", "CertificateEnded",
                             "CertificateExpiringSoon", "CertificateExpiring", "DiskSpaceCritical", "DiskSpaceLow",
                             "HostMemoryCritical", "QuotaFull", "QuotaNearlyFull", "MailQueueVeryLong",
                             "MailQueueLong", "MailBlocklisted", "GitPullFailed", "TargetDown", "TunnelAgentGone",
                             "TunnelDatagramsDropped", "IdpSignInsBarred"})
        CHECK_MESSAGE(r.notified(name, alert_state::firing) >= 1, name);
    // The warning beside a critical one on the same labels is silenced.
    std::string active;
    r.rules->each_alert([&](const alert_event& e) {
        if (e.to == alert_state::firing && !e.inhibited)
            active += std::string(e.rule) + ":" + std::string(label_value(e.labels, "path")) + " ";
    });
    CHECK(active.find("DiskSpaceLow:/ ") == std::string::npos);
    CHECK(active.find("DiskSpaceLow:/b ") != std::string::npos);
    CHECK(active.find("CertificateExpiring:/c ") == std::string::npos);
}

TEST_CASE("a label set empty is no part of the alert: a reason that changes words is the same alert")
{
    rig r;
    REQUIRE(r.load("every=10s\noff TargetDown\nalert Down critical reason=\"\" description=\"{{ $labels.reason }}\" "
                   ": failure == 1\n"));
    int64_t t = T0;
    r.put(L({{"__name__", "failure"}, {"name", "a"}, {"reason", "first words"}}), t, 1);
    r.rules->eval(t);
    t += 10000;
    // The daemon's feed ends a series whose labels changed, as here.
    r.st.mark_stale(r.st.find(L({{"__name__", "failure"}, {"name", "a"}, {"reason", "first words"}})), t);
    r.put(L({{"__name__", "failure"}, {"name", "a"}, {"reason", "other words"}}), t, 1);
    r.rules->eval(t);
    CHECK(r.notified("Down", alert_state::firing) == 1);
    const std::string a = r.alerts();
    CHECK(a.find("\"reason\"") == std::string::npos);
    CHECK(a.find("\"description\":\"other words\"") != std::string::npos);
}
