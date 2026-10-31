#pragma once
// The metrics runtime's recording and alerting rules: a line format beside --scrape and --keys, Prometheus's alerting
// semantics over the store's series, the built-in set that replaces the daemon's fixed alerts, the state that survives
// a restart, and the JSON of /api/v1/rules and /api/v1/alerts.
//
// ─── THE RULES FILE ──────────────────────────────────────────────────────────
//   # a comment, on a line of its own
//   every=30s                                  the interval of every rule without its own, 10s when none is given
//   record <metric> [key=value ...] : <promql>
//   alert <name> <severity> [key=value ...] : <promql>
//   off <name>                                 a built-in rule left out
//
// One rule a line; a line that starts with a space or a tab carries on the rule above it, and the expression is
// everything after the head's ` : `. A value is a word, or quoted with \" \\ \n \t inside. The keys:
//   every=<duration>    how often the rule is evaluated, on times that are whole multiples of it
//   for=<duration>      how long the condition holds before an alert fires; 0 by default
//   keep=<duration>     how long an alert keeps firing once its condition is gone, Prometheus's keep_firing_for
//   inhibits=<a>[,<b>]  alerts whose notifications this one silences while it fires, on the labels both share
//   summary=, description=, runbook_url=   annotations, templated
//   <label>=<value>     any other key is a label added to what the rule writes, templated; <label>="" takes it off
// A rule named like a built-in one takes its place; durations are Prometheus's (90s, 1h30m).
//
// Templates are a subset of Prometheus's: {{ $value }}, {{ $labels.<name> }} and {{ .Value }}, {{ .Labels.<name> }},
// each optionally through humanize, humanize1024, humanizePercentage, humanizeDuration or printf "<one verb>", as
// `{{ $value | humanize }}` or `{{ humanize $value }}`; a missing label is empty.
//
// ─── EVALUATION ──────────────────────────────────────────────────────────────
// eval(now) evaluates every rule that is due, in the order the set lists them: the built-ins with any replaced in place,
// then the file's own. A recording rule's samples are written before the next rule runs, so a later rule reads them.
// An alert is pending from the evaluation its condition first holds, firing once it has held for `for`, and resolved
// at the first evaluation it does not hold, or `keep` after that. ALERTS{alertname,alertstate,...} and
// ALERTS_FOR_STATE are written as Prometheus writes them, with a staleness marker when one ends.
//
// A notification is due when an alert fires and no firing alert that inhibits it shares its labels, and again when
// one told of is resolved: an alert inhibited when it fires is told of once nothing inhibits it any more, and one told
// of before an inhibitor began is resolved on its own.
//
// Thread-safety: one thread, the runtime's loop; the hooks are called from inside eval().
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "metrics_query.h"
#include "metrics_types.h"

namespace socketley::metrics
{

// One `{{ }}` or the text between them, ready to be expanded.
struct template_part
{
    enum class kind : uint8_t { text, value, label };
    enum class filter : uint8_t { none, humanize, humanize1024, percentage, duration, printf };
    kind k{kind::text};
    filter f{filter::none};
    // The text, a label's name, or printf's format.
    std::string s;
};

struct rule_template
{
    // The text as written.
    std::string raw;
    std::vector<template_part> parts;
    // The text itself when it holds no `{{`.
    bool plain{true};
};

// `text` read as a template, false with `why` where it is not one this subset reads.
bool parse_template(std::string_view text, rule_template& out, std::string& why);
// `t` expanded for a series' labels and its value, appended to `out`.
void expand_template(const rule_template& t, const label_set& labels, double value, std::string& out);

struct rule_def
{
    enum class kind : uint8_t { alert, record };

    kind k{kind::alert};
    std::string name;
    std::string expr;
    // An alert's severity, also its label `severity`.
    std::string severity;
    int64_t for_ms{0};
    int64_t keep_ms{0};
    // 0 for the set's default.
    int64_t every_ms{0};
    // In name order, values templated.
    std::vector<std::pair<std::string, rule_template>> labels;
    std::vector<std::pair<std::string, rule_template>> annotations;
    std::vector<std::string> inhibits;
    // "builtin" or the file's path, and the line the rule starts on.
    std::string source;
    uint32_t line{0};
};

struct rule_file
{
    // 0 when the file sets no `every=`.
    int64_t every_ms{0};
    std::vector<rule_def> rules;
    // The built-ins `off` names, with the lines that name them.
    std::vector<std::pair<std::string, uint32_t>> off;
};

// The text of a rules file read whole, every expression checked; false with `why` as "line N: ...".
bool parse_rules(std::string_view text, std::string_view source, rule_file& out, std::string& why);

// The built-in set in the same format: the daemon's alerts over the series its /metrics writes.
std::string_view builtin_rules();

// The built-ins with `user` laid over them, every rule's interval set, and every inhibition checked.
bool merge_rules(const rule_file& builtin, const rule_file* user, std::vector<rule_def>& out, std::string& why);

enum class alert_state : uint8_t { inactive, pending, firing };
std::string_view state_name(alert_state s);

// A change of one alert, as the notifier and the page are told of it.
struct alert_event
{
    std::string_view rule;
    std::string_view severity;
    // The alert's labels: the series', the rule's, alertname and severity.
    const label_set& labels;
    const std::vector<std::pair<std::string, std::string>>& annotations;
    double value{0};
    alert_state from{alert_state::inactive};
    alert_state to{alert_state::inactive};
    // Milliseconds; 0 for what has not happened.
    int64_t active_at{0};
    int64_t fired_at{0};
    int64_t resolved_at{0};
    // Whether a firing alert that inhibits this one shares its labels now.
    bool inhibited{false};
    // Whether a notification is due: this one firing and not yet told of, or one told of resolved.
    bool notify{false};

    // The rule and the values of the alert's own labels, as `rule:value:value`, the same every evaluation.
    std::string id() const;
    std::string_view annotation(std::string_view name) const;
};

// What the daemon's alerts sent: an emoji for the level or the resolution, the host, the summary, and the description
// on a line of its own, or " -- resolved".
std::string notification_text(const alert_event& e, std::string_view host);

struct rule_hooks
{
    // The handle of a series a rule writes, made when new; no_series when the store refuses it.
    std::function<uint32_t(const label_set&)> series;
    // A sample of a series `series` made, the staleness marker when it ends.
    std::function<void(uint32_t handle, int64_t t, double v)> append;
    // Every change of an alert, and an inhibited alert's notification once nothing inhibits it any more.
    std::function<void(const alert_event&)> on_change;
};

struct rules_filter
{
    bool alerts{true};
    bool records{true};
    // The alerts of each alerting rule left out of /api/v1/rules.
    bool exclude_alerts{false};
};

struct rule_stats
{
    uint64_t evaluations{0};
    uint64_t failures{0};
    uint64_t samples_written{0};
    uint64_t notifications{0};
};

class rule_engine
{
public:
    // Rules read `source` through an engine of their own, under limits tighter than a dashboard's.
    rule_engine(series_source& source, rule_hooks hooks);
    ~rule_engine();
    rule_engine(const rule_engine&) = delete;
    rule_engine& operator=(const rule_engine&) = delete;

    // The built-ins and `user_text`, read from `source` (empty for none), take the place of the rules there were; an
    // alert of a rule that keeps its name keeps its state. False with `why`, the rules left as they were.
    bool load(std::string_view user_text, std::string_view source, std::string& why);

    // Where the alerts' state is kept: what is there read back now, a pending alert's progress only when it was
    // written less than an hour before `now`, and written again whenever an alert changes.
    void persist_at(std::string path, int64_t now);
    // The state written now, as at a stop.
    void flush(int64_t now);

    // Every rule due by `now` evaluated; the time the next one is due.
    int64_t eval(int64_t now);

    // The `data` member of /api/v1/rules and of /api/v1/alerts, appended to `out`.
    void render_rules(std::string& out, const rules_filter& f = {}) const;
    void render_alerts(std::string& out) const;
    // Every pending and firing alert as it stands, `from` and `to` both its state.
    void each_alert(const std::function<void(const alert_event&)>& fn) const;
    // One line an alert, `state alertname severity labels summary` with tabs between, for the CLI.
    void render_alerts_text(std::string& out) const;
    // A line a rule for `socketley metrics rules`: alert or record, its name, state, severity, for and query.
    void render_rules_text(std::string& out) const;

    size_t rule_count() const;
    // Pending and firing alerts.
    size_t active_alerts() const;
    const rule_stats& stats() const;
    query_limits& limits();

    struct impl;

private:
    std::unique_ptr<impl> m;
};

}   // namespace socketley::metrics
