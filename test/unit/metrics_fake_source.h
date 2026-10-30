#pragma once
// A series_source over vectors, with tiers computed from the raw samples by the rule metrics_types.h states: a point
// at t holds the samples in (t - step, t] but NaN, its `inc` measured from the previous step's last sample with resets
// folded in.
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "runtime/metrics/metrics_regex.h"
#include "runtime/metrics/metrics_types.h"

namespace socketley::metrics::testing
{

struct fake_series
{
    label_set labels;
    std::vector<sample> samples;
};

class fake_source : public series_source
{
public:
    std::vector<fake_series> series;
    // Tier steps the fake offers, and the oldest time they hold.
    std::vector<int64_t> tiers;
    int64_t tiers_from{std::numeric_limits<int64_t>::min()};
    uint64_t sample_calls{0};

    uint32_t add(std::vector<std::pair<std::string, std::string>> ls, std::vector<sample> s)
    {
        label_set out;
        for (auto& [n, v] : ls)
            if (!v.empty())
                out.push_back({n, v});
        std::sort(out.begin(), out.end(), [](const label& a, const label& b) { return a.name < b.name; });
        std::sort(s.begin(), s.end(), [](const sample& a, const sample& b) { return a.t < b.t; });
        series.push_back({std::move(out), std::move(s)});
        return static_cast<uint32_t>(series.size() - 1);
    }

    void select(std::span<const matcher> ms, int64_t mint, int64_t maxt, std::vector<uint32_t>& out) override
    {
        std::vector<regex> res(ms.size());
        for (size_t i = 0; i < ms.size(); ++i)
            if (ms[i].op == match_op::re || ms[i].op == match_op::nre)
            {
                std::string why;
                res[i].compile(ms[i].value, why);
            }
        for (uint32_t id = 0; id < series.size(); ++id)
        {
            bool ok = true;
            for (size_t i = 0; i < ms.size() && ok; ++i)
            {
                const std::string_view v = label_value(series[id].labels, ms[i].name);
                switch (ms[i].op)
                {
                    case match_op::eq: ok = v == ms[i].value; break;
                    case match_op::ne: ok = v != ms[i].value; break;
                    case match_op::re: ok = res[i].matches(v); break;
                    case match_op::nre: ok = !res[i].matches(v); break;
                }
            }
            if (!ok)
                continue;
            const auto& s = series[id].samples;
            auto it = std::lower_bound(s.begin(), s.end(), mint, [](const sample& x, int64_t t) { return x.t < t; });
            if (it != s.end() && it->t <= maxt)
                out.push_back(id);
        }
    }

    const label_set& labels(uint32_t id) const override { return series[id].labels; }

    void samples(uint32_t id, int64_t mint, int64_t maxt, std::vector<sample>& out) override
    {
        ++sample_calls;
        const auto& s = series[id].samples;
        auto it = std::lower_bound(s.begin(), s.end(), mint, [](const sample& x, int64_t t) { return x.t < t; });
        for (; it != s.end() && it->t <= maxt; ++it)
            out.push_back(*it);
    }

    int64_t tier_for(int64_t mint, int64_t resolution) const override
    {
        int64_t best = 0;
        if (mint < tiers_from)
            return 0;
        for (int64_t t : tiers)
            if (t <= resolution && t > best)
                best = t;
        return best;
    }

    void aggregates(uint32_t id, int64_t step, int64_t mint, int64_t maxt, std::vector<agg_point>& out) override
    {
        const auto& pts = tier(id, step);
        auto it = std::upper_bound(pts.begin(), pts.end(), mint, [](int64_t t, const agg_point& p) { return t < p.t; });
        for (; it != pts.end() && it->t <= maxt; ++it)
            out.push_back(*it);
    }

    void label_names(std::vector<std::string>& out) const override
    {
        for (const auto& s : series)
            for (const auto& l : s.labels)
                if (std::find(out.begin(), out.end(), l.name) == out.end())
                    out.push_back(l.name);
    }
    void label_values(std::string_view name, std::vector<std::string>& out) const override
    {
        for (const auto& s : series)
            if (auto v = label_value(s.labels, name); !v.empty() && std::find(out.begin(), out.end(), v) == out.end())
                out.emplace_back(v);
    }
    metric_type type_of(std::string_view) const override { return metric_type::untyped; }
    std::string_view help_of(std::string_view) const override { return {}; }

    // The tier `step` of series `id`, every step that holds a sample.
    const std::vector<agg_point>& tier(uint32_t id, int64_t step)
    {
        auto key = std::make_pair(id, step);
        if (auto it = m_tiers.find(key); it != m_tiers.end())
            return it->second;
        std::vector<agg_point> pts;
        const auto& s = series[id].samples;
        double prev = 0;
        int64_t prev_end = std::numeric_limits<int64_t>::min();
        size_t i = 0;
        while (i < s.size())
        {
            if (std::isnan(s[i].v))
            {
                ++i;
                continue;
            }
            // The step whose end is the first multiple of `step` at or after the sample.
            const int64_t q = s[i].t / step - (s[i].t % step < 0 ? 1 : 0);
            const int64_t end = (s[i].t % step == 0 ? q : q + 1) * step;
            agg_point p;
            p.t = end;
            bool first = true;
            double sum = 0, c = 0;
            for (; i < s.size() && s[i].t <= end; ++i)
            {
                const double v = s[i].v;
                if (std::isnan(v))
                    continue;
                if (first)
                {
                    p.min = p.max = v;
                    if (prev_end == end - step)
                        p.inc += v >= prev ? v - prev : v;
                    first = false;
                }
                else
                    p.inc += v >= prev ? v - prev : v;
                p.min = std::min(p.min, v);
                p.max = std::max(p.max, v);
                const double t = sum + v;
                if (std::isinf(t))
                    c = 0;
                else if (std::fabs(sum) >= std::fabs(v))
                    c += (sum - t) + v;
                else
                    c += (v - t) + sum;
                sum = t;
                p.count += 1;
                p.last = v;
                prev = v;
            }
            p.sum = std::isinf(sum) ? sum : sum + c;
            prev_end = end;
            pts.push_back(p);
        }
        return m_tiers.emplace(key, std::move(pts)).first->second;
    }

private:
    std::map<std::pair<uint32_t, int64_t>, std::vector<agg_point>> m_tiers;
};

}   // namespace socketley::metrics::testing
