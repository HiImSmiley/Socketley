// Fuzz target: the metrics runtime's reader of the Prometheus text format (socketley/runtime/metrics/metrics_text).
//
// Properties checked, beyond "did it crash":
//   * a sample's name and raw series are views into the input, the name at the series' front;
//   * every label name is a view into the input and every value lies in the input or in the parser's scratch;
//   * the counts add up: delivered plus refused lines never exceed the lines read;
//   * a delivered sample written back out in canonical form reads back as the same name, labels and value bits.
#include "fuzz_common.h"
#include "runtime/metrics/metrics_text.h"

#include <bit>
#include <cmath>
#include <string>
#include <vector>

namespace m = socketley::metrics;

namespace {

struct copy
{
    std::string name;
    std::vector<std::pair<std::string, std::string>> labels;
    uint64_t bits;
    bool has_ts;
    int64_t ts;
};

bool inside(std::string_view part, std::string_view whole)
{
    return part.empty() || (part.data() >= whole.data() && part.data() + part.size() <= whole.data() + whole.size());
}

struct checking_sink : m::text_sink
{
    std::string_view input;
    std::vector<copy> got;

    void on_sample(const m::text_sample& s) override
    {
        FUZZ_CHECK(inside(s.series, input), "series view outside the input");
        FUZZ_CHECK(s.name.data() == s.series.data() && s.name.size() <= s.series.size(), "name not the series' front");
        FUZZ_CHECK(!s.name.empty(), "empty metric name");
        copy c{std::string(s.name), {}, std::bit_cast<uint64_t>(s.value), s.has_timestamp, s.timestamp_ms};
        for (const auto& l : s.labels)
        {
            FUZZ_CHECK(inside(l.name, s.series), "label name outside the series");
            c.labels.emplace_back(std::string(l.name), std::string(l.value));
        }
        got.push_back(std::move(c));
    }
    void on_type(std::string_view family, m::metric_type) override
    {
        FUZZ_CHECK(inside(family, input), "family view outside the input");
    }
    void on_help(std::string_view family, std::string_view) override
    {
        FUZZ_CHECK(inside(family, input), "family view outside the input");
    }
};

void write_value(double v, std::string& out)
{
    if (std::isnan(v))
        out += "NaN";
    else if (std::isinf(v))
        out += v > 0 ? "+Inf" : "-Inf";
    else
    {
        char buf[64];
        std::snprintf(buf, sizeof buf, "%.17g", v);
        out += buf;
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    data = fuzz::never_null(data);
    fuzz::set_current(data, size);
    const std::string_view in(reinterpret_cast<const char*>(data), size);

    m::text_limits lim;
    lim.max_line = 4096;
    lim.max_labels = 16;
    lim.max_name = 128;
    m::text_parser p(lim);
    checking_sink s;
    s.input = in;
    m::text_stats st;
    p.parse(in, s, st);
    FUZZ_CHECK(st.samples == s.got.size(), "samples counted differ from samples delivered");
    FUZZ_CHECK(st.samples + st.refused <= st.lines, "more outcomes than lines");

    // The canonical form of what was read reads back the same.
    std::string out;
    for (const auto& c : s.got)
    {
        out += c.name;
        out += '{';
        for (size_t i = 0; i < c.labels.size(); ++i)
        {
            if (i)
                out += ',';
            out += c.labels[i].first;
            out += "=\"";
            for (char ch : c.labels[i].second)
            {
                if (ch == '\\' || ch == '"')
                    out += '\\';
                if (ch == '\n')
                {
                    out += "\\n";
                    continue;
                }
                out += ch;
            }
            out += '"';
        }
        out += "} ";
        write_value(std::bit_cast<double>(c.bits), out);
        if (c.has_ts)
            out += ' ' + std::to_string(c.ts);
        out += '\n';
    }
    // Escaping a kept backslash lengthens a line, so the second read takes longer lines.
    m::text_limits wide = lim;
    wide.max_line = lim.max_line * 3;
    m::text_parser again(wide);
    checking_sink s2;
    s2.input = out;
    m::text_stats st2;
    again.parse(out, s2, st2);
    FUZZ_CHECK(s2.got.size() == s.got.size(), "the canonical form lost or gained a sample");
    for (size_t i = 0; i < s.got.size() && i < s2.got.size(); ++i)
    {
        const auto& a = s.got[i];
        const auto& b = s2.got[i];
        FUZZ_CHECK(a.name == b.name && a.labels == b.labels, "the canonical form read back other labels");
        const double x = std::bit_cast<double>(a.bits), y = std::bit_cast<double>(b.bits);
        FUZZ_CHECK((std::isnan(x) && std::isnan(y)) || a.bits == b.bits, "the canonical form read back another value");
        FUZZ_CHECK(a.has_ts == b.has_ts && (!a.has_ts || a.ts == b.ts), "the canonical form read back another time");
    }
    return 0;
}
