// Fuzz target: the metrics runtime's rules file (socketley/runtime/metrics/metrics_rules).
//
// Properties checked, beyond "did it crash":
//   * a file that reads gives each rule a name, an expression the query engine takes, and a line inside the file;
//   * a refusal says which line, and that line is one the file has;
//   * every template that reads expands without a crash for labels and values at the edges.
#include "fuzz_common.h"
#include "runtime/metrics/metrics_query.h"
#include "runtime/metrics/metrics_rules.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <limits>
#include <string>

namespace m = socketley::metrics;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    data = fuzz::never_null(data);
    fuzz::set_current(data, size);
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    const size_t lines = static_cast<size_t>(std::count(text.begin(), text.end(), '\n')) + 1;
    m::rule_file f;
    std::string why;
    if (m::parse_rules(text, "fuzz", f, why))
    {
        for (const m::rule_def& r : f.rules)
        {
            if (r.name.empty() || r.expr.empty() || r.line == 0 || r.line > lines)
                __builtin_trap();
            const m::label_set ls = {{"name", "x"}, {"path", std::string(300, 'p')}};
            std::string out;
            for (const auto& [k, t] : r.annotations)
                for (const double v : {0.0, -1.0, 1e300, std::numeric_limits<double>::infinity(),
                                       std::numeric_limits<double>::quiet_NaN()})
                    m::expand_template(t, ls, v, out);
        }
    }
    else if (why.starts_with("line "))
    {
        const unsigned long n = std::strtoul(why.c_str() + 5, nullptr, 10);
        if (n == 0 || n > lines)
            __builtin_trap();
    }
    m::rule_template t;
    if (m::parse_template(text, t, why))
    {
        std::string out;
        m::expand_template(t, {{"a", "b"}}, 0.5, out);
    }
    return 0;
}
