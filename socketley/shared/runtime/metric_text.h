#pragma once
// Prometheus's text exposition format 0.0.4, written: a family's two comment lines, its series, escaped labels.
#include <charconv>
#include <cmath>
#include <cstdint>
#include <string>
#include <string_view>

#include "metric_catalog.h"

namespace socketley::metric_text
{

// Separate from json_escape_into because Prometheus takes a raw tab in a label value and rejects JSON's \t.
inline void label_escape_into(std::string& out, std::string_view s)
{
    for (char c : s)
    {
        if (c == '\\')      out += "\\\\";
        else if (c == '"')  out += "\\\"";
        else if (c == '\n') out += "\\n";
        else                out += c;
    }
}

inline void append_uint(std::string& out, uint64_t v)
{
    char buf[24];
    const auto r = std::to_chars(buf, buf + sizeof buf, v);
    out.append(buf, static_cast<size_t>(r.ptr - buf));
}

// A sample's value as the format spells it, a whole number without a fraction or an exponent.
inline void append_value(std::string& out, const metric_catalog::series& s)
{
    if (s.integral)
        return append_uint(out, s.integer);
    const double v = s.value;
    if (std::isnan(v))
        out += "NaN";
    else if (std::isinf(v))
        out += v > 0 ? "+Inf" : "-Inf";
    else if (v == std::trunc(v) && std::fabs(v) < 9.0e15)
    {
        char buf[24];
        const auto r = std::to_chars(buf, buf + sizeof buf, static_cast<int64_t>(v));
        out.append(buf, static_cast<size_t>(r.ptr - buf));
    }
    else
    {
        char buf[32];
        const auto r = std::to_chars(buf, buf + sizeof buf, v);
        out.append(buf, static_cast<size_t>(r.ptr - buf));
    }
}

// A family's two comment lines, the name said once for both.
inline void metric_head(std::string& out, std::string_view name, std::string_view type, std::string_view help)
{
    out += "# HELP ";
    out += name;
    out += ' ';
    out += help;
    out += "\n# TYPE ";
    out += name;
    out += ' ';
    out += type;
    out += '\n';
}

// One series line, its labels in the order given.
inline void append_series(std::string& out, const metric_catalog::series& s)
{
    out += s.fam->name;
    if (!s.labels.empty())
    {
        out += '{';
        bool first = true;
        for (const metric_catalog::label& l : s.labels)
        {
            if (!first)
                out += ',';
            first = false;
            out += l.name;
            out += "=\"";
            label_escape_into(out, l.value);
            out += '"';
        }
        out += '}';
    }
    out += ' ';
    append_value(out, s);
    out += '\n';
}

// A sink that writes each series as text, the family's head before its first series and a blank line after its last.
class writer
{
public:
    explicit writer(std::string& out) : m_out(out) {}
    ~writer() { finish(); }
    writer(const writer&) = delete;
    writer& operator=(const writer&) = delete;

    // A family's series must come together, since the format allows one head per family.
    void operator()(const metric_catalog::series& s)
    {
        if (s.fam->name != m_family)
        {
            finish();
            metric_head(m_out, s.fam->name, metric_catalog::kind_name(s.fam->type), s.fam->help);
            m_family = s.fam->name;
        }
        append_series(m_out, s);
    }

    // The blank line after the last family, idempotent, so text written after it starts a block of its own.
    void finish()
    {
        if (!m_family.empty())
            m_out += '\n';
        m_family = {};
    }

private:
    std::string& m_out;
    std::string_view m_family;
};

}   // namespace socketley::metric_text
