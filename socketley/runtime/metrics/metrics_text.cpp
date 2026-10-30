#include "metrics_text.h"

#include <charconv>
#include <cstring>
#include <limits>

namespace socketley::metrics
{

namespace
{

bool is_ws(char c) { return c == ' ' || c == '\t'; }
bool name_start(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == ':'; }
bool name_char(char c) { return name_start(c) || (c >= '0' && c <= '9'); }
bool label_start(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'; }
bool label_char(char c) { return label_start(c) || (c >= '0' && c <= '9'); }

bool iequals(std::string_view a, std::string_view b)
{
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i)
        if ((a[i] | 0x20) != b[i])
            return false;
    return true;
}

void skip_ws(std::string_view s, size_t& i)
{
    while (i < s.size() && is_ws(s[i]))
        ++i;
}

size_t token_end(std::string_view s, size_t i)
{
    while (i < s.size() && !is_ws(s[i]))
        ++i;
    return i;
}

}   // namespace

bool parse_go_float(std::string_view s, double& out)
{
    if (s.empty())
        return false;
    if (iequals(s, "nan"))
    {
        out = std::numeric_limits<double>::quiet_NaN();
        return true;
    }
    bool neg = false;
    if (s[0] == '+' || s[0] == '-')
    {
        neg = s[0] == '-';
        s.remove_prefix(1);
    }
    if (iequals(s, "inf") || iequals(s, "infinity"))
    {
        out = neg ? -std::numeric_limits<double>::infinity() : std::numeric_limits<double>::infinity();
        return true;
    }
    // The decimal grammar checked here, since from_chars would also take forms Go refuses such as `nan(1)`.
    size_t i = 0, digits = 0;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9')
        ++i, ++digits;
    if (i < s.size() && s[i] == '.')
    {
        ++i;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9')
            ++i, ++digits;
    }
    if (!digits)
        return false;
    bool negative_exponent = false;
    if (i < s.size() && (s[i] == 'e' || s[i] == 'E'))
    {
        ++i;
        if (i < s.size() && (s[i] == '+' || s[i] == '-'))
            negative_exponent = s[i++] == '-';
        const size_t from = i;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9')
            ++i;
        if (i == from)
            return false;
    }
    if (i != s.size())
        return false;
    double v = 0;
    const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), v, std::chars_format::general);
    if (ec == std::errc::result_out_of_range)
    {
        // Go rounds an underflow to zero and refuses only an overflow.
        if (!negative_exponent)
            return false;
        v = 0;
    }
    else if (ec != std::errc{} || end != s.data() + s.size())
        return false;
    out = neg ? -v : v;
    return true;
}

void text_parser::parse(std::string_view body, text_sink& sink, text_stats& stats)
{
    size_t pos = 0;
    while (pos < body.size())
    {
        const void* nl = std::memchr(body.data() + pos, '\n', body.size() - pos);
        const size_t end = nl ? static_cast<size_t>(static_cast<const char*>(nl) - body.data()) : body.size();
        parse_line(body.substr(pos, end - pos), sink, stats);
        pos = end + 1;
    }
}

bool text_parser::parse_line(std::string_view line, text_sink& sink, text_stats& stats)
{
    if (!line.empty() && line.back() == '\r')
        line.remove_suffix(1);
    ++stats.lines;
    if (line.size() > m_limits.max_line)
    {
        ++stats.refused;
        return false;
    }
    size_t i = 0;
    skip_ws(line, i);
    if (i == line.size())
        return true;
    const bool ok = line[i] == '#' ? comment_line(line.substr(i), sink) : sample_line(line.substr(i), sink);
    if (!ok)
        ++stats.refused;
    else if (line[i] != '#')
        ++stats.samples;
    return ok;
}

metric_type text_parser::type_of_sample(std::string_view name) const
{
    if (m_family.empty() || !name.starts_with(m_family))
        return metric_type::untyped;
    const std::string_view suffix = name.substr(m_family.size());
    if (suffix.empty())
        return m_family_type;
    if (m_family_type == metric_type::histogram && (suffix == "_bucket" || suffix == "_sum" || suffix == "_count"))
        return m_family_type;
    if (m_family_type == metric_type::summary && (suffix == "_sum" || suffix == "_count"))
        return m_family_type;
    return metric_type::untyped;
}

bool text_parser::comment_line(std::string_view line, text_sink& sink)
{
    size_t i = 1;
    skip_ws(line, i);
    const size_t kw_end = token_end(line, i);
    const std::string_view kw = line.substr(i, kw_end - i);
    const bool help = kw == "HELP", type = kw == "TYPE";
    // Any other comment, `#HELP` without its space among them, is no line to refuse.
    if ((!help && !type) || kw_end == i + 0 || i == 1 || kw_end == line.size() || !is_ws(line[kw_end]))
        return true;
    i = kw_end;
    skip_ws(line, i);
    const size_t name_from = i;
    if (i >= line.size() || !name_start(line[i]))
        return false;
    while (i < line.size() && name_char(line[i]))
        ++i;
    const std::string_view name = line.substr(name_from, i - name_from);
    if (name.size() > m_limits.max_name || (i < line.size() && !is_ws(line[i])))
        return false;
    skip_ws(line, i);
    if (type)
    {
        const size_t e = token_end(line, i);
        const std::string_view t = line.substr(i, e - i);
        size_t rest = e;
        skip_ws(line, rest);
        if (rest != line.size())
            return false;
        metric_type mt;
        if (t == "counter") mt = metric_type::counter;
        else if (t == "gauge") mt = metric_type::gauge;
        else if (t == "histogram") mt = metric_type::histogram;
        else if (t == "summary") mt = metric_type::summary;
        else if (t == "untyped") mt = metric_type::untyped;
        else return false;
        m_family.assign(name);
        m_family_type = mt;
        sink.on_type(name, mt);
        return true;
    }
    std::string_view text = line.substr(i);
    if (text.find('\\') != std::string_view::npos)
    {
        m_scratch.clear();
        for (size_t k = 0; k < text.size(); ++k)
        {
            if (text[k] == '\\' && k + 1 < text.size() && (text[k + 1] == '\\' || text[k + 1] == 'n'))
            {
                m_scratch += text[k + 1] == 'n' ? '\n' : '\\';
                ++k;
            }
            else
                m_scratch += text[k];
        }
        text = m_scratch;
    }
    sink.on_help(name, text);
    return true;
}

bool text_parser::sample_line(std::string_view line, text_sink& sink)
{
    size_t i = 0;
    if (!name_start(line[0]))
        return false;
    while (i < line.size() && name_char(line[i]))
        ++i;
    const std::string_view name = line.substr(0, i);
    if (name.size() > m_limits.max_name)
        return false;
    size_t series_end = i;
    m_refs.clear();
    m_scratch.clear();
    bool braced = false;
    skip_ws(line, i);
    if (i < line.size() && line[i] == '{')
    {
        braced = true;
        ++i;
        while (true)
        {
            skip_ws(line, i);
            if (i >= line.size())
                return false;
            if (line[i] == '}')
            {
                ++i;
                break;
            }
            const size_t ln_from = i;
            if (!label_start(line[i]))
                return false;
            while (i < line.size() && label_char(line[i]))
                ++i;
            const size_t ln_len = i - ln_from;
            if (ln_len > m_limits.max_name)
                return false;
            skip_ws(line, i);
            if (i >= line.size() || line[i] != '=')
                return false;
            ++i;
            skip_ws(line, i);
            if (i >= line.size() || line[i] != '"')
                return false;
            ++i;
            const size_t v_from = i;
            bool escaped = false;
            while (i < line.size() && line[i] != '"')
            {
                if (line[i] == '\\')
                {
                    escaped = true;
                    if (++i >= line.size())
                        return false;
                }
                ++i;
            }
            if (i >= line.size())
                return false;
            span_ref r{static_cast<uint32_t>(ln_from), static_cast<uint32_t>(ln_len), static_cast<uint32_t>(v_from),
                       static_cast<uint32_t>(i - v_from), false};
            ++i;
            if (escaped)
            {
                // Only \\, \" and \n mean something; any other escape stays as written, as Prometheus keeps it.
                r.scratch = true;
                r.value_off = static_cast<uint32_t>(m_scratch.size());
                for (size_t k = v_from; k < v_from + r.value_len; ++k)
                {
                    const char c = line[k];
                    if (c == '\\')
                    {
                        const char n = line[k + 1];
                        if (n == '\\' || n == '"' || n == 'n')
                        {
                            m_scratch += n == 'n' ? '\n' : n;
                            ++k;
                            continue;
                        }
                    }
                    m_scratch += c;
                }
                r.value_len = static_cast<uint32_t>(m_scratch.size() - r.value_off);
            }
            const std::string_view ln = line.substr(ln_from, ln_len);
            if (ln == name_label)
                return false;
            for (const auto& o : m_refs)
                if (line.substr(o.name_off, o.name_len) == ln)
                    return false;
            m_refs.push_back(r);
            if (m_refs.size() > m_limits.max_labels)
                return false;
            skip_ws(line, i);
            if (i < line.size() && line[i] == ',')
                ++i;
            else if (i < line.size() && line[i] == '}')
            {
                ++i;
                break;
            }
            else
                return false;
        }
        series_end = i;
    }
    // A bare name is ended by the space before its value; a closing brace needs none.
    if (!braced && (series_end == line.size() || !is_ws(line[series_end])))
        return false;
    skip_ws(line, i);
    const size_t v_end = token_end(line, i);
    text_sample s;
    if (!parse_go_float(line.substr(i, v_end - i), s.value))
        return false;
    i = v_end;
    skip_ws(line, i);
    if (i < line.size())
    {
        const size_t t_end = token_end(line, i);
        const auto [p, ec] = std::from_chars(line.data() + i, line.data() + t_end, s.timestamp_ms);
        if (ec != std::errc{} || p != line.data() + t_end)
            return false;
        s.has_timestamp = true;
        i = t_end;
        skip_ws(line, i);
        if (i != line.size())
            return false;
    }
    m_labels.clear();
    for (const auto& r : m_refs)
        m_labels.push_back({line.substr(r.name_off, r.name_len),
                            r.scratch ? std::string_view(m_scratch).substr(r.value_off, r.value_len)
                                      : line.substr(r.value_off, r.value_len)});
    s.name = name;
    s.series = line.substr(0, series_end);
    s.labels = m_labels;
    s.type = type_of_sample(name);
    sink.on_sample(s);
    return true;
}

}   // namespace socketley::metrics
