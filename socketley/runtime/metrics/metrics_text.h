#pragma once
// The Prometheus text exposition format 0.0.4 read a line at a time into views, allocating nothing once its scratch
// has grown to the longest line: a bad line is skipped and counted, never the end of the scrape.
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "metrics_types.h"

namespace socketley::metrics
{

struct text_label
{
    std::string_view name;
    std::string_view value;
};

struct text_sample
{
    std::string_view name;
    // The bytes `name{labels}` as the line wrote them, which a scrape cache hashes to find the series without labels.
    std::string_view series;
    // In the line's order, values unescaped; valid until the callback returns.
    std::span<const text_label> labels;
    double  value{0};
    bool    has_timestamp{false};
    int64_t timestamp_ms{0};
    // The type `# TYPE` gave the family this sample belongs to, a histogram's `_bucket`, `_sum` and `_count` included.
    metric_type type{metric_type::untyped};
};

class text_sink
{
public:
    virtual ~text_sink() = default;
    virtual void on_sample(const text_sample& s) = 0;
    virtual void on_type(std::string_view /*family*/, metric_type /*type*/) {}
    virtual void on_help(std::string_view /*family*/, std::string_view /*help*/) {}
};

struct text_limits
{
    size_t max_line{64 * 1024};
    size_t max_labels{64};
    size_t max_name{256};
};

struct text_stats
{
    uint64_t lines{0};
    uint64_t samples{0};
    // Lines skipped as malformed or past a limit.
    uint64_t refused{0};
};

class text_parser
{
public:
    explicit text_parser(text_limits limits = {}) : m_limits(limits) {}

    // Every line of `body` handed to `sink`; a last line without its newline counts as a line.
    void parse(std::string_view body, text_sink& sink, text_stats& stats);

    // One line without its newline, false when it was refused.
    bool parse_line(std::string_view line, text_sink& sink, text_stats& stats);

private:
    bool sample_line(std::string_view line, text_sink& sink);
    bool comment_line(std::string_view line, text_sink& sink);
    metric_type type_of_sample(std::string_view name) const;

    text_limits m_limits;
    std::vector<text_label> m_labels;
    // Each label value's place: in the line, or in m_scratch when it held an escape.
    struct span_ref
    {
        uint32_t name_off, name_len, value_off, value_len;
        bool     scratch;
    };
    std::vector<span_ref> m_refs;
    std::string m_scratch;
    std::string m_family;
    metric_type m_family_type{metric_type::untyped};
};

// Go's strconv.ParseFloat over the whole of `s`: decimal, hexadecimal with a `p` exponent, Inf, Infinity and NaN in
// any case, with an optional sign.
bool parse_go_float(std::string_view s, double& out);

}   // namespace socketley::metrics
