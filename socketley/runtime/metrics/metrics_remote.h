#pragma once
// Prometheus remote-write 1.0: the Snappy block format a request body is compressed in, and the protobuf WriteRequest
// inside it, read into views of the opened body and written back from labels and samples.
//
// Snappy as https://github.com/google/snappy/blob/main/format_description.txt has it: a varint of the length, then
// literals and copies with 1-, 2- and 4-byte offsets; what this writes any Snappy reader opens.  The protobuf is
// prometheus/prompb's types.proto and remote.proto: WriteRequest{1: TimeSeries, 3: MetricMetadata},
// TimeSeries{1: Label, 2: Sample, 3: Exemplar, 4: Histogram}, Label{1: name, 2: value}, Sample{1: double, 2: int64},
// MetricMetadata{1: type, 2: family, 4: help, 5: unit}; unknown fields are skipped as protobuf says they must be.
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace socketley::metrics::remote
{

// ── Snappy ──────────────────────────────────────────────────────────────────

// The most `n` bytes can take compressed.
constexpr size_t snappy_bound(size_t n)
{
    return 32 + n + n / 6;
}

// The length a compressed block says it opens to, false for a preamble that is not a varint of at most 32 bits.
bool snappy_length(const uint8_t* in, size_t n, size_t& length);

// Compresses `n` bytes of `in`, fewer than 4 GiB, into `out`, which holds snappy_bound(n); the bytes written.
size_t snappy_compress(const uint8_t* in, size_t n, uint8_t* out);

// Opens block `in` into `out`, which holds `cap`; the bytes written, or -1 for a block that is malformed, does not
// open to exactly the length it says, or would not fit.
long snappy_decompress(const uint8_t* in, size_t n, uint8_t* out, size_t cap);

void snappy_compress(std::string_view in, std::string& out);
// False for a block that is malformed or says it opens to more than `limit` bytes, `out` then unspecified.
bool snappy_decompress(std::string_view in, std::string& out, size_t limit);

// ── WriteRequest ────────────────────────────────────────────────────────────

// The headers a remote_write POST carries.
inline constexpr std::string_view content_type = "application/x-protobuf";
inline constexpr std::string_view content_encoding = "snappy";
inline constexpr std::string_view version_header = "X-Prometheus-Remote-Write-Version";
inline constexpr std::string_view version = "0.1.0";

struct label
{
    std::string_view name;
    std::string_view value;
};

struct sample
{
    double  value{0};
    int64_t timestamp_ms{0};
};

// MetricMetadata.MetricType, numbered as the proto numbers it.
enum class metadata_type : uint32_t { unknown, counter, gauge, histogram, gaugehistogram, summary, info, stateset };

struct series
{
    // In the order the request gave them, views into the body decoded; valid until the callback returns.
    std::span<const label>  labels;
    std::span<const sample> samples;
    // Native histograms and exemplars the series carried, which this reader counts and does not read.
    uint32_t histograms{0};
    uint32_t exemplars{0};
};

struct metadata
{
    // A type number the proto does not name is passed on as it came.
    uint32_t         type{0};
    std::string_view family;
    std::string_view help;
    std::string_view unit;
};

class write_sink
{
public:
    virtual ~write_sink() = default;
    virtual void on_series(const series& s) = 0;
    virtual void on_metadata(const metadata& /*m*/) {}
};

struct decode_result
{
    bool        ok{false};
    // Why it was refused, a constant string, null when it was not.
    const char* error{nullptr};
    uint64_t    series{0};
    uint64_t    samples{0};
    uint64_t    metadata{0};
    uint64_t    histograms{0};
};

// Reads WriteRequests, reusing its scratch from one to the next so a request allocates only past the largest before.
class write_decoder
{
public:
    // A request is checked whole before its first series is handed on, so one refused hands on nothing.
    decode_result decode(std::string_view proto, write_sink& sink);

    // A request body as a POST carries it, Snappy-compressed, opened to at most `limit` bytes.
    decode_result decode_snappy(std::string_view body, write_sink& sink, size_t limit = 32u << 20);

private:
    std::string         m_opened;
    std::vector<label>  m_labels;
    std::vector<sample> m_samples;
};

// Builds a WriteRequest a series at a time; the caller gives each series' labels sorted by name, as Prometheus wants.
class write_encoder
{
public:
    void add(std::span<const label> labels, std::span<const sample> samples);
    void add_metadata(const metadata& m);

    // The protobuf so far, and the body a POST sends.
    std::string_view proto() const { return m_out; }
    void compressed(std::string& out) const { snappy_compress(m_out, out); }

    void clear() { m_out.clear(); }

private:
    std::string m_out;
};

}   // namespace socketley::metrics::remote
