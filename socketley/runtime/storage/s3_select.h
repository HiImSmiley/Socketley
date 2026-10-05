#pragma once
// S3 SelectObjectContent: the request document, a SQL subset run over CSV or JSON records fed in pieces of any size,
// and the event stream the answer travels in.
//
// Pure code with no I/O, so a unit test reaches it without a ring.
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include "s3_auth.h"

namespace socketley::storage
{

// The longest record S3 Select reads or writes, past which the request fails with OverMaxRecordSize.
inline constexpr size_t select_max_record = size_t{1} << 20;
// The longest SQL expression a request may carry, past which it fails with ExpressionTooLong.
inline constexpr size_t select_max_expression = size_t{256} << 10;

enum class select_format : uint8_t { csv, json };
enum class select_header : uint8_t { none, use, ignore };
enum class select_json_type : uint8_t { document, lines };

struct select_csv_input
{
    select_header header{select_header::none};
    // A record starting with this character is skipped; empty for none.
    std::string   comments{"#"};
    char          quote_escape{'"'};
    // One or two bytes.
    std::string   record_delimiter{"\n"};
    char          field_delimiter{','};
    char          quote{'"'};
    // Whether a quoted field may hold the record delimiter, which otherwise ends the record wherever it stands.
    bool          allow_quoted_record_delimiter{false};
};

struct select_csv_output
{
    // ALWAYS when true, ASNEEDED when false.
    bool        quote_always{false};
    char        quote_escape{'"'};
    std::string record_delimiter{"\n"};
    char        field_delimiter{','};
    char        quote{'"'};
};

struct select_request
{
    std::string       expression;
    // RequestProgress/Enabled: the caller sends Progress events while the scan runs.
    bool              progress{false};
    select_format     input{select_format::csv};
    select_csv_input  csv_in;
    select_json_type  json_type{select_json_type::document};
    select_format     output{select_format::csv};
    select_csv_output csv_out;
    std::string       json_record_delimiter{"\n"};
    // ScanRange, both ends inclusive; End alone means the object's last End bytes.
    bool              has_scan_start{false};
    bool              has_scan_end{false};
    uint64_t          scan_start{0};
    uint64_t          scan_end{0};
};

// The body of POST /<bucket>/<key>?select&select-type=2, the expression compiled to check it; false with `err` set.
bool parse_select_request(std::string_view xml, select_request& out, s3_error& err);

// One query over one object: bytes go in through feed() in pieces of any size, and records come out of
// take_output() encoded as the request's OutputSerialization says, without the event stream around them.
class select_engine
{
public:
    select_engine();
    ~select_engine();
    select_engine(const select_engine&)            = delete;
    select_engine& operator=(const select_engine&) = delete;

    // `object_size` resolves a ScanRange of End alone and is otherwise unused; false with `err` set.
    bool init(const select_request& req, s3_error& err, uint64_t object_size = 0);

    // The object offset the first byte fed must come from, which a ScanRange with a Start moves past zero.
    uint64_t first_offset() const;

    // The next bytes of the object; ignored once done().
    void feed(std::string_view bytes);
    // The object has ended: the last record without a delimiter is read and an aggregate's one record is written.
    bool finish();

    // The records encoded since the last call.
    std::string take_output();
    size_t      pending_output() const;

    // Nothing more is needed from the object: LIMIT is reached, the ScanRange is passed, or the query failed.
    bool done() const;
    bool failed() const;
    const s3_error& error() const;

    // The Stats and Progress counters: bytes of the object read, the same uncompressed, and bytes of records written.
    uint64_t bytes_scanned() const;
    uint64_t bytes_processed() const;
    uint64_t bytes_returned() const;

private:
    struct impl;
    std::unique_ptr<impl> m_impl;
};

// One event-stream message carrying `payload`, with :message-type event, :event-type `event_type` and a
// :content-type when `content_type` is not empty.
std::string select_event(std::string_view event_type, std::string_view payload, std::string_view content_type);

// A Records event, whose payload is application/octet-stream.
std::string select_records_event(std::string_view records);
// Stats once the scan ends and Progress while it runs, each a text/xml event.
std::string select_stats_event(uint64_t scanned, uint64_t processed, uint64_t returned);
std::string select_progress_event(uint64_t scanned, uint64_t processed, uint64_t returned);
// The XML of those two events alone, `element` being Stats or Progress.
std::string select_details_xml(std::string_view element, uint64_t scanned, uint64_t processed, uint64_t returned);
// Cont, the keep-alive, and End, the last message of a stream that succeeded; neither has a payload.
std::string select_cont_event();
std::string select_end_event();
// The message that ends a stream that failed after its 200 was sent.
std::string select_error_event(std::string_view code, std::string_view message);

}   // namespace socketley::storage
