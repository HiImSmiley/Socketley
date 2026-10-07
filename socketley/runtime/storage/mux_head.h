#pragma once
// What HTTP/2 and HTTP/3 share at the edge of a stream: a request's header list written back as the HTTP/1.1 head
// parse_head() reads, and an answer's HTTP/1.1 head, as this runtime writes it, read into a status and a list of
// fields with the connection-specific ones dropped. Both protocols carry the same semantics in different frames (RFC
// 9113 8 and RFC 9114 4), so a stream of either runs every operation as an HTTP/1.1 connection does.
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace socketley::storage
{

struct mux_request
{
    std::string line;          // the head, ending in an empty line
    bool        has_cl{false};
    uint64_t    cl{0};
    // A body is coming and its length was not given, so it is handed over as chunked framing.
    bool        synth_chunked{false};
};

enum class mux_verdict : uint8_t
{
    ok,
    // Not a request either protocol allows: the stream is reset with its PROTOCOL_ERROR / H3_MESSAGE_ERROR.
    malformed,
    // Longer than a head this runtime reads: answered 431.
    too_large,
};

// `fields` in the order the peer sent them, pseudo-headers first; `end_stream` when no body follows the head.
mux_verdict mux_request_head(const std::vector<std::pair<std::string, std::string>>& fields, bool end_stream,
                             size_t max_head, mux_request& out);

struct mux_response
{
    std::string status;   // three digits
    std::vector<std::pair<std::string, std::string>> fields;   // lowercase names, connection-specific ones dropped
    bool chunked{false};  // the body is HTTP/1.1 chunked framing, to be read through
    bool interim{false};  // a 1xx: a final head follows
};

// `head` is a status line and its fields, without the empty line that ends it.
void mux_response_head(std::string_view head, mux_response& out);

}   // namespace socketley::storage
