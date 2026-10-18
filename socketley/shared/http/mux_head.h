#pragma once
// What HTTP/2 and HTTP/3 share at the edge of a stream: a request's header list written back as the HTTP/1.1 head a
// runtime's own parser reads, and an answer's HTTP/1.1 head read into a status and a list of fields with the
// connection-specific ones dropped. Both protocols carry the same semantics in different frames (RFC 9113 8 and RFC
// 9114 4), so a stream of either runs every operation as an HTTP/1.1 connection does.
//
// Here and not under a runtime because it is the contract every runtime that speaks a multiplexed HTTP meets: the
// storage speaks both today, and an entrance proxy has the same edge to cross.
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace socketley::mux
{

struct request
{
    std::string line;          // the head, ending in an empty line
    bool        has_cl{false};
    uint64_t    cl{0};
    // A body is coming and its length was not given, so it is handed over as chunked framing.
    bool        synth_chunked{false};
};

enum class verdict : uint8_t
{
    ok,
    // Not a request either protocol allows: the stream is reset with its PROTOCOL_ERROR / H3_MESSAGE_ERROR.
    malformed,
    // Longer than a head this runtime reads: answered 431.
    too_large,
};

// `fields` in the order the peer sent them, pseudo-headers first; `end_stream` when no body follows the head.
verdict request_head(const std::vector<std::pair<std::string, std::string>>& fields, bool end_stream,
                             size_t max_head, request& out);

struct response
{
    std::string status;   // three digits
    std::vector<std::pair<std::string, std::string>> fields;   // lowercase names, connection-specific ones dropped
    bool chunked{false};  // the body is HTTP/1.1 chunked framing, to be read through
    bool interim{false};  // a 1xx: a final head follows
};

// `head` is a status line and its fields, without the empty line that ends it.
void response_head(std::string_view head, response& out);

}   // namespace socketley::mux
