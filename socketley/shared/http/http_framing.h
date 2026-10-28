#pragma once
// How long a backend's HTTP response is, and therefore whether its socket may
// go back in the pool: free functions over string_view so a fuzz target can
// call them, in shared/ because both the proxy and the server ask, and every
// uncertainty resolves to `unknown` because the cost of not telling is one
// un-pooled socket and the cost of guessing wrong is a client reading someone
// else's data.

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>

#include "../util/ascii.h"
#include "../util/text_list.h"

// Same spelling and guards as event_loop_definitions.h, repeated rather than
// included so this header stays reachable from a fuzz target that links
// nothing.
#ifndef SOCKETLEY_LIKELY
#define SOCKETLEY_LIKELY(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef SOCKETLEY_UNLIKELY
#define SOCKETLEY_UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif

// How long a peer may take to finish an HTTP head.  Here for the same reason
// the length question is: both the proxy and the server ask it, and before this
// only the proxy answered.  Both bound the SIZE of an incomplete head at 16 KB
// already; neither bounded the time, so a peer that sent "GET / HTTP/1.1" and
// stopped held its slot for ever.  Measured on a server with
// --max-connections 2: two such peers refused every real request and nothing
// reclaimed them in 75 seconds.
//
// The two runtimes check it at different rates, which is deliberate rather than
// an oversight: the proxy has a 250 ms chain of its own, the server rides its
// 30-second idle sweep, so the same 10-second deadline is noticed in 10-20
// seconds there and 10-40 here.  A second chain in the server for this alone is
// more machinery than the defect is worth.
inline constexpr int http_header_deadline_secs = 10;

// ─── shared header-line helpers ─────────────────────────────────────────────

// One byte of a name against a lowercase literal's: a letter in either case, anything else exactly, since folding
// with | 0x20 alone reads a CR as '-' and "Content\rLength" as Content-Length.
inline bool http_lower_equals(char c, char lower)
{
    // The same byte, or a letter's other case, which differs from it in 0x20 alone.
    const auto d = static_cast<unsigned char>(c ^ lower);
    return d == 0 || (d == 0x20 && static_cast<unsigned char>(lower - 'a') < 26);
}

inline bool header_name_equals(std::string_view line, const char* lower_name, size_t name_len)
{
    if (line.size() < name_len + 1 || line[name_len] != ':')
        return false;
    for (size_t i = 0; i < name_len; i++)
    {
        if (!http_lower_equals(line[i], lower_name[i]))
            return false;
    }
    return true;
}

// A field name compared to a lowercase literal with the name already split off
// at its colon, which RFC 9112 Section 5.1 requires be possible on its own.
inline bool http_token_equals(std::string_view s, const char* lower, size_t len)
{
    if (s.size() != len)
        return false;
    for (size_t i = 0; i < len; i++)
    {
        if (!http_lower_equals(s[i], lower[i]))
            return false;
    }
    return true;
}

// Whether a name may go out as a header's name: a token (RFC 9110 5.6.2), so it can neither end the line nor be
// read as a value -- names a script supplied are often derived from a request.
inline bool http_field_name_ok(std::string_view s)
{
    if (s.empty() || s.size() > 256)
        return false;
    for (char c : s)
    {
        const unsigned char u = static_cast<unsigned char>(c);
        if (u <= 0x20 || u >= 0x7F)
            return false;
        switch (c)
        {
            case '(': case ')': case ',': case '/': case ':': case ';':
            case '<': case '=': case '>': case '?': case '@': case '[':
            case '\\': case ']': case '{': case '}': case '"':
                return false;
            default: break;
        }
    }
    return true;
}

// Whether a value may go out as one header line: a CR or LF in it would end the line and start another the
// sender never meant, and NUL ends it early for some readers.
inline bool http_field_value_ok(std::string_view v)
{
    return v.find_first_of(std::string_view("\r\n\0", 3)) == std::string_view::npos;
}

// The optional whitespace a field value may carry on either side, tabs
// included, or "Transfer-Encoding:\tchunked" reads as carrying no transfer
// coding at all.
inline std::string_view http_trim_ows(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t')) s.remove_suffix(1);
    return s;
}

// The hop an X-Forwarded-For names last, which the proxy on this machine appended; everything before it is the
// client's own word.
inline std::string_view http_last_forwarded_hop(std::string_view xff)
{
    if (const size_t comma = xff.rfind(','); comma != std::string_view::npos)
        xff.remove_prefix(comma + 1);
    return http_trim_ows(xff);
}

// The value of field `lower` in a request's head, the last of them, with how many times it came.
inline std::string_view http_request_field(std::string_view head, std::string_view lower, int& count)
{
    count = 0;
    std::string_view value;
    for (size_t p = head.find("\r\n"); p != std::string_view::npos && p + 2 < head.size();)
    {
        const size_t start = p + 2;
        size_t nl = head.find("\r\n", start);
        if (nl == std::string_view::npos)
            nl = head.size();
        const std::string_view line = head.substr(start, nl - start);
        if (line.empty())
            break;
        if (line.size() > lower.size() && line[lower.size()] == ':' &&
            std::equal(lower.begin(), lower.end(), line.begin(), [](char a, char b) { return http_lower_equals(b, a); }))
        {
            ++count;
            value = http_trim_ows(line.substr(lower.size() + 1));
        }
        p = nl;
    }
    return value;
}

// The credentials an Authorization value carries after `scheme_lower`, a scheme RFC 9110 11.1 matches in any case,
// trimmed; false for another scheme, so "BASIC" or "Bearer" reaches what "basic" and "bearer" do.
inline bool http_auth_credentials(std::string_view authorization, std::string_view scheme_lower,
                                  std::string_view& credentials)
{
    const size_t n = scheme_lower.size();
    if (authorization.size() <= n || authorization[n] != ' ')
        return false;
    for (size_t i = 0; i < n; ++i)
        if (!http_lower_equals(authorization[i], scheme_lower[i]))
            return false;
    credentials = http_trim_ows(authorization.substr(n + 1));
    return true;
}

// Does a comma-separated field value carry this token, since Connection and
// Transfer-Encoding are lists and matching the whole value finds neither
// member.
inline bool http_list_has_token(std::string_view val, const char* lower, size_t len)
{
    size_t pos = 0;
    for (;;)
    {
        const size_t comma = val.find(',', pos);
        const std::string_view item = http_trim_ows(
            val.substr(pos, (comma == std::string_view::npos) ? std::string_view::npos : comma - pos));
        if (http_token_equals(item, lower, len))
            return true;
        if (comma == std::string_view::npos)
            return false;
        pos = comma + 1;
    }
}

// A whole field of decimal digits and nothing else, because std::from_chars
// reports success for "3x" as 3 and RFC 9112 Section 6.3 calls that
// unrecoverable.
inline bool http_whole_decimal(std::string_view s, size_t& out)
{
    if (s.empty())
        return false;
    size_t v = 0;
    for (char c : s)
    {
        if (c < '0' || c > '9')
            return false;
        if (v > (SIZE_MAX - static_cast<size_t>(c - '0')) / 10)
            return false;                       // would overflow
        v = v * 10 + static_cast<size_t>(c - '0');
    }
    out = v;
    return true;
}

// "HTTP/x.y NNN[ reason]" and nothing looser, because 1xx, 204 and 304
// override every length in the headers.
inline bool http_status_code(std::string_view line, uint16_t& out)
{
    static const char proto[] = "http/";
    if (line.size() < 5)
        return false;
    for (size_t i = 0; i < 5; i++)
    {
        if (socketley::ascii::lower(line[i]) != proto[i])
            return false;
    }
    const size_t sp = line.find(' ');
    if (sp == std::string_view::npos || sp + 4 > line.size())
        return false;
    for (size_t i = sp + 1; i <= sp + 3; i++)
    {
        if (line[i] < '0' || line[i] > '9')
            return false;
    }
    if (sp + 4 != line.size() && line[sp + 4] != ' ')
        return false;
    out = static_cast<uint16_t>((line[sp + 1] - '0') * 100 +
                                (line[sp + 2] - '0') * 10 +
                                (line[sp + 3] - '0'));
    return true;
}

// A header block that is not strictly CRLF-framed is refused, because leniency
// this proxy and its backend choose differently is request smuggling, and
// until `complete` a trailing CR is a split CRLF rather than a verdict, with
// `from` the length an earlier call passed, whose last byte alone is read again.
inline bool http_eol_framing_ok(std::string_view bytes, bool complete, size_t from = 0)
{
    for (size_t i = from > 0 ? std::min(from, bytes.size()) - 1 : 0; i < bytes.size(); i++)
    {
        if (bytes[i] == '\n')
        {
            if (i == 0 || bytes[i - 1] != '\r')
                return false;   // bare LF
        }
        else if (bytes[i] == '\r')
        {
            const bool have_next = (i + 1 < bytes.size());
            if (have_next ? (bytes[i + 1] != '\n') : complete)
                return false;   // bare CR
        }
    }
    return true;
}

// One transfer coding list, left to right, carrying `chunked_seen` across
// several Transfer-Encoding lines because "chunked" then "gzip" is the same
// unframeable message as "chunked, gzip".
inline bool http_te_codings_ok(std::string_view val, bool& chunked_seen,
                               bool* other_seen = nullptr)
{
    while (!val.empty())
    {
        std::string_view coding = socketley::take_item(val);

        if (const auto semi = coding.find(';'); semi != std::string_view::npos)
            coding = coding.substr(0, semi);
        coding = http_trim_ows(coding);

        if (!coding.empty())
        {
            // Anything at all after the chunked coding — including a second
            // chunked, which RFC 9112 Section 6.1 forbids outright — means the
            // body is not framed by chunk sizes the way it claims to be.
            if (chunked_seen)
                return false;
            if (http_token_equals(coding, "chunked", 7))
                chunked_seen = true;
            else if (other_seen)
                // "gzip, chunked" is framable -- chunked is the final coding,
                // so the chunk sizes do delimit it -- and the bytes inside are
                // still compressed.  A recipient that takes the framing off and
                // hands them on as the body has handed on gzip and called it
                // the body, so whether anything BUT chunked is present has to
                // be knowable separately from whether the message is framed.
                *other_seen = true;
        }
    }
    return true;
}

// What one header block says about the framing of its own message, gathered
// for every block including the interim 1xx ones, whose shape still matters
// even where their values do not.
struct http_header_scan
{
    bool   ok{true};                // no shape two recipients could read differently
    bool   has_content_length{false};
    size_t content_length{0};
    bool   transfer_encoding{false};
    bool   chunked{false};
    bool   conn_close{false};
    bool   conn_keep_alive{false};
};

// Read the header lines of one block, where `headers` excludes the terminating
// blank line and `from` is just past the status line.
inline http_header_scan http_scan_header_lines(std::string_view headers, size_t from)
{
    http_header_scan out;
    size_t h_pos    = from;
    bool   cl_seen  = false;
    size_t cl_value = 0;

    while (h_pos < headers.size())
    {
        auto nl = headers.find("\r\n", h_pos);
        if (nl == std::string_view::npos) nl = headers.size();
        const auto line = headers.substr(h_pos, nl - h_pos);
        h_pos = nl + 2;

        if (line.empty())
            continue;

        // Obsolete line folding (RFC 9112 Section 5.2), read here as a header
        // line of its own, which a backend that unfolds it would not.
        if (SOCKETLEY_UNLIKELY(line[0] == ' ' || line[0] == '\t'))
        {
            out.ok = false;
            return out;
        }

        const auto colon = line.find(':');
        if (colon == std::string_view::npos)
            continue;                           // not a header line; both sides skip it

        const std::string_view name = line.substr(0, colon);

        // Whitespace between a field name and its colon (RFC 9112 Section
        // 5.1), unrecoverable because "Content-Length : 5" frames the response
        // for a lenient backend and not for this parser.
        if (SOCKETLEY_UNLIKELY(name.find(' ')  != std::string_view::npos ||
                               name.find('\t') != std::string_view::npos))
        {
            out.ok = false;
            return out;
        }

        const std::string_view val = http_trim_ows(line.substr(colon + 1));

        if (http_token_equals(name, "content-length", 14))
        {
            size_t v = 0;
            if (SOCKETLEY_UNLIKELY(!http_whole_decimal(val, v)))
            {
                out.ok = false;
                return out;
            }
            // Two Content-Lengths that disagree (RFC 9112 Section 6.3), where
            // taking the last silently picks a side the backend may have
            // settled the other way.
            if (SOCKETLEY_UNLIKELY(cl_seen && v != cl_value))
            {
                out.ok = false;
                return out;
            }
            cl_seen  = true;
            cl_value = v;
            out.has_content_length = true;
            out.content_length     = v;
        }
        else if (http_token_equals(name, "transfer-encoding", 17))
        {
            // Chunked frames the body only as the final coding, and anything
            // after it leaves a length two recipients can read two ways.
            if (!val.empty())
            {
                out.transfer_encoding = true;
                if (SOCKETLEY_UNLIKELY(!http_te_codings_ok(val, out.chunked)))
                {
                    out.ok = false;
                    return out;
                }
            }
        }
        else if (http_token_equals(name, "connection", 10))
        {
            if (http_list_has_token(val, "close", 5))
                out.conn_close = true;
            if (http_list_has_token(val, "keep-alive", 10))
                out.conn_keep_alive = true;
        }
    }
    // A length beside a transfer coding is the shape request smuggling is made
    // of (RFC 9112 Section 6.3), and no reading of it is safe to pool on.
    if (SOCKETLEY_UNLIKELY(out.transfer_encoding && out.has_content_length))
        out.ok = false;
    return out;
}

// Does the sender keep the connection open behind this response (RFC 9112
// Section 9.3), where `status_line` has passed http_status_code() and a version
// that is not one digit, a dot and one digit is read as the one that closes.
inline bool http_response_persists(std::string_view status_line, const http_header_scan& h)
{
    if (h.conn_close)
        return false;
    if (status_line.find(' ') != 8 || status_line[6] != '.' ||
        status_line[5] < '0' || status_line[5] > '9' ||
        status_line[7] < '0' || status_line[7] > '9')
        return false;
    const int version = (status_line[5] - '0') * 10 + (status_line[7] - '0');
    return version >= 11 || (version == 10 && h.conn_keep_alive);
}

// Request framing, which is worse than response framing because two recipients
// read a request and a difference between them serves a second message out of
// the first one's body, so the rules live here once and both runtimes ask this
// function.
// ─── WHAT IT DELIBERATELY DOES NOT DO ───────────────────────────────────────
// It decides the framing and nothing else: it collects no headers, judges no
// connection reuse, and reads no body.

// The framing a request header block declares about itself, where `ok ==
// false` means no recipient may act on this message and every field below is
// meaningless.
struct http_request_framing_scan
{
    bool   ok{true};
    bool   has_content_length{false};
    size_t content_length{0};
    bool   transfer_encoding{false};  // a non-empty Transfer-Encoding is present
    bool   chunked{false};            // ... and `chunked` is its final coding
    bool   other_codings{false};      // ... and something other than chunked is in it
};

// Read the header lines of one complete request block, after the caller has
// run http_eol_framing_ok(), and stricter than the response scan because a
// request is forwarded to a second parser that could make a field out of what
// this one discards.
inline http_request_framing_scan http_scan_request_headers(std::string_view headers)
{
    http_request_framing_scan out;
    bool   cl_seen         = false;
    bool   te_final_chunked = false;
    size_t pos             = 0;

    while (pos < headers.size())
    {
        auto nl = headers.find("\r\n", pos);
        if (nl == std::string_view::npos)
            nl = headers.size();
        const std::string_view line = headers.substr(pos, nl - pos);
        pos = nl + 2;

        // An obs-fold continuation (RFC 9112 Section 5.2), which two ends can
        // read differently and flattening only guesses about.
        if (SOCKETLEY_UNLIKELY(line.empty() || line[0] == ' ' || line[0] == '\t'))
        {
            out.ok = false;
            return out;
        }

        const auto colon = line.find(':');
        if (SOCKETLEY_UNLIKELY(colon == std::string_view::npos || colon == 0))
        {
            out.ok = false;
            return out;
        }

        // Whitespace between the field name and its colon (RFC 9112 Section
        // 5.1), which walks past every conflict check below while the other
        // end still frames the body by it.
        const std::string_view name = line.substr(0, colon);
        if (SOCKETLEY_UNLIKELY(name.back() == ' ' || name.back() == '\t'))
        {
            out.ok = false;
            return out;
        }

        // OWS is SP or HTAB (RFC 9110 Section 5.6.3), and a trim that knows
        // only spaces fails every check below on a perfectly ordinary message.
        const std::string_view val = http_trim_ows(line.substr(colon + 1));

        if (http_token_equals(name, "content-length", 14))
        {
            size_t v = 0;
            // The number and not merely the presence, because std::from_chars
            // reads "6x" as 6 and RFC 9112 Section 6.3 calls an invalid
            // Content-Length unrecoverable.
            if (SOCKETLEY_UNLIKELY(!http_whole_decimal(val, v)))
            {
                out.ok = false;
                return out;
            }
            if (SOCKETLEY_UNLIKELY(cl_seen))
            {
                out.ok = false;
                return out;
            }
            cl_seen                = true;
            out.has_content_length = true;
            out.content_length     = v;
        }
        else if (http_token_equals(name, "transfer-encoding", 17))
        {
            // Present is present even with an empty value, because the field
            // is re-emitted to a backend that may read "no codings" as "not
            // chunked".
            out.transfer_encoding = true;
            if (SOCKETLEY_UNLIKELY(!http_te_codings_ok(val, te_final_chunked,
                                                       &out.other_codings)))
            {
                out.ok = false;
                return out;
            }
        }
    }

    // Content-Length together with Transfer-Encoding (RFC 9112 Section 6.3):
    // the message carries two answers to "how long is the body" and each
    // recipient picks one, independently.
    if (SOCKETLEY_UNLIKELY(out.transfer_encoding && out.has_content_length))
    {
        out.ok = false;
        return out;
    }

    // A Transfer-Encoding whose final coding is not chunked leaves the body
    // with no declared length, which RFC 9112 Section 6.1 makes a MUST-400.
    if (SOCKETLEY_UNLIKELY(out.transfer_encoding && !te_final_chunked))
    {
        out.ok = false;
        return out;
    }

    out.chunked = te_final_chunked;
    return out;
}

// ─── Decoding a chunked body, one read at a time ────────────────────────────
// Used in three places: a server delivering a chunked request body to a script,
// a proxy finding where a chunked request body ends so the bytes behind it are
// parsed as the next request rather than relayed, and the response scan below
// finding where a chunked answer ends so the client's next request is served.
//
// Stepping rather than one-shot, because a read can carry a size line, a
// payload run, the CRLF after it and the start of the next size line, and the
// caller needs each payload run separately.  `in` is advanced past everything
// consumed so the caller knows exactly how much to erase.

enum class chunk_step
{
    need_more,   // nothing more can be decided from what is here
    payload,     // `out` names bytes of the body, already consumed from `in`
    done,        // the terminating 0-chunk and its trailers are complete
    bad,         // not chunked framing, and the stream cannot be resynchronised
};

struct http_chunked_decoder
{
    enum class phase : uint8_t { size, data, data_crlf, trailer, finished, broken };
    phase  st{phase::size};
    size_t chunk_left{0};
    // A size line is a handful of hex digits and maybe an extension; anything
    // beyond this is a peer filling memory one byte at a time with a line it
    // never terminates.  Kept small because 16 hex digits already exceeds what
    // size_t can hold.
    static constexpr size_t MAX_SIZE_LINE = 256;
    // Trailers are headers, and the same reasoning bounds them.
    static constexpr size_t MAX_TRAILER_BYTES = 8192;
    size_t trailer_seen{0};
};

// Hex, strict: `from_chars` with base 16 would also take a leading '+', and a
// chunk size is not allowed one.
inline bool http_chunk_hex(std::string_view s, size_t& out)
{
    if (s.empty()) return false;
    size_t v = 0;
    for (char c : s)
    {
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return false;
        // Overflow refused rather than wrapped: a wrapped size is a short read
        // that then reads the next chunk's header as payload.
        if (v > (SIZE_MAX - static_cast<size_t>(d)) / 16) return false;
        v = v * 16 + static_cast<size_t>(d);
    }
    out = v;
    return true;
}

inline chunk_step http_chunked_next(http_chunked_decoder& d, std::string_view& in,
                             std::string_view& out)
{
    out = std::string_view();
    for (;;)
    {
        switch (d.st)
        {
        case http_chunked_decoder::phase::broken:
            return chunk_step::bad;
        case http_chunked_decoder::phase::finished:
            return chunk_step::done;

        case http_chunked_decoder::phase::size:
        {
            const size_t nl = in.find("\r\n");
            if (nl == std::string_view::npos)
            {
                // A line that never ends is refused rather than waited on.
                if (in.size() > http_chunked_decoder::MAX_SIZE_LINE)
                {
                    d.st = http_chunked_decoder::phase::broken;
                    return chunk_step::bad;
                }
                return chunk_step::need_more;
            }
            // A bare CR or LF inside the line is a line end to a lenient peer
            // and not to this reader, so the two would disagree about where
            // the body ends.
            if (nl > http_chunked_decoder::MAX_SIZE_LINE ||
                in.substr(0, nl).find_first_of("\r\n") != std::string_view::npos)
            {
                d.st = http_chunked_decoder::phase::broken;
                return chunk_step::bad;
            }
            // An extension is legal and carries no meaning here, so the size is
            // whatever precedes the first ';'.
            std::string_view line = in.substr(0, nl);
            const size_t semi = line.find(';');
            if (semi != std::string_view::npos) line = line.substr(0, semi);
            // Trailing spaces are tolerated by RFC 9112 for the size, leading
            // ones are not part of the grammar and would let " 5" mean 5.
            while (!line.empty() && (line.back() == ' ' || line.back() == '\t'))
                line.remove_suffix(1);

            size_t sz = 0;
            if (!http_chunk_hex(line, sz))
            {
                d.st = http_chunked_decoder::phase::broken;
                return chunk_step::bad;
            }
            in.remove_prefix(nl + 2);
            if (sz == 0)
            {
                d.st = http_chunked_decoder::phase::trailer;
                d.trailer_seen = 0;
                continue;
            }
            d.chunk_left = sz;
            d.st = http_chunked_decoder::phase::data;
            continue;
        }

        case http_chunked_decoder::phase::data:
        {
            if (in.empty()) return chunk_step::need_more;
            const size_t n = in.size() < d.chunk_left ? in.size() : d.chunk_left;
            out = in.substr(0, n);
            in.remove_prefix(n);
            d.chunk_left -= n;
            if (d.chunk_left == 0)
                d.st = http_chunked_decoder::phase::data_crlf;
            // Returned even when the chunk is not finished: the caller wants
            // every byte as it lands, which is the whole reason for this.
            return chunk_step::payload;
        }

        case http_chunked_decoder::phase::data_crlf:
        {
            if (in.size() < 2) return chunk_step::need_more;
            if (in[0] != '\r' || in[1] != '\n')
            {
                // The declared length and the framing disagree, so nothing
                // after this point can be trusted to be payload.
                d.st = http_chunked_decoder::phase::broken;
                return chunk_step::bad;
            }
            in.remove_prefix(2);
            d.st = http_chunked_decoder::phase::size;
            continue;
        }

        case http_chunked_decoder::phase::trailer:
        {
            // Either an immediate CRLF -- no trailers -- or header lines until
            // an empty one.
            for (;;)
            {
                const size_t nl = in.find("\r\n");
                if (nl == std::string_view::npos)
                {
                    if (in.size() + d.trailer_seen > http_chunked_decoder::MAX_TRAILER_BYTES)
                    {
                        d.st = http_chunked_decoder::phase::broken;
                        return chunk_step::bad;
                    }
                    return chunk_step::need_more;
                }
                d.trailer_seen += nl + 2;
                if (d.trailer_seen > http_chunked_decoder::MAX_TRAILER_BYTES ||
                    in.substr(0, nl).find_first_of("\r\n") != std::string_view::npos)
                {
                    d.st = http_chunked_decoder::phase::broken;
                    return chunk_step::bad;
                }
                const bool empty_line = (nl == 0);
                in.remove_prefix(nl + 2);
                if (empty_line)
                {
                    d.st = http_chunked_decoder::phase::finished;
                    return chunk_step::done;
                }
                // A trailer line is discarded: nothing downstream reads them,
                // and inventing headers from them after the request has been
                // dispatched is how a trailer becomes a request smuggling.
            }
        }
        }
    }
}

// ─── response framing state ─────────────────────────────────────────────────
// One of these per backend connection, written only by
// http_response_scan_chunk() and read only by http_response_frame_complete()
// and the pool gate.
struct http_response_framing
{
    bool headers_parsed{false};
    bool has_content_length{false};
    // The backend closes this socket behind this response, by Connection: close
    // or by answering HTTP/1.0 without keep-alive.
    bool conn_close{false};
    // It said so with Connection: close, which reaches the client as well.
    bool close_said{false};
    bool chunked{false};
    bool no_body{false};            // 204/304/1xx: no message body
    uint16_t status_code{0};
    size_t body_remaining{0};

    // Any transfer coding at all makes Content-Length inoperative (RFC 9112
    // Section 6.1), so a socket pooled at that offset is pooled mid-answer.
    bool transfer_encoding{false};

    // How many interim 1xx blocks this connection has consumed, because a
    // stream of nothing but interim responses never reaches a message
    // boundary.
    uint8_t interim_blocks{0};

    // At least one byte of this response has arrived.
    bool response_bytes_seen{false};

    // The length of this response could not be established with certainty, and
    // one of these is never pooled.
    bool unknown{false};

    // More body bytes arrived than the response had room for, distinct from
    // `unknown` because the end of this response is known exactly and what is
    // wrong is the socket, which must never be pooled.
    bool overrun{false};

    // How many bytes at the end of the chunk just scanned lie past the end of
    // the response, cleared by every scan, so the caller can forward the rest
    // and drop these.
    size_t excess_in_chunk{0};

    // The backend answered 101, so this connection carries a different
    // protocol with no message boundaries, and the flag is never cleared
    // because there is no way back.
    bool switched_protocols{false};

    // A chunked body walked to its terminating chunk, which is the only way a
    // chunked response ends on a socket that stays open.
    http_chunked_decoder chunk_dec{};
    bool chunk_done{false};

    // Bytes of an unfinished header block, or of an unfinished chunk-size or
    // trailer line, kept for the next read because both are framing that a
    // read boundary may cut anywhere -- and a scan that gave up there left the
    // client's next request waiting on an answer nobody could call finished.
    std::string carry;
};

// The most an unfinished head may hold, the request side's own bound.
inline constexpr size_t http_response_head_max = 16 * 1024;

// Walk chunked body bytes, keeping only an unfinished line for the next read.
inline void http_response_walk_chunked(http_response_framing& st, std::string_view in)
{
    std::string joined;
    if (!st.carry.empty())
    {
        joined.swap(st.carry);
        joined.append(in.data(), in.size());
        in = joined;
    }
    if (SOCKETLEY_UNLIKELY(st.chunk_done))
    {
        st.overrun = true;
        st.excess_in_chunk = in.size();
        return;
    }
    for (;;)
    {
        std::string_view out;
        switch (http_chunked_next(st.chunk_dec, in, out))
        {
        case chunk_step::payload:
            continue;
        case chunk_step::need_more:
            st.carry.assign(in.data(), in.size());
            return;
        case chunk_step::done:
            st.chunk_done = true;
            if (!in.empty())
            {
                st.overrun = true;
                st.excess_in_chunk = in.size();
            }
            return;
        case chunk_step::bad:
            st.unknown = true;
            return;
        }
    }
}

// Fold body bytes into the framing and report how many arrived past the end of
// the answer, since a byte nobody asked for both puts a stranger's data on the
// client's wire and leaves the socket at an offset no next request can start
// from.
inline void http_response_consume_body(http_response_framing& st, std::string_view body)
{
    const size_t avail = body.size();
    if (st.chunked && !st.no_body)
    {
        http_response_walk_chunked(st, body);
        return;
    }

    const bool bounded = st.no_body ||
                         (st.has_content_length && !st.chunked && !st.transfer_encoding);
    const size_t left = st.no_body ? 0
                                   : (st.has_content_length ? st.body_remaining : 0);

    if (SOCKETLEY_UNLIKELY(bounded && avail > left))
    {
        st.overrun = true;
        st.excess_in_chunk = avail - left;
    }

    if (st.has_content_length)
        st.body_remaining = (avail >= st.body_remaining) ? 0 : st.body_remaining - avail;
}

// Fold one read's worth of response bytes into the framing state, where
// `chunk` is one completion's bytes in order and never empty.
inline void http_response_scan_chunk(http_response_framing& st, std::string_view chunk)
{
    // Per chunk and not per response, cleared here rather than at each of the
    // returns, because a stale value would truncate a sound forward.
    st.excess_in_chunk = 0;

    // The connection switched protocols, so these bytes are not HTTP and must
    // not be scanned: a payload that happens to spell a complete response
    // would otherwise file a live WebSocket socket in the pool.
    if (SOCKETLEY_UNLIKELY(st.switched_protocols))
        return;

    // Once the length cannot be told, nothing later can make it tellable.
    if (SOCKETLEY_UNLIKELY(st.unknown))
        return;

    // Past the header block: only the body's own framing is left to follow.
    if (st.headers_parsed)
    {
        http_response_consume_body(st, chunk);
        return;
    }

    st.response_bytes_seen = true;

    // An unfinished block from the last read is scanned as one with this one,
    // and the excess arithmetic below still holds, because a block that ends
    // here ends inside `chunk` and so does everything behind it.
    std::string joined;
    std::string_view view = chunk;
    if (!st.carry.empty())
    {
        joined.swap(st.carry);
        joined.append(chunk.data(), chunk.size());
        view = joined;
    }

    // Interim 1xx responses have no body and the real response follows
    // immediately behind them, often in the same read, so this walks forward
    // through the bytes.
    size_t base = 0;
    for (;;)
    {
        const std::string_view rest = view.substr(base);
        const auto hdr_end = rest.find("\r\n\r\n");

        if (hdr_end == std::string_view::npos)
        {
            // The block is cut by the read boundary, so it waits for the next
            // read, bounded the way a request head is.
            if (SOCKETLEY_UNLIKELY(rest.size() > http_response_head_max))
            {
                st.unknown = true;
                return;
            }
            st.carry.assign(rest.data(), rest.size());
            return;
        }

        // Same rule as the request side, except that there is nothing to
        // reject here because the bytes are already on their way to the
        // client, so only the socket is condemned.
        if (SOCKETLEY_UNLIKELY(!http_eol_framing_ok(rest.substr(0, hdr_end), true)))
        {
            st.unknown = true;
            return;
        }

        const std::string_view headers = rest.substr(0, hdr_end);
        const auto first_nl = headers.find("\r\n");
        const std::string_view status_line = (first_nl != std::string_view::npos)
            ? headers.substr(0, first_nl) : headers;

        uint16_t code = 0;
        if (SOCKETLEY_UNLIKELY(!http_status_code(status_line, code)))
        {
            // No readable code means 1xx, 204 and 304 cannot be ruled out, and
            // those override every length the headers carry.
            st.unknown = true;
            return;
        }

        // The header lines of this block, starting behind the status line,
        // whose two spaces would otherwise reach the field-name whitespace
        // check.
        const http_header_scan h = http_scan_header_lines(
            headers, (first_nl != std::string_view::npos) ? first_nl + 2 : headers.size());

        // A block whose fields two recipients could read differently, wherever
        // it sits, including an interim one that was previously skipped whole.
        if (SOCKETLEY_UNLIKELY(!h.ok))
        {
            st.unknown = true;
            return;
        }

        // 101 is in the 1xx range and is not an interim block, and
        // headers_parsed is set with it because the block did resolve and a
        // WebSocket session closing normally must not charge the circuit
        // breaker.
        if (code == 101)
        {
            st.headers_parsed     = true;
            st.status_code        = code;
            st.switched_protocols = true;
            return;
        }

        // Other 1xx informational responses have no body, so the next block
        // starts directly behind this one.
        if (code >= 100 && code < 200)
        {
            // Except that a 1xx claiming a transfer coding contradicts itself:
            // it has no body to encode, and if the backend meant it, the bytes
            // behind this block are not a header block at all.
            if (SOCKETLEY_UNLIKELY(h.transfer_encoding))
            {
                st.unknown = true;
                return;
            }
            if (SOCKETLEY_UNLIKELY(++st.interim_blocks >= 8))
            {
                // A stream of nothing but interim responses has no message
                // boundary in it at all.
                st.unknown = true;
                return;
            }
            base += hdr_end + 4;
            continue;
        }

        st.headers_parsed = true;
        st.status_code = code;

        // 204 No Content, 304 Not Modified: no message body per RFC 7230.
        if (code == 204 || code == 304)
            st.no_body = true;

        st.has_content_length = h.has_content_length;
        st.body_remaining     = h.content_length;
        st.transfer_encoding  = h.transfer_encoding;
        st.chunked            = h.chunked;
        st.conn_close         = !http_response_persists(status_line, h);
        st.close_said         = h.conn_close;

        // Deduct body bytes already here and notice when there are more than
        // the response had room for, which is what a backend flushing an
        // answer and the head of the next produces.
        http_response_consume_body(st, view.substr(base + hdr_end + 4));
        return;
    }
}

// A response head answering a client that asked to close, with the backend's
// Connection and Keep-Alive fields replaced by `Connection: close`, because a
// pooled backend says keep-alive and RFC 9112 9.6 has the closing side say
// close; `head` ends with its blank line and the body is not the caller's
// concern here.
inline std::string http_head_saying_close(std::string_view head)
{
    auto name_is = [](std::string_view line, std::string_view name) {
        if (line.size() <= name.size() || line[name.size()] != ':')
            return false;
        for (size_t i = 0; i < name.size(); ++i)
            // Letters alone are folded, since '\r' | 0x20 is '-'.
            if (socketley::ascii::lower(line[i]) != name[i])
                return false;
        return true;
    };
    std::string out;
    out.reserve(head.size() + 19);
    size_t pos = 0;
    while (pos < head.size())
    {
        size_t eol = head.find("\r\n", pos);
        if (eol == std::string_view::npos)
            eol = head.size();
        const std::string_view line = head.substr(pos, eol - pos);
        const size_t next = eol + 2 <= head.size() ? eol + 2 : head.size();
        if (line.empty())
        {
            out.append("Connection: close\r\n\r\n");
            out.append(head.substr(next));
            return out;
        }
        if (!(pos > 0 && (name_is(line, "connection") || name_is(line, "keep-alive"))))
            out.append(head.substr(pos, next - pos));
        pos = next;
    }
    return out;
}

// A response head with `field` ("Name: value") added before its blank line,
// unless a field named `lower_name` is there already; `head` ends with its
// blank line.
inline std::string http_head_adding(std::string_view head, std::string_view lower_name, std::string_view field)
{
    for (size_t pos = head.find("\r\n"); pos != std::string_view::npos && pos + 2 < head.size();
         pos = head.find("\r\n", pos + 2))
    {
        const std::string_view line = head.substr(pos + 2, lower_name.size() + 1);
        if (line.size() == lower_name.size() + 1 && line.back() == ':' &&
            std::equal(lower_name.begin(), lower_name.end(), line.begin(),
                       [](char a, char b) { return a == socketley::ascii::lower(b); }))
            return std::string(head);
    }
    std::string out(head.substr(0, head.size() - 2));
    out.append(field);
    out.append("\r\n\r\n");
    return out;
}

// Has this backend delivered a response whose end this proxy can point at,
// asked by both halves of the pooling decision so no teardown path reaches the
// pool without asking.
inline bool http_response_frame_complete(const http_response_framing& st)
{
    // A connection that switched protocols has no message boundary at all,
    // stated first because the fields below describe a response this socket is
    // no longer carrying.
    if (st.switched_protocols)
        return false;
    // Either no response has started or its header block never resolved, and a
    // request already sent would land its answer on whoever borrows the socket
    // next.
    if (!st.headers_parsed || st.unknown)
        return false;
    // No body to wait for, and asked BEFORE the coding because a response to
    // HEAD carries its GET's headers -- Transfer-Encoding among them -- and
    // none of its bytes, so a chunked HEAD reply that is already whole would
    // otherwise be waited on for a terminating chunk that RFC 9112 Section 6.3
    // forbids the server to send.  Measured through a pool: 10 chunked HEADs
    // cost 9 backend connections, the same as before the method was passed in
    // at all.  A 304 may quote them the same way (RFC 9112 Section 6.1).
    if (st.no_body)
        return true;
    // A chunked response ends at its terminating chunk and any other coding
    // runs to connection close, so Content-Length is inoperative either way
    // (RFC 9112 Section 6.1).
    if (st.chunked)
        return st.chunk_done;
    if (st.transfer_encoding)
        return false;
    // Everything else is over only once a declared length has run out, so a
    // response framed by connection close correctly fails here.
    return st.has_content_length && st.body_remaining == 0;
}

// May this socket be handed to the pool, which the message being finished is
// necessary and not sufficient for: a response complete to its last byte can
// sit on a socket that already holds the head of something nobody requested.
inline bool http_response_pool_safe(const http_response_framing& st)
{
    return http_response_frame_complete(st) && !st.overrun;
}

// ─── One Range header, into numbers ─────────────────────────────────────────
// RFC 9110 14.1.  Only `bytes` and only a single range: a multi-range request
// needs a multipart/byteranges body, and 14.2 permits a server to ignore the
// field entirely -- so the whole file is answered for those rather than a
// wrong slice.  `first`/`last` are inclusive, as on the wire.
struct http_range
{
    bool   present{false};   // a Range header was there and named `bytes`
    bool   usable{false};    // and it parsed as exactly one range in the file
    // Syntactically a single byte-range, and entirely past the end.  14.4 says
    // answer 416 with Content-Range: bytes */<total>.  Kept apart from the
    // merely unparseable, which 14.2 lets a server ignore and answer whole --
    // collapsing the two would answer 416 for a malformed header, where the
    // file is the more useful reply, or 200 for a seek past the end, which is
    // what a player uses to learn the length.
    bool   unsatisfiable{false};
    size_t first{0};
    size_t last{0};          // inclusive
};

inline bool http_range_num(std::string_view s, size_t& out)
{
    if (s.empty()) return false;
    size_t v = 0;
    auto r = std::from_chars(s.data(), s.data() + s.size(), v);
    if (r.ec != std::errc{} || r.ptr != s.data() + s.size()) return false;
    out = v;
    return true;
}

// `total` is needed because a suffix range (`bytes=-500`) is defined against
// the file's length, so this cannot be parsed without knowing it.
inline http_range http_parse_range(std::string_view v, size_t total)
{
    http_range r;
    while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
    if (v.size() < 7 || v.substr(0, 6) != "bytes=") return r;
    r.present = true;
    v.remove_prefix(6);
    // One range only; a comma means the multipart form this does not produce.
    if (v.find(',') != std::string_view::npos) return r;
    while (!v.empty() && v.front() == ' ') v.remove_prefix(1);

    const size_t dash = v.find('-');
    if (dash == std::string_view::npos) return r;
    std::string_view a = v.substr(0, dash), b = v.substr(dash + 1);
    while (!b.empty() && (b.back() == ' ' || b.back() == '\t')) b.remove_suffix(1);

    if (a.empty())
    {
        // Suffix: the last N bytes.  N == 0 is meaningless and is not a range.
        size_t n;
        if (!http_range_num(b, n)) return r;
        // A zero-length suffix is syntactically a range and names no bytes.
        if (n == 0) { r.unsatisfiable = true; return r; }
        if (total == 0) { r.unsatisfiable = true; return r; }
        r.first = n >= total ? 0 : total - n;
        r.last  = total - 1;
        r.usable = true;
        return r;
    }

    if (!http_range_num(a, r.first)) return r;
    if (b.empty())
    {
        // Open-ended: to the end of what exists.
        if (total == 0 || r.first >= total) { r.unsatisfiable = true; return r; }
        r.last = total - 1;
        r.usable = true;
        return r;
    }
    if (!http_range_num(b, r.last)) return r;
    // An inverted range is not a range at all, so it is ignored rather than
    // refused: 416 claims the file is shorter than asked, which is not the
    // complaint.
    if (r.last < r.first) return r;
    if (total == 0 || r.first >= total) { r.unsatisfiable = true; return r; }
    if (r.last >= total) r.last = total - 1;            // clamped, per 14.1.1
    r.usable = true;
    return r;
}
