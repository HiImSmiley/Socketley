#pragma once
// How long a backend's HTTP response is, and therefore whether its socket may
// go back in the pool: free functions over string_view so a fuzz target can
// call them, in shared/ because both the proxy and the server ask, and every
// uncertainty resolves to `unknown` because the cost of not telling is one
// un-pooled socket and the cost of guessing wrong is a client reading someone
// else's data.

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <system_error>

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

inline bool header_name_equals(std::string_view line, const char* lower_name, size_t name_len)
{
    if (line.size() < name_len + 1 || line[name_len] != ':')
        return false;
    for (size_t i = 0; i < name_len; i++)
    {
        if ((line[i] | 0x20) != lower_name[i])
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
        if ((s[i] | 0x20) != lower[i])
            return false;
    }
    return true;
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
        if ((line[i] | 0x20) != proto[i])
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
// until `complete` a trailing CR is a split CRLF rather than a verdict.
inline bool http_eol_framing_ok(std::string_view bytes, bool complete)
{
    for (size_t i = 0; i < bytes.size(); i++)
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
            if (!val.empty())
            {
                out.transfer_encoding = true;
                out.chunked = http_list_has_token(val, "chunked", 7);
            }
        }
        else if (http_token_equals(name, "connection", 10))
        {
            if (http_list_has_token(val, "close", 5))
                out.conn_close = true;
        }
    }
    return out;
}

// Request framing, which is worse than response framing because two recipients
// read a request and a difference between them serves a second message out of
// the first one's body, so the rules live here once and both runtimes ask this
// function.
// ─── WHAT IT DELIBERATELY DOES NOT DO ───────────────────────────────────────
// It decides the framing and nothing else: it collects no headers, judges no
// connection reuse, and reads no body.

// One transfer coding list, left to right, carrying `chunked_seen` across
// several Transfer-Encoding lines because "chunked" then "gzip" is the same
// unframeable message as "chunked, gzip".
inline bool http_te_codings_ok(std::string_view val, bool& chunked_seen,
                               bool* other_seen = nullptr)
{
    size_t pos = 0;
    for (;;)
    {
        const auto comma = val.find(',', pos);
        const size_t end = (comma == std::string_view::npos) ? val.size() : comma;
        std::string_view coding = val.substr(pos, end - pos);

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

        if (comma == std::string_view::npos)
            return true;
        pos = comma + 1;
    }
}

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

// ─── response framing state ─────────────────────────────────────────────────
// One of these per backend connection, written only by
// http_response_scan_chunk() and read only by http_response_frame_complete()
// and the pool gate.
struct http_response_framing
{
    bool headers_parsed{false};
    bool has_content_length{false};
    bool conn_close{false};
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

    // At least one byte of this response has been forwarded, so the header
    // scan may not run again and read body bytes as a status line.
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
};

// Fold `avail` body bytes into the countdown and report how many arrived past
// the end of the answer, since a byte nobody asked for both puts a stranger's
// data on the client's wire and leaves the socket at an offset no next request
// can start from.
inline void http_response_consume_body(http_response_framing& st, size_t avail)
{
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
    // five returns, because a stale value would truncate a sound forward.
    st.excess_in_chunk = 0;

    // The connection switched protocols, so these bytes are not HTTP and must
    // not be scanned: a payload that happens to spell a complete response
    // would otherwise file a live WebSocket socket in the pool.
    if (SOCKETLEY_UNLIKELY(st.switched_protocols))
        return;

    // Past the header block: nothing left to read, only a length to count down.
    if (st.headers_parsed)
    {
        http_response_consume_body(st, chunk.size());
        return;
    }

    // Only the first chunk of a response can be scanned this way, because a
    // header block split across two reads makes the second one match inside
    // the body.
    if (SOCKETLEY_UNLIKELY(st.response_bytes_seen))
    {
        st.unknown = true;
        return;
    }
    st.response_bytes_seen = true;

    // Interim 1xx responses have no body and the real response follows
    // immediately behind them, often in the same read, so this walks forward
    // through the chunk.
    size_t base = 0;
    for (;;)
    {
        const std::string_view rest = chunk.substr(base);
        const auto hdr_end = rest.find("\r\n\r\n");

        if (hdr_end == std::string_view::npos)
        {
            // No complete header block, which from the start of the chunk is
            // the ordinary split block and costs one un-pooled socket.
            if (base == 0)
                return;

            // Behind an interim block the next read carries a continuation
            // rather than a beginning, so response_bytes_seen stays set and
            // the answer is that this cannot be told.
            if (!rest.empty())
            {
                st.unknown = true;
                return;
            }

            // Unless the interim block ended exactly on the read boundary,
            // when the next chunk really is the response's first.
            st.response_bytes_seen = false;
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
        st.conn_close         = h.conn_close;

        // Deduct body bytes already in this chunk and notice when there are
        // more than the response had room for, which is what a backend
        // flushing an answer and the head of the next produces.
        const size_t body_start = base + hdr_end + 4;
        const size_t body_in_chunk = (chunk.size() > body_start) ? chunk.size() - body_start : 0;
        http_response_consume_body(st, body_in_chunk);
        return;
    }
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
    // A chunked response is not tracked to its terminating chunk and any other
    // coding runs to connection close, so Content-Length is inoperative either
    // way (RFC 9112 Section 6.1).
    if (st.chunked || st.transfer_encoding)
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

// ─── Decoding a chunked request body, one read at a time ────────────────────
// The proxy forwards a chunked body without understanding it -- "bounding it
// would mean guessing where it ends and truncating a legitimate upload" -- and
// that is enough to hand the framing to a backend that will parse it.  A server
// delivering the body to a script has to take the framing off, so this is the
// one piece the proxy could not lend.
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
            if (nl > http_chunked_decoder::MAX_SIZE_LINE)
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
                if (d.trailer_seen > http_chunked_decoder::MAX_TRAILER_BYTES)
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
