#pragma once
// How long a backend's HTTP response is, and therefore whether its socket may
// go back in the pool.
//
// ─── WHY THIS IS ITS OWN FILE ───────────────────────────────────────────────
//
// This was a hundred and twenty lines in the middle of
// proxy_instance::handle_backend_read, between a provided-buffer lookup and a
// circuit-breaker update.  Nothing outside a running daemon could call it: not
// a unit test, not a fuzz target.  fuzz_http_request.cpp reaches the request
// side through an explicit-instantiation access idiom because the functions it
// wants are at least *functions*; there was no equivalent trick available here,
// because a block of code inside a completion handler is not a symbol.
//
// So it is lifted, and lifted the way that note asked for: free functions over
// std::string_view and one plain struct of state, with no io_uring, no sockets
// and no proxy_instance in sight.  handle_backend_read now calls
// http_response_scan_chunk() and is shorter for it; test/fuzz/fuzz_http_response
// .cpp calls the same function with no machinery at all, and compiles against
// this header alone rather than against the fifteen translation units of the
// SDK — which is why that target can run in the per-push CI job.
//
// ─── WHAT THE DECISION IS FOR ───────────────────────────────────────────────
//
// Every byte of the response is forwarded to the client either way; nothing
// here changes what the client sees.  What it decides is whether the *backend
// socket* may be handed to the connection pool once the response is judged
// finished.  Judge it finished early and the socket is pooled with the rest of
// the answer still coming, and the next request to borrow it reads the tail of
// a stranger's response as the head of its own.  That is why every uncertainty
// below resolves to `unknown` rather than to a guess: the cost of "I cannot
// tell" is one un-pooled socket, and the cost of guessing wrong is a client
// receiving somebody else's data.

#include <cstddef>
#include <cstdint>
#include <string_view>

// Same spelling and same guards as shared/event_loop_definitions.h.  Repeated
// rather than included: this header is deliberately reachable from a fuzz
// target that links nothing, and event_loop_definitions.h drags in the loop's
// owner-table types for two branch hints.
#ifndef SOCKETLEY_LIKELY
#define SOCKETLEY_LIKELY(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef SOCKETLEY_UNLIKELY
#define SOCKETLEY_UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif

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

// A field name compared to a lowercase literal, with the name already split off
// at its colon.  header_name_equals() above does both jobs at once, which works
// only as long as nothing needs to look at the name on its own — and RFC 9112
// Section 5.1 requires exactly that (see the whitespace check below).
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

// The optional whitespace a field value may carry on either side.  Tabs count:
// "Transfer-Encoding:\tchunked" is an ordinary field, and a trim that knows only
// about spaces reads its value as beginning with a tab — which then fails every
// comparison and leaves the response looking as though it carried no transfer
// coding at all.
inline std::string_view http_trim_ows(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t')) s.remove_suffix(1);
    return s;
}

// Does a comma-separated field value carry this token?  Connection and
// Transfer-Encoding are both lists, and a backend is free to write
// "keep-alive, close" or "gzip, chunked".  Matching on the first characters of
// the whole value finds neither.
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

// A whole field of decimal digits and nothing else.  std::from_chars stops at
// the first byte it cannot use and reports success for what it read, so
// "Content-Length: 3x" comes back as 3 — a length the backend never sent and
// almost certainly shorter than the body.  RFC 9112 Section 6.3 calls a
// Content-Length that is not a whole decimal unrecoverable, and so does this.
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

// "HTTP/x.y NNN[ reason]" and nothing looser.  The code decides whether there
// is a body at all — 1xx, 204 and 304 override every length in the headers — so
// a status line this cannot read is not a detail to shrug at: framing the
// response by its Content-Length then assumes the one thing that was not
// established.
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

// Every line in an HTTP header block ends with CRLF and nothing else.  A bare
// LF is *permitted* to be accepted by a recipient (RFC 7230 Section 3.5), and a
// bare CR may be accepted or replaced with SP (RFC 9112 Section 2.2) — but
// "permitted" is per recipient, and this proxy is not the only recipient.  It
// hands the bytes on to a backend that makes the choice independently, and the
// moment the two choose differently they disagree about where one request ends
// and the next begins.  That is request smuggling, and it does not need the
// backend to be wrong about anything: it only needs it to be lenient in a
// place where we were strict, or the other way round.  So this proxy takes the
// only position that requires no agreement at all — a header block that is not
// strictly CRLF-framed is refused and never reaches a backend.
//
// `complete` says whether these bytes are the whole header block.  Until they
// are, a CR as the final byte is just a CRLF that has been split across two
// TCP segments and must not be judged yet; a bare LF needs no such care,
// because the byte before it has already arrived.
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

// What one header block says about the framing of its own message.
//
// Separate from the framing state below because it is gathered for *every*
// block, including the interim 1xx ones whose values do not apply to the
// response behind them.  Their shape still does: a 1xx that carries a
// Content-Length nobody can read, or a field name a lenient backend would
// accept and this one drops, is a backend contradicting itself about where its
// own blocks end — and the block after it is the response.
struct http_header_scan
{
    bool   ok{true};                // no shape two recipients could read differently
    bool   has_content_length{false};
    size_t content_length{0};
    bool   transfer_encoding{false};
    bool   chunked{false};
    bool   conn_close{false};
};

// Read the header lines of one block.  `headers` is the block without its
// terminating blank line; `from` is the offset just past the status line.
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

        // Obsolete line folding (RFC 9112 Section 5.2).  A recipient must
        // reject it or replace it with a space before forwarding; this does
        // neither, and reads the continuation as a header line of its own.  A
        // backend that unfolds it sees a different set of fields, and the two
        // can take their length from different places.
        if (SOCKETLEY_UNLIKELY(line[0] == ' ' || line[0] == '\t'))
        {
            out.ok = false;
            return out;
        }

        const auto colon = line.find(':');
        if (colon == std::string_view::npos)
            continue;                           // not a header line; both sides skip it

        const std::string_view name = line.substr(0, colon);

        // Whitespace between a field name and its colon (RFC 9112 Section 5.1),
        // which the standard requires be treated as unrecoverable for exactly
        // this reason: this parser ignores such a field and a lenient backend
        // honours it, so "Content-Length : 5" frames the response for one of us
        // and not the other.
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
            // Two Content-Lengths that disagree (RFC 9112 Section 6.3).  Taking
            // the last one silently picks a side in a disagreement the backend
            // may have settled the other way.
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

// ─── response framing state ─────────────────────────────────────────────────
//
// One of these per backend connection, cleared when the connection is reset.
// Every member is written only by http_response_scan_chunk() and read only by
// http_response_frame_complete() and the pool gate.
struct http_response_framing
{
    bool headers_parsed{false};
    bool has_content_length{false};
    bool conn_close{false};
    bool chunked{false};
    bool no_body{false};            // 204/304/1xx: no message body
    uint16_t status_code{0};
    size_t body_remaining{0};

    // Any transfer coding at all, chunked or not.  RFC 9112 Section 6.1: its
    // presence makes Content-Length inoperative — chunked frames the body by
    // chunk sizes, and any other coding leaves it running to connection close.
    // Either way the number in Content-Length is not where the response ends,
    // and a socket pooled at that offset is pooled mid-answer.
    bool transfer_encoding{false};

    // How many interim 1xx blocks have been consumed on this connection.  A
    // stream that is nothing but interim responses never reaches a message
    // boundary, and the loop that follows them has to stop somewhere.
    uint8_t interim_blocks{0};

    // At least one byte of this response has been forwarded already.  The
    // header scan only ever looks at the chunk in front of it, so it can only
    // be trusted on the *first* chunk: run it on a later one and it finds its
    // "\r\n\r\n" somewhere inside the body and reads body bytes as a status
    // line and headers.
    bool response_bytes_seen{false};

    // The length of this response could not be established with certainty —
    // the header block straddled a read boundary, or it was framed in a way a
    // backend and this proxy could read differently.  Deciding a response is
    // over when it is not hands the socket to the pool with the tail of the
    // previous answer still queued on it, and the next borrower reads someone
    // else's response as the start of its own.  Never pool one of these.
    bool unknown{false};
};

// Fold one read's worth of response bytes into the framing state.
//
// `chunk` is exactly what came off the socket in one completion, in order, and
// never empty — a read of zero bytes is an EOF and is handled long before this
// is reached.  Feeding an empty chunk is not wrong so much as meaningless: it
// consumes the one-shot header scan below without giving it anything to scan.
inline void http_response_scan_chunk(http_response_framing& st, std::string_view chunk)
{
    // Past the header block: nothing left to read, only a length to count down.
    if (st.headers_parsed)
    {
        if (st.has_content_length && st.body_remaining > 0)
        {
            if (chunk.size() >= st.body_remaining)
                st.body_remaining = 0;
            else
                st.body_remaining -= chunk.size();
        }
        return;
    }

    // Only the first chunk of a response can be scanned this way.  The scan
    // never looks past the chunk in front of it, so a header block split across
    // two reads leaves the first chunk with no "\r\n\r\n" and the second one
    // matching somewhere inside the *body* — status line and headers then come
    // out of body bytes, and a body that happens to contain a line like
    // "Content-Length: 4" gives a length that runs out almost immediately.
    // Nothing here can recover the real framing after that point, so say so and
    // let the socket be closed rather than pooled.
    if (SOCKETLEY_UNLIKELY(st.response_bytes_seen))
    {
        st.unknown = true;
        return;
    }
    st.response_bytes_seen = true;

    // Interim 1xx responses are header blocks with no body, and the real
    // response follows immediately behind them — in the same read, if the
    // backend flushed them together, which is the ordinary case for
    // Expect: 100-continue.  So this walks forward through the chunk rather
    // than handing the problem to the next one.
    size_t base = 0;
    for (;;)
    {
        const std::string_view rest = chunk.substr(base);
        const auto hdr_end = rest.find("\r\n\r\n");

        if (hdr_end == std::string_view::npos)
        {
            // No complete header block here.
            //
            // From the start of the chunk this is the ordinary split block: the
            // rest arrives next time, where response_bytes_seen turns it into
            // `unknown` above.  Costs one un-pooled socket, decides nothing.
            if (base == 0)
                return;

            // Behind an interim block it is the dangerous shape, and it is the
            // one that used to be got wrong.  What sits here is the front of the
            // real response, already forwarded; the next read carries its
            // *continuation*, not its beginning.  Clearing response_bytes_seen
            // — which is what this branch did — told the scan the opposite, so
            // the remainder of the header block was read as a whole response:
            // the first surviving header line became the status line, and a
            // Transfer-Encoding or a Connection: close ahead of the read
            // boundary was invisible.  A chunked response then framed itself by
            // a Content-Length from the middle of its own headers and the
            // socket went to the pool with the chunked terminator still on it.
            // That is precisely the defect response_bytes_seen exists to
            // prevent, so the flag stays set and the answer is "cannot tell".
            if (!rest.empty())
            {
                st.unknown = true;
                return;
            }

            // Unless the interim block ended exactly on the read boundary.
            // Then the next chunk really is the first chunk of the response,
            // and the connection keeps its place in the pool.
            st.response_bytes_seen = false;
            return;
        }

        // Same rule as the request side, and for the same reason: a header
        // block that is not strictly CRLF-framed is one this proxy and the
        // backend can read differently.  Merged on a bare LF,
        //   Content-Length: 6\nTransfer-Encoding: chunked
        // is a single line whose name is Content-Length and whose value parses
        // as 6, so the chunked flag never sets and the response is declared
        // over after six body bytes of what is really a chunked stream.  There
        // is nothing to reject on this side — the bytes are already on their
        // way to the client — but the socket underneath must not be reused.
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
            // those override every length the headers carry.  Framing this by
            // Content-Length would assume the one thing that was not read.
            st.unknown = true;
            return;
        }

        // The header lines of *this* block, whichever block it turns out to be.
        // The status line is not one of them, so the scan starts behind it —
        // reading it as a header line would put its two spaces in front of the
        // field-name whitespace check.
        const http_header_scan h = http_scan_header_lines(
            headers, (first_nl != std::string_view::npos) ? first_nl + 2 : headers.size());

        // A block whose fields two recipients could read differently, wherever
        // it sits in the stream.  In an interim block this used to be skipped
        // outright — the whole block was — and a 1xx carrying
        // "Content-Length: HTTP/1.1 100 Continue" let the response behind it be
        // framed and pooled as though the backend had been perfectly clear.
        if (SOCKETLEY_UNLIKELY(!h.ok))
        {
            st.unknown = true;
            return;
        }

        // 1xx informational: no body, so the next block starts directly behind
        // this one.  Keep walking.
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

        // Deduct body bytes already received in this chunk.
        if (st.has_content_length)
        {
            const size_t body_start = base + hdr_end + 4;
            const size_t body_in_chunk = (chunk.size() > body_start) ? chunk.size() - body_start : 0;
            if (body_in_chunk >= st.body_remaining)
                st.body_remaining = 0;
            else
                st.body_remaining -= body_in_chunk;
        }
        return;
    }
}

// Has this backend delivered a response whose end this proxy can point at?
//
// Both halves of the pooling decision ask this, which is the whole point.  It
// used to be spelled out at the one call site that detaches a *finished*
// connection — the path a successful keep-alive exchange takes — while every
// teardown path reached the pool through backend_pool_eligible(), and that gate
// never asked whether the response was over at all.  A pair torn down in the
// middle of a response therefore looked poolable, and a socket pooled with the
// tail of a response still on it hands that tail to the next borrower as the
// head of its own answer: the crossed-delivery bug wearing a different hat.
inline bool http_response_frame_complete(const http_response_framing& st)
{
    // Either no response has started on this socket or its header block never
    // resolved.  Both mean there is no message boundary to reuse from — and if
    // a request has already gone out, its answer is still to come and would
    // land on whoever borrows the socket next.
    if (!st.headers_parsed || st.unknown)
        return false;
    // A chunked response is not tracked to its terminating chunk, so "over"
    // cannot be established for one at all — and any *other* transfer coding
    // leaves the body running to connection close, which has no boundary short
    // of EOF.  RFC 9112 Section 6.1: either way the Content-Length below is
    // inoperative and must not be used to call the response finished.
    if (st.chunked || st.transfer_encoding)
        return false;
    // 204/304: the framing rules say there is no body to wait for.
    if (st.no_body)
        return true;
    // Everything else is over only once a declared length has run out.  A
    // response framed by connection close has no boundary short of EOF, so it
    // is not reusable by construction and correctly fails here.
    return st.has_content_length && st.body_remaining == 0;
}
