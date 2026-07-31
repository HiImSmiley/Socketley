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

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <system_error>

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
    if (!st.headers_parsed)
    {
        const auto hdr_end = chunk.find("\r\n\r\n");

        // Only the first chunk of a response can be scanned this way.  The
        // scan never looked past the chunk in front of it, so a header block
        // split across two reads left the first chunk with no "\r\n\r\n" and
        // the second one matching somewhere inside the *body* — status line and
        // headers then came out of body bytes, and a body that happens to
        // contain a line like "Content-Length: 4" gave a length that runs out
        // almost immediately.  Nothing here can recover the real framing after
        // that point, so say so and let the socket be closed rather than pooled.
        if (SOCKETLEY_UNLIKELY(st.response_bytes_seen))
        {
            st.unknown = true;
            return;
        }
        st.response_bytes_seen = true;

        // Same rule as the request side, and for the same reason: a header
        // block that is not strictly CRLF-framed is one this proxy and the
        // backend can read differently.  Merged on a bare LF,
        //   Content-Length: 6\nTransfer-Encoding: chunked
        // is a single line whose name is Content-Length and whose value parses
        // as 6, so the chunked flag never sets and the response is declared
        // over after six body bytes of what is really a chunked stream.  There
        // is nothing to reject on this side — the bytes are already on their
        // way to the client — but the socket underneath must not be reused.
        if (hdr_end != std::string_view::npos &&
            SOCKETLEY_UNLIKELY(!http_eol_framing_ok(chunk.substr(0, hdr_end), true)))
        {
            st.unknown = true;
            return;
        }

        if (hdr_end == std::string_view::npos)
            return;

        st.headers_parsed = true;
        const std::string_view headers = chunk.substr(0, hdr_end);

        // Parse status code from "HTTP/1.x NNN ..."
        const auto first_nl = headers.find("\r\n");
        const std::string_view status_line = (first_nl != std::string_view::npos)
            ? headers.substr(0, first_nl) : headers;
        const auto sp1 = status_line.find(' ');
        if (sp1 != std::string_view::npos && sp1 + 3 <= status_line.size())
        {
            uint16_t code = 0;
            auto [p, ec] = std::from_chars(status_line.data() + sp1 + 1,
                                           status_line.data() + sp1 + 4, code);
            if (ec == std::errc{})
                st.status_code = code;
        }

        // 1xx informational: reset header state and continue waiting for the
        // real response.
        if (st.status_code >= 100 && st.status_code < 200)
        {
            st.headers_parsed = false;
            st.status_code = 0;
            // The real response has not started yet, so the next chunk is still
            // a first chunk as far as the scan above is concerned.  Without
            // this an interim 1xx would make every response behind it
            // unframeable and cost the backend connection its place in the
            // pool.  (If the real response shares this chunk with the 1xx it is
            // still missed, as before — that costs pooling, never correctness.)
            st.response_bytes_seen = false;
            return;
        }

        // 204 No Content, 304 Not Modified: no message body per RFC 7230.
        if (st.status_code == 204 || st.status_code == 304)
            st.no_body = true;

        // Parse Content-Length, Transfer-Encoding, Connection.
        size_t h_pos = (first_nl != std::string_view::npos) ? first_nl + 2 : 0;

        while (h_pos < headers.size())
        {
            auto nl = headers.find("\r\n", h_pos);
            if (nl == std::string_view::npos) nl = headers.size();
            const auto line = headers.substr(h_pos, nl - h_pos);

            if (header_name_equals(line, "content-length", 14))
            {
                const auto colon = line.find(':');
                if (colon != std::string_view::npos)
                {
                    auto val = line.substr(colon + 1);
                    while (!val.empty() && val[0] == ' ') val.remove_prefix(1);
                    size_t cl_val = 0;
                    auto [p, ec] = std::from_chars(val.data(), val.data() + val.size(), cl_val);
                    if (ec == std::errc{})
                    {
                        st.has_content_length = true;
                        st.body_remaining = cl_val;
                    }
                }
            }
            else if (header_name_equals(line, "transfer-encoding", 17))
            {
                const auto colon = line.find(':');
                if (colon != std::string_view::npos)
                {
                    auto val = line.substr(colon + 1);
                    while (!val.empty() && val[0] == ' ') val.remove_prefix(1);
                    if (val.size() >= 7 && (val[0] | 0x20) == 'c' && (val[1] | 0x20) == 'h')
                        st.chunked = true;
                }
            }
            else if (header_name_equals(line, "connection", 10))
            {
                const auto colon = line.find(':');
                if (colon != std::string_view::npos)
                {
                    auto val = line.substr(colon + 1);
                    while (!val.empty() && val[0] == ' ') val.remove_prefix(1);
                    if (val.size() >= 5 && (val[0] | 0x20) == 'c' && (val[1] | 0x20) == 'l')
                        st.conn_close = true;
                }
            }

            h_pos = nl + 2;
        }

        // Deduct body bytes already received in this chunk.
        if (st.has_content_length)
        {
            const size_t body_start = hdr_end + 4;
            const size_t body_in_chunk = (chunk.size() > body_start) ? chunk.size() - body_start : 0;
            if (body_in_chunk >= st.body_remaining)
                st.body_remaining = 0;
            else
                st.body_remaining -= body_in_chunk;
        }
    }
    else if (st.has_content_length && st.body_remaining > 0)
    {
        if (chunk.size() >= st.body_remaining)
            st.body_remaining = 0;
        else
            st.body_remaining -= chunk.size();
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
    // cannot be established for one at all.
    if (st.chunked)
        return false;
    // 204/304: the framing rules say there is no body to wait for.
    if (st.no_body)
        return true;
    // Everything else is over only once a declared length has run out.  A
    // response framed by connection close has no boundary short of EOF, so it
    // is not reusable by construction and correctly fails here.
    return st.has_content_length && st.body_remaining == 0;
}
