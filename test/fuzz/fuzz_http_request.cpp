// Fuzz target: the proxy's HTTP request-line and header handling
// (socketley/runtime/proxy/proxy_instance.cpp).
//
// ─── ON THE SEAM ────────────────────────────────────────────────────────────
//
// There is no seam.  Both functions this target exercises —
// proxy_instance::parse_http_request_line and
// proxy_instance::rewrite_http_request — are private members of proxy_instance,
// they take a proxy_client_connection* rather than a buffer, and neither is
// declared in any header a test can reach.  There is no free function, no
// detail namespace, and no existing unit test that touches HTTP parsing at all:
// the whole of that code is only reachable today by starting a daemon, creating
// a proxy runtime and opening a socket, which is what test/integration and the
// load harnesses do.  That is a fine end-to-end check and a hopeless fuzzing
// interface — a full daemon round trip per input is four orders of magnitude
// too slow, and a crash lands in a process the fuzzer is not driving.
//
// This target was told not to invent a seam and not to edit socketley/, so it
// calls the real functions where they are, through the explicit-instantiation
// access idiom below.  That is standard C++ ([temp.spec]: access checking is
// not applied to the template arguments of an explicit instantiation), not a
// cast or a layout assumption, so it binds to the real symbols and breaks
// loudly at compile time if either signature changes.
//
// It is still a workaround.  The right fix, when someone is allowed to touch
// socketley/, is one of:
//
//   (a) lift the request-line split and the header scan into free functions
//       over (std::string_view in, out params) in a header — they already only
//       read conn->partial and write three strings, so this is a move, not a
//       redesign; or
//   (b) a single `friend struct proxy_http_test_access;` in proxy_instance.h.
//
// Either one deletes the block of machinery below.
//
// ─── WHAT IS COVERED ────────────────────────────────────────────────────────
//
//   parse_http_request_line   METHOD/PATH/VERSION split, and the CL+TE
//                             request-smuggling rejection (RFC 7230 3.3.3)
//   rewrite_http_request      hop-by-hop header stripping, Host rewriting,
//                             Connection: close tracking, body passthrough
//
// and, through a two-chunk feed, the boundary behaviour a peer gets for free by
// choosing where to stop sending — which is the part of a header parser that
// end-to-end tests almost never reach.
//
// ─── WHAT IS NOT COVERED ────────────────────────────────────────────────────
//
// The rest of handle_client_read: buffer accounting, the 431/404/502/503 error
// replies, backend selection, retries, the response-side header parse that
// decides whether a backend connection may be pooled, and anything involving
// io_uring.  The `feed` function below models only the order in which
// handle_client_read calls these two functions; it is not that handler.
//
// ─── THE ORACLE ─────────────────────────────────────────────────────────────
//
// Beyond crashes, this target asserts one security property: nothing the proxy
// forwards may be framed in a way the proxy and a backend can read differently.
// Measured with a *strict* line splitter — one that treats a bare LF as a line
// terminator, the way most backends do — and applied to EVERY message in the
// forwarded bytes, not only the first.  Per message:
//
//   * the header block is strictly CRLF-framed (no bare LF, no bare CR)
//   * no obs-fold continuation line
//   * no whitespace between a field name and its colon
//   * at most one Content-Length, and it is a whole decimal
//   * never Content-Length together with Transfer-Encoding
//
// which is the same list parse_http_request_line enforces — the point being
// that it enforces it on the first message in the buffer only, while a backend
// applies it to every message on the connection.  A payload put second used to
// slip past all five: rewrite_http_request appended everything past the header
// terminator verbatim and cleared the buffer, so a clean request in front of a
// CL+TE one was enough to hand the CL+TE one to a backend unchecked.  Both
// halves are fixed now — the forwarded body is bounded by what the request
// declared, and this oracle walks the whole stream — and the seeds under
// corpus/http named pipelined_* are the shapes that used to get through.
//
// If this oracle fires on the first CI run, that is the finding, not a broken
// test: read the reported input before touching the oracle.  FUZZ_SMUGGLING=0
// downgrades it to a warning for triage only.

#include "fuzz_common.h"

#include "runtime/proxy/proxy_instance.h"

#include <algorithm>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

// ─── access idiom (see the note above) ──────────────────────────────────────

template <typename Tag, typename Tag::type M>
struct fuzz_rob
{
    friend typename Tag::type fuzz_get(Tag) { return M; }
};

struct tag_parse_request_line
{
    using type = http_request_parse (proxy_instance::*)(proxy_client_connection*);
};
struct tag_rewrite_request
{
    using type = void (proxy_instance::*)(proxy_client_connection*, std::string_view, std::string&);
};
struct tag_backends
{
    using type = std::vector<backend_info> proxy_instance::*;
};

tag_parse_request_line::type fuzz_get(tag_parse_request_line);
tag_rewrite_request::type    fuzz_get(tag_rewrite_request);
tag_backends::type           fuzz_get(tag_backends);

template struct fuzz_rob<tag_parse_request_line, &proxy_instance::parse_http_request_line>;
template struct fuzz_rob<tag_rewrite_request, &proxy_instance::rewrite_http_request>;
template struct fuzz_rob<tag_backends, &proxy_instance::m_backends>;

namespace {

bool smuggling_is_fatal()
{
    static const bool fatal = [] {
        const char* e = std::getenv("FUZZ_SMUGGLING");
        return !(e && e[0] == '0');
    }();
    return fatal;
}

// Split a header block the way a permissive backend does: on LF, discarding a
// single trailing CR.  Deliberately *not* the same splitter the proxy uses —
// the whole point is that the two can see different lines.
std::vector<std::string_view> strict_header_lines(std::string_view block)
{
    std::vector<std::string_view> out;
    size_t pos = 0;
    while (pos <= block.size())
    {
        size_t nl = block.find('\n', pos);
        std::string_view line = (nl == std::string_view::npos)
            ? block.substr(pos)
            : block.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (!line.empty())
            out.push_back(line);
        if (nl == std::string_view::npos)
            break;
        pos = nl + 1;
    }
    return out;
}

bool name_is(std::string_view line, std::string_view lower)
{
    size_t colon = line.find(':');
    if (colon == std::string_view::npos || colon != lower.size())
        return false;
    for (size_t i = 0; i < lower.size(); i++)
        if (static_cast<char>(line[i] | 0x20) != lower[i])
            return false;
    return true;
}

// Every line of a header block ends CRLF and nothing else.  A bare LF may be
// accepted by a recipient and a bare CR may be accepted or turned into a space,
// and "may" is per recipient: the proxy and the backend choose independently,
// and the moment they choose differently they disagree about where one request
// ends.  Written out here rather than borrowed from http_framing.h so
// that the oracle does not judge the code under test with the code under test.
bool crlf_framed(std::string_view block)
{
    for (size_t i = 0; i < block.size(); i++)
    {
        if (block[i] == '\n')
        {
            if (i == 0 || block[i - 1] != '\r')
                return false;                       // bare LF
        }
        else if (block[i] == '\r')
        {
            if (i + 1 >= block.size() || block[i + 1] != '\n')
                return false;                       // bare CR
        }
    }
    return true;
}

// The verdict on one message in the forwarded stream, and how far past it the
// next message begins.
struct fwd_message
{
    const char* violation{nullptr};   // null when the message is unambiguous
    bool terminated{false};           // header block ended with a blank line
    bool chunked{false};
    size_t content_length{0};
    size_t body_offset{0};            // from the start of the message
};

// Judge one message of the forwarded stream the way a backend would, and say
// where its body starts.  `msg` runs from the request line to the end of the
// forwarded bytes; only the part up to the terminating blank line is judged.
fwd_message judge_message(std::string_view msg)
{
    fwd_message out;

    const size_t line_end = msg.find("\r\n");
    if (line_end == std::string_view::npos)
        return out;   // no request line here at all; nothing to frame

    std::string_view rest = msg.substr(line_end + 2);

    // A request with no headers at all ends right here, and everything behind
    // it belongs to whatever comes next on the connection -- not to this
    // message.  Searching on for a "\r\n\r\n" instead would walk past the
    // empty block and read a *pipelined* request's fields as this one's, which
    // is a different finding wearing this one's name.
    std::string_view headers;
    if (rest.compare(0, 2, "\r\n") == 0)
    {
        headers = {};
        out.terminated = true;
        out.body_offset = line_end + 2 + 2;
    }
    else
    {
        const size_t hdr_end = rest.find("\r\n\r\n");
        if (hdr_end == std::string_view::npos)
        {
            headers = rest;                     // block never terminated
            out.body_offset = msg.size();
        }
        else
        {
            headers = rest.substr(0, hdr_end);
            out.terminated = true;
            out.body_offset = line_end + 2 + hdr_end + 4;
        }
    }

    // The request line counts.  A bare LF in it splits the message somewhere
    // this side never looked, and the tail becomes a header line — or a request
    // line — for the backend alone.
    if (!crlf_framed(msg.substr(0, line_end + 2 + headers.size())))
    {
        out.violation = "a forwarded request's header block is not strictly CRLF-framed — "
                        "a bare LF or bare CR is one this proxy and a backend are free to "
                        "split differently, which is where the two stop agreeing about "
                        "where a request ends";
        return out;
    }

    unsigned cl_count = 0;
    for (std::string_view line : strict_header_lines(headers))
    {
        // Obs-fold: a continuation line is more of the previous value to one
        // recipient and a field of its own to another.
        if (line[0] == ' ' || line[0] == '\t')
        {
            out.violation = "a forwarded request carries an obs-fold continuation line "
                            "(RFC 9112 5.2), which a backend may unfold into a field this "
                            "proxy never saw";
            return out;
        }

        const size_t colon = line.find(':');
        if (colon == std::string_view::npos)
            continue;                        // not a field line; both sides skip it

        // Whitespace before the colon (RFC 9112 5.1): "Content-Length : 6" is
        // not a Content-Length to a strict parser and is one to a lenient parser.
        if (colon == 0 || line[colon - 1] == ' ' || line[colon - 1] == '\t')
        {
            out.violation = "a forwarded request has whitespace between a field name and "
                            "its colon (RFC 9112 5.1) — a lenient backend honours the field "
                            "and frames the body by it while this proxy ignored it";
            return out;
        }

        if (name_is(line, "content-length"))
        {
            cl_count++;

            // The value with its optional surrounding whitespace removed, and
            // then digits only.  Not "skip every space": "6 6" would come out as
            // 66 that way, which is a length neither end would have used.
            std::string_view val = line.substr(colon + 1);
            while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
                val.remove_prefix(1);
            while (!val.empty() && (val.back() == ' ' || val.back() == '\t'))
                val.remove_suffix(1);

            out.content_length = 0;
            bool whole_decimal = !val.empty();
            for (char c : val)
            {
                if (c < '0' || c > '9') { whole_decimal = false; break; }
                out.content_length = out.content_length * 10 + static_cast<size_t>(c - '0');
                // Saturate rather than wrap.  Any length this large already runs
                // past every byte that was forwarded, so the walk stops on it.
                if (out.content_length > (size_t{1} << 40))
                    out.content_length = size_t{1} << 40;
            }
            if (!whole_decimal)
            {
                out.violation = "a forwarded request's Content-Length is not a whole "
                                "decimal (RFC 9112 6.3) — the two ends then take the "
                                "body's length from different places";
                return out;
            }
        }
        else if (name_is(line, "transfer-encoding"))
        {
            out.chunked = true;
        }
    }

    if (cl_count > 1)
    {
        out.violation = "a forwarded request carries two Content-Length fields (RFC 9112 "
                        "6.3) — the message gives two answers to how long its body is and "
                        "each recipient picks one";
        return out;
    }

    if (cl_count > 0 && out.chunked)
    {
        out.violation = "a forwarded request carries both Content-Length and "
                        "Transfer-Encoding — RFC 7230 3.3.3 requires this to be rejected, "
                        "and a backend that disagrees with the proxy about where one "
                        "request ends is request smuggling";
        return out;
    }

    return out;
}

// The forwarded bytes, judged by a backend's line rules — every message in them,
// not only the first.
//
// Judging only the first was the hole this oracle had.  A backend reads a
// connection as a stream of messages: it frames one, and then it frames the
// next out of whatever follows.  So a payload put *second* was never looked at
// here, which is precisely the shape that used to get through the proxy —
// rewrite_http_request appended everything past the header terminator verbatim
// while parse_http_request_line validated only the message in front of it.  An
// oracle that stopped at message one could not see that, and did not.
void check_no_smuggling(std::string_view forwarded, const uint8_t* raw, size_t raw_size)
{
    // A stream of empty messages cannot occur — every step consumes at least a
    // request line — but the walk is over attacker-chosen bytes and gets a
    // ceiling rather than an argument.
    for (unsigned index = 0; index < 64 && !forwarded.empty(); index++)
    {
        const fwd_message m = judge_message(forwarded);

        if (m.violation)
        {
            if (smuggling_is_fatal())
                FUZZ_CHECK(false, m.violation);
            fuzz_observe(m.violation, raw, raw_size);
            return;
        }

        // Nothing terminated the header block, so there is no message behind
        // this one to walk to.
        if (!m.terminated)
            return;

        std::string_view body_and_rest = forwarded.substr(m.body_offset);

        // Chunked is where the walk has to stop, and honestly so.  The proxy
        // never de-chunks and cannot point at the terminating chunk (the
        // response side says the same thing in http_response_frame_complete),
        // so it forwards a chunked body as an opaque stream — and this oracle
        // cannot tell that stream's bytes from a message behind it either.
        // Reading on would report body content as a smuggled request.
        if (m.chunked)
            return;

        // The declared body eats the rest of what was forwarded: no further
        // message begins inside these bytes.
        if (m.content_length >= body_and_rest.size())
            return;

        forwarded = body_and_rest.substr(m.content_length);
    }
}

// A fresh proxy with one resolved backend, so the Host-rewrite branch of
// rewrite_http_request is live rather than falling through to "keep whatever
// the client sent".  Built once: the constructor is trivial and nothing here
// touches the event loop, but rebuilding it per input would still be waste.
// A static object rather than a `new` that never gets freed: ASan's leak
// checker runs at exit on these binaries and a deliberately leaked proxy would
// report as a finding, which is exactly the kind of noise that gets a whole
// sanitizer turned off.  The destructor only closes descriptors that were never
// opened here.
proxy_instance& shared_proxy()
{
    static proxy_instance px("fuzz");
    static const bool initialised = [] {
        px.set_protocol(protocol_http);
        px.add_backend("127.0.0.1:9");
        auto& backends = px.*fuzz_get(tag_backends{});
        backends[0].resolved_host = "127.0.0.1";
        backends[0].resolved_port = 9;
        return true;
    }();
    (void)initialised;
    return px;
}

// Model of the order in which handle_client_read calls the two functions:
// parse the request line, and once it succeeds rewrite what is buffered at that
// moment.  Bytes that arrive after the rewrite go out through the body path,
// which forwards only as much as the request declared — modelled at the end of
// this function, because getting that boundary wrong in either direction is
// what this target is about.
std::string feed(std::string_view chunk1, std::string_view chunk2)
{
    auto conn = std::make_unique<proxy_client_connection>();
    conn->reset(-1);

    proxy_instance& px = shared_proxy();
    auto parse = fuzz_get(tag_parse_request_line{});
    auto rewrite = fuzz_get(tag_rewrite_request{});

    std::string forwarded;

    if (!chunk1.empty())
        conn->partial.append(chunk1.data(), chunk1.size());
    // The parser reports three states now (need_more / complete / invalid);
    // this target only distinguishes 'a request came out of it' from 'not yet'.
    bool parsed = ((px.*parse)(conn.get()) == http_request_parse::complete);

    // Whether the second read had to arrive before the request line was
    // complete.  If it did, the rewrite below sees it and checks it; if it did
    // not, it goes to the backend behind the rewrite's back, and only the second
    // of those two is the case this target is about.
    bool chunk2_buffered = false;
    if (!parsed && !chunk2.empty())
    {
        conn->partial.append(chunk2.data(), chunk2.size());
        chunk2_buffered = true;
        parsed = ((px.*parse)(conn.get()) == http_request_parse::complete);
    }

    if (!parsed)
        return forwarded;   // still waiting for a complete request line

    // The request line held together: method, path and version must all be
    // slices of the line that was parsed, and none of them may contain the
    // terminator that separates them from the headers.
    FUZZ_CHECK(conn->ex.method.find('\r') == std::string::npos &&
               conn->ex.method.find('\n') == std::string::npos,
               "the parsed method contains a line terminator");
    FUZZ_CHECK(conn->ex.path.find('\r') == std::string::npos &&
               conn->ex.path.find('\n') == std::string::npos,
               "the parsed path contains a line terminator — it is spliced into the "
               "rewritten request line verbatim");
    FUZZ_CHECK(conn->ex.version.find('\r') == std::string::npos &&
               conn->ex.version.find('\n') == std::string::npos,
               "the parsed version contains a line terminator");

    // handle_client_read strips the runtime's own "/<name>" prefix and passes
    // what is left.  Feed it the parsed path unchanged: that is the shape the
    // rewrite sees for a bare-prefix request, and it keeps the path attacker-
    // controlled, which is the point.
    std::string new_path = conn->ex.path.empty() ? std::string("/") : conn->ex.path;
    (px.*rewrite)(conn.get(), new_path, forwarded);

    FUZZ_CHECK(!forwarded.empty(), "rewrite_http_request produced nothing from a request it accepted");
    FUZZ_CHECK(forwarded.find("\r\n") != std::string::npos,
               "the rewritten request has no request-line terminator");
    FUZZ_CHECK(forwarded.compare(0, conn->ex.method.size(), conn->ex.method) == 0,
               "the rewritten request does not begin with the method that was parsed");

    // Whatever had not arrived yet reaches the backend through
    // handle_client_read's body path, which forwards only as much as the
    // request declared and holds the rest back for the next parse.  Modelled
    // here rather than appended whole: "everything left over goes out raw" is
    // exactly the defect this target is about, and a model that keeps doing it
    // would report a hole the handler no longer has.  Appended at all only when
    // these bytes were not already folded into the buffer the rewrite ran over
    // — otherwise they would be counted twice and the oracle would fire on a
    // request that was in fact checked.
    if (!chunk2_buffered && !chunk2.empty())
    {
        const size_t n = conn->ex.body_unbounded
            ? chunk2.size()
            : std::min(conn->ex.body_remaining, chunk2.size());
        forwarded.append(chunk2.data(), n);
    }

    return forwarded;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    data = ::fuzz::never_null(data);
    ::fuzz::set_current(data, size);

    // MAX_HEADER_SIZE is 16 KB; past that the proxy answers 431 without
    // parsing, so larger inputs exercise nothing new.
    if (size > 64 * 1024)
        return 0;

    std::string_view all(reinterpret_cast<const char*>(data), size);

    // Whole request in one read.
    check_no_smuggling(feed(all, {}), data, size);

    // Same request split across two reads.  The split point comes from the
    // input's own last byte so the fuzzer can steer it; the case that matters
    // most is a split that lands right after the request line, because that is
    // the one where the header checks run against a buffer that has no headers
    // in it yet.
    if (size >= 2)
    {
        size_t split = static_cast<size_t>(::fuzz::byte_at(data, size, size - 1)) % size;
        check_no_smuggling(feed(all.substr(0, split), all.substr(split)), data, size);
    }

    // And the specific split the model above is about: everything up to and
    // including the first CRLF, then the rest.
    {
        size_t eol = all.find("\r\n");
        if (eol != std::string_view::npos && eol + 2 < all.size())
            check_no_smuggling(feed(all.substr(0, eol + 2), all.substr(eol + 2)), data, size);
    }

    ::fuzz::set_current(nullptr, 0);
    return 0;
}
