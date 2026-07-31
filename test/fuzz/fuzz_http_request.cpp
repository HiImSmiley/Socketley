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
// Beyond crashes, this target asserts one security property: the request the
// proxy forwards must not carry both a Content-Length and a Transfer-Encoding
// header when measured by a *strict* line splitter — one that treats a bare LF
// as a line terminator, the way most backends do.
//
// parse_http_request_line's own check splits headers on CRLF only, so a peer
// that separates the two headers with a bare LF presents them as one line to
// the check and as two lines to the backend.  Reading the code says that gets
// forwarded.  This target turns that reading into an executable claim rather
// than a paragraph in a review.
//
// If this oracle fires on the first CI run, that is the finding, not a broken
// test: read the reported input before touching the oracle.  FUZZ_SMUGGLING=0
// downgrades it to a warning for triage only.

#include "fuzz_common.h"

#include "runtime/proxy/proxy_instance.h"

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
    using type = std::string (proxy_instance::*)(proxy_client_connection*, std::string_view);
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

// The forwarded bytes, judged by a backend's line rules.
void check_no_smuggling(std::string_view forwarded, const uint8_t* raw, size_t raw_size)
{
    size_t line_end = forwarded.find("\r\n");
    if (line_end == std::string_view::npos)
        return;
    std::string_view headers = forwarded.substr(line_end + 2);

    // A request with no headers at all ends right here, and everything behind
    // it belongs to whatever comes next on the connection -- not to this
    // message.  Searching on for a "\r\n\r\n" instead would walk past the
    // empty block and read a *pipelined* request's fields as this one's, which
    // is a different finding wearing this one's name.
    if (headers.compare(0, 2, "\r\n") == 0)
        headers = {};
    else
    {
        size_t hdr_end = headers.find("\r\n\r\n");
        if (hdr_end != std::string_view::npos)
            headers = headers.substr(0, hdr_end);
    }

    bool cl = false, te = false;
    for (std::string_view line : strict_header_lines(headers))
    {
        if (name_is(line, "content-length"))    cl = true;
        if (name_is(line, "transfer-encoding")) te = true;
    }

    if (cl && te)
    {
        if (smuggling_is_fatal())
        {
            FUZZ_CHECK(false,
                       "the proxy forwarded a request carrying both Content-Length and "
                       "Transfer-Encoding — RFC 7230 3.3.3 requires this to be rejected, and "
                       "a backend that disagrees with the proxy about where one request ends "
                       "is request smuggling");
        }
        else
        {
            fuzz_observe("CL+TE survived the proxy's smuggling check (FUZZ_SMUGGLING=0)", raw, raw_size);
        }
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
// parse the request line, and once it succeeds rewrite everything buffered at
// that moment.  Bytes that arrive after the rewrite are forwarded raw, which is
// why they are appended to the result here — a smuggling check that only ran
// over the first chunk did not run over them.
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
    FUZZ_CHECK(conn->method.find('\r') == std::string::npos &&
               conn->method.find('\n') == std::string::npos,
               "the parsed method contains a line terminator");
    FUZZ_CHECK(conn->path.find('\r') == std::string::npos &&
               conn->path.find('\n') == std::string::npos,
               "the parsed path contains a line terminator — it is spliced into the "
               "rewritten request line verbatim");
    FUZZ_CHECK(conn->version.find('\r') == std::string::npos &&
               conn->version.find('\n') == std::string::npos,
               "the parsed version contains a line terminator");

    // handle_client_read strips the runtime's own "/<name>" prefix and passes
    // what is left.  Feed it the parsed path unchanged: that is the shape the
    // rewrite sees for a bare-prefix request, and it keeps the path attacker-
    // controlled, which is the point.
    std::string new_path = conn->path.empty() ? std::string("/") : conn->path;
    forwarded = (px.*rewrite)(conn.get(), new_path);

    FUZZ_CHECK(!forwarded.empty(), "rewrite_http_request produced nothing from a request it accepted");
    FUZZ_CHECK(forwarded.find("\r\n") != std::string::npos,
               "the rewritten request has no request-line terminator");
    FUZZ_CHECK(forwarded.compare(0, conn->method.size(), conn->method) == 0,
               "the rewritten request does not begin with the method that was parsed");

    // Whatever had not arrived yet goes to the backend without ever passing
    // through the checks above.  Appended only when it was not already folded
    // into the buffer the rewrite ran over — otherwise it would be counted
    // twice and the oracle would fire on a request that was in fact checked.
    if (!chunk2_buffered && !chunk2.empty())
        forwarded.append(chunk2.data(), chunk2.size());

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
