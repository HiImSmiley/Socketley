// Fuzz target: the proxy's HTTP *response* header parser — the one that decides
// whether a backend socket may be handed back to the connection pool.
// (socketley/shared/http_framing.h, called from
// proxy_instance::handle_backend_read.)
//
// ─── ON THE SEAM ────────────────────────────────────────────────────────────
//
// fuzz_http_request.cpp reaches its two functions through an explicit-
// instantiation access idiom, and its author wrote that the better answer was
// to lift the parse into free functions over string_view.  For the response
// side the idiom was not merely worse, it was unavailable: this parser was not
// a private member function, it was a hundred and twenty lines of code sitting
// in the middle of handle_backend_read, between a provided-buffer lookup and a
// circuit-breaker update.  A block of statements inside a completion handler is
// not a symbol; there is nothing to take the address of.
//
// So the lift was done, and it is small: the state is one plain struct, the
// scan is one function over (state&, string_view), the pooling predicate is one
// function over (const state&).  proxy_instance.cpp is 160 lines shorter,
// handle_backend_read lost a goto and a label, proxy_backend_connection lost
// nine loose members and reset() lost nine assignments — a field added to the
// framing state can no longer be forgotten in reset() and leak from one
// response into the next.  Nothing else in socketley/ was touched.  In
// particular the *request* side was left alone: rewrite_http_request reads
// m_backends and m_prefix and writes through a proxy_client_connection, so
// lifting that one is a redesign rather than a move, and fuzz_http_request's
// machinery stays.
//
// The dividend is not only that this target exists.  Because the header pulls
// in nothing but <charconv> and <string_view> — no io_uring, no sockets, no
// proxy_instance — this target compiles in a second and belongs in the per-push
// CI job, where fuzz_http_request costs fifteen SDK translation units and is
// nightly-only.
//
// ─── WHY THIS PARSER AND NOT ANOTHER ────────────────────────────────────────
//
// It was the last parser an unauthenticated peer can reach with no fuzz target,
// and its consequence is one step worse than the request side's.  A misparsed
// *request* reaches a backend as something other than what the client sent.  A
// misparsed *response length* pools the backend socket with bytes still coming,
// and the next borrower reads the tail of a stranger's response as the head of
// its own — a data leak between unrelated clients, produced by a backend that
// need not be malicious, only unusual.  Two defects were found here by reading
// and fixed on 2026-07-31 (a CRLF-only header split that merged Content-Length
// with a bare-LF Transfer-Encoding, and a scan that only ever looked at the
// current read rather than an accumulated buffer), which is the evidence that
// reading is not enough.
//
// ─── THE ORACLE ─────────────────────────────────────────────────────────────
//
// "No crash" is worth almost nothing on this parser: it is bounds-safe, it
// allocates nothing, and it would survive every input in this corpus while
// still handing out the wrong answer.  So the target states the property the
// code exists to hold and checks that instead.
//
// The property is about the *pooling decision*, not the field values.  Field
// values are the parser's own opinion; whether the socket may be reused is a
// claim about the bytes.  Concretely, when the parser first says
// http_response_frame_complete() — the exact predicate both pooling paths in
// proxy_instance.cpp consult — with N bytes consumed:
//
//   1. an independent reading of those same bytes must be able to say where
//      this response ends at all, and
//   2. that end must be at or before N.
//
// If (2) fails the socket goes to the pool with the rest of the answer still on
// the wire.  If (1) fails the socket goes to the pool at an offset nobody can
// name, which is the same outcome reached by a different route.  The converse —
// the reference can frame it and the parser cannot — is not checked, because
// declining to pool is always safe.
//
// The reference framer below is deliberately a *different* implementation, not
// a copy: it splits lines permissively (LF terminates, the way a lenient
// backend does) and then requires a strict CRLF reader to agree, it rejects
// what RFC 9112 requires a recipient to reject, and it resolves every remaining
// doubt to "cannot say".  Being conservative in that direction is what makes
// the one-sided check above sound.
//
// FUZZ_HTTPRESP_SKIP=<id>[,<id>...] demotes a named finding to a printed
// observation, so one known defect does not stop every input and hide the next.
// Triage only.  The ids are the first argument of each RESP_FINDING below.

#include "fuzz_common.h"

#include "shared/http_framing.h"

#include <cstdlib>
#include <cstring>
#include <string_view>

namespace {

// ─── finding suppression (same contract as fuzz_cache_ops) ──────────────────

bool finding_suppressed(const char* id)
{
    static const char* const env = [] {
        const char* e = std::getenv("FUZZ_HTTPRESP_SKIP");
        return (e && *e) ? e : nullptr;
    }();
    if (!env)
        return false;
    const size_t n = std::strlen(id);
    for (const char* p = env; *p; )
    {
        const char* e   = std::strchr(p, ',');
        const char* end = e ? e : p + std::strlen(p);
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n')) p++;
        while (end > p && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\n')) end--;
        if (static_cast<size_t>(end - p) == n && std::strncmp(p, id, n) == 0)
            return true;
        if (!e)
            break;
        p = e + 1;
    }
    return false;
}

// Allocation-free for the reason given in fuzz_cache_ops: libFuzzer runs a leak
// scan whenever an input's mallocs and frees do not balance, and a harness that
// grows a static buffer triggers a forked heap walk per execution.  Ids are
// string literals, so pointer identity is enough to count them.
void observe_once(const char* id, const char* what)
{
    static const char* ids[16] = {nullptr};
    static int         hits[16] = {0};
    for (int i = 0; i < 16; i++)
    {
        if (ids[i] == nullptr)
            ids[i] = id;
        if (ids[i] == id)
        {
            if (hits[i]++ < 3)
                std::fprintf(stderr, "[fuzz-httpresp] suppressed finding '%s': %s\n", id, what);
            return;
        }
    }
}

#define RESP_FINDING(id, expr, what)                                          \
    do {                                                                      \
        if (!(expr))                                                          \
        {                                                                     \
            if (finding_suppressed(id)) observe_once(id, what);                \
            else ::fuzz::fail(#expr, __FILE__, __LINE__, (what));              \
        }                                                                     \
    } while (0)

// ─── the reference framer ───────────────────────────────────────────────────
//
// An independent answer to "where does this response end", written from RFC
// 9112 Sections 6.1-6.3 rather than from the parser under test.  Everything it
// cannot settle without assuming which of two readings a backend picked comes
// back as `ambiguous`, and `ambiguous` is the verdict the parser is not allowed
// to answer "poolable" to.

struct ref_view
{
    bool     headers_complete{false};  // a blank line was reached
    bool     ambiguous{false};         // no single reading of the framing
    bool     status_readable{false};   // a three-digit code was found
    uint16_t code{0};
    bool     has_length{false};        // exactly one agreed Content-Length
    size_t   length{0};
    size_t   headers_end{0};           // offset just past the blank line
    bool     says_close{false};        // Connection carries the token "close"
    bool     coded{false};             // a Transfer-Encoding is present
    bool     chunked{false};           // ... and chunked is its final coding
    size_t   chunk_end{std::string_view::npos};  // where that chunked body ends

    // Why the framing has no single reading.  Kept as a pair of string
    // literals rather than an enum so each cause reports and suppresses under
    // its own id: one known defect must not stop every input and hide the rest,
    // and "ambiguous" as a single bucket would do exactly that.  Pointer
    // identity is what observe_once counts by, so these must stay literals.
    const char* amb_id{nullptr};
    const char* amb_what{nullptr};
};

void mark(ref_view& r, const char* id, const char* what)
{
    r.ambiguous = true;
    r.amb_id    = id;
    r.amb_what  = what;
}

bool ieq(std::string_view a, std::string_view b)   // b must be lowercase
{
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); i++)
        if (static_cast<char>(a[i] | 0x20) != b[i])
            return false;
    return true;
}

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t')) s.remove_suffix(1);
    return s;
}

// A comma-separated list carries `tok` (case-insensitive), ignoring empty
// elements the way an HTTP list is allowed to.
bool list_has_token(std::string_view val, std::string_view tok)
{
    size_t pos = 0;
    for (;;)
    {
        const size_t comma = val.find(',', pos);
        std::string_view item = trim(val.substr(pos, (comma == std::string_view::npos)
                                                        ? std::string_view::npos : comma - pos));
        if (ieq(item, tok))
            return true;
        if (comma == std::string_view::npos)
            return false;
        pos = comma + 1;
    }
}

// Whole-field decimal, no sign, no trailing anything, no overflow.
bool all_digits(std::string_view s, size_t& out)
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

// One header block starting at `from`.  Does not follow 1xx; reference_frame
// below does that.
ref_view read_one_block(std::string_view sv, size_t from)
{
    ref_view r;

    // ── pass 1: find the blank line, permissively ──
    // LF terminates a line and a single trailing CR is dropped, which is how a
    // lenient backend reads it.  Anything that makes the permissive reading and
    // the strict CRLF reading differ is recorded, not resolved.
    bool   sloppy_eol = false;
    size_t block_end  = std::string_view::npos;
    size_t p          = from;
    while (p <= sv.size())
    {
        const size_t nl = sv.find('\n', p);
        if (nl == std::string_view::npos)
            return r;                           // headers never finished
        std::string_view line = sv.substr(p, nl - p);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        else
            sloppy_eol = true;                  // bare LF
        if (line.find('\r') != std::string_view::npos)
            sloppy_eol = true;                  // bare CR inside a line
        p = nl + 1;
        if (line.empty())
        {
            block_end = p;
            break;
        }
    }
    if (block_end == std::string_view::npos)
        return r;

    r.headers_complete = true;
    r.headers_end      = block_end;

    // A strict CRLF reader has to end the block in exactly the same place.  If
    // it does not, this proxy and its backend are looking at different header
    // blocks and no length either of them computes means anything.
    const size_t strict = sv.find("\r\n\r\n", from);
    if (sloppy_eol || strict == std::string_view::npos || strict + 4 != block_end)
    {
        mark(r, "pool-eol",
             "the response header block is not strictly CRLF-framed, so a backend that "
             "honours a bare LF and this proxy see different header lines — the classic "
             "form being Content-Length and Transfer-Encoding merged into one line — and "
             "the socket was still declared poolable");
        return r;
    }

    // ── pass 2: the status line and the framing headers ──
    const std::string_view block = sv.substr(from, block_end - from - 2);  // without the blank line
    size_t                 lpos  = 0;
    bool                   first = true;
    int                    cl_count = 0;
    bool                   cl_bad = false;
    size_t                 cl_value = 0;

    while (lpos < block.size())
    {
        size_t nl = block.find("\r\n", lpos);
        if (nl == std::string_view::npos)
            nl = block.size();
        const std::string_view line = block.substr(lpos, nl - lpos);
        lpos = nl + 2;

        if (first)
        {
            first = false;
            // "HTTP/x.y NNN[ reason]".  A code that cannot be read is not a
            // framing ambiguity on its own — it is recorded so the oracle can
            // report it separately — but it does mean 1xx/204/304 cannot be
            // ruled out, so the caller treats an unreadable code as no length.
            const size_t sp = line.find(' ');
            if (line.size() >= 5 && ieq(line.substr(0, 5), "http/") &&
                sp != std::string_view::npos && sp + 4 <= line.size() &&
                line[sp + 1] >= '0' && line[sp + 1] <= '9' &&
                line[sp + 2] >= '0' && line[sp + 2] <= '9' &&
                line[sp + 3] >= '0' && line[sp + 3] <= '9' &&
                (sp + 4 == line.size() || line[sp + 4] == ' '))
            {
                r.status_readable = true;
                r.code = static_cast<uint16_t>((line[sp + 1] - '0') * 100 +
                                               (line[sp + 2] - '0') * 10 +
                                               (line[sp + 3] - '0'));
            }
            continue;
        }

        // Obsolete line folding.  RFC 9112 Section 5.2: a recipient that is not
        // a message/http parser MUST reject it or replace it with SP before
        // forwarding.  This parser does neither — it reads the continuation as
        // a header line of its own — so what it thinks the headers are and what
        // the backend meant are two different things.
        if (line[0] == ' ' || line[0] == '\t')
        {
            mark(r, "pool-obs-fold",
                 "a folded (leading-whitespace) header line was read as a header of its "
                 "own, so this proxy and its backend disagree about which fields the "
                 "response carries, and the socket was still declared poolable");
            return r;
        }

        const size_t colon = line.find(':');
        if (colon == std::string_view::npos)
            continue;                           // not a header line; both sides skip it

        const std::string_view name = line.substr(0, colon);
        // Whitespace between the field name and the colon.  RFC 9112 Section
        // 5.1 requires a response carrying one to be treated as unrecoverable,
        // precisely because recipients disagree about whether the field counts.
        if (name.find(' ') != std::string_view::npos || name.find('\t') != std::string_view::npos)
        {
            mark(r, "pool-name-ws",
                 "a field name with whitespace before its colon was ignored by this proxy "
                 "and may be honoured by the backend (RFC 9112 Section 5.1 requires the "
                 "message to be rejected outright), so the two can take their length from "
                 "different fields, and the socket was still declared poolable");
            return r;
        }

        const std::string_view val = trim(line.substr(colon + 1));

        if (ieq(name, "content-length"))
        {
            size_t v = 0;
            if (!all_digits(val, v))
                cl_bad = true;
            else if (cl_count > 0 && v != cl_value)
                cl_bad = true;                  // two different lengths
            else
                cl_value = v;
            cl_count++;
        }
        else if (ieq(name, "transfer-encoding"))
        {
            // Any transfer coding at all makes Content-Length inoperative
            // (RFC 9112 Section 6.1): if the final coding is chunked the body
            // is framed by chunk sizes, and if it is not, a response body runs
            // to connection close.  Codings are read left to right across every
            // Transfer-Encoding line, and one after chunked is no framing.
            size_t pos = 0;
            for (;;)
            {
                const size_t comma = val.find(',', pos);
                std::string_view item = val.substr(pos, (comma == std::string_view::npos)
                                                        ? std::string_view::npos : comma - pos);
                const size_t semi = item.find(';');
                if (semi != std::string_view::npos) item = item.substr(0, semi);
                item = trim(item);
                if (!item.empty())
                {
                    r.coded = true;
                    if (r.chunked)
                    {
                        mark(r, "pool-te-after-chunked",
                             "a coding follows chunked, so the chunk sizes do not frame the "
                             "body and the socket was still declared poolable");
                        return r;
                    }
                    if (ieq(item, "chunked"))
                        r.chunked = true;
                }
                if (comma == std::string_view::npos)
                    break;
                pos = comma + 1;
            }
        }
        else if (ieq(name, "connection"))
        {
            if (list_has_token(val, "close"))
                r.says_close = true;
        }
    }

    if (cl_bad)
    {
        mark(r, "pool-cl-bad",
             "the Content-Length is not a whole decimal number, or two of them disagree; "
             "this proxy took a value out of it anyway and declared the socket poolable, "
             "and a backend that read it differently or refused it leaves the stream "
             "somewhere else entirely");
        return r;
    }
    if (cl_count > 0 && r.coded)
    {
        mark(r, "pool-te",
             "the response carries both a Transfer-Encoding and a Content-Length, the "
             "shape RFC 9112 Section 6.3 says must be treated as an error, and the socket "
             "was still declared poolable");
        return r;
    }
    if (cl_count > 0)
    {
        r.has_length = true;
        r.length     = cl_value;
    }
    return r;
}

// Where a chunked body starting at `from` ends, or npos when it has not ended
// in these bytes or cannot be read one way only.  Written from RFC 9112
// Section 7.1 and not from the decoder: a line is CRLF-terminated with no other
// CR or LF in it, a size is hex digits then optional whitespace then optional
// extensions, a chunk's data is followed by exactly CRLF, and the trailer
// section runs to an empty line.
size_t reference_chunked_end(std::string_view sv, size_t from, ref_view& r)
{
    auto line_at = [&](size_t at, std::string_view& line) -> bool {
        const size_t nl = sv.find("\r\n", at);
        if (nl == std::string_view::npos)
            return false;
        line = sv.substr(at, nl - at);
        return true;
    };
    auto bare_eol = [](std::string_view l) {
        return l.find('\r') != std::string_view::npos || l.find('\n') != std::string_view::npos;
    };

    size_t p = from;
    for (;;)
    {
        std::string_view line;
        if (!line_at(p, line))
            return std::string_view::npos;
        if (bare_eol(line))
        {
            mark(r, "pool-chunk-eol",
                 "a chunk-size line carries a bare CR or LF, so a lenient reader ends it "
                 "somewhere else, and the socket was still declared poolable");
            return std::string_view::npos;
        }
        size_t i = 0, size = 0;
        bool   any = false;
        for (; i < line.size(); i++)
        {
            const char c = line[i];
            int d;
            if (c >= '0' && c <= '9')      d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else break;
            if (size > (SIZE_MAX - static_cast<size_t>(d)) / 16)
                return std::string_view::npos;
            size = size * 16 + static_cast<size_t>(d);
            any = true;
        }
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) i++;
        if (!any || (i < line.size() && line[i] != ';'))
            return std::string_view::npos;
        p += line.size() + 2;

        if (size == 0)
        {
            for (;;)
            {
                std::string_view t;
                if (!line_at(p, t))
                    return std::string_view::npos;
                if (bare_eol(t))
                    return std::string_view::npos;
                p += t.size() + 2;
                if (t.empty())
                    return p;
            }
        }
        if (sv.size() - p < size + 2)
            return std::string_view::npos;
        if (sv[p + size] != '\r' || sv[p + size + 1] != '\n')
            return std::string_view::npos;
        p += size + 2;
    }
}

// Follow interim 1xx responses to the real one, the way the parser's own reset
// path is meant to.  Bounded: an endless run of 1xx blocks is a stream with no
// response in it, and the reference says so rather than looping.
ref_view reference_frame(std::string_view sv)
{
    size_t from = 0;
    for (int hop = 0; hop < 8; hop++)
    {
        ref_view r = read_one_block(sv, from);
        if (!r.headers_complete || r.ambiguous)
            return r;
        if (r.status_readable && r.code >= 100 && r.code < 200)
        {
            from = r.headers_end;               // 1xx has no body; the next block starts here
            continue;
        }
        if (r.chunked && r.status_readable && r.code != 204 && r.code != 304)
            r.chunk_end = reference_chunked_end(sv, r.headers_end, r);
        return r;
    }
    ref_view r;
    r.headers_complete = true;
    mark(r, "pool-1xx-chain",
         "the stream is nothing but interim 1xx responses, so no final response has "
         "arrived and there is no message boundary at all, yet the socket was declared "
         "poolable");
    return r;
}

// Where the reference says this response ends, or npos for "cannot say".
size_t reference_boundary(const ref_view& r)
{
    if (!r.headers_complete || r.ambiguous || !r.status_readable)
        return std::string_view::npos;
    if (r.code == 204 || r.code == 304)
        return r.headers_end;                   // no body, whatever the headers claim
    if (r.chunked)
        return r.chunk_end;
    if (r.coded)
        return std::string_view::npos;          // another coding runs to close
    if (r.has_length)
        return r.headers_end + r.length;
    return std::string_view::npos;              // close-delimited: no boundary short of EOF
}

// ─── the model of handle_backend_read ───────────────────────────────────────
//
// One `feed` is one backend connection receiving one response in a given
// sequence of reads.  handle_backend_read calls the scan once per completion
// and asks the pooling predicate afterwards, detaching the socket the first
// time the answer is yes — so that first yes is the moment being judged here,
// and `consumed` at that moment is where the socket's stream position would be.
struct feed_result
{
    bool   completed{false};
    size_t consumed_at_complete{0};
};

void check_frame_invariants(const http_response_framing& st,
                            bool had_cl_before, size_t prev_remaining)
{
    // The stated contract of `unknown`: a response whose end could not be
    // established is never poolable.  backend_pool_eligible() also refuses on
    // this flag directly, so this is the shared predicate holding up its half.
    FUZZ_CHECK(!(st.unknown && http_response_frame_complete(st)),
               "the framing was marked unknown and the pooling predicate still "
               "said the response was complete — a socket whose stream position "
               "nobody can name would be handed to the pool");

    // The other half of that contract, and the half that had to be stated
    // separately once an overrun stopped being spelled `unknown`.
    //
    // An overrun response IS complete — its Content-Length ran out, and saying
    // otherwise is what lost a pipelined request (see the `overrun` field).  So
    // http_response_frame_complete() answers yes for one and must; what may not
    // happen is the socket being pooled, and http_response_pool_safe() is the
    // predicate carrying that now.  Without this line, moving the verdict off
    // `unknown` would have removed a guarantee this target was making and put
    // nothing in its place.
    FUZZ_CHECK(!(st.overrun && http_response_pool_safe(st)),
               "bytes arrived past the end of the response and the pooling "
               "predicate still said the socket was safe to hand on — the next "
               "request to borrow it reads those bytes as the head of its own "
               "answer");

    // No wrap.  body_remaining is a size_t counting down; an underflow turns
    // "one byte left" into "eighteen exabytes left", which never completes, and
    // the reverse arithmetic mistake completes immediately.
    if (had_cl_before && st.has_content_length)
        FUZZ_CHECK(st.body_remaining <= prev_remaining,
                   "Content-Length remainder grew while consuming body bytes — "
                   "the countdown wrapped");

    FUZZ_CHECK(st.status_code < 1000, "a status code with more than three digits was recorded");
}

void feed(std::string_view all, const size_t* cuts, size_t ncuts,
          const uint8_t* raw, size_t raw_size)
{
    http_response_framing st{};
    feed_result           out;

    const ref_view r = reference_frame(all);
    const size_t   M = reference_boundary(r);

    size_t consumed = 0;
    for (size_t i = 0; i < ncuts; i++)
    {
        const size_t end = cuts[i];
        if (end <= consumed || end > all.size())
            continue;                           // a degenerate cut, not a read
        const std::string_view chunk = all.substr(consumed, end - consumed);

        const bool   had_cl  = st.has_content_length;
        const size_t prev_br = st.body_remaining;

        http_response_scan_chunk(st, chunk);
        consumed = end;

        check_frame_invariants(st, had_cl, prev_br);

        if (out.completed || !http_response_frame_complete(st))
            continue;

        // ── the first yes: this is where the socket would be pooled ──
        out.completed            = true;
        out.consumed_at_complete = consumed;

        RESP_FINDING("pool-no-headers", r.headers_complete,
                     "the parser declared the response complete and poolable before a "
                     "header block had even finished arriving — there is no message here "
                     "to be at the end of");

        if (r.ambiguous)
            RESP_FINDING(r.amb_id, false, r.amb_what);

        // Everything below is about where the response ends, which only means
        // something once the reference agrees it can read the headers at all.
        // (Reachable with ambiguous still set when the finding above was
        // demoted with FUZZ_HTTPRESP_SKIP.)
        if (!r.headers_complete || r.ambiguous)
            continue;

        if (!r.status_readable)
        {
            // The status line yields no three-digit code, so 1xx / 204 / 304 —
            // the codes that override Content-Length — cannot be ruled out, and
            // the parser framed the response by Content-Length anyway.  Real,
            // but it needs a backend that emits a malformed status line, so it
            // is recorded rather than fatal; a run stopping here would never
            // reach the shapes a working backend can actually produce.
            fuzz_observe("the response was framed by Content-Length although its status "
                         "line carries no readable code — 1xx/204/304 could not be ruled out",
                         raw, raw_size);
        }
        else if (M == std::string_view::npos)
        {
            RESP_FINDING("pool-no-boundary", false,
                         "the parser declared the response complete and poolable, but "
                         "nothing in the headers says where it ends — no Content-Length "
                         "and no status that forbids a body, which means the body runs "
                         "to connection close and the socket is never at a message "
                         "boundary");
        }
        else
        {
            RESP_FINDING("pool-early",
                         M <= consumed,
                         "the parser declared the response complete after fewer bytes "
                         "than the response actually occupies — the backend socket goes "
                         "to the pool with the tail of this answer still to come, and "
                         "the next request to borrow it reads that tail as the head of "
                         "its own response");
        }

        // Not fatal, and deliberately so: pooling a socket the backend said it
        // would close costs the next borrower one failed request, which retry
        // covers.  It is the same parser being too narrow — the value is
        // matched on its first two characters, so "keep-alive, close" reads as
        // keep-alive — and it belongs in the record without stopping the run.
        if (r.says_close && !st.conn_close)
            fuzz_observe("the backend sent Connection: close and the parser did not see it; "
                         "the socket was pooled anyway",
                         raw, raw_size);
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    data = ::fuzz::never_null(data);
    ::fuzz::set_current(data, size);

    // PROXY_READ_BUF_SIZE is 64 KB, so a single read never delivers more than
    // that and a longer input exercises no new arithmetic.
    if (size > 64 * 1024)
        return 0;

    const std::string_view all(reinterpret_cast<const char*>(data), size);

    // Cut lists.  Each one is a different sequence of reads over the same
    // bytes, because where the read boundaries fall is the peer's choice, not
    // ours — the backend decides it by choosing when to flush, and a network
    // decides the rest.  That freedom is the whole reason `response_bytes_seen`
    // and `unknown` exist, and it is what an end-to-end test never varies.
    size_t cuts[64];

    // 1. One read: the common case, and the only one where the header scan gets
    //    the whole block at once.
    cuts[0] = size;
    feed(all, cuts, 1, data, size);

    if (size >= 2)
    {
        // 2. A split the fuzzer steers, taken from the input's own last byte.
        const size_t at = static_cast<size_t>(::fuzz::byte_at(data, size, size - 1)) % size;
        cuts[0] = at;
        cuts[1] = size;
        feed(all, cuts, 2, data, size);
    }

    // 3. The header block whole in the first read and the body after it — what
    //    a keep-alive exchange with a body larger than one segment looks like,
    //    and the only shape in which the Content-Length countdown runs across
    //    more than one completion.
    {
        const size_t hdr = all.find("\r\n\r\n");
        if (hdr != std::string_view::npos && hdr + 4 < size)
        {
            cuts[0] = hdr + 4;
            cuts[1] = size;
            feed(all, cuts, 2, data, size);

            // 3b. …and with the body itself split in two, so the countdown is
            //     stepped rather than settled in one go.
            const size_t mid = hdr + 4 + (size - hdr - 4) / 2;
            cuts[0] = hdr + 4;
            cuts[1] = mid;
            cuts[2] = size;
            feed(all, cuts, 3, data, size);
        }

        // 4. A read boundary inside the header block, including one that lands
        //    between the CR and the LF of the terminator.  This is the shape
        //    the `response_bytes_seen` guard exists for: the first read has no
        //    "\r\n\r\n" in it, so a scan that looked at each read on its own
        //    found its terminator inside the body of the second one.
        if (hdr != std::string_view::npos && hdr >= 1)
        {
            cuts[0] = hdr / 2 + 1;
            cuts[1] = size;
            feed(all, cuts, 2, data, size);

            cuts[0] = hdr + 3;                  // between the second CR and its LF
            cuts[1] = size;
            feed(all, cuts, 2, data, size);
        }
    }

    // 5. Many small reads.  The adversarial chunking — a backend that flushes a
    //    few bytes at a time reaches every state transition in order — capped so
    //    the executions-per-second the fuzzer gets stays useful.
    if (size >= 2)
    {
        const size_t step = 1 + static_cast<size_t>(::fuzz::byte_at(data, size, 0)) % 8;
        size_t n = 0;
        for (size_t at = step; at < size && n < 63; at += step)
            cuts[n++] = at;
        cuts[n++] = size;
        feed(all, cuts, n, data, size);
    }

    ::fuzz::set_current(nullptr, 0);
    return 0;
}
