// Fuzz target: proxy_instance (socketley/runtime/proxy/proxy_instance.{h,cpp})
// driven as a *sequence of lifecycle, connection and backend operations* against
// a real io_uring event_loop, with real clients on one side and real backends on
// the other.
//
// The reasoning for this shape of target, and the four invariants every one of
// them inherits, are in test/fuzz/fuzz_runtime_ops.h.  What follows is what is
// specific to the proxy — which is the runtime that needed this most and had it
// least.
//
// ─── WHY THE PROXY NEEDED ITS OWN ───────────────────────────────────────────
//
// fuzz_http_request and fuzz_http_response already throw bytes at proxy code,
// and both found real defects.  Neither can reach the ones that actually cost
// this project its week, because those are not about the content of a message:
//
//   * a group gateway that gave up on a backend handshake by closing the client
//     without writing one byte to it — no status, no framing error, nothing a
//     client can tell apart from the proxy dying (84d624c);
//   * a backend socket pooled somewhere other than a message boundary, so the
//     next borrower read the tail of a stranger's response as the head of its
//     own — nine separate ways of reaching it (70a8c6a), and then a tenth from
//     the teardown paths (984dadc);
//   * a pooled connection the backend had already closed, which cost the client
//     its request and told it nothing (984dadc);
//   * an @group gateway opening a fresh TCP connection for every single
//     request, because the pool key could not express a group member (decdb7d).
//
// Every one of those needs a *history* — connect, request, answer, pool, change
// the membership, request again, abort in the middle — and none is a function of
// any byte on any socket.  So the input decodes to a program of typed
// operations, the program runs against a real proxy_instance with real peers at
// both ends, and the invariants below are checked after every single step.
//
// ─── THE THREE INVARIANTS THIS TARGET ADDS ──────────────────────────────────
//
// The four in fuzz_runtime_ops.h are about the ring.  These three are about the
// user, and they are the ones the expensive defects broke: not one of those
// crashed, and a target that only asks "did it fall over" would have called
// every one of them a clean run.
//
//  A. NO CLIENT IS EVER CLOSED WITHOUT AN ANSWER once it has sent a complete
//     request.  `client-closed-without-answer`.  This is exactly what 84d624c
//     and 984dadc fixed, and it is invisible from inside the proxy: every
//     counter is happy, no error is recorded anywhere, and the only party that
//     finds out is the client.  So it is checked from the client's socket —
//     the connection was closed by the far end, this client had a whole request
//     outstanding, and not one byte ever came back.
//
//  B. NO POOLED SOCKET IS HANDED OUT OFF A MESSAGE BOUNDARY.  Checked from the
//     backend's end, which is the only end that knows: the harness backend
//     tracks whether it has finished the response it is writing, and a socket
//     the proxy *files* in its pool while that answer is unfinished is
//     `pool-off-boundary`.  The same fact from the other direction is
//     `request-on-unfinished-socket`: a request arriving on a backend socket
//     whose previous response never completed, which is the moment the next
//     borrower inherits somebody else's tail.
//
//  C. NO RESPONSE REACHES A CLIENT THAT DID NOT ASK FOR IT.  `crosstalk`.
//     Every request carries an `X-Fuzz-Req: <n>` header with an id owned by
//     exactly one client; the harness backend echoes it back as `X-Fuzz-Ack`,
//     and every client checks the marks in what it receives against its own.
//     This is the failure that matters most and it is completely silent — the
//     bytes are well formed, the framing is correct, and they are simply the
//     wrong bytes.
//
//     C holds over an encrypted backend leg too, and that is not a free
//     extension of it.  The proxy pools TLS backend sockets, so the socket a
//     client's request goes out on may be one a previous client used; what
//     stops the previous exchange leaking into this one is a probe that
//     decrypts whatever is waiting and asks whether any of it was application
//     data.  `pooled_tls_socket_speaks_unbidden` is C over that path, and it
//     fires when the probe is taken out.
//
//  D. A POOLED SOCKET IS THE CONNECTION IT IS FILED AS.  Two statements, both
//     from outside the proxy, because both halves of what the proxy compares
//     come from the same function of its own.  `pooled-entry-endpoint` asks
//     the kernel, through getpeername(), whether a pooled socket really goes
//     to the endpoint it is filed under — which is the whole identity check
//     on the acquire side, and on an encrypted leg is also the SNI name and
//     the name the peer's certificate was verified against.
//     `pooled-entry-session` asks whether an entry's session and the leg the
//     harness configured agree.  See check_backend_pool().
//
// ─── AND WHERE EACH OF THE THREE IS ENTITLED TO SPEAK ────────────────────────
//
// All three are stated over the harness's own bookkeeping while the program
// decides independently when a backend reads, when it answers and when a client
// writes.  Each of them used to be stated at a moment where that bookkeeping
// had already moved on, and each of them accused the proxy of it.  Between them
// they cost three agents a day of re-diagnosis on 2026-08-01 and hid one real
// defect behind the noise, so the moment each one speaks is now part of the
// invariant rather than an accident of where the check happened to sit:
//
//   A speaks about requests the proxy has undertaken to answer.  A request
//     written into a connection the proxy has already said it is ending — a
//     response carrying Connection: close — is not one of those, and does not
//     move the ledger.  See client_send().
//
//   B speaks about the filing decision, once, at the moment release_to_pool()
//     makes it.  What a backend does to a socket that is already correctly
//     filed is that backend's traffic; whether the next borrower survives it is
//     the acquire probe's question and C's, not B's.  See check_backend_pool().
//
//   C speaks about marks, and a mark is only evidence if this harness put the
//     right one on the answer.  An answer written over a request this end never
//     read is answered blind: the id belongs to whoever the proxy has on the
//     other end of that socket now, and this end does not know who that is.
//     See bsock_respond() and bsock_note_request().
//
// None of the three excludes a case to be quieter.  Each excludes a case where
// its own words would be false, and every one of them still fires on the defect
// it was written for the moment that defect is put back — which is the only
// test of a change like this that means anything, and is written into the
// commit that made it.
//
// ─── AND THE THREE IT INHERITS FROM THE PRODUCT ─────────────────────────────
//
// socketley/shared/invariants.h states three properties of its own and this
// target is built with SOCKETLEY_INVARIANTS, so they are live here and they
// abort on their own account rather than through RT_FINDING.  Two of the three
// were written on 2026-08-01 for defects this target could reach and could not
// see, and they are the reason a run of this file is worth more than the sum of
// the checks written below:
//
//   (1) / (1b) REACHABILITY AND PROGRESS-REACHABILITY, over a pair.  (1) is old:
//     nothing in flight on either half means no completion is coming.  (1b) is
//     the sharpening 6f7b9e2 proved was needed — a client that has half-closed
//     and is owed no answer is dead however much the ring has armed on its
//     backend, because a backend's idle multishot read completes only if the
//     backend sends, and a backend with no request outstanding never does.  That
//     is the 26-connection leak, and every functional check in this file passed
//     while it happened.
//
//   (3) PROGRESS.  Completions charged to a connection must be matched by
//     observable change on it — bytes the kernel confirmed, or the connection's
//     own state moving.  The end-of-stream re-arm that reached 1,352,398
//     iterations on one connection violated nothing else anywhere: no byte was
//     lost, no framing was wrong, and this target ran it and reported a clean
//     execution.
//
// Their aborts print the decoded program, the same as a finding below —
// fuzzrt::adopt_invariant_reports() in init_once() is what arranges that.  They
// have no ids and FUZZ_PROXY_SKIP cannot demote them, which is deliberate: the
// only lever over them is -DSOCKETLEY_INVARIANTS_WARN_ONLY, it would take the
// same assertions out of fuzz_server_ops and fuzz_client_ops with it, and it
// stays unset.
//
// ─── WHAT IS REAL HERE AND WHAT IS NOT ──────────────────────────────────────
//
// Everything on the wire.  One process-wide event_loop with a real ring, a real
// proxy_instance bound to a real loopback port, real client sockets opened by
// the harness, and real listening sockets the proxy dials as its backends.  The
// backends are driven by the program rather than by a policy: what they accept,
// what they answer, how much of it they answer, and when they hang up are all
// operations, because the orderings between those and the client's are where the
// defects were.
//
// Both legs can be encrypted, independently, and the harness speaks OpenSSL
// directly at each end rather than through shared/tls_context.h — see the note
// above write_tls_material() for why a peer built on the record layer under
// test would report a clean handshake whatever that layer did.
//
// Two things the harness reaches inside for, and both are the clock.  A backend
// response deadline is two seconds and a header deadline ten, so an input that
// waited for either would be the whole budget; OP_DEADLINE moves the deadlines
// into the past and calls the sweep directly.  OP_AGE does the same for the
// pool's idle stamps and a circuit breaker's opened_at.  Nothing else about the
// runtime is simulated.
//
// ─── WHAT IT DOES NOT REACH ─────────────────────────────────────────────────
//
//   * the idle sweep timer firing on its own.  It is a thirty-second chain
//     armed by the pool; this target sees it armed and withdrawn, and reaches
//     what it *does* through OP_AGE and the acquire path instead.
//   * health checks completing.  The sweep is armed and withdrawn; its probes
//     need a one-second timer to fire.
//   * splice forwarding under load.  It is reachable (TCP mode, large payloads)
//     but the payloads here are small, so the pipe path is entered rarely.
//   * `on_route`, and a Lua filter chain of any shape other than the one
//     written by write_lua_script() below.
//   * a proxy in its own process (proxy_worker).  That is a supervision
//     boundary, not an ordering, and the ordering is what this is for.
//   * mutual TLS on the listener (--client-ca), a rejected certificate, and a
//     handshake that fails halfway.  One certificate is generated and both
//     ends accept it; a peer that presents the wrong one, or none, is a second
//     certificate this does not make.

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/time_types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

// The harness's own TLS, and deliberately not the runtime's.  socketley/shared/
// tls_context.h is the record layer under test on both legs; a harness built on
// it would break in exactly the same way as the thing it is testing and report
// a clean handshake.  So the peers here speak OpenSSL directly, over the socket
// rather than over memory BIOs, which is also the only way this end can be
// driven a step at a time between pumps of the proxy's loop.
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "fuzz_common.h"
#include "fuzz_runtime_ops.h"

#include "shared/endpoint_table.h"
#include "shared/event_loop.h"
#include "shared/event_loop_definitions.h"
#include "shared/logging.h"
#include "shared/runtime_instance.h"
#include "shared/tls_context.h"
#include "shared/trace.h"
#include "shared/write_queue.h"
#include "shared/http_framing.h"

// Reaching inside the class, for the same reason and by the same means as
// fuzz_server_ops and fuzz_cache_ops: the invariants are about m_backend_pool,
// m_client_pool, m_backend_struct_pool, m_conn_idx and m_client_slots, all
// private, and the deadline sweep is a private member function — and the
// alternatives are a friend declaration or a test-only accessor, both of which
// change socketley/ to suit a test.  Every header proxy_instance.h needs is
// included above, so the macro is never in effect over libstdc++ or over sol2.
// proxy_instance.cpp is compiled normally and linked in; member access affects
// neither layout nor mangling.
#define private public
#include "runtime/proxy/proxy_instance.h"
#undef private

namespace {

constexpr int    NCLIENTS  = 4;     // harness client sockets
constexpr int    NBACKENDS = 3;     // harness listeners the proxy dials
constexpr int    NBSOCK    = 8;     // accepted backend-side sockets, all backends
constexpr size_t MAX_STEPS = 384;
// Request ids are allocated per input and looked up by index, so the table is
// the ceiling on how many a program may mark.  Two per step is the most any
// operation takes.
constexpr size_t MAX_IDS   = 2 * MAX_STEPS + 8;

// ─────────────────────────── request shapes ─────────────────────────────────
//
// Chosen around the boundaries the request path actually has: the terminating
// blank line, the declared body, the pipelined request behind it, the prefix
// test, the framing refusals, and the header-size limit.  Each is stamped with
// one or two ids, which is what makes a response attributable to a client.

enum req_id : uint8_t
{
    RQ_WHOLE = 0,     // one complete keep-alive request
    RQ_HALF,          // request line and one header, no terminator: the header deadline
    RQ_PIPELINED,     // two complete requests in one write
    RQ_CONN_CLOSE,    // complete, Connection: close
    RQ_BODY,          // POST with a declared body, sent whole
    RQ_BODY_SPLIT,    // POST with a declared body, only part of it sent
    RQ_DENY,          // path the filter chain answers 403 for
    RQ_NO_PREFIX,     // not this proxy's prefix: 404
    RQ_SMUGGLE,       // Content-Length and Transfer-Encoding together: 400
    RQ_BARE_LF,       // header block framed with bare LF: 400
    RQ_HUGE_HEADER,   // past MAX_HEADER_SIZE: 431
    RQ_EXPECT_100,    // Expect: 100-continue, so an interim block is in play
    RQ_RAW,           // no HTTP at all — TCP mode, and garbage for the HTTP one
    RQ_COUNT
};

const char* req_name(int r)
{
    switch (r % RQ_COUNT)
    {
        case RQ_WHOLE:       return "whole";
        case RQ_HALF:        return "half";
        case RQ_PIPELINED:   return "two-pipelined";
        case RQ_CONN_CLOSE:  return "whole+close";
        case RQ_BODY:        return "body-whole";
        case RQ_BODY_SPLIT:  return "body-split";
        case RQ_DENY:        return "filter-denies";
        case RQ_NO_PREFIX:   return "wrong-prefix";
        case RQ_SMUGGLE:     return "cl+te";
        case RQ_BARE_LF:     return "bare-lf";
        case RQ_HUGE_HEADER: return "huge-header";
        case RQ_EXPECT_100:  return "expect-100";
        default:             return "raw-bytes";
    }
}

// ─────────────────────────── response shapes ────────────────────────────────
//
// The pooling decision is the whole reason these are what they are.  Half of
// them leave the socket at a message boundary and half do not, and which is
// which is recorded rather than inferred — that record *is* invariant B.

enum rsp_id : uint8_t
{
    RS_OK = 0,        // 200 with a Content-Length body, complete
    RS_HEAD_ONLY,     // header block promising a body that never comes
    RS_HEAD_SPLIT,    // half a header block
    RS_CHUNKED,       // chunked, terminated
    RS_CHUNKED_OPEN,  // chunked, no terminating chunk
    RS_204,           // no body by the framing rules
    RS_304,
    RS_CONN_CLOSE,    // complete, but Connection: close
    RS_NO_LENGTH,     // framed by the close, so there is no boundary short of EOF
    RS_100_THEN_OK,   // an interim block and the response behind it
    RS_1XX_ONLY,      // interim blocks and nothing else
    RS_BARE_LF,       // a header block two recipients could read differently
    RS_CL_TE,         // Content-Length and a transfer coding at once
    RS_GARBAGE,       // no status line this proxy can read
    RS_OK_PLUS_TAIL,  // a complete answer with the head of another behind it
    RS_TWO,           // two complete answers to one request
    // A whole answer to a request that was never made, marked with the last one
    // this socket did answer.  It is what a backend puts on the wire after the
    // exchange is over — a duplicated answer, a late interim block, a desynced
    // keep-alive stream — and the socket it lands on is by then in the proxy's
    // pool.  Whoever borrows it next reads somebody else's answer as its own,
    // which is the whole of invariant C in one operation.
    RS_UNSOLICITED,
    RS_COUNT
};

const char* rsp_name(int r)
{
    switch (r % RS_COUNT)
    {
        case RS_OK:           return "200+CL";
        case RS_HEAD_ONLY:    return "headers-only";
        case RS_HEAD_SPLIT:   return "half-a-header-block";
        case RS_CHUNKED:      return "chunked-done";
        case RS_CHUNKED_OPEN: return "chunked-unterminated";
        case RS_204:          return "204";
        case RS_304:          return "304";
        case RS_CONN_CLOSE:   return "200+close";
        case RS_NO_LENGTH:    return "200-no-length";
        case RS_100_THEN_OK:  return "100+200";
        case RS_1XX_ONLY:     return "1xx-only";
        case RS_BARE_LF:      return "bare-lf-headers";
        case RS_CL_TE:        return "CL+TE";
        case RS_GARBAGE:      return "no-status-line";
        case RS_OK_PLUS_TAIL: return "200+tail-of-another";
        case RS_TWO:          return "two-complete-answers";
        default:              return "an answer nobody asked for";
    }
}

// ─────────────────────────── the program ────────────────────────────────────

enum op_code : uint8_t
{
    OP_START, OP_STOP, OP_DESTROY,
    OP_PUMP,
    OP_CONNECT, OP_REQUEST, OP_RECV, OP_FIN, OP_ABORT, OP_CLOSE_CLIENT,
    OP_BE_LISTEN, OP_BE_ACCEPT, OP_BE_RECV, OP_BE_RESPOND, OP_BE_FIN, OP_BE_ABORT,
    OP_BE_SERVE,
    OP_MEMBERSHIP,
    OP_CONFIG,
    OP_DEADLINE,
    OP_AGE,
    OP_STATS,
    OP_COUNT
};

struct step
{
    uint8_t op = 0, a = 0, b = 0, c = 0;
};

step   g_prog[MAX_STEPS];
size_t g_steps = 0;

const char* listen_mode_name(int m)
{
    switch (m % 3)
    {
        case 0:  return "down — the connect is refused";
        case 1:  return "up";
        default: return "stalled — a backlog nothing is accepted from";
    }
}

const char* config_knob_name(int k)
{
    switch (k % 8)
    {
        case 0:  return "strategy";
        case 1:  return "retries";
        case 2:  return "circuit-threshold";
        case 3:  return "backend-timeout";
        case 4:  return "max-connections";
        case 5:  return "idle-timeout";
        case 6:  return "proxy hooks";
        default: return "health-check";
    }
}

const char* hook_mode_name(int m)
{
    switch (m % 4)
    {
        case 0:  return "none";
        case 1:  return "pass-through";
        case 2:  return "rewrite (same bytes, other storage)";
        default: return "drop";
    }
}

const char* backend_shape_name(int s)
{
    switch (s % 6)
    {
        case 0:  return "one plain backend";
        case 1:  return "two plain backends";
        case 2:  return "@fuzzgrp alone";
        case 3:  return "one plain backend + @fuzzgrp";
        case 4:  return "a dead port + one plain backend";
        default: return "three plain backends";
    }
}

// ─── a configuration the input cannot move ──────────────────────────────────
//
// Every seed in this corpus starts from the default proxy configuration; only
// the operation stream drifts.  That is a hole with a name on it: the defect
// 6de09db fixed — a half-closed client losing its answer — was reachable only
// with --backend-timeout 0, because the predicate that decided whether an
// answer was still owed rested on a flag arm_response_deadline() never sets
// when the deadline is switched off.  Nothing in the corpus pins that value,
// including proxy/client_fin_after_a_whole_request, which is the seed for
// exactly that loss.  It was found by editing this file to hard-code the
// timeout and replaying by hand, and a defect found that way stays fixed only
// for as long as somebody remembers to do it again.
//
// OP_CONFIG can *reach* 0 by mutation, and that is not the same thing.  A
// mutation reaching it puts the value there partway through a program, on a
// runtime that has already run under the default; the configuration a defect
// lives in is the one the runtime was built with and never left.  Worse, the
// value is one byte of the mutator's choosing in a program that has to reach a
// half-close and a whole request as well — so it is reachable in principle and
// vanishingly rare in practice, which is the worst of both.
//
// So the configuration is a dimension of the *run*, not of the input.
// FUZZ_PROXY_CONFIG pins any of the numeric knobs for the whole run: the
// instance is built with them, OP_CONFIG cannot move them afterwards, and the
// corpus replays unchanged underneath.  run_fuzz.sh sweeps the values that
// disable a guarantee — see the matrix there for which, and why those.
//
//   FUZZ_PROXY_CONFIG="backend-timeout=0"
//   FUZZ_PROXY_CONFIG="backend-timeout=0,circuit-threshold=0"
//
// The names are the CLI flags they correspond to, so a finding can be
// reproduced against a real daemon by reading them straight across.
struct pinned_config
{
    bool has_backend_timeout{false};    int backend_timeout{0};
    bool has_circuit_threshold{false};  int circuit_threshold{0};
    bool has_retries{false};            int retries{0};
    bool has_max_connections{false};    int max_connections{0};
    bool has_idle_timeout{false};       int idle_timeout{0};
    bool any{false};
    char text[192]{};
};

pinned_config g_pin;

// Refuse rather than ignore.  A misspelt knob that silently pinned nothing
// would make a matrix entry a second copy of the default run, reported green,
// and the whole point of the entry is that it is a different configuration.
void parse_pinned_config()
{
    const char* env = std::getenv("FUZZ_PROXY_CONFIG");
    if (!env || !*env)
        return;

    std::snprintf(g_pin.text, sizeof(g_pin.text), "%s", env);

    std::string spec(env);
    size_t at = 0;
    while (at < spec.size())
    {
        size_t comma = spec.find(',', at);
        if (comma == std::string::npos)
            comma = spec.size();
        std::string item = spec.substr(at, comma - at);
        at = comma + 1;
        if (item.empty())
            continue;

        const size_t eq = item.find('=');
        if (eq == std::string::npos)
        {
            std::fprintf(stderr, "fuzz_proxy_ops: FUZZ_PROXY_CONFIG item '%s' is not "
                                 "<knob>=<value>\n", item.c_str());
            std::exit(2);
        }
        const std::string key = item.substr(0, eq);
        const int val = std::atoi(item.c_str() + eq + 1);

        if (key == "backend-timeout")        { g_pin.has_backend_timeout = true;   g_pin.backend_timeout = val; }
        else if (key == "circuit-threshold") { g_pin.has_circuit_threshold = true; g_pin.circuit_threshold = val; }
        else if (key == "retries")           { g_pin.has_retries = true;           g_pin.retries = val; }
        else if (key == "max-connections")   { g_pin.has_max_connections = true;   g_pin.max_connections = val; }
        else if (key == "idle-timeout")      { g_pin.has_idle_timeout = true;      g_pin.idle_timeout = val; }
        else
        {
            std::fprintf(stderr, "fuzz_proxy_ops: FUZZ_PROXY_CONFIG knob '%s' is not one of "
                                 "backend-timeout, circuit-threshold, retries, "
                                 "max-connections, idle-timeout\n", key.c_str());
            std::exit(2);
        }
        g_pin.any = true;
    }

    if (g_pin.any)
        std::fprintf(stderr, "fuzz_proxy_ops: pinned configuration %s "
                             "(OP_CONFIG cannot move these)\n", g_pin.text);
}

void print_program()
{
    std::fprintf(stderr,
        "\n--- decoded operation sequence (%zu steps) ---\n"
        "// Each line is one step against one proxy_instance on one event_loop.\n"
        "// \"client\" is a harness socket dialling the proxy's listener;\n"
        "// \"backend\" is a harness listener the proxy dials, and \"bsock\" one\n"
        "// of the connections it accepted there.\n", g_steps);

    // Which configuration this program ran in.  Without it a reproducer from a
    // matrix entry is a program that does not reproduce, because the thing that
    // made it fail is not in the bytes.
    if (g_pin.any)
        std::fprintf(stderr,
                     "// PINNED CONFIGURATION: %s\n"
                     "//   reproduce with: FUZZ_PROXY_CONFIG=%s <target> <input>\n",
                     g_pin.text, g_pin.text);

    for (size_t i = 0; i < g_steps; i++)
    {
        const step& s = g_prog[i];
        std::fprintf(stderr, "  /* %4zu */ ", i);
        switch (s.op)
        {
            case OP_START:      std::fputs("rt.start(loop);\n", stderr); break;
            case OP_STOP:       std::fputs("rt.stop(loop);\n", stderr); break;
            case OP_DESTROY:
                std::fprintf(stderr, "drain(rt); destroy rt; create one on new ports;"
                                     "  // %s, %s%s\n",
                             backend_shape_name(s.a & 0x07),
                             (s.a & 0x08) ? "TCP" : "HTTP",
                             (s.a & 0x10) ? ", lua filter chain" : "");
                break;
            case OP_PUMP:       std::fprintf(stderr, "loop.poll_completions(%d) x%d;\n",
                                             s.b & 1, 1 + (s.a & 3)); break;
            case OP_CONNECT:    std::fprintf(stderr, "client[%d].connect();\n", s.a % NCLIENTS); break;
            case OP_REQUEST:    std::fprintf(stderr, "client[%d].send(%s);\n",
                                             s.a % NCLIENTS, req_name(s.b)); break;
            case OP_RECV:       std::fprintf(stderr, "client[%d].recv();\n", s.a % NCLIENTS); break;
            case OP_FIN:        std::fprintf(stderr, "client[%d].shutdown(SHUT_WR);\n", s.a % NCLIENTS); break;
            case OP_ABORT:      std::fprintf(stderr, "client[%d].close();   // RST\n", s.a % NCLIENTS); break;
            case OP_CLOSE_CLIENT:
                std::fprintf(stderr, "rt.lua_close_client(client[%d]);\n", s.a % NCLIENTS); break;
            case OP_BE_LISTEN:  std::fprintf(stderr, "backend[%d].listen = %s;\n",
                                             s.a % NBACKENDS, listen_mode_name(s.b)); break;
            case OP_BE_ACCEPT:  std::fprintf(stderr, "backend[%d].accept();\n", s.a % NBACKENDS); break;
            case OP_BE_RECV:    std::fprintf(stderr, "bsock[%d].recv();\n", s.a % NBSOCK); break;
            case OP_BE_RESPOND: std::fprintf(stderr, "bsock[%d].send(%s);\n",
                                             s.a % NBSOCK, rsp_name(s.b)); break;
            case OP_BE_FIN:     std::fprintf(stderr, "bsock[%d].shutdown(SHUT_WR);\n", s.a % NBSOCK); break;
            case OP_BE_ABORT:   std::fprintf(stderr, "bsock[%d].close();   // RST\n", s.a % NBSOCK); break;
            case OP_BE_SERVE:   std::fprintf(stderr, "backend[%d].accept_all(); read; answer each %s;\n",
                                             s.a % NBACKENDS, rsp_name(s.b)); break;
            case OP_MEMBERSHIP: std::fprintf(stderr, "publish endpoints; @fuzzgrp = {%s%s%s};\n",
                                             (s.a & 1) ? "be0 " : "", (s.a & 2) ? "be1 " : "",
                                             (s.a & 4) ? "be2" : ""); break;
            case OP_CONFIG:     std::fprintf(stderr, "config %s = %d;%s\n",
                                             config_knob_name(s.a), s.b,
                                             (s.a % 8) == 6 ? hook_mode_name(s.b) : ""); break;
            case OP_DEADLINE:   std::fputs("expire every deadline; rt.response_deadline_sweep();\n", stderr); break;
            case OP_AGE:        std::fputs("age the pool's idle stamps and the open breakers;\n", stderr); break;
            case OP_STATS:      std::fputs("rt.get_stats();\n", stderr); break;
            default:            std::fprintf(stderr, "/* op %u */\n", s.op); break;
        }
    }
    std::fputs("--- end of sequence ---\n", stderr);
}

// ─────────────────────────── process-wide state ─────────────────────────────
//
// One loop for the whole process rather than one per input, for the reasons
// given in fuzz_server_ops: building one costs three ring setups and a 16 MB
// provided-buffer group, and reusing it makes the end-of-input quiescence check
// load-bearing — every input has to leave the loop owing nothing, so inputs stay
// independent *because* the invariant holds rather than by hoping it does.

event_loop*        g_loop = nullptr;
fuzzrt::ring_watch g_watch;

// Connection reuse, counted at the backend's end.  g_be_accepts is one TCP
// handshake — and on an encrypted leg one TLS handshake — that the proxy paid
// for; g_be_requests is one request that arrived on a backend socket.  Both are
// the harness's own observations, made by the peer doing the work, so neither
// depends on the proxy's account of its pool.
//
// Printed per input when FUZZ_PROXY_POOL_REPORT is set, which is off in CI and
// on when somebody is measuring: a seed whose accepts stop tracking its
// requests is a seed that started reusing connections, and that is the whole of
// what pooling buys.
unsigned long g_be_accepts  = 0;
unsigned long g_be_requests = 0;

std::vector<std::unique_ptr<proxy_instance>>* g_graveyard = nullptr;

// The script the filter chain comes from, written once into /dev/shm.
std::string* g_lua_path = nullptr;

// Which hook behaviour the C++ proxy hooks take, and whether that behaviour can
// swallow a request or a response.  A configured drop is not a defect, so it
// suspends invariant A for as long as it is in force — see cb_proxy_request.
int  g_hook_mode = 0;
bool g_hook_drops = false;

struct world;
world* g_world = nullptr;


// ─────────────────────────── request ids ────────────────────────────────────
//
// One id per request, owned by exactly one client, allocated per input and
// never reused inside one.  This is the whole of invariant C's machinery: the
// mark travels to the backend inside the request, comes back inside the
// response, and is checked against the client that receives it.

uint32_t g_next_id = 1;
int8_t   g_id_owner[MAX_IDS];

void reset_ids()
{
    g_next_id = 1;
    std::memset(g_id_owner, -1, sizeof(g_id_owner));
}

uint32_t alloc_id(int client_slot)
{
    if (g_next_id >= MAX_IDS)
        return 0;                       // out of marks: this request goes unmarked
    const uint32_t id = g_next_id++;
    g_id_owner[id] = static_cast<int8_t>(client_slot);
    return id;
}

// ─────────────────────────────── the world ──────────────────────────────────

struct client_sock
{
    int      fd{-1};
    uint16_t lport{0};        // our end's port; the proxy sees it as the peer's
    int      proxy_fd{-1};    // the descriptor the proxy accepted it on
    bool     accepted{false}; // on_connect fired for this connection
    bool     self_closed{false};
    bool     fin_sent{false};
    bool     reported{false}; // invariant A has already spoken about this one

    // Invariant A's state.  reqs_sent counts *complete* requests only — half a
    // request is owed nothing — and rx_since_req is reset by each of them, so
    // "closed with nothing at all since the last thing I asked for" is one
    // comparison.
    uint32_t reqs_sent{0};
    size_t   rx_since_req{0};
    uint32_t run_epoch{0};    // which run of the runtime the request belongs to

    // Everything this connection ever received, which rx_since_req deliberately
    // forgets.  The oracle's *claim* is about the last request; its *detail
    // line* used to read "received 0 bytes" on a connection that had carried a
    // whole answer, and a report the wire contradicts is a report nobody
    // believes the next time.  This is what makes the two numbers say different
    // things instead of one of them saying something false.
    size_t   rx_total{0};

    // Set the moment the proxy says, in a response on this connection, that it
    // is ending it.  From then on the proxy owes this client nothing more: see
    // client_send(), which keeps writing but stops counting.
    bool     peer_announced_close{false};

    // A mark can straddle two reads, so the tail of the last one is kept.
    std::string carry;

    // The listener leg's TLS, when the proxy terminates it.  Null on a
    // cleartext proxy; tls_ok says the handshake finished, and until it does
    // this client can send nothing at all.
    SSL*     ssl{nullptr};
    bool     tls_ok{false};
};

struct backend_sock
{
    int      fd{-1};
    int      backend{-1};     // which harness listener accepted it
    uint16_t peer_port{0};    // the proxy's end, which is how a pooled fd is
                              // recognised — see check_backend_pool()

    // Invariant B's state.  True from the moment a response is started until
    // the moment it is finished.  On its own it says only that *this end* has
    // an unfinished message somewhere behind it; whether the proxy filed the
    // socket inside that message is answered by the two counters below, not by
    // this flag.  See check_backend_pool().
    bool     resp_pending{false};

    // Where this end's writing has got to, and where the last message boundary
    // in it falls.  Together they place every byte on this wire: everything
    // before complete_at is whole messages, everything from complete_at to
    // tx_bytes is the unfinished one.
    //
    // These are what let invariant B be stated as the geometric fact it claims
    // to be.  The proxy's own position in the stream is tx_bytes minus whatever
    // it has not consumed yet, and a filing is off a boundary exactly when that
    // position is past complete_at.  resp_pending cannot answer it: it is true
    // for a socket filed correctly at complete_at and then written to again,
    // which is the harness's own later traffic and not a pooling mistake.
    size_t   tx_bytes{0};
    size_t   complete_at{0};

    // Whether this socket was in the proxy's pool at the end of the previous
    // step.  A false→true transition is the filing decision, and the filing
    // decision is the only moment at which invariant B has anything to say
    // about the proxy: what the harness does to the socket afterwards is the
    // harness's own traffic, not a pooling mistake.
    bool     in_pool{false};
    bool     pool_seen{false};   // scratch for the walk in progress

    // Ids read out of requests on this socket and not yet answered, and the
    // last one that was — which is what an unsolicited answer is marked with,
    // so that a client receiving one can be told whose it was.
    uint32_t owed[8];
    uint8_t  owed_n{0};
    uint32_t last_id{0};

    // How far this end has read, and how far the wire had already run when this
    // end last answered something it had not read.  A request lying unread at
    // the *backend's* end when an answer goes out is a request the proxy has
    // already been given an answer for, so it is not owed one — putting it in
    // owed[] is what made this harness stamp a later answer with an id whose
    // client had let go of the socket.  See bsock_respond().
    size_t   rx_bytes{0};
    size_t   blind_horizon{0};
    uint32_t blind_pending{0};

    std::string carry;

    // The backend leg's TLS, when the proxy dials one.  This end is the server:
    // it presents the certificate the proxy verifies the endpoint's name
    // against.
    SSL*     ssl{nullptr};
    bool     tls_ok{false};
};

struct backend_listener
{
    int      fd{-1};
    uint16_t port{0};
    int      mode{0};         // 0 down, 1 up, 2 stalled
    int      filler{-1};      // the connection that fills a stalled backlog
};

struct world
{
    std::unique_ptr<proxy_instance> rt;
    uint16_t         port{0};
    uint16_t         dead_port{0};
    int              shape{0};
    bool             tcp{false};
    bool             lua{false};
    bool             tls_front{false};   // the proxy terminates TLS on its listener
    bool             tls_back{false};    // the proxy dials its backends over TLS
    uint32_t         epoch{0};      // bumped by every start, stop and destroy
    client_sock      cli[NCLIENTS];
    backend_listener be[NBACKENDS];
    backend_sock     bs[NBSOCK];
    uint8_t          group_mask{0x07};
};

uint16_t next_port()
{
    // Below the ephemeral range (32768 upwards here), so neither the proxy's
    // listener nor a harness backend can collide with a socket the kernel
    // handed out, and rotated so a port left in an odd state by one input does
    // not decide the next one.
    static uint16_t base = 0, top = 0, p = 0;
    if (base == 0)
    {
        // Where to stay, when something else on this machine has claimed
        // ports of its own.
        //
        // 20000-29999 is below the ephemeral range, which is what this was
        // chosen for -- but it is also exactly where test/integration's
        // lib_ports.sh hands out its 2000-wide windows (21000, 23000, 25000,
        // 27000, 29000), and that claim is made under an flock this harness
        // does not take.  A fuzz target squatting in a claimed window makes a
        // suite fail on a port it was promised: measured, a Sanitize run in
        // window 21000 came back 139/2 with fuzz targets live and 141/0 on a
        // quiet machine.
        //
        // So the range is overridable, and test/nightly.sh points the fuzz job
        // at 31000-32767 -- still below ephemeral, and the one stretch no
        // window reaches.  Unset, this is what it always was.
        base = 20000;
        top  = 30000;
        if (const char* env = ::getenv("SOCKETLEY_FUZZ_PORT_BASE"))
        {
            const long v = ::strtol(env, nullptr, 10);
            if (v >= 1024 && v < 32000)
            {
                base = static_cast<uint16_t>(v);
                const char* env_top = ::getenv("SOCKETLEY_FUZZ_PORT_TOP");
                const long  t       = env_top ? ::strtol(env_top, nullptr, 10) : 0;
                top = (t > v && t <= 32768) ? static_cast<uint16_t>(t)
                                            : static_cast<uint16_t>(32768);
            }
        }
        p = static_cast<uint16_t>(base + (::getpid() % (top - base)));
    }
    if (++p >= top)
        p = base;
    return p;
}

proxy_instance* live_rt()
{
    return g_world && g_world->rt && g_world->rt->get_state() == runtime_running
         ? g_world->rt.get() : nullptr;
}

// ─────────────────────────── building the traffic ───────────────────────────

// Append one complete request, marked with `id`.
void append_request(std::string& out, uint32_t id, const char* method,
                    const char* path, const char* extra, const char* body)
{
    out += method;
    out += ' ';
    out += path;
    out += " HTTP/1.1\r\nHost: fuzz\r\n";
    if (id != 0)
    {
        char m[48];
        std::snprintf(m, sizeof(m), "X-Fuzz-Req: %u\r\n", id);
        out += m;
    }
    if (extra)
        out += extra;
    out += "\r\n";
    if (body)
        out += body;
}

// Build request shape `shape` for client `slot`.  Returns how many *complete*
// requests it contains, which is what invariant A counts.
int build_request(int shape, int slot, std::string& out)
{
    out.clear();
    switch (shape % RQ_COUNT)
    {
        case RQ_WHOLE:
            append_request(out, alloc_id(slot), "GET", "/fuzz-proxy/a", nullptr, nullptr);
            return 1;

        case RQ_HALF:
            // A request line and one header and then nothing.  Held for the
            // terminating blank line, which is correct framing and is why the
            // hold has to be bounded — see PROXY_HEADER_TIMEOUT_SEC.
            out = "GET /fuzz-proxy/slow HTTP/1.1\r\nHost: fuzz\r\n";
            return 0;

        case RQ_PIPELINED:
            // Two whole requests in one write.  The second must go through the
            // framing checks rather than round the back of them (7a235aa), and
            // it must not be lost while the first is answered.
            append_request(out, alloc_id(slot), "GET", "/fuzz-proxy/p1", nullptr, nullptr);
            append_request(out, alloc_id(slot), "GET", "/fuzz-proxy/p2", nullptr, nullptr);
            return 2;

        case RQ_CONN_CLOSE:
            append_request(out, alloc_id(slot), "GET", "/fuzz-proxy/c",
                           "Connection: close\r\n", nullptr);
            return 1;

        case RQ_BODY:
            append_request(out, alloc_id(slot), "POST", "/fuzz-proxy/b",
                           "Content-Length: 8\r\n", "abcdefgh");
            return 1;

        case RQ_BODY_SPLIT:
            // The header block is complete, so the request is forwarded; the
            // body is not, so what follows on this socket is still body and not
            // the next request.
            append_request(out, alloc_id(slot), "POST", "/fuzz-proxy/bs",
                           "Content-Length: 8\r\n", "abc");
            return 1;

        case RQ_DENY:
            append_request(out, alloc_id(slot), "GET", "/fuzz-proxy/deny", nullptr, nullptr);
            return 1;

        case RQ_NO_PREFIX:
            append_request(out, alloc_id(slot), "GET", "/somewhere-else", nullptr, nullptr);
            return 1;

        case RQ_SMUGGLE:
            append_request(out, alloc_id(slot), "POST", "/fuzz-proxy/s",
                           "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n",
                           "0\r\n\r\n");
            return 1;

        case RQ_BARE_LF:
            // A header block two recipients could read differently, which is
            // what request smuggling is made of.
            out = "GET /fuzz-proxy/lf HTTP/1.1\r\nHost: fuzz\nX-Fuzz-Req: 0\r\n\r\n";
            return 1;

        case RQ_HUGE_HEADER:
        {
            out = "GET /fuzz-proxy/h HTTP/1.1\r\nHost: fuzz\r\nX-Pad: ";
            out.append(proxy_client_connection::MAX_HEADER_SIZE + 512, 'P');
            out += "\r\n\r\n";
            return 1;
        }

        case RQ_EXPECT_100:
            append_request(out, alloc_id(slot), "POST", "/fuzz-proxy/e",
                           "Expect: 100-continue\r\nContent-Length: 4\r\n", "wxyz");
            return 1;

        default:
        {
            // No HTTP at all.  In TCP mode this is the payload; in HTTP mode it
            // is a request line nothing can parse, held for a terminator that
            // never comes.
            static const char raw[] = "\x01\x02\x03\xff\x00\x0a\x0d binary payload";
            out.assign(raw, sizeof(raw) - 1);
            return 0;
        }
    }
}

// Build response shape `shape`, answering `id` (0 means "nothing was asked" —
// a backend speaking unbidden, which the proxy must forward to whoever owns the
// socket and nobody else).  Sets `complete` to whether the stream is left at a
// message boundary, which is the fact invariant B is stated over.
// `boundary_at` is where the last message boundary falls *inside this buffer* —
// the offset one past the end of the last complete message in it, or 0 if there
// is no boundary in it at all.  For every shape it is simply the whole buffer or
// nothing, because one call writes one message; RS_OK_PLUS_TAIL is the exception
// this parameter exists for, and it is exactly the shape invariant B is about.
// Without it a complete answer with the head of another behind it would record
// its boundary at the end of the *write* rather than at the end of the *message*,
// and the arithmetic in check_backend_pool() would call the defect a boundary.
void build_response(int shape, uint32_t id, std::string& out, bool& complete,
                    size_t& boundary_at)
{
    out.clear();
    complete = true;
    boundary_at = 0;

    char ack[48];
    ack[0] = '\0';
    if (id != 0)
        std::snprintf(ack, sizeof(ack), "X-Fuzz-Ack: %u\r\n", id);

    switch (shape % RS_COUNT)
    {
        case RS_OK:
            out = "HTTP/1.1 200 OK\r\n";
            out += ack;
            out += "Content-Length: 5\r\n\r\nhello";
            break;

        case RS_HEAD_ONLY:
            // The header block promises sixteen bytes that never arrive.  The
            // response has not finished, so the socket is not at a boundary.
            out = "HTTP/1.1 200 OK\r\n";
            out += ack;
            out += "Content-Length: 16\r\n\r\n";
            complete = false;
            break;

        case RS_HEAD_SPLIT:
            out = "HTTP/1.1 200 OK\r\nContent-Len";
            complete = false;
            break;

        case RS_CHUNKED:
            out = "HTTP/1.1 200 OK\r\n";
            out += ack;
            out += "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
            break;

        case RS_CHUNKED_OPEN:
            out = "HTTP/1.1 200 OK\r\n";
            out += ack;
            out += "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
            complete = false;
            break;

        case RS_204:
            out = "HTTP/1.1 204 No Content\r\n";
            out += ack;
            out += "\r\n";
            break;

        case RS_304:
            out = "HTTP/1.1 304 Not Modified\r\n";
            out += ack;
            out += "\r\n";
            break;

        case RS_CONN_CLOSE:
            out = "HTTP/1.1 200 OK\r\n";
            out += ack;
            out += "Connection: close\r\nContent-Length: 2\r\n\r\nhi";
            break;

        case RS_NO_LENGTH:
            // Framed by the close: there is no boundary short of EOF, so this
            // socket is never reusable however much of it has arrived.
            out = "HTTP/1.1 200 OK\r\n";
            out += ack;
            out += "\r\nbody-to-eof";
            complete = false;
            break;

        case RS_100_THEN_OK:
            out = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n";
            out += ack;
            out += "Content-Length: 2\r\n\r\nok";
            break;

        case RS_1XX_ONLY:
            // A stream with no message boundary in it at all.
            for (int i = 0; i < 10; i++)
                out += "HTTP/1.1 100 Continue\r\n\r\n";
            complete = false;
            break;

        case RS_BARE_LF:
            // Merged on a bare LF, "Content-Length: 6" swallows the transfer
            // coding behind it and the response looks six bytes long.
            out = "HTTP/1.1 200 OK\r\nContent-Length: 6\nTransfer-Encoding: chunked\r\n\r\n";
            out += "abcdef";
            complete = false;
            break;

        case RS_CL_TE:
            out = "HTTP/1.1 200 OK\r\n";
            out += ack;
            out += "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
            complete = false;
            break;

        case RS_GARBAGE:
            out = "not-a-status-line\r\nX-Thing: 1\r\n\r\nbody";
            complete = false;
            break;

        case RS_OK_PLUS_TAIL:
            // A complete answer with the head of another behind it, carrying
            // the same mark.  If the socket is pooled here, the next borrower
            // reads that head as the start of its own answer — which is the
            // crossed-delivery defect, and is how invariants B and C meet.
            out = "HTTP/1.1 200 OK\r\n";
            out += ack;
            out += "Content-Length: 5\r\n\r\nhello";
            // The one boundary in this buffer, and it is not at the end of it.
            boundary_at = out.size();
            out += "HTTP/1.1 200 OK\r\n";
            out += ack;
            out += "Content-Length: 9\r\n\r\nstr";
            complete = false;
            break;

        case RS_TWO:
            // Two whole answers to one request.  The stream *is* at a boundary,
            // so the socket may legitimately be pooled — but a proxy that pools
            // it without noticing the second answer hands that answer to the
            // next borrower.
            out = "HTTP/1.1 200 OK\r\n";
            out += ack;
            out += "Content-Length: 3\r\n\r\none";
            out += "HTTP/1.1 200 OK\r\n";
            out += ack;
            out += "Content-Length: 3\r\n\r\ntwo";
            break;

        default:   // RS_UNSOLICITED
            // A whole, well-formed answer, on a socket where nothing was asked.
            // The stream is at a boundary afterwards, so nothing about the
            // *framing* is wrong; what is wrong is who these bytes are for.
            out = "HTTP/1.1 200 OK\r\n";
            out += ack;
            out += "Content-Length: 6\r\n\r\nstrayx";
            break;
    }

    // A shape that finishes its message ends at a boundary, wherever it ends.
    // The shapes that do not, and that carry no boundary earlier in the buffer
    // either, leave this at 0 — there is no place in what they wrote that a
    // borrower could start reading from.
    if (complete)
        boundary_at = out.size();
}

// ─────────────────────────────── the harness's TLS ──────────────────────────
//
// One self-signed certificate for 127.0.0.1, generated once into /dev/shm and
// used for both legs at once: the proxy serves it on its own listener, and the
// harness backends serve it while the proxy verifies it against the same file
// given as --ca.  It carries an iPAddress SAN because that is what the endpoint
// is — create_ssl_client checks an address literal against the iPAddress SAN
// and refuses to send it as SNI, so a certificate with only a CN would be
// rejected and the whole backend leg would be untestable.
//
// The harness's clients verify nothing.  They are not what is under test, and a
// harness that refused the proxy's certificate would report a TLS defect it had
// caused itself.

std::string* g_cert_path = nullptr;
std::string* g_key_path  = nullptr;
SSL_CTX*     g_peer_client_ctx = nullptr;   // the harness's clients
SSL_CTX*     g_peer_server_ctx = nullptr;   // the harness's backends

void write_tls_material()
{
    char cert[160], key[160];
    std::snprintf(cert, sizeof(cert), "/dev/shm/socketley-fuzz-proxy-%d.crt",
                  static_cast<int>(::getpid()));
    std::snprintf(key, sizeof(key), "/dev/shm/socketley-fuzz-proxy-%d.key",
                  static_cast<int>(::getpid()));

    EVP_PKEY* pkey = EVP_EC_gen("P-256");
    if (!pkey)
        return;

    X509* x = X509_new();
    if (!x)
    {
        EVP_PKEY_free(pkey);
        return;
    }

    bool ok = X509_set_version(x, 2) == 1 &&                 // v3, for the SAN
              ASN1_INTEGER_set(X509_get_serialNumber(x), 1) == 1 &&
              X509_gmtime_adj(X509_getm_notBefore(x), -3600) != nullptr &&
              X509_gmtime_adj(X509_getm_notAfter(x), 365 * 24 * 3600) != nullptr &&
              X509_set_pubkey(x, pkey) == 1;

    X509_NAME* nm = X509_get_subject_name(x);
    ok = ok && X509_NAME_add_entry_by_txt(
                   nm, "CN", MBSTRING_ASC,
                   reinterpret_cast<const unsigned char*>("127.0.0.1"), -1, -1, 0) == 1 &&
         X509_set_issuer_name(x, nm) == 1;

    X509V3_CTX vctx;
    X509V3_set_ctx_nodb(&vctx);
    X509V3_set_ctx(&vctx, x, x, nullptr, nullptr, 0);
    // Its own trust anchor: the same file is the proxy's --ca, so it has to be
    // usable as one.
    for (const auto& [nid, value] : { std::pair<int, const char*>{NID_basic_constraints,
                                                                  "critical,CA:TRUE"},
                                      std::pair<int, const char*>{NID_subject_alt_name,
                                                                  "IP:127.0.0.1,DNS:localhost"} })
    {
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &vctx, nid, value);
        if (!ext) { ok = false; break; }
        ok = ok && X509_add_ext(x, ext, -1) == 1;
        X509_EXTENSION_free(ext);
    }

    ok = ok && X509_sign(x, pkey, EVP_sha256()) > 0;

    if (ok)
    {
        FILE* f = std::fopen(cert, "wb");
        ok = f && PEM_write_X509(f, x) == 1;
        if (f) std::fclose(f);
    }
    if (ok)
    {
        FILE* f = std::fopen(key, "wb");
        ok = f && PEM_write_PrivateKey(f, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1;
        if (f) std::fclose(f);
    }

    X509_free(x);
    EVP_PKEY_free(pkey);

    if (!ok)
        return;

    g_peer_client_ctx = SSL_CTX_new(TLS_client_method());
    g_peer_server_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_peer_client_ctx || !g_peer_server_ctx)
        return;
    SSL_CTX_set_verify(g_peer_client_ctx, SSL_VERIFY_NONE, nullptr);
    if (SSL_CTX_use_certificate_file(g_peer_server_ctx, cert, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(g_peer_server_ctx, key, SSL_FILETYPE_PEM) != 1)
        return;

    g_cert_path = new std::string(cert);
    g_key_path  = new std::string(key);
}

bool tls_available()
{
    return g_cert_path != nullptr && g_peer_client_ctx != nullptr &&
           g_peer_server_ctx != nullptr;
}

// One handshake, driven a step at a time with the proxy's loop pumped between
// the steps.  There is no other way round it: the proxy's half of both
// handshakes advances only when a completion is dispatched, and this thread is
// the one that dispatches them.  The bound is on rounds rather than on time,
// for the reason ring_watch gives — a machine slow enough to delay the peer
// delays this loop by the same factor — and a handshake that does not finish
// inside it is simply reported as failed, which is a state the program is
// entitled to reach.
bool tls_handshake(SSL* ssl, bool accept_side)
{
    // A stopped runtime dispatches nothing, so no number of rounds can finish a
    // handshake against one — but the attempt still has to be made and still has
    // to fail, because a client whose handshake failed must end up mute rather
    // than fall back to cleartext.  Skipping it would let such a client send a
    // plaintext request into a TLS listener, be closed for it, and be reported
    // as a request that went unanswered.
    const int rounds = live_rt() ? 48 : 6;
    for (int i = 0; i < rounds; i++)
    {
        ERR_clear_error();
        const int r = accept_side ? SSL_accept(ssl) : SSL_connect(ssl);
        if (r == 1)
            return true;
        const int e = SSL_get_error(ssl, r);
        if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
            return false;
        g_loop->poll_completions(i < 8 ? 0 : 1);
    }
    return false;
}

// ─────────────────────────── the harness sockets ────────────────────────────

void client_close(client_sock& c)
{
    if (c.ssl)
    {
        // No SSL_shutdown: the harness closes abortively on purpose (see
        // set_abortive), and a close_notify would be a graceful teardown the
        // program did not ask for.
        SSL_free(c.ssl);
        c.ssl = nullptr;
    }
    c.tls_ok = false;
    if (c.fd < 0)
        return;
    ::close(c.fd);        // SO_LINGER{1,0}: an RST, and no TIME_WAIT
    c.fd = -1;
    c.lport = 0;
    c.proxy_fd = -1;
    c.accepted = false;
    c.self_closed = false;
    c.fin_sent = false;
    c.reported = false;
    c.reqs_sent = 0;
    c.rx_since_req = 0;
    c.rx_total = 0;
    c.peer_announced_close = false;
    c.carry.clear();
}

void client_connect(world& w, int idx)
{
    client_sock& c = w.cli[idx];
    if (c.fd >= 0)
        return;

    int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return;

    // Invariant 3.  The kernel has just chosen this number; if the ring still
    // names it, an SQE is about to resolve onto this socket.
    g_watch.fresh_fd(fd, "harness client socket()");

    fuzzrt::set_abortive(fd);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(w.port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0 &&
        errno != EINPROGRESS)
    {
        ::close(fd);
        return;
    }

    // The local port is assigned by connect(), whether or not it has completed,
    // and it is how on_connect below recognises which harness client the proxy
    // has just accepted.
    struct sockaddr_in me{};
    socklen_t melen = sizeof(me);
    if (::getsockname(fd, reinterpret_cast<struct sockaddr*>(&me), &melen) == 0)
        c.lport = ntohs(me.sin_port);

    c.fd = fd;
    c.self_closed = false;
    c.fin_sent = false;
    c.reported = false;
    c.reqs_sent = 0;
    c.rx_since_req = 0;
    c.rx_total = 0;
    c.peer_announced_close = false;
    c.accepted = false;
    c.proxy_fd = -1;
    c.carry.clear();
    c.run_epoch = w.epoch;

    // The listener leg.  The handshake runs here rather than being spread over
    // later steps: a client that has not finished one cannot send a request, so
    // leaving it half-done would put every TLS program out of reach of the
    // invariants that matter.  Failing it is still reachable — the program can
    // stop the runtime, or point the client at a listener that is not
    // encrypted — and a failure leaves the socket open and mute, which is
    // exactly what such a client looks like.
    if (w.tls_front && tls_available())
    {
        c.ssl = SSL_new(g_peer_client_ctx);
        if (c.ssl)
        {
            SSL_set_fd(c.ssl, c.fd);
            c.tls_ok = tls_handshake(c.ssl, false);
        }
    }
}

// ─── invariant A, stated where it is observable ─────────────────────────────
//
// The far end has closed this connection.  If a whole request went out on it
// and not one byte ever came back, the client has been told nothing at all: no
// status, no framing error, nothing to separate a proxy that has gone away from
// a backend that has.  It cannot even tell whether re-sending is safe.
//
// Everything this excludes is excluded because it is a different claim, not to
// make the check quieter:
//
//   * a connection the proxy never accepted (over --max-connections, or reset
//     before its turn came) was never a request at all;
//   * a client that closed or aborted its own socket is the far end;
//   * a runtime that has been stopped or destroyed since the request was sent
//     took its connections with it, which is what stopping means;
//   * TCP mode has no request and no response to be owed;
//   * a proxy hook configured to drop is a policy that swallows requests, and a
//     policy doing what it says is not a defect.
//
// One thing it does *not* exclude, and the distinction is the whole of it: a
// connection that received an answer earlier and nothing since.  reqs_sent and
// rx_since_req are per-request by design — a keep-alive client's second request
// has to be judged on its own bytes — so "answered, then asked again, then
// closed in silence" is a real loss and is reported.  What is not a loss is a
// request written into a connection the proxy has already said it is ending: a
// response carrying Connection: close is the proxy undertaking to answer
// nothing further, and RFC 9112 Section 9.6 says the client must not send
// another request on it.  client_send() keeps writing those bytes, because the
// proxy has to survive receiving them, and stops counting them — see the note
// there.  Without that, the deadline sweep's own 408 or 504 (87 bytes, read in
// full by the client) was erased by the client's next request and this oracle
// reported "received 0 bytes" against a wire that had plainly carried an
// answer.  Three agents read that report as a defect.
//
// A client that had half-closed first is reported under an id of its own.  It
// is the same loss — the request is already at the backend and the answer is
// discarded — but it is a claim somebody can argue with: shutdown(SHUT_WR) is
// "I have nothing more to send", and a proxy is entitled to read it as "abort"
// if it says so.  This one does not say so; it says the opposite, in a comment
// on the code that was meant to hold the connection.  Separating the two ids
// keeps that argument out of the way of the cases nobody argues about.
void client_report_close(world& w, client_sock& c)
{
    if (c.reported)
        return;
    c.reported = true;

    if (c.self_closed || !c.accepted || w.tcp || g_hook_drops)
        return;
    if (c.reqs_sent == 0 || c.rx_since_req != 0)
        return;
    if (c.run_epoch != w.epoch || !live_rt())
        return;


    // Both numbers, always.  The claim is about the bytes since the last
    // request; the total is what makes it checkable against the wire, and a
    // total of 0 is the shape where the proxy wrote nothing to this client at
    // all — which is the one that is still undiagnosed.
    fuzzrt::set_detail("client fd %d (proxy fd %d) sent %u complete request(s)%s and "
                       "received %zu bytes before the proxy closed it "
                       "(%zu bytes in total on this connection)",
                       c.fd, c.proxy_fd, c.reqs_sent,
                       c.fin_sent ? " and then half-closed" : "", c.rx_since_req,
                       c.rx_total);
    if (c.fin_sent)
    {
        RT_FINDING("answer-lost-to-a-half-close", false,
                   "a client that had sent a whole request and then half-closed its write "
                   "side was torn down without an answer — the request is already at the "
                   "backend, so whatever it did there happened and the client will never "
                   "learn the outcome");
    }
    else if (c.rx_total == 0)
    {
        RT_FINDING("client-closed-without-answer", false,
                   "a client that had sent a whole request was closed without one byte of "
                   "an answer — no status, no framing error, nothing to distinguish a proxy "
                   "that has gone away from a backend that has, and nothing in any log on "
                   "the client's side");
    }
    else
    {
        // ── the same loss, already decided, reported and not aborted ─────────
        //
        // Bytes did reach this client and then it was closed with nothing since
        // its last request.  ea10b66 traced that shape and shipped the answer:
        // the backend sent something this proxy cannot frame, those bytes were
        // forwarded, and from there the proxy owes neither of the two things it
        // could owe.  Not a Connection: close — http_response_scan_chunk never
        // reaches headers_parsed on them, so there is no parsed response to hang
        // the field on, and backend bytes are forwarded verbatim because that is
        // what makes responses stream, so there is no rewriter to hang it with.
        // Not an answer either — a status line written behind those bytes lands
        // at an offset the proxy has itself established is not a message
        // boundary, the client-side twin of the fault efdbabd fixed in the pool
        // direction, and response_started bars it.  The breaker charge ea10b66
        // added is what is paid instead.
        //
        // The loss is real and this does not pretend otherwise: it is printed,
        // with the same words and the same two byte counts.  What it is not is a
        // violation, because a decision reported as a defect every night is an
        // oracle people stop reading — and this id is too coarse to demote,
        // since FUZZ_PROXY_SKIP would take the arm above with it.  That arm is
        // the sharper of the two: a total of 0 means answer_gateway_failure
        // declined, which is a live defect and still aborts.
        //
        // Split here rather than at the id, because the discriminator is a fact
        // about the wire the report already carries.  FUZZ_STRICT=1 makes every
        // observation abort, which is the way back to the old behaviour for
        // anyone digging.
        // Big enough for the whole of g_detail plus the sentence below it, so
        // the observation is never a truncated version of the finding's words.
        char msg[sizeof(fuzzrt::g_detail) + 256];
        std::snprintf(msg, sizeof(msg),
                      "%s — the backend sent bytes this proxy cannot frame and they were "
                      "forwarded, so it can neither announce the close nor answer behind "
                      "them (ea10b66); the client on that request is lost and the breaker "
                      "is charged for it",
                      fuzzrt::g_detail);
        fuzz_observe(msg, ::fuzz::current_data(), ::fuzz::current_size());
    }
    fuzzrt::g_detail[0] = 0;
}

// Case-insensitive substring search, for the one header this harness has to
// recognise in what a *proxy* wrote rather than in what it built itself.  The
// spelling on the wire is this proxy's own — send_error() and the response
// rewriter both emit "Connection: close" — but a check on an announcement that
// ends a connection should not be one capital letter away from missing it.
size_t find_ci(std::string_view hay, std::string_view needle, size_t from)
{
    if (needle.empty() || hay.size() < needle.size())
        return std::string_view::npos;
    for (size_t i = from; i + needle.size() <= hay.size(); i++)
    {
        size_t j = 0;
        for (; j < needle.size(); j++)
        {
            const char a = static_cast<char>(std::tolower(static_cast<unsigned char>(hay[i + j])));
            const char b = static_cast<char>(std::tolower(static_cast<unsigned char>(needle[j])));
            if (a != b)
                break;
        }
        if (j == needle.size())
            return i;
    }
    return std::string_view::npos;
}

// ─── invariant C, stated where it is observable ─────────────────────────────
//
// Every mark in what a client receives has to be one of its own.  The bytes are
// well formed either way; that is what makes this the failure that has to be
// checked rather than noticed.
//
// The same pass reads one thing out of the response for invariant A: whether
// the proxy has announced that it is ending this connection.  It is read here
// because here is where the client's received bytes already are, and because
// the two facts are read out of the same carry — a header split across two
// reads has to be found either way.
void client_scan_marks(world& w, int slot, std::string_view chunk)
{
    client_sock& c = w.cli[slot];
    // A mark can straddle two reads, so the scan runs over the tail of the last
    // one and this chunk together.
    std::string buf;
    buf.reserve(c.carry.size() + chunk.size());
    buf.append(c.carry);
    buf.append(chunk);

    static const std::string_view MARK = "X-Fuzz-Ack: ";
    size_t pos = 0;
    for (;;)
    {
        const size_t at = buf.find(MARK, pos);
        if (at == std::string::npos)
            break;
        size_t p = at + MARK.size();
        uint32_t id = 0;
        bool digits = false;
        while (p < buf.size() && buf[p] >= '0' && buf[p] <= '9')
        {
            digits = true;
            id = id * 10 + static_cast<uint32_t>(buf[p] - '0');
            if (id >= MAX_IDS) { id = 0; break; }
            p++;
        }
        if (p >= buf.size())
            break;                      // the number may not be finished yet
        pos = p;
        if (!digits || id == 0 || id >= MAX_IDS)
            continue;

        const int owner = g_id_owner[id];
        if (owner >= 0 && owner != slot)
        {
            fuzzrt::set_detail("client[%d] received an answer marked %u, which client[%d] "
                               "asked for", slot, id, owner);
            RT_FINDING("crosstalk", false,
                       "a response reached a client that did not ask for it — the bytes are "
                       "well formed and correctly framed and they belong to somebody else, "
                       "which is why nothing but a mark can see it");
            fuzzrt::g_detail[0] = 0;
        }
    }

    static const std::string_view CLOSING = "Connection: close";
    if (!c.peer_announced_close && find_ci(buf, CLOSING, 0) != std::string_view::npos)
        c.peer_announced_close = true;

    // Keep enough of the tail that a mark or a close announcement split across
    // two reads is still found — the longer of the two decides the length.
    const size_t keep = (MARK.size() > CLOSING.size() ? MARK.size() : CLOSING.size()) + 12;
    if (buf.size() > keep)
        c.carry.assign(buf, buf.size() - keep, keep);
    else
        c.carry = std::move(buf);
}

void client_recv(world& w, int idx)
{
    client_sock& c = w.cli[idx];
    if (c.fd < 0)
        return;
    static char sink[16384];
    for (int i = 0; i < 4; i++)
    {
        ssize_t n;
        if (c.ssl)
        {
            if (!c.tls_ok)
                return;
            ERR_clear_error();
            const int r = SSL_read(c.ssl, sink, static_cast<int>(sizeof(sink)));
            if (r > 0)
            {
                n = r;
            }
            else
            {
                const int e = SSL_get_error(c.ssl, r);
                if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
                    break;
                // ZERO_RETURN is a close_notify and SYSCALL an abrupt end;
                // both are the far end ending this connection, which is what
                // invariant A is asked about.
                client_report_close(w, c);
                break;
            }
        }
        else
        {
            n = ::recv(c.fd, sink, sizeof(sink), MSG_DONTWAIT);
            if (n == 0)
            {
                client_report_close(w, c);
                break;
            }
            if (n < 0)
            {
                if (errno == ECONNRESET || errno == EPIPE)
                    client_report_close(w, c);
                break;   // EAGAIN otherwise
            }
        }
        c.rx_since_req += static_cast<size_t>(n);
        c.rx_total     += static_cast<size_t>(n);
        client_scan_marks(w, idx, std::string_view(sink, static_cast<size_t>(n)));
    }
}

void client_send(world& w, int idx, int shape)
{
    client_sock& c = w.cli[idx];
    if (c.fd < 0)
        return;

    // A client that has shut down its own write side cannot send, and the
    // failure says nothing about the far end.  send() on a socket with
    // SEND_SHUTDOWN returns EPIPE from the local kernel before the peer is ever
    // consulted — so the branch below, which reads EPIPE as "the proxy closed
    // this connection", was reporting a close that had not happened.  It agreed
    // with the truth only for as long as the proxy really did tear a
    // half-closed client down; against a proxy that correctly holds the
    // connection for its answer it fires on every program of the shape
    // "request, FIN, request".
    //
    // Nothing is lost by not sending: a real client does not write after its
    // own FIN, and the peer-close this oracle is about is still observed
    // directly, by client_recv, which run_step calls for every client after
    // every step and which reports on a recv of 0 or a reset.  That is the far
    // end saying so, rather than this side inferring it from its own state.
    if (c.fin_sent)
        return;

    static std::string buf;
    const int whole = build_request(shape, idx, buf);

    // A short write on a non-blocking socket is ordinary and the remainder is
    // deliberately dropped: what the proxy has to survive is a request that
    // stops halfway, and that is what a short write produces.  A request only
    // counts as complete when all of it went out.
    ssize_t n;
    if (c.ssl)
    {
        if (!c.tls_ok)
            return;
        ERR_clear_error();
        // SSL_write is all-or-nothing by default, so the record layer's short
        // write is "nothing went out" rather than "half did".  Half a request
        // over TLS is still reachable — the shapes that are half a request are
        // half a request before they are encrypted.
        const int r = SSL_write(c.ssl, buf.data(), static_cast<int>(buf.size()));
        if (r > 0)
        {
            n = r;
        }
        else
        {
            const int e = SSL_get_error(c.ssl, r);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
            {
                client_report_close(w, c);
                c.self_closed = true;
                client_close(c);
            }
            return;
        }
    }
    else
    {
        n = ::send(c.fd, buf.data(), buf.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n < 0)
        {
            if (errno == EPIPE || errno == ECONNRESET)
            {
                client_report_close(w, c);
                c.self_closed = true;
                client_close(c);
            }
            return;
        }
    }
    // A request written into a connection the proxy has said it is ending is
    // still written — the proxy has to survive receiving it, and refusing to
    // send would take that coverage away — but it is not a request the proxy
    // has undertaken to answer, so it does not move invariant A's ledger.
    //
    // This is the whole of the artefact that was read as a defect three times.
    // The deadline sweep answers 408 or 504 with Connection: close, the client
    // reads all 87 bytes of it, and the program's next OP_REQUEST used to reset
    // rx_since_req to 0 — which is right for a keep-alive client, whose second
    // request must be judged on its own bytes, and wrong here, because it
    // erased the only record that the first one had been answered.  The report
    // then read "sent 3 complete requests and received 0 bytes" against a wire
    // that had carried a whole answer.  Freezing the ledger at the
    // announcement, rather than excusing the finding afterwards, keeps the
    // oracle's words literally true wherever it does fire.
    // The same freeze, for a close the proxy is making rather than announcing.
    //
    // peer_announced_close above covers the endings the proxy puts into words:
    // 408, 504, or a response carrying Connection: close.  It cannot cover the
    // ending where there is nothing to say.  When a backend resets mid-
    // connection the proxy marks the client closing and tears the pair down
    // without writing another byte — correctly, because the request it was
    // carrying has already been answered in full and there is no second answer
    // owed — and a request the program writes into that connection afterwards
    // was reset rx_since_req to 0 and erased the record of the answer that did
    // arrive.  The report then read "sent 2 complete request(s) and received 0
    // bytes" against a wire that had carried 71 of them.
    //
    // Measured on the artefact this shape came in on: at that second write the
    // proxy's own connection had closing=1 and rx_since_req was 71, so the
    // answer was delivered and recorded before the ledger threw it away.
    //
    // Asked of the proxy's connection rather than of anything on the wire,
    // because that is where the fact lives.  A descriptor the proxy has let go
    // of entirely counts the same as one it has marked: both mean this end is
    // no longer owed an answer, which is also what RFC 9112 Section 9.6 says of
    // a client that keeps sending on a connection the server is ending.
    //
    // What this deliberately does NOT excuse is the shape the id exists for: a
    // proxy that accepts a request on a live connection and then closes it
    // having written nothing.  There closing is false at this instant, the
    // ledger moves normally, and the finding still fires.
    bool proxy_ending = false;
    if (w.rt && c.proxy_fd >= 0 && c.proxy_fd < proxy_instance::MAX_FDS)
    {
        const auto* cc = w.rt->m_client_slots[c.proxy_fd].get();
        // client_conn_close as well as closing, because `closing` is the
        // teardown and the undertaking comes before it.
        //
        // A request carrying "Connection: close" is the CLIENT ending the
        // connection.  The proxy records that while parsing the request and
        // closes after answering it, which is what RFC 9112 Section 9.6
        // requires -- and the same section forbids the client from sending
        // another request on it.  But `closing` only becomes true at the
        // teardown, so between the two there is a window where the proxy has
        // undertaken to close, has not yet done it, and a request written into
        // that window was counted as one deserving an answer.
        //
        // Measured on the 125-byte artefact the nightly of 2026-08-14 aborted
        // on, at the second send:
        //
        //     closing=0  conn_close=1  announced=0  ->  counted=1
        //
        // The proxy then closed the pair with 57 bytes of that request still in
        // its buffer, which is correct, and the oracle called it
        // answer-lost-to-a-half-close.  Nothing was lost that had been promised.
        //
        // peer_announced_close does not cover it: that reads the proxy's own
        // words, and here there are none to read.  The proxy forwards the
        // backend's response verbatim -- which is what makes responses stream --
        // so it has no rewriter with which to add the "close" connection option
        // Section 9.6 says a server SHOULD send back.  The undertaking is real
        // and only the connection state records it.
        proxy_ending = (cc == nullptr) || cc->closing || cc->client_conn_close;
    }

    if (static_cast<size_t>(n) == buf.size() && whole > 0 &&
        !c.peer_announced_close && !proxy_ending)
    {
        c.reqs_sent += static_cast<uint32_t>(whole);
        c.rx_since_req = 0;
        c.run_epoch = w.epoch;
    }
}

// ─────────────────────────── the harness backends ───────────────────────────

void bsock_close(backend_sock& b)
{
    if (b.ssl)
    {
        SSL_free(b.ssl);
        b.ssl = nullptr;
    }
    b.tls_ok = false;
    if (b.fd < 0)
        return;
    ::close(b.fd);
    b.fd = -1;
    b.backend = -1;
    b.peer_port = 0;
    b.resp_pending = false;
    b.tx_bytes = 0;
    b.complete_at = 0;
    b.in_pool = false;
    b.pool_seen = false;
    b.owed_n = 0;
    b.last_id = 0;
    b.rx_bytes = 0;
    b.blind_horizon = 0;
    b.blind_pending = 0;
    b.carry.clear();
}

void backend_listen(world& w, int idx, int mode)
{
    backend_listener& L = w.be[idx];
    mode %= 3;

    if (L.filler >= 0) { ::close(L.filler); L.filler = -1; }
    if (L.fd >= 0)     { ::close(L.fd);     L.fd = -1; }
    L.mode = mode;
    if (mode == 0)
        return;                          // nothing listens: the connect is refused

    int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return;
    g_watch.fresh_fd(fd, "harness backend listener socket()");

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(L.port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    // Backlog 0 for the stalled mode.  The kernel completes one handshake into
    // the queue and drops the SYNs behind it, which is the shape of a backend
    // that neither refuses nor answers — the one a TCP health probe is happy
    // with and nothing else notices.  Whether a given kernel drops or accepts
    // is not load-bearing: either way nothing here ever accepts from it, so no
    // answer is ever produced, which is the behaviour being tested.
    if (::bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0 ||
        ::listen(fd, mode == 2 ? 0 : 16) < 0)
    {
        ::close(fd);
        return;
    }
    L.fd = fd;

    if (mode == 2)
    {
        // Fill the one slot the backlog has, so the next handshake has nowhere
        // to go.  Held for as long as this backend is stalled.
        int f = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (f >= 0)
        {
            g_watch.fresh_fd(f, "harness backlog filler socket()");
            fuzzrt::set_abortive(f);
            if (::connect(f, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0 &&
                errno != EINPROGRESS)
            {
                ::close(f);
            }
            else
            {
                L.filler = f;
            }
        }
    }
}

int backend_accept(world& w, int idx)
{
    backend_listener& L = w.be[idx];
    if (L.fd < 0 || L.mode != 1)
        return -1;

    int slot = -1;
    for (int i = 0; i < NBSOCK; i++)
        if (w.bs[i].fd < 0) { slot = i; break; }
    if (slot < 0)
        return -1;

    struct sockaddr_in peer{};
    socklen_t plen = sizeof(peer);
    int fd = ::accept4(L.fd, reinterpret_cast<struct sockaddr*>(&peer), &plen, SOCK_NONBLOCK);
    if (fd < 0)
        return -1;

    // Invariant 3, at the other moment the kernel hands this process a number.
    g_watch.fresh_fd(fd, "harness backend accept4()");

    // What connection reuse is worth, counted where it cannot be argued with:
    // one accept here is one TCP handshake the proxy paid for, and on an
    // encrypted leg one TLS handshake on top of it.  Against the requests
    // counted in bsock_note_request() this is handshakes-per-request, measured
    // from outside the proxy by the peer that had to do them.  See the report
    // at the end of LLVMFuzzerTestOneInput.
    g_be_accepts++;

    fuzzrt::set_abortive(fd);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    backend_sock& b = w.bs[slot];
    b.fd = fd;
    b.backend = idx;
    b.peer_port = ntohs(peer.sin_port);
    b.resp_pending = false;
    b.tx_bytes = 0;
    b.complete_at = 0;
    b.in_pool = false;
    b.pool_seen = false;
    b.owed_n = 0;
    b.last_id = 0;
    b.rx_bytes = 0;
    b.blind_horizon = 0;
    b.blind_pending = 0;
    b.carry.clear();

    // The backend leg.  This end is the server: it presents the certificate the
    // proxy pins the endpoint's name to and verifies against the trust store it
    // was given.  A handshake that does not complete leaves the socket open and
    // mute, which is a backend the proxy has to give up on by deadline rather
    // than by refusal — one of the cases this target exists for.
    if (w.tls_back && tls_available())
    {
        b.ssl = SSL_new(g_peer_server_ctx);
        if (b.ssl)
        {
            SSL_set_fd(b.ssl, b.fd);
            b.tls_ok = tls_handshake(b.ssl, true);
        }
    }
    return slot;
}

// How many bytes are waiting at *this* end of the backend socket, unread.
//
// This is the mirror image of the liveness probe in acquire_pooled_backend, and
// the two together are the whole of the crosstalk diagnosis: bytes waiting at
// the proxy's end when a socket is borrowed are an answer nobody asked for, and
// bytes waiting at the backend's end when an answer goes out are a request
// nobody read.  The first is the defect ed07f12 fixed.  The second is this
// harness getting ahead of its own ledger, and it is what the two functions
// below now account for instead of blaming the proxy for.
size_t bsock_unread(const backend_sock& b)
{
    if (b.fd < 0)
        return 0;
    size_t n = 0;
    if (b.ssl)
    {
        const int p = SSL_pending(b.ssl);
        if (p > 0)
            n += static_cast<size_t>(p);
    }
    int q = 0;
    if (::ioctl(b.fd, FIONREAD, &q) == 0 && q > 0)
        n += static_cast<size_t>(q);
    return n;
}

// ─── invariant B, at the moment a socket changes hands ──────────────────────
//
// A request arriving on a socket whose previous response never finished is the
// next borrower reading somebody else's tail.  Nothing else puts a second
// request on a backend socket: this proxy holds a pipelined request back until
// the first exchange is over.
//
// `abs_off` is where this request's mark sits in the stream this end has read,
// counted from the first byte of the connection.  It exists for the second
// thing this function decides: whether the request is one this end still owes
// an answer for, or one it has already answered without having read it.  See
// blind_horizon in bsock_respond() — a request that was already on the wire
// when an answer went out has been answered, and adding it to owed[] is what
// made a later answer carry an id whose client had let go of the socket two
// steps earlier.  That answer is on the wire, correctly framed, and it reaches
// whichever client the proxy has on the other end of this socket now; the
// finding it produced named the proxy for a mark this harness had stamped.
void bsock_note_request(backend_sock& b, uint32_t id, size_t abs_off)
{
    // Not stated for a TCP proxy, which client_report_close already excludes for
    // the same reason.  This claim is about HTTP message boundaries -- "the
    // previous response on it was still unfinished" -- and a TCP proxy frames
    // nothing: it is a byte pipe between one client connection and one backend
    // connection for the life of both, so no socket is ever "handed to another
    // request" and there is no boundary for a hand-over to be off.  The harness
    // goes on writing its HTTP-shaped marks through the pipe because that is how
    // it recognises its own traffic, and a shape like 200-no-length leaves
    // resp_pending set for ever by construction -- it is framed by the close --
    // so every later request on that pipe was reported against a response that
    // was never going to end.
    if (g_world && g_world->tcp)
        return;

    // Already answered, before this end had read it.  Both terms are needed:
    // the offset says the request was on the wire when the blind answer went
    // out, and the counter bounds how many requests one blind answer may
    // account for, so a blind answer written over bytes that carried no mark at
    // all cannot swallow the next real one.
    //
    // ASKED BEFORE resp_pending, and that ordering is the whole of the fourth
    // shape 1eb7d53 recorded and left alone.  A request from behind this mark
    // was on the wire before this end wrote anything at all, so it cannot have
    // been "handed to a socket carrying the tail of a previous response": there
    // was no previous response when the proxy sent it, and the tail the report
    // named is bytes this end volunteered onto the socket afterwards, without
    // having read the request that was already sitting there.
    //
    // Measured on repro-req-on-unfinished: one request on the wire, 81 bytes,
    // its mark at offset 40; the harness answered blind with 39 bytes of a
    // headers-only response before reading any of it, setting blind_horizon to
    // 81; and then read the request and charged the proxy for the answer it had
    // just invented.  tx=39 with complete_at=0 -- this end had never finished a
    // message on that socket, so there was no boundary for the proxy to be off.
    //
    // The defect the id exists for is untouched, because it is not blind: a
    // socket really handed over mid-response was answering a request this end
    // had read, so blind_pending is 0 there and the report below still fires.
    if (b.blind_pending > 0 && abs_off < b.blind_horizon)
    {
        b.blind_pending--;
        // last_id is deliberately not moved here.  It is what an answer
        // volunteered onto a quiet socket is marked with, and it has to mean
        // "the request this end answered knowingly" — this one was answered
        // before it was read, so this end never saw which client it belonged
        // to, and stamping a later answer with it would be a mark invented for
        // the second time in the same exchange.
        return;
    }

    if (b.resp_pending)
    {
        fuzzrt::set_detail("a request marked %u arrived on the backend socket at port %u "
                           "while the previous response on it was still unfinished",
                           id, static_cast<unsigned>(b.peer_port));
        RT_FINDING("request-on-unfinished-socket", false,
                   "a backend socket carrying the unfinished tail of one response was "
                   "handed to another request — whatever is still on the wire becomes the "
                   "head of the next borrower's answer");
        fuzzrt::g_detail[0] = 0;
        b.resp_pending = false;   // reported once; do not repeat it every request
    }

    g_be_requests++;

    if (b.owed_n < 8)
        b.owed[b.owed_n++] = id;
}

void bsock_recv(world& w, int idx)
{
    backend_sock& b = w.bs[idx];
    if (b.fd < 0)
        return;
    static char sink[16384];
    for (int i = 0; i < 4; i++)
    {
        ssize_t n;
        if (b.ssl)
        {
            if (!b.tls_ok)
                return;
            ERR_clear_error();
            const int r = SSL_read(b.ssl, sink, static_cast<int>(sizeof(sink)));
            if (r > 0)
            {
                n = r;
            }
            else
            {
                const int e = SSL_get_error(b.ssl, r);
                if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
                    break;
                bsock_close(b);
                return;
            }
        }
        else
        {
            n = ::recv(b.fd, sink, sizeof(sink), MSG_DONTWAIT);
        }
        if (n > 0)
        {
            // Where this chunk starts in the stream, so that a mark found in it
            // can be placed against blind_horizon.  The carry in front of it is
            // bytes already counted, so the buffer as a whole starts that many
            // bytes earlier.
            const size_t carry_len = b.carry.size();
            const size_t buf_off   = b.rx_bytes - carry_len;
            b.rx_bytes += static_cast<size_t>(n);

            std::string buf;
            buf.reserve(b.carry.size() + static_cast<size_t>(n));
            buf.append(b.carry);
            buf.append(sink, static_cast<size_t>(n));

            static const std::string_view MARK = "X-Fuzz-Req: ";
            size_t pos = 0;
            for (;;)
            {
                const size_t at = buf.find(MARK, pos);
                if (at == std::string::npos)
                    break;
                size_t p = at + MARK.size();
                uint32_t id = 0;
                bool digits = false;
                while (p < buf.size() && buf[p] >= '0' && buf[p] <= '9')
                {
                    digits = true;
                    id = id * 10 + static_cast<uint32_t>(buf[p] - '0');
                    if (id >= MAX_IDS) { id = 0; break; }
                    p++;
                }
                if (p >= buf.size())
                    break;
                pos = p;
                if (digits)
                    bsock_note_request(b, id, buf_off + at);
            }

            const size_t keep = MARK.size() + 12;
            if (buf.size() > keep)
                b.carry.assign(buf, buf.size() - keep, keep);
            else
                b.carry = std::move(buf);
            continue;
        }
        if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK))
        {
            bsock_close(b);
            return;
        }
        break;
    }
    (void)w;
}

void bsock_respond(world& w, int idx, int shape)
{
    backend_sock& b = w.bs[idx];
    if (b.fd < 0)
        return;

    // What is on the wire at this end but has not been read.  Nothing below
    // changes what goes out — the program decides that — but it decides what
    // this end may honestly claim about what it is answering.
    const size_t unread = bsock_unread(b);

    // Whether this end has anything it knows it owes an answer for.  Read
    // before the queue is popped below, because "the queue is empty now" and
    // "the queue was empty when this answer was decided" are different facts
    // and only the second one makes an answer blind.
    const bool nothing_owed = (b.owed_n == 0);

    uint32_t id = 0;
    if (b.owed_n > 0)
    {
        id = b.owed[0];
        for (uint8_t i = 1; i < b.owed_n; i++)
            b.owed[i - 1] = b.owed[i];
        b.owed_n--;
        b.last_id = id;
    }
    else if ((shape % RS_COUNT) == RS_UNSOLICITED)
    {
        // Nothing was asked on this socket *as far as this end knows*, and the
        // two ways that can be true are not the same thing.
        //
        // With nothing unread, the socket really is quiet: this is an answer
        // volunteered onto a socket nobody is using, and marking it with
        // whoever asked last is what lets a client that receives it be told
        // whose answer it got.  That is the defect ed07f12 fixed, and it is
        // still marked, so it is still caught.
        //
        // With a request lying unread, it is not quiet at all: the proxy has an
        // exchange outstanding here and will pair this answer with it, because
        // positional pairing is all HTTP/1.1 gives it.  An older id on such an
        // answer is a mismatch this harness invented and then reported the
        // proxy for.  It goes out unmarked.
        if (unread == 0)
            id = b.last_id;
    }

    static std::string buf;
    bool complete = true;
    size_t boundary_at = 0;
    build_response(shape, id, buf, complete, boundary_at);

    ssize_t n;
    if (b.ssl)
    {
        if (!b.tls_ok)
            return;
        ERR_clear_error();
        const int r = SSL_write(b.ssl, buf.data(), static_cast<int>(buf.size()));
        if (r > 0)
        {
            n = r;
        }
        else
        {
            const int e = SSL_get_error(b.ssl, r);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
                bsock_close(b);
            return;
        }
    }
    else
    {
        n = ::send(b.fd, buf.data(), buf.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n < 0)
        {
            if (errno == EPIPE || errno == ECONNRESET)
                bsock_close(b);
            return;
        }
    }
    // A short write leaves the answer unfinished as surely as a shape that was
    // never going to finish it.
    b.resp_pending = !complete || static_cast<size_t>(n) != buf.size();

    // Where the wire now runs to, and where the last boundary on it is.  A
    // boundary only counts if the write actually reached it: a short write that
    // stopped before the end of the message left no place on this wire that a
    // borrower could start reading from, however complete the shape was going
    // to be.
    if (boundary_at > 0 && static_cast<size_t>(n) >= boundary_at)
        b.complete_at = b.tx_bytes + boundary_at;
    b.tx_bytes += static_cast<size_t>(n);

    // Recorded here rather than above, because an answer that never left this
    // end answered nothing: a return through either failure branch above must
    // not leave a horizon behind that swallows the next request read.
    //
    // Answering something this end has not read puts the ledger behind the
    // wire.  From here on every request already on the wire has had its answer,
    // whatever order this end gets round to reading them in, and recording how
    // far the wire had run is what lets bsock_note_request() tell those apart
    // from the requests that arrived afterwards and really are owed one.
    if (nothing_owed && unread > 0)
    {
        const size_t horizon = b.rx_bytes + unread;
        if (horizon > b.blind_horizon)
        {
            b.blind_horizon = horizon;
            b.blind_pending++;
        }
    }
    (void)w;
}

// The ordinary exchange in one step: take everything waiting on this listener,
// read what is on each socket, and answer whatever was asked.  Without it a
// blind mutator would have to guess a four-step sequence before one request was
// ever answered, and almost none of this target would be reachable.
void backend_serve(world& w, int idx, int shape)
{
    for (int i = 0; i < NBSOCK; i++)
        if (backend_accept(w, idx) < 0)
            break;
    for (int i = 0; i < NBSOCK; i++)
    {
        if (w.bs[i].fd < 0 || w.bs[i].backend != idx)
            continue;
        bsock_recv(w, i);
        if (w.bs[i].fd >= 0 && w.bs[i].owed_n > 0)
            bsock_respond(w, i, shape);
    }
}

// ─────────────────────────── instance construction ──────────────────────────

void cb_on_connect(int fd)
{
    // Which harness client this is.  The proxy's peer port is the client's own
    // local port, which is the only thing the two ends share — and having it
    // makes invariant A precise: a connection the proxy never accepted was
    // never owed an answer, and this is what says which those were.
    if (!g_world)
        return;
    struct sockaddr_in peer{};
    socklen_t plen = sizeof(peer);
    if (::getpeername(fd, reinterpret_cast<struct sockaddr*>(&peer), &plen) != 0)
        return;
    const uint16_t port = ntohs(peer.sin_port);
    for (int i = 0; i < NCLIENTS; i++)
    {
        if (g_world->cli[i].fd >= 0 && g_world->cli[i].lport == port)
        {
            g_world->cli[i].accepted = true;
            g_world->cli[i].proxy_fd = fd;
            return;
        }
    }
}

void cb_on_disconnect(int) {}

std::optional<std::string> cb_proxy_request(int, std::string_view data)
{
    switch (g_hook_mode % 4)
    {
        case 0:
        case 1:
            return std::optional<std::string>(std::string());   // unchanged
        case 2:
            // Same bytes, other storage: the path that moves a hook's string
            // into the write queue instead of copying the caller's view.
            return std::optional<std::string>(std::string(data));
        default:
            return std::nullopt;                                 // drop
    }
}

std::optional<std::string> cb_proxy_response(int, std::string_view data)
{
    switch (g_hook_mode % 4)
    {
        case 0:
        case 1:
            return std::optional<std::string>(std::string());
        case 2:
            return std::optional<std::string>(std::string(data));
        default:
            return std::nullopt;
    }
}

// The group's membership, as the daemon publishes it: a snapshot of endpoints,
// not a pointer into another runtime.  Republished by OP_MEMBERSHIP while
// requests are in flight, which is the moment drop_departed_endpoints() and the
// per-member breakers exist for.
void publish_endpoints(world& w)
{
    if (!w.rt)
        return;
    auto tbl = std::make_shared<endpoint_table>();
    for (int i = 0; i < NBACKENDS; i++)
    {
        if (!(w.group_mask & (1u << i)))
            continue;
        tbl->add_to_group("fuzzgrp", runtime_endpoint{"127.0.0.1", w.be[i].port});
    }
    w.rt->set_endpoints(std::move(tbl));
}

std::unique_ptr<proxy_instance> make_instance(world& w)
{
    auto rt = std::make_unique<proxy_instance>("fuzz-proxy");
    rt->set_port(w.port);
    rt->set_event_loop(g_loop);
    rt->set_protocol(w.tcp ? protocol_tcp : protocol_http);

    char addr[64];
    switch (w.shape % 6)
    {
        case 0:
            std::snprintf(addr, sizeof(addr), "127.0.0.1:%u", w.be[0].port);
            rt->add_backend(addr);
            break;
        case 1:
            std::snprintf(addr, sizeof(addr), "127.0.0.1:%u", w.be[0].port);
            rt->add_backend(addr);
            std::snprintf(addr, sizeof(addr), "127.0.0.1:%u", w.be[1].port);
            rt->add_backend(addr);
            break;
        case 2:
            rt->add_backend("@fuzzgrp");
            break;
        case 3:
            // The mixed shape 84d624c is about: a group entry beside a plain
            // backend, where a member's failure used to be charged to whatever
            // occupied the group's index.
            std::snprintf(addr, sizeof(addr), "127.0.0.1:%u", w.be[0].port);
            rt->add_backend(addr);
            rt->add_backend("@fuzzgrp");
            break;
        case 4:
            std::snprintf(addr, sizeof(addr), "127.0.0.1:%u", w.dead_port);
            rt->add_backend(addr);
            std::snprintf(addr, sizeof(addr), "127.0.0.1:%u", w.be[1].port);
            rt->add_backend(addr);
            break;
        default:
            for (int i = 0; i < NBACKENDS; i++)
            {
                std::snprintf(addr, sizeof(addr), "127.0.0.1:%u", w.be[i].port);
                rt->add_backend(addr);
            }
            break;
    }

    rt->set_on_connect(cb_on_connect);
    rt->set_on_disconnect(cb_on_disconnect);

    // The pinned configuration, applied to every instance this input builds —
    // including the ones OP_DESTROY creates — so that a program cannot leave
    // the configuration the run is about by restarting the runtime.  OP_CONFIG
    // is refused for the same knobs; see run_step().
    if (g_pin.has_backend_timeout)
        rt->set_backend_timeout(g_pin.backend_timeout);
    if (g_pin.has_circuit_threshold)
        rt->set_circuit_threshold(g_pin.circuit_threshold);
    if (g_pin.has_retries)
        rt->set_retry_count(g_pin.retries);
    if (g_pin.has_max_connections)
        rt->set_max_connections(static_cast<uint32_t>(g_pin.max_connections));
    if (g_pin.has_idle_timeout)
        rt->set_idle_timeout(static_cast<uint32_t>(g_pin.idle_timeout));

    // The two legs, independently.  Nothing but a refused start may leave a leg
    // that asked for encryption running in cleartext, so a setup() that returns
    // false here is the runtime doing its job and the program simply gets
    // nothing more out of it.
    if (w.tls_front && tls_available())
    {
        rt->set_tls(true);
        rt->set_cert_path(*g_cert_path);
        rt->set_key_path(*g_key_path);
    }
    if (w.tls_back && tls_available())
    {
        // --ca alone turns the backend leg on for every backend at once,
        // group members included: they have no address of their own to carry an
        // https:// scheme.  The trust store is the certificate the harness
        // backends serve, so the chain and the endpoint's name both check out.
        rt->set_ca_path(*g_cert_path);
    }

    // A filter chain, when the configuration asked for one.  There is no other
    // way to reach run_request_filters: it is guarded by lua()->has_filters(),
    // so a proxy with no script does not make the call at all.  The script
    // answers 403 for one path and rewrites the headers of every other request,
    // which are the chain's two vocabularies — see 7689b7a.
    if (w.lua && g_lua_path && !g_lua_path->empty())
    {
        if (!rt->load_lua_script(*g_lua_path))
            w.lua = false;
    }

    return rt;
}

// ─────────────────────────── the invariant checks ───────────────────────────

// Invariant 4, from outside the class.  invariants.h states it at the moment of
// the push and this states it at rest, which are different questions: a struct
// can be pushed safely and become unsafe afterwards if anything re-arms on it.
//
// `deep` walks the whole pool.  Per step only the back of it is looked at —
// that is where a struct that has just gone in is — and the whole thing is
// walked once at the end of the input.
void check_struct_pools(proxy_instance* rt, bool deep)
{
    {
        const size_t n = rt->m_client_pool.size();
        for (size_t i = deep ? 0 : (n > 4 ? n - 4 : 0); i < n; i++)
        {
            auto* c = rt->m_client_pool[i].get();
            RT_FINDING("pool-owner-set",
                       c->read_req.owner == nullptr && c->write_req.owner == nullptr &&
                       c->splice_in_req.owner == nullptr && c->splice_out_req.owner == nullptr &&
                       c->connect_req.owner == nullptr && c->abort_req.owner == nullptr,
                       "a pooled client struct still carries a live owner on one of its "
                       "requests, so a completion that arrives for it is dispatched into "
                       "whichever connection takes the struct over");
            RT_FINDING("pool-armed",
                       !c->read_pending && !c->write_pending && !c->zc_notif_pending &&
                       !c->splice_in_pending && !c->splice_out_pending &&
                       !c->connect_pending && !c->abort_watch_pending,
                       "a client struct is in the pool with an operation still armed on it "
                       "— the next accept is handed a struct the kernel is still using");
            RT_FINDING("pool-fd-held",
                       c->connect_fd < 0 && c->pipe_to_backend[0] < 0 && c->pipe_to_backend[1] < 0,
                       "a pooled client struct still holds a descriptor — it is lost for good "
                       "unless the struct happens to be reused");
            RT_FINDING("pool-session-held", c->ssl == nullptr,
                       "a pooled client struct still carries a TLS session, so the next "
                       "connection would inherit a peer's negotiated identity");
        }
    }
    {
        const size_t n = rt->m_backend_struct_pool.size();
        for (size_t i = deep ? 0 : (n > 4 ? n - 4 : 0); i < n; i++)
        {
            auto* c = rt->m_backend_struct_pool[i].get();
            RT_FINDING("pool-owner-set",
                       c->read_req.owner == nullptr && c->write_req.owner == nullptr &&
                       c->splice_in_req.owner == nullptr && c->splice_out_req.owner == nullptr,
                       "a pooled backend struct still carries a live owner on one of its "
                       "requests");
            RT_FINDING("pool-armed",
                       !c->read_pending && !c->write_pending && !c->zc_notif_pending &&
                       !c->splice_in_pending && !c->splice_out_pending && !c->pool_draining,
                       "a backend struct is in the pool with an operation still armed on it");
            RT_FINDING("pool-fd-held",
                       c->pipe_to_client[0] < 0 && c->pipe_to_client[1] < 0,
                       "a pooled backend struct still holds a splice pipe open");
            RT_FINDING("pool-session-held", c->ssl == nullptr,
                       "a pooled backend struct still carries a TLS session");
        }
    }
}

// Invariant B at the moment of filing, and the pool's own two rules.
//
// The socket pool is the one place in this runtime where a *descriptor* changes
// hands without going back to the kernel, so everything that makes a descriptor
// dangerous applies to it: an SQE that still names it, an index entry that
// still claims it, and — the one that is this target's own — a response that
// has not finished on it.
//
// ─── WHY THIS ASKS AT FILING TIME AND NOT AT REST ───────────────────────────
//
// It used to ask at rest: walk the pool every step, and report any socket found
// in it while the harness backend's answer was unfinished.  That reported two
// different things under one id.  One is the defect — release_to_pool() files a
// socket in the middle of a message, because the proxy and the backend disagree
// about where the message ended (efdbabd) — and the other is a backend starting
// a NEW message, unbidden, on a socket the proxy had already filed correctly at
// a boundary.  In the second the finding's own words are false: it says the
// socket "was filed in the pool somewhere other than a message boundary", and
// the filing was right; the state changed under it afterwards.
//
// The proxy cannot be asked to notice the second, either.  Noticing would mean
// having something armed on a pooled socket, and pooled-fd-armed above forbids
// exactly that by name — the two invariants cannot both be satisfied as they
// were written.  The earliest the proxy can act is when it next reaches for the
// socket, which is where acquire_pooled_backend's probe now refuses it.
//
// So the question is asked once, of the filing, and in_pool is what makes that
// possible: a socket seen in the pool that was not in it at the end of the
// previous step has just been filed, and that is the one observation invariant
// B is entitled to make about the proxy.  Everything the harness does to a
// socket that is already filed is the harness's own traffic; whether the next
// borrower survives it is the probe's question, and crosstalk's, not this one's.
//
// Three separate agents diagnosed the at-rest form as a defect on 2026-08-01
// before it was written down.
//
// ─── AND WHY "JUST FILED" IS NOT ON ITS OWN ENOUGH ──────────────────────────
//
// in_pool narrows *when* the question is asked.  It does not make resp_pending
// the right thing to ask, and a sixth artefact of this id came in against the
// narrowed form on 2026-08-02 to prove it.
//
// The gap is that the proxy's filing decision and this walk's first sight of it
// are not the same instant.  detach_and_pool_backend takes the decision when the
// response frames complete, but the socket does not reach the pool until the
// read it cancelled has come back -ECANCELED through finish_pool_drain, which is
// at least one more pump away.  A backend that writes again inside that window
// sets resp_pending on a socket whose filing was already decided, at a boundary,
// against a stream with nothing unread on it — and the old form charged the
// filing for it.  That reproducer answered its one request completely at step
// 57, wrote an unsolicited half-response at step 58, and the drain landed at
// step 59; the filing was right and the two bytes of state that said otherwise
// were both written after it.
//
// resp_pending cannot tell those apart, because it is a fact about this end's
// writing and the claim is a fact about the proxy's *reading*.  So the claim is
// stated as the geometric fact it has always named.  This end knows where every
// message boundary on the wire is (complete_at) and how far it has written
// (tx_bytes); the proxy's own position is tx_bytes less whatever it has not
// consumed, and the socket was filed off a boundary exactly when that position
// is past complete_at.
//
// That measurement is stable, which is what makes it answerable from a walk that
// may be several steps late.  Nothing is armed on a pooled fd — pool-armed above
// forbids it by name — so the proxy consumes nothing further from it and its
// position at this walk is its position at the filing.  Bytes the harness writes
// afterwards raise tx_bytes and the unread count together and cancel out
// exactly, which is precisely the artefact class, and they are silent now for a
// reason rather than by exclusion.
//
// Nothing is lost.  The defect efdbabd fixed is a complete answer with the head
// of another behind it in one write: the proxy consumes all of it, so its
// position is the end of both and complete_at is the end of the first, and the
// difference between them is the report.  Checked by putting that fix back out
// and watching this fire on proxy/response_with_a_tail — "56 bytes past the last
// message boundary ... written 114 bytes, the last whole message ends at 58, and
// 0 are still unread".
void check_backend_pool(world& w, proxy_instance* rt)
{
    for (int i = 0; i < NBSOCK; i++)
        w.bs[i].pool_seen = false;

    for (const auto& pool : rt->m_backend_pool)
    {
        for (const auto& pb : pool)
        {
            if (pb.fd < 0)
                continue;

            RT_FINDING("pooled-fd-armed", g_loop->fd_inflight(pb.fd) == 0,
                       "a descriptor in the backend pool is still named by a submission in "
                       "the ring — the next request takes it while that operation is "
                       "outstanding, and the operation then belongs to a connection it was "
                       "never part of");

            if (pb.fd < proxy_instance::MAX_FDS)
                RT_FINDING("pooled-fd-indexed",
                           rt->m_conn_idx[pb.fd].side == conn_none,
                           "a descriptor in the backend pool is still in the dispatch index, "
                           "so a completion naming it would be routed into a connection that "
                           "has been given away");

            // ── the key against the kernel ──
            //
            // A pooled socket is handed to the next request whose endpoint
            // equals the one it is filed under, so the filed endpoint is the
            // whole of the identity check on the acquire side and nothing
            // downstream re-derives it.  That makes the filing the only place
            // it can be wrong, and the proxy cannot check it: both halves come
            // out of its own backend_endpoint_of().  getpeername() is a second
            // source — the address the kernel actually has this socket
            // connected to — so a socket filed under an endpoint it does not
            // go to is caught here rather than by whoever borrows it.
            //
            // This is what makes "a pooled socket cannot cross host or port"
            // a checked fact.  It matters more once a socket carries a
            // session: on a TLS leg the endpoint filed here is also the SNI
            // name sent and the name the certificate was verified against —
            // start_backend_tls derives both from the same call — so a
            // mis-filed endpoint is a mis-filed peer identity too.
            struct sockaddr_in peer{};
            socklen_t peerlen = sizeof(peer);
            if (::getpeername(pb.fd, reinterpret_cast<struct sockaddr*>(&peer), &peerlen) == 0)
            {
                char ip[INET_ADDRSTRLEN] = {0};
                ::inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
                const uint16_t rport = ntohs(peer.sin_port);
                fuzzrt::set_detail("filed under %s:%u, actually connected to %s:%u",
                                   pb.host.c_str(), static_cast<unsigned>(pb.port),
                                   ip, static_cast<unsigned>(rport));
                RT_FINDING("pooled-entry-endpoint",
                           rport == pb.port && pb.host == ip,
                           "a socket in the backend pool is filed under an endpoint it is not "
                           "connected to — the pool hands it to the next request for that "
                           "endpoint, so that request goes to a peer nobody routed it to, and "
                           "on an encrypted leg to a peer whose certificate was checked "
                           "against a different name");
                fuzzrt::g_detail[0] = 0;
            }

            // ── the session against the configuration ──
            //
            // An entry's session and the leg it belongs to have to agree, and
            // the harness knows which leg it configured, so this is stated
            // from outside the proxy rather than from its own flags.
            //
            // Both directions are defects and neither is quiet.  A socket from
            // an encrypted leg pooled *without* its session is a descriptor
            // whose record layer has been thrown away: the next borrower
            // writes a plaintext request into a stream the peer is decrypting,
            // and every byte of it is garbage or an alert.  A socket from a
            // cleartext leg pooled *with* one could only have got it from
            // somewhere else.
            fuzzrt::set_detail("the backend leg is %s and the pooled entry %s a session",
                               w.tls_back ? "encrypted" : "cleartext",
                               pb.ssl ? "carries" : "does not carry");
            RT_FINDING("pooled-entry-session",
                       (pb.ssl != nullptr) == (w.tls_back && tls_available()),
                       "a backend pool entry disagrees with its own leg about whether it has "
                       "a TLS session — a pooled descriptor and the record layer that owns "
                       "its stream are one thing, and either half without the other is handed "
                       "to the next request as a connection it cannot speak on");
            fuzzrt::g_detail[0] = 0;

            // Which of the harness's own backend sockets this is.  The proxy's
            // end of that connection is the peer the harness accepted, so the
            // local port of the pooled descriptor names it exactly.
            struct sockaddr_in me{};
            socklen_t melen = sizeof(me);
            if (::getsockname(pb.fd, reinterpret_cast<struct sockaddr*>(&me), &melen) != 0)
                continue;
            const uint16_t lport = ntohs(me.sin_port);
            for (int i = 0; i < NBSOCK; i++)
            {
                if (w.bs[i].fd < 0 || w.bs[i].peer_port != lport)
                    continue;

                const bool just_filed = !w.bs[i].in_pool;
                w.bs[i].pool_seen = true;

                if (!just_filed || !w.bs[i].resp_pending)
                    break;

                // ── where the proxy's end of this stream actually sits ──
                //
                // Everything this end has written is either a whole message
                // (up to complete_at) or the unfinished one behind it (up to
                // tx_bytes).  The proxy's own position is everything it has
                // taken off the socket, which is tx_bytes less whatever is
                // still waiting for it — and the filing is off a boundary
                // exactly when that position is past complete_at.
                //
                // The position does not move once the socket is in the pool.
                // Nothing is armed on a pooled fd — pooled-fd-armed above
                // forbids it by name — so the proxy reads no further, and this
                // measurement at the walk is the position it had at the filing
                // however many steps ago that was.  That is what makes the
                // question answerable here at all, and it is the whole
                // difference between this and asking whether resp_pending
                // happens to be set: the flag drifts with the harness's own
                // later writes, and this does not.
                int nread = 0;
                if (::ioctl(pb.fd, FIONREAD, &nread) != 0 || nread < 0)
                    nread = 0;
                const size_t unconsumed =
                    static_cast<size_t>(nread) +
                    (pb.ssl ? static_cast<size_t>(std::max(0, SSL_pending(pb.ssl))) : 0);

                // On a cleartext leg the two counts are in the same units and
                // the position is exact.  On an encrypted one they are not —
                // this end counts the plaintext it handed to SSL_write and the
                // socket holds ciphertext — so the arithmetic is not available
                // and the question is asked in the one form that needs no
                // units: nothing left unconsumed anywhere means the proxy took
                // every byte this end wrote, the unfinished message with them.
                bool off_boundary;
                if (pb.ssl)
                {
                    off_boundary = (unconsumed == 0);
                }
                else
                {
                    const size_t consumed = w.bs[i].tx_bytes > unconsumed
                                                ? w.bs[i].tx_bytes - unconsumed
                                                : 0;
                    off_boundary = consumed > w.bs[i].complete_at;
                }

                if (!off_boundary)
                    break;

                fuzzrt::set_detail("the socket to 127.0.0.1:%u was filed in the pool with the "
                                   "proxy's end of the stream %zu bytes past the last message "
                                   "boundary on it (this end has written %zu bytes, the last "
                                   "whole message ends at %zu, and %zu are still unread)",
                                   static_cast<unsigned>(pb.port),
                                   (w.bs[i].tx_bytes > unconsumed
                                        ? w.bs[i].tx_bytes - unconsumed
                                        : 0) - w.bs[i].complete_at,
                                   w.bs[i].tx_bytes, w.bs[i].complete_at, unconsumed);
                RT_FINDING("pool-off-boundary", false,
                           "a backend socket was filed in the connection pool somewhere other "
                           "than a message boundary — the tail of this response is still to "
                           "come, and the next request to borrow the socket reads it as the "
                           "head of its own answer");
                fuzzrt::g_detail[0] = 0;
                w.bs[i].resp_pending = false;   // one report is the diagnosis
                break;
            }
        }
    }

    // Carried into the next step, so that the next walk can tell a socket that
    // has just been filed from one that has been sitting there.  A socket that
    // left the pool goes back to false and is adjudicated again the next time
    // the proxy files it, which is right: that is a second filing decision.
    for (int i = 0; i < NBSOCK; i++)
        w.bs[i].in_pool = w.bs[i].pool_seen;
}

void check_instance(world& w, bool deep)
{
    auto* rt = w.rt.get();
    if (!rt)
        return;

    check_struct_pools(rt, deep);
    check_backend_pool(w, rt);

    // The dispatch index and the owning slot have to agree for every client the
    // harness knows the proxy accepted.  A full walk of the 65536-entry tables
    // is an end-of-input cost; this is the part that can be paid per step.
    for (int i = 0; i < NCLIENTS; i++)
    {
        const int fd = w.cli[i].proxy_fd;
        if (fd < 0 || fd >= proxy_instance::MAX_FDS)
            continue;
        if (!rt->m_client_slots[fd])
            continue;
        RT_CHECK(rt->m_conn_idx[fd].side == conn_client &&
                 rt->m_conn_idx[fd].client == rt->m_client_slots[fd].get(),
                 "the dispatch index does not point at the connection the slot holds for "
                 "that descriptor");
        RT_CHECK(rt->m_client_slots[fd]->fd == fd,
                 "a connection's own fd disagrees with the slot it is filed under");
    }

    if (!deep)
        return;

    // The whole of both tables, once.  A slot with no index entry is a
    // connection no completion can ever be routed to; an index entry with no
    // slot is a pointer into storage nobody owns.
    for (int fd = 0; fd < proxy_instance::MAX_FDS; fd++)
    {
        const auto& e = rt->m_conn_idx[fd];
        if (rt->m_client_slots[fd])
        {
            RT_CHECK(e.side == conn_client && e.client == rt->m_client_slots[fd].get(),
                     "a client slot is not the one the dispatch index names for its fd");
        }
        if (rt->m_backend_slots[fd])
        {
            RT_CHECK(e.side == conn_backend && e.backend == rt->m_backend_slots[fd].get(),
                     "a backend slot is not the one the dispatch index names for its fd");
        }
        if (e.side == conn_client)
            RT_CHECK(rt->m_client_slots[fd] != nullptr,
                     "the dispatch index names a client connection nothing owns");
        else if (e.side == conn_backend)
            RT_CHECK(rt->m_backend_slots[fd] != nullptr,
                     "the dispatch index names a backend connection nothing owns");
    }
}

// ─────────────────────────── lifecycle operations ───────────────────────────

void do_start(world& w)
{
    if (!w.rt)
        return;
    const runtime_state st = w.rt->get_state();
    if (st != runtime_created && st != runtime_stopped)
        return;
    w.epoch++;
    w.rt->start(*g_loop);
    if (w.rt->get_state() == runtime_running)
        publish_endpoints(w);
}

void do_stop(world& w)
{
    if (w.rt && w.rt->get_state() == runtime_running)
    {
        w.epoch++;
        w.rt->stop(*g_loop);
    }
}

// Invariant 1, in its strongest form: the instance is freed, and then the loop
// is pumped again.  If anything the kernel still holds names storage inside it,
// run() reads the request before it dispatches — so the read is of freed memory
// and ASan says so.
void retire_instance(world& w, const char* where)
{
    if (!w.rt)
        return;
    do_stop(w);

    // The budget is the sweeps': this runtime arms three separate timer chains
    // (idle, response deadline, health) and a stop has to withdraw every one of
    // them.  A withdrawal that did not reach the ring is what this waits for and
    // what it reports.
    const bool drained = g_watch.drain_owner(w.rt.get(), 40);
    if (!drained)
    {
        g_watch.report_stuck_owner(w.rt.get(), where);
        RT_FINDING("owner-never-drains", false,
                   "the ring still owes this instance a completion long after it stopped, so "
                   "its storage can never be freed — the manager holds the whole instance in "
                   "its graveyard until whatever it is finally reports");
        fuzzrt::g_detail[0] = 0;
        g_graveyard->push_back(std::move(w.rt));
        return;
    }

    check_instance(w, true);
    w.rt.reset();
    for (int i = 0; i < 4; i++)
        g_loop->poll_completions(0);
}

void reap_graveyard()
{
    for (size_t i = 0; i < g_graveyard->size(); )
    {
        if (g_loop->owner_inflight((*g_graveyard)[i].get()) == 0)
        {
            (*g_graveyard)[i] = std::move(g_graveyard->back());
            g_graveyard->pop_back();
        }
        else
        {
            i++;
        }
    }
}

void reset_world_sockets(world& w)
{
    for (auto& c : w.cli)
    {
        c.self_closed = true;
        client_close(c);
    }
    for (auto& b : w.bs)
        bsock_close(b);
    for (auto& L : w.be)
    {
        if (L.filler >= 0) { ::close(L.filler); L.filler = -1; }
        if (L.fd >= 0)     { ::close(L.fd);     L.fd = -1; }
        L.mode = 0;
    }
}

// ── the clock, moved by hand ────────────────────────────────────────────────
//
// A backend response deadline is two seconds and a header deadline ten.  An
// input that waited for either would be the whole budget, so the deadlines are
// moved into the past and the sweep is called directly.  Everything the sweep
// then does — charging the breaker, withdrawing a handshake, answering 504 or
// 408, retrying elsewhere — is the product's own code on the product's own
// path; the only thing simulated is that time passed.
void expire_deadlines(world& w)
{
    auto* rt = w.rt.get();
    if (!rt || rt->get_state() != runtime_running)
        return;

    const auto past = std::chrono::steady_clock::now() - std::chrono::seconds(60);
    // Only the connections the harness knows about, so this stays O(clients)
    // rather than walking the 65536-entry slot table on every step.
    for (int i = 0; i < NCLIENTS; i++)
    {
        const int fd = w.cli[i].proxy_fd;
        if (fd < 0 || fd >= proxy_instance::MAX_FDS || !rt->m_client_slots[fd])
            continue;
        auto* c = rt->m_client_slots[fd].get();
        if (c->awaiting_response) c->response_deadline = past;
        if (c->awaiting_headers)  c->header_deadline = past;
    }
    rt->response_deadline_sweep();
}

// The same for the two other clocks the proxy reads: a pooled socket is stale
// after a minute, and an open breaker goes half-open after circuit_timeout.
// Both are consulted on the request path, so moving the stamp is enough to
// reach what they decide without arming anything.
void age_state(world& w)
{
    auto* rt = w.rt.get();
    if (!rt)
        return;
    const auto past = std::chrono::steady_clock::now() -
                      std::chrono::seconds(proxy_instance::POOL_IDLE_TIMEOUT_SEC + 5);
    for (auto& pool : rt->m_backend_pool)
        for (auto& pb : pool)
            pb.idle_since = past;
    const auto opened = std::chrono::steady_clock::now() -
                        std::chrono::seconds(rt->m_mesh.circuit_timeout + 1);
    for (auto& cb : rt->m_circuit_breakers)
        if (cb.current == circuit_breaker::open)
            cb.opened_at = opened;
    for (auto& [key, cb] : rt->m_group_breakers)
    {
        (void)key;
        if (cb.current == circuit_breaker::open)
            cb.opened_at = opened;
    }
}

// ─────────────────────────────── the interpreter ────────────────────────────

void run_step(world& w, const step& s)
{
    switch (s.op)
    {
        case OP_START: do_start(w); break;
        case OP_STOP:  do_stop(w);  break;

        case OP_DESTROY:
            retire_instance(w, "OP_DESTROY");
            reset_world_sockets(w);
            w.port      = next_port();
            w.dead_port = next_port();
            for (int i = 0; i < NBACKENDS; i++)
                w.be[i].port = next_port();
            w.shape = s.a & 0x07;
            w.tcp   = (s.a & 0x08) != 0;
            w.lua   = (s.a & 0x10) != 0;
            w.group_mask = static_cast<uint8_t>((s.c & 0x07) ? (s.c & 0x07) : 0x07);
            w.tls_front = (s.c & 0x08) != 0;
            w.tls_back  = (s.c & 0x10) != 0;
            w.epoch++;
            w.rt = make_instance(w);
            publish_endpoints(w);
            // Every backend starts listening: an instance nobody can reach is a
            // program that ends after its first request, and the other two modes
            // are one OP_BE_LISTEN away.
            for (int i = 0; i < NBACKENDS; i++)
                backend_listen(w, i, 1);
            break;

        case OP_PUMP:
        {
            const int passes = 1 + (s.a & 3);
            for (int i = 0; i < passes; i++)
                g_loop->poll_completions(s.b & 1);
            break;
        }

        case OP_CONNECT: client_connect(w, s.a % NCLIENTS); break;
        case OP_REQUEST: client_send(w, s.a % NCLIENTS, s.b); break;
        case OP_RECV:    client_recv(w, s.a % NCLIENTS); break;

        case OP_FIN:
        {
            client_sock& c = w.cli[s.a % NCLIENTS];
            if (c.fd >= 0 && !c.fin_sent)
            {
                ::shutdown(c.fd, SHUT_WR);
                c.fin_sent = true;
            }
            break;
        }

        case OP_ABORT:
        {
            client_sock& c = w.cli[s.a % NCLIENTS];
            c.self_closed = true;
            client_close(c);
            break;
        }

        case OP_CLOSE_CLIENT:
        {
            // The Lua-facing close, which takes a raw descriptor and has to
            // survive being handed a stale one.  The client is not owed an
            // answer after it: the script asked for the connection to end.
            client_sock& c = w.cli[s.a % NCLIENTS];
            if (w.rt)
            {
                const int target = c.proxy_fd >= 0 ? c.proxy_fd
                                                   : static_cast<int>(s.b);
                w.rt->lua_close_client(target);

                // Marked on the connection that was actually closed, not on the
                // client this step names.
                //
                // proxy_fd is a raw descriptor number and this call is the one
                // interface that takes one, so a number left over from a
                // previous run of the runtime still looks live: stop() closes
                // the proxy's end and frees the number, a restart hands the very
                // same number to the next client that connects, and the harness
                // is then holding it under two clients at once.  Measured on the
                // artefact this came in on -- cli[0] fd=9 proxy_fd=10 and cli[1]
                // fd=8 proxy_fd=10, with 10 belonging to cli[1] -- so asking for
                // client[0] closed client[1]'s connection.  The proxy is right
                // to do that: it was handed a descriptor that names a live
                // client, and a bare fd carries no generation for it to check.
                // What was wrong is that the harness then credited the close to
                // client[0] and went on to report client[1], which had asked for
                // nothing, as a client the proxy closed without an answer.
                //
                // Keyed on the descriptor, so it is right however the collision
                // arose -- including the s.b path above, which is an arbitrary
                // number and can name a live connection just as easily.
                for (int k = 0; k < NCLIENTS; k++)
                    if (w.cli[k].proxy_fd == target)
                        w.cli[k].self_closed = true;
                c.self_closed = true;
            }
            break;
        }

        case OP_BE_LISTEN:  backend_listen(w, s.a % NBACKENDS, s.b); break;
        case OP_BE_ACCEPT:  backend_accept(w, s.a % NBACKENDS); break;
        case OP_BE_RECV:    bsock_recv(w, s.a % NBSOCK); break;
        case OP_BE_RESPOND: bsock_respond(w, s.a % NBSOCK, s.b); break;

        case OP_BE_FIN:
        {
            backend_sock& b = w.bs[s.a % NBSOCK];
            if (b.fd >= 0)
                ::shutdown(b.fd, SHUT_WR);
            break;
        }

        case OP_BE_ABORT:   bsock_close(w.bs[s.a % NBSOCK]); break;
        case OP_BE_SERVE:   backend_serve(w, s.a % NBACKENDS, s.b); break;

        case OP_MEMBERSHIP:
            w.group_mask = static_cast<uint8_t>(s.a & 0x07);
            publish_endpoints(w);
            break;

        case OP_CONFIG:
            if (w.rt)
            {
                // A knob the run pinned is not a knob the program owns.  The
                // op is still decoded and still printed — the program is what
                // it is — it simply does not land, so a configuration the
                // matrix is sweeping cannot be left partway through an input.
                switch (s.a % 8)
                {
                    case 0: w.rt->set_strategy(static_cast<proxy_strategy>(s.b % 3)); break;
                    case 1:
                        if (!g_pin.has_retries)
                        {
                            w.rt->set_retry_count(s.b % 3);
                            w.rt->set_retry_all((s.b & 4) != 0);
                        }
                        break;
                    case 2:
                        if (!g_pin.has_circuit_threshold)
                            w.rt->set_circuit_threshold(s.b % 4);
                        break;
                    case 3:
                        if (!g_pin.has_backend_timeout)
                            w.rt->set_backend_timeout(s.b % 3);
                        break;
                    case 4:
                        if (!g_pin.has_max_connections)
                            w.rt->set_max_connections(s.b % 6);
                        break;
                    case 5:
                        if (!g_pin.has_idle_timeout)
                            w.rt->set_idle_timeout(s.b & 1);
                        break;
                    case 6:
                        g_hook_mode = s.b % 4;
                        g_hook_drops = (g_hook_mode % 4) == 3;
                        if (g_hook_mode == 0)
                        {
                            w.rt->set_on_proxy_request(nullptr);
                            w.rt->set_on_proxy_response(nullptr);
                        }
                        else
                        {
                            w.rt->set_on_proxy_request(cb_proxy_request);
                            w.rt->set_on_proxy_response(cb_proxy_response);
                        }
                        break;
                    default:
                        // setup() reads this, and an HTTP probe against a TLS
                        // backend is refused there — so it only moves between
                        // runs.
                        if (w.rt->get_state() != runtime_running)
                        {
                            w.rt->set_health_check(
                                static_cast<mesh_config::health_type>(s.b % 3));
                            w.rt->set_health_interval(1);
                        }
                        break;
                }
            }
            break;

        case OP_DEADLINE: expire_deadlines(w); break;
        case OP_AGE:      age_state(w); break;

        case OP_STATS:
            // Called for the walk it does over the connection tables and the
            // breakers, not for what it returns: a runtime that has never been
            // started legitimately has nothing to say.
            if (w.rt)
            {
                const std::string st = w.rt->get_stats();
                (void)st.size();
            }
            break;

        default:
            break;
    }

    // One non-blocking pass after every step, so the ring makes progress even
    // through a stretch of the program with no explicit pump in it.  OP_PUMP is
    // still what lets the fuzzer decide *how much* progress, which is the knob
    // that matters: the interesting orderings are the ones where a completion
    // has not been reaped yet.
    g_loop->poll_completions(0);

    // Every client is read after every step.  Invariant A is stated over what a
    // client's socket does, so a client that is never read is a client the
    // oracle cannot speak about — and leaving the reading to OP_RECV alone would
    // make the check depend on the mutator issuing one.
    for (int i = 0; i < NCLIENTS; i++)
        client_recv(w, i);

    check_instance(w, false);
}

// ──────────────────────────── one-time setup ────────────────────────────────

// The filter chain, as a script, because that is the only interface it has.
// Two filters and both vocabularies: the first answers a request outright — no
// backend is selected, no endpoint resolved, no socket taken from the pool —
// and the second lets it through with a header set on it.
void write_lua_script()
{
    char path[128];
    std::snprintf(path, sizeof(path), "/dev/shm/socketley-fuzz-proxy-%d.lua",
                  static_cast<int>(::getpid()));

    static const char script[] =
        "filters = {\n"
        "  function(req)\n"
        "    if string.find(req.path, 'deny', 1, true) then\n"
        "      return { status = 403, body = 'denied\\n' }\n"
        "    end\n"
        "  end,\n"
        "  function(req)\n"
        "    return { set_headers = { ['x-fuzz-filter'] = 'yes' } }\n"
        "  end,\n"
        "}\n";

    int fd = ::open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return;
    const bool ok = ::write(fd, script, sizeof(script) - 1) ==
                    static_cast<ssize_t>(sizeof(script) - 1);
    ::close(fd);
    if (ok)
        g_lua_path = new std::string(path);
}

void init_once()
{
    if (g_loop)
        return;

    // The runtime logs a line whenever a timer withdrawal does not reach the
    // ring and on a few other conditions this target deliberately provokes.
    // Those are checked here directly, so the text is noise.
    logger::g_level = log_error;

    // The runtimes are written for the daemon's process, and the daemon ignores
    // SIGPIPE at startup.  A harness that did not do the same would kill itself
    // on a socket the program deliberately reset, and report it as a finding in
    // the runtime.
    signal(SIGPIPE, SIG_IGN);

    // Before anything is built, because make_instance() reads it.
    parse_pinned_config();

    g_graveyard = new std::vector<std::unique_ptr<proxy_instance>>();
    write_lua_script();
    write_tls_material();

    g_loop = new event_loop(2048);
    if (!g_loop->init())
    {
        std::fprintf(stderr,
            "fuzz_proxy_ops: event_loop::init() failed — there is no io_uring here, so this "
            "target cannot check anything it exists to check.\n");
        std::abort();
    }
    g_watch.loop = g_loop;

    fuzzrt::skip_env() = "FUZZ_PROXY_SKIP";
    fuzzrt::print_program_hook() = print_program;
    // Three of the checks this target runs on are the product's own — invariant
    // 4 at the moment of a pool push, and the two in invariants.h that state
    // reachability and progress over a pair.  This is what makes their aborts
    // reproducible rather than merely readable.
    fuzzrt::adopt_invariant_reports();
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    init_once();
    (void)fuzzrt::finding_suppressed("");
    (void)fuzzrt::fd_scan_limit();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    init_once();

    data = ::fuzz::never_null(data);
    ::fuzz::set_current(data, size);
    g_steps = 0;

    // Four bytes per operation, like the other operation-sequence targets.  A
    // longer input only buys more steps, and a step here costs syscalls, so the
    // ceiling is on steps.
    if (size < 4)
        return 0;

    reap_graveyard();
    reset_ids();

    g_be_accepts  = 0;
    g_be_requests = 0;

    world w;
    g_world = &w;

    w.port      = next_port();
    w.dead_port = next_port();
    for (int i = 0; i < NBACKENDS; i++)
        w.be[i].port = next_port();

    // The leading bytes are read as configuration as well as as the first step,
    // exactly as in fuzz_server_ops: the shape of the proxy has to be decided
    // before anything is started, and an input whose first four bytes were spent
    // saying so would be four bytes of every program that said nothing.
    w.shape      = data[0] & 0x07;
    w.tcp        = (data[0] & 0x08) != 0;
    w.lua        = (data[0] & 0x10) != 0;
    w.group_mask = static_cast<uint8_t>((data[1] & 0x07) ? (data[1] & 0x07) : 0x07);
    // The two TLS bits live in byte 1 rather than byte 0 because the top three
    // bits of byte 0 are what px_head() in make_corpus.py uses to steer which
    // *operation* the same byte spells.  Byte 1 is that operation's first
    // argument, where a couple of high bits change nothing.
    w.tls_front  = (data[1] & 0x08) != 0;
    w.tls_back   = (data[1] & 0x10) != 0;
    g_hook_mode  = data[2] % 4;
    g_hook_drops = (g_hook_mode % 4) == 3;

    for (int i = 0; i < NBACKENDS; i++)
        backend_listen(w, i, 1);

    w.rt = make_instance(w);
    publish_endpoints(w);
    if (g_hook_mode != 0)
    {
        w.rt->set_on_proxy_request(cb_proxy_request);
        w.rt->set_on_proxy_response(cb_proxy_response);
    }

    size_t off = 0;
    while (off + 4 <= size && g_steps < MAX_STEPS)
    {
        step s;
        s.op = static_cast<uint8_t>(data[off + 0] % OP_COUNT);
        s.a  = data[off + 1];
        s.b  = data[off + 2];
        s.c  = data[off + 3];
        off += 4;

        g_prog[g_steps++] = s;
        run_step(w, s);
    }

    // ── the end of the input is where the invariants are at their strongest ──
    //
    // Everything is stopped, every peer is gone, and the ring is drained.  From
    // here nothing may still be owed: not to the instance, and not against any
    // descriptor number in the process.
    reset_world_sockets(w);
    retire_instance(w, "end of input");

    // Only meaningful with nothing stuck: an instance in the graveyard is one
    // that was already reported, and the descriptors it is holding are the same
    // finding said twice.
    if (g_graveyard->empty())
        g_watch.sweep_descriptors("end of input");

    // What the pool saved on this input, from the backend's end.  Off unless
    // asked for: it is a measurement rather than an invariant, and a number
    // printed on every input of a mutation run is a number nobody reads.
    if (std::getenv("FUZZ_PROXY_POOL_REPORT"))
        std::fprintf(stderr,
                     "pool: backend accepts=%lu requests=%lu  (tls_back=%d tls_front=%d)\n",
                     g_be_accepts, g_be_requests,
                     w.tls_back && tls_available() ? 1 : 0,
                     w.tls_front && tls_available() ? 1 : 0);

    g_world = nullptr;
    ::fuzz::set_current(nullptr, 0);
    return 0;
}
