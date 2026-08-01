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
//     the proxy has filed in its pool while that answer is unfinished is
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

#include <algorithm>
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
#include <sys/stat.h>
#include <unistd.h>

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
#include "runtime/proxy/http_response_framing.h"

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

void print_program()
{
    std::fprintf(stderr,
        "\n--- decoded operation sequence (%zu steps) ---\n"
        "// Each line is one step against one proxy_instance on one event_loop.\n"
        "// \"client\" is a harness socket dialling the proxy's listener;\n"
        "// \"backend\" is a harness listener the proxy dials, and \"bsock\" one\n"
        "// of the connections it accepted there.\n", g_steps);

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

    // A mark can straddle two reads, so the tail of the last one is kept.
    std::string carry;
};

struct backend_sock
{
    int      fd{-1};
    int      backend{-1};     // which harness listener accepted it
    uint16_t peer_port{0};    // the proxy's end, which is how a pooled fd is
                              // recognised — see check_backend_pool()

    // Invariant B's state.  True from the moment a response is started until
    // the moment it is finished; a socket in the proxy's pool with this set is
    // a socket pooled off a message boundary.
    bool     resp_pending{false};

    // Ids read out of requests on this socket and not yet answered, and the
    // last one that was — which is what an unsolicited answer is marked with,
    // so that a client receiving one can be told whose it was.
    uint32_t owed[8];
    uint8_t  owed_n{0};
    uint32_t last_id{0};

    std::string carry;
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
    static uint16_t p = 0;
    if (p == 0)
        p = static_cast<uint16_t>(20000 + (::getpid() % 4000));
    if (++p >= 30000)
        p = 20000;
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
void build_response(int shape, uint32_t id, std::string& out, bool& complete)
{
    out.clear();
    complete = true;

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
}

// ─────────────────────────── the harness sockets ────────────────────────────

void client_close(client_sock& c)
{
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
    c.accepted = false;
    c.proxy_fd = -1;
    c.carry.clear();
    c.run_epoch = w.epoch;
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

    fuzzrt::set_detail("client fd %d (proxy fd %d) sent %u complete request(s)%s and "
                       "received %zu bytes before the proxy closed it",
                       c.fd, c.proxy_fd, c.reqs_sent,
                       c.fin_sent ? " and then half-closed" : "", c.rx_since_req);
    if (c.fin_sent)
    {
        RT_FINDING("answer-lost-to-a-half-close", false,
                   "a client that had sent a whole request and then half-closed its write "
                   "side was torn down without an answer — the request is already at the "
                   "backend, so whatever it did there happened and the client will never "
                   "learn the outcome");
    }
    else
    {
        RT_FINDING("client-closed-without-answer", false,
                   "a client that had sent a whole request was closed without one byte of "
                   "an answer — no status, no framing error, nothing to distinguish a proxy "
                   "that has gone away from a backend that has, and nothing in any log on "
                   "the client's side");
    }
    fuzzrt::g_detail[0] = 0;
}

// ─── invariant C, stated where it is observable ─────────────────────────────
//
// Every mark in what a client receives has to be one of its own.  The bytes are
// well formed either way; that is what makes this the failure that has to be
// checked rather than noticed.
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

    // Keep enough of the tail that a mark split across two reads is still found.
    const size_t keep = MARK.size() + 12;
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
        ssize_t n = ::recv(c.fd, sink, sizeof(sink), MSG_DONTWAIT);
        if (n > 0)
        {
            c.rx_since_req += static_cast<size_t>(n);
            client_scan_marks(w, idx, std::string_view(sink, static_cast<size_t>(n)));
            continue;
        }
        if (n == 0)
        {
            client_report_close(w, c);
            break;
        }
        if (errno == ECONNRESET || errno == EPIPE)
        {
            client_report_close(w, c);
            break;
        }
        break;   // EAGAIN
    }
}

void client_send(world& w, int idx, int shape)
{
    client_sock& c = w.cli[idx];
    if (c.fd < 0)
        return;

    static std::string buf;
    const int whole = build_request(shape, idx, buf);

    // A short write on a non-blocking socket is ordinary and the remainder is
    // deliberately dropped: what the proxy has to survive is a request that
    // stops halfway, and that is what a short write produces.  A request only
    // counts as complete when all of it went out.
    ssize_t n = ::send(c.fd, buf.data(), buf.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
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
    if (static_cast<size_t>(n) == buf.size() && whole > 0)
    {
        c.reqs_sent += static_cast<uint32_t>(whole);
        c.rx_since_req = 0;
        c.run_epoch = w.epoch;
    }
}

// ─────────────────────────── the harness backends ───────────────────────────

void bsock_close(backend_sock& b)
{
    if (b.fd < 0)
        return;
    ::close(b.fd);
    b.fd = -1;
    b.backend = -1;
    b.peer_port = 0;
    b.resp_pending = false;
    b.owed_n = 0;
    b.last_id = 0;
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

    fuzzrt::set_abortive(fd);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    backend_sock& b = w.bs[slot];
    b.fd = fd;
    b.backend = idx;
    b.peer_port = ntohs(peer.sin_port);
    b.resp_pending = false;
    b.owed_n = 0;
    b.last_id = 0;
    b.carry.clear();
    return slot;
}

// ─── invariant B, at the moment a socket changes hands ──────────────────────
//
// A request arriving on a socket whose previous response never finished is the
// next borrower reading somebody else's tail.  Nothing else puts a second
// request on a backend socket: this proxy holds a pipelined request back until
// the first exchange is over.
void bsock_note_request(backend_sock& b, uint32_t id)
{
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
        ssize_t n = ::recv(b.fd, sink, sizeof(sink), MSG_DONTWAIT);
        if (n > 0)
        {
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
                    bsock_note_request(b, id);
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
        // Nothing was asked on this socket, which is the point: the answer is
        // marked with whoever asked last, so a client that receives it can be
        // told whose answer it got.
        id = b.last_id;
    }

    static std::string buf;
    bool complete = true;
    build_response(shape, id, buf, complete);

    ssize_t n = ::send(b.fd, buf.data(), buf.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
    if (n < 0)
    {
        if (errno == EPIPE || errno == ECONNRESET)
            bsock_close(b);
        return;
    }
    // A short write leaves the answer unfinished as surely as a shape that was
    // never going to finish it.
    b.resp_pending = !complete || static_cast<size_t>(n) != buf.size();
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

// Invariant B at rest, and the pool's own two rules.
//
// The socket pool is the one place in this runtime where a *descriptor* changes
// hands without going back to the kernel, so everything that makes a descriptor
// dangerous applies to it: an SQE that still names it, an index entry that
// still claims it, and — the one that is this target's own — a response that
// has not finished on it.
void check_backend_pool(world& w, proxy_instance* rt)
{
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
                if (!w.bs[i].resp_pending)
                    break;
                fuzzrt::set_detail("the socket to 127.0.0.1:%u is in the pool while the "
                                   "backend's answer on it is unfinished",
                                   static_cast<unsigned>(pb.port));
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
                w.rt->lua_close_client(c.proxy_fd >= 0 ? c.proxy_fd
                                                       : static_cast<int>(s.b));
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
                switch (s.a % 8)
                {
                    case 0: w.rt->set_strategy(static_cast<proxy_strategy>(s.b % 3)); break;
                    case 1:
                        w.rt->set_retry_count(s.b % 3);
                        w.rt->set_retry_all((s.b & 4) != 0);
                        break;
                    case 2: w.rt->set_circuit_threshold(s.b % 4); break;
                    case 3: w.rt->set_backend_timeout(s.b % 3); break;
                    case 4: w.rt->set_max_connections(s.b % 6); break;
                    case 5: w.rt->set_idle_timeout(s.b & 1); break;
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

    g_graveyard = new std::vector<std::unique_ptr<proxy_instance>>();
    write_lua_script();

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

    g_world = nullptr;
    ::fuzz::set_current(nullptr, 0);
    return 0;
}
