// Fuzz target: server_instance (socketley/runtime/server/server_instance.{h,cpp})
// driven as a *sequence of lifecycle and connection operations* against a real
// io_uring event_loop.
//
// The reasoning for this shape of target, and the four invariants it checks, are
// in test/fuzz/fuzz_runtime_ops.h.  What follows is what is specific to the
// server.
//
// ─── WHAT IS REAL HERE AND WHAT IS NOT ──────────────────────────────────────
//
// Everything is real.  There is one process-wide event_loop with a real ring, a
// real server_instance bound to a real loopback port, and real client sockets
// opened by the harness.  Nothing is stubbed, because every defect this is for
// lives in the seam between the runtime and the kernel — a descriptor number
// reissued between a submission and its consumption cannot be reproduced against
// a fake ring, which is exactly why it survived so long.
//
// The loop is process-wide rather than per input for two reasons.  Building one
// costs three ring setups (two of them capability probes), a 16 MB provided-
// buffer group and an 8192-entry fixed-file table, which would be most of the
// budget; and, more usefully, reusing it turns the end-of-input quiescence check
// into something load-bearing.  Every input has to leave the loop owing nothing
// — no owner with a submission outstanding, no descriptor number with a count on
// it — and that is asserted, so inputs stay independent *because* the invariant
// holds rather than by hoping it does.
//
// ─── WHAT THE OPERATIONS REACH ──────────────────────────────────────────────
//
// start/stop/destroy in any order and any number of times, including a start on
// the same loop iteration as the stop before it, which is what `restart` does
// and is where the duplicated timer chains came from.  Clients that connect,
// send whole messages, send half a message, send an RST mid-write, send a FIN
// and stay open, or vanish while the server is mid-response.  HTTP over the
// async-file path and over the shared splice pipe.  WebSocket upgrades and
// frames.  Reentrant callbacks: a Lua-equivalent on_client_message that
// broadcasts, that answers the sender, or that disconnects the sender from
// inside the handler that is reading it.  Upstream targets pointed at a port
// nothing listens on, which is the reconnect-timer path.  And UDP, which is a
// different socket, a different completion and a different restart hazard.
//
// And cache requests: `server --cache` posts the client's command to the
// daemon's request_channel and answers when the reply comes back, so between
// the question and the answer there is a window in which the connection that
// asked can be closed, its descriptor reissued and its struct handed to the
// next client.  That is the exact shape of defect this target exists for, so
// the alphabet reaches it directly — see the OP_CACHE and PL_CACHE_* notes
// below, and the stub sink that stands in for a cache runtime.
//
// ─── WHAT IT DOES NOT COVER ─────────────────────────────────────────────────
//
// Lua (the C++ callbacks stand in for it), TLS, routing between runtimes,
// direct-descriptor accept, and anything that depends on a timer longer than
// the drain budget actually elapsing: the idle sweep is thirty seconds and the
// accept backoff a hundred milliseconds, so this target sees them armed and
// withdrawn but never fired.
//
// The cache behind a cache request is a stub and not a cache_instance, on
// purpose.  What is under test is the server's half — the cookie that has to
// survive the connection it names being reused, the cap, the deferred close —
// and a stub can be made to answer nothing, answer enormously, or reach back
// into the server from inside the request, none of which a real cache would do
// on demand.  That the stub can stand in at all is the property the change was
// for: the server holds no pointer to a cache and never did know what was on
// the other end.

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <memory>
#include <queue>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/time_types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include "fuzz_common.h"
#include "fuzz_runtime_ops.h"

#include "shared/loop/event_loop.h"
#include "shared/loop/event_loop_definitions.h"
#include "shared/util/logging.h"
#include "shared/ipc/request_channel.h"
#include "shared/runtime/runtime_instance.h"
#include "shared/runtime/runtime_manager.h"
#include "shared/loop/write_queue.h"

// Reaching inside the class, for the same reason and by the same means as
// fuzz_cache_ops: invariant 4 is about m_conn_pool, m_conn_retired, m_clients
// and m_conn_idx, all private, and the alternatives are a friend declaration or
// a test-only accessor — both of which change socketley/ to suit a test.  Every
// header server_instance.h needs is included above, so the macro is never in
// effect over libstdc++ or over sol2.  server_instance.cpp is compiled normally
// and linked in; member access affects neither layout nor mangling.
#define private public
#include "runtime/server/server_instance.h"
#undef private

namespace {

// ─────────────────────────── the alphabet of a program ──────────────────────

constexpr int    NPEERS    = 6;
constexpr size_t MAX_STEPS = 512;

// What a peer can put on the wire.  Small and fixed, for the same reason
// fuzz_cache_ops keys off a small table: the invariants are about *history*, so
// the same shapes have to be revisited over and over, and a decoded program has
// to be something a person can read back.  The lengths are chosen around the
// framing boundaries — under one read, exactly one read, more than one read, and
// past the 1 MB partial cap.
enum payload_id : uint8_t
{
    PL_EMPTY = 0,   // a write of nothing: legal, and it must not look like EOF
    PL_LINE,        // one whole message
    PL_FRAGMENT,    // no newline: accumulates in partial
    PL_TWO_LINES,
    PL_CRLF,
    PL_BIG_LINE,    // larger than one 16 KB read
    PL_HUGE,        // 256 KB with no newline at all
    PL_HTTP_ROOT,   // → index.html, the async-file path
    PL_HTTP_BLOB,   // → blob.bin, the splice path
    PL_HTTP_KEEPALIVE,
    PL_HTTP_TRAVERSAL,
    PL_HTTP_PARTIAL,   // half a request line, then nothing
    PL_WS_UPGRADE,
    PL_WS_TEXT,
    PL_WS_CLOSE,
    PL_WS_FRAGMENT,
    PL_RESP_PING,
    PL_AUTH_OK,
    PL_AUTH_BAD,
    // ── cache requests ──────────────────────────────────────────────────────
    // One command, two pipelined, and a burst larger than the per-connection
    // cap.  The burst is the one that matters: the cap is the only thing
    // between one socket and an unbounded queue, and what the server does at it
    // (close, rather than answer out of order) is a decision with a wire-
    // visible consequence.
    PL_CACHE_ONE,
    PL_CACHE_TWO,
    PL_CACHE_BURST,
    // "cache" with nothing after it, and a cache command glued to an ordinary
    // message: the prefix test is a starts_with on a hot path and both of these
    // sit on its edges.
    PL_CACHE_BARE,
    PL_CACHE_MIXED,
    PL_COUNT
};

struct payload
{
    const char* data;
    size_t      len;
    const char* name;
};

std::string* g_big_line    = nullptr;
std::string* g_huge        = nullptr;
std::string* g_cache_burst = nullptr;

const payload& payload_at(int i)
{
    static payload table[PL_COUNT];
    static bool built = false;
    if (!built)
    {
        // Built once, and out of storage that is never freed, so that no input
        // is charged with the allocations: libFuzzer runs a full LeakSanitizer
        // scan for every input whose malloc and free counts disagree.
        g_big_line = new std::string(20000, 'L');
        g_big_line->push_back('\n');
        g_huge     = new std::string(256 * 1024, 'H');

        // Past server_instance::MAX_CACHE_PENDING on its own, so one send is
        // enough to walk a connection into the cap without the harness having
        // to arrange a burst out of many steps.
        g_cache_burst = new std::string();
        g_cache_burst->reserve(5000 * 14);
        for (int i = 0; i < 5000; i++)
            g_cache_burst->append("cache get k\n");

        auto set = [](payload_id id, const char* d, size_t n, const char* nm) {
            table[id] = { d, n, nm };
        };
        set(PL_EMPTY,     "",                 0, "empty");
        set(PL_LINE,      "hello\n",          6, "line");
        set(PL_FRAGMENT,  "half-a-",          7, "fragment");
        set(PL_TWO_LINES, "one\ntwo\n",       8, "two-lines");
        set(PL_CRLF,      "\r\n\r\n",         4, "crlf");
        set(PL_BIG_LINE,  g_big_line->data(), g_big_line->size(), "big-line");
        set(PL_HUGE,      g_huge->data(),     g_huge->size(),     "huge-no-newline");

        static const char http_root[] =
            "GET / HTTP/1.1\r\nHost: f\r\nConnection: close\r\n\r\n";
        static const char http_blob[] =
            "GET /blob.bin HTTP/1.1\r\nHost: f\r\nConnection: close\r\n\r\n";
        static const char http_ka[] =
            "GET /index.html HTTP/1.1\r\nHost: f\r\nConnection: keep-alive\r\n\r\n";
        static const char http_trav[] =
            "GET /../../etc/passwd HTTP/1.1\r\nHost: f\r\n\r\n";
        static const char http_part[] = "GET /index.htm";
        set(PL_HTTP_ROOT,      http_root, sizeof(http_root) - 1, "http-root");
        set(PL_HTTP_BLOB,      http_blob, sizeof(http_blob) - 1, "http-blob");
        set(PL_HTTP_KEEPALIVE, http_ka,   sizeof(http_ka)   - 1, "http-keepalive");
        set(PL_HTTP_TRAVERSAL, http_trav, sizeof(http_trav) - 1, "http-traversal");
        set(PL_HTTP_PARTIAL,   http_part, sizeof(http_part) - 1, "http-partial");

        static const char ws_up[] =
            "GET /ws HTTP/1.1\r\nHost: f\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        // Masked client frames, which is the only kind a server may accept.
        static const unsigned char ws_text[]  = {0x81, 0x83, 0x01, 0x02, 0x03, 0x04,
                                                 'a' ^ 0x01, 'b' ^ 0x02, 'c' ^ 0x03};
        static const unsigned char ws_close[] = {0x88, 0x80, 0x00, 0x00, 0x00, 0x00};
        // First fragment of a text message, never continued.
        static const unsigned char ws_frag[]  = {0x01, 0x81, 0x00, 0x00, 0x00, 0x00, 'x'};
        set(PL_WS_UPGRADE,  ws_up, sizeof(ws_up) - 1, "ws-upgrade");
        set(PL_WS_TEXT,     reinterpret_cast<const char*>(ws_text),  sizeof(ws_text),  "ws-text");
        set(PL_WS_CLOSE,    reinterpret_cast<const char*>(ws_close), sizeof(ws_close), "ws-close");
        set(PL_WS_FRAGMENT, reinterpret_cast<const char*>(ws_frag),  sizeof(ws_frag),  "ws-fragment");

        static const char resp_ping[] = "*1\r\n$4\r\nPING\r\n";
        set(PL_RESP_PING, resp_ping, sizeof(resp_ping) - 1, "resp-ping");
        static const char auth_ok[]  = "AUTH fuzzpw\n";
        static const char auth_bad[] = "AUTH wrong\n";
        set(PL_AUTH_OK,  auth_ok,  sizeof(auth_ok)  - 1, "auth-ok");
        set(PL_AUTH_BAD, auth_bad, sizeof(auth_bad) - 1, "auth-bad");

        static const char cache_one[]   = "cache get k\n";
        static const char cache_two[]   = "cache set k v\ncache get k\n";
        static const char cache_bare[]  = "cache\ncache \n";
        static const char cache_mixed[] = "hello\ncache get k\nworld\n";
        set(PL_CACHE_ONE,   cache_one,   sizeof(cache_one)   - 1, "cache-one");
        set(PL_CACHE_TWO,   cache_two,   sizeof(cache_two)   - 1, "cache-two");
        set(PL_CACHE_BURST, g_cache_burst->data(), g_cache_burst->size(), "cache-burst");
        set(PL_CACHE_BARE,  cache_bare,  sizeof(cache_bare)  - 1, "cache-bare");
        set(PL_CACHE_MIXED, cache_mixed, sizeof(cache_mixed) - 1, "cache-mixed");
        built = true;
    }
    return table[i % PL_COUNT];
}

// ─────────────────────────── the program ────────────────────────────────────

enum op_code : uint8_t
{
    OP_START, OP_STOP, OP_DESTROY,
    OP_PUMP,
    OP_CONNECT, OP_SEND, OP_RECV, OP_FIN, OP_ABORT,
    OP_BROADCAST, OP_SEND_TO, OP_DISCONNECT,
    OP_PIPE, OP_UNPIPE,
    OP_GROUP,
    OP_CONFIG,
    OP_STATS,
    OP_UPSTREAM,
    // Move the cache the server is linked to: attach or detach the name, take
    // the stub sink out of the channel's table or put it back, and change what
    // it answers.  Each of those is a moment a request already in the queue has
    // to survive — the sink it was posted for can be gone by the time it is
    // drained, which is precisely why the lookup happens at drain time.
    OP_CACHE,
    OP_COUNT
};

struct step
{
    uint8_t op = 0, a = 0, b = 0, c = 0;
};

step   g_prog[MAX_STEPS];
size_t g_steps = 0;

// What the stub cache answers.  Named here because print_program() has to say
// it, and the two that matter are the last two: an empty answer is the one the
// server must not write a bare newline for, and "reach back into the server" is
// the request being served while the runtime that asked is torn down under it.
const char* sink_mode_name(int m)
{
    switch (m % 5)
    {
        case 0:  return "short-line";
        case 1:  return "no-trailing-newline";
        case 2:  return "64KB";
        case 3:  return "empty";
        default: return "reach-back-into-the-server";
    }
}

const char* cb_mode_name(int m)
{
    switch (m % 6)
    {
        case 0:  return "inert";
        case 1:  return "broadcast-on-message";
        case 2:  return "answer-the-sender";
        case 3:  return "disconnect-the-sender";
        case 4:  return "answer-then-disconnect";
        default: return "broadcast-on-disconnect";
    }
}

void print_program()
{
    std::fprintf(stderr,
        "\n--- decoded operation sequence (%zu steps) ---\n"
        "// Each line is one step against one server_instance on one event_loop.\n",
        g_steps);

    for (size_t i = 0; i < g_steps; i++)
    {
        const step& s = g_prog[i];
        std::fprintf(stderr, "  /* %4zu */ ", i);
        switch (s.op)
        {
            case OP_START:      std::fputs("rt.start(loop);\n", stderr); break;
            case OP_STOP:       std::fputs("rt.stop(loop);\n", stderr); break;
            case OP_DESTROY:    std::fputs("drain(rt); destroy rt; create a fresh one on a new port;\n", stderr); break;
            case OP_PUMP:       std::fprintf(stderr, "loop.poll_completions(%d) x%d;\n",
                                             s.b & 1, 1 + (s.a & 3)); break;
            case OP_CONNECT:    std::fprintf(stderr, "peer[%d].connect();\n", s.a % NPEERS); break;
            case OP_SEND:       std::fprintf(stderr, "peer[%d].send(%s);\n",
                                             s.a % NPEERS, payload_at(s.b).name); break;
            case OP_RECV:       std::fprintf(stderr, "peer[%d].recv();\n", s.a % NPEERS); break;
            case OP_FIN:        std::fprintf(stderr, "peer[%d].shutdown(SHUT_WR);\n", s.a % NPEERS); break;
            case OP_ABORT:      std::fprintf(stderr, "peer[%d].close();   // RST\n", s.a % NPEERS); break;
            case OP_BROADCAST:  std::fprintf(stderr, "rt.broadcast(%s);\n", payload_at(s.b).name); break;
            case OP_SEND_TO:    std::fprintf(stderr, "rt.send_to(client[%d], %s);\n",
                                             s.a, payload_at(s.b).name); break;
            case OP_DISCONNECT: std::fprintf(stderr, "rt.disconnect(client[%d]);\n", s.a); break;
            case OP_PIPE:       std::fprintf(stderr, "rt.pipe(client[%d], client[%d]);\n", s.a, s.b); break;
            case OP_UNPIPE:     std::fprintf(stderr, "rt.unpipe(client[%d]);\n", s.a); break;
            case OP_GROUP:      std::fprintf(stderr, "rt.group_%s(client[%d], \"g%d\");\n",
                                             (s.c % 3) == 0 ? "join" : (s.c % 3) == 1 ? "leave" : "send",
                                             s.a, s.b % 3); break;
            case OP_CONFIG:     std::fprintf(stderr, "config knob %d = %d   // %s\n",
                                             s.a % 8, s.b,
                                             (s.a % 8) == 5 ? cb_mode_name(s.b) : ""); break;
            case OP_STATS:      std::fputs("rt.publish_offthread_stats();\n", stderr); break;
            case OP_UPSTREAM:   std::fputs("rt.add_upstream_target(\"127.0.0.1:9\");  // nothing listens\n", stderr); break;
            case OP_CACHE:      std::fprintf(stderr, "cache: link=%s sink=%s answer=%s\n",
                                             (s.a & 1) ? "\"fuzz-cache\"" : "\"\"",
                                             (s.b & 1) ? "registered" : "withdrawn",
                                             sink_mode_name(s.c)); break;
            default:            std::fprintf(stderr, "/* op %u */\n", s.op); break;
        }
    }
    std::fputs("--- end of sequence ---\n", stderr);
}

// ─────────────────────────── process-wide state ─────────────────────────────

event_loop*        g_loop = nullptr;
fuzzrt::ring_watch g_watch;

// ─────────────────────────── the stub cache ─────────────────────────────────
//
// A request_sink and nothing else.  It stands where a cache_instance would, and
// the only reason it can is that the server does not know the difference: what
// crosses the boundary is a command and an answer, both of them bytes.
//
// The manager is real, because it owns the channel and because it is the thing
// that publishes who answers for a name — the same object the daemon uses, with
// an empty runtime map.
runtime_manager* g_mgr = nullptr;
constexpr const char* CACHE_NAME = "fuzz-cache";

int g_sink_mode = 0;

struct stub_cache : request_sink
{
    void serve_request(std::string_view payload, std::string& out) override;
};
stub_cache g_sink;

// Instances the loop would not stop owing anything.  They are kept rather than
// freed, exactly as runtime_manager keeps them, and retried on later inputs.
// Reachable from here, so LeakSanitizer does not count them as lost — a stuck
// instance is reported as the finding it is, not as a leak in the harness.
std::vector<std::unique_ptr<server_instance>>* g_graveyard = nullptr;

// The directory the HTTP paths are served out of.  One small .html to reach the
// async-file read and one larger non-HTML file to reach the splice pipe, since
// serve_http() picks between them on the extension.
std::string* g_http_dir = nullptr;

int g_cb_mode = 0;   // what the C++ callbacks do; see cb_mode_name()

struct world;
world* g_world = nullptr;

// ─────────────────────────────── the world ──────────────────────────────────

struct peer_sock
{
    int  fd{-1};
    bool fin_sent{false};
};

struct world
{
    std::unique_ptr<server_instance> rt;
    uint16_t  port{0};
    bool      udp{false};
    bool      tick{false};
    peer_sock peers[NPEERS];
    // Whether any instance this input started armed a tick timer.  A tick
    // handler is a separate io_handler that frees itself from inside its own
    // completion, so it is not covered by the instance's owner count and has to
    // be waited for on its own.
    bool      tick_used{false};
};

uint16_t next_port()
{
    // Deliberately below the ephemeral range (32768 upwards here), so a
    // listener can never collide with a client socket the harness or the
    // runtime opened, and rotated so a port left in an odd state by one input
    // does not decide the next one.
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

// ─────────────────────────── the C++ callbacks ──────────────────────────────
//
// These stand in for Lua.  Their point is reentrancy: every one of them runs
// *inside* a completion handler, so what they do to the connection they were
// called about is exactly the ordering the runtime has to survive.  Mode 3 is
// the sharpest — the sender is disconnected from inside the read that delivered
// its message.

server_instance* live_rt()
{
    return g_world && g_world->rt && g_world->rt->get_state() == runtime_running
         ? g_world->rt.get() : nullptr;
}

void cb_on_client_message(int fd, std::string_view msg)
{
    auto* rt = live_rt();
    if (!rt)
        return;
    switch (g_cb_mode % 6)
    {
        case 0: break;
        case 1: rt->broadcast(msg); break;
        case 2: rt->send_to(fd, "ack"); break;
        case 3: rt->disconnect(fd); break;
        case 4: rt->send_to(fd, "bye"); rt->disconnect(fd); break;
        default: break;
    }
}

void cb_on_connect(int fd)
{
    auto* rt = live_rt();
    if (rt && (g_cb_mode % 6) == 2)
        rt->send_to(fd, "welcome");
}

void cb_on_disconnect(int fd)
{
    auto* rt = live_rt();
    // A write queued from the disconnect callback is the case close_conn()
    // re-examines what is in flight for: the callback runs before the struct is
    // released, and it can put a message back on the connection that is leaving.
    if (rt && (g_cb_mode % 6) == 5)
    {
        rt->send_to(fd, "gone");
        rt->broadcast("someone left");
    }
}

bool cb_on_auth(int)
{
    // Refuse one in four, which is the path that closes a connection between
    // the accept and the first read — before it ever had a read armed.
    static unsigned n = 0;
    return (++n & 3) != 0;
}

void cb_on_tick(double) {}

// ─────────────────────────── the stub cache, answering ──────────────────────

void stub_cache::serve_request(std::string_view payload, std::string& out)
{
    switch (g_sink_mode % 5)
    {
        case 0:
            out.append("ok\n");
            break;
        case 1:
            // No trailing newline: the server has to add one, and it has to
            // look at the last byte of a string it did not build to decide.
            out.append("no-newline");
            break;
        case 2:
            out.append(64 * 1024, 'R');
            out.push_back('\n');
            break;
        case 3:
            // Nothing at all.  An empty answer must produce no write — a bare
            // newline here would be a reply the client never asked for and
            // would shift every later answer by one line.
            break;
        default:
        {
            // The sharp one.  Serving a request reaches back into the runtime
            // that asked, from inside the channel's own completion: it
            // broadcasts, it disconnects a client, and one time in eight it
            // stops the server outright.  The reply is then delivered to an
            // origin that has been torn down since the request was taken off
            // the queue, which is the case drain() re-checks origin_live() for
            // and the reason it does so *after* the sink has run rather than
            // before.
            auto* rt = live_rt();
            if (rt)
            {
                rt->broadcast("from-the-cache\n");
                std::vector<int> fds = rt->clients();
                if (!fds.empty() && (payload.size() & 1))
                    rt->disconnect(fds[payload.size() % fds.size()]);
                static unsigned n = 0;
                if ((++n & 7) == 0)
                    rt->stop(*g_loop);
            }
            out.append("reentrant\n");
            break;
        }
    }
}

// ─────────────────────────── instance construction ──────────────────────────

std::unique_ptr<server_instance> make_instance(world& w)
{
    auto rt = std::make_unique<server_instance>("fuzz-server");
    rt->set_port(w.port);
    rt->set_udp(w.udp);
    rt->set_event_loop(g_loop);
    // The manager is how a runtime reaches the request channel, exactly as in
    // the daemon.  The cache link starts on so that an input that never issues
    // an OP_CACHE still exercises the request path.
    rt->set_runtime_manager(g_mgr);
    rt->set_cache_name(CACHE_NAME);
    rt->set_on_client_message(cb_on_client_message);
    rt->set_on_connect(cb_on_connect);
    rt->set_on_disconnect(cb_on_disconnect);
    rt->set_on_auth(cb_on_auth);
    // Not on a UDP instance.  config_refusal() refuses --master-pw in any mode
    // but master, and refuses --udp WITH master, so an instance carrying both
    // can never start -- which is why m_udp_fd was never once opened in 20,037
    // inputs while the header claimed UDP was covered.
    if (!w.udp)
        rt->set_master_pw("fuzzpw");
    if (g_http_dir)
        rt->set_http_dir(*g_http_dir);
    if (w.tick)
    {
        rt->set_tick_interval(10);
        rt->set_on_tick(cb_on_tick);
    }
    return rt;
}

// ─────────────────────────── the invariant checks ───────────────────────────

// Invariant 4, from outside the class.  invariants.h states it at the moment of
// the push and this states it at rest, which are different questions: a struct
// can be pushed safely and become unsafe afterwards if anything re-arms on it.
//
// `deep` walks the whole pool.  A pool is 512 structs and this runs after every
// step, so the per-step form only looks at the back of it — pool_release()
// pushes to the back, so that is where a struct that has just gone in is — and
// the whole thing is walked once at the end of the input.
void check_pool(server_instance* rt, bool deep)
{
    const size_t n = rt->m_conn_pool.size();
    const size_t from = deep ? 0 : (n > 4 ? n - 4 : 0);
    for (size_t i = from; i < n; i++)
    {
        auto* c = rt->m_conn_pool[i].get();
        RT_FINDING("pool-armed", !rt->conn_ops_pending(c),
                   "a connection struct is in the pool with an operation still armed on it "
                   "— the next accept is handed a struct the kernel is still writing into");
        RT_FINDING("pool-owner-set", c->read_req.owner == nullptr && c->write_req.owner == nullptr
                   && c->file_read_req.owner == nullptr && c->splice_in_req.owner == nullptr
                   && c->splice_out_req.owner == nullptr,
                   "a pooled connection still carries a live owner on one of its requests, so a "
                   "completion that arrives for it is dispatched into whichever client takes the "
                   "struct over rather than dropped");
        RT_FINDING("pool-fd-held", c->fd < 0,
                   "a pooled connection still names a descriptor");
        RT_FINDING("pool-file-held", c->file_fd < 0 && c->splice_file_fd < 0,
                   "a pooled connection still holds a file descriptor open — it is lost for "
                   "good unless the struct happens to be reused");
    }
}

void check_instance(server_instance* rt, bool deep)
{
    if (!rt)
        return;

    // The dispatch index and the owning map have to agree.  Every completion is
    // routed through m_conn_idx first, so an entry that points at a struct the
    // map no longer owns is a dispatch into freed storage.
    for (const auto& [fd, up] : rt->m_clients)
    {
        RT_CHECK(fd >= 0 && fd < server_instance::MAX_FDS,
                 "m_clients holds a descriptor outside the dispatch index");
        RT_CHECK(rt->m_conn_idx[fd] == up.get(),
                 "the dispatch index does not point at the connection m_clients holds for that fd");
        RT_CHECK(up->fd == fd,
                 "a connection's own fd disagrees with the key it is filed under");
    }

    // A retired struct is one the ring has not finished with.  reap_retired()
    // moves it to the pool the moment that stops being true, so one sitting here
    // with nothing armed is one nothing will ever come back for.
    for (const auto& up : rt->m_conn_retired)
        RT_FINDING("retired-idle", rt->conn_ops_pending(up.get()),
                   "a connection struct is on the retired list with nothing armed on it — "
                   "no completion will arrive to put it back, so it is held until the "
                   "instance is destroyed");

    check_pool(rt, deep);

    // Invariants 1 and 2 in the form this runtime takes, and only while it is
    // running.  m_accept_armed says "the accept request is occupied"; nothing
    // else stops a second submission being armed on it, and nothing lowers it
    // but the completion it is waiting for.  A bound listener with no accept
    // armed and no backoff pending is a socket nothing will ever be accepted on
    // again — the runtime is up, the port answers, and every connection to it
    // waits in the backlog for ever.
    //
    // Only while running.  Between a stop and the next start the flag is
    // deliberately left standing and the completion that would lower it is
    // dropped rather than dispatched, so the state is stale by design until
    // setup() puts it right.
    if (rt->get_state() == runtime_running && !rt->m_udp && rt->m_listen_fd >= 0)
    {
        RT_FINDING("listener-without-accept",
                   rt->m_accept_armed || rt->m_accept_backoff_armed,
                   "a running server has a bound listener with nothing armed to accept on "
                   "it — the port answers and every connection sits in the backlog for ever");
        RT_FINDING("accept-armed-without-inflight",
                   !rt->m_accept_armed || g_loop->owner_inflight(rt) > 0,
                   "the accept request is marked occupied although the ring owes this owner "
                   "nothing — the completion that would free it is never coming, so no accept "
                   "chain can ever be armed on this request again");
    }

    // The same question of the one ear a UDP server has, which the clause above
    // excludes because it is a different socket and a different completion.  A
    // refused recvmsg re-arms from on_loop_turn() and not from a timer, so what
    // must be true is that one of the two is standing.
    if (rt->get_state() == runtime_running && rt->m_udp && rt->m_udp_fd >= 0)
    {
        RT_FINDING("udp-socket-without-read",
                   rt->m_udp_recv_armed || rt->m_udp_recv_rearm_due,
                   "a running UDP server has a bound socket with no read armed on it and "
                   "nothing owed that would arm one — the port answers, `ps` counts it, and "
                   "every datagram sent to it is dropped for the life of the runtime");
    }

    // A cache request is owed a reply and the reply is what lowers the count,
    // so a connection carrying one has something that will wake it.  A pooled
    // struct must not: the count goes into the pool with the struct, and the
    // next client to take it would inherit a backlog it never created and be
    // closed at the cap for somebody else's traffic.  reset() clears it, so
    // this is a check that reset() is actually reached.
    for (const auto& up : rt->m_conn_pool)
        RT_FINDING("pool-cache-pending", up->cache_pending == 0,
                   "a connection struct is in the pool still counting cache requests it "
                   "was never answered for — the next client to take it inherits the "
                   "backlog and is closed at the cap for traffic it never sent");

    if (deep)
    {
        // Nothing may be in two places at once.  The pool hands its structs to
        // the next accept, so one that is also indexed is one two connections
        // are about to share.
        for (const auto& up : rt->m_conn_pool)
        {
            const auto* c = up.get();
            for (const auto& [fd, owned] : rt->m_clients)
                RT_CHECK(owned.get() != c, "a struct is in the pool and in m_clients at once");
            for (const auto& r : rt->m_conn_retired)
                RT_CHECK(r.get() != c, "a struct is in the pool and on the retired list at once");
        }
    }
}

// ─────────────────────────── peer socket operations ─────────────────────────

void peer_connect(world& w, int idx)
{
    peer_sock& p = w.peers[idx];
    if (p.fd >= 0)
        return;

    const int type = (w.udp ? SOCK_DGRAM : SOCK_STREAM) | SOCK_NONBLOCK;
    int fd = ::socket(AF_INET, type, 0);
    if (fd < 0)
        return;

    // Invariant 3.  The kernel has just chosen this number; if the ring still
    // names it, an SQE is about to resolve onto this socket.
    g_watch.fresh_fd(fd, "harness socket()");

    fuzzrt::set_abortive(fd);
    if (!w.udp)
    {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(w.port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0
        && errno != EINPROGRESS)
    {
        ::close(fd);
        return;
    }
    p.fd = fd;
    p.fin_sent = false;
}

void peer_close(world& w, int idx)
{
    peer_sock& p = w.peers[idx];
    if (p.fd < 0)
        return;
    ::close(p.fd);   // SO_LINGER{1,0}: an RST, and no TIME_WAIT
    p.fd = -1;
    p.fin_sent = false;
}

void peer_send(world& w, int idx, int pl)
{
    peer_sock& p = w.peers[idx];
    if (p.fd < 0)
        return;
    const payload& pay = payload_at(pl);
    // A short write on a non-blocking socket is ordinary and the remainder is
    // deliberately dropped: what the server has to survive is a message that
    // stops halfway, and that is what a short write produces.
    ssize_t n = ::send(p.fd, pay.data, pay.len, MSG_NOSIGNAL | MSG_DONTWAIT);
    if (n < 0 && (errno == EPIPE || errno == ECONNRESET))
        peer_close(w, idx);
}

void peer_recv(world& w, int idx)
{
    peer_sock& p = w.peers[idx];
    if (p.fd < 0)
        return;
    static char sink[16384];
    for (int i = 0; i < 4; i++)
    {
        ssize_t n = ::recv(p.fd, sink, sizeof(sink), MSG_DONTWAIT);
        if (n <= 0)
            break;
    }
}

void peer_fin(world& w, int idx)
{
    peer_sock& p = w.peers[idx];
    if (p.fd < 0 || p.fin_sent)
        return;
    ::shutdown(p.fd, SHUT_WR);
    p.fin_sent = true;
}

// A descriptor the runtime is currently serving, chosen out of the ones it says
// it has.  Deliberately also reachable with an index that no longer resolves —
// the Lua-facing entry points take a raw fd and have to survive being handed a
// stale one, which is how a closed client's number came to be reused.
int client_fd(world& w, uint8_t sel)
{
    if (!w.rt)
        return -1;
    std::vector<int> fds = w.rt->clients();
    if (fds.empty())
        return static_cast<int>(sel) % 64;   // a number nobody is serving
    return fds[sel % fds.size()];
}

// ─────────────────────────── lifecycle operations ───────────────────────────

void do_start(world& w)
{
    if (!w.rt)
        return;
    const runtime_state st = w.rt->get_state();
    if (st != runtime_created && st != runtime_stopped)
        return;

    w.rt->start(*g_loop);

    // A tick handler is a self-deleting io_handler with a timer of its own, and
    // a start() makes a new one whether or not the previous one has died yet.
    // Nothing here holds a pointer to it, so the only way an input can be sure
    // it is gone is to outlast its period — see drain_ticks().
    if (w.tick && w.rt->get_state() == runtime_running)
        w.tick_used = true;
}

void do_stop(world& w)
{
    if (w.rt && w.rt->get_state() == runtime_running)
        w.rt->stop(*g_loop);
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

    const bool drained = g_watch.drain_owner(w.rt.get(), w.tick ? 60 : 30);
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

    check_instance(w.rt.get(), true);
    w.rt.reset();
    for (int i = 0; i < 4; i++)
        g_loop->poll_completions(0);
}

// A tick handler frees itself from inside its own completion and nothing here
// holds a pointer to it, so the only way to be sure it is gone is to keep
// pumping until its period has certainly elapsed.  The period is pinned at the
// 10 ms floor by make_instance(), so this budget is four times over.
//
// It has to be waited for rather than left running.  The handler is unreachable
// from the moment stop() nulls m_tick, so an input that returns with one still
// counting down has leaked it, and LeakSanitizer would report that against
// whichever input happens to run next.
void drain_ticks(world& w)
{
    if (!w.tick_used)
        return;
    for (int ms = 0; ms < 40; ms++)
        g_loop->poll_completions(1);
    w.tick_used = false;
}

// Instances an earlier input could not free.  Retried here rather than dropped,
// because an operation that reports late still reports, and the difference
// between "late" and "never" is the whole finding.
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

// ─────────────────────────────── the interpreter ────────────────────────────

void run_step(world& w, const step& s)
{
    const int pidx = s.a % NPEERS;

    switch (s.op)
    {
        case OP_START:
            do_start(w);
            break;

        case OP_STOP:
            do_stop(w);
            break;

        case OP_DESTROY:
            retire_instance(w, "OP_DESTROY");
            drain_ticks(w);
            for (auto& p : w.peers)
                if (p.fd >= 0) { ::close(p.fd); p.fd = -1; }
            w.port = next_port();
            w.udp  = (s.b & 1) != 0;
            w.tick = (s.c & 1) != 0;
            w.rt   = make_instance(w);
            break;

        case OP_PUMP:
        {
            const int passes = 1 + (s.a & 3);
            for (int i = 0; i < passes; i++)
                g_loop->poll_completions(s.b & 1);
            break;
        }

        case OP_CONNECT:  peer_connect(w, pidx); break;
        case OP_SEND:     peer_send(w, pidx, s.b); break;
        case OP_RECV:     peer_recv(w, pidx); break;
        case OP_FIN:      peer_fin(w, pidx); break;
        case OP_ABORT:    peer_close(w, pidx); break;

        case OP_BROADCAST:
            if (w.rt)
            {
                const payload& p = payload_at(s.b);
                w.rt->broadcast(std::string_view(p.data, p.len));
            }
            break;

        case OP_SEND_TO:
            if (w.rt)
            {
                const payload& p = payload_at(s.b);
                w.rt->send_to(client_fd(w, s.a), std::string_view(p.data, p.len));
            }
            break;

        case OP_DISCONNECT:
            if (w.rt)
                w.rt->disconnect(client_fd(w, s.a));
            break;

        case OP_PIPE:
            if (w.rt)
                w.rt->pipe(client_fd(w, s.a), client_fd(w, s.b));
            break;

        case OP_UNPIPE:
            if (w.rt)
                w.rt->unpipe(client_fd(w, s.a));
            break;

        case OP_GROUP:
            if (w.rt)
            {
                const char* names[3] = { "g0", "g1", "g2" };
                const char* g = names[s.b % 3];
                if ((s.c % 3) == 0)      w.rt->join_group(client_fd(w, s.a), g);
                else if ((s.c % 3) == 1) w.rt->leave_group(client_fd(w, s.a), g);
                else                     w.rt->group_send(g, "grp\n");
            }
            break;

        case OP_CONFIG:
            if (w.rt)
            {
                switch (s.a % 8)
                {
                    case 0: w.rt->set_max_connections(s.b % 5); break;
                    case 1: w.rt->set_idle_timeout(s.b & 1); break;
                    case 2: w.rt->set_drain((s.b & 1) != 0); break;
                    case 3: w.rt->set_rate_limit((s.b & 1) ? 1.0 : 0.0); break;
                    case 4: w.rt->set_mode(static_cast<server_mode>(s.b % 4)); break;
                    case 5: g_cb_mode = s.b % 6; break;
                    case 6: w.rt->set_http_cache((s.b & 1) != 0); break;
                    default:
                        // Only between runs: setup() reads it, and a socket
                        // family cannot change under a bound listener.
                        if (w.rt->get_state() != runtime_running)
                        {
                            w.udp = (s.b & 1) != 0;
                            w.rt->set_udp(w.udp);
                        }
                        break;
                }
            }
            break;

        case OP_STATS:
            if (w.rt)
                w.rt->publish_offthread_stats();
            break;

        case OP_UPSTREAM:
            // Port 9 (discard) with nothing on it: the connect fails at once and
            // the runtime arms a reconnect timer, which is the request a stop has
            // to withdraw or the instance is held for up to thirty seconds.
            // The literal is a valid address, so this cannot refuse; the result
            // is consumed rather than cast away because (void) does not silence
            // nodiscard on this toolchain.
            if (w.rt && w.rt->get_state() != runtime_running)
                if (!w.rt->add_upstream_target("127.0.0.1:9")) {}
            break;

        case OP_CACHE:
            if (w.rt)
                w.rt->set_cache_name((s.a & 1) ? CACHE_NAME : "");
            // Withdrawing the sink is what the manager does when the cache is
            // stopped or removed, and it is legal at any moment — including
            // with requests already queued against the name.  Those must be
            // answered "no such target", not served through a pointer that has
            // been taken out of the table.
            if (s.b & 1)
            {
                g_mgr->requests().register_sink(CACHE_NAME, &g_sink);
            }
            else
            {
                g_mgr->requests().drop_sink(&g_sink);
            }
            g_sink_mode = s.c % 5;
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

    check_instance(w.rt.get(), false);
}

// ──────────────────────────── one-time setup ────────────────────────────────

void build_http_dir()
{
    char dir[128];
    std::snprintf(dir, sizeof(dir), "/dev/shm/socketley-fuzz-http-%d", static_cast<int>(::getpid()));
    if (::mkdir(dir, 0700) != 0 && errno != EEXIST)
        return;

    auto write_file = [&](const char* name, const std::string& body) {
        char path[256];
        std::snprintf(path, sizeof(path), "%s/%s", dir, name);
        int fd = ::open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0)
            return;
        if (::write(fd, body.data(), body.size()) < 0) {}
        ::close(fd);
    };

    // .html goes down the malloc + async-read path; anything else goes down the
    // splice pipe, and serve_http() decides on the extension alone.
    write_file("index.html", "<html><body>fuzz</body></html>\n");
    write_file("blob.bin", std::string(256 * 1024, 'B'));

    g_http_dir = new std::string(dir);
}

void init_once()
{
    if (g_loop)
        return;

    // The runtimes log a line whenever a timer withdrawal does not reach the
    // ring and on a few other conditions this target deliberately provokes.
    // Those are checked here directly, so the text is noise.
    logger::g_level = log_error;

    // The runtimes are written for the daemon's process, and the daemon ignores
    // SIGPIPE at startup (daemon.cpp) — the drain path in server_instance::
    // teardown writes with write(2) rather than send(MSG_NOSIGNAL), so a peer
    // that has gone raises it.  A harness that did not do the same would kill
    // itself on a socket the program deliberately reset, and report it as a
    // finding in the runtime.
    signal(SIGPIPE, SIG_IGN);

    g_graveyard = new std::vector<std::unique_ptr<server_instance>>();
    build_http_dir();

    g_loop = new event_loop(2048);
    if (!g_loop->init())
    {
        std::fprintf(stderr,
            "fuzz_server_ops: event_loop::init() failed — there is no io_uring here, so this "
            "target cannot check anything it exists to check.\n");
        std::abort();
    }
    g_watch.loop = g_loop;

    // Never freed, like everything else here that survives an input: the
    // channel is an io_handler registered with the loop and the loop is
    // process-wide.  Reachable from this pointer, so LeakSanitizer does not
    // count it.
    g_mgr = new runtime_manager();
    g_mgr->requests().attach(*g_loop);
    g_mgr->requests().register_sink(CACHE_NAME, &g_sink);

    fuzzrt::skip_env() = "FUZZ_SERVER_SKIP";
    fuzzrt::print_program_hook() = print_program;
    fuzzrt::adopt_invariant_reports();
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    init_once();
    (void)payload_at(0);
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

    // Four bytes per operation, like fuzz_cache_ops.  A longer input only buys
    // more steps, and a step here costs syscalls, so the ceiling is on steps.
    if (size < 4)
        return 0;

    reap_graveyard();

    world w;
    g_world  = &w;
    w.port   = next_port();
    w.udp    = (data[0] & 0x80) != 0;
    w.tick   = (data[1] & 0x80) != 0;
    g_cb_mode = data[2] % 6;

    // The cache stub starts registered and in its plainest mode for every
    // input, so that replaying one input on its own reproduces what it did
    // inside a longer run.  OP_CACHE moves it from there.
    g_mgr->requests().register_sink(CACHE_NAME, &g_sink);
    g_sink_mode = data[3] % 5;

    w.rt     = make_instance(w);

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
    // here nothing may still be owed: not to the instance, not to any tick
    // handler it armed, and not against any descriptor number in the process.
    for (auto& p : w.peers)
        if (p.fd >= 0) { ::close(p.fd); p.fd = -1; }

    retire_instance(w, "end of input");
    drain_ticks(w);

    // The request channel must not be left carrying work.
    //
    // An entry that survives this input names an origin that has just been
    // destroyed, so the next input's drain would reach through a pointer into
    // freed storage — ASan would report it, but one input later and with the
    // program that caused it already gone.  Asserting it here catches it while
    // the sequence that produced it is still printable, and says which of the
    // two it was: a missed drop_origin, or a queue with no wakeup coming.
    for (int i = 0; i < 8 && g_mgr->requests().pending() > 0; i++)
        g_loop->poll_completions(1);
    RT_FINDING("channel-backlog", g_mgr->requests().pending() == 0,
               "the request channel is still carrying cross-runtime requests after every "
               "runtime this input created is gone — either no wakeup is coming for them "
               "or the origins they name have already been freed");

    // Only meaningful with nothing stuck: an instance in the graveyard is one
    // that was already reported, and the descriptors it is holding are the same
    // finding said twice.
    if (g_graveyard->empty())
        g_watch.sweep_descriptors("end of input");

    g_world = nullptr;
    ::fuzz::set_current(nullptr, 0);
    return 0;
}
