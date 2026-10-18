// Fuzz target: client_instance (socketley/runtime/client/client_instance.{h,cpp})
// driven as a *sequence of lifecycle and connection operations* against a real
// io_uring event_loop.
//
// The reasoning for this shape of target, and the four invariants it checks, are
// in test/fuzz/fuzz_runtime_ops.h.  What follows is what is specific to the
// client.
//
// ─── WHY THE CLIENT IS THE SHARPEST CASE OF ALL OF THEM ─────────────────────
//
// This runtime has exactly one read request and one write request, and it reuses
// both across every reconnect it ever makes.  A server has a struct per
// connection and can tell two of them apart by address; the client cannot.  Nor
// can it tell them apart by descriptor: it closes a socket and dials again in
// the same breath, and the kernel hands the number straight back — so the new
// socket is the same address, the same fd and the same owner as the old one.
// The only thing separating them is m_conn_generation, and everything this
// target is looking for is a path that forgets to consult it:
//
//   * a read completion for the socket before last, appended to the current
//     conversation, because the descriptor number was reissued;
//   * a read armed while the previous one is still in the ring, giving the
//     kernel two writers into m_conn.read_buf;
//   * the reconnect timer — which hangs off no descriptor, so neither a close
//     nor a cancel reaches it — left counting down thirty seconds past a stop,
//     with the ring still owing this owner a completion the whole time and the
//     instance unfreeable until it lands.
//
// So the operations here are almost all about *losing* the connection: the peer
// resets it, the peer half-closes it, the peer stops listening so the next dial
// is refused, the runtime is stopped mid-write, started again immediately, and
// destroyed while a reconnect is pending.
//
// ─── WHAT IT DOES NOT COVER ─────────────────────────────────────────────────
//
// Lua (the C++ callbacks stand in for it), TLS, UDP — the client's datagram path
// is a handful of lines with no framing state and the server target already
// exercises the UDP side of the loop — and any reconnect that actually elapses:
// the backoff floor is one second with jitter, so this target sees the timer
// armed, withdrawn and cancelled, but never fired.

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <cstring>
#include <memory>
#include <queue>
#include <string>
#include <string_view>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/time_types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>

#include "fuzz_common.h"
#include "fuzz_runtime_ops.h"

#include "shared/loop/event_loop.h"
#include "shared/loop/event_loop_definitions.h"
#include "shared/util/logging.h"
#include "shared/runtime/runtime_instance.h"
#include "shared/loop/write_queue.h"

// Reaching inside the class, exactly as fuzz_cache_ops and fuzz_server_ops do
// and for the same reason: the per-connection half of invariant 2 is about
// m_conn.read_pending, m_conn.write_pending and m_reconnect_pending, all
// private, and the alternatives are a friend declaration or a test-only
// accessor — both of which change socketley/ to suit a test.  Every header
// client_instance.h needs is included above, so the macro is never in effect
// over libstdc++ or over sol2.
#define private public
#include "runtime/client/client_instance.h"
#undef private

namespace {

constexpr int    NPEERS    = 4;
constexpr size_t MAX_STEPS = 512;

// ─────────────────────────── the alphabet of a program ──────────────────────

enum payload_id : uint8_t
{
    PL_EMPTY = 0,
    PL_LINE,
    PL_FRAGMENT,      // no newline: accumulates in m_conn.partial
    PL_TWO_LINES,
    PL_CRLF_ONLY,
    PL_BIG_LINE,      // larger than the 4 KB read buffer, so several reads
    PL_HUGE,          // 2 MB with no newline: past MAX_PARTIAL_SIZE
    PL_BINARY,
    PL_COUNT
};

struct payload
{
    const char* data;
    size_t      len;
    const char* name;
};

// The two long payloads.  Namespace-scope pointers, not locals inside
// payload_at(): the table below holds only data() of each, so a pointer to the
// std::string object itself has to stay somewhere LeakSanitizer can see, or the
// 32-byte header is reported as leaked while its buffer is not.
std::string* g_big_line = nullptr;
std::string* g_huge     = nullptr;

const payload& payload_at(int i)
{
    static payload table[PL_COUNT];
    static bool built = false;
    if (!built)
    {
        // Never freed, on purpose: libFuzzer runs a full LeakSanitizer scan for
        // every input whose malloc and free counts disagree, so a table built
        // lazily inside an input would pay for that scan over and over.
        g_big_line = new std::string(9000, 'L');
        g_big_line->push_back('\n');
        g_huge = new std::string(2 * 1024 * 1024, 'H');
        std::string* big  = g_big_line;
        std::string* huge = g_huge;

        table[PL_EMPTY]     = { "",            0, "empty" };
        table[PL_LINE]      = { "hello\n",     6, "line" };
        table[PL_FRAGMENT]  = { "half-a-",     7, "fragment" };
        table[PL_TWO_LINES] = { "one\ntwo\n",  8, "two-lines" };
        table[PL_CRLF_ONLY] = { "\r\n\r\n",    4, "crlf-only" };
        table[PL_BIG_LINE]  = { big->data(),  big->size(),  "big-line" };
        table[PL_HUGE]      = { huge->data(), huge->size(), "huge-no-newline" };
        static const unsigned char bin[] = {0x00, 0xFF, 0x0A, 0x00, 0x0D, 0x0A, 0x80};
        table[PL_BINARY]    = { reinterpret_cast<const char*>(bin), sizeof(bin), "binary" };
        built = true;
    }
    return table[i % PL_COUNT];
}

// ─────────────────────────── the program ────────────────────────────────────

enum op_code : uint8_t
{
    OP_START, OP_STOP, OP_DESTROY,
    OP_PUMP,
    OP_LISTEN_UP, OP_LISTEN_DOWN,
    OP_ACCEPT, OP_PSEND, OP_PRECV, OP_PFIN, OP_PABORT,
    OP_SEND,
    OP_CONFIG,
    OP_STATS,
    OP_COUNT
};

struct step
{
    uint8_t op = 0, a = 0, b = 0, c = 0;
};

step   g_prog[MAX_STEPS];
size_t g_steps = 0;

void print_program()
{
    std::fprintf(stderr,
        "\n--- decoded operation sequence (%zu steps) ---\n"
        "// Each line is one step against one client_instance on one event_loop.\n"
        "// \"peer\" is the harness end: the listener the client dials and the\n"
        "// sockets it accepts there.\n", g_steps);

    for (size_t i = 0; i < g_steps; i++)
    {
        const step& s = g_prog[i];
        std::fprintf(stderr, "  /* %4zu */ ", i);
        switch (s.op)
        {
            case OP_START:       std::fputs("rt.start(loop);\n", stderr); break;
            case OP_STOP:        std::fputs("rt.stop(loop);\n", stderr); break;
            case OP_DESTROY:     std::fputs("drain(rt); destroy rt; create a fresh one on a new port;\n", stderr); break;
            case OP_PUMP:        std::fprintf(stderr, "loop.poll_completions(%d) x%d;\n",
                                              s.b & 1, 1 + (s.a & 3)); break;
            case OP_LISTEN_UP:   std::fputs("peer.listen();\n", stderr); break;
            case OP_LISTEN_DOWN: std::fputs("peer.close_listener();   // the next dial is refused\n", stderr); break;
            case OP_ACCEPT:      std::fprintf(stderr, "peer[%d] = accept();\n", s.a % NPEERS); break;
            case OP_PSEND:       std::fprintf(stderr, "peer[%d].send(%s);\n",
                                              s.a % NPEERS, payload_at(s.b).name); break;
            case OP_PRECV:       std::fprintf(stderr, "peer[%d].recv();\n", s.a % NPEERS); break;
            case OP_PFIN:        std::fprintf(stderr, "peer[%d].shutdown(SHUT_WR);\n", s.a % NPEERS); break;
            case OP_PABORT:      std::fprintf(stderr, "peer[%d].close();   // RST\n", s.a % NPEERS); break;
            case OP_SEND:        std::fprintf(stderr, "rt.lua_send(%s);\n", payload_at(s.b).name); break;
            case OP_CONFIG:      std::fprintf(stderr, "config knob %d = %d;\n", s.a % 5, s.b); break;
            case OP_STATS:       std::fputs("rt.publish_offthread_stats();\n", stderr); break;
            default:             std::fprintf(stderr, "/* op %u */\n", s.op); break;
        }
    }
    std::fputs("--- end of sequence ---\n", stderr);
}

// ─────────────────────────── process-wide state ─────────────────────────────
//
// One loop for the whole process rather than one per input.  Building one costs
// three ring setups and an 8192-entry fixed-file table, which would be most of
// the budget — and, more usefully, reusing it makes the end-of-input quiescence
// check load-bearing: every input has to leave the loop owing nothing, so inputs
// stay independent *because* the invariant holds rather than by hoping it does.

event_loop*        g_loop = nullptr;
fuzzrt::ring_watch g_watch;

std::vector<std::unique_ptr<client_instance>>* g_graveyard = nullptr;

struct world;
world* g_world = nullptr;
int    g_cb_mode = 0;

// ─────────────────────────────── the world ──────────────────────────────────

struct world
{
    std::unique_ptr<client_instance> rt;
    uint16_t port{0};
    int      listen_fd{-1};
    int      peers[NPEERS]{-1, -1, -1, -1};
    bool     tick{false};
    bool     tick_used{false};
};

uint16_t next_port()
{
    // Below the ephemeral range, so the harness listener can never collide with
    // a socket the kernel handed out, and rotated so a port left in an odd state
    // by one input does not decide the next one.
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
// These stand in for Lua, and their point is reentrancy: each runs inside a
// completion handler, so what it does to the connection it was called about is
// exactly the ordering the runtime has to survive.  Sending from inside
// on_message is the one that matters here — it can arm a write on a socket the
// same handler is about to lose.

client_instance* live_rt()
{
    return g_world && g_world->rt && g_world->rt->get_state() == runtime_running
         ? g_world->rt.get() : nullptr;
}

void cb_on_message(std::string_view msg)
{
    auto* rt = live_rt();
    if (!rt)
        return;
    switch (g_cb_mode % 4)
    {
        case 0: break;
        case 1: rt->lua_send("ack"); break;
        case 2: rt->lua_send(msg); break;                    // echo it straight back
        default: rt->lua_send("a"); rt->lua_send("b"); break; // one of these queues
    }
}

void cb_on_connect(int)
{
    auto* rt = live_rt();
    if (rt && (g_cb_mode % 4) >= 2)
        rt->lua_send("hello");
}

void cb_on_disconnect(int)
{
    // Sending from the disconnect callback is a send on a socket that has just
    // been lost; the runtime has to refuse it rather than arm on fd -1.
    auto* rt = live_rt();
    if (rt && (g_cb_mode % 4) == 3)
        rt->lua_send("goodbye");
}

void cb_on_tick(double) {}

// ─────────────────────────── instance construction ──────────────────────────

std::unique_ptr<client_instance> make_instance(world& w)
{
    auto rt = std::make_unique<client_instance>("fuzz-client");
    char target[64];
    std::snprintf(target, sizeof(target), "127.0.0.1:%u", static_cast<unsigned>(w.port));
    rt->set_target(target);
    rt->set_port(w.port);
    rt->set_event_loop(g_loop);
    rt->set_on_message(cb_on_message);
    rt->set_on_connect(cb_on_connect);
    rt->set_on_disconnect(cb_on_disconnect);
    // Reconnect on by default: without it a dial that fails makes setup() report
    // failure, the state goes to `failed`, and the instance can never be started
    // again — which would end most programs after their first step.
    rt->set_reconnect(0);
    if (w.tick)
    {
        rt->set_tick_interval(10);
        rt->set_on_tick(cb_on_tick);
    }
    return rt;
}

// ─────────────────────────── the invariant checks ───────────────────────────

void check_instance(client_instance* rt)
{
    if (!rt)
        return;

    // A socket the runtime no longer believes in must not still be named.  Both
    // directions matter: a descriptor kept past the drop is one nothing will
    // ever close, and a connection with no descriptor is one that will arm on
    // fd -1.
    RT_CHECK(rt->m_connected || rt->m_conn->fd < 0,
             "the client is not connected but still holds a descriptor — nothing will "
             "close it, and the next dial overwrites the field");
    RT_CHECK(!rt->m_connected || rt->m_conn->fd >= 0,
             "the client believes it is connected with no descriptor to be connected on");

    // Every request this runtime owns is stamped with the socket it was armed
    // for.  A pending flag with no generation behind it would mean a completion
    // that cannot be attributed to any socket at all.
    if (rt->m_conn->read_pending)
        RT_CHECK(rt->m_conn->read_req.generation != 0,
                 "a read is armed on a request that was never stamped with a socket");
    if (rt->m_conn->write_pending)
        RT_CHECK(rt->m_conn->write_req.generation != 0,
                 "a write is armed on a request that was never stamped with a socket");

    if (rt->get_state() != runtime_running)
        return;

    // Invariants 1 and 2 in the form this runtime takes.  Each of the three
    // flags says "this request is occupied"; nothing else stops a second
    // submission being armed on it, and nothing lowers one but the completion it
    // is waiting for.  So while the runtime is running, a flag that is up with
    // nothing in the ring is a request that will never be free again: arm_read()
    // declines to arm a read it believes is already in flight, and the client
    // stays connected and deaf for the rest of the process.
    //
    // Only while running.  Between a stop and the next start the flags are
    // deliberately left standing — the request really is occupied until its
    // completion lands — and after the stop the loop drops those completions
    // rather than dispatching them, so nothing lowers the flags until the next
    // setup() does.  That is the state this check would otherwise report on
    // every input, and it is why the check is anchored to `running`.
    if (rt->m_conn->read_pending || rt->m_conn->write_pending || rt->m_reconnect_pending)
    {
        const uint32_t owed = g_loop->owner_inflight(rt);
        if (owed == 0)
        {
            fuzzrt::set_detail("running, with owner_inflight() at zero: read_pending=%d "
                               "write_pending=%d reconnect_pending=%d fd=%d connected=%d",
                               static_cast<int>(rt->m_conn->read_pending),
                               static_cast<int>(rt->m_conn->write_pending),
                               static_cast<int>(rt->m_reconnect_pending),
                               rt->m_conn->fd, static_cast<int>(rt->m_connected));
            RT_FINDING("pending-without-inflight", false,
                       "a running client has a request marked occupied although the ring owes "
                       "it nothing — the completion that would free it is never coming, so "
                       "that request can never be armed again");
            fuzzrt::g_detail[0] = 0;
        }
    }

    // Reachability, from invariants.h, in this runtime's form: a client that
    // believes it is connected and is allowed to read must have something that
    // will wake it.  There is no poll loop and no timer here — every step
    // happens inside a completion handler — so a connected client with nothing
    // in the ring is one nobody will ever come back to.
    if (rt->m_connected && rt->m_conn->fd >= 0 && !rt->m_conn->closing
        && rt->get_mode() != client_mode_out)
    {
        RT_FINDING("connected-but-unreachable", g_loop->owner_inflight(rt) > 0,
                   "the client is connected and reading, and the ring owes it nothing — "
                   "nothing will ever wake it again, so it sits on an open socket deaf "
                   "until the runtime stops");
    }
}

void check_after_drain(client_instance* rt)
{
    if (!rt)
        return;
    RT_FINDING("fd-held-after-drain", rt->m_conn->fd < 0,
               "the client still holds a socket after it stopped and drained");
}

// ─────────────────────────── peer socket operations ─────────────────────────

void listen_up(world& w)
{
    if (w.listen_fd >= 0)
        return;
    int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return;
    g_watch.fresh_fd(fd, "harness listener socket()");

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(w.port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0 ||
        ::listen(fd, 16) < 0)
    {
        ::close(fd);
        return;
    }
    w.listen_fd = fd;
}

void listen_down(world& w)
{
    if (w.listen_fd < 0)
        return;
    ::close(w.listen_fd);
    w.listen_fd = -1;
}

void peer_accept(world& w, int idx)
{
    if (w.listen_fd < 0 || w.peers[idx] >= 0)
        return;
    int fd = ::accept4(w.listen_fd, nullptr, nullptr, SOCK_NONBLOCK);
    if (fd < 0)
        return;

    // Invariant 3.  The kernel has just chosen this number; if the ring still
    // names it, an SQE is about to resolve onto this socket instead of the one
    // it was submitted for.
    g_watch.fresh_fd(fd, "harness accept4()");

    fuzzrt::set_abortive(fd);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    w.peers[idx] = fd;
}

void peer_close(world& w, int idx)
{
    if (w.peers[idx] < 0)
        return;
    ::close(w.peers[idx]);   // SO_LINGER{1,0}: an RST, and no TIME_WAIT
    w.peers[idx] = -1;
}

void peer_send(world& w, int idx, int pl)
{
    if (w.peers[idx] < 0)
        return;
    const payload& p = payload_at(pl);
    // A short write is ordinary and the remainder is deliberately dropped: what
    // the client has to survive is a message that stops halfway.
    ssize_t n = ::send(w.peers[idx], p.data, p.len, MSG_NOSIGNAL | MSG_DONTWAIT);
    if (n < 0 && (errno == EPIPE || errno == ECONNRESET))
        peer_close(w, idx);
}

void peer_recv(world& w, int idx)
{
    if (w.peers[idx] < 0)
        return;
    static char sink[16384];
    for (int i = 0; i < 4; i++)
    {
        ssize_t n = ::recv(w.peers[idx], sink, sizeof(sink), MSG_DONTWAIT);
        if (n <= 0)
            break;
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
    w.rt->start(*g_loop);
    if (w.tick && w.rt->get_state() == runtime_running)
        w.tick_used = true;
}

void do_stop(world& w)
{
    if (w.rt && w.rt->get_state() == runtime_running)
        w.rt->stop(*g_loop);
}

// See drain_ticks() in fuzz_server_ops.cpp: a tick handler frees itself from
// inside its own completion and nothing here holds a pointer to it, so the only
// way to be sure it is gone is to outlast its period, which make_instance()
// pins at the 10 ms floor.
void drain_ticks(world& w)
{
    if (!w.tick_used)
        return;
    for (int ms = 0; ms < 40; ms++)
        g_loop->poll_completions(1);
    w.tick_used = false;
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

    // The reconnect timer is the whole reason this budget exists.  It hangs off
    // no descriptor, so nothing a stop closes can reach it, and its backoff
    // floor is a second — so if teardown's withdrawal did not land, this will
    // not drain, and that is the finding rather than something to wait out.
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

    check_after_drain(w.rt.get());
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

// ─────────────────────────────── the interpreter ────────────────────────────

void run_step(world& w, const step& s)
{
    const int pidx = s.a % NPEERS;

    switch (s.op)
    {
        case OP_START: do_start(w); break;
        case OP_STOP:  do_stop(w);  break;

        case OP_DESTROY:
            retire_instance(w, "OP_DESTROY");
            drain_ticks(w);
            listen_down(w);
            for (int i = 0; i < NPEERS; i++)
                peer_close(w, i);
            w.port = next_port();
            w.tick = (s.c & 1) != 0;
            w.rt   = make_instance(w);
            if (s.b & 1)
                listen_up(w);
            break;

        case OP_PUMP:
        {
            const int passes = 1 + (s.a & 3);
            for (int i = 0; i < passes; i++)
                g_loop->poll_completions(s.b & 1);
            break;
        }

        case OP_LISTEN_UP:   listen_up(w); break;
        case OP_LISTEN_DOWN: listen_down(w); break;
        case OP_ACCEPT:      peer_accept(w, pidx); break;
        case OP_PSEND:       peer_send(w, pidx, s.b); break;
        case OP_PRECV:       peer_recv(w, pidx); break;
        case OP_PFIN:
            if (w.peers[pidx] >= 0)
                ::shutdown(w.peers[pidx], SHUT_WR);
            break;
        case OP_PABORT:      peer_close(w, pidx); break;

        case OP_SEND:
            if (w.rt)
            {
                const payload& p = payload_at(s.b);
                w.rt->lua_send(std::string_view(p.data, p.len));
            }
            break;

        case OP_CONFIG:
            if (w.rt)
            {
                switch (s.a % 5)
                {
                    case 0: w.rt->set_reconnect((s.b % 3) - 1); break;   // -1, 0, 1
                    case 1: w.rt->set_mode(static_cast<client_mode>(s.b % 3)); break;
                    case 2: g_cb_mode = s.b % 4; break;
                    case 3: w.rt->set_rate_limit((s.b & 1) ? 1.0 : 0.0); break;
                    default: w.rt->set_idle_timeout(s.b & 1); break;
                }
            }
            break;

        case OP_STATS:
            if (w.rt)
                w.rt->publish_offthread_stats();
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

    check_instance(w.rt.get());
}

// ──────────────────────────── one-time setup ────────────────────────────────

void init_once()
{
    if (g_loop)
        return;

    // The runtime logs a line whenever a timer withdrawal does not reach the
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

    g_graveyard = new std::vector<std::unique_ptr<client_instance>>();

    g_loop = new event_loop(2048);
    if (!g_loop->init())
    {
        std::fprintf(stderr,
            "fuzz_client_ops: event_loop::init() failed — there is no io_uring here, so this "
            "target cannot check anything it exists to check.\n");
        std::abort();
    }
    g_watch.loop = g_loop;

    fuzzrt::skip_env() = "FUZZ_CLIENT_SKIP";
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
    g_world   = &w;
    w.port    = next_port();
    w.tick    = (data[0] & 0x80) != 0;
    g_cb_mode = data[1] % 4;
    w.rt      = make_instance(w);
    if (data[2] & 1)
        listen_up(w);

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
    listen_down(w);
    for (int i = 0; i < NPEERS; i++)
        peer_close(w, i);

    retire_instance(w, "end of input");
    drain_ticks(w);

    // Only meaningful with nothing stuck: an instance in the graveyard is one
    // that was already reported, and the descriptors it is holding are the same
    // finding said twice.
    if (g_graveyard->empty())
        g_watch.sweep_descriptors("end of input");

    g_world = nullptr;
    ::fuzz::set_current(nullptr, 0);
    return 0;
}
