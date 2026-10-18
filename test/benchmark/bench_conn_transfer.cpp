// What the two cross-runtime transports cost, against the in-process relay
// they replace.
//
// ─── WHAT THIS MEASURES, AND WHAT IT DOES NOT ───────────────────────────────
//
// Three arrangements of the same work — N connections, R request/response
// exchanges on each — over loopback TCP with the same message size:
//
//   RELAY-IN-PROCESS   one process.  It reads the client's bytes, copies them
//                      the way a routed message is copied today — into the
//                      string the owning runtime is asked to write — and
//                      answers.  This is the shape server_instance takes when
//                      both runtimes are in the daemon, with the Lua and the
//                      write queue taken out so that what is left is the
//                      transport.
//
//   HANDOVER           two processes.  The middle accepts, sends the descriptor
//                      to the endpoint with SCM_RIGHTS, relinquishes, and is
//                      not in the path again.  The endpoint reads and writes
//                      the client's socket directly.
//
//   RELAY-OVER-UNIX    two processes.  The middle stays in the path and every
//                      byte crosses an AF_UNIX socket in each direction, tagged
//                      with the conn_ref it belongs to.
//
// ─── HOW IT IS TIMED, AND WHY THAT WAY ──────────────────────────────────────
//
// The CLIENT is timed, and the client is byte-for-byte the same code in all
// three.  The first version of this timed the endpoint, which is not the same
// work in the three arrangements — the handover's endpoint is a separate
// process, so its measurement swallowed the child's exit — and it made the
// handover look 1.6x worse than it is at 16 KB.
//
// R is swept, because the two mechanisms are paid at different rates.  The
// handover costs one sendmsg per CONNECTION and nothing afterwards; the relay
// costs two socket crossings per MESSAGE.  Comparing them at one value of R
// answers a question nobody asked.  The crossover is the answer.
//
// It does NOT measure the daemon.  No Lua, no write queue, no io_uring, no
// runtime lifecycle — deliberately, because those are identical in all three
// and would bury the difference.  test/benchmark/bench_route.sh measures the
// whole path for the denominator.
//
// ─── WHAT IT SAID, 2026-08-01 ───────────────────────────────────────────────
//
// Dev VM, 4 CPUs, 3.9 GB, loopback, 8000 exchanges per row, median of 5,
// machine load 2.4 falling to 1.0 over the run (another agent's fuzzer was on
// the box for the first third of it).  Per-exchange cost relative to the
// in-process relay:
//
//   msgs per connection      1       8      64    1024
//   handover              1.22x   1.02x   1.03x   1.00x
//   unix relay            1.34x   1.77x   1.90x   1.96x        (64 B)
//   unix relay            1.46x   1.82x   2.01x   2.37x        (1 KB / 16 KB)
//
// The handover is free from the second message onwards: process isolation at
// the cost of the in-process path.  It is 22-28% worse on a connection that
// carries exactly one message, where the sendmsg is the whole of the work.
// The relay costs roughly twice the in-process path once a connection carries
// traffic, and that is the number the split turns on — it is what every routed
// connection would pay if there were only one mechanism.
//
// Run-to-run spread was 1-50% depending on the row, worst on the 8-messages
// rows.  A ratio inside 10% here is not a result.  The 1.00-1.10x readings for
// the handover should be read as "no measurable difference", not as a win.
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include "shared/net/conn_identity.h"
#include "shared/net/conn_transfer.h"

namespace
{

using clock_type = std::chrono::steady_clock;

enum class mode { in_process, handover, relay };

bool write_all(int fd, const char* p, size_t n)
{
    while (n)
    {
        const ssize_t w = ::write(fd, p, n);
        if (w > 0) { p += w; n -= static_cast<size_t>(w); continue; }
        if (w < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

bool read_exact(int fd, char* p, size_t n)
{
    while (n)
    {
        const ssize_t r = ::read(fd, p, n);
        if (r > 0) { p += r; n -= static_cast<size_t>(r); continue; }
        if (r < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

// Without this every measurement is of Nagle's timer.  Set on both ends of
// every TCP socket in every arrangement, so it cannot advantage one.
void no_delay(int fd)
{
    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

// How many connections one row may open.  Not a tuning knob: this kernel keeps
// 16384 TIME_WAIT entries and a client that opens and closes more than that in
// a row runs out of ephemeral ports, at which point connect() fails, the client
// gives up, and the middle blocks in accept() for a connection that is never
// coming.  That is not a slow benchmark, it is a hung one — the first version
// of this file opened 20000 per row and sat for thirteen minutes using eight
// seconds of CPU.
constexpr int max_conns_per_row = 400;

struct listener
{
    int fd{-1};
    uint16_t port{0};

    listener()
    {
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in a{};
        a.sin_family      = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port        = 0;
        if (::bind(fd, reinterpret_cast<struct sockaddr*>(&a), sizeof(a)) != 0) { perror("bind"); exit(2); }
        if (::listen(fd, 512) != 0) { perror("listen"); exit(2); }

        // A run that loses a client must fail rather than hang.  Without this
        // the middle waits in accept() for ever and the whole harness looks
        // like a slow benchmark instead of a broken one.
        struct timeval tv{20, 0};
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        socklen_t l = sizeof(a);
        ::getsockname(fd, reinterpret_cast<struct sockaddr*>(&a), &l);
        port = ntohs(a.sin_port);
    }
    ~listener() { if (fd >= 0) ::close(fd); }
};

// TIME_WAIT sockets on this machine right now.  Read between rows: a row
// started on the previous row's debris measures the debris, and a row started
// near the kernel's limit measures a machine the harness broke itself.
int time_wait_count()
{
    FILE* f = ::popen("ss -tan state time-wait 2>/dev/null | wc -l", "r");
    if (!f) return -1;
    char buf[32] = {0};
    if (!fgets(buf, sizeof(buf), f)) { pclose(f); return -1; }
    pclose(f);
    return atoi(buf);
}

// ── The client.  Identical in all three arrangements; this is what is timed. ─

double client_main(uint16_t port, size_t msg_size, int conns, int rounds)
{
    std::vector<char> out(msg_size, 'x');
    std::vector<char> back(msg_size);

    const auto t0 = clock_type::now();
    for (int c = 0; c < conns; ++c)
    {
        const int s = ::socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a{};
        a.sin_family      = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port        = htons(port);
        if (::connect(s, reinterpret_cast<struct sockaddr*>(&a), sizeof(a)) != 0)
        {
            ::close(s);
            return -1;
        }
        no_delay(s);

        for (int i = 0; i < rounds; ++i)
        {
            if (!write_all(s, out.data(), msg_size)) { ::close(s); return -1; }
            if (!read_exact(s, back.data(), msg_size)) { ::close(s); return -1; }
        }
        ::close(s);
    }
    const auto t1 = clock_type::now();
    return std::chrono::duration<double>(t1 - t0).count();
}

// ── The endpoint process, for the two split arrangements ────────────────────

void endpoint_handover(int channel_fd, size_t msg_size, int conns, int rounds)
{
    std::vector<char> buf(msg_size);
    for (int c = 0; c < conns; ++c)
    {
        conn_transfer::handover h;
        int client_fd = -1;
        if (!conn_transfer::recv_handover(channel_fd, h, client_fd))
            return;
        no_delay(client_fd);

        size_t carried = std::min(h.backlog.size(), msg_size);
        if (carried) memcpy(buf.data(), h.backlog.data(), carried);

        for (int i = 0; i < rounds; ++i)
        {
            const size_t have = (i == 0) ? carried : 0;
            if (have < msg_size && !read_exact(client_fd, buf.data() + have, msg_size - have))
                break;
            // The same copy the in-process arrangement makes, so what is being
            // compared is where the bytes travel and not how often they are
            // duplicated once they arrive.
            const std::string owned(buf.data(), msg_size);
            if (!write_all(client_fd, owned.data(), owned.size())) break;
        }
        ::close(client_fd);
    }
}

void endpoint_relay(int channel_fd, int total_messages)
{
    std::string in;
    conn_transfer::relay_op op{};
    conn_ref ref{};
    std::string payload;
    bool fatal = false;
    char rb[65536];

    int done = 0;
    while (done < total_messages)
    {
        const ssize_t n = ::read(channel_fd, rb, sizeof(rb));
        if (n <= 0) return;
        in.append(rb, static_cast<size_t>(n));

        while (conn_transfer::take_relay_frame(in, op, ref, payload, fatal))
        {
            if (op != conn_transfer::relay_op::data) continue;
            const std::string out =
                conn_transfer::relay_frame(conn_transfer::relay_op::data, ref, payload);
            if (!write_all(channel_fd, out.data(), out.size())) return;
            ++done;
        }
        if (fatal) return;
    }
}

// ── The middle, per arrangement ─────────────────────────────────────────────

void middle_in_process(int client_fd, size_t msg_size, int rounds)
{
    std::vector<char> buf(msg_size);
    for (int i = 0; i < rounds; ++i)
    {
        if (!read_exact(client_fd, buf.data(), msg_size)) return;
        const std::string owned(buf.data(), msg_size);
        if (!write_all(client_fd, owned.data(), owned.size())) return;
    }
}

void middle_relay(int client_fd, int channel_fd, const conn_ref& ref,
                  size_t msg_size, int rounds)
{
    std::vector<char> buf(msg_size);
    std::string in;
    conn_transfer::relay_op op{};
    conn_ref got{};
    std::string payload;
    bool fatal = false;
    char rb[65536];

    for (int i = 0; i < rounds; ++i)
    {
        if (!read_exact(client_fd, buf.data(), msg_size)) return;

        const std::string out = conn_transfer::relay_frame(
            conn_transfer::relay_op::data, ref, std::string_view(buf.data(), msg_size));
        if (!write_all(channel_fd, out.data(), out.size())) return;

        for (;;)
        {
            if (conn_transfer::take_relay_frame(in, op, got, payload, fatal))
            {
                if (op != conn_transfer::relay_op::data) continue;
                if (!write_all(client_fd, payload.data(), payload.size())) return;
                break;
            }
            if (fatal) return;
            const ssize_t n = ::read(channel_fd, rb, sizeof(rb));
            if (n <= 0) return;
            in.append(rb, static_cast<size_t>(n));
        }
    }
}

// ── One run of one arrangement ──────────────────────────────────────────────

double run_once(mode m, size_t msg_size, int conns, int rounds)
{
    listener l;

    int chan[2] = {-1, -1};
    pid_t endpoint = -1;
    if (m != mode::in_process)
    {
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, chan) != 0) { perror("socketpair"); exit(2); }
        endpoint = ::fork();
        if (endpoint == 0)
        {
            ::close(chan[0]);
            ::close(l.fd);
            if (m == mode::handover) endpoint_handover(chan[1], msg_size, conns, rounds);
            else                     endpoint_relay(chan[1], conns * rounds);
            ::close(chan[1]);
            _exit(0);
        }
        ::close(chan[1]);
    }

    // The client reports its own elapsed time down a pipe.  It is the only
    // thing timed and it is the same code in all three arrangements.
    int result[2];
    if (::pipe(result) != 0) { perror("pipe"); exit(2); }

    const pid_t client = ::fork();
    if (client == 0)
    {
        ::close(result[0]);
        ::close(l.fd);
        if (chan[0] >= 0) ::close(chan[0]);
        const double s = client_main(l.port, msg_size, conns, rounds);
        if (::write(result[1], &s, sizeof(s)) != sizeof(s)) {}
        ::close(result[1]);
        _exit(0);
    }
    ::close(result[1]);

    bool lost_a_client = false;
    for (int c = 0; c < conns; ++c)
    {
        const int accepted = ::accept(l.fd, nullptr, nullptr);
        if (accepted < 0) { lost_a_client = true; break; }
        no_delay(accepted);

        const conn_ref ref{conn_owner_key("bench0"), static_cast<uint64_t>(c) + 1};

        switch (m)
        {
        case mode::in_process:
            middle_in_process(accepted, msg_size, rounds);
            ::close(accepted);
            break;

        case mode::handover:
        {
            conn_transfer::handover h;
            h.ref    = ref;
            h.origin = "middle";
            if (!conn_transfer::send_handover(chan[0], h, accepted))
            {
                fprintf(stderr, "bench: handover failed\n");
                exit(2);
            }
            // Nothing is armed on it — there is no ring here — so the sender
            // gives it up immediately and is out of the path.
            conn_transfer::relinquish(nullptr, accepted);
            break;
        }

        case mode::relay:
            middle_relay(accepted, chan[0], ref, msg_size, rounds);
            ::close(accepted);
            break;
        }
    }

    double seconds = -1;
    if (::read(result[0], &seconds, sizeof(seconds)) != sizeof(seconds))
        seconds = -1;
    ::close(result[0]);
    if (lost_a_client)
        seconds = -1;

    // The endpoint is waiting on a channel that is about to have no writer, and
    // the client on a socket the middle has stopped answering; closing first
    // is what turns both of those waits into an EOF.
    if (endpoint > 0) ::close(chan[0]);

    int st = 0;
    ::waitpid(client, &st, 0);
    if (endpoint > 0) ::waitpid(endpoint, &st, 0);

    return seconds;
}

double median(std::vector<double> v)
{
    if (v.empty()) return -1;
    for (const double d : v) if (d < 0) return -1;
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

double spread(std::vector<double> v)
{
    if (v.size() < 2) return 0;
    std::sort(v.begin(), v.end());
    const double med = v[v.size() / 2];
    return med > 0 ? (v.back() - v.front()) / med * 100.0 : 0;
}

}   // namespace

int main(int argc, char** argv)
{
    // Total exchanges is held constant across the R sweep, so every row does
    // the same amount of application work and only the connection count moves.
    const int total    = (argc > 1) ? atoi(argv[1]) : 20000;
    const int repeats  = (argc > 2) ? atoi(argv[2]) : 5;
    const size_t sizes[] = { 64, 1024, 16384 };
    const int rounds_per_conn[] = { 1, 8, 64, 1024 };

    printf("conn_transfer: three arrangements, %d exchanges per row, "
           "median of %d\n", total, repeats);
    printf("timed on the client, which is the same code in all three; "
           "TCP_NODELAY everywhere\n\n");

    for (const size_t sz : sizes)
    {
        printf("── %zu-byte messages ──────────────────────────────────────────\n", sz);
        printf("  %8s %8s | %11s %11s %11s | %s\n",
               "msgs/cxn", "cxns", "in-process", "handover", "unix-relay",
               "handover vs relay");

        for (const int r : rounds_per_conn)
        {
            const int conns = std::min(max_conns_per_row, std::max(1, total / r));

            // Between rows, not only at the start: the previous row's sockets
            // are still in TIME_WAIT and the next row's connect() has to find a
            // port.  Waiting is cheaper than reporting a number taken on a
            // machine the harness had exhausted.
            for (int waited = 0; waited < 120 && time_wait_count() > 4000; ++waited)
                ::sleep(1);

            // Discarded: the first run of any arrangement pays for page faults
            // and socket buffer growth, and whichever went first would
            // otherwise look worst.
            const int warm_c = std::min(conns, 32);
            const int warm_r = std::min(r, 64);
            run_once(mode::in_process, sz, warm_c, warm_r);
            run_once(mode::handover,   sz, warm_c, warm_r);
            run_once(mode::relay,      sz, warm_c, warm_r);

            std::vector<double> a, b, c;
            for (int i = 0; i < repeats; ++i)
            {
                // Interleaved, not batched: a machine that drifts over the run
                // drifts through all three instead of penalising the last.
                a.push_back(run_once(mode::in_process, sz, conns, r));
                b.push_back(run_once(mode::handover,   sz, conns, r));
                c.push_back(run_once(mode::relay,      sz, conns, r));
            }

            const double ma = median(a), mb = median(b), mc = median(c);
            if (ma < 0 || mb < 0 || mc < 0)
            {
                printf("  %8d %8d | FAILED\n", r, conns);
                continue;
            }

            const double n = static_cast<double>(conns) * r;
            printf("  %8d %8d | %8.2fus %8.2fus %8.2fus | handover %.2fx in-process, "
                   "relay %.2fx  (spread %.0f/%.0f/%.0f%%)\n",
                   r, conns,
                   ma / n * 1e6, mb / n * 1e6, mc / n * 1e6,
                   mb / ma, mc / ma,
                   spread(a), spread(b), spread(c));
        }
        printf("\n");
    }
    return 0;
}
