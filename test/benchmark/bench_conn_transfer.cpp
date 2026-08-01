// What the two cross-runtime transports cost, against the in-process relay
// they replace.
//
// ─── WHAT THIS MEASURES, AND WHAT IT DOES NOT ───────────────────────────────
//
// Three arrangements of the same ping-pong, over the same loopback TCP
// connection, with the same message size:
//
//   RELAY-IN-PROCESS   one process.  It reads the client's bytes, copies them
//                      the way a routed message is copied today — into a string
//                      the receiving runtime is handed, and out of one the
//                      owning runtime is asked to write — and answers.  This is
//                      the shape server_instance takes when both runtimes are
//                      in the daemon, with the Lua and the write queue taken
//                      out so that what is left is the transport.
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
// It does NOT measure the daemon.  There is no Lua here, no write queue, no
// io_uring, no runtime lifecycle — deliberately, because those are identical in
// all three arrangements and including them would bury the difference under
// something they share.  What comes out is the cost of the transport and
// nothing else, which is the only quantity the choice between them turns on.
//
// The handover's cost is paid once per connection and the relay's is paid per
// message, so the two are not comparable at one connection length: the ratio is
// reported at several, and the crossover is the answer.
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

#include "shared/conn_identity.h"
#include "shared/conn_transfer.h"

namespace
{

using clock_type = std::chrono::steady_clock;

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

void no_delay(int fd)
{
    // Without this every measurement is of Nagle's timer.  Set on both ends of
    // every TCP socket in every arrangement, so it cannot advantage one.
    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

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
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        if (::bind(fd, reinterpret_cast<struct sockaddr*>(&a), sizeof(a)) != 0) { perror("bind"); exit(2); }
        if (::listen(fd, 16) != 0) { perror("listen"); exit(2); }
        socklen_t l = sizeof(a);
        ::getsockname(fd, reinterpret_cast<struct sockaddr*>(&a), &l);
        port = ntohs(a.sin_port);
    }
    ~listener() { if (fd >= 0) ::close(fd); }
};

int dial(uint16_t port)
{
    const int s = ::socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    if (::connect(s, reinterpret_cast<struct sockaddr*>(&a), sizeof(a)) != 0) { perror("connect"); exit(2); }
    no_delay(s);
    return s;
}

// ── The three arrangements ──────────────────────────────────────────────────
//
// Each runs the endpoint's side of `rounds` echo exchanges on a connection it
// was given, and returns when they are done.  The client side is the same code
// for all three, so what differs is only how the endpoint reaches the socket.

// The in-process relay: the two copies a routed message pays today.  One into
// the buffer the receiving runtime is handed, one into the string the owning
// runtime is asked to write.
void endpoint_in_process(int client_fd, size_t msg_size, int rounds)
{
    std::vector<char> buf(msg_size);
    for (int i = 0; i < rounds; ++i)
    {
        if (!read_exact(client_fd, buf.data(), msg_size)) return;

        // deliver_routed hands the receiving runtime a view of the bytes; the
        // runtime answers through write_to_ref, which builds the string the
        // write queue will hold.  That string is the copy.
        std::string owned(buf.data(), msg_size);
        if (!write_all(client_fd, owned.data(), owned.size())) return;
    }
}

// Handover: the middle is gone from the path after one sendmsg.
void endpoint_handover(int channel_fd, size_t msg_size, int rounds)
{
    conn_transfer::handover h;
    int client_fd = -1;
    if (!conn_transfer::recv_handover(channel_fd, h, client_fd))
    {
        fprintf(stderr, "bench: endpoint did not receive the handover\n");
        _exit(2);
    }
    no_delay(client_fd);

    std::vector<char> buf(msg_size);
    size_t from_backlog = std::min(h.backlog.size(), msg_size);
    if (from_backlog)
        memcpy(buf.data(), h.backlog.data(), from_backlog);

    for (int i = 0; i < rounds; ++i)
    {
        size_t have = (i == 0) ? from_backlog : 0;
        if (have < msg_size && !read_exact(client_fd, buf.data() + have, msg_size - have))
            break;
        std::string owned(buf.data(), msg_size);
        if (!write_all(client_fd, owned.data(), owned.size())) break;
    }
    ::close(client_fd);
}

// Relay: every byte crosses AF_UNIX twice more than it would in one process.
void endpoint_relay(int channel_fd, size_t msg_size, int rounds)
{
    std::string in;
    conn_transfer::relay_op op{};
    conn_ref ref{};
    std::string payload;
    bool fatal = false;

    int done = 0;
    char rb[65536];
    while (done < rounds)
    {
        const ssize_t n = ::read(channel_fd, rb, sizeof(rb));
        if (n <= 0) break;
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
    (void)msg_size;
}

// The middle's side of the relay: client → frame → endpoint, and back.
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

        bool answered = false;
        while (!answered)
        {
            while (conn_transfer::take_relay_frame(in, op, got, payload, fatal))
            {
                if (op != conn_transfer::relay_op::data) continue;
                if (!write_all(client_fd, payload.data(), payload.size())) return;
                answered = true;
                break;
            }
            if (answered || fatal) break;
            const ssize_t n = ::read(channel_fd, rb, sizeof(rb));
            if (n <= 0) return;
            in.append(rb, static_cast<size_t>(n));
        }
    }
}

// ── The client, identical for all three ─────────────────────────────────────

double run_client(int fd, size_t msg_size, int rounds)
{
    std::vector<char> out(msg_size, 'x');
    std::vector<char> back(msg_size);

    const auto t0 = clock_type::now();
    for (int i = 0; i < rounds; ++i)
    {
        if (!write_all(fd, out.data(), msg_size)) return -1;
        if (!read_exact(fd, back.data(), msg_size)) return -1;
    }
    const auto t1 = clock_type::now();
    return std::chrono::duration<double>(t1 - t0).count();
}

struct sample { double seconds; };

double median(std::vector<double> v)
{
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

// ── Drivers ─────────────────────────────────────────────────────────────────

double once_in_process(size_t msg_size, int rounds)
{
    listener l;
    const pid_t child = ::fork();
    if (child == 0)
    {
        const int c = dial(l.port);
        run_client(c, msg_size, rounds);
        ::close(c);
        _exit(0);
    }
    const int accepted = ::accept(l.fd, nullptr, nullptr);
    no_delay(accepted);

    // Timed on the endpoint side for all three, so the client's own cost is
    // outside the measurement in every arrangement equally.
    const auto t0 = clock_type::now();
    endpoint_in_process(accepted, msg_size, rounds);
    const auto t1 = clock_type::now();

    ::close(accepted);
    int st = 0; ::waitpid(child, &st, 0);
    return std::chrono::duration<double>(t1 - t0).count();
}

double once_handover(size_t msg_size, int rounds)
{
    listener l;

    int chan[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, chan) != 0) { perror("socketpair"); exit(2); }

    const pid_t endpoint = ::fork();
    if (endpoint == 0)
    {
        ::close(chan[0]);
        ::close(l.fd);
        endpoint_handover(chan[1], msg_size, rounds);
        _exit(0);
    }
    ::close(chan[1]);

    const pid_t client = ::fork();
    if (client == 0)
    {
        ::close(chan[0]);
        ::close(l.fd);
        const int c = dial(l.port);
        run_client(c, msg_size, rounds);
        ::close(c);
        _exit(0);
    }

    const int accepted = ::accept(l.fd, nullptr, nullptr);
    no_delay(accepted);

    const auto t0 = clock_type::now();

    conn_transfer::handover h;
    h.ref    = conn_ref{conn_owner_key("bench0"), 1};
    h.origin = "middle";
    if (!conn_transfer::send_handover(chan[0], h, accepted))
    {
        fprintf(stderr, "bench: handover failed\n");
        exit(2);
    }
    // The middle is out of the path from here.  It stops writing at once and
    // gives the descriptor up; nothing is armed on it, so this closes now.
    conn_transfer::relinquish(nullptr, accepted);

    int st = 0;
    ::waitpid(endpoint, &st, 0);
    const auto t1 = clock_type::now();

    ::waitpid(client, &st, 0);
    ::close(chan[0]);
    return std::chrono::duration<double>(t1 - t0).count();
}

double once_relay(size_t msg_size, int rounds)
{
    listener l;

    int chan[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, chan) != 0) { perror("socketpair"); exit(2); }

    const pid_t endpoint = ::fork();
    if (endpoint == 0)
    {
        ::close(chan[0]);
        ::close(l.fd);
        endpoint_relay(chan[1], msg_size, rounds);
        _exit(0);
    }
    ::close(chan[1]);

    const pid_t client = ::fork();
    if (client == 0)
    {
        ::close(chan[0]);
        ::close(l.fd);
        const int c = dial(l.port);
        run_client(c, msg_size, rounds);
        ::close(c);
        _exit(0);
    }

    const int accepted = ::accept(l.fd, nullptr, nullptr);
    no_delay(accepted);

    const conn_ref ref{conn_owner_key("bench0"), 1};

    const auto t0 = clock_type::now();
    middle_relay(accepted, chan[0], ref, msg_size, rounds);
    const auto t1 = clock_type::now();

    ::close(accepted);
    int st = 0;
    ::waitpid(client, &st, 0);
    ::waitpid(endpoint, &st, 0);
    ::close(chan[0]);
    return std::chrono::duration<double>(t1 - t0).count();
}

void report(const char* name, size_t msg_size, int rounds, const std::vector<double>& runs)
{
    const double s = median(runs);
    if (s <= 0) { printf("  %-18s FAILED\n", name); return; }
    const double per_msg_us = (s / rounds) * 1e6;
    const double mbps = (static_cast<double>(msg_size) * rounds * 2.0) / s / (1024.0 * 1024.0);
    printf("  %-18s %9.2f us/round  %9.1f rounds/s  %8.1f MiB/s\n",
           name, per_msg_us, rounds / s, mbps);
}

}   // namespace

int main(int argc, char** argv)
{
    int rounds  = (argc > 1) ? atoi(argv[1]) : 20000;
    int repeats = (argc > 2) ? atoi(argv[2]) : 5;
    if (rounds < 100)  rounds = 100;
    if (repeats < 1)   repeats = 1;

    const size_t sizes[] = { 64, 1024, 16384 };

    printf("conn_transfer: three arrangements of the same ping-pong\n");
    printf("rounds=%d  repeats=%d (median reported)  TCP_NODELAY on every socket\n\n",
           rounds, repeats);

    for (const size_t sz : sizes)
    {
        printf("message size %zu bytes\n", sz);

        std::vector<double> a, b, c;
        // One warm-up of each, discarded: the first run of any of these pays
        // for page faults and socket buffer growth, and whichever went first
        // would otherwise look worst.
        once_in_process(sz, std::min(rounds, 2000));
        once_handover(sz, std::min(rounds, 2000));
        once_relay(sz, std::min(rounds, 2000));

        for (int i = 0; i < repeats; ++i)
        {
            // Interleaved rather than batched, so a machine that drifts over
            // the run drifts through all three instead of penalising the last.
            a.push_back(once_in_process(sz, rounds));
            b.push_back(once_handover(sz, rounds));
            c.push_back(once_relay(sz, rounds));
        }

        report("relay-in-process", sz, rounds, a);
        report("handover", sz, rounds, b);
        report("relay-over-unix", sz, rounds, c);

        const double ma = median(a), mb = median(b), mc = median(c);
        if (ma > 0 && mb > 0 && mc > 0)
            printf("  handover is %.2fx the in-process relay, "
                   "the unix relay is %.2fx\n", mb / ma, mc / ma);
        printf("\n");
    }
    return 0;
}
