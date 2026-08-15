/*
 * floor_server — the irreducible cost of this traffic, in C
 *
 * Not a competitor, and it must never be read as one.  The cache is measured
 * against Redis and the proxy against haproxy; the server runtime, which has
 * the most benchmarks of the three, has had nothing underneath it.  So
 * "74,038 round trips/sec, p50 12.7us" has been a number without a scale, and
 * nobody could say whether it was good, because nobody knew what the kernel and
 * the scheduler alone charge to carry the same traffic.  That is the only thing
 * this program measures: accept, read, write back the bytes, and nothing else.
 *
 * What it deliberately does NOT do, because each of these would put work back
 * under the number and raise the floor:
 *
 *   - no io_uring; the point is to exclude the runtime's I/O machinery
 *   - no framing, no protocol, no parsing -- the bytes that arrive go back out
 *     unexamined, which is why it needs no notion of a message at all
 *   - no statistics, no counters, no logging on the data path
 *   - no buffering strategy beyond one stack buffer per connection
 *   - no configuration
 *
 * The client is the other half of the contract.  This is driven by
 * test/benchmark/bench.c -- the same binary, the same `server msg` and
 * `server concurrent` code paths, the same round-trip definition (each request's
 * reply read before the next is sent) and the same reported metric.  A floor
 * measured by a different client would compare two client implementations and
 * tell you nothing about the server, which would be worse than having no floor
 * at all: it would be a number that looks like an answer.
 *
 *
 * ── Why the two modes differ ───────────────────────────────────────────────
 *
 * -m block  (for the 1-connection benchmarks, `server msg`)
 *
 *     One connection, served with blocking read/write and no readiness call at
 *     all.  That is the true floor for a single connection: there is nothing to
 *     multiplex, so asking the kernel which of one socket is ready is pure
 *     overhead, and a floor that included it would be quietly charging itself
 *     for a decision it never has to make.  Two syscalls per round trip, read
 *     and write, and there is no way to serve a byte with fewer.
 *
 * -m epoll  (for `server concurrent`)
 *
 *     With N connections something has to discover which are readable, and one
 *     thread with epoll is the cheapest standard way to do it.  Single-threaded
 *     on purpose: socketley's worker is a single-threaded event loop, so a
 *     floor that spread the same work over ten cores would not be a floor for
 *     it -- it would be a different architecture, and the comparison would
 *     measure the core count rather than the per-request cost.
 *
 *     Thread-per-connection with blocking I/O is the other honest floor, and it
 *     is not used here for that same reason: at 100 connections it measures the
 *     scheduler, and socketley never pays that.
 *
 * The two modes are therefore not interchangeable, and the numbers from them
 * are not either.  Each socketley benchmark is compared against the mode that
 * matches its shape; bench_server_floor.sh pairs them up and says which is
 * which.
 *
 * Compile: gcc -O3 -o floor_server floor_server.c
 * Usage:   floor_server <port> [-m block|epoll]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define BUF_SIZE   65536
#define MAX_EVENTS 256
#define BACKLOG    4096

/* TCP_NODELAY on every accepted socket, because socketley sets it on its own
 * (server_instance.cpp) and a floor running with Nagle enabled would lose a
 * round-trip comparison to a socket option rather than to anything real. */
static void tune(int fd)
{
    int opt = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) { }
}

static int listen_on(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) { }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(fd); return -1;
    }
    if (listen(fd, BACKLOG) < 0) {
        perror("listen"); close(fd); return -1;
    }
    return fd;
}

/* Echo everything received, until the peer closes.
 *
 * A short write is looped, a short read is not: whatever arrived goes straight
 * back, and the client's recv_exact() reassembles.  There is nothing here that
 * knows what a message is, which is the point -- adding a framing rule would be
 * adding the first piece of the thing being measured against. */
static void serve_blocking(int fd)
{
    char buf[BUF_SIZE];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) return;                 /* EOF, or the peer went away */
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(fd, buf + off, (size_t)(n - off));
            if (w <= 0) return;
            off += w;
        }
    }
}

static int run_blocking(int lfd)
{
    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            return 2;
        }
        tune(cfd);
        serve_blocking(cfd);   /* one at a time, on purpose: see the header */
        close(cfd);
    }
}

static int run_epoll(int lfd)
{
    /* The listening socket must be non-blocking here, and it is not optional.
     * The accept drain below stops on EAGAIN, which a blocking listener never
     * returns -- it parks in accept4() instead, and the server then never reads
     * from the connections it has already taken.  That deadlocks every client
     * at once and the run reports a rate of zero, which is how this was found. */
    int fl = fcntl(lfd, F_GETFL, 0);
    if (fl < 0 || fcntl(lfd, F_SETFL, fl | O_NONBLOCK) < 0) {
        perror("fcntl(listen, O_NONBLOCK)");
        return 2;
    }

    int ep = epoll_create1(0);
    if (ep < 0) { perror("epoll_create1"); return 2; }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = lfd;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, lfd, &ev) < 0) {
        perror("epoll_ctl(listen)"); close(ep); return 2;
    }

    struct epoll_event events[MAX_EVENTS];
    char buf[BUF_SIZE];

    for (;;) {
        int n = epoll_wait(ep, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait"); close(ep); return 2;
        }

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            if (fd == lfd) {
                /* Drain the accept queue: with 100 clients arriving at a
                 * barrier they land together, and accepting one per wakeup
                 * would charge the floor an epoll_wait per connection. */
                for (;;) {
                    int cfd = accept4(lfd, NULL, NULL, SOCK_NONBLOCK);
                    if (cfd < 0) break;
                    tune(cfd);
                    struct epoll_event cev;
                    memset(&cev, 0, sizeof(cev));
                    cev.events = EPOLLIN;
                    cev.data.fd = cfd;
                    if (epoll_ctl(ep, EPOLL_CTL_ADD, cfd, &cev) < 0)
                        close(cfd);
                }
                continue;
            }

            /* Level-triggered, so one read per wakeup is enough; anything left
             * wakes us again.  Blocking writes on a non-blocking socket are
             * handled the only way that stays honest at this size: loop on
             * EAGAIN.  At 64B and 1024B replies the socket buffer is never the
             * constraint, so this loop does not run in practice -- it is here
             * so that a larger size fails slowly instead of wrongly. */
            ssize_t r = read(fd, buf, sizeof(buf));
            if (r <= 0) {
                if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
                epoll_ctl(ep, EPOLL_CTL_DEL, fd, NULL);
                close(fd);
                continue;
            }

            ssize_t off = 0;
            int dead = 0;
            while (off < r) {
                ssize_t w = write(fd, buf + off, (size_t)(r - off));
                if (w > 0) { off += w; continue; }
                if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
                dead = 1;
                break;
            }
            if (dead) {
                epoll_ctl(ep, EPOLL_CTL_DEL, fd, NULL);
                close(fd);
            }
        }
    }
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);

    if (argc < 2) {
        fprintf(stderr,
            "Usage: %s <port> [-m block|epoll]\n"
            "\n"
            "  block   one connection at a time, blocking read/write, no\n"
            "          readiness syscall -- the floor for a single connection\n"
            "  epoll   one thread, many connections -- the floor at concurrency\n"
            "\n"
            "Drive it with socketley-bench so the client is the same one the\n"
            "socketley numbers came from:\n"
            "  socketley_bench server msg        127.0.0.1 <port> 100000 64\n"
            "  socketley_bench server concurrent 127.0.0.1 <port> 100 500\n",
            argv[0]);
        return 1;
    }

    int port = atoi(argv[1]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "floor_server: bad port: %s\n", argv[1]);
        return 1;
    }

    const char *mode = "block";
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            mode = argv[i + 1];
            i++;
        } else {
            fprintf(stderr, "floor_server: unknown argument: %s\n", argv[i]);
            return 1;
        }
    }

    int lfd = listen_on(port);
    if (lfd < 0) return 2;

    if (strcmp(mode, "block") == 0) return run_blocking(lfd);
    if (strcmp(mode, "epoll") == 0) return run_epoll(lfd);

    fprintf(stderr, "floor_server: unknown mode: %s\n", mode);
    close(lfd);
    return 1;
}
