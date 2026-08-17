/*
 * floor_relay — the irreducible cost of a PROXIED round trip, in C
 *
 * floor_server.c answers the question "what does one hop cost".  This answers
 * the one that matters for a proxy: what do FOUR handoffs cost, when nothing
 * between them is ours.
 *
 * A proxied round trip is client -> proxy -> backend -> proxy -> client.  Each
 * arrow is a wakeup and a loopback TCP traversal.  Measured on this tree, that
 * round trip costs about 52us of CPU across the three processes while a direct
 * one costs 10.4us — and the whole optimisation question is how much of that
 * 42us difference is ours to remove and how much is what the kernel charges for
 * two more handoffs.
 *
 * This program is the second number.  Accept, connect to the backend, and pump
 * bytes both ways.  No io_uring, no framing, no protocol, no routing, no
 * statistics, no configuration — the same rules floor_server.c is written under,
 * and for the same reason: anything added here would be charged to the kernel
 * and quietly lower the bar socketley is compared against.
 *
 *   client            socketley_bench, unchanged
 *   this              accept, read, write, read, write
 *   backend           floor_server -m block, unchanged
 *
 * Drive it exactly as the proxy is driven, so the two numbers are comparable:
 *
 *   floor_server 30002 -m block &
 *   floor_relay  30001 127.0.0.1 30002 -m block &
 *   socketley_bench server msg 127.0.0.1 30001 20000 64
 *
 * ── The two modes ──────────────────────────────────────────────────────────
 *
 * -m block  one connection, blocking I/O, no readiness syscall at all.  With a
 *           single connection there is nothing to multiplex and epoll_wait would
 *           be overhead the floor never has to pay, which would flatter the
 *           thing being measured against it.
 *
 * -m epoll  one thread, many connections, because a socketley proxy shard is a
 *           single-threaded event loop.  A relay spread over sixteen cores would
 *           be a different architecture and the comparison would measure core
 *           count.
 *
 * WHAT THIS IS NOT.  It is not a proxy: no backend selection, no health, no
 * pooling — the backend connection is opened per client connection and closed
 * with it.  With keep-alive clients, which is what the benchmarks use, that is
 * one connect per measurement and not per request, so it does not enter the
 * per-round-trip figure.  It also does not read what it forwards, so it cannot
 * stand in for an HTTP proxy that parses a request line.
 *
 * Compile: gcc -O3 -o floor_relay floor_relay.c
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
#include <sys/un.h>
#include <stddef.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define BUF_SIZE   65536
#define MAX_EVENTS 256
#define BACKLOG    4096
#define MAX_FDS    65536

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

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) { perror("bind"); close(fd); return -1; }
    if (listen(fd, BACKLOG) < 0) { perror("listen"); close(fd); return -1; }
    return fd;
}

/* The backend leg, in whichever family it was asked for.
 *
 * `host` is either a dotted quad or "unix:/path/to.sock".  The second form is
 * here for one comparison and one only: the relay's listener stays TCP, so the
 * client half of the round trip is byte-for-byte the same in both arms and the
 * only thing that changes is the address family of the backend leg.  Run it
 * both ways and the difference is exactly what the kernel charges for putting
 * a loopback TCP stack under a connection that never leaves the host --
 * measured with none of socketley's code in the path, which is the only way to
 * say whether the proxy is capturing that saving or losing it.
 *
 * tune() is TCP_NODELAY and means nothing on AF_UNIX, so it is not called
 * there.  Nagle is the one thing that could make this comparison a lie in the
 * unix arm's favour if it were left applying to only one side. */
static int dial(const char *host, int port)
{
    if (strncmp(host, "unix:", 5) == 0) {
        const char *path = host + 5;
        struct sockaddr_un a;
        memset(&a, 0, sizeof(a));
        a.sun_family = AF_UNIX;
        /* sun_path is 108 bytes and truncation is silent, which would dial a
         * different socket and report its timings as this one's. */
        if (strlen(path) >= sizeof(a.sun_path)) {
            fprintf(stderr, "floor_relay: unix path too long (max %zu)\n",
                    sizeof(a.sun_path) - 1);
            return -1;
        }
        memcpy(a.sun_path, path, strlen(path));
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        socklen_t alen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                                     strlen(path) + 1);
        if (connect(fd, (struct sockaddr *)&a, alen) < 0) { close(fd); return -1; }
        return fd;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1) { close(fd); return -1; }
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0) { close(fd); return -1; }
    tune(fd);
    return fd;
}

static int write_all(int fd, const char *b, ssize_t n)
{
    ssize_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, b + off, (size_t)(n - off));
        if (w > 0) { off += w; continue; }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        return -1;
    }
    return 0;
}

/* One client, one backend, bytes both ways until either end goes.
 *
 * Blocking and strictly alternating, which is what a request/response client
 * produces anyway: read from the client, write to the backend, read the reply,
 * write it back.  Four handoffs, no bookkeeping between them. */
static void serve_blocking(int cfd, const char *bhost, int bport)
{
    int bfd = dial(bhost, bport);
    if (bfd < 0) { close(cfd); return; }
    char buf[BUF_SIZE];
    for (;;) {
        ssize_t n = read(cfd, buf, sizeof(buf));
        if (n <= 0) break;
        if (write_all(bfd, buf, n) < 0) break;
        n = read(bfd, buf, sizeof(buf));
        if (n <= 0) break;
        if (write_all(cfd, buf, n) < 0) break;
    }
    close(bfd);
    close(cfd);
}

static int run_blocking(int lfd, const char *bhost, int bport)
{
    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) { if (errno == EINTR) continue; perror("accept"); return 2; }
        tune(cfd);
        serve_blocking(cfd, bhost, bport);
    }
}

/* peer[fd] is the other half of the pair, or -1.  A flat array rather than a
 * map for the same reason the rest of this file has no data structures: a hash
 * lookup per event would be charged to the kernel's side of the comparison. */
static int peer[MAX_FDS];

static void drop_pair(int ep, int fd)
{
    int p = (fd >= 0 && fd < MAX_FDS) ? peer[fd] : -1;
    if (fd >= 0 && fd < MAX_FDS) { peer[fd] = -1; epoll_ctl(ep, EPOLL_CTL_DEL, fd, NULL); close(fd); }
    if (p  >= 0 && p  < MAX_FDS) { peer[p]  = -1; epoll_ctl(ep, EPOLL_CTL_DEL, p,  NULL); close(p);  }
}

static int run_epoll(int lfd, const char *bhost, int bport)
{
    int fl = fcntl(lfd, F_GETFL, 0);
    if (fl < 0 || fcntl(lfd, F_SETFL, fl | O_NONBLOCK) < 0) { perror("fcntl"); return 2; }

    int ep = epoll_create1(0);
    if (ep < 0) { perror("epoll_create1"); return 2; }
    for (int i = 0; i < MAX_FDS; i++) peer[i] = -1;

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN; ev.data.fd = lfd;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, lfd, &ev) < 0) { perror("epoll_ctl"); close(ep); return 2; }

    struct epoll_event events[MAX_EVENTS];
    char buf[BUF_SIZE];

    for (;;) {
        int n = epoll_wait(ep, events, MAX_EVENTS, -1);
        if (n < 0) { if (errno == EINTR) continue; perror("epoll_wait"); close(ep); return 2; }

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            if (fd == lfd) {
                for (;;) {
                    int cfd = accept4(lfd, NULL, NULL, SOCK_NONBLOCK);
                    if (cfd < 0) break;
                    tune(cfd);
                    int bfd = dial(bhost, bport);       /* blocking connect: once per
                                                           connection, never per request */
                    if (bfd < 0 || cfd >= MAX_FDS || bfd >= MAX_FDS) {
                        close(cfd); if (bfd >= 0) close(bfd); continue;
                    }
                    int bl = fcntl(bfd, F_GETFL, 0);
                    if (bl >= 0) { if (fcntl(bfd, F_SETFL, bl | O_NONBLOCK) < 0) {} }
                    peer[cfd] = bfd; peer[bfd] = cfd;
                    struct epoll_event e2;
                    memset(&e2, 0, sizeof(e2));
                    e2.events = EPOLLIN;
                    e2.data.fd = cfd; if (epoll_ctl(ep, EPOLL_CTL_ADD, cfd, &e2) < 0) { drop_pair(ep, cfd); continue; }
                    e2.data.fd = bfd; if (epoll_ctl(ep, EPOLL_CTL_ADD, bfd, &e2) < 0) { drop_pair(ep, cfd); continue; }
                }
                continue;
            }

            if (fd < 0 || fd >= MAX_FDS || peer[fd] < 0) continue;
            ssize_t r = read(fd, buf, sizeof(buf));
            if (r <= 0) {
                if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
                drop_pair(ep, fd);
                continue;
            }
            if (write_all(peer[fd], buf, r) < 0) drop_pair(ep, fd);
        }
    }
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);

    if (argc < 3) {
        fprintf(stderr,
            "Usage: %s <listen-port> <backend-host> <backend-port> [-m block|epoll]\n"
            "       %s <listen-port> unix:<path>                   [-m block|epoll]\n"
            "\n"
            "The cost of four handoffs with nothing of ours between them.  Pair it\n"
            "with floor_server as the backend and drive both with socketley_bench:\n"
            "\n"
            "  floor_server 30002 -m block &\n"
            "  floor_relay  30001 127.0.0.1 30002 -m block &\n"
            "  socketley_bench server msg 127.0.0.1 30001 20000 64\n"
            "\n"
            "The second form dials the backend over AF_UNIX while the listener\n"
            "stays TCP, so the two arms differ in the backend leg alone:\n"
            "\n"
            "  floor_server -u /tmp/be.sock -m block &\n"
            "  floor_relay  30001 unix:/tmp/be.sock -m block &\n",
            argv[0], argv[0]);
        return 1;
    }

    int lport = atoi(argv[1]);
    const char *bhost = argv[2];
    const int backend_is_unix = (strncmp(bhost, "unix:", 5) == 0);
    /* A unix backend has no port, so the third argument is the mode's and the
     * option scan starts one earlier. */
    int argi = backend_is_unix ? 3 : 4;
    int bport = 0;
    if (!backend_is_unix) {
        if (argc < 4) { fprintf(stderr, "floor_relay: a tcp backend needs a port\n"); return 1; }
        bport = atoi(argv[3]);
        if (bport <= 0 || bport > 65535) { fprintf(stderr, "floor_relay: bad port\n"); return 1; }
    }
    if (lport <= 0 || lport > 65535) {
        fprintf(stderr, "floor_relay: bad port\n");
        return 1;
    }

    const char *mode = "block";
    for (int i = argi; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) { mode = argv[i + 1]; i++; }
        else { fprintf(stderr, "floor_relay: unknown argument: %s\n", argv[i]); return 1; }
    }

    int lfd = listen_on(lport);
    if (lfd < 0) return 2;

    if (strcmp(mode, "block") == 0) return run_blocking(lfd, bhost, bport);
    if (strcmp(mode, "epoll") == 0) return run_epoll(lfd, bhost, bport);

    fprintf(stderr, "floor_relay: unknown mode: %s\n", mode);
    close(lfd);
    return 1;
}
