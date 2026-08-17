/*
 * floor_pingpong — what ONE duplex exchange costs, by address family
 *
 * floor_server answers "what does one hop cost" and floor_relay answers "what
 * do four cost".  This answers the question underneath both: what does the
 * kernel charge to carry 64 bytes from one process to another and back, and
 * how much of that is the loopback TCP stack rather than the handoff itself.
 *
 * It exists because that number was needed to size `--backend unix:` before it
 * was written, and because the first instrument that produced it measured one
 * block of AF_UNIX, tore it down, and then measured one block of TCP.
 * Sequential A-then-B over a single window is the shape this tree has already
 * caught reporting the block ORDER as if it were the result.  Here both pairs
 * are built and both children are running before anything is timed, the blocks
 * alternate, and the order flips on odd passes.
 *
 * ── Wall time is not the answer on its own ─────────────────────────────────
 *
 * It reports the CPU both processes burned per round trip beside the latency,
 * and the two do not move together.  Converting the backend leg of a relay
 * chain removes almost exactly the CPU this program predicts for a leg — and,
 * with one connection on one core, almost none of the latency, because a
 * serial round trip there waits on wakeups rather than on work and the freed
 * CPU has nothing to do.  A quiet arithmetic that goes from "3 us cheaper per
 * exchange" to "3 us faster per request" is wrong in the only regime a proxy
 * is ever in; the CPU column is the one that turns into throughput.
 *
 * Measured on this tree, 64 bytes, 20k round trips a block, 7 passes, the
 * saving paired per pass:
 *
 *              AF_UNIX          TCP loopback       saved
 *   one core    6.92 us (cpu  6.68)   9.88 us (cpu 10.62)   2.95 us wall, 4.20 cpu
 *   unpinned    9.87 us (cpu 12.39)  19.04 us (cpu 20.77)   8.85 us wall, 8.35 cpu
 *
 * More CPU goes away than latency on one core, which is the whole point of
 * printing both.
 *
 * Compile: it is a premake project — bin/<config>/floor_pingpong
 * Run:     floor_pingpong [-n OPS] [-m BYTES] [-P PASSES] [-c CPU]
 *
 *   -c CPU   put both processes on one core.  Without it the scheduler places
 *            them, which is the deployed case and also the noisier one: it
 *            never co-locates a chain, so the unpinned figures carry a
 *            cross-core wakeup on every leg.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>

static double now_us(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

static int cmpd(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

static int g_cpu = -1;   /* -1: leave placement to the scheduler */

static void pin_self(void)
{
    if (g_cpu < 0) return;
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(g_cpu, &s);
    if (sched_setaffinity(0, sizeof(s), &s) < 0) { }
}

/* This process plus every child that has been reaped.  The echo children are
 * only reaped at exit, so their CPU is read from /proc while they live. */
static double self_cpu_us(void)
{
    struct rusage r;
    if (getrusage(RUSAGE_SELF, &r) < 0) return 0;
    return (double)r.ru_utime.tv_sec * 1e6 + r.ru_utime.tv_usec +
           (double)r.ru_stime.tv_sec * 1e6 + r.ru_stime.tv_usec;
}

static double child_cpu_us(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    /* utime and stime are fields 14 and 15, and field 2 is a comm that may
     * contain spaces and parentheses — so the scan starts after the last ')'. */
    char buf[1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0) return 0;
    buf[n] = '\0';
    char *p = strrchr(buf, ')');
    if (!p) return 0;
    long ut = 0, st = 0;
    int field = 2;   /* the ')' ends field 2 */
    for (char *tok = strtok(p + 1, " "); tok; tok = strtok(NULL, " "))
    {
        ++field;
        if (field == 14) ut = atol(tok);
        else if (field == 15) { st = atol(tok); break; }
    }
    const long hz = sysconf(_SC_CLK_TCK);
    if (hz <= 0) return 0;
    return (double)(ut + st) * 1e6 / (double)hz;
}

static void echo_child(int fd, size_t msg)
{
    pin_self();
    char *b = malloc(msg);
    if (!b) _exit(1);
    for (;;)
    {
        size_t got = 0;
        while (got < msg)
        {
            ssize_t r = read(fd, b + got, msg - got);
            if (r <= 0) _exit(0);
            got += (size_t)r;
        }
        size_t off = 0;
        while (off < msg)
        {
            ssize_t w = write(fd, b + off, msg - off);
            if (w <= 0) _exit(0);
            off += (size_t)w;
        }
    }
}

/* One block of n round trips.  p50 through *p50, CPU per round trip across
 * both processes through *cpu. */
static int block(int fd, pid_t peer, int n, size_t msg,
                 char *out, char *in, double *lat, double *p50, double *cpu)
{
    const double c0 = self_cpu_us() + child_cpu_us(peer);
    for (int i = 0; i < n; i++)
    {
        const double t0 = now_us();
        size_t off = 0;
        while (off < msg)
        {
            ssize_t w = write(fd, out + off, msg - off);
            if (w <= 0) return -1;
            off += (size_t)w;
        }
        size_t got = 0;
        while (got < msg)
        {
            ssize_t r = read(fd, in + got, msg - got);
            if (r <= 0) return -1;
            got += (size_t)r;
        }
        lat[i] = now_us() - t0;
    }
    const double c1 = self_cpu_us() + child_cpu_us(peer);
    qsort(lat, (size_t)n, sizeof(double), cmpd);
    *p50 = lat[n / 2];
    *cpu = (c1 - c0) / n;
    return 0;
}

int main(int argc, char **argv)
{
    int n = 20000, passes = 7;
    size_t msg = 64;

    for (int i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "-n") && i + 1 < argc) n = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-m") && i + 1 < argc) msg = (size_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "-P") && i + 1 < argc) passes = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-c") && i + 1 < argc) g_cpu = atoi(argv[++i]);
        else
        {
            fprintf(stderr,
                "Usage: %s [-n OPS] [-m BYTES] [-P PASSES] [-c CPU]\n"
                "\n"
                "AF_UNIX against loopback TCP, one duplex exchange, interleaved.\n"
                "Reports latency and the CPU both processes burned per round\n"
                "trip -- the second is the one that turns into throughput.\n",
                argv[0]);
            return 1;
        }
    }
    if (n < 100 || passes < 1 || msg < 1)
    {
        fprintf(stderr, "floor_pingpong: -n >= 100, -P >= 1, -m >= 1\n");
        return 1;
    }
    pin_self();

    /* ── both pairs up, both children running, before either is timed ────── */
    int u[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, u) < 0) { perror("socketpair"); return 2; }
    const pid_t pu = fork();
    if (pu < 0) { perror("fork"); return 2; }
    if (pu == 0) { close(u[0]); echo_child(u[1], msg); _exit(0); }
    close(u[1]);

    int l = socket(AF_INET, SOCK_STREAM, 0), opt = 1;
    if (l < 0) { perror("socket"); return 2; }
    if (setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) { }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(l, (struct sockaddr *)&a, sizeof(a)) < 0) { perror("bind"); return 2; }
    socklen_t al = sizeof(a);
    if (getsockname(l, (struct sockaddr *)&a, &al) < 0) { perror("getsockname"); return 2; }
    if (listen(l, 8) < 0) { perror("listen"); return 2; }
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (c < 0) { perror("socket"); return 2; }
    if (connect(c, (struct sockaddr *)&a, sizeof(a)) < 0) { perror("connect"); return 2; }
    int s = accept(l, NULL, NULL);
    if (s < 0) { perror("accept"); return 2; }
    /* Nagle off on BOTH ends.  AF_UNIX has no such timer, so leaving it on for
     * one side of this comparison would be measuring Nagle. */
    if (setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) { }
    if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) { }
    const pid_t pt = fork();
    if (pt < 0) { perror("fork"); return 2; }
    if (pt == 0) { close(c); close(l); echo_child(s, msg); _exit(0); }
    close(s);
    close(l);

    char *out = malloc(msg), *in = malloc(msg);
    double *lat = malloc(sizeof(double) * (size_t)n);
    double *ru = malloc(sizeof(double) * (size_t)passes);
    double *rt = malloc(sizeof(double) * (size_t)passes);
    double *cu = malloc(sizeof(double) * (size_t)passes);
    double *ct = malloc(sizeof(double) * (size_t)passes);
    if (!out || !in || !lat || !ru || !rt || !cu || !ct) { perror("malloc"); return 2; }
    memset(out, 'x', msg);

    /* One discarded block each, so neither arm pays for the other's cold cache. */
    double d0, d1;
    block(u[0], pu, n / 4, msg, out, in, lat, &d0, &d1);
    block(c,    pt, n / 4, msg, out, in, lat, &d0, &d1);

    printf("# msg=%zuB ops=%d passes=%d placement=%s\n",
           msg, n, passes, g_cpu < 0 ? "unpinned" : "one core");
    for (int p = 0; p < passes; p++)
    {
        /* Order flipped on odd passes, so a systematic advantage to going
         * first cancels rather than accumulating into the result. */
        int bad;
        if (p & 1)
            bad = block(c, pt, n, msg, out, in, lat, &rt[p], &ct[p]) < 0 ||
                  block(u[0], pu, n, msg, out, in, lat, &ru[p], &cu[p]) < 0;
        else
            bad = block(u[0], pu, n, msg, out, in, lat, &ru[p], &cu[p]) < 0 ||
                  block(c, pt, n, msg, out, in, lat, &rt[p], &ct[p]) < 0;
        if (bad) { fprintf(stderr, "floor_pingpong: a peer went away\n"); return 2; }
        printf("  pass %d   unix %6.2f us (cpu %5.2f)   tcp %6.2f us (cpu %5.2f)"
               "   saved %5.2f us wall, %5.2f us cpu\n",
               p + 1, ru[p], cu[p], rt[p], ct[p], rt[p] - ru[p], ct[p] - cu[p]);
    }

    /* The saving is the median of the per-pass DIFFERENCES, not the difference
     * of the two medians.  The arms are paired — each pass measures both, back
     * to back — and subtracting independent medians throws that away: one slow
     * pass in one arm moves that arm's median and the subtraction reports it as
     * a saving.  It did, on the first run of this program: 7.4-7.9 us in every
     * pass and "10.03" on the summary line. */
    double *dw = malloc(sizeof(double) * (size_t)passes);
    double *dc = malloc(sizeof(double) * (size_t)passes);
    if (!dw || !dc) { perror("malloc"); return 2; }
    for (int p = 0; p < passes; p++) { dw[p] = rt[p] - ru[p]; dc[p] = ct[p] - cu[p]; }
    qsort(dw, (size_t)passes, sizeof(double), cmpd);
    qsort(dc, (size_t)passes, sizeof(double), cmpd);
    qsort(ru, (size_t)passes, sizeof(double), cmpd);
    qsort(rt, (size_t)passes, sizeof(double), cmpd);
    qsort(cu, (size_t)passes, sizeof(double), cmpd);
    qsort(ct, (size_t)passes, sizeof(double), cmpd);
    const int h = passes / 2;
    printf("  median   unix %6.2f us (cpu %5.2f)   tcp %6.2f us (cpu %5.2f)\n"
           "  paired   saved %5.2f us wall, %5.2f us cpu   (worst pass %5.2f, best %5.2f)\n",
           ru[h], cu[h], rt[h], ct[h], dw[h], dc[h], dw[0], dw[passes - 1]);

    close(u[0]);
    close(c);
    waitpid(pu, NULL, 0);
    waitpid(pt, NULL, 0);
    return 0;
}
