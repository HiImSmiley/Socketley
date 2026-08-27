/*
 * Cache vs Redis — sustained RESP throughput with pipelining as a knob.
 *
 * What this measures, and what it does not:
 *   - THROUGHPUT of the batch path: c connections, each keeping one batch of
 *     P commands in flight (send P, validate P responses, repeat).  At P=1 it
 *     is the per-connection request/response path; at P>1 it is the parser's
 *     batch path.  It does NOT measure per-op latency — depth trades latency
 *     for throughput by construction.
 *   - Only VALIDATED responses count: "+OK\r\n" for SET, "$<len>\r\n...\r\n"
 *     with the exact expected length for GET.  Errors and short counts are
 *     reported and the tool refuses to print a rate over them.
 *   - Every rate carries cores-per-client beside it (RUSAGE_THREAD over the
 *     timed window).  A client at ~1.0 core is the ceiling, not the server;
 *     the line says so and the number must not be quoted as a comparison.
 *
 * Both arms run in every round, order flipped on odd rounds, so a clock or
 * load drift moves both together.  The summary is the median of per-round
 * paired differences, not the difference of medians.
 *
 * Usage:
 *   bench_cache_vs_redis [options] <socketley_port> <redis_port>
 *     -H <host>   host for both arms            (default 127.0.0.1)
 *     -P <depth>  pipeline depth                (default 1)
 *     -c <n>      client threads, 1 conn each   (default 1)
 *     -n <ops>    ops per thread per round      (default 100000)
 *     -v <bytes>  value size                    (default 64)
 *     -t <test>   set | get                     (default set)
 *     -r <n>      rounds                        (default 3)
 *
 * Compile: gcc -O3 -Wall -Wextra -o bench_cache_vs_redis bench_cache_vs_redis.c -lpthread
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <pthread.h>
#include <errno.h>

static inline long long now_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000LL + tv.tv_usec;
}

static long long thread_cpu_us(void)
{
    struct rusage ru;
    getrusage(RUSAGE_THREAD, &ru);
    return (ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) * 1000000LL
         + (ru.ru_utime.tv_usec + ru.ru_stime.tv_usec);
}

/* An arm is either a TCP port or a unix socket path.  Both ends of the
 * comparison speak both -- Redis has had `unixsocket` forever and socketley
 * gained `--listen unix:` on 2026-08-25 -- so unix-vs-unix is a fair fight and
 * not a trick.
 *
 * It is also the only fight that can separate us.  Over TCP loopback both arms
 * spend ~89% of their time in the same kernel network path (netfilter alone is
 * 9.24% here), which is why a cache at 106,213 and Redis at 108,342 once read
 * as a tie: neither number was about the server.  A unix socket cuts that
 * shared part away and leaves the ~11% where the implementations differ. */
typedef struct { const char* host; int port; const char* upath; } endpoint;

static int connect_ep(const endpoint* ep)
{
    if (ep->upath)
    {
        struct sockaddr_un ua;
        memset(&ua, 0, sizeof(ua));
        ua.sun_family = AF_UNIX;
        /* sun_path is 108 bytes and truncation is SILENT, which would connect
         * to a different socket than the caller named. */
        if (strlen(ep->upath) >= sizeof(ua.sun_path)) return -1;
        strncpy(ua.sun_path, ep->upath, sizeof(ua.sun_path) - 1);
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        if (connect(fd, (struct sockaddr*)&ua, sizeof(ua)) < 0) { close(fd); return -1; }
        return fd;   /* no TCP_NODELAY: there is no Nagle on AF_UNIX */
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int opt = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {}
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)ep->port);
    inet_pton(AF_INET, ep->host, &addr.sin_addr);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    return fd;
}

static int send_all(int fd, const char* buf, size_t len)
{
    size_t total = 0;
    while (total < len)
    {
        ssize_t n = write(fd, buf + total, len - total);
        if (n <= 0) { if (n < 0 && errno == EINTR) continue; return -1; }
        total += (size_t)n;
    }
    return 0;
}

/* ── Incremental RESP response validator ─────────────────────────────────────
 * Carries state across read() calls so a response split anywhere is handled.
 * expect_bulk_len < 0 means "+OK\r\n" (SET); >= 0 means "$<that len>\r\n
 * <payload>\r\n" (GET).  "-ERR..." lines and "$-1" count as errors, anything
 * unrecognised is a protocol failure that aborts the thread. */
typedef struct
{
    int state;          /* 0=at type byte, 1=in status line, 2=in error line,
                           3=in bulk header, 4=in bulk payload+crlf */
    long long ok;
    long long err;
    int proto_fail;
    int expect_bulk_len;
    char hdr[32];       /* status/header accumulation */
    int  hdr_len;
    long bulk_left;     /* payload + trailing CRLF bytes still to skip */
    long bulk_len;      /* parsed $<len> */
} resp_val;

static void resp_feed(resp_val* v, const char* p, size_t n)
{
    size_t i = 0;
    while (i < n && !v->proto_fail)
    {
        char c = p[i];
        switch (v->state)
        {
        case 0:
            v->hdr_len = 0;
            if (c == '+')      { v->state = 1; i++; }
            else if (c == '-') { v->state = 2; i++; }
            else if (c == '$') { v->state = 3; i++; }
            else               { v->proto_fail = 1; }
            break;
        case 1: /* status line: accumulate to \n, must be exactly OK */
        case 2: /* error line: accumulate to \n */
            if (v->hdr_len < (int)sizeof(v->hdr) - 1)
                v->hdr[v->hdr_len++] = c;
            i++;
            if (c == '\n')
            {
                if (v->state == 1)
                {
                    if (v->hdr_len >= 3 && memcmp(v->hdr, "OK\r", 3) == 0
                        && v->expect_bulk_len < 0)
                        v->ok++;
                    else
                        v->err++;
                }
                else
                    v->err++;
                v->state = 0;
            }
            break;
        case 3: /* bulk header digits up to \n */
            if (v->hdr_len < (int)sizeof(v->hdr) - 1)
                v->hdr[v->hdr_len++] = c;
            i++;
            if (c == '\n')
            {
                v->hdr[v->hdr_len] = '\0';
                v->bulk_len = strtol(v->hdr, NULL, 10);
                if (v->bulk_len < 0)          /* $-1 nil: a miss is an error here */
                {
                    v->err++;
                    v->state = 0;
                }
                else
                {
                    v->bulk_left = v->bulk_len + 2; /* payload + CRLF */
                    v->state = 4;
                }
            }
            break;
        case 4:
        {
            size_t take = (size_t)v->bulk_left < n - i ? (size_t)v->bulk_left : n - i;
            v->bulk_left -= (long)take;
            i += take;
            if (v->bulk_left == 0)
            {
                if (v->expect_bulk_len >= 0 && v->bulk_len == v->expect_bulk_len)
                    v->ok++;
                else
                    v->err++;
                v->state = 0;
            }
            break;
        }
        }
    }
}

/* ── Worker ── */
typedef struct
{
    const char* host;
    int port;
    const char* upath;      /* non-NULL: an AF_UNIX arm; port is then unused */
    int tid;
    int depth;
    long long ops;      /* timed ops target */
    int val_size;
    int is_get;         /* 0 = SET workload, 1 = GET workload */
    /* results */
    long long ok, err;
    long long wall_us, cpu_us;
    int failed;         /* connect/protocol failure */
    pthread_barrier_t* barrier;
} worker_args;

#define KEYSPACE 1000

static char* build_batch(int tid, int depth, int val_size, int is_get,
                         long long* key_ctr, size_t* out_len, char* value)
{
    /* generous upper bound per command */
    size_t cap = (size_t)depth * (64 + (size_t)(is_get ? 0 : val_size));
    char* buf = malloc(cap);
    size_t off = 0;
    for (int i = 0; i < depth; i++)
    {
        char key[32];
        int klen = snprintf(key, sizeof(key), "t%02dk%06lld",
                            tid, (*key_ctr)++ % KEYSPACE);
        if (is_get)
            off += (size_t)snprintf(buf + off, cap - off,
                "*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n", klen, key);
        else
        {
            off += (size_t)snprintf(buf + off, cap - off,
                "*3\r\n$3\r\nSET\r\n$%d\r\n%s\r\n$%d\r\n", klen, key, val_size);
            memcpy(buf + off, value, (size_t)val_size);
            off += (size_t)val_size;
            memcpy(buf + off, "\r\n", 2);
            off += 2;
        }
    }
    *out_len = off;
    return buf;
}

/* send one batch and validate exactly `depth` responses; returns 0 on ok */
static int do_batch(int fd, const char* batch, size_t blen, int depth, resp_val* v)
{
    long long want = v->ok + v->err + depth;
    if (send_all(fd, batch, blen) < 0) return -1;
    char rbuf[65536];
    while (v->ok + v->err < want)
    {
        ssize_t n = read(fd, rbuf, sizeof(rbuf));
        if (n <= 0) return -1;
        resp_feed(v, rbuf, (size_t)n);
        if (v->proto_fail) return -1;
    }
    return 0;
}

static void* worker(void* arg)
{
    worker_args* a = (worker_args*)arg;
    a->failed = 1;

    endpoint aep = { a->host, a->port, a->upath };
    int fd = connect_ep(&aep);
    if (fd < 0) { pthread_barrier_wait(a->barrier); return NULL; }

    char* value = malloc((size_t)a->val_size);
    memset(value, 'V', (size_t)a->val_size);

    long long key_ctr = 0;
    resp_val v = {0};

    /* GET workload: populate this thread's keyspace first (validated SETs) */
    if (a->is_get)
    {
        v.expect_bulk_len = -1;
        long long kc = 0;
        for (int done = 0; done < KEYSPACE; done += 500)
        {
            size_t blen;
            char* b = build_batch(a->tid, 500, a->val_size, 0, &kc, &blen, value);
            int rc = do_batch(fd, b, blen, 500, &v);
            free(b);
            if (rc < 0 || v.err) { close(fd); free(value); pthread_barrier_wait(a->barrier); return NULL; }
        }
        v.ok = 0;
    }

    v.expect_bulk_len = a->is_get ? a->val_size : -1;

    size_t blen;
    char* batch = build_batch(a->tid, a->depth, a->val_size, a->is_get,
                              &key_ctr, &blen, value);

    /* warmup: two batches, untimed */
    for (int w = 0; w < 2; w++)
        if (do_batch(fd, batch, blen, a->depth, &v))
        { close(fd); free(batch); free(value); pthread_barrier_wait(a->barrier); return NULL; }
    v.ok = 0; v.err = 0;

    pthread_barrier_wait(a->barrier);   /* all threads start together */

    long long batches = (a->ops + a->depth - 1) / a->depth;
    long long t0 = now_us(), c0 = thread_cpu_us();
    for (long long b = 0; b < batches; b++)
        if (do_batch(fd, batch, blen, a->depth, &v)) break;
    long long t1 = now_us(), c1 = thread_cpu_us();

    a->ok = v.ok; a->err = v.err;
    a->wall_us = t1 - t0;
    a->cpu_us = c1 - c0;
    a->failed = v.proto_fail;

    close(fd);
    free(batch);
    free(value);
    return NULL;
}

/* ── One arm, one round ── */
typedef struct
{
    double rate;            /* validated ops/sec, 0 when refused */
    long long ok, err, expected;
    double cores_mean, cores_max;   /* per client thread */
    double wall_s;
    int refused;
} arm_result;

static arm_result run_arm(const char* host, int port, const char* upath,
                          int clients, int depth,
                          long long ops_per_thread, int val_size, int is_get)
{
    arm_result r = {0};
    pthread_t* th = malloc((size_t)clients * sizeof(pthread_t));
    worker_args* wa = calloc((size_t)clients, sizeof(worker_args));
    pthread_barrier_t barrier;
    pthread_barrier_init(&barrier, NULL, (unsigned)clients);

    for (int i = 0; i < clients; i++)
    {
        wa[i] = (worker_args){ host, port, upath, i, depth, ops_per_thread,
                               val_size, is_get, 0,0,0,0,0, &barrier };
        pthread_create(&th[i], NULL, worker, &wa[i]);
    }

    long long wall_max = 0;
    double cores_sum = 0;
    for (int i = 0; i < clients; i++)
    {
        pthread_join(th[i], NULL);
        r.ok += wa[i].ok;
        r.err += wa[i].err;
        if (wa[i].failed) r.refused = 1;
        if (wa[i].wall_us > wall_max) wall_max = wa[i].wall_us;
        double cores = wa[i].wall_us > 0
                     ? (double)wa[i].cpu_us / (double)wa[i].wall_us : 0.0;
        cores_sum += cores;
        if (cores > r.cores_max) r.cores_max = cores;
    }
    pthread_barrier_destroy(&barrier);

    long long batches = (ops_per_thread + depth - 1) / depth;
    r.expected = batches * depth * clients;
    r.wall_s = wall_max / 1e6;
    r.cores_mean = cores_sum / clients;

    if (r.err > 0 || r.ok != r.expected) r.refused = 1;
    if (!r.refused && r.wall_s > 0) r.rate = r.ok / r.wall_s;

    free(th); free(wa);
    return r;
}

static void print_arm(const char* label, arm_result* r)
{
    if (r->refused)
    {
        printf("  [%-9s] REFUSED: %lld ok / %lld err of %lld expected — "
               "no rate over unvalidated responses\n",
               label, r->ok, r->err, r->expected);
        return;
    }
    printf("  [%-9s] %10.0f ops/s  (%lld validated, %.3fs)  "
           "cores/client mean %.2f max %.2f%s\n",
           label, r->rate, r->ok, r->wall_s, r->cores_mean, r->cores_max,
           r->cores_max >= 0.95
             ? "  ** GENERATOR-SATURATED: this is the client's ceiling, not the server's rate **"
             : "");
}

static int cmp_double(const void* a, const void* b)
{
    double d = *(const double*)a - *(const double*)b;
    return d < 0 ? -1 : d > 0 ? 1 : 0;
}
static double median(double* v, int n)
{
    qsort(v, (size_t)n, sizeof(double), cmp_double);
    return n % 2 ? v[n/2] : (v[n/2 - 1] + v[n/2]) / 2.0;
}

int main(int argc, char** argv)
{
    const char* host = "127.0.0.1";
    int depth = 1, clients = 1, val_size = 64, rounds = 3, is_get = 0;
    long long ops = 100000;

    int opt;
    while ((opt = getopt(argc, argv, "H:P:c:n:v:t:r:")) != -1)
    {
        switch (opt)
        {
        case 'H': host = optarg; break;
        case 'P': depth = atoi(optarg); break;
        case 'c': clients = atoi(optarg); break;
        case 'n': ops = atoll(optarg); break;
        case 'v': val_size = atoi(optarg); break;
        case 't': is_get = strcmp(optarg, "get") == 0; break;
        case 'r': rounds = atoi(optarg); break;
        default:
            fprintf(stderr, "usage: %s [-H host] [-P depth] [-c clients] "
                    "[-n ops/thread] [-v valsize] [-t set|get] [-r rounds] "
                    "<socketley_port|unix:path> <redis_port|unix:path>\n", argv[0]);
            return 1;
        }
    }
    if (optind + 2 != argc || depth < 1 || clients < 1 || rounds < 1)
    {
        fprintf(stderr, "usage: %s [-H host] [-P depth] [-c clients] "
                "[-n ops/thread] [-v valsize] [-t set|get] [-r rounds] "
                "<socketley_port> <redis_port>\n", argv[0]);
        return 1;
    }
    /* Each arm is "<port>" or "unix:<path>".  Mixing them is allowed and is
     * sometimes exactly the question ("what does the transport cost us"), but
     * a Redis comparison must use the SAME transport on both sides or it is
     * not a comparison. */
    const char* arg_a = argv[optind];
    const char* arg_b = argv[optind + 1];
    const char* upath_a = strncmp(arg_a, "unix:", 5) == 0 ? arg_a + 5 : NULL;
    const char* upath_b = strncmp(arg_b, "unix:", 5) == 0 ? arg_b + 5 : NULL;
    int port_a = upath_a ? 0 : atoi(arg_a);
    int port_b = upath_b ? 0 : atoi(arg_b);
    if (!upath_a && port_a <= 0) { fprintf(stderr, "arm A: not a port or unix:<path>: %s\n", arg_a); return 1; }
    if (!upath_b && port_b <= 0) { fprintf(stderr, "arm B: not a port or unix:<path>: %s\n", arg_b); return 1; }
    if ((upath_a != NULL) != (upath_b != NULL))
        fprintf(stderr, "  WARNING: the two arms use DIFFERENT transports; this measures the transport, not the servers\n");

    printf("\n  RESP %s throughput — depth %d, %d client thread(s), "
           "%lld ops/thread/round, %dB values, %d round(s)\n",
           is_get ? "GET" : "SET", depth, clients, ops, val_size, rounds);
    printf("  Measures the batch path's throughput, not per-op latency. "
           "Arms interleaved, order flipped per round.\n\n");

    double* ra = malloc((size_t)rounds * sizeof(double));
    double* rb = malloc((size_t)rounds * sizeof(double));
    double* diff = malloc((size_t)rounds * sizeof(double));
    int valid = 0;

    for (int round = 0; round < rounds; round++)
    {
        arm_result a, b;
        int a_first = (round % 2 == 0);
        printf("  round %d (%s first):\n", round + 1, a_first ? "socketley" : "redis");
        if (a_first)
        {
            a = run_arm(host, port_a, upath_a, clients, depth, ops, val_size, is_get);
            b = run_arm(host, port_b, upath_b, clients, depth, ops, val_size, is_get);
        }
        else
        {
            b = run_arm(host, port_b, upath_b, clients, depth, ops, val_size, is_get);
            a = run_arm(host, port_a, upath_a, clients, depth, ops, val_size, is_get);
        }
        print_arm("socketley", &a);
        print_arm("redis", &b);
        if (!a.refused && !b.refused)
        {
            ra[valid] = a.rate; rb[valid] = b.rate;
            diff[valid] = a.rate - b.rate;
            valid++;
        }
    }

    if (valid == rounds && valid > 0)
    {
        double da = median(ra, valid), db = median(rb, valid);
        printf("\n  median: socketley %.0f ops/s, redis %.0f ops/s, "
               "median paired diff %+.0f ops/s (%d/%d rounds valid)\n",
               da, db, median(diff, valid), valid, rounds);
    }
    else
        printf("\n  %d/%d rounds valid — no summary over refused rounds\n",
               valid, rounds);

    free(ra); free(rb); free(diff);
    return 0;
}
