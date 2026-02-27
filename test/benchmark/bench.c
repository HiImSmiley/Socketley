/*
 * socketley-bench — proper C benchmark tool for Socketley
 *
 * Replaces bash/nc measurement with persistent-connection C code using
 * clock_gettime(CLOCK_MONOTONIC). Bash scripts keep orchestration
 * (create/start/stop runtimes) but call this binary for measurement.
 *
 * Compile: gcc -O3 -o socketley-bench bench.c -lpthread
 *
 * Usage:
 *   socketley-bench [OPTIONS] <category> <test> <host> <port> [params...]
 *
 * Options:
 *   -j          JSON output (single-line object per test)
 *   -r N        Number of runs (default 5)
 *   -w N        Warm-up percentage (default 10)
 *
 * Categories/tests:
 *   server conn|burst|msg|concurrent
 *   cache  set|get|mixed|concurrent
 *   proxy  tcp|concurrent|overhead
 *   ws     handshake|echo|concurrent
 */

/* ═══════════════════════════════════════════════════════════════════════════
 * A. Includes / Config
 * ═══════════════════════════════════════════════════════════════════════════ */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>

#define MAX_OPS        2000000
#define MAX_LATENCIES  2000000
#define BUF_SIZE       65536
#define DEFAULT_RUNS   5
#define DEFAULT_WARMUP 10

struct bench_config {
    const char *host;
    int         port;
    int         port2;       /* second endpoint for overhead test */
    int         num_ops;
    int         msg_size;
    int         num_clients;
    int         runs;
    int         warmup_pct;
    int         json;
};

/* ═══════════════════════════════════════════════════════════════════════════
 * B. Timing
 * ═══════════════════════════════════════════════════════════════════════════ */

static inline int64_t time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static inline double ns_to_us(int64_t ns) { return ns / 1000.0; }
static inline double ns_to_ms(int64_t ns) { return ns / 1000000.0; }
static inline double ns_to_s(int64_t ns)  { return ns / 1000000000.0; }

struct latency_log {
    int64_t *samples;
    int      count;
    int      capacity;
};

static void lat_init(struct latency_log *l, int cap)
{
    l->capacity = cap;
    l->count = 0;
    l->samples = (int64_t *)malloc(cap * sizeof(int64_t));
}

static void lat_free(struct latency_log *l)
{
    free(l->samples);
    l->samples = NULL;
    l->count = 0;
}

static void lat_record(struct latency_log *l, int64_t ns)
{
    if (l->count < l->capacity)
        l->samples[l->count++] = ns;
}

static int cmp_i64(const void *a, const void *b)
{
    int64_t va = *(const int64_t *)a;
    int64_t vb = *(const int64_t *)b;
    if (va < vb) return -1;
    if (va > vb) return  1;
    return 0;
}

static void lat_sort(struct latency_log *l)
{
    qsort(l->samples, l->count, sizeof(int64_t), cmp_i64);
}

static int64_t lat_percentile(struct latency_log *l, double pct)
{
    if (l->count == 0) return 0;
    int idx = (int)(pct / 100.0 * (l->count - 1));
    if (idx >= l->count) idx = l->count - 1;
    return l->samples[idx];
}

/* ═══════════════════════════════════════════════════════════════════════════
 * C. Connection helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static int tcp_connect(const char *host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int opt = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    /* 10-second receive timeout prevents benchmark from hanging
     * if the server stops sending responses */
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static ssize_t send_all(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, p + sent, len - sent);
        if (n <= 0) return -1;
        sent += n;
    }
    return (ssize_t)sent;
}

/* Read until we've accumulated at least `expect` bytes or connection closes.
 * Returns total bytes read. */
static ssize_t recv_until(int fd, char *buf, size_t bufsz, size_t expect)
{
    size_t total = 0;
    while (total < expect) {
        ssize_t n = read(fd, buf + total, bufsz - total);
        if (n <= 0) break;
        total += n;
    }
    return (ssize_t)total;
}

/* Count newlines in buffer (for plaintext cache responses). */
static int count_newlines(const char *buf, size_t len)
{
    int cnt = 0;
    for (size_t i = 0; i < len; i++)
        if (buf[i] == '\n') cnt++;
    return cnt;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * D. Stats engine — multi-run executor with median selection
 * ═══════════════════════════════════════════════════════════════════════════ */

struct run_result {
    double throughput;     /* ops/sec or conn/sec or msg/sec */
    double throughput_mb;  /* MB/sec (if applicable, else 0) */
    int    success;
    int    failed;
    struct latency_log latencies;
};

static int cmp_double(const void *a, const void *b)
{
    double va = *(const double *)a;
    double vb = *(const double *)b;
    if (va < vb) return -1;
    if (va > vb) return  1;
    return 0;
}

static double median_double(double *arr, int n)
{
    qsort(arr, n, sizeof(double), cmp_double);
    if (n % 2 == 1) return arr[n / 2];
    return (arr[n / 2 - 1] + arr[n / 2]) / 2.0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * E. JSON output helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static void json_start(FILE *f) { fprintf(f, "{"); }
static void json_end(FILE *f)   { fprintf(f, "}\n"); }

static int json_first = 1;

static void json_sep(FILE *f)
{
    if (!json_first) fprintf(f, ",");
    json_first = 0;
}

static void json_kv_str(FILE *f, const char *key, const char *val)
{
    json_sep(f);
    fprintf(f, "\"%s\":\"%s\"", key, val);
}

static void json_kv_int(FILE *f, const char *key, int val)
{
    json_sep(f);
    fprintf(f, "\"%s\":%d", key, val);
}

static void json_kv_dbl(FILE *f, const char *key, double val)
{
    json_sep(f);
    fprintf(f, "\"%s\":%.2f", key, val);
}

static void json_reset(void) { json_first = 1; }

/* ═══════════════════════════════════════════════════════════════════════════
 * F. Cache protocol helpers (plaintext SET/GET pipeline builders)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Build a buffer of N pipelined SET commands:  "SET keyN <value>\n"
 * Returns malloc'd buffer; caller frees.  *out_len receives total length. */
static char *build_set_pipeline(int count, const char *value, int value_len,
                                size_t *out_len)
{
    /* estimate: "SET key" + digits + " " + value + "\n" per op */
    size_t est = (size_t)count * (10 + 7 + value_len + 2);
    char *buf = (char *)malloc(est);
    size_t off = 0;
    for (int i = 0; i < count; i++) {
        int n = sprintf(buf + off, "SET key%d %.*s\n", i, value_len, value);
        off += n;
    }
    *out_len = off;
    return buf;
}

/* Build a buffer of N pipelined GET commands:  "GET keyN\n" */
static char *build_get_pipeline(int count, size_t *out_len)
{
    size_t est = (size_t)count * 16;
    char *buf = (char *)malloc(est);
    size_t off = 0;
    for (int i = 0; i < count; i++) {
        int n = sprintf(buf + off, "GET key%d\n", i);
        off += n;
    }
    *out_len = off;
    return buf;
}

/* Build mixed 80% GET / 20% SET command buffer. Assumes keys 0..count-1 exist. */
static char *build_mixed_pipeline(int count, const char *value, int value_len,
                                  size_t *out_len)
{
    size_t est = (size_t)count * (10 + 7 + value_len + 2);
    char *buf = (char *)malloc(est);
    size_t off = 0;
    unsigned int seed = 42;
    int new_key = count;
    for (int i = 0; i < count; i++) {
        if ((rand_r(&seed) % 100) < 80) {
            int key_idx = rand_r(&seed) % count;
            int n = sprintf(buf + off, "GET key%d\n", key_idx);
            off += n;
        } else {
            int n = sprintf(buf + off, "SET key%d %.*s\n", new_key++, value_len, value);
            off += n;
        }
    }
    *out_len = off;
    return buf;
}

/* Send a full pipeline buffer and drain responses (count newlines until we
 * have `expected` responses). Returns number of responses received. */
static int pipeline_execute(int fd, const char *cmd_buf, size_t cmd_len,
                            int expected_responses)
{
    if (send_all(fd, cmd_buf, cmd_len) < 0)
        return 0;

    /* Drain responses: each response ends with \n */
    char rbuf[BUF_SIZE];
    int got = 0;
    while (got < expected_responses) {
        ssize_t n = read(fd, rbuf, sizeof(rbuf));
        if (n <= 0) break;
        got += count_newlines(rbuf, n);
    }
    return got;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * G. WebSocket helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static const char *WS_UPGRADE_FMT =
    "GET / HTTP/1.1\r\n"
    "Host: %s:%d\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "\r\n";

/* Send WS upgrade request. Returns 1 if got "101", 0 otherwise. */
static int ws_upgrade(int fd, const char *host, int port)
{
    char req[512];
    int len = snprintf(req, sizeof(req), WS_UPGRADE_FMT, host, port);
    if (send_all(fd, req, len) < 0) return 0;

    char resp[1024];
    ssize_t n = read(fd, resp, sizeof(resp) - 1);
    if (n <= 0) return 0;
    resp[n] = '\0';
    return strstr(resp, "101") != NULL;
}

/* Build a masked WebSocket text frame.
 * Returns frame length; frame written into `out` (must be >= payload_len+14). */
static int ws_build_frame(char *out, const char *payload, int payload_len)
{
    int off = 0;
    out[off++] = (char)0x81; /* FIN + text opcode */

    if (payload_len < 126) {
        out[off++] = (char)(0x80 | payload_len); /* MASK bit + len */
    } else {
        out[off++] = (char)(0x80 | 126);
        out[off++] = (char)((payload_len >> 8) & 0xFF);
        out[off++] = (char)(payload_len & 0xFF);
    }

    /* Mask key (fixed — not security-relevant for benchmarks) */
    char mask[4] = {0x12, 0x34, 0x56, 0x78};
    memcpy(out + off, mask, 4);
    off += 4;

    for (int i = 0; i < payload_len; i++)
        out[off++] = payload[i] ^ mask[i % 4];

    return off;
}

/* Read a WS frame, return payload length (-1 on error). */
static int ws_read_frame(int fd, char *buf, int bufsz)
{
    unsigned char hdr[2];
    ssize_t n = recv_until(fd, (char *)hdr, 2, 2);
    if (n < 2) return -1;

    int payload_len = hdr[1] & 0x7F;
    if (payload_len == 126) {
        unsigned char ext[2];
        if (recv_until(fd, (char *)ext, 2, 2) < 2) return -1;
        payload_len = (ext[0] << 8) | ext[1];
    } else if (payload_len == 127) {
        /* 8-byte length — unlikely in benchmarks */
        unsigned char ext[8];
        if (recv_until(fd, (char *)ext, 8, 8) < 8) return -1;
        payload_len = (int)((ext[4] << 24) | (ext[5] << 16) | (ext[6] << 8) | ext[7]);
    }

    if (payload_len > bufsz) payload_len = bufsz;
    if (payload_len > 0) {
        if (recv_until(fd, buf, payload_len, payload_len) < payload_len)
            return -1;
    }
    return payload_len;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * H. Server benchmarks
 * ═══════════════════════════════════════════════════════════════════════════ */

static struct run_result bench_server_conn(struct bench_config *cfg)
{
    struct run_result r = {0};
    lat_init(&r.latencies, cfg->num_ops);

    int warmup = cfg->num_ops * cfg->warmup_pct / 100;

    int64_t start = time_ns();

    for (int i = 0; i < cfg->num_ops; i++) {
        int64_t t0 = time_ns();
        int fd = tcp_connect(cfg->host, cfg->port);
        int64_t t1 = time_ns();

        if (fd >= 0) {
            close(fd);
            r.success++;
            if (i >= warmup)
                lat_record(&r.latencies, t1 - t0);
        } else {
            r.failed++;
        }
    }

    int64_t end = time_ns();
    double elapsed = ns_to_s(end - start);
    r.throughput = r.success / elapsed;

    return r;
}

static struct run_result bench_server_burst(struct bench_config *cfg)
{
    struct run_result r = {0};
    lat_init(&r.latencies, 1);

    int *fds = (int *)malloc(cfg->num_ops * sizeof(int));

    int64_t start = time_ns();

    for (int i = 0; i < cfg->num_ops; i++) {
        fds[i] = tcp_connect(cfg->host, cfg->port);
        if (fds[i] >= 0) r.success++;
        else r.failed++;
    }

    int64_t connected = time_ns();

    for (int i = 0; i < cfg->num_ops; i++) {
        if (fds[i] >= 0) close(fds[i]);
    }

    free(fds);

    double connect_s = ns_to_s(connected - start);
    r.throughput = r.success / connect_s;

    /* Let the server drain EOF CQEs from the closed connections before the
       next run starts.  Without this, the server's io_uring event loop is
       still processing teardowns when the next burst begins, and accept
       latency jumps from ~10µs to ~215µs (27x slower). */
    struct timespec drain = { .tv_sec = 1, .tv_nsec = 0 };
    nanosleep(&drain, NULL);

    return r;
}

static struct run_result bench_server_msg(struct bench_config *cfg)
{
    struct run_result r = {0};
    lat_init(&r.latencies, cfg->num_ops);

    int fd = tcp_connect(cfg->host, cfg->port);
    if (fd < 0) { r.failed = cfg->num_ops; return r; }

    char *msg = (char *)malloc(cfg->msg_size + 1);
    memset(msg, 'X', cfg->msg_size);
    msg[cfg->msg_size] = '\n';

    int warmup = cfg->num_ops * cfg->warmup_pct / 100;

    int64_t start = time_ns();

    for (int i = 0; i < cfg->num_ops; i++) {
        int64_t t0 = time_ns();
        ssize_t n = send_all(fd, msg, cfg->msg_size + 1);
        int64_t t1 = time_ns();

        if (n == cfg->msg_size + 1) {
            r.success++;
            if (i >= warmup)
                lat_record(&r.latencies, t1 - t0);
        } else {
            r.failed++;
            break;
        }
    }

    int64_t end = time_ns();
    close(fd);
    free(msg);

    double elapsed = ns_to_s(end - start);
    r.throughput = r.success / elapsed;
    r.throughput_mb = (r.success * (double)(cfg->msg_size + 1)) / elapsed / (1024.0 * 1024.0);

    return r;
}

/* Concurrent server benchmark — threaded */
struct server_concurrent_args {
    struct bench_config *cfg;
    int                  thread_success;
};

static void *server_concurrent_worker(void *arg)
{
    struct server_concurrent_args *a = (struct server_concurrent_args *)arg;
    struct bench_config *cfg = a->cfg;

    int fd = tcp_connect(cfg->host, cfg->port);
    if (fd < 0) return NULL;

    char *msg = (char *)malloc(cfg->msg_size + 1);
    memset(msg, 'Y', cfg->msg_size);
    msg[cfg->msg_size] = '\n';

    int local = 0;
    for (int i = 0; i < cfg->num_ops; i++) {
        if (send_all(fd, msg, cfg->msg_size + 1) == cfg->msg_size + 1) local++;
        else break;
    }

    close(fd);
    free(msg);
    a->thread_success = local;
    return NULL;
}

static struct run_result bench_server_concurrent(struct bench_config *cfg)
{
    struct run_result r = {0};
    lat_init(&r.latencies, 1);

    int nc = cfg->num_clients;
    int msgs = cfg->num_ops; /* per client */

    pthread_t *threads = (pthread_t *)malloc(nc * sizeof(pthread_t));
    struct server_concurrent_args *args =
        (struct server_concurrent_args *)malloc(nc * sizeof(*args));

    int64_t start = time_ns();

    for (int i = 0; i < nc; i++) {
        args[i].cfg = cfg;
        args[i].thread_success = 0;
        pthread_create(&threads[i], NULL, server_concurrent_worker, &args[i]);
    }

    for (int i = 0; i < nc; i++)
        pthread_join(threads[i], NULL);

    int64_t end = time_ns();

    int total = 0;
    for (int i = 0; i < nc; i++)
        total += args[i].thread_success;

    free(threads);
    free(args);

    double elapsed = ns_to_s(end - start);
    r.success = total;
    r.throughput = total / elapsed;

    return r;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * I. Cache benchmarks
 * ═══════════════════════════════════════════════════════════════════════════ */

static struct run_result bench_cache_set(struct bench_config *cfg)
{
    struct run_result r = {0};
    lat_init(&r.latencies, 1);

    int fd = tcp_connect(cfg->host, cfg->port);
    if (fd < 0) { r.failed = cfg->num_ops; return r; }

    /* Build value */
    char value[4096];
    int vlen = cfg->msg_size > 0 ? cfg->msg_size : 64;
    if (vlen > (int)sizeof(value)) vlen = (int)sizeof(value);
    memset(value, 'V', vlen);

    size_t cmd_len;
    char *cmd_buf = build_set_pipeline(cfg->num_ops, value, vlen, &cmd_len);

    int64_t start = time_ns();
    r.success = pipeline_execute(fd, cmd_buf, cmd_len, cfg->num_ops);
    int64_t end = time_ns();

    close(fd);
    free(cmd_buf);

    double elapsed = ns_to_s(end - start);
    r.throughput = r.success / elapsed;
    r.throughput_mb = (r.success * (double)vlen) / elapsed / (1024.0 * 1024.0);

    return r;
}

static struct run_result bench_cache_get(struct bench_config *cfg)
{
    struct run_result r = {0};
    lat_init(&r.latencies, 1);

    int fd = tcp_connect(cfg->host, cfg->port);
    if (fd < 0) { r.failed = cfg->num_ops; return r; }

    /* Pre-populate */
    char value[64];
    memset(value, 'V', sizeof(value));
    size_t pop_len;
    char *pop_buf = build_set_pipeline(cfg->num_ops, value, 64, &pop_len);
    pipeline_execute(fd, pop_buf, pop_len, cfg->num_ops);
    free(pop_buf);

    /* Benchmark GETs */
    size_t cmd_len;
    char *cmd_buf = build_get_pipeline(cfg->num_ops, &cmd_len);

    int64_t start = time_ns();
    r.success = pipeline_execute(fd, cmd_buf, cmd_len, cfg->num_ops);
    int64_t end = time_ns();

    close(fd);
    free(cmd_buf);

    double elapsed = ns_to_s(end - start);
    r.throughput = r.success / elapsed;

    return r;
}

static struct run_result bench_cache_mixed(struct bench_config *cfg)
{
    struct run_result r = {0};
    lat_init(&r.latencies, 1);

    int fd = tcp_connect(cfg->host, cfg->port);
    if (fd < 0) { r.failed = cfg->num_ops; return r; }

    /* Pre-populate 20% of keys */
    char value[64];
    memset(value, 'V', sizeof(value));
    int prepop = cfg->num_ops / 5;
    if (prepop > 0) {
        size_t pop_len;
        char *pop_buf = build_set_pipeline(prepop, value, 64, &pop_len);
        pipeline_execute(fd, pop_buf, pop_len, prepop);
        free(pop_buf);
    }

    /* Build mixed pipeline */
    size_t cmd_len;
    char *cmd_buf = build_mixed_pipeline(cfg->num_ops, value, 64, &cmd_len);

    int64_t start = time_ns();
    r.success = pipeline_execute(fd, cmd_buf, cmd_len, cfg->num_ops);
    int64_t end = time_ns();

    close(fd);
    free(cmd_buf);

    double elapsed = ns_to_s(end - start);
    r.throughput = r.success / elapsed;

    return r;
}

/* Concurrent cache — threaded pipeline clients */
struct cache_concurrent_args {
    struct bench_config *cfg;
    int                  client_id;
    int                  thread_success;
};

static void *cache_concurrent_worker(void *arg)
{
    struct cache_concurrent_args *a = (struct cache_concurrent_args *)arg;
    struct bench_config *cfg = a->cfg;

    int fd = tcp_connect(cfg->host, cfg->port);
    if (fd < 0) return NULL;

    char value[64];
    memset(value, 'V', sizeof(value));

    /* Build per-client pipeline: "SET cN_keyM value\n"
     * Max per line: "SET c" + 3 digits + "_key" + 7 digits + " " + 64 + "\n" = ~85 */
    int ops = cfg->num_ops;
    size_t est = (size_t)ops * 96;
    char *buf = (char *)malloc(est);
    size_t off = 0;
    for (int i = 0; i < ops; i++) {
        int n = snprintf(buf + off, est - off, "SET c%d_key%d %.64s\n",
                         a->client_id, i, value);
        if (n < 0 || off + n >= est) break;
        off += n;
    }

    a->thread_success = pipeline_execute(fd, buf, off, ops);
    close(fd);
    free(buf);
    return NULL;
}

static struct run_result bench_cache_concurrent(struct bench_config *cfg)
{
    struct run_result r = {0};
    lat_init(&r.latencies, 1);

    int nc = cfg->num_clients;
    pthread_t *threads = (pthread_t *)malloc(nc * sizeof(pthread_t));
    struct cache_concurrent_args *args =
        (struct cache_concurrent_args *)malloc(nc * sizeof(*args));

    int64_t start = time_ns();

    for (int i = 0; i < nc; i++) {
        args[i].cfg = cfg;
        args[i].client_id = i;
        args[i].thread_success = 0;
        pthread_create(&threads[i], NULL, cache_concurrent_worker, &args[i]);
    }

    for (int i = 0; i < nc; i++)
        pthread_join(threads[i], NULL);

    int64_t end = time_ns();

    int total = 0;
    for (int i = 0; i < nc; i++)
        total += args[i].thread_success;

    free(threads);
    free(args);

    double elapsed = ns_to_s(end - start);
    r.success = total;
    r.throughput = total / elapsed;

    return r;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * J. Proxy benchmarks
 * ═══════════════════════════════════════════════════════════════════════════ */

static struct run_result bench_proxy_tcp(struct bench_config *cfg)
{
    struct run_result r = {0};
    lat_init(&r.latencies, cfg->num_ops);

    int fd = tcp_connect(cfg->host, cfg->port);
    if (fd < 0) { r.failed = cfg->num_ops; return r; }

    int msize = cfg->msg_size > 0 ? cfg->msg_size : 128;
    char *msg = (char *)malloc(msize + 1);
    memset(msg, 'P', msize);
    msg[msize] = '\n';

    int warmup = cfg->num_ops * cfg->warmup_pct / 100;

    int64_t start = time_ns();

    for (int i = 0; i < cfg->num_ops; i++) {
        int64_t t0 = time_ns();
        ssize_t n = write(fd, msg, msize + 1);
        int64_t t1 = time_ns();

        if (n == msize + 1) {
            r.success++;
            if (i >= warmup)
                lat_record(&r.latencies, t1 - t0);
        } else {
            r.failed++;
        }
    }

    int64_t end = time_ns();
    close(fd);
    free(msg);

    double elapsed = ns_to_s(end - start);
    r.throughput = r.success / elapsed;
    r.throughput_mb = (r.success * (double)(msize + 1)) / elapsed / (1024.0 * 1024.0);

    return r;
}

/* Concurrent proxy — threaded */
struct proxy_concurrent_args {
    struct bench_config *cfg;
    int                  thread_success;
};

static void *proxy_concurrent_worker(void *arg)
{
    struct proxy_concurrent_args *a = (struct proxy_concurrent_args *)arg;
    struct bench_config *cfg = a->cfg;

    int fd = tcp_connect(cfg->host, cfg->port);
    if (fd < 0) return NULL;

    int msize = cfg->msg_size > 0 ? cfg->msg_size : 128;
    char *msg = (char *)malloc(msize + 1);
    memset(msg, 'P', msize);
    msg[msize] = '\n';

    int local = 0;
    for (int i = 0; i < cfg->num_ops; i++) {
        ssize_t n = write(fd, msg, msize + 1);
        if (n == msize + 1) local++;
    }

    close(fd);
    free(msg);
    a->thread_success = local;
    return NULL;
}

static struct run_result bench_proxy_concurrent(struct bench_config *cfg)
{
    struct run_result r = {0};
    lat_init(&r.latencies, 1);

    int nc = cfg->num_clients;
    pthread_t *threads = (pthread_t *)malloc(nc * sizeof(pthread_t));
    struct proxy_concurrent_args *args =
        (struct proxy_concurrent_args *)malloc(nc * sizeof(*args));

    int64_t start = time_ns();

    for (int i = 0; i < nc; i++) {
        args[i].cfg = cfg;
        args[i].thread_success = 0;
        pthread_create(&threads[i], NULL, proxy_concurrent_worker, &args[i]);
    }

    for (int i = 0; i < nc; i++)
        pthread_join(threads[i], NULL);

    int64_t end = time_ns();

    int total = 0;
    for (int i = 0; i < nc; i++)
        total += args[i].thread_success;

    free(threads);
    free(args);

    double elapsed = ns_to_s(end - start);
    r.success = total;
    r.throughput = total / elapsed;

    return r;
}

/* Proxy overhead: measure direct vs proxied throughput on same message pattern */
static void bench_proxy_overhead(struct bench_config *cfg)
{
    int msize = cfg->msg_size > 0 ? cfg->msg_size : 128;
    char *msg = (char *)malloc(msize + 1);
    memset(msg, 'O', msize);
    msg[msize] = '\n';

    double direct_rate = 0, proxied_rate = 0;

    /* Direct to backend (port2) */
    {
        int fd = tcp_connect(cfg->host, cfg->port2);
        if (fd >= 0) {
            int success = 0;
            int64_t start = time_ns();
            for (int i = 0; i < cfg->num_ops; i++) {
                ssize_t n = write(fd, msg, msize + 1);
                if (n == msize + 1) success++;
            }
            int64_t end = time_ns();
            close(fd);
            direct_rate = success / ns_to_s(end - start);
        }
    }

    /* Through proxy (port) */
    {
        int fd = tcp_connect(cfg->host, cfg->port);
        if (fd >= 0) {
            int success = 0;
            int64_t start = time_ns();
            for (int i = 0; i < cfg->num_ops; i++) {
                ssize_t n = write(fd, msg, msize + 1);
                if (n == msize + 1) success++;
            }
            int64_t end = time_ns();
            close(fd);
            proxied_rate = success / ns_to_s(end - start);
        }
    }

    free(msg);

    double overhead_pct = 0;
    if (direct_rate > 0)
        overhead_pct = (1.0 - proxied_rate / direct_rate) * 100.0;

    if (cfg->json) {
        json_reset();
        json_start(stdout);
        json_kv_str(stdout, "test", "proxy_overhead");
        json_kv_int(stdout, "operations", cfg->num_ops);
        json_kv_dbl(stdout, "direct_msg_per_sec", direct_rate);
        json_kv_dbl(stdout, "proxied_msg_per_sec", proxied_rate);
        json_kv_dbl(stdout, "overhead_percent", overhead_pct);
        json_end(stdout);
    } else {
        printf("socketley-bench: proxy overhead  %s  %d ops  direct=%d  proxied=%d\n\n",
               cfg->host, cfg->num_ops, cfg->port2, cfg->port);
        printf("  Direct:   %12.0f msg/sec\n", direct_rate);
        printf("  Proxied:  %12.0f msg/sec\n", proxied_rate);
        printf("  Overhead: %11.1f%%\n", overhead_pct);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * K. WebSocket benchmarks
 * ═══════════════════════════════════════════════════════════════════════════ */

static struct run_result bench_ws_handshake(struct bench_config *cfg)
{
    struct run_result r = {0};
    lat_init(&r.latencies, cfg->num_ops);

    int warmup = cfg->num_ops * cfg->warmup_pct / 100;

    int64_t start = time_ns();

    for (int i = 0; i < cfg->num_ops; i++) {
        int64_t t0 = time_ns();
        int fd = tcp_connect(cfg->host, cfg->port);
        if (fd < 0) { r.failed++; continue; }

        int ok = ws_upgrade(fd, cfg->host, cfg->port);
        int64_t t1 = time_ns();
        close(fd);

        if (ok) {
            r.success++;
            if (i >= warmup)
                lat_record(&r.latencies, t1 - t0);
        } else {
            r.failed++;
        }
    }

    int64_t end = time_ns();
    double elapsed = ns_to_s(end - start);
    r.throughput = r.success / elapsed;

    return r;
}

/* WS frame send throughput — measures how fast we can push masked frames
 * over an established WS connection. No echo expected from the server. */
static struct run_result bench_ws_echo(struct bench_config *cfg)
{
    struct run_result r = {0};
    lat_init(&r.latencies, cfg->num_ops);

    /* Connect + WS upgrade with retry.  After the previous run closes a
       connection that had thousands of in-flight echo writes, the server's
       io_uring ring is flooded with write-error CQEs.  The accept/read for
       the next connection may be delayed or lost (CQ overflow), so retry
       the handshake a few times with a brief pause. */
    int fd = -1;
    for (int attempt = 0; attempt < 5; attempt++) {
        fd = tcp_connect(cfg->host, cfg->port);
        if (fd >= 0 && ws_upgrade(fd, cfg->host, cfg->port))
            break;
        if (fd >= 0) close(fd);
        fd = -1;
        struct timespec pause = { .tv_sec = 0, .tv_nsec = 100000000 }; /* 100 ms */
        nanosleep(&pause, NULL);
    }
    if (fd < 0) { r.failed = cfg->num_ops; return r; }

    int msize = cfg->msg_size > 0 ? cfg->msg_size : 64;
    char *payload = (char *)malloc(msize);
    memset(payload, 'E', msize);

    char *frame = (char *)malloc(msize + 14);
    int frame_len = ws_build_frame(frame, payload, msize);

    int warmup = cfg->num_ops * cfg->warmup_pct / 100;

    int64_t start = time_ns();

    for (int i = 0; i < cfg->num_ops; i++) {
        int64_t t0 = time_ns();

        if (send_all(fd, frame, frame_len) < 0) {
            r.failed++;
            break;
        }
        int64_t t1 = time_ns();

        r.success++;
        if (i >= warmup)
            lat_record(&r.latencies, t1 - t0);
    }

    int64_t end = time_ns();
    close(fd);
    free(payload);
    free(frame);

    double elapsed = ns_to_s(end - start);
    r.throughput = r.success / elapsed;
    r.throughput_mb = (r.success * (double)(frame_len)) / elapsed / (1024.0 * 1024.0);

    /* Let the server drain echo-error CQEs before the next run. */
    struct timespec drain = { .tv_sec = 0, .tv_nsec = 500000000 }; /* 500 ms */
    nanosleep(&drain, NULL);

    return r;
}

/* Concurrent WS — threaded handshakes */
struct ws_concurrent_args {
    struct bench_config *cfg;
    int                  thread_success;
};

static void *ws_concurrent_worker(void *arg)
{
    struct ws_concurrent_args *a = (struct ws_concurrent_args *)arg;
    struct bench_config *cfg = a->cfg;

    int local = 0;
    for (int i = 0; i < cfg->num_ops; i++) {
        int fd = tcp_connect(cfg->host, cfg->port);
        if (fd < 0) continue;
        if (ws_upgrade(fd, cfg->host, cfg->port))
            local++;
        close(fd);
    }

    a->thread_success = local;
    return NULL;
}

static struct run_result bench_ws_concurrent(struct bench_config *cfg)
{
    struct run_result r = {0};
    lat_init(&r.latencies, 1);

    int nc = cfg->num_clients;
    pthread_t *threads = (pthread_t *)malloc(nc * sizeof(pthread_t));
    struct ws_concurrent_args *args =
        (struct ws_concurrent_args *)malloc(nc * sizeof(*args));

    int64_t start = time_ns();

    for (int i = 0; i < nc; i++) {
        args[i].cfg = cfg;
        args[i].thread_success = 0;
        pthread_create(&threads[i], NULL, ws_concurrent_worker, &args[i]);
    }

    for (int i = 0; i < nc; i++)
        pthread_join(threads[i], NULL);

    int64_t end = time_ns();

    int total = 0;
    for (int i = 0; i < nc; i++)
        total += args[i].thread_success;

    free(threads);
    free(args);

    double elapsed = ns_to_s(end - start);
    r.success = total;
    r.throughput = total / elapsed;

    return r;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Multi-run executor + output
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct run_result (*bench_fn)(struct bench_config *);

static void run_and_report(struct bench_config *cfg, bench_fn fn,
                           const char *category, const char *test,
                           const char *unit)
{
    int runs = cfg->runs;
    double *throughputs = (double *)malloc(runs * sizeof(double));
    double *throughputs_mb = (double *)malloc(runs * sizeof(double));
    struct run_result best = {0};
    lat_init(&best.latencies, 1);

    /* Find the run with the median throughput to extract its latencies */
    struct run_result *all_results =
        (struct run_result *)malloc(runs * sizeof(struct run_result));

    for (int i = 0; i < runs; i++) {
        all_results[i] = fn(cfg);
        throughputs[i] = all_results[i].throughput;
        throughputs_mb[i] = all_results[i].throughput_mb;
    }

    double med = median_double(throughputs, runs);
    double med_mb = median_double(throughputs_mb, runs);

    /* Find the run closest to median for latency data */
    int best_idx = 0;
    double best_diff = 1e18;
    for (int i = 0; i < runs; i++) {
        /* re-read from all_results since throughputs was sorted by median_double */
        double diff = fabs(all_results[i].throughput - med);
        if (diff < best_diff) {
            best_diff = diff;
            best_idx = i;
        }
    }

    struct latency_log *lat = &all_results[best_idx].latencies;
    lat_sort(lat);

    if (cfg->json) {
        json_reset();
        json_start(stdout);
        json_kv_str(stdout, "test", test);
        json_kv_str(stdout, "category", category);
        json_kv_int(stdout, "runs", runs);
        json_kv_int(stdout, "operations", cfg->num_ops);
        json_kv_dbl(stdout, "median_throughput", med);
        if (med_mb > 0)
            json_kv_dbl(stdout, "median_throughput_mb", med_mb);
        json_kv_int(stdout, "success", all_results[best_idx].success);
        json_kv_int(stdout, "failed", all_results[best_idx].failed);
        if (lat->count > 0) {
            json_kv_dbl(stdout, "lat_min_us", ns_to_us(lat_percentile(lat, 0)));
            json_kv_dbl(stdout, "lat_p50_us", ns_to_us(lat_percentile(lat, 50)));
            json_kv_dbl(stdout, "lat_p95_us", ns_to_us(lat_percentile(lat, 95)));
            json_kv_dbl(stdout, "lat_p99_us", ns_to_us(lat_percentile(lat, 99)));
            json_kv_dbl(stdout, "lat_max_us", ns_to_us(lat_percentile(lat, 100)));
        }
        /* Per-run throughputs */
        fprintf(stdout, ",\"per_run\":[");
        for (int i = 0; i < runs; i++) {
            if (i > 0) fprintf(stdout, ",");
            fprintf(stdout, "%.2f", all_results[i].throughput);
        }
        fprintf(stdout, "]");
        json_end(stdout);
    } else {
        printf("socketley-bench: %s %s  %s:%d  %d ops  %d runs\n\n",
               category, test, cfg->host, cfg->port, cfg->num_ops, runs);

        for (int i = 0; i < runs; i++) {
            printf("  Run %d:  %12.0f %s", i + 1, all_results[i].throughput, unit);
            if (all_results[i].throughput_mb > 0)
                printf("  (%.1f MB/s)", all_results[i].throughput_mb);
            printf("\n");
        }

        printf("\n  Median: %12.0f %s", med, unit);
        if (med_mb > 0)
            printf("  (%.1f MB/s)", med_mb);
        printf("\n");

        if (lat->count > 0) {
            printf("  Latency (us):  min=%.1f  p50=%.1f  p95=%.1f  p99=%.1f  max=%.1f\n",
                   ns_to_us(lat_percentile(lat, 0)),
                   ns_to_us(lat_percentile(lat, 50)),
                   ns_to_us(lat_percentile(lat, 95)),
                   ns_to_us(lat_percentile(lat, 99)),
                   ns_to_us(lat_percentile(lat, 100)));
        }

        printf("  Success: %d  Failed: %d\n", all_results[best_idx].success,
               all_results[best_idx].failed);
    }

    for (int i = 0; i < runs; i++)
        lat_free(&all_results[i].latencies);
    free(all_results);
    free(throughputs);
    free(throughputs_mb);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * L. Main / argument parsing
 * ═══════════════════════════════════════════════════════════════════════════ */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS] <category> <test> <host> <port> [params...]\n"
        "\n"
        "Options:\n"
        "  -j          JSON output\n"
        "  -r N        Number of runs (default %d)\n"
        "  -w N        Warm-up percentage (default %d)\n"
        "\n"
        "Categories and tests:\n"
        "  server conn <count>                  Connection rate\n"
        "  server burst <count>                 Burst connections\n"
        "  server msg <count> <size>            Message throughput\n"
        "  server concurrent <clients> <msgs>   Multi-client throughput\n"
        "\n"
        "  cache set <count> [value_size]        SET throughput\n"
        "  cache get <count>                     GET throughput\n"
        "  cache mixed <count>                   80/20 GET/SET mix\n"
        "  cache concurrent <clients> <ops>      Multi-client\n"
        "\n"
        "  proxy tcp <count> [msg_size]          TCP forwarding\n"
        "  proxy concurrent <clients> <msgs>     Multi-client\n"
        "  proxy overhead <count> <backend_port> Direct vs proxied\n"
        "\n"
        "  ws handshake <count>                  WS upgrade rate\n"
        "  ws echo <count> [msg_size]            WS echo RTT\n"
        "  ws concurrent <clients> <ops>         Multi-client WS\n",
        prog, DEFAULT_RUNS, DEFAULT_WARMUP);
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);

    struct bench_config cfg = {0};
    cfg.runs = DEFAULT_RUNS;
    cfg.warmup_pct = DEFAULT_WARMUP;
    cfg.msg_size = 64;
    cfg.num_clients = 20;
    cfg.num_ops = 10000;

    /* Parse options */
    int optind_local = 1;
    while (optind_local < argc && argv[optind_local][0] == '-') {
        const char *opt = argv[optind_local];
        if (strcmp(opt, "-j") == 0) {
            cfg.json = 1;
            optind_local++;
        } else if (strcmp(opt, "-r") == 0 && optind_local + 1 < argc) {
            cfg.runs = atoi(argv[optind_local + 1]);
            if (cfg.runs < 1) cfg.runs = 1;
            optind_local += 2;
        } else if (strcmp(opt, "-w") == 0 && optind_local + 1 < argc) {
            cfg.warmup_pct = atoi(argv[optind_local + 1]);
            if (cfg.warmup_pct < 0) cfg.warmup_pct = 0;
            if (cfg.warmup_pct > 50) cfg.warmup_pct = 50;
            optind_local += 2;
        } else if (strcmp(opt, "--help") == 0 || strcmp(opt, "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", opt);
            usage(argv[0]);
            return 1;
        }
    }

    /* Need at least: category test host port */
    int remaining = argc - optind_local;
    if (remaining < 4) {
        usage(argv[0]);
        return 1;
    }

    const char *category = argv[optind_local];
    const char *test     = argv[optind_local + 1];
    cfg.host             = argv[optind_local + 2];
    cfg.port             = atoi(argv[optind_local + 3]);

    /* Parse per-test params from argv[optind_local + 4 ...] */
    int pstart = optind_local + 4;
    int pcount = argc - pstart;

    /* ── server ── */
    if (strcmp(category, "server") == 0) {
        if (strcmp(test, "conn") == 0) {
            if (pcount >= 1) cfg.num_ops = atoi(argv[pstart]);
            run_and_report(&cfg, bench_server_conn, "server", "conn", "conn/sec");
        }
        else if (strcmp(test, "burst") == 0) {
            if (pcount >= 1) cfg.num_ops = atoi(argv[pstart]);
            run_and_report(&cfg, bench_server_burst, "server", "burst", "conn/sec");
        }
        else if (strcmp(test, "msg") == 0) {
            if (pcount >= 1) cfg.num_ops = atoi(argv[pstart]);
            if (pcount >= 2) cfg.msg_size = atoi(argv[pstart + 1]);
            run_and_report(&cfg, bench_server_msg, "server", "msg", "msg/sec");
        }
        else if (strcmp(test, "concurrent") == 0) {
            if (pcount >= 1) cfg.num_clients = atoi(argv[pstart]);
            if (pcount >= 2) cfg.num_ops = atoi(argv[pstart + 1]);
            run_and_report(&cfg, bench_server_concurrent, "server", "concurrent", "msg/sec");
        }
        else {
            fprintf(stderr, "Unknown server test: %s\n", test);
            return 1;
        }
    }
    /* ── cache ── */
    else if (strcmp(category, "cache") == 0) {
        if (strcmp(test, "set") == 0) {
            if (pcount >= 1) cfg.num_ops = atoi(argv[pstart]);
            if (pcount >= 2) cfg.msg_size = atoi(argv[pstart + 1]);
            run_and_report(&cfg, bench_cache_set, "cache", "set", "ops/sec");
        }
        else if (strcmp(test, "get") == 0) {
            if (pcount >= 1) cfg.num_ops = atoi(argv[pstart]);
            run_and_report(&cfg, bench_cache_get, "cache", "get", "ops/sec");
        }
        else if (strcmp(test, "mixed") == 0) {
            if (pcount >= 1) cfg.num_ops = atoi(argv[pstart]);
            run_and_report(&cfg, bench_cache_mixed, "cache", "mixed", "ops/sec");
        }
        else if (strcmp(test, "concurrent") == 0) {
            if (pcount >= 1) cfg.num_clients = atoi(argv[pstart]);
            if (pcount >= 2) cfg.num_ops = atoi(argv[pstart + 1]);
            run_and_report(&cfg, bench_cache_concurrent, "cache", "concurrent", "ops/sec");
        }
        else {
            fprintf(stderr, "Unknown cache test: %s\n", test);
            return 1;
        }
    }
    /* ── proxy ── */
    else if (strcmp(category, "proxy") == 0) {
        if (strcmp(test, "tcp") == 0) {
            if (pcount >= 1) cfg.num_ops = atoi(argv[pstart]);
            if (pcount >= 2) cfg.msg_size = atoi(argv[pstart + 1]);
            run_and_report(&cfg, bench_proxy_tcp, "proxy", "tcp", "msg/sec");
        }
        else if (strcmp(test, "concurrent") == 0) {
            if (pcount >= 1) cfg.num_clients = atoi(argv[pstart]);
            if (pcount >= 2) cfg.num_ops = atoi(argv[pstart + 1]);
            run_and_report(&cfg, bench_proxy_concurrent, "proxy", "concurrent", "msg/sec");
        }
        else if (strcmp(test, "overhead") == 0) {
            if (pcount >= 1) cfg.num_ops = atoi(argv[pstart]);
            if (pcount >= 2) cfg.port2 = atoi(argv[pstart + 1]);
            bench_proxy_overhead(&cfg);
        }
        else {
            fprintf(stderr, "Unknown proxy test: %s\n", test);
            return 1;
        }
    }
    /* ── ws ── */
    else if (strcmp(category, "ws") == 0) {
        if (strcmp(test, "handshake") == 0) {
            if (pcount >= 1) cfg.num_ops = atoi(argv[pstart]);
            run_and_report(&cfg, bench_ws_handshake, "ws", "handshake", "handshake/sec");
        }
        else if (strcmp(test, "echo") == 0) {
            if (pcount >= 1) cfg.num_ops = atoi(argv[pstart]);
            if (pcount >= 2) cfg.msg_size = atoi(argv[pstart + 1]);
            run_and_report(&cfg, bench_ws_echo, "ws", "echo", "frame/sec");
        }
        else if (strcmp(test, "concurrent") == 0) {
            if (pcount >= 1) cfg.num_clients = atoi(argv[pstart]);
            if (pcount >= 2) cfg.num_ops = atoi(argv[pstart + 1]);
            run_and_report(&cfg, bench_ws_concurrent, "ws", "concurrent", "handshake/sec");
        }
        else {
            fprintf(stderr, "Unknown ws test: %s\n", test);
            return 1;
        }
    }
    else {
        fprintf(stderr, "Unknown category: %s\n", category);
        usage(argv[0]);
        return 1;
    }

    return 0;
}
