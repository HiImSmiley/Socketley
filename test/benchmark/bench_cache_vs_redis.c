/*
 * Cache vs Redis Benchmark — Full Data Structure Comparison
 * Tests: Strings, Lists, Sets, Hashes, TTL, Concurrent, Pipeline
 *
 * Both socketley cache and Redis accept inline commands over TCP.
 * Redis RESP responses have different newline counts for bulk strings.
 *
 * Compile: gcc -O3 -o bench_cache_vs_redis bench_cache_vs_redis.c -lpthread
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <pthread.h>
#include <errno.h>

/* ── Timing ── */

static inline long long get_time_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000LL + tv.tv_usec;
}

/* ── Connection ── */

static int connect_to(const char* host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int opt = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

/* Read until we get expected number of newlines */
static int read_responses(int fd, int expected_nl, char* buf, int buf_size)
{
    int total_read = 0;
    int newlines = 0;

    while (newlines < expected_nl && total_read < buf_size - 1)
    {
        int n = read(fd, buf + total_read, buf_size - 1 - total_read);
        if (n <= 0) break;
        for (int i = total_read; i < total_read + n; i++)
        {
            if (buf[i] == '\n') newlines++;
        }
        total_read += n;
    }
    buf[total_read] = '\0';
    return newlines;
}

/* Send full buffer, handling partial writes */
static int send_all(int fd, const char* buf, int len)
{
    int total = 0;
    while (total < len)
    {
        int n = write(fd, buf + total, len - total);
        if (n <= 0) return -1;
        total += n;
    }
    return total;
}

/* ── Helpers ── */

static void print_sep(void)
{
    printf("  ────────────────────────────────────────────────────────────────────\n");
}

typedef struct {
    double rate;
    int responses;
    double elapsed_s;
} bench_result;

/*
 * Generic pipelined benchmark: build commands, send all, read responses, measure.
 * nl_per_resp: newlines per response (1 for most, 2 for Redis bulk-string reads)
 */
static bench_result run_pipeline(const char* host, int port, const char* cmd_buf,
                                  int cmd_len, int num_ops, int nl_per_resp)
{
    bench_result r = {0};

    int fd = connect_to(host, port);
    if (fd < 0) return r;

    int recv_size = num_ops * 128;
    if (recv_size < 65536) recv_size = 65536;
    char* recv_buf = malloc(recv_size);

    long long start = get_time_us();
    if (send_all(fd, cmd_buf, cmd_len) < 0) { close(fd); free(recv_buf); return r; }
    r.responses = read_responses(fd, num_ops * nl_per_resp, recv_buf, recv_size);
    long long end = get_time_us();

    close(fd);
    free(recv_buf);

    r.elapsed_s = (end - start) / 1000000.0;
    r.rate = num_ops / r.elapsed_s;
    return r;
}

/* ================================================================
 * Test: Pipelined SET (strings)
 * ================================================================ */
static void test_set(const char* host, int port, int count, int val_size, const char* label)
{
    char* value = malloc(val_size + 1);
    memset(value, 'V', val_size);
    value[val_size] = '\0';

    int est = (int)(30 + val_size) * count;
    char* cmd = malloc(est);
    int off = 0;
    for (int i = 0; i < count; i++)
        off += sprintf(cmd + off, "SET sk%06d %s\n", i, value);

    bench_result r = run_pipeline(host, port, cmd, off, count, 1);
    printf("  [%-9s] SET %5d x %4dB: %10.0f ops/sec  (%.3fs)\n",
           label, count, val_size, r.rate, r.elapsed_s);

    free(value);
    free(cmd);
}

/* ================================================================
 * Test: Pipelined GET (strings, pre-populated)
 * ================================================================ */
static void test_get(const char* host, int port, int count, int nl_per_resp, const char* label)
{
    /* Populate */
    int fd = connect_to(host, port);
    if (fd < 0) { printf("  [%-9s] GET CONNECT FAILED\n", label); return; }

    char* cmd = malloc((size_t)80 * count);
    int off = 0;
    for (int i = 0; i < count; i++)
        off += sprintf(cmd + off, "SET gk%06d val%06d\n", i, i);

    send_all(fd, cmd, off);
    char* drain = malloc(count * 64);
    read_responses(fd, count, drain, count * 64);
    close(fd);

    /* Benchmark GET */
    off = 0;
    for (int i = 0; i < count; i++)
        off += sprintf(cmd + off, "GET gk%06d\n", i);

    bench_result r = run_pipeline(host, port, cmd, off, count, nl_per_resp);
    printf("  [%-9s] GET %5d keys:     %10.0f ops/sec  (%.3fs)\n",
           label, count, r.rate, r.elapsed_s);

    free(cmd);
    free(drain);
}

/* ================================================================
 * Test: Pipelined LPUSH (lists)
 * ================================================================ */
static void test_lpush(const char* host, int port, int count, const char* label)
{
    char* cmd = malloc((size_t)80 * count);
    int off = 0;
    for (int i = 0; i < count; i++)
        off += sprintf(cmd + off, "LPUSH benchlist item%06d\n", i);

    bench_result r = run_pipeline(host, port, cmd, off, count, 1);
    printf("  [%-9s] LPUSH %5d:         %10.0f ops/sec  (%.3fs)\n",
           label, count, r.rate, r.elapsed_s);

    free(cmd);
}

/* ================================================================
 * Test: Pipelined LPOP (lists, pre-populated)
 * ================================================================ */
static void test_lpop(const char* host, int port, int count, int nl_per_resp, const char* label)
{
    /* Populate via RPUSH */
    int fd = connect_to(host, port);
    if (fd < 0) return;

    char* cmd = malloc((size_t)80 * count);
    int off = 0;
    for (int i = 0; i < count; i++)
        off += sprintf(cmd + off, "RPUSH poplist val%06d\n", i);

    send_all(fd, cmd, off);
    char* drain = malloc(count * 64);
    read_responses(fd, count, drain, count * 64);
    close(fd);

    /* Benchmark LPOP */
    off = 0;
    for (int i = 0; i < count; i++)
        off += sprintf(cmd + off, "LPOP poplist\n");

    bench_result r = run_pipeline(host, port, cmd, off, count, nl_per_resp);
    printf("  [%-9s] LPOP  %5d:         %10.0f ops/sec  (%.3fs)\n",
           label, count, r.rate, r.elapsed_s);

    free(cmd);
    free(drain);
}

/* ================================================================
 * Test: Pipelined SADD (sets)
 * ================================================================ */
static void test_sadd(const char* host, int port, int count, const char* label)
{
    char* cmd = malloc((size_t)80 * count);
    int off = 0;
    for (int i = 0; i < count; i++)
        off += sprintf(cmd + off, "SADD benchset member%06d\n", i);

    bench_result r = run_pipeline(host, port, cmd, off, count, 1);
    printf("  [%-9s] SADD  %5d:         %10.0f ops/sec  (%.3fs)\n",
           label, count, r.rate, r.elapsed_s);

    free(cmd);
}

/* ================================================================
 * Test: Pipelined SISMEMBER (sets, pre-populated)
 * ================================================================ */
static void test_sismember(const char* host, int port, int count, const char* label)
{
    /* Populate */
    int fd = connect_to(host, port);
    if (fd < 0) return;

    char* cmd = malloc((size_t)80 * count);
    int off = 0;
    for (int i = 0; i < count; i++)
        off += sprintf(cmd + off, "SADD ismemset member%06d\n", i);

    send_all(fd, cmd, off);
    char* drain = malloc(count * 64);
    read_responses(fd, count, drain, count * 64);
    close(fd);

    /* Benchmark SISMEMBER */
    off = 0;
    for (int i = 0; i < count; i++)
        off += sprintf(cmd + off, "SISMEMBER ismemset member%06d\n", i);

    bench_result r = run_pipeline(host, port, cmd, off, count, 1);
    printf("  [%-9s] SISMEMBER %5d:     %10.0f ops/sec  (%.3fs)\n",
           label, count, r.rate, r.elapsed_s);

    free(cmd);
    free(drain);
}

/* ================================================================
 * Test: Pipelined HSET (hashes)
 * ================================================================ */
static void test_hset(const char* host, int port, int count, const char* label)
{
    char* cmd = malloc((size_t)80 * count);
    int off = 0;
    for (int i = 0; i < count; i++)
        off += sprintf(cmd + off, "HSET benchhash field%06d val%06d\n", i, i);

    bench_result r = run_pipeline(host, port, cmd, off, count, 1);
    printf("  [%-9s] HSET  %5d:         %10.0f ops/sec  (%.3fs)\n",
           label, count, r.rate, r.elapsed_s);

    free(cmd);
}

/* ================================================================
 * Test: Pipelined HGET (hashes, pre-populated)
 * ================================================================ */
static void test_hget(const char* host, int port, int count, int nl_per_resp, const char* label)
{
    /* Populate */
    int fd = connect_to(host, port);
    if (fd < 0) return;

    char* cmd = malloc((size_t)80 * count);
    int off = 0;
    for (int i = 0; i < count; i++)
        off += sprintf(cmd + off, "HSET gethash field%06d val%06d\n", i, i);

    send_all(fd, cmd, off);
    char* drain = malloc(count * 64);
    read_responses(fd, count, drain, count * 64);
    close(fd);

    /* Benchmark HGET */
    off = 0;
    for (int i = 0; i < count; i++)
        off += sprintf(cmd + off, "HGET gethash field%06d\n", i);

    bench_result r = run_pipeline(host, port, cmd, off, count, nl_per_resp);
    printf("  [%-9s] HGET  %5d:         %10.0f ops/sec  (%.3fs)\n",
           label, count, r.rate, r.elapsed_s);

    free(cmd);
    free(drain);
}

/* ================================================================
 * Test: Pipelined EXPIRE + TTL
 * ================================================================ */
static void test_expire_ttl(const char* host, int port, int count, const char* label)
{
    /* Populate keys */
    int fd = connect_to(host, port);
    if (fd < 0) return;

    char* cmd = malloc((size_t)80 * count * 2);
    int off = 0;
    for (int i = 0; i < count; i++)
        off += sprintf(cmd + off, "SET ttlk%06d val\n", i);

    send_all(fd, cmd, off);
    char* drain = malloc(count * 64);
    read_responses(fd, count, drain, count * 64);
    close(fd);

    /* Benchmark EXPIRE */
    off = 0;
    for (int i = 0; i < count; i++)
        off += sprintf(cmd + off, "EXPIRE ttlk%06d 300\n", i);

    bench_result r1 = run_pipeline(host, port, cmd, off, count, 1);
    printf("  [%-9s] EXPIRE %5d:        %10.0f ops/sec  (%.3fs)\n",
           label, count, r1.rate, r1.elapsed_s);

    /* Benchmark TTL */
    off = 0;
    for (int i = 0; i < count; i++)
        off += sprintf(cmd + off, "TTL ttlk%06d\n", i);

    bench_result r2 = run_pipeline(host, port, cmd, off, count, 1);
    printf("  [%-9s] TTL   %5d:        %10.0f ops/sec  (%.3fs)\n",
           label, count, r2.rate, r2.elapsed_s);

    free(cmd);
    free(drain);
}

/* ================================================================
 * Test: Concurrent clients (pipelined SET)
 * ================================================================ */
struct concurrent_args
{
    const char* host;
    int port;
    int ops;
    int client_id;
    int val_size;
    long long elapsed_us;
    int success;
};

static void* concurrent_worker(void* arg)
{
    struct concurrent_args* a = (struct concurrent_args*)arg;

    int fd = connect_to(a->host, a->port);
    if (fd < 0) { a->success = 0; return NULL; }

    char* value = malloc(a->val_size + 1);
    memset(value, 'W', a->val_size);
    value[a->val_size] = '\0';

    int est = (int)(30 + a->val_size) * a->ops;
    char* cmd = malloc(est);
    int off = 0;
    for (int i = 0; i < a->ops; i++)
        off += sprintf(cmd + off, "SET c%03dk%06d %s\n", a->client_id, i, value);

    char* recv_buf = malloc(a->ops * 64);

    long long start = get_time_us();
    send_all(fd, cmd, off);
    a->success = read_responses(fd, a->ops, recv_buf, a->ops * 64);
    long long end = get_time_us();
    a->elapsed_us = end - start;

    close(fd);
    free(value);
    free(cmd);
    free(recv_buf);
    return NULL;
}

static void test_concurrent(const char* host, int port, int clients, int ops,
                             int val_size, const char* label)
{
    pthread_t* threads = malloc(clients * sizeof(pthread_t));
    struct concurrent_args* args = malloc(clients * sizeof(struct concurrent_args));

    long long start = get_time_us();
    for (int i = 0; i < clients; i++)
    {
        args[i] = (struct concurrent_args){host, port, ops, i, val_size, 0, 0};
        pthread_create(&threads[i], NULL, concurrent_worker, &args[i]);
    }

    int total = 0;
    for (int i = 0; i < clients; i++)
    {
        pthread_join(threads[i], NULL);
        total += args[i].success;
    }

    long long end = get_time_us();
    double elapsed_s = (end - start) / 1000000.0;
    double rate = total / elapsed_s;

    printf("  [%-9s] %3d clients x %5d: %10.0f ops/sec  [%d/%d in %.3fs]\n",
           label, clients, ops, rate, total, clients * ops, elapsed_s);

    free(threads);
    free(args);
}

/* ================================================================
 * Test: Pipeline depth (latency per op at different depths)
 * ================================================================ */
static void test_pipeline_depth(const char* host, int port, int depth, const char* label)
{
    char* cmd = malloc(depth * 80);
    int off = 0;
    for (int i = 0; i < depth; i++)
        off += sprintf(cmd + off, "SET pd%d v%d\n", i, i);

    bench_result r = run_pipeline(host, port, cmd, off, depth, 1);
    double per_op_us = r.elapsed_s * 1000000.0 / depth;

    printf("  [%-9s] Pipeline %5d:      %8.1f us/op  %10.0f ops/sec\n",
           label, depth, per_op_us, r.rate);

    free(cmd);
}

/* ================================================================
 * MAIN
 * ================================================================ */

int main(int argc, char** argv)
{
    const char* host = "127.0.0.1";
    int cache_port = 19001;
    int redis_port = 6379;

    if (argc >= 2) cache_port = atoi(argv[1]);
    if (argc >= 3) redis_port = atoi(argv[2]);

    printf("\n");
    printf("  ╔══════════════════════════════════════════════════════════════════╗\n");
    printf("  ║   SOCKETLEY CACHE vs REDIS — Full Data Structure Benchmark     ║\n");
    printf("  ║   (Inline protocol, pipelined, fair comparison)                 ║\n");
    printf("  ╚══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("  Socketley: %s:%d\n", host, cache_port);
    printf("  Redis:     %s:%d\n", host, redis_port);
    printf("\n");

    int N = 50000; /* default operation count */

    /* ── 1. Strings: SET ── */
    printf("  ┌─ 1. STRING SET (pipelined) ────────────────────────────────────┐\n");
    int sizes[] = {64, 256, 1024};
    for (int s = 0; s < 3; s++)
    {
        printf("\n  %dB values, %d ops:\n", sizes[s], N);
        test_set(host, cache_port, N, sizes[s], "socketley");
        test_set(host, redis_port, N, sizes[s], "redis");
    }
    print_sep();

    /* ── 2. Strings: GET ── */
    printf("\n  ┌─ 2. STRING GET (pipelined, pre-populated) ───────────────────┐\n\n");
    test_get(host, cache_port, N, 1, "socketley");  /* socketley: 1 nl/resp */
    test_get(host, redis_port, N, 2, "redis");      /* redis: 2 nl/resp (bulk string) */
    print_sep();

    /* ── 3. Lists: LPUSH ── */
    printf("\n  ┌─ 3. LIST LPUSH (pipelined) ──────────────────────────────────┐\n\n");
    test_lpush(host, cache_port, N, "socketley");
    test_lpush(host, redis_port, N, "redis");
    print_sep();

    /* ── 4. Lists: LPOP ── */
    printf("\n  ┌─ 4. LIST LPOP (pipelined, pre-populated) ───────────────────┐\n\n");
    test_lpop(host, cache_port, N, 1, "socketley");
    test_lpop(host, redis_port, N, 2, "redis");
    print_sep();

    /* ── 5. Sets: SADD ── */
    printf("\n  ┌─ 5. SET SADD (pipelined) ────────────────────────────────────┐\n\n");
    test_sadd(host, cache_port, N, "socketley");
    test_sadd(host, redis_port, N, "redis");
    print_sep();

    /* ── 6. Sets: SISMEMBER ── */
    printf("\n  ┌─ 6. SET SISMEMBER (pipelined, pre-populated) ────────────────┐\n\n");
    test_sismember(host, cache_port, N, "socketley");
    test_sismember(host, redis_port, N, "redis");
    print_sep();

    /* ── 7. Hashes: HSET ── */
    printf("\n  ┌─ 7. HASH HSET (pipelined) ───────────────────────────────────┐\n\n");
    test_hset(host, cache_port, N, "socketley");
    test_hset(host, redis_port, N, "redis");
    print_sep();

    /* ── 8. Hashes: HGET ── */
    printf("\n  ┌─ 8. HASH HGET (pipelined, pre-populated) ───────────────────┐\n\n");
    test_hget(host, cache_port, N, 1, "socketley");
    test_hget(host, redis_port, N, 2, "redis");
    print_sep();

    /* ── 9. TTL: EXPIRE + TTL ── */
    printf("\n  ┌─ 9. TTL EXPIRE + TTL (pipelined) ───────────────────────────┐\n\n");
    test_expire_ttl(host, cache_port, N, "socketley");
    test_expire_ttl(host, redis_port, N, "redis");
    print_sep();

    /* ── 10. Concurrent clients ── */
    printf("\n  ┌─ 10. CONCURRENT CLIENTS (pipelined SET, 64B) ────────────────┐\n\n");
    int cc[] = {10, 50, 100};
    for (int c = 0; c < 3; c++)
    {
        test_concurrent(host, cache_port, cc[c], 1000, 64, "socketley");
        test_concurrent(host, redis_port, cc[c], 1000, 64, "redis");
        printf("\n");
    }
    print_sep();

    /* ── 11. Pipeline depth ── */
    printf("\n  ┌─ 11. PIPELINE DEPTH (SET latency) ───────────────────────────┐\n\n");
    int depths[] = {10, 100, 1000, 5000};
    for (int d = 0; d < 4; d++)
    {
        test_pipeline_depth(host, cache_port, depths[d], "socketley");
        test_pipeline_depth(host, redis_port, depths[d], "redis");
        printf("\n");
    }

    printf("  ══════════════════════════════════════════════════════════════════\n");
    printf("  Done.\n\n");

    return 0;
}
