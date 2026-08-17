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
 *
 * Every rate here is completed round trips per second except `server conn`,
 * `server burst` (connection establishments) and `server ingest` (writes with
 * nothing read back, which is the only thing measurable about a --mode in
 * runtime).  Each result says which of the three it is, in the output and in the
 * JSON key it is published under; see `enum metric_kind`.  The round-trip tests
 * need a backend that answers -- test/benchmark/echo.lua -- because no --mode of
 * a plain server runtime replies on its own.
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
/* One whole run, executed and thrown away, before the measured ones.
 *
 * Three of the position effects in these benchmarks are first-run effects and
 * nothing else: `proxy concurrent` run 1 was systematically 22% slow and the
 * slowest of five 44 times in 98, because the first request on each connection
 * is what opens the backend connection; `cache concurrent` run 1 was 31% fast
 * and the slowest 57 times in 88.  A per-benchmark warmup would have to be
 * remembered by each new benchmark, so it is done once here for all of them. */
#define DEFAULT_WARMUP_RUNS 1

/* Two thresholds, because two different things are being caught.
 *
 * SPREAD_WARN is the honest-reporting line: above it the median is not a number
 * anyone should quote on its own, so the run says so and the spread is
 * published beside every figure.  It does not fail the run -- on this machine
 * `server concurrent` legitimately spans about 1.6x because the whole system
 * enters brief stalls, and a benchmark that exits non-zero on a real property
 * of the thing it measures would just be switched off.
 *
 * SPREAD_FATAL is the old UNSTABLE check, which is about breakage rather than
 * noise: repetitions of one test do not differ by orders of magnitude unless a
 * run measured something other than throughput.  It was set at 100x, which no
 * observed spread has ever reached -- the 3-5x that prompted this work sailed
 * under it -- so it has never once fired.  10x is still far outside anything
 * this machine produces and inside the range where a run has plainly broken. */
#define SPREAD_WARN    1.5
#define SPREAD_FATAL  10.0

struct bench_config {
    const char *host;
    int         port;
    int         port2;       /* second endpoint for overhead test */
    int         num_ops;
    int         msg_size;
    int         num_clients;
    int         runs;
    int         warmup_pct;
    int         warmup_runs;  /* whole runs executed and discarded before measuring */
    int         json;
    /* Time-box a run instead of counting it out (-d).  num_ops becomes an upper
     * bound and the measured window is duration_ms wide, whatever rate the
     * server turns out to have.
     *
     * This exists because the count-based form set the window from a guess.
     * `proxy concurrent 8 200` is 1600 round trips, which on this machine is
     * eighteen milliseconds — short enough that one scheduling delay is the
     * whole measurement.  Repeated seven times it spanned 3.2x; the same case at
     * 128000 round trips spanned 1.29x.  A guess that was right when it was
     * written also stops being right the moment the thing under test gets
     * faster, and nothing announces that.
     *
     * It also squares the finish line for the threaded tests.  With a count
     * each thread stops when it personally is done, so the tail of the window
     * has fewer connections in flight than the head, and the elapsed time
     * charged to every thread is the slowest one's.  A deadline stops them all
     * within one round trip of each other. */
    int         duration_ms;
    /* Runs executed and thrown away before the measured ones.  The first run
     * against a freshly started process pays for its page faults, its accept
     * path and its allocator; folding that into a median is how a harness
     * reports a slower number for a faster program. */
    /* Request target for the HTTP tests (-u).  Both proxies are pointed at the
     * same one, so it has to be a path the shared backend really serves: a 404
     * is cheaper to produce than a file and would be measured as if it were a
     * file. */
    const char *path;
};

/* Deadline for the current run, or 0 when the run is counted out rather than
 * timed.  Set by run_and_report before each call; read by every worker. */
static int64_t g_run_deadline_ns = 0;

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

/* True once a time-boxed run's window has closed.  Costs one clock_gettime per
 * round trip, beside a send and a recv that each cost more than that. */
static inline int deadline_passed(void)
{
    return g_run_deadline_ns != 0 && time_ns() >= g_run_deadline_ns;
}

/* The loop condition for a worker that counts operations.  Both terms, in one
 * place, because the comment on g_run_deadline_ns above says it is "read by
 * every worker" and that was not true of any of them but one.
 *
 * deadline_passed() was consulted at 3 sites against 11 measurements, of which
 * 5 are concurrent.  The concurrent ones are where it matters: with no deadline
 * a worker runs a fixed num_ops and the run ends at pthread_join over all of
 * them, so `elapsed` is the MAXIMUM over nc threads while the numerator is
 * fixed at nc*num_ops.  At 100 threads on 10 cores that is a straggler
 * measurement wearing a throughput label, and the spread of a maximum over 100
 * samples is what the 3-5x run-to-run variance on these tests was.
 *
 * Writing the condition rather than the test is the point: a worker added later
 * gets both terms by using the loop form its neighbours use, instead of having
 * to know that a global exists. */
static inline int bench_op_continue(int i, const struct bench_config *cfg)
{
    return i < cfg->num_ops && !deadline_passed();
}

struct latency_log {
    int64_t *samples;
    int      count;
    int      capacity;
};

static void lat_init(struct latency_log *l, int cap)
{
    /* Clamped, because callers pass the operation count and a time-boxed run's
     * count is an upper bound rather than an estimate: `-d 1500` with a cap of
     * a hundred million would ask for 800 MB to hold samples for round trips
     * that will never happen.  MAX_LATENCIES is already the number of samples
     * the percentiles are willing to look at. */
    if (cap > MAX_LATENCIES) cap = MAX_LATENCIES;
    if (cap < 1) cap = 1;
    l->capacity = cap;
    l->count = 0;
    l->samples = (int64_t *)malloc((size_t)cap * sizeof(int64_t));
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

/* Read exactly len bytes, or fail.
 *
 * A send that returns tells you the kernel took the bytes, not that anything
 * served them.  Timing a loop of sends alone measures how fast this process can
 * fill a socket buffer, and once it is full, how fast the peer drains it --
 * which is a property of buffer sizes and of the peer's read loop, not of the
 * work being asked for. */
static ssize_t recv_exact(int fd, void *buf, size_t len)
{
    char *p = (char *)buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, p + got, len - got);
        if (n <= 0) return -1;
        got += n;
    }
    return (ssize_t)got;
}

/* A reply that never arrives has to end the run rather than hang it: without a
 * deadline a mute backend turns the measurement into a stall that the outer
 * script timeout eventually kills, and that reports as infrastructure trouble
 * instead of as this benchmark's own answer. */
static void set_recv_timeout(int fd, int ms)
{
    struct timeval tv;
    tv.tv_sec  = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) < 0) { }
}

/* ── What a reported number means ──────────────────────────────────────────
 *
 * Five benchmarks here used to send in a loop and never read a reply, and call
 * the result throughput.  What that measures is how fast this process can fill a
 * socket buffer: the rate is roughly 1/latency of a write syscall, and the
 * "latency percentiles" are the cost of write() and nothing else.  Measured on
 * the same 64B traffic against the same server, 372,700/sec write-only against
 * 39,199/sec for a completed round trip -- a factor of ten between two numbers
 * that were both being published as "msg/sec".
 *
 * So a result now carries what it measured, the JSON key it is published under
 * says the same thing, and the two cannot drift apart because the key is derived
 * from the kind rather than written next to it.  Results from before this exist
 * in test/benchmark/results/ under the old names and are not comparable; that is
 * why the names changed rather than the numbers quietly moving.
 *
 * METRIC_WRITE_ONLY has not been abolished -- it is a real property of a
 * `--mode in` runtime, which by definition never answers, and the only thing
 * that can be asked of one.  It is kept where it is deliberate (server ingest)
 * and named so nobody reads it as a service rate. */
enum metric_kind {
    METRIC_ROUND_TRIP = 0,  /* request sent, its reply read, before the next goes */
    METRIC_WRITE_ONLY,      /* bytes handed to the kernel; no reply is expected */
    METRIC_CONNECT          /* completed TCP connection establishments */
};

static const char *metric_name(enum metric_kind m)
{
    switch (m) {
        case METRIC_ROUND_TRIP: return "round_trip";
        case METRIC_WRITE_ONLY: return "write_only";
        default:                return "connect";
    }
}

/* The JSON key the rate is published under.  Deliberately not one shared key:
 * a tool that reads both an old file and a new one must see two different
 * fields, because they are two different measurements. */
static const char *metric_rate_key(enum metric_kind m)
{
    switch (m) {
        case METRIC_ROUND_TRIP: return "median_round_trips_per_sec";
        case METRIC_WRITE_ONLY: return "median_writes_per_sec";
        default:                return "median_connects_per_sec";
    }
}

static const char *metric_lat_prefix(enum metric_kind m)
{
    switch (m) {
        case METRIC_ROUND_TRIP: return "rtt";
        case METRIC_WRITE_ONLY: return "write";
        default:                return "connect";
    }
}

/* One line, printed beside the number, saying what it is.  A reader who takes a
 * figure out of this output and puts it in a README should not have to find this
 * file to know whether anything was served. */
static const char *metric_meaning(enum metric_kind m)
{
    switch (m) {
        case METRIC_ROUND_TRIP:
            return "completed round trips: each request's reply was read before the next was sent";
        case METRIC_WRITE_ONLY:
            return "writes accepted by the kernel; nothing was read back, so this is not a service rate";
        default:
            return "completed TCP connection establishments";
    }
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
    /* How many operations the run was supposed to complete.  A run that ends
     * with fewer than this did not measure throughput — it measured how long it
     * waited for responses that never arrived, and reporting that number as a
     * result hides a defect as if it were slow hardware.  0 means "unknown",
     * which skips the check. */
    int    expected;
    /* Threaded runs only: the fraction of the run during which every thread was
     * working.  The aggregate rate of a threaded run is the sum of the
     * per-thread rates, which is the total rate only while they overlap -- so
     * the overlap travels with the number instead of being assumed.  0 means
     * "not a threaded run", which skips the check. */
    double overlap;
    struct latency_log latencies;
};

/* Set when any run finished short, so the process can exit non-zero. */
static int g_incomplete_runs = 0;

/* ── Threaded benchmarks: what "elapsed" may legitimately mean ──────────────
 *
 * A threaded run used to be scored as total_ops / (last thread finished -
 * barrier released).  That charges every operation for the ramp before the
 * threads are all working and for the tail after most have stopped, and it was
 * the leading suspect for these numbers spreading several-fold run to run: with
 * 100 threads on 10 cores, the theory went, the figure is bounded by the
 * unluckiest thread's scheduling rather than by the server.
 *
 * Measured, it is not.  Per-thread timestamps over 25 runs of `server
 * concurrent 100 500`: threads begin within 0.6-2.7 ms of one another and
 * finish within 3.0-14.3 ms of a ~400 ms run, so the window in which all of
 * them are working is 97-99% of the time being charged, and every thread's own
 * rate rises and falls with the aggregate instead of one lagging.  The
 * straggler was worth ruling out, and it is ruled out; the spread comes from
 * stalls the whole system enters together, which no way of dividing by time
 * will remove.  See the spread reporting in run_and_report().
 *
 * The ramp is still worth removing, because unlike the stalls it does not
 * average out -- it is always in the same direction and it grows as the run
 * gets shorter.  So each thread times its own counted phase, and the run is
 * scored over the span from the first counted phase opening to the last one
 * closing: the connect storm, the barrier and the join are outside it, the
 * served work is inside it.
 *
 * Deliberately not the sum of the per-thread rates, which was the first version
 * of this.  That sum is the aggregate only while the threads overlap -- and the
 * overlap check below, written to justify the assumption, refuted it instead:
 * `cache concurrent` runs 20 threads that each fire one long pipeline, they are
 * all working for only 66-78% of the run, and summing their rates therefore
 * described a machine that was never running.  It inflated that benchmark by
 * about a third.  Completed operations divided by the span they completed in
 * cannot overstate the total, whatever the threads did inside it.
 *
 * The overlap still travels with the result, because it says what concurrency
 * was actually sustained: 0.95-0.99 on the per-request benchmarks means the
 * figure really is a rate at N clients, while 0.66 means it is an average over
 * a concurrency that fell away as threads finished. */
struct conc_slot {
    int     counted;   /* ops completed inside this thread's counted phase */
    int64_t t_open;    /* when the counted phase opened */
    int64_t t_close;   /* when its last counted op completed */
    struct latency_log lat;  /* per-thread samples, merged by the parent */
};

struct conc_summary {
    double rate;       /* counted operations over the span they completed in */
    int    counted;
    double overlap;    /* all-threads-working window / any-thread-working window */
    int    active;     /* threads that contributed a measurable phase */
};

static struct conc_summary conc_finalize(const struct conc_slot *s, int n)
{
    struct conc_summary out = {0};
    int64_t open_max = 0, open_min = 0, close_min = 0, close_max = 0;
    int seeded = 0;

    for (int i = 0; i < n; i++) {
        /* t_open == 0 means the thread counted an operation without ever
         * opening its phase, which is a bug in the worker rather than a slow
         * thread; including it would divide by a span measured from the epoch
         * and silently drag the total to nothing. */
        if (s[i].counted <= 0 || s[i].t_open <= 0 ||
            s[i].t_close <= s[i].t_open) continue;
        if (!seeded) {
            open_min = open_max = s[i].t_open;
            close_min = close_max = s[i].t_close;
            seeded = 1;
        }
        if (s[i].t_open  > open_max)  open_max  = s[i].t_open;
        if (s[i].t_open  < open_min)  open_min  = s[i].t_open;
        if (s[i].t_close < close_min) close_min = s[i].t_close;
        if (s[i].t_close > close_max) close_max = s[i].t_close;

        out.counted += s[i].counted;
        out.active++;
    }
    if (!seeded) return out;

    double all_working = ns_to_s(close_min - open_max);
    double any_working = ns_to_s(close_max - open_min);
    out.overlap = (any_working > 0 && all_working > 0) ? all_working / any_working : 0.0;
    out.rate    = (any_working > 0) ? out.counted / any_working : 0.0;
    return out;
}

/* Pool one thread's latency samples into the run's log. */
static void lat_merge(struct latency_log *dst, const struct latency_log *src)
{
    for (int i = 0; i < src->count && dst->count < dst->capacity; i++)
        dst->samples[dst->count++] = src->samples[i];
}

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
/* `bounded` stops draining when a time-boxed run's window closes.
 *
 * It is a parameter and not a check inside, because the six callers want
 * opposite things and the difference is not visible from here.  Three of them
 * are measuring, and a measured drain must end with the window or the run's
 * elapsed time is the slowest connection's rather than the window's.  The other
 * three are PRE-POPULATING -- bench_cache_get and bench_cache_mixed fill the
 * store before they measure reads against it -- and a fill cut short by a
 * deadline leaves a half-populated store that the measurement afterwards then
 * reports a throughput for.  That number would look entirely reasonable.
 *
 * The wrappers below carry the choice in their names, so a call site states
 * which it is instead of passing a bare 1. */
static int pipeline_drain(int fd, const char *cmd_buf, size_t cmd_len,
                          int expected_responses, int bounded)
{
    if (send_all(fd, cmd_buf, cmd_len) < 0)
        return 0;

    /* Drain responses: each response ends with \n */
    char rbuf[BUF_SIZE];
    int got = 0;
    while (got < expected_responses) {
        if (bounded && deadline_passed()) break;
        ssize_t n = read(fd, rbuf, sizeof(rbuf));
        if (n <= 0) break;
        got += count_newlines(rbuf, n);
    }
    return got;
}

/* Setup: must complete, whatever the clock says. */
static inline int pipeline_execute(int fd, const char *b, size_t n, int e)
{
    return pipeline_drain(fd, b, n, e, 0);
}

/* Measured: ends with the run's window when there is one. */
static inline int pipeline_measure(int fd, const char *b, size_t n, int e)
{
    return pipeline_drain(fd, b, n, e, 1);
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

/* Read one server->client text frame and return its payload length, or -1.
 *
 * A server frame is never masked (RFC 6455 §5.1), so the header is 2 bytes plus
 * an extended length when the payload is 126 bytes or more.  The length is read
 * from the wire rather than assumed to match what was sent: assuming it would
 * turn a server that replied with something else -- a close frame, a pong, a
 * truncated frame -- into a silent success, and this is the read that makes the
 * WebSocket benchmark a round trip in the first place.
 *
 * `cap` bounds the payload this will accept into `out`; a frame larger than that
 * is a failure rather than an overrun. */
static int ws_recv_frame(int fd, char *out, int cap)
{
    unsigned char hdr[2];
    if (recv_exact(fd, hdr, 2) != 2) return -1;
    if ((hdr[0] & 0x0F) != 0x1) return -1;   /* not a text frame */
    if (hdr[1] & 0x80) return -1;            /* a server frame must not be masked */

    int len = hdr[1] & 0x7F;
    if (len == 126) {
        unsigned char ext[2];
        if (recv_exact(fd, ext, 2) != 2) return -1;
        len = (ext[0] << 8) | ext[1];
    } else if (len == 127) {
        return -1;   /* 64-bit lengths are past anything this tool sends */
    }

    if (len > cap) return -1;
    if (len > 0 && recv_exact(fd, out, (size_t)len) != len) return -1;
    return len;
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

/* Single-client message throughput: one request out, its reply read, then the
 * next.  Against test/benchmark/echo.lua, because a plain server runtime answers
 * nothing in any --mode and this loop would otherwise be timing write().
 *
 * The reply is the same bytes back, newline included, so its length is known and
 * recv_exact can insist on all of it: a short read here means the server stopped
 * mid-message, which is a defect and not a slow run, and `expected` below is what
 * makes the harness say so instead of averaging it in. */
static struct run_result bench_server_msg(struct bench_config *cfg)
{
    struct run_result r = {0};
    lat_init(&r.latencies, cfg->num_ops);

    int fd = tcp_connect(cfg->host, cfg->port);
    if (fd < 0) { r.failed = cfg->num_ops; return r; }
    set_recv_timeout(fd, 2000);

    char *msg = (char *)malloc(cfg->msg_size + 1);
    memset(msg, 'X', cfg->msg_size);
    msg[cfg->msg_size] = '\n';
    char *rep = (char *)malloc(cfg->msg_size + 1);

    int warmup = cfg->num_ops * cfg->warmup_pct / 100;
    r.expected = (cfg->duration_ms > 0) ? 0 : cfg->num_ops;

    int64_t start = time_ns();

    for (int i = 0; bench_op_continue(i, cfg); i++) {
        int64_t t0 = time_ns();
        if (send_all(fd, msg, cfg->msg_size + 1) != cfg->msg_size + 1) { r.failed++; break; }
        if (recv_exact(fd, rep, cfg->msg_size + 1) != cfg->msg_size + 1) { r.failed++; break; }
        int64_t t1 = time_ns();

        r.success++;
        if (i >= warmup)
            lat_record(&r.latencies, t1 - t0);
    }

    int64_t end = time_ns();
    close(fd);
    free(msg);
    free(rep);

    double elapsed = ns_to_s(end - start);
    r.throughput = r.success / elapsed;
    /* One direction.  A round trip moves this much each way; counting both would
     * double a figure that is read as "how much payload got through". */
    r.throughput_mb = (r.success * (double)(cfg->msg_size + 1)) / elapsed / (1024.0 * 1024.0);

    return r;
}

/* The write-only loop, kept on purpose and named for what it is.
 *
 * A `--mode in` runtime accepts messages and never answers -- that is the mode,
 * not a missing feature -- so the rate at which one can be fed is the only thing
 * measurable about it, and it is worth measuring.  What it is NOT is a service
 * rate: nothing here waits for the server to do anything, so a run can finish
 * with most of the traffic still sitting in socket buffers.  That is why it is a
 * separate test under a separate name rather than the same number as `msg`. */
static struct run_result bench_server_ingest(struct bench_config *cfg)
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
    pthread_barrier_t   *barrier;
    int                  thread_success;
    struct conc_slot    *slot;
};

static void *server_concurrent_worker(void *arg)
{
    struct server_concurrent_args *a = (struct server_concurrent_args *)arg;
    struct bench_config *cfg = a->cfg;

    int fd = tcp_connect(cfg->host, cfg->port);

    char *msg = NULL, *rep = NULL;
    if (fd >= 0) {
        set_recv_timeout(fd, 5000);
        msg = (char *)malloc(cfg->msg_size + 1);
        memset(msg, 'Y', cfg->msg_size);
        msg[cfg->msg_size] = '\n';
        rep = (char *)malloc(cfg->msg_size + 1);
    }

    /* All threads connected — wait for barrier before sending.
     *
     * Reached even when the connect failed. A worker that returns early leaves
     * the barrier one short of its count, and the main thread then waits on it
     * forever — so a runtime refusing connections showed up as a benchmark that
     * hung until the suite timeout, saying nothing about why. */
    pthread_barrier_wait(a->barrier);
    if (fd < 0) return NULL;

    /* One request in flight per client, its reply read before the next goes.
     *
     * Not a pipeline, on purpose.  With N clients each holding one outstanding
     * request the server is under exactly the concurrency the test claims to be
     * measuring, and every operation counted has been served.  The loop this
     * replaces sent all of them without reading any, which on this traffic
     * (100 x 500 x 65B is ~32 KB per connection) fits inside socket buffers --
     * so a run could and did finish before the server had read most of it. */
    int local = 0;
    /* bench_op_continue, so -d ends the run on the clock; the warmup count and
     * the per-operation timestamp are what the counted phase needs.  Both sides
     * of this were separate improvements to the same loop. */
    int warmup = cfg->num_ops * cfg->warmup_pct / 100;
    for (int i = 0; bench_op_continue(i, cfg); i++) {
        int64_t t0 = time_ns();
        if (send_all(fd, msg, cfg->msg_size + 1) != cfg->msg_size + 1) break;
        if (recv_exact(fd, rep, cfg->msg_size + 1) != cfg->msg_size + 1) break;
        int64_t t1 = time_ns();
        local++;
        /* The counted phase opens at the first post-warmup send, not at the
         * barrier: the first operations of a run pay for a cold accept path
         * and a cold connection, and charging the rest of the run for them is
         * the one part of the old figure that never averages out. */
        if (i >= warmup) {
            if (a->slot->counted == 0) a->slot->t_open = t0;
            a->slot->counted++;
            a->slot->t_close = t1;
            lat_record(&a->slot->lat, t1 - t0);
        }
    }

    close(fd);
    free(msg);
    free(rep);
    a->thread_success = local;
    return NULL;
}

static struct run_result bench_server_concurrent(struct bench_config *cfg)
{
    struct run_result r = {0};

    int nc = cfg->num_clients;
    int per_thread = cfg->num_ops - cfg->num_ops * cfg->warmup_pct / 100;
    int cap = nc * (per_thread > 0 ? per_thread : 1);
    if (cap > MAX_LATENCIES) cap = MAX_LATENCIES;
    lat_init(&r.latencies, cap);

    pthread_t *threads = (pthread_t *)malloc(nc * sizeof(pthread_t));
    struct server_concurrent_args *args =
        (struct server_concurrent_args *)malloc(nc * sizeof(*args));
    /* calloc, and owned here rather than embedded in args: the workers write
     * through a pointer into this array, so it is zeroed once and read back
     * after the join without a copy. */
    struct conc_slot *slots = (struct conc_slot *)calloc(nc, sizeof(*slots));

    pthread_barrier_t barrier;
    pthread_barrier_init(&barrier, NULL, nc + 1); /* nc workers + main thread */

    for (int i = 0; i < nc; i++) {
        args[i].cfg = cfg;
        args[i].barrier = &barrier;
        args[i].thread_success = 0;
        args[i].slot = &slots[i];
        lat_init(&slots[i].lat, per_thread > 0 ? per_thread : 1);
        pthread_create(&threads[i], NULL, server_concurrent_worker, &args[i]);
    }

    /* Wait until all threads have connected before letting them send. */
    pthread_barrier_wait(&barrier);

    for (int i = 0; i < nc; i++)
        pthread_join(threads[i], NULL);

    int total = 0;
    for (int i = 0; i < nc; i++) {
        total += args[i].thread_success;
        lat_merge(&r.latencies, &slots[i].lat);
    }

    struct conc_summary cs = conc_finalize(slots, nc);

    for (int i = 0; i < nc; i++)
        lat_free(&slots[i].lat);
    free(slots);

    pthread_barrier_destroy(&barrier);
    free(threads);
    free(args);

    /* success/expected stay the whole run — a short run is still a short run,
     * and the completeness check must see every operation that was asked for,
     * not only the counted ones. */
    r.success = total;
    /* Timed: the clock ends the run, so a short count is the design and not a
     * failure.  Counted: every connection owed num_ops. */
    r.expected = (cfg->duration_ms > 0) ? 0 : nc * cfg->num_ops;
    /* The counted span, not total/elapsed: the wall includes the connect storm,
     * the barrier and the join, and that bias never averages out. */
    r.throughput = cs.rate;
    r.overlap = cs.overlap;

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
    r.success = pipeline_measure(fd, cmd_buf, cmd_len, cfg->num_ops);
    /* Timed: pipeline_measure ends the drain with the window, so a short
     * count is the design.  Counted: the whole pipeline was owed. */
    r.expected = (cfg->duration_ms > 0) ? 0 : cfg->num_ops;
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
    r.success = pipeline_measure(fd, cmd_buf, cmd_len, cfg->num_ops);
    /* Timed: pipeline_measure ends the drain with the window, so a short
     * count is the design.  Counted: the whole pipeline was owed. */
    r.expected = (cfg->duration_ms > 0) ? 0 : cfg->num_ops;
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
    r.success = pipeline_measure(fd, cmd_buf, cmd_len, cfg->num_ops);
    /* Timed: pipeline_measure ends the drain with the window, so a short
     * count is the design.  Counted: the whole pipeline was owed. */
    r.expected = (cfg->duration_ms > 0) ? 0 : cfg->num_ops;
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
    pthread_barrier_t   *barrier;
    int                  client_id;
    int                  thread_success;
    struct conc_slot    *slot;
};

static void *cache_concurrent_worker(void *arg)
{
    struct cache_concurrent_args *a = (struct cache_concurrent_args *)arg;
    struct bench_config *cfg = a->cfg;

    int fd = tcp_connect(cfg->host, cfg->port);

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

    /* All threads connected + pipeline built — wait for barrier.
     * Reached even on a failed connect — see server_concurrent_worker. */
    pthread_barrier_wait(a->barrier);

    if (fd < 0) { free(buf); return NULL; }

    /* One pipelined write and its replies, so there is no per-operation timing
     * to take here and no warmup to skip -- the thread's whole phase is the
     * measurement.  Timing it per thread still drops the ramp before the last
     * thread gets going and the tail after the first one stops, which is what
     * the shared window is for.
     *
     * pipeline_measure rather than pipeline_execute: it ends the drain with the
     * window, which is what -d needs. */
    a->slot->t_open = time_ns();
    a->thread_success = pipeline_measure(fd, buf, off, ops);
    a->slot->t_close = time_ns();
    a->slot->counted = a->thread_success;
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
    struct conc_slot *slots = (struct conc_slot *)calloc(nc, sizeof(*slots));

    pthread_barrier_t barrier;
    pthread_barrier_init(&barrier, NULL, nc + 1);

    for (int i = 0; i < nc; i++) {
        args[i].cfg = cfg;
        args[i].barrier = &barrier;
        args[i].client_id = i;
        args[i].thread_success = 0;
        args[i].slot = &slots[i];
        lat_init(&slots[i].lat, 1);
        pthread_create(&threads[i], NULL, cache_concurrent_worker, &args[i]);
    }

    pthread_barrier_wait(&barrier);

    for (int i = 0; i < nc; i++)
        pthread_join(threads[i], NULL);

    int total = 0;
    for (int i = 0; i < nc; i++)
        total += args[i].thread_success;

    struct conc_summary cs = conc_finalize(slots, nc);

    for (int i = 0; i < nc; i++)
        lat_free(&slots[i].lat);
    free(slots);

    pthread_barrier_destroy(&barrier);
    free(threads);
    free(args);

    r.success = total;
    /* Timed: the clock ends the run, so a short count is the design and not a
     * failure.  Counted: every connection owed num_ops. */
    r.expected = (cfg->duration_ms > 0) ? 0 : nc * cfg->num_ops;
    /* The counted span, not total/elapsed: the wall includes the connect storm,
     * the barrier and the join, and that bias never averages out. */
    r.throughput = cs.rate;
    r.overlap = cs.overlap;

    return r;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * J. Proxy benchmarks
 * ═══════════════════════════════════════════════════════════════════════════ */

/* TCP forwarding: one request through the proxy to the backend and its reply
 * back, before the next.  The backend must echo (test/benchmark/echo.lua) --
 * without a reply this timed a write into the proxy's accept buffer and said
 * nothing about forwarding at all. */
static struct run_result bench_proxy_tcp(struct bench_config *cfg)
{
    struct run_result r = {0};
    lat_init(&r.latencies, cfg->num_ops);

    int fd = tcp_connect(cfg->host, cfg->port);
    if (fd < 0) { r.failed = cfg->num_ops; return r; }
    set_recv_timeout(fd, 2000);

    int msize = cfg->msg_size > 0 ? cfg->msg_size : 128;
    char *msg = (char *)malloc(msize + 1);
    memset(msg, 'P', msize);
    msg[msize] = '\n';
    char *rep = (char *)malloc(msize + 1);

    int warmup = cfg->num_ops * cfg->warmup_pct / 100;
    /* A timed run stops at the clock, not at a count, so falling short of
     * num_ops is the normal outcome and must not be reported as a defect. */
    r.expected = (cfg->duration_ms > 0) ? 0 : cfg->num_ops;

    int64_t start = time_ns();
    /* The warm-up has to be measured in whatever unit ends the run.  A timed
     * run is given an operation cap, not an estimate, so "the first 10% of
     * num_ops" is ten million round trips that never happen — and the
     * percentiles below would come out of an empty log. */
    int64_t warm_until = (cfg->duration_ms > 0)
        ? start + (int64_t)cfg->duration_ms * cfg->warmup_pct * 10000LL
        : 0;

    for (int i = 0; i < cfg->num_ops; i++) {
        if (deadline_passed()) break;
        int64_t t0 = time_ns();
        if (send_all(fd, msg, msize + 1) != msize + 1) { r.failed++; break; }
        if (recv_exact(fd, rep, msize + 1) != msize + 1) { r.failed++; break; }
        int64_t t1 = time_ns();

        r.success++;
        if (warm_until ? (t1 >= warm_until) : (i >= warmup))
            lat_record(&r.latencies, t1 - t0);
    }

    int64_t end = time_ns();
    close(fd);
    free(msg);
    free(rep);

    double elapsed = ns_to_s(end - start);
    r.throughput = r.success / elapsed;
    r.throughput_mb = (r.success * (double)(msize + 1)) / elapsed / (1024.0 * 1024.0);

    return r;
}

/* Concurrent proxy — threaded */
struct proxy_concurrent_args {
    struct bench_config *cfg;
    pthread_barrier_t   *barrier;
    int                  thread_success;
    struct conc_slot    *slot;
};

static void *proxy_concurrent_worker(void *arg)
{
    struct proxy_concurrent_args *a = (struct proxy_concurrent_args *)arg;
    struct bench_config *cfg = a->cfg;

    int fd = tcp_connect(cfg->host, cfg->port);

    int msize = cfg->msg_size > 0 ? cfg->msg_size : 128;
    char *msg = NULL, *rep = NULL;
    if (fd >= 0) {
        set_recv_timeout(fd, 5000);
        msg = (char *)malloc(msize + 1);
        memset(msg, 'P', msize);
        msg[msize] = '\n';
        rep = (char *)malloc(msize + 1);
    }

    /* Barrier is reached even on a failed connect — see server_concurrent_worker. */
    pthread_barrier_wait(a->barrier);
    if (fd < 0) return NULL;

    /* Read the reply before sending the next — see server_concurrent_worker for
     * why the version without this measured socket buffers. */
    int local = 0;
    int warmup = cfg->num_ops * cfg->warmup_pct / 100;
    for (int i = 0; i < cfg->num_ops; i++) {
        if (deadline_passed()) break;
        int64_t t0 = time_ns();
        if (send_all(fd, msg, msize + 1) != msize + 1) break;
        if (recv_exact(fd, rep, msize + 1) != msize + 1) break;
        int64_t t1 = time_ns();
        local++;
        /* Warmup matters more here than anywhere else: the proxy's first
         * request per connection is what opens the backend connection, and
         * `proxy concurrent` run 1 was systematically 22% slower than the rest
         * for exactly that reason. */
        if (i >= warmup) {
            if (a->slot->counted == 0) a->slot->t_open = t0;
            a->slot->counted++;
            a->slot->t_close = t1;
            lat_record(&a->slot->lat, t1 - t0);
        }
    }

    close(fd);
    free(msg);
    free(rep);
    a->thread_success = local;
    return NULL;
}

static struct run_result bench_proxy_concurrent(struct bench_config *cfg)
{
    struct run_result r = {0};

    int nc = cfg->num_clients;
    int per_thread = cfg->num_ops - cfg->num_ops * cfg->warmup_pct / 100;
    int cap = nc * (per_thread > 0 ? per_thread : 1);
    if (cap > MAX_LATENCIES) cap = MAX_LATENCIES;
    lat_init(&r.latencies, cap);

    pthread_t *threads = (pthread_t *)malloc(nc * sizeof(pthread_t));
    struct proxy_concurrent_args *args =
        (struct proxy_concurrent_args *)malloc(nc * sizeof(*args));
    struct conc_slot *slots = (struct conc_slot *)calloc(nc, sizeof(*slots));

    pthread_barrier_t barrier;
    pthread_barrier_init(&barrier, NULL, nc + 1);

    for (int i = 0; i < nc; i++) {
        args[i].cfg = cfg;
        args[i].barrier = &barrier;
        args[i].thread_success = 0;
        args[i].slot = &slots[i];
        lat_init(&slots[i].lat, per_thread > 0 ? per_thread : 1);
        pthread_create(&threads[i], NULL, proxy_concurrent_worker, &args[i]);
    }

    pthread_barrier_wait(&barrier);

    for (int i = 0; i < nc; i++)
        pthread_join(threads[i], NULL);

    int total = 0;
    for (int i = 0; i < nc; i++) {
        total += args[i].thread_success;
        lat_merge(&r.latencies, &slots[i].lat);
    }

    struct conc_summary cs = conc_finalize(slots, nc);

    for (int i = 0; i < nc; i++)
        lat_free(&slots[i].lat);
    free(slots);

    pthread_barrier_destroy(&barrier);
    free(threads);
    free(args);

    r.success = total;
    /* Timed: the clock ends the run, so a short count is the design and not a
     * failure.  Counted: every connection owed num_ops. */
    r.expected = (cfg->duration_ms > 0) ? 0 : nc * cfg->num_ops;
    /* The counted span, not total/elapsed: the wall includes the connect storm,
     * the barrier and the join, a bias that never averages out. */
    r.throughput = cs.rate;
    r.overlap = cs.overlap;

    return r;
}

/* ─── Proxy overhead ─────────────────────────────────────────────────────────
 *
 * What one proxy hop costs, as a percentage of the direct rate.
 *
 * The measurement is paired and interleaved, which is the whole of the repair.
 * The version before this ran each leg exactly once, 500 round trips long — a
 * seventeen-millisecond window — direct first and proxied second.  Over seven
 * repetitions its direct leg alone came out anywhere between 15712 and 46364
 * round trips a second, so the quotient of the two legs was free to land almost
 * anywhere, and one recorded run reported an overhead of -106%.  A proxy hop
 * cannot make a request faster than not taking it; that impossibility was the
 * only thing that gave the number away, and a number that is merely wrong
 * rather than impossible would have been believed.
 *
 * Three things are different here.  Each leg is timed rather than counted, so
 * the window does not shrink as the code gets faster.  The legs alternate which
 * one goes first, so whatever the first leg pays for — a cold path, a page not
 * yet faulted — is charged to each of them equally instead of always to
 * `direct`.  And the overhead is computed per pair and only then aggregated, so
 * a machine that is slow for one pair slows both of its legs and leaves their
 * ratio alone; the spread that survives that is reported next to the answer as
 * a confidence interval.  When that interval is too wide to support the number,
 * this says so rather than printing it.
 */

/* Half-width of the 95% confidence interval of the mean of `v`, expressed the
 * same way `v` is.  Student's t for the small n a benchmark actually runs; the
 * asymptotic 1.96 understates the interval at n = 5 by a third. */
static double ci95_half_width(const double *v, int n)
{
    static const double t95[] = {
        0,     0,     12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365,
        2.306, 2.262, 2.228,  2.201, 2.179, 2.160, 2.145, 2.131, 2.120,
        2.110, 2.101, 2.093,  2.086
    };
    if (n < 2) return 0;
    double m = 0;
    for (int i = 0; i < n; i++) m += v[i];
    m /= n;
    double ss = 0;
    for (int i = 0; i < n; i++) ss += (v[i] - m) * (v[i] - m);
    double sd = sqrt(ss / (n - 1));
    double t  = (n <= 21) ? t95[n] : 1.96;
    return t * sd / sqrt((double)n);
}

/* One leg: a timed round-trip loop against `port`.  Returns the rate, or 0 when
 * the connection could not carry the whole window. */
static double overhead_leg(struct bench_config *cfg, int port,
                           const char *msg, char *rep, int msize, int *ops_out)
{
    *ops_out = 0;
    int fd = tcp_connect(cfg->host, port);
    if (fd < 0) return 0;
    set_recv_timeout(fd, 2000);

    int64_t window = (int64_t)cfg->duration_ms * 1000000LL;
    int64_t start  = time_ns();
    int64_t stop   = start + window;
    int     success = 0;
    int     broke   = 0;

    for (int i = 0; i < cfg->num_ops; i++) {
        if (window > 0 && time_ns() >= stop) break;
        if (send_all(fd, msg, msize + 1) != msize + 1) { broke = 1; break; }
        if (recv_exact(fd, rep, msize + 1) != msize + 1) { broke = 1; break; }
        success++;
    }
    int64_t end = time_ns();
    close(fd);

    *ops_out = success;
    if (broke || success == 0) return 0;
    return success / ns_to_s(end - start);
}

static void bench_proxy_overhead(struct bench_config *cfg)
{
    int msize = cfg->msg_size > 0 ? cfg->msg_size : 128;
    char *msg = (char *)malloc(msize + 1);
    memset(msg, 'O', msize);
    msg[msize] = '\n';

    char *rep = (char *)malloc(msize + 1);

    /* A leg that is not timed is a leg whose window is a guess.  Without -d the
     * count still governs, so an explicit `proxy overhead 500 <port>` behaves as
     * it always did — but the pairing below still applies, and 500 round trips
     * is short enough that the interval will say so. */
    int pairs = cfg->runs > 0 ? cfg->runs : 1;
    int warm  = cfg->warmup_runs;

    double *ratio  = (double *)malloc((size_t)pairs * sizeof(double));
    double *direct = (double *)malloc((size_t)pairs * sizeof(double));
    double *proxied = (double *)malloc((size_t)pairs * sizeof(double));
    int kept = 0, short_legs = 0;
    int min_direct_ops = 0, min_proxied_ops = 0;

    for (int p = -warm; p < pairs; p++) {
        double d, x;
        int dops = 0, xops = 0;
        /* Alternate which leg goes first.  Whatever the first leg of a pair
         * pays that the second does not is then charged to `direct` and
         * `proxied` in equal numbers instead of always to the same one. */
        if ((p & 1) == 0) {
            d = overhead_leg(cfg, cfg->port2, msg, rep, msize, &dops);
            x = overhead_leg(cfg, cfg->port,  msg, rep, msize, &xops);
        } else {
            x = overhead_leg(cfg, cfg->port,  msg, rep, msize, &xops);
            d = overhead_leg(cfg, cfg->port2, msg, rep, msize, &dops);
        }
        if (p < 0) continue;                       /* warm-up pair, discarded */

        if (d <= 0 || x <= 0) { short_legs++; continue; }
        if (kept == 0 || dops < min_direct_ops)  min_direct_ops  = dops;
        if (kept == 0 || xops < min_proxied_ops) min_proxied_ops = xops;
        direct[kept]  = d;
        proxied[kept] = x;
        ratio[kept]   = x / d;
        kept++;
    }

    free(msg);
    free(rep);

    /* The answer, and the width of the ground it stands on.  Both come from the
     * per-pair ratios: a pair measured while the machine was busy has both of
     * its legs slowed and its ratio survives, which is the point of pairing. */
    double med_ratio = 0, half = 0, overhead_pct = 0, half_pct = 0;
    double med_direct = 0, med_proxied = 0;
    if (kept > 0) {
        double *tmp = (double *)malloc((size_t)kept * sizeof(double));
        memcpy(tmp, ratio, (size_t)kept * sizeof(double));
        med_ratio = median_double(tmp, kept);
        memcpy(tmp, direct, (size_t)kept * sizeof(double));
        med_direct = median_double(tmp, kept);
        memcpy(tmp, proxied, (size_t)kept * sizeof(double));
        med_proxied = median_double(tmp, kept);
        free(tmp);
        half         = ci95_half_width(ratio, kept);
        overhead_pct = (1.0 - med_ratio) * 100.0;
        half_pct     = half * 100.0;
    }

    /* Two ways this refuses to answer, and they are different questions.
     * `complete` asks whether both legs ever carried a request to completion;
     * `resolved` asks whether the pairs agreed closely enough for the number to
     * mean anything.  A run can be complete and unresolved — that is precisely
     * the state the old single-shot version was in every time, with nothing in
     * its output to say so. */
    int complete = (kept > 0 && short_legs == 0);
    int resolved = (complete && kept >= 3 && half_pct <= 5.0);

    if (cfg->json) {
        json_reset();
        json_start(stdout);
        json_kv_str(stdout, "test", "proxy_overhead");
        json_kv_int(stdout, "pairs", kept);
        json_kv_int(stdout, "pairs_discarded_short", short_legs);
        json_kv_int(stdout, "duration_ms_per_leg", cfg->duration_ms);
        json_kv_int(stdout, "direct_min_round_trips", min_direct_ops);
        json_kv_int(stdout, "proxied_min_round_trips", min_proxied_ops);
        json_kv_dbl(stdout, "direct_msg_per_sec", med_direct);
        json_kv_dbl(stdout, "proxied_msg_per_sec", med_proxied);
        json_kv_dbl(stdout, "overhead_ci95_half_width_pct", half_pct);
        if (resolved)
            json_kv_dbl(stdout, "overhead_percent", overhead_pct);
        else
            json_kv_str(stdout, "overhead_percent",
                        complete ? "not resolved" : "not measurable");
        fprintf(stdout, ",\"per_pair_ratio\":[");
        for (int i = 0; i < kept; i++)
            fprintf(stdout, "%s%.4f", i ? "," : "", ratio[i]);
        fprintf(stdout, "]");
        json_end(stdout);
    } else {
        printf("socketley-bench: proxy overhead  %s  direct=%d  proxied=%d  "
               "%d pairs", cfg->host, cfg->port2, cfg->port, kept);
        if (cfg->duration_ms > 0) printf("  %d ms/leg", cfg->duration_ms);
        printf("\n\n");
        printf("  Direct:   %12.0f round trips/sec  (median of %d)\n", med_direct, kept);
        printf("  Proxied:  %12.0f round trips/sec  (median of %d)\n", med_proxied, kept);
        if (resolved) {
            printf("  Overhead: %11.1f%%  ±%.1f (95%% CI over the pairs)\n",
                   overhead_pct, half_pct);
        } else if (complete) {
            printf("  Overhead:  not resolved — the pairs span ±%.1f%%, which is "
                   "wider than the answer\n", half_pct);
            printf("             Give it more pairs (-r) or a longer window (-d) "
                   "before believing a figure here.\n");
        } else {
            printf("  Overhead:  not measurable — %d pair(s) had a leg that did "
                   "not carry the window\n", short_legs);
        }
    }

    free(ratio);
    free(direct);
    free(proxied);

    /* A run that could not answer is a failed run.  Silence here is what let a
     * -106%% into a results file. */
    if (!resolved) g_incomplete_runs++;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * J2. HTTP through a proxy
 *
 * The TCP path measures forwarding and nothing else, which is the narrowest
 * slice of what a proxy does and the one where an HTTP proxy is least itself.
 * These two tests measure the mode haproxy is written for.
 *
 * They come in a pair on purpose.  Keep-alive and connection-per-request are
 * not two settings of one benchmark, they are the two halves of the thing that
 * separates proxies: with keep-alive the connection is set up once and the
 * proxy's per-request cost is all that is left; without it every request pays
 * an accept, a backend connect (or a pooled one, which is exactly the
 * difference being looked for), and a teardown.  A proxy can be good at one and
 * ordinary at the other, and a suite that measures only the first will say so
 * with a straight face.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Read one HTTP response and say how many bytes of it belonged to this reply.
 *
 * Framing is the whole difficulty of a keep-alive client.  Reading "some bytes"
 * and calling it a response works exactly once per connection: the next reply
 * starts inside whatever is left in the buffer, and from then on the client is
 * counting boundaries that are no longer where it thinks they are.  A run like
 * that still produces a number, and the number is larger than the truth.
 *
 * Returns 1 on a complete, well-formed response; 0 otherwise.  `carry` holds
 * bytes already read that belong to the next response, so the caller can pass
 * them back in.  *keep is set to 0 when the server said it is closing. */
struct http_reader {
    char buf[BUF_SIZE];
    int  len;          /* bytes currently in buf */
};

static int hr_fill(struct http_reader *r, int fd)
{
    if (r->len >= (int)sizeof(r->buf)) return 0;   /* header larger than buffer */
    ssize_t n = read(fd, r->buf + r->len, sizeof(r->buf) - r->len);
    if (n <= 0) return 0;
    r->len += (int)n;
    return 1;
}

/* Case-insensitive search for a header value in a NUL-free byte range. */
static const char *hdr_find(const char *h, int hlen, const char *name)
{
    int nlen = (int)strlen(name);
    for (int i = 0; i + nlen <= hlen; i++) {
        if (strncasecmp(h + i, name, nlen) == 0 &&
            (i == 0 || h[i - 1] == '\n'))
            return h + i + nlen;
    }
    return NULL;
}

static int http_read_response(struct http_reader *r, int fd, int *keep)
{
    int hdr_end = -1;
    for (;;) {
        for (int i = 0; i + 3 < r->len; i++) {
            if (r->buf[i] == '\r' && r->buf[i + 1] == '\n' &&
                r->buf[i + 2] == '\r' && r->buf[i + 3] == '\n') {
                hdr_end = i + 4;
                break;
            }
        }
        if (hdr_end >= 0) break;
        if (!hr_fill(r, fd)) return 0;
    }

    /* A status line, not merely bytes.  A proxy that closes on us delivers zero
     * bytes, and counting that as a served request is how a broken backend
     * turns into a throughput record. */
    if (r->len < 7 || strncmp(r->buf, "HTTP/1.", 7) != 0) return 0;

    long body = 0;
    int  chunked = 0;
    const char *v;
    if ((v = hdr_find(r->buf, hdr_end, "Content-Length:")) != NULL)
        body = strtol(v, NULL, 10);
    else if ((v = hdr_find(r->buf, hdr_end, "Transfer-Encoding:")) != NULL &&
             strncasecmp(v, " chunked", 8) == 0)
        chunked = 1;

    if ((v = hdr_find(r->buf, hdr_end, "Connection:")) != NULL &&
        strncasecmp(v, " close", 6) == 0)
        *keep = 0;

    if (chunked) {
        /* Only what a static file server actually emits is handled: the
         * terminating zero-length chunk.  Anything else is refused rather than
         * guessed at, because a client that mis-frames a body reports a rate
         * for responses it never finished reading. */
        for (;;) {
            for (int i = 0; i + 4 < r->len; i++)
                if (memcmp(r->buf + i, "0\r\n\r\n", 5) == 0) {
                    int end = i + 5;
                    memmove(r->buf, r->buf + end, r->len - end);
                    r->len -= end;
                    return 1;
                }
            if (!hr_fill(r, fd)) return 0;
        }
    }

    /* The whole response has to fit in one buffer, headers included, because
     * the leftover bytes after it are the start of the next one and there is
     * nowhere else to keep them.  A body larger than BUF_SIZE therefore fails
     * the request rather than being streamed — deliberately, because the other
     * option is a client that loses framing on large files and reports a rate
     * for responses it never finished reading.  Serve a smaller file; this is a
     * proxy benchmark, not a download. */
    long want = hdr_end + body;
    if (want > (long)sizeof(r->buf)) return 0;
    while (r->len < want) {
        if (!hr_fill(r, fd)) return 0;
    }
    memmove(r->buf, r->buf + want, r->len - want);
    r->len -= (int)want;
    return 1;
}

struct http_args {
    struct bench_config *cfg;
    pthread_barrier_t   *barrier;
    const char          *request;
    int                  req_len;
    int                  keepalive;
    int                  thread_success;
    int                  thread_failed;
};

static void *http_worker(void *arg)
{
    struct http_args *a = (struct http_args *)arg;
    struct bench_config *cfg = a->cfg;
    struct http_reader r;
    int fd = -1;

    if (a->keepalive) {
        fd = tcp_connect(cfg->host, cfg->port);
        if (fd >= 0) { set_recv_timeout(fd, 5000); r.len = 0; }
    }

    pthread_barrier_wait(a->barrier);
    if (a->keepalive && fd < 0) return NULL;

    int local = 0;
    for (int i = 0; i < cfg->num_ops; i++) {
        if (deadline_passed()) break;

        if (!a->keepalive) {
            fd = tcp_connect(cfg->host, cfg->port);
            if (fd < 0) { a->thread_failed++; break; }
            set_recv_timeout(fd, 5000);
            r.len = 0;
        }

        int keep = 1;
        if (send_all(fd, a->request, a->req_len) != a->req_len) { a->thread_failed++; break; }
        if (!http_read_response(&r, fd, &keep))                 { a->thread_failed++; break; }
        local++;

        if (!a->keepalive) {
            close(fd); fd = -1;
        } else if (!keep) {
            /* The server ended the connection on a run that asked it not to.
             * Reconnecting silently would turn a keep-alive measurement into a
             * connection-per-request one and report it under the wrong name. */
            close(fd); fd = -1;
            a->thread_failed++;
            break;
        }
    }

    if (fd >= 0) close(fd);
    a->thread_success = local;
    return NULL;
}

static struct run_result bench_http(struct bench_config *cfg, int keepalive)
{
    struct run_result r = {0};
    lat_init(&r.latencies, 1);

    int nc = cfg->num_clients > 0 ? cfg->num_clients : 1;
    char request[512];
    int req_len = snprintf(request, sizeof request,
        "GET %s HTTP/1.1\r\nHost: %s\r\n%s\r\n",
        cfg->path ? cfg->path : "/", cfg->host,
        keepalive ? "" : "Connection: close\r\n");

    pthread_t *threads = (pthread_t *)malloc((size_t)nc * sizeof(pthread_t));
    struct http_args *args = (struct http_args *)malloc((size_t)nc * sizeof(*args));
    pthread_barrier_t barrier;
    pthread_barrier_init(&barrier, NULL, nc + 1);

    for (int i = 0; i < nc; i++) {
        args[i].cfg = cfg;
        args[i].barrier = &barrier;
        args[i].request = request;
        args[i].req_len = req_len;
        args[i].keepalive = keepalive;
        args[i].thread_success = 0;
        args[i].thread_failed = 0;
        pthread_create(&threads[i], NULL, http_worker, &args[i]);
    }

    pthread_barrier_wait(&barrier);
    int64_t start = time_ns();
    for (int i = 0; i < nc; i++) pthread_join(threads[i], NULL);
    int64_t end = time_ns();

    int total = 0, failed = 0;
    for (int i = 0; i < nc; i++) { total += args[i].thread_success; failed += args[i].thread_failed; }

    pthread_barrier_destroy(&barrier);
    free(threads);
    free(args);

    r.success  = total;
    r.failed   = failed;
    r.expected = (cfg->duration_ms > 0) ? 0 : nc * cfg->num_ops;
    r.throughput = total / ns_to_s(end - start);
    return r;
}

static struct run_result bench_http_keepalive(struct bench_config *cfg)
{ return bench_http(cfg, 1); }
static struct run_result bench_http_close(struct bench_config *cfg)
{ return bench_http(cfg, 0); }

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

/* WebSocket echo round trip: one masked text frame out, the server's frame read
 * back, before the next goes.
 *
 * The name was always "echo" and the loop never read one: it pushed masked
 * frames at a plain server, which relays to every client except the sender and
 * therefore answered nothing at all.  So the figure was the cost of write() on a
 * frame, and the p50 was the cost of write().  It needs test/benchmark/echo.lua
 * on the server for the same reason the TCP benchmarks do. */
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
    set_recv_timeout(fd, 2000);

    int msize = cfg->msg_size > 0 ? cfg->msg_size : 64;
    char *payload = (char *)malloc(msize);
    memset(payload, 'E', msize);

    char *frame = (char *)malloc(msize + 14);
    int frame_len = ws_build_frame(frame, payload, msize);
    char *rep = (char *)malloc(msize + 1);

    int warmup = cfg->num_ops * cfg->warmup_pct / 100;
    r.expected = (cfg->duration_ms > 0) ? 0 : cfg->num_ops;

    int64_t start = time_ns();

    for (int i = 0; bench_op_continue(i, cfg); i++) {
        int64_t t0 = time_ns();

        if (send_all(fd, frame, frame_len) < 0) { r.failed++; break; }
        /* The echoed payload is the same bytes back: self.send strips the
         * newline it appends when the connection is a WebSocket, so a frame of
         * any other length means the server answered something else. */
        if (ws_recv_frame(fd, rep, msize) != msize) { r.failed++; break; }
        int64_t t1 = time_ns();

        r.success++;
        if (i >= warmup)
            lat_record(&r.latencies, t1 - t0);
    }

    int64_t end = time_ns();
    close(fd);
    free(payload);
    free(frame);
    free(rep);

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
    pthread_barrier_t   *barrier;
    int                  thread_success;
    struct conc_slot    *slot;
};

static void *ws_concurrent_worker(void *arg)
{
    struct ws_concurrent_args *a = (struct ws_concurrent_args *)arg;
    struct bench_config *cfg = a->cfg;

    /* Wait for all threads to be ready before starting handshake storm */
    pthread_barrier_wait(a->barrier);

    int local = 0;
    /* bench_op_continue, so -d ends the run on the clock; the warmup count and
     * the per-operation timestamp are what the counted phase needs.  Both sides
     * of this were separate improvements to the same loop. */
    int warmup = cfg->num_ops * cfg->warmup_pct / 100;
    for (int i = 0; bench_op_continue(i, cfg); i++) {
        int64_t t0 = time_ns();
        int fd = tcp_connect(cfg->host, cfg->port);
        if (fd < 0) continue;
        int ok = ws_upgrade(fd, cfg->host, cfg->port);
        int64_t t1 = time_ns();
        close(fd);
        if (!ok) continue;
        local++;
        if (i >= warmup) {
            /* Keyed off the first counted operation, not off i == warmup: this
             * loop skips failed connects, so an index-triggered open can be
             * stepped over entirely, leaving t_open at 0 and the thread's rate
             * computed against the epoch. */
            if (a->slot->counted == 0) a->slot->t_open = t0;
            a->slot->counted++;
            a->slot->t_close = t1;
            lat_record(&a->slot->lat, t1 - t0);
        }
    }

    a->thread_success = local;
    return NULL;
}

static struct run_result bench_ws_concurrent(struct bench_config *cfg)
{
    struct run_result r = {0};

    int nc = cfg->num_clients;
    int per_thread = cfg->num_ops - cfg->num_ops * cfg->warmup_pct / 100;
    int cap = nc * (per_thread > 0 ? per_thread : 1);
    if (cap > MAX_LATENCIES) cap = MAX_LATENCIES;
    lat_init(&r.latencies, cap);

    pthread_t *threads = (pthread_t *)malloc(nc * sizeof(pthread_t));
    struct ws_concurrent_args *args =
        (struct ws_concurrent_args *)malloc(nc * sizeof(*args));
    struct conc_slot *slots = (struct conc_slot *)calloc(nc, sizeof(*slots));

    pthread_barrier_t barrier;
    pthread_barrier_init(&barrier, NULL, nc + 1);

    for (int i = 0; i < nc; i++) {
        args[i].cfg = cfg;
        args[i].barrier = &barrier;
        args[i].thread_success = 0;
        args[i].slot = &slots[i];
        lat_init(&slots[i].lat, per_thread > 0 ? per_thread : 1);
        pthread_create(&threads[i], NULL, ws_concurrent_worker, &args[i]);
    }

    pthread_barrier_wait(&barrier);

    for (int i = 0; i < nc; i++)
        pthread_join(threads[i], NULL);

    int total = 0;
    for (int i = 0; i < nc; i++) {
        total += args[i].thread_success;
        lat_merge(&r.latencies, &slots[i].lat);
    }

    struct conc_summary cs = conc_finalize(slots, nc);

    for (int i = 0; i < nc; i++)
        lat_free(&slots[i].lat);
    free(slots);

    pthread_barrier_destroy(&barrier);
    free(threads);
    free(args);

    r.success = total;
    /* Timed: the clock ends the run, so a short count is the design and not a
     * failure.  Counted: every connection owed num_ops. */
    r.expected = (cfg->duration_ms > 0) ? 0 : nc * cfg->num_ops;
    /* The counted span, not total/elapsed: the wall includes the connect storm,
     * the barrier and the join, and that bias never averages out. */
    r.throughput = cs.rate;
    r.overlap = cs.overlap;

    return r;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Multi-run executor + output
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct run_result (*bench_fn)(struct bench_config *);

/* Does this test burn an ephemeral port for every operation it counts?
 *
 * Such a test must not be given a discarded warm-up run.  Warming helps where
 * runs reuse state and hurts where what accumulates between them is
 * exhaustion: every connection is new by definition, so there is nothing to
 * warm, and the extra run only puts several thousand more sockets into
 * TIME_WAIT before the measurement starts.  That is the mechanism behind
 * `server burst`'s monotonic decline across repetitions (see bench_server.sh).
 *
 * METRIC_CONNECT catches `server conn` and `server burst`.  It does not catch
 * the two WebSocket tests, which connect, upgrade and close once per operation
 * and are published as round trips -- correctly, since an upgrade is a request
 * with a reply, but the port cost is the same.  Naming them here was the
 * alternative to relabelling them METRIC_CONNECT, which would have changed the
 * JSON key their rate is published under to say something false about what they
 * measure.
 *
 * Honestly, the WebSocket half of this is reasoning and not measurement.  `ws
 * concurrent 20 25` opens 500 connections per run, which is a tenth of what
 * `server burst` does, and at that size the effect does not surface: 14
 * interleaved invocations per arm put the difference in within-invocation
 * spread at 1.76x against 1.61x, which is 1.05 sigma and therefore nothing.  An
 * earlier six-invocation pair appeared to show 2.23x against 1.21x, and that
 * was this benchmark's own noise being read as a result -- it spreads 1.3-2.7x
 * by itself.  What stands without the numbers is that a run which opens every
 * connection fresh has no warm state to gain and pays ports either way, so it
 * is skipped for the same reason as the others rather than on a measured win.
 *
 * A test added later that opens a connection per operation has to be listed
 * here; nothing detects it automatically, which is why this is one function
 * with its reasoning attached rather than a condition spelled out at the one
 * place that needs it. */
static int consumes_a_port_per_op(const char *category, const char *test,
                                  enum metric_kind metric)
{
    if (metric == METRIC_CONNECT) return 1;
    if (strcmp(category, "ws") == 0 &&
        (strcmp(test, "handshake") == 0 || strcmp(test, "concurrent") == 0))
        return 1;
    return 0;
}

static void run_and_report(struct bench_config *cfg, bench_fn fn,
                           const char *category, const char *test,
                           const char *unit, enum metric_kind metric)
{
    int runs = cfg->runs;
    double *throughputs = (double *)malloc(runs * sizeof(double));
    double *throughputs_mb = (double *)malloc(runs * sizeof(double));
    struct run_result best = {0};
    lat_init(&best.latencies, 1);

    /* Find the run with the median throughput to extract its latencies */
    struct run_result *all_results =
        (struct run_result *)malloc(runs * sizeof(struct run_result));

    /* Warm-up runs are executed and dropped.  The first run against a freshly
     * started runtime pays for its page faults and its first pass through every
     * branch; averaged in, that cost is reported as the program being slower
     * than it is, and it lands on whichever side of a comparison happens to go
     * first.
     *
     * Skipped entirely for the tests that consume a port per operation: they
     * have no warm state to gain and would burn another run's worth of
     * ephemeral ports ahead of the measurement. */
    int warm = consumes_a_port_per_op(category, test, metric)
                   ? 0 : cfg->warmup_runs;
    for (int i = 0; i < warm; i++) {
        if (cfg->duration_ms > 0)
            g_run_deadline_ns = time_ns() + (int64_t)cfg->duration_ms * 1000000LL;
        struct run_result w = fn(cfg);
        lat_free(&w.latencies);
    }

    for (int i = 0; i < runs; i++) {
        /* Set per run, not once: each run gets its own full window. */
        if (cfg->duration_ms > 0)
            g_run_deadline_ns = time_ns() + (int64_t)cfg->duration_ms * 1000000LL;
        all_results[i] = fn(cfg);
        throughputs[i] = all_results[i].throughput;
        throughputs_mb[i] = all_results[i].throughput_mb;
    }
    g_run_deadline_ns = 0;

    /* Kept before median_double sorts the array in place.
     *
     * A single run has no spread to report, and reporting one anyway is the
     * failure this whole change is about: hi/lo of one sample is exactly 1.00,
     * which would be published as spread_ratio 1.00 and stable=1 -- a claim of
     * perfect repeatability derived from something that was never repeated.
     * Below two runs the fields are omitted entirely, so a reader sees nothing
     * rather than a reassuring number. */
    double lo = 0, hi = 0, spread = 0.0;
    if (runs >= 2) {
        lo = hi = throughputs[0];
        for (int i = 1; i < runs; i++) {
            if (throughputs[i] < lo) lo = throughputs[i];
            if (throughputs[i] > hi) hi = throughputs[i];
        }
        if (lo > 0) spread = hi / lo;
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

    /* Second, independent signal.  Counting completed operations is not enough
     * on its own: the client tallies responses by newline and can overshoot on
     * the final read, so a broken run can still report success >= expected.
     * Repetitions of one test on one machine do not legitimately differ by two
     * orders of magnitude, so such a spread means at least one run measured
     * something other than throughput. */
    if (runs >= 2 && spread > 0) {
        if (spread > SPREAD_FATAL) {
            g_incomplete_runs++;
            fprintf(stderr,
                "socketley-bench: UNSTABLE %s %s: runs span %.0f..%.0f (%.1fx) — "
                "repetitions of one test should not differ this much; at least "
                "one run measured something other than throughput\n",
                category, test, lo, hi, spread);
        } else if (spread > SPREAD_WARN) {
            fprintf(stderr,
                "socketley-bench: SPREAD %s %s: runs span %.0f..%.0f (%.1fx) — "
                "the median is not a number to quote on its own; report the "
                "range\n",
                category, test, lo, hi, spread);
        }
    }

    /* How much of the run actually had every thread working.  The rate is
     * honest either way -- it is completed operations over the span they
     * completed in -- but what the rate is a rate *of* changes: at 0.98 it is
     * throughput at N concurrent clients, at 0.66 it is an average over a
     * concurrency that drained away as threads finished, and reading the second
     * as the first overstates what the runtime sustains at N. */
    for (int i = 0; i < runs; i++) {
        if (all_results[i].overlap > 0 && all_results[i].overlap < 0.80) {
            fprintf(stderr,
                "socketley-bench: OVERLAP %s %s run %d/%d: every thread was "
                "working for only %.0f%% of the run — this is an average over a "
                "falling concurrency, not a rate at %d clients\n",
                category, test, i + 1, runs, all_results[i].overlap * 100.0,
                cfg->num_clients);
        }
    }

    for (int i = 0; i < runs; i++) {
        if (all_results[i].expected > 0 &&
            all_results[i].success < all_results[i].expected) {
            g_incomplete_runs++;
            fprintf(stderr,
                "socketley-bench: INCOMPLETE %s %s run %d/%d: %d of %d operations "
                "completed — the elapsed time measures waiting, not throughput\n",
                category, test, i + 1, runs,
                all_results[i].success, all_results[i].expected);
        }
    }

    struct latency_log *lat = &all_results[best_idx].latencies;
    lat_sort(lat);

    /* The smallest difference this invocation could have told from its own
     * noise, as a percentage of the median.  Computed from the runs as they
     * came out, before the sort that median_double left behind. */
    double ci_pct = 0;
    if (runs >= 2 && med > 0) {
        double *raw = (double *)malloc((size_t)runs * sizeof(double));
        for (int i = 0; i < runs; i++) raw[i] = all_results[i].throughput;
        ci_pct = 100.0 * ci95_half_width(raw, runs) / med;
        free(raw);
    }

    if (cfg->json) {
        json_reset();
        json_start(stdout);
        json_kv_str(stdout, "test", test);
        json_kv_str(stdout, "category", category);
        json_kv_int(stdout, "runs", runs);
        json_kv_int(stdout, "operations", cfg->num_ops);
        /* Payload size belongs in the output because several tests differ in
           nothing else: bench_cache.sh runs "cache set" once per value size,
           and without this the resulting records are indistinguishable, so
           tooling comparing two benchmark runs cannot line them up. */
        json_kv_int(stdout, "msg_size", cfg->msg_size);
        /* What was measured, and the rate under a key that says the same.  A
         * file from before this carries median_throughput and nothing else; a
         * reader that finds neither key it knows has been told the two runs are
         * not comparable, which is the truth. */
        json_kv_str(stdout, "metric", metric_name(metric));
        json_kv_dbl(stdout, metric_rate_key(metric), med);
        /* How much of that figure is the measurement and how much is the
         * machine.  A median with no width beside it invites a reader to treat
         * a 10% move between two files as a result; these say whether it can
         * be one, from two directions: the observed spread, and the CI the run
         * count supports. */
        if (spread > 0) {
            json_kv_dbl(stdout, "min_per_sec", lo);
            json_kv_dbl(stdout, "max_per_sec", hi);
            json_kv_dbl(stdout, "spread_ratio", spread);
            json_kv_int(stdout, "stable", spread <= SPREAD_WARN);
        }
        if (all_results[best_idx].overlap > 0)
            json_kv_dbl(stdout, "thread_overlap", all_results[best_idx].overlap);
        json_kv_int(stdout, "duration_ms", cfg->duration_ms);
        json_kv_int(stdout, "warmup_runs", cfg->warmup_runs);
        json_kv_dbl(stdout, "ci95_half_width_pct", ci_pct);
        if (med_mb > 0)
            json_kv_dbl(stdout, "median_MB_per_sec", med_mb);
        json_kv_int(stdout, "success", all_results[best_idx].success);
        if (all_results[best_idx].expected > 0) {
            json_kv_int(stdout, "expected", all_results[best_idx].expected);
            json_kv_int(stdout, "complete",
                        all_results[best_idx].success >= all_results[best_idx].expected);
        }
        json_kv_int(stdout, "failed", all_results[best_idx].failed);
        if (lat->count > 0) {
            /* Prefixed by what a sample is.  "lat_p50_us" on a write-only loop
             * was the cost of write() presented as a service latency, and the
             * name is what let it be read as one. */
            char k[32];
            const char *p = metric_lat_prefix(metric);
            snprintf(k, sizeof k, "%s_min_us", p); json_kv_dbl(stdout, k, ns_to_us(lat_percentile(lat, 0)));
            snprintf(k, sizeof k, "%s_p50_us", p); json_kv_dbl(stdout, k, ns_to_us(lat_percentile(lat, 50)));
            snprintf(k, sizeof k, "%s_p95_us", p); json_kv_dbl(stdout, k, ns_to_us(lat_percentile(lat, 95)));
            snprintf(k, sizeof k, "%s_p99_us", p); json_kv_dbl(stdout, k, ns_to_us(lat_percentile(lat, 99)));
            snprintf(k, sizeof k, "%s_max_us", p); json_kv_dbl(stdout, k, ns_to_us(lat_percentile(lat, 100)));
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
            printf("  (%.1f MB/s one way)", med_mb);
        printf("\n");
        /* Printed for every test, not only unstable ones.  A spread that is
         * only shown when it is bad teaches the reader that its absence means
         * nothing was checked. */
        if (spread > 0)
            printf("  Spread: %12.0f .. %.0f  (%.2fx)%s\n", lo, hi, spread,
                   spread > SPREAD_WARN ? "  — too wide to quote the median alone" : "");
        else
            printf("  Spread: not measured — a single run cannot have one\n");
        if (all_results[best_idx].overlap > 0)
            printf("  Threads all working for %.0f%% of the run\n",
                   all_results[best_idx].overlap * 100.0);
        if (runs >= 2)
            printf("  Resolves: differences above %.1f%% (95%% CI over %d runs); "
                   "anything smaller is this machine\n", ci_pct, runs);
        /* Beside the number, every time.  A figure copied out of this output
         * carries no context with it, so the context goes next to it. */
        printf("  Measures: %s\n", metric_meaning(metric));

        if (lat->count > 0) {
            printf("  %s (us):  min=%.1f  p50=%.1f  p95=%.1f  p99=%.1f  max=%.1f\n",
                   metric == METRIC_ROUND_TRIP ? "Round-trip latency"
                                               : (metric == METRIC_WRITE_ONLY ? "write() cost"
                                                                              : "Connect latency"),
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
        "  -w N        Warm-up percentage of a run's operations (default %d)\n"
        "  -d MS       Time-box each run to MS milliseconds; the operation count\n"
        "              becomes an upper bound.  Use this rather than guessing a\n"
        "              count: a count picked for today's speed shrinks the window\n"
        "              as the code gets faster, and a window of a few tens of\n"
        "              milliseconds measures the scheduler.  Worth most on the\n"
        "              concurrent tests, where without it a run ends at the\n"
        "              SLOWEST of its threads and the rate reported is that one's.\n"
        "  -W N        Run and discard N runs before the measured ones\n"
        "  -u PATH     Request target for the HTTP tests (default /)\n"
        "\n"
        "Categories and tests:\n"
        "  server conn <count>                  Connection rate\n"
        "  server burst <count>                 Burst connections\n"
        "  server msg <count> <size>            Round-trip rate (needs an echoing backend)\n"
        "  server ingest <count> <size>         Write-only: how fast --mode in can be fed\n"
        "  server concurrent <clients> <msgs>   Multi-client round trips (echoing backend)\n"
        "\n"
        "  cache set <count> [value_size]        SET throughput\n"
        "  cache get <count>                     GET throughput\n"
        "  cache mixed <count>                   80/20 GET/SET mix\n"
        "  cache concurrent <clients> <ops>      Multi-client\n"
        "\n"
        "  proxy tcp <count> [msg_size]          TCP forwarding\n"
        "  proxy concurrent <clients> <msgs>     Multi-client\n"
        "  proxy overhead <count> <backend_port> Direct vs proxied, paired (-r pairs)\n"
        "  proxy http-keepalive <clients> <reqs> HTTP on a reused connection\n"
        "  proxy http-close <clients> <reqs>     HTTP, one connection per request\n"
        "\n"
        "  ws handshake <count>                  WS upgrade rate\n"
        "  ws echo <count> [msg_size]            WS echo RTT\n"
        "  ws concurrent <clients> <ops>         Multi-client WS\n",
        prog, DEFAULT_RUNS, DEFAULT_WARMUP, DEFAULT_WARMUP_RUNS);
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);

    struct bench_config cfg = {0};
    cfg.runs = DEFAULT_RUNS;
    cfg.warmup_pct = DEFAULT_WARMUP;
    cfg.warmup_runs = DEFAULT_WARMUP_RUNS;
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
        } else if (strcmp(opt, "-d") == 0 && optind_local + 1 < argc) {
            cfg.duration_ms = atoi(argv[optind_local + 1]);
            if (cfg.duration_ms < 0) cfg.duration_ms = 0;
            optind_local += 2;
        } else if (strcmp(opt, "-W") == 0 && optind_local + 1 < argc) {
            cfg.warmup_runs = atoi(argv[optind_local + 1]);
            if (cfg.warmup_runs < 0) cfg.warmup_runs = 0;
            /* Upper clamp kept from the other side of this merge: -W is runs
             * discarded before the measured ones, so a typo of 1000 is an hour
             * of warm-up and no result. */
            if (cfg.warmup_runs > 10) cfg.warmup_runs = 10;
            optind_local += 2;
        } else if (strcmp(opt, "-u") == 0 && optind_local + 1 < argc) {
            cfg.path = argv[optind_local + 1];
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
            run_and_report(&cfg, bench_server_conn, "server", "conn", "conn/sec", METRIC_CONNECT);
        }
        else if (strcmp(test, "burst") == 0) {
            if (pcount >= 1) cfg.num_ops = atoi(argv[pstart]);
            run_and_report(&cfg, bench_server_burst, "server", "burst", "conn/sec", METRIC_CONNECT);
        }
        else if (strcmp(test, "msg") == 0) {
            if (pcount >= 1) cfg.num_ops = atoi(argv[pstart]);
            if (pcount >= 2) cfg.msg_size = atoi(argv[pstart + 1]);
            run_and_report(&cfg, bench_server_msg, "server", "msg", "round-trip/sec", METRIC_ROUND_TRIP);
        }
        else if (strcmp(test, "concurrent") == 0) {
            if (pcount >= 1) cfg.num_clients = atoi(argv[pstart]);
            if (pcount >= 2) cfg.num_ops = atoi(argv[pstart + 1]);
            run_and_report(&cfg, bench_server_concurrent, "server", "concurrent", "round-trip/sec", METRIC_ROUND_TRIP);
        }
        else if (strcmp(test, "ingest") == 0) {
            if (pcount >= 1) cfg.num_ops = atoi(argv[pstart]);
            if (pcount >= 2) cfg.msg_size = atoi(argv[pstart + 1]);
            run_and_report(&cfg, bench_server_ingest, "server", "ingest", "write/sec", METRIC_WRITE_ONLY);
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
            run_and_report(&cfg, bench_cache_set, "cache", "set", "round-trip/sec", METRIC_ROUND_TRIP);
        }
        else if (strcmp(test, "get") == 0) {
            if (pcount >= 1) cfg.num_ops = atoi(argv[pstart]);
            run_and_report(&cfg, bench_cache_get, "cache", "get", "round-trip/sec", METRIC_ROUND_TRIP);
        }
        else if (strcmp(test, "mixed") == 0) {
            if (pcount >= 1) cfg.num_ops = atoi(argv[pstart]);
            run_and_report(&cfg, bench_cache_mixed, "cache", "mixed", "round-trip/sec", METRIC_ROUND_TRIP);
        }
        else if (strcmp(test, "concurrent") == 0) {
            if (pcount >= 1) cfg.num_clients = atoi(argv[pstart]);
            if (pcount >= 2) cfg.num_ops = atoi(argv[pstart + 1]);
            run_and_report(&cfg, bench_cache_concurrent, "cache", "concurrent", "round-trip/sec", METRIC_ROUND_TRIP);
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
            run_and_report(&cfg, bench_proxy_tcp, "proxy", "tcp", "round-trip/sec", METRIC_ROUND_TRIP);
        }
        else if (strcmp(test, "concurrent") == 0) {
            if (pcount >= 1) cfg.num_clients = atoi(argv[pstart]);
            if (pcount >= 2) cfg.num_ops = atoi(argv[pstart + 1]);
            run_and_report(&cfg, bench_proxy_concurrent, "proxy", "concurrent", "round-trip/sec", METRIC_ROUND_TRIP);
        }
        else if (strcmp(test, "overhead") == 0) {
            if (pcount >= 1) cfg.num_ops = atoi(argv[pstart]);
            if (pcount >= 2) cfg.port2 = atoi(argv[pstart + 1]);
            bench_proxy_overhead(&cfg);
        }
        else if (strcmp(test, "http-keepalive") == 0) {
            if (pcount >= 1) cfg.num_clients = atoi(argv[pstart]);
            if (pcount >= 2) cfg.num_ops = atoi(argv[pstart + 1]);
            run_and_report(&cfg, bench_http_keepalive, "proxy", "http-keepalive",
                           "request/sec", METRIC_ROUND_TRIP);
        }
        else if (strcmp(test, "http-close") == 0) {
            if (pcount >= 1) cfg.num_clients = atoi(argv[pstart]);
            if (pcount >= 2) cfg.num_ops = atoi(argv[pstart + 1]);
            run_and_report(&cfg, bench_http_close, "proxy", "http-close",
                           "request/sec", METRIC_ROUND_TRIP);
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
            run_and_report(&cfg, bench_ws_handshake, "ws", "handshake", "handshake/sec", METRIC_ROUND_TRIP);
        }
        else if (strcmp(test, "echo") == 0) {
            if (pcount >= 1) cfg.num_ops = atoi(argv[pstart]);
            if (pcount >= 2) cfg.msg_size = atoi(argv[pstart + 1]);
            run_and_report(&cfg, bench_ws_echo, "ws", "echo", "round-trip/sec", METRIC_ROUND_TRIP);
        }
        else if (strcmp(test, "concurrent") == 0) {
            if (pcount >= 1) cfg.num_clients = atoi(argv[pstart]);
            if (pcount >= 2) cfg.num_ops = atoi(argv[pstart + 1]);
            run_and_report(&cfg, bench_ws_concurrent, "ws", "concurrent", "handshake/sec", METRIC_ROUND_TRIP);
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

    /* Exit non-zero when any run finished short.  The JSON still carries the
     * numbers so a failure can be inspected, but callers that check exit codes
     * will not silently fold an incomplete run into their results. */
    return g_incomplete_runs > 0 ? 2 : 0;
}
