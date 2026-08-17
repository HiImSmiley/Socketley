/*
 * floor_sockmap — the same four handoffs, with the relay taken out of the loop
 *
 * floor_relay is accept, read, write, read, write: two syscalls and one copy in
 * each direction, plus the wakeup that gets the relay onto a CPU to do them.
 * Measured on this tree, that is 12.25us of CPU per round trip over a direct
 * connection, of which `--backend unix:` takes about 3.
 *
 * A BPF sockmap moves the bytes between the two sockets inside the kernel: the
 * verdict program runs at the point the data arrives and hands the skb to the
 * other socket, so the relay process is never woken and never copies anything.
 * If the remaining 9us is mostly the relay's syscalls and copies, this drops it
 * and the phase is worth building.  If it is the two socket traversals and the
 * two wakeups themselves, this changes little and the phase is dead before any
 * socketley code is written.  That is the whole question, and it is cheaper to
 * ask here than in proxy_instance.cpp.
 *
 * ── THE ANSWER, and it points both ways ────────────────────────────────────
 *
 * Measured against floor_relay on the same core, 64B, 40k round trips a pass,
 * five passes, medians:
 *
 *                     wall p50      CPU per round trip
 *   direct             9.96 us        5.25 us
 *   floor_relay       21.38 us       17.00 us
 *   floor_sockmap     23.16 us        7.50 us
 *
 * The CPU is real and it is large: 9.5us gone, which is 83% of the relay's own
 * share (17.00 - 5.25 = 11.75).  More than three times what `--backend unix:`
 * was worth.
 *
 * And the latency is WORSE by 1.8us.  A redirect is handed to sk_psock rather
 * than done inline, so the byte takes a scheduling hop the copy path does not.
 * At one connection on one core that hop is the whole critical path and the
 * freed CPU has nothing to do with itself -- the same divergence AF_UNIX
 * showed, except here it changes the sign.
 *
 * So this is a throughput lever with a latency cost, not a faster relay.
 * Whether the CPU converts is the open question, and answering it needs a
 * prototype this one is not: the map holds one pair, so there is no
 * concurrency to measure.  A multi-connection version needs BPF_MAP_TYPE_SOCKHASH
 * and a verdict keyed on the reversed 4-tuple, which is a real program rather
 * than eleven instructions.
 *
 * No clang and no libbpf on this box, so the two programs are assembled by hand
 * and loaded through the bare bpf() syscall.  They are eleven and two
 * instructions; a toolchain would be more machinery than the thing it builds.
 *
 * WHICH WAY IS WHICH.  A verdict program is attached to the map, not to a
 * socket, so it sees data arriving on both halves and has to work out which one
 * it came from.  It reads __sk_buff.local_port, which is in host byte order:
 * data arriving on the client's connection has the relay's listen port as its
 * local port, and data arriving from the backend has an ephemeral one.  So
 * local_port == listen_port means "from the client, send to the backend".
 *
 * Needs root: unprivileged BPF is disabled here (kernel.unprivileged_bpf_disabled=2).
 * It creates one map and two programs, attaches them to that map alone, and
 * exits; nothing is pinned and no system-wide hook is touched.
 *
 * Compile: it is a premake project -- bin/<config>/floor_sockmap
 * Run:     sudo ./floor_sockmap <listen-port> <backend-host> <backend-port>
 *
 * ONE CONNECTION AT A TIME, deliberately: the map has two entries and the
 * verdict tells the halves apart by local port.  It is an instrument, not a
 * relay.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <linux/bpf.h>

#ifndef BPF_PSEUDO_MAP_FD
#define BPF_PSEUDO_MAP_FD 1
#endif

#define INSN(C, D, S, O, I) \
    ((struct bpf_insn){ .code = (C), .dst_reg = (D), .src_reg = (S), .off = (O), .imm = (I) })

#define MOV64_REG(D, S)      INSN(BPF_ALU64 | BPF_MOV | BPF_X, D, S, 0, 0)
#define MOV64_IMM(D, I)      INSN(BPF_ALU64 | BPF_MOV | BPF_K, D, 0, 0, I)
#define LDX_W(D, S, O)       INSN(BPF_LDX  | BPF_SIZE(BPF_W) | BPF_MEM, D, S, O, 0)
#define JNE_IMM(D, I, O)     INSN(BPF_JMP  | BPF_JNE | BPF_K, D, 0, O, I)
#define JMP_A(O)             INSN(BPF_JMP  | BPF_JA  | BPF_K, 0, 0, O, 0)
#define CALL(F)              INSN(BPF_JMP  | BPF_CALL, 0, 0, 0, F)
#define EXIT()               INSN(BPF_JMP  | BPF_EXIT, 0, 0, 0, 0)

static int bpf_sys(int cmd, union bpf_attr *attr)
{
    return (int)syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static char g_log[65536];

static int load_prog(enum bpf_prog_type type, const struct bpf_insn *insns, int n)
{
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.prog_type = type;
    a.insns = (uint64_t)(unsigned long)insns;
    a.insn_cnt = (uint32_t)n;
    a.license = (uint64_t)(unsigned long)"GPL";
    a.log_buf = (uint64_t)(unsigned long)g_log;
    a.log_size = sizeof(g_log);
    a.log_level = 1;
    g_log[0] = '\0';
    const int fd = bpf_sys(BPF_PROG_LOAD, &a);
    if (fd < 0)
        fprintf(stderr, "floor_sockmap: prog load failed: %s\n%s\n", strerror(errno), g_log);
    return fd;
}

/* How many times a program has run, so "the bytes did not move" can be told
 * apart from "the verdict never fired".  Needs kernel.bpf_stats_enabled=1 for
 * run_cnt to be maintained; without it this reports 0 and says so. */
static void report_runs(const char *what, int prog_fd)
{
    struct bpf_prog_info info;
    memset(&info, 0, sizeof(info));
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.info.bpf_fd = (uint32_t)prog_fd;
    a.info.info_len = sizeof(info);
    a.info.info = (uint64_t)(unsigned long)&info;
    if (bpf_sys(BPF_OBJ_GET_INFO_BY_FD, &a) < 0)
    {
        fprintf(stderr, "  %-8s info: %s\n", what, strerror(errno));
        return;
    }
    fprintf(stderr, "  %-8s run_cnt=%llu  run_time_ns=%llu\n", what,
            (unsigned long long)info.run_cnt, (unsigned long long)info.run_time_ns);
}

static int listen_on(int port)
{
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }
    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) { }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) { perror("bind"); return -1; }
    if (listen(fd, 128) < 0) { perror("listen"); return -1; }
    return fd;
}

static int dial(const char *host, int port)
{
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1) { close(fd); return -1; }
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0) { close(fd); return -1; }
    int opt = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) { }
    return fd;
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    if (argc < 4)
    {
        fprintf(stderr, "Usage: sudo %s <listen-port> <backend-host> <backend-port>\n", argv[0]);
        return 1;
    }
    const int lport = atoi(argv[1]);
    const char *bhost = argv[2];
    const int bport = atoi(argv[3]);
    if (lport <= 0 || lport > 65535 || bport <= 0 || bport > 65535)
    { fprintf(stderr, "floor_sockmap: bad port\n"); return 1; }

    /* ── the map ─────────────────────────────────────────────────────────── */
    union bpf_attr ma;
    memset(&ma, 0, sizeof(ma));
    ma.map_type = BPF_MAP_TYPE_SOCKMAP;
    ma.key_size = 4;
    ma.value_size = 4;      /* a socket fd */
    ma.max_entries = 2;
    const int map_fd = bpf_sys(BPF_MAP_CREATE, &ma);
    if (map_fd < 0) { fprintf(stderr, "floor_sockmap: map create: %s\n", strerror(errno)); return 2; }

    /* ── the parser: every byte that arrives is a whole message ──────────── */
    const struct bpf_insn parser[] = {
        LDX_W(BPF_REG_0, BPF_REG_1, (short)offsetof(struct __sk_buff, len)),
        EXIT(),
    };
    const int parser_fd = load_prog(BPF_PROG_TYPE_SK_SKB, parser,
                                    (int)(sizeof(parser) / sizeof(parser[0])));
    if (parser_fd < 0) return 2;

    /* ── the verdict: send it to the other half ──────────────────────────── */
    const struct bpf_insn verdict[] = {
        /* 0 */ MOV64_REG(BPF_REG_6, BPF_REG_1),
        /* 1 */ LDX_W(BPF_REG_3, BPF_REG_6, (short)offsetof(struct __sk_buff, local_port)),
        /* 2 */ JNE_IMM(BPF_REG_3, lport, 2),      /* not our listener -> from the backend */
        /* 3 */ MOV64_IMM(BPF_REG_3, 1),           /* from the client  -> key 1, the backend */
        /* 4 */ JMP_A(1),
        /* 5 */ MOV64_IMM(BPF_REG_3, 0),           /* from the backend -> key 0, the client */
        /* 6 */ MOV64_REG(BPF_REG_1, BPF_REG_6),
        /* 7 */ INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_2, BPF_PSEUDO_MAP_FD, 0, map_fd),
        /* 8 */ INSN(0, 0, 0, 0, 0),               /* the upper half of the 64-bit load */
        /* 9 */ MOV64_IMM(BPF_REG_4, 0),
        /*10 */ CALL(BPF_FUNC_sk_redirect_map),
        /*11 */ EXIT(),
    };
    const int verdict_fd = load_prog(BPF_PROG_TYPE_SK_SKB, verdict,
                                     (int)(sizeof(verdict) / sizeof(verdict[0])));
    if (verdict_fd < 0) return 2;

    union bpf_attr at;
    memset(&at, 0, sizeof(at));
    at.target_fd = (uint32_t)map_fd;
    at.attach_bpf_fd = (uint32_t)parser_fd;
    at.attach_type = BPF_SK_SKB_STREAM_PARSER;
    if (bpf_sys(BPF_PROG_ATTACH, &at) < 0)
    { fprintf(stderr, "floor_sockmap: attach parser: %s\n", strerror(errno)); return 2; }

    memset(&at, 0, sizeof(at));
    at.target_fd = (uint32_t)map_fd;
    at.attach_bpf_fd = (uint32_t)verdict_fd;
    at.attach_type = BPF_SK_SKB_STREAM_VERDICT;
    if (bpf_sys(BPF_PROG_ATTACH, &at) < 0)
    { fprintf(stderr, "floor_sockmap: attach verdict: %s\n", strerror(errno)); return 2; }

    const int lfd = listen_on(lport);
    if (lfd < 0) return 2;
    fprintf(stderr, "floor_sockmap: ready on %d -> %s:%d\n", lport, bhost, bport);

    for (;;)
    {
        const int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) { if (errno == EINTR) continue; perror("accept"); return 2; }
        int opt = 1;
        if (setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) { }
        const int bfd = dial(bhost, bport);
        if (bfd < 0) { close(cfd); continue; }

        uint32_t k;
        union bpf_attr ua;
        k = 0;
        memset(&ua, 0, sizeof(ua));
        ua.map_fd = (uint32_t)map_fd;
        ua.key = (uint64_t)(unsigned long)&k;
        ua.value = (uint64_t)(unsigned long)&cfd;
        if (bpf_sys(BPF_MAP_UPDATE_ELEM, &ua) < 0)
        { fprintf(stderr, "floor_sockmap: map[0]=client: %s\n", strerror(errno)); return 2; }
        k = 1;
        memset(&ua, 0, sizeof(ua));
        ua.map_fd = (uint32_t)map_fd;
        ua.key = (uint64_t)(unsigned long)&k;
        ua.value = (uint64_t)(unsigned long)&bfd;
        if (bpf_sys(BPF_MAP_UPDATE_ELEM, &ua) < 0)
        { fprintf(stderr, "floor_sockmap: map[1]=backend: %s\n", strerror(errno)); return 2; }

        /* ── WHAT ARRIVED BEFORE THE MAP DID ────────────────────────────
         *
         * A socket joins the sockmap after accept() and after the backend
         * connect, and a client that sends immediately has already put its
         * first request in the receive queue by then.  Adding the socket does
         * not re-parse what is already sitting there, so those bytes are
         * stranded: the verdict program never sees them, the backend never
         * gets them, and the connection hangs on the first request.  It cost
         * one round of "the relay works but the benchmark times out" to find.
         *
         * So both halves are drained once, by hand, into the other half.  Any
         * real implementation of this needs the same step, and it is the
         * reason a sockmap cannot simply be switched on for an existing
         * connection.
         */
        {
            char pre[65536];
            int half[2] = { cfd, bfd };
            for (int h = 0; h < 2; h++)
            {
                for (;;)
                {
                    const ssize_t r = recv(half[h], pre, sizeof(pre), MSG_DONTWAIT);
                    if (r <= 0) break;
                    ssize_t off = 0;
                    while (off < r)
                    {
                        const ssize_t w = send(half[h ^ 1], pre + off, (size_t)(r - off), 0);
                        if (w <= 0) break;
                        off += w;
                    }
                }
            }
        }

        /* Nothing else to do.  The kernel carries every byte from here on; this
         * process only waits for the client to go away so it can clean up.
         *
         * poll() and NOT recv(): a socket in a sockmap has its data taken by
         * the psock before userspace sees it, so a read here is at best a race
         * with the redirect for the same bytes.  POLLRDHUP asks the one
         * question this process still has an interest in. */
        struct pollfd pfd[2];
        pfd[0].fd = cfd; pfd[0].events = POLLRDHUP | POLLERR | POLLHUP;
        pfd[1].fd = bfd; pfd[1].events = POLLRDHUP | POLLERR | POLLHUP;
        for (;;)
        {
            const int pr = poll(pfd, 2, 1000);
            if (pr < 0 && errno == EINTR) continue;
            if (pr == 0) { report_runs("parser", parser_fd); report_runs("verdict", verdict_fd); continue; }
            break;
        }
        fprintf(stderr, "connection over:\n");
        report_runs("parser", parser_fd);
        report_runs("verdict", verdict_fd);

        k = 0; memset(&ua, 0, sizeof(ua));
        ua.map_fd = (uint32_t)map_fd; ua.key = (uint64_t)(unsigned long)&k;
        if (bpf_sys(BPF_MAP_DELETE_ELEM, &ua) < 0) { }
        k = 1; memset(&ua, 0, sizeof(ua));
        ua.map_fd = (uint32_t)map_fd; ua.key = (uint64_t)(unsigned long)&k;
        if (bpf_sys(BPF_MAP_DELETE_ELEM, &ua) < 0) { }
        close(cfd);
        close(bfd);
    }
}
