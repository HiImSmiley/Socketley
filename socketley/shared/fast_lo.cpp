#include "fast_lo.h"

#include <linux/bpf.h>
#include <linux/magic.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace socketley {

// SK_PASS is the verdict return value; not named in <linux/bpf.h>.
static constexpr int SKL_SK_PASS = 1;
// 127.0.0.1 as the context fields hold it.
static constexpr int32_t LO4 = 0x0100007f;
// The last two words of ::1 and of an IPv4-mapped address, as loaded from memory.
static constexpr int32_t LO6_W3 = 0x01000000;
static constexpr int32_t MAPPED_W2 = static_cast<int32_t>(0xffff0000u);
static constexpr int32_t SKL_TCP_ESTABLISHED = 1;
static constexpr int32_t SKL_TCP_LISTEN = 10;
static constexpr int32_t SKL_TCP_CLOSE = 7;

// The socket key is {local address, remote address, local port, remote port},
// four u32s, ports in network order in the low half; an address is its last 32
// bits, which is all that tells 127.0.0.1 (LO4, plain or IPv4-mapped) from ::1
// (LO6_W3) once the whole address was checked on entry, and this is the one
// place the width is named.
static constexpr uint32_t SKL_KEY = 16;
static constexpr int16_t KEY_REMOTE = 4;
static constexpr int16_t KEY_LPORT = 8;
static constexpr int16_t KEY_RPORT = 12;

// A state value: count is the pair's unread redirected backlog as the program
// last knew it, mark the count at which it next asks the reconciler for the
// truth, and ask the count at which the check in flight was asked, which names
// that check.  A count of SKL_TAINT pins the pair to TCP for its life; a mark
// of SKL_PENDING says a check is in flight.
struct state_val
{
    uint64_t count;
    uint64_t mark;
    uint64_t ask;
    uint64_t ours;   // 1 when this socket is one of our workers' (see load_ops)
};
static constexpr uint64_t SKL_TAINT = UINT64_MAX;
static constexpr uint64_t SKL_PENDING = UINT64_MAX;

// What the program puts in the ring to ask: the socket's key and its ask.
struct ask_rec
{
    uint8_t key[SKL_KEY];
    uint64_t ask;
};

// The reconciler's answer, which only the program applies, so it alone ever
// writes a state value and a taint can never be overwritten: the peer's true
// backlog, and the ask it answers, so an answer to an earlier check is thrown
// away rather than applied to a later one.
struct snap_val
{
    uint64_t rmem;
    uint64_t ask;
};

// The per-CPU event counters, each bumped once per socket: an entry at the
// sockops program, a taint (by its reason) at the sk_msg program.
enum : uint32_t { C_ENTERED, C_BOUND, C_UNANSWERED, C_BUDGET, C_PEER_OFF, C_COUNT };

// Big enough for thousands of checks in flight at 32 bytes a record.
static constexpr uint32_t SKL_RING_BYTES = 256u << 10;

bool parse_fast_lo_mode(std::string_view v, fast_lo_mode& out)
{
    if (v == "own") { out = fast_lo_mode::own; return true; }
    if (v == "all") { out = fast_lo_mode::all; return true; }
    return false;
}

bool parse_fast_lo_limit(std::string_view v, fast_lo_limits& out)
{
    const size_t comma = v.find(',');
    if (comma == std::string_view::npos)
        return false;
    auto to_mib = [](std::string_view s, uint64_t& bytes) {
        if (s.empty())
            return false;
        uint64_t mib = 0;
        for (char c : s)
        {
            if (c < '0' || c > '9')
                return false;
            mib = mib * 10 + static_cast<uint64_t>(c - '0');
            if (mib > (1ull << 20))       // a terabyte of MiB is a typo, not a bound
                return false;
        }
        if (mib == 0)
            return false;
        bytes = mib << 20;
        return true;
    };
    fast_lo_limits parsed;
    if (!to_mib(v.substr(0, comma), parsed.pair_bytes) ||
        !to_mib(v.substr(comma + 1), parsed.global_bytes))
        return false;
    if (parsed.global_bytes < parsed.pair_bytes)
        return false;
    out = parsed;
    return true;
}

static long sys_bpf(int cmd, union bpf_attr* attr)
{
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int map_create(uint32_t type, uint32_t key, uint32_t value, uint32_t entries,
                      const char* name, uint32_t flags = 0)
{
    union bpf_attr a{};
    a.map_type = type;
    a.key_size = key;
    a.value_size = value;
    a.max_entries = entries;
    a.map_flags = flags;
    std::strncpy(a.map_name, name, sizeof(a.map_name) - 1);
    return static_cast<int>(sys_bpf(BPF_MAP_CREATE, &a));
}

static void map_put(int fd, const void* key, const void* value, uint64_t flags)
{
    union bpf_attr a{};
    a.map_fd = static_cast<uint32_t>(fd);
    a.key = reinterpret_cast<uint64_t>(key);
    a.value = reinterpret_cast<uint64_t>(value);
    a.flags = flags;
    if (sys_bpf(BPF_MAP_UPDATE_ELEM, &a) != 0) {}
}

// A few instructions and forward labels, enough to write the two programs
// below as they read rather than as hand-counted jump offsets.
class bpf_asm
{
public:
    int label() { m_at.push_back(-1); return static_cast<int>(m_at.size()) - 1; }
    void bind(int l) { m_at[l] = static_cast<int>(m_code.size()); }

    void op(uint8_t code, uint8_t dst, uint8_t src, int16_t off, int32_t imm)
    {
        struct bpf_insn i{};
        i.code = code; i.dst_reg = dst; i.src_reg = src; i.off = off; i.imm = imm;
        m_code.push_back(i);
    }
    void mov(uint8_t dst, uint8_t src) { op(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, 0, 0); }
    void movi(uint8_t dst, int32_t imm) { op(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm); }
    void addi(uint8_t dst, int32_t imm) { op(BPF_ALU64 | BPF_ADD | BPF_K, dst, 0, 0, imm); }
    void add(uint8_t dst, uint8_t src) { op(BPF_ALU64 | BPF_ADD | BPF_X, dst, src, 0, 0); }
    void sub(uint8_t dst, uint8_t src) { op(BPF_ALU64 | BPF_SUB | BPF_X, dst, src, 0, 0); }
    void rshi(uint8_t dst, int32_t imm) { op(BPF_ALU64 | BPF_RSH | BPF_K, dst, 0, 0, imm); }
    void be32(uint8_t dst) { op(BPF_ALU | BPF_END | BPF_TO_BE, dst, 0, 0, 32); }
    void ldw(uint8_t dst, uint8_t src, size_t off) { op(BPF_LDX | BPF_MEM | BPF_W, dst, src, static_cast<int16_t>(off), 0); }
    void lddw(uint8_t dst, uint8_t src, long off) { op(BPF_LDX | BPF_MEM | BPF_DW, dst, src, static_cast<int16_t>(off), 0); }
    void stx8(uint8_t dst, int off, uint8_t src) { op(BPF_STX | BPF_MEM | BPF_DW, dst, src, static_cast<int16_t>(off), 0); }
    void stw(int16_t fp_off, uint8_t src) { op(BPF_STX | BPF_MEM | BPF_W, BPF_REG_10, src, fp_off, 0); }
    void stwi(int16_t fp_off, int32_t imm) { op(BPF_ST | BPF_MEM | BPF_W, BPF_REG_10, 0, fp_off, imm); }
    void fp_ptr(uint8_t dst, int16_t fp_off) { mov(dst, BPF_REG_10); addi(dst, fp_off); }
    void call(int32_t fn) { op(BPF_JMP | BPF_CALL, 0, 0, 0, fn); }
    void exit() { op(BPF_JMP | BPF_EXIT, 0, 0, 0, 0); }

    void ld64(uint8_t dst, uint64_t v)
    {
        op(BPF_LD | BPF_DW | BPF_IMM, dst, 0, 0, static_cast<int32_t>(v & 0xffffffffu));
        op(0, 0, 0, 0, static_cast<int32_t>(v >> 32));
    }
    void ld_map(uint8_t dst, int fd)
    {
        op(BPF_LD | BPF_DW | BPF_IMM, dst, BPF_PSEUDO_MAP_FD, 0, fd);
        op(0, 0, 0, 0, 0);
    }

    void jmp(int l) { fix(l); op(BPF_JMP | BPF_JA, 0, 0, 0, 0); }
    void jeqi(uint8_t r, int32_t imm, int l) { fix(l); op(BPF_JMP | BPF_JEQ | BPF_K, r, 0, 0, imm); }
    void jnei(uint8_t r, int32_t imm, int l) { fix(l); op(BPF_JMP | BPF_JNE | BPF_K, r, 0, 0, imm); }
    // A 32-bit compare, for an immediate with its top bit set.
    void jnei32(uint8_t r, int32_t imm, int l) { fix(l); op(BPF_JMP32 | BPF_JNE | BPF_K, r, 0, 0, imm); }
    void jne(uint8_t r, uint8_t s, int l) { fix(l); op(BPF_JMP | BPF_JNE | BPF_X, r, s, 0, 0); }
    void jeq(uint8_t r, uint8_t s, int l) { fix(l); op(BPF_JMP | BPF_JEQ | BPF_X, r, s, 0, 0); }
    void jge(uint8_t r, uint8_t s, int l) { fix(l); op(BPF_JMP | BPF_JGE | BPF_X, r, s, 0, 0); }
    void jgt(uint8_t r, uint8_t s, int l) { fix(l); op(BPF_JMP | BPF_JGT | BPF_X, r, s, 0, 0); }

    // Map helpers with the key and value on the stack.
    void lookup(int map, int16_t key)
    {
        ld_map(BPF_REG_1, map); fp_ptr(BPF_REG_2, key); call(BPF_FUNC_map_lookup_elem);
    }
    void erase(int map, int16_t key)
    {
        ld_map(BPF_REG_1, map); fp_ptr(BPF_REG_2, key); call(BPF_FUNC_map_delete_elem);
    }
    void update(int map, int16_t key, int16_t value, int32_t flags)
    {
        ld_map(BPF_REG_1, map); fp_ptr(BPF_REG_2, key); fp_ptr(BPF_REG_3, value);
        movi(BPF_REG_4, flags); call(BPF_FUNC_map_update_elem);
    }
    // Adds one to a u64 array slot whose u32 index is on the stack at `key`.
    void bump(int map, int16_t key)
    {
        const int none = label();
        lookup(map, key); jeqi(BPF_REG_0, 0, none);
        movi(BPF_REG_1, 1);
        op(BPF_STX | BPF_ATOMIC | BPF_DW, BPF_REG_0, BPF_REG_1, 0, BPF_ADD);
        bind(none);
    }

    // Resolves every jump; false if a label was never bound.
    bool finish()
    {
        for (auto [at, l] : m_fix)
        {
            if (m_at[l] < 0)
                return false;
            m_code[at].off = static_cast<int16_t>(m_at[l] - at - 1);
        }
        return true;
    }
    const std::vector<struct bpf_insn>& code() const { return m_code; }

private:
    void fix(int l) { m_fix.emplace_back(static_cast<int>(m_code.size()), l); }

    std::vector<struct bpf_insn> m_code;
    std::vector<int> m_at;
    std::vector<std::pair<int, int>> m_fix;
};

// The last verifier log, kept so a rejected program is debuggable.
static char g_verifier_log[16384];

static int prog_load(const bpf_asm& a, uint32_t type, const char* name)
{
    union bpf_attr at{};
    at.prog_type = type;
    at.insns = reinterpret_cast<uint64_t>(a.code().data());
    at.insn_cnt = static_cast<uint32_t>(a.code().size());
    at.license = reinterpret_cast<uint64_t>("Apache-2.0");
    at.log_level = 1;
    at.log_size = sizeof(g_verifier_log);
    at.log_buf = reinterpret_cast<uint64_t>(g_verifier_log);
    g_verifier_log[0] = '\0';
    std::strncpy(at.prog_name, name, sizeof(at.prog_name) - 1);
    // The verifier gives up with EAGAIN whenever the caller has a signal or
    // task work pending, which the daemon's io_uring queues, so it is retried
    // as libbpf retries it.
    for (int attempt = 1;; ++attempt)
    {
        const long fd = sys_bpf(BPF_PROG_LOAD, &at);
        if (fd >= 0 || errno != EAGAIN || attempt == 5)
            return static_cast<int>(fd);
    }
}

// The peer's key is this socket's with the addresses swapped and the ports
// swapped.
static constexpr int16_t K_PORT = -4;    // u32 port, the ports map's key
static constexpr int16_t K_SELF = -24;   // this socket's key
static constexpr int16_t K_PEER = -40;   // the peer's key
static constexpr int16_t K_VAL  = -44;   // u32 map value
static constexpr int16_t K_TGID = -48;   // u32 tgid, the pids map's key
static constexpr int16_t K_OURS = -52;   // u32 ownership flag on the way to enter
static constexpr int16_t K_INIT = -88;   // state_val (32 bytes), a fresh socket's counter

// The sockops program, which sorts sockets at four moments: a listen or a
// connect by one of this daemon's processes is remembered, an established
// loopback pair to one of its ports -- or in all mode from one of its connects
// to any local listener -- enters the sockhash with a zeroed backlog counter,
// and the close of such a socket deletes what it left in the maps.
static int load_ops(int socks, int ports, int mine, int state, int snap, int pids,
                    int counters, bool all, uint64_t pair_bytes, uint64_t netns_cookie)
{
    bpf_asm a;
    const int out = a.label(), listen = a.label(), st = a.label(), connect = a.label();
    const int active = a.label(), enter = a.label(), not_passive = a.label();
    const int active_notours = a.label();

    // Ours: the calling process is one of this daemon's workers.
    auto ours = [&] {
        a.call(BPF_FUNC_get_current_pid_tgid); a.rshi(BPF_REG_0, 32); a.stw(K_TGID, BPF_REG_0);
        a.lookup(pids, K_TGID); a.jeqi(BPF_REG_0, 0, out);
    };
    // Both keys from the addresses' last words, an AF_INET socket's IPv4
    // field being an IPv4-mapped address's; r8 is the local port and r9 the
    // remote, and this is the only spelling of the key layout in this program.
    auto keys = [&] {
        const int v4 = a.label(), store = a.label();
        a.ldw(BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_ops, remote_port)); a.rshi(BPF_REG_9, 16);
        a.ldw(BPF_REG_3, BPF_REG_6, offsetof(struct bpf_sock_ops, family));
        a.jeqi(BPF_REG_3, AF_INET, v4);
        a.jnei(BPF_REG_3, AF_INET6, out);
        a.ldw(BPF_REG_1, BPF_REG_6, offsetof(struct bpf_sock_ops, local_ip6[3]));
        a.ldw(BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_ops, remote_ip6[3]));
        a.jmp(store);
        a.bind(v4);
        a.ldw(BPF_REG_1, BPF_REG_6, offsetof(struct bpf_sock_ops, local_ip4));
        a.ldw(BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_ops, remote_ip4));
        a.bind(store);
        a.stw(K_SELF, BPF_REG_1); a.stw(K_SELF + KEY_REMOTE, BPF_REG_2);
        a.stw(K_SELF + KEY_LPORT, BPF_REG_8); a.stw(K_SELF + KEY_RPORT, BPF_REG_9);
        a.stw(K_PEER, BPF_REG_2); a.stw(K_PEER + KEY_REMOTE, BPF_REG_1);
        a.stw(K_PEER + KEY_LPORT, BPF_REG_9); a.stw(K_PEER + KEY_RPORT, BPF_REG_8);
    };
    // Both whole addresses are 127.0.0.1 (plain or IPv4-mapped) or ::1, else out.
    auto loopback = [&] {
        const int v4 = a.label(), done = a.label();
        a.ldw(BPF_REG_3, BPF_REG_6, offsetof(struct bpf_sock_ops, family));
        a.jeqi(BPF_REG_3, AF_INET, v4);
        for (size_t base : { offsetof(struct bpf_sock_ops, local_ip6),
                             offsetof(struct bpf_sock_ops, remote_ip6) })
        {
            const int mapped = a.label(), ok = a.label();
            a.ldw(BPF_REG_1, BPF_REG_6, base); a.jnei(BPF_REG_1, 0, out);
            a.ldw(BPF_REG_1, BPF_REG_6, base + 4); a.jnei(BPF_REG_1, 0, out);
            a.ldw(BPF_REG_1, BPF_REG_6, base + 8); a.ldw(BPF_REG_2, BPF_REG_6, base + 12);
            a.jnei(BPF_REG_1, 0, mapped);
            a.jeqi(BPF_REG_2, LO6_W3, ok);
            a.jmp(out);
            a.bind(mapped);
            a.jnei32(BPF_REG_1, MAPPED_W2, out); a.jnei(BPF_REG_2, LO4, out);
            a.bind(ok);
        }
        a.jmp(done);
        a.bind(v4);
        a.ldw(BPF_REG_1, BPF_REG_6, offsetof(struct bpf_sock_ops, local_ip4)); a.jnei(BPF_REG_1, LO4, out);
        a.ldw(BPF_REG_1, BPF_REG_6, offsetof(struct bpf_sock_ops, remote_ip4)); a.jnei(BPF_REG_1, LO4, out);
        a.bind(done);
    };
    auto set_state_cb = [&] {
        a.mov(BPF_REG_1, BPF_REG_6); a.movi(BPF_REG_2, BPF_SOCK_OPS_STATE_CB_FLAG);
        a.call(BPF_FUNC_sock_ops_cb_flags_set);
    };

    a.mov(BPF_REG_6, BPF_REG_1);
    a.ldw(BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_ops, op));
    a.ldw(BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_ops, local_port));
    a.be32(BPF_REG_8); a.rshi(BPF_REG_8, 16);
    a.stw(K_PORT, BPF_REG_8);
    a.jeqi(BPF_REG_7, BPF_SOCK_OPS_TCP_LISTEN_CB, listen);
    a.jeqi(BPF_REG_7, BPF_SOCK_OPS_STATE_CB, st);

    // A child inherits its listener's state callback, which only the listener needs.
    a.jnei(BPF_REG_7, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB, not_passive);
    a.mov(BPF_REG_1, BPF_REG_6); a.movi(BPF_REG_2, 0); a.call(BPF_FUNC_sock_ops_cb_flags_set);
    a.bind(not_passive);

    // Only the three moments below build keys, since every TCP socket under
    // the cgroup passes through here at its other callbacks too.
    const int sorted = a.label();
    a.jeqi(BPF_REG_7, BPF_SOCK_OPS_TCP_CONNECT_CB, sorted);
    a.jeqi(BPF_REG_7, BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, sorted);
    a.jnei(BPF_REG_7, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB, out);
    a.bind(sorted);
    // Only ever a socket in the daemon's own network namespace: at the root
    // cgroup this program fires for containers too, whose 127.0.0.1 pairs share
    // our tuple space and would otherwise overwrite our entries and be
    // redirected into.
    a.mov(BPF_REG_1, BPF_REG_6); a.call(BPF_FUNC_get_netns_cookie);
    a.ld64(BPF_REG_1, netns_cookie); a.jne(BPF_REG_0, BPF_REG_1, out);
    keys();
    loopback();
    a.jeqi(BPF_REG_7, BPF_SOCK_OPS_TCP_CONNECT_CB, connect);
    a.jeqi(BPF_REG_7, BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, active);

    // Passive: a listener of ours, and nothing received yet -- bytes that came
    // by TCP before the shortcut would be read after the ones that come by it.
    a.lddw(BPF_REG_1, BPF_REG_6, offsetof(struct bpf_sock_ops, bytes_received));
    a.jnei(BPF_REG_1, 0, out);
    a.lookup(ports, K_PORT);
    if (!all)
    {
        a.jeqi(BPF_REG_0, 0, out);
        a.lookup(mine, K_PEER); a.jeqi(BPF_REG_0, 0, out);
        a.erase(mine, K_PEER);
        a.stwi(K_OURS, 1);   // accepted on our listener, peer our connect: ours
    }
    else
    {
        // In all mode our listener accepting is ours; a foreign listener's
        // child, entered because a connect of ours made it, is not.
        const int foreign_child = a.label();
        a.jeqi(BPF_REG_0, 0, foreign_child);
        a.stwi(K_OURS, 1); a.jmp(enter);
        a.bind(foreign_child);
        a.lookup(mine, K_PEER); a.jeqi(BPF_REG_0, 0, out);
        a.erase(mine, K_PEER);
        a.stwi(K_OURS, 0);
    }
    a.jmp(enter);

    // Active: to a port of ours, and in own mode from a connect of ours; in
    // all mode a connect of ours to any local listener enters too, and keeps
    // its mark for that listener's passive side to find.
    a.bind(active);
    a.stw(K_PORT, BPF_REG_9);
    a.lookup(ports, K_PORT); a.jeqi(BPF_REG_0, 0, active_notours);
    if (!all)
    {
        a.lookup(mine, K_SELF); a.jeqi(BPF_REG_0, 0, out);
        a.stwi(K_OURS, 1);   // own mode: our connect to our listener
    }
    else
    {
        // Connecting to our listener; ours iff this socket is our own connect,
        // else a foreign client of it.
        a.lookup(mine, K_SELF);
        a.stwi(K_OURS, 0);
        const int notmine = a.label();
        a.jeqi(BPF_REG_0, 0, notmine);
        a.stwi(K_OURS, 1);
        a.bind(notmine);
    }
    a.jmp(enter);

    // In own mode a connect whose peer is not ours will never see passive, so
    // its mark goes.
    a.bind(active_notours);
    if (!all)
    {
        a.erase(mine, K_SELF);
        a.jmp(out);
    }
    else
    {
        a.lookup(mine, K_SELF); a.jeqi(BPF_REG_0, 0, out);
        a.stwi(K_OURS, 1);   // our connect to a foreign listener
        a.jmp(enter);
    }

    // Enter: a zero backlog whose first check falls at the per-pair bound, the
    // state callback that deletes it on close, and the sockhash.
    a.bind(enter);
    a.movi(BPF_REG_1, 0);
    a.stx8(BPF_REG_10, K_INIT + static_cast<int>(offsetof(state_val, count)), BPF_REG_1);
    a.stx8(BPF_REG_10, K_INIT + static_cast<int>(offsetof(state_val, ask)), BPF_REG_1);
    a.ld64(BPF_REG_1, pair_bytes); a.stx8(BPF_REG_10, K_INIT + static_cast<int>(offsetof(state_val, mark)), BPF_REG_1);
    a.ldw(BPF_REG_1, BPF_REG_10, K_OURS); a.stx8(BPF_REG_10, K_INIT + static_cast<int>(offsetof(state_val, ours)), BPF_REG_1);
    // NOEXIST: a live entry with our tuple must not be overwritten -- the close
    // callback deletes, so a reused tuple finds the key free.
    a.update(state, K_SELF, K_INIT, BPF_NOEXIST); a.jnei(BPF_REG_0, 0, out);
    set_state_cb();
    a.mov(BPF_REG_1, BPF_REG_6); a.ld_map(BPF_REG_2, socks); a.fp_ptr(BPF_REG_3, K_SELF);
    a.movi(BPF_REG_4, BPF_NOEXIST); a.call(BPF_FUNC_sock_hash_update);
    a.stwi(K_VAL, C_ENTERED); a.bump(counters, K_VAL);
    a.jmp(out);

    // A connect of ours is marked, and asks for the state callback so a
    // connect that never establishes still deletes its mark on close.
    a.bind(connect);
    ours();
    a.stwi(K_VAL, 1); a.update(mine, K_SELF, K_VAL, BPF_ANY);
    set_state_cb();
    a.jmp(out);

    // A listener counts its port, since reuseport listeners share one, and
    // asks for the state callback that takes the count down on close.
    a.bind(listen);
    ours();
    a.stwi(K_VAL, 0); a.update(ports, K_PORT, K_VAL, BPF_NOEXIST);
    a.lookup(ports, K_PORT); a.jeqi(BPF_REG_0, 0, out);
    a.movi(BPF_REG_1, 1);
    a.op(BPF_STX | BPF_ATOMIC | BPF_W, BPF_REG_0, BPF_REG_1, 0, BPF_ADD);
    set_state_cb();
    a.jmp(out);

    // State change: on the close of a socket that carried the flag, delete its
    // counter, any unapplied answer and its connect-mark; a listener's close
    // also uncounts its port.
    a.bind(st);
    a.ldw(BPF_REG_1, BPF_REG_6, offsetof(struct bpf_sock_ops, args[1])); a.jnei(BPF_REG_1, SKL_TCP_CLOSE, out);
    keys();
    a.erase(state, K_SELF);
    a.erase(snap, K_SELF);
    a.erase(mine, K_SELF);
    a.ldw(BPF_REG_1, BPF_REG_6, offsetof(struct bpf_sock_ops, args[0])); a.jnei(BPF_REG_1, SKL_TCP_LISTEN, out);
    a.lookup(ports, K_PORT); a.jeqi(BPF_REG_0, 0, out);
    a.movi(BPF_REG_1, -1);
    a.op(BPF_STX | BPF_ATOMIC | BPF_W, BPF_REG_0, BPF_REG_1, 0, BPF_ADD | BPF_FETCH);
    a.jnei(BPF_REG_1, 1, out);
    a.erase(ports, K_PORT);

    a.bind(out);
    a.movi(BPF_REG_0, 1);
    a.exit();

    if (!a.finish())
        return -1;
    return prog_load(a, BPF_PROG_TYPE_SOCK_OPS, "skl_fastlo_ops");
}

// The sk_msg program: a send goes to the peer's receive queue and is counted
// toward the pair's unread backlog.  Crossing the mark asks the reconciler,
// through the ring, for the peer's true queue, and the answer is applied on the
// next send; a reader that keeps up is snapped back long before the hard
// ceiling (twice the bound), while a stalled one is not and the pair is tainted
// to TCP for good -- real backpressure, and order kept because tcp_bpf_recvmsg
// drains the redirect queue before the TCP receive queue.
static int load_msg(int socks, int state, int snap, int ring, int budget, int counters,
                    uint64_t pair_bytes)
{
    bpf_asm a;
    const int pass = a.label(), do_redir = a.label(), taint_pass = a.label();
    const int no_snap = a.label(), stale = a.label(), counted = a.label();
    const int delta = a.label(), applied = a.label();
    const int t_bound = a.label(), t_unanswered = a.label(), t_budget = a.label();
    // The ask record is laid out on the stack as the ring carries it, key first,
    // so this socket's key is where the record starts.
    constexpr int16_t rec = -40, peer = -16, k0 = -44, rsave = -56;
    constexpr int16_t self = rec + static_cast<int16_t>(offsetof(ask_rec, key));
    constexpr int16_t rec_ask = rec + static_cast<int16_t>(offsetof(ask_rec, ask));
    const uint64_t hard = pair_bytes * 2;

    // r6 = ctx, r7 = this message's size, r8 = the state value, r9 = its count
    // (on the way to a taint, its reason); all four are kept across the helper
    // calls.

    // The key as the sockops program builds it: the addresses' last words.
    auto keys = [&] {
        const int v4 = a.label(), store = a.label();
        a.ldw(BPF_REG_2, BPF_REG_6, offsetof(struct sk_msg_md, family));
        a.jeqi(BPF_REG_2, AF_INET, v4);
        a.ldw(BPF_REG_7, BPF_REG_6, offsetof(struct sk_msg_md, local_ip6[3]));
        a.ldw(BPF_REG_8, BPF_REG_6, offsetof(struct sk_msg_md, remote_ip6[3]));
        a.jmp(store);
        a.bind(v4);
        a.ldw(BPF_REG_7, BPF_REG_6, offsetof(struct sk_msg_md, local_ip4));
        a.ldw(BPF_REG_8, BPF_REG_6, offsetof(struct sk_msg_md, remote_ip4));
        a.bind(store);
        a.ldw(BPF_REG_9, BPF_REG_6, offsetof(struct sk_msg_md, local_port)); a.be32(BPF_REG_9); a.rshi(BPF_REG_9, 16);
        a.ldw(BPF_REG_1, BPF_REG_6, offsetof(struct sk_msg_md, remote_port)); a.rshi(BPF_REG_1, 16);
        a.stw(self, BPF_REG_7); a.stw(self + KEY_REMOTE, BPF_REG_8);
        a.stw(self + KEY_LPORT, BPF_REG_9); a.stw(self + KEY_RPORT, BPF_REG_1);
        a.stw(peer, BPF_REG_8); a.stw(peer + KEY_REMOTE, BPF_REG_7);
        a.stw(peer + KEY_LPORT, BPF_REG_1); a.stw(peer + KEY_RPORT, BPF_REG_9);
    };

    a.mov(BPF_REG_6, BPF_REG_1);
    keys();
    a.ldw(BPF_REG_7, BPF_REG_6, offsetof(struct sk_msg_md, size));

    // A socket with no counter is not on the shortcut; leave it on TCP.
    a.lookup(state, self); a.jeqi(BPF_REG_0, 0, pass);
    a.mov(BPF_REG_8, BPF_REG_0);
    a.lddw(BPF_REG_9, BPF_REG_8, offsetof(state_val, count));
    a.ld64(BPF_REG_2, SKL_TAINT); a.jeq(BPF_REG_9, BPF_REG_2, pass);

    // Redirect only into a socket we own: a foreign receiver reached through the
    // psock ingress queue breaks any reader that is not recvmsg (splice, Go
    // io.Copy, HAProxy splicing), which we cannot enumerate.  The peer's own
    // state entry says whether it is ours; a peer not on the shortcut, or not
    // ours, keeps this direction on TCP without a taint.
    a.lookup(state, peer); a.jeqi(BPF_REG_0, 0, pass);
    a.lddw(BPF_REG_1, BPF_REG_0, offsetof(state_val, ours)); a.jeqi(BPF_REG_1, 0, pass);

    // A check in flight whose answer has arrived: the count becomes the peer's
    // true queue plus what was sent since the check was asked.
    a.lddw(BPF_REG_1, BPF_REG_8, offsetof(state_val, mark));
    a.ld64(BPF_REG_2, SKL_PENDING); a.jne(BPF_REG_1, BPF_REG_2, no_snap);
    a.lookup(snap, self); a.jeqi(BPF_REG_0, 0, no_snap);
    a.lddw(BPF_REG_1, BPF_REG_0, offsetof(snap_val, rmem));
    a.lddw(BPF_REG_2, BPF_REG_0, offsetof(snap_val, ask));
    a.lddw(BPF_REG_3, BPF_REG_8, offsetof(state_val, ask));
    a.jne(BPF_REG_2, BPF_REG_3, stale);
    a.stx8(BPF_REG_10, rsave, BPF_REG_1);
    a.jgt(BPF_REG_9, BPF_REG_2, delta);
    a.mov(BPF_REG_9, BPF_REG_1); a.jmp(applied);
    a.bind(delta);
    a.sub(BPF_REG_9, BPF_REG_2); a.add(BPF_REG_9, BPF_REG_1);
    a.bind(applied);
    a.stx8(BPF_REG_8, offsetof(state_val, count), BPF_REG_9);
    a.erase(snap, self);
    a.mov(BPF_REG_1, BPF_REG_9); a.ld64(BPF_REG_2, pair_bytes / 2); a.add(BPF_REG_1, BPF_REG_2);
    a.stx8(BPF_REG_8, offsetof(state_val, mark), BPF_REG_1);
    // The peer really holds the bound or more: a stalled reader.
    a.lddw(BPF_REG_1, BPF_REG_10, rsave); a.ld64(BPF_REG_2, pair_bytes); a.jge(BPF_REG_1, BPF_REG_2, t_bound);
    a.jmp(no_snap);
    // An answer to an earlier check than the one in flight: drop it and wait.
    a.bind(stale);
    a.erase(snap, self);
    a.bind(no_snap);

    // The global budget is a single flag the reconciler raises.
    a.stwi(k0, 0); a.lookup(budget, k0); a.jeqi(BPF_REG_0, 0, counted);
    a.lddw(BPF_REG_2, BPF_REG_0, 0); a.jnei(BPF_REG_2, 0, t_budget);
    a.bind(counted);

    a.add(BPF_REG_9, BPF_REG_7); a.stx8(BPF_REG_8, offsetof(state_val, count), BPF_REG_9);
    a.ld64(BPF_REG_1, hard); a.jge(BPF_REG_9, BPF_REG_1, t_unanswered);
    // Below the mark (a pending mark is above every count): nothing to ask.
    a.lddw(BPF_REG_1, BPF_REG_8, offsetof(state_val, mark)); a.jgt(BPF_REG_1, BPF_REG_9, do_redir);
    a.ld64(BPF_REG_1, SKL_PENDING); a.stx8(BPF_REG_8, offsetof(state_val, mark), BPF_REG_1);
    a.stx8(BPF_REG_8, offsetof(state_val, ask), BPF_REG_9);
    a.stx8(BPF_REG_10, rec_ask, BPF_REG_9);
    a.ld_map(BPF_REG_1, ring); a.fp_ptr(BPF_REG_2, rec); a.movi(BPF_REG_3, sizeof(ask_rec));
    a.movi(BPF_REG_4, 0); a.call(BPF_FUNC_ringbuf_output);

    a.bind(do_redir);
    a.mov(BPF_REG_1, BPF_REG_6); a.ld_map(BPF_REG_2, socks); a.fp_ptr(BPF_REG_3, peer);
    a.movi(BPF_REG_4, BPF_F_INGRESS); a.call(BPF_FUNC_msg_redirect_hash);
    a.jeqi(BPF_REG_0, SKL_SK_PASS, pass);
    // The peer is not in the sockhash: it received by TCP before it could
    // enter, or it has closed.
    a.movi(BPF_REG_9, C_PEER_OFF);
    a.jmp(taint_pass);

    // A bound was crossed, named off the hot path where the jump lands.
    a.bind(t_bound); a.movi(BPF_REG_9, C_BOUND); a.jmp(taint_pass);
    a.bind(t_unanswered); a.movi(BPF_REG_9, C_UNANSWERED); a.jmp(taint_pass);
    a.bind(t_budget); a.movi(BPF_REG_9, C_BUDGET);

    // Pin to TCP for good, and count why.
    a.bind(taint_pass);
    a.lookup(state, self); a.jeqi(BPF_REG_0, 0, pass);
    a.ld64(BPF_REG_1, SKL_TAINT); a.stx8(BPF_REG_0, offsetof(state_val, count), BPF_REG_1);
    a.stw(k0, BPF_REG_9); a.bump(counters, k0);

    a.bind(pass);
    a.movi(BPF_REG_0, SKL_SK_PASS);
    a.exit();

    if (!a.finish())
        return -1;
    return prog_load(a, BPF_PROG_TYPE_SK_MSG, "skl_fastlo_msg");
}

// The daemon's own cgroup, where every socket of its workers is born.
static bool own_cgroup(std::string& dir)
{
    std::ifstream f("/proc/self/cgroup");
    std::string line;
    while (std::getline(f, line))
    {
        if (line.rfind("0::", 0) == 0)
        {
            dir = "/sys/fs/cgroup" + line.substr(3);
            return true;
        }
    }
    return false;
}

static int g_pids = -1;

static void mark(int pid, bool on)
{
    if (g_pids < 0 || pid <= 0)
        return;
    uint32_t key = static_cast<uint32_t>(pid), one = 1;
    union bpf_attr a{};
    a.map_fd = static_cast<uint32_t>(g_pids);
    a.key = reinterpret_cast<uint64_t>(&key);
    a.value = reinterpret_cast<uint64_t>(&one);
    a.flags = BPF_ANY;
    if (sys_bpf(on ? BPF_MAP_UPDATE_ELEM : BPF_MAP_DELETE_ELEM, &a) < 0) {}
}

void fast_lo_adopt(int pid) { mark(pid, true); }
void fast_lo_release(int pid) { mark(pid, false); }

// ---- the reconciler ---------------------------------------------------------
//
// Two threads rather than the io_uring loop, because they block in poll,
// netlink and map syscalls that must never sit on the daemon's hot path; they
// touch only the BPF maps, never the data path.  One answers checks and waits
// on nothing but the ring, so an idle daemon costs it nothing and no slow job
// delays an answer; the other is the once-a-second safety net.  Every fd they
// hold is O_CLOEXEC so a worker the daemon forks meanwhile does not inherit it.

namespace {

struct recon_args
{
    int state{-1};
    int snap{-1};
    int ring{-1};
    int budget{-1};
    int stop_fd{-1};
    uint64_t global_bytes{0};
    fast_lo_gauges* gauges{nullptr};
};

// The safety net's period: it recomputes the global sum from the pairs that
// hold anything and re-asks for any check whose ring record was lost.
static constexpr int SWEEP_MS = 1000;
// A pair whose count is below this is not looked up by the sweep: the count
// bounds its unread backlog from above, and an idle pair must cost nothing.
static constexpr uint64_t SWEEP_FLOOR = 64u << 10;

// One receiver's committed receive memory, which on this kernel includes the
// redirected ingress backlog (sk_rmem_alloc), by an exact INET_DIAG lookup of
// its 4-tuple: about a microsecond, where a dump walks the kernel's whole
// established table and takes milliseconds however few sockets match.  A
// socket that has gone answers with an error and reads as an empty queue.
static bool diag_exact(int nl, std::vector<uint8_t>& buf, const uint8_t* key, uint64_t& rmem)
{
    struct
    {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 req;
    } m{};
    m.nlh.nlmsg_len = sizeof(m);
    m.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    m.nlh.nlmsg_flags = NLM_F_REQUEST;
    // AF_INET6 for every key, since the kernel looks an IPv4-mapped pair up in
    // the IPv4 table, where an AF_INET socket and a dual-stack one both live.
    m.req.sdiag_family = AF_INET6;
    m.req.sdiag_protocol = IPPROTO_TCP;
    m.req.idiag_states = ~0u;
    m.req.idiag_ext = 1u << (INET_DIAG_SKMEMINFO - 1);
    // The receiver is the key's peer: its local end is the key's remote one,
    // and each whole address is rebuilt from its last word.
    auto whole = [key](int16_t at, __be32* out) {
        std::memcpy(&out[3], key + at, 4);
        out[2] = out[3] == static_cast<__be32>(LO4) ? htonl(0xffff) : 0;
    };
    whole(KEY_REMOTE, m.req.id.idiag_src);
    whole(0, m.req.id.idiag_dst);
    std::memcpy(&m.req.id.idiag_sport, key + KEY_RPORT, 2);
    std::memcpy(&m.req.id.idiag_dport, key + KEY_LPORT, 2);
    m.req.id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
    m.req.id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
    if (::send(nl, &m, sizeof(m), 0) < 0)
        return false;
    const ssize_t got = ::recv(nl, buf.data(), buf.size(), 0);
    if (got < 0)
        return false;
    rmem = 0;
    auto len = static_cast<unsigned int>(got);
    const struct nlmsghdr* h = reinterpret_cast<const struct nlmsghdr*>(buf.data());
    if (!NLMSG_OK(h, len) || h->nlmsg_type != SOCK_DIAG_BY_FAMILY ||
        h->nlmsg_len < NLMSG_LENGTH(sizeof(struct inet_diag_msg)))
        return true;
    const auto* d = reinterpret_cast<const struct inet_diag_msg*>(NLMSG_DATA(h));
    int rem = static_cast<int>(h->nlmsg_len) - static_cast<int>(NLMSG_LENGTH(sizeof(*d)));
    const struct nlattr* na = reinterpret_cast<const struct nlattr*>(
        reinterpret_cast<const uint8_t*>(d) + NLMSG_ALIGN(sizeof(*d)));
    for (; rem >= static_cast<int>(sizeof(*na)) && na->nla_len >= sizeof(*na) &&
           static_cast<int>(na->nla_len) <= rem;
         rem -= NLA_ALIGN(na->nla_len),
         na = reinterpret_cast<const struct nlattr*>(
             reinterpret_cast<const uint8_t*>(na) + NLA_ALIGN(na->nla_len)))
    {
        if ((na->nla_type & NLA_TYPE_MASK) != INET_DIAG_SKMEMINFO)
            continue;
        const uint32_t* sk = reinterpret_cast<const uint32_t*>(
            reinterpret_cast<const uint8_t*>(na) + NLA_HDRLEN);
        const size_t need = (static_cast<size_t>(SK_MEMINFO_RMEM_ALLOC) + 1) * sizeof(uint32_t);
        if (static_cast<size_t>(na->nla_len) >= NLA_HDRLEN + need)
            rmem = sk[SK_MEMINFO_RMEM_ALLOC];
    }
    return true;
}

// The consumer side of a BPF ring buffer, read in place from its mapping.
class ring_reader
{
public:
    bool open(int fd)
    {
        m_page = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
        m_cons = ::mmap(nullptr, m_page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (m_cons == MAP_FAILED)
        {
            m_cons = nullptr;
            return false;
        }
        // The data pages are mapped twice back to back, so a record that wraps
        // reads as one contiguous span.
        m_prod = ::mmap(nullptr, m_page + 2 * SKL_RING_BYTES, PROT_READ, MAP_SHARED, fd,
                        static_cast<off_t>(m_page));
        if (m_prod == MAP_FAILED)
        {
            m_prod = nullptr;
            return false;
        }
        return true;
    }
    ~ring_reader()
    {
        if (m_cons)
            ::munmap(m_cons, m_page);
        if (m_prod)
            ::munmap(m_prod, m_page + 2 * SKL_RING_BYTES);
    }

    // Every committed ask record, appended to `asks`.  The producer wakes the
    // consumer only when it finds it caught up, so a record committed while
    // this ran sent no wakeup: the producer position is read again after each
    // pass, until a pass finds nothing new.
    void drain(std::vector<ask_rec>& asks)
    {
        auto* cons_pos = static_cast<unsigned long*>(m_cons);
        auto* prod_pos = static_cast<unsigned long*>(m_prod);
        const uint8_t* data = static_cast<const uint8_t*>(m_prod) + m_page;
        unsigned long c = __atomic_load_n(cons_pos, __ATOMIC_ACQUIRE);
        bool more = true;
        while (more)
        {
            more = false;
            // Orders the consumer position just published before this read.
            __atomic_thread_fence(__ATOMIC_SEQ_CST);
            const unsigned long p = __atomic_load_n(prod_pos, __ATOMIC_ACQUIRE);
            while (c < p)
            {
                const auto* hdr = reinterpret_cast<const uint32_t*>(data + (c & (SKL_RING_BYTES - 1)));
                const uint32_t len = __atomic_load_n(hdr, __ATOMIC_ACQUIRE);
                if (len & BPF_RINGBUF_BUSY_BIT)
                    return;   // still being written; its commit wakes the consumer
                const uint32_t body = len & ~(BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT);
                if (!(len & BPF_RINGBUF_DISCARD_BIT) && body == sizeof(ask_rec))
                {
                    ask_rec r;
                    std::memcpy(&r, reinterpret_cast<const uint8_t*>(hdr) + BPF_RINGBUF_HDR_SZ, sizeof(r));
                    asks.push_back(r);
                }
                c += (body + BPF_RINGBUF_HDR_SZ + 7) & ~7ul;
                __atomic_store_n(cons_pos, c, __ATOMIC_RELEASE);
                more = true;
            }
        }
    }

private:
    size_t m_page{0};
    void* m_cons{nullptr};
    void* m_prod{nullptr};
};

// The held-memory sum across pairs, kept current by both threads, and the
// over-budget flag the program reads.
class ledger
{
public:
    explicit ledger(const recon_args& a) : m_a(a) {}

    // One pair's backlog as just measured.
    void note(const uint8_t* key, uint64_t rm)
    {
        std::lock_guard<std::mutex> g(m_mu);
        uint64_t& held = m_held[std::string(reinterpret_cast<const char*>(key), SKL_KEY)];
        m_sum = m_sum - held + rm;
        held = rm;
        publish_locked(m_sum >= m_a.global_bytes ? 1 : 0);
        m_a.gauges->held.store(m_sum, std::memory_order_relaxed);
    }

    // Every pair at once, from a sweep; a sweep that failed raises the flag.
    void replace(std::unordered_map<std::string, uint64_t>&& held, uint64_t sum, bool failed)
    {
        std::lock_guard<std::mutex> g(m_mu);
        m_held = std::move(held);
        m_sum = sum;
        publish_locked(failed || m_sum >= m_a.global_bytes ? 1 : 0);
        m_a.gauges->held.store(m_sum, std::memory_order_relaxed);
    }

private:
    void publish_locked(uint64_t over)
    {
        if (over == m_over)
            return;
        uint32_t zero = 0;
        map_put(m_a.budget, &zero, &over, BPF_ANY);
        m_over = over;
        m_a.gauges->over.store(over, std::memory_order_relaxed);
    }

    const recon_args m_a;
    std::mutex m_mu;
    std::unordered_map<std::string, uint64_t> m_held;
    uint64_t m_sum{0};
    uint64_t m_over{UINT64_MAX};   // unknown, so the first publish always writes
};

// Answers the checks the program asks for.  It never writes the state map, so a
// taint the program sets cannot be overwritten: it leaves the peer's true queue
// in the snap map, named by the check's ask, for the program to apply on its
// next send.
static void answer_loop(const recon_args& a, ledger& book)
{
    const int nl = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    ring_reader ring;
    if (nl < 0 || !ring.open(a.ring))
    {
        if (nl >= 0)
            ::close(nl);
        return;   // the sweep still answers, once a second
    }
    std::vector<uint8_t> buf(8192);
    std::vector<ask_rec> asks;
    struct pollfd pfd[2]{};
    pfd[0].fd = a.stop_fd;
    pfd[0].events = POLLIN;
    pfd[1].fd = a.ring;
    pfd[1].events = POLLIN;
    while (true)
    {
        if (::poll(pfd, 2, -1) > 0 && (pfd[0].revents & POLLIN))
            break;
        asks.clear();
        ring.drain(asks);
        for (const ask_rec& r : asks)
        {
            uint64_t rm = 0;
            if (!diag_exact(nl, buf, r.key, rm))
                continue;   // the sweep re-asks for anything left pending
            const snap_val ans{rm, r.ask};
            map_put(a.snap, r.key, &ans, BPF_ANY);
            book.note(r.key, rm);
        }
    }
    ::close(nl);
}

// Once a second: the global sum from every pair that holds anything, a tainted
// pair's frozen queue included, and a fresh answer to any check still pending.
static void sweep_loop(const recon_args& a, ledger& book)
{
    const int nl = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    std::vector<uint8_t> buf(8192);
    constexpr uint32_t BATCH = 4096;
    std::vector<uint8_t> keys(static_cast<size_t>(BATCH) * SKL_KEY);
    std::vector<state_val> vals(BATCH);
    struct pollfd pfd{};
    pfd.fd = a.stop_fd;
    pfd.events = POLLIN;
    while (::poll(&pfd, 1, SWEEP_MS) == 0)
    {
        std::unordered_map<std::string, uint64_t> held;
        uint64_t sum = 0, on = 0, tcp = 0;
        bool failed = nl < 0;
        uint8_t in_batch[SKL_KEY], out_batch[SKL_KEY];
        bool first = true;
        while (!failed)
        {
            union bpf_attr b{};
            b.batch.map_fd = static_cast<uint32_t>(a.state);
            b.batch.keys = reinterpret_cast<uint64_t>(keys.data());
            b.batch.values = reinterpret_cast<uint64_t>(vals.data());
            b.batch.count = BATCH;
            b.batch.out_batch = reinterpret_cast<uint64_t>(out_batch);
            if (!first)
                b.batch.in_batch = reinterpret_cast<uint64_t>(in_batch);
            const long rc = sys_bpf(BPF_MAP_LOOKUP_BATCH, &b);
            const int err = errno;
            for (uint32_t i = 0; i < b.batch.count && !failed; ++i)
            {
                const uint8_t* key = keys.data() + static_cast<size_t>(i) * SKL_KEY;
                const state_val& v = vals[i];
                ++(v.count == SKL_TAINT ? tcp : on);
                uint64_t rm = v.count;
                if (v.count == SKL_TAINT || v.count >= SWEEP_FLOOR)
                {
                    if (!diag_exact(nl, buf, key, rm))
                        failed = true;
                    else if (v.count != SKL_TAINT && v.mark == SKL_PENDING)
                    {
                        const snap_val ans{rm, v.ask};
                        map_put(a.snap, key, &ans, BPF_ANY);
                    }
                }
                if (rm)
                {
                    held[std::string(reinterpret_cast<const char*>(key), SKL_KEY)] = rm;
                    sum += rm;
                }
            }
            if (rc != 0)
            {
                failed = failed || err != ENOENT;   // a partial read under-counts the sum
                break;
            }
            std::memcpy(in_batch, out_batch, SKL_KEY);
            first = false;
        }
        book.replace(std::move(held), sum, failed);
        if (!failed)
        {
            a.gauges->on_shortcut.store(on, std::memory_order_relaxed);
            a.gauges->on_tcp.store(tcp, std::memory_order_relaxed);
        }
    }
    if (nl >= 0)
        ::close(nl);
}

static void* recon_main(void* arg)
{
    recon_args* a = static_cast<recon_args*>(arg);
    {
        ledger book(*a);
        std::thread sweeper(sweep_loop, std::cref(*a), std::ref(book));
        answer_loop(*a, book);
        // The answer loop leaves on the stop signal, which the sweeper sees too;
        // if the ring could not be opened it leaves at once, so wait for stop.
        struct pollfd pfd{};
        pfd.fd = a->stop_fd;
        pfd.events = POLLIN;
        while (::poll(&pfd, 1, -1) <= 0) {}
        sweeper.join();
    }
    delete a;
    return nullptr;
}

}  // namespace

bool fast_lo::start_reconciler()
{
    m_stop_fd = ::eventfd(0, EFD_CLOEXEC);
    if (m_stop_fd < 0)
        return false;
    recon_args* a = new recon_args{m_state, m_snap, m_ring, m_budget, m_stop_fd,
                                   m_limits.global_bytes, &m_gauges};
    pthread_t t;
    if (pthread_create(&t, nullptr, recon_main, a) != 0)
    {
        delete a;
        ::close(m_stop_fd);
        m_stop_fd = -1;
        return false;
    }
    m_recon = static_cast<unsigned long>(t);
    return true;
}

void fast_lo::stop_reconciler()
{
    if (m_recon)
    {
        const uint64_t one = 1;
        if (::write(m_stop_fd, &one, sizeof(one)) < 0) {}
        pthread_join(static_cast<pthread_t>(m_recon), nullptr);
        m_recon = 0;
    }
    if (m_stop_fd >= 0)
    {
        ::close(m_stop_fd);
        m_stop_fd = -1;
    }
}

// The daemon's one shortcut object, for fast_lo_now(); the mutex keeps a
// snapshot from reading one that is being torn down.
static std::mutex g_live_mu;
static const fast_lo* g_live = nullptr;

bool fast_lo::start(fast_lo_mode mode, fast_lo_limits limits)
{
    // Each refusal names the step and keeps its errno for the daemon's log line.
    auto fail = [this](const char* why, int err) {
        m_reason = why;
        m_errno = err;
        return false;
    };
    const auto denied = [](int err) { return err == EPERM || err == EACCES; };

    if (mode == fast_lo_mode::off)
        return fail("off", 0);

    m_limits = limits;
    m_mode = mode;
    {
        std::lock_guard<std::mutex> g(g_live_mu);
        g_live = this;
    }

    struct statfs sf{};
    if (::statfs("/sys/fs/cgroup", &sf) < 0 || sf.f_type != CGROUP2_SUPER_MAGIC)
        return fail("needs cgroup v2 mounted at /sys/fs/cgroup", 0);
    std::string own_cg;
    if (!own_cgroup(own_cg))
        return fail("could not read this process's cgroup", 0);

    // This daemon's network namespace, baked into the sockops guard so the
    // shortcut never takes a socket from another one.  Read off any socket:
    // SO_NETNS_COOKIE reports the namespace the socket lives in.
    {
        const int probe = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (probe < 0)
            return fail("could not open a socket to read the netns cookie", errno);
        socklen_t len = sizeof(m_netns_cookie);
        const int rc = ::getsockopt(probe, SOL_SOCKET, SO_NETNS_COOKIE, &m_netns_cookie, &len);
        const int err = errno;
        ::close(probe);
        if (rc < 0)
            return fail("this kernel has no SO_NETNS_COOKIE, needed to fence the shortcut "
                        "to this namespace", err);
    }

    // The per-socket maps are not preallocated and are pruned as sockets
    // close, so at rest they cost their bucket arrays; the sockhash sizes the
    // pair ceiling.
    m_pids   = map_create(BPF_MAP_TYPE_HASH, 4, 4, 4096, "skl_fastlo_pids");
    m_socks  = map_create(BPF_MAP_TYPE_SOCKHASH, SKL_KEY, sizeof(uint64_t), 65536, "skl_fastlo_socks");
    m_ports  = map_create(BPF_MAP_TYPE_HASH, 4, 4, 1024, "skl_fastlo_ports");
    m_mine   = map_create(BPF_MAP_TYPE_HASH, SKL_KEY, 4, 16384, "skl_fastlo_mine", BPF_F_NO_PREALLOC);
    m_state  = map_create(BPF_MAP_TYPE_HASH, SKL_KEY, sizeof(state_val), 65536, "skl_fastlo_state", BPF_F_NO_PREALLOC);
    m_snap   = map_create(BPF_MAP_TYPE_HASH, SKL_KEY, sizeof(snap_val), 65536, "skl_fastlo_snap", BPF_F_NO_PREALLOC);
    m_ring   = map_create(BPF_MAP_TYPE_RINGBUF, 0, 0, SKL_RING_BYTES, "skl_fastlo_ring");
    m_budget = map_create(BPF_MAP_TYPE_ARRAY, 4, sizeof(uint64_t), 1, "skl_fastlo_bdgt");
    m_counters = map_create(BPF_MAP_TYPE_PERCPU_ARRAY, 4, sizeof(uint64_t), C_COUNT, "skl_fastlo_cnt");
    if (m_pids < 0 || m_socks < 0 || m_ports < 0 || m_mine < 0 || m_state < 0 ||
        m_snap < 0 || m_ring < 0 || m_budget < 0 || m_counters < 0)
        return fail(denied(errno)
            ? "no CAP_BPF (run the daemon as root or setcap cap_bpf,cap_net_admin+ep)"
            : "map creation failed", errno);

    m_ops = load_ops(m_socks, m_ports, m_mine, m_state, m_snap, m_pids, m_counters,
                     mode == fast_lo_mode::all, m_limits.pair_bytes, m_netns_cookie);
    if (m_ops >= 0)
        m_msg = load_msg(m_socks, m_state, m_snap, m_ring, m_budget, m_counters, m_limits.pair_bytes);
    if (m_ops < 0 || m_msg < 0)
        return fail(denied(errno) ? "no CAP_BPF/CAP_NET_ADMIN to load the programs"
                                  : "programs could not be loaded", errno);

    union bpf_attr a{};
    a.target_fd = static_cast<uint32_t>(m_socks);
    a.attach_bpf_fd = static_cast<uint32_t>(m_msg);
    a.attach_type = BPF_SK_MSG_VERDICT;
    if (sys_bpf(BPF_PROG_ATTACH, &a) < 0)
        return fail("attach of the sk_msg program to the sockhash failed", errno);

    // own needs only the daemon's cgroup, where every socket of its runtimes
    // is born; all needs the root, where a foreign client's socket is.
    const std::string where = mode == fast_lo_mode::all ? "/sys/fs/cgroup" : own_cg;
    const int cg = ::open(where.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cg < 0)
        return fail("could not open the cgroup to attach to", errno);
    union bpf_attr l{};
    l.link_create.prog_fd = static_cast<uint32_t>(m_ops);
    l.link_create.target_fd = static_cast<uint32_t>(cg);
    l.link_create.attach_type = BPF_CGROUP_SOCK_OPS;
    m_link = static_cast<int>(sys_bpf(BPF_LINK_CREATE, &l));
    const int link_errno = errno;
    ::close(cg);
    if (m_link < 0)
        return fail(denied(link_errno) ? "no CAP_NET_ADMIN to attach to the cgroup"
                                       : "attach of the sockops program to the cgroup failed",
                    link_errno);

    if (!start_reconciler())
        return fail("could not start the backlog reconciler", errno);

    g_pids = m_pids;
    m_reason = "ok";
    std::lock_guard<std::mutex> g(g_live_mu);
    m_attached = true;
    return true;
}

fast_lo::~fast_lo()
{
    {
        std::lock_guard<std::mutex> g(g_live_mu);
        if (g_live == this)
            g_live = nullptr;
    }
    // Join the reconciler before the maps it reads and writes are closed.
    stop_reconciler();
    // Everything is anonymous, so the last close detaches and frees it.
    if (g_pids == m_pids)
        g_pids = -1;
    for (int fd : { m_link, m_ops, m_msg, m_pids, m_socks, m_ports, m_mine, m_state, m_snap,
                    m_ring, m_budget, m_counters })
        if (fd >= 0)
            ::close(fd);
}

// The kernel's count of possible CPUs, which sizes a per-CPU map value.
static unsigned possible_cpus()
{
    static const unsigned n = [] {
        std::ifstream f("/sys/devices/system/cpu/possible");
        std::string s;
        unsigned hi = 0;
        if (std::getline(f, s))
        {
            const size_t at = s.find_last_of("-,");
            hi = static_cast<unsigned>(std::strtoul(s.c_str() + (at == std::string::npos ? 0 : at + 1),
                                                    nullptr, 10));
        }
        return hi + 1;
    }();
    return n;
}

fast_lo_figures fast_lo_now()
{
    fast_lo_figures f;
    std::lock_guard<std::mutex> g(g_live_mu);
    const fast_lo* lo = g_live;
    if (!lo)
        return f;
    if (!lo->m_attached)
    {
        f.mode = "unavailable";
        f.reason = lo->m_reason;
        return f;
    }
    f.mode = lo->m_mode == fast_lo_mode::all ? "all" : "own";
    f.sockets_shortcut = lo->m_gauges.on_shortcut.load(std::memory_order_relaxed);
    f.sockets_tcp = lo->m_gauges.on_tcp.load(std::memory_order_relaxed);
    f.held_bytes = lo->m_gauges.held.load(std::memory_order_relaxed);
    f.over_budget = lo->m_gauges.over.load(std::memory_order_relaxed) != 0;
    f.budget_bytes = lo->m_limits.global_bytes;
    f.pair_bytes = lo->m_limits.pair_bytes;
    uint64_t* const slots[C_COUNT] = { &f.entered, &f.tainted_bound, &f.tainted_unanswered,
                                       &f.tainted_budget, &f.tainted_peer_off };
    std::vector<uint64_t> per_cpu(possible_cpus());
    for (uint32_t k = 0; k < C_COUNT; ++k)
    {
        union bpf_attr a{};
        a.map_fd = static_cast<uint32_t>(lo->m_counters);
        a.key = reinterpret_cast<uint64_t>(&k);
        a.value = reinterpret_cast<uint64_t>(per_cpu.data());
        if (sys_bpf(BPF_MAP_LOOKUP_ELEM, &a) != 0)
            continue;
        for (uint64_t v : per_cpu)
            *slots[k] += v;
    }
    return f;
}

bool fast_lo_active()
{
    static const bool on = [] {
        const char* e = std::getenv(fast_lo_env);
        return e && e[0] != '\0';
    }();
    return on;
}

// 127.0.0.1 as AF_INET or as an IPv4-mapped AF_INET6 address, or ::1.
static bool loopback(const sockaddr_storage& ss)
{
    if (ss.ss_family == AF_INET)
        return reinterpret_cast<const sockaddr_in&>(ss).sin_addr.s_addr == htonl(INADDR_LOOPBACK);
    if (ss.ss_family == AF_INET6)
    {
        const auto& a = reinterpret_cast<const sockaddr_in6&>(ss).sin6_addr;
        static constexpr uint8_t mapped[16] = { 0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 127,0,0,1 };
        return std::memcmp(a.s6_addr, mapped, 16) == 0 || IN6_IS_ADDR_LOOPBACK(&a);
    }
    return false;
}

bool fast_lo_covers(int fd)
{
    sockaddr_storage a{}, b{};
    socklen_t la = sizeof(a), lb = sizeof(b);
    if (fd < 0 || ::getsockname(fd, reinterpret_cast<sockaddr*>(&a), &la) < 0 ||
        ::getpeername(fd, reinterpret_cast<sockaddr*>(&b), &lb) < 0)
        return false;
    return loopback(a) && loopback(b);
}

}  // namespace socketley

#ifdef SKL_FASTLO_SELFTEST
// A standalone check that both hand-assembled programs pass the kernel verifier
// on this box, so a rejection is caught in seconds, not a daemon build.  Build:
//   g++ -std=c++2b -DSKL_FASTLO_SELFTEST socketley/shared/fast_lo.cpp -o /tmp/skl_selftest
#include <cstdio>
int main()
{
    using namespace socketley;
    const int socks = map_create(BPF_MAP_TYPE_SOCKHASH, SKL_KEY, 8, 4096, "socks");
    const int ports = map_create(BPF_MAP_TYPE_HASH, 4, 4, 1024, "ports");
    const int pids = map_create(BPF_MAP_TYPE_HASH, 4, 4, 4096, "pids");
    const int mine = map_create(BPF_MAP_TYPE_HASH, SKL_KEY, 4, 4096, "mine", BPF_F_NO_PREALLOC);
    const int state = map_create(BPF_MAP_TYPE_HASH, SKL_KEY, sizeof(state_val), 4096, "state", BPF_F_NO_PREALLOC);
    const int snap = map_create(BPF_MAP_TYPE_HASH, SKL_KEY, sizeof(snap_val), 4096, "snap", BPF_F_NO_PREALLOC);
    const int ring = map_create(BPF_MAP_TYPE_RINGBUF, 0, 0, SKL_RING_BYTES, "ring");
    const int budget = map_create(BPF_MAP_TYPE_ARRAY, 4, 8, 1, "budget");
    const int counters = map_create(BPF_MAP_TYPE_PERCPU_ARRAY, 4, 8, C_COUNT, "counters");
    std::printf("maps socks=%d ports=%d pids=%d mine=%d state=%d snap=%d ring=%d budget=%d\n",
                socks, ports, pids, mine, state, snap, ring, budget);
    for (bool all : { false, true })
    {
        const int ops = load_ops(socks, ports, mine, state, snap, pids, counters, all, 4ull << 20, 0);
        std::printf("load_ops(all=%d) = %d errno=%d\n", all, ops, errno);
        if (ops < 0) std::printf("%s\n", g_verifier_log);
    }
    const int msg = load_msg(socks, state, snap, ring, budget, counters, 4ull << 20);
    std::printf("load_msg = %d errno=%d\n", msg, errno);
    if (msg < 0) std::printf("%s\n", g_verifier_log);

    // The reconciler's exact lookup, for each loopback kind: a sender's key
    // must find its receiver's unread 100000 bytes.
    auto addr16 = [](const sockaddr_storage& ss, uint8_t* out, uint16_t& port) {
        if (ss.ss_family == AF_INET)
        {
            const auto& a = reinterpret_cast<const sockaddr_in&>(ss);
            std::memset(out, 0, 10); out[10] = 0xff; out[11] = 0xff;
            std::memcpy(out + 12, &a.sin_addr, 4);
            port = a.sin_port;
        }
        else
        {
            const auto& a = reinterpret_cast<const sockaddr_in6&>(ss);
            std::memcpy(out, &a.sin6_addr, 16);
            port = a.sin6_port;
        }
    };
    auto fill = [](sockaddr_storage& ss, int fam, const char* ip, uint16_t port) -> socklen_t {
        if (fam == AF_INET)
        {
            auto& a = reinterpret_cast<sockaddr_in&>(ss);
            a.sin_family = AF_INET; inet_pton(AF_INET, ip, &a.sin_addr); a.sin_port = port;
            return sizeof(a);
        }
        auto& a = reinterpret_cast<sockaddr_in6&>(ss);
        a.sin6_family = AF_INET6; inet_pton(AF_INET6, ip, &a.sin6_addr); a.sin6_port = port;
        return sizeof(a);
    };
    struct kind { const char* name; int lfam; const char* lip; int cfam; const char* cip; };
    for (const kind& k : { kind{"127.0.0.1", AF_INET, "127.0.0.1", AF_INET, "127.0.0.1"},
                           kind{"v4-mapped", AF_INET6, "::", AF_INET, "127.0.0.1"},
                           kind{"::1", AF_INET6, "::1", AF_INET6, "::1"} })
    {
        sockaddr_storage la{}, ca{};
        const int l = ::socket(k.lfam, SOCK_STREAM, 0);
        const int off = 0;
        if (k.lfam == AF_INET6)
            ::setsockopt(l, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
        socklen_t ll = fill(la, k.lfam, k.lip, 0);
        if (::bind(l, reinterpret_cast<sockaddr*>(&la), ll) < 0 || ::listen(l, 1) < 0 ||
            ::getsockname(l, reinterpret_cast<sockaddr*>(&la), &ll) < 0)
        {
            std::printf("%s: listen failed\n", k.name);
            continue;
        }
        const uint16_t lport = k.lfam == AF_INET ? reinterpret_cast<sockaddr_in&>(la).sin_port
                                                 : reinterpret_cast<sockaddr_in6&>(la).sin6_port;
        const socklen_t cl = fill(ca, k.cfam, k.cip, lport);
        const int c = ::socket(k.cfam, SOCK_STREAM, 0);
        if (::connect(c, reinterpret_cast<sockaddr*>(&ca), cl) < 0)
        {
            std::printf("%s: connect failed\n", k.name);
            continue;
        }
        const int srv = ::accept(l, nullptr, nullptr);
        std::vector<char> junk(100000, 'j');
        size_t sent = 0;
        while (sent < junk.size())
        {
            const ssize_t w = ::send(c, junk.data() + sent, junk.size() - sent, 0);
            if (w <= 0) break;
            sent += static_cast<size_t>(w);
        }
        ::usleep(20000);
        sockaddr_storage self{}, peer{};
        socklen_t sl = sizeof(self), pl = sizeof(peer);
        uint8_t key[SKL_KEY]{};
        uint8_t a16[16];
        uint16_t sp = 0, pp = 0;
        if (::getsockname(c, reinterpret_cast<sockaddr*>(&self), &sl) == 0 &&
            ::getpeername(c, reinterpret_cast<sockaddr*>(&peer), &pl) == 0)
        {
            addr16(self, a16, sp);
            std::memcpy(key, a16 + 12, 4);
            addr16(peer, a16, pp);
            std::memcpy(key + KEY_REMOTE, a16 + 12, 4);
            std::memcpy(key + KEY_LPORT, &sp, 2);
            std::memcpy(key + KEY_RPORT, &pp, 2);
        }
        const int nl = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
        std::vector<uint8_t> buf(8192);
        uint64_t rmem = 0;
        const bool ok = diag_exact(nl, buf, key, rmem);
        std::printf("diag %-9s lookup=%d receiver rmem=%llu (%s)\n", k.name, ok,
                    static_cast<unsigned long long>(rmem), ok && rmem >= 100000 ? "ok" : "WRONG");
        ::close(nl); ::close(srv); ::close(c); ::close(l);
    }
    return 0;
}
#endif
