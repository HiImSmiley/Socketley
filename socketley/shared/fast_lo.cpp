#include "fast_lo.h"

#include <linux/bpf.h>
#include <linux/magic.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace socketley {

// SK_PASS is the verdict return value; not named in <linux/bpf.h>.
static constexpr int SKL_SK_PASS = 1;
// 127.0.0.1 as the context fields hold it.
static constexpr int32_t LO4 = 0x0100007f;
static constexpr int32_t SKL_TCP_LISTEN = 10;
static constexpr int32_t SKL_TCP_CLOSE = 7;

bool parse_fast_lo_mode(std::string_view v, fast_lo_mode& out)
{
    if (v == "own") { out = fast_lo_mode::own; return true; }
    if (v == "all") { out = fast_lo_mode::all; return true; }
    return false;
}

static long sys_bpf(int cmd, union bpf_attr* attr)
{
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int map_create(uint32_t type, uint32_t key, uint32_t value, uint32_t entries,
                      const char* name)
{
    union bpf_attr a{};
    a.map_type = type;
    a.key_size = key;
    a.value_size = value;
    a.max_entries = entries;
    std::strncpy(a.map_name, name, sizeof(a.map_name) - 1);
    return static_cast<int>(sys_bpf(BPF_MAP_CREATE, &a));
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
    void rshi(uint8_t dst, int32_t imm) { op(BPF_ALU64 | BPF_RSH | BPF_K, dst, 0, 0, imm); }
    void be32(uint8_t dst) { op(BPF_ALU | BPF_END | BPF_TO_BE, dst, 0, 0, 32); }
    void ldw(uint8_t dst, uint8_t src, size_t off) { op(BPF_LDX | BPF_MEM | BPF_W, dst, src, static_cast<int16_t>(off), 0); }
    void lddw(uint8_t dst, uint8_t src, long off) { op(BPF_LDX | BPF_MEM | BPF_DW, dst, src, static_cast<int16_t>(off), 0); }
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
    void jne(uint8_t r, uint8_t s, int l) { fix(l); op(BPF_JMP | BPF_JNE | BPF_X, r, s, 0, 0); }

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

static int prog_load(const bpf_asm& a, uint32_t type, const char* name)
{
    union bpf_attr at{};
    at.prog_type = type;
    at.insns = reinterpret_cast<uint64_t>(a.code().data());
    at.insn_cnt = static_cast<uint32_t>(a.code().size());
    at.license = reinterpret_cast<uint64_t>("Apache-2.0");
    std::strncpy(at.prog_name, name, sizeof(at.prog_name) - 1);
    return static_cast<int>(sys_bpf(BPF_PROG_LOAD, &at));
}

// A socket's key is {local ip, remote ip, local port, remote port}, ports in
// network order in the low half; the peer's key is the same four swapped.
static constexpr int16_t K_PORT = -4;    // u32 port, the ports map's key
static constexpr int16_t K_SELF = -24;   // this socket's key
static constexpr int16_t K_PEER = -40;   // the peer's key
static constexpr int16_t K_VAL  = -44;   // u32 map value
static constexpr int16_t K_COMM = -64;   // 16-byte comm

struct identity
{
    uint64_t comm[2]{0, 0};
    uint64_t cgroup{0};
};

// The sockops program, which sorts sockets at four moments: a listen or a
// connect by one of this daemon's processes is remembered, and an established
// loopback pair to one of its ports enters the sockhash.
static int load_ops(int socks, int ports, int mine, int taint, const identity& id, bool all)
{
    bpf_asm a;
    const int out = a.label(), listen = a.label(), state = a.label(), connect = a.label();
    const int active = a.label(), enter = a.label(), not_passive = a.label();

    // Ours: the process is this daemon's binary and sits in its cgroup.
    auto ours = [&] {
        a.fp_ptr(BPF_REG_1, K_COMM); a.movi(BPF_REG_2, 16); a.call(BPF_FUNC_get_current_comm);
        a.lddw(BPF_REG_1, BPF_REG_10, K_COMM);     a.ld64(BPF_REG_2, id.comm[0]); a.jne(BPF_REG_1, BPF_REG_2, out);
        a.lddw(BPF_REG_1, BPF_REG_10, K_COMM + 8); a.ld64(BPF_REG_2, id.comm[1]); a.jne(BPF_REG_1, BPF_REG_2, out);
        a.call(BPF_FUNC_get_current_cgroup_id);    a.ld64(BPF_REG_1, id.cgroup);  a.jne(BPF_REG_0, BPF_REG_1, out);
    };

    a.mov(BPF_REG_6, BPF_REG_1);
    a.ldw(BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_ops, op));
    a.ldw(BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_ops, local_port));
    a.be32(BPF_REG_8); a.rshi(BPF_REG_8, 16);
    a.stw(K_PORT, BPF_REG_8);
    a.jeqi(BPF_REG_7, BPF_SOCK_OPS_TCP_LISTEN_CB, listen);
    a.jeqi(BPF_REG_7, BPF_SOCK_OPS_STATE_CB, state);

    // A child inherits its listener's state callback, which only the listener needs.
    a.jnei(BPF_REG_7, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB, not_passive);
    a.mov(BPF_REG_1, BPF_REG_6); a.movi(BPF_REG_2, 0); a.call(BPF_FUNC_sock_ops_cb_flags_set);
    a.bind(not_passive);

    a.ldw(BPF_REG_1, BPF_REG_6, offsetof(struct bpf_sock_ops, local_ip4));  a.jnei(BPF_REG_1, LO4, out);
    a.ldw(BPF_REG_1, BPF_REG_6, offsetof(struct bpf_sock_ops, remote_ip4)); a.jnei(BPF_REG_1, LO4, out);
    a.ldw(BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_ops, remote_port)); a.rshi(BPF_REG_9, 16);
    a.stwi(K_SELF, LO4); a.stwi(K_SELF + 4, LO4); a.stw(K_SELF + 8, BPF_REG_8); a.stw(K_SELF + 12, BPF_REG_9);
    a.stwi(K_PEER, LO4); a.stwi(K_PEER + 4, LO4); a.stw(K_PEER + 8, BPF_REG_9); a.stw(K_PEER + 12, BPF_REG_8);
    a.jeqi(BPF_REG_7, BPF_SOCK_OPS_TCP_CONNECT_CB, connect);
    a.jeqi(BPF_REG_7, BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, active);
    a.jnei(BPF_REG_7, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB, out);

    // Passive: a listener of ours, and nothing received yet -- bytes that came
    // by TCP before the shortcut would be read after the ones that come by it.
    a.lddw(BPF_REG_1, BPF_REG_6, offsetof(struct bpf_sock_ops, bytes_received));
    a.jnei(BPF_REG_1, 0, out);
    a.lookup(ports, K_PORT); a.jeqi(BPF_REG_0, 0, out);
    if (!all)
    {
        a.lookup(mine, K_PEER); a.jeqi(BPF_REG_0, 0, out);
        a.erase(mine, K_PEER);
    }
    a.jmp(enter);

    // Active: to a port of ours, and in own mode from a connect of ours.
    a.bind(active);
    a.stw(K_PORT, BPF_REG_9);
    a.lookup(ports, K_PORT); a.jeqi(BPF_REG_0, 0, out);
    if (!all)
    {
        a.lookup(mine, K_SELF); a.jeqi(BPF_REG_0, 0, out);
    }

    a.bind(enter);
    a.erase(taint, K_SELF);
    a.mov(BPF_REG_1, BPF_REG_6); a.ld_map(BPF_REG_2, socks); a.fp_ptr(BPF_REG_3, K_SELF);
    a.movi(BPF_REG_4, BPF_ANY); a.call(BPF_FUNC_sock_hash_update);
    a.jmp(out);

    a.bind(connect);
    ours();
    a.stwi(K_VAL, 1); a.update(mine, K_SELF, K_VAL, BPF_ANY);
    a.jmp(out);

    // A listener counts its port, since reuseport listeners share one, and
    // asks for the state callback that takes the count down on close.
    a.bind(listen);
    ours();
    a.stwi(K_VAL, 0); a.update(ports, K_PORT, K_VAL, BPF_NOEXIST);
    a.lookup(ports, K_PORT); a.jeqi(BPF_REG_0, 0, out);
    a.movi(BPF_REG_1, 1);
    a.op(BPF_STX | BPF_ATOMIC | BPF_W, BPF_REG_0, BPF_REG_1, 0, BPF_ADD);
    a.mov(BPF_REG_1, BPF_REG_6); a.movi(BPF_REG_2, BPF_SOCK_OPS_STATE_CB_FLAG);
    a.call(BPF_FUNC_sock_ops_cb_flags_set);
    a.jmp(out);

    a.bind(state);
    a.ldw(BPF_REG_1, BPF_REG_6, offsetof(struct bpf_sock_ops, args[0])); a.jnei(BPF_REG_1, SKL_TCP_LISTEN, out);
    a.ldw(BPF_REG_1, BPF_REG_6, offsetof(struct bpf_sock_ops, args[1])); a.jnei(BPF_REG_1, SKL_TCP_CLOSE, out);
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

// The sk_msg program: a send goes to the peer's receive queue when the peer is
// in the sockhash, and a socket that once sent by TCP stays on TCP, so no byte
// can overtake one still queued the slow way.
static int load_msg(int socks, int taint)
{
    bpf_asm a;
    const int pass = a.label();
    constexpr int16_t self = -16, peer = -32, val = -36;

    a.mov(BPF_REG_6, BPF_REG_1);
    a.ldw(BPF_REG_7, BPF_REG_6, offsetof(struct sk_msg_md, local_ip4));
    a.ldw(BPF_REG_8, BPF_REG_6, offsetof(struct sk_msg_md, remote_ip4));
    a.ldw(BPF_REG_9, BPF_REG_6, offsetof(struct sk_msg_md, local_port)); a.be32(BPF_REG_9); a.rshi(BPF_REG_9, 16);
    a.ldw(BPF_REG_1, BPF_REG_6, offsetof(struct sk_msg_md, remote_port)); a.rshi(BPF_REG_1, 16);
    a.stw(self, BPF_REG_7); a.stw(self + 4, BPF_REG_8); a.stw(self + 8, BPF_REG_9); a.stw(self + 12, BPF_REG_1);
    a.stw(peer, BPF_REG_8); a.stw(peer + 4, BPF_REG_7); a.stw(peer + 8, BPF_REG_1); a.stw(peer + 12, BPF_REG_9);

    a.lookup(taint, self); a.jnei(BPF_REG_0, 0, pass);
    a.mov(BPF_REG_1, BPF_REG_6); a.ld_map(BPF_REG_2, socks); a.fp_ptr(BPF_REG_3, peer);
    a.movi(BPF_REG_4, BPF_F_INGRESS); a.call(BPF_FUNC_msg_redirect_hash);
    a.jeqi(BPF_REG_0, SKL_SK_PASS, pass);
    a.stwi(val, 1); a.update(taint, self, val, BPF_ANY);

    a.bind(pass);
    a.movi(BPF_REG_0, SKL_SK_PASS);
    a.exit();

    if (!a.finish())
        return -1;
    return prog_load(a, BPF_PROG_TYPE_SK_MSG, "skl_fastlo_msg");
}

// Workers exec the binary /proc/self/exe names, so that basename is their comm.
static bool own_identity(identity& id, std::string& cgroup_dir)
{
    char buf[4096];
    const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0)
        return false;
    buf[n] = '\0';
    const char* base = std::strrchr(buf, '/');
    base = base ? base + 1 : buf;
    char comm[16]{};
    std::strncpy(comm, base, 15);
    std::memcpy(id.comm, comm, sizeof(comm));

    std::ifstream f("/proc/self/cgroup");
    std::string line;
    while (std::getline(f, line))
    {
        if (line.rfind("0::", 0) == 0)
        {
            cgroup_dir = "/sys/fs/cgroup" + line.substr(3);
            struct stat st{};
            if (::stat(cgroup_dir.c_str(), &st) < 0)
                return false;
            id.cgroup = st.st_ino;
            return true;
        }
    }
    return false;
}

bool fast_lo::start(fast_lo_mode mode)
{
    if (mode == fast_lo_mode::off)
    {
        m_reason = "off";
        return false;
    }

    struct statfs sf{};
    if (::statfs("/sys/fs/cgroup", &sf) < 0 || sf.f_type != CGROUP2_SUPER_MAGIC)
    {
        m_reason = "needs cgroup v2 mounted at /sys/fs/cgroup";
        return false;
    }
    identity id;
    std::string own_cg;
    if (!own_identity(id, own_cg))
    {
        m_reason = "could not read this process's binary name or cgroup";
        return false;
    }

    m_socks = map_create(BPF_MAP_TYPE_SOCKHASH, 16, sizeof(uint64_t), 65536, "skl_fastlo_socks");
    m_ports = map_create(BPF_MAP_TYPE_HASH, 4, 4, 4096, "skl_fastlo_ports");
    m_mine  = map_create(BPF_MAP_TYPE_LRU_HASH, 16, 4, 65536, "skl_fastlo_mine");
    m_taint = map_create(BPF_MAP_TYPE_LRU_HASH, 16, 4, 65536, "skl_fastlo_taint");
    if (m_socks < 0 || m_ports < 0 || m_mine < 0 || m_taint < 0)
    {
        m_reason = (errno == EPERM || errno == EACCES)
            ? "no CAP_BPF (run the daemon as root or setcap cap_bpf,cap_net_admin,cap_perfmon+ep)"
            : "map creation failed";
        return false;
    }

    m_ops = load_ops(m_socks, m_ports, m_mine, m_taint, id, mode == fast_lo_mode::all);
    m_msg = load_msg(m_socks, m_taint);
    if (m_ops < 0 || m_msg < 0)
    {
        m_reason = (errno == EPERM || errno == EACCES)
            ? "no CAP_BPF/CAP_NET_ADMIN to load the programs"
            : "programs rejected by the verifier (it also needs CAP_PERFMON to name the "
              "daemon's processes)";
        return false;
    }

    union bpf_attr a{};
    a.target_fd = static_cast<uint32_t>(m_socks);
    a.attach_bpf_fd = static_cast<uint32_t>(m_msg);
    a.attach_type = BPF_SK_MSG_VERDICT;
    if (sys_bpf(BPF_PROG_ATTACH, &a) < 0)
    {
        m_reason = "attach of the sk_msg program to the sockhash failed";
        return false;
    }

    // own needs only the daemon's cgroup, where every socket of its runtimes
    // is born; all needs the root, where a foreign client's socket is.
    const std::string where = mode == fast_lo_mode::all ? "/sys/fs/cgroup" : own_cg;
    const int cg = ::open(where.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cg < 0)
    {
        m_reason = "could not open the cgroup to attach to";
        return false;
    }
    union bpf_attr l{};
    l.link_create.prog_fd = static_cast<uint32_t>(m_ops);
    l.link_create.target_fd = static_cast<uint32_t>(cg);
    l.link_create.attach_type = BPF_CGROUP_SOCK_OPS;
    m_link = static_cast<int>(sys_bpf(BPF_LINK_CREATE, &l));
    const int link_errno = errno;
    ::close(cg);
    if (m_link < 0)
    {
        m_reason = (link_errno == EPERM || link_errno == EACCES)
            ? "no CAP_NET_ADMIN to attach to the cgroup"
            : "attach of the sockops program to the cgroup failed";
        return false;
    }

    m_reason = "ok";
    return true;
}

fast_lo::~fast_lo()
{
    // Everything is anonymous, so the last close detaches and frees it.
    for (int fd : { m_link, m_ops, m_msg, m_socks, m_ports, m_mine, m_taint })
        if (fd >= 0)
            ::close(fd);
}

bool fast_lo_active()
{
    static const bool on = [] {
        const char* e = std::getenv(fast_lo_env);
        return e && e[0] != '\0';
    }();
    return on;
}

// Both ends 127.0.0.1, as AF_INET or as an IPv4-mapped AF_INET6 address.
static bool loopback4(const sockaddr_storage& ss)
{
    if (ss.ss_family == AF_INET)
        return reinterpret_cast<const sockaddr_in&>(ss).sin_addr.s_addr == htonl(INADDR_LOOPBACK);
    if (ss.ss_family == AF_INET6)
    {
        const auto& a = reinterpret_cast<const sockaddr_in6&>(ss).sin6_addr;
        static constexpr uint8_t mapped[16] = { 0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 127,0,0,1 };
        return std::memcmp(a.s6_addr, mapped, 16) == 0;
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
    return loopback4(a) && loopback4(b);
}

}  // namespace socketley
