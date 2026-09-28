#include "sockmap_relay.h"

#include <linux/bpf.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/tcp.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <initializer_list>

namespace socketley {

// SK_DROP/SK_PASS are the verdict return values; not named in <linux/bpf.h>.
static constexpr int SKL_SK_DROP = 0;
static constexpr int SKL_SK_PASS = 1;

static long sys_bpf(int cmd, union bpf_attr* attr)
{
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

bool sockmap_relay::is_inet(int fd)
{
    int dom = 0;
    socklen_t len = sizeof(dom);
    if (fd < 0 || getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &dom, &len) < 0)
        return false;
    // The redirect between a TCP and a unix socket loses bytes (measured), so
    // the kernel path is for AF_INET/AF_INET6 pairs only.
    return dom == AF_INET || dom == AF_INET6;
}

static uint64_t sock_cookie(int fd)
{
    uint64_t c = 0;
    socklen_t len = sizeof(c);
    if (getsockopt(fd, SOL_SOCKET, SO_COOKIE, &c, &len) < 0)
        return 0;
    return c;
}

static int map_create_sockhash(uint32_t entries)
{
    union bpf_attr a{};
    a.map_type = BPF_MAP_TYPE_SOCKHASH;
    a.key_size = sizeof(uint64_t);
    a.value_size = sizeof(uint64_t);   // a value is a descriptor, held as u64
    a.max_entries = entries;
    return static_cast<int>(sys_bpf(BPF_MAP_CREATE, &a));
}

// The whole verdict: look up this socket's peer by its own cookie and redirect
// to it; if there is no peer, pass the bytes to this socket's own userspace
// queue rather than dropping them, so a pair half-out of the map loses nothing.
static int prog_load(int peer_map)
{
    struct bpf_insn insns[16];
    int n = 0;
    auto emit = [&](uint8_t code, uint8_t dst, uint8_t src, int16_t off, int32_t imm) {
        struct bpf_insn i{};
        i.code = code; i.dst_reg = dst; i.src_reg = src; i.off = off; i.imm = imm;
        insns[n++] = i;
    };

    emit(BPF_ALU64 | BPF_MOV | BPF_X, 6, 1, 0, 0);                 // r6 = ctx
    emit(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_socket_cookie); // r0 = cookie(ctx)
    emit(BPF_STX | BPF_MEM | BPF_DW, 10, 0, -8, 0);                // *(u64*)(fp-8) = r0
    emit(BPF_ALU64 | BPF_MOV | BPF_X, 3, 10, 0, 0);                // r3 = fp
    emit(BPF_ALU64 | BPF_ADD | BPF_K, 3, 0, 0, -8);                // r3 = &key
    emit(BPF_ALU64 | BPF_MOV | BPF_X, 1, 6, 0, 0);                 // r1 = ctx
    emit(BPF_LD | BPF_DW | BPF_IMM, 2, BPF_PSEUDO_MAP_FD, 0, peer_map);  // r2 = peer_map
    emit(0, 0, 0, 0, 0);                                           // ld_imm64 second half
    emit(BPF_ALU64 | BPF_MOV | BPF_K, 4, 0, 0, 0);                 // r4 = flags 0 (egress)
    emit(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_sk_redirect_hash);  // r0 = redirect verdict
    emit(BPF_JMP | BPF_JNE | BPF_K, 0, 0, 1, SKL_SK_DROP);         // if r0 != SK_DROP, skip
    emit(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, SKL_SK_PASS);       // no peer: pass to userspace
    emit(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);

    union bpf_attr a{};
    a.prog_type = BPF_PROG_TYPE_SK_SKB;
    a.insns = reinterpret_cast<uint64_t>(insns);
    a.insn_cnt = static_cast<uint32_t>(n);
    a.license = reinterpret_cast<uint64_t>("Apache-2.0");
    a.expected_attach_type = BPF_SK_SKB_STREAM_VERDICT;
    return static_cast<int>(sys_bpf(BPF_PROG_LOAD, &a));
}

bool sockmap_relay::init()
{
    if (m_ok)
        return true;

    m_peer_map = map_create_sockhash(4096);
    m_verd_map = map_create_sockhash(4096);
    if (m_peer_map < 0 || m_verd_map < 0)
    {
        m_reason = (errno == EPERM || errno == EACCES)
            ? "no CAP_BPF/CAP_NET_ADMIN (run the daemon with setcap cap_bpf,cap_net_admin+ep)"
            : "sockhash map creation failed";
        return false;
    }

    m_prog = prog_load(m_peer_map);
    if (m_prog < 0)
    {
        m_reason = (errno == EPERM || errno == EACCES)
            ? "no CAP_BPF to load the verdict program"
            : "verdict program load rejected by the verifier";
        return false;
    }

    union bpf_attr a{};
    a.target_fd = m_verd_map;
    a.attach_bpf_fd = m_prog;
    a.attach_type = BPF_SK_SKB_STREAM_VERDICT;
    if (sys_bpf(BPF_PROG_ATTACH, &a) < 0)
    {
        m_reason = "attach of the verdict to the sockhash failed";
        return false;
    }

    m_ok = true;
    m_reason = "ok";
    return true;
}

// A socket enters the verdict map first, which is what runs the program on its
// bytes; the peer map is filled by enter() before this so the lookup can find
// the partner from the first packet.
bool sockmap_relay::insert_one(int fd)
{
    uint64_t key = sock_cookie(fd);
    uint64_t val = static_cast<uint64_t>(static_cast<uint32_t>(fd));
    union bpf_attr a{};
    a.map_fd = m_verd_map;
    a.key = reinterpret_cast<uint64_t>(&key);
    a.value = reinterpret_cast<uint64_t>(&val);
    a.flags = BPF_ANY;
    return sys_bpf(BPF_MAP_UPDATE_ELEM, &a) == 0;
}

void sockmap_relay::delete_one(int fd)
{
    uint64_t key = sock_cookie(fd);
    for (int map : { m_verd_map, m_peer_map })
    {
        union bpf_attr a{};
        a.map_fd = map;
        a.key = reinterpret_cast<uint64_t>(&key);
        if (sys_bpf(BPF_MAP_DELETE_ELEM, &a) < 0) {}
    }
}

// Order that closes the setup race: both peer entries, then each verdict entry,
// so the first byte the program sees already has a partner to redirect to.
bool sockmap_relay::enter(int fd_a, int fd_b)
{
    if (!m_ok || fd_a < 0 || fd_b < 0)
        return false;

    uint64_t ca = sock_cookie(fd_a), cb = sock_cookie(fd_b);
    if (ca == 0 || cb == 0)
        return false;

    uint64_t va = static_cast<uint64_t>(static_cast<uint32_t>(fd_a));
    uint64_t vb = static_cast<uint64_t>(static_cast<uint32_t>(fd_b));

    auto put_peer = [&](uint64_t key, uint64_t val) {
        union bpf_attr a{};
        a.map_fd = m_peer_map;
        a.key = reinterpret_cast<uint64_t>(&key);
        a.value = reinterpret_cast<uint64_t>(&val);
        a.flags = BPF_ANY;
        return sys_bpf(BPF_MAP_UPDATE_ELEM, &a) == 0;
    };

    if (!put_peer(ca, vb) || !put_peer(cb, va))
    {
        leave(fd_a, fd_b);
        return false;
    }
    if (!insert_one(fd_a) || !insert_one(fd_b))
    {
        leave(fd_a, fd_b);
        return false;
    }

    // Bytes sitting in the receive queue before the verdict was attached wait
    // for the next packet unless the socket is woken; a low-water mark of one
    // byte flushes them at once and keeps their order.
    int one = 1;
    if (setsockopt(fd_a, SOL_SOCKET, SO_RCVLOWAT, &one, sizeof(one)) < 0) {}
    if (setsockopt(fd_b, SOL_SOCKET, SO_RCVLOWAT, &one, sizeof(one)) < 0) {}
    return true;
}

void sockmap_relay::leave(int fd_a, int fd_b)
{
    if (m_verd_map < 0)
        return;
    if (fd_a >= 0) delete_one(fd_a);
    if (fd_b >= 0) delete_one(fd_b);
}

static bool tcp_counters(int fd, uint64_t& received, uint64_t& acked)
{
    struct tcp_info ti{};
    socklen_t len = sizeof(ti);
    if (fd < 0 || getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &len) < 0)
        return false;
    received = ti.tcpi_bytes_received;
    acked = ti.tcpi_bytes_acked;
    return true;
}

static uint64_t ioctl_count(int fd, unsigned long req)
{
    int v = 0;
    if (fd < 0 || ioctl(fd, req, &v) < 0 || v < 0)
        return 0;
    return static_cast<uint64_t>(v);
}

// Taken before the verdict is attached, when nothing reads the source, so its
// receive queue only grows: reading SIOCINQ either side of TCP_INFO and
// retrying until they agree makes received - queued one instant's figure.
sockmap_relay::direction_base sockmap_relay::base(int src_fd, int dst_fd)
{
    direction_base b;
    uint64_t rx = 0, acked = 0, unused = 0;
    for (int i = 0; i < 8; i++)
    {
        const uint64_t q1 = ioctl_count(src_fd, SIOCINQ);
        tcp_counters(src_fd, rx, unused);
        const uint64_t q2 = ioctl_count(src_fd, SIOCINQ);
        b.rx = rx - q2;
        if (q1 == q2)
            break;
    }
    tcp_counters(dst_fd, unused, acked);
    b.tx = acked + ioctl_count(dst_fd, SIOCOUTQ);
    return b;
}

uint64_t sockmap_relay::relayed(int src_fd, const direction_base& b, bool src_fin)
{
    uint64_t rx = 0, unused = 0;
    if (!tcp_counters(src_fd, rx, unused))
        return 0;
    if (src_fin && rx > 0)
        rx--;
    return rx > b.rx ? rx - b.rx : 0;
}

// What the destination has taken into its send queue since the base, acked or
// not, against what the source has received: the gap is the redirect's queue.
static uint64_t taken_by_dst(int dst_fd, const sockmap_relay::direction_base& b)
{
    uint64_t unused = 0, acked = 0;
    tcp_counters(dst_fd, unused, acked);
    const uint64_t tx = acked + ioctl_count(dst_fd, SIOCOUTQ);
    return tx > b.tx ? tx - b.tx : 0;
}

uint64_t sockmap_relay::held(int src_fd, int dst_fd, const direction_base& b, bool src_fin)
{
    const uint64_t in = relayed(src_fd, b, src_fin);
    const uint64_t taken = taken_by_dst(dst_fd, b);
    const uint64_t queued = in > taken ? in - taken : 0;
    return queued + ioctl_count(dst_fd, SIOCOUTQ);
}

bool sockmap_relay::drained(int src_fd, int dst_fd, const direction_base& b, bool src_fin)
{
    return taken_by_dst(dst_fd, b) >= relayed(src_fd, b, src_fin);
}

sockmap_relay::~sockmap_relay()
{
    // The maps and program are anonymous, so closing the last descriptor frees
    // them and detaches the verdict; nothing outlives the process.
    if (m_prog >= 0) close(m_prog);
    if (m_verd_map >= 0) close(m_verd_map);
    if (m_peer_map >= 0) close(m_peer_map);
}

}  // namespace socketley
