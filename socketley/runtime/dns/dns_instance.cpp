#include "dns_instance.h"
#include "dns_answer.h"
#include "dns_sign.h"
#include "dns_wire.h"
#include "dns_zone.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <functional>
#include <sstream>
#include <memory>
#include <thread>
#include <unordered_map>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../shared/net/dns_feed.h"
#include "../../shared/net/endpoint.h"
#include "../../shared/persist/paths.h"
#include "../../shared/loop/event_loop.h"
#include "../../shared/loop/eventfd_wake.h"
#include "../../shared/net/ip_block.h"
#include "../../shared/util/base64.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/wall_clock.h"
#include "../../shared/util/text_list.h"
#include "../../shared/persist/replaced_file.h"

namespace socketley::dns
{

namespace
{

// Datagrams taken from a socket in one call, and replies sent in one; a burst of queries costs two system calls
// for each this many.
constexpr unsigned udp_batch = 64;
// A query is a few dozen bytes; one this large is no query, and is cut off.
constexpr size_t   udp_rx_buf = 4096;
constexpr size_t   reply_buf  = 4096;
// The socket buffers asked for, each way.
constexpr int      udp_sock_buf = 8 << 20;
// Batches taken in one turn before the loop is given back, so other work and the timer are not starved.
constexpr int      udp_rounds = 32;
// RFC 7766 6.2.3: a connection left quiet is closed after a few seconds; a transfer under way is not quiet.
constexpr int      tcp_idle_secs = 10;
// A connection whose answers have not moved for this long has a peer that does not read them, and is closed.
constexpr int      tcp_stall_secs = 30;
constexpr uint32_t tcp_max_conns = 256;
// What a connection may have waiting to be written: a whole transfer of a large zone, and no more.
constexpr size_t   tcp_out_max = 256u << 20;
// Past this much unsent, a connection's queries are neither read nor answered until its peer has read some.
constexpr size_t   tcp_out_high = 64u << 10;
constexpr size_t   tcp_rbuf = 16384;
// A NOTIFY is sent again at these seconds after the first, until the secondary answers it (RFC 1996 3.6).
constexpr int      notify_backoff[] = {1, 3, 7, 15, 31};
// The client blocks the rate limit remembers, so a flood from forged sources cannot grow the table without end.
constexpr size_t   rrl_max_blocks = 1u << 18;

int64_t steady_sec()
{
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

// host[:port], [v6]:port or a bare v6 address, the port 53 when none is given.
bool parse_target(std::string_view s, sockaddr_storage& out, socklen_t& len)
{
    std::string host(s);
    uint16_t port = 53;
    if (!s.empty() && s.front() == '[')
    {
        const size_t close = s.find(']');
        if (close == std::string_view::npos)
            return false;
        host = std::string(s.substr(1, close - 1));
        std::string_view rest = s.substr(close + 1);
        if (!rest.empty())
        {
            if (rest.front() != ':')
                return false;
            rest.remove_prefix(1);
            const auto [e, ec] = std::from_chars(rest.data(), rest.data() + rest.size(), port);
            if (ec != std::errc{} || e != rest.data() + rest.size() || port == 0)
                return false;
        }
    }
    else if (std::count(s.begin(), s.end(), ':') == 1)
    {
        const size_t colon = s.find(':');
        host = std::string(s.substr(0, colon));
        const std::string_view p = s.substr(colon + 1);
        const auto [e, ec] = std::from_chars(p.data(), p.data() + p.size(), port);
        if (ec != std::errc{} || e != p.data() + p.size() || port == 0)
            return false;
    }
    socketley::endpoint e;
    if (!socketley::literal_endpoint(host, port, e))
        return false;
    out = e.addr;
    len = e.len;
    return true;
}

std::vector<std::string> split_csv(std::string_view s)
{
    std::vector<std::string> out;
    while (!s.empty())
    {
        std::string_view item = take_item(s);
        while (!item.empty() && item.front() == ' ')
            item.remove_prefix(1);
        while (!item.empty() && item.back() == ' ')
            item.remove_suffix(1);
        if (!item.empty())
            out.emplace_back(item);
    }
    return out;
}

// What signs a zone as it is loaded where the runtime signs its zones; false with why.
using zone_signer = std::function<bool(zone&, std::string&)>;

// Every zone of `paths`, read and checked, one apex each, and signed by `sign` where it is given; false with the reason.
bool load_all(const std::vector<std::string>& paths, zone_set& out, std::string& why,
              const extra_records* extra = nullptr, const zone_signer* sign = nullptr)
{
    out.zones.clear();
    for (const auto& p : paths)
    {
        auto z = std::make_shared<zone>();
        if (!load_zone(p, {}, *z, why))
            return false;
        if (extra)
            add_extra(*z, *extra);
        if (sign && *sign && !(*sign)(*z, why))
        {
            why = p + ": " + why;
            return false;
        }
        for (const auto& other : out.zones)
            if (other->origin == z->origin)
            {
                why = p + ": " + to_text(z->origin) + " is already served from " + other->path;
                return false;
            }
        out.zones.push_back(std::move(z));
    }
    return true;
}

// The addresses --publish names, each in wire form; false naming the one that is no address.
bool parse_publish(std::string_view csv, std::vector<std::string>& v4, std::vector<std::string>& v6, std::string& bad)
{
    for (const auto& a : split_csv(csv))
    {
        in_addr a4{};
        in6_addr a6{};
        if (::inet_pton(AF_INET, a.c_str(), &a4) == 1)
            v4.emplace_back(reinterpret_cast<const char*>(&a4), 4);
        else if (::inet_pton(AF_INET6, a.c_str(), &a6) == 1)
            v6.emplace_back(reinterpret_cast<const char*>(&a6), 16);
        else
        {
            bad = a;
            return false;
        }
    }
    return true;
}

// This machine's addresses the internet can reach, from its interfaces: IPv4 outside the private, shared, loopback
// and link-local blocks, IPv6 in 2000::/3. A host behind NAT has none, and is given its address with --publish.
void public_addresses(std::vector<std::string>& v4, std::vector<std::string>& v6)
{
    ifaddrs* list = nullptr;
    if (::getifaddrs(&list) < 0)
        return;
    for (ifaddrs* i = list; i; i = i->ifa_next)
    {
        if (!i->ifa_addr || !(i->ifa_flags & IFF_UP) || (i->ifa_flags & IFF_LOOPBACK))
            continue;
        if (i->ifa_addr->sa_family == AF_INET)
        {
            const auto* a = reinterpret_cast<const uint8_t*>(&reinterpret_cast<const sockaddr_in*>(i->ifa_addr)->sin_addr);
            const bool priv = a[0] == 10 || a[0] == 127 || a[0] == 0 || (a[0] == 172 && (a[1] & 0xF0) == 16) ||
                              (a[0] == 192 && a[1] == 168) || (a[0] == 169 && a[1] == 254) ||
                              (a[0] == 100 && (a[1] & 0xC0) == 64) || a[0] >= 224;
            std::string w(reinterpret_cast<const char*>(a), 4);
            if (!priv && std::find(v4.begin(), v4.end(), w) == v4.end())
                v4.push_back(std::move(w));
        }
        else if (i->ifa_addr->sa_family == AF_INET6)
        {
            const auto* a = reinterpret_cast<const uint8_t*>(&reinterpret_cast<const sockaddr_in6*>(i->ifa_addr)->sin6_addr);
            std::string w(reinterpret_cast<const char*>(a), 16);
            if ((a[0] & 0xE0) == 0x20 && std::find(v6.begin(), v6.end(), w) == v6.end())
                v6.push_back(std::move(w));
        }
    }
    ::freeifaddrs(list);
    std::sort(v4.begin(), v4.end());
    std::sort(v6.begin(), v6.end());
}

std::string peer_text(const sockaddr_storage& ss)
{
    char buf[INET6_ADDRSTRLEN] = "?";
    if (ss.ss_family == AF_INET)
        ::inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(&ss)->sin_addr, buf, sizeof buf);
    else if (ss.ss_family == AF_INET6)
        ::inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(&ss)->sin6_addr, buf, sizeof buf);
    return buf;
}

}   // namespace

// ─── The run ────────────────────────────────────────────────────────────────
// Everything that serves, made by setup() and let go of by teardown(), and kept until the ring owes it nothing.

class dns_run : public io_handler
{
public:
    struct counters
    {
        uint64_t udp_queries{0}, tcp_queries{0};
        uint64_t noerror{0}, nxdomain{0}, refused{0}, formerr{0}, notimp{0}, other_rcode{0};
        uint64_t truncated{0}, referrals{0}, dropped{0};
        uint64_t rrl_dropped{0}, rrl_slipped{0}, send_failed{0};
        uint64_t tcp_conns{0}, tcp_refused{0}, tcp_evicted{0};
        uint64_t transfers{0}, transfers_refused{0};
        uint64_t notify_sent{0}, notify_acked{0}, notify_given_up{0};
        uint64_t reloads{0}, reload_failures{0};
    };

    dns_run(dns_instance& owner, event_loop& loop) : m_owner(owner), m_loop(loop)
    {
        // Not zeroed, so the pages a quiet server never fills are never resident.
        m_rx_bufs = std::make_unique_for_overwrite<uint8_t[]>(static_cast<size_t>(udp_batch) * udp_rx_buf);
        m_tx_bufs = std::make_unique_for_overwrite<uint8_t[]>(static_cast<size_t>(udp_batch) * reply_buf);
    }
    ~dns_run() override
    {
        m_loop.deregister_owner(this);
    }

    bool start(std::string& why);
    void stop();
    bool drained() const { return m_loop.owner_drained(this); }
    void on_cqe(struct io_uring_cqe* cqe) override;

    const counters& stats() const { return m_c; }
    size_t tcp_count() const { return m_conns.size(); }
    std::shared_ptr<const zone_set> zones() const { return m_zones; }

private:
    struct udp_ep
    {
        int fd{-1};
        bool pktinfo{false};
        io_request rd{};
        bool rd_pending{false};
        msghdr msg{};
        iovec iov{};
        sockaddr_storage src{};
        alignas(cmsghdr) char cbuf[128]{};
        uint8_t buf[udp_rx_buf]{};
    };
    struct tcp_listener
    {
        int fd{-1};
        io_request req{};
        bool pending{false};
    };
    struct tcp_conn
    {
        uint64_t id{0};
        int fd{-1};
        sockaddr_storage peer{};
        io_request rd{}, wr{};
        bool rd_pending{false}, wr_pending{false}, dead{false};
        std::string in;
        std::string out;
        size_t out_off{0};
        // Answers made while a write through the ring still reads `out`, which must not move under it.
        std::string later;
        int64_t last{0};
        // What the kernel held unsent or unacknowledged at the last tick while a write waited on it.
        int queued{0};

        // Where the next answer goes: `out` unless the ring is reading it.
        std::string& tail() { return wr_pending ? later : out; }
        size_t waiting() const { return out.size() - out_off + later.size(); }
        bool held() const { return waiting() > tcp_out_high; }
        char rbuf[tcp_rbuf];
    };
    // A NOTIFY goes from a socket of its own, connected to the secondary, so its answer comes back to this shard:
    // from the shared port the kernel would hand it to any of them.
    struct notify_job
    {
        int fd{-1};
        std::string origin;
        sockaddr_storage to{};
        socklen_t to_len{0};
        uint16_t id{0};
        int tries{0};
        int64_t next_at{0};
    };
    struct rrl_bucket
    {
        int64_t sec{0};
        uint32_t count{0};
        uint32_t slip{0};
    };

    bool open_udp(int family, uint16_t port, uint32_t bind4);
    bool open_tcp(int family, uint16_t port, uint32_t bind4);
    void arm_udp(udp_ep& ep);
    void udp_done(udp_ep& ep, int res);
    // One datagram: answered into the next slot of the send batch, or dropped.
    void udp_query(udp_ep& ep, const uint8_t* q, size_t len, const sockaddr_storage& src, socklen_t srclen,
                   const msghdr& in_msg);
    void udp_flush(udp_ep& ep);
    bool rrl_limited(const sockaddr_storage& src, bool& slip);

    void arm_accept(tcp_listener& l);
    void accept_done(tcp_listener& l, struct io_uring_cqe* cqe);
    // RFC 7766 6.2.3: a full table makes room by closing the connection longest without a whole query or a write,
    // among those with nothing left to write.
    void evict_quietest();
    void arm_read(const std::shared_ptr<tcp_conn>& c);
    void read_done(const std::shared_ptr<tcp_conn>& c, int res);
    // Answers what `in` holds and flushes, over again while the socket takes the answers whole.
    void tcp_serve(const std::shared_ptr<tcp_conn>& c);
    size_t tcp_answer(const std::shared_ptr<tcp_conn>& c);
    void tcp_flush(const std::shared_ptr<tcp_conn>& c);
    void write_done(const std::shared_ptr<tcp_conn>& c, int res);
    void close_conn(const std::shared_ptr<tcp_conn>& c);
    std::shared_ptr<tcp_conn> conn_of(io_request* req);

    void arm_tick();
    void tick();
    void check_zones();
    void reload_done();
    void arm_wake();
    void queue_notify(const zone& z);
    void send_notify(notify_job& j);
    // Whether the secondary has answered `j`, read without waiting.
    bool notify_answered(notify_job& j);
    void drop_notify(notify_job& j)
    {
        if (j.fd >= 0)
            ::close(j.fd);
        j.fd = -1;
    }
    void count(const answer_meta& m);
    // What the rest of socketley has asked to be published (dns_feed.h), as records for the zones.
    extra_records feed_extra();

    dns_instance& m_owner;
    event_loop&   m_loop;
    counters      m_c;
    bool          m_stopped{false};

    std::shared_ptr<const zone_set> m_zones;
    std::vector<std::string> m_paths;
    // The addresses runtimes' names are given (--publish), and when the feed was last read.
    std::vector<std::string> m_v4, m_v6;
    int64_t m_feed_stamp{-1};
    std::chrono::steady_clock::time_point m_refusal_said{};
    bool m_auto_addresses{false};
    int64_t m_addresses_at{0};
    std::vector<ip_block> m_transfer;
    std::vector<std::pair<sockaddr_storage, socklen_t>> m_notify_to;
    std::vector<notify_job> m_notify;
    uint16_t m_notify_id{0};

    std::vector<std::unique_ptr<udp_ep>> m_udp;
    std::vector<std::unique_ptr<tcp_listener>> m_tcp;
    std::unordered_map<uint64_t, std::shared_ptr<tcp_conn>> m_conns;
    std::vector<std::shared_ptr<tcp_conn>> m_closing;
    uint64_t m_next_id{1};

    // recvmmsg's and sendmmsg's arrays, and the buffers behind them.
    mmsghdr m_rx[udp_batch]{};
    iovec   m_rx_iov[udp_batch]{};
    sockaddr_storage m_rx_src[udp_batch]{};
    alignas(cmsghdr) char m_rx_cbuf[udp_batch][128]{};
    std::unique_ptr<uint8_t[]> m_rx_bufs;
    mmsghdr m_tx[udp_batch]{};
    iovec   m_tx_iov[udp_batch]{};
    sockaddr_storage m_tx_dst[udp_batch]{};
    alignas(cmsghdr) char m_tx_cbuf[udp_batch][64]{};
    std::unique_ptr<uint8_t[]> m_tx_bufs;
    unsigned m_tx_n{0};

    std::unordered_map<uint64_t, rrl_bucket> m_rrl;
    uint32_t m_rrl_limit{0};

    io_request m_tick{};
    __kernel_timespec m_tick_ts{1, 0};
    bool m_tick_armed{false};
    int64_t m_last_sweep{0};
    // With --dnssec, what signs each zone as it is loaded, and the key of each by its apex.
    zone_signer m_signer;
    std::unordered_map<std::string, zone_key> m_keys;

    // A reload read, checked and signed off the loop, which answers from the zones before it meanwhile.
    struct reload_job
    {
        std::vector<std::string> paths;
        extra_records extra;
        std::shared_ptr<const zone_set> prior;
        std::shared_ptr<zone_set> next;
        // The zones of files that are no zone now, kept as they were, and how each file stood when it was read.
        std::vector<const zone*> kept;
        std::vector<std::pair<std::string, socketley::file_stamp>> broken;
        bool whole{false};
        std::string why;
        std::atomic<bool> done{false};
        std::thread th;
    };
    static void read_zones(reload_job& j, const zone_signer* sign);
    std::unique_ptr<reload_job> m_reload;
    // A file that is no zone, as it stood when read, so it is not read again until it changes.
    std::unordered_map<std::string, socketley::file_stamp> m_broken;
    // The zone sets a reload replaced, let go of off the loop.
    std::thread m_retire;
    int m_wake_fd{-1};
    io_request m_wake_req{};
    uint64_t m_wake_buf{0};
    bool m_wake_armed{false};
};

bool dns_run::start(std::string& why)
{
    m_paths = m_owner.zone_paths();
    if (m_owner.get_dnssec())
        m_signer = [this](zone& z, std::string& err) {
            auto it = m_keys.find(z.origin);
            if (it == m_keys.end())
            {
                zone_key k;
                if (!load_or_make_key(dns_dnssec_dir(m_owner.get_name()), z.origin, k, err))
                    return false;
                it = m_keys.emplace(z.origin, std::move(k)).first;
            }
            if (sign_zone(z, it->second, socketley::wall::now_sec()))
                return true;
            err = "its signatures could not be made";
            return false;
        };
    if (std::string bad; !parse_publish(m_owner.get_publish(), m_v4, m_v6, bad))
    {
        why = "--publish: '" + bad + "' is not an address";
        return false;
    }
    // Through an entrance and without addresses given, this machine's own are published, and looked at again now
    // and then, since a host's address can change.
    m_auto_addresses = !m_owner.get_proxy().empty() && m_v4.empty() && m_v6.empty();
    if (m_auto_addresses)
    {
        public_addresses(m_v4, m_v6);
        m_addresses_at = steady_sec();
        if (m_v4.empty() && m_v6.empty())
            LOG_WARN("dns: --proxy is set but this machine has no public address on its interfaces (behind NAT?); "
                     "no runtime's name is published until --publish names one");
    }
    // A zone named rather than given as a file, or a file since removed, is written first.
    if (!m_owner.ensure_zone_files(why))
        return false;
    auto zs = std::make_shared<zone_set>();
    const extra_records extra = feed_extra();
    if (!load_all(m_paths, *zs, why, &extra, &m_signer))
        return false;
    m_zones = zs;

    std::string bad;
    if (!m_owner.get_transfer().empty() && !ip_block::parse_list(m_owner.get_transfer(), m_transfer, bad))
    {
        why = "--transfer: '" + bad + "' is not an address or block";
        return false;
    }
    for (const auto& t : split_csv(m_owner.get_notify()))
    {
        sockaddr_storage ss{};
        socklen_t len = 0;
        if (!parse_target(t, ss, len))
        {
            why = "--notify: '" + t + "' is not an address, or address:port";
            return false;
        }
        m_notify_to.emplace_back(ss, len);
    }
    // The kernel spreads one network's queries over the shards by port, so each keeps its share of the limit.
    const uint32_t shards = std::max<uint32_t>(m_owner.get_shards(), 1);
    m_rrl_limit = m_owner.get_rrl() == 0 ? 0 : std::max<uint32_t>(1, (m_owner.get_rrl() + shards - 1) / shards);

    const uint16_t port = m_owner.effective_port();
    const uint32_t bind4 = m_owner.bind_in_addr();
    const bool any = m_owner.get_bind_address().empty();
    // IPv4, and IPv6 beside it when no address was given and the host has it; a host without IPv6 serves IPv4.
    if (!open_udp(AF_INET, port, bind4) || !open_tcp(AF_INET, port, bind4))
    {
        why = "port " + std::to_string(port) + " could not be bound: " + std::strerror(errno) +
              (port < 1024 && ::geteuid() != 0 ? " (a port below 1024 needs root or CAP_NET_BIND_SERVICE)" : "");
        return false;
    }
    if (any)
    {
        if (open_udp(AF_INET6, port, 0))
        {
            if (!open_tcp(AF_INET6, port, 0))
                LOG_WARN("dns: IPv6 TCP could not be bound; IPv6 is served over UDP only");
        }
    }
    for (auto& ep : m_udp)
        arm_udp(*ep);
    for (auto& l : m_tcp)
        arm_accept(*l);
    arm_tick();
    // Without one a reload is read on the loop, as it is at start.
    m_wake_fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    arm_wake();

    for (const auto& z : m_zones->zones)
    {
        LOG_INFO(("dns: serving " + to_text(z->origin) + " serial " + std::to_string(z->serial) + ", " +
                  std::to_string(z->records) + " records, from " + z->path).c_str());
        queue_notify(*z);
    }
    return true;
}

bool dns_run::open_udp(int family, uint16_t port, uint32_t bind4)
{
    const int fd = ::socket(family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return false;
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    // Every shard binds the port; the kernel spreads the datagrams over them by their addresses.
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
    // A burst of queries waits in the socket while a batch is answered, and is dropped once the buffer is full; the
    // kernel's default holds a few hundred, so it is raised to what net.core.rmem_max allows, forced past it where
    // this process may.
    for (const int opt : {SO_RCVBUF, SO_SNDBUF})
    {
        const int want = udp_sock_buf;
        if (::setsockopt(fd, SOL_SOCKET, opt == SO_RCVBUF ? SO_RCVBUFFORCE : SO_SNDBUFFORCE, &want, sizeof want) < 0 &&
            ::setsockopt(fd, SOL_SOCKET, opt, &want, sizeof want) < 0) {}
    }
    bool pktinfo = false;
    int rc = -1;
    if (family == AF_INET)
    {
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = bind4;
        a.sin_port = htons(port);
        // Bound to every address, a reply has to leave from the one the query came to, or the asker drops it.
        if (bind4 == htonl(INADDR_ANY))
            pktinfo = ::setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof one) == 0;
        rc = ::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof a);
    }
    else
    {
        ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
        pktinfo = ::setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof one) == 0;
        sockaddr_in6 a{};
        a.sin6_family = AF_INET6;
        a.sin6_addr = in6addr_any;
        a.sin6_port = htons(port);
        rc = ::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof a);
    }
    if (rc < 0)
    {
        const int e = errno;
        ::close(fd);
        errno = e;
        return false;
    }
    auto ep = std::make_unique<udp_ep>();
    ep->fd = fd;
    ep->pktinfo = pktinfo;
    m_udp.push_back(std::move(ep));
    return true;
}

bool dns_run::open_tcp(int family, uint16_t port, uint32_t bind4)
{
    const int fd = ::socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return false;
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
    int rc = -1;
    if (family == AF_INET)
    {
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = bind4;
        a.sin_port = htons(port);
        rc = ::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof a);
    }
    else
    {
        ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
        sockaddr_in6 a{};
        a.sin6_family = AF_INET6;
        a.sin6_addr = in6addr_any;
        a.sin6_port = htons(port);
        rc = ::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof a);
    }
    if (rc < 0 || ::listen(fd, 1024) < 0)
    {
        const int e = errno;
        ::close(fd);
        errno = e;
        return false;
    }
    auto l = std::make_unique<tcp_listener>();
    l->fd = fd;
    m_tcp.push_back(std::move(l));
    return true;
}

void dns_run::stop()
{
    if (m_stopped)
        return;
    m_stopped = true;
    for (auto& ep : m_udp)
        if (ep->fd >= 0)
        {
            m_loop.close_fd(ep->fd);
            ep->fd = -1;
        }
    for (auto& l : m_tcp)
        if (l->fd >= 0)
        {
            ::shutdown(l->fd, SHUT_RDWR);
            m_loop.close_fd(l->fd);
            l->fd = -1;
        }
    std::vector<std::shared_ptr<tcp_conn>> all;
    for (auto& [id, c] : m_conns)
        all.push_back(c);
    for (auto& c : all)
        close_conn(c);
    if (m_tick_armed && !m_loop.submit_timeout_remove(&m_tick)) {}
    if (m_reload && m_reload->th.joinable())
        m_reload->th.join();
    m_reload.reset();
    if (m_retire.joinable())
        m_retire.join();
    if (m_wake_fd >= 0)
    {
        m_loop.close_fd(m_wake_fd);
        m_wake_fd = -1;
    }
    for (auto& j : m_notify)
        drop_notify(j);
    m_notify.clear();
}

// ─── UDP ────────────────────────────────────────────────────────────────────

void dns_run::arm_udp(udp_ep& ep)
{
    if (ep.rd_pending || ep.fd < 0 || m_stopped)
        return;
    ep.iov.iov_base = ep.buf;
    ep.iov.iov_len = sizeof ep.buf;
    ep.msg = msghdr{};
    ep.msg.msg_name = &ep.src;
    ep.msg.msg_namelen = sizeof ep.src;
    ep.msg.msg_iov = &ep.iov;
    ep.msg.msg_iovlen = 1;
    ep.msg.msg_control = ep.cbuf;
    ep.msg.msg_controllen = sizeof ep.cbuf;
    ep.rd = io_request{};
    ep.rd.owner = this;
    ep.rd.type = op_recvmsg;
    ep.rd.fd = ep.fd;
    ep.rd_pending = m_loop.submit_recvmsg(ep.fd, &ep.msg, &ep.rd);
}

void dns_run::udp_done(udp_ep& ep, int res)
{
    ep.rd_pending = false;
    if (m_stopped)
        return;
    if (res > 0 && !(ep.msg.msg_flags & MSG_TRUNC))
        udp_query(ep, ep.buf, static_cast<size_t>(res), ep.src, ep.msg.msg_namelen, ep.msg);
    // What else has come is taken now, many at a time, without the ring: a burst of queries costs a recvmmsg and a
    // sendmmsg for each batch of them rather than a completion each.
    for (int round = 0; res >= 0 && round < udp_rounds; ++round)
    {
        for (unsigned i = 0; i < udp_batch; ++i)
        {
            m_rx_iov[i].iov_base = m_rx_bufs.get() + i * udp_rx_buf;
            m_rx_iov[i].iov_len = udp_rx_buf;
            msghdr& h = m_rx[i].msg_hdr;
            h = msghdr{};
            h.msg_name = &m_rx_src[i];
            h.msg_namelen = sizeof m_rx_src[i];
            h.msg_iov = &m_rx_iov[i];
            h.msg_iovlen = 1;
            h.msg_control = m_rx_cbuf[i];
            h.msg_controllen = sizeof m_rx_cbuf[i];
        }
        const int n = ::recvmmsg(ep.fd, m_rx, udp_batch, MSG_DONTWAIT, nullptr);
        if (n <= 0)
            break;
        for (int i = 0; i < n; ++i)
            if (!(m_rx[i].msg_hdr.msg_flags & MSG_TRUNC))
                udp_query(ep, m_rx_bufs.get() + static_cast<size_t>(i) * udp_rx_buf, m_rx[i].msg_len, m_rx_src[i],
                          m_rx[i].msg_hdr.msg_namelen, m_rx[i].msg_hdr);
        // Answered at once rather than after the next read, which may wait: a batch that came short says the queue
        // is drained for now, and its replies leave before anything else is read.
        if (static_cast<unsigned>(n) < udp_batch)
            udp_flush(ep);
    }
    udp_flush(ep);
    arm_udp(ep);
}

bool dns_run::rrl_limited(const sockaddr_storage& src, bool& slip)
{
    slip = false;
    if (m_rrl_limit == 0)
        return false;
    // A /24 for IPv4 and a /56 for IPv6: one network, which is how a forger spreading his sources is still caught.
    uint64_t key = 0;
    if (src.ss_family == AF_INET)
    {
        const auto* a = reinterpret_cast<const uint8_t*>(&reinterpret_cast<const sockaddr_in*>(&src)->sin_addr);
        key = (1ull << 56) | uint64_t(a[0]) << 16 | uint64_t(a[1]) << 8 | a[2];
    }
    else
    {
        const auto* a = reinterpret_cast<const uint8_t*>(&reinterpret_cast<const sockaddr_in6*>(&src)->sin6_addr);
        for (int i = 0; i < 7; ++i)
            key = key << 8 | a[i];
        key |= 2ull << 56;
    }
    if (m_rrl.size() >= rrl_max_blocks && !m_rrl.count(key))
        m_rrl.clear();
    rrl_bucket& b = m_rrl[key];
    const int64_t now = steady_sec();
    if (b.sec != now)
    {
        b.sec = now;
        b.count = 0;
    }
    if (++b.count <= m_rrl_limit)
        return false;
    // Every second one past the limit is answered truncated (BIND's slip of 2): a real resolver comes back over
    // TCP and is served, while a forged source gets a reply no larger than its query.
    slip = (++b.slip & 1) == 0;
    return true;
}

void dns_run::udp_query(udp_ep& ep, const uint8_t* q, size_t len, const sockaddr_storage& src, socklen_t srclen,
                        const msghdr& in_msg)
{
    runtime_instance::stat_add(m_owner.m_stat_total_messages, 1);
    runtime_instance::stat_add(m_owner.m_stat_bytes_in, len);
    if (m_tx_n == udp_batch)
        udp_flush(ep);
    const unsigned slot = m_tx_n;
    uint8_t* out = m_tx_bufs.get() + static_cast<size_t>(slot) * reply_buf;
    answer_meta meta;
    const bool xfr = !m_transfer.empty() && ip_block::any_contains(m_transfer, reinterpret_cast<const sockaddr*>(&src));
    size_t n = answer(*m_zones, q, len, out, reply_buf, /*tcp=*/false, xfr, meta);
    if (meta.notify_ack)
        return;   // answers to our NOTIFYs come to their own sockets; one here is stray
    if (n == 0)
    {
        ++m_c.dropped;
        return;
    }
    ++m_c.udp_queries;
    count(meta);
    bool slip = false;
    if (rrl_limited(src, slip))
    {
        if (!slip)
        {
            ++m_c.rrl_dropped;
            return;
        }
        ++m_c.rrl_slipped;
        // The header and question alone, truncated: as large as the query and no larger.
        const size_t qend = meta.question_end;
        if (qend < header_len || qend > n)
            return;
        n = qend;
        out[2] |= 0x02;   // TC
        wr16(out + 6, 0);
        wr16(out + 8, 0);
        wr16(out + 10, 0);
    }

    m_tx_iov[slot].iov_base = out;
    m_tx_iov[slot].iov_len = n;
    std::memcpy(&m_tx_dst[slot], &src, srclen);
    msghdr& h = m_tx[slot].msg_hdr;
    h = msghdr{};
    h.msg_name = &m_tx_dst[slot];
    h.msg_namelen = srclen;
    h.msg_iov = &m_tx_iov[slot];
    h.msg_iovlen = 1;
    // The reply leaves from the address the query came to.
    if (ep.pktinfo)
        for (cmsghdr* cm = CMSG_FIRSTHDR(&in_msg); cm; cm = CMSG_NXTHDR(const_cast<msghdr*>(&in_msg), cm))
        {
            if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_PKTINFO)
            {
                in_pktinfo pi{};
                std::memcpy(&pi, CMSG_DATA(cm), sizeof pi);
                in_pktinfo outpi{};
                outpi.ipi_spec_dst = pi.ipi_addr;
                h.msg_control = m_tx_cbuf[slot];
                h.msg_controllen = CMSG_SPACE(sizeof outpi);
                cmsghdr* oc = CMSG_FIRSTHDR(&h);
                oc->cmsg_level = IPPROTO_IP;
                oc->cmsg_type = IP_PKTINFO;
                oc->cmsg_len = CMSG_LEN(sizeof outpi);
                std::memcpy(CMSG_DATA(oc), &outpi, sizeof outpi);
                break;
            }
            if (cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_PKTINFO)
            {
                in6_pktinfo pi{};
                std::memcpy(&pi, CMSG_DATA(cm), sizeof pi);
                h.msg_control = m_tx_cbuf[slot];
                h.msg_controllen = CMSG_SPACE(sizeof pi);
                cmsghdr* oc = CMSG_FIRSTHDR(&h);
                oc->cmsg_level = IPPROTO_IPV6;
                oc->cmsg_type = IPV6_PKTINFO;
                oc->cmsg_len = CMSG_LEN(sizeof pi);
                std::memcpy(CMSG_DATA(oc), &pi, sizeof pi);
                break;
            }
        }
    m_tx[slot].msg_len = 0;
    ++m_tx_n;
    runtime_instance::stat_add(m_owner.m_stat_bytes_out, n);
}

void dns_run::udp_flush(udp_ep& ep)
{
    unsigned sent = 0;
    while (sent < m_tx_n)
    {
        const int n = ::sendmmsg(ep.fd, m_tx + sent, m_tx_n - sent, MSG_DONTWAIT);
        if (n <= 0)
        {
            // A full send buffer drops what is left, as the network would; the asker tries again.
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            {
                // One bad destination fails only itself.
                ++m_c.send_failed;
                ++sent;
                continue;
            }
            m_c.send_failed += m_tx_n - sent;
            break;
        }
        sent += static_cast<unsigned>(n);
    }
    m_tx_n = 0;
}

void dns_run::count(const answer_meta& m)
{
    switch (m.rcode)
    {
        case rcode::NOERROR:  ++m_c.noerror; break;
        case rcode::NXDOMAIN: ++m_c.nxdomain; break;
        case rcode::REFUSED:  ++m_c.refused; break;
        case rcode::FORMERR:  ++m_c.formerr; break;
        case rcode::NOTIMP:   ++m_c.notimp; break;
        default:              ++m_c.other_rcode; break;
    }
    if (m.truncated)
        ++m_c.truncated;
    if (m.referral)
        ++m_c.referrals;
}

// ─── TCP ────────────────────────────────────────────────────────────────────

void dns_run::arm_accept(tcp_listener& l)
{
    if (m_stopped || l.fd < 0 || l.pending)
        return;
    l.req = io_request{};
    l.req.owner = this;
    l.req.fd = l.fd;
    l.req.type = event_loop::supports_multishot_accept() ? op_multishot_accept : op_accept;
    l.pending = l.req.type == op_multishot_accept ? m_loop.submit_multishot_accept(l.fd, &l.req)
                                                  : m_loop.submit_accept(l.fd, nullptr, nullptr, &l.req);
}

void dns_run::accept_done(tcp_listener& l, struct io_uring_cqe* cqe)
{
    if (!(cqe->flags & IORING_CQE_F_MORE))
        l.pending = false;
    const int fd = cqe->res;
    if (fd >= 0)
    {
        const uint32_t limit = m_owner.get_max_connections() ? m_owner.get_max_connections() : tcp_max_conns;
        if (!m_stopped && m_conns.size() >= limit)
            evict_quietest();
        if (m_stopped || m_conns.size() >= limit)
        {
            ++m_c.tcp_refused;
            m_loop.close_fd(fd);
        }
        else
        {
            // Default-initialised, so the read buffer is not zeroed before the first read fills it.
            auto c = std::make_shared_for_overwrite<tcp_conn>();
            c->id = m_next_id++;
            c->fd = fd;
            socklen_t len = sizeof c->peer;
            if (::getpeername(fd, reinterpret_cast<sockaddr*>(&c->peer), &len) < 0) {}
            int one = 1;
            ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
            c->last = steady_sec();
            m_conns.emplace(c->id, c);
            ++m_c.tcp_conns;
            runtime_instance::stat_add(m_owner.m_stat_total_connections, 1);
            m_owner.m_stat_active_connections.store(m_conns.size(), std::memory_order_relaxed);
            arm_read(c);
        }
    }
    // Out of descriptors or memory is left to tick(), which asks again a second later.
    const bool starved = fd == -EMFILE || fd == -ENFILE || fd == -ENOBUFS || fd == -ENOMEM;
    if (!l.pending && !m_stopped && fd != -ECANCELED && !starved)
        arm_accept(l);
}

void dns_run::evict_quietest()
{
    std::shared_ptr<tcp_conn> pick;
    for (const auto& [id, c] : m_conns)
        if (c->waiting() == 0 && (!pick || c->last < pick->last))
            pick = c;
    if (!pick)
        return;
    ++m_c.tcp_evicted;
    close_conn(pick);
}

std::shared_ptr<dns_run::tcp_conn> dns_run::conn_of(io_request* req)
{
    auto* raw = reinterpret_cast<tcp_conn*>(req->buffer);
    if (auto it = m_conns.find(raw->id); it != m_conns.end() && it->second.get() == raw)
        return it->second;
    for (const auto& c : m_closing)
        if (c.get() == raw)
            return c;
    return nullptr;
}

void dns_run::arm_read(const std::shared_ptr<tcp_conn>& c)
{
    if (c->dead || c->rd_pending || c->fd < 0)
        return;
    c->rd = io_request{};
    c->rd.owner = this;
    c->rd.buffer = reinterpret_cast<char*>(c.get());
    c->rd.fd = c->fd;
    c->rd.type = op_read;
    c->rd_pending = m_loop.submit_read(c->fd, c->rbuf, sizeof c->rbuf, &c->rd);
    if (!c->rd_pending)
        close_conn(c);
}

void dns_run::read_done(const std::shared_ptr<tcp_conn>& c, int res)
{
    c->rd_pending = false;
    if (c->dead)
    {
        if (!c->wr_pending)
            std::erase(m_closing, c);
        return;
    }
    if (res <= 0)
    {
        close_conn(c);
        return;
    }
    c->in.append(c->rbuf, static_cast<size_t>(res));
    runtime_instance::stat_add(m_owner.m_stat_bytes_in, static_cast<uint64_t>(res));
    tcp_serve(c);
    if (!c->dead && !c->held())
        arm_read(c);
}

void dns_run::tcp_serve(const std::shared_ptr<tcp_conn>& c)
{
    for (;;)
    {
        const size_t took = tcp_answer(c);
        if (c->dead)
            return;
        // A message can be no longer than 65535 bytes and its length; more than that waiting is no DNS client.
        if (!c->held() && c->in.size() > max_message + 2)
        {
            close_conn(c);
            return;
        }
        tcp_flush(c);
        // A flush the socket took whole makes room for the queries held back behind it.
        if (c->dead || c->held() || took == 0)
            return;
    }
}

// Every whole message the connection has brought, answered in order (RFC 7766 allows pipelining), until what waits
// to be written is past tcp_out_high; the bytes taken from `in`.
size_t dns_run::tcp_answer(const std::shared_ptr<tcp_conn>& c)
{
    size_t off = 0;
    static thread_local uint8_t out[max_message + 2];
    const bool xfr_ok = !m_transfer.empty() && ip_block::any_contains(m_transfer, reinterpret_cast<const sockaddr*>(&c->peer));
    while (!c->held() && c->in.size() - off >= 2)
    {
        const size_t len = rd16(reinterpret_cast<const uint8_t*>(c->in.data()) + off);
        if (c->in.size() - off - 2 < len)
            break;
        const auto* q = reinterpret_cast<const uint8_t*>(c->in.data()) + off + 2;
        off += 2 + len;
        runtime_instance::stat_add(m_owner.m_stat_total_messages, 1);
        answer_meta meta;
        const size_t n = answer(*m_zones, q, len, out + 2, max_message, /*tcp=*/true, xfr_ok, meta);
        if (meta.xfr)
        {
            // The zone as it stands now, whole; a reload meanwhile does not change what is already queued.
            ++m_c.transfers;
            ++m_c.tcp_queries;
            ++m_c.noerror;
            LOG_INFO(("dns: transfer of " + to_text(meta.xfr->origin) + " serial " + std::to_string(meta.xfr->serial) +
                      " to " + peer_text(c->peer)).c_str());
            transfer(*meta.xfr, q, meta.question_end, [&](const uint8_t* p, size_t n2)
                     {
                         uint8_t pre[2];
                         wr16(pre, static_cast<uint16_t>(n2));
                         c->tail().append(reinterpret_cast<const char*>(pre), 2);
                         c->tail().append(reinterpret_cast<const char*>(p), n2);
                     });
            if (c->waiting() > tcp_out_max)
            {
                close_conn(c);
                return 0;
            }
            continue;
        }
        if (n == 0)
        {
            ++m_c.dropped;
            continue;
        }
        if (meta.qtype == type::AXFR || meta.qtype == type::IXFR)
        {
            ++m_c.transfers_refused;
            // Said, at most once a second, so a secondary asking from an address --transfer does not name is found.
            if (const auto now = std::chrono::steady_clock::now(); now - m_refusal_said >= std::chrono::seconds(1))
            {
                m_refusal_said = now;
                LOG_WARN(("dns: a zone transfer was refused to " + peer_text(c->peer) +
                          ", which --transfer does not name").c_str());
            }
        }
        ++m_c.tcp_queries;
        count(meta);
        wr16(out, static_cast<uint16_t>(n));
        c->tail().append(reinterpret_cast<const char*>(out), n + 2);
        if (c->waiting() > tcp_out_max)
        {
            close_conn(c);
            return 0;
        }
    }
    c->in.erase(0, off);
    // Only a whole query counts as activity, so a peer trickling bytes of one it never finishes is still quiet.
    if (off > 0)
        c->last = steady_sec();
    return off;
}

void dns_run::tcp_flush(const std::shared_ptr<tcp_conn>& c)
{
    if (c->dead || c->wr_pending || c->out_off >= c->out.size())
        return;
    // Straight to the socket first: an answer is small and the buffer is almost always empty.
    while (c->out_off < c->out.size())
    {
        const ssize_t n = ::send(c->fd, c->out.data() + c->out_off, c->out.size() - c->out_off, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n > 0)
        {
            c->out_off += static_cast<size_t>(n);
            runtime_instance::stat_add(m_owner.m_stat_bytes_out, static_cast<uint64_t>(n));
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
        close_conn(c);
        return;
    }
    if (c->out_off >= c->out.size())
    {
        c->out.clear();
        c->out_off = 0;
        return;
    }
    // The rest when the socket takes it, through the ring.
    const size_t chunk = std::min<size_t>(c->out.size() - c->out_off, 1u << 20);
    c->wr = io_request{};
    c->wr.owner = this;
    c->wr.buffer = reinterpret_cast<char*>(c.get());
    c->wr.fd = c->fd;
    c->wr.type = op_write;
    c->wr_pending = m_loop.submit_write(c->fd, c->out.data() + c->out_off, static_cast<uint32_t>(chunk), &c->wr);
    if (!c->wr_pending)
        close_conn(c);
}

void dns_run::write_done(const std::shared_ptr<tcp_conn>& c, int res)
{
    c->wr_pending = false;
    if (c->dead)
    {
        if (!c->rd_pending)
            std::erase(m_closing, c);
        return;
    }
    if (res <= 0)
    {
        close_conn(c);
        return;
    }
    c->out_off += static_cast<size_t>(res);
    c->last = steady_sec();
    runtime_instance::stat_add(m_owner.m_stat_bytes_out, static_cast<uint64_t>(res));
    // Nothing reads `out` now, so what waited beside it joins it.
    if (!c->later.empty())
    {
        c->out.append(c->later);
        c->later.clear();
    }
    // The queries held back while the peer was not reading are answered, and reading starts again, once it has.
    tcp_serve(c);
    if (!c->dead && !c->held())
        arm_read(c);
}

void dns_run::close_conn(const std::shared_ptr<tcp_conn>& c)
{
    if (c->dead)
        return;
    c->dead = true;
    if (c->fd >= 0)
    {
        ::shutdown(c->fd, SHUT_RDWR);
        m_loop.close_fd(c->fd);
        c->fd = -1;
    }
    m_conns.erase(c->id);
    m_owner.m_stat_active_connections.store(m_conns.size(), std::memory_order_relaxed);
    // Kept while the ring may still write into its buffer.
    if (c->rd_pending || c->wr_pending)
        m_closing.push_back(c);
}

// ─── Once a second ──────────────────────────────────────────────────────────

void dns_run::arm_tick()
{
    if (m_tick_armed || m_stopped)
        return;
    m_tick = io_request{};
    m_tick.owner = this;
    m_tick.type = op_timeout;
    m_tick_ts = {1, 0};
    m_tick_armed = m_loop.submit_timeout(&m_tick_ts, &m_tick);
}

void dns_run::tick()
{
    const int64_t now = steady_sec();
    // A read or accept the ring had no room for when it was last asked is asked again here, or the socket would be
    // deaf for good.
    for (auto& ep : m_udp)
        arm_udp(*ep);
    for (auto& l : m_tcp)
        arm_accept(*l);
    // Connections quiet for too long with nothing left to write, and those whose peer has stopped reading.
    std::vector<std::shared_ptr<tcp_conn>> idle;
    for (auto& [id, c] : m_conns)
    {
        // A slow reader drains the kernel's queue long before the write waiting behind it wakes, and that is movement.
        if (int q = 0; c->wr_pending && ::ioctl(c->fd, SIOCOUTQ, &q) == 0)
        {
            if (q < c->queued)
                c->last = now;
            c->queued = q;
        }
        if ((now - c->last > tcp_idle_secs && c->waiting() == 0) || now - c->last > tcp_stall_secs)
            idle.push_back(c);
    }
    for (auto& c : idle)
        close_conn(c);
    // The rate limit's blocks of seconds gone by.
    if (now - m_last_sweep >= 10)
    {
        m_last_sweep = now;
        std::erase_if(m_rrl, [now](const auto& kv) { return now - kv.second.sec > 5; });
    }
    // Answers read before a reload may replace the NOTIFYs they answer.
    std::erase_if(m_notify, [this](notify_job& j)
                  {
                      if (!notify_answered(j))
                          return false;
                      ++m_c.notify_acked;
                      drop_notify(j);
                      return true;
                  });
    check_zones();
    for (auto it = m_notify.begin(); it != m_notify.end();)
    {
        if (it->next_at > now)
        {
            ++it;
            continue;
        }
        if (it->tries >= static_cast<int>(std::size(notify_backoff)))
        {
            ++m_c.notify_given_up;
            LOG_WARN(("dns: " + peer_text(it->to) + " never answered the NOTIFY for " + it->origin).c_str());
            drop_notify(*it);
            it = m_notify.erase(it);
            continue;
        }
        send_notify(*it);
        ++it;
    }
}

// A zone file changed on disk is read again; the new zone is served once it has been read whole and checked, and the
// old one kept, with the reason logged, when it is not a zone.
extra_records dns_run::feed_extra()
{
    extra_records x;
    dns_feed::snapshot s = dns_feed::read();
    m_feed_stamp = s.stamp_ns;
    // Names are published only where there are addresses to give them; DNS-01 answers always.
    if (!m_v4.empty() || !m_v6.empty())
        x.names = std::move(s.names);
    x.v4 = m_v4;
    x.v6 = m_v6;
    x.challenges = std::move(s.challenges);
    x.records = std::move(s.records);
    // Seconds since November 2023 that the feed last changed: it only grows, so the serial a secondary sees grows
    // whenever the feed or the file changes, and is the same in every shard and after every restart.
    constexpr int64_t base = 1700000000;
    if (s.stamp_ns > 0)
        x.serial_add = static_cast<uint32_t>(std::max<int64_t>(0, s.stamp_ns / 1000000000 - base));
    return x;
}

// Every zone of a reload read and checked; where one is not a zone each file is taken on its own, a sound one as it now
// is and a broken one as it was served.
void dns_run::read_zones(reload_job& j, const zone_signer* sign)
{
    j.next = std::make_shared<zone_set>();
    j.whole = load_all(j.paths, *j.next, j.why, &j.extra, sign);
    if (j.whole)
        return;
    j.next->zones.clear();
    for (const auto& p : j.paths)
    {
        auto z = std::make_shared<zone>();
        std::string ignored;
        bool sound = load_zone(p, {}, *z, ignored);
        if (sound)
        {
            add_extra(*z, j.extra);
            if (sign && *sign && !(*sign)(*z, ignored))
                sound = false;
            for (const auto& other : j.next->zones)
                if (other->origin == z->origin)
                    sound = false;
            for (const auto& o : j.prior->zones)
                if (o->path != p && o->origin == z->origin)
                    sound = false;
        }
        if (sound)
        {
            j.next->zones.push_back(std::move(z));
            continue;
        }
        for (const auto& o : j.prior->zones)
            if (o->path == p)
            {
                j.kept.push_back(o.get());
                j.next->zones.push_back(o);
                if (const socketley::file_stamp now = socketley::file_stamp::of(p); now.exists())
                    j.broken.emplace_back(p, now);
            }
    }
}

void dns_run::check_zones()
{
    // A reload under way is looked at again once it has been served.
    if (m_reload)
        return;
    bool changed = dns_feed::stamp_ns() != m_feed_stamp;
    // This machine's addresses, looked at once a minute when they are what is published.
    if (m_auto_addresses && steady_sec() - m_addresses_at >= 60)
    {
        m_addresses_at = steady_sec();
        std::vector<std::string> v4, v6;
        public_addresses(v4, v6);
        if (v4 != m_v4 || v6 != m_v6)
        {
            LOG_INFO("dns: this machine's public addresses changed; the names published are given the new ones");
            m_v4 = std::move(v4);
            m_v6 = std::move(v6);
            changed = true;
        }
    }
    // A signed zone is signed again as a new week begins, its serial raised for the secondaries.
    const int64_t epoch = sign_epoch(socketley::wall::now_sec());
    for (const auto& z : m_zones->zones)
        if (z->dnssec && z->sign_epoch != epoch)
            changed = true;
    for (const auto& z : m_zones->zones)
    {
        // A file gone for a moment is no change; it is read again once it is back.
        const socketley::file_stamp now = socketley::file_stamp::of(z->path);
        const auto seen = m_broken.find(z->path);
        if (now.exists() && now != z->stamp && (seen == m_broken.end() || seen->second != now))
            changed = true;
    }
    if (!changed)
        return;
    auto job = std::make_unique<reload_job>();
    job->paths = m_paths;
    job->extra = feed_extra();
    job->prior = m_zones;
    reload_job* raw = job.get();
    const zone_signer* sign = &m_signer;
    m_reload = std::move(job);
    if (m_wake_fd < 0)
    {
        read_zones(*raw, sign);
        raw->done = true;
        reload_done();
        return;
    }
    const int wake = m_wake_fd;
    raw->th = std::thread([raw, sign, wake] {
        read_zones(*raw, sign);
        raw->done.store(true, std::memory_order_release);
        socketley::eventfd_bump(wake);
    });
}

void dns_run::arm_wake()
{
    if (m_wake_armed || m_wake_fd < 0 || m_stopped)
        return;
    // Polled, not read: the ring's read is a socket's recv, which an eventfd answers at once with ENOTSOCK.
    m_wake_req = io_request{};
    m_wake_req.owner = this;
    m_wake_req.fd = m_wake_fd;
    m_wake_req.type = op_poll;
    m_wake_armed = m_loop.submit_poll_add(m_wake_fd, POLLIN, &m_wake_req);
}

void dns_run::reload_done()
{
    if (!m_reload || !m_reload->done.load(std::memory_order_acquire))
        return;
    if (m_reload->th.joinable())
        m_reload->th.join();
    const std::unique_ptr<reload_job> j = std::move(m_reload);
    if (!j->whole)
    {
        ++m_c.reload_failures;
        LOG_ERROR(("dns: zone not reloaded, still serving the one before: " + j->why).c_str());
    }
    m_broken.clear();
    for (auto& [p, st] : j->broken)
        m_broken[p] = st;
    const std::vector<const zone*>& kept = j->kept;
    const std::shared_ptr<zone_set> next = j->next;
    if (kept.size() < next->zones.size())
        ++m_c.reloads;
    std::shared_ptr<const zone_set> prior = std::move(m_zones);
    m_zones = next;
    j->prior.reset();
    for (const auto& z : next->zones)
    {
        if (std::find(kept.begin(), kept.end(), z.get()) != kept.end())
            continue;
        const zone* before = prior->find(z->origin);
        const bool newer = !before || before->origin != z->origin || before->serial != z->serial;
        LOG_INFO(("dns: reloaded " + to_text(z->origin) + " serial " + std::to_string(z->serial) + ", " +
                  std::to_string(z->records) + " records").c_str());
        if (before && before->origin == z->origin && before->serial == z->serial && before->records != z->records)
            LOG_WARN(("dns: " + to_text(z->origin) + " changed but its serial did not; secondaries will not see the "
                      "change until it is raised").c_str());
        if (newer)
            queue_notify(*z);
    }
    // A large zone takes milliseconds to free, which the queries behind it would wait.
    if (m_retire.joinable())
        m_retire.join();
    m_retire = std::thread([old = std::move(prior)]() mutable { old.reset(); });
}

void dns_run::queue_notify(const zone& z)
{
    // One shard tells the secondaries; the others serve the same files.
    if (m_owner.get_shard_index() != 0)
        return;
    const std::string origin = to_text(z.origin);
    std::erase_if(m_notify, [&](notify_job& j)
                  {
                      if (j.origin != origin)
                          return false;
                      // The serial before was told, if the answer has come meanwhile.
                      if (notify_answered(j))
                          ++m_c.notify_acked;
                      drop_notify(j);
                      return true;
                  });
    for (const auto& [to, len] : m_notify_to)
    {
        notify_job j;
        j.origin = origin;
        j.to = to;
        j.to_len = len;
        j.id = ++m_notify_id;
        j.next_at = 0;
        m_notify.push_back(j);
    }
    for (auto& j : m_notify)
        if (j.tries == 0)
            send_notify(j);
}

void dns_run::send_notify(notify_job& j)
{
    const zone* z = nullptr;
    for (const auto& zz : m_zones->zones)
        if (to_text(zz->origin) == j.origin)
            z = zz.get();
    j.next_at = steady_sec() + notify_backoff[std::min<size_t>(j.tries, std::size(notify_backoff) - 1)];
    ++j.tries;
    if (!z)
        return;
    if (j.fd < 0)
    {
        j.fd = ::socket(j.to.ss_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (j.fd >= 0 && ::connect(j.fd, reinterpret_cast<const sockaddr*>(&j.to), j.to_len) < 0)
            drop_notify(j);
        if (j.fd < 0)
            return;
    }
    uint8_t buf[512];
    const size_t n = make_notify(*z, j.id, buf, sizeof buf);
    if (n && ::send(j.fd, buf, n, MSG_DONTWAIT) > 0)
        ++m_c.notify_sent;
}

bool dns_run::notify_answered(notify_job& j)
{
    if (j.fd < 0)
        return false;
    uint8_t buf[512];
    for (;;)
    {
        const ssize_t n = ::recv(j.fd, buf, sizeof buf, MSG_DONTWAIT);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < static_cast<ssize_t>(header_len))
            return false;
        // A response to this NOTIFY: its ID, QR set, opcode NOTIFY. A connected socket takes datagrams from the
        // secondary's address alone.
        const uint16_t flags = rd16(buf + 2);
        if (rd16(buf) == j.id && (flags & 0x8000) && ((flags >> 11) & 0xF) == opcode::NOTIFY)
            return true;
    }
}

// ─── Completions ────────────────────────────────────────────────────────────

void dns_run::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req)
        return;
    if (req == &m_wake_req)
    {
        m_wake_armed = false;
        if (m_stopped)
            return;
        if (::read(m_wake_fd, &m_wake_buf, sizeof m_wake_buf) < 0) {}
        reload_done();
        arm_wake();
        return;
    }
    if (req == &m_tick)
    {
        if (cqe->res == -ECANCELED)
        {
            m_tick_armed = false;
            return;
        }
        m_tick_armed = false;
        if (!m_stopped)
        {
            tick();
            arm_tick();
        }
        return;
    }
    for (auto& ep : m_udp)
        if (req == &ep->rd)
        {
            udp_done(*ep, cqe->res);
            return;
        }
    for (auto& l : m_tcp)
        if (req == &l->req)
        {
            accept_done(*l, cqe);
            return;
        }
    const auto c = conn_of(req);
    if (!c)
        return;
    if (req == &c->rd)
        read_done(c, cqe->res);
    else if (req == &c->wr)
        write_done(c, cqe->res);
}

}   // namespace socketley::dns

// ─── The runtime ────────────────────────────────────────────────────────────

using socketley::dns::dns_run;

dns_instance::dns_instance(std::string_view name) : runtime_instance(runtime_dns, name) {}

dns_instance::~dns_instance() = default;

std::string dns_dnssec_dir(std::string_view runtime_name)
{
    return (socketley_paths::resolve().state_dir / "dns" / (std::string(runtime_name) + ".dnssec")).string();
}

std::string dns_instance::ds_records(std::string& why) const
{
    socketley::dns::zone_set zs;
    if (!socketley::dns::load_all(zone_paths(), zs, why))
        return {};
    std::string out;
    for (const auto& z : zs.zones)
    {
        socketley::dns::zone_key k;
        if (!socketley::dns::load_or_make_key(dns_dnssec_dir(get_name()), z->origin, k, why))
            return {};
        out += socketley::dns::ds_text(z->origin, k) + "\n";
        out += socketley::dns::to_text(z->origin) + " IN DNSKEY 257 3 13 " +
               socketley::base64::encode(std::string_view(k.dnskey).substr(4)) + "\n";
    }
    return out;
}

std::vector<std::string> dns_instance::zone_paths() const
{
    auto paths = socketley::dns::split_csv(m_zones);
    for (auto& p : paths)
        if (p.find('/') == std::string::npos)
            p = managed_zone_path(p);
    return paths;
}

std::string dns_instance::managed_zone_path(std::string_view zone)
{
    std::string n;
    for (char c : zone)
        n += (c >= 'A' && c <= 'Z') ? static_cast<char>(c | 0x20) : c;
    while (!n.empty() && n.back() == '.')
        n.pop_back();
    return (socketley_paths::resolve().state_dir / "zones" / (n + ".zone")).string();
}

bool dns_instance::ensure_zone_files(std::string& why) const
{
    for (const auto& entry : socketley::dns::split_csv(m_zones))
    {
        const bool named = entry.find('/') == std::string::npos;
        const std::string path = named ? managed_zone_path(entry) : entry;
        struct stat st{};
        if (::stat(path.c_str(), &st) == 0)
            continue;
        // A file this process may not look at is not missing, and is not written over.
        if (errno != ENOENT)
        {
            why = "--zone: " + path + " cannot be read: " + std::strerror(errno);
            return false;
        }
        // The zone a missing file is for: the name given, or the file's own name less ".zone".
        std::string origin = named ? entry : std::filesystem::path(path).filename().string();
        if (!named && origin.ends_with(".zone"))
            origin.resize(origin.size() - 5);
        while (!origin.empty() && origin.back() == '.')
            origin.pop_back();
        if (std::string bad; (!named && !path.ends_with(".zone")) || origin.find('.') == std::string::npos ||
                             !dns_feed::valid_name(origin, bad) || origin.starts_with("*."))
        {
            why = named ? "--zone: '" + entry + "' is neither a zone's name such as example.com nor a file's path"
                        : "--zone: " + path + " does not exist, and its name says no zone to write it for (name it "
                                              "<zone>.zone, or give the zone's name instead of a path)";
            return false;
        }
        for (char& c : origin)
            if (c >= 'A' && c <= 'Z')
                c = static_cast<char>(c | 0x20);

        // Its servers' addresses: --publish's, or this machine's public ones.
        std::vector<std::string> v4, v6;
        if (std::string bad; !socketley::dns::parse_publish(m_publish, v4, v6, bad))
        {
            why = "--publish takes IPv4 and IPv6 addresses, not '" + bad + "'";
            return false;
        }
        if (v4.empty() && v6.empty())
            socketley::dns::public_addresses(v4, v6);
        if (v4.empty() && v6.empty())
        {
            why = "--zone: writing the zone " + origin + " needs the address its name servers answer on, and this "
                  "machine has no public one on its interfaces (behind NAT?); give it with --publish";
            return false;
        }

        const std::time_t now = std::time(nullptr);
        std::tm tm{};
        ::gmtime_r(&now, &tm);
        char serial[48];
        std::snprintf(serial, sizeof serial, "%04d%02d%02d01", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
        std::string text = "; The zone " + origin + ", written by socketley for dns runtime '" + std::string(get_name()) +
                           "'. Yours to edit: it is read again within a second.\n"
                           "; The names of runtimes (--domain) need no line here; the runtime adds them itself.\n"
                           "; The registrar is told ns1." + origin + " and ns2." + origin +
                           " as the name servers, with the addresses below as their glue.\n"
                           "$ORIGIN " + origin + ".\n"
                           "$TTL 3600\n"
                           "@    SOA  ns1 hostmaster " + serial + " 1h 15m 1w 300\n"
                           "     NS   ns1\n"
                           "     NS   ns2\n";
        // The zone's own name too, which the entrance answers for as it does the names beneath it.
        for (const char* ns : {"@  ", "ns1", "ns2"})
        {
            char buf[INET6_ADDRSTRLEN];
            for (const auto& a : v4)
                if (::inet_ntop(AF_INET, a.data(), buf, sizeof buf))
                    text += std::string(ns) + "  A    " + buf + "\n";
            for (const auto& a : v6)
                if (::inet_ntop(AF_INET6, a.data(), buf, sizeof buf))
                    text += std::string(ns) + "  AAAA " + buf + "\n";
        }

        std::error_code ec;
        std::filesystem::create_directories(std::filesystem::path(path).parent_path(), ec);
        // Made once: two shards writing at once leave one whole file, and neither is overwritten.
        if (std::string err; !socketley::create_file_once(path, text, &err, 0644))
        {
            why = "--zone: " + path + " could not be written: " + err;
            return false;
        }
    }
    return true;
}

uint16_t dns_instance::effective_port() const
{
    return get_port() ? get_port() : dns_default_port;
}

void dns_instance::listen_addresses(std::vector<std::string>& out) const
{
    out.push_back("udp:" + std::to_string(effective_port()));
    out.push_back("tcp:" + std::to_string(effective_port()));
}

size_t dns_instance::get_connection_count() const
{
    return m_run ? m_run->tcp_count() : 0;
}

std::string dns_instance::config_refusal() const
{
    const auto paths = zone_paths();
    if (paths.empty())
        return "dns: --zone is required: the zone's name, such as example.com, or a zone file\n";
    if (!get_listen_path().empty())
        return "dns: --listen unix: is not served; DNS is asked over UDP and TCP\n";
    if (get_tls())
        return "dns: --tls is not served; DNS over TLS is not part of this runtime\n";
    std::vector<socketley::ip_block> blocks;
    if (std::string bad; !m_transfer.empty() && !socketley::ip_block::parse_list(m_transfer, blocks, bad))
        return "dns: --transfer takes addresses or blocks such as 192.0.2.7 or 2001:db8::/32, not '" + bad + "'\n";
    for (const auto& t : socketley::dns::split_csv(m_notify))
    {
        sockaddr_storage ss{};
        socklen_t len = 0;
        if (!socketley::dns::parse_target(t, ss, len))
            return "dns: --notify takes addresses, with a port if not 53, not '" + t + "'\n";
    }
    std::vector<std::string> v4, v6;
    if (std::string bad; !socketley::dns::parse_publish(m_publish, v4, v6, bad))
        return "dns: --publish takes IPv4 and IPv6 addresses, not '" + bad + "'\n";
    if (std::string why; !ensure_zone_files(why))
        return "dns: " + why + "\n";
    socketley::dns::zone_set zs;
    if (std::string why; !socketley::dns::load_all(paths, zs, why))
        return "dns: " + why + "\n";
    return {};
}

void dns_instance::on_cqe(struct io_uring_cqe*)
{
    // Every completion belongs to a run, which is its own owner; nothing lands here.
}

bool dns_instance::setup(event_loop& loop)
{
    m_graveyard.reap();
    auto run = std::make_unique<dns_run>(*this, loop);
    std::string why;
    if (!run->start(why))
    {
        LOG_ERROR(("dns: " + why).c_str());
        m_graveyard.retire(std::move(run));
        return false;
    }
    m_run = std::move(run);
    return true;
}

void dns_instance::teardown(event_loop&)
{
    m_graveyard.retire(std::move(m_run));
}

void dns_instance::on_loop_turn()
{
    m_graveyard.reap();
}

std::string dns_instance::stats_lines() const
{
    if (!m_run)
        return {};
    const auto& c = m_run->stats();
    std::ostringstream out;
    size_t records = 0, zones = 0;
    if (const auto zs = m_run->zones())
        for (const auto& z : zs->zones)
        {
            ++zones;
            records += z->records;
        }
    out << "zones:" << zones << "\n"
        << "records:" << records << "\n"
        << "udp_queries:" << c.udp_queries << "\n"
        << "tcp_queries:" << c.tcp_queries << "\n"
        << "noerror:" << c.noerror << "\n"
        << "nxdomain:" << c.nxdomain << "\n"
        << "refused:" << c.refused << "\n"
        << "formerr:" << c.formerr << "\n"
        << "notimp:" << c.notimp << "\n"
        << "other_rcode:" << c.other_rcode << "\n"
        << "truncated:" << c.truncated << "\n"
        << "referrals:" << c.referrals << "\n"
        << "dropped:" << c.dropped << "\n"
        << "rrl_dropped:" << c.rrl_dropped << "\n"
        << "rrl_slipped:" << c.rrl_slipped << "\n"
        << "send_failed:" << c.send_failed << "\n"
        << "tcp_conns:" << c.tcp_conns << "\n"
        << "tcp_refused:" << c.tcp_refused << "\n"
        << "tcp_evicted:" << c.tcp_evicted << "\n"
        << "transfers:" << c.transfers << "\n"
        << "transfers_refused:" << c.transfers_refused << "\n"
        << "notify_sent:" << c.notify_sent << "\n"
        << "notify_acked:" << c.notify_acked << "\n"
        << "notify_given_up:" << c.notify_given_up << "\n"
        << "zone_reloads:" << c.reloads << "\n"
        << "zone_reload_failures:" << c.reload_failures << "\n";
    return out.str();
}
