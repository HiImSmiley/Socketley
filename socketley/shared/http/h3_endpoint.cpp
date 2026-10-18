// HTTP/3, RFC 9114 over QUIC (RFC 9000): the UDP socket, the connections on it and everything between a datagram
// and a stream's bytes. QUIC is ngtcp2's, its TLS 1.3 OpenSSL 3.5's through ngtcp2's helper, and HTTP/3 with QPACK
// nghttp3's. What a runtime does with a stream it says through h3::host; this file never looks past that.
//
// Lifted out of the storage runtime, which was the only thing that spoke HTTP/3 and had every line of this inside
// it. An entrance proxy has the same datagrams to read before it can route a stream by its :authority, and copying
// two thousand lines of congestion control and loss recovery per runtime is not a thing to do twice.
#include "h3_endpoint.h"

#if SOCKETLEY_HTTP3

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <unordered_map>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <nghttp3/nghttp3.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "../loop/event_loop.h"
#include "../util/logging.h"
#include "../crypto/tls_context.h"

#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
#endif

namespace socketley::h3
{


namespace
{

constexpr size_t   scid_len        = 18;
// What a stream and the connection may be sent before this side gives the window back; ngtcp2 grows them toward the
// maxima as the round trip asks.
constexpr uint64_t stream_window   = 1u << 20;
constexpr uint64_t conn_window     = 4u << 20;
constexpr uint64_t stream_window_max = 16u << 20;
constexpr uint64_t conn_window_max = 64u << 20;
constexpr uint64_t max_streams     = 128;
constexpr size_t   max_head        = 32 * 1024;
constexpr size_t   max_conns       = 4096;
constexpr size_t   pull_slice      = 64 * 1024;
constexpr size_t   rx_buf          = 64 * 1024;
// Packets written at once and sent in one sendmsg by UDP GSO: as many of ngtcp2's largest (its default
// max_tx_udp_payload_size) as fit the 64 KiB a UDP datagram, and so a GSO send, may carry.
constexpr size_t   max_udp_payload = NGTCP2_MAX_PMTUD_UDP_PAYLOAD_SIZE;
constexpr size_t   gso_burst       = 65000 / max_udp_payload;
constexpr uint64_t idle_timeout_ns = 30ull * NGTCP2_SECONDS;
// A handshake not done by then is dropped, so an Initial from an address that never answers holds nothing for long.
constexpr uint64_t handshake_timeout_ns = 10ull * NGTCP2_SECONDS;
// How long a Retry's token proves the address it was sent to.
constexpr uint64_t retry_token_timeout_ns = 10ull * NGTCP2_SECONDS;

uint64_t now_ns()
{
    timespec ts{};
    ::clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<uint64_t>(ts.tv_nsec);
}

std::string cid_key(const uint8_t* p, size_t n)
{
    return std::string(reinterpret_cast<const char*>(p), n);
}

void rand_cb(uint8_t* dest, size_t len, const ngtcp2_rand_ctx*)
{
    if (RAND_bytes(dest, static_cast<int>(len)) != 1) {}
}

void h3_rand(uint8_t* dest, size_t len)
{
    if (RAND_bytes(dest, static_cast<int>(len)) != 1) {}
}

}   // namespace


struct conn : std::enable_shared_from_this<conn>
{
    endpoint*      ep{nullptr};
    ngtcp2_conn*   q{nullptr};
    nghttp3_conn*  h{nullptr};
    ngtcp2_crypto_ossl_ctx* octx{nullptr};
    SSL*           ssl{nullptr};
    ngtcp2_crypto_conn_ref ref{};
    sockaddr_storage local{}, remote{};
    socklen_t      local_len{0}, remote_len{0};
    std::vector<std::string> cids;
    std::unordered_map<int64_t, std::unique_ptr<stream>> streams;
    ngtcp2_ccerr   err{};
    bool           dead{false};
    bool           dirty{false};
    // The peer as text, for a host that logs it; its address itself stays in `remote`, which the host reads
    // through peer_of() -- parsing it into a runtime's own type is that runtime's business.
    std::string    peer;

    ~conn()
    {
        if (h)
            nghttp3_conn_del(h);
        if (q)
            ngtcp2_conn_del(q);
        if (octx)
            ngtcp2_crypto_ossl_ctx_del(octx);
        if (ssl)
            SSL_free(ssl);
    }
};

struct endpoint
{
    // What used to be the runtime's: who is told about the streams, the ring every operation goes through, the
    // owner a completion is dispatched by, and whether this endpoint has been stopped.
    host*       h{nullptr};
    event_loop* loop{nullptr};
    io_handler* owner{nullptr};
    bool        stopped{false};
    // The Alt-Svc value every answer over TCP carries, which names the port a browser should try.
    std::string alt;
    options     o{};

    int         fd{-1};
    uint16_t    port{0};
    // The certificate's context, watched for a renewed one and asking for a client's when --ca says so, as TCP's;
    // `ctx` is its OpenSSL context, set up for QUIC.
    std::unique_ptr<tls_context> tls;
    SSL_CTX*    ctx{nullptr};
    uint8_t     secret[32]{};
    io_request  rd{};
    bool        rd_pending{false};
    msghdr      msg{};
    iovec       iov{};
    sockaddr_storage src{};
    alignas(cmsghdr) char cbuf[256]{};
    std::vector<uint8_t> rbuf = std::vector<uint8_t>(rx_buf);
    std::vector<uint8_t> txbuf = std::vector<uint8_t>(gso_burst * max_udp_payload);
    std::unordered_map<std::string, std::shared_ptr<conn>> by_cid;
    std::vector<std::shared_ptr<conn>> conns;
    // One timeout for every connection's earliest expiry; two timespecs, so one waiting to be submitted is never
    // written over by the next.
    io_request  tm{};
    __kernel_timespec ts[2]{};
    int         ts_at{0};
    bool        tm_armed{false};
    uint64_t    tm_deadline{0};
    std::vector<std::weak_ptr<conn>> dirty;
    // Handshakes under way past which a new client is asked to prove its address with a Retry first (RFC 9000
    // 8.1.2), so datagrams with forged sources cannot fill the table: SOCKETLEY_STORAGE_HTTP3_RETRY_AFTER, 0 always.
    size_t      retry_after{64};
    // The congestion controller, SOCKETLEY_STORAGE_HTTP3_CC=bbr|cubic|reno. BBR by default: it paces by the path's
    // measured rate and round trip rather than backing off at every loss, so a link that loses a packet in a hundred
    // at 50 ms -- Wi-Fi, mobile -- carried a download ten to twenty times faster than with CUBIC, and as fast without
    // loss.
    ngtcp2_cc_algo cc{NGTCP2_CC_ALGO_BBR};
    // Shards share the UDP port, and the kernel picks one by the client's address: a client that moves may reach
    // another. The shard is the first byte of every connection ID this side gives, and a packet for another shard's
    // is handed to it through that shard's inbox, a datagram socket of its own, which answers it from the same port.
    uint32_t    shard{0}, shards{1};
    int         inbox{-1};
    io_request  in_rd{};
    bool        in_pending{false};
    std::vector<uint8_t> inbuf = std::vector<uint8_t>(rx_buf + 64);
    // Read with the sender's credentials, which the kernel vouches for: only this user's processes -- the shards --
    // are listened to, since an abstract name is anyone's to send to.
    msghdr      in_msg{};
    iovec       in_iov{};
    alignas(cmsghdr) char in_cbuf[CMSG_SPACE(sizeof(ucred))]{};
    // Every step between a datagram and a stream's bytes; the host is reached only through `h`.
    bool open(uint16_t port, uint16_t advertise, uint32_t shard, uint32_t shards, const std::string& cert,
                          const std::string& key, const std::string& ca);
    void arm_inbox();
    void forward(uint32_t owner, const sockaddr_storage& local, socklen_t local_len,
                             const sockaddr_storage& remote, socklen_t remote_len, const uint8_t* data, size_t len);
    void arm_read();
    bool owns(io_request* req) const;
    void cqe(io_request* req, int res);
    void datagram(size_t res);
    void packet(const sockaddr_storage& local, socklen_t local_len, const sockaddr_storage& remote,
                            socklen_t remote_len, const uint8_t* data, size_t len, bool forwarded);
    void retry(const ngtcp2_pkt_hd& hd, const sockaddr_storage& local, socklen_t local_len,
                          const sockaddr_storage& remote, socklen_t remote_len);
    std::shared_ptr<conn> new_conn(const ngtcp2_pkt_hd& hd, const ngtcp2_cid* odcid,
                                                  const sockaddr_storage& local, socklen_t local_len,
                                                  const sockaddr_storage& remote, socklen_t remote_len);
    bool app_ready(conn& hc);

    void stream_closed(conn& hc, int64_t sid);
    void mark_dirty(const std::shared_ptr<conn>& hc);
    void dirty_raw(conn& hc);
    void flush_dirty();
    void send(const sockaddr_storage& local, socklen_t, const sockaddr_storage& remote, socklen_t remote_len,
                          const uint8_t* data, size_t len, size_t gso);
    void write(const std::shared_ptr<conn>& hc);
    void arm_timer(uint64_t soonest);
    void expire();
    void close(const std::shared_ptr<conn>& hc);
    void drop(const std::shared_ptr<conn>& hc);
    size_t open_conns() const;
    void stop();
    // A stream the peer opened, and its head once complete.
    void begin(conn& hc, int64_t sid);
    void deliver_head(stream& st, bool fin);
};


namespace
{

int alpn_h3(SSL*, const unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned int inlen, void*)
{
    for (unsigned int p = 0; p < inlen;)
    {
        const unsigned int n = in[p];
        if (n == 0 || p + 1 + n > inlen)
            break;
        if (n == 2 && in[p + 1] == 'h' && in[p + 2] == '3')
        {
            *out = in + p + 1;
            *outlen = 2;
            return SSL_TLSEXT_ERR_OK;
        }
        p += 1 + n;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

// Bytes QUIC handed over that no phase will take: the connection's window gets them back, as it does by itself only
// for what it never handed over.
void give_back_raw(conn* hc, uint64_t n)
{
    if (n && hc && hc->q && !hc->dead)
        ngtcp2_conn_extend_max_offset(hc->q, n);
}

void give_back_raw(conn* hc, uint64_t n);

void drop_rx(stream& st)
{
    uint64_t left = 0;
    for (const auto& piece : st.rxq)
        left += piece.size();
    left -= std::min<uint64_t>(left, st.rx_head);
    st.rxq.clear();
    st.rx_head = 0;
    give_back_raw(st.owner, left);
}

// The inbox of shard `n` of the runtime on `port`: an abstract unix name, gone with the socket.
socklen_t inbox_addr(uint16_t port, uint32_t n, sockaddr_un& out)
{
    out = sockaddr_un{};
    out.sun_family = AF_UNIX;
    const std::string name = "socketley-h3/" + std::to_string(port) + "/" + std::to_string(n);
    std::memcpy(out.sun_path + 1, name.data(), name.size());
    return static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + name.size());
}

// An address ngtcp2 names, as the sockaddr_storage this side keeps.
void path_addr(const ngtcp2_addr& a, sockaddr_storage& out, socklen_t& len)
{
    len = static_cast<socklen_t>(std::min<size_t>(a.addrlen, sizeof out));
    std::memcpy(&out, a.addr, len);
}

std::string peer_text(const sockaddr_storage& remote)
{
    const auto* a = reinterpret_cast<const sockaddr_in*>(&remote);
    char host[INET_ADDRSTRLEN] = {};
    ::inet_ntop(AF_INET, &a->sin_addr, host, sizeof host);
    return std::string(host) + ":" + std::to_string(ntohs(a->sin_port));
}

ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref* ref)
{
    return static_cast<conn*>(ref->user_data)->q;
}

}   // namespace

// ─── The endpoint ───────────────────────────────────────────────────────────


bool endpoint::open(uint16_t port, uint16_t advertise, uint32_t shard, uint32_t shards, const std::string& cert,
                          const std::string& key, const std::string& ca)
{
    const bool reuseport = shards > 1;
    if (ngtcp2_crypto_ossl_init() != 0)
        return false;
    tls = std::make_unique<tls_context>();
    if (!tls->init_server(cert, key, ca))
    {
        LOG_WARN("storage: HTTP/3 not offered -- the certificate or key could not be loaded for QUIC");
        return false;
    }
    ctx = tls->native();
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_options(ctx, (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) | SSL_OP_SINGLE_ECDH_USE |
                                     SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_NO_ANTI_REPLAY);
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_alpn_select_cb(ctx, alpn_h3, nullptr);
    // Every packet is sealed on its own, so the cipher is most of a transfer's CPU: AES-128-GCM, a quarter fewer
    // rounds than AES-256 and what browsers ask for first, is chosen when the client offers it.
    if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256") != 1)
        ERR_clear_error();
    if (RAND_bytes(secret, sizeof secret) != 1)
        return false;

    const int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return false;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (reuseport)
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
    // The address a datagram came to, so the answer leaves from it; several datagrams a read, and the buffers a
    // stream of them needs.
    setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof one);
    setsockopt(fd, IPPROTO_UDP, UDP_GRO, &one, sizeof one);
    int buf = 4 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof buf);
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof buf);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = INADDR_ANY;
    a.sin_port = htons(port);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) < 0)
    {
        LOG_WARN(("storage: HTTP/3 not offered -- UDP port " + std::to_string(port) + " could not be bound: " +
                  std::strerror(errno)).c_str());
        ::close(fd);
        return false;
    }
    this->fd = fd;
    this->port = port;
    if (const char* cc = std::getenv("SOCKETLEY_STORAGE_HTTP3_CC"); cc && *cc)
    {
        const std::string_view v(cc);
        if (v == "bbr")
            this->cc = NGTCP2_CC_ALGO_BBR;
        else if (v == "reno")
            this->cc = NGTCP2_CC_ALGO_RENO;
        else if (v == "cubic")
            this->cc = NGTCP2_CC_ALGO_CUBIC;
        else
            LOG_WARN("storage: SOCKETLEY_STORAGE_HTTP3_CC is none of bbr, cubic, reno; bbr is used");
    }
    if (const char* ra = std::getenv("SOCKETLEY_STORAGE_HTTP3_RETRY_AFTER"); ra && *ra)
    {
        size_t v = 0;
        const auto [end, ec] = std::from_chars(ra, ra + std::strlen(ra), v);
        if (ec == std::errc{} && *end == '\0')
            this->retry_after = v;
    }
    this->shard = shard;
    this->shards = std::max<uint32_t>(shards, 1);
    if (shards > 1)
    {
        // Without its inbox a shard still serves; only a client that moved to it from another is lost.
        sockaddr_un un{};
        const socklen_t ul = inbox_addr(port, shard, un);
        inbox = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (inbox >= 0 && ::bind(inbox, reinterpret_cast<sockaddr*>(&un), ul) != 0)
        {
            LOG_WARN("storage: HTTP/3 shard inbox could not be bound; a client that changes address may be lost");
            ::close(inbox);
            this->inbox = -1;
        }
        else if (inbox >= 0)
        {
            int sz = 4 << 20, on = 1;
            setsockopt(this->inbox, SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
            setsockopt(this->inbox, SOL_SOCKET, SO_PASSCRED, &on, sizeof on);
        }
    }
    this->rd.owner = owner;
    this->tm.owner = owner;
    this->in_rd.owner = owner;
    // Behind a proxy the port a browser reaches may not be this one; 0 offers HTTP/3 to no one who was not told.
    if (advertise)
        this->alt = "h3=\":" + std::to_string(advertise) + "\"; ma=86400";
    arm_read();
    arm_inbox();
    return true;
}

void endpoint::arm_inbox()
{
    if (in_pending || inbox < 0 || stopped)
        return;
    in_rd = io_request{};
    in_rd.owner = owner;
    in_iov.iov_base = inbuf.data();
    in_iov.iov_len = inbuf.size();
    in_msg = msghdr{};
    in_msg.msg_iov = &in_iov;
    in_msg.msg_iovlen = 1;
    in_msg.msg_control = in_cbuf;
    in_msg.msg_controllen = sizeof in_cbuf;
    in_pending = loop->submit_recvmsg(inbox, &in_msg, &in_rd);
}

// A packet for a connection another shard holds, with the addresses it came by, to that shard's inbox.
void endpoint::forward(uint32_t owner, const sockaddr_storage& local, socklen_t local_len,
                             const sockaddr_storage& remote, socklen_t remote_len, const uint8_t* data, size_t len)
{
    if (inbox < 0 || local_len > 255 || remote_len > 255)
        return;
    std::vector<uint8_t> msg;
    msg.reserve(2 + local_len + remote_len + len);
    msg.push_back(static_cast<uint8_t>(remote_len));
    msg.insert(msg.end(), reinterpret_cast<const uint8_t*>(&remote), reinterpret_cast<const uint8_t*>(&remote) + remote_len);
    msg.push_back(static_cast<uint8_t>(local_len));
    msg.insert(msg.end(), reinterpret_cast<const uint8_t*>(&local), reinterpret_cast<const uint8_t*>(&local) + local_len);
    msg.insert(msg.end(), data, data + len);
    sockaddr_un un{};
    const socklen_t ul = inbox_addr(port, owner, un);
    // A shard that is not there, or whose inbox is full, loses the packet as the path would; QUIC sends it again.
    if (::sendto(inbox, msg.data(), msg.size(), MSG_DONTWAIT, reinterpret_cast<sockaddr*>(&un), ul) > 0)
        h->count(event::forwarded);
}

void endpoint::arm_read()
{
    if (rd_pending || fd < 0 || stopped)
        return;
    iov.iov_base = rbuf.data();
    iov.iov_len = rbuf.size();
    msg = msghdr{};
    msg.msg_name = &src;
    msg.msg_namelen = sizeof src;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof cbuf;
    rd = io_request{};
    rd.owner = owner;
    rd_pending = loop->submit_recvmsg(fd, &msg, &rd);
}

bool endpoint::owns(io_request* req) const
{
    return req == &rd || req == &tm || req == &in_rd;
}

void endpoint::cqe(io_request* req, int res)
{
    if (req == &in_rd)
    {
        in_pending = false;
        if (stopped)
            return;
        // Another shard's packet: the addresses it came by, then the datagram, taken as if it had come here --
        // from a process of this user's only, and whole.
        bool mine = false;
        for (cmsghdr* cm = CMSG_FIRSTHDR(&in_msg); cm; cm = CMSG_NXTHDR(&in_msg, cm))
            if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_CREDENTIALS)
            {
                ucred cr{};
                std::memcpy(&cr, CMSG_DATA(cm), sizeof cr);
                mine = cr.uid == ::geteuid();
            }
        const size_t n = res > 0 && mine && !(in_msg.msg_flags & MSG_TRUNC) ? static_cast<size_t>(res) : 0;
        const uint8_t* p = inbuf.data();
        if (n > 2 && p[0] <= sizeof(sockaddr_storage) && 1u + p[0] + 1u < n)
        {
            sockaddr_storage remote{}, local{};
            const socklen_t rl = p[0];
            std::memcpy(&remote, p + 1, rl);
            const socklen_t ll = p[1 + rl];
            if (ll <= sizeof(sockaddr_storage) && 2u + rl + ll <= n)
            {
                std::memcpy(&local, p + 2 + rl, ll);
                packet(local, ll, remote, rl, p + 2 + rl + ll, n - 2 - rl - ll, true);
                flush_dirty();
            }
        }
        arm_inbox();
        return;
    }
    if (req == &tm)
    {
        if (res == -ECANCELED)
            return;
        tm_armed = false;
        if (!stopped)
            expire();
        return;
    }
    rd_pending = false;
    if (stopped)
        return;
    if (res > 0)
        datagram(static_cast<size_t>(res));
    // What else has come is read now, without the ring: a burst of a client's packets is taken in one turn, and
    // what they call for -- acknowledgements, answers -- leaves in one write per connection rather than one each.
    for (int more = 0; res > 0 && more < 256; ++more)
    {
        iov.iov_base = rbuf.data();
        iov.iov_len = rbuf.size();
        msg.msg_name = &src;
        msg.msg_namelen = sizeof src;
        msg.msg_controllen = sizeof cbuf;
        msg.msg_flags = 0;
        const ssize_t n = ::recvmsg(fd, &msg, MSG_DONTWAIT);
        if (n <= 0)
            break;
        datagram(static_cast<size_t>(n));
    }
    flush_dirty();
    arm_read();
}

// A datagram msg holds, of `res` bytes: the local address from IP_PKTINFO, and the size each packet was when GRO
// joined several.
void endpoint::datagram(size_t res)
{
    sockaddr_storage local{};
    socklen_t local_len = sizeof(sockaddr_in);
    auto* l4 = reinterpret_cast<sockaddr_in*>(&local);
    l4->sin_family = AF_INET;
    l4->sin_port = htons(port);
    size_t seg = res;
    for (cmsghdr* cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm))
    {
        if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_PKTINFO)
        {
            in_pktinfo pi{};
            std::memcpy(&pi, CMSG_DATA(cm), sizeof pi);
            l4->sin_addr = pi.ipi_addr;
        }
        else if (cm->cmsg_level == IPPROTO_UDP && cm->cmsg_type == UDP_GRO)
        {
            int g = 0;
            std::memcpy(&g, CMSG_DATA(cm), sizeof g);
            if (g > 0)
                seg = static_cast<size_t>(g);
        }
    }
    for (size_t off = 0; off < res; off += seg)
        packet(local, local_len, src, msg.msg_namelen, rbuf.data() + off, std::min(seg, res - off), false);
}

// ─── A datagram in ──────────────────────────────────────────────────────────

void endpoint::packet(const sockaddr_storage& local, socklen_t local_len, const sockaddr_storage& remote,
                            socklen_t remote_len, const uint8_t* data, size_t len, bool forwarded)
{
    ngtcp2_version_cid vc{};
    const int rv = ngtcp2_pkt_decode_version_cid(&vc, data, len, scid_len);
    if (rv == NGTCP2_ERR_VERSION_NEGOTIATION)
    {
        // A version this side does not speak: the ones it does, so the client can choose again.
        uint8_t out[256];
        uint32_t versions[] = {NGTCP2_PROTO_VER_V1};
        uint8_t unused = 0;
        h3_rand(&unused, 1);
        const ngtcp2_ssize n = ngtcp2_pkt_write_version_negotiation(out, sizeof out, unused, vc.scid, vc.scidlen,
                                                                     vc.dcid, vc.dcidlen, versions, 1);
        if (n > 0)
            send(local, local_len, remote, remote_len, out, static_cast<size_t>(n), 0);
        return;
    }
    if (rv != 0)
        return;
    std::shared_ptr<conn> hc;
    if (auto it = by_cid.find(cid_key(vc.dcid, vc.dcidlen)); it != by_cid.end())
        hc = it->second;
    if (!hc && !forwarded && shards > 1 && vc.dcidlen == scid_len)
    {
        // A connection ID of another shard's, on anything but a client's first packet: that shard's connection.
        const bool initial = (data[0] & 0x80) && ((data[0] & 0x30) >> 4) == 0;
        const uint32_t owner = vc.dcid[0];
        if (!initial && owner < shards && owner != shard)
        {
            forward(owner, local, local_len, remote, remote_len, data, len);
            return;
        }
    }
    if (!hc)
    {
        ngtcp2_pkt_hd hd{};
        if (ngtcp2_accept(&hd, data, len) != 0 || conns.size() >= max_conns)
            return;
        // A client that has not proven its address is sent a Retry while many handshakes are under way; one that
        // comes back with the token is let in as the client the first Initial named.
        ngtcp2_cid odcid{};
        bool retried = false;
        if (hd.type == NGTCP2_PKT_INITIAL && hd.tokenlen > 0 && hd.token[0] == NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY2)
        {
            if (ngtcp2_crypto_verify_retry_token2(&odcid, hd.token, hd.tokenlen, secret, sizeof secret,
                                                  hd.version, reinterpret_cast<const sockaddr*>(&remote), remote_len,
                                                  &hd.dcid, retry_token_timeout_ns, now_ns()) != 0)
            {
                // A token this side did not give, or one too old: the client is told so and starts again.
                uint8_t out[256];
                const ngtcp2_ssize n = ngtcp2_crypto_write_connection_close(out, sizeof out, hd.version, &hd.scid,
                                                                            &hd.dcid, NGTCP2_INVALID_TOKEN, nullptr, 0);
                if (n > 0)
                    send(local, local_len, remote, remote_len, out, static_cast<size_t>(n), 0);
                return;
            }
            retried = true;
        }
        else if (hd.type == NGTCP2_PKT_INITIAL)
        {
            // Counted only as far as the bound, so a flood of handshakes, the case the bound is for, stops the scan early.
            size_t shaking = 0;
            for (const auto& other : conns)
                if ((shaking += !other->dead && !ngtcp2_conn_get_handshake_completed(other->q)) >= retry_after)
                    break;
            if (shaking >= retry_after)
            {
                retry(hd, local, local_len, remote, remote_len);
                return;
            }
        }
        hc = new_conn(hd, retried ? &odcid : nullptr, local, local_len, remote, remote_len);
        if (!hc)
            return;
    }
    if (hc->dead)
        return;
    ngtcp2_path path{};
    path.local.addr = reinterpret_cast<sockaddr*>(const_cast<sockaddr_storage*>(&local));
    path.local.addrlen = local_len;
    path.remote.addr = reinterpret_cast<sockaddr*>(const_cast<sockaddr_storage*>(&remote));
    path.remote.addrlen = remote_len;
    ngtcp2_pkt_info pi{};
    const int r = ngtcp2_conn_read_pkt(hc->q, &path, &pi, data, len, now_ns());
    if (r != 0)
    {
        if (r == NGTCP2_ERR_DRAINING || r == NGTCP2_ERR_DROP_CONN)
        {
            drop(hc);
            return;
        }
        if (r == NGTCP2_ERR_CRYPTO)
            ngtcp2_ccerr_set_tls_alert(&hc->err, ngtcp2_conn_get_tls_alert(hc->q), nullptr, 0);
        else if (hc->err.error_code == 0)
            ngtcp2_ccerr_set_liberr(&hc->err, r, nullptr, 0);
        close(hc);
        return;
    }
    // The client moved -- a NAT that rebound it, or another network: once ngtcp2 takes the new path, what is sent goes
    // there, and the requests that follow are judged by the address they now come from.
    const ngtcp2_path* now = ngtcp2_conn_get_path(hc->q);
    if (now->remote.addrlen != hc->remote_len || std::memcmp(now->remote.addr, &hc->remote, hc->remote_len) != 0 ||
        now->local.addrlen != hc->local_len || std::memcmp(now->local.addr, &hc->local, hc->local_len) != 0)
    {
        path_addr(now->remote, hc->remote, hc->remote_len);
        path_addr(now->local, hc->local, hc->local_len);
        hc->peer = peer_text(hc->remote);
    }
    mark_dirty(hc);
}

void endpoint::retry(const ngtcp2_pkt_hd& hd, const sockaddr_storage& local, socklen_t local_len,
                          const sockaddr_storage& remote, socklen_t remote_len)
{
    ngtcp2_cid scid{};
    scid.datalen = scid_len;
    h3_rand(scid.data, scid.datalen);
    uint8_t token[NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN2];
    const ngtcp2_ssize tl = ngtcp2_crypto_generate_retry_token2(token, secret, sizeof secret, hd.version,
                                                                reinterpret_cast<const sockaddr*>(&remote), remote_len,
                                                                &scid, &hd.dcid, now_ns());
    if (tl < 0)
        return;
    uint8_t out[1200];
    const ngtcp2_ssize n = ngtcp2_crypto_write_retry(out, sizeof out, hd.version, &hd.scid, &scid, &hd.dcid, token,
                                                     static_cast<size_t>(tl));
    if (n > 0)
    {
        send(local, local_len, remote, remote_len, out, static_cast<size_t>(n), 0);
        h->count(event::retry_sent);
    }
}

std::shared_ptr<conn> endpoint::new_conn(const ngtcp2_pkt_hd& hd, const ngtcp2_cid* odcid,
                                                  const sockaddr_storage& local, socklen_t local_len,
                                                  const sockaddr_storage& remote, socklen_t remote_len)
{
    auto hc = std::make_shared<conn>();
    hc->ep = this;
    hc->local = local;
    hc->local_len = local_len;
    hc->remote = remote;
    hc->remote_len = remote_len;
    hc->ref.get_conn = get_conn;
    hc->ref.user_data = hc.get();
    hc->peer = peer_text(remote);

    ngtcp2_cid scid{};
    scid.datalen = scid_len;
    h3_rand(scid.data, scid.datalen);
    scid.data[0] = static_cast<uint8_t>(shard);

    static const ngtcp2_callbacks cb = []
    {
        ngtcp2_callbacks c{};
        c.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
        c.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
        c.encrypt = ngtcp2_crypto_encrypt_cb;
        c.decrypt = ngtcp2_crypto_decrypt_cb;
        c.hp_mask = ngtcp2_crypto_hp_mask_cb;
        c.update_key = ngtcp2_crypto_update_key_cb;
        c.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        c.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        c.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
        c.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
        c.rand = rand_cb;
        c.recv_stream_data = [](ngtcp2_conn*, uint32_t flags, int64_t sid, uint64_t, const uint8_t* data, size_t len,
                                void* ud, void*) -> int
        {
            auto* hc = static_cast<conn*>(ud);
            if (!hc->h)
                return 0;
            const nghttp3_ssize n = nghttp3_conn_read_stream2(hc->h, sid, data, len, flags & NGTCP2_STREAM_DATA_FLAG_FIN,
                                                              now_ns());
            if (n < 0)
            {
                ngtcp2_ccerr_set_application_error(&hc->err, nghttp3_err_infer_quic_app_error_code(static_cast<int>(n)),
                                                   nullptr, 0);
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
            ngtcp2_conn_extend_max_stream_offset(hc->q, sid, static_cast<uint64_t>(n));
            ngtcp2_conn_extend_max_offset(hc->q, static_cast<uint64_t>(n));
            return 0;
        };
        c.acked_stream_data_offset = [](ngtcp2_conn*, int64_t sid, uint64_t, uint64_t len, void* ud, void*) -> int
        {
            auto* hc = static_cast<conn*>(ud);
            if (hc->h && nghttp3_conn_add_ack_offset(hc->h, sid, len) != 0)
                return NGTCP2_ERR_CALLBACK_FAILURE;
            return 0;
        };
        c.stream_close2 = [](ngtcp2_conn*, uint32_t flags, int64_t sid, uint64_t rx, uint64_t tx, void* ud, void*) -> int
        {
            auto* hc = static_cast<conn*>(ud);
            if (!hc->h)
                return 0;
            uint32_t f = NGHTTP3_STREAM_CLOSE_FLAG_NONE;
            if (flags & NGTCP2_STREAM_CLOSE2_FLAG_RX_APP_ERROR_CODE_SET)
                f |= NGHTTP3_STREAM_CLOSE_FLAG_RX_APP_ERROR_CODE_SET;
            if (flags & NGTCP2_STREAM_CLOSE2_FLAG_TX_APP_ERROR_CODE_SET)
                f |= NGHTTP3_STREAM_CLOSE_FLAG_TX_APP_ERROR_CODE_SET;
            const int rv = nghttp3_conn_close_stream2(hc->h, f, sid, rx, tx);
            return rv == 0 || rv == NGHTTP3_ERR_STREAM_NOT_FOUND ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
        };
        c.stream_reset = [](ngtcp2_conn*, int64_t sid, uint64_t, uint64_t, void* ud, void*) -> int
        {
            auto* hc = static_cast<conn*>(ud);
            return !hc->h || nghttp3_conn_shutdown_stream_read(hc->h, sid) == 0 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
        };
        c.stream_stop_sending = [](ngtcp2_conn*, int64_t sid, uint64_t, void* ud, void*) -> int
        {
            auto* hc = static_cast<conn*>(ud);
            return !hc->h || nghttp3_conn_shutdown_stream_read(hc->h, sid) == 0 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
        };
        c.extend_max_remote_streams_bidi = [](ngtcp2_conn*, uint64_t max, void* ud) -> int
        {
            auto* hc = static_cast<conn*>(ud);
            if (hc->h)
                nghttp3_conn_set_max_client_streams_bidi(hc->h, max);
            return 0;
        };
        c.extend_max_stream_data = [](ngtcp2_conn*, int64_t sid, uint64_t, void* ud, void*) -> int
        {
            auto* hc = static_cast<conn*>(ud);
            return !hc->h || nghttp3_conn_unblock_stream(hc->h, sid) == 0 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
        };
        c.get_new_connection_id2 = [](ngtcp2_conn*, ngtcp2_cid* cid, ngtcp2_stateless_reset_token* token, size_t cidlen,
                                      void* ud) -> int
        {
            auto* hc = static_cast<conn*>(ud);
            h3_rand(cid->data, cidlen);
            cid->datalen = cidlen;
            endpoint& ep = *hc->ep;
            if (cidlen > 0)
                cid->data[0] = static_cast<uint8_t>(ep.shard);
            if (ngtcp2_crypto_generate_stateless_reset_token(token->data, ep.secret, sizeof ep.secret, cid) != 0)
                return NGTCP2_ERR_CALLBACK_FAILURE;
            const std::string k = cid_key(cid->data, cid->datalen);
            hc->cids.push_back(k);
            ep.by_cid[k] = hc->shared_from_this();
            return 0;
        };
        c.remove_connection_id = [](ngtcp2_conn*, const ngtcp2_cid* cid, void* ud) -> int
        {
            auto* hc = static_cast<conn*>(ud);
            const std::string k = cid_key(cid->data, cid->datalen);
            hc->ep->by_cid.erase(k);
            std::erase(hc->cids, k);
            return 0;
        };
        c.recv_tx_key = [](ngtcp2_conn*, ngtcp2_encryption_level level, void* ud) -> int
        {
            if (level != NGTCP2_ENCRYPTION_LEVEL_1RTT)
                return 0;
            auto* hc = static_cast<conn*>(ud);
            return hc->ep->app_ready(*hc) ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
        };
        return c;
    }();

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = now_ns();
    settings.max_window = conn_window_max;
    settings.max_stream_window = stream_window_max;
    settings.cc_algo = cc;
    settings.handshake_timeout = handshake_timeout_ns;
    if (odcid)
    {
        // The address is proven: the amplification limit no longer holds this connection back.
        settings.token = hd.token;
        settings.tokenlen = hd.tokenlen;
        settings.token_type = NGTCP2_TOKEN_TYPE_RETRY;
    }
    uint32_t pn = 0;
    h3_rand(reinterpret_cast<uint8_t*>(&pn), sizeof pn);
    settings.initial_pkt_num = pn & 0x7fffffff;

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_stream_data_bidi_local = stream_window;
    params.initial_max_stream_data_bidi_remote = stream_window;
    params.initial_max_stream_data_uni = stream_window;
    params.initial_max_data = conn_window;
    params.initial_max_streams_bidi = max_streams;
    params.initial_max_streams_uni = 3;
    params.max_idle_timeout = idle_timeout_ns;
    params.active_connection_id_limit = 7;
    params.stateless_reset_token_present = 1;
    params.original_dcid = odcid ? *odcid : hd.dcid;
    params.original_dcid_present = 1;
    if (odcid)
    {
        params.retry_scid = hd.dcid;
        params.retry_scid_present = 1;
    }
    if (ngtcp2_crypto_generate_stateless_reset_token(params.stateless_reset_token, secret, sizeof secret,
                                                     &scid) != 0)
        return nullptr;

    ngtcp2_path path{};
    path.local.addr = reinterpret_cast<sockaddr*>(&hc->local);
    path.local.addrlen = hc->local_len;
    path.remote.addr = reinterpret_cast<sockaddr*>(&hc->remote);
    path.remote.addrlen = hc->remote_len;
    if (ngtcp2_conn_server_new(&hc->q, &hd.scid, &scid, &path, hd.version, &cb, &settings, &params, nullptr, hc.get()) != 0)
        return nullptr;

    hc->ssl = SSL_new(ctx);
    if (!hc->ssl || ngtcp2_crypto_ossl_ctx_new(&hc->octx, nullptr) != 0)
        return nullptr;
    ngtcp2_crypto_ossl_ctx_set_ssl(hc->octx, hc->ssl);
    if (ngtcp2_crypto_ossl_configure_server_session(hc->ssl) != 0)
        return nullptr;
    SSL_set_app_data(hc->ssl, &hc->ref);
    SSL_set_accept_state(hc->ssl);
    ngtcp2_conn_set_tls_native_handle(hc->q, hc->octx);

    for (const ngtcp2_cid* id : std::initializer_list<const ngtcp2_cid*>{&hd.dcid, &scid})
    {
        const std::string k = cid_key(id->data, id->datalen);
        hc->cids.push_back(k);
        by_cid[k] = hc;
    }
    conns.push_back(hc);
    h->count(event::conn_opened);
    return hc;
}

// The handshake's keys for application data are in: HTTP/3's control and QPACK streams are opened.
bool endpoint::app_ready(conn& hc)
{
    if (hc.h)
        return true;
    if (ngtcp2_conn_get_streams_uni_left2(hc.q) < 3)
        return false;
    static const nghttp3_callbacks cb = []
    {
        nghttp3_callbacks c{};
        c.rand = h3_rand;
        // nghttp3's per-stream user data is the stream itself; a runtime's own object hangs off its `user`, and
        // this side never follows that pointer.
        c.acked_stream_data = [](nghttp3_conn*, int64_t, uint64_t len, void*, void* sud) -> int
        {
            if (auto* st = static_cast<stream*>(sud))
                acked(*st, len);
            return 0;
        };
        c.stream_close = [](nghttp3_conn*, int64_t sid, uint64_t, void* ud, void*) -> int
        {
            auto* hc = static_cast<conn*>(ud);
            // A request stream done is one more the client may open: ngtcp2 does not give it back by itself.
            if (ngtcp2_is_bidi_stream(sid) && !ngtcp2_conn_is_local_stream(hc->q, sid))
                ngtcp2_conn_extend_max_streams_bidi(hc->q, 1);
            hc->ep->stream_closed(*hc, sid);
            return 0;
        };
        c.recv_data = [](nghttp3_conn*, int64_t, const uint8_t* data, size_t len, void* ud, void* sud) -> int
        {
            if (auto* st = static_cast<stream*>(sud))
                pull(*st, std::string_view(reinterpret_cast<const char*>(data), len));
            else
                give_back_raw(static_cast<conn*>(ud), len);
            return 0;
        };
        c.deferred_consume = [](nghttp3_conn*, int64_t sid, size_t n, void* ud, void*) -> int
        {
            auto* hc = static_cast<conn*>(ud);
            ngtcp2_conn_extend_max_stream_offset(hc->q, sid, n);
            ngtcp2_conn_extend_max_offset(hc->q, n);
            return 0;
        };
        c.begin_headers = [](nghttp3_conn*, int64_t sid, void* ud, void*) -> int
        {
            auto* hc = static_cast<conn*>(ud);
            hc->ep->begin(*hc, sid);
            return 0;
        };
        c.recv_header = [](nghttp3_conn*, int64_t, int32_t, nghttp3_rcbuf* name, nghttp3_rcbuf* value, uint8_t, void*,
                           void* sud) -> int
        {
            auto* st = static_cast<stream*>(sud);
            if (!st)
                return 0;
            const nghttp3_vec n = nghttp3_rcbuf_get_buf(name), v = nghttp3_rcbuf_get_buf(value);
            auto& f = st->fields;
            f.emplace_back(std::string(reinterpret_cast<const char*>(n.base), n.len),
                           std::string(reinterpret_cast<const char*>(v.base), v.len));
            return 0;
        };
        c.end_headers = [](nghttp3_conn*, int64_t, int fin, void* ud, void* sud) -> int
        {
            if (auto* st = static_cast<stream*>(sud))
                static_cast<conn*>(ud)->ep->deliver_head(*st, fin != 0);
            return 0;
        };
        c.end_stream = [](nghttp3_conn*, int64_t, void*, void* sud) -> int
        {
            if (auto* st = static_cast<stream*>(sud))
            {
                st->remote_closed = true;
                pull(*st, {});
            }
            return 0;
        };
        c.stop_sending = [](nghttp3_conn*, int64_t sid, uint64_t code, void* ud, void*) -> int
        {
            auto* hc = static_cast<conn*>(ud);
            ngtcp2_conn_shutdown_stream_read(hc->q, 0, sid, code);
            return 0;
        };
        c.reset_stream = [](nghttp3_conn*, int64_t sid, uint64_t code, void* ud, void*) -> int
        {
            auto* hc = static_cast<conn*>(ud);
            ngtcp2_conn_shutdown_stream_write(hc->q, 0, sid, code);
            return 0;
        };
        return c;
    }();
    nghttp3_settings settings;
    nghttp3_settings_default(&settings);
    settings.qpack_max_dtable_capacity = 4096;
    settings.qpack_blocked_streams = 100;
    settings.max_field_section_size = 64 * 1024;
    if (nghttp3_conn_server_new(&hc.h, &cb, &settings, nghttp3_mem_default(), &hc) != 0)
        return false;
    nghttp3_conn_set_max_client_streams_bidi(hc.h, ngtcp2_conn_get_local_transport_params2(hc.q)->initial_max_streams_bidi);
    int64_t ctrl = 0, enc = 0, dec = 0;
    if (ngtcp2_conn_open_uni_stream(hc.q, &ctrl, nullptr) != 0 || nghttp3_conn_bind_control_stream(hc.h, ctrl) != 0 ||
        ngtcp2_conn_open_uni_stream(hc.q, &enc, nullptr) != 0 || ngtcp2_conn_open_uni_stream(hc.q, &dec, nullptr) != 0 ||
        nghttp3_conn_bind_qpack_streams(hc.h, enc, dec) != 0)
        return false;
    return true;
}

// ─── A stream's request in ──────────────────────────────────────────────────

void acked(stream& st, uint64_t len)
{
    // Acknowledged bytes are let go from the front; a chunk goes when the whole of it is.
    st.tx_acked_front += len;
    while (!st.tx.empty() && st.tx_given_chunks > 0 && st.tx_acked_front >= st.tx.front().size())
    {
        st.tx_acked_front -= st.tx.front().size();
        st.tx.pop_front();
        --st.tx_given_chunks;
    }
}

void endpoint::stream_closed(conn& hc, int64_t sid)
{
    auto it = hc.streams.find(sid);
    if (it == hc.streams.end())
        return;
    stream& st = *it->second;
    drop_rx(st);
    st.gone = true;
    h->stream_gone(st);
    hc.streams.erase(it);
}



// ─── Packets out, timers, ends ──────────────────────────────────────────────

void endpoint::mark_dirty(const std::shared_ptr<conn>& hc)
{
    if (hc->dirty)
        return;
    hc->dirty = true;
    dirty.push_back(hc);
}

void endpoint::dirty_raw(conn& hc)
{
    if (!hc.dirty && !hc.dead)
        mark_dirty(hc.shared_from_this());
}

void endpoint::flush_dirty()
{
    std::vector<std::weak_ptr<conn>> due;
    due.swap(dirty);
    // Only a connection written to can have moved its expiry earlier, so only those are looked at: one whose expiry
    // moved later leaves the timer early, and h3_expire, finding nothing due, sets it again.
    uint64_t soonest = UINT64_MAX;
    for (auto& w : due)
        if (auto hc = w.lock())
        {
            hc->dirty = false;
            if (!hc->dead)
                write(hc);
            if (!hc->dead)
                soonest = std::min<uint64_t>(soonest, ngtcp2_conn_get_expiry2(hc->q));
        }
    arm_timer(soonest);
}

void endpoint::send(const sockaddr_storage& local, socklen_t, const sockaddr_storage& remote, socklen_t remote_len,
                          const uint8_t* data, size_t len, size_t gso)
{
    iovec iov{const_cast<uint8_t*>(data), len};
    msghdr msg{};
    msg.msg_name = const_cast<sockaddr_storage*>(&remote);
    msg.msg_namelen = remote_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    alignas(cmsghdr) char cbuf[CMSG_SPACE(sizeof(in_pktinfo)) + CMSG_SPACE(sizeof(uint16_t))]{};
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof cbuf;
    cmsghdr* cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = IPPROTO_IP;
    cm->cmsg_type = IP_PKTINFO;
    cm->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
    in_pktinfo pi{};
    pi.ipi_spec_dst = reinterpret_cast<const sockaddr_in*>(&local)->sin_addr;
    std::memcpy(CMSG_DATA(cm), &pi, sizeof pi);
    size_t used = CMSG_SPACE(sizeof(in_pktinfo));
    if (gso && len > gso)
    {
        cm = CMSG_NXTHDR(&msg, cm);
        cm->cmsg_level = IPPROTO_UDP;
        cm->cmsg_type = UDP_SEGMENT;
        cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
        const uint16_t g = static_cast<uint16_t>(gso);
        std::memcpy(CMSG_DATA(cm), &g, sizeof g);
        used += CMSG_SPACE(sizeof(uint16_t));
    }
    msg.msg_controllen = used;
    // A datagram that does not fit the socket's buffer is lost, as one is on the way; QUIC sends it again.
    const ssize_t n = ::sendmsg(fd, &msg, MSG_DONTWAIT);
    if (n < 0) {}
    else
    {
        h->sent(static_cast<size_t>(n));
    }
}

void endpoint::write(const std::shared_ptr<conn>& hc)
{
    static const ngtcp2_write_pkt write_pkt = [](ngtcp2_conn* q, ngtcp2_path* path, ngtcp2_pkt_info* pi, uint8_t* dest,
                                                 size_t destlen, ngtcp2_tstamp ts, void* ud) -> ngtcp2_ssize
    {
        auto* hc = static_cast<conn*>(ud);
        for (;;)
        {
            int64_t sid = -1;
            int fin = 0;
            nghttp3_vec vec[16];
            nghttp3_ssize cnt = 0;
            if (hc->h && ngtcp2_conn_get_max_data_left2(q))
            {
                cnt = nghttp3_conn_writev_stream(hc->h, &sid, &fin, vec, 16);
                if (cnt < 0)
                {
                    ngtcp2_ccerr_set_application_error(&hc->err, nghttp3_err_infer_quic_app_error_code(static_cast<int>(cnt)),
                                                       nullptr, 0);
                    return NGTCP2_ERR_CALLBACK_FAILURE;
                }
            }
            ngtcp2_ssize ndatalen = 0;
            uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE | NGTCP2_WRITE_STREAM_FLAG_PADDING;
            if (fin)
                flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
            const ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(q, path, pi, dest, destlen, &ndatalen, flags, sid,
                                                                  reinterpret_cast<const ngtcp2_vec*>(vec),
                                                                  static_cast<size_t>(cnt), ts);
            if (nwrite < 0)
            {
                switch (nwrite)
                {
                    case NGTCP2_ERR_STREAM_DATA_BLOCKED:
                        nghttp3_conn_block_stream(hc->h, sid);
                        continue;
                    case NGTCP2_ERR_STREAM_SHUT_WR:
                        nghttp3_conn_shutdown_stream_write(hc->h, sid);
                        continue;
                    case NGTCP2_ERR_WRITE_MORE:
                        if (nghttp3_conn_add_write_offset(hc->h, sid, static_cast<uint64_t>(ndatalen)) != 0)
                            return NGTCP2_ERR_CALLBACK_FAILURE;
                        continue;
                    default:
                        ngtcp2_ccerr_set_liberr(&hc->err, static_cast<int>(nwrite), nullptr, 0);
                        return NGTCP2_ERR_CALLBACK_FAILURE;
                }
            }
            if (ndatalen >= 0 && sid >= 0 &&
                nghttp3_conn_add_write_offset(hc->h, sid, static_cast<uint64_t>(ndatalen)) != 0)
                return NGTCP2_ERR_CALLBACK_FAILURE;
            return nwrite;
        }
    };
    // Bursts while ngtcp2 has packets to give and its pacing lets them go; it says when the next may.
    for (int round = 0; round < 64 && !hc->dead; ++round)
    {
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_pkt_info pi{};
        size_t gso = 0;
        const uint64_t ts = now_ns();
        const ngtcp2_ssize n = ngtcp2_conn_write_aggregate_pkt2(hc->q, &ps.path, &pi, txbuf.data(), txbuf.size(),
                                                                &gso, write_pkt, gso_burst, ts);
        if (n < 0)
        {
            close(hc);
            return;
        }
        ngtcp2_conn_update_pkt_tx_time(hc->q, ts);
        if (n == 0)
            break;
        // Each burst on the path ngtcp2 wrote it for: the current one, or a path being validated.
        sockaddr_storage to{}, from{};
        socklen_t to_len = 0, from_len = 0;
        path_addr(ps.path.remote, to, to_len);
        path_addr(ps.path.local, from, from_len);
        send(from, from_len, to, to_len, txbuf.data(), static_cast<size_t>(n), gso);
    }
    // Streams whose bytes nghttp3 has all taken are told their write is done at the end of the turn.
    for (auto& [sid, st] : hc->streams)
        if (st && st->drained())
            h->write_done(*st);
}

void endpoint::arm_timer(uint64_t soonest)
{
    if (soonest == UINT64_MAX)
        return;
    if (tm_armed && tm_deadline <= soonest)
        return;
    if (tm_armed && !loop->submit_timeout_remove(&tm)) {}
    const uint64_t now = now_ns();
    const uint64_t wait = soonest > now ? soonest - now : 0;
    __kernel_timespec& slot = ts[ts_at ^= 1];
    slot.tv_sec = static_cast<long long>(wait / 1000000000ull);
    slot.tv_nsec = static_cast<long long>(wait % 1000000000ull);
    tm = io_request{};
    tm.owner = owner;
    tm_armed = loop->submit_timeout(&slot, &tm);
    tm_deadline = soonest;
}

void endpoint::expire()
{
    const uint64_t now = now_ns();
    std::vector<std::shared_ptr<conn>> due;
    for (auto& hc : conns)
        if (!hc->dead && ngtcp2_conn_get_expiry2(hc->q) <= now)
            due.push_back(hc);
    for (auto& hc : due)
    {
        const int r = ngtcp2_conn_handle_expiry(hc->q, now);
        if (r != 0)
        {
            // Idle past its timeout, or its handshake never finished: it is gone without a word.
            drop(hc);
            continue;
        }
        mark_dirty(hc);
    }
    flush_dirty();
    // The timer that fired is spent: it is set again by every connection's expiry, those not due included.
    uint64_t soonest = UINT64_MAX;
    for (auto& hc : conns)
        if (!hc->dead)
            soonest = std::min<uint64_t>(soonest, ngtcp2_conn_get_expiry2(hc->q));
    arm_timer(soonest);
}

void endpoint::close(const std::shared_ptr<conn>& hc)
{
    if (hc->dead)
        return;
    if (!ngtcp2_conn_in_closing_period2(hc->q) && !ngtcp2_conn_in_draining_period2(hc->q))
    {
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_pkt_info pi{};
        uint8_t buf[1500];
        const ngtcp2_ssize n = ngtcp2_conn_write_connection_close(hc->q, &ps.path, &pi, buf, sizeof buf, &hc->err,
                                                                  now_ns());
        if (n > 0)
        {
            sockaddr_storage to{}, from{};
            socklen_t to_len = 0, from_len = 0;
            path_addr(ps.path.remote, to, to_len);
            path_addr(ps.path.local, from, from_len);
            send(from, from_len, to, to_len, buf, static_cast<size_t>(n), 0);
        }
    }
    drop(hc);
}

void endpoint::drop(const std::shared_ptr<conn>& hc)
{
    if (hc->dead)
        return;
    hc->dead = true;
    // The streams are taken out of the table before the host is told, because what it does with one -- closing its
    // own object, which may ask this side for the stream again -- must not find the table it is walking.
    std::vector<std::unique_ptr<stream>> all;
    all.reserve(hc->streams.size());
    for (auto& [sid, st] : hc->streams)
        all.push_back(std::move(st));
    hc->streams.clear();
    for (auto& st : all)
    {
        st->gone = true;
        // The connection goes with this; a host object kept a little longer by an operation in flight must not
        // reach it, which is what clearing the owner says.
        st->owner = nullptr;
        h->stream_gone(*st);
    }
    for (const std::string& k : hc->cids)
        if (auto it = by_cid.find(k); it != by_cid.end() && it->second == hc)
            by_cid.erase(it);
    std::erase(conns, hc);
}

size_t endpoint::open_conns() const
{
    return conns.size();
}

void endpoint::stop()
{
    // Every client is told the connection ends, as HTTP/2's GOAWAY tells it.
    auto all = conns;
    for (auto& hc : all)
    {
        ngtcp2_ccerr_set_application_error(&hc->err, NGHTTP3_H3_NO_ERROR, nullptr, 0);
        close(hc);
    }
    if (tm_armed && !loop->submit_timeout_remove(&tm)) {}
    if (fd >= 0)
    {
        loop->close_fd(fd);
        fd = -1;
    }
    if (inbox >= 0)
    {
        loop->close_fd(inbox);
        inbox = -1;
    }
}




// ─── A stream, and its request ──────────────────────────────────────────────

// A stream the peer opened: its state is this side's, and what the host keeps beside it is the host's.
void endpoint::begin(conn& hc, int64_t sid)
{
    auto st = std::make_unique<stream>();
    st->sid   = sid;
    st->owner = &hc;
    st->user  = h->make_stream(*st);
    if (st->user == 0)
    {
        if (hc.q && !hc.dead)
            ngtcp2_conn_shutdown_stream(hc.q, 0, sid, NGHTTP3_H3_REQUEST_REJECTED);
        return;
    }
    stream* raw = st.get();
    hc.streams[sid] = std::move(st);
    h->count(event::stream_opened);
    nghttp3_conn_set_stream_user_data(hc.h, sid, raw);
}

// The head is complete: written back as the HTTP/1.1 head a runtime's own parser reads, and handed over -- or the
// status it earned instead, which the host answers on the stream.
void endpoint::deliver_head(stream& st, bool fin)
{
    if (st.opened)
        return;   // trailers: read, and dropped
    st.opened = true;
    st.remote_closed = fin;
    mux::request mr;
    const mux::verdict v = mux::request_head(st.fields, fin, o.max_head, mr);
    std::vector<std::pair<std::string, std::string>>().swap(st.fields);
    if (v == mux::verdict::malformed)
    {
        if (st.owner && st.owner->q && !st.owner->dead)
            ngtcp2_conn_shutdown_stream(st.owner->q, 0, st.sid, NGHTTP3_H3_MESSAGE_ERROR);
        h->stream_gone(st);
        if (st.owner)
            st.owner->streams.erase(st.sid);
        return;
    }
    st.synth_chunked = mr.synth_chunked;
    h->start_stream(st, mr, v == mux::verdict::too_large ? 431 : 0);
}

// ─── A stream's body in ─────────────────────────────────────────────────────

void pull(stream& st, std::string_view fresh)
{
    conn* hc = st.owner;
    if (!hc || !hc->ep)
        return;
    host& h = *hc->ep->h;
    // The answer is done and the rest of the body is not read.
    if (st.end_pending || st.gone)
    {
        give_back_raw(hc, fresh.size());
        return;
    }
    if (st.pulling)
    {
        if (!fresh.empty())
            st.rxq.emplace_back(fresh);
        return;
    }
    st.pulling = true;
    uint64_t given = 0;
    auto open_for = [&] { return !st.gone && h.can_take(st); };
    auto give = [&](const char* d, size_t n)
    {
        given += n;
        if (!st.synth_chunked)
        {
            h.take(st, d, n);
            return;
        }
        char hex[20];
        const auto r = std::to_chars(hex, hex + sizeof hex, n, 16);
        std::string framed;
        framed.reserve(n + 32);
        framed.append(hex, r.ptr);
        framed += "\r\n";
        framed.append(d, n);
        framed += "\r\n";
        h.take(st, framed.data(), framed.size());
    };
    while (open_for() && !st.rxq.empty())
    {
        std::string front = std::move(st.rxq.front());
        st.rxq.pop_front();
        size_t at = std::exchange(st.rx_head, 0);
        while (at < front.size() && open_for())
        {
            const size_t n = std::min(pull_slice, front.size() - at);
            at += n;
            give(front.data() + at - n, n);
        }
        if (at < front.size())
        {
            st.rx_head = at;
            st.rxq.push_front(std::move(front));
        }
    }
    while (!fresh.empty())
    {
        if (!open_for() || !st.rxq.empty())
        {
            st.rxq.emplace_back(fresh);
            break;
        }
        const size_t n = std::min(pull_slice, fresh.size());
        const char* d = fresh.data();
        fresh.remove_prefix(n);
        give(d, n);
    }
    if (st.synth_chunked && st.remote_closed && !st.chunk_end_given && st.rxq.empty() && open_for())
    {
        st.chunk_end_given = true;
        static const char end[] = "0\r\n\r\n";
        h.take(st, end, sizeof end - 1);
    }
    st.pulling = false;
    if (given && !st.gone && st.owner && st.owner->q)
    {
        ngtcp2_conn_extend_max_stream_offset(st.owner->q, st.sid, given);
        ngtcp2_conn_extend_max_offset(st.owner->q, given);
        st.owner->ep->dirty_raw(*st.owner);
    }
}

// ─── A stream's answer out ──────────────────────────────────────────────────

namespace
{

// What nghttp3 is handed of a stream's answer when it asks: the chunks it does not have yet,
// from where the last call left off. The bytes stay until the peer acknowledges them, because QUIC may
// have to send them again.
nghttp3_ssize read_data(nghttp3_conn*, int64_t, nghttp3_vec* vec, size_t veccnt, uint32_t* pflags, void*, void* sud)
{
    auto* sp = static_cast<stream*>(sud);
    if (!sp)
    {
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }
    stream& st = *sp;
    size_t n = 0;
    // The chunks not yet given, from where the last call left off.
    size_t i = st.tx_given_chunks;
    size_t off = st.tx_given_front;
    while (n < veccnt && i < st.tx.size())
    {
        const std::string& ch = st.tx[i];
        if (off < ch.size())
        {
            vec[n].base = reinterpret_cast<uint8_t*>(const_cast<char*>(ch.data())) + off;
            vec[n].len = ch.size() - off;
            st.tx_given += vec[n].len;
            ++n;
        }
        ++i;
        off = 0;
    }
    st.tx_given_chunks = i;
    st.tx_given_front = 0;
    if (st.tx_given == st.tx_total)
    {
        if (st.end_pending)
        {
            *pflags |= NGHTTP3_DATA_FLAG_EOF;
            st.ended = true;
        }
        else if (n == 0)
        {
            st.blocked = true;
            return NGHTTP3_ERR_WOULDBLOCK;
        }
    }
    return static_cast<nghttp3_ssize>(n);
}

}   // namespace

void answer(stream& st, std::string data, bool finish)
{
    if (st.gone || !st.owner || !st.owner->h)
        return;
    conn& hc = *st.owner;
    std::string_view rest = data;
    while (!rest.empty())
    {
        if (st.os == stream::out_state::head)
        {
            st.head_acc.append(rest);
            rest = {};
            const size_t end = st.head_acc.find("\r\n\r\n");
            if (end == std::string::npos)
                break;
            mux::response mr;
            mux::response_head(std::string_view(st.head_acc.data(), end + 2), mr);
            const std::string after = st.head_acc.substr(end + 4);
            st.head_acc.clear();
            std::vector<nghttp3_nv> nva;
            nva.reserve(mr.fields.size() + 1);
            auto nv = [](std::string_view n, std::string_view v)
            {
                return nghttp3_nv{reinterpret_cast<uint8_t*>(const_cast<char*>(n.data())),
                                  reinterpret_cast<uint8_t*>(const_cast<char*>(v.data())), n.size(), v.size(),
                                  NGHTTP3_NV_FLAG_NONE};
            };
            nva.push_back(nv(":status", mr.status));
            for (const auto& [n, v] : mr.fields)
                nva.push_back(nv(n, v));
            if (mr.interim)
                nghttp3_conn_submit_info(hc.h, st.sid, nva.data(), nva.size());
            else
            {
                st.os = mr.chunked ? stream::out_state::dechunk : stream::out_state::body;
                static const nghttp3_data_reader dr{read_data};
                nghttp3_conn_submit_response(hc.h, st.sid, nva.data(), nva.size(), &dr);
                st.submitted = true;
            }
            if (!after.empty())
            {
                data = after;
                rest = data;
            }
            continue;
        }
        if (st.os == stream::out_state::body)
        {
            const size_t n = rest.size();
            if (rest.data() == data.data() && n == data.size())
                st.tx.push_back(std::move(data));
            else
                st.tx.emplace_back(rest);
            st.tx_total += n;
            rest = {};
            break;
        }
        st.dechunk_in.append(rest);
        rest = {};
        std::string_view view = st.dechunk_in;
        std::string out;
        for (;;)
        {
            std::string_view piece;
            if (http_chunked_next(st.dechunk, view, piece) != chunk_step::payload)
                break;
            out.append(piece);
        }
        st.dechunk_in.erase(0, st.dechunk_in.size() - view.size());
        if (!out.empty())
        {
            st.tx_total += out.size();
            st.tx.push_back(std::move(out));
        }
    }
    // An answer handed over whole -- send_response's, whose end is already decided -- carries the stream's end with
    // its last bytes, in the same packet, instead of in one of its own a turn later; finish_request still follows
    // for the rest. A chunked one ends with its last chunk, which the stream cannot see coming.
    if (finish && st.submitted && st.os == stream::out_state::body)
        st.end_pending = true;
    if (st.submitted && st.blocked)
    {
        st.blocked = false;
        nghttp3_conn_resume_stream(hc.h, st.sid);
    }
    hc.ep->dirty_raw(hc);
}

// The answer is over: the stream carries its end, and a body still coming that it did not need
// is not read.  False when the stream cannot be ended and the host must let go of it instead.
bool answer_end(stream& st)
{
    if (st.gone || !st.owner || !st.owner->h)
        return false;
    conn& hc = *st.owner;
    st.end_pending = true;
    if (!st.submitted)
    {
        // An answer with no head would be a broken stream; this one simply ends.
        ngtcp2_conn_shutdown_stream(hc.q, 0, st.sid, NGHTTP3_H3_INTERNAL_ERROR);
        return false;
    }
    // A body still coming that the answer did not need is not read.
    if (!st.remote_closed)
        ngtcp2_conn_shutdown_stream_read(hc.q, 0, st.sid, NGHTTP3_H3_NO_ERROR);
    drop_rx(st);
    if (st.blocked)
    {
        st.blocked = false;
        nghttp3_conn_resume_stream(hc.h, st.sid);
    }
    hc.ep->dirty_raw(hc);
    return true;
}

// The host has let go of its object: the stream is ended toward the client and forgotten.
void gone(stream& st)
{
    if (st.gone || !st.owner)
        return;
    conn& hc = *st.owner;
    drop_rx(st);
    st.gone = true;
    // Ended before its answer did: the client is told the request was cancelled.  An end already asked for is not
    // a cancel, and resetting then would take the answer with it.
    if (!st.ended && !st.end_pending && hc.q && !hc.dead)
        ngtcp2_conn_shutdown_stream(hc.q, 0, st.sid, NGHTTP3_H3_REQUEST_CANCELLED);
    // The reset, or the window its unread body gave back, goes out.
    if (hc.ep)
        hc.ep->dirty_raw(hc);
    if (hc.h)
        nghttp3_conn_set_stream_user_data(hc.h, st.sid, nullptr);
    const int64_t sid = st.sid;
    hc.streams.erase(sid);
}

// ─── The endpoint a runtime holds ───────────────────────────────────────────

void endpoint_free::operator()(endpoint* e) const { delete e; }

endpoint_ptr open(const options& o, host& h, event_loop& loop, std::string& err)
{
    auto e = endpoint_ptr(new endpoint);
    e->h = &h;
    e->loop = &loop;
    e->owner = o.owner;
    e->o = o;
    e->retry_after = o.retry_after;
    if (o.cc == "reno")
        e->cc = NGTCP2_CC_ALGO_RENO;
    else if (o.cc == "cubic")
        e->cc = NGTCP2_CC_ALGO_CUBIC;
    if (!e->open(o.port, o.advertise, o.shard, o.shards, o.cert, o.key, o.ca))
    {
        err = "the UDP socket or the certificate for QUIC could not be opened";
        return {};
    }
    return e;
}

bool owns(const endpoint& e, const io_request* req)
{
    return req == &e.rd || req == &e.tm || req == &e.in_rd;
}

void completion(endpoint& e, io_request* req, int res) { e.cqe(req, res); }
void flush(endpoint& e) { e.flush_dirty(); }
size_t open_conns(const endpoint& e) { return e.open_conns(); }
std::string alt_svc(const endpoint& e) { return e.alt; }
void release(stream& st) { st.user = 0; }

void stop(endpoint& e) { e.stop(); }

const sockaddr_storage* peer_of(const stream& st) { return st.owner ? &st.owner->remote : nullptr; }
std::string peer_text_of(const stream& st) { return st.owner ? st.owner->peer : std::string(); }
ssl_st* tls_of(const stream& st) { return st.owner ? st.owner->ssl : nullptr; }

}   // namespace socketley::h3

#endif   // SOCKETLEY_HTTP3
