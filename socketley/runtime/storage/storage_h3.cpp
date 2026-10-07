// HTTP/3, RFC 9114 over QUIC (RFC 9000), for a storage runtime with --tls: a UDP socket on the TCP listener's port,
// read and written through the ring; QUIC is ngtcp2's, its TLS 1.3 OpenSSL 3.5's through ngtcp2's helper, and HTTP/3
// and QPACK are nghttp3's. Each request is a stream, and each stream a conn with no socket, exactly as for HTTP/2:
// its head is written back as the HTTP/1.1 head parse_head() reads, its body handed to its phase as a recv's bytes
// would be, and its answer read back into HTTP/3's fields and DATA. Every operation runs as it does over HTTP/1.1.
//
// A body in is given back to the window only as its phase takes it, as for HTTP/2. A body out is held until the peer
// acknowledges it, since QUIC may send it again; a stream is told its write is done -- and asked for the next piece
// of a file -- once nghttp3 has taken all it was handed. A browser learns of HTTP/3 from the Alt-Svc header every
// answer over TCP carries, and goes on over TCP when UDP does not reach.
#include "storage_run.h"
#include "storage_instance.h"

#if SOCKETLEY_HTTP3

#include <algorithm>
#include <charconv>
#include <cstring>
#include <deque>
#include <unordered_map>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <nghttp3/nghttp3.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "mux_head.h"
#include "../../shared/logging.h"

#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
#endif

namespace socketley::storage
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
// Packets written at once and sent in one sendmsg by UDP GSO.
constexpr size_t   gso_burst       = 16;
constexpr uint64_t idle_timeout_ns = 30ull * NGTCP2_SECONDS;

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

struct h3_conn;

// What a stream's answer has given nghttp3 and what the peer has acknowledged, held as it was handed over: QUIC sends
// a lost packet's bytes again, so they live until acknowledged.
struct h3_stream
{
    int64_t  sid{0};
    h3_conn* conn{nullptr};
    // The request's fields as they came, until its head is complete.
    std::vector<std::pair<std::string, std::string>> fields;
    bool     opened{false};
    // DATA received and not yet handed to the phase.
    std::deque<std::string> rxq;
    size_t   rx_head{0};
    bool     remote_closed{false};
    bool     synth_chunked{false};
    bool     chunk_end_given{false};

    enum class out_state : uint8_t { head, body, dechunk } os{out_state::head};
    std::string head_acc;
    http_chunked_decoder dechunk;
    std::string dechunk_in;
    std::deque<std::string> tx;
    size_t   tx_given_front{0};   // what of tx.front() nghttp3 already has
    size_t   tx_given_chunks{0};  // chunks nghttp3 has whole, at the front
    uint64_t tx_total{0}, tx_given{0}, tx_acked_front{0};
    bool     submitted{false};
    bool     blocked{false};      // read_data said it would block; resumed when more comes
    bool     end_pending{false};
    bool     ended{false};        // EOF given
    bool     gone{false};
};

struct h3_conn : std::enable_shared_from_this<h3_conn>
{
    storage_run*   run{nullptr};
    ngtcp2_conn*   q{nullptr};
    nghttp3_conn*  h{nullptr};
    ngtcp2_crypto_ossl_ctx* octx{nullptr};
    SSL*           ssl{nullptr};
    ngtcp2_crypto_conn_ref ref{};
    sockaddr_storage local{}, remote{};
    socklen_t      local_len{0}, remote_len{0};
    std::vector<std::string> cids;
    std::unordered_map<int64_t, std::shared_ptr<conn>> streams;
    ngtcp2_ccerr   err{};
    bool           dead{false};
    bool           dirty{false};
    std::string    peer;
    client_ip      ip{};

    ~h3_conn()
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

struct h3_endpoint
{
    int         fd{-1};
    uint16_t    port{0};
    SSL_CTX*    ctx{nullptr};
    uint8_t     secret[32]{};
    io_request  rd{};
    bool        rd_pending{false};
    msghdr      msg{};
    iovec       iov{};
    sockaddr_storage src{};
    alignas(cmsghdr) char cbuf[256]{};
    std::vector<uint8_t> rbuf = std::vector<uint8_t>(rx_buf);
    std::vector<uint8_t> txbuf = std::vector<uint8_t>(gso_burst * 1500);
    std::unordered_map<std::string, std::shared_ptr<h3_conn>> by_cid;
    std::vector<std::shared_ptr<h3_conn>> conns;
    // One timeout for every connection's earliest expiry; two timespecs, so one waiting to be submitted is never
    // written over by the next.
    io_request  tm{};
    __kernel_timespec ts[2]{};
    int         ts_at{0};
    bool        tm_armed{false};
    uint64_t    tm_deadline{0};
    std::vector<std::weak_ptr<h3_conn>> dirty;

    ~h3_endpoint()
    {
        if (ctx)
            SSL_CTX_free(ctx);
    }
};

void h3_endpoint_free::operator()(h3_endpoint* e) const { delete e; }
void h3_stream_free::operator()(h3_stream* s) const { delete s; }

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
void h3_give_back(h3_conn* hc, uint64_t n)
{
    if (n && hc && hc->q && !hc->dead)
        ngtcp2_conn_extend_max_offset(hc->q, n);
}

void h3_drop_rx(h3_stream& st)
{
    uint64_t left = 0;
    for (const auto& piece : st.rxq)
        left += piece.size();
    left -= std::min<uint64_t>(left, st.rx_head);
    st.rxq.clear();
    st.rx_head = 0;
    h3_give_back(st.conn, left);
}

ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref* ref)
{
    return static_cast<h3_conn*>(ref->user_data)->q;
}

}   // namespace

// ─── The endpoint ───────────────────────────────────────────────────────────

bool storage_run::h3_open(uint16_t port, uint16_t advertise, bool reuseport, const std::string& cert,
                          const std::string& key)
{
    auto ep = std::unique_ptr<h3_endpoint, h3_endpoint_free>(new h3_endpoint);
    if (ngtcp2_crypto_ossl_init() != 0)
        return false;
    ep->ctx = SSL_CTX_new(TLS_server_method());
    if (!ep->ctx)
        return false;
    SSL_CTX_set_min_proto_version(ep->ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ep->ctx, TLS1_3_VERSION);
    SSL_CTX_set_options(ep->ctx, (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) | SSL_OP_SINGLE_ECDH_USE |
                                     SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_NO_ANTI_REPLAY);
    SSL_CTX_set_mode(ep->ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_alpn_select_cb(ep->ctx, alpn_h3, nullptr);
    if (SSL_CTX_use_certificate_chain_file(ep->ctx, cert.c_str()) != 1 ||
        SSL_CTX_use_PrivateKey_file(ep->ctx, key.c_str(), SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ep->ctx) != 1)
    {
        ERR_clear_error();
        LOG_WARN("storage: HTTP/3 not offered -- the certificate or key could not be loaded for QUIC");
        return false;
    }
    if (RAND_bytes(ep->secret, sizeof ep->secret) != 1)
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
    ep->fd = fd;
    ep->port = port;
    ep->rd.owner = this;
    ep->tm.owner = this;
    m_h3 = std::move(ep);
    // Behind a proxy the port a browser reaches may not be this one; 0 offers HTTP/3 to no one who was not told.
    if (advertise)
        m_alt_svc = "h3=\":" + std::to_string(advertise) + "\"; ma=86400";
    h3_arm_read();
    return true;
}

void storage_run::h3_arm_read()
{
    h3_endpoint& ep = *m_h3;
    if (ep.rd_pending || ep.fd < 0 || m_stopped)
        return;
    ep.iov.iov_base = ep.rbuf.data();
    ep.iov.iov_len = ep.rbuf.size();
    ep.msg = msghdr{};
    ep.msg.msg_name = &ep.src;
    ep.msg.msg_namelen = sizeof ep.src;
    ep.msg.msg_iov = &ep.iov;
    ep.msg.msg_iovlen = 1;
    ep.msg.msg_control = ep.cbuf;
    ep.msg.msg_controllen = sizeof ep.cbuf;
    ep.rd = io_request{};
    ep.rd.owner = this;
    ep.rd_pending = m_loop.submit_recvmsg(ep.fd, &ep.msg, &ep.rd);
}

bool storage_run::h3_owns(io_request* req) const
{
    return m_h3 && (req == &m_h3->rd || req == &m_h3->tm);
}

void storage_run::h3_cqe(io_request* req, int res)
{
    h3_endpoint& ep = *m_h3;
    if (req == &ep.tm)
    {
        if (res == -ECANCELED)
            return;
        ep.tm_armed = false;
        if (!m_stopped)
            h3_expire();
        return;
    }
    ep.rd_pending = false;
    if (m_stopped)
        return;
    if (res > 0)
    {
        // The local address, from IP_PKTINFO, and the size each datagram was when GRO joined them.
        sockaddr_storage local{};
        socklen_t local_len = sizeof(sockaddr_in);
        auto* l4 = reinterpret_cast<sockaddr_in*>(&local);
        l4->sin_family = AF_INET;
        l4->sin_port = htons(ep.port);
        size_t seg = static_cast<size_t>(res);
        for (cmsghdr* cm = CMSG_FIRSTHDR(&ep.msg); cm; cm = CMSG_NXTHDR(&ep.msg, cm))
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
        const size_t total = static_cast<size_t>(res);
        for (size_t off = 0; off < total; off += seg)
            h3_packet(local, local_len, ep.src, ep.msg.msg_namelen, ep.rbuf.data() + off, std::min(seg, total - off));
        h3_flush_dirty();
    }
    h3_arm_read();
}

// ─── A datagram in ──────────────────────────────────────────────────────────

void storage_run::h3_packet(const sockaddr_storage& local, socklen_t local_len, const sockaddr_storage& remote,
                            socklen_t remote_len, const uint8_t* data, size_t len)
{
    h3_endpoint& ep = *m_h3;
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
            h3_send(local, local_len, remote, remote_len, out, static_cast<size_t>(n), 0);
        return;
    }
    if (rv != 0)
        return;
    std::shared_ptr<h3_conn> hc;
    if (auto it = ep.by_cid.find(cid_key(vc.dcid, vc.dcidlen)); it != ep.by_cid.end())
        hc = it->second;
    if (!hc)
    {
        ngtcp2_pkt_hd hd{};
        if (ngtcp2_accept(&hd, data, len) != 0 || ep.conns.size() >= max_conns)
            return;
        hc = h3_new_conn(hd, local, local_len, remote, remote_len);
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
            h3_drop(hc);
            return;
        }
        if (r == NGTCP2_ERR_CRYPTO)
            ngtcp2_ccerr_set_tls_alert(&hc->err, ngtcp2_conn_get_tls_alert(hc->q), nullptr, 0);
        else if (hc->err.error_code == 0)
            ngtcp2_ccerr_set_liberr(&hc->err, r, nullptr, 0);
        h3_close(hc);
        return;
    }
    h3_dirty(hc);
}

std::shared_ptr<h3_conn> storage_run::h3_new_conn(const ngtcp2_pkt_hd& hd, const sockaddr_storage& local,
                                                  socklen_t local_len, const sockaddr_storage& remote,
                                                  socklen_t remote_len)
{
    h3_endpoint& ep = *m_h3;
    auto hc = std::make_shared<h3_conn>();
    hc->run = this;
    hc->local = local;
    hc->local_len = local_len;
    hc->remote = remote;
    hc->remote_len = remote_len;
    hc->ref.get_conn = get_conn;
    hc->ref.user_data = hc.get();
    hc->ip = client_ip_from(reinterpret_cast<const sockaddr*>(&remote));
    {
        const auto* a = reinterpret_cast<const sockaddr_in*>(&remote);
        char host[INET_ADDRSTRLEN] = {};
        ::inet_ntop(AF_INET, &a->sin_addr, host, sizeof host);
        hc->peer = std::string(host) + ":" + std::to_string(ntohs(a->sin_port));
    }

    ngtcp2_cid scid{};
    scid.datalen = scid_len;
    h3_rand(scid.data, scid.datalen);

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
            auto* hc = static_cast<h3_conn*>(ud);
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
            auto* hc = static_cast<h3_conn*>(ud);
            if (hc->h && nghttp3_conn_add_ack_offset(hc->h, sid, len) != 0)
                return NGTCP2_ERR_CALLBACK_FAILURE;
            return 0;
        };
        c.stream_close2 = [](ngtcp2_conn*, uint32_t flags, int64_t sid, uint64_t rx, uint64_t tx, void* ud, void*) -> int
        {
            auto* hc = static_cast<h3_conn*>(ud);
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
            auto* hc = static_cast<h3_conn*>(ud);
            return !hc->h || nghttp3_conn_shutdown_stream_read(hc->h, sid) == 0 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
        };
        c.stream_stop_sending = [](ngtcp2_conn*, int64_t sid, uint64_t, void* ud, void*) -> int
        {
            auto* hc = static_cast<h3_conn*>(ud);
            return !hc->h || nghttp3_conn_shutdown_stream_read(hc->h, sid) == 0 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
        };
        c.extend_max_remote_streams_bidi = [](ngtcp2_conn*, uint64_t max, void* ud) -> int
        {
            auto* hc = static_cast<h3_conn*>(ud);
            if (hc->h)
                nghttp3_conn_set_max_client_streams_bidi(hc->h, max);
            return 0;
        };
        c.extend_max_stream_data = [](ngtcp2_conn*, int64_t sid, uint64_t, void* ud, void*) -> int
        {
            auto* hc = static_cast<h3_conn*>(ud);
            return !hc->h || nghttp3_conn_unblock_stream(hc->h, sid) == 0 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
        };
        c.get_new_connection_id2 = [](ngtcp2_conn*, ngtcp2_cid* cid, ngtcp2_stateless_reset_token* token, size_t cidlen,
                                      void* ud) -> int
        {
            auto* hc = static_cast<h3_conn*>(ud);
            h3_rand(cid->data, cidlen);
            cid->datalen = cidlen;
            h3_endpoint& ep = *hc->run->m_h3;
            if (ngtcp2_crypto_generate_stateless_reset_token(token->data, ep.secret, sizeof ep.secret, cid) != 0)
                return NGTCP2_ERR_CALLBACK_FAILURE;
            const std::string k = cid_key(cid->data, cid->datalen);
            hc->cids.push_back(k);
            ep.by_cid[k] = hc->shared_from_this();
            return 0;
        };
        c.remove_connection_id = [](ngtcp2_conn*, const ngtcp2_cid* cid, void* ud) -> int
        {
            auto* hc = static_cast<h3_conn*>(ud);
            const std::string k = cid_key(cid->data, cid->datalen);
            hc->run->m_h3->by_cid.erase(k);
            std::erase(hc->cids, k);
            return 0;
        };
        c.recv_tx_key = [](ngtcp2_conn*, ngtcp2_encryption_level level, void* ud) -> int
        {
            if (level != NGTCP2_ENCRYPTION_LEVEL_1RTT)
                return 0;
            auto* hc = static_cast<h3_conn*>(ud);
            return hc->run->h3_app_ready(*hc) ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
        };
        return c;
    }();

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = now_ns();
    settings.max_window = conn_window_max;
    settings.max_stream_window = stream_window_max;
    settings.cc_algo = NGTCP2_CC_ALGO_CUBIC;
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
    params.original_dcid = hd.dcid;
    params.original_dcid_present = 1;
    if (ngtcp2_crypto_generate_stateless_reset_token(params.stateless_reset_token, ep.secret, sizeof ep.secret,
                                                     &scid) != 0)
        return nullptr;

    ngtcp2_path path{};
    path.local.addr = reinterpret_cast<sockaddr*>(&hc->local);
    path.local.addrlen = hc->local_len;
    path.remote.addr = reinterpret_cast<sockaddr*>(&hc->remote);
    path.remote.addrlen = hc->remote_len;
    if (ngtcp2_conn_server_new(&hc->q, &hd.scid, &scid, &path, hd.version, &cb, &settings, &params, nullptr, hc.get()) != 0)
        return nullptr;

    hc->ssl = SSL_new(ep.ctx);
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
        ep.by_cid[k] = hc;
    }
    ep.conns.push_back(hc);
    ++m_c.h3_conns;
    return hc;
}

// The handshake's keys for application data are in: HTTP/3's control and QPACK streams are opened.
bool storage_run::h3_app_ready(h3_conn& hc)
{
    if (hc.h)
        return true;
    if (ngtcp2_conn_get_streams_uni_left2(hc.q) < 3)
        return false;
    static const nghttp3_callbacks cb = []
    {
        nghttp3_callbacks c{};
        c.rand = h3_rand;
        c.acked_stream_data = [](nghttp3_conn*, int64_t, uint64_t len, void*, void* sud) -> int
        {
            if (auto* sc = static_cast<conn*>(sud))
                sc->run->h3_acked(*sc, len);
            return 0;
        };
        c.stream_close = [](nghttp3_conn*, int64_t sid, uint64_t, void* ud, void*) -> int
        {
            auto* hc = static_cast<h3_conn*>(ud);
            // A request stream done is one more the client may open: ngtcp2 does not give it back by itself.
            if (ngtcp2_is_bidi_stream(sid) && !ngtcp2_conn_is_local_stream(hc->q, sid))
                ngtcp2_conn_extend_max_streams_bidi(hc->q, 1);
            hc->run->h3_stream_closed(*hc, sid);
            return 0;
        };
        c.recv_data = [](nghttp3_conn*, int64_t, const uint8_t* data, size_t len, void* ud, void* sud) -> int
        {
            if (auto* sc = static_cast<conn*>(sud))
                sc->run->h3_data(*sc, std::string_view(reinterpret_cast<const char*>(data), len));
            else
                h3_give_back(static_cast<h3_conn*>(ud), len);
            return 0;
        };
        c.deferred_consume = [](nghttp3_conn*, int64_t sid, size_t n, void* ud, void*) -> int
        {
            auto* hc = static_cast<h3_conn*>(ud);
            ngtcp2_conn_extend_max_stream_offset(hc->q, sid, n);
            ngtcp2_conn_extend_max_offset(hc->q, n);
            return 0;
        };
        c.begin_headers = [](nghttp3_conn*, int64_t sid, void* ud, void*) -> int
        {
            auto* hc = static_cast<h3_conn*>(ud);
            return hc->run->h3_begin(*hc, sid) ? 0 : NGHTTP3_ERR_CALLBACK_FAILURE;
        };
        c.recv_header = [](nghttp3_conn*, int64_t, int32_t, nghttp3_rcbuf* name, nghttp3_rcbuf* value, uint8_t, void*,
                           void* sud) -> int
        {
            auto* sc = static_cast<conn*>(sud);
            if (!sc || !sc->h3s)
                return 0;
            const nghttp3_vec n = nghttp3_rcbuf_get_buf(name), v = nghttp3_rcbuf_get_buf(value);
            auto& f = sc->h3s->fields;
            f.emplace_back(std::string(reinterpret_cast<const char*>(n.base), n.len),
                           std::string(reinterpret_cast<const char*>(v.base), v.len));
            return 0;
        };
        c.end_headers = [](nghttp3_conn*, int64_t, int fin, void*, void* sud) -> int
        {
            if (auto* sc = static_cast<conn*>(sud))
                sc->run->h3_request(*sc, fin != 0);
            return 0;
        };
        c.end_stream = [](nghttp3_conn*, int64_t, void*, void* sud) -> int
        {
            if (auto* sc = static_cast<conn*>(sud))
                sc->run->h3_data_end(*sc);
            return 0;
        };
        c.stop_sending = [](nghttp3_conn*, int64_t sid, uint64_t code, void* ud, void*) -> int
        {
            auto* hc = static_cast<h3_conn*>(ud);
            ngtcp2_conn_shutdown_stream_read(hc->q, 0, sid, code);
            return 0;
        };
        c.reset_stream = [](nghttp3_conn*, int64_t sid, uint64_t code, void* ud, void*) -> int
        {
            auto* hc = static_cast<h3_conn*>(ud);
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

bool storage_run::h3_begin(h3_conn& hc, int64_t sid)
{
    auto sc = std::make_shared<conn>();
    sc->run = this;
    sc->id = m_next_id++;
    sc->h3s.reset(new h3_stream);
    sc->h3s->sid = sid;
    sc->h3s->conn = &hc;
    sc->quic_ssl = hc.ssl;
    sc->accepted = sc->last_progress = sc->request_began = std::chrono::steady_clock::now();
    sc->ip = hc.ip;
    sc->ip_known = true;
    sc->peer = hc.peer;
    sc->any_request = true;
    hc.streams[sid] = sc;
    m_streams[sc->id] = sc;
    ++m_c.h3_streams;
    nghttp3_conn_set_stream_user_data(hc.h, sid, sc.get());
    return true;
}

void storage_run::h3_request(conn& raw, bool fin)
{
    auto sc = find(raw.id);
    if (!sc || sc->dead || !sc->h3s)
        return;
    h3_stream& st = *sc->h3s;
    if (st.opened)
        return;   // trailers: read, and dropped
    st.opened = true;
    st.remote_closed = fin;
    mux_request mr;
    const mux_verdict v = mux_request_head(st.fields, fin, max_head, mr);
    std::vector<std::pair<std::string, std::string>>().swap(st.fields);
    if (v == mux_verdict::malformed)
    {
        ngtcp2_conn_shutdown_stream(st.conn->q, 0, st.sid, NGHTTP3_H3_MESSAGE_ERROR);
        close_conn(sc);
        return;
    }
    st.synth_chunked = mr.synth_chunked;
    if (v == mux_verdict::too_large)
    {
        new_request_id(sc->req.request_id);
        response r;
        r.status = 431;
        sc->ph = phase::respond;
        send_response(sc, std::move(r));
        return;
    }
    if (!parse_head(sc, mr.line))
        return;
    sc->req.version = "HTTP/3";
    ++m_c.requests;
    runtime_instance::stat_add(m_owner.m_stat_total_messages, 1);
    dispatch(sc);
}

void storage_run::h3_data(conn& raw, std::string_view data)
{
    auto sc = find(raw.id);
    if (!sc || sc->dead)
    {
        if (raw.h3s)
            h3_give_back(raw.h3s->conn, data.size());
        return;
    }
    sc->last_progress = std::chrono::steady_clock::now();
    h3_pull(sc, data);
}

void storage_run::h3_data_end(conn& raw)
{
    auto sc = find(raw.id);
    if (!sc || sc->dead || !sc->h3s)
        return;
    sc->h3s->remote_closed = true;
    h3_pull(sc, {});
}

// What came is handed to the phase while it takes it, held when it does not, and given back to QUIC's windows as it
// is taken -- so a put that cannot keep up stops the client.
void storage_run::h3_pull(const std::shared_ptr<conn>& c, std::string_view fresh)
{
    if (c->dead || !c->h3s)
        return;
    h3_stream& st = *c->h3s;
    // The answer is done and the rest of the body is not read.
    if (st.end_pending || st.gone)
    {
        h3_give_back(st.conn, fresh.size());
        return;
    }
    if (c->pulling)
    {
        if (!fresh.empty())
            st.rxq.emplace_back(fresh);
        return;
    }
    c->pulling = true;
    uint64_t given = 0;
    auto open = [&] { return !c->dead && c->ph != phase::respond && c->ph != phase::hook_wait && c->park_off >= c->park.size(); };
    auto give = [&](const char* d, size_t n)
    {
        given += n;
        if (!st.synth_chunked)
        {
            plain_in(c, d, n);
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
        plain_in(c, framed.data(), framed.size());
    };
    while (open() && !st.rxq.empty())
    {
        std::string front = std::move(st.rxq.front());
        st.rxq.pop_front();
        size_t at = std::exchange(st.rx_head, 0);
        while (at < front.size() && open())
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
        if (!open() || !st.rxq.empty())
        {
            st.rxq.emplace_back(fresh);
            break;
        }
        const size_t n = std::min(pull_slice, fresh.size());
        const char* d = fresh.data();
        fresh.remove_prefix(n);
        give(d, n);
    }
    if (st.synth_chunked && st.remote_closed && !st.chunk_end_given && st.rxq.empty() && open())
    {
        st.chunk_end_given = true;
        static const char end[] = "0\r\n\r\n";
        plain_in(c, end, sizeof end - 1);
    }
    c->pulling = false;
    if (given && !st.gone && st.conn && st.conn->q)
    {
        ngtcp2_conn_extend_max_stream_offset(st.conn->q, st.sid, given);
        ngtcp2_conn_extend_max_offset(st.conn->q, given);
        h3_dirty_raw(*st.conn);
    }
}

// ─── A stream's answer out ──────────────────────────────────────────────────

namespace
{

nghttp3_ssize read_data(nghttp3_conn*, int64_t, nghttp3_vec* vec, size_t veccnt, uint32_t* pflags, void*, void* sud)
{
    auto* sc = static_cast<conn*>(sud);
    if (!sc || !sc->h3s)
    {
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }
    h3_stream& st = *sc->h3s;
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

void storage_run::h3_acked(conn& raw, uint64_t len)
{
    if (!raw.h3s)
        return;
    h3_stream& st = *raw.h3s;
    // Acknowledged bytes are let go from the front; a chunk goes when the whole of it is.
    st.tx_acked_front += len;
    while (!st.tx.empty() && st.tx_given_chunks > 0 && st.tx_acked_front >= st.tx.front().size())
    {
        st.tx_acked_front -= st.tx.front().size();
        st.tx.pop_front();
        --st.tx_given_chunks;
    }
}

void storage_run::h3_stream_out(const std::shared_ptr<conn>& c, std::string data)
{
    h3_stream& st = *c->h3s;
    if (st.gone || !st.conn || !st.conn->h)
        return;
    h3_conn& hc = *st.conn;
    std::string_view rest = data;
    while (!rest.empty())
    {
        if (st.os == h3_stream::out_state::head)
        {
            st.head_acc.append(rest);
            rest = {};
            const size_t end = st.head_acc.find("\r\n\r\n");
            if (end == std::string::npos)
                break;
            mux_response mr;
            mux_response_head(std::string_view(st.head_acc.data(), end + 2), mr);
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
                st.os = mr.chunked ? h3_stream::out_state::dechunk : h3_stream::out_state::body;
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
        if (st.os == h3_stream::out_state::body)
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
    c->last_progress = std::chrono::steady_clock::now();
    if (st.submitted && st.blocked)
    {
        st.blocked = false;
        nghttp3_conn_resume_stream(hc.h, st.sid);
    }
    h3_dirty_raw(hc);
}

void storage_run::h3_stream_end(const std::shared_ptr<conn>& c)
{
    if (c->file_fd >= 0)
    {
        m_loop.close_fd(c->file_fd);
        c->file_fd = -1;
    }
    c->dec.reset();
    c->sel.reset();
    zip_end(*c);
    c->ph = phase::respond;
    h3_stream& st = *c->h3s;
    if (st.gone || !st.conn || !st.conn->h)
    {
        close_conn(c);
        return;
    }
    h3_conn& hc = *st.conn;
    st.end_pending = true;
    if (!st.submitted)
    {
        // An answer with no head would be a broken stream; this one simply ends.
        ngtcp2_conn_shutdown_stream(hc.q, 0, st.sid, NGHTTP3_H3_INTERNAL_ERROR);
        close_conn(c);
        return;
    }
    // A body still coming that the answer did not need is not read.
    if (!st.remote_closed)
        ngtcp2_conn_shutdown_stream_read(hc.q, 0, st.sid, NGHTTP3_H3_NO_ERROR);
    h3_drop_rx(st);
    if (st.blocked)
    {
        st.blocked = false;
        nghttp3_conn_resume_stream(hc.h, st.sid);
    }
    h3_dirty_raw(hc);
}

// QUIC and HTTP/3 are done with the stream: its conn goes, if its answer has not already let it go.
void storage_run::h3_stream_closed(h3_conn& hc, int64_t sid)
{
    auto it = hc.streams.find(sid);
    if (it == hc.streams.end())
        return;
    auto sc = it->second;
    h3_drop_rx(*sc->h3s);
    sc->h3s->gone = true;
    hc.streams.erase(it);
    close_conn(sc);
}

void storage_run::h3_stream_gone(const std::shared_ptr<conn>& c)
{
    h3_stream& st = *c->h3s;
    if (st.gone || !st.conn)
        return;
    h3_drop_rx(st);
    st.gone = true;
    h3_conn& hc = *st.conn;
    // Ended before its answer did: the client is told the request was cancelled.
    if (!st.ended && hc.q && !hc.dead)
        ngtcp2_conn_shutdown_stream(hc.q, 0, st.sid, NGHTTP3_H3_REQUEST_CANCELLED);
    // The reset, or the window its unread body gave back, goes out.
    h3_dirty_raw(hc);
    if (hc.h)
        nghttp3_conn_set_stream_user_data(hc.h, st.sid, nullptr);
    hc.streams.erase(st.sid);
}

bool storage_run::h3_stream_drained(const conn& c) const
{
    const h3_stream& st = *c.h3s;
    return st.os != h3_stream::out_state::head && st.tx_given == st.tx_total;
}

// ─── Packets out, timers, ends ──────────────────────────────────────────────

void storage_run::h3_dirty(const std::shared_ptr<h3_conn>& hc)
{
    if (hc->dirty)
        return;
    hc->dirty = true;
    m_h3->dirty.push_back(hc);
}

void storage_run::h3_dirty_raw(h3_conn& hc)
{
    if (!hc.dirty && !hc.dead)
        h3_dirty(hc.shared_from_this());
}

void storage_run::h3_flush_dirty()
{
    if (!m_h3)
        return;
    std::vector<std::weak_ptr<h3_conn>> due;
    due.swap(m_h3->dirty);
    for (auto& w : due)
        if (auto hc = w.lock())
        {
            hc->dirty = false;
            if (!hc->dead)
                h3_write(hc);
        }
    // Streams whose bytes nghttp3 has all taken go on, as an HTTP/1.1 connection does when its write is done.
    h3_arm_timer();
}

void storage_run::h3_send(const sockaddr_storage& local, socklen_t, const sockaddr_storage& remote, socklen_t remote_len,
                          const uint8_t* data, size_t len, size_t gso)
{
    h3_endpoint& ep = *m_h3;
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
    const ssize_t n = ::sendmsg(ep.fd, &msg, MSG_DONTWAIT);
    if (n < 0) {}
    else
    {
        runtime_instance::stat_add(m_owner.m_stat_bytes_out, static_cast<uint64_t>(n));
        m_c.bytes_out += static_cast<uint64_t>(n);
    }
}

void storage_run::h3_write(const std::shared_ptr<h3_conn>& hc)
{
    h3_endpoint& ep = *m_h3;
    static const ngtcp2_write_pkt write_pkt = [](ngtcp2_conn* q, ngtcp2_path* path, ngtcp2_pkt_info* pi, uint8_t* dest,
                                                 size_t destlen, ngtcp2_tstamp ts, void* ud) -> ngtcp2_ssize
    {
        auto* hc = static_cast<h3_conn*>(ud);
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
        const ngtcp2_ssize n = ngtcp2_conn_write_aggregate_pkt2(hc->q, &ps.path, &pi, ep.txbuf.data(), ep.txbuf.size(),
                                                                &gso, write_pkt, gso_burst, ts);
        if (n < 0)
        {
            h3_close(hc);
            return;
        }
        ngtcp2_conn_update_pkt_tx_time(hc->q, ts);
        if (n == 0)
            break;
        h3_send(hc->local, hc->local_len, hc->remote, hc->remote_len, ep.txbuf.data(), static_cast<size_t>(n), gso);
    }
    // Streams whose bytes nghttp3 has all taken are told their write is done at the end of the turn.
    for (auto& [sid, sc] : hc->streams)
        if (!sc->dead && sc->after_write != conn::after_kind::none && h3_stream_drained(*sc))
            m_h2_due.push_back(sc);
}

void storage_run::h3_arm_timer()
{
    h3_endpoint& ep = *m_h3;
    uint64_t soonest = UINT64_MAX;
    for (auto& hc : ep.conns)
        if (!hc->dead)
            soonest = std::min<uint64_t>(soonest, ngtcp2_conn_get_expiry2(hc->q));
    if (soonest == UINT64_MAX)
        return;
    if (ep.tm_armed && ep.tm_deadline <= soonest)
        return;
    if (ep.tm_armed && !m_loop.submit_timeout_remove(&ep.tm)) {}
    const uint64_t now = now_ns();
    const uint64_t wait = soonest > now ? soonest - now : 0;
    __kernel_timespec& ts = ep.ts[ep.ts_at ^= 1];
    ts.tv_sec = static_cast<long long>(wait / 1000000000ull);
    ts.tv_nsec = static_cast<long long>(wait % 1000000000ull);
    ep.tm = io_request{};
    ep.tm.owner = this;
    ep.tm_armed = m_loop.submit_timeout(&ts, &ep.tm);
    ep.tm_deadline = soonest;
}

void storage_run::h3_expire()
{
    h3_endpoint& ep = *m_h3;
    const uint64_t now = now_ns();
    std::vector<std::shared_ptr<h3_conn>> due;
    for (auto& hc : ep.conns)
        if (!hc->dead && ngtcp2_conn_get_expiry2(hc->q) <= now)
            due.push_back(hc);
    for (auto& hc : due)
    {
        const int r = ngtcp2_conn_handle_expiry(hc->q, now);
        if (r != 0)
        {
            // Idle past its timeout, or its handshake never finished: it is gone without a word.
            h3_drop(hc);
            continue;
        }
        h3_dirty(hc);
    }
    h3_flush_dirty();
}

void storage_run::h3_close(const std::shared_ptr<h3_conn>& hc)
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
            h3_send(hc->local, hc->local_len, hc->remote, hc->remote_len, buf, static_cast<size_t>(n), 0);
    }
    h3_drop(hc);
}

void storage_run::h3_drop(const std::shared_ptr<h3_conn>& hc)
{
    if (hc->dead)
        return;
    hc->dead = true;
    h3_endpoint& ep = *m_h3;
    std::vector<std::shared_ptr<conn>> all;
    for (auto& [sid, sc] : hc->streams)
        all.push_back(sc);
    hc->streams.clear();
    for (auto& sc : all)
    {
        sc->h3s->gone = true;
        sc->h3s->conn = nullptr;
        close_conn(sc);
    }
    for (const std::string& k : hc->cids)
        if (auto it = ep.by_cid.find(k); it != ep.by_cid.end() && it->second == hc)
            ep.by_cid.erase(it);
    std::erase(ep.conns, hc);
}

void storage_run::h3_stop()
{
    if (!m_h3)
        return;
    h3_endpoint& ep = *m_h3;
    // Every client is told the connection ends, as HTTP/2's GOAWAY tells it.
    auto all = ep.conns;
    for (auto& hc : all)
    {
        ngtcp2_ccerr_set_application_error(&hc->err, NGHTTP3_H3_NO_ERROR, nullptr, 0);
        h3_close(hc);
    }
    if (ep.tm_armed && !m_loop.submit_timeout_remove(&ep.tm)) {}
    if (ep.fd >= 0)
    {
        m_loop.close_fd(ep.fd);
        ep.fd = -1;
    }
}

}   // namespace socketley::storage

#else   // !SOCKETLEY_HTTP3

namespace socketley::storage
{
struct h3_endpoint {};
struct h3_stream {};
void h3_endpoint_free::operator()(h3_endpoint* e) const { delete e; }
void h3_stream_free::operator()(h3_stream* s) const { delete s; }
// Built without HTTP/3: no endpoint is ever opened, so no stream or request of its own reaches these.
bool storage_run::h3_open(uint16_t, uint16_t, bool, const std::string&, const std::string&) { return false; }
bool storage_run::h3_owns(io_request*) const { return false; }
void storage_run::h3_cqe(io_request*, int) {}
void storage_run::h3_pull(const std::shared_ptr<conn>&, std::string_view) {}
void storage_run::h3_stream_out(const std::shared_ptr<conn>&, std::string) {}
void storage_run::h3_stream_end(const std::shared_ptr<conn>&) {}
void storage_run::h3_stream_gone(const std::shared_ptr<conn>&) {}
bool storage_run::h3_stream_drained(const conn&) const { return true; }
void storage_run::h3_flush_dirty() {}
void storage_run::h3_stop() {}
}   // namespace socketley::storage

#endif
