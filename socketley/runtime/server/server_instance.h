#pragma once
#include "../../shared/loop/fd_table.h"
#include "../../shared/net/async_resolver.h"
#include "../../shared/net/conn_reachability.h"
#include "../../shared/http/http_framing.h"
#include <string>
#include <string_view>
#include <unordered_map>
#include <memory>
#include <vector>
#include <chrono>
#include <netinet/in.h>
#include <sys/uio.h>
#include <unistd.h>
#include <cstdlib>
#include <filesystem>
#include <sys/stat.h>

#include "../../shared/net/conn_identity.h"
#include "../../shared/runtime/runtime_instance.h"
#include "../../shared/net/unix_companion.h"
#include "../../shared/loop/write_queue.h"
#include "../../shared/net/direct_send.h"
#include "../../shared/loop/event_loop_definitions.h"
#include "../../shared/ipc/request_channel.h"
#include "../../shared/crypto/tls_context.h"
#include "../../shared/util/transparent_string.h"
#include "../../shared/http/ws_protocol.h"
#include <linux/time_types.h>

class runtime_manager;

// tls_conn_state lives in shared/crypto/tls_context.h, included above: the proxy runs
// the same state machine on both of its legs, and a second spelling of it
// would be a second thing to keep in step.

enum proto_state : uint8_t {
    proto_unknown     = 0,
    proto_tcp         = 1,  // newline-delimited text
    proto_http        = 2,  // HTTP request (not WS upgrade)
    proto_ws_upgrading = 3,
    proto_ws          = 4,  // active WebSocket
    proto_resp        = 5   // RESP2 wire protocol
};

// Declared ahead of server_connection because a connection holds one while
// it streams a body: the views below point into the head the connection
// owns, not into the buffer the body is being erased from.
struct http_request
{
    std::string_view method;
    std::string_view path;
    std::string_view version;
    std::string_view body;
    std::string_view query;  // everything after '?'
    std::vector<std::pair<std::string_view, std::string_view>> headers;
    int client_id{-1};
};

// A relayed message held for a connection that has not said what it speaks,
// with the kind its sender gave it so a websocket still gets that opcode.
struct held_relay
{
    std::shared_ptr<const std::string> msg;
    ws_kind kind;
};

inline size_t write_queue_size_of(const held_relay& h)
{
    return socketley::write_queue_size_of(h.msg);
}

struct alignas(64) server_connection
{
    static constexpr size_t MAX_WRITE_BATCH = 32;

    // How large a coalesced entry may grow, the same 64 KB the cache uses and
    // for the same reason: past this the entry is large enough that another
    // one costs nothing worth saving.
    static constexpr size_t WRITE_COALESCE_LIMIT = 64 * 1024;
    static constexpr size_t READ_BUF_SIZE = 16384;  // 16KB read buffer

    // === HOT fields (CQE dispatch path) — first 2 cache lines ===
    int fd{-1};
    int fixed_idx{-1};       // io_uring fixed file table index (-1 = not registered)
    // Identity of the connection currently in this struct, because structs are
    // pooled and descriptor numbers reissued, so same address and same fd is
    // not the same connection.
    uint32_t generation{0};
    // The half of this connection's conn_ref that varies, 64 bits and per
    // runtime, because `generation` above is the loop's stamp and wraps.
    uint64_t ref_serial{0};
    bool direct_fd{false};   // true if fd came from direct-accept (fixed file index)
    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};
    proto_state proto{proto_unknown};
    bool routed{false};
    bool file_read_pending{false};
    bool http_keep_alive{false};
    // The request being answered is a HEAD, read by queue_http_response()
    // alone so no emitter has to know.
    bool http_head{false};
    bool wr_shutdown{false};   // our FIN is already on the wire (shutdown SHUT_WR)
    // Refused mid-request, so what the peer is still sending is read away
    // after our FIN until its EOF, header_deadline, or the byte bound.
    bool drain_on_close{false};
    // What a closing connection read and threw away while its FIN was out.
    uint32_t drained_bytes{0};
    // This runtime closed the connection because the producer outran the
    // socket, not because the peer went away.  Sticky, and read by the refusal
    // a script gets so it can tell "slow down" from "it is gone".
    bool closed_for_backlog{false};
    // The queue has been over the backpressure watermark since the last time
    // on_writable fired, so the next crossing back down owes the script a
    // call.  Edge-triggered: cleared when the call is queued, which is what
    // keeps a draining 8 MiB queue from firing once per completion.
    bool drain_wanted{false};
    uint32_t active_idx{0};  // index in m_active_fds for O(1) removal
    uint32_t write_batch_count{0};

    // Non-null only with --tls, on a memory BIO pair nothing the kernel holds
    // ever names, and freed only by this struct -- which is what makes freeing
    // it never have to wait on the ring.
    SSL* ssl{nullptr};
    tls_conn_state tls_state{tls_conn_none};
    // The peer's close_notify, remembered rather than acted on, because the
    // read that carries it can carry the last request ahead of it.
    bool tls_peer_closed{false};
    // When the handshake began, which the deadline reads instead of
    // last_activity.  last_activity is refreshed on every read -- but only when
    // --idle-timeout is set, so the deadline silently changed meaning with a
    // flag that has nothing to do with it: measured, a peer dribbling one byte
    // every twenty seconds inside an unfinished record held its slot for ever
    // WITH --idle-timeout and lost it in 63 seconds without.  Flat, like the
    // client's, because a handshake is bounded by round trips and not by data.
    std::chrono::steady_clock::time_point handshake_since{};
    // An HTTP head that has arrived in part and stopped.  The size of one is
    // bounded at 16 KB in parse_partial(); the time was not, so a peer that
    // sent a request line and nothing else held its slot against
    // --max-connections until it chose to let go.  Dated from the first
    // incomplete read and never renewed, for the reason the proxy's own arm
    // gives: renewing it hands the bound back to the client.
    bool awaiting_headers{false};
    std::chrono::steady_clock::time_point header_deadline{};

    io_request read_req;
    io_request write_req;

    // === WARM fields (message processing path) ===
    std::string partial;
    socketley::byte_counted_queue<socketley::write_chunk> write_queue;

    // Relay traffic that arrived before this connection said what it speaks,
    // held rather than dropped because writing it early puts it in front of
    // the response the client is parsing for, and released by
    // relay_hold_flush() or by the deadline.
    socketley::byte_counted_queue<held_relay> relay_hold;

    // When this hold started, measured from the first message held rather than
    // from the accept, because until there is traffic to hold there is nothing
    // to be late for.
    std::chrono::steady_clock::time_point relay_hold_since{};

    // Has this client ever sent a byte of application data, sticky, because a
    // connection that has spoken is waiting for an answer relay bytes would
    // land in front of and only one that has not gets a deadline.
    bool spoke{false};

    // Has this connection ever been HTTP, sticky because `proto` is reset
    // after every keep-alive response and a connection that forgot would
    // rejoin the relay set between two requests.
    bool http_seen{false};

    // writev batch: holds refs alive until CQE completes
    socketley::write_chunk write_batch[MAX_WRITE_BATCH];
    struct iovec write_iovs[MAX_WRITE_BATCH];

    // === COLD fields (rarely accessed per-CQE) ===

    // Async file read state (HTTP static file serving)
    io_request file_read_req;
    int file_fd{-1};
    char* file_buf{nullptr};
    size_t file_size{0};
    std::string file_content_type;
    bool file_is_html{false};
    // Set only when this read is a candidate for the revalidating cache, so
    // handle_file_read knows which key to store under; empty means do not
    // store.
    std::string file_url_path;
    struct stat file_st{};

    // Splice state for zero-copy file serving (non-HTML only)
    io_request splice_in_req;
    io_request splice_out_req;
    int splice_file_fd{-1};
    // This connection's own pipe, not the runtime's.  One shared pipe meant
    // exactly one connection could take the zero-copy path at a time, and
    // everything else fell back to read+write -- measured at 975 us against
    // 6087 on a 4 MiB file, so the second concurrent download paid 6.2x for
    // being second.  Owned here, it also cannot carry one response's leftover
    // bytes into another's, which is what the drain loop in splice_cleanup()
    // existed to prevent.
    int splice_pipe[2]{-1, -1};
    size_t splice_remaining{0};
    // ─── A request body being streamed rather than gathered ─────────────
    // How many body bytes are still owed for the request whose headers were
    // already parsed, and the head itself, owned -- because the point of
    // streaming is that `partial` is erased as the body arrives, and the views
    // an http_request holds into it would dangle.  The proxy keeps the same
    // two things for the same reason, as saved_request and body_remaining.
    size_t body_remaining{0};
    // ── A file sent in pieces, for a connection with no splice arm ──────────
    // TLS cannot be spliced -- that would hand the peer plaintext inside an
    // encrypted stream -- so before this a TLS listener answered every request
    // by allocating the whole file and then building the response around it:
    // measured, one request for a 256 MB file took the worker to 505 MB and
    // three at once to 1,250 MB, with the client deciding how many there are.
    // Here the memory is one piece plus whatever the write queue holds, and
    // neither follows the file's size.
    int      stream_fd{-1};
    // Read into directly and then MOVED into the queue, so a piece is copied
    // zero times on its way out.
    std::string stream_buf;
    uint64_t stream_offset{0};
    uint64_t stream_remaining{0};
    bool     stream_pending{false};
    io_request stream_req{};

    // Set when a body was finished straight out of the read buffer, which
    // leaves body_remaining at 0 and body_chunked false -- the two things
    // parse_partial() looks at to decide whether a body is in progress.  Without
    // it the request that body belonged to would never be answered.
    bool body_done_pending{false};
    // Chunked has no length to count down, so body_remaining stays 0 and this
    // is what says a body is still owed.  The decoder holds the position in the
    // framing across reads.
    bool body_chunked{false};
    http_chunked_decoder chunk_dec;
    // A response the script is writing itself.  Two flags and not one: the
    // fall-through to the static file and the 404 must not also answer
    // (response_started), and a HEAD gets the headers and no body at all, so
    // whether chunks may be queued is a separate question (chunked_response).
    bool response_started{false};
    bool chunked_response{false};
    std::string http_head_saved;
    // Parsed once, at the top of the exchange, with its views rebased onto the
    // string above -- so the streamed request and a gathered one cannot come to
    // different conclusions about the same head.
    http_request http_req_saved;
    // The header list a gathered request borrows and hands back empty, so a
    // keep-alive connection grows it once rather than once per request.
    std::vector<std::pair<std::string_view, std::string_view>> http_hdr_scratch;

    // A 206 in progress: where the slice starts, and the file's whole length,
    // which Content-Range has to state and Content-Length must not.
    size_t range_first{0};
    size_t range_total{0};
    bool   is_range{false};
    uint32_t splice_pipe_pending{0};
    // Headers are queued and the file→pipe splice starts once they are on the
    // wire; this says the transfer is owed, not that an op is armed.
    bool splice_pending{false};
    // These two say an op is armed, unlike the splice bookkeeping
    // splice_cleanup zeroes, which made a guard true and freed the connection
    // with a splice still running.
    bool splice_in_pending{false};
    bool splice_out_pending{false};

    // WebSocket handshake headers (non-empty only for ws_active connections)
    std::string ws_cookie;
    std::string ws_origin;
    std::string ws_protocol;  // Sec-WebSocket-Protocol
    std::string ws_auth;      // Authorization

    // Rate limiting (token bucket)
    double rl_tokens{0.0};
    double rl_max{0.0};
    std::chrono::steady_clock::time_point rl_last{};

    // Master auth attempt tracking
    uint8_t auth_failures{0};

    // Cache requests this connection has not been answered yet, a count and
    // not a queue because the channel answers one origin in order -- and
    // nothing in flight points into this struct.
    uint32_t cache_pending{0};

    // WebSocket fragment reassembly (zero-alloc, in-place compaction in partial)
    size_t ws_frag_len{0};
    uint8_t ws_frag_opcode{0};

    // Idle connection tracking
    std::chrono::steady_clock::time_point last_activity{};

    // Pipe pairing: fd of peer connection for zero-copy forwarding (-1 = not piped)
    int pipe_peer_fd{-1};

    // Per-connection metadata (freed automatically on disconnect)
    std::unordered_map<std::string, std::string> meta;

    // Multicast group memberships (cleaned up on disconnect)
    std::vector<std::string> groups;

    // The last of four arms -- a bundle, plain multishot, a provided-buffer
    // read, and only then a plain read into this -- so a start with a buffer
    // ring never writes to it.  Held rather than freed once taken, so no read
    // can be armed on storage that has gone.
    std::unique_ptr<char[]> read_buf;

    // What a struct owns that no container releases for it, because a
    // connection retired with a file read in flight never reaches
    // pool_release() if the runtime stops first -- and a plain close is right,
    // since the instance only goes away once the ring owes it nothing.
    ~server_connection()
    {
        free(file_buf);
        if (file_fd >= 0)        close(file_fd);
        if (splice_file_fd >= 0) close(splice_file_fd);
        if (stream_fd >= 0)      close(stream_fd);
        // The session, for a struct that never reached pool_release(), safe
        // here because no submission ever named it.
        tls_context::free_ssl(ssl);
    }

    server_connection() = default;
    server_connection(const server_connection&) = delete;
    server_connection& operator=(const server_connection&) = delete;

    // Connection pool support: reset to initial state for reuse
    void reset(int new_fd)
    {
        fd = new_fd;
        fixed_idx = -1;
        // Cleared and not carried, because leaving the previous connection's
        // serial in a struct handed to a new client is the defect one level
        // up.
        ref_serial = 0;
        direct_fd = false;
        // pool_release() already did this, repeated because a struct leaving
        // the pool must not carry the previous connection's session under any
        // circumstances.
        tls_context::free_ssl(ssl);
        ssl = nullptr;
        tls_state = tls_conn_none;
        tls_peer_closed = false;
        read_req = {};
        write_req = {};
        write_queue.clear();
        // The previous occupant's unclassified relay traffic must not be
        // handed to this one.
        relay_hold.clear();
        relay_hold_since = {};
        // A struct that carried a client which had spoken would otherwise hand
        // the next one a permanent exemption from the deadline.
        spoke = false;
        // And a struct that carried an HTTP client would hand the next one a
        // permanent exclusion from the relay, silently receiving nothing.
        http_seen = false;
        for (uint32_t i = 0; i < write_batch_count; i++) write_batch[i].clear();
        write_batch_count = 0;
        read_pending = false;
        write_pending = false;
        closing = false;
        // With `closing`, and for the same reason the neighbours above give:
        // a struct that carried a producer which outran the socket would hand
        // the next client on this slot a backlog it never had, and self.send()
        // would name backpressure for a connection that simply went away.
        closed_for_backlog = false;
        // And the next client would be owed an on_writable for a queue it
        // never filled.
        drain_wanted = false;
        if (file_fd >= 0) { close(file_fd); file_fd = -1; }
        if (file_buf) { free(file_buf); file_buf = nullptr; }
        file_read_req = {};
        file_size = 0;
        file_content_type.clear();
        file_is_html = false;
        file_url_path.clear();
        file_st = {};
        file_read_pending = false;
        splice_in_req = {};
        splice_out_req = {};
        if (splice_file_fd >= 0) { close(splice_file_fd); splice_file_fd = -1; }
        splice_remaining = 0;
        // A struct that carried a half-received body would take the next
        // client's first bytes for the rest of somebody else's upload.
        body_remaining = 0;
        body_chunked = false;
        body_done_pending = false;
        // A struct that carried a half-sent file would send the rest of it to
        // whoever gets this descriptor next.
        if (stream_fd >= 0) { close(stream_fd); stream_fd = -1; }
        stream_buf.clear();
        stream_buf.shrink_to_fit();
        stream_offset = 0;
        stream_remaining = 0;
        stream_pending = false;
        stream_req = {};
        response_started = false;
        chunked_response = false;
        chunk_dec = http_chunked_decoder{};
        http_head_saved.clear();
        http_req_saved = http_request{};

        // With the rest of the per-response state: a struct that carried a
        // 206 would answer the next client's whole-file request with that
        // slice's headers.
        range_first = 0;
        range_total = 0;
        is_range = false;
        splice_pipe_pending = 0;
        splice_pending = false;
        splice_in_pending = false;
        splice_out_pending = false;
        http_keep_alive = false;
        http_head = false;
        proto = proto_unknown;
        routed = false;
        ws_cookie.clear();
        ws_origin.clear();
        ws_protocol.clear();
        ws_auth.clear();
        rl_tokens = 0.0;
        rl_max = 0.0;
        auth_failures = 0;
        cache_pending = 0;
        ws_frag_len = 0;
        ws_frag_opcode = 0;
        pipe_peer_fd = -1;
        // A slot comes back from the pool for a new peer, and a clock left
        // running belongs to the last one -- which would drop the new peer
        // mid-head for something its predecessor did.
        awaiting_headers = false;
        header_deadline = {};
        partial.clear();
        meta.clear();
        groups.clear();
    }
};


enum server_mode : uint8_t
{
    mode_inout  = 0,
    mode_in     = 1,
    mode_out    = 2,
    mode_master = 3
};

// Who a message reaches when no script answers it, which --mode never said: it
// names a direction, and every one of these is bidirectional.  Until this was a
// choice the answer was `others` over TCP and `all` over UDP, from two code
// paths that were meant to agree.
//
// A SET, and a set of DISJOINT recipients.  Disjoint because `others` meaning
// "everyone else" would make `others,master` mean exactly `others`, and one
// behaviour under two spellings is what this file already refused once: the
// master is named separately, so `others` is everyone else who is not it.
// `all` is not a value for the same reason -- `sender,others` says it.
enum server_send_to : uint8_t
{
    send_to_unset  = 0,        // whatever this mode has always done, see below
    send_to_sender = 1u << 0,  // the connection the message came from
    send_to_others = 1u << 1,  // every other connection, the master excepted
    send_to_master = 1u << 2   // the master, which only mode_master has at all
};

// The whole rule binding --mode to the three flags that only mean something in
// some of its answers, in one place because a command line is not the only way
// this set arrives: a state file carries it too, and the boot restore that
// reads one used to start a runtime no `create` would have accepted.
//
// Judged as a set and never per flag, since --mode may be typed on either side
// of any of them, and returned as a message rather than a bool so the caller
// can say which half is wrong.
// The port a server listens on when none was configured.  Named once because
// setup() and listen_addresses() have to answer with the same number, which is
// the reason the companion node in setup() is careful to ask get_port() rather
// than the local variable this default has already been written into.
inline constexpr uint16_t server_default_port = 8000;

inline std::string server_mode_config_refusal(server_mode mode,
                                              uint8_t     send_to,
                                              bool        udp,
                                              bool        has_master_pw)
{
    // Per RECIPIENT and not per flag: `in` and `out` answer nobody at all, so
    // no recipient means anything there, while `master` names a connection
    // that only mode_master ever claims.
    if (send_to != send_to_unset)
    {
        if (mode == mode_in || mode == mode_out)
            return "--send-to needs --mode inout or master: this mode carries "
                   "messages one way and never answers one\n";

        if ((send_to & send_to_master) && mode != mode_master)
            return "--send-to master needs --mode master: nothing claims the "
                   "master connection in any other mode, so there is nobody to "
                   "send to\n";
    }

    // Master mode claims a CONNECTION as the master and a datagram has none,
    // so process_message() reached the mode_master case with a null sender and
    // a packet beginning "master " dereferenced it.  The case guards that line
    // as well; this is the refusal that makes the documented promise true.
    if (udp && mode == mode_master)
        return "--udp cannot be combined with --mode master: master mode claims "
               "one connection as the master and a datagram is not a "
               "connection\n";

    // The "master " prefix is read in exactly one place, the mode_master case,
    // so in any other mode the password is not a credential -- it is an
    // ordinary message, and the client that types it has its password relayed
    // to every other connection verbatim.
    if (has_master_pw && mode != mode_master)
        return "--master-pw needs --mode master: no other mode reads the "
               "\"master \" prefix, so the password is not a credential there "
               "-- it is an ordinary message and is relayed to the other "
               "connections verbatim\n";

    return {};
}

struct upstream_target
{
    std::string address;        // "host:port" as specified by user
    std::string resolved_host;
    uint16_t resolved_port{0};
};

struct upstream_connection
{
    static constexpr size_t MAX_WRITE_BATCH = 32;

    // How large a coalesced entry may grow, the same 64 KB the cache uses and
    // for the same reason: past this the entry is large enough that another
    // one costs nothing worth saving.
    static constexpr size_t WRITE_COALESCE_LIMIT = 64 * 1024;
    static constexpr size_t READ_BUF_SIZE = 16384;  // 16KB read buffer

    int conn_id;                  // 1-based Lua-facing ID (stable across reconnects)
    int fd{-1};
    // Same purpose as server_connection::generation: an upstream socket's fd
    // number can be reissued to an accepted client, and the client index is
    // consulted first, so the completion needs to say which one it belongs to.
    uint32_t generation{0};
    upstream_target target;
    io_request read_req;
    io_request write_req;
    char read_buf[READ_BUF_SIZE];
    std::string partial;
    socketley::byte_counted_queue<socketley::write_chunk> write_queue;
    socketley::write_chunk write_batch[MAX_WRITE_BATCH];
    struct iovec write_iovs[MAX_WRITE_BATCH];
    uint32_t write_batch_count{0};
    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};
    bool connected{false};
    // Whether the kernel says the far end accepted, which is a different
    // question from whether this runtime holds a socket for it -- see
    // note_upstream_established().  The send paths ask `connected`, because a
    // write during a handshake belongs in the queue; the stats and the Lua
    // callback ask this one, because both are claims about the far end.
    bool established{false};
    // An upstream's write queue fills the same way a client's does, so it
    // carries the same sticky fact: this runtime closed the connection because
    // the producer outran the socket, and not because the peer went away.
    // Without it a script's next upstream_send() is answered "is not
    // connected", which is the peer's sentence for this runtime's decision.
    bool closed_for_backlog{false};
    // Armed at the soft watermark, on the size a message LEAVES behind: a
    // producer pacing on upstream_pending() stops on that same number, so
    // arming on the size before the push arms one send too late.
    bool drain_wanted{false};
    int reconnect_attempt{0};
    io_request timeout_req{};
    struct __kernel_timespec timeout_ts{};
    // A reconnect timer is not attached to an fd, so nothing a stop does can
    // cancel it; it stays armed on this struct for up to 30 seconds.
    bool timeout_pending{false};

    // Resolved endpoint kept across reconnects, because upstream_try_connect
    // runs on the event loop thread and a flapping upstream would look up the
    // name once per attempt.
    struct sockaddr_in cached_addr{};
    bool has_cached_addr{false};
    // The name is being looked up off the loop, so the next attempt comes in a tenth of a second and counts no backoff.
    bool resolving{false};
};

#ifndef SOCKETLEY_NO_LUA
class callback_conn_scope;
#endif

class server_instance : public runtime_instance, public request_origin
{
public:
    server_instance(std::string_view name);
    ~server_instance() override;

    // See runtime_instance::as_server(): this class is what the question is
    // asking for.
    server_instance* as_server() override { return this; }

    // The four flags that are one answer, asked of this object so that a state
    // file carrying a set no parser ever saw is refused at start.
    std::string config_refusal() const override
    {
        return server_mode_config_refusal(m_mode, m_send_to, m_udp,
                                          !m_master_pw.empty());
    }

    void set_mode(server_mode mode);
    server_mode get_mode() const;

    // A mask of server_send_to bits, or send_to_unset to let the mode decide:
    // inout has always answered `others` and master has always dropped what a
    // non-master said, and an unset flag keeps both.
    void set_send_to(uint8_t mask);
    uint8_t get_send_to() const;

    void set_udp(bool udp);
    bool is_udp() const override;

    // How many bytes are queued for this connection and not yet on the wire,
    // and whether the runtime closed it because that number reached the bound.
    // A producer that can ask this can pace; one that cannot finds out by
    // having its connection taken away.  -1 for an id that is not a connection
    // of this runtime, which a caller has to tell from 0.
    // The id-taking forms, which is what a script has: a connection pointer is
    // this runtime's own currency and never leaves it.
    bool begin_chunked_response(int client_id, int status,
                                const std::vector<std::pair<std::string, std::string>>& headers);
    bool send_response_chunk(int client_id, std::string_view data);
    bool finish_chunked_response(int client_id);

    long     pending_bytes(int client_id) const;
    bool     closed_for_backlog(int client_id) const;
    // The upstream side of the same two questions.  A separate id space, so a
    // separate call: self.pending() resolves a CLIENT id and an upstream is in
    // another map entirely.
    long     upstream_pending(int conn_id) const;
    bool     upstream_closed_for_backlog(int conn_id) const;

    // What setup() will bind, answered without binding it; see the base class.
    void listen_addresses(std::vector<std::string>& out) const override;
    uint16_t effective_port() const override;

    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;

private:
    // The invocation and which of its awaits each self.cache request answers, by the request's own key.
    std::unordered_map<uint32_t, std::pair<uint32_t, uint32_t>> m_awaits;
    uint32_t m_await_key{0};
    // The two listeners setup() chooses between, each of which opens and binds
    // m_listen_fd or returns false, with everything after that point the same
    // for both.
    bool setup_tcp_listener(uint16_t port);
    bool setup_unix_listener(const std::string& path);

public:

    // A runtime whose own verbs collide with the sniffer's -- a store speaking
    // GET and PUT reads as HTTP -- declares its wire protocol here and is not
    // sniffed; proto_unknown, the default, keeps the auto-detection.
    void set_wire_protocol(proto_state p) { m_wire_protocol = p; m_wire_protocol_declared = true; }

    // Whether the type spoke, which is not what it said: a registered type
    // that asks for proto_unknown wants the sniffer, and one that never called
    // set_wire_protocol() has said nothing at all.
    bool wire_protocol_declared() const { return m_wire_protocol_declared; }

    size_t get_connection_count() const override;
    // The bytes this server owes across every queue it holds; see the definition
    // for why it is summed rather than tracked.
    size_t total_queued_bytes() const override;

    // Lua actions
    fanout_count broadcast(std::string_view msg) override;
    bool send_to(int client_id, std::string_view msg) override;
    bool        disconnect(int client_fd);
    std::string peer_ip(int client_fd);

    // Lua client enumeration + multicast
    std::vector<int> clients();
    int handle_for_sibling_ref(const conn_ref& r);
    size_t multicast(const std::vector<int>& fds, std::string_view msg);

    // Lua per-connection metadata
    bool        set_data(int fd, std::string_view key, std::string_view val);
    bool        del_data(int fd, std::string_view key);
    std::string get_data(int fd, std::string_view key) const;

    // Multicast groups
    bool join_group(int fd, std::string_view group);
    bool leave_group(int fd, std::string_view group);
    size_t group_send(std::string_view group, std::string_view msg);

    // Zero-copy pipe pairing (data forwarded directly, bypasses Lua callbacks)
    bool pipe(int fd_a, int fd_b);
    bool unpipe(int fd);

    struct ws_headers_result {
        bool is_websocket{false};
        std::string cookie, origin, protocol, auth;
    };
    ws_headers_result ws_headers(int client_fd) const;

    // C++ WebSocket callback
    void set_on_websocket(std::function<void(int fd, const ws_headers_result&)> cb);

    // Stats
    std::string stats_lines() const override;

    // ── Client routing ──────────────────────────────────────────────────────
    // The Lua-facing half, taking a descriptor or a routed handle and never a
    // conn_ref, with `err` filled in because the reason may be the daemon's
    // words rather than a guess this side would render.
    bool route_client(int client_id, std::string_view target_name,
                      std::string* err = nullptr);
    bool unroute_client(int client_id);
    std::string_view get_client_route(int client_id) const;
    bool send_to_client(int client_id, std::string_view msg);

    // owner_send resolves a handle rather than writing a sub-server's
    // descriptor number into the owner's table, and a handle whose connection
    // has gone resolves to nothing.
    bool owner_send(int client_id, std::string_view msg);
    bool owner_broadcast(std::string_view msg);

    // ── The cross-runtime interface ─────────────────────────────────────────
    // Everything one runtime does to another's connection goes through these
    // four, each taking a conn_ref, so the in-process form and the form
    // arriving over a socket are the same call -- and accept_routed mints a
    // local handle or returns -1.
    int accept_routed(const conn_ref& ref, std::string_view origin_name);

    // Called on the receiving runtime: the connection is gone.
    void release_routed(const conn_ref& ref);

    // Both directions at once for a runtime that has stopped, idempotent
    // because in one process this arrives second and finds nothing while
    // across processes it arrives first.
    void forget_runtime(std::string_view gone);

    // Called on the owning runtime by a receiver that is shutting down,
    // leaving the connection itself untouched and served here again.
    void drop_route(const conn_ref& ref);

    // Called on the receiving runtime: bytes arrived from it.
    void deliver_routed(const conn_ref& ref, std::string_view msg);

    // Called on the owning runtime to write to one of its connections by name,
    // false when the ref names nothing here any more.
    bool write_to_ref(const conn_ref& ref, std::string_view msg);

    // The name of one of this runtime's own connections, for a caller about to
    // hand it to another runtime, invalid for a descriptor this runtime does
    // not hold.
    conn_ref ref_for_fd(int fd) const;

    // Master mode
    void set_master_pw(std::string_view pw);
    std::string_view get_master_pw() const;

    // HTTP static file serving
    void set_http_dir(std::string_view path);
    const std::filesystem::path& get_http_dir() const;
    void set_http_cache(bool enabled);
    bool get_http_cache() const;
    void rebuild_http_cache();

    // False when the address named a port that cannot work, storing nothing in
    // that case.
    [[nodiscard]] bool add_upstream_target(std::string_view addr);
    // What a refused upstream is answered with, one line.
    static std::string upstream_refusal(std::string_view addr)
    {
        return "invalid upstream address: " + std::string(addr) + " (the port must be a number between 1 and 65535)\n";
    }
    void clear_upstream_targets();
    const std::vector<upstream_target>& get_upstream_targets() const;

    // Lua upstream actions
    // Answers whether the bytes were taken, which was unconditionally `true`:
    // it tested only `connected`, and a queue that had reached its bound set
    // `closing` without clearing `connected` -- so every later send reported
    // success for ever while nothing left the process.
    bool upstream_send(int conn_id, std::string_view msg);
    // What it reached, counted like the client-facing broadcast's.
    fanout_count upstream_broadcast(std::string_view msg);
    std::vector<int> upstreams() const;

    // ── request_origin ──────────────────────────────────────────────────────
    // An answer from the linked cache one turn later, whose cookie names the
    // connection and the identity it had, so a client that has gone fails the
    // compare and the answer is dropped.
    void on_request_reply(uint64_t cookie, request_status st,
                          std::string_view reply) override;

#ifndef SOCKETLEY_NO_LUA
    // ── self.cache(command) from a script ───────────────────────────────────
    // Post the command and leave the calling handler stopped until the cache
    // answers; see runtime_instance::begin_cache_await for what the answer
    // means.
    const char* begin_cache_await(lua_State* th, std::string_view cmd) override;

    // How long a handler may stay stopped on one await before it is told the
    // answer is not coming.  Not the callback deadline, which bounds how long a
    // handler may HOLD the loop: this one bounds how long it may be off it, and
    // the wait is somebody else's process, so the number is the one the request
    // path already uses for a peer that has stopped talking.
    static constexpr uint32_t cache_await_ms = 10000;

    // Come back for handlers whose answer never arrived.  Armed only while at
    // least one is waiting, so a server whose script never awaits puts no timer
    // in the ring.
    void arm_await_sweep();

    // Let go of the connection an await was holding open, and finish the close
    // it was deferring if that was the last answer owed.
    void release_await_hold(uint64_t ctx);

    // The same hold for an await that is not the linked cache's, such as a
    // socketley.storage call, charged the way a cache answer is so the two
    // share one cap and one release.
    void hold_answering_connection(uint64_t& ctx) override;
#endif

private:
    proto_state m_wire_protocol{proto_unknown};
    bool        m_wire_protocol_declared{false};

#ifndef SOCKETLEY_NO_LUA
    friend class callback_conn_scope;

    // Which connection the callback now running is serving, so an await started
    // inside it knows whose socket to hold open.  Null between callbacks, and
    // null inside one that is answering nobody -- a tick, or a message routed
    // here from another runtime, whose connection lives somewhere else.
    server_connection* m_callback_conn{nullptr};
#endif

    // Ask the linked cache something on behalf of `conn`, where `silent` is
    // the auto-store, which wants no answer and is not charged to the
    // connection.
    void post_cache_request(server_connection* conn, std::string_view payload, bool silent);

    // How many unanswered cache requests one connection may have, well above
    // what a 16 KB read can hold, with a close rather than a refusal because a
    // refusal would overtake the answers queued ahead of it.
    static constexpr uint32_t MAX_CACHE_PENDING = 4096;

    // What one unclassified connection may accumulate before the oldest held
    // message is dropped, sized for the accept-to-classification window rather
    // than for a backlog -- and dropping the oldest beats growing,
    // disconnecting or blocking.
    static constexpr size_t RELAY_HOLD_MAX_BYTES = 64 * 1024;

    // How long relay traffic is held for a connection that has said nothing,
    // 250 ms, because a pure listener is a legitimate client of an inout
    // server and would otherwise never be classified -- long enough to hear a
    // client that intends to speak, short enough not to read as a stall.
    static constexpr uint32_t RELAY_HOLD_DEADLINE_MS = 250;

    // Is this connection still waiting to be classified, where
    // proto_ws_upgrading counts because a handshake spanning several reads has
    // not queued its 101 yet.
    static bool proto_unsettled(const server_connection* conn)
    {
        return conn->proto == proto_unknown || conn->proto == proto_ws_upgrading;
    }

    // An HTTP connection is never a relay target at any point in its life, and
    // RESP is the same protocol shape and the same answer, because both
    // correlate replies to requests by order alone -- so there is no delay or
    // hold that makes an unsolicited line well formed.
    static bool relay_targetable(const server_connection* conn)
    {
        return !conn->http_seen && conn->proto != proto_resp;
    }

    // May the deadline release this connection's hold: still unclassified,
    // never spoken, and with any TLS handshake finished, since a session still
    // exchanging records has no keys to encrypt with.
    static bool relay_deadline_applies(const server_connection* conn)
    {
        return proto_unsettled(conn) && !conn->spoke
               && conn->tls_state != tls_conn_handshake;
    }

    // Hold one relayed message for a connection that has no protocol yet.
    void relay_hold_push(server_connection* conn,
                         const std::shared_ptr<const std::string>& msg,
                         ws_kind kind);

    // Release what was held once the protocol is known, from the one point
    // every path through handle_read reaches.
    void relay_hold_flush(server_connection* conn);

    // Arm the deadline timer if it is not already counting, one for the whole
    // instance, because a per-connection timeout would need a request and a
    // withdrawal on every close path.
    void relay_deadline_arm(uint32_t after_ms);

    // Everything whose deadline has passed, re-arming for the remainder rather
    // than the full deadline, which is what keeps the bound the number that is
    // written down.
    void relay_deadline_sweep();

    // ── the --cache auto-store ──────────────────────────────────────────────
    // A linked server's auto-store is accumulated per read and posted
    // together, because one entry per message dropped 88% of the writes on a
    // 200,000 message burst -- flushed wherever the batch could otherwise be
    // stranded.
    std::string m_cache_store_batch;
    // Flush at this size rather than only at the end of a read, so a single
    // enormous read cannot build an unbounded batch.
    static constexpr size_t CACHE_STORE_BATCH_BYTES = 32 * 1024;
    void flush_cache_store();

    void handle_accept(struct io_uring_cqe* cqe);

    // What an accepted descriptor goes through before it is a connection,
    // shared by the port's accept chain and the node's, because a connection
    // must mean the same thing whichever way it arrived.
    bool adopt_client(int client_fd, bool from_unix);

public:
    // The companion's re-arm, which has no completion of its own when the ring
    // refused the submission that would have produced one.
    void on_loop_turn() override;

private:
    void handle_read(struct io_uring_cqe* cqe, io_request* req);
    void handle_write(struct io_uring_cqe* cqe, io_request* req);
    void handle_file_read(struct io_uring_cqe* cqe, io_request* req);
    // Parses conn->partial and dispatches whatever whole messages are in it,
    // from handle_read and from the three completion arms that finish an async
    // HTTP response.
    void parse_partial(server_connection* conn);
    void handle_splice_in(struct io_uring_cqe* cqe, server_connection* conn);
    void handle_splice_out(struct io_uring_cqe* cqe, server_connection* conn);
    void splice_cleanup(server_connection* conn);
    void invoke_on_websocket(int fd);

    // Every descriptor this runtime gives back goes through here, because a
    // close does not withdraw an SQE that already carries the number --
    // through m_ring_loop, since descriptors are closed after teardown has
    // cleared m_loop.
    void close_tracked(int fd);

    // Is anything the kernel holds still naming this struct, asked once,
    // because each close path used to assemble its own list of flags and the
    // lists disagreed.
    bool conn_ops_pending(const server_connection* conn) const;

    // The same flags sorted by who is obliged to report them, which is the
    // seam between conn_reachability.h and this runtime's connection struct.
    socketley::reach::owed conn_owed(const server_connection* conn) const;

    // The one place a connection nothing is going to finish is finished,
    // called after every completion for the connection it named.
    void finish_unreachable_conn(int fd);
    // The single teardown for a client connection, legal only when
    // conn_ops_pending() is false.
    void close_conn(server_connection* conn, bool notify_disconnect = true);
    // Hand a connection struct back: to the pool when the ring is done with it,
    // to the retired list when it is not.
    void release_conn(std::unique_ptr<server_connection> conn);
    // Completions for retired connections and upstreams: recognised by the
    // address the kernel hands back, since they are no longer in any index.
    bool reap_retired(struct io_uring_cqe* cqe, io_request* req);
    // Give a provided buffer back when its completion is dropped, because the
    // group is shared by every server runtime on this loop.
    void return_provided_buf(struct io_uring_cqe* cqe);
    void arm_udp_recv();

#ifdef SOCKETLEY_INVARIANTS
    // Debug-only: asserts that a connection the runtime still has indexed
    // still has something that will wake it.
    void inv_check_reachable(int fd, const char* where);
#endif

    std::function<void(int, const ws_headers_result&)> m_cb_on_websocket;
    // `range_hdr` is the client's Range field as text, resolved against the
    // file's length here rather than at the caller, which does not know it
    // yet.  Empty means no Range, which is every request that is not a media
    // player seeking.
    // A pipe for this connection, or false when the cap is reached -- in which
    // case the caller serves the file the ordinary way, exactly as every
    // connection but the first used to.
    bool splice_pipe_acquire(server_connection* conn);
    // Idempotent, because it is reached from the response's end, from the
    // retire path and from pool_release, and only the first of those has to
    // happen for a connection that finished normally.
    void splice_pipe_release(server_connection* conn);

    // Hands whatever of the body is in `partial` to the script and erases it,
    // decrementing body_remaining.  Takes nothing and keeps nothing: the whole
    // point is that the runtime never holds the body.
    void deliver_body_chunks(server_connection* conn);
    // The same delivery straight out of the read buffer, for the case that needs
    // no accumulation at all; returns how many of those bytes were body.
    size_t deliver_body_span(server_connection* conn, const char* p, size_t n);

    // ── Sending a file in pieces ────────────────────────────────────────────
    // Above this size a file that cannot be spliced is streamed rather than
    // allocated whole.  Not lower, because one read of the whole thing is
    // cheaper when the whole thing is small, and a megabyte is already the cap
    // on what the revalidation map will hold.
    static constexpr size_t HTTP_STREAM_MIN   = 1u << 20;    // 1 MiB
    // One piece in flight, which is what the memory bound is made of.
    static constexpr size_t HTTP_STREAM_PIECE = 256u << 10;  // 256 KiB

    // Begins it: headers are already queued by the caller, this arms the first
    // read.  False if the read could not be armed at all.
    bool stream_file_begin(server_connection* conn, int ffd, uint64_t first, uint64_t len);
    // Arms the next piece, if one is owed and the queue has room for it.
    void stream_file_more(server_connection* conn, bool force = false);
    // A piece arrived: queue it, and either arm the next or wait for the drain.
    void handle_file_stream(struct io_uring_cqe* cqe, server_connection* conn);
    // Closes the descriptor and forgets the state, from every path that ends a
    // stream -- finished, refused or torn down.
    void stream_file_cleanup(server_connection* conn);
    // A response the script sends itself, in three steps.  Each answers
    // whether it was taken, which for the chunks is the backpressure that
    // makes a body larger than memory possible at all.
    bool begin_chunked_response(server_connection* conn, int status,
                                const std::vector<std::pair<std::string, std::string>>& headers);
    bool send_response_chunk(server_connection* conn, std::string_view data);
    bool end_chunked_response(server_connection* conn);
    // The body is complete: re-parse the saved head and dispatch the request
    // with an empty body, so the response path is the one it always was.
    void finish_streamed_body(server_connection* conn);

    void serve_http(server_connection* conn, const std::string& path,
                    std::string_view range_hdr = {});
    void handle_http_request(server_connection* conn, const http_request& req, size_t total_consumed);
    // `ends_exchange` false when bytes still follow or a refusal owns the teardown.
    void queue_http_response(server_connection* conn, std::shared_ptr<const std::string> resp,
                             bool ends_exchange = true);
    bool send_final_and_fin(server_connection* conn, std::string_view data);

    // Answer a request whose framing could not be established and end the
    // connection, in one function because a refusal that forgets to clear
    // `partial` leaves bytes the reparse loop reads as a fresh request.
    void refuse_http_request(server_connection* conn,
                             const std::shared_ptr<const std::string>& resp,
                             bool drain = true);

    // End a WebSocket connection over a frame that broke the protocol, with
    // the RFC 6455 7.4.1 code for what broke rather than a goodbye's 1000.
    void fail_ws_connection(server_connection* conn, uint16_t code = 1002);

    // Upstream helpers
    bool upstream_try_connect(upstream_connection* uc);
    void upstream_schedule_reconnect(upstream_connection* uc);
    void upstream_disconnect(upstream_connection* uc);
    void handle_upstream_read(struct io_uring_cqe* cqe, upstream_connection* uc);
    void handle_upstream_write(struct io_uring_cqe* cqe, upstream_connection* uc);
    // Answers whether the message was taken; see the definition.
    bool queue_upstream_send(upstream_connection* uc, const std::shared_ptr<const std::string>& msg);
    bool admit_upstream_send(upstream_connection* uc, size_t bytes);
    void upstream_flush_write_queue(upstream_connection* uc);
    bool upstream_send_direct(upstream_connection* uc);
    void invoke_on_upstream(int conn_id, std::string_view data);
    void invoke_on_upstream_connect(int conn_id);
    void note_upstream_established();
    // Set by a dial, cleared when every dialled upstream has answered.
    bool m_upstream_awaiting{false};
    void invoke_on_upstream_disconnect(int conn_id);

    // `kind` is what a WebSocket sender's frame said, kept by every relay below.
    void process_message(server_connection* sender, std::string_view msg,
                         ws_kind kind = ws_kind::by_payload);
    // Two exclusions, because `others` in master mode means everyone who is
    // neither the sender nor the master, and one of those is the only thing
    // this ever needed before.
    // Answers what it reached; see fanout_count.  A broadcast drops a client
    // whose queue is full exactly as a send does, and nothing counted it.
    // Where a broadcast is written once for all its recipients, whose queues
    // hold slices of it; see socketley::place_in_segment().
    std::shared_ptr<std::string> m_bcast_seg;
    std::shared_ptr<std::string> m_bcast_ws_seg;
    fanout_count queue_broadcast(const std::shared_ptr<const std::string>& msg, int exclude_fd,
                         int exclude_fd2 = -1, ws_kind kind = ws_kind::by_payload);
    void remove_active_fd(int fd);
    // `even_when_closing` is for an answer that was already promised, which
    // nothing else may set: the socket is still open precisely because that
    // answer is owed.
    // Answers whether the message was taken; see the definition for what a
    // false costs a caller that ignores it.
    // `ws_cache`, when given, is where the websocket frame for THIS payload is
    // kept: a server->client frame carries no per-recipient bit, so one set of
    // recipients needs one frame.  Null means "build it for this connection
    // alone", which is what a single send is.  group_send() and multicast()
    // were calling this per recipient and paying a UTF-8 pass, two allocations
    // and a full payload copy apiece -- O(N) where queue_broadcast() had long
    // been O(1).
    bool queue_send(server_connection* conn, const std::shared_ptr<const std::string>& msg,
                    bool even_when_closing = false,
                    std::shared_ptr<const std::string>* ws_cache = nullptr,
                    ws_kind kind = ws_kind::by_payload);

    // The same, for a caller that OWNS its bytes and has exactly one recipient
    // -- which is every self.send() and every reply to one client.  A
    // shared_ptr buys a fan-out the right to copy once for N connections; for
    // one connection it buys a second allocation and a queue entry that cannot
    // be coalesced, because appending to a payload others hold would change it
    // for them.  See write_queue.h on the three kinds of entry.
    bool queue_send(server_connection* conn, std::string&& msg,
                 bool even_when_closing = false, ws_kind kind = ws_kind::by_payload);

    // Whether this connection will take `bytes` more, and the two flags that
    // follow from the answer.  Extracted because both queue_send forms have to
    // agree: a bound enforced at one door and not the other is not a bound.
    void abandon_for_backlog(server_connection* conn);
    bool admit_send(server_connection* conn, size_t bytes, bool even_when_closing);
    void flush_write_queue(server_connection* conn);
    void submit_batch(server_connection* conn);
    bool send_direct(server_connection* conn);
    bool send_line_now(server_connection* conn, std::string_view msg, bool add_nl);
    bool send_ws_message(server_connection* conn, std::string_view msg);
    void submit_borrowed(server_connection* conn);
    void after_write(server_connection* conn);
    // A client's batch or an upstream's, which hold it in the same fields.
    template <class C> static void skip_written(C* conn, size_t written);

    // ── TLS record layer ────────────────────────────────────────────────────
    // OpenSSL does no I/O here: these two move bytes between the memory BIO
    // pair and the buffers io_uring uses, so everything above them sees the
    // same plaintext it always did.

    // Ciphertext in, driving the handshake and appending plaintext to
    // conn->partial, marking the connection closing on anything terminal while
    // an orderly close_notify lands in tls_peer_closed instead.
    void tls_feed(server_connection* conn, const char* data, size_t len);

    // Plaintext queue to SSL to one write submission, the only thing that puts
    // handshake records or alerts on the wire, at most one write exactly as
    // the cleartext path does.
    void tls_flush(server_connection* conn);

    // Has this connection bytes the ring has not been given, which for TLS the
    // write queue only half answers because a handshake record sits in the
    // write BIO.
    bool conn_has_output(const server_connection* conn) const;

    // Sends our FIN once the response is fully on the wire; see the definition
    // for why it is shutdown() and why only completions call it.
    void maybe_shutdown_write(server_connection* conn);

    // The listener's TLS context, rebuilt on every start so `reload` installs
    // a renewed certificate, with existing sessions holding their own
    // reference.
    std::unique_ptr<tls_context> m_tls;
    void submit_conn_read(server_connection* conn);
    // True when `conn` is still there to be used.  submit_conn_read() reports a
    // refused submission on the connection itself and leaves nothing in the
    // ring to notice it later, so the teardown is owed at the call -- and a
    // connection that cannot be read sits in m_clients against
    // --max-connections until the runtime stops.
    bool arm_conn_read(server_connection* conn);
    static bool drains_on_close(const server_connection* conn)
    {
        return conn->drain_on_close && conn->ssl == nullptr &&
               conn->drained_bytes <= DRAIN_LIMIT_BYTES;
    }
    void release_fixed_slot(server_connection* conn);

    // UDP helpers
    void handle_udp_read(struct io_uring_cqe* cqe);
    // Every datagram this server sends leaves through here, so the byte count
    // is taken once instead of at each call site.
    bool udp_send_one(std::string_view msg, const struct sockaddr_in& to);
    // What it reached and what the socket refused, in the same two numbers a
    // TCP fan-out answers with.
    fanout_count udp_broadcast(std::string_view msg, const struct sockaddr_in* exclude);
    int find_or_add_peer(const struct sockaddr_in& addr);

    // The idle sweep's own arm, because setup() has two exits -- the UDP path
    // returns before the TCP path ever reaches the arm, so --idle-timeout was
    // accepted and did nothing on a UDP server.
    void arm_idle_sweep();
    // The outbound leg, called from both of those exits for the same reason:
    // an upstream is a TCP socket this runtime dials and has nothing to do
    // with the family its own listener was configured in.
    void start_upstreams();
    // And its pair, because teardown() has two exits as well: a restart that
    // ran one without the other freed an upstream the ring still named.
    void stop_upstreams(event_loop& loop);
    // Starts the clock on a head that arrived in part, and arms the sweep that
    // reads it -- a plain --http server has neither --idle-timeout nor TLS, so
    // without this there is no chain running at all.
    void arm_header_deadline(server_connection* conn);

    // And its withdrawal, for the same reason at the other end: teardown() has
    // the same two exits, and a timer this instance armed and did not withdraw
    // is a completion the ring still owes it -- which keeps the whole instance
    // in the manager's graveyard until the timeout fires on its own.
    void withdraw_timers(event_loop& loop);

    // Drop peers not heard from within `timeout`, keeping m_udp_peer_idx
    // correct: removal is swap-and-pop, so the element that moves has its own
    // index rewritten.  Returns how many went.
    size_t forget_idle_udp_peers(std::chrono::steady_clock::time_point now,
                                 std::chrono::seconds timeout);

    // Remove one peer by its index, with the same swap-and-pop bookkeeping.
    void drop_udp_peer(int idx);

    server_mode m_mode;
    uint8_t m_send_to{send_to_unset};
    bool m_udp{false};
public:
    void refresh_cached_limits() override
    {
        m_idle_timeout_cached = get_idle_timeout();
        m_max_conns_cached    = get_max_connections();
        m_rate_limit_cached   = get_rate_limit();
    }

private:
    uint32_t m_idle_timeout_cached{0};  // cached at setup() to avoid virtual call per CQE
    uint32_t m_max_conns_cached{0};
    double m_rate_limit_cached{0.0};

    // Master mode
    int m_master_fd{-1};
    std::string m_master_pw;
    int m_listen_fd;
    // The socket node this run's listener actually bound, deliberately not
    // get_listen_path(), because a runtime edited between start and stop would
    // unlink a path it never bound.
    std::string m_bound_listen_path;

    // The node beside the port, for callers already on this box.  Null for
    // every runtime that has only one way in, which is most of them.
    std::unique_ptr<socketley::unix_companion> m_companion;
    struct sockaddr_in m_accept_addr;
    socklen_t m_accept_addrlen;
    // One accept request per chain rather than per instance, because a stop
    // does not end the chain and nothing reaps the ring between a stop and the
    // start that follows -- and a spent request is released only once
    // owner_inflight() says nothing is left.
    std::unique_ptr<io_request> m_accept_req;
    std::vector<std::unique_ptr<io_request>> m_accept_spent;
    event_loop* m_loop;
    // The same loop kept across teardown, because a completion arriving while
    // stopped may carry a buffer or a slot that has to go back; never used to
    // submit.
    event_loop* m_ring_loop{nullptr};

    // EMFILE/ENFILE accept backoff
    io_request m_accept_backoff_req{};
    struct __kernel_timespec m_accept_backoff_ts{};

    // Idle connection sweep timer
    io_request m_idle_sweep_req{};
    struct __kernel_timespec m_idle_sweep_ts{};

    // Relay-hold deadline timer, armed on demand and re-armed by its own
    // completion, so a server with no listeners never puts it in the ring.
    io_request m_relay_deadline_req{};
    struct __kernel_timespec m_relay_deadline_ts{};

    // The bound on a callback that stopped on an await.  Its own timer and not
    // the idle sweep's: that one ticks at 30 seconds, and a handler given ten
    // would wait three times its budget before anything looked.
    io_request m_await_sweep_req{};
    struct __kernel_timespec m_await_sweep_ts{};

    // An armed request stays armed across a stop, because a timeout is
    // attached to no fd, and these flags say occupied so a restart does not
    // give the server a second sweep chain.
    bool m_accept_armed{false};
    bool m_accept_backoff_armed{false};
    bool m_idle_sweep_armed{false};
    // Set by arm_header_deadline() and cleared by the sweep that finds nobody
    // waiting, because the sweep decides whether to re-arm and a walk it has
    // already finished is the only place that knows.
    bool m_headers_outstanding{false};
    // The same for a refused connection still draining, kept by the same walk.
    bool m_drains_outstanding{false};
    bool m_relay_deadline_armed{false};
    bool m_await_sweep_armed{false};
    bool m_udp_recv_armed{false};
    // A read the ring would not take, retried from on_loop_turn(): every other
    // re-arm hangs off a completion, and a refused submission produces none.
    bool m_udp_recv_rearm_due{false};

    std::unordered_map<int, std::unique_ptr<server_connection>> m_clients;
    // O(1) fd→conn lookup for CQE dispatch (non-owning, m_clients owns)
    static constexpr int MAX_FDS = 8192;
    socketley::fd_table<server_connection*> m_conn_idx{MAX_FDS};

    // Active fd tracking for O(1) broadcast iteration (no map overhead)
    std::vector<int> m_active_fds;

    bool m_multishot_active{false};

    uint64_t m_message_counter = 0;

    // ── Cross-runtime routing ───────────────────────────────────────────────
    // What this runtime owns and has routed away, keyed by serial rather than
    // fd so a descriptor reissued to a new client is not silently still
    // routed.
    std::unordered_map<uint64_t, std::string> m_routes;

    // Our serials back to the descriptor that carries them, the only place a
    // conn_ref becomes an fd, with the entry removed the moment the connection
    // closes.
    std::unordered_map<uint64_t, int> m_conn_by_serial;
    // Connections whose queue crossed back under the watermark, to be told so
    // on the next loop turn.  Serials and not descriptors, because the point
    // of waiting a turn is that the connection may be gone by then and a
    // recycled fd would hand the call to whoever took the slot -- a serial
    // that no longer resolves is exactly the answer wanted.
    std::vector<uint64_t> m_drain_pending;
    socketley::direct_send_gate m_direct_gate;
    // The upstream leg's own, because a relay alternates between the two fds
    // and one gate shared by both would see a new fd every turn and admit neither.
    socketley::direct_send_gate m_upstream_gate;
    // The connection a direct send went out on this turn, 0 for none.  Its
    // write counts as outstanding until the turn ends, where on_loop_turn()
    // runs what the completion would have, so no teardown overtakes it.
    uint64_t m_direct_serial{0};
    bool direct_owed(const server_connection* conn) const
    { return m_direct_serial != 0 && conn->ref_serial == m_direct_serial; }
    // Connections whose streamed response ended with a pipelined request still
    // buffered.  end_chunked_response() is reached from inside a Lua callback,
    // and calling the parser from there is re-entering the function that is
    // running -- so the serial waits for the next loop turn, exactly as the
    // drain dispatch above does and for the same reason.
    std::vector<uint64_t> m_reparse_pending;
    // Upstreams whose queue crossed back under the watermark, told so on the
    // next loop turn.  conn_ids and not pointers: the id is stable across
    // reconnects and re-resolving it is how an upstream that went away in
    // between is simply not called.
    std::vector<int> m_upstream_drain_pending;

    // What another runtime has routed to us, of which we hold only the name
    // and a local handle to show Lua.
    struct forwarded_client
    {
        conn_ref    ref;
        std::string origin;      // runtime name that owns the connection
    };
    std::unordered_map<int, forwarded_client> m_forwarded;
    std::unordered_map<conn_ref, int, conn_ref_hash> m_forwarded_by_ref;
    int m_next_handle{conn_handle_base};
    int alloc_handle();

    // Mints the serial half of this runtime's conn_refs, per instance and
    // seeded from the monotonic clock, so it never restarts at a value a peer
    // could hold.
    conn_serial_source m_serials;

    // Whether m_serials has been told which shard it mints for, as a flag
    // rather than a value comparison because shard 0 is a real shard.
    bool     m_serials_shard_set{false};
    uint64_t next_serial();

    // conn_owner_key(get_id()) computed lazily, because get_id() is set after
    // construction and a ref minted before that would carry owner 0.
    mutable uint64_t m_owner_key{0};
    uint64_t owner_key() const;

    // Stats
    uint32_t m_stat_peak_connections{0};

    // Connection pool: pre-allocated connections for reuse (avoids malloc per accept)
    static constexpr size_t CONN_POOL_INIT = 64;
    std::vector<std::unique_ptr<server_connection>> m_conn_pool;

    // Connections and upstreams the kernel has not finished with, held until
    // their completions arrive, because freeing them at the next start read a
    // completion out of memory already handed to somebody else.
    std::vector<std::unique_ptr<server_connection>> m_conn_retired;
    std::vector<std::unique_ptr<upstream_connection>> m_upstream_retired;

    // Acquire a connection from the pool (or allocate if empty)
    std::unique_ptr<server_connection> pool_acquire(int fd);
    // Return a connection to the pool for reuse
    void pool_release(std::unique_ptr<server_connection> conn);

    // Provided buffer ring
    static constexpr uint16_t BUF_GROUP_ID = 1;
    // A ring turns through every buffer it has, so this is 4 MiB resident once
    // traffic has cycled it, the cache's footprint.
    // Past this a closing connection stops waiting for the peer's EOF, which
    // is the cache's bound for the same drain.
    static constexpr uint32_t DRAIN_LIMIT_BYTES = 64u << 20;
    // And past this many seconds, which the 30-second sweep rounds up.
    static constexpr uint32_t DRAIN_LIMIT_SECS = 10;
    static constexpr uint32_t BUF_COUNT = 256;
    static constexpr uint32_t BUF_SIZE = 16384;
    bool m_use_provided_bufs{false};
    bool m_recv_multishot{false};
    bool m_recv_bundle{false};

    // UDP mode
    static constexpr size_t MAX_UDP_PEERS = 10000;
    // `last_seen` is the whole difference between a peer table and a leak: a
    // peer was entered on its first datagram and removed only by teardown, so
    // every restart of every UDP client left one behind for ever.
    struct udp_peer
    {
        struct sockaddr_in                    addr;
        std::chrono::steady_clock::time_point last_seen{};
    };
    int m_udp_fd{-1};
    // Everything one recvmsg names, held apart from the instance and replaced
    // per run, because a stop drops the completion that would lower
    // m_udp_recv_armed.
    struct udp_recv_state
    {
        io_request         req{};
        struct msghdr      msg{};
        struct iovec       iov{};
        struct sockaddr_in addr{};
        char               buf[65536];
    };
    std::unique_ptr<udp_recv_state> m_udp_recv;
    std::vector<std::unique_ptr<udp_recv_state>> m_udp_recv_spent;
    std::vector<udp_peer> m_udp_peers;
    std::unordered_map<uint64_t, int> m_udp_peer_idx;  // packed IP+port → index in m_udp_peers
    // Where the next eviction's sample of the full table begins.
    size_t m_udp_evict_hand{0};
    // Datagrams the socket refused, counted so the log can be throttled and
    // still say how many went unsaid.
    uint64_t m_udp_send_failures{0};

    // Per-IP auth failure tracking
    struct auth_ip_record {
        uint32_t failures{0};
        std::chrono::steady_clock::time_point last_failure{};
    };
    std::unordered_map<uint64_t, auth_ip_record> m_auth_ip_failures;
    static constexpr size_t max_auth_records = 65536;
    // Who a failure is held against: the IPv4 address, or for a unix-socket peer its user id.
    static uint64_t auth_peer_key(int fd);

    // HTTP static file serving
    std::filesystem::path m_http_dir;
    std::filesystem::path m_http_base;  // canonical resolved path (set at setup/rebuild time)

    // A directory descriptor on m_http_base so a request can be opened with
    // openat2(RESOLVE_BENEATH) rather than canonicalised, -1 when there is
    // none and the old path is taken.
    int m_http_root_fd{-1};
    void open_http_root();
    bool m_http_cache_enabled{false};
    // Both variants are prebuilt, because a cache hit has to stay a refcount
    // bump and the response's own Connection header has to match what the
    // client asked for.
    struct cached_file
    {
        std::shared_ptr<const std::string> response;        // Connection: keep-alive
        std::shared_ptr<const std::string> response_close;  // Connection: close
    };
    std::unordered_map<std::string, cached_file, string_hash, string_equal> m_http_cache;

    // ─── DISK MODE'S REVALIDATING CACHE ─────────────────────────────────────
    // One statx per request to decide whether a cached response is still good
    // -- 662 ns against 1838 for openat2+fstat+close -- keyed on
    // dev+ino+size+mtime, because every editor that writes-then-renames puts a
    // new inode at the same path.
    struct reval_file
    {
        dev_t    dev{0};
        ino_t    ino{0};
        uint64_t size{0};
        int64_t  mtime_sec{0};
        uint32_t mtime_nsec{0};
        size_t   bytes{0};   // what this entry costs, both variants together
        std::shared_ptr<const std::string> response;        // Connection: keep-alive
        std::shared_ptr<const std::string> response_close;  // Connection: close
    };
    std::unordered_map<std::string, reval_file, string_hash, string_equal> m_http_reval;
    size_t m_http_reval_bytes{0};
    bool   m_http_reval_full_logged{false};

    // Bounded, unlike m_http_cache, because this one fills lazily from
    // whatever is requested, and a file over the per-file cap never enters the
    // map.
    static constexpr size_t HTTP_REVAL_MAX_FILE  = 1u << 20;   // 1 MiB
    static constexpr size_t HTTP_REVAL_MAX_TOTAL = 64u << 20;  // 64 MiB
    // The cap for a connection that has the splice arm available, which is a
    // different question: see the measurement at the reval_take that reads it.
    static constexpr size_t HTTP_REVAL_SPLICE_MAX_FILE = 256u << 10;  // 256 KiB

    // SOCKETLEY_HTTP_REVALIDATE=0 restores the per-request open and read
    // exactly, read once at start.
    bool m_http_reval_enabled{true};
    bool http_reval_active() const { return m_http_reval_enabled && m_http_root_fd >= 0; }
    bool http_reval_would_fit(const std::string& url_path, size_t cost) const;
    // Says once that the map stopped taking files; see the definition for why
    // it is called from two places.
    void note_http_reval_full();
    void http_reval_store(const std::string& url_path, const struct stat& st,
                          std::shared_ptr<const std::string> ka,
                          std::shared_ptr<const std::string> cl);

    // Splice pipe for zero-copy file serving (shared across connections, one at a time)
    // How many connections hold a splice pipe right now.  A cap and not a
    // pool: the pipes are per connection, so this only bounds how much kernel
    // memory they add up to.
    uint32_t m_splice_live{0};
    // ─── A budget in bytes, not a count ─────────────────────────────────────
    // This was 8, chosen to keep the kernel pipe memory small, and the
    // measurement says that was cautious in the expensive direction: past the
    // cap a connection takes the read path, which allocates the WHOLE file per
    // request.  Worker RSS and throughput on 4 MiB files, 64 concurrent:
    //
    //     cap 8    1.03 GB/s   RSS 202 MB
    //     cap 32   1.31 GB/s   RSS 171 MB
    //     cap 64  12.80 GB/s   RSS  35 MB
    //
    // The pipes cost less than the fallback they avoid, because the kernel
    // allocates a pipe's buffer as it is used while the read path allocates the
    // file up front.  At and below the cap this serves 13-14 GB/s flat; past it
    // the rate falls 13x and CPU per request rises 6x.
    //
    // Expressed as bytes so it follows the pipe size when --write-buffer moves
    // it: a runtime configured small because it serves many streams gets more
    // pipes, not fewer, out of the same budget.  The count is bounded as well,
    // because each pipe is two descriptors and a byte budget alone would let a
    // very small --write-buffer ask for thousands.
    static constexpr size_t   MAX_SPLICE_PIPE_BYTES = 64u * 1024 * 1024;
    static constexpr uint32_t MAX_CONCURRENT_SPLICE = 256;

    // Multicast groups: group_name → list of fds in that group
    std::unordered_map<std::string, std::vector<int>> m_groups;
    void remove_from_all_groups(int fd);

    // Upstream connections
    std::vector<upstream_target> m_upstream_targets;
    std::unordered_map<int, std::unique_ptr<upstream_connection>> m_upstreams;     // conn_id → upstream
    std::unordered_map<int, upstream_connection*> m_upstream_by_fd;                // fd → upstream (CQE dispatch)
    int m_next_upstream_id{1};
    socketley::async_resolver m_resolver;
};
