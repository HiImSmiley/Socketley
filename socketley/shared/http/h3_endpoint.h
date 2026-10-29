#pragma once
// HTTP/3, RFC 9114 over QUIC (RFC 9000): the UDP socket, the connections on it, their handshakes, their timers and
// their packets, apart from what any one runtime does with a stream. QUIC is ngtcp2's, its TLS 1.3 OpenSSL's through
// ngtcp2's helper, and HTTP/3 with QPACK nghttp3's; none of that is one runtime's business, so it lives here beside
// the multiplexed-HTTP head contract (mux_head.h) that an HTTP/3 stream crosses exactly as an HTTP/2 one does.
//
// A host is told the five things only it can decide -- a stream opened, its head, its body, its end, and that its
// answer has been taken -- through the interface below rather than through a template, because unlike HTTP/2's frame
// reader this boundary is crossed once per stream event and never per packet: the packet path, the congestion
// controller and the loss recovery do not reach the host at all, so a virtual call here costs nothing measurable
// and saves templating two thousand lines of ngtcp2 plumbing.
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "http_framing.h"
#include "mux_head.h"

struct sockaddr_storage;
struct ssl_st;
struct io_request;
class io_handler;
class tls_context;
class event_loop;

namespace socketley::h3
{

struct conn;
struct endpoint;

// What a stream's answer has given nghttp3 and what the peer has acknowledged, held as it was handed over: QUIC
// sends a lost packet's bytes again, so they live until acknowledged.
struct stream
{
    int64_t  sid{0};
    conn*    owner{nullptr};
    // What the host keeps for this stream: a key into a table of its own, not a pointer.  A stream here can
    // outlive the host's object for it by an operation in flight, and a key that no longer resolves is a miss
    // rather than a dangling read -- which is how the runtime this was lifted from already looked its streams up.
    uint64_t user{0};

    // The request's fields as they came, until its head is complete.
    std::vector<std::pair<std::string, std::string>> fields;
    bool     opened{false};
    // DATA received and not yet handed to whatever reads it.
    std::deque<std::string> rxq;
    size_t   rx_head{0};
    bool     remote_closed{false};
    bool     synth_chunked{false};
    bool     chunk_end_given{false};
    // A pull running inside the parse its own read asked for.
    bool     pulling{false};

    enum class out_state : uint8_t { head, body, dechunk } os{out_state::head};
    std::string head_acc;
    http_chunked_decoder dechunk;
    std::string dechunk_in;
    std::deque<std::string> tx;
    size_t   tx_given_front{0};    // what of tx.front() nghttp3 already has
    size_t   tx_given_chunks{0};   // chunks nghttp3 has whole, at the front
    uint64_t tx_total{0}, tx_given{0}, tx_acked_front{0};
    // What the peer has acknowledged of tx_total, so what the answer still holds here is the difference.
    uint64_t tx_acked{0};
    bool     submitted{false};
    bool     blocked{false};       // read_data said it would block; resumed when more comes
    bool     end_pending{false};
    bool     ended{false};         // EOF given
    bool     gone{false};

    // Its answer has begun and nghttp3 has taken all of it: the same test the runtime this was lifted from
    // used to decide a stream's write was done, which is not `ended` -- a stream still owing its last bytes
    // has them taken before its EOF is given.
    bool drained() const { return os != out_state::head && tx_given == tx_total; }
    // The bytes of its answer this side still keeps, framed or not, which is what a host's backpressure counts.
    uint64_t held() const
    {
        return (tx_total > tx_acked ? tx_total - tx_acked : 0) + head_acc.size() + dechunk_in.size();
    }
};

// The runtime's own counters, which differ in name and place per runtime.
enum class event : uint8_t { conn_opened, stream_opened, retry_sent, forwarded };

// What a runtime answers about its own streams. Every call carries the stream, whose `user` is what the host
// returned when it was made; a host that keeps its object in a table of its own looks it up from there rather than
// following `user`, which is why `user` is never dereferenced on this side.
class host
{
public:
    virtual ~host() = default;

    // A stream the peer opened. The host's key for it, or 0 to refuse the stream.
    virtual uint64_t make_stream(stream& st) = 0;
    // Its head, complete. `answer_status` is 431 when the head is longer than this side reads, and the host answers
    // that rather than routing the request; `r.line` is the head written back as HTTP/1.1, which is what a runtime's
    // own parser reads.
    virtual void start_stream(stream& st, mux::request& r, int answer_status) = 0;
    // Whether whatever reads this stream can take more right now; false holds the rest until it can, which is
    // what stops a client the reader cannot keep up with.
    virtual bool can_take(stream& st) = 0;
    // A slice of the request's body, handed over as a recv's bytes would be.  What is taken this way is what the
    // window is given back, so a host that holds bytes instead of taking them holds the client too.
    virtual void take(stream& st, const char* d, size_t n) = 0;
    // nghttp3 has taken everything this stream handed it: the next piece of its answer may be asked for.
    virtual void write_done(stream& st) = 0;
    // The stream is over, by its own end or by the connection's: the host lets go of what it kept.
    virtual void stream_gone(stream& st) = 0;
    virtual void count(event e) = 0;
    // Bytes this endpoint put on the wire, for the runtime's own byte tally.
    virtual void sent(size_t n) { (void)n; }

    // Where a packet for another shard of this runtime goes, and the name this shard is reached by; a host with one
    // shard answers 1 and need not implement the forwarding.
    virtual uint32_t shards() const { return 1; }
    virtual std::string inbox_name(uint32_t /*shard*/) const { return {}; }
};

// How an endpoint is opened. `cert`/`key` are the files its context watches, `ca` a client CA or empty, `advertise`
// the port Alt-Svc names when it is not `port`.
struct options
{
    // What a completion of this endpoint is dispatched by: the runtime that holds it, which the event loop knows.
    io_handler* owner{nullptr};
    uint16_t    port{0};
    uint16_t    advertise{0};
    uint32_t    shard{0};
    uint32_t    shards{1};
    std::string cert, key, ca;
    // The bounds and dials a runtime may differ on; the defaults are what a web server wants.
    uint64_t    max_streams{128};
    size_t      max_conns{4096};
    size_t      max_head{32 * 1024};
    // Handshakes under way past which a new client proves its address with a Retry first (RFC 9000 8.1.2), so
    // datagrams with forged sources cannot fill the table; 0 always retries.
    size_t      retry_after{64};
    // bbr, cubic or reno. BBR by default: it paces by the path's measured rate and round trip rather than backing
    // off at every loss, so a link that loses a packet in a hundred at 50 ms -- Wi-Fi, mobile -- carried a download
    // ten to twenty times faster than with CUBIC, and as fast without loss.
    std::string cc{"bbr"};
};

struct endpoint_free { void operator()(endpoint* e) const; };
using endpoint_ptr = std::unique_ptr<endpoint, endpoint_free>;

// Opens the socket and the context; empty with `err` set when it cannot. `loop` is the ring every read, write and
// timer of this endpoint goes through, and `h` is told about its streams for as long as it lives.
endpoint_ptr open(const options& o, host& h, event_loop& loop, std::string& err);

// Whether this request is one of the endpoint's, and its completion. Asked before every other owner, because the
// endpoint's reads and timers carry no connection of their own.
bool owns(const endpoint& e, const io_request* req);
void completion(endpoint& e, io_request* req, int res);

// Once per turn of the loop, after the completions: every connection whose state moved writes its packets.
void flush(endpoint& e);

// A stream's body, handed on while whatever reads it takes it and held when it does not; what was taken is given
// back to the windows, so a reader that cannot keep up stops the client. `fresh` is what just arrived, or empty to
// hand on only what is held -- which is what a host calls after its reader has made room.
void pull(stream& st, std::string_view fresh);

// A stream's answer, read back into HTTP/3's fields and DATA; `finish` when this is the whole of it.
void answer(stream& st, std::string data, bool finish);
// The answer is over, which on a stream is its end and not a half-closed socket. False when the stream could not
// be ended and the host must let go of it instead.
bool answer_end(stream& st);
// A stream's acknowledged bytes, let go of: QUIC may have to send them again until then.
void acked(stream& st, uint64_t len);
// The host has let go of a stream that nothing answered: it is reset toward the client and forgotten.
void gone(stream& st);
// And the same for one whose answer is finished: the host's object goes now, the stream stays until its last frame
// has been sent, and this side forgets it alone.  The host's key is cleared, so the stream_gone() that follows
// resolves to nothing rather than to an object already let go.
void release(stream& st);

// What a stream's connection is: the address its packets come from, and that address as text. A runtime parses the
// address into whatever type it keeps, which is why neither is parsed here.
const sockaddr_storage* peer_of(const stream& st);
std::string peer_text_of(const stream& st);
// The TLS session of the connection a stream is on, for a runtime that asks whether a request came encrypted.
ssl_st* tls_of(const stream& st);

size_t open_conns(const endpoint& e);
// The Alt-Svc value every answer over TCP carries, or empty when no endpoint is open.
std::string alt_svc(const endpoint& e);
void stop(endpoint& e);

}   // namespace socketley::h3
