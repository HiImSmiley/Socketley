#pragma once
// The HTTP(S) requests a storage runtime makes of other hosts, for the webhooks its events go to and the endpoints its
// buckets replicate to: a target's URL, its addresses, and one exchange at a time on a connection kept between them,
// every step on the loop and the resolving on a thread of the owner's.
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <sys/socket.h>

#include "../loop/event_loop.h"
#include "../loop/file_io.h"
#include "../loop/hash_pool.h"
#include "../net/endpoint.h"
#include "../net/read_buffer.h"
#include "../crypto/tls_context.h"
#include "http_url.h"

namespace socketley
{

// One line of a targets file, split into its fields at spaces and tabs.
struct target_line
{
    size_t line_no{0};
    std::vector<std::string_view> fields;
};

// The lines of a targets file that say something: a field that begins with '#' begins a comment to the end of its line.
std::vector<target_line> split_target_lines(std::string_view text);

// A targets file read whole, false with `why` when it cannot be; `what` names the file in `why`.
bool read_targets_file(const std::string& path, std::string_view what, std::string& out, std::string& why);

// Whether `name` is a target's name: letters, digits, '-', '_' and '.'.
bool valid_target_name(std::string_view name);

// One address a host resolved to.
using http_endpoint = socketley::endpoint;

using socketley::literal_endpoint;

// The addresses `host` has, in the order the resolver gives them, a name in `hosts_file` (`name address` lines, a
// test aid) before the system's; blocking, so it runs on the resolver thread.
std::vector<http_endpoint> resolve_http_host(const std::string& host, uint16_t port, const std::string& hosts_file);

// What a host answered, status 0 when no whole answer came.
struct http_answer
{
    int         status{0};
    // The status line and the header lines, and the body with any chunked framing taken off.
    std::string head;
    std::string body;
    // Why no whole answer came, empty when one did.
    std::string failure;

    // The value of the header named `lower`, empty when there is none.
    std::string_view header(std::string_view lower) const;
};

// The next bytes of a request's body, handed to `give`: empty after the last, and `ok` false when they cannot be had.
using http_body_give   = std::function<void(bool ok, std::string_view piece)>;
using http_body_source = std::function<void(http_body_give give)>;

struct http_request
{
    // The request line and the header lines, ending with the blank line.
    std::string head;
    // A body held whole, sent after the head.
    std::string body;
    // A body handed out a piece at a time after the head and `body`, none when empty.
    http_body_source source;
    // Or a body moved straight from a file by sendfile, [file_off, file_off + file_len) of `file_fd`, which the caller
    // keeps open; over TLS once the connection's send key is the kernel's, with `source` given beside it for where that
    // cannot be.
    int         file_fd{-1};
    uint64_t    file_off{0};
    uint64_t    file_len{0};
    // The exchange ends once the answer's head is in, for a host whose answer has nothing more to say.
    bool        head_only{false};
    // How long the answer may take once the whole request is written.
    int         answer_secs{10};
    // The most bytes the answer may hold, head included; 0 is 1 MiB.
    size_t      max_answer{0};
};

// The exchanges of one target, one at a time, on a connection kept for the next while the host keeps it, as a proxy
// keeps its backends'.
class http_peer
{
public:
    // An exchange with no progress for this long has failed.
    static constexpr int stall_secs = 10;
    // A connection kept this long with nothing to send is closed, sooner than a host commonly gives up on one.
    static constexpr int keep_idle_secs = 4;
    // A host's addresses are asked for again this often while it is used, and at once after every address it had
    // refused a connection, but not twice within the floor.
    static constexpr int resolve_every_secs = 60;
    static constexpr int resolve_floor_ms   = 1000;

    // `resolver` asks for a named host's addresses, `hosts_file` is the test aid, and `what` names the target in the
    // log, the runtime it is for first.
    http_peer(event_loop& loop, file_io& io, hash_pool& resolver, http_target target, std::string hosts_file,
              std::string what);
    ~http_peer();

    http_peer(const http_peer&)            = delete;
    http_peer& operator=(const http_peer&) = delete;

    const http_target& target() const { return m_target; }
    bool busy() const { return m_busy; }
    // Asks for a named host's addresses now, so the first exchange does not wait for them.
    void prime();

    // Starts an exchange, whose end `done` hears exactly once; a host with no address yet is resolved first.
    void exchange(http_request req, std::function<void(http_answer)> done);
    // Ends an exchange that has stalled.
    void tick(std::chrono::steady_clock::time_point now);
    // Ends the exchange in progress without telling anyone, for a stop.
    void stop();

    uint64_t resolves() const { return m_resolves; }
    // The connections made, and the exchanges that went on one kept from the exchange before.
    uint64_t connects() const { return m_connects; }
    uint64_t reuses() const { return m_reuses; }

private:
    bool resolve();
    // The loop's resolver asked, and asked again on a short timer while it waits; false when it cannot say and the
    // system's must be asked on the resolver's thread.
    bool ask_loop();
    void ask_thread();
    void resolved(std::vector<http_endpoint> addrs);
    void connect();
    void connected(int64_t res);
    // The next step: the handshake, the next bytes owed to the socket, or a read of the answer.
    void advance();
    // Writes `bytes` whole, then advances.
    void send(std::shared_ptr<std::string> bytes, size_t off);
    // Moves the next piece of a file body through the pipe into the socket, then advances once all is sent.
    void splice_body();
    void file_body();
    // Closes the pipe, which a transfer cut short leaves holding bytes no later one may send.
    void drop_pipe();
    // Hands what the record layer has to say to send(); false when it had nothing.
    bool flush_cipher();
    void receive();
    void got(const char* p, size_t n);
    // Whether the answer read so far is whole, for the exchange or, with `framed`, to its last byte.
    bool answer_complete(bool framed = false) const;
    // Whether the connection of the exchange that just ended may carry the next one.
    bool keepable() const;
    // Whether a kept connection is still open, which a host that gave up on it no longer has; what TLS sent on it
    // since, a session ticket, is taken in.
    bool still_open();
    // The exchange ends, answered or failed for `why`, and `done` hears the answer.
    void finish(bool answered, std::string why = {});
    void close_socket();

    event_loop& m_loop;
    file_io&    m_io;
    hash_pool&  m_resolver;
    http_target m_target;
    std::string m_hosts_file;
    std::string m_what;
    std::unique_ptr<tls_context> m_tls;
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};

    // The host's addresses and the one tried next; a literal address is its own and never resolved.
    std::vector<http_endpoint> m_addrs;
    size_t      m_cur{0};
    bool        m_literal{false};
    bool        m_resolving{false};
    // The pause before the loop's resolver is asked again, doubled each time up to a cap.
    std::chrono::milliseconds m_ask_wait{0};
    std::chrono::steady_clock::time_point m_resolved_at{};
    uint64_t    m_resolves{0};
    uint64_t    m_connects{0};
    uint64_t    m_reuses{0};

    // The exchange in progress, and a generation bumped at its end so a late completion is told from a current one.
    bool        m_busy{false};
    bool        m_stopped{false};
    uint64_t    m_gen{0};
    http_request m_req;
    std::function<void(http_answer)> m_done;
    int         m_fd{-1};
    SSL*        m_ssl{nullptr};
    bool        m_handshaken{false};
    bool        m_head_given{false};
    // The head of a request whose body comes from a source, held for the body's first piece.
    std::string m_head_out;
    // A body held in memory that the record layer has not taken yet, and how far it has.
    std::string m_tls_rest;
    size_t      m_tls_rest_off{0};
    // The socket's own flags, read once for sendfile, which makes it non-blocking for the call alone.
    int         m_sock_flags{-1};
    // A file body's pipe, its bytes sent so far and those in the pipe; dirty from a transfer's start to its end.
    int         m_pipe_rd{-1};
    int         m_pipe_wr{-1};
    uint32_t    m_pipe_size{0};
    uint64_t    m_file_sent{0};
    uint32_t    m_in_pipe{0};
    bool        m_pipe_dirty{false};
    // Over TLS: the file body goes by sendfile through kernel TLS, or by the source where the kernel cannot take it.
    bool        m_file_kernel{false};
    bool        m_file_by_source{false};
    bool        m_source_done{false};
    bool        m_sent{false};
    // A write failed, so the answer the host may have sent before closing is all that is left to read.
    bool        m_write_failed{false};
    // The host closed the connection, which then carries no further exchange.
    bool        m_eof{false};
    std::string m_in;
    // How much the next read takes, and the buffer it takes it into, reused once no read in flight holds it.
    socketley::read_size m_read{16 * 1024, 256 * 1024};
    std::shared_ptr<char[]> m_rbuf;
    uint32_t m_rbuf_size{0};
    // Where the answer's head ends in m_in once found, so each read does not search it from the start again.
    mutable size_t m_head_end = std::string::npos;
    std::chrono::steady_clock::time_point m_deadline{};
    // When the connection was made, and since when, kept from the last exchange, it has had nothing on it.
    std::chrono::steady_clock::time_point m_connected_at{};
    std::chrono::steady_clock::time_point m_idle_since{};
};

}   // namespace socketley
