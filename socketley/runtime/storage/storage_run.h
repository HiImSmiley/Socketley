#pragma once
// One run of a storage runtime, from setup() to teardown(): the store, the
// listener and every connection.
//
// It is an io_handler of its own rather than the runtime object, because a stop
// and a start in one process must leave the completions the ring still owes the
// first run somewhere to land -- a run is freed only once the loop owes it
// nothing, and the next run is a different object with a different identity.
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "checksum.h"
#include "multipart.h"
#include "object_store.h"
#include "s3_auth.h"
#include "../../shared/storage_rpc.h"
#include "shard_node.h"
#include "storage_transport.h"
#include "../../shared/event_loop.h"
#include "../../shared/file_io.h"
#include "../../shared/hash_pool.h"
#include "../../shared/http_framing.h"
#include "../../shared/tls_context.h"

class storage_instance;

namespace socketley::storage
{

// What `stats` says about the traffic, on top of what the store says about
// what it holds.
struct storage_counters
{
    uint64_t requests{0};
    uint64_t gets{0};
    uint64_t heads{0};
    uint64_t puts{0};
    uint64_t deletes{0};
    uint64_t lists{0};
    uint64_t copies{0};
    uint64_t client_errors{0};
    uint64_t server_errors{0};
    // Body bytes sent to clients, and the part of them that never entered this
    // process: they went file to pipe to socket inside the kernel.
    uint64_t bytes_out{0};
    uint64_t zero_copy_bytes{0};
    uint64_t zero_copy_gets{0};
    uint64_t copied_gets{0};
    // Body bytes taken in from clients.
    uint64_t bytes_in{0};
    uint64_t timeouts{0};
    // Multipart: uploads begun, parts taken, uploads completed and aborted.
    uint64_t mpu_created{0};
    uint64_t mpu_parts{0};
    uint64_t mpu_completed{0};
    uint64_t mpu_aborted{0};
    // TLS handshakes that completed and that did not.
    uint64_t tls_handshakes{0};
    uint64_t tls_failures{0};
    // S3 errors answered, by the code in the XML.
    std::map<std::string, uint64_t, std::less<>> errors;
};

// The request as parsed.  Owns its strings, so what an asynchronous step
// needs later is still here after the next read has reused the buffer.
struct s3_request
{
    std::string method;
    std::string version;
    std::string raw_path;
    std::string raw_query;
    std::string host;
    std::string payload_hash;
    std::string bucket;
    std::string key;
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<header_ref>                          refs;
    std::vector<std::pair<std::string, std::string>> query;
    std::string request_id;

    bool   has_content_length{false};
    uint64_t content_length{0};
    bool   chunked{false};
    bool   keep_alive{true};
    bool   expect_continue{false};

    std::string_view header(std::string_view lower) const
    {
        for (const auto& h : headers)
            if (h.first == lower)
                return h.second;
        return {};
    }
    bool has_header(std::string_view lower) const
    {
        for (const auto& h : headers)
            if (h.first == lower)
                return true;
        return false;
    }
    bool has_query(std::string_view name) const
    {
        for (const auto& q : query)
            if (q.first == name)
                return true;
        return false;
    }
    std::string_view get_query(std::string_view name) const
    {
        for (const auto& q : query)
            if (q.first == name)
                return q.second;
        return {};
    }
};

// The checksum a request asks to be taken of its body: named by a header that
// carries the value, by a trailer that will, or by the SDK's algorithm header.
struct checksum_request
{
    checksum_algo algo{checksum_algo::none};
    // The base64 the request gave ahead of the body, empty when it did not.
    std::string   expected_b64;
    // The trailer that will carry the value after the body, empty when none.
    std::string   trailer_name;
};

// False with `err` when the request names a checksum the runtime cannot take
// or names two that disagree.
bool parse_checksum_request(const s3_request& r, checksum_request& out, s3_error& err);

// The bucket and key an x-amz-copy-source header names, decoded; false with
// `err` when it names neither or is not one.
bool parse_copy_source(std::string_view header, std::string& bucket, std::string& key, s3_error& err);

enum class phase : uint8_t
{
    // Reading a request head, the state a connection rests in.
    head,
    // Collecting a small body the operation needs whole.
    body_small,
    // Streaming a body into an object.
    body_put,
    // Reading and discarding what is left of a body whose answer is already decided.
    body_discard,
    // The answer is being sent, and nothing is read until it is.
    respond,
    // A script's on_request has the request and has not answered yet; nothing is
    // read until it does.
    hook_wait,
};

class storage_run;

struct conn
{
    conn() = default;
    conn(const conn&)            = delete;
    conn& operator=(const conn&) = delete;
    ~conn()
    {
        if (ssl)
            tls_context::free_ssl(ssl);
    }

    storage_run* run{nullptr};
    uint64_t     id{0};
    int          fd{-1};
    // An identity for callbacks that outlive a close.
    bool         dead{false};

    // ── TLS ─────────────────────────────────────────────────────────────────
    // Null on a cleartext connection.  With a session, `rbuf`'s job is done by
    // `cbuf` (ciphertext), `wq` holds plaintext waiting for the record layer
    // and `wbuf` the ciphertext the kernel is reading.
    SSL*            ssl{nullptr};
    tls_conn_state  tls_state{tls_conn_none};
    bool            pulling{false};
    std::unique_ptr<char[]> cbuf;
    std::chrono::steady_clock::time_point accepted{};

    io_request rd_req{};
    io_request wr_req{};
    io_request sp_in_req{};
    io_request sp_out_req{};
    bool       rd_pending{false};
    bool       wr_pending{false};
    bool       sp_in_pending{false};
    bool       sp_out_pending{false};
    bool       closing{false};

    // A recv lands here, and for a body with nothing to decode straight in the
    // put's staging buffer instead.
    static constexpr size_t rbuf_size = 8192;
    char        rbuf[rbuf_size];
    bool        rd_direct{false};
    size_t      rd_direct_room{0};

    phase       ph{phase::head};
    // Bytes read and not yet consumed: a head being assembled, or the start of
    // the next request behind this one.
    std::string in;
    s3_request  req;
    std::chrono::steady_clock::time_point last_progress{};
    std::chrono::steady_clock::time_point request_began{};

    // The response on its way out: `wbuf` is what the kernel is reading and
    // `wq` what waits behind it.
    std::string wbuf;
    size_t      woff{0};
    std::string wq;
    // How much of `wq` the record layer has already taken.
    size_t      wq_off{0};
    // Called once everything queued has been written.
    std::function<void()> after_write;
    bool        close_after_write{false};

    // ── A body being collected ──────────────────────────────────────────────
    std::string body;
    uint64_t    body_limit{0};
    uint64_t    body_left{0};        // bytes of Content-Length still to come
    http_chunked_decoder chunk;
    std::string chunk_in;            // chunked framing waiting for the rest of a line
    std::function<void()> on_body;   // the small body is complete

    // ── A body streaming into an object ─────────────────────────────────────
    std::shared_ptr<put_op>    put;
    // Shared with the job that is feeding it on a helper thread, which may outlive the request.
    std::shared_ptr<body_hook> hook;
    // A recv for a body whose hook is heavy lands here, in a buffer that the
    // hook's job then owns until it reports.
    std::shared_ptr<char[]> hbuf;
    bool        rd_hook{false};
    bool        hook_busy{false};
    uint32_t    hash_lane{0};
    bool        has_lane{false};
    // What the hook or the chunk decoder produced that the put could not take.
    std::string park;
    size_t      park_off{0};
    bool        put_fin_called{false};
    st          put_failed{st::ok};
    bool        has_expected_md5{false};
    md5_t       expected_md5{};
    s3_error    body_error;
    bool        body_refused{false};
    uint64_t    decoded_total{0};
    // The trailer a checksum will arrive in after the body, when it does.
    std::string ck_trailer;

    // ── A file being sent ───────────────────────────────────────────────────
    int         file_fd{-1};
    uint64_t    file_off{0};
    uint64_t    file_left{0};
    int         pipe_rd{-1};
    int         pipe_wr{-1};
    uint64_t    pipe_held{0};
    uint32_t    pipe_size{0};
    std::string sbuf;
    bool        spliced{false};
    // The response is for a range or a whole object, kept for the counters.
    uint64_t    sent_body{0};

    // The address of the peer, read the first time a script asks for it.
    std::string peer;
    // Who the authenticator said made the request, for the script.
    std::string principal;
};

// An object's metadata as a script sees it: the user metadata without its
// header prefix, and the fields S3 reports.
storage_rpc::object_info rpc_info_of(const object_meta& m, std::string key = {});

// One request's result, which every operation ends by giving to respond().
struct response
{
    int         status{200};
    std::string reason;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    // A HEAD or a 304 carries the headers a body would have and no body.
    bool        head_only{false};
    // The Content-Length to send when it is not the body's own.
    bool        has_length_override{false};
    uint64_t    length_override{0};
    bool        close{false};
};

class storage_run : public io_handler
{
public:
    storage_run(storage_instance& owner, event_loop& loop, store_options opts, authenticator* auth);
    ~storage_run() override;

    storage_run(const storage_run&)            = delete;
    storage_run& operator=(const storage_run&) = delete;

    // Opens the store, which blocks and so runs before anything is bound.
    bool open(std::string& err);
    bool listen_on(int fd);
    // A descriptor accepted somewhere else (the companion node), which becomes a
    // connection exactly as one of this run's own accepts does.
    bool adopt_external(int fd);
    // The context every accepted connection's session is made from; none means
    // cleartext.
    void set_tls(std::unique_ptr<tls_context> ctx) { m_tls = std::move(ctx); }
    bool tls_enabled() const { return m_tls != nullptr; }

    void on_cqe(struct io_uring_cqe* cqe) override;

    // Everything is closed and the run is left for the loop to finish with.
    void stop();
    // Nothing is owed to this run any more, so it can be freed.
    bool drained() const;


    size_t connection_count() const { return m_conns.size(); }
    const storage_counters& counters() const { return m_c; }
    object_store& store() { return m_store; }
    shard_node& node() { return m_node; }
    file_io& io() { return m_io; }
    void set_authenticator(authenticator* a) { m_auth = a; }
    // An authenticator the run keeps for as long as it lives, because a
    // request in flight when a stop came is still asking it.
    void adopt_authenticator(std::unique_ptr<authenticator> a)
    {
        m_auth_owned = std::move(a);
        m_auth       = m_auth_owned.get();
    }
    multipart_store& multipart() { return m_mpu; }
    // Uploads left open this many seconds are aborted; zero keeps them until they are.
    void set_mpu_expire_secs(uint32_t s)
    {
        m_mpu_expire_secs = s;
        if (s != 0)
            arm_sweep();
    }
    void on_turn();

    // Called by the object store's callbacks through a captured id.
    std::shared_ptr<conn> find(uint64_t id);

    // ── The wire ────────────────────────────────────────────────────────────
    void accept_done(struct io_uring_cqe* cqe);
    void arm_accept();
    void adopt(int fd);
    void arm_read(const std::shared_ptr<conn>& c);
    void read_done(const std::shared_ptr<conn>& c, struct io_uring_cqe* cqe);
    void write_done(const std::shared_ptr<conn>& c, struct io_uring_cqe* cqe);
    void splice_in_done(const std::shared_ptr<conn>& c, struct io_uring_cqe* cqe);
    void splice_out_done(const std::shared_ptr<conn>& c, struct io_uring_cqe* cqe);
    // Plaintext, wherever it came from: the socket's bytes or a session's.
    void plain_in(const std::shared_ptr<conn>& c, const char* p, size_t n);
    void tls_in(const std::shared_ptr<conn>& c, size_t n);
    void tls_pull(const std::shared_ptr<conn>& c);
    // Moves what the record layer has to say and what waits in `wq` into `wbuf`.
    bool tls_encrypt(const std::shared_ptr<conn>& c);
    void close_conn(const std::shared_ptr<conn>& c);
    void maybe_release(const std::shared_ptr<conn>& c);
    void queue_write(const std::shared_ptr<conn>& c, std::string data);
    void pump_write(const std::shared_ptr<conn>& c);
    void sweep();
    void arm_sweep();

    // ── HTTP ────────────────────────────────────────────────────────────────
    void process_in(const std::shared_ptr<conn>& c);
    bool parse_head(const std::shared_ptr<conn>& c, size_t head_len);
    void send_response(const std::shared_ptr<conn>& c, response r);
    void send_error(const std::shared_ptr<conn>& c, const s3_error& e, bool close = false,
                    std::string_view extra_name = {}, std::string_view extra_value = {});
    void send_error_st(const std::shared_ptr<conn>& c, st s);
    // One more answered with this S3 error code, for `stats` and the metrics.
    void count_error(std::string_view code);
    void finish_request(const std::shared_ptr<conn>& c);
    void reset_request(const std::shared_ptr<conn>& c);
    std::string response_head(const conn& c, const response& r) const;

    // A body of known small size, gathered whole and handed to `done`.
    void collect_body(const std::shared_ptr<conn>& c, uint64_t limit, std::function<void()> done);
    void feed_small_body(const std::shared_ptr<conn>& c, const char* p, size_t n);

    // ── Streaming a body in ─────────────────────────────────────────────────
    void begin_put_body(const std::shared_ptr<conn>& c, std::shared_ptr<put_op> op);
    void put_body_bytes(const std::shared_ptr<conn>& c, const char* p, size_t n);
    void put_drain_park(const std::shared_ptr<conn>& c);
    void put_body_complete(const std::shared_ptr<conn>& c);
    void put_failed(const std::shared_ptr<conn>& c, st why);
    void put_refused(const std::shared_ptr<conn>& c, const s3_error& e);
    // A heavy hook is fed the `n` bytes just received into the connection's hook buffer on a
    // helper thread, and what it decoded goes to the put when it reports.
    struct hook_job;
    void hook_async(const std::shared_ptr<conn>& c, size_t n);
    void hook_async_done(uint64_t id, const std::shared_ptr<hook_job>& job);
    std::shared_ptr<char[]> take_hook_buffer();
    void give_hook_buffer(std::shared_ptr<char[]> b);
    void enter_discard(const std::shared_ptr<conn>& c);
    // Answers a request that is refused before its body was read, after reading
    // and dropping the body when it is small enough, so the client hears the
    // answer and not a reset.
    void deny_request(const std::shared_ptr<conn>& c, const s3_error& e);

    // ── Sending a file out ──────────────────────────────────────────────────
    void send_file(const std::shared_ptr<conn>& c, response head, int fd, uint64_t off, uint64_t len);
    void file_pump(const std::shared_ptr<conn>& c);
    void file_done(const std::shared_ptr<conn>& c);
    bool pipe_acquire(conn& c);
    void pipe_release(conn& c);
    void stream_read_done(const std::shared_ptr<conn>& c, int64_t res);

    // ── Scripts ─────────────────────────────────────────────────────────────
    // Asks on_request whether the request goes on, then routes it or refuses.
    void hook_request(const std::shared_ptr<conn>& c);
    // The hook has answered: `deny` refuses the request with that error, and null lets it go on.
    void hook_done(uint64_t id, const s3_error* deny);
    // Told after the commit, and only if the script has the hook.
    void notify_put(std::string_view bucket, std::string_view key, const object_meta& m);
    void notify_delete(std::string_view bucket, std::string_view key);
    // What another runtime's script asked of this one, answered on a later turn
    // through the ticket; false means it was not taken.
    bool serve_rpc(uint64_t ticket, std::string_view payload);
    void stop_rpc();
    // The operation an S3 request is, by the name S3 gives it.
    static std::string_view operation_name(const s3_request& r);

    // ── S3 ──────────────────────────────────────────────────────────────────
    void dispatch(const std::shared_ptr<conn>& c);
    // From the request's head as far as the operation, after auth and the hook.
    void route(const std::shared_ptr<conn>& c);
    void op_list_buckets(const std::shared_ptr<conn>& c);
    void op_create_bucket(const std::shared_ptr<conn>& c);
    void op_delete_bucket(const std::shared_ptr<conn>& c);
    void op_head_bucket(const std::shared_ptr<conn>& c);
    void op_bucket_location(const std::shared_ptr<conn>& c);
    void op_list_objects(const std::shared_ptr<conn>& c, bool v2);
    void op_copy_from(const std::shared_ptr<conn>& c, std::string src_bucket, std::string src_key,
                      bool replace, const object_meta& src_meta);
    void op_delete_objects(const std::shared_ptr<conn>& c);
    void op_put_object(const std::shared_ptr<conn>& c);
    void start_put(const std::shared_ptr<conn>& c, std::string key, object_meta meta,
                   put_op::committer committer, checksum_algo forced_algo = checksum_algo::none,
                   bool create_only = false);
    void op_copy_object(const std::shared_ptr<conn>& c);

    // Multipart, in storage_multipart.cpp.
    void op_create_multipart(const std::shared_ptr<conn>& c);
    void op_upload_part(const std::shared_ptr<conn>& c);
    void op_upload_part_copy(const std::shared_ptr<conn>& c);
    void op_complete_multipart(const std::shared_ptr<conn>& c);
    void op_abort_multipart(const std::shared_ptr<conn>& c);
    void op_list_parts(const std::shared_ptr<conn>& c);
    void op_list_uploads(const std::shared_ptr<conn>& c);
    void with_open_upload(const std::shared_ptr<conn>& c, std::function<void(checksum_algo)> go);
    void op_upload_part_copy_from(const std::shared_ptr<conn>& c, uint32_t number, checksum_algo algo,
                                  const std::string& src_bucket, const std::string& src_key,
                                  const object_meta& src_meta);
    bool part_number_of(const std::shared_ptr<conn>& c, uint32_t& number);
    void reap_uploads();
    void op_get_object(const std::shared_ptr<conn>& c, bool head);
    void op_delete_object(const std::shared_ptr<conn>& c);
    bool object_meta_from_headers(const std::shared_ptr<conn>& c, object_meta& m, s3_error& err);
    std::string new_request_id();

    std::string owner_id() const { return "socketley"; }

    storage_instance& owner() { return m_owner; }

private:
    storage_instance& m_owner;
    event_loop&       m_loop;
    file_io           m_io;
    // Helper threads that take the digests of large bodies; declared before
    // the store, which holds a pointer to it.
    hash_pool         m_hash;
    object_store      m_store;
    multipart_store   m_mpu;
    // What carries a request to a sibling shard, and the logic that makes one
    // and answers one; a runtime of one shard never calls the transport.
    channel_transport m_transport;
    shard_node        m_node;
    authenticator*    m_auth;
    std::unique_ptr<authenticator> m_auth_owned;
    anonymous_authenticator m_anon;
    uint32_t          m_mpu_expire_secs{0};
    std::chrono::steady_clock::time_point m_last_reap{};
    std::unique_ptr<tls_context> m_tls;

    int         m_listen_fd{-1};
    io_request  m_accept_req{};
    bool        m_accept_pending{false};
    std::unordered_map<uint64_t, std::shared_ptr<conn>> m_conns;
    uint64_t    m_next_id{1};

    // Connections whose kernel operations have not all reported, kept so the
    // memory the ring writes into outlives the close.
    std::vector<std::shared_ptr<conn>> m_closing;

    struct pooled_pipe { int rd; int wr; uint32_t size; };
    std::vector<pooled_pipe> m_pipes;
    std::vector<std::shared_ptr<char[]>> m_hook_buffers;

    struct timer
    {
        io_request req{};
        struct __kernel_timespec ts{};
        bool armed{false};
    };
    timer       m_sweep_timer;
    timer       m_accept_backoff;

    storage_counters m_c;
    uint64_t    m_rid_seq{0};
    bool        m_stopped{false};

    // Calls from other runtimes' scripts still in flight, so a stop can answer them.
    struct rpc_state;
    std::unordered_map<uint64_t, std::shared_ptr<rpc_state>> m_rpc;
    // A cap on what streaming puts hold, so a thousand uploaders cannot ask for a thousand buffers.
    uint32_t    m_max_active_puts{512};
    size_t      m_zero_copy_min{64 * 1024};
    size_t      m_max_conns{0};

    friend class ::storage_instance;
};

}   // namespace socketley::storage
