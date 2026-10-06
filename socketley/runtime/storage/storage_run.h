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
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <sys/types.h>

#include "body_reader.h"
#include "bucket_policy.h"
#include "checksum.h"
#include "multipart.h"
#include "notifier.h"
#include "object_store.h"
#include "post_policy.h"
#include "cluster.h"
#include "replicator.h"
#include "compactor.h"
#include "scrubber.h"
#include "tierer.h"
#include "s3_federation.h"
#include "s3_auth.h"
#include "s3_users.h"
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
    // SelectObjectContent requests answered, and the object bytes they scanned.
    uint64_t selects{0};
    uint64_t select_scanned{0};
    uint64_t client_errors{0};
    uint64_t server_errors{0};
    // Body bytes sent to clients, and the part of them that never entered this
    // process: they went file to pipe to socket inside the kernel.
    uint64_t bytes_out{0};
    uint64_t zero_copy_bytes{0};
    uint64_t zero_copy_gets{0};
    uint64_t copied_gets{0};
    // GETs answered from the hot small-object copy, with no file opened.
    uint64_t hot_gets{0};
    // Body bytes taken in from clients.
    uint64_t bytes_in{0};
    uint64_t timeouts{0};
    // Multipart: uploads begun, parts taken, uploads completed and aborted.
    uint64_t mpu_created{0};
    // Changes of buckets and locks another node of the cluster sent here.
    uint64_t cluster_in{0};
    // Corrupt copies the scrub had another node send again, and those no node held a good copy of.
    uint64_t scrub_heals{0};
    uint64_t scrub_unhealed{0};
    uint64_t mpu_parts{0};
    uint64_t mpu_completed{0};
    uint64_t mpu_aborted{0};
    // Objects a lifecycle rule expired and incomplete uploads one aborted.
    uint64_t lifecycle_expired{0};
    uint64_t lifecycle_aborted{0};
    // TLS handshakes that completed and that did not.
    uint64_t tls_handshakes{0};
    uint64_t tls_failures{0};
    // Receives that found the buffer ring empty and were taken by the connection's own buffer instead.
    uint64_t recv_fallbacks{0};
    // Recvs withdrawn, because the phase wanted a buffer of its own or what they brought had piled up.
    uint64_t recv_cancels{0};
    // Body bytes received straight into a put's staging buffer, without passing through one the ring lent.
    uint64_t recv_direct_bytes{0};
    // Receives that brought bytes of a body being streamed into an object.
    uint64_t body_recvs{0};
    // Bodies written encrypted, and GETs answered by opening an encrypted object's chunks.
    uint64_t sse_puts{0};
    uint64_t sse_gets{0};
    // GETs of a compressed body that its chunks were opened for, beyond the ones from memory.
    uint64_t compressed_gets{0};
    // GETs of a version moved to a tier, read from there.
    uint64_t tier_gets{0};
    // Media ffmpeg made and failed to make, and the answers served from what it made.
    uint64_t media_made{0};
    uint64_t media_failed{0};
    uint64_t media_served{0};
    // Jobs that read the object's file directly rather than over the listener, and jobs encoded on the GPU.
    uint64_t media_direct{0};
    uint64_t media_hw{0};
    // S3 errors answered, by the code in the XML.
    std::map<std::string, uint64_t, std::less<>> errors;
};

// The request as parsed: its head is kept whole and the fields are views into
// it, so an asynchronous step still finds them after the next read reused the
// input, and its buffers are reused by the next request on the connection.
struct s3_request
{
    s3_request() = default;
    // The views point into `head`, which a copy or a move would leave behind.
    s3_request(const s3_request&)            = delete;
    s3_request& operator=(const s3_request&) = delete;

    // Empties every field and keeps the buffers.
    void reset();

    // The head as it arrived, with the header names lowercased.
    std::string      head;
    std::string_view method;
    std::string_view version;
    std::string_view raw_path;
    std::string_view raw_query;
    std::string_view host;
    std::string_view payload_hash;
    std::string bucket;
    std::string key;
    std::vector<header_ref> headers;
    std::vector<std::pair<std::string, std::string>> query;
    std::string request_id;

    bool   has_content_length{false};
    uint64_t content_length{0};
    bool   chunked{false};
    bool   keep_alive{true};
    bool   expect_continue{false};
    // The bucket came from the Host header and the whole path is the key.
    bool   vhost{false};
    // The Host header named a bucket's website, which serves its objects to anyone a policy lets read them.
    bool   website{false};
    // The client asked with HEAD, whatever an application rewrote the method to since: its answer carries no body.
    bool   head_request{false};
    // The path began with a name no bucket can have (~dav, ~share, ~ui): the runtime's own applications.
    uint8_t app{0};
    // A browser's upload by form, whose fields became the key and the headers of a PutObject.
    std::unique_ptr<post_form> form;

    std::string_view header(std::string_view lower) const
    {
        for (const auto& h : headers)
            if (h.name == lower)
                return h.value;
        return {};
    }
    bool has_header(std::string_view lower) const
    {
        for (const auto& h : headers)
            if (h.name == lower)
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

// The algorithm x-amz-checksum-algorithm names, none without it; false with `err` for one the runtime cannot take.
bool checksum_algorithm_header(const s3_request& r, checksum_algo& out, s3_error& err);

// Whether the request writes or deletes a replica for another runtime's replication, which it says with its
// x-amz-replication-status header and is judged for as s3:ReplicateObject or s3:ReplicateDelete.
bool replica_request(const s3_request& r);

// The tags an x-amz-tagging header names, put into `m`; false with `err` when S3 would refuse them.
bool tagging_from_header(const s3_request& r, object_meta& m, s3_error& err);

// False with `err` when the request carries a Content-MD5 its body does not match.
bool body_md5_ok(const s3_request& r, std::string_view body, s3_error& err);
// The same for an x-amz-checksum-* header too, and false when the request carries neither, as S3 requires of some.
bool body_integrity_ok(const s3_request& r, std::string_view body, s3_error& err);

// The encryption a request names for what it writes, or the one its bucket gives it.
struct sse_ask
{
    sse_mode mode{sse_mode::none};
    std::optional<sse_key> customer;
    // The KMS key id an SSE-KMS write is sealed under.
    std::string kms_key;
    // The request said so itself, which lets a copy of an object onto itself change nothing else.
    bool     named{false};
};

// The prefixes of the SSE-C headers that name the key of what a request writes or reads, and of its copy source.
inline constexpr std::string_view sse_c_prefix      = "x-amz-server-side-encryption-customer-";
inline constexpr std::string_view sse_c_copy_prefix = "x-amz-copy-source-server-side-encryption-customer-";

// The headers that tell a client how `m` is encrypted, its key's MD5 as the request gave it under `prefix`.
void sse_headers(const s3_request& r, const object_meta& m, std::vector<std::pair<std::string, std::string>>& out,
                 std::string_view prefix = sse_c_prefix);

// The bucket and key an x-amz-copy-source header names, decoded; false with
// `err` when it names neither or is not one.
bool parse_copy_source(std::string_view header, std::string& bucket, std::string& key, s3_error& err,
                       std::string* version_id = nullptr);

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
    // Reading a browser's form up to its file, whose fields say what the upload is.
    form_head,
};

class storage_run;

struct response;
struct select_job;
struct zip_job;

// What of a bucket's ACL, and of an object's own, a request of action `a` needs, none for one they say nothing to.
uint8_t bucket_acl_need(s3_action a);
uint8_t object_acl_need(s3_action a);
struct share_link;

// What ffprobe said of an object: a stream's ladder, playlists and filters are made from it.
struct media_probe
{
    double  duration{0};
    double  fps{0};
    int64_t width{0}, height{0}, bitrate{0}, vlevel{0}, achannels{0};
    std::string vcodec, vprofile, transfer, acodec, format;
    bool    audio{false};
    struct subtitle
    {
        int64_t     index{0};
        std::string codec, lang, title;
    };
    // Text subtitles only, which WebVTT carries; pictures of text are not.
    std::vector<subtitle> subtitles;
    // The first picture carries HDR10's mastering display metadata, which the GPU's tone mapping cannot do without.
    bool    mastering{false};
    bool hdr() const { return transfer == "smpte2084" || transfer == "arib-std-b67"; }
};

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
    // Null on a cleartext connection.  With a session, what a recv brings is
    // ciphertext, `wq` holds plaintext waiting for the record layer and `wbuf`
    // the ciphertext the kernel is reading.
    SSL*            ssl{nullptr};
    tls_conn_state  tls_state{tls_conn_none};
    bool            pulling{false};
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

    // A recv lands in a buffer the ring lends for the length of the completion, and for a body
    // with nothing to decode straight in the put's staging buffer instead.
    bool        rd_direct{false};
    // The armed recv is one that keeps delivering until it is cancelled or the peer goes.
    bool        rd_multi{false};
    // A cancel for that recv has been submitted, and its last completion is awaited.
    bool        rd_cancel{false};
    // The last recv took what the socket had and left it empty, so the next one waits for data instead of trying first.
    bool        rd_drained{true};
    // The body is trickling in, judged by what arrived since `rate_since`, and its next recv waits for the pace tick.
    bool        trickle{false};
    std::chrono::steady_clock::time_point rate_since{};
    uint64_t    rate_bytes{0};
    // Waiting for the tick, and armed by it, which the next recv is then not held from.
    bool        paced{false};
    bool        pace_due{false};
    // The peer will send no more, which a connection still answering does not act on until it is done.
    bool        peer_eof{false};
    // Read into by a recv the ring could not serve, and only then allocated.
    std::unique_ptr<char[]> fbuf;
    bool        rd_fallback{false};

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
    // What is done once everything queued has been written.
    enum class after_kind : uint8_t { none, finish, pump };
    after_kind  after_write{after_kind::none};
    bool        close_after_write{false};

    // ── A body being collected ──────────────────────────────────────────────
    std::string body;
    uint64_t    body_limit{0};
    uint64_t    body_left{0};        // bytes of Content-Length still to come
    http_chunked_decoder chunk;
    std::string chunk_in;            // chunked framing waiting for the rest of a line
    bool        on_body{false};      // the small body is routed when it is complete

    // ── A body streaming into an object ─────────────────────────────────────
    std::shared_ptr<put_op>    put;
    // Shared with the job that is feeding it on a helper thread, which may outlive the request.
    std::shared_ptr<body_hook> hook;
    // A recv for a body whose hook is heavy lands here, in a buffer that the
    // hook's job then owns until it reports.
    std::shared_ptr<char[]> hbuf;
    // What `hbuf` holds that the hook has not been given, gathered so a trickling body is not handed over per segment.
    size_t      hfill{0};
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
    // The chunks of an encrypted object, opened a window at a time, which the file's bytes are sent through.
    std::shared_ptr<body_reader> dec;
    // A SelectObjectContent streaming its answer, which the pump feeds instead of a file's bytes.
    std::shared_ptr<select_job> sel;
    // A folder streamed as a ZIP, which the pump feeds entry by entry instead of a file's bytes.
    std::shared_ptr<zip_job> zip;
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
    // The user its key signs for, null for a request with no credentials.
    std::shared_ptr<const user_identity> user;
    // The CORS header lines every answer to this request carries, empty unless a rule allows its origin.
    std::string cors_head;
    // The peer's address as a policy condition compares it, read the first time one does.
    client_ip   ip;
    bool        ip_known{false};
    // The request carried no credentials, and was let in by a bucket policy rather than by the runtime.
    bool        anonymous{false};
    // Another node of the cluster sent it, to write what that node made, which no policy judges.
    bool        cluster{false};
    bool        policy_admitted{false};
    // A missing key is answered AccessDenied, for a requester a policy lets read and not list, as S3 does.
    bool        hide_missing{false};
    // The grants the object's own ACL must give, the bucket's having left the request to them.
    uint8_t     acl_need{0};
    // An ACL's grant admitted the request, which its access log line says.
    bool        by_acl{false};
    // The S3 error code the answer carries, for the access log.
    std::string error_code;
    // Given the answer before it is sent, by an application that turns an S3 answer into its own; it sends it on.
    std::function<void(const std::shared_ptr<conn>&, response&)> on_answer;
    // What a header an application added to the request points into.
    std::string app_header;
    // The share a request to ~share was let in by, for what it may still do.
    std::string share_id;
    // The key a website request asked for, before its index document was added.
    std::string website_key;
    // The failure a website request is serving its error document for, and its status.
    s3_error    website_error;
    int         website_status{0};
};

// An object's metadata as a script sees it: the user metadata without its
// header prefix, and the fields S3 reports.
storage_rpc::object_info rpc_info_of(const object_meta& m, std::string key = {});

// The text a status line gives after the code.
const char* reason_phrase(int status);

// A pass of the lifecycle sweep over every bucket with rules, which keeps its place between steps.
struct lifecycle_pass
{
    uint64_t id{0};
    std::vector<std::string> buckets;
    size_t   bucket{0};
    // The rules of the bucket being walked, null until its walk begins.
    std::shared_ptr<const lifecycle_config> cfg;
    bool     uploads_done{false};
    size_t   rule{0};
    // The rule's walk of the keys' versions, after its walk of their latest objects.
    bool     versions_phase{false};
    std::string resume;
    bool     has_resume{false};
    // Found due and not yet removed, each with the rules that found it.
    struct due_key
    {
        std::string bucket;
        // The object's key, or the upload's id when `upload`.
        std::string key;
        std::shared_ptr<const lifecycle_config> cfg;
        size_t      rule{0};
        bool        upload{false};
        // A version removed for good, rather than the latest object expired.
        std::string version_id{};
        // The tier the version moves to, rather than being removed.
        std::string tier{};
    };
    std::deque<due_key> due;
    uint32_t inflight{0};
    // Entries looked at since the step began, which a step does not exceed.
    size_t   scanned{0};
    bool     pumping{false};
    uint64_t expired{0};
    uint64_t aborted{0};
    uint64_t moved{0};
};

// One request's result, which every operation ends by giving to respond().
struct response
{
    int         status{200};
    std::string reason;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    // A body the caller holds until send_response returns, sent instead of `body`.
    std::string_view body_view;
    // Header lines already rendered, "Name: value\r\n" each, sent after `headers`.
    std::string_view headers_raw;
    // A HEAD or a 304 carries the headers a body would have and no body.
    bool        head_only{false};
    // The Content-Length to send when it is not the body's own.
    bool        has_length_override{false};
    uint64_t    length_override{0};
    bool        close{false};
    // The body follows in chunks of a length not known when the head is sent.
    bool        chunked{false};
};

class storage_run : public io_handler, public change_sink
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
    // The domains a Host of `<bucket>.<domain>` addresses a bucket under; none serves path style only.
    void set_website_domains(std::vector<std::string> d) { m_website_domains = std::move(d); }
    void set_domains(std::vector<std::string> d) { m_domains = std::move(d); }

    void on_cqe(struct io_uring_cqe* cqe) override;

    // Everything is closed and the run is left for the loop to finish with.
    void stop();
    // Nothing is owed to this run any more, so it can be freed.
    bool drained() const;


    size_t connection_count() const { return m_conns.size(); }
    const storage_counters& counters() const { return m_c; }
    object_store& store() { return m_store; }
    uint64_t hot_bytes() const { return m_store.hot_bytes(); }
    // Pieces of digest work handed to the helper threads.
    uint64_t hash_handoffs() const { return m_hash.submitted(); }
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
    notifier& notifications() { return m_notify; }
    const notifier& notifications() const { return m_notify; }
    replicator& replication() { return m_repl; }
    const replicator& replication() const { return m_repl; }
    // Makes this runtime a node of the cluster `cfg` names, before open().
    void set_cluster(cluster_config cfg);
    // A whole scrub in `secs`, 0 for none.
    void set_scrub_secs(uint32_t secs)
    {
        m_scrub.set_period(secs);
        if (secs)
            arm_sweep();
    }
    const scrubber& scrub() const { return m_scrub; }
    // Versions unwritten for `secs` are compressed, 0 for none.
    void set_compress_secs(uint32_t secs)
    {
        m_compact.set_age(secs);
        if (secs)
            arm_sweep();
    }
    const compactor& compaction() const { return m_compact; }
    // The tiers a bucket's lifecycle may move versions to, each named as the storage class its rules give.
    void set_tiers(std::vector<replication_target> tiers)
    {
        m_tier.set_tiers(std::move(tiers));
        if (m_tier.enabled())
            arm_sweep();
    }
    const tierer& tiers() const { return m_tier; }
    // The addresses whose connections arrive from a proxy that terminated TLS for them (--tls-offloaded).
    void set_tls_offloaded(std::vector<bucket_policy::cidr> from) { m_tls_offloaded = std::move(from); }
    // Whether the client reached the runtime over TLS, here or at a proxy --tls-offloaded trusts.
    bool secure(conn& c);
    // The OIDC provider and LDAP directory STS takes identities from (--federation).
    void set_federation(federation_config cfg)
    {
        m_fed  = std::make_unique<federation_config>(std::move(cfg));
        m_oidc = m_fed->oidc.enabled() ? std::make_unique<oidc_verifier>(m_fed->oidc) : nullptr;
    }
    // A version the scrub found corrupt: logged, and in a cluster taken away and sent again by a node that holds it.
    void scrub_found(scrubber::finding f);
    // Reads the id of this node's data, or makes it; blocking, so it runs at open().
    bool load_cluster_id(std::string& err);
    const std::string& cluster_self() const { return m_cluster_self; }
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
    // What the next recv on a connection should be, or that none should be.
    struct read_plan
    {
        enum class kind : uint8_t { none, ring, own };
        kind     k{kind::none};
        char*    buf{nullptr};
        uint32_t len{0};
        bool     direct{false};
        bool     hook{false};
    };
    read_plan plan_read(const conn& c) const;
    // Withdraws the recv that is armed, whose last completion says -ECANCELED.
    void cancel_read(const std::shared_ptr<conn>& c);
    // Arms the recvs that waited for this tick.
    void pace_tick();
    void read_done(const std::shared_ptr<conn>& c, struct io_uring_cqe* cqe);
    void write_done(const std::shared_ptr<conn>& c, struct io_uring_cqe* cqe);
    void splice_in_done(const std::shared_ptr<conn>& c, struct io_uring_cqe* cqe);
    void splice_out_done(const std::shared_ptr<conn>& c, struct io_uring_cqe* cqe);
    // Plaintext, wherever it came from: the socket's bytes or a session's.
    void plain_in(const std::shared_ptr<conn>& c, const char* p, size_t n);
    void tls_in(const std::shared_ptr<conn>& c, const char* data, size_t n);
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
    bool parse_head(const std::shared_ptr<conn>& c, std::string_view head);
    void send_response(const std::shared_ptr<conn>& c, response r);
    void send_error(const std::shared_ptr<conn>& c, const s3_error& e, bool close = false,
                    std::string_view extra_name = {}, std::string_view extra_value = {});
    void send_error_st(const std::shared_ptr<conn>& c, st s);
    // Sets the bucket's document of `kind`, or removes it for an empty `xml`, and answers `status` with no body.
    void store_doc(const std::shared_ptr<conn>& c, bucket_doc kind, std::string bucket, std::string xml, int status);
    // One more answered with this S3 error code, for `stats` and the metrics, and `c`'s for its access log.
    void count_error(conn& c, std::string_view code);
    void finish_request(const std::shared_ptr<conn>& c);
    void reset_request(const std::shared_ptr<conn>& c);
    // The status line and headers, with room reserved for `room` more bytes behind them.
    std::string response_head(const conn& c, const response& r, size_t room = 0) const;

    // A body of known small size, gathered whole and then routed.
    void collect_body(const std::shared_ptr<conn>& c, uint64_t limit);
    // The operation a request with its small body in hand asks for.
    void route_small(const std::shared_ptr<conn>& c);
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
    // Whether the buckets a request names belong to the owners its x-amz-expected-bucket-owner headers name.
    bool expected_owner_ok(const s3_request& r) const;

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
    // A browser's upload by form (POST Object), in storage_post.cpp: its fields are read, its policy and
    // signature checked, and it goes on as the PutObject its fields describe.
    void begin_post_form(const std::shared_ptr<conn>& c);
    void post_form_more(const std::shared_ptr<conn>& c);
    void post_form_ready(const std::shared_ptr<conn>& c);
    void send_post_result(const std::shared_ptr<conn>& c, const object_meta& m);
    void op_list_buckets(const std::shared_ptr<conn>& c);
    void op_create_bucket(const std::shared_ptr<conn>& c);
    void op_delete_bucket(const std::shared_ptr<conn>& c);
    void op_head_bucket(const std::shared_ptr<conn>& c);
    // False with `err` S3's refusal of a write's ACL headers, `bucket` for a bucket being made.
    bool acl_headers_ok(const std::shared_ptr<conn>& c, bool bucket, s3_error& err);
    // The bucket's ownership, its default when it was given none: ObjectWriter under --acls, else BucketOwnerEnforced.
    object_ownership bucket_ownership(std::string_view bucket) const;
    // Who an ACL's grant may name.
    acl_resolver acl_users() const;
    // Makes `m`, a new object's, hold the owner and grants its write asks for where the bucket takes ACLs.
    bool object_acl_stamp(const std::shared_ptr<conn>& c, object_meta& m, s3_error& err);
    // Whether the object's own grants give the requester what its request needs of them, when the bucket left that
    // to them.
    bool acl_admits(const std::shared_ptr<conn>& c, const object_meta& m);
    // Makes a new bucket's ownership and ACL what its CreateBucket asked for, then runs `then`.
    void create_bucket_docs(const std::shared_ptr<conn>& c, const std::string& name, std::function<void(st)> then);
    // ACLs are taken by every bucket that was given no ownership controls (--acls).
    void set_acls_default(bool on) { m_acls_default = on; }
    // False with `err` when a write asks for a storage class S3 does not have.
    static bool storage_class_ok(const s3_request& r, s3_error& err);
    void op_get_acl(const std::shared_ptr<conn>& c);
    void op_put_acl(const std::shared_ptr<conn>& c);
    void op_ownership_controls(const std::shared_ptr<conn>& c);
    void op_bucket_location(const std::shared_ptr<conn>& c);
    // PutBucketCors, GetBucketCors and DeleteBucketCors, and the OPTIONS preflight, in storage_cors.cpp.
    void op_put_cors(const std::shared_ptr<conn>& c);
    void op_get_cors(const std::shared_ptr<conn>& c);
    void op_delete_cors(const std::shared_ptr<conn>& c);
    void op_preflight(const std::shared_ptr<conn>& c);
    // Fills the connection's CORS lines for an actual request from an origin a rule of its bucket allows.
    void cors_actual(const std::shared_ptr<conn>& c);
    // PutBucketPolicy, GetBucketPolicy, DeleteBucketPolicy and GetBucketPolicyStatus, in storage_policy.cpp.
    void op_put_policy(const std::shared_ptr<conn>& c);
    void op_get_policy(const std::shared_ptr<conn>& c);
    void op_delete_policy(const std::shared_ptr<conn>& c);
    void op_get_policy_status(const std::shared_ptr<conn>& c);
    // Whether a request by `user` (null for none) is judged by more than its signature: a bucket has a policy, or
    // the user is not an admin free of an identity policy.
    bool needs_judging(const user_identity* user) const
    {
        if (user && user->cluster)
            return false;
        return m_store.any_policy() || m_store.any_acls() || m_acls_default || (user && !user->unrestricted());
    }
    // Judges an authenticated or anonymous request by ownership and the policies of the buckets it touches,
    // changing `v`.
    void apply_policy(const std::shared_ptr<conn>& c, const request_view& rv, auth_verdict& v);
    // What ownership and every policy say to `q` by `user` (null for no credentials) on `bucket`: deny when a Deny
    // matches, allow when the user owns the bucket, is an admin or is let by a policy, and none otherwise.
    policy_effect access_of(const std::shared_ptr<conn>& c, std::string_view bucket, const policy_request& q,
                            const user_identity* user);
    // What a user's own policies say to IAM action `action`, its place in iam_action_names, on `resource`.
    policy_effect iam_access(const std::shared_ptr<conn>& c, const user_identity& u, std::string_view principal,
                             int action, std::string_view resource);
    // The id of the user that owns `bucket`, the default owner for one that names none.
    std::string_view owner_of(std::string_view bucket) const
    {
        const std::string_view o = m_store.bucket_owner(bucket);
        return o.empty() ? default_owner : o;
    }
    // The display name an Owner element gives user `id`.
    std::string display_of(std::string_view id) const { return m_auth->display_name(id); }
    // Whether this request's policies let it remove version `version_id`'s key, which DeleteObjects names only in its body.
    bool policy_allows_version_delete(const std::shared_ptr<conn>& c, std::string_view key);
    // Whether the bucket's policy lets this request do `action` to `key` as well as what it was judged for.
    bool policy_allows(const std::shared_ptr<conn>& c, s3_action action, std::string_view key);

    // Event notifications, in storage_notify.cpp: the configuration's two operations, and the events of a change.
    void op_put_notification(const std::shared_ptr<conn>& c);
    void op_get_notification(const std::shared_ptr<conn>& c);
    // The events of a change, one `{target, json}` for every rule of its bucket that asks for it.
    std::vector<std::pair<std::string, std::string>> change_events(const change_note& n);
    // The store's sink for the events and copies of the changes the owner of their key makes.
    uint64_t stage(const change_note& n) override;
    void staged(uint64_t ticket, std::function<void()> then) override;
    void settle(uint64_t ticket, bool made, std::function<void()> then) override;
    void made(change_note n, std::function<void()> answer) override;
    // What a staged change's outbox record keeps of it, for the start that asks the files whether it was made.
    static std::string encode_change_check(const change_note& n);
    static bool decode_change_check(std::string_view b, change_note& n);

    // Replication, in storage_replication.cpp: the configuration's three operations, the status a new version is
    // written with, and the copies a change queues.
    void op_put_replication(const std::shared_ptr<conn>& c);
    // A bucket's website, in storage_website.cpp: the configuration's three operations, and a request to the website.
    void op_put_website(const std::shared_ptr<conn>& c);
    void op_get_website(const std::shared_ptr<conn>& c);
    void op_get_logging(const std::shared_ptr<conn>& c);
    void op_put_logging(const std::shared_ptr<conn>& c);
    // Notes the answer to `c`'s request, `status` with `bytes` of body, in its bucket's access log when it has one.
    // `op`, `key` and `error`, when given, stand for the request's own, as for each key of a DeleteObjects.
    void access_log(const std::shared_ptr<conn>& c, int status, uint64_t bytes, std::string_view op = {},
                    std::string_view key = {}, std::string_view error = {});
    // Delivers the access logs held longer than the delivery interval, or every one when `all`.
    void flush_access_logs(bool all);
    void deliver_access_log(const std::string& target, std::string key, bool partitioned, const std::string& acl,
                            std::string data);
    void op_get_public_access(const std::shared_ptr<conn>& c);
    void op_put_public_access(const std::shared_ptr<conn>& c);
    void op_delete_public_access(const std::shared_ptr<conn>& c);
    // The runtime's own applications under the paths no bucket can have, in storage_dav.cpp and its neighbours:
    // true when the request was one, and is answered or under way.
    bool app_request(const std::shared_ptr<conn>& c);
    // A request whose body the application read whole, given on from route_small.
    void app_body(const std::shared_ptr<conn>& c);
    void op_dav(const std::shared_ptr<conn>& c);
    void dav_body(const std::shared_ptr<conn>& c);
    void dav_propfind(const std::shared_ptr<conn>& c, const std::string& bucket, const std::string& key);
    void dav_collection(const std::shared_ptr<conn>& c, const std::string& bucket, const std::string& key);
    void dav_tree(const std::shared_ptr<conn>& c, std::string bucket, std::string prefix, std::string dst_bucket,
                  std::string dst_prefix, bool keep_source);
    // A versioned bucket's deleted files under a folder, and one of them brought back by removing its delete marker.
    void dav_trash(const std::shared_ptr<conn>& c, std::string bucket, std::string prefix);
    void dav_restore(const std::shared_ptr<conn>& c, std::string bucket, std::string key);
    // Turns the request into the S3 operation `method` on `bucket`/`key` and sends it down the S3 path, after the
    // policy has had its say; `extra` is a header to add, name and value, and `query` the S3 query it carries.
    void app_forward(const std::shared_ptr<conn>& c, std::string_view method, std::string bucket, std::string key,
                     std::string_view extra_name = {}, std::string extra_value = {},
                     std::vector<std::pair<std::string, std::string>> query = {});
    // Whether the request's user may do `method` to `bucket`/`key` as S3 would judge it.
    bool app_allowed(const std::shared_ptr<conn>& c, std::string_view method, std::string_view bucket,
                     std::string_view key, std::string_view query = {});
    // Whether the user lists bucket `b` among its own: one it owns, one a policy lets it list, every one for an admin.
    bool lists_bucket(const std::shared_ptr<conn>& c, const bucket_info& b);
    // Every page of a listing as one, up to the bound an application lists to.
    void app_list(std::string bucket, list_query q, std::function<void(st, list_page)> done);
    // HTTP Basic credentials, the web interface's session cookie, or none on a runtime that takes none; false after
    // answering 401.
    bool app_login(const std::shared_ptr<conn>& c, std::string_view realm);
    // Failed sign-ins counted by the client's address, an IPv6 one by its /64, in this shard's memory: past
    // login_tries within login_window a sign-in from there is refused until the window ends.
    struct login_misses
    {
        uint32_t count{0};
        std::chrono::steady_clock::time_point first{};
    };
    std::unordered_map<std::string, login_misses> m_misses;
    std::string miss_key(conn& c);
    // Answers 429 and is true while the client's address may not sign in.
    bool login_barred(const std::shared_ptr<conn>& c);
    void login_missed(conn& c);
    // The web interface's session cookie judged into `v`; false when the request carries none.
    bool ui_cookie(const std::shared_ptr<conn>& c, auth_verdict& v);
    static bool has_ui_cookie(const conn& c);
    // A Content-Disposition that saves `key` under its last name, as ?download asks.
    static std::string attachment_of(std::string_view key);
    // A ZIP of what is under `prefix` in `bucket` (only the names in `only` and what is under them, when it names
    // any), saved as `archive`.zip, with an exact Content-Length; storage_zip.cpp.
    // `by_link` for a share link's folder, which its link and not the policies lets the visitor read.
    void zip_start(const std::shared_ptr<conn>& c, std::string bucket, std::string prefix, std::vector<std::string> only,
                   std::string archive, bool by_link);
    void zip_pump(const std::shared_ptr<conn>& c);
    // Lets go of an archive's open object, at a close or the next request.
    void zip_end(conn& c);
    // The interface's sign-in (/~ui/session) and the films a user has part watched (/~ui/progress).
    void ui_session(const std::shared_ptr<conn>& c);
    // The time before which a user's sessions are no longer let in, set by signing out everywhere into
    // <dir>/.ui/sessions/ and read from there again after a second, so the other shards follow.
    struct session_floor
    {
        int64_t ms{0};
        std::chrono::steady_clock::time_point at{};
    };
    std::unordered_map<std::string, session_floor> m_floors;
    int64_t sessions_since(const std::string& who);
    void ui_progress(const std::shared_ptr<conn>& c);
    void ui_progress_body(const std::shared_ptr<conn>& c);
    // Who else a library is shared with, /~ui/access, as statements of the bucket's policy.
    void ui_access(const std::shared_ptr<conn>& c);
    // Files and folders whose name holds a text, in every library the user lists, /~ui/search.
    void ui_search(const std::shared_ptr<conn>& c);
    // How full each library the user lists is, and an admin's quota on one, /~ui/usage.
    void ui_usage(const std::shared_ptr<conn>& c);
    void ui_usage_body(const std::shared_ptr<conn>& c);
    // A library's size summed from its listing, kept a minute: the bytes, the objects, and whether it was too large
    // to list whole.
    struct usage_count
    {
        uint64_t bytes{0}, objects{0};
        bool     partial{false};
        std::chrono::steady_clock::time_point at{};
    };
    std::unordered_map<std::string, usage_count> m_usage;
    void ui_access_body(const std::shared_ptr<conn>& c);
    void ui_body(const std::shared_ptr<conn>& c);
    void app_reply(const std::shared_ptr<conn>& c, int status, std::string body = {},
                   std::string_view type = "text/plain; charset=utf-8");
    void op_share(const std::shared_ptr<conn>& c);
    void share_body(const std::shared_ptr<conn>& c);
    // The link `id` names, once it is current and its password given; false after answering.
    bool share_open(const std::shared_ptr<conn>& c, std::string_view id, share_link& s);
    // The bucket and key a link and the path under it name, as share_open admits them; false after answering.
    bool share_target(const std::shared_ptr<conn>& c, std::string_view id, std::string_view rel, std::string& bucket,
                      std::string& key);
    void op_ui(const std::shared_ptr<conn>& c);
    // Thumbnails and HLS made by ffmpeg and kept under <dir>/.media/, in storage_media.cpp.
    struct media_want
    {
        std::string bucket, key, variant, dir, file;
        // The path after the variant as asked for, which a master playlist names its streams by.
        std::string source;
        // Where the object's ffprobe is kept, which a stream's playlists and filters are made from.
        std::string probe_dir;
        uint8_t     kind{0};
        bool        image{false};
        bool        head{false};
        // The segment asked for, -1 for a stream's init segment.
        int64_t     seg{-1};
        int64_t     deadline_ms{0};
        int64_t     asked_ms{0};
        // The object as one string, bucket, key and ETag, which its open file is kept under; and the version the
        // URLs of its playlists carry.
        std::string object, version;
    };
    void op_media(const std::shared_ptr<conn>& c);
    // A media request once its object is known, and its file open where ffmpeg may read it directly.
    void media_continue(const std::shared_ptr<conn>& c, media_want w);
    std::shared_ptr<const media_probe> media_probe_of(const std::string& probe_dir);
    // A medium's use, written to its lock's time at most once a minute, which eviction orders by.
    void media_touch(const std::string& dir);
    // Ends the rendition job at `i`: killed when running, its files cleared, the rendition marked done when whole.
    void media_end_rendition(size_t i, bool kill);
    void media_source(const std::shared_ptr<conn>& c, std::string_view rest);
    // Answers from the cache, or starts the making when no shard is at it; false while the request must wait.
    bool media_try(const std::shared_ptr<conn>& c, const media_want& w);
    // A stream's segment: served, or waited for while a job nears it, or a job (re)started at it.
    bool media_segment(const std::shared_ptr<conn>& c, const media_want& w);
    // The job that makes `w`, from segment `from` for a stream; false when ffmpeg could not be started.
    bool media_start(const media_want& w, int lock_fd, int64_t from);
    bool media_serve(const std::shared_ptr<conn>& c, const media_want& w, bool growing);
    void media_tick();
    void media_arm();
    // Evicts the least recently used media past the cache's size, never `keep`, the medium just made.
    void media_evict(const std::string& keep);
    void media_stop();
    // STS's GetSessionToken and AssumeRole, POST / with a form, answered with temporary credentials.
    void op_sts(const std::shared_ptr<conn>& c);
    // AssumeRoleWithWebIdentity and AssumeRoleWithLDAPIdentity, which carry no signature: an outside provider vouches
    // for the caller, and the session signs as the user the provider file maps it to.
    void op_sts_federated(const std::shared_ptr<conn>& c, const std::vector<std::pair<std::string, std::string>>& fields,
                          std::string_view action);
    void sts_fail(const std::shared_ptr<conn>& c, int status, std::string_view code, std::string_view message);
    // Mints the session of a federated caller mapped to `user`, as `action` answers it.
    void sts_federated_session(const std::shared_ptr<conn>& c, std::string_view action, const std::string& user,
                               const std::string& role_arn, const std::string& session_name, int64_t duration,
                               const std::string& policy);
    // IAM's users, keys, groups, roles and their policies, in storage_iam.cpp, for an admin, or a user its policies
    // allow.
    void op_iam(const std::shared_ptr<conn>& c, const std::vector<std::pair<std::string, std::string>>& fields,
                std::string_view action, const auth_verdict& v);
    // A request to a bucket's website: an object, its index document, a redirect, or an error page.
    void op_website(const std::shared_ptr<conn>& c);
    // A website request that failed with `e`: a redirect, the error document, or an HTML page.
    void website_failure(const std::shared_ptr<conn>& c, const s3_error& e);
    void website_error_page(const std::shared_ptr<conn>& c, const s3_error& e);
    void website_redirect_to(const std::shared_ptr<conn>& c, int status, std::string location);
    // Whether a website request with no credentials may read `c->req.key`, as GetObject.
    bool website_readable(const std::shared_ptr<conn>& c);
    void op_delete_website(const std::shared_ptr<conn>& c);
    // A bucket's quota, in storage_quota.cpp: its three operations, which only an admin may ask.
    void op_put_quota(const std::shared_ptr<conn>& c);
    void op_get_quota(const std::shared_ptr<conn>& c);
    void op_delete_quota(const std::shared_ptr<conn>& c);
    bool quota_admin(const std::shared_ptr<conn>& c);
    void op_get_replication(const std::shared_ptr<conn>& c);
    void op_delete_replication(const std::shared_ptr<conn>& c);
    // Puts into `m` the status a new version of `key` is written with: REPLICA for a replica a replication wrote,
    // PENDING when a rule of `bucket` copies it, and none for an SSE-C version, which is never copied.
    void replication_mark(std::string_view bucket, std::string_view key, object_meta& m, bool sse_c, bool replica);
    // Puts into `m` the version id a replica's source gave it, which the store gives the replica when it can.
    void replica_source(const s3_request& r, object_meta& m);
    // Queues the copies a change already made makes, true when any was.
    bool replicate_change(const change_note& n);
    // Stages the copies of a change about to be made, its ticket in the replication outbox or 0, and says in
    // `copied` whether the bucket's replication copies it.
    uint64_t stage_copies(const change_note& n, std::string_view check, bool& copied);
    // What the other nodes of the cluster are sent of a change this node made, false for nothing.
    bool node_change(const change_note& n, cluster_change& out) const;
    // Puts into `m` the stamp and the lock another node's write was made with, in storage_cluster.cpp; false with
    // `err` for a write that names none, or a version this node cannot keep until it hears of the bucket's versioning.
    bool cluster_mark(const std::shared_ptr<conn>& c, object_meta& m, s3_error& err);
    // Applies a record of a bucket's or a version's change another node sent.
    void op_cluster(const std::shared_ptr<conn>& c);
    // The IAM document as a record for another node, empty for none, and one another node sent taken when it is the
    // newer, in storage_iam.cpp; blocking, as an IAM change is.
    std::string iam_record();
    st iam_take(int64_t rev, const std::string& json);
    // A share link made, counted or revoked (`json` empty) told to the other nodes, `then` once that is durable when
    // given; one another node told taken, its downloads the larger count; and every link as records, in
    // storage_share.cpp.
    void share_sent(const std::string& id, std::string json, std::function<void()> then);
    st share_take(const std::string& id, const std::string& json);
    // Links that burn what they name, ended at their expiry or after their last download: looked over by the sweep.
    void share_burn_tick();
    void share_burn(std::string id, std::string bucket, std::string key, bool folder);
    // A link's webhook told of a download or of its files' removal, in order, one exchange at a time per URL.
    static bool notify_allowed(std::string_view url);
    void share_tell(const std::string& url, std::string_view what, const std::string& bucket, const std::string& key,
                    uint64_t downloads, uint64_t max_downloads, int64_t expires_ms, bool burn);
    void share_tell_next(const std::string& url);
    struct hook_peer
    {
        std::unique_ptr<http_peer> peer;
        std::deque<std::string> queue;
        std::chrono::steady_clock::time_point used{};
    };
    std::unordered_map<std::string, std::unique_ptr<hook_peer>> m_hooks;
    std::vector<std::string> share_records();
    // Who a request's change is told as: its user or "anonymous", and the client's address, left empty for a
    // bucket that sends no events.
    change_origin origin_of(const conn& c) const;
    // A lifecycle rule's expiry, which S3's records name as S3 itself.
    static change_origin lifecycle_origin() { return {"s3.amazonaws.com", {}}; }

    // Object lock, in storage_object_lock.cpp.
    void op_put_object_lock_config(const std::shared_ptr<conn>& c);
    void op_get_object_lock_config(const std::shared_ptr<conn>& c);
    // PutObjectRetention and PutObjectLegalHold, and the two Gets.
    void op_put_lock_attr(const std::shared_ptr<conn>& c, bool legal_hold);
    void op_get_lock_attr(const std::shared_ptr<conn>& c, bool legal_hold);
    // Whether the request asks to go past a GOVERNANCE retention of `key` and may.
    bool bypass_allowed(const std::shared_ptr<conn>& c, std::string_view key);
    // The retention and legal hold a write's headers ask for, or its bucket's default, put into `m`; false with
    // `err` when S3 would refuse them.
    bool lock_from_headers(const std::shared_ptr<conn>& c, object_meta& m, s3_error& err);
    // False, with the request refused, while a bucket it touches is waiting to learn of a change to its documents.
    bool docs_settled(const std::shared_ptr<conn>& c);
    void op_list_objects(const std::shared_ptr<conn>& c, bool v2);
    void op_copy_from(const std::shared_ptr<conn>& c, std::string src_bucket, std::string src_key,
                      std::string src_version, bool replace, const object_meta& src_meta);
    void op_delete_objects(const std::shared_ptr<conn>& c);
    void op_put_object(const std::shared_ptr<conn>& c);
    void start_put(const std::shared_ptr<conn>& c, std::string key, object_meta meta,
                   put_op::committer committer, checksum_algo forced_algo = checksum_algo::none,
                   const put_condition& cond = {}, const part_place& place = {}, const sse_seal_spec* seal = nullptr);
    // The size the body will have, and whether the request says it.
    static bool body_length(const conn& c, uint64_t& expected);
    void op_copy_object(const std::shared_ptr<conn>& c);

    // Server-side encryption, in storage_sse.cpp.
    void set_sse_master(const sse_key& k);
    bool has_sse_master() const { return m_has_master; }
    // PutBucketEncryption, GetBucketEncryption and DeleteBucketEncryption.
    void op_put_encryption(const std::shared_ptr<conn>& c);
    void op_get_encryption(const std::shared_ptr<conn>& c);
    void op_delete_encryption(const std::shared_ptr<conn>& c);
    // What a new object of `bucket` is encrypted with; false with `err` once the request is refused.
    bool sse_for_write(const std::shared_ptr<conn>& c, std::string_view bucket, sse_ask& out, s3_error& err);
    // A fresh data key for a new object or upload, wrapped into the record `meta` is given.
    bool sse_new_key(const sse_ask& ask, bool per_part, object_meta& meta, sse_seal_spec& seal, s3_error& err);
    // The key a part of an upload is sealed with, from the upload's `record`, which the part's `meta` is given too;
    // an empty record seals nothing.
    bool sse_part_key(const std::shared_ptr<conn>& c, const std::string& record, uint32_t number, object_meta& meta,
                      sse_seal_spec& seal, s3_error& err);
    // Binds a completed upload's part list to its data key: wrapped again with it under the key at hand, or for an
    // SSE-C upload begun with an upload's wrap and completed without its client's key, MACed under the master key;
    // refused when neither can be.
    s3_error sse_bind_parts(object_meta& m, const std::optional<sse_key>& customer) const;
    // Whether an SSE-C object's part list MAC is there and holds, false with `err` when it does not.
    bool sse_parts_mac_ok(const object_meta& m, const std::string& record, const sse_digest& parts,
                          s3_error& err) const;
    // The key the SSE-C headers under `prefix` give, none when they are absent; false with `err` when they are refused.
    bool sse_customer(const std::shared_ptr<conn>& c, std::string_view prefix, std::optional<sse_key>& out,
                      s3_error& err);
    // The data key of `m`, opened with the master key or with `customer`, whichever its record names.
    bool sse_data_key(const object_meta& m, const std::optional<sse_key>& customer, sse_key& out, s3_error& err) const;
    // Both, for a read of `m` whose key headers are under `prefix`; an object stored in the clear takes none, and
    // one under the master key is not opened unless `need_key`, since only its bytes need it.
    bool sse_read_key(const std::shared_ptr<conn>& c, const object_meta& m, std::string_view prefix, sse_key& out,
                      s3_error& err, bool need_key = true);
    // Sends [first, first + len) of an encrypted object through its chunks, as send_file sends a clear one.
    // Reads the part list `m` keeps after its body, from `fd` or from the file opened again when it is -1, and
    // hands `then` the header of the file it came from, the file still open for a GET, and the list.
    void read_part_list(const std::shared_ptr<conn>& c, const object_meta& m, int fd, uint64_t data_off, bool head,
                        std::function<void(const object_meta&, int, uint64_t, bool, const part_list&)> then);
    // A body that is sealed, opened with `key`, or compressed, opened with none.
    void send_sealed(const std::shared_ptr<conn>& c, response head, int fd, uint64_t data_off, const object_meta& m,
                     const sse_key* key, uint64_t first, uint64_t len);
    // A body `reader` brings from elsewhere, a version moved to a tier.
    void send_reader(const std::shared_ptr<conn>& c, response head, std::shared_ptr<body_reader> reader, uint64_t len);
    void sealed_pump(const std::shared_ptr<conn>& c);
    // SelectObjectContent: a SQL expression run over a CSV or JSON object, answered as an event stream.
    void op_select(const std::shared_ptr<conn>& c);
    void select_pump(const std::shared_ptr<conn>& c);
    // Feeds [first, first + len) of a source object's plaintext into `op`, opening it with the key `customer`
    // or the master gives, and runs `done` with the put's result; a failure on the way is answered here.
    struct copy_feed;
    void feed_copy(const std::shared_ptr<conn>& c, std::shared_ptr<put_op> op, const std::string& src_bucket,
                   const std::string& src_key, const std::string& src_version, std::optional<sse_key> customer,
                   uint64_t first, uint64_t len, std::function<void(const std::shared_ptr<conn>&, put_result)> done);
    // CopyObject when the source or the copy is encrypted, which a copy of the bytes cannot be.
    void copy_sealed(const std::shared_ptr<conn>& c, std::string src_bucket, std::string src_key,
                     std::string src_version, object_meta meta, const object_meta& src, const sse_ask& dst,
                     std::optional<sse_key> src_customer, std::string source_id, checksum_algo algo);

    // Multipart, in storage_multipart.cpp.
    void op_create_multipart(const std::shared_ptr<conn>& c);
    void op_upload_part(const std::shared_ptr<conn>& c);
    void op_upload_part_copy(const std::shared_ptr<conn>& c);
    void op_complete_multipart(const std::shared_ptr<conn>& c);
    // The answer to a completion, for the object it made.
    void send_completed(const std::shared_ptr<conn>& c, const object_meta& m, const std::string& checksum_b64);
    // A completion of an upload that is gone, answered as before when the key still holds what it made.
    void completed_before(const std::shared_ptr<conn>& c, const std::string& id, s3_error missing);
    void op_abort_multipart(const std::shared_ptr<conn>& c);
    void op_list_parts(const std::shared_ptr<conn>& c);
    void op_list_uploads(const std::shared_ptr<conn>& c);
    // `number` and its body's size ask for a place in the upload's data file, which `go` is given.
    void with_open_upload(const std::shared_ptr<conn>& c, uint32_t number,
                          std::function<void(checksum_algo, part_place)> go);
    void op_upload_part_copy_from(const std::shared_ptr<conn>& c, uint32_t number, checksum_algo algo,
                                  const std::string& src_bucket, const std::string& src_key,
                                  const std::string& src_version, const object_meta& src_meta,
                                  const std::string& record);
    bool part_number_of(const std::shared_ptr<conn>& c, uint32_t& number);
    void reap_uploads();

    // Lifecycle: the configuration's three operations, and the sweep that carries it out, in storage_lifecycle.cpp.
    void op_put_lifecycle(const std::shared_ptr<conn>& c);
    void op_get_lifecycle(const std::shared_ptr<conn>& c);
    void op_delete_lifecycle(const std::shared_ptr<conn>& c);
    // Starts a pass when one is due, from the sweep's tick.
    void lifecycle_tick();
    // Moves the pass on by a bounded step: deletes up to the in-flight cap, and a bounded walk to find more.
    void lifecycle_pump();
    // A bucket's rules changed, so a pass runs soon.
    void lifecycle_changed();
    void lifecycle_issue(lifecycle_pass& p);
    // False when the pass has nothing left to walk.
    bool lifecycle_walk(lifecycle_pass& p);
    void lifecycle_done(uint64_t pass_id);
    // A HEAD finds the object as GetObjectAttributes does, which `attributes` answers instead.
    void op_get_object(const std::shared_ptr<conn>& c, bool head, bool attributes = false);
    // x-amz-expiration for the latest object `key`, when a lifecycle rule of its bucket will expire it.
    void expiration_header(std::string_view bucket, std::string_view key, const object_meta& m,
                           std::vector<std::pair<std::string, std::string>>& headers) const;
    void op_delete_object(const std::shared_ptr<conn>& c);
    // Versioning, in storage_versioning.cpp: the bucket's configuration, ListObjectVersions, and the
    // answers a request naming a version or meeting a delete marker is given.
    void op_get_versioning(const std::shared_ptr<conn>& c);
    void op_put_versioning(const std::shared_ptr<conn>& c);
    void op_list_versions(const std::shared_ptr<conn>& c);
    // The request's versionId, empty when it names none; false once it has been refused as malformed.
    bool version_param(const std::shared_ptr<conn>& c, std::string& out);
    // A 404 for a key whose latest is the delete marker `m`, or a 405 for the marker asked for by its id.
    void send_delete_marker(const std::shared_ptr<conn>& c, const object_meta& m, bool by_version);
    // PutObjectTagging, GetObjectTagging and DeleteObjectTagging, in storage_tagging.cpp.
    void op_put_object_tagging(const std::shared_ptr<conn>& c);
    void op_get_object_tagging(const std::shared_ptr<conn>& c);
    // A bucket's own tags, in storage_tagging.cpp, kept as a bucket document like its CORS rules.
    void op_put_bucket_tagging(const std::shared_ptr<conn>& c);
    void op_get_bucket_tagging(const std::shared_ptr<conn>& c);
    void op_delete_bucket_tagging(const std::shared_ptr<conn>& c);
    void op_delete_object_tagging(const std::shared_ptr<conn>& c);
    bool object_meta_from_headers(const std::shared_ptr<conn>& c, object_meta& m, s3_error& err);
    void new_request_id(std::string& id);

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
    notifier          m_notify;
    replicator        m_repl;
    scrubber          m_scrub;
    compactor         m_compact;
    tierer            m_tier;
    std::vector<bucket_policy::cidr> m_tls_offloaded;
    bool              m_acls_default{false};
    std::unique_ptr<federation_config> m_fed;
    std::unique_ptr<oidc_verifier> m_oidc;
    // The thread an LDAP bind waits on, apart from the digests', since a bind may take seconds.
    hash_pool         m_ldap_pool{1};
    bool              m_ldap_attached{false};
    // The name the cluster file gives this node, empty for a runtime that is no node of one, and the id of its data.
    std::string       m_cluster_self;
    std::string       m_cluster_id;
    // Each change staged and not yet settled, by the ticket the store holds: its tickets in the two outboxes, and the
    // change itself when it was written PENDING and nothing was staged to copy it, which settle() then marks FAILED.
    struct staged_change
    {
        uint64_t notify{0};
        uint64_t copies{0};
        std::optional<change_note> uncopied;
        // Its answer began to wait, which a commit begins after it settled.
        bool     answered{false};
    };
    // The copies of changes settled before their answer, by ticket, which that answer waits for when sync asks it to.
    std::unordered_map<uint64_t, uint64_t> m_settled_copies;
    std::unordered_map<uint64_t, staged_change> m_staged;
    uint64_t          m_next_ticket{1};
    // The last sequencer an event was given, which only grows.
    uint64_t          m_notify_seq{0};
    // What carries a request to a sibling shard, and the logic that makes one
    // and answers one; a runtime of one shard never calls the transport.
    channel_transport m_transport;
    shard_node        m_node;
    authenticator*    m_auth;
    std::unique_ptr<authenticator> m_auth_owned;
    anonymous_authenticator m_anon;
    uint32_t          m_mpu_expire_secs{0};
    std::chrono::steady_clock::time_point m_last_reap{};
    // How many links that burn the last look found, the ones this shard is removing for, and the next look.
    size_t            m_burns{0};
    std::unordered_set<std::string> m_burning;
    std::chrono::steady_clock::time_point m_burn_next{};
    // What a lifecycle day is, shorter only under SOCKETLEY_STORAGE_LIFECYCLE_DAY_SECS, a test aid.
    int64_t           m_lc_day_ms{0};
    std::unique_ptr<lifecycle_pass> m_lc;
    uint64_t          m_lc_passes{0};
    std::chrono::steady_clock::time_point m_lc_next{};
    // The rules changed during a pass, so the next starts when it ends.
    bool              m_lc_again{false};
    std::unique_ptr<tls_context> m_tls;
    std::vector<std::string> m_domains;
    // The domains under which a Host names a bucket's website.
    std::vector<std::string> m_website_domains;
    // The key every SSE-S3 data key is wrapped with, and its name, when the runtime was given one.
    bool        m_has_master{false};
    sse_key     m_master{};
    std::array<uint8_t, 4> m_master_kid{};
    // The key an SSE-C part list is MACed with when its completion did not carry the client's key.
    sse_key     m_parts_mac_key{};

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
    // The pause between the steps of a lifecycle pass.
    timer       m_lc_timer;
    // One timer for every trickling body, and the connections waiting for it.
    timer       m_pace_timer;
    std::vector<uint64_t> m_paced;

    struct media_job
    {
        pid_t       pid{-1};
        int         lock_fd{-1};
        media_want  want;
        int64_t     started_ms{0};
        bool        seeked{false};
        // A rendition's job, one of several over one film: where it began, the next segment it writes, the film's
        // segments, the furthest one its players asked for and when, and whether it is held still for being ahead.
        int64_t     from{0}, next{0}, total{0}, wanted{0}, asked_ms{0};
        bool        paused{false};
        // Encoded on the GPU, whose failure at its start sends the rendition back to x264.
        bool        gpu{false};
        // A shared hold on the rendition, which keeps its eviction off while any of its jobs runs.
        int         share_fd{-1};
        int64_t     playlist_mtime{0}, want_mtime{0};
    };
    std::vector<media_job> m_media_jobs;
    std::vector<std::pair<std::weak_ptr<conn>, media_want>> m_media_waits;
    timer       m_media_timer;
    // What this shard knows of the cache without asking the disk again: probes, renditions whole, uses written.
    std::unordered_map<std::string, std::shared_ptr<const media_probe>> m_media_probes;
    std::unordered_set<std::string> m_media_done;
    std::unordered_map<std::string, int64_t> m_media_touched;
    // An unencrypted object's open file, which ffmpeg reads as its own fd 3 rather than over the listener.
    struct media_src
    {
        int      fd{-1};
        uint64_t off{0}, len{0};
        int64_t  used_ms{0};
    };
    std::unordered_map<std::string, media_src> m_media_srcs;
    int64_t     m_media_evicted_ms{0};
    bool        m_media_dir_ready{false};
    // ffmpeg's path, looked up at the first media request; empty when there is none.
    std::string m_ffmpeg;
    bool        m_ffmpeg_known{false};
    // The GPU's encoder, found by a one-second test run: unknown, being tested, none, or VAAPI with or without the
    // low-power encoder; and the render node it is on.
    enum class media_hw : uint8_t { unknown, testing, none, vaapi, vaapi_lp };
    media_hw    m_hw{media_hw::unknown};
    bool        m_hw_tried_lp{false};
    std::string m_hw_device;
    void media_hw_detect();
    // The streams this shard makes at once, more where renditions are made on a GPU.
    int streams_max() const;
    bool media_hw_test(bool low_power);
    // The key that signs ffmpeg's reads of an object, shared by every shard through the cache's directory.
    std::string m_media_key;

    // Asked again at each sweep until every sibling has heard this shard started, or it gave up.
    void tell_started();
    enum class start_note : uint8_t { untold, telling, told };
    start_note  m_start_note{start_note::untold};
    uint32_t    m_start_tries{0};

    storage_counters m_c;
    uint64_t    m_rid_seq{0};
    // The decoded path of the request being parsed, kept for its capacity.
    std::string m_path_scratch;
    bool        m_stopped{false};

    // A put of a body held whole in memory, fed to the store as it takes it.
    struct whole_put
    {
        std::shared_ptr<put_op> put;
        std::string data;
        size_t      off{0};
        bool        finishing{false};
        bool        done{false};

        // Removes what was written, and tells nobody.
        void abort();
    };
    // Writes `data` as the object, encrypted when the bucket encrypts, marked for replication and with S3's default
    // checksum as a client's put is, telling `done` once; null with `err` when it cannot start.
    std::shared_ptr<whole_put> put_whole(const std::string& bucket, const std::string& key, object_meta meta,
                                         std::string data, std::function<void(st, const put_result*)> done,
                                         s3_error& err);

    // Server access logging, in storage_logging.cpp: lines held per destination until they are delivered as one
    // object, and the deliveries in flight, so a stop can drop them.
    struct access_log_buffer
    {
        std::string target;
        // The key in front of the object's name, the date partition excepted.
        std::string prefix;
        bool        partitioned{false};
        // The ACL each log object is written with, empty for its owner's full control.
        std::string acl;
        std::string data;
        std::chrono::steady_clock::time_point since{};
    };
    // The ACL TargetGrants give a log object in `target`, false with `err` for a grantee that is no one.
    bool logging_acl(const logging_config& cfg, std::string& out, s3_error& err) const;
    std::map<std::string, access_log_buffer, std::less<>> m_access_logs;
    std::vector<std::shared_ptr<whole_put>> m_log_deliveries;
    std::string m_log_line;

    // Calls from other runtimes' scripts still in flight, so a stop can answer them.
    struct rpc_state;
    std::unordered_map<uint64_t, std::shared_ptr<rpc_state>> m_rpc;
    // A cap on what streaming puts hold, so a thousand uploaders cannot ask for a thousand buffers.
    uint32_t    m_max_active_puts{512};
    size_t      m_zero_copy_min{64 * 1024};
    size_t      m_max_conns{0};
    // Whether a recv can be lent a buffer by the ring, and be armed once to keep delivering.
    bool        m_ring{false};
    bool        m_multishot{false};

    friend class ::storage_instance;
};

}   // namespace socketley::storage
