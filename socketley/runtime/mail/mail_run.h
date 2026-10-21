#pragma once
// The mail runtime on its sockets: SMTP on its port, submission with STARTTLS and over TLS on theirs, reads from a
// buffer ring so a connection that says nothing holds no read buffer of its own, each message streamed to the spool
// as it arrives and answered once it is on the disk, then handed to the delivery.
#include <cstdint>
#include <functional>
#include <optional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <netinet/in.h>
#include <openssl/ssl.h>
#include <sys/uio.h>

#include "mail_aliases.h"
#include "mail_command.h"
#include "imap_session.h"
#include "mail_spool.h"
#include "smtp_session.h"
#include "../../shared/crypto/password_file.h"
#include "../../shared/http/notifier.h"
#include "../../shared/ipc/request_channel.h"
#include "../../shared/loop/event_loop.h"
#include "../../shared/loop/file_io.h"
#include "../../shared/loop/hash_pool.h"
#include "../../shared/loop/write_queue.h"
#include "../../shared/persist/watched_file.h"

class mail_instance;
class tls_context;

namespace socketley::idp
{
class session_verifier;
}

namespace socketley::mail
{

class delivery;
class mailboxes;
class mail_lua;

// Where a recipient's mail goes: a mailbox of this runtime, an address elsewhere, or nowhere.
struct route_to
{
    enum kind : uint8_t { none, mailbox, remote, sink } k{none};
    // The mailbox's owner, or the address mail is sent on to.
    std::string target;
};

class mail_run : public io_handler, public request_origin
{
public:
    mail_run(mail_instance& owner, event_loop& loop);
    ~mail_run() override;

    bool start(std::string& why);
    void stop();
    bool drained() const;
    void on_loop_turn();
    void on_cqe(struct io_uring_cqe* cqe) override;

    // A command of the CLI, a script or a notification, answered through the channel.
    void command(uint64_t ticket, std::string_view payload);
    void on_request_reply(uint64_t cookie, request_status st, std::string_view reply) override;

    size_t conn_count() const { return m_conns.size(); }
    std::string stats() const;

    mail_instance& owner() { return m_owner; }
    event_loop& loop() { return m_loop; }
    file_io& fio() { return m_fio; }
    hash_pool& pool() { return m_pool; }
    spool& queue() { return m_spool; }
    const std::string& hostname() const { return m_hostname; }
    const std::vector<std::string>& domains() const { return m_domains; }
    bool is_local_domain(std::string_view d) const;
    const alias_table& aliases() const { return m_aliases.value(); }
    // An address a bounce said is dead, which mail is not sent to again until it is forgiven.
    bool suppressed(std::string_view addr) const;
    void suppress(std::string addr);
    // A bounce taken for no-reply@: the recipients it says failed, suppressed.
    void bounce_taken(std::string_view message);
    // Where mail for `a` goes, by the aliases, the no-reply address and the mailboxes.
    route_to route(const address& a, bool from_null) const;
    // A message of this runtime's own making queued, as a bounce or `socketley send` is: false when it cannot be.
    void queue_message(const std::string& from, const std::vector<std::string>& rcpts, std::string body, bool bounce,
                       std::string user, std::function<void(bool ok, std::string id)> done);
    uint32_t shard() const;
    std::string state_dir() const { return m_state_dir; }
    uint64_t next_cookie() { return m_next_cookie++; }
    // Who answers a request this runtime posted, by cookie.
    void expect_reply(uint64_t cookie, std::function<void(request_status, std::string_view)> cb);
    // A request to another runtime of the daemon, and its answer.
    void ask(const std::string& target, std::string payload, std::function<void(request_status, std::string_view)> cb);
    mailboxes* boxes() const { return m_mailboxes.get(); }
    // Whether the script decides recipients, and so takes those no mailbox has.
    bool script_takes() const;

private:
    enum class port_kind : uint8_t { smtp, submission, submissions, imap, imaps };
    struct conn : smtp_session::hooks, imap_session::hooks
    {
        mail_run* run{nullptr};
        uint64_t id{0};
        int fd{-1};
        sockaddr_in peer{};
        port_kind kind{port_kind::smtp};
        io_request rd{}, wr{};
        bool rd_pending{false}, wr_pending{false}, dead{false};
        bool rearm{false}, reflush{false};
        std::unique_ptr<char[]> rbuf;
        std::vector<socketley::write_chunk> queue;
        std::vector<socketley::write_chunk> sending;
        size_t sending_at{0};
        size_t sent{0};
        size_t owed{0};
        std::vector<iovec> iov;
        std::string spare;
        bool closing{false};
        int64_t closing_ms{0};
        int64_t heard_ms{0};
        SSL* ssl{nullptr};
        bool handshaken{false};
        // STARTTLS answered: what comes next is a handshake, after which the session starts over.
        bool upgrading{false};
        std::unique_ptr<smtp_session> smtp;
        std::unique_ptr<imap_session> imap;
        // The message being received, its spool writer and envelope.
        uint64_t writer{0};
        entry_ptr entry;
        // Bytes said in reply while input is being taken, written once it has all been.
        bool in_input{false};
        // An idp user signed in, and the address the account names, which with its username are what it sends as.
        bool idp_user{false};
        std::string user_email;

        void reply(std::string_view bytes) override;
        void start_tls() override;
        void authenticate(std::string_view mech, std::string user, std::string secret,
                          std::function<void(bool, std::string)> done) override;
        void mail_from(const address& from, std::function<void(rcpt_verdict)> done) override;
        void rcpt_to(const address& to, std::function<void(rcpt_verdict)> done) override;
        bool data_begin() override;
        void data_bytes(std::string_view piece) override;
        void data_end(std::function<void(rcpt_verdict)> done) override;
        void data_abort() override;
        void close() override;
        void login(std::string user, std::string password, std::function<void(bool, std::string)> done) override;
    };
    struct listener
    {
        int fd{-1};
        io_request req{};
        bool pending{false};
        port_kind kind{port_kind::smtp};
    };

    bool open_listener(listener& l, uint16_t port, port_kind kind, std::string& why);
    void arm_accept(listener& l);
    void accept_done(listener& l, struct io_uring_cqe* cqe);
    conn* conn_of(io_request* req);
    conn* find(uint64_t id);
    void arm_read(conn& c);
    void read_done(conn& c, struct io_uring_cqe* cqe);
    void bytes_in(conn& c, const char* p, size_t n);
    void tls_in(conn& c, const char* p, size_t n);
    void plain_in(conn& c, const char* p, size_t n);
    void out(conn& c, std::string_view bytes);
    void queue_owned(conn& c, std::string_view bytes);
    void queue_tls_out(conn& c);
    void flush(conn& c);
    void write_done(conn& c, int res);
    void close_soon(conn& c);
    void close_conn(conn& c);
    void settle();
    void arm_tick();
    void tick();
    void refresh_files();
    // The domains of --dns, from the zones the daemon writes, and the records this runtime gives them.
    void refresh_domains();
    void publish_records();
    std::string records_text() const;
    std::string m_published;
    std::unordered_set<std::string> m_suppressed;
    std::optional<socketley::file_stamp> m_suppressed_stamp;
    // Read again when another shard changed it, or merged with what is here before this one writes.
    void load_suppressed(bool merge);
    void save_suppressed();
    // The session of a connection once it may speak: at the accept, or once its TLS handshake is done.
    void begin_session(conn& c);
    smtp_config session_config(const conn& c) const;
    std::string received_line(const conn& c, const std::string& id, const std::string& rcpt) const;
    void accepted(const entry_ptr& e);
    std::string queue_text(std::string_view filter) const;
    std::string show_text(const std::string& id) const;
    void send_command(uint64_t ticket, socketley::bytes::reader& r);

    mail_instance& m_owner;
    event_loop& m_loop;
    file_io m_fio;
    hash_pool m_pool;
    // SPF, DKIM and DMARC of mail from elsewhere, whose lookups block a thread of these and never the loop.
    hash_pool m_checks;
    spool m_spool;
    std::unique_ptr<tls_context> m_tls;
    std::unique_ptr<socketley::idp::session_verifier> m_idp;
    std::unique_ptr<delivery> m_delivery;
    std::unique_ptr<mailboxes> m_mailboxes;
    std::unique_ptr<mail_lua> m_lua;
    // Each message stored in a mailbox, told to the targets of --notify-targets.
    std::unique_ptr<socketley::notifier> m_notify;
    std::vector<std::string> m_notify_names;
    socketley::watched<socketley::user_table> m_users;
    socketley::watched<alias_table> m_aliases;
    std::string m_hostname;
    std::vector<std::string> m_domains;
    std::string m_state_dir;

    listener m_smtp, m_sub, m_subs, m_imap_l, m_imaps_l;
    std::unique_ptr<imap_store> m_imap;
    std::unordered_map<uint64_t, std::unique_ptr<conn>> m_conns;
    std::vector<std::unique_ptr<conn>> m_closing;
    std::vector<uint64_t> m_close_soon;
    uint64_t m_next_id{1};
    bool m_ring{false};
    bool m_multishot{false};
    bool m_stopped{false};
    bool m_in_settle{false};
    std::string m_tls_out;

    io_request m_tick_req{};
    __kernel_timespec m_tick_ts{};
    bool m_tick_armed{false};
    int64_t m_next_files_ms{0};

    std::unordered_map<uint64_t, std::function<void(request_status, std::string_view)>> m_replies;
    uint64_t m_next_cookie{1};
    std::shared_ptr<bool> m_alive;

    uint64_t m_received{0};
    uint64_t m_refused_rcpt{0};
    uint64_t m_refused_relay{0};
    uint64_t m_auth_ok{0};
    uint64_t m_auth_failed{0};
    uint64_t m_tls_failures{0};
    uint64_t m_starttls{0};
    uint64_t m_too_big{0};
    uint64_t m_spool_failed{0};
    uint64_t m_bounces_taken{0};
    uint64_t m_suppressions{0};
    uint64_t m_checked{0};
    uint64_t m_dmarc_rejected{0};
    uint64_t m_quarantined{0};
};

}   // namespace socketley::mail
