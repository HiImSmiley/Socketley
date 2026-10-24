#pragma once
// The mail runtime on its sockets: SMTP on its port, submission with STARTTLS and over TLS on theirs, reads from a
// buffer ring so a connection that says nothing holds no read buffer of its own, each message streamed to the spool
// as it arrives and answered once it is on the disk, then handed to the delivery.
#include <array>
#include <cstdint>
#include <deque>
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
#include "mail_bayes.h"
#include "mail_command.h"
#include "imap_session.h"
#include "managesieve_session.h"
#include "mail_dnsbl.h"
#include "mail_greylist.h"
#include "mail_reports.h"
#include "pop3_session.h"
#include "jmap_session.h"
#include "../../shared/util/deflate.h"
#include "../../shared/util/inflate.h"
#include "mail_sieve_store.h"
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
    enum kind : uint8_t { none, mailbox, remote, sink, unsubscribe } k{none};
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
    // A lane for work that only computes, spread over every thread but the first, which waits on files and the network.
    uint32_t cpu_lane() { return 1 + m_pool.next_lane() % (m_pool.threads() > 1 ? m_pool.threads() - 1 : 1); }
    spool& queue() { return m_spool; }
    // A message of `user`'s, at `key`, learned by the spam filter as spam or not, on whichever shard it was moved.
    void learn(const std::string& user, const std::string& key, uint64_t size, bool spam);
    const std::string& hostname() const { return m_hostname; }
    const std::vector<std::string>& domains() const { return m_domains; }
    bool is_local_domain(std::string_view d) const;
    const alias_table& aliases() const { return m_aliases.value(); }
    // An address a bounce said is dead, which mail is not sent to again until it is forgiven.
    bool suppressed(std::string_view addr) const;
    // What an advertisement to `addr` carries to unsubscribe it, and the address a token stands for, empty where the
    // token is not this runtime's.
    std::string unsubscribe_token(std::string_view addr) const;
    std::string unsubscribe_address(std::string_view token) const;
    // `addr` unsubscribed by its token, false where the token is none.
    bool unsubscribe(std::string_view token);
    // Where the webmail is reached through the entrance, https://<its --domain>, empty without one.
    std::string web_url() const;
    // A bounce taken for `to`, no-reply+<token>@: the recipients it says failed, suppressed where the token is the
    // one this runtime sent mail for their domain under, so no one else's word suppresses an address.
    // A report this runtime made itself is its own word, `trusted`.
    void bounce_taken(std::string_view message, std::string_view to, bool trusted);
    // The tag of no-reply mail sent to `domain`, which its bounces come back with.
    std::string verp_token(std::string_view domain) const;
    // no-reply, or no-reply with a tag.
    static bool no_reply_local(std::string_view local);
    // Where mail for `a` goes, by the aliases, the no-reply address and the mailboxes.
    route_to route(const address& a, bool from_null) const;
    // A message of this runtime's own making queued, as a bounce or `socketley send` is: false when it cannot be.
    void queue_message(const std::string& from, const std::vector<std::string>& rcpts, std::string body, bool bounce,
                       std::string user, std::function<void(bool ok, std::string id)> done, bool requiretls = false);
    uint32_t shard() const;
    std::string state_dir() const { return m_state_dir; }
    uint64_t next_cookie() { return m_next_cookie++; }
    // Who answers a request this runtime posted, by cookie.
    void expect_reply(uint64_t cookie, std::function<void(request_status, std::string_view)> cb);
    // A request to another runtime of the daemon, and its answer.
    void ask(const std::string& target, std::string payload, std::function<void(request_status, std::string_view)> cb);
    mailboxes* boxes() const { return m_mailboxes.get(); }
    sieve_store* filters() const { return m_sieve.get(); }
    imap_store* imap() const { return m_imap.get(); }
    // Whether the script decides recipients, and so takes those no mailbox has.
    bool script_takes() const;
    // The runtime's own secret, which SRS signs the senders it rewrites with.
    const std::string& secret() const { return m_verp_key; }
    // A message `size` bytes long stored in `user`'s mailbox: the user is told once their quota is nearly full.
    void stored(const std::string& user, uint64_t size);
    // The DMARC and TLS results the reports of a day are made of.
    reports& report_book() { return m_reports; }
    // A local part less its tag, user+tag being user's, by --recipient-delimiter.
    std::string_view without_detail(std::string_view local) const;
    // imapsieve (RFC 6785): the script `folder` names run for what a client did to `uids` there, APPEND, COPY or
    // FLAG, and what it decided done to them.
    void imap_sieve(const std::string& user, const std::string& folder, std::string cause, std::vector<uint32_t> uids,
                    std::string changed);
    // A JMAP push posted from the pool (mail_push.cpp), and the users with subscriptions looked at for changes.
    void push_send(const std::string& url, const std::string& p256dh, const std::string& auth, std::string body);
    void push_tick();

private:
    enum class port_kind : uint8_t { smtp, submission, submissions, imap, imaps, sieve, pop3, pop3s, lmtp, sts, jmap, web };
    struct conn : smtp_session::hooks, imap_session::hooks, managesieve_session::hooks, pop3_session::hooks,
                  jmap_session::hooks
    {
        mail_run* run{nullptr};
        uint64_t id{0};
        int fd{-1};
        sockaddr_storage peer{};
        // Its address as text, IPv4 for a client a dual-stack listener took over IPv4.
        std::string ip;
        // The client the entrance in front of the webmail port forwards, whose failed sign-ins count against it.
        std::string forwarded;
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
        std::unique_ptr<managesieve_session> sieve;
        std::unique_ptr<pop3_session> pop3;
        std::unique_ptr<jmap_session> jmap;
        // An MTA-STS policy fetch: its request, read until its head ends.
        bool sts{false};
        std::string sts_in;
        // COMPRESS=DEFLATE: what goes out compressed as one block a loop turn, and what comes in opened.
        std::unique_ptr<socketley::deflater> zout;
        std::unique_ptr<socketley::inflater> zin;
        std::string zplain;
        std::string zopened;
        // The message being received, its spool writer and envelope.
        uint64_t writer{0};
        entry_ptr entry;
        // Bytes said in reply while input is being taken, written once it has all been.
        bool in_input{false};
        // What waits for the writes to come down to drained_at.
        std::function<void()> drained;
        // An idp user signed in, and the address the account names, which with its username are what it sends as.
        bool idp_user{false};
        std::string user_email;
        // Whether the user signed in on it may send as `a`: their username at one of the domains, the account's email,
        // or the username where it is an address.
        bool owns(const address& a) const;
        // The header of the message being received, up to its blank line, for its From to be checked; a signed-in
        // user's is held back from the spool until it is whole, so the Date and Message-ID it lacks go ahead of it.
        std::string head_seen;
        bool holding{false};
        void release_head(bool at_end);
        // Its address in --dnsbl's lists: not asked, being asked, listed nowhere, listed by `listed_by`; and the
        // MAIL that waits for the answer.
        uint8_t blocklist{0};
        std::string listed_by;
        std::function<void()> after_blocklist;

        void reply(std::string_view bytes) override;
        void start_tls() override;
        void authenticate(std::string_view mech, std::string user, std::string secret,
                          std::function<void(account, std::string)> done) override;
        void mail_from(const address& from, std::function<void(rcpt_verdict)> done) override;
        void rcpt_to(const address& to, std::function<void(rcpt_verdict)> done) override;
        bool data_begin() override;
        void data_bytes(std::string_view piece) override;
        void data_end(std::function<void(rcpt_verdict)> done) override;
        void data_abort(bool too_big) override;
        void close() override;
        void login(std::string user, std::string password, std::function<void(account, std::string)> done) override;
        void offload(std::function<void()> job, std::function<void()> done) override;
        void maildrop(const std::string& user,
                      std::function<void(bool, uint32_t, std::vector<pop3_session::message>)> done) override;
        void read(const pop3_session::message& m, std::function<void(std::shared_ptr<const std::string>)> done) override;
        void remove(const std::string& user, std::vector<uint32_t> uids, std::function<void(bool)> done) override;
        void acknowledge() override;
        void reply_shared(const std::shared_ptr<const std::string>& bytes, size_t off, size_t len) override;
        size_t backlog() const override { return owed + zplain.size(); }
        bool start_compress() override;
        void later(std::function<void()> f) override;
        void when_drained(std::function<void()> f) override;
        void imap_acted(const std::string& user, const std::string& folder, std::string cause, std::vector<uint32_t> uids,
                        std::string changed) override
        {
            run->imap_sieve(user, folder, std::move(cause), std::move(uids), std::move(changed));
        }
        void acted(const std::string& user, const std::string& folder, std::string cause,
                   std::vector<uint32_t> uids) override
        {
            run->imap_sieve(user, folder, std::move(cause), std::move(uids), {});
        }
        void bearer(std::string token, std::function<void(account, std::string)> done) override;
        void cookie(std::string cookies, std::function<void(account, std::string)> done) override;
        std::string idp_login(const std::string& back) override;
        std::string idp_logout(const std::string& back) override;
        void forward(std::string client) override { forwarded = std::move(client); }
        bool unsubscribe(const std::string& token) override { return run->unsubscribe(token); }
        void push(const std::string& url, const std::string& p256dh, const std::string& auth, std::string body) override
        {
            run->push_send(url, p256dh, auth, std::move(body));
        }
        std::string address_of(const std::string& user) override;
        void submit(const std::string& user, const std::string& from, std::vector<std::string> rcpts, std::string message,
                    std::function<void(bool, std::string)> done) override;
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
    // An MTA-STS policy fetch: the policy for mta-sts.<one of its domains>, else 404, and the connection closed.
    void sts_input(conn& c, std::string_view bytes);
    void out(conn& c, std::string_view bytes);
    void queue_owned(conn& c, std::string_view bytes);
    void queue_shared(conn& c, const std::shared_ptr<const std::string>& bytes, size_t off, size_t len);
    void queue_tls_out(conn& c);
    void flush(conn& c);
    // Bytes onto the connection as they are, encrypted where it speaks TLS: what out() does once compression is done.
    void send_raw(conn& c, std::string_view bytes);
    void write_done(conn& c, int res);
    void close_soon(conn& c);
    void close_conn(conn& c);
    void settle();
    // A connection whose read or write the ring could not take now, tried again at the loop's turn.
    void retry_io(conn& c);
    std::vector<uint64_t> m_retry_io;
    void arm_tick();
    void tick();
    void refresh_files();
    // The domains of --dns, from the zones the daemon writes, and the records this runtime gives them.
    void refresh_domains();
    void publish_records();
    std::string records_text() const;
    std::string m_published;
    // An address list a file keeps for every shard: the suppressed for 90 days after a bounce, the unsubscribed for good.
    struct address_list
    {
        std::string path;
        int64_t keep_s{0};
        std::unordered_set<std::string> set;
        std::optional<socketley::file_stamp> stamp;
    };
    address_list m_suppressed, m_unsubscribed;
    // Read again when another shard changed it; changed on a thread, under the file's lock, merged with what the
    // other shards wrote, and entries past ninety days let go.
    // An advertisement made ready for its one recipient: its link to unsubscribe where {{unsubscribe}} is, or added,
    // and List-Unsubscribe; false with `why`, `skipped` where the recipient unsubscribed.
    bool advertise(compose& c, std::string& why, bool& skipped);
    void load_list(address_list& l);
    void edit_list(address_list& l, std::vector<std::string> add, std::vector<std::string> remove);
    std::string m_verp_key;
    // The session of a connection once it may speak: at the accept, or once its TLS handshake is done.
    void begin_session(conn& c);
    smtp_config session_config(const conn& c) const;
    std::string received_line(const conn& c, const std::string& id, const std::string& rcpt) const;
    void accepted(const entry_ptr& e);
    std::string queue_text(std::string_view filter) const;
    // `socketley mail ... sieve`: a user's scripts listed, read, put, checked, activated or deleted.
    std::string sieve_command(const std::string& arg);
    std::string show_text(const std::string& id) const;
    void send_command(uint64_t ticket, socketley::bytes::reader& r);

    mail_instance& m_owner;
    event_loop& m_loop;
    file_io m_fio;
    hash_pool m_pool;
    // SPF, DKIM and DMARC of mail from elsewhere, whose lookups block a thread of these and never the loop.
    hash_pool m_checks;
    spool m_spool;
    std::unique_ptr<dnsbl> m_dnsbl;
    std::unique_ptr<sieve_store> m_sieve;
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
    // --arc-trust, split.
    std::vector<std::string> m_arc_trusted;
    std::string m_state_dir;

    // The spam filter, scored with on the first shard, which reads what every shard learned from their journal.
    std::unique_ptr<bayes> m_bayes;
    uint64_t m_bayes_off{0}, m_bayes_junked{0}, m_bayes_learned{0};
    int64_t m_bayes_folded_ms{0};
    struct learning
    {
        std::string user, key;
        uint64_t size{0};
        bool spam{false};
    };
    // What is to be learned, read eight at a time.
    std::deque<learning> m_learn_queue;
    uint32_t m_learning{0};
    void pump_learning();
    void bayes_read();
    void bayes_fold();
    std::string learn_command(const std::string& arg, std::function<void(std::string_view)> answer);
    // A certificate the entrance has still to write, the listeners that need it waiting for it.
    bool m_cert_wait = false;
    bool certificate_to_come() const;
    // The listeners that take a password or speak TLS, those opened added to `opened`.
    bool open_secured(std::string& why, std::vector<listener*>* opened = nullptr);
    listener m_smtp, m_sub, m_subs, m_imap_l, m_imaps_l, m_sieve_l, m_pop3_l, m_pop3s_l, m_lmtp_l, m_sts_l, m_jmap_l,
        m_web_l;
    // Every listener, for the loops over them.
    std::array<listener*, 12> listeners()
    {
        return {&m_smtp, &m_sub, &m_subs, &m_imap_l, &m_imaps_l, &m_sieve_l, &m_pop3_l, &m_pop3s_l, &m_lmtp_l, &m_sts_l,
                &m_jmap_l, &m_web_l};
    }
    // The MTA-STS policy its domains publish, and the id its TXT names it by.
    std::string sts_policy() const;
    std::string sts_id() const;
    std::unique_ptr<greylist> m_greylist;
    reports m_reports;
    int64_t m_next_report_ms{0};
    // Reports made and their TLS ones' rua looked up, and mail of them sent.
    void send_reports();
    // What a user is told once their mailbox passes --quota-warn, kept for the run.
    std::unordered_set<std::string> m_quota_warned;
    std::unique_ptr<imap_store> m_imap;
    std::unordered_map<uint64_t, std::unique_ptr<conn>> m_conns;
    // Connections and failed sign-ins by client address, and each address's message rate, for the limits on them.
    struct client
    {
        uint32_t conns{0};
        uint32_t failures{0};
        int64_t first_failure_ms{0};
        int64_t locked_until_ms{0};
        double tokens{0};
        int64_t tokens_ms{0};
    };
    std::unordered_map<std::string, client> m_clients;
    // Whether `ip` may send another message now, by --rate-limit's bucket of it and --global-rate-limit's.
    bool may_send(const std::string& ip);
    // An accept refused with EMFILE waits a moment before the next, rather than spinning on the same failure.
    int64_t m_accept_paused_until_ms{0};
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
    void imap_sieve_apply(const std::string& user, const std::shared_ptr<imap_folder>& f, uint32_t uid,
                          std::string_view bytes, const sieve::outcome& out, const std::string& own);
    std::vector<std::string> m_push_users;
    std::unordered_map<std::string, std::string> m_push_seen;
    int64_t m_push_list_mtime{-1};
    uint64_t m_pushes_sent{0}, m_pushes_failed{0};
    std::shared_ptr<bool> m_alive;

    uint64_t m_received{0};
    uint64_t m_refused_rcpt{0};
    uint64_t m_refused_relay{0};
    uint64_t m_auth_ok{0};
    uint64_t m_auth_failed{0};
    uint64_t m_auth_locked{0};
    uint64_t m_rate_limited{0};
    uint64_t m_tls_failures{0};
    uint64_t m_starttls{0};
    uint64_t m_too_big{0};
    uint64_t m_spool_failed{0};
    uint64_t m_bounces_taken{0};
    uint64_t m_suppressions{0};
    uint64_t m_unsubscribes{0};
    uint64_t m_bounces_unverified{0};
    uint32_t m_checks_out{0};
    uint64_t m_checked{0};
    uint64_t m_dmarc_rejected{0};
    uint64_t m_blocklisted{0};
    uint64_t m_quarantined{0};
    uint64_t m_spam_rejected{0};
    // The spool's disk has too little room for more mail.
    bool m_disk_low{false};
    uint64_t m_spam_junked{0};
    uint64_t m_greylisted{0};
    uint64_t m_reports_sent{0};
};

}   // namespace socketley::mail
