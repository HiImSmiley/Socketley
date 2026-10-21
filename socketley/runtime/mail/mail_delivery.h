#pragma once
// What becomes of the messages in the spool: each recipient's mail handed to the mail exchanger of its domain, or to
// the smarthost of --relay, by SMTP on the loop; to a mailbox of this runtime; or bounced to its sender once it fails
// for good or has been tried for --queue-lifetime.
//
// Recipients of one domain go in one transaction, and the connection to a domain carries one message after another
// while there are more for it, at most a few at once a domain.  The loop's resolver finds the exchangers; TLS is
// spoken wherever the other side offers it, and required of a smarthost that is given a password.
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <openssl/ssl.h>

#include "mail_command.h"
#include "mail_dkim.h"
#include "mail_sieve.h"
#include "mail_spool.h"
#include "mail_tls_policy.h"
#include "../../shared/loop/event_loop.h"
#include "../../shared/loop/file_io.h"
#include "../../shared/net/endpoint.h"

class tls_context;

namespace socketley::mail
{

class mail_run;
struct address;

class delivery : public io_handler
{
public:
    explicit delivery(mail_run& run);
    ~delivery() override;

    bool start(std::string& why);
    void stop();
    bool drained() const;
    void on_cqe(struct io_uring_cqe* cqe) override;
    void on_loop_turn();
    void tick(int64_t now);

    // A message just written to the spool, tried at once.
    void queued(const entry_ptr& e);
    // Every message, or the one named, tried now.
    void flush(std::string_view id);
    void forget(const std::string& id);
    void stats(std::string& out) const;

    // `c` as a message: its envelope and its bytes, the sender being no-reply@ where none is said and the runtime
    // has --no-reply; false with `why` for what makes it none.
    bool compose_message(const compose& c, std::string& from, std::vector<std::string>& rcpts, std::string& body,
                         std::string& why);
    // The TXT record of the DKIM key, for the dns runtime and `socketley show`; empty without a key.
    std::string dkim_record() const;
    std::string dkim_selector() const { return m_selector; }

    // The delays between tries, in seconds, the last repeated until the lifetime is over.
    static constexpr uint32_t retry_delays[] = {60, 300, 900, 1800, 3600, 7200, 14400, 28800};

private:
    // Who a recipient's mail is sent to: its index in the envelope, and the address, an alias's target perhaps.
    struct target
    {
        size_t      rcpt{0};
        std::string addr;
    };
    // One message's recipients for one destination.
    struct item
    {
        entry_ptr e;
        std::vector<target> to;
    };
    struct route
    {
        std::string key;
        std::deque<item> waiting;
        uint32_t active{0};
        // The exchangers by preference, or the smarthost, and when they were looked up.
        std::vector<std::string> hosts;
        int64_t looked_ms{0};
        bool looking{false};
        bool looked{false};
        // A domain that does not exist, or one that says it takes no mail (RFC 7505).
        std::string dead;
        // Its MX records came validated by DNSSEC, so DANE may be looked for beside them.
        bool mx_secure{false};
        // Its MTA-STS policy: not looked at, being looked at or fetched, known; and whether the exchangers it
        // does not name were taken out of `hosts`.
        uint8_t sts_state{0};
        int64_t sts_ms{0};
        bool sts_filtered{false};
    };
    struct out_conn;

    void dispatch(const entry_ptr& e);
    void schedule(const entry_ptr& e, int64_t at);
    void pump(route& r);
    void lookup(route& r);
    // The domain's MTA-STS policy brought up to date: its TXT record asked, and the policy fetched where its id
    // changed; the route is pumped once it is known.
    void sts_check(route& r);
    void sts_fetch(const std::string& domain, const std::string& id);
    // The policy that counts for `domain` now, null where there is none or it says none.
    const tls_policy::sts* sts_for(const std::string& domain) const;
    void sts_save();
    void poll_lookups();
    void open_conn(route& r);
    void finished(const entry_ptr& e);
    void attempt_over(const entry_ptr& e);
    // `report` says who tells a success its sender asked to hear of: 1 delivered here, 2 relayed to a server that
    // was not asked to, 0 the next hop.
    void result(const item& it, size_t t, int code, const std::string& text, bool temporary, uint8_t report = 0);
    // The delivery status report of what failed and what NOTIFY asked to hear of, or of a delay.
    void report(const entry_ptr& e, bool delay);
    static bool reported(const spool_rcpt& r, bool delay);
    void sign_then(const entry_ptr& e, std::function<void()> go);
    struct sign_job
    {
        entry_ptr e;
        std::string data;
        bool failed{false};
        bool waiting{false};
        bool looping{false};
    };
    void sign_read(const std::shared_ptr<sign_job>& j);
    void deliver_local(const entry_ptr& e, const target& t);
    // A mailbox delivery the user's Sieve script decides: run on the pool, and its actions taken on the loop.
    void filter(const std::shared_ptr<item>& it, const std::string& user, const std::string& email, std::string head,
                std::shared_ptr<const sieve::script> script, std::function<void(int, const std::string&)> settle);
    void apply(const std::shared_ptr<item>& it, const std::string& user, const std::string& own,
               const std::string& head, std::string_view bytes, const sieve::outcome& out,
               std::function<void(int, const std::string&)> settle);
    // The message sent on to each of `to`, `done` once it is queued for them or false where it could not be read.
    void redirect(const entry_ptr& e, const std::string& own, std::vector<std::string> to,
                  std::function<void(bool)> done);
    void vacation(const std::string& own, const sieve::vacation& v, std::string_view msgid);
    std::string signing_domain(std::string_view from_header) const;

    // ── one connection ─────────────────────────────────────────────────────
    void conn_connect(out_conn& c);
    void conn_connected(out_conn& c, int64_t res);
    void conn_receive(out_conn& c);
    void conn_got(out_conn& c, const char* p, size_t n);
    void conn_reply(out_conn& c, int code, std::string text);
    void conn_send(out_conn& c, std::string bytes);
    void conn_write(out_conn& c);
    void conn_next(out_conn& c);
    void conn_begin(out_conn& c);
    void conn_body(out_conn& c);
    void conn_chunk(out_conn& c);
    void conn_fail(out_conn& c, const std::string& why, bool next_address);
    void conn_close(out_conn& c);
    void conn_end_item(out_conn& c, int code, const std::string& text);

    mail_run& m_run;
    event_loop& m_loop;
    file_io m_io;
    std::unique_ptr<tls_context> m_tls;
    std::unordered_map<std::string, route> m_routes;
    std::unordered_map<uint64_t, std::unique_ptr<out_conn>> m_conns;
    uint64_t m_next_conn{1};
    std::multimap<int64_t, std::string> m_due;
    // How many of a message's items this try still has out, and how many targets each recipient still waits on.
    std::unordered_map<std::string, uint32_t> m_out;
    std::unordered_map<std::string, std::vector<uint32_t>> m_pending_targets;
    // DKIM signatures by message id, made once and put ahead of each copy sent.
    std::unordered_map<std::string, std::string> m_signed;
    std::unordered_map<std::string, std::vector<std::function<void()>>> m_signing;
    dkim::key_ptr m_key;
    std::string m_selector;
    // --relay, parsed.
    bool m_relay{false};
    bool m_relay_tls{false};
    std::string m_relay_host;
    uint16_t m_relay_port{25};
    std::string m_relay_user, m_relay_pass;
    uint16_t m_mx_port{25};
    // MTA-STS policies by domain, kept across a restart so a policy gone from DNS still counts until it expires.
    std::unordered_map<std::string, tls_policy::sts> m_sts;
    std::string m_sts_path;
    bool m_dane{false};
    bool m_stopped{false};
    bool m_polling{false};
    std::shared_ptr<bool> m_alive;

    uint64_t m_delivered{0};
    uint64_t m_deferred{0};
    uint64_t m_failed{0};
    uint64_t m_bounced{0};
    uint64_t m_reports{0};
    uint64_t m_sieve_rejected{0};
    uint64_t m_over_quota{0};
    uint64_t m_sieve_redirected{0};
    uint64_t m_sieve_vacations{0};
    uint64_t m_connects{0};
    uint64_t m_tls_sessions{0};
    uint64_t m_transactions{0};
    uint64_t m_lookups{0};
    uint64_t m_dane_verified{0};
    uint64_t m_sts_verified{0};
    uint64_t m_sts_fetched{0};
    uint64_t m_sts_testing_failed{0};
    uint64_t m_tls_refused{0};
};

}   // namespace socketley::mail
