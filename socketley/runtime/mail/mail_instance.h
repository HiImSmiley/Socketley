#pragma once
// The mail runtime: SMTP for the mail of its domains and the mail its users send, a spool on the disk until each
// message is delivered, mailboxes in a storage runtime for the users of an idp runtime, and IMAP to read them.
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "../../shared/ipc/request_channel.h"
#include "../../shared/runtime/retired_runs.h"
#include "../../shared/runtime/runtime_instance.h"

namespace socketley::mail
{
class mail_run;
}   // namespace socketley::mail

// <state>/mail/<name>[.<shard>], the spool and the keys of a mail runtime.
std::string mail_state_dir(std::string_view runtime_name, uint32_t shard, uint32_t shards);
// That directory removed, a shard's included, so a runtime made again under the name starts with nothing queued.
void mail_forget_state(std::string_view runtime_name);
// The addresses no shard of the runtime sends to again: <state>/mail/<name>.suppressed.
std::string mail_suppressed_path(std::string_view runtime_name);
// The DKIM key every shard of the runtime signs with: <state>/mail/<name>.dkim.<selector>.key.
// The key no-reply mail's tags are made with, which every shard reads.
std::string mail_verp_key_path(std::string_view runtime_name);
std::string mail_key_path(std::string_view runtime_name, std::string_view selector);
// Where the users' Sieve scripts are kept, the same for every shard.
std::string mail_sieve_dir(std::string_view runtime_name);
// A runtime's state moved under a new name, as an import that renames it asks; false with `why` where a file of the
// new name's is there already or one could not be moved.
bool mail_rename_state(std::string_view from, std::string_view to, std::string& why);
// A --relay URL with its password written ***, as show prints it; the URL as it is where it has none.
std::string mail_redacted_relay(std::string_view url);
// Where `socketley send` leaves a message too large for the daemon's channel, for the runtime to take.
std::string mail_outbox_dir(std::string_view runtime_name);

class mail_instance : public runtime_instance, public deferred_request_sink
{
public:
    explicit mail_instance(std::string_view name);
    ~mail_instance() override;

    // Ports of their own, 0 for none: submission with STARTTLS, submission over TLS, IMAP and IMAP over TLS.
    void set_submission_port(uint16_t p) { m_submission = p; }
    uint16_t get_submission_port() const { return m_submission; }
    void set_submissions_port(uint16_t p) { m_submissions = p; }
    uint16_t get_submissions_port() const { return m_submissions; }
    void set_imap_port(uint16_t p) { m_imap = p; }
    uint16_t get_imap_port() const { return m_imap; }
    void set_imaps_port(uint16_t p) { m_imaps = p; }
    uint16_t get_imaps_port() const { return m_imaps; }
    // ManageSieve (RFC 5804), where users put their filters.
    void set_sieve_port(uint16_t p) { m_sieve = p; }
    uint16_t get_sieve_port() const { return m_sieve; }
    // The DNS blocklists a connection's address is looked up in, a comma list of zones.
    void set_dnsbl(std::string_view zones) { m_dnsbl = std::string(zones); }
    std::string_view get_dnsbl() const { return m_dnsbl; }
    // The forwarders whose ARC seal of a passing chain lets mail that fails DMARC through, a comma list of domains.
    void set_arc_trust(std::string_view domains) { m_arc_trust = std::string(domains); }
    std::string_view get_arc_trust() const { return m_arc_trust; }
    // POP3 (RFC 1939) for the INBOX of each user, over STLS.
    void set_pop3_port(uint16_t v) { m_pop3 = v; }
    uint16_t get_pop3_port() const { return m_pop3; }
    // POP3 over TLS from the first byte.
    void set_pop3s_port(uint16_t v) { m_pop3s = v; }
    uint16_t get_pop3s_port() const { return m_pop3s; }
    // JMAP (RFC 8620, RFC 8621) for the mailboxes, over HTTPS where --tls is given.
    void set_jmap_port(uint16_t v) { m_jmap = v; }
    uint16_t get_jmap_port() const { return m_jmap; }
    // LMTP (RFC 2033) from this machine, for the mailboxes.
    void set_lmtp_port(uint16_t v) { m_lmtp = v; }
    uint16_t get_lmtp_port() const { return m_lmtp; }
    // The HTTPS port its MTA-STS policy is served on.
    void set_mta_sts_port(uint16_t v) { m_sts_port = v; }
    uint16_t get_mta_sts_port() const { return m_sts_port; }
    // Seconds a first triplet is greylisted for, 0 for none.
    void set_greylist(uint32_t v) { m_greylist_s = v; }
    uint32_t get_greylist() const { return m_greylist_s; }
    // Where a stranger's mail is scored.
    void set_rspamd(std::string_view v) { m_rspamd = std::string(v); }
    std::string_view get_rspamd() const { return m_rspamd; }
    // What divides a user from a tag; empty for none.
    void set_recipient_delimiter(std::string_view v) { m_delimiter = std::string(v); }
    std::string_view get_recipient_delimiter() const { return m_delimiter; }
    // Whether DMARC and TLS reports go to the domains that ask for them.
    void set_reports(bool v) { m_reports = v; }
    bool get_reports() const { return m_reports; }
    // The address its published DMARC record names for reports.
    void set_dmarc_rua(std::string_view v) { m_dmarc_rua = std::string(v); }
    std::string_view get_dmarc_rua() const { return m_dmarc_rua; }
    // The address its _smtp._tls record names for TLS reports.
    void set_tls_rpt(std::string_view v) { m_tls_rpt = std::string(v); }
    std::string_view get_tls_rpt() const { return m_tls_rpt; }
    // The MTA-STS mode it publishes for its domains, empty for none.
    void set_mta_sts(std::string_view v) { m_mta_sts = std::string(v); }
    std::string_view get_mta_sts() const { return m_mta_sts; }
    // What a mailbox holds where its user has no quota of their own, 0 for no bound.
    void set_default_quota(uint64_t v) { m_default_quota = v; }
    uint64_t get_default_quota() const { return m_default_quota; }
    // At what percent of their quota a user is told, once; 0 for never.
    void set_quota_warn(uint32_t v) { m_quota_warn = v; }
    uint32_t get_quota_warn() const { return m_quota_warn; }
    // The selector of the DKIM key made and published ahead of signing with it, for a key's rotation.
    void set_dkim_next(std::string_view s) { m_dkim_next = std::string(s); }
    std::string_view get_dkim_next() const { return m_dkim_next; }
    // The dns runtime whose zones are the mail domains, and which is given their MX, SPF, DKIM and DMARC records.
    void set_dns(std::string_view rt) { m_dns = std::string(rt); }
    std::string_view get_dns() const { return m_dns; }
    // The domains whose mail is taken here, a comma list; the dns runtime's zones where none is given.
    void set_mail_domains(std::string_view d) { m_domains = std::string(d); }
    std::string_view get_mail_domains() const { return m_domains; }
    // The name the runtime greets with and its MX names, mail.<first domain> where none is given.
    void set_hostname(std::string_view h) { m_hostname = std::string(h); }
    std::string_view get_hostname() const { return m_hostname; }
    void set_no_reply(bool on) { m_no_reply = on; }
    bool get_no_reply() const { return m_no_reply; }
    void set_idp(std::string_view rt) { m_idp = std::string(rt); }
    std::string_view get_idp() const { return m_idp; }
    // The storage runtime and bucket the mailboxes are kept in, `name[/bucket]`.
    void set_storage(std::string_view s) { m_storage = std::string(s); }
    std::string_view get_storage() const { return m_storage; }
    void set_users(std::string_view path) { m_users = std::string(path); }
    std::string_view get_users() const { return m_users; }
    // A smarthost every message for another domain goes through, smtp[s]://[user:password@]host[:port].
    void set_relay(std::string_view url) { m_relay = std::string(url); }
    std::string_view get_relay() const { return m_relay; }
    // Addresses taken for a mailbox or forwarded, `address target` a line.
    void set_aliases(std::string_view path) { m_aliases = std::string(path); }
    std::string_view get_aliases() const { return m_aliases; }
    void set_notify_targets(std::string_view path) { m_notify = std::string(path); }
    std::string_view get_notify_targets() const { return m_notify; }
    void set_max_size(uint64_t n) { m_max_size = n; }
    uint64_t get_max_size() const { return m_max_size; }
    void set_max_recipients(uint32_t n) { m_max_rcpt = n; }
    uint32_t get_max_recipients() const { return m_max_rcpt; }
    // One message of --global-rate-limit's allowance taken, false where there is none left this second.
    bool take_global_token() { return check_global_rate_limit(); }
    // How long a message is tried before it is bounced, in seconds.
    void set_queue_lifetime(uint32_t s) { m_lifetime = s; }
    uint32_t get_queue_lifetime() const { return m_lifetime; }
    void set_dkim_selector(std::string_view s) { m_selector = std::string(s); }
    std::string_view get_dkim_selector() const { return m_selector; }

    std::string config_refusal() const override;
    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;
    void on_loop_turn() override;
    size_t get_connection_count() const override;
    std::string stats_lines() const override;
    // `socketley send`, `socketley mail`, socketley.mail.send and a notification's mail reach the worker as requests.
    request_sink* as_request_sink() override { return sink_or(this); }
    bool serve_deferred(uint64_t ticket, std::string_view target, std::string_view payload) override;
    void listen_addresses(std::vector<std::string>& out) const override;
    uint16_t effective_port() const override;

    // The domains taken, the dns runtime's zones resolved by the daemon where --mail-domain names none.
    void set_resolved_domains(std::vector<std::string> d) { m_resolved = std::move(d); }
    const std::vector<std::string>& resolved_domains() const { return m_resolved; }
    std::vector<std::string> domains() const;
    std::string greeting_name() const;

    socketley::mail::mail_run* run() const { return m_run.get(); }

private:
    uint16_t    m_submission{0};
    uint16_t    m_submissions{0};
    uint16_t    m_imap{0};
    uint16_t    m_imaps{0};
    uint16_t    m_sieve{0};
    std::string m_dnsbl;
    std::string m_arc_trust;
    uint16_t m_pop3{0};
    uint16_t m_pop3s{0};
    uint16_t m_jmap{0};
    uint16_t m_lmtp{0};
    uint16_t m_sts_port{0};
    uint32_t m_greylist_s{0};
    std::string m_rspamd;
    std::string m_delimiter{"+"};
    bool m_reports{false};
    std::string m_dmarc_rua;
    std::string m_tls_rpt;
    std::string m_mta_sts;
    uint64_t m_default_quota{0};
    uint32_t m_quota_warn{90};
    std::string m_dkim_next;
    std::string m_dns;
    std::string m_domains;
    std::string m_hostname;
    bool        m_no_reply{false};
    std::string m_idp;
    std::string m_storage;
    std::string m_users;
    std::string m_relay;
    std::string m_aliases;
    std::string m_notify;
    uint64_t    m_max_size{25ull << 20};
    uint32_t    m_max_rcpt{100};
    uint32_t    m_lifetime{5 * 86400};
    std::string m_selector{"skl"};
    std::vector<std::string> m_resolved;

    std::unique_ptr<socketley::mail::mail_run> m_run;
    socketley::retired_runs<socketley::mail::mail_run> m_graveyard;
};
