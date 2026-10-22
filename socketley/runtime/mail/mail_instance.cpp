#include "mail_instance.h"

#include <charconv>
#include <filesystem>

#include "mail_run.h"
#include "../../shared/net/dns_feed.h"
#include "../../shared/persist/paths.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/text_list.h"
#include "../../shared/util/wall_clock.h"

std::string mail_state_dir(std::string_view runtime_name, uint32_t shard, uint32_t shards)
{
    std::string leaf(runtime_name);
    // A shard of several keeps a spool of its own, since each holds the messages it was handed.
    if (shards > 1)
        leaf += "." + std::to_string(shard);
    return (socketley_paths::resolve().state_dir / "mail" / leaf).string();
}

std::string mail_key_path(std::string_view runtime_name, std::string_view selector)
{
    return (socketley_paths::resolve().state_dir / "mail" /
            (std::string(runtime_name) + ".dkim." + std::string(selector) + ".key"))
        .string();
}

std::string mail_sieve_dir(std::string_view runtime_name)
{
    return (socketley_paths::resolve().state_dir / "mail" / (std::string(runtime_name) + ".sieve")).string();
}

std::string mail_redacted_relay(std::string_view url)
{
    // scheme://user:password@host:port, the password between the first colon after "//" and the last "@".
    const size_t start = url.find("//");
    const size_t at = url.rfind('@');
    if (start == std::string_view::npos || at == std::string_view::npos || at < start)
        return std::string(url);
    const size_t colon = url.find(':', start + 2);
    if (colon == std::string_view::npos || colon > at)
        return std::string(url);
    return std::string(url.substr(0, colon + 1)) + "***" + std::string(url.substr(at));
}

std::string mail_outbox_dir(std::string_view runtime_name)
{
    return (socketley_paths::resolve().state_dir / "mail" / (std::string(runtime_name) + ".outbox")).string();
}

std::string mail_verp_key_path(std::string_view runtime_name)
{
    return (socketley_paths::resolve().state_dir / "mail" / (std::string(runtime_name) + ".verp")).string();
}

std::string mail_suppressed_path(std::string_view runtime_name)
{
    return (socketley_paths::resolve().state_dir / "mail" / (std::string(runtime_name) + ".suppressed")).string();
}

namespace
{

// What follows a runtime's name in a file of its state, where the file is its: its spool or a shard's, its keys,
// suppressed list, VERP key, IMAP index, Sieve scripts and outbox; empty where the file is none of them.
std::string_view state_suffix(std::string_view file, std::string_view stem)
{
    if (!file.starts_with(stem))
        return "-";
    const std::string_view rest = file.substr(stem.size());
    if (rest.empty() || rest.starts_with(".dkim.") || rest == ".suppressed" || rest == ".suppressed.lock" ||
        rest == ".verp" || rest == ".imap" || rest == ".sieve" || rest == ".outbox" ||
        (rest.front() == '.' && rest.size() > 1 && rest.find_first_not_of("0123456789", 1) == std::string_view::npos))
        return rest.empty() ? std::string_view(".") : rest;
    return "-";
}

}   // namespace

bool mail_rename_state(std::string_view from, std::string_view to, std::string& why)
{
    const std::filesystem::path base = socketley_paths::resolve().state_dir / "mail";
    std::error_code ec;
    std::vector<std::pair<std::filesystem::path, std::filesystem::path>> moves;
    for (const auto& e : std::filesystem::directory_iterator(base, ec))
    {
        const std::string f = e.path().filename().string();
        const std::string_view rest = state_suffix(f, from);
        if (rest == "-")
            continue;
        const std::string target = std::string(to) + (rest == "." ? std::string() : std::string(rest));
        if (std::filesystem::exists(base / target))
        {
            why = "the state of " + std::string(to) + " is there already: " + (base / target).string();
            return false;
        }
        moves.emplace_back(e.path(), base / target);
    }
    for (const auto& [a, b] : moves)
        if (std::filesystem::rename(a, b, ec); ec)
        {
            why = a.string() + " could not be renamed: " + ec.message();
            return false;
        }
    return true;
}

void mail_forget_state(std::string_view runtime_name)
{
    const std::filesystem::path base = socketley_paths::resolve().state_dir / "mail";
    const std::string stem(runtime_name);
    std::error_code ec;
    std::vector<std::filesystem::path> gone;
    for (const auto& e : std::filesystem::directory_iterator(base, ec))
        if (state_suffix(e.path().filename().string(), stem) != "-")
            gone.push_back(e.path());
    for (const auto& p : gone)
    {
        // A spool that still holds mail it answered 250 for is kept aside, not deleted with the runtime.
        std::string queued;
        uint64_t n = 0;
        if (socketley::read_file((p / "spool" / "queued").string(), queued) &&
            std::from_chars(queued.data(), queued.data() + queued.size(), n).ec == std::errc() && n > 0)
        {
            const std::filesystem::path aside =
                base / (p.filename().string() + ".held-" + std::to_string(socketley::wall::now_ms() / 1000));
            std::filesystem::rename(p, aside, ec);
            if (!ec)
            {
                LOG_WARN(("mail " + stem + ": " + std::to_string(n) + " queued message(s) are kept in " +
                          aside.string() + "; delete it once they are not wanted")
                             .c_str());
                continue;
            }
        }
        std::filesystem::remove_all(p, ec);
    }
    // And the records it gave a dns runtime.
    dns_feed::write_records(runtime_name, {});
}

mail_instance::mail_instance(std::string_view name) : runtime_instance(runtime_mail, name) {}

mail_instance::~mail_instance() = default;

std::vector<std::string> mail_instance::domains() const
{
    std::vector<std::string> out;
    std::string_view list = m_domains;
    while (!list.empty())
    {
        std::string d(socketley::take_item(list));
        for (char& c : d)
            c = static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c);
        if (!d.empty())
            out.push_back(std::move(d));
    }
    if (out.empty())
        out = m_resolved;
    return out;
}

std::string mail_instance::greeting_name() const
{
    if (!m_hostname.empty())
        return m_hostname;
    const auto d = domains();
    return d.empty() ? std::string("localhost") : "mail." + d.front();
}

std::string mail_instance::config_refusal() const
{
    if (m_domains.empty() && m_dns.empty() && m_relay.empty() && m_users.empty() && m_idp.empty())
        return "mail: say whose mail this is: --mail-domain <domain>, --dns <runtime> for its zones, or --relay "
               "<url> for a runtime that only sends what this machine and its users give it\n";
    if (!get_listen_path().empty())
        return "mail: --listen unix: is not served; the runtime listens on its ports\n";
    if (!m_storage.empty() && m_idp.empty() && m_aliases.empty())
        return "mail: --storage keeps mailboxes, which are the users of --idp or the addresses of --aliases\n";
    if ((m_imap || m_imaps) && m_storage.empty())
        return "mail: --imap reads the mailboxes of --storage, which is not given\n";
    if (m_sieve && (m_storage.empty() || m_idp.empty()))
        return "mail: --sieve keeps the filters of mailboxes, which need --idp and --storage\n";
    if ((m_pop3 || m_pop3s) && (m_storage.empty() || m_idp.empty()))
        return "mail: --pop3 reads the mailboxes of --storage, whose users are --idp's\n";
    if (m_lmtp && m_storage.empty())
        return "mail: --lmtp hands mail to the mailboxes of --storage, which is not given\n";
    if ((m_pop3s || m_sts_port) && !get_tls())
        return "mail: --pop3s and --mta-sts-port speak TLS from the first byte, which needs --tls with --cert and --key\n";
    if (m_sts_port && m_mta_sts.empty())
        return "mail: --mta-sts-port serves the policy --mta-sts enforce or testing says\n";
    if ((m_submissions || m_imaps) && !get_tls())
        return "mail: --submissions and --imaps speak TLS from the first byte, which needs --tls with --cert and --key\n";
    if (m_submission && m_users.empty() && m_idp.empty())
        return "mail: --submission takes mail from users who sign in, from --users or --idp\n";
    if (m_submission && !get_tls())
        return "mail: --submission takes passwords, which go only over TLS: give it --tls with --cert and --key\n";
    if (m_max_size < 1024)
        return "mail: --max-size below 1K takes no message\n";
    const uint16_t ports[] = {effective_port(), m_submission, m_submissions, m_imap, m_imaps, m_sieve,
                              m_pop3,           m_pop3s,      m_lmtp,        m_sts_port};
    for (size_t i = 0; i < std::size(ports); ++i)
        for (size_t j = i + 1; j < std::size(ports); ++j)
            if (ports[i] && ports[i] == ports[j])
                return "mail: two of its listeners name port " + std::to_string(ports[i]) + "\n";
    return {};
}

void mail_instance::on_cqe(struct io_uring_cqe*)
{
    // Every completion belongs to the run, which is its own owner; nothing lands here.
}

bool mail_instance::setup(event_loop& loop)
{
    m_graveyard.reap();
    auto run = std::make_unique<socketley::mail::mail_run>(*this, loop);
    std::string why;
    if (!run->start(why))
    {
        LOG_ERROR(("mail " + std::string(get_name()) + ": " + why).c_str());
        m_graveyard.retire(std::move(run));
        return false;
    }
    m_run = std::move(run);
    return true;
}

void mail_instance::teardown(event_loop&)
{
    m_graveyard.retire(std::move(m_run));
}

void mail_instance::on_loop_turn()
{
    m_graveyard.reap();
    if (m_run)
        m_run->on_loop_turn();
}

bool mail_instance::serve_deferred(uint64_t ticket, std::string_view, std::string_view payload)
{
    if (!m_run || !payload.starts_with(socketley::mail::command_prefix))
        return false;
    m_run->command(ticket, payload);
    return true;
}

size_t mail_instance::get_connection_count() const
{
    return m_run ? m_run->conn_count() : 0;
}

std::string mail_instance::stats_lines() const
{
    return m_run ? m_run->stats() : std::string();
}

void mail_instance::listen_addresses(std::vector<std::string>& out) const
{
    out.push_back("tcp:" + std::to_string(effective_port()));
    for (const uint16_t p : {m_submission, m_submissions, m_imap, m_imaps, m_sieve, m_pop3, m_pop3s, m_lmtp, m_sts_port})
        if (p)
            out.push_back("tcp:" + std::to_string(p));
}

uint16_t mail_instance::effective_port() const
{
    return get_port() ? get_port() : 25;
}
