#include "mail_instance.h"

#include <filesystem>

#include "mail_run.h"
#include "../../shared/persist/paths.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/text_list.h"

std::string mail_state_dir(std::string_view runtime_name, uint32_t shard, uint32_t shards)
{
    std::string leaf(runtime_name);
    // A shard of several keeps a spool of its own, since each holds the messages it was handed.
    if (shards > 1)
        leaf += "." + std::to_string(shard);
    return (socketley_paths::resolve().state_dir / "mail" / leaf).string();
}

void mail_forget_state(std::string_view runtime_name)
{
    const std::filesystem::path base = socketley_paths::resolve().state_dir / "mail";
    const std::string stem(runtime_name);
    std::error_code ec;
    for (const auto& e : std::filesystem::directory_iterator(base, ec))
    {
        const std::string f = e.path().filename().string();
        const std::string_view rest = std::string_view(f).substr(std::min(f.size(), stem.size()));
        if (f.starts_with(stem) && (rest.empty() || (rest.front() == '.' && rest.size() > 1 &&
                                                     rest.find_first_not_of("0123456789", 1) == std::string_view::npos)))
            std::filesystem::remove_all(e.path(), ec);
    }
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
               "<url> with --users or --idp for a runtime that only sends\n";
    if (!get_listen_path().empty())
        return "mail: --listen unix: is not served; the runtime listens on its ports\n";
    if (!m_storage.empty() && m_idp.empty() && m_aliases.empty())
        return "mail: --storage keeps mailboxes, which are the users of --idp or the addresses of --aliases\n";
    if ((m_imap || m_imaps) && m_storage.empty())
        return "mail: --imap reads the mailboxes of --storage, which is not given\n";
    if ((m_submissions || m_imaps) && !get_tls())
        return "mail: --submissions and --imaps speak TLS from the first byte, which needs --tls with --cert and --key\n";
    if (m_submission && m_users.empty() && m_idp.empty())
        return "mail: --submission takes mail from users who sign in, from --users or --idp\n";
    if (m_max_size < 1024)
        return "mail: --max-size below 1K takes no message\n";
    const uint16_t ports[] = {effective_port(), m_submission, m_submissions, m_imap, m_imaps};
    for (size_t i = 0; i < 5; ++i)
        for (size_t j = i + 1; j < 5; ++j)
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
    for (const uint16_t p : {m_submission, m_submissions, m_imap, m_imaps})
        if (p)
            out.push_back("tcp:" + std::to_string(p));
}

uint16_t mail_instance::effective_port() const
{
    return get_port() ? get_port() : 25;
}
