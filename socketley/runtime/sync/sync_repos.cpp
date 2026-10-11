#include "sync_repos.h"
#include "sync_instance.h"

#include <sys/stat.h>

#include <sstream>

#include "../../shared/logging.h"
#include "../../shared/replaced_file.h"
#include "../storage/json_doc.h"

namespace socketley::sync
{

namespace
{

std::string text_of(const socketley::storage::jvalue& o, std::string_view n)
{
    for (const auto& [k, v] : o.members)
        if (k == n)
            return v.s;
    return {};
}

bool flag_of(const socketley::storage::jvalue& o, std::string_view n)
{
    for (const auto& [k, v] : o.members)
        if (k == n)
            return v.k == socketley::storage::jvalue::kind::boolean && v.b;
    return false;
}

}   // namespace

repo_runner::repo_runner(sync_instance& rt, event_loop& loop) : m_rt(rt), m_loop(loop) {}

bool repo_runner::reload(std::string& why)
{
    const std::string path(m_rt.get_repositories());
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0)
    {
        why = path + " is not there";
        return false;
    }
    const int64_t stamp = int64_t(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec;
    if (stamp == m_stamp)
        return true;
    std::string text;
    socketley::storage::jvalue doc;
    if (!read_whole_file(path, text) || !socketley::storage::json_reader(text).document(doc))
    {
        why = path + " cannot be read";
        return false;
    }
    m_stamp = stamp;
    const std::string dir = text_of(doc, "dir"), user = text_of(doc, "user"), endpoint = text_of(doc, "endpoint");
    if (dir.empty() || user.empty())
    {
        why = path + " names no storage directory and no user";
        return false;
    }
    if (!m_opened || user != m_user)
        m_git.open_runner(dir, user, endpoint, flag_of(doc, "tls"), text_of(doc, "ca"));
    m_opened = true;
    m_user = user;
    m_id.access_key = text_of(doc, "access_key");
    m_id.secret = text_of(doc, "secret");
    m_id.session_token = text_of(doc, "session_token");
    m_id.github_token = text_of(doc, "github_token");
    return true;
}

bool repo_runner::start(std::string& why)
{
    if (!reload(why))
        return false;
    LOG_INFO(("sync: pulls the repositories of " + m_user).c_str());
    arm_tick();
    return true;
}

void repo_runner::stop()
{
    m_stopped = true;
    m_git.stop();
    if (m_tick_armed)
        m_loop.submit_timeout_remove(&m_tick_req);
}

bool repo_runner::drained() const
{
    return m_loop.owner_inflight(this) == 0 && !m_loop.owner_table_full();
}

void repo_runner::on_cqe(struct io_uring_cqe* cqe)
{
    if (static_cast<io_request*>(io_uring_cqe_get_data(cqe)) == &m_tick_req)
        m_tick_armed = false;
}

void repo_runner::arm_tick()
{
    if (m_stopped || m_tick_armed)
        return;
    // Once a second: a run that ended is reaped and an asked-for one started within it.
    m_tick_ts = __kernel_timespec{1, 0};
    m_tick_req = io_request{};
    m_tick_req.owner = this;
    m_tick_req.type = op_timeout;
    m_tick_armed = m_loop.submit_timeout(&m_tick_ts, &m_tick_req);
}

void repo_runner::on_loop_turn()
{
    if (m_stopped)
        return;
    std::string why;
    if (!reload(why))
    {
        if (why != m_problem)
            LOG_WARN(("sync: " + why).c_str());
        m_problem = why;
    }
    else
        m_problem.clear();
    if (m_opened)
        m_git.serve(m_id);
    arm_tick();
}

std::string repo_runner::stats_lines() const
{
    const auto& d = m_git.done();
    std::ostringstream out;
    out << "user:" << m_user << "\n"
        << "repositories:" << const_cast<socketley::storage::git_mirrors&>(m_git).mine() << "\n"
        << "runs:" << d.runs << "\n"
        << "failures:" << d.failures << "\n"
        << "running:" << d.running << "\n"
        << "last_error:" << (m_problem.empty() ? d.last_error : m_problem) << "\n";
    return out.str();
}

}   // namespace socketley::sync
