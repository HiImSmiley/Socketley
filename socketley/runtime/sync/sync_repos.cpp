#include "sync_repos.h"
#include "sync_instance.h"

#include <sys/stat.h>

#include <sstream>
#include <vector>

#include "../../shared/util/logging.h"
#include "../../shared/persist/replaced_file.h"
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
    const std::string dir = text_of(doc, "dir"), endpoint = text_of(doc, "endpoint"), ca = text_of(doc, "ca");
    const bool tls = flag_of(doc, "tls");
    // One user's file names them at the top; active's lists every user under "users".
    std::vector<const socketley::storage::jvalue*> users;
    for (const auto& [k, v] : doc.members)
        if (k == "users")
            for (const auto& u : v.items)
                users.push_back(&u);
    if (users.empty() && !text_of(doc, "user").empty())
        users.push_back(&doc);
    if (dir.empty() || users.empty())
    {
        why = path + " names no storage directory and no user";
        return false;
    }
    m_stamp = stamp;
    std::map<std::string, pull> next;
    for (const auto* u : users)
    {
        const std::string user = text_of(*u, "user");
        if (user.empty())
            continue;
        // A user already pulled for keeps their mirror, and with it a run already under way.
        pull p;
        if (auto it = m_pulls.find(user); it != m_pulls.end())
            p.git = std::move(it->second.git);
        else
        {
            p.git = std::make_unique<socketley::storage::git_mirrors>();
            p.git->open_runner(dir, user, endpoint, tls, ca);
        }
        p.id.access_key    = text_of(*u, "access_key");
        p.id.secret        = text_of(*u, "secret");
        p.id.session_token = text_of(*u, "session_token");
        p.id.github_token  = text_of(*u, "github_token");
        next.emplace(user, std::move(p));
    }
    // A user no longer in the file is no longer pulled for: their mirror stops, and a run of theirs with it.
    for (auto& [user, p] : m_pulls)
        if (!next.contains(user) && p.git)
            p.git->stop();
    m_pulls = std::move(next);
    m_opened = true;
    return true;
}

bool repo_runner::start(std::string& why)
{
    if (!reload(why))
        return false;
    std::string who;
    for (const auto& [user, p] : m_pulls)
        who += (who.empty() ? "" : ", ") + user;
    LOG_INFO(("sync: pulls the repositories of " + who).c_str());
    arm_tick();
    return true;
}

void repo_runner::stop()
{
    m_stopped = true;
    for (auto& [user, p] : m_pulls)
        if (p.git)
            p.git->stop();
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
        for (auto& [user, p] : m_pulls)
            if (p.git)
                p.git->serve(p.id);
    arm_tick();
}

std::string repo_runner::stats_lines() const
{
    // Summed over the users it pulls for; `user` names them all, so one runtime for a whole storage still says
    // whose repositories it carries.
    std::string users, running, last_error;
    uint64_t repos = 0, runs = 0, failures = 0;
    for (const auto& [user, p] : m_pulls)
    {
        if (!p.git)
            continue;
        const auto& d = p.git->done();
        users += (users.empty() ? "" : ",") + user;
        repos += p.git->mine();
        runs += d.runs;
        failures += d.failures;
        if (!d.running.empty())
            running = d.running;
        if (!d.last_error.empty())
            last_error = d.last_error;
    }
    std::ostringstream out;
    out << "user:" << users << "\n"
        << "repositories:" << repos << "\n"
        << "runs:" << runs << "\n"
        << "failures:" << failures << "\n"
        << "running:" << running << "\n"
        << "last_error:" << (m_problem.empty() ? last_error : m_problem) << "\n";
    return out.str();
}

}   // namespace socketley::sync
