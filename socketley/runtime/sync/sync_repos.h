#pragma once
// A sync runtime a storage runtime makes to pull git repositories into its users' libraries, one at a time, when
// they are due or asked for, as `socketley git-sync` children.  With --sync per-user it is one user's; with --sync
// active it is the one runtime of the whole storage and pulls every user's, each with that user's own credentials,
// so one user's repositories are never fetched or written with another's rights.
//
// What it needs it reads from the file --repositories names, which the storage writes and makes again before the
// temporary credentials in it run out: the storage's directory, where the list and each repository's state are, the
// address it is reached on, and for each user the credentials and GitHub token a run signs and fetches with.
#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include "../../shared/event_loop.h"
#include "../storage/git_mirrors.h"

class sync_instance;

namespace socketley::sync
{

class repo_runner : public io_handler
{
public:
    repo_runner(sync_instance& rt, event_loop& loop);
    ~repo_runner() override = default;
    repo_runner(const repo_runner&)            = delete;
    repo_runner& operator=(const repo_runner&) = delete;

    bool start(std::string& why);
    void stop();
    void on_loop_turn();
    void on_cqe(struct io_uring_cqe* cqe) override;
    bool drained() const;
    std::string stats_lines() const;

private:
    // Reads the file again once it changed; false with `why` for one that is not whole.
    bool reload(std::string& why);
    void arm_tick();

    sync_instance& m_rt;
    event_loop&    m_loop;
    // One per user this runtime pulls for: their repositories, and the identity their runs sign with.
    struct pull
    {
        std::unique_ptr<socketley::storage::git_mirrors> git;
        socketley::storage::git_mirrors::identity id;
    };
    std::map<std::string, pull> m_pulls;
    int64_t     m_stamp{-1};
    bool        m_opened{false};
    std::string m_problem;
    __kernel_timespec m_tick_ts{};
    io_request m_tick_req{};
    bool m_tick_armed{false};
    bool m_stopped{false};
};

}   // namespace socketley::sync
