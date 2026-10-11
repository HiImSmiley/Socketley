#pragma once
// A user's own sync runtime, made by a storage runtime for each of its users: it pulls that user's git repositories
// into their libraries, one at a time, when they are due or asked for, as `socketley git-sync` children.
//
// What it needs it reads from the file --repositories names, which the storage writes and makes again before the
// temporary credentials in it run out: the storage's directory, where the list and each repository's state are, the
// address it is reached on, the user, and the credentials and GitHub token a run signs and fetches with.
#include <cstdint>
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
    socketley::storage::git_mirrors m_git;
    socketley::storage::git_mirrors::identity m_id;
    std::string m_user;
    int64_t     m_stamp{-1};
    bool        m_opened{false};
    std::string m_problem;
    __kernel_timespec m_tick_ts{};
    io_request m_tick_req{};
    bool m_tick_armed{false};
    bool m_stopped{false};
};

}   // namespace socketley::sync
