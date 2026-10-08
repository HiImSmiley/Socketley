#pragma once
// Git repositories a storage runtime keeps in its libraries: each one fetched once a day at the hour asked for, and
// whenever its user asks, by `socketley git-sync` (cli_git.cpp), which writes the branch's files under <name>/ of the
// library and a bundle under _backups/<name>/ when anything moved, as the user who added it.
//
// ─── THE FILES ──────────────────────────────────────────────────────────────
//   <dir>/.ui/git.json            the repositories, changed under <dir>/.ui/git.lock
//   <dir>/.ui/git/<id>/           each one's bare clone, the state its last run ended in, and that run's log
//   <dir>/.ui/git-tokens/<user>   a user's GitHub token, sealed with a key only that user's secret derives
//
// The first shard runs the schedule; a run asked for is started by whichever shard is asked, and the lock a run holds
// in its directory keeps two from running at once.
#include <cstdint>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <unordered_map>
#include <vector>

namespace socketley::storage
{

class authenticator;

class git_mirrors
{
public:
    struct repo
    {
        std::string id, owner, url, branch{"main"}, bucket{"git"}, name;
        bool private_repo{false};
        // The local hour the daily run is due from.
        int hour{3};
        int64_t added{0};
    };

    // `endpoint` is where `git-sync` reaches this runtime's S3 API, host:port; empty when it cannot, and `why` says
    // why, for the interface to show.
    void open(std::string dir, uint32_t shard, std::string endpoint, bool tls, std::string why_not);
    bool available() const { return !m_endpoint.empty(); }
    const std::string& unavailable_reason() const { return m_why_not; }
    // Whether the schedule has anything to look after.
    bool enabled() const { return !m_children.empty() || (m_shard == 0 && available()); }
    // Once a second: runs that ended are reaped, and once a minute the first shard starts what is due.
    void tick(authenticator& auth);
    void stop();

    std::vector<repo> repos();
    // An error to show, empty when added; `r.id` is set.
    std::string add(repo& r);
    bool remove(std::string_view id);
    // An error to show, empty when the run started.
    std::string run_now(std::string_view id, authenticator& auth);
    bool running(std::string_view id) const;
    // How its last run ended, as git-sync wrote it, "null" for none.
    std::string state_json(std::string_view id) const;

    // A user's GitHub token: sealed to a file, removed with an empty one, and whether there is one.
    bool set_token(authenticator& auth, std::string_view user, std::string_view token);
    bool has_token(std::string_view user) const;

    static constexpr size_t max_repos = 100;

private:
    std::string work_of(std::string_view id) const { return m_dir + "/.ui/git/" + std::string(id); }
    std::string token_path(std::string_view user) const;
    std::string token_of(authenticator& auth, std::string_view user) const;
    bool save(const std::vector<repo>& rs);
    std::string start(const repo& r, authenticator& auth);
    bool due(const repo& r, int64_t now) const;

    std::string m_dir, m_endpoint, m_why_not;
    uint32_t m_shard{0};
    bool m_tls{false};
    bool m_any{false};
    int64_t m_next_look{0};
    std::vector<repo> m_cache;
    int64_t m_cache_stamp{-1};
    // The runs this process started, by repository.
    std::unordered_map<std::string, pid_t> m_children;
};

}   // namespace socketley::storage
