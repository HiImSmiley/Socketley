#pragma once
// Git repositories a storage runtime keeps in its libraries: each one fetched every day, week or month, from 3:00
// local time, or only when its user asks (never, the default), by `socketley git-sync` (cli_git.cpp), which writes the branch's files under <name>/ of the
// library and a bundle under _backups/<name>/ when anything moved, as the user who added it.
//
// ─── THE FILES ──────────────────────────────────────────────────────────────
//   <dir>/.ui/git.json            the repositories, changed under <dir>/.ui/git.lock
//   <dir>/.ui/git/<id>/           each one's bare clone, the state its last run ended in, and that run's log
//   <dir>/.ui/git-tokens/<hash>   a user's GitHub token, under the first 32 hex of the SHA-256 of the user's name,
//                                 sealed with a key only that user's secret derives
//
// The storage keeps the list and says what each run ended in; the runs are each user's own sync runtime's, which the
// storage's first shard makes for every user, named <storage>-sync-<user> and owned by the storage, and hands
// temporary credentials in <dir>/.ui/sync/<hash>.json. A run is asked for by <dir>/.ui/git/<id>/asked, and the lock a
// run holds in its directory keeps two from running at once.
#include <cstdint>
#include <functional>
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
        // How often it is fetched by itself: never, day, week or month.
        std::string every{"never"};
        int64_t added{0};
    };

    // What a run signs with, and the GitHub token a private repository is read with.
    struct identity
    {
        std::string access_key, secret, session_token, github_token;
    };

    // `endpoint` is where `git-sync` reaches this runtime's S3 API, host:port; empty when it cannot, and `why` says
    // why, for the interface to show.
    // `cert` is the runtime's own certificate, which a run trusts its connection back by; empty without one.
    void open(std::string dir, uint32_t shard, std::string endpoint, bool tls, std::string why_not, std::string cert = {});
    // The side of a user's sync runtime, which runs that user's repositories and nobody else's.
    void open_runner(std::string dir, std::string user, std::string endpoint, bool tls, std::string cert);
    bool available() const { return !m_endpoint.empty(); }
    const std::string& unavailable_reason() const { return m_why_not; }
    void set_unavailable(std::string why) { m_why_not = std::move(why); }
    // Whether the first shard has runs to watch the end of.
    bool enabled() const { return m_shard == 0 && m_any; }
    // Once a second, on the storage: a run whose state changed since is told to on_run.
    void tick();
    // Told of a run that ended, with the repository and its state.json as the run wrote it.
    std::function<void(const repo&, const std::string& state)> on_run;
    // Once a second, on a user's sync runtime: a run that ended is reaped, and the next is started -- one moved to
    // another library, one asked for, then one due, a minute apart at most.
    void serve(const identity& id);
    void stop();
    // What a user's sync runtime has done, for its figures.
    struct figures
    {
        uint64_t runs{0}, failures{0};
        std::string running, last_error;
    };
    const figures& done() const { return m_done; }
    size_t mine();

    std::vector<repo> repos();
    // An error to show, empty when added; `r.id` is set.
    std::string add(repo& r);
    bool remove(std::string_view id);
    // How often a repository is fetched by itself; false for no such repository or no such period.
    bool set_every(std::string_view id, std::string_view every);
    static bool valid_every(std::string_view e) { return e == "never" || e == "day" || e == "week" || e == "month"; }
    // The local hour a run that is due starts from.
    static constexpr int due_hour = 3;
    // An error to show, empty when the run is asked for.
    std::string run_now(std::string_view id);
    bool running(std::string_view id) const;
    bool spawned_live(std::string_view id) const;
    // How its last run ended, as git-sync wrote it, "null" for none.
    std::string state_json(std::string_view id) const;

    // A user's GitHub token: sealed to a file, removed with an empty one, and whether there is one.
    bool set_token(authenticator& auth, std::string_view user, std::string_view token);
    bool has_token(std::string_view user) const;
    std::string token_of(authenticator& auth, std::string_view user) const;

    static constexpr size_t max_repos = 100;

private:
    std::string work_of(std::string_view id) const { return m_dir + "/.ui/git/" + std::string(id); }
    std::string token_path(std::string_view user) const;
    bool save(const std::vector<repo>& rs);
    std::string start(const repo& r, const identity& id);
    bool due(const repo& r, int64_t now) const;

    std::string m_dir, m_endpoint, m_why_not;
    uint32_t m_shard{0};
    bool m_tls{false};
    std::string m_cert;
    bool m_any{false};
    // The user a sync runtime runs the repositories of; empty on the storage.
    std::string m_user;
    int64_t m_next_look{0};
    // The state.json of each repository as last seen, so a run that ended is told once.
    std::unordered_map<std::string, int64_t> m_seen;
    bool m_seen_once{false};
    figures m_done;
    std::vector<repo> m_cache;
    int64_t m_cache_stamp{-1};
    // The runs this process started, by repository.
    std::unordered_map<std::string, pid_t> m_children;
};

}   // namespace socketley::storage
