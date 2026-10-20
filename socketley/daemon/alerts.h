#pragma once
// What the daemon says is wrong, looked at by the metrics endpoint's thread at each point of its history, whether or
// not a page is open: a runtime that failed or keeps being started again, a certificate that ends within two weeks,
// a disk, the host's memory or a runtime's own limit nearly full, a git repository whose last pull failed.
//
// An alert is raised when its condition has held for `hold` readings -- one for what does not come and go, three for
// a level that can -- and cleared when it has not held for three. Raising and clearing are logged, kept for the page,
// and handed to the daemon's loop for daemon.alert_webhook when one is set, which posts each until the hook takes it,
// across a restart. The ones already told of are written to the state directory, so a restart does not tell of them
// again.
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace alerts
{

// What one runtime's alerts are read from, gathered under the manager's lock.
struct facts
{
    std::string name, type;
    bool failed{false};
    unsigned restarts{0};
    // The certificate file it serves with, empty for none.
    std::string cert;
    // A storage runtime's directory, empty for any other.
    std::string dir;
    // What it holds against the limit it was given, both 0 when it has none or none applies.
    uint64_t used{0}, limit{0};
    // A sync's failures since the last thing it carried, and what it said last.
    uint64_t failing{0};
    std::string error;
};

struct alert
{
    std::string id, level, runtime, title, detail;
    int64_t since{0};
};

class monitor
{
public:
    // Called from the thread that checks, with a message for the webhook.
    using sender = std::function<void(std::string body)>;
    // `state_path` keeps the alerts told of, `webhook` is the URL they are posted to, empty for none, and `send` takes
    // each message for it.
    monitor(std::string state_path, std::string webhook, sender send);

    // One look at everything, at `now` (seconds); `extra_dirs` are directories whose disks are watched besides the
    // runtimes'.
    void check(int64_t now, const std::vector<facts>& runtimes, const std::vector<std::string>& extra_dirs);

    // {"active":[...],"recent":[...],"webhook":true|false}: what is wrong now, newest first, and the last hundred
    // raisings and clearings.
    std::string json() const;
    // A message posted through the webhook now; empty when it was taken, else why not.
    std::string test();

private:
    struct state
    {
        alert a;
        unsigned held{0}, gone{0}, hold{1};
        bool raised{false};
    };
    void consider(int64_t now, std::map<std::string, alert>& seen);
    void post(const alert& a, bool raised, int64_t now);
    void save() const;

    std::string m_path, m_webhook, m_host;
    std::map<std::string, state> m_states;
    // The alerts told of, by id, with when they began and their titles, as the state file keeps them.
    std::map<std::string, std::pair<int64_t, std::string>> m_told;
    unsigned m_checks{0};
    std::deque<std::pair<int64_t, std::pair<bool, alert>>> m_recent;

    // Per runtime: the restart count last seen and when each restart since was seen.
    std::map<std::string, std::pair<unsigned, std::deque<int64_t>>> m_restarts;
    // Each certificate's seconds left when it was read, and when; git repositories are read every minute.
    std::map<std::string, std::pair<int64_t, int64_t>> m_cert_left;
    int64_t m_git_at{0};
    std::map<std::string, std::vector<alert>> m_git;
    std::set<std::string> m_git_dirs;

    sender m_send;
};

}   // namespace alerts
