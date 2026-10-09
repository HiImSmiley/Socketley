#include "alerts.h"

#include <fcntl.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include <algorithm>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <set>
#include <sstream>

#include "dashboard.h"
#include "../runtime/storage/git_mirrors.h"
#include "../runtime/storage/json_doc.h"
#include "../shared/https_client.h"
#include "../shared/log_ring.h"
#include "../shared/logging.h"

namespace alerts
{

namespace
{

std::string quote(std::string_view s)
{
    std::string o = "\"";
    for (const char c : s)
    {
        if (c == '"' || c == '\\')
            o += '\\', o += c;
        else if (static_cast<unsigned char>(c) < 0x20)
        {
            char b[8];
            std::snprintf(b, sizeof b, "\\u%04x", c);
            o += b;
        }
        else
            o += c;
    }
    return o + "\"";
}

std::string size_text(double b)
{
    static constexpr const char* units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    size_t u = 0;
    while (b >= 1000 && u + 1 < std::size(units))
        b /= 1000, ++u;
    char out[32];
    std::snprintf(out, sizeof out, b >= 100 || u == 0 ? "%.0f %s" : "%.1f %s", b, units[u]);
    return out;
}

std::string percent(double share)
{
    char out[16];
    std::snprintf(out, sizeof out, "%.0f%%", share * 100);
    return out;
}

std::string days_text(int64_t left)
{
    // Rounded to the nearest day: a certificate of five days is said to end in five, not four and a bit.
    const int64_t d = (left + 43200) / 86400;
    return d >= 2 ? "in " + std::to_string(d) + " days" : left >= 86400 ? "within two days" : "within a day";
}

std::string alert_json(const alert& a)
{
    std::string o = "{\"id\":";
    o += quote(a.id);
    o += ",\"level\":";
    o += quote(a.level);
    o += ",\"runtime\":";
    o += quote(a.runtime);
    o += ",\"title\":";
    o += quote(a.title);
    o += ",\"detail\":";
    o += quote(a.detail);
    o += ",\"since\":";
    o += std::to_string(a.since);
    o += '}';
    return o;
}

const socketley::storage::jvalue* member(const socketley::storage::jvalue& o, std::string_view k)
{
    for (const auto& [name, v] : o.members)
        if (name == k)
            return &v;
    return nullptr;
}

}   // namespace

monitor::monitor(std::string state_path, std::string webhook) : m_path(std::move(state_path)), m_webhook(std::move(webhook))
{
    char host[256] = {};
    if (::gethostname(host, sizeof host - 1) == 0)
        m_host = host;
    std::ifstream f(m_path);
    for (std::string line; std::getline(f, line);)
        if (const size_t a = line.find('\t'), b = line.find('\t', a + 1); b != std::string::npos)
            m_told[line.substr(0, a)] = {std::strtoll(line.c_str() + a + 1, nullptr, 10), line.substr(b + 1)};
    if (!m_webhook.empty())
        m_thread = std::thread(&monitor::sender, this);
}

monitor::~monitor()
{
    {
        std::lock_guard lock(m_mtx);
        m_stop = true;
    }
    m_cv.notify_all();
    if (m_thread.joinable())
        m_thread.join();
}

void monitor::check(int64_t now, const std::vector<facts>& runtimes, const std::vector<std::string>& extra_dirs)
{
    struct candidate
    {
        alert a;
        unsigned hold{1};
    };
    std::map<std::string, candidate> seen;
    const auto raise = [&](std::string id, std::string level, std::string runtime, std::string title, std::string detail,
                           unsigned hold) {
        candidate& c = seen[id];
        c.a = alert{std::move(id), std::move(level), std::move(runtime), std::move(title), std::move(detail), now};
        c.hold = hold;
    };

    // A runtime that failed, with the last thing it said that was wrong.
    for (const facts& r : runtimes)
        if (r.failed)
        {
            // The newest line that is not an alert's own, which names the runtime too.
            uint64_t next = 0;
            std::string why;
            for (const auto& l : log_ring::since(0, 20, r.name, "warn", next))
                if (l.text.find("] alert: ") == std::string::npos)
                    why = l.text;
            raise("failed:" + r.name, "critical", r.name, r.name + " failed", why, 1);
        }

    // A runtime started again three times within the hour.
    for (const facts& r : runtimes)
    {
        auto& [count, when] = m_restarts[r.name];
        for (unsigned i = count; i < r.restarts; ++i)
            when.push_back(now);
        count = r.restarts;
        while (!when.empty() && when.front() < now - 3600)
            when.pop_front();
        if (when.size() >= 3)
            raise("restarts:" + r.name, "warning", r.name,
                  r.name + " was started again " + std::to_string(when.size()) + " times in the last hour", {}, 1);
    }
    std::erase_if(m_restarts, [&](const auto& kv) {
        return std::none_of(runtimes.begin(), runtimes.end(), [&](const facts& r) { return r.name == kv.first; });
    });

    // Certificates, each read when first named and every five minutes after, what is left counted down between.
    std::set<std::string> certs_named;
    for (const facts& r : runtimes)
    {
        if (r.cert.empty() || !certs_named.insert(r.cert).second)
            continue;
        auto it = m_cert_left.find(r.cert);
        if (it == m_cert_left.end() || now - it->second.second >= 300)
        {
            dashboard::cert_facts c;
            const bool ok = dashboard::read_cert(r.cert, c);
            it = m_cert_left.insert_or_assign(r.cert, std::make_pair(ok ? c.expires_in : INT64_MAX, now)).first;
        }
        if (it->second.first == INT64_MAX)
            continue;
        const int64_t left = it->second.first - (now - it->second.second);
        if (left < 0)
            raise("cert:" + r.cert, "critical", r.name, "The certificate of " + r.name + " has ended", r.cert, 1);
        else if (left < 14 * 86400)
            raise("cert:" + r.cert, left < 3 * 86400 ? "critical" : "warning", r.name,
                  "The certificate of " + r.name + " ends " + days_text(left), r.cert, 1);
    }

    // The disks under the storage runtimes and the state directory, each disk once.
    std::vector<std::string> dirs = extra_dirs;
    for (const facts& r : runtimes)
        if (!r.dir.empty())
            dirs.push_back(r.dir);
    std::set<unsigned long> disks;
    for (const std::string& d : dirs)
    {
        struct statvfs v{};
        if (::statvfs(d.c_str(), &v) != 0 || v.f_blocks == 0 || !disks.insert(v.f_fsid).second)
            continue;
        const double total = static_cast<double>(v.f_blocks) * v.f_frsize, free = static_cast<double>(v.f_bavail) * v.f_frsize;
        if (free / total < 0.10)
            raise("disk:" + d, free / total < 0.05 ? "critical" : "warning", {},
                  "The disk of " + d + " is " + percent(1 - free / total) + " full", size_text(free) + " free of " + size_text(total), 3);
    }

    // The host's memory.
    {
        std::ifstream f("/proc/meminfo");
        double total = 0, avail = 0;
        for (std::string k, unit; f >> k;)
        {
            double v = 0;
            f >> v;
            std::getline(f, unit);
            if (k == "MemTotal:")
                total = v * 1024;
            else if (k == "MemAvailable:")
                avail = v * 1024;
        }
        if (total > 0 && avail / total < 0.10)
            raise("memory", avail / total < 0.05 ? "critical" : "warning", {},
                  "The host's memory is " + percent(1 - avail / total) + " used", size_text(avail) + " available of " + size_text(total), 3);
    }

    // A runtime near the limit it was given.
    for (const facts& r : runtimes)
        if (r.limit > 0 && static_cast<double>(r.used) / static_cast<double>(r.limit) >= 0.90)
        {
            const double share = static_cast<double>(r.used) / static_cast<double>(r.limit);
            raise("limit:" + r.name, share >= 0.98 ? "critical" : "warning", r.name,
                  r.name + " holds " + percent(share) + " of its limit",
                  size_text(static_cast<double>(r.used)) + " of " + size_text(static_cast<double>(r.limit)), 3);
        }

    std::erase_if(m_cert_left, [&](const auto& kv) { return !certs_named.count(kv.first); });

    // Git repositories whose last pull failed, read every minute and when a storage runtime is first seen: the first
    // reading comes before the runtimes are restored.
    std::set<std::string> stores;
    for (const facts& r : runtimes)
        if (!r.dir.empty())
            stores.insert(r.dir);
    if (now - m_git_at >= 60 || stores != m_git_dirs)
    {
        m_git.clear();
        m_git_dirs = stores;
        for (const facts& r : runtimes)
        {
            if (r.dir.empty())
                continue;
            socketley::storage::git_mirrors g;
            g.open(r.dir, 1, {}, false, {});
            for (const auto& repo : g.repos())
            {
                socketley::storage::jvalue st;
                if (!socketley::storage::json_reader(g.state_json(repo.id)).document(st))
                    continue;
                const auto* ok = member(st, "ok");
                const auto* err = member(st, "error");
                if (ok && ok->k == socketley::storage::jvalue::kind::boolean && !ok->b)
                    m_git[r.name].push_back(alert{"git:" + r.name + ":" + repo.id, "warning", r.name,
                                                  "Git: pulling " + repo.name + " into " + r.name + " failed",
                                                  err ? err->s : std::string(), 0});
            }
        }
        m_git_at = now;
    }
    for (const auto& [rt, list] : m_git)
        for (const alert& a : list)
            raise(a.id, a.level, a.runtime, a.title, a.detail, 1);

    // The disk of a runtime that is gone is no longer looked at, so the lists follow what exists.
    std::map<std::string, alert> plain;
    for (auto& [id, c] : seen)
    {
        plain[id] = c.a;
        m_states[id].hold = c.hold;
    }
    consider(now, plain);
}

void monitor::consider(int64_t now, std::map<std::string, alert>& seen)
{
    for (auto& [id, a] : seen)
    {
        state& s = m_states[id];
        // Since it was first seen: by this daemon, or by the one before it that told of it.
        const auto told = m_told.find(id);
        const int64_t since = s.held || s.raised ? s.a.since : told != m_told.end() ? told->second.first : now;
        s.a = a;
        s.a.since = since;
        s.gone = 0;
        if (++s.held >= s.hold && !s.raised)
        {
            s.raised = true;
            post(s.a, true, now);
        }
    }
    for (auto it = m_states.begin(); it != m_states.end();)
    {
        state& s = it->second;
        if (seen.count(it->first))
        {
            ++it;
            continue;
        }
        s.held = 0;
        if (s.raised && ++s.gone < 3)
        {
            ++it;
            continue;
        }
        if (s.raised)
            post(s.a, false, now);
        it = m_states.erase(it);
    }
    // Told of before a restart and not there now: cleared, once the first readings have had their chance to raise it.
    if (++m_checks == 4)
        for (const auto& [id, told] : decltype(m_told)(m_told))
            if (!m_states.count(id))
                post(alert{id, "warning", {}, told.second, {}, told.first}, false, now);
}

void monitor::post(const alert& a, bool raised, int64_t now)
{
    m_recent.emplace_front(now, std::make_pair(raised, a));
    if (m_recent.size() > 100)
        m_recent.pop_back();
    const bool told = m_told.count(a.id) > 0;
    if (raised == told)
        return;
    if (raised)
        m_told[a.id] = {a.since, a.title};
    else
        m_told.erase(a.id);
    save();
    if (raised)
        LOG_WARN(("alert: " + a.title + (a.detail.empty() ? "" : ": " + a.detail)).c_str());
    else
        LOG_INFO(("alert cleared: " + a.title).c_str());
    if (m_webhook.empty())
        return;
    std::string text = !raised ? "\xe2\x9c\x85 " : a.level == "critical" ? "\xf0\x9f\x94\xb4 " : "\xe2\x9a\xa0\xef\xb8\x8f ";
    if (!m_host.empty())
        text.append(m_host).append(": ");
    text += a.title;
    if (!raised)
        text += " -- resolved";
    else if (!a.detail.empty())
        text.append("\n").append(a.detail);
    if (text.size() > 1800)
        text.resize(1800);
    std::string body = "{\"content\":";
    body.append(quote(text)).append(",\"text\":").append(quote(text)).append(",\"state\":");
    body.append(quote(raised ? "firing" : "resolved")).append(",\"host\":").append(quote(m_host));
    body.append(",\"alert\":").append(alert_json(a)).append("}");
    {
        std::lock_guard lock(m_mtx);
        if (m_queue.size() < 50)
            m_queue.push_back(std::move(body));
    }
    m_cv.notify_one();
}

void monitor::sender()
{
    for (;;)
    {
        std::string body;
        {
            std::unique_lock lock(m_mtx);
            m_cv.wait(lock, [&] { return m_stop || !m_queue.empty(); });
            if (m_stop)
                return;
            body = std::move(m_queue.front());
            m_queue.pop_front();
        }
        https_client::client c;
        https_client::reply r;
        std::string err;
        if (!c.init(err, {}, "socketley-alerts") || !c.request("POST", m_webhook, "application/json", body, r, err, 10))
            LOG_WARN(("alert webhook: " + err).c_str());
        else if (r.status < 200 || r.status >= 300)
            LOG_WARN(("alert webhook: answered " + std::to_string(r.status)).c_str());
    }
}

void monitor::save() const
{
    if (m_path.empty())
        return;
    std::ostringstream o;
    for (const auto& [id, told] : m_told)
        o << id << '\t' << told.first << '\t' << told.second << '\n';
    // Private as the runtimes' files beside it are, and never through a link.
    const std::string tmp = m_path + ".tmp", s = o.str();
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    const bool ok = ::write(fd, s.data(), s.size()) == static_cast<ssize_t>(s.size());
    if (::close(fd) == 0 && ok)
        std::rename(tmp.c_str(), m_path.c_str());
    else
        std::remove(tmp.c_str());
}

std::string monitor::json() const
{
    std::vector<const alert*> active;
    for (const auto& [id, s] : m_states)
        if (s.raised)
            active.push_back(&s.a);
    std::sort(active.begin(), active.end(), [](const alert* x, const alert* y) {
        return x->level != y->level ? x->level == "critical" : x->since > y->since;
    });
    // Appended piece by piece throughout: gcc 12 takes a literal + std::string here for a copy past the largest object.
    std::string o = "{\"active\":[";
    for (size_t i = 0; i < active.size(); ++i)
    {
        if (i)
            o += ',';
        o += alert_json(*active[i]);
    }
    o += "],\"recent\":[";
    bool first = true;
    for (const auto& [at, ev] : m_recent)
    {
        o += first ? "{\"at\":" : ",{\"at\":";
        o += std::to_string(at);
        o += ",\"raised\":";
        o += ev.first ? "true" : "false";
        o += ",\"alert\":";
        o += alert_json(ev.second);
        o += '}';
        first = false;
    }
    o += "],\"webhook\":";
    o += m_webhook.empty() ? "false" : "true";
    return o + "}";
}

std::string monitor::test()
{
    if (m_webhook.empty())
        return "No webhook is set: daemon.alert_webhook in the daemon's configuration.";
    const std::string text = "\xf0\x9f\x94\x94 " + (m_host.empty() ? std::string() : m_host + ": ") +
                             "socketley's alerts reach this hook.";
    https_client::client c;
    https_client::reply r;
    std::string err;
    if (!c.init(err, {}, "socketley-alerts") ||
        !c.request("POST", m_webhook, "application/json",
                   "{\"content\":" + quote(text) + ",\"text\":" + quote(text) + ",\"state\":\"test\",\"host\":" + quote(m_host) + "}", r,
                   err, 10))
        return err;
    if (r.status < 200 || r.status >= 300)
        return "The hook answered " + std::to_string(r.status) + (r.body.empty() ? "" : ": " + r.body.substr(0, 200));
    return {};
}

}   // namespace alerts
