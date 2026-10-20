#include "alerts.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include <algorithm>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <set>
#include <utility>
#include <sstream>

#include "dashboard.h"
#include "../runtime/storage/git_mirrors.h"
#include "../shared/json/json_doc.h"
#include "../shared/http/https_client.h"
#include "../shared/util/log_ring.h"
#include "../shared/util/logging.h"
#include "../shared/json/json_escape.h"
#include "../shared/persist/replaced_file.h"
#include "../shared/crypto/cert_keeper.h"

namespace alerts
{

namespace
{

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
    o += socketley::json::quote(a.id);
    o += ",\"level\":";
    o += socketley::json::quote(a.level);
    o += ",\"runtime\":";
    o += socketley::json::quote(a.runtime);
    o += ",\"title\":";
    o += socketley::json::quote(a.title);
    o += ",\"detail\":";
    o += socketley::json::quote(a.detail);
    o += ",\"since\":";
    o += std::to_string(a.since);
    o += '}';
    return o;
}

}   // namespace

monitor::monitor(std::string state_path, std::string webhook, sender send, event_sender event)
    : m_path(std::move(state_path)), m_webhook(std::move(webhook)), m_send(std::move(send)), m_event(std::move(event))
{
    char host[256] = {};
    if (::gethostname(host, sizeof host - 1) == 0)
        m_host = host;
    std::ifstream f(m_path);
    for (std::string line; std::getline(f, line);)
        if (const size_t a = line.find('\t'), b = line.find('\t', a + 1); b != std::string::npos)
            m_told[line.substr(0, a)] = {std::strtoll(line.c_str() + a + 1, nullptr, 10), line.substr(b + 1)};
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

    // A sync that cannot carry what it owes, held for three readings so one refused file in passing is not news.
    for (const facts& r : runtimes)
        if (r.failing > 0 && !r.failed)
            raise("sync:" + r.name, "warning", r.name, r.name + " cannot carry everything it owes", r.error, 3);

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
            cert_keeper::cert_facts c;
            const bool ok = cert_keeper::read_cert(r.cert, c);
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
    // Told apart by the device the directory is on, since filesystems that give no fsid all give 0.
    std::set<dev_t> disks;
    for (const std::string& d : dirs)
    {
        struct statvfs v{};
        struct stat st{};
        if (::statvfs(d.c_str(), &v) != 0 || v.f_blocks == 0 || ::stat(d.c_str(), &st) != 0 ||
            !disks.insert(st.st_dev).second)
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
                socketley::json::jvalue st;
                if (!socketley::json::json_reader(g.state_json(repo.id)).document(st))
                    continue;
                const auto* ok = member(st, "ok");
                const auto* err = member(st, "error");
                if (ok && ok->k == socketley::json::jvalue::kind::boolean && !ok->b)
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
    if (m_event)
    {
        // An id is a topic's last levels, with what a topic may not hold in it taken out.
        std::string sub = "alerts/" + a.id;
        std::replace_if(sub.begin(), sub.end(), [](char c) { return c == '+' || c == '#'; }, '_');
        m_event(std::move(sub), raised ? alert_json(a) : std::string());
    }
    if (m_webhook.empty() || !m_send)
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
    {
        // Cut on a character's first byte, so the body stays UTF-8 a strict hook takes.
        size_t at = 1800;
        while (at > 0 && (static_cast<unsigned char>(text[at]) & 0xC0) == 0x80)
            --at;
        text.resize(at);
    }
    std::string body = "{\"content\":";
    body.append(socketley::json::quote(text)).append(",\"text\":").append(socketley::json::quote(text)).append(",\"state\":");
    body.append(socketley::json::quote(raised ? "firing" : "resolved")).append(",\"host\":").append(socketley::json::quote(m_host));
    body.append(",\"alert\":").append(alert_json(a)).append("}");
    m_send(std::move(body));
}

void monitor::save() const
{
    if (m_path.empty())
        return;
    std::ostringstream o;
    for (const auto& [id, told] : m_told)
        o << id << '\t' << told.first << '\t' << told.second << '\n';
    // Private as the runtimes' files beside it are; a crash that takes it tells an alert again.
    if (!socketley::replace_file(m_path, o.str(), socketley::durability::none)) {}
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
                   "{\"content\":" + socketley::json::quote(text) + ",\"text\":" + socketley::json::quote(text) + ",\"state\":\"test\",\"host\":" + socketley::json::quote(m_host) + "}", r,
                   err, 10))
        return err;
    if (r.status < 200 || r.status >= 300)
        return "The hook answered " + std::to_string(r.status) + (r.body.empty() ? "" : ": " + r.body.substr(0, 200));
    return {};
}

}   // namespace alerts
