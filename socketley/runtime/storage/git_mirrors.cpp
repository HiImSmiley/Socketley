#include "git_mirrors.h"

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "digest.h"
#include "../../shared/json/json_doc.h"
#include "s3_auth.h"
#include "../../shared/storage/git_names.h"
#include "../../shared/util/logging.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/persist/replaced_file.h"
#include "../../shared/persist/read_file.h"

using socketley::json::jvalue;
using socketley::json::json_reader;

extern char** environ;

namespace socketley::storage
{

namespace
{

std::string text_of(const jvalue& o, std::string_view n)
{
    const jvalue* v = member(o, n);
    return v && v->k == jvalue::kind::string ? v->s : std::string{};
}

bool write_file(const std::string& path, std::string_view data, mode_t mode)
{
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(path).parent_path(), ec);
    return socketley::replace_file(path, data, socketley::durability::data, nullptr, mode);
}

// A short lock on the list, so two shards changing it at once both get their change in.
class list_lock
{
public:
    explicit list_lock(const std::string& dir)
    {
        std::error_code ec;
        std::filesystem::create_directories(dir + "/.ui", ec);
        m_fd = ::open((dir + "/.ui/git.lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        int r = -1;
        while (m_fd >= 0 && (r = ::flock(m_fd, LOCK_EX)) != 0 && errno == EINTR) {}
        m_held = m_fd >= 0 && r == 0;
    }
    ~list_lock()
    {
        if (m_fd >= 0)
            ::close(m_fd);
    }
    // A change made without the lock is one another shard's can overwrite, so none is made.
    bool held() const { return m_held; }

private:
    int m_fd{-1};
    bool m_held{false};
};

std::vector<git_mirrors::repo> parse(const std::string& text)
{
    std::vector<git_mirrors::repo> out;
    jvalue doc;
    if (!json_reader(text).document(doc))
        return out;
    const jvalue* list = member(doc, "repos");
    if (!list || list->k != jvalue::kind::array)
        return out;
    for (const jvalue& i : list->items)
    {
        git_mirrors::repo r;
        r.id = text_of(i, "id");
        r.owner = text_of(i, "owner");
        r.url = text_of(i, "url");
        r.branch = text_of(i, "branch");
        r.bucket = text_of(i, "bucket");
        r.name = text_of(i, "name");
        const jvalue* p = member(i, "private");
        r.private_repo = p && p->k == jvalue::kind::boolean && p->b;
        r.every = text_of(i, "every");
        if (!git_mirrors::valid_every(r.every))
            r.every = "never";
        r.added = socketley::json::int_of(i, "added", 0);
        if (!r.id.empty() && !r.url.empty())
            out.push_back(std::move(r));
    }
    return out;
}

std::string random_hex(size_t bytes)
{
    std::vector<unsigned char> b(bytes);
    if (RAND_bytes(b.data(), static_cast<int>(bytes)) != 1)
        return {};
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    for (unsigned char c : b)
        out += {hex[c >> 4], hex[c & 15]};
    return out;
}

}   // namespace

void git_mirrors::open(std::string dir, uint32_t shard, std::string endpoint, bool tls, std::string why_not,
                       std::string cert)
{
    m_cert = std::move(cert);
    m_dir = std::move(dir);
    m_shard = shard;
    m_endpoint = std::move(endpoint);
    m_tls = tls;
    m_why_not = std::move(why_not);
    m_any = !repos().empty();
    // Repositories that went to the one library every user shared go to their owner's own, git-<user>, and each
    // is run there until its whole tree is written and what the old library held of it is taken over; moved-from
    // in its directory says so, so a restart in between does not forget it.
    if (m_shard == 0 && m_any)
    {
        list_lock lock(m_dir);
        std::vector<repo> rs = repos();
        bool changed = false;
        for (repo& r : rs)
            if (r.bucket == "git" && !r.owner.empty() && git_names::library_for(r.owner) != "git")
            {
                std::error_code ec;
                std::filesystem::create_directories(work_of(r.id), ec);
                if (!write_file(work_of(r.id) + "/moved-from", r.bucket, 0600))
                    continue;
                r.bucket = git_names::library_for(r.owner);
                ::unlink((work_of(r.id) + "/written").c_str());
                changed = true;
                LOG_INFO(("storage: git: " + r.url + " goes to the library " + r.bucket + ", its owner's own").c_str());
            }
        if (changed && !save(rs))
            LOG_WARN("storage: git: the list of repositories could not be written, so none moved");
    }
}

void git_mirrors::open_runner(std::string dir, std::string user, std::string endpoint, bool tls, std::string cert)
{
    m_dir = std::move(dir);
    m_user = std::move(user);
    m_endpoint = std::move(endpoint);
    m_tls = tls;
    m_cert = std::move(cert);
    m_shard = 1;
}

size_t git_mirrors::mine()
{
    size_t n = 0;
    for (const repo& r : repos())
        n += r.owner == m_user;
    return n;
}

std::vector<git_mirrors::repo> git_mirrors::repos()
{
    const std::string path = m_dir + "/.ui/git.json";
    const socketley::file_stamp stamp = socketley::file_stamp::of(path);
    if (stamp != m_cache_stamp)
    {
        std::string text;
        m_cache = socketley::read_whole_file(path, text) ? parse(text) : std::vector<repo>{};
        m_cache_stamp = stamp;
        m_any = !m_cache.empty();
    }
    return m_cache;
}

bool git_mirrors::save(const std::vector<repo>& rs)
{
    std::string o = "{\"repos\":[";
    for (size_t i = 0; i < rs.size(); ++i)
    {
        const repo& r = rs[i];
        o += (i ? ",\n" : "\n") + std::string("{\"id\":") + socketley::json::quote(r.id) + ",\"owner\":" + socketley::json::quote(r.owner) +
             ",\"url\":" + socketley::json::quote(r.url) + ",\"branch\":" + socketley::json::quote(r.branch) + ",\"bucket\":" + socketley::json::quote(r.bucket) +
             ",\"name\":" + socketley::json::quote(r.name) + ",\"private\":" + (r.private_repo ? "true" : "false") +
             ",\"every\":" + socketley::json::quote(r.every) + ",\"added\":" + std::to_string(r.added) + "}";
    }
    o += "\n]}\n";
    const bool ok = write_file(m_dir + "/.ui/git.json", o, 0600);
    m_cache_stamp.reset();
    return ok;
}

std::string git_mirrors::add(repo& r)
{
    std::string why;
    if (!git_names::valid_url(r.url, why) || !git_names::valid_branch(r.branch, why))
        return why;
    if (r.name.empty())
        r.name = git_names::name_of(r.url);
    if (!git_names::valid_name(r.name, why))
        return why;
    if (!valid_every(r.every))
        return "a repository is pulled every day, week or month, or never";
    list_lock lock(m_dir);
    if (!lock.held())
        return "the list of repositories could not be locked";
    m_cache_stamp.reset();
    std::vector<repo> rs = repos();
    if (rs.size() >= max_repos)
        return "this runtime keeps at most " + std::to_string(max_repos) + " repositories";
    for (const repo& o : rs)
        if (o.bucket == r.bucket && o.name == r.name)
            return "the library " + r.bucket + " has a repository in " + r.name + "/ already";
    r.id = random_hex(6);
    r.added = static_cast<int64_t>(std::time(nullptr));
    if (r.id.empty())
        return "no id could be made";
    rs.push_back(r);
    return save(rs) ? std::string{} : "the list of repositories could not be written";
}

bool git_mirrors::remove(std::string_view id)
{
    list_lock lock(m_dir);
    if (!lock.held())
        return false;
    m_cache_stamp.reset();
    std::vector<repo> rs = repos();
    const size_t before = rs.size();
    std::erase_if(rs, [&](const repo& r) { return r.id == id; });
    if (rs.size() == before || !save(rs))
        return false;
    if (auto it = m_children.find(std::string(id)); it != m_children.end())
        ::kill(it->second, SIGTERM);
    // The clone goes; what it wrote into the library is the user's and stays.
    std::error_code ec;
    std::filesystem::remove_all(work_of(id), ec);
    return true;
}

bool git_mirrors::set_every(std::string_view id, std::string_view every)
{
    if (!valid_every(every))
        return false;
    list_lock lock(m_dir);
    if (!lock.held())
        return false;
    m_cache_stamp.reset();
    std::vector<repo> rs = repos();
    for (repo& r : rs)
        if (r.id == id)
        {
            r.every = every;
            return save(rs);
        }
    return false;
}

// A child this process started for `id` that has not ended, which holds the run before it has taken the run's lock.
bool git_mirrors::spawned_live(std::string_view id) const
{
    const auto it = m_children.find(std::string(id));
    if (it == m_children.end())
        return false;
    // Asked without reaping, so tick() still hears how it ended.
    siginfo_t info{};
    return ::waitid(P_PID, static_cast<id_t>(it->second), &info, WEXITED | WNOHANG | WNOWAIT) == 0 && info.si_pid == 0;
}

bool git_mirrors::running(std::string_view id) const
{
    const int fd = ::open((work_of(id) + "/lock").c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return false;
    const bool held = ::flock(fd, LOCK_EX | LOCK_NB) != 0;
    ::close(fd);
    return held;
}

std::string git_mirrors::state_json(std::string_view id) const
{
    std::string text;
    if (!socketley::read_whole_file(work_of(id) + "/state.json", text) || text.empty() || text.front() != '{')
        return "null";
    while (!text.empty() && (text.back() == '\n' || text.back() == ' '))
        text.pop_back();
    return text;
}

std::string git_mirrors::token_path(std::string_view user) const
{
    return m_dir + "/.ui/git-tokens/" + sha256_hex(user).substr(0, 32);
}

bool git_mirrors::has_token(std::string_view user) const
{
    struct stat st{};
    return ::stat(token_path(user).c_str(), &st) == 0;
}

bool git_mirrors::set_token(authenticator& auth, std::string_view user, std::string_view token)
{
    const std::string path = token_path(user);
    if (token.empty())
        return ::unlink(path.c_str()) == 0 || errno == ENOENT;
    const std::string key = auth.seal_key(user, "socketley git token");
    if (key.size() != 32)
        return false;
    unsigned char nonce[12], tag[16];
    if (RAND_bytes(nonce, sizeof nonce) != 1)
        return false;
    std::string sealed(token.size(), '\0');
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int n = 0, m = 0;
    bool ok = ctx && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, reinterpret_cast<const unsigned char*>(key.data()),
                                        nonce) == 1 &&
              EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(sealed.data()), &n,
                                reinterpret_cast<const unsigned char*>(token.data()), static_cast<int>(token.size())) == 1 &&
              EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(sealed.data()) + n, &m) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof tag, tag) == 1;
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    if (!ok)
        return false;
    const std::string file = std::string("v1") + std::string(reinterpret_cast<char*>(nonce), sizeof nonce) +
                             std::string(reinterpret_cast<char*>(tag), sizeof tag) + sealed;
    return write_file(path, file, 0600);
}

std::string git_mirrors::token_of(authenticator& auth, std::string_view user) const
{
    std::string file;
    if (!socketley::read_whole_file(token_path(user), file) || file.size() < 2 + 12 + 16 || !file.starts_with("v1"))
        return {};
    const std::string key = auth.seal_key(user, "socketley git token");
    if (key.size() != 32)
        return {};
    const auto* nonce = reinterpret_cast<const unsigned char*>(file.data() + 2);
    std::string tag = file.substr(14, 16);
    const std::string sealed = file.substr(30);
    std::string token(sealed.size(), '\0');
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int n = 0, m = 0;
    const bool ok = ctx && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                                              reinterpret_cast<const unsigned char*>(key.data()), nonce) == 1 &&
                    EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(token.data()), &n,
                                      reinterpret_cast<const unsigned char*>(sealed.data()),
                                      static_cast<int>(sealed.size())) == 1 &&
                    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) == 1 &&
                    EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(token.data()) + n, &m) == 1;
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return ok ? token : std::string{};
}

std::string git_mirrors::run_now(std::string_view id)
{
    for (const repo& r : repos())
        if (r.id == id)
        {
            if (running(id))
                return "it is running already";
            if (r.private_repo && !has_token(r.owner))
                return "the repository is private and " + r.owner + " has no GitHub token set";
            std::error_code ec;
            std::filesystem::create_directories(work_of(id), ec);
            return write_file(work_of(id) + "/asked", std::to_string(std::time(nullptr)), 0600)
                       ? std::string()
                       : "the run could not be asked for";
        }
    return "no such repository";
}

std::string git_mirrors::start(const repo& r, const identity& id)
{
    if (!available())
        return m_why_not;
    if (id.access_key.empty())
        return "the storage has handed this sync runtime no credentials of " + r.owner + " yet";
    if (r.private_repo && id.github_token.empty())
        return "the repository is private and " + r.owner + " has no GitHub token set";
    const std::string work = work_of(r.id);
    std::error_code ec;
    std::filesystem::create_directories(work, ec);
    std::vector<std::string> args = {"socketley", "git-sync", "--url", r.url, "--branch", r.branch, "--work", work,
                                     "--endpoint", m_endpoint, "--bucket", r.bucket, "--name", r.name};
    if (m_tls)
        args.push_back("--tls");
    if (m_tls && !m_cert.empty())
    {
        args.push_back("--ca");
        args.push_back(m_cert);
    }
    if (std::string old; socketley::read_whole_file(work + "/moved-from", old) && !old.empty())
    {
        args.push_back("--move-from");
        args.push_back(old);
    }
    std::vector<char*> argv;
    for (std::string& s : args)
        argv.push_back(s.data());
    argv.push_back(nullptr);
    std::vector<std::string> env;
    for (char** e = environ; *e; ++e)
        if (!std::string_view(*e).starts_with("SOCKETLEY_GIT_"))
            env.emplace_back(*e);
    // Temporary credentials of the user it is kept for, so the run may do what that user may and no more.
    env.push_back("SOCKETLEY_GIT_ACCESS_KEY=" + id.access_key);
    env.push_back("SOCKETLEY_GIT_SECRET=" + id.secret);
    env.push_back("SOCKETLEY_GIT_SESSION_TOKEN=" + id.session_token);
    if (r.private_repo)
        env.push_back("SOCKETLEY_GIT_TOKEN=" + id.github_token);
    std::vector<char*> envp;
    for (std::string& s : env)
        envp.push_back(s.data());
    envp.push_back(nullptr);
    const std::string log = work + "/log";
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t attr;
    posix_spawn_file_actions_init(&fa);
    posix_spawnattr_init(&attr);
    posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 1, log.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    posix_spawn_file_actions_adddup2(&fa, 1, 2);
    posix_spawn_file_actions_addclosefrom_np(&fa, 3);
    sigset_t def, none;
    sigemptyset(&def);
    sigaddset(&def, SIGPIPE);
    sigemptyset(&none);
    posix_spawnattr_setsigdefault(&attr, &def);
    posix_spawnattr_setsigmask(&attr, &none);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK);
    pid_t pid = -1;
    const int rc = ::posix_spawn(&pid, "/proc/self/exe", &fa, &attr, argv.data(), envp.data());
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&attr);
    if (rc != 0)
        return "git-sync could not be started: " + std::string(std::strerror(rc));
    m_children[r.id] = pid;
    m_done.running = r.name;
    ::unlink((work + "/asked").c_str());
    LOG_INFO(("git: " + r.url + " (" + r.branch + ") into " + r.bucket + "/" + r.name + "/, for " + r.owner).c_str());
    return {};
}

bool git_mirrors::due(const repo& r, int64_t now) const
{
    if (r.every == "never")
        return false;
    std::string text;
    jvalue st;
    const bool ran = socketley::read_whole_file(work_of(r.id) + "/state.json", text) && json_reader(text).document(st);
    const std::time_t t = static_cast<std::time_t>(now);
    std::tm tm{};
    ::localtime_r(&t, &tm);
    if (!ran)
        return true;
    const int64_t at = socketley::json::int_of(st, "at", 0);
    const jvalue* ok = member(st, "ok");
    // One that failed is tried again an hour later.
    if (!(ok && ok->b))
        return now - at >= 3600;
    const std::time_t last = static_cast<std::time_t>(at);
    std::tm lt{};
    ::localtime_r(&last, &lt);
    if (tm.tm_hour < due_hour)
        return false;
    if (r.every == "day")
        return lt.tm_year != tm.tm_year || lt.tm_yday != tm.tm_yday;
    // A week or a month on, counted in days, less the hours a run late in its day would push the next one back.
    const int64_t days = (now - at + 6 * 3600) / 86400;
    return days >= (r.every == "week" ? 7 : 30);
}

void git_mirrors::tick()
{
    if (m_shard != 0 || !m_any)
        return;
    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    if (now < m_next_look)
        return;
    m_next_look = now + 1;
    // A run is told of once its state is written and its lock let go; what the first look finds is no news.
    for (const repo& r : repos())
    {
        const socketley::file_stamp stamp = socketley::file_stamp::of(work_of(r.id) + "/state.json");
        auto [it, fresh] = m_seen.try_emplace(r.id, stamp);
        if (stamp == it->second && !(fresh && m_seen_once))
            continue;
        if (running(r.id))
            continue;
        it->second = stamp;
        std::string state;
        if (stamp.exists() && on_run && socketley::read_whole_file(work_of(r.id) + "/state.json", state))
            on_run(r, state);
    }
    m_seen_once = true;
}

void git_mirrors::serve(const identity& id)
{
    for (auto it = m_children.begin(); it != m_children.end();)
    {
        int status = 0;
        const pid_t w = ::waitpid(it->second, &status, WNOHANG);
        if (w == 0)
        {
            ++it;
            continue;
        }
        ++m_done.runs;
        if (w == it->second && WIFEXITED(status) && WEXITSTATUS(status) == 0)
            ::unlink((work_of(it->first) + "/moved-from").c_str());
        else
        {
            ++m_done.failures;
            std::string state;
            jvalue st;
            const bool said = socketley::read_whole_file(work_of(it->first) + "/state.json", state) &&
                              json_reader(state).document(st);
            m_done.last_error = said ? text_of(st, "error") : "the run of " + it->first + " failed";
            LOG_WARN(("git: the run of " + it->first + " failed; see " + work_of(it->first) + "/log").c_str());
        }
        m_done.running.clear();
        it = m_children.erase(it);
    }
    // One run at a time, so a morning of many repositories is not a burst on the uplink.
    if (!m_children.empty() || !available())
        return;
    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    std::vector<repo> mine;
    for (const repo& r : repos())
        if (r.owner == m_user && !running(r.id))
            mine.push_back(r);
    const auto has = [&](const repo& r, const char* f) { return ::access((work_of(r.id) + "/" + f).c_str(), F_OK) == 0; };
    const repo* next = nullptr;
    // A moved one first, so its old library is emptied soon; then one asked for, at once; then, once a minute, one
    // that is due.
    for (const repo& r : mine)
        if (!next && has(r, "moved-from"))
            next = &r;
    for (const repo& r : mine)
        if (!next && has(r, "asked"))
            next = &r;
    if (!next && now >= m_next_look)
    {
        m_next_look = now + 60;
        for (const repo& r : mine)
            if (!next && due(r, now))
                next = &r;
    }
    if (!next)
        return;
    if (const std::string why = start(*next, id); !why.empty())
    {
        // Said where the interface shows it, and asked again an hour later rather than every minute.
        LOG_WARN(("git: " + next->url + " is not run: " + why).c_str());
        ++m_done.failures;
        m_done.last_error = why;
        ::unlink((work_of(next->id) + "/asked").c_str());
        std::error_code ec;
        std::filesystem::create_directories(work_of(next->id), ec);
        write_file(work_of(next->id) + "/state.json",
                   "{\"ok\":false,\"at\":" + std::to_string(now) + ",\"error\":" + socketley::json::quote(why) + "}\n", 0600);
    }
}

void git_mirrors::stop()
{
    for (auto& [id, pid] : m_children)
    {
        ::kill(pid, SIGTERM);
        ::waitpid(pid, nullptr, 0);
    }
    m_children.clear();
}

}   // namespace socketley::storage
