#include "imap_store.h"

#include <algorithm>
#include <filesystem>
#include <set>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mail_instance.h"
#include "mail_mailbox.h"
#include "mail_run.h"
#include "mail_spool.h"
#include "../../shared/loop/blocking_write.h"
#include "../../shared/persist/paths.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/persist/replaced_file.h"
#include "../../shared/storage/storage_rpc.h"
#include "../../shared/util/ascii.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/text_list.h"
#include "../../shared/util/wall_clock.h"

namespace socketley::mail
{

namespace
{

namespace rpc = socketley::storage_rpc;

// A folder looked at again in the bucket no sooner than this after the last time.
constexpr int64_t sync_ms = 2000;

std::string canonical(const std::string& folder)
{
    return socketley::ascii::iequals(folder, "INBOX") ? std::string("INBOX") : folder;
}

}   // namespace

imap_message* imap_folder::by_uid(uint32_t uid)
{
    const auto it = std::lower_bound(msgs.begin(), msgs.end(), uid,
                                     [](const imap_message& m, uint32_t u) { return m.uid < u; });
    return it != msgs.end() && it->uid == uid ? &*it : nullptr;
}

imap_store::imap_store(mail_run& run) : m_run(run) {}

imap_store::~imap_store()
{
    *m_alive = false;
}

void imap_store::flush_now()
{
    // What was appended since the last sync, synced in line, since nothing after a stop waits for the pool.
    for (auto& [name, u] : m_users)
        if (u.unsynced)
        {
            const int fd = ::open((u.base + ".log").c_str(), O_WRONLY | O_CLOEXEC);
            if (fd >= 0)
            {
                if (::fdatasync(fd) != 0) {}
                ::close(fd);
            }
            u.unsynced = false;
        }
}

const std::vector<std::pair<std::string, std::string>>& imap_store::special()
{
    static const std::vector<std::pair<std::string, std::string>> s = {
        {"INBOX", ""}, {"Sent", "\\Sent"}, {"Drafts", "\\Drafts"}, {"Junk", "\\Junk"}, {"Trash", "\\Trash"}};
    return s;
}

std::string imap_store::path_of(const std::string& user) const
{
    std::string safe;
    for (const char c : user)
        safe += (std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == '_' || c == '@') ? c : '_';
    return (socketley_paths::resolve().state_dir / "mail" / (std::string(m_run.owner().get_name()) + ".imap") / safe)
        .string();
}

std::shared_ptr<imap_folder> imap_store::make_folder(user_state& u, const std::string& name)
{
    auto f = std::make_shared<imap_folder>();
    f->name = name;
    f->uidvalidity = static_cast<uint32_t>(wall::now_ms() / 1000);
    u.folders[name] = f;
    return f;
}

imap_store::user_state& imap_store::user(const std::string& name)
{
    user_state& u = m_users[name];
    if (!u.loaded)
    {
        u.loaded = true;
        u.base = path_of(name);
        reload(u);
        // The folders every mailbox has, logged by the first shard to want them so every shard has their UIDVALIDITY.
        bool missing = false;
        for (const auto& [f, use] : special())
            missing = missing || !u.folders.count(f);
        if (missing)
            mutate(name, [this](user_state& us, std::string& lines) {
                for (const auto& [f, use] : special())
                    if (!us.folders.count(f))
                    {
                        auto made = make_folder(us, f);
                        lines += "F " + std::to_string(made->uidvalidity) + " " + f + "\n";
                    }
            });
    }
    return u;
}

void imap_store::apply(user_state& u, std::string_view text, bool fresh)
{
    const auto num = [](std::string_view v) { return std::strtoull(std::string(v).c_str(), nullptr, 10); };
    // The words of a line before its last field, which may hold spaces.
    const auto words = [](std::string_view& l, int n) {
        std::vector<std::string_view> w;
        for (int i = 0; i < n; ++i)
        {
            const size_t sp = l.find(' ');
            w.push_back(l.substr(0, sp));
            l = sp == std::string_view::npos ? std::string_view{} : l.substr(sp + 1);
        }
        return w;
    };
    const auto folder = [&u](std::string_view name) -> imap_folder* {
        const auto it = u.folders.find(std::string(name));
        return it == u.folders.end() ? nullptr : it->second.get();
    };
    while (!text.empty())
    {
        std::string_view line = socketley::take_item(text, '\n');
        if (line.size() < 3 || line[1] != ' ')
            continue;
        std::string_view l = line.substr(2);
        switch (line[0])
        {
            case 'F':
            {
                const auto w = words(l, 1);
                if (l.empty() || u.folders.count(std::string(l)))
                    break;
                auto f = std::make_shared<imap_folder>();
                f->name = std::string(l);
                f->uidvalidity = static_cast<uint32_t>(num(w[0]));
                u.folders[f->name] = std::move(f);
                break;
            }
            case 'D':
                u.folders.erase(std::string(l));
                break;
            case 'U':
            {
                const auto w = words(l, 1);
                if (imap_folder* f = folder(l))
                    f->subscribed = w[0] == "1";
                break;
            }
            case 'A':
            {
                // A <uid> <flags> <size> <date> <modseq> <folder>\t<key>
                const auto w = words(l, 5);
                const size_t tab = l.find('\t');
                imap_folder* f = tab == std::string_view::npos ? nullptr : folder(l.substr(0, tab));
                if (!f)
                    break;
                imap_message m;
                m.uid = static_cast<uint32_t>(num(w[0]));
                m.flags = static_cast<uint8_t>(num(w[1]));
                m.size = num(w[2]);
                m.date_ms = static_cast<int64_t>(num(w[3]));
                m.modseq = num(w[4]);
                m.key = std::string(l.substr(tab + 1));
                m.recent = fresh;
                f->uidnext = std::max(f->uidnext, m.uid + 1);
                f->highestmodseq = std::max(f->highestmodseq, m.modseq);
                if (f->msgs.empty() || f->msgs.back().uid < m.uid)
                    f->msgs.push_back(std::move(m));
                else if (!f->by_uid(m.uid))
                {
                    const auto at = std::lower_bound(f->msgs.begin(), f->msgs.end(), m.uid,
                                                     [](const imap_message& x, uint32_t uid) { return x.uid < uid; });
                    f->msgs.insert(at, std::move(m));
                }
                ++f->version;
                break;
            }
            case 'S':
            case 'X':
            {
                // S <uid> <flags> <modseq> <folder>, X <uid> <modseq> <folder>
                const auto w = words(l, line[0] == 'S' ? 3 : 2);
                imap_folder* f = folder(l);
                if (!f)
                    break;
                const uint32_t uid = static_cast<uint32_t>(num(w[0]));
                const uint64_t modseq = num(w.back());
                f->highestmodseq = std::max(f->highestmodseq, modseq);
                if (line[0] == 'S')
                {
                    if (imap_message* m = f->by_uid(uid))
                    {
                        m->flags = static_cast<uint8_t>(num(w[1]));
                        m->modseq = modseq;
                    }
                }
                else
                {
                    std::erase_if(f->msgs, [uid](const imap_message& m) { return m.uid == uid; });
                    f->vanished.emplace_back(modseq, uid);
                    if (f->vanished.size() > 20000)
                    {
                        f->vanished_from = f->vanished[9999].first;
                        f->vanished.erase(f->vanished.begin(), f->vanished.begin() + 10000);
                    }
                }
                ++f->version;
                break;
            }
            default:
                break;
        }
    }
}

void imap_store::reload(user_state& u)
{
    // Under the user's lock, shared, so a compaction is not caught between its snapshot and its journal.
    const std::string& base = u.base;
    const int lock = u.locked ? -1 : ::open((base + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock >= 0 && ::flock(lock, LOCK_SH) != 0) {}
    std::map<std::string, std::shared_ptr<imap_folder>> before = std::move(u.folders);
    u.folders.clear();
    std::string snap, log;
    socketley::read_file(base, snap, {.missing_ok = true}, nullptr);
    u.snapshot_gen = 0;
    u.snapshot_bytes = snap.size();
    if (snap.starts_with("SKLIMAP"))
    {
        const bool v1 = snap.starts_with("SKLIMAP1\n");
        std::string_view rest = snap;
        const std::string_view head = socketley::take_item(rest, '\n');
        if (!v1 && head.size() > 9)
            u.snapshot_gen = std::strtoull(std::string(head.substr(9)).c_str(), nullptr, 10);
        std::shared_ptr<imap_folder> f;
        const auto num = [](std::string_view v) { return std::strtoull(std::string(v).c_str(), nullptr, 10); };
        while (!rest.empty())
        {
            std::string_view line = socketley::take_item(rest, '\n');
            if (line.size() < 2)
                continue;
            std::vector<std::string_view> w;
            std::string_view l = line.substr(2);
            // F <uidvalidity> <uidnext> <subscribed> [<highestmodseq>] <name>,
            // M <uid> <flags> <size> <date> [<modseq>] <key>: the last word may hold spaces, and v1 has no modseq.
            const int fixed = (line[0] == 'F' ? 3 : 4) + (v1 ? 0 : 1);
            for (int i = 0; i < fixed; ++i)
            {
                const size_t sp = l.find(' ');
                w.push_back(l.substr(0, sp));
                l = sp == std::string_view::npos ? std::string_view{} : l.substr(sp + 1);
            }
            if (line[0] == 'F' && !l.empty())
            {
                f = std::make_shared<imap_folder>();
                f->name = std::string(l);
                f->uidvalidity = static_cast<uint32_t>(num(w[0]));
                f->uidnext = static_cast<uint32_t>(num(w[1]));
                f->subscribed = w[2] == "1";
                f->highestmodseq = v1 ? 1 : std::max<uint64_t>(1, num(w[3]));
                // What the snapshot folded in is no longer known as expunged.
                f->vanished_from = f->highestmodseq;
                u.folders[f->name] = f;
            }
            else if (line[0] == 'M' && f && !l.empty())
            {
                imap_message m;
                m.uid = static_cast<uint32_t>(num(w[0]));
                m.flags = static_cast<uint8_t>(num(w[1]));
                m.size = num(w[2]);
                m.date_ms = static_cast<int64_t>(num(w[3]));
                m.modseq = v1 ? 1 : std::max<uint64_t>(1, num(w[4]));
                m.key = std::string(l);
                m.recent = false;
                f->msgs.push_back(std::move(m));
            }
        }
        for (auto& [n, folder] : u.folders)
            std::sort(folder->msgs.begin(), folder->msgs.end(),
                      [](const imap_message& a, const imap_message& b) { return a.uid < b.uid; });
    }
    struct stat st{};
    u.log_ino = 0;
    u.log_off = 0;
    if (socketley::read_file(base + ".log", log, {.missing_ok = true}, nullptr) && ::stat((base + ".log").c_str(), &st) == 0)
    {
        u.log_ino = st.st_ino;
        // A journal of another snapshot is one a compaction already folded in.
        std::string_view rest = log;
        const std::string_view head = socketley::take_item(rest, '\n');
        const size_t whole = log.rfind('\n') == std::string::npos ? 0 : log.rfind('\n') + 1;
        if (head.starts_with("SKLIMAPLOG ") &&
            std::strtoull(std::string(head.substr(11)).c_str(), nullptr, 10) == u.snapshot_gen)
            apply(u, std::string_view(log).substr(head.size() + 1, whole > head.size() ? whole - head.size() - 1 : 0),
                  false);
        u.log_off = whole;
    }
    if (lock >= 0)
        ::close(lock);
    // The folder objects sessions hold are kept, their contents those just read.
    for (auto& [n, f] : u.folders)
        if (const auto it = before.find(n); it != before.end())
        {
            imap_folder& old = *it->second;
            old.uidvalidity = f->uidvalidity;
            old.uidnext = f->uidnext;
            old.subscribed = f->subscribed;
            old.highestmodseq = f->highestmodseq;
            old.vanished = std::move(f->vanished);
            old.vanished_from = f->vanished_from;
            for (auto& m : f->msgs)
                if (const imap_message* was = old.by_uid(m.uid))
                    m.recent = was->recent;
            old.msgs = std::move(f->msgs);
            ++old.version;
            f = it->second;
        }
}

void imap_store::refresh(const std::string& name)
{
    if (const auto it = m_users.find(name); it != m_users.end() && it->second.loaded)
        catch_up(it->second);
}

void imap_store::catch_up(user_state& u)
{
    const std::string log = u.base + ".log";
    struct stat st{};
    if (::stat(log.c_str(), &st) != 0)
    {
        if (u.log_ino)
            reload(u);
        return;
    }
    if (st.st_ino != u.log_ino || static_cast<uint64_t>(st.st_size) < u.log_off)
    {
        reload(u);
        return;
    }
    if (static_cast<uint64_t>(st.st_size) == u.log_off)
        return;
    // The lines another shard appended, up to the last whole one.
    const int fd = ::open(log.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return;
    std::string more(static_cast<size_t>(st.st_size) - u.log_off, '\0');
    const ssize_t n = ::pread(fd, more.data(), more.size(), static_cast<off_t>(u.log_off));
    ::close(fd);
    if (n <= 0)
        return;
    more.resize(static_cast<size_t>(n));
    const size_t whole = more.rfind('\n');
    if (whole == std::string::npos)
        return;
    apply(u, std::string_view(more).substr(0, whole + 1), true);
    u.log_off += whole + 1;
}

void imap_store::mutate(const std::string& name, const std::function<void(user_state&, std::string& lines)>& change)
{
    user_state& u = m_users[name];
    if (u.base.empty())
        u.base = path_of(name);
    const std::string& base = u.base;
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(base).parent_path(), ec);
    // Held only for a read of what is new and an append: no shard waits on another's disk.
    const int lock = u.locked ? -1 : ::open((base + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock >= 0 && ::flock(lock, LOCK_EX) != 0) {}
    const bool outer = !u.locked;
    u.locked = true;
    catch_up(u);
    std::string lines;
    change(u, lines);
    if (!lines.empty())
    {
        const std::string log = base + ".log";
        const int fd = ::open(log.c_str(), O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
        struct stat st{};
        if (fd >= 0 && ::fstat(fd, &st) == 0)
        {
            if (st.st_size == 0)
                lines = "SKLIMAPLOG " + std::to_string(u.snapshot_gen) + "\n" + lines;
            if (socketley::write_all(fd, lines.data(), lines.size()))
            {
                // What this shard wrote is read already; another's lines in between were read by the refresh.
                if (st.st_ino != u.log_ino || static_cast<uint64_t>(st.st_size) != u.log_off)
                    u.log_off = static_cast<uint64_t>(st.st_size);
                u.log_ino = st.st_ino;
                u.log_off += lines.size();
                u.unsynced = true;
            }
            else
                LOG_WARN(("mail: the IMAP journal " + log + " could not be written").c_str());
        }
        if (fd >= 0)
            ::close(fd);
    }
    if (outer)
        u.locked = false;
    if (lock >= 0)
        ::close(lock);
}

void imap_store::compact(const std::string& name, user_state& u)
{
    // The journal folded into a new snapshot on a helper thread, given up there if a line came since it was built.
    u.compacting = true;
    const uint64_t gen = u.snapshot_gen + 1;
    std::string text = "SKLIMAP2 " + std::to_string(gen) + "\n";
    for (const auto& [n, f] : u.folders)
    {
        text += "F " + std::to_string(f->uidvalidity) + " " + std::to_string(f->uidnext) + " " +
                (f->subscribed ? "1" : "0") + " " + std::to_string(f->highestmodseq) + " " + n + "\n";
        for (const auto& m : f->msgs)
            text += "M " + std::to_string(m.uid) + " " + std::to_string(m.flags) + " " + std::to_string(m.size) + " " +
                    std::to_string(m.date_ms) + " " + std::to_string(m.modseq) + " " + m.key + "\n";
    }
    auto done = std::make_shared<bool>(false);
    m_run.pool().submit(
        0,
        [base = u.base, text = std::move(text), gen, expect = u.log_off, ino = u.log_ino, done] {
            const int lock = ::open((base + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
            if (lock < 0 || ::flock(lock, LOCK_EX) != 0)
            {
                if (lock >= 0)
                    ::close(lock);
                return;
            }
            struct stat st{};
            std::string why;
            if (::stat((base + ".log").c_str(), &st) == 0 && st.st_ino == ino &&
                static_cast<uint64_t>(st.st_size) == expect &&
                socketley::replace_file(base, text, socketley::durability::data, &why) &&
                socketley::replace_file(base + ".log", "SKLIMAPLOG " + std::to_string(gen) + "\n",
                                        socketley::durability::data, &why))
                *done = true;
            ::close(lock);
        },
        [this, name, done, alive = m_alive] {
            if (!*alive)
                return;
            const auto it = m_users.find(name);
            if (it == m_users.end())
                return;
            it->second.compacting = false;
            // The new journal is another file, which the next refresh reads from its start.
            if (*done)
                reload(it->second);
        });
}

size_t imap_store::set_flags(const std::string& name, const std::shared_ptr<imap_folder>& f,
                             const std::vector<uint32_t>& uids, const std::function<uint8_t(uint8_t)>& change)
{
    size_t changed = 0;
    mutate(name, [&](user_state&, std::string& lines) {
        for (const uint32_t uid : uids)
            if (imap_message* m = f->by_uid(uid))
            {
                const uint8_t now = change(m->flags);
                if (now == m->flags)
                    continue;
                ++changed;
                m->flags = now;
                m->modseq = ++f->highestmodseq;
                lines += "S " + std::to_string(uid) + " " + std::to_string(now) + " " + std::to_string(m->modseq) + " " +
                         f->name + "\n";
            }
        if (!lines.empty())
            ++f->version;
    });
    return changed;
}

void imap_store::tick(int64_t)
{
    for (auto& [name, u] : m_users)
    {
        if (!u.loaded)
            continue;
        catch_up(u);
        if (u.unsynced)
        {
            u.unsynced = false;
            m_run.pool().submit(0, [log = u.base + ".log"] {
                const int fd = ::open(log.c_str(), O_WRONLY | O_CLOEXEC);
                if (fd >= 0)
                {
                    if (::fdatasync(fd) != 0) {}
                    ::close(fd);
                }
            }, [] {});
        }
        // A journal grown past its snapshot and a quarter of a mebibyte is folded into a new one.
        if (!u.compacting && u.log_off > (256u << 10) && u.log_off > u.snapshot_bytes)
            compact(name, u);
    }
}

void imap_store::folders(const std::string& name, std::function<void(std::vector<std::string>)> done)
{
    mailboxes* boxes = m_run.boxes();
    rpc::request rq;
    rq.kind = rpc::op::list;
    rq.bucket = boxes->bucket();
    rq.prefix = name + "/";
    rq.delimiter = "/";
    boxes->ask(boxes->storage(), rpc::encode(rq),
               [this, name, done, alive = m_alive](request_status st, std::string_view bytes) {
                   if (!*alive)
                       return;
                   user_state& u = user(name);
                   rpc::reply r;
                   std::vector<std::string> found;
                   if (st == request_status::ok && rpc::decode(bytes, rpc::op::list, r) && r.ok)
                       for (const auto& p : r.prefixes)
                       {
                           std::string f = p.substr(name.size() + 1);
                           if (!f.empty() && f.back() == '/')
                               f.pop_back();
                           if (!f.empty() && !u.folders.count(canonical(f)) && f.find('\t') == std::string::npos)
                               found.push_back(canonical(f));
                       }
                   // A folder the bucket has and the index not is given its UIDVALIDITY once, for every shard.
                   if (!found.empty())
                       mutate(name, [&](user_state& us, std::string& lines) {
                           for (const auto& f : found)
                               if (!us.folders.count(f))
                               {
                                   auto x = make_folder(us, f);
                                   lines += "F " + std::to_string(x->uidvalidity) + " " + f + "\n";
                               }
                       });
                   std::vector<std::string> out;
                   for (const auto& [n, f] : u.folders)
                       out.push_back(n);
                   done(std::move(out));
               });
}

uint64_t imap_store::usage(const std::string& name)
{
    user_state& u = user(name);
    catch_up(u);
    uint64_t total = 0;
    for (const auto& [n, f] : u.folders)
        for (const auto& m : f->msgs)
            total += m.size;
    return total;
}

uint64_t imap_store::quota(const std::string& name) const
{
    return m_run.boxes() ? m_run.boxes()->quota_of(name) : 0;
}

bool imap_store::subscribed(const std::string& name, const std::string& folder)
{
    const user_state& u = user(name);
    const auto it = u.folders.find(canonical(folder));
    return it != u.folders.end() && it->second->subscribed;
}

bool imap_store::create(const std::string& name, const std::string& folder)
{
    user(name);
    const std::string f = canonical(folder);
    if (f.empty() || f.find_first_of("\r\n\t*%") != std::string::npos)
        return false;
    bool made = false;
    mutate(name, [&](user_state& u, std::string& lines) {
        if (u.folders.count(f))
            return;
        auto x = make_folder(u, f);
        lines += "F " + std::to_string(x->uidvalidity) + " " + f + "\n";
        made = true;
    });
    return made;
}

void imap_store::set_subscribed(const std::string& name, const std::string& folder, bool on)
{
    user(name);
    mutate(name, [&](user_state& u, std::string& lines) {
        if (const auto it = u.folders.find(canonical(folder)); it != u.folders.end() && it->second->subscribed != on)
        {
            it->second->subscribed = on;
            lines += std::string("U ") + (on ? "1 " : "0 ") + it->first + "\n";
        }
    });
}

void imap_store::open(const std::string& name, const std::string& folder,
                      std::function<void(std::shared_ptr<imap_folder>)> done, bool force)
{
    user_state& u = user(name);
    const auto it = u.folders.find(canonical(folder));
    if (it == u.folders.end())
    {
        // A folder a delivery or another client made is in the bucket before this session has listed it.
        folders(name, [this, name, folder, done, force](std::vector<std::string>) {
            if (user(name).folders.count(canonical(folder)))
                open(name, folder, done, force);
            else
                done(nullptr);
        });
        return;
    }
    std::shared_ptr<imap_folder> f = it->second;
    const int64_t now = wall::now_ms_coarse();
    if (!force && now - f->synced_ms < sync_ms)
    {
        done(f);
        return;
    }
    f->waiting.push_back([f, done](bool) { done(f); });
    if (f->syncing)
        return;
    f->syncing = true;
    catch_up(u);
    f->sync_from = f->highestmodseq;
    sync(name, f, {}, {});
}

void imap_store::sync(const std::string& name, const std::shared_ptr<imap_folder>& f, std::string after,
                      std::vector<std::pair<std::string, std::pair<uint64_t, int64_t>>> seen)
{
    mailboxes* boxes = m_run.boxes();
    rpc::request rq;
    rq.kind = rpc::op::list;
    rq.bucket = boxes->bucket();
    rq.prefix = name + "/" + f->name + "/";
    rq.start_after = after;
    auto acc = std::make_shared<decltype(seen)>(std::move(seen));
    boxes->ask(boxes->storage(), rpc::encode(rq),
               [this, name, f, acc, prefix = rq.prefix, alive = m_alive](request_status st, std::string_view bytes) {
                   if (!*alive)
                       return;
                   rpc::reply r;
                   const bool ok = st == request_status::ok && rpc::decode(bytes, rpc::op::list, r) && r.ok;
                   if (ok)
                   {
                       for (const auto& o : r.objects)
                           // A folder's own messages, not a subfolder's.
                           if (o.key.find('/', prefix.size()) == std::string::npos)
                               acc->push_back({o.key, {o.size, o.mtime_ms}});
                       if (r.truncated && !r.objects.empty())
                       {
                           sync(name, f, r.next.empty() ? r.objects.back().key : r.next, std::move(*acc));
                           return;
                       }
                       std::set<std::string> there;
                       for (const auto& [k, v] : *acc)
                           there.insert(k);
                       std::sort(acc->begin(), acc->end());
                       // Under the user's lock, the index read to its end: what another shard gave a UID is known,
                       // and a message logged after the listing began is not expunged for being missing from it.
                       mutate(name, [&](user_state&, std::string& lines) {
                           std::set<std::string> known;
                           std::vector<uint32_t> gone;
                           for (const auto& m : f->msgs)
                           {
                               known.insert(m.key);
                               if (!there.count(m.key) && m.modseq <= f->sync_from)
                                   gone.push_back(m.uid);
                           }
                           for (const uint32_t uid : gone)
                           {
                               const uint64_t ms = ++f->highestmodseq;
                               std::erase_if(f->msgs, [uid](const imap_message& m) { return m.uid == uid; });
                               f->vanished.emplace_back(ms, uid);
                               lines += "X " + std::to_string(uid) + " " + std::to_string(ms) + " " + f->name + "\n";
                           }
                           for (const auto& [k, v] : *acc)
                               if (!known.count(k))
                               {
                                   imap_message m{f->uidnext++, k, v.first, v.second, flags_of_key(k), true,
                                                  ++f->highestmodseq};
                                   lines += "A " + std::to_string(m.uid) + " " + std::to_string(m.flags) + " " +
                                            std::to_string(m.size) + " " + std::to_string(m.date_ms) + " " +
                                            std::to_string(m.modseq) + " " + f->name + "\t" + k + "\n";
                                   f->msgs.push_back(std::move(m));
                               }
                           if (!lines.empty())
                               ++f->version;
                       });
                       f->synced_ms = wall::now_ms_coarse();
                   }
                   f->syncing = false;
                   auto waiting = std::move(f->waiting);
                   f->waiting.clear();
                   for (auto& w : waiting)
                       w(ok);
               });
}

void imap_store::body(const std::string& key, uint64_t size, std::function<void(std::shared_ptr<const std::string>)> done)
{
    if (const auto it = m_cache.find(key); it != m_cache.end() && it->second.bytes)
    {
        ++m_hits;
        it->second.used_ms = wall::now_ms_coarse();
        done(it->second.bytes);
        return;
    }
    auto& waiting = m_reading[key];
    waiting.push_back(std::move(done));
    if (waiting.size() > 1)
        return;
    ++m_gets;
    auto data = std::make_shared<std::string>();
    const auto finish = [this, key](std::shared_ptr<const std::string> b) {
        if (b)
        {
            m_cached += b->size();
            m_cache[key] = {b, nullptr, wall::now_ms_coarse()};
            // The least recently read go first while the cache holds too much.
            while (m_cached > cache_max && m_cache.size() > 1)
            {
                auto oldest = std::min_element(m_cache.begin(), m_cache.end(), [](const auto& a, const auto& b) {
                    return a.second.used_ms < b.second.used_ms;
                });
                m_cached -= oldest->second.bytes ? oldest->second.bytes->size() : 0;
                m_cache.erase(oldest);
            }
        }
        auto ws = std::move(m_reading[key]);
        m_reading.erase(key);
        for (auto& w : ws)
            w(b);
    };
    mailboxes* boxes = m_run.boxes();
    // Whole for a small one; a mebibyte at a time otherwise.
    const auto read_from = [this, boxes, key, size, data, finish, alive = m_alive](auto&& self) -> void {
        rpc::request rq;
        rq.bucket = boxes->bucket();
        rq.key = key;
        const bool ranged = size > rpc::max_value;
        rq.kind = ranged ? rpc::op::get_range : rpc::op::get;
        rq.size = data->size();
        rq.max_keys = static_cast<uint32_t>(rpc::max_value);
        boxes->ask(boxes->storage(), rpc::encode(rq),
                   [self, data, finish, ranged, alive, kind = rq.kind](request_status st, std::string_view bytes) {
                       if (!*alive)
                           return;
                       rpc::reply r;
                       if (st != request_status::ok || !rpc::decode(bytes, kind, r) || !r.ok)
                       {
                           finish(nullptr);
                           return;
                       }
                       data->append(r.data);
                       if (ranged && !r.data.empty() && data->size() < r.info.size)
                       {
                           self(self);
                           return;
                       }
                       finish(std::make_shared<const std::string>(std::move(*data)));
                   });
    };
    read_from(read_from);
}

std::shared_ptr<const mime::part> imap_store::structure(const std::string& key,
                                                         const std::shared_ptr<const std::string>& bytes)
{
    auto& c = m_cache[key];
    if (!c.bytes)
    {
        c.bytes = bytes;
        m_cached += bytes->size();
    }
    if (!c.part)
        c.part = std::make_shared<const mime::part>(mime::parse(*bytes));
    c.used_ms = wall::now_ms_coarse();
    return c.part;
}

void imap_store::delete_object(const std::string& key, std::function<void(bool)> done)
{
    mailboxes* boxes = m_run.boxes();
    rpc::request rq;
    rq.kind = rpc::op::del;
    rq.bucket = boxes->bucket();
    rq.key = key;
    boxes->ask(boxes->storage(), rpc::encode(rq), [done, alive = m_alive](request_status st, std::string_view bytes) {
        if (!*alive)
            return;
        rpc::reply r;
        done(st == request_status::ok && rpc::decode(bytes, rpc::op::del, r) && r.ok);
    });
    if (const auto it = m_cache.find(key); it != m_cache.end())
    {
        m_cached -= it->second.bytes ? it->second.bytes->size() : 0;
        m_cache.erase(it);
    }
}

void imap_store::put_object(std::string key, std::string data, std::function<void(bool)> done)
{
    // A mailbox written by IMAP before any mail came to it has no bucket yet.
    m_run.boxes()->make_bucket([this, key = std::move(key), data = std::move(data), done = std::move(done),
                                alive = m_alive](bool made) mutable {
        if (!*alive)
            return;
        if (!made)
        {
            done(false);
            return;
        }
        put_made(std::move(key), std::move(data), std::move(done));
    });
}

void imap_store::put_made(std::string key, std::string data, std::function<void(bool)> done)
{
    mailboxes* boxes = m_run.boxes();
    if (data.size() <= rpc::max_value)
    {
        rpc::request rq;
        rq.kind = rpc::op::put;
        rq.bucket = boxes->bucket();
        rq.key = std::move(key);
        rq.content_type = "message/rfc822";
        rq.data = std::move(data);
        boxes->ask(boxes->storage(), rpc::encode(rq), [done, alive = m_alive](request_status st, std::string_view b) {
            if (!*alive)
                return;
            rpc::reply r;
            done(st == request_status::ok && rpc::decode(b, rpc::op::put, r) && r.ok);
        });
        return;
    }
    rpc::request rq;
    rq.kind = rpc::op::put_begin;
    rq.bucket = boxes->bucket();
    rq.key = std::move(key);
    rq.content_type = "message/rfc822";
    rq.size = data.size();
    auto all = std::make_shared<std::string>(std::move(data));
    boxes->ask(boxes->storage(), rpc::encode(rq),
               [this, boxes, all, done, alive = m_alive](request_status st, std::string_view b) {
                   if (!*alive)
                       return;
                   rpc::reply r;
                   if (st != request_status::ok || !rpc::decode(b, rpc::op::put_begin, r) || !r.ok)
                   {
                       done(false);
                       return;
                   }
                   const auto piece = [boxes, all, done, stream = r.next, alive](auto&& self, size_t off) -> void {
                       rpc::request m;
                       m.kind = rpc::op::put_more;
                       m.stream = stream;
                       const size_t n = std::min(all->size() - off, rpc::max_value);
                       m.data = all->substr(off, n);
                       m.last = off + n >= all->size();
                       const bool last = m.last;
                       boxes->ask(boxes->storage(), rpc::encode(m),
                                  [self, off, n, last, done, alive](request_status st, std::string_view b) {
                                      if (!*alive)
                                          return;
                                      rpc::reply rr;
                                      if (st != request_status::ok || !rpc::decode(b, rpc::op::put_more, rr) || !rr.ok)
                                      {
                                          done(false);
                                          return;
                                      }
                                      if (last)
                                          done(true);
                                      else
                                          self(self, off + n);
                                  });
                   };
                   piece(piece, 0);
               });
}

uint32_t imap_store::add_message(const std::string& name, const std::shared_ptr<imap_folder>& f, const std::string& key,
                                 uint64_t size, int64_t date_ms, uint8_t flags)
{
    uint32_t uid = 0;
    mutate(name, [&](user_state&, std::string& lines) {
        // A shard that listed the bucket while the object was on its way has given it a UID already.
        for (auto it = f->msgs.rbegin(); it != f->msgs.rend(); ++it)
            if (it->key == key)
            {
                uid = it->uid;
                return;
            }
        imap_message m{f->uidnext++, key, size, date_ms, flags, true, ++f->highestmodseq};
        uid = m.uid;
        lines += "A " + std::to_string(m.uid) + " " + std::to_string(m.flags) + " " + std::to_string(m.size) + " " +
                 std::to_string(m.date_ms) + " " + std::to_string(m.modseq) + " " + f->name + "\t" + key + "\n";
        f->msgs.push_back(std::move(m));
        ++f->version;
    });
    return uid;
}

void imap_store::expunge(const std::string& name, const std::shared_ptr<imap_folder>& f,
                         const std::vector<uint32_t>& only, bool any, std::function<void(std::vector<uint32_t>)> done)
{
    refresh(name);
    std::vector<std::pair<uint32_t, std::string>> going;
    for (const auto& m : f->msgs)
        if ((any || (m.flags & flag_deleted)) &&
            (only.empty() || std::find(only.begin(), only.end(), m.uid) != only.end()))
            going.emplace_back(m.uid, m.key);
    if (going.empty())
    {
        done({});
        return;
    }
    auto left = std::make_shared<size_t>(going.size());
    auto gone = std::make_shared<std::vector<uint32_t>>();
    for (const auto& [uid, key] : going)
        delete_object(key, [this, name, f, uid, left, gone, done](bool ok) {
            if (ok)
                gone->push_back(uid);
            if (--*left)
                return;
            std::sort(gone->begin(), gone->end());
            mutate(name, [&](user_state&, std::string& lines) {
                for (const uint32_t g : *gone)
                    if (f->by_uid(g))
                    {
                        const uint64_t ms = ++f->highestmodseq;
                        std::erase_if(f->msgs, [g](const imap_message& m) { return m.uid == g; });
                        f->vanished.emplace_back(ms, g);
                        lines += "X " + std::to_string(g) + " " + std::to_string(ms) + " " + f->name + "\n";
                    }
                ++f->version;
            });
            done(std::move(*gone));
        });
}

void imap_store::copy(const std::string& name, const std::shared_ptr<imap_folder>& from,
                      const std::vector<uint32_t>& uids, const std::string& to,
                      std::function<void(bool, uint32_t, std::vector<uint32_t>)> done)
{
    user_state& u = user(name);
    const auto it = u.folders.find(canonical(to));
    if (it == u.folders.end())
    {
        done(false, 0, {});
        return;
    }
    std::shared_ptr<imap_folder> dest = it->second;
    struct job
    {
        std::vector<imap_message> todo;
        std::vector<uint32_t> made;
        size_t at{0};
        bool ok{true};
    };
    auto j = std::make_shared<job>();
    for (const uint32_t uid : uids)
        if (const imap_message* m = from->by_uid(uid))
            j->todo.push_back(*m);
    // One after the other, so the UIDs answered are in the order asked.
    auto next = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> weak = next;
    *next = [this, name, dest, j, done, weak]() {
        auto self = weak.lock();
        if (!self)
            return;
        if (j->at >= j->todo.size() || !j->ok)
        {
            done(j->ok, dest->uidvalidity, j->made);
            return;
        }
        const imap_message m = j->todo[j->at++];
        body(m.key, m.size, [this, name, dest, j, m, self](std::shared_ptr<const std::string> b) {
            if (!b)
            {
                j->ok = false;
                (*self)();
                return;
            }
            const std::string key = name + "/" + dest->name + "/" + new_spool_id(0) + ".eml";
            put_object(key, *b, [this, name, dest, j, m, key, self](bool ok) {
                if (!ok)
                {
                    j->ok = false;
                    (*self)();
                    return;
                }
                const uint32_t uid = add_message(name, dest, key, m.size, m.date_ms,
                                                 static_cast<uint8_t>(m.flags & ~flag_deleted));
                j->made.push_back(uid);
                (*self)();
            });
        });
    };
    // Kept alive by the job's own callbacks until the last answers.
    auto keep = next;
    (*keep)();
}

void imap_store::append(const std::string& name, const std::string& folder, std::string message, uint8_t flags,
                        int64_t date_ms, std::function<void(bool, uint32_t, uint32_t)> done)
{
    user_state& u = user(name);
    const auto it = u.folders.find(canonical(folder));
    if (it == u.folders.end())
    {
        done(false, 0, 0);
        return;
    }
    std::shared_ptr<imap_folder> f = it->second;
    const std::string key = name + "/" + f->name + "/" + new_spool_id(0) + ".eml";
    const uint64_t size = message.size();
    if (const uint64_t q = quota(name); q && usage(name) + size > q)
    {
        done(false, 0, 0);
        return;
    }
    put_object(key, std::move(message), [this, name, f, key, size, flags, date_ms, done](bool ok) {
        if (!ok)
        {
            done(false, 0, 0);
            return;
        }
        const uint32_t uid = add_message(name, f, key, size, date_ms, flags);
        done(true, f->uidvalidity, uid);
    });
}

void imap_store::remove(const std::string& name, const std::string& folder, std::function<void(bool)> done)
{
    user_state& u = user(name);
    const std::string fname = canonical(folder);
    const auto it = u.folders.find(fname);
    if (it == u.folders.end() || fname == "INBOX")
    {
        done(false);
        return;
    }
    open(name, fname, [this, name, fname, done](std::shared_ptr<imap_folder> f) {
        if (!f)
        {
            done(false);
            return;
        }
        empty_out(name, f, fname, {}, 4, done);
    }, true);
}

void imap_store::rename(const std::string& name, const std::string& from, const std::string& to,
                        std::function<void(bool)> done)
{
    const std::string a = canonical(from), b = canonical(to);
    if (a == "INBOX" || !create(name, b))
    {
        done(false);
        return;
    }
    open(name, a, [this, name, a, b, done](std::shared_ptr<imap_folder> f) {
        if (!f)
        {
            done(false);
            return;
        }
        empty_out(name, f, a, b, 4, done);
    }, true);
}

void imap_store::empty_out(const std::string& name, const std::shared_ptr<imap_folder>& f, const std::string& fname,
                           const std::string& to, int passes, std::function<void(bool)> done)
{
    refresh(name);
    std::vector<uint32_t> uids;
    for (const auto& m : f->msgs)
        uids.push_back(m.uid);
    if (uids.empty() || passes == 0)
    {
        bool gone = false;
        mutate(name, [&](user_state& u, std::string& lines) {
            // A message that came in while the last pass ran keeps the folder.
            if (!f->msgs.empty())
                return;
            if (u.folders.erase(fname))
                lines += "D " + fname + "\n";
            gone = true;
        });
        done(gone);
        return;
    }
    const auto expunge_them = [this, name, f, fname, to, passes, done, uids] {
        expunge(name, f, uids, true, [this, name, f, fname, to, passes, done](std::vector<uint32_t>) {
            empty_out(name, f, fname, to, passes - 1, done);
        });
    };
    if (to.empty())
    {
        expunge_them();
        return;
    }
    copy(name, f, uids, to, [expunge_them, done](bool ok, uint32_t, std::vector<uint32_t>) {
        if (ok)
            expunge_them();
        else
            done(false);
    });
}

}   // namespace socketley::mail
