#include "imap_store.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <set>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mail_compose.h"
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

bool keyword_change::apply(std::vector<std::string>& have) const
{
    using socketley::ascii::iequals;
    const auto has = [](const std::vector<std::string>& v, const std::string& w) {
        return std::any_of(v.begin(), v.end(), [&](const std::string& x) { return iequals(x, w); });
    };
    std::vector<std::string> next;
    switch (k)
    {
        case kind::none:
            return false;
        case kind::set:
            for (const auto& w : words)
                if (!has(next, w))
                    next.push_back(w);
            break;
        case kind::add:
            next = have;
            for (const auto& w : words)
                if (!has(next, w))
                    next.push_back(w);
            break;
        case kind::remove:
            for (const auto& w : have)
                if (!has(words, w))
                    next.push_back(w);
            break;
    }
    // A message holds a few keywords, not what a client could pile on it.
    if (next.size() > 64)
        next.resize(64);
    const bool changed = next.size() != have.size() ||
                         !std::equal(next.begin(), next.end(), have.begin(),
                                     [](const std::string& a, const std::string& b) { return iequals(a, b); });
    have = std::move(next);
    return changed;
}

std::string imap_store::path_of(const std::string& user) const
{
    // Each byte past letters, digits and a few marks is written %XX, so two names never share one file.
    std::string safe;
    static const char* hex = "0123456789ABCDEF";
    for (const char c : user)
    {
        const auto b = static_cast<unsigned char>(c);
        if (std::isalnum(b) || c == '.' || c == '-' || c == '_' || c == '@')
            safe += c;
        else
        {
            safe += '%';
            safe += hex[b >> 4];
            safe += hex[b & 15];
        }
    }
    if (safe.empty() || safe.front() == '.')
        safe.insert(0, "%");
    return (socketley_paths::resolve().state_dir / "mail" / (std::string(m_run.owner().get_name()) + ".imap") / safe)
        .string();
}

std::shared_ptr<imap_folder> imap_store::make_folder(user_state& u, const std::string& name)
{
    auto f = std::make_shared<imap_folder>();
    f->name = name;
    // Later than any this user's folders had, so a folder made again in the same second is told apart (RFC 3501 2.3.1.1).
    uint32_t v = static_cast<uint32_t>(wall::now_ms() / 1000);
    for (const auto& [n, x] : u.folders)
        v = std::max(v, x->uidvalidity + 1);
    f->uidvalidity = std::max(v, u.last_validity + 1);
    u.last_validity = f->uidvalidity;
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
    // Folders with messages marked expunged, their size set to what no message has, swept once the text is read.
    std::vector<imap_folder*> swept;
    const auto sweep = [&swept] {
        std::sort(swept.begin(), swept.end());
        swept.erase(std::unique(swept.begin(), swept.end()), swept.end());
        for (imap_folder* f : swept)
        {
            std::erase_if(f->msgs, [](const imap_message& m) { return m.size == UINT64_MAX; });
            if (f->gone_keys.size() > 20000)
                f->gone_keys.erase(f->gone_keys.begin(), f->gone_keys.begin() + 10000);
        }
        swept.clear();
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
                if (const auto it = u.folders.find(std::string(l)); it != u.folders.end())
                {
                    std::erase(swept, it->second.get());
                    for (const auto& m : it->second->msgs)
                        if (m.size != UINT64_MAX)
                            u.used -= std::min(u.used, m.size);
                    u.last_validity = std::max(u.last_validity, it->second->uidvalidity);
                    u.folders.erase(it);
                }
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
                const uint64_t size = m.size;
                if (f->msgs.empty() || f->msgs.back().uid < m.uid)
                {
                    f->msgs.push_back(std::move(m));
                    u.used += size;
                }
                else if (!f->by_uid(m.uid))
                {
                    const auto at = std::lower_bound(f->msgs.begin(), f->msgs.end(), m.uid,
                                                     [](const imap_message& x, uint32_t uid) { return x.uid < uid; });
                    f->msgs.insert(at, std::move(m));
                    u.used += size;
                }
                ++f->version;
                break;
            }
            case 'K':
            {
                // K <uid> <modseq> <folder>\t<keyword> ...: a message's keywords as they are now.
                const auto w = words(l, 2);
                const size_t tab = l.find('\t');
                imap_folder* f = tab == std::string_view::npos ? nullptr : folder(l.substr(0, tab));
                if (!f)
                    break;
                if (imap_message* m = f->by_uid(static_cast<uint32_t>(num(w[0]))))
                {
                    m->keywords.clear();
                    std::string_view kws = l.substr(tab + 1);
                    while (!kws.empty())
                        if (const std::string_view one = socketley::take_item(kws, ' '); !one.empty())
                            m->keywords.emplace_back(one);
                    m->modseq = std::max<uint64_t>(m->modseq, num(w[1]));
                }
                f->highestmodseq = std::max<uint64_t>(f->highestmodseq, num(w[1]));
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
                    // Taken out together at the end, one pass for however many went.
                    if (imap_message* m = f->by_uid(uid); m && m->size != UINT64_MAX)
                    {
                        u.used -= std::min(u.used, m->size);
                        f->gone_keys.emplace_back(modseq, m->key);
                        m->size = UINT64_MAX;
                        swept.push_back(f);
                    }
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
    sweep();
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
            else if (line[0] == 'W' && f && !f->msgs.empty())
            {
                // W <keyword> ...: the keywords of the message on the line before.
                std::string_view kws = line.substr(2);
                while (!kws.empty())
                    if (const std::string_view one = socketley::take_item(kws, ' '); !one.empty())
                        f->msgs.back().keywords.emplace_back(one);
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
    u.used = 0;
    for (const auto& [n, f] : u.folders)
    {
        u.last_validity = std::max(u.last_validity, f->uidvalidity);
        for (const auto& m : f->msgs)
            u.used += m.size;
    }
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
    // The lines another shard appended, up to the last whole one, read from the file the stat saw: a compaction that
    // moved a new journal into place since is read whole instead.
    const int fd = ::open(log.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return;
    if (struct stat now{}; ::fstat(fd, &now) != 0 || now.st_ino != u.log_ino)
    {
        ::close(fd);
        reload(u);
        return;
    }
    else
        st.st_size = std::max(st.st_size, now.st_size);
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

bool imap_store::mutate(const std::string& name, const std::function<void(user_state&, std::string& lines)>& change)
{
    user_state& u = m_users[name];
    if (u.base.empty())
        u.base = path_of(name);
    const std::string& base = u.base;
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(base).parent_path(), ec);
    // Held only for a read of what is new and an append: no shard waits on another's disk.
    const int lock = u.locked ? -1 : ::open((base + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    // A change made without the lock could give a UID another shard gives too: none is made.
    if (!u.locked && (lock < 0 || ::flock(lock, LOCK_EX) != 0))
    {
        if (lock >= 0)
            ::close(lock);
        LOG_WARN(("mail: the IMAP index lock of " + name + " could not be taken: " + std::strerror(errno)).c_str());
        return false;
    }
    const bool outer = !u.locked;
    bool written = true;
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
            {
                // A line cut short would join the next one: what was written of it is taken back.
                if (::ftruncate(fd, st.st_size) != 0) {}
                written = false;
                LOG_WARN(("mail: the IMAP journal " + log + " could not be written").c_str());
            }
        }
        else
            written = false;
        if (fd >= 0)
            ::close(fd);
    }
    // A change the journal did not take is undone, memory read back as the disk has it.
    if (!written)
        reload(u);
    if (outer)
        u.locked = false;
    if (lock >= 0)
        ::close(lock);
    return written;
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
        {
            text += "M " + std::to_string(m.uid) + " " + std::to_string(m.flags) + " " + std::to_string(m.size) + " " +
                    std::to_string(m.date_ms) + " " + std::to_string(m.modseq) + " " + m.key + "\n";
            if (!m.keywords.empty())
            {
                text += "W";
                for (const auto& k : m.keywords)
                    text += " " + k;
                text += "\n";
            }
        }
    }
    // 0 where the files could not be written, 1 where they moved in, 2 where a line came since the snapshot was built.
    auto done = std::make_shared<int>(0);
    m_run.pool().submit(
        0,
        [base = u.base, text = std::move(text), gen, expect = u.log_off, ino = u.log_ino, done] {
            // The files are written and synced first, the lock held only to see nothing came and move them in, so a
            // shard waiting on it waits for two renames rather than for the disk.
            // Named by the process, as two shards may fold the journal at once and the loser's files must not be the
            // winner's.
            const std::string pid = std::to_string(::getpid());
            const std::string snap_tmp = base + ".new." + pid, log_tmp = base + ".log.new." + pid;
            const std::string empty = "SKLIMAPLOG " + std::to_string(gen) + "\n";
            const auto write_synced = [](const std::string& path, const std::string& bytes) {
                const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
                const bool ok = fd >= 0 && socketley::write_all(fd, bytes.data(), bytes.size()) && ::fdatasync(fd) == 0;
                if (fd >= 0)
                    ::close(fd);
                return ok;
            };
            if (!write_synced(snap_tmp, text) || !write_synced(log_tmp, empty))
            {
                ::unlink(snap_tmp.c_str());
                ::unlink(log_tmp.c_str());
                return;
            }
            const int lock = ::open((base + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
            if (lock < 0 || ::flock(lock, LOCK_EX) != 0)
            {
                if (lock >= 0)
                    ::close(lock);
                ::unlink(snap_tmp.c_str());
                ::unlink(log_tmp.c_str());
                return;
            }
            struct stat st{};
            // The snapshot moves in first, the old one kept until the journal follows, and put back if it cannot.
            const std::string prev = base + ".prev." + pid;
            ::unlink(prev.c_str());
            const bool had = ::link(base.c_str(), prev.c_str()) == 0;
            if (::stat((base + ".log").c_str(), &st) == 0 && (st.st_ino != ino || static_cast<uint64_t>(st.st_size) != expect))
                *done = 2;
            else if (::rename(snap_tmp.c_str(), base.c_str()) == 0)
            {
                if (::rename(log_tmp.c_str(), (base + ".log").c_str()) == 0)
                    *done = 1;
                else if (had && ::rename(prev.c_str(), base.c_str()) != 0) {}
            }
            ::close(lock);
            ::unlink(snap_tmp.c_str());
            ::unlink(log_tmp.c_str());
            ::unlink(prev.c_str());
            const std::string dir = std::filesystem::path(base).parent_path().string();
            if (const int d = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC); d >= 0)
            {
                if (::fsync(d) != 0) {}
                ::close(d);
            }
        },
        [this, name, done, alive = m_alive] {
            if (!*alive)
                return;
            const auto it = m_users.find(name);
            if (it == m_users.end())
                return;
            user_state& us = it->second;
            us.compacting = false;
            // The new journal is another file, which the next refresh reads from its start; a fold that lost to new
            // lines is tried again once they stop or the journal grew by a quarter, one that failed only on the latter.
            if (*done == 1)
            {
                us.compact_quiet = UINT64_MAX;
                reload(us);
            }
            else
            {
                catch_up(us);
                us.compact_after = us.log_off + us.log_off / 4;
                us.compact_quiet = *done == 2 ? us.log_off : UINT64_MAX;
            }
        });
}

size_t imap_store::set_flags(const std::string& name, const std::shared_ptr<imap_folder>& f,
                             const std::vector<uint32_t>& uids, const std::function<uint8_t(uint8_t)>& change,
                             const keyword_change& words)
{
    size_t changed = 0;
    if (!mutate(name, [&](user_state&, std::string& lines) {
            for (const uint32_t uid : uids)
                if (imap_message* m = f->by_uid(uid))
                {
                    const uint8_t now = change(m->flags);
                    std::vector<std::string> kws = m->keywords;
                    const bool kw = words.apply(kws);
                    if (now == m->flags && !kw)
                        continue;
                    ++changed;
                    m->flags = now;
                    m->modseq = ++f->highestmodseq;
                    lines += "S " + std::to_string(uid) + " " + std::to_string(now) + " " +
                             std::to_string(m->modseq) + " " + f->name + "\n";
                    if (kw)
                    {
                        m->keywords = std::move(kws);
                        lines += "K " + std::to_string(uid) + " " + std::to_string(m->modseq) + " " + f->name + "\t";
                        for (size_t i = 0; i < m->keywords.size(); ++i)
                            lines += (i ? " " : "") + m->keywords[i];
                        lines += "\n";
                    }
                }
            if (!lines.empty())
                ++f->version;
        }))
        return 0;
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
        const bool settled = u.log_off == u.compact_quiet;
        if (u.compact_quiet != UINT64_MAX)
            u.compact_quiet = u.log_off;
        if (!u.compacting && u.log_off > (256u << 10) && u.log_off > u.snapshot_bytes &&
            (u.log_off >= u.compact_after || settled))
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
    return u.used + u.reserved;
}

bool imap_store::reserve(const std::string& name, uint64_t bytes)
{
    const uint64_t q = quota(name);
    if (q && usage(name) + bytes > q)
        return false;
    user(name).reserved += bytes;
    return true;
}

void imap_store::unreserve(const std::string& name, uint64_t bytes)
{
    user_state& u = user(name);
    u.reserved -= std::min(u.reserved, bytes);
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
    // Each superior name is made with it (RFC 3501 6.3.3), and no level of the name is empty or a path's dots.
    std::vector<std::string> levels;
    for (size_t at = 0;;)
    {
        const size_t slash = f.find('/', at);
        const std::string_view part = std::string_view(f).substr(at, slash == std::string::npos ? std::string::npos : slash - at);
        if (part.empty() || part == "." || part == "..")
            return false;
        levels.push_back(f.substr(0, slash));
        if (slash == std::string::npos)
            break;
        at = slash + 1;
    }
    bool made = false;
    mutate(name, [&](user_state& u, std::string& lines) {
        if (u.folders.count(f))
            return;
        for (const auto& level : levels)
            if (!u.folders.count(level))
            {
                auto x = make_folder(u, level);
                lines += "F " + std::to_string(x->uidvalidity) + " " + level + "\n";
            }
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
                      std::function<void(std::shared_ptr<imap_folder>)> done, bool force, int64_t max_age_ms)
{
    user_state& u = user(name);
    const auto it = u.folders.find(canonical(folder));
    if (it == u.folders.end())
    {
        // A folder a delivery or another client made is in the bucket before this session has listed it.
        folders(name, [this, name, folder, done, force, max_age_ms](std::vector<std::string>) {
            if (user(name).folders.count(canonical(folder)))
                open(name, folder, done, force, max_age_ms);
            else
                done(nullptr);
        });
        return;
    }
    std::shared_ptr<imap_folder> f = it->second;
    const int64_t now = wall::now_ms_coarse();
    if (!force && now - f->synced_ms < std::max(sync_ms, max_age_ms))
    {
        // What another shard or a delivery logged is read in, even where the bucket is not listed again.
        catch_up(u);
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
                       mutate(name, [&](user_state& u, std::string& lines) {
                           std::set<std::string> known;
                           // A key expunged since the listing began is still in it, and is not brought back.
                           for (const auto& [ms, k] : f->gone_keys)
                               if (ms > f->sync_from)
                                   known.insert(k);
                           for (auto& m : f->msgs)
                           {
                               known.insert(m.key);
                               if (!there.count(m.key) && m.modseq <= f->sync_from)
                               {
                                   const uint64_t ms = ++f->highestmodseq;
                                   u.used -= std::min(u.used, m.size);
                                   f->gone_keys.emplace_back(ms, m.key);
                                   f->vanished.emplace_back(ms, m.uid);
                                   lines += "X " + std::to_string(m.uid) + " " + std::to_string(ms) + " " + f->name +
                                            "\n";
                                   m.size = UINT64_MAX;
                               }
                           }
                           std::erase_if(f->msgs, [](const imap_message& m) { return m.size == UINT64_MAX; });
                           // An object younger than a minute is its writer's to log, which a delivery, APPEND and
                           // COPY do at once; one it never logged is taken up by a later listing.
                           const int64_t young = wall::now_ms_coarse() - 60000;
                           for (const auto& [k, v] : *acc)
                               if (!known.count(k) && v.second < young)
                               {
                                   imap_message m{f->uidnext++, k, v.first, v.second, flags_of_key(k), true,
                                                  ++f->highestmodseq, {}};
                                   lines += "A " + std::to_string(m.uid) + " " + std::to_string(m.flags) + " " +
                                            std::to_string(m.size) + " " + std::to_string(m.date_ms) + " " +
                                            std::to_string(m.modseq) + " " + f->name + "\t" + k + "\n";
                                   u.used += m.size;
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

imap_store::cached& imap_store::touch(const std::string& key)
{
    const auto [it, made] = m_cache.try_emplace(key);
    if (made)
    {
        m_lru.push_front(key);
        it->second.lru = m_lru.begin();
    }
    else
        m_lru.splice(m_lru.begin(), m_lru, it->second.lru);
    return it->second;
}

void imap_store::evict()
{
    // The least recently read go first while the cache holds too much, each in O(1).
    while (m_cached > cache_max && m_cache.size() > 1)
    {
        const auto it = m_cache.find(m_lru.back());
        if (it != m_cache.end())
        {
            m_cached -= std::min(m_cached, it->second.counted);
            m_cache.erase(it);
        }
        m_lru.pop_back();
    }
}

void imap_store::body(const std::string& key, uint64_t size, std::function<void(std::shared_ptr<const std::string>)> done,
                      bool keep)
{
    if (const auto it = m_cache.find(key); it != m_cache.end() && it->second.bytes)
    {
        ++m_hits;
        done(touch(key).bytes);
        return;
    }
    auto& waiting = m_reading[key];
    waiting.push_back(std::move(done));
    if (waiting.size() > 1)
        return;
    ++m_gets;
    auto data = std::make_shared<std::string>();
    const auto finish = [this, key, keep](std::shared_ptr<const std::string> b) {
        if (b && keep)
        {
            cached& c = touch(key);
            c.bytes = b;
            recount(c);
            evict();
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
                       if (data->empty() && !ranged)
                           *data = std::move(r.data);
                       else
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

void imap_store::head(const std::string& key, uint64_t size, std::function<void(std::shared_ptr<const std::string>)> done)
{
    // A message whose bytes are here already gives its header from them.
    if (const auto it = m_cache.find(key); it != m_cache.end() && it->second.bytes)
    {
        ++m_hits;
        const auto b = touch(key).bytes;
        done(std::make_shared<const std::string>(header_block(*b)));
        return;
    }
    if (const auto it = m_heads.find(key); it != m_heads.end())
    {
        ++m_hits;
        done(it->second);
        return;
    }
    // A small one is read whole, as its header would be most of it.
    constexpr uint32_t first = 16u << 10;
    if (size <= 2 * first)
    {
        body(key, size, [done](std::shared_ptr<const std::string> b) {
            done(b ? std::make_shared<const std::string>(header_block(*b)) : nullptr);
        });
        return;
    }
    // A header asked for again while it is read, as a prefetch and then the FETCH do, is read once.
    auto& waiting = m_head_reading[key];
    waiting.push_back(std::move(done));
    if (waiting.size() > 1)
        return;
    const auto give = [this, key](std::shared_ptr<const std::string> h) {
        auto ws = std::move(m_head_reading[key]);
        m_head_reading.erase(key);
        for (auto& w : ws)
            w(h);
    };
    ++m_gets;
    mailboxes* boxes = m_run.boxes();
    rpc::request rq;
    rq.kind = rpc::op::get_range;
    rq.bucket = boxes->bucket();
    rq.key = key;
    rq.size = 0;
    rq.max_keys = first;
    boxes->ask(boxes->storage(), rpc::encode(rq),
               [this, key, size, give, alive = m_alive](request_status st, std::string_view bytes) {
                   if (!*alive)
                       return;
                   rpc::reply r;
                   if (st != request_status::ok || !rpc::decode(bytes, rpc::op::get_range, r) || !r.ok)
                   {
                       give(nullptr);
                       return;
                   }
                   // A header longer than the first read is read with the rest of the message.
                   const std::string_view block = header_block(r.data);
                   if (block.size() >= r.data.size())
                   {
                       body(key, size, [give](std::shared_ptr<const std::string> b) {
                           give(b ? std::make_shared<const std::string>(header_block(*b)) : nullptr);
                       });
                       return;
                   }
                   auto h = std::make_shared<const std::string>(block);
                   if (m_heads_bytes > (16u << 20))
                   {
                       m_heads.clear();
                       m_heads_bytes = 0;
                   }
                   m_heads_bytes += h->size();
                   m_heads[key] = h;
                   give(h);
               });
}

std::shared_ptr<const mime::part> imap_store::structure(const std::string& key,
                                                         const std::shared_ptr<const std::string>& bytes)
{
    cached& c = touch(key);
    if (c.part && c.bytes)
        return c.part;
    if (!c.bytes)
        c.bytes = bytes;
    if (!c.part)
        c.part = std::make_shared<const mime::part>(mime::parse(*bytes));
    recount(c);
    auto part = c.part;
    evict();
    return part;
}

bool imap_store::parse_later(const std::string& key, const std::shared_ptr<const std::string>& bytes,
                             std::function<void()> done)
{
    // Measured at 3 to 13 ms for 25 MiB, which is the loop's to spend on nothing else.
    if (bytes->size() <= (1u << 20))
        return false;
    if (const auto it = m_cache.find(key); it != m_cache.end() && it->second.part)
        return false;
    auto part = std::make_shared<std::shared_ptr<const mime::part>>();
    m_run.pool().submit(
        0, [bytes, part] { *part = std::make_shared<const mime::part>(mime::parse(*bytes)); },
        [this, key, bytes, part, done = std::move(done), alive = m_alive] {
            if (!*alive)
                return;
            cached& c = touch(key);
            if (!c.bytes)
                c.bytes = bytes;
            c.part = *part;
            recount(c);
            evict();
            done();
        });
    return true;
}

void imap_store::recount(cached& c)
{
    // A part is taken at its size and a few short strings, which is what most of them hold.
    const auto parts = [](const auto& self, const mime::part& p) -> size_t {
        size_t n = 1;
        for (const auto& child : p.children)
            n += self(self, child);
        return n;
    };
    m_cached -= std::min(m_cached, c.counted);
    c.counted = (c.bytes ? c.bytes->size() : 0) + (c.part ? parts(parts, *c.part) * (sizeof(mime::part) + 128) : 0);
    m_cached += c.counted;
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
        m_cached -= std::min(m_cached, it->second.counted);
        m_lru.erase(it->second.lru);
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
                                 uint64_t size, int64_t date_ms, uint8_t flags, const std::vector<std::string>& keywords)
{
    const auto uids = add_messages(name, f, {imap_message{0, key, size, date_ms, flags, true, 0, keywords}});
    return uids.empty() ? 0 : uids.front();
}

std::vector<uint32_t> imap_store::add_messages(const std::string& name, const std::shared_ptr<imap_folder>& f,
                                               const std::vector<imap_message>& ms)
{
    std::vector<uint32_t> uids;
    if (!mutate(name, [&](user_state& u, std::string& lines) {
        // A folder deleted while the messages were written is not given them.
        if (const auto it = u.folders.find(f->name); it == u.folders.end() || it->second != f)
            return;
        for (const auto& in : ms)
        {
            // A listing that took the object up first, its writer slower than a minute, gave it a UID among the last.
            uint32_t uid = 0;
            size_t looked = 0;
            for (auto it = f->msgs.rbegin(); it != f->msgs.rend() && looked++ < 256; ++it)
                if (it->key == in.key)
                {
                    uid = it->uid;
                    break;
                }
            if (uid == 0)
            {
                imap_message m{f->uidnext++, in.key, in.size, in.date_ms, in.flags, true, ++f->highestmodseq, in.keywords};
                uid = m.uid;
                lines += "A " + std::to_string(m.uid) + " " + std::to_string(m.flags) + " " + std::to_string(m.size) +
                         " " + std::to_string(m.date_ms) + " " + std::to_string(m.modseq) + " " + f->name + "\t" +
                         m.key + "\n";
                if (!m.keywords.empty())
                {
                    lines += "K " + std::to_string(m.uid) + " " + std::to_string(m.modseq) + " " + f->name + "\t";
                    for (size_t i = 0; i < m.keywords.size(); ++i)
                        lines += (i ? " " : "") + m.keywords[i];
                    lines += "\n";
                }
                u.used += m.size;
                f->msgs.push_back(std::move(m));
            }
            uids.push_back(uid);
        }
        ++f->version;
    }))
        return {};
    return uids;
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
            mutate(name, [&](user_state& u, std::string& lines) {
                for (const uint32_t g : *gone)
                    if (imap_message* m = f->by_uid(g); m && m->size != UINT64_MAX)
                    {
                        const uint64_t ms = ++f->highestmodseq;
                        u.used -= std::min(u.used, m->size);
                        f->gone_keys.emplace_back(ms, m->key);
                        m->size = UINT64_MAX;
                        f->vanished.emplace_back(ms, g);
                        lines += "X " + std::to_string(g) + " " + std::to_string(ms) + " " + f->name + "\n";
                    }
                // One pass takes out however many went.
                std::erase_if(f->msgs, [](const imap_message& m) { return m.size == UINT64_MAX; });
                ++f->version;
            });
            done(std::move(*gone));
        });
}

void imap_store::copy(const std::string& name, const std::shared_ptr<imap_folder>& from,
                      const std::vector<uint32_t>& uids, const std::string& to, bool counts,
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
        // Each copy's new key, and whether it is 0 on its way, 1 written or 2 failed.
        std::vector<std::string> keys;
        std::vector<uint8_t> state;
        std::vector<uint32_t> made;
        size_t started{0}, logged{0}, running{0};
        uint64_t running_bytes{0};
        bool ok{true}, finished{false};
        uint64_t reserved{0};
    };
    auto j = std::make_shared<job>();
    for (const uint32_t uid : uids)
        if (const imap_message* m = from->by_uid(uid))
        {
            j->todo.push_back(*m);
            j->reserved += m->size;
        }
    // The room the copies take is held while they are made, so two COPYs cannot pass the quota together.
    if (!counts)
        j->reserved = 0;
    if (!reserve(name, j->reserved))
    {
        done(false, dest->uidvalidity, {});
        return;
    }
    // Up to 32 and 16 MiB read and written at once, logged in the order asked as they are in, so the UIDs answered keep that order.
    j->keys.resize(j->todo.size());
    j->state.assign(j->todo.size(), 0);
    auto next = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> weak = next;
    *next = [this, name, dest, j, done, weak]() {
        auto self = weak.lock();
        if (!self || j->finished)
            return;
        std::vector<imap_message> batch;
        for (; j->ok && j->logged + batch.size() < j->todo.size() && j->state[j->logged + batch.size()] != 0;)
        {
            const size_t i = j->logged + batch.size();
            if (j->state[i] == 2)
            {
                j->ok = false;
                break;
            }
            imap_message m = j->todo[i];
            m.key = j->keys[i];
            m.flags = static_cast<uint8_t>(m.flags & ~flag_deleted);
            batch.push_back(std::move(m));
        }
        if (!batch.empty())
        {
            const auto uids = add_messages(name, dest, batch);
            if (uids.size() != batch.size())
                j->ok = false;
            else
            {
                j->made.insert(j->made.end(), uids.begin(), uids.end());
                j->logged += batch.size();
            }
        }
        if (j->ok && j->logged == j->todo.size())
        {
            j->finished = true;
            unreserve(name, j->reserved);
            done(true, dest->uidvalidity, j->made);
            return;
        }
        if (!j->ok)
        {
            if (j->running > 0)
                return;
            // A COPY that failed midway takes back what it wrote, so it is all or nothing (RFC 3501 6.4.7).
            j->finished = true;
            unreserve(name, j->reserved);
            for (size_t i = j->logged; i < j->todo.size(); ++i)
                if (j->state[i] == 1)
                    delete_object(j->keys[i], [](bool) {});
            if (j->made.empty())
            {
                done(false, dest->uidvalidity, {});
                return;
            }
            expunge(name, dest, j->made, true, [done, dest](std::vector<uint32_t>) { done(false, dest->uidvalidity, {}); });
            return;
        }
        for (; j->ok && j->running < 32 && (j->running == 0 || j->running_bytes < (16u << 20)) &&
               j->started < j->todo.size();
             ++j->started)
        {
            const size_t i = j->started;
            const imap_message& m = j->todo[i];
            ++j->running;
            j->running_bytes += m.size;
            // A copy's source is read past the cache, so a large COPY does not push out what clients read.
            body(m.key, m.size, [this, name, dest, j, i, self](std::shared_ptr<const std::string> b) {
                if (!b)
                {
                    --j->running;
                    j->running_bytes -= j->todo[i].size;
                    j->state[i] = 2;
                    j->ok = false;
                    (*self)();
                    return;
                }
                j->keys[i] = name + "/" + dest->name + "/" + new_spool_id(0) + ".eml";
                put_object(j->keys[i], *b, [j, i, self](bool ok) {
                    --j->running;
                    j->running_bytes -= j->todo[i].size;
                    j->state[i] = ok ? 1 : 2;
                    j->ok = j->ok && ok;
                    (*self)();
                });
            }, false);
        }
    };
    // Kept alive by the job's own callbacks until the last answers.
    auto keep = next;
    (*keep)();
}

void imap_store::delivered(const std::string& name, const std::string& folder, const std::string& key, uint64_t size,
                           int64_t date_ms)
{
    user_state& u = user(name);
    const std::string fname = canonical(folder);
    if (!u.folders.count(fname) && !create(name, fname))
        return;
    const auto it = u.folders.find(fname);
    if (it != u.folders.end())
        add_message(name, it->second, key, size, date_ms, flags_of_key(key));
}

void imap_store::append(const std::string& name, const std::string& folder, std::string message, uint8_t flags,
                        std::vector<std::string> keywords, int64_t date_ms,
                        std::function<void(refusal, uint32_t, uint32_t)> done)
{
    user_state& u = user(name);
    const auto it = u.folders.find(canonical(folder));
    if (it == u.folders.end())
    {
        done(refusal::no_folder, 0, 0);
        return;
    }
    std::shared_ptr<imap_folder> f = it->second;
    const std::string key = name + "/" + f->name + "/" + new_spool_id(0) + ".eml";
    const uint64_t size = message.size();
    if (!reserve(name, size))
    {
        done(refusal::quota, 0, 0);
        return;
    }
    put_object(key, std::move(message),
               [this, name, f, key, size, flags, keywords = std::move(keywords), date_ms, done](bool ok) {
        unreserve(name, size);
        if (!ok)
        {
            done(refusal::storage, 0, 0);
            return;
        }
        const uint32_t uid = add_message(name, f, key, size, date_ms, flags, keywords);
        if (uid == 0)
        {
            // Its folder went while it was written: the object goes too, rather than stay where nothing lists it.
            delete_object(key, [](bool) {});
            done(refusal::no_folder, 0, 0);
            return;
        }
        done(refusal::none, f->uidvalidity, uid);
    });
}

void imap_store::remove(const std::string& name, const std::string& folder, std::function<void(bool)> done)
{
    user_state& u = user(name);
    const std::string fname = canonical(folder);
    const auto it = u.folders.find(fname);
    // The folders every mailbox has stay, as they are made again at the next start anyway.
    const auto& sp = special();
    const bool special_use = std::any_of(sp.begin(), sp.end(), [&](const auto& s) { return s.first == fname; });
    if (it == u.folders.end() || fname == "INBOX" || special_use)
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
    // The source is looked for before the destination is made, so a RENAME of nothing leaves nothing behind.
    if (a == "INBOX" || !user(name).folders.count(a) || user(name).folders.count(b) || !create(name, b))
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
    copy(name, f, uids, to, false, [expunge_them, done](bool ok, uint32_t, std::vector<uint32_t>) {
        if (ok)
            expunge_them();
        else
            done(false);
    });
}

}   // namespace socketley::mail
