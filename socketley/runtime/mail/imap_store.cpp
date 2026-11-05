#include "imap_store.h"
#include "mail_delivery.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <set>
#include <unordered_set>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "imap_order.h"
#include "mail_compose.h"
#include "mail_instance.h"
#include "mail_mailbox.h"
#include "mail_run.h"
#include "mail_spool.h"
#include "mail_text.h"
#include "../../shared/loop/blocking_write.h"
#include "../../shared/persist/paths.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/persist/replaced_file.h"
#include "../../shared/storage/storage_rpc.h"
#include "../../shared/util/base64.h"
#include "../../shared/util/crc.h"
#include "../../shared/util/random_id.h"
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

// A record of the trigram filters' file: magic, the length of what follows up to the CRC32C of it, the EMAILID's
// length, the EMAILID and the filter.
constexpr uint32_t filter_magic = 0x54464B53;   // "SKFT" as it lies in the file
// The filters held for every user together, past which the least lately searched user's are let go until asked again.
constexpr size_t filters_most_bytes = 64u << 20;

std::string hex64(uint64_t v)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string out(16, '0');
    for (int i = 15; i >= 0; --i, v >>= 4)
        out[static_cast<size_t>(i)] = digits[v & 15];
    return out;
}

// The journal's line giving a message its conversation.
std::string thread_line(uint32_t uid, uint64_t thread, const std::string& folder)
{
    return "H " + std::to_string(uid) + " " + hex64(thread) + " " + folder + "\n";
}

uint32_t get32(const char* p)
{
    uint32_t v;
    std::memcpy(&v, p, 4);
    return v;
}

void put32(std::string& out, uint32_t v)
{
    char b[4];
    std::memcpy(b, &v, 4);
    out.append(b, 4);
}

// The EMAILID a hash spells, M and its sixteen hex digits.
std::string id_of_hash(uint64_t h)
{
    static constexpr char hex[] = "0123456789abcdef";
    std::string out(17, 'M');
    for (size_t i = 1; i < 17; ++i)
        out[i] = hex[(h >> (64 - 4 * i)) & 15];
    return out;
}

// The hash an EMAILID spells, false where it spells none.
bool hash_of_id(std::string_view id, uint64_t& h)
{
    if (id.size() != 17 || id[0] != 'M')
        return false;
    h = 0;
    for (const char c : id.substr(1))
    {
        const int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
        if (d < 0)
            return false;
        h = h << 4 | static_cast<uint64_t>(d);
    }
    return true;
}

std::string filter_record(const std::string& id, std::string_view filter)
{
    std::string body;
    body += static_cast<char>(id.size());
    body += id;
    body += filter;
    std::string out;
    put32(out, filter_magic);
    put32(out, static_cast<uint32_t>(body.size()));
    out += body;
    put32(out, socketley::crc::crc32c(body));
    return out;
}

std::string canonical(const std::string& folder)
{
    return socketley::ascii::iequals(folder, "INBOX") ? std::string("INBOX") : folder;
}

}   // namespace

std::string imap_folder::id() const
{
    if (!objectid.empty())
        return objectid;
    static constexpr char hex[] = "0123456789abcdef";
    std::string out = "F";
    for (int i = 28; i >= 0; i -= 4)
        out += hex[(uidvalidity >> i) & 15];
    return out;
}

uint64_t imap_store::email_hash(std::string_view key)
{
    // FNV-1a over the object's name past its folder, which a copy and a move keep: the same on every shard and at
    // every start, and as unique as those names are among a user's.
    const size_t slash = key.rfind('/');
    const std::string_view base = slash == std::string_view::npos ? key : key.substr(slash + 1);
    uint64_t h = 1469598103934665603ull;
    for (const unsigned char c : base)
        h = (h ^ c) * 1099511628211ull;
    return h;
}

uint64_t imap_store::thread_of(std::string_view header, std::string_view key)
{
    // FNV-1a over the root's Message-ID, the same for every message of the conversation on every shard; a message
    // naming none is a conversation of its own, by its object's name as its email id is.
    const std::string root = imap_order::thread_root(header);
    if (root.empty())
        return email_hash(key) | 1;
    uint64_t h = 1469598103934665603ull;
    for (const unsigned char c : root)
        h = (h ^ c) * 1099511628211ull;
    return h | 1;
}

void imap_store::know_threads(const std::string& name, std::function<void()> done)
{
    refresh(name);
    struct one
    {
        std::string folder, key;
        uint32_t uid;
        uint64_t size;
        uint64_t thread;
    };
    struct job
    {
        std::vector<one> todo;
        size_t next{0}, open{0}, left{0};
        bool pumping{false}, finished{false};
        std::function<void()> done;
    };
    auto j = std::make_shared<job>();
    for (const auto& [n, f] : user(name).folders)
        for (const auto& m : f->msgs)
            if (!m.thread)
                j->todo.push_back({n, m.key, m.uid, m.size, 0});
    if (j->todo.empty())
    {
        done();
        return;
    }
    j->left = j->todo.size();
    j->done = std::move(done);
    // What was read is logged in one go, a message another shard gave a conversation meanwhile kept as it is.
    const auto finish = [this, name, j] {
        j->finished = true;
        mutate(name, [&](user_state& u, std::string& lines) {
            for (const auto& t : j->todo)
                if (t.thread)
                    if (const auto it = u.folders.find(t.folder); it != u.folders.end())
                        if (imap_message* m = it->second->by_uid(t.uid); m && !m->thread)
                        {
                            m->thread = t.thread;
                            lines += thread_line(t.uid, t.thread, t.folder);
                        }
        });
        j->done();
    };
    auto pump = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> weak = pump;
    // Eight headers asked for at once, as SORT and THREAD read ahead; one a cache answers at once is taken by the loop
    // that asked, not by a call deeper into it.
    *pump = [this, j, weak, finish, alive = m_alive] {
        auto self = weak.lock();
        if (!*alive || !self || j->pumping || j->finished)
            return;
        j->pumping = true;
        while (j->next < j->todo.size() && j->open < 8)
        {
            const size_t i = j->next++;
            ++j->open;
            head(j->todo[i].key, j->todo[i].size, [j, i, self, alive](std::shared_ptr<const std::string> h) {
                if (!*alive)
                    return;
                --j->open;
                --j->left;
                // A message that cannot be read now is left for the next time.
                if (h)
                    j->todo[i].thread = thread_of(*h, j->todo[i].key);
                if (!j->pumping)
                    (*self)();
            });
        }
        j->pumping = false;
        if (j->left == 0 && !j->finished)
            finish();
    };
    (*pump)();
}

std::string imap_store::email_id(std::string_view key)
{
    return id_of_hash(email_hash(key));
}

bool imap_store::meta_name_ok(std::string_view entry)
{
    // /private or /shared and what is under them, an atom with no wildcard, no empty level and no slash at its end
    // (RFC 5464 3.2).
    return (entry == "/private" || entry == "/shared" || entry.starts_with("/private/") || entry.starts_with("/shared/")) &&
           entry.size() <= 1024 && entry.find_first_of("*%\"(){}[]\\") == std::string_view::npos &&
           entry.find("//") == std::string_view::npos && entry.back() != '/' &&
           std::all_of(entry.begin(), entry.end(), [](char c) { return c > 0x20 && c < 0x7f; });
}

imap_store::meta_refusal imap_store::set_meta(const std::string& name, const std::string& folder,
                                              const std::string& entry, const std::string* value)
{
    if (!meta_name_ok(entry) || entry == "/private" || entry == "/shared")
        return meta_refusal::bad_name;
    if (value && value->size() > meta_max_value)
        return meta_refusal::too_large;
    user(name);
    const std::string fname = folder.empty() ? std::string() : canonical(folder);
    meta_refusal why = meta_refusal::none;
    const bool written = mutate(name, [&](user_state& u, std::string& lines) {
        if (!fname.empty() && !u.folders.count(fname))
        {
            why = meta_refusal::no_folder;
            return;
        }
        const auto f = u.meta.find(fname);
        const std::string* had = nullptr;
        if (f != u.meta.end())
            if (const auto e = f->second.find(entry); e != f->second.end())
                had = &e->second;
        if (value && !had && u.meta_count >= 1000)
        {
            why = meta_refusal::too_many;
            return;
        }
        if (value && u.meta_bytes - (had ? had->size() : 0) + value->size() > (1u << 20))
        {
            why = meta_refusal::too_large;
            return;
        }
        if (!value && !had)
            return;
        const std::string line = "T " + (value ? socketley::base64::encode(*value) : std::string("-")) + " " + fname +
                                 "\t" + entry + "\n";
        apply(u, line, false);
        lines += line;
    });
    return written ? why : meta_refusal::io;
}

const std::string* imap_store::meta(const std::string& name, const std::string& folder, const std::string& entry)
{
    user_state& u = user(name);
    const auto f = u.meta.find(folder.empty() ? std::string() : canonical(folder));
    if (f == u.meta.end())
        return nullptr;
    const auto e = f->second.find(entry);
    return e == f->second.end() ? nullptr : &e->second;
}

std::vector<std::pair<std::string, std::string>> imap_store::meta_under(const std::string& name, const std::string& folder,
                                                                        const std::string& entry, int depth)
{
    std::vector<std::pair<std::string, std::string>> out;
    user_state& u = user(name);
    const auto f = u.meta.find(folder.empty() ? std::string() : canonical(folder));
    if (f == u.meta.end() || depth <= 0)
        return out;
    const std::string under = entry + "/";
    for (auto it = f->second.lower_bound(under); it != f->second.end() && it->first.starts_with(under); ++it)
        if (depth > 1 || it->first.find('/', under.size()) == std::string::npos)
            out.emplace_back(it->first, it->second);
    return out;
}

std::string imap_store::rights(const std::string& owner, const std::string& folder, const std::string& who)
{
    if (owner == who)
        return std::string(all_rights);
    // An owner with no index has given nobody a right, and asking makes none for them.
    const user_state* u = indexed(owner);
    if (!u)
        return {};
    const auto it = u->folders.find(canonical(folder));
    if (it == u->folders.end())
        return {};
    std::string out;
    for (const char* id : {who.c_str(), "anyone"})
        if (const auto a = it->second->acl.find(id); a != it->second->acl.end())
            for (const char c : a->second)
                if (out.find(c) == std::string::npos)
                    out += c;
    return out;
}

bool imap_store::set_acl(const std::string& owner, const std::string& folder, const std::string& who,
                         const std::string& r)
{
    user(owner);
    const std::string fname = canonical(folder);
    bool there = false;
    const bool written = mutate(owner, [&](user_state& u, std::string& lines) {
        if (!u.folders.count(fname))
            return;
        there = true;
        const std::string line = "L " + fname + "\t" + who + "\t" + r + "\n";
        apply(u, line, false);
        lines += line;
    });
    if (written && there)
        note_share(owner, fname, who, !r.empty());
    return written && there;
}

std::map<std::string, std::string> imap_store::acl(const std::string& owner, const std::string& folder)
{
    const user_state* u = indexed(owner);
    if (!u)
        return {};
    const auto it = u->folders.find(canonical(folder));
    return it == u->folders.end() ? std::map<std::string, std::string>{} : it->second->acl;
}

std::string imap_store::list_path(std::string_view name) const
{
    return (socketley_paths::resolve().state_dir / "mail" / (std::string(m_run.owner().get_name()) + ".imap") /
            std::string(name))
        .string();
}

void imap_store::note_line(const std::string& path, const std::string& key, bool on)
{
    // A line a key and whether it is on, appended under a lock of its own.
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(path).parent_path(), ec);
    const int lock = ::open((path + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock < 0 || ::flock(lock, LOCK_EX) != 0)
    {
        if (lock >= 0)
            ::close(lock);
        return;
    }
    const std::string line = key + "\t" + (on ? "+" : "-") + "\n";
    struct stat st{};
    if (::stat(path.c_str(), &st) == 0 && st.st_size > (1 << 20))
    {
        // Past a mebibyte the list is written again with the keys that are on, this one among them.
        std::string text;
        socketley::read_file(path, text, {.missing_ok = true}, nullptr);
        text += line;
        std::map<std::string, bool> live;
        for (std::string_view rest = text; !rest.empty();)
        {
            const std::string_view l = socketley::take_item(rest, '\n');
            const size_t last = l.rfind('\t');
            if (last != std::string_view::npos)
                live[std::string(l.substr(0, last))] = l.substr(last + 1) == "+";
        }
        std::string folded;
        for (const auto& [k, is_on] : live)
            if (is_on)
                folded += k + "\t+\n";
        const std::string tmp = path + ".new." + std::to_string(::getpid());
        const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        const bool ok = fd >= 0 && socketley::write_all(fd, folded.data(), folded.size());
        if (fd >= 0)
            ::close(fd);
        if (!ok || ::rename(tmp.c_str(), path.c_str()) != 0)
            ::unlink(tmp.c_str());
        ::close(lock);
        return;
    }
    const int fd = ::open(path.c_str(), O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    if (fd >= 0)
    {
        if (!socketley::write_all(fd, line.data(), line.size()))
            LOG_WARN(("mail: the list " + path + " could not be written").c_str());
        ::close(fd);
    }
    ::close(lock);
}

std::vector<std::string> imap_store::live_lines(const std::string& path)
{
    std::string text;
    socketley::read_file(path, text, {.missing_ok = true}, nullptr);
    std::map<std::string, bool> on;
    for (std::string_view rest = text; !rest.empty();)
    {
        const std::string_view line = socketley::take_item(rest, '\n');
        const size_t last = line.rfind('\t');
        if (last != std::string_view::npos)
            on[std::string(line.substr(0, last))] = line.substr(last + 1) == "+";
    }
    std::vector<std::string> out;
    for (const auto& [k, is_on] : on)
        if (is_on)
            out.push_back(k);
    return out;
}

void imap_store::note_share(const std::string& owner, const std::string& folder, const std::string& who, bool on)
{
    // A share is checked against the owner's ACL whenever it is used, so a stale line gives nothing.
    note_line(list_path(".shares"), owner + "\t" + folder + "\t" + who, on);
}

void imap_store::note_push_user(const std::string& user, bool on)
{
    note_line(list_path(".push-users"), user, on);
}

std::vector<std::string> imap_store::push_users()
{
    return live_lines(list_path(".push-users"));
}

std::vector<std::pair<std::string, std::string>> imap_store::shared_with(const std::string& who)
{
    std::vector<std::pair<std::string, std::string>> out;
    for (const auto& key : live_lines(list_path(".shares")))
    {
        // owner \t folder \t grantee.
        const size_t a = key.find('\t'), b = a == std::string::npos ? a : key.find('\t', a + 1);
        if (b == std::string::npos)
            continue;
        const std::string owner = key.substr(0, a), folder = key.substr(a + 1, b - a - 1), grantee = key.substr(b + 1);
        if ((grantee == who || grantee == "anyone") && owner != who &&
            rights(owner, folder, who).find('l') != std::string::npos &&
            std::find(out.begin(), out.end(), std::make_pair(owner, folder)) == out.end())
            out.emplace_back(owner, folder);
    }
    return out;
}

std::string imap_store::mailbox_id(const std::string& name, const std::string& folder)
{
    const auto& folders = user(name).folders;
    const auto it = folders.find(canonical(folder));
    return it == folders.end() ? std::string() : it->second->id();
}

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

imap_store::user_state* imap_store::indexed(const std::string& name)
{
    if (const auto it = m_users.find(name); it != m_users.end() && it->second.loaded)
        return &it->second;
    const std::string base = path_of(name);
    struct stat st{};
    if (::stat(base.c_str(), &st) != 0 && ::stat((base + ".log").c_str(), &st) != 0)
        return nullptr;
    return &user(name);
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
                    if (const auto m = u.meta.find(it->first); m != u.meta.end())
                    {
                        for (const auto& [e, v] : m->second)
                            u.meta_bytes -= std::min<uint64_t>(u.meta_bytes, v.size());
                        u.meta_count -= std::min(u.meta_count, m->second.size());
                        u.meta.erase(m);
                    }
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
            case 'T':
            {
                // T <base64 value, or - for none> <folder>\t<entry>: a METADATA entry set or taken away.
                const auto w = words(l, 1);
                const size_t tab = l.find('\t');
                if (tab == std::string_view::npos)
                    break;
                const std::string fname(l.substr(0, tab)), entry(l.substr(tab + 1));
                auto& entries = u.meta[fname];
                if (const auto it = entries.find(entry); it != entries.end())
                {
                    u.meta_bytes -= std::min<uint64_t>(u.meta_bytes, it->second.size());
                    --u.meta_count;
                    entries.erase(it);
                }
                std::string value;
                if (w[0] != "-" && socketley::base64::decode(w[0], value))
                {
                    u.meta_bytes += value.size();
                    ++u.meta_count;
                    entries[entry] = std::move(value);
                }
                if (entries.empty())
                    u.meta.erase(fname);
                break;
            }
            case 'L':
            {
                // L <folder>\t<identifier>\t<rights>: an ACL entry, none taking it away.
                const size_t t1 = l.find('\t'), t2 = t1 == std::string_view::npos ? t1 : l.find('\t', t1 + 1);
                if (t2 == std::string_view::npos)
                    break;
                if (imap_folder* f = folder(l.substr(0, t1)))
                {
                    const std::string who(l.substr(t1 + 1, t2 - t1 - 1)), r(l.substr(t2 + 1));
                    if (r.empty())
                        f->acl.erase(who);
                    else
                        f->acl[who] = r;
                }
                break;
            }
            case 'I':
            {
                // I <mailboxid> <folder>: the id a folder took from the one it was renamed from.
                const auto w = words(l, 1);
                if (imap_folder* f = folder(l))
                    f->objectid = std::string(w[0]);
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
            case 'V':
            {
                const auto w = words(l, 2);
                if (imap_folder* f = folder(l))
                    if (imap_message* m = f->by_uid(static_cast<uint32_t>(num(w[0]))))
                        m->saved_ms = static_cast<int64_t>(num(w[1]));
                break;
            }
            case 'H':
            {
                // H <uid> <thread> <folder>: the conversation a message is part of, which never changes.
                const auto w = words(l, 2);
                if (imap_folder* f = folder(l))
                    if (imap_message* m = f->by_uid(static_cast<uint32_t>(num(w[0]))))
                        m->thread = std::strtoull(std::string(w[1]).c_str(), nullptr, 16);
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
    u.meta.clear();
    u.meta_bytes = 0;
    u.meta_count = 0;
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
            else if (line[0] == 'I' && f)
                f->objectid = std::string(line.substr(2));
            else if (line[0] == 'T' || line[0] == 'L')
                apply(u, std::string(line) + "\n", false);
            else if (line[0] == 'H' && f && !f->msgs.empty())
                f->msgs.back().thread = std::strtoull(std::string(line.substr(2)).c_str(), nullptr, 16);
            else if (line[0] == 'S' && f && !f->msgs.empty())
                f->msgs.back().saved_ms = static_cast<int64_t>(num(line.substr(2)));
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
            old.acl = std::move(f->acl);
            old.objectid = std::move(f->objectid);
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
        if (!f->objectid.empty())
            text += "I " + f->objectid + "\n";
        for (const auto& [who, r] : f->acl)
            text += "L " + n + "\t" + who + "\t" + r + "\n";
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
            // H <thread>: the conversation of the message on the line before, S <saved> when it was put there.
            if (m.thread)
                text += "H " + hex64(m.thread) + "\n";
            if (m.saved_ms)
                text += "S " + std::to_string(m.saved_ms) + "\n";
        }
    }
    for (const auto& [fname, entries] : u.meta)
        for (const auto& [entry, value] : entries)
            text += "T " + socketley::base64::encode(value) + " " + fname + "\t" + entry + "\n";
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

namespace
{

std::string upload_key(const std::string& user, const std::string& id)
{
    return ".jmap-uploads/" + socketley::base64url::encode(user) + "/" + id;
}

}   // namespace

void imap_store::put_upload(const std::string& user, std::string data, std::function<void(std::string)> done)
{
    // U<time>x<size>x<random>: when it came, which a sweep reads, and its size, which a read needs.
    static constexpr char hex[] = "0123456789abcdef";
    const auto to_hex = [](uint64_t v) {
        std::string out;
        do
        {
            out.insert(out.begin(), hex[v & 15]);
            v >>= 4;
        } while (v);
        return out;
    };
    const std::string id = "U" + to_hex(static_cast<uint64_t>(wall::now_ms())) + "x" + to_hex(data.size()) + "x" +
                           socketley::random_hex(8);
    put_object(upload_key(user, id), std::move(data), [id, done](bool ok) { done(ok ? id : std::string()); });
}

void imap_store::get_upload(const std::string& user, const std::string& id,
                            std::function<void(std::shared_ptr<const std::string>)> done)
{
    const size_t a = id.find('x'), b = a == std::string::npos ? a : id.find('x', a + 1);
    if (!id.starts_with("U") || b == std::string::npos || b - a < 2 || id.find_first_not_of("0123456789abcdefxU") != std::string::npos)
    {
        done(nullptr);
        return;
    }
    const uint64_t size = std::strtoull(id.substr(a + 1, b - a - 1).c_str(), nullptr, 16);
    if (size == 0)
    {
        done(std::make_shared<const std::string>());
        return;
    }
    body(upload_key(user, id), size, std::move(done), false);
}

void imap_store::sweep_uploads(std::string after)
{
    mailboxes* boxes = m_run.boxes();
    if (!boxes || !boxes->enabled())
        return;
    rpc::request rq;
    rq.kind = rpc::op::list;
    rq.bucket = boxes->bucket();
    rq.prefix = ".jmap-uploads/";
    rq.start_after = std::move(after);
    boxes->ask(boxes->storage(), rpc::encode(rq), [this, alive = m_alive](request_status st, std::string_view bytes) {
        if (!*alive)
            return;
        rpc::reply r;
        if (st != request_status::ok || !rpc::decode(bytes, rpc::op::list, r) || !r.ok)
            return;
        const int64_t now = wall::now_ms();
        for (const auto& o : r.objects)
        {
            const size_t at = o.key.rfind("/U");
            const int64_t made = at == std::string::npos
                                     ? 0
                                     : static_cast<int64_t>(std::strtoull(o.key.c_str() + at + 2, nullptr, 16));
            if (now - made > 86400000)
                delete_object(o.key, [](bool) {});
        }
        // Page after page, so young uploads early in the list do not keep old ones after them.
        if (r.truncated && !r.objects.empty())
            sweep_uploads(r.objects.back().key);
    });
}

void imap_store::autoexpunge(int64_t now)
{
    const int64_t before = now - static_cast<int64_t>(m_run.owner().get_autoexpunge()) * 1000 / delivery::queue_scale();
    for (auto& [name, u] : m_users)
    {
        if (!u.loaded)
            continue;
        for (const char* folder : {"Junk", "Trash"})
        {
            const auto it = u.folders.find(folder);
            if (it == u.folders.end())
                continue;
            // Put there before the store kept that, a message is as old as it is.
            std::vector<uint32_t> old;
            for (const auto& m : it->second->msgs)
                if ((m.saved_ms ? m.saved_ms : m.date_ms) < before)
                    old.push_back(m.uid);
            if (!old.empty())
                expunge(name, it->second, old, true, [](std::vector<uint32_t>) {});
        }
    }
}

void imap_store::tick(int64_t)
{
    // On the first shard alone, as autoexpunge below, so N shards do not list and delete the same uploads.
    if (const int64_t now = wall::now_ms_coarse();
        m_run.owner().get_shard_index() == 0 && now - m_uploads_swept_ms > 3600000)
    {
        m_uploads_swept_ms = now;
        sweep_uploads();
    }
    // Hourly, on the first shard alone, so two do not expunge one message.
    if (const int64_t now = wall::now_ms(); m_run.owner().get_autoexpunge() && m_run.owner().get_shard_index() == 0 &&
                                            now - m_expunge_swept_ms > 3600000 / delivery::queue_scale())
    {
        m_expunge_swept_ms = now;
        autoexpunge(now);
    }
    for (auto& [name, u] : m_users)
    {
        write_text_filters(name, u);
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
    // Past what every user's filters may take together, the least lately searched user's are read again when asked.
    while (m_filter_bytes > filters_most_bytes)
    {
        user_state* oldest = nullptr;
        for (auto& [name, u] : m_users)
            if (u.filters_bytes && (!oldest || u.filters_used_ms < oldest->filters_used_ms))
                oldest = &u;
        if (!oldest)
            break;
        m_filter_bytes -= oldest->filters_bytes;
        oldest->filters.clear();
        oldest->filters_bytes = 0;
        oldest->filters_ino = 0;
        oldest->filters_off = 0;
    }
}

std::vector<std::shared_ptr<imap_folder>> imap_store::known(const std::string& name)
{
    refresh(name);
    std::vector<std::shared_ptr<imap_folder>> out;
    for (const auto& [n, f] : user(name).folders)
        out.push_back(f);
    return out;
}

std::vector<std::string> imap_store::folder_names(const std::string& name)
{
    std::vector<std::string> out;
    for (const auto& [n, f] : user(name).folders)
        out.push_back(n);
    return out;
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

void imap_store::freshen(const std::string& name, std::function<void()> done)
{
    user_state& u = user(name);
    const int64_t now = wall::now_ms_coarse();
    if (now - u.listed_ms < 60000)
        return done();
    u.listed_ms = now;
    folders(name, [this, name, done = std::move(done)](std::vector<std::string> names) {
        auto left = std::make_shared<size_t>(names.size() + 1);
        const auto one = [left, done] {
            if (--*left == 0)
                done();
        };
        for (const auto& f : names)
            open(name, f, [one](std::shared_ptr<imap_folder>) { one(); }, false, 60000);
        one();
    });
}

void imap_store::read_text_filters(const std::string& name)
{
    user_state& u = user(name);
    u.filters_used_ms = wall::now_ms_coarse();
    const std::string path = u.base + ".fts";
    struct stat st{};
    const bool there = ::stat(path.c_str(), &st) == 0;
    // A file compacted by another shard, or gone since it was read, is read again from its start; one not written yet
    // leaves what this shard made alone.
    if ((there && (st.st_ino != u.filters_ino || static_cast<uint64_t>(st.st_size) < u.filters_off)) ||
        (!there && u.filters_ino))
    {
        m_filter_bytes -= u.filters_bytes;
        u.filters.clear();
        u.filters_bytes = 0;
        u.filters_ino = there ? st.st_ino : 0;
        u.filters_off = 0;
    }
    if (!there || static_cast<uint64_t>(st.st_size) == u.filters_off)
        return;
    // A file far past what a mailbox's filters take is not this runtime's to read, and its messages are read instead.
    if (static_cast<uint64_t>(st.st_size) - u.filters_off > (256u << 20))
    {
        u.filters_off = static_cast<uint64_t>(st.st_size);
        return;
    }
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return;
    std::string buf(static_cast<size_t>(st.st_size) - u.filters_off, '\0');
    size_t got = 0;
    while (got < buf.size())
    {
        const ssize_t n = ::pread(fd, buf.data() + got, buf.size() - got, static_cast<off_t>(u.filters_off + got));
        if (n <= 0)
            break;
        got += static_cast<size_t>(n);
    }
    ::close(fd);
    buf.resize(got);
    // A record cut by a crash, or torn by a write still under way, is passed over to the next magic that checks out.
    size_t at = 0;
    while (at + 12 <= buf.size())
    {
        const uint32_t len = get32(buf.data() + at + 4);
        if (get32(buf.data() + at) != filter_magic || len < 2 || len > (1u << 16))
        {
            ++at;
            continue;
        }
        if (at + 12 + len > buf.size())
            break;
        const std::string_view body(buf.data() + at + 8, len);
        const auto id_len = static_cast<unsigned char>(body[0]);
        if (socketley::crc::crc32c(body) != get32(buf.data() + at + 8 + len) || 1u + id_len > len)
        {
            ++at;
            continue;
        }
        if (uint64_t h = 0; hash_of_id(body.substr(1, id_len), h))
            hold_filter(u, h, std::string(body.substr(1 + id_len)));
        at += 12 + len;
    }
    u.filters_off += at;
}

std::string_view imap_store::text_filter_of(const std::string& name, uint64_t email_hash)
{
    const user_state& u = user(name);
    const auto it = u.filters.find(email_hash);
    return it == u.filters.end() ? std::string_view{} : std::string_view(it->second);
}

void imap_store::keep_text_filter(const std::string& name, uint64_t email_hash, std::string filter)
{
    user_state& u = user(name);
    u.filters_out += filter_record(id_of_hash(email_hash), filter);
    hold_filter(u, email_hash, std::move(filter));
}

void imap_store::note_text(const std::string& name, const std::string& key, std::shared_ptr<const std::string> bytes)
{
    if (!bytes || bytes->empty())
        return;
    auto filter = std::make_shared<std::string>();
    m_run.pool().submit(
        m_run.cpu_lane(),
        [bytes, filter] {
            const mime::part root = mime::parse(*bytes);
            *filter = text_filter(*bytes, header_block(*bytes), &root);
        },
        [this, name, key, filter, alive = m_alive] {
            if (*alive)
                keep_text_filter(name, email_hash(key), std::move(*filter));
        });
}

void imap_store::hold_filter(user_state& u, uint64_t id, std::string filter)
{
    const auto [it, fresh] = u.filters.try_emplace(id);
    const size_t was = fresh ? 0 : sizeof(id) + it->second.size();
    it->second = std::move(filter);
    const size_t now = sizeof(id) + it->second.size();
    u.filters_bytes = u.filters_bytes + now - was;
    m_filter_bytes = m_filter_bytes + now - was;
}

void imap_store::write_text_filters(const std::string& name, user_state& u)
{
    // Records wait while a compaction is under way, so its rename does not drop them.
    if (u.filters_out.empty() || u.filters_compacting)
        return;
    // Every record in one write to the end, which another shard's appends do not cut into.
    const std::string path = u.base + ".fts";
    struct stat before{};
    const bool had = ::stat(path.c_str(), &before) == 0;
    // Where this shard had read the file to its end, what it appends is read already.
    const bool current = had ? before.st_ino == u.filters_ino && static_cast<uint64_t>(before.st_size) == u.filters_off
                             : u.filters_ino == 0;
    const int fd = ::open(path.c_str(), O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    if (fd >= 0)
    {
        struct stat after{};
        if (socketley::write_all(fd, u.filters_out.data(), u.filters_out.size()) && current && ::fstat(fd, &after) == 0 &&
            static_cast<uint64_t>(after.st_size) == (had ? static_cast<uint64_t>(before.st_size) : 0) + u.filters_out.size())
        {
            u.filters_ino = after.st_ino;
            u.filters_off = static_cast<uint64_t>(after.st_size);
        }
        ::close(fd);
    }
    u.filters_out.clear();
    // A file grown past three times what the messages still there need is written again with theirs alone, weighed
    // once it is twice what it was when last weighed.
    struct stat st{};
    if (u.filters_compacting || ::stat(path.c_str(), &st) != 0 || st.st_size < (1 << 20) ||
        static_cast<uint64_t>(st.st_size) < 2 * u.filters_weighed)
        return;
    u.filters_weighed = static_cast<uint64_t>(st.st_size);
    // Against every record the file holds, which a shard that only delivers has not read, and not as a search.
    const int64_t used = u.filters_used_ms;
    read_text_filters(name);
    u.filters_used_ms = used;
    std::unordered_set<uint64_t> live;
    for (const auto& [n, f] : u.folders)
        for (const auto& m : f->msgs)
            live.insert(email_hash(m.key));
    std::string keep;
    for (const auto& [id, f] : u.filters)
        if (live.count(id))
            keep += filter_record(id_of_hash(id), f);
    if (static_cast<uint64_t>(st.st_size) < 3 * keep.size())
        return;
    u.filters_compacting = true;
    const uint64_t kept = keep.size();
    // Off the lane the spool's syncs take, which a large file's write would hold up.
    m_run.pool().submit(m_run.cpu_lane(), [path, keep = std::move(keep)] {
        if (!socketley::replace_file(path, keep, socketley::durability::none)) {}
    }, [this, name, kept, alive = m_alive] {
        if (!*alive)
            return;
        user(name).filters_compacting = false;
        user(name).filters_weighed = kept;
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
        // A user keeps a thousand folders at most, so CREATE in a loop does not grow the index without end.
        if (u.folders.count(f) || u.folders.size() + levels.size() > 1000)
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
                       for (const auto& o : *acc)
                           there.insert(o.first);
                       std::sort(acc->begin(), acc->end());
                       // Under the user's lock, the index read to its end: what another shard gave a UID is known,
                       // and a message logged after the listing began is not expunged for being missing from it.
                       mutate(name, [&](user_state& u, std::string& lines) {
                           std::set<std::string> known;
                           // A key expunged since the listing began is still in it, and is not brought back.
                           for (const auto& [ms, k] : f->gone_keys)
                               if (ms > f->sync_from)
                                   known.insert(k);
                           const int64_t now = wall::now_ms_coarse();
                           std::erase_if(f->missing_since, [&](const auto& e) { return there.count(e.first) > 0; });
                           for (auto& m : f->msgs)
                           {
                               known.insert(m.key);
                               if (!there.count(m.key) && m.modseq <= f->sync_from)
                               {
                                   // A message a listing lacks goes once it has been missing a minute, so one the
                                   // store took and lists late is not expunged for it.
                                   const auto miss = f->missing_since.try_emplace(m.key, now).first;
                                   if (now - miss->second < 60000)
                                       continue;
                                   f->missing_since.erase(miss);
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
    const auto read_from = [boxes, key, size, data, finish, alive = m_alive](auto&& self) -> void {
        rpc::request rq;
        rq.bucket = boxes->bucket();
        rq.key = key;
        const bool ranged = size > rpc::max_value;
        rq.kind = ranged ? rpc::op::get_range : rpc::op::get;
        rq.size = data->size();
        rq.length = static_cast<uint32_t>(rpc::max_value);
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
    rq.length = first;
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

bool imap_store::parsed(const std::string& key, std::shared_ptr<const std::string>& bytes,
                        std::shared_ptr<const mime::part>& part)
{
    const auto it = m_cache.find(key);
    if (it == m_cache.end() || !it->second.bytes || !it->second.part)
        return false;
    ++m_hits;
    m_lru.splice(m_lru.begin(), m_lru, it->second.lru);
    bytes = it->second.bytes;
    part = it->second.part;
    return true;
}

void imap_store::section(const std::string& key, const std::shared_ptr<const std::string>& bytes, std::string section,
                         std::function<void(std::shared_ptr<const std::string>)> done)
{
    std::shared_ptr<const mime::part> part;
    if (const auto it = m_cache.find(key); it != m_cache.end())
        part = it->second.part;
    if (bytes->size() <= (1u << 20))
    {
        if (!part)
            part = structure(key, bytes);
        auto out = std::make_shared<std::string>();
        done(mime::binary_of(*bytes, *part, section, *out) > 0 ? out : nullptr);
        return;
    }
    // Parsing and decoding 16 MiB took 60 to 80 ms, which every other client of the loop waited.
    auto made = std::make_shared<std::shared_ptr<const mime::part>>(part);
    auto out = std::make_shared<std::string>();
    auto ok = std::make_shared<bool>(false);
    m_run.pool().submit(
        0,
        [bytes, made, out, ok, section = std::move(section)] {
            if (!*made)
                *made = std::make_shared<const mime::part>(mime::parse(*bytes));
            *ok = mime::binary_of(*bytes, **made, section, *out) > 0;
        },
        [this, key, bytes, made, out, ok, had = part != nullptr, done = std::move(done), alive = m_alive] {
            if (!*alive)
                return;
            if (!had)
            {
                cached& c = touch(key);
                if (!c.bytes)
                    c.bytes = bytes;
                c.part = *made;
                recount(c);
                evict();
            }
            done(*ok ? out : nullptr);
        });
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

void imap_store::put_new(std::function<std::string()> name, std::shared_ptr<const std::string> data,
                         std::function<void(std::string key)> done, int tries)
{
    std::string key = name();
    m_run.boxes()->make_bucket([this, name = std::move(name), data, done = std::move(done), key, tries,
                                alive = m_alive](bool made) mutable {
        if (!*alive)
            return;
        if (!made)
        {
            done({});
            return;
        }
        put_made(key, *data, [done, key](bool ok) { done(ok ? key : std::string()); }, true,
                 [this, name, data, done, tries]() {
                     // Three names taken in a row is no chance meeting: the write is refused, not tried for ever.
                     if (tries >= 2)
                         done({});
                     else
                         put_new(name, data, done, tries + 1);
                 });
    });
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

void imap_store::put_made(std::string key, std::string data, std::function<void(bool)> done, bool fresh,
                          std::function<void()> taken)
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
        // A new message's name is asked to be free under the key's lane, where nothing can take it in between.
        if (fresh)
            rq.if_none_match = "*";
        boxes->ask(boxes->storage(), rpc::encode(rq),
                   [done, taken, alive = m_alive](request_status st, std::string_view b) {
            if (!*alive)
                return;
            rpc::reply r;
            const bool decoded = st == request_status::ok && rpc::decode(b, rpc::op::put, r);
            if (decoded && !r.ok && r.code == "PreconditionFailed" && taken)
            {
                taken();
                return;
            }
            done(decoded && r.ok);
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
                                 uint64_t size, int64_t date_ms, uint8_t flags, const std::vector<std::string>& keywords,
                                 uint64_t thread)
{
    const auto uids = add_messages(name, f, {imap_message{0, key, size, date_ms, flags, true, 0, keywords, thread}});
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
                imap_message m{f->uidnext++, in.key,    in.size,    in.date_ms, in.flags,
                               true,         ++f->highestmodseq, in.keywords, in.thread};
                uid = m.uid;
                m.saved_ms = wall::now_ms();
                lines += "A " + std::to_string(m.uid) + " " + std::to_string(m.flags) + " " + std::to_string(m.size) +
                         " " + std::to_string(m.date_ms) + " " + std::to_string(m.modseq) + " " + f->name + "\t" +
                         m.key + "\n";
                // V <uid> <saved> <folder>: when it was put there, beside the line that put it.
                lines += "V " + std::to_string(m.uid) + " " + std::to_string(m.saved_ms) + " " + f->name + "\n";
                if (!m.keywords.empty())
                {
                    lines += "K " + std::to_string(m.uid) + " " + std::to_string(m.modseq) + " " + f->name + "\t";
                    for (size_t i = 0; i < m.keywords.size(); ++i)
                        lines += (i ? " " : "") + m.keywords[i];
                    lines += "\n";
                }
                if (m.thread)
                    lines += thread_line(m.uid, m.thread, f->name);
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
                        f->missing_since.erase(m->key);
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
    // What a user moves says what it is: into Junk spam, out of it or filed into a folder of their own not spam.
    const auto named = [](const std::string& f, std::string_view n) { return socketley::ascii::iequals(f, n); };
    const bool to_junk = named(dest->name, "Junk") && !named(from->name, "Junk");
    const bool from_junk = named(from->name, "Junk") && !named(dest->name, "Junk") && !named(dest->name, "Trash");
    const bool filed = !named(from->name, "Junk") && !named(dest->name, "Junk");
    const bool kept = filed && !named(dest->name, "Trash") && !named(dest->name, "Drafts") && !named(dest->name, "Sent") &&
                      !named(from->name, "Sent") && !named(from->name, "Drafts") && !named(from->name, "Trash") &&
                      !named(dest->name, from->name);
    if (to_junk || from_junk || kept)
        done = [this, name, j, to_junk, inner = std::move(done)](bool ok, uint32_t validity, std::vector<uint32_t> made) {
            if (ok)
                for (size_t i = 0; i < j->todo.size() && i < j->keys.size(); ++i)
                    if (i < j->state.size() && j->state[i] == 1)
                        m_run.learn(name, j->keys[i], j->todo[i].size, to_junk);
            inner(ok, validity, std::move(made));
        };
    for (const uint32_t uid : uids)
        if (const imap_message* m = from->by_uid(uid))
        {
            j->todo.push_back(*m);
            j->reserved += m->size;
        }
    // The room the copies take is held while they are made, so two COPYs cannot pass the quota together.
    if (!counts)
        j->reserved = 0;
    if (counts && !reserve(name, j->reserved))
    {
        done(false, dest->uidvalidity, {});
        return;
    }
    // A copy keeps its object's name in the folder it goes to, so its EMAILID is the original's, unless the folder
    // has that name already, or had it lately and its removal may still be on its way.
    std::set<std::string> taken;
    for (const auto& m : dest->msgs)
        taken.insert(m.key.substr(m.key.rfind('/') + 1));
    for (const auto& g : dest->gone_keys)
        taken.insert(g.second.substr(g.second.rfind('/') + 1));
    j->keys.resize(j->todo.size());
    for (size_t i = 0; i < j->todo.size(); ++i)
    {
        const std::string& k = j->todo[i].key;
        const std::string base = k.substr(k.rfind('/') + 1);
        j->keys[i] = taken.insert(base).second && base.ends_with(".eml")
                         ? name + "/" + dest->name + "/" + base
                         : name + "/" + dest->name + "/" + new_spool_id(m_run.shard()) + ".eml";
    }
    // Up to 32 and 16 MiB read and written at once, logged in the order asked as they are in, so the UIDs answered keep that order.
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
            body(m.key, m.size, [this, j, i, self](std::shared_ptr<const std::string> b) {
                if (!b)
                {
                    --j->running;
                    j->running_bytes -= j->todo[i].size;
                    j->state[i] = 2;
                    j->ok = false;
                    (*self)();
                    return;
                }
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
                           int64_t date_ms, uint64_t thread)
{
    user_state& u = user(name);
    const std::string fname = canonical(folder);
    if (!u.folders.count(fname) && !create(name, fname))
        return;
    const auto it = u.folders.find(fname);
    if (it != u.folders.end())
        add_message(name, it->second, key, size, date_ms, flags_of_key(key), {}, thread);
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
    const uint64_t size = message.size();
    if (!reserve(name, size))
    {
        done(refusal::quota, 0, 0);
        return;
    }
    auto bytes = std::make_shared<const std::string>(std::move(message));
    // Named by this shard, so two shards writing in the same microsecond never give one name to two messages.
    const std::string prefix = name + "/" + f->name + "/";
    const uint32_t shard = m_run.shard();
    put_new([prefix, shard] { return prefix + new_spool_id(shard) + ".eml"; }, bytes,
            [this, name, f, size, flags, keywords = std::move(keywords), date_ms, done, bytes](std::string key) {
        unreserve(name, size);
        if (key.empty())
        {
            done(refusal::storage, 0, 0);
            return;
        }
        const uint32_t uid =
            add_message(name, f, key, size, date_ms, flags, keywords, thread_of(header_block(*bytes), key));
        if (uid == 0)
        {
            // Its folder went while it was written: the object goes too, rather than stay where nothing lists it.
            delete_object(key, [](bool) {});
            done(refusal::no_folder, 0, 0);
            return;
        }
        note_text(name, key, bytes);
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
    // The source is looked for before the destination is made, so a RENAME of nothing leaves nothing behind; a
    // folder is not renamed into itself.
    if (a == b || b == "INBOX" || b.starts_with(a + "/") || !user(name).folders.count(a) || user(name).folders.count(b))
    {
        done(false);
        return;
    }
    // The folders under it go with it, each as the one above it is done (RFC 3501 6.3.5); INBOX's stay.
    std::vector<std::pair<std::string, std::string>> moves{{a, b}};
    if (a != "INBOX")
        for (const auto& [f, _] : user(name).folders)
            if (f.starts_with(a + "/") && !user(name).folders.count(b + f.substr(a.size())))
                moves.emplace_back(f, b + f.substr(a.size()));
    auto step = std::make_shared<std::function<void(size_t)>>();
    std::weak_ptr<std::function<void(size_t)>> weak = step;
    *step = [this, name, moves, done, weak](size_t at) {
        auto self = weak.lock();
        if (!self)
            return;
        if (at == moves.size())
        {
            done(true);
            return;
        }
        const auto& [from_name, to_name] = moves[at];
        const std::string id = from_name == "INBOX" ? std::string() : mailbox_id(name, from_name);
        if (!create(name, to_name))
        {
            done(false);
            return;
        }
        // A renamed folder keeps its MAILBOXID and its METADATA; INBOX's stay INBOX's (RFC 8474 4.1, RFC 5464 3.4).
        if (!id.empty())
            mutate(name, [&](user_state& u, std::string& lines) {
                if (const auto it = u.folders.find(to_name); it != u.folders.end())
                {
                    it->second->objectid = id;
                    lines += "I " + id + " " + to_name + "\n";
                }
                if (const auto m = u.meta.find(from_name); m != u.meta.end())
                {
                    std::string moved;
                    for (const auto& [entry, value] : m->second)
                        moved += "T " + socketley::base64::encode(value) + " " + to_name + "\t" + entry + "\n";
                    apply(u, moved, false);
                    lines += moved;
                }
                if (const auto f = u.folders.find(from_name); f != u.folders.end() && !f->second->acl.empty())
                {
                    std::string moved;
                    for (const auto& [who, r] : f->second->acl)
                        moved += "L " + to_name + "\t" + who + "\t" + r + "\n";
                    apply(u, moved, false);
                    lines += moved;
                    for (const auto& [who, r] : f->second->acl)
                    {
                        note_share(name, from_name, who, false);
                        note_share(name, to_name, who, true);
                    }
                }
            });
        open(name, from_name, [this, name, from_name, to_name, done, self, at](std::shared_ptr<imap_folder> f) {
            if (!f)
            {
                done(false);
                return;
            }
            empty_out(name, f, from_name, to_name, 4, [done, self, at](bool ok) {
                if (ok)
                    (*self)(at + 1);
                else
                    done(false);
            });
        }, true);
    };
    (*step)(0);
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
            // INBOX stays, emptied, as a RENAME of it leaves it (RFC 3501 6.3.5).
            if (fname == "INBOX")
            {
                gone = true;
                return;
            }
            // A message that came in while the last pass ran keeps the folder.
            if (!f->msgs.empty())
                return;
            // A folder made again under the name since is another's, and stays.
            if (const auto it = u.folders.find(fname); it != u.folders.end() && it->second == f)
            {
                u.folders.erase(it);
                lines += "D " + fname + "\n";
            }
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
