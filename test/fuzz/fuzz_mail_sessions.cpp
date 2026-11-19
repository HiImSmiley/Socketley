// Fuzz target: the two conversations of a mail runtime a signed-in user drives, IMAP and JMAP
// (socketley/runtime/mail/imap_session.cpp, jmap_session.cpp, jmap_methods.cpp).
//
// Reachable by anyone who reaches the IMAP or the JMAP port before sign-in, as far as the command reader and the
// request reader go, and by every mail user past it: the commands and method calls themselves.  The sessions are
// the runtime's own; under them is a store of this file's, in memory, which answers at once or a step later as the
// input says, so a session is also taken away while an answer to it is still owed.
//
// The first byte of an input chooses what it is, the second (bit 0) whether the store answers late:
//
//   0  bytes an IMAP client sends, in pieces cut where a 0xFF byte stands, to a session not signed in; user u with
//      password p signs in to a mailbox of five folders and three messages.
//   1  the same to a session already signed in with INBOX selected, so every byte is spent past the sign-in.
//   2  bytes a JMAP client sends, in pieces cut where a 0xFF byte stands: whole HTTP requests, as they come.
//   3  the body of one JMAP API request, sent as user u's.
//
// What must hold, beside no report from the sanitizers:
//
//   * IMAP: everything said is whole lines ended by CRLF, and a line that ends in {n} is followed by n bytes and
//     goes on after them: a literal says its own length, so nothing a message or a mailbox name holds is read by the
//     client as a line of the server's.  What the session keeps of its input stays under the largest command it
//     takes.
//   * JMAP: everything said is HTTP responses one after the other, each as long as its Content-Length says, and one
//     that says application/json holds JSON.  An API answer of 200 is an object.
//   * Neither session is called again once it is gone, whatever the store still owed it.

#include <algorithm>
#include <charconv>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "fuzz_common.h"

#include "../../socketley/runtime/mail/imap_order.h"
#include "../../socketley/runtime/mail/imap_session.h"
#include "../../socketley/runtime/mail/imap_store.h"
#include "../../socketley/runtime/mail/jmap_session.h"
#include "../../socketley/runtime/mail/dav.h"
#include "../../socketley/runtime/mail/mail_mime.h"
#include "../../socketley/runtime/mail/mail_web.h"
#include "../../socketley/shared/json/json_doc.h"
#include "../../socketley/shared/util/ascii.h"

namespace
{

// What the store holds beside the folders: each message's bytes by its key, and the uploads.
std::map<std::string, std::shared_ptr<const std::string>> g_objects;
uint64_t g_made = 0;
// Answers owed: run at once, or kept until the next step.
bool g_late = false;
std::deque<std::function<void()>> g_owed;

void answer(std::function<void()> f)
{
    if (g_late && g_owed.size() < 4096)
        g_owed.push_back(std::move(f));
    else
        f();
}

void settle()
{
    // What an answer asks in turn is answered in the same step, to a bound, so a session is never left waiting.
    for (size_t n = 0; !g_owed.empty() && n < 8192; ++n)
    {
        auto f = std::move(g_owed.front());
        g_owed.pop_front();
        f();
    }
}

std::string canonical(const std::string& folder)
{
    return socketley::ascii::iequals(folder, "INBOX") ? std::string("INBOX") : folder;
}

std::string key_for(const std::string& user, const std::string& folder)
{
    return user + "/" + folder + "/m" + std::to_string(++g_made);
}

}   // namespace

// ─── The store, in memory ───────────────────────────────────────────────────
//
// The class is the runtime's and so are its fields; only what its methods do is this file's.  It keeps no file and
// asks no storage runtime, and it bounds what an input can make it hold.

namespace socketley::mail
{

namespace
{
constexpr size_t max_folders = 24;
constexpr size_t max_messages = 64;
constexpr size_t max_object = 1u << 20;
}

imap_store::imap_store(mail_run& run) : m_run(run) {}

imap_store::~imap_store()
{
    *m_alive = false;
}

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

imap_message* imap_folder::by_uid(uint32_t uid)
{
    const auto it = std::lower_bound(msgs.begin(), msgs.end(), uid,
                                     [](const imap_message& m, uint32_t u) { return m.uid < u; });
    return it != msgs.end() && it->uid == uid ? &*it : nullptr;
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
    if (next.size() > 64)
        next.resize(64);
    const bool changed = next.size() != have.size() ||
                         !std::equal(next.begin(), next.end(), have.begin(),
                                     [](const std::string& a, const std::string& b) { return iequals(a, b); });
    have = std::move(next);
    return changed;
}

const std::vector<std::pair<std::string, std::string>>& imap_store::special()
{
    static const std::vector<std::pair<std::string, std::string>> s = {
        {"INBOX", ""}, {"Sent", "\\Sent"}, {"Drafts", "\\Drafts"}, {"Junk", "\\Junk"}, {"Trash", "\\Trash"}};
    return s;
}

uint64_t imap_store::email_hash(std::string_view key)
{
    const size_t slash = key.rfind('/');
    const std::string_view base = slash == std::string_view::npos ? key : key.substr(slash + 1);
    uint64_t h = 1469598103934665603ull;
    for (const unsigned char c : base)
        h = (h ^ c) * 1099511628211ull;
    return h;
}

std::string imap_store::email_id(std::string_view key)
{
    static constexpr char hex[] = "0123456789abcdef";
    const uint64_t h = email_hash(key);
    std::string out(17, 'M');
    for (size_t i = 1; i < 17; ++i)
        out[i] = hex[(h >> (64 - 4 * i)) & 15];
    return out;
}

uint64_t imap_store::thread_of(std::string_view header, std::string_view key)
{
    const std::string root = imap_order::thread_root(header);
    if (root.empty())
        return email_hash(key) | 1;
    uint64_t h = 1469598103934665603ull;
    for (const unsigned char c : root)
        h = (h ^ c) * 1099511628211ull;
    return h | 1;
}

bool imap_store::meta_name_ok(std::string_view entry)
{
    return (entry == "/private" || entry == "/shared" || entry.starts_with("/private/") || entry.starts_with("/shared/")) &&
           entry.size() <= 1024 && entry.find_first_of("*%\"(){}[]\\") == std::string_view::npos &&
           entry.find("//") == std::string_view::npos && entry.back() != '/' &&
           std::all_of(entry.begin(), entry.end(), [](char c) { return c > 0x20 && c < 0x7f; });
}

imap_store::user_state& imap_store::user(const std::string& name)
{
    return m_users[name];
}

std::shared_ptr<imap_folder> imap_store::make_folder(user_state& u, const std::string& name)
{
    auto f = std::make_shared<imap_folder>();
    f->name = name;
    f->uidvalidity = ++u.last_validity + 1000;
    u.folders[name] = f;
    return f;
}

std::vector<std::string> imap_store::folder_names(const std::string& name)
{
    std::vector<std::string> out;
    for (const auto& [n, f] : user(name).folders)
        out.push_back(n);
    return out;
}

std::vector<std::shared_ptr<imap_folder>> imap_store::known(const std::string& name)
{
    std::vector<std::shared_ptr<imap_folder>> out;
    for (const auto& [n, f] : user(name).folders)
        out.push_back(f);
    return out;
}

void imap_store::folders(const std::string& name, std::function<void(std::vector<std::string>)> done)
{
    answer([this, name, done = std::move(done)] { done(folder_names(name)); });
}

void imap_store::freshen(const std::string&, std::function<void()> done)
{
    answer(std::move(done));
}

void imap_store::read_text_filters(const std::string&) {}

std::string_view imap_store::text_filter_of(const std::string&, uint64_t)
{
    return {};
}

void imap_store::keep_text_filter(const std::string&, uint64_t, std::string) {}

void imap_store::open(const std::string& name, const std::string& folder,
                      std::function<void(std::shared_ptr<imap_folder>)> done, bool, int64_t, int64_t)
{
    answer([this, name, folder, done = std::move(done)] {
        const auto& fs = user(name).folders;
        const auto it = fs.find(canonical(folder));
        done(it == fs.end() ? nullptr : it->second);
    });
}

bool imap_store::create(const std::string& name, const std::string& folder)
{
    user_state& u = user(name);
    const std::string f = canonical(folder);
    if (f.empty() || u.folders.count(f) || u.folders.size() >= max_folders)
        return false;
    make_folder(u, f);
    return true;
}

std::string imap_store::mailbox_id(const std::string& name, const std::string& folder)
{
    const auto& fs = user(name).folders;
    const auto it = fs.find(canonical(folder));
    return it == fs.end() ? std::string() : it->second->id();
}

imap_store::meta_refusal imap_store::set_meta(const std::string& name, const std::string& folder,
                                              const std::string& entry, const std::string* value)
{
    if (!meta_name_ok(entry) || entry == "/private" || entry == "/shared")
        return meta_refusal::bad_name;
    if (value && value->size() > meta_max_value)
        return meta_refusal::too_large;
    user_state& u = user(name);
    const std::string f = folder.empty() ? std::string() : canonical(folder);
    if (!f.empty() && !u.folders.count(f))
        return meta_refusal::no_folder;
    auto& entries = u.meta[f];
    if (!value)
    {
        entries.erase(entry);
        return meta_refusal::none;
    }
    if (!entries.count(entry) && entries.size() >= 32)
        return meta_refusal::too_many;
    entries[entry] = *value;
    return meta_refusal::none;
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

std::vector<std::pair<std::string, std::string>> imap_store::meta_under(const std::string& name,
                                                                        const std::string& folder,
                                                                        const std::string& entry, int depth)
{
    std::vector<std::pair<std::string, std::string>> out;
    user_state& u = user(name);
    const auto f = u.meta.find(folder.empty() ? std::string() : canonical(folder));
    if (f == u.meta.end())
        return out;
    for (const auto& [k, v] : f->second)
    {
        if (k.size() <= entry.size() || !k.starts_with(entry) || k[entry.size()] != '/')
            continue;
        const auto levels = std::count(k.begin() + static_cast<std::ptrdiff_t>(entry.size()), k.end(), '/');
        if (depth >= 2 || levels <= depth)
            out.emplace_back(k, v);
    }
    return out;
}

std::string imap_store::granted(const std::map<std::string, std::string>& acl, const std::string& who)
{
    std::string out;
    for (const char* id : {who.c_str(), "anyone"})
        if (const auto a = acl.find(id); a != acl.end())
            for (const char c : a->second)
                if (out.find(c) == std::string::npos)
                    out += c;
    return out;
}

std::string imap_store::rights(const std::string& owner, const std::string& folder, const std::string& who)
{
    if (owner == who)
        return std::string(all_rights);
    const auto u = m_users.find(owner);
    if (u == m_users.end())
        return {};
    const auto it = u->second.folders.find(canonical(folder));
    return it == u->second.folders.end() ? std::string() : granted(it->second->acl, who);
}

bool imap_store::set_acl(const std::string& owner, const std::string& folder, const std::string& who,
                         const std::string& rights)
{
    const auto& fs = user(owner).folders;
    const auto it = fs.find(canonical(folder));
    if (it == fs.end())
        return false;
    if (rights.empty())
        it->second->acl.erase(who);
    else if (it->second->acl.count(who) || it->second->acl.size() < 16)
        it->second->acl[who] = rights;
    ++it->second->version;
    return true;
}

std::map<std::string, std::string> imap_store::acl(const std::string& owner, const std::string& folder)
{
    const auto& fs = user(owner).folders;
    const auto it = fs.find(canonical(folder));
    return it == fs.end() ? std::map<std::string, std::string>() : it->second->acl;
}

std::vector<std::pair<std::string, std::string>> imap_store::shared_with(const std::string& who)
{
    std::vector<std::pair<std::string, std::string>> out;
    for (const auto& [owner, u] : m_users)
        if (owner != who)
            for (const auto& [n, f] : u.folders)
                if (!granted(f->acl, who).empty())
                    out.emplace_back(owner, n);
    return out;
}

void imap_store::note_push_user(const std::string&, bool) {}

void imap_store::remove(const std::string& name, const std::string& folder, std::function<void(bool)> done)
{
    answer([this, name, folder, done = std::move(done)] {
        const std::string f = canonical(folder);
        done(f != "INBOX" && user(name).folders.erase(f) > 0);
    });
}

void imap_store::rename(const std::string& name, const std::string& from, const std::string& to,
                        std::function<void(bool)> done)
{
    answer([this, name, from, to, done = std::move(done)] {
        user_state& u = user(name);
        const std::string a = canonical(from), b = canonical(to);
        const auto it = u.folders.find(a);
        if (it == u.folders.end() || a == "INBOX" || b.empty() || u.folders.count(b))
            return done(false);
        auto f = it->second;
        u.folders.erase(it);
        f->name = b;
        ++f->version;
        u.folders[b] = std::move(f);
        done(true);
    });
}

void imap_store::set_subscribed(const std::string& name, const std::string& folder, bool on)
{
    const auto& fs = user(name).folders;
    if (const auto it = fs.find(canonical(folder)); it != fs.end())
        it->second->subscribed = on;
}

bool imap_store::subscribed(const std::string& name, const std::string& folder)
{
    const auto& fs = user(name).folders;
    const auto it = fs.find(canonical(folder));
    return it != fs.end() && it->second->subscribed;
}

uint64_t imap_store::usage(const std::string& name)
{
    uint64_t n = 0;
    for (const auto& [fname, f] : user(name).folders)
        for (const auto& m : f->msgs)
            n += m.size;
    return n;
}

uint64_t imap_store::quota(const std::string&) const
{
    return 8u << 20;
}

void imap_store::body(const std::string& key, uint64_t, std::function<void(std::shared_ptr<const std::string>)> done,
                      bool)
{
    answer([key, done = std::move(done)] {
        const auto it = g_objects.find(key);
        done(it == g_objects.end() ? nullptr : it->second);
    });
}

void imap_store::head(const std::string& key, uint64_t, std::function<void(std::shared_ptr<const std::string>)> done)
{
    answer([key, done = std::move(done)] {
        const auto it = g_objects.find(key);
        if (it == g_objects.end())
            return done(nullptr);
        // The header block and the line that ends it, as the runtime's own read gives it.
        const size_t end = it->second->find("\r\n\r\n");
        done(end == std::string::npos ? it->second : std::make_shared<const std::string>(it->second->substr(0, end + 4)));
    });
}

imap_store::cached& imap_store::touch(const std::string& key)
{
    return m_cache[key];
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
        c.part = std::make_shared<const mime::part>(mime::parse(*c.bytes));
    return c.part;
}

bool imap_store::parsed(const std::string& key, std::shared_ptr<const std::string>& bytes,
                        std::shared_ptr<const mime::part>& part)
{
    const auto it = m_cache.find(key);
    if (it == m_cache.end() || !it->second.bytes || !it->second.part)
        return false;
    bytes = it->second.bytes;
    part = it->second.part;
    return true;
}

void imap_store::section(const std::string& key, const std::shared_ptr<const std::string>& bytes, std::string section,
                         std::function<void(std::shared_ptr<const std::string>)> done)
{
    const std::shared_ptr<const mime::part> part = structure(key, bytes);
    answer([bytes, part, section = std::move(section), done = std::move(done)] {
        auto out = std::make_shared<std::string>();
        done(mime::binary_of(*bytes, *part, section, *out) > 0 ? out : nullptr);
    });
}

bool imap_store::parse_later(const std::string&, const std::shared_ptr<const std::string>&, std::function<void()>)
{
    return false;
}

void imap_store::refresh(const std::string&) {}

size_t imap_store::set_flags(const std::string&, const std::shared_ptr<imap_folder>& f, const std::vector<uint32_t>& uids,
                             const std::function<uint8_t(uint8_t)>& change, const keyword_change& words)
{
    size_t changed = 0;
    for (const uint32_t uid : uids)
    {
        imap_message* m = f->by_uid(uid);
        if (!m)
            continue;
        const uint8_t next = change(m->flags);
        const bool kw = words.apply(m->keywords);
        if (next == m->flags && !kw)
            continue;
        m->flags = next;
        m->modseq = ++f->highestmodseq;
        ++changed;
    }
    if (changed)
        ++f->version;
    return changed;
}

void imap_store::expunge(const std::string&, const std::shared_ptr<imap_folder>& f, const std::vector<uint32_t>& only,
                         bool any, std::function<void(std::vector<uint32_t> gone)> done)
{
    answer([f, only, any, done = std::move(done)] {
        std::vector<uint32_t> gone;
        std::erase_if(f->msgs, [&](const imap_message& m) {
            const bool named = only.empty() || std::find(only.begin(), only.end(), m.uid) != only.end();
            if (!named || !(any || (m.flags & flag_deleted)))
                return false;
            gone.push_back(m.uid);
            return true;
        });
        for (const uint32_t uid : gone)
            if (f->vanished.size() < 256)
                f->vanished.emplace_back(++f->highestmodseq, uid);
        if (!gone.empty())
            ++f->version;
        done(std::move(gone));
    });
}

uint32_t imap_store::add_message(const std::string&, const std::shared_ptr<imap_folder>& f, const std::string& key,
                                 uint64_t size, int64_t date_ms, uint8_t flags, const std::vector<std::string>& keywords,
                                 uint64_t thread)
{
    if (f->msgs.size() >= max_messages)
        return 0;
    imap_message m;
    m.uid = f->uidnext++;
    m.key = key;
    m.size = size;
    m.date_ms = date_ms;
    m.flags = flags;
    m.keywords = keywords;
    m.thread = thread;
    m.modseq = ++f->highestmodseq;
    f->msgs.push_back(std::move(m));
    ++f->version;
    return f->msgs.back().uid;
}

void imap_store::copy(const std::string& name, const std::shared_ptr<imap_folder>& from, const std::vector<uint32_t>& uids,
                      const std::string& to, bool, std::function<void(bool, uint32_t uidvalidity, std::vector<uint32_t>)> done)
{
    answer([this, name, from, uids, to, done = std::move(done)] {
        const auto& fs = user(name).folders;
        const auto it = fs.find(canonical(to));
        if (it == fs.end())
            return done(true, 0, {});
        std::vector<uint32_t> made;
        for (const uint32_t uid : uids)
        {
            const imap_message* m = from->by_uid(uid);
            if (!m)
                continue;
            const auto bytes = g_objects.find(m->key);
            const std::string key = key_for(name, it->second->name);
            if (bytes != g_objects.end())
                g_objects[key] = bytes->second;
            // Copied first: the folder copied into may be the one copied from, and its messages move as it grows.
            const imap_message src = *m;
            const uint32_t given = add_message(name, it->second, key, src.size, src.date_ms, src.flags, src.keywords,
                                               src.thread);
            if (!given)
                return done(false, it->second->uidvalidity, {});
            made.push_back(given);
        }
        done(true, it->second->uidvalidity, std::move(made));
    });
}

void imap_store::know_threads(const std::string&, std::function<void()> done)
{
    answer(std::move(done));
}

void imap_store::append(const std::string& name, const std::string& folder, std::string message, uint8_t flags,
                        std::vector<std::string> keywords, int64_t date_ms,
                        std::function<void(refusal, uint32_t uidvalidity, uint32_t uid)> done)
{
    answer([this, name, folder, message = std::move(message), flags, keywords = std::move(keywords), date_ms,
            done = std::move(done)]() mutable {
        const auto& fs = user(name).folders;
        const auto it = fs.find(canonical(folder));
        if (it == fs.end())
            return done(refusal::no_folder, 0, 0);
        if (message.size() > max_object || usage(name) + message.size() > quota(name))
            return done(refusal::quota, 0, 0);
        const std::string key = key_for(name, it->second->name);
        const uint64_t size = message.size();
        const uint64_t thread = thread_of(std::string_view(message).substr(0, message.find("\r\n\r\n")), key);
        g_objects[key] = std::make_shared<const std::string>(std::move(message));
        const uint32_t uid = add_message(name, it->second, key, size, date_ms, flags, keywords, thread);
        if (!uid)
            return done(refusal::storage, 0, 0);
        done(refusal::none, it->second->uidvalidity, uid);
    });
}

void imap_store::put_upload(const std::string& name, std::string data, std::function<void(std::string id)> done)
{
    answer([name, data = std::move(data), done = std::move(done)]() mutable {
        if (data.size() > max_object || g_objects.size() > 256)
            return done({});
        const std::string id = "U" + std::to_string(++g_made) + "-" + std::to_string(data.size());
        g_objects[".jmap-uploads/" + name + "/" + id] = std::make_shared<const std::string>(std::move(data));
        done(id);
    });
}

void imap_store::uploads_held(const std::string& name, std::function<void(bool, uint64_t, size_t)> done, std::string,
                              uint64_t, size_t)
{
    answer([name, done = std::move(done)] {
        const std::string prefix = ".jmap-uploads/" + name + "/";
        uint64_t bytes = 0;
        size_t count = 0;
        for (auto it = g_objects.lower_bound(prefix); it != g_objects.end() && it->first.starts_with(prefix); ++it)
        {
            bytes += it->second->size();
            ++count;
        }
        done(true, bytes, count);
    });
}

void imap_store::get_upload(const std::string& name, const std::string& id,
                            std::function<void(std::shared_ptr<const std::string>)> done)
{
    answer([name, id, done = std::move(done)] {
        const auto it = g_objects.find(".jmap-uploads/" + name + "/" + id);
        done(it == g_objects.end() ? nullptr : it->second);
    });
}

// What the JMAP session reaches beside the store and is no part of what is tried here: calendars and contacts, which
// this mailbox has none of, and the webmail's page, a few bytes of one.
bool dav_path(std::string_view path, std::string_view method)
{
    return path.starts_with("/dav/") || (path == "/" && method == "PROPFIND");
}

void dav_serve(dav_store&, std::shared_ptr<bool>, std::string, std::string, dav_request, std::function<void(dav_reply)> done)
{
    dav_reply out;
    out.code = 404;
    done(std::move(out));
}

const web_page& webmail_page()
{
    static const web_page page{"<!doctype html><title>mail</title>", "\"p1\"", "default-src 'none'", "gz", "\"p1-gz\""};
    return page;
}

}   // namespace socketley::mail

namespace
{

using namespace socketley::mail;

// A mailbox for user u: the five folders every mailbox has, and three messages in INBOX, one of them of several parts
// and one whose headers are everything a header should not be.
struct world
{
    // The store is never given a runtime, and asks for none: a place for the reference it holds, never read.
    alignas(64) unsigned char no_runtime[64]{};
    imap_store store;

    world() : store(*reinterpret_cast<mail_run*>(no_runtime))
    {
        g_objects.clear();
        g_owed.clear();
        g_made = 0;
        for (const auto& [name, use] : imap_store::special())
            store.create("u", name);
        store.create("u", "Lists/dev");
        store.create("v", "INBOX");
        store.set_acl("v", "INBOX", "u", "lrs");
        const bool was = g_late;
        g_late = false;
        const auto put = [&](std::string_view text, uint8_t flags) {
            store.append("u", "INBOX", std::string(text), flags, {}, 1700000000000, [](imap_store::refusal, uint32_t, uint32_t) {});
        };
        put("From: Ann <ann@example.test>\r\nTo: u@example.test\r\nSubject: hello\r\nMessage-ID: <1@example.test>\r\n"
            "Date: Mon, 01 Jan 2024 10:00:00 +0000\r\n\r\nA first line.\r\nAnd a second.\r\n", flag_seen);
        put("From: =?utf-8?q?B=C3=B6b?= <bob@example.test>\r\nTo: u@example.test, \"x\" <x@example.test>\r\n"
            "Subject: Re: hello\r\nIn-Reply-To: <1@example.test>\r\nMessage-ID: <2@example.test>\r\nMIME-Version: 1.0\r\n"
            "Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n--b1\r\nContent-Type: text/plain; charset=utf-8\r\n"
            "Content-Transfer-Encoding: quoted-printable\r\n\r\nGr=C3=BC=C3=9Fe\r\n--b1\r\n"
            "Content-Type: application/octet-stream; name=\"a.bin\"\r\nContent-Disposition: attachment; filename=\"a.bin\"\r\n"
            "Content-Transfer-Encoding: base64\r\n\r\nAAECAwQF\r\n--b1--\r\n", 0);
        put("Subject: {5}\r\nFrom: \"a\\\"b\" <\"q q\"@example.test>\r\nX-Odd: \x01\x7f\xff\r\n\tfolded )( \"\r\n"
            "Keywords: one, two\r\n\r\nbody with a lone \r in it\r\n.\r\n", flag_flagged | flag_deleted);
        g_late = was;
    }
};

// ─── IMAP ───────────────────────────────────────────────────────────────────

struct imap_hooks : imap_session::hooks
{
    std::string out;
    bool closed{false};
    void reply(std::string_view bytes) override
    {
        if (out.size() < (64u << 20))
            out.append(bytes);
    }
    void start_tls() override {}
    void close() override { closed = true; }
    void login(std::string user, std::string password, std::function<void(account, std::string)> done) override
    {
        const bool ok = user == "u" && password == "p";
        answer([ok, done = std::move(done)] { done(ok ? account::yes : account::no, ok ? "u" : ""); });
    }
};

// Whether a line is a status response, whose words after the status are text a literal is no part of (RFC 3501 9,
// resp-text): "<tag> OK ...", "* BAD ...", and a continuation request.
bool status_line(std::string_view line)
{
    if (line.starts_with("+"))
        return true;
    const size_t sp = line.find(' ');
    if (sp == std::string_view::npos)
        return false;
    const std::string_view rest = line.substr(sp + 1);
    for (const std::string_view st : {"OK", "NO", "BAD", "BYE", "PREAUTH"})
        if (rest.starts_with(st) && (rest.size() == st.size() || rest[st.size()] == ' '))
            return true;
    return false;
}

// Whole lines, each literal as long as it says.
void check_imap_output(std::string_view r)
{
    // Whether the line being read began a response, or goes on after a literal of it.
    bool begins = true;
    while (!r.empty())
    {
        const size_t nl = r.find("\r\n");
        FUZZ_CHECK(nl != std::string_view::npos, "IMAP said a line that does not end");
        const std::string_view line = r.substr(0, nl);
        r.remove_prefix(nl + 2);
        const bool status = begins && status_line(line);
        begins = true;
        const size_t open = line.rfind('{');
        if (status || line.empty() || line.back() != '}' || open == std::string_view::npos)
            continue;
        const std::string_view digits = line.substr(open + 1, line.size() - open - 2);
        if (digits.empty() || digits.find_first_not_of("0123456789") != std::string_view::npos)
            continue;
        size_t n = 0;
        const auto res = std::from_chars(digits.data(), digits.data() + digits.size(), n);
        if (res.ec != std::errc() || n > r.size())
            fuzz::dump("the line", reinterpret_cast<const uint8_t*>(line.data()), line.size());
        FUZZ_CHECK(res.ec == std::errc() && n <= r.size(), "IMAP said a literal longer than what follows it");
        r.remove_prefix(n);
        begins = false;
    }
}

void imap_case(std::string_view in, bool signed_in)
{
    // On the heap: ASan's fake stack, on by default in newer runtimes, aligns a local to 32 bytes, not 64.
    const auto owned = std::make_unique<world>();
    world& w = *owned;
    imap_hooks h;
    imap_config cfg;
    cfg.hostname = "mx.example.test";
    cfg.login_in_clear = true;
    cfg.max_append = 64u << 10;
    {
        imap_session s(cfg, h, w.store);
        s.greet();
        if (signed_in)
        {
            s.input("a LOGIN u p\r\nb SELECT INBOX\r\n");
            settle();
        }
        size_t polls = 0;
        while (!in.empty() && !h.closed)
        {
            const size_t cut = in.find('\xff');
            s.input(in.substr(0, cut));
            in = cut == std::string_view::npos ? std::string_view{} : in.substr(cut + 1);
            settle();
            if (s.idling() && polls++ < 8)
                s.poll();
            FUZZ_CHECK(s.buffered() <= cfg.max_append + 5 * imap_session::max_line + (64u << 10),
                       "IMAP keeps more of its input than its largest command");
        }
        // The session goes with answers still owed it where the input left some.
        if (!g_late)
            settle();
        s.gone();
    }
    settle();
    check_imap_output(h.out);
}

// ─── JMAP ───────────────────────────────────────────────────────────────────

struct jmap_hooks : jmap_session::hooks
{
    std::string out;
    bool closed{false};
    void reply(std::string_view bytes) override
    {
        if (out.size() < (64u << 20))
            out.append(bytes);
    }
    void close() override { closed = true; }
    void login(std::string user, std::string password, std::function<void(account, std::string)> done) override
    {
        const bool ok = user == "u" && password == "p";
        answer([ok, done = std::move(done)] { done(ok ? account::yes : account::no, ok ? "u" : ""); });
    }
    void bearer(std::string token, std::function<void(account, std::string)> done) override
    {
        const bool ok = token == "tok";
        answer([ok, done = std::move(done)] { done(ok ? account::yes : account::no, ok ? "u" : ""); });
    }
    std::string address_of(const std::string& user) override { return user + "@example.test"; }
    void submit(const std::string&, const std::string&, std::vector<std::string>, std::string message,
                std::function<void(bool, std::string)> done, int64_t) override
    {
        // What goes out is held to what the SMTP side takes: lines that end in CRLF and nothing else.
        for (size_t i = 0; i < message.size(); ++i)
            if (message[i] == '\n')
                FUZZ_CHECK(i > 0 && message[i - 1] == '\r', "JMAP submitted a message with a bare LF");
        answer([done = std::move(done)] { done(true, "Q1"); });
    }
};

void check_jmap_output(std::string_view r, bool streamed, bool api_only)
{
    namespace js = socketley::json;
    while (!r.empty())
    {
        FUZZ_CHECK(r.starts_with("HTTP/1.1 "), "JMAP said what is no HTTP response");
        const size_t end = r.find("\r\n\r\n");
        FUZZ_CHECK(end != std::string_view::npos, "JMAP said a head that does not end");
        const std::string_view head = r.substr(0, end + 2);
        r.remove_prefix(end + 4);
        const int code = (head[9] - '0') * 100 + (head[10] - '0') * 10 + (head[11] - '0');
        for (size_t at = head.find("\r\n") + 2; at < head.size();)
        {
            const size_t nl = head.find("\r\n", at);
            const std::string_view field = head.substr(at, nl - at);
            FUZZ_CHECK(field.find(':') != std::string_view::npos && field.find('\r') == std::string_view::npos &&
                           field.find('\n') == std::string_view::npos,
                       "JMAP said a header that is no field");
            at = nl + 2;
        }
        const size_t cl = head.find("\r\nContent-Length: ");
        if (cl == std::string_view::npos)
        {
            // Only an EventSource and a 304 say no length, and an EventSource is the last thing a connection says.
            FUZZ_CHECK(code == 304 || streamed, "JMAP said a response of no length");
            if (code == 304)
                continue;
            return;
        }
        size_t n = 0;
        const char* p = head.data() + cl + 18;
        const auto res = std::from_chars(p, head.data() + head.size(), n);
        FUZZ_CHECK(res.ec == std::errc() && n <= r.size(), "JMAP said a body shorter than its Content-Length");
        const std::string_view body = r.substr(0, n);
        r.remove_prefix(n);
        if (head.find("\r\nContent-Type: application/json") != std::string_view::npos && !body.empty())
        {
            js::jvalue doc;
            js::json_policy policy;
            policy.object_root = false;
            policy.max_depth = 64;
            FUZZ_CHECK(js::json_reader(body, policy).document(doc), "JMAP said JSON that does not read");
            if (api_only && code == 200)
                FUZZ_CHECK(doc.k == js::jvalue::kind::object, "a JMAP API answer that is no object");
        }
    }
}

void jmap_case(std::string_view in, bool api_body)
{
    // On the heap: ASan's fake stack, on by default in newer runtimes, aligns a local to 32 bytes, not 64.
    const auto owned = std::make_unique<world>();
    world& w = *owned;
    jmap_hooks h;
    jmap_config cfg;
    cfg.hostname = "mx.example.test";
    cfg.login_in_clear = true;
    cfg.max_size = 64u << 10;
    bool streamed = false;
    {
        jmap_session s(cfg, h, w.store);
        if (api_body)
        {
            std::string rq = "POST /jmap/api HTTP/1.1\r\nHost: mx.example.test\r\nAuthorization: Basic dTpw\r\n"
                             "Content-Type: application/json\r\nContent-Length: " + std::to_string(in.size()) + "\r\n\r\n";
            rq.append(in);
            s.input(rq);
            settle();
        }
        else
            while (!in.empty() && !h.closed)
            {
                const size_t cut = in.find('\xff');
                s.input(in.substr(0, cut));
                in = cut == std::string_view::npos ? std::string_view{} : in.substr(cut + 1);
                settle();
                if (s.streaming())
                    s.poll();
                FUZZ_CHECK(s.buffered() <= jmap_session::max_request + jmap_session::max_head + (128u << 10),
                           "JMAP keeps more of its input than its largest request");
            }
        if (!g_late)
            settle();
        streamed = s.streaming();
    }
    settle();
    check_jmap_output(h.out, streamed, api_body);
}

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz::current_data() = data;
    fuzz::current_size() = size;
    if (size < 2 || size > (48u << 10))
        return 0;
    g_late = data[1] & 1;
    const std::string_view in(reinterpret_cast<const char*>(data) + 2, size - 2);
    switch (data[0] % 4)
    {
        case 0: imap_case(in, false); break;
        case 1: imap_case(in, true); break;
        case 2: jmap_case(in, false); break;
        case 3: jmap_case(in, true); break;
    }
    g_owed.clear();
    g_objects.clear();
    return 0;
}
