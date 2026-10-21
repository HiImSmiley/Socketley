#include "imap_store.h"

#include <algorithm>
#include <filesystem>
#include <set>

#include "mail_instance.h"
#include "mail_mailbox.h"
#include "mail_run.h"
#include "mail_spool.h"
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
    // Every one, since a save handed to the pool before the stop may never have been written.
    for (auto& [name, u] : m_users)
        if (u.loaded)
            save(name, true);
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
    u.dirty = true;
    return f;
}

imap_store::user_state& imap_store::user(const std::string& name)
{
    user_state& u = m_users[name];
    if (!u.loaded)
    {
        u.loaded = true;
        load(name, u);
        for (const auto& [f, use] : special())
            if (!u.folders.count(f))
                make_folder(u, f);
    }
    return u;
}

void imap_store::load(const std::string& name, user_state& u)
{
    std::string text;
    if (!socketley::read_file(path_of(name), text, {.missing_ok = true}, nullptr) || !text.starts_with("SKLIMAP1\n"))
        return;
    std::string_view rest = std::string_view(text).substr(9);
    std::shared_ptr<imap_folder> f;
    while (!rest.empty())
    {
        std::string_view line = socketley::take_item(rest, '\n');
        if (line.size() < 2)
            continue;
        std::vector<std::string_view> w;
        std::string_view l = line.substr(2);
        // F <uidvalidity> <uidnext> <subscribed> <name>, M <uid> <flags> <size> <date> <key>; the last word may hold spaces.
        const int fixed = line[0] == 'F' ? 3 : 4;
        for (int i = 0; i < fixed; ++i)
        {
            const size_t sp = l.find(' ');
            w.push_back(l.substr(0, sp));
            l = sp == std::string_view::npos ? std::string_view{} : l.substr(sp + 1);
        }
        const auto num = [](std::string_view s) { return std::strtoull(std::string(s).c_str(), nullptr, 10); };
        if (line[0] == 'F' && !l.empty())
        {
            f = std::make_shared<imap_folder>();
            f->name = std::string(l);
            f->uidvalidity = static_cast<uint32_t>(num(w[0]));
            f->uidnext = static_cast<uint32_t>(num(w[1]));
            f->subscribed = w[2] == "1";
            u.folders[f->name] = f;
        }
        else if (line[0] == 'M' && f && !l.empty())
        {
            imap_message m;
            m.uid = static_cast<uint32_t>(num(w[0]));
            m.flags = static_cast<uint8_t>(num(w[1]));
            m.size = num(w[2]);
            m.date_ms = static_cast<int64_t>(num(w[3]));
            m.key = std::string(l);
            m.recent = false;
            f->msgs.push_back(std::move(m));
        }
    }
    for (auto& [n, folder] : u.folders)
        std::sort(folder->msgs.begin(), folder->msgs.end(),
                  [](const imap_message& a, const imap_message& b) { return a.uid < b.uid; });
}

void imap_store::save(const std::string& name, bool now)
{
    auto it = m_users.find(name);
    if (it == m_users.end())
        return;
    it->second.dirty = false;
    std::string text = "SKLIMAP1\n";
    for (const auto& [n, f] : it->second.folders)
    {
        text += "F " + std::to_string(f->uidvalidity) + " " + std::to_string(f->uidnext) + " " +
                (f->subscribed ? "1" : "0") + " " + n + "\n";
        for (const auto& m : f->msgs)
            text += "M " + std::to_string(m.uid) + " " + std::to_string(m.flags) + " " + std::to_string(m.size) + " " +
                    std::to_string(m.date_ms) + " " + m.key + "\n";
    }
    // Written by a helper thread, since its sync is the disk's and not the loop's to wait for; in line at a stop.
    const std::string path = path_of(name);
    auto write = [path, text = std::move(text)] {
        std::error_code ec;
        std::filesystem::create_directories(std::filesystem::path(path).parent_path(), ec);
        std::string why;
        if (!socketley::replace_file(path, text, socketley::durability::data, &why))
            LOG_WARN(("mail: the IMAP index " + path + " could not be written: " + why).c_str());
    };
    if (now || !m_run.pool().enabled())
        write();
    else
        m_run.pool().submit(0, std::move(write), [] {});
}

void imap_store::touched(const std::string& name)
{
    m_users[name].dirty = true;
}

void imap_store::tick(int64_t)
{
    for (auto& [name, u] : m_users)
        if (u.dirty)
            save(name);
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
                   if (st == request_status::ok && rpc::decode(bytes, rpc::op::list, r) && r.ok)
                       for (const auto& p : r.prefixes)
                       {
                           std::string f = p.substr(name.size() + 1);
                           if (!f.empty() && f.back() == '/')
                               f.pop_back();
                           if (!f.empty() && !u.folders.count(canonical(f)))
                               make_folder(u, canonical(f));
                       }
                   std::vector<std::string> out;
                   for (const auto& [n, f] : u.folders)
                       out.push_back(n);
                   done(std::move(out));
               });
}

bool imap_store::create(const std::string& name, const std::string& folder)
{
    user_state& u = user(name);
    const std::string f = canonical(folder);
    if (u.folders.count(f) || f.empty() || f.find_first_of("\r\n*%") != std::string::npos)
        return false;
    make_folder(u, f);
    return true;
}

void imap_store::set_subscribed(const std::string& name, const std::string& folder, bool on)
{
    user_state& u = user(name);
    if (const auto it = u.folders.find(canonical(folder)); it != u.folders.end())
    {
        it->second->subscribed = on;
        u.dirty = true;
    }
}

void imap_store::open(const std::string& name, const std::string& folder,
                      std::function<void(std::shared_ptr<imap_folder>)> done, bool force)
{
    user_state& u = user(name);
    const auto it = u.folders.find(canonical(folder));
    if (it == u.folders.end())
    {
        done(nullptr);
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
                       std::set<std::string> known;
                       const size_t before = f->msgs.size();
                       std::erase_if(f->msgs, [&](const imap_message& m) { return !there.count(m.key); });
                       bool changed = f->msgs.size() != before;
                       for (const auto& m : f->msgs)
                           known.insert(m.key);
                       std::sort(acc->begin(), acc->end());
                       for (const auto& [k, v] : *acc)
                           if (!known.count(k))
                           {
                               f->msgs.push_back({f->uidnext++, k, v.first, v.second, 0, true});
                               changed = true;
                           }
                       if (changed)
                       {
                           ++f->version;
                           user(name).dirty = true;
                       }
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

void imap_store::expunge(const std::string& name, const std::shared_ptr<imap_folder>& f,
                         const std::vector<uint32_t>& only, std::function<void(std::vector<uint32_t>)> done)
{
    std::vector<std::pair<uint32_t, std::string>> going;
    for (const auto& m : f->msgs)
        if ((m.flags & flag_deleted) && (only.empty() || std::find(only.begin(), only.end(), m.uid) != only.end()))
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
            {
                gone->push_back(uid);
                std::erase_if(f->msgs, [uid](const imap_message& m) { return m.uid == uid; });
            }
            if (--*left)
                return;
            ++f->version;
            touched(name);
            std::sort(gone->begin(), gone->end());
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
            touched(name);
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
            put_object(key, *b, [dest, j, m, key, self](bool ok) {
                if (!ok)
                {
                    j->ok = false;
                    (*self)();
                    return;
                }
                const uint32_t uid = dest->uidnext++;
                dest->msgs.push_back({uid, key, m.size, m.date_ms, static_cast<uint8_t>(m.flags & ~flag_deleted), true});
                ++dest->version;
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
    put_object(key, std::move(message), [this, name, f, key, size, flags, date_ms, done](bool ok) {
        if (!ok)
        {
            done(false, 0, 0);
            return;
        }
        const uint32_t uid = f->uidnext++;
        f->msgs.push_back({uid, key, size, date_ms, flags, true});
        ++f->version;
        touched(name);
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
        for (auto& m : f->msgs)
            m.flags |= flag_deleted;
        expunge(name, f, {}, [this, name, fname, done](std::vector<uint32_t>) {
            m_users[name].folders.erase(fname);
            touched(name);
            done(true);
        });
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
        std::vector<uint32_t> uids;
        for (const auto& m : f->msgs)
            uids.push_back(m.uid);
        copy(name, f, uids, b, [this, name, a, done](bool ok, uint32_t, std::vector<uint32_t>) {
            if (!ok)
            {
                done(false);
                return;
            }
            remove(name, a, done);
        });
    }, true);
}

}   // namespace socketley::mail
