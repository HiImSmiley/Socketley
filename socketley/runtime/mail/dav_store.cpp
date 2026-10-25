#include "dav_store.h"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>

#include "mail_mailbox.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/storage/storage_rpc.h"

namespace socketley::mail
{

namespace rpc = socketley::storage_rpc;

namespace
{

// A collection holds this many entries at most, ten pages of a listing.
constexpr size_t max_entries = 10000;

// An etag as the storage gave it, without the quotes HTTP puts around it, which the DAV answer adds once.
std::string bare(std::string_view e)
{
    if (e.size() >= 2 && e.front() == '"' && e.back() == '"')
        e = e.substr(1, e.size() - 2);
    return std::string(e);
}

}   // namespace

bool dav_store::collection_ok(std::string_view name)
{
    if (name.empty() || name.size() > 64 || name.front() == '.')
        return false;
    return std::all_of(name.begin(), name.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' ||
               c == '-';
    });
}

bool dav_store::entry_ok(std::string_view name)
{
    if (name.empty() || name.size() > 255 || name.front() == '.')
        return false;
    return std::all_of(name.begin(), name.end(), [](char c) {
        const auto u = static_cast<unsigned char>(c);
        return u > 0x20 && u != 0x7F && c != '/' && c != '\\';
    });
}

std::string dav_store::key_of(const std::string& user, const std::string& kind, const std::string& coll,
                              const std::string& name) const
{
    return ".dav/" + user + "/" + kind + "/" + coll + "/" + name;
}

std::string dav_store::journal_of(const std::string& user, const std::string& kind, const std::string& coll) const
{
    return m_dir + "/" + user + "/" + kind + "-" + coll + ".log";
}

void dav_store::list_page(std::string prefix, std::string after, std::shared_ptr<std::vector<entry>> got,
                          std::shared_ptr<std::vector<std::string>> prefixes, bool folders, std::function<void(bool)> done)
{
    rpc::request rq;
    rq.kind = rpc::op::list;
    rq.bucket = m_boxes.bucket();
    rq.prefix = prefix;
    rq.delimiter = "/";
    rq.start_after = after;
    m_boxes.ask(m_boxes.storage(), rpc::encode(rq),
                [this, prefix, got, prefixes, folders, done, alive = m_alive](request_status st, std::string_view bytes) {
                    if (!*alive)
                        return;
                    rpc::reply r;
                    // A bucket not made yet holds nothing.
                    if (st != request_status::ok || !rpc::decode(bytes, rpc::op::list, r))
                        return done(false);
                    if (!r.ok)
                        return done(r.code == "NoSuchBucket");
                    std::string last;
                    for (auto& o : r.objects)
                    {
                        last = o.key;
                        std::string name = o.key.substr(prefix.size());
                        if (!folders && !name.empty() && name.front() != '.')
                            got->push_back({std::move(name), bare(o.etag), o.size, o.mtime_ms});
                    }
                    for (const auto& p : r.prefixes)
                    {
                        last = std::max(last, p);
                        std::string name = p.substr(prefix.size());
                        if (!name.empty() && name.back() == '/')
                            name.pop_back();
                        if (folders && collection_ok(name))
                            prefixes->push_back(std::move(name));
                    }
                    if (r.truncated && !last.empty() && got->size() < max_entries && prefixes->size() < 1000)
                        return list_page(prefix, last, got, prefixes, folders, done);
                    done(true);
                });
}

void dav_store::collections(const std::string& user, const std::string& kind,
                            std::function<void(bool, std::vector<std::string>)> done)
{
    auto got = std::make_shared<std::vector<entry>>();
    auto names = std::make_shared<std::vector<std::string>>();
    list_page(".dav/" + user + "/" + kind + "/", {}, got, names, true, [kind, names, done](bool ok) {
        std::vector<std::string> out{std::string(default_of(kind))};
        for (auto& n : *names)
            if (n != out.front())
                out.push_back(std::move(n));
        done(ok, std::move(out));
    });
}

void dav_store::entries(const std::string& user, const std::string& kind, const std::string& coll,
                        std::function<void(bool, std::vector<entry>)> done)
{
    auto got = std::make_shared<std::vector<entry>>();
    auto names = std::make_shared<std::vector<std::string>>();
    list_page(key_of(user, kind, coll, ""), {}, got, names, false, [got, done](bool ok) { done(ok, std::move(*got)); });
}

void dav_store::get(const std::string& user, const std::string& kind, const std::string& coll, const std::string& name,
                    std::function<void(bool, bool, std::string, std::string)> done)
{
    rpc::request rq;
    rq.kind = rpc::op::get;
    rq.bucket = m_boxes.bucket();
    rq.key = key_of(user, kind, coll, name);
    m_boxes.ask(m_boxes.storage(), rpc::encode(rq), [done, alive = m_alive](request_status st, std::string_view bytes) {
        if (!*alive)
            return;
        rpc::reply r;
        if (st != request_status::ok || !rpc::decode(bytes, rpc::op::get, r))
            return done(false, false, {}, {});
        if (!r.ok)
            return done(r.code == "NoSuchKey" || r.code == "NoSuchBucket", false, {}, {});
        done(true, true, std::move(r.data), bare(r.info.etag));
    });
}

void dav_store::head(const std::string& user, const std::string& kind, const std::string& coll, const std::string& name,
                     std::function<void(bool, std::string)> done)
{
    rpc::request rq;
    rq.kind = rpc::op::head;
    rq.bucket = m_boxes.bucket();
    rq.key = key_of(user, kind, coll, name);
    m_boxes.ask(m_boxes.storage(), rpc::encode(rq), [done, alive = m_alive](request_status st, std::string_view bytes) {
        if (!*alive)
            return;
        rpc::reply r;
        if (st != request_status::ok || !rpc::decode(bytes, rpc::op::head, r))
            return done(false, {});
        if (!r.ok)
            return done(r.code == "NoSuchKey" || r.code == "NoSuchBucket" || r.code == "NotFound", {});
        done(true, bare(r.info.etag));
    });
}

void dav_store::put(const std::string& user, const std::string& kind, const std::string& coll, const std::string& name,
                    std::string data, std::string type, std::function<void(std::string)> done)
{
    m_boxes.make_bucket([this, user, kind, coll, name, data = std::move(data), type = std::move(type), done,
                         alive = m_alive](bool made) mutable {
        if (!*alive)
            return;
        if (!made)
            return done({});
        rpc::request rq;
        rq.kind = rpc::op::put;
        rq.bucket = m_boxes.bucket();
        rq.key = key_of(user, kind, coll, name);
        rq.data = std::move(data);
        rq.content_type = std::move(type);
        m_boxes.ask(m_boxes.storage(), rpc::encode(rq),
                    [this, user, kind, coll, name, done, alive](request_status st, std::string_view bytes) {
                        if (!*alive)
                            return;
                        rpc::reply r;
                        if (st != request_status::ok || !rpc::decode(bytes, rpc::op::put, r) || !r.ok)
                            return done({});
                        if (!name.starts_with("."))
                            note(user, kind, coll, name, false);
                        done(r.info.etag.empty() ? std::string("0") : bare(r.info.etag));
                    });
    });
}

void dav_store::remove(const std::string& user, const std::string& kind, const std::string& coll,
                       const std::string& name, std::function<void(bool)> done)
{
    rpc::request rq;
    rq.kind = rpc::op::del;
    rq.bucket = m_boxes.bucket();
    rq.key = key_of(user, kind, coll, name);
    m_boxes.ask(m_boxes.storage(), rpc::encode(rq),
                [this, user, kind, coll, name, done, alive = m_alive](request_status st, std::string_view bytes) {
                    if (!*alive)
                        return;
                    rpc::reply r;
                    const bool ok = st == request_status::ok && rpc::decode(bytes, rpc::op::del, r) && r.ok;
                    if (ok && !name.starts_with("."))
                        note(user, kind, coll, name, true);
                    done(ok);
                });
}

void dav_store::remove_collection(const std::string& user, const std::string& kind, const std::string& coll,
                                  std::function<void(bool)> done)
{
    entries(user, kind, coll, [this, user, kind, coll, done, alive = m_alive](bool ok, std::vector<entry> all) {
        if (!*alive)
            return;
        if (!ok)
            return done(false);
        auto names = std::make_shared<std::vector<std::string>>();
        for (auto& e : all)
            names->push_back(std::move(e.name));
        names->push_back(".props");
        remove_each(user, kind, coll, names, 0, true, done);
    });
}

void dav_store::remove_each(const std::string& user, const std::string& kind, const std::string& coll,
                            std::shared_ptr<std::vector<std::string>> names, size_t i, bool all_ok,
                            std::function<void(bool)> done)
{
    if (i == names->size())
        return done(all_ok);
    const std::string name = (*names)[i];
    remove(user, kind, coll, name, [this, user, kind, coll, names, i, all_ok, done](bool one) {
        remove_each(user, kind, coll, names, i + 1, all_ok && one, done);
    });
}

void dav_store::props(const std::string& user, const std::string& kind, const std::string& coll,
                      std::function<void(bool, bool, std::vector<std::pair<std::string, std::string>>)> done)
{
    get(user, kind, coll, ".props", [done](bool ok, bool found, std::string data, std::string) {
        std::vector<std::pair<std::string, std::string>> out;
        for (std::string_view rest = data; !rest.empty();)
        {
            const size_t nl = rest.find('\n');
            const std::string_view line = rest.substr(0, nl);
            rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
            const size_t tab = line.find('\t');
            if (tab != std::string_view::npos)
                out.emplace_back(std::string(line.substr(0, tab)), std::string(line.substr(tab + 1)));
        }
        done(ok, found, std::move(out));
    });
}

void dav_store::set_props(const std::string& user, const std::string& kind, const std::string& coll,
                          const std::vector<std::pair<std::string, std::string>>& props, std::function<void(bool)> done)
{
    std::string text;
    for (const auto& [k, v] : props)
    {
        std::string value = v;
        std::replace(value.begin(), value.end(), '\n', ' ');
        std::replace(value.begin(), value.end(), '\r', ' ');
        text += k + "\t" + value + "\n";
    }
    put(user, kind, coll, ".props", std::move(text), "text/plain", [done](std::string etag) { done(!etag.empty()); });
}

void dav_store::note(const std::string& user, const std::string& kind, const std::string& coll, const std::string& name,
                     bool gone)
{
    const std::string path = journal_of(user, kind, coll);
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(path).parent_path(), ec);
    // One write of one line with O_APPEND, so two shards noting at once each add a whole line.
    const std::string line = std::string(gone ? "-" : "+") + "\t" + name + "\n";
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    if (::write(fd, line.data(), line.size()) < 0) {}
    ::close(fd);
}

bool dav_store::read_journal(const std::string& path, uint64_t& base, std::vector<std::pair<std::string, bool>>& lines) const
{
    base = 0;
    lines.clear();
    std::string text;
    if (!socketley::read_file(path, text))
        return true;
    for (std::string_view rest = text; !rest.empty();)
    {
        const size_t nl = rest.find('\n');
        // A line still being written by another shard is not one yet.
        if (nl == std::string_view::npos)
            break;
        const std::string_view line = rest.substr(0, nl);
        rest = rest.substr(nl + 1);
        if (line.size() > 2 && (line[0] == '+' || line[0] == '-') && line[1] == '\t')
            lines.emplace_back(std::string(line.substr(2)), line[0] == '-');
    }
    return true;
}

uint64_t dav_store::token(const std::string& user, const std::string& kind, const std::string& coll) const
{
    uint64_t base = 0;
    std::vector<std::pair<std::string, bool>> lines;
    read_journal(journal_of(user, kind, coll), base, lines);
    return base + lines.size();
}

bool dav_store::changes_since(const std::string& user, const std::string& kind, const std::string& coll,
                              uint64_t since, std::vector<std::pair<std::string, bool>>& out) const
{
    out.clear();
    uint64_t base = 0;
    std::vector<std::pair<std::string, bool>> lines;
    read_journal(journal_of(user, kind, coll), base, lines);
    if (since < base || since > base + lines.size())
        return false;
    for (size_t i = static_cast<size_t>(since - base); i < lines.size(); ++i)
    {
        auto it = std::find_if(out.begin(), out.end(), [&](const auto& c) { return c.first == lines[i].first; });
        if (it == out.end())
            out.push_back(lines[i]);
        else
            it->second = lines[i].second;
    }
    return true;
}

}   // namespace socketley::mail
