#include "idp_accounts.h"
#include "../../shared/loop/file_io.h"
#include "../../shared/util/settings.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <unordered_set>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>


#include "idp_logic.h"
#include "../../shared/util/byte_codec.h"
#include "../../shared/json/json_doc.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/persist/replaced_file.h"
#include "../../shared/util/random_id.h"
#include "../../shared/util/text_list.h"

namespace socketley::idp
{

namespace
{

constexpr uint8_t op_put    = 1;
constexpr uint8_t op_remove = 2;
constexpr std::string_view journal_owner = "socketley-idp-accounts";
// Past this many records the journal is folded into a snapshot, so a start replays a bounded tail.
uint64_t compact_after()
{
    static const uint64_t n = socketley::settings::number<uint64_t>("SOCKETLEY_IDP_COMPACT_AFTER").value_or(1000);
    return n;
}

std::string lower(std::string_view s)
{
    std::string out(s);
    for (char& c : out)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

// A rename kept by syncing the directory that holds it.
void sync_dir_of(const std::string& path)
{
    const std::string dir = std::filesystem::path(path).parent_path().string();
    if (const int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC); dfd >= 0)
    {
        if (::fsync(dfd) != 0) {}
        ::close(dfd);
    }
}

// Written beside and renamed into place after its bytes are on the disk, so a crash leaves the old file or the new.
bool write_whole(const std::string& path, const std::string& data)
{
    return replace_file(path, data, durability::data_and_dir);
}

}   // namespace

std::string_view account::field(std::string_view name) const
{
    const auto it = fields.find(name);
    return it == fields.end() ? std::string_view{} : std::string_view(it->second);
}

bool account::in_group(std::string_view group) const
{
    std::string_view g = field("groups");
    while (!g.empty())
    {
        std::string_view one = take_item(g);
        while (!one.empty() && one.front() == ' ')
            one.remove_prefix(1);
        while (!one.empty() && one.back() == ' ')
            one.remove_suffix(1);
        if (one == group)
            return true;
    }
    return false;
}

bool account_store::valid_field_name(std::string_view name)
{
    if (name.empty() || name.size() > 64)
        return false;
    return std::all_of(name.begin(), name.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == ':';
    });
}

bool account_store::valid_username(std::string_view name)
{
    if (name.empty() || name.size() > 64)
        return false;
    return std::all_of(name.begin(), name.end(), [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-' || c == '@' || c == '+';
    });
}

void account_store::index(const account& a)
{
    if (const std::string_view u = a.username(); !u.empty())
        m_names[lower(u)] = a.id;
    if (const std::string_view e = a.field("email"); !e.empty())
        m_emails.emplace(lower(e), a.id);
}

void account_store::unindex(const account& a)
{
    if (const std::string_view u = a.username(); !u.empty())
        if (const auto it = m_names.find(lower(u)); it != m_names.end() && it->second == a.id)
            m_names.erase(it);
    if (const std::string_view e = a.field("email"); !e.empty())
        for (auto [it, end] = m_emails.equal_range(lower(e)); it != end; ++it)
            if (it->second == a.id)
            {
                m_emails.erase(it);
                break;
            }
}

bool account_store::apply(std::string_view record)
{
    ++m_changes;
    socketley::bytes::reader r(record);
    uint8_t op = 0;
    std::string id;
    if (!r.u8(op) || !r.bytes(id, 64) || id.empty())
        return false;
    if (op == op_remove)
    {
        if (const auto it = m_accounts.find(id); it != m_accounts.end())
        {
            unindex(it->second);
            m_accounts.erase(it);
            ++m_standing_changes;
            note_standing(id);
        }
        return true;
    }
    if (op != op_put)
        return false;
    uint32_t n = 0;
    if (!r.u32(n) || n > max_fields)
        return false;
    field_list fl;
    for (uint32_t i = 0; i < n; ++i)
    {
        std::string k, v;
        if (!r.bytes(k, 64) || !r.bytes(v, max_value))
            return false;
        fl.emplace_back(std::move(k), std::move(v));
    }
    const auto [it, made] = m_accounts.try_emplace(id);
    account& a = it->second;
    a.id = id;
    unindex(a);
    if (made || std::any_of(fl.begin(), fl.end(), [](const auto& kv) { return shapes_standing(kv.first); }))
    {
        ++m_standing_changes;
        note_standing(id);
    }
    for (auto& [k, v] : fl)
    {
        if (v.empty())
            a.fields.erase(k);
        else
            a.fields[k] = std::move(v);
    }
    index(a);
    return true;
}

bool account_store::read_snapshot(const std::string& path, std::string& why)
{
    // Accounts read again are a standing to be made again.
    ++m_standing_changes;
    m_standing_all = true;
    m_standing_dirty.clear();
    std::ifstream f(path);
    if (!f)
        return true;   // no snapshot yet: everything is in the journal
    using socketley::json::json_reader;
    using socketley::json::jvalue;
    std::string line;
    size_t line_no = 0;
    bool header = false;
    while (std::getline(f, line))
    {
        ++line_no;
        if (line.empty())
            continue;
        jvalue v;
        if (!json_reader(line).document(v))
        {
            why = path + " line " + std::to_string(line_no) + " is not JSON";
            return false;
        }
        if (!header)
        {
            std::string format;
            uint64_t version = 0;
            for (const auto& [k, m] : v.members)
            {
                if (k == "format" && m.k == jvalue::kind::string)
                    format = m.s;
                else if (k == "version" && m.k == jvalue::kind::number)
                    version = std::strtoull(m.s.c_str(), nullptr, 10);
            }
            if (format != journal_owner)
            {
                why = path + " is not an accounts snapshot";
                return false;
            }
            // A newer build's snapshot is left alone rather than read in part and written back without the rest.
            if (version > format_version)
            {
                why = path + " is version " + std::to_string(version) + ", newer than this build reads (" +
                      std::to_string(format_version) + "); start the build that wrote it";
                return false;
            }
            header = true;
            continue;
        }
        account a;
        for (const auto& [k, m] : v.members)
        {
            if (k == "id" && m.k == jvalue::kind::string)
                a.id = m.s;
            else if (k == "fields" && m.k == jvalue::kind::object)
                for (const auto& [fk, fv] : m.members)
                    if (fv.k == jvalue::kind::string && !fv.s.empty())
                        a.fields[fk] = fv.s;
        }
        if (a.id.empty())
        {
            why = path + " line " + std::to_string(line_no) + " has no id";
            return false;
        }
        index(a);
        m_accounts[a.id] = std::move(a);
    }
    return true;
}

bool account_store::open(const std::string& dir, std::string& why)
{
    close();
    m_dir = dir;
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (!std::filesystem::is_directory(dir, ec))
    {
        why = "the accounts directory " + dir + " cannot be made";
        return false;
    }
    if (::chmod(dir.c_str(), 0700) != 0) {}
    if (!read_snapshot(dir + "/accounts.snapshot", why))
        return false;
    const std::string jpath = dir + "/accounts.journal";
    std::string owner;
    const auto probe = mutation_journal::probe(jpath, owner);
    if (probe == mutation_journal::probe_result::not_a_journal ||
        probe == mutation_journal::probe_result::unreadable ||
        (probe == mutation_journal::probe_result::has_records && owner != journal_owner))
    {
        why = jpath + " is not this provider's journal";
        return false;
    }
    if (probe == mutation_journal::probe_result::has_records)
    {
        mutation_journal::replay_stats st;
        bool bad = false;
        mutation_journal::replay(jpath, [&](std::string_view rec) {
            if (!apply(rec))
                bad = true;
            ++m_journal_records;
        }, st);
        if (bad)
        {
            why = jpath + " holds a record this build cannot read";
            return false;
        }
    }
    if (!m_journal.open_append(jpath, journal_owner))
    {
        why = jpath + " cannot be opened for writing";
        return false;
    }
    note_journal();
    if (m_journal_records >= compact_after() && !compact(why))
        return false;
    return true;
}

void account_store::note_journal()
{
    struct stat st{};
    if (m_journal.fd() >= 0 && ::fstat(m_journal.fd(), &st) == 0)
    {
        m_journal_id = static_cast<uint64_t>(st.st_ino);
        m_journal_end = static_cast<uint64_t>(st.st_size);
    }
}

bool account_store::follow_open(const std::string& dir, std::string& why)
{
    close();
    m_dir = dir;
    m_following = true;
    const std::string jpath = dir + "/accounts.journal";
    // The journal before the snapshot, so a compaction between the two leaves records the snapshot holds already,
    // which change nothing read again, rather than records neither holds.
    m_follow_fd = ::open(jpath.c_str(), O_RDONLY | O_CLOEXEC);
    if (!read_snapshot(dir + "/accounts.snapshot", why))
        return false;
    struct stat st{};
    // A journal the writer has made and not yet begun is one it has written nothing to.
    if (m_follow_fd >= 0 && ::fstat(m_follow_fd, &st) == 0 && st.st_size == 0)
    {
        ::close(m_follow_fd);
        m_follow_fd = -1;
    }
    if (m_follow_fd < 0)
        return true;   // the writer has written nothing yet
    std::string owner;
    if (::fstat(m_follow_fd, &st) != 0 ||
        !mutation_journal::replay_fd(m_follow_fd, owner, [this](std::string_view rec) {
            if (apply(rec))
                ++m_journal_records;
        }, m_follow_off) ||
        owner != journal_owner)
    {
        why = jpath + " is not this provider's journal";
        return false;
    }
    m_journal_id = static_cast<uint64_t>(st.st_ino);
    return true;
}

bool account_store::follow(uint64_t journal, uint64_t end)
{
    if (!m_following || journal == 0)
        return true;
    if (journal != m_journal_id)
        return false;
    if (end > m_follow_off)
        m_follow_off = mutation_journal::tail(m_follow_fd, m_follow_off, end, [this](std::string_view rec) {
            if (apply(rec))
                ++m_journal_records;
        });
    return true;
}

void account_store::take_followed(account_store& fresh)
{
    m_accounts.swap(fresh.m_accounts);
    m_names.swap(fresh.m_names);
    m_emails.swap(fresh.m_emails);
    std::swap(m_follow_fd, fresh.m_follow_fd);
    std::swap(m_follow_off, fresh.m_follow_off);
    std::swap(m_journal_id, fresh.m_journal_id);
    std::swap(m_journal_records, fresh.m_journal_records);
    m_dir = fresh.m_dir;
    m_following = true;
    // Accounts read again are a standing to be made again, as read_snapshot() says of its own store.
    ++m_changes;
    ++m_standing_changes;
    m_standing_all = true;
    m_standing_dirty.clear();
}

account_store::~account_store()
{
    if (m_follow_fd >= 0)
        ::close(m_follow_fd);
}

void account_store::close()
{
    // Its waiters are answered now, as refused, and a sync still in flight finds a store of another generation.
    ++m_gen;
    auto waiting = std::move(m_waiting);
    m_waiting.clear();
    for (auto& [seq, then] : waiting)
        then(false);
    if (m_loop && m_syncing)
        m_loop->close_fd(m_journal.release());
    m_journal.close();
    m_syncing = false;
    m_committed = m_synced = m_syncing_upto = m_synced_old = m_compact_from = 0;
    m_broken = false;
    m_compacting = false;
    m_tail.clear();
    m_compact_ready.reset();
    if (m_follow_fd >= 0)
        ::close(m_follow_fd);
    m_follow_fd = -1;
    m_follow_off = 0;
    m_following = false;
    m_accounts.clear();
    m_names.clear();
    m_emails.clear();
    m_journal_records = 0;
    m_journal_id = 0;
    m_journal_end = 0;
}

bool account_store::commit(const std::string& record, std::string& why)
{
    return commit_many({record}, why);
}

bool account_store::commit_many(const std::vector<std::string>& records, std::string& why)
{
    if (m_following)
    {
        why = "the accounts are written by shard 0";
        return false;
    }
    if (!m_journal.is_open())
    {
        why = "the accounts are not open";
        return false;
    }
    if (m_broken)
    {
        why = "the accounts' disk refused a change, so the store takes none until it is restarted";
        return false;
    }
    for (const auto& r : records)
        m_journal.append(r);
    if (!m_journal.flush())
    {
        why = "the change could not be written to the disk";
        return false;
    }
    // In the journal's file and so in a dump a restart replays; on the disk once the sync it goes in is done, which
    // the answer to it waits for (when_durable), while the loop goes on with the next request.
    struct stat st{};
    if (::fstat(m_journal.fd(), &st) == 0)
        m_flushed_end = static_cast<uint64_t>(st.st_size);
    for (const auto& r : records)
        apply(r);
    if (m_compacting)
        m_tail.insert(m_tail.end(), records.begin(), records.end());
    m_journal_records += records.size();
    ++m_committed;
    if (!m_io)
    {
        // No ring to sync through: the commit's own, as before.
        const bool ok = ::fdatasync(m_journal.fd()) == 0;
        if (ok)
            m_journal_end = m_flushed_end;
        m_syncing_upto = m_committed;
        synced(ok);
        if (!ok)
        {
            why = "the change could not be written to the disk";
            return false;
        }
        return true;
    }
    sync_next();
    return true;
}

void account_store::when_durable(std::function<void(bool)> then)
{
    if (m_synced >= m_committed)
    {
        then(!m_broken);
        return;
    }
    m_waiting.emplace_back(m_committed, std::move(then));
    sync_next();
}

void account_store::sync_next()
{
    if (m_syncing || !m_io || m_synced >= m_committed || !m_journal.is_open())
        return;
    m_syncing = true;
    m_syncing_upto = m_committed;
    const uint64_t end = m_flushed_end;
    const uint64_t gen = m_gen;
    if (!m_io->sync(m_journal.fd(), true, [this, end, gen](int64_t res) {
            if (gen != m_gen)
                return;
            m_syncing = false;
            if (res >= 0)
                m_journal_end = end;
            synced(res >= 0);
        }))
    {
        m_syncing = false;
        synced(false);
    }
}

void account_store::synced(bool ok)
{
    if (ok)
        m_synced_old = m_syncing_upto;
    else
        m_broken = true;
    m_synced = m_compacting ? std::min(m_synced_old, m_compact_from) : m_synced_old;
    // A compaction's fresh journal goes in once no sync names the old one.
    if (ok && m_compact_ready && !m_syncing)
    {
        auto job = std::move(m_compact_ready);
        compact_step(job, 7);
        return;
    }
    if (ok && !m_compacting && m_journal_records >= compact_after())
        compact_async();
    std::vector<std::pair<uint64_t, std::function<void(bool)>>> due;
    for (auto it = m_waiting.begin(); it != m_waiting.end();)
        if (!ok || it->first <= m_synced)
        {
            due.push_back(std::move(*it));
            it = m_waiting.erase(it);
        }
        else
            ++it;
    for (auto& [seq, then] : due)
        then(ok);
    if (ok)
        sync_next();
}

namespace
{

std::string snapshot_header()
{
    return "{\"format\":" + socketley::json::quote(journal_owner) + ",\"version\":" +
           std::to_string(account_store::format_version) + "}\n";
}

void append_snapshot_line(std::string& out, const account& a)
{
    out += "{\"id\":" + socketley::json::quote(a.id) + ",\"fields\":{";
    bool first = true;
    for (const auto& [k, v] : a.fields)
    {
        if (!first)
            out += ',';
        first = false;
        out += socketley::json::quote(k) + ":" + socketley::json::quote(v);
    }
    out += "}}\n";
}

}   // namespace

std::string account_store::snapshot_text() const
{
    std::string out = snapshot_header();
    for (const auto& [id, a] : m_accounts)
        append_snapshot_line(out, a);
    return out;
}

bool account_store::compact(std::string& why)
{
    if (m_compacting || m_syncing)
    {
        why = "a compaction or a sync is under way";
        return false;
    }
    const std::string out = snapshot_text();
    if (!write_whole(m_dir + "/accounts.snapshot", out))
    {
        why = "the accounts snapshot could not be written";
        return false;
    }
    // A new journal behind the snapshot that now holds the old one's effects, put in its place, so a shard still
    // reading the old one reads it to its end; a crash before this replays records the snapshot holds, which changes
    // nothing, since a record sets values rather than adding to them.
    const std::string jpath = m_dir + "/accounts.journal";
    const std::string fresh = jpath + ".new";
    ::unlink(fresh.c_str());
    m_journal.close();
    if (!m_journal.open_append(fresh, journal_owner) || !m_journal.sync() || ::rename(fresh.c_str(), jpath.c_str()) != 0)
    {
        ::unlink(fresh.c_str());
        if (!m_journal.open_append(jpath, journal_owner))
            why = "the journal could not be opened again after the snapshot";
        else
            why = "the journal could not be begun again behind the snapshot";
        note_journal();
        return false;
    }
    sync_dir_of(jpath);
    note_journal();
    m_journal_records = 0;
    return true;
}

struct account_store::compaction
{
    uint64_t gen{0};
    // The ids when it began, written a piece a completion with each account as it is then, which the tail replayed
    // over it leaves as it is because a record only sets fields or removes an account.
    std::vector<std::string> ids;
    size_t next_id{0};
    std::string text;
    uint64_t at{0};
    uint64_t written{0};
    int fd{-1};
    int dir{-1};
    size_t tail_in{0};
    mutation_journal fresh;
};

void account_store::compact_async()
{
    if (m_compacting || m_compact_ready || !m_io || !m_loop || m_following || !m_journal.is_open())
        return;
    auto job = std::make_shared<compaction>();
    job->gen = m_gen;
    job->ids.reserve(m_accounts.size());
    for (const auto& [id, a] : m_accounts)
        job->ids.push_back(id);
    job->text = snapshot_header();
    m_compacting = true;
    m_compact_from = m_committed;
    m_tail.clear();
    compact_step(job, 0);
}

// One step a completion: the snapshot written beside, synced, renamed and its directory synced; the fresh journal
// with the tail, synced, renamed and the directory synced; and, on the loop, the fresh journal taken.
void account_store::compact_step(const std::shared_ptr<compaction>& job, int step)
{
    // A store closed meanwhile: what the compaction holds open goes, and nothing else of it is done.
    if (job->gen != m_gen)
    {
        for (int* fd : {&job->fd, &job->dir})
            if (*fd >= 0)
            {
                ::close(*fd);
                *fd = -1;
            }
        return;
    }
    const std::string snap = m_dir + "/accounts.snapshot", jpath = m_dir + "/accounts.journal";
    const auto next = [this, job](int s) {
        return [this, job, s](int64_t res) {
            if (job->gen != m_gen)
            {
                if (s == 1 && res >= 0)
                    ::close(static_cast<int>(res));
                compact_step(job, -1);
                return;
            }
            if (res < 0)
            {
                compact_done(job, false);
                return;
            }
            if (s == 1)
                job->fd = static_cast<int>(res);
            if (s == 2)
                job->written += static_cast<uint64_t>(res);
            compact_step(job, s);
        };
    };
    bool queued = true;
    switch (step)
    {
        case 0:
            queued = m_io->openat(AT_FDCWD, snap + ".new", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600, next(1));
            break;
        case 1:
        case 2:
            // The next piece once this one is out, so the loop is held for a piece and not for the store.
            while (job->written == job->text.size() && job->next_id < job->ids.size())
            {
                job->at += job->written;
                job->written = 0;
                job->text.clear();
                for (; job->next_id < job->ids.size() && job->text.size() < (64u << 10); ++job->next_id)
                    if (const auto it = m_accounts.find(job->ids[job->next_id]); it != m_accounts.end())
                        append_snapshot_line(job->text, it->second);
            }
            if (job->written < job->text.size())
            {
                const auto n = static_cast<uint32_t>(std::min<uint64_t>(job->text.size() - job->written, 1u << 30));
                queued = m_io->pwrite(job->fd, job->text.data() + job->written, n, job->at + job->written, next(2));
                break;
            }
            queued = m_io->sync(job->fd, true, next(3));
            break;
        case 3:
            m_loop->close_fd(job->fd);
            job->fd = -1;
            queued = m_io->renameat(AT_FDCWD, snap + ".new", AT_FDCWD, snap, next(4));
            break;
        case 4:
        case 6:
            job->dir = ::open(m_dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            queued = job->dir >= 0 && m_io->sync(job->dir, false, [this, job, step](int64_t res) {
                if (job->gen != m_gen)
                {
                    compact_step(job, -1);
                    return;
                }
                m_loop->close_fd(job->dir);
                job->dir = -1;
                if (res < 0)
                    compact_done(job, false);
                else
                    compact_step(job, step + 1);
            });
            break;
        case 5:
        {
            // The fresh journal begins with what was committed since the snapshot was taken.
            ::unlink((jpath + ".new").c_str());
            if (!job->fresh.open_append(jpath + ".new", journal_owner))
            {
                compact_done(job, false);
                return;
            }
            for (; job->tail_in < m_tail.size(); ++job->tail_in)
                job->fresh.append(m_tail[job->tail_in]);
            if (!job->fresh.flush())
            {
                compact_done(job, false);
                return;
            }
            queued = m_io->sync(job->fresh.fd(), true, [this, job](int64_t res) {
                if (job->gen != m_gen)
                    return;
                if (res < 0)
                {
                    compact_done(job, false);
                    return;
                }
                m_loop->close_fd(job->fresh.release());
                if (!m_io->renameat(AT_FDCWD, m_dir + "/accounts.journal.new", AT_FDCWD, m_dir + "/accounts.journal",
                                    [this, job](int64_t r) {
                                        if (job->gen != m_gen)
                                            return;
                                        if (r < 0)
                                            compact_done(job, false);
                                        else
                                            compact_step(job, 6);
                                    }))
                    compact_done(job, false);
            });
            break;
        }
        case 7:
            // Taken on the loop once no sync names the old journal, which the rename has unlinked.
            if (m_syncing)
            {
                m_compact_ready = job;
                return;
            }
            compact_done(job, true);
            return;
        default:
            return;
    }
    if (!queued)
        compact_done(job, false);
}

void account_store::compact_done(const std::shared_ptr<compaction>& job, bool ok)
{
    if (job->fd >= 0)
        m_loop->close_fd(job->fd);
    if (job->dir >= 0)
        m_loop->close_fd(job->dir);
    job->fd = job->dir = -1;
    if (job->fresh.is_open())
        m_loop->close_fd(job->fresh.release());
    if (ok)
    {
        // The fresh journal, under the journal's name, with the rest of the tail behind what it was begun with.
        const std::string jpath = m_dir + "/accounts.journal";
        m_loop->close_fd(m_journal.release());
        ok = m_journal.open_append(jpath, journal_owner);
        if (ok)
        {
            struct stat st{};
            if (::fstat(m_journal.fd(), &st) == 0)
            {
                m_journal_id = static_cast<uint64_t>(st.st_ino);
                m_journal_end = static_cast<uint64_t>(st.st_size);
            }
            for (size_t i = job->tail_in; i < m_tail.size(); ++i)
                m_journal.append(m_tail[i]);
            ok = m_journal.flush();
            if (::fstat(m_journal.fd(), &st) == 0)
                m_flushed_end = static_cast<uint64_t>(st.st_size);
            m_journal_records = m_tail.size();
        }
        if (!ok)
            m_broken = true;
    }
    else
    {
        ::unlink((m_dir + "/accounts.snapshot.new").c_str());
        ::unlink((m_dir + "/accounts.journal.new").c_str());
    }
    m_compacting = false;
    m_tail.clear();
    if (m_broken)
    {
        synced(false);
        return;
    }
    // Where it went in, what was committed before it began is in the snapshot, and what came after is in the fresh
    // journal, on the disk once the next sync, of the fresh one, says so; where it failed, the old journal's syncs
    // stand as they were.
    if (ok)
        m_synced_old = m_compact_from;
    m_synced = m_synced_old;
    sync_next();
}

const account* account_store::by_id(std::string_view id) const
{
    const auto it = m_accounts.find(std::string(id));
    return it == m_accounts.end() ? nullptr : &it->second;
}

const account* account_store::by_name(std::string_view username) const
{
    const auto it = m_names.find(lower(username));
    return it == m_names.end() ? nullptr : by_id(it->second);
}

std::vector<const account*> account_store::all() const
{
    // Each key lower-cased once, not once a comparison.
    std::vector<std::pair<std::string, const account*>> keyed;
    keyed.reserve(m_accounts.size());
    for (const auto& [id, a] : m_accounts)
        keyed.emplace_back(lower(a.username()), &a);
    std::sort(keyed.begin(), keyed.end(), [](const auto& x, const auto& y) { return x.first < y.first; });
    std::vector<const account*> out;
    out.reserve(keyed.size());
    for (const auto& [k, a] : keyed)
        out.push_back(a);
    return out;
}

void account_store::note_standing(const std::string& id)
{
    // A shard that only follows the journal makes no standing, and past one an account the whole is made again.
    if (m_following || m_standing_all)
        return;
    if (m_standing_dirty.size() >= m_accounts.size())
    {
        m_standing_all = true;
        m_standing_dirty.clear();
        return;
    }
    m_standing_dirty.push_back(id);
}

bool account_store::take_standing_dirty(std::vector<std::string>& ids)
{
    const bool all = m_standing_all;
    m_standing_all = false;
    ids.swap(m_standing_dirty);
    m_standing_dirty.clear();
    return all;
}

std::vector<const account*> account_store::by_email(std::string_view email) const
{
    std::vector<const account*> out;
    for (auto [it, end] = m_emails.equal_range(lower(email)); it != end; ++it)
        if (const account* a = by_id(it->second))
            out.push_back(a);
    std::sort(out.begin(), out.end(), [](const account* x, const account* y) {
        return lower(x->username()) < lower(y->username());
    });
    return out;
}

namespace
{

bool fields_ok(const field_list& fields, std::string& why)
{
    if (fields.size() > account_store::max_fields)
    {
        why = "too many fields at once";
        return false;
    }
    for (const auto& [k, v] : fields)
    {
        if (!account_store::valid_field_name(k))
        {
            why = "the field name \"" + k + "\" may hold only a-z, 0-9 and . _ - :, at most 64";
            return false;
        }
        if (v.size() > account_store::max_value)
        {
            why = "the field \"" + k + "\" is longer than 64 KiB; keep large things in a storage and their address here";
            return false;
        }
    }
    return true;
}

std::string put_record(std::string_view id, const field_list& fields)
{
    socketley::bytes::writer w;
    w.u8(op_put);
    w.bytes(id);
    w.u32(static_cast<uint32_t>(fields.size()));
    for (const auto& [k, v] : fields)
    {
        w.bytes(k);
        w.bytes(v);
    }
    return w.take();
}

}   // namespace

bool account_store::create(const field_list& fields, std::string& id, std::string& why)
{
    if (!fields_ok(fields, why))
        return false;
    std::string_view username;
    for (const auto& [k, v] : fields)
        if (k == "username")
            username = v;
    if (!valid_username(username))
    {
        why = "a username is 1 to 64 letters, digits and . _ - @ +";
        return false;
    }
    if (by_name(username))
    {
        why = "the username \"" + std::string(username) + "\" is taken";
        return false;
    }
    id = random_b64url(16);
    if (id.empty() || m_accounts.contains(id))
    {
        why = "no randomness for an id";
        return false;
    }
    return commit(put_record(id, fields), why);
}

size_t account_store::create_many(const std::vector<field_list>& accounts, std::string& why)
{
    std::vector<std::string> records;
    std::unordered_set<std::string> names;
    for (const auto& fields : accounts)
    {
        std::string one;
        std::string_view username;
        for (const auto& [k, v] : fields)
            if (k == "username")
                username = v;
        const std::string lname = lower(username);
        if (!fields_ok(fields, one) || !valid_username(username))
            why += std::string(username) + ": " + (one.empty() ? "a username is 1 to 64 letters, digits and . _ - @ +" : one) + "\n";
        else if (by_name(username) || names.contains(lname))
            why += std::string(username) + ": the username is taken\n";
        else
        {
            const std::string id = random_b64url(16);
            if (id.empty())
            {
                why += std::string(username) + ": no randomness for an id\n";
                continue;
            }
            names.insert(lname);
            records.push_back(put_record(id, fields));
        }
    }
    if (records.empty())
        return 0;
    std::string err;
    if (!commit_many(records, err))
    {
        why += err + "\n";
        return 0;
    }
    return records.size();
}

bool account_store::update(std::string_view id, const field_list& fields, std::string& why)
{
    const account* a = by_id(id);
    if (!a)
    {
        why = "no such account";
        return false;
    }
    if (!fields_ok(fields, why))
        return false;
    for (const auto& [k, v] : fields)
        if (k == "username")
        {
            if (!valid_username(v))
            {
                why = "a username is 1 to 64 letters, digits and . _ - @ +";
                return false;
            }
            if (const account* other = by_name(v); other && other->id != a->id)
            {
                why = "the username \"" + v + "\" is taken";
                return false;
            }
        }
    return commit(put_record(id, fields), why);
}

bool account_store::remove(std::string_view id, std::string& why)
{
    if (!by_id(id))
    {
        why = "no such account";
        return false;
    }
    socketley::bytes::writer w;
    w.u8(op_remove);
    w.bytes(id);
    return commit(w.take(), why);
}

}   // namespace socketley::idp
