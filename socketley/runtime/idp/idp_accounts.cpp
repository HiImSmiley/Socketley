#include "idp_accounts.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>


#include "idp_logic.h"
#include "../../shared/util/byte_codec.h"
#include "../../shared/crypto/jws.h"
#include "../../shared/json/json_doc.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/persist/replaced_file.h"
#include "../../shared/util/base64.h"
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
constexpr uint64_t compact_after = 1000;

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
}

void account_store::unindex(const account& a)
{
    if (const std::string_view u = a.username(); !u.empty())
        if (const auto it = m_names.find(lower(u)); it != m_names.end() && it->second == a.id)
            m_names.erase(it);
}

bool account_store::apply(std::string_view record)
{
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
    account& a = m_accounts[id];
    a.id = id;
    unindex(a);
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
    if (m_journal_records >= compact_after && !compact(why))
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
    if (m_follow_fd < 0)
        return true;   // the writer has written nothing yet
    struct stat st{};
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

void account_store::close()
{
    m_journal.close();
    if (m_follow_fd >= 0)
        ::close(m_follow_fd);
    m_follow_fd = -1;
    m_follow_off = 0;
    m_following = false;
    m_accounts.clear();
    m_names.clear();
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
    for (const auto& r : records)
        m_journal.append(r);
    if (!m_journal.sync())
    {
        why = "the change could not be written to the disk";
        return false;
    }
    note_journal();
    for (const auto& r : records)
        apply(r);
    m_journal_records += records.size();
    if (m_journal_records >= compact_after)
    {
        std::string ignored;
        compact(ignored);
    }
    return true;
}

bool account_store::compact(std::string& why)
{
    std::string out = "{\"format\":" + socketley::json::quote(journal_owner) + ",\"version\":" +
                      std::to_string(format_version) + "}\n";
    for (const auto& [id, a] : m_accounts)
    {
        out += "{\"id\":" + socketley::json::quote(id) + ",\"fields\":{";
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
    std::vector<const account*> out;
    out.reserve(m_accounts.size());
    for (const auto& [id, a] : m_accounts)
        out.push_back(&a);
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
    std::unordered_map<std::string, bool> names;
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
            names[lname] = true;
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
