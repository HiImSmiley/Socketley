#pragma once
// The identity provider's accounts: each one a fixed random id and a map of fields, with no schema.
//
// A field is a name and a text value. A few names mean something to the provider -- username, password (a scrypt
// hash), disabled, groups, name, email, picture, reset -- and every other name is an attribute it keeps and hands
// to applications without knowing it, so a field an application or a later version adds needs no change here, and
// a version that does not know a field keeps it as it was.
//
// Every change is a record in a journal, synced to the disk before the change is answered, and the whole is written
// as a snapshot now and then and the journal cut behind it. A snapshot names its format version; one newer than this
// build reads is refused rather than rewritten without what it does not understand.
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../../shared/persist/mutation_journal.h"

namespace socketley
{
class file_io;
}
class event_loop;

namespace socketley::idp
{

struct account
{
    std::string id;
    std::map<std::string, std::string, std::less<>> fields;

    std::string_view field(std::string_view name) const;
    std::string_view username() const { return field("username"); }
    bool disabled() const { return field("disabled") == "1"; }
    // Whether the comma-separated groups hold `group`.
    bool in_group(std::string_view group) const;
};

using field_list = std::vector<std::pair<std::string, std::string>>;

class account_store
{
public:
    static constexpr uint32_t format_version = 1;
    static constexpr size_t   max_fields     = 256;
    static constexpr size_t   max_value      = 64 * 1024;

    account_store() = default;
    ~account_store();
    account_store(const account_store&) = delete;
    account_store& operator=(const account_store&) = delete;

    // The accounts kept under `dir`, read whole: the snapshot, then every journal record after it.
    bool open(const std::string& dir, std::string& why);
    // The ring a commit's sync goes through, off the loop, and the loop that closes the journal it may still name;
    // without them the sync is made in the commit.
    void set_io(file_io* io, event_loop* loop)
    {
        m_io = io;
        m_loop = loop;
    }
    // Runs `then` once every change committed so far is on the disk, with false when the disk refused it -- from then
    // on the store takes no change, its memory being ahead of its disk until a restart replays the journal.
    void when_durable(std::function<void(bool)> then);
    // The same, as a shard that does not write them reads them: the journal stays open, for follow().
    bool follow_open(const std::string& dir, std::string& why);
    // The records the writer has added up to `end` of the journal `journal` names; false when it has since begun
    // another, which follow_open() then reads whole.
    bool follow(uint64_t journal, uint64_t end);
    // The accounts `fresh` read whole with follow_open(), on a thread that touched no other store, taken in place of
    // these; `fresh` is left holding the ones taken out, for that thread to free.
    void take_followed(account_store& fresh);
    void close();

    // The journal written, by its inode, which a compaction changes; and its length, which every change grows.
    uint64_t journal_id() const { return m_journal_id; }
    uint64_t journal_end() const { return m_journal_end; }
    // A count every change made or read adds to, so what is derived from the accounts is made again only after one.
    uint64_t changes() const { return m_changes; }
    // The same, added to only by an account made or removed or a field shapes_standing() names.
    uint64_t standing_changes() const { return m_standing_changes; }
    // The ids of those changes since the last take, or true for every account, as after the store was read whole.
    bool take_standing_dirty(std::vector<std::string>& ids);

    const account* by_id(std::string_view id) const;
    // By username, case aside.
    const account* by_name(std::string_view username) const;
    // Every account, ordered by username.
    std::vector<const account*> all() const;
    // Every account in no order, for a pass that needs none.
    template <class F>
    void each(F&& f) const
    {
        for (const auto& [id, a] : m_accounts)
            f(a);
    }
    // The accounts holding `email`, case aside, ordered by username.
    std::vector<const account*> by_email(std::string_view email) const;
    size_t size() const { return m_accounts.size(); }

    // A new account under a new id with `fields`, which must hold a username no other account has.
    bool create(const field_list& fields, std::string& id, std::string& why);
    // Fields set, and those given an empty value removed, as one change.
    bool update(std::string_view id, const field_list& fields, std::string& why);
    bool remove(std::string_view id, std::string& why);
    // Many new accounts as one write and one sync; one that cannot be made is named in `why` and the rest made.
    size_t create_many(const std::vector<field_list>& accounts, std::string& why);

    // A name a field may have: lower case letters, digits and . _ - :, at most 64.
    static bool valid_field_name(std::string_view name);
    // A username: letters, digits and . _ - @ +, from 1 to 64.
    static bool valid_username(std::string_view name);

    // The journal's records since the last snapshot, for a test that the snapshot cuts them.
    uint64_t journal_records() const { return m_journal_records; }
    // Writes the snapshot now and cuts the journal behind it.
    bool compact(std::string& why);

private:
    bool commit(const std::string& record, std::string& why);
    bool commit_many(const std::vector<std::string>& records, std::string& why);
    bool apply(std::string_view record);
    void index(const account& a);
    void note_standing(const std::string& id);
    void unindex(const account& a);
    bool read_snapshot(const std::string& path, std::string& why);
    void note_journal();
    void sync_next();
    void synced(bool ok);
    // The snapshot and a fresh journal written through the ring while commits go on, the ones made meanwhile kept in
    // m_tail to begin the fresh journal with; compact() does the same on the loop, without a ring.
    struct compaction;
    std::string snapshot_text() const;
    void compact_async();
    void compact_step(const std::shared_ptr<compaction>& job, int step);
    void compact_done(const std::shared_ptr<compaction>& job, bool ok);

    std::string m_dir;
    std::unordered_map<std::string, account> m_accounts;
    // Usernames lower-cased, to the id they name; and e-mail addresses lower-cased, to the ids holding them.
    std::unordered_map<std::string, std::string> m_names;
    std::unordered_multimap<std::string, std::string> m_emails;
    mutation_journal m_journal;
    uint64_t m_journal_records{0};
    uint64_t m_journal_id{0};
    uint64_t m_journal_end{0};
    uint64_t m_changes{0};
    uint64_t m_standing_changes{0};
    std::vector<std::string> m_standing_dirty;
    bool m_standing_all{true};
    // A commit is applied at once, so the next one sees it, and is made durable by a group sync through the ring:
    // the changes committed while one is in flight go in the next, and each waiter runs once its own are in one.
    file_io* m_io{nullptr};
    event_loop* m_loop{nullptr};
    // Bumped by close(), so a sync that ends after it finds the store it was made for gone.
    uint64_t m_gen{0};
    uint64_t m_committed{0};
    uint64_t m_synced{0};
    uint64_t m_syncing_upto{0};
    uint64_t m_flushed_end{0};
    bool m_syncing{false};
    bool m_broken{false};
    std::vector<std::pair<uint64_t, std::function<void(bool)>>> m_waiting;
    // A compaction under way: the commits made since it began, and the one durable point its waiters stop at until
    // the fresh journal that holds them is on the disk -- the old one is unlinked by the rename.
    bool m_compacting{false};
    uint64_t m_compact_from{0};
    uint64_t m_synced_old{0};
    std::vector<std::string> m_tail;
    std::shared_ptr<compaction> m_compact_ready;
    bool m_following{false};
    int m_follow_fd{-1};
    uint64_t m_follow_off{0};
};

}   // namespace socketley::idp
