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
#include <map>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../../shared/persist/mutation_journal.h"

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
    account_store(const account_store&) = delete;
    account_store& operator=(const account_store&) = delete;

    // The accounts kept under `dir`, read whole: the snapshot, then every journal record after it.
    bool open(const std::string& dir, std::string& why);
    // The same, as a shard that does not write them reads them: the journal stays open, for follow().
    bool follow_open(const std::string& dir, std::string& why);
    // The records the writer has added up to `end` of the journal `journal` names; false when it has since begun
    // another, which follow_open() then reads whole.
    bool follow(uint64_t journal, uint64_t end);
    bool following() const { return m_following; }
    void close();

    // The journal written, by its inode, which a compaction changes; and its length, which every change grows.
    uint64_t journal_id() const { return m_journal_id; }
    uint64_t journal_end() const { return m_journal_end; }

    const account* by_id(std::string_view id) const;
    // By username, case aside.
    const account* by_name(std::string_view username) const;
    // Every account, ordered by username.
    std::vector<const account*> all() const;
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
    void unindex(const account& a);
    bool read_snapshot(const std::string& path, std::string& why);
    void note_journal();

    std::string m_dir;
    std::unordered_map<std::string, account> m_accounts;
    // Usernames lower-cased, to the id they name.
    std::unordered_map<std::string, std::string> m_names;
    mutation_journal m_journal;
    uint64_t m_journal_records{0};
    uint64_t m_journal_id{0};
    uint64_t m_journal_end{0};
    bool m_following{false};
    int m_follow_fd{-1};
    uint64_t m_follow_off{0};
};

}   // namespace socketley::idp
