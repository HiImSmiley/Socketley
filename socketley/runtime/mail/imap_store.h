#pragma once
// What IMAP reads its mailboxes through: a folder's messages by UID with their flags, kept per user under the
// runtime's state, and their bytes in the storage runtime, which stays what counts.  A folder is compared with its
// prefix in the bucket when it is opened and at most every two seconds after, so mail a delivery or another client put
// there is given the next UID, and what went is gone from it.  Bytes read are kept a while, as is their structure.
//
// Every shard serves IMAP, so a user's index is a snapshot and a journal every shard reads: a change is a line
// appended under the user's lock once the journal is read to its end, so UIDs are given out once whichever shard
// gives them, and each shard reads only the lines it has not, one stat a command when there are none.  Each change
// of a message has the folder's next mod-sequence (RFC 7162).  The journal is folded into the snapshot once it
// outgrows it.
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "mail_mime.h"

namespace socketley::mail
{

class mail_run;

enum : uint8_t
{
    flag_seen = 1,
    flag_answered = 2,
    flag_flagged = 4,
    flag_deleted = 8,
    flag_draft = 16,
};

struct imap_message
{
    uint32_t    uid{0};
    std::string key;
    uint64_t    size{0};
    int64_t     date_ms{0};
    uint8_t     flags{0};
    // A message delivered since a session last looked, \Recent to the first to see it.
    bool        recent{true};
    uint64_t    modseq{1};
};

struct imap_folder
{
    std::string name;
    uint32_t    uidvalidity{0};
    uint32_t    uidnext{1};
    // By UID, ascending.
    std::vector<imap_message> msgs;
    // Grows with every change, so a session knows when to look again.
    uint64_t    version{0};
    // The mod-sequence of its last change, and of the expunges since, for QRESYNC's VANISHED.
    uint64_t    highestmodseq{1};
    std::vector<std::pair<uint64_t, uint32_t>> vanished;
    int64_t     synced_ms{0};
    bool        syncing{false};
    // The mod-sequence the folder had as its listing in the bucket began.
    uint64_t    sync_from{0};
    std::vector<std::function<void(bool)>> waiting;
    bool        subscribed{true};
    imap_message* by_uid(uint32_t uid);
};

class imap_store
{
public:
    explicit imap_store(mail_run& run);
    ~imap_store();

    // The folders every mailbox has, with the special use RFC 6154 gives them.
    static const std::vector<std::pair<std::string, std::string>>& special();

    // The user's folders, those the bucket has and those made empty here.
    void folders(const std::string& user, std::function<void(std::vector<std::string>)> done);
    // A folder brought up to what the bucket holds; null when it does not exist and is not one every mailbox has.
    void open(const std::string& user, const std::string& folder, std::function<void(std::shared_ptr<imap_folder>)> done,
              bool force = false);
    bool create(const std::string& user, const std::string& folder);
    void remove(const std::string& user, const std::string& folder, std::function<void(bool)> done);
    void rename(const std::string& user, const std::string& from, const std::string& to, std::function<void(bool)> done);
    void set_subscribed(const std::string& user, const std::string& folder, bool on);

    // A message's bytes, from the cache or the bucket.
    void body(const std::string& key, uint64_t size, std::function<void(std::shared_ptr<const std::string>)> done);
    // Its structure, parsed once.
    std::shared_ptr<const mime::part> structure(const std::string& key, const std::shared_ptr<const std::string>& bytes);

    // What other shards changed in `user`'s index read in; a stat where they changed nothing.
    void refresh(const std::string& user);
    // The flags of `uids` in `f` made what `change` makes of each, logged; those it changes get the next modseq.
    void set_flags(const std::string& user, const std::shared_ptr<imap_folder>& f, const std::vector<uint32_t>& uids,
                   const std::function<uint8_t(uint8_t)>& change);
    // Those with \Deleted among `uids`, or every one where `uids` is empty, removed from the bucket and the folder.
    void expunge(const std::string& user, const std::shared_ptr<imap_folder>& f, const std::vector<uint32_t>& only,
                 std::function<void(std::vector<uint32_t> gone)> done);
    // Copies into another folder, answering the new UIDs in the order of `uids`.
    void copy(const std::string& user, const std::shared_ptr<imap_folder>& from, const std::vector<uint32_t>& uids,
              const std::string& to, std::function<void(bool, uint32_t uidvalidity, std::vector<uint32_t>)> done);
    // A message put into a folder, as APPEND does.
    void append(const std::string& user, const std::string& folder, std::string message, uint8_t flags, int64_t date_ms,
                std::function<void(bool, uint32_t uidvalidity, uint32_t uid)> done);

    void tick(int64_t now);
    // Every journal synced now, in line, as the runtime stops.
    void flush_now();
    uint64_t gets() const { return m_gets; }
    uint64_t cache_hits() const { return m_hits; }

private:
    struct user_state
    {
        std::map<std::string, std::shared_ptr<imap_folder>> folders;
        bool loaded{false};
        // The journal as far as it was read: its inode and the offset, and whether lines went in unsynced.
        uint64_t log_ino{0};
        uint64_t log_off{0};
        uint64_t snapshot_gen{0};
        uint64_t snapshot_bytes{0};
        bool unsynced{false};
        bool compacting{false};
    };
    user_state& user(const std::string& name);
    // The snapshot and the whole journal read, everything known before forgotten.
    void reload(const std::string& name, user_state& u);
    // The journal's lines from `text`, applied; `fresh` says a message they add is \Recent.
    void apply(user_state& u, std::string_view text, bool fresh);
    // `change` made to `u` under the user's lock, the index read to its end first; it appends the lines it logs.
    void mutate(const std::string& name, const std::function<void(user_state&, std::string& lines)>& change);
    void compact(const std::string& name, user_state& u);
    // A message put into `f`, given the next UID under the lock and logged.
    uint32_t add_message(const std::string& name, const std::shared_ptr<imap_folder>& f, const std::string& key,
                         uint64_t size, int64_t date_ms, uint8_t flags);
    void sync(const std::string& user, const std::shared_ptr<imap_folder>& f, std::string after,
              std::vector<std::pair<std::string, std::pair<uint64_t, int64_t>>> seen);
    void put_object(std::string key, std::string data, std::function<void(bool)> done);
    void put_made(std::string key, std::string data, std::function<void(bool)> done);
    void delete_object(const std::string& key, std::function<void(bool)> done);
    std::string path_of(const std::string& user) const;
    void refresh(const std::string& name, user_state& u);
    std::shared_ptr<imap_folder> make_folder(user_state& u, const std::string& name);

    mail_run& m_run;
    std::unordered_map<std::string, user_state> m_users;
    // Bytes read, least recently used first out, up to cache_max.
    struct cached
    {
        std::shared_ptr<const std::string> bytes;
        std::shared_ptr<const mime::part> part;
        int64_t used_ms{0};
    };
    std::unordered_map<std::string, cached> m_cache;
    size_t m_cached{0};
    std::unordered_map<std::string, std::vector<std::function<void(std::shared_ptr<const std::string>)>>> m_reading;
    uint64_t m_gets{0};
    uint64_t m_hits{0};
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
    static constexpr size_t cache_max = 64u << 20;
};

}   // namespace socketley::mail
