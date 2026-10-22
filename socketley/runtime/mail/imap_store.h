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
#include <list>
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
    // The keywords a client set on it ($Forwarded, $Junk, its own), as it gave them.
    std::vector<std::string> keywords;
};

// What STORE or APPEND asks of a message's keywords: none, these as they are, or these added or taken away.
struct keyword_change
{
    enum class kind : uint8_t { none, set, add, remove };
    kind k{kind::none};
    std::vector<std::string> words;
    // The keywords `have` become, true where they changed.
    bool apply(std::vector<std::string>& have) const;
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
    // Expunges are known from this mod-sequence on; before it, VANISHED says every UID it does not have.
    uint64_t    vanished_from{0};
    int64_t     synced_ms{0};
    bool        syncing{false};
    // The mod-sequence the folder had as its listing in the bucket began, and the keys expunged since a while, which a
    // listing taken before they went still holds and does not bring back.
    uint64_t    sync_from{0};
    // When a listing first lacked each message the index holds, as a store may list a write it acknowledged late.
    std::unordered_map<std::string, int64_t> missing_since;
    std::vector<std::pair<uint64_t, std::string>> gone_keys;
    std::vector<std::function<void(bool)>> waiting;
    bool        subscribed{true};
    // Its MAILBOXID (RFC 8474), the one of the folder a RENAME made it from, else of its UIDVALIDITY.
    std::string objectid;
    std::string id() const;
    imap_message* by_uid(uint32_t uid);
};

class imap_store
{
public:
    explicit imap_store(mail_run& run);
    ~imap_store();

    // The folders every mailbox has, with the special use RFC 6154 gives them.
    static const std::vector<std::pair<std::string, std::string>>& special();

    // The folders the index knows for `user`, as they are now.
    std::vector<std::string> folder_names(const std::string& user);
    // The user's folders, those the bucket has and those made empty here.
    void folders(const std::string& user, std::function<void(std::vector<std::string>)> done);
    // A folder brought up to what the bucket holds, listed again where it was last listed longer than `max_age_ms` ago;
    // null when it does not exist and is not one every mailbox has.
    void open(const std::string& user, const std::string& folder, std::function<void(std::shared_ptr<imap_folder>)> done,
              bool force = false, int64_t max_age_ms = 2000);
    bool create(const std::string& user, const std::string& folder);
    // A folder's MAILBOXID, empty where there is no such folder.
    std::string mailbox_id(const std::string& user, const std::string& folder);
    // A message's EMAILID (RFC 8474): of its object, which nothing changes while it is in the folder.
    static std::string email_id(std::string_view key);

    // METADATA (RFC 5464): the entries of a folder, "" the server's, kept in the index for every shard.  An entry is
    // its name in lower case, /private/... or /shared/..., at most 1000 a user, of 64 KiB each and 1 MiB in all.
    enum class meta_refusal : uint8_t { none, no_folder, too_many, too_large, bad_name };
    meta_refusal set_meta(const std::string& user, const std::string& folder, const std::string& entry,
                          const std::string* value);
    // The value of `entry`, null where it has none; and, with `depth` 1 or past, the entries under it that deep.
    const std::string* meta(const std::string& user, const std::string& folder, const std::string& entry);
    std::vector<std::pair<std::string, std::string>> meta_under(const std::string& user, const std::string& folder,
                                                                const std::string& entry, int depth);
    static constexpr size_t meta_max_value = 64u << 10;
    static bool meta_name_ok(std::string_view entry);
    void remove(const std::string& user, const std::string& folder, std::function<void(bool)> done);
    void rename(const std::string& user, const std::string& from, const std::string& to, std::function<void(bool)> done);
    void set_subscribed(const std::string& user, const std::string& folder, bool on);
    bool subscribed(const std::string& user, const std::string& folder);
    // The bytes of every message the user's index has, and those of APPENDs and COPYs still being written, and the
    // bound their idp account puts on them, 0 for none.
    uint64_t usage(const std::string& user);
    uint64_t quota(const std::string& user) const;
    // Room taken for a message being written, so two at once cannot pass the bound together; given back after.
    bool reserve(const std::string& user, uint64_t bytes);
    void unreserve(const std::string& user, uint64_t bytes);

    // A message's bytes, from the cache or the bucket; kept in the cache only where `keep`.
    void body(const std::string& key, uint64_t size, std::function<void(std::shared_ptr<const std::string>)> done,
              bool keep = true);
    // Its header block alone, read from its start, what ENVELOPE, SORT and a header SEARCH need; the whole message
    // where the header is longer than the first read.
    void head(const std::string& key, uint64_t size, std::function<void(std::shared_ptr<const std::string>)> done);
    // Whether body() or, given `head`, head() would answer at once.
    bool holds(const std::string& key, bool head) const
    {
        const auto it = m_cache.find(key);
        return (it != m_cache.end() && it->second.bytes) || (head && m_heads.count(key));
    }
    // Its structure, parsed once.
    std::shared_ptr<const mime::part> structure(const std::string& key, const std::shared_ptr<const std::string>& bytes);
    // True where a message too large to parse on the loop is parsed on the pool, `done` called once structure() has it.
    bool parse_later(const std::string& key, const std::shared_ptr<const std::string>& bytes, std::function<void()> done);

    // What other shards changed in `user`'s index read in; a stat where they changed nothing.
    void refresh(const std::string& user);
    // The flags of `uids` in `f` made what `change` makes of each, logged; those it changes get the next modseq, and
    // how many it changed is answered.
    size_t set_flags(const std::string& user, const std::shared_ptr<imap_folder>& f, const std::vector<uint32_t>& uids,
                   const std::function<uint8_t(uint8_t)>& change, const keyword_change& words = {});
    // Those with \Deleted among `only`, or of the folder where it is empty, removed from the bucket and the folder;
    // with `any` whatever their flags, since a flag set in memory alone is lost to what another shard logs.
    void expunge(const std::string& user, const std::shared_ptr<imap_folder>& f, const std::vector<uint32_t>& only,
                 bool any, std::function<void(std::vector<uint32_t> gone)> done);
    // Copies into another folder, answering the new UIDs in the order of `uids`, the room they take held against the
    // quota where `counts` (a MOVE gives it back); a target that does not exist answers a UIDVALIDITY of 0.
    void copy(const std::string& user, const std::shared_ptr<imap_folder>& from, const std::vector<uint32_t>& uids,
              const std::string& to, bool counts,
              std::function<void(bool, uint32_t uidvalidity, std::vector<uint32_t>)> done);
    // A message a delivery put into the bucket, given its UID now, so IDLE and every shard know of it at once and
    // its bytes count against the quota; the folder is made where a filter named one not there.
    void delivered(const std::string& user, const std::string& folder, const std::string& key, uint64_t size,
                   int64_t date_ms);
    // A message put into a folder, as APPEND does.
    // Its answer is false with why: over the quota, no such folder, or the storage refused it.
    enum class refusal : uint8_t { none, quota, no_folder, storage };
    void append(const std::string& user, const std::string& folder, std::string message, uint8_t flags,
                std::vector<std::string> keywords, int64_t date_ms,
                std::function<void(refusal, uint32_t uidvalidity, uint32_t uid)> done);

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
        // Held by this shard in mutate, which a reload inside does not take again: a second flock waits on the first.
        bool locked{false};
        // The bytes of its messages, kept as they come and go, and those reserved for messages being written.
        uint64_t used{0};
        uint64_t reserved{0};
        // A UIDVALIDITY given out, so a folder made again in the same second gets a later one.
        uint32_t last_validity{0};
        // A compaction that lost to new lines waits for the journal to grow this far before the next.
        uint64_t compact_after{0};
        // The journal's length at the last turn since a fold lost to new lines, tried again once it holds still.
        uint64_t compact_quiet{UINT64_MAX};
        // The index's path, worked out once: resolving the state directory costs several syscalls.
        std::string base;
        // METADATA entries by folder, "" the server's, and the bytes of their values.
        std::map<std::string, std::map<std::string, std::string>> meta;
        uint64_t meta_bytes{0};
        size_t meta_count{0};
    };
    user_state& user(const std::string& name);
    // The snapshot and the whole journal read, everything known before forgotten.
    void reload(user_state& u);
    // The journal's lines from `text`, applied; `fresh` says a message they add is \Recent.
    void apply(user_state& u, std::string_view text, bool fresh);
    // `change` made to `u` under the user's lock, the index read to its end first; it appends the lines it logs.
    // False where the lock could not be taken or the lines not written, the change then read back as the disk has it.
    bool mutate(const std::string& name, const std::function<void(user_state&, std::string& lines)>& change);
    void compact(const std::string& name, user_state& u);
    // A message put into `f`, given the next UID under the lock and logged.
    // 0 where the folder went meanwhile, or the journal took no line.
    uint32_t add_message(const std::string& name, const std::shared_ptr<imap_folder>& f, const std::string& key,
                         uint64_t size, int64_t date_ms, uint8_t flags, const std::vector<std::string>& keywords = {});
    // Messages put into `f` together, their UIDs in order under one lock and one write; empty where the folder went.
    std::vector<uint32_t> add_messages(const std::string& name, const std::shared_ptr<imap_folder>& f,
                                       const std::vector<imap_message>& ms);
    void sync(const std::string& user, const std::shared_ptr<imap_folder>& f, std::string after,
              std::vector<std::pair<std::string, std::pair<uint64_t, int64_t>>> seen);
    void put_object(std::string key, std::string data, std::function<void(bool)> done);
    void put_made(std::string key, std::string data, std::function<void(bool)> done);
    void delete_object(const std::string& key, std::function<void(bool)> done);
    // `f` emptied, its messages copied to `to` first where it names a folder, and its D logged; again for what came in
    // meanwhile, `passes` times at most.
    void empty_out(const std::string& name, const std::shared_ptr<imap_folder>& f, const std::string& fname,
                   const std::string& to, int passes, std::function<void(bool)> done);
    std::string path_of(const std::string& user) const;
    void catch_up(user_state& u);
    std::shared_ptr<imap_folder> make_folder(user_state& u, const std::string& name);

    mail_run& m_run;
    std::unordered_map<std::string, user_state> m_users;
    // Bytes read, least recently used first out, up to cache_max.
    struct cached
    {
        std::shared_ptr<const std::string> bytes;
        std::shared_ptr<const mime::part> part;
        std::list<std::string>::iterator lru;
        // The bytes counted for it in m_cached, its parsed structure among them.
        size_t counted{0};
    };
    // Counts `c` again after its bytes or structure changed.
    void recount(cached& c);
    std::unordered_map<std::string, cached> m_cache;
    std::list<std::string> m_lru;
    size_t m_cached{0};
    // A key's entry made or read now, ahead of the others in leaving.
    cached& touch(const std::string& key);
    void evict();
    // Header blocks read on their own, a few mebibytes of them.
    std::unordered_map<std::string, std::shared_ptr<const std::string>> m_heads;
    size_t m_heads_bytes{0};
    std::unordered_map<std::string, std::vector<std::function<void(std::shared_ptr<const std::string>)>>> m_reading;
    std::unordered_map<std::string, std::vector<std::function<void(std::shared_ptr<const std::string>)>>> m_head_reading;
    uint64_t m_gets{0};
    uint64_t m_hits{0};
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
    static constexpr size_t cache_max = 64u << 20;
};

}   // namespace socketley::mail
