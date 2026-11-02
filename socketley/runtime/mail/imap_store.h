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
    // The conversation it is part of, a hash of its root's Message-ID (imap_order::thread_of); 0 until it is known.
    uint64_t    thread{0};
    // When it was put into its folder, 0 where that was before the store kept it (RFC 8514's SAVEDATE).
    int64_t     saved_ms{0};
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
    // Who else may do what with it (RFC 4314): an identifier, a user or "anyone", and their rights.
    std::map<std::string, std::string> acl;
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
    // The folders themselves, with what other shards logged read in first, for NOTIFY to see what changed.
    std::vector<std::shared_ptr<imap_folder>> known(const std::string& user);
    // The user's folders, those the bucket has and those made empty here.
    void folders(const std::string& user, std::function<void(std::vector<std::string>)> done);
    // The user's folders listed and each brought up to the bucket at most once a minute, for a client that never SELECTs.
    void freshen(const std::string& user, std::function<void()> done);
    // The trigram filters of the user's messages read in as far as any shard wrote them, before a search asks for them.
    void read_text_filters(const std::string& user);
    // A message's trigram filter by the hash its EMAILID spells, empty where none was made yet.
    std::string_view text_filter_of(const std::string& user, uint64_t email_hash);
    // A message's filter kept for later searches, and written for every shard at the next tick.
    void keep_text_filter(const std::string& user, uint64_t email_hash, std::string filter);
    // The filter of a message just stored, made on the pool from its bytes, so no search reads the message to make it.
    void note_text(const std::string& user, const std::string& key, std::shared_ptr<const std::string> bytes);
    // A folder brought up to what the bucket holds, listed again where it was last listed longer than `max_age_ms` ago;
    // null when it does not exist and is not one every mailbox has.
    void open(const std::string& user, const std::string& folder, std::function<void(std::shared_ptr<imap_folder>)> done,
              bool force = false, int64_t max_age_ms = 2000);
    bool create(const std::string& user, const std::string& folder);
    // A folder's MAILBOXID, empty where there is no such folder.
    std::string mailbox_id(const std::string& user, const std::string& folder);
    // A message's EMAILID (RFC 8474): of its object, which nothing changes while it is in the folder.
    static std::string email_id(std::string_view key);
    // The number its EMAILID spells in hex, which a search looks a message up by without making the string.
    static uint64_t email_hash(std::string_view key);

    // METADATA (RFC 5464): the entries of a folder, "" the server's, kept in the index for every shard.  An entry is
    // its name in lower case, /private/... or /shared/..., at most 1000 a user, of 64 KiB each and 1 MiB in all.
    enum class meta_refusal : uint8_t { none, no_folder, too_many, too_large, bad_name, io };
    meta_refusal set_meta(const std::string& user, const std::string& folder, const std::string& entry,
                          const std::string* value);
    // The value of `entry`, null where it has none; and, with `depth` 1 or past, the entries under it that deep.
    const std::string* meta(const std::string& user, const std::string& folder, const std::string& entry);
    std::vector<std::pair<std::string, std::string>> meta_under(const std::string& user, const std::string& folder,
                                                                const std::string& entry, int depth);
    static constexpr size_t meta_max_value = 64u << 10;

    // ACL (RFC 4314).  A folder's owner has every right; another user what the folder's ACL gives them and anyone.
    static constexpr std::string_view all_rights = "lrswipkxtea";
    std::string rights(const std::string& owner, const std::string& folder, const std::string& who);
    // The rights of `who` on the owner's folder made `rights`, none taking them away; false where there is no folder.
    bool set_acl(const std::string& owner, const std::string& folder, const std::string& who, const std::string& rights);
    std::map<std::string, std::string> acl(const std::string& owner, const std::string& folder);
    // The folders others gave `who`, or anyone, a right on, as owner and folder, from the runtime's list of shares.
    std::vector<std::pair<std::string, std::string>> shared_with(const std::string& who);
    // A runtime-wide file beside the users' indexes, which no user's name can be (".shares", ".push-users").
    std::string list_path(std::string_view name) const;
    // The users with a JMAP PushSubscription, whose states the runtime watches to push their changes.
    void note_push_user(const std::string& user, bool on);
    std::vector<std::string> push_users();
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
    // Its bytes and structure where the cache holds both, read now; false where it does not.
    bool parsed(const std::string& key, std::shared_ptr<const std::string>& bytes, std::shared_ptr<const mime::part>& part);
    // Part `section` of the message `key`, its transfer encoding undone, to `done`, null where there is no such part: a
    // message too large to parse on the loop is parsed and decoded on the pool, and its structure kept either way.
    void section(const std::string& key, const std::shared_ptr<const std::string>& bytes, std::string section,
                 std::function<void(std::shared_ptr<const std::string>)> done);
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
                   int64_t date_ms, uint64_t thread = 0);
    // The conversation of a message whose header is `header`, never 0: its root's, or its own where it names none.
    static uint64_t thread_of(std::string_view header, std::string_view key);
    // Every message of a user given its conversation, those not yet known read for it, before `done`.
    void know_threads(const std::string& user, std::function<void()> done);
    // A message put into a folder, as APPEND does.
    // Its answer is false with why: over the quota, no such folder, or the storage refused it.
    enum class refusal : uint8_t { none, quota, no_folder, storage };
    void append(const std::string& user, const std::string& folder, std::string message, uint8_t flags,
                std::vector<std::string> keywords, int64_t date_ms,
                std::function<void(refusal, uint32_t uidvalidity, uint32_t uid)> done);

    // A JMAP upload (RFC 8620 6.1): kept under .jmap-uploads/ of the bucket, apart from every user's folders, for a
    // day, its id naming its size so it is read back in one; the id answered, empty where it could not be written.
    void put_upload(const std::string& user, std::string data, std::function<void(std::string id)> done);
    void get_upload(const std::string& user, const std::string& id, std::function<void(std::shared_ptr<const std::string>)> done);

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
        // When freshen last listed the bucket for this user.
        int64_t listed_ms{0};
        // Trigram filters by EMAILID's hash, as far as their file was read, and those made here and not yet written to it.
        std::unordered_map<uint64_t, std::string> filters;
        uint64_t filters_ino{0};
        uint64_t filters_off{0};
        size_t filters_bytes{0};
        std::string filters_out;
        int64_t filters_used_ms{0};
        bool filters_compacting{false};
        // The file's size when it was last weighed for compaction.
        uint64_t filters_weighed{0};
    };
    user_state& user(const std::string& name);
    // The state of a user some shard keeps an index for, or null, nothing made for a name no mail or sign-in made.
    user_state* indexed(const std::string& name);
    // A filter held in memory and counted against what every user's may take together.
    void hold_filter(user_state& u, uint64_t id, std::string filter);
    // The filters made here appended to the user's file, which is written again once it is mostly for messages gone.
    void write_text_filters(const std::string& name, user_state& u);
    size_t m_filter_bytes{0};
    // Uploads older than a day taken away, a page of them each hour.
    void sweep_uploads(std::string after = {});
    int64_t m_uploads_swept_ms{0};
    void note_share(const std::string& owner, const std::string& folder, const std::string& who, bool on);
    // A runtime-wide list of keys, each on or off by its last line, folded past a mebibyte.
    void note_line(const std::string& path, const std::string& key, bool on);
    std::vector<std::string> live_lines(const std::string& path);
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
                         uint64_t size, int64_t date_ms, uint8_t flags, const std::vector<std::string>& keywords = {},
                         uint64_t thread = 0);
    // Messages put into `f` together, their UIDs in order under one lock and one write; empty where the folder went.
    std::vector<uint32_t> add_messages(const std::string& name, const std::shared_ptr<imap_folder>& f,
                                       const std::vector<imap_message>& ms);
    void sync(const std::string& user, const std::shared_ptr<imap_folder>& f, std::string after,
              std::vector<std::pair<std::string, std::pair<uint64_t, int64_t>>> seen);
    void put_object(std::string key, std::string data, std::function<void(bool)> done);
    void put_made(std::string key, std::string data, std::function<void(bool)> done, bool fresh = false,
                  std::function<void()> taken = nullptr);
    // A new message's bytes under a name `name` makes, never over another's: a name taken meanwhile is made again; the
    // name it went under to `done`, empty where it could not be written.
    void put_new(std::function<std::string()> name, std::shared_ptr<const std::string> data,
                 std::function<void(std::string key)> done, int tries = 0);
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
    int64_t m_expunge_swept_ms{0};
    // Junk and Trash of every user known emptied of what they held longer than --autoexpunge.
    void autoexpunge(int64_t now);
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
