#pragma once
// What IMAP reads its mailboxes through: a folder's messages by UID with their flags, kept per user in a file of the
// runtime's state, and their bytes in the storage runtime, which stays what counts.  A folder is compared with its
// prefix in the bucket when it is opened and at most every two seconds after, so mail a delivery or another client put
// there is given the next UID, and what went is gone from it.  Bytes read are kept a while, as is their structure.
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
    int64_t     synced_ms{0};
    bool        syncing{false};
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

    // Flags changed by a session, kept.
    void touched(const std::string& user);
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
    // Every index written now, in line, as the runtime stops.
    void flush_now();
    uint64_t gets() const { return m_gets; }
    uint64_t cache_hits() const { return m_hits; }

private:
    struct user_state
    {
        std::map<std::string, std::shared_ptr<imap_folder>> folders;
        bool loaded{false};
        bool dirty{false};
    };
    user_state& user(const std::string& name);
    void load(const std::string& name, user_state& u);
    void save(const std::string& name, bool now = false);
    void sync(const std::string& user, const std::shared_ptr<imap_folder>& f, std::string after,
              std::vector<std::pair<std::string, std::pair<uint64_t, int64_t>>> seen);
    void put_object(std::string key, std::string data, std::function<void(bool)> done);
    void put_made(std::string key, std::string data, std::function<void(bool)> done);
    void delete_object(const std::string& key, std::function<void(bool)> done);
    std::string path_of(const std::string& user) const;
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
