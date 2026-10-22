#pragma once
// The mailboxes of a mail runtime: its users are an idp runtime's, asked over the request channel whether an address
// is one of theirs and whether a password is, and their mail is objects of a storage runtime's bucket,
// <user>/<folder>/<id>.eml, written whole when small and in pieces of a mebibyte when not.
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "mail_account.h"
#include "mail_spool.h"
#include "../../shared/ipc/request_channel.h"

namespace socketley::mail
{

class mail_run;

// The flags a delivery gives a message, in its key's name as Maildir writes them: ",FS" before ".eml", the letters
// D (draft), F (flagged), R (answered), S (seen) and T (deleted) in that order; nothing where there are none.
std::string key_flags(uint8_t flags);
uint8_t flags_of_key(std::string_view key);

class mailboxes
{
public:
    explicit mailboxes(mail_run& run);

    // --storage and --idp read; false with `why` when --storage names no runtime.
    bool configure(std::string& why);
    bool enabled() const { return !m_storage.empty(); }
    const std::string& storage() const { return m_storage; }
    const std::string& bucket() const { return m_bucket; }

    // Whether `name`, a local part or an address, is a user's: `done(yes, username, email)`, asked of the idp
    // runtime and kept a minute, `unreachable` where it does not answer; without one, any name an alias gave is a
    // mailbox of that name.
    void find(const std::string& name, std::function<void(account, std::string, std::string)> done);
    // Whether `password` is `user`'s, asked of the idp runtime, which hashes it.
    void verify(const std::string& user, const std::string& password,
                std::function<void(account, std::string, std::string)> done);

    // `e` into `user`'s `folder`, `head` put ahead of it and every Authentication-Results this host would have
    // written taken out of it; `done` with 250, or a 4xx or 5xx and why.
    // `flags`, imap4flags' system flags as IMAP's bits, go in the key, which IMAP reads them from as it takes it.
    void deliver(const entry_ptr& e, const std::string& user, const std::string& folder, std::string head,
                 std::function<void(int, std::string)> done, uint8_t flags = 0);

    // The bucket made in the storage runtime, once, before the first write to it.
    void make_bucket(std::function<void(bool)> then);

    // A request to another runtime and its answer, through the runtime's channel.
    void ask(const std::string& target, std::string payload, std::function<void(request_status, std::string_view)> cb);

    // A message is in a mailbox, told to whoever --notify-targets names.
    struct stored_info
    {
        std::string id, user, folder, key, from, subject;
        uint64_t size{0};
    };
    std::function<void(const stored_info&)> on_stored;

    // The bytes `user`'s mailboxes may hold, as the idp runtime's mail_quota field said when last asked; 0 for no bound.
    uint64_t quota_of(const std::string& user) const;
    uint64_t stored() const { return m_stored; }
    uint64_t store_failures() const { return m_store_failures; }

private:
    struct known
    {
        bool        found{false};
        std::string user, email;
        uint64_t    quota{0};
        int64_t     until_ms{0};
    };
    static void take_answer(std::string_view rest, known& k);
    struct writing;
    void put_small(const std::shared_ptr<writing>& w);
    void put_stream(const std::shared_ptr<writing>& w);
    void put_piece(const std::shared_ptr<writing>& w);
    void read_on(const std::shared_ptr<writing>& w);
    void finish(const std::shared_ptr<writing>& w, int code, std::string text);

    mail_run& m_run;
    std::string m_storage;
    std::string m_bucket{"mail"};
    std::string m_idp;
    bool m_bucket_made{false};
    std::vector<std::function<void(bool)>> m_bucket_waiting;
    std::unordered_map<std::string, known> m_known;
    std::unordered_map<std::string, uint64_t> m_quota;
    uint64_t m_stored{0};
    uint64_t m_store_failures{0};
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
};

}   // namespace socketley::mail
