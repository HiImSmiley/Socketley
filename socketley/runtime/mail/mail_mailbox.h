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

#include "mail_spool.h"
#include "../../shared/ipc/request_channel.h"

namespace socketley::mail
{

class mail_run;

class mailboxes
{
public:
    explicit mailboxes(mail_run& run);

    // --storage and --idp read; false with `why` when --storage names no runtime.
    bool configure(std::string& why);
    bool enabled() const { return !m_storage.empty(); }
    const std::string& storage() const { return m_storage; }
    const std::string& bucket() const { return m_bucket; }

    // Whether `name`, a local part or an address, is a user's: `done(true, username, email)`, asked of the idp
    // runtime and kept a minute; without one, any name an alias gave is a mailbox of that name.
    void find(const std::string& name, std::function<void(bool, std::string, std::string)> done);
    // Whether `password` is `user`'s, asked of the idp runtime, which hashes it.
    void verify(const std::string& user, const std::string& password,
                std::function<void(bool, std::string, std::string)> done);

    // `e` into `user`'s `folder`, `head` put ahead of it and every Authentication-Results this host would have
    // written taken out of it; `done` with 250, or a 4xx or 5xx and why.
    void deliver(const entry_ptr& e, const std::string& user, const std::string& folder, std::string head,
                 std::function<void(int, std::string)> done);

    // A request to another runtime and its answer, through the runtime's channel.
    void ask(const std::string& target, std::string payload, std::function<void(request_status, std::string_view)> cb);

    uint64_t stored() const { return m_stored; }
    uint64_t store_failures() const { return m_store_failures; }

private:
    struct known
    {
        bool        found{false};
        std::string user, email;
        int64_t     until_ms{0};
    };
    struct writing;
    void put_small(const std::shared_ptr<writing>& w);
    void put_stream(const std::shared_ptr<writing>& w);
    void put_piece(const std::shared_ptr<writing>& w);
    void read_on(const std::shared_ptr<writing>& w);
    void finish(const std::shared_ptr<writing>& w, int code, std::string text);
    void make_bucket(std::function<void(bool)> then);

    mail_run& m_run;
    std::string m_storage;
    std::string m_bucket{"mail"};
    std::string m_idp;
    bool m_bucket_made{false};
    std::vector<std::function<void(bool)>> m_bucket_waiting;
    std::unordered_map<std::string, known> m_known;
    uint64_t m_stored{0};
    uint64_t m_store_failures{0};
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
};

}   // namespace socketley::mail
