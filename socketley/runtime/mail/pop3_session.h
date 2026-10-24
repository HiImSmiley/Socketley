#pragma once
// One POP3 conversation (RFC 1939) without a socket: a user signs in with USER and PASS or SASL PLAIN (RFC 5034),
// over STLS (RFC 2595) unless the peer is this machine, and reads, deletes and lists the messages of their INBOX by
// the same index IMAP keeps, a UIDL being the folder's UIDVALIDITY and the message's UID.  What is deleted goes at
// QUIT, as RFC 1939 6 has it, and nothing before.
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "mail_account.h"

namespace socketley::mail
{

struct pop3_config
{
    std::string hostname;
    bool tls_offered{false};
    bool tls_active{false};
    // A password may go in the clear, from this machine.
    bool login_in_clear{false};
    // XOAUTH2 and OAUTHBEARER offered beside PLAIN, where an idp gives the tokens they carry.
    bool bearer_offered{false};
};

class pop3_session
{
public:
    // A message of the maildrop as the session took it at sign-in.
    struct message
    {
        uint32_t uid{0};
        uint64_t size{0};
        std::string key;
    };

    struct hooks
    {
        virtual ~hooks() = default;
        virtual void reply(std::string_view bytes) = 0;
        // The OK to STLS is out: what follows is a TLS handshake.
        virtual void start_tls() = 0;
        virtual void login(std::string user, std::string password, std::function<void(account, std::string)> done) = 0;
        // The user's INBOX as it is now, its UIDVALIDITY and its messages in UID order; false where it cannot be read.
        virtual void maildrop(const std::string& user,
                              std::function<void(bool, uint32_t, std::vector<message>)> done) = 0;
        // A message's bytes, null where the store cannot give them.
        virtual void read(const message& m, std::function<void(std::shared_ptr<const std::string>)> done) = 0;
        // The messages of these UIDs taken out of the INBOX; false where that could not be written.
        virtual void remove(const std::string& user, std::vector<uint32_t> uids, std::function<void(bool)> done) = 0;
        virtual void close() = 0;
    };

    pop3_session(const pop3_config& cfg, hooks& h);
    ~pop3_session();
    pop3_session(const pop3_session&)            = delete;
    pop3_session& operator=(const pop3_session&) = delete;

    void greet();
    void input(std::string_view bytes);
    // The handshake STLS began is done; the client starts again from the greeting's state.
    void tls_started();
    const std::string& user() const { return m_user; }
    size_t buffered() const { return m_in.size() - m_at; }

    // A command line is 255 bytes in RFC 1939 and 2048 with SASL's initial response; past this it is refused.
    static constexpr size_t max_line = 4096;

private:
    void run();
    void command(std::string_view line);
    void ok(std::string_view text);
    void err(std::string_view text);
    void capabilities();
    void sign_in(std::string user, std::string password);
    // The message number `arg` names, live and not deleted; 0 where it names none.
    size_t number(std::string_view arg) const;
    // A message's bytes as POP3 sends them, its lines dot-stuffed and ended by ".", its body cut to `lines` lines where
    // that is not -1, as TOP asks.
    static std::string multiline(std::string_view message, int64_t lines);

    pop3_config m_cfg;
    hooks& m_hooks;
    std::string m_in;
    size_t m_at{0};
    bool m_waiting{false};
    bool m_running{false};
    bool m_closed{false};
    bool m_discarding{false};
    // AUTH PLAIN waiting for its response on a line of its own.
    bool m_sasl{false};
    // plain, XOAUTH2 or OAUTHBEARER, the mechanism the continuation answers.
    std::string m_sasl_mech;
    std::string m_pending_user;
    std::string m_user;
    bool m_transaction{false};
    uint32_t m_validity{0};
    std::vector<message> m_drop;
    std::vector<bool> m_deleted;
    uint32_t m_errors{0};
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
};

}   // namespace socketley::mail
