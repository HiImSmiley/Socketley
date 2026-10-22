#pragma once
// One ManageSieve conversation (RFC 5804) without a socket: a user signs in with SASL PLAIN, over STARTTLS unless
// the peer is this machine, and lists, puts, checks, gets, renames, deletes and activates their Sieve scripts in the
// store.  Strings are quoted or literals, {n+} from the client, {n} back; a literal past a script's size is refused
// and read to its end, so what follows it is still the next command.
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "mail_account.h"

namespace socketley::mail
{

class sieve_store;

struct managesieve_config
{
    std::string hostname;
    bool tls_offered{false};
    bool tls_active{false};
    // A password may go in the clear, from this machine.
    bool login_in_clear{false};
};

class managesieve_session
{
public:
    struct hooks
    {
        virtual ~hooks() = default;
        virtual void reply(std::string_view bytes) = 0;
        // The OK to STARTTLS is out: what follows is a TLS handshake.
        virtual void start_tls() = 0;
        virtual void login(std::string user, std::string password, std::function<void(account, std::string)> done) = 0;
        virtual void close() = 0;
    };

    managesieve_session(const managesieve_config& cfg, hooks& h, sieve_store& store);
    ~managesieve_session();
    managesieve_session(const managesieve_session&)            = delete;
    managesieve_session& operator=(const managesieve_session&) = delete;

    // The capabilities and OK a connection begins with.
    void greet();
    void input(std::string_view bytes);
    // The handshake STARTTLS began is done: the capabilities again, as RFC 5804 2.2 asks.
    void tls_started();
    const std::string& user() const { return m_user; }
    // What came and is not taken yet.
    size_t buffered() const { return m_in.size() - m_at; }

    static constexpr size_t max_line = 8192;
    // More arguments than any command takes.
    static constexpr size_t max_args = 8;

private:
    // One argument as the command line gave it: a quoted string, a literal's bytes, or an atom.
    struct arg
    {
        std::string text;
        bool string{false};
    };
    void run();
    // The command whose arguments are in m_args.
    void command();
    void capabilities();
    void ok(std::string_view text);
    void no(std::string_view code, std::string_view text);
    void authenticate();
    void sign_in(std::string_view b64);
    std::string quoted(std::string_view s) const;

    managesieve_config m_cfg;
    hooks& m_hooks;
    sieve_store& m_store;
    std::string m_in;
    size_t m_at{0};
    // The command being read: its arguments so far, and a literal's bytes still to come.
    std::vector<arg> m_args;
    uint64_t m_literal{0};
    bool m_dropping{false};
    // A line past max_line was cut, and what is left of it is dropped when it comes.
    bool m_discarding{false};
    // AUTHENTICATE waiting for the client's SASL response on a line of its own.
    bool m_sasl{false};
    bool m_waiting{false};
    bool m_running{false};
    bool m_closed{false};
    std::string m_user;
    uint32_t m_errors{0};
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
};

}   // namespace socketley::mail
