#pragma once
// One SMTP conversation on the receiving side, without a socket: bytes go in, replies and the message's bytes come
// out through `hooks`.  RFC 5321 with PIPELINING, SIZE, 8BITMIME, SMTPUTF8, ENHANCEDSTATUSCODES, STARTTLS (RFC 3207)
// and AUTH PLAIN and LOGIN (RFC 4954).
//
// A question the session cannot answer itself -- a password, a sender, a recipient, whether the message is kept --
// goes to its hooks with a callback, and the commands pipelined behind it wait in the input until the answer, so the
// replies go out in the order the commands came.  The message is unstuffed as it arrives and handed on in pieces; its
// end is a CRLF, a dot and a CRLF and nothing else, and a bare LF is written as CRLF, so no other server reading what
// is relayed sees an end where this one saw none.
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace socketley::mail
{

// An address as SMTP carries it, the domain in lower case; empty for the null sender of a bounce.
struct address
{
    std::string local;
    std::string domain;
    bool empty() const { return local.empty() && domain.empty(); }
    std::string text() const { return empty() ? std::string() : local + "@" + domain; }
};

// `<local@domain>` with the brackets, a quoted local part and an internationalized one allowed where `utf8`;
// false for anything else, or one past RFC 5321's lengths.
bool parse_path(std::string_view in, address& out, bool allow_null, bool utf8);
// The same without brackets, as a configuration or a header names one.
bool parse_address(std::string_view in, address& out, bool utf8 = true);

struct smtp_config
{
    std::string hostname;
    uint64_t    max_size{25u << 20};
    uint32_t    max_rcpt{100};
    // STARTTLS can be offered, and whether this connection already speaks TLS.
    bool        tls_offered{false};
    bool        tls_active{false};
    // AUTH is offered once the connection is encrypted, or from the start where it is said safe (a loopback peer).
    bool        auth_offered{false};
    bool        auth_in_clear{false};
    // A submission port: nothing is taken from one not signed in.
    bool        auth_required{false};
    // A message is accepted only where STARTTLS was spoken first.
    bool        tls_required{false};
};

// What a recipient became, once its hook decided.
struct rcpt_verdict
{
    int         code{250};
    std::string text;
};

class smtp_session
{
public:
    struct hooks
    {
        virtual ~hooks() = default;
        // Bytes for the client, gathered by the caller until input() returns.
        virtual void reply(std::string_view bytes) = 0;
        // The 220 to STARTTLS is out: what follows on the connection is a TLS handshake.
        virtual void start_tls() = 0;
        // A password or an access token said for `user`; `done(true, name)` signs the connection in as `name`.
        virtual void authenticate(std::string_view mech, std::string user, std::string secret,
                                  std::function<void(bool ok, std::string name)> done) = 0;
        virtual void mail_from(const address& from, std::function<void(rcpt_verdict)> done) = 0;
        virtual void rcpt_to(const address& to, std::function<void(rcpt_verdict)> done) = 0;
        // The message begins; false when it cannot be kept, answered 451.
        virtual bool data_begin() = 0;
        virtual void data_bytes(std::string_view piece) = 0;
        // The whole of it is in: `done` with 250 once it is on the disk, or why not.
        virtual void data_end(std::function<void(rcpt_verdict)> done) = 0;
        // What data_begin() began goes, the message refused or the connection gone.
        virtual void data_abort() = 0;
        // QUIT answered, or too many errors: the connection closes once the reply is out.
        virtual void close() = 0;
    };

    smtp_session(const smtp_config& cfg, hooks& h);
    ~smtp_session();
    smtp_session(const smtp_session&)            = delete;
    smtp_session& operator=(const smtp_session&) = delete;

    // The 220 greeting; called once the connection is up, and again after a STARTTLS has none.
    void greet();
    // Bytes from the client, whole commands acted on and the rest kept.
    void input(std::string_view bytes);
    // The TLS handshake after STARTTLS is done: the conversation starts over, without its greeting (RFC 3207 4.2).
    void tls_started();
    // The connection is gone: a message being received is dropped.
    void gone();

    // What the session knows, for the message's Received header and for the hooks.
    const std::string& helo() const { return m_helo; }
    bool               esmtp() const { return m_esmtp; }
    bool               tls() const { return m_cfg.tls_active; }
    const std::string& user() const { return m_user; }
    const address&     sender() const { return m_from; }
    const std::vector<address>& recipients() const { return m_rcpts; }
    bool               body_8bit() const { return m_8bit; }
    bool               smtputf8() const { return m_utf8; }
    // The bytes of the message counted so far, before the size limit is told.
    uint64_t           received() const { return m_size; }
    uint32_t           errors() const { return m_errors; }
    uint64_t           messages() const { return m_messages; }

    // Lines are commands until DATA, and the client may not send one longer than this (RFC 5321 4.5.3.1.4 says 512).
    static constexpr size_t max_command = 4096;
    static constexpr uint32_t max_errors = 20;

private:
    enum class phase : uint8_t { command, auth_plain, auth_login_user, auth_login_pass, data, waiting, closed };

    // The commands in `m_in` from `m_at` on, until one waits for an answer or the input runs out.
    void run();
    void command(std::string_view line);
    // Message bytes from `m_in`; true once the end is seen.
    bool data(std::string_view& in);
    void say(std::string_view line);
    void say(int code, std::string_view enhanced, std::string_view text);
    void ehlo(std::string_view arg, bool extended);
    void mail(std::string_view arg);
    void rcpt(std::string_view arg);
    void auth(std::string_view arg);
    void auth_plain(std::string_view b64);
    void sign_in(std::string_view mech, std::string user, std::string secret);
    void reset();
    void error(int code, std::string_view enhanced, std::string_view text);
    void wait();
    void resume();
    // A message refused after DATA began: its bytes up to the end are read and dropped.
    void drop_data(int code, std::string_view enhanced, std::string_view text);

    smtp_config m_cfg;
    hooks&      m_hooks;
    phase       m_phase{phase::command};
    // Unread input: commands pipelined behind one waiting, or the start of a line.
    std::string m_in;
    size_t      m_at{0};
    std::string m_helo;
    bool        m_esmtp{false};
    std::string m_user;
    address     m_from;
    bool        m_have_from{false};
    std::vector<address> m_rcpts;
    bool        m_8bit{false};
    bool        m_utf8{false};
    uint64_t    m_declared{0};
    std::string m_login_user;
    // DATA: the state of the line being read, what was counted, and whether the message is refused already.
    uint8_t     m_dstate{0};
    uint64_t    m_size{0};
    bool        m_dropping{false};
    int         m_drop_code{0};
    std::string m_drop_text;
    uint32_t    m_errors{0};
    uint64_t    m_messages{0};
    bool        m_running{false};
    // Shared with the callbacks given out, so one answered after the session is gone does nothing.
    std::shared_ptr<bool> m_alive;
};

}   // namespace socketley::mail
