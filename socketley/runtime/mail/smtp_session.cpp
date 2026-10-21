#include "smtp_session.h"

#include <charconv>
#include <cstring>

#include "../../shared/util/ascii.h"
#include "../../shared/util/base64.h"

namespace socketley::mail
{

namespace
{

// The states of a line of the message: its start, its middle, a CR read, a leading dot, and a CR after that dot.
enum : uint8_t { s_bol, s_mid, s_cr, s_dot, s_dotcr };

bool istarts(std::string_view s, std::string_view prefix)
{
    return s.size() >= prefix.size() && socketley::ascii::iequals(s.substr(0, prefix.size()), prefix);
}

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t'))
        s.remove_suffix(1);
    return s;
}

bool atext(unsigned char c, bool utf8)
{
    if (c >= 0x80)
        return utf8;
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           std::strchr("!#$%&'*+-/=?^_`{|}~", c) != nullptr;
}

// A domain of letters, digits and hyphens in dotted labels, or an address literal in brackets.
bool domain_ok(std::string_view d, bool utf8)
{
    if (d.empty() || d.size() > 255)
        return false;
    if (d.front() == '[')
        return d.size() > 2 && d.back() == ']' && d.substr(1, d.size() - 2).find_first_of(" \\[]") == std::string_view::npos;
    size_t label = 0;
    for (size_t i = 0; i < d.size(); ++i)
    {
        const auto c = static_cast<unsigned char>(d[i]);
        if (c == '.')
        {
            if (label == 0 || d[i - 1] == '-')
                return false;
            label = 0;
            continue;
        }
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                        (c == '-' && label > 0) || (c >= 0x80 && utf8);
        if (!ok || ++label > 63)
            return false;
    }
    return label > 0 && d.back() != '-';
}

}   // namespace

bool parse_address(std::string_view in, address& out, bool utf8)
{
    out = {};
    if (in.empty() || in.size() > 254)
        return false;
    const size_t at = in.rfind('@');
    if (at == std::string_view::npos || at == 0 || at + 1 >= in.size())
        return false;
    const std::string_view local = in.substr(0, at);
    const std::string_view domain = in.substr(at + 1);
    if (local.size() > 64 || !domain_ok(domain, utf8))
        return false;
    if (local.front() == '"')
    {
        if (local.size() < 2 || local.back() != '"')
            return false;
        for (size_t i = 1; i + 1 < local.size(); ++i)
        {
            const auto c = static_cast<unsigned char>(local[i]);
            if (c == '\\')
            {
                if (++i + 1 >= local.size())
                    return false;
                continue;
            }
            if (c == '"' || c < 0x20 || c == 0x7f || (c >= 0x80 && !utf8))
                return false;
        }
    }
    else
    {
        if (local.front() == '.' || local.back() == '.')
            return false;
        for (size_t i = 0; i < local.size(); ++i)
        {
            const auto c = static_cast<unsigned char>(local[i]);
            if (c == '.' ? local[i - 1] == '.' : !atext(c, utf8))
                return false;
        }
    }
    out.local = std::string(local);
    out.domain = std::string(domain);
    socketley::ascii::lower_in_place(out.domain);
    return true;
}

bool parse_path(std::string_view in, address& out, bool allow_null, bool utf8)
{
    out = {};
    if (in.size() < 2 || in.front() != '<' || in.back() != '>')
        return false;
    std::string_view inner = in.substr(1, in.size() - 2);
    if (inner.empty())
        return allow_null;
    // A source route, @a,@b:user@c, is read as its last address (RFC 5321 4.1.2 and C).
    if (inner.front() == '@')
    {
        const size_t colon = inner.find(':');
        if (colon == std::string_view::npos)
            return false;
        inner.remove_prefix(colon + 1);
    }
    // The postmaster of this host, with no domain, is the one recipient that may be named so (RFC 5321 4.5.1).
    if (socketley::ascii::iequals(inner, "postmaster"))
    {
        out.local = "postmaster";
        return true;
    }
    return parse_address(inner, out, utf8);
}

bool xtext_decode(std::string_view in, std::string& out)
{
    out.clear();
    for (size_t i = 0; i < in.size(); ++i)
    {
        const auto c = static_cast<unsigned char>(in[i]);
        if (c == '+')
        {
            // Two upper-case hex digits follow the '+'.
            unsigned v = 0;
            if (i + 2 >= in.size() || std::islower(static_cast<unsigned char>(in[i + 1])) ||
                std::islower(static_cast<unsigned char>(in[i + 2])))
                return false;
            const auto r = std::from_chars(in.data() + i + 1, in.data() + i + 3, v, 16);
            if (r.ec != std::errc() || r.ptr != in.data() + i + 3)
                return false;
            out.push_back(static_cast<char>(v));
            i += 2;
            continue;
        }
        if (c < 33 || c > 126 || c == '=')
            return false;
        out.push_back(static_cast<char>(c));
    }
    return true;
}

std::string xtext_encode(std::string_view in)
{
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string out;
    for (const char ch : in)
    {
        const auto c = static_cast<unsigned char>(ch);
        if (c < 33 || c > 126 || c == '+' || c == '=')
        {
            out.push_back('+');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 15]);
        }
        else
            out.push_back(ch);
    }
    return out;
}

smtp_session::smtp_session(const smtp_config& cfg, hooks& h)
    : m_cfg(cfg), m_hooks(h), m_alive(std::make_shared<bool>(true))
{
}

smtp_session::~smtp_session()
{
    *m_alive = false;
}

void smtp_session::say(std::string_view line)
{
    std::string out;
    out.reserve(line.size() + 2);
    out.append(line);
    out.append("\r\n");
    m_hooks.reply(out);
}

void smtp_session::say(int code, std::string_view enhanced, std::string_view text)
{
    std::string out = std::to_string(code);
    out.push_back(' ');
    if (!enhanced.empty())
    {
        out.append(enhanced);
        out.push_back(' ');
    }
    out.append(text);
    out.append("\r\n");
    m_hooks.reply(out);
}

void smtp_session::greet()
{
    say(220, {}, m_cfg.hostname + " ESMTP socketley");
}

void smtp_session::error(int code, std::string_view enhanced, std::string_view text)
{
    if (++m_errors >= max_errors)
    {
        say(421, "4.7.0", m_cfg.hostname + " too many errors, closing");
        m_phase = phase::closed;
        m_hooks.close();
        return;
    }
    say(code, enhanced, text);
}

void smtp_session::reset()
{
    // A message BDAT began goes with the transaction.
    if (m_chunking)
    {
        m_chunking = false;
        m_hooks.data_abort(false);
    }
    m_from = {};
    m_have_from = false;
    m_rcpts.clear();
    m_rcpt_dsn.clear();
    m_ret = 0;
    m_envid.clear();
    m_8bit = false;
    m_utf8 = false;
    m_declared = 0;
}

void smtp_session::wait()
{
    m_phase = phase::waiting;
}

void smtp_session::resume()
{
    if (m_phase == phase::waiting)
        m_phase = phase::command;
    // An answer given while run() is still on the stack is taken up by its loop, so pipelined commands answered at
    // once do not nest one call deeper each.
    if (!m_running)
        run();
}

void smtp_session::input(std::string_view bytes)
{
    if (m_phase == phase::closed)
        return;
    // A message's bytes with nothing kept ahead of them are read where they lie.
    if ((m_phase == phase::data || m_phase == phase::chunk) && m_at == m_in.size())
    {
        m_in.clear();
        m_at = 0;
        if (!(m_phase == phase::data ? data(bytes) : chunk(bytes)))
            return;
        m_in.assign(bytes);
        run();
        return;
    }
    m_in.append(bytes);
    run();
}

void smtp_session::run()
{
    m_running = true;
    while (m_phase != phase::waiting && m_phase != phase::closed && m_at < m_in.size())
    {
        if (m_phase == phase::data || m_phase == phase::chunk)
        {
            std::string_view rest(m_in.data() + m_at, m_in.size() - m_at);
            const size_t before = rest.size();
            const bool ended = m_phase == phase::data ? data(rest) : chunk(rest);
            m_at += before - rest.size();
            if (!ended)
                break;
            continue;
        }
        const char* start = m_in.data() + m_at;
        const void* nl = std::memchr(start, '\n', m_in.size() - m_at);
        if (!nl)
        {
            if (m_in.size() - m_at > max_command)
            {
                // The line so far is dropped and its end looked for, since the client says no more than that.
                m_in.clear();
                m_at = 0;
                error(500, "5.5.2", "Line too long");
            }
            break;
        }
        const size_t len = static_cast<const char*>(nl) - start;
        std::string_view line(start, len);
        m_at += len + 1;
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (line.size() > max_command)
        {
            error(500, "5.5.2", "Line too long");
            continue;
        }
        switch (m_phase)
        {
            case phase::command:
                command(line);
                break;
            case phase::auth_plain:
                m_phase = phase::command;
                if (line == "*")
                    error(501, "5.0.0", "Authentication cancelled");
                else
                    auth_plain(line);
                break;
            case phase::auth_login_user:
            {
                m_phase = phase::command;
                std::string user;
                if (line == "*" || !socketley::base64::decode(line, user))
                {
                    error(501, "5.5.2", line == "*" ? "Authentication cancelled" : "Cannot decode the user name");
                    break;
                }
                m_login_user = std::move(user);
                m_phase = phase::auth_login_pass;
                say("334 UGFzc3dvcmQ6");
                break;
            }
            case phase::auth_login_pass:
            {
                m_phase = phase::command;
                std::string pass;
                if (line == "*" || !socketley::base64::decode(line, pass))
                {
                    error(501, "5.5.2", line == "*" ? "Authentication cancelled" : "Cannot decode the password");
                    break;
                }
                sign_in("LOGIN", std::move(m_login_user), std::move(pass));
                m_login_user.clear();
                break;
            }
            default:
                break;
        }
    }
    if (m_at >= m_in.size())
    {
        m_in.clear();
        m_at = 0;
    }
    else if (m_at > 65536 && m_at > m_in.size() / 2)
    {
        m_in.erase(0, m_at);
        m_at = 0;
    }
    m_running = false;
}

void smtp_session::command(std::string_view line)
{
    const size_t sp = line.find(' ');
    const std::string_view verb = line.substr(0, sp);
    const std::string_view arg = sp == std::string_view::npos ? std::string_view{} : trim(line.substr(sp + 1));
    using socketley::ascii::iequals;
    if (iequals(verb, "EHLO") || iequals(verb, "HELO"))
        return ehlo(arg, iequals(verb, "EHLO"));
    if (iequals(verb, "MAIL"))
        return mail(arg);
    if (iequals(verb, "RCPT"))
        return rcpt(arg);
    if (iequals(verb, "DATA"))
    {
        if (!arg.empty())
            return error(501, "5.5.4", "DATA takes no argument");
        if (!m_have_from)
            return error(503, "5.5.1", "MAIL first");
        if (m_rcpts.empty())
            return error(554, "5.5.1", "No valid recipients");
        if (m_chunking)
            return error(503, "5.5.1", "BDAT already began the message");
        if (!m_hooks.data_begin())
        {
            say(451, "4.3.0", "The message cannot be kept now, try again later");
            reset();
            return;
        }
        m_phase = phase::data;
        m_dstate = s_bol;
        m_size = 0;
        m_dropping = false;
        say(354, {}, "End data with <CR><LF>.<CR><LF>");
        return;
    }
    if (iequals(verb, "BDAT"))
        return bdat(arg);
    if (iequals(verb, "RSET"))
    {
        reset();
        return say(250, "2.0.0", "OK");
    }
    if (iequals(verb, "NOOP"))
        return say(250, "2.0.0", "OK");
    if (iequals(verb, "QUIT"))
    {
        say(221, "2.0.0", m_cfg.hostname + " closing");
        m_phase = phase::closed;
        m_hooks.close();
        return;
    }
    if (iequals(verb, "STARTTLS"))
    {
        if (!m_cfg.tls_offered || m_cfg.tls_active)
            return error(m_cfg.tls_active ? 503 : 502, "5.5.1", m_cfg.tls_active ? "TLS already active"
                                                                                  : "TLS not available");
        if (!arg.empty())
            return error(501, "5.5.4", "STARTTLS takes no argument");
        say(220, "2.0.0", "Ready to start TLS");
        // Whatever the client sent after STARTTLS was sent in the clear and is dropped, so none of it is taken as said
        // over TLS (CVE-2011-0411).
        m_in.clear();
        m_at = 0;
        m_phase = phase::waiting;
        m_hooks.start_tls();
        return;
    }
    if (iequals(verb, "AUTH"))
        return auth(arg);
    if (iequals(verb, "VRFY"))
        return say(252, "2.5.0", "Cannot verify the user, but will try to deliver");
    if (iequals(verb, "EXPN"))
        return error(502, "5.5.1", "EXPN not available");
    if (iequals(verb, "HELP"))
        return say(214, "2.0.0", "See RFC 5321");
    // A client that speaks HTTP to a mail port is a browser or a scanner, and one reply is all it gets.
    if (iequals(verb, "GET") || iequals(verb, "POST") || iequals(verb, "CONNECT") || iequals(verb, "HEAD"))
    {
        say(554, "5.7.0", "This is a mail server");
        m_phase = phase::closed;
        m_hooks.close();
        return;
    }
    error(500, "5.5.2", "Command not recognized");
}

void smtp_session::ehlo(std::string_view arg, bool extended)
{
    if (arg.empty())
        return error(501, "5.5.4", extended ? "EHLO requires a domain or address" : "HELO requires a domain");
    reset();
    m_helo = std::string(arg.substr(0, 255));
    m_esmtp = extended;
    if (!extended)
        return say(250, {}, m_cfg.hostname);
    std::string out = "250-" + m_cfg.hostname + "\r\n";
    out += "250-PIPELINING\r\n";
    out += "250-SIZE " + std::to_string(m_cfg.max_size) + "\r\n";
    out += "250-8BITMIME\r\n";
    out += "250-SMTPUTF8\r\n";
    out += "250-CHUNKING\r\n";
    out += "250-DSN\r\n";
    if (m_cfg.tls_offered && !m_cfg.tls_active)
        out += "250-STARTTLS\r\n";
    if (m_cfg.auth_offered && m_user.empty() && (m_cfg.tls_active || m_cfg.auth_in_clear))
        out += "250-AUTH PLAIN LOGIN\r\n";
    out += "250 ENHANCEDSTATUSCODES\r\n";
    m_hooks.reply(out);
}

void smtp_session::mail(std::string_view arg)
{
    if (m_helo.empty())
        return error(503, "5.5.1", "EHLO first");
    if (m_have_from)
        return error(503, "5.5.1", "Sender already given");
    if (m_cfg.tls_required && !m_cfg.tls_active)
        return error(530, "5.7.0", "Must issue a STARTTLS command first");
    if (m_cfg.auth_required && m_user.empty())
        return error(530, "5.7.0", "Authentication required");
    if (!istarts(arg, "FROM:"))
        return error(501, "5.5.4", "Syntax: MAIL FROM:<address>");
    std::string_view rest = trim(arg.substr(5));
    const size_t close = rest.find('>');
    if (rest.empty() || rest.front() != '<' || close == std::string_view::npos)
        return error(501, "5.1.7", "Bad sender address syntax");
    const std::string_view path = rest.substr(0, close + 1);
    std::string_view params = trim(rest.substr(close + 1));
    bool utf8 = false, eight = false;
    uint64_t declared = 0;
    uint8_t ret = 0;
    std::string envid;
    while (!params.empty())
    {
        const size_t sp = params.find(' ');
        const std::string_view p = params.substr(0, sp);
        params = sp == std::string_view::npos ? std::string_view{} : trim(params.substr(sp + 1));
        if (istarts(p, "SIZE="))
        {
            const std::string_view v = p.substr(5);
            const auto r = std::from_chars(v.data(), v.data() + v.size(), declared);
            if (r.ec != std::errc() || r.ptr != v.data() + v.size())
                return error(501, "5.5.4", "Bad SIZE");
            if (declared > m_cfg.max_size)
                return error(552, "5.3.4", "Message size exceeds the limit");
        }
        else if (istarts(p, "BODY="))
        {
            const std::string_view v = p.substr(5);
            if (socketley::ascii::iequals(v, "8BITMIME"))
                eight = true;
            else if (!socketley::ascii::iequals(v, "7BIT"))
                return error(501, "5.5.4", "Bad BODY");
        }
        else if (socketley::ascii::iequals(p, "SMTPUTF8"))
            utf8 = true;
        else if (istarts(p, "AUTH="))
        {
            // The identity a relay says it was told: taken as said, since only a signed-in client may say one.
        }
        else if (istarts(p, "RET="))
        {
            const std::string_view v = p.substr(4);
            if (ret || !(socketley::ascii::iequals(v, "FULL") || socketley::ascii::iequals(v, "HDRS")))
                return error(501, "5.5.4", "Bad RET");
            ret = socketley::ascii::iequals(v, "FULL") ? 1 : 2;
        }
        else if (istarts(p, "ENVID="))
        {
            std::string plain;
            if (!envid.empty() || !xtext_decode(p.substr(6), plain) || plain.empty() || plain.size() > 100)
                return error(501, "5.5.4", "Bad ENVID");
            envid = std::string(p.substr(6));
        }
        else
            return error(555, "5.5.4", "Unsupported parameter");
    }
    address from;
    if (!parse_path(path, from, true, utf8))
        return error(501, "5.1.7", "Bad sender address syntax");
    if (!from.empty() && from.domain.empty())
        return error(501, "5.1.7", "Bad sender address syntax");
    wait();
    m_hooks.mail_from(from, [this, alive = m_alive, from, utf8, eight, declared, ret, envid](rcpt_verdict v) {
        if (!*alive)
            return;
        if (v.code / 100 == 2)
        {
            m_from = from;
            m_have_from = true;
            m_ret = ret;
            m_envid = envid;
            m_utf8 = utf8;
            m_8bit = eight;
            m_declared = declared;
            say(250, "2.1.0", v.text.empty() ? "OK" : v.text);
        }
        else
            error(v.code, v.code / 100 == 4 ? "4.7.1" : "5.7.1", v.text.empty() ? "Sender refused" : v.text);
        resume();
    });
}

void smtp_session::rcpt(std::string_view arg)
{
    if (!m_have_from)
        return error(503, "5.5.1", "MAIL first");
    if (!istarts(arg, "TO:"))
        return error(501, "5.5.4", "Syntax: RCPT TO:<address>");
    std::string_view rest = trim(arg.substr(3));
    const size_t close = rest.find('>');
    if (rest.empty() || rest.front() != '<' || close == std::string_view::npos)
        return error(501, "5.1.3", "Bad recipient address syntax");
    address to;
    if (!parse_path(rest.substr(0, close + 1), to, false, m_utf8))
        return error(501, "5.1.3", "Bad recipient address syntax");
    dsn_rcpt dsn;
    std::string_view params = trim(rest.substr(close + 1));
    while (!params.empty())
    {
        const size_t sp = params.find(' ');
        const std::string_view p = params.substr(0, sp);
        params = sp == std::string_view::npos ? std::string_view{} : trim(params.substr(sp + 1));
        if (istarts(p, "NOTIFY="))
        {
            std::string_view list = p.substr(7);
            if (dsn.notify || list.empty())
                return error(501, "5.5.4", "Bad NOTIFY");
            while (!list.empty())
            {
                const size_t comma = list.find(',');
                const std::string_view w = list.substr(0, comma);
                list = comma == std::string_view::npos ? std::string_view{} : list.substr(comma + 1);
                using socketley::ascii::iequals;
                const uint8_t bit = iequals(w, "NEVER") ? notify_never : iequals(w, "SUCCESS") ? notify_success
                                  : iequals(w, "FAILURE") ? notify_failure : iequals(w, "DELAY") ? notify_delay : 0;
                // NEVER stands alone (RFC 3461 4.1).
                if (!bit || (dsn.notify & bit) || (bit == notify_never && dsn.notify) || (dsn.notify & notify_never))
                    return error(501, "5.5.4", "Bad NOTIFY");
                dsn.notify |= bit;
            }
        }
        else if (istarts(p, "ORCPT="))
        {
            const std::string_view v = p.substr(6);
            const size_t semi = v.find(';');
            std::string plain;
            if (!dsn.orcpt.empty() || semi == 0 || semi == std::string_view::npos || v.size() > 500 ||
                !xtext_decode(v.substr(semi + 1), plain))
                return error(501, "5.5.4", "Bad ORCPT");
            dsn.orcpt = std::string(v);
        }
        else
            return error(555, "5.5.4", "Unsupported parameter");
    }
    if (m_rcpts.size() >= m_cfg.max_rcpt)
        return say(452, "4.5.3", "Too many recipients");
    wait();
    m_hooks.rcpt_to(to, [this, alive = m_alive, to, dsn = std::move(dsn)](rcpt_verdict v) {
        if (!*alive)
            return;
        if (v.code / 100 == 2)
        {
            m_rcpts.push_back(to);
            m_rcpt_dsn.push_back(dsn);
            say(250, "2.1.5", v.text.empty() ? "OK" : v.text);
        }
        else
        {
            const char* enhanced = v.code == 550 ? "5.1.1" : v.code == 554 ? "5.7.1" : v.code / 100 == 4 ? "4.2.0"
                                                                                                         : "5.7.1";
            error(v.code, enhanced, v.text.empty() ? "Recipient refused" : v.text);
        }
        resume();
    });
}

void smtp_session::auth(std::string_view arg)
{
    if (m_helo.empty() || !m_esmtp)
        return error(503, "5.5.1", "EHLO first");
    if (!m_user.empty())
        return error(503, "5.5.1", "Already authenticated");
    if (m_have_from)
        return error(503, "5.5.1", "AUTH not allowed during a mail transaction");
    if (!m_cfg.auth_offered)
        return error(502, "5.5.1", "AUTH not available");
    if (!m_cfg.tls_active && !m_cfg.auth_in_clear)
        return error(538, "5.7.11", "Encryption required for requested authentication mechanism");
    const size_t sp = arg.find(' ');
    const std::string_view mech = arg.substr(0, sp);
    const std::string_view initial = sp == std::string_view::npos ? std::string_view{} : trim(arg.substr(sp + 1));
    if (socketley::ascii::iequals(mech, "PLAIN"))
    {
        if (initial.empty())
        {
            m_phase = phase::auth_plain;
            say("334 ");
            return;
        }
        return auth_plain(initial);
    }
    if (socketley::ascii::iequals(mech, "LOGIN"))
    {
        if (initial.empty())
        {
            m_phase = phase::auth_login_user;
            say("334 VXNlcm5hbWU6");
            return;
        }
        std::string user;
        if (!socketley::base64::decode(initial, user))
            return error(501, "5.5.2", "Cannot decode the user name");
        m_login_user = std::move(user);
        m_phase = phase::auth_login_pass;
        say("334 UGFzc3dvcmQ6");
        return;
    }
    error(504, "5.5.4", "Unrecognized authentication type");
}

void smtp_session::auth_plain(std::string_view b64)
{
    std::string raw;
    if (b64 == "=")
        raw.clear();
    else if (!socketley::base64::decode(b64, raw))
        return error(501, "5.5.2", "Cannot decode the response");
    // authzid NUL authcid NUL password, the identity asked for being the one signed in as or none (RFC 4616).
    const size_t a = raw.find('\0');
    const size_t b = a == std::string::npos ? std::string::npos : raw.find('\0', a + 1);
    if (b == std::string::npos)
        return error(501, "5.5.2", "Malformed PLAIN response");
    std::string authz = raw.substr(0, a);
    std::string user = raw.substr(a + 1, b - a - 1);
    std::string pass = raw.substr(b + 1);
    if (user.empty() || (!authz.empty() && authz != user))
        return error(535, "5.7.8", "Authentication credentials invalid");
    sign_in("PLAIN", std::move(user), std::move(pass));
}

void smtp_session::sign_in(std::string_view mech, std::string user, std::string secret)
{
    wait();
    m_hooks.authenticate(mech, std::move(user), std::move(secret), [this, alive = m_alive](bool ok, std::string name) {
        if (!*alive)
            return;
        if (ok)
        {
            m_user = std::move(name);
            say(235, "2.7.0", "Authentication successful");
        }
        else
            error(535, "5.7.8", "Authentication credentials invalid");
        resume();
    });
}

void smtp_session::tls_started()
{
    m_cfg.tls_active = true;
    m_helo.clear();
    m_esmtp = false;
    m_user.clear();
    reset();
    m_phase = phase::command;
    run();
}

void smtp_session::gone()
{
    if (m_phase == phase::data || m_chunking)
        m_hooks.data_abort(false);
    m_chunking = false;
    m_phase = phase::closed;
}

void smtp_session::drop_data(int code, std::string_view enhanced, std::string_view text)
{
    m_dropping = true;
    m_drop_code = code;
    m_drop_text = std::string(enhanced) + " " + std::string(text);
}

bool smtp_session::data(std::string_view& in)
{
    std::string out;
    out.reserve(in.size() + 16);
    const char* p = in.data();
    const char* end = p + in.size();
    bool ended = false;
    while (p < end && !ended)
    {
        switch (m_dstate)
        {
            case s_mid:
            {
                // The rest of the line in one copy, its end looked for with memchr.
                const char* nl = static_cast<const char*>(std::memchr(p, '\n', static_cast<size_t>(end - p)));
                if (!nl)
                {
                    const char* stop = end;
                    if (end[-1] == '\r')
                    {
                        --stop;
                        m_dstate = s_cr;
                    }
                    out.append(p, static_cast<size_t>(stop - p));
                    p = end;
                    break;
                }
                // A bare LF ends the line as a CRLF would.
                if (nl > p && nl[-1] == '\r')
                    out.append(p, static_cast<size_t>(nl + 1 - p));
                else
                {
                    out.append(p, static_cast<size_t>(nl - p));
                    out.append("\r\n");
                }
                p = nl + 1;
                m_dstate = s_bol;
                break;
            }
            case s_bol:
                if (*p == '.')
                {
                    m_dstate = s_dot;
                    ++p;
                }
                else
                    m_dstate = s_mid;
                break;
            case s_cr:
                if (*p == '\n')
                {
                    out.append("\r\n");
                    ++p;
                    m_dstate = s_bol;
                }
                else
                {
                    out.push_back('\r');
                    m_dstate = s_mid;
                }
                break;
            case s_dot:
                if (*p == '\r')
                {
                    m_dstate = s_dotcr;
                    ++p;
                }
                else if (*p == '\n')
                {
                    // A lone dot ended by a bare LF is no end: the line is an empty one.
                    out.append("\r\n");
                    ++p;
                    m_dstate = s_bol;
                }
                else
                    m_dstate = s_mid;
                break;
            case s_dotcr:
                if (*p == '\n')
                {
                    ++p;
                    ended = true;
                }
                else
                {
                    out.push_back('\r');
                    m_dstate = s_mid;
                }
                break;
            default:
                m_dstate = s_mid;
                break;
        }
    }
    in.remove_prefix(static_cast<size_t>(p - in.data()));
    if (!out.empty() && !m_dropping)
    {
        m_size += out.size();
        if (m_size > m_cfg.max_size)
        {
            drop_data(552, "5.3.4", "Message size exceeds the limit");
            m_hooks.data_abort(true);
        }
        else
            m_hooks.data_bytes(out);
    }
    if (!ended)
        return false;
    if (m_dropping)
    {
        const std::string text = m_drop_text;
        const int code = m_drop_code;
        reset();
        m_phase = phase::command;
        m_dropping = false;
        say(std::to_string(code) + " " + text);
        return true;
    }
    message_end();
    return true;
}

void smtp_session::message_end()
{
    wait();
    m_hooks.data_end([this, alive = m_alive](rcpt_verdict v) {
        if (!*alive)
            return;
        if (v.code / 100 == 2)
            ++m_messages;
        say(v.code, v.code / 100 == 2 ? "2.0.0" : v.code / 100 == 4 ? "4.3.0" : "5.7.1",
            v.text.empty() ? (v.code / 100 == 2 ? "OK" : "Message refused") : v.text);
        reset();
        resume();
    });
}

void smtp_session::bdat(std::string_view arg)
{
    const size_t sp = arg.find(' ');
    const std::string_view n = arg.substr(0, sp);
    const std::string_view rest = sp == std::string_view::npos ? std::string_view{} : trim(arg.substr(sp + 1));
    uint64_t size = 0;
    const auto r = std::from_chars(n.data(), n.data() + n.size(), size);
    if (n.empty() || r.ec != std::errc() || r.ptr != n.data() + n.size() ||
        !(rest.empty() || socketley::ascii::iequals(rest, "LAST")))
        // A chunk whose size cannot be read cannot be skipped either: the connection is not to be trusted after it.
        return error(501, "5.5.4", "Syntax: BDAT <size> [LAST]");
    m_chunk_left = size;
    m_chunk_last = !rest.empty();
    m_chunk_refused = false;
    m_chunk_reply.clear();
    // A chunk that cannot be taken is read all the same, as its bytes are no commands (RFC 3030 2).
    if (!m_have_from)
    {
        m_chunk_refused = true;
        m_chunk_reply = "503 5.5.1 MAIL first";
    }
    else if (m_rcpts.empty())
    {
        m_chunk_refused = true;
        m_chunk_reply = "554 5.5.1 No valid recipients";
    }
    else if (!m_chunking)
    {
        if (!m_hooks.data_begin())
        {
            m_chunk_refused = true;
            m_chunk_reply = "451 4.3.0 The message cannot be kept now, try again later";
        }
        else
        {
            m_chunking = true;
            m_size = 0;
            m_dropping = false;
            m_chunk_cr = false;
        }
    }
    m_phase = phase::chunk;
    if (m_chunk_left == 0)
    {
        std::string_view none;
        chunk(none);
    }
}

bool smtp_session::chunk(std::string_view& in)
{
    const size_t n = static_cast<size_t>(std::min<uint64_t>(m_chunk_left, in.size()));
    const std::string_view piece = in.substr(0, n);
    in.remove_prefix(n);
    m_chunk_left -= n;
    if (!m_chunk_refused && !m_dropping && !piece.empty())
    {
        // A bare LF is written as CRLF, as DATA writes it, so what is relayed by DATA ends where this one ends.
        std::string out;
        out.reserve(piece.size() + 16);
        size_t from = 0;
        for (size_t i = 0; i < piece.size(); ++i)
            if (piece[i] == '\n' && !(i ? piece[i - 1] == '\r' : m_chunk_cr))
            {
                out.append(piece, from, i - from);
                out.append("\r\n");
                from = i + 1;
            }
        out.append(piece, from, piece.size() - from);
        m_chunk_cr = piece.back() == '\r';
        m_size += out.size();
        if (m_size > m_cfg.max_size)
        {
            m_dropping = true;
            m_hooks.data_abort(true);
        }
        else
            m_hooks.data_bytes(out);
    }
    if (m_chunk_left > 0)
        return false;
    m_phase = phase::command;
    if (m_chunk_refused)
    {
        say(m_chunk_reply);
        return true;
    }
    if (m_dropping)
    {
        // The message is over its size: the transaction goes, and a BDAT after this one is told MAIL first.
        m_chunking = false;
        m_dropping = false;
        reset();
        say(552, "5.3.4", "Message size exceeds the limit");
        return true;
    }
    if (!m_chunk_last)
    {
        say(250, "2.0.0", std::to_string(m_size) + " octets received");
        return true;
    }
    m_chunking = false;
    message_end();
    return true;
}

}   // namespace socketley::mail
