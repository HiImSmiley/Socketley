#include "pop3_session.h"
#include "mail_sasl.h"

#include <algorithm>
#include <charconv>
#include <cstring>

#include "../../shared/util/ascii.h"
#include "../../shared/util/base64.h"

namespace socketley::mail
{

pop3_session::pop3_session(const pop3_config& cfg, hooks& h) : m_cfg(cfg), m_hooks(h) {}

pop3_session::~pop3_session()
{
    *m_alive = false;
}

void pop3_session::ok(std::string_view text)
{
    m_hooks.reply("+OK " + std::string(text) + "\r\n");
}

void pop3_session::err(std::string_view text)
{
    m_hooks.reply("-ERR " + std::string(text) + "\r\n");
    if (++m_errors > 30)
    {
        m_hooks.reply("-ERR too many errors\r\n");
        m_closed = true;
        m_hooks.close();
    }
}

void pop3_session::greet()
{
    ok(m_cfg.hostname + " POP3 ready");
}

void pop3_session::tls_started()
{
    m_cfg.tls_active = true;
    m_waiting = false;
    m_in.clear();
    m_at = 0;
}

void pop3_session::capabilities()
{
    // A password is offered for where it does not go in the clear (RFC 2595 2.2).
    const bool sasl = m_cfg.tls_active || m_cfg.login_in_clear;
    std::string out = "+OK Capability list follows\r\nTOP\r\nUIDL\r\nRESP-CODES\r\nAUTH-RESP-CODE\r\nPIPELINING\r\n";
    if (sasl)
        out += m_cfg.bearer_offered ? "USER\r\nSASL PLAIN XOAUTH2 OAUTHBEARER\r\n" : "USER\r\nSASL PLAIN\r\n";
    if (m_cfg.tls_offered && !m_cfg.tls_active && !m_transaction)
        out += "STLS\r\n";
    out += "IMPLEMENTATION socketley\r\n.\r\n";
    m_hooks.reply(out);
}

void pop3_session::input(std::string_view bytes)
{
    if (m_closed)
        return;
    m_in.append(bytes);
    run();
}

void pop3_session::run()
{
    m_running = true;
    while (!m_closed && !m_waiting && m_at < m_in.size())
    {
        const char* start = m_in.data() + m_at;
        const void* nl = std::memchr(start, '\n', m_in.size() - m_at);
        if (!nl)
        {
            // Past a line's limit what came is dropped, and so is the rest of that line when it comes, said once.
            if (m_in.size() - m_at > max_line + 1)
            {
                m_in.clear();
                m_at = 0;
                if (!m_discarding)
                    err("line too long");
                m_discarding = true;
            }
            break;
        }
        std::string_view line(start, static_cast<size_t>(static_cast<const char*>(nl) - start));
        m_at += line.size() + 1;
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (m_discarding || line.size() > max_line)
        {
            if (!m_discarding)
                err("line too long");
            m_discarding = false;
            continue;
        }
        command(line);
    }
    if (m_at >= m_in.size())
    {
        m_in.clear();
        m_at = 0;
    }
    else if (m_at > 65536)
    {
        m_in.erase(0, m_at);
        m_at = 0;
    }
    m_running = false;
}

size_t pop3_session::number(std::string_view arg) const
{
    size_t n = 0;
    const auto r = std::from_chars(arg.data(), arg.data() + arg.size(), n);
    if (r.ec != std::errc() || r.ptr != arg.data() + arg.size() || n == 0 || n > m_drop.size() || m_deleted[n - 1])
        return 0;
    return n;
}

std::string pop3_session::multiline(std::string_view message, int64_t lines)
{
    std::string out = "+OK\r\n";
    out.reserve(message.size() + message.size() / 64 + 16);
    bool body = false;
    int64_t left = lines;
    for (size_t at = 0; at < message.size();)
    {
        const size_t nl = message.find("\r\n", at);
        const std::string_view l = message.substr(at, nl == std::string_view::npos ? std::string_view::npos : nl - at);
        at = nl == std::string_view::npos ? message.size() : nl + 2;
        if (body && lines >= 0 && left-- <= 0)
            break;
        // A line that begins with the terminator's dot is stuffed with another (RFC 1939 3).
        if (l.starts_with('.'))
            out += '.';
        out.append(l).append("\r\n");
        if (!body && l.empty())
            body = true;
    }
    return out + ".\r\n";
}

void pop3_session::sign_in(std::string user, std::string password)
{
    m_waiting = true;
    m_hooks.login(std::move(user), std::move(password), [this, alive = m_alive](account a, std::string name) {
        if (!*alive)
            return;
        const bool plain = !name.empty() && std::none_of(name.begin(), name.end(), [](char c) {
            return static_cast<unsigned char>(c) < 0x20 || c == 0x7f;
        });
        if (a == account::unreachable)
        {
            m_waiting = false;
            err("[SYS/TEMP] the accounts cannot be checked now");
        }
        else if (a != account::yes || !plain)
        {
            m_waiting = false;
            err("[AUTH] authentication failed");
        }
        else
        {
            const std::string who = name;
            m_hooks.maildrop(who, [this, who, alive](bool good, uint32_t validity, std::vector<message> drop) {
                if (!*alive)
                    return;
                m_waiting = false;
                if (!good)
                    err("[SYS/TEMP] the maildrop cannot be read now");
                else
                {
                    m_user = who;
                    m_transaction = true;
                    m_validity = validity;
                    m_drop = std::move(drop);
                    m_deleted.assign(m_drop.size(), false);
                    ok("maildrop has " + std::to_string(m_drop.size()) + " messages");
                }
                if (!m_running)
                    run();
            });
            return;
        }
        if (!m_running)
            run();
    });
}

void pop3_session::command(std::string_view line)
{
    if (m_sasl)
    {
        m_sasl = false;
        if (line == "*")
        {
            err("authentication cancelled");
            return;
        }
        std::string raw;
        if (m_sasl_mech != "plain")
        {
            std::string user, token;
            if (!socketley::base64::decode(line, raw) || !sasl_bearer(m_sasl_mech, raw, user, token) || user.empty())
                err("[AUTH] authentication failed");
            else
                sign_in(std::move(user), std::move(token));
            return;
        }
        const size_t a = socketley::base64::decode(line, raw) ? raw.find('\0') : std::string::npos;
        const size_t b = a == std::string::npos ? a : raw.find('\0', a + 1);
        if (b == std::string::npos || raw.substr(a + 1, b - a - 1).empty() ||
            (a > 0 && raw.substr(0, a) != raw.substr(a + 1, b - a - 1)))
        {
            err("[AUTH] authentication failed");
            return;
        }
        sign_in(raw.substr(a + 1, b - a - 1), raw.substr(b + 1));
        return;
    }
    const size_t sp = line.find(' ');
    std::string verb(line.substr(0, sp));
    socketley::ascii::lower_in_place(verb);
    const std::string_view arg = sp == std::string_view::npos ? std::string_view{} : line.substr(sp + 1);
    const std::string_view arg1 = arg.substr(0, arg.find(' '));
    const std::string_view arg2 = arg.find(' ') == std::string_view::npos ? std::string_view{} : arg.substr(arg.find(' ') + 1);
    if (verb == "capa")
    {
        capabilities();
        return;
    }
    if (verb == "quit")
    {
        if (!m_transaction)
        {
            ok(m_cfg.hostname + " closing");
            m_closed = true;
            m_hooks.close();
            return;
        }
        // The UPDATE state: what was marked deleted goes now (RFC 1939 6).
        std::vector<uint32_t> gone;
        for (size_t i = 0; i < m_drop.size(); ++i)
            if (m_deleted[i])
                gone.push_back(m_drop[i].uid);
        m_waiting = true;
        const auto bye = [this, alive = m_alive](bool good) {
            if (!*alive)
                return;
            if (good)
                ok(m_cfg.hostname + " closing");
            else
                err("[SYS/TEMP] some deleted messages were not removed");
            if (m_closed)
                return;
            m_closed = true;
            m_hooks.close();
        };
        if (gone.empty())
            bye(true);
        else
            m_hooks.remove(m_user, std::move(gone), bye);
        return;
    }
    if (!m_transaction)
    {
        if (verb == "stls")
        {
            if (!m_cfg.tls_offered || m_cfg.tls_active)
            {
                err("STLS is not available now");
                return;
            }
            ok("begin TLS negotiation");
            m_waiting = true;
            m_hooks.start_tls();
            return;
        }
        const bool may = m_cfg.tls_active || m_cfg.login_in_clear;
        if (verb == "user")
        {
            if (!may)
                err("[AUTH] a password goes over TLS only: STLS first");
            else if (arg.empty())
                err("USER names a user");
            else
            {
                m_pending_user = std::string(arg);
                ok("send the password");
            }
            return;
        }
        if (verb == "pass")
        {
            if (!may || m_pending_user.empty())
            {
                err(may ? "USER first" : "[AUTH] a password goes over TLS only: STLS first");
                return;
            }
            std::string user = std::move(m_pending_user);
            m_pending_user.clear();
            sign_in(std::move(user), std::string(arg));
            return;
        }
        if (verb == "auth")
        {
            std::string mech(arg1);
            socketley::ascii::lower_in_place(mech);
            if (!may)
                err("[AUTH] a password goes over TLS only: STLS first");
            else if (mech != "plain" && !(m_cfg.bearer_offered && (mech == "xoauth2" || mech == "oauthbearer")))
                err(m_cfg.bearer_offered ? "PLAIN, XOAUTH2 and OAUTHBEARER are offered" : "only PLAIN is offered");
            else if (m_sasl_mech = mech == "plain" ? "plain" : mech == "xoauth2" ? "XOAUTH2" : "OAUTHBEARER"; !arg2.empty())
            {
                m_sasl = true;
                command(arg2 == "=" ? std::string_view{} : arg2);
            }
            else
            {
                m_sasl = true;
                m_hooks.reply("+ \r\n");
            }
            return;
        }
        err("sign in first");
        return;
    }
    if (verb == "stat")
    {
        size_t n = 0;
        uint64_t bytes = 0;
        for (size_t i = 0; i < m_drop.size(); ++i)
            if (!m_deleted[i])
            {
                ++n;
                bytes += m_drop[i].size;
            }
        ok(std::to_string(n) + " " + std::to_string(bytes));
        return;
    }
    if (verb == "list" || verb == "uidl")
    {
        const bool uidl = verb == "uidl";
        const auto one = [&](size_t i) {
            return std::to_string(i + 1) + " " +
                   (uidl ? std::to_string(m_validity) + "." + std::to_string(m_drop[i].uid)
                         : std::to_string(m_drop[i].size));
        };
        if (!arg.empty())
        {
            if (const size_t n = number(arg))
                ok(one(n - 1));
            else
                err("no such message");
            return;
        }
        std::string out = "+OK\r\n";
        for (size_t i = 0; i < m_drop.size(); ++i)
            if (!m_deleted[i])
                out += one(i) + "\r\n";
        m_hooks.reply(out + ".\r\n");
        return;
    }
    if (verb == "retr" || verb == "top")
    {
        const size_t n = number(arg1);
        int64_t lines = -1;
        if (verb == "top")
        {
            const auto r = std::from_chars(arg2.data(), arg2.data() + arg2.size(), lines);
            if (arg2.empty() || r.ec != std::errc() || r.ptr != arg2.data() + arg2.size() || lines < 0)
            {
                err("TOP takes a message and a count of lines");
                return;
            }
        }
        if (!n)
        {
            err("no such message");
            return;
        }
        m_waiting = true;
        m_hooks.read(m_drop[n - 1], [this, lines, alive = m_alive](std::shared_ptr<const std::string> b) {
            if (!*alive)
                return;
            m_waiting = false;
            if (!b)
                err("[SYS/TEMP] the message cannot be read now");
            else
                m_hooks.reply(multiline(*b, lines));
            if (!m_running)
                run();
        });
        return;
    }
    if (verb == "dele")
    {
        if (const size_t n = number(arg))
        {
            m_deleted[n - 1] = true;
            ok("message " + std::to_string(n) + " deleted");
        }
        else
            err("no such message");
        return;
    }
    if (verb == "rset")
    {
        m_deleted.assign(m_drop.size(), false);
        ok("maildrop has " + std::to_string(m_drop.size()) + " messages");
        return;
    }
    if (verb == "noop")
    {
        ok("");
        return;
    }
    err("unknown command");
}

}   // namespace socketley::mail
