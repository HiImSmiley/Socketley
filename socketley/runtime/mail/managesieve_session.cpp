#include "managesieve_session.h"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <memory>

#include "mail_sieve.h"
#include "mail_sieve_store.h"
#include "../../shared/util/ascii.h"
#include "../../shared/util/base64.h"

namespace socketley::mail
{

managesieve_session::managesieve_session(const managesieve_config& cfg, hooks& h, sieve_store& store)
    : m_cfg(cfg), m_hooks(h), m_store(store)
{
}

managesieve_session::~managesieve_session()
{
    *m_alive = false;
}

std::string managesieve_session::quoted(std::string_view s) const
{
    std::string out = "\"";
    for (const char c : s)
    {
        if (c == '"' || c == '\\')
            out += '\\';
        out += (c == '\r' || c == '\n') ? ' ' : c;
    }
    return out + "\"";
}

void managesieve_session::ok(std::string_view text)
{
    m_hooks.reply("OK " + quoted(text) + "\r\n");
}

void managesieve_session::no(std::string_view code, std::string_view text)
{
    m_hooks.reply("NO " + (code.empty() ? std::string() : "(" + std::string(code) + ") ") + quoted(text) + "\r\n");
    if (++m_errors > 30)
    {
        m_hooks.reply("BYE \"Too many errors\"\r\n");
        m_closed = true;
        m_hooks.close();
    }
}

void managesieve_session::capabilities()
{
    std::string out = "\"IMPLEMENTATION\" \"socketley\"\r\n";
    // PLAIN sends a password, offered where it does not go in the clear.
    const bool sasl = m_cfg.tls_active || m_cfg.login_in_clear;
    out += sasl ? "\"SASL\" \"PLAIN\"\r\n" : "\"SASL\" \"\"\r\n";
    out += "\"SIEVE\" " + quoted(sieve::extensions()) + "\r\n";
    if (m_cfg.tls_offered && !m_cfg.tls_active)
        out += "\"STARTTLS\"\r\n";
    out += "\"NOTIFY\" \"mailto\"\r\n\"MAXREDIRECTS\" \"4\"\r\n\"VERSION\" \"1.0\"\r\n";
    m_hooks.reply(out);
}

void managesieve_session::greet()
{
    capabilities();
    ok(m_cfg.hostname + " ManageSieve ready");
}

void managesieve_session::tls_started()
{
    m_cfg.tls_active = true;
    m_waiting = false;
    m_in.clear();
    m_at = 0;
    m_args.clear();
    capabilities();
    ok("TLS negotiation successful");
}

void managesieve_session::input(std::string_view bytes)
{
    if (m_closed)
        return;
    m_in.append(bytes);
    run();
}

void managesieve_session::run()
{
    m_running = true;
    while (!m_closed && !m_waiting && m_at < m_in.size())
    {
        if (m_literal > 0)
        {
            const size_t n = static_cast<size_t>(std::min<uint64_t>(m_literal, m_in.size() - m_at));
            if (!m_dropping)
                m_args.back().text.append(m_in, m_at, n);
            m_at += n;
            m_literal -= n;
            if (m_literal > 0)
                break;
            continue;
        }
        const char* start = m_in.data() + m_at;
        const void* nl = std::memchr(start, '\n', m_in.size() - m_at);
        if (!nl)
        {
            // Past a line's limit what came is dropped, and so is the rest of that line when it comes, said once.
            if (m_in.size() - m_at > max_line + 1)
            {
                m_in.clear();
                m_at = 0;
                m_args.clear();
                if (!m_discarding)
                    no({}, "Line too long");
                m_discarding = true;
            }
            break;
        }
        std::string_view line(start, static_cast<size_t>(static_cast<const char*>(nl) - start));
        m_at += line.size() + 1;
        if (m_discarding || line.size() > max_line + 1)
        {
            if (!m_discarding)
                no({}, "Line too long");
            m_discarding = false;
            m_args.clear();
            m_dropping = false;
            // A literal ending the dropped line still has its bytes to come, and they are not commands.
            std::string_view tail = line;
            if (!tail.empty() && tail.back() == '\r')
                tail.remove_suffix(1);
            const size_t open = tail.rfind('{');
            if (!tail.empty() && tail.back() == '}' && open != std::string_view::npos &&
                (open == 0 || tail[open - 1] == ' '))
            {
                std::string_view n = tail.substr(open + 1, tail.size() - open - 2);
                if (!n.empty() && n.back() == '+')
                    n.remove_suffix(1);
                uint64_t len = 0;
                const auto r = std::from_chars(n.data(), n.data() + n.size(), len);
                if (!n.empty() && r.ec == std::errc() && r.ptr == n.data() + n.size())
                {
                    m_args.push_back({{}, true});
                    m_literal = len;
                    m_dropping = true;
                }
            }
            continue;
        }
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        // The arguments of the line, a literal at its end continued by the bytes that follow it.
        bool literal = false, bad = false;
        size_t i = 0;
        while (i < line.size() && !bad)
        {
            if (line[i] == ' ')
            {
                ++i;
                continue;
            }
            if (line[i] == '"')
            {
                arg a{{}, true};
                size_t j = i + 1;
                for (; j < line.size() && line[j] != '"'; ++j)
                {
                    if (line[j] == '\\' && j + 1 < line.size())
                        ++j;
                    a.text += line[j];
                }
                bad = j >= line.size();
                m_args.push_back(std::move(a));
                i = j + 1;
                continue;
            }
            if (line[i] == '{' && line.back() == '}')
            {
                std::string_view n = line.substr(i + 1, line.size() - i - 2);
                if (!n.empty() && n.back() == '+')
                    n.remove_suffix(1);
                uint64_t len = 0;
                const auto r = std::from_chars(n.data(), n.data() + n.size(), len);
                if (n.empty() || r.ec != std::errc() || r.ptr != n.data() + n.size())
                {
                    bad = true;
                    break;
                }
                // A literal past a script's size, or a command past what any takes, is read and dropped, and refused.
                size_t held = 0;
                for (const auto& a : m_args)
                    held += a.text.size();
                m_dropping = m_dropping || len > sieve_store::max_script + 1024 ||
                             held + len > sieve_store::max_script + max_line;
                m_args.push_back({{}, true});
                m_literal = len;
                literal = true;
                break;
            }
            size_t j = line.find(' ', i);
            if (j == std::string_view::npos)
                j = line.size();
            m_args.push_back({std::string(line.substr(i, j - i)), false});
            i = j;
        }
        if (m_args.size() > max_args)
        {
            m_args.resize(max_args);
            m_dropping = true;
        }
        if (bad)
        {
            m_args.clear();
            m_dropping = false;
            no({}, "The command could not be read");
            continue;
        }
        if (literal)
            continue;
        if (m_args.empty() && !m_sasl)
            continue;
        command();
        m_args.clear();
        m_dropping = false;
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

void managesieve_session::sign_in(std::string_view b64)
{
    std::string raw;
    if (!socketley::base64::decode(b64, raw))
    {
        no({}, "The response could not be decoded");
        return;
    }
    const size_t a = raw.find('\0');
    const size_t b = a == std::string::npos ? std::string::npos : raw.find('\0', a + 1);
    if (b == std::string::npos || raw.substr(a + 1, b - a - 1).empty())
    {
        no({}, "Malformed PLAIN response");
        return;
    }
    std::string authz = raw.substr(0, a), user = raw.substr(a + 1, b - a - 1), pass = raw.substr(b + 1);
    if (!authz.empty() && authz != user)
    {
        no({}, "Authentication failed");
        return;
    }
    m_waiting = true;
    m_hooks.login(std::move(user), std::move(pass), [this, alive = m_alive](account a, std::string name) {
        if (!*alive)
            return;
        m_waiting = false;
        // A name with a control character is none a store keeps scripts under.
        const bool plain = std::none_of(name.begin(), name.end(), [](char c) {
            return static_cast<unsigned char>(c) < 0x20 || c == 0x7f;
        });
        if (a == account::unreachable)
            no("TRYLATER", "The accounts cannot be checked now");
        else if (a == account::yes && plain && !name.empty())
        {
            m_user = std::move(name);
            ok("Logged in");
        }
        else
            no({}, "Authentication failed");
        // An answer given while run() is on the stack is taken up by its loop, not by a second one inside it.
        if (!m_running)
            run();
    });
}

void managesieve_session::store_work(std::function<bool(std::string&, std::string&)> job, std::string done_text)
{
    auto code = std::make_shared<std::string>(), why = std::make_shared<std::string>();
    auto done = std::make_shared<bool>(false);
    m_waiting = true;
    m_hooks.offload([job = std::move(job), code, why, done] { *done = job(*code, *why); },
                    [this, code, why, done, done_text = std::move(done_text), alive = m_alive] {
                        if (!*alive)
                            return;
                        m_waiting = false;
                        if (*done)
                            ok(done_text);
                        else
                            no(*code, *why);
                        if (!m_running)
                            run();
                    });
}

void managesieve_session::command()
{
    if (m_sasl)
    {
        m_sasl = false;
        if (m_args.empty() || (!m_args[0].string && m_args[0].text == "*"))
        {
            no({}, "Authentication cancelled");
            return;
        }
        sign_in(m_args[0].text);
        return;
    }
    const std::string& verb = m_args[0].text;
    using socketley::ascii::iequals;
    if (m_dropping && !iequals(verb, "PUTSCRIPT") && !iequals(verb, "CHECKSCRIPT"))
    {
        no({}, "The command is longer than any this server takes");
        return;
    }
    const auto str = [this](size_t i) -> const std::string* {
        return i < m_args.size() && m_args[i].string ? &m_args[i].text : nullptr;
    };
    if (m_args[0].string)
    {
        no({}, "A command begins with its name");
        return;
    }
    if (iequals(verb, "CAPABILITY"))
    {
        capabilities();
        ok("Capability completed");
        return;
    }
    if (iequals(verb, "LOGOUT"))
    {
        ok("Logout completed");
        m_closed = true;
        m_hooks.close();
        return;
    }
    if (iequals(verb, "NOOP"))
    {
        if (const std::string* tag = str(1))
            m_hooks.reply("OK (TAG " + quoted(*tag) + ") \"Done\"\r\n");
        else
            ok("Done");
        return;
    }
    if (iequals(verb, "STARTTLS"))
    {
        if (!m_cfg.tls_offered || m_cfg.tls_active || !m_user.empty())
        {
            no({}, "STARTTLS is not available now");
            return;
        }
        ok("Begin TLS negotiation now");
        m_waiting = true;
        m_hooks.start_tls();
        return;
    }
    if (iequals(verb, "AUTHENTICATE"))
    {
        const std::string* mech = str(1);
        if (!m_user.empty())
            no({}, "Already authenticated");
        else if (!m_cfg.tls_active && !m_cfg.login_in_clear)
            no("ENCRYPT-NEEDED", "A password goes over TLS only: STARTTLS first");
        else if (!mech || !iequals(*mech, "PLAIN"))
            no({}, "Only PLAIN is offered");
        else if (const std::string* initial = str(2))
            sign_in(*initial);
        else
        {
            m_sasl = true;
            m_hooks.reply("\"\"\r\n");
        }
        return;
    }
    if (m_user.empty())
    {
        no({}, "Authenticate first");
        return;
    }
    if (iequals(verb, "UNAUTHENTICATE"))
    {
        m_user.clear();
        ok("Unauthenticated");
        return;
    }
    std::string code, why;
    if (iequals(verb, "LISTSCRIPTS"))
    {
        std::string out;
        for (const auto& [name, active] : m_store.list(m_user))
            out += quoted(name) + (active ? " ACTIVE\r\n" : "\r\n");
        m_hooks.reply(out);
        ok("Listscripts completed");
        return;
    }
    if (iequals(verb, "HAVESPACE"))
    {
        const std::string* name = str(1);
        uint64_t size = 0;
        bool num = m_args.size() > 2 && !m_args[2].string;
        if (num)
        {
            const std::string& t = m_args[2].text;
            const auto r = std::from_chars(t.data(), t.data() + t.size(), size);
            num = r.ec == std::errc() && r.ptr == t.data() + t.size();
        }
        if (!name || !num)
            no({}, "HAVESPACE takes a name and a size");
        else if (!sieve_store::name_ok(*name))
            no({}, "A script's name is printable and holds no /");
        else if (!m_store.fits(m_user, *name, size, code))
            no(code, "There is no room for it");
        else
            ok("Putscript would succeed");
        return;
    }
    if (iequals(verb, "PUTSCRIPT") || iequals(verb, "CHECKSCRIPT"))
    {
        const bool put = iequals(verb, "PUTSCRIPT");
        const std::string* name = put ? str(1) : nullptr;
        const std::string* text = str(put ? 2 : 1);
        if ((put && !name) || !text)
            no({}, put ? "PUTSCRIPT takes a name and a script" : "CHECKSCRIPT takes a script");
        else if (m_dropping)
            no("QUOTA/MAXSIZE", "The script is larger than one may be");
        else if (!put)
        {
            if (!sieve::script::compile(*text, why))
                no(code, why);
            else
                ok("Script is valid");
        }
        else
            store_work([store = &m_store, user = m_user, name = *name, text = *text](std::string& c, std::string& w) {
                return store->put(user, name, text, c, w);
            }, "Putscript completed");
        return;
    }
    if (iequals(verb, "GETSCRIPT"))
    {
        const std::string* name = str(1);
        std::string text;
        if (!name || !m_store.get(m_user, *name, text))
        {
            no("NONEXISTENT", "There is no such script");
            return;
        }
        m_hooks.reply("{" + std::to_string(text.size()) + "}\r\n" + text + "\r\n");
        ok("Getscript completed");
        return;
    }
    if (iequals(verb, "SETACTIVE"))
    {
        const std::string* name = str(1);
        if (!name)
            no({}, "SETACTIVE takes a name, \"\" for none");
        else
            store_work([store = &m_store, user = m_user, name = *name](std::string& c, std::string& w) {
                return store->activate(user, name, c, w);
            }, name->empty() ? "No script is active" : "Setactive completed");
        return;
    }
    if (iequals(verb, "DELETESCRIPT"))
    {
        const std::string* name = str(1);
        if (!name)
            no({}, "DELETESCRIPT takes a name");
        else
            store_work([store = &m_store, user = m_user, name = *name](std::string& c, std::string& w) {
                return store->remove(user, name, c, w);
            }, "Deletescript completed");
        return;
    }
    if (iequals(verb, "RENAMESCRIPT"))
    {
        const std::string* from = str(1);
        const std::string* to = str(2);
        if (!from || !to)
            no({}, "RENAMESCRIPT takes the old name and the new");
        else
            store_work([store = &m_store, user = m_user, from = *from, to = *to](std::string& c, std::string& w) {
                return store->rename(user, from, to, c, w);
            }, "Renamescript completed");
        return;
    }
    no({}, "Unknown command");
}

}   // namespace socketley::mail
