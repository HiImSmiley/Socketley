#include "imap_session.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <ctime>
#include <map>

#include "imap_order.h"
#include "mail_compose.h"
#include "../../shared/util/ascii.h"
#include "../../shared/util/base64.h"

namespace socketley::mail
{

namespace
{

constexpr std::string_view all_flags = "\\Answered \\Flagged \\Deleted \\Seen \\Draft";

std::string upper(std::string_view s)
{
    std::string out(s);
    for (char& c : out)
        c = socketley::ascii::upper(c);
    return out;
}

bool iequal(std::string_view a, std::string_view b)
{
    return socketley::ascii::iequals(a, b);
}

std::string internal_date(int64_t ms)
{
    static constexpr char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    const time_t t = static_cast<time_t>(ms / 1000);
    struct tm tm{};
    ::gmtime_r(&t, &tm);
    // Written by hand rather than by strftime, since a header listing writes one for every message.
    char b[29] = "\"00-Jan-0000 00:00:00 +0000\"";
    const auto two = [&b](int at, int v) {
        b[at] = static_cast<char>('0' + v / 10 % 10);
        b[at + 1] = static_cast<char>('0' + v % 10);
    };
    two(1, tm.tm_mday);
    std::memcpy(b + 4, months + 3 * std::clamp(tm.tm_mon, 0, 11), 3);
    const int year = std::clamp(tm.tm_year + 1900, 0, 9999);
    two(8, year / 100);
    two(10, year % 100);
    two(13, tm.tm_hour);
    two(16, tm.tm_min);
    two(19, tm.tm_sec);
    return std::string(b, 28);
}

// A SEARCH date, 1-Feb-1994, as days since 1970; -1 for none.
int64_t search_day(std::string_view s)
{
    static constexpr std::string_view months[] = {"jan", "feb", "mar", "apr", "may", "jun",
                                                  "jul", "aug", "sep", "oct", "nov", "dec"};
    const size_t a = s.find('-'), b = s.rfind('-');
    if (a == std::string_view::npos || b == a)
        return -1;
    struct tm tm{};
    tm.tm_mday = std::atoi(std::string(s.substr(0, a)).c_str());
    tm.tm_year = std::atoi(std::string(s.substr(b + 1)).c_str()) - 1900;
    const std::string mon = upper(s.substr(a + 1, b - a - 1));
    tm.tm_mon = -1;
    for (int i = 0; i < 12; ++i)
        if (iequal(mon, months[i]))
            tm.tm_mon = i;
    if (tm.tm_mon < 0 || tm.tm_mday < 1)
        return -1;
    return static_cast<int64_t>(::timegm(&tm)) / 86400;
}

uint8_t flag_bit(std::string_view f)
{
    if (iequal(f, "\\Seen"))
        return flag_seen;
    if (iequal(f, "\\Answered"))
        return flag_answered;
    if (iequal(f, "\\Flagged"))
        return flag_flagged;
    if (iequal(f, "\\Deleted"))
        return flag_deleted;
    if (iequal(f, "\\Draft"))
        return flag_draft;
    return 0;
}

// LIST's patterns: * matches anything, % anything but the hierarchy's delimiter.  A row of the table at a time, so a
// pattern of many stars costs its length times the name's, never more.
bool wildmatch(std::string_view pat, std::string_view name)
{
    if (pat.size() > 1024)
        return false;
    const bool inbox = iequal(name.substr(0, 5), "INBOX");
    // can[j]: the pattern so far matches name[0, j).
    std::vector<char> can(name.size() + 1, 0), next(name.size() + 1, 0);
    can[0] = 1;
    for (const char p : pat)
    {
        std::fill(next.begin(), next.end(), 0);
        if (p == '*' || p == '%')
        {
            // A star takes any run of the name after a place the pattern reached; % no run with the delimiter.
            char reach = 0;
            for (size_t j = 0; j <= name.size(); ++j)
            {
                if (p == '%' && j > 0 && name[j - 1] == '/')
                    reach = 0;
                reach = reach || can[j];
                next[j] = reach;
            }
        }
        else
            for (size_t j = 0; j < name.size(); ++j)
                if (can[j] && (p == name[j] ||
                               (inbox && j < 5 && socketley::ascii::lower(p) == socketley::ascii::lower(name[j]))))
                    next[j + 1] = 1;
        can.swap(next);
    }
    return can[name.size()];
}

bool contains_ci(std::string_view hay, std::string_view needle)
{
    if (needle.empty())
        return true;
    const auto it = std::search(hay.begin(), hay.end(), needle.begin(), needle.end(), [](char a, char b) {
        return socketley::ascii::lower(a) == socketley::ascii::lower(b);
    });
    return it != hay.end();
}

// UIDs as a sequence set, runs written as ranges: 1:3,7,9:12.
std::string set_text(std::vector<uint32_t> v)
{
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());
    std::string out;
    for (size_t i = 0; i < v.size();)
    {
        size_t j = i;
        while (j + 1 < v.size() && v[j + 1] == v[j] + 1)
            ++j;
        out += (out.empty() ? "" : ",") + std::to_string(v[i]) + (j > i ? ":" + std::to_string(v[j]) : std::string());
        i = j + 1;
    }
    return out;
}

// The ranges of a UID set as it was written, * the highest UID there is, for UIDs that may no longer exist.
bool uid_ranges(std::string_view set, uint32_t top, std::vector<std::pair<uint32_t, uint32_t>>& out)
{
    out.clear();
    while (!set.empty())
    {
        const size_t comma = set.find(',');
        const std::string_view one = set.substr(0, comma);
        set = comma == std::string_view::npos ? std::string_view{} : set.substr(comma + 1);
        const size_t colon = one.find(':');
        const auto value = [top](std::string_view v, uint32_t& n) {
            if (v == "*")
            {
                n = top;
                return true;
            }
            if (v.empty() || v.size() > 10 || v.find_first_not_of("0123456789") != std::string_view::npos)
                return false;
            n = static_cast<uint32_t>(std::min<uint64_t>(std::strtoull(std::string(v).c_str(), nullptr, 10), UINT32_MAX));
            return true;
        };
        uint32_t a = 0, b = 0;
        if (!value(one.substr(0, colon), a) || (colon != std::string_view::npos && !value(one.substr(colon + 1), b)))
            return false;
        if (colon == std::string_view::npos)
            b = a;
        out.emplace_back(std::min(a, b), std::max(a, b));
    }
    return true;
}

bool in_ranges(const std::vector<std::pair<uint32_t, uint32_t>>& r, uint32_t uid)
{
    for (const auto& [a, b] : r)
        if (uid >= a && uid <= b)
            return true;
    return false;
}

// A FETCH item: its name as asked and as answered, and the section and range of a BODY[...].
struct item
{
    std::string name;
    std::string answer;
    std::string section;
    bool peek{false};
    bool partial{false};
    uint64_t from{0}, count{0};
    bool body() const
    {
        return name == "ENVELOPE" || name == "BODYSTRUCTURE" || name == "BODY" || name.starts_with("BODY[") ||
               name.starts_with("BODY.PEEK[") || name == "RFC822" || name == "RFC822.HEADER" || name == "RFC822.TEXT";
    }
};

bool parse_item(std::string_view t, item& it)
{
    it = {};
    const std::string u = upper(t);
    const size_t br = u.find('[');
    if (br == std::string::npos)
    {
        it.name = u;
        it.answer = u;
        static constexpr std::string_view known[] = {"UID", "FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE",
                                                     "BODYSTRUCTURE", "BODY", "RFC822", "RFC822.HEADER", "RFC822.TEXT",
                                                     "MODSEQ"};
        return std::find(std::begin(known), std::end(known), u) != std::end(known);
    }
    const size_t close = u.find(']', br);
    if (close == std::string::npos)
        return false;
    const std::string head = u.substr(0, br);
    if (head != "BODY" && head != "BODY.PEEK")
        return false;
    it.peek = head == "BODY.PEEK";
    it.section = std::string(t.substr(br + 1, close - br - 1));
    it.name = "BODY[" + upper(it.section) + "]";
    it.answer = it.name;
    std::string_view rest = t.substr(close + 1);
    if (!rest.empty())
    {
        if (rest.front() != '<' || rest.back() != '>')
            return false;
        const std::string range(rest.substr(1, rest.size() - 2));
        const size_t dot = range.find('.');
        it.partial = true;
        it.from = std::strtoull(range.c_str(), nullptr, 10);
        it.count = dot == std::string::npos ? UINT64_MAX : std::strtoull(range.c_str() + dot + 1, nullptr, 10);
        it.answer += "<" + std::to_string(it.from) + ">";
    }
    return true;
}

// A SEARCH criterion, and what it needs of the message.
struct crit
{
    std::string key;
    std::string arg, arg2;
    std::vector<crit> kids;
    std::vector<size_t> set;
    bool content() const
    {
        if (key == "FROM" || key == "TO" || key == "CC" || key == "BCC" || key == "SUBJECT" || key == "HEADER" ||
            key == "BODY" || key == "TEXT" || key == "SENTBEFORE" || key == "SENTON" || key == "SENTSINCE")
            return true;
        for (const auto& k : kids)
            if (k.content())
                return true;
        return false;
    }
};

}   // namespace

imap_session::imap_session(const imap_config& cfg, hooks& h, imap_store& store)
    : m_cfg(cfg), m_hooks(h), m_store(store), m_alive(std::make_shared<bool>(true))
{
}

imap_session::~imap_session()
{
    *m_alive = false;
}

void imap_session::untagged(std::string_view line)
{
    std::string out = "* ";
    out.append(line);
    out.append("\r\n");
    m_hooks.reply(out);
}

void imap_session::finish(const std::string& tag, std::string_view status, std::string_view text)
{
    std::string out = tag;
    out += ' ';
    out.append(status);
    out += ' ';
    out.append(text);
    out += "\r\n";
    m_hooks.reply(out);
}

static std::string capabilities(const imap_config& cfg)
{
    std::string c = "IMAP4rev1 LITERAL+ SASL-IR IDLE NAMESPACE UIDPLUS MOVE UNSELECT CHILDREN SPECIAL-USE ID ENABLE "
                    "CONDSTORE QRESYNC ESEARCH LIST-EXTENDED LIST-STATUS STATUS=SIZE QUOTA QUOTA=RES-STORAGE SORT "
                    "SORT=DISPLAY THREAD=ORDEREDSUBJECT THREAD=REFERENCES";
    if (cfg.tls_offered && !cfg.tls_active)
        c += " STARTTLS";
    c += cfg.tls_active || cfg.login_in_clear ? " AUTH=PLAIN" : " LOGINDISABLED";
    return c;
}

void imap_session::greet()
{
    untagged("OK [CAPABILITY " + capabilities(m_cfg) + "] " + m_cfg.hostname + " IMAP4rev1 socketley ready");
}

void imap_session::tls_started()
{
    m_cfg.tls_active = true;
    m_waiting = false;
    run();
}

void imap_session::gone()
{
    m_state = state::logout;
}

void imap_session::resume()
{
    m_waiting = false;
    if (!m_running)
        run();
}

void imap_session::input(std::string_view bytes)
{
    if (m_state == state::logout)
        return;
    m_in.append(bytes);
    run();
}

bool imap_session::tokenize(std::string_view s, std::vector<token>& out) const
{
    size_t i = 0;
    while (i < s.size())
    {
        const char c = s[i];
        if (c == ' ')
        {
            ++i;
            continue;
        }
        if (c == '(')
        {
            out.push_back({token::open, "("});
            ++i;
            continue;
        }
        if (c == ')')
        {
            out.push_back({token::close, ")"});
            ++i;
            continue;
        }
        if (c == '"')
        {
            std::string v;
            for (++i; i < s.size() && s[i] != '"'; ++i)
            {
                if (s[i] == '\\' && i + 1 < s.size())
                    ++i;
                v += s[i];
            }
            if (i >= s.size())
                return false;
            ++i;
            out.push_back({token::string, std::move(v)});
            continue;
        }
        if (c == '{')
        {
            const size_t close = s.find('}', i);
            if (close == std::string_view::npos)
                return false;
            std::string_view num = s.substr(i + 1, close - i - 1);
            if (!num.empty() && num.back() == '+')
                num.remove_suffix(1);
            const size_t n = std::strtoull(std::string(num).c_str(), nullptr, 10);
            const size_t start = close + 3;
            if (s.substr(close + 1, 2) != "\r\n" || start + n > s.size())
                return false;
            out.push_back({token::string, std::string(s.substr(start, n))});
            i = start + n;
            continue;
        }
        // An atom, a section in brackets read whole with its spaces and parentheses.
        std::string a;
        while (i < s.size() && s[i] != ' ' && s[i] != '(' && s[i] != ')')
        {
            if (s[i] == '[')
            {
                const size_t close = s.find(']', i);
                if (close == std::string_view::npos)
                    return false;
                a.append(s.substr(i, close - i + 1));
                i = close + 1;
                continue;
            }
            a += s[i++];
        }
        out.push_back({token::atom, std::move(a)});
    }
    return true;
}

void imap_session::run()
{
    m_running = true;
    while (!m_waiting && m_state != state::logout)
    {
        if (m_literal > 0)
        {
            const size_t n = std::min(m_literal, m_in.size());
            m_cmd.append(m_in, 0, n);
            m_in.erase(0, n);
            m_literal -= n;
            if (m_literal > 0)
                break;
            continue;
        }
        const size_t nl = m_in.find('\n');
        if (nl == std::string::npos)
        {
            if (m_in.size() > max_line)
            {
                untagged("BYE line too long");
                m_state = state::logout;
                m_hooks.close();
            }
            else if (!m_cmd.empty())
                m_hooks.acknowledge();
            break;
        }
        std::string line = m_in.substr(0, nl);
        m_in.erase(0, nl + 1);
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (m_idle)
        {
            if (iequal(line, "DONE"))
            {
                m_idle = false;
                finish(m_idle_tag, "OK", "IDLE terminated");
            }
            continue;
        }
        if (m_auth_continue)
        {
            m_auth_continue = false;
            if (line == "*")
            {
                finish(m_auth_tag, "BAD", "AUTHENTICATE cancelled");
                continue;
            }
            std::string raw;
            if (!socketley::base64::decode(line, raw))
            {
                finish(m_auth_tag, "BAD", "Invalid base64");
                continue;
            }
            const size_t a = raw.find('\0');
            const size_t b = a == std::string::npos ? std::string::npos : raw.find('\0', a + 1);
            if (b == std::string::npos)
            {
                finish(m_auth_tag, "NO", "[AUTHENTICATIONFAILED] Malformed response");
                continue;
            }
            sign_in(m_auth_tag, raw.substr(a + 1, b - a - 1), raw.substr(b + 1));
            continue;
        }
        // A literal at the end of the line: its bytes are what comes next, asked for unless LITERAL+ said they come.
        if (!line.empty() && line.back() == '}')
        {
            const size_t open = line.rfind('{');
            if (open != std::string::npos)
            {
                std::string num = line.substr(open + 1, line.size() - open - 2);
                const bool plus = !num.empty() && num.back() == '+';
                if (plus)
                    num.pop_back();
                const bool digits = !num.empty() && num.find_first_not_of("0123456789") == std::string::npos;
                if (digits)
                {
                    const uint64_t n = std::strtoull(num.c_str(), nullptr, 10);
                    if (n > m_cfg.max_append + max_line)
                    {
                        const std::string tag = line.substr(0, line.find(' '));
                        m_cmd.clear();
                        finish(tag, "NO", "[TOOBIG] Literal too large");
                        if (plus)
                        {
                            untagged("BYE literal too large");
                            m_state = state::logout;
                            m_hooks.close();
                        }
                        continue;
                    }
                    m_cmd += line;
                    m_cmd += "\r\n";
                    m_literal = static_cast<size_t>(n);
                    if (!plus)
                        m_hooks.reply("+ Ready for literal data\r\n");
                    continue;
                }
            }
        }
        m_cmd += line;
        std::string full = std::move(m_cmd);
        m_cmd.clear();
        std::vector<token> t;
        if (!tokenize(full, t) || t.empty() || t[0].k != token::atom)
        {
            const std::string tag = full.substr(0, full.find(' '));
            finish(tag.empty() ? "*" : tag, "BAD", "Command not understood");
            continue;
        }
        const std::string tag = t[0].text;
        t.erase(t.begin());
        command(tag, std::move(t));
    }
    m_running = false;
}

void imap_session::sign_in(const std::string& tag, std::string user, std::string password)
{
    m_waiting = true;
    m_hooks.login(std::move(user), std::move(password), [this, alive = m_alive, tag](bool ok, std::string name) {
        if (!*alive)
            return;
        if (ok)
        {
            m_user = std::move(name);
            m_state = state::auth;
            finish(tag, "OK", "[CAPABILITY " + capabilities(m_cfg) + "] Logged in");
        }
        else
            finish(tag, "NO", "[AUTHENTICATIONFAILED] Authentication failed");
        resume();
    });
}

std::string imap_session::flags_text(uint8_t f, bool recent) const
{
    std::string out;
    const auto add = [&](std::string_view s) {
        if (!out.empty())
            out += ' ';
        out.append(s);
    };
    if (f & flag_seen)
        add("\\Seen");
    if (f & flag_answered)
        add("\\Answered");
    if (f & flag_flagged)
        add("\\Flagged");
    if (f & flag_deleted)
        add("\\Deleted");
    if (f & flag_draft)
        add("\\Draft");
    if (recent)
        add("\\Recent");
    return "(" + out + ")";
}

void imap_session::update_view()
{
    if (!m_folder || m_folder->version == m_seen_version)
        return;
    m_seen_version = m_folder->version;
    // What went first, from the highest number down so each one said is still where the client has it; under QRESYNC
    // as the UIDs that vanished.
    std::vector<uint32_t> vanished;
    for (size_t i = m_view.size(); i-- > 0;)
        if (!m_folder->by_uid(m_view[i]))
        {
            if (m_qresync)
                vanished.push_back(m_view[i]);
            else
                untagged(std::to_string(i + 1) + " EXPUNGE");
            m_view.erase(m_view.begin() + static_cast<long>(i));
        }
    if (!vanished.empty())
        untagged("VANISHED " + set_text(std::move(vanished)));
    // Flags another session changed since this one was last told, said as FETCH.
    for (size_t i = 0; i < m_view.size(); ++i)
        if (const imap_message* m = m_folder->by_uid(m_view[i]); m && m->modseq > m_told_modseq)
            untagged(std::to_string(i + 1) + " FETCH (UID " + std::to_string(m->uid) + " FLAGS " +
                     flags_text(m->flags, false) +
                     (m_condstore ? " MODSEQ (" + std::to_string(m->modseq) + ")" : std::string()) + ")");
    const uint32_t last = m_view.empty() ? 0 : m_view.back();
    size_t recent = 0;
    bool grew = false;
    for (auto& m : m_folder->msgs)
        if (m.uid > last)
        {
            m_view.push_back(m.uid);
            grew = true;
            if (m.recent)
            {
                ++recent;
                m.recent = false;
            }
        }
    if (grew)
    {
        untagged(std::to_string(m_view.size()) + " EXISTS");
        untagged(std::to_string(recent) + " RECENT");
    }
    m_told_modseq = m_folder->highestmodseq;
}

bool imap_session::parse_set(std::string_view set, bool uid, std::vector<size_t>& out) const
{
    out.clear();
    const uint32_t max_uid = m_view.empty() ? 0 : m_view.back();
    const size_t count = m_view.size();
    std::vector<bool> take(count, false);
    while (!set.empty())
    {
        const size_t comma = set.find(',');
        const std::string_view one = set.substr(0, comma);
        set = comma == std::string_view::npos ? std::string_view{} : set.substr(comma + 1);
        const size_t colon = one.find(':');
        const auto value = [&](std::string_view v, uint64_t& n) {
            if (v == "*")
            {
                n = uid ? max_uid : count;
                return true;
            }
            if (v.empty() || v.find_first_not_of("0123456789") != std::string_view::npos)
                return false;
            n = std::strtoull(std::string(v).c_str(), nullptr, 10);
            return n > 0;
        };
        uint64_t a = 0, b = 0;
        if (!value(one.substr(0, colon), a) || (colon != std::string_view::npos && !value(one.substr(colon + 1), b)))
            return false;
        if (colon == std::string_view::npos)
            b = a;
        if (a > b)
            std::swap(a, b);
        if (uid)
        {
            // n:* takes the highest UID even where n is past it.
            if (one.substr(colon == std::string_view::npos ? 0 : colon + 1) == "*" && a > max_uid)
                a = max_uid;
            for (size_t i = 0; i < count; ++i)
                if (m_view[i] >= a && m_view[i] <= b)
                    take[i] = true;
        }
        else
        {
            if (b > count && !(count == 0 && one.find('*') != std::string_view::npos))
                return false;
            for (uint64_t i = a; i <= b && i <= count; ++i)
                take[i - 1] = true;
        }
    }
    for (size_t i = 0; i < count; ++i)
        if (take[i])
            out.push_back(i);
    return true;
}

void imap_session::command(std::string tag, std::vector<token> a)
{
    if (a.empty() || a[0].k != token::atom)
    {
        finish(tag, "BAD", "No command");
        return;
    }
    const std::string cmd = upper(a[0].text);
    const bool authed = m_state == state::auth || m_state == state::selected;
    const bool selected = m_state == state::selected;
    // What another shard changed of this user's mailboxes is read in before each command.
    if (authed)
        m_store.refresh(m_user);
    const auto str = [&](size_t i) -> const std::string* {
        return i < a.size() && (a[i].k == token::atom || a[i].k == token::string) ? &a[i].text : nullptr;
    };
    if (cmd == "CAPABILITY")
    {
        untagged("CAPABILITY " + capabilities(m_cfg));
        return finish(tag, "OK", "CAPABILITY completed");
    }
    if (cmd == "NOOP" || cmd == "CHECK")
    {
        if (!selected)
            return finish(tag, "OK", cmd + " completed");
        m_waiting = true;
        m_store.open(m_user, m_folder->name, [this, alive = m_alive, tag, cmd](std::shared_ptr<imap_folder>) {
            if (!*alive)
                return;
            update_view();
            finish(tag, "OK", cmd + " completed");
            resume();
        });
        return;
    }
    if (cmd == "LOGOUT")
    {
        untagged("BYE " + m_cfg.hostname + " logging out");
        finish(tag, "OK", "LOGOUT completed");
        m_state = state::logout;
        m_hooks.close();
        return;
    }
    if (cmd == "ID")
    {
        untagged("ID (\"name\" \"socketley\")");
        return finish(tag, "OK", "ID completed");
    }
    if (cmd == "ENABLE")
    {
        std::string on;
        for (size_t i = 1; i < a.size(); ++i)
        {
            const std::string e = upper(a[i].text);
            if (e == "CONDSTORE" && !m_condstore)
                on += " CONDSTORE";
            else if (e == "QRESYNC" && !m_qresync)
                on += " QRESYNC";
            else
                continue;
            m_condstore = true;
            m_qresync = m_qresync || e == "QRESYNC";
        }
        untagged("ENABLED" + on);
        return finish(tag, "OK", "ENABLE completed");
    }
    if (cmd == "STARTTLS")
    {
        if (!m_cfg.tls_offered || m_cfg.tls_active)
            return finish(tag, "BAD", "STARTTLS not available");
        finish(tag, "OK", "Begin TLS negotiation now");
        // What was pipelined behind it in the clear is dropped (CVE-2011-0411's lesson).
        m_in.clear();
        m_waiting = true;
        m_hooks.start_tls();
        return;
    }
    if (cmd == "LOGIN")
    {
        if (authed)
            return finish(tag, "BAD", "Already authenticated");
        if (!m_cfg.tls_active && !m_cfg.login_in_clear)
            return finish(tag, "NO", "[PRIVACYREQUIRED] LOGIN is disabled until STARTTLS");
        return cmd_login(tag, a);
    }
    if (cmd == "AUTHENTICATE")
    {
        if (authed)
            return finish(tag, "BAD", "Already authenticated");
        if (!m_cfg.tls_active && !m_cfg.login_in_clear)
            return finish(tag, "NO", "[PRIVACYREQUIRED] AUTHENTICATE is disabled until STARTTLS");
        return cmd_authenticate(tag, a);
    }
    if (!authed)
        return finish(tag, "BAD", "Log in first");

    if (cmd == "SELECT" || cmd == "EXAMINE")
        return cmd_select(tag, a, cmd == "EXAMINE");
    if (cmd == "LIST" || cmd == "LSUB")
        return cmd_list(tag, a, cmd == "LSUB");
    if (cmd == "NAMESPACE")
    {
        untagged("NAMESPACE ((\"\" \"/\")) NIL NIL");
        return finish(tag, "OK", "NAMESPACE completed");
    }
    if (cmd == "STATUS")
        return cmd_status(tag, a);
    if (cmd == "CREATE")
    {
        const std::string* name = str(1);
        if (!name)
            return finish(tag, "BAD", "CREATE needs a name");
        std::string n = *name;
        if (!n.empty() && n.back() == '/')
            n.pop_back();
        return m_store.create(m_user, n) ? finish(tag, "OK", "CREATE completed")
                                         : finish(tag, "NO", "[ALREADYEXISTS] Mailbox exists");
    }
    if (cmd == "DELETE" || cmd == "RENAME")
    {
        const std::string* name = str(1);
        const std::string* to = str(2);
        if (!name || (cmd == "RENAME" && !to))
            return finish(tag, "BAD", cmd + " needs a mailbox");
        m_waiting = true;
        const auto done = [this, alive = m_alive, tag, cmd](bool ok) {
            if (!*alive)
                return;
            finish(tag, ok ? "OK" : "NO", ok ? cmd + " completed" : "[NONEXISTENT] " + cmd + " failed");
            resume();
        };
        if (cmd == "DELETE")
            m_store.remove(m_user, *name, done);
        else
            m_store.rename(m_user, *name, *to, done);
        return;
    }
    if (cmd == "SUBSCRIBE" || cmd == "UNSUBSCRIBE")
    {
        const std::string* name = str(1);
        if (!name)
            return finish(tag, "BAD", cmd + " needs a mailbox");
        m_store.set_subscribed(m_user, *name, cmd == "SUBSCRIBE");
        return finish(tag, "OK", cmd + " completed");
    }
    if (cmd == "APPEND")
        return cmd_append(tag, a);
    // One quota root, "", over every folder of the user, in kibibytes (RFC 9208).
    if (cmd == "GETQUOTAROOT" || cmd == "GETQUOTA")
    {
        const std::string* name = str(1);
        if (!name)
            return finish(tag, "BAD", cmd + " needs a mailbox or a root");
        const uint64_t q = m_store.quota(m_user);
        if (cmd == "GETQUOTAROOT")
            untagged("QUOTAROOT " + mime::imap_string(*name, false) + (q ? " \"\"" : ""));
        else if (!q || !name->empty())
            return finish(tag, "NO", "[NONEXISTENT] No such quota root");
        if (q)
            untagged("QUOTA \"\" (STORAGE " + std::to_string((m_store.usage(m_user) + 1023) / 1024) + " " +
                     std::to_string(q / 1024) + ")");
        return finish(tag, "OK", cmd + " completed");
    }
    if (cmd == "SETQUOTA")
        return finish(tag, "NO", "[NOPERM] A quota is set on the user's account");
    if (cmd == "IDLE")
    {
        m_idle = true;
        m_idle_tag = tag;
        m_hooks.reply("+ idling\r\n");
        update_view();
        return;
    }
    if (!selected)
        return finish(tag, "BAD", "Select a mailbox first");
    if (cmd == "CLOSE" || cmd == "UNSELECT")
    {
        const auto done = [this, tag, cmd] {
            m_folder.reset();
            m_view.clear();
            m_state = state::auth;
            finish(tag, "OK", cmd + " completed");
        };
        if (cmd == "UNSELECT" || m_readonly)
        {
            done();
            return;
        }
        // CLOSE expunges without telling the client what went.
        m_waiting = true;
        m_store.expunge(m_user, m_folder, {}, [this, alive = m_alive, done](std::vector<uint32_t>) {
            if (!*alive)
                return;
            done();
            resume();
        });
        return;
    }
    if (cmd == "EXPUNGE")
    {
        if (m_readonly)
            return finish(tag, "NO", "[READ-ONLY] Mailbox is read-only");
        return cmd_expunge(tag, {}, false, "EXPUNGE completed");
    }
    if (cmd == "FETCH")
        return cmd_fetch(tag, a, 1, false);
    if (cmd == "STORE")
        return cmd_store(tag, a, 1, false);
    if (cmd == "SEARCH")
        return cmd_search(tag, a, 1, false);
    if (cmd == "SORT" || cmd == "THREAD")
        return cmd_order(tag, a, 1, false, cmd == "THREAD");
    if (cmd == "COPY" || cmd == "MOVE")
        return cmd_copy(tag, a, 1, false, cmd == "MOVE");
    if (cmd == "UID")
    {
        const std::string sub = a.size() > 1 ? upper(a[1].text) : std::string();
        if (sub == "FETCH")
            return cmd_fetch(tag, a, 2, true);
        if (sub == "STORE")
            return cmd_store(tag, a, 2, true);
        if (sub == "SEARCH")
            return cmd_search(tag, a, 2, true);
        if (sub == "SORT" || sub == "THREAD")
            return cmd_order(tag, a, 2, true, sub == "THREAD");
        if (sub == "COPY" || sub == "MOVE")
            return cmd_copy(tag, a, 2, true, sub == "MOVE");
        if (sub == "EXPUNGE")
        {
            std::vector<size_t> idx;
            if (a.size() < 3 || !parse_set(a[2].text, true, idx))
                return finish(tag, "BAD", "UID EXPUNGE needs a set");
            std::vector<uint32_t> uids;
            for (const size_t i : idx)
                uids.push_back(m_view[i]);
            if (uids.empty())
                return finish(tag, "OK", "UID EXPUNGE completed");
            return cmd_expunge(tag, uids, false, "UID EXPUNGE completed");
        }
        return finish(tag, "BAD", "Unknown UID command");
    }
    finish(tag, "BAD", "Unknown command " + cmd);
}

void imap_session::cmd_login(const std::string& tag, const std::vector<token>& a)
{
    if (a.size() < 3 || a[1].k == token::open || a[2].k == token::open)
        return finish(tag, "BAD", "LOGIN needs a user and a password");
    sign_in(tag, a[1].text, a[2].text);
}

void imap_session::cmd_authenticate(const std::string& tag, const std::vector<token>& a)
{
    if (a.size() < 2 || !iequal(a[1].text, "PLAIN"))
        return finish(tag, "NO", "Unsupported authentication mechanism");
    if (a.size() > 2)
    {
        // SASL-IR: the response came with the command.
        m_in.insert(0, a[2].text + "\r\n");
    }
    else
        m_hooks.reply("+ \r\n");
    m_auth_tag = tag;
    m_auth_continue = true;
}

void imap_session::cmd_select(const std::string& tag, const std::vector<token>& a, bool readonly)
{
    if (a.size() < 2 || a[1].k == token::open)
        return finish(tag, "BAD", "SELECT needs a mailbox");
    // (CONDSTORE), or (QRESYNC (uidvalidity modseq [known-uids [(seqs uids)]])) once QRESYNC is enabled.
    struct resync
    {
        bool asked{false};
        uint32_t uidvalidity{0};
        uint64_t modseq{0};
        std::string known;
    } qr;
    bool condstore = false;
    for (size_t i = 2; i < a.size(); ++i)
    {
        const std::string w = upper(a[i].text);
        if (a[i].k != token::atom)
            continue;
        if (w == "CONDSTORE")
            condstore = true;
        else if (w == "QRESYNC")
        {
            if (!m_qresync)
                return finish(tag, "BAD", "ENABLE QRESYNC first");
            if (i + 3 >= a.size() || a[i + 1].k != token::open)
                return finish(tag, "BAD", "QRESYNC needs a UIDVALIDITY and a mod-sequence");
            qr.asked = true;
            qr.uidvalidity = static_cast<uint32_t>(std::strtoul(a[i + 2].text.c_str(), nullptr, 10));
            qr.modseq = std::strtoull(a[i + 3].text.c_str(), nullptr, 10);
            if (i + 4 < a.size() && a[i + 4].k == token::atom)
                qr.known = a[i + 4].text;
            break;
        }
    }
    m_folder.reset();
    m_view.clear();
    m_state = state::auth;
    m_waiting = true;
    m_store.open(m_user, a[1].text, [this, alive = m_alive, tag, readonly, condstore, qr](std::shared_ptr<imap_folder> f) {
        if (!*alive)
            return;
        if (!f)
        {
            finish(tag, "NO", "[NONEXISTENT] No such mailbox");
            resume();
            return;
        }
        m_folder = f;
        m_readonly = readonly;
        m_state = state::selected;
        m_seen_version = f->version;
        m_told_modseq = f->highestmodseq;
        m_condstore = m_condstore || condstore || qr.asked;
        size_t recent = 0, first_unseen = 0;
        for (auto& m : f->msgs)
        {
            m_view.push_back(m.uid);
            if (m.recent && !readonly)
            {
                ++recent;
                m.recent = false;
            }
            if (!(m.flags & flag_seen) && !first_unseen)
                first_unseen = m_view.size();
        }
        untagged("FLAGS (" + std::string(all_flags) + ")");
        untagged("OK [PERMANENTFLAGS (" + std::string(readonly ? "" : all_flags) + ")] Flags permitted");
        untagged(std::to_string(m_view.size()) + " EXISTS");
        untagged(std::to_string(recent) + " RECENT");
        if (first_unseen)
            untagged("OK [UNSEEN " + std::to_string(first_unseen) + "] First unseen");
        untagged("OK [UIDVALIDITY " + std::to_string(f->uidvalidity) + "] UIDs valid");
        untagged("OK [UIDNEXT " + std::to_string(f->uidnext) + "] Predicted next UID");
        untagged("OK [HIGHESTMODSEQ " + std::to_string(f->highestmodseq) + "] Highest");
        // What changed since the client last looked, under the UIDVALIDITY it knows (RFC 7162 3.2.5).
        if (qr.asked && qr.uidvalidity == f->uidvalidity)
        {
            std::vector<std::pair<uint32_t, uint32_t>> known;
            const bool limited = !qr.known.empty() && uid_ranges(qr.known, f->uidnext - 1, known);
            std::vector<uint32_t> gone;
            if (qr.modseq >= f->vanished_from)
            {
                for (const auto& [ms, uid] : f->vanished)
                    if (ms > qr.modseq && (!limited || in_ranges(known, uid)))
                        gone.push_back(uid);
            }
            else
            {
                // Expunges older than what is remembered: every UID the client may know that is not here.
                const auto here = [&f](uint32_t uid) { return f->by_uid(uid) != nullptr; };
                if (limited)
                {
                    for (const auto& [lo, hi] : known)
                        for (uint64_t u = lo; u <= hi && u < f->uidnext && gone.size() < 1000000; ++u)
                            if (!here(static_cast<uint32_t>(u)))
                                gone.push_back(static_cast<uint32_t>(u));
                }
                else
                    for (uint32_t u = 1; u < f->uidnext && gone.size() < 1000000; ++u)
                        if (!here(u))
                            gone.push_back(u);
            }
            if (!gone.empty())
                untagged("VANISHED (EARLIER) " + set_text(std::move(gone)));
            for (size_t i = 0; i < m_view.size(); ++i)
                if (const imap_message* m = f->by_uid(m_view[i]);
                    m && m->modseq > qr.modseq && (!limited || in_ranges(known, m->uid)))
                    untagged(std::to_string(i + 1) + " FETCH (UID " + std::to_string(m->uid) + " FLAGS " +
                             flags_text(m->flags, false) + " MODSEQ (" + std::to_string(m->modseq) + "))");
        }
        finish(tag, "OK", readonly ? "[READ-ONLY] EXAMINE completed" : "[READ-WRITE] SELECT completed");
        resume();
    }, true);
}

std::string imap_session::status_text(const imap_folder& f, const std::vector<std::string>& items) const
{
    size_t unseen = 0, recent = 0;
    uint64_t size = 0;
    for (const auto& m : f.msgs)
    {
        unseen += !(m.flags & flag_seen);
        recent += m.recent;
        size += m.size;
    }
    std::string out;
    for (const auto& it : items)
    {
        std::string v;
        if (it == "MESSAGES")
            v = std::to_string(f.msgs.size());
        else if (it == "UIDNEXT")
            v = std::to_string(f.uidnext);
        else if (it == "UIDVALIDITY")
            v = std::to_string(f.uidvalidity);
        else if (it == "UNSEEN")
            v = std::to_string(unseen);
        else if (it == "RECENT")
            v = std::to_string(recent);
        else if (it == "HIGHESTMODSEQ")
            v = std::to_string(f.highestmodseq);
        else if (it == "SIZE")
            v = std::to_string(size);
        else
            continue;
        out += (out.empty() ? "" : " ") + it + " " + v;
    }
    return "STATUS " + mime::imap_string(f.name, false) + " (" + out + ")";
}

void imap_session::cmd_list(const std::string& tag, const std::vector<token>& a, bool lsub)
{
    // LIST [(selection)] <reference> <pattern | (patterns)> [RETURN (options)] (RFC 5258, RFC 5819).
    size_t i = 1;
    bool only_subscribed = lsub;
    if (i < a.size() && a[i].k == token::open)
    {
        for (++i; i < a.size() && a[i].k != token::close; ++i)
            only_subscribed = only_subscribed || upper(a[i].text) == "SUBSCRIBED" ||
                              upper(a[i].text) == "RECURSIVEMATCH";
        ++i;
    }
    if (i + 1 >= a.size())
        return finish(tag, "BAD", "LIST needs a reference and a pattern");
    const std::string ref = a[i++].text;
    std::vector<std::string> pats;
    if (a[i].k == token::open)
    {
        for (++i; i < a.size() && a[i].k != token::close; ++i)
            pats.push_back(a[i].text);
        ++i;
    }
    else
        pats.push_back(a[i++].text);
    bool told_subscribed = only_subscribed && !lsub;
    std::vector<std::string> status;
    if (i + 1 < a.size() && upper(a[i].text) == "RETURN" && a[i + 1].k == token::open)
        for (i += 2; i < a.size() && a[i].k != token::close; ++i)
        {
            const std::string w = upper(a[i].text);
            if (w == "SUBSCRIBED")
                told_subscribed = true;
            else if (w == "STATUS" && i + 1 < a.size() && a[i + 1].k == token::open)
                for (i += 2; i < a.size() && a[i].k != token::close; ++i)
                    status.push_back(upper(a[i].text));
        }
    if (!lsub && pats.size() == 1 && pats[0].empty())
    {
        untagged("LIST (\\Noselect) \"/\" \"\"");
        return finish(tag, "OK", "LIST completed");
    }
    m_waiting = true;
    m_store.folders(m_user, [this, alive = m_alive, tag, ref, pats, lsub, only_subscribed, told_subscribed,
                             status](std::vector<std::string> names) {
        if (!*alive)
            return;
        // Each line, then the folder it is of.
        std::vector<std::string> listed;
        for (const auto& n : names)
        {
            bool hit = false;
            for (const auto& p : pats)
                hit = hit || wildmatch(ref + p, n);
            const bool sub = m_store.subscribed(m_user, n);
            if (!hit || (only_subscribed && !sub))
                continue;
            bool children = false;
            for (const auto& o : names)
                children = children || (o.size() > n.size() + 1 && o.starts_with(n + "/"));
            std::string attrs = children ? "\\HasChildren" : "\\HasNoChildren";
            if (told_subscribed && sub)
                attrs += " \\Subscribed";
            for (const auto& [sp, use] : imap_store::special())
                if (sp == n && !use.empty())
                    attrs += " " + use;
            listed.push_back(std::string(lsub ? "LSUB" : "LIST") + " (" + attrs + ") \"/\" " +
                             mime::imap_string(n, false));
            listed.push_back(n);
        }
        if (status.empty())
        {
            for (size_t k = 0; k < listed.size(); k += 2)
                untagged(listed[k]);
            finish(tag, "OK", lsub ? "LSUB completed" : "LIST completed");
            resume();
            return;
        }
        // Each folder's STATUS after its LIST line, the folders opened one after the other.
        auto at = std::make_shared<size_t>(0);
        auto step = std::make_shared<std::function<void()>>();
        std::weak_ptr<std::function<void()>> weak = step;
        *step = [this, alive, tag, listed, status, at, weak] {
            auto self = weak.lock();
            if (!*alive || !self)
                return;
            if (*at >= listed.size())
            {
                finish(tag, "OK", "LIST completed");
                resume();
                return;
            }
            untagged(listed[*at]);
            const std::string name = listed[*at + 1];
            *at += 2;
            m_store.open(m_user, name, [this, alive, status, self](std::shared_ptr<imap_folder> f) {
                if (!*alive)
                    return;
                if (f)
                    untagged(status_text(*f, status));
                (*self)();
            });
        };
        auto keep = step;
        (*keep)();
    });
}

void imap_session::cmd_status(const std::string& tag, const std::vector<token>& a)
{
    if (a.size() < 3 || a[2].k != token::open)
        return finish(tag, "BAD", "STATUS needs a mailbox and items");
    std::vector<std::string> items;
    for (size_t i = 3; i < a.size() && a[i].k != token::close; ++i)
        items.push_back(upper(a[i].text));
    const std::string name = a[1].text;
    m_waiting = true;
    m_store.open(m_user, name, [this, alive = m_alive, tag, items, name](std::shared_ptr<imap_folder> f) {
        if (!*alive)
            return;
        if (!f)
        {
            finish(tag, "NO", "[NONEXISTENT] No such mailbox");
            resume();
            return;
        }
        untagged(status_text(*f, items));
        finish(tag, "OK", "STATUS completed");
        resume();
    });
}

void imap_session::cmd_append(const std::string& tag, const std::vector<token>& a)
{
    if (a.size() < 3)
        return finish(tag, "BAD", "APPEND needs a mailbox and a message");
    size_t i = 2;
    uint8_t flags = 0;
    if (a[i].k == token::open)
    {
        for (++i; i < a.size() && a[i].k != token::close; ++i)
            flags |= flag_bit(a[i].text);
        ++i;
    }
    int64_t date_ms = 0;
    if (i + 1 < a.size() && a[i].k == token::string && a[i + 1].k == token::string)
    {
        // An INTERNALDATE the client gave, read for its day and taken at midnight; its own time otherwise.
        const int64_t day = search_day(a[i].text.substr(0, a[i].text.find(' ')));
        if (day >= 0)
            date_ms = day * 86400000;
        ++i;
    }
    if (i >= a.size() || a[i].k != token::string)
        return finish(tag, "BAD", "APPEND needs the message as a literal");
    if (date_ms == 0)
        date_ms = static_cast<int64_t>(::time(nullptr)) * 1000;
    std::string message = crlf_lines(a[i].text);
    m_waiting = true;
    const uint64_t size = message.size();
    m_store.append(m_user, a[1].text, std::move(message), flags, date_ms,
                   [this, alive = m_alive, tag, size](bool ok, uint32_t validity, uint32_t uid) {
                       if (!*alive)
                           return;
                       if (!ok)
                       {
                           const uint64_t q = m_store.quota(m_user);
                           finish(tag, "NO", q && m_store.usage(m_user) + size > q ? "[OVERQUOTA] The mailbox is full"
                                                                                  : "[TRYCREATE] APPEND failed");
                       }
                       else
                       {
                           update_view();
                           finish(tag, "OK",
                                  "[APPENDUID " + std::to_string(validity) + " " + std::to_string(uid) +
                                      "] APPEND completed");
                       }
                       resume();
                   });
}

void imap_session::cmd_fetch(const std::string& tag, const std::vector<token>& a, size_t from, bool uid)
{
    if (a.size() < from + 2)
        return finish(tag, "BAD", "FETCH needs a set and items");
    std::vector<size_t> idx;
    if (!parse_set(a[from].text, uid, idx))
        return finish(tag, "BAD", "Invalid sequence set");
    std::vector<item> items;
    const auto add = [&](std::string_view t) {
        const std::string u = upper(t);
        if (u == "ALL" || u == "FAST" || u == "FULL")
        {
            for (const char* n : {"FLAGS", "INTERNALDATE", "RFC822.SIZE"})
                items.push_back({n, n, {}, false, false, 0, 0});
            if (u != "FAST")
                items.push_back({"ENVELOPE", "ENVELOPE", {}, false, false, 0, 0});
            if (u == "FULL")
                items.push_back({"BODY", "BODY", {}, false, false, 0, 0});
            return true;
        }
        item it;
        if (!parse_item(t, it))
            return false;
        items.push_back(std::move(it));
        return true;
    };
    size_t after = from + 2;
    if (a[from + 1].k == token::open)
    {
        size_t i = from + 2;
        for (; i < a.size() && a[i].k != token::close; ++i)
            if (!add(a[i].text))
                return finish(tag, "BAD", "Unknown FETCH item " + a[i].text);
        after = i + 1;
    }
    else if (!add(a[from + 1].text))
        return finish(tag, "BAD", "Unknown FETCH item " + a[from + 1].text);
    // (CHANGEDSINCE <modseq> [VANISHED]): what changed since then, and what went (RFC 7162 3.1.4, 3.2.6).
    uint64_t since = 0;
    bool vanished = false;
    if (after < a.size() && a[after].k == token::open)
        for (size_t i = after + 1; i < a.size() && a[i].k != token::close; ++i)
        {
            const std::string w = upper(a[i].text);
            if (w == "CHANGEDSINCE" && i + 1 < a.size())
                since = std::strtoull(a[++i].text.c_str(), nullptr, 10);
            else if (w == "VANISHED")
                vanished = true;
        }
    if (vanished && (!uid || !m_qresync || !since))
        return finish(tag, "BAD", "VANISHED is for UID FETCH with CHANGEDSINCE under QRESYNC");
    if (since)
    {
        m_condstore = true;
        std::erase_if(idx, [&](size_t i) {
            const imap_message* m = m_folder->by_uid(m_view[i]);
            return !m || m->modseq <= since;
        });
    }
    if ((since || m_condstore) && std::any_of(items.begin(), items.end(), [](const item& i) { return i.name == "FLAGS"; }) &&
        std::none_of(items.begin(), items.end(), [](const item& i) { return i.name == "MODSEQ"; }))
        items.push_back({"MODSEQ", "MODSEQ", {}, false, false, 0, 0});
    if (since && std::none_of(items.begin(), items.end(), [](const item& i) { return i.name == "MODSEQ"; }))
        items.push_back({"MODSEQ", "MODSEQ", {}, false, false, 0, 0});
    if (vanished)
    {
        std::vector<std::pair<uint32_t, uint32_t>> asked;
        uid_ranges(a[from].text, m_folder->uidnext - 1, asked);
        std::vector<uint32_t> gone;
        if (since >= m_folder->vanished_from)
        {
            for (const auto& [ms, u] : m_folder->vanished)
                if (ms > since && in_ranges(asked, u))
                    gone.push_back(u);
        }
        else
            for (const auto& [lo, hi] : asked)
                for (uint64_t u = lo; u <= hi && u < m_folder->uidnext && gone.size() < 1000000; ++u)
                    if (!m_folder->by_uid(static_cast<uint32_t>(u)))
                        gone.push_back(static_cast<uint32_t>(u));
        if (!gone.empty())
            untagged("VANISHED (EARLIER) " + set_text(std::move(gone)));
    }
    if (uid && std::none_of(items.begin(), items.end(), [](const item& i) { return i.name == "UID"; }))
        items.insert(items.begin(), {"UID", "UID", {}, false, false, 0, 0});
    const bool needs_body = std::any_of(items.begin(), items.end(), [](const item& i) { return i.body(); });
    struct job
    {
        std::vector<size_t> idx;
        std::vector<item> items;
        size_t at{0};
        bool needs_body{false};
        bool looping{false};
        bool waiting{false};
        std::shared_ptr<const std::string> bytes;
    };
    auto j = std::make_shared<job>();
    j->idx = std::move(idx);
    j->items = std::move(items);
    j->needs_body = needs_body;
    m_waiting = true;
    // One message after the other, each answered once its bytes are read, whether they come at once or later.
    // Held by the reads it waits on and by `keep` while it runs, and gone once neither is.
    auto step = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> weak = step;
    *step = [this, j, tag, uid, weak, alive = m_alive]() {
        auto self = weak.lock();
        if (!*alive || !self)
            return;
        j->looping = true;
        while (j->at < j->idx.size())
        {
            const size_t i = j->idx[j->at];
            imap_message* m = i < m_view.size() ? m_folder->by_uid(m_view[i]) : nullptr;
            if (!m)
            {
                ++j->at;
                continue;
            }
            if (j->needs_body && !j->bytes)
            {
                j->waiting = true;
                m_store.body(m->key, m->size, [j, self, alive](std::shared_ptr<const std::string> b) {
                    if (!*alive)
                        return;
                    j->bytes = b ? b : std::make_shared<const std::string>();
                    j->waiting = false;
                    if (!j->looping)
                        (*self)();
                });
                if (j->waiting)
                {
                    j->looping = false;
                    return;
                }
            }
            std::shared_ptr<const mime::part> part;
            if (j->needs_body && j->bytes && !j->bytes->empty())
                part = m_store.structure(m->key, j->bytes);
            // The line is said in pieces, a body the store holds going out as it is held, not copied into it.
            std::string out = "* " + std::to_string(i + 1) + " FETCH (";
            bool first = true;
            const auto next = [&] {
                if (!first)
                    out += ' ';
                first = false;
            };
            bool seen_now = false;
            for (const auto& it : j->items)
            {
                if (it.name == "FLAGS" || it.name == "MODSEQ")
                    continue;
                next();
                out += it.answer;
                out += ' ';
                if (it.name == "UID")
                    out += std::to_string(m->uid);
                else if (it.name == "INTERNALDATE")
                    out += internal_date(m->date_ms);
                else if (it.name == "RFC822.SIZE")
                    out += std::to_string(j->bytes && !j->bytes->empty() ? j->bytes->size() : m->size);
                else if (!part)
                    out += it.name == "ENVELOPE" ? "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)" : mime::imap_string("", false);
                else if (it.name == "ENVELOPE")
                    out += mime::envelope(std::string_view(*j->bytes).substr(0, part->header_len));
                else if (it.name == "BODYSTRUCTURE" || it.name == "BODY")
                    out += mime::structure(*part, *j->bytes, it.name == "BODYSTRUCTURE");
                else
                {
                    std::string spec = it.section;
                    if (it.name == "RFC822.HEADER")
                        spec = "HEADER";
                    else if (it.name == "RFC822.TEXT")
                        spec = "TEXT";
                    std::string_view got;
                    std::string built;
                    if (!mime::section_of(*j->bytes, *part, spec, got, built))
                        got = {};
                    if (it.partial)
                        got = it.from >= got.size() ? std::string_view() : got.substr(it.from, it.count);
                    out += "{" + std::to_string(got.size()) + "}\r\n";
                    const std::string_view held(*j->bytes);
                    if (got.size() >= shared_from && got.data() >= held.data() &&
                        got.data() + got.size() <= held.data() + held.size())
                    {
                        m_hooks.reply(out);
                        out.clear();
                        m_hooks.reply_shared(j->bytes, static_cast<size_t>(got.data() - held.data()), got.size());
                    }
                    else
                        out.append(got);
                    if (!it.peek && it.name != "RFC822.HEADER")
                        seen_now = true;
                }
            }
            if (seen_now && !m_readonly && !(m->flags & flag_seen))
            {
                const bool told_all = m_told_modseq == m_folder->highestmodseq;
                m_store.set_flags(m_user, m_folder, {m->uid}, [](uint8_t f) { return static_cast<uint8_t>(f | flag_seen); });
                if (told_all)
                    m_told_modseq = m_folder->highestmodseq;
            }
            const bool flags = std::any_of(j->items.begin(), j->items.end(),
                                           [](const item& it) { return it.name == "FLAGS"; });
            if (flags || seen_now)
            {
                next();
                out += "FLAGS " + flags_text(m->flags, false);
            }
            if (std::any_of(j->items.begin(), j->items.end(), [](const item& it) { return it.name == "MODSEQ"; }) ||
                (seen_now && m_condstore))
            {
                next();
                out += "MODSEQ (" + std::to_string(m->modseq) + ")";
            }
            out += ")\r\n";
            m_hooks.reply(out);
            j->bytes.reset();
            ++j->at;
            if (j->at < j->idx.size() && m_hooks.backlog() > max_backlog)
            {
                j->waiting = true;
                m_hooks.when_drained([j, self, alive] {
                    if (!*alive)
                        return;
                    j->waiting = false;
                    if (!j->looping)
                        (*self)();
                });
                if (j->waiting)
                {
                    j->looping = false;
                    return;
                }
            }
        }
        j->looping = false;
        finish(tag, "OK", uid ? "UID FETCH completed" : "FETCH completed");
        resume();
    };
    auto keep = step;
    (*keep)();
}

void imap_session::cmd_store(const std::string& tag, const std::vector<token>& a, size_t from, bool uid)
{
    if (m_readonly)
        return finish(tag, "NO", "[READ-ONLY] Mailbox is read-only");
    // STORE <set> [(UNCHANGEDSINCE <modseq>)] <action> <flags> (RFC 7162 3.1.3).
    uint64_t unchanged = UINT64_MAX;
    size_t at = from + 1;
    if (a.size() > at + 3 && a[at].k == token::open && upper(a[at + 1].text) == "UNCHANGEDSINCE" &&
        a[at + 3].k == token::close)
    {
        unchanged = std::strtoull(a[at + 2].text.c_str(), nullptr, 10);
        m_condstore = true;
        at += 4;
    }
    if (a.size() < at + 2)
        return finish(tag, "BAD", "STORE needs a set, an action and flags");
    std::vector<size_t> idx;
    if (!parse_set(a[from].text, uid, idx))
        return finish(tag, "BAD", "Invalid sequence set");
    const std::string what = upper(a[at].text);
    const bool silent = what.ends_with(".SILENT");
    const std::string op = silent ? what.substr(0, what.size() - 7) : what;
    if (op != "FLAGS" && op != "+FLAGS" && op != "-FLAGS")
        return finish(tag, "BAD", "STORE takes FLAGS, +FLAGS or -FLAGS");
    uint8_t bits = 0;
    for (size_t i = at + 1; i < a.size(); ++i)
        if (a[i].k == token::atom || a[i].k == token::string)
            bits |= flag_bit(a[i].text);
    // A message changed since the mod-sequence the client gave is left as it is, and said so.
    std::vector<uint32_t> uids, modified;
    for (const size_t i : idx)
    {
        const imap_message* m = m_folder->by_uid(m_view[i]);
        if (m && m->modseq > unchanged)
            modified.push_back(uid ? m->uid : static_cast<uint32_t>(i + 1));
        else if (m)
            uids.push_back(m->uid);
    }
    const bool told_all = m_told_modseq == m_folder->highestmodseq;
    // Changed under the user's lock on the flags as they are now, whichever shard last changed them.
    m_store.set_flags(m_user, m_folder, uids, [&op, bits](uint8_t f) {
        return static_cast<uint8_t>(op == "FLAGS" ? bits : op == "+FLAGS" ? f | bits : f & ~bits);
    });
    for (const size_t i : idx)
    {
        const imap_message* m = m_folder->by_uid(m_view[i]);
        // The UIDs are in the view's order, which is theirs.
        if (!m || !std::binary_search(uids.begin(), uids.end(), m->uid))
            continue;
        if (!silent || (m_condstore && unchanged != UINT64_MAX))
            untagged(std::to_string(i + 1) + " FETCH (" + (uid ? "UID " + std::to_string(m->uid) + " " : std::string()) +
                     "FLAGS " + flags_text(m->flags, false) +
                     (m_condstore ? " MODSEQ (" + std::to_string(m->modseq) + ")" : std::string()) + ")");
    }
    // What this session did itself it is not told again.
    if (told_all)
        m_told_modseq = m_folder->highestmodseq;
    finish(tag, "OK", (modified.empty() ? std::string() : "[MODIFIED " + set_text(modified) + "] ") +
                          (uid ? "UID STORE completed" : "STORE completed"));
}

namespace
{

bool parse_one(const std::vector<std::string>& t, size_t& i, crit& out, int depth = 0)
{
    // A criterion nested deeper than a client writes one is refused, not followed down the stack.
    if (i >= t.size() || depth > 32)
        return false;
    const std::string k = upper(t[i++]);
    out = {};
    out.key = k;
    static constexpr std::string_view bare[] = {"ALL", "ANSWERED", "DELETED", "FLAGGED", "SEEN", "DRAFT", "NEW", "OLD",
                                                "RECENT", "UNANSWERED", "UNDELETED", "UNFLAGGED", "UNSEEN", "UNDRAFT"};
    if (std::find(std::begin(bare), std::end(bare), k) != std::end(bare))
        return true;
    static constexpr std::string_view one[] = {"KEYWORD", "UNKEYWORD", "LARGER", "SMALLER", "BEFORE", "ON",
                                               "SINCE", "SENTBEFORE", "SENTON", "SENTSINCE", "FROM", "TO",
                                               "CC", "BCC", "SUBJECT", "BODY", "TEXT", "UID"};
    if (std::find(std::begin(one), std::end(one), k) != std::end(one))
    {
        if (i >= t.size())
            return false;
        out.arg = t[i++];
        return true;
    }
    if (k == "HEADER")
    {
        if (i + 1 >= t.size())
            return false;
        out.arg = t[i++];
        out.arg2 = t[i++];
        return true;
    }
    // MODSEQ [<entry-name> <entry-type>] <mod-sequence> (RFC 7162 3.1.5), the entry taken as every flag's.
    if (k == "MODSEQ")
    {
        if (i < t.size() && t[i].find_first_not_of("0123456789") != std::string::npos)
            i += 2;
        if (i >= t.size() || t[i].empty() || t[i].find_first_not_of("0123456789") != std::string::npos)
            return false;
        out.arg = t[i++];
        return true;
    }
    if (k == "NOT")
    {
        out.kids.resize(1);
        return parse_one(t, i, out.kids[0], depth + 1);
    }
    if (k == "OR")
    {
        out.kids.resize(2);
        return parse_one(t, i, out.kids[0], depth + 1) && parse_one(t, i, out.kids[1], depth + 1);
    }
    if (k == "(")
    {
        out.key = "AND";
        while (i < t.size() && t[i] != ")")
        {
            crit c;
            if (!parse_one(t, i, c, depth + 1))
                return false;
            out.kids.push_back(std::move(c));
        }
        ++i;
        return true;
    }
    // A sequence set.
    if (!k.empty() && (std::isdigit(static_cast<unsigned char>(k[0])) || k[0] == '*'))
    {
        out.key = "SET";
        out.arg = k;
        return true;
    }
    return false;
}

}   // namespace

namespace
{

// Whether message `m`, number `idx` in the session's view, its bytes `msg` and its header `head`, meets `c`.
bool matches(const crit& c, const imap_message& m, size_t idx, std::string_view msg, std::string_view head)
{
    const int64_t day = m.date_ms / 86400000;
    const std::string& k = c.key;
    if (k == "AND")
    {
        for (const auto& x : c.kids)
            if (!matches(x, m, idx, msg, head))
                return false;
        return true;
    }
    if (k == "NOT")
        return !matches(c.kids[0], m, idx, msg, head);
    if (k == "OR")
        return matches(c.kids[0], m, idx, msg, head) || matches(c.kids[1], m, idx, msg, head);
    if (k == "SET" || k == "UID")
        return std::binary_search(c.set.begin(), c.set.end(), idx);
    if (k == "ALL")
        return true;
    if (k == "ANSWERED")
        return m.flags & flag_answered;
    if (k == "UNANSWERED")
        return !(m.flags & flag_answered);
    if (k == "DELETED")
        return m.flags & flag_deleted;
    if (k == "UNDELETED")
        return !(m.flags & flag_deleted);
    if (k == "FLAGGED")
        return m.flags & flag_flagged;
    if (k == "UNFLAGGED")
        return !(m.flags & flag_flagged);
    if (k == "SEEN")
        return m.flags & flag_seen;
    if (k == "UNSEEN")
        return !(m.flags & flag_seen);
    if (k == "DRAFT")
        return m.flags & flag_draft;
    if (k == "UNDRAFT")
        return !(m.flags & flag_draft);
    if (k == "RECENT" || k == "NEW")
        return m.recent && (k == "RECENT" || !(m.flags & flag_seen));
    if (k == "OLD")
        return !m.recent;
    if (k == "KEYWORD")
        return false;
    if (k == "UNKEYWORD")
        return true;
    if (k == "MODSEQ")
        return m.modseq >= std::strtoull(c.arg.c_str(), nullptr, 10);
    if (k == "LARGER")
        return m.size > std::strtoull(c.arg.c_str(), nullptr, 10);
    if (k == "SMALLER")
        return m.size < std::strtoull(c.arg.c_str(), nullptr, 10);
    const int64_t d = search_day(c.arg);
    if (k == "BEFORE" || k == "SENTBEFORE")
        return day < d;
    if (k == "ON" || k == "SENTON")
        return day == d;
    if (k == "SINCE" || k == "SENTSINCE")
        return day >= d;
    if (k == "HEADER")
        return contains_ci(header_value(head, c.arg), c.arg2);
    if (k == "FROM" || k == "TO" || k == "CC" || k == "BCC" || k == "SUBJECT")
        return contains_ci(header_value(head, k), c.arg);
    if (k == "BODY")
        return contains_ci(msg.substr(head.size()), c.arg);
    if (k == "TEXT")
        return contains_ci(msg, c.arg);
    return false;
}

}   // namespace

void imap_session::cmd_search(const std::string& tag, const std::vector<token>& a, size_t from, bool uid)
{
    std::vector<std::string> t;
    for (size_t i = from; i < a.size(); ++i)
        t.push_back(a[i].k == token::open ? "(" : a[i].k == token::close ? ")" : a[i].text);
    size_t i = 0;
    // RETURN (MIN MAX ALL COUNT) asks for ESEARCH's answer (RFC 4731), RETURN () for ALL.
    bool esearch = false;
    std::vector<std::string> want;
    if (i + 1 < t.size() && iequal(t[i], "RETURN") && t[i + 1] == "(")
    {
        esearch = true;
        for (i += 2; i < t.size() && t[i] != ")"; ++i)
            want.push_back(upper(t[i]));
        ++i;
        if (want.empty())
            want.push_back("ALL");
    }
    if (i < t.size() && iequal(t[i], "CHARSET"))
        i += 2;
    crit all;
    all.key = "AND";
    while (i < t.size())
    {
        crit c;
        if (!parse_one(t, i, c))
            return finish(tag, "BAD", "Invalid search criteria");
        all.kids.push_back(std::move(c));
    }
    // Sets resolved now, against this session's numbering.
    std::function<bool(crit&)> resolve = [&](crit& c) {
        if (c.key == "SET" || c.key == "UID")
            if (!parse_set(c.arg, c.key == "UID", c.set))
                return false;
        for (auto& k : c.kids)
            if (!resolve(k))
                return false;
        return true;
    };
    if (!resolve(all))
        return finish(tag, "BAD", "Invalid sequence set");
    std::function<bool(const crit&)> asks_modseq = [&](const crit& c) {
        if (c.key == "MODSEQ")
            return true;
        for (const auto& k : c.kids)
            if (asks_modseq(k))
                return true;
        return false;
    };
    struct job
    {
        crit all;
        size_t at{0};
        std::vector<uint32_t> hits;
        uint64_t top_modseq{0};
        std::shared_ptr<const std::string> bytes;
        bool looping{false}, waiting{false};
    };
    auto j = std::make_shared<job>();
    j->all = std::move(all);
    const bool content = j->all.content();
    const bool modseq = asks_modseq(j->all);
    if (modseq)
        m_condstore = true;
    m_waiting = true;
    auto step = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> weak = step;
    *step = [this, j, tag, uid, content, modseq, esearch, want, weak, alive = m_alive]() {
        auto self = weak.lock();
        if (!*alive || !self)
            return;
        j->looping = true;
        while (j->at < m_view.size())
        {
            const size_t idx = j->at;
            imap_message* m = m_folder->by_uid(m_view[idx]);
            if (!m)
            {
                ++j->at;
                continue;
            }
            if (content && !j->bytes)
            {
                j->waiting = true;
                m_store.body(m->key, m->size, [j, self, alive](std::shared_ptr<const std::string> b) {
                    if (!*alive)
                        return;
                    j->bytes = b ? b : std::make_shared<const std::string>();
                    j->waiting = false;
                    if (!j->looping)
                        (*self)();
                });
                if (j->waiting)
                {
                    j->looping = false;
                    return;
                }
            }
            const std::string_view msg = j->bytes ? std::string_view(*j->bytes) : std::string_view{};
            const std::string_view head = header_block(msg);
            if (matches(j->all, *m, idx, msg, head))
            {
                j->hits.push_back(uid ? m->uid : static_cast<uint32_t>(idx + 1));
                j->top_modseq = std::max(j->top_modseq, m->modseq);
            }
            j->bytes.reset();
            ++j->at;
        }
        j->looping = false;
        if (esearch)
        {
            const auto asked = [&want](std::string_view w) { return std::find(want.begin(), want.end(), w) != want.end(); };
            std::string out = "ESEARCH (TAG " + mime::imap_string(tag, false) + ")" + (uid ? " UID" : "");
            if (!j->hits.empty() && asked("MIN"))
                out += " MIN " + std::to_string(j->hits.front());
            if (!j->hits.empty() && asked("MAX"))
                out += " MAX " + std::to_string(j->hits.back());
            if (asked("COUNT"))
                out += " COUNT " + std::to_string(j->hits.size());
            if (!j->hits.empty() && asked("ALL"))
                out += " ALL " + set_text(j->hits);
            if (modseq && !j->hits.empty())
                out += " MODSEQ " + std::to_string(j->top_modseq);
            untagged(out);
        }
        else
        {
            std::string out = "SEARCH";
            for (const uint32_t h : j->hits)
                out += " " + std::to_string(h);
            if (modseq && !j->hits.empty())
                out += " (MODSEQ " + std::to_string(j->top_modseq) + ")";
            untagged(out);
        }
        finish(tag, "OK", uid ? "UID SEARCH completed" : "SEARCH completed");
        resume();
    };
    auto keep = step;
    (*keep)();
}

void imap_session::cmd_order(const std::string& tag, const std::vector<token>& a, size_t from, bool uid, bool thread)
{
    // SORT (<criteria>) <charset> <search>, THREAD <algorithm> <charset> <search> (RFC 5256).
    const std::string what = thread ? "THREAD" : "SORT";
    std::vector<imap_order::key> keys;
    std::string algorithm;
    size_t i = from;
    if (!thread)
    {
        if (i >= a.size() || a[i].k != token::open)
            return finish(tag, "BAD", "SORT needs its criteria in parentheses");
        std::vector<std::string> w;
        for (++i; i < a.size() && a[i].k != token::close; ++i)
            w.push_back(a[i].text);
        ++i;
        if (!imap_order::parse_keys(w, keys))
            return finish(tag, "BAD", "Unknown sort criterion");
    }
    else
    {
        algorithm = i < a.size() ? upper(a[i++].text) : std::string();
        if (algorithm != "ORDEREDSUBJECT" && algorithm != "REFERENCES")
            return finish(tag, "BAD", "THREAD takes ORDEREDSUBJECT or REFERENCES");
    }
    if (i >= a.size())
        return finish(tag, "BAD", what + " needs a charset and search criteria");
    const std::string charset = upper(a[i++].text);
    if (charset != "UTF-8" && charset != "US-ASCII")
        return finish(tag, "NO", "[BADCHARSET (UTF-8 US-ASCII)] Unknown charset");
    std::vector<std::string> t;
    for (; i < a.size(); ++i)
        t.push_back(a[i].k == token::open ? "(" : a[i].k == token::close ? ")" : a[i].text);
    crit all;
    all.key = "AND";
    for (size_t k = 0; k < t.size();)
    {
        crit c;
        if (!parse_one(t, k, c))
            return finish(tag, "BAD", "Invalid search criteria");
        all.kids.push_back(std::move(c));
    }
    if (all.kids.empty())
        return finish(tag, "BAD", what + " needs search criteria");
    std::function<bool(crit&)> resolve = [&](crit& c) {
        if ((c.key == "SET" || c.key == "UID") && !parse_set(c.arg, c.key == "UID", c.set))
            return false;
        for (auto& k : c.kids)
            if (!resolve(k))
                return false;
        return true;
    };
    if (!resolve(all))
        return finish(tag, "BAD", "Invalid sequence set");
    // The header is read for every key but the arrival and the size, and for every thread.
    bool headers = thread;
    for (const auto& k : keys)
        headers = headers || (k.k != imap_order::key::kind::arrival && k.k != imap_order::key::kind::size);
    struct job
    {
        crit all;
        size_t at{0};
        std::vector<imap_order::entry> hits;
        std::shared_ptr<const std::string> bytes;
        bool looping{false}, waiting{false};
    };
    auto j = std::make_shared<job>();
    j->all = std::move(all);
    const bool read_bytes = headers || j->all.content();
    m_waiting = true;
    auto step = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> weak = step;
    *step = [this, j, tag, uid, thread, keys, algorithm, what, read_bytes, weak, alive = m_alive]() {
        auto self = weak.lock();
        if (!*alive || !self)
            return;
        j->looping = true;
        while (j->at < m_view.size())
        {
            const size_t idx = j->at;
            const imap_message* m = m_folder->by_uid(m_view[idx]);
            if (!m)
            {
                ++j->at;
                continue;
            }
            if (read_bytes && !j->bytes)
            {
                j->waiting = true;
                m_store.body(m->key, m->size, [j, self, alive](std::shared_ptr<const std::string> b) {
                    if (!*alive)
                        return;
                    j->bytes = b ? b : std::make_shared<const std::string>();
                    j->waiting = false;
                    if (!j->looping)
                        (*self)();
                });
                if (j->waiting)
                {
                    j->looping = false;
                    return;
                }
            }
            const std::string_view msg = j->bytes ? std::string_view(*j->bytes) : std::string_view{};
            const std::string_view head = header_block(msg);
            if (matches(j->all, *m, idx, msg, head))
            {
                imap_order::entry e;
                e.number = uid ? m->uid : static_cast<uint32_t>(idx + 1);
                e.seq = idx;
                e.arrival_ms = m->date_ms;
                e.size = m->size;
                e.sent_s = m->date_ms / 1000;
                if (read_bytes)
                    imap_order::read(e, head);
                j->hits.push_back(std::move(e));
            }
            j->bytes.reset();
            ++j->at;
        }
        j->looping = false;
        if (thread)
            untagged("THREAD " + (algorithm == "REFERENCES" ? imap_order::references(std::move(j->hits))
                                                             : imap_order::ordered_subject(std::move(j->hits))));
        else
        {
            imap_order::sort(j->hits, keys);
            std::string out = "SORT";
            for (const auto& e : j->hits)
                out += " " + std::to_string(e.number);
            untagged(out);
        }
        finish(tag, "OK", (uid ? "UID " : "") + what + " completed");
        resume();
    };
    auto keep = step;
    (*keep)();
}

void imap_session::cmd_copy(const std::string& tag, const std::vector<token>& a, size_t from, bool uid, bool move)
{
    if (a.size() < from + 2)
        return finish(tag, "BAD", "COPY needs a set and a mailbox");
    if (move && m_readonly)
        return finish(tag, "NO", "[READ-ONLY] Mailbox is read-only");
    std::vector<size_t> idx;
    if (!parse_set(a[from].text, uid, idx))
        return finish(tag, "BAD", "Invalid sequence set");
    std::vector<uint32_t> uids;
    uint64_t bytes = 0;
    for (const size_t i : idx)
    {
        uids.push_back(m_view[i]);
        if (const imap_message* m = m_folder->by_uid(m_view[i]))
            bytes += m->size;
    }
    if (uids.empty())
        return finish(tag, "OK", "Nothing to copy");
    // A copy takes room a move gives back.
    if (const uint64_t q = m_store.quota(m_user); !move && q && m_store.usage(m_user) + bytes > q)
        return finish(tag, "NO", "[OVERQUOTA] The mailbox is full");
    m_waiting = true;
    m_store.copy(m_user, m_folder, uids, a[from + 1].text,
                 [this, alive = m_alive, tag, uids, move, uid](bool ok, uint32_t validity, std::vector<uint32_t> made) {
                     if (!*alive)
                         return;
                     if (!ok)
                     {
                         finish(tag, "NO", "[TRYCREATE] COPY failed");
                         resume();
                         return;
                     }
                     std::string src, dst;
                     for (size_t i = 0; i < made.size() && i < uids.size(); ++i)
                     {
                         src += (i ? "," : "") + std::to_string(uids[i]);
                         dst += (i ? "," : "") + std::to_string(made[i]);
                     }
                     const std::string code = "[COPYUID " + std::to_string(validity) + " " + src + " " + dst + "] ";
                     if (!move)
                     {
                         finish(tag, "OK", code + (uid ? "UID COPY completed" : "COPY completed"));
                         resume();
                         return;
                     }
                     // MOVE: what was copied goes from here, said as expunged (RFC 6851).
                     untagged("OK " + code + "Moved");
                     for (const uint32_t u : uids)
                         if (imap_message* m = m_folder->by_uid(u))
                             m->flags |= flag_deleted;
                     m_waiting = false;
                     cmd_expunge(tag, uids, false, uid ? "UID MOVE completed" : "MOVE completed");
                 });
}

void imap_session::cmd_expunge(const std::string& tag, const std::vector<uint32_t>& only, bool, std::string_view done_text)
{
    m_waiting = true;
    m_store.expunge(m_user, m_folder, only,
                    [this, alive = m_alive, tag, text = std::string(done_text)](std::vector<uint32_t> gone) {
                        if (!*alive)
                            return;
                        // Highest number first, so each one said is where the client has it; VANISHED under QRESYNC.
                        std::vector<uint32_t> vanished;
                        for (size_t i = m_view.size(); i-- > 0;)
                            if (std::binary_search(gone.begin(), gone.end(), m_view[i]))
                            {
                                if (m_qresync)
                                    vanished.push_back(m_view[i]);
                                else
                                    untagged(std::to_string(i + 1) + " EXPUNGE");
                                m_view.erase(m_view.begin() + static_cast<long>(i));
                            }
                        if (!vanished.empty())
                            untagged("VANISHED " + set_text(std::move(vanished)));
                        m_seen_version = m_folder->version;
                        finish(tag, "OK", text);
                        resume();
                    });
}

void imap_session::poll()
{
    if (!m_idle || !m_folder)
        return;
    m_store.open(m_user, m_folder->name, [this, alive = m_alive](std::shared_ptr<imap_folder>) {
        if (*alive && m_idle)
            update_view();
    });
}

}   // namespace socketley::mail
