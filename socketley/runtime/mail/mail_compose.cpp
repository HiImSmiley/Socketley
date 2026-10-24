#include "mail_compose.h"

#include <cctype>
#include <ctime>

#include "../../shared/util/ascii.h"
#include "../../shared/util/base64.h"
#include "../../shared/util/random_id.h"

namespace socketley::mail
{

namespace
{

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n'))
        s.remove_suffix(1);
    return s;
}

bool plain_ascii(std::string_view s)
{
    for (const unsigned char c : s)
        if ((c < 0x20 && c != '\t') || c > 0x7e)
            return false;
    return true;
}

// RFC 2047 encoded words of at most 75 characters each, cut only between whole UTF-8 characters.
std::string encoded_words(std::string_view s)
{
    std::string out;
    size_t at = 0;
    while (at < s.size())
    {
        // 45 bytes are 60 characters of base64, which with "=?UTF-8?B?" and "?=" is 72.
        size_t end = std::min(s.size(), at + 45);
        while (end < s.size() && end > at && (static_cast<unsigned char>(s[end]) & 0xC0) == 0x80)
            --end;
        if (end == at)
            end = std::min(s.size(), at + 45);
        if (!out.empty())
            out += "\r\n ";
        out += "=?UTF-8?B?" + socketley::base64::encode(s.substr(at, end - at)) + "?=";
        at = end;
    }
    return out;
}

// A display name as a header carries it: as it is when it is plain words, quoted when it holds a special, encoded
// when it is not ASCII.
std::string display_name(std::string_view name)
{
    if (name.empty())
        return {};
    if (!plain_ascii(name))
        return encoded_words(name);
    if (name.find_first_of("()<>[]:;@\\,.\"") == std::string_view::npos)
        return std::string(name);
    std::string q = "\"";
    for (const char c : name)
    {
        if (c == '"' || c == '\\')
            q += '\\';
        q += c;
    }
    return q + "\"";
}

std::string mailbox_text(const address& a, std::string_view name)
{
    const std::string d = display_name(name);
    return d.empty() ? a.text() : d + " <" + a.text() + ">";
}

bool needs_qp(std::string_view text)
{
    size_t line = 0;
    for (const unsigned char c : text)
    {
        if (c == '\n')
        {
            line = 0;
            continue;
        }
        if ((c < 0x20 && c != '\t' && c != '\r') || c > 0x7e || ++line > 900)
            return true;
    }
    return false;
}

std::string text_part(std::string_view type, std::string_view text)
{
    const std::string body = crlf_lines(text);
    if (!needs_qp(body))
        return "Content-Type: " + std::string(type) + "; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\n" +
               body;
    return "Content-Type: " + std::string(type) +
           "; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" + quoted_printable(body);
}

std::string boundary()
{
    return "=_skl_" + socketley::random_hex(12);
}

bool header_name_ok(std::string_view n)
{
    if (n.empty())
        return false;
    for (const unsigned char c : n)
        if (c <= 0x20 || c >= 0x7f || c == ':')
            return false;
    return true;
}

}   // namespace

std::string rfc5322_date(int64_t unix_ms)
{
    const time_t t = static_cast<time_t>(unix_ms / 1000);
    struct tm tm{};
    ::gmtime_r(&t, &tm);
    char buf[64];
    std::strftime(buf, sizeof buf, "%a, %d %b %Y %H:%M:%S +0000", &tm);
    return buf;
}

bool parse_mailbox(std::string_view in, address& out, std::string* display)
{
    in = trim(in);
    const size_t lt = in.rfind('<');
    std::string_view addr = in;
    if (lt != std::string_view::npos)
    {
        if (in.back() != '>')
            return false;
        addr = in.substr(lt + 1, in.size() - lt - 2);
        if (display)
        {
            std::string_view name = trim(in.substr(0, lt));
            display->clear();
            // A quoted name is read with its quoted pairs, \" and \\, as the characters they stand for (RFC 5322 3.2.4).
            if (name.size() >= 2 && name.front() == '"' && name.back() == '"')
                for (size_t i = 1; i + 1 < name.size(); ++i)
                    display->push_back(name[i] == '\\' && i + 2 < name.size() ? name[++i] : name[i]);
            else
                *display = std::string(name);
        }
    }
    else if (display)
        display->clear();
    return parse_address(trim(addr), out, true);
}

bool parse_mailbox_list(std::string_view in, std::vector<address>& out)
{
    bool quoted = false;
    int angle = 0;
    size_t start = 0;
    for (size_t i = 0; i <= in.size(); ++i)
    {
        const char c = i < in.size() ? in[i] : ',';
        if (c == '"' && (i == 0 || in[i - 1] != '\\'))
            quoted = !quoted;
        else if (!quoted && c == '<')
            ++angle;
        else if (!quoted && c == '>')
            --angle;
        else if (!quoted && angle == 0 && c == ',')
        {
            const std::string_view one = trim(in.substr(start, i - start));
            start = i + 1;
            if (one.empty())
                continue;
            address a;
            if (!parse_mailbox(one, a))
                return false;
            out.push_back(std::move(a));
        }
    }
    return true;
}

std::string encode_header_value(std::string_view, std::string_view value)
{
    if (!plain_ascii(value))
        return encoded_words(value);
    return std::string(value);
}

std::string crlf_lines(std::string_view text)
{
    std::string out;
    out.reserve(text.size() + text.size() / 32 + 2);
    for (size_t i = 0; i < text.size(); ++i)
    {
        const char c = text[i];
        if (c == '\r')
        {
            out += "\r\n";
            if (i + 1 < text.size() && text[i + 1] == '\n')
                ++i;
        }
        else if (c == '\n')
            out += "\r\n";
        else
            out += c;
    }
    if (!out.empty() && !out.ends_with("\r\n"))
        out += "\r\n";
    return out;
}

std::string quoted_printable(std::string_view text)
{
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(text.size() + text.size() / 8);
    size_t col = 0;
    for (size_t i = 0; i < text.size(); ++i)
    {
        const auto c = static_cast<unsigned char>(text[i]);
        if (c == '\r' && i + 1 < text.size() && text[i + 1] == '\n')
        {
            out += "\r\n";
            ++i;
            col = 0;
            continue;
        }
        // A space or tab before a line's end is encoded, since a mail system may strip it.
        const bool line_ends = i + 1 >= text.size() || (text[i + 1] == '\r' && i + 2 < text.size() && text[i + 2] == '\n');
        const bool literal = (c >= 33 && c <= 126 && c != '=') || ((c == ' ' || c == '\t') && !line_ends);
        const size_t width = literal ? 1 : 3;
        // Lines of 76 at most, the soft break's '=' among them.
        if (col + width > 75)
        {
            out += "=\r\n";
            col = 0;
        }
        if (literal)
            out += static_cast<char>(c);
        else
        {
            out += '=';
            out += hex[c >> 4];
            out += hex[c & 15];
        }
        col += width;
    }
    return out;
}

std::string base64_lines(std::string_view data)
{
    const std::string b = socketley::base64::encode(data);
    std::string out;
    out.reserve(b.size() + b.size() / 76 * 2 + 2);
    for (size_t at = 0; at < b.size(); at += 76)
    {
        out.append(b, at, 76);
        out += "\r\n";
    }
    return out;
}

namespace
{

// A part's name as its header parameter: quoted where it is ASCII, as RFC 2231 has it, UTF-8''%XX, where not -- never
// an encoded word inside quotes, which RFC 2047 5 forbids and a client shows as it is.
std::string name_param(const std::string& name)
{
    if (plain_ascii(name))
        return "name=\"" + name + "\"";
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string named = "name*=UTF-8''";
    for (const char ch : name)
    {
        const auto u = static_cast<unsigned char>(ch);
        if (std::isalnum(u) || ch == '.' || ch == '-' || ch == '_')
            named += ch;
        else
        {
            named += '%';
            named += hex[u >> 4];
            named += hex[u & 15];
        }
    }
    return named;
}

// A name and a type a header can hold, as a part's, and an inline one's name its Content-ID's too.
bool part_fits(const attachment& a, bool inline_one, std::string& why)
{
    if (a.name.find_first_of(inline_one ? "\"\r\n\\<> " : "\"\r\n\\") == std::string::npos &&
        a.type.find_first_of("\r\n\";") == std::string::npos && !(inline_one && a.name.empty()))
        return true;
    why = "the attachment " + a.name + " has a name or type no header can hold";
    return false;
}

}   // namespace

bool compose_message(const compose& c, const address& from, std::string_view from_name, std::string_view msgid,
                     int64_t now_ms, composed& out, std::string& why)
{
    out = {};
    out.from = from.text();
    std::vector<std::string> to_h, cc_h, bcc_h;
    const auto take = [&](const std::vector<std::string>& list, std::vector<std::string>* header) {
        for (const auto& one : list)
        {
            address a;
            std::string name;
            if (!parse_mailbox(one, a, &name) || a.domain.empty())
            {
                why = one + " is not an address";
                return false;
            }
            out.rcpts.push_back(a.text());
            if (header)
                header->push_back(mailbox_text(a, name));
        }
        return true;
    };
    if (!take(c.to, &to_h) || !take(c.cc, &cc_h) || !take(c.bcc, c.draft ? &bcc_h : nullptr))
        return false;
    if (out.rcpts.empty() && !c.draft)
    {
        why = "the message names no recipient";
        return false;
    }
    if (!c.raw.empty())
    {
        out.message = crlf_lines(c.raw);
        return true;
    }
    std::string h;
    h += "Date: " + rfc5322_date(now_ms) + "\r\n";
    h += "From: " + mailbox_text(from, from_name) + "\r\n";
    const auto list = [](const std::vector<std::string>& v) {
        std::string s;
        for (const auto& x : v)
            s += (s.empty() ? "" : ",\r\n ") + x;
        return s;
    };
    if (!to_h.empty())
        h += "To: " + list(to_h) + "\r\n";
    if (!cc_h.empty())
        h += "Cc: " + list(cc_h) + "\r\n";
    if (!bcc_h.empty())
        h += "Bcc: " + list(bcc_h) + "\r\n";
    if (!c.reply_to.empty())
    {
        address a;
        std::string name;
        if (!parse_mailbox(c.reply_to, a, &name))
        {
            why = c.reply_to + " is not an address";
            return false;
        }
        h += "Reply-To: " + mailbox_text(a, name) + "\r\n";
    }
    h += "Subject: " + encode_header_value("Subject", c.subject) + "\r\n";
    h += "Message-ID: <" + std::string(msgid) + ">\r\n";
    h += "MIME-Version: 1.0\r\n";
    for (const auto& x : c.headers)
    {
        const size_t colon = x.find(':');
        const std::string_view name = trim(std::string_view(x).substr(0, colon));
        if (colon == std::string::npos || !header_name_ok(name) || x.find_first_of("\r\n") != std::string::npos)
        {
            why = "the header " + x + " is not one line of `Name: value`";
            return false;
        }
        static constexpr std::string_view own[] = {"date", "from", "to", "cc", "bcc", "subject", "message-id",
                                                   "mime-version", "content-type", "content-transfer-encoding"};
        for (const auto o : own)
            if (socketley::ascii::iequals(name, o))
            {
                why = "the header " + std::string(name) + " is the message's own and cannot be given";
                return false;
            }
        h += std::string(name) + ": " + encode_header_value(name, trim(std::string_view(x).substr(colon + 1))) + "\r\n";
    }
    std::string body;
    const bool text = !c.text.empty() || (c.html.empty() && c.attachments.empty());
    std::string main;
    // The HTML with the images it shows by cid:<name> beside it, one related whole (RFC 2387).
    std::string html = c.html.empty() ? std::string() : text_part("text/html", c.html);
    if (!html.empty() && !c.inlines.empty())
    {
        const std::string b = boundary();
        std::string related = "Content-Type: multipart/related; boundary=\"" + b + "\"\r\n\r\n--" + b + "\r\n" + html + "\r\n";
        for (const auto& a : c.inlines)
        {
            if (!part_fits(a, true, why))
                return false;
            const std::string type = a.type.empty() ? "application/octet-stream" : a.type;
            related += "--" + b + "\r\nContent-Type: " + type + "; " + name_param(a.name) + "\r\nContent-ID: <" + a.name +
                       ">\r\nContent-Disposition: inline; file" + name_param(a.name) +
                       "\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64_lines(a.data) + "\r\n";
        }
        html = related + "--" + b + "--\r\n";
    }
    if (text && !html.empty())
    {
        const std::string b = boundary();
        main = "Content-Type: multipart/alternative; boundary=\"" + b + "\"\r\n\r\n--" + b + "\r\n" +
               text_part("text/plain", c.text) + "\r\n--" + b + "\r\n" + html + "\r\n--" + b + "--\r\n";
    }
    else if (!html.empty())
        main = html;
    else if (text)
        main = text_part("text/plain", c.text);
    if (c.attachments.empty())
        body = main;
    else
    {
        const std::string b = boundary();
        body = "Content-Type: multipart/mixed; boundary=\"" + b + "\"\r\n\r\n";
        if (!main.empty())
            body += "--" + b + "\r\n" + main + "\r\n";
        for (const auto& a : c.attachments)
        {
            const std::string type = a.type.empty() ? "application/octet-stream" : a.type;
            if (!part_fits(a, false, why))
                return false;
            const std::string named = name_param(a.name);
            body += "--" + b + "\r\nContent-Type: " + type + "; " + named +
                    "\r\nContent-Disposition: attachment; file" + named +
                    "\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64_lines(a.data) + "\r\n";
        }
        body += "--" + b + "--\r\n";
    }
    out.message = h + body;
    return true;
}

std::string_view header_block(std::string_view message)
{
    const size_t end = message.find("\r\n\r\n");
    if (end != std::string_view::npos)
        return message.substr(0, end + 4);
    if (message.starts_with("\r\n"))
        return message.substr(0, 2);
    return message;
}

std::vector<std::pair<std::string_view, std::string_view>> split_headers(std::string_view headers)
{
    std::vector<std::pair<std::string_view, std::string_view>> out;
    size_t at = 0;
    while (at < headers.size())
    {
        size_t end = at;
        // A header runs on over lines that begin with a space or a tab.
        for (;;)
        {
            const size_t nl = headers.find("\r\n", end);
            if (nl == std::string_view::npos)
            {
                end = headers.size();
                break;
            }
            end = nl + 2;
            if (end >= headers.size() || (headers[end] != ' ' && headers[end] != '\t'))
                break;
        }
        const std::string_view one = headers.substr(at, end - at);
        at = end;
        if (one == "\r\n" || one.empty())
            break;
        const size_t colon = one.find(':');
        if (colon == std::string_view::npos)
            continue;
        std::string_view value = one.substr(colon + 1);
        if (value.ends_with("\r\n"))
            value.remove_suffix(2);
        out.emplace_back(one.substr(0, colon), value);
    }
    return out;
}

std::string header_value(std::string_view headers, std::string_view name)
{
    for (const auto& [n, v] : split_headers(headers))
        if (socketley::ascii::iequals(trim(n), name))
        {
            std::string out;
            for (size_t i = 0; i < v.size(); ++i)
            {
                if (v[i] == '\r' && i + 1 < v.size() && v[i + 1] == '\n')
                {
                    ++i;
                    continue;
                }
                out += v[i];
            }
            return std::string(trim(out));
        }
    return {};
}

}   // namespace socketley::mail
