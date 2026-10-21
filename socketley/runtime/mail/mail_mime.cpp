#include "mail_mime.h"

#include <algorithm>
#include <cctype>

#include "mail_compose.h"
#include "../../shared/util/ascii.h"

namespace socketley::mail::mime
{

namespace
{

constexpr int max_depth = 32;

std::string upper(std::string_view s)
{
    std::string out(s);
    for (char& c : out)
        c = socketley::ascii::upper(c);
    return out;
}

std::string lower(std::string_view s)
{
    std::string out(s);
    socketley::ascii::lower_in_place(out);
    return out;
}

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n'))
        s.remove_suffix(1);
    return s;
}

// A header's value with its comments taken out, as Content-Type and its kin are read.
std::string uncommented(std::string_view v)
{
    std::string out;
    int depth = 0;
    bool quoted = false;
    for (size_t i = 0; i < v.size(); ++i)
    {
        const char c = v[i];
        if (quoted)
        {
            out += c;
            if (c == '\\' && i + 1 < v.size())
                out += v[++i];
            else if (c == '"')
                quoted = false;
            continue;
        }
        if (c == '"' && depth == 0)
        {
            quoted = true;
            out += c;
        }
        else if (c == '(')
            ++depth;
        else if (c == ')' && depth > 0)
            --depth;
        else if (depth == 0)
            out += c;
    }
    return out;
}

// "value; name=value; name="quoted"": the value, and the parameters with their names in lower case.
std::string with_params(std::string_view v, std::vector<std::pair<std::string, std::string>>& params)
{
    const std::string s = uncommented(v);
    std::string_view rest = s;
    const size_t semi = rest.find(';');
    std::string head(trim(rest.substr(0, semi)));
    rest = semi == std::string_view::npos ? std::string_view{} : rest.substr(semi + 1);
    while (!rest.empty())
    {
        rest = trim(rest);
        const size_t eq = rest.find('=');
        if (eq == std::string_view::npos)
            break;
        const std::string name = lower(trim(rest.substr(0, eq)));
        rest = trim(rest.substr(eq + 1));
        std::string value;
        if (!rest.empty() && rest.front() == '"')
        {
            size_t i = 1;
            for (; i < rest.size() && rest[i] != '"'; ++i)
            {
                if (rest[i] == '\\' && i + 1 < rest.size())
                    ++i;
                value += rest[i];
            }
            rest = i < rest.size() ? rest.substr(i + 1) : std::string_view{};
            const size_t next = rest.find(';');
            rest = next == std::string_view::npos ? std::string_view{} : rest.substr(next + 1);
        }
        else
        {
            const size_t next = rest.find(';');
            value = std::string(trim(rest.substr(0, next)));
            rest = next == std::string_view::npos ? std::string_view{} : rest.substr(next + 1);
        }
        if (!name.empty())
            params.emplace_back(name, value);
    }
    return head;
}

// The lines of a body, a last one without its CRLF counted too: in a multipart that CRLF is the delimiter's.
size_t count_lines(std::string_view body)
{
    size_t n = 0;
    for (size_t at = body.find("\r\n"); at != std::string_view::npos; at = body.find("\r\n", at + 2))
        ++n;
    return n + (!body.empty() && !body.ends_with("\r\n") ? 1 : 0);
}

void parse_into(part& p, std::string_view msg, size_t off, size_t len, int depth, bool digest)
{
    const std::string_view region = msg.substr(off, len);
    const std::string_view head = header_block(region);
    p.header_off = off;
    // A part with no blank line is all header, and has no body.
    const bool has_body = head.size() < region.size() || head.ends_with("\r\n\r\n") || head == "\r\n";
    p.header_len = has_body ? head.size() : region.size();
    p.body_off = off + p.header_len;
    p.body_len = len - p.header_len;
    if (digest)
    {
        p.type = "message";
        p.subtype = "rfc822";
    }
    for (const auto& [name, value] : split_headers(head))
    {
        const std::string n = lower(trim(name));
        std::string v;
        for (size_t i = 0; i < value.size(); ++i)
            if (value[i] != '\r' && value[i] != '\n')
                v += value[i];
        if (n == "content-type")
        {
            std::vector<std::pair<std::string, std::string>> params;
            const std::string t = lower(with_params(v, params));
            const size_t slash = t.find('/');
            if (slash != std::string::npos && slash > 0 && slash + 1 < t.size())
            {
                p.type = t.substr(0, slash);
                p.subtype = t.substr(slash + 1);
                p.params = std::move(params);
            }
        }
        else if (n == "content-transfer-encoding")
            p.encoding = upper(trim(uncommented(v)));
        else if (n == "content-id")
            p.id = std::string(trim(v));
        else if (n == "content-description")
            p.description = std::string(trim(v));
        else if (n == "content-md5")
            p.md5 = std::string(trim(v));
        else if (n == "content-disposition")
            p.disposition = lower(with_params(v, p.disposition_params));
        else if (n == "content-language")
            p.language = std::string(trim(uncommented(v)));
        else if (n == "content-location")
            p.location = std::string(trim(uncommented(v)));
    }
    if (p.encoding.empty())
        p.encoding = "7BIT";
    const std::string_view body = msg.substr(p.body_off, p.body_len);
    if (p.type == "text" || p.message())
        p.lines = count_lines(body);
    if (depth >= max_depth)
    {
        p.type = "text";
        p.subtype = "plain";
        return;
    }
    if (p.message())
    {
        part inner;
        parse_into(inner, msg, p.body_off, p.body_len, depth + 1, false);
        p.children.push_back(std::move(inner));
        return;
    }
    if (!p.multipart())
        return;
    std::string boundary;
    for (const auto& [k, v] : p.params)
        if (k == "boundary")
            boundary = v;
    if (boundary.empty())
        return;
    const std::string dash = "--" + boundary;
    // Each delimiter is at a line's start; a part runs from the line after one to the CRLF before the next.
    std::vector<std::pair<size_t, size_t>> starts;
    size_t at = 0;
    bool closed = false;
    while (at <= body.size() && !closed)
    {
        const size_t hit = body.find(dash, at);
        if (hit == std::string_view::npos)
            break;
        const bool line_start = hit == 0 || (hit >= 2 && body.substr(hit - 2, 2) == "\r\n");
        const size_t after = hit + dash.size();
        if (!line_start)
        {
            at = after;
            continue;
        }
        closed = body.substr(after, 2) == "--";
        const size_t eol = body.find("\r\n", after);
        const size_t end_before = hit >= 2 ? hit - 2 : 0;
        if (!starts.empty())
            starts.back().second = end_before;
        if (closed || eol == std::string_view::npos)
            break;
        starts.emplace_back(eol + 2, body.size());
        at = eol + 2;
    }
    for (const auto& [s, e] : starts)
    {
        if (e < s)
            continue;
        part child;
        parse_into(child, msg, p.body_off + s, e - s, depth + 1, p.subtype == "digest");
        p.children.push_back(std::move(child));
    }
}

std::string params_list(const std::vector<std::pair<std::string, std::string>>& params)
{
    if (params.empty())
        return "NIL";
    std::string out = "(";
    for (size_t i = 0; i < params.size(); ++i)
    {
        if (i)
            out += ' ';
        out += imap_string(upper(params[i].first), false) + " " + imap_string(params[i].second, false);
    }
    return out + ")";
}

std::string extension(const part& p)
{
    std::string out = " ";
    out += p.disposition.empty() ? std::string("NIL")
                                 : "(" + imap_string(upper(p.disposition), false) + " " +
                                       params_list(p.disposition_params) + ")";
    out += " " + imap_string(p.language) + " " + imap_string(p.location);
    return out;
}

// One address of a header's list, as ENVELOPE writes it: (name NIL mailbox host).
std::string address_struct(std::string_view name, std::string_view addr)
{
    const size_t at = addr.rfind('@');
    const std::string_view mailbox = at == std::string_view::npos ? addr : addr.substr(0, at);
    const std::string_view host = at == std::string_view::npos ? std::string_view{} : addr.substr(at + 1);
    return "(" + imap_string(name) + " NIL " + imap_string(mailbox) + " " + imap_string(host) + ")";
}

// An address list, groups among it: ((...)(...)), NIL for none.
std::string address_list(std::string_view v)
{
    std::string out;
    size_t i = 0;
    bool in_group = false;
    while (i < v.size())
    {
        std::string name, addr, words;
        bool angle = false;
        // A group's end writes the group's last member and its close itself.
        bool group_closed = false;
        for (; i < v.size(); ++i)
        {
            const char c = v[i];
            if (c == '"')
            {
                for (++i; i < v.size() && v[i] != '"'; ++i)
                {
                    if (v[i] == '\\' && i + 1 < v.size())
                        ++i;
                    words += v[i];
                }
                continue;
            }
            if (c == '(')
            {
                for (int depth = 1; ++i < v.size() && depth > 0;)
                    depth += v[i] == '(' ? 1 : v[i] == ')' ? -1 : 0;
                --i;
                continue;
            }
            if (c == '<')
            {
                angle = true;
                name = std::string(trim(words));
                const size_t close = v.find('>', i);
                addr = std::string(trim(v.substr(i + 1, close == std::string_view::npos ? std::string_view::npos
                                                                                        : close - i - 1)));
                i = close == std::string_view::npos ? v.size() : close;
                continue;
            }
            if (c == ':' && !angle && !in_group)
            {
                out += "(NIL NIL " + imap_string(trim(words)) + " NIL)";
                in_group = true;
                words.clear();
                ++i;
                break;
            }
            if (c == ',' || c == ';')
            {
                if (c == ';' && in_group)
                {
                    if (!angle && !trim(words).empty())
                        out += address_struct({}, trim(words));
                    else if (angle)
                        out += address_struct(name, addr);
                    out += "(NIL NIL NIL NIL)";
                    in_group = false;
                    group_closed = true;
                    ++i;
                    break;
                }
                ++i;
                break;
            }
            words += c;
        }
        if (group_closed)
            continue;
        if (angle)
            out += address_struct(name, addr);
        else if (const std::string_view w = trim(words); !w.empty() && w.find('@') != std::string_view::npos)
            out += address_struct({}, w);
    }
    if (in_group)
        out += "(NIL NIL NIL NIL)";
    return out.empty() ? std::string("NIL") : "(" + out + ")";
}

}   // namespace

std::string imap_string(std::string_view s, bool nil_if_empty)
{
    if (s.empty() && nil_if_empty)
        return "NIL";
    bool literal = false;
    for (const unsigned char c : s)
        if (c == '\r' || c == '\n' || c >= 0x80 || c == 0)
            literal = true;
    if (literal)
        return "{" + std::to_string(s.size()) + "}\r\n" + std::string(s);
    std::string out = "\"";
    for (const char c : s)
    {
        if (c == '"' || c == '\\')
            out += '\\';
        out += c;
    }
    return out + "\"";
}

part parse(std::string_view message)
{
    part root;
    parse_into(root, message, 0, message.size(), 0, false);
    return root;
}

std::string envelope(std::string_view headers)
{
    const auto h = [&](std::string_view name) { return header_value(headers, name); };
    const std::string from = h("From");
    const std::string sender = h("Sender").empty() ? from : h("Sender");
    const std::string reply = h("Reply-To").empty() ? from : h("Reply-To");
    return "(" + imap_string(h("Date")) + " " + imap_string(h("Subject")) + " " + address_list(from) + " " +
           address_list(sender) + " " + address_list(reply) + " " + address_list(h("To")) + " " +
           address_list(h("Cc")) + " " + address_list(h("Bcc")) + " " + imap_string(h("In-Reply-To")) + " " +
           imap_string(h("Message-ID")) + ")";
}

std::string structure(const part& p, std::string_view message, bool extended)
{
    if (p.multipart() && !p.children.empty())
    {
        std::string out = "(";
        for (const auto& c : p.children)
            out += structure(c, message, extended);
        out += " " + imap_string(upper(p.subtype), false);
        if (extended)
            out += " " + params_list(p.params) + extension(p);
        return out + ")";
    }
    const std::string type = p.multipart() ? "TEXT" : upper(p.type);
    const std::string subtype = p.multipart() ? "PLAIN" : upper(p.subtype);
    std::string out = "(" + imap_string(type, false) + " " + imap_string(subtype, false) + " " + params_list(p.params) +
                      " " + imap_string(p.id) + " " + imap_string(p.description) + " " +
                      imap_string(p.encoding, false) + " " + std::to_string(p.body_len);
    if (p.message() && !p.children.empty())
    {
        const part& inner = p.children.front();
        out += " " + envelope(message.substr(inner.header_off, inner.header_len)) + " " +
               structure(inner, message, extended) + " " + std::to_string(p.lines);
    }
    else if (p.type == "text" || p.multipart())
        out += " " + std::to_string(p.lines);
    if (extended)
        out += " " + imap_string(p.md5) + extension(p);
    return out + ")";
}

bool section(std::string_view message, const part& root, std::string_view spec, std::string& out)
{
    out.clear();
    // The part numbers first, then what of the part is asked.
    const part* node = &root;
    bool numbered = false;
    while (!spec.empty() && std::isdigit(static_cast<unsigned char>(spec.front())))
    {
        size_t k = 0;
        while (!spec.empty() && std::isdigit(static_cast<unsigned char>(spec.front())))
        {
            k = k * 10 + static_cast<size_t>(spec.front() - '0');
            spec.remove_prefix(1);
        }
        if (!spec.empty() && spec.front() == '.')
            spec.remove_prefix(1);
        if (k == 0)
            return false;
        // A message/rfc822 part's numbers are of the message it encloses.
        const part* within = node;
        if (node->message() && !node->children.empty() && (numbered || node != &root))
            within = &node->children.front();
        if (within->multipart())
        {
            if (k > within->children.size())
                return false;
            node = &within->children[k - 1];
        }
        else if (k == 1)
            node = within;
        else
            return false;
        numbered = true;
    }
    const std::string text = upper(spec);
    // What HEADER and TEXT name: the root message, or the one a numbered message/rfc822 part encloses.
    const part* msg = numbered ? (node->message() && !node->children.empty() ? &node->children.front() : nullptr)
                               : &root;
    if (text.empty())
    {
        if (!numbered)
        {
            out.assign(message);
            return true;
        }
        out.assign(message.substr(node->body_off, node->body_len));
        return true;
    }
    if (text == "MIME")
    {
        if (!numbered)
            return false;
        out.assign(message.substr(node->header_off, node->header_len));
        return true;
    }
    if (!msg)
        return false;
    const std::string_view head = message.substr(msg->header_off, msg->header_len);
    if (text == "HEADER")
    {
        out.assign(head);
        return true;
    }
    if (text == "TEXT")
    {
        out.assign(message.substr(msg->body_off, msg->body_len));
        return true;
    }
    const bool fields = text.starts_with("HEADER.FIELDS ") || text.starts_with("HEADER.FIELDS(");
    const bool not_fields = text.starts_with("HEADER.FIELDS.NOT");
    if (!fields && !not_fields)
        return false;
    const size_t open = text.find('('), close = text.rfind(')');
    if (open == std::string::npos || close == std::string::npos || close < open)
        return false;
    std::vector<std::string> names;
    std::string_view list = std::string_view(text).substr(open + 1, close - open - 1);
    while (!list.empty())
    {
        list = trim(list);
        const size_t sp = list.find(' ');
        std::string n(list.substr(0, sp));
        if (!n.empty() && n.front() == '"' && n.back() == '"' && n.size() >= 2)
            n = n.substr(1, n.size() - 2);
        if (!n.empty())
            names.push_back(n);
        list = sp == std::string_view::npos ? std::string_view{} : list.substr(sp + 1);
    }
    for (const auto& [name, value] : split_headers(head))
    {
        const bool listed = std::find(names.begin(), names.end(), upper(trim(name))) != names.end();
        if (listed == fields)
            out.append(name.data(), name.size()).append(":").append(value.data(), value.size()).append("\r\n");
    }
    out += "\r\n";
    return true;
}

}   // namespace socketley::mail::mime
