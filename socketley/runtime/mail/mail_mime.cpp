#include "mail_mime.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <unordered_map>

#include <iconv.h>

#include "mail_compose.h"
#include "../../shared/util/ascii.h"
#include "../../shared/util/base64.h"

namespace socketley::mail::mime
{

namespace
{

constexpr int max_depth = 32;
// The parts one message is read into at most, the rest of a multipart past them left unsplit, as a server does to
// keep a message of millions of empty parts from becoming a gigabyte of them.
constexpr size_t max_parts = 10000;

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

// RFC 2231's continuations of one parameter, name*0, name*1 and on, joined in order; where any is encoded the whole
// is kept as name* in charset'language'%XX form, so what BODYSTRUCTURE writes stays seven bits and param() reads it.
void joined_2231(std::vector<std::pair<std::string, std::string>>& params)
{
    if (std::none_of(params.begin(), params.end(), [](const auto& p) { return p.first.find('*') != std::string::npos; }))
        return;
    struct segment
    {
        size_t index;
        std::string value;
        bool encoded;
    };
    std::vector<std::pair<std::string, std::vector<segment>>> groups;
    std::vector<std::pair<std::string, std::string>> out;
    const auto group = [&](const std::string& base) -> std::vector<segment>& {
        for (auto& g : groups)
            if (g.first == base)
                return g.second;
        out.emplace_back(base, std::string());
        return groups.emplace_back(base, std::vector<segment>{}).second;
    };
    for (auto& [name, value] : params)
    {
        const size_t star = name.find('*');
        if (star == std::string::npos)
        {
            out.emplace_back(name, std::move(value));
            continue;
        }
        const std::string base = name.substr(0, star);
        std::string_view rest = std::string_view(name).substr(star + 1);
        size_t index = 0;
        bool encoded = rest.empty();
        if (!rest.empty())
        {
            size_t n = 0;
            while (n < rest.size() && std::isdigit(static_cast<unsigned char>(rest[n])) && n < 4)
                index = index * 10 + static_cast<size_t>(rest[n++] - '0');
            if (n == 0 || (n < rest.size() && rest.substr(n) != "*"))
                continue;
            encoded = n < rest.size();
        }
        group(base).push_back({index, std::move(value), encoded});
    }
    static constexpr char hex[] = "0123456789ABCDEF";
    for (auto& [base, segs] : groups)
    {
        std::stable_sort(segs.begin(), segs.end(), [](const segment& a, const segment& b) { return a.index < b.index; });
        const bool encoded = std::any_of(segs.begin(), segs.end(), [](const segment& s) { return s.encoded; });
        std::string value;
        // The first segment of an encoded value carries its charset'language' (RFC 2231 4.1); an unencoded one has none.
        if (encoded && !segs.front().encoded)
            value = "''";
        for (const auto& s : segs)
        {
            if (!encoded || s.encoded)
            {
                value += s.value;
                continue;
            }
            for (const char c : s.value)
            {
                const auto u = static_cast<unsigned char>(c);
                if (std::isalnum(u) || c == '.' || c == '-' || c == '_')
                    value += c;
                else
                {
                    value += '%';
                    value += hex[u >> 4];
                    value += hex[u & 15];
                }
            }
        }
        // A plain value under the same name gives way to the continued one, as RFC 2231 3 has it.
        std::erase_if(out, [&](const auto& p) { return p.first == base && !p.second.empty(); });
        for (auto& p : out)
            if (p.first == base && p.second.empty())
            {
                p.first = encoded ? base + "*" : base;
                p.second = std::move(value);
                break;
            }
    }
    params = std::move(out);
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
    joined_2231(params);
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

void parse_into(part& p, std::string_view msg, size_t off, size_t len, int depth, bool digest, size_t& parts)
{
    ++parts;
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
        parse_into(inner, msg, p.body_off, p.body_len, depth + 1, false, parts);
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
        // A delimiter is the boundary, perhaps "--", and nothing but white space to the line's end (RFC 2046 5.1.1).
        const bool closing = body.substr(after, 2) == "--";
        size_t tail = after + (closing ? 2 : 0);
        while (tail < body.size() && (body[tail] == ' ' || body[tail] == '\t'))
            ++tail;
        if (tail < body.size() && body.substr(tail, 2) != "\r\n")
        {
            at = after;
            continue;
        }
        closed = closing;
        const size_t eol = tail < body.size() ? tail : std::string_view::npos;
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
        if (parts >= max_parts)
            break;
        part child;
        parse_into(child, msg, p.body_off + s, e - s, depth + 1, p.subtype == "digest", parts);
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
    size_t parts = 0;
    parse_into(root, message, 0, message.size(), 0, false, parts);
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

bool section_of(std::string_view message, const part& root, std::string_view spec, std::string_view& got,
                std::string& built)
{
    got = {};
    built.clear();
    // The part numbers first, then what of the part is asked.
    const part* node = &root;
    bool numbered = false;
    while (!spec.empty() && std::isdigit(static_cast<unsigned char>(spec.front())))
    {
        size_t k = 0;
        while (!spec.empty() && std::isdigit(static_cast<unsigned char>(spec.front())))
        {
            // A number past any part there could be is none, rather than one that wrapped round to a small one.
            if (k > max_parts)
                return false;
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
            got = message;
            return true;
        }
        got = message.substr(node->body_off, node->body_len);
        return true;
    }
    if (text == "MIME")
    {
        if (!numbered)
            return false;
        got = message.substr(node->header_off, node->header_len);
        return true;
    }
    if (!msg)
        return false;
    const std::string_view head = message.substr(msg->header_off, msg->header_len);
    if (text == "HEADER")
    {
        got = head;
        return true;
    }
    if (text == "TEXT")
    {
        got = message.substr(msg->body_off, msg->body_len);
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
        const std::string_view n = trim(name);
        const bool listed = std::any_of(names.begin(), names.end(),
                                        [n](const std::string& w) { return socketley::ascii::iequals(n, w); });
        if (listed == fields)
            built.append(name.data(), name.size()).append(":").append(value.data(), value.size()).append("\r\n");
    }
    built += "\r\n";
    got = built;
    return true;
}

bool section(std::string_view message, const part& root, std::string_view spec, std::string& out)
{
    std::string_view got;
    std::string built;
    const bool ok = section_of(message, root, spec, got, built);
    if (got.data() == built.data())
        out = std::move(built);
    else
        out.assign(got);
    return ok;
}

namespace
{

int hex_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

std::string unquote_printable(std::string_view in, bool underscore_space)
{
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i)
    {
        const char c = in[i];
        if (c == '_' && underscore_space)
        {
            out += ' ';
            continue;
        }
        if (c != '=')
        {
            out += c;
            continue;
        }
        if (i + 2 < in.size() && hex_value(in[i + 1]) >= 0 && hex_value(in[i + 2]) >= 0)
        {
            out += static_cast<char>(hex_value(in[i + 1]) * 16 + hex_value(in[i + 2]));
            i += 2;
            continue;
        }
        // A soft line break, the white space an encoder may leave before it included.
        size_t j = i + 1;
        while (j < in.size() && (in[j] == ' ' || in[j] == '\t'))
            ++j;
        if (j + 1 < in.size() && in[j] == '\r' && in[j + 1] == '\n')
        {
            i = j + 1;
            continue;
        }
        if (j < in.size() && in[j] == '\n')
        {
            i = j;
            continue;
        }
        if (j == in.size())
            break;
        out += c;
    }
    return out;
}

// Base64 with the line breaks and other bytes outside its alphabet taken out first, as a body carries it.
bool unbase64(std::string_view in, std::string& out)
{
    std::string digits;
    digits.reserve(in.size());
    for (const char c : in)
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' ||
            c == '=')
            digits += c;
    return socketley::base64::decode(digits, out);
}

enum class charset_kind : uint8_t { utf8, latin1, other };

charset_kind charset_of(std::string_view name)
{
    // RFC 2231 lets a language follow the charset after a star.
    name = trim(name.substr(0, name.find('*')));
    const std::string n = lower(name);
    if (n.empty() || n == "utf-8" || n == "utf8" || n == "us-ascii" || n == "ascii")
        return charset_kind::utf8;
    if (n == "iso-8859-1" || n == "iso8859-1" || n == "iso_8859-1" || n == "latin1" || n == "l1")
        return charset_kind::latin1;
    return charset_kind::other;
}

std::string latin1_to_utf8(std::string_view in)
{
    std::string out;
    out.reserve(in.size() + in.size() / 8);
    for (const unsigned char c : in)
    {
        if (c < 0x80)
            out += static_cast<char>(c);
        else
        {
            out += static_cast<char>(0xC0 | (c >> 6));
            out += static_cast<char>(0x80 | (c & 0x3F));
        }
    }
    return out;
}

// `in` of `charset` as UTF-8 by iconv, a byte it cannot take as U+FFFD; false where it knows no such charset.
bool iconv_utf8(std::string_view charset, std::string_view in, std::string& out)
{
    // A descriptor a charset a thread, kept for the thread's life: opening one reads a module, and few are ever asked.
    struct held
    {
        std::unordered_map<std::string, iconv_t> open;
        ~held()
        {
            for (auto& [n, cd] : open)
                if (cd != reinterpret_cast<iconv_t>(-1))
                    ::iconv_close(cd);
        }
    };
    thread_local held h;
    const std::string name = lower(trim(charset.substr(0, charset.find('*'))));
    if (name.empty() || name.size() > 40 || !std::all_of(name.begin(), name.end(), [](char c) {
            return std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == ':';
        }))
        return false;
    auto it = h.open.find(name);
    if (it == h.open.end())
    {
        if (h.open.size() >= 64)
            return false;
        it = h.open.emplace(name, ::iconv_open("UTF-8", name.c_str())).first;
    }
    iconv_t cd = it->second;
    if (cd == reinterpret_cast<iconv_t>(-1))
        return false;
    if (::iconv(cd, nullptr, nullptr, nullptr, nullptr) == static_cast<size_t>(-1)) {}
    out.assign(in.size() * 4 + 16, '\0');
    char* ip = const_cast<char*>(in.data());
    size_t il = in.size();
    char* op = out.data();
    size_t ol = out.size();
    while (il > 0)
    {
        if (::iconv(cd, &ip, &il, &op, &ol) != static_cast<size_t>(-1))
            break;
        if (errno == E2BIG)
        {
            const size_t done = static_cast<size_t>(op - out.data());
            out.resize(out.size() * 2);
            op = out.data() + done;
            ol = out.size() - done;
            continue;
        }
        // A byte not of the charset, or one cut off at the end: U+FFFD for it, and on past it.
        if (ol < 3)
        {
            const size_t done = static_cast<size_t>(op - out.data());
            out.resize(out.size() + 16);
            op = out.data() + done;
            ol = out.size() - done;
        }
        *op++ = '\xEF';
        *op++ = '\xBF';
        *op++ = '\xBD';
        ol -= 3;
        ++ip;
        --il;
        if (::iconv(cd, nullptr, nullptr, nullptr, nullptr) == static_cast<size_t>(-1)) {}
    }
    if (::iconv(cd, nullptr, nullptr, &op, &ol) == static_cast<size_t>(-1)) {}
    out.resize(static_cast<size_t>(op - out.data()));
    return true;
}

// Where the next "?=" and the next white space lie, each found once for a run of searches from rising places, so a
// value of a million "=?" is read in time linear in it.
struct word_scan
{
    std::string_view v;
    size_t close_from{std::string_view::npos}, close_at{std::string_view::npos};
    size_t space_from{std::string_view::npos}, space_at{std::string_view::npos};

    size_t next_close(size_t p)
    {
        if (close_from == std::string_view::npos || p < close_from || (close_at != std::string_view::npos && p > close_at))
        {
            close_from = p;
            close_at = v.find("?=", p);
        }
        return close_at;
    }
    size_t next_space(size_t p)
    {
        if (space_from == std::string_view::npos || p < space_from || (space_at != std::string_view::npos && p > space_at))
        {
            space_from = p;
            space_at = v.find_first_of(" \t\r\n", p);
        }
        return space_at;
    }
};

// The encoded word at `i`, decoded into `out`; its length, or 0 when it is none or of a charset no decoder knows.
size_t encoded_word(word_scan& sc, size_t i, std::string& out)
{
    const std::string_view in = sc.v.substr(i);
    if (!in.starts_with("=?"))
        return 0;
    // A charset is a few dozen bytes at most, looked for no further.
    const size_t q1 = in.substr(0, 80).find('?', 2);
    if (q1 == std::string_view::npos || q1 + 2 >= in.size() || in[q1 + 2] != '?')
        return 0;
    const size_t close = sc.next_close(i + q1 + 3);
    // A word holds no white space, so one whose end lies past the next is none.
    if (close == std::string_view::npos || sc.next_space(i + 2) < close)
        return 0;
    const size_t end = close - i;
    const std::string_view charset = in.substr(2, q1 - 2);
    const char enc = socketley::ascii::upper(in[q1 + 1]);
    const std::string_view text = in.substr(q1 + 3, end - q1 - 3);
    if (charset.empty())
        return 0;
    std::string raw;
    if (enc == 'B')
    {
        if (!socketley::base64::decode(text, raw))
            return 0;
    }
    else if (enc == 'Q')
        raw = unquote_printable(text, true);
    else
        return 0;
    const charset_kind kind = charset_of(charset);
    if (kind == charset_kind::other)
    {
        if (!iconv_utf8(charset, raw, out))
            return 0;
    }
    else
        out = kind == charset_kind::latin1 ? latin1_to_utf8(raw) : std::move(raw);
    return end + 2;
}

}   // namespace

std::string decoded_body(std::string_view body, std::string_view encoding)
{
    const std::string e = lower(trim(encoding));
    if (e == "quoted-printable")
        return unquote_printable(body, false);
    if (e == "base64")
    {
        std::string out;
        if (unbase64(body, out))
            return out;
    }
    return std::string(body);
}

std::string param(const std::vector<std::pair<std::string, std::string>>& params, std::string_view name)
{
    for (const auto& [k, v] : params)
    {
        if (k == name)
            return v;
        if (k.size() == name.size() + 1 && k.back() == '*' && std::string_view(k).substr(0, name.size()) == name)
        {
            // charset'language'%XX (RFC 2231 4).
            const size_t a = v.find('\''), b = a == std::string::npos ? a : v.find('\'', a + 1);
            if (b == std::string::npos)
                return v;
            std::string raw;
            for (size_t i = b + 1; i < v.size(); ++i)
            {
                const auto hex = [](char c) {
                    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10
                         : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
                };
                if (v[i] == '%' && i + 2 < v.size() && hex(v[i + 1]) >= 0 && hex(v[i + 2]) >= 0)
                {
                    raw += static_cast<char>(hex(v[i + 1]) * 16 + hex(v[i + 2]));
                    i += 2;
                }
                else
                    raw += v[i];
            }
            return to_utf8(raw, std::string_view(v).substr(0, a));
        }
    }
    return {};
}

std::string to_utf8(std::string_view text, std::string_view charset)
{
    const charset_kind kind = charset_of(charset);
    if (kind == charset_kind::latin1)
        return latin1_to_utf8(text);
    std::string out;
    if (kind == charset_kind::other && iconv_utf8(charset, text, out))
        return out;
    return std::string(text);
}

std::string decode_words(std::string_view value)
{
    std::string out;
    out.reserve(value.size());
    // Where the white space after the last decoded word began, while nothing else has followed it.
    size_t after_word = std::string::npos;
    word_scan sc{value};
    for (size_t i = 0; i < value.size();)
    {
        if (value[i] == '=' && i + 1 < value.size() && value[i + 1] == '?')
        {
            std::string word;
            if (const size_t n = encoded_word(sc, i, word); n > 0)
            {
                if (after_word != std::string::npos)
                    out.resize(after_word);
                out += word;
                after_word = out.size();
                i += n;
                continue;
            }
        }
        const char c = value[i++];
        out += c;
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
            after_word = std::string::npos;
    }
    return out;
}

namespace
{

bool date_digit(char c) { return c >= '0' && c <= '9'; }

bool date_number(std::string_view s, int& out, size_t max_digits)
{
    if (s.empty() || s.size() > max_digits)
        return false;
    out = 0;
    for (const char c : s)
    {
        if (!date_digit(c))
            return false;
        out = out * 10 + (c - '0');
    }
    return true;
}

int64_t date_days(int64_t y, unsigned m, unsigned d)
{
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const auto yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

std::string_view trim_date(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
        s.remove_prefix(1);
    return s;
}

}   // namespace

// An RFC 5322 date, the obsolete forms among it, as unix time and the zone it was written in.
bool parse_date(std::string_view v, int64_t& t, int& zone)
{
    std::string clean;
    int depth = 0;
    for (const char c : v)
    {
        if (c == '(')
            ++depth;
        else if (c == ')' && depth > 0)
            --depth;
        else if (depth == 0)
            clean += c == ',' ? ' ' : c;
    }
    std::vector<std::string_view> w;
    std::string_view rest = clean;
    while (!rest.empty())
    {
        rest = trim_date(rest);
        if (rest.empty())
            break;
        size_t n = 0;
        while (n < rest.size() && rest[n] != ' ' && rest[n] != '\t')
            ++n;
        w.push_back(rest.substr(0, n));
        rest.remove_prefix(n);
    }
    size_t k = 0;
    if (k < w.size() && !w[k].empty() && std::isalpha(static_cast<unsigned char>(w[k][0])))
        ++k;
    if (w.size() < k + 4)
        return false;
    int day = 0, year = 0, hour = 0, minute = 0, second = 0;
    if (!date_number(w[k], day, 2) || day < 1 || day > 31)
        return false;
    static constexpr std::string_view months[] = {"jan", "feb", "mar", "apr", "may", "jun",
                                                  "jul", "aug", "sep", "oct", "nov", "dec"};
    unsigned month = 0;
    for (unsigned mi = 0; mi < 12; ++mi)
        if (socketley::ascii::iequals(w[k + 1], months[mi]))
            month = mi + 1;
    if (!month || !date_number(w[k + 2], year, 4))
        return false;
    if (w[k + 2].size() == 2)
        year += year < 50 ? 2000 : 1900;
    else if (w[k + 2].size() == 3)
        year += 1900;
    const std::string_view time = w[k + 3];
    const size_t c1 = time.find(':');
    const size_t c2 = c1 == std::string_view::npos ? c1 : time.find(':', c1 + 1);
    if (c1 == std::string_view::npos || !date_number(time.substr(0, c1), hour, 2) ||
        !date_number(time.substr(c1 + 1, c2 == std::string_view::npos ? std::string_view::npos : c2 - c1 - 1),
                      minute, 2) ||
        (c2 != std::string_view::npos && !date_number(time.substr(c2 + 1), second, 2)))
        return false;
    if (hour > 23 || minute > 59 || second > 60)
        return false;
    zone = 0;
    if (w.size() > k + 4)
    {
        const std::string_view z = w[k + 4];
        if ((z[0] == '+' || z[0] == '-') && z.size() == 5)
        {
            int hh = 0, mm = 0;
            if (!date_number(z.substr(1, 2), hh, 2) || !date_number(z.substr(3, 2), mm, 2) || mm > 59)
                return false;
            zone = (z[0] == '-' ? -1 : 1) * (hh * 60 + mm);
        }
        else
        {
            static constexpr std::pair<std::string_view, int> names[] = {
                {"ut", 0},          {"gmt", 0},         {"z", 0},           {"est", -5 * 60}, {"edt", -4 * 60},
                {"cst", -6 * 60},   {"cdt", -5 * 60},   {"mst", -7 * 60},   {"mdt", -6 * 60}, {"pst", -8 * 60},
                {"pdt", -7 * 60}};
            for (const auto& [name, off] : names)
                if (socketley::ascii::iequals(z, name))
                    zone = off;
        }
    }
    t = date_days(year, month, static_cast<unsigned>(day)) * 86400 + hour * 3600 + minute * 60 + second -
        static_cast<int64_t>(zone) * 60;
    return true;
}


}   // namespace socketley::mail::mime
