#include "dns_zone.h"
#include "dns_wire.h"
#include "../../shared/util/ascii.h"
#include "../../shared/util/duration_parse.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <cstring>

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace socketley::dns
{

namespace
{

// ─── Tokens ─────────────────────────────────────────────────────────────────

struct token
{
    std::string text;
    bool quoted{false};
};

// One record's worth of a file: its tokens, whether its line began with blank space (the owner left out, so the last
// one stands), and the line it began on, for the message.
struct entry
{
    std::vector<token> tokens;
    bool continues_owner{false};
    size_t line{0};
};

bool fail(std::string& why, size_t line, const std::string& what)
{
    why = "line " + std::to_string(line) + ": " + what;
    return false;
}

// The file as entries: comments dropped, parentheses joining lines, quoted strings kept whole with their escapes
// resolved, an unquoted token's escapes left as they were for the name or number it is.
bool tokenize(std::string_view text, std::vector<entry>& out, std::string& why)
{
    size_t i = 0, line = 1;
    int depth = 0;
    entry cur;
    bool at_line_start = true;
    const auto finish = [&]()
    {
        if (!cur.tokens.empty())
            out.push_back(std::move(cur));
        cur = entry{};
    };
    while (i < text.size())
    {
        const char c = text[i];
        if (c == '\n')
        {
            ++line;
            ++i;
            if (depth == 0)
            {
                finish();
                at_line_start = true;
            }
            continue;
        }
        if (at_line_start && depth == 0)
        {
            cur.line = line;
            cur.continues_owner = c == ' ' || c == '\t';
            at_line_start = false;
        }
        if (c == ' ' || c == '\t' || c == '\r')
        {
            ++i;
            continue;
        }
        if (c == ';')
        {
            while (i < text.size() && text[i] != '\n')
                ++i;
            continue;
        }
        if (c == '(')
        {
            ++depth;
            ++i;
            continue;
        }
        if (c == ')')
        {
            if (--depth < 0)
                return fail(why, line, "a ')' without its '('");
            ++i;
            continue;
        }
        token t;
        if (c == '"')
        {
            t.quoted = true;
            ++i;
            for (;;)
            {
                if (i >= text.size())
                    return fail(why, line, "a quoted string that does not end");
                const char q = text[i];
                if (q == '"')
                {
                    ++i;
                    break;
                }
                if (q == '\n')
                    ++line;
                if (q == '\\' && i + 1 < text.size())
                {
                    if (i + 3 < text.size() && std::isdigit(static_cast<unsigned char>(text[i + 1])) &&
                        std::isdigit(static_cast<unsigned char>(text[i + 2])) &&
                        std::isdigit(static_cast<unsigned char>(text[i + 3])))
                    {
                        const int v = (text[i + 1] - '0') * 100 + (text[i + 2] - '0') * 10 + (text[i + 3] - '0');
                        if (v > 255)
                            return fail(why, line, "an escape above \\255");
                        t.text += static_cast<char>(v);
                        i += 4;
                    }
                    else
                    {
                        t.text += text[i + 1];
                        i += 2;
                    }
                    continue;
                }
                t.text += q;
                ++i;
            }
        }
        else
        {
            while (i < text.size())
            {
                const char q = text[i];
                if (q == ' ' || q == '\t' || q == '\r' || q == '\n' || q == ';' || q == '(' || q == ')' || q == '"')
                    break;
                if (q == '\\' && i + 1 < text.size() && text[i + 1] != '\n')
                {
                    t.text += q;
                    t.text += text[i + 1];
                    i += 2;
                    continue;
                }
                t.text += q;
                ++i;
            }
        }
        cur.tokens.push_back(std::move(t));
    }
    if (depth != 0)
        return fail(why, line, "a '(' that is never closed");
    finish();
    return true;
}

// An unquoted token's escapes resolved, for the text of a TXT record written without quotes.
std::string unescape(std::string_view s)
{
    std::string out;
    for (size_t i = 0; i < s.size(); ++i)
    {
        if (s[i] == '\\' && i + 1 < s.size())
        {
            if (i + 3 < s.size() && std::isdigit(static_cast<unsigned char>(s[i + 1])) &&
                std::isdigit(static_cast<unsigned char>(s[i + 2])) && std::isdigit(static_cast<unsigned char>(s[i + 3])))
            {
                out += static_cast<char>((s[i + 1] - '0') * 100 + (s[i + 2] - '0') * 10 + (s[i + 3] - '0'));
                i += 3;
            }
            else
                out += s[++i];
            continue;
        }
        out += s[i];
    }
    return out;
}

// ─── Numbers ────────────────────────────────────────────────────────────────

template <typename T>
bool parse_uint(std::string_view s, T& out)
{
    if (s.empty())
        return false;
    uint64_t v = 0;
    const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || end != s.data() + s.size() || v > static_cast<uint64_t>(T(~T(0))))
        return false;
    out = static_cast<T>(v);
    return true;
}

// A TTL, in seconds or as 1h30m and the like; at most 2^31-1 (RFC 2181 section 8).
bool parse_ttl(std::string_view s, uint32_t& out)
{
    if (s.empty() || !std::isdigit(static_cast<unsigned char>(s[0])))
        return false;
    uint64_t total = 0, num = 0;
    bool digits = false, unit = false;
    for (char c : s)
    {
        if (c >= '0' && c <= '9')
        {
            num = num * 10 + static_cast<uint64_t>(c - '0');
            if (num > 0x7FFFFFFF)
                return false;
            digits = true;
            continue;
        }
        if (!digits)
            return false;
        // BIND takes the units in either case, as a zone file is written.
        const uint64_t mul = duration_unit_seconds(static_cast<char>(lower(static_cast<uint8_t>(c))));
        if (mul == 0)
            return false;
        total += num * mul;
        num = 0;
        digits = false;
        unit = true;
        if (total > 0x7FFFFFFF)
            return false;
    }
    if (digits)
    {
        if (unit)
            return false;   // "1h30" says no unit for the 30; refused rather than guessed.
        total += num;
    }
    if (total > 0x7FFFFFFF)
        return false;
    out = static_cast<uint32_t>(total);
    return true;
}

// ─── Types ──────────────────────────────────────────────────────────────────

struct type_name { const char* name; uint16_t code; };
constexpr type_name known_types[] = {
    {"A", type::A}, {"NS", type::NS}, {"CNAME", type::CNAME}, {"SOA", type::SOA}, {"PTR", type::PTR},
    {"HINFO", type::HINFO}, {"MX", type::MX}, {"TXT", type::TXT}, {"AAAA", type::AAAA}, {"SRV", type::SRV},
    {"CAA", type::CAA}, {"DS", type::DS}, {"TLSA", type::TLSA},
};

bool parse_type(std::string_view s, uint16_t& out)
{
    for (const auto& t : known_types)
        if (ascii::iequals(s, t.name))
        {
            out = t.code;
            return true;
        }
    if (s.size() > 4 && ascii::iequals(s.substr(0, 4), "TYPE"))
        return parse_uint(s.substr(4), out) && out != 0;
    return false;
}

bool is_class(std::string_view s) { return ascii::iequals(s, "IN") || ascii::iequals(s, "CH") || ascii::iequals(s, "HS") || ascii::iequals(s, "CS"); }

void put16(std::string& o, uint16_t v) { o += static_cast<char>(v >> 8); o += static_cast<char>(v & 0xFF); }
void put32(std::string& o, uint32_t v) { put16(o, static_cast<uint16_t>(v >> 16)); put16(o, static_cast<uint16_t>(v)); }

// A character-string (RFC 1035 3.3): a length byte and at most 255 bytes; a longer text becomes several, which is how
// a TXT record holds a DKIM key.
void put_strings(std::string& o, std::string_view s)
{
    if (s.empty())
    {
        o += '\0';
        return;
    }
    for (size_t i = 0; i < s.size(); i += 255)
    {
        const size_t n = std::min<size_t>(255, s.size() - i);
        o += static_cast<char>(n);
        o.append(s.data() + i, n);
    }
}

std::string text_of(const token& t) { return t.quoted ? t.text : unescape(t.text); }

// Where the uncompressed name starting at `off` ends, or npos when it runs past `rd`, is longer than 255 bytes, or
// holds a pointer, which a zone's data never may.
size_t wire_name_end(std::string_view rd, size_t off)
{
    const size_t from = off;
    while (off < rd.size())
    {
        const auto len = static_cast<uint8_t>(rd[off]);
        if (len == 0)
            return off + 1 - from > 255 ? std::string_view::npos : off + 1;
        if (len >= 0x40 || off + 1 + len > rd.size())
            return std::string_view::npos;
        off += 1 + len;
    }
    return std::string_view::npos;
}

// Whether data given as \# has the shape its type is read with, since the answer reads a known type's fields
// where they belong and a short one would be read past its end.
bool rdata_fits(uint16_t t, std::string_view rd)
{
    switch (t)
    {
        case type::A:     return rd.size() == 4;
        case type::AAAA:  return rd.size() == 16;
        case type::NS:
        case type::CNAME:
        case type::PTR:   return wire_name_end(rd, 0) == rd.size();
        case type::MX:    return rd.size() >= 3 && wire_name_end(rd, 2) == rd.size();
        case type::SRV:   return rd.size() >= 7 && wire_name_end(rd, 6) == rd.size();
        case type::TLSA:  return rd.size() >= 4;
        case type::SOA:
        {
            const size_t m = wire_name_end(rd, 0);
            const size_t r = m == std::string_view::npos ? m : wire_name_end(rd, m);
            return r != std::string_view::npos && r + 20 == rd.size();
        }
        case type::TXT:
        {
            if (rd.empty())
                return false;
            for (size_t off = 0; off < rd.size(); off += 1 + static_cast<uint8_t>(rd[off]))
                if (off + 1 + static_cast<uint8_t>(rd[off]) > rd.size())
                    return false;
            return true;
        }
        default:          return true;
    }
}

// A record's data in wire form from its tokens; false with the reason.
bool parse_rdata(uint16_t t, const std::vector<token>& tk, size_t from, std::string_view origin, std::string& out,
                 std::string& why)
{
    const size_t n = tk.size() - from;
    const auto arg = [&](size_t k) -> std::string_view { return tk[from + k].text; };
    const auto need = [&](size_t k) -> bool
    {
        if (n != k)
        {
            why = "takes " + std::to_string(k) + (k == 1 ? " value" : " values") + ", not " + std::to_string(n);
            return false;
        }
        return true;
    };
    const auto name = [&](size_t k) -> bool
    {
        std::string w;
        if (!name_from_text(arg(k), origin, w))
        {
            why = "'" + std::string(arg(k)) + "' is not a name";
            return false;
        }
        out += w;
        return true;
    };
    const auto u16 = [&](size_t k) -> bool
    {
        uint16_t v = 0;
        if (!parse_uint(arg(k), v))
        {
            why = "'" + std::string(arg(k)) + "' is not a number from 0 to 65535";
            return false;
        }
        put16(out, v);
        return true;
    };

    // RFC 3597's form, for any type: \# then the length, then the data in hex.
    if (n >= 2 && arg(0) == "\\#")
    {
        const size_t start = out.size();
        uint16_t len = 0;
        if (!parse_uint(arg(1), len))
        {
            why = "\\# needs a length";
            return false;
        }
        std::string hex;
        for (size_t k = 2; k < n; ++k)
            hex += arg(k);
        if (hex.size() != static_cast<size_t>(len) * 2)
        {
            why = "\\# says " + std::to_string(len) + " bytes but gives " + std::to_string(hex.size() / 2);
            return false;
        }
        for (size_t k = 0; k < hex.size(); k += 2)
        {
            uint8_t b = 0;
            const auto [e, ec] = std::from_chars(hex.data() + k, hex.data() + k + 2, b, 16);
            if (ec != std::errc{} || e != hex.data() + k + 2)
            {
                why = "\\# data is not hex";
                return false;
            }
            out += static_cast<char>(b);
        }
        if (!rdata_fits(t, std::string_view(out).substr(start)))
        {
            why = "\\# data is not shaped as this type's record is";
            return false;
        }
        return true;
    }

    switch (t)
    {
        case type::A:
        {
            if (!need(1))
                return false;
            in_addr a{};
            if (::inet_pton(AF_INET, std::string(arg(0)).c_str(), &a) != 1)
            {
                why = "'" + std::string(arg(0)) + "' is not an IPv4 address";
                return false;
            }
            out.append(reinterpret_cast<const char*>(&a), 4);
            return true;
        }
        case type::AAAA:
        {
            if (!need(1))
                return false;
            in6_addr a{};
            if (::inet_pton(AF_INET6, std::string(arg(0)).c_str(), &a) != 1)
            {
                why = "'" + std::string(arg(0)) + "' is not an IPv6 address";
                return false;
            }
            out.append(reinterpret_cast<const char*>(&a), 16);
            return true;
        }
        case type::NS:
        case type::CNAME:
        case type::PTR:
            return need(1) && name(0);
        case type::MX:
            return need(2) && u16(0) && name(1);
        case type::SRV:
            return need(4) && u16(0) && u16(1) && u16(2) && name(3);
        case type::SOA:
        {
            if (!need(7) || !name(0) || !name(1))
                return false;
            uint32_t serial = 0;
            if (!parse_uint(arg(2), serial))
            {
                why = "the serial '" + std::string(arg(2)) + "' is not a number below 2^32";
                return false;
            }
            put32(out, serial);
            for (size_t k = 3; k < 7; ++k)
            {
                uint32_t v = 0;
                if (!parse_ttl(arg(k), v))
                {
                    why = "'" + std::string(arg(k)) + "' is not a time";
                    return false;
                }
                put32(out, v);
            }
            return true;
        }
        case type::TXT:
        {
            if (n == 0)
            {
                why = "needs a text";
                return false;
            }
            for (size_t k = 0; k < n; ++k)
                put_strings(out, text_of(tk[from + k]));
            return true;
        }
        case type::HINFO:
        {
            if (!need(2))
                return false;
            for (size_t k = 0; k < 2; ++k)
            {
                const std::string s = text_of(tk[from + k]);
                if (s.size() > 255)
                {
                    why = "a HINFO string is at most 255 bytes";
                    return false;
                }
                out += static_cast<char>(s.size());
                out += s;
            }
            return true;
        }
        case type::CAA:
        {
            if (!need(3))
                return false;
            uint8_t flags = 0;
            if (!parse_uint(arg(0), flags))
            {
                why = "the CAA flags are a number from 0 to 255";
                return false;
            }
            const std::string_view tag = arg(1);
            if (tag.empty() || tag.size() > 255 ||
                !std::all_of(tag.begin(), tag.end(), [](char c) { return std::isalnum(static_cast<unsigned char>(c)); }))
            {
                why = "a CAA tag is letters and digits, such as issue";
                return false;
            }
            out += static_cast<char>(flags);
            out += static_cast<char>(tag.size());
            for (char c : tag)
                out += static_cast<char>(lower(static_cast<uint8_t>(c)));
            out += text_of(tk[from + 2]);
            return true;
        }
        case type::TLSA:
        {
            // usage selector matching-type and the data in hex (RFC 6698 2.2).
            if (n < 4)
            {
                why = "takes a usage, a selector, a matching type and the data in hex";
                return false;
            }
            for (size_t k = 0; k < 3; ++k)
            {
                uint8_t v = 0;
                if (!parse_uint(arg(k), v))
                {
                    why = "'" + std::string(arg(k)) + "' is not a number from 0 to 255";
                    return false;
                }
                out += static_cast<char>(v);
            }
            std::string hex;
            for (size_t k = 3; k < n; ++k)
                hex += arg(k);
            if (hex.empty() || hex.size() % 2)
            {
                why = "the TLSA data is hex, two digits a byte";
                return false;
            }
            for (size_t k = 0; k < hex.size(); k += 2)
            {
                uint8_t b = 0;
                const auto [e, ec] = std::from_chars(hex.data() + k, hex.data() + k + 2, b, 16);
                if (ec != std::errc{} || e != hex.data() + k + 2)
                {
                    why = "the TLSA data is not hex";
                    return false;
                }
                out += static_cast<char>(b);
            }
            return true;
        }
        default:
            why = "this type is written in RFC 3597's form here: \\# <length> <hex>";
            return false;
    }
}

}   // namespace

// ─── Names ──────────────────────────────────────────────────────────────────

bool name_from_text(std::string_view text, std::string_view origin, std::string& out)
{
    out.clear();
    if (text == "@")
    {
        if (origin.empty())
            return false;
        out = origin;
        return true;
    }
    if (text == ".")
    {
        out.assign(1, '\0');
        return true;
    }
    if (text.empty())
        return false;
    std::string label;
    bool absolute = false;
    const auto push = [&]() -> bool
    {
        if (label.empty() || label.size() > max_label)
            return false;
        out += static_cast<char>(label.size());
        out += label;
        label.clear();
        return true;
    };
    for (size_t i = 0; i < text.size(); ++i)
    {
        char c = text[i];
        if (c == '.')
        {
            // An empty label is no label: a name has no ".." and begins with none.
            if (!push())
                return false;
            if (i + 1 == text.size())
                absolute = true;
            continue;
        }
        if (c == '\\')
        {
            if (i + 1 >= text.size())
                return false;
            if (i + 3 < text.size() && std::isdigit(static_cast<unsigned char>(text[i + 1])) &&
                std::isdigit(static_cast<unsigned char>(text[i + 2])) &&
                std::isdigit(static_cast<unsigned char>(text[i + 3])))
            {
                const int v = (text[i + 1] - '0') * 100 + (text[i + 2] - '0') * 10 + (text[i + 3] - '0');
                if (v > 255)
                    return false;
                c = static_cast<char>(v);
                i += 3;
            }
            else
                c = text[++i];
        }
        label += static_cast<char>(lower(static_cast<uint8_t>(c)));
    }
    if (!absolute)
    {
        if (!push() || origin.empty())
            return false;
        out += origin;
    }
    else
        out += '\0';
    return out.size() <= max_name;
}

// ─── The file ───────────────────────────────────────────────────────────────

bool parse_zone(std::string_view text, std::string_view origin_hint, zone& z, std::string& why)
{
    std::vector<entry> entries;
    if (!tokenize(text, entries, why))
        return false;

    std::string origin;
    if (!origin_hint.empty() && !name_from_text(origin_hint, {}, origin))
    {
        why = "'" + std::string(origin_hint) + "' is not a name";
        return false;
    }

    struct rec { std::string owner; uint16_t type; uint32_t ttl; std::string rdata; size_t line; };
    std::vector<rec> recs;
    std::string last_owner;
    uint32_t default_ttl = 0, last_ttl = 0;
    bool have_default = false, have_last = false;

    for (const auto& e : entries)
    {
        const auto& tk = e.tokens;
        if (!e.continues_owner && !tk[0].quoted && !tk[0].text.empty() && tk[0].text[0] == '$')
        {
            const std::string_view d = tk[0].text;
            if (ascii::iequals(d, "$ORIGIN"))
            {
                // Read into a name of its own: a relative one is made from the origin it replaces.
                std::string next;
                if (tk.size() != 2 || !name_from_text(tk[1].text, origin, next))
                    return fail(why, e.line, "$ORIGIN takes one name");
                origin = std::move(next);
                continue;
            }
            if (ascii::iequals(d, "$TTL"))
            {
                if (tk.size() != 2 || !parse_ttl(tk[1].text, default_ttl))
                    return fail(why, e.line, "$TTL takes one time, such as 3600 or 1h");
                have_default = true;
                continue;
            }
            // A file that names another is a way to read any file the worker may, so it is refused, not followed.
            return fail(why, e.line, std::string(d) + " is not supported; only $ORIGIN and $TTL are");
        }

        size_t i = 0;
        std::string owner;
        if (e.continues_owner)
        {
            if (last_owner.empty())
                return fail(why, e.line, "a record without an owner, and none before it");
            owner = last_owner;
        }
        else
        {
            if (!name_from_text(tk[0].text, origin, owner))
                return fail(why, e.line,
                            origin.empty() ? "'" + tk[0].text + "' is relative and no $ORIGIN is set"
                                           : "'" + tk[0].text + "' is not a name");
            i = 1;
        }

        uint32_t ttl = 0;
        bool have_ttl = false;
        for (int k = 0; k < 2 && i < tk.size(); ++k)
        {
            if (is_class(tk[i].text))
            {
                if (!ascii::iequals(tk[i].text, "IN"))
                    return fail(why, e.line, "only class IN is served");
                ++i;
                continue;
            }
            if (!have_ttl && std::isdigit(static_cast<unsigned char>(tk[i].text[0])))
            {
                if (!parse_ttl(tk[i].text, ttl))
                    return fail(why, e.line, "'" + tk[i].text + "' is not a time");
                have_ttl = true;
                ++i;
                continue;
            }
            break;
        }
        if (i >= tk.size())
            return fail(why, e.line, "a record without a type");
        uint16_t t = 0;
        if (!parse_type(tk[i].text, t))
            return fail(why, e.line, "'" + tk[i].text + "' is not a record type this server knows; write it as TYPE<n>");
        if (t == type::OPT || t == type::AXFR || t == type::IXFR || t == type::ANY)
            return fail(why, e.line, "'" + tk[i].text + "' is not a type a zone can hold");
        ++i;
        if (!have_ttl)
        {
            if (have_default)
                ttl = default_ttl;
            else if (have_last)
                ttl = last_ttl;
            else if (t != type::SOA)
                return fail(why, e.line, "a record without a TTL and no $TTL before it");
        }

        rec r{owner, t, ttl, {}, e.line};
        std::string bad;
        if (!parse_rdata(t, tk, i, origin, r.rdata, bad))
            return fail(why, e.line, tk[i - 1].text + " " + bad);
        if (r.rdata.size() > 65535)
            return fail(why, e.line, "the record's data is longer than 65535 bytes");
        // An SOA without a TTL of its own takes its MINIMUM, as BIND does.
        if (t == type::SOA && !have_ttl && !have_default && !have_last)
            r.ttl = rd32(reinterpret_cast<const uint8_t*>(r.rdata.data()) + r.rdata.size() - 4);
        last_owner = owner;
        last_ttl = r.ttl;
        have_last = true;
        recs.push_back(std::move(r));
        if (recs.size() > max_zone_records)
        {
            why = "more than " + std::to_string(max_zone_records) + " records";
            return false;
        }
    }

    // ─── The apex ───────────────────────────────────────────────────────────
    const rec* soa = nullptr;
    for (const auto& r : recs)
        if (r.type == type::SOA)
        {
            if (soa)
                return fail(why, r.line, "a second SOA; a zone has exactly one, at its apex");
            soa = &r;
        }
    if (!soa)
    {
        why = "no SOA record: a zone begins with one, at its apex";
        return false;
    }
    z = zone{};
    z.origin = soa->owner;
    {
        const auto* p = reinterpret_cast<const uint8_t*>(soa->rdata.data());
        size_t off = 0;
        for (int k = 0; k < 2; ++k)
        {
            while (p[off])
                off += 1 + p[off];
            ++off;   // the name's terminating zero
        }
        z.serial = rd32(p + off);
        const uint32_t minimum = rd32(p + soa->rdata.size() - 4);
        z.negative_ttl = std::min(soa->ttl, minimum);
    }

    for (auto& r : recs)
    {
        if (!is_subdomain(r.owner, z.origin))
            return fail(why, r.line, to_text(r.owner) + " is outside the zone " + to_text(z.origin));
        node& nd = z.names[r.owner];
        rrset* set = nullptr;
        for (auto& s : nd.sets)
            if (s.type == r.type)
                set = &s;
        if (!set)
        {
            nd.sets.push_back(rrset{r.type, r.ttl, {}});
            set = &nd.sets.back();
        }
        else
            set->ttl = std::min(set->ttl, r.ttl);   // RFC 2181 5.2: one TTL for the set, and the shortest is safe
        if (std::find(set->rdata.begin(), set->rdata.end(), r.rdata) == set->rdata.end())
        {
            if (r.type == type::CNAME && !set->rdata.empty())
                return fail(why, r.line, to_text(r.owner) + " has a second CNAME; a name is an alias of one name");
            set->rdata.push_back(std::move(r.rdata));
            ++z.records;
        }
    }

    const node* apex = z.find(z.origin);
    if (!apex || !apex->find(type::NS))
    {
        why = "no NS record at the apex " + to_text(z.origin) + ": a zone names its servers";
        return false;
    }

    // An alias is all a name may be, and a cut hands a name away with all below it but its glue.
    std::vector<std::string> cuts;
    for (auto& [name, nd] : z.names)
    {
        if (nd.find(type::CNAME) && nd.sets.size() > 1)
        {
            why = to_text(name) + " has a CNAME and other records; an alias can have nothing else";
            return false;
        }
        if (name != z.origin && nd.find(type::NS))
        {
            nd.cut = true;
            z.has_cuts = true;
            cuts.push_back(name);
        }
        if (name == z.origin && nd.find(type::CNAME))
        {
            why = "the apex cannot be a CNAME";
            return false;
        }
    }
    for (const auto& [name, nd] : z.names)
        for (const auto& c : cuts)
        {
            if (!is_subdomain(name, c))
                continue;
            for (const auto& s : nd.sets)
            {
                const bool glue = s.type == type::A || s.type == type::AAAA;
                const bool at_cut = name == c && (s.type == type::NS || s.type == type::DS);
                if (!glue && !at_cut)
                {
                    why = to_text(name) + " is delegated by the NS records of " + to_text(c) +
                          ", so it can hold only addresses for those servers";
                    return false;
                }
            }
        }

    // The names between each name and the apex exist too, empty.
    std::vector<std::string> owners;
    owners.reserve(z.names.size());
    for (const auto& [name, nd] : z.names)
        owners.push_back(name);
    for (const auto& o : owners)
        for (std::string_view p = parent(o); p.size() > z.origin.size(); p = parent(p))
            z.names.try_emplace(std::string(p));
    // A record kept in a sorted order, so an answer is the same from every shard and every restart.
    for (auto& [name, nd] : z.names)
        for (auto& s : nd.sets)
            std::sort(s.rdata.begin(), s.rdata.end());
    return true;
}

bool load_zone(const std::string& path, std::string_view origin_hint, zone& out, std::string& why)
{
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (fd < 0)
    {
        why = path + ": " + std::strerror(errno);
        return false;
    }
    struct stat st{};
    if (::fstat(fd, &st) < 0 || !S_ISREG(st.st_mode))
    {
        ::close(fd);
        why = path + ": not a regular file";
        return false;
    }
    if (static_cast<uint64_t>(st.st_size) > max_zone_file)
    {
        ::close(fd);
        why = path + ": larger than " + std::to_string(max_zone_file >> 20) + " MiB";
        return false;
    }
    std::string text(static_cast<size_t>(st.st_size), '\0');
    size_t got = 0;
    while (got < text.size())
    {
        const ssize_t n = ::read(fd, text.data() + got, text.size() - got);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        got += static_cast<size_t>(n);
    }
    ::close(fd);
    text.resize(got);
    if (!parse_zone(text, origin_hint, out, why))
    {
        why = path + ": " + why;
        return false;
    }
    out.path = path;
    out.stamp = socketley::file_stamp::of(st);
    return true;
}

size_t add_extra(zone& z, const extra_records& x)
{
    size_t added = 0;
    // The names between a new name and the apex, which exist from now on, empty.
    const auto make_path = [&](const std::string& name)
    {
        for (std::string_view p = parent(name); p.size() > z.origin.size(); p = parent(p))
            z.names.try_emplace(std::string(p));
    };
    // Whether `name` lies beneath a cut, where this zone answers nothing but referrals.
    const auto below_cut = [&](const std::string& name)
    {
        for (std::string_view p = name; z.has_cuts && p.size() > z.origin.size(); p = parent(p))
            if (const node* n = z.find(p); n && n->cut)
                return true;
        return false;
    };
    const auto put = [&](const std::string& name, uint16_t t, uint32_t ttl, const std::vector<std::string>& rdata)
    {
        if (rdata.empty() || below_cut(name))
            return;
        node& nd = z.names[name];
        if (nd.find(type::CNAME) || nd.find(t))
            return;
        nd.sets.push_back(rrset{t, ttl, rdata});
        std::sort(nd.sets.back().rdata.begin(), nd.sets.back().rdata.end());
        added += rdata.size();
        make_path(name);
    };
    for (const auto& n : x.names)
    {
        std::string w;
        // Relative: no dot past a leading "*." -- "chat", and "*.ui" for the buckets of a storage runtime named "ui".
        const bool relative = n.find('.', n.starts_with("*.") ? 2 : 0) == std::string::npos;
        if (!name_from_text(relative ? n : (n.back() == '.' ? n : n + "."), z.origin, w) || !is_subdomain(w, z.origin))
            continue;
        put(w, type::A, published_ttl, x.v4);
        put(w, type::AAAA, published_ttl, x.v6);
    }
    std::vector<std::pair<std::string, std::vector<std::string>>> txt;
    for (const auto& [name, value] : x.challenges)
    {
        std::string w;
        const std::string full = "_acme-challenge." + name + (name.back() == '.' ? "" : ".");
        if (value.size() > 255 || !name_from_text(full, {}, w) || !is_subdomain(w, z.origin))
            continue;
        std::string rd(1, static_cast<char>(value.size()));
        rd += value;
        auto it = std::find_if(txt.begin(), txt.end(), [&](const auto& e) { return e.first == w; });
        if (it == txt.end())
            txt.push_back({w, {rd}});
        else if (std::find(it->second.begin(), it->second.end(), rd) == it->second.end())
            it->second.push_back(rd);
    }
    for (const auto& [name, values] : txt)
        put(name, type::TXT, challenge_ttl, values);
    // Another runtime's records where they fall in this zone, a set to a name and type, as the file would hold them.
    struct set_of
    {
        std::string name;
        uint16_t t{0};
        uint32_t ttl{0};
        std::vector<std::string> rdata;
    };
    std::vector<set_of> sets;
    for (const auto& line : x.records)
    {
        std::vector<entry> es;
        std::string why;
        if (!tokenize(line, es, why) || es.size() != 1 || es[0].tokens.size() < 4)
            continue;
        const auto& tk = es[0].tokens;
        std::string w;
        uint32_t ttl = 0;
        uint16_t t = 0;
        size_t i = 1;
        if (!name_from_text(tk[0].text, z.origin, w) || !is_subdomain(w, z.origin) || !parse_ttl(tk[i++].text, ttl))
            continue;
        if (i < tk.size() && is_class(tk[i].text))
            ++i;
        // The zone's own apex records, and what cuts it, stay the file's.
        if (i >= tk.size() || !parse_type(tk[i++].text, t) || t == type::SOA || t == type::NS || t == type::DS ||
            t == type::OPT || t == type::CNAME)
            continue;
        std::string rd;
        if (i >= tk.size() || !parse_rdata(t, tk, i, z.origin, rd, why) || rd.size() > 65535)
            continue;
        auto it = std::find_if(sets.begin(), sets.end(), [&](const set_of& s) { return s.name == w && s.t == t; });
        if (it == sets.end())
            sets.push_back({w, t, ttl, {rd}});
        else if (std::find(it->rdata.begin(), it->rdata.end(), rd) == it->rdata.end())
            it->rdata.push_back(rd);
    }
    for (const auto& s : sets)
        put(s.name, s.t, s.ttl, s.rdata);
    z.records += added;
    z.serial += x.serial_add;
    // The serial the SOA record itself carries, which is what a secondary compares.
    if (x.serial_add)
        if (node* apex = z.names.count(z.origin) ? &z.names[z.origin] : nullptr)
            for (auto& set : apex->sets)
                if (set.type == type::SOA && !set.rdata.empty())
                {
                    std::string& rd = set.rdata[0];
                    size_t off = 0;
                    for (int k = 0; k < 2 && off < rd.size(); ++k)
                    {
                        while (off < rd.size() && rd[off])
                            off += 1 + static_cast<uint8_t>(rd[off]);
                        ++off;
                    }
                    if (off + 4 <= rd.size())
                        wr32(reinterpret_cast<uint8_t*>(rd.data()) + off, z.serial);
                }
    return added;
}

const zone* zone_set::find(std::string_view name) const
{
    const zone* best = nullptr;
    for (const auto& z : zones)
        if (is_subdomain(name, z->origin) && (!best || z->origin.size() > best->origin.size()))
            best = z.get();
    return best;
}

}   // namespace socketley::dns
