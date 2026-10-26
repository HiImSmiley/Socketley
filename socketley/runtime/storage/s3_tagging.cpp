#include "s3_tagging.h"

#include <cstdint>

#include "s3_names.h"
#include "s3_xml.h"
#include "s3_xml_tree.h"
#include "../../shared/util/text_list.h"

namespace socketley::storage
{

namespace
{

s3_error tag_error(std::string_view code, std::string_view message)
{
    s3_error e = make_error(code);
    e.message  = std::string(message);
    return e;
}

// Beyond ASCII S3 takes the letters, digits and spaces of every script, which is read here as
// anything but a control, a format character, a private-use character or a noncharacter.
bool allowed(uint32_t cp)
{
    if (cp < 0x80)
    {
        const char c = static_cast<char>(cp);
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ' ' || c == '+' ||
               c == '-' || c == '=' || c == '.' || c == '_' || c == ':' || c == '/' || c == '@';
    }
    return cp > 0x9F && cp != 0xAD && !(cp >= 0x200B && cp <= 0x200F) && !(cp >= 0x202A && cp <= 0x202E) &&
           !(cp >= 0x2060 && cp <= 0x206F) && !(cp >= 0xE000 && cp <= 0xF8FF) && cp != 0xFEFF &&
           !(cp >= 0xFFF9 && cp <= 0xFFFB) && !(cp >= 0xFDD0 && cp <= 0xFDEF) && !(cp >= 0x600 && cp <= 0x605) &&
           cp != 0x61C && cp != 0x6DD && cp != 0x70F && cp != 0x180E && (cp & 0xFFFE) != 0xFFFE && cp < 0xF0000;
}

// The characters of `s`, false when it is not UTF-8 or holds one a tag may not.
bool tag_chars(std::string_view s, size_t& chars)
{
    static constexpr uint32_t least[] = {0, 0, 0x80, 0x800, 0x10000};
    chars = 0;
    for (size_t i = 0; i < s.size();)
    {
        const auto c = static_cast<unsigned char>(s[i]);
        uint32_t cp = c;
        size_t   n  = 1;
        if (c >= 0x80)
        {
            if ((c & 0xE0) == 0xC0)
                n = 2, cp = c & 0x1F;
            else if ((c & 0xF0) == 0xE0)
                n = 3, cp = c & 0x0F;
            else if ((c & 0xF8) == 0xF0)
                n = 4, cp = c & 0x07;
            else
                return false;
            if (i + n > s.size())
                return false;
            for (size_t k = 1; k < n; ++k)
            {
                const auto cc = static_cast<unsigned char>(s[i + k]);
                if ((cc & 0xC0) != 0x80)
                    return false;
                cp = (cp << 6) | (cc & 0x3F);
            }
            if (cp < least[n] || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
                return false;
        }
        if (!allowed(cp))
            return false;
        ++chars;
        i += n;
    }
    return true;
}

// The next key and value of a stored set at `pos`, false at its end.
bool next_tag(std::string_view stored, size_t& pos, std::string_view& key, std::string_view& value)
{
    const size_t k = stored.find('\0', pos);
    if (k == std::string_view::npos)
        return false;
    const size_t v = stored.find('\0', k + 1);
    if (v == std::string_view::npos)
        return false;
    key   = stored.substr(pos, k - pos);
    value = stored.substr(k + 1, v - k - 1);
    pos   = v + 1;
    return true;
}

}   // namespace

bool check_tags(const tag_set& tags, s3_error& err, size_t max_tags)
{
    if (tags.size() > max_tags)
    {
        err = max_tags == max_object_tags ? tag_error("BadRequest", "Object tags cannot be greater than 10")
                                          : tag_error("InvalidTag", "Bucket tags cannot be greater than 50");
        return false;
    }
    for (size_t i = 0; i < tags.size(); ++i)
    {
        const auto& [k, v] = tags[i];
        size_t n = 0;
        if (!tag_chars(k, n) || n == 0)
        {
            err = tag_error("InvalidTag", "The TagKey you have provided is invalid");
            return false;
        }
        if (n > max_tag_key_chars)
        {
            err = tag_error("InvalidTag", "The TagKey you have provided is too long, max 128");
            return false;
        }
        if (k.starts_with("aws:"))
        {
            err = tag_error("InvalidTag", "Your TagKey cannot be prefixed with aws:");
            return false;
        }
        if (!tag_chars(v, n))
        {
            err = tag_error("InvalidTag", "The TagValue you have provided is invalid");
            return false;
        }
        if (n > max_tag_value_chars)
        {
            err = tag_error("InvalidTag", "The TagValue you have provided is too long, max 256");
            return false;
        }
        for (size_t j = 0; j < i; ++j)
            if (tags[j].first == k)
            {
                err = tag_error("InvalidTag", "Cannot provide multiple Tags with the same key");
                return false;
            }
    }
    return true;
}

bool parse_tagging_xml(std::string_view xml, tag_set& out, s3_error& err, size_t max_tags)
{
    out.clear();
    err = make_error("MalformedXML");
    xml_node root;
    xml_reader reader(xml);
    if (!reader.document(root) || root.name != "Tagging" || root.kids.size() != 1 || root.kids[0].name != "TagSet")
        return false;
    for (const xml_node& t : root.kids[0].kids)
    {
        if (t.name != "Tag" || t.kids.size() != 2)
            return false;
        const xml_node* key   = nullptr;
        const xml_node* value = nullptr;
        for (const xml_node& f : t.kids)
        {
            const xml_node** slot = f.name == "Key" ? &key : f.name == "Value" ? &value : nullptr;
            if (!slot || *slot || !f.kids.empty())
                return false;
            *slot = &f;
        }
        if (!key || !value)
            return false;
        out.emplace_back(key->text, value->text);
    }
    return check_tags(out, err, max_tags);
}

bool parse_tagging_header(std::string_view header, tag_set& out, s3_error& err)
{
    out.clear();
    const s3_error bad = tag_error("InvalidArgument",
        "The header 'x-amz-tagging' shall be encoded as UTF-8 then URLEncoded URL query parameters without tag name "
        "duplicates.");
    while (!header.empty())
    {
        const std::string_view one = take_item(header, '&');
        if (one.empty())
            continue;
        const size_t eq = one.find('=');
        std::string k, v;
        if (!percent_decode(one.substr(0, eq), k, true) ||
            !percent_decode(eq == std::string_view::npos ? std::string_view{} : one.substr(eq + 1), v, true))
        {
            err = bad;
            return false;
        }
        for (const auto& t : out)
            if (t.first == k)
            {
                err = bad;
                return false;
            }
        out.emplace_back(std::move(k), std::move(v));
    }
    return check_tags(out, err);
}

std::string tagging_xml(const tag_set& tags)
{
    std::string x(xml_decl);
    x += "<Tagging xmlns=\"";
    x += s3_xmlns;
    x += "\"><TagSet>";
    for (const auto& [k, v] : tags)
    {
        x += "<Tag><Key>";
        xml_escape_to(x, k);
        x += "</Key><Value>";
        xml_escape_to(x, v);
        x += "</Value></Tag>";
    }
    x += "</TagSet></Tagging>";
    return x;
}

std::string encode_tags(const tag_set& tags)
{
    std::string s;
    for (const auto& [k, v] : tags)
    {
        s += k;
        s.push_back('\0');
        s += v;
        s.push_back('\0');
    }
    return s;
}

tag_set decode_tags(std::string_view stored)
{
    tag_set out;
    size_t pos = 0;
    std::string_view k, v;
    while (next_tag(stored, pos, k, v))
        out.emplace_back(k, v);
    return out;
}

size_t tag_count(std::string_view stored)
{
    size_t n = 0;
    for (const char c : stored)
        n += c == '\0';
    return n / 2;
}

bool tags_have(std::string_view stored, std::string_view key, std::string_view value)
{
    size_t pos = 0;
    std::string_view k, v;
    while (next_tag(stored, pos, k, v))
        if (k == key)
            return v == value;
    return false;
}

}   // namespace socketley::storage
