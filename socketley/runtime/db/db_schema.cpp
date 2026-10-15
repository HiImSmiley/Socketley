#include "db_schema.h"

#include "db_doc.h"

namespace socketley::db
{

namespace
{

// The words of each line, a `#` at a word's start ending it.
template <class F>
bool each_line(std::string_view text, F&& f)
{
    size_t line_no = 0;
    while (!text.empty())
    {
        const size_t nl = text.find('\n');
        std::string_view line = text.substr(0, nl);
        text = nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
        ++line_no;
        std::vector<std::string_view> words;
        while (true)
        {
            while (!line.empty() && (line.front() == ' ' || line.front() == '\t' || line.front() == '\r'))
                line.remove_prefix(1);
            if (line.empty() || line.front() == '#')
                break;
            size_t end = 0;
            while (end < line.size() && line[end] != ' ' && line[end] != '\t' && line[end] != '\r')
                ++end;
            words.push_back(line.substr(0, end));
            line.remove_prefix(end);
        }
        if (!words.empty() && !f(line_no, words))
            return false;
    }
    return true;
}

}   // namespace

const char* access_name(access a)
{
    switch (a)
    {
        case access::priv:    return "private";
        case access::owner:   return "owner";
        case access::shared:  return "shared";
        case access::open:    return "public";
        case access::catalog: return "catalog";
    }
    return "private";
}

const collection_def* schema::find(std::string_view name) const
{
    for (const auto& c : collections)
        if (c.name == name)
            return &c;
    return nullptr;
}

bool valid_collection(std::string_view name)
{
    if (name.empty() || name.size() > 64 || name.front() < 'a' || name.front() > 'z')
        return false;
    for (const char c : name)
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-'))
            return false;
    return true;
}

bool valid_id(std::string_view id)
{
    if (id.empty() || id.size() > 128 || id.front() == '_')
        return false;
    for (const char c : id)
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' ||
              c == ':' || c == '@' || c == '+' || c == '-'))
            return false;
    return true;
}

bool parse_schema(std::string_view text, schema& out, std::string& why)
{
    schema s;
    const bool ok = each_line(text, [&](size_t line_no, const std::vector<std::string_view>& w) {
        const std::string at = "line " + std::to_string(line_no) + ": ";
        if (w.size() < 2)
        {
            why = at + "a collection and its access: private, owner, shared, public or catalog";
            return false;
        }
        collection_def c;
        if (!valid_collection(w[0]))
        {
            why = at + "a collection's name is 1 to 64 of a-z 0-9 _ -, a letter first: " + std::string(w[0]);
            return false;
        }
        if (s.find(w[0]))
        {
            why = at + std::string(w[0]) + " is declared twice";
            return false;
        }
        c.name = std::string(w[0]);
        if (w[1] == "private")
            c.acc = access::priv;
        else if (w[1] == "owner")
            c.acc = access::owner;
        else if (w[1] == "shared")
            c.acc = access::shared;
        else if (w[1] == "public")
            c.acc = access::open;
        else if (w[1] == "catalog")
            c.acc = access::catalog;
        else
        {
            why = at + "the access is private, owner, shared, public or catalog, not " + std::string(w[1]);
            return false;
        }
        for (size_t i = 2; i < w.size(); ++i)
        {
            index_def d;
            std::string_view f = w[i];
            if (f.starts_with("unique:"))
            {
                d.unique = true;
                f.remove_prefix(7);
            }
            if (!valid_path(f) || f.front() == '_')
            {
                why = at + "an index is a field's path, names of A-Z a-z 0-9 _ - joined by dots: " + std::string(w[i]);
                return false;
            }
            d.field = std::string(f);
            for (const auto& o : c.indexes)
                if (o.field == d.field)
                {
                    why = at + d.field + " is indexed twice";
                    return false;
                }
            c.indexes.push_back(std::move(d));
        }
        if (c.indexes.size() > 16)
        {
            why = at + "a collection has at most 16 indexes";
            return false;
        }
        s.collections.push_back(std::move(c));
        return true;
    });
    if (!ok)
        return false;
    out = std::move(s);
    return true;
}

bool parse_keys(std::string_view text, std::vector<service_key>& out, std::string& why)
{
    std::vector<service_key> keys;
    const bool ok = each_line(text, [&](size_t line_no, const std::vector<std::string_view>& w) {
        const std::string at = "line " + std::to_string(line_no) + ": ";
        if (w.size() != 2)
        {
            why = at + "a key is its name and its secret";
            return false;
        }
        if (w[1].size() < 16)
        {
            why = at + "the secret of " + std::string(w[0]) + " is shorter than 16 characters";
            return false;
        }
        for (const auto& k : keys)
            if (k.name == w[0])
            {
                why = at + std::string(w[0]) + " is named twice";
                return false;
            }
        keys.push_back({std::string(w[0]), std::string(w[1])});
        return true;
    });
    if (!ok)
        return false;
    out = std::move(keys);
    return true;
}

}   // namespace socketley::db
