#include "db_doc.h"
#include "../../shared/json/json_escape.h"

#include <charconv>
#include <cmath>

namespace socketley::db
{

bool valid_path(std::string_view path)
{
    if (path.empty())
        return false;
    size_t depth = 0;
    while (true)
    {
        const size_t dot = path.find('.');
        const std::string_view name = path.substr(0, dot);
        if (name.empty() || name.size() > 64 || ++depth > max_path_depth)
            return false;
        for (const char c : name)
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-'))
                return false;
        if (dot == std::string_view::npos)
            return true;
        path.remove_prefix(dot + 1);
    }
}

const jvalue* at_path(const jvalue& doc, std::string_view path)
{
    const jvalue* at = &doc;
    while (at)
    {
        const size_t dot = path.find('.');
        at = member(*at, path.substr(0, dot));
        if (dot == std::string_view::npos)
            return at;
        path.remove_prefix(dot + 1);
    }
    return nullptr;
}

jvalue* make_path(jvalue& doc, std::string_view path, std::string& why)
{
    jvalue* at = &doc;
    while (true)
    {
        if (at->k != jvalue::kind::object)
        {
            why = "a step of the path is not an object";
            return nullptr;
        }
        const size_t dot = path.find('.');
        const std::string_view name = path.substr(0, dot);
        jvalue* next = member(*at, name);
        if (!next)
        {
            at->members.emplace_back(std::string(name), jvalue{});
            next = &at->members.back().second;
            if (dot != std::string_view::npos)
                next->k = jvalue::kind::object;
        }
        if (dot == std::string_view::npos)
            return next;
        at = next;
        path.remove_prefix(dot + 1);
    }
}

bool erase_path(jvalue& doc, std::string_view path)
{
    jvalue* at = &doc;
    while (at && at->k == jvalue::kind::object)
    {
        const size_t dot = path.find('.');
        const std::string_view name = path.substr(0, dot);
        if (dot == std::string_view::npos)
        {
            for (auto it = at->members.begin(); it != at->members.end(); ++it)
                if (it->first == name)
                {
                    at->members.erase(it);
                    return true;
                }
            return false;
        }
        at = member(*at, name);
        path.remove_prefix(dot + 1);
    }
    return false;
}

bool number_of(const jvalue& v, double& out)
{
    if (v.k != jvalue::kind::number)
        return false;
    const auto r = std::from_chars(v.s.data(), v.s.data() + v.s.size(), out);
    return r.ec == std::errc() && std::isfinite(out);
}

bool same(const jvalue& a, const jvalue& b)
{
    if (a.k != b.k)
        return false;
    switch (a.k)
    {
        case jvalue::kind::null:
            return true;
        case jvalue::kind::boolean:
            return a.b == b.b;
        case jvalue::kind::number:
        {
            double x = 0, y = 0;
            return number_of(a, x) && number_of(b, y) ? x == y : a.s == b.s;
        }
        case jvalue::kind::string:
            return a.s == b.s;
        case jvalue::kind::array:
            if (a.items.size() != b.items.size())
                return false;
            for (size_t i = 0; i < a.items.size(); ++i)
                if (!same(a.items[i], b.items[i]))
                    return false;
            return true;
        case jvalue::kind::object:
            if (a.members.size() != b.members.size())
                return false;
            for (const auto& [k, m] : a.members)
            {
                const jvalue* o = member(b, k);
                if (!o || !same(m, *o))
                    return false;
            }
            return true;
    }
    return false;
}

ikey key_of(const jvalue* v)
{
    ikey k;
    if (!v)
        return k;
    switch (v->k)
    {
        case jvalue::kind::null:
            break;
        case jvalue::kind::boolean:
            k.rank = v->b ? ikey::yes : ikey::no;
            break;
        case jvalue::kind::number:
            if (number_of(*v, k.num))
                k.rank = ikey::number;
            else
            {
                k.rank = ikey::other;
                k.str = v->s;
            }
            break;
        case jvalue::kind::string:
            k.rank = ikey::string;
            k.str = v->s;
            break;
        case jvalue::kind::array:
        case jvalue::kind::object:
            k.rank = ikey::other;
            json::write_into(k.str, *v);
            break;
    }
    return k;
}

}   // namespace socketley::db
