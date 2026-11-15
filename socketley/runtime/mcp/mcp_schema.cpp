#include "mcp_schema.h"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <memory>
#include <vector>

#include "../../shared/util/regex.h"

namespace socketley::mcp
{

namespace
{

namespace js = socketley::json;
using jv = js::jvalue;
using kind = jv::kind;

// Each step into the schema, by a keyword or by a reference, counts, so a schema that refers to itself with nothing
// under it to go into ends here rather than for ever.
constexpr int max_depth = 64;
// What one call may cost, in values looked at and bytes matched, so anyOf over a wide value stays bounded.
constexpr size_t max_work = size_t{1} << 22;

enum class verdict : uint8_t { ok, no, broken };

double number(const jv& v)
{
    double d = 0;
    std::from_chars(v.s.data(), v.s.data() + v.s.size(), d);
    return d;
}

bool integral(const jv& v)
{
    if (v.k != kind::number)
        return false;
    const double d = number(v);
    return std::isfinite(d) && std::floor(d) == d;
}

size_t code_points(std::string_view s)
{
    size_t n = 0;
    for (const unsigned char c : s)
        n += (c & 0xC0) != 0x80;
    return n;
}

std::string pointer_step(std::string_view name)
{
    std::string o = "/";
    for (const char c : name)
        o += c == '~' ? std::string("~0") : c == '/' ? std::string("~1") : std::string(1, c);
    return o;
}

const char* kind_name(const jv& v)
{
    switch (v.k)
    {
        case kind::null: return "null";
        case kind::boolean: return "a boolean";
        case kind::number: return "a number";
        case kind::string: return "a string";
        case kind::array: return "an array";
        case kind::object: return "an object";
    }
    return "a value";
}

struct checker
{
    explicit checker(const jv& r) : root(r) {}
    const jv& root;
    size_t work{0};
    std::string why;
    std::vector<std::pair<const std::string*, std::unique_ptr<socketley::regex>>> patterns;

    verdict no(const std::string& where, const std::string& what)
    {
        why = (where.empty() ? std::string("the arguments") : "the argument at " + where) + " " + what;
        return verdict::no;
    }

    verdict broken(const std::string& what)
    {
        why = "the tool's input schema " + what;
        return verdict::broken;
    }

    bool equal(const jv& a, const jv& b)
    {
        ++work;
        if (a.k != b.k)
            return false;
        switch (a.k)
        {
            case kind::null: return true;
            case kind::boolean: return a.b == b.b;
            case kind::number: return a.s == b.s || number(a) == number(b);
            case kind::string: return a.s == b.s;
            case kind::array:
                if (a.items.size() != b.items.size())
                    return false;
                for (size_t i = 0; i < a.items.size(); ++i)
                    if (work > max_work || !equal(a.items[i], b.items[i]))
                        return false;
                return true;
            case kind::object:
                if (a.members.size() != b.members.size())
                    return false;
                for (const auto& [name, m] : a.members)
                {
                    const jv* other = js::member(b, name);
                    if (work > max_work || !other || !equal(m, *other))
                        return false;
                }
                return true;
        }
        return false;
    }

    const socketley::regex* pattern(const std::string& text)
    {
        for (const auto& [p, re] : patterns)
            if (p == &text)
                return re.get();
        auto re = std::make_unique<socketley::regex>();
        std::string err;
        // ECMA-262's pattern, unanchored as JSON Schema has it; RE2's syntax is the part both share.
        if (!re->compile(text, err, socketley::regex::syntax::re2, true))
            return nullptr;
        patterns.emplace_back(&text, std::move(re));
        return patterns.back().second.get();
    }

    verdict matches(const std::string& text, const std::string& where, std::string_view s)
    {
        const socketley::regex* re = pattern(text);
        if (!re)
            return broken("has a pattern this server cannot read: " + text);
        work += (s.size() + 1) * (re->program_size() / 16 + 1);
        if (work > max_work)
            return no(where, "is too large to check against the tool's input schema");
        return re->matches(s) ? verdict::ok : no(where, "does not match the pattern " + text);
    }

    // The schema a "#..." reference names in the whole schema, by JSON Pointer.
    const jv* resolve(std::string_view ref)
    {
        if (ref.empty() || ref[0] != '#')
            return nullptr;
        ref.remove_prefix(1);
        const jv* at = &root;
        while (!ref.empty())
        {
            if (ref[0] != '/')
                return nullptr;
            ref.remove_prefix(1);
            const size_t end = std::min(ref.find('/'), ref.size());
            std::string step;
            for (size_t i = 0; i < end; ++i)
                if (ref[i] == '~' && i + 1 < end && (ref[i + 1] == '0' || ref[i + 1] == '1'))
                    step += ref[++i] == '0' ? '~' : '/';
                else
                    step += ref[i];
            ref.remove_prefix(end);
            if (at->k == kind::object)
                at = js::member(*at, step);
            else if (at->k == kind::array)
            {
                size_t i = 0;
                const auto [p, ec] = std::from_chars(step.data(), step.data() + step.size(), i);
                at = ec == std::errc{} && p == step.data() + step.size() && i < at->items.size() ? &at->items[i] : nullptr;
            }
            else
                at = nullptr;
            if (!at)
                return nullptr;
        }
        return at;
    }

    bool number_keyword(const jv& schema, std::string_view name, double& out, bool& present, verdict& bad)
    {
        const jv* k = js::member(schema, name);
        present = k != nullptr;
        if (!k)
            return true;
        if (k->k != kind::number)
        {
            bad = broken("has a " + std::string(name) + " that is no number");
            return false;
        }
        out = number(*k);
        return true;
    }

    bool count_keyword(const jv& schema, std::string_view name, size_t& out, bool& present, verdict& bad)
    {
        double d = 0;
        if (!number_keyword(schema, name, d, present, bad))
            return false;
        if (present && (!(d >= 0) || std::floor(d) != d))
        {
            bad = broken("has a " + std::string(name) + " that is no count");
            return false;
        }
        out = present ? (d > 1e18 ? SIZE_MAX : static_cast<size_t>(d)) : 0;
        return true;
    }

    bool type_is(const jv& v, std::string_view t, verdict& bad)
    {
        if (t == "null")
            return v.k == kind::null;
        if (t == "boolean")
            return v.k == kind::boolean;
        if (t == "object")
            return v.k == kind::object;
        if (t == "array")
            return v.k == kind::array;
        if (t == "string")
            return v.k == kind::string;
        if (t == "number")
            return v.k == kind::number;
        if (t == "integer")
            return integral(v);
        bad = broken("names no type called " + std::string(t));
        return false;
    }

    verdict each_schema(const jv& list, std::string_view name, const auto& fn)
    {
        if (list.k != kind::array || list.items.empty())
            return broken("has a " + std::string(name) + " that is no list of schemas");
        for (const jv& s : list.items)
            if (const verdict r = fn(s); r != verdict::ok)
                return r;
        return verdict::ok;
    }

    verdict check(const jv& schema, const jv& v, const std::string& where, int depth)
    {
        if (++work > max_work)
            return no(where, "are too large to check against the tool's input schema");
        if (depth > max_depth)
            return broken("nests or refers to itself too deep");
        if (schema.k == kind::boolean)
            return schema.b ? verdict::ok : no(where, "is admitted by no value");
        if (schema.k != kind::object)
            return broken("has a schema that is no object");
        verdict bad = verdict::ok;

        if (const jv* ref = js::member(schema, "$ref"))
        {
            const jv* to = ref->k == kind::string ? resolve(ref->s) : nullptr;
            if (!to)
                return broken("refers to what is not in it: " + (ref->k == kind::string ? ref->s : std::string("?")));
            if (const verdict r = check(*to, v, where, depth + 1); r != verdict::ok)
                return r;
        }

        if (const jv* t = js::member(schema, "type"))
        {
            bool fits = false;
            if (t->k == kind::string)
                fits = type_is(v, t->s, bad);
            else if (t->k == kind::array && !t->items.empty())
                for (const jv& one : t->items)
                {
                    if (one.k != kind::string)
                        return broken("has a type list holding no name");
                    fits = fits || type_is(v, one.s, bad);
                    if (bad != verdict::ok)
                        return bad;
                }
            else
                return broken("has a type that is no name");
            if (bad != verdict::ok)
                return bad;
            if (!fits)
                return no(where, std::string("is ") + kind_name(v) + ", not of the type the tool asks for (" +
                                     js::written(*t) + ")");
        }
        if (const jv* e = js::member(schema, "enum"))
        {
            if (e->k != kind::array)
                return broken("has an enum that is no list");
            bool found = false;
            for (const jv& one : e->items)
                if (equal(one, v))
                {
                    found = true;
                    break;
                }
            if (!found)
                return no(where, "is none of the values the tool takes");
        }
        if (const jv* c = js::member(schema, "const"); c && !equal(*c, v))
            return no(where, "is not the one value the tool takes");

        if (v.k == kind::string)
        {
            size_t least = 0, most = 0;
            bool has_least = false, has_most = false;
            if (!count_keyword(schema, "minLength", least, has_least, bad) ||
                !count_keyword(schema, "maxLength", most, has_most, bad))
                return bad;
            if (has_least || has_most)
            {
                const size_t n = code_points(v.s);
                if (has_least && n < least)
                    return no(where, "is shorter than " + std::to_string(least) + " characters");
                if (has_most && n > most)
                    return no(where, "is longer than " + std::to_string(most) + " characters");
            }
            if (const jv* p = js::member(schema, "pattern"))
            {
                if (p->k != kind::string)
                    return broken("has a pattern that is no string");
                if (const verdict r = matches(p->s, where, v.s); r != verdict::ok)
                    return r;
            }
        }

        if (v.k == kind::number)
        {
            const double x = number(v);
            double lo = 0, hi = 0, xlo = 0, xhi = 0, step = 0;
            bool has_lo = false, has_hi = false, has_xlo = false, has_xhi = false, has_step = false;
            if (!number_keyword(schema, "minimum", lo, has_lo, bad) || !number_keyword(schema, "maximum", hi, has_hi, bad) ||
                !number_keyword(schema, "multipleOf", step, has_step, bad))
                return bad;
            // exclusiveMinimum is a number of its own since draft 6, and a flag on minimum in draft 4.
            const jv* ex_lo = js::member(schema, "exclusiveMinimum");
            const jv* ex_hi = js::member(schema, "exclusiveMaximum");
            const bool flag_lo = ex_lo && ex_lo->k == kind::boolean && ex_lo->b;
            const bool flag_hi = ex_hi && ex_hi->k == kind::boolean && ex_hi->b;
            if (ex_lo && ex_lo->k != kind::boolean && !number_keyword(schema, "exclusiveMinimum", xlo, has_xlo, bad))
                return bad;
            if (ex_hi && ex_hi->k != kind::boolean && !number_keyword(schema, "exclusiveMaximum", xhi, has_xhi, bad))
                return bad;
            if (has_lo && (flag_lo ? !(x > lo) : !(x >= lo)))
                return no(where, "is below the least the tool takes");
            if (has_hi && (flag_hi ? !(x < hi) : !(x <= hi)))
                return no(where, "is above the most the tool takes");
            if (has_xlo && !(x > xlo))
                return no(where, "is not above the least the tool takes");
            if (has_xhi && !(x < xhi))
                return no(where, "is not below the most the tool takes");
            if (has_step)
            {
                if (!(step > 0))
                    return broken("has a multipleOf that is not above 0");
                const double q = x / step;
                if (!std::isfinite(q) || std::fabs(q - std::round(q)) > 1e-9 * std::max(1.0, std::fabs(q)))
                    return no(where, "is no multiple of " + js::written(*js::member(schema, "multipleOf")));
            }
        }

        if (v.k == kind::object)
        {
            const jv* props = js::member(schema, "properties");
            const jv* pats = js::member(schema, "patternProperties");
            const jv* more = js::member(schema, "additionalProperties");
            if ((props && props->k != kind::object) || (pats && pats->k != kind::object))
                return broken("has properties that are no object");
            if (const jv* req = js::member(schema, "required"))
            {
                if (req->k != kind::array)
                    return broken("has a required that is no list");
                for (const jv& name : req->items)
                {
                    if (name.k != kind::string)
                        return broken("has a required holding no name");
                    if (!js::member(v, name.s))
                        return no(where, "has no " + name.s + ", which the tool requires");
                }
            }
            if (const jv* dep = js::member(schema, "dependentRequired"); dep && dep->k == kind::object)
                for (const auto& [name, list] : dep->members)
                    if (js::member(v, name) && list.k == kind::array)
                        for (const jv& other : list.items)
                            if (other.k == kind::string && !js::member(v, other.s))
                                return no(where, "has " + name + " without " + other.s + ", which goes with it");
            size_t least = 0, most = 0;
            bool has_least = false, has_most = false;
            if (!count_keyword(schema, "minProperties", least, has_least, bad) ||
                !count_keyword(schema, "maxProperties", most, has_most, bad))
                return bad;
            if (has_least && v.members.size() < least)
                return no(where, "has fewer than " + std::to_string(least) + " members");
            if (has_most && v.members.size() > most)
                return no(where, "has more than " + std::to_string(most) + " members");
            const jv* names = js::member(schema, "propertyNames");
            for (const auto& [name, m] : v.members)
            {
                const std::string at = where + pointer_step(name);
                bool named = false;
                if (props)
                    if (const jv* s = js::member(*props, name))
                    {
                        named = true;
                        if (const verdict r = check(*s, m, at, depth + 1); r != verdict::ok)
                            return r;
                    }
                if (pats)
                    for (const auto& [text, s] : pats->members)
                    {
                        const socketley::regex* re = pattern(text);
                        if (!re)
                            return broken("has a pattern this server cannot read: " + text);
                        work += (name.size() + 1) * (re->program_size() / 16 + 1);
                        if (work > max_work)
                            return no(where, "is too large to check against the tool's input schema");
                        if (!re->matches(name))
                            continue;
                        named = true;
                        if (const verdict r = check(s, m, at, depth + 1); r != verdict::ok)
                            return r;
                    }
                if (!named && more)
                {
                    if (more->k == kind::boolean && !more->b)
                        return no(where, "has " + name + ", which the tool does not take");
                    if (const verdict r = check(*more, m, at, depth + 1); r != verdict::ok)
                        return r;
                }
                if (names)
                {
                    jv as_value;
                    as_value.k = kind::string;
                    as_value.s = name;
                    if (const verdict r = check(*names, as_value, at, depth + 1); r != verdict::ok)
                        return r;
                }
            }
        }

        if (v.k == kind::array)
        {
            size_t least = 0, most = 0;
            bool has_least = false, has_most = false;
            if (!count_keyword(schema, "minItems", least, has_least, bad) ||
                !count_keyword(schema, "maxItems", most, has_most, bad))
                return bad;
            if (has_least && v.items.size() < least)
                return no(where, "has fewer than " + std::to_string(least) + " items");
            if (has_most && v.items.size() > most)
                return no(where, "has more than " + std::to_string(most) + " items");
            // The leading items by place (prefixItems, or items as a list in drafts before 2020-12), then the rest.
            const jv* prefix = js::member(schema, "prefixItems");
            const jv* items = js::member(schema, "items");
            const jv* rest = items;
            if (!prefix && items && items->k == kind::array)
            {
                prefix = items;
                rest = js::member(schema, "additionalItems");
            }
            if (prefix && prefix->k != kind::array)
                return broken("has prefixItems that are no list");
            for (size_t i = 0; i < v.items.size(); ++i)
            {
                const std::string at = where + "/" + std::to_string(i);
                const jv* s = prefix && i < prefix->items.size() ? &prefix->items[i] : rest;
                if (s)
                    if (const verdict r = check(*s, v.items[i], at, depth + 1); r != verdict::ok)
                        return r;
            }
            if (const jv* u = js::member(schema, "uniqueItems"); u && u->k == kind::boolean && u->b)
                for (size_t i = 0; i < v.items.size(); ++i)
                    for (size_t j = i + 1; j < v.items.size(); ++j)
                    {
                        if (work > max_work)
                            return no(where, "is too large to check against the tool's input schema");
                        if (equal(v.items[i], v.items[j]))
                            return no(where, "holds an item twice");
                    }
            if (const jv* c = js::member(schema, "contains"))
            {
                bool found = false;
                for (size_t i = 0; i < v.items.size() && !found; ++i)
                {
                    const verdict r = check(*c, v.items[i], where + "/" + std::to_string(i), depth + 1);
                    if (r == verdict::broken)
                        return r;
                    found = r == verdict::ok;
                }
                if (!found)
                    return no(where, "holds no item of the kind the tool asks for");
            }
        }

        if (const jv* all = js::member(schema, "allOf"))
            if (const verdict r = each_schema(*all, "allOf", [&](const jv& s) { return check(s, v, where, depth + 1); });
                r != verdict::ok)
                return r;
        for (const char* name : {"anyOf", "oneOf"})
            if (const jv* list = js::member(schema, name))
            {
                if (list->k != kind::array || list->items.empty())
                    return broken("has a " + std::string(name) + " that is no list of schemas");
                size_t fit = 0;
                std::string first_why;
                for (const jv& s : list->items)
                {
                    const verdict r = check(s, v, where, depth + 1);
                    if (r == verdict::broken)
                        return r;
                    if (r == verdict::ok)
                        ++fit;
                    else if (first_why.empty())
                        first_why = why;
                }
                if (fit == 0)
                    return no(where, "matches none of the forms the tool takes (" + first_why + ")");
                if (fit > 1 && std::string_view(name) == "oneOf")
                    return no(where, "matches more than one of the forms the tool takes");
            }
        if (const jv* n = js::member(schema, "not"))
        {
            const verdict r = check(*n, v, where, depth + 1);
            if (r == verdict::broken)
                return r;
            if (r == verdict::ok)
                return no(where, "is of a form the tool refuses");
        }
        if (const jv* cond = js::member(schema, "if"))
        {
            const verdict r = check(*cond, v, where, depth + 1);
            if (r == verdict::broken)
                return r;
            if (const jv* then = js::member(schema, r == verdict::ok ? "then" : "else"))
                if (const verdict t = check(*then, v, where, depth + 1); t != verdict::ok)
                    return t;
        }
        why.clear();
        return verdict::ok;
    }
};

}   // namespace

bool schema_admits(std::string_view schema, const json::jvalue& args, std::string& why)
{
    json::jvalue doc;
    // A schema may nest deeper than a document a request sends, and is the tool author's own.
    json::json_policy policy;
    policy.max_depth = max_depth;
    if (!json::json_reader(schema, policy).document(doc))
    {
        why = "the tool's input schema is no JSON object";
        return false;
    }
    checker c(doc);
    if (c.check(doc, args, {}, 0) == verdict::ok)
        return true;
    why = std::move(c.why);
    return false;
}

}   // namespace socketley::mcp
