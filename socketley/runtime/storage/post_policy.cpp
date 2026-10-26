#include "post_policy.h"

#include <algorithm>

#include "checksum.h"
#include "../../shared/json/json_doc.h"
#include "s3_names.h"
#include "s3_xml.h"
#include "../../shared/util/base64.h"

using socketley::json::jvalue;
using socketley::json::json_reader;

namespace socketley::storage
{

namespace
{

std::string lowered(std::string_view s)
{
    std::string out(s);
    for (char& c : out)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    return out;
}

std::string_view trimmed(std::string_view v)
{
    while (!v.empty() && (v.front() == ' ' || v.front() == '\t'))
        v.remove_prefix(1);
    while (!v.empty() && (v.back() == ' ' || v.back() == '\t'))
        v.remove_suffix(1);
    return v;
}

// The value of parameter `name` in a header such as `form-data; name="key"; filename="a b.txt"`, absent when none.
std::optional<std::string> header_param(std::string_view header, std::string_view name)
{
    size_t at = header.find(';');
    while (at != std::string_view::npos)
    {
        std::string_view rest = trimmed(header.substr(at + 1));
        const size_t eq = rest.find('=');
        if (eq == std::string_view::npos)
            return std::nullopt;
        const std::string pname = lowered(trimmed(rest.substr(0, eq)));
        std::string_view v = trimmed(rest.substr(eq + 1));
        std::string value;
        size_t used = 0;
        if (!v.empty() && v.front() == '"')
        {
            // A quoted value ends at the quote no backslash escapes.
            size_t i = 1;
            for (; i < v.size() && v[i] != '"'; ++i)
            {
                if (v[i] == '\\' && i + 1 < v.size())
                    ++i;
                value += v[i];
            }
            used = std::min(v.size(), i + 1);
        }
        else
        {
            used  = std::min(v.find(';'), v.size());
            value = std::string(trimmed(v.substr(0, used)));
        }
        if (pname == name)
            return value;
        const size_t next = v.substr(used).find(';');
        at = next == std::string_view::npos ? std::string_view::npos
                                            : static_cast<size_t>(v.data() - header.data()) + used + next;
    }
    return std::nullopt;
}

s3_error refusal(std::string_view code, std::string message = {})
{
    s3_error e = make_error(code);
    if (!message.empty())
        e.message = std::move(message);
    return e;
}

s3_error policy_refusal(std::string_view why)
{
    return refusal("AccessDenied", "Invalid according to Policy: " + std::string(why));
}

// A condition as S3 quotes it back: ["eq", "$key", "value"].
std::string quoted(std::string_view op, std::string_view name, std::string_view value)
{
    return "[\"" + std::string(op) + "\", \"$" + std::string(name) + "\", \"" + std::string(value) + "\"]";
}

bool number_of(const jvalue& v, uint64_t& out)
{
    if ((v.k != jvalue::kind::number && v.k != jvalue::kind::string) || v.s.empty() || v.s.size() > 19)
        return false;
    out = 0;
    for (char ch : v.s)
    {
        if (ch < '0' || ch > '9')
            return false;
        out = out * 10 + static_cast<uint64_t>(ch - '0');
    }
    return true;
}

}   // namespace

const std::string* post_form::field(std::string_view lower_name) const
{
    for (const auto& [n, v] : fields)
        if (n == lower_name)
            return &v;
    return nullptr;
}

form_scan scan_post_form(std::string_view content_type, std::string_view in, bool whole, post_form& out,
                         s3_error& err)
{
    const std::string type = lowered(trimmed(content_type.substr(0, content_type.find(';'))));
    const auto boundary = header_param(content_type, "boundary");
    if (type != "multipart/form-data" || !boundary || boundary->empty() || boundary->size() > 200)
    {
        err = refusal("MalformedPOSTRequest");
        return form_scan::bad;
    }
    out.boundary = *boundary;
    out.fields.clear();
    const std::string dash = "--" + out.boundary;
    const std::string delim = "\r\n" + dash;

    auto more = [&]() -> form_scan
    {
        if (in.size() > post_max_fields_bytes)
        {
            err = refusal("MaxPostPreDataLengthExceeded");
            return form_scan::bad;
        }
        if (whole)
        {
            err = refusal("MalformedPOSTRequest");
            return form_scan::bad;
        }
        return form_scan::more;
    };

    // The first boundary opens the body, or follows a preamble that is dropped.
    size_t pos = 0;
    if (in.substr(0, dash.size()) == dash)
        pos = dash.size();
    else if (const size_t d = in.find(delim); d != std::string_view::npos)
        pos = d + delim.size();
    else
        return more();
    for (;;)
    {
        if (in.size() < pos + 2)
            return more();
        if (in.substr(pos, 2) == "--")
        {
            err = refusal("IncorrectNumberOfFilesInPostRequest");
            return form_scan::bad;
        }
        if (in.substr(pos, 2) != "\r\n")
        {
            err = refusal("MalformedPOSTRequest");
            return form_scan::bad;
        }
        pos += 2;
        const size_t head_end = in.find("\r\n\r\n", pos);
        if (head_end == std::string_view::npos)
            return more();
        std::string name, filename, part_type;
        bool has_name = false;
        std::string_view heads = in.substr(pos, head_end - pos);
        while (!heads.empty())
        {
            const size_t eol = heads.find("\r\n");
            const std::string_view line = heads.substr(0, eol);
            heads = eol == std::string_view::npos ? std::string_view{} : heads.substr(eol + 2);
            const size_t colon = line.find(':');
            if (colon == std::string_view::npos)
                continue;
            const std::string hname = lowered(trimmed(line.substr(0, colon)));
            const std::string_view hvalue = trimmed(line.substr(colon + 1));
            if (hname == "content-disposition")
            {
                if (const auto n = header_param(hvalue, "name"))
                {
                    name     = lowered(*n);
                    has_name = true;
                }
                if (const auto f = header_param(hvalue, "filename"))
                    filename = *f;
            }
            else if (hname == "content-type")
                part_type = std::string(hvalue);
        }
        if (!has_name)
        {
            err = refusal("MalformedPOSTRequest");
            return form_scan::bad;
        }
        const size_t content = head_end + 4;
        if (name == "file")
        {
            if (content > post_max_fields_bytes)
            {
                err = refusal("MaxPostPreDataLengthExceeded");
                return form_scan::bad;
            }
            out.filename  = std::move(filename);
            out.file_type = std::move(part_type);
            out.file_at   = content;
            return form_scan::ok;
        }
        const size_t end = in.find(delim, content);
        if (end == std::string_view::npos)
            return more();
        // A field given twice is read as its first, which is the one a condition was written against.
        if (!out.field(name))
            out.fields.emplace_back(std::move(name), std::string(in.substr(content, end - content)));
        pos = end + delim.size();
    }
}

std::string post_key(const post_form& f)
{
    const std::string* k = f.field("key");
    if (!k)
        return {};
    std::string key = *k;
    static constexpr std::string_view var = "${filename}";
    for (size_t at = key.find(var); at != std::string::npos; at = key.find(var, at + f.filename.size()))
        key.replace(at, var.size(), f.filename);
    return key;
}

bool check_post_policy(post_form& f, std::string_view bucket, int64_t now_ms, s3_error& err)
{
    const std::string* p = f.field("policy");
    std::string text;
    jvalue doc;
    if (!p || !base64::decode(trimmed(*p), text) || !json_reader(text).document(doc))
    {
        err = refusal("InvalidPolicyDocument", "Invalid Policy: Invalid JSON.");
        return false;
    }
    const jvalue* expiration = nullptr;
    const jvalue* conditions = nullptr;
    for (const auto& [n, v] : doc.members)
        if (n == "expiration")
            expiration = &v;
        else if (n == "conditions")
            conditions = &v;
    int64_t expires_ms = 0;
    bool midnight = false;
    if (!expiration || expiration->k != jvalue::kind::string || !parse_iso8601(expiration->s, expires_ms, midnight))
    {
        err = refusal("InvalidPolicyDocument", "Invalid Policy: Policy missing expiration.");
        return false;
    }
    if (!conditions || conditions->k != jvalue::kind::array)
    {
        err = refusal("InvalidPolicyDocument", "Invalid Policy: Policy missing conditions.");
        return false;
    }
    if (now_ms >= expires_ms)
    {
        err = policy_refusal("Policy expired.");
        return false;
    }

    std::vector<std::string> covered;
    // The bucket is the one the form was posted to, and the key the one stored, with ${filename} given its name.
    const std::string bucket_name(bucket);
    const std::string key = post_key(f);
    auto value_of = [&](const std::string& name) -> const std::string*
    {
        return name == "bucket" ? &bucket_name : name == "key" && f.field("key") ? &key : f.field(name);
    };
    // A field the form does not carry is the empty string, which only a condition on "" meets.
    auto test = [&](std::string_view op, const std::string& name, const std::string& want) -> bool
    {
        covered.push_back(name);
        const std::string* found = value_of(name);
        const std::string_view have = found ? std::string_view(*found) : std::string_view{};
        const bool ok = op == "eq" ? have == want : have.starts_with(want);
        if (!ok)
            err = policy_refusal("Policy Condition failed: " + quoted(op, name, want));
        return ok;
    };
    for (const jvalue& c : conditions->items)
    {
        if (c.k == jvalue::kind::object)
        {
            if (c.members.size() != 1)
            {
                err = refusal("InvalidPolicyDocument",
                              "Invalid Policy: Invalid Simple-Condition: Simple-Conditions must have exactly one property specified.");
                return false;
            }
            for (const auto& [n, v] : c.members)
                if (v.k != jvalue::kind::string || !test("eq", lowered(n), v.s))
                {
                    if (v.k != jvalue::kind::string)
                        err = refusal("InvalidPolicyDocument", "Invalid Policy: Invalid Simple-Condition: value must be a string.");
                    return false;
                }
            continue;
        }
        if (c.k != jvalue::kind::array || c.items.empty() || c.items[0].k != jvalue::kind::string)
        {
            err = refusal("InvalidPolicyDocument", "Invalid Policy: Invalid Condition.");
            return false;
        }
        const std::string op = lowered(c.items[0].s);
        if (op == "content-length-range")
        {
            if (c.items.size() != 3 || !number_of(c.items[1], f.range_min) || !number_of(c.items[2], f.range_max))
            {
                err = refusal("InvalidPolicyDocument", "Invalid Policy: Invalid content-length-range.");
                return false;
            }
            f.has_range = true;
            continue;
        }
        if ((op != "eq" && op != "starts-with") || c.items.size() != 3 || c.items[1].k != jvalue::kind::string ||
            !c.items[1].s.starts_with('$') || c.items[2].k != jvalue::kind::string)
        {
            err = refusal("InvalidPolicyDocument", "Invalid Policy: Invalid Condition.");
            return false;
        }
        if (!test(op, lowered(std::string_view(c.items[1].s).substr(1)), c.items[2].s))
            return false;
    }
    // Every field is named by a condition, but the signature and its key, the policy, the file and x-ignore-*.
    for (const auto& [n, v] : f.fields)
    {
        if (n == "policy" || n == "x-amz-signature" || n == "signature" || n == "awsaccesskeyid" || n == "file" ||
            n.starts_with("x-ignore-") ||
            std::find(covered.begin(), covered.end(), n) != covered.end())
            continue;
        err = policy_refusal("Extra input fields: " + n);
        return false;
    }
    return true;
}

form_file_hook::form_file_hook(std::string_view boundary, bool has_range, uint64_t min, uint64_t max)
    : m_delim("\r\n--" + std::string(boundary)), m_has_range(has_range), m_min(min), m_max(max)
{
}

bool form_file_hook::feed(std::string_view raw, std::string& out, s3_error& err)
{
    if (m_done)
        return true;
    m_held.append(raw);
    size_t give = 0;
    if (const size_t at = m_held.find(m_delim); at != std::string::npos)
    {
        give   = at;
        m_done = true;
    }
    else if (m_held.size() >= m_delim.size())
        give = m_held.size() - (m_delim.size() - 1);
    out.append(m_held, 0, give);
    m_given += give;
    if (m_done)
        m_held.clear();
    else
        m_held.erase(0, give);
    if (m_has_range && m_given > m_max)
    {
        err = refusal("EntityTooLarge");
        return false;
    }
    return true;
}

bool form_file_hook::finish(std::string& /*out*/, s3_error& err)
{
    if (!m_done)
    {
        err = refusal("MalformedPOSTRequest");
        return false;
    }
    if (m_has_range && m_given < m_min)
    {
        err = refusal("EntityTooSmall");
        return false;
    }
    return true;
}

}   // namespace socketley::storage
