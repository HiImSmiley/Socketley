#include "lifecycle.h"

#include <charconv>
#include <set>

#include "object_format.h"
#include "s3_names.h"
#include "s3_tagging.h"
#include "s3_xml.h"
#include "s3_xml_tree.h"
#include "../../shared/util/random_id.h"

namespace socketley::storage
{

namespace
{

s3_error fail(std::string_view code, std::string message = {})
{
    s3_error e = make_error(code);
    if (!message.empty())
        e.message = std::move(message);
    return e;
}

bool positive_days(const xml_node& n, uint32_t& out)
{
    std::string_view t = n.text;
    while (!t.empty() && (t.front() == ' ' || t.front() == '\n' || t.front() == '\t' || t.front() == '\r'))
        t.remove_prefix(1);
    while (!t.empty() && (t.back() == ' ' || t.back() == '\n' || t.back() == '\t' || t.back() == '\r'))
        t.remove_suffix(1);
    int64_t v = 0;
    const auto r = std::from_chars(t.data(), t.data() + t.size(), v);
    if (t.empty() || r.ec != std::errc{} || r.ptr != t.data() + t.size() || v <= 0 || v > INT32_MAX)
        return false;
    out = static_cast<uint32_t>(v);
    return true;
}

// S3 keeps at most 100 newer noncurrent versions of a key.
bool newer_versions(const xml_node& n, uint32_t& out)
{
    return positive_days(n, out) && out <= 100;
}

bool non_negative_days(const xml_node& n, uint32_t& out)
{
    std::string_view t = n.text;
    while (!t.empty() && (t.front() == ' ' || t.front() == '\n' || t.front() == '\t' || t.front() == '\r'))
        t.remove_prefix(1);
    while (!t.empty() && (t.back() == ' ' || t.back() == '\n' || t.back() == '\t' || t.back() == '\r'))
        t.remove_suffix(1);
    int64_t v = 0;
    const auto r = std::from_chars(t.data(), t.data() + t.size(), v);
    if (t.empty() || r.ec != std::errc{} || r.ptr != t.data() + t.size() || v < 0 || v > INT32_MAX)
        return false;
    out = static_cast<uint32_t>(v);
    return true;
}

// A storage class as a tier is named: what a targets file's names may be.
bool class_name_ok(std::string_view s)
{
    if (s.empty() || s.size() > 64)
        return false;
    for (const char ch : s)
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' ||
              ch == '_' || ch == '.'))
            return false;
    return true;
}

std::string new_rule_id()
{
    static constexpr char digits[] = "abcdefghijklmnopqrstuvwxyz234567";
    std::string id;
    for (int w = 0; w < 2; ++w)
    {
        uint64_t v = random_u64();
        for (int i = 0; i < 12; ++i, v >>= 5)
            id.push_back(digits[v & 31]);
    }
    return id;
}

// One condition of a <Filter> or of its <And> into `r`, false with `err` when it is none S3 knows or is not well formed.
bool filter_condition(const xml_node& k, lifecycle_rule& r, s3_error& err)
{
    if (k.name == "Prefix" && k.kids.empty() && !r.filter_prefix)
    {
        r.prefix        = k.text;
        r.filter_prefix = true;
        return true;
    }
    if (k.name == "Tag")
    {
        const xml_node* key   = nullptr;
        const xml_node* value = nullptr;
        for (const xml_node& f : k.kids)
        {
            const xml_node** slot = f.name == "Key" ? &key : f.name == "Value" ? &value : nullptr;
            if (!slot || *slot || !f.kids.empty())
            {
                err = fail("MalformedXML");
                return false;
            }
            *slot = &f;
        }
        if (!key || !value)
        {
            err = fail("MalformedXML");
            return false;
        }
        for (const auto& t : r.tags)
            if (t.first == key->text)
            {
                err = fail("InvalidRequest", "Duplicate Tag Keys are not allowed.");
                return false;
            }
        const tag_set one{{key->text, value->text}};
        if (!check_tags(one, err))
            return false;
        r.tags.push_back(one.front());
        return true;
    }
    const bool gt = k.name == "ObjectSizeGreaterThan";
    if ((gt || k.name == "ObjectSizeLessThan") && k.kids.empty() && !(gt ? r.has_size_gt : r.has_size_lt))
    {
        std::string_view t = k.text;
        while (!t.empty() && (t.front() == ' ' || t.front() == '\n' || t.front() == '\t' || t.front() == '\r'))
            t.remove_prefix(1);
        while (!t.empty() && (t.back() == ' ' || t.back() == '\n' || t.back() == '\t' || t.back() == '\r'))
            t.remove_suffix(1);
        uint64_t v = 0;
        const auto res = std::from_chars(t.data(), t.data() + t.size(), v);
        if (t.empty() || res.ec != std::errc{} || res.ptr != t.data() + t.size() || (!gt && v == 0))
        {
            err = fail("InvalidArgument", std::string("'") + k.name + "' must be " +
                                              (gt ? "a non-negative integer" : "a positive integer"));
            return false;
        }
        (gt ? r.has_size_gt : r.has_size_lt) = true;
        (gt ? r.size_gt : r.size_lt)         = v;
        return true;
    }
    err = fail("MalformedXML");
    return false;
}

// One <Rule>, or the error the whole document is refused with.
bool parse_rule(const xml_node& n, lifecycle_rule& r, s3_error& err)
{
    const xml_node* id = nullptr;
    const xml_node* status = nullptr;
    const xml_node* filter = nullptr;
    const xml_node* prefix = nullptr;
    const xml_node* expiration = nullptr;
    const xml_node* noncurrent = nullptr;
    const xml_node* abort = nullptr;
    const xml_node* transition = nullptr;
    const xml_node* noncurrent_transition = nullptr;
    auto once = [&](const xml_node*& slot, const xml_node& k) -> bool
    {
        if (slot)
            return false;
        slot = &k;
        return true;
    };
    for (const xml_node& k : n.kids)
    {
        bool fresh = true;
        if (k.name == "ID")
            fresh = once(id, k);
        else if (k.name == "Status")
            fresh = once(status, k);
        else if (k.name == "Filter")
            fresh = once(filter, k);
        else if (k.name == "Prefix")
            fresh = once(prefix, k);
        else if (k.name == "Expiration")
            fresh = once(expiration, k);
        else if (k.name == "AbortIncompleteMultipartUpload")
            fresh = once(abort, k);
        else if (k.name == "Transition" || k.name == "NoncurrentVersionTransition")
        {
            // One transition of each kind a rule, since a tier is where a version stays.
            const xml_node*& slot = k.name == "Transition" ? transition : noncurrent_transition;
            if (slot)
            {
                err = fail("NotImplemented", "A rule moves objects to one storage class");
                return false;
            }
            slot = &k;
        }
        else if (k.name == "NoncurrentVersionExpiration")
            fresh = once(noncurrent, k);
        else
        {
            err = fail("MalformedXML");
            return false;
        }
        if (!fresh)
        {
            err = fail("MalformedXML");
            return false;
        }
    }

    if (id && !id->kids.empty())
    {
        err = fail("MalformedXML");
        return false;
    }
    r.id = id ? id->text : std::string{};
    if (r.id.size() > lifecycle_max_id)
    {
        err = fail("InvalidArgument", "ID length should not exceed allowed limit of 255");
        return false;
    }

    if (!status || !status->kids.empty() || (status->text != "Enabled" && status->text != "Disabled"))
    {
        err = fail("MalformedXML");
        return false;
    }
    r.enabled = status->text == "Enabled";

    // Exactly one of the rule's own <Prefix> and a <Filter> says what the rule covers.
    if ((filter != nullptr) == (prefix != nullptr))
    {
        err = fail("MalformedXML");
        return false;
    }
    if (prefix)
    {
        if (!prefix->kids.empty())
        {
            err = fail("MalformedXML");
            return false;
        }
        r.prefix = prefix->text;
        r.legacy_prefix = true;
    }
    else
    {
        if (filter->kids.size() > 1)
        {
            err = fail("MalformedXML");
            return false;
        }
        for (const xml_node& k : filter->kids)
        {
            if (k.name != "And")
            {
                if (!filter_condition(k, r, err))
                    return false;
                continue;
            }
            r.filter_and = true;
            if (k.kids.empty())
            {
                err = fail("MalformedXML");
                return false;
            }
            for (const xml_node& a : k.kids)
                if (!filter_condition(a, r, err))
                    return false;
        }
        if (filter->has_text && filter->text.find_first_not_of(" \t\r\n") != std::string::npos)
        {
            err = fail("MalformedXML");
            return false;
        }
        if (r.has_size_gt && r.has_size_lt && r.size_gt >= r.size_lt)
        {
            err = fail("InvalidRequest", "ObjectSizeLessThan must be greater than ObjectSizeGreaterThan");
            return false;
        }
    }
    if (r.prefix.size() > max_key_bytes)
    {
        err = fail("InvalidArgument", "The prefix is longer than a key can be");
        return false;
    }

    if (expiration)
    {
        const xml_node* days = nullptr;
        const xml_node* date = nullptr;
        const xml_node* marker = nullptr;
        for (const xml_node& k : expiration->kids)
        {
            bool fresh = true;
            if (k.name == "Days")
                fresh = once(days, k);
            else if (k.name == "Date")
                fresh = once(date, k);
            else if (k.name == "ExpiredObjectDeleteMarker")
                fresh = once(marker, k);
            else
                fresh = false;
            if (!fresh || !k.kids.empty())
            {
                err = fail("MalformedXML");
                return false;
            }
        }
        if ((days != nullptr) + (date != nullptr) + (marker != nullptr) != 1)
        {
            err = fail("MalformedXML");
            return false;
        }
        if (days && !positive_days(*days, r.expire_days))
        {
            err = fail("InvalidArgument", "'Days' for Expiration action must be a positive integer");
            return false;
        }
        if (date)
        {
            bool midnight = false;
            if (!parse_iso8601(date->text, r.expire_date_ms, midnight))
            {
                err = fail("InvalidArgument", "'Date' must be an ISO 8601 date");
                return false;
            }
            if (!midnight)
            {
                err = fail("InvalidArgument", "'Date' must be at midnight GMT");
                return false;
            }
            r.has_date = true;
        }
        if (marker)
        {
            if (marker->text != "true" && marker->text != "false")
            {
                err = fail("MalformedXML");
                return false;
            }
            r.delete_marker = marker->text == "true" ? 1 : 0;
        }
    }

    if (noncurrent)
    {
        const xml_node* days  = nullptr;
        const xml_node* newer = nullptr;
        for (const xml_node& k : noncurrent->kids)
        {
            const bool fresh = k.name == "NoncurrentDays" ? once(days, k)
                             : k.name == "NewerNoncurrentVersions" ? once(newer, k) : false;
            if (!fresh || !k.kids.empty())
            {
                err = fail("MalformedXML");
                return false;
            }
        }
        if (newer && !newer_versions(*newer, r.noncurrent_newer))
        {
            err = fail("InvalidArgument", "'NewerNoncurrentVersions' for NoncurrentVersionExpiration action must be a "
                                          "positive integer no greater than 100");
            return false;
        }
        if (!days)
        {
            err = fail("MalformedXML");
            return false;
        }
        if (!positive_days(*days, r.noncurrent_days))
        {
            err = fail("InvalidArgument", "'NoncurrentDays' for NoncurrentVersionExpiration action must be a positive integer");
            return false;
        }
    }

    if (transition)
    {
        const xml_node* days = nullptr;
        const xml_node* date = nullptr;
        const xml_node* cls  = nullptr;
        for (const xml_node& k : transition->kids)
        {
            const bool fresh = k.name == "Days" ? once(days, k) : k.name == "Date" ? once(date, k)
                             : k.name == "StorageClass" ? once(cls, k) : false;
            if (!fresh || !k.kids.empty())
            {
                err = fail("MalformedXML");
                return false;
            }
        }
        if (!cls || (days != nullptr) == (date != nullptr))
        {
            err = fail("MalformedXML");
            return false;
        }
        if (days && !non_negative_days(*days, r.transition_days))
        {
            err = fail("InvalidArgument", "'Days' for Transition action must be a non-negative integer");
            return false;
        }
        if (date)
        {
            bool midnight = false;
            if (!parse_iso8601(date->text, r.transition_date_ms, midnight) || !midnight)
            {
                err = fail("InvalidArgument", "'Date' must be an ISO 8601 date at midnight GMT");
                return false;
            }
            r.has_transition_date = true;
        }
        if (!class_name_ok(cls->text))
        {
            err = fail("InvalidStorageClass");
            return false;
        }
        r.transition_class = cls->text;
        r.has_transition   = true;
    }

    if (noncurrent_transition)
    {
        const xml_node* days  = nullptr;
        const xml_node* cls   = nullptr;
        const xml_node* newer = nullptr;
        for (const xml_node& k : noncurrent_transition->kids)
        {
            const bool fresh = k.name == "NoncurrentDays" ? once(days, k) : k.name == "StorageClass" ? once(cls, k)
                             : k.name == "NewerNoncurrentVersions" ? once(newer, k) : false;
            if (!fresh || !k.kids.empty())
            {
                err = fail("MalformedXML");
                return false;
            }
        }
        if (newer && !newer_versions(*newer, r.noncurrent_transition_newer))
        {
            err = fail("InvalidArgument", "'NewerNoncurrentVersions' for NoncurrentVersionTransition action must be a "
                                          "positive integer no greater than 100");
            return false;
        }
        if (!days || !cls)
        {
            err = fail("MalformedXML");
            return false;
        }
        if (!non_negative_days(*days, r.noncurrent_transition_days))
        {
            err = fail("InvalidArgument",
                       "'NoncurrentDays' for NoncurrentVersionTransition action must be a non-negative integer");
            return false;
        }
        if (!class_name_ok(cls->text))
        {
            err = fail("InvalidStorageClass");
            return false;
        }
        r.noncurrent_transition_class = cls->text;
        r.has_noncurrent_transition   = true;
    }

    if (abort)
    {
        if (abort->kids.size() != 1 || abort->kids[0].name != "DaysAfterInitiation" || !abort->kids[0].kids.empty())
        {
            err = fail("MalformedXML");
            return false;
        }
        if (!positive_days(abort->kids[0], r.abort_days))
        {
            err = fail("InvalidArgument",
                       "'DaysAfterInitiation' for AbortIncompleteMultipartUpload action must be a positive integer");
            return false;
        }
    }

    if (!expiration && !abort && !noncurrent && !transition && !noncurrent_transition)
    {
        err = fail("InvalidRequest", "At least one action needs to be specified in a rule");
        return false;
    }
    // An upload has no tags and no size yet, so a rule that asks for them cannot abort one.
    if (abort && !r.tags.empty())
    {
        err = fail("InvalidRequest", "AbortIncompleteMultipartUpload cannot be specified with Tags.");
        return false;
    }
    if (abort && (r.has_size_gt || r.has_size_lt))
    {
        err = fail("InvalidRequest", "AbortIncompleteMultipartUpload cannot be specified with an object size filter.");
        return false;
    }
    if (r.delete_marker >= 0 && !r.tags.empty())
    {
        err = fail("InvalidRequest", "ExpiredObjectDeleteMarker cannot be specified with Tags.");
        return false;
    }
    return true;
}

void filter_condition_xml(std::string& x, const lifecycle_rule& r)
{
    if (r.filter_prefix)
    {
        x += "<Prefix>";
        xml_escape_to(x, r.prefix);
        x += "</Prefix>";
    }
    for (const auto& [k, v] : r.tags)
    {
        x += "<Tag><Key>";
        xml_escape_to(x, k);
        x += "</Key><Value>";
        xml_escape_to(x, v);
        x += "</Value></Tag>";
    }
    if (r.has_size_gt)
        x += "<ObjectSizeGreaterThan>" + std::to_string(r.size_gt) + "</ObjectSizeGreaterThan>";
    if (r.has_size_lt)
        x += "<ObjectSizeLessThan>" + std::to_string(r.size_lt) + "</ObjectSizeLessThan>";
}

}   // namespace

bool parse_lifecycle(std::string_view xml, lifecycle_config& out, s3_error& err)
{
    out = lifecycle_config{};
    xml_node root;
    xml_reader reader(xml);
    if (!reader.document(root) || root.name != "LifecycleConfiguration" || root.kids.empty())
    {
        err = fail("MalformedXML");
        return false;
    }
    for (const xml_node& k : root.kids)
        if (k.name != "Rule")
        {
            err = fail("MalformedXML");
            return false;
        }
    if (root.kids.size() > lifecycle_max_rules)
    {
        err = fail("InvalidArgument", "A lifecycle configuration may hold at most 1000 rules");
        return false;
    }

    std::set<std::string, std::less<>> ids;
    out.rules.reserve(root.kids.size());
    for (const xml_node& k : root.kids)
    {
        lifecycle_rule r;
        if (!parse_rule(k, r, err))
            return false;
        if (!r.id.empty() && !ids.insert(r.id).second)
        {
            err = fail("InvalidArgument", "Rule ID must be unique. Found same ID for more than one rule");
            return false;
        }
        out.rules.push_back(std::move(r));
    }
    // A rule without an ID is given one, as S3 does, once every given ID is known.
    for (lifecycle_rule& r : out.rules)
        while (r.id.empty())
        {
            r.id = new_rule_id();
            if (!ids.insert(r.id).second)
                r.id.clear();
        }
    if (lifecycle_xml(out).size() > lifecycle_max_bytes)
    {
        err = fail("InvalidArgument", "The lifecycle configuration is larger than 4 MiB");
        return false;
    }
    return true;
}

std::string lifecycle_xml(const lifecycle_config& c)
{
    std::string x(xml_decl);
    x += "<LifecycleConfiguration xmlns=\"";
    x += s3_xmlns;
    x += "\">";
    for (const lifecycle_rule& r : c.rules)
    {
        x += "<Rule><ID>";
        xml_escape_to(x, r.id);
        x += "</ID>";
        if (r.legacy_prefix)
        {
            x += "<Prefix>";
            xml_escape_to(x, r.prefix);
            x += "</Prefix>";
        }
        else
        {
            x += r.filter_and ? "<Filter><And>" : "<Filter>";
            filter_condition_xml(x, r);
            x += r.filter_and ? "</And></Filter>" : "</Filter>";
        }
        x += r.enabled ? "<Status>Enabled</Status>" : "<Status>Disabled</Status>";
        if (r.expire_days != 0)
            x += "<Expiration><Days>" + std::to_string(r.expire_days) + "</Days></Expiration>";
        else if (r.has_date)
            x += "<Expiration><Date>" + iso8601(r.expire_date_ms) + "</Date></Expiration>";
        else if (r.delete_marker >= 0)
            x += r.delete_marker ? "<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration>"
                                 : "<Expiration><ExpiredObjectDeleteMarker>false</ExpiredObjectDeleteMarker></Expiration>";
        if (r.has_transition)
        {
            x += r.has_transition_date ? "<Transition><Date>" + iso8601(r.transition_date_ms) + "</Date>"
                                       : "<Transition><Days>" + std::to_string(r.transition_days) + "</Days>";
            x += "<StorageClass>" + r.transition_class + "</StorageClass></Transition>";
        }
        const auto newer_xml = [](uint32_t n)
        {
            return n == 0 ? std::string() : "<NewerNoncurrentVersions>" + std::to_string(n) + "</NewerNoncurrentVersions>";
        };
        if (r.noncurrent_days != 0)
            x += "<NoncurrentVersionExpiration><NoncurrentDays>" + std::to_string(r.noncurrent_days) + "</NoncurrentDays>" +
                 newer_xml(r.noncurrent_newer) + "</NoncurrentVersionExpiration>";
        if (r.has_noncurrent_transition)
            x += "<NoncurrentVersionTransition><NoncurrentDays>" + std::to_string(r.noncurrent_transition_days) +
                 "</NoncurrentDays>" + newer_xml(r.noncurrent_transition_newer) + "<StorageClass>" +
                 r.noncurrent_transition_class + "</StorageClass></NoncurrentVersionTransition>";
        if (r.abort_days != 0)
            x += "<AbortIncompleteMultipartUpload><DaysAfterInitiation>" + std::to_string(r.abort_days) +
                 "</DaysAfterInitiation></AbortIncompleteMultipartUpload>";
        x += "</Rule>";
    }
    x += "</LifecycleConfiguration>";
    return x;
}

int64_t lifecycle_due_ms(int64_t from_ms, uint32_t days, int64_t day_ms)
{
    const int64_t at = from_ms + static_cast<int64_t>(days) * day_ms;
    const int64_t rem = at % day_ms;
    if (rem == 0)
        return at;
    return at + (rem > 0 ? day_ms - rem : -rem);
}

namespace
{

// Whether the rule's filter takes the object: its prefix, its size bounds and every tag it names.
bool filter_takes(const lifecycle_rule& r, std::string_view key, const object_meta& m)
{
    if (!key.starts_with(r.prefix))
        return false;
    if ((r.has_size_gt && m.size <= r.size_gt) || (r.has_size_lt && m.size >= r.size_lt))
        return false;
    const std::string_view stored = r.tags.empty() ? std::string_view{} : tags_of(m);
    for (const auto& [k, v] : r.tags)
        if (!tags_have(stored, k, v))
            return false;
    return true;
}

// When an object the rule takes expires under it.
int64_t expiry_of(const lifecycle_rule& r, const object_meta& m, int64_t day_ms)
{
    return r.has_date ? r.expire_date_ms : lifecycle_due_ms(m.mtime_ms, r.expire_days, day_ms);
}

}   // namespace

bool lifecycle_expiry(const lifecycle_config& c, std::string_view key, const object_meta& m, int64_t day_ms,
                      int64_t& at_ms, const lifecycle_rule*& rule)
{
    rule = nullptr;
    for (const lifecycle_rule& r : c.rules)
        if (r.expires() && filter_takes(r, key, m))
            if (const int64_t at = expiry_of(r, m, day_ms); !rule || at < at_ms)
            {
                at_ms = at;
                rule  = &r;
            }
    return rule != nullptr;
}

bool lifecycle_object_due(const lifecycle_rule& r, std::string_view key, const object_meta& m, int64_t now_ms,
                          int64_t day_ms)
{
    return r.expires() && filter_takes(r, key, m) && now_ms >= expiry_of(r, m, day_ms);
}

bool lifecycle_noncurrent_due(const lifecycle_rule& r, std::string_view key, const object_meta& m, int64_t since_ms,
                              uint32_t newer, int64_t now_ms, int64_t day_ms)
{
    return r.enabled && r.noncurrent_days != 0 && newer >= r.noncurrent_newer && filter_takes(r, key, m) &&
           now_ms >= lifecycle_due_ms(since_ms, r.noncurrent_days, day_ms);
}

bool lifecycle_transition_due(const lifecycle_rule& r, std::string_view key, const object_meta& m, int64_t now_ms,
                              int64_t day_ms)
{
    if (!r.transitions() || !filter_takes(r, key, m))
        return false;
    return now_ms >= (r.has_transition_date ? r.transition_date_ms
                                            : lifecycle_due_ms(m.mtime_ms, r.transition_days, day_ms));
}

bool lifecycle_noncurrent_transition_due(const lifecycle_rule& r, std::string_view key, const object_meta& m,
                                         int64_t since_ms, uint32_t newer, int64_t now_ms, int64_t day_ms)
{
    return r.enabled && r.has_noncurrent_transition && newer >= r.noncurrent_transition_newer && filter_takes(r, key, m) &&
           now_ms >= lifecycle_due_ms(since_ms, r.noncurrent_transition_days, day_ms);
}

std::vector<std::string> lifecycle_classes(const lifecycle_config& c)
{
    std::vector<std::string> out;
    for (const lifecycle_rule& r : c.rules)
    {
        if (r.has_transition)
            out.push_back(r.transition_class);
        if (r.has_noncurrent_transition)
            out.push_back(r.noncurrent_transition_class);
    }
    return out;
}

bool lifecycle_upload_due(const lifecycle_rule& r, std::string_view key, int64_t initiated_ms, int64_t now_ms,
                          int64_t day_ms)
{
    return r.aborts() && key.starts_with(r.prefix) &&
           now_ms >= lifecycle_due_ms(initiated_ms, r.abort_days, day_ms);
}

}   // namespace socketley::storage
