#include "s3_replication.h"

#include <algorithm>
#include <charconv>

#include "s3_tagging.h"
#include "s3_xml_tree.h"

namespace socketley::storage
{

namespace
{

bool refuse(s3_error& err, std::string_view code, std::string message)
{
    err         = make_error(std::string(code));
    err.message = std::move(message);
    return false;
}

// The text of a leaf element, false when it has children.
bool leaf(const xml_node& n, std::string& out)
{
    if (!n.kids.empty())
        return false;
    out = n.text;
    return true;
}

// A Status element that says Enabled or Disabled.
bool status_of(const xml_node& n, bool& enabled)
{
    std::string v;
    if (!leaf(n, v) || (v != "Enabled" && v != "Disabled"))
        return false;
    enabled = v == "Enabled";
    return true;
}

// An element whose only child is a Status, as DeleteMarkerReplication and its kind are.
bool status_block(const xml_node& n, bool& enabled)
{
    bool seen = false;
    for (const xml_node& k : n.kids)
    {
        if (k.name != "Status" || seen || !status_of(k, enabled))
            return false;
        seen = true;
    }
    return seen;
}

bool tag_of(const xml_node& n, std::pair<std::string, std::string>& out)
{
    bool has_key = false, has_value = false;
    for (const xml_node& k : n.kids)
    {
        if (k.name == "Key" && !has_key && leaf(k, out.first))
            has_key = true;
        else if (k.name == "Value" && !has_value && leaf(k, out.second))
            has_value = true;
        else
            return false;
    }
    return has_key && has_value;
}

bool filter_of(const xml_node& f, replication_rule& r, s3_error& err)
{
    if (f.kids.size() > 1)
        return false;
    if (f.kids.empty())
        return true;
    const xml_node& k = f.kids.front();
    if (k.name == "Prefix")
    {
        r.form = replication_rule::filter_form::prefix;
        return leaf(k, r.prefix);
    }
    if (k.name == "Tag")
    {
        r.form = replication_rule::filter_form::tag;
        r.tags.emplace_back();
        return tag_of(k, r.tags.back());
    }
    if (k.name != "And")
        return false;
    r.form = replication_rule::filter_form::both;
    bool has_prefix = false;
    for (const xml_node& a : k.kids)
    {
        if (a.name == "Prefix" && !has_prefix)
        {
            has_prefix = true;
            if (!leaf(a, r.prefix))
                return false;
        }
        else if (a.name == "Tag")
        {
            r.tags.emplace_back();
            if (!tag_of(a, r.tags.back()))
                return false;
        }
        else
            return false;
    }
    for (size_t i = 0; i < r.tags.size(); ++i)
        for (size_t j = i + 1; j < r.tags.size(); ++j)
            if (r.tags[i].first == r.tags[j].first)
                return refuse(err, "InvalidRequest", "Duplicate Tag Keys are not allowed.");
    return true;
}

bool destination_of(const xml_node& d, replication_rule& r, s3_error& err)
{
    bool has_bucket = false;
    for (const xml_node& k : d.kids)
    {
        std::string v;
        if (k.name == "Bucket" && !has_bucket && leaf(k, r.dest_arn))
            has_bucket = true;
        else if (k.name == "Account" && leaf(k, r.account))
            continue;
        else if (k.name == "StorageClass" && leaf(k, r.storage_class))
        {
            static constexpr std::string_view classes[] = {
                "STANDARD", "REDUCED_REDUNDANCY", "STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER",
                "DEEP_ARCHIVE", "OUTPOSTS", "GLACIER_IR",
            };
            if (std::find(std::begin(classes), std::end(classes), r.storage_class) == std::end(classes))
                return refuse(err, "InvalidStorageClass", "The storage class you specified is not valid");
        }
        else if (k.name == "AccessControlTranslation")
        {
            if (k.kids.size() != 1 || k.kids.front().name != "Owner" || !leaf(k.kids.front(), v) || v != "Destination")
                return false;
            r.owner_override = true;
        }
        else if (k.name == "EncryptionConfiguration")
            return refuse(err, "NotImplemented", "Replicas are encrypted as their source is, with SSE-S3; this "
                                                  "endpoint has no KMS to encrypt them with a ReplicaKmsKeyID");
        else if (k.name == "ReplicationTime" || k.name == "Metrics")
        {
            bool on = false;
            for (const xml_node& m : k.kids)
                if (m.name == "Status")
                {
                    // A status that is neither Enabled nor Disabled is malformed, not off.
                    if (!status_of(m, on))
                        return false;
                    if (on)
                        return refuse(err, "NotImplemented", "S3 Replication Time Control and replication metrics "
                                                              "are not offered by this endpoint");
                }
        }
        else
            return false;
    }
    if (!has_bucket)
        return false;
    if (!r.dest_arn.starts_with(bucket_arn_prefix) || !valid_bucket_name(r.dest_arn.substr(bucket_arn_prefix.size())))
        return refuse(err, "InvalidArgument", "Invalid bucket ARN.");
    r.dest_bucket = r.dest_arn.substr(bucket_arn_prefix.size());
    return true;
}

bool source_selection_of(const xml_node& s, replication_rule& r, s3_error& err)
{
    for (const xml_node& k : s.kids)
    {
        bool on = false;
        if (k.name == "SseKmsEncryptedObjects" && status_block(k, on))
        {
            r.has_sse_kms = true;
            r.sse_kms     = on;
        }
        else if (k.name == "ReplicaModifications" && status_block(k, on))
        {
            if (on)
                return refuse(err, "NotImplemented", "Replica modification sync is not offered by this endpoint; a "
                                                      "replica's changes stay on its side");
        }
        else
            return false;
    }
    return true;
}

bool rule_of(const xml_node& n, replication_rule& r, s3_error& err)
{
    bool has_id = false, has_priority = false, has_status = false, has_prefix = false, has_filter = false;
    bool has_dest = false, has_ssc = false;
    for (const xml_node& k : n.kids)
    {
        if (k.name == "ID" && !has_id && leaf(k, r.id))
        {
            has_id = true;
            if (r.id.size() > 255)
                return refuse(err, "InvalidArgument", "ID must be less than 255 characters");
        }
        else if (k.name == "Priority" && !has_priority)
        {
            std::string v;
            const auto res = leaf(k, v) ? std::from_chars(v.data(), v.data() + v.size(), r.priority)
                                        : std::from_chars_result{v.data(), std::errc::invalid_argument};
            if (res.ec != std::errc{} || res.ptr != v.data() + v.size() || r.priority < 0)
                return refuse(err, "InvalidArgument", "Priority must be a non-negative integer");
            has_priority = r.has_priority = true;
        }
        else if (k.name == "Status" && !has_status && status_of(k, r.enabled))
            has_status = true;
        else if (k.name == "Prefix" && !has_prefix && leaf(k, r.prefix))
            has_prefix = r.v1 = true;
        else if (k.name == "Filter" && !has_filter)
        {
            has_filter = true;
            if (!filter_of(k, r, err))
                return false;
        }
        else if (k.name == "Destination" && !has_dest)
        {
            has_dest = true;
            if (!destination_of(k, r, err))
                return false;
        }
        else if (k.name == "DeleteMarkerReplication" && !r.has_delete_markers && status_block(k, r.delete_markers))
            r.has_delete_markers = true;
        else if (k.name == "ExistingObjectReplication" && !r.has_existing)
        {
            bool on = false;
            if (!status_block(k, on))
                return false;
            if (on)
                return refuse(err, "NotImplemented", "Existing object replication is not offered by this endpoint; "
                                                      "only versions written after the configuration are replicated");
            r.has_existing = true;
        }
        else if (k.name == "SourceSelectionCriteria" && !has_ssc)
        {
            has_ssc = true;
            if (!source_selection_of(k, r, err))
                return false;
        }
        else
            return false;
    }
    if (!has_status || !has_dest || (has_prefix && has_filter))
        return false;
    if (r.prefix.size() > 1024)
        return refuse(err, "InvalidArgument", "Prefix must be less than 1024 characters");
    // The second schema names its keys with a Filter, and says whether delete markers go with them.
    if (!r.v1)
    {
        if (!r.has_delete_markers)
            return refuse(err, "InvalidRequest", "DeleteMarkerReplication must be specified for this version of "
                                                 "Cross Region Replication configuration schema.");
        if (r.delete_markers && !r.tags.empty())
            return refuse(err, "InvalidRequest", "Delete marker replication is not supported if any Tag filter is "
                                                 "specified. Please refer to S3 Developer Guide for more information.");
    }
    // The first schema sends every delete marker of the keys it names.
    else
        r.delete_markers = true;
    return true;
}

void escaped(std::string& x, std::string_view tag, std::string_view text)
{
    x += "<";
    x += tag;
    x += ">";
    xml_escape_to(x, text);
    x += "</";
    x += tag;
    x += ">";
}

void tag_xml(std::string& x, const std::pair<std::string, std::string>& t)
{
    x += "<Tag>";
    escaped(x, "Key", t.first);
    escaped(x, "Value", t.second);
    x += "</Tag>";
}

}   // namespace

bool parse_replication_config(std::string_view xml, replication_config& out, s3_error& err)
{
    err = make_error("MalformedXML");
    out = replication_config{};
    xml_node root;
    if (xml.size() > replication_max_bytes || !xml_reader(xml).document(root) || root.name != "ReplicationConfiguration")
        return false;
    bool has_role = false;
    for (const xml_node& c : root.kids)
    {
        if (c.name == "Role" && !has_role && leaf(c, out.role))
        {
            has_role = true;
            continue;
        }
        if (c.name != "Rule")
            return false;
        if (out.rules.size() >= replication_max_rules)
            return refuse(err, "InvalidRequest", "Number of rules in the replication configuration exceeds the "
                                                 "allowed limit of 1000 rules.");
        replication_rule r;
        if (!rule_of(c, r, err))
            return false;
        out.rules.push_back(std::move(r));
    }
    if (!has_role || out.rules.empty())
        return false;
    // The Role is what the replication acts as, which here is the target whose credentials it signs with.
    const size_t slash = out.role.rfind('/');
    if (!out.role.starts_with("arn:aws:iam::") || slash == std::string::npos || slash + 1 == out.role.size())
        return refuse(err, "InvalidArgument", "Invalid Role specified in replication configuration");
    out.target = out.role.substr(slash + 1);

    const bool v1 = out.rules.front().v1;
    for (size_t i = 0; i < out.rules.size(); ++i)
    {
        replication_rule& r = out.rules[i];
        if (r.v1 != v1)
            return refuse(err, "InvalidRequest", "Rules in a replication configuration all use Prefix or all use "
                                                 "Filter.");
        // A name given to a rule that has none is one no rule of the document gives itself.
        if (r.id.empty())
            for (size_t n = i + 1; r.id.empty(); ++n)
            {
                std::string id = "rule-" + std::to_string(n);
                if (std::none_of(out.rules.begin(), out.rules.end(), [&](const replication_rule& o) { return o.id == id; }))
                    r.id = std::move(id);
            }
        for (size_t j = 0; j < i; ++j)
        {
            const replication_rule& o = out.rules[j];
            if (o.id == r.id)
                return refuse(err, "InvalidArgument", "Rule Id must be unique. Found same ID for more than one rule");
            if (!v1 && o.has_priority && r.has_priority && o.priority == r.priority)
                return refuse(err, "InvalidArgument", "Found duplicate priority " + std::to_string(r.priority) +
                                                          " for rules. Priority must be unique.");
            // Overlap is refused for one destination, as the message says and S3 does, and not across two.
            if (v1 && o.dest_bucket == r.dest_bucket && (o.prefix.starts_with(r.prefix) || r.prefix.starts_with(o.prefix)))
                return refuse(err, "InvalidRequest", "Found overlapping prefixes '" + o.prefix + "' and '" +
                                                         r.prefix + "' for same destination bucket");
        }
    }
    return true;
}

std::string replication_config_xml(const replication_config& c)
{
    std::string x(xml_decl);
    x += "<ReplicationConfiguration xmlns=\"";
    x += s3_xmlns;
    x += "\">";
    escaped(x, "Role", c.role);
    for (const replication_rule& r : c.rules)
    {
        x += "<Rule>";
        escaped(x, "ID", r.id);
        if (r.has_priority)
            escaped(x, "Priority", std::to_string(r.priority));
        if (r.v1)
            escaped(x, "Prefix", r.prefix);
        else
        {
            x += "<Filter>";
            if (r.form == replication_rule::filter_form::prefix)
                escaped(x, "Prefix", r.prefix);
            else if (r.form == replication_rule::filter_form::tag && !r.tags.empty())
                tag_xml(x, r.tags.front());
            else if (r.form == replication_rule::filter_form::both)
            {
                x += "<And>";
                if (!r.prefix.empty())
                    escaped(x, "Prefix", r.prefix);
                for (const auto& t : r.tags)
                    tag_xml(x, t);
                x += "</And>";
            }
            x += "</Filter>";
        }
        escaped(x, "Status", r.enabled ? "Enabled" : "Disabled");
        if (r.has_sse_kms)
            x += std::string("<SourceSelectionCriteria><SseKmsEncryptedObjects><Status>") +
                 (r.sse_kms ? "Enabled" : "Disabled") + "</Status></SseKmsEncryptedObjects></SourceSelectionCriteria>";
        if (r.has_existing)
            x += "<ExistingObjectReplication><Status>Disabled</Status></ExistingObjectReplication>";
        x += "<Destination>";
        escaped(x, "Bucket", r.dest_arn);
        if (!r.account.empty())
            escaped(x, "Account", r.account);
        if (!r.storage_class.empty())
            escaped(x, "StorageClass", r.storage_class);
        if (r.owner_override)
            x += "<AccessControlTranslation><Owner>Destination</Owner></AccessControlTranslation>";
        x += "</Destination>";
        if (r.has_delete_markers)
            x += std::string("<DeleteMarkerReplication><Status>") + (r.delete_markers ? "Enabled" : "Disabled") +
                 "</Status></DeleteMarkerReplication>";
        x += "</Rule>";
    }
    x += "</ReplicationConfiguration>";
    return x;
}

std::vector<const replication_rule*> replication_rules_for(const replication_config& c, std::string_view key,
                                                            std::string_view tags, bool marker)
{
    std::vector<const replication_rule*> out;
    for (const replication_rule& r : c.rules)
    {
        // A delete marker has no tags, so a rule that asks for some never names one.
        if (!r.enabled || !key.starts_with(r.prefix) || (marker && !r.tags.empty()))
            continue;
        bool tagged = true;
        for (const auto& [k, v] : r.tags)
            tagged = tagged && tags_have(tags, k, v);
        if (!tagged)
            continue;
        // One rule per destination bucket decides, the one of the highest priority, and the first of equals.
        auto same = std::find_if(out.begin(), out.end(),
                                 [&](const replication_rule* o) { return o->dest_bucket == r.dest_bucket; });
        if (same == out.end())
            out.push_back(&r);
        else if (r.priority > (*same)->priority)
            *same = &r;
    }
    if (marker)
        std::erase_if(out, [](const replication_rule* r) { return !r->delete_markers; });
    return out;
}

}   // namespace socketley::storage
