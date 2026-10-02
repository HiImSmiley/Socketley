#pragma once
// S3 event notifications with no I/O: a bucket's NotificationConfiguration, the events it asks for, and the JSON
// record an event is sent as.
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

#include "s3_names.h"
#include "s3_xml_tree.h"

namespace socketley::storage
{

// The most a NotificationConfiguration may be.
inline constexpr size_t notification_max_bytes = 64 * 1024;

// A webhook target is named by an ARN of this form, its name after the prefix.
inline constexpr std::string_view webhook_arn_prefix = "arn:socketley:webhook:::";

// The events this runtime emits, a bit each.
enum notify_event : uint16_t
{
    ev_put           = 1u << 0,
    ev_post          = 1u << 1,
    ev_copy          = 1u << 2,
    ev_complete      = 1u << 3,
    ev_delete        = 1u << 4,
    ev_marker        = 1u << 5,
    ev_lc_delete     = 1u << 6,
    ev_lc_marker     = 1u << 7,
    ev_tagging_put   = 1u << 8,
    ev_tagging_del   = 1u << 9,
};

// The name a record's eventName gives an event of one bit, which is S3's without its "s3:".
inline std::string_view notify_event_name(uint16_t bit)
{
    switch (bit)
    {
        case ev_put:         return "ObjectCreated:Put";
        case ev_post:        return "ObjectCreated:Post";
        case ev_copy:        return "ObjectCreated:Copy";
        case ev_complete:    return "ObjectCreated:CompleteMultipartUpload";
        case ev_delete:      return "ObjectRemoved:Delete";
        case ev_marker:      return "ObjectRemoved:DeleteMarkerCreated";
        case ev_lc_delete:   return "LifecycleExpiration:Delete";
        case ev_lc_marker:   return "LifecycleExpiration:DeleteMarkerCreated";
        case ev_tagging_put: return "ObjectTagging:Put";
        case ev_tagging_del: return "ObjectTagging:Delete";
        default:             return "";
    }
}

// The events an Event element names, false for a name S3 does not have; a name S3 has and this runtime never emits
// is zero bits.
inline bool notify_event_bits(std::string_view name, uint16_t& out)
{
    struct row { std::string_view name; uint16_t bits; };
    static constexpr row table[] = {
        {"s3:ObjectCreated:*", ev_put | ev_post | ev_copy | ev_complete},
        {"s3:ObjectCreated:Put", ev_put},
        {"s3:ObjectCreated:Post", ev_post},
        {"s3:ObjectCreated:Copy", ev_copy},
        {"s3:ObjectCreated:CompleteMultipartUpload", ev_complete},
        {"s3:ObjectRemoved:*", ev_delete | ev_marker},
        {"s3:ObjectRemoved:Delete", ev_delete},
        {"s3:ObjectRemoved:DeleteMarkerCreated", ev_marker},
        {"s3:LifecycleExpiration:*", ev_lc_delete | ev_lc_marker},
        {"s3:LifecycleExpiration:Delete", ev_lc_delete},
        {"s3:LifecycleExpiration:DeleteMarkerCreated", ev_lc_marker},
        {"s3:ObjectTagging:*", ev_tagging_put | ev_tagging_del},
        {"s3:ObjectTagging:Put", ev_tagging_put},
        {"s3:ObjectTagging:Delete", ev_tagging_del},
        {"s3:ObjectRestore:*", 0},
        {"s3:ObjectRestore:Post", 0},
        {"s3:ObjectRestore:Completed", 0},
        {"s3:ObjectRestore:Delete", 0},
        {"s3:ReducedRedundancyLostObject", 0},
        {"s3:Replication:*", 0},
        {"s3:Replication:OperationFailedReplication", 0},
        {"s3:Replication:OperationMissedThreshold", 0},
        {"s3:Replication:OperationReplicatedAfterThreshold", 0},
        {"s3:Replication:OperationNotTracked", 0},
        {"s3:LifecycleTransition", 0},
        {"s3:IntelligentTiering", 0},
        {"s3:ObjectAcl:Put", 0},
    };
    for (const row& r : table)
        if (r.name == name)
        {
            out = r.bits;
            return true;
        }
    return false;
}

// One configuration of a NotificationConfiguration: where the events it asks for go, and the keys it asks them of.
struct notify_rule
{
    std::string id;
    // Topic, Queue or CloudFunction, the element the ARN came in, kept to write it back as it was given.
    std::string kind;
    std::string arn;
    // The webhook target's name, the ARN's last field.
    std::string target;
    std::vector<std::string> events;
    uint16_t    bits{0};
    std::string prefix;
    std::string suffix;
};

struct notify_config
{
    std::vector<notify_rule> rules;
};

// Whether an event of `bit` on `key` is one `r` asks for.
inline bool notify_matches(const notify_rule& r, uint16_t bit, std::string_view key)
{
    return (r.bits & bit) != 0 && key.starts_with(r.prefix) && key.ends_with(r.suffix);
}

namespace detail
{

inline bool notify_refuse(s3_error& err, std::string message)
{
    err         = make_error("InvalidArgument");
    err.message = std::move(message);
    return false;
}

// The rule's Filter: an S3Key of at most one prefix and one suffix rule.
inline bool notify_filter(const xml_node& f, notify_rule& r, s3_error& err)
{
    bool prefix = false, suffix = false;
    for (const xml_node& s3key : f.kids)
    {
        if (s3key.name != "S3Key")
            return false;
        for (const xml_node& fr : s3key.kids)
        {
            if (fr.name != "FilterRule")
                return false;
            const xml_node* name = nullptr;
            const xml_node* value = nullptr;
            for (const xml_node& k : fr.kids)
            {
                if (!k.kids.empty())
                    return false;
                if (k.name == "Name" && !name)
                    name = &k;
                else if (k.name == "Value" && !value)
                    value = &k;
                else
                    return false;
            }
            if (!name || !value)
                return false;
            const bool is_prefix = name->text == "prefix" || name->text == "Prefix";
            const bool is_suffix = name->text == "suffix" || name->text == "Suffix";
            if (!is_prefix && !is_suffix)
                return notify_refuse(err, "filter rule name must be either prefix or suffix");
            if (value->text.size() > 1024)
                return notify_refuse(err, "The FilterRule value cannot be longer than 1024 characters.");
            if ((is_prefix && prefix) || (is_suffix && suffix))
                return notify_refuse(err, std::string("Cannot specify more than one ") + (is_prefix ? "prefix" : "suffix") +
                                              " rule in a filter.");
            (is_prefix ? r.prefix : r.suffix) = value->text;
            (is_prefix ? prefix : suffix)     = true;
        }
    }
    return true;
}

}   // namespace detail

// False with `err` for a configuration S3 would refuse: MalformedXML for one that is not a NotificationConfiguration
// of Topic, Queue and CloudFunction configurations, and InvalidArgument for an unknown event, a destination that is
// not a webhook's ARN, a bad filter, a repeated Id or two configurations that share an event on overlapping keys.
inline bool parse_notify_config(std::string_view xml, notify_config& out, s3_error& err)
{
    err = make_error("MalformedXML");
    out = notify_config{};
    xml_node root;
    if (xml.size() > notification_max_bytes || !xml_reader(xml).document(root) || root.name != "NotificationConfiguration")
        return false;
    for (const xml_node& c : root.kids)
    {
        if (c.name == "EventBridgeConfiguration")
            return detail::notify_refuse(err, "EventBridge is not a destination this endpoint can reach; name a "
                                              "webhook as " + std::string(webhook_arn_prefix) + "<name>.");
        std::string_view arn_element;
        if (c.name == "TopicConfiguration")
            arn_element = "Topic";
        else if (c.name == "QueueConfiguration")
            arn_element = "Queue";
        else if (c.name == "CloudFunctionConfiguration")
            arn_element = "CloudFunction";
        else
            return false;
        notify_rule r;
        r.kind = std::string(arn_element);
        bool has_id = false, has_arn = false, has_filter = false;
        for (const xml_node& k : c.kids)
        {
            if (k.name == "Id" && !has_id && k.kids.empty())
            {
                r.id   = k.text;
                has_id = true;
            }
            else if (k.name == arn_element && !has_arn && k.kids.empty())
            {
                r.arn   = k.text;
                has_arn = true;
            }
            else if (k.name == "Event" && k.kids.empty())
            {
                uint16_t bits = 0;
                if (!notify_event_bits(k.text, bits))
                    return detail::notify_refuse(err, "The event is not supported for notifications");
                r.bits |= bits;
                r.events.push_back(k.text);
            }
            else if (k.name == "Filter" && !has_filter)
            {
                has_filter = true;
                if (!detail::notify_filter(k, r, err))
                    return false;
            }
            else
                return false;
        }
        if (!has_arn || r.events.empty())
            return false;
        if (!r.arn.starts_with(webhook_arn_prefix) || r.arn.size() == webhook_arn_prefix.size())
            return detail::notify_refuse(err, "Unable to validate the following destination configurations");
        r.target = r.arn.substr(webhook_arn_prefix.size());
        if (r.id.empty())
            r.id = "notification-" + std::to_string(out.rules.size() + 1);
        for (const notify_rule& o : out.rules)
        {
            if (o.id == r.id)
                return detail::notify_refuse(err, "Configuration IDs must be unique.");
            const bool keys_overlap = (o.prefix.starts_with(r.prefix) || r.prefix.starts_with(o.prefix)) &&
                                      (o.suffix.ends_with(r.suffix) || r.suffix.ends_with(o.suffix));
            if ((o.bits & r.bits) != 0 && keys_overlap)
                return detail::notify_refuse(err, "Configurations overlap. Configurations on the same bucket cannot "
                                                  "share a common event type.");
        }
        out.rules.push_back(std::move(r));
    }
    return true;
}

// What GetBucketNotificationConfiguration answers, and what the bucket keeps, an empty configuration for none.
inline std::string notify_config_xml(const notify_config& c)
{
    std::string x(xml_decl);
    x += "<NotificationConfiguration xmlns=\"";
    x += s3_xmlns;
    x += "\">";
    for (const notify_rule& r : c.rules)
    {
        x += "<" + r.kind + "Configuration><Id>";
        xml_escape_to(x, r.id);
        x += "</Id><" + r.kind + ">";
        xml_escape_to(x, r.arn);
        x += "</" + r.kind + ">";
        for (const std::string& e : r.events)
        {
            x += "<Event>";
            xml_escape_to(x, e);
            x += "</Event>";
        }
        if (!r.prefix.empty() || !r.suffix.empty())
        {
            x += "<Filter><S3Key>";
            if (!r.prefix.empty())
            {
                x += "<FilterRule><Name>Prefix</Name><Value>";
                xml_escape_to(x, r.prefix);
                x += "</Value></FilterRule>";
            }
            if (!r.suffix.empty())
            {
                x += "<FilterRule><Name>Suffix</Name><Value>";
                xml_escape_to(x, r.suffix);
                x += "</Value></FilterRule>";
            }
            x += "</S3Key></Filter>";
        }
        x += "</" + r.kind + "Configuration>";
    }
    x += "</NotificationConfiguration>";
    return x;
}

// A key as an event record carries it: form-encoded, a space as '+', with '/' kept.
inline void notify_key_encode(std::string& out, std::string_view key)
{
    static constexpr char hex[] = "0123456789ABCDEF";
    for (const char ch : key)
    {
        const auto c = static_cast<unsigned char>(ch);
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
            c == '.' || c == '*' || c == '/')
            out += ch;
        else if (c == ' ')
            out += '+';
        else
        {
            out += '%';
            out += hex[c >> 4];
            out += hex[c & 15];
        }
    }
}

inline void notify_json_string(std::string& out, std::string_view s)
{
    out += '"';
    for (const char ch : s)
    {
        const auto c = static_cast<unsigned char>(ch);
        if (c == '"' || c == '\\')
        {
            out += '\\';
            out += ch;
        }
        else if (c < 0x20)
        {
            char buf[8];
            std::snprintf(buf, sizeof buf, "\\u%04x", c);
            out += buf;
        }
        else
            out += ch;
    }
    out += '"';
}

// What one event record says beyond its name.
struct notify_fields
{
    std::string_view bucket;
    std::string_view key;
    std::string_view config_id;
    std::string_view owner;
    std::string_view etag;
    std::string_view version_id;
    std::string_view sequencer;
    uint64_t         size{0};
    // Size and ETag are an object's, which a removal has none of.
    bool             has_object{false};
    int64_t          time_ms{0};
};

// The message a target is sent for one event: S3's Records array with the one record in it.
inline std::string notify_event_json(uint16_t bit, const notify_fields& f)
{
    std::string j;
    j.reserve(512 + f.key.size() * 3);
    j += R"({"Records":[{"eventVersion":"2.1","eventSource":"aws:s3","awsRegion":"us-east-1","eventTime":")";
    append_iso8601(j, f.time_ms);
    j += R"(","eventName":)";
    notify_json_string(j, notify_event_name(bit));
    j += R"(,"userIdentity":{"principalId":)";
    notify_json_string(j, f.owner);
    j += R"(},"requestParameters":{"sourceIPAddress":""},"responseElements":{},"s3":{"s3SchemaVersion":"1.0","configurationId":)";
    notify_json_string(j, f.config_id);
    j += R"(,"bucket":{"name":)";
    notify_json_string(j, f.bucket);
    j += R"(,"ownerIdentity":{"principalId":)";
    notify_json_string(j, f.owner);
    j += R"(},"arn":)";
    notify_json_string(j, "arn:aws:s3:::" + std::string(f.bucket));
    j += R"(},"object":{"key":")";
    notify_key_encode(j, f.key);
    j += '"';
    if (f.has_object)
    {
        j += R"(,"size":)";
        j += std::to_string(f.size);
        j += R"(,"eTag":)";
        notify_json_string(j, f.etag);
    }
    if (!f.version_id.empty())
    {
        j += R"(,"versionId":)";
        notify_json_string(j, f.version_id);
    }
    j += R"(,"sequencer":)";
    notify_json_string(j, f.sequencer);
    j += "}}}]}";
    return j;
}

}   // namespace socketley::storage
