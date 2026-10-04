#include "s3_logging.h"

#include "s3_xml_tree.h"

namespace socketley::storage
{

namespace
{

constexpr size_t logging_max_bytes = 16 * 1024;

bool leaf(const xml_node& n, std::string& out)
{
    if (!n.kids.empty())
        return false;
    out = n.text;
    return true;
}

}   // namespace

bool parse_logging_config(std::string_view xml, logging_config& out, s3_error& err)
{
    err = make_error("MalformedXML");
    out = logging_config{};
    xml_node root;
    if (xml.size() > logging_max_bytes || !xml_reader(xml).document(root) || root.name != "BucketLoggingStatus")
        return false;
    bool enabled = false;
    for (const xml_node& c : root.kids)
    {
        if (c.name != "LoggingEnabled" || enabled)
            return false;
        enabled = true;
        bool bucket = false, prefix = false, format = false;
        for (const xml_node& k : c.kids)
        {
            if (k.name == "TargetBucket" && !bucket && leaf(k, out.target_bucket))
                bucket = true;
            else if (k.name == "TargetPrefix" && !prefix && leaf(k, out.target_prefix))
                prefix = true;
            else if (k.name == "TargetGrants")
            {
                // A bucket whose ACLs are disabled takes no grants, as S3 refuses them for one.
                err         = make_error("AccessControlListNotSupported");
                err.message = "The bucket does not allow ACLs";
                return false;
            }
            else if (k.name == "TargetObjectKeyFormat" && !format && k.kids.size() == 1)
            {
                format = true;
                const xml_node& f = k.kids[0];
                if (f.name == "PartitionedPrefix")
                {
                    for (const xml_node& p : f.kids)
                        if (p.name != "PartitionDateSource" || (p.text != "EventTime" && p.text != "DeliveryTime"))
                            return false;
                    out.partitioned = true;
                }
                else if (f.name != "SimplePrefix" || !f.kids.empty())
                    return false;
            }
            else
                return false;
        }
        if (!bucket || out.target_bucket.empty())
            return false;
        if (out.target_prefix.size() > 512)
        {
            err         = make_error("InvalidArgument");
            err.message = "The TargetPrefix is longer than 512 bytes.";
            return false;
        }
    }
    return true;
}

std::string logging_config_xml(const logging_config* c)
{
    std::string x = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<BucketLoggingStatus xmlns=\"";
    x += s3_xmlns;
    x += "\">";
    if (c)
    {
        x += "<LoggingEnabled><TargetBucket>";
        xml_escape_to(x, c->target_bucket);
        x += "</TargetBucket><TargetPrefix>";
        xml_escape_to(x, c->target_prefix);
        x += "</TargetPrefix>";
        // The key format is told whether it was given or left to its default.
        x += c->partitioned ? "<TargetObjectKeyFormat><PartitionedPrefix><PartitionDateSource>DeliveryTime"
                              "</PartitionDateSource></PartitionedPrefix></TargetObjectKeyFormat>"
                            : "<TargetObjectKeyFormat><SimplePrefix/></TargetObjectKeyFormat>";
        x += "</LoggingEnabled>";
    }
    x += "</BucketLoggingStatus>";
    return x;
}

}   // namespace socketley::storage
