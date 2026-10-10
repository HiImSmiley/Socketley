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
            else if (k.name == "TargetGrants" && !out.grants_given)
            {
                out.grants_given = true;
                for (const xml_node& g : k.kids)
                {
                    logging_config::grant one;
                    for (const xml_node& f : g.kids)
                    {
                        if (f.name == "Permission" && (f.text == "FULL_CONTROL" || f.text == "READ" || f.text == "WRITE"))
                            one.permission = f.text;
                        else if (f.name == "Grantee")
                            for (const xml_node& who : f.kids)
                            {
                                if (who.name == "ID")
                                    one.kind = "id", one.value = who.text;
                                else if (who.name == "URI")
                                    one.kind = "uri", one.value = who.text;
                                else if (who.name == "EmailAddress")
                                    one.kind = "emailaddress", one.value = who.text;
                            }
                    }
                    if (g.name != "Grant" || one.kind.empty() || one.permission.empty())
                        return false;
                    out.grants.push_back(std::move(one));
                }
            }
            else if (k.name == "TargetObjectKeyFormat" && !format && k.kids.size() == 1)
            {
                format = true;
                const xml_node& f = k.kids[0];
                if (f.name == "PartitionedPrefix")
                {
                    for (const xml_node& p : f.kids)
                    {
                        if (p.name != "PartitionDateSource" || (p.text != "EventTime" && p.text != "DeliveryTime"))
                            return false;
                        out.event_time = p.text == "EventTime";
                    }
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
        if (!c->grants.empty())
        {
            x += "<TargetGrants>";
            for (const logging_config::grant& g : c->grants)
            {
                x += "<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"";
                x += g.kind == "id" ? "CanonicalUser\"><ID>" : g.kind == "uri" ? "Group\"><URI>"
                                                                                 : "AmazonCustomerByEmail\"><EmailAddress>";
                xml_escape_to(x, g.value);
                x += g.kind == "id" ? "</ID>" : g.kind == "uri" ? "</URI>" : "</EmailAddress>";
                x += "</Grantee><Permission>";
                x += g.permission;
                x += "</Permission></Grant>";
            }
            x += "</TargetGrants>";
        }
        // The key format is told whether it was given or left to its default.
        x += !c->partitioned ? "<TargetObjectKeyFormat><SimplePrefix/></TargetObjectKeyFormat>"
           : c->event_time   ? "<TargetObjectKeyFormat><PartitionedPrefix><PartitionDateSource>EventTime"
                               "</PartitionDateSource></PartitionedPrefix></TargetObjectKeyFormat>"
                             : "<TargetObjectKeyFormat><PartitionedPrefix><PartitionDateSource>DeliveryTime"
                               "</PartitionDateSource></PartitionedPrefix></TargetObjectKeyFormat>";
        x += "</LoggingEnabled>";
    }
    x += "</BucketLoggingStatus>";
    return x;
}

}   // namespace socketley::storage
