#include "s3_quota.h"

#include <charconv>

#include "s3_xml_tree.h"
#include "../../shared/util/number_parse.h"

namespace socketley::storage
{

namespace
{

// The most a quota document is read as, which a sane one is a fraction of.
constexpr size_t quota_max_bytes = 4096;

bool whole_number(const xml_node& n, uint64_t& out)
{
    return n.kids.empty() && socketley::parse_whole(n.text, out);
}

}   // namespace

bool parse_bucket_quota(std::string_view xml, bucket_quota& out, s3_error& err)
{
    err = make_error("MalformedXML");
    out = bucket_quota{};
    xml_node root;
    if (xml.size() > quota_max_bytes || !xml_reader(xml).document(root) || root.name != "BucketQuota")
        return false;
    bool bytes = false, objects = false;
    for (const xml_node& c : root.kids)
    {
        if (c.name == "MaxBytes" && !bytes && whole_number(c, out.max_bytes))
            bytes = true;
        else if (c.name == "MaxObjects" && !objects && whole_number(c, out.max_objects))
            objects = true;
        else
            return false;
    }
    return true;
}

std::string bucket_quota_xml(const bucket_quota& q)
{
    std::string x = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<BucketQuota xmlns=\"";
    x += s3_xmlns;
    x += "\">";
    if (q.max_bytes)
        x += "<MaxBytes>" + std::to_string(q.max_bytes) + "</MaxBytes>";
    if (q.max_objects)
        x += "<MaxObjects>" + std::to_string(q.max_objects) + "</MaxObjects>";
    x += "</BucketQuota>";
    return x;
}

}   // namespace socketley::storage
