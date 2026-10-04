#include "s3_public_access.h"

#include "s3_xml_tree.h"

namespace socketley::storage
{

namespace
{

constexpr size_t public_access_max_bytes = 4096;

bool flag(const xml_node& n, bool& out)
{
    if (!n.kids.empty())
        return false;
    if (n.text == "true" || n.text == "TRUE" || n.text == "True")
        out = true;
    else if (n.text == "false" || n.text == "FALSE" || n.text == "False")
        out = false;
    else
        return false;
    return true;
}

void flag_element(std::string& x, std::string_view name, bool v)
{
    x += "<";
    x += name;
    x += v ? ">true</" : ">false</";
    x += name;
    x += ">";
}

}   // namespace

bool parse_public_access_block(std::string_view xml, public_access_block& out, s3_error& err)
{
    err = make_error("MalformedXML");
    out = public_access_block{};
    xml_node root;
    if (xml.size() > public_access_max_bytes || !xml_reader(xml).document(root) ||
        root.name != "PublicAccessBlockConfiguration")
        return false;
    unsigned seen = 0;
    for (const xml_node& c : root.kids)
    {
        const unsigned bit = c.name == "BlockPublicAcls" ? 1u : c.name == "IgnorePublicAcls" ? 2u
                           : c.name == "BlockPublicPolicy" ? 4u : c.name == "RestrictPublicBuckets" ? 8u : 0u;
        bool& field = bit == 1 ? out.block_public_acls : bit == 2 ? out.ignore_public_acls
                    : bit == 4 ? out.block_public_policy : out.restrict_public_buckets;
        if (!bit || (seen & bit) || !flag(c, field))
            return false;
        seen |= bit;
    }
    return true;
}

std::string public_access_block_xml(const public_access_block& p)
{
    std::string x = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<PublicAccessBlockConfiguration xmlns=\"";
    x += s3_xmlns;
    x += "\">";
    flag_element(x, "BlockPublicAcls", p.block_public_acls);
    flag_element(x, "IgnorePublicAcls", p.ignore_public_acls);
    flag_element(x, "BlockPublicPolicy", p.block_public_policy);
    flag_element(x, "RestrictPublicBuckets", p.restrict_public_buckets);
    x += "</PublicAccessBlockConfiguration>";
    return x;
}

}   // namespace socketley::storage
