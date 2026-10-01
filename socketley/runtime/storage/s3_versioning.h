#pragma once
// A bucket's VersioningConfiguration, read and written back, with no I/O.
#include <string>
#include <string_view>

#include "s3_xml_tree.h"

namespace socketley::storage
{

// The most a document may be, which is far more than the two elements it has.
inline constexpr size_t versioning_max_bytes = 4096;

// False with `err` for a document S3 would refuse: a status other than Enabled or Suspended, or MFA delete,
// which needs a device this runtime has no way to ask.
inline bool parse_versioning(std::string_view xml, versioning& out, s3_error& err)
{
    err = make_error("MalformedXML");
    xml_node root;
    if (xml.size() > versioning_max_bytes || !xml_reader(xml).document(root) || root.name != "VersioningConfiguration")
        return false;
    const xml_node* status = nullptr;
    for (const xml_node& k : root.kids)
    {
        if (!k.kids.empty())
            return false;
        if (k.name == "Status" && !status)
            status = &k;
        else if (k.name == "MfaDelete")
        {
            if (k.text == "Enabled")
            {
                err = make_error("NotImplemented");
                err.message = "MFA delete is not supported";
                return false;
            }
            if (k.text != "Disabled")
                return false;
        }
        else
            return false;
    }
    if (!status || (status->text != "Enabled" && status->text != "Suspended"))
        return false;
    out = status->text == "Enabled" ? versioning::enabled : versioning::suspended;
    return true;
}

// What GetBucketVersioning answers, an empty configuration for a bucket that was never versioned.
inline std::string versioning_xml(versioning v)
{
    std::string x(xml_decl);
    x += "<VersioningConfiguration xmlns=\"";
    x += s3_xmlns;
    x += "\">";
    if (v == versioning::enabled)
        x += "<Status>Enabled</Status>";
    else if (v == versioning::suspended)
        x += "<Status>Suspended</Status>";
    x += "</VersioningConfiguration>";
    return x;
}

}   // namespace socketley::storage
