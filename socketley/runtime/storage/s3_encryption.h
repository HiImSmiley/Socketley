#pragma once
// A bucket's ServerSideEncryptionConfiguration, read and written back, with no I/O.
#include <string>
#include <string_view>

#include "s3_xml_tree.h"

namespace socketley::storage
{

// The most a document may be, which is far more than the one rule it has.
inline constexpr size_t encryption_max_bytes = 4096;

// False with `err` for a document S3 would refuse, and for SSE-KMS, which this runtime has no key service for.
inline bool parse_encryption(std::string_view xml, s3_error& err)
{
    err = make_error("MalformedXML");
    xml_node root;
    if (xml.size() > encryption_max_bytes || !xml_reader(xml).document(root) ||
        root.name != "ServerSideEncryptionConfiguration" || root.kids.size() != 1 || root.kids[0].name != "Rule")
        return false;
    const xml_node* algorithm = nullptr;
    bool kms_key = false;
    for (const xml_node& k : root.kids[0].kids)
    {
        if (k.name == "BucketKeyEnabled" && k.kids.empty() && (k.text == "true" || k.text == "false"))
            continue;
        if (k.name != "ApplyServerSideEncryptionByDefault" || algorithm)
            return false;
        for (const xml_node& d : k.kids)
        {
            if (!d.kids.empty())
                return false;
            if (d.name == "SSEAlgorithm" && !algorithm)
                algorithm = &d;
            else if (d.name == "KMSMasterKeyID" && !kms_key)
                kms_key = true;
            else
                return false;
        }
        if (!algorithm)
            return false;
    }
    if (!algorithm)
        return false;
    if (algorithm->text == "aws:kms" || algorithm->text == "aws:kms:dsse")
    {
        err = make_error("NotImplemented");
        err.message = "SSE-KMS is not supported by this runtime; AES256 is";
        return false;
    }
    if (algorithm->text != "AES256")
        return false;
    if (kms_key)
    {
        err = make_error("InvalidArgument");
        err.message = "a KMSMasterKeyID is only valid with aws:kms";
        return false;
    }
    return true;
}

// What GetBucketEncryption answers for a bucket that encrypts its new objects, which is also the document kept.
inline std::string encryption_xml()
{
    std::string x(xml_decl);
    x += "<ServerSideEncryptionConfiguration xmlns=\"";
    x += s3_xmlns;
    x += "\"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm>"
         "</ApplyServerSideEncryptionByDefault><BucketKeyEnabled>false</BucketKeyEnabled></Rule>"
         "</ServerSideEncryptionConfiguration>";
    return x;
}

}   // namespace socketley::storage
