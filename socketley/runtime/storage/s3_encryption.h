#pragma once
// A bucket's ServerSideEncryptionConfiguration, read and written back, with no I/O.
#include <string>
#include <string_view>

#include "s3_xml_tree.h"

namespace socketley::storage
{

// The most a document may be, which is far more than the one rule it has.
inline constexpr size_t encryption_max_bytes = 4096;

// A bucket's default encryption: SSE-S3, or SSE-KMS under the key it names, its local default when none.
struct encryption_config
{
    bool        kms{false};
    std::string kms_key;
    bool        bucket_key{false};
};

// The KMS key id an object is sealed under when the request or the bucket names none.
inline constexpr std::string_view default_kms_key = "arn:aws:kms:us-east-1:000000000000:alias/aws/s3";

// A key id, an alias, or the ARN of either, as a client may name a KMS key.
inline bool valid_kms_key(std::string_view k)
{
    if (k.empty() || k.size() > 2048)
        return false;
    for (char ch : k)
        if (static_cast<unsigned char>(ch) <= ' ' || ch == ';' || static_cast<unsigned char>(ch) >= 0x7f)
            return false;
    return true;
}

// False with `err` for a document S3 would refuse.
inline bool parse_encryption(std::string_view xml, encryption_config& out, s3_error& err)
{
    err = make_error("MalformedXML");
    out = encryption_config{};
    xml_node root;
    if (xml.size() > encryption_max_bytes || !xml_reader(xml).document(root) ||
        root.name != "ServerSideEncryptionConfiguration" || root.kids.size() != 1 || root.kids[0].name != "Rule")
        return false;
    const xml_node* algorithm = nullptr;
    const xml_node* kms_key   = nullptr;
    for (const xml_node& k : root.kids[0].kids)
    {
        if (k.name == "BucketKeyEnabled" && k.kids.empty() && (k.text == "true" || k.text == "false"))
        {
            out.bucket_key = k.text == "true";
            continue;
        }
        if (k.name != "ApplyServerSideEncryptionByDefault" || algorithm)
            return false;
        for (const xml_node& d : k.kids)
        {
            if (!d.kids.empty())
                return false;
            if (d.name == "SSEAlgorithm" && !algorithm)
                algorithm = &d;
            else if (d.name == "KMSMasterKeyID" && !kms_key)
                kms_key = &d;
            else
                return false;
        }
        if (!algorithm)
            return false;
    }
    if (!algorithm)
        return false;
    if (algorithm->text == "aws:kms:dsse")
    {
        err = make_error("NotImplemented");
        err.message = "DSSE-KMS is not supported by this runtime; aws:kms and AES256 are";
        return false;
    }
    if (algorithm->text != "AES256" && algorithm->text != "aws:kms")
        return false;
    out.kms = algorithm->text == "aws:kms";
    if (kms_key)
    {
        if (!out.kms)
        {
            err = make_error("InvalidArgument");
            err.message = "a KMSMasterKeyID is only valid with aws:kms";
            return false;
        }
        if (!valid_kms_key(kms_key->text))
        {
            err = make_error("InvalidArgument");
            err.message = "The KMSMasterKeyID is not a valid key id";
            return false;
        }
        out.kms_key = kms_key->text;
    }
    return true;
}

// What GetBucketEncryption answers for a bucket that encrypts its new objects, which is also the document kept.
inline std::string encryption_xml(const encryption_config& c)
{
    std::string x(xml_decl);
    x += "<ServerSideEncryptionConfiguration xmlns=\"";
    x += s3_xmlns;
    x += "\"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>";
    x += c.kms ? "aws:kms" : "AES256";
    x += "</SSEAlgorithm>";
    if (c.kms && !c.kms_key.empty())
    {
        x += "<KMSMasterKeyID>";
        xml_escape_to(x, c.kms_key);
        x += "</KMSMasterKeyID>";
    }
    // Said only when set, since clients written against servers that never say it refuse the element.
    x += c.bucket_key ? "</ApplyServerSideEncryptionByDefault><BucketKeyEnabled>true</BucketKeyEnabled>"
                      : "</ApplyServerSideEncryptionByDefault>";
    x += "</Rule></ServerSideEncryptionConfiguration>";
    return x;
}

}   // namespace socketley::storage
