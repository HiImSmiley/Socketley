#pragma once
// A bucket's public access block, S3's PublicAccessBlockConfiguration: whether a public policy may be set on it and
// whether one already there may still let in requests with no credentials.
#include <string>
#include <string_view>

#include "s3_xml.h"

namespace socketley::storage
{

struct public_access_block
{
    // ACLs are disabled here, so a public ACL is refused whatever these two say.
    bool block_public_acls{false};
    bool ignore_public_acls{false};
    bool block_public_policy{false};
    bool restrict_public_buckets{false};

    bool any() const { return block_public_acls || ignore_public_acls || block_public_policy || restrict_public_buckets; }
};

// The document PutPublicAccessBlock takes, every element optional and false when left out; false with `err` for
// anything else.
bool parse_public_access_block(std::string_view xml, public_access_block& out, s3_error& err);

// The document GetPublicAccessBlock answers.
std::string public_access_block_xml(const public_access_block& p);

}   // namespace socketley::storage
