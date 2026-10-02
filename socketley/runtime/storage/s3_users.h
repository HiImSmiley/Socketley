#pragma once
// The users of a storage runtime: who an access key signs for, what that user
// may do beyond the buckets it owns, and the owner a bucket made before there
// were users belongs to.
#include <string>
#include <string_view>

#include "bucket_policy.h"

namespace socketley::storage
{

// The owner of every bucket that names none, and the user of every key a credentials file gives outside a user.
inline constexpr std::string_view default_owner = "socketley";

struct user_identity
{
    std::string id;
    std::string display_name;
    // May do everything on every bucket that no Deny takes away, as every key could before there were users.
    bool        admin{false};
    // Declared by a section of the credentials file, so a bucket policy's principal may name it by its id.
    bool        configured{false};
    bool        has_policy{false};
    bucket_policy policy;

    // Nothing but a bucket policy's Deny can refuse this user anything.
    bool unrestricted() const { return admin && !has_policy; }
};

}   // namespace socketley::storage
