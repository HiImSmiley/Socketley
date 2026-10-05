#pragma once
// The users of a storage runtime: who an access key signs for, what that user
// may do beyond the buckets it owns, and the owner a bucket made before there
// were users belongs to.
#include <memory>
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
    // The address an ACL's grant may name the user by, empty for none.
    std::string email;
    // May do everything on every bucket that no Deny takes away, as every key could before there were users.
    bool        admin{false};
    // Declared by a section of the credentials file, so a bucket policy's principal may name it by its id.
    bool        configured{false};
    // The key the nodes of a cluster sign for each other with, whose requests write what another node made.
    bool        cluster{false};
    bool        has_policy{false};
    bucket_policy policy;
    // The most bytes the buckets this user owns may hold together, 0 for no bound.
    uint64_t    max_bytes{0};
    // A session's own policy, which bounds whatever else lets the user in, for temporary credentials given with one.
    std::shared_ptr<const bucket_policy> session_policy;
    // The policies the IAM API gave a user of the credentials file, beside the file's own.
    std::shared_ptr<const bucket_policy> iam_policy;

    // Nothing but a bucket policy's Deny can refuse this user anything.
    bool unrestricted() const { return admin && !has_policy && !session_policy && !iam_policy; }
};

}   // namespace socketley::storage
