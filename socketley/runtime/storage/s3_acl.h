#pragma once
// S3's access control lists and object ownership, with no I/O: the canned ACLs, the grant headers and the
// AccessControlPolicy document read and written, an ACL kept compactly in a header or a bucket's document, and what
// one grants a requester.
//
// A bucket whose ownership is BucketOwnerEnforced has ACLs disabled: every object is its owner's and an ACL other
// than the owner's full control is refused.  BucketOwnerPreferred and ObjectWriter take ACLs, the latter making the
// writer of an object its owner, the former only unless it gives the bucket's owner full control.
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "object_format.h"
#include "s3_auth.h"

namespace socketley::storage
{

enum class object_ownership : uint8_t { unset, enforced, preferred, writer };

std::string_view ownership_name(object_ownership o);
// An OwnershipControls document of one rule; false with `err` for anything else.
bool parse_ownership_controls(std::string_view xml, object_ownership& out, s3_error& err);
std::string ownership_controls_xml(object_ownership o);
// x-amz-object-ownership's value, unset for none and false for one S3 does not have.
bool ownership_of_header(std::string_view v, object_ownership& out);

namespace acl_perm
{
inline constexpr uint8_t read      = 1;
inline constexpr uint8_t write     = 2;
inline constexpr uint8_t read_acp  = 4;
inline constexpr uint8_t write_acp = 8;
inline constexpr uint8_t full      = 15;
}

struct acl_grant
{
    enum class who : uint8_t { user, all_users, authenticated_users, log_delivery };
    who         w{who::user};
    // The user a grant to one names.
    std::string id;
    uint8_t     perm{0};
    bool operator==(const acl_grant&) const = default;
};

struct acl_list
{
    std::string owner;
    std::vector<acl_grant> grants;
    bool operator==(const acl_list&) const = default;
};

// The ACL a bucket or object has without one: its owner's full control.
acl_list default_acl(std::string owner);

// What a write asks for in its headers: a canned ACL, or grants by permission.
struct acl_request
{
    std::string_view canned;
    // read, write, read-acp, write-acp and full-control, in that order.
    std::string_view grant[5];
    bool any() const;
};

// Who a grant may name: a user id that must be one, and the user an email address is.
struct acl_resolver
{
    std::function<bool(std::string_view id)> has_user;
    std::function<std::string(std::string_view email)> user_of_email;
};

// The ACL `rq` asks for of a bucket or an object owned by `owner` in a bucket owned by `bucket_owner`; false with
// `err` for a canned name S3 does not have, both a canned ACL and grants, or a grantee that is no one.
bool acl_from_request(const acl_request& rq, bool bucket, const std::string& owner, const std::string& bucket_owner,
                      const acl_resolver& res, acl_list& out, s3_error& err);

// An AccessControlPolicy document; its owner must be `owner`, and a grantee be someone.
bool parse_acl_xml(std::string_view xml, const std::string& owner, const acl_resolver& res, acl_list& out,
                   s3_error& err);
std::string acl_xml(const acl_list& a, const std::function<std::string(std::string_view id)>& display_name);

// The compact form an ACL is kept in, in a header's extra entry or a bucket's document.
std::string encode_acl(const acl_list& a);
bool decode_acl(std::string_view text, acl_list& out);

// What `a` grants a requester: user `id`, empty for one with no credentials, which `authenticated` says it signed
// as; grants to everyone and to every signed user are left out when `ignore_public`.
uint8_t acl_grants(const acl_list& a, std::string_view id, bool authenticated, bool ignore_public = false);
// Whether `a` grants anything to everyone or to every signed user.
bool acl_is_public(const acl_list& a);

// The extra entry an object's owner and grants are kept in when they are not the bucket owner's full control.
inline constexpr std::string_view acl_extra = "x-socketley-acl";
// The ACL `m` keeps, or the full control of the owner of its bucket, `bucket_owner`.
acl_list object_acl_of(const object_meta& m, const std::string& bucket_owner);
// The entry's value, empty for none.
std::string_view object_acl_value(const object_meta& m);
// Keeps `value`, encode_acl()'s, in `m`, or removes the entry when it is empty.
void set_object_acl(object_meta& m, std::string_view value);

}   // namespace socketley::storage
