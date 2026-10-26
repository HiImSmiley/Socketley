#include "s3_acl.h"

#include <algorithm>
#include <cctype>

#include "s3_xml.h"
#include "s3_xml_tree.h"
#include "../../shared/util/text_list.h"

namespace socketley::storage
{

namespace
{

constexpr std::string_view all_users_uri     = "http://acs.amazonaws.com/groups/global/AllUsers";
constexpr std::string_view authenticated_uri = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers";
constexpr std::string_view log_delivery_uri  = "http://acs.amazonaws.com/groups/s3/LogDelivery";

s3_error fail(std::string_view code, std::string message = {})
{
    s3_error e = make_error(code);
    if (!message.empty())
        e.message = std::move(message);
    return e;
}

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t'))
        s.remove_suffix(1);
    return s;
}

// Adds `perm` for the grantee to `out`, beside what an earlier grant gave it.
void grant(acl_list& out, acl_grant::who w, std::string id, uint8_t perm)
{
    for (acl_grant& g : out.grants)
        if (g.w == w && g.id == id)
        {
            g.perm |= perm;
            return;
        }
    out.grants.push_back({w, std::move(id), perm});
}

bool group_of(std::string_view uri, acl_grant::who& w)
{
    if (uri == all_users_uri)
        w = acl_grant::who::all_users;
    else if (uri == authenticated_uri)
        w = acl_grant::who::authenticated_users;
    else if (uri == log_delivery_uri)
        w = acl_grant::who::log_delivery;
    else
        return false;
    return true;
}

std::string_view uri_of(acl_grant::who w)
{
    switch (w)
    {
        case acl_grant::who::all_users:           return all_users_uri;
        case acl_grant::who::authenticated_users: return authenticated_uri;
        case acl_grant::who::log_delivery:        return log_delivery_uri;
        case acl_grant::who::user:                break;
    }
    return {};
}

bool perm_of(std::string_view name, uint8_t& out)
{
    if (name == "READ")
        out = acl_perm::read;
    else if (name == "WRITE")
        out = acl_perm::write;
    else if (name == "READ_ACP")
        out = acl_perm::read_acp;
    else if (name == "WRITE_ACP")
        out = acl_perm::write_acp;
    else if (name == "FULL_CONTROL")
        out = acl_perm::full;
    else
        return false;
    return true;
}

// A grantee named by the user it is, a group's URI or an email address, as a grant header or a document names one.
bool resolve(std::string_view kind, std::string_view value, const acl_resolver& res, acl_grant::who& w,
             std::string& id, s3_error& err)
{
    if (kind == "id")
    {
        if (!res.has_user || !res.has_user(value))
        {
            err = fail("InvalidArgument", "Invalid id");
            return false;
        }
        w  = acl_grant::who::user;
        id = std::string(value);
        return true;
    }
    if (kind == "uri")
    {
        if (!group_of(value, w))
        {
            err = fail("InvalidArgument", "Invalid group uri");
            return false;
        }
        return true;
    }
    if (kind == "emailaddress")
    {
        id = res.user_of_email ? res.user_of_email(value) : std::string{};
        if (id.empty())
        {
            err = fail("UnresolvableGrantByEmailAddress");
            return false;
        }
        w = acl_grant::who::user;
        return true;
    }
    err = fail("InvalidArgument", "Invalid grantee type " + std::string(kind));
    return false;
}

}   // namespace

std::string_view ownership_name(object_ownership o)
{
    switch (o)
    {
        case object_ownership::preferred: return "BucketOwnerPreferred";
        case object_ownership::writer:    return "ObjectWriter";
        case object_ownership::enforced:
        case object_ownership::unset:     break;
    }
    return "BucketOwnerEnforced";
}

bool ownership_of_header(std::string_view v, object_ownership& out)
{
    if (v.empty())
        out = object_ownership::unset;
    else if (v == "BucketOwnerEnforced")
        out = object_ownership::enforced;
    else if (v == "BucketOwnerPreferred")
        out = object_ownership::preferred;
    else if (v == "ObjectWriter")
        out = object_ownership::writer;
    else
        return false;
    return true;
}

bool parse_ownership_controls(std::string_view xml, object_ownership& out, s3_error& err)
{
    xml_node root;
    xml_reader reader(xml);
    if (!reader.document(root) || root.name != "OwnershipControls" || root.kids.size() != 1 ||
        root.kids[0].name != "Rule" || root.kids[0].kids.size() != 1 || root.kids[0].kids[0].name != "ObjectOwnership")
    {
        err = fail("MalformedXML");
        return false;
    }
    if (!ownership_of_header(root.kids[0].kids[0].text, out) || out == object_ownership::unset)
    {
        err = fail("MalformedXML");
        return false;
    }
    return true;
}

std::string ownership_controls_xml(object_ownership o)
{
    std::string x(xml_decl);
    x += "<OwnershipControls xmlns=\"";
    x += s3_xmlns;
    x += "\"><Rule><ObjectOwnership>";
    x += ownership_name(o);
    x += "</ObjectOwnership></Rule></OwnershipControls>";
    return x;
}

acl_list default_acl(std::string owner)
{
    acl_list a;
    a.owner = owner;
    a.grants.push_back({acl_grant::who::user, std::move(owner), acl_perm::full});
    return a;
}

bool acl_request::any() const
{
    if (!canned.empty())
        return true;
    for (std::string_view g : grant)
        if (!g.empty())
            return true;
    return false;
}

bool acl_from_request(const acl_request& rq, bool bucket, const std::string& owner, const std::string& bucket_owner,
                      const acl_resolver& res, acl_list& out, s3_error& err)
{
    out = default_acl(owner);
    bool grants = false;
    for (std::string_view g : rq.grant)
        grants = grants || !g.empty();
    if (!rq.canned.empty() && grants)
    {
        err = fail("InvalidRequest", "Specifying both Canned ACLs and Header Grants is not allowed");
        return false;
    }
    if (!rq.canned.empty())
    {
        const std::string_view c = rq.canned;
        if (c == "private" || c == "aws-exec-read")
            return true;
        if (c == "public-read")
            grant(out, acl_grant::who::all_users, {}, acl_perm::read);
        else if (c == "public-read-write")
            grant(out, acl_grant::who::all_users, {}, acl_perm::read | acl_perm::write);
        else if (c == "authenticated-read")
            grant(out, acl_grant::who::authenticated_users, {}, acl_perm::read);
        else if (c == "bucket-owner-read" || c == "bucket-owner-full-control")
        {
            // A bucket's own is its owner's, so these say no more of it than private does.
            if (!bucket && bucket_owner != owner)
                grant(out, acl_grant::who::user, bucket_owner,
                      c == "bucket-owner-read" ? acl_perm::read : acl_perm::full);
        }
        else if (c == "log-delivery-write")
            grant(out, acl_grant::who::log_delivery, {}, acl_perm::write | acl_perm::read_acp);
        else
        {
            err = fail("InvalidArgument");
            return false;
        }
        return true;
    }
    if (!grants)
        return true;
    // Grant headers name every grant the resource has, the owner's included only when they name it.
    out.grants.clear();
    static constexpr uint8_t perms[] = {acl_perm::read, acl_perm::write, acl_perm::read_acp, acl_perm::write_acp,
                                        acl_perm::full};
    for (size_t i = 0; i < std::size(perms); ++i)
    {
        std::string_view list = rq.grant[i];
        while (!list.empty())
        {
            const std::string_view one = trim(take_item(list));
            if (one.empty())
                continue;
            const size_t eq = one.find('=');
            if (eq == std::string_view::npos)
            {
                err = fail("InvalidArgument");
                return false;
            }
            std::string kind(trim(one.substr(0, eq)));
            std::transform(kind.begin(), kind.end(), kind.begin(), [](unsigned char ch) { return std::tolower(ch); });
            std::string_view value = trim(one.substr(eq + 1));
            if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
                value = value.substr(1, value.size() - 2);
            acl_grant::who w{};
            std::string id;
            if (!resolve(kind, value, res, w, id, err))
                return false;
            grant(out, w, std::move(id), perms[i]);
        }
    }
    // Headers of separators alone name nobody, and taken as they are they would leave a resource no one may reach.
    if (out.grants.empty())
    {
        err = fail("InvalidArgument");
        return false;
    }
    return true;
}

bool parse_acl_xml(std::string_view xml, const std::string& owner, const acl_resolver& res, acl_list& out,
                   s3_error& err)
{
    xml_node root;
    xml_reader reader(xml);
    if (!reader.document(root) || root.name != "AccessControlPolicy")
    {
        err = fail("MalformedACLError");
        return false;
    }
    out = acl_list{};
    out.owner = owner;
    bool listed = false;
    for (const xml_node& k : root.kids)
    {
        if (k.name == "Owner")
        {
            for (const xml_node& f : k.kids)
                if (f.name == "ID" && f.text != owner)
                {
                    err = fail("AccessDenied", "The owner of a resource is not changed by its ACL");
                    return false;
                }
            continue;
        }
        if (k.name != "AccessControlList")
        {
            err = fail("MalformedACLError");
            return false;
        }
        listed = true;
        for (const xml_node& g : k.kids)
        {
            const xml_node* grantee = nullptr;
            uint8_t perm = 0;
            bool    has_perm = false;
            for (const xml_node& f : g.kids)
            {
                if (f.name == "Grantee")
                    grantee = &f;
                else if (f.name == "Permission")
                    has_perm = perm_of(f.text, perm);
            }
            if (g.name != "Grant" || !grantee || !has_perm)
            {
                err = fail("MalformedACLError");
                return false;
            }
            std::string_view kind, value;
            for (const xml_node& f : grantee->kids)
            {
                if (f.name == "ID")
                    kind = "id", value = f.text;
                else if (f.name == "URI")
                    kind = "uri", value = f.text;
                else if (f.name == "EmailAddress")
                    kind = "emailaddress", value = f.text;
            }
            if (kind.empty())
            {
                err = fail("MalformedACLError");
                return false;
            }
            acl_grant::who w{};
            std::string id;
            if (!resolve(kind, value, res, w, id, err))
                return false;
            grant(out, w, std::move(id), perm);
        }
    }
    if (!listed)
    {
        err = fail("MalformedACLError");
        return false;
    }
    return true;
}

std::string acl_xml(const acl_list& a, const std::function<std::string(std::string_view id)>& display_name)
{
    std::string x(xml_decl);
    x += "<AccessControlPolicy xmlns=\"";
    x += s3_xmlns;
    x += "\"><Owner><ID>";
    xml_escape_to(x, a.owner);
    x += "</ID><DisplayName>";
    xml_escape_to(x, display_name(a.owner));
    x += "</DisplayName></Owner><AccessControlList>";
    static constexpr std::pair<uint8_t, std::string_view> names[] = {
        {acl_perm::full, "FULL_CONTROL"}, {acl_perm::read, "READ"}, {acl_perm::write, "WRITE"},
        {acl_perm::read_acp, "READ_ACP"}, {acl_perm::write_acp, "WRITE_ACP"}};
    // Groups before users, as RGW lists them, since S3 fixes no order and a client that sorts by DisplayName stops
    // at a group's missing one when a user comes first.
    for (const bool groups : {true, false})
    for (const acl_grant& g : a.grants)
    {
        if ((g.w != acl_grant::who::user) != groups)
            continue;
        uint8_t left = g.perm;
        for (const auto& [bits, name] : names)
        {
            if ((left & bits) != bits)
                continue;
            left = static_cast<uint8_t>(left & ~bits);
            x += "<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"";
            if (g.w == acl_grant::who::user)
            {
                x += "CanonicalUser\"><ID>";
                xml_escape_to(x, g.id);
                x += "</ID><DisplayName>";
                xml_escape_to(x, display_name(g.id));
                x += "</DisplayName>";
            }
            else
            {
                x += "Group\"><URI>";
                x += uri_of(g.w);
                x += "</URI>";
            }
            x += "</Grantee><Permission>";
            x += name;
            x += "</Permission></Grant>";
        }
    }
    x += "</AccessControlList></AccessControlPolicy>";
    return x;
}

std::string encode_acl(const acl_list& a)
{
    // owner, then per grant a kind letter, its permissions as a hex digit and a user's id, each line its own.
    std::string out = a.owner;
    static constexpr char kinds[] = {'u', 'a', 't', 'l'};
    static constexpr char hexd[] = "0123456789abcdef";
    for (const acl_grant& g : a.grants)
    {
        out += '\n';
        out += kinds[static_cast<size_t>(g.w)];
        out += hexd[g.perm & 15];
        out += g.id;
    }
    return out;
}

bool decode_acl(std::string_view text, acl_list& out)
{
    out = acl_list{};
    size_t nl = text.find('\n');
    out.owner = std::string(text.substr(0, nl));
    while (nl != std::string_view::npos)
    {
        text.remove_prefix(nl + 1);
        nl = text.find('\n');
        const std::string_view line = text.substr(0, nl);
        if (line.size() < 2)
            return false;
        acl_grant g;
        switch (line[0])
        {
            case 'u': g.w = acl_grant::who::user; break;
            case 'a': g.w = acl_grant::who::all_users; break;
            case 't': g.w = acl_grant::who::authenticated_users; break;
            case 'l': g.w = acl_grant::who::log_delivery; break;
            default:  return false;
        }
        const char p = line[1];
        g.perm = static_cast<uint8_t>(p >= '0' && p <= '9' ? p - '0' : p >= 'a' && p <= 'f' ? p - 'a' + 10 : 0);
        g.id   = std::string(line.substr(2));
        if (g.perm == 0 || (g.w == acl_grant::who::user) == g.id.empty())
            return false;
        out.grants.push_back(std::move(g));
    }
    return true;
}

uint8_t acl_grants(const acl_list& a, std::string_view id, bool authenticated, bool ignore_public)
{
    uint8_t p = 0;
    for (const acl_grant& g : a.grants)
    {
        switch (g.w)
        {
            case acl_grant::who::user:
                if (!id.empty() && g.id == id)
                    p |= g.perm;
                break;
            case acl_grant::who::all_users:
                if (!ignore_public)
                    p |= g.perm;
                break;
            case acl_grant::who::authenticated_users:
                if (!ignore_public && authenticated)
                    p |= g.perm;
                break;
            case acl_grant::who::log_delivery:
                break;
        }
    }
    return p;
}

acl_list object_acl_of(const object_meta& m, const std::string& bucket_owner)
{
    acl_list a;
    if (const std::string_view v = object_acl_value(m); !v.empty() && decode_acl(v, a))
        return a;
    return default_acl(bucket_owner);
}

std::string_view object_acl_value(const object_meta& m)
{
    for (const auto& [n, v] : m.extra)
        if (n == acl_extra)
            return v;
    return {};
}

void set_object_acl(object_meta& m, std::string_view value)
{
    std::string kept(value);
    erase_if(m.extra, [](const auto& e) { return e.first == acl_extra; });
    if (!kept.empty())
        m.extra.emplace_back(std::string(acl_extra), std::move(kept));
}

bool acl_is_public(const acl_list& a)
{
    return std::any_of(a.grants.begin(), a.grants.end(), [](const acl_grant& g)
    {
        return g.w == acl_grant::who::all_users || g.w == acl_grant::who::authenticated_users;
    });
}

}   // namespace socketley::storage
