#include "s3_iam.h"

#include <openssl/rand.h>

#include <algorithm>
#include <charconv>

#include "bucket_policy.h"
#include "json_doc.h"
#include "s3_names.h"

namespace socketley::storage
{

namespace
{

constexpr std::string_view iam_xmlns = "https://iam.amazonaws.com/doc/2010-05-08/";
// The most access keys a user has, as IAM allows.
constexpr size_t keys_per_user = 2;
constexpr size_t policy_doc_max = 10240;

// ─── JSON out ───────────────────────────────────────────────────────────────

void jstr(std::string& out, std::string_view v)
{
    static constexpr char hexd[] = "0123456789abcdef";
    out += '"';
    for (char ch : v)
    {
        const auto c = static_cast<unsigned char>(ch);
        if (ch == '"' || ch == '\\')
        {
            out += '\\';
            out += ch;
        }
        else if (c < 0x20)
        {
            out += "\\u00";
            out += hexd[c >> 4];
            out += hexd[c & 15];
        }
        else
            out += ch;
    }
    out += '"';
}

void jvalue_out(std::string& out, const jvalue& v)
{
    switch (v.k)
    {
        case jvalue::kind::null: out += "null"; return;
        case jvalue::kind::boolean: out += v.b ? "true" : "false"; return;
        case jvalue::kind::number: out += v.s; return;
        case jvalue::kind::string: jstr(out, v.s); return;
        case jvalue::kind::array:
            out += '[';
            for (size_t i = 0; i < v.items.size(); ++i)
            {
                if (i)
                    out += ',';
                jvalue_out(out, v.items[i]);
            }
            out += ']';
            return;
        case jvalue::kind::object:
            out += '{';
            for (size_t i = 0; i < v.members.size(); ++i)
            {
                if (i)
                    out += ',';
                jstr(out, v.members[i].first);
                out += ':';
                jvalue_out(out, v.members[i].second);
            }
            out += '}';
            return;
    }
}

void policies_out(std::string& out, const iam_policies& p)
{
    out += "\"inline\":{";
    bool first = true;
    for (const auto& [n, d] : p.inline_docs)
    {
        if (!first)
            out += ',';
        first = false;
        jstr(out, n);
        out += ':';
        jstr(out, d);
    }
    out += "},\"attached\":[";
    for (size_t i = 0; i < p.attached.size(); ++i)
    {
        if (i)
            out += ',';
        jstr(out, p.attached[i]);
    }
    out += ']';
}

// ─── JSON in ────────────────────────────────────────────────────────────────

const jvalue* member(const jvalue& o, std::string_view name)
{
    for (const auto& [n, v] : o.members)
        if (n == name)
            return &v;
    return nullptr;
}

std::string text_of(const jvalue& o, std::string_view name)
{
    const jvalue* v = member(o, name);
    return v && v->k == jvalue::kind::string ? v->s : std::string{};
}

int64_t number_of(const jvalue& o, std::string_view name)
{
    const jvalue* v = member(o, name);
    int64_t n = 0;
    if (v && v->k == jvalue::kind::number)
        std::from_chars(v->s.data(), v->s.data() + v->s.size(), n);
    return n;
}

void policies_in(const jvalue& o, iam_policies& p)
{
    if (const jvalue* i = member(o, "inline"); i && i->k == jvalue::kind::object)
        for (const auto& [n, d] : i->members)
            if (d.k == jvalue::kind::string)
                p.inline_docs[n] = d.s;
    if (const jvalue* a = member(o, "attached"); a && a->k == jvalue::kind::array)
        for (const jvalue& x : a->items)
            if (x.k == jvalue::kind::string)
                p.attached.push_back(x.s);
}

// ─── Names and ids ──────────────────────────────────────────────────────────

bool valid_name(std::string_view n, size_t max)
{
    if (n.empty() || n.size() > max)
        return false;
    for (char ch : n)
    {
        const bool word = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9');
        if (!word && std::string_view("_+=,.@-").find(ch) == std::string_view::npos)
            return false;
    }
    return true;
}

bool valid_path(std::string_view p)
{
    return !p.empty() && p.size() <= 512 && p.front() == '/' && p.back() == '/';
}

std::string random_text(std::string_view prefix, size_t n, std::string_view alphabet)
{
    std::string out(prefix);
    unsigned char raw[64];
    if (RAND_bytes(raw, static_cast<int>(n)) != 1)
        return {};
    for (size_t i = 0; i < n; ++i)
        out += alphabet[raw[i] % alphabet.size()];
    return out;
}

std::string new_id(std::string_view prefix)
{
    return random_text(prefix, 17, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
}

// ─── Policies ───────────────────────────────────────────────────────────────

// The statements of `doc`, without their Sids, which two policies merged into one may share.
bool statements_of(std::string_view doc, std::vector<jvalue>& out)
{
    jvalue root;
    if (!json_reader(doc).document(root))
        return false;
    const jvalue* st = member(root, "Statement");
    if (!st)
        return false;
    auto take = [&](const jvalue& s)
    {
        jvalue copy = s;
        std::erase_if(copy.members, [](const auto& m) { return m.first == "Sid"; });
        out.push_back(std::move(copy));
    };
    if (st->k == jvalue::kind::array)
        for (const jvalue& s : st->items)
            take(s);
    else
        take(*st);
    return true;
}

std::string merged(const std::vector<std::string_view>& docs)
{
    std::vector<jvalue> all;
    for (std::string_view d : docs)
        statements_of(d, all);
    if (all.empty())
        return {};
    std::string out = R"({"Version":"2012-10-17","Statement":[)";
    for (size_t i = 0; i < all.size(); ++i)
    {
        if (i)
            out += ',';
        jvalue_out(out, all[i]);
    }
    out += "]}";
    return out;
}

void docs_of(const iam_policies& p, std::vector<std::string_view>& docs)
{
    for (const auto& [n, d] : p.inline_docs)
        docs.push_back(d);
    for (const std::string& arn : p.attached)
        if (const char* m = iam_managed_policy(arn))
            docs.push_back(m);
}

// Whether an identity policy is one this runtime can honour, MalformedPolicyDocument otherwise.
bool policy_ok(std::string_view doc, std::string& why)
{
    if (doc.size() > policy_doc_max)
    {
        why = "The policy document is larger than 10240 characters.";
        return false;
    }
    bucket_policy p;
    s3_error err;
    if (!bucket_policy::compile_identity(doc, p, err))
    {
        why = err.message;
        return false;
    }
    return true;
}

// Whether a trust policy is JSON with Allow or Deny statements of sts actions and AWS principals.
bool trust_ok(std::string_view doc, std::string& why)
{
    jvalue root;
    if (doc.size() > policy_doc_max || !json_reader(doc).document(root) || !member(root, "Statement"))
    {
        why = "The trust policy is not a policy document.";
        return false;
    }
    return true;
}

bool glob(std::string_view pat, std::string_view text)
{
    size_t p = 0, t = 0, star = std::string_view::npos, mark = 0;
    while (t < text.size())
    {
        if (p < pat.size() && (pat[p] == '?' || pat[p] == text[t]))
        {
            ++p;
            ++t;
        }
        else if (p < pat.size() && pat[p] == '*')
        {
            star = p++;
            mark = t;
        }
        else if (star != std::string_view::npos)
        {
            p = star + 1;
            t = ++mark;
        }
        else
            return false;
    }
    while (p < pat.size() && pat[p] == '*')
        ++p;
    return p == pat.size();
}

std::vector<std::string> strings_of(const jvalue* v)
{
    std::vector<std::string> out;
    if (!v)
        return out;
    if (v->k == jvalue::kind::string)
        out.push_back(v->s);
    else if (v->k == jvalue::kind::array)
        for (const jvalue& x : v->items)
            if (x.k == jvalue::kind::string)
                out.push_back(x.s);
    return out;
}

// ─── XML out ────────────────────────────────────────────────────────────────

void el(std::string& x, std::string_view name, std::string_view v)
{
    x += '<';
    x += name;
    x += '>';
    xml_escape_to(x, v);
    x += "</";
    x += name;
    x += '>';
}

std::string arn(std::string_view kind, std::string_view path, std::string_view name)
{
    std::string a = "arn:aws:iam::";
    a += iam_account;
    a += ':';
    a += kind;
    a += path;
    a += name;
    return a;
}

void user_xml(std::string& x, const iam_user& u, std::string_view tag = "User")
{
    x += '<';
    x += tag;
    x += '>';
    el(x, "Path", u.path);
    el(x, "UserName", u.name);
    el(x, "UserId", u.id);
    el(x, "Arn", arn("user", u.path, u.name));
    el(x, "CreateDate", iso8601(u.created_ms));
    x += "</";
    x += tag;
    x += '>';
}

void group_xml(std::string& x, const iam_group& g, std::string_view tag = "Group")
{
    x += '<';
    x += tag;
    x += '>';
    el(x, "Path", g.path);
    el(x, "GroupName", g.name);
    el(x, "GroupId", g.id);
    el(x, "Arn", arn("group", g.path, g.name));
    el(x, "CreateDate", iso8601(g.created_ms));
    x += "</";
    x += tag;
    x += '>';
}

void role_xml(std::string& x, const iam_role& r, std::string_view tag = "Role")
{
    x += '<';
    x += tag;
    x += '>';
    el(x, "Path", r.path);
    el(x, "RoleName", r.name);
    el(x, "RoleId", r.id);
    el(x, "Arn", iam_role_arn(r));
    el(x, "CreateDate", iso8601(r.created_ms));
    std::string enc;
    url_encode_to(enc, r.trust, false);
    el(x, "AssumeRolePolicyDocument", enc);
    if (!r.description.empty())
        el(x, "Description", r.description);
    el(x, "MaxSessionDuration", std::to_string(r.max_session));
    x += "</";
    x += tag;
    x += '>';
}

}   // namespace

// ─── The document ───────────────────────────────────────────────────────────

bool iam_parse(std::string_view json, iam_state& out, std::string& err)
{
    out = iam_state{};
    if (json.empty())
        return true;
    jvalue root;
    if (!json_reader(json).document(root))
    {
        err = "the IAM document is not JSON";
        return false;
    }
    if (const jvalue* us = member(root, "users"); us && us->k == jvalue::kind::object)
        for (const auto& [n, v] : us->members)
        {
            iam_user u;
            u.name = n;
            u.id = text_of(v, "id");
            u.path = text_of(v, "path");
            u.created_ms = number_of(v, "created");
            policies_in(v, u.policies);
            u.groups = strings_of(member(v, "groups"));
            const jvalue* ext = member(v, "external");
            u.external = ext && ext->k == jvalue::kind::boolean && ext->b;
            out.users[n] = std::move(u);
        }
    if (const jvalue* ks = member(root, "keys"); ks && ks->k == jvalue::kind::object)
        for (const auto& [n, v] : ks->members)
        {
            iam_key k;
            k.access_key = n;
            k.secret = text_of(v, "secret");
            k.user = text_of(v, "user");
            k.active = text_of(v, "status") != "Inactive";
            k.created_ms = number_of(v, "created");
            out.keys[n] = std::move(k);
        }
    if (const jvalue* gs = member(root, "groups"); gs && gs->k == jvalue::kind::object)
        for (const auto& [n, v] : gs->members)
        {
            iam_group g;
            g.name = n;
            g.id = text_of(v, "id");
            g.path = text_of(v, "path");
            g.created_ms = number_of(v, "created");
            policies_in(v, g.policies);
            out.groups[n] = std::move(g);
        }
    if (const jvalue* rs = member(root, "roles"); rs && rs->k == jvalue::kind::object)
        for (const auto& [n, v] : rs->members)
        {
            iam_role r;
            r.name = n;
            r.id = text_of(v, "id");
            r.path = text_of(v, "path");
            r.created_ms = number_of(v, "created");
            r.trust = text_of(v, "trust");
            r.description = text_of(v, "description");
            r.max_session = number_of(v, "max_session");
            policies_in(v, r.policies);
            out.roles[n] = std::move(r);
        }
    return true;
}

std::string iam_json(const iam_state& s)
{
    std::string o = "{\"users\":{";
    bool first = true;
    for (const auto& [n, u] : s.users)
    {
        o += first ? "" : ",";
        first = false;
        jstr(o, n);
        o += ":{\"id\":";
        jstr(o, u.id);
        o += ",\"path\":";
        jstr(o, u.path);
        o += ",\"created\":" + std::to_string(u.created_ms) + ",";
        policies_out(o, u.policies);
        o += ",\"groups\":[";
        for (size_t i = 0; i < u.groups.size(); ++i)
        {
            o += i ? "," : "";
            jstr(o, u.groups[i]);
        }
        o += u.external ? "],\"external\":true}" : "]}";
    }
    o += "},\"keys\":{";
    first = true;
    for (const auto& [n, k] : s.keys)
    {
        o += first ? "" : ",";
        first = false;
        jstr(o, n);
        o += ":{\"secret\":";
        jstr(o, k.secret);
        o += ",\"user\":";
        jstr(o, k.user);
        o += k.active ? ",\"status\":\"Active\"" : ",\"status\":\"Inactive\"";
        o += ",\"created\":" + std::to_string(k.created_ms) + "}";
    }
    o += "},\"groups\":{";
    first = true;
    for (const auto& [n, g] : s.groups)
    {
        o += first ? "" : ",";
        first = false;
        jstr(o, n);
        o += ":{\"id\":";
        jstr(o, g.id);
        o += ",\"path\":";
        jstr(o, g.path);
        o += ",\"created\":" + std::to_string(g.created_ms) + ",";
        policies_out(o, g.policies);
        o += "}";
    }
    o += "},\"roles\":{";
    first = true;
    for (const auto& [n, r] : s.roles)
    {
        o += first ? "" : ",";
        first = false;
        jstr(o, n);
        o += ":{\"id\":";
        jstr(o, r.id);
        o += ",\"path\":";
        jstr(o, r.path);
        o += ",\"created\":" + std::to_string(r.created_ms) + ",\"trust\":";
        jstr(o, r.trust);
        o += ",\"description\":";
        jstr(o, r.description);
        o += ",\"max_session\":" + std::to_string(r.max_session) + ",";
        policies_out(o, r.policies);
        o += "}";
    }
    o += "}}\n";
    return o;
}

const char* iam_managed_policy(std::string_view a)
{
    if (a == "arn:aws:iam::aws:policy/AmazonS3FullAccess")
        return R"({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]})";
    if (a == "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")
        return R"({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:Get*","s3:List*"],"Resource":"*"}]})";
    if (a == "arn:aws:iam::aws:policy/AdministratorAccess")
        return R"({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]})";
    return nullptr;
}

std::string iam_user_policy(const iam_state& s, const iam_user& u)
{
    std::vector<std::string_view> docs;
    docs_of(u.policies, docs);
    for (const std::string& g : u.groups)
        if (auto it = s.groups.find(g); it != s.groups.end())
            docs_of(it->second.policies, docs);
    return merged(docs);
}

std::string iam_role_policy(const iam_role& r)
{
    std::vector<std::string_view> docs;
    docs_of(r.policies, docs);
    return merged(docs);
}

bool iam_trusts(std::string_view trust, std::string_view user_id)
{
    std::vector<jvalue> st;
    if (!statements_of(trust, st))
        return false;
    const std::string user_arn = arn("user", "/", user_id);
    const std::string bare_arn = "arn:aws:iam:::user/" + std::string(user_id);
    const std::string root_arn = "arn:aws:iam::" + std::string(iam_account) + ":root";
    bool allowed = false;
    for (const jvalue& s : st)
    {
        // A statement with a condition is one this runtime cannot judge, so it lets nobody in.
        if (member(s, "Condition"))
            continue;
        bool action = false;
        for (const std::string& a : strings_of(member(s, "Action")))
            action = action || glob(a, "sts:AssumeRole") || a == "*";
        if (!action)
            continue;
        bool who = false;
        const jvalue* p = member(s, "Principal");
        if (p && p->k == jvalue::kind::string && p->s == "*")
            who = true;
        else if (p && p->k == jvalue::kind::object)
            for (const std::string& a : strings_of(member(*p, "AWS")))
                who = who || a == "*" || a == user_arn || a == bare_arn || a == root_arn || a == user_id;
        if (!who)
            continue;
        if (text_of(s, "Effect") == "Deny")
            return false;
        allowed = allowed || text_of(s, "Effect") == "Allow";
    }
    return allowed;
}

std::string iam_role_arn(const iam_role& r)
{
    return arn("role", r.path, r.name);
}

std::string_view iam_role_name_of(std::string_view a)
{
    const size_t role = a.find(":role/");
    if (role != std::string_view::npos)
        a.remove_prefix(role + 6);
    const size_t slash = a.rfind('/');
    return slash == std::string_view::npos ? a : a.substr(slash + 1);
}

std::string iam_error_xml(std::string_view code, std::string_view message, std::string_view request_id)
{
    std::string x = "<ErrorResponse xmlns=\"";
    x += iam_xmlns;
    x += "\"><Error><Type>Sender</Type>";
    el(x, "Code", code);
    el(x, "Message", message);
    x += "</Error>";
    el(x, "RequestId", request_id);
    x += "</ErrorResponse>";
    return x;
}

// ─── The API ────────────────────────────────────────────────────────────────

namespace
{

constexpr std::string_view actions[] = {
    "CreateUser", "GetUser", "ListUsers", "UpdateUser", "DeleteUser",
    "CreateAccessKey", "ListAccessKeys", "UpdateAccessKey", "DeleteAccessKey",
    "PutUserPolicy", "GetUserPolicy", "ListUserPolicies", "DeleteUserPolicy",
    "AttachUserPolicy", "DetachUserPolicy", "ListAttachedUserPolicies",
    "CreateGroup", "GetGroup", "ListGroups", "DeleteGroup", "AddUserToGroup", "RemoveUserFromGroup",
    "ListGroupsForUser", "PutGroupPolicy", "GetGroupPolicy", "ListGroupPolicies", "DeleteGroupPolicy",
    "AttachGroupPolicy", "DetachGroupPolicy", "ListAttachedGroupPolicies",
    "CreateRole", "GetRole", "ListRoles", "UpdateRole", "DeleteRole",
    "PutRolePolicy", "GetRolePolicy", "ListRolePolicies", "DeleteRolePolicy",
    "AttachRolePolicy", "DetachRolePolicy", "ListAttachedRolePolicies",
};

struct api
{
    iam_state& s;
    std::string_view action;
    const iam_fields& f;
    int64_t now;
    std::string_view rid;
    bool (*taken)(void*, std::string_view);
    void* ctx;
    iam_result r;

    const std::string* field(std::string_view n) const
    {
        for (const auto& [k, v] : f)
            if (k == n)
                return &v;
        return nullptr;
    }
    std::string text(std::string_view n) const
    {
        const std::string* v = field(n);
        return v ? *v : std::string{};
    }

    iam_result& fail(int status, std::string_view code, std::string message)
    {
        r.ok = false;
        r.status = status;
        r.code = std::string(code);
        r.message = std::move(message);
        return r;
    }
    iam_result& missing(std::string_view name)
    {
        return fail(400, "ValidationError", "The " + std::string(name) + " is missing or not valid.");
    }
    iam_result& no_entity(std::string_view kind, std::string_view name)
    {
        return fail(404, "NoSuchEntity", "The " + std::string(kind) + " with name " + std::string(name) + " cannot be found.");
    }

    std::string begin()
    {
        std::string x = "<";
        x += action;
        x += "Response xmlns=\"";
        x += iam_xmlns;
        x += "\"><";
        x += action;
        x += "Result>";
        return x;
    }
    iam_result& finish(std::string x)
    {
        x += "</";
        x += action;
        x += "Result><ResponseMetadata>";
        el(x, "RequestId", rid);
        x += "</ResponseMetadata></";
        x += action;
        x += "Response>";
        r.xml = std::move(x);
        return r;
    }
    iam_result& done()
    {
        std::string x = "<";
        x += action;
        x += "Response xmlns=\"";
        x += iam_xmlns;
        x += "\"><ResponseMetadata>";
        el(x, "RequestId", rid);
        x += "</ResponseMetadata></";
        x += action;
        x += "Response>";
        r.xml = std::move(x);
        r.changed = true;
        return r;
    }

    // The policies of the user, group or role the request names, after `kind`'s name field.
    iam_policies* owner(std::string_view kind)
    {
        const std::string n = text(kind == "user" ? "UserName" : kind == "group" ? "GroupName" : "RoleName");
        if (kind == "user")
        {
            auto it = s.users.find(n);
            // A user of the credentials file is given policies as IAM's own are, kept beside it.
            if (it == s.users.end() && taken && taken(ctx, n))
            {
                iam_user u;
                u.name     = n;
                u.external = true;
                it = s.users.emplace(n, std::move(u)).first;
            }
            return it == s.users.end() ? nullptr : &it->second.policies;
        }
        if (kind == "group")
        {
            auto it = s.groups.find(n);
            return it == s.groups.end() ? nullptr : &it->second.policies;
        }
        auto it = s.roles.find(n);
        return it == s.roles.end() ? nullptr : &it->second.policies;
    }

    // Put, Get, List and Delete of an inline policy, and Attach, Detach and ListAttached of a managed one.
    iam_result& policy_op(std::string_view kind, std::string_view op)
    {
        const std::string owner_name = text(kind == "user" ? "UserName" : kind == "group" ? "GroupName" : "RoleName");
        iam_policies* p = owner(kind);
        if (!p)
            return no_entity(kind, owner_name);
        if (op == "Put" || op == "Get" || op == "Delete")
        {
            const std::string name = text("PolicyName");
            if (!valid_name(name, 128))
                return missing("PolicyName");
            if (op == "Put")
            {
                const std::string doc = text("PolicyDocument");
                std::string why;
                if (doc.empty() || !policy_ok(doc, why))
                    return fail(400, "MalformedPolicyDocument", why.empty() ? "The policy document is empty." : why);
                p->inline_docs[name] = doc;
                return done();
            }
            auto it = p->inline_docs.find(name);
            if (it == p->inline_docs.end())
                return fail(404, "NoSuchEntity", "The " + std::string(kind) + " policy with name " + name +
                                                     " cannot be found.");
            if (op == "Delete")
            {
                p->inline_docs.erase(it);
                return done();
            }
            std::string x = begin();
            el(x, kind == "user" ? "UserName" : kind == "group" ? "GroupName" : "RoleName", owner_name);
            el(x, "PolicyName", name);
            std::string enc;
            url_encode_to(enc, it->second, false);
            el(x, "PolicyDocument", enc);
            return finish(std::move(x));
        }
        if (op == "List")
        {
            std::string x = begin() + "<PolicyNames>";
            for (const auto& [n, d] : p->inline_docs)
                el(x, "member", n);
            x += "</PolicyNames><IsTruncated>false</IsTruncated>";
            return finish(std::move(x));
        }
        if (op == "ListAttached")
        {
            std::string x = begin() + "<AttachedPolicies>";
            for (const std::string& a : p->attached)
            {
                x += "<member>";
                el(x, "PolicyName", a.substr(a.rfind('/') + 1));
                el(x, "PolicyArn", a);
                x += "</member>";
            }
            x += "</AttachedPolicies><IsTruncated>false</IsTruncated>";
            return finish(std::move(x));
        }
        const std::string a = text("PolicyArn");
        if (op == "Attach")
        {
            if (!iam_managed_policy(a))
                return fail(404, "NoSuchEntity", "Policy " + a + " does not exist or is not attachable.");
            if (std::find(p->attached.begin(), p->attached.end(), a) == p->attached.end())
                p->attached.push_back(a);
            return done();
        }
        auto it = std::find(p->attached.begin(), p->attached.end(), a);
        if (it == p->attached.end())
            return fail(404, "NoSuchEntity", "Policy " + a + " was not found.");
        p->attached.erase(it);
        return done();
    }

    iam_result& run()
    {
        const std::string_view a = action;
        // ── users ──
        if (a == "CreateUser")
        {
            const std::string n = text("UserName"), path = field("Path") ? text("Path") : "/";
            if (!valid_name(n, 64))
                return missing("UserName");
            if (!valid_path(path))
                return missing("Path");
            if (s.users.count(n) || (taken && taken(ctx, n)))
                return fail(409, "EntityAlreadyExists", "User with name " + n + " already exists.");
            iam_user u;
            u.name = n;
            u.id = new_id("AIDA");
            u.path = path;
            u.created_ms = now;
            std::string x = begin();
            user_xml(x, u);
            s.users[n] = std::move(u);
            r.changed = true;
            return finish(std::move(x));
        }
        if (a == "GetUser" || a == "DeleteUser" || a == "UpdateUser")
        {
            const std::string n = text("UserName");
            auto it = s.users.find(n);
            if (it == s.users.end())
                return no_entity("user", n);
            if (a == "GetUser")
            {
                std::string x = begin();
                user_xml(x, it->second);
                return finish(std::move(x));
            }
            if (a == "UpdateUser")
            {
                iam_user u = it->second;
                if (const std::string* p = field("NewPath"))
                {
                    if (!valid_path(*p))
                        return missing("NewPath");
                    u.path = *p;
                }
                if (const std::string* nn = field("NewUserName"); nn && *nn != n)
                {
                    if (!valid_name(*nn, 64))
                        return missing("NewUserName");
                    if (s.users.count(*nn) || (taken && taken(ctx, *nn)))
                        return fail(409, "EntityAlreadyExists", "User with name " + *nn + " already exists.");
                    u.name = *nn;
                    for (auto& [k, key] : s.keys)
                        if (key.user == n)
                            key.user = *nn;
                    s.users.erase(it);
                }
                s.users[u.name] = std::move(u);
                return done();
            }
            // A user is deleted only once nothing is attached to it, as IAM refuses otherwise.
            const iam_user& u = it->second;
            bool keys = false;
            for (const auto& [k, key] : s.keys)
                keys = keys || key.user == n;
            if (keys || !u.policies.inline_docs.empty() || !u.policies.attached.empty() || !u.groups.empty())
                return fail(409, "DeleteConflict", "Cannot delete entity, must delete access keys, policies and group "
                                                   "memberships first.");
            s.users.erase(it);
            return done();
        }
        if (a == "ListUsers")
        {
            const std::string prefix = field("PathPrefix") ? text("PathPrefix") : "/";
            std::string x = begin() + "<Users>";
            for (const auto& [n, u] : s.users)
                if (!u.external && u.path.starts_with(prefix))
                    user_xml(x, u, "member");
            x += "</Users><IsTruncated>false</IsTruncated>";
            return finish(std::move(x));
        }
        // ── access keys ──
        if (a == "CreateAccessKey")
        {
            const std::string n = text("UserName");
            if (!s.users.count(n))
                return no_entity("user", n);
            size_t have = 0;
            for (const auto& [k, key] : s.keys)
                have += key.user == n;
            if (have >= keys_per_user)
                return fail(409, "LimitExceeded", "Cannot exceed quota for AccessKeysPerUser: 2");
            iam_key k;
            k.access_key = random_text("AKIA", 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
            k.secret = random_text("", 40, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
            k.user = n;
            k.created_ms = now;
            if (k.access_key.empty() || k.secret.empty())
                return fail(500, "ServiceFailure", "No random bytes for a key.");
            std::string x = begin() + "<AccessKey>";
            el(x, "UserName", n);
            el(x, "AccessKeyId", k.access_key);
            el(x, "Status", "Active");
            el(x, "SecretAccessKey", k.secret);
            el(x, "CreateDate", iso8601(now));
            x += "</AccessKey>";
            s.keys[k.access_key] = std::move(k);
            r.changed = true;
            return finish(std::move(x));
        }
        if (a == "ListAccessKeys")
        {
            const std::string n = text("UserName");
            if (!s.users.count(n))
                return no_entity("user", n);
            std::string x = begin() + "<AccessKeyMetadata>";
            for (const auto& [id, k] : s.keys)
                if (k.user == n)
                {
                    x += "<member>";
                    el(x, "UserName", n);
                    el(x, "AccessKeyId", id);
                    el(x, "Status", k.active ? "Active" : "Inactive");
                    el(x, "CreateDate", iso8601(k.created_ms));
                    x += "</member>";
                }
            x += "</AccessKeyMetadata><IsTruncated>false</IsTruncated>";
            el(x, "UserName", n);
            return finish(std::move(x));
        }
        if (a == "UpdateAccessKey" || a == "DeleteAccessKey")
        {
            const std::string id = text("AccessKeyId");
            auto it = s.keys.find(id);
            if (it == s.keys.end() || (field("UserName") && it->second.user != text("UserName")))
                return fail(404, "NoSuchEntity", "The Access Key with id " + id + " cannot be found.");
            if (a == "DeleteAccessKey")
            {
                s.keys.erase(it);
                return done();
            }
            const std::string st = text("Status");
            if (st != "Active" && st != "Inactive")
                return missing("Status");
            it->second.active = st == "Active";
            return done();
        }
        // ── policies of users, groups and roles ──
        for (std::string_view kind : {std::string_view("User"), std::string_view("Group"), std::string_view("Role")})
            for (std::string_view op : {"Put", "Get", "Delete", "List", "Attach", "Detach", "ListAttached"})
            {
                const bool attached = op == "Attach" || op == "Detach" || op == "ListAttached";
                const bool listing  = op == "List" || op == "ListAttached";
                std::string want = std::string(op) + std::string(kind) + (listing ? "Policies" : "Policy");
                if (attached && op == "ListAttached")
                    want = "ListAttached" + std::string(kind) + "Policies";
                if (a == want)
                    return policy_op(kind == "User" ? "user" : kind == "Group" ? "group" : "role", op);
            }
        // ── groups ──
        if (a == "CreateGroup")
        {
            const std::string n = text("GroupName"), path = field("Path") ? text("Path") : "/";
            if (!valid_name(n, 128))
                return missing("GroupName");
            if (!valid_path(path))
                return missing("Path");
            if (s.groups.count(n))
                return fail(409, "EntityAlreadyExists", "Group with name " + n + " already exists.");
            iam_group g;
            g.name = n;
            g.id = new_id("AGPA");
            g.path = path;
            g.created_ms = now;
            std::string x = begin();
            group_xml(x, g);
            s.groups[n] = std::move(g);
            r.changed = true;
            return finish(std::move(x));
        }
        if (a == "GetGroup" || a == "DeleteGroup")
        {
            const std::string n = text("GroupName");
            auto it = s.groups.find(n);
            if (it == s.groups.end())
                return no_entity("group", n);
            if (a == "DeleteGroup")
            {
                bool members = false;
                for (const auto& [un, u] : s.users)
                    members = members || std::find(u.groups.begin(), u.groups.end(), n) != u.groups.end();
                if (members || !it->second.policies.inline_docs.empty() || !it->second.policies.attached.empty())
                    return fail(409, "DeleteConflict", "Cannot delete entity, must remove users and policies first.");
                s.groups.erase(it);
                return done();
            }
            std::string x = begin();
            group_xml(x, it->second);
            x += "<Users>";
            for (const auto& [un, u] : s.users)
                if (std::find(u.groups.begin(), u.groups.end(), n) != u.groups.end())
                    user_xml(x, u, "member");
            x += "</Users><IsTruncated>false</IsTruncated>";
            return finish(std::move(x));
        }
        if (a == "ListGroups" || a == "ListGroupsForUser")
        {
            const iam_user* u = nullptr;
            if (a == "ListGroupsForUser")
            {
                auto it = s.users.find(text("UserName"));
                if (it == s.users.end())
                    return no_entity("user", text("UserName"));
                u = &it->second;
            }
            std::string x = begin() + "<Groups>";
            for (const auto& [n, g] : s.groups)
                if (!u || std::find(u->groups.begin(), u->groups.end(), n) != u->groups.end())
                    group_xml(x, g, "member");
            x += "</Groups><IsTruncated>false</IsTruncated>";
            return finish(std::move(x));
        }
        if (a == "AddUserToGroup" || a == "RemoveUserFromGroup")
        {
            auto ut = s.users.find(text("UserName"));
            if (ut == s.users.end())
                return no_entity("user", text("UserName"));
            const std::string g = text("GroupName");
            if (!s.groups.count(g))
                return no_entity("group", g);
            auto& gs = ut->second.groups;
            auto it = std::find(gs.begin(), gs.end(), g);
            if (a == "AddUserToGroup" && it == gs.end())
                gs.push_back(g);
            else if (a == "RemoveUserFromGroup")
            {
                if (it == gs.end())
                    return no_entity("user in group", g);
                gs.erase(it);
            }
            return done();
        }
        // ── roles ──
        if (a == "CreateRole")
        {
            const std::string n = text("RoleName"), path = field("Path") ? text("Path") : "/";
            if (!valid_name(n, 64))
                return missing("RoleName");
            if (!valid_path(path))
                return missing("Path");
            if (s.roles.count(n))
                return fail(409, "EntityAlreadyExists", "Role with name " + n + " already exists.");
            const std::string trust = text("AssumeRolePolicyDocument");
            std::string why;
            if (!trust_ok(trust, why))
                return fail(400, "MalformedPolicyDocument", why);
            iam_role ro;
            ro.name = n;
            ro.id = new_id("AROA");
            ro.path = path;
            ro.created_ms = now;
            ro.trust = trust;
            ro.description = text("Description");
            if (const std::string* m = field("MaxSessionDuration"))
            {
                int64_t v = 0;
                const auto res = std::from_chars(m->data(), m->data() + m->size(), v);
                if (res.ec != std::errc{} || v < 3600 || v > 43200)
                    return missing("MaxSessionDuration");
                ro.max_session = v;
            }
            std::string x = begin();
            role_xml(x, ro);
            s.roles[n] = std::move(ro);
            r.changed = true;
            return finish(std::move(x));
        }
        if (a == "GetRole" || a == "DeleteRole" || a == "UpdateRole")
        {
            const std::string n = text("RoleName");
            auto it = s.roles.find(n);
            if (it == s.roles.end())
                return no_entity("role", n);
            if (a == "GetRole")
            {
                std::string x = begin();
                role_xml(x, it->second);
                return finish(std::move(x));
            }
            if (a == "UpdateRole")
            {
                if (const std::string* d = field("Description"))
                    it->second.description = *d;
                if (const std::string* m = field("MaxSessionDuration"))
                {
                    int64_t v = 0;
                    const auto res = std::from_chars(m->data(), m->data() + m->size(), v);
                    if (res.ec != std::errc{} || v < 3600 || v > 43200)
                        return missing("MaxSessionDuration");
                    it->second.max_session = v;
                }
                return done();
            }
            if (!it->second.policies.inline_docs.empty() || !it->second.policies.attached.empty())
                return fail(409, "DeleteConflict", "Cannot delete entity, must delete policies first.");
            s.roles.erase(it);
            return done();
        }
        if (a == "ListRoles")
        {
            const std::string prefix = field("PathPrefix") ? text("PathPrefix") : "/";
            std::string x = begin() + "<Roles>";
            for (const auto& [n, ro] : s.roles)
                if (ro.path.starts_with(prefix))
                    role_xml(x, ro, "member");
            x += "</Roles><IsTruncated>false</IsTruncated>";
            return finish(std::move(x));
        }
        return fail(400, "InvalidAction", "Could not find operation " + std::string(a) + " for version 2010-05-08");
    }
};

}   // namespace

bool iam_action(std::string_view action)
{
    for (std::string_view a : actions)
        if (a == action)
            return true;
    return false;
}

iam_result iam_apply(iam_state& s, std::string_view action, const iam_fields& fields, int64_t now_ms,
                     std::string_view request_id, bool (*taken)(void*, std::string_view), void* taken_ctx)
{
    api x{s, action, fields, now_ms, request_id, taken, taken_ctx, {}};
    x.run();
    return x.r;
}

}   // namespace socketley::storage
