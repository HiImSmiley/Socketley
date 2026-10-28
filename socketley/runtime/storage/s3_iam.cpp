#include "s3_iam.h"
#include "../../shared/util/glob_match.h"

#include <openssl/rand.h>

#include <algorithm>
#include <charconv>

#include "bucket_policy.h"
#include "digest.h"
#include "../../shared/json/json_doc.h"
#include "password_hash.h"
#include "s3_names.h"
#include "s3_users.h"
#include "../../shared/json/json_escape.h"

using socketley::json::jvalue;
using socketley::json::json_reader;

namespace socketley::storage
{

namespace
{

constexpr std::string_view iam_xmlns = "https://iam.amazonaws.com/doc/2010-05-08/";
// The most access keys a user has, as IAM allows.
constexpr size_t keys_per_user = 2;
constexpr size_t policy_doc_max = 10240;
// What a login secret and an invitation's token are drawn from.
constexpr std::string_view alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

// ─── JSON out ───────────────────────────────────────────────────────────────

void jvalue_out(std::string& out, const jvalue& v)
{
    switch (v.k)
    {
        case jvalue::kind::null: out += "null"; return;
        case jvalue::kind::boolean: out += v.b ? "true" : "false"; return;
        case jvalue::kind::number: out += v.s; return;
        case jvalue::kind::string: socketley::json::quote_into(out, v.s); return;
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
                socketley::json::quote_into(out, v.members[i].first);
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
        socketley::json::quote_into(out, n);
        out += ':';
        socketley::json::quote_into(out, d);
    }
    out += "},\"attached\":[";
    for (size_t i = 0; i < p.attached.size(); ++i)
    {
        if (i)
            out += ',';
        socketley::json::quote_into(out, p.attached[i]);
    }
    out += ']';
}

// ─── JSON in ────────────────────────────────────────────────────────────────

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
    std::vector<jvalue> st;
    if (statements_of(doc, st))
        for (const jvalue& s : st)
            if (member(s, "NotPrincipal") || member(s, "NotAction"))
            {
                why = "The trust policy cannot use NotPrincipal or NotAction.";
                return false;
            }
    return true;
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
            u.password = text_of(v, "password");
            const jvalue* reset = member(v, "password_reset");
            u.password_reset = reset && reset->k == jvalue::kind::boolean && reset->b;
            u.password_ms = number_of(v, "password_set");
            u.login_secret = text_of(v, "login_secret");
            if (const jvalue* t = member(v, "tags"); t && t->k == jvalue::kind::object)
                for (const auto& [k, tv] : t->members)
                    if (tv.k == jvalue::kind::string)
                        u.tags[k] = tv.s;
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
    if (const jvalue* is = member(root, "invites"); is && is->k == jvalue::kind::object)
        for (const auto& [n, v] : is->members)
        {
            iam_invite i;
            i.id = n;
            i.hash = text_of(v, "hash");
            i.created_ms = number_of(v, "created");
            i.expires_ms = number_of(v, "expires");
            i.by = text_of(v, "by");
            const jvalue* adm = member(v, "admin");
            i.admin = adm && adm->k == jvalue::kind::boolean && adm->b;
            i.max_bytes = static_cast<uint64_t>(number_of(v, "max_bytes"));
            const jvalue* lib = member(v, "libraries");
            i.libraries = !lib || lib->k != jvalue::kind::boolean || lib->b;
            if (!i.hash.empty())
                out.invites[n] = std::move(i);
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
        socketley::json::quote_into(o, n);
        o += ":{\"id\":";
        socketley::json::quote_into(o, u.id);
        o += ",\"path\":";
        socketley::json::quote_into(o, u.path);
        o += ",\"created\":" + std::to_string(u.created_ms) + ",";
        policies_out(o, u.policies);
        o += ",\"groups\":[";
        for (size_t i = 0; i < u.groups.size(); ++i)
        {
            o += i ? "," : "";
            socketley::json::quote_into(o, u.groups[i]);
        }
        o += ']';
        if (u.external)
            o += ",\"external\":true";
        if (!u.password.empty())
        {
            o += ",\"password\":";
            socketley::json::quote_into(o, u.password);
            o += u.password_reset ? ",\"password_reset\":true" : "";
            o += ",\"password_set\":" + std::to_string(u.password_ms) + ",\"login_secret\":";
            socketley::json::quote_into(o, u.login_secret);
        }
        if (!u.tags.empty())
        {
            o += ",\"tags\":{";
            bool tfirst = true;
            for (const auto& [k, v] : u.tags)
            {
                o += tfirst ? "" : ",";
                tfirst = false;
                socketley::json::quote_into(o, k);
                o += ':';
                socketley::json::quote_into(o, v);
            }
            o += '}';
        }
        o += '}';
    }
    o += "},\"keys\":{";
    first = true;
    for (const auto& [n, k] : s.keys)
    {
        o += first ? "" : ",";
        first = false;
        socketley::json::quote_into(o, n);
        o += ":{\"secret\":";
        socketley::json::quote_into(o, k.secret);
        o += ",\"user\":";
        socketley::json::quote_into(o, k.user);
        o += k.active ? ",\"status\":\"Active\"" : ",\"status\":\"Inactive\"";
        o += ",\"created\":" + std::to_string(k.created_ms) + "}";
    }
    o += "},\"groups\":{";
    first = true;
    for (const auto& [n, g] : s.groups)
    {
        o += first ? "" : ",";
        first = false;
        socketley::json::quote_into(o, n);
        o += ":{\"id\":";
        socketley::json::quote_into(o, g.id);
        o += ",\"path\":";
        socketley::json::quote_into(o, g.path);
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
        socketley::json::quote_into(o, n);
        o += ":{\"id\":";
        socketley::json::quote_into(o, r.id);
        o += ",\"path\":";
        socketley::json::quote_into(o, r.path);
        o += ",\"created\":" + std::to_string(r.created_ms) + ",\"trust\":";
        socketley::json::quote_into(o, r.trust);
        o += ",\"description\":";
        socketley::json::quote_into(o, r.description);
        o += ",\"max_session\":" + std::to_string(r.max_session) + ",";
        policies_out(o, r.policies);
        o += "}";
    }
    o += "},\"invites\":{";
    first = true;
    for (const auto& [n, i] : s.invites)
    {
        o += first ? "" : ",";
        first = false;
        socketley::json::quote_into(o, n);
        o += ":{\"hash\":";
        socketley::json::quote_into(o, i.hash);
        o += ",\"created\":" + std::to_string(i.created_ms) + ",\"expires\":" + std::to_string(i.expires_ms);
        o += ",\"by\":";
        socketley::json::quote_into(o, i.by);
        o += i.admin ? ",\"admin\":true" : ",\"admin\":false";
        o += ",\"max_bytes\":" + std::to_string(i.max_bytes);
        o += i.libraries ? ",\"libraries\":true}" : ",\"libraries\":false}";
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
        // "*" is S3's actions alone, so the policy names IAM's for itself.
        return R"({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["*","iam:*"],"Resource":"*"}]})";
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
        // Conditions are not weighed here, so the statement that has one is read the way that cannot let anyone in
        // it would keep out: an Allow under a condition admits nobody, and a Deny under one refuses as if it held.
        const bool conditional = member(s, "Condition") != nullptr;
        if (conditional && text_of(s, "Effect") != "Deny")
            continue;
        bool action = false;
        for (const std::string& a : strings_of(member(s, "Action")))
            action = action || socketley::iam_wild_match(a, "sts:AssumeRole") || a == "*";
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

const std::string* field_of(const iam_fields& f, std::string_view n)
{
    for (const auto& [k, v] : f)
        if (k == n)
            return &v;
    return nullptr;
}

// Whether a policy document compiles to one whose Allow names an IAM action.
bool doc_grants_iam(std::string_view doc)
{
    bucket_policy p;
    s3_error err;
    return !doc.empty() && bucket_policy::compile_identity(doc, p, err) && p.allows_iam();
}

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
        return field_of(f, n);
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

    // The action as its response's elements name it: the runtime's own without their prefix, which XML would read as
    // an undeclared namespace.
    std::string_view tag() const
    {
        return action.substr(action.find(':') == std::string_view::npos ? 0 : action.find(':') + 1);
    }

    std::string begin()
    {
        std::string x = "<";
        x += tag();
        x += "Response xmlns=\"";
        x += iam_xmlns;
        x += "\"><";
        x += tag();
        x += "Result>";
        return x;
    }
    iam_result& finish(std::string x)
    {
        x += "</";
        x += tag();
        x += "Result><ResponseMetadata>";
        el(x, "RequestId", rid);
        x += "</ResponseMetadata></";
        x += tag();
        x += "Response>";
        r.xml = std::move(x);
        return r;
    }
    iam_result& done()
    {
        std::string x = "<";
        x += tag();
        x += "Response xmlns=\"";
        x += iam_xmlns;
        x += "\"><ResponseMetadata>";
        el(x, "RequestId", rid);
        x += "</ResponseMetadata></";
        x += tag();
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

    // The user `n`, or a user of the credentials file kept beside the IAM API's as policies are; null for neither.
    iam_user* user_or_file(const std::string& n)
    {
        auto it = s.users.find(n);
        if (it == s.users.end() && taken && taken(ctx, n))
        {
            iam_user u;
            u.name     = n;
            u.external = true;
            it = s.users.emplace(n, std::move(u)).first;
        }
        return it == s.users.end() ? nullptr : &it->second;
    }

    // What is wrong with a tag the runtime reads, empty when nothing is.
    static std::string tag_problem(std::string_view k, std::string_view v)
    {
        if (k.empty() || k.size() > 128 || v.size() > 256)
            return "A tag's key is 1 to 128 characters and its value at most 256.";
        if (k == iam_tag_max_bytes &&
            (v.empty() || v.find_first_not_of("0123456789") != std::string_view::npos || v.size() > 19))
            return "socketley:max-bytes is a number of bytes.";
        if (k == iam_tag_disabled && v != "true" && v != "false")
            return "socketley:disabled is true or false.";
        if (k == iam_tag_email && !v.empty() && v.find('@') == std::string_view::npos)
            return "socketley:email is an address.";
        if (k.starts_with("socketley:") && k != iam_tag_max_bytes && k != iam_tag_disabled && k != iam_tag_email &&
            k != iam_tag_display_name)
            return "socketley: is the runtime's own prefix, and " + std::string(k) + " is none of its tags.";
        return {};
    }

    void login_xml(std::string& x, const iam_user& u)
    {
        x += "<LoginProfile>";
        el(x, "UserName", u.name);
        el(x, "CreateDate", iso8601(u.password_ms));
        el(x, "PasswordResetRequired", u.password_reset ? "true" : "false");
        x += "</LoginProfile>";
    }

    // A user made by an invitation or by CreateUser, its name checked and taken by none.
    iam_result* make_user(const std::string& n, const std::string& path, iam_user*& out)
    {
        if (!valid_name(n, 64))
            return &missing("UserName");
        if (!valid_path(path))
            return &missing("Path");
        // The owner a bucket with none recorded belongs to is a name too, and a user given it would own them all.
        if (s.users.count(n) || (taken && taken(ctx, n)) || n == default_owner)
            return &fail(409, "EntityAlreadyExists", "User with name " + n + " already exists.");
        iam_user u;
        u.name = n;
        u.id = new_id("AIDA");
        u.path = path;
        u.created_ms = now;
        if (u.id.empty())
            return &fail(500, "ServiceFailure", "No random bytes for an id.");
        out = &(s.users[n] = std::move(u));
        return nullptr;
    }

    iam_result& run()
    {
        const std::string_view a = action;
        // An invitation that has ended is gone, whatever is asked.
        if (std::erase_if(s.invites, [&](const auto& kv) { return kv.second.expires_ms <= now; }) > 0)
            r.changed = true;
        // ── users ──
        if (a == "CreateUser")
        {
            iam_user* u = nullptr;
            if (iam_result* bad = make_user(text("UserName"), field("Path") ? text("Path") : "/", u))
                return *bad;
            std::string x = begin();
            user_xml(x, *u);
            r.changed = true;
            return finish(std::move(x));
        }
        // ── login profiles, a user's password for the web interface ──
        if (a == "CreateLoginProfile" || a == "UpdateLoginProfile")
        {
            const std::string n = text("UserName");
            iam_user* u = user_or_file(n);
            if (!u)
                return no_entity("user", n);
            if (a == "CreateLoginProfile" && !u->password.empty())
                return fail(409, "EntityAlreadyExists", "Login Profile for user " + n + " already exists.");
            if (a == "UpdateLoginProfile" && u->password.empty())
                return fail(404, "NoSuchEntity", "Login Profile for User " + n + " cannot be found.");
            const std::string* pw = field("Password");
            if (!pw && a == "CreateLoginProfile")
                return missing("Password");
            if (pw)
            {
                const std::string why = password_problem(*pw, n);
                if (!why.empty())
                    return fail(400, "PasswordPolicyViolation", why);
                const std::string h = password_hash(*pw);
                if (h.empty())
                    return fail(500, "ServiceFailure", "No random bytes for a salt.");
                std::string secret = u->login_secret.empty() ? random_text("", 40, alnum) : u->login_secret;
                if (secret.empty())
                    return fail(500, "ServiceFailure", "No random bytes for a secret.");
                u->password = h;
                u->password_ms = now;
                u->login_secret = std::move(secret);
            }
            if (const std::string* reset = field("PasswordResetRequired"))
                u->password_reset = *reset == "true";
            else if (a == "CreateLoginProfile")
                u->password_reset = false;
            if (a == "UpdateLoginProfile")
                return done();
            std::string x = begin();
            login_xml(x, *u);
            r.changed = true;
            return finish(std::move(x));
        }
        if (a == "GetLoginProfile" || a == "DeleteLoginProfile")
        {
            const std::string n = text("UserName");
            auto it = s.users.find(n);
            if (it == s.users.end() || it->second.password.empty())
                return fail(404, "NoSuchEntity", "Login Profile for User " + n + " cannot be found.");
            if (a == "DeleteLoginProfile")
            {
                it->second.password.clear();
                it->second.login_secret.clear();
                it->second.password_reset = false;
                // A user of the credentials file with nothing left beside it is the file's alone again.
                const iam_policies& p = it->second.policies;
                if (it->second.external && p.inline_docs.empty() && p.attached.empty() && it->second.groups.empty())
                    s.users.erase(it);
                return done();
            }
            std::string x = begin();
            login_xml(x, it->second);
            return finish(std::move(x));
        }
        if (a == "ChangePassword")
        {
            const std::string n = text("UserName");
            auto it = s.users.find(n);
            if (it == s.users.end() || it->second.password.empty())
                return fail(404, "NoSuchEntity", "Login Profile for User " + n + " cannot be found.");
            if (!password_matches(it->second.password, text("OldPassword")))
                return fail(403, "InvalidUserType", "The old password given is not the user's.");
            const std::string pw = text("NewPassword");
            if (const std::string why = password_problem(pw, n); !why.empty())
                return fail(400, "PasswordPolicyViolation", why);
            const std::string h = password_hash(pw);
            if (h.empty())
                return fail(500, "ServiceFailure", "No random bytes for a salt.");
            it->second.password = h;
            it->second.password_ms = now;
            it->second.password_reset = false;
            return done();
        }
        // ── tags of users ──
        if (a == "TagUser" || a == "UntagUser" || a == "ListUserTags")
        {
            const std::string n = text("UserName");
            auto it = s.users.find(n);
            // A user of the credentials file is described there.
            if (it == s.users.end() || it->second.external)
                return no_entity("user", n);
            auto& tags = it->second.tags;
            if (a == "ListUserTags")
            {
                std::string x = begin() + "<Tags>";
                for (const auto& [k, v] : tags)
                {
                    x += "<member>";
                    el(x, "Key", k);
                    el(x, "Value", v);
                    x += "</member>";
                }
                x += "</Tags><IsTruncated>false</IsTruncated>";
                return finish(std::move(x));
            }
            std::map<std::string, std::string> next = tags;
            for (int i = 1; i <= 50; ++i)
            {
                const std::string base = (a == "TagUser" ? "Tags.member." : "TagKeys.member.") + std::to_string(i);
                if (a == "UntagUser")
                {
                    const std::string* k = field(base);
                    if (!k)
                        break;
                    next.erase(*k);
                    continue;
                }
                const std::string* k = field(base + ".Key");
                if (!k)
                    break;
                const std::string v = text(base + ".Value");
                if (const std::string why = tag_problem(*k, v); !why.empty())
                    return fail(400, "InvalidInput", why);
                next[*k] = v;
            }
            if (field(a == "TagUser" ? "Tags.member.51.Key" : "TagKeys.member.51"))
                return fail(409, "LimitExceeded", "Cannot exceed quota for TagsPerUser: 50");
            if (next.size() > 50)
                return fail(409, "LimitExceeded", "Cannot exceed quota for TagsPerUser: 50");
            tags = std::move(next);
            return done();
        }
        // ── the runtime's own: invitations ──
        if (a == "socketley:CreateInvitation")
        {
            const std::string token = random_text("", 32, alnum);
            if (token.empty())
                return fail(500, "ServiceFailure", "No random bytes for an invitation.");
            int64_t days = 7;
            if (const std::string* d = field("ExpiresInDays"))
            {
                const auto res = std::from_chars(d->data(), d->data() + d->size(), days);
                if (res.ec != std::errc{} || res.ptr != d->data() + d->size() || days < 1 || days > 30)
                    return missing("ExpiresInDays");
            }
            iam_invite i;
            i.hash = sha256_hex(token);
            i.id = i.hash.substr(0, 16);
            i.created_ms = now;
            i.expires_ms = now + days * 86400000;
            i.by = text("UserName");
            i.admin = text("Admin") == "true";
            i.libraries = text("Libraries") != "false";
            if (const std::string* m = field("MaxBytes"); m && !m->empty())
            {
                const auto res = std::from_chars(m->data(), m->data() + m->size(), i.max_bytes);
                if (res.ec != std::errc{} || res.ptr != m->data() + m->size())
                    return missing("MaxBytes");
            }
            if (s.invites.size() >= 100)
                return fail(409, "LimitExceeded", "Cannot exceed 100 open invitations.");
            std::string x = begin() + "<Invitation>";
            el(x, "Id", i.id);
            el(x, "Token", token);
            el(x, "Expires", iso8601(i.expires_ms));
            x += "</Invitation>";
            s.invites[i.id] = std::move(i);
            r.changed = true;
            return finish(std::move(x));
        }
        if (a == "socketley:ListInvitations")
        {
            std::string x = begin() + "<Invitations>";
            for (const auto& [id, i] : s.invites)
            {
                x += "<member>";
                el(x, "Id", id);
                el(x, "CreatedBy", i.by);
                el(x, "CreateDate", iso8601(i.created_ms));
                el(x, "Expires", iso8601(i.expires_ms));
                el(x, "Admin", i.admin ? "true" : "false");
                el(x, "MaxBytes", std::to_string(i.max_bytes));
                el(x, "Libraries", i.libraries ? "true" : "false");
                x += "</member>";
            }
            x += "</Invitations>";
            return finish(std::move(x));
        }
        if (a == "socketley:DeleteInvitation")
        {
            if (!s.invites.erase(text("Id")))
                return fail(404, "NoSuchEntity", "The invitation " + text("Id") + " cannot be found.");
            return done();
        }
        if (a == "socketley:AcceptInvitation")
        {
            const std::string h = sha256_hex(text("Token"));
            const auto inv = s.invites.find(h.substr(0, 16));
            if (text("Token").empty() || inv == s.invites.end() || inv->second.hash != h)
                return fail(404, "NoSuchEntity", "The invitation is not one of this runtime's, or it has ended.");
            const std::string n = text("UserName"), pw = text("Password");
            if (const std::string why = password_problem(pw, n); !why.empty())
                return fail(400, "PasswordPolicyViolation", why);
            const iam_invite i = inv->second;
            // Everything that can refuse is asked before the user is made, so a refusal leaves no half-made one.
            const std::string hash = password_hash(pw), secret = random_text("", 40, alnum);
            if (hash.empty() || secret.empty())
                return fail(500, "ServiceFailure", "No random bytes for a salt.");
            if (const std::string* em = field("Email"); em && !em->empty() && !tag_problem(iam_tag_email, *em).empty())
                return missing("Email");
            if (const std::string* dn = field("DisplayName"); dn && dn->size() > 128)
                return missing("DisplayName");
            std::string admins_id;
            if (i.admin && !s.groups.count(std::string(iam_admins_group)))
            {
                admins_id = new_id("AGPA");
                if (admins_id.empty())
                    return fail(500, "ServiceFailure", "No random bytes for an id.");
            }
            iam_user* u = nullptr;
            if (iam_result* bad = make_user(n, "/", u))
                return *bad;
            u->password = hash;
            u->password_ms = now;
            u->login_secret = secret;
            if (i.max_bytes)
                u->tags[std::string(iam_tag_max_bytes)] = std::to_string(i.max_bytes);
            if (i.libraries)
                u->policies.inline_docs[std::string(iam_libraries_policy)] = std::string(iam_libraries_doc);
            if (const std::string* dn = field("DisplayName"); dn && !dn->empty())
                u->tags[std::string(iam_tag_display_name)] = *dn;
            if (const std::string* em = field("Email"); em && !em->empty())
                u->tags[std::string(iam_tag_email)] = *em;
            if (i.admin)
            {
                const std::string g(iam_admins_group);
                if (!s.groups.count(g))
                {
                    iam_group grp;
                    grp.name = g;
                    grp.id = std::move(admins_id);
                    grp.created_ms = now;
                    s.groups[g] = std::move(grp);
                }
                u->groups.push_back(g);
            }
            std::string x = begin();
            user_xml(x, *u);
            s.invites.erase(inv);
            r.changed = true;
            return finish(std::move(x));
        }
        if (a == "GetUser" || a == "DeleteUser" || a == "UpdateUser")
        {
            const std::string n = text("UserName");
            auto it = s.users.find(n);
            // A user of the credentials file is described there.
            if (it == s.users.end() || it->second.external)
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
            if (keys || !u.policies.inline_docs.empty() || !u.policies.attached.empty() || !u.groups.empty() ||
                !u.password.empty())
                return fail(409, "DeleteConflict", "Cannot delete entity, must delete access keys, policies, login "
                                                   "profile and group memberships first.");
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
            // A user of the credentials file may hold keys of the IAM API beside the file's, which sign as that user.
            if (!user_or_file(n))
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
            if (!s.users.count(n) && !(taken && taken(ctx, n)))
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
                const bool listing  = op == "List" || op == "ListAttached";
                std::string want = std::string(op) + std::string(kind) + (listing ? "Policies" : "Policy");
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
            if (g.id.empty())
                return fail(500, "ServiceFailure", "No random bytes for an id.");
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
            if (ro.id.empty())
                return fail(500, "ServiceFailure", "No random bytes for an id.");
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
                int64_t v = 0;
                const std::string* m = field("MaxSessionDuration");
                if (m)
                {
                    const auto res = std::from_chars(m->data(), m->data() + m->size(), v);
                    if (res.ec != std::errc{} || v < 3600 || v > 43200)
                        return missing("MaxSessionDuration");
                }
                if (const std::string* d = field("Description"))
                    it->second.description = *d;
                if (m)
                    it->second.max_session = v;
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
    return iam_action_index(action) >= 0;
}

bool iam_own_action(std::string_view action)
{
    return action == "socketley:CreateInvitation" || action == "socketley:ListInvitations" ||
           action == "socketley:DeleteInvitation" || action == "socketley:AcceptInvitation";
}

bool iam_self_service(std::string_view a)
{
    // A first password is a user's own to set, as signing in with its key already proves it; another is set with the
    // one it replaces, by ChangePassword, or by an admin.
    return a == "GetUser" || a == "ChangePassword" || a == "GetLoginProfile" || a == "CreateLoginProfile" ||
           a == "ListAccessKeys" || a == "CreateAccessKey" || a == "UpdateAccessKey" || a == "DeleteAccessKey" ||
           a == "ListUserTags" || a == "ListGroupsForUser";
}

std::vector<std::string> iam_users_of(const iam_state& s, std::string_view action, const iam_fields& f)
{
    if (action.find("Role") != std::string_view::npos || iam_own_action(action) ||
        (action.find("Group") != std::string_view::npos && action != "ListGroupsForUser" &&
         action != "AddUserToGroup" && action != "RemoveUserFromGroup") ||
        action == "ListUsers")
        return {};
    const std::string* n = field_of(f, "UserName");
    if ((action == "UpdateAccessKey" || action == "DeleteAccessKey") && !n)
        if (const std::string* id = field_of(f, "AccessKeyId"))
            if (const auto k = s.keys.find(*id); k != s.keys.end())
                return {k->second.user};
    std::vector<std::string> out{n ? *n : std::string()};
    if (action == "UpdateUser")
        if (const std::string* nn = field_of(f, "NewUserName"))
            out.push_back(*nn);
    return out;
}

std::vector<std::string> iam_resources(const iam_state& s, std::string_view action, const iam_fields& f)
{
    if (action == "ListUsers" || action == "ListGroups" || action == "ListRoles")
        return {std::string{}};
    auto text = [&f](std::string_view n)
    {
        const std::string* v = field_of(f, n);
        return v ? *v : std::string{};
    };
    auto named = [](std::string_view kind, const std::string& path, const std::string& name)
    { return std::string(kind) + (path.empty() ? std::string("/") : path) + name; };
    // An entity that is not there has the default path, and the request that makes one gives its own.
    auto path_in = [](const auto& entities, const std::string& name)
    {
        const auto it = entities.find(name);
        return it == entities.end() ? std::string("/") : it->second.path;
    };
    const bool creates = action == "CreateUser" || action == "CreateGroup" || action == "CreateRole";
    const std::string made_path = field_of(f, "Path") ? text("Path") : std::string("/");
    if (action.find("Role") != std::string_view::npos)
    {
        const std::string n = text("RoleName");
        return {named("role", creates ? made_path : path_in(s.roles, n), n)};
    }
    if (action.find("Group") != std::string_view::npos && action != "ListGroupsForUser")
    {
        const std::string n = text("GroupName");
        return {named("group", creates ? made_path : path_in(s.groups, n), n)};
    }
    std::string n = text("UserName");
    // A key named without its user is its own user's to change.
    if ((action == "UpdateAccessKey" || action == "DeleteAccessKey") && !field_of(f, "UserName"))
        if (const auto k = s.keys.find(text("AccessKeyId")); k != s.keys.end())
            n = k->second.user;
    std::vector<std::string> out{named("user", creates ? made_path : path_in(s.users, n), n)};
    // A rename or a move is a right over the user it makes as well, as IAM asks for both.
    if (action == "UpdateUser" && (field_of(f, "NewUserName") || field_of(f, "NewPath")))
        out.push_back(named("user", field_of(f, "NewPath") ? text("NewPath") : path_in(s.users, n),
                            field_of(f, "NewUserName") ? text("NewUserName") : n));
    return out;
}

bool iam_grants_iam(const iam_state& s, std::string_view action, const iam_fields& f)
{
    // Making an admin is an admin's alone, and so are the tags the runtime reads, which say what a user may hold.
    if (action == "AddUserToGroup" || action == "RemoveUserFromGroup")
        if (const std::string* g = field_of(f, "GroupName"); g && *g == iam_admins_group)
            return true;
    // Taking from the admins group is as much an admin's to do as giving to it.
    if (action == "CreateGroup" || action == "DeleteGroup" || action == "PutGroupPolicy" ||
        action == "AttachGroupPolicy" || action == "DetachGroupPolicy" || action == "DeleteGroupPolicy" ||
        action == "UpdateGroup")
        if (const std::string* g = field_of(f, "GroupName"); g && *g == iam_admins_group)
            return true;
    if (action == "TagUser" || action == "UntagUser")
        for (const auto& [k, v] : f)
            if ((k.starts_with("Tags.member.") && k.ends_with(".Key") && v.starts_with("socketley:")) ||
                (k.starts_with("TagKeys.member.") && v.starts_with("socketley:")))
                return true;
    if (action == "PutUserPolicy" || action == "PutGroupPolicy" || action == "PutRolePolicy")
    {
        const std::string* d = field_of(f, "PolicyDocument");
        return d && doc_grants_iam(*d);
    }
    if (action == "AttachUserPolicy" || action == "AttachGroupPolicy" || action == "AttachRolePolicy")
    {
        const std::string* a = field_of(f, "PolicyArn");
        const char* m = a ? iam_managed_policy(*a) : nullptr;
        return m && doc_grants_iam(m);
    }
    if (action != "AddUserToGroup")
        return false;
    const std::string* g = field_of(f, "GroupName");
    const auto it = g ? s.groups.find(*g) : s.groups.end();
    if (it == s.groups.end())
        return false;
    std::vector<std::string_view> docs;
    docs_of(it->second.policies, docs);
    for (std::string_view d : docs)
        if (doc_grants_iam(d))
            return true;
    return false;
}

bool iam_defaults_to_caller(std::string_view action)
{
    return action == "GetUser" || action == "CreateAccessKey" || action == "ListAccessKeys" ||
           action == "GetLoginProfile" || action == "ListUserTags" || action == "ListGroupsForUser" ||
           action == "socketley:CreateInvitation";
}

iam_result iam_apply(iam_state& s, std::string_view action, const iam_fields& fields, int64_t now_ms,
                     std::string_view request_id, bool (*taken)(void*, std::string_view), void* taken_ctx)
{
    api x{s, action, fields, now_ms, request_id, taken, taken_ctx, {}};
    x.run();
    return x.r;
}

}   // namespace socketley::storage
