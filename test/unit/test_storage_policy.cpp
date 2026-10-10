#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "../../socketley/runtime/storage/bucket_policy.h"
#include "../../socketley/shared/glob_match.h"
#include "../../socketley/runtime/storage/json_doc.h"

#include <string>
#include <string_view>

// The JSON a bucket policy is read from, at its edges: escapes and raw UTF-8, nesting, numbers, names given twice,
// a value read into twice, and the size limit; and the refusing policy a stored document that stops compiling becomes.

using namespace socketley::storage;

namespace {

const std::string tail = R"("Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*"})";

// One Allow statement with `effect_name` for its Effect field and `extra` before it, so a test varies only the JSON around it.
std::string doc_with(std::string_view top_extra, std::string_view effect_name = "\"Effect\"")
{
    return "{" + std::string(top_extra) + "\"Statement\":{" + std::string(effect_name) + ":\"Allow\"," + tail + "}";
}

bool compiles(std::string_view json, s3_error* out = nullptr)
{
    bucket_policy p;
    s3_error err;
    const bool ok = bucket_policy::compile(json, "pub", p, err);
    if (out)
        *out = err;
    if (!ok)
    {
        CHECK(err.code == "MalformedPolicy");
        CHECK(err.status == 400);
    }
    return ok;
}

policy_effect anonymous_get(std::string_view json, std::string_view key)
{
    bucket_policy p;
    s3_error err;
    REQUIRE(bucket_policy::compile(json, "pub", p, err));
    policy_request r;
    r.action    = s3_action::get_object;
    r.key       = key;
    r.anonymous = true;
    return p.evaluate(r);
}

}   // namespace

TEST_CASE("the plain document compiles, so every refusal below is the edge it names")
{
    CHECK(compiles(doc_with("")));
    CHECK(compiles(doc_with(R"("Version":"2012-10-17",)")));
}

TEST_CASE("unicode escapes are read as the characters they name, and a broken one is refused")
{
    // A field name is compared after its escapes are read.
    CHECK(compiles(doc_with("", R"("Effect")")));
    CHECK(compiles(doc_with("", R"("Effect")")));
    CHECK_FALSE(compiles(doc_with("", R"("effect")")));

    // A resource with an escaped character matches the key with the character.
    const std::string esc = R"({"Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/café/😀"}})";
    CHECK(anonymous_get(esc, "café/😀") == policy_effect::allow);
    CHECK(anonymous_get(esc, "cafe/😀") == policy_effect::none);
    const std::string raw = R"({"Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/café/😀"}})";
    CHECK(anonymous_get(raw, "café/😀") == policy_effect::allow);

    for (const char* bad : {R"("\ud800")", R"("\udc00")", R"("\udc00\ud800")", R"("\ud800A")", R"("\ud800x")",
                            R"("\u12")", R"("\u12G4")", R"("\x41")", R"("\)"})
    {
        INFO(std::string(bad));
        CHECK_FALSE(compiles(doc_with(std::string("\"Id\":") + bad + ",")));
    }
    CHECK(compiles(doc_with(R"("Id":"\u0000\u001f\"\\\/\b\f\n\r\t",)")));
}

TEST_CASE("raw bytes in a string are valid UTF-8 or the document is refused")
{
    CHECK(compiles(doc_with("\"Id\":\"\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80\xf4\x8f\xbf\xbf\",")));
    for (const char* bad : {"\x80", "\xc0\xaf", "\xc1\xbf", "\xe0\x80\xaf", "\xed\xa0\x80", "\xf0\x80\x80\xaf",
                            "\xf4\x90\x80\x80", "\xf5\x80\x80\x80", "\xff", "\xe2\x82", "\xc3", "\xc3\x41"})
    {
        INFO(std::string_view(bad));
        CHECK_FALSE(compiles(doc_with(std::string("\"Id\":\"") + bad + "\",")));
    }
    // A control character must be escaped, and DEL need not be.
    CHECK_FALSE(compiles(doc_with("\"Id\":\"a\x01z\",")));
    CHECK(compiles(doc_with("\"Id\":\"a\x7fz\",")));
}

TEST_CASE("nesting is bounded, and a document nested past it is refused rather than recursed into")
{
    auto nested = [](int depth) { return std::string(static_cast<size_t>(depth), '[') + std::string(static_cast<size_t>(depth), ']'); };
    // Id must be a string, so even a shallow list is refused, but by the compiler and not the reader.
    s3_error err;
    CHECK_FALSE(compiles(doc_with("\"Id\":" + nested(3) + ","), &err));
    CHECK(err.message == "Id must be a string");
    CHECK_FALSE(compiles(doc_with("\"Id\":" + nested(40) + ","), &err));
    CHECK(err.message.find("valid JSON") != std::string::npos);
    // As deep as the size limit allows, which is far past the bound.
    CHECK_FALSE(compiles("{\"Id\":" + nested(10200) + "}", &err));
    CHECK(err.message.find("valid JSON") != std::string::npos);
    CHECK_FALSE(compiles(std::string(20000, '{'), &err));
}

TEST_CASE("a document read into a value that holds one is the second document alone")
{
    // As an ACME client asks an authorization again: the second answer read into the first's value.
    jvalue doc;
    REQUIRE(json_reader(R"({"status":"pending","challenges":[{"type":"http-01"}]})").document(doc));
    REQUIRE(json_reader(R"({"status":"valid"})").document(doc));
    REQUIRE(doc.members.size() == 1);
    CHECK(doc.members[0].first == "status");
    CHECK(doc.members[0].second.s == "valid");
    CHECK_FALSE(json_reader("[1]").document(doc));
    CHECK(doc.members.empty());
}

TEST_CASE("a number is read whatever its size and never taken for anything a policy says")
{
    s3_error err;
    for (const char* n : {"1e999999999", "-1e-999999999", "123456789012345678901234567890123456789012345678901234567890",
                          "0.0000000000000000000000000000001", "-0", "1E+2"})
    {
        INFO(std::string(n));
        CHECK_FALSE(compiles(doc_with(std::string("\"Id\":") + n + ","), &err));
        CHECK(err.message == "Id must be a string");
        CHECK_FALSE(compiles(doc_with(std::string("\"Version\":") + n + ","), &err));
    }
    for (const char* n : {"01", "1.", ".5", "+1", "1e", "-", "1e+", "NaN", "Infinity", "0x10"})
    {
        INFO(std::string(n));
        CHECK_FALSE(compiles(doc_with(std::string("\"Id\":") + n + ","), &err));
        CHECK(err.message.find("valid JSON") != std::string::npos);
    }
}

TEST_CASE("a name given twice in any object is refused, also when the two are spelled differently")
{
    s3_error err;
    CHECK_FALSE(compiles(doc_with(R"("Id":"a","Id":"a",)"), &err));
    CHECK(err.message.find("valid JSON") != std::string::npos);
    CHECK_FALSE(compiles(R"({"Statement":{"Effect":"Allow","Effect":"Deny",)" + tail + "}"));
    CHECK_FALSE(compiles(R"({"Statement":{"Effect":"Allow","Effect":"Deny",)" + tail + "}"));
    CHECK_FALSE(compiles(R"({"Statement":{"Effect":"Allow","Principal":{"AWS":"*","AWS":"x"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*"}})"));
    CHECK_FALSE(compiles(R"({"Statement":{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*",)"
                         R"("Condition":{"Bool":{"aws:SecureTransport":"false"},"Bool":{"aws:SecureTransport":"true"}}}})"));
    // Names that differ only in case are two names, as JSON has them.
    CHECK_FALSE(compiles(doc_with(R"("Id":"a","id":"b",)"), &err));
    CHECK(err.message == "Unknown field id");
    // Many distinct names are not mistaken for repeats.
    std::string many = "{\"Id\":\"x\",\"Statement\":[";
    for (int i = 0; i < 100; ++i)
        many += std::string(i ? "," : "") + R"({"Sid":"s)" + std::to_string(i) + R"(","Effect":"Allow",)" + tail;
    many += "]}";
    CHECK(compiles(many));
}

TEST_CASE("the size limit is on the document as given")
{
    const std::string base = doc_with(R"("Id":"",)");
    const size_t room = policy_max_bytes - base.size();
    CHECK(compiles(doc_with("\"Id\":\"" + std::string(room, 'x') + "\",")));
    s3_error err;
    CHECK_FALSE(compiles(doc_with("\"Id\":\"" + std::string(room + 1, 'x') + "\","), &err));
    CHECK(err.message.find("20 KiB") != std::string::npos);
    CHECK(compiles(std::string(room, ' ') + base));
    CHECK_FALSE(compiles(std::string(room + 1, ' ') + base));
}

TEST_CASE("what surrounds the document: leading and trailing whitespace only")
{
    CHECK(compiles(" \t\r\n" + doc_with("") + " \n"));
    for (const std::string& bad : {doc_with("") + "x", doc_with("") + "{}", "\xef\xbb\xbf" + doc_with(""), doc_with("") + std::string(1, '\0'),
                                   std::string("\f") + doc_with(""), std::string(), std::string("null"), std::string("\"x\"")})
    {
        INFO(bad);
        CHECK_FALSE(compiles(bad));
    }
}

TEST_CASE("a refusing policy denies everything it is asked and keeps the stored text")
{
    const std::string text = R"({"Statement":{"Effect":"Deny","NotPrincipal":{"AWS":"k"}}})";
    const bucket_policy p = bucket_policy::refusing(text, "NotPrincipal is not supported");
    CHECK(p.text() == text);
    CHECK(p.broken() == "NotPrincipal is not supported");
    CHECK(p.has_deny());
    CHECK_FALSE(p.is_public());
    CHECK_FALSE(p.needs_ip());
    for (int a = 1; a < static_cast<int>(s3_action::count); ++a)
        for (const bool anon : {false, true})
        {
            policy_request r;
            r.action    = static_cast<s3_action>(a);
            r.key       = "k";
            r.anonymous = anon;
            r.principal = anon ? "" : "AKIA";
            CHECK(p.evaluate(r) == policy_effect::deny);
        }
    CHECK_FALSE(bucket_policy::refusing(text, "").broken().empty());
}

namespace {

// A policy of one statement on PutObject in "pub" whose Condition is `cond`.
std::string put_policy(std::string_view effect, std::string_view cond)
{
    return R"({"Version":"2012-10-17","Statement":{"Effect":")" + std::string(effect) +
           R"(","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::pub/*","Condition":)" +
           std::string(cond) + "}}";
}

// What an anonymous PutObject (or a part, when `inherited`) is judged, with the encryption header `sse` when `sent`.
policy_effect anonymous_put(const bucket_policy& p, bool sent, std::string_view sse = {}, bool inherited = false)
{
    policy_request r;
    r.action        = s3_action::put_object;
    r.key           = "k";
    r.anonymous     = true;
    r.sse_sent      = sent;
    r.sse           = sse;
    r.sse_inherited = inherited;
    return p.evaluate(r);
}

bucket_policy compiled(const std::string& json)
{
    bucket_policy p;
    s3_error err;
    INFO(err.message);
    REQUIRE(bucket_policy::compile(json, "pub", p, err));
    return p;
}

}   // namespace

TEST_CASE("s3:x-amz-server-side-encryption under StringEquals, StringNotEquals and Null judges a put by its header")
{
    // The policy S3's documentation gives for requiring SSE-S3: deny a put that names another method, or none.
    const bucket_policy ne = compiled(put_policy("Deny", R"({"StringNotEquals":{"s3:x-amz-server-side-encryption":"AES256"}})"));
    CHECK(anonymous_put(ne, true, "AES256") == policy_effect::none);
    CHECK(anonymous_put(ne, true, "aws:kms") == policy_effect::deny);
    // A header that is not sent equals nothing, so it differs from AES256 too.
    CHECK(anonymous_put(ne, false) == policy_effect::deny);
    // Values are compared as given, as StringEquals compares them.
    CHECK(anonymous_put(ne, true, "aes256") == policy_effect::deny);

    const bucket_policy null_true = compiled(put_policy("Deny", R"({"Null":{"s3:x-amz-server-side-encryption":"true"}})"));
    CHECK(anonymous_put(null_true, false) == policy_effect::deny);
    CHECK(anonymous_put(null_true, true, "AES256") == policy_effect::none);
    const bucket_policy null_false = compiled(put_policy("Deny", R"({"Null":{"s3:x-amz-server-side-encryption":false}})"));
    CHECK(anonymous_put(null_false, false) == policy_effect::none);
    CHECK(anonymous_put(null_false, true, "AES256") == policy_effect::deny);
    // Both values are every request.
    const bucket_policy null_both = compiled(put_policy("Deny", R"({"Null":{"s3:x-amz-server-side-encryption":["true","false"]}})"));
    CHECK(anonymous_put(null_both, false) == policy_effect::deny);
    CHECK(anonymous_put(null_both, true, "AES256") == policy_effect::deny);

    const bucket_policy eq = compiled(put_policy("Allow", R"({"StringEquals":{"s3:x-amz-server-side-encryption":["AES256","aws:kms"]}})"));
    CHECK(anonymous_put(eq, true, "AES256") == policy_effect::allow);
    CHECK(anonymous_put(eq, true, "aws:kms") == policy_effect::allow);
    CHECK(anonymous_put(eq, true, "x") == policy_effect::none);
    CHECK(anonymous_put(eq, false) == policy_effect::none);

    // Two operators in one Condition must both hold, and the key is named in any case, as IAM names it.
    const bucket_policy both = compiled(put_policy("Deny", R"({"StringNotEquals":{"S3:X-Amz-Server-Side-Encryption":"AES256"},"Null":{"s3:x-amz-server-side-encryption":"false"}})"));
    CHECK(anonymous_put(both, false) == policy_effect::none);
    CHECK(anonymous_put(both, true, "aws:kms") == policy_effect::deny);
    CHECK(anonymous_put(both, true, "AES256") == policy_effect::none);

    // A part or a completion was judged when its upload was created, so neither a Deny nor an Allow on the header is about it.
    for (const bucket_policy* p : {&ne, &null_true, &null_false, &eq})
        CHECK(anonymous_put(*p, false, {}, true) == policy_effect::none);
}

TEST_CASE("StringLike's star is a wildcard where the value holds a star of its own")
{
    // Matched first as the same character, the star was never remembered as one, and a Referer the client chose,
    // "https://evil.example/*x", escaped a Deny on "https://evil.example/*".
    struct referer : policy_context
    {
        std::string v;
        bool values(std::string_view key, std::vector<std::string>& out) const override
        {
            if (key != "aws:referer")
                return false;
            out.push_back(v);
            return true;
        }
    };
    const bucket_policy like = compiled(put_policy("Deny", R"({"StringLike":{"aws:Referer":"https://evil.example/*"}})"));
    const auto put_from = [&](std::string v)
    {
        referer ctx;
        ctx.v = std::move(v);
        policy_request r;
        r.action    = s3_action::put_object;
        r.key       = "k";
        r.anonymous = true;
        r.ctx       = &ctx;
        return like.evaluate(r);
    };
    CHECK(put_from("https://evil.example/page") == policy_effect::deny);
    CHECK(put_from("https://evil.example/*x") == policy_effect::deny);
    CHECK(put_from("https://evil.example/*") == policy_effect::deny);
    CHECK(put_from("https://good.example/page") == policy_effect::none);

    CHECK(socketley::iam_wild_match("https://evil.example/*", "https://evil.example/*x"));
    CHECK(socketley::iam_wild_match("a*b", "a*xb"));
    CHECK(socketley::iam_wild_match("a?c", "a?c"));
    CHECK_FALSE(socketley::iam_wild_match("a*b", "a*x"));
    CHECK(socketley::iam_wild_match("ARN:*", "arn:x", true));
    CHECK_FALSE(socketley::iam_wild_match("ARN:*", "arn:x", false));
}

TEST_CASE("a condition is refused where it cannot be honoured exactly, and taken on any key a request carries")
{
    for (const char* cond : {R"({"Null":{"s3:x-amz-server-side-encryption":"maybe"}})",
                             R"({"StringEquals":{"s3:x-amz-server-side-encryption":[]}})",
                             R"({"StringEquals":{"s3:x-amz-server-side-encryption":7}})",
                             R"({"StringEquals":{"s3:x-amz-server-side-encryption":"AES256","aws:SourceIp":"1.2.3.4"}})",
                             R"({"StringEquals":{"s3:ExistingObjectTag/team":"a"}})",
                             R"({"BinaryEquals":{"aws:Referer":"eA=="}})",
                             R"({"NumericLessThan":{"s3:max-keys":"ten"}})"})
    {
        INFO(cond);
        s3_error err;
        CHECK_FALSE(compiles(put_policy("Deny", cond), &err));
        CHECK_FALSE(err.message.empty());
    }
    for (const char* cond : {R"({"StringEquals":{"s3:x-amz-server-side-encryption-aws-kms-key-id":"k"}})",
                             R"({"StringEquals":{"s3:prefix":"a"}})",
                             R"({"StringEqualsIgnoreCase":{"s3:x-amz-server-side-encryption":"aes256"}})",
                             R"({"StringNotEqualsIfExists":{"s3:x-amz-server-side-encryption":"AES256"}})",
                             R"({"Null":{"aws:SourceIp":"true"}})"})
    {
        INFO(cond);
        CHECK(compiles(put_policy("Deny", cond)));
    }
}

namespace {

bucket_policy identity(const std::string& json)
{
    bucket_policy p;
    s3_error err;
    const bool ok = bucket_policy::compile_identity(json, p, err);
    INFO(err.message);
    REQUIRE(ok);
    return p;
}

policy_effect user_does(const bucket_policy& p, s3_action a, std::string_view bucket, std::string_view key = {},
                        bool every_key = false)
{
    policy_request r;
    r.action    = a;
    r.bucket    = bucket;
    r.key       = key;
    r.principal = "AKIAUSER";
    r.user      = "alice";
    r.every_key = every_key;
    return p.evaluate(r);
}

}   // namespace

TEST_CASE("an identity policy names no principal and matches its resources against bucket and bucket/key as IAM does")
{
    s3_error err;
    bucket_policy p;
    CHECK_FALSE(bucket_policy::compile_identity(
        R"({"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"*"}})", p, err));
    CHECK(err.message.find("principal") != std::string::npos);
    CHECK_FALSE(bucket_policy::compile_identity(
        R"({"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::${aws:username}/*"}})", p, err));
    // An IAM resource is taken beside an S3 action, and covers no S3 request.
    const bucket_policy cross = identity(R"({"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:iam:::user/x"}})");
    CHECK(user_does(cross, s3_action::get_object, "user", "x") == policy_effect::none);

    const bucket_policy all = identity(R"({"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}})");
    CHECK(user_does(all, s3_action::get_object, "any", "k") == policy_effect::allow);
    CHECK(user_does(all, s3_action::delete_bucket, "any") == policy_effect::allow);

    const bucket_policy logs = identity(R"({"Statement":[
        {"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::logs-*","arn:aws:s3:::logs-*/2026/*"]},
        {"Effect":"Deny","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::logs-a/keep/*"},
        {"Effect":"Allow","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::logs-b/*"}]})");
    CHECK(user_does(logs, s3_action::list_bucket, "logs-a") == policy_effect::allow);
    CHECK(user_does(logs, s3_action::list_bucket, "other") == policy_effect::none);
    CHECK(user_does(logs, s3_action::get_object, "logs-a", "2026/x") == policy_effect::allow);
    CHECK(user_does(logs, s3_action::delete_object, "logs-a", "keep/x") == policy_effect::deny);
    CHECK(user_does(logs, s3_action::delete_object, "logs-a", "other") == policy_effect::none);
    // DeleteObjects names its keys in the body: a Deny over any key refuses it, and only an Allow over all lets it in.
    CHECK(user_does(logs, s3_action::delete_object, "logs-a", {}, true) == policy_effect::deny);
    CHECK(user_does(logs, s3_action::delete_object, "logs-b", {}, true) == policy_effect::allow);
    CHECK(user_does(logs, s3_action::delete_object, "logs-c", {}, true) == policy_effect::none);

    // '*' spans '/' as it does in IAM, so a pattern for buckets names their objects too, which is why
    // "logs-*" lets the user read 2025/x though "logs-*/2026/*" would not.
    const bucket_policy star = identity(R"({"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::logs-*"}})");
    CHECK(user_does(star, s3_action::get_object, "logs-a", "any/key") == policy_effect::allow);
    CHECK(user_does(star, s3_action::get_object, "other", "logs-a") == policy_effect::none);
    CHECK(user_does(logs, s3_action::get_object, "logs-a", "2025/x") == policy_effect::allow);
}

TEST_CASE("a bucket policy's principal names a user by its id as well as by an access key")
{
    bucket_policy p;
    s3_error err;
    REQUIRE(bucket_policy::compile(R"({"Statement":[
        {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/alice"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/a/*"},
        {"Effect":"Allow","Principal":{"AWS":"AKIAUSER"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/b/*"}]})",
                                   "pub", p, err));
    CHECK(user_does(p, s3_action::get_object, "pub", "a/x") == policy_effect::allow);
    CHECK(user_does(p, s3_action::get_object, "pub", "b/x") == policy_effect::allow);
    policy_request bob;
    bob.action    = s3_action::get_object;
    bob.key       = "a/x";
    bob.principal = "AKIABOB";
    bob.user      = "bob";
    CHECK(p.evaluate(bob) == policy_effect::none);
}

namespace {

// What `p` says to user `user` asking IAM action `action` on `resource`, after "arn:aws:iam::<account>:".
policy_effect iam_does(const bucket_policy& p, std::string_view action, std::string_view resource,
                       std::string_view user = "alice")
{
    policy_request r;
    r.iam_action   = iam_action_index(action);
    REQUIRE(r.iam_action >= 0);
    r.iam_resource = resource;
    r.principal    = "AKIAUSER";
    r.user         = user;
    return p.evaluate(r);
}

}   // namespace

TEST_CASE("the IAM actions are the ones the endpoint answers, each with a bit of its own")
{
    CHECK(iam_action_index("CreateUser") == 0);
    CHECK(iam_action_index("ListUserTags") == static_cast<int>(std::size(iam_action_names)) - 1);
    CHECK(iam_action_index("CreateVirtualMFADevice") == -1);
    CHECK(iam_action_index("createuser") == -1);
}

TEST_CASE("an identity policy names IAM actions and resources, with wildcards and ${aws:username}, and a Deny wins")
{
    const bucket_policy own = identity(R"({"Statement":[
        {"Effect":"Allow","Action":["iam:CreateAccessKey","iam:ListAccessKeys"],"Resource":"arn:aws:iam:::user/${aws:username}"},
        {"Effect":"Allow","Action":"iam:List*","Resource":"*"},
        {"Effect":"Allow","Action":"iam:get*","Resource":"arn:aws:iam::123456789012:user/team/*"},
        {"Effect":"Deny","Action":"iam:ListRoles","Resource":"*"}]})");
    CHECK(iam_does(own, "CreateAccessKey", "user/alice") == policy_effect::allow);
    CHECK(iam_does(own, "CreateAccessKey", "user/bob") == policy_effect::none);
    CHECK(iam_does(own, "CreateAccessKey", "user/bob", "bob") == policy_effect::allow);
    // The variable fills in the caller's name whole, so it is no prefix of another's.
    CHECK(iam_does(own, "CreateAccessKey", "user/alice2") == policy_effect::none);
    CHECK(iam_does(own, "CreateAccessKey", "user/team/alice") == policy_effect::none);
    // A caller with no user id gives the variable no value, which matches nothing.
    CHECK(iam_does(own, "CreateAccessKey", "user/", "") == policy_effect::none);
    CHECK(iam_does(own, "DeleteAccessKey", "user/alice") == policy_effect::none);
    // iam:List* is every List action, and an action on no resource is covered by "*" alone.
    CHECK(iam_does(own, "ListUsers", "") == policy_effect::allow);
    CHECK(iam_does(own, "ListGroupsForUser", "user/bob") == policy_effect::allow);
    CHECK(iam_does(own, "ListRoles", "") == policy_effect::deny);
    // Action names match without case, as IAM's do, and resources in any account.
    CHECK(iam_does(own, "GetUser", "user/team/carol") == policy_effect::allow);
    CHECK(iam_does(own, "GetUser", "user/carol") == policy_effect::none);
    CHECK(iam_does(own, "CreateUser", "user/team/carol") == policy_effect::none);

    const bucket_policy users = identity(R"({"Statement":{"Effect":"Allow","Action":"iam:ListUsers","Resource":"arn:aws:iam:::user/*"}})");
    CHECK(iam_does(users, "ListUsers", "") == policy_effect::none);

    // "*" is S3's actions alone, so a policy written before IAM could be delegated gives none of it.
    const bucket_policy all = identity(R"({"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}})");
    CHECK(iam_does(all, "DeleteUser", "user/x") == policy_effect::none);
    CHECK(user_does(all, s3_action::get_object, "any", "k") == policy_effect::allow);
    CHECK_FALSE(all.allows_iam());
    // iam:* names every IAM action, and an explicit Deny takes any of them back.
    const bucket_policy every = identity(R"({"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"},
        {"Effect":"Deny","Action":"iam:*","Resource":"arn:aws:iam:::user/root*"}]})");
    CHECK(iam_does(every, "DeleteUser", "user/x") == policy_effect::allow);
    CHECK(iam_does(every, "DeleteUser", "user/rooted") == policy_effect::deny);

    // IAM's statements say nothing to S3's requests, nor S3's to IAM's.
    const bucket_policy s3_only = identity(R"({"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}})");
    CHECK(iam_does(s3_only, "ListUsers", "") == policy_effect::none);
    const bucket_policy iam_only = identity(R"({"Statement":{"Effect":"Allow","Action":"iam:*","Resource":"*"}})");
    CHECK(user_does(iam_only, s3_action::get_object, "any", "k") == policy_effect::none);
}

TEST_CASE("an IAM action or resource this runtime cannot honour is refused, and one it does not answer is taken")
{
    s3_error err;
    bucket_policy p;
    // An IAM action IAM has and this runtime does not answer matches nothing, so a policy written for AWS compiles.
    const bucket_policy other = identity(R"({"Statement":{"Effect":"Allow","Action":"iam:CreateVirtualMFADevice","Resource":"*"}})");
    CHECK_FALSE(other.allows_iam());
    CHECK_FALSE(bucket_policy::compile_identity(
        R"({"Statement":{"Effect":"Allow","Action":"iam:Create-User","Resource":"*"}})", p, err));
    CHECK_FALSE(bucket_policy::compile_identity(R"({"Statement":{"Effect":"Allow","Action":"iam:","Resource":"*"}})", p, err));
    CHECK_FALSE(bucket_policy::compile_identity(
        R"({"Statement":{"Effect":"Allow","Action":"iam:GetUser","Resource":"arn:aws:iam:::user/${aws:userid}"}})", p, err));
    CHECK(err.message.find("${aws:username}") != std::string::npos);
    CHECK_FALSE(bucket_policy::compile_identity(
        R"({"Statement":{"Effect":"Allow","Action":"iam:GetUser","Resource":"arn:aws:iam::user/x"}})", p, err));
    CHECK_FALSE(bucket_policy::compile_identity(
        R"({"Statement":{"Effect":"Allow","Action":"iam:GetUser","Resource":"arn:aws:iam:::user/${aws:username"}})", p, err));
    // The variable's name is read without case, as IAM reads it.
    const bucket_policy upper = identity(R"({"Statement":{"Effect":"Allow","Action":"iam:GetUser","Resource":"arn:aws:iam:::user/${AWS:UserName}"}})");
    CHECK(iam_does(upper, "GetUser", "user/alice") == policy_effect::allow);
    // A bucket's policy names no IAM action.
    CHECK_FALSE(bucket_policy::compile(
        R"({"Statement":{"Effect":"Allow","Principal":"*","Action":"iam:ListUsers","Resource":"arn:aws:s3:::pub"}})", "pub", p, err));
}

TEST_CASE("allows_iam is an Allow of an IAM action on some IAM resource")
{
    CHECK(identity(R"({"Statement":{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*"}})").allows_iam());
    // "*" is S3's actions alone.
    CHECK_FALSE(identity(R"({"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}})").allows_iam());
    CHECK(identity(R"({"Statement":{"Effect":"Allow","Action":["*","iam:*"],"Resource":"*"}})").allows_iam());
    CHECK(identity(R"({"Statement":{"Effect":"Allow","Action":"iam:*","Resource":"arn:aws:iam:::user/a"}})").allows_iam());
    CHECK_FALSE(identity(R"({"Statement":{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::*"}})").allows_iam());
    CHECK_FALSE(identity(R"({"Statement":{"Effect":"Deny","Action":"iam:*","Resource":"*"}})").allows_iam());
    CHECK_FALSE(identity(R"({"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}})").allows_iam());
}
