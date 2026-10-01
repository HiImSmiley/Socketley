#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "../../socketley/runtime/storage/bucket_policy.h"

#include <string>
#include <string_view>

// The JSON a bucket policy is read from, at its edges: escapes and raw UTF-8, nesting, numbers, names given twice,
// and the size limit; and the refusing policy a stored document that stops compiling becomes.

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
