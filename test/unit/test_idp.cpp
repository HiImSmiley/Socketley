// The identity provider's decisions without a socket: which clients a file declares, what a form says, PKCE, the
// tokens it signs and what makes one fail, and where a browser may be sent back to.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <cstdlib>
#include <string>
#include <unistd.h>

#include <openssl/evp.h>

#include "runtime/idp/idp_logic.h"
#include "shared/jws.h"

using namespace socketley::idp;

namespace
{

EVP_PKEY* fresh_key()
{
    std::string err;
    const std::string path = "/tmp/skl-idp-test-" + std::to_string(::getpid()) + "-" + std::to_string(rand()) + ".key";
    EVP_PKEY* k = socketley::jws::load_or_make_key(path, "the test key", err);
    ::unlink(path.c_str());
    return k;
}

}   // namespace

TEST_CASE("a clients file is read whole or not at all")
{
    std::vector<client> c;
    std::string why;
    REQUIRE(parse_clients("# apps\nwiki s3cret https://wiki.example.com/cb https://wiki.example.com/cb2\n"
                          "spa - http://localhost:5173/cb\n\n",
                          c, why));
    REQUIRE(c.size() == 2);
    CHECK(c[0].id == "wiki");
    CHECK(c[0].secret == "s3cret");
    CHECK(c[0].allows("https://wiki.example.com/cb2"));
    CHECK_FALSE(c[0].allows("https://wiki.example.com/cb/"));
    CHECK(c[1].is_public());

    CHECK_FALSE(parse_clients("wiki s3cret\n", c, why));
    CHECK(why.find("line 1") != std::string::npos);
    CHECK_FALSE(parse_clients("wiki s3cret http://wiki.example.com/cb\n", c, why));
    CHECK_FALSE(parse_clients("wiki s3cret http://localhost.evil.example/cb\n", c, why));
    CHECK_FALSE(parse_clients("wiki s3cret https://wiki.example.com/cb#x\n", c, why));
    CHECK_FALSE(parse_clients("a s https://a.example/cb\na t https://a.example/cb\n", c, why));
    CHECK(why.find("twice") != std::string::npos);
    CHECK_FALSE(parse_clients("we/ird s https://a.example/cb\n", c, why));
}

TEST_CASE("a form is decoded, and a pair that does not decode is left out")
{
    const params p = parse_form("a=1&b=x+y&c=%2Fpath%3Fq&bad=%zz&&d");
    CHECK(param(p, "a") == "1");
    CHECK(param(p, "b") == "x y");
    CHECK(param(p, "c") == "/path?q");
    CHECK(param(p, "bad").empty());
    CHECK(param(p, "d").empty());
    CHECK(url_encode("a b/c?d=é") == "a%20b%2Fc%3Fd%3D%C3%A9");
    CHECK(html_escape("<a href=\"x\">'&") == "&lt;a href=&quot;x&quot;&gt;&#39;&amp;");
    CHECK(json_string("a\"b\\c\n") == "\"a\\\"b\\\\c\\u000a\"");
}

TEST_CASE("PKCE S256 matches RFC 7636's own example and nothing else")
{
    // RFC 7636 Appendix B.
    const std::string verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    CHECK(pkce_matches(verifier, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
    CHECK_FALSE(pkce_matches(verifier, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cN"));
    CHECK_FALSE(pkce_matches("short", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
    CHECK_FALSE(pkce_matches(verifier, ""));
}

TEST_CASE("a browser is sent back only to the provider's host or the cookie domain")
{
    const std::string_view iss = "https://auth.example.com";
    CHECK(return_allowed("/", iss, ""));
    CHECK(return_allowed("https://auth.example.com/x", iss, ""));
    CHECK_FALSE(return_allowed("https://app.example.com/x", iss, ""));
    CHECK(return_allowed("https://app.example.com/x", iss, "example.com"));
    CHECK(return_allowed("https://example.com/", iss, ".example.com"));
    CHECK_FALSE(return_allowed("https://badexample.com/", iss, "example.com"));
    CHECK_FALSE(return_allowed("https://example.com.evil.net/", iss, "example.com"));
    CHECK_FALSE(return_allowed("https://evil.net@app.example.com/", iss, "example.com"));
    CHECK_FALSE(return_allowed("//evil.net/", iss, "example.com"));
    CHECK_FALSE(return_allowed("http://app.example.com/", iss, "example.com"));
    CHECK_FALSE(return_allowed("javascript:alert(1)", iss, "example.com"));
    CHECK(url_host("https://Auth.Example.com:8443/p") == "auth.example.com");
}

TEST_CASE("a token verifies with its own key and fails every way it was not made")
{
    EVP_PKEY* k = fresh_key();
    REQUIRE(k);
    const std::string kid = socketley::jws::thumbprint(k);
    const std::string iss = "https://auth.example.com";
    const std::string t = sign_token(k, kid, "JWT", "\"iss\":\"" + iss + "\",\"sub\":\"alice\",\"exp\":2000,\"admin\":true");
    claims c;
    std::string why;
    REQUIRE(verify_token(k, kid, "JWT", iss, t, 1000, c, why));
    CHECK(c["sub"] == "alice");
    CHECK(c["exp"] == "2000");
    CHECK(c["admin"] == "true");

    CHECK_FALSE(verify_token(k, kid, "JWT", iss, t, 2000, c, why));
    CHECK(why == "it has expired");
    CHECK_FALSE(verify_token(k, kid, "at+jwt", iss, t, 1000, c, why));
    CHECK_FALSE(verify_token(k, "other", "JWT", iss, t, 1000, c, why));
    CHECK_FALSE(verify_token(k, kid, "JWT", "https://other.example", t, 1000, c, why));

    // A claim changed after signing.
    const size_t d1 = t.find('.'), d2 = t.find('.', d1 + 1);
    const std::string forged = t.substr(0, d1 + 1) +
                               socketley::jws::b64url("{\"iss\":\"" + iss + "\",\"sub\":\"root\",\"exp\":2000}") +
                               t.substr(d2);
    CHECK_FALSE(verify_token(k, kid, "JWT", iss, forged, 1000, c, why));
    CHECK(why == "the signature does not hold");

    // The same claims signed by another key.
    EVP_PKEY* other = fresh_key();
    REQUIRE(other);
    const std::string theirs = sign_token(other, kid, "JWT", "\"iss\":\"" + iss + "\",\"sub\":\"alice\",\"exp\":2000");
    CHECK_FALSE(verify_token(k, kid, "JWT", iss, theirs, 1000, c, why));

    // alg none, which a careless verifier takes.
    const std::string none = socketley::jws::b64url("{\"alg\":\"none\",\"kid\":\"" + kid + "\",\"typ\":\"JWT\"}") + "." +
                             t.substr(d1 + 1, d2 - d1 - 1) + ".";
    CHECK_FALSE(verify_token(k, kid, "JWT", iss, none, 1000, c, why));
    CHECK_FALSE(verify_token(k, kid, "JWT", iss, "a.b", 1000, c, why));
    CHECK_FALSE(verify_token(k, kid, "JWT", iss, "", 1000, c, why));
    EVP_PKEY_free(other);
    EVP_PKEY_free(k);
}

TEST_CASE("a token only the provider reads is HS256 under a secret of its key, and nothing else passes for one")
{
    EVP_PKEY* k = fresh_key();
    EVP_PKEY* other = fresh_key();
    REQUIRE(k);
    REQUIRE(other);
    const std::string secret = token_secret(k);
    CHECK(secret.size() == 32);
    CHECK(token_secret(k) == secret);
    CHECK(token_secret(other) != secret);
    const std::string iss = "https://auth.example.com";
    const std::string body = "\"iss\":\"" + iss + "\",\"sub\":\"alice\",\"exp\":2000";
    const std::string t = sign_secret_token(secret, "refresh+jwt", body);
    claims c;
    std::string why;
    REQUIRE(verify_secret_token(secret, "refresh+jwt", iss, t, 1000, c, why));
    CHECK(c["sub"] == "alice");
    CHECK_FALSE(verify_secret_token(secret, "refresh+jwt", iss, t, 2000, c, why));
    CHECK_FALSE(verify_secret_token(secret, "at+jwt", iss, t, 1000, c, why));
    CHECK_FALSE(verify_secret_token(token_secret(other), "refresh+jwt", iss, t, 1000, c, why));
    CHECK(why == "the signature does not hold");
    // Neither kind is taken for the other, whatever the header says.
    const std::string kid = socketley::jws::thumbprint(k);
    CHECK_FALSE(verify_token(k, kid, "refresh+jwt", iss, t, 1000, c, why));
    CHECK_FALSE(verify_secret_token(secret, "refresh+jwt", iss, sign_token(k, kid, "refresh+jwt", body), 1000, c, why));
    const size_t d1 = t.find('.'), d2 = t.find('.', d1 + 1);
    const std::string forged = t.substr(0, d1 + 1) +
                               socketley::jws::b64url("{\"iss\":\"" + iss + "\",\"sub\":\"root\",\"exp\":2000}") +
                               t.substr(d2);
    CHECK_FALSE(verify_secret_token(secret, "refresh+jwt", iss, forged, 1000, c, why));
    EVP_PKEY_free(other);
    EVP_PKEY_free(k);
}

TEST_CASE("a token verified once is remembered for its typ until it expires, and a forgery is never remembered")
{
    EVP_PKEY* k = fresh_key();
    REQUIRE(k);
    const std::string kid = socketley::jws::thumbprint(k);
    const std::string iss = "https://auth.example.com";
    const std::string t = sign_token(k, kid, "at+jwt", "\"iss\":\"" + iss + "\",\"sub\":\"alice\",\"exp\":2000");
    verified_tokens seen;
    claims c;
    std::string why;
    REQUIRE(seen.verify(k, kid, "at+jwt", iss, t, 1000, c, why));
    c.clear();
    REQUIRE(seen.verify(k, kid, "at+jwt", iss, t, 1500, c, why));
    CHECK(c["sub"] == "alice");
    CHECK_FALSE(seen.verify(k, kid, "session+jwt", iss, t, 1500, c, why));
    CHECK_FALSE(seen.verify(k, kid, "at+jwt", "https://other.example", t, 1500, c, why));
    CHECK_FALSE(seen.verify(k, kid, "at+jwt", iss, t, 2000, c, why));
    const std::string forged = t.substr(0, t.rfind('.') + 1) + "AAAA";
    CHECK_FALSE(seen.verify(k, kid, "at+jwt", iss, forged, 1000, c, why));
    CHECK_FALSE(seen.verify(k, kid, "at+jwt", iss, forged, 1000, c, why));
    EVP_PKEY_free(k);
}

TEST_CASE("base64url decodes what it encodes and refuses a second spelling")
{
    for (int n = 0; n < 40; ++n)
    {
        std::string in;
        for (int i = 0; i < n; ++i)
            in += static_cast<char>(i * 37 + n);
        std::string out;
        REQUIRE(socketley::jws::b64url_decode(socketley::jws::b64url(in), out));
        CHECK(out == in);
    }
    std::string out;
    CHECK_FALSE(socketley::jws::b64url_decode("A", out));
    CHECK_FALSE(socketley::jws::b64url_decode("AB=", out));
    CHECK_FALSE(socketley::jws::b64url_decode("AB", out));   // the low bits of the last character are not zero
    CHECK(socketley::jws::b64url_decode("AA", out));
}

// ─── The accounts ───────────────────────────────────────────────────────────

#include <filesystem>
#include <fstream>

#include "runtime/idp/idp_accounts.h"

namespace
{

std::string fresh_dir()
{
    static int n = 0;
    const std::string d = "/tmp/skl-idp-accounts-" + std::to_string(::getpid()) + "-" + std::to_string(++n);
    std::filesystem::remove_all(d);
    return d;
}

}   // namespace

TEST_CASE("an account is kept across a reopen, with every field it was given, known or not")
{
    const std::string dir = fresh_dir();
    std::string id, why;
    {
        account_store s;
        REQUIRE(s.open(dir, why));
        REQUIRE(s.create({{"username", "Alice"}, {"email", "a@example.com"}, {"game.class", "mage"}}, id, why));
        CHECK(id.size() == 22);
        std::string other;
        CHECK_FALSE(s.create({{"username", "alice"}}, other, why));
        CHECK(why.find("taken") != std::string::npos);
        CHECK_FALSE(s.create({{"username", "bad name"}}, other, why));
        CHECK_FALSE(s.create({{"username", "bob"}, {"Bad", "x"}}, other, why));
        REQUIRE(s.update(id, {{"game.level", "12"}, {"email", ""}}, why));
    }
    account_store s;
    REQUIRE(s.open(dir, why));
    const account* a = s.by_name("ALICE");
    REQUIRE(a);
    CHECK(a->id == id);
    CHECK(a->field("game.class") == "mage");
    CHECK(a->field("game.level") == "12");
    CHECK(a->field("email").empty());
    CHECK(s.by_id(id) == a);
    std::filesystem::remove_all(dir);
}

TEST_CASE("a username changes without changing the id, and a removed account is gone after a reopen")
{
    const std::string dir = fresh_dir();
    std::string a, b, why;
    {
        account_store s;
        REQUIRE(s.open(dir, why));
        REQUIRE(s.create({{"username", "carol"}}, a, why));
        REQUIRE(s.create({{"username", "dave"}}, b, why));
        CHECK_FALSE(s.update(a, {{"username", "DAVE"}}, why));
        REQUIRE(s.update(a, {{"username", "caroline"}}, why));
        CHECK_FALSE(s.by_name("carol"));
        REQUIRE(s.remove(b, why));
    }
    account_store s;
    REQUIRE(s.open(dir, why));
    REQUIRE(s.by_name("caroline"));
    CHECK(s.by_name("caroline")->id == a);
    CHECK_FALSE(s.by_id(b));
    CHECK_FALSE(s.by_name("dave"));
    CHECK(s.size() == 1);
    std::filesystem::remove_all(dir);
}

TEST_CASE("a snapshot cuts the journal and holds what it held, a field it never heard of too")
{
    const std::string dir = fresh_dir();
    std::string id, why;
    {
        account_store s;
        REQUIRE(s.open(dir, why));
        REQUIRE(s.create({{"username", "erin"}, {"some.future-field", "kept"}}, id, why));
        for (int i = 0; i < 20; ++i)
            REQUIRE(s.update(id, {{"counter", std::to_string(i)}}, why));
        CHECK(s.journal_records() == 21);
        REQUIRE(s.compact(why));
        CHECK(s.journal_records() == 0);
        REQUIRE(s.update(id, {{"after", "1"}}, why));
    }
    account_store s;
    REQUIRE(s.open(dir, why));
    const account* a = s.by_name("erin");
    REQUIRE(a);
    CHECK(a->field("some.future-field") == "kept");
    CHECK(a->field("counter") == "19");
    CHECK(a->field("after") == "1");
    std::filesystem::remove_all(dir);
}

TEST_CASE("a snapshot of a newer format is refused, not read in part and written back")
{
    const std::string dir = fresh_dir();
    std::filesystem::create_directories(dir);
    {
        std::ofstream f(dir + "/accounts.snapshot");
        f << "{\"format\":\"socketley-idp-accounts\",\"version\":99}\n";
    }
    account_store s;
    std::string why;
    CHECK_FALSE(s.open(dir, why));
    CHECK(why.find("newer") != std::string::npos);
    std::filesystem::remove_all(dir);
}

TEST_CASE("a journal cut short by a crash keeps every whole record before the cut")
{
    const std::string dir = fresh_dir();
    std::string id, why;
    {
        account_store s;
        REQUIRE(s.open(dir, why));
        REQUIRE(s.create({{"username", "frank"}}, id, why));
        REQUIRE(s.update(id, {{"a", "1"}}, why));
        REQUIRE(s.update(id, {{"b", "2"}}, why));
    }
    const std::string j = dir + "/accounts.journal";
    std::filesystem::resize_file(j, std::filesystem::file_size(j) - 3);
    account_store s;
    REQUIRE(s.open(dir, why));
    const account* a = s.by_name("frank");
    REQUIRE(a);
    CHECK(a->field("a") == "1");
    CHECK(a->field("b").empty());
    // And the next change lands after the cut, read back whole.
    REQUIRE(s.update(id, {{"c", "3"}}, why));
    s.close();
    account_store t;
    REQUIRE(t.open(dir, why));
    CHECK(t.by_name("frank")->field("c") == "3");
    std::filesystem::remove_all(dir);
}

TEST_CASE("groups are a comma list, read one by one")
{
    account a;
    a.fields["groups"] = "beta, admins,team";
    CHECK(a.in_group("admins"));
    CHECK(a.in_group("beta"));
    CHECK_FALSE(a.in_group("admin"));
}

#include "runtime/idp/idp_shard.h"

TEST_CASE("a shard that reads the accounts takes each change in, and a new journal behind a snapshot whole")
{
    const std::string dir = fresh_dir();
    std::string a, b, why;
    account_store w;
    REQUIRE(w.open(dir, why));
    REQUIRE(w.create({{"username", "frank"}}, a, why));
    account_store r;
    REQUIRE(r.follow_open(dir, why));
    REQUIRE(r.by_name("frank"));
    CHECK_FALSE(r.update(a, {{"name", "F"}}, why));
    CHECK(why == "the accounts are written by shard 0");

    REQUIRE(w.update(a, {{"name", "Frank F"}}, why));
    REQUIRE(w.create({{"username", "gina"}}, b, why));
    // Nothing past the length shard 0 said, though the file holds more.
    CHECK(r.follow(w.journal_id(), 0));
    CHECK(r.by_name("frank")->field("name").empty());
    CHECK(r.follow(w.journal_id(), w.journal_end()));
    CHECK(r.by_name("frank")->field("name") == "Frank F");
    REQUIRE(r.by_name("gina"));

    const uint64_t before = w.journal_id();
    REQUIRE(w.compact(why));
    CHECK(w.journal_id() != before);
    REQUIRE(w.remove(b, why));
    // The journal it holds open is one the writer has left, so it reads the new one whole.
    CHECK_FALSE(r.follow(w.journal_id(), w.journal_end()));
    REQUIRE(r.follow_open(dir, why));
    CHECK(r.follow(w.journal_id(), w.journal_end()));
    CHECK_FALSE(r.by_name("gina"));
    REQUIRE(r.by_name("frank"));
    CHECK(r.by_name("frank")->field("name") == "Frank F");
    CHECK(r.size() == 1);
    std::filesystem::remove_all(dir);
}

TEST_CASE("a shard that reads accounts nobody has written yet starts empty and reads them once there are some")
{
    const std::string dir = fresh_dir();
    std::string a, why;
    account_store r;
    REQUIRE(r.follow_open(dir, why));
    CHECK(r.size() == 0);
    CHECK(r.follow(0, 0));
    account_store w;
    REQUIRE(w.open(dir, why));
    REQUIRE(w.create({{"username", "hal"}}, a, why));
    CHECK_FALSE(r.follow(w.journal_id(), w.journal_end()));
    REQUIRE(r.follow_open(dir, why));
    CHECK(r.by_name("hal"));
    std::filesystem::remove_all(dir);
}

TEST_CASE("the shards' questions and answers come back as they were sent")
{
    shard_call c{shard_call::update, "acct-id", {{"name", "N"}, {"email", ""}}, 1234};
    shard_call d;
    REQUIRE(decode_call(encode_call(c), d));
    CHECK(d.op == shard_call::update);
    CHECK(d.key == "acct-id");
    CHECK(d.at == 1234);
    REQUIRE(d.fields.size() == 2);
    CHECK(d.fields[1].first == "email");
    CHECK(d.fields[1].second.empty());
    CHECK_FALSE(decode_call("not a call", d));
    CHECK_FALSE(decode_call(encode_call(c).substr(0, cross_marker.size() + 3), d));

    code_entry e{"wiki", "http://x/cb", "sub", "n", "openid", "chal", 10, 20};
    bool found = false;
    code_entry f;
    REQUIRE(decode_code(encode_code(&e), found, f));
    CHECK(found);
    CHECK(f.redirect == "http://x/cb");
    CHECK(f.challenge == "chal");
    CHECK(f.expires == 20);
    REQUIRE(decode_code(encode_code(nullptr), found, f));
    CHECK_FALSE(found);

    bool ok = true;
    std::string why;
    REQUIRE(decode_result(encode_result(false, "no such account"), ok, why));
    CHECK_FALSE(ok);
    CHECK(why == "no such account");

    uint32_t shard = 99;
    CHECK(code_shard("3.abcdef", 4, shard));
    CHECK(shard == 3);
    CHECK_FALSE(code_shard("4.abcdef", 4, shard));
    CHECK_FALSE(code_shard("abcdef", 4, shard));
    CHECK_FALSE(code_shard("1.abcdef", 1, shard));
    CHECK_FALSE(code_shard("x.abcdef", 4, shard));
}

TEST_CASE("signing with one key, then another, then the first, signs each with its own")
{
    EVP_PKEY* a = fresh_key();
    EVP_PKEY* b = fresh_key();
    REQUIRE(a);
    REQUIRE(b);
    for (int round = 0; round < 2; ++round)
    {
        const std::string sa = socketley::jws::es256(a, "input");
        const std::string sb = socketley::jws::es256(b, "input");
        REQUIRE(sa.size() == 64);
        REQUIRE(sb.size() == 64);
        CHECK(socketley::jws::es256_verify(a, "input", sa));
        CHECK(socketley::jws::es256_verify(b, "input", sb));
        CHECK_FALSE(socketley::jws::es256_verify(b, "input", sa));
        CHECK_FALSE(socketley::jws::es256_verify(a, "input", sb));
        CHECK_FALSE(socketley::jws::es256_verify(a, "other", sa));
    }
    // A signature whose r or s is short, which DER writes without its leading zeros, is padded on the left.
    int short_ones = 0;
    for (int i = 0; i < 600 && short_ones < 2; ++i)
    {
        const std::string in = "n" + std::to_string(i);
        const std::string s = socketley::jws::es256(a, in);
        REQUIRE(socketley::jws::es256_verify(a, in, s));
        if (s[0] == '\0' || s[32] == '\0')
            ++short_ones;
    }
    CHECK(short_ones > 0);
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
}

TEST_CASE("a token signed under one secret, then another, verifies under its own alone")
{
    claims c;
    std::string why;
    const std::string body = "\"iss\":\"https://id.example\",\"sub\":\"a\",\"exp\":2000";
    for (int round = 0; round < 2; ++round)
    {
        const std::string t1 = sign_secret_token("secret-one", "refresh+jwt", body);
        const std::string t2 = sign_secret_token("secret-two", "refresh+jwt", body);
        CHECK(t1 != t2);
        CHECK(verify_secret_token("secret-one", "refresh+jwt", "https://id.example", t1, 1000, c, why));
        CHECK(verify_secret_token("secret-two", "refresh+jwt", "https://id.example", t2, 1000, c, why));
        CHECK_FALSE(verify_secret_token("secret-two", "refresh+jwt", "https://id.example", t1, 1000, c, why));
        CHECK_FALSE(verify_secret_token("secret-one", "refresh+jwt", "https://id.example", t2, 1000, c, why));
    }
}

TEST_CASE("a JSON string escapes quotes, backslashes and control characters, and keeps the rest as it is")
{
    CHECK(json_string("") == "\"\"");
    CHECK(json_string("plain") == "\"plain\"");
    CHECK(json_string("a\"b\\c") == "\"a\\\"b\\\\c\"");
    CHECK(json_string(std::string_view("x\ny\x01", 4)) == "\"x\\u000ay\\u0001\"");
    CHECK(json_string("\"") == "\"\\\"\"");
    CHECK(json_string("ünï") == "\"ünï\"");
    CHECK(socketley::jws::b64url("") == "");
    CHECK(socketley::jws::b64url("f") == "Zg");
    CHECK(socketley::jws::b64url("fo") == "Zm8");
    CHECK(socketley::jws::b64url("foo") == "Zm9v");
    CHECK(socketley::jws::b64url("foob") == "Zm9vYg");
    CHECK(socketley::jws::b64url("\xfb\xff") == "-_8");
}
