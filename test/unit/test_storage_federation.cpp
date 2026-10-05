#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "runtime/storage/s3_federation.h"
#include "runtime/storage/s3_names.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>

// The federation core without a daemon: base64url, JWK keys, JWT verification for every accepted algorithm and every
// reason a token is refused, the provider file, the mapping to users, and LDAP's BER, DN escaping and a bind against a
// server on a thread.

using namespace socketley::storage;

namespace
{

constexpr int64_t now_s = 1'760'000'000;
const std::string the_issuer = "https://idp.example";
const std::string the_client = "socketley";

const unsigned char* bytes(std::string_view s)
{
    return reinterpret_cast<const unsigned char*>(s.data());
}

// Keys made once, for every test that signs.
EVP_PKEY* rsa_a()
{
    static EVP_PKEY* k = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", size_t{2048});
    return k;
}
EVP_PKEY* rsa_b()
{
    static EVP_PKEY* k = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", size_t{2048});
    return k;
}
EVP_PKEY* rsa_small()
{
    static EVP_PKEY* k = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", size_t{1024});
    return k;
}
EVP_PKEY* ec_256()
{
    static EVP_PKEY* k = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
    return k;
}
EVP_PKEY* ec_384()
{
    static EVP_PKEY* k = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-384");
    return k;
}

std::string bn_bytes(EVP_PKEY* k, const char* name, size_t pad = 0)
{
    BIGNUM* bn = nullptr;
    REQUIRE(EVP_PKEY_get_bn_param(k, name, &bn) == 1);
    const size_t n = pad ? pad : static_cast<size_t>(BN_num_bytes(bn));
    std::string out(n, '\0');
    REQUIRE(BN_bn2binpad(bn, reinterpret_cast<unsigned char*>(out.data()), static_cast<int>(n)) == static_cast<int>(n));
    BN_free(bn);
    return out;
}

std::string rsa_jwk(EVP_PKEY* k, std::string_view kid, std::string_view use = "sig", std::string_view alg = {})
{
    std::string j = "{\"kty\":\"RSA\"";
    if (!kid.empty())
        j += ",\"kid\":\"" + std::string(kid) + "\"";
    if (!use.empty())
        j += ",\"use\":\"" + std::string(use) + "\"";
    if (!alg.empty())
        j += ",\"alg\":\"" + std::string(alg) + "\"";
    j += ",\"n\":\"" + base64url_encode(bn_bytes(k, OSSL_PKEY_PARAM_RSA_N)) + "\"";
    j += ",\"e\":\"" + base64url_encode(bn_bytes(k, OSSL_PKEY_PARAM_RSA_E)) + "\"}";
    return j;
}

std::string ec_jwk(EVP_PKEY* k, std::string_view crv, size_t coord, std::string_view kid, std::string_view alg = {})
{
    std::string j = "{\"kty\":\"EC\",\"crv\":\"" + std::string(crv) + "\"";
    if (!kid.empty())
        j += ",\"kid\":\"" + std::string(kid) + "\"";
    if (!alg.empty())
        j += ",\"alg\":\"" + std::string(alg) + "\"";
    j += ",\"x\":\"" + base64url_encode(bn_bytes(k, OSSL_PKEY_PARAM_EC_PUB_X, coord)) + "\"";
    j += ",\"y\":\"" + base64url_encode(bn_bytes(k, OSSL_PKEY_PARAM_EC_PUB_Y, coord)) + "\"}";
    return j;
}

std::string set_of(const std::vector<std::string>& keys)
{
    std::string j = "{\"keys\":[";
    for (size_t i = 0; i < keys.size(); ++i)
        j += (i ? "," : "") + keys[i];
    return j + "]}";
}

jwks_keys keys_of(const std::string& json)
{
    jwks_keys out;
    std::string why;
    const bool ok = parse_jwks(json, out, why);
    INFO(why);
    REQUIRE(ok);
    return out;
}

// The r||s a JWS carries for an ECDSA signature OpenSSL wrote as DER.
std::string der_to_raw(std::string_view der, size_t coord)
{
    const unsigned char* p = bytes(der);
    ECDSA_SIG* s = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der.size()));
    REQUIRE(s != nullptr);
    std::string raw(2 * coord, '\0');
    auto* out = reinterpret_cast<unsigned char*>(raw.data());
    BN_bn2binpad(ECDSA_SIG_get0_r(s), out, static_cast<int>(coord));
    BN_bn2binpad(ECDSA_SIG_get0_s(s), out + coord, static_cast<int>(coord));
    ECDSA_SIG_free(s);
    return raw;
}

// A signature by `alg` as OpenSSL writes it, DER for ECDSA.
std::string sign_der(EVP_PKEY* k, std::string_view alg, std::string_view input)
{
    const char* md = alg.ends_with("256") ? "SHA256" : alg.ends_with("384") ? "SHA384" : "SHA512";
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = nullptr;
    REQUIRE(EVP_DigestSignInit_ex(ctx, &pctx, md, nullptr, nullptr, k, nullptr) == 1);
    if (alg.starts_with("PS"))
    {
        REQUIRE(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0);
        REQUIRE(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) > 0);
    }
    size_t len = 0;
    REQUIRE(EVP_DigestSign(ctx, nullptr, &len, bytes(input), input.size()) == 1);
    std::string sig(len, '\0');
    REQUIRE(EVP_DigestSign(ctx, reinterpret_cast<unsigned char*>(sig.data()), &len, bytes(input), input.size()) == 1);
    sig.resize(len);
    EVP_MD_CTX_free(ctx);
    return sig;
}

// A signature by `alg` as a JWS carries it.
std::string sign(EVP_PKEY* k, std::string_view alg, std::string_view input)
{
    const std::string sig = sign_der(k, alg, input);
    if (alg.starts_with("ES"))
        return der_to_raw(sig, alg == "ES256" ? 32 : 48);
    return sig;
}

// The claims of a test token, each JSON value written raw so a test can make it anything.
struct claims
{
    std::string iss    = "\"" + the_issuer + "\"";
    std::string aud    = "\"" + the_client + "\"";
    std::string exp    = std::to_string(now_s + 600);
    std::string nbf;
    std::string iat    = std::to_string(now_s);
    std::string policy = "\"readers\"";
    std::string claim  = "policy";
    std::string extra;

    std::string json() const
    {
        std::string j = "{\"sub\":\"alice\"";
        auto add = [&j](std::string_view name, const std::string& v)
        {
            if (!v.empty())
                j += ",\"" + std::string(name) + "\":" + v;
        };
        add("iss", iss);
        add("aud", aud);
        add("exp", exp);
        add("nbf", nbf);
        add("iat", iat);
        add(claim, policy);
        return j + extra + "}";
    }
};

std::string header_json(std::string_view alg, std::string_view kid, std::string_view extra = {})
{
    std::string j = "{\"alg\":\"" + std::string(alg) + "\",\"typ\":\"JWT\"";
    if (!kid.empty())
        j += ",\"kid\":\"" + std::string(kid) + "\"";
    return j + std::string(extra) + "}";
}

std::string jwt(EVP_PKEY* k, std::string_view alg, std::string_view kid, const claims& c = {},
                std::string_view header_extra = {})
{
    const std::string input = base64url_encode(header_json(alg, kid, header_extra)) + "." + base64url_encode(c.json());
    return input + "." + base64url_encode(sign(k, alg, input));
}

federation_oidc oidc_cfg()
{
    federation_oidc c;
    c.issuer  = the_issuer;
    c.clients = {"other-app", the_client};
    return c;
}

// The keys most tests verify with: one RSA key and one key of each curve, each with a kid.
const jwks_keys& std_keys()
{
    static const jwks_keys k = keys_of(set_of({rsa_jwk(rsa_a(), "r"), ec_jwk(ec_256(), "P-256", 32, "e256"),
                                               ec_jwk(ec_384(), "P-384", 48, "e384")}));
    return k;
}

bool verifies(const jwks_keys& keys, const std::string& token, std::string* why_out = nullptr,
              oidc_identity* id_out = nullptr, const federation_oidc& cfg = oidc_cfg())
{
    oidc_identity id;
    std::string why;
    const bool ok = oidc_verify(cfg, keys, token, now_s, id, why);
    if (why_out)
        *why_out = why;
    if (id_out)
        *id_out = id;
    return ok;
}

std::string temp_dir()
{
    char tpl[] = "/tmp/skl-federation-XXXXXX";
    REQUIRE(::mkdtemp(tpl) != nullptr);
    return tpl;
}

void write_file(const std::string& path, const std::string& text)
{
    const std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        f << text;
    }
    // A rename gives the file a new inode, as an editor or a deploy writes it.
    REQUIRE(std::rename(tmp.c_str(), path.c_str()) == 0);
}

std::string hex_bytes(std::initializer_list<int> b)
{
    std::string s;
    for (int v : b)
        s.push_back(static_cast<char>(v));
    return s;
}

}   // namespace

// ---- base64url and ECDSA ----

TEST_CASE("base64url is read only in its one canonical spelling")
{
    std::string out;
    CHECK(jws_base64url_decode("", out));
    CHECK(out.empty());
    CHECK(jws_base64url_decode("aGk", out));
    CHECK(out == "hi");
    CHECK(jws_base64url_decode("_-8", out));
    CHECK(out == "\xff\xef");
    CHECK_FALSE(jws_base64url_decode("aGk=", out));
    CHECK_FALSE(jws_base64url_decode("aGl", out));
    CHECK_FALSE(jws_base64url_decode("a", out));
    CHECK_FALSE(jws_base64url_decode("aG+k", out));
    CHECK_FALSE(jws_base64url_decode("aG/k", out));
    CHECK_FALSE(jws_base64url_decode("aG k", out));
    std::string all;
    for (int i = 0; i < 64; ++i)
    {
        CHECK(jws_base64url_decode(base64url_encode(all), out));
        CHECK(out == all);
        all.push_back(static_cast<char>(i * 37 + 11));
    }
}

TEST_CASE("an ECDSA signature's r||s becomes the DER OpenSSL writes, and only at its exact length")
{
    for (int i = 0; i < 24; ++i)
    {
        const std::string input = "message " + std::to_string(i);
        const std::string der = sign_der(ec_256(), "ES256", input);
        const std::string raw = der_to_raw(der, 32);
        std::string back;
        REQUIRE(jws_ecdsa_to_der(raw, 32, back));
        CHECK(back == der);
    }
    const std::string der384 = sign_der(ec_384(), "ES384", "x");
    std::string back;
    CHECK(jws_ecdsa_to_der(der_to_raw(der384, 48), 48, back));
    CHECK(back == der384);
    CHECK_FALSE(jws_ecdsa_to_der(std::string(63, '\x01'), 32, back));
    CHECK_FALSE(jws_ecdsa_to_der(std::string(65, '\x01'), 32, back));
    CHECK_FALSE(jws_ecdsa_to_der({}, 0, back));
}

// ---- JWK Sets ----

TEST_CASE("a JWK Set gives its RSA and EC signing keys and skips what it cannot verify with")
{
    const jwks_keys k = keys_of(set_of({
        rsa_jwk(rsa_a(), "r"),
        ec_jwk(ec_256(), "P-256", 32, "e"),
        R"({"kty":"oct","kid":"h","k":"c2VjcmV0"})",
        rsa_jwk(rsa_b(), "enc", "enc"),
        rsa_jwk(rsa_small(), "small"),
        R"({"kty":"EC","crv":"P-256","kid":"short","x":"AAAA","y":"AAAA"})",
        ec_jwk(ec_256(), "P-256", 32, "wrong-alg", "RS256"),
        R"({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})",
    }));
    REQUIRE(k.keys.size() == 2);
    CHECK(k.skipped == 6);
    CHECK(k.keys[0].kty == "RSA");
    CHECK(k.keys[0].kid == "r");
    CHECK(k.keys[1].kty == "EC");
    CHECK(k.keys[1].crv == "P-256");

    jwks_keys none;
    std::string why;
    CHECK_FALSE(parse_jwks(R"({"keys":[{"kty":"oct","k":"c2VjcmV0"}]})", none, why));
    CHECK(why.find("no RSA key") != std::string::npos);
    CHECK_FALSE(parse_jwks(R"({"keys":{}})", none, why));
    CHECK_FALSE(parse_jwks(R"([])", none, why));
    CHECK_FALSE(parse_jwks("{\"keys\":[" + rsa_jwk(rsa_a(), "r") + "]", none, why));
}

// ---- JWT ----

TEST_CASE("a token signed with each accepted algorithm verifies and says who it is for")
{
    struct row
    {
        EVP_PKEY*   key;
        const char* alg;
        const char* kid;
    };
    const row rows[] = {
        {rsa_a(), "RS256", "r"}, {rsa_a(), "RS384", "r"},     {rsa_a(), "RS512", "r"},
        {rsa_a(), "PS256", "r"}, {ec_256(), "ES256", "e256"}, {ec_384(), "ES384", "e384"},
    };
    for (const row& r : rows)
    {
        CAPTURE(r.alg);
        std::string why;
        oidc_identity id;
        CHECK(verifies(std_keys(), jwt(r.key, r.alg, r.kid), &why, &id));
        CHECK(why.empty());
        CHECK(id.issuer == the_issuer);
        CHECK(id.subject == "alice");
        CHECK(id.audience == the_client);
        CHECK(id.expires == now_s + 600);
        CHECK(id.policies == std::vector<std::string>{"readers"});
    }
}

TEST_CASE("a token is refused for its issuer, its audience or its times")
{
    std::string why;
    oidc_identity id;
    claims c;

    SUBCASE("another issuer")
    {
        c.iss = "\"https://evil.example\"";
        CHECK_FALSE(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", c), &why));
        CHECK(why.find("issuer") != std::string::npos);
    }
    SUBCASE("no issuer")
    {
        c.iss.clear();
        CHECK_FALSE(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", c), &why));
    }
    SUBCASE("an audience array that names this client")
    {
        c.aud = "[\"x\",\"" + the_client + "\"]";
        CHECK(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", c), &why, &id));
        CHECK(id.audience == the_client);
    }
    SUBCASE("an audience array that does not")
    {
        c.aud = "[\"x\",\"y\"]";
        CHECK_FALSE(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", c), &why));
        CHECK(why.find("audience") != std::string::npos);
    }
    SUBCASE("another audience")
    {
        c.aud = "\"someone-else\"";
        CHECK_FALSE(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", c), &why));
    }
    SUBCASE("no audience")
    {
        c.aud.clear();
        CHECK_FALSE(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", c), &why));
    }
    SUBCASE("expired past the leeway")
    {
        c.exp = std::to_string(now_s - oidc_leeway_secs - 1);
        CHECK_FALSE(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", c), &why, &id));
        CHECK(id.expired);
        CHECK(why.find("expired") != std::string::npos);
    }
    SUBCASE("expired within the leeway")
    {
        c.exp = std::to_string(now_s - 30);
        CHECK(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", c), &why));
    }
    SUBCASE("no exp")
    {
        c.exp.clear();
        CHECK_FALSE(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", c), &why, &id));
        CHECK_FALSE(id.expired);
    }
    SUBCASE("an exp that is not a number")
    {
        c.exp = "\"" + std::to_string(now_s + 600) + "\"";
        CHECK_FALSE(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", c), &why));
    }
    SUBCASE("nbf in the future past the leeway")
    {
        c.nbf = std::to_string(now_s + oidc_leeway_secs + 1);
        CHECK_FALSE(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", c), &why));
        CHECK(why.find("not valid yet") != std::string::npos);
    }
    SUBCASE("nbf in the future within the leeway")
    {
        c.nbf = std::to_string(now_s + 30);
        CHECK(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", c), &why));
    }
    SUBCASE("iat in the future past the leeway")
    {
        c.iat = std::to_string(now_s + oidc_leeway_secs + 1);
        CHECK_FALSE(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", c), &why));
    }
    SUBCASE("a fractional exp")
    {
        c.exp = std::to_string(now_s + 600) + ".5";
        CHECK(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", c), &why, &id));
        CHECK(id.expires == now_s + 600);
    }
}

TEST_CASE("a token is refused for its alg, its kid or a changed byte")
{
    std::string why;
    const std::string good = jwt(rsa_a(), "RS256", "r");
    REQUIRE(verifies(std_keys(), good, &why));
    const size_t d1 = good.find('.');
    const size_t d2 = good.rfind('.');
    const std::string payload = base64url_encode(claims{}.json());

    SUBCASE("alg none")
    {
        const std::string t = base64url_encode(R"({"alg":"none"})") + "." + payload + ".";
        CHECK_FALSE(verifies(std_keys(), t, &why));
        CHECK(why.find("alg") != std::string::npos);
    }
    SUBCASE("alg HS256 keyed with the public key")
    {
        const std::string input = base64url_encode(header_json("HS256", "r")) + "." + payload;
        const std::string n = bn_bytes(rsa_a(), OSSL_PKEY_PARAM_RSA_N);
        unsigned char mac[32];
        unsigned int len = sizeof mac;
        REQUIRE(HMAC(EVP_sha256(), n.data(), static_cast<int>(n.size()), bytes(input), input.size(), mac, &len) !=
                nullptr);
        const std::string t = input + "." + base64url_encode(std::string(reinterpret_cast<char*>(mac), len));
        CHECK_FALSE(verifies(std_keys(), t, &why));
        CHECK(why.find("alg") != std::string::npos);
    }
    SUBCASE("an alg in another case")
    {
        CHECK_FALSE(verifies(std_keys(), jwt(rsa_a(), "rs256", "r"), &why));
    }
    SUBCASE("a kid no key has")
    {
        CHECK_FALSE(verifies(std_keys(), jwt(rsa_a(), "RS256", "other"), &why));
        CHECK(why.find("kid") != std::string::npos);
    }
    SUBCASE("a kid that names a key of another type")
    {
        CHECK_FALSE(verifies(std_keys(), jwt(rsa_a(), "RS256", "e256"), &why));
    }
    SUBCASE("an ES256 token whose kid names the P-384 key")
    {
        CHECK_FALSE(verifies(std_keys(), jwt(ec_256(), "ES256", "e384"), &why));
    }
    SUBCASE("a token signed by another key under the same kid")
    {
        CHECK_FALSE(verifies(std_keys(), jwt(rsa_b(), "RS256", "r"), &why));
        CHECK(why.find("signature") != std::string::npos);
    }
    SUBCASE("no kid takes the only key of its type")
    {
        CHECK(verifies(std_keys(), jwt(rsa_a(), "RS256", ""), &why));
        CHECK(verifies(std_keys(), jwt(ec_256(), "ES256", ""), &why));
        const jwks_keys two = keys_of(set_of({rsa_jwk(rsa_a(), "r"), rsa_jwk(rsa_b(), "s")}));
        CHECK_FALSE(verifies(two, jwt(rsa_a(), "RS256", ""), &why));
        CHECK(verifies(two, jwt(rsa_b(), "RS256", "s"), &why));
    }
    SUBCASE("a key without a kid is taken when it is the only one of its type")
    {
        const jwks_keys bare = keys_of(set_of({rsa_jwk(rsa_a(), ""), ec_jwk(ec_256(), "P-256", 32, "e")}));
        CHECK(verifies(bare, jwt(rsa_a(), "RS256", "anything"), &why));
        const jwks_keys two = keys_of(set_of({rsa_jwk(rsa_a(), ""), rsa_jwk(rsa_b(), "")}));
        CHECK_FALSE(verifies(two, jwt(rsa_a(), "RS256", "anything"), &why));
    }
    SUBCASE("a key that names its alg takes no other")
    {
        const jwks_keys pinned = keys_of(set_of({rsa_jwk(rsa_a(), "r", "sig", "PS256")}));
        CHECK(verifies(pinned, jwt(rsa_a(), "PS256", "r"), &why));
        CHECK_FALSE(verifies(pinned, jwt(rsa_a(), "RS256", "r"), &why));
    }
    SUBCASE("a changed payload")
    {
        claims c;
        c.policy = "\"admins\"";
        const std::string t = good.substr(0, d1) + "." + base64url_encode(c.json()) + good.substr(d2);
        CHECK_FALSE(verifies(std_keys(), t, &why));
        CHECK(why.find("signature") != std::string::npos);
    }
    SUBCASE("a changed signature")
    {
        std::string sig;
        REQUIRE(jws_base64url_decode(good.substr(d2 + 1), sig));
        sig[sig.size() / 2] = static_cast<char>(sig[sig.size() / 2] ^ 0x01);
        CHECK_FALSE(verifies(std_keys(), good.substr(0, d2 + 1) + base64url_encode(sig), &why));
        CHECK(why.find("signature") != std::string::npos);
    }
    SUBCASE("a changed ES256 signature, and one written as DER")
    {
        const std::string es = jwt(ec_256(), "ES256", "e256");
        REQUIRE(verifies(std_keys(), es, &why));
        const size_t s = es.rfind('.');
        std::string sig;
        REQUIRE(jws_base64url_decode(es.substr(s + 1), sig));
        sig[5] = static_cast<char>(sig[5] ^ 0x80);
        CHECK_FALSE(verifies(std_keys(), es.substr(0, s + 1) + base64url_encode(sig), &why));
        const std::string der = sign_der(ec_256(), "ES256", es.substr(0, s));
        CHECK_FALSE(verifies(std_keys(), es.substr(0, s + 1) + base64url_encode(der), &why));
    }
    SUBCASE("a signature padded or with a fourth part")
    {
        CHECK_FALSE(verifies(std_keys(), good + "=", &why));
        CHECK_FALSE(verifies(std_keys(), good + ".x", &why));
        CHECK_FALSE(verifies(std_keys(), good.substr(0, d2), &why));
    }
    SUBCASE("a critical header parameter")
    {
        CHECK_FALSE(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", {}, R"(,"crit":["b64"],"b64":false)"), &why));
        CHECK(why.find("critical") != std::string::npos);
    }
    SUBCASE("a header that names alg twice")
    {
        CHECK_FALSE(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", {}, R"(,"alg":"none")"), &why));
    }
    SUBCASE("a token too long")
    {
        claims c;
        c.extra = ",\"pad\":\"" + std::string(jwt_max_bytes, 'x') + "\"";
        CHECK_FALSE(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", c), &why));
        CHECK(why.find("longer") != std::string::npos);
    }
}

TEST_CASE("the policy claim names users as a comma-separated string or an array")
{
    oidc_identity id;
    std::string why;
    claims c;

    c.policy = "\" a, b ,a,,\"";
    CHECK(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", c), &why, &id));
    CHECK(id.policies == std::vector<std::string>{"a", "b"});

    c.policy = R"(["a","b,c","a"])";
    CHECK(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", c), &why, &id));
    CHECK(id.policies == std::vector<std::string>{"a", "b", "c"});

    c.policy.clear();
    CHECK(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", c), &why, &id));
    CHECK(id.policies.empty());

    c.policy = "7";
    CHECK_FALSE(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", c), &why));
    c.policy = R"(["a",1])";
    CHECK_FALSE(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", c), &why));

    // A configured claim of another name is the one read.
    federation_oidc cfg = oidc_cfg();
    cfg.claim = "groups";
    c.claim  = "groups";
    c.policy = "\"ops\"";
    CHECK(verifies(std_keys(), jwt(rsa_a(), "RS256", "r", c), &why, &id, cfg));
    CHECK(id.policies == std::vector<std::string>{"ops"});
}

TEST_CASE("a JWKS file is read again when it changes and kept when it breaks")
{
    const std::string dir  = temp_dir();
    const std::string path = dir + "/keys.json";
    federation_oidc cfg = oidc_cfg();
    cfg.jwks_path = path;
    oidc_verifier v(cfg);
    oidc_identity id;
    std::string why;

    CHECK_FALSE(v.verify(jwt(rsa_a(), "RS256", "r"), now_s, id, why));
    CHECK(why.find("cannot read") != std::string::npos);

    write_file(path, set_of({rsa_jwk(rsa_a(), "r")}));
    CHECK(v.verify(jwt(rsa_a(), "RS256", "r"), now_s, id, why));

    // A rotated key under the same kid replaces the old one.
    write_file(path, set_of({rsa_jwk(rsa_b(), "r")}));
    CHECK_FALSE(v.verify(jwt(rsa_a(), "RS256", "r"), now_s, id, why));
    CHECK(v.verify(jwt(rsa_b(), "RS256", "r"), now_s, id, why));

    // A half-written file leaves the keys last read whole.
    write_file(path, "{\"keys\":[");
    CHECK(v.verify(jwt(rsa_b(), "RS256", "r"), now_s, id, why));
    // A set of another size, so its stamp differs even where an inode is reused within one mtime tick.
    write_file(path, set_of({rsa_jwk(rsa_a(), "r"), ec_jwk(ec_256(), "P-256", 32, "e")}));
    CHECK(v.verify(jwt(rsa_a(), "RS256", "r"), now_s, id, why));
    CHECK_FALSE(v.verify(jwt(rsa_b(), "RS256", "r"), now_s, id, why));

    std::filesystem::remove_all(dir);
}

// ---- mapping ----

TEST_CASE("a verified token signs as the user its role line or its one claimed user names")
{
    federation_config cfg;
    cfg.oidc  = oidc_cfg();
    cfg.roles = {{"arn:aws:iam::1:role/readers", "reader"}, {"arn:aws:iam::1:role/gone", "nobody"}};
    const federation_user_known known = [](std::string_view u) { return u == "reader" || u == "alice" || u == "bob"; };
    oidc_identity id;
    std::string user, why;

    CHECK(federation_web_user(cfg, id, "arn:aws:iam::1:role/readers", known, user, why));
    CHECK(user == "reader");
    CHECK_FALSE(federation_web_user(cfg, id, "arn:aws:iam::1:role/gone", known, user, why));
    CHECK_FALSE(federation_web_user(cfg, id, "arn:aws:iam::1:role/other", known, user, why));
    CHECK_FALSE(federation_web_user(cfg, id, "", known, user, why));

    id.policies = {"alice"};
    CHECK(federation_web_user(cfg, id, "", known, user, why));
    CHECK(user == "alice");
    // A RoleArn no line maps falls to the claim, as a client that must send one sends any.
    CHECK(federation_web_user(cfg, id, "arn:aws:iam::1:role/other", known, user, why));
    CHECK(user == "alice");
    CHECK(federation_web_user(cfg, id, "arn:aws:iam::1:role/readers", known, user, why));
    CHECK(user == "reader");

    id.policies = {"alice", "bob"};
    CHECK_FALSE(federation_web_user(cfg, id, "", known, user, why));
    CHECK(why.find("2 users") != std::string::npos);
    id.policies = {"mallory"};
    CHECK_FALSE(federation_web_user(cfg, id, "", known, user, why));
    id.policies = {"alice", "mallory"};
    CHECK_FALSE(federation_web_user(cfg, id, "", known, user, why));
    CHECK(user.empty());
}

TEST_CASE("an LDAP user signs as its own line's user, else the wildcard's")
{
    federation_config cfg;
    cfg.ldap.users = {{"*", "="}, {"alice", "ops"}};
    const federation_user_known known = [](std::string_view u) { return u == "ops" || u == "bob"; };
    std::string user, why;

    CHECK(federation_ldap_user(cfg, "alice", known, user, why));
    CHECK(user == "ops");
    CHECK(federation_ldap_user(cfg, "bob", known, user, why));
    CHECK(user == "bob");
    CHECK_FALSE(federation_ldap_user(cfg, "carol", known, user, why));
    CHECK_FALSE(federation_ldap_user(cfg, "a/b", known, user, why));

    cfg.ldap.users = {{"alice", "ops"}};
    CHECK_FALSE(federation_ldap_user(cfg, "bob", known, user, why));
    CHECK(why.find("no ldap user line") != std::string::npos);

    cfg.ldap.users = {{"*", "bob"}};
    CHECK(federation_ldap_user(cfg, "anyone", known, user, why));
    CHECK(user == "bob");
}

// ---- the provider file ----

TEST_CASE("a provider file is read line by line")
{
    const std::string text = "# providers\n"
                             "oidc issuer https://idp.example   # the IdP\n"
                             "oidc client socketley\n"
                             "oidc client console\n"
                             "oidc jwks keys.json\n"
                             "oidc claim groups\n"
                             "\n"
                             "ldap url ldaps://ldap.example.org:1636 ca=ca.pem\n"
                             "ldap dn uid=%s,ou=People Group,dc=example,dc=org\n"
                             "ldap user alice ops\n"
                             "ldap user * =\n"
                             "role arn:aws:iam::123456789012:role/readers readers\n";
    federation_config cfg;
    std::string why;
    REQUIRE(parse_federation(text, cfg, why, "/etc/skl"));
    CHECK(cfg.oidc.issuer == "https://idp.example");
    CHECK(cfg.oidc.clients == std::vector<std::string>{"socketley", "console"});
    CHECK(cfg.oidc.jwks_path == "/etc/skl/keys.json");
    CHECK(cfg.oidc.claim == "groups");
    CHECK(cfg.ldap.tls);
    CHECK(cfg.ldap.host == "ldap.example.org");
    CHECK(cfg.ldap.port == 1636);
    CHECK(cfg.ldap.ca_file == "/etc/skl/ca.pem");
    CHECK(cfg.ldap.dn_template == "uid=%s,ou=People Group,dc=example,dc=org");
    REQUIRE(cfg.ldap.users.size() == 2);
    CHECK(cfg.ldap.users[0].ldap_user == "alice");
    CHECK(cfg.ldap.users[0].user == "ops");
    CHECK(cfg.ldap.users[1].ldap_user == "*");
    CHECK(cfg.ldap.users[1].user == "=");
    REQUIRE(cfg.roles.size() == 1);
    CHECK(cfg.roles[0].arn == "arn:aws:iam::123456789012:role/readers");
    CHECK(cfg.roles[0].user == "readers");
    CHECK(cfg.ldap.timeout_ms == 5000);

    REQUIRE(parse_federation("oidc issuer i\noidc client c\noidc jwks /abs/k.json\n", cfg, why, "/etc/skl"));
    CHECK(cfg.oidc.jwks_path == "/abs/k.json");
    CHECK(cfg.oidc.claim == "policy");
    CHECK_FALSE(cfg.ldap.enabled());

    const std::string ldap_tail = "\nldap dn uid=%s,dc=x\nldap user * =\n";
    REQUIRE(parse_federation("ldap url ldap://10.0.0.1" + ldap_tail, cfg, why));
    CHECK_FALSE(cfg.ldap.tls);
    CHECK(cfg.ldap.host == "10.0.0.1");
    CHECK(cfg.ldap.port == 389);
    CHECK_FALSE(cfg.oidc.enabled());
    REQUIRE(parse_federation("ldap url ldaps://[::1]/" + ldap_tail, cfg, why));
    CHECK(cfg.ldap.host == "::1");
    CHECK(cfg.ldap.port == 636);
    REQUIRE(parse_federation("ldap url ldap://[fe80::1]:1389" + ldap_tail, cfg, why));
    CHECK(cfg.ldap.host == "fe80::1");
    CHECK(cfg.ldap.port == 1389);
}

TEST_CASE("a provider file with a bad line is refused, naming the line")
{
    const std::string oidc = "oidc issuer i\noidc client c\noidc jwks k\n";
    const std::string ldap_tail = "\nldap dn uid=%s,dc=x\nldap user * =\n";
    struct row
    {
        std::string text;
        const char* says;
    };
    const row rows[] = {
        {"", "no OIDC and no LDAP"},
        {"# nothing\n", "no OIDC and no LDAP"},
        {"bogus x\n", "line 1: a line begins with"},
        {"oidc issuer\n", "line 1: an oidc line"},
        {"oidc issuer a b\n", "line 1: an oidc line"},
        {"oidc audience x\n", "line 1: an oidc line"},
        {oidc + "oidc issuer j\n", "line 4: `oidc issuer` is given twice"},
        {oidc + "oidc jwks j\n", "line 4: `oidc jwks` is given twice"},
        {oidc + "oidc client c\n", "line 4: the client c is given twice"},
        {oidc + "oidc claim a\noidc claim b\n", "line 5: `oidc claim` is given twice"},
        {"oidc issuer i\noidc client c\n", "needs `oidc issuer`, `oidc client` and `oidc jwks`"},
        {"oidc client c\noidc jwks k\n", "needs `oidc issuer`"},
        {"ldap url http://x" + ldap_tail, "line 1: an LDAP URL is"},
        {"ldap url ldap://x ca=c.pem" + ldap_tail, "line 1: ca=<file> is for an ldaps:// server"},
        {"ldap url ldaps://x ca=" + ldap_tail, "line 1: ca=<file>"},
        {"ldap url ldaps://x cert=c.pem" + ldap_tail, "line 1: an ldap url line"},
        {"ldap url ldap://x:0" + ldap_tail, "line 1: an LDAP URL's port"},
        {"ldap url ldap://x:65536" + ldap_tail, "line 1: an LDAP URL's port"},
        {"ldap url ldap://x:" + ldap_tail, "line 1: an LDAP URL's port"},
        {"ldap url ldap://x:ab" + ldap_tail, "line 1: an LDAP URL's port"},
        {"ldap url ldap://x/dc=example" + ldap_tail, "line 1: an LDAP URL names a host and a port"},
        {"ldap url ldap://u@x" + ldap_tail, "line 1: an LDAP URL names a host and a port"},
        {"ldap url ldap://::1" + ldap_tail, "line 1: an IPv6 LDAP host goes in brackets"},
        {"ldap url ldap://[::1" + ldap_tail, "line 1: an IPv6 LDAP host is"},
        {"ldap url ldap://" + ldap_tail, "line 1: an LDAP URL names a host"},
        {"ldap url ldap://a\nldap url ldap://b" + ldap_tail, "line 2: `ldap url` is given twice"},
        {"ldap url ldap://x\nldap dn ou=x\nldap user * =\n", "line 2: an ldap dn line"},
        {"ldap url ldap://x\nldap dn uid=%s,cn=%s\nldap user * =\n", "line 2: an ldap dn line"},
        {"ldap url ldap://x\nldap dn uid=%d%s\nldap user * =\n", "line 2: an ldap dn line"},
        {"ldap url ldap://x\nldap dn uid=%s\nldap user alice\n", "line 3: an ldap line is"},
        {"ldap url ldap://x\nldap dn uid=%s\nldap user alice bad/user\n", "line 3: an ldap user line"},
        {"ldap url ldap://x\nldap dn uid=%s\nldap user a b\nldap user a c\n",
         "line 4: the LDAP user a is mapped twice"},
        {"ldap url ldap://x\nldap dn uid=%s\n", "at least one `ldap user`"},
        {"ldap dn uid=%s\nldap user * =\n", "needs `ldap url`"},
        {"ldap\n", "line 1: an ldap line is"},
        {oidc + "role arn:x\n", "line 4: a role line"},
        {oidc + "role arn:x a b\n", "line 4: a role line"},
        {oidc + "role arn:x a:b\n", "line 4: a role line"},
        {oidc + "role arn:x a\nrole arn:x b\n", "line 5: the role arn:x is mapped twice"},
        {"role arn:x u\n", "no OIDC provider"},
    };
    for (const row& r : rows)
    {
        CAPTURE(r.text);
        federation_config cfg;
        std::string why;
        CHECK_FALSE(parse_federation(r.text, cfg, why));
        CHECK_MESSAGE(why.find(r.says) != std::string::npos, why);
    }
}

TEST_CASE("a provider file is loaded with its relative paths under its own directory")
{
    const std::string dir = temp_dir();
    write_file(dir + "/federation.conf", "oidc issuer i\noidc client c\noidc jwks keys.json\n");
    federation_config cfg;
    std::string why;
    REQUIRE(load_federation(dir + "/federation.conf", cfg, why));
    CHECK(cfg.oidc.jwks_path == dir + "/keys.json");
    write_file(dir + "/bad.conf", "oidc issuer i\n");
    CHECK_FALSE(load_federation(dir + "/bad.conf", cfg, why));
    CHECK(why.starts_with(dir + "/bad.conf: "));
    CHECK_FALSE(load_federation(dir + "/missing.conf", cfg, why));
    CHECK(why.find("cannot read") != std::string::npos);
    std::filesystem::remove_all(dir);
}

// ---- LDAP ----

TEST_CASE("a DN value is escaped as RFC 4514 says")
{
    CHECK(ldap_escape_dn_value("alice") == "alice");
    CHECK(ldap_escape_dn_value("a,b") == "a\\,b");
    CHECK(ldap_escape_dn_value(" a ") == "\\ a\\ ");
    CHECK(ldap_escape_dn_value("a b") == "a b");
    CHECK(ldap_escape_dn_value("#a#") == "\\#a#");
    CHECK(ldap_escape_dn_value("a+b=c") == "a\\+b\\=c");
    CHECK(ldap_escape_dn_value("\"<>;\\") == "\\\"\\<\\>\\;\\\\");
    CHECK(ldap_escape_dn_value(std::string_view("x\0y", 3)) == "x\\00y");
    CHECK(ldap_escape_dn_value("x\ny\x7f") == "x\\0Ay\\7F");
    CHECK(ldap_escape_dn_value("j\xc3\xb6rg") == "j\xc3\xb6rg");
    CHECK(ldap_bind_dn("uid=%s,ou=people,dc=example,dc=org", "a,b") == "uid=a\\,b,ou=people,dc=example,dc=org");
    CHECK(ldap_bind_dn("uid=%s,dc=x", "*)(uid=*") == "uid=*)(uid\\=*,dc=x");
}

TEST_CASE("a BindRequest is the BER every LDAP server reads")
{
    // The anonymous bind of message 1, as every LDAP capture shows it.
    CHECK(ldap_bind_request(1, "", "") ==
          hex_bytes({0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00}));
    CHECK(ldap_bind_request(1, "cn=admin", "secret") ==
          hex_bytes({0x30, 0x1a, 0x02, 0x01, 0x01, 0x60, 0x15, 0x02, 0x01, 0x03, 0x04, 0x08, 'c', 'n', '=', 'a',
                     'd', 'm', 'i', 'n', 0x80, 0x06, 's', 'e', 'c', 'r', 'e', 't'}));
    // A password past 127 bytes takes a long-form length, and so do the elements around it.
    const std::string long_pw(200, 'p');
    const std::string req = ldap_bind_request(1, "cn=a", long_pw);
    CHECK(req.size() == 221);
    CHECK(req.substr(0, 21) == hex_bytes({0x30, 0x81, 0xda, 0x02, 0x01, 0x01, 0x60, 0x81, 0xd4, 0x02, 0x01, 0x03,
                                          0x04, 0x04, 'c', 'n', '=', 'a', 0x80, 0x81, 0xc8}));
    CHECK(req.substr(21) == long_pw);
    const std::string longer = ldap_bind_request(1, "cn=a", std::string(300, 'p'));
    CHECK(longer.substr(0, 4) == hex_bytes({0x30, 0x82, 0x01, 0x40}));
    // A message id with its top bit set takes a leading zero, as INTEGER is signed.
    CHECK(ldap_bind_request(128, "", "").substr(2, 4) == hex_bytes({0x02, 0x02, 0x00, 0x80}));
    CHECK(ldap_bind_request(300, "", "").substr(2, 4) == hex_bytes({0x02, 0x02, 0x01, 0x2c}));
    CHECK(ldap_unbind_request(2) == hex_bytes({0x30, 0x05, 0x02, 0x01, 0x02, 0x42, 0x00}));
}

TEST_CASE("a BindResponse is read for its result code, and a cut or a stray one is not")
{
    const std::string ok =
        hex_bytes({0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00});
    const std::string bad = hex_bytes({0x30, 0x0f, 0x02, 0x01, 0x01, 0x61, 0x0a, 0x0a, 0x01, 0x31, 0x04, 0x00, 0x04,
                                       0x03, 'b', 'a', 'd'});
    ldap_bind_result r;
    std::string why;
    size_t total = 0;

    REQUIRE(ldap_message_size(ok, total) == 1);
    CHECK(total == ok.size());
    REQUIRE(ldap_parse_bind_response(ok, 1, r, why));
    CHECK(r.code == 0);
    CHECK(r.bound());

    REQUIRE(ldap_parse_bind_response(bad, 1, r, why));
    CHECK(r.code == 49);
    CHECK_FALSE(r.bound());
    CHECK(r.diagnostic == "bad");

    // Every cut of a whole message is not whole yet, and is no BindResponse.
    for (size_t n = 0; n < bad.size(); ++n)
    {
        CAPTURE(n);
        CHECK(ldap_message_size(bad.substr(0, n), total) == 0);
        CHECK_FALSE(ldap_parse_bind_response(bad.substr(0, n), 1, r, why));
    }
    // A cut inside the result, under a frame that claims it whole.
    CHECK_FALSE(ldap_parse_bind_response(hex_bytes({0x30, 0x08, 0x02, 0x01, 0x01, 0x61, 0x03, 0x0a, 0x01, 0x00}), 1, r,
                                         why));
    // Two messages back to back are framed one at a time.
    CHECK(ldap_message_size(ok + bad, total) == 1);
    CHECK(total == ok.size());
    CHECK_FALSE(ldap_parse_bind_response(ok + bad, 1, r, why));

    CHECK_FALSE(ldap_parse_bind_response(ok, 2, r, why));
    CHECK(why.find("message 1, not 2") != std::string::npos);
    // A SearchResultDone is no BindResponse.
    std::string done = ok;
    done[5] = 0x65;
    CHECK_FALSE(ldap_parse_bind_response(done, 1, r, why));
    // A Notice of Disconnection ends the session.
    const std::string notice = hex_bytes({0x30, 0x0c, 0x02, 0x01, 0x00, 0x78, 0x07, 0x0a, 0x01, 0x34, 0x04, 0x00,
                                          0x04, 0x00});
    CHECK_FALSE(ldap_parse_bind_response(notice, 1, r, why));
    CHECK(why.find("ended the session") != std::string::npos);
    // A long-form length frames the same message.
    const std::string long_form = hex_bytes({0x30, 0x81, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04,
                                             0x00, 0x04, 0x00});
    CHECK(ldap_message_size(long_form, total) == 1);
    CHECK(ldap_parse_bind_response(long_form, 1, r, why));
    CHECK(r.code == 0);

    CHECK(ldap_message_size(hex_bytes({0x31, 0x00}), total) == -1);
    CHECK(ldap_message_size(hex_bytes({0x30, 0x80}), total) == -1);
    CHECK(ldap_message_size(hex_bytes({0x30, 0x84, 0x7f, 0xff, 0xff, 0xff}), total) == -1);
}

namespace
{

// An LDAP server on 127.0.0.1 for one connection: it reads one message, answers `reply` (nothing when empty), then
// reads whatever comes until the client closes.
struct fake_ldap
{
    int         lfd{-1};
    uint16_t    port{0};
    std::string reply;
    std::string first;
    std::string after;
    std::thread th;

    explicit fake_ldap(std::string answer) : reply(std::move(answer))
    {
        lfd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        REQUIRE(lfd >= 0);
        struct sockaddr_in a{};
        a.sin_family      = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        REQUIRE(::bind(lfd, reinterpret_cast<struct sockaddr*>(&a), sizeof a) == 0);
        REQUIRE(::listen(lfd, 4) == 0);
        socklen_t len = sizeof a;
        REQUIRE(::getsockname(lfd, reinterpret_cast<struct sockaddr*>(&a), &len) == 0);
        port = ntohs(a.sin_port);
        th   = std::thread([this] { serve(); });
    }
    ~fake_ldap()
    {
        finish();
        ::close(lfd);
    }

    void finish()
    {
        if (th.joinable())
            th.join();
    }

    static bool read_some(int fd, std::string& into)
    {
        struct pollfd p{fd, POLLIN, 0};
        if (::poll(&p, 1, 3000) <= 0)
            return false;
        char buf[4096];
        const ssize_t n = ::recv(fd, buf, sizeof buf, 0);
        if (n <= 0)
            return false;
        into.append(buf, static_cast<size_t>(n));
        return true;
    }

    void serve()
    {
        struct pollfd p{lfd, POLLIN, 0};
        if (::poll(&p, 1, 3000) <= 0)
            return;
        const int fd = ::accept4(lfd, nullptr, nullptr, SOCK_CLOEXEC);
        if (fd < 0)
            return;
        size_t total = 0;
        while (ldap_message_size(first, total) == 0 && read_some(fd, first))
        {
        }
        if (!reply.empty() && ::send(fd, reply.data(), reply.size(), MSG_NOSIGNAL) < 0)
        {
        }
        while (read_some(fd, after))
        {
        }
        ::close(fd);
    }
};

federation_ldap ldap_at(uint16_t port, int timeout_ms = 3000)
{
    federation_ldap l;
    l.host        = "127.0.0.1";
    l.port        = port;
    l.dn_template = "uid=%s,ou=people,dc=example,dc=org";
    l.users       = {{"*", "="}};
    l.timeout_ms  = timeout_ms;
    return l;
}

}   // namespace

TEST_CASE("an LDAP bind goes to the server and comes back with its answer")
{
    ldap_bind_result r;
    std::string why;

    SUBCASE("the server takes the password")
    {
        fake_ldap srv(hex_bytes({0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}));
        const bool ok = ldap_simple_bind(ldap_at(srv.port), "a,lice", "pw", r, why);
        srv.finish();
        INFO(why);
        REQUIRE(ok);
        CHECK(r.bound());
        CHECK(srv.first == ldap_bind_request(1, "uid=a\\,lice,ou=people,dc=example,dc=org", "pw"));
        CHECK(srv.after == ldap_unbind_request(2));
    }
    SUBCASE("the server refuses the password")
    {
        fake_ldap srv(hex_bytes({0x30, 0x0f, 0x02, 0x01, 0x01, 0x61, 0x0a, 0x0a, 0x01, 0x31, 0x04, 0x00, 0x04, 0x03,
                                 'b', 'a', 'd'}));
        const bool ok = ldap_simple_bind(ldap_at(srv.port), "alice", "wrong", r, why);
        srv.finish();
        REQUIRE(ok);
        CHECK(r.code == 49);
        CHECK(r.diagnostic == "bad");
        CHECK(srv.after.empty());
    }
    SUBCASE("the server answers another message")
    {
        fake_ldap srv(hex_bytes({0x30, 0x0c, 0x02, 0x01, 0x07, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}));
        CHECK_FALSE(ldap_simple_bind(ldap_at(srv.port), "alice", "pw", r, why));
        srv.finish();
        CHECK_FALSE(r.bound());
    }
    SUBCASE("the server never answers")
    {
        fake_ldap srv("");
        const auto start = std::chrono::steady_clock::now();
        CHECK_FALSE(ldap_simple_bind(ldap_at(srv.port, 300), "alice", "pw", r, why));
        const auto took = std::chrono::steady_clock::now() - start;
        srv.finish();
        CHECK(why.find("did not answer within 300 ms") != std::string::npos);
        CHECK(took >= std::chrono::milliseconds(250));
        CHECK(took < std::chrono::seconds(2));
    }
    SUBCASE("nothing listens")
    {
        uint16_t port = 0;
        {
            const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
            struct sockaddr_in a{};
            a.sin_family      = AF_INET;
            a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            REQUIRE(::bind(fd, reinterpret_cast<struct sockaddr*>(&a), sizeof a) == 0);
            socklen_t len = sizeof a;
            REQUIRE(::getsockname(fd, reinterpret_cast<struct sockaddr*>(&a), &len) == 0);
            port = ntohs(a.sin_port);
            ::close(fd);
        }
        CHECK_FALSE(ldap_simple_bind(ldap_at(port), "alice", "pw", r, why));
        CHECK(why.find("cannot connect") != std::string::npos);
    }
    SUBCASE("an empty password is refused before any connection, as it would bind unauthenticated")
    {
        CHECK_FALSE(ldap_simple_bind(ldap_at(1), "alice", "", r, why));
        CHECK(why.find("password") != std::string::npos);
        CHECK_FALSE(ldap_simple_bind(ldap_at(1), "", "pw", r, why));
        CHECK_FALSE(ldap_simple_bind(ldap_at(1), "al\nice", "pw", r, why));
        CHECK_FALSE(ldap_simple_bind(federation_ldap{}, "alice", "pw", r, why));
    }
}
