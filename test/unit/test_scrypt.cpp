// scrypt as the password hashes are made and checked: the bytes RFC 7914 and OpenSSL give, the parameters OpenSSL
// refuses refused, and many checked at once the same as each alone.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <chrono>
#include <string>
#include <vector>

#include <openssl/evp.h>

#include "runtime/idp/idp_logic.h"
#include "shared/crypto/password_hash.h"
#include "shared/crypto/scrypt.h"

using namespace socketley::crypto;

namespace
{

constexpr uint64_t mem = 64ull << 20;

std::string hex(const unsigned char* p, size_t n)
{
    static constexpr char d[] = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < n; ++i)
    {
        out += d[p[i] >> 4];
        out += d[p[i] & 15];
    }
    return out;
}

std::string ours(std::string_view pw, std::string_view salt, uint64_t N, uint32_t r, uint32_t p, size_t n = 32)
{
    std::vector<unsigned char> out(n);
    if (!scrypt::derive(pw, salt, N, r, p, mem, out.data(), n))
        return "refused";
    return hex(out.data(), n);
}

std::string openssl(std::string_view pw, std::string_view salt, uint64_t N, uint32_t r, uint32_t p, size_t n = 32)
{
    std::vector<unsigned char> out(n);
    if (EVP_PBE_scrypt(pw.data(), pw.size(), reinterpret_cast<const unsigned char*>(salt.data()), salt.size(), N, r, p,
                       mem, out.data(), n) != 1)
        return "refused";
    return hex(out.data(), n);
}

}   // namespace

TEST_CASE("the vectors of RFC 7914 come out as it prints them")
{
    CHECK(ours("", "", 16, 1, 1, 64) ==
          "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906");
    CHECK(ours("password", "NaCl", 1024, 8, 16, 64) ==
          "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640");
    CHECK(ours("pleaseletmein", "SodiumChloride", 16384, 8, 1, 64) ==
          "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887");
}

TEST_CASE("every N, r and p comes out as OpenSSL's, and what it refuses is refused")
{
    for (int t = 0; t < 48; ++t)
    {
        const std::string pw = "pw-" + std::to_string(t * 7919);
        const std::string salt(static_cast<size_t>(t % 20), static_cast<char>('a' + t % 26));
        const uint64_t N = uint64_t(1) << (1 + t % 13);
        const uint32_t r = 1 + static_cast<uint32_t>(t % 9), p = 1 + static_cast<uint32_t>(t % 4);
        CHECK(ours(pw, salt, N, r, p) == openssl(pw, salt, N, r, p));
    }
    CHECK(ours("x", "s", 65536, 1, 1) == "refused");   // N must be under 2^(16r)
    CHECK(openssl("x", "s", 65536, 1, 1) == "refused");
    CHECK(ours("x", "s", 32768, 1, 1) == openssl("x", "s", 32768, 1, 1));
    CHECK(ours("x", "s", 1000, 8, 1) == "refused");    // not a power of two
    CHECK(ours("x", "s", 1, 8, 1) == "refused");
    CHECK(ours("x", "s", 16, 0, 1) == "refused");
    CHECK(ours("x", "s", 16, 8, 0) == "refused");
    CHECK(ours("x", "s", uint64_t(1) << 16, 8, 1) == "refused");   // 64 MiB and a little more
    CHECK(openssl("x", "s", uint64_t(1) << 16, 8, 1) == "refused");
}

TEST_CASE("one, two, three or four hashes made at once are each the one made alone")
{
    for (size_t n = 1; n <= scrypt::max_batch; ++n)
    {
        std::vector<std::string> pws, salts;
        std::vector<std::vector<unsigned char>> outs(n, std::vector<unsigned char>(32));
        for (size_t i = 0; i < n; ++i)
        {
            pws.push_back("password-" + std::to_string(n * 10 + i));
            salts.push_back("salt-" + std::to_string(i));
        }
        std::vector<scrypt::job> jobs;
        for (size_t i = 0; i < n; ++i)
            jobs.push_back({pws[i], salts[i], outs[i].data(), 32});
        REQUIRE(scrypt::derive_many(jobs, 1024, 8, mem));
        for (size_t i = 0; i < n; ++i)
            CHECK(hex(outs[i].data(), 32) == openssl(pws[i], salts[i], 1024, 8, 1));
    }
    std::vector<unsigned char> out(32);
    std::vector<scrypt::job> five(5, scrypt::job{"a", "b", out.data(), 32});
    CHECK_FALSE(scrypt::derive_many(five, 1024, 8, mem));
}

TEST_CASE("passwords checked many at once match as each would alone")
{
    const std::string a = password_hash("alpha-password"), b = password_hash("beta-password"),
                      c = password_hash("gamma-password");
    REQUIRE(a.starts_with("$scrypt$ln=14,r=8,p=1$"));
    // One of other parameters, made by OpenSSL, as an imported storage user's might be.
    const std::string salt = "0123456789abcdef";
    unsigned char raw[32];
    REQUIRE(EVP_PBE_scrypt("delta-password", 14, reinterpret_cast<const unsigned char*>(salt.data()), salt.size(), 1024, 4,
                           2, mem, raw, 32) == 1);
    EVP_ENCODE_CTX* e = EVP_ENCODE_CTX_new();
    unsigned char b64s[64], b64h[64];
    const int ns = EVP_EncodeBlock(b64s, reinterpret_cast<const unsigned char*>(salt.data()), 16);
    const int nh = EVP_EncodeBlock(b64h, raw, 32);
    EVP_ENCODE_CTX_free(e);
    const std::string d = "$scrypt$ln=10,r=4,p=2$" + std::string(reinterpret_cast<char*>(b64s), ns) + "$" +
                          std::string(reinterpret_cast<char*>(b64h), nh);
    REQUIRE(password_matches(d, "delta-password"));

    std::vector<password_check> checks = {
        {a, "alpha-password"}, {b, "wrong"},          {c, "gamma-password"}, {d, "delta-password"},
        {"not a hash", "x"},   {b, "beta-password"},  {a, "alpha-passwore"}, {c, "gamma-password"},
        {d, "delta-passwore"}, {a, "alpha-password"},
    };
    password_matches_many(checks);
    std::vector<bool> got, want;
    for (const auto& k : checks)
    {
        got.push_back(k.matches);
        want.push_back(password_matches(k.hash, k.password));
    }
    CHECK(got == want);
    CHECK(got == std::vector<bool>{true, false, true, true, false, true, false, true, false, true});
}

TEST_CASE("idp: the hash an unknown user's password is checked against is read as one and costs a real one's hash")
{
    // A hash that did not parse would answer at once, and the time would say the user does not exist.
    const auto began = std::chrono::steady_clock::now();
    CHECK_FALSE(password_matches(socketley::idp::no_account_hash, "socketley-no-such-user"));
    CHECK(std::chrono::steady_clock::now() - began > std::chrono::milliseconds(2));
    CHECK_FALSE(password_matches("$scrypt$ln=14,r=8,p=1$x$y", "z"));
}
