#include "password_hash.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <cstdio>
#include <cstdlib>
#include <vector>

#include "checksum.h"
#include "scrypt.h"
#include "../../shared/util/base64.h"
#include "../../shared/crypto/mac.h"

namespace socketley::storage
{

namespace
{

constexpr int salt_bytes = 16;
constexpr int hash_bytes = 32;
// 16 MiB a hash, which the memory bound must leave room for.
constexpr uint64_t max_mem = 64ull << 20;

bool derive(std::string_view password, std::string_view salt, int ln, int r, int p, std::string& out)
{
    out.assign(hash_bytes, '\0');
    return scrypt::derive(password, salt, uint64_t(1) << ln, static_cast<uint32_t>(r), static_cast<uint32_t>(p),
                          max_mem, reinterpret_cast<unsigned char*>(out.data()), out.size());
}

// A hash as password_matches() reads it.
struct parsed
{
    int ln{0}, r{0}, p{0};
    std::string salt, want;
};

bool parse(std::string_view hash, parsed& out)
{
    // $scrypt$ln=<ln>,r=<r>,p=<p>$<salt>$<hash>
    static constexpr std::string_view head = "$scrypt$ln=";
    if (!hash.starts_with(head))
        return false;
    hash.remove_prefix(head.size());
    const size_t d1 = hash.find('$'), d2 = d1 == std::string_view::npos ? d1 : hash.find('$', d1 + 1);
    if (d2 == std::string_view::npos)
        return false;
    const std::string params(hash.substr(0, d1));
    if (std::sscanf(params.c_str(), "%d,r=%d,p=%d", &out.ln, &out.r, &out.p) != 3 || out.ln < 10 || out.ln > 20 ||
        out.r < 1 || out.r > 32 || out.p < 1 || out.p > 16)
        return false;
    return base64::decode(hash.substr(d1 + 1, d2 - d1 - 1), out.salt) && base64::decode(hash.substr(d2 + 1), out.want) &&
           out.want.size() == hash_bytes;
}

}   // namespace

std::string password_hash(std::string_view password)
{
    std::string salt(salt_bytes, '\0'), h;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), salt_bytes) != 1 || !derive(password, salt, 14, 8, 1, h))
        return {};
    return "$scrypt$ln=14,r=8,p=1$" + base64::encode(salt) + "$" + base64::encode(h);
}

bool password_matches(std::string_view hash, std::string_view password)
{
    parsed h;
    std::string got;
    if (!parse(hash, h) || !derive(password, h.salt, h.ln, h.r, h.p, got))
        return false;
    return crypto::secure_equal(got, h.want);
}

void password_matches_many(std::span<password_check> checks)
{
    std::vector<parsed> hs(checks.size());
    std::vector<std::string> got(checks.size(), std::string(hash_bytes, '\0'));
    std::vector<bool> done(checks.size(), false);
    for (size_t i = 0; i < checks.size(); ++i)
    {
        checks[i].matches = false;
        if (!parse(checks[i].hash, hs[i]))
            done[i] = true;
    }
    // Those of one N and r and p = 1 together, four at most; any other alone.
    for (size_t i = 0; i < checks.size(); ++i)
    {
        if (done[i])
            continue;
        if (hs[i].p != 1)
        {
            std::string one;
            checks[i].matches = derive(checks[i].password, hs[i].salt, hs[i].ln, hs[i].r, hs[i].p, one) &&
                                crypto::secure_equal(one, hs[i].want);
            done[i] = true;
            continue;
        }
        std::vector<size_t> group;
        std::vector<scrypt::job> jobs;
        for (size_t k = i; k < checks.size() && group.size() < scrypt::max_batch; ++k)
            if (!done[k] && hs[k].p == 1 && hs[k].ln == hs[i].ln && hs[k].r == hs[i].r)
            {
                group.push_back(k);
                jobs.push_back({checks[k].password, hs[k].salt, reinterpret_cast<unsigned char*>(got[k].data()),
                                hash_bytes});
            }
        const bool ok = scrypt::derive_many(jobs, uint64_t(1) << hs[i].ln, static_cast<uint32_t>(hs[i].r), max_mem);
        for (const size_t k : group)
        {
            checks[k].matches = ok && crypto::secure_equal(got[k], hs[k].want);
            done[k] = true;
        }
    }
}

std::string password_problem(std::string_view password, std::string_view user)
{
    if (password.size() < 8)
        return "A password is at least 8 characters long.";
    if (password.size() > 128)
        return "A password is at most 128 characters long.";
    if (password == user)
        return "A password is not the user's name.";
    return {};
}

}   // namespace socketley::storage
