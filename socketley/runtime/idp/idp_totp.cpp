#include "idp_totp.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <cstdio>

namespace socketley::idp
{

namespace
{

constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

std::string uri_part(std::string_view s)
{
    std::string out;
    for (const unsigned char c : s)
    {
        if (std::isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~' || c == '@')
            out += static_cast<char>(c);
        else
        {
            char buf[4];
            std::snprintf(buf, sizeof buf, "%%%02X", c);
            out += buf;
        }
    }
    return out;
}

}   // namespace

std::string base32_encode(std::string_view bytes)
{
    std::string out;
    uint32_t buffer = 0;
    int bits = 0;
    for (const unsigned char c : bytes)
    {
        buffer = (buffer << 8) | c;
        bits += 8;
        while (bits >= 5)
        {
            out += alphabet[(buffer >> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0)
        out += alphabet[(buffer << (5 - bits)) & 31];
    return out;
}

bool base32_decode(std::string_view text, std::string& out)
{
    out.clear();
    uint32_t buffer = 0;
    int bits = 0;
    for (char c : text)
    {
        if (c == ' ' || c == '=' || c == '-')
            continue;
        if (c >= 'a' && c <= 'z')
            c = static_cast<char>(c - 32);
        int v = -1;
        if (c >= 'A' && c <= 'Z')
            v = c - 'A';
        else if (c >= '2' && c <= '7')
            v = c - '2' + 26;
        if (v < 0)
            return false;
        buffer = (buffer << 5) | static_cast<uint32_t>(v);
        bits += 5;
        if (bits >= 8)
        {
            out += static_cast<char>((buffer >> (bits - 8)) & 0xff);
            bits -= 8;
        }
    }
    return !out.empty();
}

std::string totp_code(std::string_view secret, uint64_t counter)
{
    unsigned char msg[8];
    for (int i = 7; i >= 0; --i)
    {
        msg[i] = static_cast<unsigned char>(counter & 0xff);
        counter >>= 8;
    }
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (!HMAC(EVP_sha1(), secret.data(), static_cast<int>(secret.size()), msg, sizeof msg, md, &len) || len < 20)
        return {};
    // Dynamic truncation (RFC 4226 5.3).
    const int off = md[len - 1] & 0x0f;
    const uint32_t bin = (static_cast<uint32_t>(md[off] & 0x7f) << 24) | (static_cast<uint32_t>(md[off + 1]) << 16) |
                         (static_cast<uint32_t>(md[off + 2]) << 8) | md[off + 3];
    char out[8];
    std::snprintf(out, sizeof out, "%06u", bin % 1000000);
    return out;
}

uint64_t totp_step(std::string_view secret, std::string_view code, int64_t now_s, uint64_t last_used)
{
    std::string digits;
    for (const char c : code)
        if (c >= '0' && c <= '9')
            digits += c;
        else if (c != ' ')
            return 0;
    if (digits.size() != 6 || secret.empty() || now_s < 30)
        return 0;
    const uint64_t now = static_cast<uint64_t>(now_s) / 30;
    for (const uint64_t step : {now, now - 1, now + 1})
        if (step > last_used && totp_code(secret, step) == digits)
            return step;
    return 0;
}

std::string totp_uri(std::string_view issuer, std::string_view user, std::string_view secret_b32)
{
    return "otpauth://totp/" + uri_part(issuer) + ":" + uri_part(user) + "?secret=" + std::string(secret_b32) +
           "&issuer=" + uri_part(issuer) + "&algorithm=SHA1&digits=6&period=30";
}

}   // namespace socketley::idp
