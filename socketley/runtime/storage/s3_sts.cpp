#include "s3_sts.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "s3_names.h"
#include "s3_xml.h"
#include "../../shared/util/base64.h"

namespace socketley::storage
{

namespace
{

constexpr uint8_t     token_version = 1;
constexpr uint8_t     token_role_version = 2;
constexpr size_t      mac_bytes     = 32;
constexpr std::string_view sts_xmlns = "https://sts.amazonaws.com/doc/2011-06-15/";

std::string mac(std::string_view key, std::string_view label, std::string_view msg)
{
    std::string in;
    in.reserve(label.size() + 1 + msg.size());
    in.append(label);
    in.push_back('\0');
    in.append(msg);
    std::string out(mac_bytes, '\0');
    unsigned int len = mac_bytes;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), reinterpret_cast<const unsigned char*>(in.data()),
         in.size(), reinterpret_cast<unsigned char*>(out.data()), &len);
    return out;
}

// The token's body: its version, the expiry, and the parent key, the access key and the policy, each after its
// length, and in version 2 the role assumed.
std::string payload_of(const session_grant& g)
{
    std::string p;
    p.push_back(static_cast<char>(g.role.empty() ? token_version : token_role_version));
    for (int s = 56; s >= 0; s -= 8)
        p.push_back(static_cast<char>((static_cast<uint64_t>(g.expires) >> s) & 0xFF));
    p.push_back(static_cast<char>(g.parent_key.size()));
    p += g.parent_key;
    p.push_back(static_cast<char>(g.access_key.size()));
    p += g.access_key;
    p.push_back(static_cast<char>((g.policy.size() >> 8) & 0xFF));
    p.push_back(static_cast<char>(g.policy.size() & 0xFF));
    p += g.policy;
    if (!g.role.empty())
    {
        p.push_back(static_cast<char>(g.role.size()));
        p += g.role;
    }
    return p;
}

void text_element(std::string& x, std::string_view name, std::string_view v)
{
    x += "<";
    x += name;
    x += ">";
    xml_escape_to(x, v);
    x += "</";
    x += name;
    x += ">";
}

}   // namespace

std::string sts_new_access_key()
{
    static constexpr char b32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    unsigned char raw[16];
    if (RAND_bytes(raw, sizeof raw) != 1)
        return {};
    std::string k = "ASIA";
    for (unsigned char b : raw)
        k.push_back(b32[b & 31]);
    return k;
}

std::string sts_token(const session_grant& g, std::string_view parent_secret)
{
    const std::string p = payload_of(g);
    return base64url::encode(p + mac(parent_secret, "token", p));
}

bool sts_parse(std::string_view token, session_grant& out)
{
    std::string raw;
    if (token.size() > 8192 || !base64url::decode(token, raw) || raw.size() < 1 + 8 + 1 + 1 + 2 + mac_bytes ||
        (static_cast<uint8_t>(raw[0]) != token_version && static_cast<uint8_t>(raw[0]) != token_role_version))
        return false;
    const bool with_role = static_cast<uint8_t>(raw[0]) == token_role_version;
    std::string_view p(raw.data(), raw.size() - mac_bytes);
    size_t at = 1;
    uint64_t e = 0;
    for (int i = 0; i < 8; ++i)
        e = (e << 8) | static_cast<uint8_t>(p[at++]);
    out.expires = static_cast<int64_t>(e);
    auto field = [&](size_t len, std::string& f)
    {
        if (at + len > p.size())
            return false;
        f.assign(p.substr(at, len));
        at += len;
        return true;
    };
    if (!field(static_cast<uint8_t>(p[at++]), out.parent_key) || at >= p.size() ||
        !field(static_cast<uint8_t>(p[at++]), out.access_key) || at + 2 > p.size())
        return false;
    const size_t plen = (static_cast<size_t>(static_cast<uint8_t>(p[at])) << 8) | static_cast<uint8_t>(p[at + 1]);
    at += 2;
    if (!field(plen, out.policy))
        return false;
    if (with_role && (at >= p.size() || !field(static_cast<uint8_t>(p[at++]), out.role) || out.role.empty()))
        return false;
    return at == p.size();
}

bool sts_sealed_by(std::string_view token, std::string_view parent_secret)
{
    std::string raw;
    if (!base64url::decode(token, raw) || raw.size() <= mac_bytes)
        return false;
    const std::string_view p(raw.data(), raw.size() - mac_bytes);
    const std::string want = mac(parent_secret, "token", p);
    return CRYPTO_memcmp(want.data(), raw.data() + p.size(), mac_bytes) == 0;
}

std::string sts_secret(const session_grant& g, std::string_view parent_secret)
{
    return base64url::encode(mac(parent_secret, "secret", payload_of(g))).substr(0, 40);
}

bool parse_form_fields(std::string_view text, std::vector<std::pair<std::string, std::string>>& out)
{
    while (!text.empty())
    {
        const size_t amp = text.find('&');
        const std::string_view part = text.substr(0, amp);
        text = amp == std::string_view::npos ? std::string_view{} : text.substr(amp + 1);
        if (part.empty())
            continue;
        const size_t eq = part.find('=');
        std::string k, v;
        if (!percent_decode(part.substr(0, eq), k, true) ||
            !percent_decode(eq == std::string_view::npos ? std::string_view{} : part.substr(eq + 1), v, true))
            return false;
        out.emplace_back(std::move(k), std::move(v));
    }
    return true;
}

std::string sts_credentials_xml(std::string_view action, std::string_view access_key, std::string_view secret,
                                std::string_view token, int64_t expires, std::string_view role_arn,
                                std::string_view session_name, std::string_view request_id)
{
    std::string x = "<";
    x += action;
    x += "Response xmlns=\"";
    x += sts_xmlns;
    x += "\"><";
    x += action;
    x += "Result><Credentials>";
    text_element(x, "AccessKeyId", access_key);
    text_element(x, "SecretAccessKey", secret);
    text_element(x, "SessionToken", token);
    text_element(x, "Expiration", iso8601(expires * 1000));
    x += "</Credentials>";
    if (!role_arn.empty())
    {
        x += "<AssumedRoleUser>";
        text_element(x, "Arn", std::string(role_arn) + "/" + std::string(session_name));
        text_element(x, "AssumedRoleId", std::string(access_key) + ":" + std::string(session_name));
        x += "</AssumedRoleUser>";
    }
    x += "</";
    x += action;
    x += "Result><ResponseMetadata>";
    text_element(x, "RequestId", request_id);
    x += "</ResponseMetadata></";
    x += action;
    x += "Response>";
    return x;
}

std::string sts_error_xml(std::string_view code, std::string_view message, std::string_view request_id)
{
    std::string x = "<ErrorResponse xmlns=\"";
    x += sts_xmlns;
    x += "\"><Error><Type>Sender</Type>";
    text_element(x, "Code", code);
    text_element(x, "Message", message);
    x += "</Error>";
    text_element(x, "RequestId", request_id);
    x += "</ErrorResponse>";
    return x;
}

}   // namespace socketley::storage
