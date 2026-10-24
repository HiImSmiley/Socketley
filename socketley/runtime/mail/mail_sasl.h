#pragma once
// The SASL mechanisms that carry an OAuth 2.0 bearer token rather than a password: Google's and Microsoft's XOAUTH2
// and RFC 7628's OAUTHBEARER, which mail clients sign in with where an identity provider gives them a token.
#include <string>
#include <string_view>

namespace socketley::mail
{

// The user and the token of a decoded XOAUTH2 or OAUTHBEARER response; false where it is neither.
inline bool sasl_bearer(std::string_view mech, std::string_view raw, std::string& user, std::string& token)
{
    user.clear();
    token.clear();
    const auto field = [](std::string_view kvs, std::string_view key) -> std::string_view {
        for (std::string_view rest = kvs; !rest.empty();)
        {
            const size_t end = rest.find('\x01');
            const std::string_view kv = rest.substr(0, end);
            rest = end == std::string_view::npos ? std::string_view{} : rest.substr(end + 1);
            if (kv.size() > key.size() && kv.substr(0, key.size()) == key && kv[key.size()] == '=')
                return kv.substr(key.size() + 1);
        }
        return {};
    };
    std::string_view kvs = raw;
    if (mech == "XOAUTH2")
        user = std::string(field(kvs, "user"));
    else if (mech == "OAUTHBEARER")
    {
        // gs2-header "n,a=<user>," then the key-value pairs (RFC 7628 3.1); the user may be left to the token.
        const size_t first = raw.find('\x01');
        if (first == std::string_view::npos)
            return false;
        const std::string_view gs2 = raw.substr(0, first);
        if (const size_t a = gs2.find("a="); a != std::string_view::npos)
            user = std::string(gs2.substr(a + 2, gs2.find(',', a) == std::string_view::npos ? std::string_view::npos
                                                                                           : gs2.find(',', a) - a - 2));
        kvs = raw.substr(first + 1);
    }
    else
        return false;
    const std::string_view auth = field(kvs, "auth");
    if (auth.size() <= 7 || (auth.substr(0, 7) != "Bearer " && auth.substr(0, 7) != "bearer "))
        return false;
    token = std::string(auth.substr(7));
    return !token.empty() && token.find_first_of(" \r\n") == std::string::npos;
}

}   // namespace socketley::mail
