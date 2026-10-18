#pragma once

#include <string>
#include <string_view>

// Base64 of RFC 4648 in both its alphabets, decoded only from the one spelling an encoder writes, and to nothing
// when it is another.
namespace socketley::base64
{

// The standard alphabet, padded with '=' to whole quanta.
std::string encode(std::string_view in);
bool        decode(std::string_view in, std::string& out);

} // namespace socketley::base64

// The URL alphabet without padding, as JWS, cookies and continuation tokens carry it.
namespace socketley::base64url
{

std::string encode(std::string_view in);
bool        decode(std::string_view in, std::string& out);

} // namespace socketley::base64url
