#pragma once
// A second step of signing in: the six digits an authenticator app shows from a secret it was given once (TOTP, RFC
// 6238, HMAC-SHA1 over thirty-second steps), and the base32 that secret travels in (RFC 4648).
#include <cstdint>
#include <string>
#include <string_view>

namespace socketley::idp
{

std::string base32_encode(std::string_view bytes);
// False where `text` is no base32; spaces and lower case are taken, as apps show the key in groups.
bool base32_decode(std::string_view text, std::string& out);

// The code of `secret`'s raw bytes for the step `counter`, six digits.
std::string totp_code(std::string_view secret, uint64_t counter);

// The step `code` is the code of, among the one of `now_s` and those beside it, past `last_used` so a code is taken
// once; 0 where it is none of them.
uint64_t totp_step(std::string_view secret, std::string_view code, int64_t now_s, uint64_t last_used);

// The otpauth:// URI an authenticator app takes the secret from, by a link or a QR code of it.
std::string totp_uri(std::string_view issuer, std::string_view user, std::string_view secret_b32);

}   // namespace socketley::idp
