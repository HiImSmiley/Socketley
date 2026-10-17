#pragma once
// A password as IAM keeps it for a login profile: scrypt, N = 2^14, r = 8, p = 1, a 16-byte salt and a 32-byte hash,
// written "$scrypt$ln=14,r=8,p=1$<salt>$<hash>" in base64, so the parameters can rise without making old ones unread.
#include <span>
#include <string>
#include <string_view>

namespace socketley::storage
{

// The hash of `password`, empty when no random salt could be drawn.
std::string password_hash(std::string_view password);
// Whether `password` is the one `hash` was made from, compared in constant time; false for a hash that is not one.
bool password_matches(std::string_view hash, std::string_view password);

struct password_check
{
    std::string_view hash;
    std::string_view password;
    bool matches{false};
};
// password_matches() for each, those of the same parameters up to four at once, which one core then makes in under
// half the time of one after the other.
void password_matches_many(std::span<password_check> checks);
// What is wrong with `password` as a new one for `user`, empty when nothing is.
std::string password_problem(std::string_view password, std::string_view user);

}   // namespace socketley::storage
