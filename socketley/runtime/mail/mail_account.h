#pragma once
// What a sign-in or a lookup of an account came to: yes, no, or no answer from the runtime that keeps the accounts,
// which a server tells its client as a failure for now rather than a refusal.
#include <cstdint>

namespace socketley::mail
{

enum class account : uint8_t { yes, no, unreachable };

}   // namespace socketley::mail
