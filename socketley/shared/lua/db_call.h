#pragma once
// What marks a request channel payload as a call of socketley.db on a db runtime, a JSON object after it:
// {"method":..,"path":..[,"body":..][,"if_match":..][,"if_none_match":..]}, answered {"status":..,"body":..}.
#include <string_view>

namespace socketley::db
{

inline constexpr std::string_view call_marker = "\x02skl-db\n";

}   // namespace socketley::db
