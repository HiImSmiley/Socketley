#pragma once
// Every flag `create` takes, per runtime type, with what the dashboard needs to offer it: how its value is entered,
// a label, one line of help and the section it is shown in. test_dashboard_schema holds it level with the parsers
// in flag_handlers.cpp, so a flag added there and not here turns that test red.
#include <string>
#include <string_view>

#include "../shared/runtime/runtime_definitions.h"

namespace runtime_schema
{

// The table as JSON: {"types": [...], "flags": [{"flag", "types", "kind", "label", "help", "section", "choices"?,
// "placeholder"?}, ...]}; kind is switch, text, int, size, duration, choice, list or path.
const std::string& json();

// Whether `flag`, or an alias of it, takes a file path, which a command makes absolute where it was typed.
bool is_path_flag(std::string_view flag);

// Whether `create` takes `flag`, or an alias of it, for a runtime of `type`.
bool offered(std::string_view flag, runtime_type type);

}   // namespace runtime_schema
