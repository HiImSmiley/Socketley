#pragma once
// Every flag `create` takes, per runtime type, with what the dashboard needs to offer it: how its value is entered,
// a label, one line of help and the section it is shown in. test_dashboard_schema holds it level with the parsers
// in flag_handlers.cpp, so a flag added there and not here turns that test red.
#include <string>
#include <string_view>
#include <vector>

#include "../shared/runtime/runtime_definitions.h"

namespace runtime_schema
{

// The table as JSON: {"types": [...], "flags": [{"flag", "types", "kind", "label", "help", "section", "choices"?,
// "placeholder"?}, ...]}; kind is switch, text, int, size, duration, choice, list or path.
const std::string& json();

// Whether `flag`, or an alias of it, takes a file path, which a command makes absolute where it was typed.
bool is_path_flag(std::string_view flag);

// A flag `create` takes for a type: how its value is written, and the key its state keeps it under, empty for none.
struct flag_entry
{
    std::string_view flag, kind, state_key;
};

// Every flag `create` takes for a runtime of `type`, in the table's order; none for a registered type.
std::vector<flag_entry> flags_for(runtime_type type);

// Whether `create` takes `flag`, or an alias of it, for a runtime of `type`.
bool offered(std::string_view flag, runtime_type type);

}   // namespace runtime_schema
