#pragma once
// Every flag `create` takes, per runtime type, with what the dashboard needs to offer it: how its value is entered,
// a label, one line of help and the section it is shown in. test_dashboard_schema holds it level with the parsers
// in flag_handlers.cpp, so a flag added there and not here turns that test red.
#include <string>

namespace runtime_schema
{

// The table as JSON: {"types": [...], "flags": [{"flag", "types", "kind", "label", "help", "section", "choices"?,
// "placeholder"?}, ...]}; kind is switch, text, int, size, duration, choice, list or path.
const std::string& json();

}   // namespace runtime_schema
