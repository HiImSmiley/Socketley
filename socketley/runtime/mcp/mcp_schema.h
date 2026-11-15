#pragma once
// A tool's arguments held to the input schema it declared, before its handler sees them, as every MCP revision asks
// of a server ("Servers MUST validate all tool inputs"). The part of JSON Schema a tool's input is written in is
// checked; a keyword it does not know is an annotation, as JSON Schema has it, and a reference leaves the schema only
// within it ("#/..."), never by fetching anything.
#include <string>
#include <string_view>

#include "../../shared/json/json_doc.h"

namespace socketley::mcp
{

// True when `args` is admitted by the schema whose text is `schema`; false with `why` naming the first place that is
// not, or saying the schema itself cannot be read, so a tool whose schema is broken is never called unchecked.
bool schema_admits(std::string_view schema, const json::jvalue& args, std::string& why);

}   // namespace socketley::mcp
