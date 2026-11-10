#pragma once
// A template as Lua: its text as it is, {{ x }} the value of x escaped for HTML, {{{ x }}} unescaped, {{ x|otherwise }}
// a default, and {% code %} run where it stands; what mail's campaigns and web's pages fill in.
#include <string>
#include <string_view>

namespace socketley::lua_template
{

// The Lua of template `t`: a chunk called with (out, value, path, env) that writes the text through them; false with
// `why` where a {% is never closed. {{unsubscribe}} is kept for the mail runtime where `keep_unsubscribe`.
bool compile(std::string_view t, std::string_view name, bool keep_unsubscribe, std::string& code, std::string& why);

}   // namespace socketley::lua_template
