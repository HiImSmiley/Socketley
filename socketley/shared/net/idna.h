#pragma once
// A domain name in the form DNS and the headers that name it compare in: each label past ASCII as its A-label, "xn--"
// and its Punycode (RFC 3492, IDNA 2008's ToASCII), ASCII in lower case.  The labels are taken as they are written,
// lower-cased where they are ASCII, without the mappings of UTS 46.
#include <string>
#include <string_view>

namespace socketley::idna
{

// `name` with each non-ASCII label as its A-label; empty where a label is not UTF-8 or would pass 63 bytes.
std::string to_ascii(std::string_view name);

}   // namespace socketley::idna
