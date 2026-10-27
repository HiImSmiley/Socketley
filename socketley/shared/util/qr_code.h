#pragma once
// A QR code (ISO/IEC 18004) of a short text, as a page shows an authenticator app's key: byte mode, error
// correction level M, the smallest version from 1 to 10 the text fits in.
#include <string>
#include <string_view>
#include <vector>

namespace socketley::qr
{

// The modules row by row, true for dark, without the quiet zone; empty when the text does not fit in version 10.
std::vector<std::vector<bool>> encode(std::string_view text);

// The code as an SVG of dark squares on white with its four-module quiet zone, empty when it does not fit.
std::string svg(std::string_view text);

}   // namespace socketley::qr
