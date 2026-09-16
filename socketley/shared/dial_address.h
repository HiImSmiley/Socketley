#pragma once
#include <charconv>
#include <cstdint>
#include <string>
#include <string_view>

// Where an address a runtime DIALS is judged, so the flag that accepts it and
// the code that uses it cannot disagree about what it means.
//
// Written because a client's target was parsed in try_connect() and a failed
// parse kept the defaults: `-t host:abc` dialled the port -p had set, and
// `-t host` with no port at all kept host at 127.0.0.1 and dialled the loopback
// under the name of somebody else.  Neither said anything.  The proxy refuses
// the same spellings on --backend and the server on -u.
namespace socketley::dial_addr
{

// Empty when the address can be dialled, and then host and port carry it; the
// operator's reason otherwise.  An address with no colon is a host and leaves
// port as the caller set it, which is what -p offers a client -- so the host is
// taken either way, which is the half that used to be dropped.
inline std::string refusal(std::string_view addr, std::string& host, uint16_t& port,
                           bool port_required = false)
{
    if (addr.empty())
        return "no address was given";

    const auto colon = addr.rfind(':');
    if (colon == std::string_view::npos)
    {
        // port_required is for a caller with no second flag to take the port
        // from -- a cache's --replicate -- against a client, whose -p supplies
        // it and for which a bare host is the documented composition.
        if (port_required)
            return "the address needs a port, as host:port";
        host = std::string(addr);
        return {};
    }
    if (colon == 0)
        return "there is no host before the port";

    const auto port_sv = addr.substr(colon + 1);
    uint32_t parsed = 0;
    const auto [ptr, ec] =
        std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), parsed);
    // The whole of it, and in range: `host:8080x` took the 8080 once.
    if (ec != std::errc{} || ptr != port_sv.data() + port_sv.size() ||
        parsed == 0 || parsed > 65535)
        return "the port is not a number between 1 and 65535 (got \"" +
               std::string(port_sv) + "\")";

    host = std::string(addr.substr(0, colon));
    port = static_cast<uint16_t>(parsed);
    return {};
}

// The same judgment where only the verdict is wanted, so a flag cannot judge
// by a different rule than the dial does.
inline std::string refusal(std::string_view addr, bool port_required = false)
{
    std::string host;
    uint16_t port = 1;
    return refusal(addr, host, port, port_required);
}

}  // namespace socketley::dial_addr
