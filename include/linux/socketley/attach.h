// ═══════════════════════════════════════════════════════════════════
//  socketley/attach.h — Header-only daemon attach (Tier 3)
//
//  Register your own process as a runtime in a running daemon.
//  Fully self-contained (builds on control.h). No library needed.
//
//  Example:
//    #include <socketley/attach.h>
//    int main() {
//        socketley::daemon_attach("myservice", "server", 8080);
//        // your runtime runs here, daemon sees it in `socketley ls`
//        // auto-detaches on exit
//    }
//    // g++ -std=c++17 myapp.cpp -o myapp
// ═══════════════════════════════════════════════════════════════════
#pragma once

#include "control.h"
#include <cstdint>
#include <cstdlib>
#include <string>
#include <unistd.h>

namespace socketley {
namespace detail {

inline std::string& attached_name()
{
    static std::string name;
    return name;
}

} // namespace detail

inline bool daemon_attach(const std::string& name, const std::string& type,
                          uint16_t port)
{
    std::string cmd = "attach " + type + " " + name + " " + std::to_string(port)
                    + " --pid " + std::to_string(getpid());
    auto r = ctl::command(cmd);
    if (r.exit_code == 0)
    {
        detail::attached_name() = name;
        std::atexit([] {
            if (!detail::attached_name().empty())
                ctl::command("remove " + detail::attached_name());
        });
        return true;
    }
    return false;
}

inline void daemon_detach(const std::string& name)
{
    ctl::command("remove " + name);
    if (detail::attached_name() == name)
        detail::attached_name().clear();
}

inline void daemon_detach()
{
    if (!detail::attached_name().empty())
    {
        ctl::command("remove " + detail::attached_name());
        detail::attached_name().clear();
    }
}

} // namespace socketley
