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

inline std::string& attach_error_storage()
{
    static std::string err;
    return err;
}

} // namespace detail

// Why the last daemon_attach() returned false — the daemon's refusal verbatim,
// or the connect failure.  Empty after a success.  daemon_attach() returns
// bool because registering is usually best-effort ("run anyway, just
// unlisted"), but a refusal with no reason anywhere was the SDK's only answer
// when it was not.
inline const std::string& attach_error()
{
    return detail::attach_error_storage();
}

// `owner` parents this runtime under an existing one, exactly as
// `attach ... --owner <name>` does: `socketley ls` shows the hierarchy, and
// the owner's child policy decides what happens to this entry when the owner
// goes.
inline bool daemon_attach(const std::string& name, const std::string& type,
                          uint16_t port, const std::string& owner = "")
{
    bool is_managed = std::getenv("SOCKETLEY_MANAGED") != nullptr;
    const char* env_name = std::getenv("SOCKETLEY_NAME");
    const std::string env_name_str = (env_name && env_name[0]) ? env_name : "";
    const std::string& actual_name = env_name_str.empty() ? name : env_name_str;

    std::string cmd = "attach " + type + " " + actual_name + " " + std::to_string(port)
                    + " --pid " + std::to_string(getpid());
    if (!owner.empty())
        cmd += " --owner " + owner;
    if (is_managed)
        cmd += " --managed";
    auto r = ctl::command(cmd);
    detail::attach_error_storage() = r.exit_code == 0 ? "" : r.data;
    if (r.exit_code == 0)
    {
        if (!is_managed)
        {
            detail::attached_name() = actual_name;
            std::atexit([] {
                if (!detail::attached_name().empty())
                    ctl::command("remove " + detail::attached_name());
            });
        }
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
