#pragma once
#include <filesystem>
#include <string>

struct socketley_paths
{
    std::filesystem::path socket_path;
    std::filesystem::path state_dir;     // runtimes/ JSON configs
    std::filesystem::path config_path;   // daemon config.lua
    bool system_mode = false;            // true if installed system-wide

    // Where runtimes lived before the state directory was keyed to the socket;
    // empty when state_dir already is it, so `!empty()` means "something to
    // adopt".  Exists so an upgrade cannot look like every runtime vanished.
    std::filesystem::path legacy_state_dir;

    // The path with SOCKETLEY_SOCKET out of the picture; owning the legacy
    // directory is decided by whoever serves it, which disk cannot answer.  See
    // adopt_legacy_state() in daemon.cpp.
    std::filesystem::path default_socket_path;

    static socketley_paths resolve();
};
