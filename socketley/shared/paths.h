#pragma once
#include <filesystem>
#include <string>

struct socketley_paths
{
    std::filesystem::path socket_path;
    std::filesystem::path state_dir;     // runtimes/ JSON configs
    std::filesystem::path config_path;   // daemon config.lua
    bool system_mode = false;            // true if installed system-wide

    // Where runtimes lived before the state directory was keyed to the socket,
    // empty when state_dir already is it, so `!empty()` means there is
    // something to adopt.
    std::filesystem::path legacy_state_dir;

    // The path with SOCKETLEY_SOCKET out of the picture, since owning the
    // legacy directory is decided by whoever serves it rather than by disk.
    std::filesystem::path default_socket_path;

    static socketley_paths resolve();
};
