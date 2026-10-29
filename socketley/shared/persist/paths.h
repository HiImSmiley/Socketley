#pragma once
#include <filesystem>
#include <string>

struct socketley_paths
{
    std::filesystem::path socket_path;
    std::filesystem::path state_dir;     // runtimes/ JSON configs
    std::filesystem::path config_path;   // daemon config.lua
    // Registered-type manifests, beside config_path rather than the state dir,
    // because a manifest describes an installation and not a daemon's state.
    std::filesystem::path types_dir;

    // One file per daemon that is serving, so `socketley daemons` can find the
    // ones on sockets nobody named -- the state directory cannot answer this,
    // because its key spells `/` as `_` and does not come back.
    std::filesystem::path daemons_dir;
    bool system_mode = false;            // true if installed system-wide

    // Where runtimes lived before the state directory was keyed to the socket,
    // empty when state_dir already is it, so `!empty()` means there is
    // something to adopt.
    std::filesystem::path legacy_state_dir;

    // The path with SOCKETLEY_SOCKET out of the picture, since owning the
    // legacy directory is decided by whoever serves it rather than by disk.
    std::filesystem::path default_socket_path;

    // Why state_dir must not be used, empty when it may: a /tmp fallback another user made or can reach.
    std::string state_dir_refusal;

    static socketley_paths resolve();
};
