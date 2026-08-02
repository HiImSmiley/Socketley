#pragma once
#include <filesystem>
#include <string>

struct socketley_paths
{
    std::filesystem::path socket_path;
    std::filesystem::path state_dir;     // runtimes/ JSON configs
    std::filesystem::path config_path;   // daemon config.lua
    bool system_mode = false;            // true if installed system-wide

    // Where this daemon's runtimes lived before its state directory was keyed
    // to a non-default socket — i.e. the directory a daemon on the default path
    // still uses.  Empty whenever state_dir *is* that directory, which is every
    // deployed daemon and every daemon that has never heard of
    // SOCKETLEY_SOCKET, so "is there anything to adopt" is `!empty()`.
    //
    // Set purely so that upgrading cannot look like every runtime vanished; see
    // the rule written out in paths.cpp and adopt_legacy_state() in daemon.cpp.
    std::filesystem::path legacy_state_dir;

    // The socket path this namespace resolves to with SOCKETLEY_SOCKET out of
    // the picture — the path the deployed daemon binds, and the one whose state
    // directory is legacy_state_dir.  Always set, and equal to socket_path
    // whenever the variable is unset or names the default anyway.
    //
    // It exists because owning the legacy directory is decided by whoever is
    // serving this path, and that question cannot be answered from disk: an
    // empty keyed directory beside a populated legacy one describes both the
    // daemon that has been running for months behind a fixed SOCKETLEY_SOCKET
    // and a brand-new second daemon started beside a live one.  See
    // adopt_legacy_state() in daemon.cpp.
    std::filesystem::path default_socket_path;

    static socketley_paths resolve();
};
