#pragma once
#include <filesystem>
#include <string>

struct socketley_paths
{
    std::filesystem::path socket_path;
    std::filesystem::path state_dir;     // runtimes/ JSON configs
    std::filesystem::path config_path;   // daemon config.lua
    bool system_mode = false;            // true if installed system-wide

    static socketley_paths resolve();
};
