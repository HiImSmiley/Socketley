#include "paths.h"
#include <unistd.h>
#include <pwd.h>
#include <cstdlib>

namespace fs = std::filesystem;

static fs::path get_home()
{
    const char* home = std::getenv("HOME");
    if (home && home[0])
        return home;

    struct passwd* pw = getpwuid(getuid());
    if (pw && pw->pw_dir)
        return pw->pw_dir;

    return {};
}

socketley_paths socketley_paths::resolve()
{
    socketley_paths p;

    bool installed = access("/usr/bin/socketley", X_OK) == 0;
    uid_t uid = getuid();

    // System mode: only for root or dedicated socketley system user
    bool is_privileged = (uid == 0);
    if (!is_privileged && installed)
    {
        struct passwd* pw = getpwnam("socketley");
        if (pw && pw->pw_uid == uid)
            is_privileged = true;
    }

    if (installed && is_privileged)
    {
        p.system_mode = true;
        p.socket_path = "/run/socketley/socketley.sock";
        p.state_dir   = "/var/lib/socketley/runtimes";
        p.config_path = "/etc/socketley/config.lua";

        std::error_code ec;
        fs::create_directories("/run/socketley", ec);
        fs::create_directories(p.state_dir, ec);
    }
    else
    {
        p.system_mode = false;
        p.socket_path = "/tmp/socketley.sock";

        fs::path home = get_home();
        if (!home.empty())
        {
            p.state_dir   = home / ".local" / "share" / "socketley" / "runtimes";
            p.config_path = home / ".config" / "socketley" / "config.lua";
        }
        else
        {
            p.state_dir   = "/tmp/socketley-runtimes";
            p.config_path.clear();
        }

        std::error_code ec;
        fs::create_directories(p.state_dir, ec);

        // If system daemon is running and socket is accessible, prefer it
        if (installed && access("/run/socketley/socketley.sock", R_OK | W_OK) == 0)
        {
            p.socket_path = "/run/socketley/socketley.sock";
            p.system_mode = true;
        }
    }

    return p;
}
