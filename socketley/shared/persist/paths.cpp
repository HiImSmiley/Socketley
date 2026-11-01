#include "paths.h"
#include "private_dir.h"
#include "../util/settings.h"
#include <unistd.h>
#include <pwd.h>
#include <cstdlib>
#include <string>

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

// The socket path as one readable directory-name component; sun_path bounds it
// to 107 characters, and the result is appended, never joined, so it cannot climb.
static std::string socket_key(const fs::path& sock)
{
    std::string s = sock.string();
    size_t start = 0;
    while (start < s.size() && s[start] == '/')
        ++start;

    std::string key;
    key.reserve(s.size() - start);
    for (size_t i = start; i < s.size(); ++i)
    {
        char c = s[i];
        bool plain = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                     (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        key += plain ? c : '_';
    }

    if (key.empty())
        key = "unnamed";
    return key;
}

socketley_paths socketley_paths::resolve()
{
    socketley_paths p;
    bool in_tmp = false;

    // A development affordance for several daemons in one namespace, not how
    // clustering works.
    const char* env_socket = socketley::settings::text("SOCKETLEY_SOCKET");

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
        p.types_dir   = "/etc/socketley/types";
        p.daemons_dir = "/run/socketley/daemons";

        std::error_code ec;
        fs::create_directories("/run/socketley", ec);
    }
    else
    {
        p.system_mode = false;
        p.socket_path = "/tmp/socketley.sock";

        fs::path home = get_home();
        in_tmp = home.empty();
        if (!home.empty())
        {
            p.state_dir   = home / ".local" / "share" / "socketley" / "runtimes";
            p.config_path = home / ".config" / "socketley" / "config.lua";
            p.types_dir   = home / ".config" / "socketley" / "types";
            p.daemons_dir = home / ".local" / "share" / "socketley" / "daemons";
        }
        else
        {
            p.state_dir   = "/tmp/socketley-runtimes-" + std::to_string(uid);
            p.config_path.clear();
        }

        // If system daemon is running and socket is accessible, prefer it
        if (installed && access("/run/socketley/socketley.sock", R_OK | W_OK) == 0)
        {
            p.socket_path = "/run/socketley/socketley.sock";
            p.system_mode = true;
        }
    }

    // The state directory is keyed to the socket only when the socket is
    // overridden: several daemons under one HOME otherwise shared one state
    // directory, restored each other's runtimes and deleted each other's files.
    p.default_socket_path = p.socket_path;

    if (env_socket && env_socket[0])
    {
        std::error_code ec;
        fs::path want = fs::weakly_canonical(fs::path(env_socket), ec);
        if (ec) want = fs::path(env_socket);
        ec.clear();
        fs::path have = fs::weakly_canonical(p.socket_path, ec);
        if (ec) have = p.socket_path;

        p.socket_path = env_socket;

        if (want != have && !p.state_dir.empty())
        {
            p.legacy_state_dir = p.state_dir;
            p.state_dir += "." + socket_key(want);
        }
    }

    // Made once it is decided, so a daemon keyed to its socket leaves no empty default directory behind it.
    if (!in_tmp && !p.state_dir.empty())
    {
        std::error_code ec;
        fs::create_directories(p.state_dir, ec);
    }

    if (in_tmp && !socketley::private_dir(p.state_dir.string(), true))
        p.state_dir_refusal = "the state directory " + p.state_dir.string() +
                              " is not this user's alone; remove it or set HOME";
    if (in_tmp && !p.legacy_state_dir.empty() && !socketley::private_dir(p.legacy_state_dir.string(), false))
        p.legacy_state_dir.clear();

    return p;
}
