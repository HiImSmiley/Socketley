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

// The socket path as a single directory-name component.
//
// Readable rather than hashed, deliberately.  "Where does my state live" is a
// question an operator asks once, at the worst possible moment, and
// `runtimes.tmp_mine.sock` answers it from an `ls` while `runtimes.3f2a1b9c`
// sends them looking for the function that produced it.
//
// It fits, always: sockaddr_un::sun_path is 108 bytes, so a socket path this
// daemon can actually bind is at most 107 characters, and 107 plus the
// "runtimes." prefix is well inside NAME_MAX.  A hash would buy a shorter name
// and nothing else.
//
// Everything outside [A-Za-z0-9._-] becomes '_' — the leading slash included,
// which is stripped rather than turned into one so that the common case reads
// as `runtimes.tmp_mine.sock` and not `runtimes._tmp_mine.sock`.  The result is
// one component appended to a directory name, never joined as a path, so it
// cannot climb: a value of ".." yields the directory `runtimes...`, which is an
// ordinary name.
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

    // SOCKETLEY_SOCKET overrides the socket path.  It is a development and test
    // affordance: it exists so that several daemons can coexist inside one
    // filesystem namespace, which is only ever the situation on a workstation or
    // in a test run.
    //
    // It is not how clustering works, whatever the previous wording here said.
    // Cluster members do not find each other through socket paths at all — each
    // daemon publishes dir/<name>.json into a shared directory and peers reach
    // one another over the network addresses they advertise there.  A real node
    // is a container or a host, so it has a namespace to itself and runs on the
    // default path; the systemd unit says as much, one daemon per host with a
    // RuntimeDirectory and no override in sight.
    //
    // Which is why the default path is an identity rather than a mere default.
    // A process that binds it *is* the daemon for that namespace, and anything
    // that starts a daemon there — a test, most of all — is claiming the
    // identity the deployed daemon runs under.
    const char* env_socket = std::getenv("SOCKETLEY_SOCKET");

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

    // ─── THE STATE DIRECTORY IS KEYED TO THE SOCKET, BUT ONLY OFF THE DEFAULT ──
    //
    // Until this existed, state_dir came from HOME alone while the socket was
    // separately overridable, so the one arrangement SOCKETLEY_SOCKET exists to
    // make possible — several daemons in one filesystem namespace — put all of
    // them in one state directory.  Measured, two daemons under one HOME on
    // separate sockets, the second started with no knowledge of the first:
    //
    //     A: create server collide_srv -p 19771     A holds :19771
    //     B: daemon                                 B restores collide_srv,
    //                                               binds :19771 as well, and
    //                                               reports it Up
    //     B: remove collide_srv                     A's state file is deleted
    //
    // Two daemons serving one port and each able to delete the other's runtimes,
    // silently.  test_cluster.sh worked around this in 101f7b6 by giving its
    // nodes separate HOMEs rather than separate sockets; the cause was never
    // fixed.
    //
    // THE RULE: a daemon on the default socket path keeps exactly the state
    // directory it has always had.  A daemon on an overridden path gets a
    // sibling directory named after that path.
    //
    //     SOCKETLEY_SOCKET unset, or set to the default
    //         ~/.local/share/socketley/runtimes      (unchanged, byte for byte)
    //     SOCKETLEY_SOCKET=/tmp/mine.sock
    //         ~/.local/share/socketley/runtimes.tmp_mine.sock
    //
    // WHICH WAY THIS ERRS, AND WHY.  Keying on the socket unconditionally has a
    // failure of its own: a daemon started with a socket path it did not have
    // last time finds no runtimes.  On a dev box that is right — it is a
    // different daemon and it should own nothing.  In production it would be a
    // disaster, which is why the default path is exempt: a deployed node has a
    // namespace to itself and runs on the default path with this variable
    // unset, so the state directory it uses is a fixed point that no upgrade
    // and no missing environment variable can move.  The only way to reach a
    // different directory is to set SOCKETLEY_SOCKET to a non-default value,
    // which is the explicit statement "I am a second daemon".
    //
    // And when that statement is made in error, the two errors are not
    // symmetric.  An unrecognised socket path yields an empty state directory:
    // nothing is destroyed, the old directory is still on disk, the daemon logs
    // which directory it is using, and unsetting the variable brings everything
    // back.  A shared state directory yields the transcript above, and there is
    // no undo for a state file another daemon deleted.  Empty and reversible
    // beats populated with somebody else's runtimes.
    //
    // The comparison is against the path resolved above rather than against a
    // literal, so SOCKETLEY_SOCKET set explicitly to the default — which
    // scripts do — is the default and keeps the default directory.  Both sides
    // are normalised first so that /tmp/./socketley.sock is not a third daemon.
    // Recorded before the override, because from here on socket_path may be
    // somebody else's and this is the one the deployed daemon binds.
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
            fs::create_directories(p.state_dir, ec);
        }
    }

    return p;
}
