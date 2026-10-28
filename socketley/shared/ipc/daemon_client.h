#pragma once
#include <cstdint>
#include <string>
#include <string_view>

namespace socketley {

// connect() answers "is anything listening here", not "is that the daemon", so
// the probe asks: `ping` is answered with this prefix and by nothing else.
inline constexpr std::string_view daemon_ident_prefix = "socketley-daemon ";

enum class daemon_identity
{
    // connect() refused: the path is free, so this is the case that auto-starts.
    absent,

    // Answered `ping` and named itself; the only result a command may be sent on.
    daemon,

    // Bound and answered with something no socketley daemon produces.
    foreign,

    // Bound, no answer inside the deadline -- which is also what a daemon still
    // restoring runtimes at boot looks like, so it is not `foreign`.
    mute,

    // EACCES/EPERM, the opposite of `absent`: starting a daemon here would
    // fail on the bind or take the socket from its owner.
    forbidden,

    // A build older than `ping`, treated as a daemon so an upgrade does not
    // lock the operator out.
    predates_ping,

    // Held by a process of another user -- neither this one, root, nor the
    // packaged daemon's account -- so nothing is sent: /tmp is shared, and
    // whoever binds the path first would otherwise read every command.
    stranger
};

// What a daemon says about itself when it is asked.
struct daemon_ident
{
    // The version literal the daemon was compiled with.
    std::string version;

    // Which executable, by inode: the version alone cannot answer "is this my
    // build", because every build of a release carries the same literal.
    std::string exe_path;
    bool        exe_deleted = false;
    uint64_t    exe_dev = 0;
    uint64_t    exe_ino = 0;

    // Whether the reply carried the fields above at all; every reader must gate
    // on this and stay silent when it is false.
    bool has_exe = false;
};

// One round trip -- connect, ask `ping`, read the reply -- filling OUT only on
// `daemon`.
daemon_identity daemon_probe(const char*   socket_path,
                             daemon_ident* out        = nullptr,
                             int           timeout_ms = 5000);

// Whether the process at the other end of a connected unix socket is this user, root, or the packaged daemon's account.
bool socket_peer_trusted(int fd);

// This process's executable, stat'd through the magic link so it still
// resolves after the inode has lost its name.
bool self_exe_identity(std::string& raw_path, uint64_t& dev, uint64_t& ino);

// Strip " (deleted)" from a /proc exe link and say whether it was there; the
// kernel appends it when the binary is replaced, so it is a signal, not noise.
bool split_deleted_suffix(std::string& path);

// Attach this process to a running daemon so it appears in `socketley ps`,
// registering daemon_detach with atexit on success.
bool daemon_attach(std::string_view name, std::string_view type, uint16_t port);

// Remove this process from the daemon registry, safe to call more than once.
void daemon_detach();

} // namespace socketley
