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

    // EACCES/EPERM.  Opposite of `absent`: starting a daemon here would fail on
    // the bind, or take the socket from the daemon that owns it.
    forbidden,

    // A build older than `ping`, identified by its two-byte reply to an unknown
    // command.  Treated as a daemon so an upgrade does not lock the operator out.
    predates_ping
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

// One round trip: connect, ask `ping`, read the reply.  OUT is filled only on
// `daemon`; the default timeout matches what ipc_client applies to any command.
daemon_identity daemon_probe(const char*   socket_path,
                             daemon_ident* out        = nullptr,
                             int           timeout_ms = 5000);

// This process's executable, stat'd through the magic link rather than the path
// so it still resolves after the inode has lost its name.  False if /proc fails.
bool self_exe_identity(std::string& raw_path, uint64_t& dev, uint64_t& ino);

// Strip " (deleted)" from a /proc exe link and say whether it was there; the
// kernel appends it when the binary is replaced, so it is a signal, not noise.
bool split_deleted_suffix(std::string& path);

// Attach this process to a running Socketley daemon.
// Shows up in `socketley ps/ls`; `socketley stop <name>` sends SIGTERM.
// On success calls atexit(daemon_detach) automatically. Returns true on success.
bool daemon_attach(std::string_view name, std::string_view type, uint16_t port);

// Remove this process from the daemon registry.
// Safe to call multiple times; no-op if not attached or already detached.
void daemon_detach();

} // namespace socketley
