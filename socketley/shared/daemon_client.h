#pragma once
#include <cstdint>
#include <string>
#include <string_view>

namespace socketley {

// ─── IDENTIFYING THE DAEMON ─────────────────────────────────────────────────
//
// connect() answers "is anything listening on this path".  It was being read as
// the answer to "is the thing listening on this path the daemon I am about to
// hand a command to", and those are different questions with the same return
// value.  Any AF_UNIX listener on the socket path collects the answer yes, and
// the CLI then writes the operator's command into it.
//
// So the probe asks.  `ping` is answered by a daemon with the line below, and
// by nothing else, because nothing else knows to.
inline constexpr std::string_view daemon_ident_prefix = "socketley-daemon ";

enum class daemon_identity
{
    // connect() was refused: no socket file, or a stale one left by a daemon
    // that was killed.  Both mean the path is free — a stale file is unlinked
    // by the next daemon's bind, so this is the case that must still auto-start.
    absent,

    // A daemon answered `ping` and named itself.  The only result that permits
    // a command to be sent.
    daemon,

    // Something is bound to the path, accepted the connection, and answered
    // with something no socketley daemon produces.  The command is not sent.
    foreign,

    // Something is bound to the path and did not answer inside the deadline.
    // Not called foreign: a daemon still restoring runtimes at boot has bound
    // and listened but is not yet in its event loop, and looks exactly like
    // this from outside.  Still not sent to — but it is a different sentence.
    mute,

    // The socket is there and this uid may not open it: connect() came back
    // EACCES or EPERM.
    //
    // Distinct from `absent` because the two call for opposite responses.
    // `absent` means the path is free and the CLI should start a daemon on it;
    // this means a daemon that is not ours is serving it, and starting one
    // would either fail on the bind or — where the path happens to be
    // unlinkable — take the socket away from the daemon that owns it.  Since
    // the IPC socket became owner-and-group-only this is the shape an ordinary
    // mistake takes (a second user on one box, an operator not in the
    // `socketley` group), so it gets a sentence that names the fix.
    forbidden,

    // A socketley daemon from a build before `ping` existed.  Its reply to an
    // unknown command is a two-byte frame — exit code 1, empty body — which no
    // arbitrary program produces by accident, and which does not depend on the
    // wording of any message.  Treated as a daemon so that upgrading the binary
    // under a running daemon does not lock the operator out of their own
    // runtimes; the difference is reported by `socketley version`.
    predates_ping
};

// What a daemon says about itself when it is asked.
struct daemon_ident
{
    // The version literal the daemon was compiled with.
    std::string version;

    // Which executable the daemon is running, exactly: the path from
    // readlink("/proc/self/exe") with any " (deleted)" marker moved into the
    // flag, and the device and inode that link resolves to.
    //
    // The version alone cannot answer "is this daemon my build".  Nothing in
    // SOCKETLEY_VERSION is one literal in shared/version.h, and
    // every build of a release carries it — two builds a minute apart compare
    // equal.  The inode does not: a rebuild produces a different file, and the
    // daemon goes on executing the one it started with.
    std::string exe_path;
    bool        exe_deleted = false;
    uint64_t    exe_dev = 0;
    uint64_t    exe_ino = 0;

    // Whether the reply carried the executable fields at all.  A daemon built
    // after `ping` existed but before it named its executable answers with a
    // version and a pid and stops there; that daemon is a real thing that can
    // be running, and being terse is not the same as being a different build.
    // Every reader of the fields above must gate on this and stay silent when
    // it is false.
    bool has_exe = false;
};

// One round trip against SOCKET_PATH: connect, ask `ping`, read the reply.
//
// OUT, when given, is filled in on `daemon` and left untouched otherwise.
// TIMEOUT_MS bounds the wait for the reply; the default matches the read
// timeout ipc_client.cpp already applies to every real command, so a daemon too
// busy to answer this was already too busy to serve the command that follows it.
daemon_identity daemon_probe(const char*   socket_path,
                             daemon_ident* out        = nullptr,
                             int           timeout_ms = 5000);

// This process's own executable: readlink("/proc/self/exe") verbatim, marker
// and all, plus the device and inode that link resolves to.
//
// stat() goes through the magic link rather than through the path, because that
// is what resolves to the inode this process is actually executing — and it
// keeps working after that inode has lost its name, which is the case worth
// detecting.  False when /proc cannot be read, in which case no comparison is
// possible and none may be reported.
bool self_exe_identity(std::string& raw_path, uint64_t& dev, uint64_t& ino);

// Take " (deleted)" off the end of a /proc exe link, returning whether it was
// there.  The kernel appends it once the file a running process was started
// from is unlinked, which is precisely what replacing a binary does, so the
// marker is a signal and must not be left in a path being compared.
bool split_deleted_suffix(std::string& path);

// Attach this process to a running Socketley daemon.
// Shows up in `socketley ps/ls`; `socketley stop <name>` sends SIGTERM.
// On success calls atexit(daemon_detach) automatically. Returns true on success.
bool daemon_attach(std::string_view name, std::string_view type, uint16_t port);

// Remove this process from the daemon registry.
// Safe to call multiple times; no-op if not attached or already detached.
void daemon_detach();

} // namespace socketley
