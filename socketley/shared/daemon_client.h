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

    // A socketley daemon from a build before `ping` existed.  Its reply to an
    // unknown command is a two-byte frame — exit code 1, empty body — which no
    // arbitrary program produces by accident, and which does not depend on the
    // wording of any message.  Treated as a daemon so that upgrading the binary
    // under a running daemon does not lock the operator out of their own
    // runtimes; the difference is reported by `socketley version`.
    predates_ping
};

// One round trip against SOCKET_PATH: connect, ask `ping`, read the reply.
//
// VERSION_OUT, when given, receives the daemon's version string on `daemon` and
// is left untouched otherwise.  TIMEOUT_MS bounds the wait for the reply; the
// default matches the read timeout ipc_client.cpp already applies to every real
// command, so a daemon too busy to answer this was already too busy to serve
// the command that follows it.
daemon_identity daemon_probe(const char* socket_path,
                             std::string*  version_out = nullptr,
                             int           timeout_ms  = 5000);

// Attach this process to a running Socketley daemon.
// Shows up in `socketley ps/ls`; `socketley stop <name>` sends SIGTERM.
// On success calls atexit(daemon_detach) automatically. Returns true on success.
bool daemon_attach(std::string_view name, std::string_view type, uint16_t port);

// Remove this process from the daemon registry.
// Safe to call multiple times; no-op if not attached or already detached.
void daemon_detach();

} // namespace socketley
