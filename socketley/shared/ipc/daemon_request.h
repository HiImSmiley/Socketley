#pragma once
#include <string>
#include <string_view>

// One command to the daemon at a socket and its answer, which the CLI and the bash builtin both send.
namespace socketley {

// The daemon's exit code (0 = success, 1 = bad input, 2 = fatal), or one of these, which are not the same failure and
// were reported as one.
inline constexpr int ipc_unreachable = -1;   // nothing answered the socket
inline constexpr int ipc_no_answer   = -2;   // something did, and then went quiet
inline constexpr int ipc_cut_short   = -3;   // it began an answer and closed before the end of it
inline constexpr int ipc_stranger    = -4;   // a process of another user holds the socket, so nothing was sent

int daemon_request(const std::string& socket_path, std::string_view command, std::string& data);

// The two halves of it, for a caller that keeps the connection for its next command: a trusted connection's descriptor
// or a code above, and the exchange, which `sent` tells whether any of the command reached the socket.
int daemon_connect(const std::string& socket_path);
int daemon_exchange(int fd, std::string_view command, std::string& data, bool& sent);

// The sentence a daemon_request failure deserves, on stderr, and 2.
int daemon_request_failure(const std::string& socket_path, int rc);

} // namespace socketley
