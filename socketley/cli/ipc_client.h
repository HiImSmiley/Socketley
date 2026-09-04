#pragma once
#include <string>
#include <string_view>

// Returns the daemon's exit code (0 = success, 1 = bad input, 2 = fatal), or
// one of these two, which are not the same failure and were reported as one.
inline constexpr int ipc_unreachable = -1;   // nothing answered the socket
inline constexpr int ipc_no_answer   = -2;   // something did, and then went quiet
int ipc_send(std::string_view command, std::string& data);

// The sentence an ipc_send failure deserves, in one function because eighteen
// call sites said "failed to connect to daemon" for a daemon that had
// connected and was still working.  Prints to stderr and returns 2.
int ipc_report_failure(int rc);
