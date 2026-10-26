#pragma once
#include <string>
#include <string_view>

// Returns the daemon's exit code (0 = success, 1 = bad input, 2 = fatal), or
// one of these, which are not the same failure and were reported as one.
inline constexpr int ipc_unreachable = -1;   // nothing answered the socket
inline constexpr int ipc_no_answer   = -2;   // something did, and then went quiet
inline constexpr int ipc_cut_short   = -3;   // it began an answer and closed before the end of it
int ipc_send(std::string_view command, std::string& data);

// The sentence an ipc_send failure deserves, in one function because eighteen
// call sites said "failed to connect to daemon" for a daemon that had
// connected and was still working.  Prints to stderr and returns 2.
int ipc_report_failure(int rc);
