#pragma once
#include "../shared/ipc/daemon_request.h"

#include <string>
#include <string_view>

using socketley::ipc_unreachable;
using socketley::ipc_no_answer;
using socketley::ipc_cut_short;
using socketley::ipc_stranger;

// daemon_request() to the socket the CLI resolved.
int ipc_send(std::string_view command, std::string& data);

// The sentence an ipc_send failure deserves, in one function because eighteen
// call sites said "failed to connect to daemon" for a daemon that had
// connected and was still working.  Prints to stderr and returns 2.
int ipc_report_failure(int rc);
