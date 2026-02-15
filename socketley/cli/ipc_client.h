#pragma once
#include <string>
#include <string_view>

// Returns daemon's exit code (0 = success, 1 = bad input, 2 = fatal)
// Returns -1 if connection to daemon failed
int ipc_send(std::string_view command, std::string& data);
