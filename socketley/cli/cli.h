#pragma once

#include <string>

#include "../shared/version.h"

int cli_dispatch(int argc, char** argv);
int cli_forward(int argc, char** argv);
int cli_send(int argc, char** argv);
int cli_stdin_send(int argc, char** argv);
int cli_edit(int argc, char** argv);
int cli_import(int argc, char** argv);
int cli_runtime_action(int argc, char** argv);
int cli_interactive(int argc, char** argv);

// The same session from a command this process built rather than from argv,
// because `restart` sends a `start` whose words are not the ones it was given.
int cli_interactive_command(const std::string& command);
int cli_daemon(int argc, char** argv);
int cli_config(int argc, char** argv);
int cli_cluster(int argc, char** argv);
