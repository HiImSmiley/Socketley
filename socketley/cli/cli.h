#pragma once

#ifndef SOCKETLEY_VERSION
#define SOCKETLEY_VERSION "1.0.7"
#endif

int cli_dispatch(int argc, char** argv);
int cli_forward(int argc, char** argv);
int cli_send(int argc, char** argv);
int cli_stdin_send(int argc, char** argv);
int cli_edit(int argc, char** argv);
int cli_runtime_action(int argc, char** argv);
int cli_interactive(int argc, char** argv);
int cli_daemon(int argc, char** argv);
int cli_config(int argc, char** argv);
int cli_cluster(int argc, char** argv);
