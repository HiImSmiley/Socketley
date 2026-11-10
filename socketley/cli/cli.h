#pragma once

#include <string>
#include <string_view>

#include "../shared/util/version.h"

int cli_dispatch(int argc, char** argv);
// Whether a daemon of this user's serves the socket, started where none does unless `start` is false, and said on
// stderr where it is refused: nothing is sent to whatever else holds the path.
bool ensure_daemon(bool start = true);
int cli_forward(int argc, char** argv);
int cli_send(int argc, char** argv);
int cli_idp_user(int argc, char** argv);
int cli_db_backup(int argc, char** argv);
// `socketley mqtt-pub`, `mqtt-sub` and `mqtt-passwd`, in cli_mqtt.cpp.
int cli_mqtt_pub(int argc, char** argv);
int cli_mail_send(int argc, char** argv);
int cli_mail(int argc, char** argv);
int cli_mqtt_sub(int argc, char** argv);
int cli_mqtt_passwd(int argc, char** argv);
int cli_stdin_send(char** argv);
int cli_edit(int argc, char** argv);
int cli_import(int argc, char** argv);
int cli_runtime_action(int argc, char** argv);
// `socketley <runtime> <verb> ...`, in cli_verbs.cpp: the verb read against the runtime's type.
int cli_runtime_verb(int argc, char** argv);
bool cli_is_type_verb(std::string_view type, std::string_view verb);
// One line of a secret, read without echo on a terminal and as it comes from a pipe.
bool cli_read_secret(const char* prompt, std::string& out);
// Whether `socketley <command> <word>` is for the runtime named as the command: its type's verb, or every runtime's.
bool cli_names_runtime(std::string_view command, std::string_view word);
int cli_interactive(int argc, char** argv);

// The same session from a command this process built rather than from argv,
// because `restart` sends a `start` whose words are not the ones it was given.
int cli_interactive_command(const std::string& command);
int cli_daemon(int argc, char** argv);
int cli_config(int argc, char** argv);
// `socketley export <dir>`, the daemon's setup written as the Lua `socketley --lua` reads, in cli_config.cpp.
int cli_export(int argc, char** argv);
// `socketley export --full <file>` and `socketley restore <file>`, the setup and its data in one archive, in cli_backup.cpp.
int cli_export_full(int argc, char** argv);
int cli_restore(int argc, char** argv);
int cli_cluster(int argc, char** argv);
// `socketley acme issue`, in cli_acme.cpp.
int acme_main(int argc, char** argv);
// `socketley login` and `logout`, in cli_login.cpp.
int cli_login(int argc, char** argv);
int cli_logout(int argc, char** argv);
// The access token of the person signed in at the idp `issuer`, refreshed when it has run out; false with `err`
// telling them to sign in.
bool cli_access_token(const std::string& issuer, std::string& token, std::string& err);
// A device sign-in for one command: its access token, kept nowhere and with no refresh token; the exit code.
int cli_sign_in_once(const std::string& issuer, std::string& token);
// `socketley ssh-cert` and `idp-ssh`, in cli_ssh.cpp.
int cli_ssh_cert(int argc, char** argv);
int cli_idp_ssh(int argc, char** argv);
// `socketley tunnel connect|ssh` here, `tunnel <edge> ...` to the daemon, in cli_tunnel.cpp.
int cli_tunnel(int argc, char** argv);
// `socketley update`: the newest release from GitHub, checked and installed, and the daemon restarted, in
// cli_update.cpp.
int cli_update(int argc, char** argv);
int git_sync_main(int argc, char** argv);

// A path a flag names, made absolute against the caller's directory, because the daemon resolves it against its own.
std::string cli_caller_path(std::string_view flag, std::string_view value);
