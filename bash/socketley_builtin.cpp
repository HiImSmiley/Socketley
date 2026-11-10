// socketley as a bash builtin: `enable -f /usr/lib/socketley/socketley-bash.so socketley` in a script makes
// `socketley send <name> <message>` a request to the daemon from the shell's own process, with no program started for
// it, and runs the socketley program for every other command as before.
#include "shared/ipc/daemon_request.h"
#include "shared/persist/paths.h"

#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

// What bash hands a builtin and finds in a loadable one, as its builtins.h declares them since bash 2.
extern "C" {
struct word_desc { char* word; int flags; };
struct word_list { word_list* next; word_desc* word; };
struct builtin_entry
{
    const char* name;
    int (*function)(word_list*);
    int flags;
    const char* const* long_doc;
    const char* short_doc;
    char* handle;
};

// bash's own: the path a command name runs, and the environment it gives a program.
char* find_user_command(const char*);
void maybe_make_export_env(void);
extern char** export_env;

// What bash looks up by name in the object it loads, so these two are the object's only exported symbols.
__attribute__((visibility("default"))) int socketley_builtin(word_list* list);
__attribute__((visibility("default"))) extern builtin_entry socketley_struct;
}

namespace {

constexpr int builtin_enabled = 0x01;

// The socketley program, for a command this builtin does not answer itself, with the script's environment.
int run_program(const std::vector<std::string>& args)
{
    char* path = find_user_command("socketley");
    if (!path)
    {
        std::fprintf(stderr, "socketley: no socketley program on PATH to run `%s` with\n",
                     args.empty() ? "" : args[0].c_str());
        return 127;
    }
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>("socketley"));
    for (const auto& a : args)
        argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    maybe_make_export_env();
    std::fflush(stdout);
    std::fflush(stderr);
    const pid_t pid = fork();
    if (pid < 0)
    {
        std::fprintf(stderr, "socketley: could not start %s: %s\n", path, std::strerror(errno));
        std::free(path);
        return 2;
    }
    if (pid == 0)
    {
        for (int sig : {SIGINT, SIGQUIT, SIGTERM, SIGTSTP, SIGTTIN, SIGTTOU, SIGCHLD, SIGPIPE})
            std::signal(sig, SIG_DFL);
        execve(path, argv.data(), export_env);
        std::fprintf(stderr, "socketley: could not run %s: %s\n", path, std::strerror(errno));
        _exit(127);
    }
    std::free(path);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR)
            return 2;
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 2;
}

// `send <name> <words>` as cli_send() sends it; nothing when the program has to answer it instead.
bool send_command(const std::vector<std::string>& args, std::string& command)
{
    // A flag only a mail message takes makes it the mail runtime's, which the program writes.
    static constexpr std::string_view mail_flags[] = {"--to",   "-t",     "--cc",   "--bcc",  "--from",   "--reply-to",
                                                      "--subject", "--text", "--header", "--html", "--attach",
                                                      "--raw", "--template", "--set", "--inline", "--ad", "--no-check",
                                                      "--test", "--test-to", "--rate-limit", "--lua"};
    if (args.size() < 3 || args[0] != "send"
        || std::any_of(std::begin(mail_flags), std::end(mail_flags), [&](std::string_view f) { return f == args[2]; }))
        return false;
    size_t from = 2;
    if (args[2] == "--")
    {
        if (args.size() < 4)
            return false;
        from = 3;
    }
    command = "send " + args[1] + " ";
    for (size_t i = from; i < args.size(); ++i)
    {
        if (i > from)
            command += ' ';
        command += args[i];
    }
    return true;
}

} // namespace

extern "C" int socketley_builtin(word_list* list)
{
    std::vector<std::string> args;
    for (; list; list = list->next)
        args.emplace_back(list->word && list->word->word ? list->word->word : "");

    std::string command;
    if (!send_command(args, command))
        return run_program(args);
    if (command.size() == 5 + args[1].size() + 1)
    {
        std::fprintf(stderr, "empty message\n");
        return 1;
    }

    // From the environment, which bash keeps to the script's exports, as a program it started would read it; resolved
    // again only when what it is resolved from changed, since resolve() asks the filesystem and the user database.
    static std::string home, sock, path;
    static bool resolved = false;
    const char* h = std::getenv("HOME");
    const char* k = std::getenv("SOCKETLEY_SOCKET");
    if (!resolved || home != (h ? h : "") || sock != (k ? k : ""))
    {
        home = h ? h : "";
        sock = k ? k : "";
        path = socketley_paths::resolve().socket_path.string();
        resolved = true;
    }
    // A longer path than a unix address holds would be cut, and the cut one may be another daemon's socket.
    if (path.size() >= sizeof(sockaddr_un{}.sun_path))
    {
        std::printf("the daemon's socket path is longer than the %zu bytes a unix socket address holds: %s\n",
                    sizeof(sockaddr_un{}.sun_path) - 1, path.c_str());
        return 1;
    }

    // One connection for the shell's commands, as the daemon reads a connection's commands in turn, made again when the
    // path changes or the daemon closed it: then nothing of the command went out, and it is sent once more.
    static int fd = -1;
    static std::string fd_path;
    if (fd >= 0 && fd_path != path)
    {
        close(fd);
        fd = -1;
    }
    std::string data;
    int rc = 0;
    for (int attempt = 0; attempt < 2; ++attempt)
    {
        const bool fresh = fd < 0;
        if (fresh)
        {
            fd = socketley::daemon_connect(path);
            if (fd < 0)
            {
                rc = fd;
                fd = -1;
                return socketley::daemon_request_failure(path, rc);
            }
            fd_path = path;
        }
        bool sent = false;
        rc = socketley::daemon_exchange(fd, command, data, sent);
        if (rc >= 0)
            break;
        close(fd);
        fd = -1;
        if (sent || fresh)
            return socketley::daemon_request_failure(path, rc);
    }
    if (rc < 0)
        return socketley::daemon_request_failure(path, rc);
    if (!data.empty())
    {
        std::fwrite(data.data(), 1, data.size(), stdout);
        std::fflush(stdout);
    }
    return rc;
}

namespace {
const char* const long_doc[] = {
    "Send a line to a socketley runtime from this shell, without starting a program.",
    "",
    "`socketley send <name> <message>` is a request to the daemon made from the shell itself;",
    "every other socketley command runs the socketley program on PATH, as it would without the builtin.",
    nullptr,
};
}

builtin_entry socketley_struct = {
    "socketley", socketley_builtin, builtin_enabled, long_doc, "socketley send <name> <message> | <any socketley command>",
    nullptr,
};
