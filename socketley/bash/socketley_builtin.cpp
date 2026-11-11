// socketley as a bash builtin: `enable -f /usr/lib/socketley/socketley-bash.so socketley` in a script makes
// `socketley send <name> <message>` a request to the daemon from the shell's own process, with no program started for
// it, and runs the socketley program for every other command as before.
#include "shared/ipc/daemon_request.h"
#include "shared/persist/paths.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
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
    // bash's SIGCHLD handler reaps every child it hears of, so it must not hear of this one before waitpid does.
    sigset_t chld, old;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    sigprocmask(SIG_BLOCK, &chld, &old);
    const pid_t pid = fork();
    if (pid < 0)
    {
        std::fprintf(stderr, "socketley: could not start %s: %s\n", path, std::strerror(errno));
        std::free(path);
        sigprocmask(SIG_SETMASK, &old, nullptr);
        return 2;
    }
    if (pid == 0)
    {
        // The stop signals stay as the shell has them: an interactive one ignores them, and would wait on a stopped child.
        for (int sig : {SIGINT, SIGQUIT, SIGTERM, SIGCHLD, SIGPIPE})
            std::signal(sig, SIG_DFL);
        sigprocmask(SIG_SETMASK, &old, nullptr);
        execve(path, argv.data(), export_env);
        std::fprintf(stderr, "socketley: could not run %s: %s\n", path, std::strerror(errno));
        _exit(127);
    }
    std::free(path);
    int status = 0;
    int waited;
    while ((waited = waitpid(pid, &status, 0)) < 0 && errno == EINTR)
    {
    }
    sigprocmask(SIG_SETMASK, &old, nullptr);
    if (waited < 0)
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
    if (args.size() < 3 || args[0] != "send" || args[1] == "--help" || args[1] == "-h"
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

// The descriptor kept for the shell's commands, and what it was: a script may close it or put a file of its own on it
// with exec, and a subshell inherits it with the connection its parent reads answers from.
struct kept_conn
{
    int fd{-1};
    pid_t owner{0};
    dev_t dev{0};
    ino_t ino{0};
    std::string path;

    // Whether `fd` is still this process's connection; when it is not, it is forgotten without a close, which would
    // close the script's file or the parent's connection.
    bool still_ours()
    {
        if (fd < 0)
            return false;
        struct stat st{};
        if (owner != getpid() || ::fstat(fd, &st) != 0 || !S_ISSOCK(st.st_mode) || st.st_dev != dev || st.st_ino != ino)
        {
            // A subshell's copy is its own descriptor to close; the parent's connection stays open in the parent.
            if (owner != getpid() && ::fstat(fd, &st) == 0 && S_ISSOCK(st.st_mode) && st.st_dev == dev && st.st_ino == ino)
                close(fd);
            fd = -1;
            return false;
        }
        return true;
    }

    // `c`, moved above the descriptors a script names with exec, which the checks above still guard.
    void take(int c, const std::string& p)
    {
        const int high = ::fcntl(c, F_DUPFD_CLOEXEC, 100);
        if (high >= 0)
        {
            close(c);
            c = high;
        }
        struct stat st{};
        ::fstat(c, &st);
        fd = c;
        owner = getpid();
        dev = st.st_dev;
        ino = st.st_ino;
        path = p;
    }

    void drop()
    {
        if (fd >= 0)
            close(fd);
        fd = -1;
    }
};

int send_from_shell(const std::vector<std::string>& args);

} // namespace

extern "C" int socketley_builtin(word_list* list)
{
    // An exception through bash's C would end the shell, and a builtin's failure is a status.
    try
    {
        std::vector<std::string> args;
        for (; list; list = list->next)
            args.emplace_back(list->word && list->word->word ? list->word->word : "");
        return send_from_shell(args);
    }
    catch (const std::exception& e)
    {
        std::fprintf(stderr, "socketley: %s\n", e.what());
        return 2;
    }
    catch (...)
    {
        return 2;
    }
}

namespace {

int send_from_shell(const std::vector<std::string>& args)
{
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
    static kept_conn conn;
    if (conn.still_ours() && conn.path != path)
        conn.drop();
    // Checked once above, and a failed exchange below drops it, so a descriptor not -1 here is this process's own.
    std::string data;
    int rc = 0;
    for (int attempt = 0; attempt < 2; ++attempt)
    {
        const bool fresh = conn.fd < 0;
        if (fresh)
        {
            const int c = socketley::daemon_connect(path);
            // The program starts a daemon that is not running and says why one cannot be reached, so it answers then,
            // with the path found again.
            if (c < 0)
            {
                resolved = false;
                return run_program(args);
            }
            conn.take(c, path);
        }
        bool sent = false;
        rc = socketley::daemon_exchange(conn.fd, command, data, sent);
        if (rc >= 0)
            break;
        conn.drop();
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
