#include "cli.h"
#include <iostream>
#include <fstream>
#include <string_view>
#include <string>
#include <sstream>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <csignal>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <poll.h>
#include <sys/wait.h>

#include "command_hashing.h"
#include "ipc_client.h"
#include "../daemon/daemon_handler.h"
#include "../runtime/proxy/proxy_worker.h"
#include "../shared/daemon_client.h"
#include "../shared/paths.h"

// Is the daemon executing a file that has since been replaced at the path it
// was started from — that is, has this tree been rebuilt under a running
// daemon.
//
// Decided on the inode, because the version cannot decide it.  Nothing in
// premake5.lua defines SOCKETLEY_VERSION, so it is a single literal in cli.h
// and every build of a release carries it; two builds a minute apart compare
// equal, and the whole case worth reporting is a same-version rebuild.
//
// Reported only when both sides name the same path.  Comparing inodes across
// different paths would say "your daemon is stale" to anyone running the CLI
// from a copy while a daemon runs the original — which is how every agent in
// this tree works, and it is the misidentification c1875e3 was written to
// undo.  A message printed when nothing is wrong is how a message printed when
// something is wrong gets ignored.
static bool daemon_exe_was_replaced(const socketley::daemon_ident& id)
{
    // A daemon that did not report an executable has not reported a different
    // one.  Builds exist that answer `ping` with a version and a pid and stop
    // there, and terse is not the same as mismatched.
    if (!id.has_exe)
        return false;

    std::string self;
    uint64_t    dev = 0, ino = 0;
    if (!socketley::self_exe_identity(self, dev, ino))
        return false;
    socketley::split_deleted_suffix(self);

    if (self != id.exe_path)
        return false;

    // Either signal is conclusive once the paths agree.  They are not the same
    // signal: a filesystem is free to hand the replacement the inode number the
    // unlinked file just gave up, and then only the marker shows it.
    return id.exe_deleted || dev != id.exe_dev || ino != id.exe_ino;
}

// Is *anything* listening on the socket path.
//
// Deliberately still the weak question, and used in exactly one place: the poll
// that waits for the daemon this process has just forked.  By the time it runs,
// the strong question below has already established that the path was free, so
// whatever is answering now appeared in the last few milliseconds and is the
// child.  Asking the strong question here instead would be a regression, not an
// improvement: a daemon binds and listens before it restores its runtimes and
// only enters its event loop afterwards, so a daemon coming back with a dozen
// persisted runtimes accepts connections for as long as the restore takes and
// answers none of them.  The poll's budget is one second.
static bool socket_answers()
{
    // SOCK_CLOEXEC on all of the CLI's sockets, for the same reason as the
    // daemon's: ensure_daemon() below forks and execs a daemon, and the only
    // descriptors that exec is meant to receive are the three it opens
    // /dev/null onto.  Nothing here is ever handed to a child on purpose.
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return false;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, daemon_handler::socket_path.c_str(), sizeof(addr.sun_path) - 1);

    bool ok = connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0;
    close(fd);
    return ok;
}

// Make sure a daemon is serving the socket, and — before anything is written to
// it — that the thing serving it is a daemon.
//
// The two failures are not symmetric, which is what decides where the strict
// check goes.  A false negative forks a spare daemon; that daemon finds the
// socket taken and exits 0, so it costs one process.  A false positive means
// the whole session is delivered to a stranger: `create server db -p 9000` is
// written out in full to whatever accepted the connection, and a peer that
// writes back two zero bytes — a well-formed reply frame of exit 0 with no text
// — makes the CLI report success in a shell whose convention is that silence
// means it worked.  Nothing was created; the operator is told it was.
//
// So this refuses rather than forking when the path is occupied by something it
// cannot identify.  Forking there would be worse than either: the new daemon
// unlinks the path and binds over it, which is how you take a socket away from
// whatever legitimately owns it.
static bool ensure_daemon(char* /*argv0*/)
{
    switch (socketley::daemon_probe(daemon_handler::socket_path.c_str()))
    {
        case socketley::daemon_identity::daemon:
        // A daemon too old to answer `ping` is still a daemon, and locking an
        // operator out of runtimes they are already running — with a message
        // accusing their own daemon of being an impostor — would be a worse
        // outcome than the defect this probe exists to close.  `socketley
        // version` is where the mismatch is reported.
        case socketley::daemon_identity::predates_ping:
            return true;

        case socketley::daemon_identity::foreign:
            std::cerr << "the socket at " << daemon_handler::socket_path
                      << " is held by something that is not a socketley daemon\n"
                      << "  Nothing was sent to it. Point SOCKETLEY_SOCKET "
                         "elsewhere, or free the path.\n";
            return false;

        case socketley::daemon_identity::mute:
            std::cerr << "the daemon socket at " << daemon_handler::socket_path
                      << " accepted a connection and did not answer\n"
                      << "  Nothing was sent to it. Either a daemon there is "
                         "wedged, or the path belongs to something else.\n";
            return false;

        // Not forked over.  The socket belongs to another user, and starting a
        // daemon here would at best fail on the bind and at worst unlink a
        // running daemon's socket out from under it.
        case socketley::daemon_identity::forbidden:
            std::cerr << "not permitted to open the daemon socket at "
                      << daemon_handler::socket_path << "\n"
                      << "  It belongs to another user. The daemon's socket is "
                         "reachable by its owner\n"
                         "  and, for the packaged daemon, by the socketley "
                         "group:\n"
                         "    sudo usermod -aG socketley $USER    (then log in "
                         "again)\n"
                         "  For a daemon of your own, point SOCKETLEY_SOCKET at "
                         "a path you own.\n";
            return false;

        case socketley::daemon_identity::absent:
            break;   // the path is free — including when a stale file is on it
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        std::cerr << "failed to start daemon\n";
        return false;
    }

    if (pid == 0)
    {
        // Child: become daemon
        setsid();

        // Redirect stdin/stdout/stderr to /dev/null
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0)
        {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > 2)
                close(devnull);
        }

        // Re-exec as daemon (use /proc/self/exe for reliable path)
        char self_exe[4096];
        ssize_t len = readlink("/proc/self/exe", self_exe, sizeof(self_exe) - 1);
        if (len > 0)
        {
            self_exe[len] = '\0';
            execl(self_exe, self_exe, "daemon", nullptr);
        }
        _exit(1);
    }

    // Parent: wait for daemon to be ready
    for (int i = 0; i < 50; ++i)   // 50 * 20ms = 1s max
    {
        usleep(20000);
        if (socket_answers())
            return true;
    }

    std::cerr << "failed to start daemon\n";
    return false;
}

int cli_dispatch(int argc, char** argv)
{
    if (argc < 2)
    {
        std::cerr << "no command given\n";
        return 1;
    }

    // Resolve socket path for IPC (system vs dev mode)
    auto paths = socketley_paths::resolve();
    daemon_handler::socket_path = paths.socket_path.string();

    std::string_view cmd = argv[1];

    switch (fnv1a(cmd.data()))
    {
        case fnv1a("--version"):
        case fnv1a("-v"):
        case fnv1a("version"):
        {
            std::cout << SOCKETLEY_VERSION << "\n";

            // And, on stderr, what is actually serving the socket — because a
            // second build of this tree is the one case where the version the
            // operator just printed is not the version answering their
            // commands.  A daemon holds its runtimes across an upgrade, so
            // "I rebuilt and my new flag is rejected" has exactly this cause
            // and nothing anywhere else reported it.
            //
            // stderr, not stdout, so `$(socketley version)` is byte-identical
            // in every case.  A short deadline because there is nothing to wait
            // for: this command has never needed a daemon and must not start
            // hanging on one that is busy or on a path someone else owns.
            socketley::daemon_ident id;
            switch (socketley::daemon_probe(daemon_handler::socket_path.c_str(),
                                            &id, 300))
            {
                case socketley::daemon_identity::daemon:
                    // The version first: when it differs it is the more
                    // specific thing to say, and the executable differs too.
                    if (id.version != SOCKETLEY_VERSION)
                        std::cerr << "the daemon serving " << daemon_handler::socket_path
                                  << " is version " << id.version
                                  << "; restart it to run " << SOCKETLEY_VERSION << "\n";
                    else if (daemon_exe_was_replaced(id))
                        std::cerr << "the daemon serving " << daemon_handler::socket_path
                                  << " is running an earlier build of " << id.exe_path
                                  << "; restart it to run this one\n";
                    break;

                case socketley::daemon_identity::predates_ping:
                    std::cerr << "the daemon serving " << daemon_handler::socket_path
                              << " is from a build older than " << SOCKETLEY_VERSION
                              << "; restart it to run " << SOCKETLEY_VERSION << "\n";
                    break;

                case socketley::daemon_identity::foreign:
                    std::cerr << "the socket at " << daemon_handler::socket_path
                              << " is held by something that is not a socketley daemon\n";
                    break;

                // Worth a word even here, where no command is being sent: the
                // version this printed is not the version that will answer,
                // because nothing this uid sends will be answered at all.
                case socketley::daemon_identity::forbidden:
                    std::cerr << "the socket at " << daemon_handler::socket_path
                              << " belongs to another user and this one may not "
                                 "open it\n";
                    break;

                // Nothing there, or there and busy.  Neither is worth a word:
                // the first is the ordinary case, and the second is what a
                // daemon restoring its runtimes looks like from outside.
                case socketley::daemon_identity::absent:
                case socketley::daemon_identity::mute:
                    break;
            }
            return 0;
        }

        // Not a user-facing command, and deliberately absent from the help: the
        // daemon execs itself with this after putting the control socket on
        // descriptor 3.  Run by hand it finds nothing there and exits.
        case fnv1a("proxy-worker"):
            return proxy_worker_main(3);

        case fnv1a("daemon"):
        {
            // Check for configuration flags (--name, --cluster)
            bool has_config = false;
            for (int i = 2; i < argc; ++i)
            {
                std::string_view arg = argv[i];
                if (arg == "--name" || arg == "-n" || arg == "--cluster")
                {
                    has_config = true;
                    break;
                }
            }

            if (!has_config)
                return cli_daemon(argc, argv);

            // Configuration mode talks to a daemon that is already up, and the
            // ring flags configure one that is being started.  They cannot both
            // be on the same command line: a ring's flags are fixed when the
            // ring is created, so --sqpoll here would be read, sent nowhere and
            // do nothing — which is exactly the silence this pair of flags was
            // given a parser to stop.
            for (int i = 2; i < argc; ++i)
            {
                std::string_view arg = argv[i];
                if (arg == "--sqpoll" || arg == "--no-sqpoll" || arg == "--cpus")
                {
                    std::cerr << arg << " cannot be combined with --name or --cluster\n"
                              << "  Those name a daemon that is already running; this "
                                 "one shapes the ring of a daemon being started.\n"
                              << "  Start the daemon with it: socketley daemon " << arg << "\n";
                    return 1;
                }
            }

            // Configuration mode — ensure daemon is running, then send IPC
            // The message belongs to ensure_daemon: "failed to start daemon" is
            // one of three reasons it can say no, and the other two are about a
            // path it refused to write to rather than a daemon it could not
            // start.  Reprinting it here would put the wrong sentence under the
            // right one.
            if (!ensure_daemon(argv[0]))
                return 2;

            for (int i = 2; i < argc; ++i)
            {
                std::string_view arg = argv[i];
                if ((arg == "--name" || arg == "-n") && i + 1 < argc)
                {
                    std::string ipc_cmd = std::string("daemon-name ") + argv[++i];
                    std::string data;
                    int rc = ipc_send(ipc_cmd, data);
                    if (rc < 0) { std::cerr << "failed to connect to daemon\n"; return 2; }
                    if (rc != 0) { if (!data.empty()) std::cerr << data; return rc; }
                }
                else if (arg == "--cluster" && i + 1 < argc)
                {
                    std::string ipc_cmd = std::string("daemon-cluster ") + argv[++i];
                    std::string data;
                    int rc = ipc_send(ipc_cmd, data);
                    if (rc < 0) { std::cerr << "failed to connect to daemon\n"; return 2; }
                    if (rc != 0) { if (!data.empty()) std::cerr << data; return rc; }
                }
            }

            return 0;
        }

        case fnv1a("--lua"):
            return cli_config(argc, argv);

        case fnv1a("help"):
        case fnv1a("--help"):
        case fnv1a("-h"):
        {
            // The binary's own copy first, then the installed one.
            //
            // This was the other way round, and on any machine with socketley
            // installed that made `./bin/Release/socketley --help` print
            // /usr/share's help — a different version's, describing flags this
            // binary may not have and omitting the ones it just grew.  Measured
            // here: the installed copy was eight months older than the tree.
            //
            // The order below cannot misfire in the other direction.  An
            // installed binary lives at /usr/bin/socketley, so three
            // parent_path() calls land on "/" and the candidate is
            // "/man/socketley-help.sh", which does not exist — it falls through
            // to /usr/share exactly as before.  Only a binary that really does
            // sit under a tree carrying man/ takes the first branch, and that
            // binary's help is the one that matches it.
            //
            // Everything else in this project decides dev-versus-system in
            // paths.cpp; this lookup predates that and answered a different
            // question. Nearest-wins is the same answer paths.cpp gives.
            std::string help_script;
            {
                char self_exe[4096];
                ssize_t len = readlink("/proc/self/exe", self_exe, sizeof(self_exe) - 1);
                if (len > 0)
                {
                    self_exe[len] = '\0';
                    auto bin_dir = std::filesystem::path(self_exe).parent_path().parent_path().parent_path();
                    help_script = (bin_dir / "man" / "socketley-help.sh").string();
                }
            }
            if (help_script.empty() || access(help_script.c_str(), R_OK) != 0)
                help_script = "/usr/share/socketley/socketley-help.sh";
            if (access(help_script.c_str(), R_OK) != 0)
            {
                std::cerr << "help script not found\n";
                return 1;
            }
            {
                pid_t pid = fork();
                if (pid < 0) return -1;
                if (pid == 0) { execlp("bash", "bash", help_script.c_str(), nullptr); _exit(127); }

                int status = 0;
                if (waitpid(pid, &status, 0) < 0) return -1;
                return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            }
        }

        default:
            break;
    }

    // All other commands need the daemon — auto-start if not running
    if (!ensure_daemon(argv[0]))
        return 2;

    switch (fnv1a(cmd.data()))
    {
        case fnv1a("start"):
        {
            for (int i = 2; i < argc; ++i)
                if (std::string_view(argv[i]) == "-i")
                    return cli_interactive(argc, argv);
            return cli_forward(argc, argv);
        }
        // ─── restart = stop, then start.  Nothing else. ─────────────────────
        //
        // The comment here used to say "preserving all flags" and the loop below
        // forwarded every argument to `start`.  `start` reads one flag, `-i`, and
        // hands the rest to resolve_names(), which skips anything beginning with
        // '-' and treats what follows as a RUNTIME NAME.  So a flag's value was
        // looked up as a runtime — and when it happened to name one, that runtime
        // was started:
        //
        //     $ socketley ls --name --status
        //     r1      Up 15 seconds
        //     victim  Stopped
        //     $ socketley restart r1 --some-flag victim
        //     $ socketley ls --name --status
        //     r1      Up 0 seconds
        //     victim  Up 0 seconds        <- nothing asked for this
        //
        // Exit 0 throughout, and the unknown flag accepted in silence.
        //
        // Configuration is `edit`'s job, and `import`'s.  A restart that pretended
        // to take flags could only ever be the half of that which `start` happens
        // to understand, so it takes the name and -i and refuses the rest by name.
        case fnv1a("restart"):
        {
            if (argc < 3)
            {
                std::cerr << "usage: restart <name> [-i]\n";
                return 1;
            }

            for (int i = 3; i < argc; ++i)
            {
                std::string_view arg = argv[i];
                if (arg == "-i")
                    continue;
                std::cerr << "restart does not take " << arg << "\n"
                          << "  It stops the runtime and starts it again with the "
                             "configuration it already has.\n"
                          << "  To change that configuration: socketley edit "
                          << argv[2] << " " << arg << " ...\n";
                return 1;
            }

            // The stop's answer is read now.  It was discarded, so `restart
            // nosuchruntime` ran a start against a name the stop had already
            // reported as missing — two refusals, one of them printed.
            std::string stop_cmd = std::string("stop ") + argv[2];
            std::string stop_data;
            int rc = ipc_send(stop_cmd, stop_data);
            if (rc < 0)
            {
                std::cerr << "failed to connect to daemon\n";
                return 2;
            }
            if (rc != 0)
            {
                if (!stop_data.empty()) std::cerr << stop_data;
                return rc;
            }

            std::string start_cmd = "start";
            for (int i = 2; i < argc; ++i)
            {
                start_cmd += ' ';
                start_cmd += argv[i];
            }
            std::string start_data;
            rc = ipc_send(start_cmd, start_data);
            if (rc < 0)
            {
                std::cerr << "failed to connect to daemon\n";
                return 2;
            }
            if (!start_data.empty())
                std::cout << start_data;
            return rc;
        }
        case fnv1a("ls"):
        case fnv1a("ps"):
        case fnv1a("create"):
        case fnv1a("attach"):
        case fnv1a("add"):
        case fnv1a("stop"):
        case fnv1a("remove"):
        case fnv1a("stats"):
        case fnv1a("reload"):
        case fnv1a("reload-lua"):
        case fnv1a("show"):
        case fnv1a("owner"):
        case fnv1a("dashboard"):
        // Typed by hand it answers "which daemon is on this socket", which is
        // the question the probe above asks on every command and the one an
        // operator asks when a socket is behaving oddly.  Without this case it
        // fell through to the runtime-action and piped-stdin arms and was
        // answered "empty message", which is a reply to a different question.
        case fnv1a("ping"):
            return cli_forward(argc, argv);

        case fnv1a("cluster"):
            return cli_cluster(argc, argv);

        case fnv1a("send"):
            return cli_send(argc, argv);

        case fnv1a("edit"):
            return cli_edit(argc, argv);

        // Not a plain forward.  The document `show` prints is pretty-printed,
        // and the IPC framing is one command per line, so forwarding the
        // argument verbatim would send the daemon everything up to the first
        // newline and nothing after it.  cli_import compacts first, the same
        // way the interactive editor does before it calls the same daemon
        // command.
        case fnv1a("import"):
            return cli_import(argc, argv);

        default:
            // Check for runtime action: socketley <name> <action> [args]
            if (argc >= 3)
                return cli_runtime_action(argc, argv);

            // Check for stdin shortcut: socketley <name> with piped input
            if (!isatty(STDIN_FILENO))
                return cli_stdin_send(argc, argv);

            std::cerr << "unknown command\n";
            return 1;
    }
}

int cli_forward(int argc, char** argv)
{
    std::string command;
    for (int i = 1; i < argc; ++i)
    {
        if (i > 1) command += ' ';
        command += argv[i];
    }

    std::string data;
    int exit_code = ipc_send(command, data);

    if (exit_code < 0)
    {
        std::cerr << "failed to connect to daemon\n";
        return 2;
    }

    if (!data.empty())
        std::cout << data;

    return exit_code;
}

int cli_send(int argc, char** argv)
{
    if (argc < 3)
    {
        std::cerr << "usage: send <name> [message]\n";
        std::cerr << "       echo 'msg' | socketley send <name>\n";
        return 1;
    }

    std::string name = argv[2];
    std::string message;

    if (argc >= 4)
    {
        for (int i = 3; i < argc; ++i)
        {
            if (i > 3) message += ' ';
            message += argv[i];
        }
    }
    else if (!isatty(STDIN_FILENO))
    {
        std::ostringstream ss;
        ss << std::cin.rdbuf();
        message = ss.str();

        // Only the trailing newline goes, and only the trailing one.
        //
        // `echo hi | socketley send x` should not deliver "hi\n", which is what
        // this strip is for.  Newlines INSIDE the message are the message: they
        // used to end the command and turn everything after them into commands
        // of their own (see ipc_framing.h), and ipc_send frames the command now
        // rather than the CLI mangling it.
        while (!message.empty() && (message.back() == '\n' || message.back() == '\r'))
            message.pop_back();
    }
    else
    {
        std::cerr << "usage: send <name> <message>\n";
        std::cerr << "       echo 'msg' | socketley send <name>\n";
        return 1;
    }

    if (message.empty())
    {
        std::cerr << "empty message\n";
        return 1;
    }

    std::string command = "send " + name + " " + message;

    std::string data;
    int exit_code = ipc_send(command, data);

    if (exit_code < 0)
    {
        std::cerr << "failed to connect to daemon\n";
        return 2;
    }

    if (!data.empty())
        std::cout << data;

    return exit_code;
}

int cli_stdin_send(int /*argc*/, char** argv)
{
    std::string name = argv[1];

    std::ostringstream ss;
    ss << std::cin.rdbuf();
    std::string message = ss.str();

    // The trailing newline only — see cli_send() above.
    while (!message.empty() && (message.back() == '\n' || message.back() == '\r'))
        message.pop_back();

    // Nothing arrived on stdin, and this is the arm an unrecognised word falls
    // into whenever stdin is not a terminal — which is every script, pipeline
    // and CI step there is.  `socketley gibtsnicht` on a keyboard says "unknown
    // command"; the same typo in a script used to say "empty message", naming
    // neither the word it did not understand nor the reading it had chosen.
    //
    // From here the two cases are genuinely indistinguishable: this process
    // cannot tell a misspelled command from a real runtime that was piped
    // nothing, because both are one word with no data behind it.  So it names
    // both instead of guessing, and leads with the likelier one — a runtime
    // being sent zero bytes on purpose is rare, and a typo is not.
    if (message.empty())
    {
        std::cerr << "unknown command: " << name << "\n"
                  << "  If " << name << " is a runtime you meant to send to, "
                     "nothing arrived on standard input:\n"
                  << "    echo 'data' | socketley " << name << "\n";
        return 1;
    }

    std::string command = "send " + name + " " + message;
    std::string data;
    int exit_code = ipc_send(command, data);

    if (exit_code < 0)
    {
        std::cerr << "failed to connect to daemon\n";
        return 2;
    }

    if (!data.empty())
        std::cout << data;

    return exit_code;
}

// Strip the whitespace `show` pretty-prints with, leaving string literals alone.
//
// ─── LOOKING BACK ONE CHARACTER IS NOT ENOUGH ───────────────────────────────
//
// The test was `c == '"' && pretty[i-1] != '\\'` — a quote is a delimiter
// unless the character before it is a backslash.  That is right for `\"` and
// wrong for `\\"`, where the backslash is itself escaped and the quote really
// does close the string.  A value ending in a backslash is all it takes:
//
//     "log_file": "C:\\",
//
// From that quote onwards in_string stayed true for the rest of the document,
// so every newline was preserved — and IPC frames one command per line, so the
// daemon received the first fragment as the whole `import` and the remaining
// lines as commands of their own.  The fragment is truncated JSON, which
// parse_json_string accepted, so the round trip `show | import` silently
// dropped every field after the backslash and reported success.  Measured: two
// fields lost, exit 0 on both sides.
//
// The state is carried forward now instead of being reconstructed by looking
// back: inside a string, a backslash makes the next character literal whatever
// it is, and that is the whole rule.
static std::string compact_json(const std::string& pretty)
{
    std::string result;
    result.reserve(pretty.size());
    bool in_string = false;
    bool escaped   = false;

    for (char c : pretty)
    {
        if (in_string)
        {
            result += c;
            if (escaped)        escaped = false;      // consumed, whatever it was
            else if (c == '\\') escaped = true;
            else if (c == '"')  in_string = false;
            continue;
        }

        if (c == '"')
        {
            in_string = true;
            result += c;
            continue;
        }

        if (c != '\n' && c != '\r' && c != '\t' && c != ' ')
            result += c;
    }
    return result;
}

// import <name> <json>
//
// The other half of `show`.  The man page has documented the pair as a round
// trip since the daemon grew cmd_import, but the CLI never had a case for the
// word, so `import` fell through to cli_runtime_action and was sent as the name
// of a runtime to act on — "runtime not found: import", exit 1.  The daemon
// side was never the problem and is exercised daily: interactive `edit` dumps,
// opens $EDITOR and sends the result through this same IPC command.
//
// Two things have to happen here that cli_forward would not do.
//
// The document has to be compacted.  `show` pretty-prints, IPC frames one
// command per line, and cli_forward would hand ipc_send a string whose first
// newline ends the command — the daemon would parse `import name {` and answer
// "invalid JSON".  compact_json strips whitespace outside string literals,
// which is exactly what the editor path already does before sending.
//
// And stdin has to be accepted.  The documented spelling puts the whole
// document in one argv entry, which is fine for the configs socketley writes
// but is the same shape as every command-substitution size limit: `show`
// output grows with backends, upstreams and mesh paths, and a document that
// outgrows ARG_MAX fails with E2BIG from the shell, before this binary runs at
// all.  `socketley show name | socketley import name` has no such ceiling, and
// it is the form that composes.  cli_send already reads a message from stdin
// when the argument is absent, so this is the house pattern rather than a new
// one.
int cli_import(int argc, char** argv)
{
    if (argc < 3)
    {
        std::cerr << "usage: import <name> <json>\n";
        std::cerr << "       socketley show <name> | socketley import <name>\n";
        return 1;
    }

    std::string name = argv[2];
    std::string json;

    if (argc >= 4)
    {
        // Quoted, the document is argv[3] entire, newlines and all.  Unquoted,
        // the shell has already split it on whitespace; joining with a single
        // space puts it back together well enough for the compaction below,
        // which is about to drop that whitespace anyway.
        for (int i = 3; i < argc; ++i)
        {
            if (i > 3) json += ' ';
            json += argv[i];
        }
    }
    else if (!isatty(STDIN_FILENO))
    {
        std::ostringstream ss;
        ss << std::cin.rdbuf();
        json = ss.str();
    }
    else
    {
        std::cerr << "usage: import <name> <json>\n";
        std::cerr << "       socketley show <name> | socketley import <name>\n";
        return 1;
    }

    std::string compact = compact_json(json);
    if (compact.empty())
    {
        std::cerr << "empty configuration\n";
        return 1;
    }

    std::string command = "import " + name + " " + compact;

    std::string data;
    int exit_code = ipc_send(command, data);

    if (exit_code < 0)
    {
        std::cerr << "failed to connect to daemon\n";
        return 2;
    }

    if (!data.empty())
        std::cout << data;

    return exit_code;
}

static int open_editor(const std::string& path)
{
    const char* editor = std::getenv("VISUAL");
    if (!editor || !editor[0])
        editor = std::getenv("EDITOR");
    if (!editor || !editor[0])
        editor = "vim";

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) { execlp(editor, editor, path.c_str(), nullptr); _exit(127); }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int cli_edit(int argc, char** argv)
{
    if (argc < 3)
    {
        std::cerr << "usage: edit <name> [flags]\n";
        std::cerr << "       edit <name> [-r|--reload]   # interactive editor\n";
        return 1;
    }

    std::string name = argv[2];

    // Detect interactive mode: only -r/--reload flags (or no flags at all)
    bool reload_after = false;
    bool interactive = true;
    for (int i = 3; i < argc; ++i)
    {
        std::string_view arg = argv[i];
        if (arg == "-r" || arg == "--reload")
            reload_after = true;
        else
        {
            interactive = false;
            break;
        }
    }

    // Flag-based edit: forward to daemon as before
    if (!interactive)
        return cli_forward(argc, argv);

    // Interactive mode: dump → editor → import

    // 1. Get current config as pretty JSON
    std::string dump_data;
    int rc = ipc_send("dump " + name, dump_data);
    if (rc < 0)
    {
        std::cerr << "failed to connect to daemon\n";
        return 2;
    }
    if (rc != 0)
    {
        if (!dump_data.empty())
            std::cerr << dump_data;
        return rc;
    }

    // 2. Write to tmpfile
    char tmpl[] = "/tmp/socketley-edit-XXXXXX";
    int tmpfd = mkstemp(tmpl);
    if (tmpfd < 0)
    {
        std::cerr << "failed to create temporary file\n";
        return 2;
    }

    std::string tmp_file = std::string(tmpl) + ".json";
    close(tmpfd);
    if (rename(tmpl, tmp_file.c_str()) < 0)
    {
        std::cerr << "failed to rename temporary file\n";
        unlink(tmpl);
        return 2;
    }

    {
        std::ofstream f(tmp_file, std::ios::trunc);
        if (!f.is_open())
        {
            std::cerr << "failed to write temporary file\n";
            unlink(tmpl);
            return 2;
        }
        f << dump_data;
    }

    // 3. Open editor
    int editor_rc = open_editor(tmp_file);
    if (editor_rc != 0)
    {
        std::cerr << "editor exited with error\n";
        unlink(tmp_file.c_str());
        return 1;
    }

    // 4. Read modified file
    std::string modified;
    {
        std::ifstream f(tmp_file);
        if (!f.is_open())
        {
            std::cerr << "failed to read temporary file\n";
            unlink(tmp_file.c_str());
            return 2;
        }
        std::ostringstream ss;
        ss << f.rdbuf();
        modified = ss.str();
    }

    unlink(tmp_file.c_str());

    // 5. Check if unchanged
    if (modified == dump_data)
        return 0;

    // 6. Compact and send import
    std::string json = compact_json(modified);
    std::string import_cmd = "import " + name + " " + json;

    std::string import_data;
    rc = ipc_send(import_cmd, import_data);
    if (rc < 0)
    {
        std::cerr << "failed to connect to daemon\n";
        return 2;
    }
    if (rc != 0)
    {
        if (!import_data.empty())
            std::cerr << import_data;
        return rc;
    }

    // 7. Auto-reload if requested
    if (reload_after)
    {
        std::string reload_data;
        rc = ipc_send("reload-lua " + name, reload_data);
        if (rc < 0)
        {
            std::cerr << "failed to connect to daemon\n";
            return 2;
        }
        if (rc != 0 && !reload_data.empty())
            std::cerr << reload_data;
        return rc;
    }

    return 0;
}

static volatile sig_atomic_t g_interactive_quit = 0;

static void interactive_sigint(int)
{
    g_interactive_quit = 1;
}

int cli_interactive(int argc, char** argv)
{
    // Build command: "start <name> -i"
    std::string command;
    for (int i = 1; i < argc; ++i)
    {
        if (i > 1) command += ' ';
        command += argv[i];
    }

    // Connect to daemon
    int ipc_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (ipc_fd < 0)
    {
        std::cerr << "failed to connect to daemon\n";
        return 2;
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, daemon_handler::socket_path.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(ipc_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        close(ipc_fd);
        std::cerr << "failed to connect to daemon\n";
        return 2;
    }

    // Send the start command
    std::string msg = command + "\n";
    if (write(ipc_fd, msg.data(), msg.size()) < 0)
    {
        close(ipc_fd);
        std::cerr << "failed to send command\n";
        return 2;
    }

    // Read initial NUL-terminated response: first byte = exit code, then data until \0
    char buf[4096];
    ssize_t n = read(ipc_fd, buf, sizeof(buf));
    if (n < 1)
    {
        close(ipc_fd);
        std::cerr << "failed to read response\n";
        return 2;
    }

    int exit_code = static_cast<unsigned char>(buf[0]);

    // Find NUL terminator in response
    std::string data;
    auto* nul = static_cast<char*>(std::memchr(buf + 1, '\0', n - 1));
    if (nul)
    {
        data.append(buf + 1, nul - buf - 1);
    }
    else
    {
        data.append(buf + 1, n - 1);
        while (true)
        {
            n = read(ipc_fd, buf, sizeof(buf));
            if (n <= 0) break;
            nul = static_cast<char*>(std::memchr(buf, '\0', n));
            if (nul) { data.append(buf, nul - buf); break; }
            data.append(buf, n);
        }
    }

    if (exit_code != 0)
    {
        if (!data.empty())
            std::cerr << data;
        close(ipc_fd);
        return exit_code;
    }

    // Enter interactive mode — install SIGINT handler
    g_interactive_quit = 0;
    struct sigaction sa{};
    sa.sa_handler = interactive_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);

    struct pollfd fds[2];
    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;
    fds[1].fd = ipc_fd;
    fds[1].events = POLLIN;

    while (!g_interactive_quit)
    {
        int ret = poll(fds, 2, 200);
        if (ret < 0)
        {
            if (errno == EINTR)
                continue;
            break;
        }
        if (ret == 0)
            continue;

        // Data from daemon (messages/responses)
        if (fds[1].revents & POLLIN)
        {
            n = read(ipc_fd, buf, sizeof(buf));
            if (n <= 0)
                break;

            // Check for session end marker (\0)
            auto* end = static_cast<char*>(std::memchr(buf, '\0', n));
            if (end)
            {
                if (end > buf)
                    if (::write(STDOUT_FILENO, buf, end - buf) < 0) {}
                break;
            }
            if (::write(STDOUT_FILENO, buf, n) < 0) {}
        }

        if (fds[1].revents & (POLLERR | POLLHUP))
            break;

        // Input from user
        if (fds[0].revents & POLLIN)
        {
            n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n <= 0)
                break;
            if (::write(ipc_fd, buf, n) < 0) {}
        }
    }

    // Restore default SIGINT handler
    sa.sa_handler = SIG_DFL;
    sigaction(SIGINT, &sa, nullptr);

    close(ipc_fd);
    return 0;
}

int cli_runtime_action(int argc, char** argv)
{
    // Format: socketley <name> <action> [args...]
    // Forward as: action <name> <action> [args...]
    std::string command = "action";
    for (int i = 1; i < argc; ++i)
    {
        command += ' ';
        command += argv[i];
    }

    std::string data;
    int exit_code = ipc_send(command, data);

    if (exit_code < 0)
    {
        std::cerr << "failed to connect to daemon\n";
        return 2;
    }

    if (!data.empty())
        std::cout << data;

    return exit_code;
}
