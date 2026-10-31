#include "cli.h"
#include <iostream>
#include <fstream>
#include <string_view>
#include <string>
#include <thread>
#include <sstream>
#include <vector>
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
#include "../shared/runtime/command_usage.h"
#include "../daemon/ipc_client.h"
#include "../shared/ipc/ipc_framing.h"
#include "../daemon/daemon_handler.h"
#include "../daemon/runtime_schema.h"
#include "../runtime/worker/worker_main.h"
#include "../shared/ipc/daemon_client.h"
#include "../shared/persist/paths.h"
#include <algorithm>
#include <filesystem>
#include <chrono>

// Has this tree been rebuilt under a running daemon, decided on the inode
// because two builds a minute apart carry the same version, and reported only
// when both sides name the same path.
static bool daemon_exe_was_replaced(const socketley::daemon_ident& id)
{
    // A daemon that did not report an executable has not reported a different
    // one, and terse is not the same as mismatched.
    if (!id.has_exe)
        return false;

    std::string self;
    uint64_t    dev = 0, ino = 0;
    if (!socketley::self_exe_identity(self, dev, ino))
        return false;
    socketley::split_deleted_suffix(self);

    if (self != id.exe_path)
        return false;

    // Either signal is conclusive once the paths agree, and they are not the
    // same signal, because a filesystem may reuse the unlinked file's inode
    // number.
    return id.exe_deleted || dev != id.exe_dev || ino != id.exe_ino;
}

// Deliberately still the weak question, used only in the poll that waits for
// the daemon this process just forked, because a daemon accepts connections
// while it restores its runtimes and answers none of them.
static bool socket_answers()
{
    // SOCK_CLOEXEC on all of the CLI's sockets, because ensure_daemon() forks
    // and execs a daemon that is meant to receive only the three /dev/null
    // descriptors.
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

// Make sure a daemon is serving the socket and that the thing serving it is a
// daemon, refusing rather than forking over an unidentified peer -- a false
// negative costs one spare process and a false positive writes the whole
// session to a stranger.
static bool refused_tab(int argc, char** argv);

bool ensure_daemon(bool start)
{
    switch (socketley::daemon_probe(daemon_handler::socket_path.c_str()))
    {
        case socketley::daemon_identity::daemon:
        // A daemon too old to answer `ping` is still a daemon, and locking an
        // operator out of runtimes they are running would be worse than the
        // defect this probe closes.
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

        // Not forked over, because the socket belongs to another user and
        // starting a daemon here would at worst unlink a running daemon's
        // socket.
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

        case socketley::daemon_identity::stranger:
            std::cerr << "the daemon socket at " << daemon_handler::socket_path
                      << " is held by a process of another user\n"
                      << "  Nothing was sent to it. Point SOCKETLEY_SOCKET at a "
                         "path you own.\n";
            return false;

        case socketley::daemon_identity::absent:
            if (!start)
            {
                ipc_report_failure(ipc_unreachable);
                return false;
            }
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

    // Parent: wait for daemon to be ready, five seconds at most, since a loaded machine or a sanitizer build took past one.
    for (int i = 0; i < 250; ++i)   // 250 * 20ms
    {
        usleep(20000);
        if (socket_answers())
            return true;
    }

    std::cerr << "failed to start daemon\n";
    return false;
}

static int settle_startup(int rc, std::string& data);

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
    // A longer path than a unix address holds would be cut, and the cut one may be another daemon's socket.
    if (daemon_handler::socket_path.size() >= sizeof(sockaddr_un{}.sun_path))
    {
        std::cout << "the daemon's socket path is longer than the " << sizeof(sockaddr_un{}.sun_path) - 1
                  << " bytes a unix socket address holds: " << daemon_handler::socket_path << "\n";
        return 1;
    }

    std::string_view cmd = argv[1];

    switch (fnv1a(cmd.data()))
    {
        // Which daemons are serving, which is a question nothing could answer:
        // SOCKETLEY_SOCKET moves the socket AND the state directory, so a
        // second daemon left no trace anywhere a CLI would look.  Each daemon
        // writes one file naming its socket; the probe below decides whether
        // it is alive, because a daemon killed outright leaves that file.
        case fnv1a("daemons"):
        {
            struct entry { std::string sock; long pid; std::filesystem::path file; };
            std::vector<entry> found;

            std::error_code ec;
            for (const auto& e :
                 std::filesystem::directory_iterator(paths.daemons_dir, ec))
            {
                if (e.path().extension() != ".daemon")
                    continue;
                std::ifstream f(e.path());
                std::string sock;
                if (!std::getline(f, sock) || sock.empty())
                    continue;
                // The whole stem or nothing, the rule parse_whole states:
                // strtol took the digits in front of a typo, and the removal
                // below then rebuilt a name that was another file's.
                const std::string stem = e.path().stem().string();
                char*       end = nullptr;
                const long  pid = std::strtol(stem.c_str(), &end, 10);
                if (end == stem.c_str() || *end != '\0')
                    continue;
                found.push_back({sock, pid, e.path()});
            }

            std::sort(found.begin(), found.end(),
                      [](const entry& a, const entry& b) { return a.sock < b.sock; });

            if (found.empty())
            {
                std::cout << "no daemon has registered under "
                          << paths.daemons_dir.string() << "\n";
                return 0;
            }

            std::cout << "  SOCKET                                   PID      "
                         "STATUS  BINARY\n";

            for (const auto& f : found)
            {
                socketley::daemon_ident id;
                const auto st = socketley::daemon_probe(f.sock.c_str(), &id, 300);

                const char* status = "dead";
                switch (st)
                {
                    case socketley::daemon_identity::daemon:
                    case socketley::daemon_identity::predates_ping: status = "up";      break;
                    case socketley::daemon_identity::foreign:       status = "foreign"; break;
                    case socketley::daemon_identity::absent:        status = "dead";    break;
                    // EACCES is a daemon that is up and will not let this uid
                    // in, which `default:` reported as one that is merely slow;
                    // named rather than defaulted so -Wswitch catches the next
                    // member the enum gains.
                    case socketley::daemon_identity::forbidden:     status = "denied";  break;
                    case socketley::daemon_identity::mute:          status = "busy";    break;
                    case socketley::daemon_identity::stranger:      status = "other";   break;
                }

                // Removed only when both say so, because a daemon still
                // restoring runtimes answers nothing and is not gone.
                if (st == socketley::daemon_identity::absent && f.pid > 0 &&
                    ::kill(static_cast<pid_t>(f.pid), 0) < 0 && errno == ESRCH)
                {
                    std::error_code rec;
                    std::filesystem::remove(f.file, rec);
                }

                // The one this CLI would talk to, because "which daemon am I
                // configuring" is the question underneath the list.
                const bool current = (f.sock == daemon_handler::socket_path);

                std::cout << (current ? "* " : "  ");
                std::cout.width(41); std::cout << std::left << f.sock;
                std::cout.width(9);  std::cout << std::left << f.pid;
                std::cout.width(8);  std::cout << std::left << status;
                std::cout << (id.has_exe && !id.exe_path.empty() ? id.exe_path : "-")
                          << "\n";
            }

            std::cout << "\n* is the daemon this CLI talks to; set SOCKETLEY_SOCKET "
                         "to pick another.\n";
            return 0;
        }

        case fnv1a("--version"):
        case fnv1a("-v"):
        case fnv1a("version"):
        {
            std::cout << SOCKETLEY_VERSION << "\n";

            // What is actually serving the socket, on stderr so `$(socketley
            // version)` is byte-identical, with a short deadline because this
            // command has never needed a daemon.
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

                case socketley::daemon_identity::stranger:
                    std::cerr << "the socket at " << daemon_handler::socket_path
                              << " is held by a process of another user\n";
                    break;

                // Nothing there, or there and busy, neither of which is worth
                // a word: the second is what a daemon restoring its runtimes
                // looks like from outside.
                case socketley::daemon_identity::absent:
                case socketley::daemon_identity::mute:
                    break;
            }
            return 0;
        }

        // Not a user-facing command and deliberately absent from the help,
        // because the daemon execs itself with it after putting the control
        // socket on descriptor 3.
        case fnv1a("proxy-worker"):
            return worker_main(3);

        // A certificate from an ACME CA, run by a worker for --acme and runnable by hand; it needs no daemon.
        case fnv1a("acme"):
            return acme_main(argc, argv);

        // A person signed in at an idp runtime, which may be another machine's; neither needs a daemon.
        case fnv1a("login"):
            return cli_login(argc, argv);
        case fnv1a("logout"):
            return cli_logout(argc, argv);
        case fnv1a("ssh-cert"):
            return cli_ssh_cert(argc, argv);

        // One repository a storage runtime keeps, run by the runtime (git_mirrors.h) and runnable by hand.
        case fnv1a("git-sync"):
            return git_sync_main(argc, argv);

        case fnv1a("daemon"):
        {
            // `stop` before the flag scan, because it is a verb and not a
            // setting: killing the process by hand was the only way to end a
            // daemon, and an operator with several of them had to find the
            // right pid first.
            if (argc > 2 && std::string_view(argv[2]) == "stop")
            {
                std::string data;
                const int rc = ipc_send("daemon-stop", data);
                // Its own sentence for the absent daemon, because "no daemon is
                // serving" is more use here than "failed to connect" -- but not
                // for the busy one, which is serving and was being told it was
                // not there.
                if (rc == ipc_no_answer || rc == ipc_cut_short || rc == ipc_stranger)
                    return ipc_report_failure(rc);
                if (rc < 0)
                {
                    std::cerr << "no daemon is serving "
                              << daemon_handler::socket_path << "\n";
                    return 2;
                }
                if (rc != 0 && !data.empty()) std::cerr << data;
                return rc;
            }

            // A verb like `stop`: the daemon's own figures, which no runtime's
            // `stats` carries.
            if (argc > 2 && std::string_view(argv[2]) == "stats")
            {
                std::string data;
                const int rc = ipc_send("daemon-stats", data);
                if (rc == ipc_no_answer || rc == ipc_cut_short || rc == ipc_stranger)
                    return ipc_report_failure(rc);
                if (rc < 0)
                {
                    std::cerr << "no daemon is serving "
                              << daemon_handler::socket_path << "\n";
                    return 2;
                }
                std::cout << data;
                return rc;
            }

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

            // ─── JUDGED BEFORE A DAEMON EXISTS ──────────────────────────────
            // The whole command line is read here rather than while sending it
            // below, because the send loop is downstream of ensure_daemon: a
            // `--name` with no value matched no `if`, fell through to `return
            // 0`, and left the operator a silent success and a daemon they had
            // not asked to start.
            for (int i = 2; i < argc; ++i)
            {
                const std::string_view arg = argv[i];

                // Configuration mode talks to a daemon that is already up and
                // --cpus configures one being started, so it would be read
                // here, sent nowhere and do nothing.
                if (arg == "--cpus" || arg == "--fast-lo" || arg.starts_with("--raft-"))
                {
                    std::cerr << arg << " cannot be combined with --name or --cluster\n"
                              << "  Those name a daemon that is already running; this "
                                 "one shapes the ring of a daemon being started.\n"
                              << "  Start the daemon with it: socketley daemon " << arg << "\n";
                    return 1;
                }

                if (arg == "--name" || arg == "-n" || arg == "--cluster")
                {
                    // A token that is itself a flag is not the value: it is the
                    // next flag, typed after one whose value was forgotten, and
                    // accepting it renames the daemon to "--cluster".
                    const bool has_value = i + 1 < argc && argv[i + 1][0] != '-';
                    if (!has_value)
                    {
                        const bool dir = arg == "--cluster";
                        std::cerr << arg << " requires a value\n"
                                  << "  socketley daemon " << arg << " "
                                  << (dir ? "<dir>" : "<name>") << "\n"
                                  << (dir ? "  The directory the cluster publishes into; "
                                            "every member names the same one.\n"
                                          : "  The identity this daemon publishes under; "
                                            "`socketley cluster ls` lists the ones taken.\n");
                        return 1;
                    }
                    ++i;
                    continue;
                }

                std::cerr << "unknown daemon flag: " << arg << "\n"
                          << "  With --name or --cluster this configures a daemon that is "
                             "already running, and those two are all it takes.\n"
                          << "  --cpus shapes a daemon being started: socketley daemon "
                             "--cpus <set>, on its own.\n";
                return 1;
            }

            // The message belongs to ensure_daemon, which has three reasons to
            // say no, so reprinting one here would put the wrong sentence
            // under the right one.
            if (!ensure_daemon())
                return 2;

            for (int i = 2; i < argc; ++i)
            {
                std::string_view arg = argv[i];
                if (arg == "--name" || arg == "-n")
                {
                    std::string ipc_cmd = std::string("daemon-name ") + argv[++i];
                    std::string data;
                    int rc = ipc_send(ipc_cmd, data);
                    if (rc < 0) { return ipc_report_failure(rc); }
                    if (rc != 0) { if (!data.empty()) std::cerr << data; return rc; }
                }
                else if (arg == "--cluster")
                {
                    std::string ipc_cmd = std::string("daemon-cluster ") + argv[++i];
                    std::string data;
                    int rc = ipc_send(ipc_cmd, data);
                    if (rc < 0) { return ipc_report_failure(rc); }
                    if (rc != 0) { if (!data.empty()) std::cerr << data; return rc; }
                }
            }

            return 0;
        }

        case fnv1a("--lua"):
            return cli_config(argc, argv);

        case fnv1a("export"):
            return argc >= 3 && std::string_view(argv[2]) == "--full" ? cli_export_full(argc, argv) : cli_export(argc, argv);

        case fnv1a("restore"):
            return cli_restore(argc, argv);

        case fnv1a("help"):
        case fnv1a("--help"):
        case fnv1a("-h"):
        {
            // The binary's own copy first and then the installed one, because
            // the other order made a development build print an installed
            // version's help -- and an installed binary falls through to
            // /usr/share exactly as before.
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
                // Fatal and not bad input: `help` takes no input to get
                // wrong, and a missing script is this installation's fault.
                std::cout << "help script not found\n";
                return 2;
            }
            {
                pid_t pid = fork();
                if (pid < 0)
                {
                    std::cout << "could not run " << help_script << "\n";
                    return 2;
                }
                if (pid == 0) { execlp("bash", "bash", help_script.c_str(), nullptr); _exit(127); }

                int status = 0;
                if (waitpid(pid, &status, 0) < 0)
                {
                    std::cout << "could not wait for " << help_script << "\n";
                    return 2;
                }
                // Mapped and not passed through, because this process exits 0,
                // 1 or 2: with no bash on PATH the child's _exit(127) reached
                // the shell as 127, in silence.
                if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
                    return 0;
                std::cout << "could not run " << help_script << "\n";
                return 2;
            }
        }

        default:
            break;
    }

    // A usage request is answered here and not forwarded, because reaching the
    // daemon for one forks a daemon whose only work is to spell a sentence and
    // then outlives the question.
    if (argc > 2 && !command_usage::for_verb(cmd).empty())
    {
        const std::string_view second(argv[2]);
        if (second == "--help" || second == "-h")
        {
            std::cout << command_usage::line(cmd);
            return 0;
        }
    }

    // A users file is written here and needs no daemon, which reaching for one would have forked and left running.
    if (cmd == "mqtt-passwd")
        return cli_mqtt_passwd(argc, argv);
    // `socketley mqtt passwd <file> <user>`, the topic's own command; any other `mqtt <verb>` is a runtime named mqtt.
    if (cmd == "mqtt" && argc >= 3 && std::string_view(argv[2]) == "passwd")
    {
        std::vector<char*> av = {argv[0], const_cast<char*>("mqtt-passwd")};
        for (int i = 3; i < argc; ++i)
            av.push_back(argv[i]);
        av.push_back(nullptr);
        return cli_mqtt_passwd(static_cast<int>(av.size()) - 1, av.data());
    }

    // All other commands need the daemon — auto-start if not running
    if (!ensure_daemon())
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
        // restart is one command to the daemon, not a stop and a start sent one
        // after the other: the runtime being restarted may be the one the
        // connection travels through -- an entrance proxy, which a dashboard is
        // reached through -- and the stop then arrives while the start never
        // does. Measured: an entrance left stopped and every site behind it
        // with it.
        //
        // Flags are taken again, and go to `edit` rather than to `start`: what
        // they used to do was have start read a flag's VALUE as a runtime name
        // and start whatever that named, which is why they were refused at all.
        case fnv1a("restart"):
        {
            if (argc < 3)
            {
                // From command_usage and not spelled here, because `restart
                // --help` now answers from there and two copies of one
                // sentence drift.
                std::cerr << command_usage::line("restart");
                return 1;
            }

            if (refused_tab(argc, argv))
                return 1;
            bool want_interactive = false;
            std::string edits;
            for (int i = 3; i < argc; ++i)
            {
                if (std::string_view(argv[i]) == "-i")
                    want_interactive = true;
                edits += ' ';
                ipc_frame::append_arg(edits, cli_caller_path(argv[i - 1], argv[i]));
            }

            // One verb either way, so a stopped runtime is started whether or not there was something to change:
            // sending the flags as `edit ... --restart` instead made restart mean two things.  -i travels with them,
            // because the daemon honours it on the connection the command arrives on and so has to be told.
            const std::string cmd = "restart " + std::string(argv[2]) + edits;
            if (want_interactive)
                return cli_interactive_command(cmd);

            std::string data;
            int rc = ipc_send(cmd, data);
            if (rc < 0)
                return ipc_report_failure(rc);
            rc = settle_startup(rc, data);
            if (!data.empty())
                std::cout << data;
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
        case fnv1a("settings"):
        // Typed by hand it answers which daemon is on this socket, which
        // without this case fell through to the piped-stdin arm and was
        // answered "empty message".
        case fnv1a("ping"):
            return cli_forward(argc, argv);

        case fnv1a("cluster"):
            return cli_cluster(argc, argv);

        case fnv1a("send"):
            return cli_send(argc, argv);

        case fnv1a("idp-user"):
            return cli_idp_user(argc, argv);
        case fnv1a("idp-ssh"):
            return cli_idp_ssh(argc, argv);
        case fnv1a("tunnel"):
            // `socketley tunnel invite ...` is a runtime named tunnel; `tunnel <edge> invite` and join, connect,
            // share and ssh stay as they were.
            if (argc >= 3 && cli_names_runtime("tunnel", argv[2]))
                return cli_runtime_verb(argc, argv);
            return cli_tunnel(argc, argv);
        case fnv1a("db-backup"):
            return cli_db_backup(argc, argv);
        case fnv1a("mqtt-pub"):
            return cli_mqtt_pub(argc, argv);
        case fnv1a("mqtt-sub"):
            return cli_mqtt_sub(argc, argv);
        case fnv1a("mail"):
            return cli_mail(argc, argv);
        case fnv1a("mqtt-sessions"):
        case fnv1a("mqtt-kick"):
        case fnv1a("mqtt-retained"):
        case fnv1a("dnssec"):
        case fnv1a("db-query"):
            return cli_forward(argc, argv);
        case fnv1a("metrics"):
            // `socketley metrics query ...` is the runtime named metrics; `metrics <metrics> query` is the older form.
            if (argc >= 3 && cli_names_runtime("metrics", argv[2]))
                return cli_runtime_verb(argc, argv);
            return cli_forward(argc, argv);
        case fnv1a("db-restore"):
        {
            // The backup is read by the daemon, against whose directory a relative path means something else.
            std::string file = argc == 4 ? cli_caller_path("--keys", argv[3]) : std::string();
            if (argc == 4)
                argv[3] = file.data();
            return cli_forward(argc, argv);
        }

        case fnv1a("edit"):
            return cli_edit(argc, argv);

        // Not a plain forward, because `show` pretty-prints and IPC frames one
        // command per line, so cli_import compacts first exactly as the
        // interactive editor does.
        case fnv1a("import"):
            return cli_import(argc, argv);

        default:
            // `socketley <runtime> <verb> ...`, the verb read against the runtime's type.
            if (argc >= 3)
                return cli_runtime_verb(argc, argv);

            // Check for stdin shortcut: socketley <name> with piped input
            if (!isatty(STDIN_FILENO))
                return cli_stdin_send(argv);

            // A runtime's name alone lists its verbs.
            return cli_runtime_verb(argc, argv);
    }
}

// A relative path in a flag the daemon opens, made absolute against the
// caller's directory, because the daemon resolves it against its own -- which
// is "/" under systemd -- and `--lua example.lua` loaded /example.lua.
std::string cli_caller_path(std::string_view flag, std::string_view value)
{
    // A list of zone files, each made absolute in its place.
    if (flag == "--zone" && value.find(',') != std::string_view::npos)
    {
        std::string out;
        size_t pos = 0;
        for (;;)
        {
            const size_t comma = value.find(',', pos);
            if (pos > 0)
                out += ',';
            out += cli_caller_path(flag, value.substr(pos, comma == std::string_view::npos ? std::string_view::npos
                                                                                          : comma - pos));
            if (comma == std::string_view::npos)
                return out;
            pos = comma + 1;
        }
    }
    // A zone given by its name (example.com) rather than a file: one without a slash that is no file here and
    // not called *.zone. The daemon keeps that zone's file itself.
    if (flag == "--zone" && value.find('/') == std::string_view::npos && !value.ends_with(".zone"))
    {
        std::error_code ec;
        if (!std::filesystem::exists(value, ec))
            return std::string(value);
    }
    // A broker's --persistent on asks for the file under the state directory, which the daemon names.
    if (flag == "--persistent" && value == "on")
        return std::string(value);
    std::string_view prefix;
    bool is_path = false;
    // The schema's paths, and the zone files a --zone that is no list may name.
    if (runtime_schema::is_path_flag(flag) || flag == "--zone" || flag == "--keys")
        is_path = true;
    if (!is_path && flag == "--listen" && value.starts_with("unix:"))
    {
        is_path = true;
        prefix  = "unix:";
    }
    const std::string_view path = value.substr(prefix.size());
    if (!is_path || path.empty() || path.front() == '/')
        return std::string(value);
    std::error_code ec;
    const std::filesystem::path abs = std::filesystem::absolute(path, ec);
    if (ec)
        return std::string(value);
    return std::string(prefix) + abs.lexically_normal().string();
}

// A runtime a start left starting past the daemon's two seconds, as await_worker_startup() says it, is waited for
// here, where waiting holds no daemon: while its workers use CPU, reading their files, and until 15 s pass without.
static int settle_startup(int rc, std::string& data)
{
    static constexpr std::string_view tail = " did not report back within 2s of starting";
    if (rc != 1 && rc != 2)
        return rc;
    std::vector<std::string> names;
    std::string kept;
    std::istringstream lines(data);
    for (std::string line; std::getline(lines, line);)
    {
        const size_t at = line.find(tail);
        if (line.starts_with("runtime ") && at != std::string::npos)
            names.push_back(line.substr(8, at - 8));
        else
            kept += line + "\n";
    }
    if (names.empty())
        return rc;
    // What else the command said is a failure of its own, which a runtime that comes up does not undo.
    int worst = kept.empty() ? 0 : 1;
    std::string said = kept;
    for (const std::string& name : names)
    {
        uint64_t last = UINT64_MAX;
        auto moved = std::chrono::steady_clock::now();
        for (;;)
        {
            std::string got;
            const int r = ipc_send("startup " + name, got);
            if (r == 0 || r == 1 || r < 0)
            {
                if (r == 1)
                    said += got;
                worst = r < 0 ? 2 : std::max(worst, r);
                break;
            }
            const uint64_t ticks = got.starts_with("starting ") ? std::strtoull(got.c_str() + 9, nullptr, 10) : 0;
            const auto now = std::chrono::steady_clock::now();
            if (ticks != last)
            {
                last  = ticks;
                moved = now;
            }
            else if (now - moved > std::chrono::seconds(15))
            {
                said += "runtime " + name + std::string(tail) +
                        " and has used no CPU for 15s; it is still being supervised -- check `socketley ls` for what "
                        "it settled on\n";
                worst = 2;
                break;
            }
            ::usleep(200 * 1000);
        }
    }
    data = std::move(said);
    return worst;
}

// A tab inside an argument cannot travel as one, since only a space has a stand-in on the line to the daemon.
static bool refused_tab(int argc, char** argv)
{
    for (int i = 1; i < argc; ++i)
        if (std::strchr(argv[i], '\t'))
        {
            std::cout << "an argument cannot hold a tab: \"" << argv[i] << "\"\n";
            return true;
        }
    return false;
}

int cli_forward(int argc, char** argv)
{
    if (refused_tab(argc, argv))
        return 1;
    const std::string_view verb = argc > 1 ? argv[1] : "";
    const bool opens_files = verb == "create" || verb == "edit" || verb == "add";
    std::string command;
    for (int i = 1; i < argc; ++i)
    {
        if (i > 1) command += ' ';
        // add's executable is its first word, a path the daemon would read against its own directory.
        if (verb == "add" && i == 2 && argv[i][0] != '/' && argv[i][0] != '\0')
        {
            std::error_code ec;
            const auto abs = std::filesystem::absolute(argv[i], ec);
            ipc_frame::append_arg(command, ec ? std::string(argv[i]) : abs.string());
        }
        else if (opens_files && i > 2)
            ipc_frame::append_arg(command, cli_caller_path(argv[i - 1], argv[i]));
        else if (i > 1)
            ipc_frame::append_arg(command, argv[i]);
        else
            command += argv[i];
    }

    std::string data;
    int exit_code = ipc_send(command, data);

    if (exit_code < 0)
        return ipc_report_failure(exit_code);
    if (verb == "start" || verb == "create")
        exit_code = settle_startup(exit_code, data);

    if (!data.empty())
        std::cout << data;

    return exit_code;
}

// `--password -` takes the password from the first line of stdin, so it need not be on a command line others can read.
int cli_idp_user(int argc, char** argv)
{
    std::vector<std::string> args(argv, argv + argc);
    for (size_t i = 0; i + 1 < args.size(); ++i)
        if (args[i] == "--password" && args[i + 1] == "-")
        {
            std::string line;
            if (!std::getline(std::cin, line))
            {
                std::cout << "--password - reads the password from stdin, which gave none\n";
                return 1;
            }
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            args[i + 1] = line;
        }
    std::vector<char*> ptrs;
    for (auto& a : args)
        ptrs.push_back(a.data());
    return cli_forward(static_cast<int>(ptrs.size()), ptrs.data());
}

// A backup started, and waited for here by asking after it, so the daemon is never the one waiting.
int cli_db_backup(int argc, char** argv)
{
    if (argc != 4)
        return cli_forward(argc, argv);
    const std::string db = argv[2];
    const std::string file = cli_caller_path("--keys", argv[3]);
    std::string data;
    std::string cmd = "db-backup";
    ipc_frame::append_arg(cmd += ' ', db);
    ipc_frame::append_arg(cmd += ' ', file);
    int rc = ipc_send(cmd, data);
    if (rc < 0)
        return ipc_report_failure(rc);
    if (rc != 0 || !data.starts_with("job "))
    {
        std::cout << data;
        return rc ? rc : 2;
    }
    const std::string job = data.substr(4, data.find('\n') - 4);
    for (;;)
    {
        std::string status = "db-backup";
        ipc_frame::append_arg(status += ' ', db);
        status += " --status ";
        status += job;
        data.clear();
        rc = ipc_send(status, data);
        if (rc < 0)
            return ipc_report_failure(rc);
        if (rc != 0)
        {
            std::cout << data;
            return rc;
        }
        if (data.starts_with("done "))
            return 0;
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

int cli_send(int argc, char** argv)
{
    if (argc < 3)
    {
        std::cerr << "usage: send <name> [message]\n";
        std::cerr << "       echo 'msg' | socketley send <name>\n";
        return 1;
    }

    // A flag only a mail message takes makes it one for a mail runtime, written there; any other words, a "-1" or a
    // "--" among them, are a message for a server or a client as they are.
    static constexpr std::string_view mail_flags[] = {"--to",   "-t",     "--cc",   "--bcc",  "--from",   "--reply-to",
                                                      "--subject", "--text", "--header", "--html", "--attach",
                                                      "--raw", "--template", "--set", "--inline", "--ad", "--no-check",
                                                      "--test", "--test-to", "--rate-limit", "--lua"};
    if (argc >= 4 && std::any_of(std::begin(mail_flags), std::end(mail_flags),
                                 [&](std::string_view f) { return f == argv[3]; }))
        return cli_mail_send(argc, argv);
    if (argc >= 4 && std::string_view(argv[3]) == "--")
    {
        for (int i = 3; i + 1 < argc; ++i)
            argv[i] = argv[i + 1];
        --argc;
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

        // Only the trailing newline goes, because newlines inside the message
        // are the message and ipc_send frames the command rather than the CLI
        // mangling it.
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
        return ipc_report_failure(exit_code);

    if (!data.empty())
        std::cout << data;

    return exit_code;
}

int cli_stdin_send(char** argv)
{
    std::string name = argv[1];

    std::ostringstream ss;
    ss << std::cin.rdbuf();
    std::string message = ss.str();

    // The trailing newline only — see cli_send() above.
    while (!message.empty() && (message.back() == '\n' || message.back() == '\r'))
        message.pop_back();

    // Nothing arrived on stdin, which is also where an unrecognised word falls
    // whenever stdin is not a terminal, so both readings are named rather than
    // guessed at, likelier one first.
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
        return ipc_report_failure(exit_code);

    if (!data.empty())
        std::cout << data;

    return exit_code;
}

// The escape state is carried forward rather than reconstructed by looking
// back, because `"C:\\"` left in_string true for the rest of the document and
// `show | import` silently dropped every field after it.
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

// The other half of `show`, which needs the document compacted -- IPC frames
// one command per line -- and accepted on stdin, because a `show` document can
// outgrow ARG_MAX before this binary runs at all.
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

    // The caller's flag and not part of the document, so it is taken out before the rest is read -- and taken out
    // rather than left in, because `show x | import x --restart` otherwise looks like a document of one word and
    // never reads the pipe.
    std::string restart;
    int first = 3;
    for (int i = 3; i < argc; ++i)
        if (std::string_view(argv[i]) == "--restart")
        {
            restart = " --restart";
            if (i == first)
                ++first;
        }

    if (argc > first)
    {
        // Quoted, the document is argv[first] entire; unquoted, joining with a
        // space puts it back together well enough for the compaction about to
        // drop that whitespace.
        for (int i = first; i < argc; ++i)
        {
            if (std::string_view(argv[i]) == "--restart")
                continue;
            if (i > first) json += ' ';
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

    std::string command = "import " + name + restart + " " + compact;

    std::string data;
    int exit_code = ipc_send(command, data);

    if (exit_code < 0)
        return ipc_report_failure(exit_code);

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

    // The shell splits an editor given with arguments, such as "code --wait".
    const std::string script = std::string(editor) + " \"$1\"";

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) { execl("/bin/sh", "sh", "-c", script.c_str(), "sh", path.c_str(), nullptr); _exit(127); }

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
        return ipc_report_failure(rc);
    }
    if (rc != 0)
    {
        if (!dump_data.empty())
            std::cerr << dump_data;
        return rc;
    }

    // TMPDIR then /tmp, because the file holds the runtime's whole
    // configuration and where it lands is the operator's decision to make.
    const char* tmpdir = std::getenv("TMPDIR");
    if (!tmpdir || !tmpdir[0])
        tmpdir = "/tmp";

    std::string tmpl_s = std::string(tmpdir);
    if (tmpl_s.back() != '/')
        tmpl_s += '/';
    tmpl_s += "socketley-edit-XXXXXX";

    std::vector<char> tmpl(tmpl_s.begin(), tmpl_s.end());
    tmpl.push_back('\0');

    int tmpfd = mkstemp(tmpl.data());
    if (tmpfd < 0)
    {
        std::cerr << "failed to create temporary file in " << tmpdir << "\n";
        return 2;
    }

    std::string tmp_file = std::string(tmpl.data()) + ".json";
    close(tmpfd);
    if (rename(tmpl.data(), tmp_file.c_str()) < 0)
    {
        std::cerr << "failed to rename temporary file\n";
        unlink(tmpl.data());
        return 2;
    }

    {
        std::ofstream f(tmp_file, std::ios::trunc);
        if (!f.is_open())
        {
            // tmp_file and not tmpl, because the rename succeeded and
            // unlinking the old name left the real file behind with master_pw
            // in it.
            std::cerr << "failed to write temporary file\n";
            unlink(tmp_file.c_str());
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
        return ipc_report_failure(rc);
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
            return ipc_report_failure(rc);
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
    if (refused_tab(argc, argv))
        return 1;
    // Build command: "start <name> -i"
    std::string command;
    for (int i = 1; i < argc; ++i)
    {
        if (i > 1) command += ' ';
        // Each argument whole, as cli_forward sends one, or "my dir/app.lua" arrived as two words.
        if (i > 1)
            ipc_frame::append_arg(command, argv[i]);
        else
            command += argv[i];
    }
    return cli_interactive_command(command);
}

int cli_interactive_command(const std::string& command)
{
    // Connect to daemon
    int ipc_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (ipc_fd < 0)
        return ipc_report_failure(ipc_unreachable);

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, daemon_handler::socket_path.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(ipc_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        close(ipc_fd);
        return ipc_report_failure(ipc_unreachable);
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
    // What came in the same read after the reply's end is the runtime's first output, kept for the screen.
    std::string after;
    auto* nul = static_cast<char*>(std::memchr(buf + 1, '\0', n - 1));
    if (nul)
    {
        data.append(buf + 1, nul - buf - 1);
        after.assign(nul + 1, buf + n);
    }
    else
    {
        data.append(buf + 1, n - 1);
        while (true)
        {
            n = read(ipc_fd, buf, sizeof(buf));
            if (n <= 0) break;
            nul = static_cast<char*>(std::memchr(buf, '\0', n));
            if (nul) { data.append(buf, nul - buf); after.assign(nul + 1, buf + n); break; }
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
    if (!after.empty() && ::write(STDOUT_FILENO, after.data(), after.size()) < 0) {}

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
        if (fds[0].revents & (POLLIN | POLLHUP))
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
    if (refused_tab(argc, argv))
        return 1;
    // Format: socketley <name> <action> [args...]
    // Forward as: action <name> <action> [args...]
    std::string command = "action";
    for (int i = 1; i < argc; ++i)
    {
        command += ' ';
        ipc_frame::append_arg(command, argv[i]);
    }

    std::string data;
    int exit_code = ipc_send(command, data);

    if (exit_code < 0)
        return ipc_report_failure(exit_code);

    if (!data.empty())
        std::cout << data;

    return exit_code;
}
