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

#include "command_hashing.h"
#include "ipc_client.h"
#include "../daemon/daemon_handler.h"
#include "../shared/paths.h"

static bool daemon_is_running()
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return false;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, daemon_handler::socket_path.c_str(), sizeof(addr.sun_path) - 1);

    bool ok = connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0;
    close(fd);
    return ok;
}

static bool ensure_daemon(char* argv0)
{
    if (daemon_is_running())
        return true;

    pid_t pid = fork();
    if (pid < 0)
        return false;

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
        if (daemon_is_running())
            return true;
    }

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
        case fnv1a("daemon"):
            return cli_daemon(argc, argv);

        case fnv1a("--lua"):
            return cli_config(argc, argv);

        default:
            break;
    }

    // All other commands need the daemon — auto-start if not running
    if (!ensure_daemon(argv[0]))
    {
        std::cerr << "failed to start daemon\n";
        return 2;
    }

    switch (fnv1a(cmd.data()))
    {
        case fnv1a("start"):
        {
            for (int i = 2; i < argc; ++i)
                if (std::string_view(argv[i]) == "-i")
                    return cli_interactive(argc, argv);
            return cli_forward(argc, argv);
        }
        case fnv1a("ls"):
        case fnv1a("ps"):
        case fnv1a("create"):
        case fnv1a("attach"):
        case fnv1a("stop"):
        case fnv1a("remove"):
        case fnv1a("stats"):
        case fnv1a("reload"):
        case fnv1a("reload-lua"):
        case fnv1a("show"):
        case fnv1a("owner"):
            return cli_forward(argc, argv);

        case fnv1a("cluster"):
            return cli_cluster(argc, argv);

        case fnv1a("send"):
            return cli_send(argc, argv);

        case fnv1a("edit"):
            return cli_edit(argc, argv);

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

int cli_stdin_send(int argc, char** argv)
{
    std::string name = argv[1];

    std::ostringstream ss;
    ss << std::cin.rdbuf();
    std::string message = ss.str();

    while (!message.empty() && (message.back() == '\n' || message.back() == '\r'))
        message.pop_back();

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

static std::string compact_json(const std::string& pretty)
{
    std::string result;
    result.reserve(pretty.size());
    bool in_string = false;
    for (size_t i = 0; i < pretty.size(); ++i)
    {
        char c = pretty[i];
        if (c == '"' && (i == 0 || pretty[i-1] != '\\'))
            in_string = !in_string;

        if (in_string)
        {
            result += c;
        }
        else if (c != '\n' && c != '\r' && c != '\t' && c != ' ')
        {
            result += c;
        }
    }
    return result;
}

static int open_editor(const std::string& path)
{
    const char* editor = std::getenv("VISUAL");
    if (!editor || !editor[0])
        editor = std::getenv("EDITOR");
    if (!editor || !editor[0])
        editor = "vim";

    std::string cmd = std::string(editor) + " " + path;
    return system(cmd.c_str());
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
    rename(tmpl, tmp_file.c_str());

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
    int ipc_fd = socket(AF_UNIX, SOCK_STREAM, 0);
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
