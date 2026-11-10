#include "cli.h"

#include <chrono>
#include <csignal>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#include "../daemon/ipc_client.h"
#include "../shared/crypto/password_hash.h"
#include "../shared/ipc/ipc_framing.h"
#include "../shared/persist/read_file.h"
#include "../shared/persist/replaced_file.h"
#include "../shared/runtime/command_usage.h"
#include "../shared/util/base64.h"

namespace
{

volatile std::sig_atomic_t g_stop = 0;

void on_stop_signal(int)
{
    g_stop = 1;
}


}   // namespace

// The payload goes in base64, so a space, a tab or a NUL in it arrives as it was typed or piped.
int cli_mqtt_pub(int argc, char** argv)
{
    if (argc < 4)
    {
        std::cerr << command_usage::line("mqtt-pub");
        return 1;
    }
    std::string cmd = "mqtt-pub ";
    ipc_frame::append_arg(cmd, argv[2]);
    int i = 3;
    for (; i < argc; ++i)
    {
        const std::string_view a = argv[i];
        if (a == "--retain")
            cmd += " --retain";
        else if (a == "--qos" && i + 1 < argc)
        {
            const std::string_view q = argv[++i];
            if (q != "0" && q != "1" && q != "2")
            {
                std::cout << "--qos takes 0, 1 or 2\n";
                return 1;
            }
            cmd += " --qos ";
            cmd += q;
        }
        else if (a.starts_with("--"))
        {
            std::cerr << command_usage::line("mqtt-pub");
            return 1;
        }
        else
            break;
    }
    if (i >= argc)
    {
        std::cerr << command_usage::line("mqtt-pub");
        return 1;
    }
    cmd += ' ';
    ipc_frame::append_arg(cmd, argv[i]);
    std::string payload;
    if (i + 1 < argc)
    {
        for (int k = i + 1; k < argc; ++k)
        {
            if (k > i + 1)
                payload += ' ';
            payload += argv[k];
        }
    }
    else if (!isatty(STDIN_FILENO))
    {
        std::ostringstream ss;
        ss << std::cin.rdbuf();
        payload = ss.str();
        // The newline a pipe ends with is not the message's, as it is not for `send`.
        if (payload.ends_with("\r\n"))
            payload.resize(payload.size() - 2);
        else if (payload.ends_with('\n'))
            payload.pop_back();
    }
    cmd += " --base64";
    if (!payload.empty())
        cmd += " " + socketley::base64::encode(payload);
    std::string data;
    const int rc = ipc_send(cmd, data);
    if (rc < 0)
        return ipc_report_failure(rc);
    std::cout << data;
    return rc;
}

// A tap on every shard, asked what it saw every tenth of a second, until a signal or --count messages.
int cli_mqtt_sub(int argc, char** argv)
{
    long want = 0;
    if (argc == 6 && std::string_view(argv[4]) == "--count")
    {
        char* end = nullptr;
        want = std::strtol(argv[5], &end, 10);
        if (!end || *end || want < 1)
        {
            std::cout << "--count takes how many messages, from 1\n";
            return 1;
        }
    }
    else if (argc != 4)
    {
        std::cerr << command_usage::line("mqtt-sub");
        return 1;
    }
    std::string rt;
    ipc_frame::append_arg(rt, argv[2]);
    std::string open = "mqtt-tap " + rt + " open ";
    ipc_frame::append_arg(open, argv[3]);
    std::string data;
    int rc = ipc_send(open, data);
    if (rc < 0)
        return ipc_report_failure(rc);
    if (rc != 0)
    {
        std::cout << data;
        return rc;
    }
    const std::string ids = data.substr(0, data.find('\n'));
    struct sigaction sa{};
    sa.sa_handler = on_stop_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGPIPE, &sa, nullptr);
    long seen = 0;
    int result = 0;
    while (!g_stop)
    {
        data.clear();
        rc = ipc_send("mqtt-tap " + rt + " poll " + ids, data);
        if (rc < 0)
        {
            result = ipc_report_failure(rc);
            break;
        }
        if (rc != 0)
        {
            std::cout << data;
            result = rc;
            break;
        }
        std::istringstream lines(data);
        for (std::string line; !g_stop && std::getline(lines, line);)
        {
            std::cout << line << '\n';
            if (line.starts_with("{\"topic\":") && want && ++seen >= want)
                g_stop = 1;
        }
        std::cout << std::flush;
        if (!g_stop)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    data.clear();
    if (ipc_send("mqtt-tap " + rt + " close " + ids, data) < 0) {}
    return result;
}

// A users file as --users reads it, changed here without a daemon: the password from stdin or a terminal, hashed.
int cli_mqtt_passwd(int argc, char** argv)
{
    const bool remove = argc == 5 && std::string_view(argv[4]) == "--delete";
    if (argc != 4 && !remove)
    {
        std::cerr << command_usage::line("mqtt-passwd");
        return 1;
    }
    const std::string path = cli_caller_path("--users", argv[2]);
    const std::string_view user = argv[3];
    if (user.empty() || user.find_first_of(": \t\r\n#") != std::string_view::npos)
    {
        std::cout << "a user name may not be empty or hold ':', '#' or whitespace\n";
        return 1;
    }
    std::string text, why;
    if (!socketley::read_file(path, text, {.missing_ok = true, .max_bytes = 64u << 20}, &why))
    {
        std::cout << why << "\n";
        return 1;
    }
    std::string line;
    if (!remove)
    {
        std::string pw, again;
        if (!cli_read_secret("password: ", pw) || pw.empty())
        {
            std::cout << "no password given\n";
            return 1;
        }
        if (isatty(STDIN_FILENO) && (!cli_read_secret("again: ", again) || again != pw))
        {
            std::cout << "the passwords differ\n";
            return 1;
        }
        const std::string hash = socketley::crypto::password_hash(pw);
        if (hash.empty())
        {
            std::cout << "no random salt could be drawn\n";
            return 2;
        }
        line = std::string(user) + ":" + hash;
    }
    // Every other line kept as it was, the user's own replaced where it stood.
    std::string out;
    bool found = false;
    std::istringstream in(text);
    for (std::string l; std::getline(in, l);)
    {
        const size_t colon = l.find(':');
        if (colon != std::string::npos && std::string_view(l).substr(0, colon) == user && !l.starts_with('#'))
        {
            found = true;
            if (!remove)
                out += line + "\n";
            continue;
        }
        out += l + "\n";
    }
    if (remove && !found)
    {
        std::cout << "no user " << user << " in " << path << "\n";
        return 1;
    }
    if (!found)
        out += line + "\n";
    if (!socketley::replace_file(path, out, socketley::durability::data_and_dir, &why, 0600))
    {
        std::cout << why << "\n";
        return 2;
    }
    return 0;
}
