#include "cli.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../daemon/ipc_client.h"
#include "../runtime/mail/mail_command.h"
#include "../runtime/mail/mail_instance.h"
#include "../shared/loop/blocking_write.h"
#include "../shared/ipc/ipc_framing.h"
#include "../shared/persist/read_file.h"
#include "../shared/runtime/command_usage.h"
#include "../shared/util/base64.h"
#include "../shared/util/random_id.h"

namespace
{

// A file a flag names, read here, since a relative path means this directory and not the daemon's.
bool file_arg(std::string_view path, std::string& out)
{
    std::string why;
    if (!socketley::read_file(std::string(path), out, {.max_bytes = 64u << 20}, &why))
    {
        std::cout << why << "\n";
        return false;
    }
    return true;
}

std::string_view base_name(std::string_view p)
{
    const size_t slash = p.rfind('/');
    return slash == std::string_view::npos ? p : p.substr(slash + 1);
}

int ask(const std::string& command)
{
    std::string data;
    const int rc = ipc_send(command, data);
    if (rc < 0)
        return ipc_report_failure(rc);
    std::cout << data;
    if (!data.empty() && data.back() != '\n')
        std::cout << "\n";
    return rc != 0 || data.starts_with("error") ? 1 : 0;
}

}   // namespace

// `socketley send <mail> --to ...`: the message is written by the runtime, its body from stdin or --text.
int cli_mail_send(int argc, char** argv)
{
    socketley::mail::compose c;
    bool raw = false, have_text = false;
    for (int i = 3; i < argc; ++i)
    {
        const std::string_view a = argv[i];
        const bool has = i + 1 < argc;
        const auto value = [&]() -> std::string { return argv[++i]; };
        if ((a == "--to" || a == "-t") && has)
            c.to.push_back(value());
        else if (a == "--cc" && has)
            c.cc.push_back(value());
        else if (a == "--bcc" && has)
            c.bcc.push_back(value());
        else if (a == "--from" && has)
            c.from = value();
        else if (a == "--reply-to" && has)
            c.reply_to = value();
        else if ((a == "--subject" || a == "-s") && has)
            c.subject = value();
        else if (a == "--text" && has)
        {
            c.text = value();
            have_text = true;
        }
        else if (a == "--header" && has)
            c.headers.push_back(value());
        else if (a == "--html" && has)
        {
            if (!file_arg(argv[++i], c.html))
                return 1;
        }
        else if (a == "--attach" && has)
        {
            // file[:type], the type guessed by the reader where none is said; a colon is a type's only where what
            // follows it is one, type/subtype, so a path with a colon in a directory's name is read as the path.
            std::string spec = value();
            socketley::mail::attachment at;
            const size_t colon = spec.rfind(':');
            const std::string_view after = colon == std::string::npos ? std::string_view{}
                                                                       : std::string_view(spec).substr(colon + 1);
            const size_t slash = after.find('/');
            const bool typed = slash != std::string_view::npos && slash > 0 && slash + 1 < after.size() &&
                               after.find('/', slash + 1) == std::string_view::npos &&
                               after.find_first_of(" \t") == std::string_view::npos;
            if (typed && ::access(spec.c_str(), F_OK) != 0)
            {
                at.type = std::string(after);
                spec.resize(colon);
            }
            if (!file_arg(spec, at.data))
                return 1;
            at.name = std::string(base_name(spec));
            c.attachments.push_back(std::move(at));
        }
        else if (a == "--raw")
            raw = true;
        else
        {
            std::cerr << command_usage::line("send");
            return 1;
        }
    }
    if (c.to.empty() && c.cc.empty() && c.bcc.empty())
    {
        std::cout << "send to a mail runtime needs a recipient: --to <address>\n";
        return 1;
    }
    if (!have_text && !isatty(STDIN_FILENO))
    {
        std::ostringstream ss;
        ss << std::cin.rdbuf();
        (raw ? c.raw : c.text) = ss.str();
    }
    if (raw && c.raw.empty())
    {
        std::cout << "--raw reads a whole message from stdin, and none came\n";
        return 1;
    }
    std::string cmd = "mail-send ";
    ipc_frame::append_arg(cmd, argv[2]);
    cmd += ' ';
    std::string payload = socketley::mail::command_send(c);
    // Past what the daemon's channels carry, the message is left in the runtime's outbox and only its name is sent.
    if (payload.size() > (4u << 20))
    {
        const std::string dir = mail_outbox_dir(argv[2]);
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        ::chmod(dir.c_str(), 0700);
        const std::string file = socketley::random_hex(16) + ".msg";
        const std::string path = dir + "/" + file;
        const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        const bool written = fd >= 0 && socketley::write_all(fd, payload.data(), payload.size());
        if (fd >= 0)
            ::close(fd);
        if (!written)
        {
            ::unlink(path.c_str());
            std::cout << "the message could not be written to " << dir << "\n";
            return 2;
        }
        payload = socketley::mail::command_text(socketley::mail::verb::send_file, file);
        cmd += socketley::base64::encode(payload);
        const int rc = ask(cmd);
        // Taken away by the runtime once read; one the runtime never came for is not left behind.
        ::unlink(path.c_str());
        return rc;
    }
    cmd += socketley::base64::encode(payload);
    return ask(cmd);
}

// `socketley mail <mail> sieve <user> list | get <name> | put <name> <file|-> | check <file|-> | activate <name> |
// deactivate | delete <name>`: the script's text is read here, where the file is, and sent with the verb.
int cli_mail_sieve(int argc, char** argv)
{
    const std::string_view what = argc > 5 ? argv[5] : "";
    const bool named = what == "get" || what == "put" || what == "activate" || what == "delete";
    const bool texted = what == "put" || what == "check";
    if (argc < 6 || !(named || texted || what == "list" || what == "deactivate") ||
        (named && argc < 7) || (texted && argc < (what == "put" ? 8 : 7)))
    {
        std::cerr << "usage: socketley mail <mail> sieve <user> list | get <name> | put <name> <file|-> | "
                     "check <file|-> | activate <name> | deactivate | delete <name>\n";
        return 1;
    }
    std::string name = named ? argv[6] : "", text;
    if (texted)
    {
        const std::string src = argv[what == "put" ? 7 : 6];
        std::ostringstream ss;
        if (src == "-")
            ss << std::cin.rdbuf();
        else
        {
            std::ifstream f(src, std::ios::binary);
            if (!f)
            {
                std::cout << src << " cannot be read\n";
                return 1;
            }
            ss << f.rdbuf();
        }
        text = ss.str();
    }
    std::string cmd = "mail ";
    ipc_frame::append_arg(cmd, argv[2]);
    cmd += " sieve ";
    ipc_frame::append_arg(cmd, socketley::base64::encode(std::string(argv[4]) + "\n" + std::string(what) + "\n" +
                                                         name + "\n" + text));
    return ask(cmd);
}

// `socketley mail <mail> queue|show|flush|drop [arg]`.
int cli_mail(int argc, char** argv)
{
    if (argc < 4)
    {
        std::cerr << command_usage::line("mail");
        return 1;
    }
    const std::string_view verb = argv[3];
    if (verb != "queue" && verb != "show" && verb != "flush" && verb != "drop" && verb != "dns" &&
        verb != "suppressed" && verb != "forgive" && verb != "sieve")
    {
        std::cerr << command_usage::line("mail");
        return 1;
    }
    if (verb == "sieve")
        return cli_mail_sieve(argc, argv);
    if ((verb == "show" || verb == "drop" || verb == "forgive") && argc < 5)
    {
        std::cerr << command_usage::line("mail");
        return 1;
    }
    std::string cmd = "mail ";
    ipc_frame::append_arg(cmd, argv[2]);
    cmd += ' ';
    cmd += verb;
    if (argc >= 5)
    {
        cmd += ' ';
        ipc_frame::append_arg(cmd, argv[4]);
    }
    return ask(cmd);
}
