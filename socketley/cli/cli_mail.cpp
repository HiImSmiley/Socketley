#include "cli.h"

#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

#include <unistd.h>

#include "../daemon/ipc_client.h"
#include "../runtime/mail/mail_command.h"
#include "../shared/ipc/ipc_framing.h"
#include "../shared/persist/read_file.h"
#include "../shared/runtime/command_usage.h"
#include "../shared/util/base64.h"

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
            // file[:type], the type guessed by the reader where none is said.
            std::string spec = value();
            socketley::mail::attachment at;
            const size_t colon = spec.rfind(':');
            if (colon != std::string::npos && spec.find('/', colon) != std::string::npos)
            {
                at.type = spec.substr(colon + 1);
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
    cmd += socketley::base64::encode(socketley::mail::command_send(c));
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
        verb != "suppressed" && verb != "forgive")
    {
        std::cerr << command_usage::line("mail");
        return 1;
    }
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
