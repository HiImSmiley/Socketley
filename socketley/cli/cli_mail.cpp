#include "cli.h"

#include <chrono>
#include <algorithm>
#include <filesystem>
#include <map>
#include <thread>
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
#include "../shared/json/json_doc.h"
#include "../shared/persist/read_file.h"
#include "../shared/runtime/command_usage.h"
#include "../shared/util/base64.h"
#include "../shared/util/random_id.h"
#include "mail_template.h"

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

// A file's type by its extension, for an image the HTML shows inline.
std::string type_of(std::string_view name)
{
    const size_t dot = name.rfind('.');
    std::string e(dot == std::string_view::npos ? std::string_view{} : name.substr(dot + 1));
    for (auto& ch : e)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    if (e == "png" || e == "gif" || e == "webp" || e == "avif")
        return "image/" + e;
    if (e == "jpg" || e == "jpeg")
        return "image/jpeg";
    if (e == "svg")
        return "image/svg+xml";
    return "application/octet-stream";
}

// One message to a mail runtime, its answer in `reply`: "queued <id>", "skipped: ..." or "error: ...". One past what the
// daemon's channels carry goes through the runtime's outbox, and only its name is sent.
int deliver(const char* runtime, const socketley::mail::compose& c, std::string& reply)
{
    reply.clear();
    std::string cmd = "mail-send ";
    ipc_frame::append_arg(cmd, runtime);
    cmd += ' ';
    std::string payload = socketley::mail::command_send(c);
    if (payload.size() <= (4u << 20))
    {
        cmd += socketley::base64::encode(payload);
        return ipc_send(cmd, reply);
    }
    const std::string dir = mail_outbox_dir(runtime);
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
        reply = "error: the message could not be written to " + dir;
        return 0;
    }
    cmd += socketley::base64::encode(socketley::mail::command_text(socketley::mail::verb::send_file, file));
    const int rc = ipc_send(cmd, reply);
    // Taken away by the runtime once read; one the runtime never came for is not left behind.
    ::unlink(path.c_str());
    return rc;
}

std::string_view trimmed(std::string_view v)
{
    while (!v.empty() && (v.front() == ' ' || v.front() == '\t'))
        v.remove_prefix(1);
    while (!v.empty() && (v.back() == ' ' || v.back() == '\t'))
        v.remove_suffix(1);
    return v;
}

// Text without the white space around it, as a JSON reader takes a document.
std::string_view trimmed_text(std::string_view v)
{
    while (!v.empty() && std::isspace(static_cast<unsigned char>(v.front())))
        v.remove_prefix(1);
    while (!v.empty() && std::isspace(static_cast<unsigned char>(v.back())))
        v.remove_suffix(1);
    return v;
}

// The text of an HTML message, for the plain part beside it: its links written out, its tags and styles gone.
std::string text_of_html(std::string_view h)
{
    std::string out;
    const auto lower_at = [&](size_t at, std::string_view w) {
        if (at + w.size() > h.size())
            return false;
        for (size_t k = 0; k < w.size(); ++k)
            if (std::tolower(static_cast<unsigned char>(h[at + k])) != w[k])
                return false;
        return true;
    };
    std::string href;
    for (size_t i = 0; i < h.size();)
    {
        if (h[i] != '<')
        {
            if (h[i] == '&')
            {
                static constexpr std::pair<std::string_view, char> named[] = {
                    {"&amp;", '&'}, {"&lt;", '<'}, {"&gt;", '>'}, {"&quot;", '"'}, {"&#39;", '\''}, {"&nbsp;", ' '}};
                bool hit = false;
                for (const auto& [n, ch] : named)
                    if (lower_at(i, n))
                    {
                        out += ch;
                        i += n.size();
                        hit = true;
                        break;
                    }
                if (hit)
                    continue;
            }
            out += h[i] == '\r' || h[i] == '\n' || h[i] == '\t' ? ' ' : h[i];
            ++i;
            continue;
        }
        const size_t close = h.find('>', i);
        if (close == std::string_view::npos)
            break;
        // A style or a script says nothing a reader reads.
        for (const std::string_view skip : {std::string_view("<style"), std::string_view("<script"), std::string_view("<head")})
            if (lower_at(i, skip))
            {
                const std::string end = "</" + std::string(skip.substr(1));
                size_t at = close;
                while (at < h.size() && !lower_at(at, end))
                    ++at;
                i = at;
                break;
            }
        if (h[i] != '<')
            continue;
        const std::string_view tag = h.substr(i, close - i + 1);
        std::string t(tag);
        for (auto& ch : t)
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        if (t.starts_with("<br") || t.starts_with("</p") || t.starts_with("</div") || t.starts_with("</tr") ||
            t.starts_with("</h") || t.starts_with("<li") || t.starts_with("</table") || t.starts_with("</ul") ||
            t.starts_with("</ol"))
            out += "\n";
        // A table's cells stand apart on their row.
        else if (t.starts_with("</td") || t.starts_with("</th"))
            out += " ";
        if (t.starts_with("<a "))
            if (const size_t at = t.find("href=\""); at != std::string::npos)
            {
                // The attribute's &amp; is the link's &.
                href.clear();
                const std::string_view v = tag.substr(at + 6, tag.find('"', at + 6) - at - 6);
                for (size_t k = 0; k < v.size(); ++k)
                {
                    href += v[k];
                    if (v.substr(k, 5) == "&amp;")
                        k += 4;
                }
            }
        if (t.starts_with("</a") && !href.empty())
        {
            if (!href.starts_with("mailto:") && out.find(href, out.size() > 300 ? out.size() - 300 : 0) == std::string::npos)
                out += " (" + href + ")";
            href.clear();
        }
        i = close + 1;
    }
    // Lines trimmed, and no more than one empty line in a row.
    std::string text;
    int blank = 0;
    std::string_view rest = out;
    while (!rest.empty())
    {
        const size_t nl = rest.find('\n');
        std::string line;
        for (const char ch : trimmed(rest.substr(0, nl)))
            if (!(ch == ' ' && !line.empty() && line.back() == ' '))
                line += ch;
        rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
        if (line.empty() && (++blank > 1 || text.empty()))
            continue;
        if (!line.empty())
            blank = 0;
        text += line + "\n";
    }
    return text;
}

// A recipient's value of `name`, as its source gave it.
void put(socketley::json::jvalue& row, const std::string& name, const std::string& value)
{
    socketley::json::jvalue v;
    v.k = socketley::json::jvalue::kind::string;
    v.s = value;
    row.k = socketley::json::jvalue::kind::object;
    if (socketley::json::jvalue* had = socketley::json::member(row, name))
        *had = std::move(v);
    else
        row.members.emplace_back(name, std::move(v));
}

// "5/s", "300/min", "1000/h" or a bare number a second, as messages a second.
bool parse_rate(std::string_view v, double& per_s)
{
    const size_t slash = v.find('/');
    const std::string n(v.substr(0, slash));
    char* end = nullptr;
    const double count = std::strtod(n.c_str(), &end);
    if (n.empty() || !end || *end || count <= 0)
        return false;
    const std::string_view unit = slash == std::string_view::npos ? std::string_view("s") : v.substr(slash + 1);
    const double over = unit == "s" ? 1 : unit == "min" || unit == "m" ? 60 : unit == "h" ? 3600 : 0;
    if (!over)
        return false;
    per_s = count / over;
    return true;
}

}   // namespace

// `socketley send <mail> --to ...`: the message is written by the runtime, its body from stdin or --text. With a
// template -- placeholders, --set, a source of recipients, --ad, --no-check, --dry-run, --test-to or --rate -- each
// recipient is sent a message of their own, the placeholders filled from their values, at --rate, strictly unless
// --no-check says a placeholder without a value may be empty.
int cli_mail_send(int argc, char** argv)
{
    socketley::mail::compose c;
    bool raw = false, have_text = false, templated = false, check = true, dry = false;
    std::vector<std::string> sources;
    std::map<std::string, std::string> sets;
    std::string test_to, html_path, script_path;
    double rate = 2;
    for (int i = 3; i < argc; ++i)
    {
        const std::string_view a = argv[i];
        const bool has = i + 1 < argc;
        const auto value = [&]() -> std::string { return argv[++i]; };
        if ((a == "--to" || a == "-t") && has)
        {
            // idp:, db: and json: name many recipients, each sent a message of their own.
            std::string v = value();
            if (v.starts_with("idp:") || v.starts_with("db:") || v.starts_with("json:"))
            {
                sources.push_back(std::move(v));
                templated = true;
            }
            else
                c.to.push_back(std::move(v));
        }
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
        else if ((a == "--html" || a == "--template") && has)
        {
            html_path = value();
            if (!file_arg(html_path, c.html))
                return 1;
            templated = templated || a == "--template";
        }
        else if ((a == "--attach" || a == "--inline") && has)
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
            // An inline image is shown by the HTML as cid:<its file's name>.
            if (a == "--inline")
            {
                if (at.type.empty())
                    at.type = type_of(at.name);
                c.inlines.push_back(std::move(at));
            }
            else
                c.attachments.push_back(std::move(at));
        }
        else if (a == "--set" && has)
        {
            const std::string kv = value();
            const size_t eq = kv.find('=');
            if (eq == std::string::npos || eq == 0)
            {
                std::cout << "--set takes name=value, such as --set code=AUTUMN30\n";
                return 1;
            }
            sets[kv.substr(0, eq)] = kv.substr(eq + 1);
            templated = true;
        }
        else if (a == "--rate" && has)
        {
            if (!parse_rate(value(), rate))
            {
                std::cout << "--rate is messages a second, a minute or an hour: 5/s, 300/min, 1000/h\n";
                return 1;
            }
            templated = true;
        }
        else if (a == "--test-to" && has)
        {
            test_to = value();
            templated = true;
        }
        else if (a == "--script" && has)
        {
            script_path = value();
            templated = true;
        }
        else if (a == "--ad")
            c.ad = templated = true;
        else if (a == "--no-check")
        {
            check = false;
            templated = true;
        }
        else if (a == "--dry-run")
            dry = templated = true;
        else if (a == "--raw")
            raw = true;
        else
        {
            std::cerr << command_usage::line("send");
            return 1;
        }
    }
    if (c.to.empty() && c.cc.empty() && c.bcc.empty() && sources.empty())
    {
        std::cout << "send to a mail runtime needs a recipient: --to <address>, or idp:<runtime>, db:<runtime>/<collection> "
                     "or json:<file> for many\n";
        return 1;
    }
    // A template's text is its --text or what its HTML says, never stdin, which a script or a timer may leave open.
    if (!have_text && !isatty(STDIN_FILENO) && !(templated && !c.html.empty()))
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
    if (!templated)
    {
        std::string reply;
        const int rc = deliver(argv[2], c, reply);
        if (rc < 0)
            return ipc_report_failure(rc);
        std::cout << reply << (reply.ends_with('\n') ? "" : "\n");
        return rc != 0 || reply.starts_with("error") ? 1 : 0;
    }

    if (raw || !c.cc.empty() || !c.bcc.empty())
    {
        std::cout << "--raw, --cc and --bcc write one message to all; a template writes each recipient their own\n";
        return 1;
    }
    // Each recipient's values: what their source says of them, then --set for everyone where it says nothing.
    std::vector<socketley::json::jvalue> rows;
    for (const auto& to : c.to)
        put(rows.emplace_back(), "email", to);
    // A command of the daemon's, its answer in `out`; false, said, where it failed.
    const auto daemon = [](const std::string& cmd, std::string& out) {
        const int rc = ipc_send(cmd, out);
        if (rc < 0)
        {
            ipc_report_failure(rc);
            return false;
        }
        if (rc != 0 || out.starts_with("error") || out.starts_with("usage") || out.starts_with("no "))
        {
            std::cout << out << (out.ends_with('\n') ? "" : "\n");
            return false;
        }
        return true;
    };
    for (const auto& src : sources)
    {
        const std::string what = src.substr(src.find(':') + 1);
        const size_t slash = what.find('/');
        const std::string runtime = what.substr(0, slash), part = slash == std::string::npos ? std::string() : what.substr(slash + 1);
        // An idp's accounts that are not disabled, of the group after the slash where one is, each with its fields.
        if (src.starts_with("idp:"))
        {
            std::string list;
            if (runtime.empty() || !daemon("idp-user " + runtime + " list", list))
                return 1;
            for (std::string_view rest = list; !rest.empty();)
            {
                const size_t nl = rest.find('\n');
                std::string_view line = rest.substr(0, nl);
                rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
                std::vector<std::string_view> cols;
                for (std::string_view l = line; !l.empty();)
                {
                    const size_t tab = l.find('\t');
                    cols.push_back(l.substr(0, tab));
                    l = tab == std::string_view::npos ? std::string_view{} : l.substr(tab + 1);
                }
                if (cols.empty() || cols[0].empty() || std::find(cols.begin(), cols.end(), "disabled") != cols.end())
                    continue;
                bool member = part.empty();
                for (std::string_view g = cols.size() > 2 ? cols[2] : ""; !member && !g.empty();)
                {
                    const size_t comma = g.find(',');
                    member = trimmed(g.substr(0, comma)) == part;
                    g = comma == std::string_view::npos ? std::string_view{} : g.substr(comma + 1);
                }
                if (!member)
                    continue;
                std::string shown, cmd = "idp-user " + runtime + " show ";
                ipc_frame::append_arg(cmd, std::string(cols[0]));
                if (!daemon(cmd, shown))
                    return 1;
                socketley::json::jvalue& row = rows.emplace_back();
                put(row, "username", std::string(cols[0]));
                for (std::string_view r = shown; !r.empty();)
                {
                    const size_t n2 = r.find('\n');
                    const std::string_view l = r.substr(0, n2);
                    r = n2 == std::string_view::npos ? std::string_view{} : r.substr(n2 + 1);
                    const size_t sep = l.find(": ");
                    if (sep != std::string_view::npos && l.substr(0, sep) != "password")
                        put(row, std::string(l.substr(0, sep)), std::string(l.substr(sep + 2)));
                }
                if (socketley::json::string_of(row, "email").empty() && cols[0].find('@') != std::string_view::npos)
                    put(row, "email", std::string(cols[0]));
            }
            continue;
        }
        std::vector<socketley::json::jvalue> objects;
        // A db's collection, a thousand documents a page, as its API's queries give them.
        if (src.starts_with("db:"))
        {
            if (runtime.empty() || part.empty())
            {
                std::cout << "db:<runtime>/<collection> names the collection after the slash\n";
                return 1;
            }
            for (size_t skip = 0;; skip += 1000)
            {
                std::string page, cmd = "db-query " + runtime + " ";
                ipc_frame::append_arg(cmd, part);
                cmd += ' ';
                ipc_frame::append_arg(cmd, "{\"limit\":1000,\"skip\":" + std::to_string(skip) + "}");
                if (!daemon(cmd, page))
                    return 1;
                socketley::json::jvalue v;
                const socketley::json::jvalue* docs = nullptr;
                if (!socketley::json::json_reader(trimmed_text(page)).document(v) || !(docs = socketley::json::member(v, "docs")))
                {
                    std::cout << "db runtime " << runtime << " gave no documents: " << page.substr(0, 200) << "\n";
                    return 1;
                }
                for (const auto& d : docs->items)
                    objects.push_back(d);
                if (docs->items.size() < 1000)
                    break;
            }
        }
        // A file of the caller's: a JSON array of objects, or JSON Lines, an object a line.
        std::string text;
        socketley::json::jvalue all;
        if (src.starts_with("json:") && !file_arg(src.substr(5), text))
            return 1;
        socketley::json::json_policy any_root;
        any_root.object_root = false;
        if (src.starts_with("json:") && socketley::json::json_reader(trimmed_text(text), any_root).document(all) &&
            all.k == socketley::json::jvalue::kind::array)
            objects = std::move(all.items);
        else if (src.starts_with("json:"))
        {
            std::string_view rest = text;
            while (!rest.empty())
            {
                const size_t nl = rest.find('\n');
                const std::string_view line = trimmed(rest.substr(0, nl));
                rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
                socketley::json::jvalue one;
                if (line.empty())
                    continue;
                if (!socketley::json::json_reader(line).document(one) || one.k != socketley::json::jvalue::kind::object)
                {
                    std::cout << src << " is neither a JSON array of objects nor an object a line\n";
                    return 1;
                }
                objects.push_back(std::move(one));
            }
        }
        for (auto& o : objects)
            if (o.k == socketley::json::jvalue::kind::object)
                rows.push_back(std::move(o));
    }
    if (rows.empty())
    {
        std::cout << "no recipients: the sources named none\n";
        return 1;
    }
    for (auto& row : rows)
        for (const auto& [k, v] : sets)
            if (!socketley::json::member(row, k))
                put(row, k, v);

    // The templates and the script, read and compiled before the first recipient.
    const size_t dir_end = html_path.rfind('/');
    socketley::mail::campaign tpl(c.ad, dir_end == std::string::npos ? "." : html_path.substr(0, dir_end));
    std::string why;
    using part = socketley::mail::campaign::part;
    const bool text_template = have_text || !c.text.empty();
    if ((!script_path.empty() && !tpl.script(script_path, why)) ||
        (!c.subject.empty() && !tpl.add(part::subject, "--subject", c.subject, why)) ||
        (!c.html.empty() && !tpl.add(part::html, html_path, c.html, why)) ||
        (text_template && !tpl.add(part::text, "--text", c.text, why)))
    {
        std::cout << why << "\n";
        return 1;
    }

    using result = socketley::mail::campaign::result;
    // A recipient's message: written, skipped where the script says so, or failed with why where it cannot be
    // written -- no address, Lua that fails, or, unless --no-check, a name without a value.
    const auto message_for = [&](const socketley::json::jvalue& row, socketley::mail::compose& m, std::string& why) {
        socketley::mail::campaign::message f;
        const result r = tpl.fill(row, check, f, why);
        if (r == result::missing)
            why = why == "unsubscribe" ? "{{unsubscribe}} is filled for an advertisement, --ad, alone"
                                       : "nothing fills {{" + why + "}}";
        if (r != result::written)
            return r == result::skipped ? r : result::failed;
        if (f.email.empty() || f.email.find('@') == std::string::npos)
        {
            why = "no email address";
            return result::failed;
        }
        m = c;
        m.to.clear();
        if (f.name.find_first_of("\"\r\n<>") != std::string::npos)
            f.name.clear();
        m.to.push_back(f.name.empty() ? f.email : "\"" + f.name + "\" <" + f.email + ">");
        m.subject = std::move(f.subject);
        m.html = std::move(f.html);
        m.text = text_template ? std::move(f.text) : (m.html.empty() ? std::string() : text_of_html(m.html));
        return result::written;
    };

    socketley::mail::compose m;
    if (dry || !test_to.empty())
    {
        // The first recipient the script does not leave out.
        size_t first = 0;
        result r = result::skipped;
        while (first < rows.size() && (r = message_for(rows[first], m, why)) == result::skipped)
            ++first;
        if (r != result::written)
        {
            std::cout << (first == rows.size() ? "the script left every recipient out" : "the first recipient's message cannot be written: " + why) << "\n";
            return 1;
        }
        if (dry)
        {
            std::cout << "To: " << m.to.front() << "\nSubject: " << m.subject << "\n";
            if (!m.inlines.empty() || !m.attachments.empty())
                std::cout << "Parts: " << m.inlines.size() << " inline, " << m.attachments.size() << " attached\n";
            std::cout << "\n" << m.text << (m.text.ends_with('\n') ? "" : "\n");
            std::cout << "(" << rows.size() << " recipient" << (rows.size() == 1 ? "" : "s") << " in all; nothing sent)\n";
            return 0;
        }
        m.to = {test_to};
        m.subject = "[test] " + m.subject;
        std::string reply;
        const int rc = deliver(argv[2], m, reply);
        if (rc < 0)
            return ipc_report_failure(rc);
        std::cout << reply << (reply.ends_with('\n') ? "" : "\n");
        return rc != 0 || !reply.starts_with("queued") ? 1 : 0;
    }

    // At --rate, the first a check: a first that cannot be written or is refused stops them all, unless --no-check.
    const auto gap = std::chrono::microseconds(static_cast<int64_t>(1e6 / rate));
    auto next = std::chrono::steady_clock::now();
    size_t sent = 0, skipped = 0, failed = 0;
    for (size_t i = 0; i < rows.size(); ++i)
    {
        const auto row_name = [&] {
            const std::string_view e = socketley::json::string_of(rows[i], "email");
            return e.empty() ? "recipient " + std::to_string(i + 1) : std::string(e);
        };
        const bool first = sent + failed == 0;
        const result r = message_for(rows[i], m, why);
        if (r == result::skipped)
        {
            std::cout << "skipped " << row_name() << ": " << why << "\n";
            ++skipped;
            continue;
        }
        if (r != result::written)
        {
            if (check && first)
            {
                std::cout << "stopped before sending: the first recipient's message cannot be written: " << why << "\n";
                return 1;
            }
            std::cout << "skipped " << row_name() << ": " << why << "\n";
            ++skipped;
            continue;
        }
        std::this_thread::sleep_until(next);
        next = std::chrono::steady_clock::now() + gap;
        std::string reply;
        const int rc = deliver(argv[2], m, reply);
        if (rc < 0)
            return ipc_report_failure(rc);
        while (!reply.empty() && reply.back() == '\n')
            reply.pop_back();
        if (rc == 0 && reply.starts_with("queued"))
            ++sent;
        else if (reply.starts_with("skipped"))
        {
            std::cout << "skipped " << row_name() << ": " << reply.substr(reply.find(':') + 2) << "\n";
            ++skipped;
        }
        else
        {
            if (check && first)
            {
                std::cout << "stopped before sending more: the first was refused: " << reply << "\n";
                return 1;
            }
            std::cout << "failed " << row_name() << ": " << reply << "\n";
            ++failed;
        }
    }
    std::cout << "sent " << sent << " of " << rows.size() << (skipped ? ", skipped " + std::to_string(skipped) : "")
              << (failed ? ", failed " + std::to_string(failed) : "") << "\n";
    return failed ? 1 : 0;
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

namespace
{

// `socketley mail <mail>`: what it is and how it is doing, in a few lines.
int cli_mail_overview(const char* runtime)
{
    std::string shown, stats, queue;
    const int rc = ipc_send("show " + std::string(runtime), shown);
    if (rc < 0)
        return ipc_report_failure(rc);
    socketley::json::jvalue cfg;
    if (rc != 0 || !socketley::json::json_reader(shown).document(cfg) || socketley::json::string_of(cfg, "type") != "mail")
    {
        std::cout << (shown.empty() ? "no mail runtime named " + std::string(runtime) + "\n" : shown);
        return 1;
    }
    if (ipc_send("stats " + std::string(runtime), stats) < 0)
        stats.clear();
    std::string qcmd = "mail ";
    ipc_frame::append_arg(qcmd, runtime);
    qcmd += " queue";
    if (ipc_send(qcmd, queue) < 0)
        queue.clear();
    const auto stat = [&stats](std::string_view k) -> std::string {
        for (std::string_view rest = stats; !rest.empty();)
        {
            const size_t nl = rest.find('\n');
            std::string_view line = trimmed(rest.substr(0, nl));
            rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
            if (line.starts_with(k) && line.size() > k.size() && (line[k.size()] == ':' || line[k.size()] == ' '))
                return std::string(trimmed(line.substr(k.size() + 1)));
        }
        return "0";
    };
    const auto cfg_s = [&cfg](std::string_view k) { return std::string(socketley::json::string_of(cfg, k)); };
    const auto cfg_n = [&cfg](std::string_view k) { return socketley::json::int_of(cfg, k, 0); };
    std::string ports = "smtp " + std::to_string(cfg_n("port"));
    for (const char* k : {"submission", "submissions", "imap", "imaps", "pop3", "pop3s", "jmap", "sieve", "lmtp", "web"})
        if (cfg_n(k))
            ports += std::string(", ") + k + " " + std::to_string(cfg_n(k));
    size_t queued = 0;
    for (const char ch : queue)
        queued += ch == '\n';
    std::cout << runtime << ": mail for " << (cfg_s("mail_domain").empty() ? "the zones of " + cfg_s("dns") : cfg_s("mail_domain"))
              << (cfg_s("idp").empty() ? "" : ", users of " + cfg_s("idp"))
              << (cfg_s("storage").empty() ? "" : ", mailboxes in " + cfg_s("storage")) << "\n"
              << "  ports      " << ports << "\n";
    if (!cfg_s("domain").empty() && cfg_n("web"))
        std::cout << "  webmail    " << cfg_s("domain") << " through the entrance\n";
    std::cout << "  queue      " << queued << " message" << (queued == 1 ? "" : "s") << " waiting\n"
              << "  delivered  " << stat("mail_delivered") << ", deferred " << stat("mail_deferred") << ", bounced "
              << stat("mail_bounced") << "\n"
              << "  received   " << stat("mail_received") << ", stored in mailboxes " << stat("mail_stored") << "\n"
              << "  lists      " << stat("mail_suppressed") << " suppressed after a bounce, " << stat("mail_unsubscribed")
              << " unsubscribed\n"
              << "more: socketley mail " << runtime << " queue | dns | suppressed | unsubscribed, socketley stats "
              << runtime << "\n";
    return 0;
}

}   // namespace

// `socketley mail <mail>`, or `socketley mail <mail> queue|show|flush|drop|dns|suppressed|forgive|unsubscribed|
// resubscribe [arg]`.
int cli_mail(int argc, char** argv)
{
    if (argc == 3)
        return cli_mail_overview(argv[2]);
    if (argc < 4)
    {
        std::cerr << command_usage::line("mail");
        return 1;
    }
    const std::string_view verb = argv[3];
    if (verb != "queue" && verb != "show" && verb != "flush" && verb != "drop" && verb != "dns" &&
        verb != "suppressed" && verb != "forgive" && verb != "sieve" && verb != "unsubscribed" &&
        verb != "resubscribe")
    {
        std::cerr << command_usage::line("mail");
        return 1;
    }
    if (verb == "sieve")
        return cli_mail_sieve(argc, argv);
    if ((verb == "show" || verb == "drop" || verb == "forgive" || verb == "resubscribe") && argc < 5)
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
