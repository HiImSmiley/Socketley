#include "mail_mbox.h"

#include <ctime>

#include "imap_store.h"
#include "../../shared/util/ascii.h"

namespace socketley::mail::mbox
{

namespace
{

// Whether `line` is ">*From ", which a reader would take for a message's start once its '>' are gone.
bool from_line(std::string_view line)
{
    size_t i = 0;
    while (i < line.size() && line[i] == '>')
        ++i;
    return line.substr(i).starts_with("From ");
}

int64_t asctime_ms(std::string_view from_line)
{
    // "From <sender> Www Mmm dd hh:mm:ss yyyy", the date after the sender.
    const size_t sp = from_line.find(' ', 5);
    if (sp == std::string_view::npos)
        return 0;
    const std::string date(from_line.substr(sp + 1));
    // Takeout writes the zone before the year, which UTC's +0000 is.
    std::tm tm{};
    if (!::strptime(date.c_str(), "%a %b %d %H:%M:%S +0000 %Y", &tm))
    {
        tm = {};
        if (!::strptime(date.c_str(), "%a %b %d %H:%M:%S %Y", &tm))
            return 0;
    }
    const time_t t = ::timegm(&tm);
    return t > 0 ? static_cast<int64_t>(t) * 1000 : 0;
}

std::string trimmed(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.remove_suffix(1);
    return std::string(s);
}

}   // namespace

std::string entry(std::string_view message, uint8_t flags, const std::vector<std::string>& keywords, int64_t date_ms)
{
    const time_t t = static_cast<time_t>((date_ms > 0 ? date_ms : 0) / 1000);
    std::tm tm{};
    ::gmtime_r(&t, &tm);
    char date[64];
    std::strftime(date, sizeof date, "%a %b %e %H:%M:%S %Y", &tm);
    std::string out = "From MAILER-DAEMON " + std::string(date) + "\n";
    out += flags & flag_seen ? "Status: RO\n" : "Status: O\n";
    std::string x;
    if (flags & flag_answered)
        x += 'A';
    if (flags & flag_flagged)
        x += 'F';
    if (flags & flag_draft)
        x += 'T';
    if (flags & flag_deleted)
        x += 'D';
    if (!x.empty())
        out += "X-Status: " + x + "\n";
    if (!keywords.empty())
    {
        out += "X-Keywords:";
        for (const auto& k : keywords)
            out += " " + k;
        out += "\n";
    }
    for (size_t at = 0; at < message.size();)
    {
        size_t nl = message.find('\n', at);
        const size_t end = nl == std::string_view::npos ? message.size() : nl;
        std::string_view line = message.substr(at, end - at);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (from_line(line))
            out += '>';
        out.append(line);
        out += '\n';
        at = nl == std::string_view::npos ? message.size() : nl + 1;
    }
    out += '\n';
    return out;
}

std::string folder_of_labels(std::string_view labels, uint8_t& flags)
{
    std::vector<std::string> all;
    for (size_t at = 0; at <= labels.size();)
    {
        // A label is quoted where it holds a comma.
        std::string one;
        while (at < labels.size() && labels[at] == ' ')
            ++at;
        if (at < labels.size() && labels[at] == '"')
        {
            const size_t close = labels.find('"', at + 1);
            const size_t len = close == std::string_view::npos ? std::string_view::npos : close - at - 1;
            one = std::string(labels.substr(at + 1, len));
            at = close == std::string_view::npos ? labels.size() : close + 1;
            const size_t comma = labels.find(',', at);
            at = comma == std::string_view::npos ? labels.size() + 1 : comma + 1;
        }
        else
        {
            const size_t comma = labels.find(',', at);
            one = trimmed(labels.substr(at, comma == std::string_view::npos ? std::string_view::npos : comma - at));
            at = comma == std::string_view::npos ? labels.size() + 1 : comma + 1;
        }
        if (!one.empty())
            all.push_back(std::move(one));
    }
    const auto has = [&](std::string_view l) {
        for (const auto& a : all)
            if (socketley::ascii::iequals(a, l))
                return true;
        return false;
    };
    if (!has("Unread"))
        flags = static_cast<uint8_t>(flags | flag_seen);
    if (has("Starred"))
        flags = static_cast<uint8_t>(flags | flag_flagged);
    if (has("Trash"))
        return "Trash";
    if (has("Spam"))
        return "Junk";
    if (has("Drafts") || has("Draft"))
    {
        flags = static_cast<uint8_t>(flags | flag_draft);
        return "Drafts";
    }
    if (has("Sent"))
        return "Sent";
    if (has("Inbox"))
        return "INBOX";
    static constexpr std::string_view system[] = {"Important", "Starred", "Opened", "Unread", "Archived", "Chat"};
    for (const auto& a : all)
    {
        bool sys = a.starts_with("Category ") || a.starts_with("Kategorie ");
        for (const auto s : system)
            sys = sys || socketley::ascii::iequals(a, s);
        if (!sys)
            return a;
    }
    return "Archive";
}

bool next(std::string_view text, size_t& at, bool whole, message& out)
{
    out = {};
    while (at < text.size() && (text[at] == '\n' || text[at] == '\r'))
        ++at;
    if (at >= text.size() || !text.substr(at).starts_with("From "))
        return false;
    const size_t first_nl = text.find('\n', at);
    if (first_nl == std::string_view::npos)
        return false;
    // The next message begins at a line that is "From " itself, never one with a '>' before it.
    size_t end = text.find("\nFrom ", first_nl);
    if (end == std::string_view::npos)
    {
        if (!whole)
            return false;
        end = text.size();
    }
    out.date_ms = asctime_ms(text.substr(at, first_nl - at));
    // A "From " right after the line is an empty message's end; the empty line before a "From " is the mbox's, and
    // the find leaves it out, where at the end of the text it is still to be taken off.
    const bool last = end == text.size();
    const std::string_view body = end <= first_nl ? std::string_view{} : text.substr(first_nl + 1, end - first_nl - 1);
    at = last ? end : end + 1;
    bool in_head = true, dropping = false, in_labels = false, labelled = false;
    std::string labels;
    const auto add = [&](uint8_t f) { out.flags = static_cast<uint8_t>(out.flags | f); };
    for (size_t p = 0; p < body.size();)
    {
        const size_t nl = body.find('\n', p);
        const size_t e = nl == std::string_view::npos ? body.size() : nl;
        std::string_view line = body.substr(p, e - p);
        p = nl == std::string_view::npos ? body.size() : nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        // Every line was given its '>', the header's as well (mboxrd).
        if (!line.empty() && line.front() == '>' && from_line(line))
            line.remove_prefix(1);
        if (in_head && line.empty())
            in_head = false;
        else if (in_head && (line.front() == ' ' || line.front() == '\t'))
        {
            // A folded line goes with the header before it, kept or taken out with it.
            if (in_labels)
                labels += " " + trimmed(line);
            if (dropping)
                continue;
        }
        else if (in_head)
        {
            const size_t colon = line.find(':');
            const std::string_view name = line.substr(0, colon);
            const std::string value = colon == std::string_view::npos ? std::string() : trimmed(line.substr(colon + 1));
            dropping = true;
            in_labels = false;
            if (socketley::ascii::iequals(name, "Status"))
                add(value.find('R') != std::string::npos ? flag_seen : 0);
            else if (socketley::ascii::iequals(name, "X-Status"))
                for (const char c : value)
                    add(c == 'A'   ? flag_answered
                        : c == 'F' ? flag_flagged
                        : c == 'T' ? flag_draft
                        : c == 'D' ? flag_deleted
                                   : 0);
            else if (socketley::ascii::iequals(name, "X-Keywords"))
                for (size_t k = 0; k < value.size();)
                {
                    const size_t stop = value.find(' ', k);
                    std::string w = value.substr(k, stop == std::string::npos ? std::string::npos : stop - k);
                    if (!w.empty())
                        out.keywords.push_back(std::move(w));
                    k = stop == std::string::npos ? value.size() : stop + 1;
                }
            else if (socketley::ascii::iequals(name, "X-Gmail-Labels"))
            {
                labels = value;
                in_labels = labelled = true;
            }
            else
                dropping = false;
            if (dropping)
                continue;
        }
        out.bytes.append(line);
        out.bytes += "\r\n";
    }
    if (last && out.bytes.ends_with("\r\n\r\n"))
        out.bytes.resize(out.bytes.size() - 2);
    if (labelled)
        out.folder = folder_of_labels(labels, out.flags);
    return true;
}

}   // namespace socketley::mail::mbox
