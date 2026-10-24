#pragma once
// What the CLI, a script or a notification asks of a mail runtime, as the request channel carries it: the marker, a
// verb and its fields in byte_codec form, answered in text.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "../../shared/util/byte_codec.h"

namespace socketley::mail
{

inline constexpr std::string_view command_prefix = "\x02skl-mail\n";

enum class verb : uint8_t
{
    send  = 1,
    queue = 2,
    show  = 3,
    flush = 4,
    drop  = 5,
    dns   = 6,
    // The addresses a bounce to no-reply@ said failed, which are not sent to again, and one of them let go.
    suppressed = 7,
    forgive    = 8,
    // A user's Sieve scripts: the argument is the user, the verb, a name and a script's text, a line each.
    sieve      = 9,
    // A message to send too large for the channel, its send command in a file of the runtime's outbox: the
    // argument is the file's name, and the file is gone once it is read.
    send_file  = 10,
    // The addresses that unsubscribed from advertisements, and one of them taken back.
    unsubscribed = 11,
    resubscribe  = 12,
};

struct attachment
{
    std::string name;
    std::string type;
    std::string data;
};

// A message to write and queue, or `raw` a whole one to queue as it is with the envelope `from` and `to`.
struct compose
{
    std::string from;
    std::vector<std::string> to, cc, bcc;
    std::string reply_to;
    std::string subject;
    std::string text;
    std::string html;
    std::vector<std::string> headers;
    std::vector<attachment> attachments;
    std::string raw;
    // A message kept rather than sent, as JMAP makes one: written with its Bcc, and with no recipient yet if it has none.
    bool draft{false};
    // Images the HTML shows by cid:<name>, sent inside the message rather than fetched.
    std::vector<attachment> inlines;
    // An advertisement: to one recipient, not one who unsubscribed, with a link to unsubscribe at {{unsubscribe}}.
    bool ad{false};
};

inline void put_list(socketley::bytes::writer& w, const std::vector<std::string>& v)
{
    w.u32(static_cast<uint32_t>(v.size()));
    for (const auto& s : v)
        w.bytes(s);
}

inline bool get_list(socketley::bytes::reader& r, std::vector<std::string>& v, size_t max_each)
{
    uint32_t n = 0;
    if (!r.u32(n) || n > 10000)
        return false;
    v.resize(n);
    for (auto& s : v)
        if (!r.bytes(s, max_each))
            return false;
    return true;
}

inline std::string command_send(const compose& c)
{
    socketley::bytes::writer w(command_prefix);
    w.u8(static_cast<uint8_t>(verb::send));
    w.bytes(c.from);
    put_list(w, c.to);
    put_list(w, c.cc);
    put_list(w, c.bcc);
    w.bytes(c.reply_to);
    w.bytes(c.subject);
    w.bytes(c.text);
    w.bytes(c.html);
    put_list(w, c.headers);
    w.u32(static_cast<uint32_t>(c.attachments.size()));
    for (const auto& a : c.attachments)
    {
        w.bytes(a.name);
        w.bytes(a.type);
        w.bytes(a.data);
    }
    w.bytes(c.raw);
    w.u32(static_cast<uint32_t>(c.inlines.size()));
    for (const auto& a : c.inlines)
    {
        w.bytes(a.name);
        w.bytes(a.type);
        w.bytes(a.data);
    }
    w.flag(c.ad);
    return w.take();
}

inline bool decode_send(socketley::bytes::reader& r, compose& c, size_t max_size)
{
    uint32_t n = 0;
    if (!r.bytes(c.from, 1024) || !get_list(r, c.to, 1024) || !get_list(r, c.cc, 1024) || !get_list(r, c.bcc, 1024) ||
        !r.bytes(c.reply_to, 1024) || !r.bytes(c.subject, 65536) || !r.bytes(c.text, max_size) ||
        !r.bytes(c.html, max_size) || !get_list(r, c.headers, 65536) || !r.u32(n) || n > 1000)
        return false;
    c.attachments.resize(n);
    for (auto& a : c.attachments)
        if (!r.bytes(a.name, 1024) || !r.bytes(a.type, 256) || !r.bytes(a.data, max_size))
            return false;
    if (!r.bytes(c.raw, max_size) || !r.u32(n) || n > 1000)
        return false;
    c.inlines.resize(n);
    for (auto& a : c.inlines)
        if (!r.bytes(a.name, 1024) || !r.bytes(a.type, 256) || !r.bytes(a.data, max_size))
            return false;
    uint8_t ad = 0;
    if (!r.u8(ad))
        return false;
    c.ad = ad != 0;
    return true;
}

// A verb with one text argument, or none: queue, show, flush, drop.
inline std::string command_text(verb v, std::string_view arg = {})
{
    socketley::bytes::writer w(command_prefix);
    w.u8(static_cast<uint8_t>(v));
    w.bytes(arg);
    return w.take();
}

}   // namespace socketley::mail
