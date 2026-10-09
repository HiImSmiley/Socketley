#pragma once
#include <cstdint>
#include <string>
#include <string_view>

// A frame is 0x00 [u32 length] [bytes], sent only when a line cannot carry the
// payload, because 0x00 cannot begin a legacy command.
namespace ipc_frame
{

inline constexpr char     marker      = '\0';
inline constexpr size_t   header_size = 5;          // marker + u32

// Refuse absurd lengths rather than allocate them: 16 MB is far above the
// largest command this protocol carries and far below anything that hurts to
// reject.
inline constexpr uint32_t max_payload = 16u * 1024u * 1024u;

// A newline forces it, and so does a carriage return: the daemon strips a
// trailing '\r', so one mid-payload would arrive altered.
inline bool needs_frame(std::string_view command)
{
    return command.find_first_of("\n\r") != std::string_view::npos;
}

inline std::string encode(std::string_view command)
{
    std::string out;
    out.reserve(header_size + command.size());
    out += marker;
    const uint32_t n = static_cast<uint32_t>(command.size());
    out += static_cast<char>(n & 0xFF);
    out += static_cast<char>((n >> 8) & 0xFF);
    out += static_cast<char>((n >> 16) & 0xFF);
    out += static_cast<char>((n >> 24) & 0xFF);
    out.append(command);
    return out;
}

enum class take { need_more, ok, fatal };

// Without consuming, because erasing per command makes a batched read
// quadratic; `payload` points INTO buf and `next` is only meaningful on ok.
inline take peek_frame(std::string_view buf, size_t off,
                       std::string_view& payload, size_t& next)
{
    if (buf.size() - off < header_size)
        return take::need_more;

    const auto* h = reinterpret_cast<const unsigned char*>(buf.data() + off);
    const uint32_t len =
        static_cast<uint32_t>(h[1])        |
        static_cast<uint32_t>(h[2]) << 8   |
        static_cast<uint32_t>(h[3]) << 16  |
        static_cast<uint32_t>(h[4]) << 24;

    if (len > max_payload)
        return take::fatal;

    if (buf.size() - off < header_size + len)
        return take::need_more;

    payload = buf.substr(off + header_size, len);
    next    = off + header_size + len;
    return take::ok;
}

// `need_more` leaves buf untouched; `fatal` is a length past max_payload, and
// there is no resynchronisation point in a stream whose framing is wrong.
inline take take_frame(std::string& buf, std::string& payload)
{
    std::string_view view;
    size_t           next = 0;
    const take r = peek_frame(buf, 0, view, next);
    if (r != take::ok)
        return r;

    payload.assign(view.data(), view.size());
    buf.erase(0, next);
    return take::ok;
}

// A space inside one argument travels as NUL, which no argv can hold, so the daemon splits only where the shell did.
inline constexpr char space_in_arg = '\0';

// Never the first word: a line that began with NUL would be read as a frame.
inline void append_arg(std::string& command, std::string_view arg)
{
    for (const char c : arg)
        command += c == ' ' ? space_in_arg : c;
}

// After the split, so each argument gets back the spaces it was sent with.
inline void restore_spaces(std::string& line)
{
    for (char& c : line)
        if (c == space_in_arg)
            c = ' ';
}

}   // namespace ipc_frame
