#pragma once
#include <cstdint>
#include <string>
#include <string_view>

// ─── HOW A COMMAND THAT CONTAINS A NEWLINE REACHES THE DAEMON ───────────────
//
// The control protocol is one command per line: the CLI writes `create server a
// -p 9000\n`, and the daemon splits its read buffer on every '\n'.  That works
// until a command carries a PAYLOAD — a message, a cache value, a JSON document
// — because the payload's own newlines then end the command and everything
// after them is executed as commands of its own.  Measured:
//
//     printf 'hello\ncreate server INJECTED -p 18709\n' | socketley send victim
//     socketley ls -s
//     INJECTED                     <- came out of the message text
//     victim
//
// Nothing there is malformed.  `send` is documented to take its message on
// standard input, and any data with a line break in it does this.
//
// ─── THE ANSWER, AND WHY IT IS THIS ONE ─────────────────────────────────────
//
// worker_protocol.h already solves exactly this problem in this repository, for
// the daemon-to-worker channel, and says so out loud at its string encoder:
// "Strings carry their own length, so a name with a space or a newline in it
// is" — unproblematic.  This is the same answer for the other channel.
//
// A frame is
//
//     0x00  [u32 length, little endian]  [length bytes]
//
// and the payload is one command, newlines and all.
//
// 0x00 is the marker because it is the one byte that cannot begin a legacy
// command: every command this protocol has ever carried is printable text
// starting with a letter.  So a daemon can tell the two apart by looking at one
// byte, and both forms can travel on the same connection — which is what makes
// this deployable without a flag day.
//
// ─── THE SKEW, WHICH IS REAL AND IS HANDLED BY NOT NEEDING TO BE ────────────
//
// Daemon and CLI are one binary, but a running daemon survives a rebuild — that
// is the case cli.cpp's daemon_exe_was_replaced() exists to report.  So a new
// CLI can meet an old daemon.
//
// It is handled by sending a frame ONLY when the line protocol cannot carry the
// command: no newline, no frame, and every ordinary command is byte-identical
// to what it always was.  An old daemon therefore sees exactly what it used to
// see in every case that used to work.  In the case that did NOT work — a
// payload with a newline — it now receives a frame it does not understand and
// answers nothing instead of executing the tail as commands.  A refusal by
// timeout is a poor answer; executing an injected command is a worse one.
namespace ipc_frame
{

inline constexpr char     marker      = '\0';
inline constexpr size_t   header_size = 5;          // marker + u32

// Refuse absurd lengths rather than trying to allocate them.  16 MB is far
// above any command this protocol carries — the largest by a distance is an
// `import` document — and far below anything that would hurt to reject.
inline constexpr uint32_t max_payload = 16u * 1024u * 1024u;

// Does this command have to be framed?
//
// Only a newline forces it.  A carriage return does too: the daemon strips a
// trailing '\r' from every line, so a command carrying one in the middle of a
// payload would arrive altered.
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

// Read one frame starting at `off`, without consuming anything.
//
// The offset form exists for a reader that processes a whole batch before it
// touches its buffer: erasing per command makes a read carrying many of them
// quadratic in the buffer size, and the replication link on a busy leader
// carries exactly that.  `payload` points INTO buf and stays valid only until
// the caller modifies it — which is the same discipline a line scan over the
// same buffer already has.
//
// `next` is where the frame ends, and is only meaningful when the answer is ok.
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

// Pull one whole frame off the front of `buf`.
//
// `need_more` leaves buf untouched and means exactly that — the caller keeps
// reading.  `fatal` is a length past max_payload: there is no resynchronisation
// point in a stream whose framing is wrong, so the caller closes rather than
// guessing where the next frame starts.
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

}   // namespace ipc_frame
