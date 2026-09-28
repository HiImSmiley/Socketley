// The loopback shortcut: a TCP pair with both ends on 127.0.0.1 hands each
// send straight to the peer's receive queue in the kernel, skipping TCP/IP,
// the loopback device and its softirq.
#pragma once

#include <string_view>

namespace socketley {

// own: only pairs whose both ends are this daemon's runtimes.
// all: also a local client of any process connecting to a runtime's port.
enum class fast_lo_mode { off, own, all };

// Parses the value of `daemon --fast-lo`; false on anything but own or all.
bool parse_fast_lo_mode(std::string_view v, fast_lo_mode& out);

// Loads the maps and the two programs and attaches them for as long as this
// object lives; the daemon holds it, and closing it detaches everything.
class fast_lo
{
public:
    fast_lo() = default;
    ~fast_lo();
    fast_lo(const fast_lo&) = delete;
    fast_lo& operator=(const fast_lo&) = delete;

    // True when the shortcut is attached; false with reason() set when not.
    bool start(fast_lo_mode mode);
    const char* reason() const { return m_reason; }

private:
    int m_socks{-1};
    int m_ports{-1};
    int m_mine{-1};
    int m_taint{-1};
    int m_ops{-1};
    int m_msg{-1};
    int m_link{-1};
    const char* m_reason{"not started"};
};

// Exported by a daemon whose shortcut is attached, so its workers know.
inline constexpr const char* fast_lo_env = "SOCKETLEY_FAST_LO";

// Whether this process's daemon attached the shortcut.
bool fast_lo_active();

// Whether a connected socket may be on the shortcut: both ends 127.0.0.1.
bool fast_lo_covers(int fd);

}  // namespace socketley
