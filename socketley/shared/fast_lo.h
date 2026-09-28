// The loopback shortcut: a TCP pair with both ends on 127.0.0.1 or ::1 hands each
// send straight to the peer's receive queue in the kernel, skipping TCP/IP,
// the loopback device and its softirq.
#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <string_view>

namespace socketley {

// own: only pairs whose both ends are this daemon's runtimes.
// all: also a local client of any process connecting to a runtime's port, and a
// runtime's own connect to any local listener.
enum class fast_lo_mode { off, own, all };

// The two memory bounds, in bytes, that keep a redirected backlog from growing
// without limit: a per-pair ceiling on the unread backlog and a global budget
// across every pair.
struct fast_lo_limits
{
    uint64_t pair_bytes{4ull << 20};
    uint64_t global_bytes{64ull << 20};
};

// Parses the value of `daemon --fast-lo`; false on anything but own or all.
bool parse_fast_lo_mode(std::string_view v, fast_lo_mode& out);

// Parses `--fast-lo-limit <pair-MiB>,<global-MiB>` into bytes; false on a value
// that is not two positive integers with the global at least the per-pair one.
bool parse_fast_lo_limit(std::string_view v, fast_lo_limits& out);

struct fast_lo_figures;

// What the reconciler's threads last measured, read by fast_lo_now().
struct fast_lo_gauges
{
    std::atomic<uint64_t> on_shortcut{0};
    std::atomic<uint64_t> on_tcp{0};
    std::atomic<uint64_t> held{0};
    std::atomic<uint64_t> over{0};
};

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
    bool start(fast_lo_mode mode, fast_lo_limits limits = {});
    const char* reason() const { return m_reason; }
    // The errno of the step that failed, 0 when none did.
    int error() const { return m_errno; }

private:
    friend fast_lo_figures fast_lo_now();
    bool start_reconciler();
    void stop_reconciler();

    int m_pids{-1};
    int m_socks{-1};
    int m_ports{-1};
    int m_mine{-1};
    int m_state{-1};
    int m_snap{-1};
    int m_ring{-1};
    int m_budget{-1};
    int m_counters{-1};         // per-CPU event counts, indexed by the C_* reasons
    int m_ops{-1};
    int m_msg{-1};
    int m_link{-1};
    int m_stop_fd{-1};          // eventfd the reconciler waits on, wakes it to exit
    unsigned long m_recon{0};   // pthread_t of the reconciler, 0 when none runs
    fast_lo_limits m_limits;
    fast_lo_mode m_mode{fast_lo_mode::off};
    bool m_attached{false};
    fast_lo_gauges m_gauges;
    const char* m_reason{"not started"};
    int m_errno{0};
};

// The shortcut as an operator sees it: the socket gauges and the held bytes
// are as of the reconciler's last measurement, the event counts since start.
struct fast_lo_figures
{
    std::string mode{"off"};      // off, own, all, or unavailable
    std::string reason;           // why it is unavailable
    uint64_t sockets_shortcut{0};
    uint64_t sockets_tcp{0};      // tainted, and sending by TCP for good
    uint64_t entered{0};
    uint64_t tainted_bound{0};    // the peer really held the per-pair bound
    uint64_t tainted_unanswered{0};
    uint64_t tainted_budget{0};
    uint64_t tainted_peer_off{0}; // the peer was not on the shortcut
    uint64_t held_bytes{0};
    uint64_t budget_bytes{0};
    uint64_t pair_bytes{0};
    bool over_budget{false};
};

// A snapshot of this daemon's shortcut, safe from any thread.
fast_lo_figures fast_lo_now();

// The workers the program counts as this daemon's, marked when the supervisor
// forks one and unmarked when it lets one go; no-ops while nothing is attached.
void fast_lo_adopt(int pid);
void fast_lo_release(int pid);

// Exported by a daemon whose shortcut is attached, so its workers know.
inline constexpr const char* fast_lo_env = "SOCKETLEY_FAST_LO";

// Whether this process's daemon attached the shortcut.
bool fast_lo_active();

// Whether a connected socket may be on the shortcut: both ends 127.0.0.1 or ::1.
bool fast_lo_covers(int fd);

}  // namespace socketley
