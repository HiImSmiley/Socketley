#pragma once
// Greylisting: the first message of a sender to a recipient from a network is told to come back, 451 4.7.1, and is
// taken when it does after the delay and within a day, as a server that queues mail does and a run of spam that
// never retries does not; a triplet that came back is let by for 36 days.  Kept in one file every shard reads and
// appends to, so a retry that reaches another shard is known there.  Every call may wait on the disk, so it is made
// from the pool; the calls of threads of one process share what was read.
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace socketley::mail
{

class greylist
{
public:
    explicit greylist(std::string path, int64_t delay_ms = 300000) : m_path(std::move(path)), m_delay_ms(delay_ms) {}

    // The network `ip` is of for greylisting: its /24, or /64 for IPv6, so a sender's pool of servers is one.
    static std::string network_of(std::string_view ip);

    // 0 where the triplet may send now, else how many seconds it is told to wait; one whose memory cannot be read or
    // written is let by, as a greylist that fails must not refuse mail for good.
    int64_t check(std::string_view network, std::string_view sender, std::string_view recipient, int64_t now_ms);

    static constexpr int64_t retry_window_ms = 24ll * 3600 * 1000;
    static constexpr int64_t pass_ms = 36ll * 86400 * 1000;
    static constexpr size_t max_entries = 200000;

private:
    struct entry
    {
        int64_t first_ms{0};
        int64_t passed_ms{0};
    };
    bool read_tail();
    bool append(const std::string& hash, const entry& e);
    void fold(int64_t now_ms);

    std::string m_path;
    int64_t m_delay_ms;
    std::mutex m_mu;
    std::unordered_map<std::string, entry> m_entries;
    uint64_t m_ino{0}, m_read{0}, m_lines{0};
};

}   // namespace socketley::mail
