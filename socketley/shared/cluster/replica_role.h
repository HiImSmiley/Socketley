#pragma once
// A cache replica in a cluster: what the daemon may order it to be, how long an order stands, and what it says about its copy of the data.
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace socketley::cluster
{

// A fenced replica answers no client, a primary takes writes and streams them, a follower copies a primary and answers reads.
enum class replica_mode : uint8_t { fenced = 0, primary = 1, follower = 2 };

const char* mode_name(replica_mode m);

// What one replica says about itself on every lease request, so the leader can tell which copy is the most up to date.
struct replica_report
{
    std::string name;
    // The process this replica is: a restart is a new one, and holds nothing the old one did.
    uint64_t incarnation = 0;
    // The epoch of the primary whose stream the copy came from (the replica's own, on the primary), and how far into it.
    uint64_t epoch  = 0;
    uint64_t offset = 0;
    // Whether it takes writes as the primary right now.
    bool     primary = false;

    bool operator==(const replica_report&) const = default;
};

// The daemon's word to a replica's worker, sent every tick so that its silence is what fences.
struct replica_order
{
    replica_mode mode = replica_mode::fenced;
    // The incarnation the order is for, so one meant for a replica that has since been made again reaches nobody.
    uint64_t incarnation = 0;
    uint64_t epoch       = 0;
    // How long the order stands from when the worker receives it, which is the lease the daemon still holds.
    uint32_t valid_ms = 0;
    // Where a follower dials the primary, as host:port.
    std::string target;

    bool operator==(const replica_order&) const = default;
};

std::string encode(const replica_order& o);
bool        decode(std::string_view data, replica_order& out);

// The worker's half: the role it plays and the copy it holds, with no clock and no socket of its own.
class replica_role
{
public:
    explicit replica_role(uint64_t incarnation) : m_incarnation(incarnation) {}

    struct effect
    {
        replica_mode mode = replica_mode::fenced;
        // A follower that must drop its link and dial again: a different primary, or a newer epoch of the same one.
        bool retarget = false;
    };

    // The daemon's order at `now`; what the worker has to become.
    effect order(const replica_order& o, uint64_t now);

    // What the worker may do right now, which is fenced once the last order has run out.
    replica_mode mode(uint64_t now) const { return now >= m_deadline ? replica_mode::fenced : m_order.mode; }
    // How long the last order still stands.
    uint64_t left_ms(uint64_t now) const { return now < m_deadline ? m_deadline - now : 0; }
    // Whom it follows, and the epoch of that primary, which stay as they were through a fenced order and a lapse,
    // since a fenced follower keeps following.
    bool following() const { return m_following; }
    const std::string& target() const { return m_target; }
    uint64_t follow_epoch() const { return m_follow_epoch; }

    // A dump began arriving, so the copy is a copy of nothing until it ends.
    void sync_started();
    // The dump ended and the primary said it was at `offset` when it took it.
    void sync_done(uint64_t offset);
    // A record was applied from the primary's stream, or produced for it.
    void record() { ++m_offset; }

    uint64_t incarnation() const { return m_incarnation; }
    uint64_t epoch() const { return m_epoch; }
    uint64_t offset() const { return m_offset; }
    bool     syncing() const { return m_syncing; }

private:
    uint64_t      m_incarnation;
    replica_order m_order;
    bool          m_following    = false;
    std::string   m_target;
    uint64_t      m_follow_epoch = 0;
    uint64_t      m_deadline = 0;
    uint64_t      m_epoch    = 0;
    uint64_t      m_offset   = 0;
    bool          m_syncing  = false;
};

// The lines a cache adds to its stats, and the report the daemon reads back out of them.
std::string report_lines(const replica_role& role, uint64_t now);
std::optional<replica_report> parse_report(std::string_view detail, std::string_view name);

}   // namespace socketley::cluster
