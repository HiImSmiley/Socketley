#include "replica_role.h"

#include "byte_codec.h"

#include <charconv>

namespace socketley::cluster
{

namespace {

constexpr uint8_t order_version = 1;
// A host and a port, so anything longer is a corrupt frame.
constexpr size_t max_target = 300;

bool number(std::string_view text, uint64_t& out)
{
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), out);
    return ec == std::errc{} && end == text.data() + text.size() && !text.empty();
}

}   // namespace

const char* mode_name(replica_mode m)
{
    switch (m)
    {
    case replica_mode::fenced:   return "fenced";
    case replica_mode::primary:  return "primary";
    case replica_mode::follower: return "follower";
    }
    return "fenced";
}

std::string encode(const replica_order& o)
{
    bytes::writer w;
    w.u8(order_version);
    w.u8(static_cast<uint8_t>(o.mode));
    w.u64(o.incarnation);
    w.u64(o.epoch);
    w.u32(o.valid_ms);
    w.bytes(o.target);
    return w.take();
}

bool decode(std::string_view data, replica_order& out)
{
    bytes::reader r(data);
    uint8_t version = 0, mode = 0;
    replica_order o;
    if (!r.u8(version) || version != order_version || !r.u8(mode) || mode > static_cast<uint8_t>(replica_mode::follower)
        || !r.u64(o.incarnation) || !r.u64(o.epoch) || !r.u32(o.valid_ms) || !r.bytes(o.target, max_target) || r.left() != 0)
        return false;
    o.mode = static_cast<replica_mode>(mode);
    // A follower with nobody to follow is a fenced replica, and a primary that follows somebody is not one.
    if ((o.mode == replica_mode::follower) == o.target.empty() && o.mode != replica_mode::fenced)
        return false;
    out = std::move(o);
    return true;
}

replica_role::effect replica_role::order(const replica_order& o, uint64_t now)
{
    effect e;
    // An order for another incarnation, which is one meant for a replica this process has replaced, fences and leaves the rest alone.
    if (o.incarnation != m_incarnation)
    {
        m_order    = replica_order{};
        m_deadline = 0;
        return e;
    }
    if (o.mode == replica_mode::follower)
    {
        e.retarget = !m_following || m_target != o.target || m_follow_epoch != o.epoch;
        m_following    = true;
        m_target       = o.target;
        m_follow_epoch = o.epoch;
    }
    else if (o.mode == replica_mode::primary)
    {
        m_following = false;
    }
    m_order    = o;
    m_deadline = now + o.valid_ms;
    // A follower promoted keeps the offset it had reached and now leads from it, in the epoch it was promoted into, and
    // a dump it was in the middle of is abandoned: what it holds is what the cluster has left of the data.
    if (o.mode == replica_mode::primary)
    {
        m_epoch   = o.epoch;
        m_syncing = false;
    }
    e.mode = mode(now);
    return e;
}

void replica_role::sync_started()
{
    m_syncing = true;
    m_epoch   = 0;
    m_offset  = 0;
}

void replica_role::sync_done(uint64_t offset)
{
    m_syncing = false;
    m_epoch   = m_follow_epoch;
    m_offset  = offset;
}

std::string report_lines(const replica_role& role, uint64_t now)
{
    return "cluster_incarnation:" + std::to_string(role.incarnation()) + "\n"
         + "cluster_epoch:" + std::to_string(role.epoch()) + "\n"
         + "cluster_offset:" + std::to_string(role.offset()) + "\n"
         + "cluster_role:" + mode_name(role.mode(now)) + "\n";
}

std::optional<replica_report> parse_report(std::string_view detail, std::string_view name)
{
    replica_report rep;
    rep.name = std::string(name);
    bool have_inc = false, have_epoch = false, have_offset = false, have_role = false;
    while (!detail.empty())
    {
        const size_t nl = detail.find('\n');
        const std::string_view line = detail.substr(0, nl);
        detail = nl == std::string_view::npos ? std::string_view{} : detail.substr(nl + 1);
        const size_t colon = line.find(':');
        if (colon == std::string_view::npos)
            continue;
        const std::string_view key = line.substr(0, colon), val = line.substr(colon + 1);
        if (key == "cluster_incarnation")
            have_inc = number(val, rep.incarnation);
        else if (key == "cluster_epoch")
            have_epoch = number(val, rep.epoch);
        else if (key == "cluster_offset")
            have_offset = number(val, rep.offset);
        else if (key == "cluster_role")
        {
            have_role  = true;
            rep.primary = val == "primary";
        }
    }
    if (!have_inc || !have_epoch || !have_offset || !have_role || rep.incarnation == 0)
        return std::nullopt;
    return rep;
}

}   // namespace socketley::cluster
