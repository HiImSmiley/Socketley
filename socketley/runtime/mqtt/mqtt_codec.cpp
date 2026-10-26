#include "mqtt_codec.h"

namespace socketley::mqtt
{

const char* packet_name(packet_type t)
{
    switch (t)
    {
        case packet_type::connect:     return "CONNECT";
        case packet_type::connack:     return "CONNACK";
        case packet_type::publish:     return "PUBLISH";
        case packet_type::puback:      return "PUBACK";
        case packet_type::pubrec:      return "PUBREC";
        case packet_type::pubrel:      return "PUBREL";
        case packet_type::pubcomp:     return "PUBCOMP";
        case packet_type::subscribe:   return "SUBSCRIBE";
        case packet_type::suback:      return "SUBACK";
        case packet_type::unsubscribe: return "UNSUBSCRIBE";
        case packet_type::unsuback:    return "UNSUBACK";
        case packet_type::pingreq:     return "PINGREQ";
        case packet_type::pingresp:    return "PINGRESP";
        case packet_type::disconnect:  return "DISCONNECT";
        case packet_type::auth:        return "AUTH";
    }
    return "?";
}

bool properties::empty() const
{
    return !payload_format && !message_expiry && !content_type && !response_topic && !correlation_data &&
           subscription_ids.empty() && !session_expiry && !assigned_client_id && !server_keepalive && !auth_method &&
           !auth_data && !request_problem_info && !will_delay && !request_response_info && !response_info &&
           !server_reference && !reason_string && !receive_maximum && !topic_alias_maximum && !topic_alias &&
           !maximum_qos && !retain_available && user.empty() && !maximum_packet_size && !wildcard_available &&
           !sub_ids_available && !shared_available;
}

// ── Names ───────────────────────────────────────────────────────────────────

bool valid_utf8(std::string_view s)
{
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    const size_t n = s.size();
    size_t i = 0;
    while (i < n)
    {
        const unsigned char c = p[i];
        if (c == 0)
            return false;
        if (c < 0x80)
        {
            ++i;
            continue;
        }
        size_t len = 0;
        unsigned char lo = 0x80, hi = 0xBF;
        if (c >= 0xC2 && c <= 0xDF)
            len = 2;
        else if (c >= 0xE0 && c <= 0xEF)
        {
            len = 3;
            // No overlong form and no surrogate half.
            if (c == 0xE0)
                lo = 0xA0;
            else if (c == 0xED)
                hi = 0x9F;
        }
        else if (c >= 0xF0 && c <= 0xF4)
        {
            len = 4;
            if (c == 0xF0)
                lo = 0x90;
            else if (c == 0xF4)
                hi = 0x8F;
        }
        else
            return false;
        if (i + len > n)
            return false;
        if (p[i + 1] < lo || p[i + 1] > hi)
            return false;
        for (size_t k = 2; k < len; ++k)
            if ((p[i + k] & 0xC0) != 0x80)
                return false;
        i += len;
    }
    return true;
}

bool valid_topic(std::string_view t)
{
    if (t.empty() || t.size() > 65535)
        return false;
    for (const char c : t)
        if (c == '+' || c == '#')
            return false;
    return valid_utf8(t);
}

namespace
{

// A filter without the $share/<group>/ prefix: '#' only as the whole last level, '+' only as a whole level.
bool valid_plain_filter(std::string_view f)
{
    if (f.empty() || f.size() > 65535)
        return false;
    size_t start = 0;
    while (true)
    {
        const size_t slash = f.find('/', start);
        const std::string_view level = f.substr(start, slash == std::string_view::npos ? std::string_view::npos
                                                                                       : slash - start);
        if (level.find('#') != std::string_view::npos && (level != "#" || slash != std::string_view::npos))
            return false;
        if (level.find('+') != std::string_view::npos && level != "+")
            return false;
        if (slash == std::string_view::npos)
            break;
        start = slash + 1;
    }
    return valid_utf8(f);
}

}   // namespace

bool split_shared(std::string_view f, std::string_view& group, std::string_view& filter)
{
    constexpr std::string_view prefix = "$share/";
    if (!f.starts_with(prefix))
        return false;
    const std::string_view rest = f.substr(prefix.size());
    const size_t slash = rest.find('/');
    if (slash == std::string_view::npos)
    {
        group  = rest;
        filter = {};
        return true;
    }
    group  = rest.substr(0, slash);
    filter = rest.substr(slash + 1);
    return true;
}

bool valid_filter(std::string_view f)
{
    std::string_view group, filter;
    if (split_shared(f, group, filter))
    {
        if (group.empty() || group.find_first_of("+#") != std::string_view::npos)
            return false;
        return valid_plain_filter(filter);
    }
    return valid_plain_filter(f);
}

// ── Reading ─────────────────────────────────────────────────────────────────

namespace
{

class reader
{
public:
    explicit reader(std::string_view s) : m_s(s) {}

    size_t left() const { return m_s.size() - m_p; }
    bool done() const { return m_p == m_s.size(); }

    bool u8(uint8_t& v)
    {
        if (left() < 1)
            return false;
        v = static_cast<uint8_t>(m_s[m_p++]);
        return true;
    }
    bool u16(uint16_t& v)
    {
        if (left() < 2)
            return false;
        v = static_cast<uint16_t>((static_cast<uint8_t>(m_s[m_p]) << 8) | static_cast<uint8_t>(m_s[m_p + 1]));
        m_p += 2;
        return true;
    }
    bool u32(uint32_t& v)
    {
        if (left() < 4)
            return false;
        v = 0;
        for (int i = 0; i < 4; ++i)
            v = (v << 8) | static_cast<uint8_t>(m_s[m_p + i]);
        m_p += 4;
        return true;
    }
    bool varint(uint32_t& v)
    {
        v = 0;
        for (int i = 0; i < 4; ++i)
        {
            uint8_t b = 0;
            if (!u8(b))
                return false;
            v |= static_cast<uint32_t>(b & 0x7F) << (7 * i);
            if (!(b & 0x80))
                return true;
        }
        return false;
    }
    bool binary(std::string& out)
    {
        uint16_t n = 0;
        if (!u16(n) || left() < n)
            return false;
        out.assign(m_s.data() + m_p, n);
        m_p += n;
        return true;
    }
    bool utf8(std::string& out) { return binary(out) && valid_utf8(out); }
    std::string_view take(size_t n)
    {
        const std::string_view v = m_s.substr(m_p, n);
        m_p += v.size();
        return v;
    }
    std::string_view rest() { return take(left()); }

private:
    std::string_view m_s;
    size_t           m_p{0};
};

bool fail(refusal& err, uint8_t code, std::string why)
{
    err.code = code;
    err.why  = std::move(why);
    return false;
}

// Where a property set is read, which decides the identifiers it may hold.
enum class ctx : uint8_t { connect, connack, publish, will, ack, subscribe, suback, unsubscribe, unsuback, disconnect,
                           auth };

constexpr uint64_t bit(uint8_t id) { return uint64_t{1} << id; }

uint64_t allowed(ctx c)
{
    constexpr uint64_t user = bit(0x26);
    switch (c)
    {
        case ctx::connect:
            return user | bit(0x11) | bit(0x15) | bit(0x16) | bit(0x17) | bit(0x19) | bit(0x21) | bit(0x22) |
                   bit(0x27);
        case ctx::connack:
            return user | bit(0x11) | bit(0x12) | bit(0x13) | bit(0x15) | bit(0x16) | bit(0x1A) | bit(0x1C) |
                   bit(0x1F) | bit(0x21) | bit(0x22) | bit(0x24) | bit(0x25) | bit(0x27) | bit(0x28) | bit(0x29) |
                   bit(0x2A);
        case ctx::publish:
            return user | bit(0x01) | bit(0x02) | bit(0x03) | bit(0x08) | bit(0x09) | bit(0x0B) | bit(0x23);
        case ctx::will:
            return user | bit(0x01) | bit(0x02) | bit(0x03) | bit(0x08) | bit(0x09) | bit(0x18);
        case ctx::ack:
        case ctx::suback:
        case ctx::unsuback:
            return user | bit(0x1F);
        case ctx::subscribe:
            return user | bit(0x0B);
        case ctx::unsubscribe:
            return user;
        case ctx::disconnect:
            return user | bit(0x11) | bit(0x1C) | bit(0x1F);
        case ctx::auth:
            return user | bit(0x15) | bit(0x16) | bit(0x1F);
    }
    return 0;
}

bool read_properties(reader& r, ctx c, properties& p, refusal& err)
{
    uint32_t len = 0;
    if (!r.varint(len) || len > r.left())
        return fail(err, reason::malformed, "the property length runs past the packet");
    reader pr(r.take(len));
    const uint64_t ok = allowed(c);
    uint64_t seen = 0;
    while (!pr.done())
    {
        uint32_t id = 0;
        if (!pr.varint(id))
            return fail(err, reason::malformed, "a property identifier is cut off");
        if (id > 0x2A || !(ok & bit(static_cast<uint8_t>(id))))
            return fail(err, id > 0x2A ? reason::malformed : reason::protocol_error,
                        "property " + std::to_string(id) + " is not one this packet carries");
        const bool repeats = id == 0x26 || (id == 0x0B && c == ctx::publish);
        if (!repeats && (seen & bit(static_cast<uint8_t>(id))))
            return fail(err, reason::protocol_error, "property " + std::to_string(id) + " is given twice");
        seen |= bit(static_cast<uint8_t>(id));
        auto byte = [&](std::optional<uint8_t>& v, uint8_t max) {
            uint8_t b = 0;
            if (!pr.u8(b))
                return fail(err, reason::malformed, "a property value is cut off");
            if (b > max)
                return fail(err, reason::protocol_error, "property " + std::to_string(id) + " is out of range");
            v = b;
            return true;
        };
        auto two = [&](std::optional<uint16_t>& v, bool nonzero) {
            uint16_t b = 0;
            if (!pr.u16(b))
                return fail(err, reason::malformed, "a property value is cut off");
            if (nonzero && b == 0)
                return fail(err, reason::protocol_error, "property " + std::to_string(id) + " is zero");
            v = b;
            return true;
        };
        auto four = [&](std::optional<uint32_t>& v, bool nonzero) {
            uint32_t b = 0;
            if (!pr.u32(b))
                return fail(err, reason::malformed, "a property value is cut off");
            if (nonzero && b == 0)
                return fail(err, reason::protocol_error, "property " + std::to_string(id) + " is zero");
            v = b;
            return true;
        };
        auto text = [&](std::optional<std::string>& v) {
            std::string s;
            if (!pr.utf8(s))
                return fail(err, reason::malformed, "property " + std::to_string(id) + " is no UTF-8 string");
            v = std::move(s);
            return true;
        };
        auto data = [&](std::optional<std::string>& v) {
            std::string s;
            if (!pr.binary(s))
                return fail(err, reason::malformed, "a property value is cut off");
            v = std::move(s);
            return true;
        };
        bool good = true;
        switch (id)
        {
            case 0x01: good = byte(p.payload_format, 1); break;
            case 0x02: good = four(p.message_expiry, false); break;
            case 0x03: good = text(p.content_type); break;
            case 0x08: good = text(p.response_topic); break;
            case 0x09: good = data(p.correlation_data); break;
            case 0x0B:
            {
                uint32_t v = 0;
                if (!pr.varint(v))
                    return fail(err, reason::malformed, "a subscription identifier is cut off");
                if (v == 0)
                    return fail(err, reason::protocol_error, "a subscription identifier is zero");
                p.subscription_ids.push_back(v);
                break;
            }
            case 0x11: good = four(p.session_expiry, false); break;
            case 0x12: good = text(p.assigned_client_id); break;
            case 0x13: good = two(p.server_keepalive, false); break;
            case 0x15: good = text(p.auth_method); break;
            case 0x16: good = data(p.auth_data); break;
            case 0x17: good = byte(p.request_problem_info, 1); break;
            case 0x18: good = four(p.will_delay, false); break;
            case 0x19: good = byte(p.request_response_info, 1); break;
            case 0x1A: good = text(p.response_info); break;
            case 0x1C: good = text(p.server_reference); break;
            case 0x1F: good = text(p.reason_string); break;
            case 0x21: good = two(p.receive_maximum, true); break;
            case 0x22: good = two(p.topic_alias_maximum, false); break;
            case 0x23: good = two(p.topic_alias, true); break;
            case 0x24: good = byte(p.maximum_qos, 1); break;
            case 0x25: good = byte(p.retain_available, 1); break;
            case 0x26:
            {
                std::string k, v;
                if (!pr.utf8(k) || !pr.utf8(v))
                    return fail(err, reason::malformed, "a user property is no pair of UTF-8 strings");
                p.user.emplace_back(std::move(k), std::move(v));
                break;
            }
            case 0x27: good = four(p.maximum_packet_size, true); break;
            case 0x28: good = byte(p.wildcard_available, 1); break;
            case 0x29: good = byte(p.sub_ids_available, 1); break;
            case 0x2A: good = byte(p.shared_available, 1); break;
            default:
                return fail(err, reason::malformed, "property " + std::to_string(id) + " is not one this packet carries");
        }
        if (!good)
            return false;
    }
    return true;
}

bool check_flags(const frame& f, uint8_t want, refusal& err)
{
    if (f.flags != want)
        return fail(err, reason::malformed, std::string("the reserved bits of ") + packet_name(f.type) + " are wrong");
    return true;
}

}   // namespace

frame_status take_frame(std::string_view in, uint32_t max_size, frame& out)
{
    if (in.empty())
        return frame_status::incomplete;
    const auto first = static_cast<uint8_t>(in[0]);
    const uint8_t type = first >> 4;
    if (type == 0)
        return frame_status::malformed;
    uint32_t remaining = 0;
    size_t i = 1;
    for (int k = 0;; ++k)
    {
        if (k == 4)
            return frame_status::malformed;
        if (i >= in.size())
            return frame_status::incomplete;
        const auto b = static_cast<uint8_t>(in[i++]);
        remaining |= static_cast<uint32_t>(b & 0x7F) << (7 * k);
        if (!(b & 0x80))
            break;
    }
    const size_t total = i + remaining;
    if (max_size && total > max_size)
        return frame_status::too_large;
    if (in.size() < total)
        return frame_status::incomplete;
    out.type  = static_cast<packet_type>(type);
    out.flags = first & 0x0F;
    out.body  = in.substr(i, remaining);
    out.size  = total;
    return frame_status::ok;
}

bool read_connect(const frame& f, connect_packet& out, refusal& err)
{
    out = connect_packet{};
    if (!check_flags(f, 0, err))
        return false;
    reader r(f.body);
    std::string name;
    uint8_t level = 0, flags = 0;
    if (!r.utf8(name) || !r.u8(level))
        return fail(err, reason::malformed, "the CONNECT's protocol name is cut off");
    out.level = level;
    if (!((name == "MQTT" && (level == level_311 || level == level_5)) || (name == "MQIsdp" && level == level_31)))
    {
        if (name != "MQTT" && name != "MQIsdp")
            return fail(err, reason::malformed, "the protocol is " + name + ", not MQTT");
        return fail(err, reason::unsupported_version, "protocol level " + std::to_string(level) + " is not served");
    }
    if (!r.u8(flags) || !r.u16(out.keepalive))
        return fail(err, reason::malformed, "the CONNECT's flags are cut off");
    if (flags & 0x01)
        return fail(err, reason::malformed, "the CONNECT's reserved flag is set");
    out.clean_start = flags & 0x02;
    const bool will = flags & 0x04;
    const uint8_t will_qos = (flags >> 3) & 0x03;
    const bool will_retain = flags & 0x20;
    const bool has_password = flags & 0x40;
    const bool has_user = flags & 0x80;
    if (will_qos == 3 || (!will && (will_qos || will_retain)))
        return fail(err, reason::malformed, "the CONNECT's will flags contradict each other");
    if (level < level_5 && has_password && !has_user)
        return fail(err, reason::malformed, "a password without a user name");
    if (level == level_5 && !read_properties(r, ctx::connect, out.props, err))
        return false;
    if (!r.binary(out.client_id))
        return fail(err, reason::malformed, "the client identifier is cut off");
    if (!valid_utf8(out.client_id))
        return fail(err, reason::client_id_invalid, "the client identifier is no UTF-8 string");
    if (will)
    {
        will_message w;
        w.qos    = will_qos;
        w.retain = will_retain;
        if (level == level_5 && !read_properties(r, ctx::will, w.props, err))
            return false;
        if (!r.utf8(w.topic))
            return fail(err, reason::malformed, "the will topic is cut off");
        if (!valid_topic(w.topic))
            return fail(err, reason::topic_name_invalid, "the will topic is no topic name");
        if (!r.binary(w.payload))
            return fail(err, reason::malformed, "the will message is cut off");
        out.will = std::move(w);
    }
    if (has_user)
    {
        std::string u;
        if (!r.utf8(u))
            return fail(err, reason::malformed, "the user name is no UTF-8 string");
        out.username = std::move(u);
    }
    if (has_password)
    {
        std::string p;
        if (!r.binary(p))
            return fail(err, reason::malformed, "the password is cut off");
        out.password = std::move(p);
    }
    if (!r.done())
        return fail(err, reason::malformed, "bytes follow the CONNECT's last field");
    return true;
}

// What a reader writes into is cleared field by field, since assigning a fresh packet moves every property of
// one that is empty, and that was the largest cost of a PUBACK.
static void clear_props(properties& p)
{
    if (!p.empty())
        p = properties{};
}

bool read_publish(const frame& f, uint8_t level, publish_packet& out, refusal& err)
{
    out.topic.clear();
    out.payload.clear();
    out.packet_id = 0;
    clear_props(out.props);
    out.dup    = f.flags & 0x08;
    out.qos    = (f.flags >> 1) & 0x03;
    out.retain = f.flags & 0x01;
    if (out.qos == 3)
        return fail(err, reason::malformed, "a PUBLISH of QoS 3");
    if (out.qos == 0 && out.dup)
        return fail(err, reason::malformed, "a QoS 0 PUBLISH marked as a repeat");
    reader r(f.body);
    if (!r.utf8(out.topic))
        return fail(err, reason::malformed, "the PUBLISH's topic is no UTF-8 string");
    if (out.topic.find_first_of("+#") != std::string::npos)
        return fail(err, reason::topic_name_invalid, "a PUBLISH to a wildcard");
    if (out.topic.empty() && level < level_5)
        return fail(err, reason::topic_name_invalid, "a PUBLISH without a topic");
    if (out.qos > 0)
    {
        if (!r.u16(out.packet_id))
            return fail(err, reason::malformed, "the PUBLISH's packet identifier is cut off");
        if (out.packet_id == 0)
            return fail(err, reason::protocol_error, "a PUBLISH with packet identifier 0");
    }
    if (level == level_5 && !read_properties(r, ctx::publish, out.props, err))
        return false;
    out.payload.assign(r.rest());
    return true;
}

bool read_ack(const frame& f, uint8_t level, ack_packet& out, refusal& err)
{
    out.packet_id = 0;
    out.reason = reason::success;
    clear_props(out.props);
    out.type = f.type;
    if (!check_flags(f, f.type == packet_type::pubrel ? 0x02 : 0x00, err))
        return false;
    reader r(f.body);
    if (!r.u16(out.packet_id))
        return fail(err, reason::malformed, "the packet identifier is cut off");
    if (out.packet_id == 0)
        return fail(err, reason::protocol_error, "packet identifier 0");
    if (level < level_5)
    {
        if (!r.done())
            return fail(err, reason::malformed, "bytes follow the packet identifier");
        return true;
    }
    if (r.done())
        return true;
    if (!r.u8(out.reason))
        return fail(err, reason::malformed, "the reason code is cut off");
    if (r.done())
        return true;
    if (!read_properties(r, ctx::ack, out.props, err))
        return false;
    if (!r.done())
        return fail(err, reason::malformed, "bytes follow the properties");
    return true;
}

bool read_subscribe(const frame& f, uint8_t level, subscribe_packet& out, refusal& err)
{
    out = subscribe_packet{};
    if (!check_flags(f, 0x02, err))
        return false;
    reader r(f.body);
    if (!r.u16(out.packet_id))
        return fail(err, reason::malformed, "the SUBSCRIBE's packet identifier is cut off");
    if (out.packet_id == 0)
        return fail(err, reason::protocol_error, "a SUBSCRIBE with packet identifier 0");
    if (level == level_5 && !read_properties(r, ctx::subscribe, out.props, err))
        return false;
    while (!r.done())
    {
        subscription s;
        uint8_t opts = 0;
        if (!r.utf8(s.filter) || !r.u8(opts))
            return fail(err, reason::malformed, "a SUBSCRIBE entry is cut off");
        s.qos = opts & 0x03;
        if (s.qos == 3)
            return fail(err, reason::malformed, "a subscription of QoS 3");
        if (level < level_5)
        {
            if (opts & 0xFC)
                return fail(err, reason::malformed, "the reserved bits of a subscription are set");
        }
        else
        {
            s.no_local            = opts & 0x04;
            s.retain_as_published = opts & 0x08;
            s.retain_handling     = (opts >> 4) & 0x03;
            if (s.retain_handling == 3 || (opts & 0xC0))
                return fail(err, reason::malformed, "the reserved bits of a subscription are set");
        }
        out.entries.push_back(std::move(s));
    }
    if (out.entries.empty())
        return fail(err, reason::protocol_error, "a SUBSCRIBE without a filter");
    return true;
}

bool read_unsubscribe(const frame& f, uint8_t level, unsubscribe_packet& out, refusal& err)
{
    out = unsubscribe_packet{};
    if (!check_flags(f, 0x02, err))
        return false;
    reader r(f.body);
    if (!r.u16(out.packet_id))
        return fail(err, reason::malformed, "the UNSUBSCRIBE's packet identifier is cut off");
    if (out.packet_id == 0)
        return fail(err, reason::protocol_error, "an UNSUBSCRIBE with packet identifier 0");
    if (level == level_5 && !read_properties(r, ctx::unsubscribe, out.props, err))
        return false;
    while (!r.done())
    {
        std::string filter;
        if (!r.utf8(filter))
            return fail(err, reason::malformed, "an UNSUBSCRIBE filter is cut off");
        out.filters.push_back(std::move(filter));
    }
    if (out.filters.empty())
        return fail(err, reason::protocol_error, "an UNSUBSCRIBE without a filter");
    return true;
}

bool read_disconnect(const frame& f, uint8_t level, disconnect_packet& out, refusal& err)
{
    out = disconnect_packet{};
    if (!check_flags(f, 0, err))
        return false;
    reader r(f.body);
    if (level < level_5)
    {
        if (!r.done())
            return fail(err, reason::malformed, "a DISCONNECT with a body");
        return true;
    }
    if (r.done())
        return true;
    if (!r.u8(out.reason))
        return fail(err, reason::malformed, "the reason code is cut off");
    if (r.done())
        return true;
    if (!read_properties(r, ctx::disconnect, out.props, err))
        return false;
    if (!r.done())
        return fail(err, reason::malformed, "bytes follow the properties");
    return true;
}

bool read_auth(const frame& f, uint8_t level, auth_packet& out, refusal& err)
{
    out = auth_packet{};
    if (level < level_5)
        return fail(err, reason::malformed, "AUTH is a packet of MQTT 5 only");
    if (!check_flags(f, 0, err))
        return false;
    reader r(f.body);
    if (r.done())
        return true;
    if (!r.u8(out.reason))
        return fail(err, reason::malformed, "the reason code is cut off");
    if (!read_properties(r, ctx::auth, out.props, err))
        return false;
    if (!r.done())
        return fail(err, reason::malformed, "bytes follow the properties");
    return true;
}

bool read_empty(const frame& f, refusal& err)
{
    if (!check_flags(f, 0, err))
        return false;
    if (!f.body.empty())
        return fail(err, reason::malformed, std::string("a ") + packet_name(f.type) + " with a body");
    return true;
}

bool read_connack(const frame& f, uint8_t level, connack_packet& out, refusal& err)
{
    out = connack_packet{};
    if (!check_flags(f, 0, err))
        return false;
    reader r(f.body);
    uint8_t ack = 0;
    if (!r.u8(ack) || !r.u8(out.reason))
        return fail(err, reason::malformed, "the CONNACK is cut off");
    if (ack & 0xFE)
        return fail(err, reason::malformed, "the CONNACK's reserved flags are set");
    out.session_present = ack & 0x01;
    if (level == level_5 && !r.done() && !read_properties(r, ctx::connack, out.props, err))
        return false;
    if (!r.done())
        return fail(err, reason::malformed, "bytes follow the CONNACK");
    return true;
}

bool read_suback(const frame& f, uint8_t level, suback_packet& out, refusal& err)
{
    out = suback_packet{};
    out.type = f.type;
    if (!check_flags(f, 0, err))
        return false;
    reader r(f.body);
    if (!r.u16(out.packet_id))
        return fail(err, reason::malformed, "the packet identifier is cut off");
    if (level == level_5 &&
        !read_properties(r, f.type == packet_type::suback ? ctx::suback : ctx::unsuback, out.props, err))
        return false;
    while (!r.done())
    {
        uint8_t code = 0;
        r.u8(code);
        out.reasons.push_back(code);
    }
    return true;
}

// ── Writing ─────────────────────────────────────────────────────────────────

namespace
{

void put_u16(std::string& out, uint16_t v)
{
    out.push_back(static_cast<char>(v >> 8));
    out.push_back(static_cast<char>(v & 0xFF));
}

void put_u32(std::string& out, uint32_t v)
{
    for (int i = 3; i >= 0; --i)
        out.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
}

void put_varint(std::string& out, uint32_t v)
{
    do
    {
        uint8_t b = v & 0x7F;
        v >>= 7;
        if (v)
            b |= 0x80;
        out.push_back(static_cast<char>(b));
    } while (v);
}

size_t varint_size(uint32_t v)
{
    return v < 128 ? 1 : v < 16384 ? 2 : v < 2097152 ? 3 : 4;
}

void put_str(std::string& out, std::string_view s)
{
    put_u16(out, static_cast<uint16_t>(s.size()));
    out.append(s);
}

void put_properties_body(std::string& out, const properties& p)
{
    auto b1 = [&](uint8_t id, const std::optional<uint8_t>& v) {
        if (v)
        {
            out.push_back(static_cast<char>(id));
            out.push_back(static_cast<char>(*v));
        }
    };
    auto b2 = [&](uint8_t id, const std::optional<uint16_t>& v) {
        if (v)
        {
            out.push_back(static_cast<char>(id));
            put_u16(out, *v);
        }
    };
    auto b4 = [&](uint8_t id, const std::optional<uint32_t>& v) {
        if (v)
        {
            out.push_back(static_cast<char>(id));
            put_u32(out, *v);
        }
    };
    auto bs = [&](uint8_t id, const std::optional<std::string>& v) {
        if (v)
        {
            out.push_back(static_cast<char>(id));
            put_str(out, *v);
        }
    };
    b1(0x01, p.payload_format);
    b4(0x02, p.message_expiry);
    bs(0x03, p.content_type);
    bs(0x08, p.response_topic);
    bs(0x09, p.correlation_data);
    for (const uint32_t id : p.subscription_ids)
    {
        out.push_back(0x0B);
        put_varint(out, id);
    }
    b4(0x11, p.session_expiry);
    bs(0x12, p.assigned_client_id);
    b2(0x13, p.server_keepalive);
    bs(0x15, p.auth_method);
    bs(0x16, p.auth_data);
    b1(0x17, p.request_problem_info);
    b4(0x18, p.will_delay);
    b1(0x19, p.request_response_info);
    bs(0x1A, p.response_info);
    bs(0x1C, p.server_reference);
    bs(0x1F, p.reason_string);
    b2(0x21, p.receive_maximum);
    b2(0x22, p.topic_alias_maximum);
    b2(0x23, p.topic_alias);
    b1(0x24, p.maximum_qos);
    b1(0x25, p.retain_available);
    for (const auto& [k, v] : p.user)
    {
        out.push_back(0x26);
        put_str(out, k);
        put_str(out, v);
    }
    b4(0x27, p.maximum_packet_size);
    b1(0x28, p.wildcard_available);
    b1(0x29, p.sub_ids_available);
    b1(0x2A, p.shared_available);
}

void put_properties(std::string& out, const properties& p)
{
    std::string body;
    put_properties_body(body, p);
    put_varint(out, static_cast<uint32_t>(body.size()));
    out += body;
}

size_t properties_size(const properties& p)
{
    std::string body;
    put_properties_body(body, p);
    return varint_size(static_cast<uint32_t>(body.size())) + body.size();
}

// The fixed header and the body that `fill` writes, its length known only once it is written.
template <class F>
void packet(std::string& out, uint8_t first, F&& fill)
{
    std::string body;
    fill(body);
    out.push_back(static_cast<char>(first));
    put_varint(out, static_cast<uint32_t>(body.size()));
    out += body;
}

// The 3.1.1 CONNACK return code nearest a 5.0 reason.
uint8_t v3_connack_code(uint8_t r)
{
    switch (r)
    {
        case reason::success:              return 0;
        case reason::unsupported_version:  return 1;
        case reason::client_id_invalid:    return 2;
        case reason::server_unavailable:
        case reason::server_busy:          return 3;
        case reason::bad_user_or_password: return 4;
        case reason::not_authorized:       return 5;
        default:                           return 3;
    }
}

}   // namespace

void write_connect(std::string& out, const connect_packet& p)
{
    packet(out, 0x10, [&](std::string& b) {
        put_str(b, p.level == level_31 ? "MQIsdp" : "MQTT");
        b.push_back(static_cast<char>(p.level));
        uint8_t flags = 0;
        if (p.clean_start)
            flags |= 0x02;
        if (p.will)
        {
            flags |= 0x04;
            flags |= static_cast<uint8_t>((p.will->qos & 0x03) << 3);
            if (p.will->retain)
                flags |= 0x20;
        }
        if (p.password)
            flags |= 0x40;
        if (p.username)
            flags |= 0x80;
        b.push_back(static_cast<char>(flags));
        put_u16(b, p.keepalive);
        if (p.level == level_5)
            put_properties(b, p.props);
        put_str(b, p.client_id);
        if (p.will)
        {
            if (p.level == level_5)
                put_properties(b, p.will->props);
            put_str(b, p.will->topic);
            put_str(b, p.will->payload);
        }
        if (p.username)
            put_str(b, *p.username);
        if (p.password)
            put_str(b, *p.password);
    });
}

void write_connack(std::string& out, uint8_t level, const connack_packet& p)
{
    packet(out, 0x20, [&](std::string& b) {
        b.push_back(p.session_present ? 1 : 0);
        if (level < level_5)
        {
            b.push_back(static_cast<char>(v3_connack_code(p.reason)));
            return;
        }
        b.push_back(static_cast<char>(p.reason));
        put_properties(b, p.props);
    });
}

size_t publish_size(uint8_t level, const publish_packet& p)
{
    size_t body = 2 + p.topic.size() + (p.qos ? 2 : 0) + p.payload.size();
    if (level == level_5)
        body += properties_size(p.props);
    return 1 + varint_size(static_cast<uint32_t>(body)) + body;
}

void write_publish(std::string& out, uint8_t level, const publish_packet& p)
{
    uint8_t first = 0x30 | static_cast<uint8_t>((p.qos & 0x03) << 1);
    if (p.dup)
        first |= 0x08;
    if (p.retain)
        first |= 0x01;
    size_t body = 2 + p.topic.size() + (p.qos ? 2 : 0) + p.payload.size();
    std::string props;
    if (level == level_5)
    {
        put_properties(props, p.props);
        body += props.size();
    }
    out.reserve(out.size() + 1 + varint_size(static_cast<uint32_t>(body)) + body);
    out.push_back(static_cast<char>(first));
    put_varint(out, static_cast<uint32_t>(body));
    put_str(out, p.topic);
    if (p.qos)
        put_u16(out, p.packet_id);
    out += props;
    out += p.payload;
}

size_t publish_parts_size(uint8_t level, const publish_parts& p)
{
    size_t body = 2 + p.topic.size() + (p.qos ? 2 : 0) + p.payload.size();
    if (level == level_5)
        body += varint_size(static_cast<uint32_t>(p.props.size())) + p.props.size();
    return 1 + varint_size(static_cast<uint32_t>(body)) + body;
}

void write_publish_head(std::string& out, uint8_t level, const publish_parts& p)
{
    uint8_t first = 0x30 | static_cast<uint8_t>((p.qos & 0x03) << 1);
    if (p.dup)
        first |= 0x08;
    if (p.retain)
        first |= 0x01;
    size_t body = 2 + p.topic.size() + (p.qos ? 2 : 0) + p.payload.size();
    if (level == level_5)
        body += varint_size(static_cast<uint32_t>(p.props.size())) + p.props.size();
    out.reserve(out.size() + 1 + varint_size(static_cast<uint32_t>(body)) + body - p.payload.size());
    out.push_back(static_cast<char>(first));
    put_varint(out, static_cast<uint32_t>(body));
    put_str(out, p.topic);
    if (p.qos)
        put_u16(out, p.packet_id);
    if (level == level_5)
    {
        put_varint(out, static_cast<uint32_t>(p.props.size()));
        out += p.props;
    }
}

void write_publish_parts(std::string& out, uint8_t level, const publish_parts& p)
{
    out.reserve(out.size() + publish_parts_size(level, p));
    write_publish_head(out, level, p);
    out += p.payload;
}

void put_prop_byte(std::string& out, uint8_t id, uint8_t v)
{
    out.push_back(static_cast<char>(id));
    out.push_back(static_cast<char>(v));
}

void put_prop_u32(std::string& out, uint8_t id, uint32_t v)
{
    out.push_back(static_cast<char>(id));
    put_u32(out, v);
}

void put_prop_varint(std::string& out, uint8_t id, uint32_t v)
{
    out.push_back(static_cast<char>(id));
    put_varint(out, v);
}

void put_prop_str(std::string& out, uint8_t id, std::string_view v)
{
    out.push_back(static_cast<char>(id));
    put_str(out, v);
}

void put_prop_pair(std::string& out, uint8_t id, std::string_view k, std::string_view v)
{
    out.push_back(static_cast<char>(id));
    put_str(out, k);
    put_str(out, v);
}

void write_ack(std::string& out, uint8_t level, const ack_packet& p)
{
    const uint8_t first = static_cast<uint8_t>(static_cast<uint8_t>(p.type) << 4) |
                          (p.type == packet_type::pubrel ? 0x02 : 0x00);
    packet(out, first, [&](std::string& b) {
        put_u16(b, p.packet_id);
        if (level < level_5 || (p.reason == reason::success && p.props.empty()))
            return;
        b.push_back(static_cast<char>(p.reason));
        if (!p.props.empty())
            put_properties(b, p.props);
    });
}

void write_subscribe(std::string& out, uint8_t level, const subscribe_packet& p)
{
    packet(out, 0x82, [&](std::string& b) {
        put_u16(b, p.packet_id);
        if (level == level_5)
            put_properties(b, p.props);
        for (const auto& e : p.entries)
        {
            put_str(b, e.filter);
            uint8_t opts = e.qos & 0x03;
            if (level == level_5)
            {
                if (e.no_local)
                    opts |= 0x04;
                if (e.retain_as_published)
                    opts |= 0x08;
                opts |= static_cast<uint8_t>((e.retain_handling & 0x03) << 4);
            }
            b.push_back(static_cast<char>(opts));
        }
    });
}

void write_suback(std::string& out, uint8_t level, const suback_packet& p)
{
    const bool sub = p.type == packet_type::suback;
    packet(out, sub ? 0x90 : 0xB0, [&](std::string& b) {
        put_u16(b, p.packet_id);
        if (level < level_5)
        {
            // 3.1.1's UNSUBACK has no codes, and its SUBACK one failure code.
            if (sub)
                for (const uint8_t r : p.reasons)
                    b.push_back(static_cast<char>(r >= 0x80 ? 0x80 : r));
            return;
        }
        put_properties(b, p.props);
        for (const uint8_t r : p.reasons)
            b.push_back(static_cast<char>(r));
    });
}

void write_pingresp(std::string& out)
{
    out.push_back(static_cast<char>(0xD0));
    out.push_back(0);
}

void write_disconnect(std::string& out, uint8_t level, const disconnect_packet& p)
{
    packet(out, 0xE0, [&](std::string& b) {
        if (level < level_5 || (p.reason == reason::success && p.props.empty()))
            return;
        b.push_back(static_cast<char>(p.reason));
        if (!p.props.empty())
            put_properties(b, p.props);
    });
}

}   // namespace socketley::mqtt
