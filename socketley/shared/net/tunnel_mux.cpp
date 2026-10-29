#include "tunnel_mux.h"

#include <algorithm>

namespace socketley::tunnel
{

namespace
{

uint32_t get_u32(std::string_view s, size_t at)
{
    uint32_t v = 0;
    for (size_t i = 0; i < 4; ++i)
        v = (v << 8) | static_cast<unsigned char>(s[at + i]);
    return v;
}

uint16_t get_u16(std::string_view s, size_t at)
{
    return static_cast<uint16_t>((static_cast<unsigned char>(s[at]) << 8) | static_cast<unsigned char>(s[at + 1]));
}

void put_u32(std::string& out, uint32_t v)
{
    for (int sh = 24; sh >= 0; sh -= 8)
        out.push_back(static_cast<char>((v >> sh) & 0xff));
}

void put_u16(std::string& out, uint16_t v)
{
    out.push_back(static_cast<char>(v >> 8));
    out.push_back(static_cast<char>(v & 0xff));
}

// A u16-length string from the front of `in`, taken off it; false when it runs past the end.
bool take_string(std::string_view& in, std::string_view& s)
{
    if (in.size() < 2)
        return false;
    const uint16_t n = get_u16(in, 0);
    if (in.size() < 2u + n)
        return false;
    s = in.substr(2, n);
    in.remove_prefix(2u + n);
    return true;
}

}   // namespace

session::session(bool dialled, events& ev, uint32_t max_streams)
    : m_dialled(dialled), m_ev(ev), m_max_streams(max_streams), m_next(dialled ? 1 : 2)
{
}

bool session::fail(std::string why)
{
    if (m_error.empty())
        m_error = std::move(why);
    return false;
}

void session::put(frame_type t, uint32_t stream, std::string_view payload, std::string& out) const
{
    put_u32(out, static_cast<uint32_t>(payload.size()));
    out.push_back(static_cast<char>(t));
    put_u32(out, stream);
    out.append(payload);
}

bool session::feed(std::string_view bytes, std::string& out)
{
    if (!m_error.empty())
        return false;
    m_in.append(bytes);
    size_t at = 0;
    while (m_in.size() - at >= header_size)
    {
        const uint32_t len = get_u32(m_in, at);
        const auto t = static_cast<frame_type>(static_cast<unsigned char>(m_in[at + 4]));
        const uint32_t stream = get_u32(m_in, at + 5);
        // A session that refused its bytes keeps none of them: it is dead, and holds nothing while it is closed.
        if (len > max_payload)
        {
            m_in.clear();
            return fail("a frame of " + std::to_string(len) + " bytes, past the limit of " + std::to_string(max_payload));
        }
        if (m_in.size() - at < header_size + len)
            break;
        const std::string_view payload = std::string_view(m_in).substr(at + header_size, len);
        if (!frame(t, stream, payload, out))
        {
            m_in.clear();
            return false;
        }
        at += header_size + len;
    }
    m_in.erase(0, at);
    return true;
}

bool session::frame(frame_type t, uint32_t stream, std::string_view p, std::string& out)
{
    if (!m_got_hello && t != frame_type::hello)
        return fail("a frame before the hello");
    switch (t)
    {
        case frame_type::hello:
        {
            if (m_got_hello || stream != 0 || p.size() > max_hello || p.empty())
                return fail("a hello where none belongs");
            if (static_cast<uint8_t>(p[0]) != version)
                return fail("a hello of version " + std::to_string(static_cast<uint8_t>(p[0])));
            p.remove_prefix(1);
            fields f;
            while (!p.empty())
            {
                std::string_view name, value;
                if (!take_string(p, name) || !take_string(p, value))
                    return fail("a hello cut short");
                f.emplace_back(name, value);
            }
            m_got_hello = true;
            m_ev.on_hello(f);
            return true;
        }
        case frame_type::open:
        {
            if (stream == 0 || ours(stream) || stream <= m_highest_theirs)
                return fail("an open of stream " + std::to_string(stream) + ", which is not the far side's to open");
            std::string_view target;
            if (!take_string(p, target) || target.empty() || target.size() > max_target || p.size() > max_target)
                return fail("an open with no target");
            m_highest_theirs = stream;
            if (m_said_goaway || m_streams.size() >= m_max_streams)
            {
                const char code = static_cast<char>(m_said_goaway ? reset_code::refused : reset_code::limit);
                put(frame_type::reset, stream, std::string_view(&code, 1), out);
                return true;
            }
            m_streams.emplace(stream, stream_state{});
            m_ev.on_open(stream, target, p);
            return true;
        }
        case frame_type::data:
        {
            const auto it = m_streams.find(stream);
            if (it == m_streams.end())
            {
                // Bytes for a stream this side reset may still be on their way; any other stream is no stream.
                if (stream == 0 || (ours(stream) ? stream >= m_next : stream > m_highest_theirs))
                    return fail("data for stream " + std::to_string(stream) + ", which was never opened");
                return true;
            }
            if (it->second.got_close)
                return fail("data on stream " + std::to_string(stream) + " after its close");
            if (p.size() > it->second.recv_credit)
                return fail("data on stream " + std::to_string(stream) + " past the credit it was given");
            it->second.recv_credit -= static_cast<uint32_t>(p.size());
            if (!p.empty())
                m_ev.on_data(stream, p);
            return true;
        }
        case frame_type::window:
        {
            if (p.size() != 4)
                return fail("a window frame of " + std::to_string(p.size()) + " bytes");
            const auto it = m_streams.find(stream);
            if (it == m_streams.end())
                return true;
            const uint64_t credit = uint64_t{it->second.send_credit} + get_u32(p, 0);
            if (credit > 0x7fffffffu)
                return fail("credit past 2^31 on stream " + std::to_string(stream));
            it->second.send_credit = static_cast<uint32_t>(credit);
            m_ev.on_window(stream);
            return true;
        }
        case frame_type::close:
        {
            const auto it = m_streams.find(stream);
            if (it == m_streams.end() || it->second.got_close)
                return true;
            it->second.got_close = true;
            m_ev.on_close(stream);
            settle(stream);
            return true;
        }
        case frame_type::reset:
        {
            if (p.size() != 1)
                return fail("a reset frame of " + std::to_string(p.size()) + " bytes");
            if (m_streams.erase(stream))
                m_ev.on_reset(stream, static_cast<reset_code>(static_cast<uint8_t>(p[0])));
            return true;
        }
        case frame_type::ping:
            if (p.size() != 8)
                return fail("a ping of " + std::to_string(p.size()) + " bytes");
            put(frame_type::pong, 0, p, out);
            return true;
        case frame_type::pong:
            if (p.size() != 8)
                return fail("a pong of " + std::to_string(p.size()) + " bytes");
            m_ev.on_pong(p);
            return true;
        case frame_type::goaway:
            if (p.size() > max_hello)
                return fail("a goaway too long to be one");
            m_got_goaway = true;
            m_ev.on_goaway(p);
            return true;
        case frame_type::datagram:
        {
            std::string_view service;
            if (stream == 0 || !take_string(p, service) || service.empty() || service.size() > max_target)
                return fail("a datagram with no flow or no service");
            m_ev.on_datagram(stream, service, p);
            return true;
        }
    }
    return fail("a frame of unknown type " + std::to_string(static_cast<unsigned>(t)));
}

void session::settle(uint32_t stream)
{
    const auto it = m_streams.find(stream);
    if (it != m_streams.end() && it->second.sent_close && it->second.got_close)
        m_streams.erase(it);
}

void session::hello(const fields& f, std::string& out)
{
    std::string p(1, static_cast<char>(version));
    for (const auto& [name, value] : f)
    {
        put_u16(p, static_cast<uint16_t>(std::min<size_t>(name.size(), 0xffff)));
        p.append(name, 0, 0xffff);
        put_u16(p, static_cast<uint16_t>(std::min<size_t>(value.size(), 0xffff)));
        p.append(value, 0, 0xffff);
    }
    put(frame_type::hello, 0, p, out);
}

uint32_t session::open(std::string_view target, std::string_view peer, std::string& out)
{
    if (m_got_goaway || m_said_goaway || m_streams.size() >= m_max_streams || target.empty() ||
        target.size() > max_target || peer.size() > max_target || m_next > 0x7ffffffe)
        return 0;
    const uint32_t id = m_next;
    m_next += 2;
    std::string p;
    put_u16(p, static_cast<uint16_t>(target.size()));
    p.append(target);
    p.append(peer);
    put(frame_type::open, id, p, out);
    m_streams.emplace(id, stream_state{});
    return id;
}

size_t session::send(uint32_t stream, std::string_view bytes, std::string& out)
{
    const auto it = m_streams.find(stream);
    if (it == m_streams.end() || it->second.sent_close)
        return 0;
    const size_t n = std::min<size_t>(bytes.size(), it->second.send_credit);
    for (size_t at = 0; at < n; at += max_payload)
        put(frame_type::data, stream, bytes.substr(at, std::min<size_t>(max_payload, n - at)), out);
    it->second.send_credit -= static_cast<uint32_t>(n);
    return n;
}

void session::close(uint32_t stream, std::string& out)
{
    const auto it = m_streams.find(stream);
    if (it == m_streams.end() || it->second.sent_close)
        return;
    it->second.sent_close = true;
    put(frame_type::close, stream, {}, out);
    settle(stream);
}

void session::reset(uint32_t stream, reset_code code, std::string& out)
{
    if (!m_streams.erase(stream))
        return;
    const char c = static_cast<char>(code);
    put(frame_type::reset, stream, std::string_view(&c, 1), out);
}

void session::consumed(uint32_t stream, size_t n, std::string& out)
{
    const auto it = m_streams.find(stream);
    if (it == m_streams.end() || n == 0)
        return;
    stream_state& s = it->second;
    // Never more back than was taken, whatever the caller counts.
    s.unacked = static_cast<uint32_t>(std::min<uint64_t>(uint64_t{s.unacked} + n, initial_window - s.recv_credit));
    if (s.unacked < initial_window / 2 || s.got_close)
        return;
    std::string p;
    put_u32(p, s.unacked);
    put(frame_type::window, stream, p, out);
    s.recv_credit += s.unacked;
    s.unacked = 0;
}

bool session::datagram(uint32_t flow, std::string_view service, std::string_view bytes, std::string& out)
{
    if (flow == 0 || service.empty() || service.size() > max_target || 2 + service.size() + bytes.size() > max_payload)
        return false;
    std::string p;
    p.reserve(2 + service.size() + bytes.size());
    put_u16(p, static_cast<uint16_t>(service.size()));
    p.append(service);
    p.append(bytes);
    put(frame_type::datagram, flow, p, out);
    return true;
}

void session::ping(std::string_view token, std::string& out)
{
    std::string p(token.substr(0, 8));
    p.resize(8, '\0');
    put(frame_type::ping, 0, p, out);
}

void session::goaway(std::string_view why, std::string& out)
{
    m_said_goaway = true;
    put(frame_type::goaway, 0, why.substr(0, max_hello), out);
}

uint32_t session::credit(uint32_t stream) const
{
    const auto it = m_streams.find(stream);
    return it == m_streams.end() || it->second.sent_close ? 0 : it->second.send_credit;
}

}   // namespace socketley::tunnel
