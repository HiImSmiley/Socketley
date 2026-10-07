#pragma once
// The DNS message format of RFC 1035 section 4, as an authoritative server reads a query and writes an answer.
//
// A name is kept in wire form throughout -- length-prefixed labels ending in the root's zero -- and folded to lower
// case wherever it is a key, so a lookup compares bytes and never parses text. Reading a name follows compression
// pointers only backwards and at most 128 times, which is what stops the loop a forged pointer would make; writing
// one points at a suffix already in the message whenever there is one, which is what keeps an answer small.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

namespace socketley::dns
{

// ─── Numbers of the protocol ────────────────────────────────────────────────

namespace type
{
inline constexpr uint16_t A = 1, NS = 2, CNAME = 5, SOA = 6, PTR = 12, HINFO = 13, MX = 15, TXT = 16, AAAA = 28,
                          SRV = 33, OPT = 41, DS = 43, IXFR = 251, AXFR = 252, ANY = 255, CAA = 257;
}
namespace rclass
{
inline constexpr uint16_t IN = 1, CH = 3, NONE = 254, ANY = 255;
}
namespace rcode
{
inline constexpr uint8_t NOERROR = 0, FORMERR = 1, SERVFAIL = 2, NXDOMAIN = 3, NOTIMP = 4, REFUSED = 5;
// Extended, carried half in the header and half in the OPT record.
inline constexpr uint16_t BADVERS = 16;
}
namespace opcode
{
inline constexpr uint8_t QUERY = 0, NOTIFY = 4;
}

inline constexpr size_t header_len   = 12;
inline constexpr size_t max_name     = 255;
inline constexpr size_t max_label    = 63;
// What an answer over UDP is kept within when the query offered more: the size DNS Flag Day 2020 settled on, which
// fits one packet on every path without fragments, since fragments are what an off-path forger aims at.
inline constexpr uint16_t udp_payload = 1232;
inline constexpr size_t max_message  = 65535;

// ─── Bytes ──────────────────────────────────────────────────────────────────

inline uint16_t rd16(const uint8_t* p) { return static_cast<uint16_t>(p[0] << 8 | p[1]); }
inline uint32_t rd32(const uint8_t* p)
{
    return static_cast<uint32_t>(p[0]) << 24 | static_cast<uint32_t>(p[1]) << 16 | static_cast<uint32_t>(p[2]) << 8 | p[3];
}
inline void wr16(uint8_t* p, uint16_t v) { p[0] = static_cast<uint8_t>(v >> 8); p[1] = static_cast<uint8_t>(v); }
inline void wr32(uint8_t* p, uint32_t v)
{
    p[0] = static_cast<uint8_t>(v >> 24); p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);  p[3] = static_cast<uint8_t>(v);
}
inline uint8_t lower(uint8_t c) { return c >= 'A' && c <= 'Z' ? static_cast<uint8_t>(c | 0x20) : c; }

// ─── Names in wire form ─────────────────────────────────────────────────────

// The name in `msg` at `off`, uncompressed and folded to lower case into `out` (at least max_name bytes); its length,
// and in `next` where what follows it begins. 0 when it runs past the message, loops, or is longer than a name may be.
inline size_t read_name(const uint8_t* msg, size_t len, size_t off, uint8_t* out, size_t& next)
{
    size_t n = 0;
    bool jumped = false;
    for (int hops = 0; hops < 128; ++hops)
    {
        if (off >= len)
            return 0;
        const uint8_t l = msg[off];
        if (l == 0)
        {
            if (n + 1 > max_name)
                return 0;
            out[n++] = 0;
            if (!jumped)
                next = off + 1;
            return n;
        }
        if ((l & 0xC0) == 0xC0)
        {
            if (off + 1 >= len)
                return 0;
            const size_t to = static_cast<size_t>(l & 0x3F) << 8 | msg[off + 1];
            // Only ever backwards, so a chain of pointers ends.
            if (to >= off)
                return 0;
            if (!jumped)
                next = off + 2;
            jumped = true;
            off = to;
            continue;
        }
        if (l & 0xC0)
            return 0;
        if (off + 1 + l > len || n + 1 + l + 1 > max_name)
            return 0;
        out[n++] = l;
        for (size_t i = 0; i < l; ++i)
            out[n++] = lower(msg[off + 1 + i]);
        off += 1 + l;
    }
    return 0;
}

// How many labels a wire name has, the root's not counted.
inline int label_count(std::string_view name)
{
    int c = 0;
    for (size_t i = 0; i < name.size() && name[i]; i += 1 + static_cast<uint8_t>(name[i]))
        ++c;
    return c;
}

// The name with its first label taken off; the root stays the root.
inline std::string_view parent(std::string_view name)
{
    if (name.empty() || name[0] == 0)
        return name;
    return name.substr(1 + static_cast<uint8_t>(name[0]));
}

// Whether `name` is `zone` or below it, label for label.
inline bool is_subdomain(std::string_view name, std::string_view zone)
{
    if (name.size() < zone.size() || name.compare(name.size() - zone.size(), zone.size(), zone) != 0)
        return false;
    // The tail has to begin on a label boundary of `name`.
    size_t i = 0;
    const size_t at = name.size() - zone.size();
    while (i < at)
        i += 1 + static_cast<uint8_t>(name[i]);
    return i == at;
}

// A wire name as text, with the trailing dot; for logs and the zone parser's messages.
std::string to_text(std::string_view wire);

// ─── Writing a message ──────────────────────────────────────────────────────

class writer
{
public:
    writer(uint8_t* buf, size_t cap) : m_buf(buf), m_cap(cap) {}

    size_t size() const { return m_len; }
    uint8_t* data() { return m_buf; }
    bool overflowed() const { return m_over; }
    // What may be written before the answer no longer fits its transport; the buffer itself may hold more.
    void set_limit(size_t limit) { m_cap = limit; }
    size_t limit() const { return m_cap; }

    void put8(uint8_t v)  { if (room(1)) m_buf[m_len++] = v; }
    void put16(uint16_t v) { if (room(2)) { wr16(m_buf + m_len, v); m_len += 2; } }
    void put32(uint32_t v) { if (room(4)) { wr32(m_buf + m_len, v); m_len += 4; } }
    void put(const void* p, size_t n) { if (room(n)) { std::memcpy(m_buf + m_len, p, n); m_len += n; } }
    void patch16(size_t at, uint16_t v) { wr16(m_buf + at, v); }

    // A name, pointing at a suffix already written when there is one and offering its own suffixes to later names.
    // `compress` false writes it whole, as SRV's target must be (RFC 2782), but still offers it.
    void name(std::string_view wire, bool compress = true);

    // Where the next record's count is reckoned from: a section ends where the message ended when it began.
    struct mark { size_t len; uint8_t ndict; };
    mark save() const { return {m_len, m_ndict}; }
    void restore(mark m) { m_len = m.len; m_ndict = m.ndict; m_over = false; }

    // The question's name is in the query's own case at offset 12; its suffixes are offered as if written here.
    void offer(std::string_view wire_lower, size_t at);

private:
    bool room(size_t n)
    {
        if (m_len + n > m_cap)
        {
            m_over = true;
            return false;
        }
        return true;
    }

    // Suffixes already in the message and where: a name of at most 127 labels can offer no more than that, and an
    // answer that fits a packet holds a few dozen, so a straight scan of a short array beats any table.
    struct entry { const uint8_t* name; uint8_t len; uint16_t at; };
    static constexpr uint8_t max_dict = 96;
    entry   m_dict[max_dict];
    uint8_t m_ndict{0};

    uint8_t* m_buf;
    size_t   m_cap;
    size_t   m_len{0};
    bool     m_over{false};
};

}   // namespace socketley::dns
