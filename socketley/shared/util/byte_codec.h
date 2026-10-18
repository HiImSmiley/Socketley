#pragma once
// Little-endian byte writer and bounds-checked reader shared by every binary format a daemon persists or sends to a peer.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace socketley::bytes
{

// Spelled out by shift, so the host's own order never decides a file's bytes.
inline void store32(void* at, uint32_t v)
{
    auto* p = static_cast<unsigned char*>(at);
    for (int i = 0; i < 4; ++i)
        p[i] = static_cast<unsigned char>(v >> (8 * i));
}

inline void store64(void* at, uint64_t v)
{
    auto* p = static_cast<unsigned char*>(at);
    for (int i = 0; i < 8; ++i)
        p[i] = static_cast<unsigned char>(v >> (8 * i));
}

inline uint32_t load32(const void* at)
{
    const auto* p = static_cast<const unsigned char*>(at);
    uint32_t    v = 0;
    for (int i = 0; i < 4; ++i)
        v |= static_cast<uint32_t>(p[i]) << (8 * i);
    return v;
}

inline uint64_t load64(const void* at)
{
    const auto* p = static_cast<const unsigned char*>(at);
    uint64_t    v = 0;
    for (int i = 0; i < 8; ++i)
        v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
}

inline void append32(std::string& out, uint32_t v)
{
    char b[4];
    store32(b, v);
    out.append(b, 4);
}

inline void append64(std::string& out, uint64_t v)
{
    char b[8];
    store64(b, v);
    out.append(b, 8);
}

class writer
{
public:
    void u8(uint8_t v) { m_out += static_cast<char>(v); }

    void u32(uint32_t v) { append32(m_out, v); }

    void u64(uint64_t v) { append64(m_out, v); }

    void bytes(std::string_view s)
    {
        u32(static_cast<uint32_t>(s.size()));
        m_out.append(s);
    }

    void ids(const std::vector<uint64_t>& v)
    {
        u32(static_cast<uint32_t>(v.size()));
        for (uint64_t id : v)
            u64(id);
    }

    void reserve(size_t n) { m_out.reserve(n); }

    std::string take() { return std::move(m_out); }

private:
    std::string m_out;
};

class reader
{
public:
    explicit reader(std::string_view in) : m_in(in) {}

    bool u8(uint8_t& v)
    {
        if (left() < 1)
            return false;
        v = static_cast<uint8_t>(m_in[m_off++]);
        return true;
    }

    bool u32(uint32_t& v)
    {
        if (left() < 4)
            return false;
        v = load32(m_in.data() + m_off);
        m_off += 4;
        return true;
    }

    bool u64(uint64_t& v)
    {
        if (left() < 8)
            return false;
        v = load64(m_in.data() + m_off);
        m_off += 8;
        return true;
    }

    bool flag(bool& v)
    {
        uint8_t b = 0;
        if (!u8(b) || b > 1)
            return false;
        v = b != 0;
        return true;
    }

    bool bytes(std::string& s, size_t cap)
    {
        std::string_view v;
        if (!view(v, cap))
            return false;
        s.assign(v);
        return true;
    }

    // The same field without a copy, valid as long as the buffer the reader was given.
    bool view(std::string_view& s, size_t cap)
    {
        uint32_t n = 0;
        if (!u32(n) || n > cap || n > left())
            return false;
        s = m_in.substr(m_off, n);
        m_off += n;
        return true;
    }

    // The count is checked against what is left before anything is reserved, so a forged length allocates nothing.
    bool ids(std::vector<uint64_t>& v)
    {
        uint32_t n = 0;
        if (!u32(n) || static_cast<uint64_t>(n) * 8 > left())
            return false;
        v.resize(n);
        for (uint64_t& id : v)
            if (!u64(id))
                return false;
        return true;
    }

    size_t left() const { return m_in.size() - m_off; }

private:
    std::string_view m_in;
    size_t m_off = 0;
};

}   // namespace socketley::bytes
