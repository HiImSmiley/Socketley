#pragma once
// Little-endian byte writer and bounds-checked reader shared by every binary format a daemon persists or sends to a peer.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace socketley::bytes
{

class writer
{
public:
    void u8(uint8_t v) { m_out += static_cast<char>(v); }

    void u32(uint32_t v)
    {
        for (int b = 0; b < 4; ++b)
            m_out += static_cast<char>((v >> (8 * b)) & 0xFF);
    }

    void u64(uint64_t v)
    {
        for (int b = 0; b < 8; ++b)
            m_out += static_cast<char>((v >> (8 * b)) & 0xFF);
    }

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
        v = 0;
        for (int b = 0; b < 4; ++b)
            v |= static_cast<uint32_t>(static_cast<unsigned char>(m_in[m_off++])) << (8 * b);
        return true;
    }

    bool u64(uint64_t& v)
    {
        if (left() < 8)
            return false;
        v = 0;
        for (int b = 0; b < 8; ++b)
            v |= static_cast<uint64_t>(static_cast<unsigned char>(m_in[m_off++])) << (8 * b);
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
