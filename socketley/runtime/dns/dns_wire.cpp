#include "dns_wire.h"

namespace socketley::dns
{

std::string to_text(std::string_view wire)
{
    std::string out;
    for (size_t i = 0; i < wire.size() && wire[i]; )
    {
        const size_t l = static_cast<uint8_t>(wire[i]);
        for (size_t k = 1; k <= l && i + k < wire.size(); ++k)
        {
            const auto c = static_cast<unsigned char>(wire[i + k]);
            if (c == '.' || c == '\\')
            {
                out += '\\';
                out += static_cast<char>(c);
            }
            else if (c <= 0x20 || c >= 0x7F)
            {
                char esc[5];
                esc[0] = '\\';
                esc[1] = static_cast<char>('0' + c / 100);
                esc[2] = static_cast<char>('0' + c / 10 % 10);
                esc[3] = static_cast<char>('0' + c % 10);
                esc[4] = 0;
                out += esc;
            }
            else
                out += static_cast<char>(c);
        }
        out += '.';
        i += 1 + l;
    }
    return out.empty() ? std::string(".") : out;
}

void writer::offer(std::string_view wire, size_t at)
{
    for (size_t i = 0; i < wire.size() && wire[i] && m_ndict < max_dict; i += 1 + static_cast<uint8_t>(wire[i]))
    {
        if (at + i >= 0x4000)
            break;
        m_dict[m_ndict++] = {reinterpret_cast<const uint8_t*>(wire.data()) + i, static_cast<uint8_t>(wire.size() - i),
                             static_cast<uint16_t>(at + i)};
    }
}

void writer::name(std::string_view wire, bool compress)
{
    const auto* w = reinterpret_cast<const uint8_t*>(wire.data());
    const size_t n = wire.size();
    // The longest suffix already in the message, found from the whole name down.
    size_t cut = n;
    uint16_t ptr = 0;
    if (compress)
        for (size_t i = 0; i < n && w[i]; i += 1 + w[i])
        {
            const size_t len = n - i;
            for (uint8_t d = 0; d < m_ndict; ++d)
                if (m_dict[d].len == len && std::memcmp(m_dict[d].name, w + i, len) == 0)
                {
                    cut = i;
                    ptr = m_dict[d].at;
                    break;
                }
            if (cut != n)
                break;
        }
    const size_t start = m_len;
    if (cut == n)
    {
        put(w, n);
    }
    else
    {
        put(w, cut);
        put16(static_cast<uint16_t>(0xC000 | ptr));
    }
    if (m_over)
        return;
    // The labels written here are suffixes a later name may point at.
    for (size_t i = 0; i < cut && w[i] && m_ndict < max_dict; i += 1 + w[i])
    {
        if (start + i >= 0x4000)
            break;
        m_dict[m_ndict++] = {w + i, static_cast<uint8_t>(n - i), static_cast<uint16_t>(start + i)};
    }
}

}   // namespace socketley::dns
