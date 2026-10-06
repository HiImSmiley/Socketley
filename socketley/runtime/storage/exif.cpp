// EXIF's TIFF directories, reached through a JPEG's APP1 segment or a HEIF's Exif item; every offset is checked
// against the bytes there are, since the file is anyone's.
#include "exif.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <iterator>

namespace socketley::storage
{

namespace
{

class tiff_reader
{
public:
    explicit tiff_reader(std::string_view t) : m_t(t), m_le(t.size() >= 2 && t[0] == 'I') {}

    bool has(uint64_t off, uint64_t n) const { return off <= m_t.size() && n <= m_t.size() - off; }
    uint32_t u16(uint64_t off) const
    {
        const auto* p = reinterpret_cast<const unsigned char*>(m_t.data() + off);
        return m_le ? p[0] | p[1] << 8 : p[0] << 8 | p[1];
    }
    uint32_t u32(uint64_t off) const
    {
        const auto* p = reinterpret_cast<const unsigned char*>(m_t.data() + off);
        return m_le ? static_cast<uint32_t>(p[0] | p[1] << 8 | p[2] << 16) | static_cast<uint32_t>(p[3]) << 24
                    : static_cast<uint32_t>(p[0]) << 24 | static_cast<uint32_t>(p[1] << 16 | p[2] << 8 | p[3]);
    }

    // An entry of the directory at `ifd` with tag `tag`: its type, count and where its value lies; false for none.
    bool find(uint64_t ifd, uint32_t tag, uint32_t& type, uint32_t& count, uint64_t& at) const
    {
        if (!has(ifd, 2))
            return false;
        const uint32_t n = u16(ifd);
        for (uint32_t i = 0; i < n; ++i)
        {
            const uint64_t e = ifd + 2 + 12ull * i;
            if (!has(e, 12))
                return false;
            if (u16(e) != tag)
                continue;
            type  = u16(e + 2);
            count = u32(e + 4);
            static constexpr uint64_t sizes[] = {0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8};
            const uint64_t size = type < std::size(sizes) ? sizes[type] * count : 0;
            at = size <= 4 ? e + 8 : u32(e + 8);
            return size > 0 && has(at, size);
        }
        return false;
    }

    std::string ascii(uint64_t ifd, uint32_t tag) const
    {
        uint32_t type = 0, count = 0;
        uint64_t at = 0;
        if (!find(ifd, tag, type, count, at) || type != 2)
            return {};
        std::string s(m_t.substr(at, count));
        while (!s.empty() && (s.back() == '\0' || s.back() == ' '))
            s.pop_back();
        return s;
    }

    uint64_t pointer(uint64_t ifd, uint32_t tag) const
    {
        uint32_t type = 0, count = 0;
        uint64_t at = 0;
        return find(ifd, tag, type, count, at) && (type == 4 || type == 13) && count == 1 ? u32(at) : 0;
    }

    // Degrees, minutes and seconds as three rationals, in degrees.
    bool degrees(uint64_t ifd, uint32_t tag, double& out) const
    {
        uint32_t type = 0, count = 0;
        uint64_t at = 0;
        if (!find(ifd, tag, type, count, at) || type != 5 || count != 3)
            return false;
        double parts[3];
        for (int i = 0; i < 3; ++i)
        {
            const uint32_t num = u32(at + 8ull * i), den = u32(at + 8ull * i + 4);
            if (den == 0)
                return false;
            parts[i] = static_cast<double>(num) / den;
        }
        out = parts[0] + parts[1] / 60 + parts[2] / 3600;
        return std::isfinite(out);
    }

private:
    std::string_view m_t;
    bool m_le;
};

// "2021:07:14 18:03:22" as "2021-07-14T18:03:22"; empty for anything else, the all-zero date cameras write included.
std::string iso_time(const std::string& exif)
{
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0;
    if (std::sscanf(exif.c_str(), "%4d:%2d:%2d %2d:%2d:%2d", &y, &mo, &d, &h, &mi, &s) != 6 || y < 1800 || mo < 1 ||
        mo > 12 || d < 1 || d > 31 || h < 0 || h > 23 || mi < 0 || mi > 59 || s < 0 || s > 60)
        return {};
    char buf[32];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02d", y, mo, d, h, mi, s);
    return buf;
}

uint32_t be32(std::string_view s, uint64_t off)
{
    const auto* p = reinterpret_cast<const unsigned char*>(s.data() + off);
    return static_cast<uint32_t>(p[0]) << 24 | static_cast<uint32_t>(p[1]) << 16 | static_cast<uint32_t>(p[2]) << 8 | p[3];
}

uint64_t be_n(std::string_view s, uint64_t off, unsigned n)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < n; ++i)
        v = v << 8 | static_cast<unsigned char>(s[off + i]);
    return v;
}

// The boxes of an ISO BMFF range, each by its type and its body.
template <class F>
void boxes(std::string_view s, F&& each)
{
    uint64_t at = 0;
    while (at + 8 <= s.size())
    {
        uint64_t size = be32(s, at), head = 8;
        const std::string_view type = s.substr(at + 4, 4);
        if (size == 1)
        {
            if (at + 16 > s.size())
                return;
            size = be_n(s, at + 8, 8);
            head = 16;
        }
        else if (size == 0)
            size = s.size() - at;
        if (size < head)
            return;
        // A box that runs past the bytes there are is given what there is of it and is the last, so a size near 2**64
        // cannot carry `at` around to the start.
        const uint64_t left = s.size() - at;
        const uint64_t end = size > left ? s.size() : at + size;
        if (!each(type, s.substr(at + head, end - at - head)) || size >= left)
            return;
        at += size;
    }
}

// The file offset and length of a HEIF's Exif item, from its meta box's iinf and iloc.
bool heif_place(std::string_view file, exif_place& out)
{
    std::string_view meta;
    boxes(file, [&](std::string_view type, std::string_view body)
    {
        if (type == "meta")
            meta = body.size() >= 4 ? body.substr(4) : std::string_view{};
        return type != "mdat" && meta.empty();
    });
    if (meta.empty())
        return false;
    uint32_t exif_id = 0;
    std::string_view iloc;
    boxes(meta, [&](std::string_view type, std::string_view body)
    {
        if (type == "iloc")
            iloc = body;
        else if (type == "iinf" && body.size() >= 6)
        {
            const unsigned version = static_cast<unsigned char>(body[0]);
            const uint64_t first = version == 0 ? 6 : 8;
            if (first <= body.size())
                boxes(body.substr(first), [&](std::string_view t, std::string_view e)
                {
                    if (t != "infe" || e.size() < 4)
                        return true;
                    const unsigned v = static_cast<unsigned char>(e[0]);
                    const uint64_t id_size = v >= 3 ? 4 : 2;
                    if (v < 2 || e.size() < 4 + id_size + 2 + 4)
                        return true;
                    if (e.substr(4 + id_size + 2, 4) == "Exif")
                        exif_id = static_cast<uint32_t>(be_n(e, 4, static_cast<unsigned>(id_size)));
                    return exif_id == 0;
                });
        }
        return true;
    });
    if (exif_id == 0 || iloc.size() < 8)
        return false;
    const unsigned version = static_cast<unsigned char>(iloc[0]);
    const unsigned off_size = static_cast<unsigned char>(iloc[4]) >> 4, len_size = iloc[4] & 15,
                   base_size = static_cast<unsigned char>(iloc[5]) >> 4, index_size = version >= 1 ? iloc[5] & 15 : 0;
    uint64_t at = 6;
    const unsigned count_size = version < 2 ? 2 : 4;
    if (at + count_size > iloc.size())
        return false;
    const uint64_t items = be_n(iloc, at, count_size);
    at += count_size;
    for (uint64_t i = 0; i < items; ++i)
    {
        const uint64_t need = count_size + (version >= 1 ? 2 : 0) + 2 + base_size + 2;
        if (at + need > iloc.size())
            return false;
        const uint64_t id = be_n(iloc, at, count_size);
        at += count_size;
        const unsigned method = version >= 1 ? static_cast<unsigned>(be_n(iloc, at, 2) & 15) : 0;
        at += version >= 1 ? 2 : 0;
        at += 2;
        const uint64_t base = be_n(iloc, at, base_size);
        at += base_size;
        const uint64_t extents = be_n(iloc, at, 2);
        at += 2;
        const uint64_t ext_size = index_size + off_size + len_size;
        if (at + ext_size * extents > iloc.size())
            return false;
        if (id == exif_id)
        {
            // Stored in the file, in one piece.
            if (method != 0 || extents != 1)
                return false;
            out.off = base + be_n(iloc, at + index_size, off_size);
            out.len = be_n(iloc, at + index_size + off_size, len_size);
            return out.len > 4;
        }
        at += ext_size * extents;
    }
    return false;
}

}   // namespace

bool tiff_facts(std::string_view tiff, photo_facts& out)
{
    if (tiff.size() < 8 || !(tiff.starts_with("II*\0") || tiff.starts_with(std::string_view("MM\0*", 4))))
        return false;
    const tiff_reader t(tiff);
    const uint64_t ifd0 = t.u32(4);
    if (const uint64_t exif = t.pointer(ifd0, 0x8769))
    {
        out.taken = iso_time(t.ascii(exif, 0x9003));
        if (!out.taken.empty())
        {
            // "+02:00", the camera's offset from UTC, where it wrote one.
            const std::string zone = t.ascii(exif, 0x9011);
            if (zone.size() == 6 && (zone[0] == '+' || zone[0] == '-') && zone[3] == ':')
                out.taken += zone;
        }
    }
    if (out.taken.empty())
        out.taken = iso_time(t.ascii(ifd0, 0x0132));
    if (const uint64_t gps = t.pointer(ifd0, 0x8825))
    {
        double lat = 0, lon = 0;
        const std::string ns = t.ascii(gps, 1), ew = t.ascii(gps, 3);
        if (t.degrees(gps, 2, lat) && t.degrees(gps, 4, lon) && lat <= 90 && lon <= 180 && !(lat == 0 && lon == 0))
        {
            out.located = true;
            out.lat = ns == "S" ? -lat : lat;
            out.lon = ew == "W" ? -lon : lon;
        }
    }
    return !out.taken.empty() || out.located;
}

bool exif_item_facts(std::string_view item, photo_facts& out)
{
    if (item.size() < 4)
        return false;
    const uint64_t skip = 4ull + be32(item, 0);
    return skip < item.size() && tiff_facts(item.substr(skip), out);
}

bool photo_facts_of(std::string_view head, photo_facts& out, exif_place* elsewhere)
{
    if (head.starts_with("\xFF\xD8"))
    {
        // The segments up to the picture's data, for an APP1 that is EXIF.
        uint64_t at = 2;
        while (at + 4 <= head.size() && static_cast<unsigned char>(head[at]) == 0xFF)
        {
            const unsigned marker = static_cast<unsigned char>(head[at + 1]);
            if (marker == 0xDA || marker == 0xD9)
                break;
            const uint64_t len = be_n(head, at + 2, 2);
            if (len < 2)
                break;
            if (marker == 0xE1 && at + 4 + 6 <= head.size() && head.substr(at + 4, 6) == std::string_view("Exif\0\0", 6))
            {
                const uint64_t end = std::min<uint64_t>(head.size(), at + 2 + len);
                if (tiff_facts(head.substr(at + 10, end - at - 10), out))
                    return true;
            }
            at += 2 + len;
        }
        return false;
    }
    if (head.starts_with("II*\0") || head.starts_with(std::string_view("MM\0*", 4)))
        return tiff_facts(head, out);
    if (head.size() >= 12 && head.substr(4, 4) == "ftyp")
    {
        exif_place p;
        if (!heif_place(head, p))
            return false;
        if (p.off < head.size() && p.len <= head.size() - p.off)
            return exif_item_facts(head.substr(p.off, p.len), out);
        if (elsewhere)
            *elsewhere = p;
    }
    return false;
}

}   // namespace socketley::storage
