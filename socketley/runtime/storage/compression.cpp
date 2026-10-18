#include "compression.h"

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <cstring>

#include "lz4_block.h"
#include "../../shared/util/number_parse.h"

namespace socketley::storage
{

namespace
{

}   // namespace

bool lz4_record_of(const object_meta& m, lz4_record& out)
{
    const std::string* v = nullptr;
    for (const auto& e : m.extra)
        if (e.first == lz4_extra)
            v = &e.second;
    if (!v)
        return false;
    std::string_view s = *v;
    std::string_view f[4];
    for (int i = 0; i < 4; ++i)
    {
        const size_t semi = s.find(';');
        if ((semi == std::string_view::npos) != (i == 3))
            return false;
        f[i] = s.substr(0, semi);
        s    = i == 3 ? std::string_view{} : s.substr(semi + 1);
    }
    uint64_t chunk = 0;
    if (f[0] != "1" || !socketley::parse_whole(f[1], chunk) || chunk != lz4_chunk || !socketley::parse_whole(f[2], out.table_at) ||
        !socketley::parse_whole(f[3], out.chunks))
        return false;
    return m.parts == 0 && m.size > 0 && out.chunks == lz4_chunks_of(m.size) &&
           out.table_at <= m.size;
}

std::string encode_lz4_record(const lz4_record& r)
{
    char buf[64];
    const int n = std::snprintf(buf, sizeof buf, "1;%zu;%020llu;%010llu", lz4_chunk,
                                static_cast<unsigned long long>(r.table_at), static_cast<unsigned long long>(r.chunks));
    return std::string(buf, static_cast<size_t>(n));
}

void set_lz4_record(object_meta& m, const lz4_record* r)
{
    erase_if(m.extra, [](const auto& e) { return e.first == lz4_extra; });
    if (r)
        m.extra.emplace_back(std::string(lz4_extra), encode_lz4_record(*r));
}

bool lz4_table_decode(std::string_view bytes, const object_meta& m, const lz4_record& r, lz4_table& out)
{
    if (bytes.size() != r.chunks * 4)
        return false;
    out.size = m.size;
    out.at.assign(1, 0);
    out.raw.clear();
    out.at.reserve(r.chunks + 1);
    out.raw.reserve(r.chunks);
    for (uint64_t i = 0; i < r.chunks; ++i)
    {
        uint32_t e = 0;
        std::memcpy(&e, bytes.data() + i * 4, 4);
        const bool     raw = (e & lz4_raw_bit) != 0;
        const uint64_t len = e & ~lz4_raw_bit;
        const uint64_t plain = std::min<uint64_t>(lz4_chunk, m.size - i * lz4_chunk);
        if (raw ? len != plain : len == 0 || len > lz4_bound(plain))
            return false;
        out.raw.push_back(raw);
        out.at.push_back(out.at.back() + len);
    }
    return out.at.back() == r.table_at;
}

bool lz4_open_chunks(const lz4_table& t, uint64_t first, uint64_t n, const char* stored, char* out)
{
    const uint64_t base = t.at[first];
    for (uint64_t i = first; i < first + n; ++i)
    {
        const char*    in    = stored + (t.at[i] - base);
        const size_t   len   = static_cast<size_t>(t.at[i + 1] - t.at[i]);
        const size_t   plain = static_cast<size_t>(t.plain_len(i));
        if (t.raw[i])
            std::memcpy(out, in, plain);
        else if (lz4_decompress(reinterpret_cast<const uint8_t*>(in), len, reinterpret_cast<uint8_t*>(out), plain) !=
                 static_cast<long>(plain))
            return false;
        out += plain;
    }
    return true;
}

bool lz4_open_body(const object_meta& m, std::string_view stored, std::string& plain)
{
    lz4_record r;
    lz4_table  t;
    if (!lz4_record_of(m, r) || stored.size() < r.table_at + r.chunks * 4 ||
        !lz4_table_decode(stored.substr(static_cast<size_t>(r.table_at), static_cast<size_t>(r.chunks * 4)), m, r, t))
        return false;
    plain.resize(static_cast<size_t>(m.size));
    return lz4_open_chunks(t, 0, r.chunks, stored.data(), plain.data());
}

void lz4_squeeze(const char* in, size_t n, std::string& out, std::string& table)
{
    for (size_t off = 0; off < n; off += lz4_chunk)
    {
        const size_t plain = std::min(lz4_chunk, n - off);
        const size_t at    = out.size();
        out.resize(at + lz4_bound(plain));
        size_t len = lz4_compress(reinterpret_cast<const uint8_t*>(in + off), plain,
                                  reinterpret_cast<uint8_t*>(out.data() + at));
        uint32_t e = static_cast<uint32_t>(len);
        // A chunk that does not get shorter is kept as it is, which reads with a copy.
        if (len >= plain)
        {
            std::memcpy(out.data() + at, in + off, plain);
            len = plain;
            e   = static_cast<uint32_t>(plain) | lz4_raw_bit;
        }
        out.resize(at + len);
        char b[4];
        std::memcpy(b, &e, 4);
        table.append(b, 4);
    }
}

}   // namespace socketley::storage
