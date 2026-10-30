#include "metrics_remote.h"

#include <algorithm>
#include <bit>
#include <cstring>

namespace socketley::metrics::remote
{

namespace
{

// ── Snappy ──────────────────────────────────────────────────────────────────

// A copy never reaches back past the 64 KiB block it is in, so a 2-byte offset holds every one this writes.
constexpr size_t block_size = 1u << 16;
constexpr int hash_bits = 14;
// Below this a block is one literal: there is too little to find a match in.
constexpr size_t min_matchable = 15;

uint32_t load32(const uint8_t* p)
{
    uint32_t v;
    std::memcpy(&v, p, 4);
    return v;
}

uint32_t hash32(uint32_t v)
{
    return (v * 0x1e35a7bdu) >> (32 - hash_bits);
}

uint8_t* put_varint(uint8_t* op, uint64_t v)
{
    while (v >= 0x80)
    {
        *op++ = static_cast<uint8_t>(v | 0x80);
        v >>= 7;
    }
    *op++ = static_cast<uint8_t>(v);
    return op;
}

uint8_t* put_literal(uint8_t* op, const uint8_t* p, size_t len)
{
    if (len == 0)
        return op;
    const size_t n = len - 1;
    if (n < 60)
        *op++ = static_cast<uint8_t>(n << 2);
    else
    {
        const int bytes = n < (1u << 8) ? 1 : n < (1u << 16) ? 2 : n < (1u << 24) ? 3 : 4;
        *op++ = static_cast<uint8_t>((59 + bytes) << 2);
        for (int i = 0; i < bytes; ++i)
            *op++ = static_cast<uint8_t>(n >> (8 * i));
    }
    std::memcpy(op, p, len);
    return op + len;
}

// One copy of 4 to 64 bytes, in the 1-byte-offset form where it fits.
uint8_t* put_copy_upto64(uint8_t* op, size_t offset, size_t len)
{
    if (len < 12 && offset < 2048)
    {
        *op++ = static_cast<uint8_t>(1 | ((len - 4) << 2) | ((offset >> 8) << 5));
        *op++ = static_cast<uint8_t>(offset);
    }
    else
    {
        *op++ = static_cast<uint8_t>(2 | ((len - 1) << 2));
        *op++ = static_cast<uint8_t>(offset);
        *op++ = static_cast<uint8_t>(offset >> 8);
    }
    return op;
}

// A match of any length at least 4, cut so that no piece is shorter than 4.
uint8_t* put_copy(uint8_t* op, size_t offset, size_t len)
{
    while (len >= 68)
    {
        op = put_copy_upto64(op, offset, 64);
        len -= 64;
    }
    if (len > 64)
    {
        op = put_copy_upto64(op, offset, 60);
        len -= 60;
    }
    return put_copy_upto64(op, offset, len);
}

uint8_t* compress_block(const uint8_t* b, size_t len, uint8_t* op, uint16_t* table)
{
    if (len < min_matchable)
        return put_literal(op, b, len);
    std::memset(table, 0, sizeof(uint16_t) << hash_bits);
    size_t lit = 0;
    size_t ip = 1;
    while (ip + 4 <= len)
    {
        const uint32_t now = load32(b + ip);
        uint16_t& slot = table[hash32(now)];
        const size_t cand = slot;
        slot = static_cast<uint16_t>(ip);
        if (load32(b + cand) != now)
        {
            // Further between probes the longer nothing matched, so incompressible bytes pass quickly.
            ip += 1 + ((ip - lit) >> 5);
            continue;
        }
        size_t m = 4;
        while (ip + m < len && b[cand + m] == b[ip + m])
            ++m;
        op = put_literal(op, b + lit, ip - lit);
        op = put_copy(op, ip - cand, m);
        ip += m;
        lit = ip;
        if (ip >= 2 && ip + 2 <= len)
            table[hash32(load32(b + ip - 2))] = static_cast<uint16_t>(ip - 2);
    }
    return put_literal(op, b + lit, len - lit);
}

// ── protobuf ────────────────────────────────────────────────────────────────

enum wire : uint32_t { wire_varint = 0, wire_fixed64 = 1, wire_bytes = 2, wire_fixed32 = 5 };

struct reader
{
    const uint8_t* p;
    const uint8_t* end;

    bool done() const { return p == end; }

    bool varint(uint64_t& v)
    {
        v = 0;
        for (int shift = 0; shift < 64; shift += 7)
        {
            if (p == end)
                return false;
            const uint8_t byte = *p++;
            // The tenth byte holds the 64th bit and nothing above it.
            if (shift == 63 && byte > 1)
                return false;
            v |= static_cast<uint64_t>(byte & 0x7f) << shift;
            if (!(byte & 0x80))
                return true;
        }
        return false;
    }

    bool tag(uint32_t& field, uint32_t& type)
    {
        uint64_t t;
        if (!varint(t) || t > 0xffffffffu)
            return false;
        field = static_cast<uint32_t>(t >> 3);
        type = static_cast<uint32_t>(t & 7);
        return field != 0;
    }

    bool bytes(std::string_view& out)
    {
        uint64_t n;
        if (!varint(n) || n > static_cast<uint64_t>(end - p))
            return false;
        out = {reinterpret_cast<const char*>(p), static_cast<size_t>(n)};
        p += n;
        return true;
    }

    bool fixed64(uint64_t& v)
    {
        if (end - p < 8)
            return false;
        std::memcpy(&v, p, 8);
        if constexpr (std::endian::native == std::endian::big)
            v = std::byteswap(v);
        p += 8;
        return true;
    }

    // A field this reader does not take, passed over as its wire type says; groups are refused.
    bool skip(uint32_t type)
    {
        uint64_t v;
        std::string_view s;
        switch (type)
        {
            case wire_varint: return varint(v);
            case wire_fixed64: return fixed64(v);
            case wire_bytes: return bytes(s);
            case wire_fixed32:
                if (end - p < 4)
                    return false;
                p += 4;
                return true;
            default: return false;
        }
    }
};

reader sub(std::string_view s)
{
    const auto* b = reinterpret_cast<const uint8_t*>(s.data());
    return {b, b + s.size()};
}

size_t varint_size(uint64_t v)
{
    return static_cast<size_t>(std::max(1, (std::bit_width(v) + 6) / 7));
}

void put_varint(std::string& out, uint64_t v)
{
    uint8_t buf[10];
    out.append(reinterpret_cast<const char*>(buf), static_cast<size_t>(put_varint(buf, v) - buf));
}

void put_bytes_field(std::string& out, uint8_t tag, std::string_view s)
{
    out += static_cast<char>(tag);
    put_varint(out, s.size());
    out += s;
}

size_t bytes_field_size(std::string_view s)
{
    return 1 + varint_size(s.size()) + s.size();
}

}   // namespace

bool snappy_length(const uint8_t* in, size_t n, size_t& length)
{
    uint64_t v = 0;
    for (size_t i = 0; i < 5; ++i)
    {
        if (i == n)
            return false;
        v |= static_cast<uint64_t>(in[i] & 0x7f) << (7 * i);
        if (!(in[i] & 0x80))
        {
            if (v > 0xffffffffu)
                return false;
            length = static_cast<size_t>(v);
            return true;
        }
    }
    return false;
}

size_t snappy_compress(const uint8_t* in, size_t n, uint8_t* out)
{
    uint16_t table[1u << hash_bits];
    uint8_t* op = put_varint(out, n);
    for (size_t pos = 0; pos < n; pos += block_size)
        op = compress_block(in + pos, std::min(block_size, n - pos), op, table);
    return static_cast<size_t>(op - out);
}

long snappy_decompress(const uint8_t* in, size_t n, uint8_t* out, size_t cap)
{
    size_t len = 0;
    if (!snappy_length(in, n, len) || len > cap)
        return -1;
    size_t ip = 0;
    while (in[ip++] & 0x80) {}
    size_t op = 0;
    while (ip < n)
    {
        const uint8_t tag = in[ip++];
        size_t length = 0;
        size_t offset = 0;
        switch (tag & 3)
        {
            case 0:
            {
                length = tag >> 2;
                if (length >= 60)
                {
                    const size_t bytes = length - 59;
                    if (n - ip < bytes)
                        return -1;
                    length = 0;
                    for (size_t i = 0; i < bytes; ++i)
                        length |= static_cast<size_t>(in[ip + i]) << (8 * i);
                    ip += bytes;
                }
                ++length;
                if (length > n - ip || length > len - op)
                    return -1;
                std::memcpy(out + op, in + ip, length);
                ip += length;
                op += length;
                continue;
            }
            case 1:
                if (n - ip < 1)
                    return -1;
                length = 4 + ((tag >> 2) & 7);
                offset = (static_cast<size_t>(tag >> 5) << 8) | in[ip];
                ip += 1;
                break;
            case 2:
                if (n - ip < 2)
                    return -1;
                length = (tag >> 2) + 1u;
                offset = in[ip] | (static_cast<size_t>(in[ip + 1]) << 8);
                ip += 2;
                break;
            default:
                if (n - ip < 4)
                    return -1;
                length = (tag >> 2) + 1u;
                offset = in[ip] | (static_cast<size_t>(in[ip + 1]) << 8) | (static_cast<size_t>(in[ip + 2]) << 16) |
                         (static_cast<size_t>(in[ip + 3]) << 24);
                ip += 4;
                break;
        }
        if (offset == 0 || offset > op || length > len - op)
            return -1;
        // Byte by byte where the copy overlaps what it writes, which is how a run of one byte is said.
        if (offset >= length)
            std::memcpy(out + op, out + op - offset, length);
        else
            for (size_t i = 0; i < length; ++i)
                out[op + i] = out[op - offset + i];
        op += length;
    }
    return op == len ? static_cast<long>(op) : -1;
}

void snappy_compress(std::string_view in, std::string& out)
{
    out.resize(snappy_bound(in.size()));
    const size_t n = snappy_compress(reinterpret_cast<const uint8_t*>(in.data()), in.size(),
                                     reinterpret_cast<uint8_t*>(out.data()));
    out.resize(n);
}

bool snappy_decompress(std::string_view in, std::string& out, size_t limit)
{
    const auto* b = reinterpret_cast<const uint8_t*>(in.data());
    size_t len = 0;
    if (!snappy_length(b, in.size(), len) || len > limit)
        return false;
    out.resize(len);
    return snappy_decompress(b, in.size(), reinterpret_cast<uint8_t*>(out.data()), len) == static_cast<long>(len);
}

// ── WriteRequest, read ──────────────────────────────────────────────────────

namespace
{

constexpr const char* malformed = "the request is not a well-formed WriteRequest";
constexpr const char* wrong_type = "a field of the request has the wrong wire type";
// What a field handler answers for a field it does not take, which is then skipped.
constexpr const char* not_mine = "";

// One message's fields, each handed to `on`, which checks the wire type of those it takes.
template <class F>
const char* each_field(reader r, F&& on)
{
    while (!r.done())
    {
        uint32_t field, type;
        if (!r.tag(field, type))
            return malformed;
        const char* e = on(r, field, type);
        if (e == not_mine)
        {
            if (!r.skip(type))
                return malformed;
        }
        else if (e != nullptr)
            return e;
    }
    return nullptr;
}

const char* read_label(std::string_view body, label& out)
{
    return each_field(sub(body), [&](reader& r, uint32_t field, uint32_t type) -> const char* {
        if (field != 1 && field != 2)
            return not_mine;
        if (type != wire_bytes)
            return wrong_type;
        std::string_view s;
        if (!r.bytes(s))
            return malformed;
        (field == 1 ? out.name : out.value) = s;
        return nullptr;
    });
}

const char* read_sample(std::string_view body, sample& out)
{
    return each_field(sub(body), [&](reader& r, uint32_t field, uint32_t type) -> const char* {
        if (field == 1)
        {
            uint64_t bits;
            if (type != wire_fixed64)
                return wrong_type;
            if (!r.fixed64(bits))
                return malformed;
            out.value = std::bit_cast<double>(bits);
            return nullptr;
        }
        if (field == 2)
        {
            uint64_t v;
            if (type != wire_varint)
                return wrong_type;
            if (!r.varint(v))
                return malformed;
            out.timestamp_ms = static_cast<int64_t>(v);
            return nullptr;
        }
        return not_mine;
    });
}

const char* read_metadata(std::string_view body, metadata& out)
{
    return each_field(sub(body), [&](reader& r, uint32_t field, uint32_t type) -> const char* {
        if (field == 1)
        {
            uint64_t v;
            if (type != wire_varint)
                return wrong_type;
            if (!r.varint(v))
                return malformed;
            out.type = static_cast<uint32_t>(v);
            return nullptr;
        }
        if (field != 2 && field != 4 && field != 5)
            return not_mine;
        if (type != wire_bytes)
            return wrong_type;
        std::string_view s;
        if (!r.bytes(s))
            return malformed;
        (field == 2 ? out.family : field == 4 ? out.help : out.unit) = s;
        return nullptr;
    });
}

// The request walked once: to check it whole, then again to hand each series on.
template <bool Deliver>
const char* walk(std::string_view proto, std::vector<label>& labels, std::vector<sample>& samples, write_sink* sink,
                 decode_result& res)
{
    return each_field(sub(proto), [&](reader& r, uint32_t field, uint32_t type) -> const char* {
        if (field != 1 && field != 3)
            return not_mine;
        if (type != wire_bytes)
            return wrong_type;
        std::string_view body;
        if (!r.bytes(body))
            return malformed;
        if (field == 3)
        {
            metadata m;
            if (const char* e = read_metadata(body, m))
                return e;
            ++res.metadata;
            if constexpr (Deliver)
                sink->on_metadata(m);
            return nullptr;
        }
        labels.clear();
        samples.clear();
        series s;
        const char* e = each_field(sub(body), [&](reader& ts, uint32_t f, uint32_t t) -> const char* {
            if (f < 1 || f > 4)
                return not_mine;
            if (t != wire_bytes)
                return wrong_type;
            std::string_view part;
            if (!ts.bytes(part))
                return malformed;
            if (f == 1)
            {
                label l;
                if (const char* le = read_label(part, l))
                    return le;
                if constexpr (Deliver)
                    labels.push_back(l);
            }
            else if (f == 2)
            {
                sample x;
                if (const char* se = read_sample(part, x))
                    return se;
                ++res.samples;
                if constexpr (Deliver)
                    samples.push_back(x);
            }
            else if (f == 3)
                ++s.exemplars;
            else
                ++s.histograms;
            return nullptr;
        });
        if (e)
            return e;
        ++res.series;
        res.histograms += s.histograms;
        if constexpr (Deliver)
        {
            s.labels = labels;
            s.samples = samples;
            sink->on_series(s);
        }
        return nullptr;
    });
}

}   // namespace

decode_result write_decoder::decode(std::string_view proto, write_sink& sink)
{
    decode_result checked;
    if (const char* e = walk<false>(proto, m_labels, m_samples, nullptr, checked))
    {
        checked.error = e;
        return checked;
    }
    decode_result res;
    if (const char* e = walk<true>(proto, m_labels, m_samples, &sink, res))
        res.error = e;
    else
        res.ok = true;
    return res;
}

decode_result write_decoder::decode_snappy(std::string_view body, write_sink& sink, size_t limit)
{
    if (!snappy_decompress(body, m_opened, limit))
    {
        decode_result res;
        res.error = "the body is not a Snappy block, or opens past the limit";
        return res;
    }
    return decode(m_opened, sink);
}

// ── WriteRequest, written ───────────────────────────────────────────────────

void write_encoder::add(std::span<const label> labels, std::span<const sample> samples)
{
    // Fields at their default left out, as protobuf writes them.
    const auto label_size = [](const label& l) {
        return (l.name.empty() ? 0 : bytes_field_size(l.name)) + (l.value.empty() ? 0 : bytes_field_size(l.value));
    };
    const auto sample_size = [](const sample& s) {
        return (std::bit_cast<uint64_t>(s.value) != 0 ? 9 : 0) +
               (s.timestamp_ms != 0 ? 1 + varint_size(static_cast<uint64_t>(s.timestamp_ms)) : 0);
    };
    size_t body = 0;
    for (const label& l : labels)
    {
        const size_t n = label_size(l);
        body += 1 + varint_size(n) + n;
    }
    for (const sample& s : samples)
    {
        const size_t n = sample_size(s);
        body += 1 + varint_size(n) + n;
    }
    m_out.reserve(m_out.size() + 1 + varint_size(body) + body);
    m_out += '\x0a';
    put_varint(m_out, body);
    for (const label& l : labels)
    {
        m_out += '\x0a';
        put_varint(m_out, label_size(l));
        if (!l.name.empty())
            put_bytes_field(m_out, 0x0a, l.name);
        if (!l.value.empty())
            put_bytes_field(m_out, 0x12, l.value);
    }
    for (const sample& s : samples)
    {
        m_out += '\x12';
        put_varint(m_out, sample_size(s));
        if (uint64_t bits = std::bit_cast<uint64_t>(s.value); bits != 0)
        {
            if constexpr (std::endian::native == std::endian::big)
                bits = std::byteswap(bits);
            m_out += '\x09';
            m_out.append(reinterpret_cast<const char*>(&bits), 8);
        }
        if (s.timestamp_ms != 0)
        {
            m_out += '\x10';
            put_varint(m_out, static_cast<uint64_t>(s.timestamp_ms));
        }
    }
}

void write_encoder::add_metadata(const metadata& m)
{
    size_t body = (m.type != 0 ? 1 + varint_size(m.type) : 0);
    for (const std::string_view s : {m.family, m.help, m.unit})
        body += s.empty() ? 0 : bytes_field_size(s);
    m_out += '\x1a';
    put_varint(m_out, body);
    if (m.type != 0)
    {
        m_out += '\x08';
        put_varint(m_out, m.type);
    }
    if (!m.family.empty())
        put_bytes_field(m_out, 0x12, m.family);
    if (!m.help.empty())
        put_bytes_field(m_out, 0x22, m.help);
    if (!m.unit.empty())
        put_bytes_field(m_out, 0x2a, m.unit);
}

}   // namespace socketley::metrics::remote
