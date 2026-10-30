#include "metrics_chunk.h"

namespace socketley::metrics
{

namespace
{

// Whether `x` fits the signed field of `n` bits the delta-of-delta buckets use.
bool fits_bits(int64_t x, unsigned n)
{
    const int64_t half = int64_t(1) << (n - 1);
    return x >= -(half - 1) && x <= half;
}

int64_t from_field(uint64_t bits, unsigned n)
{
    const uint64_t half = uint64_t(1) << (n - 1);
    return bits > half ? static_cast<int64_t>(bits) - (int64_t(1) << n) : static_cast<int64_t>(bits);
}

uint16_t load16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }

void store16(uint8_t* p, uint16_t v)
{
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
}

}   // namespace

void put_dod(uint8_t* buf, uint32_t& pos, int64_t dod)
{
    const auto u = static_cast<uint64_t>(dod);
    if (dod == 0)
        put_bits(buf, pos, 0, 1);
    else if (fits_bits(dod, 14))
    {
        put_bits(buf, pos, 0b10, 2);
        put_bits(buf, pos, u, 14);
    }
    else if (fits_bits(dod, 17))
    {
        put_bits(buf, pos, 0b110, 3);
        put_bits(buf, pos, u, 17);
    }
    else if (fits_bits(dod, 20))
    {
        put_bits(buf, pos, 0b1110, 4);
        put_bits(buf, pos, u, 20);
    }
    else
    {
        put_bits(buf, pos, 0b1111, 4);
        put_bits(buf, pos, u, 64);
    }
}

bool get_dod(bit_reader& r, int64_t& dod)
{
    unsigned ones = 0;
    for (; ones < 4; ++ones)
    {
        bool b = false;
        if (!r.bit(b))
            return false;
        if (!b)
            break;
    }
    static constexpr unsigned width[5] = {0, 14, 17, 20, 64};
    const unsigned n = width[ones];
    if (n == 0)
    {
        dod = 0;
        return true;
    }
    uint64_t bits = 0;
    if (!r.get(n, bits))
        return false;
    dod = n == 64 ? static_cast<int64_t>(bits) : from_field(bits, n);
    return true;
}

void put_xor(uint8_t* buf, uint32_t& pos, xor_state& x, uint64_t bits)
{
    const uint64_t d = bits ^ x.prev;
    x.prev = bits;
    if (d == 0)
    {
        put_bits(buf, pos, 0, 1);
        return;
    }
    put_bits(buf, pos, 1, 1);
    unsigned lead = static_cast<unsigned>(std::countl_zero(d));
    const auto trail = static_cast<unsigned>(std::countr_zero(d));
    if (lead >= 32)
        lead = 31;
    if (x.lead != 0xff && lead >= x.lead && trail >= x.trail)
    {
        put_bits(buf, pos, 0, 1);
        put_bits(buf, pos, d >> x.trail, 64u - x.lead - x.trail);
        return;
    }
    x.lead = static_cast<uint8_t>(lead);
    x.trail = static_cast<uint8_t>(trail);
    const unsigned sig = 64 - lead - trail;
    put_bits(buf, pos, 1, 1);
    put_bits(buf, pos, lead, 5);
    put_bits(buf, pos, sig & 63u, 6);
    put_bits(buf, pos, d >> trail, sig);
}

bool get_xor(bit_reader& r, xor_state& x)
{
    bool b = false;
    if (!r.bit(b))
        return false;
    if (!b)
        return true;
    if (!r.bit(b))
        return false;
    uint64_t bits = 0;
    if (!b)
    {
        if (x.lead == 0xff)
            return false;
        if (!r.get(64u - x.lead - x.trail, bits))
            return false;
        x.prev ^= bits << x.trail;
        return true;
    }
    uint64_t lead = 0, sig = 0;
    if (!r.get(5, lead) || !r.get(6, sig))
        return false;
    if (sig == 0)
        sig = 64;
    if (lead + sig > 64)
        return false;
    const unsigned trail = static_cast<unsigned>(64 - lead - sig);
    if (!r.get(static_cast<unsigned>(sig), bits))
        return false;
    x.lead = static_cast<uint8_t>(lead);
    x.trail = static_cast<uint8_t>(trail);
    x.prev ^= bits << trail;
    return true;
}

bool chunk_appender::append(uint8_t* buf, size_t cap, int64_t t, double v)
{
    if (!fits(cap))
        return false;
    uint8_t* body = buf + chunk_head_bytes;
    uint32_t pos = bits;
    const auto vb = std::bit_cast<uint64_t>(v);
    if (n == 0)
    {
        put_bits(body, pos, static_cast<uint64_t>(t), 64);
        put_bits(body, pos, vb, 64);
        mint = t;
        x = xor_state{};
        x.prev = vb;
    }
    else
    {
        const int64_t d = wrap_sub(t, maxt);
        put_dod(body, pos, wrap_sub(d, delta));
        delta = d;
        put_xor(body, pos, x, vb);
    }
    maxt = t;
    bits = pos;
    ++n;
    store16(buf, n);
    return true;
}

chunk_reader::chunk_reader(std::span<const uint8_t> bytes)
{
    if (bytes.size() < chunk_head_bytes)
    {
        m_failed = !bytes.empty();
        return;
    }
    m_n = load16(bytes.data());
    m_r = bit_reader(bytes.data() + chunk_head_bytes, bytes.size() - chunk_head_bytes);
}

bool chunk_reader::next()
{
    if (m_failed || m_i >= m_n)
        return false;
    if (m_i == 0)
    {
        uint64_t t = 0, v = 0;
        if (!m_r.get(64, t) || !m_r.get(64, v))
        {
            m_failed = true;
            return false;
        }
        m_t = static_cast<int64_t>(t);
        m_x = xor_state{};
        m_x.prev = v;
    }
    else
    {
        int64_t dod = 0;
        if (!get_dod(m_r, dod) || !get_xor(m_r, m_x))
        {
            m_failed = true;
            return false;
        }
        m_delta = wrap_add(m_delta, dod);
        m_t = wrap_add(m_t, m_delta);
    }
    ++m_i;
    return true;
}

void encode_chunk(std::span<const sample> in, std::vector<uint8_t>& out)
{
    const size_t n = in.size() < 0xFFFF ? in.size() : 0xFFFF;
    const size_t cap = chunk_head_bytes + (first_sample_bits + n * max_sample_bits) / 8 + 1;
    out.assign(cap, 0);
    chunk_appender a;
    for (size_t i = 0; i < n; ++i)
        if (!a.append(out.data(), cap, in[i].t, in[i].v))
            break;
    out.resize(n == 0 ? chunk_head_bytes : a.bytes());
}

bool decode_chunk(std::span<const uint8_t> bytes, std::vector<sample>& out)
{
    chunk_reader r(bytes);
    while (r.next())
        out.push_back(sample{r.t(), r.v()});
    return !r.failed();
}

namespace
{

double& column(tier_point& p, unsigned c)
{
    switch (c)
    {
        case 0: return p.min;
        case 1: return p.max;
        case 2: return p.sum;
        case 3: return p.count;
        case 4: return p.last;
        case 5: return p.first;
        default: return p.rise;
    }
}

double column(const tier_point& p, unsigned c) { return column(const_cast<tier_point&>(p), c); }

}   // namespace

void encode_tier_chunk(std::span<const tier_point> in, std::vector<uint8_t>& out)
{
    const size_t n = in.size() < 0xFFFF ? in.size() : 0xFFFF;
    const size_t per_point = (68 + tier_columns * 77) / 8 + 1;
    out.assign(chunk_head_bytes + 8 * (1 + tier_columns) + n * per_point, 0);
    store16(out.data(), static_cast<uint16_t>(n));
    uint8_t* body = out.data() + chunk_head_bytes;
    uint32_t pos = 0;
    xor_state x[tier_columns];
    int64_t t = 0, delta = 0;
    for (size_t i = 0; i < n; ++i)
    {
        const tier_point& p = in[i];
        if (i == 0)
        {
            put_bits(body, pos, static_cast<uint64_t>(p.t), 64);
            for (unsigned c = 0; c < tier_columns; ++c)
            {
                x[c].prev = std::bit_cast<uint64_t>(column(p, c));
                put_bits(body, pos, x[c].prev, 64);
            }
        }
        else
        {
            const int64_t d = wrap_sub(p.t, t);
            put_dod(body, pos, wrap_sub(d, delta));
            delta = d;
            for (unsigned c = 0; c < tier_columns; ++c)
                put_xor(body, pos, x[c], std::bit_cast<uint64_t>(column(p, c)));
        }
        t = p.t;
    }
    out.resize(chunk_head_bytes + (size_t(pos) + 7) / 8);
}

bool decode_tier_chunk(std::span<const uint8_t> bytes, std::vector<tier_point>& out)
{
    if (bytes.size() < chunk_head_bytes)
        return bytes.empty();
    const uint16_t n = load16(bytes.data());
    bit_reader r(bytes.data() + chunk_head_bytes, bytes.size() - chunk_head_bytes);
    xor_state x[tier_columns];
    int64_t t = 0, delta = 0;
    for (uint16_t i = 0; i < n; ++i)
    {
        tier_point p;
        if (i == 0)
        {
            uint64_t bits = 0;
            if (!r.get(64, bits))
                return false;
            t = static_cast<int64_t>(bits);
            for (unsigned c = 0; c < tier_columns; ++c)
            {
                if (!r.get(64, bits))
                    return false;
                x[c].prev = bits;
            }
        }
        else
        {
            int64_t dod = 0;
            if (!get_dod(r, dod))
                return false;
            delta = wrap_add(delta, dod);
            t = wrap_add(t, delta);
            for (unsigned c = 0; c < tier_columns; ++c)
                if (!get_xor(r, x[c]))
                    return false;
        }
        p.t = t;
        for (unsigned c = 0; c < tier_columns; ++c)
            column(p, c) = std::bit_cast<double>(x[c].prev);
        out.push_back(p);
    }
    return true;
}

}   // namespace socketley::metrics
