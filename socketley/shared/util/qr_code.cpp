#include "qr_code.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>

namespace socketley::qr
{
namespace
{

constexpr int max_version = 10;
// Level M, by version: error correction codewords per block, and blocks.
constexpr std::array<int, max_version + 1> ecc_per_block{0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26};
constexpr std::array<int, max_version + 1> blocks{0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5};

// The modules left for codewords once the function patterns are drawn.
int raw_modules(int ver)
{
    int n = (16 * ver + 128) * ver + 64;
    if (ver >= 2)
    {
        const int align = ver / 7 + 2;
        n -= (25 * align - 10) * align - 55;
        if (ver >= 7)
            n -= 36;
    }
    return n;
}

int data_codewords(int ver)
{
    return raw_modules(ver) / 8 - ecc_per_block[ver] * blocks[ver];
}

uint8_t gf_mul(uint8_t a, uint8_t b)
{
    int z = 0;
    for (int i = 7; i >= 0; --i)
    {
        z = (z << 1) ^ ((z >> 7) * 0x11D);
        z ^= ((b >> i) & 1) * a;
    }
    return static_cast<uint8_t>(z);
}

// The Reed-Solomon generator of `degree`, its leading 1 left out.
std::vector<uint8_t> rs_divisor(int degree)
{
    std::vector<uint8_t> r(static_cast<size_t>(degree), 0);
    r.back() = 1;
    uint8_t root = 1;
    for (int i = 0; i < degree; ++i)
    {
        for (size_t j = 0; j < r.size(); ++j)
        {
            r[j] = gf_mul(r[j], root);
            if (j + 1 < r.size())
                r[j] ^= r[j + 1];
        }
        root = gf_mul(root, 0x02);
    }
    return r;
}

std::vector<uint8_t> rs_remainder(const std::vector<uint8_t>& data, const std::vector<uint8_t>& divisor)
{
    std::vector<uint8_t> r(divisor.size(), 0);
    for (const uint8_t b : data)
    {
        const uint8_t factor = b ^ r.front();
        r.erase(r.begin());
        r.push_back(0);
        for (size_t i = 0; i < r.size(); ++i)
            r[i] ^= gf_mul(divisor[i], factor);
    }
    return r;
}

class grid
{
public:
    explicit grid(int ver) : ver(ver), size(ver * 4 + 17), dark(cells(), false), fixed(cells(), false) {}

    const int ver, size;
    std::vector<bool> dark, fixed;

    size_t cells() const { return static_cast<size_t>(size) * static_cast<size_t>(size); }
    size_t at(int x, int y) const { return static_cast<size_t>(y) * static_cast<size_t>(size) + static_cast<size_t>(x); }
    void put(int x, int y, bool d)
    {
        dark[at(x, y)] = d;
        fixed[at(x, y)] = true;
    }

    void draw_functions()
    {
        for (int i = 0; i < size; ++i)
        {
            put(6, i, i % 2 == 0);
            put(i, 6, i % 2 == 0);
        }
        finder(3, 3);
        finder(size - 4, 3);
        finder(3, size - 4);
        const std::vector<int> pos = alignment_positions();
        const size_t n = pos.size();
        for (size_t i = 0; i < n; ++i)
            for (size_t j = 0; j < n; ++j)
                // Not where a finder already is.
                if (!((i == 0 && j == 0) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0)))
                    alignment(pos[i], pos[j]);
        format_bits(0);
        version_bits();
    }

    void format_bits(int mask)
    {
        // Level M is 00 in the format's two bits.
        const int data = mask;
        int rem = data;
        for (int i = 0; i < 10; ++i)
            rem = (rem << 1) ^ ((rem >> 9) * 0x537);
        const int bits = ((data << 10) | rem) ^ 0x5412;
        const auto bit = [&](int i) { return ((bits >> i) & 1) != 0; };
        for (int i = 0; i <= 5; ++i)
            put(8, i, bit(i));
        put(8, 7, bit(6));
        put(8, 8, bit(7));
        put(7, 8, bit(8));
        for (int i = 9; i < 15; ++i)
            put(14 - i, 8, bit(i));
        for (int i = 0; i < 8; ++i)
            put(size - 1 - i, 8, bit(i));
        for (int i = 8; i < 15; ++i)
            put(8, size - 15 + i, bit(i));
        put(8, size - 8, true);
    }

    void place(const std::vector<uint8_t>& codewords)
    {
        size_t i = 0;
        const size_t bits = codewords.size() * 8;
        for (int right = size - 1; right >= 1; right -= 2)
        {
            if (right == 6)
                right = 5;
            for (int v = 0; v < size; ++v)
                for (int j = 0; j < 2; ++j)
                {
                    const int x = right - j;
                    const bool upward = ((right + 1) & 2) == 0;
                    const int y = upward ? size - 1 - v : v;
                    if (!fixed[at(x, y)] && i < bits)
                    {
                        dark[at(x, y)] = ((codewords[i >> 3] >> (7 - (i & 7))) & 1) != 0;
                        ++i;
                    }
                }
        }
    }

    void apply_mask(int mask)
    {
        for (int y = 0; y < size; ++y)
            for (int x = 0; x < size; ++x)
            {
                bool flip = false;
                switch (mask)
                {
                    case 0: flip = (x + y) % 2 == 0; break;
                    case 1: flip = y % 2 == 0; break;
                    case 2: flip = x % 3 == 0; break;
                    case 3: flip = (x + y) % 3 == 0; break;
                    case 4: flip = (x / 3 + y / 2) % 2 == 0; break;
                    case 5: flip = x * y % 2 + x * y % 3 == 0; break;
                    case 6: flip = (x * y % 2 + x * y % 3) % 2 == 0; break;
                    default: flip = ((x + y) % 2 + x * y % 3) % 2 == 0; break;
                }
                if (flip && !fixed[at(x, y)])
                    dark[at(x, y)] = !dark[at(x, y)];
            }
    }

    // Rules 1, 2 and 4 of the standard's penalty; any mask reads, this one picks the plainest.
    long penalty() const
    {
        long score = 0;
        for (int pass = 0; pass < 2; ++pass)
            for (int a = 0; a < size; ++a)
            {
                int run = 0;
                bool last = false;
                for (int b = 0; b < size; ++b)
                {
                    const bool d = pass == 0 ? dark[at(b, a)] : dark[at(a, b)];
                    if (b > 0 && d == last)
                    {
                        ++run;
                        if (run == 5)
                            score += 3;
                        else if (run > 5)
                            ++score;
                    }
                    else
                        run = 1;
                    last = d;
                }
            }
        for (int y = 0; y + 1 < size; ++y)
            for (int x = 0; x + 1 < size; ++x)
            {
                const bool d = dark[at(x, y)];
                if (d == dark[at(x + 1, y)] && d == dark[at(x, y + 1)] && d == dark[at(x + 1, y + 1)])
                    score += 3;
            }
        const long total = static_cast<long>(cells());
        const long darks = std::count(dark.begin(), dark.end(), true);
        score += (std::labs(darks * 20 - total * 10) + total - 1) / total * 10 - 10;
        return score;
    }

private:
    void finder(int cx, int cy)
    {
        for (int dy = -4; dy <= 4; ++dy)
            for (int dx = -4; dx <= 4; ++dx)
            {
                const int x = cx + dx, y = cy + dy;
                const int dist = std::max(std::abs(dx), std::abs(dy));
                if (x >= 0 && x < size && y >= 0 && y < size)
                    put(x, y, dist != 2 && dist != 4);
            }
    }

    void alignment(int cx, int cy)
    {
        for (int dy = -2; dy <= 2; ++dy)
            for (int dx = -2; dx <= 2; ++dx)
                put(cx + dx, cy + dy, std::max(std::abs(dx), std::abs(dy)) != 1);
    }

    std::vector<int> alignment_positions() const
    {
        if (ver == 1)
            return {};
        const int n = ver / 7 + 2;
        const int step = (ver * 8 + n * 3 + 5) / (n * 4 - 4) * 2;
        std::vector<int> r{6};
        for (int i = n - 1, p = size - 7; i >= 1; --i, p -= step)
            r.insert(r.begin() + 1, p);
        return r;
    }

    void version_bits()
    {
        if (ver < 7)
            return;
        int rem = ver;
        for (int i = 0; i < 12; ++i)
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
        const long bits = static_cast<long>(ver) << 12 | rem;
        for (int i = 0; i < 18; ++i)
        {
            const bool d = ((bits >> i) & 1) != 0;
            const int a = size - 11 + i % 3, b = i / 3;
            put(a, b, d);
            put(b, a, d);
        }
    }
};

}   // namespace

std::vector<std::vector<bool>> encode(std::string_view text)
{
    int ver = 1;
    // Mode, count (8 bits below version 10, 16 from it), the bytes.
    const auto needed = [&](int v) { return 4 + (v < 10 ? 8 : 16) + static_cast<int>(text.size()) * 8; };
    while (ver <= max_version && needed(ver) > data_codewords(ver) * 8)
        ++ver;
    if (ver > max_version)
        return {};

    std::vector<bool> bits;
    const auto push = [&](uint32_t v, int n) {
        for (int i = n - 1; i >= 0; --i)
            bits.push_back(((v >> i) & 1) != 0);
    };
    push(0x4, 4);
    push(static_cast<uint32_t>(text.size()), ver < 10 ? 8 : 16);
    for (const char c : text)
        push(static_cast<unsigned char>(c), 8);
    const size_t capacity = static_cast<size_t>(data_codewords(ver)) * 8;
    push(0, static_cast<int>(std::min<size_t>(4, capacity - bits.size())));
    push(0, static_cast<int>((8 - bits.size() % 8) % 8));
    for (uint32_t pad = 0xEC; bits.size() < capacity; pad ^= 0xEC ^ 0x11)
        push(pad, 8);
    std::vector<uint8_t> data(bits.size() / 8, 0);
    for (size_t i = 0; i < bits.size(); ++i)
        data[i >> 3] = static_cast<uint8_t>(data[i >> 3] | (bits[i] ? 1 << (7 - (i & 7)) : 0));

    // The data split into blocks, each with its error correction, and the blocks interleaved byte by byte.
    const int nblocks = blocks[ver], ecc = ecc_per_block[ver];
    const int raw = raw_modules(ver) / 8;
    const int short_blocks = nblocks - raw % nblocks;
    const int short_len = raw / nblocks;
    const std::vector<uint8_t> divisor = rs_divisor(ecc);
    std::vector<std::vector<uint8_t>> parts;
    for (int i = 0, k = 0; i < nblocks; ++i)
    {
        const int len = short_len - ecc + (i < short_blocks ? 0 : 1);
        std::vector<uint8_t> d(data.begin() + k, data.begin() + k + len);
        k += len;
        const std::vector<uint8_t> e = rs_remainder(d, divisor);
        // A short block is padded where a long one has its last data byte, and that pad is skipped below.
        if (i < short_blocks)
            d.push_back(0);
        d.insert(d.end(), e.begin(), e.end());
        parts.push_back(std::move(d));
    }
    std::vector<uint8_t> codewords;
    for (size_t i = 0; i < parts[0].size(); ++i)
        for (size_t j = 0; j < parts.size(); ++j)
            if (i != static_cast<size_t>(short_len - ecc) || j >= static_cast<size_t>(short_blocks))
                codewords.push_back(parts[j][i]);

    grid g(ver);
    g.draw_functions();
    g.place(codewords);
    int best = 0;
    long best_score = -1;
    for (int m = 0; m < 8; ++m)
    {
        g.apply_mask(m);
        g.format_bits(m);
        const long s = g.penalty();
        if (best_score < 0 || s < best_score)
        {
            best = m;
            best_score = s;
        }
        g.apply_mask(m);
    }
    g.apply_mask(best);
    g.format_bits(best);

    std::vector<std::vector<bool>> out(static_cast<size_t>(g.size), std::vector<bool>(static_cast<size_t>(g.size)));
    for (int y = 0; y < g.size; ++y)
        for (int x = 0; x < g.size; ++x)
            out[static_cast<size_t>(y)][static_cast<size_t>(x)] = g.dark[g.at(x, y)];
    return out;
}

std::string svg(std::string_view text)
{
    const auto m = encode(text);
    if (m.empty())
        return {};
    const std::string side = std::to_string(m.size() + 8);
    std::string out = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 " + side + " " + side +
                      "\" shape-rendering=\"crispEdges\"><rect width=\"100%\" height=\"100%\" fill=\"#fff\"/><path d=\"";
    for (size_t y = 0; y < m.size(); ++y)
        for (size_t x = 0; x < m.size(); ++x)
            if (m[y][x])
                out += "M" + std::to_string(x + 4) + " " + std::to_string(y + 4) + "h1v1h-1z";
    out += "\" fill=\"#000\"/></svg>";
    return out;
}

}   // namespace socketley::qr
