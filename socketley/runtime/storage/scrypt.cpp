#include "scrypt.h"

#include <climits>
#include <cstring>
#include <memory>
#include <sys/mman.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#if defined(__x86_64__)
#include <immintrin.h>
#endif

namespace socketley::storage::scrypt
{

namespace
{

// OpenSSL's bounds, in its order, so a hash it would refuse is refused here too.
bool params_ok(uint64_t N, uint32_t r, uint32_t p, uint64_t max_mem)
{
    constexpr uint64_t pr_max = (uint64_t(1) << 30) - 1;
    if (r == 0 || p == 0 || N < 2 || (N & (N - 1)))
        return false;
    if (p > pr_max / r)
        return false;
    if (16 * uint64_t(r) <= 63 && N >= (uint64_t(1) << (16 * r)))
        return false;
    const uint64_t blen = uint64_t(p) * 128 * r;
    if (blen > INT_MAX)
        return false;
    if (N + 2 > (UINT64_MAX / 128) / r)
        return false;
    const uint64_t vlen = 128 * uint64_t(r) * (N + 2);
    return blen <= UINT64_MAX - vlen && blen + vlen <= max_mem;
}

bool pbkdf2(std::string_view password, std::string_view salt, unsigned char* out, size_t len)
{
    return password.size() <= INT_MAX && salt.size() <= INT_MAX && len <= INT_MAX &&
           PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                             reinterpret_cast<const unsigned char*>(salt.data()), static_cast<int>(salt.size()), 1,
                             EVP_sha256(), static_cast<int>(len), out) == 1;
}

uint32_t word_at(const void* base, size_t i)
{
    uint32_t w;
    std::memcpy(&w, static_cast<const char*>(base) + 4 * i, 4);
    return w;
}

void set_word(void* base, size_t i, uint32_t w)
{
    std::memcpy(static_cast<char*>(base) + 4 * i, &w, 4);
}

#if defined(__x86_64__)

// Bytes derived from a password, cleared before they are freed, as OpenSSL clears its own.
struct cleansed
{
    size_t n;
    void operator()(unsigned char* p) const
    {
        OPENSSL_cleanse(p, n);
        delete[] p;
    }
};
using secret_bytes = std::unique_ptr<unsigned char[], cleansed>;

// Memory of its own mapping, in huge pages where the kernel gives them: a V is read at random across 16 MiB, which
// 4 KiB pages make a TLB miss nearly every block, and taken fresh each time, which they make 4096 faults.
class block_memory
{
public:
    explicit block_memory(size_t n) : m_n((n + huge - 1) & ~(huge - 1))
    {
        void* p = ::mmap(nullptr, m_n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        m_p = p == MAP_FAILED ? nullptr : static_cast<unsigned char*>(p);
        if (m_p && ::madvise(m_p, m_n, MADV_HUGEPAGE) != 0) {}
    }
    ~block_memory()
    {
        if (m_p && ::munmap(m_p, m_n) != 0) {}
    }
    block_memory(const block_memory&) = delete;
    block_memory& operator=(const block_memory&) = delete;
    bool ok() const { return m_p != nullptr; }
    template <class T>
    T* as() const
    {
        return reinterpret_cast<T*>(m_p);
    }

private:
    static constexpr size_t huge = size_t(2) << 20;
    size_t m_n;
    unsigned char* m_p;
};

// Salsa20/8 with each block's words in the order (5i mod 16), which puts the columns, then the rows, in the lanes.
inline void salsa8(__m128i (&B)[4])
{
    __m128i X0 = B[0], X1 = B[1], X2 = B[2], X3 = B[3], T;
#define SKL_QR(a, b, c, s)                                      \
    T = _mm_add_epi32(b, c);                                    \
    a = _mm_xor_si128(a, _mm_slli_epi32(T, s));                 \
    a = _mm_xor_si128(a, _mm_srli_epi32(T, 32 - s));
    for (int i = 0; i < 8; i += 2)
    {
        SKL_QR(X1, X0, X3, 7) SKL_QR(X2, X1, X0, 9) SKL_QR(X3, X2, X1, 13) SKL_QR(X0, X3, X2, 18)
        X1 = _mm_shuffle_epi32(X1, 0x93);
        X2 = _mm_shuffle_epi32(X2, 0x4E);
        X3 = _mm_shuffle_epi32(X3, 0x39);
        SKL_QR(X3, X0, X1, 7) SKL_QR(X2, X3, X0, 9) SKL_QR(X1, X2, X3, 13) SKL_QR(X0, X1, X2, 18)
        X1 = _mm_shuffle_epi32(X1, 0x39);
        X2 = _mm_shuffle_epi32(X2, 0x4E);
        X3 = _mm_shuffle_epi32(X3, 0x93);
    }
#undef SKL_QR
    B[0] = _mm_add_epi32(B[0], X0);
    B[1] = _mm_add_epi32(B[1], X1);
    B[2] = _mm_add_epi32(B[2], X2);
    B[3] = _mm_add_epi32(B[3], X3);
}

// BlockMix over 2r blocks of four vectors, the even outputs first and then the odd.
void blockmix(const __m128i* in, __m128i* out, size_t r)
{
    __m128i X[4];
    for (int k = 0; k < 4; ++k)
        X[k] = in[(2 * r - 1) * 4 + k];
    for (size_t i = 0; i < r; ++i)
    {
        for (int k = 0; k < 4; ++k)
            X[k] = _mm_xor_si128(X[k], in[2 * i * 4 + k]);
        salsa8(X);
        for (int k = 0; k < 4; ++k)
            out[i * 4 + k] = X[k];
        for (int k = 0; k < 4; ++k)
            X[k] = _mm_xor_si128(X[k], in[(2 * i + 1) * 4 + k]);
        salsa8(X);
        for (int k = 0; k < 4; ++k)
            out[(r + i) * 4 + k] = X[k];
    }
}

// The last block's first 64 bits: words 0 and 1, which the shuffle put at 0 and 13.
uint64_t integerify(const void* last_block)
{
    return word_at(last_block, 0) | uint64_t(word_at(last_block, 13)) << 32;
}

// ROMix of one 128r-byte B in place, with V of N * 128r bytes and X, Y of 128r each.
void smix(unsigned char* B, size_t r, uint64_t N, __m128i* V, __m128i* X, __m128i* Y)
{
    const size_t vb = 8 * r;
    for (size_t k = 0; k < 2 * r; ++k)
        for (size_t i = 0; i < 16; ++i)
            set_word(X, k * 16 + i, word_at(B, k * 16 + i * 5 % 16));
    for (uint64_t i = 0; i < N; i += 2)
    {
        std::memcpy(V + i * vb, X, 128 * r);
        blockmix(X, Y, r);
        std::memcpy(V + (i + 1) * vb, Y, 128 * r);
        blockmix(Y, X, r);
    }
    for (uint64_t i = 0; i < N; i += 2)
    {
        uint64_t j = integerify(X + (2 * r - 1) * 4) & (N - 1);
        for (size_t k = 0; k < vb; ++k)
            X[k] = _mm_xor_si128(X[k], V[j * vb + k]);
        blockmix(X, Y, r);
        j = integerify(Y + (2 * r - 1) * 4) & (N - 1);
        for (size_t k = 0; k < vb; ++k)
            Y[k] = _mm_xor_si128(Y[k], V[j * vb + k]);
        blockmix(Y, X, r);
    }
    for (size_t k = 0; k < 2 * r; ++k)
        for (size_t i = 0; i < 16; ++i)
            set_word(B, k * 16 + i * 5 % 16, word_at(X, k * 16 + i));
}

bool derive_sse(std::string_view password, std::string_view salt, uint64_t N, uint32_t r, uint32_t p,
                unsigned char* out, size_t out_len)
{
    const size_t blen = size_t(128) * r * p;
    secret_bytes B(new unsigned char[blen], cleansed{blen});
    if (!pbkdf2(password, salt, B.get(), blen))
        return false;
    block_memory V(size_t(128) * r * N + size_t(256) * r);
    if (!V.ok())
        return false;
    __m128i* XY = V.as<__m128i>() + size_t(8) * r * N;
    for (uint32_t i = 0; i < p; ++i)
        smix(B.get() + size_t(128) * r * i, r, N, V.as<__m128i>(), XY, XY + 8 * r);
    return pbkdf2(password, std::string_view(reinterpret_cast<const char*>(B.get()), blen), out, out_len);
}

#pragma GCC push_options
#pragma GCC target("avx2")

// C chains of four 256-bit vectors, each holding two hashes, one a 128-bit lane: 2C hashes in one stream.
template <int C>
inline void salsa8x(__m256i (&B)[C][4])
{
    __m256i X[C][4], T[C];
    for (int c = 0; c < C; ++c)
        for (int k = 0; k < 4; ++k)
            X[c][k] = B[c][k];
#define SKL_QRX(a, b, d, s)                                                         \
    for (int c = 0; c < C; ++c)                                                     \
    {                                                                               \
        T[c] = _mm256_add_epi32(X[c][b], X[c][d]);                                  \
        X[c][a] = _mm256_xor_si256(X[c][a], _mm256_slli_epi32(T[c], s));            \
        X[c][a] = _mm256_xor_si256(X[c][a], _mm256_srli_epi32(T[c], 32 - s));       \
    }
    for (int i = 0; i < 8; i += 2)
    {
        SKL_QRX(1, 0, 3, 7) SKL_QRX(2, 1, 0, 9) SKL_QRX(3, 2, 1, 13) SKL_QRX(0, 3, 2, 18)
        for (int c = 0; c < C; ++c)
        {
            X[c][1] = _mm256_shuffle_epi32(X[c][1], 0x93);
            X[c][2] = _mm256_shuffle_epi32(X[c][2], 0x4E);
            X[c][3] = _mm256_shuffle_epi32(X[c][3], 0x39);
        }
        SKL_QRX(3, 0, 1, 7) SKL_QRX(2, 3, 0, 9) SKL_QRX(1, 2, 3, 13) SKL_QRX(0, 1, 2, 18)
        for (int c = 0; c < C; ++c)
        {
            X[c][1] = _mm256_shuffle_epi32(X[c][1], 0x39);
            X[c][2] = _mm256_shuffle_epi32(X[c][2], 0x4E);
            X[c][3] = _mm256_shuffle_epi32(X[c][3], 0x93);
        }
    }
#undef SKL_QRX
    for (int c = 0; c < C; ++c)
        for (int k = 0; k < 4; ++k)
            B[c][k] = _mm256_add_epi32(B[c][k], X[c][k]);
}

// blockmix() of 2C hashes; vector (blk * C + c) * 4 + k is block blk's k-th of chain c.
template <int C>
void blockmixx(const __m256i* in, __m256i* out, size_t r)
{
    __m256i X[C][4];
    for (int c = 0; c < C; ++c)
        for (int k = 0; k < 4; ++k)
            X[c][k] = in[((2 * r - 1) * C + c) * 4 + k];
    for (size_t i = 0; i < r; ++i)
    {
        for (int c = 0; c < C; ++c)
            for (int k = 0; k < 4; ++k)
                X[c][k] = _mm256_xor_si256(X[c][k], in[(2 * i * C + c) * 4 + k]);
        salsa8x<C>(X);
        for (int c = 0; c < C; ++c)
            for (int k = 0; k < 4; ++k)
                out[(i * C + c) * 4 + k] = X[c][k];
        for (int c = 0; c < C; ++c)
            for (int k = 0; k < 4; ++k)
                X[c][k] = _mm256_xor_si256(X[c][k], in[((2 * i + 1) * C + c) * 4 + k]);
        salsa8x<C>(X);
        for (int c = 0; c < C; ++c)
            for (int k = 0; k < 4; ++k)
                out[((r + i) * C + c) * 4 + k] = X[c][k];
    }
}

// Word i of block k of hash h, as the 32-bit words of the vectors count.
template <int C>
size_t lane_word(size_t k, int h, size_t i)
{
    return ((k * C + static_cast<size_t>(h / 2)) * 4 + i / 4) * 8 + static_cast<size_t>(h % 2) * 4 + i % 4;
}

// smix() of 2C hashes at once, each with a V of its own.
template <int C>
void smixx(unsigned char* const* B, size_t r, uint64_t N, __m128i* const* V, __m256i* X, __m256i* Y)
{
    constexpr int H = 2 * C;
    const size_t vb = 8 * r;
    for (int h = 0; h < H; ++h)
        for (size_t k = 0; k < 2 * r; ++k)
            for (size_t i = 0; i < 16; ++i)
                set_word(X, lane_word<C>(k, h, i), word_at(B[h], k * 16 + i * 5 % 16));
    auto keep = [&](uint64_t i, const __m256i* S)
    {
        for (size_t blk = 0; blk < 2 * r; ++blk)
            for (int c = 0; c < C; ++c)
                for (int k = 0; k < 4; ++k)
                {
                    const __m256i v = S[(blk * C + c) * 4 + k];
                    _mm_store_si128(V[2 * c] + i * vb + blk * 4 + k, _mm256_castsi256_si128(v));
                    _mm_store_si128(V[2 * c + 1] + i * vb + blk * 4 + k, _mm256_extracti128_si256(v, 1));
                }
    };
    auto mix_in = [&](__m256i* S)
    {
        uint64_t j[H];
        for (int h = 0; h < H; ++h)
            j[h] = (word_at(S, lane_word<C>(2 * r - 1, h, 0)) |
                    uint64_t(word_at(S, lane_word<C>(2 * r - 1, h, 13))) << 32) &
                   (N - 1);
        for (size_t blk = 0; blk < 2 * r; ++blk)
            for (int c = 0; c < C; ++c)
                for (int k = 0; k < 4; ++k)
                {
                    const __m128i lo = _mm_load_si128(V[2 * c] + j[2 * c] * vb + blk * 4 + k);
                    const __m128i hi = _mm_load_si128(V[2 * c + 1] + j[2 * c + 1] * vb + blk * 4 + k);
                    __m256i& s = S[(blk * C + c) * 4 + k];
                    s = _mm256_xor_si256(s, _mm256_inserti128_si256(_mm256_castsi128_si256(lo), hi, 1));
                }
    };
    for (uint64_t i = 0; i < N; i += 2)
    {
        keep(i, X);
        blockmixx<C>(X, Y, r);
        keep(i + 1, Y);
        blockmixx<C>(Y, X, r);
    }
    for (uint64_t i = 0; i < N; i += 2)
    {
        mix_in(X);
        blockmixx<C>(X, Y, r);
        mix_in(Y);
        blockmixx<C>(Y, X, r);
    }
    for (int h = 0; h < H; ++h)
        for (size_t k = 0; k < 2 * r; ++k)
            for (size_t i = 0; i < 16; ++i)
                set_word(B[h], k * 16 + i * 5 % 16, word_at(X, lane_word<C>(k, h, i)));
}

template <int C>
bool derive_avx2(const job* jobs, uint64_t N, uint32_t r)
{
    constexpr int H = 2 * C;
    const size_t blen = size_t(128) * r;
    secret_bytes B(new unsigned char[blen * H], cleansed{blen * H});
    block_memory V(size_t(128) * r * N * H + size_t(512) * r * C);
    if (!V.ok())
        return false;
    __m256i* XY = reinterpret_cast<__m256i*>(V.as<unsigned char>() + size_t(128) * r * N * H);
    unsigned char* Bh[H];
    __m128i* Vh[H];
    for (int h = 0; h < H; ++h)
    {
        Bh[h] = B.get() + blen * h;
        Vh[h] = V.as<__m128i>() + size_t(8) * r * N * h;
        if (!pbkdf2(jobs[h].password, jobs[h].salt, Bh[h], blen))
            return false;
    }
    smixx<C>(Bh, r, N, Vh, XY, XY + size_t(8) * r * C);
    for (int h = 0; h < H; ++h)
        if (jobs[h].out &&
            !pbkdf2(jobs[h].password, std::string_view(reinterpret_cast<const char*>(Bh[h]), blen), jobs[h].out,
                    jobs[h].out_len))
            return false;
    return true;
}

// Two hashes in one stream, or four in two, the most AVX2's sixteen registers hold without spilling.
bool derive_avx2_any(std::span<const job> jobs, uint64_t N, uint32_t r)
{
    if (jobs.size() == 2)
        return derive_avx2<1>(jobs.data(), N, r);
    // Three are made as four, the fourth thrown away, which is still less than one alone beside two.
    job four[4] = {};
    for (size_t i = 0; i < jobs.size(); ++i)
        four[i] = jobs[i];
    return derive_avx2<2>(four, N, r);
}

#pragma GCC pop_options

bool has_avx2()
{
    static const bool yes = __builtin_cpu_supports("avx2");
    return yes;
}

#endif

}   // namespace

bool derive(std::string_view password, std::string_view salt, uint64_t N, uint32_t r, uint32_t p, uint64_t max_mem,
            unsigned char* out, size_t out_len)
{
    if (!params_ok(N, r, p, max_mem))
        return false;
#if defined(__x86_64__)
    return derive_sse(password, salt, N, r, p, out, out_len);
#else
    return EVP_PBE_scrypt(password.data(), password.size(), reinterpret_cast<const unsigned char*>(salt.data()),
                          salt.size(), N, r, p, max_mem, out, out_len) == 1;
#endif
}

bool derive_many(std::span<const job> jobs, uint64_t N, uint32_t r, uint64_t max_mem)
{
    if (jobs.empty())
        return true;
    if (jobs.size() > max_batch || !params_ok(N, r, 1, max_mem))
        return false;
#if defined(__x86_64__)
    if (jobs.size() > 1 && has_avx2())
        return derive_avx2_any(jobs, N, r);
#endif
    for (const job& j : jobs)
        if (!derive(j.password, j.salt, N, r, 1, max_mem, j.out, j.out_len))
            return false;
    return true;
}

}   // namespace socketley::storage::scrypt
