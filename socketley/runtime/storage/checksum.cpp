#include "checksum.h"

#include <array>
#include <cctype>
#include <cstring>

#include <openssl/evp.h>

#if defined(__x86_64__)
#endif

#include "../../shared/raft_storage.h"

namespace socketley::storage
{

namespace
{

constexpr std::string_view header_prefix = "x-amz-checksum-";

// The reflected polynomial of CRC-32 as zlib and gzip use it.
constexpr uint32_t crc32_poly = 0xEDB88320u;
// The reflected polynomial of CRC-64/NVME.
constexpr uint64_t crc64_poly = 0x9A6C9329AC4BC9B5ull;

constexpr std::array<uint32_t, 256> make_crc32_table()
{
    std::array<uint32_t, 256> t{};
    for (uint32_t i = 0; i < 256; ++i)
    {
        uint32_t c = i;
        for (int k = 0; k < 8; ++k)
            c = (c & 1) ? (c >> 1) ^ crc32_poly : c >> 1;
        t[i] = c;
    }
    return t;
}

constexpr std::array<uint64_t, 256> make_crc64_table()
{
    std::array<uint64_t, 256> t{};
    for (uint64_t i = 0; i < 256; ++i)
    {
        uint64_t c = i;
        for (int k = 0; k < 8; ++k)
            c = (c & 1) ? (c >> 1) ^ crc64_poly : c >> 1;
        t[i] = c;
    }
    return t;
}

constexpr auto crc32_table = make_crc32_table();
constexpr auto crc64_table = make_crc64_table();

uint32_t crc32_update(uint32_t crc, const unsigned char* p, size_t n)
{
    crc = ~crc;
    for (size_t i = 0; i < n; ++i)
        crc = crc32_table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

uint64_t crc64_update(uint64_t crc, const unsigned char* p, size_t n)
{
    crc = ~crc;
    for (size_t i = 0; i < n; ++i)
        crc = crc64_table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

uint32_t crc32c_update(uint32_t crc, const unsigned char* p, size_t n)
{
    return raft::storage::crc32c(p, n, crc);
}

// The big-endian bytes S3 base64-encodes for a CRC.
std::string be_bytes(uint64_t v, size_t n)
{
    std::string out(n, '\0');
    for (size_t i = 0; i < n; ++i)
        out[n - 1 - i] = static_cast<char>((v >> (8 * i)) & 0xFF);
    return out;
}

constexpr checksum_algo all_algos[] = {checksum_algo::crc32, checksum_algo::crc32c, checksum_algo::crc64nvme,
                                       checksum_algo::sha1, checksum_algo::sha256};

}   // namespace

struct checksum_stream::digest
{
    EVP_MD_CTX* ctx{nullptr};
    explicit digest(const EVP_MD* md) : ctx(EVP_MD_CTX_new())
    {
        if (ctx)
            EVP_DigestInit_ex(ctx, md, nullptr);
    }
    ~digest() { EVP_MD_CTX_free(ctx); }
};

std::string_view checksum_header(checksum_algo a)
{
    switch (a)
    {
        case checksum_algo::crc32:     return "x-amz-checksum-crc32";
        case checksum_algo::crc32c:    return "x-amz-checksum-crc32c";
        case checksum_algo::crc64nvme: return "x-amz-checksum-crc64nvme";
        case checksum_algo::sha1:      return "x-amz-checksum-sha1";
        case checksum_algo::sha256:    return "x-amz-checksum-sha256";
        case checksum_algo::none:      break;
    }
    return {};
}

std::string_view checksum_name(checksum_algo a)
{
    switch (a)
    {
        case checksum_algo::crc32:     return "CRC32";
        case checksum_algo::crc32c:    return "CRC32C";
        case checksum_algo::crc64nvme: return "CRC64NVME";
        case checksum_algo::sha1:      return "SHA1";
        case checksum_algo::sha256:    return "SHA256";
        case checksum_algo::none:      break;
    }
    return {};
}

size_t checksum_raw_len(checksum_algo a)
{
    switch (a)
    {
        case checksum_algo::crc32:
        case checksum_algo::crc32c:    return 4;
        case checksum_algo::crc64nvme: return 8;
        case checksum_algo::sha1:      return 20;
        case checksum_algo::sha256:    return 32;
        case checksum_algo::none:      break;
    }
    return 0;
}

size_t checksum_b64_len(checksum_algo a)
{
    return (checksum_raw_len(a) + 2) / 3 * 4;
}

checksum_algo checksum_from_header(std::string_view h)
{
    for (checksum_algo a : all_algos)
        if (h == checksum_header(a))
            return a;
    return checksum_algo::none;
}

checksum_algo checksum_from_name(std::string_view n)
{
    for (checksum_algo a : all_algos)
    {
        const std::string_view want = checksum_name(a);
        if (n.size() != want.size())
            continue;
        bool same = true;
        for (size_t i = 0; i < n.size(); ++i)
            if (std::toupper(static_cast<unsigned char>(n[i])) != want[i])
                same = false;
        if (same)
            return a;
    }
    return checksum_algo::none;
}

bool is_checksum_header(std::string_view h)
{
    return h.starts_with(header_prefix) && h != "x-amz-checksum-algorithm" && h != "x-amz-checksum-mode" &&
           h != "x-amz-checksum-type";
}

checksum_stream::checksum_stream(checksum_algo a) : m_algo(a)
{
    if (a == checksum_algo::sha1)
        m_digest = std::make_unique<digest>(EVP_sha1());
    else if (a == checksum_algo::sha256)
        m_digest = std::make_unique<digest>(EVP_sha256());
}

checksum_stream::~checksum_stream() = default;

void checksum_stream::update(const void* data, size_t n)
{
    if (n == 0)
        return;
    const auto* p = static_cast<const unsigned char*>(data);
    switch (m_algo)
    {
        case checksum_algo::crc32:     m_crc = crc32_update(static_cast<uint32_t>(m_crc), p, n); break;
        case checksum_algo::crc32c:    m_crc = crc32c_update(static_cast<uint32_t>(m_crc), p, n); break;
        case checksum_algo::crc64nvme: m_crc = crc64_update(m_crc, p, n); break;
        case checksum_algo::sha1:
        case checksum_algo::sha256:
            if (m_digest && m_digest->ctx)
                EVP_DigestUpdate(m_digest->ctx, data, n);
            break;
        case checksum_algo::none: break;
    }
}

std::string checksum_stream::peek_raw() const
{
    switch (m_algo)
    {
        case checksum_algo::crc32:
        case checksum_algo::crc32c:    return be_bytes(m_crc, 4);
        case checksum_algo::crc64nvme: return be_bytes(m_crc, 8);
        case checksum_algo::sha1:
        case checksum_algo::sha256:
        {
            std::string out(EVP_MAX_MD_SIZE, '\0');
            unsigned    len = 0;
            EVP_MD_CTX* copy = EVP_MD_CTX_new();
            if (copy && m_digest && m_digest->ctx && EVP_MD_CTX_copy_ex(copy, m_digest->ctx))
                EVP_DigestFinal_ex(copy, reinterpret_cast<unsigned char*>(out.data()), &len);
            EVP_MD_CTX_free(copy);
            out.resize(len);
            return out;
        }
        case checksum_algo::none: break;
    }
    return {};
}

std::string checksum_stream::peek_b64() const
{
    return base64_encode(peek_raw());
}

std::string base64_encode(std::string_view in)
{
    static constexpr char digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 3 <= in.size(); i += 3)
    {
        const uint32_t v = (static_cast<uint32_t>(static_cast<unsigned char>(in[i])) << 16) |
                           (static_cast<uint32_t>(static_cast<unsigned char>(in[i + 1])) << 8) |
                           static_cast<unsigned char>(in[i + 2]);
        out.push_back(digits[(v >> 18) & 63]);
        out.push_back(digits[(v >> 12) & 63]);
        out.push_back(digits[(v >> 6) & 63]);
        out.push_back(digits[v & 63]);
    }
    if (const size_t rest = in.size() - i; rest > 0)
    {
        uint32_t v = static_cast<uint32_t>(static_cast<unsigned char>(in[i])) << 16;
        if (rest == 2)
            v |= static_cast<uint32_t>(static_cast<unsigned char>(in[i + 1])) << 8;
        out.push_back(digits[(v >> 18) & 63]);
        out.push_back(digits[(v >> 12) & 63]);
        out.push_back(rest == 2 ? digits[(v >> 6) & 63] : '=');
        out.push_back('=');
    }
    return out;
}

bool base64_decode(std::string_view in, std::string& out)
{
    out.clear();
    // Padded to a whole number of quanta, as every encoder writes it.
    if (in.size() % 4 != 0)
        return false;
    uint32_t acc = 0;
    int bits = 0;
    size_t pad = 0;
    for (char c : in)
    {
        int v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+') v = 62;
        else if (c == '/') v = 63;
        else if (c == '=') { if (++pad > 2) return false; continue; }
        else return false;
        if (pad)
            return false;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            out.push_back(static_cast<char>((acc >> bits) & 0xFF));
        }
    }
    return true;
}

namespace
{

// The CRC of A then B from those of A and B, as zlib's crc32_combine does it for any reflected CRC whose
// initial value and final xor are the same: the CRC of A is moved past len_b zero bytes by squaring an operator.
uint64_t gf2_times(const uint64_t* mat, uint64_t vec)
{
    uint64_t sum = 0;
    for (; vec; vec >>= 1, ++mat)
        if (vec & 1)
            sum ^= *mat;
    return sum;
}

void gf2_square(uint64_t* sq, const uint64_t* mat, int width)
{
    for (int n = 0; n < width; ++n)
        sq[n] = gf2_times(mat, mat[n]);
}

uint64_t crc_combine(uint64_t crc_a, uint64_t crc_b, uint64_t len_b, uint64_t poly, int width)
{
    if (len_b == 0)
        return crc_a;
    uint64_t even[64], odd[64];
    odd[0] = poly;
    for (int n = 1; n < width; ++n)
        odd[n] = 1ull << (n - 1);
    gf2_square(even, odd, width);
    gf2_square(odd, even, width);
    do
    {
        gf2_square(even, odd, width);
        if (len_b & 1)
            crc_a = gf2_times(even, crc_a);
        len_b >>= 1;
        if (!len_b)
            break;
        gf2_square(odd, even, width);
        if (len_b & 1)
            crc_a = gf2_times(odd, crc_a);
        len_b >>= 1;
    } while (len_b);
    return crc_a ^ crc_b;
}

}   // namespace

bool checksum_combinable(checksum_algo a)
{
    return a == checksum_algo::crc32 || a == checksum_algo::crc32c || a == checksum_algo::crc64nvme;
}

std::string full_object_checksum_b64(checksum_algo a, const std::vector<std::pair<std::string, uint64_t>>& parts)
{
    if (!checksum_combinable(a))
        return {};
    const size_t bytes = checksum_raw_len(a);
    const int width = static_cast<int>(bytes * 8);
    const uint64_t poly = a == checksum_algo::crc32 ? crc32_poly : a == checksum_algo::crc32c ? 0x82F63B78u : crc64_poly;
    uint64_t crc = 0;
    for (const auto& [raw, len] : parts)
    {
        if (raw.size() != bytes)
            return {};
        uint64_t v = 0;
        for (unsigned char ch : raw)
            v = (v << 8) | ch;
        crc = crc_combine(crc, v, len, poly, width);
    }
    return base64_encode(be_bytes(crc, bytes));
}

std::string composite_checksum_b64(checksum_algo a, std::string_view concatenated_raw, size_t parts)
{
    checksum_stream s(a);
    s.update(concatenated_raw.data(), concatenated_raw.size());
    return s.peek_b64() + "-" + std::to_string(parts);
}

}   // namespace socketley::storage
