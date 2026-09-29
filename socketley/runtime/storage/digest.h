#pragma once
// MD5 for the ETag and SHA-256 for the key hash, over libcrypto's EVP so no
// deprecated one-shot call is needed.
#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include <openssl/evp.h>

namespace socketley::storage
{

class digest_stream
{
public:
    explicit digest_stream(const EVP_MD* md) : m_ctx(EVP_MD_CTX_new())
    {
        if (m_ctx)
            EVP_DigestInit_ex(m_ctx, md, nullptr);
    }
    ~digest_stream() { EVP_MD_CTX_free(m_ctx); }

    digest_stream(const digest_stream&)            = delete;
    digest_stream& operator=(const digest_stream&) = delete;

    void update(const void* data, size_t n)
    {
        if (m_ctx && n)
            EVP_DigestUpdate(m_ctx, data, n);
    }

    // The digest so far, leaving the stream usable for more bytes.
    template <size_t N>
    std::array<uint8_t, N> peek() const
    {
        std::array<uint8_t, N> out{};
        EVP_MD_CTX* copy = EVP_MD_CTX_new();
        if (copy && EVP_MD_CTX_copy_ex(copy, m_ctx))
        {
            unsigned len = 0;
            EVP_DigestFinal_ex(copy, out.data(), &len);
        }
        EVP_MD_CTX_free(copy);
        return out;
    }

    template <size_t N>
    std::array<uint8_t, N> finish()
    {
        std::array<uint8_t, N> out{};
        if (m_ctx)
        {
            unsigned len = 0;
            EVP_DigestFinal_ex(m_ctx, out.data(), &len);
        }
        return out;
    }

private:
    EVP_MD_CTX* m_ctx;
};

using md5_t = std::array<uint8_t, 16>;

class md5_stream : public digest_stream
{
public:
    md5_stream() : digest_stream(EVP_md5()) {}
    md5_t finish() { return digest_stream::finish<16>(); }
    md5_t peek() const { return digest_stream::peek<16>(); }
};

inline std::string hex(const uint8_t* p, size_t n)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.resize(n * 2);
    for (size_t i = 0; i < n; ++i)
    {
        out[2 * i]     = digits[p[i] >> 4];
        out[2 * i + 1] = digits[p[i] & 15];
    }
    return out;
}

inline std::string hex(const md5_t& d) { return hex(d.data(), d.size()); }

inline std::string sha256_hex(std::string_view s)
{
    uint8_t  out[EVP_MAX_MD_SIZE];
    unsigned len = 0;
    EVP_Digest(s.data(), s.size(), out, &len, EVP_sha256(), nullptr);
    return hex(out, len);
}

inline md5_t md5_of(std::string_view s)
{
    md5_stream m;
    m.update(s.data(), s.size());
    return m.finish();
}

}   // namespace socketley::storage
