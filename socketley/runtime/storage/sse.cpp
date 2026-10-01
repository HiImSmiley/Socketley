#include "sse.h"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstring>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "checksum.h"

namespace socketley::storage
{

namespace
{

constexpr std::string_view sse_version = "1";
constexpr std::string_view chunk_text  = "65536";
// What a wrapped key is sealed together with, so a data key is never taken for anything else.
constexpr std::string_view wrap_aad = "socketley-sse-key-v1";

void put_index(uint8_t* aad, uint64_t index)
{
    for (int i = 7; i >= 0; --i, index >>= 8)
        aad[i] = static_cast<uint8_t>(index & 0xff);
}

bool hex_nibble(char ch, uint8_t& out)
{
    if (ch >= '0' && ch <= '9')
        out = static_cast<uint8_t>(ch - '0');
    else if (ch >= 'a' && ch <= 'f')
        out = static_cast<uint8_t>(ch - 'a' + 10);
    else if (ch >= 'A' && ch <= 'F')
        out = static_cast<uint8_t>(ch - 'A' + 10);
    else
        return false;
    return true;
}

bool number(std::string_view s, uint64_t& out)
{
    const auto r = std::from_chars(s.data(), s.data() + s.size(), out);
    return !s.empty() && r.ec == std::errc{} && r.ptr == s.data() + s.size();
}

// One AES-256-GCM context with its key schedule set, reused for every chunk of a call.
class gcm
{
public:
    gcm(const uint8_t* key, bool encrypt) : m_ctx(EVP_CIPHER_CTX_new()), m_encrypt(encrypt)
    {
        m_ok = m_ctx && (encrypt ? EVP_EncryptInit_ex(m_ctx, EVP_aes_256_gcm(), nullptr, key, nullptr)
                                 : EVP_DecryptInit_ex(m_ctx, EVP_aes_256_gcm(), nullptr, key, nullptr)) == 1;
    }
    ~gcm() { EVP_CIPHER_CTX_free(m_ctx); }
    gcm(const gcm&)            = delete;
    gcm& operator=(const gcm&) = delete;

    // `out` takes n bytes and `tag` sixteen.
    bool seal(const uint8_t* nonce, const uint8_t* aad, size_t aad_len, const uint8_t* in, size_t n, uint8_t* out,
              uint8_t* tag)
    {
        int len = 0;
        if (!m_ok || !m_encrypt || EVP_EncryptInit_ex(m_ctx, nullptr, nullptr, nullptr, nonce) != 1 ||
            EVP_EncryptUpdate(m_ctx, nullptr, &len, aad, static_cast<int>(aad_len)) != 1)
            return false;
        if (n && EVP_EncryptUpdate(m_ctx, out, &len, in, static_cast<int>(n)) != 1)
            return false;
        return EVP_EncryptFinal_ex(m_ctx, out + n, &len) == 1 &&
               EVP_CIPHER_CTX_ctrl(m_ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(sse_tag), tag) == 1;
    }

    bool open(const uint8_t* nonce, const uint8_t* aad, size_t aad_len, const uint8_t* in, size_t n,
              const uint8_t* tag, uint8_t* out)
    {
        int len = 0;
        if (!m_ok || m_encrypt || EVP_DecryptInit_ex(m_ctx, nullptr, nullptr, nullptr, nonce) != 1 ||
            EVP_DecryptUpdate(m_ctx, nullptr, &len, aad, static_cast<int>(aad_len)) != 1)
            return false;
        if (n && EVP_DecryptUpdate(m_ctx, out, &len, in, static_cast<int>(n)) != 1)
            return false;
        if (EVP_CIPHER_CTX_ctrl(m_ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(sse_tag),
                                const_cast<uint8_t*>(tag)) != 1)
            return false;
        return EVP_DecryptFinal_ex(m_ctx, out + n, &len) == 1;
    }

private:
    EVP_CIPHER_CTX* m_ctx;
    bool            m_encrypt;
    bool            m_ok{false};
};

}   // namespace

// ─── The record ─────────────────────────────────────────────────────────────

std::string encode_sse(const sse_record& r)
{
    std::string v(sse_version);
    v += r.mode == sse_mode::c ? ";c;" : ";s3;";
    v += chunk_text;
    v += r.per_part ? ";p;" : ";o;";
    v += hex(r.kid.data(), r.kid.size());
    v += ';';
    v += base64_encode(r.wrapped);
    return v;
}

bool decode_sse(std::string_view v, sse_record& out)
{
    std::string_view f[6];
    for (size_t i = 0; i < 6; ++i)
    {
        const size_t semi = v.find(';');
        if ((semi == std::string_view::npos) != (i == 5))
            return false;
        f[i] = v.substr(0, semi);
        v    = i == 5 ? std::string_view{} : v.substr(semi + 1);
    }
    if (f[0] != sse_version || (f[1] != "s3" && f[1] != "c") || f[2] != chunk_text || (f[3] != "o" && f[3] != "p") ||
        f[4].size() != 8)
        return false;
    out.mode     = f[1] == "c" ? sse_mode::c : sse_mode::s3;
    out.per_part = f[3] == "p";
    for (size_t i = 0; i < 4; ++i)
    {
        uint8_t hi = 0, lo = 0;
        if (!hex_nibble(f[4][2 * i], hi) || !hex_nibble(f[4][2 * i + 1], lo))
            return false;
        out.kid[i] = static_cast<uint8_t>(hi << 4 | lo);
    }
    return base64_decode(f[5], out.wrapped) && out.wrapped.size() == sse_wrapped_bytes;
}

const std::string* sse_value(const object_meta& m)
{
    for (const auto& [n, v] : m.extra)
        if (n == sse_extra)
            return &v;
    return nullptr;
}

sse_mode sse_mode_of(const object_meta& m)
{
    const std::string* v = sse_value(m);
    sse_record r;
    if (!v || !decode_sse(*v, r))
        return v ? sse_mode::s3 : sse_mode::none;
    return r.mode;
}

uint64_t stored_size(const object_meta& m)
{
    const std::string* v = sse_value(m);
    if (!v)
        return m.size;
    sse_layout l;
    return l.init(m) ? l.stored() : UINT64_MAX;
}

// ─── Where the chunks are ───────────────────────────────────────────────────

bool sse_layout::init(const object_meta& m)
{
    const std::string* v = sse_value(m);
    sse_record r;
    if (!v || !decode_sse(*v, r))
        return false;
    m_size = m.size;
    m_plain_at.clear();
    m_cipher_at.clear();
    // A part's own file, and a copy or a put, are one stream whatever their record says.
    if (!r.per_part || m.parts <= 1)
    {
        m_stored = sse_stored_len(m.size);
        return true;
    }
    std::string_view list;
    for (const auto& [n, val] : m.extra)
        if (n == part_sizes_extra)
            list = val;
    if (list.empty())
        return false;
    std::vector<uint64_t> sizes;
    sizes.reserve(list.find(',') == std::string_view::npos ? m.parts : 16);
    if (list.find(',') == std::string_view::npos)
    {
        uint64_t each = 0;
        if (!number(list, each) || each == 0 || each > m.size / (m.parts - 1))
            return false;
        sizes.assign(m.parts - 1, each);
        sizes.push_back(m.size - each * (m.parts - 1));
    }
    else
    {
        while (!list.empty())
        {
            const size_t comma = list.find(',');
            uint64_t s = 0;
            if (!number(list.substr(0, comma), s))
                return false;
            sizes.push_back(s);
            list = comma == std::string_view::npos ? std::string_view{} : list.substr(comma + 1);
        }
    }
    if (sizes.size() != m.parts)
        return false;
    uint64_t plain = 0, cipher = 0;
    m_plain_at.reserve(sizes.size());
    m_cipher_at.reserve(sizes.size());
    for (uint64_t s : sizes)
    {
        if (s > m.size - plain)
            return false;
        m_plain_at.push_back(plain);
        m_cipher_at.push_back(cipher);
        plain  += s;
        cipher += sse_stored_len(s);
    }
    if (plain != m.size)
        return false;
    m_stored = cipher;
    return true;
}

sse_layout::chunk sse_layout::at(uint64_t x) const
{
    uint64_t part_plain = 0, part_cipher = 0, part_size = m_size;
    if (!m_plain_at.empty())
    {
        // The last part that begins at or before x, which skips any empty part in front of it.
        const size_t p = static_cast<size_t>(std::upper_bound(m_plain_at.begin(), m_plain_at.end(), x) -
                                             m_plain_at.begin()) - 1;
        part_plain  = m_plain_at[p];
        part_cipher = m_cipher_at[p];
        part_size   = (p + 1 < m_plain_at.size() ? m_plain_at[p + 1] : m_size) - part_plain;
    }
    chunk c;
    const uint64_t local = x - part_plain;
    c.index      = local / sse_chunk;
    c.plain_off  = part_plain + c.index * sse_chunk;
    c.plain_len  = std::min<uint64_t>(sse_chunk, part_size - c.index * sse_chunk);
    c.cipher_off = part_cipher + c.index * (sse_chunk + sse_overhead);
    return c;
}

// ─── Keys ───────────────────────────────────────────────────────────────────

sse_key sse_random_key()
{
    sse_key k{};
    if (RAND_bytes(k.data(), static_cast<int>(k.size())) != 1)
        std::abort();
    return k;
}

std::array<uint8_t, 4> sse_key_id(const sse_key& master)
{
    digest_stream d(EVP_sha256());
    static constexpr std::string_view label = "socketley-sse-kid";
    d.update(label.data(), label.size());
    d.update(master.data(), master.size());
    const auto h = d.finish<32>();
    return {h[0], h[1], h[2], h[3]};
}

bool sse_wrap(const sse_key& kek, const sse_key& data, std::string& wrapped)
{
    wrapped.assign(sse_wrapped_bytes, '\0');
    auto* w = reinterpret_cast<uint8_t*>(wrapped.data());
    if (RAND_bytes(w, static_cast<int>(sse_nonce)) != 1)
        return false;
    gcm g(kek.data(), true);
    return g.seal(w, reinterpret_cast<const uint8_t*>(wrap_aad.data()), wrap_aad.size(), data.data(), data.size(),
                  w + sse_nonce, w + sse_nonce + sse_key_bytes);
}

bool sse_unwrap(const sse_key& kek, std::string_view wrapped, sse_key& data)
{
    if (wrapped.size() != sse_wrapped_bytes)
        return false;
    const auto* w = reinterpret_cast<const uint8_t*>(wrapped.data());
    gcm g(kek.data(), false);
    return g.open(w, reinterpret_cast<const uint8_t*>(wrap_aad.data()), wrap_aad.size(), w + sse_nonce,
                  sse_key_bytes, w + sse_nonce + sse_key_bytes, data.data());
}

// ─── Chunks ─────────────────────────────────────────────────────────────────

bool sse_seal(const sse_key& key, uint64_t first, const char* in, size_t n, char* out)
{
    gcm g(key.data(), true);
    uint8_t aad[8];
    // Random per chunk, so a part written again under its upload's key never repeats a nonce.
    const size_t chunks = (n + sse_chunk - 1) / sse_chunk;
    for (size_t i = 0; i < chunks; ++i)
    {
        const size_t len = std::min(sse_chunk, n - i * sse_chunk);
        auto* o = reinterpret_cast<uint8_t*>(out + i * (sse_chunk + sse_overhead));
        if (RAND_bytes(o, static_cast<int>(sse_nonce)) != 1)
            return false;
        put_index(aad, first + i);
        if (!g.seal(o, aad, sizeof aad, reinterpret_cast<const uint8_t*>(in + i * sse_chunk), len, o + sse_nonce,
                    o + sse_nonce + len))
            return false;
    }
    return true;
}

bool sse_open(const sse_key& key, uint64_t first, const char* in, size_t n, char* out)
{
    gcm g(key.data(), false);
    uint8_t aad[8];
    size_t at = 0;
    for (uint64_t index = first; at < n; ++index)
    {
        const size_t whole = std::min(sse_chunk + sse_overhead, n - at);
        if (whole <= sse_overhead)
            return false;
        const size_t len = whole - sse_overhead;
        const auto* c = reinterpret_cast<const uint8_t*>(in + at);
        put_index(aad, index);
        if (!g.open(c, aad, sizeof aad, c + sse_nonce, len, c + sse_nonce + len,
                    reinterpret_cast<uint8_t*>(out + (index - first) * sse_chunk)))
            return false;
        at += whole;
    }
    return true;
}

md5_t sse_opaque_etag(const sse_key& data, const md5_t& md5)
{
    digest_stream d(EVP_sha256());
    static constexpr std::string_view label = "socketley-sse-etag";
    d.update(label.data(), label.size());
    d.update(data.data(), data.size());
    d.update(md5.data(), md5.size());
    const auto h = d.finish<32>();
    md5_t out{};
    std::copy_n(h.begin(), out.size(), out.begin());
    return out;
}

bool load_sse_master(const std::string& path, sse_key& out, std::string& err)
{
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        err = "cannot read the SSE key file " + path + ": " + std::strerror(errno);
        return false;
    }
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
    {
        ::close(fd);
        err = "the SSE key file " + path + " is not a regular file";
        return false;
    }
    if ((st.st_mode & 0077) != 0)
    {
        ::close(fd);
        err = "the SSE key file " + path + " may be read by other users; chmod 600 it";
        return false;
    }
    char buf[80];
    ssize_t got = 0;
    for (;;)
    {
        const ssize_t n = ::read(fd, buf + got, sizeof buf - static_cast<size_t>(got));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        got += n;
        if (got == static_cast<ssize_t>(sizeof buf))
            break;
    }
    ::close(fd);
    std::string_view text(buf, static_cast<size_t>(std::max<ssize_t>(got, 0)));
    if (text.size() == sse_key_bytes)
    {
        std::memcpy(out.data(), text.data(), sse_key_bytes);
        return true;
    }
    if (text.size() == 2 * sse_key_bytes + 1 && text.back() == '\n')
        text.remove_suffix(1);
    if (text.size() == 2 * sse_key_bytes)
    {
        for (size_t i = 0; i < sse_key_bytes; ++i)
        {
            uint8_t hi = 0, lo = 0;
            if (!hex_nibble(text[2 * i], hi) || !hex_nibble(text[2 * i + 1], lo))
            {
                err = "the SSE key file " + path + " holds 64 characters that are not hex digits";
                return false;
            }
            out[i] = static_cast<uint8_t>(hi << 4 | lo);
        }
        return true;
    }
    err = "the SSE key file " + path + " must hold exactly 32 bytes, or 64 hex digits";
    return false;
}

}   // namespace socketley::storage
