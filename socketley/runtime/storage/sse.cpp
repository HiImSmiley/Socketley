#include "sse.h"

#include <algorithm>
#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "checksum.h"

namespace socketley::storage
{

namespace
{

constexpr std::string_view chunk_text  = "65536";
// What a wrapped key is sealed together with, so a data key is never taken for anything else.
constexpr std::string_view wrap_aad_v1 = "socketley-sse-key-v1";
constexpr std::string_view wrap_aad_v2 = "socketley-sse-key-v2";
// What a version 2 chunk's additional data begins with, so it is never read as a version 1 one.
constexpr std::string_view chunk_aad_v2 = "SKS2";
constexpr size_t chunk_aad_max = 17;

void put_be(uint8_t* at, uint64_t v, int bytes)
{
    for (int i = bytes - 1; i >= 0; --i, v >>= 8)
        at[i] = static_cast<uint8_t>(v & 0xff);
}

// The additional data a chunk is sealed with, written into `aad`; its length.
size_t chunk_aad(uint8_t* aad, uint8_t version, uint32_t stream, uint64_t index, bool last)
{
    if (version == sse_format_v1)
    {
        put_be(aad, index, 8);
        return 8;
    }
    std::memcpy(aad, chunk_aad_v2.data(), chunk_aad_v2.size());
    put_be(aad + 4, stream, 4);
    put_be(aad + 8, index, 8);
    aad[16] = last ? 1 : 0;
    return chunk_aad_max;
}

// The additional data a data key is wrapped with.
std::string wrap_aad(uint8_t version, const sse_digest* parts, bool upload)
{
    std::string aad(version == sse_format_v1 ? wrap_aad_v1 : wrap_aad_v2);
    if (parts && version != sse_format_v1)
    {
        aad += "/parts/";
        aad.append(reinterpret_cast<const char*>(parts->data()), parts->size());
    }
    else if (upload && version != sse_format_v1)
        aad += "/upload";
    return aad;
}

// What the master key is expanded with for the part list MAC, so that key is never the master's other uses.
constexpr std::string_view parts_mac_info  = "socketley-sse-c-parts-mac";
// What a part list MAC is taken over first, so it is never taken for anything else.
constexpr std::string_view parts_mac_label = "socketley-sse-c-parts-v1";

sse_digest hmac_sha256(const uint8_t* key, size_t key_len, std::string_view data)
{
    sse_digest out{};
    unsigned int len = 0;
    if (!HMAC(EVP_sha256(), key, static_cast<int>(key_len), reinterpret_cast<const unsigned char*>(data.data()),
              data.size(), out.data(), &len) ||
        len != out.size())
        std::abort();
    return out;
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
    std::string v = std::to_string(r.version);
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
    if ((f[0] != "1" && f[0] != "2") || (f[1] != "s3" && f[1] != "c") || f[2] != chunk_text ||
        (f[3] != "o" && f[3] != "p") || f[4].size() != 8)
        return false;
    out.version  = f[0] == "1" ? sse_format_v1 : sse_format;
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

uint8_t sse_version_of(const object_meta& m)
{
    const std::string* v = sse_value(m);
    sse_record r;
    return v && decode_sse(*v, r) ? r.version : 0;
}

uint64_t stored_size(const object_meta& m)
{
    if (part_trailer t; part_trailer_of(m, t))
        return t.at + t.len;
    const std::string* v = sse_value(m);
    if (!v)
        return m.size;
    sse_layout l;
    return l.init(m) ? l.stored() : UINT64_MAX;
}

// ─── Where the chunks are ───────────────────────────────────────────────────

bool sse_layout::init(const object_meta& m, const part_list* list)
{
    const std::string* v = sse_value(m);
    sse_record r;
    if (!v || !decode_sse(*v, r))
        return false;
    m_version = r.version;
    m_size    = m.size;
    m_stream.clear();
    m_len.clear();
    m_plain_at.clear();
    m_cipher_at.clear();
    // A part's own file, and a copy or a put, are one stream whatever their record says.
    const bool parts = r.per_part && (r.version == sse_format_v1 ? m.parts > 1 : m.parts >= 1);
    if (!parts)
    {
        m_stream.push_back(0);
        m_len.push_back(m.size);
    }
    else if (list)
    {
        m_stream = list->numbers;
        m_len    = list->sizes;
    }
    else
    {
        part_list l;
        if (!part_list_of(m, l))
            return false;
        m_stream = std::move(l.numbers);
        m_len    = std::move(l.sizes);
    }
    uint64_t plain = 0, cipher = 0;
    m_plain_at.reserve(m_len.size());
    m_cipher_at.reserve(m_len.size());
    for (uint64_t s : m_len)
    {
        if (s > m.size - plain)
            return false;
        m_plain_at.push_back(plain);
        m_cipher_at.push_back(cipher);
        plain  += s;
        cipher += sse_stored_len(s, m_version);
    }
    if (plain != m.size || m_stream.size() != m_len.size())
        return false;
    m_stored = cipher;
    // A list kept after the body says where it lies, which is where the body it describes must end.
    if (part_trailer t; part_trailer_of(m, t))
        return t.at == m_stored;
    return true;
}

sse_layout::chunk sse_layout::make(uint32_t part, uint64_t index) const
{
    chunk c;
    c.part       = part;
    c.stream     = m_stream[part];
    c.index      = index;
    c.last       = m_version != sse_format_v1 && index + 1 == sse_chunks(m_len[part], m_version);
    c.plain_off  = m_plain_at[part] + index * sse_chunk;
    c.plain_len  = std::min<uint64_t>(sse_chunk, m_len[part] - index * sse_chunk);
    c.cipher_off = m_cipher_at[part] + index * (sse_chunk + sse_overhead);
    return c;
}

sse_layout::chunk sse_layout::at(uint64_t x) const
{
    // The last part that begins at or before x, which skips any empty part in front of it.
    const size_t p = static_cast<size_t>(std::upper_bound(m_plain_at.begin(), m_plain_at.end(), x) -
                                         m_plain_at.begin()) - 1;
    return make(static_cast<uint32_t>(p), (x - m_plain_at[p]) / sse_chunk);
}

bool sse_layout::first(chunk& c) const
{
    for (size_t p = 0; p < m_len.size(); ++p)
        if (sse_chunks(m_len[p], m_version) > 0)
        {
            c = make(static_cast<uint32_t>(p), 0);
            return true;
        }
    return false;
}

bool sse_layout::next(chunk& c) const
{
    if (c.index + 1 < sse_chunks(m_len[c.part], m_version))
    {
        c = make(c.part, c.index + 1);
        return true;
    }
    for (size_t p = c.part + 1; p < m_len.size(); ++p)
        if (sse_chunks(m_len[p], m_version) > 0)
        {
            c = make(static_cast<uint32_t>(p), 0);
            return true;
        }
    return false;
}

sse_digest sse_layout::parts_digest() const
{
    part_list l;
    l.numbers = m_stream;
    l.sizes   = m_len;
    const std::string bytes = encode_part_list(l, m_size);
    digest_stream d(EVP_sha256());
    d.update(bytes.data(), bytes.size());
    return d.finish<32>();
}

bool sse_parts_digest(const object_meta& m, sse_digest& out)
{
    if (part_trailer t; part_trailer_of(m, t))
    {
        out = t.digest;
        return true;
    }
    sse_layout l;
    if (!l.init(m))
        return false;
    out = l.parts_digest();
    return true;
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

bool sse_wrap(const sse_key& kek, const sse_key& data, std::string& wrapped, uint8_t version,
              const sse_digest* parts, bool upload)
{
    wrapped.assign(sse_wrapped_bytes, '\0');
    auto* w = reinterpret_cast<uint8_t*>(wrapped.data());
    if (RAND_bytes(w, static_cast<int>(sse_nonce)) != 1)
        return false;
    const std::string aad = wrap_aad(version, parts, upload);
    gcm g(kek.data(), true);
    return g.seal(w, reinterpret_cast<const uint8_t*>(aad.data()), aad.size(), data.data(), data.size(),
                  w + sse_nonce, w + sse_nonce + sse_key_bytes);
}

bool sse_unwrap(const sse_key& kek, std::string_view wrapped, sse_key& data, uint8_t version,
                const sse_digest* parts, bool upload)
{
    if (wrapped.size() != sse_wrapped_bytes)
        return false;
    const auto* w = reinterpret_cast<const uint8_t*>(wrapped.data());
    const std::string aad = wrap_aad(version, parts, upload);
    gcm g(kek.data(), false);
    return g.open(w, reinterpret_cast<const uint8_t*>(aad.data()), aad.size(), w + sse_nonce, sse_key_bytes,
                  w + sse_nonce + sse_key_bytes, data.data());
}

sse_key sse_parts_mac_key(const sse_key& master)
{
    // HKDF-SHA256 of RFC 5869 with no salt, whose one block of output is the key.
    const uint8_t zero_salt[32] = {};
    const sse_digest prk = hmac_sha256(zero_salt, sizeof zero_salt,
                                       std::string_view(reinterpret_cast<const char*>(master.data()), master.size()));
    std::string info(parts_mac_info);
    info += '\x01';
    return hmac_sha256(prk.data(), prk.size(), info);
}

sse_digest sse_parts_mac(const sse_key& mac_key, std::string_view record, const sse_digest& parts)
{
    std::string msg(parts_mac_label);
    msg += '\0';
    msg += record;
    msg += '\0';
    msg.append(reinterpret_cast<const char*>(parts.data()), parts.size());
    return hmac_sha256(mac_key.data(), mac_key.size(), msg);
}

std::string encode_parts_mac(const std::array<uint8_t, 4>& kid, const sse_digest& mac)
{
    return hex(kid.data(), kid.size()) + ";" + hex(mac.data(), mac.size());
}

bool decode_parts_mac(std::string_view v, std::array<uint8_t, 4>& kid, sse_digest& mac)
{
    if (v.size() != 2 * kid.size() + 1 + 2 * mac.size() || v[2 * kid.size()] != ';')
        return false;
    auto bytes = [](std::string_view h, uint8_t* out, size_t n)
    {
        for (size_t i = 0; i < n; ++i)
        {
            uint8_t hi = 0, lo = 0;
            if (!hex_nibble(h[2 * i], hi) || !hex_nibble(h[2 * i + 1], lo))
                return false;
            out[i] = static_cast<uint8_t>(hi << 4 | lo);
        }
        return true;
    };
    return bytes(v.substr(0, 2 * kid.size()), kid.data(), kid.size()) &&
           bytes(v.substr(2 * kid.size() + 1), mac.data(), mac.size());
}

// ─── Chunks ─────────────────────────────────────────────────────────────────

bool sse_seal(const sse_key& key, uint8_t version, uint32_t stream, uint64_t first, const char* in, size_t n,
              bool last, char* out)
{
    gcm g(key.data(), true);
    uint8_t aad[chunk_aad_max];
    const uint64_t chunks = last ? sse_chunks(n, version) : (n + sse_chunk - 1) / sse_chunk;
    // Random per chunk, so a part written again under its upload's key never repeats a nonce.
    for (uint64_t i = 0; i < chunks; ++i)
    {
        const size_t len = std::min(sse_chunk, n - static_cast<size_t>(i) * sse_chunk);
        auto* o = reinterpret_cast<uint8_t*>(out + i * (sse_chunk + sse_overhead));
        if (RAND_bytes(o, static_cast<int>(sse_nonce)) != 1)
            return false;
        const size_t alen = chunk_aad(aad, version, stream, first + i, last && i + 1 == chunks);
        if (!g.seal(o, aad, alen, reinterpret_cast<const uint8_t*>(in + i * sse_chunk), len, o + sse_nonce,
                    o + sse_nonce + len))
            return false;
    }
    return true;
}

bool sse_open(const sse_key& key, uint8_t version, const sse_layout::chunk* chunks, size_t count, const char* in,
              char* out)
{
    gcm g(key.data(), false);
    uint8_t aad[chunk_aad_max];
    for (size_t i = 0; i < count; ++i)
    {
        const sse_layout::chunk& c = chunks[i];
        const auto* p = reinterpret_cast<const uint8_t*>(in);
        const size_t len  = static_cast<size_t>(c.plain_len);
        const size_t alen = chunk_aad(aad, version, c.stream, c.index, c.last);
        if (!g.open(p, aad, alen, p + sse_nonce, len, p + sse_nonce + len, reinterpret_cast<uint8_t*>(out)))
            return false;
        in  += c.stored();
        out += len;
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
