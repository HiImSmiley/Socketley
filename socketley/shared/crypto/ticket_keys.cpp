#include "ticket_keys.h"

#if __has_include(<openssl/ssl.h>)
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <cstring>
#include <ctime>

#include "../util/settings.h"

namespace ticket_keys
{
namespace
{

area g_local;

area& keys()
{
    area* a = shared_area.load(std::memory_order_acquire);
    return a ? *a : g_local;
}

// The monotonic clock, which every process of the machine reads alike and no change of the wall clock moves.
uint64_t period_now()
{
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    return static_cast<uint64_t>(ts.tv_sec) / period_secs();
}

constexpr uint64_t whole(uint64_t period) { return (period + 1) << 1; }
constexpr uint64_t period_of(uint64_t tag) { return (tag >> 1) - 1; }

struct key
{
    uint64_t w[key_words];
    const unsigned char* bytes() const { return reinterpret_cast<const unsigned char*>(w); }
    ~key() { OPENSSL_cleanse(w, sizeof w); }
};
static_assert(sizeof(key::w) == 16 + 32 + 32);

// A seqlock read: the words, then the tag again, and a key is only what was there while the tag stood still.
bool read(const slot& s, uint64_t tag, key& k)
{
    for (uint32_t i = 0; i < key_words; ++i)
        k.w[i] = s.word[i].load(std::memory_order_relaxed);
    std::atomic_thread_fence(std::memory_order_acquire);
    return s.tag.load(std::memory_order_relaxed) == tag;
}

// The slot taken by moving its tag from `from` to `to` odd, so no two writers and no reader trust it meanwhile.
bool write(slot& s, uint64_t from, uint64_t to, const key* k)
{
    if (!s.tag.compare_exchange_strong(from, to | 1, std::memory_order_acquire, std::memory_order_relaxed))
        return false;
    std::atomic_thread_fence(std::memory_order_release);
    for (uint32_t i = 0; i < key_words; ++i)
        s.word[i].store(k ? k->w[i] : 0, std::memory_order_relaxed);
    s.tag.store(to, std::memory_order_release);
    return true;
}

// Every key older than the previous period, which opens nothing any more and so is only something to steal.
void wipe_stale(area& a, uint64_t now)
{
    for (slot& s : a.slots)
    {
        const uint64_t t = s.tag.load(std::memory_order_acquire);
        if (t != 0 && period_of(t) + 1 < now)
            write(s, t, 0, nullptr);
    }
}

// The key `period` seals with, made by the first process that asks for it; a slot left odd by a writer of an older
// period died with that writer and is taken over.
bool sealing(area& a, uint64_t period, key& k)
{
    slot& s = a.slots[period % slot_count];
    for (int attempt = 0; attempt < 3; ++attempt)
    {
        const uint64_t t = s.tag.load(std::memory_order_acquire);
        if (t == whole(period))
        {
            if (read(s, t, k))
                return true;
            continue;
        }
        if (t != 0 && period_of(t) >= period)
            return false;
        if (RAND_priv_bytes(reinterpret_cast<unsigned char*>(k.w), sizeof k.w) != 1)
            return false;
        if (write(s, t, whole(period), &k))
        {
            wipe_stale(a, period);
            return true;
        }
    }
    return false;
}

// 1 for a ticket sealed this period, 2 for one sealed the period before, which opens and is sealed again, 0 for any
// other: OpenSSL's answers.
int opening(area& a, uint64_t now, const unsigned char* name, key& k)
{
    for (const slot& s : a.slots)
    {
        const uint64_t t = s.tag.load(std::memory_order_acquire);
        if (t == 0 || (t & 1) || !read(s, t, k) || std::memcmp(k.bytes(), name, 16) != 0)
            continue;
        const uint64_t sealed = period_of(t);
        return sealed >= now ? 1 : sealed + 1 == now ? 2 : 0;
    }
    return 0;
}

int on_ticket(SSL*, unsigned char* name, unsigned char* iv, EVP_CIPHER_CTX* cipher, EVP_MAC_CTX* mac, int enc)
{
    area& a = keys();
    const uint64_t now = period_now();
    key k;
    int answer = 1;
    if (enc)
    {
        // The previous period's key while another process is still making this one's, and no ticket without either.
        if (!sealing(a, now, k) && (now == 0 || !sealing(a, now - 1, k)))
            return 0;
        if (RAND_bytes(iv, 16) != 1)
            return -1;
        std::memcpy(name, k.bytes(), 16);
    }
    else if ((answer = opening(a, now, name, k)) == 0)
        return 0;

    char digest[] = "SHA256";
    const OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, const_cast<unsigned char*>(k.bytes() + 48), 32),
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_end(),
    };
    // Fetched once, since EVP_aes_256_cbc() looks the implementation up again at every handshake.
    static EVP_CIPHER* const aes = EVP_CIPHER_fetch(nullptr, "AES-256-CBC", nullptr);
    if (!aes || EVP_CipherInit_ex(cipher, aes, nullptr, k.bytes() + 16, iv, enc) != 1 ||
        EVP_MAC_CTX_set_params(mac, params) != 1)
        return -1;
    return answer;
}

}   // namespace

uint64_t period_secs()
{
    static const uint64_t secs =
        socketley::settings::number<uint64_t>("SOCKETLEY_TLS_TICKET_SECS").value_or(3600);
    return secs;
}

bool install(SSL_CTX* ctx)
{
    SSL_CTX_clear_options(ctx, SSL_OP_NO_TICKET);
    return SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx, on_ticket) == 1;
}

void tick()
{
    area* a = shared_area.load(std::memory_order_acquire);
    wipe_stale(a ? *a : g_local, period_now());
}

}   // namespace ticket_keys

#else

namespace ticket_keys
{
uint64_t period_secs() { return 3600; }
bool install(SSL_CTX*) { return false; }
void tick() {}
}   // namespace ticket_keys

#endif
