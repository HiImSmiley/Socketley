#pragma once
// The keys a TLS server seals its session tickets with: one set for every shard of a runtime, so a client resumes on
// whichever shard SO_REUSEPORT hands it, and a new key each period that still opens tickets through the next one, so
// a key learned opens at most two periods of sessions.  They live in memory alone, in the runtime's shard region or
// in the process.
#include <atomic>
#include <cstdint>

typedef struct ssl_ctx_st SSL_CTX;

namespace ticket_keys
{

// A key's name (16 bytes), its AES-256 key and its HMAC-SHA256 key, as words so a slot is read and written by atomics
// in a region several processes map.
inline constexpr uint32_t key_words = 10;

// The current key, the previous one and the next one being made, and a spare, so a slot is never written while its
// key may still open a ticket.
inline constexpr uint32_t slot_count = 4;

struct alignas(64) slot
{
    // (period + 1) * 2 once its key is whole, that plus one while it is being written, 0 before it ever was.
    std::atomic<uint64_t> tag;
    std::atomic<uint64_t> word[key_words];
};

struct area
{
    slot slots[slot_count];
};

// The shard region's keys once a shard has adopted it, this process's own otherwise.
inline std::atomic<area*> shared_area{nullptr};

inline void share(area* a)
{
    shared_area.store(a, std::memory_order_release);
}

// Only the area that is going away, so a reader's mapping closing never takes a shard's keys from it.
inline void unshare(area* a)
{
    shared_area.compare_exchange_strong(a, nullptr, std::memory_order_acq_rel);
}

// Has `ctx` seal and open its tickets with these keys; false when OpenSSL refuses the callback.
bool install(SSL_CTX* ctx);

// Wipes the keys past their two periods, for a process that may go hours without a handshake to do it.
void tick();

// How long one key seals new tickets.
uint64_t period_secs();

}   // namespace ticket_keys
