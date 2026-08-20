#pragma once
// What names a connection when the thing naming it is somewhere else.
//
// ─── WHY A DESCRIPTOR NUMBER CANNOT DO THIS ─────────────────────────────────
//
// A file descriptor is an index into one process's table.  It has three
// properties that make it useless as a name, and cross-runtime routing relied
// on all three not mattering:
//
//   * It is not unique across processes.  Two runtimes in two processes both
//     have an fd 12, and they are different sockets.  In one process this was
//     merely latent — two servers cannot hold the same number at the same
//     instant — so the code read correctly right up until the process split,
//     at which point every routed connection is ambiguous.
//
//   * It is reissued.  Close fd 12 and the next accept takes it.  A holder of
//     the old number who writes to it does not get an error; it writes into a
//     stranger's stream.  That is not hypothetical: server::owner_send took a
//     descriptor number from a sub-server's Lua and wrote it into the owner's
//     connection table with no check that the number still meant what the
//     sub-server thought it meant.
//
//   * It is a capability.  Handing a number across a boundary and letting the
//     far side name any number it likes is not routing, it is a licence to
//     write into any of the owner's connections.
//
// A conn_ref has none of those.  It is minted once by the runtime that owns
// the connection, it is never reissued, and it means the same thing wherever
// it is read.  A holder of a stale one resolves to nothing — which is the
// entire behavioural difference, and the reason this is a defect fix and not
// only plumbing for the split.
//
// ─── WHY TWO FIELDS ─────────────────────────────────────────────────────────
//
// `owner` says which runtime minted it, so a serial only has to be unique
// within one runtime rather than across a tree of processes that never agree
// on anything.  It is derived from the runtime's id — the six hex digits the
// daemon assigns at `create`, persisted in the state file, and sent to a worker
// in its config frame — which is the one identifier both sides of a process
// boundary already have.
//
// `serial` says which connection.  Never reused within a runtime, and seeded so
// that it is not reused across a restart of one either: a routed client that
// went away while a message for it was in flight must not be resolvable to the
// connection that took its place, and a counter restarting at 1 hands exactly
// that back.
//
// ─── AND WHICH SHARD, WHICH IS NOT DECORATION ───────────────────────────────
//
// "Unique within one runtime" was maintained by ONE counter for as long as a
// runtime was one process.  With --shards it is N processes, each with a
// counter of its own, and `owner` does not tell them apart: it is derived from
// the runtime id, and every shard of a runtime has the same id.  So two shards
// mint from the same owner with independent counters, and the only thing
// keeping their serials apart is the gap between the moments they were seeded.
//
// That gap is finite and it was measured rather than assumed.  Four shards
// forked and exec'd the way proxy_supervisor does it, seeds read at
// construction: the closest two were **1,602,540 ns** apart at four shards and
// 1,479,355 ns at eight.  A counter is incremented once per connection, so the
// first shard to mint that many connections starts handing out serials its
// sibling has already used — about 25 minutes at a thousand connections a
// second, and sooner on a busier one.
//
// Latent until now, because a ref never crossed a shard boundary: each shard
// resolved only its own, and a collision inside one shard cannot happen.
// Cross-shard routing is exactly what makes them cross, so it is fixed here
// before it is relied on rather than after.
//
// The top six bits of the serial are the minting shard's index — six because
// max_shards is 64 — and the remaining 58 are the counter.  Two consequences,
// and the second is worth as much as the first:
//
//   * Two shards can no longer mint the same serial, whatever their seeds.
//   * A holder of a ref can say which shard owns it without asking anyone, so
//     a routed message goes to ONE shard instead of being offered to all N and
//     declined by N-1.
//
// 58 bits of nanoseconds is 9.1 years of uptime before the counter wraps into
// a value a previous lifetime of the same shard could have used, against 584
// years for the full 64.  A process that has been up for nine years and is
// still minting connections is outside what this seeding scheme was ever
// promising; what it is NOT outside is the runtime being restarted, which
// re-seeds from a clock that has moved on.
#include <cstdint>
#include <ctime>
#include <string>
#include <string_view>

// A runtime's half of a connection name.  Zero is reserved for "no runtime",
// so a conn_ref built before an id was assigned is detectably invalid rather
// than quietly equal to another one.
inline uint64_t conn_owner_key(std::string_view runtime_id)
{
    if (runtime_id.empty())
        return 0;

    // FNV-1a, 64-bit.  The input is six hex digits from generate_runtime_id(),
    // so what is wanted here is a spread over a small alphabet and not a
    // cryptographic property; the id itself travels beside the key in every
    // handshake, so a collision is caught rather than acted on.
    uint64_t h = 1469598103934665603ull;
    for (const char c : runtime_id)
    {
        h ^= static_cast<uint8_t>(c);
        h *= 1099511628211ull;
    }
    return h ? h : 1ull;      // never collide with the reserved zero
}

// How the serial is divided.  Six bits of shard index above 58 bits of
// counter; see the note above.
inline constexpr int      conn_serial_shard_bits  = 6;              // max_shards == 64
inline constexpr int      conn_serial_shard_shift = 64 - conn_serial_shard_bits;
inline constexpr uint64_t conn_serial_counter_mask =
    (1ull << conn_serial_shard_shift) - 1ull;
inline constexpr uint32_t conn_serial_shard_mask =
    (1u << conn_serial_shard_bits) - 1u;

struct conn_ref
{
    uint64_t owner{0};
    uint64_t serial{0};

    // A ref with either half zero names nothing.  Resolving one must fail, not
    // fall through to a default — that fall-through is what a descriptor
    // number gave us.
    bool valid() const { return owner != 0 && serial != 0; }

    bool operator==(const conn_ref& o) const
    {
        return owner == o.owner && serial == o.serial;
    }
    bool operator!=(const conn_ref& o) const { return !(*this == o); }
};

struct conn_ref_hash
{
    size_t operator()(const conn_ref& r) const noexcept
    {
        // The serial already comes from a counter, so it is its own hash; the
        // owner is mixed in because a table may hold refs from several origins
        // and two of them can be at the same serial.
        uint64_t h = r.serial * 1099511628211ull;
        h ^= r.owner + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
        return static_cast<size_t>(h);
    }
};

// Mints the serial half.  One per runtime instance.
//
// Not seeded at 1.  A runtime that is stopped and started again is the same
// runtime with the same id, so a counter restarting at 1 would mint serials
// that a peer still holds from before the restart — the descriptor-reuse defect
// rebuilt one level up.  The clock is what distinguishes the two lifetimes, and
// CLOCK_MONOTONIC is the right one: it cannot be moved backwards by an operator
// or by NTP, which CLOCK_REALTIME can.
//
// Monotonic nanoseconds since boot fit in 64 bits for 584 years, and the
// increment cannot overtake the next lifetime's seed unless one runtime mints
// more than a billion connections per second of uptime.
class conn_serial_source
{
public:
    conn_serial_source()
    {
        struct timespec ts{};
        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
            m_counter = static_cast<uint64_t>(ts.tv_sec) * 1000000000ull
                      + static_cast<uint64_t>(ts.tv_nsec);
        m_counter &= conn_serial_counter_mask;
        if (m_counter == 0)
            m_counter = 1;          // serial 0 is not a valid ref
    }

    // Say which shard this source is minting for.
    //
    // Not a constructor argument, and that is not an oversight.  A runtime's
    // shard index arrives in a config frame, which is read well after the
    // instance that owns this has been constructed — the same ordering that
    // makes owner_key() lazy in server_instance, and for the same reason.
    // Call it before the first next(), which in a worker means before the
    // listener is bound and therefore before any connection exists.
    void set_shard(uint32_t shard_index)
    {
        m_shard = shard_index & conn_serial_shard_mask;
    }

    uint64_t next()
    {
        // Masked on the way out rather than carried in the counter, so a
        // counter that wraps past 2^58 cannot climb into the shard field and
        // start minting refs that name a different process.
        const uint64_t c = m_counter++ & conn_serial_counter_mask;
        return (static_cast<uint64_t>(m_shard) << conn_serial_shard_shift)
             | (c == 0 ? 1ull : c);
    }

private:
    uint64_t m_counter{1};
    uint32_t m_shard{0};
};

// Which shard minted this ref.  Meaningful for any ref this build produced;
// a ref from an unsharded runtime reads 0, which is correct — it is shard 0
// of one.
inline uint32_t conn_ref_shard(const conn_ref& r)
{
    return static_cast<uint32_t>(r.serial >> conn_serial_shard_shift);
}

// ── Wire form ───────────────────────────────────────────────────────────────
// Sixteen bytes, little-endian, fixed width.  Fixed rather than varint because
// every framing this travels in is length-prefixed already and the saving would
// be four bytes on a message that carries a payload.

inline constexpr size_t conn_ref_wire_size = 16;

inline void put_conn_ref(std::string& out, const conn_ref& r)
{
    for (int i = 0; i < 8; ++i)
        out.push_back(static_cast<char>((r.owner >> (8 * i)) & 0xFF));
    for (int i = 0; i < 8; ++i)
        out.push_back(static_cast<char>((r.serial >> (8 * i)) & 0xFF));
}

// Returns false and leaves `r` untouched when there are not sixteen bytes at
// `p`.  The caller advances `p` itself only on success, so a truncated frame
// cannot half-consume a name.
inline bool take_conn_ref(const char*& p, const char* end, conn_ref& r)
{
    if (end - p < static_cast<ptrdiff_t>(conn_ref_wire_size))
        return false;

    uint64_t owner = 0, serial = 0;
    for (int i = 0; i < 8; ++i)
        owner |= static_cast<uint64_t>(static_cast<uint8_t>(p[i])) << (8 * i);
    for (int i = 0; i < 8; ++i)
        serial |= static_cast<uint64_t>(static_cast<uint8_t>(p[8 + i])) << (8 * i);

    p += conn_ref_wire_size;
    r.owner  = owner;
    r.serial = serial;
    return true;
}

// ── Local handles ───────────────────────────────────────────────────────────
//
// Lua is handed an integer for a client and always has been.  For a runtime's
// own clients that integer is the descriptor, and every script in existence
// treats it as opaque, so it stays.
//
// A routed connection belongs to another runtime, so it has no descriptor here
// to be.  It gets a handle out of a range that no descriptor can occupy, which
// is what removes the ambiguity that made this a defect: server::lua_send_to
// used to check its own connection table first and fall back to the forwarded
// table, so a forwarded id that collided with one of its own descriptors
// delivered to the wrong client — silently, and only in the configuration the
// split makes universal.
//
// Above MAX_FDS (8192) and above any descriptor RLIMIT_NOFILE can produce on a
// sane box.  A handle is per-runtime and means nothing outside it; what travels
// is the conn_ref it maps to.
inline constexpr int conn_handle_base = 1 << 24;      // 16777216

inline bool is_conn_handle(int id) { return id >= conn_handle_base; }
