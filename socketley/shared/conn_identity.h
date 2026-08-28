#pragma once
// What names a connection when the thing naming it is somewhere else.
//
// A descriptor is an index into one process's table: not unique across
// processes, reissued after close, and a licence to name any of them.  A
// conn_ref is minted once by the owner, never reused, and a stale one resolves
// to nothing.
//
// `owner` says which runtime minted it, so a serial need only be unique within
// one.  `serial` says which connection, seeded from the clock so a restart
// cannot hand back a name the previous lifetime used.
//
// The top six bits of the serial are the minting SHARD, because every shard of
// a runtime shares its owner key and mints from an independent counter -- so
// without them two shards eventually hand out the same serial.  It also lets a
// holder route to one shard instead of offering the ref to all N.  The
// remaining 58 bits are 9.1 years of uptime before the counter wraps.
#include <cstdint>
#include <ctime>
#include <string>
#include <string_view>

// Zero is reserved for "no runtime", so a ref built before an id was assigned
// is detectably invalid rather than quietly equal to another.
inline uint64_t conn_owner_key(std::string_view runtime_id)
{
    if (runtime_id.empty())
        return 0;

    // FNV-1a over six hex digits; the id travels beside the key in every
    // handshake, so a collision is caught rather than acted on.
    uint64_t h = 1469598103934665603ull;
    for (const char c : runtime_id)
    {
        h ^= static_cast<uint8_t>(c);
        h *= 1099511628211ull;
    }
    return h ? h : 1ull;      // never collide with the reserved zero
}

// Six bits of shard index above 58 bits of counter.
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

// Mints the serial half, one per runtime instance.  Seeded from
// CLOCK_MONOTONIC rather than 1, so a restart of the same runtime cannot mint
// serials a peer still holds -- and monotonic because NTP cannot move it back.
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

    // Not a constructor argument: the shard index arrives in a config frame,
    // read long after this is built.  Call it before the first next().
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

// Lua gets a descriptor for a runtime's own clients and a handle for a routed
// one, from a range no descriptor can occupy -- so the two can never collide.
// A handle is per-runtime; what travels is the conn_ref it maps to.
inline constexpr int conn_handle_base = 1 << 24;      // 16777216

inline bool is_conn_handle(int id) { return id >= conn_handle_base; }
