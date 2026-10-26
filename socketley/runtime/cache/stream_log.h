#pragma once
// A stream: entries in id order packed into blocks, and the groups reading it.
//
// A block is one buffer of the opening entry's field names and then entries
// stored against its first id, each naming its fields only where they differ.
//
// Blocks sit in a vector ordered by first live id, so a range starts with a
// binary search and a walk of at most one block.
//
// Blocks are cut where Redis cuts its nodes, because MAXLEN ~ removes whole
// ones and a different cut would trim a different count.

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <new>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "heap_cost.h"

struct stream_id
{
    uint64_t ms{0};
    uint64_t seq{0};

    friend constexpr bool operator==(const stream_id&, const stream_id&) = default;
    friend constexpr auto operator<=>(const stream_id&, const stream_id&) = default;

    static constexpr stream_id max() { return { UINT64_MAX, UINT64_MAX }; }
    constexpr bool is_zero() const { return ms == 0 && seq == 0; }

    // The id one above, false when there is none and it wraps to 0-0.
    bool incr()
    {
        if (seq != UINT64_MAX) { ++seq; return true; }
        if (ms != UINT64_MAX) { ++ms; seq = 0; return true; }
        ms = seq = 0;
        return false;
    }

    // The id one below, false when there is none and it wraps to the maximum.
    bool decr()
    {
        if (seq != 0) { --seq; return true; }
        if (ms != 0) { --ms; seq = UINT64_MAX; return true; }
        ms = seq = UINT64_MAX;
        return false;
    }

    static constexpr size_t text_max = 41;

    // "<ms>-<seq>" into `buf`, which holds text_max bytes, answering the length.
    size_t format(char* buf) const
    {
        char* p = std::to_chars(buf, buf + 20, ms).ptr;
        *p++ = '-';
        p = std::to_chars(p, buf + text_max, seq).ptr;
        return static_cast<size_t>(p - buf);
    }

    std::string str() const
    {
        char b[text_max];
        return std::string(b, format(b));
    }
};

// ─── Redis's number and id grammar ──────────────────────────────────────────

// Redis's string2ll: an optional minus, no leading zero, nothing else.
inline bool stream_strict_ll(std::string_view s, int64_t& out)
{
    if (s.empty() || s.size() > 20) return false;
    if (s.size() == 1 && s[0] == '0') { out = 0; return true; }
    size_t i = 0;
    const bool neg = s[0] == '-';
    if (neg && ++i == s.size()) return false;
    if (s[i] < '1' || s[i] > '9') return false;
    uint64_t v = 0;
    for (; i < s.size(); ++i)
    {
        if (s[i] < '0' || s[i] > '9') return false;
        const uint64_t d = static_cast<uint64_t>(s[i] - '0');
        if (v > (UINT64_MAX - d) / 10) return false;
        v = v * 10 + d;
    }
    if (neg)
    {
        if (v > static_cast<uint64_t>(INT64_MAX) + 1) return false;
        out = static_cast<int64_t>(0 - v);
        return true;
    }
    if (v > static_cast<uint64_t>(INT64_MAX)) return false;
    out = static_cast<int64_t>(v);
    return true;
}

// Redis's string2ull: the strict reading, then strtoull's looser one.
inline bool stream_parse_u64(std::string_view s, uint64_t& out)
{
    int64_t ll = 0;
    if (stream_strict_ll(s, ll))
    {
        if (ll < 0) return false;
        out = static_cast<uint64_t>(ll);
        return true;
    }
    char buf[128];
    if (s.size() >= sizeof(buf)) return false;
    std::memcpy(buf, s.data(), s.size());
    buf[s.size()] = '\0';
    errno = 0;
    char* end = nullptr;
    out = std::strtoull(buf, &end, 10);
    return !(errno == EINVAL || errno == ERANGE || buf[0] == '\0' || *end != '\0');
}

// Redis's stream id: "-", "+", "<ms>" with `missing_seq`, "<ms>-<seq>", and
// "<ms>-*" when `seq_given` is asked for; `strict` refuses "-" and "+".
inline bool stream_parse_id(std::string_view s, stream_id& id, uint64_t missing_seq,
                            bool strict, bool* seq_given)
{
    // Redis reads the argument as a C string, so a NUL ends it there too.
    if (const size_t nul = s.find('\0'); nul != std::string_view::npos) s = s.substr(0, nul);
    if (s.size() > 127) return false;
    if (strict && s.size() == 1 && (s[0] == '-' || s[0] == '+')) return false;
    if (seq_given) *seq_given = true;
    if (s == "-") { id = {0, 0}; return true; }
    if (s == "+") { id = stream_id::max(); return true; }
    const size_t dash = s.find('-');
    uint64_t ms = 0, seq = missing_seq;
    if (!stream_parse_u64(s.substr(0, dash), ms)) return false;
    if (dash != std::string_view::npos)
    {
        const std::string_view rest = s.substr(dash + 1);
        if (seq_given && rest == "*") { seq = 0; *seq_given = false; }
        else if (!stream_parse_u64(rest, seq)) return false;
    }
    id = { ms, seq };
    return true;
}

// ─── A stream write as one replication record ───────────────────────────────

// Arguments as <length>:<bytes>, the form in which a stream write survives the
// text line a follower and the journal split on spaces.
inline void stream_args_encode(std::string& out, const std::string_view* a, size_t n)
{
    char len[24];
    for (size_t i = 0; i < n; ++i)
    {
        const auto r = std::to_chars(len, len + sizeof(len), a[i].size());
        out.append(len, r.ptr);
        out.push_back(':');
        out.append(a[i].data(), a[i].size());
    }
}

inline bool stream_args_decode(std::string_view in, std::vector<std::string_view>& out)
{
    while (!in.empty())
    {
        size_t len = 0;
        const auto r = std::from_chars(in.data(), in.data() + in.size(), len);
        if (r.ec != std::errc{} || r.ptr == in.data() || r.ptr == in.data() + in.size() || *r.ptr != ':')
            return false;
        const size_t head = static_cast<size_t>(r.ptr - in.data()) + 1;
        if (in.size() - head < len) return false;
        out.push_back(in.substr(head, len));
        in.remove_prefix(head + len);
    }
    return true;
}

// ─── The stream ─────────────────────────────────────────────────────────────

class stream_log
{
public:
    static constexpr uint32_t node_max_entries = 100;
    static constexpr size_t   node_max_bytes   = 4096;

    struct consumer
    {
        std::string_view    name;          // the key of the map it lives in
        int64_t             seen_ms{0};
        int64_t             active_ms{-1};
        std::set<stream_id> pel;
    };
    struct nack
    {
        int64_t   delivery_ms{0};
        uint64_t  count{0};
        consumer* owner{nullptr};
        std::set<stream_id>::iterator in_owner;   // this id in owner->pel, valid while owner is set
    };
    using pel_map      = std::map<stream_id, nack>;
    using consumer_map = std::map<std::string, consumer, std::less<>>;

    // A group's pending entries by id beside the map that keeps them in order,
    // so an ack or a claim finds its entry in a probe instead of a walk down a
    // tree of every pending entry: that walk was 64% of XACK's worker on a
    // group with a million pending, level with Redis where XREADGROUP is 3.9x.
    class pel_index
    {
    public:
        static constexpr size_t npos = static_cast<size_t>(-1);

        // Written out because a nested class's member initialisers are not usable before its enclosing class ends.
        pel_index() noexcept : m_cap(0), m_size(0), m_tombs(0) {}

        size_t heap_bytes() const { return m_cap ? malloc_chunk_bytes(m_cap * sizeof(pel_map::iterator)) + malloc_chunk_bytes(m_cap) : 0; }
        pel_map::iterator at(size_t i) const { return m_slots[i]; }

        size_t locate(stream_id id) const
        {
            if (m_size == 0) return npos;
            const size_t mask = m_cap - 1;
            for (size_t i = hash(id) & mask;; i = (i + 1) & mask)
            {
                if (m_state[i] == empty) return npos;
                if (m_state[i] == full && m_slots[i]->first == id) return i;
            }
        }

        void insert(pel_map::iterator it)
        {
            if (m_cap == 0 || (m_size + m_tombs + 1) * 4 > m_cap * 3)
            {
                size_t want = 16;
                while (want < (m_size + 1) * 2) want <<= 1;
                rebuild(want < m_cap ? m_cap : want);
            }
            const size_t mask = m_cap - 1;
            size_t i = hash(it->first) & mask;
            while (m_state[i] == full) i = (i + 1) & mask;
            if (m_state[i] == tomb) --m_tombs;
            m_slots[i] = it;
            m_state[i] = full;
            ++m_size;
        }

        // As key_table::vacate: a tombstone only where a probe may pass it.
        void erase_at(size_t i)
        {
            const size_t mask = m_cap - 1;
            --m_size;
            if (m_state[(i + 1) & mask] == empty)
            {
                m_state[i] = empty;
                for (size_t j = (i - 1) & mask; m_state[j] == tomb; j = (j - 1) & mask)
                {
                    m_state[j] = empty;
                    --m_tombs;
                }
            }
            else
            {
                m_state[i] = tomb;
                ++m_tombs;
            }
        }

    private:
        static constexpr uint8_t empty = 0, tomb = 1, full = 2;

        static uint64_t hash(stream_id id)
        {
            uint64_t h = id.ms * 0x9E3779B97F4A7C15ull ^ (id.seq + 0x632BE59BD9B4E019ull);
            h ^= h >> 31; h *= 0xBF58476D1CE4E5B9ull; h ^= h >> 29;
            return h;
        }

        void rebuild(size_t cap)
        {
            std::vector<pel_map::iterator> slots(cap);
            std::vector<uint8_t> state(cap, empty);
            for (size_t i = 0; i < m_cap; ++i)
            {
                if (m_state[i] != full) continue;
                size_t j = hash(m_slots[i]->first) & (cap - 1);
                while (state[j] == full) j = (j + 1) & (cap - 1);
                slots[j] = m_slots[i];
                state[j] = full;
            }
            m_slots.swap(slots);
            m_state.swap(state);
            m_cap = cap;
            m_tombs = 0;
        }

        std::vector<pel_map::iterator> m_slots;
        std::vector<uint8_t>           m_state;
        size_t m_cap;
        size_t m_size;
        size_t m_tombs;
    };

    struct group
    {
        stream_id    last;
        int64_t      entries_read{-1};     // -1 is Redis's "not known"
        pel_map      pel;
        pel_index    ix;                   // pel by id, see pel_index
        consumer_map consumers;
    };
    using group_map = std::map<std::string, group, std::less<>>;

    // One entry read in place, valid until the stream next changes.
    class entry
    {
    public:
        stream_id id;
        uint32_t  pairs() const { return m_n; }

        template <class F>
        void each(F&& f) const
        {
            const char* p = m_p;
            const char* m = m_master;
            for (uint32_t i = 0; i < m_n; ++i)
            {
                std::string_view fld;
                if (m_master) { const size_t l = get_var(m); fld = { m, l }; m += l; }
                else          { const size_t l = get_var(p); fld = { p, l }; p += l; }
                const size_t vl = get_var(p);
                f(fld, std::string_view(p, vl));
                p += vl;
            }
        }

    private:
        friend class stream_log;
        const char* m_p{nullptr};
        const char* m_master{nullptr};     // the block's field names, or null when the entry has its own
        uint32_t    m_n{0};
    };

    enum class trim_by : uint8_t { none, maxlen, minid };
    struct trim_spec
    {
        trim_by   by{trim_by::none};
        bool      approx{false};
        int64_t   limit{0};                // 0 is no limit
        uint64_t  maxlen{0};
        stream_id minid;
    };

    stream_log() = default;
    ~stream_log() { release(); }

    // Through its own serialisation, which COPY is rare enough to afford and
    // which rebuilds every consumer pointer rather than copying stale ones.
    stream_log(const stream_log& o)
    {
        std::string s;
        o.serialize(s);
        deserialize(s);
    }
    stream_log& operator=(const stream_log& o)
    {
        if (this != &o) { stream_log c(o); *this = std::move(c); }
        return *this;
    }
    stream_log(stream_log&& o) noexcept { steal(o); }
    stream_log& operator=(stream_log&& o) noexcept
    {
        if (this != &o) { release(); steal(o); }
        return *this;
    }

    uint64_t  size()          const { return m_length; }
    bool      empty()         const { return m_length == 0; }
    stream_id last_id()       const { return m_last; }
    stream_id max_deleted()   const { return m_max_deleted; }
    uint64_t  entries_added() const { return m_entries_added; }
    size_t    block_count()   const { return m_blocks.size() - m_head; }
    // Every byte of heap the stream holds, its blocks, index and groups.
    size_t    heap_bytes()    const { return m_heap; }
    // The part of heap_bytes() the groups' pending indexes hold, which follows
    // their peak rather than their size, so a reloaded copy may hold less.
    size_t pending_index_bytes() const
    {
        size_t n = 0;
        if (m_groups)
            for (const auto& [name, g] : *m_groups) n += g.ix.heap_bytes();
        return n;
    }

    // Redis's recorded first id, which is the first live entry or 0-0.
    stream_id first_id() const { return m_length ? m_blocks[m_head].first : stream_id{}; }

    // The last entry that is still there, meaningful only while there is one.
    stream_id last_live() const { return m_last_live; }

    // XSETID's three values, already checked against the entries.
    void set_meta(stream_id last, uint64_t added, stream_id max_deleted)
    {
        m_last = last;
        m_entries_added = added;
        m_max_deleted = max_deleted;
    }
    void set_last(stream_id last) { m_last = last; }
    void set_entries_added(uint64_t n) { m_entries_added = n; }
    void set_max_deleted(stream_id id) { m_max_deleted = id; }

    // ─── Entries ────────────────────────────────────────────────────────────

    // What an append of these fields would grow the heap by, predicted with
    // the decision append() makes.
    size_t append_growth(stream_id id, const std::string_view* fv, size_t pairs) const
    {
        const plan p = plan_append(id, fv, pairs);
        size_t g = heap(p.new_cap) - heap(p.old_cap);
        if (p.new_block) g += index_growth();
        return g;
    }

    // One entry at `id`, which the caller has checked is above last_id().
    void append(stream_id id, const std::string_view* fv, size_t pairs)
    {
        const plan p = plan_append(id, fv, pairs);
        if (p.new_block)
            open_block(id, fv, pairs, p.new_cap);
        block& b = m_blocks.back();
        if (!p.new_block && p.new_cap != b.cap)
            resize(b, p.new_cap);

        char* w = b.buf + b.used;
        *w++ = static_cast<char>(p.same ? 1 : 0);
        w += put_var(w, id.ms - b.base.ms);
        w += put_var(w, id.seq);
        if (!p.same) w += put_var(w, pairs);
        for (size_t i = 0; i < pairs; ++i)
        {
            if (!p.same) w = put_str(w, fv[2 * i]);
            w = put_str(w, fv[2 * i + 1]);
        }
        b.used = static_cast<uint32_t>(w - b.buf);
        if (b.live == 0) b.first = id;
        ++b.live;
        b.last = id;
        ++m_length;
        ++m_entries_added;
        m_last = id;
        m_last_live = id;
    }

    // Every entry from `lo` to `hi` inclusive, lowest first or highest first,
    // for as long as `f` answers true.
    template <class F>
    void walk(stream_id lo, stream_id hi, bool rev, F&& f) const
    {
        if (m_length == 0 || lo > hi) return;
        if (!rev)
        {
            for (size_t b = locate(lo); b < m_blocks.size(); ++b)
            {
                const block& bk = m_blocks[b];
                if (bk.first > hi) return;
                const char* p = bk.buf + bk.body;
                const char* e = bk.buf + bk.used;
                while (p < e)
                {
                    entry en;
                    p = decode(bk, p, en);
                    if (en.id < lo) continue;
                    if (en.id > hi) return;
                    if (!f(static_cast<const entry&>(en))) return;
                }
            }
            return;
        }
        // Sized for a full block once, rather than regrown through eight sizes on every call.
        std::vector<const char*> offs;
        offs.reserve(node_max_entries);
        for (size_t b = locate(hi) + 1; b-- > m_head;)
        {
            const block& bk = m_blocks[b];
            offs.clear();
            for (const char* p = bk.buf + bk.body; p < bk.buf + bk.used; p = skip(bk, p))
                offs.push_back(p);
            for (size_t i = offs.size(); i-- > 0;)
            {
                entry en;
                decode(bk, offs[i], en);
                if (en.id > hi) continue;
                if (en.id < lo) return;
                if (!f(static_cast<const entry&>(en))) return;
            }
        }
    }

    // The entry at exactly `id`, if it is there.
    bool find(stream_id id, entry& out) const
    {
        bool found = false;
        walk(id, id, false, [&](const entry& e) { out = e; found = true; return false; });
        return found;
    }
    bool contains(stream_id id) const { entry e; return find(id, e); }

    // XDEL of one id, the tombstone it leaves counted as Redis counts it.
    bool erase(stream_id id)
    {
        if (m_length == 0) return false;
        const size_t b = locate(id);
        block& bk = m_blocks[b];
        for (const char* p = bk.buf + bk.body; p < bk.buf + bk.used;)
        {
            entry en;
            const char* q = decode(bk, p, en);
            if (en.id > id) return false;
            if (en.id == id)
            {
                remove_prefix_or_span(b, static_cast<size_t>(p - bk.buf),
                                      static_cast<size_t>(q - bk.buf), 1);
                if (id > m_max_deleted) m_max_deleted = id;
                if (m_length && id == m_last_live) m_last_live = tail_last();
                return true;
            }
            p = q;
        }
        return false;
    }

    // XTRIM and XADD's trimming, whole blocks first and then, unless `approx`,
    // entries from the front of the next.
    uint64_t trim(const trim_spec& t)
    {
        if (t.by == trim_by::none) return 0;
        uint64_t deleted = 0;
        while (m_head < m_blocks.size())
        {
            if (t.by == trim_by::maxlen && m_length <= t.maxlen) break;
            block& bk = m_blocks[m_head];
            const uint64_t entries = bk.live;
            if (t.limit && deleted + entries > static_cast<uint64_t>(t.limit)) break;
            const bool whole = t.by == trim_by::maxlen ? m_length - entries >= t.maxlen
                                                       : bk.last < t.minid;
            if (whole)
            {
                m_length -= entries;
                deleted += entries;
                drop_block(m_head);
                continue;
            }
            if (t.approx) break;
            // The prefix of this block that goes, measured before it is cut.
            uint32_t n = 0;
            const char* p = bk.buf + bk.body;
            while (p < bk.buf + bk.used)
            {
                if (t.by == trim_by::maxlen && m_length - n <= t.maxlen) break;
                entry en;
                const char* q = decode(bk, p, en);
                if (t.by == trim_by::minid && en.id >= t.minid) break;
                p = q;
                ++n;
            }
            if (n)
            {
                remove_prefix_or_span(m_head, bk.body, static_cast<size_t>(p - bk.buf), n);
                deleted += n;
            }
            break;
        }
        if (m_length == 0) m_last_live = {};
        return deleted;
    }

    // Whether an XDEL has left a hole at or after `start`, which is what makes
    // a group's read counter unknowable (Redis's streamRangeHasTombstones).
    bool tombstone_from(stream_id start) const
    {
        if (m_length == 0 || m_max_deleted.is_zero()) return false;
        if (first_id() > m_max_deleted) return false;
        return start <= m_max_deleted;
    }

    // How many entries were ever added up to and including `id`, or -1 when
    // that cannot be known (Redis's streamEstimateDistanceFromFirstEverEntry).
    int64_t estimate_read(stream_id id) const
    {
        if (!m_entries_added) return 0;
        if (!m_length && id <= m_last) return static_cast<int64_t>(m_entries_added);
        if (id == m_last) return static_cast<int64_t>(m_entries_added);
        if (id > m_last) return -1;
        const stream_id first = first_id();
        if (m_max_deleted.is_zero() || m_max_deleted < first)
        {
            if (id < first) return static_cast<int64_t>(m_entries_added - m_length);
            if (id == first) return static_cast<int64_t>(m_entries_added - m_length + 1);
        }
        return -1;
    }

    // A group's lag, false when Redis answers it with a null.
    bool lag(const group& g, int64_t& out) const
    {
        if (!m_entries_added) { out = 0; return true; }
        if (g.entries_read != -1 && !tombstone_from(g.last))
        {
            out = static_cast<int64_t>(m_entries_added) - g.entries_read;
            return true;
        }
        const int64_t er = estimate_read(g.last);
        if (er == -1) return false;
        out = static_cast<int64_t>(m_entries_added) - er;
        return true;
    }

    // A group moving its last-delivered id up to `id`, counting the read.
    void advance(group& g, stream_id id) const
    {
        if (g.entries_read != -1 && !tombstone_from(id)) ++g.entries_read;
        else if (m_entries_added) g.entries_read = estimate_read(id);
        g.last = id;
    }

    // ─── Groups ─────────────────────────────────────────────────────────────

    const group_map* groups() const { return m_groups.get(); }
    size_t group_count() const { return m_groups ? m_groups->size() : 0; }

    group* find_group(std::string_view name)
    {
        if (!m_groups) return nullptr;
        auto it = m_groups->find(name);
        return it == m_groups->end() ? nullptr : &it->second;
    }
    const group* find_group(std::string_view name) const
    {
        return const_cast<stream_log*>(this)->find_group(name);
    }

    size_t group_growth(std::string_view name) const
    {
        return (m_groups ? 0 : groups_head_bytes) + group_node_bytes + name_bytes(name.size());
    }

    // Null when the name is taken.
    group* create_group(std::string_view name, stream_id last, int64_t entries_read)
    {
        if (!m_groups)
        {
            m_groups = std::make_unique<group_map>();
            m_heap += groups_head_bytes;
        }
        auto [it, fresh] = m_groups->try_emplace(std::string(name));
        if (!fresh) return nullptr;
        it->second.last = last;
        it->second.entries_read = entries_read;
        m_heap += group_node_bytes + name_bytes(name.size());
        return &it->second;
    }

    bool destroy_group(std::string_view name)
    {
        if (!m_groups) return false;
        auto it = m_groups->find(name);
        if (it == m_groups->end()) return false;
        group& g = it->second;
        m_heap -= g.pel.size() * nack_node_bytes + g.ix.heap_bytes();
        for (const auto& [cn, c] : g.consumers)
            m_heap -= consumer_node_bytes + name_bytes(cn.size()) + c.pel.size() * cpel_node_bytes;
        m_heap -= group_node_bytes + name_bytes(it->first.size());
        m_groups->erase(it);
        if (m_groups->empty())
        {
            m_groups.reset();
            m_heap -= groups_head_bytes;
        }
        return true;
    }

    consumer* find_consumer(group& g, std::string_view name)
    {
        auto it = g.consumers.find(name);
        return it == g.consumers.end() ? nullptr : &it->second;
    }

    static size_t consumer_growth(std::string_view name)
    {
        return consumer_node_bytes + name_bytes(name.size());
    }

    // Null when the consumer is there already.
    consumer* create_consumer(group& g, std::string_view name, int64_t now_ms)
    {
        auto [it, fresh] = g.consumers.try_emplace(std::string(name));
        if (!fresh) return nullptr;
        it->second.name = it->first;
        it->second.seen_ms = now_ms;
        m_heap += consumer_node_bytes + name_bytes(name.size());
        return &it->second;
    }

    // The consumer and its pending entries gone, answering how many it had,
    // or -1 when it was not there.
    int64_t delete_consumer(group& g, std::string_view name)
    {
        auto it = g.consumers.find(name);
        if (it == g.consumers.end()) return -1;
        const size_t n = it->second.pel.size();
        for (const stream_id& id : it->second.pel)
        {
            const size_t k = g.ix.locate(id);
            const auto at = g.ix.at(k);
            g.ix.erase_at(k);
            g.pel.erase(at);
        }
        m_heap -= n * (nack_node_bytes + cpel_node_bytes);
        m_heap -= consumer_node_bytes + name_bytes(it->first.size());
        g.consumers.erase(it);
        return static_cast<int64_t>(n);
    }

    nack* find_nack(group& g, stream_id id)
    {
        const size_t k = g.ix.locate(id);
        return k == pel_index::npos ? nullptr : &g.ix.at(k)->second;
    }

    // `id` delivered to `c`: a new pending entry, or the one there moved to `c`
    // and restarted, as XREADGROUP does it.
    nack& deliver(group& g, stream_id id, consumer& c, int64_t now_ms)
    {
        nack& n = pending_entry(g, id);
        move_nack(id, n, c);
        n.delivery_ms = now_ms;
        n.count = 1;
        return n;
    }

    // A pending entry with no owner yet, which XCLAIM's FORCE makes delivered
    // once, now, as Redis's streamCreateNACK does.
    nack& force_nack(group& g, stream_id id, int64_t now_ms)
    {
        const size_t before = g.pel.size();
        nack& n = pending_entry(g, id);
        if (g.pel.size() != before)
        {
            n.delivery_ms = now_ms;
            n.count = 1;
        }
        return n;
    }

    // `n`, pending under `id`, handed to `c`.
    void move_nack(stream_id id, nack& n, consumer& c)
    {
        if (n.owner == &c) return;
        if (n.owner)
        {
            n.owner->pel.erase(n.in_owner);
            m_heap -= cpel_node_bytes;
        }
        // Deliveries come in id order, so the new id is usually the owner's last.
        n.in_owner = (c.pel.empty() || *c.pel.rbegin() < id) ? c.pel.emplace_hint(c.pel.end(), id)
                                                             : c.pel.insert(id).first;
        m_heap += cpel_node_bytes;
        n.owner = &c;
    }

    bool ack(group& g, stream_id id)
    {
        const size_t k = g.ix.locate(id);
        if (k == pel_index::npos) return false;
        const auto it = g.ix.at(k);
        if (consumer* o = it->second.owner)
        {
            o->pel.erase(it->second.in_owner);
            m_heap -= cpel_node_bytes;
        }
        g.ix.erase_at(k);
        g.pel.erase(it);
        m_heap -= nack_node_bytes;
        return true;
    }

    // ─── Persistence ────────────────────────────────────────────────────────

    // Every entry and group as native-endian lengths and bytes, the dump's own
    // convention.
    void serialize(std::string& out) const
    {
        put_u64(out, m_entries_added);
        put_id(out, m_last);
        put_id(out, m_max_deleted);
        put_u64(out, m_length);
        walk({}, stream_id::max(), false, [&](const entry& e) {
            put_id(out, e.id);
            put_u32(out, e.pairs());
            e.each([&](std::string_view f, std::string_view v) { put_bytes(out, f); put_bytes(out, v); });
            return true;
        });
        put_u32(out, static_cast<uint32_t>(group_count()));
        if (!m_groups) return;
        for (const auto& [gname, g] : *m_groups)
        {
            put_bytes(out, gname);
            put_id(out, g.last);
            put_u64(out, static_cast<uint64_t>(g.entries_read));
            put_u32(out, static_cast<uint32_t>(g.consumers.size()));
            std::map<const consumer*, uint32_t> index;
            for (const auto& [cname, c] : g.consumers)
            {
                index.emplace(&c, static_cast<uint32_t>(index.size()));
                put_bytes(out, cname);
                put_u64(out, static_cast<uint64_t>(c.seen_ms));
                put_u64(out, static_cast<uint64_t>(c.active_ms));
            }
            put_u64(out, g.pel.size());
            for (const auto& [id, n] : g.pel)
            {
                const auto oi = index.find(n.owner);
                put_id(out, id);
                put_u32(out, oi == index.end() ? UINT32_MAX : oi->second);
                put_u64(out, static_cast<uint64_t>(n.delivery_ms));
                put_u64(out, n.count);
            }
        }
    }

    // Into an empty stream, false for bytes serialize() could not have written.
    bool deserialize(std::string_view in)
    {
        const char* p = in.data();
        const char* end = p + in.size();
        uint64_t added = 0, n = 0;
        stream_id last, maxdel;
        if (!get_u64(p, end, added) || !get_id(p, end, last) || !get_id(p, end, maxdel)
            || !get_u64(p, end, n))
            return false;
        std::vector<std::string_view> fv;
        stream_id prev;
        for (uint64_t i = 0; i < n; ++i)
        {
            stream_id id;
            uint32_t pairs = 0;
            if (!get_id(p, end, id) || !get_u32(p, end, pairs)) return false;
            if ((i > 0 && id <= prev) || id.is_zero() || id > last) return false;
            if (pairs > static_cast<size_t>(end - p) / 8) return false;
            fv.clear();
            for (uint32_t k = 0; k < 2 * pairs; ++k)
            {
                std::string_view s;
                if (!get_bytes(p, end, s)) return false;
                fv.push_back(s);
            }
            append(id, fv.data(), pairs);
            prev = id;
        }
        if (added < m_length || maxdel > last) return false;
        set_meta(last, added, maxdel);

        uint32_t ng = 0;
        if (!get_u32(p, end, ng)) return false;
        for (uint32_t i = 0; i < ng; ++i)
        {
            std::string_view gname;
            stream_id glast;
            uint64_t er = 0;
            uint32_t nc = 0;
            if (!get_bytes(p, end, gname) || !get_id(p, end, glast) || !get_u64(p, end, er)
                || !get_u32(p, end, nc))
                return false;
            group* g = create_group(gname, glast, static_cast<int64_t>(er));
            if (!g || nc > static_cast<size_t>(end - p) / 20) return false;
            std::vector<consumer*> cons;
            for (uint32_t k = 0; k < nc; ++k)
            {
                std::string_view cname;
                uint64_t seen = 0, active = 0;
                if (!get_bytes(p, end, cname) || !get_u64(p, end, seen) || !get_u64(p, end, active))
                    return false;
                consumer* c = create_consumer(*g, cname, static_cast<int64_t>(seen));
                if (!c) return false;
                c->active_ms = static_cast<int64_t>(active);
                cons.push_back(c);
            }
            uint64_t np = 0;
            if (!get_u64(p, end, np) || np > static_cast<size_t>(end - p) / 36) return false;
            for (uint64_t k = 0; k < np; ++k)
            {
                stream_id id;
                uint32_t owner = 0;
                uint64_t when = 0, count = 0;
                if (!get_id(p, end, id) || !get_u32(p, end, owner) || !get_u64(p, end, when)
                    || !get_u64(p, end, count))
                    return false;
                if (owner >= cons.size() || g->ix.locate(id) != pel_index::npos) return false;
                nack& nk = force_nack(*g, id, static_cast<int64_t>(when));
                move_nack(id, nk, *cons[owner]);
                nk.delivery_ms = static_cast<int64_t>(when);
                nk.count = count;
            }
        }
        return p == end;
    }

private:
    // The pending entry for `id`, made when there is none and indexed with it.
    nack& pending_entry(group& g, stream_id id)
    {
        const size_t k = g.ix.locate(id);
        if (k != pel_index::npos) return g.ix.at(k)->second;
        // Deliveries come in id order, so the new id is usually past every pending one.
        const auto it = (g.pel.empty() || g.pel.rbegin()->first < id) ? g.pel.emplace_hint(g.pel.end(), id, nack{})
                                                                     : g.pel.emplace(id, nack{}).first;
        const size_t ix_before = g.ix.heap_bytes();
        g.ix.insert(it);
        m_heap += nack_node_bytes + (g.ix.heap_bytes() - ix_before);
        return it->second;
    }

    struct block
    {
        stream_id base;       // the id the block was opened with, which each entry's ms is stored against
        stream_id first;      // the first live entry, which the index is searched by
        stream_id last;       // the last entry placed, deleted or not, which MINID reads
        char*     buf{nullptr};
        uint32_t  used{0};
        uint32_t  cap{0};
        uint32_t  live{0};
        uint32_t  dead{0};
        uint32_t  body{0};    // where the entries begin, past the field names
        uint32_t  fields{0};  // how many field names the block opened with
    };

    static constexpr size_t rb_node             = 32;
    static constexpr size_t groups_head_bytes   = malloc_chunk_bytes(sizeof(group_map));
    static constexpr size_t group_node_bytes    = malloc_chunk_bytes(rb_node + sizeof(group_map::value_type));
    static constexpr size_t consumer_node_bytes = malloc_chunk_bytes(rb_node + sizeof(consumer_map::value_type));
    static constexpr size_t nack_node_bytes     = malloc_chunk_bytes(rb_node + sizeof(pel_map::value_type));
    static constexpr size_t cpel_node_bytes     = malloc_chunk_bytes(rb_node + sizeof(stream_id));

    static size_t heap(size_t n) { return n ? malloc_chunk_bytes(n) : 0; }
    static size_t name_bytes(size_t len)
    {
        return len < sizeof(std::string) - sizeof(char*) - sizeof(size_t) ? 0 : malloc_chunk_bytes(len + 1);
    }

    static size_t var_len(uint64_t v) { size_t n = 1; while (v >= 0x80) { v >>= 7; ++n; } return n; }
    static size_t put_var(char* p, uint64_t v)
    {
        size_t n = 0;
        while (v >= 0x80) { p[n++] = static_cast<char>((v & 0x7F) | 0x80); v >>= 7; }
        p[n++] = static_cast<char>(v);
        return n;
    }
    static uint64_t get_var(const char*& p)
    {
        uint64_t v = 0;
        for (int shift = 0;; shift += 7)
        {
            const uint8_t b = static_cast<uint8_t>(*p++);
            v |= static_cast<uint64_t>(b & 0x7F) << shift;
            if (!(b & 0x80)) return v;
        }
    }
    static char* put_str(char* w, std::string_view s)
    {
        w += put_var(w, s.size());
        if (!s.empty()) std::memcpy(w, s.data(), s.size());
        return w + s.size();
    }

    struct plan
    {
        bool   new_block;
        bool   same;
        size_t new_cap;
        size_t old_cap;
    };

    // Whether an append opens a block and what it writes, the one decision
    // append() and append_growth() both follow.
    plan plan_append(stream_id id, const std::string_view* fv, size_t pairs) const
    {
        size_t raw = 0;
        for (size_t i = 0; i < 2 * pairs; ++i) raw += fv[i].size();
        const block* t = m_head < m_blocks.size() ? &m_blocks.back() : nullptr;
        plan p{};
        p.new_block = !t || t->used + raw >= node_max_bytes || t->live + t->dead >= node_max_entries;
        p.same = p.new_block || same_fields(*t, fv, pairs);
        const stream_id base = p.new_block ? id : t->base;
        size_t e = 1 + var_len(id.ms - base.ms) + var_len(id.seq);
        if (!p.same) e += var_len(pairs);
        for (size_t i = 0; i < pairs; ++i)
        {
            if (!p.same) e += var_len(fv[2 * i].size()) + fv[2 * i].size();
            e += var_len(fv[2 * i + 1].size()) + fv[2 * i + 1].size();
        }
        if (p.new_block)
        {
            size_t master = var_len(pairs);
            for (size_t i = 0; i < pairs; ++i) master += var_len(fv[2 * i].size()) + fv[2 * i].size();
            p.old_cap = 0;
            p.new_cap = grown(0, master + e);
        }
        else
        {
            p.old_cap = t->cap;
            p.new_cap = t->used + e > t->cap ? grown(t->cap, t->used + e) : t->cap;
        }
        return p;
    }

    static size_t grown(size_t cap, size_t need)
    {
        size_t c = cap + cap / 2;
        if (c < 64) c = 64;
        return c < need ? need : c;
    }

    bool same_fields(const block& b, const std::string_view* fv, size_t pairs) const
    {
        if (b.fields != pairs) return false;
        const char* m = b.buf;
        get_var(m);
        for (size_t i = 0; i < pairs; ++i)
        {
            const size_t l = get_var(m);
            if (fv[2 * i] != std::string_view(m, l)) return false;
            m += l;
        }
        return true;
    }

    size_t index_bytes() const { return heap(m_blocks.capacity() * sizeof(block)); }

    // What the next block's slot costs the index, following push_block().
    size_t index_growth() const
    {
        if (m_blocks.size() < m_blocks.capacity() || m_head > 0) return 0;
        const size_t cap = m_blocks.capacity();
        return heap((cap ? 2 * cap : 1) * sizeof(block)) - heap(cap * sizeof(block));
    }

    void open_block(stream_id id, const std::string_view* fv, size_t pairs, size_t cap)
    {
        if (m_head < m_blocks.size())
            fit(m_blocks.back());
        block b;
        b.base = b.first = b.last = id;
        b.buf = static_cast<char*>(std::malloc(cap));
        if (!b.buf) throw std::bad_alloc();
        b.cap = static_cast<uint32_t>(cap);
        m_heap += heap(cap);
        char* w = b.buf;
        w += put_var(w, pairs);
        for (size_t i = 0; i < pairs; ++i) w = put_str(w, fv[2 * i]);
        b.used = b.body = static_cast<uint32_t>(w - b.buf);
        b.fields = static_cast<uint32_t>(pairs);
        const size_t before = index_bytes();
        if (m_head > 0 && m_blocks.size() == m_blocks.capacity())
            compact_index(true);
        m_blocks.push_back(b);
        m_heap += index_bytes();
        m_heap -= before;
    }

    void resize(block& b, size_t cap)
    {
        char* nb = static_cast<char*>(std::realloc(b.buf, cap));
        if (!nb) throw std::bad_alloc();
        m_heap += heap(cap);
        m_heap -= heap(b.cap);
        b.buf = nb;
        b.cap = static_cast<uint32_t>(cap);
    }

    // A block that will take no more appends keeps only what it holds.
    void fit(block& b)
    {
        if (b.cap > b.used) resize(b, b.used);
    }

    // The front `head` slots of the index given back, when they are most of it
    // or when `now` asks for the room.
    void compact_index(bool now)
    {
        if (m_head == 0) return;
        if (!now && (m_head < 16 || m_head * 2 < m_blocks.size())) return;
        const size_t before = index_bytes();
        m_blocks.erase(m_blocks.begin(), m_blocks.begin() + static_cast<std::ptrdiff_t>(m_head));
        m_head = 0;
        // Not when the room is wanted for the block about to be pushed.
        if (!now && m_blocks.capacity() > 64 && m_blocks.size() * 4 < m_blocks.capacity())
            m_blocks.shrink_to_fit();
        m_heap += index_bytes();
        m_heap -= before;
    }

    void drop_block(size_t b)
    {
        m_heap -= heap(m_blocks[b].cap);
        std::free(m_blocks[b].buf);
        if (b == m_head)
        {
            ++m_head;
            if (m_head == m_blocks.size())
            {
                const size_t before = index_bytes();
                m_blocks.clear();
                m_head = 0;
                if (m_blocks.capacity() > 64) m_blocks.shrink_to_fit();
                m_heap += index_bytes();
                m_heap -= before;
            }
            else
                compact_index(false);
            return;
        }
        m_blocks.erase(m_blocks.begin() + static_cast<std::ptrdiff_t>(b));
    }

    // `n` live entries between byte offsets `from` and `to` of block `b` gone,
    // and the block with them once nothing live is left in it.
    void remove_prefix_or_span(size_t b, size_t from, size_t to, uint32_t n)
    {
        block& bk = m_blocks[b];
        m_length -= n;
        bk.live -= n;
        bk.dead += n;
        if (bk.live == 0)
        {
            drop_block(b);
            return;
        }
        std::memmove(bk.buf + from, bk.buf + to, bk.used - to);
        bk.used -= static_cast<uint32_t>(to - from);
        if (from == bk.body)
        {
            entry en;
            decode(bk, bk.buf + bk.body, en);
            bk.first = en.id;
        }
        const bool tail = b + 1 == m_blocks.size();
        if (!tail && bk.cap > 2 * bk.used + 64) resize(bk, bk.used);
    }

    // The last entry of the last block, which is the last one still there.
    stream_id tail_last() const
    {
        const block& bk = m_blocks.back();
        stream_id id;
        for (const char* p = bk.buf + bk.body; p < bk.buf + bk.used;)
        {
            entry en;
            p = decode(bk, p, en);
            id = en.id;
        }
        return id;
    }

    // The block a walk from `id` starts in: the last whose first entry is not
    // past it, or the first block.
    size_t locate(stream_id id) const
    {
        auto it = std::upper_bound(m_blocks.begin() + static_cast<std::ptrdiff_t>(m_head), m_blocks.end(), id,
                                   [](stream_id x, const block& b) { return x < b.first; });
        const size_t i = static_cast<size_t>(it - m_blocks.begin());
        return i > m_head ? i - 1 : m_head;
    }

    const char* decode(const block& b, const char* p, entry& e) const
    {
        const bool same = (*p++ & 1) != 0;
        e.id.ms = b.base.ms + get_var(p);
        e.id.seq = get_var(p);
        if (same)
        {
            e.m_master = b.buf;
            e.m_n = static_cast<uint32_t>(get_var(e.m_master));
        }
        else
        {
            e.m_master = nullptr;
            e.m_n = static_cast<uint32_t>(get_var(p));
        }
        e.m_p = p;
        for (uint32_t i = 0; i < e.m_n; ++i)
        {
            if (!same) p += get_var(p);
            p += get_var(p);
        }
        return p;
    }

    const char* skip(const block& b, const char* p) const
    {
        entry e;
        return decode(b, p, e);
    }

    void release()
    {
        for (size_t b = m_head; b < m_blocks.size(); ++b) std::free(m_blocks[b].buf);
        m_blocks.clear();
        m_groups.reset();
    }

    void steal(stream_log& o) noexcept
    {
        m_blocks = std::move(o.m_blocks);
        m_head = o.m_head;
        m_length = o.m_length;
        m_entries_added = o.m_entries_added;
        m_last = o.m_last;
        m_last_live = o.m_last_live;
        m_max_deleted = o.m_max_deleted;
        m_groups = std::move(o.m_groups);
        m_heap = o.m_heap;
        o.m_blocks.clear();
        o.m_head = 0;
        o.m_length = o.m_entries_added = 0;
        o.m_last = o.m_last_live = o.m_max_deleted = {};
        o.m_heap = 0;
    }

    static void put_u32(std::string& o, uint32_t v) { o.append(reinterpret_cast<const char*>(&v), 4); }
    static void put_u64(std::string& o, uint64_t v) { o.append(reinterpret_cast<const char*>(&v), 8); }
    static void put_id(std::string& o, stream_id id) { put_u64(o, id.ms); put_u64(o, id.seq); }
    static void put_bytes(std::string& o, std::string_view s)
    {
        put_u32(o, static_cast<uint32_t>(s.size()));
        o.append(s.data(), s.size());
    }
    static bool get_u32(const char*& p, const char* e, uint32_t& v)
    {
        if (e - p < 4) return false;
        std::memcpy(&v, p, 4);
        p += 4;
        return true;
    }
    static bool get_u64(const char*& p, const char* e, uint64_t& v)
    {
        if (e - p < 8) return false;
        std::memcpy(&v, p, 8);
        p += 8;
        return true;
    }
    static bool get_id(const char*& p, const char* e, stream_id& id)
    {
        return get_u64(p, e, id.ms) && get_u64(p, e, id.seq);
    }
    static bool get_bytes(const char*& p, const char* e, std::string_view& s)
    {
        uint32_t n = 0;
        if (!get_u32(p, e, n) || static_cast<size_t>(e - p) < n) return false;
        s = { p, n };
        p += n;
        return true;
    }

    std::vector<block>         m_blocks;
    size_t                     m_head{0};         // blocks before it are trimmed and wait to be compacted away
    uint64_t                   m_length{0};
    uint64_t                   m_entries_added{0};
    stream_id                  m_last;
    stream_id                  m_last_live;
    stream_id                  m_max_deleted;
    std::unique_ptr<group_map> m_groups;
    size_t                     m_heap{0};
};
