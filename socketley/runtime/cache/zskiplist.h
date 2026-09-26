#pragma once

// The ordered half of a sorted set, with a rank you can ask for.
//
// It was a std::set<pair<double,string>>, which gives the right order and the
// right O(log n) insert, and the comment saying so was correct about
// everything except the question nobody had measured: WHERE a member sits.
// std::set has no order statistic, so ZRANK walked from the front and ZRANGE
// by index walked to `start`.
//
// Profiled at a hundred members, std::_Rb_tree_increment was 39% of the
// worker.  Swept against a real redis-server, ZRANK by set size:
//
//     members     100      1000     10000     50000
//     ratio      1.86x     0.50x     0.10x     0.03x
//
// Redis is flat across all four.  We fell by a factor of 61, and at fifty
// thousand members we were thirty-three times slower -- on a command that is
// O(log n) there and was O(n) here.  A hundred members is what the benchmark
// loads, which is why the table said 2.42x and meant "at this size".
//
// So: a skiplist carrying a SPAN on every forward pointer -- how many nodes it
// jumps over -- which is what turns a search into a rank.  Redis's structure,
// for Redis's reason.  Insert, erase, rank and index are all O(log n), and the
// ordered walk the rest of the store does is unchanged: follow level 0.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <new>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "pack_buf.h"

class zskiplist
{
public:
    using value_type = std::pair<double, std::string>;

    // A small set is one sorted buffer of [score][length][member][length] and
    // has no head at all: the head's 32 links alone were 512 bytes, three times
    // what Redis spends on a whole five-member set, and a vector of pairs was
    // still 40 bytes a member before its name.  Past SMALL_MAX members, or a
    // member past SMALL_MAX_LEN bytes, it becomes the skiplist for good.
    static constexpr size_t SMALL_MAX     = 128;
    static constexpr size_t SMALL_MAX_LEN = 64;

    // What an iterator answers in either form: the score and a view of the name.
    using entry = std::pair<double, std::string_view>;

    zskiplist() noexcept { ::new (&m_pack) pack_buf(); }
    ~zskiplist() { destroy_all(); }

    zskiplist(const zskiplist& o) : zskiplist() { for (auto it = o.begin(); it != o.end(); ++it) insert(it->first, std::string(it->second)); }
    zskiplist& operator=(const zskiplist& o)
    {
        if (this != &o) { clear(); for (auto it = o.begin(); it != o.end(); ++it) insert(it->first, std::string(it->second)); }
        return *this;
    }
    zskiplist(zskiplist&& o) noexcept { steal(o); }
    zskiplist& operator=(zskiplist&& o) noexcept
    {
        if (this != &o) { destroy_all(); steal(o); }
        return *this;
    }

    bool big() const { return m_level != 0; }

private:
    // 32 levels carries four billion members at p=1/4, which is more than the
    // process can hold; the level is per node, so the cost of the ceiling is
    // one pointer array in the head and nothing anywhere else.
    static constexpr int      max_level = 32;
    static constexpr uint32_t p_quarter = 0x3FFFFFFFu;   // 1/4 of the 32-bit range

    struct node;
    struct link
    {
        node*  fwd{nullptr};
        size_t span{0};        // nodes this pointer jumps over, 1 for adjacent
    };
    // The links sit in front of the node in the same block, level 0 nearest,
    // so a step down the list reads the score it compares and the link it
    // takes next from one line or two adjacent ones.
    struct node
    {
        value_type v;
        node*      back{nullptr};
        int        level{1};

        link&       L(int i)       { return reinterpret_cast<link*>(this)[-1 - i]; }
        const link& L(int i) const { return reinterpret_cast<const link*>(this)[-1 - i]; }
    };
    static_assert(sizeof(link) % alignof(node) == 0 && alignof(link) <= alignof(node));

    static node* make_node(int level, double score, std::string member)
    {
        const size_t front = sizeof(link) * static_cast<size_t>(level);
        char* mem = static_cast<char*>(::operator new(front + sizeof(node)));
        for (int i = 0; i < level; ++i)
            ::new (mem + front - sizeof(link) * static_cast<size_t>(i + 1)) link{};
        return ::new (mem + front) node{ value_type(score, std::move(member)), nullptr, level };
    }
    static void destroy(node* n)
    {
        char* mem = reinterpret_cast<char*>(n) - sizeof(link) * static_cast<size_t>(n->level);
        n->~node();
        ::operator delete(static_cast<void*>(mem));
    }

public:
    class const_iterator
    {
    public:
        using value_type        = entry;
        using reference         = entry;
        using difference_type   = std::ptrdiff_t;
        using iterator_category = std::bidirectional_iterator_tag;
        struct arrow { entry e; const entry* operator->() const { return &e; } };
        using pointer           = arrow;

        const_iterator() = default;
        explicit const_iterator(const node* p, const zskiplist* owner) : m_p(p), m_owner(owner) {}
        const_iterator(size_t i, size_t off, const zskiplist* owner) : m_owner(owner), m_i(i), m_off(off) {}

        entry operator*() const
        {
            if (m_owner->big()) return { m_p->v.first, m_p->v.second };
            return { m_owner->score_at(m_off), m_owner->member_at(m_off) };
        }
        arrow operator->() const { return { **this }; }
        const_iterator& operator++()
        {
            if (m_owner->big()) m_p = m_p->L(0).fwd;
            else { m_off = m_owner->next_off(m_off); ++m_i; }
            return *this;
        }
        const_iterator  operator++(int) { const_iterator t = *this; ++*this; return t; }
        // Decrementing end() is what `std::prev(order.end())` did, so the tail
        // has to be reachable from a null cursor; that is why the iterator
        // carries its list.
        const_iterator& operator--()
        {
            if (m_owner && !m_owner->big()) { m_off = m_owner->prev_off(m_off); --m_i; return *this; }
            m_p = m_p ? m_p->back : (m_owner ? m_owner->m_big.tail : nullptr);
            return *this;
        }
        const_iterator  operator--(int) { const_iterator t = *this; --*this; return t; }
        bool operator==(const const_iterator& o) const
        {
            return (m_owner && !m_owner->big()) ? m_i == o.m_i : m_p == o.m_p;
        }
        bool operator!=(const const_iterator& o) const { return !(*this == o); }

    private:
        const node*      m_p{nullptr};
        const zskiplist* m_owner{nullptr};
        size_t           m_i{0};     // small: position
        size_t           m_off{0};   // small: byte offset of that position
        friend class zskiplist;
    };

    using iterator = const_iterator;

    const_iterator begin() const
    {
        return big() ? const_iterator(m_big.head->L(0).fwd, this) : const_iterator(0, 0, this);
    }
    const_iterator end() const
    {
        return big() ? const_iterator(nullptr, this) : const_iterator(m_count, m_pack.size(), this);
    }
    const_iterator last() const
    {
        return big() ? const_iterator(m_big.tail, this)
                     : const_iterator(m_count - 1, prev_off(m_pack.size()), this);
    }

    size_t size()  const { return m_count; }
    bool   empty() const { return size() == 0; }

    // Back to small and empty, head and all.
    void clear()
    {
        destroy_all();
        ::new (&m_pack) pack_buf();
        m_level = 0;
        m_count = 0;
    }

    // Named emplace because that is what the seventeen call sites already say.
    void emplace(double score, std::string member) { insert(score, std::move(member)); }

    void insert(double score, std::string member)
    {
        if (!big())
        {
            if (m_count < SMALL_MAX && member.size() <= SMALL_MAX_LEN)
            {
                small_insert(small_lower(score, member).second, score, member);
                return;
            }
            promote();
        }
        insert_big(score, std::move(member));
    }

private:
    void insert_big(double score, std::string member)
    {
        node*  update[max_level];
        size_t rank[max_level];
        node*  x = m_big.head;
        for (int i = m_level - 1; i >= 0; --i)
        {
            rank[i] = (i == m_level - 1) ? 0 : rank[i + 1];
            while (x->L(i).fwd && less(x->L(i).fwd->v, score, member))
            {
                rank[i] += x->L(i).span;
                x = x->L(i).fwd;
            }
            update[i] = x;
        }

        const int lvl = random_level();
        if (lvl > m_level)
        {
            for (int i = m_level; i < lvl; ++i)
            {
                rank[i]   = 0;
                update[i] = m_big.head;
                update[i]->L(i).span = m_count;
            }
            m_level = static_cast<uint8_t>(lvl);
        }

        node* n = make_node(lvl, score, std::move(member));
        for (int i = 0; i < lvl; ++i)
        {
            n->L(i).fwd         = update[i]->L(i).fwd;
            update[i]->L(i).fwd = n;
            n->L(i).span         = update[i]->L(i).span - (rank[0] - rank[i]);
            update[i]->L(i).span = (rank[0] - rank[i]) + 1;
        }
        // Every level ABOVE the new node's still jumps one more node than it did.
        for (int i = lvl; i < m_level; ++i)
            update[i]->L(i).span++;

        n->back = (update[0] == m_big.head) ? nullptr : update[0];
        if (n->L(0).fwd) n->L(0).fwd->back = n;
        else              m_big.tail = n;
        ++m_count;
    }

public:
    size_t erase(const value_type& v) { return erase(v.first, v.second); }

    size_t erase(double score, std::string_view member)
    {
        std::string gone;
        return extract(score, member, gone) ? 1 : 0;
    }

    // erase() that hands the member's string back, so a score change moves
    // the name into its new node instead of copying it and freeing the old.
    bool extract(double score, std::string_view member, std::string& out)
    {
        if (!big())
        {
            const size_t off = small_lower(score, member).second;
            if (off == m_pack.size() || score_at(off) != score || member_at(off) != member)
                return false;
            out.assign(member_at(off));
            m_pack.erase(off, next_off(off) - off);
            --m_count;
            return true;
        }
        node* update[max_level];
        node* x = m_big.head;
        for (int i = m_level - 1; i >= 0; --i)
        {
            while (x->L(i).fwd && less(x->L(i).fwd->v, score, member))
                x = x->L(i).fwd;
            update[i] = x;
        }
        x = x->L(0).fwd;
        if (!x || x->v.first != score || x->v.second != member)
            return false;

        for (int i = 0; i < m_level; ++i)
        {
            if (update[i]->L(i).fwd == x)
            {
                update[i]->L(i).span += x->L(i).span - 1;
                update[i]->L(i).fwd   = x->L(i).fwd;
            }
            else
            {
                update[i]->L(i).span--;
            }
        }
        if (x->L(0).fwd) x->L(0).fwd->back = x->back;
        else              m_big.tail = x->back;
        while (m_level > 1 && !m_big.head->L(m_level - 1).fwd) --m_level;
        out = std::move(x->v.second);
        destroy(x);
        --m_count;
        return true;
    }

    // 0-based, and the whole point of the structure: the spans crossed on the
    // way down ARE the rank.  npos when the member is not there.
    static constexpr size_t npos = static_cast<size_t>(-1);

    size_t rank(double score, std::string_view member) const
    {
        if (!big())
        {
            const auto [i, off] = small_lower(score, member);
            if (off == m_pack.size() || score_at(off) != score || member_at(off) != member)
                return npos;
            return i;
        }
        size_t r = 0;
        const node* x = m_big.head;
        for (int i = m_level - 1; i >= 0; --i)
        {
            while (x->L(i).fwd && less_eq(x->L(i).fwd->v, score, member))
            {
                r += x->L(i).span;
                x = x->L(i).fwd;
            }
        }
        if (x != m_big.head && x->v.first == score && x->v.second == member)
            return r - 1;
        return npos;
    }

    // The node at a 0-based index, end() past the last.
    const_iterator at(size_t index) const
    {
        if (index >= size()) return end();
        if (!big())
        {
            size_t off = 0;
            for (size_t k = 0; k < index; ++k) off = next_off(off);
            return const_iterator(index, off, this);
        }
        size_t traversed = 0;
        const node* x = m_big.head;
        for (int i = m_level - 1; i >= 0; --i)
        {
            while (x->L(i).fwd && traversed + x->L(i).span <= index + 1)
            {
                traversed += x->L(i).span;
                x = x->L(i).fwd;
            }
            if (traversed == index + 1)
                return const_iterator(x, this);
        }
        return end();
    }

    // First node with a score at or past `min`, honouring exclusivity.  O(log n)
    // where the old std::set::lower_bound was, so nothing regressed here.
    const_iterator lower_bound_score(double min, bool inclusive) const
    {
        if (!big())
        {
            size_t i = 0, off = 0;
            for (; off < m_pack.size(); off = next_off(off), ++i)
            {
                const double sc = score_at(off);
                if (inclusive ? sc >= min : sc > min) break;
            }
            return const_iterator(i, off, this);
        }
        const node* x = m_big.head;
        for (int i = m_level - 1; i >= 0; --i)
        {
            while (x->L(i).fwd &&
                   (inclusive ? x->L(i).fwd->v.first <  min
                              : x->L(i).fwd->v.first <= min))
                x = x->L(i).fwd;
        }
        return const_iterator(x->L(0).fwd, this);
    }

private:
    // Ordered by score, then by member -- the same order the pair gave, and the
    // reason two members with one score stay apart and stay stable.
    static bool less(const value_type& a, double score, std::string_view member)
    {
        if (a.first != score) return a.first < score;
        return a.second < member;
    }
    static bool less_eq(const value_type& a, double score, std::string_view member)
    {
        if (a.first != score) return a.first < score;
        return a.second <= member;
    }

    // ─── The packed form: [8-byte score][length][member][length] per member,
    //     the trailing length walking back as the leading one walks forward ───

    double score_at(size_t off) const
    {
        double d;
        std::memcpy(&d, m_pack.data() + off, sizeof d);
        return d;
    }
    size_t mlen_at(size_t off) const { return static_cast<unsigned char>(m_pack[off + 8]); }
    std::string_view member_at(size_t off) const { return { m_pack.data() + off + 9, mlen_at(off) }; }
    size_t next_off(size_t off) const { return off + 10 + mlen_at(off); }
    size_t prev_off(size_t end) const { return end - 10 - static_cast<unsigned char>(m_pack[end - 1]); }

    // The first entry not ordered before (score, member): its position and
    // offset, the pack's end when there is none.
    std::pair<size_t, size_t> small_lower(double score, std::string_view member) const
    {
        size_t i = 0, off = 0;
        for (; off < m_pack.size(); off = next_off(off), ++i)
        {
            const double sc = score_at(off);
            if (sc != score ? !(sc < score) : !(member_at(off) < member)) break;
        }
        return { i, off };
    }

    void small_insert(size_t off, double score, std::string_view member)
    {
        char e[10 + SMALL_MAX_LEN];
        std::memcpy(e, &score, 8);
        e[8] = static_cast<char>(member.size());
        std::memcpy(e + 9, member.data(), member.size());
        e[9 + member.size()] = static_cast<char>(member.size());
        m_pack.insert(off, e, 10 + member.size());
        ++m_count;
    }

    // The packed members, in order, into a skiplist with a head of its own.
    void promote()
    {
        node* head = make_node(max_level, 0.0, std::string());
        pack_buf pack(std::move(m_pack));
        m_pack.~pack_buf();
        const size_t n = m_count;
        m_big.head = head;
        m_big.tail = nullptr;
        m_count = 0;
        m_level = 1;
        for (size_t off = 0, k = 0; k < n; ++k)
        {
            double sc;
            std::memcpy(&sc, pack.data() + off, 8);
            const size_t len = static_cast<unsigned char>(pack[off + 8]);
            insert_big(sc, std::string(pack.data() + off + 9, len));
            off += 10 + len;
        }
    }

    // Everything this holds, leaving neither form alive.
    void destroy_all() noexcept
    {
        if (!big()) { m_pack.~pack_buf(); return; }
        node* n = m_big.head->L(0).fwd;
        while (n) { node* next = n->L(0).fwd; destroy(n); n = next; }
        destroy(m_big.head);
    }

    // Into a zskiplist holding neither form, leaving `o` small and empty.
    void steal(zskiplist& o) noexcept
    {
        if (o.big())
        {
            m_big = o.m_big;
            ::new (&o.m_pack) pack_buf();
        }
        else
            ::new (&m_pack) pack_buf(std::move(o.m_pack));
        m_count = o.m_count; m_level = o.m_level;
        o.m_count = 0; o.m_level = 0;
    }

    int random_level()
    {
        int lvl = 1;
        while (lvl < max_level && next_random() < p_quarter) ++lvl;
        return lvl;
    }
    static uint32_t next_random()
    {
        // xorshift32, seeded fixed: the level pattern is then the same on every
        // run, so a test that fails once fails again.  One per thread rather
        // than per set, where it was four bytes of every small set.
        static thread_local uint32_t rng = 0x9E3779B9u;
        rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
        return rng;
    }

    // A small set is its pack and a big one its head and tail, never both, so
    // the two share their bytes; m_level is 0 while the set is small.
    struct big_t { node* head; node* tail; };
    union
    {
        pack_buf m_pack;
        big_t    m_big;
    };
    uint32_t m_count{0};     // members, in either form
    uint8_t  m_level{0};
};
