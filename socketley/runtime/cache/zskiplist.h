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

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

class zskiplist
{
public:
    using value_type = std::pair<double, std::string>;

    zskiplist() : m_head(make_node(max_level, 0.0, std::string())) {}
    ~zskiplist() { clear(); destroy(m_head); }

    zskiplist(const zskiplist& o) : zskiplist() { for (auto it = o.begin(); it != o.end(); ++it) insert(it->first, it->second); }
    zskiplist& operator=(const zskiplist& o)
    {
        if (this != &o) { clear(); for (auto it = o.begin(); it != o.end(); ++it) insert(it->first, it->second); }
        return *this;
    }
    zskiplist(zskiplist&& o) noexcept
        : m_head(o.m_head), m_tail(o.m_tail), m_len(o.m_len), m_level(o.m_level), m_rng(o.m_rng)
    {
        o.m_head = make_node(max_level, 0.0, std::string());
        o.m_tail = nullptr; o.m_len = 0; o.m_level = 1;
    }
    zskiplist& operator=(zskiplist&& o) noexcept
    {
        if (this != &o)
        {
            clear(); destroy(m_head);
            m_head = o.m_head; m_tail = o.m_tail; m_len = o.m_len; m_level = o.m_level; m_rng = o.m_rng;
            o.m_head = make_node(max_level, 0.0, std::string());
            o.m_tail = nullptr; o.m_len = 0; o.m_level = 1;
        }
        return *this;
    }

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
    struct node
    {
        value_type            v;
        node*                 back{nullptr};
        int                   level{1};
        std::unique_ptr<link[]> lv;
    };

    static node* make_node(int level, double score, std::string member)
    {
        node* n = new node;
        n->v = value_type(score, std::move(member));
        n->level = level;
        n->lv = std::make_unique<link[]>(static_cast<size_t>(level));
        return n;
    }
    static void destroy(node* n) { delete n; }

public:
    class const_iterator
    {
    public:
        using value_type        = zskiplist::value_type;
        using reference         = const value_type&;
        using pointer           = const value_type*;
        using difference_type   = std::ptrdiff_t;
        using iterator_category = std::bidirectional_iterator_tag;

        const_iterator() = default;
        explicit const_iterator(const node* p, const zskiplist* owner) : m_p(p), m_owner(owner) {}

        reference operator*()  const { return m_p->v; }
        pointer   operator->() const { return &m_p->v; }
        const_iterator& operator++() { m_p = m_p->lv[0].fwd; return *this; }
        const_iterator  operator++(int) { const_iterator t = *this; ++*this; return t; }
        // Decrementing end() is what `std::prev(order.end())` did, so the tail
        // has to be reachable from a null cursor; that is why the iterator
        // carries its list.
        const_iterator& operator--()
        {
            m_p = m_p ? m_p->back : (m_owner ? m_owner->m_tail : nullptr);
            return *this;
        }
        const_iterator  operator--(int) { const_iterator t = *this; --*this; return t; }
        bool operator==(const const_iterator& o) const { return m_p == o.m_p; }
        bool operator!=(const const_iterator& o) const { return m_p != o.m_p; }

    private:
        const node*      m_p{nullptr};
        const zskiplist* m_owner{nullptr};
        friend class zskiplist;
    };

    using iterator = const_iterator;

    const_iterator begin() const { return const_iterator(m_head->lv[0].fwd, this); }
    const_iterator end()   const { return const_iterator(nullptr, this); }
    const_iterator last()  const { return const_iterator(m_tail, this); }

    size_t size()  const { return m_len; }
    bool   empty() const { return m_len == 0; }

    void clear()
    {
        node* n = m_head->lv[0].fwd;
        while (n) { node* next = n->lv[0].fwd; destroy(n); n = next; }
        for (int i = 0; i < max_level; ++i) { m_head->lv[i].fwd = nullptr; m_head->lv[i].span = 0; }
        m_tail = nullptr; m_len = 0; m_level = 1;
    }

    // Named emplace because that is what the seventeen call sites already say.
    void emplace(double score, std::string member) { insert(score, std::move(member)); }

    void insert(double score, std::string member)
    {
        node*  update[max_level];
        size_t rank[max_level];
        node*  x = m_head;
        for (int i = m_level - 1; i >= 0; --i)
        {
            rank[i] = (i == m_level - 1) ? 0 : rank[i + 1];
            while (x->lv[i].fwd && less(x->lv[i].fwd->v, score, member))
            {
                rank[i] += x->lv[i].span;
                x = x->lv[i].fwd;
            }
            update[i] = x;
        }

        const int lvl = random_level();
        if (lvl > m_level)
        {
            for (int i = m_level; i < lvl; ++i)
            {
                rank[i]   = 0;
                update[i] = m_head;
                update[i]->lv[i].span = m_len;
            }
            m_level = lvl;
        }

        node* n = make_node(lvl, score, std::move(member));
        for (int i = 0; i < lvl; ++i)
        {
            n->lv[i].fwd         = update[i]->lv[i].fwd;
            update[i]->lv[i].fwd = n;
            n->lv[i].span         = update[i]->lv[i].span - (rank[0] - rank[i]);
            update[i]->lv[i].span = (rank[0] - rank[i]) + 1;
        }
        // Every level ABOVE the new node's still jumps one more node than it did.
        for (int i = lvl; i < m_level; ++i)
            update[i]->lv[i].span++;

        n->back = (update[0] == m_head) ? nullptr : update[0];
        if (n->lv[0].fwd) n->lv[0].fwd->back = n;
        else              m_tail = n;
        ++m_len;
    }

    size_t erase(const value_type& v) { return erase(v.first, v.second); }

    size_t erase(double score, const std::string& member)
    {
        node* update[max_level];
        node* x = m_head;
        for (int i = m_level - 1; i >= 0; --i)
        {
            while (x->lv[i].fwd && less(x->lv[i].fwd->v, score, member))
                x = x->lv[i].fwd;
            update[i] = x;
        }
        x = x->lv[0].fwd;
        if (!x || x->v.first != score || x->v.second != member)
            return 0;

        for (int i = 0; i < m_level; ++i)
        {
            if (update[i]->lv[i].fwd == x)
            {
                update[i]->lv[i].span += x->lv[i].span - 1;
                update[i]->lv[i].fwd   = x->lv[i].fwd;
            }
            else
            {
                update[i]->lv[i].span--;
            }
        }
        if (x->lv[0].fwd) x->lv[0].fwd->back = x->back;
        else              m_tail = x->back;
        while (m_level > 1 && !m_head->lv[m_level - 1].fwd) --m_level;
        destroy(x);
        --m_len;
        return 1;
    }

    // 0-based, and the whole point of the structure: the spans crossed on the
    // way down ARE the rank.  npos when the member is not there.
    static constexpr size_t npos = static_cast<size_t>(-1);

    size_t rank(double score, const std::string& member) const
    {
        size_t r = 0;
        const node* x = m_head;
        for (int i = m_level - 1; i >= 0; --i)
        {
            while (x->lv[i].fwd && less_eq(x->lv[i].fwd->v, score, member))
            {
                r += x->lv[i].span;
                x = x->lv[i].fwd;
            }
        }
        if (x != m_head && x->v.first == score && x->v.second == member)
            return r - 1;
        return npos;
    }

    // The node at a 0-based index, end() past the last.
    const_iterator at(size_t index) const
    {
        if (index >= m_len) return end();
        size_t traversed = 0;
        const node* x = m_head;
        for (int i = m_level - 1; i >= 0; --i)
        {
            while (x->lv[i].fwd && traversed + x->lv[i].span <= index + 1)
            {
                traversed += x->lv[i].span;
                x = x->lv[i].fwd;
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
        const node* x = m_head;
        for (int i = m_level - 1; i >= 0; --i)
        {
            while (x->lv[i].fwd &&
                   (inclusive ? x->lv[i].fwd->v.first <  min
                              : x->lv[i].fwd->v.first <= min))
                x = x->lv[i].fwd;
        }
        return const_iterator(x->lv[0].fwd, this);
    }

private:
    // Ordered by score, then by member -- the same order the pair gave, and the
    // reason two members with one score stay apart and stay stable.
    static bool less(const value_type& a, double score, const std::string& member)
    {
        if (a.first != score) return a.first < score;
        return a.second < member;
    }
    static bool less_eq(const value_type& a, double score, const std::string& member)
    {
        if (a.first != score) return a.first < score;
        return a.second <= member;
    }

    int random_level()
    {
        int lvl = 1;
        while (lvl < max_level && next_random() < p_quarter) ++lvl;
        return lvl;
    }
    uint32_t next_random()
    {
        // xorshift32, seeded fixed: the level pattern is then the same on every
        // run, so a test that fails once fails again.
        m_rng ^= m_rng << 13; m_rng ^= m_rng >> 17; m_rng ^= m_rng << 5;
        return m_rng;
    }

    node*    m_head{nullptr};
    node*    m_tail{nullptr};
    size_t   m_len{0};
    int      m_level{1};
    uint32_t m_rng{0x9E3779B9u};
};
