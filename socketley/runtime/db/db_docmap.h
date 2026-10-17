#pragma once
// A collection's documents by id. Each one is a node of its own, which keeps its place for as long as it lives, found
// through a flat table of (hash, node) probed in order: a lookup reads the table's line and the node's, where an
// unordered_map reads a bucket, the node before the bucket's first, and the node.
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "../../shared/transparent_string.h"

namespace socketley::db
{

template <class Doc>
class doc_map
{
public:
    using value_type = std::pair<const std::string, Doc>;

private:
    struct slot
    {
        uint64_t hash{0};
        value_type* node{nullptr};
    };

public:
    template <bool Const>
    class basic_iterator
    {
    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type = doc_map::value_type;
        using difference_type = std::ptrdiff_t;
        using pointer = std::conditional_t<Const, const value_type*, value_type*>;
        using reference = std::conditional_t<Const, const value_type&, value_type&>;

        basic_iterator() = default;
        basic_iterator(const slot* at, const slot* end) : m_at(at), m_end(end) { skip(); }
        template <bool C = Const, class = std::enable_if_t<C>>
        basic_iterator(const basic_iterator<false>& o) : m_at(o.m_at), m_end(o.m_end)
        {
        }

        reference operator*() const { return *m_at->node; }
        pointer operator->() const { return m_at->node; }
        basic_iterator& operator++()
        {
            ++m_at;
            skip();
            return *this;
        }
        basic_iterator operator++(int)
        {
            basic_iterator t = *this;
            ++*this;
            return t;
        }
        template <bool C>
        bool operator==(const basic_iterator<C>& o) const
        {
            return m_at == o.m_at;
        }

    private:
        friend class doc_map;
        template <bool>
        friend class basic_iterator;
        void skip()
        {
            while (m_at != m_end && !m_at->node)
                ++m_at;
        }
        const slot* m_at{nullptr};
        const slot* m_end{nullptr};
    };
    using iterator = basic_iterator<false>;
    using const_iterator = basic_iterator<true>;

    doc_map() = default;
    doc_map(const doc_map&) = delete;
    doc_map& operator=(const doc_map&) = delete;
    doc_map(doc_map&& o) noexcept : m_tab(std::move(o.m_tab)), m_size(o.m_size) { o.m_size = 0; }
    doc_map& operator=(doc_map&& o) noexcept
    {
        if (this != &o)
        {
            clear();
            m_tab = std::move(o.m_tab);
            m_size = o.m_size;
            o.m_size = 0;
        }
        return *this;
    }
    ~doc_map() { clear(); }

    size_t size() const { return m_size; }
    bool empty() const { return m_size == 0; }

    iterator begin() { return iterator(data(), data() + m_tab.size()); }
    iterator end() { return iterator(data() + m_tab.size(), data() + m_tab.size()); }
    const_iterator begin() const { return const_iterator(data(), data() + m_tab.size()); }
    const_iterator end() const { return const_iterator(data() + m_tab.size(), data() + m_tab.size()); }

    iterator find(std::string_view id) { return at(index_of(id)); }
    const_iterator find(std::string_view id) const { return const_cast<doc_map*>(this)->find(id); }
    bool contains(std::string_view id) const { return index_of(id) != npos; }

    void reserve(size_t n)
    {
        size_t cap = 16;
        while (cap * 3 < n * 4)
            cap *= 2;
        if (cap > m_tab.size())
            grow(cap);
    }

    // The document `id` made from `d` unless one is there; the one there and whether it was made.
    std::pair<iterator, bool> emplace(const std::string& id, Doc d)
    {
        if (const size_t i = index_of(id); i != npos)
            return {at(i), false};
        if ((m_size + 1) * 4 > m_tab.size() * 3)
            grow(m_tab.empty() ? 16 : m_tab.size() * 2);
        const uint64_t h = string_hash{}(id);
        auto node = std::make_unique<value_type>(id, std::move(d));
        const size_t i = place(h, node.get());
        node.release();
        ++m_size;
        return {at(i), true};
    }

    void erase(iterator it)
    {
        size_t i = static_cast<size_t>(it.m_at - data());
        delete m_tab[i].node;
        m_tab[i] = slot{};
        --m_size;
        // The ones after it in its run move back, so a probe never stops at the hole it left.
        const size_t mask = m_tab.size() - 1;
        for (size_t j = (i + 1) & mask; m_tab[j].node; j = (j + 1) & mask)
        {
            const size_t home = m_tab[j].hash & mask;
            // j stays when its home lies cyclically in (i, j].
            if (i <= j ? (i < home && home <= j) : (i < home || home <= j))
                continue;
            m_tab[i] = m_tab[j];
            m_tab[j] = slot{};
            i = j;
        }
    }

    void clear()
    {
        for (auto& s : m_tab)
            delete s.node;
        m_tab.clear();
        m_size = 0;
    }

private:
    static constexpr size_t npos = static_cast<size_t>(-1);

    const slot* data() const { return m_tab.data(); }
    iterator at(size_t i)
    {
        return i == npos ? end() : iterator(data() + i, data() + m_tab.size());
    }

    size_t index_of(std::string_view id) const
    {
        if (m_tab.empty())
            return npos;
        const uint64_t h = string_hash{}(id);
        const size_t mask = m_tab.size() - 1;
        for (size_t i = h & mask;; i = (i + 1) & mask)
        {
            const slot& s = m_tab[i];
            if (!s.node)
                return npos;
            if (s.hash == h && s.node->first == id)
                return i;
        }
    }

    size_t place(uint64_t h, value_type* node)
    {
        const size_t mask = m_tab.size() - 1;
        size_t i = h & mask;
        while (m_tab[i].node)
            i = (i + 1) & mask;
        m_tab[i] = slot{h, node};
        return i;
    }

    void grow(size_t cap)
    {
        std::vector<slot> old = std::move(m_tab);
        m_tab.assign(cap, slot{});
        for (const auto& s : old)
            if (s.node)
                place(s.hash, s.node);
    }

    std::vector<slot> m_tab;
    size_t m_size{0};
};

}   // namespace socketley::db
