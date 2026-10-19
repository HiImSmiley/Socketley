#pragma once
// Who a topic reaches: the subscriptions in a tree of topic levels, with '+' and '#' as levels of their own, so a
// publish walks the tree once whatever the number of subscribers; and the retained messages in a second tree that a
// new subscription's filter is walked over.
#include <cstddef>
#include <cstdint>
#include <functional>
#include <array>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "../../shared/util/transparent_string.h"

namespace socketley::mqtt
{

// The levels of a topic or filter, as views into it.
std::vector<std::string_view> split_levels(std::string_view s);

// A topic's levels where a publish needs them, held on the stack for a topic of up to 32 of them.
class topic_levels
{
public:
    explicit topic_levels(std::string_view topic);
    std::span<const std::string_view> view() const
    {
        return m_many.empty() ? std::span<const std::string_view>(m_few.data(), m_count)
                              : std::span<const std::string_view>(m_many);
    }

private:
    std::array<std::string_view, 32> m_few{};
    size_t m_count{0};
    std::vector<std::string_view> m_many;
};

// A subscription's options as the tree keeps them.
struct sub_options
{
    uint8_t  qos{0};
    bool     no_local{false};
    bool     retain_as_published{false};
    uint8_t  retain_handling{0};
    uint32_t subscription_id{0};
};

// Subscriptions by session. A session holds at most one subscription per filter; a shared one is held under its
// group, and a publish reaches one member of each group whose filter matches.
class subscription_tree
{
public:
    subscription_tree();
    ~subscription_tree();
    subscription_tree(const subscription_tree&)            = delete;
    subscription_tree& operator=(const subscription_tree&) = delete;

    // True when the session had no subscription to this filter (in this group) before.
    bool add(std::string_view filter, std::string_view group, uint64_t session, const sub_options& o);
    // True when there was one to remove.
    bool remove(std::string_view filter, std::string_view group, uint64_t session);

    // Each plain subscription a topic matches, and one member of each shared group chosen round the members, the
    // group named by its $share/<group>/<filter>. `online` says which sessions have a connection, which a shared
    // group prefers.
    void match(std::string_view topic,
               const std::function<void(uint64_t session, const sub_options&)>& plain,
               const std::function<void(std::string_view group, uint64_t session, const sub_options&)>& shared,
               const std::function<bool(uint64_t session)>& online = {});

    // Whether anything at all matches, for a peer that only needs to know whether to send.
    bool any_match(std::string_view topic) const;

    // Subscriptions held, plain and shared alike.
    size_t size() const { return m_count; }

private:
    struct member
    {
        uint64_t    session{0};
        sub_options opts;
    };
    struct group_set
    {
        std::vector<member> members;
        size_t              next{0};
        // The shared filter as subscribed, $share/<group>/<filter>, which names the group across shards.
        std::string         key;
    };
    struct node
    {
        // The literal levels below, looked up by a topic's level without a string built for it.
        std::unordered_map<std::string, std::unique_ptr<node>, string_hash, std::equal_to<>> children;
        // The wildcards' levels apart, since every topic asks after both at every level.
        std::unique_ptr<node> plus;
        std::unique_ptr<node> hash;
        std::vector<member> plain;
        std::unordered_map<std::string, group_set> groups;
        bool empty() const { return children.empty() && !plus && !hash && plain.empty() && groups.empty(); }
    };

    // The slot a filter's level lives in below `n`, made when `make`; null when there is none.
    static std::unique_ptr<node>* child(node& n, std::string_view level, bool make);
    node* find_or_make(std::string_view filter);
    void collect(node& n, std::span<const std::string_view> levels, size_t i, bool root_dollar,
                 const std::function<void(uint64_t, const sub_options&)>& plain,
                 const std::function<void(std::string_view, uint64_t, const sub_options&)>& shared,
                 const std::function<bool(uint64_t)>& online);
    static bool any_at(const node& n, std::span<const std::string_view> levels, size_t i, bool root_dollar);
    static void take(node& n, const std::function<void(uint64_t, const sub_options&)>& plain,
                     const std::function<void(std::string_view, uint64_t, const sub_options&)>& shared,
                     const std::function<bool(uint64_t)>& online);

    std::unique_ptr<node> m_root;
    size_t m_count{0};
};

// The retained messages by topic, each an opaque value the broker owns; a filter finds those it matches.
template <class V>
class retained_tree
{
public:
    // Replaces or, given an empty value, removes; the bytes the store held before and after are tracked by the
    // caller.
    void set(std::string_view topic, std::shared_ptr<V> v)
    {
        const auto levels = split_levels(topic);
        if (!v)
        {
            erase(m_root, levels, 0);
            return;
        }
        node* n = &m_root;
        for (const auto l : levels)
        {
            auto& c = n->children[std::string(l)];
            if (!c)
                c = std::make_unique<node>();
            n = c.get();
        }
        if (!n->value)
            ++m_count;
        n->value = std::move(v);
    }

    std::shared_ptr<V> get(std::string_view topic) const
    {
        const node* n = &m_root;
        for (const auto l : split_levels(topic))
        {
            const auto it = n->children.find(std::string(l));
            if (it == n->children.end())
                return nullptr;
            n = it->second.get();
        }
        return n->value;
    }

    // Every retained message a filter matches; topics starting with '$' only for a filter that names that level.
    void match(std::string_view filter, const std::function<void(const std::shared_ptr<V>&)>& f) const
    {
        walk(m_root, split_levels(filter), 0, f);
    }

    // Every retained message, for a snapshot and a listing.
    void each(const std::function<void(const std::shared_ptr<V>&)>& f) const { all(m_root, f, false, true); }

    size_t size() const { return m_count; }

private:
    struct node
    {
        std::unordered_map<std::string, std::unique_ptr<node>> children;
        std::shared_ptr<V> value;
    };

    bool erase(node& n, const std::vector<std::string_view>& levels, size_t i)
    {
        if (i == levels.size())
        {
            if (n.value)
            {
                n.value.reset();
                --m_count;
            }
            return n.children.empty();
        }
        const auto it = n.children.find(std::string(levels[i]));
        if (it == n.children.end())
            return false;
        if (erase(*it->second, levels, i + 1) && !it->second->value)
            n.children.erase(it);
        return n.children.empty() && !n.value;
    }

    // Everything at and below `n`, the '$' topics of the root level left out unless asked.
    static void all(const node& n, const std::function<void(const std::shared_ptr<V>&)>& f, bool root_skip_dollar,
                    bool is_root)
    {
        if (n.value)
            f(n.value);
        for (const auto& [k, c] : n.children)
        {
            if (is_root && root_skip_dollar && !k.empty() && k.front() == '$')
                continue;
            all(*c, f, false, false);
        }
    }

    static void walk(const node& n, const std::vector<std::string_view>& levels, size_t i,
                     const std::function<void(const std::shared_ptr<V>&)>& f)
    {
        if (i == levels.size())
        {
            if (n.value)
                f(n.value);
            return;
        }
        const bool root = i == 0;
        const std::string_view l = levels[i];
        if (l == "#")
        {
            // "a/#" matches "a" as well as everything below it.
            if (!root && n.value)
                f(n.value);
            for (const auto& [k, c] : n.children)
            {
                if (root && !k.empty() && k.front() == '$')
                    continue;
                all(*c, f, false, false);
            }
            return;
        }
        if (l == "+")
        {
            for (const auto& [k, c] : n.children)
            {
                if (root && !k.empty() && k.front() == '$')
                    continue;
                walk(*c, levels, i + 1, f);
            }
            return;
        }
        const auto it = n.children.find(std::string(l));
        if (it != n.children.end())
            walk(*it->second, levels, i + 1, f);
    }

    node   m_root;
    size_t m_count{0};
};

}   // namespace socketley::mqtt
