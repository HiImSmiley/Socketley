#include "mqtt_topics.h"

#include <algorithm>

namespace socketley::mqtt
{

std::vector<std::string_view> split_levels(std::string_view s)
{
    std::vector<std::string_view> out;
    size_t start = 0;
    while (true)
    {
        const size_t slash = s.find('/', start);
        if (slash == std::string_view::npos)
        {
            out.push_back(s.substr(start));
            return out;
        }
        out.push_back(s.substr(start, slash - start));
        start = slash + 1;
    }
}

subscription_tree::subscription_tree() : m_root(std::make_unique<node>()) {}
subscription_tree::~subscription_tree() = default;

subscription_tree::node* subscription_tree::find_or_make(std::string_view filter)
{
    node* n = m_root.get();
    for (const auto l : split_levels(filter))
    {
        auto& c = n->children[std::string(l)];
        if (!c)
            c = std::make_unique<node>();
        n = c.get();
    }
    return n;
}

bool subscription_tree::add(std::string_view filter, std::string_view group, uint64_t session, const sub_options& o)
{
    node* n = find_or_make(filter);
    if (!group.empty())
    {
        group_set& g = n->groups[std::string(group)];
        if (g.key.empty())
            g.key = "$share/" + std::string(group) + "/" + std::string(filter);
    }
    std::vector<member>& list = group.empty() ? n->plain : n->groups[std::string(group)].members;
    for (auto& m : list)
        if (m.session == session)
        {
            m.opts = o;
            return false;
        }
    list.push_back({session, o});
    ++m_count;
    return true;
}

bool subscription_tree::remove(std::string_view filter, std::string_view group, uint64_t session)
{
    const auto levels = split_levels(filter);
    std::vector<node*> path{m_root.get()};
    for (const auto l : levels)
    {
        const auto it = path.back()->children.find(std::string(l));
        if (it == path.back()->children.end())
            return false;
        path.push_back(it->second.get());
    }
    node* n = path.back();
    bool removed = false;
    if (group.empty())
    {
        const auto it = std::find_if(n->plain.begin(), n->plain.end(),
                                     [&](const member& m) { return m.session == session; });
        if (it != n->plain.end())
        {
            n->plain.erase(it);
            removed = true;
        }
    }
    else if (const auto g = n->groups.find(std::string(group)); g != n->groups.end())
    {
        auto& ms = g->second.members;
        const auto it = std::find_if(ms.begin(), ms.end(), [&](const member& m) { return m.session == session; });
        if (it != ms.end())
        {
            ms.erase(it);
            removed = true;
            if (ms.empty())
                n->groups.erase(g);
            else if (g->second.next >= ms.size())
                g->second.next = 0;
        }
    }
    if (!removed)
        return false;
    --m_count;
    // Empty levels go, deepest first, so a tree never keeps the shape of subscriptions long gone.
    for (size_t i = path.size() - 1; i > 0 && path[i]->empty(); --i)
        path[i - 1]->children.erase(std::string(levels[i - 1]));
    return true;
}

void subscription_tree::take(node& n, const std::function<void(uint64_t, const sub_options&)>& plain,
                             const std::function<void(std::string_view, uint64_t, const sub_options&)>& shared,
                             const std::function<bool(uint64_t)>& online)
{
    for (const auto& m : n.plain)
        plain(m.session, m.opts);
    for (auto& [name, g] : n.groups)
    {
        (void)name;
        const size_t count = g.members.size();
        if (count == 0)
            continue;
        if (g.next >= count)
            g.next = 0;
        // The next member round the group that has a connection, or the next one at all when none has.
        size_t pick = g.next;
        if (online)
            for (size_t k = 0; k < count; ++k)
                if (const size_t at = (g.next + k) % count; online(g.members[at].session))
                {
                    pick = at;
                    break;
                }
        g.next = (pick + 1) % count;
        const member& m = g.members[pick];
        shared(g.key, m.session, m.opts);
    }
}

void subscription_tree::collect(node& n, const std::vector<std::string_view>& levels, size_t i, bool root_dollar,
                                const std::function<void(uint64_t, const sub_options&)>& plain,
                                const std::function<void(std::string_view, uint64_t, const sub_options&)>& shared,
                                const std::function<bool(uint64_t)>& online)
{
    // A wildcard at the first level does not reach a topic starting with '$'.
    const bool wild_ok = !(i == 0 && root_dollar);
    if (wild_ok)
        if (const auto h = n.children.find("#"); h != n.children.end())
            take(*h->second, plain, shared, online);
    if (i == levels.size())
    {
        take(n, plain, shared, online);
        return;
    }
    if (const auto c = n.children.find(std::string(levels[i])); c != n.children.end())
        collect(*c->second, levels, i + 1, root_dollar, plain, shared, online);
    if (wild_ok)
        if (const auto p = n.children.find("+"); p != n.children.end())
            collect(*p->second, levels, i + 1, root_dollar, plain, shared, online);
}

void subscription_tree::match(std::string_view topic,
                              const std::function<void(uint64_t session, const sub_options&)>& plain,
                              const std::function<void(std::string_view, uint64_t, const sub_options&)>& shared,
                              const std::function<bool(uint64_t)>& online)
{
    const auto levels = split_levels(topic);
    collect(*m_root, levels, 0, !topic.empty() && topic.front() == '$', plain, shared, online);
}

bool subscription_tree::any_at(const node& n, const std::vector<std::string_view>& levels, size_t i,
                               bool root_dollar)
{
    const bool wild_ok = !(i == 0 && root_dollar);
    if (wild_ok)
        if (const auto h = n.children.find("#"); h != n.children.end() && !h->second->plain.empty())
            return true;
    if (wild_ok)
        if (const auto h = n.children.find("#"); h != n.children.end() && !h->second->groups.empty())
            return true;
    if (i == levels.size())
        return !n.plain.empty() || !n.groups.empty();
    if (const auto c = n.children.find(std::string(levels[i])); c != n.children.end() &&
                                                                  any_at(*c->second, levels, i + 1, root_dollar))
        return true;
    if (wild_ok)
        if (const auto p = n.children.find("+"); p != n.children.end() && any_at(*p->second, levels, i + 1, root_dollar))
            return true;
    return false;
}

bool subscription_tree::any_match(std::string_view topic) const
{
    return any_at(*m_root, split_levels(topic), 0, !topic.empty() && topic.front() == '$');
}

}   // namespace socketley::mqtt
