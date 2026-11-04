#include "metrics_index.h"

#include <algorithm>
#include <cctype>
#include <numeric>

#include "../../shared/util/keyed_hash.h"
#include "metrics_regex.h"

namespace socketley::metrics
{

namespace
{

uint64_t mix64(uint64_t x)
{
    x += 0x9e3779b97f4a7c15ull;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
    return x ^ (x >> 31);
}

bool label_less(const label& a, const label& b) { return a.name < b.name; }

bool is_meta(char c)
{
    switch (c)
    {
        case '.': case '+': case '*': case '?': case '(': case ')': case '[': case ']':
        case '{': case '}': case '|': case '^': case '$': case '\\':
            return true;
        default:
            return false;
    }
}

// The alternatives of `p` when each one is a literal, unescaped into `out`.
bool literal_alternatives(std::string_view p, std::vector<std::string>& out)
{
    if (p.starts_with("(?:") && p.ends_with(")"))
        p = p.substr(3, p.size() - 4);
    else if (p.starts_with("(") && p.ends_with(")"))
        p = p.substr(1, p.size() - 2);
    out.assign(1, std::string());
    for (size_t i = 0; i < p.size(); ++i)
    {
        const char c = p[i];
        if (c == '|')
            out.emplace_back();
        else if (c == '\\' && i + 1 < p.size() && std::ispunct(static_cast<unsigned char>(p[i + 1])))
            out.back() += p[++i];
        else if (is_meta(c))
            return false;
        else
            out.back() += c;
    }
    return true;
}

// Every id of any of `lists`, ascending and once, in `out`.
void union_of(const std::vector<const std::vector<uint32_t>*>& lists, uint32_t universe, std::vector<uint32_t>& out)
{
    out.clear();
    if (lists.size() == 1)
    {
        out = *lists[0];
        return;
    }
    size_t total = 0;
    for (const auto* l : lists)
        total += l->size();
    if (lists.size() <= 4 || total < universe / 16)
    {
        out.reserve(total);
        for (const auto* l : lists)
            out.insert(out.end(), l->begin(), l->end());
        std::sort(out.begin(), out.end());
        out.erase(std::unique(out.begin(), out.end()), out.end());
        return;
    }
    std::vector<uint64_t> bits((size_t(universe) + 63) / 64, 0);
    for (const auto* l : lists)
        for (uint32_t id : *l)
            bits[id >> 6] |= uint64_t(1) << (id & 63);
    out.reserve(total);
    for (size_t w = 0; w < bits.size(); ++w)
        for (uint64_t b = bits[w]; b; b &= b - 1)
            out.push_back(static_cast<uint32_t>(w * 64 + static_cast<size_t>(std::countr_zero(b))));
}

}   // namespace

bool is_normal(const label_set& ls)
{
    for (size_t i = 0; i < ls.size(); ++i)
        if (ls[i].value.empty() || (i > 0 && !(ls[i - 1].name < ls[i].name)))
            return false;
    return true;
}

bool normalize(const label_set& in, label_set& out)
{
    out.clear();
    for (const label& l : in)
        if (!l.value.empty())
            out.push_back(l);
    std::stable_sort(out.begin(), out.end(), label_less);
    for (size_t i = 1; i < out.size(); ++i)
        if (out[i - 1].name == out[i].name)
            return false;
    return true;
}

void flat_slots::place(uint32_t tag, uint32_t v)
{
    const size_t mask = m_s.size() - 1;
    size_t i = tag & mask;
    while (m_s[i] != 0)
        i = (i + 1) & mask;
    m_s[i] = (uint64_t(tag) << 32) | (uint64_t(v) + 1);
}

void flat_slots::insert(uint64_t h, uint32_t v)
{
    if ((m_used + 1) * 4 > m_s.size() * 3)
    {
        std::vector<uint64_t> old;
        old.swap(m_s);
        m_s.assign(old.empty() ? 16 : old.size() * 2, 0);
        for (uint64_t s : old)
            if (s != 0)
                place(static_cast<uint32_t>(s >> 32), static_cast<uint32_t>(s) - 1);
    }
    place(static_cast<uint32_t>(h >> 32), v);
    ++m_used;
}

// ── compiled matchers ──────────────────────────────────────────────────────

struct series_index::compiled
{
    enum class kind : uint8_t { literals, any, nonempty, general, invalid };

    std::string pattern;
    kind k{kind::invalid};
    std::vector<std::string> lits;
    metrics::regex re;

    explicit compiled(std::string_view p) : pattern(p)
    {
        std::string why;
        if (p == ".*")
            k = kind::any;
        else if (p == ".+")
            k = kind::nonempty;
        else if (literal_alternatives(p, lits))
            k = kind::literals;
        else if (re.compile(p, why))
            k = kind::general;
    }

    bool accepts(std::string_view v) const
    {
        switch (k)
        {
            case kind::any: return true;
            case kind::nonempty: return !v.empty();
            case kind::literals: return std::find(lits.begin(), lits.end(), v) != lits.end();
            case kind::invalid: return false;
            case kind::general: break;
        }
        return re.matches(v);
    }
};

series_index::series_index()
{
    m_sym_off.push_back(0);
    m_ser_off.push_back(0);
}

series_index::~series_index() = default;

const series_index::compiled& series_index::compiled_for(std::string_view pattern) const
{
    for (const auto& c : m_regexes)
        if (c->pattern == pattern)
            return *c;
    // A few dozen kept, since a dashboard asks the same few selectors again on every refresh.
    constexpr size_t keep = 32;
    auto c = std::make_unique<compiled>(pattern);
    if (m_regexes.size() < keep)
    {
        m_regexes.push_back(std::move(c));
        return *m_regexes.back();
    }
    auto& slot = m_regexes[m_regex_next++ % keep];
    slot = std::move(c);
    return *slot;
}

uint32_t series_index::find_symbol(std::string_view s) const
{
    return m_sym_table.find(keyed_hash(s), [&](uint32_t i) { return symbol(i) == s; });
}

uint32_t series_index::intern(std::string_view s)
{
    const uint64_t h = keyed_hash(s);
    const uint32_t found = m_sym_table.find(h, [&](uint32_t i) { return symbol(i) == s; });
    if (found != flat_slots::none)
        return found;
    const auto id = static_cast<uint32_t>(m_sym_off.size() - 1);
    m_sym_bytes.append(s);
    m_sym_off.push_back(static_cast<uint32_t>(m_sym_bytes.size()));
    m_name_of_sym.push_back(0);
    m_sym_table.insert(h, id);
    return id;
}

uint64_t series_index::key_hash(const label_set& ls) const
{
    m_key.clear();
    for (const label& l : ls)
    {
        const auto put = [&](const std::string& s) {
            const auto n = static_cast<uint32_t>(s.size());
            m_key.append(reinterpret_cast<const char*>(&n), sizeof n);
            m_key.append(s);
        };
        put(l.name);
        put(l.value);
    }
    return keyed_hash(m_key);
}

uint32_t series_index::find(const label_set& ls) const
{
    return m_ser_table.find(key_hash(ls), [&](uint32_t id) {
        const uint32_t b = m_ser_off[id], e = m_ser_off[id + 1];
        if ((e - b) / 2 != ls.size())
            return false;
        for (size_t i = 0; i < ls.size(); ++i)
            if (symbol(m_pairs[b + 2 * i]) != ls[i].name || symbol(m_pairs[b + 2 * i + 1]) != ls[i].value)
                return false;
        return true;
    });
}

uint32_t series_index::posting_of(uint32_t name, uint32_t value) const
{
    return m_pair_table.find(mix64((uint64_t(name) << 32) | value), [&](uint32_t p) {
        return m_postings[p].name == name && m_postings[p].value == value;
    });
}

uint32_t series_index::add(const label_set& ls)
{
    const uint32_t id = size();
    for (const label& l : ls)
    {
        const uint32_t ns = intern(l.name);
        const uint32_t vs = intern(l.value);
        m_pairs.push_back(ns);
        m_pairs.push_back(vs);
        uint32_t p = posting_of(ns, vs);
        if (p == flat_slots::none)
        {
            p = static_cast<uint32_t>(m_postings.size());
            m_postings.push_back(posting{ns, vs, {}});
            m_pair_table.insert(mix64((uint64_t(ns) << 32) | vs), p);
            if (m_name_of_sym[ns] == 0)
            {
                m_names.push_back(name_entry{ns, {}});
                m_name_of_sym[ns] = static_cast<uint32_t>(m_names.size());
            }
            m_names[m_name_of_sym[ns] - 1].postings.push_back(p);
        }
        m_postings[p].ids.push_back(id);
    }
    m_ser_off.push_back(static_cast<uint32_t>(m_pairs.size()));
    m_ser_table.insert(key_hash(ls), id);
    return id;
}

void series_index::copy_labels(uint32_t id, label_set& out) const
{
    // Into the strings `out` already has, so a buffer reused for every series of a query allocates once.
    out.resize((m_ser_off[id + 1] - m_ser_off[id]) / 2);
    size_t i = 0;
    each_label(id, [&](std::string_view n, std::string_view v) {
        out[i].name.assign(n);
        out[i++].value.assign(v);
    });
}

void series_index::forget_labels()
{
    std::vector<std::unique_ptr<label_set>>().swap(m_label_cache);
    m_label_cache_bytes = 0;
}

const label_set& series_index::labels(uint32_t id) const
{
    if (m_label_cache.size() <= id)
        m_label_cache.resize(size_t(id) + 1);
    auto& slot = m_label_cache[id];
    if (!slot)
    {
        slot = std::make_unique<label_set>();
        copy_labels(id, *slot);
        m_label_cache_bytes += sizeof(label_set) + slot->capacity() * sizeof(label);
        for (const auto& x : *slot)
            m_label_cache_bytes += (x.name.capacity() > 15 ? x.name.capacity() : 0) +
                                   (x.value.capacity() > 15 ? x.value.capacity() : 0);
    }
    return *slot;
}

const series_index::name_entry* series_index::name_of(std::string_view name) const
{
    const uint32_t s = find_symbol(name);
    if (s == flat_slots::none || m_name_of_sym[s] == 0)
        return nullptr;
    return &m_names[m_name_of_sym[s] - 1];
}

void series_index::match(std::span<const matcher> ms, std::vector<uint32_t>& out) const
{
    out.clear();
    const uint32_t universe = size();
    std::vector<std::vector<uint32_t>> pos, neg;
    std::vector<const std::vector<uint32_t>*> lists;
    std::vector<std::string_view> lits;

    // One matcher as a set the result lies in or one it lies outside; false when nothing can match.
    const auto eval = [&](const matcher& m) {
        const bool negate = m.op == match_op::ne || m.op == match_op::nre;
        const compiled* c = nullptr;
        lits.clear();
        if (m.op == match_op::eq || m.op == match_op::ne)
            lits.push_back(m.value);
        else
        {
            c = &compiled_for(m.value);
            if (c->k == compiled::kind::any)
                return !negate;
            if (c->k == compiled::kind::invalid)
                return negate;
            if (c->k == compiled::kind::literals)
                for (const auto& l : c->lits)
                    lits.push_back(l);
        }
        const bool literal = c == nullptr || c->k == compiled::kind::literals;
        const auto accepts = [&](std::string_view v) {
            const bool r = literal ? std::find(lits.begin(), lits.end(), v) != lits.end() : c->accepts(v);
            return r != negate;
        };
        const bool takes_empty = accepts("");
        const name_entry* ne = name_of(m.name);
        if (!ne)
            return takes_empty;
        lists.clear();
        // The side that is wanted, accepted values or rejected ones, is exactly the literals.
        if (literal && takes_empty == negate)
        {
            const uint32_t ns = ne->name;
            for (std::string_view v : lits)
            {
                const uint32_t vs = find_symbol(v);
                if (vs == flat_slots::none)
                    continue;
                if (const uint32_t p = posting_of(ns, vs); p != flat_slots::none)
                    lists.push_back(&m_postings[p].ids);
            }
        }
        else
            for (uint32_t p : ne->postings)
                if (accepts(symbol(m_postings[p].value)) != takes_empty)
                    lists.push_back(&m_postings[p].ids);
        if (!takes_empty)
        {
            if (lists.empty())
                return false;
            pos.emplace_back();
            union_of(lists, universe, pos.back());
        }
        else if (!lists.empty())
        {
            neg.emplace_back();
            union_of(lists, universe, neg.back());
        }
        return true;
    };

    for (const matcher& m : ms)
        if (!eval(m))
            return;

    std::vector<uint32_t> cur, tmp;
    if (pos.empty())
    {
        cur.resize(universe);
        std::iota(cur.begin(), cur.end(), 0u);
    }
    else
    {
        std::sort(pos.begin(), pos.end(), [](const auto& a, const auto& b) { return a.size() < b.size(); });
        cur = std::move(pos[0]);
        for (size_t i = 1; i < pos.size() && !cur.empty(); ++i)
        {
            tmp.clear();
            std::set_intersection(cur.begin(), cur.end(), pos[i].begin(), pos[i].end(), std::back_inserter(tmp));
            cur.swap(tmp);
        }
    }
    for (const auto& n : neg)
    {
        if (cur.empty())
            break;
        tmp.clear();
        std::set_difference(cur.begin(), cur.end(), n.begin(), n.end(), std::back_inserter(tmp));
        cur.swap(tmp);
    }
    out = std::move(cur);
}

void series_index::label_names(std::vector<std::string>& out) const
{
    out.clear();
    for (const auto& n : m_names)
        out.emplace_back(symbol(n.name));
    std::sort(out.begin(), out.end());
}

void series_index::label_values(std::string_view name, std::vector<std::string>& out) const
{
    out.clear();
    const name_entry* ne = name_of(name);
    if (!ne)
        return;
    for (uint32_t p : ne->postings)
        out.emplace_back(symbol(m_postings[p].value));
    std::sort(out.begin(), out.end());
}

size_t series_index::bytes() const
{
    size_t b = m_sym_bytes.capacity() + m_sym_off.capacity() * 4 + m_sym_table.bytes() + m_pairs.capacity() * 4 +
               m_ser_off.capacity() * 4 + m_ser_table.bytes() + m_pair_table.bytes() +
               m_postings.capacity() * sizeof(posting) + m_names.capacity() * sizeof(name_entry) +
               m_name_of_sym.capacity() * 4 + m_label_cache.capacity() * sizeof(void*) + m_label_cache_bytes;
    for (const auto& p : m_postings)
        b += p.ids.capacity() * 4;
    for (const auto& n : m_names)
        b += n.postings.capacity() * 4;
    return b;
}

}   // namespace socketley::metrics
