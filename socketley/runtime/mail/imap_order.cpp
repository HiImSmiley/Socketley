#include "imap_order.h"

#include <algorithm>
#include <map>
#include <memory>
#include <unordered_map>

#include "mail_compose.h"
#include "mail_mime.h"
#include "smtp_session.h"
#include "../../shared/util/ascii.h"

namespace socketley::mail::imap_order
{

namespace
{

std::string lower(std::string_view s)
{
    std::string out(s);
    socketley::ascii::lower_in_place(out);
    return out;
}

bool istarts(std::string_view s, std::string_view p)
{
    return s.size() >= p.size() && socketley::ascii::iequals(s.substr(0, p.size()), p);
}

// A [blob] and the spaces after it, from `p`; false where there is none.
bool skip_blob(const std::string& t, size_t& p)
{
    if (p >= t.size() || t[p] != '[')
        return false;
    size_t q = p + 1;
    while (q < t.size() && t[q] != ']' && t[q] != '[')
        ++q;
    if (q >= t.size() || t[q] != ']')
        return false;
    p = q + 1;
    while (p < t.size() && t[p] == ' ')
        ++p;
    return true;
}

// The <ids> a header holds, in order.
std::vector<std::string> ids_in(std::string_view v)
{
    std::vector<std::string> out;
    for (size_t at = 0; (at = v.find('<', at)) != std::string_view::npos;)
    {
        const size_t end = v.find('>', at);
        if (end == std::string_view::npos)
            break;
        if (end > at + 1)
            out.emplace_back(v.substr(at + 1, end - at - 1));
        at = end + 1;
    }
    return out;
}

int compare_text(const std::string& a, const std::string& b)
{
    const std::string x = lower(a), y = lower(b);
    return x < y ? -1 : x > y ? 1 : 0;
}

}   // namespace

std::string base_subject(std::string_view raw, bool* reply)
{
    bool marked = false;
    const std::string decoded = mime::decode_words(raw);
    std::string t;
    bool space = false;
    for (const char c : decoded)
    {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
        {
            space = true;
            continue;
        }
        if (space && !t.empty())
            t += ' ';
        space = false;
        t += c;
    }
    // RFC 5256 2.1, steps 2 to 5, again while a [fwd: ...] wraps what is left.
    for (int round = 0; round < 64; ++round)
    {
        for (bool again = true; again;)
        {
            again = false;
            while (!t.empty() && t.back() == ' ')
            {
                t.pop_back();
                again = true;
            }
            if (t.size() >= 5 && socketley::ascii::iequals(std::string_view(t).substr(t.size() - 5), "(fwd)"))
            {
                t.resize(t.size() - 5);
                again = marked = true;
            }
        }
        for (bool again = true; again && !t.empty();)
        {
            again = false;
            size_t lead = 0;
            while (lead < t.size() && t[lead] == ' ')
                ++lead;
            if (lead)
            {
                t.erase(0, lead);
                again = true;
                continue;
            }
            // *blob ("re" / "fw" / "fwd") *WSP [blob] ":"
            size_t p = 0;
            while (skip_blob(t, p))
            {
            }
            const std::string_view at = std::string_view(t).substr(p);
            size_t q = istarts(at, "fwd") ? p + 3 : istarts(at, "fw") || istarts(at, "re") ? p + 2 : std::string::npos;
            if (q != std::string::npos)
            {
                while (q < t.size() && t[q] == ' ')
                    ++q;
                skip_blob(t, q);
                if (q < t.size() && t[q] == ':')
                {
                    t.erase(0, q + 1);
                    again = marked = true;
                    continue;
                }
            }
            // A blob ahead of the rest goes, as long as something is left after it.
            size_t b = 0;
            if (skip_blob(t, b) && b < t.size())
            {
                t.erase(0, b);
                again = true;
            }
        }
        if (t.size() > 6 && istarts(t, "[fwd:") && t.back() == ']')
        {
            t = t.substr(5, t.size() - 6);
            marked = true;
            continue;
        }
        break;
    }
    if (reply)
        *reply = marked;
    return t;
}

void read(entry& e, std::string_view header)
{
    e.subject = base_subject(header_value(header, "Subject"), &e.reply);
    const auto first = [&header](std::string_view name, std::string& mailbox, std::string* display) {
        std::vector<address> list;
        const std::string v = header_value(header, name);
        if (!parse_mailbox_list(v, list) || list.empty())
            return;
        mailbox = lower(list[0].local);
        if (display)
        {
            // The display name of the first address, or the address where it has none (RFC 5957).
            address a;
            std::string name_shown;
            const std::string one = v.substr(0, v.find(','));
            if (parse_mailbox(one, a, &name_shown) && !name_shown.empty())
                *display = mime::decode_words(name_shown);
            else
                *display = list[0].text();
        }
    };
    first("From", e.from, &e.display_from);
    first("To", e.to, &e.display_to);
    first("Cc", e.cc, nullptr);
    int64_t t = 0;
    int zone = 0;
    e.sent_s = mime::parse_date(header_value(header, "Date"), t, zone) ? t : e.arrival_ms / 1000;
    const auto mid = ids_in(header_value(header, "Message-ID"));
    e.message_id = mid.empty() ? std::string() : mid.front();
    e.references = ids_in(header_value(header, "References"));
    if (e.references.empty())
    {
        const auto irt = ids_in(header_value(header, "In-Reply-To"));
        if (!irt.empty())
            e.references.push_back(irt.front());
    }
    // A chain longer than any reply quotes is read from its end.
    if (e.references.size() > 100)
        e.references.erase(e.references.begin(), e.references.end() - 100);
}

bool parse_keys(const std::vector<std::string>& words, std::vector<key>& out)
{
    out.clear();
    bool reverse = false;
    for (const auto& w : words)
    {
        const std::string u = lower(w);
        if (u == "reverse")
        {
            reverse = true;
            continue;
        }
        key k;
        k.reverse = reverse;
        reverse = false;
        if (u == "arrival")
            k.k = key::kind::arrival;
        else if (u == "cc")
            k.k = key::kind::cc;
        else if (u == "date")
            k.k = key::kind::date;
        else if (u == "from")
            k.k = key::kind::from;
        else if (u == "size")
            k.k = key::kind::size;
        else if (u == "subject")
            k.k = key::kind::subject;
        else if (u == "to")
            k.k = key::kind::to;
        else if (u == "displayfrom")
            k.k = key::kind::display_from;
        else if (u == "displayto")
            k.k = key::kind::display_to;
        else
            return false;
        out.push_back(k);
    }
    return !reverse && !out.empty();
}

void sort(std::vector<entry>& v, const std::vector<key>& keys)
{
    std::stable_sort(v.begin(), v.end(), [&keys](const entry& a, const entry& b) {
        for (const auto& k : keys)
        {
            int c = 0;
            switch (k.k)
            {
                case key::kind::arrival: c = a.arrival_ms < b.arrival_ms ? -1 : a.arrival_ms > b.arrival_ms; break;
                case key::kind::date: c = a.sent_s < b.sent_s ? -1 : a.sent_s > b.sent_s; break;
                case key::kind::size: c = a.size < b.size ? -1 : a.size > b.size; break;
                case key::kind::cc: c = compare_text(a.cc, b.cc); break;
                case key::kind::from: c = compare_text(a.from, b.from); break;
                case key::kind::to: c = compare_text(a.to, b.to); break;
                case key::kind::subject: c = compare_text(a.subject, b.subject); break;
                case key::kind::display_from: c = compare_text(a.display_from, b.display_from); break;
                case key::kind::display_to: c = compare_text(a.display_to, b.display_to); break;
            }
            if (c)
                return k.reverse ? c > 0 : c < 0;
        }
        // The message's number is the tie every key leaves.
        return a.seq < b.seq;
    });
}

std::string ordered_subject(std::vector<entry> v)
{
    std::stable_sort(v.begin(), v.end(), [](const entry& a, const entry& b) {
        const int c = compare_text(a.subject, b.subject);
        if (c)
            return c < 0;
        return a.sent_s != b.sent_s ? a.sent_s < b.sent_s : a.seq < b.seq;
    });
    // One thread a subject, its first message the parent of the rest, the threads in the order of their first.
    std::vector<std::vector<const entry*>> threads;
    for (const auto& e : v)
        if (threads.empty() || compare_text(threads.back().front()->subject, e.subject) != 0)
            threads.push_back({&e});
        else
            threads.back().push_back(&e);
    std::stable_sort(threads.begin(), threads.end(), [](const auto& a, const auto& b) {
        return a.front()->sent_s != b.front()->sent_s ? a.front()->sent_s < b.front()->sent_s
                                                      : a.front()->seq < b.front()->seq;
    });
    std::string out;
    for (const auto& t : threads)
    {
        out += "(" + std::to_string(t.front()->number);
        if (t.size() == 2)
            out += " " + std::to_string(t[1]->number);
        else if (t.size() > 2)
        {
            out += " ";
            for (size_t i = 1; i < t.size(); ++i)
                out += "(" + std::to_string(t[i]->number) + ")";
        }
        out += ")";
    }
    return out;
}

namespace
{

struct node
{
    const entry* msg{nullptr};
    node* parent{nullptr};
    std::vector<node*> kids;
    // For the subject grouping: whether the message's subject was a reply's.
    bool reply{false};
};

// A thread is printed and sorted by recursion this deep at most: what lies deeper starts a thread of its own.
constexpr int max_depth = 500;

// Whether `a` is `of` or above it; a walk too long to finish says it is, so no loop is ever made.
bool ancestor(const node* a, const node* of)
{
    for (int d = 0; of; of = of->parent)
        if (of == a || ++d > 100000)
            return true;
    return false;
}

void unlink(node* n)
{
    if (!n->parent)
        return;
    auto& k = n->parent->kids;
    k.erase(std::remove(k.begin(), k.end(), n), k.end());
    n->parent = nullptr;
}

// `child` under `parent`, unless it would close a loop.
void link(node* parent, node* child)
{
    if (parent == child || ancestor(child, parent))
        return;
    unlink(child);
    child->parent = parent;
    parent->kids.push_back(child);
}

// The sent time a thread is placed by: its own message's, or its first child's where it is a placeholder.
int64_t when(const node* n)
{
    for (int d = 0; n && d <= max_depth + 4; ++d)
    {
        if (n->msg)
            return n->msg->sent_s;
        if (n->kids.empty())
            return 0;
        n = n->kids.front();
    }
    return 0;
}

size_t seq_of(const node* n)
{
    for (int d = 0; n && d <= max_depth + 4; ++d)
    {
        if (n->msg)
            return n->msg->seq;
        if (n->kids.empty())
            return 0;
        n = n->kids.front();
    }
    return 0;
}

void sort_kids(std::vector<node*>& v)
{
    for (node* n : v)
        sort_kids(n->kids);
    std::stable_sort(v.begin(), v.end(), [](const node* a, const node* b) {
        const int64_t x = when(a), y = when(b);
        return x != y ? x < y : seq_of(a) < seq_of(b);
    });
}

// The thread's members after its opening parenthesis: a chain written in a row, its branches each parenthesized.
std::string members(const node* n)
{
    std::string out = n->msg ? std::to_string(n->msg->number) : std::string();
    if (n->kids.size() == 1)
        out += (out.empty() ? "" : " ") + members(n->kids.front());
    else if (n->kids.size() > 1)
    {
        if (!out.empty())
            out += " ";
        for (const node* k : n->kids)
            out += "(" + members(k) + ")";
    }
    return out;
}

// Placeholders with nothing under them go, and one's children take its place, at the top only where it had one.
void prune(std::vector<node*>& level, node* parent)
{
    for (size_t i = 0; i < level.size();)
    {
        node* n = level[i];
        prune(n->kids, n);
        if (n->msg)
        {
            ++i;
            continue;
        }
        if (n->kids.empty())
        {
            level.erase(level.begin() + static_cast<long>(i));
            continue;
        }
        if (parent || n->kids.size() == 1)
        {
            std::vector<node*> kids = std::move(n->kids);
            n->kids.clear();
            for (node* k : kids)
                k->parent = parent;
            level.erase(level.begin() + static_cast<long>(i));
            level.insert(level.begin() + static_cast<long>(i), kids.begin(), kids.end());
            continue;
        }
        ++i;
    }
}

}   // namespace

std::string references(std::vector<entry> v)
{
    std::vector<std::unique_ptr<node>> all;
    std::unordered_map<std::string, node*> by_id;
    const auto get = [&](const std::string& id) {
        node*& n = by_id[id];
        if (!n)
        {
            all.push_back(std::make_unique<node>());
            n = all.back().get();
        }
        return n;
    };
    std::sort(v.begin(), v.end(), [](const entry& a, const entry& b) { return a.seq < b.seq; });
    // Each message under the last of its references, the references chained one under the other (RFC 5256 2.2).
    for (size_t i = 0; i < v.size(); ++i)
    {
        const entry& e = v[i];
        std::string id = e.message_id;
        if (id.empty() || (by_id.count(id) && by_id[id]->msg))
            id = "\x01" + std::to_string(i);
        node* me = get(id);
        me->msg = &e;
        me->reply = e.reply;
        node* prev = nullptr;
        for (const auto& r : e.references)
        {
            node* rn = get(r);
            if (prev && !rn->parent)
                link(prev, rn);
            prev = rn;
        }
        unlink(me);
        if (prev)
            link(prev, me);
    }
    // Nodes deeper than the recursion below goes are made roots, found without recursing.
    std::vector<node*> too_deep;
    {
        std::vector<std::pair<node*, int>> stack;
        for (const auto& n : all)
            if (!n->parent)
                stack.emplace_back(n.get(), 1);
        while (!stack.empty())
        {
            auto [n, d] = stack.back();
            stack.pop_back();
            if (d > max_depth)
            {
                too_deep.push_back(n);
                d = 1;
            }
            for (node* k : n->kids)
                stack.emplace_back(k, d + 1);
        }
    }
    for (node* n : too_deep)
        unlink(n);
    std::vector<node*> roots;
    for (const auto& n : all)
        if (!n->parent)
            roots.push_back(n.get());
    prune(roots, nullptr);
    // Threads of one base subject are gathered under one root.
    std::map<std::string, node*> by_subject;
    const auto subject_of = [](const node* n) {
        const node* m = n->msg ? n : n->kids.empty() ? nullptr : n->kids.front();
        return m && m->msg ? lower(m->msg->subject) : std::string();
    };
    std::vector<node*> kept;
    for (node* r : roots)
    {
        const std::string s = subject_of(r);
        if (s.empty())
        {
            kept.push_back(r);
            continue;
        }
        const auto it = by_subject.find(s);
        if (it == by_subject.end())
        {
            by_subject[s] = r;
            kept.push_back(r);
            continue;
        }
        node* t = it->second;
        if (!t->msg && !r->msg)
        {
            for (node* k : r->kids)
                k->parent = t;
            t->kids.insert(t->kids.end(), r->kids.begin(), r->kids.end());
            r->kids.clear();
        }
        else if (!t->msg || (r->reply && !t->reply))
            link(t, r);
        else if (!r->msg || (t->reply && !r->reply))
        {
            link(r, t);
            std::replace(kept.begin(), kept.end(), t, r);
            it->second = r;
        }
        else
        {
            all.push_back(std::make_unique<node>());
            node* d = all.back().get();
            link(d, t);
            link(d, r);
            std::replace(kept.begin(), kept.end(), t, d);
            it->second = d;
        }
    }
    sort_kids(kept);
    std::string out;
    for (const node* r : kept)
        out += "(" + members(r) + ")";
    return out;
}

}   // namespace socketley::mail::imap_order
