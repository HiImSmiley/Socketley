#include "public_suffix.h"

#include <algorithm>
#include <vector>

#include "idna.h"
#include "../persist/read_file.h"
#include "../util/ascii.h"
#include "../util/logging.h"

namespace socketley::public_suffix
{

namespace
{

// A name as the rules and the headers compare: lower case, its labels past ASCII as A-labels, no trailing dot.
std::string lower(std::string_view s)
{
    std::string out(s);
    if (std::any_of(out.begin(), out.end(), [](char c) { return static_cast<unsigned char>(c) >= 0x80; }))
        out = socketley::idna::to_ascii(out);
    socketley::ascii::lower_in_place(out);
    while (!out.empty() && out.back() == '.')
        out.pop_back();
    return out;
}

}   // namespace

void list::load(std::string_view text)
{
    while (!text.empty())
    {
        const size_t nl = text.find('\n');
        std::string_view line = text.substr(0, nl);
        text = nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
        // A rule is the line up to its first white space; "//" begins a comment.
        if (const size_t ws = line.find_first_of(" \t\r"); ws != std::string_view::npos)
            line = line.substr(0, ws);
        if (line.empty() || line.starts_with("//"))
            continue;
        if (line.starts_with("!"))
            m_except.insert(lower(line.substr(1)));
        else if (line.starts_with("*."))
            m_wild.insert(lower(line.substr(2)));
        else
            m_rules.insert(lower(line));
    }
}

std::string list::registrable(std::string_view name) const
{
    const std::string n = lower(name);
    std::vector<size_t> starts;   // where each label begins, from the left
    starts.push_back(0);
    for (size_t i = 0; i < n.size(); ++i)
        if (n[i] == '.')
            starts.push_back(i + 1);
    const size_t labels = starts.size();
    // The suffix is the longest rule that matches, one label where none does, and an exception's rule less its
    // first label wherever one matches (publicsuffix.org's algorithm).
    size_t best = 1;
    bool excepted = false;
    for (size_t k = 1; k <= labels && !excepted; ++k)
    {
        const std::string_view s = std::string_view(n).substr(starts[labels - k]);
        if (m_except.count(std::string(s)))
        {
            best = k - 1;
            excepted = true;
        }
        else if (m_rules.count(std::string(s)))
            best = k;
        else if (k >= 2 && m_wild.count(std::string(std::string_view(n).substr(starts[labels - k + 1]))))
            best = k;
    }
    if (best >= labels)
        return n;
    return n.substr(starts[labels - best - 1]);
}

const list& system_list()
{
    static const list l = [] {
        list out;
        std::string text;
        if (socketley::read_file("/usr/share/publicsuffix/public_suffix_list.dat", text))
            out.load(text);
        return out;
    }();
    return l;
}

std::string registrable(std::string_view name)
{
    const list& l = system_list();
    if (!l.empty())
        return l.registrable(name);
    // Without the list no two names are known to be one organization's, so relaxed alignment is strict: the last two
    // labels would make bank.co.uk and attacker.co.uk one.
    [[maybe_unused]] static const bool told = [] {
        LOG_WARN("no public suffix list at /usr/share/publicsuffix: DMARC aligns names strictly");
        return true;
    }();
    return lower(name);
}

}   // namespace socketley::public_suffix
