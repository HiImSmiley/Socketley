#pragma once
// The registrable domain of a name by the Public Suffix List: the suffix under which anyone may register a name, and
// the one label more that someone did.  DMARC aligns by it (RFC 7489 3.2), so example.co.uk and mail.example.co.uk
// are one organization and two names under co.uk are two.  The list is the one the publicsuffix package keeps at
// /usr/share/publicsuffix, read once, its rules past ASCII compared as A-labels; without it a name is its own.
#include <string>
#include <string_view>
#include <unordered_set>

namespace socketley::public_suffix
{

class list
{
public:
    // The rules of a list in the format publicsuffix.org writes: one a line, "*." a wildcard, "!" an exception.
    void load(std::string_view text);
    bool empty() const { return m_rules.empty() && m_wild.empty(); }
    // `name`'s public suffix and one label more, in lower case; the name itself where it is a suffix or one label.
    std::string registrable(std::string_view name) const;

private:
    std::unordered_set<std::string> m_rules, m_wild, m_except;
};

// The system's list, read the first time it is asked for; empty where the file is not there.
const list& system_list();

// registrable() by the system's list, the name itself where there is none.
std::string registrable(std::string_view name);

}   // namespace socketley::public_suffix
