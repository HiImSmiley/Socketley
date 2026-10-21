#pragma once
// The addresses a mail runtime takes besides its users', and where their mail goes: `address target[,target...]` a
// line, a target being a mailbox (a name without @) or an address elsewhere it is sent on to, and `*@domain` the
// address of any local part of a domain that names none of its own.
//
//   postmaster@example.com   alice
//   info@example.com         alice,bob@elsewhere.org
//   *@example.com            alice
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace socketley::mail
{

struct alias_table
{
    // The targets of an address, in lower case; for a catch-all the key is "*@domain".
    std::unordered_map<std::string, std::vector<std::string>> map;

    bool parse(std::string_view text, std::string& why);
    // The targets of `addr`, then of its domain's catch-all; null when neither is there.
    const std::vector<std::string>* find(std::string_view local, std::string_view domain) const;
};

}   // namespace socketley::mail
