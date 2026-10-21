#pragma once
// The users of a runtime that keeps its own, a name and a scrypt hash a line as `socketley mqtt-passwd` writes them;
// read by the mqtt runtime's --users and the mail runtime's.
#include <string>
#include <string_view>
#include <unordered_map>

namespace socketley
{

class user_table
{
public:
    bool parse(std::string_view text, std::string& why);
    // The hash kept for `user`, null when there is no such user.
    const std::string* hash_of(std::string_view user) const;
    size_t size() const { return m_hashes.size(); }

private:
    std::unordered_map<std::string, std::string> m_hashes;
};

}   // namespace socketley
