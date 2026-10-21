#include "password_file.h"

#include "../util/text_list.h"

namespace socketley
{

namespace
{

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

}   // namespace

bool user_table::parse(std::string_view text, std::string& why)
{
    m_hashes.clear();
    size_t n = 0;
    while (!text.empty())
    {
        ++n;
        const std::string_view line = trim(socketley::take_item(text, '\n'));
        if (line.empty() || line.front() == '#')
            continue;
        const size_t colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0 || colon + 1 == line.size())
        {
            why = "line " + std::to_string(n) + " is not <user>:<hash>";
            return false;
        }
        const std::string_view hash = line.substr(colon + 1);
        if (!hash.starts_with("$scrypt$"))
        {
            why = "line " + std::to_string(n) + ": the password of " + std::string(line.substr(0, colon)) +
                  " is not a hash `socketley mqtt-passwd` writes";
            return false;
        }
        m_hashes.insert_or_assign(std::string(line.substr(0, colon)), std::string(hash));
    }
    return true;
}

const std::string* user_table::hash_of(std::string_view user) const
{
    const auto it = m_hashes.find(std::string(user));
    return it == m_hashes.end() ? nullptr : &it->second;
}

}   // namespace socketley
