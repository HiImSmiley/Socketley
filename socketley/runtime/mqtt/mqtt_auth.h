#pragma once
// Who may connect and what they may read and write: the users file (a name and a scrypt hash a line) and the ACL
// file in the form Mosquitto reads, both read again when they change.
//
//   # anything before the first `user` line is for clients that sent no user name
//   topic read public/#
//   user alice
//   topic readwrite alice/#
//   topic deny alice/secret/#
//   pattern readwrite devices/%c/#      # every client, %u its user name and %c its client identifier
//
// A deny that matches wins over every grant; without an ACL file everything not under '$' is allowed.
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "../../shared/persist/file_stamp.h"

namespace socketley::mqtt
{

// Whether the filter `acl` reaches every topic the filter `sub` does, so a subscription is granted only where the
// rule covers all of it.
bool filter_covers(std::string_view acl, std::string_view sub);

// Whether a topic matches a filter, with the rule that a wildcard at the first level does not reach '$'.
bool topic_matches(std::string_view filter, std::string_view topic);

enum class access : uint8_t { read = 1, write = 2 };

class acl_rules
{
public:
    // The rules in `text`; false with `why` naming the line that is not one.
    bool parse(std::string_view text, std::string& why);

    // Whether `user` (empty for a client that sent none) with client identifier `client` may publish to `topic`.
    bool may_write(std::string_view user, std::string_view client, std::string_view topic) const;
    // Whether it may receive a message published to `topic`.
    bool may_read(std::string_view user, std::string_view client, std::string_view topic) const;
    // Whether it may subscribe to `filter`, which some grant must cover whole.
    bool may_subscribe(std::string_view user, std::string_view client, std::string_view filter) const;

    bool empty() const { return m_rules.empty(); }

private:
    struct rule
    {
        // Empty for the anonymous section, `*` for a pattern that applies to every client.
        std::string user;
        bool        pattern{false};
        bool        deny{false};
        uint8_t     rights{0};
        std::string filter;
    };
    // The rule's filter with %u and %c put in, empty when a name contains a character a level cannot.
    static std::string expand(const rule& r, std::string_view user, std::string_view client);
    bool applies(const rule& r, std::string_view user) const;
    bool check(std::string_view user, std::string_view client, std::string_view topic, uint8_t right,
               bool as_filter) const;

    std::vector<rule> m_rules;
};

// A file read again whenever its stamp says it changed, kept as what it last parsed to.
template <class T>
class watched
{
public:
    void set_path(std::string path) { m_path = std::move(path); m_stamp.reset(); }
    const std::string& path() const { return m_path; }
    bool configured() const { return !m_path.empty(); }
    const T& value() const { return m_value; }

    // Read again if it changed since the last look; false with `why` when the new content is refused, the old
    // value then kept.
    template <class Parse>
    bool refresh(Parse&& parse, std::string& why);

private:
    std::string m_path;
    std::optional<socketley::file_stamp> m_stamp;
    T m_value;
};

// The users and their password hashes.
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

}   // namespace socketley::mqtt

#include "../../shared/persist/read_file.h"

namespace socketley::mqtt
{

template <class T>
template <class Parse>
bool watched<T>::refresh(Parse&& parse, std::string& why)
{
    if (m_path.empty())
        return true;
    const auto stamp = socketley::file_stamp::of(m_path);
    if (m_stamp && *m_stamp == stamp)
        return true;
    // Looked at once per change, refused or not, so a broken file is said once and not at every tick.
    m_stamp = stamp;
    std::string text;
    if (!socketley::read_file(m_path, text, {.missing_ok = false, .max_bytes = 16u << 20}, &why))
        return false;
    T next;
    if (!parse(next, text, why))
    {
        why = m_path + ": " + why;
        return false;
    }
    m_value = std::move(next);
    return true;
}

}   // namespace socketley::mqtt
