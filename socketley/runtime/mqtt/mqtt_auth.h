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

#include "../../shared/crypto/password_file.h"
#include "../../shared/persist/watched_file.h"

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

using socketley::user_table;
using socketley::watched;

}   // namespace socketley::mqtt

