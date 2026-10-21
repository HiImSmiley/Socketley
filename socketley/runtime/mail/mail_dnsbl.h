#pragma once
// The DNS blocklists of --dnsbl (RFC 5782): a connection's address, its octets reversed, asked under each zone on
// the loop's resolver, an answer in 127/8 saying it is listed.  127.255.255.x is a list's way of refusing the
// question, from a resolver it will not answer, and lists nothing.  An answer is kept five minutes; an address no
// answer came for is taken as listed nowhere, since a list that cannot be reached is no reason to refuse mail.
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "../../shared/loop/file_io.h"

namespace socketley::mail
{

class dnsbl
{
public:
    explicit dnsbl(file_io& io) : m_io(io) {}
    ~dnsbl() { *m_alive = false; }
    dnsbl(const dnsbl&)            = delete;
    dnsbl& operator=(const dnsbl&) = delete;

    void set_zones(std::string_view comma_list);
    bool enabled() const { return !m_zones.empty(); }
    // `done` with the zone that lists `ip`, empty where none does; at once where the answer is kept.
    void check(const std::string& ip, std::function<void(std::string zone)> done);
    uint64_t listed() const { return m_listed; }
    uint64_t asked() const { return m_asked; }

    // The name `ip` is asked as under a zone: an IPv4 address's octets reversed, an IPv6 one's nibbles.
    static std::string reversed(std::string_view ip);

private:
    struct asking
    {
        std::vector<std::string> names;
        std::vector<bool> done;
        std::string listed_by;
        std::vector<std::function<void(std::string)>> waiting;
    };
    void step(const std::string& ip);
    void poll();

    file_io& m_io;
    std::vector<std::string> m_zones;
    struct kept
    {
        std::string zone;
        int64_t until_ms{0};
    };
    std::unordered_map<std::string, kept> m_kept;
    std::unordered_map<std::string, asking> m_asking;
    bool m_polling{false};
    uint64_t m_listed{0};
    uint64_t m_asked{0};
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
};

}   // namespace socketley::mail
