#pragma once
// Host names answered on the loop's own thread without waiting on it: /etc/hosts first, then a question over UDP to
// the nameservers /etc/resolv.conf names, each sent on a socket that never blocks and read when the caller asks
// again, the poll a resolving caller already makes.
//
// What it cannot say it hands back as `unsure` rather than as a failure: a name no nameserver knows, which only an
// NSS module may (mDNS, LDAP, a container's own), an answer cut short, no nameserver at all.  The caller then asks
// the system's resolver, on a thread as before, so a name resolves here exactly when getaddrinfo would have.
//
// A question goes on a socket of its own, from a port the kernel picks, under an identifier drawn at random, and an
// answer counts only when it comes from the server asked, names the question asked and carries its identifier.
#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "endpoint.h"

namespace socketley
{

class dns_client
{
public:
    enum class state : uint8_t { pending, ready, unsure };

    // The one of the calling thread, since a loop and its resolver live on one.
    static dns_client& here();

    // What is known of `host` for `family` (AF_INET, AF_INET6 or AF_UNSPEC): a question is sent when none is out,
    // and `out` holds its addresses, the port left 0, once the state is ready.
    state ask(const std::string& host, int family, std::vector<endpoint>& out);

    // A record set other than addresses, for an absolute name: MX with its preference and exchange, TXT with the
    // strings of a record joined, TLSA with its record data as it came.  Ready with none for a name with none of the
    // type, and `no_domain` for one that does not exist; unsure for an answer cut short or no nameserver answering,
    // which the system's resolver then asks.  `secure`, when given, says the answer was validated by DNSSEC: the
    // nameserver set its AD bit and is on this machine, the only place its say-so is not an attacker's to forge.
    struct record
    {
        uint16_t    pref{0};
        std::string text;
    };
    state ask_records(const std::string& name, uint16_t type, std::vector<record>& out, bool& no_domain,
                      bool* secure = nullptr);

    // How often each way out was taken, for a test and a benchmark to read.
    struct counters
    {
        uint64_t from_hosts{0}, answered{0}, unsure{0}, sent{0}, timeouts{0};
    };
    const counters& counted() const { return m_c; }

    dns_client() = default;
    ~dns_client();
    dns_client(const dns_client&)            = delete;
    dns_client& operator=(const dns_client&) = delete;

private:
    using clock = std::chrono::steady_clock;

    struct config
    {
        std::vector<endpoint>    servers;
        std::vector<std::string> search;
        int                      ndots{1};
        std::chrono::milliseconds timeout{5000};
        int                      attempts{2};
    };
    // One question for one type of one candidate name.
    struct question
    {
        uint16_t    type{0};
        uint16_t    id{0};
        int         fd{-1};
        bool        done{false};
        bool        none{false};      // answered, with no address of the type
        std::vector<endpoint> addrs;
        std::vector<record>   records;
        bool        nxdomain{false};
        bool        authentic{false};
    };
    struct job
    {
        std::vector<std::string> names;   // the candidates, in the order resolv.conf says
        size_t                   at{0};   // the one being asked
        int                      family{AF_UNSPEC};
        size_t                   server{0};
        int                      tries{0};
        clock::time_point        sent{};
        std::vector<question>    qs;
        bool                     over{false};
        state                    result{state::pending};
        std::vector<endpoint>    addrs;
    };

    // /etc/resolv.conf and /etc/hosts read again when either changed, looked at once a second.
    void refresh();
    bool from_hosts(const std::string& host, int family, std::vector<endpoint>& out) const;
    // The current candidate's questions sent to the current server; false when no socket could be made.
    bool send(job& j);
    // Every answer waiting on the job's sockets taken, and the deadline of the server asked looked at.
    void pump(job& j);
    void take(job& j, question& q, const uint8_t* msg, size_t len);
    // A record question's answer taken, or its deadline looked at.
    void pump_records(job& j);
    void close_all(job& j);
    // The job's next step once each of its questions has an answer: done, or the next candidate.
    void settle(job& j);

    config                                      m_cfg;
    std::unordered_map<std::string, std::vector<endpoint>> m_hosts;
    clock::time_point                           m_checked{};
    int64_t                                     m_conf_mtime{-1}, m_hosts_mtime{-1};
    std::unordered_map<std::string, job>        m_jobs;
    counters                                    m_c;
};

}  // namespace socketley
