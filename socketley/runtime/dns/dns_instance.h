#pragma once
// The DNS runtime: an authoritative name server for the zones in its files, over UDP and TCP on one port.
//
// It answers for its zones and for nothing else -- no recursion, no cache, nothing asked of another server -- so it
// can be no open resolver and nobody's cache can be poisoned through it. A zone file it is given is checked whole
// and taken only when it is a zone; edited while the runtime runs, it is read again within a second and the new one
// served if it is sound, the old one kept if it is not. Secondaries named by --notify are told of a new serial and
// may copy the zone by AXFR from the addresses --transfer allows.
//
// As every runtime, it may run as several shards, each a process with its own sockets on the shared port, so the
// kernel spreads queries over the cores.
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "../../shared/runtime_instance.h"

namespace socketley::dns
{
class dns_run;
}

// Port 53, which only a privileged process, or one given CAP_NET_BIND_SERVICE, may bind.
inline constexpr uint16_t dns_default_port = 53;
// Responses a second to one client block before the rest are dropped or sent truncated (--rrl), 0 for no limit.
inline constexpr uint32_t dns_default_rrl = 100;

class dns_instance : public runtime_instance
{
public:
    explicit dns_instance(std::string_view name);
    ~dns_instance() override;

    // The zone files served, comma-separated (--zone, which may be given more than once).
    void set_zones(std::string_view csv) { m_zones = std::string(csv); }
    void add_zone(std::string_view path)
    {
        if (!m_zones.empty())
            m_zones += ',';
        m_zones += path;
    }
    std::string_view get_zones() const { return m_zones; }
    std::vector<std::string> zone_paths() const;

    // Who may copy a whole zone (--transfer): addresses and blocks, comma-separated; empty is nobody.
    void set_transfer(std::string_view csv) { m_transfer = std::string(csv); }
    std::string_view get_transfer() const { return m_transfer; }

    // The secondaries told when a zone's serial changes (--notify): host[:port], comma-separated.
    void set_notify(std::string_view csv) { m_notify = std::string(csv); }
    std::string_view get_notify() const { return m_notify; }

    // The addresses the names runtimes are reached by are given (--publish): IPv4 and IPv6, comma-separated. Empty
    // publishes none of them.
    void set_publish(std::string_view csv) { m_publish = std::string(csv); }
    std::string_view get_publish() const { return m_publish; }

    // Response rate limiting (--rrl), per second for one client's /24 or /56.
    void set_rrl(uint32_t per_sec) { m_rrl = per_sec; }
    uint32_t get_rrl() const { return m_rrl; }

    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;
    void on_loop_turn() override;

    size_t get_connection_count() const override;
    std::string stats_lines() const override;
    std::string config_refusal() const override;
    void listen_addresses(std::vector<std::string>& out) const override;
    uint16_t effective_port() const override;

private:
    std::string m_zones;
    std::string m_transfer;
    std::string m_notify;
    std::string m_publish;
    uint32_t    m_rrl{dns_default_rrl};

    std::unique_ptr<socketley::dns::dns_run> m_run;
    // Runs the ring still owes completions to, freed once it owes them none.
    std::vector<std::unique_ptr<socketley::dns::dns_run>> m_graveyard;
};
