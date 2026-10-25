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

#include "../../shared/runtime/runtime_instance.h"
#include "shared/runtime/retired_runs.h"

namespace socketley::dns
{
class dns_run;
}

// Port 53, which only a privileged process, or one given CAP_NET_BIND_SERVICE, may bind.
inline constexpr uint16_t dns_default_port = 53;
// Responses a second to one client block before the rest are dropped or sent truncated (--rrl), 0 for no limit.
inline constexpr uint32_t dns_default_rrl = 100;

// Where a runtime's DNSSEC keys are kept, one file a zone, the same for every shard.
std::string dns_dnssec_dir(std::string_view runtime_name);

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
    // The DS record each zone's parent is given, and its DNSKEY, a line each; the keys made where they are not yet.
    std::string ds_records(std::string& why) const;
    // Where the file of a zone given by name (--zone example.com) is kept: the state directory's zones/.
    static std::string managed_zone_path(std::string_view zone);
    // Each zone file that does not exist yet written, for a zone given by name or a missing <zone>.zone: its SOA,
    // ns1 and ns2 as its servers, with --publish's addresses or this machine's public ones. False with the reason.
    bool ensure_zone_files(std::string& why) const;

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

    // The entrance runtimes' names are reached through (--proxy): a proxy without --backend. With it, every runtime's
    // name in a zone is answered, with --publish's addresses or, without them, this machine's public ones.
    void set_proxy(std::string_view name) { m_proxy = std::string(name); }
    std::string_view get_proxy() const { return m_proxy; }
    // The port the entrance `create` makes for it listens on (--proxy-port), 443 when not given; read at create only.
    void set_proxy_port(uint16_t port) { m_proxy_port = port; }
    uint16_t get_proxy_port() const { return m_proxy_port; }

    // Response rate limiting (--rrl), per second for one client's /24 or /56.
    void set_rrl(uint32_t per_sec) { m_rrl = per_sec; }
    uint32_t get_rrl() const { return m_rrl; }

    // DNSSEC (--dnssec): every zone signed as it is loaded, with a key of its own under the runtime's state.
    void set_dnssec(bool on) { m_dnssec = on; }
    bool get_dnssec() const { return m_dnssec; }

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
    std::string m_proxy;
    uint16_t m_proxy_port{443};
    uint32_t    m_rrl{dns_default_rrl};
    bool        m_dnssec{false};

    std::unique_ptr<socketley::dns::dns_run> m_run;
    // Runs the ring still owes completions to, freed once it owes them none.
    socketley::retired_runs<socketley::dns::dns_run> m_graveyard;
};
