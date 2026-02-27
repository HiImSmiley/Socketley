#include "flag_handlers.h"
#include "../shared/runtime_instance.h"
#include <iostream>
#include <charconv>
#include "../shared/runtime_manager.h"
#include "../runtime/server/server_instance.h"
#include "../runtime/client/client_instance.h"
#include "../runtime/proxy/proxy_instance.h"
#include "../runtime/cache/cache_instance.h"

int parse_common_flags(runtime_instance* instance, const parsed_args& pa,
                       size_t& i, bool& autostart)
{
    switch (pa.hashes[i])
    {
        case fnv1a("-p"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "-p requires a port\n";
                return 1;
            }
            uint16_t port;
            if (!parse_uint16(pa.args[++i], port))
            {
                std::cout << "invalid port number\n";
                return 1;
            }
            instance->set_port(port);
            return 0;
        }

        case fnv1a("-s"):
            autostart = true;
            return 0;

        case fnv1a("--test"):
            instance->set_test_mode(true);
            return 0;

        case fnv1a("--log"):
            if (i + 1 >= pa.count)
            {
                std::cout << "--log requires a file\n";
                return 1;
            }
            instance->set_log_file(pa.args[++i]);
            return 0;

        case fnv1a("-w"):
            if (i + 1 >= pa.count)
            {
                std::cout << "-w requires a file\n";
                return 1;
            }
            instance->set_write_file(pa.args[++i]);
            return 0;

        case fnv1a("--lua"):
            if (i + 1 >= pa.count)
            {
                std::cout << "--lua requires a Lua script path\n";
                return 1;
            }
            if (!instance->load_lua_script(pa.args[++i]))
            {
                std::cout << "could not load Lua script\n";
                return 1;
            }
            return 0;

        case fnv1a("-b"):
            instance->set_bash_output(true);
            return 0;

        case fnv1a("-bp"):
            instance->set_bash_output(true);
            instance->set_bash_prefix(true);
            return 0;

        case fnv1a("-bt"):
            instance->set_bash_output(true);
            instance->set_bash_timestamp(true);
            return 0;

        case fnv1a("-bpt"):
        case fnv1a("-btp"):
            instance->set_bash_output(true);
            instance->set_bash_prefix(true);
            instance->set_bash_timestamp(true);
            return 0;

        case fnv1a("--max-connections"):
        case fnv1a("--max-conn"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--max-connections requires a value\n";
                return 1;
            }
            uint32_t max;
            if (!parse_uint32(pa.args[++i], max))
            {
                std::cout << "invalid max-connections value\n";
                return 1;
            }
            instance->set_max_connections(max);
            return 0;
        }

        case fnv1a("--rate-limit"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--rate-limit requires a value\n";
                return 1;
            }
            double rate;
            if (!parse_double(pa.args[++i], rate) || rate < 0)
            {
                std::cout << "invalid rate-limit value\n";
                return 1;
            }
            instance->set_rate_limit(rate);
            return 0;
        }

        case fnv1a("--global-rate-limit"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--global-rate-limit requires a value\n";
                return 1;
            }
            double rate;
            if (!parse_double(pa.args[++i], rate) || rate < 0)
            {
                std::cout << "invalid global-rate-limit value\n";
                return 1;
            }
            instance->set_global_rate_limit(rate);
            return 0;
        }

        case fnv1a("--idle-timeout"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--idle-timeout requires a value\n";
                return 1;
            }
            uint32_t secs;
            if (!parse_uint32(pa.args[++i], secs))
            {
                std::cout << "invalid idle-timeout value\n";
                return 1;
            }
            instance->set_idle_timeout(secs);
            return 0;
        }

        case fnv1a("--drain"):
            instance->set_drain(true);
            return 0;

        case fnv1a("--reconnect"):
        {
            int max_attempts = 0; // default: infinite
            if (i + 1 < pa.count)
            {
                int val = 0;
                auto sv = std::string_view(pa.args[i + 1]);
                auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
                if (e == std::errc{} && p == sv.data() + sv.size())
                {
                    max_attempts = val;
                    i++;
                }
            }
            instance->set_reconnect(max_attempts);
            return 0;
        }

        case fnv1a("--tls"):
            instance->set_tls(true);
            return 0;

        case fnv1a("--cert"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--cert requires a file path\n";
                return 1;
            }
            instance->set_cert_path(pa.args[++i]);
            return 0;
        }

        case fnv1a("--key"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--key requires a file path\n";
                return 1;
            }
            instance->set_key_path(pa.args[++i]);
            return 0;
        }

        case fnv1a("--ca"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--ca requires a file path\n";
                return 1;
            }
            instance->set_ca_path(pa.args[++i]);
            return 0;
        }

        case fnv1a("--group"):
        case fnv1a("-g"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--group requires a value\n";
                return 1;
            }
            instance->set_group(pa.args[++i]);
            return 0;
        }

        default:
            return -1;
    }
}

bool parse_server_mode(uint32_t hash, server_mode& mode)
{
    switch (hash)
    {
        case fnv1a("inout"):  mode = mode_inout;  return true;
        case fnv1a("in"):     mode = mode_in;     return true;
        case fnv1a("out"):    mode = mode_out;     return true;
        case fnv1a("master"): mode = mode_master;  return true;
        default: return false;
    }
}

bool parse_client_mode(uint32_t hash, client_mode& mode)
{
    switch (hash)
    {
        case fnv1a("inout"): mode = client_mode_inout; return true;
        case fnv1a("in"):    mode = client_mode_in;    return true;
        case fnv1a("out"):   mode = client_mode_out;   return true;
        default: return false;
    }
}

bool parse_cache_mode(uint32_t hash, cache_mode& mode)
{
    switch (hash)
    {
        case fnv1a("readonly"):  mode = cache_mode_readonly;  return true;
        case fnv1a("readwrite"): mode = cache_mode_readwrite; return true;
        case fnv1a("admin"):     mode = cache_mode_admin;     return true;
        default: return false;
    }
}

int parse_server_flags(server_instance* srv, const parsed_args& pa, size_t& i,
                       runtime_manager* mgr, std::string_view name)
{
    switch (pa.hashes[i])
    {
        case fnv1a("--mode"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--mode requires a value\n";
                return 1;
            }
            ++i;
            server_mode mode;
            if (!parse_server_mode(pa.hashes[i], mode))
            {
                std::cout << "unknown mode: " << pa.args[i] << "\n";
                return 1;
            }
            srv->set_mode(mode);
            return 0;
        }
        case fnv1a("--cache"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--cache requires a cache name\n";
                return 1;
            }
            srv->set_cache_name(pa.args[++i]);
            srv->set_runtime_manager(mgr);
            return 0;
        }
        case fnv1a("--udp"):
            srv->set_udp(true);
            return 0;
        case fnv1a("--master-pw"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--master-pw requires a password\n";
                return 1;
            }
            srv->set_master_pw(pa.args[++i]);
            return 0;
        }
        case fnv1a("--master-forward"):
            srv->set_master_forward(true);
            return 0;
        case fnv1a("--http"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--http requires a directory path\n";
                return 1;
            }
            srv->set_http_dir(pa.args[++i]);
            return 0;
        }
        case fnv1a("--http-cache"):
            srv->set_http_cache(true);
            return 0;
        case fnv1a("-u"):
        case fnv1a("--upstream"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "-u requires host:port\n";
                return 1;
            }
            std::string_view upstream_str = pa.args[++i];
            // Parse semicolon-separated: "host1:port1;host2:port2"
            size_t start = 0;
            size_t semi;
            while ((semi = upstream_str.find(';', start)) != std::string_view::npos)
            {
                auto addr = upstream_str.substr(start, semi - start);
                if (!addr.empty())
                    srv->add_upstream_target(addr);
                start = semi + 1;
            }
            if (start < upstream_str.size())
                srv->add_upstream_target(upstream_str.substr(start));
            return 0;
        }
        default:
            return -1;
    }
}

int parse_client_flags(client_instance* cli, const parsed_args& pa, size_t& i,
                       std::string_view name)
{
    switch (pa.hashes[i])
    {
        case fnv1a("-t"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "-t requires a target address\n";
                return 1;
            }
            cli->set_target(pa.args[++i]);
            return 0;
        }
        case fnv1a("--mode"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--mode requires a value\n";
                return 1;
            }
            ++i;
            client_mode mode;
            if (!parse_client_mode(pa.hashes[i], mode))
            {
                std::cout << "unknown mode: " << pa.args[i] << "\n";
                return 1;
            }
            cli->set_mode(mode);
            return 0;
        }
        case fnv1a("--udp"):
            cli->set_udp(true);
            return 0;
        default:
            return -1;
    }
}

int parse_proxy_flags(proxy_instance* proxy, const parsed_args& pa, size_t& i,
                      std::string_view name)
{
    switch (pa.hashes[i])
    {
        case fnv1a("--backend"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--backend requires a value\n";
                return 1;
            }
            std::string_view backend_str = pa.args[++i];

            size_t start = 0;
            size_t comma;
            while ((comma = backend_str.find(',', start)) != std::string_view::npos)
            {
                proxy->add_backend(backend_str.substr(start, comma - start));
                start = comma + 1;
            }
            if (start < backend_str.size())
                proxy->add_backend(backend_str.substr(start));
            return 0;
        }
        case fnv1a("--strategy"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--strategy requires a value\n";
                return 1;
            }
            ++i;
            switch (pa.hashes[i])
            {
                case fnv1a("round-robin"):
                    proxy->set_strategy(strategy_round_robin);
                    break;
                case fnv1a("random"):
                    proxy->set_strategy(strategy_random);
                    break;
                case fnv1a("lua"):
                    proxy->set_strategy(strategy_lua);
                    break;
                default:
                    std::cout << "unknown strategy: " << pa.args[i] << "\n";
                    return 1;
            }
            return 0;
        }
        case fnv1a("--protocol"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--protocol requires a value\n";
                return 1;
            }
            ++i;
            switch (pa.hashes[i])
            {
                case fnv1a("http"):
                    proxy->set_protocol(protocol_http);
                    break;
                case fnv1a("tcp"):
                    proxy->set_protocol(protocol_tcp);
                    break;
                default:
                    std::cout << "unknown protocol: " << pa.args[i] << "\n";
                    return 1;
            }
            return 0;
        }
        case fnv1a("--health-check"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--health-check requires tcp or http\n";
                return 1;
            }
            ++i;
            switch (pa.hashes[i])
            {
                case fnv1a("tcp"):
                    proxy->set_health_check(mesh_config::health_tcp);
                    break;
                case fnv1a("http"):
                    proxy->set_health_check(mesh_config::health_http);
                    break;
                default:
                    std::cout << "unknown health-check type: " << pa.args[i] << "\n";
                    return 1;
            }
            return 0;
        }
        case fnv1a("--health-interval"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--health-interval requires a value\n";
                return 1;
            }
            int val;
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val <= 0)
            {
                std::cout << "invalid health-interval value\n";
                return 1;
            }
            proxy->set_health_interval(val);
            return 0;
        }
        case fnv1a("--health-path"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--health-path requires a value\n";
                return 1;
            }
            proxy->set_health_path(pa.args[++i]);
            return 0;
        }
        case fnv1a("--health-threshold"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--health-threshold requires a value\n";
                return 1;
            }
            int val;
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val <= 0)
            {
                std::cout << "invalid health-threshold value\n";
                return 1;
            }
            proxy->set_health_threshold(val);
            return 0;
        }
        case fnv1a("--circuit-threshold"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--circuit-threshold requires a value\n";
                return 1;
            }
            int val;
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val <= 0)
            {
                std::cout << "invalid circuit-threshold value\n";
                return 1;
            }
            proxy->set_circuit_threshold(val);
            return 0;
        }
        case fnv1a("--circuit-timeout"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--circuit-timeout requires a value\n";
                return 1;
            }
            int val;
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val <= 0)
            {
                std::cout << "invalid circuit-timeout value\n";
                return 1;
            }
            proxy->set_circuit_timeout(val);
            return 0;
        }
        case fnv1a("--retry"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--retry requires a value\n";
                return 1;
            }
            int val;
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val < 0)
            {
                std::cout << "invalid retry value\n";
                return 1;
            }
            proxy->set_retry_count(val);
            return 0;
        }
        case fnv1a("--retry-all"):
            proxy->set_retry_all(true);
            return 0;
        case fnv1a("--client-ca"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--client-ca requires a file path\n";
                return 1;
            }
            proxy->set_mesh_client_ca(pa.args[++i]);
            return 0;
        }
        case fnv1a("--client-cert"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--client-cert requires a file path\n";
                return 1;
            }
            proxy->set_mesh_client_cert(pa.args[++i]);
            return 0;
        }
        case fnv1a("--client-key"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--client-key requires a file path\n";
                return 1;
            }
            proxy->set_mesh_client_key(pa.args[++i]);
            return 0;
        }
        case fnv1a("--sidecar"):
            // Sidecar mode: shorthand for health-check tcp + circuit + retry + drain
            proxy->set_health_check(mesh_config::health_tcp);
            proxy->set_circuit_threshold(5);
            proxy->set_circuit_timeout(30);
            proxy->set_retry_count(2);
            proxy->set_drain(true);
            return 0;
        default:
            return -1;
    }
}

int parse_cache_flags(cache_instance* cache, const parsed_args& pa, size_t& i,
                      std::string_view name)
{
    switch (pa.hashes[i])
    {
        case fnv1a("--persistent"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--persistent requires a file path\n";
                return 1;
            }
            cache->set_persistent(pa.args[++i]);
            return 0;
        }
        case fnv1a("--mode"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--mode requires a value\n";
                return 1;
            }
            ++i;
            cache_mode mode;
            if (!parse_cache_mode(pa.hashes[i], mode))
            {
                std::cout << "unknown mode: " << pa.args[i] << "\n";
                return 1;
            }
            cache->set_mode(mode);
            return 0;
        }
        case fnv1a("--maxmemory"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--maxmemory requires a size value\n";
                return 1;
            }
            size_t bytes;
            if (!parse_size_suffix(pa.args[++i], bytes))
            {
                std::cout << "invalid maxmemory value (use K/M/G suffix)\n";
                return 1;
            }
            cache->set_max_memory(bytes);
            return 0;
        }
        case fnv1a("--eviction"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--eviction requires a policy\n";
                return 1;
            }
            ++i;
            switch (pa.hashes[i])
            {
                case fnv1a("noeviction"):
                    cache->set_eviction(evict_none);
                    break;
                case fnv1a("allkeys-lru"):
                    cache->set_eviction(evict_allkeys_lru);
                    break;
                case fnv1a("allkeys-random"):
                    cache->set_eviction(evict_allkeys_random);
                    break;
                default:
                    std::cout << "unknown eviction policy: " << pa.args[i] << "\n";
                    return 1;
            }
            return 0;
        }
        case fnv1a("--resp"):
            cache->set_resp_forced(true);
            return 0;
        case fnv1a("--replicate"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--replicate requires host:port\n";
                return 1;
            }
            cache->set_replicate_target(pa.args[++i]);
            return 0;
        }
        default:
            return -1;
    }
}

int parse_common_edit_flags(runtime_instance* instance, const parsed_args& pa,
                            size_t& i, bool is_running)
{
    switch (pa.hashes[i])
    {
        case fnv1a("-p"):
        {
            if (is_running)
            {
                std::cout << "cannot change port while running\n";
                return 1;
            }
            if (i + 1 >= pa.count)
            {
                std::cout << "-p requires a port number\n";
                return 1;
            }
            uint16_t port;
            if (!parse_uint16(pa.args[++i], port))
            {
                std::cout << "invalid port number\n";
                return 1;
            }
            instance->set_port(port);
            return 0;
        }
        case fnv1a("-b"):
            instance->set_bash_output(true);
            return 0;

        case fnv1a("-bp"):
            instance->set_bash_output(true);
            instance->set_bash_prefix(true);
            return 0;

        case fnv1a("-bt"):
            instance->set_bash_output(true);
            instance->set_bash_timestamp(true);
            return 0;

        case fnv1a("-bpt"):
        case fnv1a("-btp"):
            instance->set_bash_output(true);
            instance->set_bash_prefix(true);
            instance->set_bash_timestamp(true);
            return 0;

        case fnv1a("--log"):
            if (i + 1 >= pa.count)
            {
                std::cout << "--log requires a file path\n";
                return 1;
            }
            instance->set_log_file(pa.args[++i]);
            return 0;

        case fnv1a("-w"):
            if (i + 1 >= pa.count)
            {
                std::cout << "-w requires a file path\n";
                return 1;
            }
            instance->set_write_file(pa.args[++i]);
            return 0;

        case fnv1a("--max-connections"):
        case fnv1a("--max-conn"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--max-connections requires a value\n";
                return 1;
            }
            uint32_t max;
            if (!parse_uint32(pa.args[++i], max))
            {
                std::cout << "invalid max-connections value\n";
                return 1;
            }
            instance->set_max_connections(max);
            return 0;
        }

        case fnv1a("--rate-limit"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--rate-limit requires a value\n";
                return 1;
            }
            double rate;
            if (!parse_double(pa.args[++i], rate) || rate < 0)
            {
                std::cout << "invalid rate-limit value\n";
                return 1;
            }
            instance->set_rate_limit(rate);
            return 0;
        }

        case fnv1a("--global-rate-limit"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--global-rate-limit requires a value\n";
                return 1;
            }
            double rate;
            if (!parse_double(pa.args[++i], rate) || rate < 0)
            {
                std::cout << "invalid global-rate-limit value\n";
                return 1;
            }
            instance->set_global_rate_limit(rate);
            return 0;
        }

        case fnv1a("--idle-timeout"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--idle-timeout requires a value\n";
                return 1;
            }
            uint32_t secs;
            if (!parse_uint32(pa.args[++i], secs))
            {
                std::cout << "invalid idle-timeout value\n";
                return 1;
            }
            instance->set_idle_timeout(secs);
            return 0;
        }

        case fnv1a("--group"):
        case fnv1a("-g"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--group requires a value\n";
                return 1;
            }
            instance->set_group(pa.args[++i]);
            return 0;
        }

        default:
            return -1;
    }
}

int parse_server_edit_flags(server_instance* srv, const parsed_args& pa, size_t& i,
                            bool is_running, runtime_manager* mgr)
{
    switch (pa.hashes[i])
    {
        case fnv1a("--mode"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--mode requires a value\n";
                return 1;
            }
            ++i;
            server_mode mode;
            if (!parse_server_mode(pa.hashes[i], mode))
            {
                std::cout << "unknown mode: " << pa.args[i] << "\n";
                return 1;
            }
            srv->set_mode(mode);
            return 0;
        }
        case fnv1a("--cache"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--cache requires a cache name\n";
                return 1;
            }
            srv->set_cache_name(pa.args[++i]);
            srv->set_runtime_manager(mgr);
            return 0;
        }
        case fnv1a("--udp"):
        {
            if (is_running)
            {
                std::cout << "cannot change protocol while running\n";
                return 1;
            }
            srv->set_udp(true);
            return 0;
        }
        case fnv1a("--master-pw"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--master-pw requires a password\n";
                return 1;
            }
            srv->set_master_pw(pa.args[++i]);
            return 0;
        }
        case fnv1a("--master-forward"):
            srv->set_master_forward(true);
            return 0;
        case fnv1a("--http"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--http requires a directory path\n";
                return 1;
            }
            srv->set_http_dir(pa.args[++i]);
            return 0;
        }
        case fnv1a("--http-cache"):
            srv->set_http_cache(true);
            return 0;
        case fnv1a("-u"):
        case fnv1a("--upstream"):
        {
            if (is_running)
            {
                std::cout << "cannot change upstreams while running\n";
                return 1;
            }
            if (i + 1 >= pa.count)
            {
                std::cout << "-u requires host:port\n";
                return 1;
            }
            std::string_view upstream_str = pa.args[++i];
            size_t start = 0;
            size_t semi;
            while ((semi = upstream_str.find(';', start)) != std::string_view::npos)
            {
                auto addr = upstream_str.substr(start, semi - start);
                if (!addr.empty())
                    srv->add_upstream_target(addr);
                start = semi + 1;
            }
            if (start < upstream_str.size())
                srv->add_upstream_target(upstream_str.substr(start));
            return 0;
        }
        default:
            return -1;
    }
}

int parse_client_edit_flags(client_instance* cli, const parsed_args& pa, size_t& i,
                            bool is_running)
{
    switch (pa.hashes[i])
    {
        case fnv1a("-t"):
        {
            if (is_running)
            {
                std::cout << "cannot change target while running\n";
                return 1;
            }
            if (i + 1 >= pa.count)
            {
                std::cout << "-t requires a target address\n";
                return 1;
            }
            cli->set_target(pa.args[++i]);
            return 0;
        }
        case fnv1a("--mode"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--mode requires a value\n";
                return 1;
            }
            ++i;
            client_mode mode;
            if (!parse_client_mode(pa.hashes[i], mode))
            {
                std::cout << "unknown mode: " << pa.args[i] << "\n";
                return 1;
            }
            cli->set_mode(mode);
            return 0;
        }
        case fnv1a("--udp"):
        {
            if (is_running)
            {
                std::cout << "cannot change protocol while running\n";
                return 1;
            }
            cli->set_udp(true);
            return 0;
        }
        default:
            return -1;
    }
}

int parse_proxy_edit_flags(proxy_instance* proxy, const parsed_args& pa, size_t& i)
{
    switch (pa.hashes[i])
    {
        case fnv1a("--strategy"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--strategy requires a value\n";
                return 1;
            }
            ++i;
            switch (pa.hashes[i])
            {
                case fnv1a("round-robin"):
                    proxy->set_strategy(strategy_round_robin);
                    break;
                case fnv1a("random"):
                    proxy->set_strategy(strategy_random);
                    break;
                case fnv1a("lua"):
                    proxy->set_strategy(strategy_lua);
                    break;
                default:
                    std::cout << "unknown strategy: " << pa.args[i] << "\n";
                    return 1;
            }
            return 0;
        }
        case fnv1a("--health-check"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--health-check requires tcp or http\n";
                return 1;
            }
            ++i;
            switch (pa.hashes[i])
            {
                case fnv1a("tcp"):
                    proxy->set_health_check(mesh_config::health_tcp);
                    break;
                case fnv1a("http"):
                    proxy->set_health_check(mesh_config::health_http);
                    break;
                default:
                    std::cout << "unknown health-check type: " << pa.args[i] << "\n";
                    return 1;
            }
            return 0;
        }
        case fnv1a("--health-interval"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--health-interval requires a value\n";
                return 1;
            }
            int val;
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val <= 0)
            {
                std::cout << "invalid health-interval value\n";
                return 1;
            }
            proxy->set_health_interval(val);
            return 0;
        }
        case fnv1a("--health-path"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--health-path requires a value\n";
                return 1;
            }
            proxy->set_health_path(pa.args[++i]);
            return 0;
        }
        case fnv1a("--health-threshold"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--health-threshold requires a value\n";
                return 1;
            }
            int val;
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val <= 0)
            {
                std::cout << "invalid health-threshold value\n";
                return 1;
            }
            proxy->set_health_threshold(val);
            return 0;
        }
        case fnv1a("--circuit-threshold"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--circuit-threshold requires a value\n";
                return 1;
            }
            int val;
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val <= 0)
            {
                std::cout << "invalid circuit-threshold value\n";
                return 1;
            }
            proxy->set_circuit_threshold(val);
            return 0;
        }
        case fnv1a("--circuit-timeout"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--circuit-timeout requires a value\n";
                return 1;
            }
            int val;
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val <= 0)
            {
                std::cout << "invalid circuit-timeout value\n";
                return 1;
            }
            proxy->set_circuit_timeout(val);
            return 0;
        }
        case fnv1a("--retry"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--retry requires a value\n";
                return 1;
            }
            int val;
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val < 0)
            {
                std::cout << "invalid retry value\n";
                return 1;
            }
            proxy->set_retry_count(val);
            return 0;
        }
        case fnv1a("--retry-all"):
            proxy->set_retry_all(true);
            return 0;
        default:
            return -1;
    }
}
