#pragma once
#include <cmath>
#include <string>
#include <string_view>
#include <cstdint>
#include <charconv>
#include <limits>

#include "../cli/arg_parser.h"
#include "../cli/command_hashing.h"
#include "../shared/runtime/runtime_definitions.h"
#include "../shared/util/size_suffix.h"
#include "../shared/util/number_parse.h"

// parse_double is the one number not read by parse_whole, because std::stod
// takes a std::string and from_chars for double is not available everywhere.
// The whole string or nothing, because std::stod reports success for a prefix
// and accepted `5abc` as 5, and the position it reports is what closes the
// gap.
inline bool parse_double(std::string_view sv, double& out)
{
    if (sv.empty()) return false;
    // Simple manual parse for doubles (from_chars for double is not always available)
    try {
        std::string s(sv);
        size_t consumed = 0;
        const double v = std::stod(s, &consumed);
        if (consumed != s.size()) return false;
        // "nan" parses, and NaN is false against every comparison a caller then
        // makes: `rate < 0` does not reject it and `rate > 0` does not accept
        // it, so --rate-limit nan was taken and meant no rate limit at all --
        // measured at 40 of 40 commands served where a limit of 5 served 5.
        // An infinity is left alone: for a rate that is a thing to mean.
        if (std::isnan(v)) return false;
        out = v;
        return true;
    } catch (...) {
        return false;
    }
}

class runtime_instance;
class runtime_manager;
class server_instance;
class client_instance;
class proxy_instance;
class cache_instance;
class storage_instance;
class dns_instance;
class sync_instance;
class idp_instance;
class tunnel_instance;
class db_instance;
class mqtt_instance;
class mail_instance;

enum server_mode : uint8_t;
enum client_mode : uint8_t;
enum cache_mode : uint8_t;

// 0 = handled, 1 = error, -1 = not handled, with `lua_script` an out-parameter
// so the caller loads it once every flag has been seen rather than mid-loop.
int parse_common_flags(runtime_instance* instance, const parsed_args& pa,
                       size_t& i, bool& autostart, std::string& lua_script);

int parse_server_flags(server_instance* srv, const parsed_args& pa, size_t& i,
                       runtime_manager* mgr, std::string_view name);

int parse_client_flags(client_instance* cli, const parsed_args& pa, size_t& i,
                       std::string_view name);

int parse_proxy_flags(proxy_instance* proxy, const parsed_args& pa, size_t& i,
                      std::string_view name);

int parse_cache_flags(cache_instance* cache, const parsed_args& pa, size_t& i,
                      std::string_view name);

int parse_storage_flags(storage_instance* stg, const parsed_args& pa, size_t& i,
                        std::string_view name);

int parse_dns_flags(dns_instance* dns, const parsed_args& pa, size_t& i, std::string_view name);
int parse_sync_flags(sync_instance* sy, const parsed_args& pa, size_t& i, std::string_view name);
int parse_idp_flags(idp_instance* ip, const parsed_args& pa, size_t& i, std::string_view name);
int parse_tunnel_flags(tunnel_instance* tn, const parsed_args& pa, size_t& i, std::string_view name);
int parse_db_flags(db_instance* db, const parsed_args& pa, size_t& i, std::string_view name);
int parse_mqtt_flags(mqtt_instance* mq, const parsed_args& pa, size_t& i, std::string_view name);
int parse_mail_flags(mail_instance* ml, const parsed_args& pa, size_t& i, std::string_view name);

// A `--listen` value, one function because the flag and an `import` document's
// "listen" field must judge it the same way, returning an empty string on
// success with the bare path in `out` and the reason otherwise.
std::string validate_listen_value(std::string_view value, std::string& out);

// Mode parsing helpers
bool parse_server_mode(uint32_t hash, server_mode& mode);
bool parse_server_send_to(std::string_view value, uint8_t& mask, std::string& bad);
bool parse_client_mode(uint32_t hash, client_mode& mode);
bool parse_cache_mode(uint32_t hash, cache_mode& mode);

// Edit command flag parsers (with running state check)
int parse_common_edit_flags(runtime_instance* instance, const parsed_args& pa,
                            size_t& i, bool is_running);

int parse_server_edit_flags(server_instance* srv, const parsed_args& pa, size_t& i,
                            bool is_running, runtime_manager* mgr);

int parse_client_edit_flags(client_instance* cli, const parsed_args& pa, size_t& i,
                            bool is_running);

int parse_proxy_edit_flags(proxy_instance* proxy, const parsed_args& pa, size_t& i, bool is_running);
