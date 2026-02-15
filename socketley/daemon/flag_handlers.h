#pragma once
#include <string>
#include <string_view>
#include <cstdint>
#include <charconv>

#include "../cli/arg_parser.h"
#include "../cli/command_hashing.h"
#include "../shared/runtime_definitions.h"

// Allocation-free integer parsing from string_view
inline bool parse_uint16(std::string_view sv, uint16_t& out)
{
    auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), out);
    return ec == std::errc{} && ptr == sv.data() + sv.size();
}

inline bool parse_uint32(std::string_view sv, uint32_t& out)
{
    auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), out);
    return ec == std::errc{} && ptr == sv.data() + sv.size();
}

inline bool parse_double(std::string_view sv, double& out)
{
    // Simple manual parse for doubles (from_chars for double is not always available)
    try {
        std::string s(sv);
        out = std::stod(s);
        return true;
    } catch (...) {
        return false;
    }
}

// Parse size with optional K/M/G suffix (e.g. "100M" -> 104857600)
inline bool parse_size_suffix(std::string_view sv, size_t& out)
{
    if (sv.empty()) return false;
    size_t multiplier = 1;
    std::string_view num_part = sv;
    char last = sv.back();
    if (last == 'K' || last == 'k') { multiplier = 1024; num_part = sv.substr(0, sv.size()-1); }
    else if (last == 'M' || last == 'm') { multiplier = 1024*1024; num_part = sv.substr(0, sv.size()-1); }
    else if (last == 'G' || last == 'g') { multiplier = 1024ULL*1024*1024; num_part = sv.substr(0, sv.size()-1); }
    uint64_t val;
    auto [ptr, ec] = std::from_chars(num_part.data(), num_part.data() + num_part.size(), val);
    if (ec != std::errc{}) return false;
    out = static_cast<size_t>(val * multiplier);
    return true;
}

class runtime_instance;
class runtime_manager;
class server_instance;
class client_instance;
class proxy_instance;
class cache_instance;

enum server_mode : uint8_t;
enum client_mode : uint8_t;
enum cache_mode : uint8_t;

// Result codes: 0 = handled, 1 = error, -1 = not handled (try type-specific)
int parse_common_flags(runtime_instance* instance, const parsed_args& pa,
                       size_t& i, bool& autostart);

int parse_server_flags(server_instance* srv, const parsed_args& pa, size_t& i,
                       runtime_manager* mgr, std::string_view name);

int parse_client_flags(client_instance* cli, const parsed_args& pa, size_t& i,
                       std::string_view name);

int parse_proxy_flags(proxy_instance* proxy, const parsed_args& pa, size_t& i,
                      std::string_view name);

int parse_cache_flags(cache_instance* cache, const parsed_args& pa, size_t& i,
                      std::string_view name);

// Mode parsing helpers
bool parse_server_mode(uint32_t hash, server_mode& mode);
bool parse_client_mode(uint32_t hash, client_mode& mode);
bool parse_cache_mode(uint32_t hash, cache_mode& mode);

// Edit command flag parsers (with running state check)
int parse_common_edit_flags(runtime_instance* instance, const parsed_args& pa,
                            size_t& i, bool is_running);

int parse_server_edit_flags(server_instance* srv, const parsed_args& pa, size_t& i,
                            bool is_running, runtime_manager* mgr);

int parse_client_edit_flags(client_instance* cli, const parsed_args& pa, size_t& i,
                            bool is_running);

int parse_proxy_edit_flags(proxy_instance* proxy, const parsed_args& pa, size_t& i);
