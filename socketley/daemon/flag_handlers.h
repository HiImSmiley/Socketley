#pragma once
#include <string>
#include <string_view>
#include <cstdint>
#include <charconv>
#include <limits>

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

// The same contract as the two above: the whole string, or nothing.
//
// std::stod stops at the first character it cannot use and reports success for
// what it read, so `--rate-limit 5abc` was accepted as 5 and `--rate-limit 0x10`
// as 16.  It also throws, which is why it is wrapped — and the wrapper is the
// reason this one allocates a std::string under a comment promising
// allocation-free parsing.  The position stod reports is what closes the gap.
inline bool parse_double(std::string_view sv, double& out)
{
    if (sv.empty()) return false;
    // Simple manual parse for doubles (from_chars for double is not always available)
    try {
        std::string s(sv);
        size_t consumed = 0;
        const double v = std::stod(s, &consumed);
        if (consumed != s.size()) return false;
        out = v;
        return true;
    } catch (...) {
        return false;
    }
}

// Parse size with optional K/M/G suffix (e.g. "100M" -> 104857600)
//
// ─── TWO THINGS THIS DID NOT CHECK, AND WHAT THEY COST ──────────────────────
//
// The two parsers above both end with `ptr == sv.data() + sv.size()` — the
// whole string had to be consumed.  This one did not, and from_chars reports
// success for a prefix.  So a suffix it does not know was simply left on the
// end and the number in front of it taken:
//
//     --maxmemory 100M    ->  104857600     correct
//     --maxmemory 100MB   ->        100     accepted
//     --maxmemory 100X    ->        100     accepted
//
// `100MB` is the likeliest typo there is for a size, and it configured a cache
// to a hundred bytes — one that runs, accepts connections and stores nothing.
//
// The multiplication was unchecked as well, and that one is worse for being
// plausible: 2^34 G is exactly 2^64, so it wraps to zero —
//
//     --maxmemory 17179869184G  ->  0
//
// and 0 is documented as "unlimited" (socketley.1, MEMORY).  Asking for an
// absurdly high cap therefore removed the cap, which is the one direction a
// misread limit must never fail in.
//
// Both are refusals now rather than corrections: there is no reading of `100MB`
// that is safe to guess at, and the flag's own error names the suffixes.
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

    // The whole of it, digits and one known suffix and nothing else.
    if (ptr != num_part.data() + num_part.size()) return false;

    // Checked before it is done, not after: the wrapped value is
    // indistinguishable from a legitimate small one.
    //
    // size_t is the accumulator rather than uint64_t, so the bound is the one
    // the caller will actually store into.  On this target they are the same
    // width and the static_assert says so out loud — written the other way
    // round, a `bytes > size_t::max()` after the fact would be an always-false
    // comparison here and a real one on a 32-bit build, which is the sort of
    // check that reads as covered and is not.
    static_assert(sizeof(size_t) >= sizeof(uint32_t),
                  "parse_size_suffix accumulates into size_t");
    if (val > static_cast<uint64_t>(std::numeric_limits<size_t>::max()) / multiplier)
        return false;

    out = static_cast<size_t>(val) * multiplier;
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
//
// `lua_script` is an out-parameter and not something this function acts on, and
// that is the whole point of it — see the --lua case for why loading a script
// in the middle of a flag loop made `create` depend on the order the flags were
// typed.  The caller loads it once every flag has been seen.
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
