#pragma once
// DNSSEC for the zones a dns runtime serves with --dnssec (RFC 4033-4035): each zone signed as it is loaded, with a
// combined key of ECDSA P-256 and SHA-256 (algorithm 13, RFC 6605) kept under the runtime's state, its DNSKEY at the
// apex, an NSEC chain through its names and an RRSIG over every set it is authoritative for.  An answer carries them
// where the query asked with the DO bit; the parent zone is given the DS record the CLI prints.
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

#include "dns_zone.h"

typedef struct evp_pkey_st EVP_PKEY;

namespace socketley::dns
{

namespace type_sec
{
inline constexpr uint16_t RRSIG = 46, NSEC = 47, DNSKEY = 48;
}

// A zone is signed afresh each week, the same week on every shard, and a signature holds three weeks from its
// week's start; each week raises the serial by one, so a secondary copies the new signatures before the old end.
inline constexpr uint32_t signature_days = 21;
inline constexpr int64_t sign_period_s = 7 * 86400;
inline int64_t sign_epoch(int64_t now_s) { return now_s / sign_period_s; }

struct zone_key
{
    std::shared_ptr<EVP_PKEY> pkey;
    // The DNSKEY's data: flags 257, protocol 3, algorithm 13 and the public point's x and y.
    std::string dnskey;
    uint16_t tag{0};
};

// The key of zone `origin` (wire form) kept in `dir`, made there the first time, so every shard signs with one key;
// false with why where it can neither be read nor made.
bool load_or_make_key(const std::string& dir, std::string_view origin, zone_key& out, std::string& why);

// A zone's signatures by what they were made over, so a reload signs only the sets that changed: a signature over
// the same bytes with the same key is the same signature, as its nonce is derived from them (RFC 6979).
struct signature_cache
{
    std::unordered_map<std::string, std::string> sigs;
    uint64_t made{0};
    uint64_t kept{0};
};

// `z` signed with `key` at `now_s`: its DNSKEY, NSEC chain and RRSIGs added, each taken from `cache` where it holds
// one over the same bytes, and the cache left holding this signing's; false where a signature failed.
bool sign_zone(zone& z, const zone_key& key, int64_t now_s, signature_cache* cache = nullptr);

// RFC 4034 Appendix B.
uint16_t key_tag(std::string_view dnskey_rdata);

// The DS record of a zone's key as its parent publishes it, digest SHA-256, in presentation form.
std::string ds_text(std::string_view origin, const zone_key& key);

// Whether `a` sorts before `b` in DNSSEC's canonical order (RFC 4034 6.1); both lower-case wire form.
bool canonical_less(std::string_view a, std::string_view b);

// The owner of the NSEC whose span covers `name`, the last owner before it in the chain and the last of all for one
// before the first; empty for an unsigned zone.
std::string_view covering(const zone& z, std::string_view name);

}   // namespace socketley::dns
