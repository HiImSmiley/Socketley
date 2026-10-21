#pragma once
// What a domain says of the TLS its mail is sent over: an MTA-STS policy (RFC 8461), served over HTTPS and named by
// a TXT record, which says which exchangers are its own and that each must show a certificate for its name; and the
// TLSA records DANE (RFC 7672) puts beside an exchanger in a zone DNSSEC signs, which name the certificate itself.
// The parsing and the matching are here; the lookups, the fetch and the connections are the delivery's.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace socketley::mail::tls_policy
{

enum class sts_mode : uint8_t { none, testing, enforce };

struct sts
{
    std::string id;
    sts_mode mode{sts_mode::none};
    std::vector<std::string> mx;
    // When the policy stops counting, in Unix seconds: its fetch plus its max_age.
    int64_t expires_s{0};
};

// The id of `txt` where it is an MTA-STS record ("v=STSv1; id=..."), false where it is none.
bool sts_record_id(std::string_view txt, std::string& id);
// The policy the well-known URL served, its max_age in `max_age_s`; false with `why` for one that is not.
bool parse_sts(std::string_view text, sts& out, int64_t& max_age_s, std::string& why);
// Whether `host` is one of the policy's exchangers: a name it lists, or one label under a "*." it lists.
bool mx_matches(const sts& p, std::string_view host);
// One line of the cache a restart reads back, and the line read.
std::string cache_line(const std::string& domain, const sts& p);
bool from_cache_line(std::string_view line, std::string& domain, sts& p);

struct tlsa
{
    uint8_t usage{0}, selector{0}, mtype{0};
    std::string data;
};
// A TLSA record's data as it came; false for one too short.
bool parse_tlsa(std::string_view rdata, tlsa& out);
// DANE-TA (2) and DANE-EE (3) with a selector and a matching type there are, the ones SMTP uses (RFC 7672 3.1).
bool usable(const tlsa& t);

}   // namespace socketley::mail::tls_policy
