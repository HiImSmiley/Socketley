#pragma once
// ARC (RFC 8617): the chain of seals forwarders put on a message, checked as it comes so a forwarder trusted here can
// vouch for mail its forwarding broke DMARC for, and a set of this runtime's own added to mail it forwards.  Pure
// functions of their bytes and of the keys looked up for them, so both run on a helper thread.
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

#include <openssl/evp.h>

namespace socketley::mail::arc
{

struct chain
{
    // none, pass or fail (RFC 8617 4.4), how many sets the message holds, and the domain of the newest seal.
    std::string result{"none"};
    int count{0};
    std::string sealer;
    std::string why;
};

// The TXT a selector names (`s._domainkey.d`), empty where there is none; false where the lookup failed for now.
using key_lookup = std::function<bool(const std::string& name, std::string& record)>;

// The chain of `message` checked: the newest set's message signature, and every seal in turn.
chain verify(std::string_view message, const key_lookup& key_of, int64_t now_s);

// A new set's headers, its seal first and each ended by CRLF, to put ahead of `message`: the results this host found,
// under `authserv`, signed and sealed for `domain` by `key`, with `cv` what the chain was found to be; empty where the
// message holds 50 sets already or the signing failed.
std::string seal(std::string_view message, std::string_view authserv, std::string_view results, std::string_view domain,
                 std::string_view selector, EVP_PKEY* key, int64_t now_s, std::string_view cv);

}   // namespace socketley::mail::arc
