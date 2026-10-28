#pragma once
// The Sender Rewriting Scheme: a message an alias forwards to another domain goes from an address of this runtime's
// domain that names the original sender, so SPF at the far end judges this host and a bounce still finds its way
// back.  SRS0=<hash>=<time>=<domain>=<local>@<ours> for a sender of elsewhere, SRS1=<hash>=<first forwarder>==<rest>
// for one another forwarder rewrote, as Shevek's scheme and Postfix's postsrsd write them; the hash is eight base32
// characters (40 bits, whatever a relay does to case) of an HMAC under a key of the runtime's own, the time its day,
// and an address older than 21 days by its own stamp or, for SRS1, by the first forwarder's, or not of this key, is no
// address.
#include <cstdint>
#include <string>
#include <string_view>

namespace socketley::mail::srs
{

// `sender` (local@domain) rewritten to be sent from `domain` on `day` (days since the epoch); `sender` as it is where
// it is empty, a bounce's, already of `domain`, or of a host holding '='.
std::string forward(std::string_view sender, std::string_view domain, std::string_view key, int64_t day);

// The address an SRS address of `domain` stands for, checked against `key` and `day`; empty where it is none, its
// hash is not this key's, or it is past 21 days.
std::string reverse(std::string_view address, std::string_view domain, std::string_view key, int64_t day);

}   // namespace socketley::mail::srs
