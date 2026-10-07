#pragma once
// What the rest of socketley tells a dns runtime, through files in one directory of the daemon's state, which a dns
// runtime already looks at once a second:
//
//   names            the names runtimes are reached by (--domain, --acme, a storage's --domain and --website-domain),
//                    one a line, written by the daemon whenever they change; a dns runtime with --publish gives each
//                    one under its zones the addresses --publish names
//   acme-<token>     one line, "<name> <value>": an ACME DNS-01 answer, written by `socketley acme issue` while a CA
//                    checks it and removed after; served as the TXT record of _acme-challenge.<name>
//
// Files rather than messages because each side already has what it takes: the daemon writes its state there, and a
// dns runtime, in a worker process of its own, reads a file when it changes. The directory's own time is when the
// set last changed, and a dns runtime adds it to the serial it serves, so a secondary sees a change it made.
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace dns_feed
{

// The directory, created when first written.
std::string dir();

// The names, rewritten only when they differ from what is there, so the directory's time moves only on a change.
bool write_names(const std::vector<std::string>& names);

// An ACME DNS-01 answer for `name` (without "_acme-challenge."); its file, for removing it after.
bool write_challenge(std::string_view name, std::string_view value, std::string_view token, std::string& path);

struct snapshot
{
    std::vector<std::string> names;
    // Name (the one asked about, without "_acme-challenge.") and TXT value.
    std::vector<std::pair<std::string, std::string>> challenges;
    // The directory's modification time, nanoseconds; 0 when there is none.
    int64_t stamp_ns{0};
};

// What the directory holds now; an absent directory is an empty snapshot.
snapshot read();

// The directory's modification time alone, for asking cheaply whether anything changed.
int64_t stamp_ns();

// Whether `name` is one a runtime may be reached by: labels of letters, digits and hyphens, optionally led by "*.",
// relative (no dot) or absolute; false with the reason.
bool valid_name(std::string_view name, std::string& why);

}   // namespace dns_feed
