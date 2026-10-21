#pragma once
// What the rest of socketley tells a dns runtime, through files in one directory of the daemon's state, which a dns
// runtime already looks at once a second:
//
//   names            the names runtimes are reached by (--domain, --acme, a storage's --domain and --website-domain),
//                    one a line, written by the daemon whenever they change; a dns runtime with --publish gives each
//                    one under its zones the addresses --publish names
//   routes-<proxy>   the table an entrance (a proxy without --backend) routes by, written by the daemon: the zones of
//                    the dns runtimes that name it with --proxy, and each name of a runtime that speaks HTTP with
//                    the addresses it listens on
//   acme-<token>     one line, "<name> <value>": an ACME DNS-01 answer, written by `socketley acme issue` while a CA
//                    checks it and removed after; served as the TXT record of _acme-challenge.<name>
//   records-<rt>     master-file lines with absolute owners, a runtime's records for the zones they fall in: a mail
//                    runtime's MX, SPF, DKIM and DMARC; the zone file wins where it names the type at the name
//
// Beside the directory, as .dns-zones, the daemon writes "<dns runtime> <origin>" lines: the zones each dns runtime
// serves, which a mail runtime reads for its domains and which would move every serial if they lay inside.
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

// The table entrance `name` routes by (runtime_names::entrance_table), rewritten only when it changes; and those of
// entrances that are gone, removed.
bool write_routes(std::string_view entrance, std::string_view table);
void remove_routes_except(const std::vector<std::string>& entrances);
// The file entrance `name` reads.
std::string routes_path(std::string_view entrance);

// A runtime's records, rewritten only when they change; removed when `text` is empty.
bool write_records(std::string_view runtime, std::string_view text);
// The zones of every dns runtime, "<runtime> <origin>" a line, rewritten only when they change.
bool write_zones(std::string_view text);
// Those zones read back, each runtime's origins in the order written.
std::vector<std::pair<std::string, std::string>> read_zones();

struct snapshot
{
    std::vector<std::string> names;
    // Every runtime's record lines.
    std::vector<std::string> records;
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
