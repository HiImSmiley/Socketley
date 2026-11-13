// Fuzz target: the state file's JSON reader (socketley/shared/persist/state_persistence.cpp), the hand-written getters
// that parse_json_string() reads a runtime's file and an `import` document with.
//
// Reachable by whoever may write a runtime's state file or send `socketley import`: the operator, or a process that
// can reach the control socket. There is no privilege boundary behind it -- such a caller may already give a runtime
// a script -- so what is at stake is the daemon itself: a file left half-written by a crash, or an import typed by
// hand, must not crash it or read back as something other than it says.
//
// An input is: one byte naming the type assumed for a document that gives none (as an import for a runtime that
// exists may leave it out), then the document.
//
// What must hold, beside no report from the sanitizers:
//
//   * A document the reader takes is written back by format_json_pretty() as one it takes again, and that one reads
//     back as the same configuration: writing it a second time gives the same bytes. A state file is read at every
//     start and written at every change, so a field that drifts between the two is a setting that changes by itself.
//   * raw_field() names nothing that is not in the document.

#include <optional>
#include <string>

#include "fuzz_common.h"

#include "../../socketley/shared/persist/state_persistence.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz::set_current(data, size);
    if (size < 1 || size > (64u << 10))
        return 0;
    // An empty directory makes the object a parser and nothing else: no writer thread, no file.
    static const state_persistence parser{std::filesystem::path{}};
    const std::optional<runtime_type> assumed =
        data[0] < 0x80 ? std::optional<runtime_type>(static_cast<runtime_type>(data[0] % 15)) : std::nullopt;
    const std::string json(reinterpret_cast<const char*>(data) + 1, size - 1);

    for (const char* key : {"name", "listen", "type", "extra", "backends"})
    {
        const std::string raw = parser.raw_field(json, key);
        FUZZ_CHECK(raw.size() <= json.size(), "a raw field longer than the document it was read from");
    }

    runtime_config first;
    if (!parser.parse_json_string(json, first, assumed))
        return 0;
    const std::string written = parser.format_json_pretty(first);

    runtime_config again;
    FUZZ_CHECK(parser.parse_json_string(written, again, assumed), "a state file this side wrote does not read back");
    const std::string rewritten = parser.format_json_pretty(again);
    if (rewritten != written)
    {
        size_t at = 0;
        while (at < written.size() && at < rewritten.size() && written[at] == rewritten[at])
            ++at;
        const size_t from = at > 60 ? at - 60 : 0;
        fuzz::dump("written", reinterpret_cast<const uint8_t*>(written.data()) + from,
                   std::min<size_t>(written.size() - from, 160));
        fuzz::dump("read and written again", reinterpret_cast<const uint8_t*>(rewritten.data()) + from,
                   std::min<size_t>(rewritten.size() - from, 160));
    }
    FUZZ_CHECK(rewritten == written, "a state file read back and written again is not the file it was");
    return 0;
}
