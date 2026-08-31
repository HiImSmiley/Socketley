#pragma once
// The usage line for a daemon verb, in one place because the CLI answers
// `<verb> --help` without a daemon and the daemon answers a short argv, and two
// copies of the same sentence drift.
#include <string>
#include <string_view>

namespace command_usage {

// Empty for a verb that has no usage line of its own, which the caller reads as
// "not a daemon verb" rather than as an empty answer.
inline constexpr std::string_view for_verb(std::string_view verb)
{
    if (verb == "create") return "create <type> <name> [flags]";
    if (verb == "start")  return "start <name|pattern>... [-i]";
    if (verb == "stop")   return "stop <name|pattern>...";
    if (verb == "remove") return "remove <name|pattern>...";
    if (verb == "owner")  return "owner <name>";
    if (verb == "send")   return "send <name> <message>";
    if (verb == "edit")   return "edit <name> [flags]";
    if (verb == "show")   return "show <name|pattern>...";
    if (verb == "import") return "import <name> <json>";
    return {};
}

// The one verb that also reads its message from a pipe, said here so the short
// form and `--help` cannot answer with different halves of it.
inline constexpr std::string_view second_line(std::string_view verb)
{
    if (verb == "send") return "       echo 'msg' | socketley send <name>";
    return {};
}

// The whole answer, so a call site spells the verb once and neither end owns
// the wording.
inline std::string line(std::string_view verb)
{
    std::string out = "usage: " + std::string(for_verb(verb)) + "\n";
    if (const std::string_view s = second_line(verb); !s.empty())
        out += std::string(s) + "\n";
    return out;
}

}  // namespace command_usage
