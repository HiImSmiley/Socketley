#pragma once
#include <cstdint>
#include <cstddef>
#include <string_view>
#include "command_hashing.h"

// Wide enough for the longest create a configuration file can ask for, which
// is a proxy carrying every flag its type accepts at sixty-nine tokens.
constexpr size_t MAX_ARGS = 96;

struct parsed_args
{
    std::string_view args[MAX_ARGS];
    uint32_t hashes[MAX_ARGS];
    size_t count = 0;

    // The line held more tokens than there are slots, and the last slot is
    // carrying all of them.
    bool overflowed = false;

    // The last slot takes the whole remainder, because everything past
    // MAX_ARGS used to be dropped silently -- a forty-word cache value arrived
    // as twenty-eight -- while a command whose arguments are a list is refused
    // by the caller on the flag below.
    void parse(std::string_view line)
    {
        count = 0;
        overflowed = false;
        size_t i = 0;
        while (i < line.size() && count < MAX_ARGS)
        {
            while (i < line.size() && (line[i] == ' ' || line[i] == '\t'))
                ++i;
            if (i >= line.size()) break;

            size_t start = i;

            if (count == MAX_ARGS - 1)
            {
                // The last slot: everything that is left, trailing whitespace
                // trimmed so a line ending in spaces does not become a token
                // with spaces on the end of it.
                size_t end = line.size();
                while (end > start && (line[end - 1] == ' ' || line[end - 1] == '\t'))
                    --end;

                args[count]   = line.substr(start, end - start);
                hashes[count] = fnv1a(args[count]);
                ++count;

                // Exactly MAX_ARGS tokens is not an overflow, because the last
                // slot then holds one token and contains no separator.
                overflowed = args[count - 1].find_first_of(" \t") != std::string_view::npos;
                break;
            }

            while (i < line.size() && line[i] != ' ' && line[i] != '\t')
                ++i;

            args[count] = line.substr(start, i - start);
            hashes[count] = fnv1a(args[count]);
            ++count;
        }
    }

    std::string_view rest_from(size_t idx) const
    {
        if (idx >= count) return {};
        const char* start = args[idx].data();
        const char* end = args[count - 1].data() + args[count - 1].size();
        return std::string_view(start, end - start);
    }
};
