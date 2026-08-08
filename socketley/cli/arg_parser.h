#pragma once
#include <cstdint>
#include <cstddef>
#include <string_view>
#include "command_hashing.h"

constexpr size_t MAX_ARGS = 32;

struct parsed_args
{
    std::string_view args[MAX_ARGS];
    uint32_t hashes[MAX_ARGS];
    size_t count = 0;

    // The line held more tokens than there are slots, and the last slot is
    // carrying all of them.  See parse().
    bool overflowed = false;

    // ─── WHAT USED TO HAPPEN PAST THE THIRTY-SECOND WORD ────────────────────
    //
    // The loop stopped at MAX_ARGS and the rest of the line was never looked
    // at.  rest_from() spans from one argument to the end of the LAST one, so
    // everything past the limit was simply gone — silently, with exit 0.
    // Measured, a cache SET with a forty-word value:
    //
    //     socketley c1 set k1 w0 w1 ... w39     exit 0
    //     socketley c1 get k1 | wc -w           28
    //
    // Twelve words dropped, and the failure only shows up later, when the
    // source of the value is no longer around to compare against.  For a cache
    // that is the worst property it could have.
    //
    // The last slot takes the whole remainder now, so rest_from() covers the
    // line again and a message, a value or a document arrives entire.  What
    // that cannot fix is a command whose arguments are a LIST — `start a b c`
    // past the limit would take the tail as one impossible name, and `create`
    // would lose flags.  Those are refused instead, by the caller, on the flag
    // below: process_command() knows which commands end in free text and which
    // do not, and this struct does not.
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

                // Exactly MAX_ARGS tokens is not an overflow: the last slot
                // then holds one token and contains no separator.  More than
                // that, and it holds several.
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
