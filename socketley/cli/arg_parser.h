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

    void parse(std::string_view line)
    {
        count = 0;
        size_t i = 0;
        while (i < line.size() && count < MAX_ARGS)
        {
            while (i < line.size() && (line[i] == ' ' || line[i] == '\t'))
                ++i;
            if (i >= line.size()) break;

            size_t start = i;
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
