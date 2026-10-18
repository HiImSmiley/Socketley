#pragma once
// A document of the db runtime is a JSON object, read strictly by storage's json_reader and written back here; a
// field is reached by a dotted path, and a value is ordered for an index by its kind first and then within it.
#include <cstdint>
#include <string>
#include <string_view>

#include "../../shared/json/json_doc.h"

namespace socketley::db
{

using socketley::json::jvalue;
using socketley::json::json_reader;
using socketley::json::member;

// A path is at most this many names deep, each 1 to 64 of A-Z a-z 0-9 _ -.
inline constexpr size_t max_path_depth = 8;

// `v` as JSON, appended to `out`; a number is written as it was read.

// Whether `path` is names joined by dots that a document may hold.
bool valid_path(std::string_view path);

// The value at `path` in the object `doc`, null when a step is absent or not an object.
const jvalue* at_path(const jvalue& doc, std::string_view path);
// The member at `path`, made with the objects leading to it; null with `why` when a step on the way is not an object.
jvalue* make_path(jvalue& doc, std::string_view path, std::string& why);
// The member at `path` taken out; false when it was not there.
bool erase_path(jvalue& doc, std::string_view path);


// Two values the same: numbers by their value, objects member for member in any order.
bool same(const jvalue& a, const jvalue& b);

// A value as an index orders it: absent and null, then false, true, numbers, strings, and arrays and objects by
// their JSON, so a range never mixes kinds.
struct ikey
{
    enum rank_t : uint8_t { null = 0, no = 1, yes = 2, number = 3, string = 4, other = 5 };
    uint8_t rank{null};
    double num{0};
    std::string str;

    friend bool operator<(const ikey& a, const ikey& b)
    {
        if (a.rank != b.rank)
            return a.rank < b.rank;
        if (a.rank == number)
            return a.num < b.num;
        return a.str < b.str;
    }
    friend bool operator==(const ikey& a, const ikey& b)
    {
        return a.rank == b.rank && (a.rank == number ? a.num == b.num : a.str == b.str);
    }
};

ikey key_of(const jvalue* v);

// A number's value; false for one too large for a double to hold.
bool number_of(const jvalue& v, double& out);

}   // namespace socketley::db
