#pragma once
// A regular expression matched in time linear in the string: RE2's syntax against a whole string, as Prometheus anchors
// every label matcher, or POSIX's extended syntax searched for anywhere, as Sieve's :regex asks.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace socketley
{

class regex
{
public:
    enum class syntax : uint8_t { re2, posix_extended };

    // False with `why` set when the pattern is not syntax this engine reads, where `.` matches a newline in both,
    // `search` finds the leftmost match anywhere (group 0 spanning it) and `fold` takes ASCII letters in either case.
    bool compile(std::string_view pattern, std::string& why, syntax dialect = syntax::re2, bool search = false,
                 bool fold = false);

    bool matches(std::string_view s) const;
    // The byte offsets of each group of a match, begin and end per group, -1 for a group that took no part; `most`
    // bounds how many groups are tracked, which is what a match's cost grows with.
    bool matches(std::string_view s, std::vector<int>& groups, int most = -1) const;

    // What one byte of a string can cost at most, in instructions, which with the groups tracked bounds a match.
    size_t program_size() const { return m_prog.size(); }

    // Groups including the whole match, group 0.
    int  group_count() const { return m_groups; }
    int  group_named(std::string_view name) const;
    bool matches_empty() const { return m_matches_empty; }

    struct inst
    {
        uint8_t  op{0};
        uint32_t x{0};
        uint32_t y{0};
    };

private:
    enum class shape : uint8_t { program, literal, anything, nonempty, prefix, suffix, contains, literals };

    bool run(std::string_view s, int* groups, int ngroups) const;
    bool fast(std::string_view s) const;

    shape m_shape{shape::program};
    std::string m_lit;
    std::vector<std::string> m_lits;
    std::vector<inst> m_prog;
    std::vector<std::vector<std::pair<uint32_t, uint32_t>>> m_classes;
    std::vector<std::string> m_names;   // by group index, empty for an unnamed one
    int m_groups{1};
    bool m_matches_empty{false};
    bool m_search{false};

    // The thread lists of one match, kept so a match allocates nothing once it has run once.
    struct scratch
    {
        std::vector<uint32_t> dense, sparse;
        std::vector<int> caps;
        uint32_t n{0};
    };
    mutable scratch m_lists[2];
    mutable std::vector<int> m_cur;
    mutable std::vector<uint64_t> m_stack;
};

}   // namespace socketley
