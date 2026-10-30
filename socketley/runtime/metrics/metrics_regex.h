#pragma once
// RE2's syntax matched against a whole string in time linear in its length, as Prometheus anchors every label matcher
// and label_replace's regex.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace socketley::metrics
{

class regex
{
public:
    // False with `why` set when the pattern is not RE2 syntax this engine reads; `.` matches a newline, as in Prometheus.
    bool compile(std::string_view pattern, std::string& why);

    bool matches(std::string_view s) const;
    // The byte offsets of each group of a whole-string match, begin and end per group, -1 for a group that took no part.
    bool matches(std::string_view s, std::vector<int>& groups) const;

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

}   // namespace socketley::metrics
