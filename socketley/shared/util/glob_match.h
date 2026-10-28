#pragma once

// Redis' glob, on views, without a copy and without a strlen.
//
// It was fnmatch(pattern.c_str(), text.c_str(), 0) at five places.  Both
// arguments are C strings, so every comparison strlen'd two buffers whose
// length both sides already knew -- and two of the five built a std::string
// per candidate, one of them rebuilding the PATTERN for every key it scanned.
//
// Profiled with a thousand pattern subscribers parked, PUBLISH from an
// unrelated client fell from 2,074,368/s to 129,280/s and __strlen_avx2 was
// the top symbol in the worker.  Walking every pattern is unavoidable -- a
// pattern matches channels that do not exist yet, so there is nothing to look
// up, and Redis pays it too -- but the strlen and the allocations are not.
//
// ─── AND IT IS NOT A DROP-IN FOR fnmatch, DELIBERATELY ──────────────────────
//
// fnmatch is POSIX and understands [[:alpha:]]; Redis does not.  Matching
// Redis is the requirement here, so this implements Redis' stringmatchlen
// grammar exactly -- * ? [...] [^...] a-c and backslash escapes -- and a
// pattern using a POSIX class now means what it means to Redis, which is the
// literal characters.  That is a behaviour change, in the direction of the
// server we are asked to be compatible with, and it is covered by a
// differential test against a real redis-server.
//
// Iterative, with one backtrack point, rather than the recursion Redis uses:
// a pattern of a thousand stars against a long channel is a legal thing for a
// client to send and must not be a thousand stack frames.

#include <cstddef>
#include <cstring>
#include <string_view>

namespace socketley
{

inline bool glob_match(std::string_view pat, std::string_view str) noexcept
{
    constexpr size_t none = static_cast<size_t>(-1);
    size_t pi = 0, si = 0, star = none, star_si = 0;
    // Linear in the input, so a pattern built to backtrack stops here and matches nothing, as Redis's nesting limit does.
    size_t budget = 64 * (pat.size() + str.size()) + 4096;

    while (si < str.size())
    {
        if (budget-- == 0) return false;
        if (pi < pat.size())
        {
            const char c = pat[pi];
            if (c == '*')
            {
                // Collapse a run, so "a***b" costs what "a*b" costs.
                while (pi + 1 < pat.size() && pat[pi + 1] == '*') ++pi;
                star = pi++; star_si = si;
                // Plain bytes after a star are placed at their first occurrence, which is what the backtracking finds.
                size_t end = pi;
                while (end < pat.size() && pat[end] != '*' && pat[end] != '?'
                       && pat[end] != '[' && pat[end] != '\\')
                    ++end;
                const size_t len = end - pi;
                // The last run can only be the subject's tail.
                if (end == pat.size())
                    return len <= str.size() - si && str.substr(str.size() - len) == pat.substr(pi);
                // A long subject is searched by memmem, as the restart below is quadratic in it.
                if (pat[end] == '*' && len > 0 && str.size() - si > 256)
                {
                    const void* at = ::memmem(str.data() + si, str.size() - si, pat.data() + pi, len);
                    if (!at) return false;
                    si = static_cast<size_t>(static_cast<const char*>(at) - str.data()) + len;
                    pi = end;
                }
                continue;
            }
            if (c == '?') { ++pi; ++si; continue; }
            if (c == '[')
            {
                size_t e   = pi + 1;
                bool   neg = (e < pat.size() && pat[e] == '^');
                if (neg) ++e;
                bool hit = false;
                while (e < pat.size() && pat[e] != ']')
                {
                    if (pat[e] == '\\' && e + 1 < pat.size())
                    {
                        ++e;
                        if (pat[e] == str[si]) hit = true;
                    }
                    // A '-' before the closing bracket is a RANGE whose end is
                    // that bracket, not the set {x, '-'}: Redis reads "[.-]" as
                    // '.' through ']' and then runs off the end of the pattern
                    // looking for a close that is no longer there.  Treating it
                    // as a two-character set was the more sensible reading and
                    // made KEYS "x[.-]y" answer where redis-server answers
                    // nothing, which is the one thing this file must not do.
                    else if (e + 2 < pat.size() && pat[e + 1] == '-')
                    {
                        char lo = pat[e], hi = pat[e + 2];
                        if (lo > hi) { const char t = lo; lo = hi; hi = t; }
                        if (str[si] >= lo && str[si] <= hi) hit = true;
                        e += 2;
                    }
                    else if (pat[e] == str[si])
                    {
                        hit = true;
                    }
                    ++e;
                }
                // The class is read byte by byte, so its length is charged, or one long class is quadratic again.
                if (e - pi >= budget) return false;
                budget -= e - pi;
                if (neg) hit = !hit;
                if (hit)
                {
                    // Past the ']', or to the end when the class was never closed
                    // -- which is what Redis does with an unterminated one.
                    pi = (e < pat.size()) ? e + 1 : e;
                    ++si;
                    continue;
                }
            }
            else if (c == '\\' && pi + 1 < pat.size())
            {
                if (pat[pi + 1] == str[si]) { pi += 2; ++si; continue; }
            }
            else if (c == str[si])
            {
                ++pi; ++si;
                continue;
            }
        }
        // Nothing matched here.  If a star is behind us it can eat one more
        // character; otherwise the pattern cannot cover this string.
        if (star != none) { pi = star + 1; si = ++star_si; continue; }
        return false;
    }

    while (pi < pat.size() && pat[pi] == '*') ++pi;
    return pi == pat.size();
}


// IAM's wildcard (StringLike, ARNs): '*' is any run of characters, '?' is one, nothing else is special, and `fold`
// compares letters without case. A '*' in the pattern is a wildcard even where the text holds one too.
inline bool iam_wild_match(std::string_view pat, std::string_view str, bool fold = false) noexcept
{
    constexpr size_t none = static_cast<size_t>(-1);
    const auto low = [](char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; };
    size_t pi = 0, si = 0, star = none, star_si = 0;
    while (si < str.size())
    {
        if (pi < pat.size() && pat[pi] == '*')
        {
            star    = pi++;
            star_si = si;
            continue;
        }
        if (pi < pat.size() && (pat[pi] == '?' || (fold ? low(pat[pi]) == low(str[si]) : pat[pi] == str[si])))
        {
            ++pi;
            ++si;
            continue;
        }
        if (star == none)
            return false;
        pi = star + 1;
        si = ++star_si;
    }
    while (pi < pat.size() && pat[pi] == '*')
        ++pi;
    return pi == pat.size();
}

}  // namespace socketley
