#pragma once

// The environment a worker is exec'd with.
//
// glibc hands a process's heap transparent huge pages only when it is asked,
// and `madvise` is this box's THP mode, so the default is 4 KiB pages for a
// keyspace that does not fit in the TLB.  Measured on a cache holding 173k
// keys: pipelined GET goes from 4,508,850 to 5,089,330 a second, 6 of 6
// interleaved passes, for 0.9 to 1.6 MB of RSS on a 27 MB working set.
//
// It is built in the PARENT because after fork only async-signal-safe calls
// are legal and the daemon carries a metrics thread, so a setenv() between
// fork and exec is a malloc in a child that may hold the allocator's lock.
//
// WHAT IT IS WORTH DEPENDS ON THE MACHINE HAVING 2 MB PAGES TO GIVE, and that
// is measured rather than assumed.  The same A/B, same swap protocol, on one
// box over one night:
//
//     order-9 blocks 716, compaction_proactiveness 20   +17.9%
//     order-9 blocks  12, compaction_proactiveness  1    +3.2%
//     the same, after one echo 1 > vm.compact_memory     +5.4%
//
// `thp_fault_fallback` stayed at zero throughout, so nothing was refused -- a
// starved system still gets its huge pages and gets less out of them.  An
// operator seeing a smaller figure than the commit quotes should look at
// /proc/buddyinfo before looking here.
//
// Only a cache asks for them.  A server serving a cached 10 KB file over 64
// keep-alive connections measured 0.9994 with them, spread [0.971, 1.077] over
// six passes -- nothing -- while its idle RSS rose by 0.8 to 3.7 MB.  A cache
// is the one runtime whose hot path walks a keyed structure larger than the
// TLB covers, which is what a huge page is for.

#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

extern char** environ;

namespace socketley
{

// The tunable glibc reads at startup, which is why it can only be set by
// whoever spawns the process and never by the process itself.
inline constexpr std::string_view hugetlb_tunable = "glibc.malloc.hugetlb=1";

class worker_env
{
public:
    // `hugepages` is the caller's decision about THIS runtime; the env var is
    // the operator's veto over all of them.  `extra` are set the way setenv()
    // with overwrite does -- replacing what the parent had under that name --
    // and they are here rather than in the child because a setenv() after fork
    // is a malloc against a lock the child may not own.
    using var = std::pair<std::string_view, std::string_view>;

    explicit worker_env(bool hugepages, std::initializer_list<var> extra = {})
    {
        const char* off = ::getenv("SOCKETLEY_HUGEPAGE");
        const bool  want = hugepages && !(off && off[0] == '0' && off[1] == '\0');

        bool tunables_seen = false;
        for (char** e = environ; e && *e; ++e)
        {
            std::string_view entry(*e);
            if (replaced(entry, extra))
                continue;
            if (want && entry.rfind("GLIBC_TUNABLES=", 0) == 0)
            {
                tunables_seen = true;
                m_strings.push_back(merged(entry));
                continue;
            }
            m_strings.emplace_back(entry);
        }

        for (const var& v : extra)
            m_strings.emplace_back(std::string(v.first) + "=" + std::string(v.second));

        if (want && !tunables_seen)
            m_strings.emplace_back(std::string("GLIBC_TUNABLES=") + std::string(hugetlb_tunable));

        // Pointers last, because a push_back into m_strings after this would
        // leave every one of them pointing at freed storage.
        m_pointers.reserve(m_strings.size() + 1);
        for (auto& s : m_strings)
            m_pointers.push_back(s.data());
        m_pointers.push_back(nullptr);
    }

    worker_env(const worker_env&)            = delete;
    worker_env& operator=(const worker_env&) = delete;

    char* const* envp() const { return m_pointers.data(); }

private:
    // Whether an inherited entry is one `extra` is about to write, compared on
    // the name alone: "FOO=1" and "FOOBAR=2" must not match each other.
    static bool replaced(std::string_view entry, std::initializer_list<var> extra)
    {
        const size_t eq = entry.find('=');
        if (eq == std::string_view::npos)
            return false;
        const std::string_view name = entry.substr(0, eq);
        for (const var& v : extra)
            if (v.first == name)
                return true;
        return false;
    }

    // An operator who named this tunable themselves meant it, so theirs wins
    // and we add nothing; anything else is appended beside what is there.
    static std::string merged(std::string_view entry)
    {
        if (entry.find("glibc.malloc.hugetlb") != std::string_view::npos)
            return std::string(entry);

        std::string out(entry);
        if (out.size() > std::strlen("GLIBC_TUNABLES=") && out.back() != ':')
            out.push_back(':');
        out.append(hugetlb_tunable);
        return out;
    }

    std::vector<std::string> m_strings;
    std::vector<char*>       m_pointers;
};

}   // namespace socketley
