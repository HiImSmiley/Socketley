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
// Only a cache asks for them.  A server serving a cached 10 KB file over 64
// keep-alive connections measured 0.9994 with them, spread [0.971, 1.077] over
// six passes -- nothing -- while its idle RSS rose by 0.8 to 3.7 MB.  A cache
// is the one runtime whose hot path walks a keyed structure larger than the
// TLB covers, which is what a huge page is for.

#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
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
    // the operator's veto over all of them.
    explicit worker_env(bool hugepages)
    {
        const char* off = ::getenv("SOCKETLEY_HUGEPAGE");
        const bool  want = hugepages && !(off && off[0] == '0' && off[1] == '\0');

        bool tunables_seen = false;
        for (char** e = environ; e && *e; ++e)
        {
            std::string_view entry(*e);
            if (want && entry.rfind("GLIBC_TUNABLES=", 0) == 0)
            {
                tunables_seen = true;
                m_strings.push_back(merged(entry));
                continue;
            }
            m_strings.emplace_back(entry);
        }

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
