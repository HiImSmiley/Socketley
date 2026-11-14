#pragma once
// This program's read-only image -- code, constants, relocations -- unmapped from the process once its start-up has
// run, as the kernel frees its init text after boot: the pages stay in the page cache and come back on the next touch.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>

namespace image_trim
{

namespace detail
{

// A page this process holds its own copy of (pagemap: bit 63 present, bit 61 clear), a debugger's breakpoint or a
// uprobe, is kept, because dropping it would quietly remove the probe.
inline void release_range(int pagemap, uintptr_t start, uintptr_t end, uintptr_t page)
{
    constexpr size_t batch = 512;
    uint64_t entries[batch];
    uintptr_t run = start;
    for (uintptr_t at = start; at < end;)
    {
        const size_t want = std::min(batch, static_cast<size_t>((end - at) / page));
        const ssize_t got = ::pread(pagemap, entries, want * sizeof(uint64_t),
                                    static_cast<off_t>(at / page * sizeof(uint64_t)));
        if (got <= 0 || static_cast<size_t>(got) % sizeof(uint64_t) != 0)
            return;
        const size_t n = static_cast<size_t>(got) / sizeof(uint64_t);
        for (size_t i = 0; i < n; ++i, at += page)
        {
            const bool present = entries[i] >> 63 & 1;
            const bool file    = entries[i] >> 61 & 1;
            if (present && !file)
            {
                if (at > run && ::madvise(reinterpret_cast<void*>(run), at - run, MADV_DONTNEED) != 0) {}
                run = at + page;
            }
        }
    }
    if (end > run && ::madvise(reinterpret_cast<void*>(run), end - run, MADV_DONTNEED) != 0) {}
}

}   // namespace detail

// Every PT_LOAD of the executable that is not writable, page-aligned inward so no page shared with a writable
// segment -- the relocated, copied-on-write relro among them -- is ever touched.
inline void release()
{
    const int pagemap = ::open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
    if (pagemap < 0)
        return;
    struct ctx_t { int pagemap; uintptr_t page; } ctx{ pagemap, static_cast<uintptr_t>(::sysconf(_SC_PAGESIZE)) };
    ::dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* arg) -> int {
        const auto& c = *static_cast<ctx_t*>(arg);
        uintptr_t relro_lo = 0, relro_hi = 0;
        for (int i = 0; i < info->dlpi_phnum; ++i)
            if (info->dlpi_phdr[i].p_type == PT_GNU_RELRO)
            {
                relro_lo = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
                relro_hi = relro_lo + info->dlpi_phdr[i].p_memsz;
            }
        for (int i = 0; i < info->dlpi_phnum; ++i)
        {
            const ElfW(Phdr)& ph = info->dlpi_phdr[i];
            if (ph.p_type != PT_LOAD || (ph.p_flags & PF_W))
                continue;
            const uintptr_t lo = info->dlpi_addr + ph.p_vaddr;
            const uintptr_t start = (lo + c.page - 1) & ~(c.page - 1);
            const uintptr_t end = (lo + ph.p_filesz) & ~(c.page - 1);
            if (end <= start || (relro_hi > start && relro_lo < end))
                continue;
            detail::release_range(c.pagemap, start, end, c.page);
        }
        return 1;   // the executable is the first object reported, and the libraries are not ours to trim
    }, &ctx);
    ::close(pagemap);
}

}   // namespace image_trim
