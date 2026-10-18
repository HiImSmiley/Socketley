#include "crc.h"

#include <cstring>

namespace socketley::crc
{

namespace
{

#if defined(__x86_64__)
// SSE4.2's crc32 instruction computes the Castagnoli polynomial eight bytes a step.
__attribute__((target("sse4.2")))
uint32_t crc32c_sse42(const unsigned char* p, size_t len, uint32_t crc)
{
    uint64_t c = static_cast<uint32_t>(~crc);
    while (len >= 8)
    {
        uint64_t v;
        std::memcpy(&v, p, 8);
        c = __builtin_ia32_crc32di(c, v);
        p += 8;
        len -= 8;
    }
    uint32_t c32 = static_cast<uint32_t>(c);
    while (len--)
        c32 = __builtin_ia32_crc32qi(c32, *p++);
    return ~c32;
}
#endif

} // namespace

uint32_t crc32c(const void* data, size_t len, uint32_t crc)
{
#if defined(__x86_64__)
    static const bool hw = __builtin_cpu_supports("sse4.2");
    if (hw)
        return crc32c_sse42(static_cast<const unsigned char*>(data), len, crc);
#endif
    return ~detail::sliced(detail::castagnoli, ~crc, data, len);
}

} // namespace socketley::crc
