#include "spare_buffers.h"

#include <vector>

namespace socketley::spare
{
namespace
{

// 64 KiB to 8 MiB, at most 32 of them and 32 MiB: below that malloc is cheap, above it a buffer is rare.
constexpr size_t keep_min = 64u << 10;
constexpr size_t keep_max = 8u << 20;
constexpr size_t total_max = 32u << 20;
constexpr size_t count_max = 32;

struct pool
{
    std::vector<std::string> bufs;
    size_t bytes = 0;
};

pool& kept()
{
    static thread_local pool p;
    return p;
}

void give(std::string* s)
{
    auto& p = kept();
    const size_t cap = s->capacity();
    if (cap >= keep_min && cap <= keep_max && p.bufs.size() < count_max && p.bytes + cap <= total_max)
    {
        s->clear();
        p.bytes += cap;
        p.bufs.push_back(std::move(*s));
    }
    delete s;
}

}   // namespace

std::shared_ptr<std::string> buffer()
{
    return std::shared_ptr<std::string>(new std::string, give);
}

void take(std::string& into, size_t n)
{
    if (n < keep_min || !into.empty() || into.capacity() >= n)
        return;
    auto& p = kept();
    size_t best = p.bufs.size();
    for (size_t i = 0; i < p.bufs.size(); ++i)
        if (p.bufs[i].capacity() >= n && (best == p.bufs.size() || p.bufs[i].capacity() < p.bufs[best].capacity()))
            best = i;
    if (best == p.bufs.size())
        return;
    p.bytes -= p.bufs[best].capacity();
    into.swap(p.bufs[best]);
    p.bufs[best] = std::move(p.bufs.back());
    p.bufs.pop_back();
}

}   // namespace socketley::spare
