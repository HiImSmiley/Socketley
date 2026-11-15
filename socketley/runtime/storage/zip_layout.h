#pragma once
// Where the files of a ZIP lie in it, judged before any is opened: each one's bytes in a stretch of the archive of
// its own. A directory whose entries share their bytes, each naming the same deflated stretch, unpacks a few
// kilobytes into as many times their size as it has entries (the overlapping-file bomb that UnZip refuses since
// CVE-2019-13232), so such an archive is refused whole rather than any of it written.
#include <algorithm>
#include <cstdint>
#include <vector>

namespace socketley::storage
{

struct zip_span
{
    uint64_t local{0};   // where its local header begins
    uint64_t csize{0};   // what the directory says its bytes take
    uint64_t limit{0};   // set by zip_spans_apart: where the next file, or the directory, begins
};

// True when no file's least stretch (its local header's fixed 30 bytes and its bytes) reaches the next file's
// header or into the central directory at [cd_off, cd_off + cd_size), with each one's `limit` set to where the
// stretch after it begins, which the file's bytes, once its local header's own lengths are read, must also end by.
inline bool zip_spans_apart(std::vector<zip_span>& spans, uint64_t size, uint64_t cd_off, uint64_t cd_size)
{
    std::vector<zip_span*> by_place;
    by_place.reserve(spans.size());
    for (auto& s : spans)
        by_place.push_back(&s);
    std::sort(by_place.begin(), by_place.end(), [](const zip_span* a, const zip_span* b) { return a->local < b->local; });
    const uint64_t cd_end = cd_size > size - std::min(cd_off, size) ? size : cd_off + cd_size;
    for (size_t i = 0; i < by_place.size(); ++i)
    {
        zip_span& s = *by_place[i];
        if (s.local > size || size - s.local < 30 || s.csize > size - s.local - 30)
            return false;
        const uint64_t end = s.local + 30 + s.csize;
        // The directory, read already, is no file's: a file before it ends at it, one after it begins past it.
        uint64_t limit = s.local < cd_off ? std::min(cd_off, size) : size;
        if (s.local >= cd_off && s.local < cd_end)
            return false;
        if (i + 1 < by_place.size())
            limit = std::min(limit, by_place[i + 1]->local);
        if (end > limit)
            return false;
        s.limit = limit;
    }
    return true;
}

}   // namespace socketley::storage
