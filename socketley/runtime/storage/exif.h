// When and where a photo was taken, as its EXIF says: read from the first bytes of a JPEG, a TIFF or a HEIF (HEIC).
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace socketley::storage
{

struct photo_facts
{
    // "2021-07-14T18:03:22", with the camera's "+02:00" after it where it wrote one; empty when unsaid.
    std::string taken;
    bool        located{false};
    double      lat{0}, lon{0};
};

// Where a HEIF keeps its Exif item, counted from the file's start.
struct exif_place
{
    uint64_t off{0}, len{0};
};

// The facts from a file's first bytes; false when they say none. A HEIF whose Exif item lies past them gives false and
// its place in `elsewhere`, whose bytes exif_item_facts then reads.
bool photo_facts_of(std::string_view head, photo_facts& out, exif_place* elsewhere = nullptr);
// A HEIF's Exif item: the offset of its TIFF header, then the bytes.
bool exif_item_facts(std::string_view item, photo_facts& out);
// The TIFF structure EXIF is, from its byte order mark.
bool tiff_facts(std::string_view tiff, photo_facts& out);

}   // namespace socketley::storage
