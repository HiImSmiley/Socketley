#pragma once
// DEFLATE written (RFC 1951) as a stream that is read as it goes: each call's bytes compressed against the 32 KiB
// before them, in a block of the fixed Huffman codes, and flushed with an empty stored block, so the other side
// opens all of it at once, as IMAP's COMPRESS (RFC 4978) and a sync flush of zlib have it.  Matches are found by a
// hash of three bytes and a chain of at most 64 earlier places, so a call costs a bounded amount per byte.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace socketley
{

class deflater
{
public:
    deflater();
    // `in` compressed onto the end of `out`, ended so that every byte of it can be read from what is there.
    void compress(std::string_view in, std::string& out);

private:
    void bits(uint32_t value, int count, std::string& out);
    void code(uint32_t code, int length, std::string& out);
    void literal(uint8_t c, std::string& out);
    void match(uint32_t length, uint32_t distance, std::string& out);

    // At least the last 32 KiB of what was compressed, and where in the whole stream it begins.
    std::string m_hist;
    uint64_t m_hist_at{0};
    // By the hash of three bytes, the latest place they began, and before each place the one before it.
    std::vector<int64_t> m_head;
    std::vector<int64_t> m_prev;
    uint32_t m_bitbuf{0};
    int m_bitcount{0};
};

}   // namespace socketley
