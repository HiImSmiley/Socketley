#pragma once
// DEFLATE written (RFC 1951) as a stream that is read as it goes: each call's bytes compressed against the 32 KiB
// before them, in a block of Huffman codes made for what it holds, the fixed ones where those come out shorter, or
// stored as they are where neither makes them smaller, and ended on a byte with an empty stored block after codes, so the other side opens all of it at once, as IMAP's COMPRESS (RFC 4978) and a
// sync flush of zlib have it.  Matches are found by a hash of three bytes and a chain of at most 64 earlier places, so
// a call costs a bounded amount per byte.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace socketley
{

class deflater
{
public:
    // How hard matches are looked for: fast walks 64 earlier places, best up to 4096, a quarter of that once it holds
    // a match of 32 and none once one of 258, and takes a match only where the next byte's is no longer, as gzip -9.
    enum class effort : uint8_t { fast, best };
    explicit deflater(effort e = effort::fast);
    // `in` compressed onto the end of `out`, ended so that every byte of it can be read from what is there.
    void compress(std::string_view in, std::string& out);
    // The final block, an empty one, which a gzip or zlib reader needs to know the stream ended.
    void finish(std::string& out);
    // Begins again as if `dict` had just been compressed, so pieces of one stream can be compressed apart and their
    // outputs joined in order, as pigz does; what comes out is what one deflater given every piece would write.
    void prime(std::string_view dict);

private:
    void bits(uint32_t value, int count, std::string& out);
    void code(uint32_t code, int length, std::string& out);

    // At least the last 32 KiB of what was compressed, and where in the whole stream it begins.
    std::string m_hist;
    uint64_t m_hist_at{0};
    // By the hash of three bytes, the latest place they began, and before each place the one before it.
    std::vector<int64_t> m_head;
    std::vector<int64_t> m_prev;
    uint32_t m_bitbuf{0};
    int m_bitcount{0};
    int m_chain{64};
    uint32_t m_good{max_good};
    bool m_lazy{false};
    static constexpr uint32_t max_good = 1u << 16;
};

}   // namespace socketley
