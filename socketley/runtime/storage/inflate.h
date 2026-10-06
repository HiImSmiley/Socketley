#pragma once
// DEFLATE opened, as RFC 1951 describes it: the raw form a ZIP entry of method 8 holds, read in pieces as they arrive
// and given out a bounded amount at a time, so neither a large entry nor one that opens to far more than it took is
// ever held whole.
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace socketley::storage
{

class inflater
{
public:
    enum class result : uint8_t
    {
        need_input,   // everything fed is used; feed more, or end() if there is none
        output_full,  // `max_out` bytes were given; run() again for the rest
        done,         // the final block ended; what follows it in the input is not the stream's
        bad,          // not DEFLATE, or the input ended inside it
    };

    // More of the stream, in order.
    void feed(const uint8_t* p, size_t n);
    // Nothing more will be fed: a stream not finished by what was is bad.
    void end() { m_ended = true; }
    // Opens what was fed, appending at most `max_out` bytes to `out`.
    result run(std::string& out, size_t max_out);

    uint64_t produced() const { return m_produced; }

    struct huffman
    {
        // Codes up to fast_bits long are found in one look; a longer one walks the counts as RFC 1951 builds them.
        static constexpr unsigned fast_bits = 9;
        uint16_t count[16]{};
        std::vector<uint16_t> symbol;
        std::vector<uint16_t> fast;   // (symbol << 4) | length, 0 for a code longer than fast_bits
        bool build(const uint8_t* lengths, unsigned n);
    };

private:
    enum class state : uint8_t { header, stored_len, stored_copy, codes, finished, failed };

    bool     bits(unsigned n, uint32_t& v);
    bool     decode(const huffman& h, unsigned& sym);
    bool     dynamic_tables();
    void     put(uint8_t b, std::string& out);
    void     compact();

    std::string m_in;
    uint64_t    m_bit{0};
    bool        m_ended{false};
    state       m_at{state::header};
    bool        m_last{false};
    uint32_t    m_stored_left{0};
    // A match whose copy was stopped by max_out: its distance and what is left of its length.
    uint32_t    m_copy_left{0};
    uint32_t    m_copy_dist{0};
    huffman     m_lit;
    huffman     m_dist;
    std::vector<uint8_t> m_window = std::vector<uint8_t>(32768);
    uint32_t    m_wpos{0};
    uint64_t    m_produced{0};
};

}   // namespace socketley::storage
