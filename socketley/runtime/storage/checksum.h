#pragma once
// The additional checksums S3 clients send and expect back -- CRC32, CRC32C,
// CRC64NVME, SHA-1 and SHA-256 -- as a stream over the bytes of a body, and the
// base64 they travel in.
//
// Pure code with no I/O, so a unit test reaches it without a ring.
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace socketley::storage
{

enum class checksum_algo : uint8_t { none, crc32, crc32c, crc64nvme, sha1, sha256 };

// The header a checksum travels in, as a request carries it and as an object
// is stored with it.
std::string_view checksum_header(checksum_algo a);

// The name x-amz-sdk-checksum-algorithm and x-amz-checksum-algorithm use.
std::string_view checksum_name(checksum_algo a);

// Bytes of the raw value, and characters of its base64.
size_t checksum_raw_len(checksum_algo a);
size_t checksum_b64_len(checksum_algo a);

// None for a name or header that is not one of the algorithms above.
checksum_algo checksum_from_header(std::string_view lowercase_header);
checksum_algo checksum_from_name(std::string_view name);

// Whether `header` is an x-amz-checksum-* value header at all, known algorithm or not.
bool is_checksum_header(std::string_view lowercase_header);

class checksum_stream
{
public:
    explicit checksum_stream(checksum_algo a);
    ~checksum_stream();

    checksum_stream(const checksum_stream&)            = delete;
    checksum_stream& operator=(const checksum_stream&) = delete;

    void update(const void* data, size_t n);

    // The value over what has been fed, raw and in base64, leaving the stream
    // usable for more bytes.
    std::string peek_raw() const;
    std::string peek_b64() const;

    checksum_algo algo() const { return m_algo; }

private:
    checksum_algo m_algo;
    uint64_t      m_crc{0};
    struct digest;
    std::unique_ptr<digest> m_digest;
};

// Standard base64 with padding, for the checksum headers and Content-MD5.
std::string base64_encode(std::string_view in);
bool        base64_decode(std::string_view in, std::string& out);

// The checksum of a multipart object: the algorithm over the raw checksums of
// its parts in order, in base64 with "-<parts>" after it.
std::string composite_checksum_b64(checksum_algo a, std::string_view concatenated_raw, size_t parts);

// Whether a multipart object may carry the checksum of its whole bytes, which a CRC alone can be combined into.
bool checksum_combinable(checksum_algo a);

// The CRC of the parts' bytes joined, in base64, from each part's raw CRC and length; empty for no CRC.
std::string full_object_checksum_b64(checksum_algo a, const std::vector<std::pair<std::string, uint64_t>>& parts);

}   // namespace socketley::storage
