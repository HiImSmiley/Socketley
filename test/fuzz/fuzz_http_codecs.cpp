// Fuzz target: what every HTTP runtime but the proxy, the server and the storage reads a peer's first bytes with, and
// the codecs HTTP/2 and a ZIP hand a stranger's bytes to -- none of which another target reaches.
//
// The first input byte picks the reader, and the rest is its input:
//   0  http::take_request (shared/http/request_head.h): the request an idp, a db, a web, an mcp, a metrics and a
//      tunnel runtime take off a connection
//   1  the Cookie readers (shared/http/cookie.h): the one a runtime verifies a session by and the one a proxy and a
//      tunnel edge strip the provider's cookies with
//   2  site_path and hidden_path (shared/http/site_path.h): a request's path as a site of files reads it
//   3  an HPACK header block, three times through one decoder, so the table a block leaves is what the next reads
//   4  a Huffman string, and a field encoded and decoded again
//   5  DEFLATE opened whole and in two pieces
//   6  bytes compressed and opened again
//
// Properties checked, beyond "did it crash":
//   * a request taken whole lies inside the input, never carries a Transfer-Encoding, and is the same request when
//     more bytes follow it -- or a second request could be read out of the first one's body;
//   * no cookie a verifier would find is left by the stripping of its name;
//   * a path taken is absolute, with no empty, "." or ".." segment and no NUL;
//   * a block decoded within its bound is within it, and a field encoded reads back as itself;
//   * DEFLATE opens to the same bytes however its input is cut, to no more than it was allowed, and what was
//     compressed opens to what it was.
//
// WHAT THIS TARGET DOES NOT COVER: the HTTP/2 session around HPACK (stream states, flow control, the flood
// counters), which lives in each runtime's connection code, and the ZIP directory around DEFLATE.

#include "fuzz_common.h"
#include "shared/http/cookie.h"
#include "shared/http/hpack.h"
#include "shared/http/request_head.h"
#include "shared/http/site_path.h"
#include "shared/util/deflate.h"
#include "shared/util/inflate.h"

#include <string>
#include <string_view>
#include <vector>

namespace
{

bool inside(std::string_view part, std::string_view whole)
{
    return part.empty() || (part.data() >= whole.data() && part.data() + part.size() <= whole.data() + whole.size());
}

void request(std::string_view in)
{
    using socketley::http::request_view;
    request_view v;
    int status = 0;
    bool te = false;
    const auto field = [&](std::string_view f, std::string_view value) {
        FUZZ_CHECK(inside(f, in) && inside(value, in), "a field handed to the caller lies outside the input");
        te = te || header_name_equals(f, "transfer-encoding", 17);
    };
    const int r = socketley::http::take_request(in, 8192, 65536, v, status, field);
    if (r < 0)
    {
        FUZZ_CHECK(status == 400 || status == 411 || status == 413 || status == 431, "a refusal with no status of its own");
        return;
    }
    if (r == 0)
        return;
    FUZZ_CHECK(!te, "a request with a Transfer-Encoding was taken by its Content-Length");
    FUZZ_CHECK(v.head_len >= 4 && v.head_len <= in.size() && v.body_len <= in.size() - v.head_len,
               "a request taken is longer than the input");
    FUZZ_CHECK(inside(v.method, in) && inside(v.path, in) && inside(v.query, in), "a request's parts lie outside the input");
    FUZZ_CHECK(in.substr(v.head_len - 4, 4) == "\r\n\r\n", "a head that does not end at its blank line");
    // The same request with another's bytes behind it, as a pipelining client sends them.
    std::string more(in.substr(0, v.head_len + v.body_len));
    more += "GET /next HTTP/1.1\r\nHost: x\r\n\r\n";
    request_view w;
    int status2 = 0;
    const int r2 = socketley::http::take_request(more, 8192, 65536, w, status2, [](std::string_view, std::string_view) {});
    FUZZ_CHECK(r2 == 1 && w.head_len == v.head_len && w.body_len == v.body_len && w.close == v.close,
               "a request reads differently once another follows it");
}

void cookies(std::string_view in)
{
    const size_t nul = in.find('\0');
    const std::string_view name = in.substr(0, nul);
    const std::string_view header = nul == std::string_view::npos ? std::string_view{} : in.substr(nul + 1);
    if (name.empty() || name.find_first_of(";= \t") != std::string_view::npos)
        return;
    const std::string kept = socketley::http::without_cookies(header, {name});
    const bool left = socketley::http::for_each_cookie(kept, name, [](std::string_view) { return true; });
    FUZZ_CHECK(!left, "a cookie a verifier finds was left by the stripping of its name");
    socketley::http::for_each_cookie(header, name, [&](std::string_view v) {
        FUZZ_CHECK(inside(v, header), "a cookie's value lies outside its header");
        return false;
    });
}

void path(std::string_view in)
{
    std::string out;
    if (!socketley::http::site_path(in, out))
        return;
    FUZZ_CHECK(!out.empty() && out.front() == '/', "a path taken is not absolute");
    FUZZ_CHECK(out.find('\0') == std::string::npos, "a path taken holds a NUL");
    for (size_t at = 1; at < out.size();)
    {
        const size_t slash = std::min(out.find('/', at), out.size());
        const std::string_view seg = std::string_view(out).substr(at, slash - at);
        FUZZ_CHECK(!seg.empty() && seg != "." && seg != "..", "a path taken holds an empty or a dot segment");
        at = slash + 1;
    }
    (void)socketley::http::hidden_path(out);
    (void)socketley::http::private_file_name(out);
}

void hpack_block(std::string_view in)
{
    constexpr size_t max_list = 4096;
    socketley::hpack::decoder d(256);
    for (int round = 0; round < 3; ++round)
    {
        std::vector<socketley::hpack::header> out;
        const auto r = d.decode(in, out, max_list);
        FUZZ_CHECK(d.table_size() <= 256, "the table grew past the size it was given");
        if (r == socketley::hpack::decoder::result::error)
            return;
        if (r != socketley::hpack::decoder::result::ok)
            continue;
        size_t listed = 0;
        for (const auto& h : out)
            listed += h.name.size() + h.value.size() + 32;
        FUZZ_CHECK(listed <= max_list, "a block decoded within its bound is longer than it");
    }
}

void hpack_strings(std::string_view in)
{
    std::string plain;
    (void)socketley::hpack::huffman_decode(in, plain);
    FUZZ_CHECK(plain.size() <= in.size() * 8 / 5 + 1, "a Huffman string opened to more symbols than its bits hold");
    // A field as the encoder writes one: a lowercase name, any value.
    const size_t cut = in.size() / 3;
    std::string name(in.substr(0, cut));
    for (char& c : name)
        c = static_cast<char>('a' + static_cast<unsigned char>(c) % 26);
    const std::string value(in.substr(cut));
    if (name.empty())
        return;
    std::string block;
    socketley::hpack::encode(block, name, value);
    socketley::hpack::decoder d;
    std::vector<socketley::hpack::header> out;
    FUZZ_CHECK(d.decode(block, out, 1 << 20) == socketley::hpack::decoder::result::ok && out.size() == 1 &&
                   out[0].name == name && out[0].value == value,
               "a field encoded does not decode back to itself");
}

// Opens `in` fed in the pieces `cut` makes of it, to at most `limit` bytes, and says how it ended.
socketley::inflater::result open(std::string_view in, size_t cut, size_t limit, std::string& out)
{
    socketley::inflater z;
    const auto* p = reinterpret_cast<const uint8_t*>(in.data());
    cut = std::min(cut, in.size());
    z.feed(p, cut);
    bool second = false;
    for (;;)
    {
        const size_t before = out.size();
        const auto r = z.run(out, std::min<size_t>(4096, limit - out.size()));
        FUZZ_CHECK(out.size() <= limit && out.size() - before <= 4096, "more was opened than was allowed");
        if (r == socketley::inflater::result::need_input && !second)
        {
            second = true;
            z.feed(p + cut, in.size() - cut);
            z.end();
            continue;
        }
        if (r == socketley::inflater::result::output_full && out.size() < limit)
            continue;
        return r;
    }
}

void inflate(std::string_view in)
{
    if (in.empty())
        return;
    constexpr size_t limit = 1 << 20;
    const size_t cut = static_cast<uint8_t>(in[0]) * (in.size() - 1) / 255;
    in.remove_prefix(1);
    std::string whole, pieces;
    const auto a = open(in, in.size(), limit, whole);
    const auto b = open(in, cut, limit, pieces);
    FUZZ_CHECK(a == b && whole == pieces, "DEFLATE opened differently when its input came in two pieces");
}

void round_trip(std::string_view in)
{
    if (in.empty())
        return;
    socketley::deflater z(in[0] & 1 ? socketley::deflater::effort::best : socketley::deflater::effort::fast);
    in.remove_prefix(1);
    std::string packed, plain;
    z.compress(in.substr(0, in.size() / 2), packed);
    z.compress(in.substr(in.size() / 2), packed);
    z.finish(packed);
    const auto r = open(packed, packed.size(), in.size() + 1, plain);
    FUZZ_CHECK(r == socketley::inflater::result::done && plain == in, "what was compressed does not open to what it was");
}

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    data = ::fuzz::never_null(data);
    ::fuzz::set_current(data, size);
    if (size < 1 || size > 64 * 1024)
        return 0;
    const std::string_view in(reinterpret_cast<const char*>(data) + 1, size - 1);
    switch (data[0] % 7)
    {
        case 0: request(in); break;
        case 1: cookies(in); break;
        case 2: path(in); break;
        case 3: hpack_block(in); break;
        case 4: hpack_strings(in); break;
        case 5: inflate(in); break;
        default: round_trip(in); break;
    }
    return 0;
}
