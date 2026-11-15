// Fuzz target: the decoders of text and archives a stranger hands this daemon that no other target reaches -- the
// round where an out-of-bounds write in a decoder of untrusted data (Brotli's, CVE-2026-111497) was looked for in
// every one socketley has.
//
// The first input byte picks the decoder, and the rest is its input:
//   0  IMAP's modified UTF-7 (runtime/mail/imap_utf7.cpp), a mailbox name any IMAP client sends
//   1  a name as IDNA's A-labels and its registrable domain (shared/net/idna.cpp, public_suffix.cpp), which a
//      stranger's From, MAIL FROM and every DKIM d= are read as
//   2  a header value's RFC 2047 words, a body's quoted-printable and base64, and an RFC 2231 parameter
//      (runtime/mail/mail_mime.cpp), as every message a sender writes is read
//   3  base64 and base64url (shared/util/base64.cpp), as JWS, cookies, SASL and S3 checksums carry it
//   4  %XX as a path, a query and SigV4 read it (shared/http/url.h)
//   5  a ZIP's files, where its central directory says they lie (runtime/storage/zip_layout.h), before any is opened
//   6  a gzip'd or plain tar as `socketley restore` reads it (shared/persist/tar_archive.cpp)
//
// Properties checked, beyond "did it crash":
//   * modified UTF-7 decodes to UTF-8 that encodes to what decodes to it again, and encodes UTF-8 to what decodes
//     to it;
//   * an A-label name is ASCII with no label past 63 bytes, and a registrable domain is a suffix of the name;
//   * decoded text is never longer than its input allows (base64 three bytes of four, quoted-printable one of one);
//   * base64 decodes only the one spelling an encoder writes, so what it took encodes back to the same input;
//   * %XX decoding is never longer than its input;
//   * no two ZIP files the layout admits share a byte, nor any reach into the directory, and each ends by its limit;
//   * a tar entry's content read is never more than its header said.
//
// WHAT THIS TARGET DOES NOT COVER: DEFLATE itself (fuzz_http_codecs), Snappy (fuzz_metrics_remote), LZ4 and EXIF
// (fuzz_storage_parsers), DNS names (fuzz_dns), HPACK's Huffman (fuzz_http_codecs), and iconv's own charsets, which
// are glibc's.

#include "fuzz_common.h"
#include "runtime/mail/imap_utf7.h"
#include "runtime/mail/mail_mime.h"
#include "runtime/storage/zip_layout.h"
#include "shared/http/url.h"
#include "shared/net/idna.h"
#include "shared/net/public_suffix.h"
#include "shared/persist/tar_archive.h"
#include "shared/util/base64.h"

#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <sys/mman.h>
#include <unistd.h>

namespace
{

bool valid_utf8(std::string_view s)
{
    for (size_t i = 0; i < s.size();)
    {
        const auto c = static_cast<unsigned char>(s[i]);
        const size_t n = c < 0x80 ? 1 : c >= 0xC2 && c < 0xE0 ? 2 : c >= 0xE0 && c < 0xF0 ? 3 : c >= 0xF0 && c < 0xF5 ? 4 : 0;
        if (n == 0 || i + n > s.size())
            return false;
        for (size_t k = 1; k < n; ++k)
            if ((static_cast<unsigned char>(s[i + k]) & 0xC0) != 0x80)
                return false;
        i += n;
    }
    return true;
}

void utf7(std::string_view in)
{
    using namespace socketley::mail;
    const std::string d = imap_utf7::decode(in);
    if (!d.empty())
    {
        FUZZ_CHECK(valid_utf8(d), "modified UTF-7 decoded to bytes that are no UTF-8");
        // Two runs side by side decode as one would, so what comes back is what decodes alike, not the same bytes.
        FUZZ_CHECK(imap_utf7::decode(imap_utf7::encode(d)) == d, "a modified UTF-7 name decoded does not encode back");
    }
    const std::string e = imap_utf7::encode(in);
    if (!e.empty())
    {
        for (const char c : e)
            FUZZ_CHECK(static_cast<unsigned char>(c) >= 0x20 && static_cast<unsigned char>(c) < 0x7F,
                       "modified UTF-7 encoded to a byte that is not printable ASCII");
        FUZZ_CHECK(imap_utf7::decode(e) == in, "UTF-8 encoded as modified UTF-7 does not decode back to itself");
    }
}

void names(std::string_view in)
{
    const std::string a = socketley::idna::to_ascii(in);
    size_t label = 0;
    for (const char c : a)
    {
        FUZZ_CHECK(static_cast<unsigned char>(c) < 0x80, "an A-label name holds a byte past ASCII");
        label = c == '.' ? 0 : label + 1;
        FUZZ_CHECK(label <= 63, "an A-label name holds a label past 63 bytes");
    }
    static const socketley::public_suffix::list rules = [] {
        socketley::public_suffix::list l;
        l.load("com\nuk\nco.uk\n*.ck\n!www.ck\ntest\nxn--p1ai\n");
        return l;
    }();
    const std::string r = rules.registrable(in);
    std::string lowered = a.empty() ? std::string(in) : a;
    for (char& c : lowered)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    while (!lowered.empty() && lowered.back() == '.')
        lowered.pop_back();
    if (!r.empty() && valid_utf8(in))
        FUZZ_CHECK(lowered.ends_with(r), "a registrable domain is not a suffix of its name");
}

void mime(std::string_view in)
{
    using namespace socketley::mail;
    const std::string words = mime::decode_words(in);
    // A word's text grows only by its charset's conversion into UTF-8, a few bytes a byte at most.
    FUZZ_CHECK(words.size() <= in.size() * 8 + 16, "RFC 2047 words decoded to far more than they hold");
    const std::string qp = mime::decoded_body(in, "quoted-printable");
    FUZZ_CHECK(qp.size() <= in.size(), "quoted-printable decoded to more bytes than it was");
    const std::string b64 = mime::decoded_body(in, "base64");
    FUZZ_CHECK(b64.size() <= in.size(), "base64 decoded to more bytes than it was");
    const size_t eq = in.find('=');
    if (eq != std::string_view::npos)
    {
        const std::vector<std::pair<std::string, std::string>> params{
            {"filename*", std::string(in.substr(eq + 1))}, {"name", std::string(in.substr(0, eq))}};
        const std::string v = mime::param(params, "filename");
        FUZZ_CHECK(v.size() <= (in.size() - eq) * 8 + 16, "an RFC 2231 value decoded to far more than it holds");
        (void)mime::param(params, "name");
    }
}

void base64(std::string_view in)
{
    std::string out;
    if (socketley::base64::decode(in, out))
    {
        FUZZ_CHECK(out.size() * 4 <= in.size() * 3, "base64 decoded to more than three bytes of four");
        FUZZ_CHECK(socketley::base64::encode(out) == in, "base64 took a spelling no encoder writes");
    }
    if (socketley::base64url::decode(in, out))
    {
        FUZZ_CHECK(out.size() * 4 <= in.size() * 3, "base64url decoded to more than three bytes of four");
        FUZZ_CHECK(socketley::base64url::encode(out) == in, "base64url took a spelling no encoder writes");
    }
}

void percent(std::string_view in)
{
    using socketley::http::bad_escape;
    std::string out;
    for (const bool plus : {false, true})
        for (const bad_escape b : {bad_escape::reject, bad_escape::keep})
            if (socketley::http::percent_decode(in, out, plus, b))
                FUZZ_CHECK(out.size() <= in.size(), "%XX decoded to more bytes than it was");
}

uint64_t take64(std::string_view& in)
{
    uint64_t v = 0;
    const size_t n = std::min<size_t>(in.size(), 8);
    std::memcpy(&v, in.data(), n);
    in.remove_prefix(n);
    return v;
}

void zip(std::string_view in)
{
    using socketley::storage::zip_span;
    // An archive's size, its directory's place and size, then each file's place and size, values kept small often
    // enough that they meet one another.
    const auto small = [](uint64_t v) { return (v & 0x8000000000000000ull) ? v : v % 4096; };
    const uint64_t size = small(take64(in));
    const uint64_t cd_off = small(take64(in));
    const uint64_t cd_size = small(take64(in));
    if (cd_off > size || cd_size > size - cd_off)
        return;   // read_directory refuses these before the layout is asked
    std::vector<zip_span> spans;
    while (in.size() >= 16 && spans.size() < 256)
    {
        zip_span s;
        s.local = small(take64(in));
        s.csize = small(take64(in));
        spans.push_back(s);
    }
    if (!socketley::storage::zip_spans_apart(spans, size, cd_off, cd_size))
        return;
    for (size_t i = 0; i < spans.size(); ++i)
    {
        const zip_span& a = spans[i];
        FUZZ_CHECK(a.local <= size && a.limit <= size, "a ZIP file admitted lies past the archive");
        FUZZ_CHECK(a.local + 30 + a.csize <= a.limit, "a ZIP file admitted ends past its limit");
        FUZZ_CHECK(a.limit <= cd_off || a.local >= cd_off + cd_size, "a ZIP file admitted reaches into the directory");
        for (size_t k = i + 1; k < spans.size(); ++k)
        {
            const zip_span& b = spans[k];
            FUZZ_CHECK(a.limit <= b.local || b.limit <= a.local, "two ZIP files admitted share bytes");
        }
    }
}

void tar(std::string_view in)
{
    // The archive as a file, which is what the reader opens.
    const int fd = ::memfd_create("fuzz-tar", MFD_CLOEXEC);
    if (fd < 0)
        return;
    size_t at = 0;
    while (at < in.size())
    {
        const ssize_t n = ::write(fd, in.data() + at, in.size() - at);
        if (n <= 0)
            break;
        at += static_cast<size_t>(n);
    }
    const std::string path = "/proc/self/fd/" + std::to_string(fd);
    socketley::tar_reader r;
    std::string why;
    if (r.open(path, why))
    {
        socketley::tar_reader::entry e;
        for (int entries = 0; entries < 64; ++entries)
        {
            const auto st = r.next(e, why);
            if (st != socketley::tar_reader::status::entry)
                break;
            std::string body;
            const uint64_t said = e.size;
            if (!r.read(body, 1 << 16, why))
                break;
            FUZZ_CHECK(body.size() <= said, "a tar entry read gave more than its header said");
        }
    }
    ::close(fd);
}

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    data = ::fuzz::never_null(data);
    ::fuzz::set_current(data, size);
    if (size < 1 || size > 256 * 1024)
        return 0;
    const std::string_view in(reinterpret_cast<const char*>(data) + 1, size - 1);
    switch (data[0] % 7)
    {
        case 0: utf7(in); break;
        case 1: names(in); break;
        case 2: mime(in); break;
        case 3: base64(in); break;
        case 4: percent(in); break;
        case 5: zip(in); break;
        default:
            // A gzip'd tar opens to a thousand times its size, which is time and not a finding.
            if (in.size() <= 64 * 1024)
                tar(in);
            break;
    }
    return 0;
}
