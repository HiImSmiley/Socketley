// Fuzz target: the FastCGI client codec (socketley/shared/http/fastcgi.{h,cpp}).
//
// What an application server -- php-fpm, or whatever answers on the socket a proxy names -- sends back reaches
// next_record() and parse_cgi_head() byte for byte, so the input is taken as that stream: records read off its front
// the way the proxy's read handler does, the STDOUT content gathered and its CGI head parsed as it grows.
//
// Checked beside "does not crash": a record's content lies inside the buffer and `consumed` covers it; a head that
// parses has a status from 100 to 999, ends inside what it was given, and holds at most 256 fields; and the encoders
// round-trip -- PARAMS built from the input decode back to the same pairs, STDIN to the same bytes.

#include "fuzz_common.h"
#include "../../socketley/shared/http/fastcgi.h"

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

namespace fcgi = socketley::fastcgi;

namespace
{

void read_stream(std::string_view buf)
{
    std::string out;
    int guard = 0;
    while (!buf.empty() && guard++ < 4096)
    {
        fcgi::record r;
        size_t used = 0;
        const fcgi::take t = fcgi::next_record(buf, r, used);
        if (t != fcgi::take::record)
            break;
        FUZZ_CHECK(used >= fcgi::header_size && used <= buf.size(), "a record consumed outside the buffer");
        FUZZ_CHECK(r.content.data() >= buf.data() && r.content.data() + r.content.size() <= buf.data() + used,
                   "a record's content lies outside the bytes it consumed");
        if (r.type == fcgi::record_type::stdout_data)
        {
            out += r.content;
            fcgi::cgi_head h;
            size_t len = 0;
            if (fcgi::parse_cgi_head(out, len, h, 4096) == fcgi::head_result::done)
            {
                FUZZ_CHECK(h.status >= 100 && h.status <= 999, "a parsed head's status is outside 100-999");
                FUZZ_CHECK(len > 0 && len <= out.size(), "a parsed head ends outside the bytes it was given");
                FUZZ_CHECK(h.fields.size() <= 256, "a parsed head holds more than 256 fields");
            }
        }
        if (r.type == fcgi::record_type::end_request)
        {
            uint32_t app = 0;
            uint8_t proto = 0;
            if (!fcgi::parse_end_request(r.content, app, proto)) {}
        }
        buf.remove_prefix(used);
    }
}

void round_trip(std::string_view in)
{
    // Pairs cut from the input at its own bytes, so lengths around 127 and 128 are reached.
    std::vector<std::pair<std::string, std::string>> pairs;
    for (size_t at = 0; at + 2 <= in.size() && pairs.size() < 64;)
    {
        const size_t a = static_cast<unsigned char>(in[at]) % 160, b = static_cast<unsigned char>(in[at + 1]) * 3;
        at += 2;
        const std::string_view rest = in.substr(at);
        pairs.emplace_back(std::string(rest.substr(0, a)), std::string(rest.substr(std::min(a, rest.size()), b)));
        at += std::min(rest.size(), a + b);
    }
    std::string w;
    fcgi::append_params(w, pairs);
    std::string stream;
    std::string_view rest = w;
    while (!rest.empty())
    {
        fcgi::record r;
        size_t used = 0;
        FUZZ_CHECK(fcgi::next_record(rest, r, used) == fcgi::take::record, "an encoded PARAMS stream did not decode");
        FUZZ_CHECK(r.type == fcgi::record_type::params, "an encoded PARAMS record decoded as another type");
        stream += r.content;
        rest.remove_prefix(used);
    }
    std::string_view s = stream;
    for (const auto& [name, value] : pairs)
    {
        size_t n[2] = {0, 0};
        for (size_t& x : n)
        {
            FUZZ_CHECK(!s.empty(), "a PARAMS stream ended inside a length");
            const auto b0 = static_cast<unsigned char>(s[0]);
            if (b0 < 128)
            {
                x = b0;
                s.remove_prefix(1);
                continue;
            }
            FUZZ_CHECK(s.size() >= 4, "a PARAMS stream ended inside a four-byte length");
            x = (static_cast<size_t>(b0 & 0x7f) << 24) | (static_cast<size_t>(static_cast<unsigned char>(s[1])) << 16) |
                (static_cast<size_t>(static_cast<unsigned char>(s[2])) << 8) | static_cast<unsigned char>(s[3]);
            s.remove_prefix(4);
        }
        FUZZ_CHECK(n[0] == name.size() && n[1] == value.size() && s.size() >= n[0] + n[1] &&
                       s.substr(0, n[0]) == name && s.substr(n[0], n[1]) == value,
                   "a PARAMS pair did not decode back to itself");
        s.remove_prefix(n[0] + n[1]);
    }
    FUZZ_CHECK(s.empty(), "a PARAMS stream held bytes past its pairs");

    w.clear();
    fcgi::append_stdin(w, in);
    std::string body;
    rest = w;
    while (!rest.empty())
    {
        fcgi::record r;
        size_t used = 0;
        FUZZ_CHECK(fcgi::next_record(rest, r, used) == fcgi::take::record, "an encoded STDIN stream did not decode");
        body += r.content;
        rest.remove_prefix(used);
    }
    FUZZ_CHECK(body == in, "a STDIN stream did not decode back to its body");
}

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    data = ::fuzz::never_null(data);
    ::fuzz::set_current(data, size);
    if (size > 256 * 1024)
        return 0;
    const std::string_view buf(reinterpret_cast<const char*>(data), size);
    read_stream(buf);
    round_trip(buf.substr(0, std::min<size_t>(size, 4096)));
    return 0;
}
