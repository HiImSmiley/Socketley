#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "shared/http/fastcgi.h"

#include <string>
#include <string_view>
#include <vector>

namespace fcgi = socketley::fastcgi;

namespace
{

// Every record of `wire`, in order, which fails the test at bytes that do not make whole records.
std::vector<fcgi::record> records_of(std::string_view wire)
{
    std::vector<fcgi::record> out;
    while (!wire.empty())
    {
        fcgi::record r;
        size_t used = 0;
        REQUIRE(fcgi::next_record(wire, r, used) == fcgi::take::record);
        out.push_back(r);
        wire.remove_prefix(used);
    }
    return out;
}

// The name-value pairs of a PARAMS stream, as an application server reads them.
std::vector<std::pair<std::string, std::string>> pairs_of(std::string_view s)
{
    const auto length = [&](size_t& n) {
        REQUIRE(!s.empty());
        const auto b = static_cast<unsigned char>(s[0]);
        if (b < 128)
        {
            n = b;
            s.remove_prefix(1);
            return;
        }
        REQUIRE(s.size() >= 4);
        n = (static_cast<size_t>(b & 0x7f) << 24) | (static_cast<size_t>(static_cast<unsigned char>(s[1])) << 16) |
            (static_cast<size_t>(static_cast<unsigned char>(s[2])) << 8) | static_cast<unsigned char>(s[3]);
        s.remove_prefix(4);
    };
    std::vector<std::pair<std::string, std::string>> out;
    while (!s.empty())
    {
        size_t a = 0, b = 0;
        length(a);
        length(b);
        REQUIRE(s.size() >= a + b);
        out.emplace_back(std::string(s.substr(0, a)), std::string(s.substr(a, b)));
        s.remove_prefix(a + b);
    }
    return out;
}

}   // namespace

TEST_CASE("fastcgi: a BEGIN_REQUEST asks for the responder role and keeps the connection when told to")
{
    std::string w;
    fcgi::append_begin(w, true);
    const std::string want("\x01\x01\x00\x01\x00\x08\x00\x00" "\x00\x01\x01\x00\x00\x00\x00\x00", 16);
    CHECK(w == want);
    w.clear();
    fcgi::append_begin(w, false);
    CHECK(static_cast<unsigned char>(w[10]) == 0);
}

TEST_CASE("fastcgi: PARAMS carry short and long lengths, split past 64 KiB, and end with an empty record")
{
    const std::string big(70000, 'v');
    std::string w;
    fcgi::append_params(w, {{"A", "1"}, {"LONG", std::string(200, 'x')}, {"BIG", big}});
    const auto rs = records_of(w);
    REQUIRE(rs.size() == 3);
    CHECK(rs[0].type == fcgi::record_type::params);
    CHECK(rs[0].content.size() == fcgi::max_content);
    CHECK(rs[2].content.empty());
    std::string stream;
    for (const auto& r : rs)
        stream += r.content;
    const auto pairs = pairs_of(stream);
    REQUIRE(pairs.size() == 3);
    CHECK(pairs[0] == std::pair<std::string, std::string>{"A", "1"});
    CHECK(pairs[1].second == std::string(200, 'x'));
    CHECK(pairs[2].second == big);
}

TEST_CASE("fastcgi: a body is STDIN records of at most 64 KiB, and the empty record ends it")
{
    std::string w;
    fcgi::append_stdin(w, std::string(70000, 'b'));
    auto rs = records_of(w);
    REQUIRE(rs.size() == 2);
    CHECK(rs[0].content.size() == 65535);
    CHECK(rs[1].content.size() == 70000 - 65535);
    w.clear();
    fcgi::append_stdin(w, {});
    rs = records_of(w);
    REQUIRE(rs.size() == 1);
    CHECK(rs[0].type == fcgi::record_type::stdin_data);
    CHECK(rs[0].content.empty());
}

TEST_CASE("fastcgi: a record is read whole, its padding skipped, and anything but version 1 refused")
{
    // STDOUT, id 1, 3 bytes of content and 5 of padding.
    const std::string rec("\x01\x06\x00\x01\x00\x03\x05\x00" "abc" "\0\0\0\0\0", 16);
    fcgi::record r;
    size_t used = 0;
    for (size_t n = 0; n < rec.size(); ++n)
        CHECK(fcgi::next_record(std::string_view(rec).substr(0, n), r, used) == fcgi::take::need_more);
    const std::string buf = rec + "next";
    REQUIRE(fcgi::next_record(buf, r, used) == fcgi::take::record);
    CHECK(r.type == fcgi::record_type::stdout_data);
    CHECK(r.id == 1);
    CHECK(r.content == "abc");
    CHECK(used == 16);
    std::string v2 = rec;
    v2[0] = 2;
    CHECK(fcgi::next_record(v2, r, used) == fcgi::take::bad);
}

TEST_CASE("fastcgi: END_REQUEST says the application's status and the protocol's")
{
    uint32_t app = 0;
    uint8_t proto = 9;
    CHECK(fcgi::parse_end_request(std::string("\x00\x00\x01\x02\x00\x00\x00\x00", 8), app, proto));
    CHECK(app == 258);
    CHECK(proto == 0);
    CHECK_FALSE(fcgi::parse_end_request("short", app, proto));
}

TEST_CASE("fastcgi: a CGI response's head gives its status, its fields and what the proxy acts on itself")
{
    fcgi::cgi_head h;
    size_t len = 0;
    const std::string plain = "Content-Type: text/html\r\nX-Powered-By: PHP/8.2\r\n\r\n<p>hi</p>";
    REQUIRE(fcgi::parse_cgi_head(plain, len, h) == fcgi::head_result::done);
    CHECK(h.status == 200);
    CHECK(len == plain.find("<p>"));
    REQUIRE(h.fields.size() == 2);
    CHECK(h.fields[0] == std::pair<std::string, std::string>{"Content-Type", "text/html"});

    REQUIRE(fcgi::parse_cgi_head("Status: 404 Not Found\nContent-Type: text/plain\n\nnope", len, h) == fcgi::head_result::done);
    CHECK(h.status == 404);
    CHECK(h.reason == "Not Found");
    CHECK(h.fields.size() == 1);

    REQUIRE(fcgi::parse_cgi_head("Location: https://example.com/\r\n\r\n", len, h) == fcgi::head_result::done);
    CHECK(h.status == 302);
    CHECK(h.location == "https://example.com/");

    REQUIRE(fcgi::parse_cgi_head("Status: 201\r\nLocation: /x\r\n\r\n", len, h) == fcgi::head_result::done);
    CHECK(h.status == 201);

    REQUIRE(fcgi::parse_cgi_head("X-Accel-Redirect: /private/a.zip\r\nContent-Length: 0\r\n\r\n", len, h) ==
            fcgi::head_result::done);
    CHECK(h.accel_redirect == "/private/a.zip");
    CHECK(h.has_length);
    CHECK(h.fields.size() == 1);
}

TEST_CASE("fastcgi: a head that is not one is refused, and one not yet whole waits")
{
    fcgi::cgi_head h;
    size_t len = 0;
    CHECK(fcgi::parse_cgi_head("Content-Type: text/html\r\n", len, h) == fcgi::head_result::need_more);
    CHECK(fcgi::parse_cgi_head("no colon here\r\n\r\n", len, h) == fcgi::head_result::bad);
    CHECK(fcgi::parse_cgi_head("Bad Name: x\r\n\r\n", len, h) == fcgi::head_result::bad);
    CHECK(fcgi::parse_cgi_head(": empty name\r\n\r\n", len, h) == fcgi::head_result::bad);
    CHECK(fcgi::parse_cgi_head(std::string("X: a\x01" "b\r\n\r\n"), len, h) == fcgi::head_result::bad);
    CHECK(fcgi::parse_cgi_head("Status: abc\r\n\r\n", len, h) == fcgi::head_result::bad);
    CHECK(fcgi::parse_cgi_head("Status: 099\r\n\r\n", len, h) == fcgi::head_result::bad);
    CHECK(fcgi::parse_cgi_head("Status: 2000\r\n\r\n", len, h) == fcgi::head_result::bad);
    CHECK(fcgi::parse_cgi_head("X: " + std::string(100, 'a'), len, h, 64) == fcgi::head_result::bad);
    std::string many;
    for (int i = 0; i < 300; ++i)
        many += "X-" + std::to_string(i) + ": v\r\n";
    CHECK(fcgi::parse_cgi_head(many + "\r\n", len, h) == fcgi::head_result::bad);
}

TEST_CASE("fastcgi: the CGI variables of a request, with the headers a server could be fooled by left out")
{
    fcgi::request_info r;
    r.method = "POST";
    r.target = "/shop/cart.php/extra?id=7";
    r.path = "/shop/cart.php/extra";
    r.query = "id=7";
    r.protocol = "HTTP/1.1";
    r.script_name = "/shop/cart.php";
    r.script_filename = "/var/www/site/shop/cart.php";
    r.path_info = "/extra";
    r.document_root = "/var/www/site";
    r.server_name = "example.com";
    r.server_port = "443";
    r.remote_addr = "203.0.113.9";
    r.remote_port = "50000";
    r.https = true;
    r.content_length = 5;
    r.has_body = true;
    r.headers = {{"Content-Type", "application/x-www-form-urlencoded"}, {"Content-Length", "5"},
                 {"Cookie", "a=1"}, {"cookie", "b=2"}, {"Proxy", "http://evil:8080"}, {"X_Forwarded_For", "1.2.3.4"},
                 {"Accept-Language", "de"}};
    const auto p = fcgi::cgi_params(r);
    const auto get = [&](std::string_view k) -> std::string {
        for (const auto& [n, v] : p)
            if (n == k)
                return v;
        return "<none>";
    };
    CHECK(get("REQUEST_METHOD") == "POST");
    CHECK(get("SCRIPT_FILENAME") == "/var/www/site/shop/cart.php");
    CHECK(get("PATH_INFO") == "/extra");
    CHECK(get("QUERY_STRING") == "id=7");
    CHECK(get("HTTPS") == "on");
    CHECK(get("CONTENT_TYPE") == "application/x-www-form-urlencoded");
    CHECK(get("CONTENT_LENGTH") == "5");
    CHECK(get("HTTP_COOKIE") == "a=1; b=2");
    CHECK(get("HTTP_ACCEPT_LANGUAGE") == "de");
    CHECK(get("HTTP_PROXY") == "<none>");
    CHECK(get("HTTP_X_FORWARDED_FOR") == "<none>");
    CHECK(get("HTTP_CONTENT_LENGTH") == "<none>");

    r.https = false;
    r.path_info.clear();
    r.has_body = false;
    r.content_length = 0;
    const auto q = fcgi::cgi_params(r);
    const auto has = [&](std::string_view k) {
        for (const auto& [n, v] : q)
            if (n == k)
                return true;
        return false;
    };
    CHECK_FALSE(has("HTTPS"));
    CHECK_FALSE(has("PATH_INFO"));
    CHECK_FALSE(has("CONTENT_LENGTH"));
}
