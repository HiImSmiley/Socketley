// The header-name comparisons every HTTP path frames a message by: a letter matches in either case, and every other
// byte only as itself, so no control byte stands in for the hyphen of Content-Length or Transfer-Encoding.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <string_view>

#include "shared/http/http_framing.h"
#include "shared/http/request_head.h"

#include <string>
#include <utility>
#include <vector>

TEST_CASE("a field name matches a literal in any letter case")
{
    CHECK(header_name_equals("Content-Length: 5", "content-length", 14));
    CHECK(header_name_equals("CONTENT-LENGTH:5", "content-length", 14));
    CHECK(http_token_equals("Transfer-Encoding", "transfer-encoding", 17));
    CHECK(http_token_equals("CHUNKED", "chunked", 7));
}

TEST_CASE("a byte that is not a letter matches only itself")
{
    CHECK_FALSE(header_name_equals(std::string_view("Content\rLength: 5", 17), "content-length", 14));
    CHECK_FALSE(http_token_equals(std::string_view("transfer\rencoding", 17), "transfer-encoding", 17));
    CHECK_FALSE(http_token_equals(std::string_view("x\x11", 2), "x1", 2));
    CHECK_FALSE(http_token_equals("x\x7f", "x_", 2));
    CHECK(http_list_has_token("keep-alive, Upgrade", "upgrade", 7));
    CHECK_FALSE(http_list_has_token(std::string_view("keep\ralive", 10), "keep-alive", 10));
}

TEST_CASE("a request whose Content-Length is spelled with a CR for its hyphen is not framed by it")
{
    const http_request_framing_scan s = http_scan_request_headers(std::string_view("Content\rLength: 5\r\n\r\n", 21));
    CHECK_FALSE(s.has_content_length);
    const http_request_framing_scan t = http_scan_request_headers("Content-Length: 5\r\n\r\n");
    CHECK(t.has_content_length);
    CHECK(t.content_length == 5);
}

TEST_CASE("a request field name that is not a token is refused, so no backend's trimmed reading of it frames the body")
{
    CHECK_FALSE(http_scan_request_headers("Host: x\r\nTransfer-Encoding\x0b: chunked\r\nContent-Length: 5").ok);
    CHECK_FALSE(http_scan_request_headers("Host: x\r\nContent-Length\x0c: 5").ok);
    CHECK_FALSE(http_scan_request_headers("Host: x\r\n\x0b" "Transfer-Encoding: chunked").ok);
    CHECK_FALSE(http_scan_request_headers(std::string_view("Host: x\r\nX-A\0: 1", 16)).ok);
    CHECK_FALSE(http_scan_request_headers("Host: x\r\nX-A\x7f: 1").ok);
    CHECK_FALSE(http_scan_request_headers("Host: x\r\nX-Forwarded-User\x0b: admin").ok);
    CHECK_FALSE(http_scan_request_headers("Host: x\r\nContent-Length : 5").ok);
    const http_request_framing_scan s = http_scan_request_headers("Host: x\r\nX_Odd.Name~2!: 1\r\nContent-Length: 5");
    CHECK(s.ok);
    CHECK(s.content_length == 5);
}

TEST_CASE("a head checked a byte at a time from where the last check stopped is judged as it is whole")
{
    const char* const heads[] = {
        "GET / HTTP/1.1\r\nHost: h\r\n\r\n", "GET / HTTP/1.1\r\nHost: h\n\r\n", "GET / HTTP/1.1\rHost: h\r\n",
        "GET / HTTP/1.1\r\n\nHost: h\r\n", "\nGET /", "GET /\r", "GET /\r\r\n", "\r\n\r\n"};
    for (const std::string_view whole : heads)
        for (const bool complete : {false, true})
        {
            size_t passed = 0;
            bool ok = true;
            for (size_t n = 1; n <= whole.size() && ok; ++n)
            {
                ok = http_eol_framing_ok(whole.substr(0, n), complete && n == whole.size(), passed);
                passed = n;
            }
            CHECK(ok == http_eol_framing_ok(whole, complete));
        }
}

TEST_CASE("an Authorization scheme is matched in any case and its credentials trimmed")
{
    std::string_view cred;
    REQUIRE(http_auth_credentials("Basic dXNlcjpwdw==", "basic", cred));
    CHECK(cred == "dXNlcjpwdw==");
    REQUIRE(http_auth_credentials("BEARER   tok  ", "bearer", cred));
    CHECK(cred == "tok");
    CHECK(http_auth_credentials("bearer x", "bearer", cred));
    CHECK_FALSE(http_auth_credentials("Bearerx", "bearer", cred));
    CHECK_FALSE(http_auth_credentials("Bearer", "bearer", cred));
    CHECK_FALSE(http_auth_credentials("Basic x", "bearer", cred));
    CHECK_FALSE(http_auth_credentials(std::string_view("Bea\rer x", 8), "bearer", cred));
}

namespace
{

struct taken
{
    int r{0};
    int status{0};
    socketley::http::request_view v;
    std::vector<std::pair<std::string, std::string>> fields;
};

taken take(std::string_view in, size_t max_head = 1024, size_t max_body = 64)
{
    taken t;
    t.r = socketley::http::take_request(in, max_head, max_body, t.v, t.status, [&t](std::string_view f, std::string_view v) {
        t.fields.emplace_back(std::string(f.substr(0, f.find(':'))), std::string(v));
    });
    return t;
}

}   // namespace

TEST_CASE("a request is taken whole: its line, its fields, its body, and the next one behind it left alone")
{
    const std::string two = "POST /c/x?y=1 HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nX-A:  v \r\n\r\nabcGET / HTTP/1.1\r\n\r\n";
    taken t = take(two);
    REQUIRE(t.r == 1);
    CHECK(t.v.method == "POST");
    CHECK(t.v.path == "/c/x");
    CHECK(t.v.query == "y=1");
    CHECK(t.v.body_len == 3);
    CHECK(two.substr(t.v.head_len, t.v.body_len) == "abc");
    CHECK_FALSE(t.v.close);
    REQUIRE(t.fields.size() == 3);
    CHECK(t.fields[2] == std::pair<std::string, std::string>{"X-A", "v"});
    taken next = take(std::string_view(two).substr(t.v.head_len + t.v.body_len));
    CHECK(next.r == 1);
    CHECK(next.v.method == "GET");
}

TEST_CASE("a request not yet whole waits, and one that cannot be read is refused with its status")
{
    CHECK(take("GET / HTTP/1.1\r\nHost: h\r\n").r == 0);
    CHECK(take("POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab").r == 0);
    taken big = take("POST / HTTP/1.1\r\nContent-Length: 65\r\n\r\n");
    CHECK(big.r == -1);
    CHECK(big.status == 413);
    taken te = take("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
    CHECK(te.r == -1);
    CHECK(te.status == 411);
    CHECK(take(std::string(2000, 'a'), 1024).status == 431);
    CHECK(take("GET / HTTP/2.0\r\n\r\n").status == 400);
    CHECK(take("GET /\r\n\r\n").r == -1);
    CHECK(take("GET / HTTP/1.1\nHost: h\r\n\r\n").r == -1);
}

TEST_CASE("keep-alive is the version's, and the last Connection field's when there is one")
{
    CHECK(take("GET / HTTP/1.0\r\n\r\n").v.close);
    CHECK_FALSE(take("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n").v.close);
    CHECK(take("GET / HTTP/1.1\r\nConnection: close\r\n\r\n").v.close);
    CHECK_FALSE(take("GET / HTTP/1.1\r\nConnection: close\r\nConnection: keep-alive\r\n\r\n").v.close);
    CHECK(take("GET / HTTP/1.1\r\nConnection: Upgrade, close\r\n\r\n").v.close);
    CHECK(take("GET / HTTP/1.1\r\nConnection: close\r\n\r\n").fields.empty());
}
