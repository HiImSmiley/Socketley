// The header-name comparisons every HTTP path frames a message by: a letter matches in either case, and every other
// byte only as itself, so no control byte stands in for the hyphen of Content-Length or Transfer-Encoding.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <string_view>

#include "shared/http/http_framing.h"

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
