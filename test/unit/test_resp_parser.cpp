#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "../../socketley/runtime/cache/resp_parser.h"

TEST_CASE("RESP encoding")
{
    SUBCASE("encode_ok")
    {
        CHECK(resp::encode_ok() == "+OK\r\n");
    }

    SUBCASE("encode_error")
    {
        CHECK(resp::encode_error("test error") == "-ERR test error\r\n");
    }

    SUBCASE("encode_integer")
    {
        CHECK(resp::encode_integer(42) == ":42\r\n");
        CHECK(resp::encode_integer(0) == ":0\r\n");
        CHECK(resp::encode_integer(-1) == ":-1\r\n");
    }

    SUBCASE("encode_bulk")
    {
        CHECK(resp::encode_bulk("hello") == "$5\r\nhello\r\n");
        CHECK(resp::encode_bulk("") == "$0\r\n\r\n");
    }

    SUBCASE("encode_null")
    {
        CHECK(resp::encode_null() == "$-1\r\n");
    }

    SUBCASE("encode_array_header")
    {
        CHECK(resp::encode_array_header(3) == "*3\r\n");
        CHECK(resp::encode_array_header(0) == "*0\r\n");
    }

    SUBCASE("encode_simple")
    {
        CHECK(resp::encode_simple("PONG") == "+PONG\r\n");
    }
}

TEST_CASE("RESP parsing")
{
    std::vector<std::string> args;
    size_t consumed = 0;

    SUBCASE("simple SET command")
    {
        std::string buf = "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n";
        auto result = resp::parse_message(buf, args, consumed);
        CHECK(result == resp::parse_result::ok);
        CHECK(consumed == buf.size());
        REQUIRE(args.size() == 3);
        CHECK(args[0] == "SET");
        CHECK(args[1] == "key");
        CHECK(args[2] == "value");
    }

    SUBCASE("GET command")
    {
        std::string buf = "*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
        auto result = resp::parse_message(buf, args, consumed);
        CHECK(result == resp::parse_result::ok);
        REQUIRE(args.size() == 2);
        CHECK(args[0] == "GET");
        CHECK(args[1] == "key");
    }

    SUBCASE("incomplete message")
    {
        std::string buf = "*2\r\n$3\r\nGET\r\n$3\r\nke";
        auto result = resp::parse_message(buf, args, consumed);
        CHECK(result == resp::parse_result::incomplete);
    }

    SUBCASE("empty buffer")
    {
        std::string buf = "";
        auto result = resp::parse_message(buf, args, consumed);
        CHECK(result == resp::parse_result::incomplete);
    }

    SUBCASE("PING command")
    {
        std::string buf = "*1\r\n$4\r\nPING\r\n";
        auto result = resp::parse_message(buf, args, consumed);
        CHECK(result == resp::parse_result::ok);
        REQUIRE(args.size() == 1);
        CHECK(args[0] == "PING");
    }

    SUBCASE("multiple messages in buffer")
    {
        std::string buf = "*1\r\n$4\r\nPING\r\n*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
        auto result = resp::parse_message(buf, args, consumed);
        CHECK(result == resp::parse_result::ok);
        REQUIRE(args.size() == 1);
        CHECK(args[0] == "PING");
        CHECK(consumed < buf.size());

        // Parse second message
        std::string_view remaining(buf.data() + consumed, buf.size() - consumed);
        result = resp::parse_message(remaining, args, consumed);
        CHECK(result == resp::parse_result::ok);
        REQUIRE(args.size() == 2);
        CHECK(args[0] == "GET");
    }

    SUBCASE("non-RESP input")
    {
        std::string buf = "set key value\r\n";
        auto result = resp::parse_message(buf, args, consumed);
        CHECK(result == resp::parse_result::error);
    }
}

TEST_CASE("RESP to_lower")
{
    SUBCASE("uppercase")
    {
        std::string s = "GET";
        resp::to_lower(s);
        CHECK(s == "get");
    }

    SUBCASE("mixed case")
    {
        std::string s = "HgEtAlL";
        resp::to_lower(s);
        CHECK(s == "hgetall");
    }

    SUBCASE("already lowercase")
    {
        std::string s = "set";
        resp::to_lower(s);
        CHECK(s == "set");
    }
}
