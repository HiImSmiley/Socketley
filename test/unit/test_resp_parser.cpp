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

    SUBCASE("inline command input")
    {
        std::string buf = "set key value\r\n";
        auto result = resp::parse_message(buf, args, consumed);
        CHECK(result == resp::parse_result::ok);
        REQUIRE(args.size() == 3);
        CHECK(args[0] == "set");
        CHECK(args[1] == "key");
        CHECK(args[2] == "value");
        CHECK(consumed == buf.size());
    }
}

// The parser the product actually runs.
//
// Everything above exercises parse_message(), which no runtime calls: the only
// two call sites in socketley/ are cache_instance.cpp and server_instance.cpp,
// and both call parse_message_views().  parse_message() is the differential
// reference fuzz_resp.cpp measures against and the subject of every assertion
// in this file — so the eight checks above could all pass while the parser that
// reads unauthenticated bytes off a socket was broken in any way they describe.
//
// Same cases, same expectations, against the one that runs.  MAX_RESP_ARGS is
// 64 in both call sites; 8 here is enough for these messages and small enough
// that the ceiling case below is cheap to state.
TEST_CASE("RESP parsing — parse_message_views, the parser the runtimes call")
{
    static constexpr int MAX_ARGS = 8;
    std::string_view views[MAX_ARGS];
    int    argc     = 0;
    size_t consumed = 0;

    SUBCASE("simple SET command")
    {
        std::string buf = "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n";
        auto result = resp::parse_message_views(buf, views, MAX_ARGS, argc, consumed);
        CHECK(result == resp::parse_result::ok);
        CHECK(consumed == buf.size());
        REQUIRE(argc == 3);
        CHECK(views[0] == "SET");
        CHECK(views[1] == "key");
        CHECK(views[2] == "value");
    }

    SUBCASE("GET command")
    {
        std::string buf = "*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
        auto result = resp::parse_message_views(buf, views, MAX_ARGS, argc, consumed);
        CHECK(result == resp::parse_result::ok);
        REQUIRE(argc == 2);
        CHECK(views[0] == "GET");
        CHECK(views[1] == "key");
    }

    SUBCASE("incomplete message")
    {
        std::string buf = "*2\r\n$3\r\nGET\r\n$3\r\nke";
        auto result = resp::parse_message_views(buf, views, MAX_ARGS, argc, consumed);
        CHECK(result == resp::parse_result::incomplete);
    }

    SUBCASE("empty buffer")
    {
        std::string buf = "";
        auto result = resp::parse_message_views(buf, views, MAX_ARGS, argc, consumed);
        CHECK(result == resp::parse_result::incomplete);
    }

    SUBCASE("PING command")
    {
        std::string buf = "*1\r\n$4\r\nPING\r\n";
        auto result = resp::parse_message_views(buf, views, MAX_ARGS, argc, consumed);
        CHECK(result == resp::parse_result::ok);
        REQUIRE(argc == 1);
        CHECK(views[0] == "PING");
    }

    SUBCASE("multiple messages in buffer")
    {
        std::string buf = "*1\r\n$4\r\nPING\r\n*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
        auto result = resp::parse_message_views(buf, views, MAX_ARGS, argc, consumed);
        CHECK(result == resp::parse_result::ok);
        REQUIRE(argc == 1);
        CHECK(views[0] == "PING");
        CHECK(consumed < buf.size());

        std::string_view remaining(buf.data() + consumed, buf.size() - consumed);
        result = resp::parse_message_views(remaining, views, MAX_ARGS, argc, consumed);
        CHECK(result == resp::parse_result::ok);
        REQUIRE(argc == 2);
        CHECK(views[0] == "GET");
        CHECK(views[1] == "key");
    }

    SUBCASE("inline command input")
    {
        std::string buf = "set key value\r\n";
        auto result = resp::parse_message_views(buf, views, MAX_ARGS, argc, consumed);
        CHECK(result == resp::parse_result::ok);
        REQUIRE(argc == 3);
        CHECK(views[0] == "set");
        CHECK(views[1] == "key");
        CHECK(views[2] == "value");
        CHECK(consumed == buf.size());
    }

    // The array ceiling, which is this parser's and not the reference's: an
    // array declaring more elements than the caller offered room for is refused
    // rather than truncated.  fuzz_resp.cpp skips its differential comparison
    // whenever the reference produced more arguments than this allows, so the
    // behaviour is asserted here or nowhere.
    SUBCASE("more elements than the caller has room for")
    {
        std::string buf = "*9\r\n$1\r\na\r\n$1\r\nb\r\n$1\r\nc\r\n$1\r\nd\r\n"
                          "$1\r\ne\r\n$1\r\nf\r\n$1\r\ng\r\n$1\r\nh\r\n$1\r\ni\r\n";
        auto result = resp::parse_message_views(buf, views, MAX_ARGS, argc, consumed);
        CHECK(result == resp::parse_result::too_many_args);
    }

    // The one shape the two parsers are known to read differently, recorded
    // here rather than only as a nightly observation nobody reads.
    //
    // fuzz_resp.cpp names it: parse_message calls "*1\r\nX" an error, because it
    // checks for '$' before checking the length, and this one calls it
    // incomplete, because it wants four bytes of element header first.  Neither
    // is wrong — the bytes are not a valid message either way — and the
    // consequence of the difference is bounded only because a runtime calls one
    // of them.  Written down so that a change to either is a decision somebody
    // makes rather than a nightly line that starts appearing.
    SUBCASE("the shape the two parsers read differently")
    {
        std::string buf = "*1\r\nX";
        auto result = resp::parse_message_views(buf, views, MAX_ARGS, argc, consumed);
        CHECK(result == resp::parse_result::incomplete);

        std::vector<std::string> ref_args;
        size_t ref_consumed = 0;
        auto ref = resp::parse_message(buf, ref_args, ref_consumed);
        CHECK(ref == resp::parse_result::error);

        // The point of recording it: whatever they each say, neither accepts it.
        CHECK(result != resp::parse_result::ok);
        CHECK(ref    != resp::parse_result::ok);
    }
}

TEST_CASE("a bulk value's trailing CRLF is part of the frame, not padding")
{
    // Both parsers skipped the two bytes after a bulk payload without reading
    // them, so "$3\r\nfooXY" parsed as "foo".  The length field is the only
    // thing that frames a RESP stream: once it misstates the payload, every
    // later byte is parsed at a shifted offset, and the inline-command
    // fallback will execute whatever lands on the new boundary.  Redis
    // answers "Protocol error: expected '\r\n'"; so must we.
    std::vector<std::string> args;
    std::string_view views[8];
    int    argc     = 0;
    size_t consumed = 0;

    SUBCASE("single-digit length, the views fast path")
    {
        std::string buf = "*1\r\n$4\r\nPINGXX";
        CHECK(resp::parse_message_views(buf, views, 8, argc, consumed)
              == resp::parse_result::error);
        CHECK(resp::parse_message(buf, args, consumed)
              == resp::parse_result::error);
    }

    SUBCASE("multi-digit length, the views slow path")
    {
        std::string buf = "*1\r\n$10\r\nabcdefghijXX";
        CHECK(resp::parse_message_views(buf, views, 8, argc, consumed)
              == resp::parse_result::error);
        CHECK(resp::parse_message(buf, args, consumed)
              == resp::parse_result::error);
    }

    SUBCASE("a lying terminator mid-frame, not only on the last element")
    {
        std::string buf = "*3\r\n$3\r\nSET\r\n$3\r\nkeyXY$5\r\nvalue\r\n";
        CHECK(resp::parse_message_views(buf, views, 8, argc, consumed)
              == resp::parse_result::error);
        CHECK(resp::parse_message(buf, args, consumed)
              == resp::parse_result::error);
    }

    SUBCASE("a payload may contain CRLF; only the terminator position is framed")
    {
        // Length-based skipping must stay length-based: a fix that scanned for
        // the next CRLF instead of checking the byte AT offset+len would
        // reject this legal frame.  Value is "a\r\nb", length 4.
        std::string buf = "*1\r\n$4\r\na\r\nb\r\n";
        auto result = resp::parse_message_views(buf, views, 8, argc, consumed);
        CHECK(result == resp::parse_result::ok);
        CHECK(consumed == buf.size());
        REQUIRE(argc == 1);
        CHECK(views[0] == "a\r\nb");

        CHECK(resp::parse_message(buf, args, consumed) == resp::parse_result::ok);
        REQUIRE(args.size() == 1);
        CHECK(args[0] == "a\r\nb");
    }

    SUBCASE("a truncated terminator is incomplete, not an error")
    {
        // The bytes seen so far are consistent with a valid frame still in
        // flight; erroring here would kill pipelined clients on a short read.
        std::string buf = "*1\r\n$4\r\nPING\r";
        CHECK(resp::parse_message_views(buf, views, 8, argc, consumed)
              == resp::parse_result::incomplete);
        CHECK(resp::parse_message(buf, args, consumed)
              == resp::parse_result::incomplete);
    }
}
