// The one JSON string writer and the strict reader's accessors every runtime, the daemon and the CLI now share: what
// goes in comes back the same bytes, and a byte JSON has no literal for is escaped rather than written raw or dropped.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <string>

#include "shared/json/json_doc.h"
#include "shared/json/json_escape.h"

using namespace socketley::json;

TEST_CASE("a string is quoted with its quote, backslash and control bytes escaped, the rest as it is")
{
    CHECK(quote("") == "\"\"");
    CHECK(quote("plain text") == "\"plain text\"");
    CHECK(quote("a\"b\\c") == "\"a\\\"b\\\\c\"");
    CHECK(quote("l1\nl2\r\tx") == "\"l1\\nl2\\r\\tx\"");
    CHECK(quote(std::string_view("\x01\x08\x0c\x1f", 4)) == "\"\\u0001\\u0008\\u000c\\u001f\"");
    CHECK(quote(std::string_view("nul\0in", 6)) == "\"nul\\u0000in\"");
    CHECK(quote("ünï \x7f") == "\"ünï \x7f\"");
    CHECK(escape("x\"y") == "x\\\"y");
    std::string out = "{\"k\":";
    quote_into(out, "v");
    CHECK(out == "{\"k\":\"v\"");
}

TEST_CASE("every byte comes back from the reader as it was written")
{
    std::string all;
    for (int c = 1; c < 128; ++c)
        all += static_cast<char>(c);
    all += "ü€";
    jvalue doc;
    REQUIRE(json_reader("{\"s\":" + quote(all) + "}").document(doc));
    CHECK(string_of(doc, "s") == all);
}

TEST_CASE("a member is found by name, and a string or a whole number read from it, a default for anything else")
{
    jvalue doc;
    REQUIRE(json_reader(R"({"name":"n1","port":8080,"neg":-3,"frac":1.5,"big":99999999999999999999,"str":"7",)"
                        R"("list":[{"name":"a"},{"name":"b"}],"nested":{"name":"inner"}})")
                .document(doc));
    CHECK(string_of(doc, "name") == "n1");
    CHECK(int_of(doc, "port") == 8080);
    CHECK(int_of(doc, "neg") == -3);
    CHECK(int_of(doc, "frac", -1) == -1);
    CHECK(int_of(doc, "big", -1) == -1);
    CHECK(int_of(doc, "str", -1) == -1);
    CHECK(string_of(doc, "port").empty());
    CHECK(int_of(doc, "missing", 42) == 42);
    CHECK_FALSE(member(doc, "missing"));
    // A member of a nested object is that object's, not its parent's.
    CHECK(string_of(*member(doc, "nested"), "name") == "inner");
    const jvalue* list = member(doc, "list");
    REQUIRE(list);
    REQUIRE(list->items.size() == 2);
    CHECK(string_of(list->items[1], "name") == "b");
    CHECK_FALSE(member(list->items[0], "nope"));
    CHECK_FALSE(member(*list, "name"));
}
