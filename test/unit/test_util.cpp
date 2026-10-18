#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "shared/http/cookie.h"
#include "shared/util/ascii.h"
#include "shared/util/number_parse.h"
#include "shared/util/proc_stat.h"

#include <chrono>
#include <string>

#include <cstdlib>

#include <unistd.h>

// The small helpers in shared/util that every runtime leans on.

TEST_CASE("ASCII case folds A to Z and nothing else")
{
    std::string s = "HgEtAlL";
    socketley::ascii::lower_in_place(s);
    CHECK(s == "hgetall");
    // A byte past ASCII is no letter here, whatever a locale would make of it.
    std::string latin = "\xC4\xD6@[`{";
    socketley::ascii::lower_in_place(latin);
    CHECK(latin == "\xC4\xD6@[`{");
    CHECK(socketley::ascii::iequals("MaxLen", "MAXLEN"));
    CHECK_FALSE(socketley::ascii::iequals("maxlen", "maxle"));
    CHECK_FALSE(socketley::ascii::iequals("@", "`"));
    CHECK(socketley::ascii::upper('z') == 'Z');
}

TEST_CASE("a process's /proc stat line is read from after its name, and a gone one reads as nothing")
{
    socketley::proc_stat st;
    REQUIRE(socketley::read_proc_stat(::getpid(), st));
    CHECK(st.state == 'R');
    CHECK(st.rss_pages > 0);
    // Burning a little CPU moves the ticks, which is what a wedge check measures.
    const uint64_t before = st.utime + st.stime;
    const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    volatile uint64_t spin = 0;
    while (st.utime + st.stime == before && std::chrono::steady_clock::now() < until)
    {
        for (uint64_t i = 0; i < 1000000; ++i)
            spin = spin + i;
        REQUIRE(socketley::read_proc_stat(::getpid(), st));
    }
    CHECK(st.utime + st.stime > before);
    socketley::proc_stat gone{'x', 1, 2, 3};
    CHECK_FALSE(socketley::read_proc_stat(0x7ffffff0, gone));
    CHECK(gone.state == 'x');
}

TEST_CASE("every cookie of a name is visited in order until one is taken")
{
    const std::string_view h = "a=1; skl=first;skl=second; \tskl=third; skl2=no; xskl=no";
    std::string seen;
    CHECK_FALSE(socketley::http::for_each_cookie(h, "skl", [&](std::string_view v) {
        seen += std::string(v) + ",";
        return false;
    }));
    CHECK(seen == "first,second,third,");
    CHECK(socketley::http::for_each_cookie(h, "skl", [](std::string_view v) { return v == "second"; }));
    CHECK(socketley::http::cookie_value(h, "skl") == "first");
    CHECK(socketley::http::cookie_value(h, "a") == "1");
    CHECK(socketley::http::cookie_value(h, "missing").empty());
    CHECK(socketley::http::cookie_value("skl=", "skl").empty());
}

TEST_CASE("a number in the environment is read whole or not at all")
{
    const auto read = [](const char* v) {
        ::setenv("SOCKETLEY_TEST_NUMBER", v, 1);
        return socketley::getenv_whole<uint32_t>("SOCKETLEY_TEST_NUMBER", 1, 4096);
    };
    CHECK(read("512") == 512u);
    // A typo is the default, never the number read off its front.
    CHECK_FALSE(read("512x"));
    CHECK_FALSE(read(" 512"));
    CHECK_FALSE(read("+512"));
    CHECK_FALSE(read(""));
    CHECK_FALSE(read("-1"));
    CHECK_FALSE(read("0"));
    CHECK_FALSE(read("4097"));
    CHECK_FALSE(read("99999999999"));
    ::unsetenv("SOCKETLEY_TEST_NUMBER");
    CHECK_FALSE(socketley::getenv_whole<uint32_t>("SOCKETLEY_TEST_NUMBER"));
}
