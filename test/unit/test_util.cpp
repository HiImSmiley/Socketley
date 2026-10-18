#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "shared/util/ascii.h"
#include "shared/util/proc_stat.h"

#include <chrono>
#include <string>

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
