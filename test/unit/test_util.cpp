#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "shared/http/cookie.h"
#include "shared/net/failure_bar.h"
#include "shared/util/ascii.h"
#include "shared/util/number_parse.h"
#include "shared/util/settings.h"
#include "shared/util/proc_stat.h"
#include "shared/util/byte_codec.h"
#include "shared/runtime/stats_text.h"
#include "shared/loop/line_framing.h"

#include <chrono>
#include <random>
#include <string>
#include <vector>

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

TEST_CASE("the cookies a proxy took are left out of what it forwards, every other one kept")
{
    CHECK(socketley::http::without_cookies(" a=1; skl=x;skl_known=y; \tb=2;skl =z; skl2=3", {"skl", "skl_known"}) ==
          "a=1; b=2; skl2=3");
    CHECK(socketley::http::without_cookies("skl=x; skl=y", {"skl"}).empty());
    CHECK(socketley::http::without_cookies("theme=dark", {"skl"}) == "theme=dark");
    CHECK(socketley::http::without_cookies("", {"skl"}).empty());
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

TEST_CASE("an address that keeps failing is barred until its window ends, and the remembered ones are bounded")
{
    using namespace std::chrono_literals;
    socketley::failure_bar bar(3, 15min, 64);
    const auto t0 = socketley::failure_bar::clock::now();
    for (int i = 0; i < 2; ++i)
        bar.missed("a", t0);
    CHECK(bar.barred_for("a", t0) == 0);
    bar.missed("a", t0 + 1s);
    CHECK(bar.barred_for("a", t0 + 1s) == 15 * 60 - 1);
    CHECK(bar.barred_for("a", t0 + 15min - 500ms) == 1);
    CHECK(bar.barred_for("b", t0 + 1s) == 0);
    // The window is counted from the first failure, so it ends whole and counting starts again.
    CHECK(bar.barred_for("a", t0 + 15min) == 0);
    bar.missed("a", t0 + 15min);
    CHECK(bar.barred_for("a", t0 + 15min) == 0);
    // A flood of new addresses past the bound keeps the newest and forgets the oldest.
    for (int i = 0; i < 1000; ++i)
        for (int k = 0; k < 3; ++k)
            bar.missed("flood" + std::to_string(i), t0 + std::chrono::seconds(i));
    CHECK(bar.barred_for("flood999", t0 + 999s) > 0);
    CHECK(bar.barred_for("flood0", t0 + 1s) == 0);
}

TEST_CASE("a setting is read through its table entry: its range, its flag rule and its name in the file")
{
    namespace st = socketley::settings;
    ::setenv("SOCKETLEY_STORAGE_HASH_THREADS", "4", 1);
    CHECK(st::number<unsigned>("SOCKETLEY_STORAGE_HASH_THREADS") == 4u);
    // Past the table's range, or no whole number, is the default and never a guess.
    ::setenv("SOCKETLEY_STORAGE_HASH_THREADS", "17", 1);
    CHECK_FALSE(st::number<unsigned>("SOCKETLEY_STORAGE_HASH_THREADS"));
    ::setenv("SOCKETLEY_STORAGE_HASH_THREADS", "4x", 1);
    CHECK_FALSE(st::number<unsigned>("SOCKETLEY_STORAGE_HASH_THREADS"));
    ::unsetenv("SOCKETLEY_STORAGE_HASH_THREADS");
    CHECK_FALSE(st::number<unsigned>("SOCKETLEY_STORAGE_HASH_THREADS"));
    // A table range wider than the type asked for is still bounded by the type.
    ::setenv("SOCKETLEY_STORAGE_HOT_BYTES", "70000", 1);
    CHECK_FALSE(st::number<uint16_t>("SOCKETLEY_STORAGE_HOT_BYTES"));
    CHECK(st::number<uint64_t>("SOCKETLEY_STORAGE_HOT_BYTES") == 70000u);
    ::unsetenv("SOCKETLEY_STORAGE_HOT_BYTES");

    ::unsetenv("SOCKETLEY_PROXY_SPLICE");
    CHECK_FALSE(st::flag("SOCKETLEY_PROXY_SPLICE", false));
    ::setenv("SOCKETLEY_PROXY_SPLICE", "1", 1);
    CHECK(st::flag("SOCKETLEY_PROXY_SPLICE", false));
    ::setenv("SOCKETLEY_PROXY_SPLICE", "0", 1);
    CHECK_FALSE(st::flag("SOCKETLEY_PROXY_SPLICE", true));
    ::setenv("SOCKETLEY_PROXY_SPLICE", "", 1);
    CHECK(st::flag("SOCKETLEY_PROXY_SPLICE", true));
    ::unsetenv("SOCKETLEY_PROXY_SPLICE");

    const st::setting* s = st::by_config_name("storage_hash_threads");
    REQUIRE(s);
    CHECK(s->name == "SOCKETLEY_STORAGE_HASH_THREADS");
    CHECK(st::refusal(*s, "4").empty());
    CHECK(st::refusal(*s, "99") == "storage_hash_threads is 99, not a whole number from 0 to 16");
    CHECK_FALSE(st::by_config_name("SOCKETLEY_STORAGE_HASH_THREADS"));
    CHECK_FALSE(st::by_config_name("no_such_thing"));
    // Every name is the program's own, and the file's spelling of each leads back to it.
    for (const st::setting& e : st::table)
    {
        CHECK(e.name.starts_with("SOCKETLEY_"));
        CHECK(st::by_config_name(st::config_name(e)) == &e);
        CHECK_FALSE(e.meaning.empty());
    }
}

TEST_CASE("a frame opens with its marker, and a flag is one byte that is 0 or 1")
{
    socketley::bytes::writer w("cross:");
    w.flag(true);
    w.flag(false);
    const std::string frame = w.take();
    CHECK(frame == std::string("cross:\x01\x00", 8));

    socketley::bytes::reader r(frame);
    bool a = false, b = true;
    CHECK_FALSE(socketley::bytes::reader(frame).marker("other:"));
    CHECK(r.marker("cross:"));
    CHECK(r.flag(a));
    CHECK(r.flag(b));
    CHECK(a);
    CHECK_FALSE(b);
    CHECK(r.left() == 0);

    bool c = false;
    CHECK_FALSE(socketley::bytes::reader(std::string_view("\x02", 1)).flag(c));
}

TEST_CASE("a stats text is read field by field, the last line too without a newline")
{
    const std::string_view text = "name:a\nnot a field\nbytes:10\nbytes:20\nlast_error:disk: full";
    std::vector<std::pair<std::string, std::string>> seen;
    socketley::stats_text::for_each_field(text, [&](std::string_view k, std::string_view v) {
        seen.emplace_back(k, v);
    });
    REQUIRE(seen.size() == 4);
    CHECK(seen[3] == std::pair<std::string, std::string>{"last_error", "disk: full"});
    CHECK(socketley::stats_text::field(text, "bytes") == "10");
    CHECK(socketley::stats_text::field(text, "last_error") == "disk: full");
    CHECK(socketley::stats_text::field(text, "byte").empty());
    CHECK(socketley::stats_text::field("", "name").empty());

    size_t calls = 0;
    socketley::stats_text::for_each_field(text, [&](std::string_view, std::string_view) { return ++calls < 2; });
    CHECK(calls == 2);
}

TEST_CASE("the line index finds every newline and counts the lines on_message is handed, long lines too")
{
    // Lines short and long around the 64 bytes past which the index hands its search to memchr, some empty or
    // ending in '\r', in buffers of every length mod 16.
    std::mt19937 rng(7);
    socketley::line_ends ends;
    for (int round = 0; round < 400; ++round)
    {
        std::string data;
        const size_t want = 1 + rng() % 9000;
        while (data.size() < want)
        {
            const unsigned kind = rng() % 6;
            const size_t n = kind == 0 ? 0 : kind < 3 ? rng() % 20 : kind < 5 ? 40 + rng() % 60 : 100 + rng() % 5000;
            data.append(n, 'x');
            if (rng() % 4 == 0)
                data += '\r';
            data += '\n';
        }
        if (rng() % 2)
            data.append(rng() % 40, 'y');
        std::vector<uint32_t> at;
        size_t lines = 0, start = 0;
        for (size_t i = 0; i < data.size(); ++i)
        {
            if (data[i] != '\n')
                continue;
            at.push_back(static_cast<uint32_t>(i));
            lines += i != start && !(i == start + 1 && data[start] == '\r');
            start = i + 1;
        }
        const size_t got = socketley::index_lines(data.data(), data.size(), ends);
        REQUIRE(ends.size == at.size());
        CHECK(std::equal(at.begin(), at.end(), ends.at.get()));
        CHECK(got == lines);
        CHECK(got == socketley::count_lines(data.data(), data.size()));
    }
}
