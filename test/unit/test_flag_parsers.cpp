#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <cmath>
#include "doctest.h"
#include "../../socketley/daemon/flag_handlers.h"

#include <cstdint>
#include <limits>

// ─── WHY THESE FOUR ARE TESTED TOGETHER ─────────────────────────────────────
//
// They are one contract with four spellings, and until this file existed only
// two of them kept it: parse_uint16 and parse_uint32 both end with
// `ptr == sv.data() + sv.size()`, and the other two did not.
//
// from_chars and stod are both happy to read a PREFIX and report success, so a
// parser that does not check the position accepts trailing anything and takes
// the number in front of it.  Measured on the parent commit, through the flag
// each one serves:
//
//     --maxmemory 100MB     ->        100 bytes   (wanted 104857600)
//     --maxmemory 100X      ->        100 bytes
//     --maxmemory 17179869184G ->       0 bytes   -- and 0 is "unlimited"
//     --rate-limit 5abc     ->          5
//
// The size case is the one with teeth: `100MB` is the likeliest typo there is
// for a size, and it configured a cache to a hundred bytes — one that runs,
// accepts connections and stores nothing.  The overflow is worse for being
// plausible in the other direction: 2^34 G is exactly 2^64, so an absurdly high
// cap wrapped to the value that means no cap at all.
//
// The table below is what the flag handlers actually see, so a later change to
// any of the four has to keep answering it the same way.

TEST_CASE("parse_uint16 takes the whole string or nothing")
{
    uint16_t v = 0;
    CHECK(parse_uint16("0", v));      CHECK(v == 0);
    CHECK(parse_uint16("8080", v));   CHECK(v == 8080);
    CHECK(parse_uint16("65535", v));  CHECK(v == 65535);

    CHECK_FALSE(parse_uint16("65536", v));   // out of range
    CHECK_FALSE(parse_uint16("80a", v));     // trailing
    CHECK_FALSE(parse_uint16("a80", v));     // leading
    CHECK_FALSE(parse_uint16("", v));
    CHECK_FALSE(parse_uint16("-1", v));
    CHECK_FALSE(parse_uint16(" 80", v));     // from_chars does not skip space
}

TEST_CASE("parse_uint32 takes the whole string or nothing")
{
    uint32_t v = 0;
    CHECK(parse_uint32("4294967295", v)); CHECK(v == 4294967295u);
    CHECK(parse_uint32("77", v));         CHECK(v == 77u);

    CHECK_FALSE(parse_uint32("4294967296", v));
    CHECK_FALSE(parse_uint32("77x", v));
    CHECK_FALSE(parse_uint32("", v));
    CHECK_FALSE(parse_uint32("-5", v));
}

TEST_CASE("parse_double takes the whole string or nothing")
{
    double d = 0;
    CHECK(parse_double("5", d));      CHECK(d == doctest::Approx(5.0));
    CHECK(parse_double("0.5", d));    CHECK(d == doctest::Approx(0.5));
    CHECK(parse_double("-2.25", d));  CHECK(d == doctest::Approx(-2.25));

    // Every one of these used to be accepted, taking the number in front.
    CHECK_FALSE(parse_double("5abc", d));
    CHECK_FALSE(parse_double("0.5 ", d));
    CHECK_FALSE(parse_double("", d));
    CHECK_FALSE(parse_double("abc", d));
}

// NaN parses as a number and behaves as none: every comparison against it is
// false, so the guards a caller writes afterwards neither reject nor accept it.
// --rate-limit nan was taken and meant NO rate limit at all -- 40 of 40 commands
// served, where a limit of 5 served 5 -- because `rate < 0` did not reject it at
// the door and `rate > 0` did not enable the limiter behind it.
TEST_CASE("parse_double refuses NaN, which is not a number a flag can mean")
{
    double d = 0;
    CHECK_FALSE(parse_double("nan", d));
    CHECK_FALSE(parse_double("NaN", d));
    CHECK_FALSE(parse_double("-nan", d));
    CHECK_FALSE(parse_double("NAN", d));

    // An infinity is left alone on purpose: for a rate it is a thing to mean,
    // and unlike NaN it compares the way a reader expects.
    CHECK(parse_double("inf", d));   CHECK(std::isinf(d)); CHECK(d > 0);
    CHECK(parse_double("-inf", d));  CHECK(std::isinf(d)); CHECK(d < 0);
    CHECK(parse_double("0", d));     CHECK(d == doctest::Approx(0.0));
}

TEST_CASE("parse_size_suffix: the suffixes it documents")
{
    size_t n = 0;
    CHECK(parse_size_suffix("0", n));     CHECK(n == 0u);
    CHECK(parse_size_suffix("100", n));   CHECK(n == 100u);
    CHECK(parse_size_suffix("1K", n));    CHECK(n == 1024u);
    CHECK(parse_size_suffix("1k", n));    CHECK(n == 1024u);
    CHECK(parse_size_suffix("100M", n));  CHECK(n == 104857600u);
    CHECK(parse_size_suffix("100m", n));  CHECK(n == 104857600u);
    CHECK(parse_size_suffix("1G", n));    CHECK(n == 1073741824u);
    CHECK(parse_size_suffix("1g", n));    CHECK(n == 1073741824u);
}

TEST_CASE("parse_size_suffix: a suffix it does not know is refused, not ignored")
{
    size_t n = 12345;   // poisoned, so an accepted-but-unwritten case is visible

    // The typo this is really about.  It used to answer 100.
    CHECK_FALSE(parse_size_suffix("100MB", n));
    CHECK_FALSE(parse_size_suffix("100KB", n));
    CHECK_FALSE(parse_size_suffix("100GB", n));
    CHECK_FALSE(parse_size_suffix("100X", n));
    CHECK_FALSE(parse_size_suffix("100 M", n));
    CHECK_FALSE(parse_size_suffix("M100", n));
    CHECK_FALSE(parse_size_suffix("", n));
    CHECK_FALSE(parse_size_suffix("M", n));
    CHECK_FALSE(parse_size_suffix("-1M", n));

    CHECK(n == 12345u);   // nothing above wrote to it
}

TEST_CASE("parse_size_suffix: a size that would wrap is refused, not wrapped")
{
    size_t n = 0;

    // 2^34 G is exactly 2^64.  This answered 0 — and 0 is documented as
    // "unlimited", so the largest request became no limit at all.
    CHECK_FALSE(parse_size_suffix("17179869184G", n));
    CHECK_FALSE(parse_size_suffix("17179869185G", n));
    CHECK_FALSE(parse_size_suffix("99999999999999999999G", n));

    // And the boundary still works: one below the wrap is a legal size.
    CHECK(parse_size_suffix("17179869183G", n));
    CHECK(n == 17179869183ull * 1024ull * 1024ull * 1024ull);
}

// ─── parse_duration_seconds ─────────────────────────────────────────────────
//
// One grammar for every flag that takes a duration.  Before this parser,
// three of the four duration flags never checked from_chars's end pointer, so
// `--health-interval 5x` configured five seconds without a word about the x.

#include "../../socketley/shared/util/duration_parse.h"

static constexpr uint64_t dur_max = std::numeric_limits<int>::max();

TEST_CASE("parse_duration_seconds: a bare number stays seconds")
{
    uint64_t s = 0;

    CHECK(parse_duration_seconds("0", dur_max, s) == duration_parse::ok);
    CHECK(s == 0u);
    CHECK(parse_duration_seconds("300", dur_max, s) == duration_parse::ok);
    CHECK(s == 300u);
    CHECK(parse_duration_seconds("007", dur_max, s) == duration_parse::ok);
    CHECK(s == 7u);

    // The compatibility line: the uint32 ceiling --idle-timeout always had.
    CHECK(parse_duration_seconds("4294967295",
                                 std::numeric_limits<uint32_t>::max(), s)
          == duration_parse::ok);
    CHECK(s == 4294967295u);
}

TEST_CASE("parse_duration_seconds: the five suffixes it documents")
{
    uint64_t s = 0;

    CHECK(parse_duration_seconds("5s", dur_max, s) == duration_parse::ok);
    CHECK(s == 5u);
    CHECK(parse_duration_seconds("5m", dur_max, s) == duration_parse::ok);
    CHECK(s == 300u);
    CHECK(parse_duration_seconds("5h", dur_max, s) == duration_parse::ok);
    CHECK(s == 18000u);
    CHECK(parse_duration_seconds("5d", dur_max, s) == duration_parse::ok);
    CHECK(s == 432000u);
    CHECK(parse_duration_seconds("5w", dur_max, s) == duration_parse::ok);
    CHECK(s == 3024000u);
    CHECK(parse_duration_seconds("0s", dur_max, s) == duration_parse::ok);
    CHECK(s == 0u);
}

TEST_CASE("parse_duration_seconds: malformed is refused, and refused whole")
{
    uint64_t s = 12345;   // poisoned, so an accepted-but-unwritten case shows

    CHECK(parse_duration_seconds("5x", dur_max, s)   == duration_parse::malformed);
    CHECK(parse_duration_seconds("m", dur_max, s)    == duration_parse::malformed);
    CHECK(parse_duration_seconds("-5s", dur_max, s)  == duration_parse::malformed);
    CHECK(parse_duration_seconds("+5s", dur_max, s)  == duration_parse::malformed);
    CHECK(parse_duration_seconds("5 s", dur_max, s)  == duration_parse::malformed);
    CHECK(parse_duration_seconds(" 5s", dur_max, s)  == duration_parse::malformed);
    CHECK(parse_duration_seconds("5s ", dur_max, s)  == duration_parse::malformed);
    CHECK(parse_duration_seconds("", dur_max, s)     == duration_parse::malformed);
    CHECK(parse_duration_seconds("s", dur_max, s)    == duration_parse::malformed);
    CHECK(parse_duration_seconds("5sm", dur_max, s)  == duration_parse::malformed);
    CHECK(parse_duration_seconds("5m5s", dur_max, s) == duration_parse::malformed);

    // Fractions are refused: 90m already spells 1.5h, and a rule that takes
    // 1.5h but must refuse 0.5s is two rules wearing one suffix.
    CHECK(parse_duration_seconds("1.5h", dur_max, s) == duration_parse::malformed);
    CHECK(parse_duration_seconds("5.", dur_max, s)   == duration_parse::malformed);
    CHECK(parse_duration_seconds(".5h", dur_max, s)  == duration_parse::malformed);

    // Uppercase is refused: 5M reads as months everywhere else, and a guess
    // wrong by a factor of 43200 is worse than a refusal.
    CHECK(parse_duration_seconds("5S", dur_max, s)   == duration_parse::malformed);
    CHECK(parse_duration_seconds("5M", dur_max, s)   == duration_parse::malformed);
    CHECK(parse_duration_seconds("5H", dur_max, s)   == duration_parse::malformed);
    CHECK(parse_duration_seconds("5D", dur_max, s)   == duration_parse::malformed);
    CHECK(parse_duration_seconds("5W", dur_max, s)   == duration_parse::malformed);

    CHECK(s == 12345u);   // nothing above wrote to it
}

TEST_CASE("parse_duration_seconds: a duration past the cap is refused, not wrapped")
{
    uint64_t s = 12345;

    // The multiplied form: 99999999999w is ~6e16 seconds, comfortably inside
    // uint64 but far past any caller's cap, so the cap is what refuses it.
    CHECK(parse_duration_seconds("99999999999w", dur_max, s)
          == duration_parse::out_of_range);

    // The digits themselves overflow uint64 before any unit is applied.
    CHECK(parse_duration_seconds("18446744073709551616", dur_max, s)
          == duration_parse::out_of_range);
    CHECK(parse_duration_seconds("18446744073709551616s", dur_max, s)
          == duration_parse::out_of_range);

    // A count whose product with the unit would wrap uint64: refused by the
    // divided comparison, which cannot itself wrap.
    CHECK(parse_duration_seconds("30516044060218w",
                                 std::numeric_limits<uint64_t>::max(), s)
          == duration_parse::out_of_range);

    // One second over the int cap the proxy flags store into.
    CHECK(parse_duration_seconds("2147483648", dur_max, s)
          == duration_parse::out_of_range);
    CHECK(s == 12345u);

    // And the boundary itself is a legal duration.
    CHECK(parse_duration_seconds("2147483647", dur_max, s)
          == duration_parse::ok);
    CHECK(s == 2147483647u);
    CHECK(parse_duration_seconds("3550w", dur_max, s) == duration_parse::ok);
    CHECK(s == 3550u * 604800u);
}
