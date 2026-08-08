#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
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
