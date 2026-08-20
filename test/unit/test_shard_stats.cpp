#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "../../socketley/shared/shard_stats.h"

#include <chrono>
#include <functional>
#include <sys/wait.h>
#include <unistd.h>

// What is actually being tested here is that the memory is SHARED, and there is
// exactly one way to test that honestly: write it from a different process.
//
// A single-process test of this header passes on a plain heap allocation.  Two
// shard_table objects in one process mapping one memfd would also pass on a
// mapping that is MAP_PRIVATE, because a private mapping of the same file still
// starts out identical — the divergence only appears after a write, and only
// across the boundary a private mapping is meant to stop.  So every case below
// that claims sharing forks.
namespace
{

// Run `fn` in a child and wait for it.  Returns the child's exit status, so a
// CHECK inside the child is reported rather than lost: doctest's own failure
// counter lives in the child's address space and dies with it.
int in_child(const std::function<int()>& fn)
{
    const pid_t p = ::fork();
    REQUIRE(p >= 0);
    if (p == 0)
        _exit(fn());
    int st = 0;
    ::waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

}   // namespace

TEST_CASE("a region is created, mapped and described")
{
    shard_stats::shard_table t;
    REQUIRE(t.create(4));
    CHECK(t.mapped());
    CHECK(t.fd() >= 0);
    CHECK(t.count() == 4);

    // The daemon's own object is not a shard and must not publish.  If it could,
    // the obvious next mistake is the daemon writing a placeholder's zero into
    // slot 0 on every health tick and cancelling out the shard that lives there.
    CHECK_FALSE(t.writable());
    t.publish_active(99);
    CHECK(t.sum_active() == 0);
}

TEST_CASE("a region will not be created outside the bounds a build allows")
{
    shard_stats::shard_table t;
    CHECK_FALSE(t.create(0));
    CHECK_FALSE(t.create(max_shards + 1));
    CHECK_FALSE(t.mapped());
}

TEST_CASE("four processes publish and any one of them can add them up")
{
    shard_stats::shard_table region;
    REQUIRE(region.create(4));

    // Each child adopts its own slot and publishes a figure that identifies it,
    // so a build that let two shards share one line fails on the sum rather than
    // happening to agree.
    for (uint32_t i = 0; i < 4; ++i)
    {
        const int rc = in_child([&] {
            shard_stats::shard_table w;
            if (!w.adopt(::dup(region.fd()), i))
                return 1;
            if (!w.writable())
                return 2;
            w.publish_active((i + 1) * 10);        // 10, 20, 30, 40
            return 0;
        });
        CHECK(rc == 0);
    }

    // The children have EXITED.  Their figures are still readable, which is the
    // property the whole design rests on: a reader is never waiting on a writer,
    // so a shard that is descheduled, stopped or dead delays nothing.
    CHECK(region.sum_active() == 100);
    CHECK(region.active_at(0) == 10);
    CHECK(region.active_at(3) == 40);

    // And a fifth reader, in yet another process, sees the same sum — this is
    // what says the mapping is shared rather than merely inherited.
    CHECK(in_child([&] {
        shard_stats::shard_table r;
        if (!r.adopt(::dup(region.fd()), 0))
            return 1;
        // adopt() clears the slot it takes, so this reader's own slot is 0 and
        // the other three are untouched.
        return r.sum_active() == 90 ? 0 : 3;
    }) == 0);
}

TEST_CASE("a slot outside the declared shard count is refused")
{
    shard_stats::shard_table region;
    REQUIRE(region.create(2));

    CHECK(in_child([&] {
        shard_stats::shard_table w;
        // Slot 2 of a two-shard table.  Allowing it would be a write into a line
        // nobody is summing at best, and past the end of the mapping at worst.
        return w.adopt(::dup(region.fd()), 2) ? 1 : 0;
    }) == 0);
}

TEST_CASE("a descriptor that is not a region of this shape is refused")
{
    shard_stats::shard_table w;
    // A pipe: readable, mappable by nothing, and the wrong size.  The point is
    // that adopt() answers false rather than mapping something it cannot check.
    int p[2];
    REQUIRE(::pipe(p) == 0);
    CHECK_FALSE(w.adopt(p[0], 0));     // takes ownership of p[0] either way
    ::close(p[1]);
    CHECK_FALSE(w.mapped());
}

TEST_CASE("a retired shard stops being counted")
{
    shard_stats::shard_table region;
    REQUIRE(region.create(4));
    for (uint32_t i = 0; i < 4; ++i)
        CHECK(in_child([&] {
            shard_stats::shard_table w;
            if (!w.adopt(::dup(region.fd()), i)) return 1;
            w.publish_active(10);
            return 0;
        }) == 0);
    REQUIRE(region.sum_active() == 40);

    // The runtime is edited from four shards to two and restarted.  Without
    // this the two shards that remain would answer 40 for the 20 connections
    // they hold, and would go on doing so forever: the two that went away
    // publish nothing on their way out, by construction.
    region.set_shard_count(2);
    CHECK(region.count() == 2);
    CHECK(region.sum_active() == 20);

    // One shard dies on its own account and the daemon clears its line.
    region.clear_slot(1);
    CHECK(region.sum_active() == 10);
}

TEST_CASE("a replacement shard does not inherit its predecessor's figure")
{
    shard_stats::shard_table region;
    REQUIRE(region.create(2));

    CHECK(in_child([&] {
        shard_stats::shard_table w;
        if (!w.adopt(::dup(region.fd()), 0)) return 1;
        w.publish_active(17);
        return 0;
    }) == 0);
    REQUIRE(region.active_at(0) == 17);

    // The shard died holding 17 connections; its replacement holds none yet.
    // Reporting 17 until the replacement's first turn is the restart equivalent
    // of the stale-slot problem above, and it is adopt()'s job rather than the
    // daemon's because only the new process knows when it has arrived.
    CHECK(in_child([&] {
        shard_stats::shard_table w;
        if (!w.adopt(::dup(region.fd()), 0)) return 1;
        return w.sum_active() == 0 ? 0 : 2;
    }) == 0);
}

// ─── What it costs, next to the alternative ─────────────────────────────────
//
// Reported, never asserted.  A timing assertion on a shared box is a test that
// fails for reasons that have nothing to do with the code, and this number is
// here to be read in the log beside the round trip it replaces — measured on
// this tree 2026-08-20 at 5.68 us pinned / 10.28 us unpinned for one AF_UNIX
// exchange, which is what asking the other shards would have cost.
TEST_CASE("what a sum over eight shards costs")
{
    shard_stats::shard_table region;
    REQUIRE(region.create(8));
    for (uint32_t i = 0; i < 8; ++i)
        REQUIRE(in_child([&] {
            shard_stats::shard_table w;
            if (!w.adopt(::dup(region.fd()), i)) return 1;
            w.publish_active(5);
            return 0;
        }) == 0);
    REQUIRE(region.sum_active() == 40);

    constexpr int reps = 200000;
    volatile uint64_t sink = 0;
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < reps; ++i)
        sink += region.sum_active();
    const auto t1 = std::chrono::steady_clock::now();
    (void)sink;

    const double ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count()
        / static_cast<double>(reps);
    MESSAGE("sum over 8 shards: " << ns << " ns per call");
    CHECK(region.sum_active() == 40);
}
