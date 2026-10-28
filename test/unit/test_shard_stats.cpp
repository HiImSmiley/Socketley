#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "../../socketley/shared/ipc/shard_stats.h"

#include <algorithm>
#include <chrono>
#include <functional>
#include <fcntl.h>
#include <new>
#include <sys/mman.h>
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

TEST_CASE("all five counters cross the boundary, not only the connection count")
{
    // The four lifetime counters moved into this region when the worker's 250 ms
    // stats frame was removed, and the failure they invite is silent: a build
    // that publishes active_connections and leaves the rest at zero reports a
    // proxy that has served nothing while showing its clients connected.  So
    // each field is given a value that could not be confused with another's.
    shard_stats::shard_table region;
    REQUIRE(region.create(3));

    for (uint32_t i = 0; i < 3; ++i)
    {
        const int rc = in_child([&] {
            shard_stats::shard_table w;
            if (!w.adopt(::dup(region.fd()), i))
                return 1;
            shard_stats::figures f;
            f.active_connections = i + 1;                //   1,   2,   3
            f.total_connections  = (i + 1) * 10;         //  10,  20,  30
            f.total_messages     = (i + 1) * 100;        // 100, 200, 300
            f.bytes_in           = (i + 1) * 1000;
            f.bytes_out          = (i + 1) * 10000;
            w.publish(f);
            return 0;
        });
        CHECK(rc == 0);
    }

    const shard_stats::figures sum = region.sum();
    CHECK(sum.active_connections == 6);
    CHECK(sum.total_connections  == 60);
    CHECK(sum.total_messages     == 600);
    CHECK(sum.bytes_in           == 6000);
    CHECK(sum.bytes_out          == 60000);

    // And one shard on its own, which is what `stats` prints under [shard i].
    const shard_stats::figures one = region.at(1);
    CHECK(one.active_connections == 2);
    CHECK(one.total_messages     == 200);
    CHECK(one.bytes_out          == 20000);

    // A slot past the declared count is not a read of somebody else's line.
    CHECK(region.at(3) == shard_stats::figures{});
}

TEST_CASE("the daemon reads a region it made without taking a slot in it")
{
    // The placeholder instance for a worker-backed runtime answers `stats`,
    // `ls`, the metrics thread and every Lua binding, and it must read the same
    // region the shards write — without becoming one of them.  adopt() would
    // make it one: it claims a slot and bumps that slot's generation, which is a
    // shard saying it is here.
    shard_stats::shard_table region;
    REQUIRE(region.create(2));

    CHECK_FALSE(region.any_live());          // nothing has attached yet

    REQUIRE(in_child([&] {
        shard_stats::shard_table w;
        if (!w.adopt(::dup(region.fd()), 0))
            return 1;
        shard_stats::figures f;
        f.active_connections = 7;
        f.bytes_in           = 4096;
        w.publish(f);
        return 0;
    }) == 0);

    shard_stats::shard_table reader;
    REQUIRE(reader.attach_reader(region.fd()));
    CHECK(reader.mapped());
    CHECK_FALSE(reader.writable());          // no slot: it can never publish
    CHECK(reader.count() == 2);
    CHECK(reader.sum().active_connections == 7);
    CHECK(reader.sum().bytes_in == 4096);
    CHECK(reader.any_live());

    // A reader that could write would cancel out the shard whose slot it landed
    // on, once per health tick, and the figure would read low with nothing to
    // say why.  Both publishing calls have to be no-ops.
    reader.publish_active(999);
    reader.publish(shard_stats::figures{999, 999, 999, 999, 999});
    CHECK(reader.sum().active_connections == 7);

    // The descriptor was DUPLICATED.  Closing the reader must not take the
    // region's own fd with it, or the next shard forked is handed a number this
    // object has already closed.
    reader.close();
    CHECK(region.at(0).active_connections == 7);
    CHECK(::fcntl(region.fd(), F_GETFD, 0) >= 0);
}

TEST_CASE("a retired or replaced shard leaves none of its five behind")
{
    // clear_slot() and adopt() both zero a slot, and both were written when a
    // slot held one number.  A build that clears active_connections and leaves
    // the other four is the shape of the bug: connections falls to zero on a
    // restart, as it should, while bytes_out keeps a dead process's total for
    // ever and the runtime's lifetime counters only ever grow.
    shard_stats::shard_table region;
    REQUIRE(region.create(2));

    REQUIRE(in_child([&] {
        shard_stats::shard_table w;
        if (!w.adopt(::dup(region.fd()), 1))
            return 1;
        w.publish(shard_stats::figures{5, 50, 500, 5000, 50000});
        return 0;
    }) == 0);
    REQUIRE(region.sum().bytes_out == 50000);

    region.clear_slot(1);
    CHECK(region.sum() == shard_stats::figures{});

    // And the same for a replacement, which clears the slot it takes rather
    // than being cleared by the daemon.
    REQUIRE(in_child([&] {
        shard_stats::shard_table w;
        if (!w.adopt(::dup(region.fd()), 1))
            return 1;
        w.publish(shard_stats::figures{5, 50, 500, 5000, 50000});
        return 0;
    }) == 0);
    REQUIRE(region.sum().bytes_out == 50000);
    REQUIRE(in_child([&] {
        shard_stats::shard_table w;
        // Adopting the same slot is the restart: whatever the last occupant
        // said is not about this process.
        if (!w.adopt(::dup(region.fd()), 1))
            return 1;
        return w.sum() == shard_stats::figures{} ? 0 : 2;
    }) == 0);
    CHECK(region.sum() == shard_stats::figures{});
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
        sink = sink + region.sum_active();
    const auto t1 = std::chrono::steady_clock::now();
    (void)sink;

    const double ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count()
        / static_cast<double>(reps);
    MESSAGE("sum over 8 shards: " << ns << " ns per call");
    CHECK(region.sum_active() == 40);
}

// ─── The second region: which connections each shard holds, by name ─────────
//
// shard_clients.h, and every case that claims sharing forks for the reason the
// cases above do: a single-process test of this passes on a heap allocation.

#include "../../socketley/shared/ipc/shard_clients.h"

namespace
{
conn_ref mk(uint64_t owner, uint64_t serial) { return conn_ref{owner, serial}; }
}

TEST_CASE("four shards publish their clients and any one can read the rest")
{
    shard_clients::client_table region;
    REQUIRE(region.create(4));
    CHECK(region.count() == 4);

    for (uint32_t i = 0; i < 4; ++i)
        CHECK(in_child([&] {
            shard_clients::client_table w;
            if (!w.adopt(::dup(region.fd()), i, 4)) return 1;
            // Two clients each, named so the reader can tell whose is whose.
            w.push(mk(99, (i + 1) * 100 + 1));
            w.push(mk(99, (i + 1) * 100 + 2));
            return w.own_count() == 2 ? 0 : 2;
        }) == 0);

    // Everything, including this reader's own block: invalid_index skips
    // nothing, which is what the daemon and these tests want.
    std::vector<conn_ref> all;
    CHECK(region.read_others(all, shard_clients::client_table::invalid_index));
    CHECK(all.size() == 8);

    // And a reader that IS one of the shards leaves its own out, because the
    // caller already has those as descriptors.
    CHECK(in_child([&] {
        shard_clients::client_table r;
        if (!r.adopt(::dup(region.fd()), 1, 4)) return 1;
        // adopt() clears the block it takes, so shard 1's two are gone from
        // the region as well as skipped — 6 remain.
        std::vector<conn_ref> out;
        if (!r.read_others(out, r.index())) return 2;
        return out.size() == 6 ? 0 : 3;
    }) == 0);
}

TEST_CASE("a swap-remove leaves the list exactly as the vector has it")
{
    shard_clients::client_table region;
    REQUIRE(region.create(1));

    CHECK(in_child([&] {
        shard_clients::client_table w;
        if (!w.adopt(::dup(region.fd()), 0, 1)) return 1;
        for (uint64_t i = 1; i <= 5; ++i) w.push(mk(7, i));
        // Remove the middle one, which is the case that moves another entry:
        // server_instance does exactly this to m_active_fds, and active_idx is
        // the index into both.
        w.swap_remove(1);
        return w.own_count() == 4 ? 0 : 2;
    }) == 0);

    std::vector<conn_ref> out;
    REQUIRE(region.read_others(out, shard_clients::client_table::invalid_index));
    REQUIRE(out.size() == 4);
    // 1, 5, 3, 4 — the last entry swapped into the hole, exactly as the vector
    // would have it.
    CHECK(out[0] == mk(7, 1));
    CHECK(out[1] == mk(7, 5));
    CHECK(out[2] == mk(7, 3));
    CHECK(out[3] == mk(7, 4));
}

TEST_CASE("a retired shard's clients stop being listed")
{
    shard_clients::client_table region;
    REQUIRE(region.create(2));
    for (uint32_t i = 0; i < 2; ++i)
        CHECK(in_child([&] {
            shard_clients::client_table w;
            if (!w.adopt(::dup(region.fd()), i, 2)) return 1;
            w.push(mk(7, i + 1));
            return 0;
        }) == 0);

    std::vector<conn_ref> out;
    REQUIRE(region.read_others(out, shard_clients::client_table::invalid_index));
    REQUIRE(out.size() == 2);

    // The shard is gone and publishes nothing on its way out — that is what
    // being killed means — so the daemon is the only one that can say so.
    region.clear_block(1);
    REQUIRE(region.read_others(out, shard_clients::client_table::invalid_index));
    CHECK(out.size() == 1);
    CHECK(out[0] == mk(7, 1));
}

TEST_CASE("a shard killed inside a write leaves a block the daemon can still clear")
{
    shard_clients::client_table region;
    REQUIRE(region.create(2));
    CHECK(in_child([&] {
        shard_clients::client_table w;
        if (!w.adopt(::dup(region.fd()), 1, 2)) return 1;
        w.push(mk(7, 1)); w.push(mk(7, 2));
        return 0;
    }) == 0);

    // What a SIGKILL between begin_write and end_write leaves: an odd version
    // no process will ever make even again.
    const size_t len = shard_clients::region_size(2);
    void* p = ::mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_SHARED, region.fd(), 0);
    REQUIRE(p != MAP_FAILED);
    auto* b = reinterpret_cast<shard_clients::block_header*>(
        static_cast<uint8_t*>(p) + sizeof(shard_clients::region_header) + shard_clients::block_size);
    b->version.fetch_add(1, std::memory_order_relaxed);

    std::vector<conn_ref> out;
    CHECK_FALSE(region.read_block(1, out));

    // The daemon clears it once the pid is reaped, and a clear that only added
    // one would leave it odd -- unreadable for as long as the runtime runs.
    region.clear_block(1);
    out.clear();
    CHECK(region.read_block(1, out));
    CHECK(out.empty());
    CHECK((b->version.load(std::memory_order_relaxed) & 1u) == 0);
    ::munmap(p, len);
}

TEST_CASE("a replacement shard does not inherit its predecessor's clients")
{
    shard_clients::client_table region;
    REQUIRE(region.create(1));
    CHECK(in_child([&] {
        shard_clients::client_table w;
        if (!w.adopt(::dup(region.fd()), 0, 1)) return 1;
        w.push(mk(7, 1)); w.push(mk(7, 2));
        return 0;
    }) == 0);

    std::vector<conn_ref> out;
    REQUIRE(region.read_others(out, shard_clients::client_table::invalid_index));
    REQUIRE(out.size() == 2);

    CHECK(in_child([&] {
        shard_clients::client_table w;
        if (!w.adopt(::dup(region.fd()), 0, 1)) return 1;
        return w.own_count() == 0 ? 0 : 2;
    }) == 0);
}

TEST_CASE("a reader never sees half of one shard's list")
{
    // The seqlock's whole job.  A list is a length and N entries that have to
    // agree, and a reader CAN catch a length that no longer matches the
    // entries — which a counter cannot, and which is why these are two regions.
    //
    // ─── THE FIRST VERSION OF THIS CASE ASSERTED THE WRONG THING ────────────
    //
    // It had the writer clear its block and rebuild it, alternating between a
    // three-entry set and a five-entry one, and asserted that every read showed
    // one set whole.  That failed 24,649 times out of 200,000 — and the code
    // was right, the assertion was wrong.  clear_own() and each push() are
    // separate critical sections, so a reader can see a consistent view of a
    // rebuild in progress: two of the five, correctly reported as two.
    //
    // The reason it was the wrong model is that PRODUCTION NEVER REBUILDS.
    // server_instance publishes one push per accept and one swap_remove per
    // close, mirroring what it already does to m_active_fds — that is the whole
    // point of the incremental writer — and the only clear_own() calls are at
    // setup and teardown, where the list is empty either way.
    //
    // So the writer below is shaped like the real one, and the invariant is the
    // one a real reader depends on: the list holds DISTINCT serials.  That is
    // exactly the tearing signature of swap_remove, which copies the last entry
    // over the hole and then shortens the count — a reader that saw the old
    // count over the new entries would see the tail twice.
    shard_clients::client_table region;
    REQUIRE(region.create(1));

    // The writer keeps writing until the reader has what it came for, or a loaded box lets the reader finish its
    // reads before the writer is first scheduled and every one of them finds the list empty.
    void* flag_mem = ::mmap(nullptr, sizeof(std::atomic<int>), PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    REQUIRE(flag_mem != MAP_FAILED);
    auto* done = new (flag_mem) std::atomic<int>(0);

    const pid_t writer = ::fork();
    REQUIRE(writer >= 0);
    if (writer == 0)
    {
        shard_clients::client_table w;
        if (!w.adopt(::dup(region.fd()), 0, 1)) _exit(1);
        uint64_t next = 1;
        const auto cap = std::chrono::steady_clock::now() + std::chrono::seconds(120);
        for (int round = 0; round < 200000 || done->load(std::memory_order_acquire) == 0; ++round)
        {
            if (w.own_count() < 8)
                w.push(mk(7, next++));
            else
                w.swap_remove(round % 8);      // middles as well as the end
            if ((round & 1023) == 0 && std::chrono::steady_clock::now() > cap)
                break;
        }
        _exit(0);
    }

    // The 300,000 reads are counted from the first that finds the writer's entries, so a writer the scheduler starts
    // late shortens nothing the case races against it, and a writer that never starts fails it at the deadline.
    int reads = 0, dup = 0, empty = 0, first = -1;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    for (int i = 0; first >= 0 ? i < first + 300000 : std::chrono::steady_clock::now() < deadline; ++i)
    {
        std::vector<conn_ref> out;
        if (!region.read_block(0, out))
            continue;                          // gave up within the bound
        ++reads;
        if (out.empty()) { ++empty; continue; }
        if (first < 0) first = i;
        std::vector<uint64_t> serials;
        serials.reserve(out.size());
        for (const auto& r : out) serials.push_back(r.serial);
        std::sort(serials.begin(), serials.end());
        if (std::adjacent_find(serials.begin(), serials.end()) != serials.end())
            ++dup;
    }
    done->store(1, std::memory_order_release);
    int st = 0; ::waitpid(writer, &st, 0);
    ::munmap(flag_mem, sizeof(std::atomic<int>));
    CHECK((WIFEXITED(st) && WEXITSTATUS(st) == 0));

    MESSAGE("seqlock: " << reads << " clean reads, " << empty << " empty, "
                        << dup << " with a duplicated entry");
    CHECK(dup == 0);
    CHECK(reads > 0);
    CHECK(reads - empty > 0);
}
