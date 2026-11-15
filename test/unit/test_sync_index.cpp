// The record a sync keeps of what it last carried: what survives a crash, what a truncated tail or a damaged record
// costs, that a rewritten index says exactly what the appended one did, and that one kept for another directory or
// prefix is not read as this job's.
//
// Every assertion here is about a failure that would otherwise be silent. An index that forgot a carried file would
// carry it again -- wasteful but safe. An index that remembered a file it never carried would believe the far side
// holds it, and `--mode out` would never send it at all; an index whose tail is rubbish after a crash would refuse
// to open and the job would start from nothing, carrying a whole directory a second time. And an index read from
// rubbish -- a damaged middle, another job's records -- would remember files never carried to these keys, which is
// the one failure that sends nothing at all.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <cstdio>
#include <fcntl.h>
#include <filesystem>
#include <memory>
#include <string>
#include <unistd.h>
#include <vector>

#include "runtime/sync/sync_index.h"
#include "shared/loop/event_loop.h"
#include "shared/loop/file_io.h"

using namespace socketley::sync;

namespace
{

std::string temp_path()
{
    static int n = 0;
    return "/tmp/skl-sync-index-" + std::to_string(::getpid()) + "-" + std::to_string(++n) + ".idx";
}

// Removes its file on every exit path, a failed REQUIRE included.
struct tmp_file
{
    std::string path;
    explicit tmp_file(std::string p) : path(std::move(p)) {}
    ~tmp_file() { ::unlink(path.c_str()); }
};

index_entry made(uint64_t size, int64_t mtime, std::string etag)
{
    index_entry e;
    e.size = size;
    e.mtime_ns = mtime;
    e.etag = std::move(etag);
    return e;
}

size_t file_size(const std::string& p)
{
    const int fd = ::open(p.c_str(), O_RDONLY);
    if (fd < 0)
        return 0;
    const off_t n = ::lseek(fd, 0, SEEK_END);
    ::close(fd);
    return n < 0 ? 0 : static_cast<size_t>(n);
}

// Cuts `bytes` off the end, as a crash in the middle of a write leaves.
void truncate_by(const std::string& p, size_t bytes)
{
    const size_t n = file_size(p);
    REQUIRE(n > bytes);
    REQUIRE(::truncate(p.c_str(), static_cast<off_t>(n - bytes)) == 0);
}

}   // namespace

TEST_CASE("a file carried is remembered, and one gone is forgotten")
{
    const tmp_file tf(temp_path());
    const std::string& p = tf.path;
    std::string why;
    {
        sync_index ix;
        REQUIRE(ix.open(p, "/srv\nlaptop", why));
        CHECK(why.empty());
        CHECK(ix.size() == 0);
        CHECK(ix.find("ui/photos", "a.jpg") == nullptr);

        REQUIRE(ix.carried("ui/photos", "a.jpg", made(10, 1000, "etag-a"), why));
        REQUIRE(ix.carried("ui/photos", "b/c.txt", made(20, 2000, "etag-b"), why));
        const index_entry* e = ix.find("ui/photos", "a.jpg");
        REQUIRE(e != nullptr);
        CHECK(e->size == 10);
        CHECK(e->mtime_ns == 1000);
        CHECK(e->etag == "etag-a");
        CHECK(ix.size() == 2);

        REQUIRE(ix.gone("ui/photos", "a.jpg", why));
        CHECK(ix.find("ui/photos", "a.jpg") == nullptr);
        CHECK(ix.size() == 1);
    }
    // Opened again, it says the same: the record is on the disk and not only in the map.
    sync_index ix;
    REQUIRE(ix.open(p, "/srv\nlaptop", why));
    CHECK(ix.size() == 1);
    CHECK(ix.find("ui/photos", "a.jpg") == nullptr);
    REQUIRE(ix.find("ui/photos", "b/c.txt") != nullptr);
    CHECK(ix.find("ui/photos", "b/c.txt")->etag == "etag-b");
}

TEST_CASE("one path carried to two targets is two records")
{
    const tmp_file tf(temp_path());
    const std::string& p = tf.path;
    std::string why;
    sync_index ix;
    REQUIRE(ix.open(p, "/srv\nlaptop", why));
    REQUIRE(ix.carried("ui/photos", "a.jpg", made(10, 1000, "one"), why));
    REQUIRE(ix.carried("ui2/photos", "a.jpg", made(10, 1000, "two"), why));
    CHECK(ix.size() == 2);
    // A target that has it still has it after the other forgets it, or a failure at one would stop the other.
    REQUIRE(ix.gone("ui/photos", "a.jpg", why));
    CHECK(ix.find("ui/photos", "a.jpg") == nullptr);
    REQUIRE(ix.find("ui2/photos", "a.jpg") != nullptr);
    CHECK(ix.find("ui2/photos", "a.jpg")->etag == "two");
}

TEST_CASE("a record cut short by a crash costs that record and no other")
{
    const tmp_file tf(temp_path());
    const std::string& p = tf.path;
    std::string why;
    {
        sync_index ix;
        REQUIRE(ix.open(p, "/srv\nlaptop", why));
        REQUIRE(ix.carried("t", "first", made(1, 1, "a"), why));
        REQUIRE(ix.carried("t", "second", made(2, 2, "bb"), why));
    }
    // The last record loses its tail, as a write interrupted partway leaves it.
    truncate_by(p, 3);
    sync_index ix;
    REQUIRE(ix.open(p, "/srv\nlaptop", why));
    CHECK(why.empty());
    CHECK(ix.size() == 1);
    REQUIRE(ix.find("t", "first") != nullptr);
    CHECK(ix.find("t", "first")->etag == "a");
    CHECK(ix.find("t", "second") == nullptr);
    // And the next append lands behind what was kept, not behind the rubbish.
    REQUIRE(ix.carried("t", "third", made(3, 3, "ccc"), why));
    sync_index again;
    REQUIRE(again.open(p, "/srv\nlaptop", why));
    CHECK(again.size() == 2);
    CHECK(again.find("t", "third") != nullptr);
}

TEST_CASE("a file that is not an index is refused rather than read as one")
{
    const tmp_file tf(temp_path());
    const std::string& p = tf.path;
    const int fd = ::open(p.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    REQUIRE(fd >= 0);
    const std::string junk = "this is somebody else's file\n";
    REQUIRE(::write(fd, junk.data(), junk.size()) == static_cast<ssize_t>(junk.size()));
    ::close(fd);
    sync_index ix;
    std::string why;
    CHECK_FALSE(ix.open(p, "/srv\nlaptop", why));
    CHECK(why.find("not a sync index") != std::string::npos);
}

TEST_CASE("rewriting the index keeps every live record and drops the dead ones")
{
    const tmp_file tf(temp_path());
    const std::string& p = tf.path;
    std::string why;
    sync_index ix;
    REQUIRE(ix.open(p, "/srv\nlaptop", why));
    // Enough records, carried and gone again, that the file is worth rewriting.
    for (int i = 0; i < 100; ++i)
        REQUIRE(ix.carried("t", "keep-" + std::to_string(i), made(uint64_t(i), i, "e"), why));
    for (int i = 0; i < 100; ++i)
    {
        REQUIRE(ix.carried("t", "drop-" + std::to_string(i), made(1, 1, "e"), why));
        REQUIRE(ix.gone("t", "drop-" + std::to_string(i), why));
    }
    const size_t live = ix.size(), before = file_size(p);
    REQUIRE(live == 100);
    REQUIRE(ix.compact(why));
    CHECK(file_size(p) < before);

    sync_index again;
    REQUIRE(again.open(p, "/srv\nlaptop", why));
    CHECK(again.size() == live);
    for (int i = 0; i < 100; ++i)
    {
        const index_entry* e = again.find("t", "keep-" + std::to_string(i));
        REQUIRE(e != nullptr);
        CHECK(e->size == static_cast<uint64_t>(i));
        CHECK(again.find("t", "drop-" + std::to_string(i)) == nullptr);
    }
}

TEST_CASE("a path with a tab, a newline or a quote in it comes back as it went in")
{
    // The record is length-prefixed exactly so these need no escaping; a line-based file would have lost them.
    const tmp_file tf(temp_path());
    const std::string& p = tf.path;
    std::string why;
    const std::string odd = "a\tb\nc\"d'e\\f g.txt";
    {
        sync_index ix;
        REQUIRE(ix.open(p, "/srv\nlaptop", why));
        REQUIRE(ix.carried("t", odd, made(7, 7, "e"), why));
    }
    sync_index ix;
    REQUIRE(ix.open(p, "/srv\nlaptop", why));
    CHECK(ix.size() == 1);
    REQUIRE(ix.find("t", odd) != nullptr);
    CHECK(ix.find("t", odd)->size == 7);
}

// Flips one byte at `off`, as a disk that wrote one page and not the one before it leaves the file.
static void flip_at(const std::string& p, size_t off)
{
    const int fd = ::open(p.c_str(), O_RDWR);
    REQUIRE(fd >= 0);
    char c = 0;
    REQUIRE(::pread(fd, &c, 1, static_cast<off_t>(off)) == 1);
    c = static_cast<char>(c ^ 0x5a);
    REQUIRE(::pwrite(fd, &c, 1, static_cast<off_t>(off)) == 1);
    ::close(fd);
}

TEST_CASE("a damaged record ends the file there, and nothing after it is believed")
{
    const tmp_file tf(temp_path());
    const std::string& p = tf.path;
    std::string why;
    size_t after_first = 0;
    {
        sync_index ix;
        REQUIRE(ix.open(p, "/srv\nlaptop", why));
        REQUIRE(ix.carried("t", "first", made(1, 1, "a"), why));
        after_first = file_size(p);
        REQUIRE(ix.carried("t", "second", made(2, 2, "b"), why));
        REQUIRE(ix.carried("t", "third", made(3, 3, "c"), why));
    }
    // A byte inside the second record's path: its length still reads, its checksum no longer agrees.
    flip_at(p, after_first + 8 + 1 + 2 + 1 + 2 + 2);
    sync_index ix;
    REQUIRE(ix.open(p, "/srv\nlaptop", why));
    CHECK(ix.size() == 1);
    CHECK(ix.find("t", "first") != nullptr);
    CHECK(ix.find("t", "second") == nullptr);
    // The third was whole, and is still not believed: it came after a record nobody can vouch for.
    CHECK(ix.find("t", "third") == nullptr);
    CHECK(file_size(p) == after_first);
}

TEST_CASE("an index kept for another directory or prefix is begun again, and the same one is read")
{
    const tmp_file tf(temp_path());
    const std::string& p = tf.path;
    std::string why;
    {
        sync_index ix;
        REQUIRE(ix.open(p, "/srv\nlaptop", why));
        REQUIRE(ix.carried("t", "a.jpg", made(1, 1, "a"), why));
    }
    {
        sync_index ix;
        REQUIRE(ix.open(p, "/srv\nlaptop", why));
        CHECK(ix.size() == 1);
    }
    {
        // Another prefix: a.jpg is another key now, which the far side does not have.
        sync_index ix;
        REQUIRE(ix.open(p, "/srv\ndesktop", why));
        CHECK(ix.size() == 0);
        REQUIRE(ix.carried("t", "b.jpg", made(2, 2, "b"), why));
    }
    sync_index ix;
    REQUIRE(ix.open(p, "/srv\ndesktop", why));
    CHECK(ix.size() == 1);
    CHECK(ix.find("t", "b.jpg") != nullptr);
    CHECK(ix.find("t", "a.jpg") == nullptr);
    sync_index other;
    REQUIRE(other.open(p, "/elsewhere\ndesktop", why));
    CHECK(other.size() == 0);
}

TEST_CASE("an etag longer than a record holds is kept short, and the records after it still read")
{
    const tmp_file tf(temp_path());
    const std::string& p = tf.path;
    std::string why;
    {
        sync_index ix;
        REQUIRE(ix.open(p, "s", why));
        REQUIRE(ix.carried("t", "long", made(1, 1, std::string(400, 'x')), why));
        REQUIRE(ix.carried("t", "after", made(2, 2, "e"), why));
        CHECK(ix.find("t", "long")->etag.size() == 255);
    }
    sync_index ix;
    REQUIRE(ix.open(p, "s", why));
    CHECK(ix.size() == 2);
    REQUIRE(ix.find("t", "long") != nullptr);
    CHECK(ix.find("t", "long")->etag == std::string(255, 'x'));
    REQUIRE(ix.find("t", "after") != nullptr);
    CHECK(ix.find("t", "after")->size == 2);
}

TEST_CASE("a file holding part of the magic is the index a crash left before its first record")
{
    const tmp_file tf(temp_path());
    const std::string& p = tf.path;
    const int fd = ::open(p.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    REQUIRE(fd >= 0);
    REQUIRE(::write(fd, "SKLS", 4) == 4);
    ::close(fd);
    sync_index ix;
    std::string why;
    REQUIRE(ix.open(p, "s", why));
    CHECK(ix.size() == 0);
    REQUIRE(ix.carried("t", "a", made(1, 1, "e"), why));
    sync_index again;
    REQUIRE(again.open(p, "s", why));
    CHECK(again.size() == 1);
}

TEST_CASE("a target no longer named is forgotten, and stays forgotten")
{
    const tmp_file tf(temp_path());
    const std::string& p = tf.path;
    std::string why;
    {
        sync_index ix;
        REQUIRE(ix.open(p, "s", why));
        REQUIRE(ix.carried("ui/photos", "a", made(1, 1, "e"), why));
        REQUIRE(ix.carried("old/photos", "a", made(1, 1, "e"), why));
        ix.retain({"ui/photos"});
        CHECK(ix.size() == 1);
        CHECK(ix.find("old/photos", "a") == nullptr);
        REQUIRE(ix.compact(why));
    }
    sync_index ix;
    REQUIRE(ix.open(p, "s", why));
    CHECK(ix.size() == 1);
    CHECK(ix.find("ui/photos", "a") != nullptr);
    CHECK(ix.find("old/photos", "a") == nullptr);
}

// ─── THROUGH THE RING ───────────────────────────────────────────────────────
// A sync job's index syncs through its loop's file_io, so a disk that takes seconds over one fdatasync holds up no
// other job. What would go wrong: a record counted on the disk that a crash can still take back, a rewrite renamed
// over the index before what it holds is synced, records written while a rewrite is synced left out of it, and a
// waiter that is never answered, which wedges the listing that waits on it.

namespace
{

struct ring : io_handler
{
    event_loop loop{256};
    std::unique_ptr<socketley::file_io> io;

    ring()
    {
        REQUIRE(loop.init());
        io = std::make_unique<socketley::file_io>(loop, this);
    }

    void on_cqe(struct io_uring_cqe* cqe) override
    {
        auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
        if (req && socketley::file_io::owns_type(req->type))
            io->on_cqe(cqe);
    }

    // Turns the loop until `done` says so or the ring owes nothing, and says which.
    template <class F>
    bool until(F done)
    {
        for (int i = 0; i < 20000 && !done(); ++i)
            loop.poll_completions(1);
        return done();
    }
};

}   // namespace

TEST_CASE("through the ring, a record is counted on the disk only once its sync ends, and the waiter is answered then")
{
    const tmp_file tf(temp_path());
    std::string why;
    ring r;
    std::vector<std::string> failures;
    sync_index ix;
    ix.attach(*r.io, [&](const std::string& w) { failures.push_back(w); });
    REQUIRE(ix.open(tf.path, "/srv\nlaptop", why));
    // Nothing written: nothing to wait for.
    bool answered = false;
    ix.when_durable([&](bool ok) { answered = ok; });
    CHECK(answered);

    REQUIRE(ix.carried("t", "a", made(1, 1, "a"), why));
    CHECK_FALSE(ix.durable());
    answered = false;
    int calls = 0;
    ix.when_durable([&](bool ok) {
        answered = ok;
        ++calls;
    });
    // Not on the loop: the answer waits for the ring's completion.
    CHECK_FALSE(answered);
    // Written while that sync is in flight: a second waiter, answered by the sync after it.
    REQUIRE(ix.carried("t", "b", made(2, 2, "b"), why));
    bool second = false;
    ix.when_durable([&](bool ok) { second = ok; });
    REQUIRE(r.until([&] { return answered && second; }));
    CHECK(calls == 1);
    CHECK(ix.durable());
    CHECK(failures.empty());
    REQUIRE(r.until([&] { return r.io->inflight() == 0; }));

    sync_index again;
    REQUIRE(again.open(tf.path, "/srv\nlaptop", why));
    CHECK(again.size() == 2);
}

TEST_CASE("through the ring, records written while a rewrite is synced are carried into it, and none is lost")
{
    const tmp_file tf(temp_path());
    std::string why;
    ring r;
    std::vector<std::string> failures;
    int round = 0;
    {
        sync_index ix;
        ix.attach(*r.io, [&](const std::string& w) { failures.push_back(w); });
        REQUIRE(ix.open(tf.path, "/srv\nlaptop", why));
        for (int i = 0; i < 300; ++i)
            REQUIRE(ix.carried("t", "f" + std::to_string(i), made(i, i, "e" + std::to_string(i)), why));
        // Dead records, so the rewrite has something to drop.
        for (int i = 0; i < 100; ++i)
            REQUIRE(ix.gone("t", "f" + std::to_string(i), why));
        // A sync of the old file in flight as the rewrite begins, which the rename waits for.
        bool before = false;
        ix.when_durable([&](bool ok) { before = ok; });
        REQUIRE(ix.compact(why, true));
        REQUIRE(ix.rewriting());
        // Records go on being written while it is synced, and a waiter comes in between.
        bool waited = false;
        for (int spins = 0; spins < 20000 && ix.rewriting(); ++spins)
        {
            r.loop.poll_completions(1);
            if (round < 20)
            {
                REQUIRE(ix.carried("t", "n" + std::to_string(round), made(7, 7, "n"), why));
                REQUIRE(ix.gone("t", "f" + std::to_string(100 + round), why));
                ++round;
            }
            if (round == 3 && !waited)
            {
                waited = true;
                ix.when_durable([](bool) {});
            }
        }
        REQUIRE_FALSE(ix.rewriting());
        CHECK(before);
        CHECK(round > 0);
        bool after = false;
        ix.when_durable([&](bool ok) { after = ok; });
        REQUIRE(r.until([&] { return after; }));
        REQUIRE(r.until([&] { return r.io->inflight() == 0; }));
        CHECK(failures.empty());
        CHECK_FALSE(std::filesystem::exists(tf.path + ".new"));
        // The rewrite dropped the dead records: smaller than the same records appended, as a blocking index keeps them.
        const tmp_file twin_file(temp_path());
        {
            sync_index twin;
            REQUIRE(twin.open(twin_file.path, "/srv\nlaptop", why));
            for (int i = 0; i < 300; ++i)
                REQUIRE(twin.carried("t", "f" + std::to_string(i), made(i, i, "e" + std::to_string(i)), why));
            for (int i = 0; i < 100 + round; ++i)
                REQUIRE(twin.gone("t", "f" + std::to_string(i), why));
            for (int i = 0; i < round; ++i)
                REQUIRE(twin.carried("t", "n" + std::to_string(i), made(7, 7, "n"), why));
        }
        CHECK(file_size(tf.path) < file_size(twin_file.path));
    }
    sync_index again;
    REQUIRE(again.open(tf.path, "/srv\nlaptop", why));
    for (int i = 0; i < 300; ++i)
        CHECK_MESSAGE((again.find("t", "f" + std::to_string(i)) == nullptr) == (i < 100 + round), "f" << i);
    for (int i = 0; i < round; ++i)
        CHECK(again.find("t", "n" + std::to_string(i)) != nullptr);
    CHECK(again.size() == size_t(300 - 100));
}

TEST_CASE("through the ring, an index let go of with writes, a sync and a rewrite in flight is not touched by them")
{
    const tmp_file tf(temp_path());
    std::string why;
    ring r;
    {
        auto ix = std::make_unique<sync_index>();
        ix->attach(*r.io, [](const std::string&) {});
        REQUIRE(ix->open(tf.path, "/srv\nlaptop", why));
        for (int i = 0; i < 100; ++i)
            REQUIRE(ix->carried("t", "f" + std::to_string(i), made(i, i, "e"), why));
        bool answered = false;
        ix->when_durable([&](bool) { answered = true; });
        REQUIRE(ix->compact(why, true));
        REQUIRE(ix->rewriting());
        // Queued behind the write in flight, and written as the index goes.
        REQUIRE(ix->carried("t", "late", made(1, 1, "l"), why));
        ix.reset();
        CHECK_FALSE(answered);
    }
    // Their completions find nothing of the index; the descriptors they name stay open until they are done.
    REQUIRE(r.until([&] { return r.io->inflight() == 0; }));
    CHECK_FALSE(std::filesystem::exists(tf.path + ".new"));
    sync_index again;
    REQUIRE(again.open(tf.path, "/srv\nlaptop", why));
    CHECK(again.size() == 101);
    CHECK(again.find("t", "late") != nullptr);
}
