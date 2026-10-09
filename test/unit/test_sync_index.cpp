// The record a sync keeps of what it last carried: what survives a crash, what a truncated tail costs, and that a
// rewritten index says exactly what the appended one did.
//
// Every assertion here is about a failure that would otherwise be silent. An index that forgot a carried file would
// carry it again -- wasteful but safe. An index that remembered a file it never carried would believe the far side
// holds it, and `--mode out` would never send it at all; an index whose tail is rubbish after a crash would refuse
// to open and the job would start from nothing, carrying a whole directory a second time.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <cstdio>
#include <fcntl.h>
#include <string>
#include <unistd.h>

#include "runtime/sync/sync_index.h"

using namespace socketley::sync;

namespace
{

std::string temp_path()
{
    static int n = 0;
    return "/tmp/skl-sync-index-" + std::to_string(::getpid()) + "-" + std::to_string(++n) + ".idx";
}

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
    const std::string p = temp_path();
    std::string why;
    {
        sync_index ix;
        REQUIRE(ix.open(p, why));
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
    REQUIRE(ix.open(p, why));
    CHECK(ix.size() == 1);
    CHECK(ix.find("ui/photos", "a.jpg") == nullptr);
    REQUIRE(ix.find("ui/photos", "b/c.txt") != nullptr);
    CHECK(ix.find("ui/photos", "b/c.txt")->etag == "etag-b");
    ::unlink(p.c_str());
}

TEST_CASE("one path carried to two targets is two records")
{
    const std::string p = temp_path();
    std::string why;
    sync_index ix;
    REQUIRE(ix.open(p, why));
    REQUIRE(ix.carried("ui/photos", "a.jpg", made(10, 1000, "one"), why));
    REQUIRE(ix.carried("ui2/photos", "a.jpg", made(10, 1000, "two"), why));
    CHECK(ix.size() == 2);
    // A target that has it still has it after the other forgets it, or a failure at one would stop the other.
    REQUIRE(ix.gone("ui/photos", "a.jpg", why));
    CHECK(ix.find("ui/photos", "a.jpg") == nullptr);
    REQUIRE(ix.find("ui2/photos", "a.jpg") != nullptr);
    CHECK(ix.find("ui2/photos", "a.jpg")->etag == "two");
    ::unlink(p.c_str());
}

TEST_CASE("a record cut short by a crash costs that record and no other")
{
    const std::string p = temp_path();
    std::string why;
    {
        sync_index ix;
        REQUIRE(ix.open(p, why));
        REQUIRE(ix.carried("t", "first", made(1, 1, "a"), why));
        REQUIRE(ix.carried("t", "second", made(2, 2, "bb"), why));
    }
    // The last record loses its tail, as a write interrupted partway leaves it.
    truncate_by(p, 3);
    sync_index ix;
    REQUIRE(ix.open(p, why));
    CHECK(why.empty());
    CHECK(ix.size() == 1);
    REQUIRE(ix.find("t", "first") != nullptr);
    CHECK(ix.find("t", "first")->etag == "a");
    CHECK(ix.find("t", "second") == nullptr);
    // And the next append lands behind what was kept, not behind the rubbish.
    REQUIRE(ix.carried("t", "third", made(3, 3, "ccc"), why));
    sync_index again;
    REQUIRE(again.open(p, why));
    CHECK(again.size() == 2);
    CHECK(again.find("t", "third") != nullptr);
    ::unlink(p.c_str());
}

TEST_CASE("a file that is not an index is refused rather than read as one")
{
    const std::string p = temp_path();
    const int fd = ::open(p.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    REQUIRE(fd >= 0);
    const std::string junk = "this is somebody else's file\n";
    REQUIRE(::write(fd, junk.data(), junk.size()) == static_cast<ssize_t>(junk.size()));
    ::close(fd);
    sync_index ix;
    std::string why;
    CHECK_FALSE(ix.open(p, why));
    CHECK(why.find("not a sync index") != std::string::npos);
    ::unlink(p.c_str());
}

TEST_CASE("rewriting the index keeps every live record and drops the dead ones")
{
    const std::string p = temp_path();
    std::string why;
    sync_index ix;
    REQUIRE(ix.open(p, why));
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
    REQUIRE(again.open(p, why));
    CHECK(again.size() == live);
    for (int i = 0; i < 100; ++i)
    {
        const index_entry* e = again.find("t", "keep-" + std::to_string(i));
        REQUIRE(e != nullptr);
        CHECK(e->size == static_cast<uint64_t>(i));
        CHECK(again.find("t", "drop-" + std::to_string(i)) == nullptr);
    }
    ::unlink(p.c_str());
}

TEST_CASE("a path with a tab, a newline or a quote in it comes back as it went in")
{
    // The record is length-prefixed exactly so these need no escaping; a line-based file would have lost them.
    const std::string p = temp_path();
    std::string why;
    const std::string odd = "a\tb\nc\"d'e\\f g.txt";
    {
        sync_index ix;
        REQUIRE(ix.open(p, why));
        REQUIRE(ix.carried("t", odd, made(7, 7, "e"), why));
    }
    sync_index ix;
    REQUIRE(ix.open(p, why));
    CHECK(ix.size() == 1);
    REQUIRE(ix.find("t", odd) != nullptr);
    CHECK(ix.find("t", odd)->size == 7);
    ::unlink(p.c_str());
}
