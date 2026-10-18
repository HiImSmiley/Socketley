// Whole files as every runtime writes and watches them: replaced whole at the durability a call names, made once by
// whichever of several writers comes first, and told changed by a stamp no two different files share.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include "shared/persist/file_stamp.h"
#include "shared/persist/replaced_file.h"

namespace
{

std::string fresh_dir()
{
    const std::string d = "/tmp/skl-persist-test-" + std::to_string(::getpid()) + "-" + std::to_string(rand());
    std::filesystem::create_directories(d);
    return d;
}

std::string read(const std::string& p)
{
    std::string out;
    REQUIRE(socketley::read_whole_file(p, out));
    return out;
}

}   // namespace

TEST_CASE("a file replaced whole holds the new bytes at the mode given, and nothing is left beside it")
{
    const std::string d = fresh_dir(), p = d + "/f";
    for (const auto sync : {socketley::durability::none, socketley::durability::data, socketley::durability::data_and_dir})
    {
        REQUIRE(socketley::replace_file(p, "one", sync));
        REQUIRE(socketley::replace_file(p, "two", sync, nullptr, 0640));
        CHECK(read(p) == "two");
        struct stat st{};
        REQUIRE(::stat(p.c_str(), &st) == 0);
        CHECK((st.st_mode & 0777) == 0640);
    }
    size_t files = 0;
    for (const auto& e : std::filesystem::directory_iterator(d))
        files += e.is_regular_file();
    CHECK(files == 1);
    std::filesystem::remove_all(d);
}

TEST_CASE("a replace that cannot be made says which step failed, and leaves the old file as it was")
{
    const std::string d = fresh_dir(), p = d + "/f";
    REQUIRE(socketley::replace_file(p, "kept", socketley::durability::data));
    std::string why;
    CHECK_FALSE(socketley::replace_file(d + "/no/such/dir/f", "x", socketley::durability::data, &why));
    CHECK(why.starts_with("open failed for "));
    CHECK(read(p) == "kept");
    std::filesystem::remove_all(d);
}

TEST_CASE("of writers racing to make one file, one wins whole and the others take it as made")
{
    const std::string d = fresh_dir(), p = d + "/once";
    std::atomic<int> made{0}, ok{0};
    std::vector<std::thread> ts;
    for (int i = 0; i < 8; ++i)
        ts.emplace_back([&, i] {
            bool mine = false;
            if (socketley::create_file_once(p, std::string(4096, static_cast<char>('a' + i)), nullptr, 0600, &mine))
                ++ok;
            if (mine)
                ++made;
        });
    for (auto& t : ts)
        t.join();
    CHECK(ok == 8);
    CHECK(made == 1);
    const std::string got = read(p);
    REQUIRE(got.size() == 4096);
    CHECK(got == std::string(4096, got[0]));
    std::filesystem::remove_all(d);
}

TEST_CASE("a stamp tells a missing file, a rewrite and a replacement of the same size apart")
{
    const std::string d = fresh_dir(), p = d + "/f";
    const socketley::file_stamp none = socketley::file_stamp::of(p);
    CHECK_FALSE(none.exists());
    CHECK(none == socketley::file_stamp{});
    REQUIRE(socketley::replace_file(p, "aaaa", socketley::durability::none));
    const socketley::file_stamp a = socketley::file_stamp::of(p);
    CHECK(a.exists());
    CHECK(a.size == 4);
    CHECK(a != none);
    // Same size, put in place by a rename: a new inode, whatever the clock says.
    REQUIRE(socketley::replace_file(p, "bbbb", socketley::durability::none));
    const socketley::file_stamp b = socketley::file_stamp::of(p);
    CHECK(b.size == a.size);
    CHECK(b.ino != a.ino);
    CHECK(b != a);
    CHECK(socketley::file_stamp::of(p) == b);
    std::filesystem::remove_all(d);
}

TEST_CASE("a file is read whole, a missing or a too large one refused unless allowed, and a link when asked")
{
    const std::string d = fresh_dir(), p = d + "/f";
    std::string out, why;
    CHECK_FALSE(socketley::read_file(d + "/none", out, {}, &why));
    CHECK(why.find("No such file") != std::string::npos);
    CHECK(socketley::read_file(d + "/none", out, {.missing_ok = true}));
    CHECK(out.empty());
    const std::string big(200000, 'x');
    REQUIRE(socketley::replace_file(p, big, socketley::durability::none));
    REQUIRE(socketley::read_file(p, out));
    CHECK(out == big);
    CHECK_FALSE(socketley::read_file(p, out, {.max_bytes = 100000}, &why));
    CHECK(out.empty());
    CHECK(socketley::read_file(p, out, {.max_bytes = 200000}));
    REQUIRE(::symlink(p.c_str(), (d + "/link").c_str()) == 0);
    CHECK(socketley::read_file(d + "/link", out));
    CHECK_FALSE(socketley::read_file(d + "/link", out, {.no_follow = true}));
    std::filesystem::remove_all(d);
}
