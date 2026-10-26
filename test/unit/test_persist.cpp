// Whole files as every runtime writes and watches them: replaced whole at the durability a call names, made once by
// whichever of several writers comes first, and told changed by a stamp no two different files share.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <filesystem>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "shared/persist/file_stamp.h"
#include "shared/persist/replaced_file.h"
#include "shared/persist/tar_archive.h"
#include "shared/util/deflate.h"
#include "shared/util/inflate.h"

namespace
{

std::string fresh_dir()
{
    const std::string d = "/tmp/skl-persist-test-" + std::to_string(::getpid()) + "-" + std::to_string(rand());
    std::filesystem::create_directories(d);
    return d;
}

struct dir_guard
{
    std::filesystem::path d;
    explicit dir_guard(const std::string& p) : d(p) {}
    ~dir_guard() { std::error_code ec; std::filesystem::remove_all(d, ec); }
};

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
    dir_guard guard(d);
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
}

TEST_CASE("a replace that cannot be made says which step failed, and leaves the old file as it was")
{
    const std::string d = fresh_dir(), p = d + "/f";
    dir_guard guard(d);
    REQUIRE(socketley::replace_file(p, "kept", socketley::durability::data));
    std::string why;
    CHECK_FALSE(socketley::replace_file(d + "/no/such/dir/f", "x", socketley::durability::data, &why));
    CHECK(why.starts_with("open failed for "));
    CHECK(read(p) == "kept");
}

TEST_CASE("of writers racing to make one file, one wins whole and the others take it as made")
{
    const std::string d = fresh_dir(), p = d + "/once";
    dir_guard guard(d);
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
}

TEST_CASE("a stamp tells a missing file, a rewrite and a replacement of the same size apart")
{
    const std::string d = fresh_dir(), p = d + "/f";
    dir_guard guard(d);
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
}

TEST_CASE("a file is read whole, a missing or a too large one refused unless allowed, and a link when asked")
{
    const std::string d = fresh_dir(), p = d + "/f";
    dir_guard guard(d);
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
}

namespace
{

std::string opened(const std::string& deflated)
{
    socketley::inflater in;
    in.feed(reinterpret_cast<const uint8_t*>(deflated.data()), deflated.size());
    in.end();
    std::string out;
    for (;;)
    {
        const auto r = in.run(out, 1u << 20);
        if (r == socketley::inflater::result::done)
            return out;
        if (r != socketley::inflater::result::output_full)
            return "(not opened)";
    }
}

}   // namespace

TEST_CASE("DEFLATE: best effort is no larger than fast, both open to what went in, and finish ends the stream")
{
    std::string text;
    std::mt19937 rng(7);
    static const char* words[] = {"mail ", "runtime ", "storage ", "socketley ", "the ", "a ", "journal ", "\n"};
    for (int i = 0; i < 200000; ++i)
        text += words[rng() % 8];
    std::string fast, best;
    socketley::deflater f(socketley::deflater::effort::fast), b(socketley::deflater::effort::best);
    for (size_t at = 0; at < text.size(); at += 100000)
    {
        f.compress(std::string_view(text).substr(at, 100000), fast);
        b.compress(std::string_view(text).substr(at, 100000), best);
    }
    f.finish(fast);
    b.finish(best);
    CHECK(opened(fast) == text);
    CHECK(opened(best) == text);
    CHECK(best.size() <= fast.size());
    CHECK(fast.size() < text.size() / 3);
}

TEST_CASE("DEFLATE: pieces compressed apart against the 32 KiB before each are the stream one deflater writes")
{
    std::string text;
    std::mt19937 rng(9);
    static const char* words[] = {"inbox ", "zone ", "bucket ", "socketley ", "of ", "an ", "segment ", "\n"};
    for (int i = 0; i < 150000; ++i)
        text += words[rng() % 8];
    // Bytes no code makes smaller, between the text, go out stored.
    std::string noise(200000, '\0');
    for (auto& c : noise)
        c = static_cast<char>(rng());
    text.insert(300000, noise);
    for (const auto e : {socketley::deflater::effort::fast, socketley::deflater::effort::best})
    {
        std::string whole, apart;
        socketley::deflater one(e), each(e);
        for (size_t at = 0; at < text.size(); at += 70000)
        {
            const std::string_view in = std::string_view(text).substr(at, 70000);
            one.compress(in, whole);
            each.prime(std::string_view(text).substr(0, at));
            each.compress(in, apart);
        }
        one.finish(whole);
        each.finish(apart);
        CHECK(apart == whole);
        CHECK(opened(apart) == text);
    }
    std::string stored;
    socketley::deflater z;
    z.compress(noise, stored);
    CHECK(stored.size() <= noise.size() + 5 * 4);
    z.finish(stored);
    CHECK(opened(stored) == noise);
}

TEST_CASE("tar: what is written reads back, a long name, a link, a file of several pieces, each compression")
{
    const std::filesystem::path dir = std::filesystem::temp_directory_path() / ("skl-tar-" + std::to_string(::getpid()));
    dir_guard guard(dir.string());
    std::filesystem::create_directories(dir);
    std::string big(3u << 20, '\0');
    std::mt19937 rng(11);
    for (auto& c : big)
        c = static_cast<char>('a' + rng() % 4);
    {
        FILE* fp = std::fopen((dir / "big").c_str(), "wb");
        REQUIRE(fp);
        std::fwrite(big.data(), 1, big.size(), fp);
        std::fclose(fp);
    }
    const std::string long_name = "var/lib/" + std::string(150, 'x') + "/file";
    for (auto c : {socketley::tar_writer::compression::none, socketley::tar_writer::compression::fast,
                   socketley::tar_writer::compression::best})
    {
        const std::string path = (dir / "a.tar").string();
        std::string why;
        {
            socketley::tar_writer w;
            REQUIRE_MESSAGE(w.open(path, c, why), why);
            struct stat st{};
            REQUIRE(::stat(dir.c_str(), &st) == 0);
            CHECK(w.add_dir("var/lib", st, why));
            CHECK(w.add_bytes(long_name, "short", 0640, why));
            CHECK(w.add_file("var/lib/big", (dir / "big").string(), why));
            CHECK(w.add_link("var/lib/link", "/" + std::string(120, 'y'), st, why));
            REQUIRE_MESSAGE(w.close(why), why);
            CHECK(w.files() == 3);
        }
        // Compressed on two threads, the archive is the same to the byte.
        if (c != socketley::tar_writer::compression::none)
        {
            std::string by[2];
            // Taken once, since writing the first archive changes the directory's time.
            struct stat st{};
            REQUIRE(::stat(dir.c_str(), &st) == 0);
            for (const unsigned threads : {1u, 2u})
            {
                const std::string p = (dir / ("t" + std::to_string(threads) + ".tar")).string();
                socketley::tar_writer w;
                REQUIRE_MESSAGE(w.open(p, c, why, threads), why);
                CHECK(w.add_dir("var/lib", st, why));
                CHECK(w.add_file("var/lib/big", (dir / "big").string(), why));
                CHECK(w.add_link("var/lib/link", "/" + std::string(120, 'y'), st, why));
                REQUIRE_MESSAGE(w.close(why), why);
                CHECK(socketley::read_file(p, by[threads - 1]));
            }
            CHECK(by[0].size() > 1000);
            CHECK(by[1] == by[0]);
        }
        socketley::tar_reader r;
        REQUIRE_MESSAGE(r.open(path, why), why);
        socketley::tar_reader::entry e;
        REQUIRE(r.next(e, why) == socketley::tar_reader::status::entry);
        CHECK(e.name == "var/lib/");
        CHECK(e.type == '5');
        REQUIRE(r.next(e, why) == socketley::tar_reader::status::entry);
        CHECK(e.name == long_name);
        CHECK(e.mode == 0640);
        std::string got;
        CHECK(r.read(got, 100, why));
        CHECK(got == "short");
        REQUIRE(r.next(e, why) == socketley::tar_reader::status::entry);
        CHECK(e.name == "var/lib/big");
        CHECK(e.size == big.size());
        got.clear();
        while (r.left() > 0)
            REQUIRE(r.read(got, 1u << 19, why));
        CHECK(got == big);
        REQUIRE(r.next(e, why) == socketley::tar_reader::status::entry);
        CHECK(e.type == '2');
        CHECK(e.link == "/" + std::string(120, 'y'));
        CHECK(r.next(e, why) == socketley::tar_reader::status::end);
        // An entry passed over unread is skipped whole.
        socketley::tar_reader skip;
        REQUIRE(skip.open(path, why));
        for (int i = 0; i < 4; ++i)
            REQUIRE(skip.next(e, why) == socketley::tar_reader::status::entry);
        CHECK(e.type == '2');
    }
    // What is no tar is told so.
    {
        FILE* fp = std::fopen((dir / "junk").c_str(), "wb");
        std::string junk(2048, 'j');
        std::fwrite(junk.data(), 1, junk.size(), fp);
        std::fclose(fp);
        socketley::tar_reader r;
        std::string why;
        REQUIRE(r.open((dir / "junk").string(), why));
        socketley::tar_reader::entry e;
        CHECK(r.next(e, why) == socketley::tar_reader::status::bad);
    }
}
