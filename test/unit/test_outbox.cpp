#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "shared/loop/event_loop.h"
#include "shared/loop/file_io.h"
#include "shared/persist/outbox.h"

#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
using namespace socketley;

namespace {

struct engine : io_handler
{
    event_loop               loop{256};
    std::unique_ptr<file_io> io;

    engine()
    {
        REQUIRE(loop.init());
        io = std::make_unique<file_io>(loop, this);
    }

    void on_cqe(struct io_uring_cqe* cqe) override
    {
        auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
        if (req && file_io::owns_type(req->type))
            io->on_cqe(cqe);
    }

    bool until(const std::function<bool()>& done, int budget_ms = 10000)
    {
        for (int i = 0; i < budget_ms && !done(); ++i)
            loop.poll_completions(1);
        return done();
    }
};

struct tmp_dir
{
    std::string path;
    tmp_dir() : path(fs::temp_directory_path() / ("outbox_test_" + std::to_string(::getpid())))
    {
        fs::remove_all(path);
        fs::create_directories(path);
    }
    ~tmp_dir() { fs::remove_all(path); }
};

bool synced(engine& e, outbox& box)
{
    bool fired = false;
    box.sync([&] { fired = true; });
    return e.until([&] { return fired; });
}

}   // namespace

TEST_CASE("an entry added while the outbox is started again empty survives a stop")
{
    tmp_dir dir;
    engine e;
    const std::string file = dir.path + "/sub/outbox.0";
    const std::string payload(16384, 'p');
    std::string err;
    {
        outbox box(e.loop, *e.io, "test");
        REQUIRE(box.open(dir.path, "sub", 0, [](std::string_view) { return true; },
                         [](uint64_t, std::string_view) { return true; }, err));
        struct stat first{};
        REQUIRE(::stat(file.c_str(), &first) == 0);
        // Past the megabyte with everything delivered, so the last sync is followed by a rotation.
        bool rotated = false;
        for (int round = 0; round < 200 && !rotated; ++round)
        {
            std::vector<uint64_t> ids;
            for (int i = 0; i < 8; ++i)
                ids.push_back(box.add(payload));
            REQUIRE(synced(e, box));
            for (const uint64_t id : ids)
                box.done(id);
            REQUIRE(synced(e, box));
            struct stat now{};
            REQUIRE(::stat(file.c_str(), &now) == 0);
            rotated = now.st_ino != first.st_ino;
        }
        REQUIRE(rotated);
        CHECK(box.owed() == 0);
        // The rotation's directory sync is still in flight here, and what is added now waits on it.
        box.add("late");
        box.stop();
    }
    // The rotation's last completion, which the stopped outbox ignores.
    for (int i = 0; i < 50; ++i)
        e.loop.poll_completions(1);

    std::vector<std::string> kept;
    outbox again(e.loop, *e.io, "test");
    REQUIRE(again.open(dir.path, "sub", 0, [](std::string_view) { return true; },
                       [&](uint64_t, std::string_view p) { kept.emplace_back(p); return true; }, err));
    REQUIRE(kept.size() == 1);
    CHECK(kept[0] == "late");
    struct stat after{};
    REQUIRE(::stat(file.c_str(), &after) == 0);
    CHECK(after.st_size < 4096);
    again.stop();
}
