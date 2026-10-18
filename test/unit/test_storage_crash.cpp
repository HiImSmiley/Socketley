#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "runtime/storage/object_format.h"
#include "runtime/storage/object_store.h"
#include "shared/loop/event_loop.h"
#include "shared/loop/file_io.h"

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

// A writer that is killed at a random moment, over and over, while it puts and
// deletes objects of every size at once.  What is on disk afterwards, before
// any recovery has run, must hold only whole objects at their final paths --
// and after recovery, exactly the states the writer's own log allows: nothing
// it was told was done may be undone, and nothing it never started may appear.

namespace fs = std::filesystem;
using namespace socketley;
using namespace socketley::storage;

namespace {

constexpr int         key_count = 24;
constexpr const char* bucket    = "crashbkt";

std::string key_name(uint32_t k) { return "obj/" + std::to_string(k); }

// The body an operation writes, which says what it is in its first sixteen
// bytes and is otherwise noise derived from them, so a survivor can be checked
// without asking the writer what it meant.
std::string make_body(uint32_t key, uint32_t op, uint32_t len)
{
    if (len < 16)
        len = 16;
    std::string s(len, '\0');
    std::memcpy(s.data(), "CRSH", 4);
    std::memcpy(s.data() + 4, &key, 4);
    std::memcpy(s.data() + 8, &op, 4);
    std::memcpy(s.data() + 12, &len, 4);
    uint64_t x = 0x9E3779B97F4A7C15ull ^ (static_cast<uint64_t>(key) << 32) ^ op;
    for (size_t i = 16; i < len; ++i)
    {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        s[i] = static_cast<char>(x);
    }
    return s;
}

bool body_is_whole(const std::string& body, uint32_t& key, uint32_t& op)
{
    if (body.size() < 16 || body.compare(0, 4, "CRSH") != 0)
        return false;
    uint32_t len;
    std::memcpy(&key, body.data() + 4, 4);
    std::memcpy(&op, body.data() + 8, 4);
    std::memcpy(&len, body.data() + 12, 4);
    return len == body.size() && make_body(key, op, len) == body;
}

// Operation n of a key is a delete when it is a multiple of three.
bool is_delete(uint32_t n) { return n % 3 == 0; }

uint32_t length_for(uint32_t key, uint32_t n)
{
    static constexpr uint32_t sizes[] = {16, 100, 4000, 4096, 9000, 70000, 300000,
                                         (1u << 20) - 5, (1u << 20) + 5, 2500000};
    // Mostly small, so a great many commits happen per second, with the large
    // ones enough to be killed in the middle of.
    const uint64_t h = (static_cast<uint64_t>(key) * 2654435761u + n * 40503u) >> 3;
    const uint32_t r = static_cast<uint32_t>(h % 100);
    if (r < 55) return sizes[h % 3];
    if (r < 85) return sizes[3 + h % 3];
    if (r < 95) return sizes[6 + h % 2];
    return sizes[8 + h % 2];
}

struct log_record
{
    uint32_t key;
    uint32_t n;
};

// The two files the writer appends to, which is how the parent knows what
// was started and what was acknowledged.
void log_append(int fd, uint32_t key, uint32_t n)
{
    log_record r{key, n};
    if (::write(fd, &r, sizeof r) < 0) {}
}

std::vector<log_record> log_read(const std::string& path)
{
    std::vector<log_record> out;
    std::ifstream f(path, std::ios::binary);
    log_record r;
    while (f.read(reinterpret_cast<char*>(&r), sizeof r))
        out.push_back(r);
    return out;
}

struct tmpdir
{
    std::string path;
    tmpdir()
    {
        char tmpl[] = "/tmp/socketley-crash-XXXXXX";
        path = ::mkdtemp(tmpl);
    }
    ~tmpdir()
    {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

struct engine : io_handler
{
    event_loop                    loop{512};
    std::unique_ptr<file_io>      io;
    std::unique_ptr<object_store> store;
    recovery_report               report;

    bool start(const std::string& dir, std::string& err)
    {
        if (!loop.init())
        {
            err = "no ring";
            return false;
        }
        io = std::make_unique<file_io>(loop, this);
        store_options o;
        o.dir           = dir;
        o.compact_floor = 64;
        store = std::make_unique<object_store>(loop, *io, o);
        return store->open(err, &report);
    }

    void on_cqe(struct io_uring_cqe* cqe) override
    {
        auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
        if (req && file_io::owns_type(req->type))
            io->on_cqe(cqe);
    }
};

// ─── The writer, which never returns ────────────────────────────────────────

struct writer;

// One put on its way in, alive for as long as a callback can still reach it.
struct put_run : std::enable_shared_from_this<put_run>
{
    writer*                 w{nullptr};
    uint32_t                key{0};
    uint32_t                op{0};
    std::string             body;
    size_t                  off{0};
    std::shared_ptr<put_op> put;

    void step();
};

struct writer
{
    engine&  e;
    int      intent_fd;
    int      ack_fd;
    uint32_t n[key_count]{};

    void kick(uint32_t key)
    {
        const uint32_t op = ++n[key];
        log_append(intent_fd, key, op);

        if (is_delete(op))
        {
            e.store->remove(bucket, key_name(key),
                [this, key, op](st s, bool)
                {
                    if (s == st::ok)
                        log_append(ack_fd, key, op);
                    kick(key);
                });
            return;
        }

        auto run  = std::make_shared<put_run>();
        run->w    = this;
        run->key  = key;
        run->op   = op;
        run->body = make_body(key, op, length_for(key, op));
        st why;
        // Half the keys go as PutObject sends them, answered at the rename from a pooled file.
        run->put = e.store->begin_put(bucket, key_name(key), {}, run->body.size(), true, why, key % 2 == 0);
        if (!run->put)
        {
            kick(key);
            return;
        }
        run->step();
    }
};

void put_run::step()
{
    auto self = shared_from_this();
    while (off < body.size())
    {
        // Uneven pieces so a piece straddles a buffer boundary.
        const size_t want = std::min<size_t>(65536 + (op % 7) * 977, body.size() - off);
        const size_t took = put->append(body.data() + off, want);
        off += took;
        if (took < want)
        {
            put->on_ready([self] { self->step(); });
            return;
        }
    }
    put->on_ready(nullptr);
    put->finish(nullptr, [self](put_result r)
    {
        if (r.status == st::ok)
            log_append(self->w->ack_fd, self->key, self->op);
        self->put.reset();
        self->w->kick(self->key);
    });
}

[[noreturn]] void child_main(const std::string& dir, const std::string& logs, int ready_fd)
{
    engine e;
    std::string err;
    if (!e.start(dir, err))
    {
        std::fprintf(stderr, "child: %s\n", err.c_str());
        _exit(3);
    }
    if (!e.store->has_bucket(bucket))
    {
        bool done = false;
        e.store->create_bucket(bucket, {}, [&](st) { done = true; });
        while (!done)
            e.loop.poll_completions(1);
    }

    const int intent = ::open((logs + "/intent.log").c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    const int ack    = ::open((logs + "/ack.log").c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);

    writer w{e, intent, ack, {}};
    // Continue the numbering, so an operation number never repeats across rounds.
    for (const log_record& r : log_read(logs + "/intent.log"))
        if (r.key < key_count && r.n > w.n[r.key])
            w.n[r.key] = r.n;

    if (::write(ready_fd, "R", 1) < 0) {}
    for (uint32_t k = 0; k < key_count; ++k)
        w.kick(k);
    for (;;)
        e.loop.poll_completions(1);
}

// What the disk holds before anything has looked at it.
struct survey
{
    std::map<std::string, std::pair<uint32_t, uint32_t>> found;   // key -> (key index, op)
    uint64_t files{0};
    std::string problem;
};

survey survey_disk(const std::string& dir)
{
    survey s;
    const std::string data = dir + "/" + bucket + "/data";
    std::error_code ec;
    for (fs::recursive_directory_iterator it(data, ec), end; !ec && it != end; it.increment(ec))
    {
        if (!it->is_regular_file())
            continue;
        ++s.files;
        std::ifstream f(it->path(), std::ios::binary);
        std::stringstream ss;
        ss << f.rdbuf();
        const std::string all = ss.str();

        const decoded_header h = decode_object_header(all.substr(0, 65536));
        if (h.status != header_status::ok)
        {
            s.problem = "torn header at " + it->path().string();
            return s;
        }
        if (all.size() != h.header_len + h.meta.size)
        {
            s.problem = "wrong length at " + it->path().string();
            return s;
        }
        const std::string body = all.substr(h.header_len);
        if (md5_of(body) != h.meta.md5)
        {
            s.problem = "etag mismatch at " + it->path().string();
            return s;
        }
        uint32_t k, op;
        if (!body_is_whole(body, k, op) || key_name(k) != h.key)
        {
            s.problem = "body is not the operation's at " + it->path().string();
            return s;
        }
        if (it->path().filename().string() != key_hash(h.key))
        {
            s.problem = "file is not at its key's path: " + it->path().string();
            return s;
        }
        s.found[h.key] = {k, op};
    }
    return s;
}

}   // namespace

TEST_CASE("a writer killed at random moments leaves only whole objects and never undoes an acknowledged one")
{
    int rounds = 300;
    if (const char* e = std::getenv("SOCKETLEY_CRASH_ROUNDS"))
        rounds = std::max(1, std::atoi(e));

    tmpdir root;
    const std::string dir = root.path + "/store";
    fs::create_directories(dir);

    std::mt19937_64 rng(0xC0FFEEull ^ static_cast<uint64_t>(::getpid()));
    uint64_t total_files = 0, kills_with_tmp = 0, torn_journals = 0, adopted = 0, dropped = 0;
    uint64_t killed_busy = 0, rolled = 0;

    for (int round = 0; round < rounds; ++round)
    {
        int ready[2];
        REQUIRE(::pipe(ready) == 0);
        const pid_t child = ::fork();
        REQUIRE(child >= 0);
        if (child == 0)
        {
            ::close(ready[0]);
            child_main(dir, root.path, ready[1]);
        }
        ::close(ready[1]);

        // The moment is random within the first stretch of the writer's life,
        // which is where the recovery it just did is over and its first puts
        // are in every stage from a rename to a journal fsync.
        char c;
        REQUIRE(::read(ready[0], &c, 1) == 1);
        ::close(ready[0]);
        // Every fourth round waits up to half a second, because on a loaded box
        // a 60 ms window ended before any rename in every round and the file
        // then checked nothing (files seen 0 beside three agents' builds).
        const uint64_t window_us = round % 4 == 3 ? 500000 : 60000;
        const auto delay_us = static_cast<useconds_t>(rng() % window_us);
        ::usleep(delay_us);
        ::kill(child, SIGKILL);
        int status = 0;
        REQUIRE(::waitpid(child, &status, 0) == child);
        REQUIRE(WIFSIGNALED(status));
        INFO("round " << round);

        // Before any recovery: no path a reader could open holds anything but a whole object.
        const survey before = survey_disk(dir);
        INFO(before.problem);
        REQUIRE(before.problem.empty());
        total_files += before.files;
        std::error_code ec;
        if (!fs::is_empty(dir + "/" + bucket + "/tmp", ec))
            ++kills_with_tmp;

        // What the writer said it began and finished.
        uint32_t started[key_count]{}, acked[key_count]{};
        for (const log_record& r : log_read(root.path + "/intent.log"))
            if (r.key < key_count)
                started[r.key] = std::max(started[r.key], r.n);
        for (const log_record& r : log_read(root.path + "/ack.log"))
            if (r.key < key_count)
                acked[r.key] = std::max(acked[r.key], r.n);
        for (uint32_t k = 0; k < key_count; ++k)
            if (started[k] > acked[k])
                ++killed_busy;

        // Now recover, as a start would.
        engine e;
        std::string err;
        REQUIRE(e.start(dir, err));
        INFO(err);
        CHECK(e.report.corrupt_files == 0);
        CHECK_FALSE(e.report.clean_start);
        torn_journals += e.report.torn_tails;
        adopted += e.report.adopted;
        dropped += e.report.dropped;

        // A whole pooled file of the put in flight is rolled forward, so the
        // disk is judged again as the recovery left it, and must still be whole.
        const survey after = survey_disk(dir);
        INFO(after.problem);
        REQUIRE(after.problem.empty());
        for (const auto& [name, kv] : before.found)
            if (!after.found.contains(name))
                FAIL_CHECK("the start removed the object file of " << name);
        rolled += e.report.rolled_forward;

        // The store and the files agree.
        CHECK(e.store->totals().objects == after.found.size());
        for (const auto& [name, kv] : after.found)
        {
            const object_meta* m = e.store->find(bucket, name);
            REQUIRE(m != nullptr);
            CHECK(m->md5 == md5_of(make_body(kv.first, kv.second, static_cast<uint32_t>(m->size))));
        }

        // And with what the writer was told.
        for (uint32_t k = 0; k < key_count; ++k)
        {
            const auto it = after.found.find(key_name(k));
            if (it == after.found.end())
            {
                // Absent is allowed when nothing was acknowledged, or when a
                // delete at or after the last acknowledgement was begun.
                bool delete_possible = acked[k] == 0;
                for (uint32_t n = std::max<uint32_t>(acked[k], 1); n <= started[k]; ++n)
                    if (is_delete(n))
                        delete_possible = true;
                INFO("key " << k << " acked " << acked[k] << " started " << started[k]);
                CHECK(delete_possible);
            }
            else
            {
                const uint32_t op = it->second.second;
                INFO("key " << k << " op " << op << " acked " << acked[k] << " started " << started[k]);
                CHECK_FALSE(is_delete(op));
                // Nothing the writer was told is done was undone, and nothing it never began appeared.
                CHECK(op >= acked[k]);
                CHECK(op <= started[k]);
            }
        }
    }

    // The rounds did what they claim: killed a busy writer, over and over.
    MESSAGE("rounds " << rounds << ", files seen " << total_files << ", rounds with a tmp file left "
            << kills_with_tmp << ", keys killed mid-operation " << killed_busy
            << ", torn journal tails " << torn_journals << ", adopted " << adopted
            << ", dropped " << dropped << ", rolled forward " << rolled);
    CHECK(killed_busy > static_cast<uint64_t>(rounds));
    CHECK(total_files > 0);
}
