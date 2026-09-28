#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "shared/event_loop.h"
#include "shared/raft.h"
#include "shared/raft_storage.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <vector>

// Raft's WAL and snapshot files: what recovery keeps, what it cuts, and that the io_uring writer leaves exactly the node's state behind.

namespace raft = socketley::raft;
namespace st   = socketley::raft::storage;
namespace fs   = std::filesystem;

namespace {

raft::entry make_entry(raft::index_t i, raft::term_t t, std::string data = "")
{
    raft::entry e;
    e.index = i;
    e.term  = t;
    e.data  = data.empty() ? "e" + std::to_string(i) + "t" + std::to_string(t) : data;
    return e;
}

struct tmpdir
{
    std::string path;

    tmpdir()
    {
        char tmpl[] = "/tmp/socketley-raftwal-XXXXXX";
        path = ::mkdtemp(tmpl);
    }
    ~tmpdir()
    {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

std::string slurp(const std::string& p)
{
    std::ifstream f(p, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

void spill(const std::string& p, const std::string& data)
{
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f << data;
}

raft::persisted fresh(std::vector<raft::node_id> voters)
{
    raft::persisted p;
    p.snap.voters = std::move(voters);
    p.snap.data   = "book";
    return p;
}

std::vector<std::string> names_in(const std::string& dir)
{
    std::vector<std::string> out;
    for (const auto& e : fs::directory_iterator(dir))
        out.push_back(e.path().filename().string());
    std::sort(out.begin(), out.end());
    return out;
}

}   // namespace

TEST_CASE("crc32c is the Castagnoli polynomial")
{
    CHECK(st::crc32c("123456789", 9) == 0xE3069283u);
    CHECK(st::crc32c("", 0) == 0u);
}

TEST_CASE("replay applies hard state, entries and truncations, and a re-stated entry cuts nothing")
{
    std::string wal;
    st::append_hard(wal, raft::hard_state{3, 2});
    for (raft::index_t i = 1; i <= 5; ++i)
        st::append_entry(wal, make_entry(i, 1));
    st::append_truncate(wal, 4);
    st::append_entry(wal, make_entry(4, 3));
    // The same entry again, as a rotated segment's image says it, must not drop entry 5 behind it.
    st::append_entry(wal, make_entry(5, 3));
    st::append_entry(wal, make_entry(2, 1));
    st::append_hard(wal, raft::hard_state{4, 0});

    raft::persisted p;
    const st::replay_result r = st::replay(wal, p);
    CHECK(r.stopped.empty());
    CHECK(r.valid == wal.size());
    CHECK(p.hard == raft::hard_state{4, 0});
    REQUIRE(p.log.size() == 5);
    CHECK(p.log[2] == make_entry(3, 1));
    CHECK(p.log[3] == make_entry(4, 3));
    CHECK(p.log[4] == make_entry(5, 3));

    // An entry of another term at an index the log holds replaces everything from there.
    std::string conflict;
    st::append_entry(conflict, make_entry(3, 7));
    CHECK(st::replay(conflict, p).stopped.empty());
    CHECK(p.log.size() == 3);
    CHECK(p.log.back() == make_entry(3, 7));

    // A gap is where replay stops, since what should fill it was lost.
    std::string gap;
    st::append_entry(gap, make_entry(9, 7));
    const st::replay_result g = st::replay(gap, p);
    CHECK_FALSE(g.stopped.empty());
    CHECK(g.valid == 0);
    CHECK(p.log.size() == 3);
}

TEST_CASE("a torn tail at any byte is cut back to the last whole record")
{
    std::string wal;
    std::vector<size_t> ends;
    st::append_hard(wal, raft::hard_state{1, 1});
    ends.push_back(wal.size());
    for (raft::index_t i = 1; i <= 6; ++i)
    {
        st::append_entry(wal, make_entry(i, 1, std::string(i * 7, 'x')));
        ends.push_back(wal.size());
    }

    for (size_t cut = 0; cut <= wal.size(); ++cut)
    {
        raft::persisted p;
        const st::replay_result r = st::replay(std::string_view(wal).substr(0, cut), p);
        size_t whole = 0, records = 0;
        for (size_t e : ends)
            if (e <= cut)
            {
                whole = e;
                ++records;
            }
        REQUIRE(r.valid == whole);
        CHECK(r.stopped.empty() == (cut == whole));
        CHECK(p.log.size() == (records ? records - 1 : 0));
    }

    // A flipped bit anywhere in a record ends replay at that record.
    for (size_t k = 0; k < ends.size(); ++k)
    {
        std::string bad = wal;
        const size_t begin = k ? ends[k - 1] : 0;
        bad[begin + (ends[k] - begin) / 2] ^= 0x10;
        raft::persisted p;
        CHECK(st::replay(bad, p).valid == begin);
    }
}

TEST_CASE("recovery truncates a torn segment on disk and keeps every whole record")
{
    tmpdir d;
    std::string err;
    REQUIRE(st::initialize(d.path, fresh({1}), err));

    st::recovery rec;
    REQUIRE(st::recover(d.path, rec, err));
    CHECK(rec.state.snap.voters == std::vector<raft::node_id>{1});
    CHECK(rec.state.snap.data == "book");
    CHECK(rec.state.log.empty());

    std::string tail;
    st::append_hard(tail, raft::hard_state{2, 1});
    st::append_entry(tail, make_entry(1, 2));
    st::append_entry(tail, make_entry(2, 2));
    const size_t whole = tail.size();
    st::append_entry(tail, make_entry(3, 2));
    tail.resize(tail.size() - 3);
    spill(rec.segment, slurp(rec.segment) + tail);
    const size_t before = rec.segment_len;

    REQUIRE(st::recover(d.path, rec, err));
    CHECK(rec.state.hard == raft::hard_state{2, 1});
    REQUIRE(rec.state.log.size() == 2);
    CHECK(rec.state.log[1] == make_entry(2, 2));
    CHECK(rec.segment_len == before + whole);
    CHECK(fs::file_size(rec.segment) == before + whole);
    REQUIRE(rec.notes.size() == 1);
    CHECK(rec.notes[0].find("truncated") != std::string::npos);

    // Files hold the state machine, so nobody else may read them.
    struct stat sb{};
    REQUIRE(::stat(rec.segment.c_str(), &sb) == 0);
    CHECK((sb.st_mode & 0777) == 0600);
}

TEST_CASE("an unfinished rotation is discarded and the segment before it decides")
{
    tmpdir d;
    std::string err;
    raft::persisted p = fresh({1, 2, 3});
    p.hard = raft::hard_state{5, 2};
    for (raft::index_t i = 1; i <= 8; ++i)
        p.log.push_back(make_entry(i, 5));
    REQUIRE(st::initialize(d.path, p, err));

    // A newer snapshot and a segment whose image never got its seal, as a crash inside the rotation leaves them.
    raft::snapshot s;
    s.index  = 6;
    s.term   = 5;
    s.voters = {1, 2, 3};
    std::string snap;
    st::append_snapshot(snap, s);
    spill(d.path + "/" + st::snapshot_name(6, 5), snap);
    std::string half;
    st::append_hard(half, raft::hard_state{5, 2});
    spill(d.path + "/" + st::segment_name(2), half);
    spill(d.path + "/whatever.tmp", "x");

    st::recovery rec;
    REQUIRE(st::recover(d.path, rec, err));
    CHECK(rec.segment_seq == 1);
    CHECK(rec.state.snap.index == 0);
    CHECK(rec.state.log.size() == 8);
    CHECK(rec.state.hard == raft::hard_state{5, 2});
    CHECK(names_in(d.path) == std::vector<std::string>{st::snapshot_name(0, 0), st::segment_name(1)});
}

TEST_CASE("a sealed segment whose snapshot is missing is refused, never guessed around")
{
    tmpdir d;
    std::string err;
    REQUIRE(st::initialize(d.path, fresh({1}), err));
    fs::remove(d.path + "/" + st::snapshot_name(0, 0));
    st::recovery rec;
    CHECK_FALSE(st::recover(d.path, rec, err));
    CHECK(err.find("missing or corrupt") != std::string::npos);
}

namespace {

// Drives one node's readies through the writer the way raft_host does, one persist at a time.
struct harness
{
    event_loop loop{256};
    st::wal    w;
    std::unique_ptr<raft::node> n;
    raft::index_t applied = 0;

    void drain(int budget_ms = 5000)
    {
        for (int i = 0; i < budget_ms && w.busy(); ++i)
            loop.poll_completions(1);
    }

    void pump()
    {
        while (n->has_ready())
        {
            raft::ready r = n->take_ready();
            bool ok = false, called = false;
            if (w.persist(r, *n, [&](bool k) { ok = k; called = true; }))
            {
                drain();
                REQUIRE(called);
                REQUIRE(ok);
            }
            REQUIRE_FALSE(w.failed());
            for (const raft::entry& e : r.committed)
                applied = e.index;
        }
    }
};

}   // namespace

TEST_CASE("the io_uring writer leaves exactly the node's state behind, one fsync per ready")
{
    tmpdir d;
    std::string err;
    REQUIRE(st::initialize(d.path, fresh({1}), err));
    st::recovery rec;
    REQUIRE(st::recover(d.path, rec, err));

    harness h;
    REQUIRE(h.loop.init());
    REQUIRE(h.w.open(h.loop, d.path, rec, err));
    raft::options o;
    o.id = 1;
    h.n  = std::make_unique<raft::node>(o, rec.state);
    for (int i = 0; i < 40 && h.n->current_role() != raft::role::leader; ++i)
    {
        h.n->tick();
        h.pump();
    }
    REQUIRE(h.n->current_role() == raft::role::leader);

    // Ten proposals before one ready are one write and one fsync: the group commit.
    const uint64_t before = h.w.fsyncs();
    for (int i = 0; i < 10; ++i)
        REQUIRE(h.n->propose("p" + std::to_string(i)).status == raft::propose_status::ok);
    h.pump();
    CHECK(h.w.fsyncs() == before + 1);

    // A compaction rotates the segment, and the next appends go into the new one.
    REQUIRE(h.n->compact(h.applied - 2, "sm-state"));
    h.pump();
    for (int i = 0; i < 5; ++i)
        REQUIRE(h.n->propose("q" + std::to_string(i)).status == raft::propose_status::ok);
    h.pump();
    h.drain();
    for (int i = 0; i < 50; ++i)
        h.loop.poll_completions(1);

    const raft::index_t snap_index = h.n->current_snapshot().index;
    CHECK(names_in(d.path) == std::vector<std::string>{st::snapshot_name(snap_index, h.n->current_snapshot().term),
                                                         st::segment_name(2)});

    st::recovery back;
    REQUIRE(st::recover(d.path, back, err));
    CHECK(back.notes.empty());
    CHECK(back.state.hard == raft::hard_state{h.n->term(), h.n->vote()});
    CHECK(back.state.snap.index == snap_index);
    CHECK(back.state.snap.data == "sm-state");
    CHECK(back.state.snap.voters == std::vector<raft::node_id>{1});
    REQUIRE(back.state.log.size() == h.n->last_index() - snap_index);
    for (raft::index_t i = snap_index + 1; i <= h.n->last_index(); ++i)
        CHECK(back.state.log[i - snap_index - 1] == *h.n->entry_at(i));
    CHECK(back.segment_len == fs::file_size(back.segment));

    h.w.retire();
    h.loop.shutdown_ring();
}
