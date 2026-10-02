#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "runtime/storage/bucket_policy.h"
#include "runtime/storage/lifecycle.h"
#include "runtime/storage/object_format.h"
#include "runtime/storage/multipart.h"
#include "runtime/storage/object_store.h"
#include "runtime/storage/shard_node.h"
#include "runtime/storage/shard_owner.h"
#include "runtime/storage/shard_wire.h"
#include "shared/event_loop.h"
#include "shared/file_io.h"

#include <algorithm>
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

// N stores on one directory in one process, as N shards of one runtime are on
// disk, each on a ring of its own and joined by a transport that delivers a
// request on a later turn the way a link does.

namespace fs = std::filesystem;
using namespace socketley;
using namespace socketley::storage;

namespace {

struct tmpdir
{
    std::string path;

    tmpdir()
    {
        char tmpl[] = "/tmp/socketley-shards-XXXXXX";
        path = ::mkdtemp(tmpl);
    }
    ~tmpdir()
    {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

std::string pattern(size_t n, unsigned seed = 1)
{
    std::string s(n, '\0');
    uint64_t x = 0x9E3779B97F4A7C15ull * (seed + 1);
    for (size_t i = 0; i < n; ++i)
    {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        s[i] = static_cast<char>(x);
    }
    return s;
}

struct cluster;

struct member : io_handler
{
    event_loop                    loop{256};
    std::unique_ptr<file_io>      io;
    std::unique_ptr<object_store> store;
    std::unique_ptr<multipart_store> mpu;
    std::unique_ptr<shard_node>   node;
    recovery_report               report;

    void on_cqe(struct io_uring_cqe* cqe) override
    {
        auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
        if (req && file_io::owns_type(req->type))
            io->on_cqe(cqe);
    }
};

struct cluster : shard_transport
{
    struct task
    {
        uint32_t                                  peer;
        std::string                               payload;
        std::function<void(bool, std::string_view)> cb;
    };

    std::string                          dir;
    uint32_t                             n{0};
    std::vector<std::unique_ptr<member>> m;
    std::deque<task>                     queue;
    // A shard the transport cannot reach, for the cases that lose one.
    std::set<uint32_t>                   unreachable;
    // Decides per message whether it is delivered (0), lost (1) or held back until release_held() (2).
    std::function<int(uint32_t peer, wire::op o)> fault;
    std::deque<task>                     withheld;
    uint64_t                             calls{0};
    // Whether each shard tells the others it started, after which its drops go only to the siblings that asked.
    bool                                 announce{true};
    // Requests the transport keeps back, delivered in order once `release` is called, for the cases that race one.
    std::function<bool(const task&)>     hold_back;
    std::deque<task>                     held_back;

    cluster(std::string d, uint32_t shards, uint64_t max_bytes = 0, bool announce_starts = true)
        : dir(std::move(d)), announce(announce_starts)
    {
        start(shards, max_bytes);
    }

    ~cluster() { stop(false); }

    void start(uint32_t shards, uint64_t max_bytes = 0)
    {
        n = shards;
        for (uint32_t i = 0; i < n; ++i)
        {
            auto mb = std::make_unique<member>();
            REQUIRE(mb->loop.init());
            mb->io = std::make_unique<file_io>(mb->loop, mb.get());
            store_options o;
            o.dir       = dir;
            o.shard     = i;
            o.nshards   = n;
            o.max_bytes = max_bytes;
            mb->store = std::make_unique<object_store>(mb->loop, *mb->io, o);
            std::string err;
            const bool ok = mb->store->open(err, &mb->report);
            INFO(err);
            REQUIRE(ok);
            mb->mpu = std::make_unique<multipart_store>(mb->loop, *mb->io, *mb->store);
            REQUIRE(mb->mpu->open(err));
            mb->node = std::make_unique<shard_node>(*mb->store, *this);
            mb->node->set_multipart(mb->mpu.get());
            multipart_store* mp = mb->mpu.get();
            mb->store->set_drop_guard([mp](std::string_view bucket) { return mp->bucket_uploads_busy(bucket); });
            mb->store->set_forget_listener([mp](const std::string& bucket) { mp->drop_bucket(bucket); });
            m.push_back(std::move(mb));
        }
        if (announce)
            for (auto& mb : m)
                mb->node->announce_start([](bool) {});
        settle();
    }

    void stop(bool clean)
    {
        for (auto& mb : m)
        {
            mb->node->stop();
            mb->store->close(clean);
        }
        // The rings are polled once more so what a close queued is finished with.
        for (auto& mb : m)
            mb->loop.poll_completions(0);
        m.clear();
        queue.clear();
        withheld.clear();
    }

    void restart(uint32_t shards, bool clean = true)
    {
        stop(clean);
        start(shards);
    }

    void call(uint32_t peer, std::string payload, std::function<void(bool, std::string_view)> cb) override
    {
        ++calls;
        queue.push_back({peer, std::move(payload), std::move(cb)});
    }

    void pump()
    {
        for (auto& mb : m)
            mb->node->flush_holds();
        while (!queue.empty())
        {
            task t = std::move(queue.front());
            queue.pop_front();
            if (hold_back && hold_back(t))
            {
                held_back.push_back(std::move(t));
                continue;
            }
            if (unreachable.contains(t.peer) || t.peer >= m.size())
            {
                t.cb(false, {});
                continue;
            }
            if (wire::op o{}; fault && wire::request_op(t.payload, o))
            {
                const int f = fault(t.peer, o);
                if (f == 1)
                {
                    t.cb(false, {});
                    continue;
                }
                if (f == 2)
                {
                    withheld.push_back(std::move(t));
                    continue;
                }
            }
            auto cb = t.cb;
            m[t.peer]->node->serve(t.payload, [cb](bool ok, std::string reply) { cb(ok, reply); });
        }
    }

    void release_held()
    {
        while (!withheld.empty())
        {
            queue.push_back(std::move(withheld.front()));
            withheld.pop_front();
        }
    }

    void release()
    {
        hold_back = nullptr;
        while (!held_back.empty())
        {
            queue.push_back(std::move(held_back.front()));
            held_back.pop_front();
        }
    }

    bool until(const std::function<bool()>& done, int budget_ms = 10000)
    {
        for (int i = 0; i < budget_ms && !done(); ++i)
        {
            pump();
            for (auto& mb : m)
                mb->loop.poll_completions(0);
            if (!done())
                m[0]->loop.poll_completions(1);
        }
        return done();
    }

    void settle(int turns = 60)
    {
        for (int i = 0; i < turns; ++i)
        {
            pump();
            for (auto& mb : m)
                mb->loop.poll_completions(0);
        }
    }

    // ── Operations, each on the shard a client happened to land on ─────────
    st make_bucket(uint32_t s, const std::string& name)
    {
        st got = st::io_error;
        bool fired = false;
        m[s]->node->create_bucket(name, {}, [&](st r) { got = r; fired = true; });
        REQUIRE(until([&] { return fired; }));
        return got;
    }

    st drop_bucket(uint32_t s, const std::string& name)
    {
        st got = st::io_error;
        bool fired = false;
        m[s]->node->delete_bucket(name, [&](st r) { got = r; fired = true; });
        REQUIRE(until([&] { return fired; }));
        return got;
    }

    // Starts a put and returns before it ends, for the ones that race.
    std::shared_ptr<put_op> begin(uint32_t s, const std::string& bucket, const std::string& key,
                                  const std::string& body, bool create_only,
                                  std::function<void(put_result)> done, object_meta meta = {}, bool plain = false)
    {
        st why = st::ok;
        auto op = m[s]->store->begin_put(bucket, key, std::move(meta), body.size(), true, why, plain);
        if (!op)
        {
            done({why, {}});
            return nullptr;
        }
        REQUIRE(op->append(body.data(), body.size()) == body.size());
        op->set_create_only(create_only);
        op->finish(nullptr, std::move(done));
        return op;
    }

    put_result put(uint32_t s, const std::string& bucket, const std::string& key,
                   const std::string& body, bool create_only = false, object_meta meta = {})
    {
        put_result out;
        bool fired = false;
        auto op = begin(s, bucket, key, body, create_only,
                        [&](put_result r) { out = std::move(r); fired = true; }, std::move(meta));
        REQUIRE(until([&] { return fired; }));
        return out;
    }

    st del(uint32_t s, const std::string& bucket, const std::string& key, bool* existed = nullptr)
    {
        st got = st::io_error;
        bool fired = false;
        m[s]->store->remove(bucket, key, [&](st r, bool e) { got = r; if (existed) *existed = e; fired = true; });
        REQUIRE(until([&] { return fired; }));
        return got;
    }

    // What a GET on shard `s` finds: the header and the bytes, from the file.
    st get(uint32_t s, const std::string& bucket, const std::string& key, std::string& body,
           object_meta* meta = nullptr)
    {
        open_result r;
        bool fired = false;
        m[s]->store->open_object(bucket, key, 0, [&](open_result o) { r = std::move(o); fired = true; });
        REQUIRE(until([&] { return fired; }));
        if (r.status != st::ok)
            return r.status;
        body.assign(r.meta.size, '\0');
        size_t got = 0;
        while (got < body.size())
        {
            const ssize_t k = ::pread(r.fd, body.data() + got, body.size() - got,
                                      static_cast<off_t>(r.data_off + got));
            if (k <= 0)
                break;
            got += static_cast<size_t>(k);
        }
        ::close(r.fd);
        body.resize(got);
        if (meta)
            *meta = r.meta;
        return st::ok;
    }

    // A read of another shard's key as a GET makes it: the drop epoch first, then the file, then the copy kept.
    bool warm(uint32_t s, const std::string& bucket, const std::string& key)
    {
        const uint64_t epoch = m[s]->store->hot_epoch();
        std::string body;
        object_meta meta;
        if (get(s, bucket, key, body, &meta) != st::ok)
            return false;
        m[s]->store->hot_put_foreign(bucket, key, epoch, meta, body);
        settle();
        return held(s, bucket, key);
    }

    bool held(uint32_t s, const std::string& bucket, const std::string& key, std::string* body = nullptr)
    {
        object_store::hot_hit hit;
        const bool h = m[s]->store->hot_find(bucket, key, hit) && hit.foreign && hit.body;
        if (h && body)
            *body = *hit.body;
        return h;
    }

    // How many shards other than the key's owner keep a copy of it.
    uint32_t copies(const std::string& bucket, const std::string& key)
    {
        uint32_t n = 0;
        for (uint32_t s = 0; s < this->n; ++s)
            if (s != object_owner(bucket, key, this->n) && held(s, bucket, key))
                ++n;
        return n;
    }

    st stat(uint32_t s, const std::string& bucket, const std::string& key, object_meta& meta)
    {
        st got = st::io_error;
        bool fired = false;
        m[s]->store->stat_object(bucket, key, [&](st r, const object_meta& mm) { got = r; meta = mm; fired = true; });
        REQUIRE(until([&] { return fired; }));
        // The copy a stat keeps is kept once the owner has answered for it.
        settle();
        return got;
    }

    st list(uint32_t s, const std::string& bucket, const list_query& q, list_page& page)
    {
        st got = st::io_error;
        bool fired = false;
        m[s]->node->list(bucket, q, [&](st r, list_page p) { got = r; page = std::move(p); fired = true; });
        REQUIRE(until([&] { return fired; }));
        return got;
    }

    // Whether tmp/ empties, the removals of a refused body being on the ring.
    bool tmp_empties(const std::string& bucket, int budget_ms = 3000)
    {
        return until([&] { return tmp_files_of(bucket).empty(); }, budget_ms);
    }

    std::vector<std::string> tmp_files_of(const std::string& bucket) const
    {
        std::vector<std::string> out;
        std::error_code ec;
        for (const auto& e : fs::directory_iterator(dir + "/" + bucket + "/tmp", ec))
            out.push_back(e.path().filename().string());
        return out;
    }

    // ── Multipart, each step on the shard a client happened to land on ─────
    std::string mpu_create(uint32_t s, const std::string& bucket, const std::string& key,
                           checksum_algo algo = checksum_algo::none)
    {
        std::string id;
        st got = st::io_error;
        bool fired = false;
        m[s]->node->mpu_create(bucket, key, {}, algo, [&](st r, std::string i) { got = r; id = i; fired = true; });
        REQUIRE(until([&] { return fired; }));
        REQUIRE(got == st::ok);
        return id;
    }

    // Asks the upload's owner first, as the runtime does, and writes into the data file where it is given a place.
    st mpu_put_part(uint32_t s, const std::string& bucket, const std::string& key, const std::string& id,
                    uint32_t number, const std::string& body, part_place* given = nullptr)
    {
        st began = st::io_error;
        part_place place;
        bool asked = false;
        m[s]->node->mpu_begin(bucket, key, id, number, body.size(), true, [&](st r, checksum_algo, part_place p)
        {
            began = r;
            place = std::move(p);
            asked = true;
        });
        REQUIRE(until([&] { return asked; }));
        if (began != st::ok)
            return began;
        if (given)
            *given = place;
        object_meta meta;
        if (place.off)
            meta.extra.emplace_back(std::string(mpu_place_extra), encode_place(place.off));
        st why = st::ok;
        auto op = m[s]->store->begin_put(bucket, "mpu/" + id + "/" + std::to_string(number), std::move(meta),
                                         body.size(), true, why);
        if (!op)
            return why;
        op->set_committer(m[s]->node->mpu_part_committer(bucket, key, id, number));
        if (place.off)
            op->place_body(place.path, place.off, place.room);
        size_t off = 0;
        while (off < body.size() && !op->failed())
        {
            const size_t took = op->append(body.data() + off, std::min<size_t>(body.size() - off, 1u << 20));
            off += took;
            if (took == 0)
            {
                bool ready = false;
                op->on_ready([&] { ready = true; });
                if (!until([&] { return ready || op->failed(); }))
                    return st::io_error;
            }
        }
        put_result out;
        bool fired = false;
        op->finish(nullptr, [&](put_result r) { out = std::move(r); fired = true; });
        REQUIRE(until([&] { return fired; }, 30000));
        return out.status;
    }

    complete_result mpu_complete(uint32_t s, const std::string& bucket, const std::string& key, const std::string& id,
                                 const std::vector<std::pair<uint32_t, std::string>>& parts)
    {
        std::vector<complete_part> list;
        for (const auto& [n, body] : parts)
        {
            complete_part cp;
            cp.number = n;
            cp.etag   = hex(md5_of(body));
            list.push_back(cp);
        }
        complete_result out;
        bool fired = false;
        m[s]->node->mpu_complete(bucket, key, id, std::move(list), [] {}, [&](complete_result r) { out = std::move(r); fired = true; });
        REQUIRE(until([&] { return fired; }, 60000));
        return out;
    }

    std::vector<wire::upload_stub> mpu_list(uint32_t s, const std::string& bucket)
    {
        std::vector<wire::upload_stub> out;
        bool fired = false;
        m[s]->node->mpu_list(bucket, [&](st r, std::vector<wire::upload_stub> v) { REQUIRE(r == st::ok); out = std::move(v); fired = true; });
        REQUIRE(until([&] { return fired; }));
        return out;
    }

    bool mpu_abort(uint32_t s, const std::string& bucket, const std::string& key, const std::string& id)
    {
        bool found = false, fired = false;
        m[s]->node->mpu_abort(bucket, key, id, [&](bool f) { found = f; fired = true; });
        REQUIRE(until([&] { return fired; }));
        return found;
    }

    parts_page mpu_parts(uint32_t s, const std::string& bucket, const std::string& key, const std::string& id,
                         uint32_t marker = 0, uint32_t max = 1000)
    {
        parts_page pg;
        bool fired = false;
        m[s]->node->mpu_parts(bucket, key, id, marker, max, [&](parts_page p) { pg = std::move(p); fired = true; });
        REQUIRE(until([&] { return fired; }));
        return pg;
    }

    uint64_t objects_held() const
    {
        uint64_t total = 0;
        for (const auto& mb : m)
            total += mb->store->totals().objects;
        return total;
    }
};

// A page's entries as one sorted name list, prefixes and objects together.
std::vector<std::string> names_of(const list_page& p)
{
    std::vector<std::string> out;
    for (const auto& e : p.objects)
        out.push_back(e.key);
    for (const auto& c : p.prefixes)
        out.push_back(c);
    std::sort(out.begin(), out.end());
    return out;
}

// Every page of one query, each as (names, truncated), following resume points.
std::vector<std::pair<std::vector<std::string>, bool>> pages_of(
    const std::function<st(const list_query&, list_page&)>& list, list_query q)
{
    std::vector<std::pair<std::vector<std::string>, bool>> out;
    for (int i = 0; i < 2000; ++i)
    {
        list_page p;
        REQUIRE(list(q, p) == st::ok);
        out.emplace_back(names_of(p), p.truncated);
        if (!p.truncated)
            break;
        q.has_resume = true;
        q.resume_at  = p.resume_at;
    }
    return out;
}

// The directory copied, for a second reading of the same files.
std::string copy_dir(const std::string& from)
{
    char tmpl[] = "/tmp/socketley-shards-copy-XXXXXX";
    std::string to = ::mkdtemp(tmpl);
    std::error_code ec;
    fs::copy(from, to, fs::copy_options::recursive, ec);
    REQUIRE_FALSE(ec);
    return to;
}

std::vector<std::string> tmp_files(const std::string& dir, const std::string& bucket)
{
    std::vector<std::string> out;
    std::error_code ec;
    for (const auto& e : fs::directory_iterator(dir + "/" + bucket + "/tmp", ec))
        out.push_back(e.path().filename().string());
    std::sort(out.begin(), out.end());
    return out;
}

}   // namespace

TEST_CASE("the owner of a key is the cache's slot function over bucket/key")
{
    // Pinned to the function a client can compute, not to a table that would
    // agree with whatever the code did.
    CHECK(object_slot("bucket", "key") == cache_slot_of("bucket/key"));
    CHECK(object_slot("media", "a/b/c.jpg") == cache_slot_of("media/a/b/c.jpg"));
    for (uint32_t n : {1u, 2u, 3u, 4u, 8u})
        for (const char* k : {"a", "dir/file", "x y", "\xff\xfe"})
            CHECK(object_owner("bkt", k, n) == cache_shard_of_slot(cache_slot_of(std::string("bkt/") + k), n));

    // One shard owns everything, and four share a spread of keys evenly enough.
    for (int i = 0; i < 100; ++i)
        CHECK(object_owner("bkt", "k" + std::to_string(i), 1) == 0);
    std::map<uint32_t, int> spread;
    for (int i = 0; i < 4000; ++i)
        ++spread[object_owner("bkt", "key-" + std::to_string(i), 4)];
    REQUIRE(spread.size() == 4);
    for (const auto& [shard, count] : spread)
        CHECK(count > 800);
}

TEST_CASE("a put through any shard is committed by the key's owner and read from every shard")
{
    tmpdir d;
    cluster c(d.path, 4);
    REQUIRE(c.make_bucket(2, "bkt") == st::ok);
    // Every shard holds the bucket, whichever one was asked to make it.
    for (uint32_t s = 0; s < 4; ++s)
        CHECK(c.m[s]->store->has_bucket("bkt"));
    CHECK(c.make_bucket(3, "bkt") == st::bucket_exists);

    std::map<std::string, std::string> bodies;
    for (int i = 0; i < 60; ++i)
    {
        const std::string key = "obj/" + std::to_string(i);
        bodies[key] = pattern(500 + i * 137, i);
        // Landed on a shard that is the owner for some keys and not for others.
        const uint32_t landing = static_cast<uint32_t>(i) % 4;
        REQUIRE(c.put(landing, "bkt", key, bodies[key]).status == st::ok);
    }

    uint64_t crossed = 0;
    for (const auto& [key, body] : bodies)
    {
        const uint32_t owner = object_owner("bkt", key, 4);
        // Held by its owner and by nobody else.
        for (uint32_t s = 0; s < 4; ++s)
            CHECK((c.m[s]->store->find("bkt", key) != nullptr) == (s == owner));
        // And served, whole, by all four.
        for (uint32_t s = 0; s < 4; ++s)
        {
            std::string got;
            object_meta gm;
            REQUIRE(c.get(s, "bkt", key, got, &gm) == st::ok);
            CHECK(got == body);
            CHECK(gm.md5 == md5_of(body));
            object_meta sm;
            REQUIRE(c.stat(s, "bkt", key, sm) == st::ok);
            CHECK(sm == gm);
        }
    }
    for (uint32_t s = 0; s < 4; ++s)
        crossed += c.m[s]->node->counters().commits_out;
    CHECK(crossed > 0);
    CHECK(crossed < 60);
    CHECK(c.objects_held() == 60);

    // Nothing is left in tmp/, and each shard's journal names only its own keys.
    CHECK(tmp_files(d.path, "bkt").empty());
    c.stop(true);
    cluster again(d.path, 4);
    CHECK(again.objects_held() == 60);
    for (uint32_t s = 0; s < 4; ++s)
        for (const auto& [key, body] : bodies)
            CHECK((again.m[s]->store->find("bkt", key) != nullptr) == (s == object_owner("bkt", key, 4)));
}

TEST_CASE("a delete through any shard removes the object for all of them")
{
    tmpdir d;
    cluster c(d.path, 4);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    for (int i = 0; i < 24; ++i)
        REQUIRE(c.put(static_cast<uint32_t>(i) % 4, "bkt", "k" + std::to_string(i), "body" + std::to_string(i)).status == st::ok);

    for (int i = 0; i < 24; ++i)
    {
        const std::string key = "k" + std::to_string(i);
        bool existed = false;
        REQUIRE(c.del(static_cast<uint32_t>(i + 1) % 4, "bkt", key, &existed) == st::ok);
        CHECK(existed);
        for (uint32_t s = 0; s < 4; ++s)
        {
            std::string got;
            CHECK(c.get(s, "bkt", key, got) == st::no_such_key);
        }
        bool again = true;
        REQUIRE(c.del(static_cast<uint32_t>(i) % 4, "bkt", key, &again) == st::ok);
        CHECK_FALSE(again);
    }
    CHECK(c.objects_held() == 0);

    // The journals agree after a restart: nothing comes back.
    c.stop(true);
    cluster back(d.path, 4);
    CHECK(back.objects_held() == 0);
}

TEST_CASE("a commit or a delete is answered only after every sibling has dropped its copy of the key")
{
    tmpdir d;
    cluster c(d.path, 4);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    const std::string keep = "keep", key = "k";
    const uint32_t owner = object_owner("bkt", key, 4);
    const std::string v1 = pattern(3000, 1);
    REQUIRE(c.put(0, "bkt", keep, "kept").status == st::ok);
    REQUIRE(c.put(1, "bkt", key, v1).status == st::ok);

    auto warm_all = [&](const std::string& k)
    {
        for (uint32_t s = 0; s < 4; ++s)
            if (s != object_owner("bkt", k, 4))
                REQUIRE(c.warm(s, "bkt", k));
        CHECK(c.copies("bkt", k) == 3);
    };
    warm_all(key);
    warm_all(keep);

    // An overwrite, landed on the owner and on each of the others in turn.
    for (uint32_t landing = 0; landing < 4; ++landing)
    {
        const std::string v = pattern(2500 + landing, 10 + landing);
        REQUIRE(c.put(landing, "bkt", key, v).status == st::ok);
        // Nothing is still on its way to a sibling when the client is answered.
        CHECK(c.queue.empty());
        CHECK(c.copies("bkt", key) == 0);
        // The other key was not touched.
        CHECK(c.copies("bkt", keep) == 3);
        warm_all(key);
        for (uint32_t s = 0; s < 4; ++s)
            if (s != owner)
            {
                std::string body;
                REQUIRE(c.held(s, "bkt", key, &body));
                CHECK(body == v);
            }
    }

    // A delete landed on each shard.
    for (uint32_t landing = 0; landing < 4; ++landing)
    {
        REQUIRE(c.put(0, "bkt", key, pattern(900, 40 + landing)).status == st::ok);
        warm_all(key);
        REQUIRE(c.del(landing, "bkt", key) == st::ok);
        CHECK(c.queue.empty());
        CHECK(c.copies("bkt", key) == 0);
    }

    // A create-only put that lost changes nothing, so nothing is dropped for it.
    REQUIRE(c.put(2, "bkt", key, "first", true).status == st::ok);
    warm_all(key);
    CHECK(c.put(3, "bkt", key, "second", true).status == st::precondition_failed);
    CHECK(c.copies("bkt", key) == 3);

    // Every crossing was counted on both sides.
    uint64_t out = 0, in = 0;
    for (uint32_t s = 0; s < 4; ++s)
    {
        out += c.m[s]->node->counters().hot_drops_out;
        in += c.m[s]->node->counters().hot_drops_in;
    }
    CHECK(out == in);
    CHECK(in > 0);
}

namespace {

uint64_t drops_sent(cluster& c)
{
    uint64_t n = 0;
    for (uint32_t s = 0; s < c.n; ++s)
        n += c.m[s]->node->counters().hot_drops_out;
    return n;
}

}   // namespace

// A key of the same bucket in the same slot as `key`, and one in another slot owned by the same shard.
static std::string same_slot(const std::string& bucket, const std::string& key, bool same)
{
    const uint32_t slot = object_slot(bucket, key), owner = object_owner(bucket, key, 4);
    for (int i = 0;; ++i)
    {
        const std::string k = "other" + std::to_string(i);
        if (same ? object_slot(bucket, k) == slot : object_slot(bucket, k) != slot && object_owner(bucket, k, 4) == owner)
            return k;
    }
}

TEST_CASE("a change is dropped only on the siblings that read from its slot, and on none for a slot nobody read")
{
    tmpdir d;
    cluster c(d.path, 4);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    const std::string key = "k", near = same_slot("bkt", key, true), far = same_slot("bkt", key, false);
    const uint32_t owner = object_owner("bkt", key, 4);
    const uint32_t a = (owner + 1) % 4, b = (owner + 2) % 4;

    // Writes landed on every shard of a key no sibling has read cross only to commit.
    for (uint32_t landing = 0; landing < 4; ++landing)
        REQUIRE(c.put(landing, "bkt", key, pattern(3000, landing)).status == st::ok);
    REQUIRE(c.del(a, "bkt", key) == st::ok);
    CHECK(drops_sent(c) == 0);

    // One sibling reads it, and only that one is told of the next change, wherever it lands, and of every one after.
    REQUIRE(c.put(owner, "bkt", key, pattern(3000, 7)).status == st::ok);
    REQUIRE(c.warm(a, "bkt", key));
    CHECK(c.m[owner]->node->holders(object_slot("bkt", key)) == uint64_t{1} << a);
    REQUIRE(c.put(b, "bkt", key, pattern(3000, 8)).status == st::ok);
    CHECK(drops_sent(c) == 1);
    CHECK(c.copies("bkt", key) == 0);
    REQUIRE(c.put(b, "bkt", key, pattern(3000, 9)).status == st::ok);
    CHECK(drops_sent(c) == 2);

    // Another key of the slot is kept without asking and dropped like the first; one of another slot is told to nobody.
    REQUIRE(c.put(owner, "bkt", near, pattern(3000, 10)).status == st::ok);
    CHECK(drops_sent(c) == 3);
    const uint64_t asked = c.m[a]->node->counters().hot_holds_out;
    REQUIRE(c.warm(a, "bkt", near));
    CHECK(c.m[a]->node->counters().hot_holds_out == asked);
    REQUIRE(c.put(b, "bkt", near, pattern(3000, 11)).status == st::ok);
    CHECK(drops_sent(c) == 4);
    CHECK(c.copies("bkt", near) == 0);
    REQUIRE(c.put(owner, "bkt", far, pattern(3000, 12)).status == st::ok);
    CHECK(drops_sent(c) == 4);

    // Two readers, and a delete landed on one of them drops both.
    REQUIRE(c.warm(a, "bkt", key));
    REQUIRE(c.warm(b, "bkt", key));
    REQUIRE(c.del(a, "bkt", key) == st::ok);
    CHECK(drops_sent(c) == 6);
    CHECK(c.copies("bkt", key) == 0);
    std::string body;
    CHECK(c.get(b, "bkt", key, body) == st::no_such_key);

    // An owner that started again is asked again before a copy of its keys is kept.
    REQUIRE(c.put(owner, "bkt", key, pattern(3000, 13)).status == st::ok);
    c.m[a]->store->hot_forget_owner(owner);
    const uint64_t before = c.m[a]->node->counters().hot_holds_out;
    REQUIRE(c.warm(a, "bkt", key));
    CHECK(c.m[a]->node->counters().hot_holds_out == before + 1);
}

TEST_CASE("a change made while a drop of the key is on its way is answered only after that sibling has dropped it")
{
    tmpdir d;
    cluster c(d.path, 4);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    const std::string key = "k";
    const uint32_t owner = object_owner("bkt", key, 4);
    const uint32_t reader = (owner + 1) % 4;
    // A put that takes a file from the pool answers before its syncs, so the next put of the key starts before its
    // drops are answered; the first puts make the pool.
    for (unsigned i = 0; i < 3; ++i)
    {
        bool filled = false;
        auto fill = c.begin(owner, "bkt", key, pattern(3000, 1), false, [&](put_result) { filled = true; }, {}, true);
        REQUIRE(c.until([&] { return filled; }));
        c.settle();
    }
    REQUIRE(c.warm(reader, "bkt", key));

    // The reader's drops are kept back while two puts from the pool land on the owner, one behind the other.
    c.hold_back = [&](const cluster::task& t)
    {
        wire::op o{};
        return t.peer == reader && wire::request_op(t.payload, o) && o == wire::op::hot_drop;
    };
    bool one = false, two = false;
    auto p1 = c.begin(owner, "bkt", key, pattern(3000, 2), false, [&](put_result r) { CHECK(r.status == st::ok); one = true; }, {}, true);
    auto p2 = c.begin(owner, "bkt", key, pattern(3000, 3), false, [&](put_result r) { CHECK(r.status == st::ok); two = true; }, {}, true);
    c.until([&] { return one || two; }, 500);
    // Neither may be answered while the reader still answers the version both replaced.
    CHECK_FALSE(one);
    CHECK_FALSE(two);
    REQUIRE(c.held(reader, "bkt", key));

    c.release();
    REQUIRE(c.until([&] { return one && two; }));
    CHECK_FALSE(c.held(reader, "bkt", key));
}

TEST_CASE("until its siblings have answered its start, an owner drops a change on every one of them")
{
    tmpdir d;
    cluster c(d.path, 4, 0, false);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    REQUIRE(c.put(1, "bkt", "k", pattern(3000, 1)).status == st::ok);
    CHECK(drops_sent(c) == 3);
    const uint32_t owner = object_owner("bkt", "k", 4);
    bool all = false;
    c.m[owner]->node->announce_start([&](bool ok) { all = ok; });
    c.settle();
    REQUIRE(all);
    REQUIRE(c.put(1, "bkt", "k", pattern(3000, 2)).status == st::ok);
    CHECK(drops_sent(c) == 3);
}

TEST_CASE("a sibling keeps nothing of a version its owner had replaced by the time it asked")
{
    tmpdir d;
    cluster c(d.path, 4);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    const uint32_t owner = object_owner("bkt", "k", 4);
    const uint32_t reader = (owner + 1) % 4;
    REQUIRE(c.put(0, "bkt", "k", pattern(3000, 1)).status == st::ok);

    // The reader is no holder, so the overwrite tells it nothing and the epoch cannot catch the old read.
    const uint64_t epoch = c.m[reader]->store->hot_epoch();
    std::string old_body;
    object_meta old_meta;
    REQUIRE(c.get(reader, "bkt", "k", old_body, &old_meta) == st::ok);
    REQUIRE(c.put(2, "bkt", "k", pattern(3000, 2)).status == st::ok);
    REQUIRE(drops_sent(c) == 0);
    REQUIRE(c.m[reader]->store->hot_epoch() == epoch);
    c.m[reader]->store->hot_put_foreign("bkt", "k", epoch, old_meta, old_body);
    c.settle();
    CHECK_FALSE(c.held(reader, "bkt", "k"));
    // Nor of one deleted while it was being read.
    REQUIRE(c.warm(reader, "bkt", "k"));
    const uint64_t before_delete = c.m[reader]->store->hot_epoch();
    std::string cur_body;
    object_meta cur_meta;
    REQUIRE(c.get(reader, "bkt", "k", cur_body, &cur_meta) == st::ok);
    REQUIRE(c.del(3, "bkt", "k") == st::ok);
    CHECK_FALSE(c.held(reader, "bkt", "k"));
    c.m[reader]->store->hot_put_foreign("bkt", "k", before_delete, cur_meta, cur_body);
    c.settle();
    CHECK_FALSE(c.held(reader, "bkt", "k"));

    // A read of another key of the slot that began before the reader was dropped for the slot still asks, and is refused.
    const std::string near = same_slot("bkt", "k", true);
    REQUIRE(c.put(0, "bkt", near, pattern(3000, 3)).status == st::ok);
    tmpdir d2;
    cluster c2(d2.path, 4);
    REQUIRE(c2.make_bucket(0, "bkt") == st::ok);
    REQUIRE(c2.put(0, "bkt", "k", pattern(3000, 4)).status == st::ok);
    REQUIRE(c2.put(0, "bkt", near, pattern(3000, 5)).status == st::ok);
    const uint64_t early = c2.m[reader]->store->hot_epoch();
    std::string near_body;
    object_meta near_meta;
    REQUIRE(c2.get(reader, "bkt", near, near_body, &near_meta) == st::ok);
    REQUIRE(c2.put(2, "bkt", near, pattern(3000, 6)).status == st::ok);
    REQUIRE(c2.warm(reader, "bkt", "k"));
    REQUIRE(drops_sent(c2) == 0);
    c2.m[reader]->store->hot_put_foreign("bkt", near, early, near_meta, near_body);
    c2.settle();
    CHECK_FALSE(c2.held(reader, "bkt", near));
}

TEST_CASE("a read of the old file that ends after the overwrite was answered is not kept")
{
    tmpdir d;
    cluster c(d.path, 4);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    const uint32_t owner = object_owner("bkt", "k", 4);
    const uint32_t reader = (owner + 1) % 4;
    const std::string v1 = pattern(3000, 1), v2 = pattern(3000, 2);
    REQUIRE(c.put(0, "bkt", "k", v1).status == st::ok);

    // The reader has begun and read the old file...
    const uint64_t epoch = c.m[reader]->store->hot_epoch();
    std::string old_body;
    object_meta old_meta;
    REQUIRE(c.get(reader, "bkt", "k", old_body, &old_meta) == st::ok);
    CHECK(old_body == v1);
    // ...the overwrite is answered...
    REQUIRE(c.put(0, "bkt", "k", v2).status == st::ok);
    // ...and only then does the read end.
    c.m[reader]->store->hot_put_foreign("bkt", "k", epoch, old_meta, old_body);
    c.settle();
    CHECK_FALSE(c.held(reader, "bkt", "k"));
    // The next read keeps the new version.
    REQUIRE(c.warm(reader, "bkt", "k"));
    std::string body;
    REQUIRE(c.held(reader, "bkt", "k", &body));
    CHECK(body == v2);
}

TEST_CASE("a stat of another shard's key reads its header once and never answers a version its owner replaced")
{
    tmpdir d;
    cluster c(d.path, 4);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    // One object too big to be held whole, and one small enough.
    for (const std::string key : {"big", "small"})
    {
        const uint32_t owner = object_owner("bkt", key, 4);
        const size_t size = key == "big" ? object_store::hot_max_object + 5000 : 3000;
        REQUIRE(c.put(0, "bkt", key, pattern(size, 1)).status == st::ok);

        auto meta_held = [&](uint32_t s)
        {
            object_store::hot_hit hit;
            return c.m[s]->store->hot_find("bkt", key, hit) && hit.foreign && !hit.body;
        };
        auto stat_all = [&](uint64_t size_now)
        {
            for (uint32_t s = 0; s < 4; ++s)
            {
                object_meta meta;
                REQUIRE(c.stat(s, "bkt", key, meta) == st::ok);
                CHECK(meta.size == size_now);
                if (s != owner)
                    CHECK(meta_held(s));
            }
        };
        stat_all(size);

        // An overwrite landed anywhere is what every shard's next stat says.
        for (uint32_t landing = 0; landing < 4; ++landing)
        {
            const size_t next = size + 1 + landing;
            REQUIRE(c.put(landing, "bkt", key, pattern(next, 10 + landing)).status == st::ok);
            for (uint32_t s = 0; s < 4; ++s)
                CHECK_FALSE(meta_held(s));
            stat_all(next);
        }

        // A GET of a small object takes the place of its metadata with the whole copy.
        const uint32_t reader = (owner + 1) % 4;
        if (key == "small")
        {
            REQUIRE(c.warm(reader, "bkt", key));
            object_meta meta;
            REQUIRE(c.stat(reader, "bkt", key, meta) == st::ok);
            CHECK(c.held(reader, "bkt", key));
        }

        // A stat whose read ends after an overwrite was answered is not kept.
        const uint64_t epoch = c.m[reader]->store->hot_epoch();
        object_meta old;
        REQUIRE(c.stat(owner, "bkt", key, old) == st::ok);
        REQUIRE(c.put(owner, "bkt", key, pattern(size + 9, 30)).status == st::ok);
        c.m[reader]->store->hot_put_foreign("bkt", key, epoch, old, {});
        c.settle();
        object_meta now;
        REQUIRE(c.stat(reader, "bkt", key, now) == st::ok);
        CHECK(now.size == size + 9);

        // And a delete is what every shard's next stat says.
        REQUIRE(c.del((owner + 2) % 4, "bkt", key) == st::ok);
        for (uint32_t s = 0; s < 4; ++s)
        {
            object_meta gone;
            CHECK(c.stat(s, "bkt", key, gone) == st::no_such_key);
            CHECK_FALSE(meta_held(s));
        }
    }
    // What the copies of metadata were charged is given back when they go.
    for (uint32_t s = 0; s < 4; ++s)
        CHECK(c.m[s]->store->hot_bytes() == 0);
}

TEST_CASE("a sibling that cannot be reached does not stop a commit or a delete from being answered")
{
    tmpdir d;
    cluster c(d.path, 3);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    std::string key;
    for (int i = 0; key.empty(); ++i)
        if (object_owner("bkt", "obj" + std::to_string(i), 3) == 0)
            key = "obj" + std::to_string(i);
    REQUIRE(c.put(0, "bkt", key, "one").status == st::ok);
    REQUIRE(c.warm(1, "bkt", key));
    REQUIRE(c.warm(2, "bkt", key));

    c.unreachable.insert(2);
    uint64_t failed = c.m[0]->node->counters().peer_failures;
    CHECK(c.put(0, "bkt", key, "two").status == st::ok);
    CHECK(c.m[0]->node->counters().peer_failures > failed);
    // The sibling that could be told has dropped it; the one that could not is what a restart would empty.
    CHECK_FALSE(c.held(1, "bkt", key));
    failed = c.m[0]->node->counters().peer_failures;
    CHECK(c.del(0, "bkt", key) == st::ok);
    CHECK(c.m[0]->node->counters().peer_failures > failed);
    c.unreachable.clear();
    CHECK(c.put(1, "bkt", key, "three").status == st::ok);
}

TEST_CASE("the same key put at once through every shard never tears and every shard serves the winner")
{
    tmpdir d;
    cluster c(d.path, 4);
    REQUIRE(c.make_bucket(1, "bkt") == st::ok);

    constexpr int rounds = 12;
    constexpr int writers = 16;
    for (int round = 0; round < rounds; ++round)
    {
        std::vector<std::string> bodies;
        std::vector<std::shared_ptr<put_op>> ops;
        int done = 0;
        for (int w = 0; w < writers; ++w)
            bodies.push_back(pattern(9000 + static_cast<size_t>(w) * 977, static_cast<unsigned>(round * 100 + w)));
        for (int w = 0; w < writers; ++w)
            ops.push_back(c.begin(static_cast<uint32_t>(w) % 4, "bkt", "contended", bodies[static_cast<size_t>(w)], false,
                                  [&](put_result r) { CHECK(r.status == st::ok); ++done; }));
        REQUIRE(c.until([&] { return done == writers; }));

        // One object, whole, that is one of the bodies, and the same for all.
        std::string first;
        object_meta first_meta;
        for (uint32_t s = 0; s < 4; ++s)
        {
            std::string got;
            object_meta gm;
            REQUIRE(c.get(s, "bkt", "contended", got, &gm) == st::ok);
            CHECK(md5_of(got) == gm.md5);
            CHECK(std::find(bodies.begin(), bodies.end(), got) != bodies.end());
            if (s == 0)
            {
                first      = got;
                first_meta = gm;
            }
            else
            {
                CHECK(got == first);
                CHECK(gm == first_meta);
            }
        }
        // The owner's memory names the same winner as the file.
        const object_meta* held = c.m[object_owner("bkt", "contended", 4)]->store->find("bkt", "contended");
        REQUIRE(held != nullptr);
        CHECK(*held == first_meta);
    }
    CHECK(c.objects_held() == 1);
    CHECK(tmp_files(d.path, "bkt").empty());
}

TEST_CASE("a create-only put is refused by the owner when the key exists, and only one racing creator wins")
{
    tmpdir d;
    cluster c(d.path, 4);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);

    // Whichever shard is asked, an existing key is refused and stays as it was.
    REQUIRE(c.put(0, "bkt", "there", "first").status == st::ok);
    for (uint32_t s = 0; s < 4; ++s)
        CHECK(c.put(s, "bkt", "there", "second", true).status == st::precondition_failed);
    std::string got;
    REQUIRE(c.get(3, "bkt", "there", got) == st::ok);
    CHECK(got == "first");
    // The refused bodies' names are removed on the ring, a turn or two later.
    CHECK(c.tmp_empties("bkt"));

    // Sixteen creators of one new key, from every shard: exactly one succeeds.
    int ok = 0, refused = 0, done = 0;
    std::vector<std::shared_ptr<put_op>> ops;
    for (int w = 0; w < 16; ++w)
        ops.push_back(c.begin(static_cast<uint32_t>(w) % 4, "bkt", "new", "body" + std::to_string(w), true,
                              [&](put_result r)
                              {
                                  ++done;
                                  if (r.status == st::ok)
                                      ++ok;
                                  else if (r.status == st::precondition_failed)
                                      ++refused;
                              }));
    REQUIRE(c.until([&] { return done == 16; }));
    CHECK(ok == 1);
    CHECK(refused == 15);
    CHECK(c.tmp_empties("bkt"));
}

TEST_CASE("a copy whose source and destination belong to different shards commits at the destination's owner")
{
    tmpdir d;
    cluster c(d.path, 4);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);

    int checked = 0;
    for (int i = 0; i < 40 && checked < 12; ++i)
    {
        const std::string src = "src" + std::to_string(i);
        const std::string dst = "dst" + std::to_string(i);
        if (object_owner("bkt", src, 4) == object_owner("bkt", dst, 4))
            continue;
        const std::string body = pattern(70000 + i, i);
        REQUIRE(c.put(0, "bkt", src, body).status == st::ok);

        // Asked of a shard that owns neither.
        uint32_t landing = 0;
        while (landing == object_owner("bkt", src, 4) || landing == object_owner("bkt", dst, 4))
            ++landing;
        put_result out;
        bool fired = false;
        c.m[landing]->store->copy("bkt", src, "bkt", dst, {}, [&](put_result r) { out = std::move(r); fired = true; });
        REQUIRE(c.until([&] { return fired; }));
        REQUIRE(out.status == st::ok);

        for (uint32_t s = 0; s < 4; ++s)
        {
            std::string got;
            REQUIRE(c.get(s, "bkt", dst, got) == st::ok);
            CHECK(got == body);
        }
        CHECK(c.m[object_owner("bkt", dst, 4)]->store->find("bkt", dst) != nullptr);
        ++checked;
    }
    CHECK(checked == 12);
    CHECK(tmp_files(d.path, "bkt").empty());
}

TEST_CASE("a listing through any shard is the listing one shard would give, page for page")
{
    tmpdir d;
    std::string reference_dir;
    {
        cluster c(d.path, 4);
        REQUIRE(c.make_bucket(3, "bkt") == st::ok);
        int n = 0;
        for (int dir = 0; dir < 6; ++dir)
            for (int sub = 0; sub < 3; ++sub)
                for (int f = 0; f < 9; ++f)
                    REQUIRE(c.put(static_cast<uint32_t>(n++) % 4, "bkt",
                                  "dir" + std::to_string(dir) + "/sub" + std::to_string(sub) + "/file" + std::to_string(f),
                                  "x").status == st::ok);
        for (int t = 0; t < 40; ++t)
            REQUIRE(c.put(static_cast<uint32_t>(t) % 4, "bkt", "top" + std::to_string(t), "y").status == st::ok);
        // Names that sort between and around the prefixes above.
        for (const char* k : {"dir0", "dir0.txt", "dir1/", "dir1/sub0", "dir2/sub1/file", "a", "zzz", "dir5/sub2/file9x"})
            REQUIRE(c.put(0, "bkt", k, "z").status == st::ok);
        c.stop(true);
        reference_dir = copy_dir(d.path);
    }

    // The reference: one shard on a copy of the same files, which rebuilds its
    // journal from them because the copy's journals were written for four.
    cluster four(d.path, 4);
    cluster one(reference_dir, 1);
    REQUIRE(one.m[0]->report.objects == four.objects_held());
    CHECK(one.objects_held() == 6 * 3 * 9 + 40 + 8);

    struct query { const char* prefix; const char* delimiter; size_t max_keys; const char* start_after; };
    const std::vector<query> queries = {
        {"", "", 1000, ""},   {"", "", 7, ""},     {"", "/", 1000, ""},  {"", "/", 2, ""},
        {"", "/", 1, ""},     {"dir1/", "/", 2, ""}, {"dir1/", "", 10, ""}, {"dir2/sub1/", "/", 3, ""},
        {"top", "", 11, ""},  {"dir", "/", 4, ""},  {"dir", "", 5, "dir1/sub1/file4"},
        {"", "/", 3, "dir2/"}, {"", "sub", 6, ""},  {"dir3/", "sub", 2, ""}, {"nomatch", "", 10, ""},
    };
    int compared = 0;
    for (const query& qs : queries)
    {
        list_query q;
        q.prefix      = qs.prefix;
        q.delimiter   = qs.delimiter;
        q.max_keys    = qs.max_keys;
        q.start_after = qs.start_after;
        const auto expect = pages_of([&](const list_query& lq, list_page& p) { return one.list(0, "bkt", lq, p); }, q);
        for (uint32_t s = 0; s < 4; ++s)
        {
            const auto got = pages_of([&](const list_query& lq, list_page& p) { return four.list(s, "bkt", lq, p); }, q);
            INFO("prefix=" << qs.prefix << " delimiter=" << qs.delimiter << " max=" << qs.max_keys
                           << " after=" << qs.start_after << " shard=" << s);
            CHECK(got == expect);
            ++compared;
        }
    }
    CHECK(compared == static_cast<int>(queries.size()) * 4);
    CHECK(four.m[0]->node->counters().list_fanouts > 0);
    CHECK(one.m[0]->node->counters().list_fanouts == 0);
    std::error_code ec;
    fs::remove_all(reference_dir, ec);
}

TEST_CASE("merging pages keeps a prefix once and stops at the nearest shard that was cut short")
{
    auto page = [](std::vector<std::string> keys, std::vector<std::string> prefixes, bool truncated)
    {
        list_page p;
        for (auto& k : keys)
            p.objects.push_back({k, {}});
        p.prefixes  = std::move(prefixes);
        p.truncated = truncated;
        return p;
    };

    // The same prefix in two shards is one entry, and it counts once.
    {
        const auto m = wire::merge_pages({page({"a"}, {"p/"}, false), page({"b"}, {"p/"}, false)}, 10);
        CHECK(names_of(m) == std::vector<std::string>{"a", "b", "p/"});
        CHECK(m.prefixes.size() == 1);
        CHECK_FALSE(m.truncated);
    }
    // More entries than the page holds: truncated, resuming just after the last given.
    {
        const auto m = wire::merge_pages({page({"a", "c", "e"}, {}, false), page({"b", "d", "f"}, {}, false)}, 4);
        CHECK(names_of(m) == std::vector<std::string>{"a", "b", "c", "d"});
        CHECK(m.truncated);
        CHECK(m.resume_at == std::string("d") + '\0');
    }
    // After a prefix the next page begins past everything under it.
    {
        const auto m = wire::merge_pages({page({}, {"p/", "q/"}, false), page({"a"}, {"p/"}, false)}, 2);
        CHECK(names_of(m) == std::vector<std::string>{"a", "p/"});
        CHECK(m.truncated);
        CHECK(m.resume_at == "p0");
    }
    // A shard cut short is known only as far as its own last name: "c" from the
    // other shard is beyond it and is not used.
    {
        const auto m = wire::merge_pages({page({"a", "b"}, {}, true), page({"c", "d"}, {}, false)}, 10);
        CHECK(names_of(m) == std::vector<std::string>{"a", "b"});
        CHECK(m.truncated);
        CHECK(m.resume_at == std::string("b") + '\0');
    }
    // Nothing truncated and nothing over: the whole, not truncated.
    {
        const auto m = wire::merge_pages({page({"a"}, {}, false), page({}, {}, false)}, 1);
        CHECK(names_of(m) == std::vector<std::string>{"a"});
        CHECK_FALSE(m.truncated);
    }
}

TEST_CASE("a page is cut back to the bytes a reply may carry and says it was")
{
    // What a sibling receives of a page written to at most `max_bytes`.
    auto sent = [](const list_page& in, size_t max_bytes)
    {
        list_page out;
        st s = st::io_error;
        REQUIRE(wire::decode_page(wire::encode_page(st::ok, in, max_bytes), s, out));
        CHECK(s == st::ok);
        return out;
    };
    list_page whole_page;
    for (int i = 0; i < 100; ++i)
    {
        list_entry e;
        e.key = "key" + std::to_string(1000 + i);
        e.meta.content_type = std::string(200, 'x');
        whole_page.objects.push_back(std::move(e));
    }
    const list_page p = sent(whole_page, 4000);
    CHECK(p.objects.size() < 100);
    CHECK(p.objects.size() > 5);
    CHECK(p.truncated);
    CHECK(p.resume_at == "key" + std::to_string(1000 + p.objects.size()));

    // Objects and prefixes are counted in the order their names interleave, and cut at one name.
    list_page mixed;
    for (int i = 0; i < 60; ++i)
    {
        const std::string n = "k" + std::to_string(100 + i);
        if (i % 3 == 0)
        {
            mixed.prefixes.push_back(n + "/");
            continue;
        }
        list_entry e;
        e.key = n;
        e.meta.content_type = std::string(150, 'y');
        mixed.objects.push_back(std::move(e));
    }
    // A prefix costs 13 and an object 250, so k117 is the first name past 3000.
    mixed = sent(mixed, 3000);
    CHECK(mixed.truncated);
    CHECK(mixed.resume_at == "k117");
    CHECK(mixed.objects.size() == 11);
    CHECK(mixed.prefixes.size() == 6);
    CHECK(mixed.objects.back().key == "k116");
    CHECK(mixed.prefixes.back() == "k115/");

    // A page that fits keeps the end its walk gave it.
    list_page small = whole_page;
    small.objects.resize(3);
    small.truncated = true;
    small.resume_at = "key1003";
    const list_page kept = sent(small, 4000);
    CHECK(kept.objects.size() == 3);
    CHECK(kept.truncated);
    CHECK(kept.resume_at == "key1003");

    // And a page of every shard's that was cut merges without losing an entry.
    list_page whole;
    for (int i = 0; i < 100; ++i)
    {
        list_entry e;
        e.key = "key" + std::to_string(1000 + i);
        whole.objects.push_back(std::move(e));
    }
    const list_page cut = [&]
    {
        list_page c = whole;
        c.objects.resize(30);
        c.truncated = true;
        return c;
    }();
    const auto m = wire::merge_pages({cut, list_page{}}, 50);
    CHECK(m.objects.size() == 30);
    CHECK(m.truncated);
}

TEST_CASE("the wire forms round-trip and refuse what is not theirs")
{
    commit_request req;
    req.bucket   = "bkt";
    req.key      = "some/key";
    req.tmp_name = "1.abcdef";
    req.meta.size = 42;
    req.meta.md5  = md5_of("x");
    req.meta.content_type = "text/plain";
    req.meta.extra = {{"x-amz-meta-a", "b"}};
    req.cond.if_match = "\"abc\"";
    req.cond.if_none_match = "*";
    req.cause = change_cause::complete;
    req.who   = {"alice", "192.0.2.7"};
    const std::string enc = wire::encode_commit(req);
    commit_request back;
    REQUIRE(wire::decode_commit(enc, back));
    CHECK(back.bucket == req.bucket);
    CHECK(back.key == req.key);
    CHECK(back.tmp_name == req.tmp_name);
    CHECK(back.meta == req.meta);
    CHECK(back.cond.if_match == req.cond.if_match);
    CHECK(back.cond.if_none_match == "*");
    // The cause decides the event its owner sends, so one past the last is refused rather than guessed.
    CHECK(back.cause == change_cause::complete);
    // And who asked for it, which the event the owner sends names.
    CHECK(back.who.principal == "alice");
    CHECK(back.who.source_ip == "192.0.2.7");
    commit_request bad = req;
    bad.cause = static_cast<change_cause>(static_cast<uint8_t>(change_cause::lifecycle) + 1);
    commit_request junk_cause;
    CHECK_FALSE(wire::decode_commit(wire::encode_commit(bad), junk_cause));
    {
        std::string b, k, v, val;
        bool by = false;
        uint8_t what = 0;
        change_origin w;
        REQUIRE(wire::decode_remove(wire::encode_remove("bkt", "k", "", false, {"bob", "::1"}), b, k, &v, &by, &w));
        CHECK((w.principal == "bob" && w.source_ip == "::1"));
        REQUIRE(wire::decode_set_tags(wire::encode_set_tags("bkt", "k", "", "t", 0, false, {"anonymous", "10.0.0.1"}),
                                      b, k, v, val, &what, &by, &w));
        CHECK((w.principal == "anonymous" && w.source_ip == "10.0.0.1"));
    }
    wire::op o{};
    REQUIRE(wire::request_op(enc, o));
    CHECK(o == wire::op::commit);

    // A cut anywhere, a payload that is another protocol's, and a flipped byte.
    for (size_t cut = 0; cut < enc.size(); ++cut)
    {
        commit_request junk;
        CHECK_FALSE(wire::decode_commit(std::string_view(enc).substr(0, cut), junk));
    }
    CHECK_FALSE(wire::request_op("*1\r\n$4\r\nPING\r\n", o));
    CHECK_FALSE(wire::request_op("", o));
    std::string flipped = enc;
    // A byte of the record, which ends before the cause and the origin's two strings.
    const size_t tail = 1 + 8 + req.who.principal.size() + req.who.source_ip.size();
    flipped[flipped.size() - tail - 5] ^= 0x10;
    commit_request junk;
    CHECK_FALSE(wire::decode_commit(flipped, junk));

    list_query q;
    q.prefix = "p/";
    q.delimiter = "/";
    q.start_after = "sa";
    q.resume_at = "ra";
    q.has_resume = true;
    q.max_keys = 77;
    list_query qb;
    std::string bucket;

    // A drop of a key, which no other op decodes.
    std::string dk;
    const std::string drop = wire::encode_hot_drop("bkt", "a/key");
    REQUIRE(wire::decode_hot_drop(drop, bucket, dk));
    CHECK(bucket == "bkt");
    CHECK(dk == "a/key");
    REQUIRE(wire::request_op(drop, o));
    CHECK(o == wire::op::hot_drop);
    CHECK_FALSE(wire::decode_remove(drop, bucket, dk));
    CHECK_FALSE(wire::decode_hot_drop(wire::encode_remove("bkt", "a/key"), bucket, dk));
    for (size_t cut = 0; cut < drop.size(); ++cut)
        CHECK_FALSE(wire::decode_hot_drop(std::string_view(drop).substr(0, cut), bucket, dk));

    // Holds asked together, each with the whole version read, and their answer a byte each.
    {
        std::vector<wire::hold_entry> asked(3);
        for (size_t i = 0; i < asked.size(); ++i)
        {
            asked[i].bucket = "bkt" + std::to_string(i);
            asked[i].key = "a/key" + std::to_string(i);
            asked[i].meta.size = 100 + i;
            asked[i].meta.mtime_ms = 1700000000000 + static_cast<int64_t>(i);
            asked[i].meta.content_type = "text/plain";
            asked[i].meta.extra = {{"x-amz-meta-n", std::to_string(i)}};
        }
        const std::string holds = wire::encode_hot_hold(2, asked.data(), asked.size());
        uint32_t from = 0;
        std::vector<wire::hold_entry> got;
        REQUIRE(wire::decode_hot_hold(holds, from, got));
        CHECK(from == 2);
        REQUIRE(got.size() == asked.size());
        for (size_t i = 0; i < got.size(); ++i)
        {
            CHECK(got[i].bucket == asked[i].bucket);
            CHECK(got[i].key == asked[i].key);
            CHECK(got[i].meta == asked[i].meta);
        }
        REQUIRE(wire::request_op(holds, o));
        CHECK(o == wire::op::hot_hold);
        for (size_t cut = 0; cut < holds.size(); ++cut)
            CHECK_FALSE(wire::decode_hot_hold(std::string_view(holds).substr(0, cut), from, got));
        CHECK_FALSE(wire::decode_hot_hold(holds + "x", from, got));
        CHECK_FALSE(wire::decode_hot_hold(wire::encode_hot_hold(2, asked.data(), 0), from, got));
        std::vector<uint8_t> held;
        REQUIRE(wire::decode_held(wire::encode_held({1, 0, 1}), held));
        CHECK(held == std::vector<uint8_t>{1, 0, 1});
        CHECK_FALSE(wire::decode_held(wire::encode_status(st::io_error), held));
    }

    REQUIRE(wire::decode_list(wire::encode_list("bkt", q), bucket, qb));
    CHECK(bucket == "bkt");
    CHECK(qb.prefix == q.prefix);
    CHECK(qb.delimiter == q.delimiter);
    CHECK(qb.start_after == q.start_after);
    CHECK(qb.resume_at == q.resume_at);
    CHECK(qb.has_resume);
    CHECK(qb.max_keys == 77);

    list_page page;
    page.truncated = true;
    page.resume_at = "r";
    page.prefixes  = {"a/", "b/"};
    list_entry e;
    e.key = "k";
    e.meta.size = 9;
    page.objects.push_back(e);
    st s{};
    list_page pb;
    const std::string pe = wire::encode_page(st::ok, page);
    REQUIRE(wire::decode_page(pe, s, pb));
    CHECK(s == st::ok);
    CHECK(pb.truncated);
    CHECK(pb.prefixes == page.prefixes);
    REQUIRE(pb.objects.size() == 1);
    CHECK(pb.objects[0].key == "k");
    for (size_t cut = 0; cut < pe.size(); ++cut)
    {
        list_page junk_page;
        st junk_st{};
        CHECK_FALSE(wire::decode_page(std::string_view(pe).substr(0, cut), junk_st, junk_page));
    }
}

TEST_CASE("a bucket made through one shard is on all of them and dropped from all of them")
{
    tmpdir d;
    cluster c(d.path, 3);
    REQUIRE(c.make_bucket(2, "shared") == st::ok);
    for (uint32_t s = 0; s < 3; ++s)
    {
        CHECK(c.m[s]->store->has_bucket("shared"));
        CHECK(c.m[s]->store->bucket_created_ms("shared") == c.m[0]->store->bucket_created_ms("shared"));
    }
    // Each shard has a journal of its own for it.
    for (uint32_t s = 0; s < 3; ++s)
        CHECK(fs::exists(d.path + "/shared/index." + std::to_string(s)));

    // A shard holding an object refuses the drop for everyone, wherever it was asked,
    // and the bucket is still whole and usable afterwards.
    // A key that a shard other than 0 owns, so that shard 0's own emptiness is not what refuses.
    std::string k = "k";
    for (int i = 0; object_owner("shared", k, 3) == 0; ++i)
        k = "k" + std::to_string(i);
    REQUIRE(c.put(1, "shared", k, "v").status == st::ok);
    for (uint32_t s = 0; s < 3; ++s)
        CHECK(c.drop_bucket(s, "shared") == st::bucket_not_empty);
    for (uint32_t s = 0; s < 3; ++s)
        CHECK(c.m[s]->store->has_bucket("shared"));
    REQUIRE(c.put(0, "shared", "k2", "v2").status == st::ok);
    REQUIRE(c.del(2, "shared", k) == st::ok);
    REQUIRE(c.del(1, "shared", "k2") == st::ok);

    REQUIRE(c.drop_bucket(1, "shared") == st::ok);
    for (uint32_t s = 0; s < 3; ++s)
        CHECK_FALSE(c.m[s]->store->has_bucket("shared"));
    CHECK_FALSE(fs::exists(d.path + "/shared"));
    CHECK(c.drop_bucket(2, "shared") == st::no_such_bucket);

    // And it can be made again from another shard.
    REQUIRE(c.make_bucket(1, "shared") == st::ok);
    REQUIRE(c.put(2, "shared", "again", "ok").status == st::ok);
    std::string got;
    REQUIRE(c.get(0, "shared", "again", got) == st::ok);
    CHECK(got == "ok");
}

TEST_CASE("a restart with a different shard count repartitions the keys and loses none")
{
    tmpdir d;
    std::map<std::string, std::string> bodies;
    {
        cluster c(d.path, 4);
        REQUIRE(c.make_bucket(0, "bkt") == st::ok);
        REQUIRE(c.make_bucket(1, "other") == st::ok);
        for (int i = 0; i < 80; ++i)
        {
            const std::string key = "k" + std::to_string(i);
            bodies[key] = pattern(100 + i, i);
            REQUIRE(c.put(static_cast<uint32_t>(i) % 4, i % 5 == 0 ? "other" : "bkt", key, bodies[key]).status == st::ok);
        }
        c.stop(true);
    }

    // 4 -> 2 -> 1 -> 3 -> 8 -> 4, each after a clean stop, each reading everything back from every shard.
    uint64_t expected = 80;
    for (uint32_t n : {2u, 1u, 3u, 8u, 4u})
    {
        cluster c(d.path, n);
        CHECK(c.objects_held() == expected);
        for (const auto& [key, body] : bodies)
        {
            const std::string bucket = key[0] == 'k' && std::stoi(key.substr(1)) % 5 == 0 ? "other" : "bkt";
            for (uint32_t s = 0; s < n; ++s)
            {
                std::string got;
                REQUIRE(c.get(s, bucket, key, got) == st::ok);
                CHECK(got == body);
                CHECK((c.m[s]->store->find(bucket, key) != nullptr) == (s == object_owner(bucket, key, n)));
            }
        }
        // A journal of a shard the split no longer has is not left to be trusted.
        for (uint32_t s = n; s < 8; ++s)
            CHECK_FALSE(fs::exists(d.path + "/bkt/index." + std::to_string(s)));
        // A write under the new split lands and survives the next one.
        const std::string key = "w" + std::to_string(n);
        bodies[key] = "written under " + std::to_string(n);
        REQUIRE(c.put(n - 1, "bkt", key, bodies[key]).status == st::ok);
        ++expected;
        c.stop(true);
    }
}

TEST_CASE("a restarted shard removes its own temporary files and no sibling's")
{
    tmpdir d;
    {
        cluster c(d.path, 3);
        REQUIRE(c.make_bucket(0, "bkt") == st::ok);
        c.stop(false);
    }
    const std::string tmp = d.path + "/bkt/tmp/";
    auto touch = [&](const std::string& name) { std::ofstream(tmp + name) << "x"; };
    touch("0.aaaa");   // shard 0's
    touch("1.bbbb");   // shard 1's, an upload it has in flight
    touch("2.cccc");   // shard 2's
    touch("7.dddd");   // a shard the split does not have
    touch("legacy");   // a name no shard gave it

    // Shard 1 restarts on its own, as the supervisor restarts one shard.
    {
        event_loop loop{256};
        REQUIRE(loop.init());
        struct h : io_handler { void on_cqe(struct io_uring_cqe*) override {} } handler;
        file_io io(loop, &handler);
        store_options o;
        o.dir = d.path;
        o.shard = 1;
        o.nshards = 3;
        object_store s(loop, io, o);
        std::string err;
        REQUIRE(s.open(err));
        CHECK(tmp_files(d.path, "bkt") == std::vector<std::string>{"0.aaaa", "2.cccc", "7.dddd", "legacy"});
        s.close(false);
    }
    // Shard 0 also clears what belongs to no shard of the split.
    {
        event_loop loop{256};
        REQUIRE(loop.init());
        struct h : io_handler { void on_cqe(struct io_uring_cqe*) override {} } handler;
        file_io io(loop, &handler);
        store_options o;
        o.dir = d.path;
        o.shard = 0;
        o.nshards = 3;
        object_store s(loop, io, o);
        std::string err;
        REQUIRE(s.open(err));
        CHECK(tmp_files(d.path, "bkt") == std::vector<std::string>{"2.cccc"});
        s.close(false);
    }
}

TEST_CASE("a listing fails whole when a shard cannot be reached, and a put whose owner is gone is refused and cleaned up")
{
    tmpdir d;
    cluster c(d.path, 3);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    for (int i = 0; i < 30; ++i)
        REQUIRE(c.put(0, "bkt", "k" + std::to_string(i), "v").status == st::ok);

    c.unreachable.insert(2);
    list_page page;
    CHECK(c.list(0, "bkt", {}, page) == st::io_error);

    // A key whose owner is the shard that cannot be reached.
    std::string victim;
    for (int i = 0; victim.empty(); ++i)
        if (object_owner("bkt", "gone" + std::to_string(i), 3) == 2)
            victim = "gone" + std::to_string(i);
    CHECK(c.put(0, "bkt", victim, "body").status == st::io_error);
    CHECK(c.tmp_empties("bkt"));

    c.unreachable.clear();
    CHECK(c.put(0, "bkt", victim, "body").status == st::ok);
    CHECK(c.list(1, "bkt", {}, page) == st::ok);
    CHECK(page.objects.size() == 31);
}

TEST_CASE("a quota is an equal share for each shard")
{
    tmpdir d;
    // 4 MiB over four shards is a MiB each, so one 700 KiB object fits and a second does not.
    cluster c(d.path, 4, 4u << 20);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    const std::string big = pattern(700 * 1024, 5);
    int accepted = 0, refused = 0;
    // Every key is shard 1's and every put lands on shard 0, whose own bytes stay
    // empty, so only the owner can know that its share is used.
    for (int i = 0, made = 0; made < 8; ++i)
    {
        const std::string key = "big" + std::to_string(i);
        if (object_owner("bkt", key, 4) != 1)
            continue;
        ++made;
        const put_result r = c.put(0, "bkt", key, big);
        if (r.status == st::ok)
            ++accepted;
        else if (r.status == st::storage_full)
            ++refused;
    }
    CHECK(accepted == 1);
    CHECK(refused == 7);
    CHECK(c.tmp_empties("bkt"));
    for (const auto& mb : c.m)
        CHECK(mb->store->totals().bytes <= (1u << 20));
}

// ─── Multipart on a sharded runtime ─────────────────────────────────────────

namespace {

// A key the shard `want` owns in `bucket`, for a test that needs the owner and the shards around it.
std::string key_owned_by(const std::string& bucket, uint32_t want, uint32_t shards, const std::string& stem = "mp")
{
    for (int i = 0; i < 100000; ++i)
    {
        const std::string k = stem + std::to_string(i);
        if (object_owner(bucket, k, shards) == want)
            return k;
    }
    FAIL("no key");
    return {};
}

}   // namespace

TEST_CASE("an upload lives on the shard that owns its key and completes through any other")
{
    tmpdir d;
    cluster c(d.path, 4);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    const std::string key = key_owned_by("bkt", 2, 4);

    // Begun through shard 3, whose own store holds nothing of it.
    const std::string id = c.mpu_create(3, "bkt", key);
    CHECK(c.m[2]->mpu->find("bkt", id) != nullptr);
    for (uint32_t s : {0u, 1u, 3u})
        CHECK(c.m[s]->mpu->find("bkt", id) == nullptr);

    // Parts written where each connection landed, whichever shard that is.
    const std::string p1 = pattern(5u << 20, 1), p2 = pattern(5u << 20, 2), p3 = pattern(100000, 3);
    REQUIRE(c.mpu_put_part(0, "bkt", key, id, 1, p1) == st::ok);
    REQUIRE(c.mpu_put_part(1, "bkt", key, id, 2, p2) == st::ok);
    REQUIRE(c.mpu_put_part(2, "bkt", key, id, 3, p3) == st::ok);
    // A part of the same number again replaces it, from a fourth shard.
    REQUIRE(c.mpu_put_part(3, "bkt", key, id, 3, p3) == st::ok);

    const parts_page pg = c.mpu_parts(1, "bkt", key, id);
    REQUIRE(pg.status == st::ok);
    CHECK(pg.key == key);
    REQUIRE(pg.rows.size() == 3);
    CHECK(pg.rows[0].size == p1.size());
    CHECK(pg.rows[2].etag == hex(md5_of(p3)));
    // Pages of it.
    const parts_page first = c.mpu_parts(0, "bkt", key, id, 0, 2);
    CHECK(first.rows.size() == 2);
    CHECK(first.truncated);
    CHECK(first.next_marker == 2);
    const parts_page rest = c.mpu_parts(3, "bkt", key, id, first.next_marker, 2);
    REQUIRE(rest.rows.size() == 1);
    CHECK(rest.rows[0].number == 3);
    CHECK_FALSE(rest.truncated);
    // The wrong key names no upload, whoever is asked.
    CHECK(c.mpu_parts(1, "bkt", "elsewhere", id).status != st::ok);

    // Completed through shard 1, which reads the parts and writes the object; the key's owner commits it.
    const uint64_t out_before = c.m[1]->node->counters().commits_out;
    const complete_result done = c.mpu_complete(1, "bkt", key, id, {{1, p1}, {2, p2}, {3, p3}});
    REQUIRE(done.error.code.empty());
    CHECK(done.meta.parts == 3);
    CHECK(done.meta.size == p1.size() + p2.size() + p3.size());
    std::string md5s = std::string(reinterpret_cast<const char*>(md5_of(p1).data()), 16) +
                       std::string(reinterpret_cast<const char*>(md5_of(p2).data()), 16) +
                       std::string(reinterpret_cast<const char*>(md5_of(p3).data()), 16);
    CHECK(done.meta.etag() == hex(md5_of(md5s)) + "-3");
    CHECK(c.m[1]->node->counters().commits_out == out_before + 1);
    CHECK(c.m[2]->store->find("bkt", key) != nullptr);
    for (uint32_t s : {0u, 1u, 3u})
        CHECK(c.m[s]->store->find("bkt", key) == nullptr);

    std::string all = p1 + p2 + p3;
    for (uint32_t s = 0; s < 4; ++s)
    {
        std::string got;
        REQUIRE(c.get(s, "bkt", key, got) == st::ok);
        CHECK(got == all);
    }

    // The upload is gone from its owner, with its directory, and nothing is left in tmp/.
    CHECK(c.until([&] { return c.m[2]->mpu->find("bkt", id) == nullptr; }));
    CHECK(c.until([&] { return !fs::exists(d.path + "/bkt/mpu/" + id); }));
    CHECK(c.tmp_empties("bkt"));
    // Completing it again is NoSuchUpload, through any shard.
    for (uint32_t s : {0u, 2u, 3u})
        CHECK(c.mpu_complete(s, "bkt", key, id, {{1, p1}}).error.code == "NoSuchUpload");
}

TEST_CASE("a completion that fails on another shard opens the upload again, and a bad list is refused there")
{
    tmpdir d;
    cluster c(d.path, 3);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    const std::string key = key_owned_by("bkt", 1, 3);
    const std::string id = c.mpu_create(2, "bkt", key);
    const std::string p1 = pattern(5u << 20, 4), p2 = pattern(1000, 5);
    REQUIRE(c.mpu_put_part(0, "bkt", key, id, 1, p1) == st::ok);
    REQUIRE(c.mpu_put_part(2, "bkt", key, id, 2, p2) == st::ok);

    // A part the client never sent, a wrong ETag, a list out of order: each refused by the owner.
    CHECK(c.mpu_complete(0, "bkt", key, id, {{1, p1}, {9, p2}}).error.code == "InvalidPart");
    CHECK(c.mpu_complete(0, "bkt", key, id, {{1, p2}, {2, p2}}).error.code == "InvalidPart");
    CHECK(c.mpu_complete(0, "bkt", key, id, {{2, p2}, {1, p1}}).error.code == "InvalidPartOrder");
    // Each left the upload open, so the right list still completes it.
    const complete_result ok = c.mpu_complete(2, "bkt", key, id, {{1, p1}, {2, p2}});
    CHECK(ok.error.code.empty());
    std::string got;
    REQUIRE(c.get(0, "bkt", key, got) == st::ok);
    CHECK(got == p1 + p2);
}

TEST_CASE("an assembler that dies leaves the upload sealed only until it is opened again")
{
    tmpdir d;
    cluster c(d.path, 2);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    const std::string key = key_owned_by("bkt", 1, 2);
    const std::string id = c.mpu_create(0, "bkt", key);
    const std::string p1 = pattern(1000, 6);
    REQUIRE(c.mpu_put_part(0, "bkt", key, id, 1, p1) == st::ok);

    // The owner is asked to seal it for an assembler on shard 0, which then never answers.
    bool prepared = false;
    c.m[1]->mpu->prepare_complete("bkt", id, {complete_part{1, hex(md5_of(p1)), checksum_algo::none, {}}},
                                  [&](s3_error e, assemble_plan) { CHECK(e.code.empty()); prepared = true; }, true);
    REQUIRE(c.until([&] { return prepared; }));
    checksum_algo a = checksum_algo::none;
    CHECK(c.m[1]->mpu->begin_part("bkt", id, a) != st::ok);
    // Not yet: the assembler may still be working.
    c.m[1]->mpu->unseal_stale(0);
    CHECK(c.m[1]->mpu->begin_part("bkt", id, a) != st::ok);
    c.m[1]->mpu->unseal_stale(static_cast<int64_t>(c.m[1]->store->now_ms()) + 1000);
    CHECK(c.m[1]->mpu->begin_part("bkt", id, a) == st::ok);
}

TEST_CASE("a listing of uploads is every shard's, and a bucket with one anywhere is not dropped")
{
    tmpdir d;
    cluster c(d.path, 4);
    REQUIRE(c.make_bucket(1, "bkt") == st::ok);

    std::vector<std::pair<std::string, std::string>> made;
    for (int i = 0; i < 12; ++i)
    {
        const std::string key = "up/" + std::to_string(i);
        made.emplace_back(key, c.mpu_create(static_cast<uint32_t>(i) % 4, "bkt", key));
    }
    std::vector<std::string> want;
    for (const auto& [k, id] : made)
        want.push_back(k + "/" + id);
    std::sort(want.begin(), want.end());
    // Held by more than one shard, and listed whole by every one.
    int holders = 0;
    for (uint32_t s = 0; s < 4; ++s)
        holders += c.m[s]->mpu->uploads_of("bkt").empty() ? 0 : 1;
    CHECK(holders >= 2);
    for (uint32_t s = 0; s < 4; ++s)
    {
        std::vector<std::string> got;
        for (const auto& u : c.mpu_list(s, "bkt"))
            got.push_back(u.key + "/" + u.id);
        std::sort(got.begin(), got.end());
        CHECK(got == want);
    }

    // No object in the bucket: a drop through any shard takes the open uploads of every shard with it, as in S3.
    CHECK(c.drop_bucket(1, "bkt") == st::ok);
    for (uint32_t s = 0; s < 4; ++s)
    {
        CHECK_FALSE(c.m[s]->store->has_bucket("bkt"));
        CHECK(c.m[s]->mpu->uploads_of("bkt").empty());
        CHECK(c.m[s]->mpu->totals().uploads == 0);
    }
    CHECK_FALSE(c.mpu_abort(0, "bkt", made[0].first, made[0].second));
}

TEST_CASE("a part whose owner cannot be reached is refused and its temporary file removed")
{
    tmpdir d;
    cluster c(d.path, 3);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    const std::string key = key_owned_by("bkt", 2, 3);
    const std::string id = c.mpu_create(0, "bkt", key);
    c.unreachable.insert(2);
    CHECK(c.mpu_put_part(0, "bkt", key, id, 1, pattern(2000, 7)) == st::io_error);
    CHECK(c.tmp_empties("bkt"));
    c.unreachable.clear();
    CHECK(c.mpu_put_part(0, "bkt", key, id, 1, pattern(2000, 7)) == st::ok);
    CHECK(c.mpu_parts(1, "bkt", key, id).rows.size() == 1);
}

TEST_CASE("uploads are found again by the shard that owns their key after a restart, whatever the count")
{
    tmpdir d;
    std::vector<std::pair<std::string, std::string>> made;
    const std::string p1 = pattern(5u << 20, 8), p2 = pattern(2000, 9);
    {
        cluster c(d.path, 4);
        REQUIRE(c.make_bucket(0, "bkt") == st::ok);
        for (int i = 0; i < 8; ++i)
        {
            const std::string key = "held/" + std::to_string(i);
            const std::string id = c.mpu_create(static_cast<uint32_t>(i) % 4, "bkt", key);
            REQUIRE(c.mpu_put_part(static_cast<uint32_t>(i + 1) % 4, "bkt", key, id, 1, p1) == st::ok);
            REQUIRE(c.mpu_put_part(static_cast<uint32_t>(i + 2) % 4, "bkt", key, id, 2, p2) == st::ok);
            made.emplace_back(key, id);
        }
        c.stop(true);
    }
    for (uint32_t n : {2u, 3u, 1u, 4u})
    {
        cluster c(d.path, n);
        int total = 0;
        for (const auto& [key, id] : made)
        {
            const uint32_t owner = object_owner("bkt", key, n);
            for (uint32_t s = 0; s < n; ++s)
                CHECK((c.m[s]->mpu->find("bkt", id) != nullptr) == (s == owner));
            const parts_page pg = c.mpu_parts(static_cast<uint32_t>(total) % n, "bkt", key, id);
            REQUIRE(pg.status == st::ok);
            CHECK(pg.rows.size() == 2);
            ++total;
        }
        c.stop(true);
    }
    // And one of them completes, in the split the last round left.
    cluster c(d.path, 4);
    const auto& [key, id] = made[3];
    const complete_result done = c.mpu_complete(1, "bkt", key, id, {{1, p1}, {2, p2}});
    CHECK(done.error.code.empty());
    std::string got;
    REQUIRE(c.get(2, "bkt", key, got) == st::ok);
    CHECK(got == p1 + p2);
}

TEST_CASE("a restarted shard leaves a sibling's upload being made alone, and removes one that was never made")
{
    tmpdir d;
    {
        cluster c(d.path, 2);
        REQUIRE(c.make_bucket(0, "bkt") == st::ok);
        c.stop(true);
    }
    // A directory with no meta file yet is another shard's upload being made this moment.
    fs::create_directories(d.path + "/bkt/mpu/0123456789abcdef0123456789abcdef");
    {
        cluster c(d.path, 2);
        CHECK(fs::exists(d.path + "/bkt/mpu/0123456789abcdef0123456789abcdef"));
        c.stop(true);
    }
    // At one shard there is nobody it could be, and it is removed as it always was.
    {
        cluster c(d.path, 1);
        CHECK_FALSE(fs::exists(d.path + "/bkt/mpu/0123456789abcdef0123456789abcdef"));
    }
}

TEST_CASE("parts written in place through any shard become the object without a copy, completed through another")
{
    tmpdir d;
    cluster c(d.path, 4);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    const std::string key = key_owned_by("bkt", 2, 4, "inplace");
    const std::string id = c.mpu_create(3, "bkt", key);
    const uint64_t base = c.m[2]->mpu->find("bkt", id)->place_base;

    // Each part through another shard, and the owner says where each goes.
    const size_t P = 5u << 20;
    const std::string p1 = pattern(P, 41), p2 = pattern(P, 42), p3 = pattern(P, 43), p4 = pattern(4321, 44);
    const std::vector<std::pair<uint32_t, const std::string*>> parts = {{3, &p3}, {1, &p1}, {4, &p4}, {2, &p2}};
    uint32_t via = 0;
    for (const auto& [n, body] : parts)
    {
        part_place g;
        REQUIRE(c.mpu_put_part(via++ % 4, "bkt", key, id, n, *body, &g) == st::ok);
        CHECK(g.off == base + (n - 1) * P);
    }
    // A second upload of a number through yet another shard is not given its place again.
    part_place again;
    REQUIRE(c.mpu_put_part(1, "bkt", key, id, 2, p2, &again) == st::ok);
    CHECK(again.off == 0);
    REQUIRE(c.mpu_put_part(0, "bkt", key, id, 2, p2, &again) == st::ok);
    CHECK(again.off == 0);
    // So part 2 is in its own file now, and the completion copies.
    CHECK(!c.m[2]->mpu->find("bkt", id)->parts.at(2).in_place);

    const std::string id2 = c.mpu_create(0, "bkt", key);
    via = 1;
    for (const auto& [n, body] : parts)
        REQUIRE(c.mpu_put_part(via++ % 4, "bkt", key, id2, n, *body) == st::ok);
    struct stat sb{};
    REQUIRE(::stat((d.path + "/bkt/mpu/" + id2 + "/data").c_str(), &sb) == 0);
    const ino_t data_ino = sb.st_ino;

    // Completed through shard 1, which links the data file and has the key's owner commit it.
    const complete_result done = c.mpu_complete(1, "bkt", key, id2, {{1, p1}, {2, p2}, {3, p3}, {4, p4}});
    REQUIRE(done.error.code.empty());
    CHECK(done.meta.parts == 4);
    struct stat ob{};
    REQUIRE(::stat((d.path + "/bkt/data/" + object_rel_path(key)).c_str(), &ob) == 0);
    CHECK(ob.st_ino == data_ino);
    for (uint32_t s = 0; s < 4; ++s)
    {
        std::string got;
        REQUIRE(c.get(s, "bkt", key, got) == st::ok);
        CHECK(got == p1 + p2 + p3 + p4);
    }
    CHECK(c.until([&] { return !fs::exists(d.path + "/bkt/mpu/" + id2); }));

    // The first upload, whose part 2 was sent again, completes by copying through shard 3.
    const complete_result done1 = c.mpu_complete(3, "bkt", key, id, {{1, p1}, {2, p2}, {3, p3}, {4, p4}});
    REQUIRE(done1.error.code.empty());
    REQUIRE(::stat((d.path + "/bkt/data/" + object_rel_path(key)).c_str(), &ob) == 0);
    CHECK(ob.st_ino != data_ino);
    std::string got;
    REQUIRE(c.get(2, "bkt", key, got) == st::ok);
    CHECK(got == p1 + p2 + p3 + p4);
    CHECK(c.tmp_empties("bkt"));
}

TEST_CASE("the wire carries a part's place and a plan made without a copy")
{
    wire::mpu_ref ref{"bkt", "k", std::string(32, 'a'), 7, 0, true, 5ull << 30};
    wire::mpu_ref back;
    REQUIRE(wire::decode_mpu_ref(wire::encode_mpu_ref(wire::op::mpu_begin, ref), wire::op::mpu_begin, back));
    CHECK(back.a == 7);
    CHECK(back.flag);
    CHECK(back.size == 5ull << 30);

    // The upload's encryption record crosses with the place, so a part fed on another shard is sealed as its upload is.
    part_place place{4096 + (6ull << 30), 5u << 20, "ignored", "1;s3;65536;p;0a0b0c0d;" + std::string(80, 'Q')};
    st s = st::io_error;
    checksum_algo algo = checksum_algo::none;
    part_place got;
    const std::string enc = wire::encode_mpu_begin(st::ok, checksum_algo::crc32c, place);
    REQUIRE(wire::decode_mpu_begin(enc, s, algo, got));
    CHECK(s == st::ok);
    CHECK(algo == checksum_algo::crc32c);
    CHECK(got.off == place.off);
    CHECK(got.room == place.room);
    CHECK(got.path.empty());
    CHECK(got.sse == place.sse);
    for (size_t cut = 0; cut < enc.size(); ++cut)
        CHECK_FALSE(wire::decode_mpu_begin(std::string_view(enc).substr(0, cut), s, algo, got));

    assemble_plan plan;
    plan.bucket = "bkt";
    plan.id     = std::string(32, 'b');
    plan.key    = "k";
    plan.in_place = true;
    mpu_part p;
    p.number   = 1;
    p.size     = 5u << 20;
    p.data_off = 8192;
    p.in_place = true;
    plan.parts.push_back(p);
    s3_error err;
    assemble_plan pb;
    const std::string pe = wire::encode_mpu_plan({}, plan);
    REQUIRE(wire::decode_mpu_plan(pe, err, pb));
    CHECK(err.code.empty());
    CHECK(pb.in_place);
    REQUIRE(pb.parts.size() == 1);
    CHECK(pb.parts[0].in_place);
    CHECK(pb.parts[0].data_off == 8192);
    for (size_t cut = 0; cut < pe.size(); ++cut)
        CHECK_FALSE(wire::decode_mpu_plan(std::string_view(pe).substr(0, cut), err, pb));
}

TEST_CASE("a lifecycle configuration put through any shard is synced by shard 0 and held by every shard")
{
    tmpdir d;
    auto doc = [](const std::string& id, const std::string& prefix, int days)
    {
        return "<LifecycleConfiguration><Rule><ID>" + id + "</ID><Filter><Prefix>" + prefix +
               "</Prefix></Filter><Status>Enabled</Status><Expiration><Days>" + std::to_string(days) +
               "</Days></Expiration></Rule></LifecycleConfiguration>";
    };
    auto set = [](cluster& c, uint32_t s, bucket_doc kind, const std::string& xml)
    {
        st got = st::io_error;
        bool fired = false;
        c.m[s]->node->set_doc(kind, "bkt", xml, [&](st r) { got = r; fired = true; });
        REQUIRE(c.until([&] { return fired; }));
        return got;
    };
    auto rule_id = [](cluster& c, uint32_t s) -> std::string
    {
        const auto cfg = c.m[s]->store->lifecycle("bkt");
        return cfg ? cfg->rules.at(0).id : std::string("none");
    };

    cluster c(d.path, 3);
    REQUIRE(c.make_bucket(1, "bkt") == st::ok);
    // Answered only once every shard has it, so nothing is settled before looking.
    REQUIRE(set(c, 2, bucket_doc::lifecycle, doc("first", "a/", 3)) == st::ok);
    for (uint32_t s = 0; s < 3; ++s)
        CHECK(rule_id(c, s) == "first");
    CHECK(fs::exists(d.path + "/bkt/lifecycle"));
    CHECK_FALSE(fs::exists(d.path + "/bkt/lifecycle.new"));

    // Two changes asked at once through different shards end the same everywhere, in the order shard 0 took them.
    bool f1 = false, f2 = false;
    c.m[1]->node->set_doc(bucket_doc::lifecycle, "bkt", doc("second", "b/", 4), [&](st) { f1 = true; });
    c.m[2]->node->set_doc(bucket_doc::lifecycle, "bkt", doc("third", "c/", 5), [&](st) { f2 = true; });
    REQUIRE(c.until([&] { return f1 && f2; }));
    const std::string last = rule_id(c, 0);
    CHECK((last == "second" || last == "third"));
    for (uint32_t s = 1; s < 3; ++s)
        CHECK(rule_id(c, s) == last);

    // A CORS document beside it is a document of its own, and a document that does not parse is not taken.
    REQUIRE(set(c, 1, bucket_doc::cors,
                "<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod>"
                "</CORSRule></CORSConfiguration>") == st::ok);
    for (uint32_t s = 0; s < 3; ++s)
    {
        CHECK(c.m[s]->store->bucket_cors("bkt") != nullptr);
        CHECK(rule_id(c, s) == last);
    }
    CHECK(c.m[2]->store->adopt_doc(bucket_doc::lifecycle, "bkt", "<NotLifecycle/>") == st::io_error);
    CHECK(rule_id(c, 2) == last);

    // A removal through a shard other than 0 reaches every shard and the disk, and leaves the other document.
    REQUIRE(set(c, 2, bucket_doc::lifecycle, "") == st::ok);
    for (uint32_t s = 0; s < 3; ++s)
    {
        CHECK(rule_id(c, s) == "none");
        CHECK(c.m[s]->store->bucket_cors("bkt") != nullptr);
    }
    CHECK_FALSE(fs::exists(d.path + "/bkt/lifecycle"));

    // What is synced is what every shard reads at its next start, however many there are.
    REQUIRE(set(c, 0, bucket_doc::lifecycle, doc("kept", "k/", 6)) == st::ok);
    c.restart(2);
    for (uint32_t s = 0; s < 2; ++s)
    {
        CHECK(rule_id(c, s) == "kept");
        CHECK(c.m[s]->store->lifecycle_buckets() == 1);
        CHECK(c.m[s]->store->bucket_cors("bkt") != nullptr);
    }
    // And a bucket that is dropped takes both with it.
    REQUIRE(set(c, 1, bucket_doc::cors, "") == st::ok);
    REQUIRE(c.drop_bucket(1, "bkt") == st::ok);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    for (uint32_t s = 0; s < 2; ++s)
    {
        CHECK(rule_id(c, s) == "none");
        CHECK(c.m[s]->store->lifecycle_buckets() == 0);
        CHECK_FALSE(c.m[s]->store->any_cors());
    }
}

TEST_CASE("a document change is answered only once no shard can go on with the old one")
{
    tmpdir d;
    const std::string p1 = R"({"Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::bkt/one/*"}})";
    const std::string p2 = R"({"Statement":{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::bkt/*"}})";
    const std::string p3 = R"({"Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::bkt/three/*"}})";
    auto start_set = [](cluster& c, uint32_t s, const std::string& doc, st& got, bool& fired)
    {
        fired = false;
        c.m[s]->node->set_doc(bucket_doc::policy, "bkt", doc, [&](st r) { got = r; fired = true; });
    };
    auto set = [&](cluster& c, uint32_t s, const std::string& doc)
    {
        st got = st::io_error;
        bool fired = false;
        start_set(c, s, doc, got, fired);
        REQUIRE(c.until([&] { return fired; }));
        return got;
    };
    auto text = [](cluster& c, uint32_t s) -> std::string
    {
        const bucket_policy* p = c.m[s]->store->policy("bkt");
        return p ? p->text() : std::string("none");
    };
    auto on_disk = [&](const std::string& file) -> std::string
    {
        std::ifstream f(d.path + "/bkt/" + file);
        if (!f)
            return "none";
        return std::string(std::istreambuf_iterator<char>(f), {});
    };

    cluster c(d.path, 3);
    REQUIRE(c.make_bucket(1, "bkt") == st::ok);
    REQUIRE(set(c, 1, p1) == st::ok);
    for (uint32_t s = 0; s < 3; ++s)
    {
        CHECK(c.m[s]->store->docs_settled("bkt"));
        CHECK(text(c, s) == p1);
    }

    // A shard that cannot be told the change may happen makes it fail, and nothing changes anywhere.
    c.unreachable = {2};
    CHECK(set(c, 1, p2) == st::unavailable);
    CHECK(set(c, 0, "") == st::unavailable);
    c.unreachable.clear();
    // The word that the change was abandoned is not waited for, and settles the shard that promised when it lands.
    c.settle();
    for (uint32_t s = 0; s < 3; ++s)
    {
        CHECK(text(c, s) == p1);
        CHECK_FALSE(c.m[s]->store->any_doubt());
    }
    CHECK(on_disk("policy") == p1);
    CHECK(on_disk("policy.new") == "none");

    // A shard that promised and never heard the change was abandoned waits, then settles on the file as it is.
    c.fault = [](uint32_t peer, wire::op o)
    {
        return (peer == 2 && o == wire::op::doc_prepare) || (peer == 1 && o == wire::op::doc_abort) ? 1 : 0;
    };
    CHECK(set(c, 0, p2) == st::unavailable);
    c.fault = nullptr;
    CHECK(c.m[1]->store->any_doubt());
    CHECK(c.m[1]->store->docs_settled("bkt"));
    CHECK_FALSE(c.m[1]->store->any_doubt());
    CHECK(text(c, 1) == p1);

    // A shard that misses the change being made still holds the old copy, and settles on the new one before serving.
    c.fault = [](uint32_t peer, wire::op o) { return peer == 2 && o == wire::op::doc_adopt ? 1 : 0; };
    CHECK(set(c, 1, p2) == st::ok);
    c.fault = nullptr;
    CHECK(text(c, 0) == p2);
    CHECK(text(c, 1) == p2);
    CHECK(c.m[2]->store->any_doubt());
    CHECK(text(c, 2) == p1);
    CHECK(c.m[2]->store->docs_settled("bkt"));
    CHECK(text(c, 2) == p2);

    // Between its promise and the outcome a shard serves nothing of the bucket, and the outcome lets it go.
    st got = st::io_error;
    bool fired = false;
    c.fault = [](uint32_t peer, wire::op o) { return peer == 1 && o == wire::op::doc_prepare ? 2 : 0; };
    start_set(c, 0, p3, got, fired);
    REQUIRE(c.until([&] { return c.m[2]->store->any_doubt(); }));
    c.settle();
    CHECK_FALSE(fired);
    CHECK(on_disk("policy.new") == p3);
    CHECK_FALSE(c.m[2]->store->docs_settled("bkt"));
    CHECK(c.m[1]->store->docs_settled("bkt"));
    c.fault = nullptr;
    c.release_held();
    REQUIRE(c.until([&] { return fired; }));
    CHECK(got == st::ok);
    for (uint32_t s = 0; s < 3; ++s)
    {
        CHECK_FALSE(c.m[s]->store->any_doubt());
        CHECK(text(c, s) == p3);
    }

    // A removal is decided the same way.
    c.fault = [](uint32_t peer, wire::op o) { return peer == 1 && o == wire::op::doc_adopt ? 1 : 0; };
    CHECK(set(c, 2, "") == st::ok);
    c.fault = nullptr;
    CHECK(c.m[1]->store->docs_settled("bkt"));
    for (uint32_t s = 0; s < 3; ++s)
        CHECK(text(c, s) == "none");
    CHECK(on_disk("policy") == "none");
    CHECK(on_disk("policy.new") == "none");
}

TEST_CASE("a shard that takes a bucket up late reads the documents it already has before serving it")
{
    tmpdir d;
    const std::string doc = R"({"Statement":{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::bkt/*"}})";
    cluster c(d.path, 3);
    c.unreachable = {2};
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    c.unreachable.clear();
    CHECK_FALSE(c.m[2]->store->has_bucket("bkt"));
    bool fired = false;
    st got = st::io_error;
    c.m[1]->node->set_doc(bucket_doc::policy, "bkt", doc, [&](st r) { got = r; fired = true; });
    REQUIRE(c.until([&] { return fired; }));
    CHECK(got == st::ok);
    // Asked to make the bucket, shard 2 learns it is there and takes it up.
    CHECK(c.make_bucket(2, "bkt") == st::bucket_exists);
    REQUIRE(c.m[2]->store->has_bucket("bkt"));
    CHECK(c.m[2]->store->any_doubt());
    CHECK(c.m[2]->store->docs_settled("bkt"));
    const bucket_policy* p = c.m[2]->store->policy("bkt");
    REQUIRE(p != nullptr);
    CHECK(p->text() == doc);
}

TEST_CASE("a stored policy that no longer compiles refuses every request at every shard")
{
    tmpdir d;
    {
        cluster c(d.path, 2);
        REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    }
    {
        std::ofstream f(d.path + "/bkt/policy");
        f << R"({"Statement":{"Effect":"Deny","NotPrincipal":{"AWS":"k"},"Action":"s3:*","Resource":"arn:aws:s3:::bkt/*"}})";
    }
    cluster c(d.path, 2);
    for (uint32_t s = 0; s < 2; ++s)
    {
        CHECK(c.m[s]->store->docs_settled("bkt"));
        const bucket_policy* p = c.m[s]->store->policy("bkt");
        REQUIRE(p != nullptr);
        CHECK(p->broken().find("NotPrincipal") != std::string::npos);
        CHECK(p->has_deny());
        CHECK_FALSE(p->is_public());
        policy_request r;
        r.action    = s3_action::get_object;
        r.key       = "a";
        r.principal = "k";
        CHECK(p->evaluate(r) == policy_effect::deny);
        r.anonymous = true;
        CHECK(p->evaluate(r) == policy_effect::deny);
    }
    // Replaced through the keys, the bucket is open again.
    bool fired = false;
    st got = st::io_error;
    const std::string good = R"({"Statement":{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::bkt/*"}})";
    c.m[1]->node->set_doc(bucket_doc::policy, "bkt", good, [&](st r) { got = r; fired = true; });
    REQUIRE(c.until([&] { return fired; }));
    CHECK(got == st::ok);
    for (uint32_t s = 0; s < 2; ++s)
        CHECK(c.m[s]->store->policy("bkt")->broken().empty());
}

TEST_CASE("a conditional delete keeps an object its condition refuses, decided under the key's lane")
{
    tmpdir d;
    cluster c(d.path, 1);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    REQUIRE(c.put(0, "bkt", "k", "v").status == st::ok);
    auto remove_if = [&](bool verdict)
    {
        bool existed = true, fired = false;
        st got = st::io_error;
        c.m[0]->store->remove_local("bkt", "k", [&](st r, bool e) { got = r; existed = e; fired = true; },
                                    [verdict](const object_meta&) { return verdict; });
        REQUIRE(c.until([&] { return fired; }));
        CHECK(got == st::ok);
        return existed;
    };
    CHECK_FALSE(remove_if(false));
    std::string body;
    CHECK(c.get(0, "bkt", "k", body) == st::ok);
    CHECK(remove_if(true));
    CHECK(c.get(0, "bkt", "k", body) == st::no_such_key);
}

TEST_CASE("a lifecycle day is rounded up to the next boundary, which for a real day is midnight UTC")
{
    // 2026-01-01T10:30:00Z with Days 1 is due at 2026-01-03T00:00:00Z.
    const int64_t written = 1767263400000;
    CHECK(lifecycle_due_ms(written, 1, lifecycle_day_ms) == 1767398400000);
    // A write exactly at midnight is due exactly N days later.
    CHECK(lifecycle_due_ms(1767225600000, 2, lifecycle_day_ms) == 1767225600000 + 2 * lifecycle_day_ms);
    lifecycle_rule r;
    r.enabled     = true;
    r.prefix      = "logs/";
    r.expire_days = 1;
    object_meta m;
    m.mtime_ms = written;
    CHECK(lifecycle_object_due(r, "logs/a", m, 1767398400000, lifecycle_day_ms));
    CHECK_FALSE(lifecycle_object_due(r, "logs/a", m, 1767398399999, lifecycle_day_ms));
    CHECK_FALSE(lifecycle_object_due(r, "other/a", m, 1767398400000, lifecycle_day_ms));
    r.enabled = false;
    CHECK_FALSE(lifecycle_object_due(r, "logs/a", m, 1767398400000, lifecycle_day_ms));
}

TEST_CASE("a lifecycle filter by tags and size matches what S3's does, and is written back as it came")
{
    s3_error err;
    lifecycle_config c;
    const std::string doc =
        "<LifecycleConfiguration><Rule><ID>a</ID><Filter><And><Prefix>p/</Prefix>"
        "<Tag><Key>k</Key><Value>v</Value></Tag><Tag><Key>j</Key><Value></Value></Tag>"
        "<ObjectSizeGreaterThan>10</ObjectSizeGreaterThan><ObjectSizeLessThan>20</ObjectSizeLessThan>"
        "</And></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>"
        "<Rule><ID>t</ID><Filter><Tag><Key>only</Key><Value>1</Value></Tag></Filter><Status>Enabled</Status>"
        "<Expiration><Date>2020-01-01T00:00:00Z</Date></Expiration></Rule></LifecycleConfiguration>";
    REQUIRE(parse_lifecycle(doc, c, err));
    lifecycle_config again;
    REQUIRE(parse_lifecycle(lifecycle_xml(c), again, err));
    CHECK(lifecycle_xml(again) == lifecycle_xml(c));
    CHECK(lifecycle_xml(c).find("<Filter><And><Prefix>p/</Prefix><Tag><Key>k</Key><Value>v</Value></Tag>") !=
          std::string::npos);
    CHECK(lifecycle_xml(c).find("<Filter><Tag><Key>only</Key><Value>1</Value></Tag></Filter>") != std::string::npos);

    const lifecycle_rule& r = c.rules[0];
    const int64_t later = 1767398400000;
    auto obj = [](uint64_t size, std::string tags)
    {
        object_meta m;
        m.size = size;
        set_tags_extra(m, tags);
        return m;
    };
    const std::string both = std::string("j\0\0k\0v\0", 7);
    CHECK(lifecycle_object_due(r, "p/x", obj(15, both), later, lifecycle_day_ms));
    CHECK_FALSE(lifecycle_object_due(r, "q/x", obj(15, both), later, lifecycle_day_ms));
    CHECK_FALSE(lifecycle_object_due(r, "p/x", obj(10, both), later, lifecycle_day_ms));
    CHECK_FALSE(lifecycle_object_due(r, "p/x", obj(20, both), later, lifecycle_day_ms));
    CHECK_FALSE(lifecycle_object_due(r, "p/x", obj(15, std::string("k\0v\0", 4)), later, lifecycle_day_ms));
    CHECK_FALSE(lifecycle_object_due(r, "p/x", obj(15, std::string("j\0\0k\0w\0", 7)), later, lifecycle_day_ms));
    CHECK_FALSE(lifecycle_object_due(r, "p/x", obj(15, ""), later, lifecycle_day_ms));
    CHECK(lifecycle_object_due(c.rules[1], "any", obj(0, std::string("only\0" "1\0", 7)), later, lifecycle_day_ms));
    CHECK_FALSE(lifecycle_object_due(c.rules[1], "any", obj(0, std::string("only\0" "2\0", 7)), later, lifecycle_day_ms));
}

TEST_CASE("a version tag is named by its owner, kept out of a path, and an unversioned object is its null version")
{
    CHECK(valid_version_id("null"));
    CHECK(valid_version_id(std::string(32, 'a')));
    CHECK_FALSE(valid_version_id(""));
    CHECK_FALSE(valid_version_id(std::string(32, 'A')));
    CHECK_FALSE(valid_version_id("../../data/ab/" + std::string(18, 'a')));
    CHECK_FALSE(valid_version_id(std::string(31, 'a') + "/"));

    object_meta m;
    m.mtime_ms = 1234;
    CHECK_FALSE(has_version(m));
    CHECK(version_of(m).id == "null");
    CHECK(version_of(m).seq == 1234000);
    CHECK_FALSE(is_delete_marker(m));

    version_tag t;
    t.seq    = 0x1122334455667788ull;
    t.id     = std::string(16, '0') + "0123456789abcdef";
    t.marker = true;
    set_version_extra(m, t);
    set_version_extra(m, t);
    CHECK(std::count_if(m.extra.begin(), m.extra.end(), [](const auto& e) { return e.first == version_extra; }) == 1);
    const version_tag back = version_of(m);
    CHECK(back.seq == t.seq);
    CHECK(back.id == t.id);
    CHECK(back.marker);
    CHECK(is_delete_marker(m));
    // Through the header, as a start reads it back.
    const decoded_header h = decode_object_header(encode_object_header("k", m));
    REQUIRE(h.status == header_status::ok);
    CHECK(version_of(h.meta).id == t.id);
    CHECK(version_rel_path("k", t.id) == "versions/" + key_hash("k").substr(0, 2) + "/" + key_hash("k") + "." + t.id);
    clear_version_extra(m);
    CHECK_FALSE(has_version(m));
}

TEST_CASE("the versioned wire forms round-trip, and merged version pages stop at the nearest shard cut short")
{
    put_result pr;
    pr.status = st::ok;
    version_tag t{77, std::string(32, 'c'), false};
    set_version_extra(pr.meta, t);
    put_result pb;
    REQUIRE(wire::decode_committed(wire::encode_committed(pr), pb));
    CHECK(pb.status == st::ok);
    CHECK(version_of(pb.meta).id == t.id);
    REQUIRE(wire::decode_committed(wire::encode_committed(put_result{st::busy, {}}), pb));
    CHECK(pb.status == st::busy);
    CHECK_FALSE(has_version(pb.meta));

    std::string bucket, key, id, tags;
    REQUIRE(wire::decode_remove(wire::encode_remove("bkt", "a/key", "null"), bucket, key, &id));
    CHECK((bucket == "bkt" && key == "a/key" && id == "null"));
    remove_result rr{st::ok, true, true, std::string(32, 'd')}, rb;
    REQUIRE(wire::decode_removed(wire::encode_removed(rr), rb));
    CHECK((rb.status == rr.status && rb.existed && rb.marker && rb.version_id == rr.version_id));
    REQUIRE(wire::decode_set_tags(wire::encode_set_tags("bkt", "k", "null", std::string("a\0b\0", 4)), bucket, key, id,
                                  tags));
    CHECK((id == "null" && tags == std::string("a\0b\0", 4)));
    st s = st::ok;
    REQUIRE(wire::decode_tagged(wire::encode_tagged(st::delete_marker, "null"), s, id));
    CHECK(s == st::delete_marker);

    version_query q;
    q.prefix = "p/";
    q.delimiter = "/";
    q.key_marker = "p/k";
    q.version_marker = std::string(32, 'e');
    q.max_keys = 9;
    version_query qb;
    const std::string lv = wire::encode_list_versions("bkt", q);
    REQUIRE(wire::decode_list_versions(lv, bucket, qb));
    CHECK((qb.prefix == q.prefix && qb.delimiter == q.delimiter && qb.key_marker == q.key_marker &&
           qb.version_marker == q.version_marker && qb.max_keys == 9));
    wire::op o{};
    REQUIRE(wire::request_op(lv, o));
    CHECK(o == wire::op::list_versions);
    for (size_t cut = 0; cut < lv.size(); ++cut)
        CHECK_FALSE(wire::decode_list_versions(std::string_view(lv).substr(0, cut), bucket, qb));

    auto item = [](const std::string& key, uint64_t seq, bool latest)
    {
        version_item it;
        it.key = key;
        it.meta.size = seq;
        set_version_extra(it.meta, {seq, std::string(16, '0') + std::string(16, static_cast<char>('0' + seq % 10)), false});
        it.latest = latest;
        return it;
    };
    version_page a, b;
    a.items = {item("a", 2, true), item("a", 1, false), item("c", 1, true)};
    b.items = {item("b", 1, true), item("d", 1, true), item("e", 1, true)};
    b.items.push_back({"p/", {}, false, true});
    a.items.push_back({"p/", {}, false, true});
    st ps = st::io_error;
    version_page back;
    REQUIRE(wire::decode_version_page(wire::encode_version_page(st::ok, a), ps, back));
    REQUIRE(back.items.size() == a.items.size());
    CHECK((back.items[1].key == "a" && !back.items[1].latest && version_of(back.items[1].meta).seq == 1));
    CHECK(back.items.back().prefix);

    // Whole pages: one sorted listing, the common prefix once.
    const version_page whole = wire::merge_version_pages({a, b}, 100);
    std::vector<std::string> keys;
    for (const auto& it : whole.items)
        keys.push_back(it.key);
    CHECK(keys == std::vector<std::string>{"a", "a", "b", "c", "d", "e", "p/"});
    CHECK_FALSE(whole.truncated);
    // A page cut short after "c" says nothing about what sorts after it, so the merge stops there.
    a.items.pop_back();
    a.truncated = true;
    const version_page cut = wire::merge_version_pages({a, b}, 100);
    CHECK(cut.items.size() == 4);
    CHECK(cut.items.back().key == "c");
    CHECK(cut.truncated);
    CHECK(wire::merge_version_pages({b}, 2).items.size() == 2);
    CHECK(wire::merge_version_pages({b}, 2).truncated);
}

TEST_CASE("the owner of a key writes nothing by a versioning it may hold an old copy of")
{
    tmpdir d;
    cluster c(d.path, 3);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    for (uint32_t s = 0; s < 3; ++s)
        REQUIRE(c.m[s]->store->docs_settled("bkt"));
    std::string key;
    for (int i = 0; key.empty(); ++i)
        if (object_owner("bkt", "k" + std::to_string(i), 3) == 2)
            key = "k" + std::to_string(i);
    const std::string enabled = "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";

    // Shard 2 promised and never heard: it holds "off", and settles on the file before it commits a write.
    c.fault = [](uint32_t peer, wire::op o) { return peer == 2 && o == wire::op::doc_adopt ? 1 : 0; };
    st got = st::io_error;
    bool fired = false;
    c.m[1]->node->set_doc(bucket_doc::versioning, "bkt", enabled, [&](st r) { got = r; fired = true; });
    REQUIRE(c.until([&] { return fired; }));
    c.fault = nullptr;
    REQUIRE(got == st::ok);
    CHECK(c.m[2]->store->bucket_versioning("bkt") == versioning::off);
    const put_result r = c.put(0, "bkt", key, "v1");
    REQUIRE(r.status == st::ok);
    CHECK(version_of(r.meta).id != "null");
    CHECK(c.m[2]->store->bucket_versioning("bkt") == versioning::enabled);

    // While a change is undecided the owner refuses the write, and the shard that took it answers so.
    c.fault = [](uint32_t peer, wire::op o) { return peer == 1 && o == wire::op::doc_prepare ? 2 : 0; };
    fired = false;
    c.m[0]->node->set_doc(bucket_doc::versioning, "bkt",
                          "<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>",
                          [&](st s) { got = s; fired = true; });
    REQUIRE(c.until([&] { return c.m[2]->store->any_doubt(); }));
    c.fault = nullptr;
    CHECK(c.put(0, "bkt", key, "v2").status == st::unavailable);
    c.release_held();
    REQUIRE(c.until([&] { return fired; }));
    CHECK(got == st::ok);
    const put_result r3 = c.put(0, "bkt", key, "v3");
    REQUIRE(r3.status == st::ok);
    CHECK(version_of(r3.meta).id == "null");
}

TEST_CASE("a key's versions through any shard: markers, removal for good, a listing, and a start from the files alone")
{
    tmpdir d;
    cluster c(d.path, 3);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    st got = st::io_error;
    bool fired = false;
    c.m[2]->node->set_doc(bucket_doc::versioning, "bkt",
                          "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
                          [&](st r) { got = r; fired = true; });
    REQUIRE(c.until([&] { return fired; }));
    REQUIRE(got == st::ok);
    for (uint32_t s = 0; s < 3; ++s)
        CHECK(c.m[s]->store->bucket_versioning("bkt") == versioning::enabled);
    CHECK(fs::is_directory(d.path + "/bkt/versions/ff"));

    const std::string key = "some/key";
    const uint32_t owner = object_owner("bkt", key, 3);
    std::vector<std::string> ids, bodies;
    for (uint32_t i = 0; i < 4; ++i)
    {
        bodies.push_back(pattern(100 + i, i + 1));
        const put_result r = c.put(i % 3, "bkt", key, bodies.back());
        REQUIRE(r.status == st::ok);
        ids.push_back(version_of(r.meta).id);
        CHECK(valid_version_id(ids.back()));
        CHECK(ids.back() != "null");
    }
    CHECK(std::set<std::string>(ids.begin(), ids.end()).size() == 4);

    auto read_version = [&](uint32_t s, const std::string& id, std::string& body) -> st
    {
        open_result r;
        bool done = false;
        c.m[s]->store->open_version("bkt", key, id, 0, [&](open_result o) { r = std::move(o); done = true; });
        REQUIRE(c.until([&] { return done; }));
        if (r.status != st::ok)
            return r.status;
        body.assign(r.meta.size, '\0');
        CHECK(::pread(r.fd, body.data(), body.size(), static_cast<off_t>(r.data_off)) == static_cast<ssize_t>(body.size()));
        ::close(r.fd);
        return st::ok;
    };
    auto remove = [&](uint32_t s, const std::string& id) -> remove_result
    {
        remove_result r;
        bool done = false;
        c.m[s]->store->remove_version("bkt", key, id, [&](remove_result o) { r = std::move(o); done = true; });
        REQUIRE(c.until([&] { return done; }));
        return r;
    };
    auto listing = [&](uint32_t s, size_t page) -> std::vector<std::pair<std::string, bool>>
    {
        std::vector<std::pair<std::string, bool>> out;
        version_query q;
        q.max_keys = page;
        for (;;)
        {
            version_page p;
            st ls = st::io_error;
            bool done = false;
            c.m[s]->node->list_versions("bkt", q, [&](st r, version_page pg) { ls = r; p = std::move(pg); done = true; });
            REQUIRE(c.until([&] { return done; }));
            REQUIRE(ls == st::ok);
            for (const auto& it : p.items)
                out.emplace_back(it.key + "#" + version_of(it.meta).id, it.latest);
            if (!p.truncated)
                return out;
            REQUIRE(!p.items.empty());
            q.key_marker     = p.items.back().key;
            q.version_marker = version_of(p.items.back().meta).id;
        }
    };

    for (uint32_t s = 0; s < 3; ++s)
        for (size_t i = 0; i < ids.size(); ++i)
        {
            std::string body;
            REQUIRE(read_version(s, ids[i], body) == st::ok);
            CHECK(body == bodies[i]);
        }

    // A marker through a shard that does not own the key, read by all of them as no such key.
    const uint32_t other = (owner + 1) % 3;
    const remove_result mk = remove(other, "");
    REQUIRE(mk.status == st::ok);
    CHECK(mk.marker);
    CHECK(c.m[owner]->store->find("bkt", key) == nullptr);
    REQUIRE(c.m[owner]->store->latest_marker("bkt", key) != nullptr);
    for (uint32_t s = 0; s < 3; ++s)
    {
        open_result r;
        bool done = false;
        c.m[s]->store->open_object("bkt", key, 0, [&](open_result o) { r = std::move(o); done = true; });
        REQUIRE(c.until([&] { return done; }));
        CHECK(r.status == st::no_such_key);
        CHECK(r.delete_marker);
        std::string body;
        CHECK(read_version(s, mk.version_id, body) == st::delete_marker);
    }

    // The marker removed is the key back; the latest removed for good is the one behind it.
    CHECK(remove(owner, mk.version_id).marker);
    std::string body;
    REQUIRE(c.get(other, "bkt", key, body) == st::ok);
    CHECK(body == bodies[3]);
    CHECK_FALSE(remove(other, ids[3]).marker);
    REQUIRE(c.get(other, "bkt", key, body) == st::ok);
    CHECK(body == bodies[2]);
    CHECK(remove(other, ids[0]).existed);
    CHECK(read_version(owner, ids[0], body) == st::no_such_version);
    CHECK(c.put(other, "bkt", "zz", "z").status == st::ok);
    REQUIRE(remove(owner, "").status == st::ok);

    const auto before = listing(1, 1000);
    REQUIRE(before.size() == 4);
    CHECK(before[0].second);
    CHECK_FALSE(before[1].second);
    CHECK(before.back().first.starts_with("zz#"));
    CHECK(listing(2, 1) == before);
    CHECK(listing(0, 2) == before);
    CHECK(c.drop_bucket(0, "bkt") == st::bucket_not_empty);

    // A crash with every journal gone: the files alone give the versions back in their order.
    c.stop(false);
    for (const auto& e : fs::recursive_directory_iterator(d.path))
        if (e.path().filename().string().starts_with("index."))
            fs::remove(e.path());
    c.start(3);
    CHECK(listing(0, 1000) == before);
    REQUIRE(c.m[owner]->store->latest_marker("bkt", key) != nullptr);
    CHECK(read_version(other, ids[2], body) == st::ok);
    CHECK(body == bodies[2]);
}

TEST_CASE("a bucket dropped while an upload it held is still removing its files waits for them and is dropped")
{
    for (const uint32_t shards : {1u, 2u})
    {
        INFO("shards " << shards);
        tmpdir d;
        cluster c(d.path, shards);
        REQUIRE(c.make_bucket(0, "bkt") == st::ok);
        const uint32_t owner = shards - 1;
        const std::string key = key_owned_by("bkt", owner, shards);
        const std::string id = c.mpu_create(0, "bkt", key);
        // Enough parts that removing them takes more than one turn of the ring.
        for (uint32_t n = 1; n <= 40; ++n)
            REQUIRE(c.mpu_put_part(0, "bkt", key, id, n, pattern(100, n)) == st::ok);

        // The upload is going away, as one is once its completion has been answered, and its files are still there.
        REQUIRE(c.m[owner]->mpu->abort("bkt", id, {}));
        REQUIRE(fs::exists(d.path + "/bkt/mpu/" + id));
        st got = st::io_error;
        bool fired = false;
        c.m[0]->node->delete_bucket("bkt", [&](st r) { got = r; fired = true; });
        REQUIRE(c.until([&] { return fired; }));
        CHECK(got == st::ok);
        for (uint32_t s = 0; s < shards; ++s)
        {
            CHECK_FALSE(c.m[s]->store->has_bucket("bkt"));
            CHECK(c.m[s]->mpu->totals().uploads == 0);
        }
    }
}

TEST_CASE("a completion assembled on another shard is answered only once the upload's owner has let it go")
{
    tmpdir d;
    cluster c(d.path, 2);
    REQUIRE(c.make_bucket(0, "bkt") == st::ok);
    const std::string key = key_owned_by("bkt", 1, 2);
    const std::string id = c.mpu_create(0, "bkt", key);
    const std::string p1 = pattern(1000, 7);
    REQUIRE(c.mpu_put_part(0, "bkt", key, id, 1, p1) == st::ok);

    c.hold_back = [](const cluster::task& t)
    {
        wire::op o{};
        return wire::request_op(t.payload, o) && o == wire::op::mpu_finish;
    };
    complete_result out;
    bool fired = false;
    c.m[0]->node->mpu_complete("bkt", key, id, {complete_part{1, hex(md5_of(p1)), checksum_algo::none, {}}}, [] {},
                               [&](complete_result r) { out = std::move(r); fired = true; });
    REQUIRE(c.until([&] { return !c.held_back.empty(); }));
    c.settle();
    // The object is committed, and the owner, not yet told, still holds the upload sealed.
    CHECK_FALSE(fired);
    REQUIRE(c.m[1]->mpu->find("bkt", id) != nullptr);
    CHECK(c.m[1]->mpu->find("bkt", id)->state == mpu_state::sealed);
    c.release();
    REQUIRE(c.until([&] { return fired; }));
    CHECK(out.error.code.empty());
    const mpu_upload* u = c.m[1]->mpu->find("bkt", id);
    CHECK((u == nullptr || u->state == mpu_state::removing));

    // So the client's next requests, deleting the object and then the bucket, find nothing in the way.
    CHECK(c.del(0, "bkt", key) == st::ok);
    CHECK(c.drop_bucket(0, "bkt") == st::ok);
}
