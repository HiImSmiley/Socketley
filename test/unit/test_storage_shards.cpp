#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

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
    uint64_t                             calls{0};

    cluster(std::string d, uint32_t shards, uint64_t max_bytes = 0)
        : dir(std::move(d))
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
            mb->store->set_drop_guard([mp](std::string_view bucket) { return mp->bucket_has_uploads(bucket); });
            m.push_back(std::move(mb));
        }
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
        while (!queue.empty())
        {
            task t = std::move(queue.front());
            queue.pop_front();
            if (unreachable.contains(t.peer) || t.peer >= m.size())
            {
                t.cb(false, {});
                continue;
            }
            auto cb = t.cb;
            m[t.peer]->node->serve(t.payload, [cb](bool ok, std::string reply) { cb(ok, reply); });
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
        m[s]->node->create_bucket(name, [&](st r) { got = r; fired = true; });
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
                                  std::function<void(put_result)> done, object_meta meta = {})
    {
        st why = st::ok;
        auto op = m[s]->store->begin_put(bucket, key, std::move(meta), body.size(), true, why);
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
        return held(s, bucket, key);
    }

    bool held(uint32_t s, const std::string& bucket, const std::string& key, std::string* body = nullptr)
    {
        object_store::hot_hit hit;
        const bool h = m[s]->store->hot_find(bucket, key, hit) && hit.foreign;
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
    CHECK_FALSE(c.held(reader, "bkt", "k"));
    // The next read keeps the new version.
    REQUIRE(c.warm(reader, "bkt", "k"));
    std::string body;
    REQUIRE(c.held(reader, "bkt", "k", &body));
    CHECK(body == v2);
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
    list_page p;
    for (int i = 0; i < 100; ++i)
    {
        list_entry e;
        e.key = "key" + std::to_string(1000 + i);
        e.meta.content_type = std::string(200, 'x');
        p.objects.push_back(std::move(e));
    }
    wire::limit_page(p, 4000);
    CHECK(p.objects.size() < 100);
    CHECK(p.objects.size() > 5);
    CHECK(p.truncated);
    CHECK(p.resume_at == "key" + std::to_string(1000 + p.objects.size()));

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
    req.create_only = true;
    const std::string enc = wire::encode_commit(req);
    commit_request back;
    REQUIRE(wire::decode_commit(enc, back));
    CHECK(back.bucket == req.bucket);
    CHECK(back.key == req.key);
    CHECK(back.tmp_name == req.tmp_name);
    CHECK(back.meta == req.meta);
    CHECK(back.create_only);
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
    flipped[flipped.size() - 5] ^= 0x10;
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

    // No object in the bucket, and a drop through any shard is still refused while an upload is open.
    for (uint32_t s = 0; s < 4; ++s)
        CHECK(c.drop_bucket(s, "bkt") == st::bucket_not_empty);
    for (uint32_t s = 0; s < 4; ++s)
        CHECK(c.m[s]->store->has_bucket("bkt"));
    // Aborting them all, each through another shard than the one that made it, lets it go.
    for (size_t i = 0; i < made.size(); ++i)
        CHECK(c.mpu_abort(static_cast<uint32_t>(i + 1) % 4, "bkt", made[i].first, made[i].second));
    CHECK_FALSE(c.mpu_abort(0, "bkt", made[0].first, made[0].second));
    CHECK(c.until([&] { return c.mpu_list(0, "bkt").empty(); }));
    CHECK(c.drop_bucket(2, "bkt") == st::ok);
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

    part_place place{4096 + (6ull << 30), 5u << 20, "ignored"};
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
