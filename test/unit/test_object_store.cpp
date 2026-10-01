#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "runtime/storage/object_format.h"
#include "runtime/storage/object_store.h"
#include "runtime/storage/s3_names.h"
#include "runtime/storage/s3_xml.h"
#include "shared/event_loop.h"
#include "shared/file_io.h"
#include "shared/hash_pool.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

// The object store on a real ring and a real directory: what a PUT leaves on
// disk, what a listing says, and what a start makes of whatever a crash left.

namespace fs = std::filesystem;
using namespace socketley;
using namespace socketley::storage;

namespace {

struct tmpdir
{
    std::string path;

    tmpdir()
    {
        char tmpl[] = "/tmp/socketley-objstore-XXXXXX";
        path = ::mkdtemp(tmpl);
    }
    ~tmpdir()
    {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

// One store on one ring, as a runtime holds them, and a way to run the ring
// until something is true.
struct rig : io_handler
{
    event_loop                    loop{256};
    std::unique_ptr<file_io>      io;
    // Declared between the ring and the store, as a runtime holds it.
    std::unique_ptr<hash_pool>    pool;
    std::unique_ptr<object_store> store;
    recovery_report               report;
    // Puts go as S3's PutObject sends them, free to take a pooled file.
    bool                          plain{false};

    explicit rig(const std::string& dir, uint64_t compact_floor = 4096, uint64_t max_bytes = 0,
                 unsigned hash_threads = 0, uint32_t shard = 0, uint32_t nshards = 1)
    {
        REQUIRE(loop.init());
        io = std::make_unique<file_io>(loop, this);
        if (hash_threads)
        {
            pool = std::make_unique<hash_pool>(hash_threads);
            REQUIRE(pool->attach(*io));
        }
        store_options o;
        o.dir           = dir;
        o.compact_floor = compact_floor;
        o.max_bytes     = max_bytes;
        o.shard         = shard;
        o.nshards       = nshards;
        store = std::make_unique<object_store>(loop, *io, o);
        if (pool)
            store->set_hash_pool(pool.get());
        std::string err;
        const bool ok = store->open(err, &report);
        INFO(err);
        REQUIRE(ok);
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

    st make_bucket(const std::string& name)
    {
        st got = st::io_error;
        bool fired = false;
        store->create_bucket(name, [&](st s) { got = s; fired = true; });
        REQUIRE(until([&] { return fired; }));
        return got;
    }

    st drop_bucket(const std::string& name)
    {
        st got = st::io_error;
        bool fired = false;
        store->delete_bucket(name, [&](st s) { got = s; fired = true; });
        REQUIRE(until([&] { return fired; }));
        return got;
    }

    // A whole body through the streaming path, in pieces of `piece` bytes.
    put_result put(const std::string& bucket, const std::string& key, const std::string& body,
                   object_meta meta = {}, size_t piece = 100000, const md5_t* expect = nullptr)
    {
        st why = st::ok;
        auto op = store->begin_put(bucket, key, std::move(meta), body.size(), true, why, plain);
        if (!op)
            return {why, {}};
        size_t off = 0;
        while (off < body.size() && !op->failed())
        {
            const size_t want = std::min(piece, body.size() - off);
            const size_t took = op->append(body.data() + off, want);
            off += took;
            if (took == 0)
            {
                bool ready = false;
                op->on_ready([&] { ready = true; });
                if (!until([&] { return ready || op->failed(); }))
                    return {st::io_error, {}};
            }
        }
        put_result out;
        bool fired = false;
        op->finish(expect, [&](put_result r) { out = std::move(r); fired = true; });
        REQUIRE(until([&] { return fired; }));
        return out;
    }

    // The bytes of an object as a reader gets them, read through the header.
    st get(const std::string& bucket, const std::string& key, std::string& body, object_meta* meta = nullptr)
    {
        open_result r;
        bool fired = false;
        store->open_object(bucket, key, 0, [&](open_result o) { r = std::move(o); fired = true; });
        REQUIRE(until([&] { return fired; }));
        if (r.status != st::ok)
            return r.status;
        body.assign(r.meta.size, '\0');
        size_t got = 0;
        while (got < body.size())
        {
            const ssize_t n = ::pread(r.fd, body.data() + got, body.size() - got,
                                      static_cast<off_t>(r.data_off + got));
            if (n <= 0)
                break;
            got += static_cast<size_t>(n);
        }
        ::close(r.fd);
        body.resize(got);
        if (meta)
            *meta = r.meta;
        return st::ok;
    }

    st del(const std::string& bucket, const std::string& key, bool* existed = nullptr)
    {
        st got = st::io_error;
        bool fired = false;
        store->remove(bucket, key, [&](st s, bool e) { got = s; if (existed) *existed = e; fired = true; });
        REQUIRE(until([&] { return fired; }));
        return got;
    }

    st tag(const std::string& bucket, const std::string& key, const std::string& tags)
    {
        st got = st::io_error;
        bool fired = false;
        store->set_tags(bucket, key, tags, [&](st s) { got = s; fired = true; });
        REQUIRE(until([&] { return fired; }));
        return got;
    }

    // A bucket document changed as shard 0 changes one with no siblings: staged, then committed.
    void set_doc(bucket_doc kind, const std::string& bucket, const std::string& xml)
    {
        bool staged = false, committed = false;
        store->stage_doc(kind, bucket, xml, [&](st s) { CHECK(s == st::ok); staged = true; });
        REQUIRE(until([&] { return staged; }));
        store->commit_doc(kind, bucket, xml, [&](bool visible, st s)
        {
            CHECK(visible);
            CHECK(s == st::ok);
            committed = true;
        });
        REQUIRE(until([&] { return committed; }));
    }

    void settle(int turns = 50)
    {
        for (int i = 0; i < turns; ++i)
            loop.poll_completions(1);
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

std::string journal_path(const std::string& dir, const std::string& bucket)
{
    return dir + "/" + bucket + "/index.0";
}

std::string data_path(const std::string& dir, const std::string& bucket, const std::string& key)
{
    return dir + "/" + bucket + "/data/" + object_rel_path(key);
}

size_t count_pool_files(const std::string& dir, const std::string& bucket)
{
    std::error_code ec;
    size_t n = 0;
    for (const auto& e : fs::directory_iterator(dir + "/" + bucket + "/pool", ec))
        n += e.is_regular_file() ? 1 : 0;
    return n;
}

}   // namespace

TEST_CASE("an object header round-trips and refuses a flipped bit")
{
    object_meta m;
    m.size     = 12345;
    m.mtime_ms = 1700000000123;
    m.md5      = md5_of("hello");
    m.content_type = "text/plain";
    m.extra = {{"x-amz-meta-a", "1"}, {"cache-control", "no-cache"}};

    const std::string h = encode_object_header("a/b/c", m);
    CHECK(h.size() % object_header_align == 0);
    CHECK(h.size() == object_header_len("a/b/c", m));

    const decoded_header d = decode_object_header(h);
    REQUIRE(d.status == header_status::ok);
    CHECK(d.key == "a/b/c");
    CHECK(d.meta == m);
    CHECK(d.header_len == h.size());

    std::string bad = h;
    bad[30] ^= 1;
    CHECK(decode_object_header(bad).status == header_status::bad);
    CHECK(decode_object_header(h.substr(0, 10)).status == header_status::need_more);
    CHECK(decode_object_header(std::string(4096, '\0')).status == header_status::bad);
}

TEST_CASE("a journal record decodes whole, torn and corrupt")
{
    object_meta m;
    m.size = 7;
    m.md5  = md5_of("x");
    std::string rec;
    encode_put_record(rec, "k", m);
    encode_delete_record(rec, "k", 99);

    decoded_record a = decode_journal_record(rec);
    REQUIRE(a.status == record_status::ok);
    CHECK(a.rec.type == record_type::put);
    CHECK(a.rec.key == "k");
    CHECK(a.rec.meta == m);
    decoded_record b = decode_journal_record(std::string_view(rec).substr(a.consumed));
    REQUIRE(b.status == record_status::ok);
    CHECK(b.rec.type == record_type::del);
    CHECK(b.rec.mtime_ms == 99);

    CHECK(decode_journal_record(std::string_view(rec).substr(0, a.consumed - 3)).status == record_status::torn);
    std::string flipped = rec;
    flipped[12] ^= 0x40;
    CHECK(decode_journal_record(flipped).status == record_status::corrupt);
}

TEST_CASE("part sizes are one number when all but the last agree, and a list that does not add up is trusted for nothing")
{
    CHECK(encode_part_sizes({}).empty());
    CHECK(encode_part_sizes({7}) == "7");
    CHECK(encode_part_sizes({5, 5, 5, 2}) == "5");
    CHECK(encode_part_sizes({5, 5, 9}) == "5");
    CHECK(encode_part_sizes({6, 5, 7, 1}) == "6,5,7,1");
    CHECK(encode_part_sizes(std::vector<uint64_t>(1000, 5242880 + 1) ).size() == 7);
    std::vector<uint64_t> varied;
    for (uint64_t i = 0; i < 1000; ++i)
        varied.push_back(5242880 + i);
    CHECK(encode_part_sizes(varied).empty());

    auto with = [](uint64_t size, uint32_t parts, std::string sizes)
    {
        object_meta m;
        m.size  = size;
        m.parts = parts;
        if (!sizes.empty())
            m.extra.emplace_back(std::string(part_sizes_extra), std::move(sizes));
        return m;
    };
    uint64_t first = 0, len = 0;
    auto at = [&](const object_meta& m, uint32_t n)
    {
        const part_status s = part_range(m, n, first, len);
        return std::pair(s, std::pair(first, len));
    };
    using r = std::pair<part_status, std::pair<uint64_t, uint64_t>>;

    // A single-part object, and a multipart one of one part, are their own part 1.
    CHECK(at(with(10, 0, ""), 1) == r{part_status::ok, {0, 10}});
    CHECK(part_range(with(10, 0, ""), 2, first, len) == part_status::out_of_range);
    CHECK(at(with(10, 1, ""), 1) == r{part_status::ok, {0, 10}});
    CHECK(part_range(with(10, 3, ""), 0, first, len) == part_status::out_of_range);

    const object_meta uniform = with(23, 3, "10");
    CHECK(at(uniform, 1) == r{part_status::ok, {0, 10}});
    CHECK(at(uniform, 2) == r{part_status::ok, {10, 10}});
    CHECK(at(uniform, 3) == r{part_status::ok, {20, 3}});
    CHECK(part_range(uniform, 4, first, len) == part_status::out_of_range);
    // A last part larger than the others is still described by the one size.
    CHECK(at(with(29, 3, "10"), 3) == r{part_status::ok, {20, 9}});

    const object_meta list = with(19, 4, "6,5,7,1");
    CHECK(at(list, 1) == r{part_status::ok, {0, 6}});
    CHECK(at(list, 3) == r{part_status::ok, {11, 7}});
    CHECK(at(list, 4) == r{part_status::ok, {18, 1}});

    // What a header could say and the object not bear out is unknown, never a guess.
    CHECK(part_range(with(10, 3, ""), 2, first, len) == part_status::unknown);
    CHECK(part_range(with(19, 3, "10"), 1, first, len) == part_status::unknown);
    CHECK(part_range(with(19, 3, "0"), 1, first, len) == part_status::unknown);
    CHECK(part_range(with(19, 3, "x"), 1, first, len) == part_status::unknown);
    CHECK(part_range(with(20, 4, "6,5,7,1"), 1, first, len) == part_status::unknown);
    CHECK(part_range(with(19, 3, "6,5,7,1"), 1, first, len) == part_status::unknown);
    CHECK(part_range(with(19, 4, "6,5,,8"), 1, first, len) == part_status::unknown);
    CHECK(part_range(with(19, 4, "6,5,7,1,"), 1, first, len) == part_status::unknown);
}

TEST_CASE("tag slots in a header's padding take changes in turn, and a torn one leaves the one before")
{
    object_meta m;
    m.size     = 99;
    m.mtime_ms = 1700000000000;
    m.md5      = md5_of("x");
    m.content_type = "text/plain";
    set_tags_extra(m, std::string("a\0" "1\0", 4));
    std::string h = encode_object_header("key", m);

    decoded_header d = decode_object_header(h);
    REQUIRE(d.status == header_status::ok);
    CHECK(d.tag_slot == -1);
    CHECK(d.meta == m);

    // Each change goes to the slot the last one did not use, with the next number.
    const std::string sets[] = {std::string("b\0" "2\0", 4), std::string("c\0" "3\0", 4), std::string()};
    std::vector<uint64_t> where;
    for (const std::string& t : sets)
    {
        uint64_t at = 0;
        const std::string slot = encode_tag_slot(d, t, at);
        REQUIRE_FALSE(slot.empty());
        CHECK(at % 512 == 0);
        CHECK(at + slot.size() <= object_header_align);
        h.replace(at, slot.size(), slot);
        where.push_back(at);
        d = decode_object_header(h);
        REQUIRE(d.status == header_status::ok);
        CHECK(tags_of(d.meta) == t);
        object_meta want = m;
        set_tags_extra(want, t);
        CHECK(d.meta == want);
    }
    CHECK(where[0] != where[1]);
    CHECK(where[0] == where[2]);
    CHECK(d.tag_seq == 3);

    // The newest slot torn: the one before it is the truth again.
    h[where[2] + 10] ^= 0x10;
    d = decode_object_header(h);
    REQUIRE(d.status == header_status::ok);
    CHECK(tags_of(d.meta) == sets[1]);
    CHECK(d.tag_seq == 2);
    // And a header read short of its slots is the header as it was written.
    CHECK(tags_of(decode_object_header(std::string_view(h).substr(0, 300)).meta) == std::string("a\0" "1\0", 4));

    uint64_t at = 0;
    CHECK(encode_tag_slot(d, std::string(4000, 'v'), at).empty());
    object_meta fat = m;
    fat.extra.emplace_back("x-amz-meta-big", std::string(3500, 'm'));
    CHECK(encode_tag_slot(decode_object_header(encode_object_header("key", fat)), "t", at).empty());
}

TEST_CASE("a tag change keeps the object's bytes, ETag and time, and its file alone brings it back after a crash")
{
    tmpdir d;
    const std::string small(std::string("env\0" "prod\0", 9));
    // Ten tags of 128-byte keys and 256-byte values outgrow every slot, so the object is written again.
    std::string big;
    for (int i = 0; i < 10; ++i)
        big += std::string(127, 'k') + char('0' + i) + '\0' + std::string(256, 'v') + '\0';
    object_meta first;
    {
        rig r(d.path);
        REQUIRE(r.make_bucket("bkt") == st::ok);
        object_meta m;
        m.content_type = "text/plain";
        m.extra = {{"x-amz-meta-who", "me"}};
        REQUIRE(r.put("bkt", "small", pattern(10000)).status == st::ok);
        REQUIRE(r.put("bkt", "big", pattern(3u << 20, 2), m).status == st::ok);
        first = *r.store->find("bkt", "big");

        CHECK(r.tag("bkt", "small", small) == st::ok);
        CHECK(r.store->totals().tag_writes == 1);
        CHECK(r.tag("bkt", "big", big) == st::ok);
        CHECK(r.store->totals().tag_rewrites == 1);
        CHECK(r.tag("bkt", "nothing", small) == st::no_such_key);
        CHECK(r.tag("nobkt", "small", small) == st::no_such_bucket);

        std::string body;
        object_meta read;
        REQUIRE(r.get("bkt", "big", body, &read) == st::ok);
        CHECK(body == pattern(3u << 20, 2));
        CHECK(read == *r.store->find("bkt", "big"));
        CHECK(tags_of(read) == big);
        CHECK(read.etag() == first.etag());
        CHECK(read.mtime_ms == first.mtime_ms);
        REQUIRE(r.get("bkt", "small", body, &read) == st::ok);
        CHECK(body == pattern(10000));
        CHECK(tags_of(read) == small);
        CHECK(fs::is_empty(d.path + "/bkt/tmp"));

        // A header that holds a big set has no room for slots, and the one written for a small set has.
        CHECK(r.tag("bkt", "big", std::string("x\0" "y\0", 4)) == st::ok);
        CHECK(r.store->totals().tag_rewrites == 2);
        CHECK(r.tag("bkt", "big", small) == st::ok);
        CHECK(r.store->totals().tag_writes == 2);
        CHECK(r.store->totals().tag_rewrites == 2);
        r.settle();
    }
    // A crash with the journal gone: only the object files say what the tags are.
    fs::remove(journal_path(d.path, "bkt"));
    rig again(d.path);
    CHECK_FALSE(again.report.clean_start);
    REQUIRE(again.store->find("bkt", "big") != nullptr);
    CHECK(tags_of(*again.store->find("bkt", "big")) == small);
    CHECK(again.store->find("bkt", "big")->etag() == first.etag());
    CHECK(again.store->find("bkt", "big")->mtime_ms == first.mtime_ms);
    CHECK(tags_of(*again.store->find("bkt", "small")) == small);

    // Removing them is a change like any other.
    CHECK(again.tag("bkt", "small", "") == st::ok);
    std::string body;
    object_meta read;
    REQUIRE(again.get("bkt", "small", body, &read) == st::ok);
    CHECK(tags_of(read).empty());
    CHECK(body == pattern(10000));
}

TEST_CASE("bucket names follow the S3 rules")
{
    CHECK(valid_bucket_name("my-bucket.1"));
    CHECK_FALSE(valid_bucket_name("ab"));
    CHECK_FALSE(valid_bucket_name("UPPER"));
    CHECK_FALSE(valid_bucket_name("-lead"));
    CHECK_FALSE(valid_bucket_name("trail-"));
    CHECK_FALSE(valid_bucket_name("a..b"));
    CHECK_FALSE(valid_bucket_name("192.168.0.1"));
    CHECK_FALSE(valid_bucket_name("xn--foo"));
    CHECK_FALSE(valid_bucket_name(std::string(64, 'a')));
    CHECK_FALSE(valid_bucket_name("under_score"));
}

TEST_CASE("buckets are created, listed, and refused when they exist or hold objects")
{
    tmpdir d;
    rig r(d.path);
    CHECK(r.make_bucket("alpha") == st::ok);
    CHECK(r.make_bucket("alpha") == st::bucket_exists);
    CHECK(r.make_bucket("Bad_Name") == st::invalid_bucket_name);
    CHECK(r.make_bucket("beta") == st::ok);

    const auto bs = r.store->buckets();
    REQUIRE(bs.size() == 2);
    CHECK(bs[0].name == "alpha");
    CHECK(bs[1].name == "beta");
    CHECK(bs[0].created_ms > 1600000000000);

    CHECK(r.put("alpha", "k", "v").status == st::ok);
    CHECK(r.drop_bucket("alpha") == st::bucket_not_empty);
    CHECK(r.drop_bucket("nothere") == st::no_such_bucket);
    CHECK(r.drop_bucket("beta") == st::ok);
    CHECK_FALSE(r.store->has_bucket("beta"));
    CHECK(r.make_bucket("beta") == st::ok);
    CHECK(r.put("nothere", "k", "v").status == st::no_such_bucket);
}

TEST_CASE("a put is readable back byte for byte, with its etag, and overwrites in place")
{
    tmpdir d;
    rig r(d.path);
    REQUIRE(r.make_bucket("bkt") == st::ok);

    object_meta m;
    m.content_type = "application/x-test";
    m.extra = {{"x-amz-meta-owner", "me"}, {"content-disposition", "attachment"}};
    const std::string body = pattern(300000);
    const put_result p = r.put("bkt", "dir/one.bin", body, m);
    REQUIRE(p.status == st::ok);
    CHECK(p.meta.etag() == hex(md5_of(body)));
    CHECK(p.meta.size == body.size());

    std::string got;
    object_meta gm;
    REQUIRE(r.get("bkt", "dir/one.bin", got, &gm) == st::ok);
    CHECK(got == body);
    CHECK(gm.content_type == "application/x-test");
    CHECK(gm.extra == m.extra);
    CHECK(gm.md5 == md5_of(body));

    const object_meta* head = r.store->find("bkt", "dir/one.bin");
    REQUIRE(head != nullptr);
    CHECK(*head == gm);

    // The file is where the hash says, and self-describing.
    const std::string path = data_path(d.path, "bkt", "dir/one.bin");
    REQUIRE(fs::exists(path));
    const decoded_header h = decode_object_header(slurp(path).substr(0, 8192));
    REQUIRE(h.status == header_status::ok);
    CHECK(h.key == "dir/one.bin");
    CHECK(fs::file_size(path) == h.header_len + body.size());

    const std::string second = pattern(50, 7);
    REQUIRE(r.put("bkt", "dir/one.bin", second).status == st::ok);
    REQUIRE(r.get("bkt", "dir/one.bin", got) == st::ok);
    CHECK(got == second);
    CHECK(r.store->totals().objects == 1);
    CHECK(r.store->totals().bytes == second.size());
}

TEST_CASE("sizes at every edge of the staging buffers survive a round trip")
{
    tmpdir d;
    rig r(d.path);
    REQUIRE(r.make_bucket("bkt") == st::ok);

    // Empty, one byte, around a page, and either side of the one-megabyte
    // buffer -- where the second buffer and the separate header write begin.
    for (size_t n : {size_t{0}, size_t{1}, size_t{4095}, size_t{4096}, size_t{4097},
                     size_t{(1u << 20) - 1}, size_t{1u << 20}, size_t{(1u << 20) + 1},
                     size_t{3u << 20}, size_t{(3u << 20) + 17}})
    {
        const std::string key = "k" + std::to_string(n);
        const std::string body = pattern(n, static_cast<unsigned>(n));
        // Pieces that do not divide the buffer, so a piece straddles two.
        const put_result p = r.put("bkt", key, body, {}, 333333);
        REQUIRE(p.status == st::ok);
        std::string got;
        REQUIRE(r.get("bkt", key, got) == st::ok);
        CHECK(got.size() == body.size());
        CHECK(got == body);
        CHECK(p.meta.md5 == md5_of(body));
    }
}

TEST_CASE("a body that fails its digest is not stored and leaves no temporary file")
{
    tmpdir d;
    rig r(d.path);
    REQUIRE(r.make_bucket("bkt") == st::ok);
    REQUIRE(r.put("bkt", "k", "first").status == st::ok);

    const md5_t wrong = md5_of("something else");
    const put_result p = r.put("bkt", "k", "second", {}, 100, &wrong);
    CHECK(p.status == st::bad_digest);
    r.settle();

    std::string got;
    REQUIRE(r.get("bkt", "k", got) == st::ok);
    CHECK(got == "first");
    CHECK(fs::is_empty(d.path + "/bkt/tmp"));

    const md5_t right = md5_of("second");
    CHECK(r.put("bkt", "k", "second", {}, 100, &right).status == st::ok);
}

TEST_CASE("a delete removes the object and a later put brings it back")
{
    tmpdir d;
    rig r(d.path);
    REQUIRE(r.make_bucket("bkt") == st::ok);
    REQUIRE(r.put("bkt", "k", "v").status == st::ok);

    bool existed = false;
    CHECK(r.del("bkt", "k", &existed) == st::ok);
    CHECK(existed);
    CHECK(r.store->find("bkt", "k") == nullptr);
    CHECK_FALSE(fs::exists(data_path(d.path, "bkt", "k")));
    std::string got;
    CHECK(r.get("bkt", "k", got) == st::no_such_key);

    CHECK(r.del("bkt", "k", &existed) == st::ok);
    CHECK_FALSE(existed);
    CHECK(r.del("nobucket", "k") == st::no_such_bucket);

    REQUIRE(r.put("bkt", "k", "w").status == st::ok);
    REQUIRE(r.get("bkt", "k", got) == st::ok);
    CHECK(got == "w");
    CHECK(r.drop_bucket("bkt") == st::bucket_not_empty);
    CHECK(r.del("bkt", "k") == st::ok);
    CHECK(r.drop_bucket("bkt") == st::ok);
}

namespace {

std::vector<std::string> keys_of(const list_page& p)
{
    std::vector<std::string> out;
    for (const auto& e : p.objects)
        out.push_back(e.key);
    return out;
}

}   // namespace

TEST_CASE("listing honours prefix, delimiter, start-after, max-keys and resumes exactly")
{
    tmpdir d;
    rig r(d.path);
    REQUIRE(r.make_bucket("bkt") == st::ok);
    for (const char* k : {"a", "b/1", "b/2", "b/sub/x", "c", "d/1", "e", "photos/2020/a.jpg",
                          "photos/2020/b.jpg", "photos/2021/c.jpg", "photos/index.html"})
        REQUIRE(r.put("bkt", k, k).status == st::ok);

    list_page p;
    REQUIRE(r.store->list("bkt", {}, p) == st::ok);
    CHECK(keys_of(p) == std::vector<std::string>{"a", "b/1", "b/2", "b/sub/x", "c", "d/1", "e",
                                                 "photos/2020/a.jpg", "photos/2020/b.jpg",
                                                 "photos/2021/c.jpg", "photos/index.html"});
    CHECK_FALSE(p.truncated);

    list_query q;
    q.delimiter = "/";
    REQUIRE(r.store->list("bkt", q, p) == st::ok);
    CHECK(keys_of(p) == std::vector<std::string>{"a", "c", "e"});
    CHECK(p.prefixes == std::vector<std::string>{"b/", "d/", "photos/"});

    q.prefix = "photos/";
    REQUIRE(r.store->list("bkt", q, p) == st::ok);
    CHECK(keys_of(p) == std::vector<std::string>{"photos/index.html"});
    CHECK(p.prefixes == std::vector<std::string>{"photos/2020/", "photos/2021/"});

    q = {};
    q.prefix = "photos/2020/";
    REQUIRE(r.store->list("bkt", q, p) == st::ok);
    CHECK(keys_of(p) == std::vector<std::string>{"photos/2020/a.jpg", "photos/2020/b.jpg"});

    q = {};
    q.start_after = "b/2";
    q.max_keys    = 3;
    REQUIRE(r.store->list("bkt", q, p) == st::ok);
    CHECK(keys_of(p) == std::vector<std::string>{"b/sub/x", "c", "d/1"});
    CHECK(p.truncated);
    CHECK(p.resume_at == "e");

    // Paged through with resume points, delimiter on: every entry exactly
    // once, common prefixes counting against the page.
    q = {};
    q.delimiter = "/";
    q.max_keys  = 2;
    std::vector<std::string> seen;
    for (int pages = 0; pages < 20; ++pages)
    {
        REQUIRE(r.store->list("bkt", q, p) == st::ok);
        CHECK(p.objects.size() + p.prefixes.size() <= 2);
        for (const auto& e : p.objects)
            seen.push_back(e.key);
        for (const auto& c : p.prefixes)
            seen.push_back(c);
        if (!p.truncated)
            break;
        q.has_resume = true;
        q.resume_at  = p.resume_at;
    }
    std::sort(seen.begin(), seen.end());
    CHECK(seen == std::vector<std::string>{"a", "b/", "c", "d/", "e", "photos/"});

    q = {};
    q.max_keys = 0;
    REQUIRE(r.store->list("bkt", q, p) == st::ok);
    CHECK(p.objects.empty());
    CHECK_FALSE(p.truncated);
    CHECK(r.store->list("nope", {}, p) == st::no_such_bucket);
}

TEST_CASE("a delimiter that matches within the prefix's own length is not a rollup")
{
    tmpdir d;
    rig r(d.path);
    REQUIRE(r.make_bucket("bkt") == st::ok);
    for (const char* k : {"dir/", "dir/a", "dir/b/c", "dirx"})
        REQUIRE(r.put("bkt", k, "1").status == st::ok);

    list_query q;
    q.prefix    = "dir/";
    q.delimiter = "/";
    list_page p;
    REQUIRE(r.store->list("bkt", q, p) == st::ok);
    CHECK(keys_of(p) == std::vector<std::string>{"dir/", "dir/a"});
    CHECK(p.prefixes == std::vector<std::string>{"dir/b/"});
}

TEST_CASE("a marker that is a rolled-up prefix skips the keys behind it")
{
    tmpdir d;
    rig r(d.path);
    REQUIRE(r.make_bucket("bkt") == st::ok);
    for (const char* k : {"a", "b/1", "b/2", "c", "d/1"})
        REQUIRE(r.put("bkt", k, "1").status == st::ok);

    list_query q;
    q.delimiter   = "/";
    q.start_after = "b/";
    list_page p;
    REQUIRE(r.store->list("bkt", q, p) == st::ok);
    CHECK(keys_of(p) == std::vector<std::string>{"c"});
    CHECK(p.prefixes == std::vector<std::string>{"d/"});

    // Without a delimiter the same marker is only a key to start after.
    q.delimiter.clear();
    REQUIRE(r.store->list("bkt", q, p) == st::ok);
    CHECK(keys_of(p) == std::vector<std::string>{"b/1", "b/2", "c", "d/1"});
}

TEST_CASE("a clean restart keeps every object and trusts the journal")
{
    tmpdir d;
    {
        rig r(d.path);
        REQUIRE(r.make_bucket("bkt") == st::ok);
        REQUIRE(r.put("bkt", "one", pattern(1000)).status == st::ok);
        REQUIRE(r.put("bkt", "two", pattern(2000)).status == st::ok);
        REQUIRE(r.del("bkt", "one") == st::ok);
        r.settle();
        r.store->close(true);
    }
    rig again(d.path);
    CHECK(again.report.clean_start);
    CHECK(again.report.objects == 1);
    CHECK(again.report.adopted == 0);
    std::string got;
    REQUIRE(again.get("bkt", "two", got) == st::ok);
    CHECK(got == pattern(2000));
    CHECK(again.get("bkt", "one", got) == st::no_such_key);
    CHECK(again.store->find("bkt", "one") == nullptr);

    // The marker is gone once the store is up, so a crash from here on reads
    // as one.
    CHECK_FALSE(fs::exists(d.path + "/.clean.0"));
}

TEST_CASE("a start after a crash removes temporary files and drops records whose file is gone")
{
    tmpdir d;
    {
        rig r(d.path);
        REQUIRE(r.make_bucket("bkt") == st::ok);
        REQUIRE(r.put("bkt", "keep", "keep-body").status == st::ok);
        REQUIRE(r.put("bkt", "lost", "lost-body").status == st::ok);
        r.settle();
    }
    // A body that never got renamed, and a file the disk lost.
    spill(d.path + "/bkt/tmp/deadbeef", pattern(5000));
    fs::remove(data_path(d.path, "bkt", "lost"));

    rig again(d.path);
    CHECK_FALSE(again.report.clean_start);
    CHECK(again.report.tmp_removed == 1);
    CHECK(again.report.dropped == 1);
    CHECK(fs::is_empty(d.path + "/bkt/tmp"));
    CHECK(again.store->find("bkt", "keep") != nullptr);
    CHECK(again.store->find("bkt", "lost") == nullptr);
    list_page p;
    REQUIRE(again.store->list("bkt", {}, p) == st::ok);
    CHECK(keys_of(p) == std::vector<std::string>{"keep"});
}

TEST_CASE("a file renamed into place whose journal record never landed is adopted")
{
    tmpdir d;
    std::string body = pattern(4321);
    {
        rig r(d.path);
        REQUIRE(r.make_bucket("bkt") == st::ok);
        REQUIRE(r.put("bkt", "first", "one").status == st::ok);
        r.settle();
    }
    // What a crash between the rename and the journal append leaves: the
    // second object's file, and a journal that has never heard of it.
    const std::string jbefore = slurp(journal_path(d.path, "bkt"));
    {
        rig r(d.path);
        REQUIRE(r.put("bkt", "second", body).status == st::ok);
        r.settle();
    }
    spill(journal_path(d.path, "bkt"), jbefore);

    rig again(d.path);
    CHECK(again.report.adopted == 1);
    std::string got;
    REQUIRE(again.get("bkt", "second", got) == st::ok);
    CHECK(got == body);
    const object_meta* m = again.store->find("bkt", "second");
    REQUIRE(m != nullptr);
    CHECK(m->size == body.size());
    CHECK(again.store->find("bkt", "first") != nullptr);
}

TEST_CASE("an overwrite whose journal record never landed serves the new object")
{
    tmpdir d;
    {
        rig r(d.path);
        REQUIRE(r.make_bucket("bkt") == st::ok);
        REQUIRE(r.put("bkt", "k", "old-body").status == st::ok);
        r.settle();
    }
    const std::string jbefore = slurp(journal_path(d.path, "bkt"));
    {
        rig r(d.path);
        REQUIRE(r.put("bkt", "k", "new-body-longer").status == st::ok);
        r.settle();
    }
    spill(journal_path(d.path, "bkt"), jbefore);

    rig again(d.path);
    const object_meta* m = again.store->find("bkt", "k");
    REQUIRE(m != nullptr);
    CHECK(m->size == std::string("new-body-longer").size());
    CHECK(m->md5 == md5_of("new-body-longer"));
}

TEST_CASE("a deleted object does not come back after a crash")
{
    tmpdir d;
    {
        rig r(d.path);
        REQUIRE(r.make_bucket("bkt") == st::ok);
        REQUIRE(r.put("bkt", "gone", "body").status == st::ok);
        REQUIRE(r.put("bkt", "stay", "body").status == st::ok);
        REQUIRE(r.del("bkt", "gone") == st::ok);
        r.settle();
    }
    rig again(d.path);
    CHECK(again.store->find("bkt", "gone") == nullptr);
    CHECK(again.store->find("bkt", "stay") != nullptr);
    CHECK(again.report.adopted == 0);
}

TEST_CASE("a torn journal tail is cut off and the object behind it comes back from its file")
{
    tmpdir d;
    // A long key, so the record is long and what is left of it after a crash
    // is longer than the record the next append writes over it.
    const std::string longkey(300, 'k');
    {
        rig r(d.path);
        REQUIRE(r.make_bucket("bkt") == st::ok);
        REQUIRE(r.put("bkt", "one", "1").status == st::ok);
        REQUIRE(r.put("bkt", longkey, "22").status == st::ok);
        r.settle();
    }
    const std::string j = slurp(journal_path(d.path, "bkt"));
    // The last record with its final bytes missing, as a crash in the middle of the append leaves it.
    spill(journal_path(d.path, "bkt"), j.substr(0, j.size() - 9));

    rig again(d.path);
    CHECK(again.report.torn_tails == 1);
    CHECK(again.store->find("bkt", "one") != nullptr);
    // The file of the second is whole, so it is not lost.
    CHECK(again.store->find("bkt", longkey) != nullptr);

    // And a new append lands on a record boundary with nothing of the old tail
    // behind it: another restart reads a journal that is whole.
    REQUIRE(again.put("bkt", "three", "333").status == st::ok);
    again.settle();
    rig third(d.path);
    CHECK(third.report.torn_tails == 0);
    CHECK(third.report.rebuilt_journals == 0);
    CHECK(third.store->find("bkt", "three") != nullptr);
    CHECK(third.store->find("bkt", longkey) != nullptr);
}

TEST_CASE("a journal that is lost or damaged in the middle is rebuilt from the files")
{
    for (int variant = 0; variant < 3; ++variant)
    {
        tmpdir d;
        {
            rig r(d.path);
            REQUIRE(r.make_bucket("bkt") == st::ok);
            for (int i = 0; i < 20; ++i)
                REQUIRE(r.put("bkt", "key" + std::to_string(i), pattern(100 + i, i)).status == st::ok);
            REQUIRE(r.del("bkt", "key3") == st::ok);
            r.settle();
        }
        const std::string jp = journal_path(d.path, "bkt");
        std::string j = slurp(jp);
        if (variant == 0)
            fs::remove(jp);
        else if (variant == 1)
        {
            j[j.size() / 2] ^= 0x55;
            spill(jp, j);
        }
        else
            spill(jp, std::string(j.size(), 'x'));

        rig again(d.path);
        INFO("variant " << variant);
        // Variant 0 is an empty journal and reads as clean but short, which the
        // unclean start's walk of the files repairs.
        CHECK(again.store->totals().objects == 19);
        CHECK(again.store->find("bkt", "key3") == nullptr);
        for (int i = 0; i < 20; ++i)
        {
            if (i == 3)
                continue;
            std::string got;
            REQUIRE(again.get("bkt", "key" + std::to_string(i), got) == st::ok);
            CHECK(got == pattern(100 + i, i));
        }
        // And the journal on disk now says the same, so the next start needs no repair.
        again.settle();
        rig third(d.path);
        CHECK(third.store->totals().objects == 19);
        CHECK(third.report.adopted == 0);
    }
}

TEST_CASE("the journal is compacted once garbage outweighs the live objects, and survives a restart")
{
    tmpdir d;
    uint64_t compactions = 0;
    {
        rig r(d.path, /*compact_floor=*/50);
        REQUIRE(r.make_bucket("bkt") == st::ok);
        for (int i = 0; i < 5; ++i)
            REQUIRE(r.put("bkt", "live" + std::to_string(i), "v").status == st::ok);
        // The same key over and over is all garbage.
        for (int i = 0; i < 200; ++i)
            REQUIRE(r.put("bkt", "hot", "v" + std::to_string(i)).status == st::ok);
        r.settle(200);
        compactions = r.store->totals().compactions;
        CHECK(compactions >= 1);
        // Bounded by the floor and the live set, not by the 205 puts.
        CHECK(r.store->totals().journal_records < 120);
        std::string got;
        REQUIRE(r.get("bkt", "hot", got) == st::ok);
        CHECK(got == "v199");
        r.store->close(true);
    }
    rig again(d.path, 50);
    CHECK(again.store->totals().objects == 6);
    std::string got;
    REQUIRE(again.get("bkt", "hot", got) == st::ok);
    CHECK(got == "v199");
    for (int i = 0; i < 5; ++i)
        CHECK(again.store->find("bkt", "live" + std::to_string(i)) != nullptr);
    CHECK(fs::file_size(journal_path(d.path, "bkt")) < 205u * 100u);
}

TEST_CASE("puts that arrive while the journal is being compacted are not lost")
{
    tmpdir d;
    {
        rig r(d.path, 20);
        REQUIRE(r.make_bucket("bkt") == st::ok);
        // Everything in flight at once, so most commits meet a frozen journal.
        int done = 0;
        std::vector<std::shared_ptr<put_op>> ops;
        for (int i = 0; i < 300; ++i)
        {
            st why;
            auto op = r.store->begin_put("bkt", "k" + std::to_string(i % 40), {}, 10, true, why);
            REQUIRE(op);
            const std::string body = "body-" + std::to_string(i);
            op->append(body.data(), body.size());
            // The size was promised as 10 and the body is shorter or longer;
            // the store only cares what arrived.
            op->finish(nullptr, [&](put_result res) { CHECK(res.status == st::ok); ++done; });
            ops.push_back(op);
        }
        REQUIRE(r.until([&] { return done == 300; }));
        // A compaction may still be starting behind the last record; a fixed number of turns lost that race on a slow disk.
        CHECK(r.until([&] { return r.store->totals().compactions >= 1 && !r.store->busy(); }));
        r.store->close(true);
    }
    rig again(d.path, 20);
    CHECK(again.report.clean_start);
    CHECK(again.store->totals().objects == 40);
}

TEST_CASE("concurrent puts to one key end with one whole object every reader agrees on")
{
    tmpdir d;
    rig r(d.path);
    REQUIRE(r.make_bucket("bkt") == st::ok);

    constexpr int writers = 24;
    int done = 0;
    std::vector<std::string> bodies;
    std::vector<std::shared_ptr<put_op>> ops;
    for (int i = 0; i < writers; ++i)
        bodies.push_back(pattern(20000 + i * 1111, i));
    for (int i = 0; i < writers; ++i)
    {
        st why;
        auto op = r.store->begin_put("bkt", "same", {}, bodies[i].size(), true, why);
        REQUIRE(op);
        REQUIRE(op->append(bodies[i].data(), bodies[i].size()) == bodies[i].size());
        op->finish(nullptr, [&](put_result res) { CHECK(res.status == st::ok); ++done; });
        ops.push_back(op);
    }
    REQUIRE(r.until([&] { return done == writers; }));

    std::string got;
    object_meta gm;
    REQUIRE(r.get("bkt", "same", got, &gm) == st::ok);
    const object_meta* m = r.store->find("bkt", "same");
    REQUIRE(m != nullptr);
    // The memory and the file name the same winner, and it is one of the bodies, whole.
    CHECK(*m == gm);
    CHECK(md5_of(got) == gm.md5);
    CHECK(std::find(bodies.begin(), bodies.end(), got) != bodies.end());
    CHECK(r.store->totals().objects == 1);
    CHECK(r.store->totals().bytes == got.size());

    r.settle();
    rig again(d.path);
    const object_meta* am = again.store->find("bkt", "same");
    REQUIRE(am != nullptr);
    CHECK(*am == gm);
}

TEST_CASE("a copy makes a whole second object with the metadata it is given")
{
    tmpdir d;
    rig r(d.path);
    REQUIRE(r.make_bucket("src") == st::ok);
    REQUIRE(r.make_bucket("dst") == st::ok);
    object_meta m;
    m.content_type = "text/x-src";
    m.extra = {{"x-amz-meta-k", "v"}};
    const std::string body = pattern((2u << 20) + 123);
    REQUIRE(r.put("src", "in/orig", body, m).status == st::ok);

    object_meta want = m;
    want.content_type = "text/x-copy";
    want.extra = {{"x-amz-meta-other", "1"}};
    put_result out;
    bool fired = false;
    r.store->copy("src", "in/orig", "dst", "out/copy", want, [&](put_result p) { out = p; fired = true; });
    REQUIRE(r.until([&] { return fired; }));
    REQUIRE(out.status == st::ok);

    std::string got;
    object_meta gm;
    REQUIRE(r.get("dst", "out/copy", got, &gm) == st::ok);
    CHECK(got == body);
    CHECK(gm.content_type == "text/x-copy");
    CHECK(gm.extra == want.extra);
    CHECK(gm.md5 == md5_of(body));
    // The source is untouched.
    REQUIRE(r.get("src", "in/orig", got, &gm) == st::ok);
    CHECK(gm.content_type == "text/x-src");

    // Onto itself, with a new content type.
    fired = false;
    object_meta again = m;
    again.content_type = "text/replaced";
    r.store->copy("src", "in/orig", "src", "in/orig", again, [&](put_result p) { out = p; fired = true; });
    REQUIRE(r.until([&] { return fired; }));
    CHECK(out.status == st::ok);
    REQUIRE(r.get("src", "in/orig", got, &gm) == st::ok);
    CHECK(got == body);
    CHECK(gm.content_type == "text/replaced");

    fired = false;
    r.store->copy("src", "missing", "dst", "x", m, [&](put_result p) { out = p; fired = true; });
    REQUIRE(r.until([&] { return fired; }));
    CHECK(out.status == st::no_such_key);
}

TEST_CASE("a quota refuses a body that would not fit and counts what it holds")
{
    tmpdir d;
    rig r(d.path, 4096, /*max_bytes=*/100000);
    REQUIRE(r.make_bucket("bkt") == st::ok);
    CHECK(r.put("bkt", "a", pattern(60000)).status == st::ok);
    CHECK(r.put("bkt", "big", pattern(60000)).status == st::storage_full);
    // The unlink is on the ring, and a loaded disk takes longer than a fixed number of turns.
    CHECK(r.until([&] { return fs::is_empty(d.path + "/bkt/tmp"); }));
    CHECK(r.put("bkt", "small", pattern(30000)).status == st::ok);
    // Overwriting frees what the old body held.
    CHECK(r.del("bkt", "a") == st::ok);
    CHECK(r.put("bkt", "big", pattern(60000)).status == st::ok);

    // A body of unknown length is held to the quota as it grows.
    st why;
    auto op = r.store->begin_put("bkt", "grow", {}, 0, false, why);
    REQUIRE(op);
    const std::string chunk = pattern(50000);
    bool failed = false;
    op->on_failed([&](st s) { failed = (s == st::storage_full); });
    for (int i = 0; i < 4 && !failed; ++i)
    {
        size_t off = 0;
        while (off < chunk.size() && !failed)
        {
            const size_t took = op->append(chunk.data() + off, chunk.size() - off);
            off += took;
            if (took == 0)
                break;
        }
    }
    CHECK(failed);
    op->abort();
    r.settle();
}

TEST_CASE("an object too large for a single put is refused before a byte is taken")
{
    tmpdir d;
    rig r(d.path);
    REQUIRE(r.make_bucket("bkt") == st::ok);
    st why = st::ok;
    auto op = r.store->begin_put("bkt", "k", {}, (5ull << 30) + 1, true, why);
    CHECK_FALSE(op);
    CHECK(why == st::too_large);

    std::string longkey(1025, 'k');
    op = r.store->begin_put("bkt", longkey, {}, 1, true, why);
    CHECK_FALSE(op);
    CHECK(why == st::key_too_long);

    object_meta big;
    big.extra = {{"x-amz-meta-x", std::string(9000, 'v')}};
    op = r.store->begin_put("bkt", "k", big, 1, true, why);
    CHECK_FALSE(op);
    CHECK(why == st::metadata_too_large);
}

TEST_CASE("an aborted put leaves nothing behind")
{
    tmpdir d;
    rig r(d.path);
    REQUIRE(r.make_bucket("bkt") == st::ok);
    st why;
    auto op = r.store->begin_put("bkt", "k", {}, 0, false, why);
    REQUIRE(op);
    const std::string body = pattern(2u << 20);
    size_t off = 0;
    while (off < body.size())
    {
        const size_t took = op->append(body.data() + off, std::min<size_t>(100000, body.size() - off));
        if (!took)
            break;
        off += took;
    }
    r.settle(20);
    op->abort();
    // The unlink is on the ring, and a loaded disk takes longer than a fixed number of turns.
    CHECK(r.until([&] { return fs::is_empty(d.path + "/bkt/tmp"); }));
    CHECK(r.store->find("bkt", "k") == nullptr);
    // The bucket can be removed again: nothing holds it.
    CHECK(r.drop_bucket("bkt") == st::ok);
}

TEST_CASE("a bucket removed while empty leaves no directory and can be made again")
{
    tmpdir d;
    {
        rig r(d.path);
        REQUIRE(r.make_bucket("gone") == st::ok);
        REQUIRE(r.put("gone", "k", "v").status == st::ok);
        REQUIRE(r.del("gone", "k") == st::ok);
        REQUIRE(r.drop_bucket("gone") == st::ok);
        CHECK_FALSE(fs::exists(d.path + "/gone"));
        REQUIRE(r.make_bucket("gone") == st::ok);
        std::string got;
        CHECK(r.get("gone", "k", got) == st::no_such_key);
        r.settle();
    }
    rig again(d.path);
    CHECK(again.store->has_bucket("gone"));
    // The renamed directory was removed at this start.
    CHECK(fs::is_empty(d.path + "/.trash"));
}

TEST_CASE("prefix successor jumps over a whole rolled-up prefix even with high bytes")
{
    tmpdir d;
    rig r(d.path);
    REQUIRE(r.make_bucket("bkt") == st::ok);
    const std::string hi = std::string("a\xFF") + "/x";
    for (const std::string& k : {std::string("a\xFF") + "/1", hi, std::string("a\xFF") + "/z",
                                 std::string("bkt")})
        REQUIRE(r.put("bkt", k, "1").status == st::ok);
    list_query q;
    q.delimiter = "/";
    list_page p;
    REQUIRE(r.store->list("bkt", q, p) == st::ok);
    CHECK(keys_of(p) == std::vector<std::string>{"bkt"});
    CHECK(p.prefixes == std::vector<std::string>{std::string("a\xFF") + "/"});
}

namespace {

size_t count_dirs(const std::string& p)
{
    size_t n = 0;
    for (const auto& e : fs::directory_iterator(p))
        n += e.is_directory() ? 1 : 0;
    return n;
}

}   // namespace

TEST_CASE("a bucket has its 256 object directories from the start and a put makes none")
{
    tmpdir d;
    rig r(d.path);
    REQUIRE(r.make_bucket("bkt") == st::ok);
    CHECK(count_dirs(d.path + "/bkt/data") == 256);
    const uint64_t synced = r.store->totals().fsyncs;
    for (int i = 0; i < 200; ++i)
        REQUIRE(r.put("bkt", "key-" + std::to_string(i), "v").status == st::ok);
    CHECK(count_dirs(d.path + "/bkt/data") == 256);
    // Every object is one directory down, at the first two hex digits of its hash.
    const std::string h = key_hash("key-7");
    CHECK(fs::exists(d.path + "/bkt/data/" + h.substr(0, 2) + "/" + h));
    // No put synced a directory it had to make: file, directory and journal, at most.
    CHECK(r.store->totals().fsyncs - synced <= 3u * 200u);
}

TEST_CASE("puts one after another sync their file and directory and no journal between them")
{
    tmpdir d;
    rig r(d.path);
    REQUIRE(r.make_bucket("bkt") == st::ok);
    REQUIRE(r.put("bkt", "first", "v").status == st::ok);
    REQUIRE(r.until([&] { return !r.store->busy(); }));
    const uint64_t synced  = r.store->totals().fsyncs;
    const uint64_t written = fs::file_size(journal_path(d.path, "bkt"));
    for (int i = 0; i < 20; ++i)
        REQUIRE(r.put("bkt", "key-" + std::to_string(i), "v").status == st::ok);
    REQUIRE(r.until([&] { return !r.store->busy(); }));
    // A journal sync issued behind each answer would be waited for by the next put's own.
    CHECK(r.store->totals().fsyncs - synced == 2u * 20u);
    // The records are written all the same, and only their sync is left for later.
    CHECK(fs::file_size(journal_path(d.path, "bkt")) > written);
}

TEST_CASE("an answered put and an answered delete survive the loss of the journal behind them")
{
    tmpdir d;
    uint64_t after_a = 0;
    {
        rig r(d.path);
        REQUIRE(r.make_bucket("bkt") == st::ok);
        REQUIRE(r.put("bkt", "a", "first").status == st::ok);
        r.settle();
        after_a = fs::file_size(journal_path(d.path, "bkt"));
        // Answered, and the journal has not necessarily heard of them yet.
        REQUIRE(r.put("bkt", "b", "second").status == st::ok);
        REQUIRE(r.put("bkt", "c", "third").status == st::ok);
        REQUIRE(r.del("bkt", "a") == st::ok);
        r.settle();
    }
    // What a crash may leave: the journal as it was after the first put only.
    fs::resize_file(journal_path(d.path, "bkt"), after_a);
    REQUIRE_FALSE(fs::exists(d.path + "/.clean.0"));

    rig again(d.path);
    CHECK_FALSE(again.report.clean_start);
    std::string got;
    // The delete was answered, the file is gone, and the record that said so is not needed.
    CHECK(again.get("bkt", "a", got) == st::no_such_key);
    CHECK(again.get("bkt", "b", got) == st::ok);
    CHECK(got == "second");
    CHECK(again.get("bkt", "c", got) == st::ok);
    CHECK(got == "third");
    list_query q;
    list_page p;
    REQUIRE(again.store->list("bkt", q, p) == st::ok);
    CHECK(keys_of(p) == std::vector<std::string>{"b", "c"});
    CHECK(again.report.dropped == 1);
    CHECK(again.report.adopted == 2);
}

TEST_CASE("a clean stop right behind the last answer still leaves a journal the next start trusts")
{
    tmpdir d;
    {
        rig r(d.path);
        REQUIRE(r.make_bucket("bkt") == st::ok);
        for (int i = 0; i < 20; ++i)
            REQUIRE(r.put("bkt", "k" + std::to_string(i), "v").status == st::ok);
        REQUIRE(r.del("bkt", "k3") == st::ok);
        // No settling: the records of the last answers may still be queued.
        r.store->close(true);
    }
    REQUIRE(fs::exists(d.path + "/.clean.0"));
    rig again(d.path);
    CHECK(again.report.clean_start);
    CHECK(again.report.adopted == 0);
    CHECK(again.report.dropped == 0);
    // The listing is the journal's, since nothing was walked: the last delete must be in it.
    list_query q;
    list_page p;
    REQUIRE(again.store->list("bkt", q, p) == st::ok);
    CHECK(p.objects.size() == 19);
    CHECK(again.store->find("bkt", "k3") == nullptr);
    CHECK(again.store->find("bkt", "k19") != nullptr);
}

TEST_CASE("an object directory that has gone is made again by the next put and by the next start")
{
    tmpdir d;
    const std::string h = key_hash("lost");
    {
        rig r(d.path);
        REQUIRE(r.make_bucket("bkt") == st::ok);
        fs::remove(d.path + "/bkt/data/" + h.substr(0, 2));
        // Nothing is in it, so the put has to make it.
        REQUIRE(r.put("bkt", "lost", "body").status == st::ok);
        std::string got;
        REQUIRE(r.get("bkt", "lost", got) == st::ok);
        CHECK(got == "body");
        r.settle();
    }
    fs::remove_all(d.path + "/bkt/data/00");
    rig again(d.path);
    CHECK(count_dirs(d.path + "/bkt/data") == 256);
    std::string got;
    CHECK(again.get("bkt", "lost", got) == st::ok);
}

TEST_CASE("a copy of an object file away from its key's path does not stand in for a file that is gone")
{
    tmpdir d;
    {
        rig r(d.path);
        REQUIRE(r.make_bucket("bkt") == st::ok);
        REQUIRE(r.put("bkt", "a", "alpha").status == st::ok);
        REQUIRE(r.put("bkt", "b", "beta").status == st::ok);
        r.settle();
    }
    // A delete of b whose record never landed, and a copy of a's file in a
    // directory its key does not lead to: as many whole files as records.
    fs::remove(data_path(d.path, "bkt", "b"));
    const std::string h     = key_hash("a");
    const std::string other = h.substr(0, 2) == "00" ? "01" : "00";
    fs::copy_file(data_path(d.path, "bkt", "a"), d.path + "/bkt/data/" + other + "/" + h);

    rig again(d.path);
    CHECK_FALSE(again.report.clean_start);
    CHECK(again.report.dropped == 1);
    CHECK(again.store->find("bkt", "b") == nullptr);
    CHECK(again.store->find("bkt", "a") != nullptr);
    list_page p;
    REQUIRE(again.store->list("bkt", {}, p) == st::ok);
    CHECK(keys_of(p) == std::vector<std::string>{"a"});
}

TEST_CASE("an overwrite of the same size whose journal record never landed serves the new object")
{
    tmpdir d;
    {
        rig r(d.path);
        REQUIRE(r.make_bucket("bkt") == st::ok);
        REQUIRE(r.put("bkt", "k", "old-body").status == st::ok);
        r.settle();
    }
    const std::string jbefore = slurp(journal_path(d.path, "bkt"));
    {
        rig r(d.path);
        REQUIRE(r.put("bkt", "k", "new-body").status == st::ok);
        r.settle();
    }
    spill(journal_path(d.path, "bkt"), jbefore);

    // Same name and same size as the record says, so only the header tells them apart.
    rig again(d.path);
    CHECK(again.report.adopted == 1);
    const object_meta* m = again.store->find("bkt", "k");
    REQUIRE(m != nullptr);
    CHECK(m->md5 == md5_of("new-body"));
    std::string got;
    REQUIRE(again.get("bkt", "k", got) == st::ok);
    CHECK(got == "new-body");
}

namespace {

// Sets an environment variable for as long as it lives.
struct env_var
{
    std::string name;
    env_var(const char* n, const char* v) : name(n) { ::setenv(n, v, 1); }
    ~env_var() { ::unsetenv(name.c_str()); }
};

void crash_start_everywhere()
{
    tmpdir d;
    const char* buckets[] = {"bkt-a", "bkt-b", "bkt-c"};
    std::map<std::string, uint64_t> half;
    {
        rig r(d.path);
        for (const char* b : buckets)
        {
            REQUIRE(r.make_bucket(b) == st::ok);
            for (int i = 0; i < 300; ++i)
                REQUIRE(r.put(b, "key-" + std::to_string(i), std::string(b) + std::to_string(i)).status == st::ok);
        }
        r.settle();
        for (const char* b : buckets)
            half[b] = fs::file_size(journal_path(d.path, b));
        for (const char* b : buckets)
        {
            for (int i = 300; i < 600; ++i)
                REQUIRE(r.put(b, "key-" + std::to_string(i), std::string(b) + std::to_string(i)).status == st::ok);
            for (int i = 0; i < 100; ++i)
                REQUIRE(r.del(b, "key-" + std::to_string(i)) == st::ok);
            // An overwrite of the same size, which only the header tells from the record.
            for (int i = 100; i < 150; ++i)
                REQUIRE(r.put(b, "key-" + std::to_string(i), std::string(b) + "Z" + std::to_string(i).substr(1)).status == st::ok);
        }
        r.settle();
    }
    // The journals as they were half way, which is what a crash that lost the last group commits leaves.
    for (const char* b : buckets)
        fs::resize_file(journal_path(d.path, b), half[b]);

    rig again(d.path);
    CHECK_FALSE(again.report.clean_start);
    CHECK(again.report.objects == 3u * 500u);
    CHECK(again.report.dropped == 3u * 100u);
    CHECK(again.report.adopted == 3u * (300u + 50u));
    for (const char* b : buckets)
        for (int i = 0; i < 600; ++i)
        {
            const std::string key = "key-" + std::to_string(i);
            const object_meta* m  = again.store->find(b, key);
            INFO(b << " " << key);
            if (i < 100)
            {
                CHECK(m == nullptr);
                continue;
            }
            REQUIRE(m != nullptr);
            const std::string body = i < 150 ? std::string(b) + "Z" + std::to_string(i).substr(1)
                                             : std::string(b) + std::to_string(i);
            CHECK(m->md5 == md5_of(body));
        }
}

size_t open_fds()
{
    size_t n = 0;
    for ([[maybe_unused]] const auto& e : fs::directory_iterator("/proc/self/fd"))
        ++n;
    return n;
}

}   // namespace

TEST_CASE("a start after a crash finds every adoption and every loss in every object directory of every bucket")
{
    // As many threads as CPUs with many headers in flight, then one thread
    // reading one file at a time, then several threads one file each through a ring.
    SUBCASE("the default walk") { crash_start_everywhere(); }
    SUBCASE("one thread, no ring")
    {
        env_var t("SOCKETLEY_STORAGE_RECOVERY_THREADS", "1");
        env_var w("SOCKETLEY_STORAGE_RECOVERY_DEPTH", "0");
        crash_start_everywhere();
    }
    SUBCASE("three threads, one file in flight each")
    {
        env_var t("SOCKETLEY_STORAGE_RECOVERY_THREADS", "3");
        env_var w("SOCKETLEY_STORAGE_RECOVERY_DEPTH", "1");
        crash_start_everywhere();
    }
}

TEST_CASE("the walk of the object files keeps within the descriptors RLIMIT_NOFILE leaves and finds every object")
{
    tmpdir d;
    {
        rig r(d.path);
        REQUIRE(r.make_bucket("bkt") == st::ok);
        r.store->close(true);
    }
    // Written straight into place, some twenty to a directory, and no journal
    // knows them, as a crash that took every record leaves them.
    constexpr int count = 5000;
    for (int i = 0; i < count; ++i)
    {
        const std::string key = "k" + std::to_string(i);
        object_meta m;
        m.size = 1;
        m.md5  = md5_of("v");
        spill(data_path(d.path, "bkt", key), encode_object_header(key, m) + "v");
    }
    fs::remove(d.path + "/.clean.0");

    // In a child, since a hard limit once lowered stays lowered, and after the
    // ring, whose table of registered files the limit would refuse.
    const pid_t pid = ::fork();
    REQUIRE(pid >= 0);
    if (pid == 0)
    {
        struct quiet : io_handler
        {
            void on_cqe(struct io_uring_cqe*) override {}
        } h;
        event_loop loop{256};
        if (!loop.init())
            ::_exit(10);
        file_io io(loop, &h);
        // Room for the store and a few files more, far fewer than the threads would hold at full depth.
        struct rlimit low{};
        low.rlim_cur = low.rlim_max = open_fds() + 12;
        if (::setrlimit(RLIMIT_NOFILE, &low) < 0)
            ::_exit(11);
        store_options o;
        o.dir = d.path;
        object_store s(loop, io, o);
        recovery_report rep;
        std::string err;
        if (!s.open(err, &rep))
        {
            std::fprintf(stderr, "open: %s\n", err.c_str());
            ::_exit(12);
        }
        const bool good = !rep.clean_start && rep.objects == count && rep.adopted == count &&
                          s.find("bkt", "k4999") != nullptr;
        s.close(false);
        ::_exit(good ? 0 : 13);
    }
    int status = 0;
    REQUIRE(::waitpid(pid, &status, 0) == pid);
    REQUIRE(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0);
}

TEST_CASE("a body hashed on the pool's threads stores the same bytes and the same ETag as one hashed in line")
{
    tmpdir d;
    rig r(d.path, 4096, 0, 2);
    REQUIRE(r.make_bucket("bkt") == st::ok);
    // Below, at and above the size from which a body is handed to the pool, and
    // several buffers long, so digest jobs are outstanding when the next bytes arrive.
    for (size_t size : {size_t{100} * 1024, size_t{256} * 1024 - 1, size_t{256} * 1024, size_t{3} * 1024 * 1024 + 17,
                        size_t{9} * 1024 * 1024})
    {
        const std::string body = pattern(size, static_cast<unsigned>(size));
        const uint64_t before = r.pool->submitted();
        const put_result res = r.put("bkt", "k" + std::to_string(size), body, {}, 70001);
        REQUIRE(res.status == st::ok);
        CHECK(res.meta.md5 == md5_of(body));
        CHECK(res.meta.size == size);
        std::string got;
        REQUIRE(r.get("bkt", "k" + std::to_string(size), got) == st::ok);
        CHECK(got == body);
        if (size >= 256 * 1024)
            CHECK(r.pool->submitted() > before);
        else
            CHECK(r.pool->submitted() == before);
    }
}

TEST_CASE("a digest that disagrees with the body refuses it after the pool has finished, and leaves nothing")
{
    tmpdir d;
    rig r(d.path, 4096, 0, 2);
    REQUIRE(r.make_bucket("bkt") == st::ok);
    const std::string body = pattern(2 * 1024 * 1024, 5);
    const md5_t wrong = md5_of("something else");
    CHECK(r.put("bkt", "bad", body, {}, 100000, &wrong).status == st::bad_digest);
    std::string got;
    CHECK(r.get("bkt", "bad", got) == st::no_such_key);
    // The unlink is on the ring, and a loaded disk takes longer than a fixed number of turns.
    CHECK(r.until([&] { return fs::is_empty(d.path + "/bkt/tmp"); }));
    const md5_t right = md5_of(body);
    CHECK(r.put("bkt", "good", body, {}, 100000, &right).status == st::ok);
}

TEST_CASE("a body given up while the pool is still reading it leaves no temporary file and a store that stops cleanly")
{
    tmpdir d;
    {
        rig r(d.path, 4096, 0, 2);
        REQUIRE(r.make_bucket("bkt") == st::ok);
        st why = st::ok;
        const std::string body = pattern(4 * 1024 * 1024, 9);
        auto op = r.store->begin_put("bkt", "half", {}, body.size(), true, why);
        REQUIRE(op);
        size_t off = 0;
        for (int i = 0; i < 6 && off < body.size(); ++i)
            off += op->append(body.data() + off, 300000);
        // Digest jobs are queued or running for what was appended.
        op->abort();
        op.reset();
        // The unlink is on the ring, and a loaded disk takes longer than a fixed number of turns.
        CHECK(r.until([&] { return fs::is_empty(d.path + "/bkt/tmp"); }));
        std::string got;
        CHECK(r.get("bkt", "half", got) == st::no_such_key);
        // A put after the abandoned one still goes through the pool.
        const std::string ok = pattern(1024 * 1024, 3);
        CHECK(r.put("bkt", "after", ok).status == st::ok);
    }
}

TEST_CASE("a hot copy answers only the version the index names, and keeps within its budget")
{
    tmpdir d;
    ::setenv("SOCKETLEY_STORAGE_HOT_BYTES", "10000", 1);
    rig r(d.path);
    ::unsetenv("SOCKETLEY_STORAGE_HOT_BYTES");
    REQUIRE(r.make_bucket("bkt") == st::ok);

    const std::string v1 = pattern(3000, 1), v2 = pattern(3000, 2);
    REQUIRE(r.put("bkt", "k", v1).status == st::ok);
    const object_meta m1 = *r.store->find("bkt", "k");
    r.store->hot_put("bkt", "k", m1, v1);
    const std::string* hot = r.store->hot_get("bkt", "k", m1);
    REQUIRE(hot != nullptr);
    CHECK(*hot == v1);

    // A read of the old file that finishes after the overwrite committed.
    REQUIRE(r.put("bkt", "k", v2).status == st::ok);
    const object_meta m2 = *r.store->find("bkt", "k");
    r.store->hot_put("bkt", "k", m1, v1);
    CHECK(r.store->hot_bytes() == 0);
    CHECK(r.store->hot_get("bkt", "k", m2) == nullptr);

    // A copy whose version is not the one asked for is dropped, not answered.
    r.store->hot_put("bkt", "k", m2, v2);
    REQUIRE(r.store->hot_get("bkt", "k", m2) != nullptr);
    CHECK(r.store->hot_get("bkt", "k", m1) == nullptr);
    CHECK(r.store->hot_bytes() == 0);

    // The least recently answered go first, as many as the budget needs.
    auto warm = [&](const char* k, size_t n)
    {
        const std::string body = pattern(n, static_cast<unsigned>(k[0]));
        REQUIRE(r.put("bkt", k, body).status == st::ok);
        r.store->hot_put("bkt", k, *r.store->find("bkt", k), body);
    };
    auto held = [&](const char* k) { return r.store->hot_get("bkt", k, *r.store->find("bkt", k)) != nullptr; };
    warm("a", 3000);
    warm("b", 3000);
    warm("c", 3000);
    REQUIRE(held("a"));
    warm("d", 6000);
    CHECK(r.store->hot_bytes() <= 10000);
    CHECK(held("a"));
    CHECK_FALSE(held("b"));
    CHECK_FALSE(held("c"));
    CHECK(held("d"));

    // The one-lookup form names the index's own record, and follows it through an overwrite.
    r.store->hot_put("bkt", "k", *r.store->find("bkt", "k"), v2);
    object_store::hot_hit hit;
    REQUIRE(r.store->hot_find("bkt", "k", hit));
    CHECK(hit.meta == r.store->find("bkt", "k"));
    CHECK(*hit.body == v2);
    REQUIRE(r.put("bkt", "k", v1).status == st::ok);
    CHECK_FALSE(r.store->hot_find("bkt", "k", hit));
    r.store->hot_put("bkt", "k", *r.store->find("bkt", "k"), v1);
    REQUIRE(r.store->hot_find("bkt", "k", hit));
    CHECK(hit.meta == r.store->find("bkt", "k"));
    CHECK(*hit.body == v1);

    for (const char* k : {"a", "b", "c", "d", "k"})
        REQUIRE(r.del("bkt", k) == st::ok);
    CHECK(r.store->hot_bytes() == 0);
}

TEST_CASE("a copy of another shard's key is kept unless a drop of it arrived while it was being read")
{
    tmpdir d;
    rig r(d.path);
    REQUIRE(r.make_bucket("bkt") == st::ok);

    auto meta_of = [](const std::string& body) { object_meta m; m.size = body.size(); m.md5 = md5_of(body); return m; };
    auto held = [&](const char* k, std::string* body = nullptr)
    {
        object_store::hot_hit hit;
        const bool h = r.store->hot_find("bkt", k, hit);
        if (h)
            CHECK(hit.foreign);
        if (h && body)
            *body = *hit.body;
        return h;
    };
    const std::string v1 = pattern(2000, 1), v2 = pattern(2000, 2);

    // A read with no drop in between is kept and answered whole.
    uint64_t e = r.store->hot_epoch();
    r.store->hot_put_foreign("bkt", "k", e, meta_of(v1), v1);
    std::string got;
    REQUIRE(held("k", &got));
    CHECK(got == v1);
    CHECK(r.store->hot_bytes() > 0);

    // The owner's word drops it, and the next read keeps the new version.
    r.store->hot_invalidate("bkt", "k");
    CHECK_FALSE(held("k"));
    CHECK(r.store->hot_bytes() == 0);
    r.store->hot_put_foreign("bkt", "k", r.store->hot_epoch(), meta_of(v2), v2);
    REQUIRE(held("k", &got));
    CHECK(got == v2);

    // A read that began before the drop and ended after it may hold the version the drop replaced.
    e = r.store->hot_epoch();
    r.store->hot_invalidate("bkt", "k");
    r.store->hot_put_foreign("bkt", "k", e, meta_of(v1), v1);
    CHECK_FALSE(held("k"));

    // A drop of another key does not spoil the read of this one.
    e = r.store->hot_epoch();
    r.store->hot_invalidate("bkt", "other");
    r.store->hot_put_foreign("bkt", "k", e, meta_of(v2), v2);
    CHECK(held("k"));
    r.store->hot_invalidate("bkt", "k");

    // A read that outlasted more drops than are remembered is not trusted.
    e = r.store->hot_epoch();
    r.store->hot_invalidate("bkt", "k");
    for (int i = 0; i < 70; ++i)
        r.store->hot_invalidate("bkt", "filler" + std::to_string(i));
    r.store->hot_put_foreign("bkt", "k", e, meta_of(v1), v1);
    CHECK_FALSE(held("k"));

    // A bucket dropped and made again is every key's drop.
    e = r.store->hot_epoch();
    REQUIRE(r.drop_bucket("bkt") == st::ok);
    REQUIRE(r.make_bucket("bkt") == st::ok);
    r.store->hot_put_foreign("bkt", "k", e, meta_of(v1), v1);
    CHECK_FALSE(held("k"));
    // and a bucket that is not there keeps nothing
    e = r.store->hot_epoch();
    r.store->hot_put_foreign("nobkt", "k", e, meta_of(v1), v1);
    CHECK(r.store->hot_bytes() == 0);

    // The budget and the size cap hold for these as for the owner's.
    r.store->hot_put_foreign("bkt", "big", r.store->hot_epoch(), meta_of(std::string(60001, 'x')), std::string(60001, 'x'));
    CHECK_FALSE(held("big"));
    r.store->hot_put_foreign("bkt", "short", r.store->hot_epoch(), meta_of(v1), std::string_view(v1).substr(0, 10));
    CHECK_FALSE(held("short"));
}

TEST_CASE("the HTTP and XML dates agree with gmtime and strftime across leap days, centuries and millis")
{
    auto reference = [](int64_t ms, const char* fmt, bool frac)
    {
        const time_t s = static_cast<time_t>(ms / 1000);
        struct tm tm{};
        gmtime_r(&s, &tm);
        char buf[64];
        std::string out(buf, std::strftime(buf, sizeof buf, fmt, &tm));
        if (frac)
        {
            std::snprintf(buf, sizeof buf, ".%03dZ", static_cast<int>(ms % 1000));
            out += buf;
        }
        return out;
    };
    std::vector<int64_t> at = {0, 999, 1000, 86399999, 86400000, 951782400000, 951868799999, 951868800000,
                               4107542400000, 4107628800000, 1790467200123, 253402300799999};
    uint64_t x = 0x9e3779b97f4a7c15ull;
    for (int i = 0; i < 200000; ++i)
    {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        at.push_back(static_cast<int64_t>(x % 253402300800000ull));
    }
    size_t bad = 0;
    for (const int64_t ms : at)
    {
        const std::string h = http_date(ms), w = reference(ms, "%a, %d %b %Y %H:%M:%S GMT", false);
        const std::string i = iso8601(ms), v = reference(ms, "%Y-%m-%dT%H:%M:%S", true);
        if (h != w || i != v)
        {
            if (++bad <= 3)
                FAIL_CHECK(ms << ": " << h << " / " << w << ", " << i << " / " << v);
        }
    }
    CHECK(bad == 0);
}

namespace {

// The listing as it was written before it was built in place: a string per piece, joined.
std::string reference_escape(std::string_view in)
{
    std::string out;
    for (unsigned char c : in)
    {
        switch (c)
        {
            case '&':  out += "&amp;"; break;
            case '<':  out += "&lt;"; break;
            case '>':  out += "&gt;"; break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default:
                if (c < 0x20 && c != '\t' && c != '\n' && c != '\r')
                {
                    char buf[12];
                    std::snprintf(buf, sizeof buf, "&#x%X;", c);
                    out += buf;
                }
                else
                    out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

std::string reference_url_encode(std::string_view in)
{
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : in)
    {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || c == '/')
            out.push_back(static_cast<char>(c));
        else
        {
            out.push_back('%');
            out.push_back(digits[c >> 4]);
            out.push_back(digits[c & 15]);
        }
    }
    return out;
}

std::string reference_list_xml(const list_render& r, const list_page& p)
{
    const auto enc = [&](std::string_view s)
    {
        return reference_escape(r.url_encode_keys ? reference_url_encode(s) : std::string(s));
    };
    std::string x(xml_decl);
    x += "<ListBucketResult xmlns=\"" + std::string(s3_xmlns) + "\">";
    x += "<Name>" + reference_escape(r.bucket) + "</Name>";
    x += "<Prefix>" + enc(r.prefix) + "</Prefix>";
    if (r.v2)
    {
        if (!r.continuation_token.empty())
            x += "<ContinuationToken>" + reference_escape(r.continuation_token) + "</ContinuationToken>";
        if (p.truncated && !r.next_token.empty())
            x += "<NextContinuationToken>" + reference_escape(r.next_token) + "</NextContinuationToken>";
        x += "<KeyCount>" + std::to_string(p.objects.size() + p.prefixes.size()) + "</KeyCount>";
    }
    else
        x += "<Marker>" + enc(r.marker) + "</Marker>";
    x += "<MaxKeys>" + std::to_string(r.max_keys) + "</MaxKeys>";
    if (!r.delimiter.empty())
        x += "<Delimiter>" + enc(r.delimiter) + "</Delimiter>";
    if (r.url_encode_keys)
        x += "<EncodingType>url</EncodingType>";
    x += std::string("<IsTruncated>") + (p.truncated ? "true" : "false") + "</IsTruncated>";
    if (!r.v2 && p.truncated && !r.delimiter.empty() && !r.next_marker.empty())
        x += "<NextMarker>" + enc(r.next_marker) + "</NextMarker>";
    if (r.v2 && !r.start_after.empty())
        x += "<StartAfter>" + enc(r.start_after) + "</StartAfter>";
    for (const list_entry& e : p.objects)
    {
        x += "<Contents><Key>" + enc(e.key) + "</Key><LastModified>" + iso8601(e.meta.mtime_ms) +
             "</LastModified><ETag>" + quoted_etag(e.meta) + "</ETag><Size>" +
             std::to_string(e.meta.size) + "</Size>";
        if (!r.v2 || r.fetch_owner)
            x += "<Owner><ID>" + reference_escape(r.owner_id) + "</ID><DisplayName>" +
                 reference_escape(r.owner_id) + "</DisplayName></Owner>";
        x += "<StorageClass>STANDARD</StorageClass></Contents>";
    }
    for (const std::string& c : p.prefixes)
        x += "<CommonPrefixes><Prefix>" + enc(c) + "</Prefix></CommonPrefixes>";
    x += "</ListBucketResult>";
    return x;
}

}   // namespace

TEST_CASE("a listing built in place is the listing built by joining pieces, for every byte a key can hold")
{
    uint64_t x = 0x2545f4914f6cdd1dull;
    const auto next = [&]
    {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        return x;
    };
    // Every byte value is in the alphabet, so the escapes, the percent forms and the
    // control characters all meet a run of plain bytes on both sides.
    const auto text = [&](size_t max)
    {
        std::string s;
        const size_t n = next() % (max + 1);
        for (size_t i = 0; i < n; ++i)
            s.push_back(next() % 3 ? static_cast<char>('a' + next() % 26) : static_cast<char>(next() % 256));
        return s;
    };

    size_t bad = 0;
    for (int round = 0; round < 3000; ++round)
    {
        list_page page;
        const size_t objects = next() % 6, prefixes = next() % 4;
        for (size_t i = 0; i < objects; ++i)
        {
            list_entry e;
            e.key = text(40);
            e.meta.size     = next() % 4 ? next() % 100000 : next();
            e.meta.mtime_ms = static_cast<int64_t>(next() % 253402300800000ull);
            for (auto& b : e.meta.md5)
                b = static_cast<uint8_t>(next());
            e.meta.parts = next() % 3 ? 0 : static_cast<uint32_t>(next() % 10000);
            page.objects.push_back(std::move(e));
        }
        for (size_t i = 0; i < prefixes; ++i)
            page.prefixes.push_back(text(20));
        page.truncated = next() % 2;

        const std::string bucket = text(12), prefix = text(10), delim = text(3), start = text(10),
                          token = text(10), next_token = text(10), marker = text(10), next_marker = text(10);
        list_render r;
        r.bucket             = bucket;
        r.prefix             = prefix;
        r.delimiter          = delim;
        r.start_after        = start;
        r.continuation_token = token;
        r.next_token         = next_token;
        r.marker             = marker;
        r.next_marker        = next_marker;
        r.max_keys           = next() % 1001;
        r.url_encode_keys    = next() % 2;
        r.fetch_owner        = next() % 2;
        r.v2                 = next() % 2;
        r.owner_id           = next() % 2 ? "socketley" : "o<w&ner";

        const std::string want = reference_list_xml(r, page), got = list_xml(r, page);
        if (want != got && ++bad <= 2)
            FAIL_CHECK("round " << round << "\nwant " << want << "\ngot  " << got);
    }
    CHECK(bad == 0);

    // The escape and the url encoder on their own, appended to text already there.
    size_t off = 0;
    for (int i = 0; i < 20000; ++i)
    {
        const std::string s = text(64);
        std::string a = "<", b = "<";
        xml_escape_to(a, s);
        b += reference_escape(s);
        std::string u = "%", v = "%";
        url_encode_to(u, s);
        v += reference_url_encode(s);
        if (a != b || u != v)
            ++off;
    }
    CHECK(off == 0);
}

TEST_CASE("a listing rendered while the index is walked is the listing rendered from the page")
{
    tmpdir d;
    rig r(d.path);
    REQUIRE(r.make_bucket("bkt") == st::ok);
    for (const char* k : {"a", "b/1", "b/2", "b/sub/x", "c", "d/1", "e", "photos/2020/a.jpg",
                          "photos/2020/b.jpg", "photos/2021/c.jpg", "photos/index.html", "z&<>'\"", "z\x01y"})
        REQUIRE(r.put("bkt", k, k).status == st::ok);

    size_t compared = 0;
    for (const char* prefix : {"", "b/", "photos/", "photos/2020/", "nothing"})
        for (const char* delimiter : {"", "/"})
            for (const char* after : {"", "b/2", "c", "photos/"})
                for (const size_t max_keys : {size_t{0}, size_t{1}, size_t{2}, size_t{5}, size_t{1000}})
                    for (const bool v2 : {false, true})
                        for (const bool encode : {false, true})
                        {
                            list_query q;
                            q.prefix      = prefix;
                            q.delimiter   = delimiter;
                            q.start_after = after;
                            q.max_keys    = max_keys;

                            list_page page;
                            REQUIRE(r.store->list("bkt", q, page) == st::ok);

                            list_render lr;
                            lr.bucket          = "bkt";
                            lr.prefix          = prefix;
                            lr.delimiter       = delimiter;
                            lr.max_keys        = max_keys;
                            lr.url_encode_keys = encode;
                            lr.v2              = v2;
                            lr.owner_id        = "socketley";

                            list_xml_writer walk(lr);
                            REQUIRE(r.store->list_walk("bkt", q, walk) == st::ok);

                            // What the S3 handler says about where the page ends, from the page and from the walk.
                            const std::string* last = nullptr;
                            if (!page.objects.empty())
                                last = &page.objects.back().key;
                            if (!page.prefixes.empty() && (!last || page.prefixes.back() > *last))
                                last = &page.prefixes.back();
                            if (last)
                                CHECK((walk.last_named() && *walk.last_named() == *last));
                            else
                                CHECK(walk.last_named() == nullptr);
                            CHECK(walk.is_truncated() == page.truncated);
                            if (page.truncated)
                                CHECK(walk.resume_at() == page.resume_at);

                            CHECK(walk.finish() == list_xml(lr, page));
                            ++compared;
                        }
    CHECK(compared == 5 * 2 * 4 * 5 * 2 * 2);
}

// ─── Pooled files: answered at the rename, rolled forward after a crash ────

TEST_CASE("a plain put takes a pooled file and is answered before its directories are synced")
{
    tmpdir d;
    rig r(d.path);
    r.plain = true;
    REQUIRE(r.make_bucket("bkt") == st::ok);
    // The first finds the pool empty and has it made; its files join once pool/ is synced.
    REQUIRE(r.put("bkt", "first", "v").status == st::ok);
    REQUIRE(r.until([&] { return !r.store->busy() && count_pool_files(d.path, "bkt") > 0; }));
    r.settle(20);
    const size_t pooled = count_pool_files(d.path, "bkt");
    CHECK(pooled >= 8);

    st why = st::ok;
    auto op = r.store->begin_put("bkt", "k", {}, 5, true, why, true);
    REQUIRE(op);
    REQUIRE(op->append("hello", 5) == 5);
    bool fired = false, busy_at_answer = false;
    op->finish(nullptr, [&](put_result res)
    {
        CHECK(res.status == st::ok);
        busy_at_answer = r.store->working();
        fired = true;
    });
    REQUIRE(r.until([&] { return fired; }));
    // The syncs of data/<leaf> and pool/ are still owed when the answer goes.
    CHECK(busy_at_answer);
    CHECK(count_pool_files(d.path, "bkt") == pooled - 1);
    REQUIRE(r.until([&] { return !r.store->working(); }));
    std::string got;
    REQUIRE(r.get("bkt", "k", got) == st::ok);
    CHECK(got == "hello");
    r.store->close(true);
}

TEST_CASE("a put with a condition or a committer never takes a pooled file")
{
    tmpdir d;
    rig r(d.path);
    r.plain = true;
    REQUIRE(r.make_bucket("bkt") == st::ok);
    REQUIRE(r.put("bkt", "first", "v").status == st::ok);
    REQUIRE(r.until([&] { return !r.store->busy() && count_pool_files(d.path, "bkt") > 0; }));
    r.settle(20);
    // A caller that marks a pooled put conditional afterwards is refused rather than rolled forward.
    st why = st::ok;
    auto op = r.store->begin_put("bkt", "k", {}, 1, true, why, true);
    REQUIRE(op);
    op->set_create_only(true);
    CHECK(op->failed());
    // And one that says so at the start writes to a file of its own.
    r.settle(20);
    const size_t pooled = count_pool_files(d.path, "bkt");
    auto op2 = r.store->begin_put("bkt", "k2", {}, 1, true, why, false);
    REQUIRE(op2);
    op2->set_create_only(true);
    CHECK_FALSE(op2->failed());
    CHECK(count_pool_files(d.path, "bkt") == pooled);
    op2->abort();
    r.settle(20);
}

namespace {

// What a crash can leave of an answered pooled put: the new object still under
// its pool name, and the object it replaced still at the key's path.
struct lost_rename
{
    std::string v1, v2, pool_name;
};

lost_rename stage_lost_rename(const std::string& dir, bool clean_stop)
{
    lost_rename s;
    s.v1 = pattern(3000, 1);
    s.v2 = pattern(5000, 2);
    rig r(dir);
    r.plain = true;
    REQUIRE(r.make_bucket("bkt") == st::ok);
    REQUIRE(r.put("bkt", "key", s.v1).status == st::ok);
    REQUIRE(r.until([&] { return !r.store->busy(); }));
    const std::string file_v1 = slurp(data_path(dir, "bkt", "key"));
    REQUIRE(r.put("bkt", "key", s.v2).status == st::ok);
    REQUIRE(r.until([&] { return !r.store->busy(); }));
    r.store->close(clean_stop);
    s.pool_name = "0.00000000000000000000000000000001";
    fs::rename(data_path(dir, "bkt", "key"), dir + "/bkt/pool/" + s.pool_name);
    spill(data_path(dir, "bkt", "key"), file_v1);
    return s;
}

}   // namespace

TEST_CASE("an answered pooled put whose rename a crash took is rolled forward by the next start")
{
    for (const bool clean : {false, true})
    {
        INFO("clean stop " << clean);
        tmpdir d;
        const lost_rename s = stage_lost_rename(d.path, clean);
        rig again(d.path);
        CHECK(again.report.rolled_forward == 1);
        std::string got;
        REQUIRE(again.get("bkt", "key", got) == st::ok);
        CHECK(got == s.v2);
        // And the index names the version that was rolled forward.
        const object_meta* idx = again.store->find("bkt", "key");
        REQUIRE(idx != nullptr);
        CHECK(idx->md5 == md5_of(s.v2));
        CHECK(idx->size == s.v2.size());
        CHECK(count_pool_files(d.path, "bkt") == 0);
    }
}

TEST_CASE("a pooled file that is not whole is removed and never replaces the object")
{
    for (int variant = 0; variant < 3; ++variant)
    {
        INFO("variant " << variant);
        tmpdir d;
        const lost_rename s = stage_lost_rename(d.path, false);
        const std::string p = d.path + "/bkt/pool/" + s.pool_name;
        std::string f = slurp(p);
        if (variant == 0)
            f[f.size() - 100] ^= 1;          // a page of the body that never reached the disk
        else if (variant == 1)
            f.resize(f.size() - 1);          // cut short
        else
            f = std::string(f.size(), '\0'); // nothing but the length
        spill(p, f);
        rig again(d.path);
        CHECK(again.report.rolled_forward == 0);
        std::string got;
        REQUIRE(again.get("bkt", "key", got) == st::ok);
        CHECK(got == s.v1);
        CHECK(count_pool_files(d.path, "bkt") == 0);
    }
}

TEST_CASE("a whole pooled file of a key another shard owns is left to that shard")
{
    tmpdir d;
    std::string key;
    {
        rig r(d.path);
        REQUIRE(r.make_bucket("bkt") == st::ok);
        r.store->close(true);
    }
    // A key shard 1 of two owns, written by a single-shard run whose rename a crash took.
    {
        rig probe(d.path, 4096, 0, 0, 0, 2);
        for (int i = 0; key.empty(); ++i)
            if (probe.store->owner_of("bkt", "k" + std::to_string(i)) == 1)
                key = "k" + std::to_string(i);
        probe.store->close(true);
    }
    object_meta m;
    m.size = 4;
    m.md5  = md5_of("body");
    const std::string pool_name = "0.00000000000000000000000000000002";
    fs::create_directories(d.path + "/bkt/pool");
    spill(d.path + "/bkt/pool/" + pool_name, encode_object_header(key, m) + "body");
    {
        rig s0(d.path, 4096, 0, 0, 0, 2);
        CHECK(s0.report.rolled_forward == 0);
        CHECK(fs::exists(d.path + "/bkt/pool/" + pool_name));
    }
    rig s1(d.path, 4096, 0, 0, 1, 2);
    CHECK(s1.report.rolled_forward == 1);
    CHECK(s1.store->find("bkt", key) != nullptr);
    CHECK_FALSE(fs::exists(d.path + "/bkt/pool/" + pool_name));
}

TEST_CASE("a pooled file rolled forward on a start that trusts its journal is still indexed")
{
    tmpdir d;
    {
        rig r(d.path);
        REQUIRE(r.make_bucket("bkt") == st::ok);
        REQUIRE(r.put("bkt", "old", "o").status == st::ok);
        r.store->close(true);
    }
    // A whole pooled file its journal never heard of, beside the marker of a clean stop.
    object_meta m;
    m.size = 4;
    m.md5  = md5_of("body");
    fs::create_directories(d.path + "/bkt/pool");
    spill(d.path + "/bkt/pool/0.00000000000000000000000000000004", encode_object_header("new", m) + "body");
    REQUIRE(fs::exists(d.path + "/.clean.0"));

    rig again(d.path);
    CHECK(again.report.clean_start);
    CHECK(again.report.rolled_forward == 1);
    CHECK(again.store->find("bkt", "new") != nullptr);
    CHECK(again.store->find("bkt", "old") != nullptr);
    std::string got;
    REQUIRE(again.get("bkt", "new", got) == st::ok);
    CHECK(got == "body");
}

TEST_CASE("a new pooled put whose rename and journal record a crash both took is in the index after the next start")
{
    tmpdir d;
    const std::string v = pattern(2000, 7);
    std::string journal;
    {
        rig r(d.path);
        r.plain = true;
        for (const char* b : {"bkt", "other"})
        {
            REQUIRE(r.make_bucket(b) == st::ok);
            REQUIRE(r.put(b, "old", "o").status == st::ok);
        }
        REQUIRE(r.put("bkt", "gone", "g").status == st::ok);
        REQUIRE(r.until([&] { return !r.store->busy(); }));
        r.store->close(true);
        journal = slurp(journal_path(d.path, "bkt"));
    }
    {
        rig r(d.path);
        r.plain = true;
        REQUIRE(r.put("bkt", "new", v).status == st::ok);
        REQUIRE(r.del("bkt", "gone") == st::ok);
        REQUIRE(r.until([&] { return !r.store->busy(); }));
    }
    // The record of each comes after its syncs, so a crash may leave neither
    // record, and the new object's file still in pool/ under the name it was taken by.
    spill(journal_path(d.path, "bkt"), journal);
    fs::create_directories(d.path + "/bkt/pool");
    fs::rename(data_path(d.path, "bkt", "new"), d.path + "/bkt/pool/0.00000000000000000000000000000003");
    REQUIRE_FALSE(fs::exists(d.path + "/.clean.0"));

    rig again(d.path);
    CHECK_FALSE(again.report.clean_start);
    CHECK(again.report.rolled_forward == 1);
    CHECK(again.report.dropped == 1);
    const object_meta* m = again.store->find("bkt", "new");
    REQUIRE(m != nullptr);
    CHECK(m->md5 == md5_of(v));
    CHECK(again.store->find("bkt", "gone") == nullptr);
    CHECK(again.store->find("bkt", "old") != nullptr);
    CHECK(again.store->find("other", "old") != nullptr);
    list_page p;
    REQUIRE(again.store->list("bkt", {}, p) == st::ok);
    CHECK(keys_of(p) == std::vector<std::string>{"new", "old"});
}

TEST_CASE("the next operation on a key waits until the pooled put before it is synced")
{
    tmpdir d;
    rig r(d.path);
    r.plain = true;
    REQUIRE(r.make_bucket("bkt") == st::ok);
    REQUIRE(r.put("bkt", "first", "v").status == st::ok);
    REQUIRE(r.until([&] { return !r.store->busy() && count_pool_files(d.path, "bkt") >= 16; }));
    r.settle(20);
    // Eight takes leave the pool above the mark that makes more, so no other sync is counted.
    for (int i = 0; i < 8; ++i)
    {
        INFO("round " << i);
        const std::string key = "k" + std::to_string(i);
        st why = st::ok;
        auto op = r.store->begin_put("bkt", key, {}, 1, true, why, true);
        REQUIRE(op);
        REQUIRE(op->append("x", 1) == 1);
        uint64_t at_answer = 0;
        bool answered = false, deleted = false, early = false;
        op->finish(nullptr, [&](put_result res)
        {
            REQUIRE(res.status == st::ok);
            at_answer = r.store->totals().fsyncs;
            answered  = true;
            r.store->remove("bkt", key, [&](st s, bool)
            {
                CHECK(s == st::ok);
                deleted = true;
            });
        });
        // Watched a completion at a time: the object's file must outlive the put's
        // data/<leaf> and pool/ syncs, since a delete let in at the answer races them
        // and a crash could then roll the put forward over it.
        REQUIRE(r.until([&]
        {
            if (answered && r.store->totals().fsyncs < at_answer + 2 && !fs::exists(data_path(d.path, "bkt", key)))
                early = true;
            return deleted && !r.store->working();
        }));
        CHECK_FALSE(early);
    }
}

TEST_CASE("the version a writer put in a body's header stands unless a newer one of the key was committed first")
{
    tmpdir d;
    rig r(d.path);
    REQUIRE(r.make_bucket("bkt") == st::ok);
    r.set_doc(bucket_doc::versioning, "bkt", "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>");
    REQUIRE(r.put("bkt", "k", "first").status == st::ok);
    // A body written to tmp/ with the version given, handed to the commit as a landing shard hands it.
    auto commit = [&](uint64_t seq, std::string& id)
    {
        char hex[17];
        std::snprintf(hex, sizeof hex, "%016llx", static_cast<unsigned long long>(seq));
        id = std::string(hex) + "0123456789abcdef";
        object_meta m;
        m.size     = 4;
        m.md5      = md5_of("body");
        m.mtime_ms = static_cast<int64_t>(r.store->now_ms());
        set_version_extra(m, version_tag{seq, id, false});
        commit_request req;
        req.bucket   = "bkt";
        req.key      = "k";
        req.tmp_name = r.store->tmp_name();
        req.meta     = m;
        spill(d.path + "/bkt/tmp/" + req.tmp_name, encode_object_header("k", m) + "body");
        put_result out;
        bool done = false;
        r.store->commit(std::move(req), [&](put_result p) { out = std::move(p); done = true; });
        REQUIRE(r.until([&] { return done; }));
        return out;
    };
    auto on_disk = [&]
    {
        std::string body;
        object_meta m;
        REQUIRE(r.get("bkt", "k", body, &m) == st::ok);
        CHECK(body == "body");
        return version_of(m).id;
    };
    const uint64_t newest = version_of(*r.store->find("bkt", "k")).seq;

    // Older than the key's newest, as a writer whose sync ended after a later one's leaves it: the owner gives another.
    std::string stale_id;
    const put_result stale = commit(newest - 1, stale_id);
    REQUIRE(stale.status == st::ok);
    CHECK(version_of(stale.meta).id != stale_id);
    CHECK(version_of(stale.meta).seq > newest);
    CHECK(on_disk() == version_of(stale.meta).id);

    // Newer than every version the key has: kept as the writer wrote it.
    std::string fresh_id;
    const put_result fresh = commit(version_of(stale.meta).seq + 1000, fresh_id);
    REQUIRE(fresh.status == st::ok);
    CHECK(version_of(fresh.meta).id == fresh_id);
    CHECK(on_disk() == fresh_id);

    // Written while the bucket was Enabled, committed by an owner that missed the change to Suspended and settles
    // it from the file first: the version is the null one the file says, not the id the writer chose.
    r.store->doubt_doc(bucket_doc::versioning, "bkt", 7);
    spill(d.path + "/bkt/versioning", "<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>");
    std::string enabled_id;
    const put_result settled = commit(version_of(fresh.meta).seq + 1000, enabled_id);
    REQUIRE(settled.status == st::ok);
    CHECK(r.store->bucket_versioning("bkt") == versioning::suspended);
    CHECK(version_of(settled.meta).id == "null");
    CHECK(on_disk() == "null");
}

TEST_CASE("a versioned bucket's journal holds every version through a compaction, and a clean start reads no file")
{
    tmpdir d;
    using entry = std::tuple<std::string, std::string, bool, std::string>;
    auto listing = [](rig& r)
    {
        version_page p;
        version_query q;
        REQUIRE(r.store->list_versions("bkt", q, p) == st::ok);
        std::vector<entry> out;
        for (const version_item& i : p.items)
            out.emplace_back(i.key, version_of(i.meta).id, i.latest, is_delete_marker(i.meta) ? "" : i.meta.etag());
        return out;
    };
    auto purge = [](rig& r, const std::string& key, const std::string& id)
    {
        bool fired = false;
        r.store->remove_version("bkt", key, id, [&](remove_result rr) { CHECK(rr.status == st::ok); fired = true; });
        REQUIRE(r.until([&] { return fired; }));
    };
    std::vector<entry> before;
    {
        rig r(d.path, /*compact_floor=*/16);
        r.plain = true;
        REQUIRE(r.make_bucket("bkt") == st::ok);
        r.set_doc(bucket_doc::versioning, "bkt",
                  "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>");
        std::vector<std::string> ids;
        for (int i = 0; i < 12; ++i)
        {
            const put_result p = r.put("bkt", "a", "a" + std::to_string(i));
            REQUIRE(p.status == st::ok);
            ids.push_back(version_of(p.meta).id);
        }
        REQUIRE(r.put("bkt", "b", "b").status == st::ok);
        REQUIRE(r.put("bkt", "c", "c").status == st::ok);
        REQUIRE(r.del("bkt", "c") == st::ok);
        // Removed for good: garbage enough for a compaction, which must carry the versions left.
        for (size_t i = 1; i < 10; ++i)
            purge(r, "a", ids[i]);
        r.settle(200);
        CHECK(r.store->totals().compactions >= 1);
        before = listing(r);
        // The latest of a and the two left behind it, b, and c's marker in front of its one version.
        REQUIRE(before.size() == 6);
        r.store->close(true);
    }
    {
        rig r(d.path, 16);
        CHECK(r.report.clean_start);
        CHECK(r.report.files_read == 0);
        CHECK(listing(r) == before);
        std::string got;
        REQUIRE(r.get("bkt", "a", got) == st::ok);
        CHECK(got == "a11");
        // Stopped without its marker, as a crash leaves it.
        r.store->close(false);
    }
    const std::string journal = slurp(journal_path(d.path, "bkt"));
    rig r(d.path, 16);
    CHECK_FALSE(r.report.clean_start);
    // The latest of a and of b, c's marker, a's two versions behind its latest and c's behind its marker.
    CHECK(r.report.files_read == 6);
    CHECK(listing(r) == before);
    // The files said what the journal did, so it was not written again.
    CHECK(slurp(journal_path(d.path, "bkt")) == journal);
}
