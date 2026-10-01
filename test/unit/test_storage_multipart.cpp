#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "runtime/storage/body_reader.h"
#include "runtime/storage/checksum.h"
#include "runtime/storage/multipart.h"
#include "runtime/storage/object_format.h"
#include "runtime/storage/object_store.h"
#include "runtime/storage/s3_multipart_xml.h"
#include "runtime/storage/s3_sigv4_auth.h"
#include "shared/event_loop.h"
#include "shared/file_io.h"
#include "shared/raft_storage.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

// The pieces multipart and SigV4 are made of that need no daemon: the checksums
// and their base64, the XML a client completes an upload with, the credentials
// a runtime is given, and the multipart store on a real ring and directory.

namespace fs = std::filesystem;
using namespace socketley;
using namespace socketley::storage;

namespace {

std::string b64_of(checksum_algo a, std::string_view data)
{
    checksum_stream s(a);
    s.update(data.data(), data.size());
    return s.peek_b64();
}

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

}   // namespace

// ─── Checksums ──────────────────────────────────────────────────────────────

TEST_CASE("the checksums match their published check values")
{
    // "123456789" is the check input every CRC catalogue publishes a value for.
    const std::string in = "123456789";
    CHECK(b64_of(checksum_algo::crc32, in) == base64_encode(std::string("\xCB\xF4\x39\x26", 4)));
    CHECK(b64_of(checksum_algo::crc32c, in) == base64_encode(std::string("\xE3\x06\x92\x83", 4)));
    CHECK(b64_of(checksum_algo::crc64nvme, in) == base64_encode(std::string("\xAE\x8B\x14\x86\x0A\x79\x98\x88", 8)));
    CHECK(b64_of(checksum_algo::sha1, in) == "98O8HYCOBHMq32eZZczDTKeuNEE=");
    CHECK(b64_of(checksum_algo::sha256, "abc") == "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=");
    CHECK(b64_of(checksum_algo::sha1, "abc") == "qZk+NkcGgWq6PiVxeFDCbJzQ2J0=");
    // Empty input is the algorithm's initial value: 0 for a CRC.
    CHECK(b64_of(checksum_algo::crc32, "") == "AAAAAA==");
    CHECK(b64_of(checksum_algo::crc32c, "") == "AAAAAA==");
    CHECK(b64_of(checksum_algo::crc64nvme, "") == "AAAAAAAAAAA=");
}

TEST_CASE("a checksum over pieces is the checksum over the whole, whatever the cuts")
{
    const std::string data = pattern(100003, 7);
    for (checksum_algo a : {checksum_algo::crc32, checksum_algo::crc32c, checksum_algo::crc64nvme,
                            checksum_algo::sha1, checksum_algo::sha256})
    {
        const std::string whole = b64_of(a, data);
        for (size_t piece : {size_t{1}, size_t{7}, size_t{8}, size_t{9}, size_t{4096}, size_t{65537}})
        {
            checksum_stream s(a);
            for (size_t off = 0; off < data.size(); off += piece)
                s.update(data.data() + off, std::min(piece, data.size() - off));
            INFO(checksum_name(a) << " in pieces of " << piece);
            CHECK(s.peek_b64() == whole);
        }
        // Peeking leaves the stream where it was.
        checksum_stream s(a);
        s.update(data.data(), 10);
        (void)s.peek_b64();
        s.update(data.data() + 10, data.size() - 10);
        CHECK(s.peek_b64() == whole);
        CHECK(whole.size() == checksum_b64_len(a));
    }
}

TEST_CASE("crc32c takes the same value on the hardware path and the table path for every length and alignment")
{
    const std::string data = pattern(300, 3);
    // The table path is the raft one, which is what the object header is checksummed with.
    for (size_t off = 0; off < 9; ++off)
        for (size_t len = 0; len < 40; ++len)
        {
            checksum_stream s(checksum_algo::crc32c);
            s.update(data.data() + off, len);
            const uint32_t want = raft::storage::crc32c(data.data() + off, len);
            std::string raw = s.peek_raw();
            uint32_t got = 0;
            for (unsigned char ch : raw)
                got = (got << 8) | ch;
            INFO("off " << off << " len " << len);
            CHECK(got == want);
        }
}

TEST_CASE("the header and the name of each algorithm find each other")
{
    for (checksum_algo a : {checksum_algo::crc32, checksum_algo::crc32c, checksum_algo::crc64nvme,
                            checksum_algo::sha1, checksum_algo::sha256})
    {
        CHECK(checksum_from_header(checksum_header(a)) == a);
        CHECK(checksum_from_name(checksum_name(a)) == a);
        CHECK(is_checksum_header(checksum_header(a)));
    }
    CHECK(checksum_from_name("crc32c") == checksum_algo::crc32c);
    CHECK(checksum_from_name("CRC32X") == checksum_algo::none);
    CHECK(checksum_from_header("x-amz-checksum-md5") == checksum_algo::none);
    // The headers that share the prefix and carry no value.
    CHECK(!is_checksum_header("x-amz-checksum-algorithm"));
    CHECK(!is_checksum_header("x-amz-checksum-mode"));
    CHECK(is_checksum_header("x-amz-checksum-md5"));
    CHECK(!is_checksum_header("x-amz-meta-checksum"));
}

TEST_CASE("base64 round-trips and refuses what an encoder would not write")
{
    for (size_t n = 0; n < 40; ++n)
    {
        const std::string in = pattern(n, 5);
        std::string out;
        REQUIRE(base64_decode(base64_encode(in), out));
        CHECK(out == in);
    }
    std::string out;
    CHECK(base64_encode("") == "");
    CHECK(base64_encode("f") == "Zg==");
    CHECK(base64_encode("fo") == "Zm8=");
    CHECK(base64_encode("foo") == "Zm9v");
    CHECK(!base64_decode("Zm9", out));
    CHECK(!base64_decode("Zg=", out));
    CHECK(!base64_decode("Zg===", out));
    CHECK(!base64_decode("Z=g=", out));
    CHECK(!base64_decode("Zm9v!", out));
    CHECK(!base64_decode("Zm 9", out));
}

TEST_CASE("the composite checksum is the algorithm over the part checksums, with the part count")
{
    const std::string a = pattern(50, 1), b = pattern(60, 2);
    const std::string raw = [&] {
        checksum_stream x(checksum_algo::sha256), y(checksum_algo::sha256);
        x.update(a.data(), a.size());
        y.update(b.data(), b.size());
        return x.peek_raw() + y.peek_raw();
    }();
    const std::string got = composite_checksum_b64(checksum_algo::sha256, raw, 2);
    CHECK(got.ends_with("-2"));
    CHECK(got.substr(0, got.size() - 2) == b64_of(checksum_algo::sha256, raw));
}

// ─── The part list of CompleteMultipartUpload ───────────────────────────────

TEST_CASE("a CompleteMultipartUpload document is read for its parts, numbers, ETags and checksums")
{
    std::vector<complete_part> parts;
    REQUIRE(parse_complete_request(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
        "<Part><PartNumber>1</PartNumber><ETag>&quot;abc&quot;</ETag><ChecksumCRC32>AAAAAA==</ChecksumCRC32></Part>"
        "<Part><ETag>\"def\"</ETag><PartNumber>2</PartNumber></Part>"
        "<Part><PartNumber>10000</PartNumber><ETag>W/\"ghi\"</ETag></Part>"
        "</CompleteMultipartUpload>", parts));
    REQUIRE(parts.size() == 3);
    CHECK(parts[0].number == 1);
    CHECK(parts[0].etag == "abc");
    CHECK(parts[0].checksum_algo_ == checksum_algo::crc32);
    CHECK(parts[0].checksum_b64 == "AAAAAA==");
    CHECK(parts[1].number == 2);
    CHECK(parts[1].etag == "def");
    CHECK(parts[1].checksum_algo_ == checksum_algo::none);
    CHECK(parts[2].number == 10000);
    CHECK(parts[2].etag == "ghi");

    CHECK(parse_complete_request("<CompleteMultipartUpload/>", parts) == false);
    REQUIRE(parse_complete_request("<CompleteMultipartUpload></CompleteMultipartUpload>", parts));
    CHECK(parts.empty());
    CHECK(!parse_complete_request("<Delete></Delete>", parts));
    CHECK(!parse_complete_request("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber></Part></CompleteMultipartUpload>", parts));
    CHECK(!parse_complete_request("<CompleteMultipartUpload><Part><ETag>x</ETag></Part></CompleteMultipartUpload>", parts));
    CHECK(!parse_complete_request("<CompleteMultipartUpload><Part><PartNumber>x</PartNumber><ETag>y</ETag></Part></CompleteMultipartUpload>", parts));
    CHECK(!parse_complete_request("<CompleteMultipartUpload><Part><PartNumber>-1</PartNumber><ETag>y</ETag></Part></CompleteMultipartUpload>", parts));
    CHECK(!parse_complete_request("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>y", parts));
    CHECK(!parse_complete_request("", parts));
    CHECK(!parse_complete_request("not xml at all", parts));
}

// ─── Credentials ────────────────────────────────────────────────────────────

TEST_CASE("a credentials file is one access:secret per line, and the secret is the rest of the line")
{
    credential_set set;
    std::string err;
    REQUIRE(parse_credentials("# keys\n\nAKA:secretA\n  AKB : secretB  \r\nAKC:sec:ret:c\n", set, err));
    CHECK(set.size() == 3);
    CHECK(set.secret("AKA") == "secretA");
    CHECK(set.secret("AKB") == "secretB");
    CHECK(set.secret("AKC") == "sec:ret:c");
    CHECK(set.secret("AKD").empty());
    CHECK(set.secret("").empty());

    credential_set again;
    REQUIRE(parse_credentials("AKA:one\nAKA:two\n", again, err));
    CHECK(again.size() == 1);
    CHECK(again.secret("AKA") == "two");

    for (const char* bad : {"no colon here\n", "AKA:\n", ":secret\n", "A/B:secret\n", "A B:secret\n", "AKA:ok\nbroken\n"})
    {
        credential_set s;
        std::string e;
        INFO(bad);
        CHECK(!parse_credentials(bad, s, e));
        CHECK(!e.empty());
    }
    credential_set s;
    CHECK(!parse_credentials("AKA:ok\nbroken\n", s, err));
    CHECK(err.starts_with("line 2"));
}

TEST_CASE("a credentials configuration is refused for what is wrong with it")
{
    sigv4_config cfg;
    CHECK(sigv4_config_error(cfg).empty());
    cfg.access_key = "AKA";
    CHECK(sigv4_config_error(cfg).find("go together") != std::string::npos);
    cfg.secret_key = "s";
    CHECK(sigv4_config_error(cfg).empty());
    cfg.access_key = "A/B";
    CHECK(!sigv4_config_error(cfg).empty());
    cfg.access_key = "AKA";
    cfg.credentials_file = "/nonexistent/credentials";
    CHECK(sigv4_config_error(cfg).find("cannot read") != std::string::npos);
}

// ─── The multipart store on a ring and a directory ──────────────────────────

namespace {

struct tmpdir
{
    std::string path;
    tmpdir()
    {
        char tmpl[] = "/tmp/socketley-mpustore-XXXXXX";
        path = ::mkdtemp(tmpl);
    }
    ~tmpdir()
    {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

struct rig : io_handler
{
    event_loop                        loop{256};
    std::unique_ptr<file_io>          io;
    std::unique_ptr<object_store>     store;
    std::unique_ptr<multipart_store>  mp;

    explicit rig(const std::string& dir, uint64_t max_bytes = 0)
    {
        REQUIRE(loop.init());
        io = std::make_unique<file_io>(loop, this);
        store_options o;
        o.dir       = dir;
        o.max_bytes = max_bytes;
        store = std::make_unique<object_store>(loop, *io, o);
        std::string err;
        REQUIRE(store->open(err));
        mp = std::make_unique<multipart_store>(loop, *io, *store);
        const bool ok = mp->open(err);
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

    void bucket(const std::string& name)
    {
        st got = st::io_error;
        bool fired = false;
        store->create_bucket(name, [&](st s) { got = s; fired = true; });
        REQUIRE(until([&] { return fired; }));
        REQUIRE(got == st::ok);
    }

    std::string create(const std::string& b, const std::string& key, checksum_algo algo = checksum_algo::none,
                       object_meta meta = {})
    {
        st got = st::io_error;
        std::string id;
        bool fired = false;
        mp->create(b, key, std::move(meta), algo, [&](st s, std::string i) { got = s; id = std::move(i); fired = true; });
        REQUIRE(until([&] { return fired; }));
        REQUIRE(got == st::ok);
        return id;
    }

    // A part through the streaming path, the way the runtime takes one: written into
    // the upload's data file when its owner gives it a place there.
    put_result part(const std::string& b, const std::string& id, uint32_t n, const std::string& body,
                    bool wait = true, part_place* given = nullptr, const sse_seal_spec* seal = nullptr)
    {
        checksum_algo algo = checksum_algo::none;
        part_place place;
        if (mp->begin_part(b, id, n, body.size(), true, algo, place) != st::ok)
            return {st::cancelled, {}};
        if (given)
            *given = place;
        object_meta meta;
        if (algo != checksum_algo::none)
            meta.extra.emplace_back(std::string(checksum_header(algo)), std::string(checksum_b64_len(algo), 'A'));
        if (place.off)
            meta.extra.emplace_back(std::string(mpu_place_extra), encode_place(place.off));
        if (seal)
            meta.extra.emplace_back(std::string(sse_extra), place.sse);
        st why = st::ok;
        auto op = store->begin_put(b, "mpu/" + id + "/" + std::to_string(n), std::move(meta), body.size(), true, why,
                                   false, seal);
        REQUIRE(op);
        if (algo != checksum_algo::none)
            op->track_checksum(algo, {});
        op->set_committer(mp->part_committer(b, id, n));
        if (place.off)
            op->place_body(place.path, place.off, place.room);
        size_t off = 0;
        while (off < body.size())
        {
            const size_t took = op->append(body.data() + off, std::min<size_t>(100000, body.size() - off));
            off += took;
            if (took == 0)
            {
                bool ready = false;
                op->on_ready([&] { ready = true; });
                REQUIRE(until([&] { return ready || op->failed(); }));
            }
        }
        auto out = std::make_shared<put_result>();
        auto fired = std::make_shared<bool>(false);
        held.push_back(op);
        op->finish(nullptr, [out, fired](put_result r) { *out = std::move(r); *fired = true; });
        if (!wait)
        {
            pending.push_back({out, fired});
            return {};
        }
        REQUIRE(until([&] { return *fired; }));
        return *out;
    }

    complete_result finish(const std::string& b, const std::string& id, std::vector<complete_part> parts)
    {
        complete_result out;
        bool fired = false;
        mp->complete(b, id, std::move(parts), {}, [&](complete_result r) { out = std::move(r); fired = true; });
        REQUIRE(until([&] { return fired; }));
        return out;
    }

    st object(const std::string& b, const std::string& key, std::string& body, object_meta* meta = nullptr)
    {
        open_result r;
        bool fired = false;
        store->open_object(b, key, 0, [&](open_result o) { r = std::move(o); fired = true; });
        REQUIRE(until([&] { return fired; }));
        if (r.status != st::ok)
            return r.status;
        body.assign(r.meta.size, '\0');
        size_t got = 0;
        while (got < body.size())
        {
            const ssize_t n = ::pread(r.fd, body.data() + got, body.size() - got, static_cast<off_t>(r.data_off + got));
            if (n <= 0)
                break;
            got += static_cast<size_t>(n);
        }
        ::close(r.fd);
        if (meta)
            *meta = r.meta;
        return st::ok;
    }

    std::vector<std::shared_ptr<put_op>> held;
    struct waiting { std::shared_ptr<put_result> out; std::shared_ptr<bool> fired; };
    std::vector<waiting> pending;
};

std::vector<std::string> names_in(const std::string& dir)
{
    std::vector<std::string> out;
    std::error_code ec;
    for (const auto& e : fs::directory_iterator(dir, ec))
        out.push_back(e.path().filename().string());
    std::sort(out.begin(), out.end());
    return out;
}

constexpr size_t MiB = 1u << 20;

}   // namespace

TEST_CASE("parts are assembled into one object with the multipart ETag and the metadata given at create")
{
    tmpdir d;
    rig r(d.path);
    r.bucket("bkt");
    object_meta meta;
    meta.content_type = "text/x";
    meta.extra.emplace_back("x-amz-meta-a", "b");
    const std::string id = r.create("bkt", "obj/key", checksum_algo::none, meta);
    CHECK(id.size() == 32);

    const std::string p1 = pattern(5 * MiB, 1), p2 = pattern(5 * MiB + 11, 2), p3 = pattern(999, 3);
    REQUIRE(r.part("bkt", id, 3, p3).status == st::ok);
    REQUIRE(r.part("bkt", id, 1, p1).status == st::ok);
    REQUIRE(r.part("bkt", id, 2, p2).status == st::ok);

    const mpu_upload* up = r.mp->find("bkt", id);
    REQUIRE(up);
    CHECK(up->parts.size() == 3);
    CHECK(up->held == p1.size() + p2.size() + p3.size());
    CHECK(r.mp->totals().bytes == up->held);
    CHECK(names_in(d.path + "/bkt/mpu/" + id) == std::vector<std::string>{"1", "2", "3", "data", "meta"});
    // Part 3 came first and is too small to fix a part size, part 1 fixed it and part 2 is bigger than it.
    CHECK(!up->parts.at(3).in_place);
    CHECK(up->parts.at(1).in_place);
    CHECK(!up->parts.at(2).in_place);

    const complete_result done = r.finish("bkt", id, {{1, hex(md5_of(p1)), {}, {}}, {2, hex(md5_of(p2)), {}, {}}, {3, hex(md5_of(p3)), {}, {}}});
    REQUIRE(done.error.code.empty());
    const std::string joined = hex(md5_of(std::string(reinterpret_cast<const char*>(md5_of(p1).data()), 16) +
                                          std::string(reinterpret_cast<const char*>(md5_of(p2).data()), 16) +
                                          std::string(reinterpret_cast<const char*>(md5_of(p3).data()), 16)));
    CHECK(done.meta.etag() == joined + "-3");

    std::string body;
    object_meta got;
    REQUIRE(r.object("bkt", "obj/key", body, &got) == st::ok);
    CHECK(body == p1 + p2 + p3);
    CHECK(got.content_type == "text/x");
    CHECK(got.parts == 3);
    REQUIRE(got.extra.size() == 2);
    CHECK(got.extra[0].first == "x-amz-meta-a");
    // Part 2 differs from part 1, so the header lists every size.
    CHECK(got.extra[1] == std::pair<std::string, std::string>(std::string(part_sizes_extra), "5242880,5242891,999"));
    uint64_t first = 0, len = 0;
    REQUIRE(part_range(got, 2, first, len) == part_status::ok);
    CHECK(body.substr(first, len) == p2);

    // The upload goes away: its directory, its bytes in the quota, its place in the map.
    REQUIRE(r.until([&] { return r.mp->find("bkt", id) == nullptr; }));
    CHECK(r.until([&] { return !r.mp->busy(); }));
    CHECK(!fs::exists(d.path + "/bkt/mpu/" + id));
    CHECK(r.mp->totals().uploads == 0);
    CHECK(names_in(d.path + "/bkt/tmp").empty());
}

TEST_CASE("completion is refused for the parts it cannot use, and leaves the upload open")
{
    tmpdir d;
    rig r(d.path);
    r.bucket("bkt");
    const std::string id = r.create("bkt", "k");
    const std::string big = pattern(5 * MiB), small = pattern(100);
    REQUIRE(r.part("bkt", id, 1, big).status == st::ok);
    REQUIRE(r.part("bkt", id, 2, small).status == st::ok);
    const std::string e1 = hex(md5_of(big)), e2 = hex(md5_of(small));

    CHECK(r.finish("bkt", id, {{1, std::string(32, '0'), {}, {}}, {2, e2, {}, {}}}).error.code == "InvalidPart");
    CHECK(r.finish("bkt", id, {{1, e1, {}, {}}, {9, e2, {}, {}}}).error.code == "InvalidPart");
    CHECK(r.finish("bkt", id, {{2, e2, {}, {}}, {1, e1, {}, {}}}).error.code == "InvalidPartOrder");
    CHECK(r.finish("bkt", id, {{1, e1, {}, {}}, {1, e1, {}, {}}}).error.code == "InvalidPartOrder");
    CHECK(r.finish("bkt", id, {{0, e1, {}, {}}}).error.code == "InvalidArgument");
    CHECK(r.finish("bkt", id, {}).error.code == "MalformedXML");
    REQUIRE(r.part("bkt", id, 3, small).status == st::ok);
    CHECK(r.finish("bkt", id, {{2, e2, {}, {}}, {3, hex(md5_of(small)), {}, {}}}).error.code == "EntityTooSmall");
    CHECK(r.finish("bkt", "0123456789abcdef0123456789abcdef", {{1, e1, {}, {}}}).error.code == "NoSuchUpload");

    // Still open, and still completes.
    const mpu_upload* up = r.mp->find("bkt", id);
    REQUIRE(up);
    CHECK(up->state == mpu_state::open);
    CHECK(r.finish("bkt", id, {{1, e1, {}, {}}, {3, hex(md5_of(small)), {}, {}}}).error.code.empty());
    std::string body;
    REQUIRE(r.object("bkt", "k", body) == st::ok);
    CHECK(body == big + small);
}

TEST_CASE("a part sent again replaces the old one on the disk and in the list, whichever finishes last")
{
    tmpdir d;
    rig r(d.path);
    r.bucket("bkt");
    const std::string id = r.create("bkt", "k");
    // Two sends of part 1 in flight together: the list and the disk must end in the same state.
    const std::string a = pattern(300000, 1), b = pattern(200000, 2);
    r.part("bkt", id, 1, a, false);
    r.part("bkt", id, 1, b, false);
    REQUIRE(r.until([&] { return *r.pending[0].fired && *r.pending[1].fired; }));
    CHECK(r.pending[0].out->status == st::ok);
    CHECK(r.pending[1].out->status == st::ok);
    const mpu_upload* up = r.mp->find("bkt", id);
    REQUIRE(up);
    REQUIRE(up->parts.size() == 1);
    const mpu_part& p = up->parts.at(1);
    // Whatever won, the file on the disk is the one the list describes.
    std::ifstream f(d.path + "/bkt/mpu/" + id + "/1", std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string on_disk = ss.str();
    REQUIRE(on_disk.size() == p.data_off + p.size);
    CHECK(md5_of(std::string_view(on_disk).substr(p.data_off)) == p.md5);
    CHECK(up->held == p.size);
    CHECK(r.mp->totals().bytes == p.size);
}

TEST_CASE("an upload being completed takes no new part")
{
    tmpdir d;
    rig r(d.path);
    r.bucket("bkt");
    const std::string id = r.create("bkt", "k");
    const std::string small = pattern(100);
    REQUIRE(r.part("bkt", id, 1, small).status == st::ok);
    bool fired = false;
    complete_result out;
    r.mp->complete("bkt", id, {{1, hex(md5_of(small)), {}, {}}}, {}, [&](complete_result c) { out = std::move(c); fired = true; });
    // The completion is on the ring and has not answered, and nothing may join the upload now.
    checksum_algo algo;
    CHECK(r.mp->begin_part("bkt", id, algo) != st::ok);
    CHECK(r.mp->find("bkt", id)->state != mpu_state::open);
    CHECK(!r.mp->abort("bkt", id, {}));
    REQUIRE(r.until([&] { return fired; }));
    CHECK(out.error.code.empty());
}

TEST_CASE("an abort removes the files, gives the room back and refuses new parts")
{
    tmpdir d;
    rig r(d.path);
    r.bucket("bkt");
    const std::string id = r.create("bkt", "k");
    REQUIRE(r.part("bkt", id, 1, pattern(100000)).status == st::ok);
    REQUIRE(r.part("bkt", id, 2, pattern(50000)).status == st::ok);
    CHECK(r.mp->bucket_has_uploads("bkt"));

    bool done = false;
    REQUIRE(r.mp->abort("bkt", id, [&] { done = true; }));
    // A second abort of the same upload finds it on its way out.
    CHECK(!r.mp->abort("bkt", id, {}));
    checksum_algo algo;
    CHECK(r.mp->begin_part("bkt", id, algo) != st::ok);
    REQUIRE(r.until([&] { return done; }));
    REQUIRE(r.until([&] { return r.mp->find("bkt", id) == nullptr; }));
    CHECK(!fs::exists(d.path + "/bkt/mpu/" + id));
    CHECK(!r.mp->bucket_has_uploads("bkt"));
    CHECK(r.mp->totals().bytes == 0);
    CHECK(r.part("bkt", id, 3, "late").status == st::cancelled);
    CHECK(names_in(d.path + "/bkt/tmp").empty());
}

TEST_CASE("a part that lands after its upload was aborted is dropped and its temporary file removed")
{
    tmpdir d;
    rig r(d.path);
    r.bucket("bkt");
    const std::string id = r.create("bkt", "k");
    // The body is in and the put is finishing when the abort arrives.
    r.part("bkt", id, 1, pattern(700000), false);
    bool done = false;
    REQUIRE(r.mp->abort("bkt", id, [&] { done = true; }));
    REQUIRE(r.until([&] { return *r.pending[0].fired && done; }));
    REQUIRE(r.until([&] { return r.mp->find("bkt", id) == nullptr; }));
    CHECK(!fs::exists(d.path + "/bkt/mpu/" + id));
    // The temporary file is unlinked by an operation nobody waits for.
    CHECK(r.until([&] { return names_in(d.path + "/bkt/tmp").empty(); }));
    CHECK(r.mp->totals().bytes == 0);
}

TEST_CASE("uploads and their parts are found again by a new store on the same directory")
{
    tmpdir d;
    std::string id1, id2;
    const std::string p1 = pattern(5 * MiB, 1), p2 = pattern(123456, 2);
    {
        rig r(d.path);
        r.bucket("bkt");
        object_meta m;
        m.content_type = "text/kept";
        id1 = r.create("bkt", "one", checksum_algo::sha256, m);
        REQUIRE(r.part("bkt", id1, 1, p1).status == st::ok);
        REQUIRE(r.part("bkt", id1, 2, p2).status == st::ok);
        id2 = r.create("bkt", "two");
    }
    // What a crash could leave beside them: a directory with no meta file, a
    // stray file, a part cut short, and something that is not an upload id.
    const std::string junk = "0123456789abcdef0123456789abcdef";
    fs::create_directories(d.path + "/bkt/mpu/" + junk);
    std::ofstream(d.path + "/bkt/mpu/" + junk + "/1") << "no header";
    std::ofstream(d.path + "/bkt/mpu/" + id2 + "/stray") << "x";
    {
        std::ofstream cut(d.path + "/bkt/mpu/" + id2 + "/2", std::ios::binary);
        cut << std::string(100, 'x');
    }
    fs::create_directories(d.path + "/bkt/mpu/not-an-id");

    rig again(d.path);
    const mpu_upload* u1 = again.mp->find("bkt", id1);
    const mpu_upload* u2 = again.mp->find("bkt", id2);
    REQUIRE(u1);
    REQUIRE(u2);
    CHECK(u1->key == "one");
    CHECK(u1->algo == checksum_algo::sha256);
    CHECK(u1->meta.content_type == "text/kept");
    for (const auto& [n, v] : u1->meta.extra)
        CHECK(n != "x-amz-checksum-algorithm");
    REQUIRE(u1->parts.size() == 2);
    CHECK(u1->parts.at(1).md5 == md5_of(p1));
    CHECK(u1->parts.at(2).size == p2.size());
    CHECK(u1->parts.at(1).checksum_b64 == b64_of(checksum_algo::sha256, p1));
    // Both were written in the data file, which a start reads from and gives no more places in.
    CHECK(u1->parts.at(1).in_place);
    CHECK(u1->parts.at(2).in_place);
    CHECK(u1->place_frozen);
    CHECK(u2->parts.empty());
    CHECK(!fs::exists(d.path + "/bkt/mpu/" + junk));
    CHECK(!fs::exists(d.path + "/bkt/mpu/" + id2 + "/stray"));
    CHECK(!fs::exists(d.path + "/bkt/mpu/" + id2 + "/2"));
    CHECK(fs::exists(d.path + "/bkt/mpu/not-an-id"));
    CHECK(again.mp->totals().uploads == 2);
    CHECK(again.mp->totals().bytes == p1.size() + p2.size());

    // A restored upload is a working one.
    part_place g;
    REQUIRE(again.part("bkt", id1, 3, std::string(5 * MiB, 't'), true, &g).status == st::ok);
    CHECK(g.off == 0);
    REQUIRE(again.part("bkt", id1, 3, "tail").status == st::ok);
    // Part 2 is small and not used; the object is parts 1 and 3.
    const complete_result done = again.finish("bkt", id1, {{1, hex(md5_of(p1)), checksum_algo::sha256, b64_of(checksum_algo::sha256, p1)},
                                                          {3, hex(md5_of("tail")), {}, {}}});
    REQUIRE(done.error.code.empty());
    std::string body;
    object_meta got;
    REQUIRE(again.object("bkt", "one", body, &got) == st::ok);
    CHECK(body == p1 + "tail");
    CHECK(got.content_type == "text/kept");
    CHECK(got.parts == 2);
    // The checksum of the whole is the SHA-256 of the part checksums, and it is stored.
    bool found = false;
    for (const auto& [n, v] : got.extra)
        if (n == "x-amz-checksum-sha256")
        {
            found = true;
            const std::string raw = [&] {
                std::string x;
                for (std::string_view part : {std::string_view(p1), std::string_view("tail")})
                {
                    checksum_stream cs(checksum_algo::sha256);
                    cs.update(part.data(), part.size());
                    x += cs.peek_raw();
                }
                return x;
            }();
            CHECK(v == composite_checksum_b64(checksum_algo::sha256, raw, 2));
        }
    CHECK(found);
}

TEST_CASE("the parts count against the quota and complete gives them back")
{
    tmpdir d;
    rig r(d.path, 3 * MiB);
    r.bucket("bkt");
    const std::string id = r.create("bkt", "k");
    REQUIRE(r.part("bkt", id, 1, pattern(1 * MiB)).status == st::ok);
    REQUIRE(r.part("bkt", id, 2, pattern(1 * MiB)).status == st::ok);
    CHECK(r.store->options().max_bytes == 3 * MiB);
    // Two megabytes are held, so another two do not fit and one does.
    st why = st::ok;
    CHECK(!r.store->begin_put("bkt", "other", {}, 2 * MiB, true, why));
    CHECK(why == st::storage_full);
    auto op = r.store->begin_put("bkt", "other", {}, 1 * MiB, true, why);
    REQUIRE(op);
    op->abort();
    for (int i = 0; i < 100; ++i)
        r.loop.poll_completions(1);
    bool done = false;
    REQUIRE(r.mp->abort("bkt", id, [&] { done = true; }));
    REQUIRE(r.until([&] { return done && r.mp->find("bkt", id) == nullptr; }));
    auto op2 = r.store->begin_put("bkt", "other", {}, 2 * MiB, true, why);
    CHECK(op2);
    if (op2)
        op2->abort();
    for (int i = 0; i < 100; ++i)
        r.loop.poll_completions(1);
}

// ─── Parts written where the object needs them ──────────────────────────────

namespace {

ino_t inode_of(const std::string& path)
{
    struct stat sb{};
    return ::stat(path.c_str(), &sb) == 0 ? sb.st_ino : 0;
}

complete_part listed(uint32_t n, const std::string& body)
{
    return {n, hex(md5_of(body)), {}, {}};
}

std::string slurp_file(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    std::ostringstream s;
    s << f.rdbuf();
    return s.str();
}

}   // namespace

TEST_CASE("equal parts are written into the data file at their place and the file becomes the object")
{
    tmpdir d;
    rig r(d.path);
    r.bucket("bkt");
    object_meta meta;
    meta.content_type = "text/y";
    meta.extra.emplace_back("x-amz-meta-z", "1");
    const std::string id = r.create("bkt", "in/place", checksum_algo::crc32, meta);
    const mpu_upload* up = r.mp->find("bkt", id);
    REQUIRE(up);
    REQUIRE(up->place_base >= 4096);

    // Out of order, and the short last part before two of the others.
    const size_t P = 5 * MiB;
    const std::string p1 = pattern(P, 1), p2 = pattern(P, 2), p3 = pattern(P, 3), p4 = pattern(777777, 4);
    const std::vector<std::pair<uint32_t, const std::string*>> order = {{2, &p2}, {4, &p4}, {1, &p1}, {3, &p3}};
    for (const auto& [n, body] : order)
    {
        part_place g;
        REQUIRE(r.part("bkt", id, n, *body, true, &g).status == st::ok);
        CHECK(g.off == up->place_base + (n - 1) * P);
        CHECK(up->parts.at(n).in_place);
        CHECK(up->parts.at(n).data_off == g.off);
    }
    // The numbered files are headers alone, and the data file ends where the last part does.
    CHECK(fs::file_size(d.path + "/bkt/mpu/" + id + "/1") == 4096);
    CHECK(fs::file_size(d.path + "/bkt/mpu/" + id + "/data") == up->place_base + 3 * P + p4.size());
    const ino_t data_ino = inode_of(d.path + "/bkt/mpu/" + id + "/data");
    REQUIRE(data_ino != 0);

    const complete_result done = r.finish("bkt", id, {listed(1, p1), listed(2, p2), listed(3, p3), listed(4, p4)});
    REQUIRE(done.error.code.empty());
    CHECK(done.meta.parts == 4);
    // No byte was copied: the object's file is the data file.
    CHECK(inode_of(d.path + "/bkt/data/" + object_rel_path("in/place")) == data_ino);

    std::string body;
    object_meta got;
    REQUIRE(r.object("bkt", "in/place", body, &got) == st::ok);
    CHECK(body == p1 + p2 + p3 + p4);
    CHECK(got.content_type == "text/y");
    CHECK(got.parts == 4);
    CHECK(got.etag() == done.meta.etag());
    bool has_ck = false;
    for (const auto& [n, v] : got.extra)
        has_ck = has_ck || n == "x-amz-checksum-crc32";
    CHECK(has_ck);
    REQUIRE(r.until([&] { return r.mp->find("bkt", id) == nullptr; }));
    // Nothing of the completion is still counted as in flight.
    CHECK(r.until([&] { return !r.mp->busy(); }));
    CHECK(!fs::exists(d.path + "/bkt/mpu/" + id));
    CHECK(r.until([&] { return names_in(d.path + "/bkt/tmp").empty(); }));
}

TEST_CASE("parts that are not where the object needs them are copied, from the data file and their own")
{
    tmpdir d;
    rig r(d.path);
    r.bucket("bkt");
    const size_t P = 5 * MiB;
    const std::string a = pattern(P, 11), b = pattern(P, 12), c = pattern(P + 4096, 13), e = pattern(1000, 14);

    SUBCASE("a gap in the numbers")
    {
        const std::string id = r.create("bkt", "k");
        REQUIRE(r.part("bkt", id, 1, a).status == st::ok);
        REQUIRE(r.part("bkt", id, 3, b).status == st::ok);
        CHECK(r.mp->find("bkt", id)->parts.at(3).in_place);
        const ino_t data_ino = inode_of(d.path + "/bkt/mpu/" + id + "/data");
        REQUIRE(r.finish("bkt", id, {listed(1, a), listed(3, b)}).error.code.empty());
        CHECK(inode_of(d.path + "/bkt/data/" + object_rel_path("k")) != data_ino);
        std::string body;
        REQUIRE(r.object("bkt", "k", body) == st::ok);
        CHECK(body == a + b);
    }
    SUBCASE("a part bigger than the first")
    {
        const std::string id = r.create("bkt", "k");
        REQUIRE(r.part("bkt", id, 1, a).status == st::ok);
        REQUIRE(r.part("bkt", id, 2, c).status == st::ok);
        REQUIRE(r.part("bkt", id, 3, e).status == st::ok);
        CHECK(!r.mp->find("bkt", id)->parts.at(2).in_place);
        CHECK(r.mp->find("bkt", id)->parts.at(3).in_place);
        REQUIRE(r.finish("bkt", id, {listed(1, a), listed(2, c), listed(3, e)}).error.code.empty());
        std::string body;
        REQUIRE(r.object("bkt", "k", body) == st::ok);
        CHECK(body == a + c + e);
    }
    SUBCASE("the last part first, smaller than any part size")
    {
        const std::string id = r.create("bkt", "k");
        REQUIRE(r.part("bkt", id, 3, e).status == st::ok);
        REQUIRE(r.part("bkt", id, 1, a).status == st::ok);
        REQUIRE(r.part("bkt", id, 2, b).status == st::ok);
        const mpu_upload* up = r.mp->find("bkt", id);
        CHECK(!up->parts.at(3).in_place);
        CHECK(up->parts.at(1).in_place);
        CHECK(up->parts.at(2).in_place);
        REQUIRE(r.finish("bkt", id, {listed(1, a), listed(2, b), listed(3, e)}).error.code.empty());
        std::string body;
        REQUIRE(r.object("bkt", "k", body) == st::ok);
        CHECK(body == a + b + e);
    }
    SUBCASE("a last part over the minimum first fixes a part size the others do not fit")
    {
        const std::string id = r.create("bkt", "k");
        const std::string big1 = pattern(P + 8192, 15), big2 = pattern(P + 8192, 16);
        REQUIRE(r.part("bkt", id, 3, a).status == st::ok);
        REQUIRE(r.part("bkt", id, 1, big1).status == st::ok);
        REQUIRE(r.part("bkt", id, 2, big2).status == st::ok);
        const mpu_upload* up = r.mp->find("bkt", id);
        CHECK(up->parts.at(3).in_place);
        CHECK(!up->parts.at(1).in_place);
        REQUIRE(r.finish("bkt", id, {listed(1, big1), listed(2, big2), listed(3, a)}).error.code.empty());
        std::string body;
        REQUIRE(r.object("bkt", "k", body) == st::ok);
        CHECK(body == big1 + big2 + a);
    }
    SUBCASE("the data file holds a part the list leaves out")
    {
        const std::string id = r.create("bkt", "k");
        REQUIRE(r.part("bkt", id, 1, a).status == st::ok);
        REQUIRE(r.part("bkt", id, 2, b).status == st::ok);
        const ino_t data_ino = inode_of(d.path + "/bkt/mpu/" + id + "/data");
        REQUIRE(r.finish("bkt", id, {listed(1, a)}).error.code.empty());
        CHECK(inode_of(d.path + "/bkt/data/" + object_rel_path("k")) != data_ino);
        std::string body;
        REQUIRE(r.object("bkt", "k", body) == st::ok);
        CHECK(body == a);
    }
}

TEST_CASE("a part number is written in place once, and another upload of it goes to its own file")
{
    tmpdir d;
    rig r(d.path);
    r.bucket("bkt");
    const size_t P = 5 * MiB;
    const std::string id = r.create("bkt", "k");
    const std::string a1 = pattern(P, 21), a2 = pattern(P, 22), b1 = pattern(P, 23), b2 = pattern(P, 24),
                      c1 = pattern(P / 2, 25);
    part_place g;
    REQUIRE(r.part("bkt", id, 1, a1, true, &g).status == st::ok);
    CHECK(g.off != 0);

    // Again after it landed, the same size: its own file.
    REQUIRE(r.part("bkt", id, 1, a2, true, &g).status == st::ok);
    CHECK(g.off == 0);
    const mpu_upload* up = r.mp->find("bkt", id);
    CHECK(!up->parts.at(1).in_place);
    CHECK(up->parts.at(1).md5 == md5_of(a2));
    // And another size.
    REQUIRE(r.part("bkt", id, 1, c1, true, &g).status == st::ok);
    CHECK(g.off == 0);
    REQUIRE(r.part("bkt", id, 1, a2).status == st::ok);

    // Two uploads of one number at once: one is given the place, and whichever lands last is the part.
    part_place g1, g2;
    r.part("bkt", id, 2, b1, false, &g1);
    r.part("bkt", id, 2, b2, false, &g2);
    CHECK((g1.off != 0) != (g2.off != 0));
    REQUIRE(r.until([&] { return *r.pending[0].fired && *r.pending[1].fired; }));
    CHECK(r.pending[0].out->status == st::ok);
    CHECK(r.pending[1].out->status == st::ok);
    const std::string& won = up->parts.at(2).md5 == md5_of(b1) ? b1 : b2;
    CHECK(up->parts.at(2).md5 == md5_of(won));

    REQUIRE(r.finish("bkt", id, {listed(1, a2), listed(2, won)}).error.code.empty());
    std::string body;
    REQUIRE(r.object("bkt", "k", body) == st::ok);
    CHECK(body == a2 + won);
}

TEST_CASE("a commit that names a place its owner never gave is refused")
{
    tmpdir d;
    rig r(d.path);
    r.bucket("bkt");
    const std::string id = r.create("bkt", "k");
    REQUIRE(r.part("bkt", id, 1, pattern(5 * MiB, 31)).status == st::ok);
    const mpu_upload* up = r.mp->find("bkt", id);
    const uint64_t off = up->place_base + 6 * 5 * MiB;
    const std::string body = pattern(1000, 32);
    object_meta meta;
    meta.extra.emplace_back(std::string(mpu_place_extra), encode_place(off));
    st why = st::ok;
    auto op = r.store->begin_put("bkt", "mpu/" + id + "/7", std::move(meta), body.size(), true, why);
    REQUIRE(op);
    op->set_committer(r.mp->part_committer("bkt", id, 7));
    op->place_body(r.mp->data_path("bkt", id), off, body.size());
    REQUIRE(op->append(body.data(), body.size()) == body.size());
    put_result out;
    bool fired = false;
    op->finish(nullptr, [&](put_result p) { out = std::move(p); fired = true; });
    REQUIRE(r.until([&] { return fired; }));
    CHECK(out.status == st::io_error);
    CHECK(!up->parts.contains(7));
    CHECK(r.until([&] { return names_in(d.path + "/bkt/tmp").empty(); }));
}

TEST_CASE("a part list too long for the header follows the body, so any list S3 takes completes")
{
    // A header room of 12 bytes, so three parts of unequal sizes are already too many for it.
    ::setenv("SOCKETLEY_STORAGE_PART_LIST_MAX", "12", 1);
    tmpdir d;
    std::optional<rig> r(std::in_place, d.path);
    ::unsetenv("SOCKETLEY_STORAGE_PART_LIST_MAX");
    r->bucket("bkt");
    const std::string a = pattern(5 * MiB + 1, 41), b = pattern(5 * MiB + 70000, 42), c = pattern(999, 43);
    const std::string whole = a + b + c;

    for (const bool sealed : {false, true})
    {
        INFO("sealed " << sealed);
        const std::string key = sealed ? "s" : "p";
        object_meta meta;
        sse_seal_spec seal;
        if (sealed)
        {
            sse_record rec;
            rec.mode     = sse_mode::s3;
            rec.per_part = true;
            seal.key     = sse_random_key();
            REQUIRE(sse_wrap(sse_random_key(), seal.key, rec.wrapped));
            meta.extra.emplace_back(std::string(sse_extra), encode_sse(rec));
        }
        const std::string id = r->create("bkt", key, checksum_algo::none, meta);
        // Uploaded as 2, 5 and 9, which a sealed object must keep since each stream was sealed as its number.
        for (const auto& [n, body] : {std::pair<uint32_t, const std::string*>{5, &b}, {2, &a}, {9, &c}})
        {
            seal.stream = n;
            REQUIRE(r->part("bkt", id, n, *body, true, nullptr, sealed ? &seal : nullptr).status == st::ok);
        }
        const uint64_t trailers = r->mp->trailers();
        const complete_result done = r->finish("bkt", id, {listed(2, a), listed(5, b), listed(9, c)});
        REQUIRE(done.error.code.empty());
        CHECK(r->mp->trailers() == trailers + 1);

        const std::string file = slurp_file(d.path + "/bkt/data/" + object_rel_path(key));
        const decoded_header h = decode_object_header(file);
        REQUIRE(h.status == header_status::ok);
        part_trailer t;
        REQUIRE(part_trailer_of(h.meta, t));
        bool sizes_in_header = false;
        for (const auto& [n, v] : h.meta.extra)
            sizes_in_header = sizes_in_header || n == part_sizes_extra || n == part_numbers_extra;
        CHECK_FALSE(sizes_in_header);
        const uint64_t body_len = sealed ? sse_stored_len(a.size(), sse_format) + sse_stored_len(b.size(), sse_format) +
                                               sse_stored_len(c.size(), sse_format)
                                         : whole.size();
        CHECK(t.at == body_len);
        CHECK(t.len == 20 + 3 * 12);
        CHECK(stored_size(h.meta) == body_len + t.len);
        CHECK(file.size() == h.header_len + stored_size(h.meta));

        part_list l;
        REQUIRE(decode_part_trailer(std::string_view(file).substr(h.header_len + t.at), h.meta, t, l));
        CHECK(l.numbers == std::vector<uint32_t>{2, 5, 9});
        CHECK(l.sizes == std::vector<uint64_t>{a.size(), b.size(), c.size()});
        uint64_t first = 0, len = 0;
        CHECK(part_range(h.meta, 2, first, len) == part_status::in_trailer);
        REQUIRE(part_range_in(l, 2, first, len) == part_status::ok);
        CHECK((first == a.size() && len == b.size()));
        CHECK(part_range_in(l, 4, first, len) == part_status::out_of_range);
        // A list bent by a byte, or claimed for another object, is not taken.
        std::string bent = file.substr(h.header_len + t.at);
        bent[24] ^= 1;
        CHECK_FALSE(decode_part_trailer(bent, h.meta, t, l));
        object_meta other = h.meta;
        other.size += 1;
        CHECK_FALSE(decode_part_trailer(std::string_view(file).substr(h.header_len + t.at), other, t, l));

        if (sealed)
        {
            std::string back;
            REQUIRE(sse_open_body(h.meta, seal.key, std::string_view(file).substr(h.header_len), back));
            CHECK(back == whole);
        }
        else
        {
            std::string body;
            REQUIRE(r->object("bkt", key, body) == st::ok);
            CHECK(body == whole);
        }
    }

    // A start that reads the files, the journals gone, takes both objects back at their length with the list.
    r.reset();
    for (const auto& e : fs::directory_iterator(d.path + "/bkt"))
        if (e.path().filename().string().starts_with("index."))
            fs::remove(e.path());
    rig again(d.path);
    for (const char* key : {"p", "s"})
    {
        const object_meta* m = again.store->find("bkt", key);
        REQUIRE(m != nullptr);
        part_trailer t;
        CHECK(part_trailer_of(*m, t));
    }
}
