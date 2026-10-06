#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "../../socketley/shared/write_queue.h"

#include <memory>
#include <string>

// The write queue's coalescing decision, which had no test of its own.
//
// Three runtimes hold one of these and the fourth holds two, and what they push
// into it is either bytes they own or bytes several connections are sending.  The
// second kind is the interesting one: the alternative to copying is a refcount,
// so a copy has to buy something, and what it buys is an appendable tail for the
// NEXT message.
//
// A payload already at the coalescing limit cannot buy that -- fits_in_tail
// fails on its size alone whatever arrives after it -- so for that shape the
// copy was the whole cost and none of the benefit.  Every chunk of a 64 KiB
// streamed response is that shape, and so is a kept --http response once the
// queue is deep.
//
// What is NOT covered here: whether the runtimes pick the right limit and batch
// for their own traffic.  That is a question about four call sites and this file
// has one queue.

namespace {

constexpr size_t LIMIT = 64 * 1024;     // WRITE_COALESCE_LIMIT, as the server sets it
constexpr size_t BATCH = 32;            // MAX_WRITE_BATCH, likewise

using queue_t = socketley::byte_counted_queue<socketley::write_chunk>;

std::shared_ptr<const std::string> shared_of(size_t n, char c)
{
    return std::make_shared<const std::string>(std::string(n, c));
}

// Fill past the batch threshold, so the next push reaches the coalescing
// decision at all -- below it every push is a refcount whatever the size.
void fill_to_batch(queue_t& q)
{
    for (size_t i = 0; i < BATCH; ++i)
        q.push_shared(shared_of(16, 'f'), LIMIT, BATCH);
    REQUIRE(q.size() == BATCH);
}

std::string drain(queue_t& q)
{
    std::string out;
    while (!q.empty())
    {
        out.append(q.front().view());
        q.pop();
    }
    return out;
}

}  // namespace

TEST_CASE("below the batch threshold a shared payload is never copied")
{
    queue_t q;
    auto p = shared_of(1024, 'a');
    q.push_shared(p, LIMIT, BATCH);
    CHECK(q.size() == 1);
    CHECK_FALSE(q.back().owns());
    CHECK(p.use_count() == 2);          // the queue holds it, nothing was copied
}

TEST_CASE("past the threshold a small payload seeds an appendable tail")
{
    queue_t q;
    fill_to_batch(q);

    auto seed = shared_of(1024, 's');
    q.push_shared(seed, LIMIT, BATCH);
    CHECK(q.size() == BATCH + 1);
    CHECK(q.back().owns());             // copied on purpose: it can now grow
    CHECK(seed.use_count() == 1);

    const size_t before = q.bytes();
    q.push_shared(shared_of(2048, 't'), LIMIT, BATCH);
    CHECK(q.size() == BATCH + 1);        // appended, not queued
    CHECK(q.bytes() == before + 2048);
    CHECK(q.back().size() == 1024 + 2048);
}

TEST_CASE("a payload at the coalescing limit is not copied")
{
    queue_t q;
    fill_to_batch(q);

    auto big = shared_of(LIMIT, 'b');
    q.push_shared(big, LIMIT, BATCH);
    CHECK(q.size() == BATCH + 1);
    CHECK_FALSE(q.back().owns());        // the invariant this file exists for
    CHECK(big.use_count() == 2);

    // And the proof that the copy could not have bought anything: the message
    // after it does not fit in it either, at any size.
    q.push_shared(shared_of(1, 'c'), LIMIT, BATCH);
    CHECK(q.size() == BATCH + 2);
}

// A tail seeded at the payload's own size doubled its way to the limit, copying
// everything it held at each step -- 7.6% of a relaying worker was that copy and
// most of its malloc was the steps.  The address not moving is the proof that
// nothing was copied.
TEST_CASE("a seeded tail takes the backlog it joined without moving")
{
    queue_t q;
    fill_to_batch(q);
    const size_t backlog = q.bytes();

    q.push_shared(shared_of(200, 's'), LIMIT, BATCH);
    REQUIRE(q.back().owns());
    const char* at = q.back().data();

    size_t taken = 200;
    while (taken + 200 <= backlog)
    {
        q.push_shared(shared_of(200, 't'), LIMIT, BATCH);
        taken += 200;
    }
    CHECK(q.size() == BATCH + 1);
    CHECK(q.back().size() == taken);
    CHECK(q.back().data() == at);
}

// And the other half, which is what keeps the reservation from being a leak: it
// follows the bytes the queue is charged for, so a connection that is keeping up
// gets a string its own size and none is ever larger than the limit.
TEST_CASE("a seed is sized by the backlog, never past the limit")
{
    constexpr size_t small = 4096;
    socketley::byte_counted_queue<std::string> q;

    q.push_coalesced(std::string_view(std::string(3000, 'a')), small);
    CHECK(q.back().capacity() < small);

    const size_t backlog = q.bytes();
    q.push_coalesced(std::string_view(std::string(2000, 'b')), small);
    REQUIRE(q.size() == 2);
    CHECK(q.back().capacity() >= backlog);
    CHECK(q.back().capacity() < 2 * small);
}

// A queue that empties on every send seeds each tail at one message and grew it
// by doubling for the rest of the flight -- 11.8% of a cache fanning out to 50
// subscribers.  Past the regrow bound the tail stays where it is and the next
// entry starts at the backlog, so nothing already queued is copied again.
TEST_CASE("a full tail past the regrow bound is followed, not copied")
{
    socketley::byte_counted_queue<std::string> q;
    const size_t big = socketley::write_queue_regrow_max + 904;
    q.push_coalesced(std::string_view(std::string(big, 'a')), LIMIT);
    REQUIRE(q.size() == 1);
    const char* at = q.front().data();
    const size_t backlog = q.bytes();

    q.push_coalesced(std::string_view(std::string(q.back().capacity() - big + 1, 'b')), LIMIT);
    CHECK(q.size() == 2);
    CHECK(q.front().data() == at);
    CHECK(q.front().size() == big);
    CHECK(q.back().capacity() >= backlog);
}

// Below it a tail still grows, because a few kilobytes are cheaper to copy than
// to send as another entry, and three-byte replies are what coalescing is for.
TEST_CASE("a small full tail still takes the next payload")
{
    socketley::byte_counted_queue<std::string> q;
    q.push_coalesced(std::string_view(std::string(100, 'a')), LIMIT);
    q.push_coalesced(std::string_view(std::string(q.back().capacity() - 100 + 1, 'b')), LIMIT);
    CHECK(q.size() == 1);
}

TEST_CASE("one byte under the limit is still seeded, one byte over is not")
{
    queue_t under;
    fill_to_batch(under);
    auto u = shared_of(LIMIT - 1, 'u');
    under.push_shared(u, LIMIT, BATCH);
    CHECK(under.back().owns());
    CHECK(u.use_count() == 1);

    queue_t over;
    fill_to_batch(over);
    auto o = shared_of(LIMIT + 1, 'o');
    over.push_shared(o, LIMIT, BATCH);
    CHECK_FALSE(over.back().owns());
    CHECK(o.use_count() == 2);
}

TEST_CASE("the bytes leave whole and in order, in both shapes")
{
    // Small payloads, which coalesce, and large ones, which no longer copy:
    // the queue is a queue either way and a change to the decision must not
    // reorder or drop a byte.
    for (size_t n : { size_t{1024}, LIMIT })
    {
        queue_t q;
        std::string expect;
        for (size_t i = 0; i < BATCH; ++i)
        {
            auto p = shared_of(16, static_cast<char>('A' + (i % 26)));
            expect.append(*p);
            q.push_shared(p, LIMIT, BATCH);
        }
        for (int i = 0; i < 4; ++i)
        {
            auto p = shared_of(n, static_cast<char>('0' + i));
            expect.append(*p);
            q.push_shared(p, LIMIT, BATCH);
        }
        CHECK(q.bytes() ==
              expect.size() + q.size() * socketley::write_queue_entry_overhead);
        CHECK(drain(q) == expect);
        CHECK(q.bytes() == 0);
    }
}

// ─── push_coalesced_line ────────────────────────────────────────────────────
// A payload and its newline, without the caller building the two together
// first.  The temporary that shape replaces was malloc'd, copied into, copied
// out of by append_back and freed -- per line, on a path an echo server walks
// millions of times a second.  So the question these ask is not whether the
// bytes are right (they are the same bytes) but whether the ENTRY COUNT is:
// the win is entirely in coalescing, and a version that queued one entry per
// line would pass a bytes-only check.

TEST_CASE("a line joins the tail instead of queueing behind it")
{
    queue_t q;
    q.push(socketley::write_chunk(std::string("seed\n")));
    REQUIRE(q.size() == 1);

    for (int i = 0; i < 8; ++i)
        q.push_coalesced_line("line", LIMIT);

    // One entry still, because every line went into the tail.
    CHECK(q.size() == 1);
    CHECK(drain(q) == "seed\nline\nline\nline\nline\nline\nline\nline\nline\n");
}

TEST_CASE("the newline is the last byte of each line and not of the batch")
{
    queue_t q;
    q.push(socketley::write_chunk(std::string("x")));
    q.push_coalesced_line("aa", LIMIT);
    q.push_coalesced_line("", LIMIT);      // an empty line is still a line
    q.push_coalesced_line("bbb", LIMIT);
    CHECK(drain(q) == "xaa\n\nbbb\n");
}

TEST_CASE("a line the tail cannot take queues as its own entry, newline included")
{
    queue_t q;
    // A tail already at the limit cannot grow, which is the case that has to
    // fall back rather than silently drop the newline.
    q.push(socketley::write_chunk(std::string(LIMIT, 'T')));
    REQUIRE(q.size() == 1);

    q.push_coalesced_line("over", LIMIT);
    CHECK(q.size() == 2);

    const std::string out = drain(q);
    CHECK(out.size() == LIMIT + 5);
    CHECK(out.compare(LIMIT, 5, "over\n") == 0);
}

TEST_CASE("a payload one byte under the limit still leaves room for its newline")
{
    // The bound is the payload PLUS the newline, so a payload that fits on its
    // own and the newline that does not must not be split across two entries
    // with the byte count still adding up.
    queue_t q;
    q.push(socketley::write_chunk(std::string("s")));
    const size_t room = LIMIT - 1;      // tail holds 1, so `room` payload fits exactly
    q.push_coalesced_line(std::string(room, 'p'), LIMIT);
    CHECK(q.size() == 2);               // payload + newline would be one over
    CHECK(drain(q) == "s" + std::string(room, 'p') + "\n");
}

// ─── push_slice ─────────────────────────────────────────────────────────────
// A broadcast is written once into a segment and every recipient's queue holds
// a slice of it; the claim these check is that a recipient behind a busy
// channel holds ONE entry per run of broadcasts and no copy of any of them.

TEST_CASE("a slice that follows the tail grows it instead of queueing")
{
    queue_t q;
    auto seg = std::make_shared<std::string>();
    seg->reserve(1024);
    seg->append("aaaa"); seg->append("bbbbbb"); seg->append("cc");
    std::shared_ptr<const std::string> s = seg;

    q.push_slice(s, 0, 4);
    const char* at = q.back().data();
    q.push_slice(s, 4, 6);
    q.push_slice(s, 10, 2);
    CHECK(q.size() == 1);
    CHECK(q.back().data() == at);                   // the segment's own bytes, not a copy
    CHECK(q.bytes() == 12 + socketley::write_queue_entry_overhead);
    CHECK(drain(q) == "aaaabbbbbbcc");
}

TEST_CASE("a slice that does not follow, or is of another segment, is its own entry")
{
    queue_t q;
    auto a = std::make_shared<std::string>("0123456789");
    auto b = std::make_shared<std::string>("abcdefghij");
    std::shared_ptr<const std::string> sa = a, sb = b;

    q.push_slice(sa, 0, 3);
    q.push_slice(sa, 5, 2);                        // a gap: bytes 3..4 belong to nobody here
    q.push_slice(sb, 7, 3);                        // the right offset, the wrong segment
    CHECK(q.size() == 3);
    CHECK(drain(q) == "012" "56" "hij");
}

TEST_CASE("slices interleave with a connection's own bytes in the order pushed")
{
    queue_t q;
    auto seg = std::make_shared<std::string>("BCAST1BCAST2");
    std::shared_ptr<const std::string> s = seg;

    q.push_slice(s, 0, 6);
    q.push(socketley::write_chunk(std::string("own-reply")));
    q.push_slice(s, 6, 6);                          // follows the segment, not the tail
    CHECK(q.size() == 3);
    CHECK(drain(q) == "BCAST1own-replyBCAST2");
}

TEST_CASE("a slice survives being copied and moved, and keeps its segment alive")
{
    auto seg = std::make_shared<std::string>("hello, world");
    std::shared_ptr<const std::string> s = seg;
    socketley::write_chunk c(s, 7, 5);
    socketley::write_chunk copy(c);
    socketley::write_chunk moved(std::move(c));
    seg.reset(); s.reset();                          // the chunks are the only owners now
    CHECK(copy.view() == "world");
    CHECK(moved.view() == "world");
    CHECK_FALSE(moved.owns());                       // never appended to: the bytes are shared
    CHECK(moved.continues_at(nullptr, 12) == false);
}

namespace {
// What a writev of these iovecs would send, as the kernel reads them.
std::string sent_by(const struct iovec* iovs, uint32_t n)
{
    std::string out;
    for (uint32_t i = 0; i < n; ++i)
        out.append(static_cast<const char*>(iovs[i].iov_base), iovs[i].iov_len);
    return out;
}
}  // namespace

TEST_CASE("after a short write the rest of the batch is sent from where its short strings moved to")
{
    // Strings of up to 15 bytes keep their bytes inside themselves, so moving one to the front of the batch moves its
    // bytes, and an iovec still naming the old slot sent what the move and the clear left there: a proxy relayed
    // "\0000007" and "\0\3\0\0\0\0\0\0" in place of a record's first bytes once a backend's socket filled.
    socketley::write_chunk batch[4] = { std::string("0123456789"), std::string("00000076|<"),
                                        std::string("short"), std::string(100, 'x') };
    struct iovec iovs[4];
    for (int i = 0; i < 4; ++i)
        iovs[i] = { const_cast<char*>(batch[i].data()), batch[i].size() };

    const uint32_t left = socketley::drop_written(batch, iovs, 4, 10);
    REQUIRE(left == 3);
    CHECK(sent_by(iovs, left) == "00000076|<short" + std::string(100, 'x'));
    for (uint32_t i = 0; i < left; ++i)
        CHECK(iovs[i].iov_base == batch[i].data());
    CHECK(batch[3].size() == 0);                     // the vacated slot is cleared

    // Part of the first entry left as well: the iovec starts inside the moved bytes.
    const uint32_t again = socketley::drop_written(batch, iovs, left, 13);
    REQUIRE(again == 2);
    CHECK(sent_by(iovs, again) == "rt" + std::string(100, 'x'));
    CHECK(iovs[0].iov_base == batch[0].data() + 3);
}

TEST_CASE("bytes that do not live in their entry are sent from where they were")
{
    // A ring buffer lent to the queue, or a shared segment, stays put however the entry holding it moves.
    const std::string lent = "lent-bytes";
    socketley::write_chunk batch[2] = { std::string("ab"), std::string() };
    struct iovec iovs[2] = { { const_cast<char*>(batch[0].data()), 2 },
                             { const_cast<char*>(lent.data()), lent.size() } };
    bool owned[2] = { true, false };
    const uint32_t left = socketley::drop_written(
        iovs, 2, 4,
        [&](uint32_t to, uint32_t from)
        {
            batch[to] = std::move(batch[from]);
            owned[to] = owned[from];
        },
        [&](uint32_t i) -> const char* { return owned[i] ? batch[i].data() : nullptr; });
    REQUIRE(left == 1);
    CHECK(sent_by(iovs, left) == "nt-bytes");
}
