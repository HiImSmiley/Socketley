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
