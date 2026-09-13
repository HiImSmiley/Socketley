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
