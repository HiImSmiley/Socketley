#pragma once
// One shard of a storage runtime, as seen by its siblings: the requests it makes
// of the others and the requests it answers for them.
//
// It knows nothing of what carries a request, only that `call` reaches shard
// `peer` and answers once, so the logic is the same over the request channel of
// a worker and over a pair of stores in one process.  A runtime of one shard
// makes no call at all: every operation below then runs on the store alone.
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include "object_store.h"

namespace socketley::storage
{

class shard_transport
{
public:
    virtual ~shard_transport() = default;

    // `cb` is called exactly once, with ok false when the sibling could not be
    // reached or did not answer, and otherwise with its reply.
    virtual void call(uint32_t peer, std::string payload,
                      std::function<void(bool ok, std::string_view reply)> cb) = 0;
};

// What `stats` says about the crossings, on top of what the store says.
struct shard_counters
{
    // Commits and removes this shard sent to an owner, and ones it served.
    uint64_t commits_out{0};
    uint64_t commits_in{0};
    uint64_t removes_out{0};
    uint64_t removes_in{0};
    // Listings this shard fanned out, and pages it gave to a sibling's.
    uint64_t list_fanouts{0};
    uint64_t list_pages_served{0};
    uint64_t bucket_ops{0};
    // Requests that got no answer.
    uint64_t peer_failures{0};
};

class shard_node : public shard_peers
{
public:
    shard_node(object_store& store, shard_transport& transport);
    ~shard_node() override;

    shard_node(const shard_node&)            = delete;
    shard_node& operator=(const shard_node&) = delete;

    // ── Asked of the owner of a key ─────────────────────────────────────────
    void commit(uint32_t owner, commit_request req, std::function<void(put_result)> cb) override;
    void remove(uint32_t owner, std::string bucket, std::string key,
                std::function<void(st, bool)> cb) override;

    // ── Buckets are made and dropped by shard 0 and told to the rest ────────
    void create_bucket(std::string name, std::function<void(st)> cb);
    void delete_bucket(std::string name, std::function<void(st)> cb);

    // ── A listing is every shard's, merged ──────────────────────────────────
    void list(std::string_view bucket, const list_query& q, std::function<void(st, list_page)> cb);

    // Answers a request a sibling sent, once, with `ok` false for a payload that
    // is not one of ours.
    void serve(std::string_view payload, std::function<void(bool ok, std::string reply)> reply);

    const shard_counters& counters() const { return m_c; }

    // Nothing is answered to anybody after this, for a node whose store is going.
    void stop();

private:
    void run_create(std::string name, std::function<void(st, int64_t)> cb);
    void run_drop(std::string name, std::function<void(st)> cb);

    // Asks every shard but this one, and `done` runs when the last has answered.
    void each_peer(const std::function<std::string(uint32_t peer)>& make,
                   std::function<void(uint32_t peer, bool ok, std::string_view reply)> one,
                   std::function<void()> done);

    object_store&    m_store;
    shard_transport& m_transport;
    shard_counters   m_c;
    std::shared_ptr<bool> m_alive;
};

}   // namespace socketley::storage
