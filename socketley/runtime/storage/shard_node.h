#pragma once
// One shard of a storage runtime, as seen by its siblings: the requests it makes
// of the others and the requests it answers for them.
//
// It knows nothing of what carries a request, only that `call` reaches shard
// `peer` and answers once, so the logic is the same over the request channel of
// a worker and over a pair of stores in one process.  A runtime of one shard
// makes no call at all: every operation below then runs on the store alone.
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>

#include "../../shared/cache_shard_map.h"
#include "multipart.h"
#include "object_store.h"
#include "shard_wire.h"

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
    uint64_t tags_out{0};
    uint64_t tags_in{0};
    // Listings this shard fanned out, and pages it gave to a sibling's.
    uint64_t list_fanouts{0};
    uint64_t list_pages_served{0};
    uint64_t bucket_ops{0};
    // Multipart steps this shard sent to the shard that owns an upload, and ones it served.
    uint64_t mpu_out{0};
    uint64_t mpu_in{0};
    // Requests that got no answer.
    uint64_t peer_failures{0};
    // Drops of a key's small copy this shard sent to its siblings (one per sibling), and ones it served.
    uint64_t hot_drops_out{0};
    uint64_t hot_drops_in{0};
    // Copies of another shard's key this shard asked to keep, and asks it answered for its own keys.
    uint64_t hot_holds_out{0};
    uint64_t hot_holds_in{0};
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
    void remove(uint32_t owner, std::string bucket, std::string key, std::string version_id, bool bypass,
                std::function<void(remove_result)> cb) override;
    void change_header(uint32_t owner, std::string bucket, std::string key, std::string version_id,
                       header_change change, std::function<void(st, std::string)> cb) override;
    // Sent by the owner before it answers a commit or a delete, so no sibling answers the old bytes after it.
    void invalidate(std::string bucket, std::string key, std::function<void()> done) override;
    void hold(uint32_t owner, std::string bucket, std::string key, const object_meta& read,
              std::function<void(bool)> cb) override;
    // Tells the siblings this shard has started, so they drop the copies they hold of its keys, which a
    // commit this shard died in may have replaced without their being told; `done` hears whether all answered.
    void announce_start(std::function<void(bool)> done);
    // Sends the holds asked for since the last call, one message per owner, which the runtime does once a turn.
    void flush_holds();
    // Every copy a sibling holds of this shard's keys is now in a slot it asked about, so a drop goes only to those.
    void trust_holders() { m_holders_known = true; }
    // The siblings that may hold a copy of a key in `slot`.
    uint64_t holders(uint32_t slot) const { return m_holders[slot]; }

    // ── Buckets are made and dropped by shard 0 and told to the rest ────────
    // `owner` is the id of the user that makes it, empty for the default owner.
    void create_bucket(std::string name, std::string owner, std::function<void(st)> cb);
    void delete_bucket(std::string name, std::function<void(st)> cb);
    // Sets a bucket's configuration document of `kind`, or removes it when `xml` is empty; every shard has it before `cb`.
    void set_doc(bucket_doc kind, std::string name, std::string xml, std::function<void(st)> cb);

    // ── A listing is every shard's, merged ──────────────────────────────────
    void list(std::string_view bucket, const list_query& q, std::function<void(st, list_page)> cb);
    void list_versions(std::string_view bucket, const version_query& q, std::function<void(st, version_page)> cb);

    // ── An upload lives on the shard that owns its key ─────────────────────
    // Every step that names an upload goes to that shard, so its parts and its
    // state are one process's; a part's body is written where the connection
    // landed and only its name crosses, and a completed upload is assembled
    // where the request landed and committed by the owner of the key.
    void set_multipart(multipart_store* mpu) { m_mpu = mpu; }
    void mpu_create(std::string bucket, std::string key, object_meta meta, checksum_algo algo,
                    std::function<void(st, std::string)> cb);
    // no_such_key when the upload is missing, on its way out, or sealed.  Part `number`
    // (0 for one that is copied) of `expected` bytes when `known` is given its place in
    // the upload's data file, decided by the owner so each place is given once.
    void mpu_begin(std::string bucket, std::string key, std::string id, uint32_t number, uint64_t expected,
                   bool known, std::function<void(st, checksum_algo, part_place)> cb);
    put_op::committer mpu_part_committer(std::string bucket, std::string key, std::string id, uint32_t number);
    void mpu_complete(std::string bucket, std::string key, std::string id, std::vector<complete_part> parts,
                      std::function<void()> progress, std::function<void(complete_result)> cb,
                      complete_binder bind = {}, put_condition cond = {});
    // `cb` gets false when there was no such upload.
    void mpu_abort(std::string bucket, std::string key, std::string id, std::function<void(bool)> cb);
    void mpu_parts(std::string bucket, std::string key, std::string id, uint32_t marker, uint32_t max_parts,
                   std::function<void(parts_page)> cb);
    void mpu_list(std::string bucket, std::function<void(st, std::vector<wire::upload_stub>)> cb);

    // Answers a request a sibling sent, once, with `ok` false for a payload that
    // is not one of ours.
    void serve(std::string_view payload, std::function<void(bool ok, std::string reply)> reply);

    const shard_counters& counters() const { return m_c; }

    // Nothing is answered to anybody after this, for a node whose store is going.
    void stop();

private:
    void run_create(std::string name, std::string owner, std::function<void(st, int64_t)> cb);
    void run_drop(std::string name, std::function<void(st)> cb);
    // Shard 0's half of set_doc, one change of a bucket at a time so every shard hears them in one order.
    void run_doc(bucket_doc kind, std::string name, std::string xml, std::function<void(st)> cb);
    // Removes a change no shard will make and tells the others so, then runs `then` and the next change.
    void abandon_doc(bucket_doc kind, std::string name, uint64_t seq, std::function<void()> then);
    void tell_abandoned(bucket_doc kind, const std::string& name, uint64_t seq);
    void doc_next(const std::string& name);
    // Whether SOCKETLEY_STORAGE_DOC_FAULT, a test hook, says a document message of `phase` is lost on its way here.
    bool doc_fault(std::string_view phase) const;

    // Asks every shard in `mask` but this one, and `done` runs when the last has answered.
    void each_peer(const std::function<std::string(uint32_t peer)>& make,
                   std::function<void(uint32_t peer, bool ok, std::string_view reply)> one,
                   std::function<void()> done, uint64_t mask = ~uint64_t{0});


    void serve_mpu(wire::op o, std::string_view payload, std::function<void(bool ok, std::string reply)> reply);
    const mpu_upload* mpu_find(const std::string& bucket, const std::string& key, const std::string& id) const;

    object_store&    m_store;
    multipart_store* m_mpu{nullptr};
    shard_transport& m_transport;
    shard_counters   m_c;
    // The document changes of a bucket waiting behind the one being made.
    std::map<std::string, std::deque<std::function<void()>>> m_doc_lanes;
    // The number of the last change shard 0 asked the others to prepare for.
    uint64_t m_doc_seq{0};
    std::string m_doc_fault;
    // The siblings that may hold a copy of a key of each slot, one bit per shard, kept for the life of this shard
    // so that a change never finds a sibling missing that an earlier change of the slot still had to tell.
    std::vector<uint64_t> m_holders = std::vector<uint64_t>(cache_slot_count, 0);
    bool        m_holders_known{false};
    // The holds waiting for the end of the turn, by owner, and what each was asked with.
    std::vector<std::vector<wire::hold_entry>>          m_hold_q;
    std::vector<std::vector<std::function<void(bool)>>> m_hold_cb;
    std::shared_ptr<bool> m_alive;
};

}   // namespace socketley::storage
