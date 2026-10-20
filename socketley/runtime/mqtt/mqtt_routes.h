#pragma once
// The topic rules: what a broker hands to another runtime of its daemon beside its own subscribers, a line each.
//
//   sensor/+/temp    cache://telemetry/stream/temps        an entry in a cache stream
//   alarm/#          cache://events/channel/alarms         a PUBLISH to the cache's subscribers
//   device/+/state   db://fleet/devices/%1                 a document, %1 the first '+' level
//   log/#            storage://raw/mqtt/%Y/%m/%d/          an NDJSON object a minute
//   chat/#           server://chat                         every client of a server
//   ig/share/#       mqtt://threads-live/shared/%c         a message on another broker
//
// %1 to %9 stand for the levels the '+' of the filter matched, %c for the client that published and %t for the
// whole topic; a storage prefix also takes %Y %m %d %H %M of the time its object is written. A line starting
// with '#' and not followed by a target is a comment, as is anything after a target.
//
// Each rule keeps its own queue: a target that does not answer holds its messages up to a limit, is tried again
// after a growing pause, and costs the broker nothing meanwhile. What is queued goes into the snapshot.
#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <string_view>
#include <vector>

#include "mqtt_broker.h"
#include "../../shared/loop/backlog_gate.h"

namespace socketley::mqtt
{

enum class target_kind : uint8_t { cache_stream, cache_channel, db, storage, server, mqtt, webhook };

// A request waiting for its target, numbered so one sent again goes back to where it stood.
struct route_request
{
    uint64_t    seq{0};
    std::string bytes;
};

const char* target_kind_name(target_kind k);

struct route
{
    std::string filter;
    target_kind kind{target_kind::cache_stream};
    std::string runtime;
    // The stream, channel, collection, bucket or topic, with its placeholders.
    std::string name;
    // The db document's identifier or the storage prefix, with its placeholders; empty where there is none.
    std::string detail;
    std::string text;

    // Requests built and not yet sent, oldest first; those in flight are held by whoever sent them.
    std::deque<route_request> queue;
    uint64_t next_seq{0};
    size_t   inflight{0};
    int64_t  retry_at_ms{0};
    uint32_t backoff_ms{0};
    uint64_t delivered{0};
    uint64_t failed{0};
    uint64_t dropped{0};
    backlog_gate gate;
    // A storage rule's lines gathered for its next object.
    std::string batch;
    size_t   batch_lines{0};
    int64_t  batch_started_ms{0};
    uint64_t batch_seq{0};
    std::string last_error;

    // A new request at the end, the oldest dropped past `limit`.
    void push(std::string bytes, size_t limit);
    // A request that was sent and must go again, before every later one.
    void put_back(route_request q);
    // The next try put off, twice as long as the last up to five seconds, since a target here is cheap to ask.
    void back_off(int64_t now);
};

class route_table
{
public:
    // How many requests one rule holds before it drops the oldest, and how many it has in flight.
    static constexpr size_t queue_limit  = 100000;
    static constexpr size_t window       = 64;
    static constexpr size_t batch_bytes  = 1u << 20;
    static constexpr int64_t batch_ms    = 60000;

    // The rules in `text`; false with `why` naming the line that is not one.
    bool parse(std::string_view text, std::string& why);

    std::vector<route>& routes() { return m_routes; }
    const std::vector<route>& routes() const { return m_routes; }
    bool empty() const { return m_routes.empty(); }

    // The requests a message makes, queued on every rule whose filter it matches; `shard` names the object files a
    // storage rule writes, so two shards never write the same key.
    void offer(const message& m, int64_t now, uint32_t shard);
    // A storage rule's lines turned into one request once enough are gathered or they are old enough; `force` for
    // a stop, which writes what there is.
    void cut_batches(int64_t now, uint32_t shard, bool force);

    // The rules' queues as bytes for the snapshot, and back; a rule no longer in the file loses what it held.
    // `flying` holds each rule's requests in flight, saved in their place so a restart sends them again.
    std::string save(const std::vector<std::vector<const route_request*>>& flying = {}) const;
    void load(std::string_view bytes);

    // The request a rule sends for a message, for a test that wants to see it.
    static std::string request_for(const route& r, const message& m, const std::vector<std::string_view>& plus);

private:
    std::vector<route> m_routes;
};

// What each target kind's answer says: delivered, refused for good (dropped and counted), or worth another try.
enum class reply_verdict : uint8_t { delivered, refused, retry };
reply_verdict judge_reply(target_kind k, std::string_view reply, std::string& why);

// A topic's levels that a filter's '+' matched, in order; empty when the topic does not match.
bool plus_levels(std::string_view filter, std::string_view topic, std::vector<std::string_view>& out);

// The payload as JSON: a string when it is UTF-8, else {"base64": ...}.
void payload_json(std::string& out, std::string_view payload);

}   // namespace socketley::mqtt
