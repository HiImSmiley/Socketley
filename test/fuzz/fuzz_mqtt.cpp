// Fuzz target: the MQTT runtime's codec and broker (socketley/runtime/mqtt/).
//
// Reachable by any peer that can open a TCP connection to an mqtt runtime: its first byte is read by take_frame()
// and every packet after it by the readers and the broker.
//
// The first byte of an input chooses what it is:
//
//   even   a stream of packets read at protocol level 4 (bit 1 clear) or 5 (bit 1 set). What a reader accepts must
//          be written back and read again to the same fields: a packet the broker reads one way and writes another
//          is one a peer sees differently than the broker meant.
//   odd    a program run against one broker on four connections, a record at a time:
//              [op][conn][len lo][len hi][len bytes]
//          op % 5: 0 bytes in, 1 the connection ends, 2 the clock moves len*10 ms and ticks, 3 the connection stops
//          (or starts) reading, 4 the state is written as a snapshot, read into a second broker, and that one's
//          snapshot read into a third, which must hold what the second does.
//          Whatever the program, everything written to a connection must be whole packets the client side reads,
//          and the retained store's byte count must be what its messages add up to.

#include "fuzz_common.h"

#include "../../socketley/runtime/mqtt/mqtt_broker.h"
#include "../../socketley/runtime/mqtt/mqtt_codec.h"

#include <map>
#include <memory>
#include <set>

using namespace socketley::mqtt;

namespace
{

void codec_stream(std::string_view in, uint8_t level)
{
    while (!in.empty())
    {
        frame f;
        const frame_status st = take_frame(in, 1u << 20, f);
        if (st != frame_status::ok)
            return;
        FUZZ_CHECK(f.size <= in.size(), "a frame larger than its input");
        refusal err;
        switch (f.type)
        {
            case packet_type::connect:
            {
                connect_packet p;
                if (read_connect(f, p, err))
                {
                    std::string again;
                    write_connect(again, p);
                    frame g;
                    FUZZ_CHECK(take_frame(again, 0, g) == frame_status::ok, "a written CONNECT is no frame");
                    connect_packet q;
                    FUZZ_CHECK(read_connect(g, q, err), "a written CONNECT does not read back");
                    FUZZ_CHECK(q.client_id == p.client_id && q.keepalive == p.keepalive &&
                                   q.clean_start == p.clean_start && q.username == p.username &&
                                   q.password == p.password && q.will.has_value() == p.will.has_value(),
                               "a CONNECT reads back different");
                }
                break;
            }
            case packet_type::publish:
            {
                publish_packet p;
                if (read_publish(f, level, p, err))
                {
                    std::string again;
                    write_publish(again, level, p);
                    FUZZ_CHECK(again.size() == publish_size(level, p), "publish_size disagrees with the writer");
                    frame g;
                    FUZZ_CHECK(take_frame(again, 0, g) == frame_status::ok, "a written PUBLISH is no frame");
                    publish_packet q;
                    FUZZ_CHECK(read_publish(g, level, q, err), "a written PUBLISH does not read back");
                    FUZZ_CHECK(q.topic == p.topic && q.payload == p.payload && q.qos == p.qos &&
                                   q.packet_id == p.packet_id && q.retain == p.retain && q.dup == p.dup,
                               "a PUBLISH reads back different");
                }
                break;
            }
            case packet_type::subscribe:
            {
                subscribe_packet p;
                if (read_subscribe(f, level, p, err))
                {
                    std::string again;
                    write_subscribe(again, level, p);
                    frame g;
                    FUZZ_CHECK(take_frame(again, 0, g) == frame_status::ok, "a written SUBSCRIBE is no frame");
                    subscribe_packet q;
                    FUZZ_CHECK(read_subscribe(g, level, q, err), "a written SUBSCRIBE does not read back");
                    FUZZ_CHECK(q.entries.size() == p.entries.size(), "a SUBSCRIBE reads back different");
                    for (size_t i = 0; i < p.entries.size(); ++i)
                    {
                        (void)valid_filter(p.entries[i].filter);
                        FUZZ_CHECK(q.entries[i].filter == p.entries[i].filter && q.entries[i].qos == p.entries[i].qos,
                                   "a subscription reads back different");
                    }
                }
                break;
            }
            case packet_type::unsubscribe:
            {
                unsubscribe_packet p;
                (void)read_unsubscribe(f, level, p, err);
                break;
            }
            case packet_type::puback:
            case packet_type::pubrec:
            case packet_type::pubrel:
            case packet_type::pubcomp:
            {
                ack_packet p;
                if (read_ack(f, level, p, err))
                {
                    std::string again;
                    write_ack(again, level, p);
                    frame g;
                    ack_packet q;
                    FUZZ_CHECK(take_frame(again, 0, g) == frame_status::ok && read_ack(g, level, q, err),
                               "a written acknowledgement does not read back");
                    FUZZ_CHECK(q.packet_id == p.packet_id && q.type == p.type, "an acknowledgement reads back different");
                }
                break;
            }
            case packet_type::disconnect:
            {
                disconnect_packet p;
                (void)read_disconnect(f, level, p, err);
                break;
            }
            case packet_type::auth:
            {
                auth_packet p;
                (void)read_auth(f, level, p, err);
                break;
            }
            case packet_type::connack:
            {
                connack_packet p;
                (void)read_connack(f, level, p, err);
                break;
            }
            case packet_type::suback:
            case packet_type::unsuback:
            {
                suback_packet p;
                (void)read_suback(f, level, p, err);
                break;
            }
            default:
                (void)read_empty(f, err);
                break;
        }
        in.remove_prefix(f.size);
    }
}

struct io : broker_io
{
    std::map<uint64_t, std::string> out;
    std::set<uint64_t> closed;
    std::set<uint64_t> stuck;
    int64_t now{1'700'000'000'000};

    void send(uint64_t conn, std::string_view bytes) override { out[conn].append(bytes); }
    size_t backlog(uint64_t conn) const override { return stuck.contains(conn) ? (64u << 20) : 0; }
    void close(uint64_t conn) override { closed.insert(conn); }
    int64_t now_ms() const override { return now; }
};

struct hooks : broker_hooks
{
    void authenticate(const auth_ask& ask, std::function<void(auth_answer)> done) override
    {
        // A user name of "no" is refused, so both answers are reached.
        auth_answer a;
        a.code = ask.username && *ask.username == "no" ? reason::not_authorized : reason::success;
        a.username = ask.username.value_or("");
        done(a);
    }
    bool may_write(std::string_view, std::string_view, std::string_view t) override { return !t.starts_with("deny"); }
    bool may_read(std::string_view, std::string_view, std::string_view) override { return true; }
    bool may_subscribe(std::string_view, std::string_view, std::string_view f) override { return !f.starts_with("deny"); }
};

// Everything a client could have been sent reads as whole packets: CONNACK first, then what follows it.
void check_output(const std::string& bytes)
{
    std::string_view in = bytes;
    bool first = true;
    uint8_t level = level_311;
    while (!in.empty())
    {
        frame f;
        FUZZ_CHECK(take_frame(in, 0, f) == frame_status::ok, "the broker wrote a partial or broken frame");
        refusal err;
        if (first)
        {
            FUZZ_CHECK(f.type == packet_type::connack || f.type == packet_type::disconnect,
                       "the first packet a client is sent is not CONNACK");
            connack_packet a;
            // The CONNACK's length says which version it is: 2 bytes is 3.1.1.
            level = f.body.size() == 2 ? level_311 : level_5;
            if (f.type == packet_type::connack)
                FUZZ_CHECK(read_connack(f, level, a, err), "the broker wrote a CONNACK no client reads");
            first = false;
        }
        else if (f.type == packet_type::publish)
        {
            publish_packet p;
            FUZZ_CHECK(read_publish(f, level, p, err), "the broker wrote a PUBLISH no client reads");
            FUZZ_CHECK(valid_topic(p.topic), "the broker delivered to a topic that is none");
        }
        in.remove_prefix(f.size);
    }
}

void broker_program(std::string_view in)
{
    io t;
    hooks h;
    broker_config cfg;
    cfg.session_queue      = 8;
    cfg.retained_max_bytes = 4096;
    cfg.max_sessions       = 6;
    cfg.max_packet         = 1u << 16;
    cfg.sys_interval_s     = 0;
    broker b(cfg, t, h);
    std::set<uint64_t> open;
    uint64_t generation[4] = {1, 2, 3, 4};
    while (in.size() >= 4)
    {
        const uint8_t op = static_cast<uint8_t>(in[0]) % 5;
        const uint8_t slot = static_cast<uint8_t>(in[1]) % 4;
        size_t len = static_cast<uint8_t>(in[2]) | (static_cast<size_t>(static_cast<uint8_t>(in[3])) << 8);
        in.remove_prefix(4);
        len = std::min(len, in.size());
        const std::string_view data = in.substr(0, len);
        in.remove_prefix(len);
        uint64_t& conn = generation[slot];
        switch (op)
        {
            case 0:
                if (!open.contains(conn))
                {
                    b.connected(conn, {"fuzz", "", false, false});
                    open.insert(conn);
                }
                if (!t.closed.contains(conn))
                    b.input(conn, data);
                break;
            case 1:
                if (open.contains(conn))
                {
                    b.disconnected(conn);
                    open.erase(conn);
                    conn += 4;
                }
                break;
            case 2:
                t.now += static_cast<int64_t>(len) * 10;
                b.tick();
                break;
            case 3:
                if (t.stuck.contains(conn))
                {
                    t.stuck.erase(conn);
                    b.drained(conn);
                }
                else
                    t.stuck.insert(conn);
                break;
            case 4:
            {
                // Reading a snapshot sends the wills of sessions that ended with the broker that wrote it, so the
                // first restore may differ from the original; a second one must not differ from the first.
                io t2, t3;
                t2.now = t3.now = t.now;
                hooks h2, h3;
                broker c(cfg, t2, h2), d(cfg, t3, h3);
                std::string why;
                FUZZ_CHECK(c.restore(b.snapshot(), why), "a snapshot the broker wrote does not read back");
                FUZZ_CHECK(c.session_count() <= b.session_count(), "a snapshot made sessions up");
                FUZZ_CHECK(d.restore(c.snapshot(), why), "a restored broker's snapshot does not read back");
                FUZZ_CHECK(d.retained_count() == c.retained_count() && d.session_count() == c.session_count() &&
                               d.subscription_count() == c.subscription_count() && d.queued_count() == c.queued_count() &&
                               d.inflight_count() == c.inflight_count(),
                           "a snapshot read twice does not come back the same");
                break;
            }
        }
        // A connection the broker closed is let go by the transport, as the real one does.
        for (const uint64_t id : std::set<uint64_t>(t.closed))
            if (open.contains(id))
            {
                b.disconnected(id);
                open.erase(id);
                for (auto& g : generation)
                    if (g == id)
                        g += 4;
            }
        size_t counted = 0;
        b.retained_each("#", [&](const message_ptr& m) { counted += m->topic.size() + m->payload.size(); });
        FUZZ_CHECK(counted == b.retained_bytes(), "the retained byte count is not what is held");
        FUZZ_CHECK(b.retained_bytes() <= cfg.retained_max_bytes, "the retained store grew past its limit");
        FUZZ_CHECK(b.session_count() <= cfg.max_sessions, "more sessions than the limit");
    }
    for (const auto& [id, bytes] : t.out)
        check_output(bytes);
}

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz::set_current(data, size);
    if (size == 0)
        return 0;
    const std::string_view in(reinterpret_cast<const char*>(data) + 1, size - 1);
    if (data[0] & 1)
        broker_program(in);
    else
        codec_stream(in, (data[0] & 2) ? level_5 : level_311);
    return 0;
}
