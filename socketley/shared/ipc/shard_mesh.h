#pragma once
// A crossing between two shards of one runtime without the daemon in the
// middle, as a mesh_sink that resolves `name#j` in this process's own sink
// table and delegates to the daemon relay whenever no link is usable, so
// correctness never depends on the mesh and every crossing is counted by
// route.
#include <algorithm>
#include <cstdint>
#include <memory>
#include <chrono>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

#include "../loop/event_loop.h"
#include "../loop/event_loop_definitions.h"
#include "../loop/frame_writer.h"
#include "../util/logging.h"
#include "request_channel.h"
#include "worker_protocol.h"

class shard_link;

// What a served request came to: `deferred` means the answer is written later
// through shard_link::send_reply() on the link it arrived on.
enum class mesh_verdict : uint8_t { served, deferred, refused };

// What a link hands a request to once it has arrived from a sibling, supplied
// by the worker because the link knows nothing about runtimes.
using shard_mesh_server = mesh_verdict (*)(void* ctx, shard_link* from,
                                           uint64_t ticket,
                                           std::string_view target,
                                           std::string_view payload,
                                           std::string& reply);

// And what it hands a routing frame to.  Null for a sibling link, which never
// carries one: a shard set routes through the daemon exactly as it did before
// the mesh, and only a link between two runtimes has routes to carry.
using shard_mesh_router = void (*)(void* ctx, std::string_view payload);

// One link, to one sibling.
class shard_link : public io_handler
{
public:
    // `label` names the far end in the one place a reader meets it, a log
    // line; empty means a sibling shard, which is what this class was for
    // before a link could also reach another runtime.
    shard_link(int fd, uint32_t peer_index, request_channel* channel,
               shard_mesh_server server, void* server_ctx,
               std::string label = {}, shard_mesh_router router = nullptr)
        : m_writer(fd), m_fd(fd), m_peer(peer_index),
          m_label(label.empty() ? "shard " + std::to_string(peer_index)
                                : std::move(label)),
          m_channel(channel), m_server(server), m_ctx(server_ctx),
          m_router(router)
    {
        // Non-blocking, because a blocking descriptor here would stall this
        // shard's event loop on a sibling's scheduling.
        const int fl = ::fcntl(m_fd, F_GETFL, 0);
        if (fl >= 0)
            if (::fcntl(m_fd, F_SETFL, fl | O_NONBLOCK) < 0) {}
    }

    ~shard_link() override
    {
        // The owner slot attach() claimed, given back here because nothing
        // else gave it back at all: register_owner() re-uses a slot only once
        // its token is cleared, and MAX_OWNERS is 1024, so a peer restart --
        // which retires one link and attaches another -- cost one of them
        // permanently.  Safe with completions still in the ring: the token
        // goes now and the slot stays claimed until they have drained.
        if (m_loop)
            m_loop->deregister_owner(this);
        // A link retired before its grace ran out still says it ended unexplained.
        if (!m_held_warning.empty())
            LOG_WARN(m_held_warning.c_str());
        // A link never die()d still has its descriptor, which the loop closes once nothing in the ring names it.
        if (m_fd >= 0)
        {
            if (m_loop)
                m_loop->close_fd(m_fd);
            else
                ::close(m_fd);
        }
    }

    shard_link(const shard_link&)            = delete;
    shard_link& operator=(const shard_link&) = delete;

    // register_owner() first, then the writer, then the arm, because a
    // submission made before the registration has its completion dropped and
    // the recv then never reports.
    bool attach(event_loop& loop)
    {
        m_loop = &loop;
        loop.register_owner(this);

        // Nothing is queued on a link this new, so this only installs the
        // ring.
        m_writer.use_ring(&loop, this);

        arm();
        return m_armed;
    }

    bool alive() const { return !m_dead && m_fd >= 0 && !m_writer.dead(); }
    uint32_t peer() const { return m_peer; }

    // A number no other link in this process has had, so a deferred answer
    // can name the link it belongs on without holding a pointer to it.
    uint64_t serial() const { return m_serial; }

    // A link's queue is held to what the asker's parked tickets bound and not to the writer's cap, which one turn of
    // large values passes before its flush and which ended the link for good.
    static constexpr size_t BACKLOG = 256u << 20;

    // One answer back to the asker, with a write the link cannot take ending
    // it exactly as an inline answer's would.
    bool send_reply(uint64_t ticket, request_status st, std::string_view reply)
    {
        if (!alive())
            return false;
        if (!put(worker_proto::chan_reply_frame_size(reply), [&](std::string& out) {
                    worker_proto::append_chan_reply_frame(
                        out, ticket, static_cast<uint8_t>(st), reply);
                }))
        {
            die("could not answer a sibling: the backlog is full");
            return false;
        }
        return true;
    }

    // Send one request to the sibling, returning false so the caller can relay
    // it instead.
    bool send_request(uint64_t ticket, std::string_view target,
                      std::string_view payload)
    {
        if (!alive())
            return false;

        if (!put(worker_proto::chan_request_frame_size(target, payload),
                [&](std::string& out) {
                    worker_proto::append_chan_request_frame(out, ticket, target, payload);
                }))
        {
            // The backlog is full or the socket is gone, and either way this
            // link is not carrying anything more.
            die("the backlog to a sibling filled or its socket went");
            return false;
        }

        if (m_writer.dead())
        {
            die("writing to a sibling failed");
            return false;
        }

        m_owed.insert(ticket);
        return true;
    }

    // One routing frame to the peer, in the encoding the daemon's own leg uses,
    // so the far side reads it with the function it already had.  False means
    // this link is not carrying it and the caller sends it the long way --
    // which is later and therefore still in order, since the slow route cannot
    // overtake the fast one.
    bool send_route(std::string_view payload)
    {
        if (!alive())
            return false;

        if (!m_writer.write(worker_proto::frame(
                worker_proto::frame_type::route_down, payload), BACKLOG))
        {
            die("the backlog to a peer filled or its socket went");
            return false;
        }
        if (m_writer.dead())
        {
            die("writing to a peer failed");
            return false;
        }
        return true;
    }

    // The recv and the writer's send, told apart by the request address rather
    // than the op type, which cannot separate two submissions of the same
    // shape.
    void on_cqe(struct io_uring_cqe* cqe) override
    {
        auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
        if (!req)
            return;

        if (m_writer.owns_request(req))
        {
            m_writer.on_send_cqe(cqe->res);
            if (m_writer.dead())
                die("sending to a sibling failed");
            return;
        }

        if (req != &m_req)
            return;

        m_armed = false;
        if (m_dead)
            return;

        const int res = cqe->res;
        if (res > 0)
        {
            // A recv and not a readiness notification, so the bytes are
            // already here and no second syscall follows.
            m_in.append(m_rbuf.get(), static_cast<size_t>(res));
            // A read that filled the buffer left more behind it, and a link that streams is read in larger pieces.
            if (static_cast<size_t>(res) == m_rsize && m_rsize < max_read_bytes)
            {
                m_rsize *= 2;
                m_rbuf = std::make_unique<char[]>(m_rsize);
            }
            take_frames();
            return;                    // re-armed by pump(), at the end of the turn
        }

        // Any end of input is the peer going away, because both directions
        // carry traffic for the whole life of a link and this protocol has no
        // graceful half-close.
        if (res == 0)
        {
            die("a sibling closed its end", m_peer_exit_expected);
            return;
        }

        // Nothing arrived and nothing is wrong, since -ECANCELED is this ring
        // going down or close_fd() withdrawing the arm.
        if (res == -EAGAIN || res == -EWOULDBLOCK || res == -EINTR ||
            res == -ECANCELED)
            return;

        die("reading from a sibling failed", m_peer_exit_expected);
    }

    // This process is leaving, so a sibling that goes first is the order of an
    // ordinary stop and not a mesh that broke -- which is the difference
    // between a log where a real mesh failure is visible and one where every
    // stop says the same thing.
    void expect_peer_exit()
    {
        m_peer_exit_expected = true;
        // A sibling seen to go just before this process heard it was stopping was the same stop, told in another order.
        if (!m_held_warning.empty())
            LOG_DEBUG(m_held_warning.c_str());
        m_held_warning.clear();
    }

    // A link's unexpected end said once it has stayed unexplained past the grace, since the daemon tells every
    // shard to stop in one turn and a sibling can be gone before this one has read that it is going too.
    void settle(std::chrono::steady_clock::time_point now)
    {
        if (!m_held_warning.empty() && now - m_held_at >= peer_exit_grace)
        {
            LOG_WARN(m_held_warning.c_str());
            m_held_warning.clear();
        }
    }

    // ── Once per turn of the owner's loop ───────────────────────────────────
    // The two things a completion cannot do for itself -- put this turn's
    // frames on the wire and replace a recv that is no longer standing -- done
    // once per turn, because per-frame submission turned 5,920 ring entries
    // into 61,221.
    void pump()
    {
        if (m_dead)
            return;

        m_writer.flush();
        if (m_writer.dead())
        {
            die("flushing to a sibling failed");
            return;
        }
        arm();
    }

    // States the ring cannot end on its own -- no recv standing, or bytes
    // queued with no send standing -- which the owner's loop asks before it
    // sleeps.
    bool needs_wake() const
    {
        return (!m_dead && (!m_armed || m_writer.needs_retry())) || !m_held_warning.empty();
    }

    // The one function that ends a link, ordered flag then tickets then
    // descriptor so no step can be reached twice, with `expected` covering the
    // N-1 links every clean stop retires.
    void die(const char* why, bool expected = false)
    {
        if (m_dead)
            return;
        m_dead = true;
        m_writer.mark_dead();

        // Every crossing this link was carrying, answered now rather than left
        // for a deadline that does not exist.
        if (m_channel)
            for (const uint64_t t : m_owed)
                m_channel->complete_deferred(t, request_status::no_target, {});
        const size_t swept = m_owed.size();
        m_owed.clear();

        if (m_fd >= 0)
        {
            // close_fd() and not poll_remove(), because a recv and a send are
            // withdrawn by descriptor, and the writer is left on the ring
            // since mark_dead() makes every later flush() a no-op.
            if (m_loop)
                m_loop->close_fd(m_fd);
            else
                ::close(m_fd);
            m_fd = -1;
        }

        const std::string note =
            "shard mesh: the link to " + m_label
            + " is down (" + std::string(why) + "); " + std::to_string(swept)
            + " crossing(s) answered, the rest relay through the daemon";
        // An expected end that dropped work is still worth a line, because a
        // stop that answered crossings `no_target` is a thing a caller saw;
        // an expected end with nothing in flight is only bookkeeping.
        if (expected && swept > 0)
            LOG_INFO(note.c_str());
        else if (expected)
            LOG_DEBUG(note.c_str());
        else
        {
            m_held_warning = note;
            m_held_at = std::chrono::steady_clock::now();
        }
    }

    size_t owed() const { return m_owed.size(); }

private:
    static void append_header(std::string& out, worker_proto::frame_type type, size_t len)
    {
        socketley::bytes::append32(out, static_cast<uint32_t>(len));
        worker_proto::put_u16(out, worker_proto::version);
        worker_proto::put_u16(out, static_cast<uint16_t>(type));
    }

    // One frame of `size` bytes onto the link, in pieces when it is past what a reader takes as one: a sibling's
    // answer of large values is as long as the values, and a single shard writes such an answer to its client whole.
    template <class Fill>
    bool put(size_t size, Fill&& fill)
    {
        static constexpr size_t piece = 4u << 20;
        if (size - worker_proto::header_size <= worker_proto::max_payload)
            return m_writer.write_with(size, std::forward<Fill>(fill), BACKLOG);
        const size_t pieces = (size + piece - 1) / piece;
        if (!m_writer.admit(size + pieces * (worker_proto::header_size + 1), BACKLOG))
            return false;
        std::string whole;
        whole.reserve(size);
        fill(whole);
        for (size_t at = 0; at < whole.size(); at += piece)
        {
            const size_t n = std::min(piece, whole.size() - at);
            const bool last = at + n == whole.size();
            if (!m_writer.write_with(worker_proto::header_size + 1 + n, [&](std::string& out) {
                    append_header(out, worker_proto::frame_type::mesh_part, n + 1);
                    out.push_back(last ? 1 : 0);
                    out.append(whole, at, n);
                }, BACKLOG))
                return false;
        }
        return true;
    }

    void arm()
    {
        if (m_dead || !m_loop || m_armed || m_fd < 0 || !m_loop->ring_open())
            return;
        // The request carries its own owner, and one left empty matches no
        // live registration, so the completion is dropped and every crossing
        // hangs.
        m_req   = { this, nullptr, m_fd, static_cast<uint32_t>(m_rsize), op_read };
        m_armed = m_loop->submit_read(m_fd, m_rbuf.get(), static_cast<uint32_t>(m_rsize), &m_req);
        // A submission the ring refused is not a dead link, so needs_wake()
        // clamps the wait and pump() tries again next turn.
    }

    // Act on every whole frame the recv completions have delivered so far.
    void take_frames()
    {
        // A turn of the loop inside handle() lands here again, and the outer walk already reaches what it appended.
        if (m_taking)
            return;
        m_taking = true;

        worker_proto::frame_type type{};
        uint16_t                 ver = 0;
        std::string_view         view;
        std::string              payload;
        bool                     fatal = false;
        size_t                   off   = 0;

        while (worker_proto::peek_frame(m_in, off, type, ver, view, fatal))
        {
            // Copied, since handle() may append to m_in and move what view points at.
            payload.assign(view.data(), view.size());
            handle(type, payload);
            if (m_dead)
            {
                m_taking = false;
                return;    // handle() gave up on the link; m_in goes with it
            }
        }
        m_in.erase(0, off);
        m_taking = false;

        if (fatal)
            die("a sibling sent a frame this build cannot read");
    }

    void handle(worker_proto::frame_type type, const std::string& payload)
    {
        // Two frame types and no others, where a chan_req's ticket belongs to
        // the sibling and a chan_rep's to this process, so the two spaces
        // never meet.
        if (type == worker_proto::frame_type::chan_req)
        {
            worker_proto::chan_request_view q;
            if (!worker_proto::decode_chan_request(payload, q))
            {
                // Answered as dropped when its ticket can be read, or the sender holds the crossing for good.
                worker_proto::reader r(payload.data(), payload.size());
                if (const uint64_t ticket = r.u64(); r.ok)
                    send_reply(ticket, request_status::dropped, {});
                return;
            }

            std::string reply;
            const mesh_verdict v = m_server
                ? m_server(m_ctx, this, q.ticket, q.target, q.payload, reply)
                : mesh_verdict::refused;

            // The runtime answers on a later turn through send_reply(), so
            // nothing is written for it here.
            if (v == mesh_verdict::deferred)
                return;

            send_reply(q.ticket,
                       v == mesh_verdict::served ? request_status::ok
                                                 : request_status::no_target,
                       reply);
            return;
        }

        if (type == worker_proto::frame_type::chan_rep)
        {
            worker_proto::chan_reply_view p;
            if (!worker_proto::decode_chan_reply(payload, p))
                return;

            m_owed.erase(p.ticket);
            if (m_channel)
                m_channel->complete_deferred(
                    p.ticket, static_cast<request_status>(p.status), p.payload);
        }
        if (type == worker_proto::frame_type::mesh_part && !payload.empty())
        {
            m_part.append(payload, 1, std::string::npos);
            if (m_part.size() > BACKLOG)
            {
                die("a sibling sent more of one frame than a link holds");
                return;
            }
            if (payload[0] == 0)
                return;
            // The whole frame, header and all, which is read as if it had come in one piece.
            std::string whole = std::move(m_part);
            m_part.clear();
            worker_proto::reader r(whole.data(), whole.size());
            const uint32_t len = r.u32();
            r.u16();
            const auto inner = static_cast<worker_proto::frame_type>(r.u16());
            if (!r.ok || len != whole.size() - worker_proto::header_size ||
                inner == worker_proto::frame_type::mesh_part)
            {
                die("a sibling sent a frame in pieces that do not make one");
                return;
            }
            whole.erase(0, worker_proto::header_size);
            handle(inner, whole);
            return;
        }
        if (type == worker_proto::frame_type::route_down)
        {
            // Applied by the far side with the same function the daemon's leg
            // ends in, so a routed connection cannot behave differently
            // depending on which way its bytes came.
            if (m_router)
                m_router(m_ctx, payload);
            return;
        }

        // Anything else travels the daemon's wire, not this one, and is skipped
        // rather than fatal — the length in the header is what makes that safe.
    }

    frame_writer m_writer;
    int          m_fd{-1};
    uint32_t     m_peer{0};
    std::string  m_label;
    uint64_t     m_serial{next_serial()};

    static uint64_t next_serial()
    {
        static uint64_t n = 0;
        return ++n;
    }

    request_channel*  m_channel{nullptr};
    shard_mesh_server m_server{nullptr};
    void*             m_ctx{nullptr};
    shard_mesh_router m_router{nullptr};
    // What has come of a frame sent in pieces, until its last.
    std::string       m_part;

    event_loop* m_loop{nullptr};
    io_request  m_req{};
    bool        m_armed{false};
    bool        m_dead{false};
    bool        m_taking{false};

    // Set by expect_peer_exit(); false means a sibling going is news.
    bool        m_peer_exit_expected{false};
    // An unexpected end waiting out the grace before it is said, and when it came.
    std::string m_held_warning;
    std::chrono::steady_clock::time_point m_held_at{};
    static constexpr std::chrono::milliseconds peer_exit_grace{1500};

    // What a standing recv writes into, one at a time and named by m_req.
    // 64 KiB was measured against this and is the same: a cache sharded two
    // ways, 64 KiB values crossing, three passes each -- 248/230/197 us a GET
    // at 16 KiB against 242/165/266 at 64 KiB, spread wider than the
    // difference.  That quarters the reads AND the submissions for the same
    // bytes, so it bounds a multishot recv here as well; the crossing's cost
    // is the hop, not the read.  Measured at one request in flight per
    // connection, which is where a per-turn quantum would show worst: with
    // many queued, one read already drains many frames.
    //
    // Doubled whenever a read fills it, since one recv a turn would otherwise hold a streaming link to 16 KiB a turn.
    static constexpr size_t max_read_bytes = 256 * 1024;
    size_t                  m_rsize{16 * 1024};
    std::unique_ptr<char[]> m_rbuf{std::make_unique<char[]>(16 * 1024)};
    std::string m_in;

    std::unordered_set<uint64_t> m_owed;
};

// What `name#j` resolves to in a shard's own sink table, registered under the
// qualified name so the lookup hits here instead of falling through to the
// daemon.
class mesh_sink : public deferred_request_sink
{
public:
    mesh_sink(shard_link* link, request_sink* relay)
        : m_link(link), m_relay(relay) {}

    bool serve_deferred(uint64_t ticket, std::string_view target,
                        std::string_view payload) override
    {
        if (m_link && m_link->send_request(ticket, target, payload))
        {
            ++m_direct;
            return true;
        }

        // No link, or a link that has just given up, so the crossing is slower
        // here and never lost.
        if (m_relay && m_relay->serve_deferred(ticket, target, payload))
        {
            ++m_relayed;
            return true;
        }
        return false;
    }

    uint64_t stat_direct()  const { return m_direct; }
    uint64_t stat_relayed() const { return m_relayed; }

private:
    shard_link*   m_link{nullptr};
    request_sink* m_relay{nullptr};
    uint64_t      m_direct{0};
    uint64_t      m_relayed{0};
};
